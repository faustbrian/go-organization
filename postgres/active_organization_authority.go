package postgres

import (
	"context"
	"strconv"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
)

var _ sessionpg.OrganizationSessionAuthority = (*Repository)(nil)

func selectedOrganization(record session.Session) (session.SessionSpec, organization.ID, session.AuthorityBinding, error) {
	s, err := record.Bindings()
	if err != nil {
		return s, "", session.AuthorityBinding{}, organization.ErrForbidden
	}
	v, err := s.Authority.Bindings()
	if err != nil || !v.Organization.Present {
		return s, "", session.AuthorityBinding{}, organization.ErrForbidden
	}
	id := organization.ID(v.ActiveOrganizationID)
	key, err := organization.OrganizationSessionScope(s.TenantID, id)
	if err != nil || key != v.Organization.Binding.ScopeKey {
		return s, "", session.AuthorityBinding{}, organization.ErrForbidden
	}
	return s, id, v.Organization.Binding, nil
}

// ObserveOrganizationSession supplies uncached current organization/member and
// scoped policy evidence to the session owner. Its original read start precedes
// all IO; the returned aggregate epoch is not the membership's policy epoch.
// It grants no permission, changes no state, and borrows this primary pool.
func (r *Repository) ObserveOrganizationSession(ctx context.Context, record session.Session) (sessionpg.OrganizationSessionAuthorityObservation, error) {
	if r == nil || r.pool == nil || ctx == nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, organization.ErrInvalidInput
	}
	s, id, original, err := selectedOrganization(record)
	if err != nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, err
	}
	start := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	view, err := r.Read(ctx, organization.Query{Operation: organization.Get, TenantID: s.TenantID, ActorID: s.UserID, OrganizationID: id})
	if err != nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, err
	}
	scope, err := OrganizationAuthorityScope(s.TenantID, id, s.UserID)
	if err != nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, err
	}
	store, err := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
	if err != nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, organization.ErrUnavailable
	}
	current, err := store.Get(ctx, scope)
	if err != nil {
		return sessionpg.OrganizationSessionAuthorityObservation{}, publicTeamAuthorityError(err)
	}
	if !view.Actor.Role.Valid() || current.Version != view.Actor.AuthorizationVersion || view.Organization.Version != original.Version || !time.Now().Before(start.Add(20*time.Second)) {
		return sessionpg.OrganizationSessionAuthorityObservation{}, organization.ErrForbidden
	}
	return sessionpg.OrganizationSessionAuthorityObservation{OrganizationID: string(id), Authority: session.AuthorityBinding{ScopeKey: original.ScopeKey, Version: view.Organization.Version}, ReadStartedAt: start, ValidUntil: start.Add(20 * time.Second)}, nil
}

// RequireOrganizationSession fences the exact original selected aggregate and
// membership under retained SHARE locks in the caller's existing Work. It owns
// no transaction and must be called only after the session owner's row locks.
// It also serves selected session revocation; no competing selection is stored.
func (r *Repository) RequireOrganizationSession(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if r == nil || r.pool == nil || ctx == nil || owner == nil {
		return organization.ErrInvalidInput
	}
	s, id, expected, err := selectedOrganization(record)
	if err != nil {
		return err
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || b.TenantID != s.TenantID {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var version, authorization string
	// Work's closed decoder accepts built-in destinations, not domain aliases.
	var role string
	rows, err := w.Query(ctx, `SELECT o.version::text,m.authorization_version::text,m.role
FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3 AND o.state='active' AND m.state='active'
FOR SHARE OF o,m`, string(s.TenantID), string(id), string(s.UserID))
	if err := one(rows, err, &version, &authorization, &role); err != nil {
		return err
	}
	policyVersion, err := positive(authorization)
	if err != nil || version != strconv.FormatUint(expected.Version, 10) || !organization.Role(role).Valid() {
		return identity.ForbiddenError{}
	}
	scope, err := OrganizationAuthorityScope(s.TenantID, id, s.UserID)
	if err != nil {
		return err
	}
	return authority.RequireAuthority(ctx, w, scope, policyVersion, r.maximum)
}
