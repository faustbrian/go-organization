package postgres

import (
	"context"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

var _ organization.CredentialAuthorityReader = (*Repository)(nil)

// ObserveCredentialAuthority reads active organization ownership independently
// of any creator. ActorID selects an actual current member and its scoped policy
// epoch only when explicitly requested. These uncached storage facts grant no
// authentication or permission. All failures return a zero projection.
func (r *Repository) ObserveCredentialAuthority(ctx context.Context, q organization.CredentialAuthorityQuery) (organization.CredentialAuthorityObservation, error) {
	if r == nil || r.pool == nil || ctx == nil || q.Validate() != nil {
		return organization.CredentialAuthorityObservation{}, organization.ErrInvalidInput
	}
	start := time.Now().UTC()
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	o := organization.CredentialAuthorityObservation{TenantID: q.TenantID, OrganizationID: q.OrganizationID, ReadStartedAt: start, ValidUntil: start.Add(20 * time.Second)}
	var version, credential, member, authorizationVersion, role string
	var err error
	if q.ActorID == "" {
		err = r.pool.Raw().QueryRow(ctx, `SELECT version::text,credential_version::text
FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active'`, string(q.TenantID), string(q.OrganizationID)).Scan(&version, &credential)
	} else {
		err = r.pool.Raw().QueryRow(ctx, `SELECT o.version::text,o.credential_version::text,m.version::text,m.authorization_version::text,m.role
FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id)
WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3 AND o.state='active' AND m.state='active'`, string(q.TenantID), string(q.OrganizationID), string(q.ActorID)).Scan(&version, &credential, &member, &authorizationVersion, &role)
	}
	if err != nil {
		return organization.CredentialAuthorityObservation{}, storageError(ctx, err)
	}
	if o.Version, err = positive(version); err != nil {
		return organization.CredentialAuthorityObservation{}, err
	}
	if o.CredentialVersion, err = positive(credential); err != nil {
		return organization.CredentialAuthorityObservation{}, err
	}
	if q.ActorID != "" {
		o.Actor = organization.Member{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.ActorID, Role: organization.Role(role), Active: true}
		if o.Actor.Version, err = positive(member); err != nil {
			return organization.CredentialAuthorityObservation{}, err
		}
		if o.Actor.AuthorizationVersion, err = positive(authorizationVersion); err != nil {
			return organization.CredentialAuthorityObservation{}, err
		}
		scope, err := OrganizationAuthorityScope(q.TenantID, q.OrganizationID, q.ActorID)
		if err != nil {
			return organization.CredentialAuthorityObservation{}, err
		}
		store, err := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
		if err != nil {
			return organization.CredentialAuthorityObservation{}, organization.ErrUnavailable
		}
		current, err := store.Get(ctx, scope)
		if err != nil {
			return organization.CredentialAuthorityObservation{}, publicTeamAuthorityError(err)
		}
		if current.Version != o.Actor.AuthorizationVersion {
			return organization.CredentialAuthorityObservation{}, organization.ErrForbidden
		}
	}
	if err := ctx.Err(); err != nil {
		return organization.CredentialAuthorityObservation{}, err
	}
	o.VerifiedAt = time.Now().UTC()
	if err := o.Validate(q, o.VerifiedAt); err != nil {
		return organization.CredentialAuthorityObservation{}, err
	}
	return o, nil
}

// RequireCredentialAuthority fences the exact observed active organization and
// optional actual member in the invoking contributor's existing Work. It owns
// no transaction and invokes no policy callback. Call after identity/session
// row locks; retained SHARE locks follow owner, member, scoped authorization.
// The primary clock check follows all waits and never renews original freshness.
// The consumer separately binds these facts to its command, authenticates its
// credential and enforces current permission policy. This fence grants neither.
func (r *Repository) RequireCredentialAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, o organization.CredentialAuthorityObservation) error {
	if r == nil || r.pool == nil || ctx == nil || owner == nil {
		return organization.ErrInvalidInput
	}
	q := organization.CredentialAuthorityQuery{TenantID: o.TenantID, OrganizationID: o.OrganizationID, ActorID: o.Actor.UserID}
	if o.Validate(q, time.Now().UTC()) != nil {
		return identity.ForbiddenError{}
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || b.TenantID != o.TenantID || q.ActorID != "" && (b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(q.ActorID)) {
		return identity.ForbiddenError{}
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var version, credential string
	rows, err := w.Query(ctx, `SELECT version::text,credential_version::text
FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR SHARE`, string(o.TenantID), string(o.OrganizationID))
	if err := one(rows, err, &version, &credential); err != nil {
		return err
	}
	if version != strconv.FormatUint(o.Version, 10) || credential != strconv.FormatUint(o.CredentialVersion, 10) {
		return identity.ForbiddenError{}
	}
	if q.ActorID != "" {
		var member, authorizationVersion, role string
		rows, err := w.Query(ctx, `SELECT version::text,authorization_version::text,role
FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active' FOR SHARE`, string(o.TenantID), string(o.OrganizationID), string(q.ActorID))
		if err := one(rows, err, &member, &authorizationVersion, &role); err != nil {
			return err
		}
		if member != strconv.FormatUint(o.Actor.Version, 10) || authorizationVersion != strconv.FormatUint(o.Actor.AuthorizationVersion, 10) || role != string(o.Actor.Role) {
			return identity.ForbiddenError{}
		}
		scope, err := OrganizationAuthorityScope(o.TenantID, o.OrganizationID, q.ActorID)
		if err != nil {
			return err
		}
		if err := authority.RequireAuthority(ctx, w, scope, o.Actor.AuthorizationVersion, r.maximum); err != nil {
			return authorityError(err)
		}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if o.Validate(q, now) != nil {
		return identity.ForbiddenError{}
	}
	return nil
}
