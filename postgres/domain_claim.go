package postgres

import (
	"context"
	"strconv"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/jackc/pgx/v5"
)

func isDomainMutation(op organization.Operation) bool {
	return op == organization.ReserveDomain || op == organization.WithdrawDomain
}
func isDomainOperation(op organization.Operation) bool {
	return isDomainMutation(op) || op == organization.GetDomainClaim
}

func (s *Service) PrepareReserveDomain(ctx context.Context, r organization.DomainClaimRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareReserveDomain(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareWithdrawDomain(ctx context.Context, r organization.DomainClaimRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareWithdrawDomain(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) GetDomainClaim(ctx context.Context, r organization.DomainClaimReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.GetDomainClaim(ctx, r)
}

func (r *Repository) readDomain(ctx context.Context, q organization.Query, v organization.View) (organization.View, error) {
	if !scope(string(q.DomainClaimID)) {
		return organization.View{}, organization.ErrInvalidInput
	}
	if v.Actor.Role != organization.RoleOwner && v.Actor.Role != organization.RoleAdministrator {
		return organization.View{}, organization.ErrForbidden
	}
	scope, err := OrganizationAuthorityScope(q.TenantID, q.OrganizationID, q.ActorID)
	if err != nil {
		return organization.View{}, err
	}
	store, err := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
	if err != nil {
		return organization.View{}, organization.ErrUnavailable
	}
	current, err := store.Get(ctx, scope)
	if err != nil {
		return organization.View{}, publicTeamAuthorityError(err)
	}
	if current.Version != v.Actor.AuthorizationVersion {
		return organization.View{}, organization.ErrForbidden
	}
	c := organization.DomainClaim{ID: q.DomainClaimID, OrganizationID: q.OrganizationID, TenantID: q.TenantID}
	var version string
	err = r.pool.Raw().QueryRow(ctx, `SELECT canonical_domain,state,version::text FROM organization.domain_claims WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.DomainClaimID)).Scan(&c.Domain, &c.State, &version)
	if err == pgx.ErrNoRows && q.Operation == organization.ReserveDomain {
		return v, nil
	}
	if err != nil {
		return organization.View{}, storageError(ctx, err)
	}
	if c.Version, err = positive(version); err != nil {
		return organization.View{}, err
	}
	v.DomainClaim = c
	return v, nil
}

// The existing tenant/aggregate locks serialize the bounded retained-cardinality
// check. The partial unique index, not a tenant-local lookup, arbitrates global
// name custody. ON CONFLICT keeps the transaction usable and redacts the owner.
func (p *Contributor) mutateDomain(ctx context.Context, w kernel.Work, c nativeCommand) error {
	if e := p.requireDomainOrganization(ctx, w, c, c.org.Version); e != nil {
		return e
	}
	b, claim := c.spec.Binding, c.domainClaim
	var n int64
	var e error
	if c.operation == organization.ReserveDomain {
		var count int64
		rows, err := w.Query(ctx, `SELECT count(*) FROM organization.domain_claims WHERE tenant_id=$1 AND organization_id=$2`, string(b.TenantID), string(c.org.ID))
		if err = one(rows, err, &count); err != nil {
			return err
		}
		if count < 0 || uint64(count) >= p.config.Domains.MaximumClaims {
			return identity.ForbiddenError{}
		}
		n, e = w.Exec(ctx, `INSERT INTO organization.domain_claims(tenant_id,organization_id,claim_id,canonical_domain,state,version) VALUES($1,$2,$3,$4,'requested',1) ON CONFLICT DO NOTHING`, string(b.TenantID), string(c.org.ID), string(claim.ID), claim.Domain)
	} else {
		n, e = w.Exec(ctx, `UPDATE organization.domain_claims SET state='withdrawn',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 AND canonical_domain=$4 AND state='requested' AND version=$5::numeric`, string(b.TenantID), string(c.org.ID), string(claim.ID), claim.Domain, strconv.FormatUint(claim.Version, 10))
	}
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, e = w.Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615 AND state='active'`, string(b.TenantID), string(c.org.ID), strconv.FormatUint(c.org.Version, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func (p *Contributor) requireDomainOrganization(ctx context.Context, w kernel.Work, c nativeCommand, expected uint64) error {
	b := c.spec.Binding
	var version, state string
	rows, e := w.Query(ctx, `SELECT version::text,state FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state); e != nil {
		return e
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if version != strconv.FormatUint(expected, 10) {
		return identity.ConflictError{}
	}
	actor, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if actor != c.actor || !actor.Active || actor.Role != organization.RoleOwner && actor.Role != organization.RoleAdministrator {
		return identity.ForbiddenError{}
	}
	scope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, actor.UserID)
	if e != nil {
		return e
	}
	return authorityError(authority.RequireAuthority(ctx, w, scope, actor.AuthorizationVersion, p.config.Session.MaximumDuration))
}

func (p *Contributor) checkDomainCommit(ctx context.Context, w kernel.Work, c nativeCommand) error {
	if e := p.requireDomainOrganization(ctx, w, c, c.org.Version+1); e != nil {
		return e
	}
	state, version := string(organization.DomainRequested), uint64(1)
	if c.operation == organization.WithdrawDomain {
		state, version = string(organization.DomainWithdrawn), c.domainClaim.Version+1
	}
	var domain, currentState, currentVersion string
	rows, e := w.Query(ctx, `SELECT canonical_domain,state,version::text FROM organization.domain_claims WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 FOR UPDATE`, string(c.spec.Binding.TenantID), string(c.org.ID), string(c.domainClaim.ID))
	if e = one(rows, e, &domain, &currentState, &currentVersion); e != nil {
		return e
	}
	if domain != c.domainClaim.Domain || state != currentState || currentVersion != strconv.FormatUint(version, 10) {
		return identity.ConflictError{}
	}
	return nil
}
