package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

func (s *Service) GetTeam(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.GetTeam(ctx, r)
}
func (s *Service) PrepareUpdateTeam(ctx context.Context, r organization.UpdateTeamRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareUpdateTeam(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareDeleteTeam(ctx context.Context, r organization.DeleteTeamRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareDeleteTeam(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}

// The caller holds the original tenant, organization and actor authority locks.
// Team deletion follows lifecycle.cascade.team_delete: the organization epoch
// and absence of the live row deny all bindings without per-member fan-out.
func (p *Contributor) changeTeam(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var name, version string
	rows, e := w.Query(ctx, `SELECT name,version::text FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.team.ID))
	if e = one(rows, e, &name, &version); e != nil {
		return e
	}
	if version != strconv.FormatUint(c.team.Version, 10) {
		return identity.ConflictError{}
	}
	if c.operation == organization.UpdateTeam {
		if name == c.team.Name {
			return identity.ConflictError{}
		}
		n, e := w.Exec(ctx, `UPDATE organization.teams SET name=$4,version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND version=$5::numeric AND version<18446744073709551615`, string(b.TenantID), string(c.org.ID), string(c.team.ID), c.team.Name, version)
		if e != nil {
			return e
		}
		if n != 1 {
			return identity.ConflictError{}
		}
		return nil
	}
	if name != c.team.Name {
		return identity.ConflictError{}
	}
	n, e := w.Exec(ctx, `UPDATE organization.team_identities SET deleted_version=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND deleted_version IS NULL`, string(b.TenantID), string(c.org.ID), string(c.team.ID), strconv.FormatUint(c.team.Version+1, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, e = w.Exec(ctx, `DELETE FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND version=$4::numeric`, string(b.TenantID), string(c.org.ID), string(c.team.ID), version)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
