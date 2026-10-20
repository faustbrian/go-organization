package postgres

import (
	"context"
	"math"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	"github.com/jackc/pgx/v5"
)

// TeamRoleBindingMigrationSource adds bounded retained team-role assignments.
// Install after DynamicRoleMigrationSource and TeamLifecycleMigrationSource.
// Its team foreign key references terminal identities, not deletable live rows;
// deleting a team therefore denies all derived authority without per-user fan-out.
type TeamRoleBindingMigrationSource struct{ Version migrations.Version }

func (s TeamRoleBindingMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_team_roles", migrations.TransactionModeDefault, teamRoleSchemaSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const teamRoleSchemaSQL = `CREATE TABLE organization.team_role_bindings(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 role_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 state text NOT NULL CHECK(state IN('active','removed')),
 PRIMARY KEY(tenant_id,organization_id,team_id,role_id),
 FOREIGN KEY(tenant_id,organization_id,team_id) REFERENCES organization.team_identities(tenant_id,organization_id,team_id),
 FOREIGN KEY(tenant_id,organization_id,role_id) REFERENCES organization.custom_roles(tenant_id,organization_id,role_id)
);
CREATE INDEX organization_team_role_effective ON organization.team_role_bindings(tenant_id,organization_id,role_id,team_id) WHERE state='active';`

// PrepareAssignTeamDynamicRole uses the existing role.assign action, native
// protected counters and one coordinator; the command explicitly tags its team.
func (s *Service) PrepareAssignTeamDynamicRole(ctx context.Context, r organization.TeamRoleBindingRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareAssignTeamDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}

// PrepareRevokeTeamDynamicRole removes one exact team-targeted role assignment.
func (s *Service) PrepareRevokeTeamDynamicRole(ctx context.Context, r organization.TeamRoleBindingRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareRevokeTeamDynamicRole(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}

func (r *Repository) readTeamRoleBinding(ctx context.Context, q organization.Query, v organization.View) (organization.View, error) {
	if !scope(string(q.TeamID)) || q.TargetID != "" {
		return organization.View{}, organization.ErrInvalidInput
	}
	v.Team = organization.Team{ID: q.TeamID, OrganizationID: q.OrganizationID, TenantID: q.TenantID}
	var version string
	e := r.pool.Raw().QueryRow(ctx, `SELECT t.name,t.version::text FROM organization.teams t JOIN organization.team_identities i USING(tenant_id,organization_id,team_id) WHERE t.tenant_id=$1 AND t.organization_id=$2 AND t.team_id=$3 AND i.deleted_version IS NULL`, string(q.TenantID), string(q.OrganizationID), string(q.TeamID)).Scan(&v.Team.Name, &version)
	if e != nil {
		return organization.View{}, storageError(ctx, e)
	}
	if v.Team.Version, e = positive(version); e != nil {
		return organization.View{}, e
	}
	v.TeamRoleBinding = organization.TeamRoleBinding{TeamID: q.TeamID, RoleID: q.DynamicRoleID, OrganizationID: q.OrganizationID, TenantID: q.TenantID}
	e = r.pool.Raw().QueryRow(ctx, `SELECT version::text,state='active' FROM organization.team_role_bindings WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND role_id=$4`, string(q.TenantID), string(q.OrganizationID), string(q.TeamID), string(q.DynamicRoleID)).Scan(&version, &v.TeamRoleBinding.Active)
	if e == pgx.ErrNoRows {
		return v, nil
	}
	if e != nil {
		return organization.View{}, storageError(ctx, e)
	}
	if v.TeamRoleBinding.Version, e = positive(version); e != nil {
		return organization.View{}, e
	}
	return v, nil
}

func (p *Contributor) decodeTeamRole(c *nativeCommand, t func(string) string, n func(string) uint64) error {
	b := c.spec.Binding
	if !isRoleBindingMutation(c.operation) || p.config.DynamicRoles.TeamBindingsVersion != 1 || p.config.Teams.LifecycleVersion != 1 || !scope(t("team-role-id")) || !boundedTeamName(t("team-role-name")) || n("team-role-version") == 0 || n("team-role-version") == ^uint64(0) || n("binding-member-version") != 0 || c.target.Version != 0 || c.target.AuthorizationVersion != 0 || c.target.Role != "" || c.user.Version != 0 || c.user.Status != "" || b.UserID != identity.UserID(b.ActorID) || len(c.dynamicRole.Statements) != 0 || c.operation == organization.RevokeDynamicRole && n("binding-version") == 0 {
		return organization.ErrInvalidInput
	}
	c.team = organization.Team{ID: organization.ID(t("team-role-id")), OrganizationID: c.org.ID, TenantID: b.TenantID, Name: t("team-role-name"), Version: n("team-role-version")}
	c.teamRoleBinding = organization.TeamRoleBinding{RoleID: c.dynamicRole.ID, TeamID: c.team.ID, OrganizationID: c.org.ID, TenantID: b.TenantID, Version: n("binding-version")}
	c.roleBinding = organization.RoleBinding{}
	return nil
}

// The existing caller holds tenant/organization/actor/role locks. Team.Version
// is the team's shared subject epoch; organization policy fences every member.
// No stale session/cache decision is admitted and no per-member grant is copied.
func (p *Contributor) mutateTeamRoleBinding(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var name, version string
	rows, e := w.Query(ctx, `SELECT name,version::text FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.team.ID))
	if e = one(rows, e, &name, &version); e != nil {
		return e
	}
	if version != strconv.FormatUint(c.team.Version, 10) || name != c.team.Name {
		return identity.ConflictError{}
	}
	var active bool
	var stored string
	rows, e = w.Query(ctx, `SELECT version::text,state='active' FROM organization.team_role_bindings WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND role_id=$4 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.team.ID), string(c.dynamicRole.ID))
	if e != nil {
		return e
	}
	found := rows.Next()
	if found {
		e = rows.Scan(&stored, &active)
	}
	if rowErr := rows.Err(); e == nil {
		e = rowErr
	}
	rows.Close()
	if e != nil {
		return e
	}
	if found && stored != strconv.FormatUint(c.teamRoleBinding.Version, 10) || !found && c.teamRoleBinding.Version != 0 {
		return identity.ConflictError{}
	}
	if c.operation == organization.AssignDynamicRole && active {
		return identity.ConflictError{}
	}
	if c.operation == organization.RevokeDynamicRole && !active {
		return identity.ForbiddenError{}
	}
	state := "active"
	if c.operation == organization.RevokeDynamicRole {
		state = "removed"
	}
	n, e := w.Exec(ctx, `INSERT INTO organization.team_role_bindings(tenant_id,organization_id,team_id,role_id,version,state) VALUES($1,$2,$3,$4,$5::numeric,$6) ON CONFLICT(tenant_id,organization_id,team_id,role_id) DO UPDATE SET version=EXCLUDED.version,state=EXCLUDED.state WHERE organization.team_role_bindings.version=$7::numeric`, string(b.TenantID), string(c.org.ID), string(c.team.ID), string(c.dynamicRole.ID), strconv.FormatUint(c.teamRoleBinding.Version+1, 10), state, strconv.FormatUint(c.teamRoleBinding.Version, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, e = w.Exec(ctx, `UPDATE organization.teams SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND version=$4::numeric AND version<18446744073709551615`, string(b.TenantID), string(c.org.ID), string(c.team.ID), version)
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

// Select each role once, regardless of direct plus multiple-team paths. The
// existing engine therefore sees the complete allow/deny set without duplicate
// role identities, and exact live membership epochs deny removal/readmission.
const effectiveTeamRolesSQL = `SELECT r.role_id,r.name,r.version::text,r.statements FROM organization.custom_roles r
 WHERE r.tenant_id=$1 AND r.organization_id=$2 AND r.state='active' AND r.role_id>$3 COLLATE "C" AND
 ($4 OR EXISTS(SELECT 1 FROM organization.role_bindings b JOIN organization.memberships m USING(tenant_id,organization_id,user_id)
 WHERE b.tenant_id=r.tenant_id AND b.organization_id=r.organization_id AND b.role_id=r.role_id AND b.user_id=$5 AND b.state='active' AND m.state='active' AND b.organization_member_version=m.version)
 OR EXISTS(SELECT 1 FROM organization.team_role_bindings b JOIN organization.teams t USING(tenant_id,organization_id,team_id)
 JOIN organization.team_identities ti USING(tenant_id,organization_id,team_id)
 JOIN organization.team_memberships tm USING(tenant_id,organization_id,team_id)
 JOIN organization.memberships m ON m.tenant_id=tm.tenant_id AND m.organization_id=tm.organization_id AND m.user_id=tm.user_id
 WHERE b.tenant_id=r.tenant_id AND b.organization_id=r.organization_id AND b.role_id=r.role_id AND b.state='active'
 AND ti.deleted_version IS NULL AND tm.user_id=$5 AND tm.state='active' AND m.state='active' AND tm.organization_member_version=m.version))
 ORDER BY r.role_id COLLATE "C" LIMIT $6`
