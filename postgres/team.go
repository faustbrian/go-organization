package postgres

import (
	"context"
	"strconv"
	"strings"
	"unicode/utf8"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/jackc/pgx/v5"
)

func isTeamMutation(op organization.Operation) bool {
	return op == organization.CreateTeam || op == organization.AddTeamMember || op == organization.RemoveTeamMember
}
func isTeamOperation(op organization.Operation) bool {
	return isTeamMutation(op) || op == organization.ListTeams || op == organization.ListMyTeams || op == organization.ListTeamMembers
}
func boundedTeamName(name string) bool {
	if len(name) < 1 || len(name) > 256 || !utf8.ValidString(name) || strings.TrimSpace(name) != name {
		return false
	}
	for _, r := range name {
		if r < ' ' || r == 127 {
			return false
		}
	}
	return true
}

// Public team operations use exactly the existing admission, native plan and
// one-command coordinator. No team store or transaction glue is caller-written.
func (s *Service) PrepareCreateTeam(ctx context.Context, r organization.CreateTeamRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareCreateTeam(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareAddTeamMember(ctx context.Context, r organization.TeamMemberRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareAddTeamMember(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) PrepareRemoveTeamMember(ctx context.Context, r organization.TeamMemberRequest, network string) (PreparedCommand, error) {
	if s == nil {
		return PreparedCommand{}, organization.ErrInvalidInput
	}
	c, e := s.core.PrepareRemoveTeamMember(ctx, r)
	if e != nil {
		return PreparedCommand{}, e
	}
	return s.prepare(ctx, c, network)
}
func (s *Service) ListTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.ListTeams(ctx, r)
}
func (s *Service) ListMyTeams(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.ListMyTeams(ctx, r)
}
func (s *Service) ListTeamMembers(ctx context.Context, r organization.TeamReadRequest) (organization.View, error) {
	if s == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.core.ListTeamMembers(ctx, r)
}

func (r *Repository) readTeams(ctx context.Context, q organization.Query, v organization.View) (organization.View, error) {
	actorScope, err := OrganizationAuthorityScope(q.TenantID, q.OrganizationID, q.ActorID)
	if err != nil {
		return organization.View{}, err
	}
	store, err := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
	if err != nil {
		return organization.View{}, organization.ErrUnavailable
	}
	current, err := store.Get(ctx, actorScope)
	if err != nil {
		return organization.View{}, publicTeamAuthorityError(err)
	}
	if current.Version != v.Actor.AuthorizationVersion {
		return organization.View{}, organization.ErrForbidden
	}
	bad := func() (organization.View, error) { return organization.View{}, organization.ErrInvalidInput }
	if q.Operation == organization.ListTeams || q.Operation == organization.ListMyTeams || q.Operation == organization.ListTeamMembers {
		if q.Limit < 1 || q.Limit > 100 || q.TeamCursor != "" && !scope(q.TeamCursor) {
			return bad()
		}
	}
	if q.Operation == organization.ListTeams && v.Actor.Role != organization.RoleOwner && v.Actor.Role != organization.RoleAdministrator {
		return organization.View{}, organization.ErrForbidden
	}
	if q.Operation == organization.CreateTeam || q.Operation == organization.AddTeamMember || q.Operation == organization.RemoveTeamMember || q.Operation == organization.ListTeamMembers {
		if !scope(string(q.TeamID)) {
			return bad()
		}
		v.Team = organization.Team{ID: q.TeamID, OrganizationID: q.OrganizationID, TenantID: q.TenantID}
		var version string
		e := r.pool.Raw().QueryRow(ctx, `SELECT name,version::text FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.TeamID)).Scan(&v.Team.Name, &version)
		if e != nil {
			if e == pgx.ErrNoRows && q.Operation == organization.CreateTeam {
				return v, nil
			}
			return organization.View{}, storageError(ctx, e)
		}
		if v.Team.Version, e = positive(version); e != nil {
			return organization.View{}, e
		}
	}
	if q.Operation == organization.CreateTeam {
		return v, nil
	}
	if q.Operation == organization.AddTeamMember || q.Operation == organization.RemoveTeamMember {
		if !scope(string(q.TargetID)) {
			return bad()
		}
		v.Target = organization.Member{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.TargetID}
		var version, epoch string
		e := r.pool.Raw().QueryRow(ctx, `SELECT role,version::text,authorization_version::text,state='active' FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.TargetID)).Scan(&v.Target.Role, &version, &epoch, &v.Target.Active)
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if v.Target.Version, e = positive(version); e != nil {
			return organization.View{}, e
		}
		if v.Target.AuthorizationVersion, e = positive(epoch); e != nil {
			return organization.View{}, e
		}
		v.TargetUser, e = r.directory.Get(ctx, identity.GetUserQuery{TenantID: q.TenantID, UserID: q.TargetID})
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		v.TeamMember = organization.TeamMember{TenantID: q.TenantID, OrganizationID: q.OrganizationID, TeamID: q.TeamID, UserID: q.TargetID}
		e = r.pool.Raw().QueryRow(ctx, `SELECT version::text,organization_member_version::text,state='active' FROM organization.team_memberships WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND user_id=$4`, string(q.TenantID), string(q.OrganizationID), string(q.TeamID), string(q.TargetID)).Scan(&version, &epoch, &v.TeamMember.Active)
		if e == pgx.ErrNoRows {
			return v, nil
		}
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if v.TeamMember.Version, e = positive(version); e != nil {
			return organization.View{}, e
		}
		if v.TeamMember.OrganizationMemberVersion, e = positive(epoch); e != nil {
			return organization.View{}, e
		}
		return v, nil
	}
	if q.Operation == organization.ListTeamMembers {
		var allowed bool
		e := r.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM organization.memberships a JOIN organization.organizations o USING(tenant_id,organization_id) WHERE a.tenant_id=$1 AND a.organization_id=$2 AND a.user_id=$3 AND a.state='active' AND o.state='active' AND (a.role IN('owner','administrator') OR EXISTS(SELECT 1 FROM organization.team_memberships tm WHERE tm.tenant_id=a.tenant_id AND tm.organization_id=a.organization_id AND tm.team_id=$4 AND tm.user_id=a.user_id AND tm.state='active' AND tm.organization_member_version=a.version)))`, string(q.TenantID), string(q.OrganizationID), string(q.ActorID), string(q.TeamID)).Scan(&allowed)
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if !allowed {
			return organization.View{}, organization.ErrForbidden
		}
		rows, e := r.pool.Raw().Query(ctx, `SELECT tm.user_id,tm.version::text,tm.organization_member_version::text FROM organization.team_memberships tm JOIN organization.memberships m USING(tenant_id,organization_id,user_id) WHERE tm.tenant_id=$1 AND tm.organization_id=$2 AND tm.team_id=$3 AND tm.state='active' AND m.state='active' AND tm.organization_member_version=m.version AND tm.user_id>$4 COLLATE "C" ORDER BY tm.user_id COLLATE "C" LIMIT $5`, string(q.TenantID), string(q.OrganizationID), string(q.TeamID), q.TeamCursor, int32(q.Limit+1))
		if e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		defer rows.Close()
		for rows.Next() {
			m := organization.TeamMember{TenantID: q.TenantID, OrganizationID: q.OrganizationID, TeamID: q.TeamID, Active: true}
			var version, epoch string
			if e = rows.Scan(&m.UserID, &version, &epoch); e != nil {
				return organization.View{}, storageError(ctx, e)
			}
			if m.Version, e = positive(version); e != nil {
				return organization.View{}, e
			}
			if m.OrganizationMemberVersion, e = positive(epoch); e != nil {
				return organization.View{}, e
			}
			if len(v.TeamMembers) == int(q.Limit) {
				v.NextTeamCursor = string(v.TeamMembers[len(v.TeamMembers)-1].UserID)
				break
			}
			v.TeamMembers = append(v.TeamMembers, m)
		}
		if e = rows.Err(); e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		return v, nil
	}
	rows, e := r.pool.Raw().Query(ctx, `SELECT t.team_id,t.name,t.version::text FROM organization.teams t WHERE t.tenant_id=$1 AND t.organization_id=$2 AND t.team_id>$3 COLLATE "C" AND ($4 OR EXISTS(SELECT 1 FROM organization.team_memberships tm JOIN organization.memberships m USING(tenant_id,organization_id,user_id) WHERE tm.tenant_id=t.tenant_id AND tm.organization_id=t.organization_id AND tm.team_id=t.team_id AND tm.user_id=$5 AND tm.state='active' AND m.state='active' AND tm.organization_member_version=m.version)) ORDER BY t.team_id COLLATE "C" LIMIT $6`, string(q.TenantID), string(q.OrganizationID), q.TeamCursor, q.Operation == organization.ListTeams, string(q.ActorID), int32(q.Limit+1))
	if e != nil {
		return organization.View{}, storageError(ctx, e)
	}
	defer rows.Close()
	for rows.Next() {
		t := organization.Team{TenantID: q.TenantID, OrganizationID: q.OrganizationID}
		var version string
		if e = rows.Scan(&t.ID, &t.Name, &version); e != nil {
			return organization.View{}, storageError(ctx, e)
		}
		if t.Version, e = positive(version); e != nil {
			return organization.View{}, e
		}
		if len(v.Teams) == int(q.Limit) {
			v.NextTeamCursor = string(v.Teams[len(v.Teams)-1].ID)
			break
		}
		v.Teams = append(v.Teams, t)
	}
	if e = rows.Err(); e != nil {
		return organization.View{}, storageError(ctx, e)
	}
	return v, nil
}

func (p *Contributor) mutateTeam(ctx context.Context, w kernel.Work, c nativeCommand) error {
	b := c.spec.Binding
	var version, state string
	rows, e := w.Query(ctx, `SELECT version::text,state FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, string(b.TenantID), string(c.org.ID))
	if e = one(rows, e, &version, &state); e != nil {
		return e
	}
	v, e := positive(version)
	if e != nil {
		return e
	}
	if state != "active" {
		return identity.ForbiddenError{}
	}
	if v != c.org.Version {
		return identity.ConflictError{}
	}
	actor, e := readMember(ctx, w, b.TenantID, c.org.ID, identity.UserID(b.ActorID))
	if e != nil {
		return e
	}
	if !actor.Active || actor != c.actor || actor.Role != organization.RoleOwner && actor.Role != organization.RoleAdministrator {
		return identity.ForbiddenError{}
	}
	actorScope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, actor.UserID)
	if e != nil {
		return e
	}
	if e = authority.RequireAuthority(ctx, w, actorScope, actor.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
		return authorityError(e)
	}
	if c.operation == organization.CreateTeam {
		var count int64
		var duplicate bool
		rows, e = w.Query(ctx, `SELECT count(*),coalesce(bool_or(team_id=$3),false) FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2`, string(b.TenantID), string(c.org.ID), string(c.team.ID))
		if e = one(rows, e, &count, &duplicate); e != nil {
			return e
		}
		if duplicate {
			return identity.ConflictError{}
		}
		if count < 0 {
			return identity.UnavailableError{}
		}
		if uint64(count) >= p.config.Teams.MaximumTeams {
			return identity.ForbiddenError{}
		}
		if _, e = w.Exec(ctx, `INSERT INTO organization.teams(tenant_id,organization_id,team_id,name,version) VALUES($1,$2,$3,$4,1)`, string(b.TenantID), string(c.org.ID), string(c.team.ID), c.team.Name); e != nil {
			return e
		}
	} else {
		var name string
		rows, e = w.Query(ctx, `SELECT name,version::text FROM organization.teams WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.team.ID))
		if e = one(rows, e, &name, &version); e != nil {
			return e
		}
		if version != strconv.FormatUint(c.team.Version, 10) || name != c.team.Name {
			return identity.ConflictError{}
		}
		target, e := readMember(ctx, w, b.TenantID, c.org.ID, b.UserID)
		if e != nil {
			return e
		}
		expected := c.target
		expected.Active = true
		if !target.Active || target != expected {
			return identity.ForbiddenError{}
		}
		targetScope, e := OrganizationAuthorityScope(b.TenantID, c.org.ID, target.UserID)
		if e != nil {
			return e
		}
		if e = authority.RequireAuthority(ctx, w, targetScope, target.AuthorizationVersion, p.config.Session.MaximumDuration); e != nil {
			return authorityError(e)
		}
		var actualVersion, actualOrgVersion uint64
		var active bool
		rows, e = w.Query(ctx, `SELECT version::text,organization_member_version::text,state='active' FROM organization.team_memberships WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND user_id=$4 FOR UPDATE`, string(b.TenantID), string(c.org.ID), string(c.team.ID), string(b.UserID))
		if e != nil {
			return e
		}
		if rows.Next() {
			var a, o string
			if e = rows.Scan(&a, &o, &active); e != nil {
				rows.Close()
				return e
			}
			if actualVersion, e = positive(a); e != nil {
				rows.Close()
				return e
			}
			if actualOrgVersion, e = positive(o); e != nil {
				rows.Close()
				return e
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if actualVersion != c.teamMember.Version || actualOrgVersion != c.teamMember.OrganizationMemberVersion {
			return identity.ConflictError{}
		}
		current := active && actualOrgVersion == target.Version
		if c.operation == organization.AddTeamMember {
			if current {
				return identity.ConflictError{}
			}
			var count int64
			rows, e = w.Query(ctx, `SELECT count(*) FROM organization.team_memberships tm JOIN organization.memberships m USING(tenant_id,organization_id,user_id) WHERE tm.tenant_id=$1 AND tm.organization_id=$2 AND tm.team_id=$3 AND tm.state='active' AND m.state='active' AND tm.organization_member_version=m.version`, string(b.TenantID), string(c.org.ID), string(c.team.ID))
			if e = one(rows, e, &count); e != nil {
				return e
			}
			if count < 0 {
				return identity.UnavailableError{}
			}
			if uint64(count) >= p.config.Teams.MaximumMembers {
				return identity.ForbiddenError{}
			}
			_, e = w.Exec(ctx, `INSERT INTO organization.team_memberships(tenant_id,organization_id,team_id,user_id,state,version,organization_member_version) VALUES($1,$2,$3,$4,'active',$5::numeric,$6::numeric) ON CONFLICT(tenant_id,organization_id,team_id,user_id) DO UPDATE SET state='active',version=EXCLUDED.version,organization_member_version=EXCLUDED.organization_member_version`, string(b.TenantID), string(c.org.ID), string(c.team.ID), string(b.UserID), strconv.FormatUint(actualVersion+1, 10), strconv.FormatUint(target.Version, 10))
		} else {
			if !current {
				return identity.ForbiddenError{}
			}
			_, e = w.Exec(ctx, `UPDATE organization.team_memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND user_id=$4`, string(b.TenantID), string(c.org.ID), string(c.team.ID), string(b.UserID))
		}
		if e != nil {
			return e
		}
		// The lifecycle.cascade.team_change contract advances the one directly
		// changed subject's existing scoped authorization epoch as well as the
		// organization policy epoch; it creates no role or permission authority.
		next, e := authority.AdvanceAuthority(ctx, w, targetScope, target.AuthorizationVersion, p.config.Session.MaximumDuration)
		if e != nil {
			return authorityError(e)
		}
		if _, e = w.Exec(ctx, `UPDATE organization.memberships SET authorization_version=$4::numeric WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(b.TenantID), string(c.org.ID), string(b.UserID), strconv.FormatUint(next.Version, 10)); e != nil {
			return e
		}
		n, e := w.Exec(ctx, `UPDATE organization.teams SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND team_id=$3 AND version=$4::numeric AND version<18446744073709551615`, string(b.TenantID), string(c.org.ID), string(c.team.ID), strconv.FormatUint(c.team.Version, 10))
		if e != nil {
			return e
		}
		if n != 1 {
			return identity.ConflictError{}
		}
	}
	// The shared epoch is the authority fence required by the organization goal:
	// no team binding mutates independent role/permission or session authority.
	n, e := w.Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND version<18446744073709551615`, string(b.TenantID), string(c.org.ID), strconv.FormatUint(c.org.Version, 10))
	if e != nil {
		return e
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}

func publicTeamAuthorityError(err error) error {
	if err == authority.ErrAuthorityDenied || err == authority.ErrAuthorityConflict || err == authority.ErrAuthorityOverflow {
		return organization.ErrForbidden
	}
	if err == context.Canceled || err == context.DeadlineExceeded {
		return err
	}
	return organization.ErrUnavailable
}
