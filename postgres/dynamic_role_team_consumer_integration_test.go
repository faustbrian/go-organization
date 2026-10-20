//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestOrganizationGenuineTeamRoleConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "team-role")
}

// Every bearer below is issued by the real signup/verification/password-signin
// journey. The controlled external seams remain delivery and HIBP only.
func exerciseGenuineTeamDynamicRoles(t *testing.T, ctx context.Context, db *sql.DB, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID, fresh func() *organizationpg.Service) {
	t.Helper()
	var steps migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}, organizationpg.DynamicRoleMigrationSource{Version: 7010}, organizationpg.TeamRoleBindingMigrationSource{Version: 7011}} {
		more, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		steps = append(steps, more...)
	}
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	backend, e = backend.ForNamespace("organization")
	if e != nil {
		t.Fatal(e)
	}
	runner, e := migrations.NewRunner(steps, backend)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("populated team-role migration", e)
		}
	}
	newID := func() organization.ID {
		t.Helper()
		id, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		return organization.ID(id)
	}
	org, team, role := newID(), newID(), newID()
	commit := func(p organizationpg.PreparedCommand, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		if got, e := s.Execute(ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine team-role commit", e)
		}
	}
	orgView := func() organization.View {
		t.Helper()
		v, e := s.Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "team-role"})
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Slug: "genuine-team-roles", Name: "Genuine team roles", CorrelationID: "team-role"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: orgView().Organization.Version, UserID: memberID, Role: organization.RoleMember, CorrelationID: "team-role"}, "127.0.0.1"))
	commit(s.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: orgView().Organization.Version, TeamID: team, Name: "Engineering", CorrelationID: "team-role"}, "127.0.0.1"))
	commit(s.PrepareCreateDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: orgView().Organization.Version, RoleID: role, Name: "Document reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "team-role"}, "127.0.0.1"))
	q := organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: org, RoleID: role, TargetTeamID: team, CorrelationID: "team-role"}
	current := func() organization.View {
		t.Helper()
		v, e := s.GetDynamicRole(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	userRead := q
	userRead.TargetTeamID = ""
	userRead.TargetUserID = memberID
	u, e := s.GetDynamicRole(ctx, userRead)
	if e != nil {
		t.Fatal(e)
	}
	v := current()
	commit(s.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, UserID: memberID, OrganizationMemberVersion: u.Target.Version, CorrelationID: "team-role"}, "127.0.0.1"))
	request := func(v organization.View) organization.TeamRoleBindingRequest {
		return organization.TeamRoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: org, TeamID: team, RoleID: role, OrganizationVersion: v.Organization.Version, TeamVersion: v.Team.Version, RoleVersion: v.DynamicRole.Version, BindingVersion: v.TeamRoleBinding.Version, CorrelationID: "team-role"}
	}
	check := func(want authorization.Outcome) {
		t.Helper()
		d, e := s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member, OrganizationID: org, OrganizationVersion: orgView().Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-role"})
		if e != nil || d.Outcome != want {
			t.Fatalf("genuine team effective permission: %+v %v", d, e)
		}
	}
	v = current()
	if v.TeamRoleBinding.Version != 0 || v.TeamRoleBinding.Active {
		t.Fatal("genuine team binding was not initially absent")
	}
	stale := v.Organization.Version
	assigned, e := s.PrepareAssignTeamDynamicRole(ctx, request(v), "127.0.0.1")
	commit(assigned, e)
	check(authorization.Allow)
	if _, e = s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member, OrganizationID: org, OrganizationVersion: stale, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "stale-team-role"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("warm stale policy allowed team role", e)
	}
	warm := s
	s = fresh()
	q.Authentication = recoveryOwner
	v = current()
	if !v.TeamRoleBinding.Active {
		t.Fatal("fresh genuine client cannot discover team assignment")
	}
	commit(s.PrepareRevokeTeamDynamicRole(ctx, request(v), "127.0.0.1"))
	check(authorization.Deny)
	s = warm
	check(authorization.Deny)
	s = fresh()
	v = current()
	if v.TeamRoleBinding.Active || v.TeamRoleBinding.Version == 0 {
		t.Fatal("fresh genuine client cannot discover team binding tombstone")
	}
	commit(s.PrepareAssignTeamDynamicRole(ctx, request(v), "127.0.0.1"))
	check(authorization.Allow)
	teamMember := func() organization.TeamMember {
		t.Helper()
		members, e := s.ListTeamMembers(ctx, organization.TeamReadRequest{Authentication: owner, OrganizationID: org, TeamID: team, Limit: 10, CorrelationID: "team-role"})
		if e != nil || len(members.TeamMembers) != 1 || members.TeamMembers[0].UserID != memberID {
			t.Fatal("genuine current team admission missing", e)
		}
		return members.TeamMembers[0]
	}
	tm := teamMember()
	v = current()
	commit(s.PrepareRemoveTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, UserID: memberID, OrganizationMemberVersion: tm.OrganizationMemberVersion, MembershipVersion: tm.Version, CorrelationID: "team-role"}, "127.0.0.1"))
	check(authorization.Deny)
	v = current()
	// Membership tombstones use the existing retained-command contract; only
	// team-role binding discovery is the fresh-client contract selected here.
	commit(s.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, UserID: memberID, OrganizationMemberVersion: tm.OrganizationMemberVersion, MembershipVersion: tm.Version + 1, CorrelationID: "team-role"}, "127.0.0.1"))
	check(authorization.Allow)
	tm = teamMember()
	u, e = s.GetDynamicRole(ctx, userRead)
	if e != nil {
		t.Fatal(e)
	}
	commit(s.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: u.Organization.Version, UserID: memberID, MemberVersion: u.Target.Version, CorrelationID: "team-role"}, "127.0.0.1"))
	if _, e = s.CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: member, OrganizationID: org, OrganizationVersion: orgView().Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-role"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine removed org member retained team authority", e)
	}
	u, e = s.GetDynamicRole(ctx, userRead)
	if e != nil || u.Target.Active {
		t.Fatal("genuine removed member snapshot missing", e)
	}
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: u.Organization.Version, UserID: memberID, MemberVersion: u.Target.Version, Role: organization.RoleMember, CorrelationID: "team-role"}, "127.0.0.1"))
	check(authorization.Deny)
	u, e = s.GetDynamicRole(ctx, userRead)
	if e != nil {
		t.Fatal(e)
	}
	v = current()
	commit(s.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, UserID: memberID, OrganizationMemberVersion: u.Target.Version, MembershipVersion: tm.Version, CorrelationID: "team-role"}, "127.0.0.1"))
	check(authorization.Allow)
	v = current()
	commit(s.PrepareDeleteTeam(ctx, organization.DeleteTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: v.Organization.Version, TeamID: team, TeamVersion: v.Team.Version, CorrelationID: "team-role"}, "127.0.0.1"))
	check(authorization.Deny)
	handle := mustRoleRecovery(t, assigned)
	got, e := s.Recover(ctx, recoveryOwner, handle)
	if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
		t.Fatal("genuine original team-role recovery", e)
	}
}
