//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Credentials here are issued by the actual signup/verification/signin journey
// in TestOrganizationGenuinePasswordConsumer, never a private session/store.
func exerciseGenuineTeams(t *testing.T, ctx context.Context, db *sql.DB, s *organizationpg.Service, owner, member, recoveryOwner organization.Authentication, memberID identity.UserID) {
	t.Helper()
	var steps migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}} {
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
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("genuine populated team upgrade", e)
	}
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	org := organization.ID(id)
	id, e = identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	team := organization.ID(id)
	commit := func(p organizationpg.PreparedCommand, e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
		if got, e := s.Execute(ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine team consumer mutation", e)
		}
	}
	commit(s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Genuine teams", Slug: "genuine-teams", CorrelationID: "teams"}, "127.0.0.1"))
	commit(s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: organization.RoleMember, CorrelationID: "teams"}, "127.0.0.1"))
	created, err := s.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, TeamID: team, Name: "Engineering", CorrelationID: "teams"}, "127.0.0.1")
	commit(created, err)
	// A separately issued genuine session may recover the same actor's exact
	// historical result; preparation's original bearer is not recovery custody.
	if recoveryOwner.Bearer.Token() == owner.Bearer.Token() {
		t.Fatal("recovery did not exercise another legitimate session")
	}
	handle, err := created.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	retained, err := s.Recover(ctx, recoveryOwner, handle)
	if err != nil || retained.Receipt.Outcome != identity.CommitOutcomeCommitted || retained.Receipt.Binding != handle.Binding {
		t.Fatal("genuine fresh-session team recovery", err)
	}
	q := organization.TeamReadRequest{Authentication: owner, OrganizationID: org, Limit: 10, CorrelationID: "teams"}
	v, e := s.ListTeams(ctx, q)
	if e != nil || len(v.Teams) != 1 || v.Teams[0].ID != team {
		t.Fatal("genuine team primary list", e)
	}
	q.Authentication = member
	q.TeamID = team
	if _, e = s.ListTeamMembers(ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("org member was implicitly team member", e)
	}
	r := organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, TeamID: team, TeamVersion: 1, UserID: memberID, OrganizationMemberVersion: 1, CorrelationID: "teams"}
	commit(s.PrepareAddTeamMember(ctx, r, "127.0.0.1"))
	v, e = s.ListTeamMembers(ctx, q)
	if e != nil || len(v.TeamMembers) != 1 || v.TeamMembers[0].UserID != memberID {
		t.Fatal("genuine team member list", e)
	}
	q.TeamID = ""
	v, e = s.ListMyTeams(ctx, q)
	if e != nil || len(v.Teams) != 1 || v.Organization.Version != 4 {
		t.Fatal("genuine mine list", e)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 4
	r.TeamVersion = 2
	r.MembershipVersion = 1
	commit(s.PrepareRemoveTeamMember(ctx, r, "127.0.0.1"))
	q.TeamID = team
	if _, e = s.ListTeamMembers(ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine removed member retained access", e)
	}
	// Re-admit the actual organization member before terminal team deletion so
	// the deletion assertion cannot pass merely because the binding was removed.
	r.CommandID = commandID(t)
	r.OrganizationVersion = 5
	r.TeamVersion = 3
	r.MembershipVersion = 2
	commit(s.PrepareAddTeamMember(ctx, r, "127.0.0.1"))
	ownerRead := organization.TeamReadRequest{Authentication: owner, OrganizationID: org, TeamID: team, CorrelationID: "team-management"}
	exact, e := s.GetTeam(ctx, ownerRead)
	if e != nil || exact.Team.Version != 4 || exact.Organization.Version != 6 {
		t.Fatal("genuine exact team", e)
	}
	commit(s.PrepareUpdateTeam(ctx, organization.UpdateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, TeamID: team, OrganizationVersion: 6, TeamVersion: 4, Name: "Platform", CorrelationID: "team-management"}, "127.0.0.1"))
	exact, e = s.GetTeam(ctx, ownerRead)
	if e != nil || exact.Team.Name != "Platform" || exact.Team.Version != 5 {
		t.Fatal("genuine team name update", e)
	}
	if listed, e := s.ListTeamMembers(ctx, q); e != nil || len(listed.TeamMembers) != 1 {
		t.Fatal("genuine member absent before deletion", e)
	}
	deleted, e := s.PrepareDeleteTeam(ctx, organization.DeleteTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, TeamID: team, OrganizationVersion: 7, TeamVersion: 5, CorrelationID: "team-management"}, "127.0.0.1")
	commit(deleted, e)
	if _, e = s.GetTeam(ctx, ownerRead); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine deleted team still accessible", e)
	}
	if _, e = s.ListTeamMembers(ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine former member retained deleted team", e)
	}
	handle, e = deleted.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	retained, e = s.Recover(ctx, recoveryOwner, handle)
	if e != nil || retained.Receipt.Outcome != identity.CommitOutcomeCommitted || retained.Receipt.Binding != handle.Binding {
		t.Fatal("genuine terminal deletion recovery", e)
	}
}
