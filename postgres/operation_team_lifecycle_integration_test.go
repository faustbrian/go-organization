//go:build integration

package postgres_test

import (
	"errors"
	"reflect"
	"testing"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func teamLifecycleOperationFixture(t *testing.T, optional bool) *orgFixture {
	t.Helper()
	f := teamCreateOperationFixture(t)
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("team_lifecycle_operation")
	if err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.TeamLifecycleMigrationSource{Version: 304}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.teams.LifecycleVersion = 1
	f.compose(t)
	if optional {
		installTeamDeleteOperationMigration(t, f)
	}
	return f
}
func installTeamDeleteOperationMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("team_delete_operation")
	if err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.TeamDeleteOperationLookupMigrationSource{Version: 322}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
}
func teamLifecycleOperationRequest(t *testing.T, f *orgFixture) organization.UpdateTeamOperationRequest {
	t.Helper()
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	p, err := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	key, err := identity.NewIdempotencyKey([]byte("original-team-rename"))
	if err != nil {
		t.Fatal(err)
	}
	return organization.UpdateTeamOperationRequest{Authentication: f.auth(tenant, "owner"), IdempotencyKey: key, OrganizationID: metadataOrganization, TeamID: "engineering", OrganizationVersion: 4, TeamVersion: 2, Name: "Platform", CorrelationID: "team-lifecycle-operation"}
}
func teamDeleteOperationRequest(r organization.UpdateTeamOperationRequest) organization.DeleteTeamOperationRequest {
	return organization.DeleteTeamOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion + 1, TeamVersion: r.TeamVersion + 1, CorrelationID: "natural-team-delete"}
}

func TestTeamLifecycleOperationOriginalRenameAndTerminalDelete(t *testing.T) {
	f := teamLifecycleOperationFixture(t, true)
	r := teamLifecycleOperationRequest(t, f)
	s := slugNativeOperationService(t, f.service)
	renamed, err := s.UpdateTeam(f.ctx, r, "127.0.0.1")
	if err != nil || renamed.Receipt.Outcome != identity.CommitOutcomeCommitted || renamed.Receipt.Feature == nil || renamed.Receipt.Feature.BeforeVersion != 4 || renamed.Receipt.Feature.AfterVersion != 5 {
		t.Fatal("original-key rename", err)
	}
	q := organization.TeamReadRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "renamed-member-read"}
	if v, err := s.ListMyTeams(f.ctx, q); err != nil || len(v.Teams) != 1 || v.Teams[0].Name != r.Name || v.Teams[0].ID != r.TeamID || v.Teams[0].Version != 3 {
		t.Fatal("current member did not see exact rename", err)
	}
	q.TeamID = r.TeamID
	if v, err := s.ListTeamMembers(f.ctx, q); err != nil || len(v.TeamMembers) != 1 || v.TeamMembers[0].Version != 1 || v.TeamMembers[0].OrganizationMemberVersion != 1 {
		t.Fatal("rename changed member binding", err)
	}
	if _, err := s.GetTeam(f.ctx, organization.TeamReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, CorrelationID: "exact-renamed-team"}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*organization.UpdateTeamOperationRequest){func(r *organization.UpdateTeamOperationRequest) { r.TeamID = "other" }, func(r *organization.UpdateTeamOperationRequest) { r.OrganizationVersion++ }, func(r *organization.UpdateTeamOperationRequest) { r.TeamVersion++ }, func(r *organization.UpdateTeamOperationRequest) { r.Name = "Different" }} {
		bad := r
		change(&bad)
		if _, err := s.UpdateTeam(f.ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed rename intent adopted original", err)
		}
	}
	x := teamDeleteOperationRequest(r)
	deleted, err := s.DeleteTeam(f.ctx, x, "127.0.0.1")
	if err != nil || deleted.Receipt.Outcome != identity.CommitOutcomeCommitted || deleted.Receipt.Feature == nil || deleted.Receipt.Feature.BeforeVersion != 5 || deleted.Receipt.Feature.AfterVersion != 6 {
		t.Fatal("natural terminal deletion", err)
	}
	for range 2 {
		rebuilt := slugNativeOperationService(t, f.service)
		if out, err := rebuilt.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, renamed) {
			t.Fatal("rename recovery after deletion changed original", err)
		}
		if out, err := rebuilt.DeleteTeam(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
			t.Fatal("natural deletion reconstruction changed original", err)
		}
		if out, err := rebuilt.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: deleted.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, deleted) {
			t.Fatal("explicit terminal deletion history", err)
		}
	}
	if _, err := s.GetTeam(f.ctx, organization.TeamReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, CorrelationID: "deleted-team"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("deleted team remained live", err)
	}
	if _, err := s.ListTeamMembers(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("deleted team retained membership authority", err)
	}
	q.TeamID = ""
	if v, err := s.ListMyTeams(f.ctx, q); err != nil || len(v.Teams) != 0 {
		t.Fatal("deleted team retained own-team view", err)
	}
	var retired, bindings, epoch, effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT deleted_version FROM organization.team_identities WHERE team_id='engineering'),(SELECT count(*) FROM organization.team_memberships WHERE state='active'),(SELECT version FROM organization.organizations),(SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.delete')`).Scan(&retired, &bindings, &epoch, &effects); err != nil || retired != 4 || bindings != 1 || epoch != 6 || effects != 1 {
		t.Fatal("terminal deletion lost retained identity/binding or singleton effects", err)
	}
	for _, change := range []func(*organization.DeleteTeamOperationRequest){func(r *organization.DeleteTeamOperationRequest) { r.TeamID = "other" }, func(r *organization.DeleteTeamOperationRequest) { r.TeamVersion++ }, func(r *organization.DeleteTeamOperationRequest) { r.OrganizationVersion++ }} {
		bad := x
		change(&bad)
		if out, err := s.DeleteTeam(f.ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed deletion selector adopted old success", err)
		}
	}
	reuse := teamCreateRequest(t, f, "org-test-basic", "engineering", "retired-reuse", 6)
	if out, err := s.CreateTeam(f.ctx, reuse, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("retired canonical team ID reused", err)
	}
}

func TestTeamLifecycleOperationWritePermissionWithoutOrganizationRead(t *testing.T) {
	f := teamLifecycleOperationFixture(t, true)
	r := teamLifecycleOperationRequest(t, f)
	s := leaveOperationPolicyFacade(t, f, teamMemberWriteWithoutOrganizationRead{}, nil)
	if _, err := s.Get(f.ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "denied-general-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("org read not actually denied", err)
	}
	// Include the already published creation facade in this sibling permission
	// sweep: its original recovery must use the actual team-write action too.
	createdRequest := teamCreateRequest(t, f, "org-test-basic", "second-team", "write-only-create", 4)
	created, err := s.CreateTeam(f.ctx, createdRequest, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.CreateTeam(f.ctx, createdRequest, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, created) {
		t.Fatal("published CreateTeam recovery required unrelated org read", err)
	}
	r.OrganizationVersion = 5
	renamed, err := s.UpdateTeam(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, renamed) {
		t.Fatal("rename original required unrelated org read", err)
	}
	x := teamDeleteOperationRequest(r)
	deleted, err := s.DeleteTeam(f.ctx, x, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.DeleteTeam(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
		t.Fatal("natural delete required unrelated org read", err)
	}
	for _, original := range []organization.StoreResult{created, renamed, deleted} {
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("explicit team facade recovery required unrelated org read", err)
		}
	}
	config := f.configuration
	config.Authorization = teamMemberWriteWithoutOrganizationRead{}
	legacy, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: created.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("raw legacy recovery changed permission contract", err)
	}
}

func TestTeamLifecycleOperationLegacyDeleteNeedsNoOptionalMigration(t *testing.T) {
	f := teamLifecycleOperationFixture(t, false)
	r := teamLifecycleOperationRequest(t, f)
	p, err := f.service.PrepareDeleteTeam(f.ctx, organization.DeleteTeamRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, CorrelationID: r.CorrelationID}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	installTeamDeleteOperationMigration(t, f)
	x := organization.DeleteTeamOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, CorrelationID: r.CorrelationID}
	if out, err := slugNativeOperationService(t, f.service).DeleteTeam(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy tombstone invented natural original history", err)
	}
	var legacy int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.delete' AND delete_team_id IS NULL AND delete_team_version IS NULL`).Scan(&legacy); err != nil || legacy != 1 {
		t.Fatal("legacy delete correlation backfilled", err)
	}
}
