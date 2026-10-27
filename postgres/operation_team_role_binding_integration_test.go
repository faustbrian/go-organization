//go:build integration

package postgres_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func teamRoleBindingOperationFixture(t *testing.T, optional bool) (*orgFixture, organization.AssignTeamDynamicRoleOperationRequest) {
	t.Helper()
	// The raw-team fixture has no request-key schema. Reuse the existing
	// operation assembly, including the real native key/preparation migrations.
	f := dynamicRoleOperationFixture(t, false)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	p, err := f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 2, TeamID: "engineering", Name: "Engineering", CorrelationID: "team-role-setup"}, "127.0.0.1")
	commitRole(t, f, p, err)
	commitRole(t, f, prepareRole(t, f, 3), nil)
	p, err = f.service.PrepareAddTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 4, TeamID: "engineering", TeamVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "team-role-setup"}, "127.0.0.1")
	commitRole(t, f, p, err)
	q := organization.DynamicRoleReadRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: metadataOrganization, RoleID: "reader", TargetTeamID: "engineering", CorrelationID: "team-role-setup"}
	if optional {
		installTeamRoleBindingOperationMigration(t, f)
	}
	v := teamRoleSnapshot(t, f, q)
	key, err := identity.NewIdempotencyKey([]byte("original-team-role-assignment"))
	if err != nil {
		t.Fatal(err)
	}
	return f, organization.AssignTeamDynamicRoleOperationRequest{Authentication: q.Authentication, IdempotencyKey: key, OrganizationID: q.OrganizationID, RoleID: q.RoleID, TeamID: q.TargetTeamID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, TeamVersion: v.Team.Version, BindingVersion: v.TeamRoleBinding.Version, CorrelationID: "original-team-role-assignment"}
}

func installTeamRoleBindingOperationMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	installDynamicRoleOperationSources(t, f, organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306}, organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: 324}, organizationpg.TeamRoleBindingRevokeOperationLookupMigrationSource{Version: 325})
}

func revokeTeamRoleBindingOperationRequest(r organization.AssignTeamDynamicRoleOperationRequest) organization.RevokeTeamDynamicRoleOperationRequest {
	return organization.RevokeTeamDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion + 1, RoleVersion: r.RoleVersion, TeamVersion: r.TeamVersion + 1, BindingVersion: r.BindingVersion + 1, CorrelationID: "natural-team-role-revoke"}
}

func TestTeamRoleBindingOperationOriginalPermissionWithoutOrganizationRead(t *testing.T) {
	f, r := teamRoleBindingOperationFixture(t, true)
	s := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil)
	if _, err := s.Get(f.ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "deny-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("org read not actually denied", err)
	}
	assigned, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil || assigned.Receipt.Feature == nil || assigned.Receipt.Feature.BeforeVersion != 5 || assigned.Receipt.Feature.AfterVersion != 6 || assigned.Receipt.Binding.UserID != "owner" || assigned.MemberID != "owner" {
		t.Fatal("actual human-bound team assignment", err)
	}
	if out, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, assigned) {
		t.Fatal("original team assignment required unrelated read", err)
	}
	q := organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetTeamID: r.TeamID, CorrelationID: "actual-team-selectors"}
	v, err := s.GetDynamicRole(f.ctx, q)
	if err != nil || v.DynamicRole.ID != r.RoleID || v.DynamicRole.Version != 1 || v.Team.ID != r.TeamID || v.Team.Version != 3 || !v.TeamRoleBinding.Active || v.TeamRoleBinding.Version != 1 {
		t.Fatal("chosen team binding intent differs", err)
	}
	permission := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, OrganizationVersion: 6, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "actual-team-role-permission"}
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Allow {
		t.Fatal("actual team member permission not granted", err)
	}
	x := revokeTeamRoleBindingOperationRequest(r)
	revoked, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil || revoked.Receipt.Feature == nil || revoked.Receipt.Feature.BeforeVersion != 6 || revoked.Receipt.Feature.AfterVersion != 7 {
		t.Fatal("actual team role revocation", err)
	}
	permission.OrganizationVersion = 7
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("actual team member permission retained", err)
	}
	v, err = s.GetDynamicRole(f.ctx, q)
	if err != nil || v.TeamRoleBinding.Active || v.TeamRoleBinding.Version != 2 || v.Team.Version != 4 {
		t.Fatal("team binding tombstone differs", err)
	}
	for range 2 {
		if out, err := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil).RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, revoked) {
			t.Fatal("reconstructed team revoke differs", err)
		}
	}
	for _, original := range []organization.StoreResult{assigned, revoked} {
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("actual self-actor original required org read", err)
		}
	}
	config := f.configuration
	config.Authorization = new(directRoleBindingPolicy)
	legacy, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: assigned.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("raw legacy recovery permission changed", err)
	}
	r.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("new-team-role-assignment"))
	r.OrganizationVersion = 7
	r.TeamVersion = 4
	r.BindingVersion = 2
	if _, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if out, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
		t.Fatal("old team revoke reached reassignment", err)
	}
	permission.OrganizationVersion = 8
	if d, err := s.CheckPermission(f.ctx, permission); err != nil || d.Outcome != authorization.Allow {
		t.Fatal("new team grant changed by old revoke", err)
	}
}

func TestTeamRoleBindingOperationExactKeyIntent(t *testing.T) {
	f, r := teamRoleBindingOperationFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	original, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"organization", "role", "team", "org-epoch", "role-epoch", "team-epoch", "binding-epoch"} {
		t.Run(field, func(t *testing.T) {
			bad := r
			switch field {
			case "organization":
				bad.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
			case "role":
				bad.RoleID = "different-role"
			case "team":
				bad.TeamID = "different-team"
			case "org-epoch":
				bad.OrganizationVersion++
			case "role-epoch":
				bad.RoleVersion++
			case "team-epoch":
				bad.TeamVersion++
			case "binding-epoch":
				bad.BindingVersion++
			}
			if out, err := s.AssignTeamDynamicRole(f.ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
				t.Fatal("changed team-binding intent adopted original key", err)
			}
		})
	}
	r.CorrelationID = "diagnostic-only"
	if out, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, original) {
		t.Fatal("correlation changed original intent", err)
	}
}

func TestTeamRoleBindingOperationDirectAndTeamHistoryCannotAlias(t *testing.T) {
	f, r := teamRoleBindingOperationFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	if _, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	direct := organization.AssignDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: "member", OrganizationVersion: 6, RoleVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "direct-team-key-isolation"}
	if out, err := s.AssignDynamicRole(f.ctx, direct, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out != (organization.StoreResult{}) {
		t.Fatal("team key silently adopted direct target", err)
	}
	direct.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("independent-direct-assignment"))
	if _, err := s.AssignDynamicRole(f.ctx, direct, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	x := revokeTeamRoleBindingOperationRequest(r)
	x.OrganizationVersion = 7
	teamRemoved, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	directRevoke := organization.RevokeDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: "member", OrganizationVersion: 8, RoleVersion: 1, OrganizationMemberVersion: 1, BindingVersion: 1, CorrelationID: "independent-direct-revoke"}
	directRemoved, err := s.RevokeDynamicRole(f.ctx, directRevoke, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, teamRemoved) {
		t.Fatal("direct history changed team original", err)
	}
	if out, err := s.RevokeDynamicRole(f.ctx, directRevoke, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, directRemoved) {
		t.Fatal("team history changed direct original", err)
	}
	wrongDirect := directRevoke
	wrongDirect.OrganizationVersion = 7
	if out, err := s.RevokeDynamicRole(f.ctx, wrongDirect, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("team selectors supplied direct original", err)
	}
	wrongTeam := x
	wrongTeam.OrganizationVersion = 8
	if out, err := s.RevokeTeamDynamicRole(f.ctx, wrongTeam, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("direct selectors supplied team original", err)
	}
	var directRows, teamRows, mixed int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE revoke_role_id IS NOT NULL),count(*) FILTER(WHERE revoke_team_id IS NOT NULL),count(*) FILTER(WHERE revoke_role_id IS NOT NULL AND revoke_team_id IS NOT NULL) FROM organization.command_effects`).Scan(&directRows, &teamRows, &mixed); err != nil || directRows != 1 || teamRows != 1 || mixed != 0 {
		t.Fatal("direct/team effects share original selectors", err)
	}
}

func TestTeamRoleBindingOperationLegacyWritersNeedNoOptionalSchema(t *testing.T) {
	f, r := teamRoleBindingOperationFixture(t, false)
	s := slugNativeOperationService(t, f.service)
	original, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal("keyed team assign imposed optional schema", err)
	}
	x := revokeTeamRoleBindingOperationRequest(r)
	if out, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("natural team revoke ran without optional schema", err)
	}
	p, err := f.service.PrepareRevokeTeamDynamicRole(f.ctx, organization.TeamRoleBindingRequest{Authentication: x.Authentication, CommandID: commandID(t), OrganizationID: x.OrganizationID, RoleID: x.RoleID, TeamID: x.TeamID, OrganizationVersion: x.OrganizationVersion, RoleVersion: x.RoleVersion, TeamVersion: x.TeamVersion, BindingVersion: x.BindingVersion, CorrelationID: x.CorrelationID}, "127.0.0.1")
	commitRole(t, f, p, err)
	installTeamRoleBindingOperationMigration(t, f)
	if out, err := s.RevokeTeamDynamicRole(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy tombstone invented original team success", err)
	}
	if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
		t.Fatal("legacy team assign original lost", err)
	}
}

func TestTeamRoleBindingOperationReadmissionAndTerminalTeamFences(t *testing.T) {
	f, r := teamRoleBindingOperationFixture(t, true)
	s := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil)
	original, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	check := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, OrganizationVersion: 6, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-readmission-permission"}
	p, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: "member", MemberVersion: 1, CorrelationID: "remove-team-role-admission"}, "127.0.0.1")
	commitRole(t, f, p, err)
	check.OrganizationVersion = 7
	if _, err := s.CheckPermission(f.ctx, check); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed member retained team role", err)
	}
	p, err = f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 7, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "readmit-team-role-member"}, "127.0.0.1")
	commitRole(t, f, p, err)
	check.OrganizationVersion = 8
	if d, err := s.CheckPermission(f.ctx, check); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("organization readmission revived old team authority", err)
	}
	p, err = f.service.PrepareAddTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 8, TeamID: r.TeamID, TeamVersion: 3, UserID: "member", OrganizationMemberVersion: 3, MembershipVersion: 1, CorrelationID: "new-exact-team-admission"}, "127.0.0.1")
	commitRole(t, f, p, err)
	check.OrganizationVersion = 9
	if d, err := s.CheckPermission(f.ctx, check); err != nil || d.Outcome != authorization.Allow {
		t.Fatal("explicit compatible new team admission lost permission", err)
	}
	p, err = f.service.PrepareDeleteTeam(f.ctx, organization.DeleteTeamRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 9, TeamID: r.TeamID, TeamVersion: 4, CorrelationID: "terminal-team-role-owner"}, "127.0.0.1")
	commitRole(t, f, p, err)
	check.OrganizationVersion = 10
	if d, err := s.CheckPermission(f.ctx, check); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("terminal team retained derived authority", err)
	}
	if out, err := s.AssignTeamDynamicRole(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, original) {
		t.Fatal("terminal team original history lost", err)
	}
	q := organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetTeamID: r.TeamID, CorrelationID: "terminal-team-read"}
	if _, err := s.GetDynamicRole(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("terminal team exposed live binding", err)
	}
	retired := r
	retired.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("retired-team-assignment"))
	retired.OrganizationVersion = 10
	retired.TeamVersion = 4
	retired.BindingVersion = 1
	if out, err := s.AssignTeamDynamicRole(f.ctx, retired, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("new key revived terminal team binding", err)
	}
	p, err = f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 10, TeamID: r.TeamID, Name: "Reused engineering", CorrelationID: "terminal-team-id-reuse"}, "127.0.0.1")
	var reused organization.StoreResult
	if err == nil {
		reused, err = f.service.Execute(f.ctx, p)
	}
	if err == nil || reused.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("terminal team ID was reused", err)
	}
}
