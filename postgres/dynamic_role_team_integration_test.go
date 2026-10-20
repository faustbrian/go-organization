//go:build integration

package postgres_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func teamRoleFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303}, organizationpg.TeamLifecycleMigrationSource{Version: 304}, organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}
	f.dynamicRoles = customRoleConfig()
	f.dynamicRoles.TeamBindingsVersion = 1
	f.compose(t)
	return f
}

func unboundTeamRoleScope(t *testing.T) (*orgFixture, organization.DynamicRoleReadRequest) {
	t.Helper()
	f := teamRoleFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	p, e := f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 2, TeamID: "engineering", Name: "Engineering", CorrelationID: "team-role"}, "127.0.0.1")
	commitRole(t, f, p, e)
	p = prepareRole(t, f, 3)
	commitRole(t, f, p, nil)
	p, e = f.service.PrepareAddTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 4, TeamID: "engineering", TeamVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "team-role"}, "127.0.0.1")
	commitRole(t, f, p, e)
	read := organization.DynamicRoleReadRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: metadataOrganization, RoleID: "reader", TargetTeamID: "engineering", CorrelationID: "team-role"}
	return f, read
}

func teamRoleSnapshot(t *testing.T, f *orgFixture, q organization.DynamicRoleReadRequest) organization.View {
	t.Helper()
	v, e := f.service.GetDynamicRole(f.ctx, q)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func teamRoleRequest(t *testing.T, q organization.DynamicRoleReadRequest, v organization.View) organization.TeamRoleBindingRequest {
	return organization.TeamRoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, RoleID: q.RoleID, TeamID: q.TargetTeamID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, TeamVersion: v.Team.Version, BindingVersion: v.TeamRoleBinding.Version, CorrelationID: "team-role"}
}
func assertTeamRolePermission(t *testing.T, f *orgFixture, want authorization.Outcome) {
	t.Helper()
	v, e := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: metadataOrganization, CorrelationID: "team-role"})
	if e != nil {
		t.Fatal(e)
	}
	d, e := f.service.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: metadataOrganization, OrganizationVersion: v.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-role"})
	if e != nil || d.Outcome != want {
		t.Fatalf("effective team/direct decision: %+v %v", d, e)
	}
}

func TestTeamRoleEffectivePermissionAndFreshBindingDiscovery(t *testing.T) {
	f, read := unboundTeamRoleScope(t)
	v, e := f.service.GetDynamicRole(f.ctx, read)
	if e != nil || v.Team.ID != "engineering" || v.TeamRoleBinding.TeamID != "engineering" || v.TeamRoleBinding.Version != 0 || v.TeamRoleBinding.Active {
		t.Fatal("absent team binding not discoverable", e)
	}
	request := func(v organization.View) organization.TeamRoleBindingRequest {
		return organization.TeamRoleBindingRequest{Authentication: read.Authentication, CommandID: commandID(t), OrganizationID: read.OrganizationID, RoleID: read.RoleID, TeamID: read.TargetTeamID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, TeamVersion: v.Team.Version, BindingVersion: v.TeamRoleBinding.Version, CorrelationID: "team-role"}
	}
	p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, request(v), "127.0.0.1")
	commitRole(t, f, p, e)
	current := func(s *organizationpg.Service) organization.View {
		t.Helper()
		v, e := s.GetDynamicRole(f.ctx, read)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	check := func(s *organizationpg.Service, want authorization.Outcome) {
		t.Helper()
		v := current(s)
		d, e := s.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: metadataOrganization, OrganizationVersion: v.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-role"})
		if e != nil || d.Outcome != want {
			t.Fatalf("team-derived permission: %+v %v", d, e)
		}
	}
	check(f.service, authorization.Allow)
	fresh, e := organizationpg.NewService(f.participant, f.configuration)
	if e != nil {
		t.Fatal(e)
	}
	v = current(fresh)
	if !v.TeamRoleBinding.Active || v.TeamRoleBinding.Version == 0 {
		t.Fatal("fresh manager cannot discover current team binding")
	}
	p, e = fresh.PrepareRevokeTeamDynamicRole(f.ctx, request(v), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = fresh.Execute(f.ctx, p); e != nil {
		t.Fatal(e)
	}
	check(f.service, authorization.Deny)
	v = current(f.service)
	if v.TeamRoleBinding.Active || v.TeamRoleBinding.Version == 0 {
		t.Fatal("team binding tombstone not discoverable")
	}
	p, e = f.service.PrepareAssignTeamDynamicRole(f.ctx, request(v), "127.0.0.1")
	commitRole(t, f, p, e)
	check(fresh, authorization.Allow)
	v = current(fresh)
	stale := request(v)
	stale.TeamVersion--
	if _, e = fresh.PrepareRevokeTeamDynamicRole(f.ctx, stale, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale team epoch admitted", e)
	}
}

func TestTeamRoleDirectAndTeamDenyPrecedenceAndDeduplication(t *testing.T) {
	f, q := unboundTeamRoleScope(t)
	p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, q, teamRoleSnapshot(t, f, q)), "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Allow)
	userRead := q
	userRead.TargetTeamID = ""
	userRead.TargetUserID = "member"
	direct := func(q organization.DynamicRoleReadRequest, v organization.View) organization.RoleBindingRequest {
		return organization.RoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, RoleID: q.RoleID, UserID: q.TargetUserID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, OrganizationMemberVersion: v.Target.Version, BindingVersion: v.RoleBinding.Version, CorrelationID: "deny-precedence"}
	}
	p, e = f.service.PrepareAssignDynamicRole(f.ctx, direct(userRead, teamRoleSnapshot(t, f, userRead)), "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Allow)
	p, e = f.service.PrepareRevokeDynamicRole(f.ctx, direct(userRead, teamRoleSnapshot(t, f, userRead)), "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Allow)
	v := teamRoleSnapshot(t, f, q)
	r := dynamicRoleRequest(t, f, v.Organization.Version)
	r.RoleID = "denier"
	r.Statements[0].Effect = authorization.Deny
	p, e = f.service.PrepareCreateDynamicRole(f.ctx, r, "127.0.0.1")
	commitRole(t, f, p, e)
	userRead.RoleID = "denier"
	p, e = f.service.PrepareAssignDynamicRole(f.ctx, direct(userRead, teamRoleSnapshot(t, f, userRead)), "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Deny)
	v = teamRoleSnapshot(t, f, userRead)
	r.CommandID = commandID(t)
	r.OrganizationVersion = v.Organization.Version
	r.RoleVersion = v.DynamicRole.Version
	r.Statements[0].Effect = authorization.Allow
	p, e = f.service.PrepareUpdateDynamicRole(f.ctx, r, "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Allow)
	v = teamRoleSnapshot(t, f, q)
	r = dynamicRoleRequest(t, f, v.Organization.Version)
	r.RoleVersion = v.DynamicRole.Version
	r.Statements[0].Effect = authorization.Deny
	p, e = f.service.PrepareUpdateDynamicRole(f.ctx, r, "127.0.0.1")
	commitRole(t, f, p, e)
	assertTeamRolePermission(t, f, authorization.Deny)
}

func TestTeamRoleWithdrawalAndReadmissionFailClosed(t *testing.T) {
	for _, withdrawal := range []string{"team-member", "org-member", "team-delete", "role-delete"} {
		t.Run(withdrawal, func(t *testing.T) {
			f, q := unboundTeamRoleScope(t)
			p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, q, teamRoleSnapshot(t, f, q)), "127.0.0.1")
			commitRole(t, f, p, e)
			assertTeamRolePermission(t, f, authorization.Allow)
			v := teamRoleSnapshot(t, f, q)
			switch withdrawal {
			case "team-member":
				p, e = f.service.PrepareRemoveTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, TeamID: q.TargetTeamID, TeamVersion: v.Team.Version, UserID: "member", OrganizationMemberVersion: 1, MembershipVersion: 1, CorrelationID: "team-role-removal"}, "127.0.0.1")
			case "org-member":
				p, e = f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, UserID: "member", MemberVersion: 1, CorrelationID: "team-role-removal"}, "127.0.0.1")
			case "team-delete":
				p, e = f.service.PrepareDeleteTeam(f.ctx, organization.DeleteTeamRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, TeamID: q.TargetTeamID, TeamVersion: v.Team.Version, CorrelationID: "team-role-removal"}, "127.0.0.1")
			case "role-delete":
				p, e = f.service.PrepareDeleteDynamicRole(f.ctx, organization.DynamicRoleRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, RoleID: q.RoleID, RoleVersion: v.DynamicRole.Version, CorrelationID: "team-role-removal"}, "127.0.0.1")
			}
			commitRole(t, f, p, e)
			if withdrawal != "org-member" {
				assertTeamRolePermission(t, f, authorization.Deny)
				return
			}
			v, e = f.service.Get(f.ctx, organization.ReadRequest{Authentication: q.Authentication, OrganizationID: q.OrganizationID, CorrelationID: "team-role-removal"})
			if e != nil {
				t.Fatal(e)
			}
			if _, e = f.service.CheckPermission(f.ctx, organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "team-role-removal"}); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("removed org member kept team authority", e)
			}
			p, e = f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "team-role-readmission"}, "127.0.0.1")
			commitRole(t, f, p, e)
			assertTeamRolePermission(t, f, authorization.Deny)
		})
	}
}

func TestTeamRoleRollbackContentionAndOriginalRecovery(t *testing.T) {
	f, q := unboundTeamRoleScope(t)
	before := teamRoleSnapshot(t, f, q)
	request := teamRoleRequest(t, q, before)
	p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, request, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_team_role() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled team role rollback'; END $$; CREATE TRIGGER fail_team_role BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.fail_team_role()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("team binding escaped outbox rollback", e)
	}
	after := teamRoleSnapshot(t, f, q)
	if after.Team.Version != before.Team.Version || after.Organization.Version != before.Organization.Version || after.TeamRoleBinding.Version != 0 {
		t.Fatal("team/policy/binding epochs escaped rollback")
	}
	_, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_team_role ON public.identity_outbox_bindings; DROP FUNCTION organization.fail_team_role()`)
	if e != nil {
		t.Fatal(e)
	}
	lossy, fault := f.lostCommitService(t)
	request.CommandID = commandID(t)
	p, e = lossy.PrepareAssignTeamDynamicRole(f.ctx, request, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	handle := mustRoleRecovery(t, p)
	fault.armed.Store(true)
	if got, e := lossy.Execute(f.ctx, p); e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost team binding commit claimed outcome", e)
	}
	for range 2 {
		got, e := f.service.Recover(f.ctx, q.Authentication, handle)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
			t.Fatal("original team binding recovery", e)
		}
	}
	after = teamRoleSnapshot(t, f, q)
	if after.Team.Version != before.Team.Version+1 || after.Organization.Version != before.Organization.Version+1 || after.TeamRoleBinding.Version != 1 {
		t.Fatal("recovery replayed team/policy/binding effects")
	}
	request = teamRoleRequest(t, q, after)
	a, e := f.service.PrepareRevokeTeamDynamicRole(f.ctx, request, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	request.CommandID = commandID(t)
	b, e := f.service.PrepareRevokeTeamDynamicRole(f.ctx, request, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	outcomes := make(chan bool, 2)
	for _, p := range []organizationpg.PreparedCommand{a, b} {
		wg.Add(1)
		go func(p organizationpg.PreparedCommand) {
			defer wg.Done()
			got, e := f.service.Execute(f.ctx, p)
			outcomes <- e == nil && got.Receipt.Outcome == identity.CommitOutcomeCommitted
		}(p)
	}
	wg.Wait()
	close(outcomes)
	committed := 0
	for ok := range outcomes {
		if ok {
			committed++
		}
	}
	if committed != 1 {
		t.Fatal("team binding contention", committed)
	}
	assertTeamRolePermission(t, f, authorization.Deny)
}

func TestTeamRoleCurrentManagerAndTerminalReplayFences(t *testing.T) {
	for _, withdrawal := range []string{"demoted", "removed", "session-revoked"} {
		t.Run(withdrawal, func(t *testing.T) {
			f, q := unboundTeamRoleScope(t)
			v := teamRoleSnapshot(t, f, q)
			f.add(t, "org-test-basic", "second", organization.RoleAdministrator, v.Organization.Version)
			q.Authentication = f.auth("org-test-basic", "second")
			v = teamRoleSnapshot(t, f, q)
			p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, q, v), "127.0.0.1")
			commitRole(t, f, p, e)
			v = teamRoleSnapshot(t, f, q)
			switch withdrawal {
			case "demoted":
				change, e := f.service.PrepareUpdateMember(f.ctx, roleRequest(t, f, "org-test-basic", "owner", "second", v.Organization.Version, 1, organization.RoleMember), "127.0.0.1")
				commitRole(t, f, change, e)
			case "removed":
				change, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: q.OrganizationID, OrganizationVersion: v.Organization.Version, UserID: "second", MemberVersion: 1, CorrelationID: "team-role-withdrawal"}, "127.0.0.1")
				commitRole(t, f, change, e)
			case "session-revoked":
				if _, e := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='second'`); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := f.service.GetDynamicRole(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("withdrawn manager discovered team binding", e)
			}
			// The external policy continues allowing role.assign; current native
			// membership/session authority, not that policy, must veto disclosure.
			if got, e := f.service.Execute(f.ctx, p); !errors.Is(e, organization.ErrForbidden) || got != (organization.StoreResult{}) {
				t.Fatal("withdrawn manager received terminal team-role receipt", e)
			}
			if _, e := f.service.Recover(f.ctx, q.Authentication, mustRoleRecovery(t, p)); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("withdrawn manager recovered team-role receipt", e)
			}
			assertTeamRolePermission(t, f, authorization.Allow)
		})
	}
}

func TestTeamRoleFinalSessionFenceAndScope(t *testing.T) {
	f, q := unboundTeamRoleScope(t)
	for _, foreign := range []organization.DynamicRoleReadRequest{
		{Authentication: f.auth("org-test-scope", "owner"), OrganizationID: q.OrganizationID, RoleID: q.RoleID, TargetTeamID: q.TargetTeamID, CorrelationID: "foreign"},
		{Authentication: q.Authentication, OrganizationID: "foreign-org", RoleID: q.RoleID, TargetTeamID: q.TargetTeamID, CorrelationID: "foreign"},
		{Authentication: q.Authentication, OrganizationID: q.OrganizationID, RoleID: q.RoleID, TargetTeamID: "foreign-team", CorrelationID: "foreign"},
	} {
		if _, e := f.service.GetDynamicRole(f.ctx, foreign); e == nil {
			t.Fatal("foreign team binding disclosed")
		}
	}
	before := teamRoleSnapshot(t, f, q)
	p, e := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, q, before), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.team_role_withdraw_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER team_role_withdraw_session AFTER INSERT ON organization.team_role_bindings FOR EACH ROW EXECUTE FUNCTION organization.team_role_withdraw_session()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("same-Work session withdrawal committed team role", e)
	}
	after := teamRoleSnapshot(t, f, q)
	if after.TeamRoleBinding.Version != 0 || after.Team.Version != before.Team.Version || after.Organization.Version != before.Organization.Version {
		t.Fatal("final session fence leaked binding or epochs")
	}
}

func TestTeamRoleMalformedTargetCannotFallBackToDirect(t *testing.T) {
	f, q := unboundTeamRoleScope(t)
	q.TargetTeamID, q.TargetUserID = "", "member"
	v := teamRoleSnapshot(t, f, q)
	repository, e := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	core, e := organization.NewService(f.sessions, repository, f.configuration.Authorization, f.configuration.Core)
	if e != nil {
		t.Fatal(e)
	}
	c, e := core.PrepareAssignDynamicRole(f.ctx, organization.RoleBindingRequest{Authentication: q.Authentication, CommandID: commandID(t), OrganizationID: q.OrganizationID, RoleID: q.RoleID, UserID: q.TargetUserID, OrganizationVersion: v.Organization.Version, RoleVersion: v.DynamicRole.Version, OrganizationMemberVersion: v.Target.Version, CorrelationID: "malformed-team-target"})
	if e != nil {
		t.Fatal(e)
	}
	native, e := f.participant.MapCommand(c)
	if e != nil {
		t.Fatal(e)
	}
	plan := kernel.CommandPlan{Feature: &kernel.FeatureRegistration{Contributor: f.participant.Descriptor(), Operation: organization.AssignDynamicRole.Descriptor()}, SubjectType: "organization", Lifecycle: &kernel.LifecyclePlan{EventType: "organization.role_assigned.v1", BeforeVersion: v.Organization.Version, AfterVersion: v.Organization.Version + 1}, Audits: []kernel.AuditPlan{{EventType: string(organization.AssignDynamicRole), RetentionClass: "protected"}}, CommandCounters: &kernel.CommandCounterPlan{}}
	if e = f.participant.ValidateFeatureCommand(native, plan); e != nil {
		t.Fatal("ordinary direct assignment rejected", e)
	}
	spec, _ := native.Feature()
	spec.Fields = append(spec.Fields,
		identity.FeatureField{Name: "organization.team-role-id", Value: identity.FeatureValue{Kind: identity.FeatureText}},
		identity.FeatureField{Name: "organization.team-role-name", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "Engineering"}},
		identity.FeatureField{Name: "organization.team-role-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}},
	)
	forged, e := identity.NewFeatureSessionCommand(spec, q.Authentication.Bearer)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.participant.ValidateFeatureCommand(forged, plan); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("malformed explicit team target silently became direct assignment", e)
	}
}
