//go:build integration

package postgres_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func (f *activeOrganizationFixture) selectForAuthority(t *testing.T, a organization.Authentication, target organization.ID, key string) organization.StoreResult {
	t.Helper()
	source := f.record(t, a)
	result, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, organization.ActiveOrganizationOperationRequest{Authentication: a, IdempotencyKey: selectionKey(t, key), SessionID: source.SessionID, OrganizationID: target, CorrelationID: key}, "127.0.0.1")
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual authority case selection", key, err)
	}
	return result
}

func (f *activeOrganizationFixture) denySelectionHistory(t *testing.T, a organization.Authentication, original organization.StoreResult) {
	t.Helper()
	service := f.operations(t, f.pool)
	if view, err := service.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: a, CorrelationID: "withdrawn-current-read"}); err == nil || view != (organization.ActiveOrganizationView{}) {
		t.Fatal("withdrawn selected authority disclosed view", err)
	}
	if result, err := service.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: a, Binding: original.Receipt.Binding}); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted || result.Receipt.Binding.CommandID != "" {
		t.Fatal("withdrawn authority disclosed original history", err)
	}
	if _, err := f.native(t, f.pool).PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: a, CommandID: commandID(t), SessionID: original.Receipt.Binding.RecordID, CorrelationID: "withdrawn-clear"}, "127.0.0.1"); err == nil {
		t.Fatal("withdrawn selection became clearing authority")
	}
}

func (f *activeOrganizationFixture) exerciseSelectionAuthorityWithdrawal(t *testing.T, first, second organization.ID) {
	t.Helper()
	native := f.native(t, f.pool)
	active := f.selectForAuthority(t, f.member, second, "policy-epoch-selection")
	removed := f.selectForAuthority(t, f.spareMember, first, "removed-member-selection")
	current := f.record(t, f.member)
	pending, err := native.PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.member, CommandID: commandID(t), SessionID: current.SessionID, OrganizationID: first, CorrelationID: "late-target-removal"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	command, err := native.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: first, OrganizationVersion: 2, UserID: f.memberID, MemberVersion: 1, CorrelationID: "actual-member-removal"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := native.Execute(f.ctx, command); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual selected membership removal", err)
	}
	if result, err := native.Execute(f.ctx, pending); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("late target membership withdrawal crossed protected admission", err)
	}
	if after := f.record(t, f.member); after.Version != current.Version {
		t.Fatal("denied late target changed the source session")
	}
	f.denySelectionHistory(t, f.spareMember, removed)

	memberView, err := native.Get(f.ctx, organization.ReadRequest{Authentication: f.owner, OrganizationID: second, CorrelationID: "before-policy-epoch"})
	if err != nil {
		t.Fatal(err)
	}
	command, err = native.PrepareUpdateMember(f.ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: second, OrganizationVersion: memberView.Organization.Version, UserID: f.memberID, MemberVersion: 1, Role: organization.RoleAdministrator, CorrelationID: "actual-policy-epoch"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := native.Execute(f.ctx, command); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual member policy transition", err)
	}
	f.denySelectionHistory(t, f.member, active)

	// This fresh genuine session is not derived from a stale selected session.
	archiveActor := f.signinMember()
	archived := f.selectForAuthority(t, archiveActor, second, "archive-selection")
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(organizationpg.LifecycleMigrationSource{Version: 7020}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("actual lifecycle extension", err)
	}
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	proofSource, primary, _ := transferProofSource(t, f.ctx, f.pool, f.db, sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, f.profile, f.lookup, policy, 9, []string{baselineTenant}, f.keys["fingerprint"], true)
	archive, restore := lifecyclePrimaries(t, proofSource)
	lifecycle := selectionOrganizationServiceWithRoles(t, f.pool, f.sessions, f.profile, f.lookup, f.keys, f.material, organization.DynamicRoleConfig{}, primary, archive, restore)
	proof := f.ownerProof(proofSource, f.owner, organization.Archive)
	command, err = lifecycle.PrepareArchive(f.ctx, organization.LifecycleRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: second, OrganizationVersion: 3, Proof: proof, Reason: "selection-authority-test", CorrelationID: "actual-archive"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := lifecycle.Execute(f.ctx, command); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual selected organization archive", err)
	}
	f.denySelectionHistory(t, archiveActor, archived)

	third := f.create(t, "selection-logout")
	logoutActor := f.signinMember()
	loggedOut := f.selectForAuthority(t, logoutActor, third, "logout-selection")
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	execution := sessionpg.IssueExecutorConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.IssueAdmissionConfig(f.profile), Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: f.keys["fingerprint"]}}, Authorization: policy, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}
	executor, err := sessionpg.NewRevokeOneExecutor(f.pool, sessionpg.RevokeOneExecutorConfig{Execution: execution, Sessions: f.sessions, OrganizationPassword: &sessionpg.OrganizationPasswordSessionAdmission{Profile: f.profile, Authority: repository}})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	logout, err := session.NewSignOutService(f.sessions, executor, session.SignOutConfig{Cookie: cookie, PolicyID: "session-signout", PolicyVersion: 9, MaximumDuration: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.ParseToken(logoutActor.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	result, err := logout.SignOut(f.ctx, session.SignOutRequest{TenantID: logoutActor.TenantID, CommandID: commandID(t), CorrelationID: "actual-selected-logout", Transport: session.CredentialBearer, Credential: credential})
	if err != nil || result.CommitOutcome != identity.CommitOutcomeCommitted || !result.ClearBearer || result.ClearCookie || result.Cookie.Name != "" {
		t.Fatal("actual selected logout", err)
	}
	f.denySelectionHistory(t, logoutActor, loggedOut)
}
