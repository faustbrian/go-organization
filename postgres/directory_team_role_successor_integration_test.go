//go:build integration

package postgres_test

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type directoryTeamRoleSuccessorFixture struct {
	fixture        *orgFixture
	owner          *directoryTeamWorkOwner
	coordinator    *kernel.Coordinator
	registry       *kernel.ContributorRegistry
	source         organizationpg.DirectoryTeamRoleSource
	bindingVersion uint64
}

func newDirectoryTeamRoleSuccessorFixture(t *testing.T) directoryTeamRoleSuccessorFixture {
	t.Helper()
	f, view := directoryTeamRolePermissionFixture(t)
	history := append(migrationList(nil), f.history...)
	for _, source := range []migrations.Source{
		organizationpg.DirectoryMembershipMigrationSource{Version: 311},
		organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 312},
		organizationpg.DirectoryTeamRoleSuccessorMigrationSource{Version: 313},
	} {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal("load ordered directory successor migrations", err)
		}
		history = append(history, steps...)
	}
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("apply additive role successor after published User successor", err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("replay additive role successor migration", err)
	}
	owner, coordinator, registry := directoryTeamWorkCoordinator(t, f)
	owner.recordRoleSuccessor = true
	return directoryTeamRoleSuccessorFixture{
		fixture: f, owner: owner, coordinator: coordinator, registry: registry,
		source: organizationpg.DirectoryTeamRoleSource{
			Scope: organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization,
				UserID: "member", TeamID: "engineering", ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a"},
			MemberResourceID: "source-member", RoleID: "reader", ProviderVersion: 2, MappingVersion: 3, ConnectionVersion: 4,
		},
		bindingVersion: view.TeamRoleBinding.Version,
	}
}

func (f directoryTeamRoleSuccessorFixture) prepare(t *testing.T, source organizationpg.DirectoryTeamRoleSource, active bool) (organization.CredentialAuthorityObservation, identity.Command, kernel.CommandPlan) {
	t.Helper()
	observed, err := f.owner.repository.ObserveDirectoryTeamMembership(f.fixture.ctx, source.Scope)
	if err != nil {
		t.Fatal(err)
	}
	input := directoryTeamInput()
	input.Scope, input.User.TenantID, input.Active = source.Scope, source.Scope.TenantID, active
	input.OrganizationVersion, input.CredentialVersion = observed.OrganizationVersion, observed.CredentialVersion
	input.MemberVersion, input.MemberAuthorizationVersion = observed.MemberVersion, observed.MemberAuthorizationVersion
	input.TeamVersion, input.User.Version, input.ExpectedVersion = observed.TeamVersion, observed.UserVersion, observed.Version
	binding := uint64(0)
	if active {
		binding = f.bindingVersion
	}
	command, plan := directoryTeamNativeCommand(t, f.coordinator, f.registry, f.owner, input,
		directoryTeamRoleTarget{source: source, bindingVersion: binding})
	return f.owner.roleOrganization, command, plan
}

func (f directoryTeamRoleSuccessorFixture) commit(t *testing.T, source organizationpg.DirectoryTeamRoleSource, active bool) (organization.CredentialAuthorityObservation, identity.CommandResult) {
	t.Helper()
	original, command, plan := f.prepare(t, source, active)
	receipt, err := executeDirectoryTeamNative(f.fixture.ctx, f.coordinator, command, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.AuditEventID == "" {
		t.Fatal("original protected role Work did not commit with authenticated receipt", receipt.Outcome, err)
	}
	return original, receipt
}

func (f directoryTeamRoleSuccessorFixture) requireSuccessor(t *testing.T, source organizationpg.DirectoryTeamRoleSource, original organization.CredentialAuthorityObservation, receipt identity.CommandResult, version uint64) {
	t.Helper()
	got, err := f.owner.repository.RecoverDirectoryTeamRoleSuccessor(f.fixture.ctx, source, original, receipt)
	want := original
	want.Version = version
	if err != nil || got != want {
		t.Fatal("role successor did not change only the original organization version", err)
	}
}

func TestDirectoryTeamRoleSuccessorRecoversOriginalWorkAndAuthenticatedReceipt(t *testing.T) {
	f := newDirectoryTeamRoleSuccessorFixture(t)
	original, command, plan := f.prepare(t, f.source, true)
	receipt, err := executeDirectoryTeamNative(f.fixture.ctx, f.coordinator, command, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil {
		t.Fatal("original protected role Work did not commit", receipt.Outcome, err)
	}
	f.requireSuccessor(t, f.source, original, receipt, original.Version+1)
	if replay, err := executeDirectoryTeamNative(f.fixture.ctx, f.coordinator, command, plan); err != nil || !reflect.DeepEqual(replay, receipt) || f.owner.applyCalls != 1 {
		t.Fatal("original role replay changed receipt or repeated its effects", err)
	}
	recovered := (directorySuccessorFixture{fixture: f.fixture}).recoverReceipt(t, receipt.Binding)
	if !reflect.DeepEqual(recovered, receipt) {
		t.Fatal("independently authorized recovery changed the original role receipt")
	}
	fresh, err := organizationpg.NewRepository(f.fixture.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.owner.repository = fresh
	f.requireSuccessor(t, f.source, original, recovered, original.Version+1)

	beforeWithdrawal, withdrawal := f.commit(t, f.source, false)
	f.requireSuccessor(t, f.source, beforeWithdrawal, withdrawal, beforeWithdrawal.Version+1)
	if observed, err := fresh.ObserveDirectoryTeamMembership(f.fixture.ctx, f.source.Scope); err != nil || observed.Source || observed.Version != 2 {
		t.Fatal("successor was not committed with the exact source withdrawal", err)
	}
}

func TestDirectoryTeamRoleSuccessorValidatesOrderedRolePrefix(t *testing.T) {
	f := newDirectoryTeamRoleSuccessorFixture(t)
	_, added := f.commit(t, f.source, true)
	_, withdrawn := f.commit(t, f.source, false)
	ctx := f.fixture.ctx
	current, err := f.owner.repository.ObserveCredentialAuthority(ctx, organization.CredentialAuthorityQuery{
		TenantID: f.source.Scope.TenantID, OrganizationID: f.source.Scope.OrganizationID,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := organizationpg.NewDirectoryTeamRoleCommittedChild(f.source, added)
	if err != nil {
		t.Fatal(err)
	}
	second, err := organizationpg.NewDirectoryTeamRoleCommittedChild(f.source, withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	configured := organizationpg.DirectorySuccessorSourceScope{TenantID: f.source.Scope.TenantID, OrganizationID: f.source.Scope.OrganizationID,
		ProviderID: f.source.Scope.ProviderID, ConnectionID: f.source.Scope.ConnectionID, ActorID: added.Binding.ActorID}
	if !first.MatchesSource(configured) || !second.MatchesSource(configured) {
		t.Fatal("original role evidence did not match its configured source")
	}
	configured.ActorID = "another-service-account"
	if first.MatchesSource(configured) || (organizationpg.DirectorySourceCommittedChild{}).MatchesSource(configured) {
		t.Fatal("foreign or absent role evidence matched an unrelated source account")
	}
	if err := f.owner.repository.ValidateDirectorySourceSuccessorChain(ctx, current, []organizationpg.DirectorySourceCommittedChild{first, second}); err != nil {
		t.Fatal("exact historical role transitions did not reach the active owner", err)
	}
	for name, prefix := range map[string][]organizationpg.DirectorySourceCommittedChild{
		"reversed": {second, first}, "wrong successor": {first}, "repeated": {first, second, second},
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.owner.repository.ValidateDirectorySourceSuccessorChain(ctx, current, prefix); err == nil {
				t.Fatal("invalid ordered role prefix could authorize continued work")
			}
		})
	}
}

func TestDirectoryTeamRoleSuccessorRejectsChangedSourceReceiptAndAuthority(t *testing.T) {
	f := newDirectoryTeamRoleSuccessorFixture(t)
	original, receipt := f.commit(t, f.source, true)
	memberAuthority, err := f.owner.repository.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{
		TenantID: f.source.Scope.TenantID, OrganizationID: f.source.Scope.OrganizationID, ActorID: "member",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{
		"tenant", "organization", "user", "team", "provider", "connection", "group", "member-resource", "role",
		"provider-version", "mapping-version", "connection-version", "command", "actor", "correlation", "record",
		"missing-audit", "transition", "operation", "outcome", "original-version", "credential-version", "expired", "member-observation",
	} {
		t.Run(mode, func(t *testing.T) {
			source, observed, changed := f.source, original, receipt
			feature := *receipt.Feature
			changed.Feature = &feature
			switch mode {
			case "tenant":
				source.Scope.TenantID = "org-test-scope"
			case "organization":
				source.Scope.OrganizationID = "other"
			case "user":
				source.Scope.UserID = "outsider"
			case "team":
				source.Scope.TeamID = "other"
			case "provider":
				source.Scope.ProviderID = "other"
			case "connection":
				source.Scope.ConnectionID = "other"
			case "group":
				source.Scope.GroupID = "other"
			case "member-resource":
				source.MemberResourceID = "other"
			case "role":
				source.RoleID = "other"
			case "provider-version":
				source.ProviderVersion++
			case "mapping-version":
				source.MappingVersion++
			case "connection-version":
				source.ConnectionVersion++
			case "command":
				changed.Binding.CommandID = commandID(t)
			case "actor":
				changed.Binding.ActorID = "other"
			case "correlation":
				changed.Binding.CorrelationID = "other"
			case "record":
				changed.Binding.RecordID = "other"
			case "missing-audit":
				changed.AuditEventID = ""
			case "transition":
				changed.Feature.BeforeVersion++
				changed.Feature.AfterVersion++
			case "operation":
				changed.Feature.Operation.SchemaID = "other"
			case "outcome":
				changed.Outcome = identity.CommitOutcomeUnknown
			case "original-version":
				observed.Version++
			case "credential-version":
				observed.CredentialVersion++
			case "expired":
				observed.ReadStartedAt = observed.ReadStartedAt.Add(-time.Minute)
				observed.VerifiedAt = observed.VerifiedAt.Add(-time.Minute)
				observed.ValidUntil = observed.ValidUntil.Add(-time.Minute)
			case "member-observation":
				observed = memberAuthority
			}
			got, err := f.owner.repository.RecoverDirectoryTeamRoleSuccessor(f.fixture.ctx, source, observed, changed)
			if err == nil || got != (organization.CredentialAuthorityObservation{}) {
				t.Fatal("changed source, receipt or original authority disclosed a role successor", mode, err)
			}
		})
	}
	f.requireSuccessor(t, f.source, original, receipt, original.Version+1)
	f.fixture.add(t, "org-test-basic", "outsider", organization.RoleMember, original.Version+1)
	if got, err := f.owner.repository.RecoverDirectoryTeamRoleSuccessor(f.fixture.ctx, f.source, original, receipt); err == nil || got != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("historical role successor survived an unrelated organization authority change", err)
	}
}

func TestDirectoryTeamRoleSuccessorPreservesOptOutLegacyWork(t *testing.T) {
	f := newDirectoryTeamRoleSuccessorFixture(t)
	f.owner.recordRoleSuccessor = false
	original, receipt := f.commit(t, f.source, true)
	if got, err := f.owner.repository.RecoverDirectoryTeamRoleSuccessor(f.fixture.ctx, f.source, original, receipt); err == nil || got != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("legacy role Work without successor evidence acquired recovery authority", err)
	}
	current, err := f.owner.repository.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{
		TenantID: f.source.Scope.TenantID, OrganizationID: f.source.Scope.OrganizationID,
	})
	if err != nil || current.Version != original.Version+1 {
		t.Fatal("opt-out legacy role Work lost its existing organization transition", err)
	}
}

func TestDirectoryTeamRoleSuccessorFinalDenialRollsBackRecordedEffect(t *testing.T) {
	f := newDirectoryTeamRoleSuccessorFixture(t)
	original, command, plan := f.prepare(t, f.source, true)
	spec, _ := command.Feature()
	f.owner.denyFinal = true
	result, err := executeDirectoryTeamNative(f.fixture.ctx, f.coordinator, command, plan)
	if err == nil || result.Outcome == identity.CommitOutcomeCommitted || f.owner.applyCalls != 1 {
		t.Fatal("final-denied role Work unexpectedly committed", result.Outcome, err)
	}
	var effects int
	if err := f.fixture.pool.Raw().QueryRow(f.fixture.ctx, `SELECT count(*) FROM organization.command_effects WHERE command_id=$1`, string(spec.Binding.CommandID)).Scan(&effects); err != nil || effects != 0 {
		t.Fatal("final denial retained durable role successor evidence", effects, err)
	}
	current, err := f.owner.repository.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{
		TenantID: f.source.Scope.TenantID, OrganizationID: f.source.Scope.OrganizationID,
	})
	if err != nil || current.Version != original.Version || current.CredentialVersion != original.CredentialVersion {
		t.Fatal("final denial retained the role's organization successor", err)
	}
	if observed, err := f.owner.repository.ObserveDirectoryTeamMembership(f.fixture.ctx, f.source.Scope); err != nil || observed.Source || observed.Version != 0 {
		t.Fatal("final denial retained the exact source grant", err)
	}
}
