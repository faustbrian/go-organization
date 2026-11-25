//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

type directorySuccessorFixture struct {
	fixture *orgFixture
	store   *organizationpg.Repository
	source  organizationpg.DirectoryMembershipSource
}

func TestDirectoryMembershipSuccessorMigrationPreservesLegacyEffectsAndBoundsLock(t *testing.T) {
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	f.create(t, "org-test-basic")
	readLegacy := func() string {
		t.Helper()
		var effects string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_agg(to_jsonb(e)-ARRAY['directory_org_before','directory_org_after','directory_credential_version'] ORDER BY command_id)::text FROM organization.command_effects e`).Scan(&effects); err != nil {
			t.Fatal("read existing command effects", err)
		}
		return effects
	}
	before := readLegacy()
	steps, err := (organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 307}).Load(f.ctx)
	if err != nil || len(steps) != 1 {
		t.Fatal("load additive successor migration", err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.command_effects IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	apply := func() error {
		t.Helper()
		tx, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(f.ctx)
		if _, err := tx.Exec(f.ctx, steps[0].UpSQL()); err != nil {
			return err
		}
		return tx.Commit(f.ctx)
	}
	var lock *pgconn.PgError
	if err := apply(); !errors.As(err, &lock) || lock.Code != "55P03" {
		t.Fatal("blocked schema expansion did not hit its PostgreSQL lock timeout", err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := apply(); err != nil {
		t.Fatal("retry after lock budget failed", err)
	}
	if after := readLegacy(); after != before {
		t.Fatal("migration rewrote existing command effect data")
	}
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects
 WHERE directory_org_before IS NULL AND directory_org_after IS NULL AND directory_credential_version IS NULL`).Scan(&effects); err != nil || effects != 2 {
		t.Fatal("historical or old-writer effects acquired successor evidence", effects, err)
	}
}

func newDirectorySuccessorFixture(t *testing.T) directorySuccessorFixture {
	t.Helper()
	f := newOrgFixture(t,
		organizationpg.CredentialAuthorityMigrationSource{Version: 305},
		organizationpg.DirectoryMembershipMigrationSource{Version: 306},
		organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 307},
	)
	f.create(t, "org-test-basic")
	store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return directorySuccessorFixture{fixture: f, store: store, source: organizationpg.DirectoryMembershipSource{
		TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: "member",
		ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one",
	}}
}

func (f directorySuccessorFixture) prepare(t *testing.T, source organizationpg.DirectoryMembershipSource, withdraw, denyFinal, record bool) (*directoryMembershipWorkOwner, *kernel.Coordinator, identity.Command, kernel.CommandPlan) {
	t.Helper()
	observed, err := f.store.ObserveDirectoryMembership(f.fixture.ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	original, err := f.store.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{TenantID: source.TenantID, OrganizationID: source.OrganizationID})
	if err != nil {
		t.Fatal(err)
	}
	input := organizationpg.DirectoryMembershipInput{
		Source: source, ActorID: "directory-service", Organization: original,
		MemberVersion: observed.Member.Version, MemberAuthorizationVersion: observed.Member.AuthorizationVersion,
		ExpectedVersion: observed.ContributionVersion, Action: organizationpg.DirectoryMembershipGrant,
		User:           identity.User{TenantID: source.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1},
		MaximumMembers: 20, MaximumPerUser: 10,
	}
	if withdraw {
		input.Action, input.User = organizationpg.DirectoryMembershipWithdraw, identity.User{}
	}
	owner := &directoryMembershipWorkOwner{repository: f.store, withdraw: withdraw, denyFinal: denyFinal, recordSuccessor: record}
	coordinator, command, plan := directoryMembershipNativeWork(t, f.fixture, owner, input)
	return owner, coordinator, command, plan
}

func (f directorySuccessorFixture) commit(t *testing.T, source organizationpg.DirectoryMembershipSource, withdraw bool) (organization.CredentialAuthorityObservation, identity.CommandResult) {
	t.Helper()
	owner, coordinator, command, plan := f.prepare(t, source, withdraw, false, true)
	original := owner.input.Organization
	receipt, err := executeDirectoryTeamNative(f.fixture.ctx, coordinator, command, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil {
		t.Fatal("original directory child did not commit", receipt.Outcome, err)
	}
	return original, receipt
}

func (f directorySuccessorFixture) requireSuccessor(t *testing.T, source organizationpg.DirectoryMembershipSource, original organization.CredentialAuthorityObservation, receipt identity.CommandResult, version uint64) {
	t.Helper()
	got, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, source, original, receipt)
	want := original
	want.Version = version
	if err != nil || got != want {
		t.Fatal("durable successor did not change only the original organization version", err)
	}
}

func TestDirectoryMembershipSuccessorCommittedEffectiveAndOverlappingSources(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	first, grant := f.commit(t, f.source, false)
	f.requireSuccessor(t, f.source, first, grant, first.Version+1)

	other := f.source
	other.ProviderID, other.ConnectionID, other.ResourceID = "provider-two", "connection-two", "resource-two"
	overlap, secondGrant := f.commit(t, other, false)
	f.requireSuccessor(t, other, overlap, secondGrant, overlap.Version)

	retained, firstWithdrawal := f.commit(t, f.source, true)
	f.requireSuccessor(t, f.source, retained, firstWithdrawal, retained.Version)
	removed, lastWithdrawal := f.commit(t, other, true)
	f.requireSuccessor(t, other, removed, lastWithdrawal, removed.Version+1)
	if current, err := f.store.ObserveDirectoryMembership(f.fixture.ctx, other); err != nil || current.Member.Active {
		t.Fatal("last source successor did not accompany effective withdrawal", err)
	}
}

type directorySuccessorRecoveryPolicy struct{ binding identity.CommandBinding }

func (p directorySuccessorRecoveryPolicy) Decide(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	b := p.binding
	allowed := dc.PolicyRevision == 1 && dc.Request.Subject.Kind == b.ActorKind &&
		dc.Request.Subject.ID == authorization.SubjectID(b.ActorID) && dc.Request.Tenant == authorization.TenantID(b.TenantID) &&
		dc.Request.Action == authorization.Action(b.OperationID) && dc.Request.Resource.Type == "identity.user" &&
		dc.Request.Resource.ID == authorization.ResourceID(b.UserID)
	outcome := authorization.Deny
	if allowed {
		outcome = authorization.Allow
	}
	return authorization.Decision{Outcome: outcome, Revision: 1}, nil
}

func (f directorySuccessorFixture) recoverReceipt(t *testing.T, b identity.CommandBinding) identity.CommandResult {
	t.Helper()
	domain, err := kernel.NewRepository(f.fixture.pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := kernel.NewCoordinator(f.fixture.pool, registry, kernel.CoordinatorConfig{
		MaximumDuration: time.Second, LeaseDuration: time.Minute,
		CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x55}},
		QueryPolicy: &kernel.CommandQueryPolicy{Authorization: directorySuccessorRecoveryPolicy{binding: b}, Clock: clock.System{}, PolicyVersion: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	caller := authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{
		Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: b.ActorKind},
		Tenant:  authorization.TenantID(b.TenantID), Action: authorization.Action(b.OperationID),
		Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)},
	}}
	recovered, err := reader.RecoverFeatureCommand(f.fixture.ctx, query, caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Binding != b {
		t.Fatal("new primary reader did not recover the original committed receipt", err)
	}
	return recovered
}

func TestDirectoryMembershipSuccessorRecoversExactPersistedReceiptWithoutWork(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	original, committed := f.commit(t, f.source, false)
	recovered := f.recoverReceipt(t, committed.Binding)
	if !reflect.DeepEqual(recovered, committed) {
		t.Fatal("new primary reader changed the original committed receipt")
	}
	freshStore, err := organizationpg.NewRepository(f.fixture.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	f.store = freshStore
	f.requireSuccessor(t, f.source, original, recovered, original.Version+1)
}

func TestDirectoryMembershipSuccessorRejectsCommittedChildWithoutRecordedEffect(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	owner, coordinator, command, plan := f.prepare(t, f.source, false, false, false)
	receipt, err := executeDirectoryTeamNative(f.fixture.ctx, coordinator, command, plan)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("legacy directory child did not commit", err)
	}
	if got, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, f.source, owner.input.Organization, receipt); err == nil || got != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("committed child without durable successor evidence gained authority", err)
	}
}

func TestDirectoryMembershipSuccessorRecoversAfterRealLostCommitAcknowledgement(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	fault := new(commitResponseLoss)
	pool, err := database.Connect(f.fixture.ctx, database.Config{DSN: f.fixture.dsn, MaxConns: 2, Configure: func(config *database.PoolConfig) error {
		config.ConnConfig.Database = f.fixture.database
		config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &lossyCommitConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal("fault connection unavailable", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error("fault pool cleanup failed")
		}
	})
	faultFixture := *f.fixture
	faultFixture.pool = pool
	faultStore, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	faulted := directorySuccessorFixture{fixture: &faultFixture, store: faultStore, source: f.source}
	owner, coordinator, command, plan := faulted.prepare(t, f.source, false, false, true)
	original := owner.input.Organization
	spec, _ := command.Feature()
	fault.armed.Store(true)
	unknown, err := executeDirectoryTeamNative(f.fixture.ctx, coordinator, command, plan)
	if !fault.lost.Load() || err == nil || unknown.Outcome != identity.CommitOutcomeUnknown || unknown.Binding != spec.Binding {
		t.Fatal("real committed response loss did not retain uncertainty", unknown.Outcome, err)
	}
	if got, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, f.source, original, unknown); err == nil || got != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("unknown outcome disclosed successor authority", err)
	}
	recovered := f.recoverReceipt(t, spec.Binding)
	if recovered.Feature == nil || recovered.Feature.BeforeVersion != 0 || recovered.Feature.AfterVersion != 1 || recovered.AuditEventID == "" {
		t.Fatal("lost acknowledgement recovery did not retain the exact original transition")
	}
	f.requireSuccessor(t, f.source, original, recovered, original.Version+1)
	if again := f.recoverReceipt(t, spec.Binding); !reflect.DeepEqual(again, recovered) || owner.applyCalls != 1 {
		t.Fatal("lost acknowledgement recovery changed the receipt or repeated effects")
	}
}

func TestDirectoryMembershipSuccessorRejectsChangedSourceReceiptAndAuthority(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	original, receipt := f.commit(t, f.source, false)
	memberAuthority, err := f.store.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{TenantID: f.source.TenantID, OrganizationID: f.source.OrganizationID, ActorID: "member"})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"resource", "provider", "connection", "user", "tenant", "organization", "command", "correlation", "missing-audit", "transition", "outcome", "original-version", "credential-version", "expired", "member-observation"} {
		t.Run(mode, func(t *testing.T) {
			source, observed, changed := f.source, original, receipt
			feature := *receipt.Feature
			changed.Feature = &feature
			switch mode {
			case "resource":
				source.ResourceID = "different-resource"
			case "provider":
				source.ProviderID = "different-provider"
			case "connection":
				source.ConnectionID = "different-connection"
			case "user":
				source.UserID = "outsider"
			case "tenant":
				source.TenantID = "org-test-scope"
			case "organization":
				source.OrganizationID = "different-organization"
			case "command":
				changed.Binding.CommandID = commandID(t)
			case "correlation":
				changed.Binding.CorrelationID = "different-correlation"
			case "missing-audit":
				changed.AuditEventID = ""
			case "transition":
				changed.Feature.BeforeVersion++
				changed.Feature.AfterVersion++
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
			got, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, source, observed, changed)
			if err == nil || got != (organization.CredentialAuthorityObservation{}) {
				t.Fatal("unproven successor disclosed organization authority", mode, err)
			}
		})
	}
	f.requireSuccessor(t, f.source, original, receipt, original.Version+1)
	f.fixture.add(t, "org-test-basic", "outsider", organization.RoleMember, original.Version+1)
	if got, err := f.store.RecoverDirectoryMembershipSuccessor(f.fixture.ctx, f.source, original, receipt); err == nil || got != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("historical successor survived a later organization authority change", err)
	}
}

func TestDirectoryMembershipSuccessorFinalDenialRollsBackDurableEffect(t *testing.T) {
	f := newDirectorySuccessorFixture(t)
	owner, coordinator, command, plan := f.prepare(t, f.source, false, true, true)
	spec, _ := command.Feature()
	count := func() int {
		t.Helper()
		var effects int
		if err := f.fixture.pool.Raw().QueryRow(f.fixture.ctx, `SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2`, string(spec.Binding.CommandID), spec.Binding.OperationID).Scan(&effects); err != nil {
			t.Fatal(err)
		}
		return effects
	}
	if count() != 0 {
		t.Fatal("new command already has durable successor evidence")
	}
	result, err := executeDirectoryTeamNative(f.fixture.ctx, coordinator, command, plan)
	if err == nil || result.Outcome == identity.CommitOutcomeCommitted || owner.applyCalls != 1 || count() != 0 {
		t.Fatal("final denial retained durable successor evidence", result.Outcome, err)
	}
	observed, err := f.store.ObserveDirectoryMembership(f.fixture.ctx, f.source)
	if err != nil || observed.ContributionVersion != 0 || observed.Member.Active {
		t.Fatal("final denial retained a directory contribution or effective membership", err)
	}
	current, err := f.store.ObserveCredentialAuthority(f.fixture.ctx, organization.CredentialAuthorityQuery{TenantID: f.source.TenantID, OrganizationID: f.source.OrganizationID})
	if err != nil || current.Version != owner.input.Organization.Version {
		t.Fatal("final denial retained the organization successor version", err)
	}
}
