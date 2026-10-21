//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is the explicit trusted external-observer seam, not a domain store,
// session/policy engine or duplicate authority. No DNS interoperability claimed.
type nativeDomainObserver struct {
	calls atomic.Int32
	ttl   time.Duration
}

func (o *nativeDomainObserver) ObserveDomain(ctx context.Context, claim organization.DomainClaim) (organization.DomainObservation, error) {
	if err := ctx.Err(); err != nil {
		return organization.DomainObservation{}, err
	}
	o.calls.Add(1)
	at := time.Now().UTC().Truncate(time.Microsecond)
	ttl := o.ttl
	if ttl == 0 {
		ttl = time.Hour
	}
	return organization.DomainObservation{Claim: claim, Method: organization.DomainDNS, ObservedAt: at, ExpiresAt: at.Add(ttl), Verified: true}, nil
}

func evidenceFixture(t *testing.T) (*orgFixture, *nativeDomainObserver) {
	t.Helper()
	f := newOrgFixture(t, organizationpg.DomainClaimMigrationSource{Version: 310}, organizationpg.DomainEvidenceMigrationSource{Version: 311})
	observer := new(nativeDomainObserver)
	var err error
	f.domainEvidence, err = organizationpg.NewDomainEvidenceSource(observer, [32]byte{0x81})
	if err != nil {
		t.Fatal(err)
	}
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 10, EvidenceMaximumAge: time.Hour}
	f.compose(t)
	f.create(t, "org-test-basic")
	committedTeam(t, f, reserveDomain(t, f, domainRequest(t, f, "org-test-basic", "proof", "proof.example", 1)))
	return f, observer
}
func evidenceOwner(t *testing.T, f *orgFixture, service *organizationpg.Service, recovery ...organizationpg.Recovery) *organizationpg.DomainEvidenceService {
	t.Helper()
	if service == nil {
		service = f.service
	}
	owner, err := service.DomainEvidence(f.auth("org-test-basic", "owner"), "127.0.0.1", recovery...)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}
func evidenceRequest(t *testing.T, f *orgFixture, epoch uint64) organization.DomainEvidenceRequest {
	t.Helper()
	r := domainRequest(t, f, "org-test-basic", "proof", "proof.example", epoch)
	r.ClaimVersion = 1
	return organization.DomainEvidenceRequest{Claim: r}
}
func prepareEvidence(t *testing.T, f *orgFixture, owner *organizationpg.DomainEvidenceService) organization.DomainEvidenceCommand {
	t.Helper()
	c, err := owner.Prepare(f.ctx, evidenceRequest(t, f, 2))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func evidenceRecovery(t *testing.T, c organization.DomainEvidenceCommand) organizationpg.Recovery {
	t.Helper()
	x, err := c.Command().Input()
	if err != nil {
		t.Fatal(err)
	}
	return organizationpg.Recovery{Binding: x.Binding}
}
func committedEvidence(t *testing.T, f *orgFixture, owner *organizationpg.DomainEvidenceService, c organization.DomainEvidenceCommand) organization.DomainEvidenceResult {
	t.Helper()
	r, err := owner.ApplyDomainEvidence(f.ctx, c)
	if err != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted || r.Proof.ProofVersion == 0 {
		t.Fatal("domain evidence not committed", r.Receipt.Outcome, err)
	}
	return r
}

func TestDomainEvidenceNativeApplyReadRecoverAndConflict(t *testing.T) {
	f, observer := evidenceFixture(t)
	owner := evidenceOwner(t, f, nil)
	c := prepareEvidence(t, f, owner)
	x, _ := c.Command().Input()
	if _, err := f.participant.MapCommand(c.Command()); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("public mapping forged external admission", err)
	}
	result := committedEvidence(t, f, owner, c)
	if result.Proof != x.DomainProof {
		t.Fatal("commit changed original authoritative proof")
	}
	key := organization.DomainProofKey(result.Proof)
	if got, err := owner.GetDomainProof(f.ctx, key); err != nil || got != result.Proof {
		t.Fatal("current primary proof", err)
	}
	for range 2 {
		got, err := owner.ApplyDomainEvidence(f.ctx, c)
		if err != nil || got.Proof != result.Proof || !reflect.DeepEqual(got.Receipt, result.Receipt) {
			t.Fatal("same command replay changed original proof", err)
		}
		recovered, err := evidenceOwner(t, f, nil, evidenceRecovery(t, c)).RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
		if err != nil || recovered.Proof != result.Proof || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("exact recovery changed proof", err)
		}
	}
	if observer.calls.Load() != 1 {
		t.Fatal("apply/recovery repeated external observation")
	}
	// Same command identity, changed original observation is not an idempotent retry.
	changed := evidenceOwner(t, f, nil)
	request := evidenceRequest(t, f, 3)
	request.Claim.CommandID = x.Binding.CommandID
	changedCommand, err := changed.Prepare(f.ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := changed.ApplyDomainEvidence(f.ctx, changedCommand); !errors.Is(err, organization.ErrConflict) || got.Proof != (organization.DomainProof{}) {
		t.Fatal("changed command reused authority", err)
	}
	for _, mutate := range []func(*organization.DomainProofKey){func(k *organization.DomainProofKey) { k.TenantID = "other" }, func(k *organization.DomainProofKey) { k.OrganizationID = "other" }, func(k *organization.DomainProofKey) { k.ClaimID = "other" }, func(k *organization.DomainProofKey) { k.Domain = "other.example" }, func(k *organization.DomainProofKey) { k.ClaimVersion++ }, func(k *organization.DomainProofKey) { k.ProofVersion++ }, func(k *organization.DomainProofKey) { k.Method = organization.DomainHTTPS }, func(k *organization.DomainProofKey) { k.ObservedAt = k.ObservedAt.Add(time.Microsecond) }, func(k *organization.DomainProofKey) { k.ExpiresAt = k.ExpiresAt.Add(time.Microsecond) }, func(k *organization.DomainProofKey) { k.Revoked = true }} {
		wrong := key
		mutate(&wrong)
		if got, err := owner.GetDomainProof(f.ctx, wrong); err == nil || got != (organization.DomainProof{}) {
			t.Fatal("scope mismatch granted proof")
		}
	}
	r := domainRequest(t, f, "org-test-basic", "proof", "proof.example", 3)
	r.ClaimVersion = 1
	withdrawn, err := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, withdrawn)
	if _, err = owner.GetDomainProof(f.ctx, key); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn claim retained routing proof", err)
	}
	recovered, err := owner.RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
	if err != nil || recovered.Proof != result.Proof {
		t.Fatal("withdrawal rewrote historical proof", err)
	}
}

func TestDomainEvidenceNativeTerminalRevocation(t *testing.T) {
	f, observer := evidenceFixture(t)
	owner := evidenceOwner(t, f, nil)
	c := prepareEvidence(t, f, owner)
	original := committedEvidence(t, f, owner, c)
	revoker := evidenceOwner(t, f, nil)
	r := evidenceRequest(t, f, 3)
	r.ProofVersion = 1
	revoked, err := revoker.PrepareRevocation(f.ctx, r, organization.DomainProofKey(original.Proof))
	if err != nil {
		t.Fatal(err)
	}
	terminal := committedEvidence(t, f, revoker, revoked)
	expected := original.Proof
	expected.ProofVersion = 2
	expected.Revoked = true
	if terminal.Proof != expected {
		t.Fatal("revocation reset original observation")
	}
	if _, err = owner.GetDomainProof(f.ctx, organization.DomainProofKey(original.Proof)); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("revoked proof remained current", err)
	}
	x, _ := c.Command().Input()
	historical, err := owner.RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
	if err != nil || historical.Proof != original.Proof {
		t.Fatal("revocation changed original committed result", err)
	}
	next := evidenceOwner(t, f, nil)
	nextCommand, err := next.Prepare(f.ctx, evidenceRequest(t, f, 4))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := next.ApplyDomainEvidence(f.ctx, nextCommand); !errors.Is(err, organization.ErrConflict) || got.Proof != (organization.DomainProof{}) {
		t.Fatal("terminal revocation resurrected", err)
	}
	if observer.calls.Load() != 2 {
		t.Fatal("revocation performed external observation")
	}
}

func TestDomainEvidenceNativeCurrentAuthorityDenials(t *testing.T) {
	for _, kind := range []string{"member", "organization", "session"} {
		t.Run(kind, func(t *testing.T) {
			f, _ := evidenceFixture(t)
			owner := evidenceOwner(t, f, nil)
			c := prepareEvidence(t, f, owner)
			var query string
			switch kind {
			case "member":
				query = `UPDATE organization.memberships SET state='removed',version=version+1 WHERE user_id='owner'`
			case "organization":
				query = `UPDATE organization.organizations SET state='archived',version=version+1`
			case "session":
				query = `UPDATE organization_sessions.sessions SET state='revoked' WHERE user_id='owner'`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, query); err != nil {
				t.Fatal(err)
			}
			if got, err := owner.ApplyDomainEvidence(f.ctx, c); !errors.Is(err, organization.ErrForbidden) || got.Proof != (organization.DomainProof{}) {
				t.Fatal("stale current authority applied proof", err)
			}
			x, _ := c.Command().Input()
			if got, err := owner.RecoverDomainEvidence(f.ctx, x.Binding.CommandID); !errors.Is(err, organization.ErrForbidden) || got.Proof != (organization.DomainProof{}) {
				t.Fatal("stale authority recovered proof", err)
			}
		})
	}
}

func TestDomainEvidenceNativeRollbackAndLostCommit(t *testing.T) {
	for _, table := range []string{"audit.records", "public.identity_outbox_bindings"} {
		t.Run(table, func(t *testing.T) {
			f, _ := evidenceFixture(t)
			owner := evidenceOwner(t, f, nil)
			c := prepareEvidence(t, f, owner)
			x, _ := c.Command().Input()
			when := ""
			if table == "audit.records" {
				when = " WHEN (NEW.outcome=" + strconv.Itoa(int(audit.OutcomeSucceeded)) + ")"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.evidence_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic evidence failure'; END $$; CREATE TRIGGER evidence_fail BEFORE INSERT ON `+table+` FOR EACH ROW`+when+` EXECUTE FUNCTION public.evidence_fail()`); err != nil {
				t.Fatal(err)
			}
			got, err := owner.ApplyDomainEvidence(f.ctx, c)
			if err == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted || got.Proof != (organization.DomainProof{}) {
				t.Fatal("protected failure did not rollback proof", got.Receipt.Outcome, err)
			}
			if _, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER evidence_fail ON `+table+`; DROP FUNCTION public.evidence_fail()`); err != nil {
				t.Fatal(err)
			}
			var proofs, epoch int
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.domain_evidence),version::integer FROM organization.organizations`).Scan(&proofs, &epoch); err != nil || proofs != 0 || epoch != 2 {
				t.Fatal("partial authority after rollback", proofs, epoch, err)
			}
			recovered, err := evidenceOwner(t, f, nil, evidenceRecovery(t, c)).RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
			var dependencyFailure identity.UnavailableError
			// The sole journal preserves the original dependency-failure error
			// alongside its authoritative NotCommitted classification on recovery.
			if !errors.As(err, &dependencyFailure) || recovered.Receipt.Outcome != identity.CommitOutcomeNotCommitted || recovered.Receipt.Binding != x.Binding || recovered.Proof != (organization.DomainProof{}) {
				t.Fatal("durable abort recovery", err)
			}
		})
	}
	f, observer := evidenceFixture(t)
	service, fault := f.lostCommitService(t)
	owner := evidenceOwner(t, f, service)
	c := prepareEvidence(t, f, owner)
	x, _ := c.Command().Input()
	fault.armed.Store(true)
	result, err := owner.ApplyDomainEvidence(f.ctx, c)
	if err == nil || !fault.lost.Load() || result.Receipt.Outcome != identity.CommitOutcomeUnknown || result.Proof != (organization.DomainProof{}) {
		t.Fatal("lost commit inferred authority", result.Receipt.Outcome, err)
	}
	recovered, err := evidenceOwner(t, f, nil, evidenceRecovery(t, c)).RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
	if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Proof != x.DomainProof || observer.calls.Load() != 1 {
		t.Fatal("lost commit failed exact proof recovery", err)
	}
}

func TestDomainEvidenceNativeContentionAndOriginalExpiry(t *testing.T) {
	t.Run("contention", func(t *testing.T) {
		f, _ := evidenceFixture(t)
		first, second := evidenceOwner(t, f, nil), evidenceOwner(t, f, nil)
		a, b := prepareEvidence(t, f, first), prepareEvidence(t, f, second)
		var wait sync.WaitGroup
		wait.Add(2)
		outcomes := make(chan identity.CommitOutcome, 2)
		for _, attempt := range []struct {
			owner   *organizationpg.DomainEvidenceService
			command organization.DomainEvidenceCommand
		}{{first, a}, {second, b}} {
			go func() {
				defer wait.Done()
				result, _ := attempt.owner.ApplyDomainEvidence(f.ctx, attempt.command)
				outcomes <- result.Receipt.Outcome
			}()
		}
		wait.Wait()
		close(outcomes)
		committed := 0
		for outcome := range outcomes {
			if outcome == identity.CommitOutcomeCommitted {
				committed++
			}
		}
		if committed != 1 {
			t.Fatal("concurrent proof commands did not select exactly one", committed)
		}
	})
	t.Run("original-expiry", func(t *testing.T) {
		f, observer := evidenceFixture(t)
		observer.ttl = 500 * time.Millisecond
		owner := evidenceOwner(t, f, nil)
		c := prepareEvidence(t, f, owner)
		x, _ := c.Command().Input()
		lock, err := f.pool.Raw().Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(f.ctx)
		if _, err = lock.Exec(f.ctx, `SELECT tenant_id FROM organization.tenant_locks WHERE tenant_id='org-test-basic' FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		done := make(chan organization.DomainEvidenceResult, 1)
		fail := make(chan error, 1)
		go func() { result, err := owner.ApplyDomainEvidence(f.ctx, c); done <- result; fail <- err }()
		entered := false
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if err = f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%organization.tenant_locks%')`).Scan(&entered); err != nil {
				t.Fatal(err)
			}
			if entered {
				break
			}
			tick := time.NewTimer(5 * time.Millisecond)
			select {
			case <-f.ctx.Done():
				tick.Stop()
				t.Fatal(f.ctx.Err())
			case <-tick.C:
			}
		}
		if !entered {
			t.Fatal("execution never waited on original tenant authority lock")
		}
		timer := time.NewTimer(time.Until(x.DomainProof.ExpiresAt.Add(30 * time.Millisecond)))
		defer timer.Stop()
		<-timer.C
		if err = lock.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		result, err := <-done, <-fail
		if err == nil || result.Proof != (organization.DomainProof{}) || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("lock wait renewed original proof expiry", err)
		}
	})
	t.Run("current-expiry", func(t *testing.T) {
		f, observer := evidenceFixture(t)
		observer.ttl = 500 * time.Millisecond
		owner := evidenceOwner(t, f, nil)
		c := prepareEvidence(t, f, owner)
		original := committedEvidence(t, f, owner, c)
		x, _ := c.Command().Input()
		timer := time.NewTimer(time.Until(original.Proof.ExpiresAt.Add(time.Millisecond)))
		defer timer.Stop()
		<-timer.C
		if _, err := owner.GetDomainProof(f.ctx, organization.DomainProofKey(original.Proof)); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("expired proof remained current", err)
		}
		recovered, err := owner.RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
		if err != nil || recovered.Proof != original.Proof {
			t.Fatal("expiry rewrote historical result", err)
		}
	})
}

func TestDomainEvidenceNativeArchiveDoesNotResurrect(t *testing.T) {
	f, _ := evidenceFixture(t)
	owner := evidenceOwner(t, f, nil)
	c := prepareEvidence(t, f, owner)
	original := committedEvidence(t, f, owner, c)
	x, _ := c.Command().Input()
	// Old and new native lifecycle writers both update this owned parent state;
	// the database invariant does not depend on the writer selecting evidence.
	for _, state := range []string{"archived", "active"} {
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state=$1,version=version+1`, state); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.GetDomainProof(f.ctx, organization.DomainProofKey(original.Proof)); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("archive/restore resurrected old proof", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.domain_claims SET proof_retired=false`); err == nil {
		t.Fatal("terminal proof retirement reset")
	}
	recovered, err := owner.RecoverDomainEvidence(f.ctx, x.Binding.CommandID)
	if err != nil || recovered.Proof != original.Proof {
		t.Fatal("lifecycle retirement rewrote history", err)
	}
	next := evidenceOwner(t, f, nil)
	command, err := next.Prepare(f.ctx, evidenceRequest(t, f, 5))
	if err != nil {
		t.Fatal(err)
	}
	if result, err := next.ApplyDomainEvidence(f.ctx, command); err == nil || result.Proof != (organization.DomainProof{}) {
		t.Fatal("retired claim acquired new authority", err)
	}
}

func TestDomainEvidenceNativePopulatedMigration(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	committedTeam(t, f, reserveDomain(t, f, domainRequest(t, f, tenant, "retained", "retained.example", 1)))
	r := domainRequest(t, f, tenant, "retained", "retained.example", 2)
	r.ClaimVersion = 1
	p, err := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	committedTeam(t, f, reserveDomain(t, f, domainRequest(t, f, tenant, "requested", "requested.example", 3)))
	steps, err := (organizationpg.DomainEvidenceMigrationSource{Version: 311}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
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
	runner, err := migrations.NewRunner(append(append(migrationList(nil), f.history...), steps...), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = runner.Up(f.ctx); err != nil {
			t.Fatal("populated proof migration", err)
		}
	}
	for _, expected := range []struct {
		id      string
		state   organization.DomainClaimState
		version uint64
		retired bool
	}{{"retained", organization.DomainWithdrawn, 2, true}, {"requested", organization.DomainRequested, 1, false}} {
		var state organization.DomainClaimState
		var version uint64
		var retired bool
		if err = f.pool.Raw().QueryRow(f.ctx, `SELECT state,version::bigint,proof_retired FROM organization.domain_claims WHERE claim_id=$1`, expected.id).Scan(&state, &version, &retired); err != nil || state != expected.state || version != expected.version || retired != expected.retired {
			t.Fatal("migration changed reservation custody", err)
		}
	}
	if current, err := f.service.GetDomainClaim(f.ctx, domainRead(f, tenant, "requested")); err != nil || current.DomainClaim.State != organization.DomainRequested || current.Organization.Version != 4 {
		t.Fatal("old binary lost current custody", err)
	}
}
