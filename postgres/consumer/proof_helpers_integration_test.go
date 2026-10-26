//go:build integration

package consumer_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
const transferAudience = "organization-action"

const transferFixturePassword = "synthetic organization transfer password"

func transferProofSource(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, storage sessionpg.Config, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, policy authorization.Service, revision uint64, tenants []string, fingerprintKey [32]byte, lifecycle ...bool) (*passwordpg.ReauthenticationService, *passwordpg.ActionPrimarySource, primitive.EncodedHash) {
	t.Helper()
	install := func(namespace string, source migrations.Source) {
		t.Helper()
		backend, err := migrationpg.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(source, backend)
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			if _, err = runner.Up(ctx); err != nil {
				t.Fatal("transfer prerequisite migration", err)
			}
		}
	}
	var history migrations.Source = passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.UsernameSigninMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11}
	targets := []passwordpg.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: string(organization.OwnerTransfer), Audience: transferAudience}}
	if len(lifecycle) > 0 && lifecycle[0] {
		history = passwordpg.OrganizationLifecycleReauthenticationMigrationSource{Base: history, Version: 12}
		for _, op := range []organization.Operation{organization.Archive, organization.Restore} {
			targets = append(targets, passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(op), Audience: transferAudience})
		}
	}
	install("identity_password", history)
	install("transfer_admission", riskpg.DurableCounterMigrationSource{Schema: "transfer_admission", Version: 1})
	material := func() []byte {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { clear(b) })
		return b
	}
	riskPolicy, err := baselineRiskPolicy(revision, false, false)
	if err != nil {
		t.Fatal("transfer risk policy", err)
	}
	key, err := risk.NewCounterDigestKey(1, material())
	if err != nil {
		t.Fatal("transfer counter key", err)
	}
	evidence, err := risk.NewEvidenceKey(1, material(), material())
	if err != nil {
		t.Fatal("transfer evidence key", err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "transfer_admission", Namespace: "transfer-verify", Policy: riskPolicy, Keys: []risk.CounterDigestKey{key}, ReplayKey: material(), Tenants: tenants, MaximumRecords: 1000, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal("transfer durable counters", err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: riskPolicy, Keys: []risk.CounterDigestKey{key}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal("transfer counter coordinator", err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal("transfer audit sink", err)
	}
	policyID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: riskPolicy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		t.Fatal("transfer risk evaluator", err)
	}
	crypto, err := primitive.New(primitive.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	dummy, err := crypto.Hash(ctx, []byte(transferFixturePassword))
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	signer, err := passwordpg.NewReauthenticationSigningKey("transfer-proof", private)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: revision}
	// Race instrumentation can stretch real Argon2 work beyond this fixture's
	// former three-second request budget. Keep bounded setup headroom without
	// changing production deadlines, signed proof age or session freshness.
	source, err := passwordpg.NewReauthenticationService(pool, passwordpg.ReauthenticationConfig{Repository: passwordpg.Config{MaximumDuration: 8 * time.Second, HashPolicy: primitive.DefaultPolicy()}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 5 * time.Second, DummyHash: dummy, Now: time.Now}, Session: storage, Profile: profile, LookupKeys: []session.DigestKey{lookup}, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "transfer-verify", Keys: []risk.EvidenceKey{evidence}}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 8 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: fingerprintKey}, QueryPolicy: &query, AdmissionPolicy: &query}, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{"transfer-proof": private.Public().(ed25519.PublicKey)}, Issuer: "organization-test", Environment: "isolated", Targets: targets, TTL: 5 * time.Minute, IdentifierKey: material()})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := passwordpg.NewActionPrimarySource(source, passwordpg.ActionPrimaryConfig{Action: string(organization.OwnerTransfer), Audience: transferAudience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	return source, primary, dummy
}

func issueTransferProof(t *testing.T, ctx context.Context, source *passwordpg.ReauthenticationService, a organization.Authentication, user identity.UserID, revision uint64, candidate string, operation ...organization.Operation) auth.ReauthenticationProof {
	t.Helper()
	secret, err := primitive.NewSecret([]byte(candidate))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(revision), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(a.TenantID), Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	op := organization.OwnerTransfer
	if len(operation) > 0 {
		op = operation[0]
	}
	got, err := source.Verify(ctx, passwordpg.ReauthenticationRequest{TenantID: a.TenantID, Session: a.Bearer, Password: secret, Target: passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(op), Audience: transferAudience}, Caller: caller, Network: "127.0.0.1", Device: "transfer-consumer"})
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Proof == (auth.ReauthenticationProof{}) {
		t.Fatal("real action-bound password verification", err)
	}
	return got.Proof
}

func lifecyclePrimaries(t *testing.T, source *passwordpg.ReauthenticationService) (*passwordpg.ActionPrimarySource, *passwordpg.ActionPrimarySource) {
	t.Helper()
	makeSource := func(op organization.Operation) *passwordpg.ActionPrimarySource {
		t.Helper()
		s, e := passwordpg.NewActionPrimarySource(source, passwordpg.ActionPrimaryConfig{Action: string(op), Audience: transferAudience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	return makeSource(organization.Archive), makeSource(organization.Restore)
}

func assertLifecycleProofConsumed(t *testing.T, ctx context.Context, pool *database.Pool, proof auth.ReauthenticationProof, p organizationpg.PreparedCommand, op organization.Operation) {
	t.Helper()
	b := mustRoleRecovery(t, p).Binding
	command, e := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if e != nil {
		t.Fatal(e)
	}
	var consumed bool
	e = pool.Raw().QueryRow(ctx, `SELECT coalesce(consumed_command_id=$4 AND consumed_purpose=$5 AND consumed_at IS NOT NULL,false) FROM identity_password.reauthentication_records WHERE proof_id=$1 AND tenant_id=$2 AND user_id=$3 AND purpose='identity.password.verify'`, string(proof.Proof.ID), string(proof.Proof.Tenant), string(proof.Proof.Subject), command, string(op)).Scan(&consumed)
	if e != nil || !consumed {
		t.Fatal("lifecycle did not consume exact password proof for original command/action", e)
	}
}
