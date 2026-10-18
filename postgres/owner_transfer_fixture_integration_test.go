//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

const transferAudience = "organization-action"
const transferFixturePassword = "synthetic organization transfer password"

// The actual security-event owner accepts canonical ULIDs as well as its
// opaque base64 and UUID profiles. Keep legacy display-ID fixtures unchanged.
var transferTenants = map[string]string{"org-test-basic": "01ARZ3NDEKTSV4RRFFQ69G5FA1", "org-test-race": "01ARZ3NDEKTSV4RRFFQ69G5FA2", "org-test-rollback": "01ARZ3NDEKTSV4RRFFQ69G5FA3", "org-test-scope": "01ARZ3NDEKTSV4RRFFQ69G5FA4"}
var transferUsers = map[string]string{"owner": "01ARZ3NDEKTSV4RRFFQ69G5FB1", "second": "01ARZ3NDEKTSV4RRFFQ69G5FB2", "member": "01ARZ3NDEKTSV4RRFFQ69G5FB3", "outsider": "01ARZ3NDEKTSV4RRFFQ69G5FB4"}

func isTransferFixtureTenant(value string) bool {
	for _, tenant := range transferTenants {
		if value == tenant {
			return true
		}
	}
	return false
}
func transferUser(value string) string {
	if id, ok := transferUsers[value]; ok {
		return id
	}
	return value
}

func (f *ownerFixture) add(t *testing.T, tenant, user string, role organization.Role, version uint64) organizationpg.PreparedCommand {
	return f.orgFixture.add(t, tenant, transferUser(user), role, version)
}

type ownerFixture struct {
	*orgFixture
	proofOwner *passwordpg.ReauthenticationService
}

// Use only actual native proof issuance, admission, signing, risk/audit and
// transactional consumption. This helper adds no domain store or auth engine.
func transferProofSource(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, storage sessionpg.Config, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, policy authorization.Service, revision uint64, tenants []string, fingerprintKey [32]byte) (*passwordpg.ReauthenticationService, *passwordpg.ActionPrimarySource, primitive.EncodedHash) {
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
	install("identity_password", passwordpg.ActionReauthenticationMigrationSource{Base: passwordpg.UsernameSigninMigrationSource{Base: passwordpg.EmailReauthenticationMigrationSource{}, Version: 10}, Version: 11})
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
	source, err := passwordpg.NewReauthenticationService(pool, passwordpg.ReauthenticationConfig{Repository: passwordpg.Config{MaximumDuration: 8 * time.Second, HashPolicy: primitive.DefaultPolicy()}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 5 * time.Second, DummyHash: dummy, Now: time.Now}, Session: storage, Profile: profile, LookupKeys: []session.DigestKey{lookup}, Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "transfer-verify", Keys: []risk.EvidenceKey{evidence}}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 8 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: fingerprintKey}, QueryPolicy: &query, AdmissionPolicy: &query}, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{"transfer-proof": private.Public().(ed25519.PublicKey)}, Issuer: "organization-test", Environment: "isolated", Targets: []passwordpg.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: string(organization.OwnerTransfer), Audience: transferAudience}}, TTL: 5 * time.Minute, IdentifierKey: material()})
	if err != nil {
		t.Fatal(err)
	}
	primary, err := passwordpg.NewActionPrimarySource(source, passwordpg.ActionPrimaryConfig{Action: string(organization.OwnerTransfer), Audience: transferAudience, MaximumAge: 15 * time.Minute, Transport: session.CredentialBearer})
	if err != nil {
		t.Fatal(err)
	}
	return source, primary, dummy
}

func newOwnerFixture(t *testing.T) *ownerFixture {
	t.Helper()
	tenants := []identity.TenantID{}
	users := []identity.UserID{}
	for _, tenant := range transferTenants {
		tenants = append(tenants, identity.TenantID(tenant))
	}
	for _, user := range transferUsers {
		users = append(users, identity.UserID(user))
	}
	f := newOrgFixtureWithIdentities(t, tenants, users, mfapg.MigrationSource{Version: 310})
	for _, tenant := range transferTenants {
		for alias, user := range transferUsers {
			f.authentication[tenant+":"+alias] = f.auth(tenant, user)
		}
	}
	// Seed the real MFA authority schema for these synthetic account fixtures,
	// retaining its actual signup-command FK rather than inferring empty state.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields)
SELECT decode(md5(tenant_id||':'||user_id),'hex'),tenant_id,'identity.password.signup',decode(repeat('01',32),'hex'),1,decode('01','hex') FROM identity.users;
INSERT INTO identity.commands(command_id,tenant_id,purpose)
SELECT command_id,tenant_id,purpose FROM identity.identity_command_id_claims WHERE purpose='identity.password.signup';
INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose)
SELECT tenant_id,user_id,1,0,decode(md5(tenant_id||':'||user_id),'hex'),'identity.password.signup' FROM identity.users`); err != nil {
		t.Fatal("native factor authority fixture", err)
	}
	c, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.Database = f.database
	db := stdlib.OpenDB(*c)
	defer db.Close()
	tenantNames := []string{}
	for _, tenant := range tenants {
		tenantNames = append(tenantNames, string(tenant))
	}
	source, primary, hash := transferProofSource(t, f.ctx, f.pool, db, sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}, f.profile, f.key, f.configuration.Authorization, 1, tenantNames, [32]byte{0x45})
	if _, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) SELECT tenant_id,user_id,credential_id,version,'argon2id',$1 FROM identity.credential_references WHERE kind=1`, hash.String()); err != nil {
		t.Fatal(err)
	}
	// Recomposition also preserves primary custody in the existing lost-commit
	// fixture's copied configuration, without a second coordinator implementation.
	f.ownerTransferPrimary = primary
	f.compose(t)
	return &ownerFixture{orgFixture: f, proofOwner: source}
}

func issueTransferProof(t *testing.T, ctx context.Context, source *passwordpg.ReauthenticationService, a organization.Authentication, user identity.UserID, revision uint64, candidate string) auth.ReauthenticationProof {
	t.Helper()
	secret, err := primitive.NewSecret([]byte(candidate))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(revision), Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(user)}, Tenant: authorization.TenantID(a.TenantID), Action: "identity.password.verify", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}}}
	got, err := source.Verify(ctx, passwordpg.ReauthenticationRequest{TenantID: a.TenantID, Session: a.Bearer, Password: secret, Target: passwordpg.ReauthenticationTarget{Purpose: "identity.password.verify", Action: string(organization.OwnerTransfer), Audience: transferAudience}, Caller: caller, Network: "127.0.0.1", Device: "transfer-consumer"})
	if err != nil || got.Outcome != identity.CommitOutcomeCommitted || got.Proof == (auth.ReauthenticationProof{}) {
		t.Fatal("real action-bound password verification", err)
	}
	return got.Proof
}
