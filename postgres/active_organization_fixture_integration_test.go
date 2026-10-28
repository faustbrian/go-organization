//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	password "github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
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

type activeOrganizationFixture struct {
	ctx                       context.Context
	pool                      *database.Pool
	db                        *sql.DB
	graph                     *baselineGraph
	sessions                  *session.SessionService
	profile                   sessionpg.IdentifierAdmissionConfig
	lookup                    session.DigestKey
	keys                      map[string][32]byte
	material                  func(string) []byte
	owner, member             organization.Authentication
	cookieMember              organization.Authentication
	spareMember               organization.Authentication
	ownerID, memberID         identity.UserID
	signinOwner, signinMember func() organization.Authentication
	ownerProof                func(*passwordpg.ReauthenticationService, organization.Authentication, ...organization.Operation) auth.ReauthenticationProof
}

func (f *activeOrganizationFixture) installSelectionPreservingPopulatedRows(t *testing.T) {
	t.Helper()
	snapshot := func() string {
		var before string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_array(
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,session_id) FROM session_store.sessions s),
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,family_id) FROM session_store.families s),
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,organization_id) FROM organization.organizations s),
		(SELECT jsonb_agg(to_jsonb(s) ORDER BY tenant_id,organization_id,user_id) FROM organization.memberships s))::text`).Scan(&before); err != nil {
			t.Fatal("populated upgrade snapshot", err)
		}
		return before
	}
	before := snapshot()
	backend, err := migrationpg.New(f.db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_selected_sessions")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(sessionpg.OrganizationSelectionMigrationSource{Schema: "session_store", Version: 7011}, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("public populated selection migration/replay", err)
		}
	}
	if after := snapshot(); after != before {
		t.Fatal("selection migration rewrote populated session/family/organization/member authority")
	}
}

// This is solely a storage-native same-family preservation fixture. It has no
// bearer, is never used for authentication and claims no public family-issuance
// API. The native repository must still decode its complete structural record.
func (f *activeOrganizationFixture) sameFamilySibling(t *testing.T, original session.SessionSpec) func() {
	t.Helper()
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	keys, err := sessionpg.SessionAuthorityKeys(original.TenantID, original.UserID, original.FamilyID, string(id))
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	lookup, err := json.Marshal(session.TokenDigest{KeyVersion: original.Lookup.KeyVersion, Sum: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO session_store.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record)
SELECT tenant_id,$3::text,user_id,family_id,version,family_version,state,digest_version,$4,expires_at,
jsonb_set(jsonb_set(jsonb_set(record,'{SessionID}',to_jsonb($3::text)),'{Authority,Session,ScopeKey}',to_jsonb($5::text)),'{Lookup}',$6::jsonb)
FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(original.TenantID), original.SessionID, string(id), digest[:], keys.Session, string(lookup)); err != nil {
		t.Fatal("same-family storage fixture", err)
	}
	repository, err := sessionpg.NewRepository(f.pool, sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(f.ctx, original.TenantID, string(id))
	if err != nil {
		t.Fatal("same-family complete native record", err)
	}
	spec, err := stored.Session.Bindings()
	if err != nil || spec.FamilyID != original.FamilyID || spec.SessionID == original.SessionID {
		t.Fatal("same-family fixture scope", err)
	}
	snapshot := func() string {
		var wire string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT to_jsonb(s) FROM session_store.sessions s WHERE tenant_id=$1 AND session_id=$2),(SELECT to_jsonb(f) FROM session_store.families f WHERE tenant_id=$1 AND family_id=$3))::text`, string(original.TenantID), string(id), original.FamilyID).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		return wire
	}
	before := snapshot()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(ctx, `DELETE FROM session_store.sessions WHERE tenant_id=$1 AND session_id=$2`, string(original.TenantID), string(id)); err != nil {
			t.Error("same-family owned fixture cleanup", err)
		}
	})
	return func() {
		if snapshot() != before {
			t.Fatal("selection changed same-family sibling or family authority")
		}
	}
}

// Signup and verification use the unchanged public HTTP composition above.
// Signin explicitly selects native bearer issuance; no cookie or CSRF state is
// removed from an existing session and no authentication proof is constructed.
func selectionSigninService(t *testing.T, ctx context.Context, pool *database.Pool, g *baselineGraph, material func(string) []byte) *passwordpg.SigninService {
	t.Helper()
	c := g.signin
	c.Transport, c.CSRFKey, c.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
	policy, err := baselineRiskPolicy(3, false, false)
	if err != nil {
		t.Fatal(err)
	}
	key, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "risk_store", Namespace: "local-baseline", Policy: policy, Keys: []risk.CounterDigestKey{key}, ReplayKey: material("counter-replay"), Tenants: []string{baselineTenant}, MaximumRecords: 100000, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal("actual counted authentication authority", err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}, Store: store, Clock: time.Now, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, lost risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, lost.Record())
		return err
	}}})
	if err != nil {
		t.Fatal(err)
	}
	c.Risk.Evaluation = evaluator
	g.signin = c
	service, err := passwordpg.NewSigninService(pool, c)
	if err != nil {
		t.Fatal("genuine bearer signin composition", err)
	}
	return service
}

func genuineSelectionSignin(t *testing.T, ctx context.Context, pool *database.Pool, c passwordpg.SigninConfig, service *passwordpg.SigninService, address, candidate string) (organization.Authentication, identity.UserID) {
	t.Helper()
	executor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: c.Session, Coordinator: c.Coordinator, Authorization: c.Coordinator.QueryPolicy.Authorization, Clock: clock.System{}, ActorID: baselineActor, Action: "identity.password.signin", Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: 9, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: baselineActor, Action: "identity.password.signin", Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], PolicyID: c.PolicyID, PolicyVersion: 9, Clock: clock.System{}, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: c.FlowKeys[0], TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	id := commandID(t)
	prepared, err := issuer.Prepare(session.PreAuthPrepareInput{CommandID: id, TenantID: baselineTenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual original signin preauth", err)
	}
	b, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal("actual signin flow unavailable")
	}
	secret, err := primitive.NewSecret([]byte(candidate))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	input, err := identifier.NewInput(address)
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: baselineActor}, Tenant: baselineTenant, Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}
	result, err := service.Signin(ctx, password.SigninRequest{TenantID: baselineTenant, PreAuthID: b.Binding.ID, Cookie: auth.NewBearerCredential(wire), Identifier: input, Password: secret, Remember: remember, Caller: caller, Origin: c.Origins[0], CallbackURL: c.CallbackURLs[0], Network: "127.0.0.1", Device: "selection-consumer"})
	if err != nil || result.State != auth.SignInStateAuthenticated || result.Transport != password.BearerSignin || result.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || result.Issuance.Session.CSRFState() != (session.CSRFState{}) {
		t.Fatal("actual registered password bearer issuance", err)
	}
	spec, err := result.Issuance.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	wire, err = result.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal("original issued bearer unavailable")
	}
	return organization.Authentication{TenantID: baselineTenant, Bearer: auth.NewBearerCredential(wire)}, spec.UserID
}

// Only these explicit provider seams are controlled. Capability issuance,
// encrypted queue custody, worker transitions and HIBP parsing remain native.
type registrationMailbox struct {
	mu   sync.Mutex
	body string
}

func (m *registrationMailbox) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || a.TenantID != baselineTenant || len(a.Body) > 4096 {
		return delivery.DeliveryResult{}, delivery.ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.body != "" {
		return delivery.DeliveryResult{}, delivery.ErrUnavailable
	}
	m.body = strings.Clone(a.Body)
	return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
}

type hibpTransport struct{}

func (hibpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || len(r.URL.Path) != 12 {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n")), Request: r}, nil
}

func consumerDatabase(t *testing.T) (context.Context, *database.Pool, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN")
	parsed, e := pgx.ParseConfig(dsn)
	if dsn == "" || e != nil || parsed.Host != "127.0.0.1" {
		t.Fatal("explicit task-owned loopback PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("isolated primary unavailable")
	}
	var existing int
	if e = admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&existing); e != nil || existing != 0 {
		_ = admin.Close(ctx)
		t.Fatal("consumer fixture requires absent native audit roles")
	}
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	name := "organization_consumer_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		t.Fatal("consumer database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("consumer database cleanup failed")
		}
		if _, e := admin.Exec(cleanup, "DROP ROLE IF EXISTS audit_writer,audit_reader,audit_retention"); e != nil {
			t.Error("consumer audit-role cleanup failed")
		}
		_ = admin.Close(cleanup)
	})
	parsed.Database = name
	parsed.RuntimeParams["search_path"] = "public"
	db := stdlib.OpenDB(*parsed)
	t.Cleanup(func() { _ = db.Close() })
	pool, e := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		c.ConnConfig.RuntimeParams["search_path"] = "public"
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("consumer pool cleanup failed")
		}
	})
	return ctx, pool, db
}

func newActiveOrganizationFixture(t *testing.T) *activeOrganizationFixture {
	ctx, pool, db := consumerDatabase(t)
	keyNames := []string{"fingerprint", "request", "counter", "risk-evidence", "risk-seal", "preauth-cookie", "session-token", "session-csrf", "http-device", "delivery-envelope", "dummy-password", "capability-binding", "capability-signing", "signin-proof", "migration", "counter-replay", "http-rate", "otp-lockout", "otp-wrap", "otp-attempt", "otp-code", "otp-intent", "identifier", "delivery-digest", "delivery-namespace", "password-flow", "signup-binding", "signup-intent", "verification-scope", "capability-replay", "capability-envelope", "counter-envelope", "verification-http"}
	keys := make(map[string][32]byte, len(keyNames))
	for _, name := range keyNames {
		var k [32]byte
		if _, e := rand.Read(k[:]); e != nil {
			t.Fatal("fixture entropy unavailable")
		}
		keys[name] = k
	}
	t.Cleanup(func() { clear(keys) })
	material := func(name string) []byte { k := keys[name]; return append([]byte(nil), k[:]...) }
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	mailbox := &registrationMailbox{}
	t.Cleanup(func() { mailbox.mu.Lock(); mailbox.body = ""; mailbox.mu.Unlock() })
	graph, e := fixtureGraph(ctx, origin, keys, pool, mailbox, hibpTransport{})
	if e != nil {
		var invalid identity.InvalidInputError
		if errors.As(e, &invalid) && len(invalid.Field) <= 128 && strings.IndexFunc(invalid.Field, func(r rune) bool { return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '.') }) < 0 {
			t.Fatal("public native identity graph rejected configuration field", invalid.Field)
		}
		t.Fatal("public native identity graph rejected", e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if graph.close(cleanup) != nil {
			t.Error("identity graph cleanup failed")
		}
	})
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, e := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if e != nil {
		t.Fatal("public migration plan failed", e)
	}
	install, e := identity.NewIdempotencyKey([]byte("organization-real-consumer-install"))
	if e != nil {
		t.Fatal(e)
	}
	applied, e := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "organization_real_consumer_install", Plan: plan.Plan, IdempotencyKey: install})
	if e != nil || applied.Result.State() != reference.MigrationApplied {
		t.Fatalf("public native migration application failed: state=%v deadline=%t canceled=%t receipts=%d", applied.Result.State(), errors.Is(e, context.DeadlineExceeded), errors.Is(e, context.Canceled), len(applied.Result.Receipts()))
	}
	// These existing public standalone allocations add common preparation and
	// lockout custody without selecting password-change or other feature APIs.
	kernelSteps, e := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	riskSteps, e := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	orgSteps, e := (organizationpg.MigrationSource{Version: 7000}).Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, extension := range []struct {
		namespace string
		steps     []migrations.Migration
	}{{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-1:]}, {"identity_risk_lockouts", riskSteps[len(riskSteps)-1:]}, {"organization", orgSteps}} {
		backend, e := migrationpg.New(db)
		if e != nil {
			t.Fatal(e)
		}
		backend, e = backend.ForNamespace(extension.namespace)
		if e != nil {
			t.Fatal(e)
		}
		runner, e := migrations.NewRunner(migrationList(extension.steps), backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("public common/organization migrations failed", e)
		}
	}
	if e = graph.features.Initialize(ctx); e != nil {
		t.Fatal("native initialization failed", e)
	}
	server.Config.Handler = graph.server.Handler()
	server.StartTLS()
	lookup, e := session.NewDigestKey(11, material("session-token"))
	if e != nil {
		t.Fatal(e)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	sessions, e := sessionpg.NewSelectedSessionService(pool, sessionpg.SelectedSessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Admission: sessionpg.SelectedSessionAdmissionConfig{SingleFactor: sessionpg.SingleFactorSessionAdmissionConfig{Verified: &profile}, OrganizationPassword: &sessionpg.OrganizationPasswordSessionAdmission{Profile: profile, Authority: repository}}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if e != nil {
		t.Fatal(e)
	}
	nativeSignin := selectionSigninService(t, ctx, pool, graph, material)
	var cookieMember organization.Authentication
	register := func() (organization.Authentication, identity.UserID, func() organization.Authentication, func(*passwordpg.ReauthenticationService, organization.Authentication, ...organization.Operation) auth.ReauthenticationProof) {
		t.Helper()
		client := server.Client()
		client.Timeout = 6 * time.Second
		client.Jar, _ = cookiejar.New(nil)
		call := func(path string, body any, idempotency string) (int, []byte, []*http.Cookie) {
			t.Helper()
			wire, e := json.Marshal(body)
			if e != nil {
				t.Fatal(e)
			}
			r, e := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
			if idempotency != "" {
				r.Header.Set("Idempotency-Key", idempotency)
			}
			response, e := client.Do(r)
			if e != nil {
				t.Fatal("native identity HTTPS unavailable")
			}
			payload, e := io.ReadAll(io.LimitReader(response.Body, 16385))
			closed := response.Body.Close()
			if e != nil || closed != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("native identity response boundary failed")
			}
			return response.StatusCode, payload, response.Cookies()
		}
		preauth := func(method string) sessionhttp.PreAuthResponse {
			t.Helper()
			status, body, _ := call("/v1/session/preauth-issue", map[string]string{"method": method}, "")
			var out sessionhttp.PreAuthResponse
			if status != 200 || json.Unmarshal(body, &out) != nil || !out.Issued {
				t.Fatal("actual preauth rejected", status)
			}
			return out
		}
		var random [32]byte
		if _, e := rand.Read(random[:]); e != nil {
			t.Fatal(e)
		}
		address := "organization-" + hex.EncodeToString(random[:8]) + "@example.invalid"
		candidate := hex.EncodeToString(random[:])
		clear(random[:])
		flow := preauth("signup")
		status, body, cookies := call("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "organization-signup-"+string(flow.FlowID))
		var signup passwordhttp.SignupResponse
		if status != 200 || json.Unmarshal(body, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(cookies) != 0 {
			t.Fatal("actual signup did not commit verification-only", status)
		}
		if _, e := graph.workers.ProcessDeliveryOne(ctx, 0); e != nil {
			t.Fatal("actual verification delivery failed", e)
		}
		mailbox.mu.Lock()
		link := mailbox.body
		mailbox.body = ""
		mailbox.mu.Unlock()
		parsed, e := url.Parse(link)
		if e != nil || parsed.Query().Get("token") == "" {
			t.Fatal("actual capability not captured")
		}
		status, body, cookies = call("/v1/email/verification-confirm", map[string]string{"token": parsed.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(commandID(t))}, "")
		var confirmed emailhttp.ConfirmationResponse
		if status != 200 || json.Unmarshal(body, &confirmed) != nil || !confirmed.Confirmed || confirmed.CommitOutcome != "committed" || len(cookies) != 0 {
			t.Fatal("actual confirmation failed or issued session", status)
		}
		flow = preauth("password")
		status, body, cookies = call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
		var cookieSignin passwordhttp.SigninResponse
		if status != 200 || json.Unmarshal(body, &cookieSignin) != nil || !cookieSignin.SignedIn || len(cookies) != 1 {
			t.Fatal("unchanged genuine cookie signin", status)
		}
		cookieMember = organization.Authentication{TenantID: baselineTenant, Bearer: auth.NewBearerCredential(cookies[0].Value)}
		signin := func() (organization.Authentication, identity.UserID) {
			return genuineSelectionSignin(t, ctx, pool, graph.signin, nativeSignin, address, candidate)
		}
		first, user := signin()
		return first, user, func() organization.Authentication {
				next, nextUser := signin()
				if nextUser != user {
					t.Fatal("fresh genuine signin changed original user")
				}
				return next
			}, func(source *passwordpg.ReauthenticationService, a organization.Authentication, op ...organization.Operation) auth.ReauthenticationProof {
				return issueTransferProof(t, ctx, source, a, user, 9, candidate, op...)
			}
	}
	owner, ownerID, signinOwner, ownerProof := register()
	member, memberID, signinMember, _ := register()
	return &activeOrganizationFixture{ctx: ctx, pool: pool, db: db, graph: graph, sessions: sessions, profile: profile, lookup: lookup, keys: keys, material: material, owner: owner, member: member, cookieMember: cookieMember, ownerID: ownerID, memberID: memberID, signinOwner: signinOwner, signinMember: signinMember, ownerProof: ownerProof}
}
