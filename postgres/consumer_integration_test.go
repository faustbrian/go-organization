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

	"github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
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
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

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

func TestOrganizationGenuinePasswordConsumer(t *testing.T) {
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
		t.Fatal("public native migration application failed", e)
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
	sessions, e := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if e != nil {
		t.Fatal(e)
	}
	register := func() (organization.Authentication, identity.UserID, func() organization.Authentication, func(*passwordpg.ReauthenticationService, organization.Authentication) auth.ReauthenticationProof) {
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
		signin := func() (organization.Authentication, identity.UserID) {
			flow = preauth("password")
			status, body, cookies = call("/v1/password/signin", map[string]any{"flowID": string(flow.FlowID), "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
			var signed passwordhttp.SigninResponse
			if status != 200 || json.Unmarshal(body, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
				t.Fatal("actual password signin failed", status)
			}
			token, e := session.ParseToken(cookies[0].Value)
			if e != nil {
				t.Fatal("issued session token rejected")
			}
			credential, e := session.NewCredential(session.CredentialBearer, token)
			if e != nil {
				t.Fatal(e)
			}
			observed, e := sessions.Get(ctx, session.GetRequest{TenantID: baselineTenant, Credential: credential})
			if e != nil || observed.ValidateAt(time.Now()) != nil {
				t.Fatal("real primary SessionService rejected issued session", e)
			}
			bindings, e := observed.Session.Bindings()
			if e != nil {
				t.Fatal(e)
			}
			return organization.Authentication{TenantID: baselineTenant, Bearer: auth.NewBearerCredential(cookies[0].Value)}, bindings.UserID
		}
		first, user := signin()
		return first, user, func() organization.Authentication {
				next, nextUser := signin()
				if nextUser != user {
					t.Fatal("fresh genuine signin changed original user")
				}
				return next
			}, func(source *passwordpg.ReauthenticationService, a organization.Authentication) auth.ReauthenticationProof {
				return issueTransferProof(t, ctx, source, a, user, 9, candidate)
			}
	}
	owner, ownerID, signinOwner, ownerProof := register()
	member, memberID, signinRecipient, _ := register()
	if ownerID == memberID {
		t.Fatal("real registrations did not create distinct users")
	}
	service := consumerOrganizationService(t, pool, sessions, profile, lookup, keys, material)
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	orgID := organization.ID(id)
	p, e := service.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: orgID, Slug: "genuine", Name: "Genuine consumer", CorrelationID: "genuine-create"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := service.Execute(ctx, p); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("real session organization create failed", e)
	}
	read := organization.ReadRequest{Authentication: owner, OrganizationID: orgID, CorrelationID: "genuine-read"}
	if v, e := service.Get(ctx, read); e != nil || v.Actor.UserID != ownerID || v.Actor.Role != organization.RoleOwner {
		t.Fatal("real creator grant unavailable", e)
	}
	read.Authentication = member
	if _, e := service.Get(ctx, read); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("genuine nonmember gained scoped access", e)
	}
	p, e = service.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: orgID, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "genuine-add"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := service.Execute(ctx, p); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine target admission failed", e)
	}
	read.Limit = 10
	listed, e := service.ListMembers(ctx, read)
	if e != nil || len(listed.Members) != 2 {
		t.Fatal("genuine admitted member list failed", e)
	}
	users := map[identity.UserID]bool{}
	for _, m := range listed.Members {
		users[m.UserID] = m.Active && m.OrganizationID == orgID && m.TenantID == baselineTenant
	}
	if !users[ownerID] || !users[memberID] {
		t.Fatal("real member listing did not preserve exact user/organization scope")
	}
	p, e = service.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: orgID, UserID: memberID, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "genuine-remove"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := service.Execute(ctx, p); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine member removal failed", e)
	}
	read.Limit = 0
	if _, e := service.Get(ctx, read); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("removed genuine actor retained access", e)
	}
	read.Limit = 10
	if _, e := service.ListMembers(ctx, read); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("removed genuine actor retained member-list access", e)
	}
	exerciseGenuineMetadata(t, ctx, service, owner, member, memberID)
	recoveryOwner := owner
	trackOwnerSignin := func() organization.Authentication { recoveryOwner = signinOwner(); return recoveryOwner }
	exerciseGenuineInvitations(t, ctx, pool, db, service, sessions, profile, lookup, owner, member, ownerID, memberID, origin, keys, material, signinRecipient, trackOwnerSignin)
	exerciseGenuineTeams(t, ctx, db, service, owner, member, recoveryOwner, memberID)
	exerciseGenuineSelfLeave(t, ctx, service, owner, member, memberID, signinRecipient)
	exerciseGenuineOrganizationList(t, ctx, service, owner, member, memberID)
	transferPolicy, e := fixtureAuthorization()
	if e != nil {
		t.Fatal(e)
	}
	proofSource, primary, _ := transferProofSource(t, ctx, pool, db, sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, profile, lookup, transferPolicy, 9, []string{baselineTenant}, keys["fingerprint"])
	transferService := consumerOrganizationService(t, pool, sessions, profile, lookup, keys, material, primary)
	exerciseGenuineOwnerTransfer(t, ctx, transferService, owner, member, recoveryOwner, memberID, ownerProof(proofSource, owner))
}

func consumerOrganizationService(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, selectedPrimary ...*passwordpg.ActionPrimarySource) *organizationpg.Service {
	t.Helper()
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	teams := organization.TeamConfig{Version: 1, MaximumTeams: 100, MaximumMembers: 100, LifecycleVersion: 1}
	var primary *passwordpg.ActionPrimarySource
	var proofAudience string
	if len(selectedPrimary) > 0 {
		primary = selectedPrimary[0]
		proofAudience = transferAudience
	}
	participant, e := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, OwnerTransferPrimary: primary})
	if e != nil {
		t.Fatal(e)
	}
	policy, e := baselineRiskPolicy(9, false, false)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := risk.NewCounterDigestKey(1, material("counter"))
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if e != nil {
		t.Fatal(e)
	}
	counters, e := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if e != nil {
		t.Fatal(e)
	}
	domain, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	audits, e := postgres.NewIdentityContributor(postgres.Config{})
	if e != nil {
		t.Fatal(e)
	}
	outbox, e := lifecyclepg.NewContributor()
	if e != nil {
		t.Fatal(e)
	}
	registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if e != nil {
		t.Fatal(e)
	}
	authorize, e := fixtureAuthorization()
	if e != nil {
		t.Fatal(e)
	}
	coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}})
	if e != nil {
		t.Fatal(e)
	}
	service, e := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, OwnerTransferAudience: proofAudience, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, e := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), e)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry})
	if e != nil {
		t.Fatal(e)
	}
	return service
}
