//go:build integration

package consumer_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// The published leaf and actual native owner meet without an application
// adapter. Registration uses the retained public Reference graph over HTTPS;
// only its email sender and outbound HIBP provider are controlled seams.
func TestOrganizationGenuineHTTPConsumer(t *testing.T) {
	ctx, pool, db := consumerDatabase(t)
	keys := make(map[string][32]byte)
	for _, name := range strings.Fields("fingerprint request counter risk-evidence risk-seal preauth-cookie session-token session-csrf http-device delivery-envelope dummy-password capability-binding capability-signing signin-proof migration counter-replay http-rate otp-lockout otp-wrap otp-attempt otp-code otp-intent identifier delivery-digest delivery-namespace password-flow signup-binding signup-intent verification-scope capability-replay capability-envelope counter-envelope verification-http") {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("consumer entropy unavailable")
		}
		keys[name] = key
	}
	t.Cleanup(func() { clear(keys) })
	material := func(name string) []byte { key := keys[name]; return append([]byte(nil), key[:]...) }
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	mailbox := &registrationMailbox{}
	t.Cleanup(func() { mailbox.mu.Lock(); mailbox.body = ""; mailbox.mu.Unlock() })
	graph, err := fixtureGraph(ctx, origin, keys, pool, mailbox, hibpTransport{})
	if err != nil {
		t.Fatal("genuine Reference graph unavailable", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if graph.close(cleanup) != nil {
			t.Error("genuine Reference graph cleanup failed")
		}
	})
	installOrganizationHTTPConsumer(t, ctx, graph, db)
	lookup, err := session.NewDigestKey(11, material("session-token"))
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	newNative := func() *organizationpg.OperationService {
		source := consumerOrganizationService(t, pool, sessions, profile, lookup, keys, material)
		authorize, err := fixtureAuthorization()
		if err != nil {
			t.Fatal(err)
		}
		query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("organization-http-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("organization-http", map[string][]byte{"organization-http": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		service, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "organization-http-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
			id, err := identity.NewSubjectID()
			return organization.ID(id), errors.Join(ctx.Err(), err)
		}})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	backend, err := ratepg.OpenStrict(ctx, pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal("genuine HTTP rate owner unavailable", err)
	}
	// These are application-owned transport denial records, not substitute
	// protected domain audits. Successful mutations retain the native audit owner.
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE organization.http_rate_denials(operation text NOT NULL,reason text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	auditDenial := func(ctx context.Context, operation, reason string) error {
		_, err := pool.Raw().Exec(ctx, `INSERT INTO organization.http_rate_denials(operation,reason) VALUES($1,$2)`, operation, reason)
		return err
	}
	safe, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: backend, Namespace: "organization-http-consumer", Now: time.Now, MaximumDuration: time.Second, EmergencyMaximumKeys: 128, Degraded: func(ctx context.Context, e identityhttp.SafeRateEvent) error {
		return auditDenial(ctx, e.OperationID, "safe-degraded")
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = safe.Close() })
	admin, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: backend, Namespace: "organization-http-consumer", Key: keys["http-rate"], Now: time.Now, MaximumDuration: time.Second, Denied: func(ctx context.Context, e organizationhttp.AdminRateEvent) error {
		return auditDenial(ctx, string(e.Operation), e.Reason)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	parsedOrigin, _ := url.Parse(origin)
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: parsedOrigin.Hostname(), TenantID: baselineTenant}}}
	transport := identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Genuine organization consumer", Version: "1"}}
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: organizationhttp.Config{Network: network, Sessions: sessions, Service: newNative(), SafeRate: safe, AdminRate: admin, Now: time.Now, MaximumDuration: 4 * time.Second}, Create: true, Get: true, MemberList: true, MemberAdd: true, MemberRemove: true})
	if err != nil {
		t.Fatal("published organization feature rejected native owner", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewRouter(transport, ops, nil)
	if err != nil {
		t.Fatal("published organization router rejected native composition", err)
	}
	omitted, omittedDocument, err := identityhttp.NewRouter(transport, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var absent struct {
		Paths map[string]any `json:"paths"`
	}
	if json.Unmarshal(omittedDocument.JSON(), &absent) != nil || len(absent.Paths) != 0 {
		t.Fatal("omitted organization advertised routes")
	}
	omittedRequest := httptest.NewRequest(http.MethodPost, "/v1/organization/create", nil)
	omittedRequest.Host, omittedRequest.RemoteAddr, omittedRequest.TLS = parsedOrigin.Host, "127.0.0.1:12345", &tls.ConnectionState{}
	omittedResponse := httptest.NewRecorder()
	omitted.ServeHTTP(omittedResponse, omittedRequest)
	if omittedResponse.Code != 404 {
		t.Fatal("omitted organization exposed a route", omittedResponse.Code)
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil || document.Version() != "3.1.1" || len(document.Operations()) != 5 {
		t.Fatal("selected organization document unavailable", err)
	}
	validateResponse := func(path, method string, status int, body []byte) {
		t.Helper()
		schema := parsed.Raw()
		for _, key := range []string{"paths", strings.SplitN(path, "?", 2)[0], strings.ToLower(method), "responses", strconv.Itoa(status), "content", "application/json", "schema"} {
			var found bool
			schema, found = schema.Lookup(key)
			if !found {
				t.Fatal("actual native response undocumented", status)
			}
		}
		instance, err := parse.JSON(ctx, bytes.NewReader(body), parse.DefaultLimits())
		if err != nil {
			t.Fatal("actual native response not JSON")
		}
		report, err := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("actual native response violates selected schema", status)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/organization/", handler)
	mux.Handle("/", graph.server.Handler())
	server.Config.Handler = mux
	server.Config.ReadHeaderTimeout = time.Second
	server.Config.ReadTimeout = 6 * time.Second
	server.Config.WriteTimeout = 6 * time.Second
	server.Config.IdleTimeout = time.Second
	server.Config.MaxHeaderBytes = 32768
	server.StartTLS()
	owner, ownerID := registerOrganizationHTTPHuman(t, ctx, server, origin, graph, mailbox, sessions)
	member, memberID := registerOrganizationHTTPHuman(t, ctx, server, origin, graph, mailbox, sessions)
	if ownerID == memberID {
		t.Fatal("genuine HTTP users were not distinct")
	}
	var baselineDebits int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM rate_limit_atomic_commands`).Scan(&baselineDebits); err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Timeout = 6 * time.Second
	client.Jar = nil
	call := func(a organization.Authentication, method, path string, body any, key string, cookieOnly bool) (int, []byte) {
		t.Helper()
		var wire []byte
		if body != nil {
			var marshalErr error
			wire, marshalErr = json.Marshal(body)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			defer clear(wire)
		}
		r, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		if cookieOnly {
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: a.Bearer.Token()})
		} else {
			r.Header.Set("Authorization", "Bearer "+a.Bearer.Token())
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("native organization HTTPS unavailable")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(payload) > 1<<20 || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("Authorization") != "" || bytes.Contains(payload, []byte(a.Bearer.Token())) {
			t.Fatal("native organization response violated credential/IO custody")
		}
		validateResponse(path, method, response.StatusCode, payload)
		return response.StatusCode, payload
	}
	mutate := func(a organization.Authentication, path string, body any, key string, expected int) organizationhttp.MutationResponse {
		t.Helper()
		status, payload := call(a, http.MethodPost, path, body, key, false)
		var out organizationhttp.MutationResponse
		if status != expected || json.Unmarshal(payload, &out) != nil {
			t.Fatal("native HTTP mutation returned unexpected outcome", path, status)
		}
		return out
	}
	read := func(a organization.Authentication, path string, expected int) organizationhttp.ReadResponse {
		t.Helper()
		status, payload := call(a, http.MethodGet, path, nil, "", false)
		var out organizationhttp.ReadResponse
		if status != expected || expected == 200 && json.Unmarshal(payload, &out) != nil {
			t.Fatal("native HTTP read returned unexpected outcome", status)
		}
		return out
	}
	createBody := map[string]any{"name": "HTTP consumer", "slug": "http-consumer"}
	created := mutate(owner, "/v1/organization/create", createBody, "http-create", 200)
	assertOrganizationHTTPReceipt(t, ctx, db, newNative(), owner, created, organization.Create, ownerID, 0, 1)
	if status, _ := call(owner, http.MethodPost, "/v1/organization/create", createBody, "http-create", true); status != 400 {
		t.Fatal("ambient cookie supplied bearer fallback", status)
	}
	if retry := mutate(owner, "/v1/organization/create", createBody, "http-create", 200); !reflect.DeepEqual(retry, created) {
		t.Fatal("same HTTP key replaced original create custody")
	}
	changed := mutate(owner, "/v1/organization/create", map[string]any{"name": "HTTP consumer", "slug": "changed-intent"}, "http-create", 409)
	if changed.Committed || changed.Error != "conflict" {
		t.Fatal("changed keyed HTTP input was accepted")
	}
	getPath := "/v1/organization/get?organizationID=" + string(created.OrganizationID)
	if view := read(owner, getPath, 200); view.Organization.ID != created.OrganizationID || view.Organization.Version != 1 || view.Membership.UserID != ownerID || view.Membership.Role != organization.RoleOwner {
		t.Fatal("native HTTP creator read lost current authority")
	}
	addBody := map[string]any{"organizationID": created.OrganizationID, "userID": memberID, "role": "member", "organizationVersion": 1, "memberVersion": 0}
	added := mutate(owner, "/v1/organization/member/add", addBody, "http-add", 200)
	assertOrganizationHTTPReceipt(t, ctx, db, newNative(), owner, added, organization.AddMember, memberID, 1, 2)
	if retry := mutate(owner, "/v1/organization/member/add", addBody, "http-add", 200); !reflect.DeepEqual(retry, added) {
		t.Fatal("same HTTP admission key replaced original command")
	}
	listPath := "/v1/organization/member/list?organizationID=" + string(created.OrganizationID) + "&limit=10"
	if view := read(member, listPath, 200); view.Organization.Version != 2 || view.Membership.UserID != memberID || view.Members == nil || len(*view.Members) != 2 {
		t.Fatal("genuine admitted bearer could not list native members")
	}
	removeBody := map[string]any{"organizationID": created.OrganizationID, "userID": memberID, "organizationVersion": 2, "memberVersion": 1}
	removed := mutate(owner, "/v1/organization/member/remove", removeBody, "", 200)
	assertOrganizationHTTPReceipt(t, ctx, db, newNative(), owner, removed, organization.RemoveMember, memberID, 2, 3)
	if repeat := mutate(owner, "/v1/organization/member/remove", removeBody, "", 200); !reflect.DeepEqual(repeat, removed) {
		t.Fatal("non-keyed HTTP repeat fabricated another removal receipt")
	}
	read(member, getPath, 403)
	last := mutate(owner, "/v1/organization/member/remove", map[string]any{"organizationID": created.OrganizationID, "userID": ownerID, "organizationVersion": 3, "memberVersion": 1}, "", 409)
	if last.Committed || last.Error != "last_owner" {
		t.Fatal("HTTP last-owner denial was lost")
	}
	var orgVersion, targetVersion, targetState string
	var effects, mappings, rateDebits, denials, organizations, owners int
	if err := db.QueryRowContext(ctx, `SELECT o.version::text,m.version::text,m.state,(SELECT count(*) FROM organization.command_effects),(SELECT count(*) FROM identity.request_key_mappings WHERE namespace='organization-http-consumer'),(SELECT count(*) FROM rate_limit_atomic_commands),(SELECT count(*) FROM organization.http_rate_denials),(SELECT count(*) FROM organization.organizations),(SELECT count(*) FROM organization.memberships WHERE role='owner' AND state='active') FROM organization.organizations o JOIN organization.memberships m ON m.tenant_id=o.tenant_id AND m.organization_id=o.organization_id WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3`, baselineTenant, string(created.OrganizationID), string(memberID)).Scan(&orgVersion, &targetVersion, &targetState, &effects, &mappings, &rateDebits, &denials, &organizations, &owners); err != nil || orgVersion != "3" || targetVersion != "2" || targetState != "removed" || effects != 3 || mappings != 2 || rateDebits != baselineDebits+8 || denials != 0 || organizations != 1 || owners != 1 {
		t.Fatal("HTTP journey diverged from durable domain/key/atomic-rate owners", err)
	}
	// Withdraw the actual current session row, not a transport authentication
	// double. Even a retained original key must then disclose no old receipt.
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, baselineTenant, string(ownerID)); err != nil {
		t.Fatal(err)
	}
	denied := mutate(owner, "/v1/organization/create", createBody, "http-create", 403)
	if denied.Committed || denied.CommandID != "" || denied.Recovery != nil || denied.Error != "forbidden" {
		t.Fatal("revoked HTTP bearer recovered original authority")
	}
	read(owner, getPath, 403)
	var afterEffects, afterDebits int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects),(SELECT count(*) FROM rate_limit_atomic_commands)`).Scan(&afterEffects, &afterDebits); err != nil || afterEffects != effects || afterDebits != rateDebits {
		t.Fatal("revoked actor reached domain work or HTTP admission", err)
	}
}

func installOrganizationHTTPConsumer(t *testing.T, ctx context.Context, graph *baselineGraph, db *sql.DB) {
	t.Helper()
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, err := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("organization-http-consumer-install"))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "organization_http_consumer_install", Plan: plan.Plan, IdempotencyKey: key})
	if err != nil || applied.Result.State() != reference.MigrationApplied {
		t.Fatal("native public migration application failed", err)
	}
	// Reference baseline 02c6195 migration_catalog.go includes the native atomic
	// rate migration in identity_http_rate when registration verification is
	// selected. Reuse that existing owner/history rather than reinstalling it.
	kernelSteps, err := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	riskSteps, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	orgSteps, err := (organizationpg.MigrationSource{Version: 7000}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	indexSteps, err := (organizationpg.OperationLookupMigrationSource{Version: 7001}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, extension := range []struct {
		namespace string
		steps     []migrations.Migration
	}{{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-1:]}, {"identity_risk_lockouts", riskSteps[len(riskSteps)-1:]}, {"organization", append(orgSteps, indexSteps...)}} {
		backend, err := migrationpg.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(extension.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(migrationList(extension.steps), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("native HTTP consumer extension migration failed", err)
		}
	}
	if err := graph.features.Initialize(ctx); err != nil {
		t.Fatal("genuine Reference initialization failed", err)
	}
}

func registerOrganizationHTTPHuman(t *testing.T, ctx context.Context, server *httptest.Server, origin string, graph *baselineGraph, mailbox *registrationMailbox, sessions *session.SessionService) (organization.Authentication, identity.UserID) {
	t.Helper()
	client := server.Client()
	client.Timeout = 6 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	post := func(path string, body any, key string) ([]byte, []*http.Cookie) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		if key != "" {
			r.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("genuine identity HTTPS unavailable")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if response.StatusCode != 200 || readErr != nil || closeErr != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("genuine identity operation failed", path, response.StatusCode)
		}
		return payload, response.Cookies()
	}
	preauth := func(method string) sessionhttp.PreAuthResponse {
		t.Helper()
		payload, _ := post("/v1/session/preauth-issue", map[string]string{"method": method}, "")
		var out sessionhttp.PreAuthResponse
		if json.Unmarshal(payload, &out) != nil || !out.Issued {
			t.Fatal("genuine preauth did not issue")
		}
		return out
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	address, candidate := "organization-http-"+hex.EncodeToString(random[:8])+"@example.invalid", hex.EncodeToString(random[:])
	clear(random[:])
	flow := preauth("signup")
	payload, cookies := post("/v1/password/signup", map[string]any{"flowID": flow.FlowID, "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "http-signup-"+string(flow.FlowID))
	var signup passwordhttp.SignupResponse
	if json.Unmarshal(payload, &signup) != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("genuine signup failed verification-only contract")
	}
	if _, err := graph.workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal(err)
	}
	mailbox.mu.Lock()
	link := mailbox.body
	mailbox.body = ""
	mailbox.mu.Unlock()
	verification, err := url.Parse(link)
	if err != nil || verification.Query().Get("token") == "" {
		t.Fatal("genuine verification delivery unavailable")
	}
	payload, cookies = post("/v1/email/verification-confirm", map[string]string{"token": verification.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(commandID(t))}, "")
	var confirmed emailhttp.ConfirmationResponse
	if json.Unmarshal(payload, &confirmed) != nil || !confirmed.Confirmed || confirmed.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("genuine verification did not commit without session")
	}
	flow = preauth("password")
	payload, cookies = post("/v1/password/signin", map[string]any{"flowID": flow.FlowID, "identifier": address, "password": candidate, "callbackURL": origin + "/confirm"}, "")
	var signed passwordhttp.SigninResponse
	if json.Unmarshal(payload, &signed) != nil || !signed.SignedIn || signed.CommitOutcome != "committed" || len(cookies) != 1 {
		t.Fatal("genuine password signin did not issue session")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("genuine issued token rejected")
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := sessions.Get(ctx, session.GetRequest{TenantID: baselineTenant, Credential: credential})
	if err != nil || current.ValidateAt(time.Now()) != nil || !current.Authenticated {
		t.Fatal("genuine current session unavailable", err)
	}
	bindings, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	return organization.Authentication{TenantID: baselineTenant, Bearer: auth.NewBearerCredential(cookies[0].Value)}, bindings.UserID
}

func assertOrganizationHTTPReceipt(t *testing.T, ctx context.Context, db *sql.DB, native *organizationpg.OperationService, actor organization.Authentication, out organizationhttp.MutationResponse, op organization.Operation, target identity.UserID, before, after uint64) {
	t.Helper()
	if !out.Committed || out.CommitOutcome != "committed" || out.CommandID == "" || out.OrganizationID == "" || out.MemberID != target || out.BeforeVersion != before || out.AfterVersion != after || out.Error != "" || out.Recovery == nil {
		t.Fatal("HTTP lost native committed transition")
	}
	scope := out.Recovery
	binding := identity.CommandBinding{CommandID: scope.CommandID, TenantID: scope.TenantID, UserID: scope.UserID, ActorID: scope.ActorID, ActorKind: scope.ActorKind, OperationID: scope.OperationID, RecordID: scope.RecordID, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion, SchemaID: scope.SchemaID, SchemaVersion: scope.SchemaVersion, CorrelationID: scope.CorrelationID}
	if binding.CommandID != out.CommandID || binding.TenantID != baselineTenant || binding.UserID != target || binding.OperationID != string(op) || binding.RecordID != string(out.OrganizationID) {
		t.Fatal("HTTP changed native original correlation")
	}
	actual, err := native.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: actor, Binding: binding})
	if err != nil || actual.Receipt.Validate() != nil || actual.Receipt.Outcome != identity.CommitOutcomeCommitted || actual.Receipt.Binding != binding || actual.Receipt.Feature == nil || actual.Receipt.Feature.BeforeVersion != before || actual.Receipt.Feature.AfterVersion != after || actual.OrganizationID != out.OrganizationID || actual.MemberID != target {
		t.Fatal("HTTP response not backed by native original receipt", err)
	}
	id, err := base64.RawURLEncoding.DecodeString(string(binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var effects, journals, audits, outboxes int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2),(SELECT count(*) FROM identity.commands WHERE command_id=$3),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.record_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$3)`, string(binding.CommandID), string(op), id, actual.Receipt.AuditEventID).Scan(&effects, &journals, &audits, &outboxes); err != nil || effects != 1 || journals != 1 || audits != 1 || outboxes != 1 {
		t.Fatal("HTTP receipt lacks one atomic native journal/effect/audit/outbox", err)
	}
}

var _ organizationhttp.Service = (*organizationpg.OperationService)(nil)
