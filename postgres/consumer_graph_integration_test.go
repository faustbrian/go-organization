//go:build integration

package postgres_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	httpclient "github.com/faustbrian/go-http-client/v2"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/hibp"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type baselineGraph struct {
	stores   reference.StoreSet
	features reference.FeatureSet
	workers  reference.WorkerSet
	server   *reference.Server
	hibp     *hibp.Client
	http     *httpclient.Client
}

func (g *baselineGraph) close(ctx context.Context) error {
	if g == nil {
		return nil
	}
	return errors.Join(g.stores.Close(ctx), g.hibp.Close(ctx), g.http.Close())
}

type fixedTenant struct{}

func (*fixedTenant) ResolveTenant(ctx context.Context) (identity.TenantID, error) {
	return baselineTenant, ctx.Err()
}

func baselineRiskPolicy(version uint64, screening, reset bool, change ...bool) (risk.Policy, error) {
	return risk.NewPolicy(baselineRiskPolicyConfig(version, screening, reset, change...))
}

func baselineRiskPolicyConfig(version uint64, screening, reset bool, change ...bool) risk.PolicyConfig {
	c := risk.PolicyConfig{Version: version, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}}
	if screening {
		c.HIBP = risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.signup"}}
		if reset {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.reset-complete")
		}
		if len(change) == 1 && change[0] {
			c.HIBP.Operations = append(c.HIBP.Operations, "identity.password.change")
		}
	}
	return c
}

// fixtureGraph is test-only composition from the public identity baseline
// graph (go-identity/reference, source 02c6195). Only startup configuration is
// copied: all authentication, authority, SQL, replay, audit and issuance remain
// the public native owners. Reset/change/MFA workloads are not selected here.
func fixtureGraph(ctx context.Context, origin string, fixtureKeys map[string][32]byte, pool *database.Pool, sender delivery.Sender, outbound http.RoundTripper) (_ *baselineGraph, err error) {
	key := func(name string) [32]byte { return fixtureKeys[name] }
	bytes := func(name string) []byte { k := key(name); return append([]byte(nil), k[:]...) }
	authorize, err := fixtureAuthorization()
	if err != nil {
		return nil, err
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: authorize, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: key("fingerprint")}, QueryPolicy: &query, AdmissionPolicy: &query}
	requestKeys, err := kernel.NewRequestKeyConfig("local-baseline", key("request"), query)
	if err != nil {
		return nil, err
	}
	policy, err := baselineRiskPolicy(3, false, false)
	if err != nil {
		return nil, err
	}
	protectedPolicy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		return nil, err
	}
	screeningPolicy, err := baselineRiskPolicy(3, true, false)
	if err != nil {
		return nil, err
	}
	digest, err := risk.NewCounterDigestKey(1, bytes("counter"))
	if err != nil {
		return nil, err
	}
	evidence, err := risk.NewEvidenceKey(1, bytes("risk-evidence"), bytes("risk-seal"))
	if err != nil {
		return nil, err
	}
	flowKey, err := session.NewDigestKey(3, bytes("preauth-cookie"))
	if err != nil {
		return nil, err
	}
	lookup, err := session.NewDigestKey(11, bytes("session-token"))
	if err != nil {
		return nil, err
	}
	csrf, err := session.NewCSRFKey(12, bytes("session-csrf"))
	if err != nil {
		return nil, err
	}
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, err
	}
	sessionCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteStrictMode})
	if err != nil {
		return nil, err
	}
	deviceCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		return nil, err
	}
	deviceKey, err := session.NewBrowserDeviceKey(1, bytes("http-device"))
	if err != nil {
		return nil, err
	}
	codeProfile, err := otp.NewCodeProfile(otp.CodeProfileSpec{Purpose: otp.PurposeSignin, Alphabet: "0123456789", Length: 6, TTL: 5 * time.Minute, ResendInterval: 30 * time.Second, MaximumSends: 3, Attempts: 3, Replacement: otp.ReplacePrevious})
	if err != nil {
		return nil, err
	}
	codePolicy, err := otp.NewAttemptPolicy(codeProfile, otp.CheckPolicySpec{Enabled: true, MaximumChecks: 2, LockoutAfter: time.Minute})
	if err != nil {
		return nil, err
	}
	envelope, err := keyring.New(map[string][]byte{"delivery-envelope": bytes("delivery-envelope")})
	if err != nil {
		return nil, err
	}
	profile := primitive.DefaultPolicy()
	crypto, err := primitive.New(profile)
	if err != nil {
		return nil, err
	}
	dummy, err := crypto.Hash(ctx, bytes("dummy-password"))
	if err != nil {
		return nil, err
	}
	transport, err := httpclient.New(httpclient.Config{Transport: outbound})
	if err != nil {
		return nil, err
	}
	checker, err := hibp.New(hibp.Config{UserAgent: "golib-identity/local-baseline", AddPadding: true, CacheEntries: 100, CacheTTL: time.Hour, ResponseBytes: 1 << 20, MaxBreachCount: 1000000000, OutboundConcurrency: 1, Timeout: 2 * time.Second, PolicyVersion: "local-baseline-v1", MaxWaiters: 8, MaxCandidateBytes: 128, CacheBytes: 8 << 20, DisableCache: true}, transport, clock.System{})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	g := &baselineGraph{hibp: checker.(*hibp.Client), http: transport}
	defer func() {
		if err != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			_ = g.close(cleanup)
		}
	}()
	provider, err := hibp.NewSignalProvider(g.hibp, screeningPolicy)
	if err != nil {
		return nil, err
	}
	collect := func(ctx context.Context, b risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		command, err := identity.ParseCommandID(b.Attempt)
		if err != nil {
			return nil, err
		}
		signal, err := provider.Assess(ctx, hibp.CheckRequest{OperationID: "identity.password.signup", TenantID: identity.TenantID(b.Tenant), Action: b.Operation, Purpose: "identity.password.signup", SubjectScope: "password-screening", PolicyVersion: "local-baseline-v1", ReplayID: command, Candidate: candidate})
		return []risk.Signal{signal}, err
	}
	normalization, err := identifier.NewNormalizationProfile(identifier.NormalizationProfileSpec{ID: "local-email-nfc", Version: 1, Unicode: identifier.UnicodeNormalizationNFC, MaximumBytes: 512})
	if err != nil {
		return nil, err
	}
	addressPolicy := email.AddressPolicy{MaximumBytes: 512, Canonicalization: normalization}
	address, err := email.NewAddressParser(addressPolicy)
	if err != nil {
		return nil, err
	}
	callback := origin + "/confirm"
	verification, err := email.NewRegistrationVerificationPolicy(email.RegistrationVerificationConfig{Address: addressPolicy, Issuer: origin, Audience: "email", MaximumLifetime: 5 * time.Minute, Redirects: []string{callback}, CurrentBindingKeyVersion: 1, RetainedBindingKeys: map[uint32][32]byte{1: key("capability-binding")}})
	if err != nil {
		return nil, err
	}
	signer, err := capability.NewHMACSHA256Signer("local-baseline", bytes("capability-signing"))
	if err != nil {
		return nil, err
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes("capability-signing"))
	if err != nil {
		return nil, err
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "local-baseline", Verifier: verifier}})
	if err != nil {
		return nil, err
	}
	private := ed25519.NewKeyFromSeed(bytes("signin-proof"))
	loginSigner, err := passwordpg.NewSigninSigningKey("local-baseline", private)
	if err != nil {
		return nil, err
	}
	schema := identity.AttributeSchema{ID: "local-signup-fields", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPersonal, MigrationVersion: 1, Default: identity.AttributeValue{Kind: identity.AttributeString, Scalar: identity.AttributeScalar{Kind: identity.AttributeString, String: "registered"}}}}}
	fields, err := identity.NewAttributeProcessor(schema, authorize, func(ctx context.Context, _ identity.NormalizationPolicy, value identity.AttributeScalar) (identity.AttributeScalar, error) {
		return value, ctx.Err()
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 9, ValidateCanonicalUserID: func(ctx context.Context, user identity.UserID) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := identity.ParseSubjectID(string(user))
		return err
	}, ValidateValue: func(ctx context.Context, _ identity.FieldPolicy, _ identity.AttributeValue) error { return ctx.Err() }})
	if err != nil {
		return nil, err
	}
	storage := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	issuance := session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 4 * time.Second, LookupKey: lookup, TokenSize: 32, Cookie: sessionCookie}
	preauth := &reference.PasswordPreAuthConfiguration{ActorID: baselineActor, Origin: origin, CallbackURL: callback, FlowKeyIndex: 0, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: flowCookie}
	configured := reference.StoreConfiguration{
		DurableAdmission: &reference.DurableAdmissionConfiguration{Schema: "risk_store", Namespace: "local-baseline", Policy: policy, Keys: []risk.CounterDigestKey{digest}, ReplayKey: bytes("counter-replay"), Tenants: []string{baselineTenant}, MaximumRecords: 100000, Timeout: 10 * time.Second},
		Migrations:       &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "local-operator", LookupKey: key("migration"), LockTimeout: time.Second, CleanupTimeout: time.Second},
		HTTPRate:         &reference.HTTPRateConfiguration{Namespace: "local-baseline", IdentifierKey: key("http-rate"), MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond},
		HTTPPreAuth:      &reference.HTTPPreAuthConfiguration{Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Device: &session.BrowserDeviceConfig{Namespace: "local-baseline", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: 24 * time.Hour, Cookie: deviceCookie}},
		OTP: &reference.OTPSendConfiguration{
			BootstrapTenantIDs: []identity.TenantID{baselineTenant}, Store: otppg.ContributorConfig{Schema: "otp_store", GlobalAuthorityID: "deployment", UserPolicyNamespace: "users", LockoutKey: key("otp-lockout"), PreAuth: storage, PreAuthCookieKeys: map[uint32][]byte{3: bytes("preauth-cookie")}},
			Codec:       otppg.AttemptCodecConfig{WrappingKeys: map[string][]byte{"otp-wrap": bytes("otp-wrap")}, CurrentWrappingKey: "otp-wrap", AttemptKeys: map[uint32][32]byte{7: key("otp-attempt")}, CodeKeys: map[uint32][32]byte{4: key("otp-code")}, CurrentCodeKeyVersion: 4, MaximumDuration: time.Second},
			Coordinator: coordinator, RequestKeys: requestKeys, Policy: codePolicy, TemplateID: "otp-code", TemplateVersion: 1, LocaleChain: []string{"en"}, ProviderVersion: 1, PolicyID: "otp-policy", PolicyVersion: 9, PreAuthAction: "identity.otp.signin", IntentKey: key("otp-intent"), IdentifierKey: key("identifier"), Timeout: 4 * time.Second, RiskTimeout: 2 * time.Second, AuditTimeout: time.Second, RiskPolicyID: baselineTenant, ConfigurationID: "local-baseline-v1", RiskKeys: []risk.EvidenceKey{evidence},
			PreAuth: &reference.OTPPreAuthConfiguration{ActorID: baselineActor, Origin: origin, LookupKeyVersion: 3, AuditRetentionVersion: 1, FlowTTL: 5 * time.Minute, TokenSize: 32, Cookie: flowCookie},
			Signin:  &otppg.SigninConfig{Coordinator: coordinator, CurrentAttemptKeyVersion: 7, Session: storage, Profile: sessionpg.OTPAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline"}, Issuer: issuance, CSRFKey: csrf},
		},
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.Production = true
	configured.Delivery = &reference.DeliveryConfiguration{Enqueue: deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: key("delivery-digest")}, ActiveEnvelopeKeyID: "delivery-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "local-mailbox", PolicyVersion: 1}}}, Coordinator: coordinator, PolicyID: "delivery-policy", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: key("delivery-namespace"), Policies: map[uint64]delivery.Config{1: deliveryPolicy}, StateTracking: true}, Templates: []delivery.Template{
		{ID: "otp-code", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", RequiredVariables: []string{"code"}, VariableSchema: []delivery.VariableSchema{{Name: "code", Kind: "code", Sensitive: true}}, MaxRenderedBytes: 128, Subject: "Verification", Body: "{{.code}}", ContentType: "text/plain"},
		{ID: "registration", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096},
	}}
	signin := passwordpg.SigninConfig{
		Repository: passwordpg.Config{MaximumDuration: 4 * time.Second, HashPolicy: profile}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: 2 * time.Second, DummyHash: dummy, Now: time.Now}, Session: storage,
		Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, Address: addressPolicy, FlowKeys: []session.DigestKey{flowKey}, Issuance: issuance, CSRFKey: csrf,
		Risk: risk.AuthenticationAdmissionCustodyConfig{ConfigurationID: "local-password-v1", Keys: []risk.EvidenceKey{evidence}}, Coordinator: coordinator, SigningKey: loginSigner, VerificationKeys: map[string]ed25519.PublicKey{"local-baseline": private.Public().(ed25519.PublicKey)}, Issuer: origin, Environment: "local-capture", PolicyID: "password-login", ProofTTL: time.Minute, IdentifierKey: bytes("password-flow"), Origins: []string{origin}, CallbackURLs: []string{callback},
	}
	configured.PasswordSignin = &reference.PasswordSigninConfiguration{Native: signin, PreAuth: preauth}
	configured.HTTPPasswordSignin = &reference.HTTPPasswordSigninConfiguration{ActorID: baselineActor, PolicyRevision: 9}
	configured.PasswordSignup = &reference.PasswordSignupConfiguration{
		Native: passwordpg.SignupConfig{
			Repository: signin.Repository, Registration: password.RegistrationPolicy{Enabled: true, RequireVerifiedEmail: true, MinimumBytes: 12, MaximumBytes: 128}, ConfigurationID: "local-signup-v1", PolicyID: "password-signup", Fields: fields, FieldSchema: schema, Address: address, SelectUser: func(ctx context.Context) (identity.UserID, error) {
				if err := ctx.Err(); err != nil {
					return "", err
				}
				id, err := identity.NewSubjectID()
				return identity.UserID(id), err
			}, Session: storage, FlowKeys: signin.FlowKeys, Origins: []string{origin}, CallbackURLs: []string{callback}, AuthorizationNamespace: "users",
			RegistrationDomain: kernel.PasswordRegistrationDomainConfig{ComparisonProfile: "local-email-v1", CurrentIdentifierKeyVersion: 1, RetainedIdentifierKeys: map[uint32][32]byte{1: key("signup-binding")}}, RequestKeys: requestKeys, IntentKey: key("signup-intent"), ActiveEnvelopeKeyID: "delivery-envelope",
			Screening: password.HashPreparationConfig{Primitive: crypto, MinimumBytes: 12, MaximumBytes: 128, Timeout: 3 * time.Second, DummyHash: dummy, Policy: screeningPolicy, Now: time.Now, Collect: collect}, Risk: signin.Risk, Coordinator: coordinator,
			Verification: passwordpg.SignupVerificationConfig{Policy: verification, Lifetime: 5 * time.Minute}, Delivery: passwordpg.SignupDeliveryConfig{Resolver: resolver, Endpoint: origin + "/email/confirm", TemplateID: "registration", TemplateVersion: 1, ProviderVersion: 1, Locales: []string{"en"}, ScopeKey: key("verification-scope"), Timeout: time.Second},
		},
		Issuer:      issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: capability.DefaultLimits()}, Audience: "email", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: key("capability-replay")}, PreparationTimeout: time.Second},
		Preparation: issuerpg.IssuancePreparationConfig{Deployment: "deployment", ActiveEnvelopeKey: "capability-envelope", EnvelopeKeys: map[string][]byte{"capability-envelope": bytes("capability-envelope")}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "local-baseline", HMAC: bytes("capability-signing")}}, Clock: time.Now},
		Counters:    riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": bytes("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: protectedPolicy, Keys: []risk.CounterDigestKey{digest}}}, PreAuth: preauth,
	}
	configured.HTTPPasswordSignup = &reference.HTTPPasswordSignupConfiguration{ActorID: baselineActor, PolicyRevision: 9}
	configured.HTTPRegistrationVerification = &reference.HTTPRegistrationVerificationConfiguration{Origin: origin, ActorID: baselineActor, PolicyRevision: 9, VerificationNamespace: "local-registration", VerificationKey: key("verification-http")}
	configured.Session = &reference.SessionConfiguration{Native: sessionpg.SignOutServiceConfig{Execution: sessionpg.IssueExecutorConfig{Repository: storage, Profile: sessionpg.IssueAdmissionConfig(signin.Profile), Coordinator: coordinator, Authorization: authorize, Clock: clock.System{}, PolicyID: "session-signout", PolicyVersion: 9, AuditRetentionVersion: 1}, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "local-baseline", MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}, Cookie: sessionCookie, MaximumDuration: 4 * time.Second}, CSRFKeys: []session.CSRFKey{csrf}}
	configured.HTTPSession = &reference.HTTPSessionConfiguration{Transport: session.CredentialCookie, TrustedOrigins: []identityhttp.Origin{identityhttp.Origin(origin)}, RateNamespace: "local-session", EmergencyMaximumKeys: 128, Degraded: func(ctx context.Context, _ identityhttp.SafeRateEvent) error { return ctx.Err() }}
	dependencies := reference.ReferenceDependencies{PostgreSQL: pool, EnvelopeKeys: envelope, DeliverySender: sender}
	g.stores, err = reference.ComposeStores(configured, dependencies)
	if err != nil {
		return nil, err
	}
	providers, err := reference.ComposeProviders(g.stores)
	if err != nil {
		return nil, err
	}
	worker := deliverypg.WorkerConfig{ProviderConfigVersion: 1, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "local-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "baseline-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "baseline-worker"}}}}
	g.workers, err = reference.ComposeWorkers(g.stores, providers, worker)
	if err != nil {
		return nil, err
	}
	g.features, err = reference.ComposeFeatures(g.stores, providers, g.workers)
	if err != nil {
		return nil, err
	}
	parsedOrigin, _ := url.Parse(origin) // The fixture constructs this exact HTTPS origin.
	g.server, err = reference.NewServer(reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: fixturePolicies(authorize), HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 64, MaximumDepth: 8}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: parsedOrigin.Hostname(), TenantID: baselineTenant}}}, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Local identity baseline", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: 5 * time.Second}, Tenant: reference.TenantPolicy{Resolver: &fixedTenant{}}}, dependencies, g.features)
	if err != nil {
		return nil, err
	}
	return g, nil
}

const (
	baselineTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
	baselineActor  = "AAAAAAAAAAAAAAAAAAAAAw"
)

// This finite application policy is evaluated by the public authorization
// engine. It is not native user/session authority: actual owners independently
// authenticate original flows, credentials, sessions and organization membership.
type baselineEvaluator struct{}

func (*baselineEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	allow := false
	if string(r.Tenant) == baselineTenant && r.Subject.ID != "" && r.Resource.ID != "" {
		if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == baselineActor {
			switch r.Action {
			case "identity.session.preauth-issue":
				allow = r.Resource.Type == "identity.anonymous-flow"
			case "identity.password.signup", "identity.password.signup.recover", "identity.password.signin", "identity.password.signin.recover":
				allow = r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) || r.Resource.Type == "identity.anonymous-flow" || r.Resource.Type == "identity.user"
			case "identity.user.create", "identity.email.verification-confirm":
				allow = r.Resource.Type == "identity.user"
			}
		}
		if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "baseline-worker" && r.Action == "identity.delivery.process" {
			allow = r.Resource.Type == "identity.delivery-worker" && r.Resource.ID == "baseline-worker"
		}
		if r.Subject.Kind == authorization.SubjectUser {
			switch r.Action {
			case "identity.session.revoke-one", "identity.session.revoke-one.recover":
				allow = r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID)
			case "identity.organization.create", "identity.organization.member.add", "identity.organization.member.remove", "identity.organization.get", "identity.organization.member.list":
				allow = r.Resource.Type == "organization" || r.Resource.Type == "identity.user"
			}
		}
	}
	if allow {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return authorization.Decision{Outcome: authorization.Deny}, nil
}
func fixtureAuthorization() (authorization.Service, error) {
	snapshot, e := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-consumer", Revision: 9, Evaluator: &baselineEvaluator{}})
	if e != nil {
		return nil, e
	}
	engine, e := authorization.NewEngine(snapshot)
	if e != nil {
		return nil, e
	}
	return authorization.NewDecisionService(engine)
}
func fixturePolicies(service authorization.Service) identity.PolicySet {
	return identity.PolicySet{
		Authorize: service,
		AssessRisk: func(ctx context.Context, _ identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			return identity.RiskPolicyDecision{}, identity.ForbiddenError{}
		},
		MapClaims: func(ctx context.Context, _ identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			return identity.ClaimsPolicyDecision{}, identity.ForbiddenError{}
		},
		DecideRetention: func(ctx context.Context, _ identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			return identity.RetentionPolicyDecision{}, identity.ForbiddenError{}
		},
		Redact: func(ctx context.Context, _ identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{}, identity.ForbiddenError{}
		},
	}
}
