//go:build integration

package consumer_test

import (
	"context"
	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identifier "github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	primitive "github.com/faustbrian/go-password/v2"
	database "github.com/faustbrian/go-postgres"
	"net/http"
	"testing"
	"time"
)

// Only public signin configuration is selected here. The registered password,
// preauth issuance, risk, credential verification and session issuance stay native.
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
