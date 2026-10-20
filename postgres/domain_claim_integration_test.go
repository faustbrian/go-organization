//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/stdlib"
)

func domainFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newOrgFixture(t, organizationpg.DomainClaimMigrationSource{Version: 310})
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 10}
	f.compose(t)
	return f
}
func domainRequest(t *testing.T, f *orgFixture, tenant, claim, domain string, epoch uint64) organization.DomainClaimRequest {
	t.Helper()
	return organization.DomainClaimRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, ClaimID: organization.ID(claim), OrganizationVersion: epoch, Domain: domain, CorrelationID: "domain"}
}
func reserveDomain(t *testing.T, f *orgFixture, r organization.DomainClaimRequest) organizationpg.PreparedCommand {
	t.Helper()
	p, e := f.service.PrepareReserveDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func domainRead(f *orgFixture, tenant, claim string) organization.DomainClaimReadRequest {
	return organization.DomainClaimReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, ClaimID: organization.ID(claim), CorrelationID: "domain-read"}
}

// Delay only the final claim read, after mutation has staged every protected
// effect. The original native observation starts during preparation and has an
// exclusive lifetime of at most 20s (session/postgres primarySessionReader).
// Neither an observation nor the production execution timeout is renewed here.
type domainCommitExpiryTrace struct {
	ctx           context.Context
	before, after time.Time
	entered       atomic.Bool
	inWindow      atomic.Bool
	crossed       atomic.Bool
}

type domainCommitExpiryWriter struct {
	io.Writer
	trace *domainCommitExpiryTrace
}

func (w domainCommitExpiryWriter) Write(frame []byte) (int, error) {
	// Work intentionally bypasses pgx QueryTracer via PgConn.ExecParams. The
	// pgproto3 frontend flush contains complete encoded messages, so match the
	// exact final-read Parse text without retaining or exposing any frame data.
	const finalRead = `SELECT canonical_domain,state,version::text FROM organization.domain_claims WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 FOR UPDATE`
	if !bytes.Contains(frame, []byte(finalRead)) {
		return w.Writer.Write(frame)
	}
	d := w.trace
	d.entered.Store(true)
	d.inWindow.Store(time.Now().Before(d.before.Add(20 * time.Second)))
	timer := time.NewTimer(time.Until(d.after.Add(20*time.Second + 20*time.Millisecond)))
	defer timer.Stop()
	select {
	case <-d.ctx.Done():
		return 0, d.ctx.Err()
	case <-timer.C:
		d.crossed.Store(true)
	}
	return w.Writer.Write(frame)
}

func TestDomainClaimFinalReadCannotOutliveOriginalAdmission(t *testing.T) {
	for _, op := range []organization.Operation{organization.ReserveDomain, organization.WithdrawDomain} {
		t.Run(string(op), func(t *testing.T) {
			f := domainFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			r := domainRequest(t, f, tenant, "expired-final-read", "expiry.example", 1)
			if op == organization.WithdrawDomain {
				committedTeam(t, f, reserveDomain(t, f, r))
				r.CommandID = commandID(t)
				r.OrganizationVersion, r.ClaimVersion = 2, 1
			}
			trace := &domainCommitExpiryTrace{ctx: f.ctx}
			pool, e := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = f.database
				c.ConnConfig.BuildFrontend = func(r io.Reader, w io.Writer) *pgproto3.Frontend {
					return pgproto3.NewFrontend(r, domainCommitExpiryWriter{Writer: w, trace: trace})
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := pool.Close(ctx); e != nil {
					t.Error(e)
				}
			})
			observed := *f
			observed.pool = pool
			observed.compose(t)
			trace.before = time.Now()
			var p organizationpg.PreparedCommand
			if op == organization.ReserveDomain {
				p, e = observed.service.PrepareReserveDomain(f.ctx, r, "127.0.0.1")
			} else {
				p, e = observed.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
			}
			trace.after = time.Now()
			if e != nil || trace.after.Sub(trace.before) > 500*time.Millisecond {
				t.Fatal("preparation must leave a bounded execution window", e)
			}
			// Age the exact prepared command outside its execution budget, then
			// cross its original observation expiry inside the final read only.
			timer := time.NewTimer(time.Until(trace.before.Add(18500 * time.Millisecond)))
			defer timer.Stop()
			select {
			case <-f.ctx.Done():
				t.Fatal(f.ctx.Err())
			case <-timer.C:
			}
			got, err := observed.service.Execute(f.ctx, p)
			if !trace.entered.Load() || !trace.inWindow.Load() || !trace.crossed.Load() {
				t.Fatal("regression did not cross original expiry at final claim read", err)
			}
			var claims, epoch, effects, audits, events int
			var state string
			var version int
			e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.domain_claims),o.version::integer,
(SELECT count(*) FROM organization.command_effects WHERE operation=$2),
(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.tenant_id=$1 AND a.action=$2 AND a.outcome=$3),
(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic=$4),
COALESCE((SELECT state FROM organization.domain_claims WHERE claim_id=$5),''),COALESCE((SELECT version::integer FROM organization.domain_claims WHERE claim_id=$5),0)
FROM organization.organizations o WHERE o.tenant_id=$1`, tenant, string(op), int16(audit.OutcomeSucceeded), map[organization.Operation]string{organization.ReserveDomain: "organization.domain_reserved.v1", organization.WithdrawDomain: "organization.domain_withdrawn.v1"}[op], string(r.ClaimID)).Scan(&claims, &epoch, &effects, &audits, &events, &state, &version)
			if e != nil {
				t.Fatal(e)
			}
			wantClaims, wantVersion, wantState := 0, 0, ""
			if op == organization.WithdrawDomain {
				wantClaims, wantVersion, wantState = 1, 1, string(organization.DomainRequested)
			}
			if !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted || epoch != int(r.OrganizationVersion) || claims != wantClaims || version != wantVersion || state != wantState || effects != 0 || audits != 0 || events != 0 {
				t.Fatal("expired final read retained protected mutation", err, got.Receipt.Outcome, "epoch", epoch, "claims", claims, "claim-version", version, "state", state, "effects", effects, "audits", audits, "events", events)
			}
		})
	}
}

func TestDomainClaimReplayWithdrawalAndIsolation(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	r := domainRequest(t, f, tenant, "original", "Example.COM.", 1)
	p := reserveDomain(t, f, r)
	for range 2 {
		committedTeam(t, f, p)
	}
	v, e := f.service.GetDomainClaim(f.ctx, domainRead(f, tenant, "original"))
	if e != nil || v.DomainClaim.Domain != "example.com" || v.DomainClaim.Version != 1 || v.Organization.Version != 2 {
		t.Fatal("current canonical claim", e)
	}
	h, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(h)
	if e != nil {
		t.Fatal(e)
	}
	var recovered organizationpg.Recovery
	if e = json.Unmarshal(wire, &recovered); e != nil {
		t.Fatal(e)
	}
	f.compose(t)
	for range 2 {
		got, e := f.service.Recover(f.ctx, r.Authentication, recovered)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != h.Binding {
			t.Fatal("reconstructed exact recovery", e)
		}
	}
	// Same command identity with a newly prepared current observation and changed
	// intent must conflict, never become a second reservation or fresh replay.
	changed := r
	changed.ClaimID = "changed"
	changed.Domain = "other.example"
	changed.OrganizationVersion = 2
	other := reserveDomain(t, f, changed)
	if got, e := f.service.Execute(f.ctx, other); !errors.Is(e, organization.ErrConflict) || got.Receipt.Outcome != identity.CommitOutcomeConflict {
		t.Fatal("changed fingerprint did not conflict", e, got.Receipt.Outcome)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 2
	r.ClaimVersion = 1
	p, e = f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		committedTeam(t, f, p)
	}
	v, e = f.service.GetDomainClaim(f.ctx, domainRead(f, tenant, "original"))
	if e != nil || v.DomainClaim.State != organization.DomainWithdrawn || v.DomainClaim.Version != 2 || v.DomainClaim.ID != "original" || v.Organization.Version != 3 {
		t.Fatal("withdrawal did not preserve immutable tombstone", e)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 3
	r.ClaimVersion = 0
	if _, e = f.service.PrepareReserveDomain(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("tombstone resurrected", e)
	}
	r.ClaimID = "successor"
	committedTeam(t, f, reserveDomain(t, f, r))
	// Both scopes have genuine current management authority for the same actor
	// and organization ID. Denial must come from exact claim scope, not absence
	// of a foreign organization or membership before the claim read is reached.
	f.create(t, "org-test-scope")
	q := domainRead(f, tenant, "original")
	q.Authentication = f.auth("org-test-scope", "owner")
	if _, e = f.service.GetDomainClaim(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross-tenant custody disclosed", e)
	}
	otherOrg := organization.ID("other-isolation")
	created, e := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: r.Authentication, CommandID: commandID(t), ID: otherOrg, Name: "Other isolation", Slug: "other-isolation", CorrelationID: "domain"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, created)
	q = domainRead(f, tenant, "original")
	q.OrganizationID = otherOrg
	if _, e = f.service.GetDomainClaim(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross-organization custody disclosed", e)
	}
	if got, e := f.service.Recover(f.ctx, r.Authentication, recovered); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 1 || got.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("later custody changed original historical outcome", e)
	}
	var originals, successors int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE claim_id='original' AND version=2 AND state='withdrawn'),count(*) FILTER(WHERE claim_id='successor' AND version=1 AND state='requested') FROM organization.domain_claims WHERE tenant_id=$1`, tenant).Scan(&originals, &successors); e != nil || originals != 1 || successors != 1 {
		t.Fatal("re-reservation changed prior identity", e)
	}
}

func TestDomainClaimGlobalContention(t *testing.T) {
	for _, crossTenant := range []bool{false, true} {
		t.Run(map[bool]string{false: "same-tenant-orgs", true: "cross-tenant"}[crossTenant], func(t *testing.T) {
			f := domainFixture(t)
			tenant := "org-test-race"
			f.create(t, tenant)
			otherTenant := tenant
			if crossTenant {
				otherTenant = "org-test-scope"
			}
			otherOrg := organization.ID("other-organization")
			created, e := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(otherTenant, "owner"), CommandID: commandID(t), ID: otherOrg, Name: "Competitor", Slug: "competitor", CorrelationID: "domain"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			committedTeam(t, f, created)
			a := domainRequest(t, f, tenant, "first", "Global.EXAMPLE.", 1)
			b := domainRequest(t, f, otherTenant, "second", "global.example", 1)
			b.OrganizationID = otherOrg
			prepared := []organizationpg.PreparedCommand{reserveDomain(t, f, a), reserveDomain(t, f, b)}
			type result struct {
				r organization.StoreResult
				e error
			}
			results := make(chan result, 2)
			start := make(chan struct{})
			var wg sync.WaitGroup
			for _, p := range prepared {
				wg.Go(func() { <-start; r, e := f.service.Execute(f.ctx, p); results <- result{r, e} })
			}
			close(start)
			wg.Wait()
			close(results)
			wins, conflicts := 0, 0
			for got := range results {
				if got.e == nil && got.r.Receipt.Outcome == identity.CommitOutcomeCommitted {
					wins++
				} else if errors.Is(got.e, organization.ErrConflict) && got.r.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
					conflicts++
				} else {
					t.Fatal("unexpected global contention result", got.e, got.r.Receipt.Outcome)
				}
			}
			if wins != 1 || conflicts != 1 {
				t.Fatal("global uniqueness did not select exactly one winner", wins, conflicts)
			}
			var active int
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.domain_claims WHERE canonical_domain='global.example' AND state='requested'`).Scan(&active); e != nil || active != 1 {
				t.Fatal("global unique state", e)
			}
		})
	}
}

func TestDomainClaimCurrentAuthority(t *testing.T) {
	for _, withdrawal := range []string{"session", "credential", "account", "global", "scoped", "member", "organization", "stale-epoch"} {
		t.Run(withdrawal, func(t *testing.T) {
			f := domainFixture(t)
			tenant := "org-test-target"
			f.create(t, tenant)
			r := domainRequest(t, f, tenant, "authority", "authority.example", 1)
			p := reserveDomain(t, f, r)
			var e error
			switch withdrawal {
			case "session":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "credential":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE identity.credential_references SET enabled=false,version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "account":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "global":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE identity.global_authorities SET version=version+1`)
			case "scoped":
				scope, se := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "owner")
				if se != nil {
					t.Fatal(se)
				}
				_, e = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second)
			case "member":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "organization":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived' WHERE tenant_id=$1`, tenant)
			case "stale-epoch":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1`, tenant)
			}
			if e != nil {
				t.Fatal("authority fixture mutation", e)
			}
			got, e := f.service.Execute(f.ctx, p)
			if e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("stale authority committed domain", e, got.Receipt.Outcome)
			}
			var count int
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.domain_claims`).Scan(&count); e != nil || count != 0 {
				t.Fatal("denial retained claim", e)
			}
		})
	}
}

func TestDomainClaimMemberAndStaleVersionDenials(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	f.add(t, tenant, "second", organization.RoleAdministrator, 2)
	r := domainRequest(t, f, tenant, "managed", "managed.example", 3)
	r.Authentication = f.auth(tenant, "member")
	if _, e := f.service.PrepareReserveDomain(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("member reserved domain", e)
	}
	r.Authentication = f.auth(tenant, "second")
	committedTeam(t, f, reserveDomain(t, f, r))
	q := domainRead(f, tenant, "managed")
	q.Authentication = f.auth(tenant, "member")
	if _, e := f.service.GetDomainClaim(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("member read custody", e)
	}
	r.CommandID = commandID(t)
	r.OrganizationVersion = 4
	r.ClaimVersion = 2
	if _, e := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale claim withdrew", e)
	}
	r.ClaimVersion = 1
	r.OrganizationVersion = 3
	if _, e := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale org withdrew", e)
	}
}

func TestDomainClaimRollbackAndLostCommit(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-rollback"
	f.create(t, tenant)
	for i, table := range []string{"audit.records", "public.identity_outbox_bindings"} {
		r := domainRequest(t, f, tenant, "rollback", "rollback.example", 1)
		p := reserveDomain(t, f, r)
		when := ""
		if table == "audit.records" {
			// Kernel08705b0 domain.go:512-518 requires a detached failure audit
			// before NotCommitted can be durable. Fail the success effect only;
			// a total audit outage must remain Unknown, not falsify that owner.
			when = " WHEN (NEW.outcome=" + strconv.Itoa(int(audit.OutcomeSucceeded)) + ")"
		}
		_, e := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.domain_fail_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic domain failure'; END $$; CREATE TRIGGER domain_fail_effect BEFORE INSERT ON `+table+` FOR EACH ROW`+when+` EXECUTE FUNCTION public.domain_fail_effect()`)
		if e != nil {
			t.Fatal(e)
		}
		if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("effect failure did not durably abort claim", e, got.Receipt.Outcome)
		}
		if _, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER domain_fail_effect ON `+table+`; DROP FUNCTION public.domain_fail_effect()`); e != nil {
			t.Fatal(e)
		}
		var count, epoch, effects int
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.domain_claims),version::integer,(SELECT count(*) FROM organization.command_effects WHERE operation=$2) FROM organization.organizations WHERE tenant_id=$1`, tenant, string(organization.ReserveDomain)).Scan(&count, &epoch, &effects); e != nil || count != 0 || epoch != 1 || effects != 0 {
			t.Fatal("rollback retained partial custody", e)
		}
		var failed int
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action=$2 AND r.outcome=$3`, tenant, string(organization.ReserveDomain), int16(audit.OutcomeFailed)).Scan(&failed); e != nil || failed != i+1 {
			t.Fatal("abort omitted its mandatory failure audit", e, failed)
		}
	}
	service, fault := f.lostCommitService(t)
	r := domainRequest(t, f, tenant, "committed", "committed.example", 1)
	p, e := service.PrepareReserveDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	h, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	fault.armed.Store(true)
	got, e := service.Execute(f.ctx, p)
	if e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost COMMIT did not remain unknown", e, got.Receipt.Outcome)
	}
	for range 2 {
		got, e = f.service.Recover(f.ctx, r.Authentication, h)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("lost COMMIT primary recovery", e)
		}
	}
	var claims, events, audits, effects int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.domain_claims),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='organization.domain_reserved.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action=$2 AND r.outcome=$3),(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation=$2)`, tenant, string(organization.ReserveDomain), int16(audit.OutcomeSucceeded)).Scan(&claims, &events, &audits, &effects); e != nil || claims != 1 || events != 1 || audits != 1 || effects != 1 {
		t.Fatal("recovery duplicated protected effects", e, claims, events, audits, effects)
	}
}

type domainWithdrawalPolicy struct {
	f         *orgFixture
	operation organization.Operation
	fired     bool
}

func (p *domainWithdrawalPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if !p.fired && c.Request.Action == authorization.Action(p.operation) {
		p.fired = true
		if _, e := p.f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`); e != nil {
			return authorization.Decision{}, e
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}
func TestDomainClaimReadDeniesPostPolicyRevocation(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	committedTeam(t, f, reserveDomain(t, f, domainRequest(t, f, tenant, "read", "read.example", 1)))
	policy := &domainWithdrawalPolicy{f: f, operation: organization.GetDomainClaim}
	c := f.configuration
	c.Authorization = policy
	s, e := organizationpg.NewService(f.participant, c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetDomainClaim(f.ctx, domainRead(f, tenant, "read")); !policy.fired || !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("post-policy revoked source disclosed custody", e)
	}
}

func TestDomainClaimMutationDeniesPostPolicyRevocation(t *testing.T) {
	for _, op := range []organization.Operation{organization.ReserveDomain, organization.WithdrawDomain} {
		t.Run(string(op), func(t *testing.T) {
			f := domainFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			r := domainRequest(t, f, tenant, "callback", "callback.example", 1)
			if op == organization.WithdrawDomain {
				committedTeam(t, f, reserveDomain(t, f, r))
				r.CommandID = commandID(t)
				r.OrganizationVersion = 2
				r.ClaimVersion = 1
			}
			policy := &domainWithdrawalPolicy{f: f, operation: op}
			config := f.configuration
			config.Authorization = policy
			s, e := organizationpg.NewService(f.participant, config)
			if e != nil {
				t.Fatal(e)
			}
			var p organizationpg.PreparedCommand
			if op == organization.ReserveDomain {
				p, e = s.PrepareReserveDomain(f.ctx, r, "127.0.0.1")
			} else {
				p, e = s.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
			}
			if e != nil {
				if !policy.fired || !errors.Is(e, organization.ErrForbidden) {
					t.Fatal(e)
				}
			} else {
				if got, e := s.Execute(f.ctx, p); !policy.fired || !errors.Is(e, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("callback revoked source retained mutation authority", e, got.Receipt.Outcome)
				}
			}
			var claims int
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.domain_claims WHERE state='requested'`).Scan(&claims); e != nil || op == organization.ReserveDomain && claims != 0 || op == organization.WithdrawDomain && claims != 1 {
				t.Fatal("callback denial retained partial custody", e)
			}
		})
	}
}

func TestDomainClaimPopulatedMigrationAndRetainedQuota(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	legacy := f.service
	steps, e := (organizationpg.DomainClaimMigrationSource{Version: 310}).Load(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := pgx.ParseConfig(f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	c.Database = f.database
	db := stdlib.OpenDB(*c)
	defer db.Close()
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	runner, e := migrations.NewRunner(append(append(migrationList(nil), f.history...), steps...), backend)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = runner.Up(f.ctx); e != nil {
			t.Fatal("populated domain forward migration", e)
		}
	}
	v, e := legacy.ListMembers(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, Limit: 10, CorrelationID: "legacy"})
	if e != nil || v.Organization.Version != 2 || len(v.Members) != 2 {
		t.Fatal("domain migration changed existing lifecycle", e)
	}
	if _, e = legacy.PrepareReserveDomain(f.ctx, domainRequest(t, f, tenant, "disabled", "disabled.example", 2), "127.0.0.1"); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("legacy zero profile enabled domains", e)
	}
	f.domains = organization.DomainConfig{Version: 1, MaximumClaims: 1}
	f.compose(t)
	r := domainRequest(t, f, tenant, "retained", "retained.example", 2)
	committedTeam(t, f, reserveDomain(t, f, r))
	r.CommandID = commandID(t)
	r.OrganizationVersion = 3
	r.ClaimVersion = 1
	p, e := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	r.CommandID = commandID(t)
	r.ClaimID = "new"
	r.ClaimVersion = 0
	r.OrganizationVersion = 4
	p = reserveDomain(t, f, r)
	if got, e := f.service.Execute(f.ctx, p); !errors.Is(e, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("withdrawal replenished retained quota", e)
	}
	// The migration owns scope and canonical representation at the database
	// boundary, not merely in the public service's input validation.
	for _, args := range [][]any{{tenant, "missing", "foreign", "scope.example"}, {tenant, string(metadataOrganization), "upper", "Upper.example"}, {tenant, string(metadataOrganization), "numeric", "example.123"}, {tenant, string(metadataOrganization), "empty", "a..example"}} {
		if _, e = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.domain_claims(tenant_id,organization_id,claim_id,canonical_domain,state,version) VALUES($1,$2,$3,$4,'requested',1)`, args...); e == nil {
			t.Fatal("schema admitted malformed/cross-scope claim")
		}
	}
}

func TestDomainClaimWithdrawContention(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-race"
	f.create(t, tenant)
	r := domainRequest(t, f, tenant, "withdraw", "withdraw.example", 1)
	committedTeam(t, f, reserveDomain(t, f, r))
	r.OrganizationVersion = 2
	r.ClaimVersion = 1
	r.CommandID = commandID(t)
	a, e := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	r.CommandID = commandID(t)
	b, e := f.service.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	type result struct {
		r organization.StoreResult
		e error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, p := range []organizationpg.PreparedCommand{a, b} {
		wg.Go(func() { r, e := f.service.Execute(f.ctx, p); results <- result{r, e} })
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for got := range results {
		if got.e == nil && got.r.Receipt.Outcome == identity.CommitOutcomeCommitted {
			wins++
		} else if errors.Is(got.e, organization.ErrConflict) && got.r.Receipt.Outcome == identity.CommitOutcomeNotCommitted {
			conflicts++
		} else {
			t.Fatal("withdraw race", got.e, got.r.Receipt.Outcome)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatal("withdraw applied twice", wins, conflicts)
	}
}

func TestDomainClaimDeniesOrganizationChangedDuringWait(t *testing.T) {
	f := domainFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	p := reserveDomain(t, f, domainRequest(t, f, tenant, "wait", "wait.example", 1))
	ctx, cancel := context.WithTimeout(f.ctx, 8*time.Second)
	defer cancel()
	config, e := pgx.ParseConfig(f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	config.Database = f.database
	admin, e := pgx.ConnectConfig(ctx, config)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(context.Background())
	var pid int32
	if e = admin.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); e != nil {
		t.Fatal(e)
	}
	tx, e := admin.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	var version string
	if e = tx.QueryRow(ctx, `SELECT version::text FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 FOR UPDATE`, tenant, string(metadataOrganization)).Scan(&version); e != nil {
		t.Fatal(e)
	}
	type execution struct {
		r organization.StoreResult
		e error
	}
	done := make(chan execution, 1)
	go func() { r, e := f.service.Execute(ctx, p); done <- execution{r, e} }()
	joined := false
	defer func() {
		_ = tx.Rollback(context.Background())
		cancel()
		if !joined {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("domain waiter failed to stop")
			}
		}
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if e = f.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))`, f.database, pid).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			break
		}
		select {
		case got := <-done:
			joined = true
			t.Fatal("domain did not reach real aggregate wait", got.e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	if _, e = tx.Exec(ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id=$1`, tenant); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	select {
	case got := <-done:
		joined = true
		if !errors.Is(got.e, organization.ErrForbidden) || got.r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("wait retained stale active organization", got.e, got.r.Receipt.Outcome)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var claims int
	if e = f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM organization.domain_claims`).Scan(&claims); e != nil || claims != 0 {
		t.Fatal("stale waiter retained claim", e)
	}
}

func TestDomainClaimRecoveryAndReplayCurrentAuthority(t *testing.T) {
	for _, op := range []organization.Operation{organization.ReserveDomain, organization.WithdrawDomain} {
		for _, stage := range []string{"get", "management", "query", "replay"} {
			t.Run(string(op)+"/"+stage, func(t *testing.T) {
				f := domainFixture(t)
				tenant := "org-test-basic"
				f.create(t, tenant)
				r := domainRequest(t, f, tenant, "recovery", "recovery.example", 1)
				if op == organization.WithdrawDomain {
					committedTeam(t, f, reserveDomain(t, f, r))
					r.CommandID = commandID(t)
					r.OrganizationVersion = 2
					r.ClaimVersion = 1
				}
				policy := &recoveryWithdrawalPolicy{fixture: f, operation: op, stage: stage, withdrawal: "role", tenant: tenant, user: "owner"}
				if stage == "replay" {
					policy.stage = "management"
				}
				c := f.configuration
				c.Authorization = policy
				var e error
				c.Coordinator, e = kernel.NewCoordinator(f.pool, c.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
				if e != nil {
					t.Fatal(e)
				}
				s, e := organizationpg.NewService(f.participant, c)
				if e != nil {
					t.Fatal(e)
				}
				var p organizationpg.PreparedCommand
				if op == organization.ReserveDomain {
					p, e = s.PrepareReserveDomain(f.ctx, r, "127.0.0.1")
				} else {
					p, e = s.PrepareWithdrawDomain(f.ctx, r, "127.0.0.1")
				}
				if e != nil {
					t.Fatal(e)
				}
				if got, e := s.Execute(f.ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("domain setup", e)
				}
				h, e := p.Recovery()
				if e != nil {
					t.Fatal(e)
				}
				policy.armed = true
				var got organization.StoreResult
				if stage == "replay" {
					got, e = s.Execute(f.ctx, p)
				} else {
					got, e = s.Recover(f.ctx, r.Authentication, h)
				}
				if !policy.fired || !errors.Is(e, organization.ErrForbidden) || got != (organization.StoreResult{}) {
					t.Fatal("withdrawn manager disclosed historical custody", e, got.Receipt.Outcome)
				}
			})
		}
	}
}

var _ migrations.Source = organizationpg.DomainClaimMigrationSource{}
