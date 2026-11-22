//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func domainResolver(t *testing.T, f *orgFixture) *organizationpg.Repository {
	t.Helper()
	r, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestResolveDomainProofReturnsExactCurrentDetachedProof(t *testing.T) {
	f, observer := evidenceFixture(t)
	owner := evidenceOwner(t, f, nil)
	proof := committedEvidence(t, f, owner, prepareEvidence(t, f, owner)).Proof
	r := domainResolver(t, f)
	got, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain)
	if err != nil || got != proof {
		t.Fatal("resolution changed exact authoritative proof", got, err)
	}
	exact, err := r.GetDomainProof(f.ctx, organization.DomainProofKey(got))
	if err != nil || exact != got {
		t.Fatal("resolved proof cannot be revalidated by exact primary identity", err)
	}
	got.Domain = "detached.example"
	again, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain)
	if err != nil || again != proof || observer.calls.Load() != 1 {
		t.Fatal("resolution mutated proof or repeated external observation", err)
	}
}

func TestResolveDomainProofDeniesAbsentForeignAndUnprovenClaims(t *testing.T) {
	f, _ := evidenceFixture(t)
	r := domainResolver(t, f)
	if got, err := r.ResolveDomainProof(f.ctx, "org-test-basic", "proof.example"); !errors.Is(err, organization.ErrForbidden) || got != (organization.DomainProof{}) {
		t.Fatal("reservation without proof authorized resolution", err)
	}
	owner := evidenceOwner(t, f, nil)
	committedEvidence(t, f, owner, prepareEvidence(t, f, owner))
	for _, input := range []struct {
		tenant identity.TenantID
		domain string
	}{{"org-test-basic", "absent.example"}, {"org-test-target", "proof.example"}, {"absent-tenant", "proof.example"}} {
		got, err := r.ResolveDomainProof(f.ctx, input.tenant, input.domain)
		if !errors.Is(err, organization.ErrForbidden) || got != (organization.DomainProof{}) {
			t.Fatal("absent or foreign claim disclosed proof", input, err)
		}
	}
}

func TestResolveDomainProofRechecksRevocationAndWithdrawal(t *testing.T) {
	for _, terminal := range []string{"revocation", "withdrawal"} {
		t.Run(terminal, func(t *testing.T) {
			f, _ := evidenceFixture(t)
			owner := evidenceOwner(t, f, nil)
			proof := committedEvidence(t, f, owner, prepareEvidence(t, f, owner)).Proof
			r := domainResolver(t, f)
			if _, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain); err != nil {
				t.Fatal(err)
			}
			if terminal == "revocation" {
				revoker := evidenceOwner(t, f, nil)
				request := evidenceRequest(t, f, 3)
				request.ProofVersion = proof.ProofVersion
				command, err := revoker.PrepareRevocation(f.ctx, request, organization.DomainProofKey(proof))
				if err != nil {
					t.Fatal(err)
				}
				committedEvidence(t, f, revoker, command)
			} else {
				request := domainRequest(t, f, string(proof.TenantID), string(proof.ClaimID), proof.Domain, 3)
				request.ClaimVersion = proof.ClaimVersion
				command, err := f.service.PrepareWithdrawDomain(f.ctx, request, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				committedTeam(t, f, command)
			}
			if got, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain); !errors.Is(err, organization.ErrForbidden) || got != (organization.DomainProof{}) {
				t.Fatal("terminal claim reused cached resolution", err)
			}
		})
	}
}

func TestResolveDomainProofDeniesExpiredInactiveRetiredAndMismatchedEvidence(t *testing.T) {
	for _, state := range []string{"expired", "archived", "restored-retired", "canonical-mismatch"} {
		t.Run(state, func(t *testing.T) {
			f, _ := evidenceFixture(t)
			owner := evidenceOwner(t, f, nil)
			proof := committedEvidence(t, f, owner, prepareEvidence(t, f, owner)).Proof
			r := domainResolver(t, f)
			if _, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain); err != nil {
				t.Fatal(err)
			}
			// Synthetic timestamps exercise primary-clock expiry without sleeping or
			// changing the production clock. Lifecycle updates retain real triggers.
			var query string
			switch state {
			case "expired":
				query = `UPDATE organization.domain_evidence SET observed_at=clock_timestamp()-interval '2 hours',expires_at=clock_timestamp()-interval '1 hour'`
			case "archived", "restored-retired":
				query = `UPDATE organization.organizations SET state='archived',version=version+1`
			case "canonical-mismatch":
				query = `UPDATE organization.domain_evidence SET canonical_domain='other.example'`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, query); err != nil {
				t.Fatal(err)
			}
			if state == "restored-retired" {
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='active',version=version+1`); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := r.ResolveDomainProof(f.ctx, proof.TenantID, proof.Domain); !errors.Is(err, organization.ErrForbidden) || got != (organization.DomainProof{}) {
				t.Fatal("non-current evidence authorized resolution", err)
			}
		})
	}
}

func TestResolveDomainProofRequiresExactCanonicalInputAndContext(t *testing.T) {
	f, _ := evidenceFixture(t)
	r := domainResolver(t, f)
	for _, domain := range []string{"", "PROOF.example", "proof.example.", " proof.example", "https://proof.example", "proof.example/path"} {
		if got, err := r.ResolveDomainProof(f.ctx, "org-test-basic", domain); !errors.Is(err, organization.ErrInvalidInput) || got != (organization.DomainProof{}) {
			t.Fatal("noncanonical domain was accepted", domain, err)
		}
	}
	if _, err := r.ResolveDomainProof(f.ctx, "", "proof.example"); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("empty tenant accepted", err)
	}
	if _, err := r.ResolveDomainProof(nil, "org-test-basic", "proof.example"); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("nil context accepted", err)
	}
	var missing *organizationpg.Repository
	if _, err := missing.ResolveDomainProof(f.ctx, "org-test-basic", "proof.example"); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("nil repository accepted", err)
	}
	cancelled, cancel := context.WithCancel(f.ctx)
	cancel()
	if _, err := r.ResolveDomainProof(cancelled, "org-test-basic", "proof.example"); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled lookup did not preserve cancellation", err)
	}
}

type domainResolutionTrace struct {
	sql   string
	args  []any
	calls int
}

func (trace *domainResolutionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM organization.domain_claims c") {
		trace.sql, trace.args = data.SQL, append([]any(nil), data.Args...)
		trace.calls++
	}
	return ctx
}

func (*domainResolutionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// Run explicitly on a task-owned isolated cluster. The synthetic corpus models
// 10 retained claims per ordinary organization, one maximum-size 10,000-claim
// organization, 90/10 tenant skew and terminal history;
// it measures this read's incremental cost, not a production workload SLA.
func TestResolveDomainProofRepresentativeQueryCost(t *testing.T) {
	if os.Getenv("GOLIB_ORGANIZATION_DOMAIN_RESOLUTION_PERFORMANCE") != "1" {
		t.Skip("explicit representative query measurement only")
	}
	f, _ := evidenceFixture(t)
	owner := evidenceOwner(t, f, nil)
	committedEvidence(t, f, owner, prepareEvidence(t, f, owner))
	const organizations = 10000
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count)
SELECT CASE WHEN n<=9000 THEN 'org-test-basic' ELSE 'org-test-target' END,'measure-org-'||n,'measure-org-'||n,'Measurement','active',1,1,1 FROM generate_series(1,$1::integer) n`, organizations); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.domain_claims(tenant_id,organization_id,claim_id,canonical_domain,state,version,proof_retired)
SELECT CASE WHEN n<=90000 THEN 'org-test-basic' ELSE 'org-test-target' END,'measure-org-'||CASE WHEN n<=10000 THEN 1 ELSE (n-1)/10+1 END,'measure-claim-'||n,'measure-'||n||'.example',CASE WHEN n%10=0 THEN 'withdrawn' ELSE 'requested' END,CASE WHEN n%10=0 THEN 2 ELSE 1 END,n%10=7 FROM generate_series(1,$1::integer) n`, organizations*10); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.domain_evidence(tenant_id,organization_id,claim_id,canonical_domain,claim_version,proof_version,method,observed_at,expires_at,revoked,command_id)
SELECT tenant_id,organization_id,claim_id,canonical_domain,1,1,'dns-txt',clock_timestamp()-interval '2 hours',CASE WHEN n%10=6 THEN clock_timestamp()-interval '1 hour' ELSE clock_timestamp()+interval '1 hour' END,false,'measure-proof-'||n
FROM (SELECT c.*,substring(claim_id FROM 15)::integer AS n FROM organization.domain_claims c WHERE claim_id LIKE 'measure-claim-%') numbered WHERE n%10<>8`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.domain_evidence(tenant_id,organization_id,claim_id,canonical_domain,claim_version,proof_version,method,observed_at,expires_at,revoked,command_id)
SELECT tenant_id,organization_id,claim_id,canonical_domain,claim_version,2,method,observed_at,expires_at,true,command_id||'-revoked' FROM organization.domain_evidence WHERE claim_id LIKE 'measure-claim-%' AND substring(claim_id FROM 15)::integer%10=9;
ANALYZE organization.organizations; ANALYZE organization.domain_claims; ANALYZE organization.domain_evidence`); err != nil {
		t.Fatal(err)
	}
	trace := new(domainResolutionTrace)
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 1, Configure: func(config *database.PoolConfig) error {
		config.ConnConfig.Database, config.ConnConfig.Tracer = f.database, trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	r, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err := pool.Raw().QueryRow(f.ctx, `SELECT version()`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("engine=%s corpus=100001 claims/10001 organizations; 90/10 tenant skew; 10 retained claims/ordinary org and one supported-maximum 10000-claim org; single local client; first call then warm samples; no production equivalence claimed", version)
	metadata, err := pool.Raw().Query(f.ctx, `SELECT indexdef FROM pg_indexes WHERE schemaname='organization' AND tablename IN ('organizations','domain_claims','domain_evidence') ORDER BY tablename,indexname`)
	if err != nil {
		t.Fatal(err)
	}
	for metadata.Next() {
		var definition string
		if err := metadata.Scan(&definition); err != nil {
			metadata.Close()
			t.Fatal(err)
		}
		t.Log("actual index:", definition)
	}
	metadata.Close()
	if err := metadata.Err(); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		name, tenant, domain string
		present              bool
	}{
		{"dense-live", "org-test-basic", "measure-1.example", true},
		{"sparse-live", "org-test-target", "measure-99991.example", true},
		{"missing", "org-test-basic", "not-present.example", false},
		{"foreign", "org-test-target", "measure-1.example", false},
		{"withdrawn", "org-test-basic", "measure-10.example", false},
		{"expired", "org-test-basic", "measure-6.example", false},
		{"retired", "org-test-basic", "measure-7.example", false},
		{"unproven", "org-test-basic", "measure-8.example", false},
		{"revoked", "org-test-basic", "measure-9.example", false},
	} {
		t.Run(input.name, func(t *testing.T) {
			before := trace.calls
			start := time.Now()
			proof, err := r.ResolveDomainProof(f.ctx, identity.TenantID(input.tenant), input.domain)
			first := time.Since(start)
			if input.present && (err != nil || proof.Domain != input.domain) || !input.present && (!errors.Is(err, organization.ErrForbidden) || proof != (organization.DomainProof{})) {
				t.Fatal("representative result", proof, err)
			}
			if trace.calls-before != 1 || len(trace.args) != 2 {
				t.Fatal("resolution must execute one bounded primary query", trace.calls-before)
			}
			t.Logf("query=%s bindings=(%T,%T)", trace.sql, trace.args[0], trace.args[1])
			connection, err := pool.Raw().Acquire(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			description, describeErr := connection.Conn().Prepare(f.ctx, "domain_resolution_measurement", trace.sql)
			connection.Release()
			if describeErr != nil {
				t.Fatal(describeErr)
			}
			t.Logf("actual PostgreSQL parameter OIDs=%v (25=text; schema scope columns use identity.directory_id text domain)", description.ParamOIDs)
			rows, err := pool.Raw().Query(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+trace.sql, trace.args...)
			if err != nil {
				t.Fatal(err)
			}
			for rows.Next() {
				var line string
				if err := rows.Scan(&line); err != nil {
					rows.Close()
					t.Fatal(err)
				}
				t.Log(line)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			elapsed := make([]time.Duration, 100)
			for i := range elapsed {
				start := time.Now()
				_, err := r.ResolveDomainProof(f.ctx, identity.TenantID(input.tenant), input.domain)
				elapsed[i] = time.Since(start)
				if input.present && err != nil || !input.present && !errors.Is(err, organization.ErrForbidden) {
					t.Fatal(err)
				}
			}
			slices.Sort(elapsed)
			t.Log(fmt.Sprintf("first=%s warm-p50=%s warm-p95=%s warm-max=%s queries/call=1", first, elapsed[49], elapsed[94], elapsed[99]))
		})
	}
}
