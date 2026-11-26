//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
)

// The predecessor and candidate use the same populated native schema, bindings,
// and connection. Serial warm-cache samples show incremental local read cost,
// not production contention or source-owner write throughput.
func TestDirectoryMembershipAttributionNativeQueryPlans(t *testing.T) {
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	f.create(t, "org-test-basic")
	for _, query := range []string{
		`INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count)
SELECT tenant,'plan-'||n,'plan-'||n,'Plan fixture','active',1,4,1
FROM unnest(ARRAY['org-test-basic','org-test-scope','org-test-target']) tenant CROSS JOIN generate_series(1,400) n`,
		`INSERT INTO organization.memberships(tenant_id,organization_id,user_id,role,state,version,authorization_version)
SELECT tenant_id,organization_id,u,CASE WHEN u='owner' THEN 'owner' ELSE 'member' END,'active',1,1
FROM organization.organizations CROSS JOIN unnest(ARRAY['owner','second','member','outsider']) u WHERE organization_id LIKE 'plan-%'`,
		`INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
SELECT tenant_id,organization_id,user_id,1,'distributed','source-'||n,'resource-'||n,1,
n=5 AND user_id='member' AND organization_id<>'plan-1'
FROM organization.memberships CROSS JOIN generate_series(1,5) n WHERE user_id IN ('member','second')`,
		`INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
SELECT 'org-test-basic','plan-1',u,1,'dense','source-'||n,'resource-'||n,1,n=6000 AND u='member'
FROM unnest(ARRAY['member','second']) u CROSS JOIN generate_series(1,6000) n`,
		`INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
SELECT 'org-test-basic','plan-2','member',1,'multi','source-'||n,'resource-'||n,1,true FROM generate_series(1,3000) n`,
		`INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active)
SELECT 'org-test-basic','plan-3','second',incarnation,'history','source-'||n,'old-resource-'||n,1,true
FROM generate_series(2,3) incarnation CROSS JOIN generate_series(1,3000) n`,
		`ANALYZE organization.organizations,organization.memberships,organization.directory_membership_grants`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, query); err != nil {
			t.Fatal("populate representative attribution fixture", err)
		}
	}
	var engine, columns, indexes string
	var organizations, members, grants, active int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version(),
(SELECT string_agg(table_name||'.'||column_name||'='||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='organization' AND table_name IN ('organizations','memberships','directory_membership_grants')),
(SELECT string_agg(indexname||': '||indexdef,E'\n' ORDER BY indexname) FROM pg_indexes
 WHERE schemaname='organization' AND tablename IN ('organizations','memberships','directory_membership_grants')),
(SELECT count(*) FROM organization.organizations),(SELECT count(*) FROM organization.memberships),
(SELECT count(*) FROM organization.directory_membership_grants),(SELECT count(*) FROM organization.directory_membership_grants WHERE active)`).Scan(&engine, &columns, &indexes, &organizations, &members, &grants, &active); err != nil {
		t.Fatal("describe representative attribution database", err)
	}
	if organizations != 1201 || members != 4801 || grants != 33000 || active != 10198 {
		t.Fatalf("unexpected attribution distribution: organizations=%d members=%d grants=%d active=%d", organizations, members, grants, active)
	}
	t.Logf("isolated %s; organizations=%d memberships=%d grants=%d active=%d; three tenants, sparse distributed grants, 6k retained rows each for one-source and local members, 3k current origins, 6k active noncurrent incarnations; warm serial, no concurrent load; columns=%s; indexes=%s", engine, organizations, members, grants, active, columns, indexes)
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	queries := organizationpg.DirectoryMembershipPlanSQL()
	var baselineOIDs []uint32
	for _, name := range []string{"observe", "attribution"} {
		query := queries[name]
		if query == "" {
			t.Fatal("missing actual production SQL export", name)
		}
		description, err := connection.Conn().Prepare(f.ctx, "membership_attribution_"+name, query)
		if err != nil {
			t.Fatal("describe typed production query", name, err)
		}
		if len(description.ParamOIDs) != 5 {
			t.Fatalf("%s described %d parameters; want five native strings", name, len(description.ParamOIDs))
		}
		if name == "observe" {
			baselineOIDs = slices.Clone(description.ParamOIDs)
		} else if !slices.Equal(description.ParamOIDs, baselineOIDs) {
			t.Fatalf("candidate changed native parameter types: baseline=%v candidate=%v", baselineOIDs, description.ParamOIDs)
		}
		var parameterTypes string
		if err := connection.QueryRow(f.ctx, `SELECT string_agg(oid::text||'='||typname||'(base='||typbasetype::text||')',', ' ORDER BY oid) FROM pg_type WHERE oid=ANY($1::oid[])`, description.ParamOIDs).Scan(&parameterTypes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s actual SQL=%s; Go binding types=string,string,string,string,string; PostgreSQL OIDs=%v (%s)", name, query, description.ParamOIDs, parameterTypes)
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, tenant, org, user, provider, connection, resource string
		memberRole, contributionResource, contributionVersion   string
		contributionActive, local, other                        bool
		absentMember, absentOwner                               bool
	}{
		{name: "sparse-selected-origin", tenant: "org-test-target", org: "plan-400", user: "member", provider: "distributed", connection: "source-5", resource: "resource-5", memberRole: "member", contributionResource: "resource-5", contributionVersion: "1", contributionActive: true},
		{name: "sparse-other-origin", tenant: "org-test-target", org: "plan-400", user: "member", provider: "distributed", connection: "source-1", resource: "resource-1", memberRole: "member", contributionResource: "resource-1", contributionVersion: "1", other: true},
		{name: "sparse-local", tenant: "org-test-target", org: "plan-400", user: "outsider", provider: "missing", connection: "missing", resource: "missing", memberRole: "member", contributionVersion: "0", local: true},
		{name: "dense-one-selected-origin", tenant: "org-test-basic", org: "plan-1", user: "member", provider: "dense", connection: "source-6000", resource: "resource-6000", memberRole: "member", contributionResource: "resource-6000", contributionVersion: "1", contributionActive: true},
		{name: "dense-one-other-origin", tenant: "org-test-basic", org: "plan-1", user: "member", provider: "missing", connection: "missing", resource: "missing", memberRole: "member", contributionVersion: "0", other: true},
		{name: "dense-local-tombstone", tenant: "org-test-basic", org: "plan-1", user: "second", provider: "dense", connection: "source-1", resource: "resource-1", memberRole: "member", contributionResource: "resource-1", contributionVersion: "1", local: true},
		{name: "dense-multiple-origins", tenant: "org-test-basic", org: "plan-2", user: "member", provider: "multi", connection: "source-1500", resource: "resource-1500", memberRole: "member", contributionResource: "resource-1500", contributionVersion: "1", contributionActive: true, other: true},
		{name: "dense-multiple-other-origins", tenant: "org-test-basic", org: "plan-2", user: "member", provider: "missing", connection: "missing", resource: "missing", memberRole: "member", contributionVersion: "0", other: true},
		{name: "active-retained-and-future-incarnations", tenant: "org-test-basic", org: "plan-3", user: "second", provider: "history", connection: "source-3000", resource: "new-resource", memberRole: "member", contributionVersion: "0", local: true},
		{name: "same-identifiers-other-tenant", tenant: "org-test-scope", org: "plan-1", user: "member", provider: "dense", connection: "source-6000", resource: "resource-6000", memberRole: "member", contributionVersion: "0", local: true},
		{name: "absent-member", tenant: "org-test-basic", org: "plan-1", user: "missing", provider: "dense", connection: "source-6000", resource: "resource-6000", contributionVersion: "0", absentMember: true},
		{name: "absent-owner", tenant: "org-test-basic", org: "missing", user: "member", provider: "dense", connection: "source-6000", resource: "resource-6000", absentOwner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []any{tc.tenant, tc.org, tc.user, tc.provider, tc.connection}
			for i, arg := range args {
				if _, ok := arg.(string); !ok {
					t.Fatalf("binding %d changed native driver type to %T", i+1, arg)
				}
			}
			var expected [][]any
			if !tc.absentOwner {
				memberVersion, memberEpoch, memberActive := "1", "1", true
				if tc.absentMember {
					memberVersion, memberEpoch, memberActive = "0", "0", false
				}
				expected = [][]any{{tc.memberRole, memberVersion, memberEpoch, memberActive, tc.contributionResource, tc.contributionVersion, tc.contributionActive}}
			}
			for _, name := range []string{"observe", "attribution"} {
				query := queries[name]
				want := expected
				if name == "attribution" && !tc.absentOwner {
					want = [][]any{append(slices.Clone(expected[0]), "1", "1", tc.other)}
				}
				tx, err := connection.BeginTx(f.ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(f.ctx)
				if _, err := tx.Exec(f.ctx, `SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='1s'`); err != nil {
					t.Fatal(err)
				}
				var wire []byte
				if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&wire); err != nil {
					t.Fatal("actual attribution access plan", name, err)
				}
				var report []struct {
					Plan directoryMembershipPlan
					MS   float64 `json:"Execution Time"`
				}
				if err := json.Unmarshal(wire, &report); err != nil || len(report) != 1 {
					t.Fatal("decode attribution access plan", name, err)
				}
				plan := report[0].Plan
				if plan.examined() > 64 || plan.Hits+plan.Reads > 256 {
					t.Fatalf("%s traversed unrelated or noncurrent grant history: %s", name, wire)
				}
				samples := make([]time.Duration, 7)
				for i := range samples {
					started := time.Now()
					rows, err := tx.Query(f.ctx, query, args...)
					if err != nil {
						t.Fatal("execute typed native query", name, err)
					}
					var got [][]any
					for rows.Next() {
						values, err := rows.Values()
						if err != nil {
							rows.Close()
							t.Fatal(err)
						}
						got = append(got, values)
					}
					rows.Close()
					samples[i] = time.Since(started)
					if rows.Err() != nil || !reflect.DeepEqual(got, want) {
						t.Fatalf("%s native result = %v, %v; want %v", name, got, rows.Err(), want)
					}
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal(err)
				}
				slices.Sort(samples)
				t.Logf("%s bindings=%v; returned=%d examined=%.0f shared-buffers=%d server=%.3fms; seven warm native statement samples p50=%s max=%s excluding connection acquisition and transaction begin/rollback; plan=%s", name, args, len(want), plan.examined(), plan.Hits+plan.Reads, report[0].MS, samples[3], samples[6], wire)
			}
			source := organizationpg.DirectoryMembershipSource{TenantID: identity.TenantID(tc.tenant), OrganizationID: organization.ID(tc.org), UserID: identity.UserID(tc.user), ProviderID: organization.ID(tc.provider), ConnectionID: organization.ID(tc.connection), ResourceID: organization.ID(tc.resource)}
			baselineSamples, candidateSamples := make([]time.Duration, 7), make([]time.Duration, 7)
			for i := range baselineSamples {
				started := time.Now()
				original, originalErr := repo.ObserveDirectoryMembership(f.ctx, source)
				baselineSamples[i] = time.Since(started)
				started = time.Now()
				got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, source)
				candidateSamples[i] = time.Since(started)
				if tc.absentOwner {
					if !errors.Is(originalErr, organization.ErrForbidden) || !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryMembershipAttribution{}) {
						t.Fatalf("absent owning API result: original=%v candidate=%+v, %v", originalErr, got, err)
					}
				} else if originalErr != nil || err != nil || got.Membership != original || got.OrganizationVersion != 1 || got.CredentialVersion != 1 || got.Local != tc.local || got.OtherSource != tc.other {
					t.Fatalf("owning API attribution changed selected facts: original=%+v, %v candidate=%+v, %v; want local=%t other=%t", original, originalErr, got, err, tc.local, tc.other)
				}
			}
			slices.Sort(baselineSamples)
			slices.Sort(candidateSamples)
			t.Logf("seven paired owning API samples with pooled acquisition/decoding: baseline p50=%s max=%s; attribution p50=%s max=%s; each implementation executes one primary statement; attribution adds owner versions and bounded current-origin lookup", baselineSamples[3], baselineSamples[6], candidateSamples[3], candidateSamples[6])
		})
	}
}
