//go:build integration

package postgres_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryMembershipPlan struct {
	Node     string                    `json:"Node Type"`
	Index    string                    `json:"Index Name"`
	Rows     float64                   `json:"Actual Rows"`
	Loops    float64                   `json:"Actual Loops"`
	Filtered float64                   `json:"Rows Removed by Filter"`
	Hits     int64                     `json:"Shared Hit Blocks"`
	Reads    int64                     `json:"Shared Read Blocks"`
	Plans    []directoryMembershipPlan `json:"Plans"`
}

func (p directoryMembershipPlan) examined() float64 {
	var rows float64
	if p.Node == "Seq Scan" || p.Node == "Index Scan" || p.Node == "Index Only Scan" || p.Node == "Bitmap Heap Scan" {
		rows = (p.Rows + p.Filtered) * p.Loops
	}
	for _, child := range p.Plans {
		rows += child.examined()
	}
	return rows
}

// This is physical query-cost evidence on the native migrated schema, not a
// production workload prediction. There is no predecessor for the source SQL;
// report its incremental cost beside the existing canonical member removal and
// the real coordinator caller. Warm, uncontended local timings exclude setup,
// transaction begin/rollback and connection acquisition.
func TestDirectoryMembershipNativeQueryPlans(t *testing.T) {
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	// Establish the measured organization before synthetic memberships put the
	// existing owner above the ordinary creation limit of 100 organizations.
	f.create(t, "org-test-basic")
	// Three tenants, 400 organizations each and four logical members per org
	// avoid a tiny canonical table. 12k distributed sources plus 12k sources
	// concentrated on two members model retained-history skew. Only one of the
	// latter member's 6k sources is active; the other's entire history is dead.
	for _, sql := range []string{
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
		`ANALYZE organization.organizations`,
		`ANALYZE organization.memberships`,
		`ANALYZE organization.directory_membership_grants`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql); err != nil {
			t.Fatal("representative native setup", err)
		}
	}
	var version, columns, indexes string
	var organizations, members, sources, active int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version(),
(SELECT string_agg(table_name||'.'||column_name||'='||COALESCE(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY table_name,ordinal_position) FROM information_schema.columns WHERE table_schema='organization' AND table_name IN ('organizations','memberships','directory_membership_grants')),
(SELECT string_agg(indexname||': '||indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='organization' AND tablename IN ('organizations','memberships','directory_membership_grants')),
(SELECT count(*) FROM organization.organizations),(SELECT count(*) FROM organization.memberships),
(SELECT count(*) FROM organization.directory_membership_grants),(SELECT count(*) FROM organization.directory_membership_grants WHERE active)`).Scan(&version, &columns, &indexes, &organizations, &members, &sources, &active); err != nil {
		t.Fatal(err)
	}
	if organizations != 1201 || members != 4801 || sources != 24000 || active != 1198 {
		t.Fatal("unexpected representative distribution", organizations, members, sources, active)
	}
	t.Logf("isolated %s; organizations=%d memberships=%d sources=%d active=%d; warm serial workload, no concurrent writers; not production-scale/concurrency evidence\ncolumns: %s\nindexes: %s", version, organizations, members, sources, active, columns, indexes)

	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	queries := organizationpg.DirectoryMembershipPlanSQL()
	for _, name := range []string{"owner", "observe", "require", "active", "insert", "update", "remove-member"} {
		description, err := connection.Conn().Prepare(f.ctx, "directory_plan_"+name, queries[name])
		if err != nil {
			t.Fatal("describe production SQL", name, err)
		}
		var parameterTypes string
		if err := connection.QueryRow(f.ctx, `SELECT string_agg(oid::text||'='||typname||'(base='||typbasetype::text||')',', ' ORDER BY oid) FROM pg_type WHERE oid=ANY($1::oid[])`, description.ParamOIDs).Scan(&parameterTypes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s actual SQL=%s; PostgreSQL parameter OIDs=%v; %s", name, queries[name], description.ParamOIDs, parameterTypes)
	}

	readArgs := []any{"org-test-basic", "plan-1", "member", "1", "dense", "source-6000"}
	writeArgs := []any{"org-test-basic", "plan-1", "member", "1", "dense", "source-6000", "resource-6000", "2", false, "1"}
	cases := []struct {
		name, query string
		args        []any
		rows        [][]any
		write       bool
		affected    int64
	}{
		{name: "owner-exact", query: "owner", args: readArgs[:2], rows: [][]any{{"1", "1", int64(4), int64(1)}}},
		{name: "owner-missing", query: "owner", args: []any{"org-test-basic", "missing"}},
		{name: "observe-active", query: "observe", args: []any{"org-test-basic", "plan-1", "member", "dense", "source-6000"}, rows: [][]any{{"member", "1", "1", true, "resource-6000", "1", true}}},
		{name: "observe-tombstone", query: "observe", args: []any{"org-test-basic", "plan-1", "second", "dense", "source-1"}, rows: [][]any{{"member", "1", "1", true, "resource-1", "1", false}}},
		{name: "observe-no-source", query: "observe", args: []any{"org-test-basic", "plan-1", "member", "missing", "missing"}, rows: [][]any{{"member", "1", "1", true, "", "0", false}}},
		{name: "observe-no-member", query: "observe", args: []any{"org-test-basic", "plan-1", "missing", "dense", "source-6000"}, rows: [][]any{{"", "0", "0", false, "", "0", false}}},
		{name: "observe-no-org", query: "observe", args: []any{"org-test-basic", "missing", "member", "dense", "source-6000"}},
		{name: "require-active", query: "require", args: readArgs, rows: [][]any{{"resource-6000", "1", true}}},
		{name: "require-tombstone", query: "require", args: []any{"org-test-basic", "plan-1", "second", "1", "dense", "source-1"}, rows: [][]any{{"resource-1", "1", false}}},
		{name: "require-missing", query: "require", args: []any{"org-test-basic", "plan-1", "member", "1", "dense", "missing"}},
		{name: "active-dense-retained", query: "active", args: readArgs[:4], rows: [][]any{{true}}},
		{name: "active-dense-all-inactive", query: "active", args: []any{"org-test-basic", "plan-1", "second", "1"}, rows: [][]any{{false}}},
		{name: "active-sparse", query: "active", args: []any{"org-test-target", "plan-400", "member", "1"}, rows: [][]any{{true}}},
		{name: "active-no-incarnation", query: "active", args: []any{"org-test-basic", "plan-1", "member", "2"}, rows: [][]any{{false}}},
		{name: "insert-new", query: "insert", args: []any{"org-test-basic", "plan-1", "outsider", "1", "new", "new", "new", "1", true}, write: true, affected: 1},
		{name: "insert-conflict", query: "insert", args: append(slices.Clone(writeArgs[:8]), true), write: true},
		{name: "withdraw-exact", query: "update", args: writeArgs, write: true, affected: 1},
		{name: "withdraw-stale", query: "update", args: append(slices.Clone(writeArgs[:9]), "2"), write: true},
		{name: "withdraw-wrong-resource", query: "update", args: []any{"org-test-basic", "plan-1", "member", "1", "dense", "source-6000", "different", "2", false, "1"}, write: true},
		{name: "regrant-already-active", query: "update", args: []any{"org-test-basic", "plan-1", "member", "1", "dense", "source-6000", "resource-6000", "2", true, "1"}, write: true},
		{name: "regrant-exact", query: "update", args: []any{"org-test-basic", "plan-1", "second", "1", "dense", "source-1", "resource-1", "2", true, "1"}, write: true, affected: 1},
		{name: "remove-member-exact", query: "remove-member", args: []any{"org-test-basic", "plan-1", "member", "2", "1"}, write: true, affected: 1},
		{name: "remove-member-stale", query: "remove-member", args: []any{"org-test-basic", "plan-1", "member", "2", "2"}, write: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, arg := range tc.args {
				if _, ok := arg.(string); !ok && !(tc.write && (i == 8) && reflect.TypeOf(arg).Kind() == reflect.Bool) {
					t.Fatalf("binding %d has unexpected native type %T", i+1, arg)
				}
			}
			begin := func() pgx.Tx {
				t.Helper()
				tx, err := connection.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = tx.Rollback(f.ctx) })
				if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='2s'"); err != nil {
					t.Fatal(err)
				}
				return tx
			}
			tx := begin()
			var wire []byte
			if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+queries[tc.query], tc.args...).Scan(&wire); err != nil {
				t.Fatal(err)
			}
			var report []struct {
				Plan directoryMembershipPlan
				MS   float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(wire, &report); err != nil || len(report) != 1 {
				t.Fatal("invalid actual plan", err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			// Bound examined work rather than requiring a brittle planner node
			// path. Scanning thousands of retained sources must not pass merely
			// because EXISTS returns one boolean or a write affects one row.
			plan := report[0].Plan
			if plan.examined() > 64 || plan.Hits+plan.Reads > 256 {
				t.Fatalf("exact query examined retained history: %s", wire)
			}
			samples := make([]time.Duration, 7)
			for i := range samples {
				tx := begin()
				started := time.Now()
				if tc.write {
					tag, err := tx.Exec(f.ctx, queries[tc.query], tc.args...)
					samples[i] = time.Since(started)
					if err != nil || tag.RowsAffected() != tc.affected {
						t.Fatal("native write result", tag.RowsAffected(), tc.affected, err)
					}
				} else {
					rows, err := tx.Query(f.ctx, queries[tc.query], tc.args...)
					if err != nil {
						t.Fatal(err)
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
					if rows.Err() != nil || !reflect.DeepEqual(got, tc.rows) {
						t.Fatal("native read result", got, tc.rows, rows.Err())
					}
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			slices.Sort(samples)
			t.Logf("bindings=%v (strings plus boolean active); examined=%.0f shared-buffers=%d server-explain=%.3fms; seven warm native statement samples p50=%s max=%s; each mutation/lock rolled back; plan=%s", tc.args, plan.examined(), plan.Hits+plan.Reads, report[0].MS, samples[3], samples[6], wire)
		})
	}
	connection.Release()
	// This real caller uses the same native Work helper as the behavioral
	// regression. Command/audit preparation is outside each measured execution.
	store, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []identity.UserID{"member", "second", "outsider"} {
		for _, action := range []organizationpg.DirectoryMembershipAction{organizationpg.DirectoryMembershipGrant, organizationpg.DirectoryMembershipWithdraw} {
			source := organizationpg.DirectoryMembershipSource{TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: user, ProviderID: "native", ConnectionID: "native", ResourceID: "native"}
			observed, err := store.ObserveDirectoryMembership(f.ctx, source)
			if err != nil {
				t.Fatal(err)
			}
			org, err := store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: source.TenantID, OrganizationID: source.OrganizationID})
			if err != nil {
				t.Fatal(err)
			}
			input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", User: identity.User{TenantID: source.TenantID, ID: user, Status: identity.StatusActive, Version: 1}, Organization: org, MemberVersion: observed.Member.Version, MemberAuthorizationVersion: observed.Member.AuthorizationVersion, ExpectedVersion: observed.ContributionVersion, Action: action, MaximumMembers: 20, MaximumPerUser: 1000}
			if action == organizationpg.DirectoryMembershipWithdraw {
				input.User = identity.User{}
			}
			owner := &directoryMembershipWorkOwner{repository: store, withdraw: action == organizationpg.DirectoryMembershipWithdraw}
			coordinator, command, commandPlan := directoryMembershipNativeWork(t, f, owner, input)
			started := time.Now()
			result, err := executeDirectoryTeamNative(f.ctx, coordinator, command, commandPlan)
			elapsed := time.Since(started)
			if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("representative native caller", err, result.Outcome)
			}
			t.Logf("whole native caller user=%s action=%d elapsed=%s (reserve/begin/apply/final-check/audit/outbox/commit included; preparation and observations excluded)", user, action, elapsed)
		}
	}
}
