//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
)

// Native migrated, isolated density evidence; warm serial samples do not model
// production contention, connection acquisition, or the source owner's writes.
func TestDirectoryTeamRoleObservationNativeQueryPlans(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	const tenant = "org-test-basic"
	org := string(metadataOrganization)
	for _, query := range []string{
		`INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements)
SELECT $1,$2,'dense-role-'||n,'Dense role',1,CASE WHEN n=100 THEN 'deleted' ELSE 'active' END,'[]' FROM generate_series(1,100) n`,
		`INSERT INTO organization.teams(tenant_id,organization_id,team_id,name,version)
SELECT $1,$2,'dense-team-'||n,'Dense team',1 FROM generate_series(1,100) n`,
		`INSERT INTO organization.team_role_bindings(tenant_id,organization_id,team_id,role_id,version,state)
SELECT $1,$2,'dense-team-'||t,'dense-role-'||r,7,CASE WHEN r=99 THEN 'removed' ELSE 'active' END
FROM generate_series(1,100) t CROSS JOIN generate_series(1,100) r`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, query, tenant, org); err != nil {
			t.Fatal("dense native selection fixture", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.custom_roles,organization.teams,organization.team_identities,organization.team_role_bindings`); err != nil {
		t.Fatal(err)
	}
	var engine, columns, indexes string
	var bindings int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version(),
(SELECT string_agg(table_name||'.'||column_name||'='||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY table_name,ordinal_position)
 FROM information_schema.columns WHERE table_schema='organization' AND table_name IN ('custom_roles','teams','team_identities','team_role_bindings')),
(SELECT string_agg(indexname||': '||indexdef,E'\n' ORDER BY indexname) FROM pg_indexes
 WHERE schemaname='organization' AND tablename IN ('custom_roles','teams','team_identities','team_role_bindings')),
(SELECT count(*) FROM organization.team_role_bindings)`).Scan(&engine, &columns, &indexes, &bindings); err != nil {
		t.Fatal(err)
	}
	if bindings != 10001 {
		t.Fatalf("dense fixture has %d bindings, want 10001", bindings)
	}
	query := organizationpg.DirectoryTeamRoleObservationPlanSQL()
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	description, err := connection.Conn().Prepare(f.ctx, "directory_team_role_observe", query)
	if err != nil {
		t.Fatal("describe actual observation query", err)
	}
	var parameterTypes string
	if err := connection.QueryRow(f.ctx, `SELECT string_agg(oid::text||'='||typname||'(base='||typbasetype::text||')',', ' ORDER BY oid) FROM pg_type WHERE oid=ANY($1::oid[])`, description.ParamOIDs).Scan(&parameterTypes); err != nil {
		t.Fatal(err)
	}
	t.Logf("isolated %s; bindings=%d, 101 teams, 101 roles; 100x100 dense bindings, one removed column, one deleted role; warm serial and no concurrent load; SQL=%s; Go binding types=string,string,string,string; PostgreSQL parameter OIDs=%v (%s); columns=%s; indexes=%s", engine, bindings, query, description.ParamOIDs, parameterTypes, columns, indexes)
	for _, tc := range []struct {
		name, team, role string
		version          uint64
	}{
		{"native-add", "engineering", "reader", view.TeamRoleBinding.Version},
		{"dense-match", "dense-team-50", "dense-role-50", 7},
		{"no-binding", "engineering", "dense-role-50", 0},
		{"no-team", "missing", "reader", 0},
		{"no-role", "dense-team-50", "missing", 0},
		{"removed-binding", "dense-team-50", "dense-role-99", 0},
		{"deleted-role", "dense-team-50", "dense-role-100", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []any{tenant, org, tc.team, tc.role}
			var wire []byte
			if err := connection.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+query, args...).Scan(&wire); err != nil {
				t.Fatal(err)
			}
			var report []struct {
				Plan directoryMembershipPlan
				MS   float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(wire, &report); err != nil || len(report) != 1 {
				t.Fatal("decode actual native observation plan", err)
			}
			p := report[0].Plan
			// Small native target tables may legitimately scan their 101 rows;
			// unrelated dense binding history must not become examined work.
			if p.examined() > 512 || p.Hits+p.Reads > 512 {
				t.Fatalf("exact observation traversed unrelated binding history: %s", wire)
			}
			var samples []time.Duration
			for range 7 {
				started := time.Now()
				var got string
				err := connection.QueryRow(f.ctx, query, args...).Scan(&got)
				samples = append(samples, time.Since(started))
				if tc.version == 0 {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("inactive or absent selection returned %q: %v", got, err)
					}
				} else if err != nil || got != strconv.FormatUint(tc.version, 10) {
					t.Fatalf("exact selection = %q, %v; want %d", got, err, tc.version)
				}
			}
			slices.Sort(samples)
			t.Logf("typed bindings=%v; examined=%.0f shared-buffers=%d server=%.3fms; seven native samples p50=%s max=%s; plan=%s", args, p.examined(), p.Hits+p.Reads, report[0].MS, samples[3], samples[6], wire)
		})
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected := directoryTeamRoleObservationScope()
	selected.TeamID = "dense-team-50"
	if got, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, selected, "dense-role-50"); got != 7 || err != nil {
		t.Fatalf("owning API lost exact native selection beside dense history: %d, %v", got, err)
	}
	selected.TenantID = "org-test-scope"
	if got, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, selected, "dense-role-50"); got != 0 || !errors.Is(err, organization.ErrForbidden) {
		t.Fatalf("dense lookup crossed tenant scope: %d, %v", got, err)
	}
}
