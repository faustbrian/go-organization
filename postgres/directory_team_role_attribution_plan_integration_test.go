//go:build integration

package postgres_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
)

type directoryTeamRoleAttributionIndexPlan struct {
	Index     string                                  `json:"Index Name"`
	Condition string                                  `json:"Index Cond"`
	Loops     float64                                 `json:"Actual Loops"`
	Plans     []directoryTeamRoleAttributionIndexPlan `json:"Plans"`
}

func (p directoryTeamRoleAttributionIndexPlan) exactIndex(index string, keys []string) bool {
	if p.Index == index && p.Loops > 0 {
		for _, key := range keys {
			if !strings.Contains(p.Condition, key) {
				return false
			}
		}
		return true
	}
	for _, child := range p.Plans {
		if child.exactIndex(index, keys) {
			return true
		}
	}
	return false
}

// The partial membership and binding reads are cost context, not equivalent
// predecessors: neither returns retained role-source metadata. These populated
// native-schema samples are warm and serial, not production-load predictions.
func TestDirectoryTeamRoleAttributionNativeQueryPlans(t *testing.T) {
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
		`INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
SELECT $1,$2,'provider','connection','dense-'||n,'engineering',u,7,1,n=5000
FROM unnest(ARRAY['member','owner']) u CROSS JOIN generate_series(1,10000) n`,
		`INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
SELECT $1,$2,u,'provider','connection','dense-'||n,'engineering','retained-member-'||n,'reader',7,1,11,13,17
FROM unnest(ARRAY['member','owner']) u CROSS JOIN generate_series(1,10000) n`,
		`INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
VALUES($1,$2,'provider','connection','membership-only','engineering','member',9,1,true)`,
		`ANALYZE organization.organizations,organization.memberships,organization.teams,organization.team_identities,organization.team_memberships,organization.custom_roles,organization.team_role_bindings,organization.directory_team_grants,organization.directory_team_role_grants`,
	} {
		var args []any
		if strings.Contains(query, "$1") {
			args = []any{tenant, org}
		}
		if _, err := f.pool.Raw().Exec(f.ctx, query, args...); err != nil {
			t.Fatal("populate native attribution fixture", err)
		}
	}
	var engine, columns, indexes string
	var grants, retained, bindings, active int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version(),
(SELECT string_agg(table_schema||'.'||table_name||'.'||column_name||'='||coalesce(domain_schema||'.'||domain_name,udt_schema||'.'||udt_name),', ' ORDER BY table_schema,table_name,ordinal_position)
 FROM information_schema.columns WHERE (table_schema='organization' AND table_name IN ('organizations','memberships','teams','team_identities','team_memberships','custom_roles','team_role_bindings','directory_team_grants','directory_team_role_grants')) OR (table_schema='identity' AND table_name='users')),
(SELECT string_agg(indexname||': '||indexdef,E'\n' ORDER BY indexname) FROM pg_indexes
 WHERE (schemaname='organization' AND tablename IN ('organizations','memberships','teams','team_identities','team_memberships','custom_roles','team_role_bindings','directory_team_grants','directory_team_role_grants')) OR (schemaname='identity' AND tablename='users')),
(SELECT count(*) FROM organization.directory_team_grants),
(SELECT count(*) FROM organization.directory_team_role_grants),
(SELECT count(*) FROM organization.team_role_bindings),
(SELECT count(*) FROM organization.directory_team_grants WHERE active)`).Scan(&engine, &columns, &indexes, &grants, &retained, &bindings, &active); err != nil {
		t.Fatal("describe native attribution database", err)
	}
	if grants != 20001 || retained != 20000 || bindings != 10001 || active != 3 {
		t.Fatalf("unexpected fixture distribution: grants=%d retained=%d bindings=%d active=%d", grants, retained, bindings, active)
	}
	t.Logf("isolated %s; one selected tenant/organization with two members, 101 teams and 101 roles; grants=%d retained=%d bindings=%d active=%d; each member has 10k retained origins with one current source; columns=%s; indexes=%s", engine, grants, retained, bindings, active, columns, indexes)
	queries := organizationpg.DirectoryTeamRoleAttributionPlanSQL()
	connection, err := f.pool.Raw().Acquire(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Release()
	for _, item := range []struct {
		name       string
		parameters int
	}{{"membership", 7}, {"binding", 4}, {"attribution", 8}} {
		query := queries[item.name]
		if query == "" {
			t.Fatal("missing production query export", item.name)
		}
		description, err := connection.Conn().Prepare(f.ctx, "team_role_attribution_"+item.name, query)
		if err != nil || len(description.ParamOIDs) != item.parameters {
			t.Fatalf("describe actual %s query: %v; parameters=%v", item.name, err, description)
		}
		var parameterTypes string
		if err := connection.QueryRow(f.ctx, `SELECT string_agg(oid::text||'='||typname||'(base='||typbasetype::text||')',', ' ORDER BY oid) FROM pg_type WHERE oid=ANY($1::oid[])`, description.ParamOIDs).Scan(&parameterTypes); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s actual SQL=%s; %d Go string bindings; PostgreSQL parameter OIDs=%v (%s)", item.name, query, item.parameters, description.ParamOIDs, parameterTypes)
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, group, team, role string
		sourceVersion           uint64
		source, retained        bool
		binding, roleVersion    uint64
		forbidden               bool
	}{
		{name: "current-selected-dense-origin", group: "dense-5000", team: "engineering", role: "reader", sourceVersion: 7, source: true, retained: true, binding: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version},
		{name: "inactive-retained-origin", group: "dense-1", team: "engineering", role: "reader", sourceVersion: 7, retained: true, binding: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version},
		{name: "absent-selected-origin", group: "missing", team: "engineering", role: "reader", binding: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version},
		{name: "membership-without-retained-role", group: "membership-only", team: "engineering", role: "reader", sourceVersion: 9, source: true, binding: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version},
		{name: "different-requested-role", group: "dense-5000", team: "engineering", role: "dense-role-50", sourceVersion: 7, source: true, retained: true, roleVersion: 1},
		{name: "dense-current-native-binding", group: "missing", team: "dense-team-50", role: "dense-role-50", binding: 7, roleVersion: 1},
		{name: "removed-native-binding", group: "missing", team: "dense-team-50", role: "dense-role-99", roleVersion: 1},
		{name: "deleted-requested-role", group: "dense-5000", team: "engineering", role: "dense-role-100", sourceVersion: 7, source: true, retained: true},
		{name: "missing-requested-role", group: "dense-5000", team: "engineering", role: "missing-role", sourceVersion: 7, source: true, retained: true},
		{name: "absent-target-team", group: "dense-5000", team: "missing-team", role: "reader", forbidden: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope := organizationpg.DirectoryTeamGrantScope{TenantID: tenant, OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: organization.ID(tc.group), TeamID: organization.ID(tc.team), UserID: "member"}
			membership, membershipErr := repo.ObserveDirectoryTeamMembership(f.ctx, scope)
			if !tc.forbidden && (membershipErr != nil || membership.Local || membership.Source != tc.source || membership.Version != tc.sourceVersion) {
				t.Fatalf("native membership control = %+v, %v", membership, membershipErr)
			}
			want := organizationpg.DirectoryTeamRoleAttribution{Membership: membership, CurrentBindingVersion: tc.binding, CurrentRoleVersion: tc.roleVersion}
			if tc.retained {
				want.Retained = organizationpg.DirectoryTeamRoleSource{Scope: scope, MemberResourceID: organization.ID("retained-member-" + strings.TrimPrefix(tc.group, "dense-")), RoleID: "reader", ProviderVersion: 11, MappingVersion: 13, ConnectionVersion: 17}
				want.RetainedGrantVersion, want.RetainedBindingVersion = 7, 1
			}
			for _, name := range []string{"membership", "binding", "attribution"} {
				args := []any{tenant, org, "provider", "connection", tc.group, tc.team, "member"}
				if name == "binding" {
					args = []any{tenant, org, tc.team, tc.role}
				} else if name == "attribution" {
					args = append(args, tc.role)
				}
				for i, arg := range args {
					if _, ok := arg.(string); !ok {
						t.Fatalf("%s binding %d has nonnative type %T", name, i+1, arg)
					}
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
				if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+queries[name], args...).Scan(&wire); err != nil {
					t.Fatal("explain actual typed query", name, err)
				}
				var report []struct {
					Plan directoryMembershipPlan
					MS   float64 `json:"Execution Time"`
				}
				var indexReport []struct {
					Plan directoryTeamRoleAttributionIndexPlan
				}
				if err := json.Unmarshal(wire, &report); err != nil || len(report) != 1 {
					t.Fatal("decode actual query plan", name, err)
				}
				if err := json.Unmarshal(wire, &indexReport); err != nil || len(indexReport) != 1 {
					t.Fatal("decode actual index conditions", name, err)
				}
				plan := report[0].Plan
				if plan.examined() > 512 || plan.Hits+plan.Reads > 512 {
					t.Fatalf("%s traversed unrelated retained history: %s", name, wire)
				}
				if !tc.forbidden && name != "binding" {
					keys := []string{"tenant_id", "organization_id", "provider_id", "connection_id", "group_id", "team_id", "user_id"}
					if !indexReport[0].Plan.exactIndex("directory_team_grants_pkey", keys) {
						t.Fatalf("%s lost exact selected membership index conditions: %s", name, wire)
					}
					if name == "attribution" && tc.sourceVersion != 0 && !indexReport[0].Plan.exactIndex("directory_team_role_grants_pkey", keys) {
						t.Fatalf("attribution lost exact retained role index conditions: %s", wire)
					}
				}
				if tc.binding != 0 && name != "membership" {
					keys := []string{"tenant_id", "organization_id", "team_id", "role_id"}
					primary := indexReport[0].Plan.exactIndex("team_role_bindings_pkey", keys)
					effective := indexReport[0].Plan.exactIndex("organization_team_role_effective", keys)
					if !primary && !effective {
						t.Fatalf("%s lost exact native binding index conditions: %s", name, wire)
					}
				}
				var wantNative [][]any
				if !tc.forbidden && (name != "binding" || tc.binding != 0) {
					if name == "binding" {
						wantNative = [][]any{{strconv.FormatUint(tc.binding, 10)}}
					} else {
						wantNative = [][]any{{membership.Local, membership.Source,
							strconv.FormatUint(membership.Version, 10), strconv.FormatUint(membership.OrganizationVersion, 10),
							strconv.FormatUint(membership.CredentialVersion, 10), strconv.FormatUint(membership.MemberVersion, 10),
							strconv.FormatUint(membership.MemberAuthorizationVersion, 10), strconv.FormatUint(membership.TeamVersion, 10),
							strconv.FormatUint(membership.UserVersion, 10)}}
						if name == "attribution" {
							wantNative[0] = append(wantNative[0], strconv.FormatUint(tc.binding, 10), strconv.FormatUint(tc.roleVersion, 10), tc.retained)
							if tc.retained {
								wantNative[0] = append(wantNative[0], string(want.Retained.MemberResourceID), "reader", "7", "1", "11", "13", "17")
							} else {
								wantNative[0] = append(wantNative[0], "", "", "", "", "", "", "")
							}
						}
					}
				}
				samples := make([]time.Duration, 7)
				var returned [][]any
				for i := range samples {
					started := time.Now()
					rows, err := tx.Query(f.ctx, queries[name], args...)
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
					if rows.Err() != nil || !reflect.DeepEqual(got, wantNative) {
						t.Fatalf("%s native result = %v, %v; want %v", name, got, rows.Err(), wantNative)
					}
					returned = got
				}
				if err := tx.Rollback(f.ctx); err != nil {
					t.Fatal(err)
				}
				slices.Sort(samples)
				t.Logf("%s bindings=%v; rows=%v; returned=%d examined=%.0f shared-buffers=%d server=%.3fms; seven warm serial native samples p50=%s max=%s exclude acquisition/begin/rollback; plan=%s", name, args, returned, len(returned), plan.examined(), plan.Hits+plan.Reads, report[0].MS, samples[3], samples[6], wire)
			}
			samples := make([]time.Duration, 7)
			for i := range samples {
				started := time.Now()
				got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, scope, organization.ID(tc.role))
				samples[i] = time.Since(started)
				if tc.forbidden {
					if !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryTeamRoleAttribution{}) || !errors.Is(membershipErr, organization.ErrForbidden) {
						t.Fatalf("absent target leaked attribution: %+v, %v", got, err)
					}
				} else if err != nil || got != want {
					t.Fatalf("owning API attribution = %+v, %v; want %+v", got, err, want)
				}
			}
			slices.Sort(samples)
			t.Logf("seven warm serial owning attribution API samples include pooled acquisition/decoding, one primary statement per call: p50=%s max=%s; partial reads are not semantically equivalent predecessors; no production contention or external source-authority cost modeled", samples[3], samples[6])
		})
	}
}
