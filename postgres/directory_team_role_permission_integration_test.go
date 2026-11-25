//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryTeamRolePermissionFixture(t *testing.T) (*orgFixture, organization.View) {
	t.Helper()
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303}, organizationpg.TeamLifecycleMigrationSource{Version: 304},
		organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306},
		organizationpg.CredentialAuthorityMigrationSource{Version: 307}, organizationpg.DirectoryTeamGrantMigrationSource{Version: 308},
		organizationpg.DirectoryTeamRoleMigrationSource{Version: 309}, organizationpg.ProviderRoleGrantMigrationSource{Version: 310})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}
	f.dynamicRoles = customRoleConfig()
	f.dynamicRoles.TeamBindingsVersion = 1
	f.compose(t)
	const tenant = "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	commitRole(t, f, prepareRole(t, f, 3), nil)
	q := organization.DynamicRoleReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, RoleID: "reader", TargetTeamID: "engineering", CorrelationID: "directory-role"}
	view := teamRoleSnapshot(t, f, q)
	p, err := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, q, view), "127.0.0.1")
	commitRole(t, f, p, err)
	return f, teamRoleSnapshot(t, f, q)
}

func TestDirectoryTeamRoleReadRequiresExplicitCurrentSource(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	const tenant = "org-test-basic"
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	want := organizationpg.DirectoryTeamRoleSource{
		Scope:            organizationpg.DirectoryTeamGrantScope{TenantID: tenant, OrganizationID: metadataOrganization, UserID: "member", TeamID: "engineering", ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a"},
		MemberResourceID: "source-member", RoleID: "reader", ProviderVersion: 2, MappingVersion: 3, ConnectionVersion: 4,
	}
	current, unavailable, called := true, false, 0
	authority := func(_ context.Context, got []organizationpg.DirectoryTeamRoleSource) ([]bool, error) {
		called++
		if len(got) != 1 || got[0] != want {
			t.Fatal("source check crossed scope or lost authority versions")
		}
		if unavailable {
			return nil, organization.ErrUnavailable
		}
		return []bool{current}, nil
	}
	enabled, err := repo.WithDirectoryTeamRoles(authority)
	if err != nil {
		t.Fatal(err)
	}
	permission := organization.Query{Operation: organization.CheckPermission, TenantID: tenant, ActorID: "member", OrganizationID: metadataOrganization, Limit: 10, IncludeTeamRoles: true}
	read := func(reader *organizationpg.Repository, allows bool) {
		t.Helper()
		out, err := reader.Read(f.ctx, permission)
		if err != nil {
			t.Fatal("read persisted permission roles", err)
		}
		if (len(out.DynamicRoles) == 1 && out.DynamicRoles[0].ID == "reader") != allows || !allows && len(out.DynamicRoles) != 0 {
			t.Fatal("wrong effective permission role set")
		}
	}
	// At this read boundary fixtures isolate source-row eligibility from the
	// coordinator writer. The native team role and member above are real.
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 VALUES($1,$2,'provider','connection','group-a','engineering','member',1,1,true)`, tenant, string(metadataOrganization))
	if err != nil {
		t.Fatal(err)
	}
	read(enabled, false)
	if called != 0 {
		t.Fatal("legacy membership-only grant was treated as a role source")
	}
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 VALUES($1,$2,'member','provider','connection','group-a','engineering','source-member','reader',1,$3::numeric,2,3,4)`, tenant, string(metadataOrganization), view.TeamRoleBinding.Version)
	if err != nil {
		t.Fatal(err)
	}
	read(repo, false)
	read(enabled, true)
	federated, err := organizationpg.NewRepositoryWithProviderRoleGrants(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	combined, err := federated.WithDirectoryTeamRoles(authority)
	if err != nil {
		t.Fatal(err)
	}
	read(combined, true)
	current = false
	read(enabled, false)
	read(combined, false)
	unavailable = true
	if roles, err := enabled.Read(f.ctx, permission); err == nil || len(roles.DynamicRoles) != 0 {
		t.Fatal("unknown directory authority produced a usable role view")
	}
	unavailable, current = false, true
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.directory_team_grants SET version=2 WHERE tenant_id=$1 AND organization_id=$2 AND group_id='group-a'`, tenant, string(metadataOrganization))
	if err != nil {
		t.Fatal(err)
	}
	read(enabled, false)
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.directory_team_grants SET version=1 WHERE tenant_id=$1 AND organization_id=$2 AND group_id='group-a'`, tenant, string(metadataOrganization))
	if err != nil {
		t.Fatal(err)
	}
	read(enabled, true)
	binding := organization.DynamicRoleReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, RoleID: "reader", TargetTeamID: "engineering", CorrelationID: "directory-role"}
	p, err := f.service.PrepareRevokeTeamDynamicRole(f.ctx, teamRoleRequest(t, binding, view), "127.0.0.1")
	commitRole(t, f, p, err)
	read(enabled, false)
	fresh := teamRoleSnapshot(t, f, binding)
	p, err = f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, binding, fresh), "127.0.0.1")
	commitRole(t, f, p, err)
	read(enabled, false)
}

func TestDirectoryTeamRoleDenyOverridesIndependentNativeAllow(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	const tenant = "org-test-basic"
	deny := dynamicRoleRequest(t, f, view.Organization.Version)
	deny.RoleVersion = view.DynamicRole.Version
	deny.Statements[0].Effect = authorization.Deny
	p, err := f.service.PrepareUpdateDynamicRole(f.ctx, deny, "127.0.0.1")
	commitRole(t, f, p, err)
	allow := dynamicRoleRequest(t, f, view.Organization.Version+1)
	allow.RoleID, allow.Name = "local-reader", "Local reader"
	p, err = f.service.PrepareCreateDynamicRole(f.ctx, allow, "127.0.0.1")
	commitRole(t, f, p, err)
	local := roleBindingRequest(t, f, view.Organization.Version+2)
	local.RoleID = allow.RoleID
	p, err = f.service.PrepareAssignDynamicRole(f.ctx, local, "127.0.0.1")
	commitRole(t, f, p, err)
	for _, sql := range []string{
		`INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 VALUES($1,$2,'provider','connection','group-a','engineering','member',1,1,true)`,
		`INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 VALUES($1,$2,'member','provider','connection','group-a','engineering','source-member','reader',1,1,2,3,4)`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, tenant, string(metadataOrganization)); err != nil {
			t.Fatal(err)
		}
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := repo.WithDirectoryTeamRoles(func(_ context.Context, got []organizationpg.DirectoryTeamRoleSource) ([]bool, error) {
		if len(got) != 1 || got[0].RoleID != "reader" {
			t.Fatal("missing exact directory deny role")
		}
		return []bool{true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	check := organization.PermissionCheckRequest{
		Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, OrganizationVersion: view.Organization.Version + 3,
		Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "directory-role",
	}
	if got, err := f.service.CheckPermission(f.ctx, check); err != nil || got.Outcome != authorization.Allow {
		t.Fatal("independent local allow missing from negative control", err)
	}
	actual, err := organization.NewService(f.configuration.Sessions, selected, f.configuration.Authorization, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := actual.CheckPermission(f.ctx, check); err != nil || got.Outcome != authorization.Deny {
		t.Fatal("directory deny did not override independent allow", err)
	}
}

func TestDirectoryTeamRoleCandidatePlanBoundsDenseRetainedHistory(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	const tenant = "org-test-basic"
	org := string(metadataOrganization)
	// Another member has dense stale history, including keys that would have
	// been filtered before the result limit if the predicate were misplaced.
	for _, sql := range []string{
		`INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 SELECT $1,$2,'provider','connection','dense-'||i,'engineering','owner',1,1,true FROM generate_series(1,10000) i`,
		`INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 SELECT $1,$2,'owner','provider','connection','dense-'||i,'engineering','source-owner','reader',2,1,2,3,4 FROM generate_series(1,10000) i`,
		`INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 VALUES($1,$2,'provider','connection','exact','engineering','member',1,1,true)`,
		`INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 VALUES($1,$2,'member','provider','connection','exact','engineering','source-member','reader',1,1,2,3,4)`,
		`INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements)
 SELECT $1,$2,'unassigned-'||i,'Unassigned',1,'active','[]' FROM generate_series(1,95) i`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, tenant, org); err != nil {
			t.Fatal("install dense fixture on native schema", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.directory_team_role_grants, organization.directory_team_grants, organization.custom_roles`); err != nil {
		t.Fatal(err)
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	enabled, err := repo.WithDirectoryTeamRoles(func(_ context.Context, sources []organizationpg.DirectoryTeamRoleSource) ([]bool, error) {
		if len(sources) != 1 || sources[0].Scope.GroupID != "exact" {
			t.Fatal("dense unrelated history reached the source callback")
		}
		return []bool{true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	roleQuery := organization.Query{Operation: organization.CheckPermission, TenantID: tenant, OrganizationID: metadataOrganization,
		ActorID: "member", Limit: 10, IncludeTeamRoles: true}
	if received, err := enabled.Read(f.ctx, roleQuery); err != nil || len(received.DynamicRoles) != 1 || received.DynamicRoles[0].ID != "reader" {
		t.Fatal("target permission was lost beside dense unrelated history", err)
	}
	roleQuery.ActorID = "owner"
	if out, err := enabled.Read(f.ctx, roleQuery); !errors.Is(err, organization.ErrForbidden) || len(out.DynamicRoles) != 0 {
		t.Fatal("dense stale own history silently supplied an incomplete policy view", err)
	}
	queries := organizationpg.DirectoryTeamRolePlanSQL()
	point := []any{tenant, org, "member", "provider", "connection", "exact", "engineering"}
	version := strconv.FormatUint(view.Organization.Version, 10)
	for _, tc := range []struct {
		name, query string
		args        []any
	}{
		{"member", "candidates", []any{tenant, org, "member", version, "1", "1", 129}},
		{"owner-overflow", "candidates", []any{tenant, org, "owner", version, "1", "1", 129}},
		{"miss", "candidates", []any{tenant, org, "outsider", version, "1", "1", 129}},
		{"owner-capacity", "capacity", []any{tenant, org, "owner", "provider", "connection", "dense-1", "engineering"}},
		{"selection", "selection", []any{tenant, org, "engineering", "reader"}},
		{"projection-read", "row", point},
		{"org-lock", "lock", []any{tenant, org}},
		{"projection-write", "upsert", append(append([]any(nil), point...), "source-member", "reader", "1", "1", "2", "3", "4")},
		{"projection-withdraw", "delete", point},
		{"policy-advance", "epoch", []any{tenant, org, version, "1"}},
		{"effective-roles", "effective", []any{tenant, org, "", false, "member", 11, []string{"reader"}}},
		{"effective-federated-roles", "federated", []any{tenant, org, "", 11, "member", version, "1", "1", []string{"reader"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := f.pool.Raw().Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			if _, err := tx.Exec(f.ctx, "SET LOCAL statement_timeout='2s'"); err != nil {
				t.Fatal(err)
			}
			var wire []byte
			if err := tx.QueryRow(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+queries[tc.query], tc.args...).Scan(&wire); err != nil {
				t.Fatal(err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			var report []struct {
				Plan directoryMembershipPlan
				MS   float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(wire, &report); err != nil || len(report) != 1 {
				t.Fatal("decode native query plan", err)
			}
			p := report[0].Plan
			t.Logf("directory candidate examined=%.0f buffers=%d db=%.3fms", p.examined(), p.Hits+p.Reads, report[0].MS)
			if p.examined() > 512 || p.Hits+p.Reads > 512 {
				t.Fatalf("directory candidates traversed large retained history: %s", wire)
			}
		})
	}
}
