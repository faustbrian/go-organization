//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestProviderRolePermissionPostgres(t *testing.T) {
	f := dynamicRoleFixture(t)
	const tenant = "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	commitRole(t, f, prepareRole(t, f, 2), nil)
	writer := dynamicRoleRequest(t, f, 3)
	writer.RoleID, writer.Name = "writer", "Writer"
	writer.Statements[0].PermissionID = "document-write"
	p, err := f.service.PrepareCreateDynamicRole(f.ctx, writer, "127.0.0.1")
	commitRole(t, f, p, err)
	p, err = f.service.PrepareAssignDynamicRole(f.ctx, roleBindingRequest(t, f, 4), "127.0.0.1")
	commitRole(t, f, p, err)

	repo, err := organizationpg.NewRepositoryWithProviderRoleGrants(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := organization.NewService(f.sessions, repo, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	check := organization.PermissionCheckRequest{
		Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, OrganizationVersion: 5,
		Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "provider-role-permission",
	}
	assertPermission := func(service interface {
		CheckPermission(ctx context.Context, request organization.PermissionCheckRequest) (authorization.Decision, error)
	}, action authorization.Action, want authorization.Outcome) {
		t.Helper()
		request := check
		request.Action = action
		decision, err := service.CheckPermission(f.ctx, request)
		if err != nil || decision.Outcome != want {
			t.Fatalf("%s: decision %v, want %v, err=%v", action, decision.Outcome, want, err)
		}
	}
	assertPermission(f.service, "document.read", authorization.Allow)
	if decision, err := selected.CheckPermission(f.ctx, check); !errors.Is(err, organization.ErrUnavailable) || decision.Outcome == authorization.Allow {
		t.Fatalf("selected permission fell back when its required schema was missing: %+v, %v", decision, err)
	}
	installProviderRoleGrantSchema(t, f)
	assertPermission(selected, "document.read", authorization.Allow)
	assertPermission(selected, "document.write", authorization.Deny)

	// Seed only provider-owned state; the administrator grant above used the
	// genuine organization workflow. The SSO writer is a separate participant.
	seedProviderRoleGrant(t, f, "provider-a", []string{"reader", "writer"})
	seedProviderRoleGrant(t, f, "provider-b", []string{"writer"})
	assertPermission(selected, "document.read", authorization.Allow)
	assertPermission(selected, "document.write", authorization.Allow)
	assertPermission(f.service, "document.write", authorization.Deny) // opt-in only

	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.provider_role_grants SET role_ids='{}' WHERE tenant_id=$1 AND organization_id=$2 AND provider_id='provider-a'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.read", authorization.Allow)  // admin-owned reader
	assertPermission(selected, "document.write", authorization.Allow) // independently provider-b owned

	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.provider_role_sources SET generation=2,active=false WHERE tenant_id=$1 AND organization_id=$2 AND provider_id='provider-b'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.write", authorization.Deny)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.provider_role_sources SET active=true WHERE tenant_id=$1 AND organization_id=$2 AND provider_id='provider-b'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.write", authorization.Deny) // re-enabled at a new generation
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.provider_role_grants SET provider_generation=2,mapping_version=1 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id='provider-b'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.write", authorization.Deny) // no old mapping authority
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.provider_role_grants SET mapping_version=2,organization_member_version=2 WHERE tenant_id=$1 AND organization_id=$2 AND provider_id='provider-b'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.write", authorization.Deny) // exact live membership epoch required
	assertPermission(selected, "document.read", authorization.Allow)

	const addSources = `WITH inserted AS (
 INSERT INTO organization.provider_role_sources(tenant_id,organization_id,provider_id,generation,mapping_version,active)
 SELECT $1,$2,'stale-'||i,1,2,false FROM generate_series($3::int,$4::int) i RETURNING provider_id
)
INSERT INTO organization.provider_role_grants(tenant_id,organization_id,user_id,provider_id,provider_generation,mapping_version,organization_member_version,flow_started_at,assertion_issued_at,role_ids)
SELECT $1,$2,'member',provider_id,1,2,1,now(),now(),'{}' FROM inserted`

	if _, err := f.pool.Raw().Exec(f.ctx, addSources, tenant, string(metadataOrganization), 1, 126); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.read", authorization.Allow) // exactly 128 bounded source rows
	if _, err := f.pool.Raw().Exec(f.ctx, addSources, tenant, string(metadataOrganization), 127, 127); err != nil {
		t.Fatal(err)
	}
	assertPermission(selected, "document.read", authorization.Deny) // no partial authority after overflow
	assertPermission(f.service, "document.read", authorization.Allow)
}

func TestProviderRolePermissionComposesTeamRoles(t *testing.T) {
	f, read := unboundTeamRoleScope(t)
	p, err := f.service.PrepareAssignTeamDynamicRole(f.ctx, teamRoleRequest(t, read, teamRoleSnapshot(t, f, read)), "127.0.0.1")
	commitRole(t, f, p, err)
	denier := dynamicRoleRequest(t, f, teamRoleSnapshot(t, f, read).Organization.Version)
	denier.RoleID, denier.Name = "denier", "Provider deny"
	denier.Statements[0].Effect = authorization.Deny
	p, err = f.service.PrepareCreateDynamicRole(f.ctx, denier, "127.0.0.1")
	commitRole(t, f, p, err)
	installProviderRoleGrantSchema(t, f)
	repo, err := organizationpg.NewRepositoryWithProviderRoleGrants(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	selected, err := organization.NewService(f.sessions, repo, fixturePolicy{}, f.configuration.Core)
	if err != nil {
		t.Fatal(err)
	}
	check := organization.PermissionCheckRequest{
		Authentication: f.auth("org-test-basic", "member"), OrganizationID: metadataOrganization,
		OrganizationVersion: teamRoleSnapshot(t, f, read).Organization.Version, Action: "document.read", ResourceType: "document",
		ResourceID: "one", CorrelationID: "provider-grant-with-team",
	}
	if decision, err := selected.CheckPermission(f.ctx, check); err != nil || decision.Outcome != authorization.Allow {
		t.Fatalf("provider selection displaced the separate team grant: %+v, %v", decision, err)
	}
	seedProviderRoleGrant(t, f, "provider-with-deny", []string{"denier"})
	if decision, err := selected.CheckPermission(f.ctx, check); err != nil || decision.Outcome != authorization.Deny {
		t.Fatalf("provider deny did not constrain the independent team allow: %+v, %v", decision, err)
	}
	if decision, err := f.service.CheckPermission(f.ctx, check); err != nil || decision.Outcome != authorization.Allow {
		t.Fatalf("unselected readers were affected by provider roles: %+v, %v", decision, err)
	}
}

func seedProviderRoleGrant(t *testing.T, f *orgFixture, provider string, roles []string) {
	t.Helper()
	const tenant = "org-test-basic"
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.provider_role_sources(tenant_id,organization_id,provider_id,generation,mapping_version,active) VALUES($1,$2,$3,1,2,true)`, tenant, string(metadataOrganization), provider); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.provider_role_grants(tenant_id,organization_id,user_id,provider_id,provider_generation,mapping_version,organization_member_version,flow_started_at,assertion_issued_at,role_ids) VALUES($1,$2,'member',$3,1,2,1,$4,$4,$5)`, tenant, string(metadataOrganization), provider, time.Unix(120, 0).UTC(), roles); err != nil {
		t.Fatal(err)
	}
}

func installProviderRoleGrantSchema(t *testing.T, fixture *orgFixture) {
	t.Helper()
	additional, err := (organizationpg.ProviderRoleGrantMigrationSource{Version: 12001}).Load(fixture.ctx)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(fixture.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = fixture.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(append(append(migrationList(nil), fixture.history...), additional...), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(fixture.ctx); err != nil {
		t.Fatal("populated grant schema migration", err)
	}
	if _, err = runner.Up(fixture.ctx); err != nil {
		t.Fatal("grant schema migration replay", err)
	}
}
