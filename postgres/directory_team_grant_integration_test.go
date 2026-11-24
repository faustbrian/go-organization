//go:build integration

package postgres_test

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestDirectoryTeamMembershipObservesIndependentSourceAndLocalGrants(t *testing.T) {
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303}, organizationpg.TeamLifecycleMigrationSource{Version: 304}, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryTeamGrantMigrationSource{Version: 306})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 10, LifecycleVersion: 1}
	f.compose(t)
	const tenant = "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := organizationpg.DirectoryTeamGrantScope{TenantID: tenant, OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a", TeamID: "engineering", UserID: "member"}
	observe := func(selected organizationpg.DirectoryTeamGrantScope, local, source bool, version uint64) {
		t.Helper()
		got, err := repository.ObserveDirectoryTeamMembership(f.ctx, selected)
		if err != nil || got.Local != local || got.Source != source || got.Version != version {
			t.Fatalf("exact source observation: %+v, %v", got, err)
		}
	}
	observe(scope, false, false, 0)
	seed := func(group string) {
		t.Helper()
		_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_team_grants(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active) VALUES($1,$2,'provider','connection',$3,'engineering','member',1,1,true)`, tenant, string(metadataOrganization), group)
		if err != nil {
			t.Fatal(err)
		}
	}
	seed("group-a")
	seed("group-b")
	observe(scope, false, true, 1)
	other := scope
	other.GroupID = "group-b"
	observe(other, false, true, 1)
	// A source-only grant is deliberately excluded from the normal team API.
	view, err := f.service.ListMyTeams(f.ctx, organization.TeamReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, Limit: 10, CorrelationID: "source-is-not-role-authority"})
	if err != nil || len(view.Teams) != 0 {
		t.Fatal("source grant entered local permission-bearing team reads", err)
	}
	request := teamAddRequest(t, f, tenant, 3)
	p, err := f.service.PrepareAddTeamMember(f.ctx, request, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	observe(scope, true, true, 1)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.directory_team_grants SET active=false,version=2 WHERE group_id='group-a'`); err != nil {
		t.Fatal(err)
	}
	observe(scope, true, false, 2)
	observe(other, true, true, 1)
	// Local withdrawal does not remove an independent source grant.
	request.CommandID, request.OrganizationVersion, request.TeamVersion, request.MembershipVersion = commandID(t), 4, 2, 1
	p, err = f.service.PrepareRemoveTeamMember(f.ctx, request, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	observe(other, false, true, 1)
	// Removing and re-entering the organization cannot revive an old source.
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET version=2 WHERE tenant_id=$1 AND organization_id=$2 AND user_id='member'`, tenant, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	observe(other, false, false, 1)
	for _, invalid := range []organizationpg.DirectoryTeamGrantScope{
		{TenantID: "org-test-scope", OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a", TeamID: "engineering", UserID: "member"},
		{TenantID: tenant, OrganizationID: metadataOrganization, ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a", TeamID: "missing", UserID: "member"},
	} {
		if got, err := repository.ObserveDirectoryTeamMembership(f.ctx, invalid); err == nil || got.Version != 0 {
			t.Fatal("foreign or missing target disclosed state", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status=$1 WHERE tenant_id=$2 AND user_id='member'`, string(identity.StatusSuspended), tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ObserveDirectoryTeamMembership(f.ctx, other); err == nil {
		t.Fatal("inactive identity remained an observable member")
	}
}
