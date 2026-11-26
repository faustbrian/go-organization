//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryTeamRoleAttributionRepository(t *testing.T, f *orgFixture) *organizationpg.Repository {
	t.Helper()
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func directoryTeamRoleAttributionSource() organizationpg.DirectoryTeamRoleSource {
	return organizationpg.DirectoryTeamRoleSource{
		Scope:            organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: "member", TeamID: "engineering", ProviderID: "provider", ConnectionID: "connection", GroupID: "group-a"},
		MemberResourceID: "retained-member-resource", RoleID: "reader", ProviderVersion: 11, MappingVersion: 13, ConnectionVersion: 17,
	}
}

func seedDirectoryTeamAttributionMembership(t *testing.T, f *orgFixture, s organizationpg.DirectoryTeamGrantScope) {
	t.Helper()
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_team_grants
 (tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
 VALUES($1,$2,$3,$4,$5,$6,$7,7,1,true)`, string(s.TenantID), string(s.OrganizationID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID), string(s.UserID)); err != nil {
		t.Fatal("seed exact directory team grant", err)
	}
}

func seedDirectoryTeamRoleAttribution(t *testing.T, f *orgFixture, source organizationpg.DirectoryTeamRoleSource, bindingVersion uint64) {
	t.Helper()
	s := source.Scope
	seedDirectoryTeamAttributionMembership(t, f, s)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_team_role_grants
 (tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id,member_resource_id,role_id,grant_version,binding_version,provider_version,mapping_version,connection_version)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,7,$10::numeric,$11::numeric,$12::numeric,$13::numeric)`, string(s.TenantID), string(s.OrganizationID), string(s.UserID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID), string(source.MemberResourceID), string(source.RoleID), bindingVersion, source.ProviderVersion, source.MappingVersion, source.ConnectionVersion); err != nil {
		t.Fatal("seed retained role source", err)
	}
}

func directoryTeamRoleAttributionSnapshot(t *testing.T, f *orgFixture) string {
	t.Helper()
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'organizations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY tenant_id,organization_id) FROM organization.organizations o),
 'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY tenant_id,organization_id,user_id) FROM organization.memberships m),
 'teams',(SELECT jsonb_agg(to_jsonb(t) ORDER BY tenant_id,organization_id,team_id) FROM organization.teams t),
 'team-identities',(SELECT jsonb_agg(to_jsonb(i) ORDER BY tenant_id,organization_id,team_id) FROM organization.team_identities i),
 'local',(SELECT jsonb_agg(to_jsonb(l) ORDER BY tenant_id,organization_id,team_id,user_id) FROM organization.team_memberships l),
 'sources',(SELECT jsonb_agg(to_jsonb(g) ORDER BY tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id) FROM organization.directory_team_grants g),
 'retained',(SELECT jsonb_agg(to_jsonb(d) ORDER BY tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id) FROM organization.directory_team_role_grants d),
 'roles',(SELECT jsonb_agg(to_jsonb(r) ORDER BY tenant_id,organization_id,role_id) FROM organization.custom_roles r),
 'bindings',(SELECT jsonb_agg(to_jsonb(b) ORDER BY tenant_id,organization_id,team_id,role_id) FROM organization.team_role_bindings b),
 'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY tenant_id,user_id) FROM identity.users u),
 'effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM organization.command_effects e))::text`).Scan(&state); err != nil {
		t.Fatal("snapshot role attribution state", err)
	}
	return state
}

func TestObserveDirectoryTeamRoleAttributionRetainsExactSourceAcrossReplacementAndStaleness(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	repo := directoryTeamRoleAttributionRepository(t, f)
	source := directoryTeamRoleAttributionSource()
	seedDirectoryTeamRoleAttribution(t, f, source, view.TeamRoleBinding.Version)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.custom_roles(tenant_id,organization_id,role_id,name,version,state,statements)
	 VALUES('org-test-basic',$1,'other-reader','Other role',23,'active','[]'),
	 ('org-test-basic',$1,'unbound-reader','Unbound role',41,'active','[]')`, string(metadataOrganization)); err != nil {
		t.Fatal("seed independently requested role", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.team_role_bindings(tenant_id,organization_id,team_id,role_id,version,state)
 VALUES('org-test-basic',$1,'engineering','other-reader',29,'active')`, string(metadataOrganization)); err != nil {
		t.Fatal("seed independent binding", err)
	}
	exec := func(t *testing.T, query string) {
		t.Helper()
		if _, err := f.pool.Raw().Exec(f.ctx, query, string(metadataOrganization)); err != nil {
			t.Fatal("change isolated attribution fixture", err)
		}
	}
	for _, tc := range []struct {
		name, query, restore string
		requestedRole        organization.ID
		bindingVersion       uint64
		roleVersion          uint64
		retainedRole         organization.ID
		membershipVersion    uint64
		membershipSource     bool
	}{
		{name: "current-exact-retained-source", requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "newer-selected-grant-does-not-erase-retained-metadata", query: `UPDATE organization.directory_team_grants SET version=8 WHERE organization_id=$1`, restore: `UPDATE organization.directory_team_grants SET version=7 WHERE organization_id=$1`, requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 8, membershipSource: true},
		{name: "inactive-selected-grant-keeps-retained-record", query: `UPDATE organization.directory_team_grants SET active=false WHERE organization_id=$1`, restore: `UPDATE organization.directory_team_grants SET active=true WHERE organization_id=$1`, requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 7},
		{name: "old-member-epoch-keeps-retained-record", query: `UPDATE organization.directory_team_grants SET organization_member_version=2 WHERE organization_id=$1`, restore: `UPDATE organization.directory_team_grants SET organization_member_version=1 WHERE organization_id=$1`, requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 7},
		{name: "replaced-native-binding-keeps-original-retained-version", query: `UPDATE organization.team_role_bindings SET version=31 WHERE organization_id=$1 AND role_id='reader'`, restore: `UPDATE organization.team_role_bindings SET version=1 WHERE organization_id=$1 AND role_id='reader'`, requestedRole: "reader", bindingVersion: 31, roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "removed-binding-keeps-active-role-and-retained-record", query: `UPDATE organization.team_role_bindings SET state='removed' WHERE organization_id=$1 AND role_id='reader'`, restore: `UPDATE organization.team_role_bindings SET state='active' WHERE organization_id=$1 AND role_id='reader'`, requestedRole: "reader", roleVersion: view.DynamicRole.Version, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "deleted-requested-role-keeps-retained-record", query: `UPDATE organization.custom_roles SET state='deleted' WHERE organization_id=$1 AND role_id='reader'`, restore: `UPDATE organization.custom_roles SET state='active' WHERE organization_id=$1 AND role_id='reader'`, requestedRole: "reader", retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "updated-role-version-is-current-not-retained", query: `UPDATE organization.custom_roles SET version=37 WHERE organization_id=$1 AND role_id='reader'`, restore: `UPDATE organization.custom_roles SET version=1 WHERE organization_id=$1 AND role_id='reader'`, requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: 37, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "requested-role-differs-from-retained-role", requestedRole: "other-reader", bindingVersion: 29, roleVersion: 23, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "active-requested-role-without-binding-keeps-role-version", requestedRole: "unbound-reader", roleVersion: 41, retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "missing-requested-role-does-not-erase-retained-record", requestedRole: "missing-role", retainedRole: "reader", membershipVersion: 7, membershipSource: true},
		{name: "retained-role-differs-from-requested-role", query: `UPDATE organization.directory_team_role_grants SET role_id='other-reader' WHERE organization_id=$1`, restore: `UPDATE organization.directory_team_role_grants SET role_id='reader' WHERE organization_id=$1`, requestedRole: "reader", bindingVersion: view.TeamRoleBinding.Version, roleVersion: view.DynamicRole.Version, retainedRole: "other-reader", membershipVersion: 7, membershipSource: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.query != "" {
				exec(t, tc.query)
				defer exec(t, tc.restore)
			}
			before := directoryTeamRoleAttributionSnapshot(t, f)
			membership, err := repo.ObserveDirectoryTeamMembership(f.ctx, source.Scope)
			if err != nil || membership.Local || membership.Source != tc.membershipSource || membership.Version != tc.membershipVersion {
				t.Fatalf("invalid native membership control: %+v, %v", membership, err)
			}
			got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, source.Scope, tc.requestedRole)
			retained := source
			retained.RoleID = tc.retainedRole
			want := organizationpg.DirectoryTeamRoleAttribution{Membership: membership, CurrentBindingVersion: tc.bindingVersion, CurrentRoleVersion: tc.roleVersion, Retained: retained, RetainedGrantVersion: 7, RetainedBindingVersion: view.TeamRoleBinding.Version}
			if err != nil || got != want {
				t.Fatalf("attribution lost current target or exact retained metadata: got %+v, %v; want %+v", got, err, want)
			}
			if after := directoryTeamRoleAttributionSnapshot(t, f); after != before {
				t.Fatal("role attribution changed persisted state")
			}
		})
	}
}

func TestObserveDirectoryTeamRoleAttributionDoesNotSubstituteLocalOrOtherSource(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	repo := directoryTeamRoleAttributionRepository(t, f)
	source := directoryTeamRoleAttributionSource()
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.team_memberships(tenant_id,organization_id,team_id,user_id,state,version,organization_member_version)
 VALUES('org-test-basic',$1,'engineering','member','active',3,1)`, string(metadataOrganization)); err != nil {
		t.Fatal("seed independent local membership", err)
	}
	otherGroup, otherProvider, otherConnection := source, source, source
	otherGroup.Scope.GroupID, otherGroup.MemberResourceID = "other-group", "other-group-member"
	otherProvider.Scope.ProviderID, otherProvider.MemberResourceID = "other-provider", "other-provider-member"
	otherConnection.Scope.ConnectionID, otherConnection.MemberResourceID = "other-connection", "other-connection-member"
	others := []organizationpg.DirectoryTeamRoleSource{otherGroup, otherProvider, otherConnection}
	selections := []organizationpg.DirectoryTeamGrantScope{source.Scope}
	for _, other := range others {
		seedDirectoryTeamRoleAttribution(t, f, other, view.TeamRoleBinding.Version)
		selections = append(selections, other.Scope)
	}
	for _, selected := range selections {
		before := directoryTeamRoleAttributionSnapshot(t, f)
		membership, err := repo.ObserveDirectoryTeamMembership(f.ctx, selected)
		if err != nil || !membership.Local || membership.Source != (selected != source.Scope) {
			t.Fatalf("independent local/source control failed: %+v, %v", membership, err)
		}
		got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, selected, "reader")
		want := organizationpg.DirectoryTeamRoleAttribution{Membership: membership, CurrentBindingVersion: view.TeamRoleBinding.Version, CurrentRoleVersion: view.DynamicRole.Version}
		for _, other := range others {
			if selected == other.Scope {
				want.Retained, want.RetainedGrantVersion, want.RetainedBindingVersion = other, 7, view.TeamRoleBinding.Version
			}
		}
		if err != nil || got != want {
			t.Fatalf("local or another source substituted selected role origin: %+v, %v; want %+v", got, err, want)
		}
		if after := directoryTeamRoleAttributionSnapshot(t, f); after != before {
			t.Fatal("independent-source observation changed persisted state")
		}
	}
	ownerScope := source.Scope
	ownerScope.UserID = "owner"
	ownerMembership, err := repo.ObserveDirectoryTeamMembership(f.ctx, ownerScope)
	if err != nil {
		t.Fatal("read independent owner membership", err)
	}
	owner, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, ownerScope, "reader")
	ownerWant := organizationpg.DirectoryTeamRoleAttribution{Membership: ownerMembership, CurrentBindingVersion: view.TeamRoleBinding.Version, CurrentRoleVersion: view.DynamicRole.Version}
	if err != nil || owner != ownerWant {
		t.Fatalf("another member's selected source leaked to the owner: %+v, %v; want %+v", owner, err, ownerWant)
	}
	seedDirectoryTeamAttributionMembership(t, f, source.Scope)
	got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, source.Scope, "reader")
	if err != nil || !got.Membership.Source || got.Membership.Version != 7 || got.Retained != (organizationpg.DirectoryTeamRoleSource{}) || got.RetainedGrantVersion != 0 || got.RetainedBindingVersion != 0 {
		t.Fatalf("membership-only selected grant became a retained role source: %+v, %v", got, err)
	}
}

func TestObserveDirectoryTeamRoleAttributionDeniesForeignOrInactiveTargets(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	repo := directoryTeamRoleAttributionRepository(t, f)
	source := directoryTeamRoleAttributionSource()
	seedDirectoryTeamRoleAttribution(t, f, source, view.TeamRoleBinding.Version)
	for _, tc := range []struct {
		name string
		edit func(*organizationpg.DirectoryTeamGrantScope)
	}{
		{"foreign-tenant", func(s *organizationpg.DirectoryTeamGrantScope) { s.TenantID = "org-test-scope" }},
		{"missing-organization", func(s *organizationpg.DirectoryTeamGrantScope) { s.OrganizationID = "other-organization" }},
		{"missing-member", func(s *organizationpg.DirectoryTeamGrantScope) { s.UserID = "outsider" }},
		{"missing-user", func(s *organizationpg.DirectoryTeamGrantScope) { s.UserID = "missing-user" }},
		{"missing-team", func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "missing-team" }},
		{"case-sensitive-team", func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "Engineering" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := source.Scope
			tc.edit(&selected)
			before := directoryTeamRoleAttributionSnapshot(t, f)
			if got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, selected, "reader"); !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryTeamRoleAttribution{}) {
				t.Fatalf("foreign target disclosed role attribution: %+v, %v", got, err)
			}
			if after := directoryTeamRoleAttributionSnapshot(t, f); after != before {
				t.Fatal("foreign target observation changed persisted state")
			}
		})
	}
	for _, tc := range []struct{ name, query, restore string }{
		{"archived-organization", `UPDATE organization.organizations SET state='archived' WHERE organization_id=$1`, `UPDATE organization.organizations SET state='active' WHERE organization_id=$1`},
		{"removed-member", `UPDATE organization.memberships SET state='removed' WHERE organization_id=$1 AND user_id='member'`, `UPDATE organization.memberships SET state='active' WHERE organization_id=$1 AND user_id='member'`},
		{"suspended-user", `UPDATE identity.users SET status='suspended' WHERE tenant_id=(SELECT tenant_id FROM organization.organizations WHERE organization_id=$1) AND user_id='member'`, `UPDATE identity.users SET status='active' WHERE tenant_id=(SELECT tenant_id FROM organization.organizations WHERE organization_id=$1) AND user_id='member'`},
		{"deleted-team", `UPDATE organization.team_identities SET deleted_version=2 WHERE organization_id=$1 AND team_id='engineering'`, `UPDATE organization.team_identities SET deleted_version=NULL WHERE organization_id=$1 AND team_id='engineering'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.pool.Raw().Exec(f.ctx, tc.query, string(metadataOrganization)); err != nil {
				t.Fatal("seed inactive target", err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(f.ctx, tc.restore, string(metadataOrganization)); err != nil {
					t.Fatal("restore isolated target", err)
				}
			}()
			before := directoryTeamRoleAttributionSnapshot(t, f)
			if got, err := repo.ObserveDirectoryTeamRoleAttribution(f.ctx, source.Scope, "reader"); !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryTeamRoleAttribution{}) {
				t.Fatalf("inactive target disclosed role attribution: %+v, %v", got, err)
			}
			if after := directoryTeamRoleAttributionSnapshot(t, f); after != before {
				t.Fatal("inactive target observation changed persisted state")
			}
		})
	}
}

func TestObserveDirectoryTeamRoleAttributionRejectsInvalidAndCanceledReads(t *testing.T) {
	f, _ := directoryTeamRolePermissionFixture(t)
	repo := directoryTeamRoleAttributionRepository(t, f)
	source := directoryTeamRoleAttributionSource()
	for _, tc := range []struct {
		name  string
		repo  *organizationpg.Repository
		ctx   context.Context
		scope organizationpg.DirectoryTeamGrantScope
		role  organization.ID
	}{
		{"nil-repository", nil, f.ctx, source.Scope, "reader"},
		{"unconfigured-repository", &organizationpg.Repository{}, f.ctx, source.Scope, "reader"},
		{"nil-context", repo, nil, source.Scope, "reader"},
		{"empty-scope", repo, f.ctx, organizationpg.DirectoryTeamGrantScope{}, "reader"},
		{"empty-role", repo, f.ctx, source.Scope, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.repo.ObserveDirectoryTeamRoleAttribution(tc.ctx, tc.scope, tc.role); !errors.Is(err, organization.ErrInvalidInput) || got != (organizationpg.DirectoryTeamRoleAttribution{}) {
				t.Fatalf("invalid read disclosed role attribution: %+v, %v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := repo.ObserveDirectoryTeamRoleAttribution(ctx, source.Scope, "reader"); !errors.Is(err, context.Canceled) || got != (organizationpg.DirectoryTeamRoleAttribution{}) {
		t.Fatalf("canceled read disclosed role attribution: %+v, %v", got, err)
	}
}
