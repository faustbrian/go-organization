//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryMembershipAttributionFixture(t *testing.T) (*orgFixture, *organizationpg.Repository, organizationpg.DirectoryMembershipSource) {
	t.Helper()
	f := newOrgFixture(t, organizationpg.CredentialAuthorityMigrationSource{Version: 305}, organizationpg.DirectoryMembershipMigrationSource{Version: 306})
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleAdministrator, 1)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET version=7,authorization_version=11 WHERE tenant_id='org-test-basic' AND organization_id=$1 AND user_id='member'`, string(metadataOrganization)); err != nil {
		t.Fatal("seed current member incarnation", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived',version=22 WHERE tenant_id='org-test-basic' AND organization_id=$1`, string(metadataOrganization)); err != nil {
		t.Fatal("seed independent credential epoch", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='active',version=23 WHERE tenant_id='org-test-basic' AND organization_id=$1`, string(metadataOrganization)); err != nil {
		t.Fatal("restore active owner fixture", err)
	}
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	source := organizationpg.DirectoryMembershipSource{TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider", ConnectionID: "connection", ResourceID: "resource"}
	return f, repo, source
}

func directoryMembershipAttributionSnapshot(t *testing.T, f *orgFixture) string {
	t.Helper()
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'organizations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY tenant_id,organization_id) FROM organization.organizations o),
 'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY tenant_id,organization_id,user_id) FROM organization.memberships m),
 'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY tenant_id,organization_id,user_id,member_version,provider_id,connection_id) FROM organization.directory_membership_grants g),
 'effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM organization.command_effects e),
 'users',(SELECT jsonb_agg(to_jsonb(u) ORDER BY tenant_id,user_id) FROM identity.users u))::text`).Scan(&state); err != nil {
		t.Fatal("snapshot attribution-owned state", err)
	}
	return state
}

func TestObserveDirectoryMembershipAttributionReportsOnlyCurrentEffectiveOrigins(t *testing.T) {
	f, repo, source := directoryMembershipAttributionFixture(t)
	type grant struct {
		memberVersion uint64
		provider      string
		connection    string
		resource      string
		version       uint64
		active        bool
	}
	exact := grant{7, "provider", "connection", "resource", 3, true}
	otherProvider := grant{7, "other-provider", "connection", "other-resource", 4, true}
	otherConnection := grant{7, "provider", "other-connection", "other-resource", 5, true}
	retained := grant{6, "provider", "connection", "retained-resource", 6, true}
	future := grant{8, "provider", "connection", "future-resource", 7, true}
	tombstone := exact
	tombstone.active = false
	inactiveOther := otherProvider
	inactiveOther.active = false
	retainedOther := otherProvider
	retainedOther.memberVersion = 6
	futureOther := otherConnection
	futureOther.memberVersion = 8
	caseProvider := otherProvider
	caseProvider.provider = "Provider"
	caseConnection := otherConnection
	caseConnection.connection = "Connection"
	for _, tc := range []struct {
		name                string
		grants              []grant
		removed             bool
		absent              bool
		owner               bool
		local               bool
		other               bool
		contributionActive  bool
		contributionVersion uint64
	}{
		{name: "local-active-member", local: true},
		{name: "selected-active-source", grants: []grant{exact}, contributionActive: true, contributionVersion: 3},
		{name: "distinct-provider-same-connection", grants: []grant{otherProvider}, other: true},
		{name: "same-provider-distinct-connection", grants: []grant{otherConnection}, other: true},
		{name: "case-sensitive-provider-is-distinct", grants: []grant{caseProvider}, other: true},
		{name: "case-sensitive-connection-is-distinct", grants: []grant{caseConnection}, other: true},
		{name: "selected-and-other-active-sources", grants: []grant{exact, otherProvider}, other: true, contributionActive: true, contributionVersion: 3},
		{name: "selected-tombstone-is-not-origin", grants: []grant{tombstone}, local: true, contributionVersion: 3},
		{name: "other-active-source-with-selected-tombstone", grants: []grant{tombstone, otherConnection}, other: true, contributionVersion: 3},
		{name: "inactive-other-source-is-not-origin", grants: []grant{inactiveOther}, local: true},
		{name: "retained-selected-incarnation-is-not-origin-or-conflict", grants: []grant{retained}, local: true},
		{name: "future-selected-incarnation-is-not-origin-or-conflict", grants: []grant{future}, local: true},
		{name: "retained-other-incarnation-is-not-origin", grants: []grant{retainedOther}, local: true},
		{name: "future-other-incarnation-is-not-origin", grants: []grant{futureOther}, local: true},
		{name: "current-source-survives-retained-and-future-history", grants: []grant{exact, retained, future}, contributionActive: true, contributionVersion: 3},
		{name: "removed-local-member-has-no-effective-origin", removed: true},
		{name: "removed-directory-member-retains-detached-contribution-only", removed: true, grants: []grant{exact, otherProvider}, contributionActive: true, contributionVersion: 3},
		{name: "absent-member-has-no-effective-origin", absent: true},
		{name: "other-canonical-member-is-local", owner: true, grants: []grant{exact}, local: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM organization.directory_membership_grants`); err != nil {
				t.Fatal("reset isolated source fixture", err)
			}
			state := "active"
			if tc.removed {
				state = "removed"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state=$2 WHERE tenant_id='org-test-basic' AND organization_id=$1 AND user_id='member'`, string(metadataOrganization), state); err != nil {
				t.Fatal("seed canonical member state", err)
			}
			for _, g := range tc.grants {
				if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,$4::numeric,$5,$6,$7,$8::numeric,$9)`, string(source.TenantID), string(source.OrganizationID), string(source.UserID), strconv.FormatUint(g.memberVersion, 10), g.provider, g.connection, g.resource, strconv.FormatUint(g.version, 10), g.active); err != nil {
					t.Fatal("seed source incarnation", err)
				}
			}
			selected := source
			if tc.absent {
				selected.UserID = "outsider"
			}
			if tc.owner {
				selected.UserID = "owner"
			}
			before := directoryMembershipAttributionSnapshot(t, f)
			got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, selected)
			wantMember := organization.Member{TenantID: source.TenantID, OrganizationID: source.OrganizationID, UserID: source.UserID, Role: organization.RoleAdministrator, Version: 7, AuthorizationVersion: 11, Active: !tc.removed}
			if tc.absent {
				wantMember = organization.Member{}
			}
			if tc.owner {
				wantMember = organization.Member{TenantID: source.TenantID, OrganizationID: source.OrganizationID, UserID: "owner", Role: organization.RoleOwner, Version: 1, AuthorizationVersion: 1, Active: true}
			}
			wantMembership := organizationpg.DirectoryMembershipObservation{Member: wantMember, ContributionActive: tc.contributionActive, ContributionVersion: tc.contributionVersion}
			if err != nil || got.Membership != wantMembership || got.OrganizationVersion != 23 || got.CredentialVersion != 2 || got.Local != tc.local || got.OtherSource != tc.other {
				t.Fatalf("attribution = %+v, %v; want membership %+v, owner versions 23/2, local=%t, other=%t", got, err, wantMembership, tc.local, tc.other)
			}
			original, err := repo.ObserveDirectoryMembership(f.ctx, selected)
			if err != nil || got.Membership != original {
				t.Fatalf("attribution changed detached membership contract: %+v, %v", original, err)
			}
			if after := directoryMembershipAttributionSnapshot(t, f); after != before {
				t.Fatal("attribution observation changed membership, sources, owner versions, identity, or effects")
			}
		})
	}
}

func TestObserveDirectoryMembershipAttributionRejectsReboundAndForeignOwners(t *testing.T) {
	f, repo, source := directoryMembershipAttributionFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,7,$4,$5,'bound-resource',9,true)`, string(source.TenantID), string(source.OrganizationID), string(source.UserID), string(source.ProviderID), string(source.ConnectionID)); err != nil {
		t.Fatal("seed another resource bound to exact source", err)
	}
	before := directoryMembershipAttributionSnapshot(t, f)
	if got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, source); !errors.Is(err, organization.ErrConflict) || got != (organizationpg.DirectoryMembershipAttribution{}) {
		t.Fatalf("resource rebound disclosed attribution: %+v, %v", got, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*organizationpg.DirectoryMembershipSource)
	}{
		{"other-tenant", func(s *organizationpg.DirectoryMembershipSource) { s.TenantID = "org-test-scope" }},
		{"other-organization", func(s *organizationpg.DirectoryMembershipSource) { s.OrganizationID = "other" }},
		{"case-sensitive-organization", func(s *organizationpg.DirectoryMembershipSource) { s.OrganizationID = "01arz3ndektsv4rrffq69g5fav" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := source
			tc.edit(&selected)
			if got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, selected); !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryMembershipAttribution{}) {
				t.Fatalf("foreign owner disclosed attribution: %+v, %v", got, err)
			}
		})
	}
	if after := directoryMembershipAttributionSnapshot(t, f); after != before {
		t.Fatal("rejected observation changed persisted state")
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived',version=24 WHERE tenant_id=$1 AND organization_id=$2`, string(source.TenantID), string(source.OrganizationID)); err != nil {
		t.Fatal("archive owner fixture", err)
	}
	if got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, source); !errors.Is(err, organization.ErrForbidden) || got != (organizationpg.DirectoryMembershipAttribution{}) {
		t.Fatalf("archived owner disclosed attribution: %+v, %v", got, err)
	}
}

func TestObserveDirectoryMembershipAttributionPreservesUint64Versions(t *testing.T) {
	f, repo, source := directoryMembershipAttributionFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET version=18446744073709551615 WHERE tenant_id=$1 AND organization_id=$2`, string(source.TenantID), string(source.OrganizationID)); err != nil {
		t.Fatal("seed maximum organization version", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET version=18446744073709551615,authorization_version=18446744073709551615 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(source.TenantID), string(source.OrganizationID), string(source.UserID)); err != nil {
		t.Fatal("seed maximum member versions", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,18446744073709551615,$4,$5,$6,18446744073709551615,true)`, string(source.TenantID), string(source.OrganizationID), string(source.UserID), string(source.ProviderID), string(source.ConnectionID), string(source.ResourceID)); err != nil {
		t.Fatal("seed maximum contribution version", err)
	}
	got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, source)
	if err != nil || got.OrganizationVersion != math.MaxUint64 || got.CredentialVersion != 2 || got.Membership.Member.Version != math.MaxUint64 || got.Membership.Member.AuthorizationVersion != math.MaxUint64 || got.Membership.ContributionVersion != math.MaxUint64 || !got.Membership.ContributionActive || got.Local || got.OtherSource {
		t.Fatalf("maximum version attribution was truncated or changed: %+v, %v", got, err)
	}
}

func TestObserveDirectoryMembershipAttributionRejectsInvalidAndCanceledReads(t *testing.T) {
	f, repo, source := directoryMembershipAttributionFixture(t)
	for _, tc := range []struct {
		name   string
		repo   *organizationpg.Repository
		ctx    context.Context
		source organizationpg.DirectoryMembershipSource
	}{
		{"nil-repository", nil, f.ctx, source},
		{"unconfigured-repository", &organizationpg.Repository{}, f.ctx, source},
		{"nil-context", repo, nil, source},
		{"empty-source", repo, f.ctx, organizationpg.DirectoryMembershipSource{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.repo.ObserveDirectoryMembershipAttribution(tc.ctx, tc.source); !errors.Is(err, organization.ErrInvalidInput) || got != (organizationpg.DirectoryMembershipAttribution{}) {
				t.Fatalf("invalid read disclosed attribution: %+v, %v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := repo.ObserveDirectoryMembershipAttribution(ctx, source); !errors.Is(err, context.Canceled) || got != (organizationpg.DirectoryMembershipAttribution{}) {
		t.Fatalf("canceled read disclosed attribution: %+v, %v", got, err)
	}
	ctx, cancel = context.WithDeadline(f.ctx, time.Now().Add(-time.Second))
	defer cancel()
	if got, err := repo.ObserveDirectoryMembershipAttribution(ctx, source); !errors.Is(err, context.DeadlineExceeded) || got != (organizationpg.DirectoryMembershipAttribution{}) {
		t.Fatalf("expired read disclosed attribution: %+v, %v", got, err)
	}
}

func TestObserveDirectoryMembershipAttributionBoundsBlockedStorageRead(t *testing.T) {
	f, _, source := directoryMembershipAttributionFixture(t)
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.directory_membership_grants IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("block source storage", err)
	}
	started := time.Now()
	got, err := repo.ObserveDirectoryMembershipAttribution(f.ctx, source)
	if !errors.Is(err, context.DeadlineExceeded) || got != (organizationpg.DirectoryMembershipAttribution{}) {
		t.Fatalf("blocked read escaped repository deadline or disclosed partial attribution: %+v, %v", got, err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked read exceeded bounded storage budget: %s", elapsed)
	}
}
