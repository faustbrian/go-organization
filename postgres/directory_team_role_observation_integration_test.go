//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryTeamRoleObservationScope() organizationpg.DirectoryTeamGrantScope {
	return organizationpg.DirectoryTeamGrantScope{TenantID: "org-test-basic", OrganizationID: metadataOrganization,
		ProviderID: "provider", ConnectionID: "connection", GroupID: "group", TeamID: "engineering", UserID: "member"}
}

func TestObserveDirectoryTeamRoleBindingReturnsOnlyExactActiveNativeSelection(t *testing.T) {
	f, view := directoryTeamRolePermissionFixture(t)
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := directoryTeamRoleObservationScope()
	version, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, scope, "reader")
	if err != nil || version != view.TeamRoleBinding.Version {
		t.Fatalf("exact binding version = %d, %v; want %d", version, err, view.TeamRoleBinding.Version)
	}
	grantInput := directoryTeamInput()
	grantInput.Scope, grantInput.User.TenantID = scope, scope.TenantID
	grantInput.OrganizationVersion = view.Organization.Version
	grantInput.TeamVersion = view.Team.Version
	grant, err := organizationpg.NewDirectoryTeamGrantUpdate(grantInput)
	if err != nil {
		t.Fatal("prepare exact add from observation", err)
	}
	source := organizationpg.DirectoryTeamRoleSource{Scope: scope, MemberResourceID: "source-member", RoleID: "reader", ProviderVersion: 1, MappingVersion: 1, ConnectionVersion: 1}
	if _, err := organizationpg.NewDirectoryTeamRoleUpdate(grant, source, version); err != nil {
		t.Fatal("observed binding cannot prepare exact role add", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*organizationpg.DirectoryTeamGrantScope)
		role organization.ID
	}{
		{"other-tenant", func(s *organizationpg.DirectoryTeamGrantScope) { s.TenantID = "org-test-scope" }, "reader"},
		{"other-organization", func(s *organizationpg.DirectoryTeamGrantScope) { s.OrganizationID = "other" }, "reader"},
		{"other-team", func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "other" }, "reader"},
		{"case-sensitive-team", func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "Engineering" }, "reader"},
		{"other-role", func(*organizationpg.DirectoryTeamGrantScope) {}, "other"},
		{"case-sensitive-role", func(*organizationpg.DirectoryTeamGrantScope) {}, "Reader"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := scope
			tc.edit(&selected)
			if got, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, selected, tc.role); got != 0 || !errors.Is(err, organization.ErrForbidden) {
				t.Fatalf("foreign or missing native binding disclosed version %d: %v", got, err)
			}
		})
	}
	for _, tc := range []struct{ name, change, restore string }{
		{"removed-binding", `UPDATE organization.team_role_bindings SET state='removed'`, `UPDATE organization.team_role_bindings SET state='active'`},
		{"deleted-role", `UPDATE organization.custom_roles SET state='deleted'`, `UPDATE organization.custom_roles SET state='active'`},
		{"deleted-team", `UPDATE organization.team_identities SET deleted_version=2`, `UPDATE organization.team_identities SET deleted_version=NULL`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.pool.Raw().Exec(f.ctx, tc.change); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := f.pool.Raw().Exec(f.ctx, tc.restore); err != nil {
					t.Fatal(err)
				}
			}()
			if got, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, scope, "reader"); got != 0 || !errors.Is(err, organization.ErrForbidden) {
				t.Fatalf("inactive target disclosed version %d: %v", got, err)
			}
		})
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `DELETE FROM organization.teams WHERE team_id='engineering'`); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.ObserveDirectoryTeamRoleBinding(f.ctx, scope, "reader"); got != 0 || !errors.Is(err, organization.ErrForbidden) {
		t.Fatalf("binding with absent native team disclosed version %d: %v", got, err)
	}
}

func TestObserveDirectoryTeamRoleBindingRejectsInvalidAndCancelledReads(t *testing.T) {
	f, _ := directoryTeamRolePermissionFixture(t)
	repo, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	scope := directoryTeamRoleObservationScope()
	for _, tc := range []struct {
		name  string
		repo  *organizationpg.Repository
		ctx   context.Context
		scope organizationpg.DirectoryTeamGrantScope
		role  organization.ID
	}{
		{"nil-repository", nil, f.ctx, scope, "reader"},
		{"nil-context", repo, nil, scope, "reader"},
		{"empty-scope", repo, f.ctx, organizationpg.DirectoryTeamGrantScope{}, "reader"},
		{"empty-role", repo, f.ctx, scope, ""},
		{"oversized-role", repo, f.ctx, scope, organization.ID(strings.Repeat("x", 257))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := tc.repo.ObserveDirectoryTeamRoleBinding(tc.ctx, tc.scope, tc.role); got != 0 || !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatalf("invalid read returned version %d: %v", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	if got, err := repo.ObserveDirectoryTeamRoleBinding(ctx, scope, "reader"); got != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read returned version %d: %v", got, err)
	}
}
