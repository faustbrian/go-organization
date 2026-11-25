package postgres_test

import (
	"testing"

	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func TestDirectoryTeamRoleUpdateMatchesSource(t *testing.T) {
	for _, operation := range []struct {
		name           string
		active         bool
		bindingVersion uint64
	}{
		{name: "grant", active: true, bindingVersion: 5},
		{name: "withdrawal", active: false, bindingVersion: 0},
	} {
		t.Run(operation.name, func(t *testing.T) {
			input := directoryTeamInput()
			input.Active = operation.active
			grant, err := organizationpg.NewDirectoryTeamGrantUpdate(input)
			if err != nil {
				t.Fatal(err)
			}
			source := organizationpg.DirectoryTeamRoleSource{
				Scope: input.Scope, MemberResourceID: "source-member", RoleID: "reader",
				ProviderVersion: 2, MappingVersion: 3, ConnectionVersion: 4,
			}
			update, err := organizationpg.NewDirectoryTeamRoleUpdate(grant, source, operation.bindingVersion)
			if err != nil {
				t.Fatal(err)
			}
			if !update.MatchesSource(source, operation.active) {
				t.Fatal("exact source and original grant direction did not match")
			}
			if update.MatchesSource(source, !operation.active) {
				t.Fatal("opposite grant direction matched")
			}
			for _, mismatch := range []struct {
				name string
				edit func(*organizationpg.DirectoryTeamRoleSource)
			}{
				{"tenant", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.TenantID = "other" }},
				{"organization", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.OrganizationID = "other" }},
				{"provider", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.ProviderID = "other" }},
				{"connection", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.ConnectionID = "other" }},
				{"group", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.GroupID = "other" }},
				{"team", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.TeamID = "other" }},
				{"user", func(s *organizationpg.DirectoryTeamRoleSource) { s.Scope.UserID = "other" }},
				{"member resource", func(s *organizationpg.DirectoryTeamRoleSource) { s.MemberResourceID = "other" }},
				{"role", func(s *organizationpg.DirectoryTeamRoleSource) { s.RoleID = "other" }},
				{"provider version", func(s *organizationpg.DirectoryTeamRoleSource) { s.ProviderVersion++ }},
				{"mapping version", func(s *organizationpg.DirectoryTeamRoleSource) { s.MappingVersion++ }},
				{"connection version", func(s *organizationpg.DirectoryTeamRoleSource) { s.ConnectionVersion++ }},
			} {
				t.Run(mismatch.name, func(t *testing.T) {
					changed := source
					mismatch.edit(&changed)
					if update.MatchesSource(changed, operation.active) {
						t.Fatal("different source matched frozen update")
					}
				})
			}
			if update.MatchesSource(organizationpg.DirectoryTeamRoleSource{}, operation.active) {
				t.Fatal("zero source matched valid update")
			}
			if (organizationpg.DirectoryTeamRoleUpdate{}).MatchesSource(source, operation.active) {
				t.Fatal("zero update matched valid source")
			}
		})
	}
	for _, active := range []bool{true, false} {
		if (organizationpg.DirectoryTeamRoleUpdate{}).MatchesSource(organizationpg.DirectoryTeamRoleSource{}, active) {
			t.Fatal("zero update matched zero source")
		}
	}
}
