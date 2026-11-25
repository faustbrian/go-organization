package postgres_test

import (
	"errors"
	"strings"
	"testing"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// Existing v1 scope JSON, including exported field order, is durable identity.
const directoryTeamGrantRecordGolden = "4c8a53d2ec256a45ed6b9d8e927100635dcfee5daa4f54e48c49a03d5b1b3455"

func TestDirectoryTeamGrantScopeRecordIDPreservesExistingFormat(t *testing.T) {
	input := directoryTeamInput()
	got, err := input.Scope.RecordID()
	if err != nil || got != directoryTeamGrantRecordGolden {
		t.Fatalf("scope identity = %q, %v; want immutable existing v1 identity %q", got, err, directoryTeamGrantRecordGolden)
	}
	for _, active := range []bool{true, false} {
		input.Active, input.ExpectedVersion = active, 9
		update, err := organizationpg.NewDirectoryTeamGrantUpdate(input)
		if err != nil || update.RecordID() != got {
			t.Fatal("update changed durable scope identity across direction or version", err)
		}
	}
	for _, edit := range []func(*organizationpg.DirectoryTeamGrantScope){
		func(s *organizationpg.DirectoryTeamGrantScope) { s.TenantID = "Tenant" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.OrganizationID = "Org" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.ProviderID = "Provider" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.ConnectionID = "Connection" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.GroupID = "Group" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "Team" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.UserID = "Member" },
	} {
		changed := input.Scope
		edit(&changed)
		other, err := changed.RecordID()
		if err != nil || other == got {
			t.Fatal("scope identity lost exact case-sensitive field", err)
		}
	}
}

func TestDirectoryTeamGrantScopeRecordIDRejectsInvalidScope(t *testing.T) {
	for _, edit := range []func(*organizationpg.DirectoryTeamGrantScope){
		func(s *organizationpg.DirectoryTeamGrantScope) { s.TenantID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.OrganizationID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.ProviderID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.ConnectionID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.GroupID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.TeamID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.UserID = "" },
		func(s *organizationpg.DirectoryTeamGrantScope) { s.GroupID = organization.ID(strings.Repeat("x", 257)) },
	} {
		invalid := directoryTeamInput().Scope
		edit(&invalid)
		if got, err := invalid.RecordID(); got != "" || !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("invalid scope produced a usable record identity", err)
		}
	}
}
