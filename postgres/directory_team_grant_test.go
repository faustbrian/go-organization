package postgres_test

import (
	"bytes"
	"context"
	"math"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

func directoryTeamInput() organizationpg.DirectoryTeamGrantInput {
	return organizationpg.DirectoryTeamGrantInput{
		Scope:   organizationpg.DirectoryTeamGrantScope{TenantID: "tenant", OrganizationID: "org", ProviderID: "provider", ConnectionID: "connection", GroupID: "group", TeamID: "team", UserID: "member"},
		ActorID: "directory-service", User: identity.User{TenantID: "tenant", ID: "member", Status: identity.StatusActive, Version: 1},
		OrganizationVersion: 3, CredentialVersion: 1, MemberVersion: 1, MemberAuthorizationVersion: 1, TeamVersion: 1, Active: true,
	}
}

func TestDirectoryTeamGrantIntentBindsExactSourceAndVersions(t *testing.T) {
	input := directoryTeamInput()
	update, err := organizationpg.NewDirectoryTeamGrantUpdate(input)
	if err != nil || update.RecordID() == "" || update.BeforeVersion() != 0 || update.AfterVersion() != 1 {
		t.Fatal("valid exact source update", err)
	}
	field, err := update.Field()
	if err != nil || field.Name != "organization.directory-team-membership" || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("bounded command field", err)
	}
	for _, edit := range []func(*organizationpg.DirectoryTeamGrantInput){
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Scope.ProviderID = "other" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Scope.ConnectionID = "other" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Scope.GroupID = "other" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Scope.TeamID = "other" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.MemberVersion++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.MemberAuthorizationVersion++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.OrganizationVersion++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.TeamVersion++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.User.Version++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.ActorID = "other-service" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.ExpectedVersion++ },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Active = false },
	} {
		changed := input
		edit(&changed)
		other, err := organizationpg.NewDirectoryTeamGrantUpdate(changed)
		if err != nil {
			t.Fatal(err)
		}
		otherField, _ := other.Field()
		if bytes.Equal(field.Value.Bytes, otherField.Value.Bytes) {
			t.Fatal("changed input retained original command digest")
		}
	}
	input.Active, input.ExpectedVersion = false, 10
	withdrawal, err := organizationpg.NewDirectoryTeamGrantUpdate(input)
	if err != nil || withdrawal.RecordID() != update.RecordID() || withdrawal.BeforeVersion() != 10 || withdrawal.AfterVersion() != 11 {
		t.Fatal("source identity must survive action and epoch changes", err)
	}
	field.Value.Bytes[0] ^= 0xff
	fresh, _ := update.Field()
	if bytes.Equal(field.Value.Bytes, fresh.Value.Bytes) {
		t.Fatal("field aliases frozen intent")
	}
}

func TestDirectoryTeamGrantRejectsInvalidAndUnownedWork(t *testing.T) {
	for _, edit := range []func(*organizationpg.DirectoryTeamGrantInput){
		func(i *organizationpg.DirectoryTeamGrantInput) {
			i.Scope.GroupID = organization.ID(strings.Repeat("x", 257))
		},
		func(i *organizationpg.DirectoryTeamGrantInput) { i.Scope.TenantID = "foreign" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.User.ID = "foreign" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.User.Status = identity.StatusSuspended },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.ActorID = "" },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.MemberVersion = 0 },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.TeamVersion = 0 },
		func(i *organizationpg.DirectoryTeamGrantInput) { i.ExpectedVersion = math.MaxUint64 },
	} {
		input := directoryTeamInput()
		edit(&input)
		if _, err := organizationpg.NewDirectoryTeamGrantUpdate(input); err == nil {
			t.Fatal("invalid source grant accepted")
		}
	}
	if _, err := (organizationpg.DirectoryTeamGrantUpdate{}).Field(); err == nil {
		t.Fatal("zero update supplied field")
	}
	update, _ := organizationpg.NewDirectoryTeamGrantUpdate(directoryTeamInput())
	if err := (*organizationpg.Repository)(nil).ApplyDirectoryTeamGrantUpdate(context.Background(), kernel.Work{}, nil, identity.Command{}, update); err == nil {
		t.Fatal("unowned Work accepted")
	}
}
