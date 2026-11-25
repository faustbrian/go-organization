package postgres_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
)

// This is the existing source.v1 SHA-256 over the purpose, a NUL separator and
// {"TenantID":"tenant-one","OrganizationID":"organization-one","UserID":"user-one","ProviderID":"provider-one","ConnectionID":"connection-one","ResourceID":"Resource-One"}.
const directoryMembershipRecordGolden = "19604cfe551d101c5f5ba0623cb3da0c0f0e5003ed5f296ce6477101d1fec006"

func directoryMembershipRecordSource() organizationpg.DirectoryMembershipSource {
	return organizationpg.DirectoryMembershipSource{
		TenantID:       "tenant-one",
		OrganizationID: "organization-one",
		UserID:         "user-one",
		ProviderID:     "provider-one",
		ConnectionID:   "connection-one",
		ResourceID:     "Resource-One",
	}
}

func directoryMembershipRecordInput() organizationpg.DirectoryMembershipInput {
	source := directoryMembershipRecordSource()
	now := time.Now().UTC()
	return organizationpg.DirectoryMembershipInput{
		Source:  source,
		ActorID: "directory-service",
		User:    identity.User{TenantID: source.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1},
		Organization: organization.CredentialAuthorityObservation{
			TenantID:          source.TenantID,
			OrganizationID:    source.OrganizationID,
			Version:           1,
			CredentialVersion: 1,
			ReadStartedAt:     now,
			VerifiedAt:        now,
			ValidUntil:        now.Add(20 * time.Second),
		},
		Action:         organizationpg.DirectoryMembershipGrant,
		MaximumMembers: 10,
		MaximumPerUser: 10,
	}
}

func TestDirectoryMembershipSourceRecordIDPreservesExistingFormat(t *testing.T) {
	got, err := directoryMembershipRecordSource().RecordID()
	if err != nil || got != directoryMembershipRecordGolden {
		t.Fatalf("source record ID = %q, %v; want existing format %q", got, err, directoryMembershipRecordGolden)
	}
}

func TestDirectoryMembershipUpdateUsesSourceRecordIDAcrossTransitions(t *testing.T) {
	for _, action := range []organizationpg.DirectoryMembershipAction{organizationpg.DirectoryMembershipGrant, organizationpg.DirectoryMembershipWithdraw} {
		for _, version := range []uint64{1, 9} {
			input := directoryMembershipRecordInput()
			input.Action = action
			input.MemberVersion = 4
			input.MemberAuthorizationVersion = 7
			input.ExpectedVersion = version
			if action == organizationpg.DirectoryMembershipWithdraw {
				input.User = identity.User{}
			}
			update, err := organizationpg.NewDirectoryMembershipUpdate(input)
			if err != nil {
				t.Fatalf("prepare action %d version %d: %v", action, version, err)
			}
			recordID, err := input.Source.RecordID()
			if err != nil || update.RecordID() != recordID || recordID != directoryMembershipRecordGolden {
				t.Fatalf("action %d version %d record ID = %q, source %q, %v", action, version, update.RecordID(), recordID, err)
			}
		}
	}
}

var directoryMembershipRecordFields = []struct {
	name string
	set  func(*organizationpg.DirectoryMembershipSource, string)
}{
	{"tenant", func(s *organizationpg.DirectoryMembershipSource, value string) { s.TenantID = identity.TenantID(value) }},
	{"organization", func(s *organizationpg.DirectoryMembershipSource, value string) {
		s.OrganizationID = organization.ID(value)
	}},
	{"user", func(s *organizationpg.DirectoryMembershipSource, value string) { s.UserID = identity.UserID(value) }},
	{"provider", func(s *organizationpg.DirectoryMembershipSource, value string) { s.ProviderID = organization.ID(value) }},
	{"connection", func(s *organizationpg.DirectoryMembershipSource, value string) {
		s.ConnectionID = organization.ID(value)
	}},
	{"resource", func(s *organizationpg.DirectoryMembershipSource, value string) { s.ResourceID = organization.ID(value) }},
}

func TestDirectoryMembershipSourceRecordIDRejectsInvalidScope(t *testing.T) {
	if got, err := (organizationpg.DirectoryMembershipSource{}).RecordID(); got != "" || !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatalf("zero source record ID = %q, %v", got, err)
	}
	for _, field := range directoryMembershipRecordFields {
		for _, invalid := range []struct{ name, value string }{
			{"empty", ""},
			{"oversized", strings.Repeat("a", 129)},
			{"space", "source value"},
			{"control", "source\x00value"},
			{"delete", "source\x7fvalue"},
			{"invalid-utf8", "source\xffvalue"},
		} {
			t.Run(field.name+"/"+invalid.name, func(t *testing.T) {
				source := directoryMembershipRecordSource()
				field.set(&source, invalid.value)
				got, err := source.RecordID()
				if got != "" || !errors.Is(err, organization.ErrInvalidInput) {
					t.Fatalf("invalid source record ID = %q, %v", got, err)
				}
			})
		}
	}
}

func TestDirectoryMembershipSourceRecordIDRetainsExactScope(t *testing.T) {
	seen := map[string]bool{directoryMembershipRecordGolden: true}
	for _, field := range directoryMembershipRecordFields {
		for _, value := range []string{"other-source", "Other-Source", strings.Repeat("a", 128), "source-\u00e9"} {
			source := directoryMembershipRecordSource()
			field.set(&source, value)
			got, err := source.RecordID()
			if err != nil || got == "" || seen[got] {
				t.Fatalf("%s changed scope record ID = %q, %v; want a distinct exact source", field.name, got, err)
			}
			seen[got] = true
		}
	}
}

func TestDirectoryMembershipSourceRecordIDCopiesDoNotChangeOriginalIdentity(t *testing.T) {
	input := directoryMembershipRecordInput()
	update, err := organizationpg.NewDirectoryMembershipUpdate(input)
	if err != nil {
		t.Fatal(err)
	}
	original := input.Source
	copied := original
	copied.ResourceID = "resource-one"
	input.Source = copied
	changed, err := copied.RecordID()
	if err != nil || changed == directoryMembershipRecordGolden {
		t.Fatalf("case-changed copy record ID = %q, %v", changed, err)
	}
	got, err := original.RecordID()
	if err != nil || got != directoryMembershipRecordGolden || update.RecordID() != directoryMembershipRecordGolden {
		t.Fatalf("copy changed original source %q, update %q, %v", got, update.RecordID(), err)
	}
}
