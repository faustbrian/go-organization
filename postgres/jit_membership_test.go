package postgres

import (
	"bytes"
	"context"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
)

func providerJITMembershipInput() ProviderJITMembershipInput {
	started := time.Unix(100, 0).UTC()
	return ProviderJITMembershipInput{
		Owner: organization.CredentialAuthorityObservation{
			TenantID: "tenant", OrganizationID: "org", Version: 11, CredentialVersion: 2,
			ReadStartedAt: started, VerifiedAt: started.Add(time.Second), ValidUntil: started.Add(20 * time.Second),
		},
		UserID: "new-member", MaximumMembers: 100, MaximumPerUser: 10,
	}
}

func TestProviderJITMembershipBindsOriginalOwnerTargetAndCapacity(t *testing.T) {
	input := providerJITMembershipInput()
	prepared, err := NewProviderJITMembership(input)
	if err != nil {
		t.Fatal(err)
	}
	field, err := prepared.Field()
	if err != nil || field.Name != "organization.sso-provider-jit-membership" || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("membership intent must expose only its bounded fingerprint", err)
	}
	if prepared.ExpectedOrganizationVersion() != input.Owner.Version+1 {
		t.Fatal("membership must advance the exact observed organization once")
	}
	for name, edit := range map[string]func(*ProviderJITMembershipInput){
		"tenant":            func(i *ProviderJITMembershipInput) { i.Owner.TenantID = "other" },
		"organization":      func(i *ProviderJITMembershipInput) { i.Owner.OrganizationID = "other" },
		"policy epoch":      func(i *ProviderJITMembershipInput) { i.Owner.Version++ },
		"credential epoch":  func(i *ProviderJITMembershipInput) { i.Owner.CredentialVersion++ },
		"target":            func(i *ProviderJITMembershipInput) { i.UserID = "other" },
		"member capacity":   func(i *ProviderJITMembershipInput) { i.MaximumMembers++ },
		"per-user capacity": func(i *ProviderJITMembershipInput) { i.MaximumPerUser++ },
		"original read": func(i *ProviderJITMembershipInput) {
			i.Owner.ReadStartedAt = i.Owner.ReadStartedAt.Add(time.Millisecond)
		},
		"original verified": func(i *ProviderJITMembershipInput) { i.Owner.VerifiedAt = i.Owner.VerifiedAt.Add(time.Millisecond) },
		"original deadline": func(i *ProviderJITMembershipInput) { i.Owner.ValidUntil = i.Owner.ValidUntil.Add(-time.Millisecond) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			edit(&changed)
			other, err := NewProviderJITMembership(changed)
			if err != nil {
				t.Fatal(err)
			}
			otherField, err := other.Field()
			if err != nil || bytes.Equal(field.Value.Bytes, otherField.Value.Bytes) {
				t.Fatal("changed membership effect retained the original command fingerprint", err)
			}
		})
	}

	field.Value.Bytes[0] ^= 1
	retained, err := prepared.Field()
	if err != nil || bytes.Equal(field.Value.Bytes, retained.Value.Bytes) {
		t.Fatal("detached command field mutated the retained membership intent", err)
	}
	input.Owner.Version++
	if prepared.ExpectedOrganizationVersion() != 12 {
		t.Fatal("input mutation changed the retained predecessor")
	}
}

func TestProviderJITMembershipRejectsInvalidOwnerAndCapacity(t *testing.T) {
	for name, edit := range map[string]func(*ProviderJITMembershipInput){
		"zero observation": func(i *ProviderJITMembershipInput) { i.Owner = organization.CredentialAuthorityObservation{} },
		"invalid tenant":   func(i *ProviderJITMembershipInput) { i.Owner.TenantID = "bad tenant" },
		"invalid owner":    func(i *ProviderJITMembershipInput) { i.Owner.OrganizationID = "bad owner" },
		"missing epoch":    func(i *ProviderJITMembershipInput) { i.Owner.CredentialVersion = 0 },
		"member observation": func(i *ProviderJITMembershipInput) {
			i.Owner.Actor = organization.Member{TenantID: i.Owner.TenantID, OrganizationID: i.Owner.OrganizationID, UserID: "actor", Role: organization.RoleOwner, Active: true, Version: 1, AuthorizationVersion: 1}
		},
		"overflow predecessor": func(i *ProviderJITMembershipInput) { i.Owner.Version = math.MaxUint64 },
		"extended freshness":   func(i *ProviderJITMembershipInput) { i.Owner.ValidUntil = i.Owner.ValidUntil.Add(time.Nanosecond) },
		"empty target":         func(i *ProviderJITMembershipInput) { i.UserID = "" },
		"invalid target":       func(i *ProviderJITMembershipInput) { i.UserID = "bad target" },
		"zero member capacity": func(i *ProviderJITMembershipInput) { i.MaximumMembers = 0 },
		"oversized members":    func(i *ProviderJITMembershipInput) { i.MaximumMembers = 100001 },
		"zero user capacity":   func(i *ProviderJITMembershipInput) { i.MaximumPerUser = 0 },
		"oversized per user":   func(i *ProviderJITMembershipInput) { i.MaximumPerUser = 1001 },
	} {
		t.Run(name, func(t *testing.T) {
			input := providerJITMembershipInput()
			edit(&input)
			if got, err := NewProviderJITMembership(input); !errors.Is(err, organization.ErrInvalidInput) || got != (ProviderJITMembership{}) {
				t.Fatal("invalid input retained membership authority", err)
			}
		})
	}
	if _, err := (ProviderJITMembership{}).Field(); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero preparation provided command data", err)
	}
	if (ProviderJITMembership{}).ExpectedOrganizationVersion() != 0 {
		t.Fatal("zero preparation provided an aggregate version")
	}
}

func TestProviderJITMembershipRequiresOriginalWork(t *testing.T) {
	prepared, err := NewProviderJITMembership(providerJITMembershipInput())
	if err != nil {
		t.Fatal(err)
	}
	// A pool handle is deliberately present, but no transaction is fabricated.
	// Invalid Work must reject this before any database access is possible.
	repository := &Repository{pool: &database.Pool{}, maximum: time.Second}
	if err := repository.ApplyProviderJITMembership(context.Background(), kernel.Work{}, nil, identity.Command{}, prepared); err == nil {
		t.Fatal("membership application accepted Work outside the original callback")
	}
	if err := repository.ApplyProviderJITMembership(context.Background(), kernel.Work{}, nil, identity.Command{}, ProviderJITMembership{}); err == nil {
		t.Fatal("membership application accepted zero preparation")
	}
}
