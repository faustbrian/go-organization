package organization_test

import (
	"errors"
	"slices"
	"strconv"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
)

func TestProviderRoleGrantSet(t *testing.T) {
	scope := organization.ProviderRoleGrantScope{
		TenantID: "tenant", OrganizationID: "org", UserID: "member", ProviderID: "provider-a",
	}
	input := organization.ProviderRoleGrantInput{
		Scope: scope, MemberVersion: 2, MappingVersion: 5,
		OriginalFlowStartedAt: time.Unix(100, 0).UTC(), AssertedAt: time.Unix(101, 0).UTC(),
		RoleIDs: []organization.ID{"writer", "reader"},
	}
	set, err := organization.NewProviderRoleGrantSet(input)
	if err != nil {
		t.Fatal(err)
	}
	input.RoleIDs[0] = "mutated-input"
	value, ok := set.Value()
	if !ok || value.Scope != scope || value.MemberVersion != 2 || value.MappingVersion != 5 ||
		!value.OriginalFlowStartedAt.Equal(input.OriginalFlowStartedAt) || !value.AssertedAt.Equal(input.AssertedAt) ||
		!slices.Equal(value.RoleIDs, []organization.ID{"reader", "writer"}) {
		t.Fatalf("unexpected provider role grant projection: %+v", value)
	}
	value.RoleIDs[0] = "mutated-output"
	if value, _ := set.Value(); value.RoleIDs[0] != "reader" {
		t.Fatal("projection mutated the original grant set")
	}
	input.RoleIDs = []organization.ID{}
	clear, err := organization.NewProviderRoleGrantSet(input)
	if value, ok := clear.Value(); err != nil || !ok || value.RoleIDs == nil || len(value.RoleIDs) != 0 {
		t.Fatalf("explicit empty set must be a valid withdrawal: %+v, %v", value, err)
	}
	bounded := make([]organization.ID, 101)
	for i := range bounded {
		bounded[i] = organization.ID("custom-role-" + strconv.Itoa(i))
	}
	input.RoleIDs = bounded[:100]
	if set, err := organization.NewProviderRoleGrantSet(input); err != nil {
		t.Fatal("100 distinct custom roles denied", err)
	} else if value, ok := set.Value(); !ok || len(value.RoleIDs) != 100 {
		t.Fatal("accepted set lost a role")
	}
	for name, roles := range map[string][]organization.ID{
		"absent": nil, "duplicate": {"reader", "reader"}, "static-owner": {"owner"},
		"static-admin": {"administrator"}, "static-member": {"member"}, "malformed": {"reader role"},
		"over-limit": bounded,
	} {
		t.Run(name, func(t *testing.T) {
			input := input
			input.RoleIDs = roles
			set, err := organization.NewProviderRoleGrantSet(input)
			if _, valid := set.Value(); !errors.Is(err, organization.ErrInvalidInput) || valid {
				t.Fatalf("invalid desired set accepted: valid=%v err=%v", valid, err)
			}
		})
	}
}

func TestProviderRoleGrantSetRequiresOriginalCheckpoint(t *testing.T) {
	input := organization.ProviderRoleGrantInput{
		Scope: organization.ProviderRoleGrantScope{
			TenantID: "tenant", OrganizationID: "org", UserID: "member", ProviderID: "provider-a",
		},
		MemberVersion: 2, MappingVersion: 5, RoleIDs: []organization.ID{},
		OriginalFlowStartedAt: time.Unix(100, 0).UTC(), AssertedAt: time.Unix(101, 0).UTC(),
	}
	for _, tc := range []struct {
		name string
		edit func(*organization.ProviderRoleGrantInput)
	}{
		{"no original start", func(x *organization.ProviderRoleGrantInput) { x.OriginalFlowStartedAt = time.Time{} }},
		{"no issuer time", func(x *organization.ProviderRoleGrantInput) { x.AssertedAt = time.Time{} }},
		{"ordering lost on storage", func(x *organization.ProviderRoleGrantInput) {
			x.OriginalFlowStartedAt = x.OriginalFlowStartedAt.Add(time.Nanosecond)
		}},
		{"no member epoch", func(x *organization.ProviderRoleGrantInput) { x.MemberVersion = 0 }},
		{"no mapping epoch", func(x *organization.ProviderRoleGrantInput) { x.MappingVersion = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := input
			tc.edit(&in)
			if _, err := organization.NewProviderRoleGrantSet(in); !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatalf("unusable checkpoint accepted: %v", err)
			}
		})
	}
}

func TestProviderRoleGrantSetRejectsStaleReplacement(t *testing.T) {
	base := organization.ProviderRoleGrantInput{
		Scope: organization.ProviderRoleGrantScope{
			TenantID: "tenant", OrganizationID: "org", UserID: "member", ProviderID: "provider-a",
		},
		MemberVersion: 2, MappingVersion: 5, RoleIDs: []organization.ID{},
		OriginalFlowStartedAt: time.Unix(100, 0).UTC(), AssertedAt: time.Unix(101, 0).UTC(),
	}
	previous, err := organization.NewProviderRoleGrantSet(base)
	if err != nil {
		t.Fatal(err)
	}
	laterFlow := func(x *organization.ProviderRoleGrantInput) {
		x.OriginalFlowStartedAt = x.OriginalFlowStartedAt.Add(time.Microsecond)
	}
	for _, tc := range []struct {
		name string
		edit func(*organization.ProviderRoleGrantInput)
		want error
	}{
		{"new assertion in same issuer second", laterFlow, nil},
		{"replay cannot restore removed role", func(x *organization.ProviderRoleGrantInput) { x.RoleIDs = []organization.ID{"writer"} }, organization.ErrConflict},
		{"older original flow with newer assertion", func(x *organization.ProviderRoleGrantInput) {
			x.OriginalFlowStartedAt = x.OriginalFlowStartedAt.Add(-time.Microsecond)
			x.AssertedAt = x.AssertedAt.Add(time.Second)
		}, organization.ErrConflict},
		{"older signed assertion in newer flow", func(x *organization.ProviderRoleGrantInput) {
			laterFlow(x)
			x.MappingVersion++
			x.AssertedAt = x.AssertedAt.Add(-time.Second)
		}, organization.ErrConflict},
		{"old mapping on new assertion", func(x *organization.ProviderRoleGrantInput) { x.MappingVersion--; laterFlow(x) }, organization.ErrConflict},
		{"removed membership", func(x *organization.ProviderRoleGrantInput) { x.MemberVersion--; laterFlow(x) }, organization.ErrConflict},
		{"readmitted membership", func(x *organization.ProviderRoleGrantInput) { x.MemberVersion++; laterFlow(x) }, nil},
		{"another provider", func(x *organization.ProviderRoleGrantInput) { x.Scope.ProviderID = "provider-b"; laterFlow(x) }, organization.ErrInvalidInput},
		{"another tenant", func(x *organization.ProviderRoleGrantInput) { x.Scope.TenantID = "foreign"; laterFlow(x) }, organization.ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := base
			tc.edit(&next)
			set, err := organization.NewProviderRoleGrantSet(next)
			if err != nil {
				t.Fatal(err)
			}
			if got := set.CheckReplacement(previous); !errors.Is(got, tc.want) {
				t.Fatalf("replacement: got %v, want %v", got, tc.want)
			}
		})
	}
	if err := (organization.ProviderRoleGrantSet{}).CheckReplacement(previous); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatalf("invalid zero proposed set: %v", err)
	}
	if err := previous.CheckReplacement(organization.ProviderRoleGrantSet{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatalf("missing predecessor must not be inferred from zero: %v", err)
	}
}
