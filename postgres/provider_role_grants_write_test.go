package postgres

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestProviderRoleGrantSAMLAccountMustMatchExactScope(t *testing.T) {
	scope := organization.ProviderRoleGrantScope{TenantID: "tenant-a", OrganizationID: "org-a", UserID: "member", ProviderID: "provider-a"}
	account := identity.Account{TenantID: scope.TenantID, UserID: scope.UserID,
		Provider: "sso.saml.v1.db897049df0fc5ff544ff0d74fcfe8c2c60f8c8cfe2e2daa4ca3999cf33610ce"}
	if !matchesSAMLProviderRoleAccount(account, scope) {
		t.Fatal("linked account in the exact provider and organization scope denied")
	}
	for name, change := range map[string]func(*identity.Account, *organization.ProviderRoleGrantScope){
		"foreign tenant":       func(a *identity.Account, _ *organization.ProviderRoleGrantScope) { a.TenantID = "tenant-b" },
		"foreign user":         func(a *identity.Account, _ *organization.ProviderRoleGrantScope) { a.UserID = "other" },
		"foreign organization": func(_ *identity.Account, s *organization.ProviderRoleGrantScope) { s.OrganizationID = "org-b" },
		"foreign provider":     func(_ *identity.Account, s *organization.ProviderRoleGrantScope) { s.ProviderID = "provider-b" },
		"OIDC namespace": func(a *identity.Account, _ *organization.ProviderRoleGrantScope) {
			a.Provider = "sso.oidc.v1." + a.Provider[12:]
		},
		"unscoped provider": func(a *identity.Account, _ *organization.ProviderRoleGrantScope) { a.Provider = "provider-a" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate, target := account, scope
			change(&candidate, &target)
			if matchesSAMLProviderRoleAccount(candidate, target) {
				t.Fatal("account outside the exact SAML grant scope passed")
			}
		})
	}
}

func TestProviderRoleGrantUpdateBindsExactIntent(t *testing.T) {
	scope := organization.ProviderRoleGrantScope{TenantID: "tenant", OrganizationID: "org", UserID: "member", ProviderID: "enterprise-a"}
	started := time.Unix(100, 0).UTC()
	input := organization.ProviderRoleGrantInput{Scope: scope, MemberVersion: 3, MappingVersion: 5,
		OriginalFlowStartedAt: started, AssertedAt: started.Add(time.Second), RoleIDs: []organization.ID{"writer", "reader"}}
	observed := organization.CredentialAuthorityObservation{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID, Version: 11, CredentialVersion: 2,
		Actor: organization.Member{TenantID: scope.TenantID, OrganizationID: scope.OrganizationID, UserID: scope.UserID, Role: organization.RoleMember,
			Version: input.MemberVersion, AuthorizationVersion: 12, Active: true},
		ReadStartedAt: started.Add(2 * time.Second), VerifiedAt: started.Add(3 * time.Second), ValidUntil: started.Add(22 * time.Second)}
	newGrant := func(input organization.ProviderRoleGrantInput) organization.ProviderRoleGrantSet {
		t.Helper()
		grants, err := organization.NewProviderRoleGrantSet(input)
		if err != nil {
			t.Fatal(err)
		}
		return grants
	}
	field := func(input organization.ProviderRoleGrantInput, authority organization.CredentialAuthorityObservation, generation uint64) identity.FeatureField {
		t.Helper()
		update, err := NewProviderRoleGrantUpdate(newGrant(input), authority, generation, authority.Version)
		if err != nil {
			t.Fatal(err)
		}
		result, err := update.Field()
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	base := field(input, observed, 9)
	if base.Name != "organization.sso-provider-role-replacement" || base.Value.Kind != identity.FeatureBytes || len(base.Value.Bytes) != 32 {
		t.Fatal("update must expose only an exact, bounded command fingerprint")
	}
	update, err := NewProviderRoleGrantUpdate(newGrant(input), observed, 9, observed.Version)
	if err != nil {
		t.Fatal(err)
	}
	if update.ExpectedOrganizationVersion() != observed.Version {
		t.Fatal("update lost the exact expected aggregate version")
	}
	advanced, err := NewProviderRoleGrantUpdate(newGrant(input), observed, 9, observed.Version+1)
	if err != nil {
		t.Fatal(err)
	}
	advancedField, err := advanced.Field()
	if err != nil || advanced.ExpectedOrganizationVersion() != observed.Version+1 || bytes.Equal(advancedField.Value.Bytes, base.Value.Bytes) {
		t.Fatal("expected aggregate revision was not bound to the exact intent", err)
	}
	projected, err := update.Field()
	if err != nil {
		t.Fatal(err)
	}
	projected.Value.Bytes[0] ^= 1
	retained, err := update.Field()
	if err != nil || !bytes.Equal(retained.Value.Bytes, base.Value.Bytes) || bytes.Equal(retained.Value.Bytes, projected.Value.Bytes) {
		t.Fatal("projection changed the fingerprint retained for native Apply")
	}
	ordered := input
	ordered.RoleIDs = []organization.ID{"reader", "writer"}
	if same := field(ordered, observed, 9); !bytes.Equal(same.Value.Bytes, base.Value.Bytes) {
		t.Fatal("unordered roles changed the exact intent")
	}
	for _, tc := range []struct {
		name string
		edit func(*organization.ProviderRoleGrantInput, *organization.CredentialAuthorityObservation, *uint64)
	}{
		{"provider source", func(i *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, _ *uint64) {
			i.Scope.ProviderID = "enterprise-b"
		}},
		{"source generation", func(_ *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, v *uint64) {
			*v++
		}},
		{"mapping version", func(i *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, _ *uint64) {
			i.MappingVersion++
		}},
		{"original flow", func(i *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, _ *uint64) {
			i.OriginalFlowStartedAt = i.OriginalFlowStartedAt.Add(time.Microsecond)
		}},
		{"signed assertion time", func(i *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, _ *uint64) {
			i.AssertedAt = i.AssertedAt.Add(time.Microsecond)
		}},
		{"explicit withdrawal", func(i *organization.ProviderRoleGrantInput, _ *organization.CredentialAuthorityObservation, _ *uint64) {
			i.RoleIDs = []organization.ID{}
		}},
		{"aggregate authority", func(_ *organization.ProviderRoleGrantInput, o *organization.CredentialAuthorityObservation, _ *uint64) {
			o.Version++
		}},
		{"scoped authorization", func(_ *organization.ProviderRoleGrantInput, o *organization.CredentialAuthorityObservation, _ *uint64) {
			o.Actor.AuthorizationVersion++
		}},
		{"original expiry", func(_ *organization.ProviderRoleGrantInput, o *organization.CredentialAuthorityObservation, _ *uint64) {
			o.ValidUntil = o.ValidUntil.Add(-time.Microsecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, observation, generation := input, observed, uint64(9)
			tc.edit(&input, &observation, &generation)
			if changed := field(input, observation, generation); bytes.Equal(changed.Value.Bytes, base.Value.Bytes) {
				t.Fatal("a changed authority or effect retained the original fingerprint")
			}
		})
	}
	for _, tc := range []struct {
		name string
		edit func(*organization.CredentialAuthorityObservation)
	}{
		{"foreign member", func(o *organization.CredentialAuthorityObservation) { o.Actor.UserID = "foreign" }},
		{"member version mismatch", func(o *organization.CredentialAuthorityObservation) { o.Actor.Version++ }},
		{"missing current authority", func(o *organization.CredentialAuthorityObservation) { o.Actor.AuthorizationVersion = 0 }},
		{"extended lease", func(o *organization.CredentialAuthorityObservation) {
			o.ValidUntil = o.ValidUntil.Add(time.Microsecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observation := observed
			tc.edit(&observation)
			if got, err := NewProviderRoleGrantUpdate(newGrant(input), observation, 9, observation.Version); !errors.Is(err, organization.ErrInvalidInput) || got != (ProviderRoleGrantUpdate{}) {
				t.Fatalf("invalid organization evidence retained a grant update: %v", err)
			}
		})
	}
	if _, err := (ProviderRoleGrantUpdate{}).Field(); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero update provided command data", err)
	}
	if (ProviderRoleGrantUpdate{}).ExpectedOrganizationVersion() != 0 {
		t.Fatal("zero update provided an expected aggregate revision")
	}
	for _, expected := range []uint64{0, observed.Version - 1, observed.Version + 2, math.MaxUint64} {
		if got, err := NewProviderRoleGrantUpdate(newGrant(input), observed, 9, expected); !errors.Is(err, organization.ErrInvalidInput) || got != (ProviderRoleGrantUpdate{}) {
			t.Fatalf("unrelated expected revision %d retained an update: %v", expected, err)
		}
	}
	observed.Version = math.MaxUint64
	if _, err := NewProviderRoleGrantUpdate(newGrant(input), observed, 9, math.MaxUint64); err != nil {
		t.Fatal("unchanged maximum revision must remain representable", err)
	}
	if got, err := NewProviderRoleGrantUpdate(newGrant(input), observed, 9, 0); !errors.Is(err, organization.ErrInvalidInput) || got != (ProviderRoleGrantUpdate{}) {
		t.Fatal("overflowed aggregate successor retained an update", err)
	}
}

func TestProviderRoleOrganizationVersionPredictsEffectiveChange(t *testing.T) {
	scope := organization.ProviderRoleGrantScope{TenantID: "tenant", OrganizationID: "org", UserID: "member", ProviderID: "enterprise-a"}
	started := time.Unix(100, 0).UTC()
	current := organization.ProviderRoleGrantInput{Scope: scope, MemberVersion: 3, MappingVersion: 5,
		OriginalFlowStartedAt: started, AssertedAt: started.Add(time.Second), RoleIDs: []organization.ID{"reader"}}
	previous, err := organization.NewProviderRoleGrantSet(current)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		exists     bool
		generation uint64
		edit       func(*organization.ProviderRoleGrantInput)
		changed    bool
	}{
		{name: "first grant", generation: 9, changed: true},
		{name: "first empty projection", generation: 9, edit: func(i *organization.ProviderRoleGrantInput) { i.RoleIDs = []organization.ID{} }},
		{name: "same current set", exists: true, generation: 9},
		{name: "withdrawal", exists: true, generation: 9, changed: true, edit: func(i *organization.ProviderRoleGrantInput) { i.RoleIDs = []organization.ID{} }},
		{name: "changed role", exists: true, generation: 9, changed: true, edit: func(i *organization.ProviderRoleGrantInput) { i.RoleIDs = []organization.ID{"writer"} }},
		{name: "new source generation", exists: true, generation: 10, changed: true},
		{name: "new mapping", exists: true, generation: 9, changed: true, edit: func(i *organization.ProviderRoleGrantInput) { i.MappingVersion++ }},
		{name: "new membership", exists: true, generation: 9, changed: true, edit: func(i *organization.ProviderRoleGrantInput) { i.MemberVersion++ }},
		{name: "invalidated empty projection", exists: true, generation: 10, edit: func(i *organization.ProviderRoleGrantInput) { i.RoleIDs = []organization.ID{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := current
			if tc.edit != nil {
				tc.edit(&input)
			}
			want := uint64(11)
			if tc.changed {
				want++
			}
			got, err := providerRoleOrganizationVersion(11, input, tc.generation, previous, 9, tc.exists)
			if err != nil || got != want {
				t.Fatalf("aggregate prediction=%d, want %d: %v", got, want, err)
			}
			got, err = providerRoleOrganizationVersion(math.MaxUint64, input, tc.generation, previous, 9, tc.exists)
			if tc.changed {
				if !errors.Is(err, organization.ErrConflict) || got != 0 {
					t.Fatalf("overflowed changed aggregate prediction=%d: %v", got, err)
				}
			} else if err != nil || got != math.MaxUint64 {
				t.Fatalf("unchanged maximum aggregate prediction=%d: %v", got, err)
			}
		})
	}
}
