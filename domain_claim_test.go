package organization_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestCanonicalDomain(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"Example.COM", "example.com"}, {"EXAMPLE.com.", "example.com"},
		{"a-b.example", "a-b.example"}, {"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"example.a1", "example.a1"}, {"example.123", ""},
		{strings.Repeat("x", 63) + ".example", strings.Repeat("x", 63) + ".example"},
		{strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61), strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)},
		{"", ""}, {"localhost", ""}, {"127.0.0.1", ""}, {"*.example.com", ""},
		{" example.com", ""}, {"example.com..", ""}, {"a..example", ""},
		{"-a.example", ""}, {"a-.example", ""}, {"bücher.example", ""},
		{"a_b.example", ""}, {"https://example.com", ""}, {"example.com:443", ""},
		{strings.Repeat("x", 64) + ".example", ""}, {strings.Repeat("x", 255), ""},
	} {
		got, err := organization.CanonicalDomain(tc.input)
		if tc.want == "" {
			if got != "" || !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatalf("invalid domain admitted: %q", tc.input)
			}
		} else if err != nil || got != tc.want {
			t.Fatalf("canonical domain: got %q, %v", got, err)
		}
	}
}

func TestDomainPreparationAndCurrentRead(t *testing.T) {
	s, a, _, owner, policy := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{Version: 1, MaximumClaims: 20})
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	r := organization.DomainClaimRequest{Authentication: a, CommandID: id, OrganizationID: "org", ClaimID: "claim", OrganizationVersion: 7, Domain: "Example.COM.", CorrelationID: "domain"}
	c, e := s.PrepareReserveDomain(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	x, e := c.Input()
	if e != nil || x.DomainClaim.Domain != "example.com" || x.DomainClaim.ID != r.ClaimID || x.DomainClaim.Version != 0 || x.Binding.UserID != "actor" || x.Binding.OperationID != string(organization.ReserveDomain) || x.Domains.MaximumClaims != 20 || owner.writes != 0 {
		t.Fatal("reservation preparation lost binding", e)
	}
	claim := x.DomainClaim
	claim.Version = 1
	owner.view.DomainClaim = claim
	if _, e = s.PrepareReserveDomain(t.Context(), r); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("reused immutable claim identity", e)
	}
	r.ClaimVersion = 1
	c, e = s.PrepareWithdrawDomain(t.Context(), r)
	if e != nil {
		t.Fatal(e)
	}
	x, e = c.Input()
	if e != nil || x.DomainClaim != claim || x.Operation != organization.WithdrawDomain {
		t.Fatal("withdraw did not retain exact claim", e)
	}
	q := organization.DomainClaimReadRequest{Authentication: a, OrganizationID: "org", ClaimID: "claim", CorrelationID: "domain-read"}
	v, e := s.GetDomainClaim(t.Context(), q)
	if e != nil || v.DomainClaim != claim {
		t.Fatal("own current claim", e)
	}
	policy.beforeReturn = func() { owner.view.Actor.Active = false }
	if _, e = s.GetDomainClaim(t.Context(), q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("post-policy withdrawn member disclosed claim", e)
	}
}

func TestDomainPreparationDenials(t *testing.T) {
	for _, test := range []string{"member", "stale-org", "withdrawn", "stale-claim", "foreign-claim", "expired", "policy"} {
		t.Run(test, func(t *testing.T) {
			s, a, c, owner, policy := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{Version: 1, MaximumClaims: 20})
			id, e := identity.NewCommandID()
			if e != nil {
				t.Fatal(e)
			}
			r := organization.DomainClaimRequest{Authentication: a, CommandID: id, OrganizationID: "org", ClaimID: "claim", OrganizationVersion: 7, ClaimVersion: 1, Domain: "example.com", CorrelationID: "domain"}
			owner.view.DomainClaim = organization.DomainClaim{ID: "claim", OrganizationID: "org", TenantID: "tenant-a", Domain: "example.com", Version: 1, State: organization.DomainRequested}
			want := organization.ErrForbidden
			switch test {
			case "member":
				owner.view.Actor.Role = organization.RoleMember
			case "stale-org":
				r.OrganizationVersion = 6
				want = organization.ErrConflict
			case "withdrawn":
				owner.view.DomainClaim.State = organization.DomainWithdrawn
				owner.view.DomainClaim.Version = 2
				want = organization.ErrConflict
			case "stale-claim":
				r.ClaimVersion = 2
				want = organization.ErrConflict
			case "foreign-claim":
				owner.view.DomainClaim.TenantID = "other"
			case "expired":
				policy.beforeReturn = func() { c.now = c.now.Add(21 * time.Second) }
			case "policy":
				policy.revision = 2
			}
			if _, e = s.PrepareWithdrawDomain(t.Context(), r); !errors.Is(e, want) || owner.writes != 0 {
				t.Fatal("domain denial", e)
			}
		})
	}
}

func FuzzCanonicalDomain(f *testing.F) {
	for _, s := range []string{"example.com", "Example.COM.", "xn--bcher-kva.example", "bücher.example", "127.0.0.1", "a..example", "", "a.example.123", strings.Repeat("a", 254)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got, e := organization.CanonicalDomain(s)
		if e != nil {
			if got != "" || !errors.Is(e, organization.ErrInvalidInput) {
				t.Fatal("invalid classification")
			}
			return
		}
		if len(got) > 253 || len(got) < 3 || got != strings.ToLower(got) || strings.HasSuffix(got, ".") {
			t.Fatal("noncanonical admitted")
		}
		parts := strings.Split(got, ".")
		if len(parts) < 2 {
			t.Fatal("single label")
		}
		if !strings.ContainsAny(parts[len(parts)-1], "abcdefghijklmnopqrstuvwxyz") {
			t.Fatal("numeric final label admitted")
		}
		if got != strings.ToLower(strings.TrimSuffix(s, ".")) {
			t.Fatal("unexpected normalization")
		}
		for _, label := range parts {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				t.Fatal("invalid label")
			}
			for _, b := range []byte(label) {
				if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
					t.Fatal("invalid byte")
				}
			}
		}
		if again, e := organization.CanonicalDomain(got); e != nil || again != got {
			t.Fatal("not idempotent")
		}
	})
}

func TestDomainReservationPublicBoundary(t *testing.T) {
	var service *organization.Service
	if _, err := service.PrepareReserveDomain(t.Context(), organization.DomainClaimRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, err := service.PrepareWithdrawDomain(t.Context(), organization.DomainClaimRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal(err)
	}
	if _, err := service.GetDomainClaim(t.Context(), organization.DomainClaimReadRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal(err)
	}
	if organization.ReserveDomain.Descriptor().Validate() != nil || organization.WithdrawDomain.Descriptor().Validate() != nil || organization.GetDomainClaim.Descriptor().Validate() == nil {
		t.Fatal("domain mutation/read descriptors")
	}
}
