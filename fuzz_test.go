package organization_test

import (
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func FuzzCreateSlugBoundary(f *testing.F) {
	for _, seed := range []string{"example", "a-b", "a", "", "-a", "a-", "A", "a\x00b", "é", string([]byte{0xff}), "a/b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, slug string) {
		if len(slug) > 1024 {
			return
		}
		s, auth, _, owner, policy := policyFixture(t)
		id, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		p, e := s.PrepareCreate(t.Context(), organization.CreateRequest{Authentication: auth, CommandID: id, ID: "org", Slug: slug, Name: "Example", CorrelationID: "fuzz"})
		valid := len(slug) >= 1 && len(slug) <= 63
		for i := 0; i < len(slug); i++ {
			c := slug[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i != 0 && i != len(slug)-1) {
				valid = false
			}
		}
		if !valid {
			if !errors.Is(e, organization.ErrInvalidInput) || p != (organization.Command{}) || policy.calls != 0 || owner.writes != 0 {
				t.Fatal("invalid slug crossed public policy boundary")
			}
			return
		}
		x, projectionErr := p.Input()
		if e != nil || projectionErr != nil || x.Organization.Slug != slug || owner.writes != 0 {
			t.Fatal("valid slug changed during preparation")
		}
	})
}
