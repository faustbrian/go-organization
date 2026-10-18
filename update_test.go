package organization_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func updateRequest(t *testing.T, a organization.Authentication) organization.UpdateRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return organization.UpdateRequest{Authentication: a, CommandID: id, OrganizationID: "org", OrganizationVersion: 7, Name: "Updated name", Slug: "updated", CorrelationID: "metadata-update"}
}

func TestUpdatePreparesExactMetadataForOwnerAndAdministrator(t *testing.T) {
	for _, role := range []organization.Role{organization.RoleOwner, organization.RoleAdministrator} {
		t.Run(string(role), func(t *testing.T) {
			s, a, _, owner, policy := policyFixture(t)
			owner.view.Actor.Role = role
			r := updateRequest(t, a)
			c, err := s.PrepareUpdate(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			x, err := c.Input()
			if err != nil || x.Operation != organization.Update || x.Binding.CommandID != r.CommandID || x.Binding.ActorID != "actor" || x.Binding.UserID != "actor" || x.Organization.ID != "org" || x.Organization.Version != 7 || x.Organization.Name != r.Name || x.Organization.Slug != r.Slug || x.Actor != owner.view.Actor || x.Target != (organization.Member{}) || x.Role != "" {
				t.Fatal("metadata command changed identity, scope, version, or membership", err)
			}
			if policy.last.Request.Action != authorization.Action(organization.Update) || policy.last.Request.Resource.ID != "org" || policy.last.Request.Tenant != "tenant-a" {
				t.Fatal("update policy did not use exact operation and organization")
			}
			result, err := s.Execute(t.Context(), c, outcomeOwner(func(command organization.Command) (organization.StoreResult, error) {
				result, err := owner.Execute(t.Context(), command)
				result.Receipt.AuditEventID = "metadata-audit"
				return result, err
			}))
			if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Feature.BeforeVersion != 7 || result.Receipt.Feature.AfterVersion != 8 || owner.writes != 1 {
				t.Fatal("update did not preserve sole owner's receipt", err)
			}
		})
	}
}

func TestUpdateRejectsUnsafeInputAndAuthorityWithoutMutation(t *testing.T) {
	for _, variant := range []string{"empty-name", "long-name", "control-name", "padded-name", "invalid-utf8", "empty-slug", "long-slug", "uppercase-slug", "padded-slug", "zero-version", "overflow-version", "stale-version", "identical", "member", "removed", "foreign", "archived", "policy-denial", "policy-revision", "invalid-command"} {
		t.Run(variant, func(t *testing.T) {
			s, a, _, owner, policy := policyFixture(t)
			r := updateRequest(t, a)
			want := organization.ErrInvalidInput
			switch variant {
			case "empty-name":
				r.Name = ""
			case "long-name":
				r.Name = strings.Repeat("a", 257)
			case "control-name":
				r.Name = "a\nb"
			case "padded-name":
				r.Name = " name"
			case "invalid-utf8":
				r.Name = string([]byte{0xff})
			case "empty-slug":
				r.Slug = ""
			case "long-slug":
				r.Slug = strings.Repeat("a", 64)
			case "uppercase-slug":
				r.Slug = "Updated"
			case "padded-slug":
				r.Slug = "-updated"
			case "zero-version":
				r.OrganizationVersion = 0
			case "overflow-version":
				r.OrganizationVersion = ^uint64(0)
			case "stale-version":
				r.OrganizationVersion--
				want = organization.ErrConflict
			case "identical":
				r.Name, r.Slug = owner.view.Organization.Name, owner.view.Organization.Slug
				want = organization.ErrConflict
			case "member":
				owner.view.Actor.Role = organization.RoleMember
				want = organization.ErrForbidden
			case "removed":
				owner.view.Actor.Active = false
				want = organization.ErrForbidden
			case "foreign":
				owner.view.Organization.TenantID = "other"
				want = organization.ErrForbidden
			case "archived":
				owner.view.Organization.Active = false
				want = organization.ErrForbidden
			case "policy-denial":
				policy.outcome = authorization.Deny
				want = organization.ErrForbidden
			case "policy-revision":
				policy.revision++
				want = organization.ErrForbidden
			case "invalid-command":
				r.CommandID = "invalid"
			}
			c, err := s.PrepareUpdate(t.Context(), r)
			if !errors.Is(err, want) || c != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("unsafe update accepted or wrong error", err)
			}
		})
	}
}

func TestUpdatePreservesNameAndSlugBoundaries(t *testing.T) {
	s, a, _, _, _ := policyFixture(t)
	r := updateRequest(t, a)
	r.Name, r.Slug = strings.Repeat("é", 128), strings.Repeat("a", 63)
	if _, err := s.PrepareUpdate(t.Context(), r); err != nil {
		t.Fatal("valid byte boundaries rejected", err)
	}
}

func TestUpdatePreparationWithholdsExpiredOrCanceledAdmission(t *testing.T) {
	for _, variant := range []string{"expired", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			s, a, at, owner, policy := policyFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := organization.ErrForbidden
			policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
			if variant == "canceled" {
				policy.beforeReturn, want = cancel, context.Canceled
			}
			command, err := s.PrepareUpdate(ctx, updateRequest(t, a))
			if !errors.Is(err, want) || command != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("update preparation renewed original admission", err)
			}
		})
	}
}

func FuzzUpdateMetadataBoundary(f *testing.F) {
	for _, seed := range [][2]string{{"New name", "new"}, {strings.Repeat("é", 128), strings.Repeat("a", 63)}, {"", "a"}, {" padded", "a"}, {"a\nb", "a"}, {"New", "-a"}, {"New", "A"}, {string([]byte{0xff}), "a"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, name, slug string) {
		if len(name) > 2048 || len(slug) > 2048 {
			return
		}
		s, a, _, owner, policy := policyFixture(t)
		r := updateRequest(t, a)
		r.Name, r.Slug = name, slug
		command, err := s.PrepareUpdate(t.Context(), r)
		valid := len(name) > 0 && len(name) <= 256 && utf8.ValidString(name) && strings.TrimSpace(name) == name && len(slug) > 0 && len(slug) <= 63
		for _, c := range name {
			if c < ' ' || c == 127 {
				valid = false
			}
		}
		for i := 0; i < len(slug); i++ {
			c := slug[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' && i > 0 && i < len(slug)-1) {
				valid = false
			}
		}
		if !valid {
			if !errors.Is(err, organization.ErrInvalidInput) || command != (organization.Command{}) || policy.calls != 0 || owner.reads != 0 || owner.writes != 0 {
				t.Fatal("invalid metadata crossed admission")
			}
			return
		}
		if name == "Example" && slug == "example" {
			if !errors.Is(err, organization.ErrConflict) {
				t.Fatal("no-op metadata became a transition")
			}
			return
		}
		x, inputErr := command.Input()
		if err != nil || inputErr != nil || x.Organization.Name != name || x.Organization.Slug != slug || owner.writes != 0 {
			t.Fatal("valid metadata changed during preparation", err)
		}
	})
}
