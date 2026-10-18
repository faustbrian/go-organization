package organization_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	organization "github.com/faustbrian/go-organization"
)

func (o *policyOwner) ReadOrganizations(ctx context.Context, q organization.OrganizationListQuery) ([]organization.OrganizationListEntry, error) {
	o.listReads++
	o.listQuery = q
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if o.listError != nil {
		return nil, o.listError
	}
	var entries []organization.OrganizationListEntry
	for _, entry := range o.organizations {
		if q.After == "" || entry.Organization.ID > q.After {
			entries = append(entries, entry)
		}
	}
	if o.beforeListReturn != nil {
		o.beforeListReturn()
	}
	return entries, nil
}

func organizationListFixture(t *testing.T) (*organization.Service, organization.ListOrganizationsRequest, *policyClock, *policyOwner, *recordingPolicy) {
	t.Helper()
	s, a, clock, owner, policy := policyFixture(t)
	for _, id := range []organization.ID{"a", "b", "c"} {
		org, member := owner.view.Organization, owner.view.Actor
		org.ID, org.Slug, org.Name = id, string(id), "Organization "+string(id)
		member.OrganizationID, member.Role = id, organization.RoleMember
		owner.organizations = append(owner.organizations, organization.OrganizationListEntry{Organization: org, Member: member})
	}
	return s, organization.ListOrganizationsRequest{Authentication: a, Limit: 1, CorrelationID: "list-organizations"}, clock, owner, policy
}

func TestListOrganizationsUsesSelfScopeAndStableVisiblePages(t *testing.T) {
	s, r, _, owner, policy := organizationListFixture(t)
	denyMiddle := true
	policy.beforeReturn = func() {
		policy.outcome = authorization.Allow
		if denyMiddle && policy.last.Request.Resource.ID == "b" {
			policy.outcome = authorization.Deny
		}
	}
	first, err := s.ListOrganizations(t.Context(), r)
	if err != nil || len(first.Organizations) != 1 || first.Organizations[0].ID != "a" || first.NextCursor == "" {
		t.Fatal("first visible organization page", err)
	}
	if owner.listQuery.TenantID != "tenant-a" || owner.listQuery.ActorID != "actor" || owner.listQuery.MaximumRows != 100 || policy.last.Request.Action != authorization.Action(organization.ListOrganizations) {
		t.Fatal("listing substituted tenant/actor or ignored configured scan bound")
	}
	r.Cursor = first.NextCursor
	// If the cursor leaked a hidden scanned ID instead of the last returned
	// visible ID, a newly allowed middle organization would be skipped here.
	denyMiddle = false
	newlyVisible, err := s.ListOrganizations(t.Context(), r)
	if err != nil || len(newlyVisible.Organizations) != 1 || newlyVisible.Organizations[0].ID != "b" || newlyVisible.NextCursor == "" {
		t.Fatal("continuation skipped the previously hidden middle organization", err)
	}
	denyMiddle = true
	second, err := s.ListOrganizations(t.Context(), r)
	if err != nil || len(second.Organizations) != 1 || second.Organizations[0].ID != "c" || second.NextCursor != "" {
		t.Fatal("denied organization blocked visible continuation", err)
	}
	first.Organizations[0].Name = "caller mutation"
	if owner.organizations[0].Organization.Name == "caller mutation" {
		t.Fatal("output aliases repository storage")
	}
}

func TestListOrganizationsRejectsUnsafeProjectionAndInput(t *testing.T) {
	for _, variant := range []string{"zero", "overlarge", "malformed-cursor", "oversized-cursor", "foreign", "removed", "unordered", "duplicate", "over-scan", "storage-error", "invalid-metadata", "unknown-role"} {
		t.Run(variant, func(t *testing.T) {
			s, r, _, owner, _ := organizationListFixture(t)
			want := organization.ErrUnavailable
			switch variant {
			case "zero":
				r.Limit = 0
				want = organization.ErrInvalidInput
			case "overlarge":
				r.Limit = 201
				want = organization.ErrInvalidInput
			case "malformed-cursor":
				r.Cursor = "bad"
				want = organization.ErrInvalidInput
			case "oversized-cursor":
				r.Cursor = organization.OrganizationCursor(strings.Repeat("a", 513))
				want = organization.ErrInvalidInput
			case "foreign":
				owner.organizations[0].Organization.TenantID = "other"
				want = organization.ErrForbidden
			case "removed":
				owner.organizations[0].Member.Active = false
				want = organization.ErrForbidden
			case "unordered":
				owner.organizations[0], owner.organizations[1] = owner.organizations[1], owner.organizations[0]
			case "duplicate":
				owner.organizations[1] = owner.organizations[0]
			case "over-scan":
				owner.organizations = make([]organization.OrganizationListEntry, 101)
				want = organization.ErrLimit
			case "storage-error":
				owner.listError = errors.New("private storage diagnostic")
			case "invalid-metadata":
				owner.organizations[0].Organization.Name = strings.Repeat("a", 257)
			case "unknown-role":
				owner.organizations[0].Member.Role = "unknown"
				want = organization.ErrForbidden
			}
			got, err := s.ListOrganizations(t.Context(), r)
			if !errors.Is(err, want) || len(got.Organizations) != 0 || got.NextCursor != "" {
				t.Fatal("unsafe list disclosed partial metadata", err)
			}
		})
	}
}

func TestListOrganizationsWithholdsLateWithdrawalAndOriginalFreshness(t *testing.T) {
	for _, variant := range []string{"session-expiry", "membership", "epoch", "policy", "expired", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			s, r, clock, owner, policy := organizationListFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := organization.ErrForbidden
			policy.beforeReturn = func() {
				if policy.last.Request.Resource.ID != "c" {
					return
				}
				switch variant {
				case "membership":
					owner.organizations[0].Member.Active = false
				case "epoch":
					owner.organizations[0].Organization.Version++
				case "policy":
					policy.outcome = authorization.Deny
				case "expired":
					clock.now = clock.now.Add(20 * time.Second)
				case "canceled":
					cancel()
				}
			}
			if variant == "session-expiry" {
				policy.beforeReturn = func() { clock.now = clock.now.Add(time.Hour) }
			}
			if variant == "canceled" {
				want = context.Canceled
			}
			got, err := s.ListOrganizations(ctx, r)
			if !errors.Is(err, want) || len(got.Organizations) != 0 || got.NextCursor != "" {
				t.Fatal("late withdrawal disclosed list", err)
			}
		})
	}
}

func TestListOrganizationsUnknownPolicyAndEmptyBoundaries(t *testing.T) {
	for _, variant := range []string{"policy-error", "policy-revision", "unknown-policy", "empty", "all-denied", "maximum-page"} {
		t.Run(variant, func(t *testing.T) {
			s, r, _, owner, policy := organizationListFixture(t)
			switch variant {
			case "policy-error":
				policy.err = errors.New("private policy diagnostic")
			case "policy-revision":
				policy.revision++
			case "unknown-policy":
				policy.outcome = authorization.Outcome(99)
			case "empty":
				owner.organizations = nil
			case "all-denied":
				policy.outcome = authorization.Deny
			case "maximum-page":
				r.Limit = 200
			}
			got, err := s.ListOrganizations(t.Context(), r)
			if variant == "empty" || variant == "all-denied" {
				if err != nil || got.Organizations == nil || len(got.Organizations) != 0 || got.NextCursor != "" {
					t.Fatal("empty visible list invented a continuation", err)
				}
				return
			}
			if variant == "maximum-page" {
				if err != nil || len(got.Organizations) != 3 || got.NextCursor != "" {
					t.Fatal("valid maximum page rejected", err)
				}
				return
			}
			want := organization.ErrForbidden
			if variant == "policy-error" {
				want = organization.ErrUnavailable
			}
			if !errors.Is(err, want) || len(got.Organizations) != 0 || got.NextCursor != "" {
				t.Fatal("unknown policy disclosed partial data", err)
			}
		})
	}
}

func TestListOrganizationsPreservesOriginalFreshnessThroughFinalRead(t *testing.T) {
	s, request, at, owner, _ := organizationListFixture(t)
	owner.beforeListReturn = func() {
		if owner.listReads == 2 {
			at.now = at.now.Add(20 * time.Second)
		}
	}
	// Re-authentication itself remains valid. Only the final primary read
	// crosses the original exclusive deadline; it must not release the page.
	result, err := s.ListOrganizations(t.Context(), request)
	if !errors.Is(err, organization.ErrForbidden) || len(result.Organizations) != 0 || result.NextCursor != "" {
		t.Fatal("final read renewed original observation freshness", err)
	}
}

func FuzzOrganizationListCursorBoundedParsing(f *testing.F) {
	for _, seed := range []string{"", "bad", "AA==", strings.Repeat("a", 512), strings.Repeat("a", 513), "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		if len(cursor) > 4096 {
			return
		}
		s, request, _, _, _ := organizationListFixture(t)
		request.Cursor = organization.OrganizationCursor(cursor)
		result, err := s.ListOrganizations(t.Context(), request)
		if err != nil {
			if len(result.Organizations) != 0 || result.NextCursor != "" {
				t.Fatal("invalid cursor disclosed partial metadata")
			}
			return
		}
		if len(result.Organizations) > 1 {
			t.Fatal("cursor bypassed output bound")
		}
		for _, org := range result.Organizations {
			if org.TenantID != "tenant-a" || org.ID != "a" && org.ID != "b" && org.ID != "c" {
				t.Fatal("cursor created authority outside the current subject")
			}
		}
	})
}
