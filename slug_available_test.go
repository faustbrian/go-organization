package organization_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
)

type slugReader struct {
	organization.Repository
	query        organization.OrganizationSlugQuery
	available    bool
	reads        int
	beforeReturn func()
	err          error
	projection   func(organization.OrganizationSlugAvailability) organization.OrganizationSlugAvailability
}

func (r *slugReader) ReadOrganizationSlug(ctx context.Context, q organization.OrganizationSlugQuery) (organization.OrganizationSlugAvailability, error) {
	r.query, r.reads = q, r.reads+1
	if r.beforeReturn != nil {
		r.beforeReturn()
	}
	if err := ctx.Err(); err != nil {
		return organization.OrganizationSlugAvailability{}, err
	}
	result := organization.OrganizationSlugAvailability{TenantID: q.TenantID, Slug: q.Slug, Available: r.available}
	if r.projection != nil {
		result = r.projection(result)
	}
	return result, r.err
}

func slugFixture(t *testing.T) (*organization.Service, organization.SlugAvailableRequest, *policyClock, *policyOwner, *recordingPolicy, *slugReader, *policyReader) {
	t.Helper()
	var reader *slugReader
	var sessions *policyReader
	s, a, at, owner, policy := policyFixtureRepository(t, organization.TeamConfig{}, organization.DomainConfig{}, func(sr *policyReader, repo *policyOwner) organization.Repository {
		sessions = sr
		reader = &slugReader{Repository: repo, available: true}
		return reader
	})
	return s, organization.SlugAvailableRequest{Authentication: a, Slug: "candidate-slug", CorrelationID: "slug-available"}, at, owner, policy, reader, sessions
}

func TestSlugAvailableAuthenticatesSelfWithoutMembershipAndNeverReserves(t *testing.T) {
	s, request, _, owner, policy, reader, _ := slugFixture(t)
	owner.view = organization.View{}
	result, err := s.SlugAvailable(t.Context(), request)
	if err != nil || !result.Available {
		t.Fatal("authenticated nonmember cannot check candidate", err)
	}
	if owner.reads != 0 || owner.writes != 0 || reader.reads != 2 || reader.query.TenantID != request.Authentication.TenantID || reader.query.Slug != request.Slug {
		t.Fatal("candidate read substituted membership, tenant or reservation")
	}
	decision := policy.last
	if policy.calls != 2 || decision.Request.Subject.ID != "actor" || decision.Request.Action != authorization.Action(organization.SlugAvailable) || decision.Request.Tenant != "tenant-a" || decision.Request.Resource.Type != "organization.slug" || decision.Request.Resource.ID != authorization.ResourceID(request.Slug) || len(decision.Request.Resource.Attributes) != 0 || decision.CorrelationID != request.CorrelationID {
		t.Fatal("policy was not bound to authenticated self and candidate")
	}
	reader.available = false // A competing create can occupy a previously available slug.
	result, err = s.SlugAvailable(t.Context(), request)
	if err != nil || result.Available {
		t.Fatal("availability reserved the candidate or used a positive cache", err)
	}
	if owner.writes != 0 {
		t.Fatal("advisory read performed a write")
	}
}

func TestSlugAvailableAcceptsReconstructedCurrentSession(t *testing.T) {
	s, request, _, _, _, reader, sessions := slugFixture(t)
	reader.beforeReturn = func() {
		if reader.reads != 2 {
			return
		}
		// Real primary readers reconstruct immutable session/snapshot values on
		// every read; private pointer identity is never the credential binding.
		spec, err := sessions.observation.Session.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		bindings, err := spec.Authority.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		spec.Authority, err = session.NewAuthoritySnapshot(bindings)
		if err != nil {
			t.Fatal(err)
		}
		remember, err := spec.Remember.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		spec.Remember, err = session.NewRememberPolicy(remember)
		if err != nil {
			t.Fatal(err)
		}
		sessions.observation.Session, err = session.NewSession(spec)
		if err != nil {
			t.Fatal(err)
		}
		sessions.observation.Current = spec.Authority
	}
	if result, err := s.SlugAvailable(t.Context(), request); err != nil || !result.Available {
		t.Fatal("equivalent reconstructed current session was rejected", err)
	}
}

func TestSlugAvailableFailsClosedOnPolicyAndStorage(t *testing.T) {
	for _, variant := range []string{"deny", "policy-error", "revision", "unknown", "withdrawal", "storage-error"} {
		t.Run(variant, func(t *testing.T) {
			s, request, _, _, policy, reader, _ := slugFixture(t)
			want := organization.ErrForbidden
			switch variant {
			case "deny":
				policy.outcome = authorization.Deny
			case "policy-error":
				policy.err = errors.New("private policy failure")
				want = organization.ErrUnavailable
			case "revision":
				policy.revision++
			case "unknown":
				policy.outcome = authorization.Outcome(99)
			case "withdrawal":
				policy.beforeReturn = func() {
					if policy.calls == 2 {
						policy.outcome = authorization.Deny
					}
				}
			case "storage-error":
				reader.err = errors.New("private storage failure")
				want = organization.ErrUnavailable
			}
			result, err := s.SlugAvailable(t.Context(), request)
			if !errors.Is(err, want) || result.Available {
				t.Fatal("failed authority disclosed availability", err)
			}
		})
	}
}

func TestSlugAvailableRejectsInvalidInputBeforeAuthority(t *testing.T) {
	for _, slug := range []string{"", "Upper", "-start", "end-", "white space", "a/b", "é", strings.Repeat("a", 64)} {
		t.Run(slug, func(t *testing.T) {
			s, request, _, _, policy, reader, _ := slugFixture(t)
			request.Slug = slug
			result, err := s.SlugAvailable(t.Context(), request)
			if !errors.Is(err, organization.ErrInvalidInput) || result.Available || policy.calls != 0 || reader.reads != 0 {
				t.Fatal("malformed candidate reached authority", err)
			}
		})
	}
	for _, correlation := range []string{"", "bad correlation", strings.Repeat("a", 129)} {
		s, request, _, _, policy, reader, _ := slugFixture(t)
		request.CorrelationID = correlation
		result, err := s.SlugAvailable(t.Context(), request)
		if !errors.Is(err, organization.ErrInvalidInput) || result.Available || policy.calls != 0 || reader.reads != 0 {
			t.Fatal("malformed correlation reached authority", err)
		}
	}
	s, request, _, _, _, _, _ := slugFixture(t)
	for _, candidate := range []string{"a", "a--b", strings.Repeat("a", 63)} {
		request.Slug = candidate
		if result, err := s.SlugAvailable(t.Context(), request); err != nil || !result.Available {
			t.Fatal("valid create/update slug syntax rejected", err)
		}
	}
}

func TestSlugAvailableRejectsChangedOrMisboundProjection(t *testing.T) {
	for _, variant := range []string{"tenant", "slug", "changed"} {
		t.Run(variant, func(t *testing.T) {
			s, request, _, _, _, reader, _ := slugFixture(t)
			reader.projection = func(result organization.OrganizationSlugAvailability) organization.OrganizationSlugAvailability {
				switch variant {
				case "tenant":
					result.TenantID = "other"
				case "slug":
					result.Slug = "other"
				case "changed":
					if reader.reads == 2 {
						result.Available = false
					}
				}
				return result
			}
			result, err := s.SlugAvailable(t.Context(), request)
			if !errors.Is(err, organization.ErrForbidden) || result.Available {
				t.Fatal("unbound or changed source disclosed availability", err)
			}
		})
	}
}

func TestSlugAvailableRejectsLateWithdrawalAndOriginalExpiry(t *testing.T) {
	for _, variant := range []string{"session-revoked", "session-changed", "session-expired", "observation-expired", "renewed-observation", "clock-backwards", "canceled", "source-error", "source-panic"} {
		t.Run(variant, func(t *testing.T) {
			s, request, at, _, _, reader, sessions := slugFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := organization.ErrForbidden
			reader.beforeReturn = func() {
				if reader.reads != 2 {
					return
				}
				switch variant {
				case "session-revoked":
					sessions.observation.Active = false
				case "session-changed":
					spec, err := sessions.observation.Session.Bindings()
					if err != nil {
						t.Fatal(err)
					}
					bindings, err := spec.Authority.Bindings()
					if err != nil {
						t.Fatal(err)
					}
					bindings.Session.Version++
					spec.Version++
					spec.Authority, err = session.NewAuthoritySnapshot(bindings)
					if err != nil {
						t.Fatal(err)
					}
					sessions.observation.Session, err = session.NewSession(spec)
					if err != nil {
						t.Fatal(err)
					}
					sessions.observation.Current = spec.Authority
				case "session-expired":
					at.now = at.now.Add(time.Hour)
				case "observation-expired":
					at.now = at.now.Add(20 * time.Second)
				case "renewed-observation":
					at.now = at.now.Add(20 * time.Second)
					sessions.observation.ReadStartedAt = at.now
					sessions.observation.ValidUntil = at.now.Add(20 * time.Second)
				case "clock-backwards":
					at.now = at.now.Add(-time.Second)
				case "canceled":
					cancel()
				case "source-error":
					reader.err = errors.New("private late source failure")
				case "source-panic":
					panic("private source panic")
				}
			}
			if variant == "canceled" {
				want = context.Canceled
			}
			if variant == "source-error" || variant == "source-panic" {
				want = organization.ErrUnavailable
			}
			result, err := s.SlugAvailable(ctx, request)
			if !errors.Is(err, want) || result.Available {
				t.Fatal("late withdrawal released availability", err)
			}
		})
	}
}

func TestSlugAvailableRejectsMissingReaderAndAuthentication(t *testing.T) {
	s, authentication, _, _, _ := policyFixture(t)
	request := organization.SlugAvailableRequest{Authentication: authentication, Slug: "candidate", CorrelationID: "slug"}
	if result, err := s.SlugAvailable(t.Context(), request); !errors.Is(err, organization.ErrUnavailable) || result.Available {
		t.Fatal("missing optional reader accepted", err)
	}
	for _, variant := range []string{"bearer", "tenant", "invalid-tenant", "authority-unavailable", "canceled", "deadline", "nil-service", "nil-context"} {
		t.Run(variant, func(t *testing.T) {
			s, request, _, _, _, reader, sessions := slugFixture(t)
			ctx := t.Context()
			want := organization.ErrForbidden
			switch variant {
			case "bearer":
				request.Authentication.Bearer = organization.Authentication{}.Bearer
			case "tenant":
				request.Authentication.TenantID = "other"
			case "invalid-tenant":
				request.Authentication.TenantID = ""
				want = organization.ErrInvalidInput
			case "authority-unavailable":
				sessions.observation.Current = session.AuthoritySnapshot{}
				want = organization.ErrUnavailable
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
				want = context.Canceled
			case "deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				want = context.DeadlineExceeded
			case "nil-service":
				s = nil
				want = organization.ErrInvalidInput
			case "nil-context":
				ctx = nil
				want = organization.ErrInvalidInput
			}
			result, err := s.SlugAvailable(ctx, request)
			if !errors.Is(err, want) || result.Available || reader.reads != 0 {
				t.Fatal("unauthenticated request reached candidate source", err)
			}
		})
	}
}
