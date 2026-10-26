package organization

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// SlugAvailable is an authenticated tenant-local advisory candidate read, not
// organization discovery, membership authority or a reservation operation.
const SlugAvailable Operation = "identity.organization.slug-available"

// SlugAvailableRequest selects a candidate in Authentication's tenant. Slug
// uses CreateRequest's lowercase ASCII label syntax (1..63 bytes, no leading
// or trailing hyphen). CorrelationID is a required safe identifier of <=128
// bytes. No organization, target user or membership selector is accepted.
type SlugAvailableRequest struct {
	Authentication      Authentication
	Slug, CorrelationID string
}

// SlugAvailableResult discloses only observed availability. A true result does
// not reserve the slug or guarantee a later create/update; those operations'
// authoritative tenant-local uniqueness checks remain required.
type SlugAvailableResult struct {
	Available bool
}

// OrganizationSlugQuery is an exact trusted primary occupancy query generated
// after session authentication and explicit candidate policy admission.
type OrganizationSlugQuery struct {
	TenantID identity.TenantID
	Slug     string
}

// OrganizationSlugAvailability echoes the exact query scope and exposes no
// organization identity or metadata. Available is false for every retained row
// occupying the tenant-local unique slug, including archived organizations.
type OrganizationSlugAvailability struct {
	TenantID  identity.TenantID
	Slug      string
	Available bool
}

// OrganizationSlugReader is an additive optional Repository capability. Read
// current primary occupancy without positive caching, honor ctx and release
// resources before returning. A missing capability returns ErrUnavailable;
// existing Repository implementations remain compatible. This trusted storage
// projection is not an authentication endpoint or reservation mechanism.
type OrganizationSlugReader interface {
	ReadOrganizationSlug(context.Context, OrganizationSlugQuery) (OrganizationSlugAvailability, error)
}

// SlugAvailable admits the current verified human session and explicit policy
// without requiring membership or management permission. It rechecks policy,
// exact source projection and live session after callbacks, retaining original
// freshness. Withdrawal, changed source, outage, expiry or cancellation returns
// zero availability with an error. It performs no mutation or reservation.
func (s *Service) SlugAvailable(ctx context.Context, r SlugAvailableRequest) (out SlugAvailableResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = SlugAvailableResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !validSlug(r.Slug) || !safeID(r.CorrelationID) {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	observed, actor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	reader, ok := s.repository.(OrganizationSlugReader)
	if !ok || nilValue(reader) {
		return out, ErrUnavailable
	}
	query := OrganizationSlugQuery{TenantID: r.Authentication.TenantID, Slug: r.Slug}
	if err = s.authorizeSlugCandidate(bounded, actor, query, r.CorrelationID); err != nil {
		return out, err
	}
	before, err := reader.ReadOrganizationSlug(bounded, query)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if before.TenantID != query.TenantID || before.Slug != query.Slug {
		return out, ErrForbidden
	}
	if err = s.authorizeSlugCandidate(bounded, actor, query, r.CorrelationID); err != nil {
		return out, err
	}
	after, err := reader.ReadOrganizationSlug(bounded, query)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if before != after {
		return out, ErrForbidden
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	// Read the session after storage callbacks too: a fresh source projection
	// cannot preserve a withdrawn or replaced original session admission.
	current, currentActor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	originalSession, originalErr := observed.Session.Bindings()
	currentSession, currentErr := current.Session.Bindings()
	if currentActor != actor || originalErr != nil || currentErr != nil || originalSession.Authority.CompareCurrent(currentSession.Authority) != nil {
		return out, ErrForbidden
	}
	// Primary readers reconstruct opaque values. Compare their public immutable
	// bindings, not the private allocation identity of Session/AuthoritySnapshot.
	currentSession.Authority = originalSession.Authority
	if currentSession != originalSession {
		return out, ErrForbidden
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	return SlugAvailableResult{Available: before.Available}, nil
}

func (s *Service) authorizeSlugCandidate(ctx context.Context, actor identity.UserID, q OrganizationSlugQuery, correlation string) error {
	decision, err := s.policy.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.PolicyVersion), CorrelationID: correlation, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(SlugAvailable), Resource: authorization.Resource{Type: "organization.slug", ID: authorization.ResourceID(q.Slug)}, Tenant: authorization.TenantID(q.TenantID), Environment: authorization.Environment{Time: s.config.Clock.Now()}}})
	if err != nil {
		return publicError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.config.PolicyVersion) {
		return ErrForbidden
	}
	return nil
}
