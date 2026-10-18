package organization

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// ListOrganizations is the current authenticated subject's organization read.
// It is not an active-organization selection or an arbitrary-user lookup.
const ListOrganizations Operation = "identity.organization.list"

// OrganizationCursor is an opaque, non-authoritative keyset locator. Empty
// starts a listing; only use a returned cursor unchanged. It binds tenant,
// authenticated subject and deployed policy, not a snapshot or membership grant.
type OrganizationCursor string

// ListOrganizationsRequest lists only the current authenticated human's active
// organizations. Limit is 1..200 with no default (the operation's typed catalog
// bound). Cursor is empty or a canonical <=512-byte returned continuation.
// Pages use bytewise organization-ID order over current committed state; earlier
// additions require restarting. Unknown authority/errors yield no partial page.
type ListOrganizationsRequest struct {
	Authentication Authentication
	Cursor         OrganizationCursor
	Limit          uint32
	CorrelationID  string
}

// ListOrganizationsResult owns its bounded organization snapshots. NextCursor
// derives only from the last returned visible ID and is empty at the observed
// end. Neither a snapshot nor continuation is current authorization evidence.
type ListOrganizationsResult struct {
	Organizations []Organization
	NextCursor    OrganizationCursor
}

// OrganizationListQuery is a trusted storage query generated after session
// authentication. MaximumRows is the configured per-user membership cap (1..1000),
// not the requested output size. Return at most MaximumRows+1 candidates after
// the exclusive ID in ascending bytewise order; the extra row detects a changed
// deployment cap without falsely declaring EOF. No arbitrary target is exposed
// through the public authenticated list request.
type OrganizationListQuery struct {
	TenantID    identity.TenantID
	ActorID     identity.UserID
	After       ID
	MaximumRows uint32
}

// OrganizationListEntry is an owned current active organization/self-member
// projection. Native readers must also verify that Member.AuthorizationVersion
// is the current organization-scoped authority, not an unrelated global epoch.
type OrganizationListEntry struct {
	Organization Organization
	Member       Member
}

// OrganizationListReader is an additive optional repository capability. Existing
// Repository implementations remain source-compatible; selecting listing on a
// reader without this capability returns ErrUnavailable. Reads must honor ctx,
// release rows/locks before returning, and use current primary state without a
// positive cache. The authenticated service owns policy filtering/disclosure.
type OrganizationListReader interface {
	ReadOrganizations(context.Context, OrganizationListQuery) ([]OrganizationListEntry, error)
}

// ListOrganizations authenticates self and filters only explicit initial Deny
// decisions. Captured allows must still allow at final policy admission; current
// session, exact organization/member snapshots and original freshness are then
// rechecked after callbacks. Scan work is bounded by MaximumPerUser, never by an
// unbounded search for a full output page. No mutation or selection is performed.
func (s *Service) ListOrganizations(ctx context.Context, r ListOrganizationsRequest) (out ListOrganizationsResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = ListOrganizationsResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || r.Limit < 1 || r.Limit > 200 || !safeID(r.CorrelationID) {
		return out, ErrInvalidInput
	}
	after, cursorScope, err := parseOrganizationCursor(r.Cursor)
	if err != nil {
		return out, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if after != "" && s.config.ValidateCanonicalID(bounded, after) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	scope := s.organizationCursorScope(r.Authentication.TenantID, actor)
	if r.Cursor != "" && cursorScope != scope {
		return out, ErrInvalidInput
	}
	reader, ok := s.repository.(OrganizationListReader)
	if !ok || nilValue(reader) {
		return out, ErrUnavailable
	}
	query := OrganizationListQuery{TenantID: r.Authentication.TenantID, ActorID: actor, After: after, MaximumRows: uint32(s.config.MaximumPerUser)}
	entries, err := reader.ReadOrganizations(bounded, query)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if len(entries) > int(query.MaximumRows) {
		return out, ErrLimit
	}
	// The supplied reader transfers snapshots, never mutation custody. Capture
	// them before calling external policy, and release no partially built output.
	entries = append([]OrganizationListEntry(nil), entries...)
	for i, entry := range entries {
		org := entry.Organization
		if !validView(View{Organization: org, Actor: entry.Member}, query.TenantID, org.ID, actor) {
			return out, ErrForbidden
		}
		if !safeID(string(org.ID)) || !validSlug(org.Slug) || !boundedText(org.Name, 256) || org.ID <= after || i > 0 && entries[i-1].Organization.ID >= org.ID {
			return out, ErrUnavailable
		}
		if s.config.ValidateCanonicalID(bounded, org.ID) != nil {
			return out, ErrUnavailable
		}
	}
	visible := make([]Organization, 0, len(entries))
	for _, entry := range entries {
		allowed, e := s.organizationListDecision(bounded, actor, entry.Organization, r.CorrelationID)
		if e != nil {
			return out, e
		}
		if allowed {
			visible = append(visible, entry.Organization)
		}
	}
	for _, org := range visible {
		allowed, e := s.organizationListDecision(bounded, actor, org, r.CorrelationID)
		if e != nil {
			return out, e
		}
		if !allowed {
			return out, ErrForbidden
		}
	}
	if _, current, e := s.authenticate(bounded, r.Authentication); e != nil || current != actor {
		if e != nil {
			return out, e
		}
		return out, ErrForbidden
	}
	fresh, err := reader.ReadOrganizations(bounded, query)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if len(fresh) != len(entries) {
		return out, ErrForbidden
	}
	for i := range fresh {
		if fresh[i] != entries[i] {
			return out, ErrForbidden
		}
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	count := len(visible)
	if count > int(r.Limit) {
		count = int(r.Limit)
	}
	result := ListOrganizationsResult{Organizations: make([]Organization, count)}
	for i := range result.Organizations {
		org := visible[i]
		org.ID, org.TenantID = ID(strings.Clone(string(org.ID))), identity.TenantID(strings.Clone(string(org.TenantID)))
		org.Name, org.Slug = strings.Clone(org.Name), strings.Clone(org.Slug)
		result.Organizations[i] = org
	}
	if len(visible) > count {
		result.NextCursor = encodeOrganizationCursor(scope, result.Organizations[count-1].ID)
	}
	return result, nil
}

func (s *Service) organizationListDecision(ctx context.Context, actor identity.UserID, org Organization, correlation string) (bool, error) {
	decision, err := s.policy.Decide(ctx, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.PolicyVersion), CorrelationID: correlation, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(ListOrganizations), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(org.ID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(org.Version, 10))}}, Tenant: authorization.TenantID(org.TenantID), Environment: authorization.Environment{Time: s.config.Clock.Now()}}})
	if err != nil {
		return false, publicError(ctx, err)
	}
	if err = ctx.Err(); err != nil {
		return false, err
	}
	if decision.Revision != authorization.Revision(s.config.PolicyVersion) {
		return false, ErrForbidden
	}
	if decision.Outcome == authorization.Deny {
		return false, nil
	}
	if decision.Outcome != authorization.Allow {
		return false, ErrForbidden
	}
	return true, nil
}

func (s *Service) organizationCursorScope(tenant identity.TenantID, actor identity.UserID) [32]byte {
	// This public framing only detects scope mismatch; it grants no authority
	// and needs no signing key, state store or independent cursor owner. Current
	// session/membership/policy is mandatory even for a caller-crafted position.
	h := sha256.New()
	_, _ = h.Write([]byte("organization.list.cursor.v1\x00"))
	for _, value := range []string{string(tenant), string(actor), s.config.PolicyID} {
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	var version [8]byte
	binary.BigEndian.PutUint64(version[:], s.config.PolicyVersion)
	_, _ = h.Write(version[:])
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest
}

func encodeOrganizationCursor(scope [32]byte, after ID) OrganizationCursor {
	data := make([]byte, 33+len(after))
	data[0] = 1
	copy(data[1:33], scope[:])
	copy(data[33:], after)
	return OrganizationCursor(base64.RawURLEncoding.EncodeToString(data))
}

func parseOrganizationCursor(cursor OrganizationCursor) (ID, [32]byte, error) {
	var scope [32]byte
	if cursor == "" {
		return "", scope, nil
	}
	if len(cursor) > 512 {
		return "", scope, ErrInvalidInput
	}
	data, err := base64.RawURLEncoding.Strict().DecodeString(string(cursor))
	if err != nil || len(data) < 34 || len(data) > 161 || data[0] != 1 || base64.RawURLEncoding.EncodeToString(data) != string(cursor) || !safeID(string(data[33:])) {
		return "", scope, ErrInvalidInput
	}
	copy(scope[:], data[1:33])
	return ID(data[33:]), scope, nil
}
