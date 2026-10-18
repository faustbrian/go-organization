package organization

import (
	"context"
	"crypto/sha256"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// InvitationListMine is the authenticated recipient's safe invitation listing,
// not an organization membership check or an administrator's recipient lookup.
const InvitationListMine Operation = "identity.organization.invitation.list-mine"

// InvitationCursor is an opaque, non-authoritative continuation. Empty starts
// a page; return a supplied continuation unchanged, never across subjects.
type InvitationCursor string

// InvitationListMineRequest binds self through Authentication, never a claimed
// recipient. Limit is 1..200; Cursor is empty or a returned <=512-byte locator.
// Current verified identifier ID/version matches are required for every state.
type InvitationListMineRequest struct {
	Authentication Authentication
	Cursor         InvitationCursor
	Limit          uint32
	CorrelationID  string
}

// InvitationListMineResult owns safe invitation metadata only, without email,
// capability, delivery custody or permission to accept. All retained installed
// states are included; live pending rows project Expired at exclusive expiry.
// Pages use tenant-unique invitation IDs in bytewise C order over current state,
// not a retained snapshot. Earlier additions require restarting the listing.
type InvitationListMineResult struct {
	Invitations []Invitation
	NextCursor  InvitationCursor
}

// InvitationRecipientIdentifier is a current verified email's safe identifier
// projection. It carries no address or proof and cannot authenticate a subject.
type InvitationRecipientIdentifier struct {
	ID      identity.IdentifierID
	Version uint64
}

// InvitationListMineQuery is the trusted self scope selected after native
// session authentication. Read at most Limit+1 rows after the exclusive ID;
// Limit is 1..200. Tenant+invitation ID is the installed schema's unique key.
type InvitationListMineQuery struct {
	TenantID    identity.TenantID
	RecipientID identity.UserID
	After       ID
	Limit       uint32
}

// InvitationListMineSnapshot transfers independently owned primary projections.
// Identifiers contains the complete bounded (<=128) current verified-email
// ID/version set, sorted by ID, and IdentifierAuthorityVersion is its directory
// owner's current epoch. No membership is required. Returned invitations must
// match Recipient and a current identifier exactly; unknown states fail closed.
type InvitationListMineSnapshot struct {
	Recipient                  identity.User
	IdentifierAuthorityVersion uint64
	Identifiers                []InvitationRecipientIdentifier
	Invitations                []Invitation
}

// InvitationListMineReader is an optional additive repository capability.
// Existing InvitationRepository implementations need not implement it unless
// listing is selected. Read current primary state, honor ctx, and release rows
// before returning; never retain a positive authority cache or external locks.
type InvitationListMineReader interface {
	ReadInvitationsMine(context.Context, InvitationListMineQuery) (InvitationListMineSnapshot, error)
}

// ListMine authenticates the actual human recipient and current self-list
// policy. It needs no organization membership or recipient-selected address.
// Both decisions precede live session and exact recipient/page revalidation;
// withdrawal, outage, cancellation or original freshness expiry releases no page.
func (s *InvitationService) ListMine(ctx context.Context, r InvitationListMineRequest) (out InvitationListMineResult, err error) {
	defer func() {
		if recover() != nil {
			out, err = InvitationListMineResult{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || r.Limit < 1 || r.Limit > 200 || !safeID(r.CorrelationID) {
		return out, ErrInvalidInput
	}
	after, cursorScope, err := parseOrganizationCursor(OrganizationCursor(r.Cursor))
	if err != nil {
		return out, err
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	if after != "" && s.base.config.ValidateCanonicalID(bounded, after) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	baseScope := s.base.organizationCursorScope(r.Authentication.TenantID, actor)
	// Reuse the existing bounded keyset framing, domain-separated from the
	// organization listing. A locator grants no authority and needs no keys.
	scope := sha256.Sum256(append([]byte("organization.invitation.list-mine.cursor.v1\x00"), baseScope[:]...))
	if r.Cursor != "" && scope != cursorScope {
		return out, ErrInvalidInput
	}
	reader, ok := s.repository.(InvitationListMineReader)
	if !ok || nilValue(reader) {
		return out, ErrUnavailable
	}
	q := InvitationListMineQuery{TenantID: r.Authentication.TenantID, RecipientID: actor, After: after, Limit: r.Limit}
	before, err := reader.ReadInvitationsMine(bounded, q)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validInvitationsMine(before, q) {
		return out, ErrUnavailable
	}
	for _, i := range before.Invitations {
		if s.base.config.ValidateCanonicalID(bounded, i.ID) != nil || s.base.config.ValidateCanonicalID(bounded, i.OrganizationID) != nil {
			return out, ErrUnavailable
		}
	}
	before.Identifiers = append([]InvitationRecipientIdentifier(nil), before.Identifiers...)
	before.Invitations = append([]Invitation(nil), before.Invitations...)
	for range 2 {
		decision, e := s.base.policy.Decide(bounded, authorization.DecisionContext{PolicyRevision: authorization.Revision(s.base.config.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(q.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(InvitationListMine), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(actor)}, Environment: authorization.Environment{Time: s.base.config.Clock.Now()}}})
		if e != nil {
			return out, publicError(bounded, e)
		}
		if decision.Outcome != authorization.Allow || decision.Revision != authorization.Revision(s.base.config.PolicyVersion) {
			return out, ErrForbidden
		}
	}
	if _, current, e := s.base.authenticate(bounded, r.Authentication); e != nil || current != actor {
		if e != nil {
			return out, e
		}
		return out, ErrForbidden
	}
	afterRead, err := reader.ReadInvitationsMine(bounded, q)
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !sameInvitationsMine(before, afterRead) {
		return out, ErrForbidden
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	now := s.base.config.Clock.Now()
	if observed.ValidateAt(now) != nil {
		return out, ErrForbidden
	}
	count := len(before.Invitations)
	if count > int(r.Limit) {
		count = int(r.Limit)
	}
	out.Invitations = make([]Invitation, count)
	for n := range out.Invitations {
		out.Invitations[n] = before.Invitations[n]
		if out.Invitations[n].Status == InvitationPending && !now.Before(out.Invitations[n].ExpiresAt) {
			out.Invitations[n].Status = InvitationExpired
		}
	}
	if len(before.Invitations) > count {
		out.NextCursor = InvitationCursor(encodeOrganizationCursor(scope, out.Invitations[count-1].ID))
	}
	return out, nil
}

func validInvitationsMine(s InvitationListMineSnapshot, q InvitationListMineQuery) bool {
	if s.Recipient.Validate(q.TenantID) != nil || s.Recipient.ID != q.RecipientID || s.Recipient.Status != identity.StatusActive || s.IdentifierAuthorityVersion == 0 || len(s.Identifiers) > 128 || len(s.Invitations) > int(q.Limit)+1 {
		return false
	}
	ids := make(map[identity.IdentifierID]uint64, len(s.Identifiers))
	for n, i := range s.Identifiers {
		if !safeID(string(i.ID)) || i.Version == 0 || n > 0 && s.Identifiers[n-1].ID >= i.ID {
			return false
		}
		ids[i.ID] = i.Version
	}
	for n, i := range s.Invitations {
		if !validInvitation(i, q.TenantID, i.OrganizationID) || !safeID(string(i.OrganizationID)) || i.RecipientUserID != q.RecipientID || ids[i.RecipientIdentifierID] != i.RecipientIdentifierVersion || i.ID <= q.After || n > 0 && s.Invitations[n-1].ID >= i.ID {
			return false
		}
	}
	return true
}
func sameInvitationsMine(a, b InvitationListMineSnapshot) bool {
	if a.Recipient != b.Recipient || a.IdentifierAuthorityVersion != b.IdentifierAuthorityVersion || len(a.Identifiers) != len(b.Identifiers) || len(a.Invitations) != len(b.Invitations) {
		return false
	}
	for n := range a.Identifiers {
		if a.Identifiers[n] != b.Identifiers[n] {
			return false
		}
	}
	for n := range a.Invitations {
		if a.Invitations[n] != b.Invitations[n] {
			return false
		}
	}
	return true
}
