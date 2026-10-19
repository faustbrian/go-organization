package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

var _ organization.InvitationListMineReader = (*InvitationRepository)(nil)

// ListMine returns current recipient-owned safe metadata through the actual
// session, directory and self-list policy owners, without organization-member
// admission or the administrator delivery-status projection.
func (s *InvitationService) ListMine(ctx context.Context, r organization.InvitationListMineRequest) (organization.InvitationListMineResult, error) {
	if s == nil {
		return organization.InvitationListMineResult{}, organization.ErrInvalidInput
	}
	return s.root.ListMine(ctx, r)
}

// ReadInvitationsMine is a trusted storage port, not authentication by claimed
// recipient ID. The public service derives this scope from its genuine session.
// The native directory owns complete current verified identifier decoding and
// its epoch. Only safe identifier projections leave that owner read.
func (r *InvitationRepository) ReadInvitationsMine(ctx context.Context, q organization.InvitationListMineQuery) (organization.InvitationListMineSnapshot, error) {
	if r == nil || ctx == nil || r.organizations == nil || !scope(string(q.TenantID)) || !scope(string(q.RecipientID)) || q.After != "" && !scope(string(q.After)) || q.Limit < 1 || q.Limit > 200 {
		return organization.InvitationListMineSnapshot{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.organizations.maximum)
	defer cancel()
	state, err := r.organizations.directory.GetIdentifierState(bounded, identity.IdentifierQuery{TenantID: q.TenantID, UserID: q.RecipientID, MaximumIdentifiers: 128})
	if err != nil {
		return organization.InvitationListMineSnapshot{}, storageError(bounded, err)
	}
	if state.User.Validate(q.TenantID) != nil || state.User.ID != q.RecipientID || state.User.Status != identity.StatusActive || state.AuthorityVersion == 0 || len(state.Identifiers) > 128 {
		return organization.InvitationListMineSnapshot{}, organization.ErrForbidden
	}
	out := organization.InvitationListMineSnapshot{Recipient: state.User, IdentifierAuthorityVersion: state.AuthorityVersion, Identifiers: make([]organization.InvitationRecipientIdentifier, 0), Invitations: make([]organization.Invitation, 0)}
	ids, versions := make([]string, 0, len(state.Identifiers)), make([]string, 0, len(state.Identifiers))
	for _, i := range state.Identifiers {
		if i.Kind != identity.IdentifierEmail || !i.Verified {
			continue
		}
		out.Identifiers = append(out.Identifiers, organization.InvitationRecipientIdentifier{ID: i.ID, Version: i.Version})
		ids = append(ids, string(i.ID))
		versions = append(versions, strconv.FormatUint(i.Version, 10))
	}
	if len(ids) == 0 {
		return out, bounded.Err()
	}
	rows, err := r.organizations.pool.Raw().Query(bounded, invitationMineSQL, string(q.TenantID), string(q.RecipientID), ids, versions, string(q.After), int32(q.Limit+1))
	if err != nil {
		return organization.InvitationListMineSnapshot{}, storageError(bounded, err)
	}
	defer rows.Close()
	for rows.Next() {
		var org organization.ID
		item := organization.Invitation{TenantID: q.TenantID}
		var identifierVersion, version, state string
		if err = rows.Scan(&org, &item.ID, &item.RecipientUserID, &item.RecipientIdentifierID, &identifierVersion, &item.CreatedBy, &item.Role, &state, &version, &item.ExpiresAt); err != nil {
			return organization.InvitationListMineSnapshot{}, storageError(bounded, err)
		}
		item.OrganizationID = org
		if item.Version, err = positive(version); err != nil {
			return organization.InvitationListMineSnapshot{}, err
		}
		if item.RecipientIdentifierVersion, err = positive(identifierVersion); err != nil {
			return organization.InvitationListMineSnapshot{}, err
		}
		switch state {
		case "pending":
			item.Status = organization.InvitationPending
		case "accepted":
			item.Status = organization.InvitationAccepted
		case "cancelled":
			item.Status = organization.InvitationCancelled
		case "rejected":
			item.Status = organization.InvitationRejected
		case "expired":
			item.Status = organization.InvitationExpired
		default:
			return organization.InvitationListMineSnapshot{}, organization.ErrUnavailable
		}
		if len(out.Invitations) >= int(q.Limit)+1 {
			return organization.InvitationListMineSnapshot{}, organization.ErrUnavailable
		}
		out.Invitations = append(out.Invitations, item)
	}
	if rows.Err() != nil {
		return organization.InvitationListMineSnapshot{}, storageError(bounded, rows.Err())
	}
	if bounded.Err() != nil {
		return organization.InvitationListMineSnapshot{}, bounded.Err()
	}
	return out, nil
}

// The directory contract bounds identifier partitions to128. Each exact indexed
// partition emits at most201 rows before the merge (<=25728 candidates); the
// final page has at most201 rows. No scan through unrelated historical email
// versions, organization memberships or delivery/capability records is needed.
// Context bounds execution even when visibility churn adds physical scan work.
// Installed PK(tenant_id,invitation_id) makes the final C-order key unique.
const invitationMineSQL = `/* organization.invitation.list-mine */
SELECT i.organization_id,i.invitation_id,i.recipient_user_id,i.recipient_identifier_id,i.recipient_identifier_version::text,i.created_by,i.role,i.state,i.version::text,i.expires_at
FROM unnest($3::text[],$4::text[]) AS verified(identifier_id,identifier_version)
CROSS JOIN LATERAL (
 SELECT organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,expires_at
 FROM organization.invitations
 WHERE tenant_id=$1 AND recipient_user_id=$2
 AND recipient_identifier_id=verified.identifier_id::identity.directory_id
 AND recipient_identifier_version=verified.identifier_version::numeric
 AND invitation_id>$5 COLLATE "C"
 ORDER BY invitation_id COLLATE "C" LIMIT $6
) i
ORDER BY i.invitation_id COLLATE "C" LIMIT $6`
