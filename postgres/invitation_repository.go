package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	"github.com/jackc/pgx/v5"
)

// InvitationRepositoryConfig selects the exact retained policy revision of the
// real delivery status owner. It must match that owner's configuration; no
// delivery permission is inferred from an invitation ID or recipient metadata.
type InvitationRepositoryConfig struct{ DeliveryPolicyVersion uint64 }

// InvitationRepository reads this owner's primary tables and borrows existing
// identity and delivery owners for their projections. It owns no coordinator,
// transaction, cache, provider or shutdown. Initialize/migrate its borrowed
// owners before use. Concurrent independent reads honor one enclosing budget.
type InvitationRepository struct {
	organizations *Repository
	delivery      *deliverypg.EnqueueService
	policyVersion uint64
}

var _ organization.InvitationRepository = (*InvitationRepository)(nil)

// NewInvitationRepository constructs the selected read/preparation port without
// IO. The caller retains pool, delivery owner and key lifetimes.
func NewInvitationRepository(base *Repository, status *deliverypg.EnqueueService, c InvitationRepositoryConfig) (*InvitationRepository, error) {
	if base == nil || base.pool == nil || base.pool.Raw() == nil || base.directory == nil || status == nil || c.DeliveryPolicyVersion == 0 {
		return nil, organization.ErrInvalidInput
	}
	return &InvitationRepository{organizations: base, delivery: status, policyVersion: c.DeliveryPolicyVersion}, nil
}

func (r *InvitationRepository) ReadInvitation(ctx context.Context, q organization.InvitationQuery) (organization.InvitationSnapshot, error) {
	if ctx == nil || r == nil || r.organizations == nil || !scope(string(q.TenantID)) || !scope(string(q.ActorID)) || !scope(string(q.OrganizationID)) || !scope(string(q.InvitationID)) || q.Cursor != "" || q.Limit != 0 {
		return organization.InvitationSnapshot{}, organization.ErrInvalidInput
	}
	if q.Operation != organization.InvitationSend && q.Operation != organization.InvitationAccept && q.Operation != organization.InvitationGet {
		return organization.InvitationSnapshot{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.organizations.maximum)
	defer cancel()
	var v organization.InvitationSnapshot
	if q.Operation == organization.InvitationAccept {
		if q.RecipientUserID != q.ActorID || q.RecipientIdentifierID != "" {
			return v, organization.ErrInvalidInput
		}
		var version string
		err := r.organizations.pool.Raw().QueryRow(bounded, `SELECT slug,name,version::text FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active'`, string(q.TenantID), string(q.OrganizationID)).Scan(&v.Organization.Slug, &v.Organization.Name, &version)
		if err != nil {
			return v, storageError(bounded, err)
		}
		v.Organization.ID, v.Organization.TenantID, v.Organization.Active = q.OrganizationID, q.TenantID, true
		if v.Organization.Version, err = positive(version); err != nil {
			return organization.InvitationSnapshot{}, err
		}
	} else {
		op := organization.Get
		if q.Operation == organization.InvitationSend {
			if !scope(string(q.RecipientUserID)) || !scope(string(q.RecipientIdentifierID)) {
				return v, organization.ErrInvalidInput
			}
			op = organization.AddMember
		}
		current, err := r.organizations.Read(bounded, organization.Query{Operation: op, TenantID: q.TenantID, ActorID: q.ActorID, OrganizationID: q.OrganizationID, TargetID: q.RecipientUserID})
		if err != nil {
			return v, err
		}
		if current.Actor.Role != organization.RoleOwner {
			return v, organization.ErrForbidden
		}
		v.Organization, v.Actor, v.Target = current.Organization, current.Actor, current.Target
	}
	if q.Operation != organization.InvitationSend {
		row := r.organizations.pool.Raw().QueryRow(bounded, invitationSelect+` WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3`, string(q.TenantID), string(q.OrganizationID), string(q.InvitationID))
		i, err := scanInvitation(row, q.TenantID, q.OrganizationID)
		if err != nil {
			return organization.InvitationSnapshot{}, storageError(bounded, err)
		}
		v.Record = i
		if q.Operation == organization.InvitationGet {
			v.Record, err = r.deliveryMetadata(bounded, q.ActorID, i)
			if err != nil {
				return organization.InvitationSnapshot{}, err
			}
			return v, bounded.Err()
		}
		if i.Invitation.RecipientUserID != q.ActorID {
			return organization.InvitationSnapshot{}, organization.ErrForbidden
		}
		q.RecipientIdentifierID = i.Invitation.RecipientIdentifierID
		var errTarget error
		v.Target, errTarget = r.currentTarget(bounded, q.TenantID, q.OrganizationID, q.RecipientUserID)
		if errTarget != nil {
			return organization.InvitationSnapshot{}, errTarget
		}
	}
	recipient, err := r.resolveRecipient(bounded, q.TenantID, q.RecipientUserID, q.RecipientIdentifierID)
	if err != nil {
		return organization.InvitationSnapshot{}, err
	}
	v.RecipientUser, v.RecipientIdentifier = recipient.User, recipient.Identifier
	if q.Operation == organization.InvitationSend {
		var pending int64
		err = r.organizations.pool.Raw().QueryRow(bounded, `SELECT count(*) FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND state='pending' AND expires_at>clock_timestamp()`, string(q.TenantID), string(q.OrganizationID)).Scan(&pending)
		if err != nil {
			return organization.InvitationSnapshot{}, storageError(bounded, err)
		}
		if pending < 0 {
			return organization.InvitationSnapshot{}, organization.ErrUnavailable
		}
		v.PendingCount = uint64(pending)
	}
	if bounded.Err() != nil {
		return organization.InvitationSnapshot{}, bounded.Err()
	}
	return v, nil
}

// resolveRecipient uses the public directory partition (bounded by its128-item
// contract) only to locate an exact identifier. ResolveRecipient then owns
// verified eligibility and every independent security epoch. A torn observation
// conflicts rather than silently upgrading the original recipient selection.
func (r *InvitationRepository) resolveRecipient(ctx context.Context, tenant identity.TenantID, user identity.UserID, id identity.IdentifierID) (kernel.RecipientRecord, error) {
	state, err := r.organizations.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: tenant, UserID: user, MaximumIdentifiers: 128})
	if err != nil {
		return kernel.RecipientRecord{}, storageError(ctx, err)
	}
	for n, i := range state.Identifiers {
		if i.ID != id {
			continue
		}
		if i.Kind != identity.IdentifierEmail || !i.Verified {
			return kernel.RecipientRecord{}, organization.ErrForbidden
		}
		recipient, err := r.organizations.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: tenant, UserID: user, Kind: identity.IdentifierEmail, CanonicalValue: i.CanonicalValue, Eligibility: kernel.RecipientVerified})
		if err != nil {
			return kernel.RecipientRecord{}, storageError(ctx, err)
		}
		if recipient.Suppressed {
			return kernel.RecipientRecord{}, organization.ErrForbidden
		}
		if recipient.Validate() != nil {
			return kernel.RecipientRecord{}, organization.ErrUnavailable
		}
		verification := state.Verifications[n]
		// RecipientRecord normalizes driver time locations to UTC; compare
		// the authenticated instant, not time.Time's location pointer.
		verificationMatches := recipient.Verification.IdentifierID == verification.IdentifierID && recipient.Verification.State == verification.State && recipient.Verification.Version == verification.Version && recipient.Verification.VerifiedAt.Equal(verification.VerifiedAt)
		if recipient.User != state.User || recipient.Identifier != i || recipient.IdentifierAuthorityVersion != state.AuthorityVersion || !verificationMatches {
			return kernel.RecipientRecord{}, organization.ErrConflict
		}
		return recipient, nil
	}
	return kernel.RecipientRecord{}, organization.ErrForbidden
}

func (r *InvitationRepository) currentTarget(ctx context.Context, tenant identity.TenantID, org organization.ID, user identity.UserID) (organization.Member, error) {
	m := organization.Member{TenantID: tenant, OrganizationID: org, UserID: user}
	var version, authority string
	err := r.organizations.pool.Raw().QueryRow(ctx, `SELECT role,state='active',version::text,authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(tenant), string(org), string(user)).Scan(&m.Role, &m.Active, &version, &authority)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, nil
	}
	if err != nil {
		return organization.Member{}, storageError(ctx, err)
	}
	if m.Version, err = positive(version); err != nil {
		return organization.Member{}, err
	}
	if m.AuthorizationVersion, err = positive(authority); err != nil {
		return organization.Member{}, err
	}
	return m, nil
}

const invitationSelect = `SELECT invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version::text,created_by,role,state,version::text,expires_at,delivery_effect_id FROM organization.invitations`

type invitationScanner interface{ Scan(...any) error }

func scanInvitation(row invitationScanner, tenant identity.TenantID, org organization.ID) (organization.InvitationDelivery, error) {
	v := organization.InvitationDelivery{Invitation: organization.Invitation{TenantID: tenant, OrganizationID: org}}
	i := &v.Invitation
	var identifierVersion, version, state string
	err := row.Scan(&i.ID, &i.RecipientUserID, &i.RecipientIdentifierID, &identifierVersion, &i.CreatedBy, &i.Role, &state, &version, &i.ExpiresAt, &v.EffectID)
	if err != nil {
		return organization.InvitationDelivery{}, err
	}
	if i.Version, err = positive(version); err != nil {
		return organization.InvitationDelivery{}, err
	}
	if i.RecipientIdentifierVersion, err = positive(identifierVersion); err != nil {
		return organization.InvitationDelivery{}, err
	}
	switch state {
	case "pending":
		i.Status = organization.InvitationPending
	case "accepted":
		i.Status = organization.InvitationAccepted
	default:
		return organization.InvitationDelivery{}, organization.ErrUnavailable
	}
	return v, nil
}

func (r *InvitationRepository) deliveryMetadata(ctx context.Context, actor identity.UserID, i organization.InvitationDelivery) (organization.InvitationDelivery, error) {
	tenant, user := i.Invitation.TenantID, i.Invitation.RecipientUserID
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(r.policyVersion), CorrelationID: "organization.invitation.metadata", Request: authorization.Request{Tenant: authorization.TenantID(tenant), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: "identity.delivery.status-get", Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(user)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	observed, err := r.delivery.StatusGet(ctx, delivery.StatusGetRequest{TenantID: delivery.TenantID(tenant), IntentID: i.EffectID}, user, caller)
	if err != nil {
		if ctx.Err() != nil {
			return organization.InvitationDelivery{}, ctx.Err()
		}
		if errors.Is(err, delivery.ErrForbidden) || errors.Is(err, delivery.ErrNotFound) {
			return organization.InvitationDelivery{}, organization.ErrForbidden
		}
		return organization.InvitationDelivery{}, organization.ErrUnavailable
	}
	i.State = observed.State
	return i, nil
}

// ListInvitations closes primary rows before invoking the existing delivery
// status owner. The1..100 bound also bounds per-item owner reads/callbacks;
// one outer budget rejects an incomplete page instead of releasing partial data.
func (r *InvitationRepository) ListInvitations(ctx context.Context, q organization.InvitationQuery) (organization.InvitationPage, error) {
	if ctx == nil || r == nil || r.organizations == nil || q.Operation != organization.InvitationList || !scope(string(q.TenantID)) || !scope(string(q.ActorID)) || !scope(string(q.OrganizationID)) || q.InvitationID != "" || q.RecipientUserID != "" || q.RecipientIdentifierID != "" || q.Limit < 1 || q.Limit > 100 || q.Cursor != "" && !scope(string(q.Cursor)) {
		return organization.InvitationPage{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.organizations.maximum)
	defer cancel()
	v, err := r.organizations.Read(bounded, organization.Query{Operation: organization.Get, TenantID: q.TenantID, ActorID: q.ActorID, OrganizationID: q.OrganizationID})
	if err != nil {
		return organization.InvitationPage{}, err
	}
	if v.Actor.Role != organization.RoleOwner {
		return organization.InvitationPage{}, organization.ErrForbidden
	}
	rows, err := r.organizations.pool.Raw().Query(bounded, invitationSelect+` WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id>$3 COLLATE "C" ORDER BY invitation_id COLLATE "C" LIMIT $4`, string(q.TenantID), string(q.OrganizationID), string(q.Cursor), int32(q.Limit+1))
	if err != nil {
		return organization.InvitationPage{}, storageError(bounded, err)
	}
	defer rows.Close()
	page := organization.InvitationPage{Organization: v.Organization, Actor: v.Actor}
	for rows.Next() {
		item, err := scanInvitation(rows, q.TenantID, q.OrganizationID)
		if err != nil {
			return organization.InvitationPage{}, storageError(bounded, err)
		}
		if len(page.Invitations) == int(q.Limit) {
			page.NextCursor = page.Invitations[len(page.Invitations)-1].Invitation.ID
			break
		}
		page.Invitations = append(page.Invitations, item)
	}
	if rows.Err() != nil {
		return organization.InvitationPage{}, storageError(bounded, rows.Err())
	}
	rows.Close()
	for n, item := range page.Invitations {
		page.Invitations[n], err = r.deliveryMetadata(bounded, q.ActorID, item)
		if err != nil {
			return organization.InvitationPage{}, err
		}
	}
	if bounded.Err() != nil {
		return organization.InvitationPage{}, bounded.Err()
	}
	return page, nil
}
