package organization

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// InvitationResendRequest selects an exact pending invitation and organization
// policy epoch. The original recipient, verified identifier, static member role
// and exclusive deadline are preserved; callers cannot redirect delivery or
// extend the grant. Retain CommandID and the prepared command for exact retries.
type InvitationResendRequest struct {
	Authentication                         Authentication
	CommandID                              identity.CommandID
	ID, OrganizationID                     ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// PrepareResend freezes current owner/administrator and original recipient
// admission without issuing a proof or writing state. The native adapter must
// atomically supersede the predecessor and issue/enqueue exactly one successor
// for version+1 through the existing capability, delivery and coordinator owners.
// The predecessor remains usable until that single commit, never alongside its
// successor. Historical recovery must not regenerate or redeliver either grant.
func (s *InvitationService) PrepareResend(ctx context.Context, r InvitationResendRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	// A new pending version must leave room for its later terminal transition.
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 || r.InvitationVersion >= ^uint64(0)-1 {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.base.config.MaximumDuration)
	defer cancel()
	for _, id := range []ID{r.ID, r.OrganizationID} {
		if s.base.config.ValidateCanonicalID(bounded, id) != nil {
			return out, ErrInvalidInput
		}
	}
	observed, actor, err := s.base.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationResend, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(View{Organization: v.Organization, Actor: v.Actor}, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner && v.Actor.Role != RoleAdministrator {
		return out, ErrForbidden
	}
	i := v.Record.Invitation
	if !validInvitation(i, r.Authentication.TenantID, r.OrganizationID) || i.ID != r.ID {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationResend, r.CorrelationID); err != nil {
		return out, err
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if observed.ValidateAt(s.base.config.Clock.Now()) != nil || i.Status != InvitationPending || !s.base.config.Clock.Now().Before(i.ExpiresAt) {
		return out, ErrForbidden
	}
	if i.Version != r.InvitationVersion || v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	recipient, identifier := v.RecipientUser, v.RecipientIdentifier
	if recipient.Validate(r.Authentication.TenantID) != nil || recipient.ID != i.RecipientUserID || recipient.Status != identity.StatusActive || identifier.Validate(recipient.ID) != nil || identifier.ID != i.RecipientIdentifierID || identifier.Version != i.RecipientIdentifierVersion || identifier.Kind != identity.IdentifierEmail || !identifier.Verified {
		return out, ErrForbidden
	}
	if v.Target.Active {
		return out, ErrConflict
	}
	// Rotation replaces this same pending grant rather than adding another;
	// a reached pending-count limit must not turn replacement into new issuance.
	c := s.base.command(r.CommandID, InvitationResend, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, recipient, RoleMember)
	c.state.input.Binding.RecordID = string(i.ID)
	c.state.input.Binding.SchemaID = InvitationResend.Descriptor().SchemaID
	c.state.input.Invitation = InvitationInput{Record: i, RecipientIdentifier: identifier, MaximumPending: s.config.MaximumPending}
	return c, nil
}
