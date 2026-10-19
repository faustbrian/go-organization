package organization

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// InvitationRejectRequest selects an exact pending invitation and original
// versions. Authentication must independently identify its current verified
// recipient. Rejection needs neither membership nor the invitation bearer.
type InvitationRejectRequest struct {
	Authentication                         Authentication
	CommandID                              identity.CommandID
	ID, OrganizationID                     ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// PrepareReject freezes recipient admission without consuming a capability.
// Native execution must repeat current session, recipient and organization
// admission and atomically terminalize the pending row with audit and events.
func (s *InvitationService) PrepareReject(ctx context.Context, r InvitationRejectRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 {
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
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationReject, TenantID: r.Authentication.TenantID, ActorID: actor, RecipientUserID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	i := v.Record.Invitation
	if !validInvitation(i, r.Authentication.TenantID, r.OrganizationID) || i.ID != r.ID || i.RecipientUserID != actor || !v.Organization.Active || v.Organization.TenantID != r.Authentication.TenantID || v.Organization.ID != r.OrganizationID || v.Organization.Version == 0 {
		return out, ErrForbidden
	}
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationReject, r.CorrelationID); err != nil {
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
	identifier := v.RecipientIdentifier
	if v.RecipientUser.Validate(r.Authentication.TenantID) != nil || v.RecipientUser.ID != actor || v.RecipientUser.Status != identity.StatusActive || identifier.Validate(actor) != nil || identifier.ID != i.RecipientIdentifierID || identifier.Version != i.RecipientIdentifierVersion || identifier.Kind != identity.IdentifierEmail || !identifier.Verified {
		return out, ErrForbidden
	}
	c := s.base.command(r.CommandID, InvitationReject, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, v.RecipientUser, "")
	c.state.input.Binding.RecordID = string(i.ID)
	c.state.input.Binding.SchemaID = InvitationReject.Descriptor().SchemaID
	c.state.input.Invitation = InvitationInput{Record: i, RecipientIdentifier: identifier}
	return c, nil
}
