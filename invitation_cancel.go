package organization

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// InvitationCancelRequest selects an exact live pending invitation and both
// original aggregate versions. The current owner/administrator is authenticated
// independently; cancellation never needs the recipient's bearer or proof.
type InvitationCancelRequest struct {
	Authentication                         Authentication
	CommandID                              identity.CommandID
	ID, OrganizationID                     ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// PrepareCancel freezes current owner/administrator admission. The native owner
// must repeat it under its existing transaction and terminally advance the
// invitation version; cryptographic validity alone must never bypass that row.
func (s *InvitationService) PrepareCancel(ctx context.Context, r InvitationCancelRequest) (out Command, err error) {
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
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationCancel, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
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
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationCancel, r.CorrelationID); err != nil {
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
	// This is an actor-owned administrative effect, not admission of or an
	// operation on the recipient's global identity. No recipient liveness or
	// current email identifier is needed to withdraw a pending invitation.
	c := s.base.command(r.CommandID, InvitationCancel, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: r.Authentication.TenantID}, "")
	c.state.input.Binding.RecordID = string(i.ID)
	c.state.input.Binding.SchemaID = InvitationCancel.Descriptor().SchemaID
	c.state.input.Invitation = InvitationInput{Record: i}
	return c, nil
}
