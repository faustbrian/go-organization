package organization

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// InvitationExpireRequest terminalizes an exact pending invitation. Reason is
// a registered non-secret code, never free-form text. Independent owner/admin
// authentication is required; recipient credentials and proof are not authority.
type InvitationExpireRequest struct {
	Authentication                         Authentication
	CommandID                              identity.CommandID
	ID, OrganizationID                     ID
	OrganizationVersion, InvitationVersion uint64
	Reason                                 identity.PolicyReason
	CorrelationID                          string
}

// PrepareExpire admits explicit expiry before or after the natural deadline.
// The operation catalog's pending-row transition differs from natural expiry's
// pending-version projection: native execution must atomically persist the next
// terminal version, reason, canonical audit and event, invalidating every proof.
func (s *InvitationService) PrepareExpire(ctx context.Context, r InvitationExpireRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 || !safeID(string(r.Reason)) || len(r.Reason) > 64 || !slices.Contains(s.config.ExpirationReasons, r.Reason) {
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
	v, err := s.repository.ReadInvitation(bounded, InvitationQuery{Operation: InvitationExpire, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, InvitationID: r.ID})
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
	if err = s.base.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, InvitationExpire, r.CorrelationID); err != nil {
		return out, err
	}
	if bounded.Err() != nil {
		return out, bounded.Err()
	}
	if observed.ValidateAt(s.base.config.Clock.Now()) != nil || i.Version != invitationIssuedVersion(i) || i.Status != InvitationPending && i.Status != InvitationExpired {
		return out, ErrForbidden
	}
	if i.Version != r.InvitationVersion || v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	c := s.base.command(r.CommandID, InvitationExpire, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: r.Authentication.TenantID}, "")
	c.state.input.Binding.RecordID = string(i.ID)
	c.state.input.Binding.SchemaID = InvitationExpire.Descriptor().SchemaID
	c.state.input.Invitation = InvitationInput{Record: i, ExpirationReason: r.Reason}
	return c, nil
}
