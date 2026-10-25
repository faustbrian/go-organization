package postgres

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
	organization "github.com/faustbrian/go-organization"
)

// Accept performs once-only invitation acceptance using the caller's original
// CommandID, exact versions and privately held proof. It prepares through the
// existing native owner, calls admit synchronously outside SQL with authenticated
// original rate facts, then executes that same preparation. A nil gate is invalid;
// gate errors are returned unchanged, panic fails unavailable, and cancellation
// denies execution. The callback must honor its bounded context. No request key,
// command allocation, automatic recovery or renewed observation is introduced.
// Independent calls may run concurrently; no preparation is shared between them.
func (s *InvitationService) Accept(ctx context.Context, r organization.InvitationAcceptRequest, network string, admit organization.InvitationAcceptAdmitter) (organization.StoreResult, error) {
	if s == nil || s.core == nil || s.root == nil || ctx == nil || admit == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return organization.StoreResult{}, err
	}
	prepared, err := s.PrepareAccept(bounded, r, network)
	if err != nil {
		return organization.StoreResult{}, err
	}
	admission, err := s.invitationAcceptAdmission(bounded, prepared)
	if err != nil {
		return organization.StoreResult{}, err
	}
	if err := invokeInvitationAcceptAdmission(bounded, admit, admission); err != nil {
		// Transport gates may return typed rate/unavailable errors. Preserve their
		// identity instead of normalizing them as a native execution failure.
		return organization.StoreResult{}, err
	}
	return s.Execute(bounded, prepared)
}

// RecoverAccept discloses only the exact original acceptance under current
// genuine recipient/session policy. It delegates to the existing native recovery
// owner, preserving outcomes and errors, including NotCommitted and Unknown.
// Save the full admission/result Binding and owning OrganizationID; a bare ID,
// current membership or absent row cannot infer historical success. This method
// neither prepares nor executes, consumes proof, sends delivery or renews expiry.
func (s *InvitationService) RecoverAccept(ctx context.Context, r organization.InvitationAcceptRecoveryRequest) (organization.StoreResult, error) {
	if s == nil || s.core == nil || s.root == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	return s.Recover(ctx, r.Authentication, InvitationRecovery{Binding: r.Binding, OrganizationID: r.OrganizationID})
}

func (s *InvitationService) invitationAcceptAdmission(ctx context.Context, prepared PreparedInvitation) (out organization.InvitationAcceptAdmission, err error) {
	defer func() {
		if recover() != nil {
			out, err = organization.InvitationAcceptAdmission{}, organization.ErrUnavailable
		}
	}()
	p := prepared.state
	if p == nil || p.service != s || p.input.Operation != organization.InvitationAccept {
		return out, organization.ErrInvalidInput
	}
	verifier, err := capability.NewService(s.config.Issuer.Crypto)
	if err != nil {
		return out, organization.ErrUnavailable
	}
	grant, err := verifier.Verify(ctx, p.input.Invitation.Proof, capability.Purpose(organization.InvitationAccept), s.config.Invitation.Audience)
	if err != nil {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		return out, organization.ErrForbidden
	}
	signed := grant.Payload()
	// The issuer's retained consumption plan authenticates the exact original
	// envelope/ID/expiry but omits IssuedAt. Reverify that same proof to obtain
	// its signed interval; current InvitationConfig.Lifetime is not original
	// issuance and must never replenish a transport rate lifetime.
	if grant.EnvelopeDigest() != p.envelope || grant.EnvelopeDigest() != p.capability.ProofFingerprint || signed.ID != p.capability.CapabilityID || !signed.ExpiresAt.Equal(p.capability.ExpiresAt) {
		return out, organization.ErrForbidden
	}
	out = organization.InvitationAcceptAdmission{Binding: p.input.Binding, OrganizationID: p.input.Organization.ID, ChallengeID: signed.ID, ChallengeLifetime: signed.ExpiresAt.Sub(signed.IssuedAt)}
	if out.Validate() != nil {
		return organization.InvitationAcceptAdmission{}, organization.ErrUnavailable
	}
	return out, ctx.Err()
}

func invokeInvitationAcceptAdmission(ctx context.Context, admit organization.InvitationAcceptAdmitter, admission organization.InvitationAcceptAdmission) (err error) {
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := admit(ctx, admission); err != nil {
		return err
	}
	return ctx.Err()
}
