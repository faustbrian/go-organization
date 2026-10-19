package postgres

import (
	"context"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	organization "github.com/faustbrian/go-organization"
)

// InvitationDeliveryStatus observes the original resend command's delivery
// effect, never the invitation's latest effect. State is delivery-owned metadata,
// not proof of receipt or permission to redeliver. No address or proof is exposed.
type InvitationDeliveryStatus struct {
	EffectID delivery.IntentID
	State    delivery.DeliveryState
}

// InvitationResendResult preserves the command outcome even when a subsequent
// metadata read fails. Delivery is nil for errors/unknown/noncommitted outcomes;
// it is never synthesized as queued. Replayed/recovered receipts describe the
// original transition and original delivery, not a new invitation or new send.
type InvitationResendResult struct {
	organization.StoreResult
	Delivery *InvitationDeliveryStatus
}

// PrepareResend freezes the genuine owner/administrator and exact original
// recipient, role, deadline and pending version. Install
// InvitationResendMigrationSource first. Only acknowledged Execute preparation
// may generate a successor, using the existing kernel/issuer/delivery owners.
func (s *InvitationService) PrepareResend(ctx context.Context, r organization.InvitationResendRequest, network string) (PreparedInvitation, error) {
	if s == nil {
		return PreparedInvitation{}, organization.ErrInvalidInput
	}
	c, err := s.root.PrepareResend(ctx, r)
	if err != nil {
		return PreparedInvitation{}, err
	}
	return s.prepare(ctx, c, network)
}

// ExecuteResend executes only an original prepared resend and observes its
// bounded delivery state under current authority. Generic Execute remains
// compatible but supplies only the unchanged core receipt/IDs contract.
// Preserve the original preparation and Recovery handle for exact retries.
func (s *InvitationService) ExecuteResend(ctx context.Context, p PreparedInvitation) (InvitationResendResult, error) {
	if s == nil || ctx == nil || p.state == nil || p.state.service != s || p.state.input.Operation != organization.InvitationResend {
		return InvitationResendResult{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	r, err := s.Execute(bounded, p)
	if err != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return InvitationResendResult{StoreResult: r}, err
	}
	a := organization.Authentication{TenantID: p.state.input.Binding.TenantID, Bearer: p.state.input.Bearer}
	out, err := s.resendDelivery(bounded, a, InvitationRecovery{Binding: p.state.input.Binding, OrganizationID: p.state.input.Organization.ID}, r)
	if p.state.input.Session.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return InvitationResendResult{StoreResult: r}, organization.ErrForbidden
	}
	return out, err
}

// RecoverResend uses the sole existing recovery authority and a current genuine
// session. It never prepares, signs or enqueues. After later resends/acceptance,
// it still observes only this original command's delivery effect.
func (s *InvitationService) RecoverResend(ctx context.Context, a organization.Authentication, recovery InvitationRecovery) (InvitationResendResult, error) {
	if s == nil || ctx == nil {
		return InvitationResendResult{}, organization.ErrInvalidInput
	}
	if recovery.Binding.OperationID != string(organization.InvitationResend) {
		return InvitationResendResult{}, organization.ErrForbidden
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	r, err := s.Recover(bounded, a, recovery)
	if err != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return InvitationResendResult{StoreResult: r}, err
	}
	return s.resendDelivery(bounded, a, recovery, r)
}

func (s *InvitationService) resendDelivery(ctx context.Context, a organization.Authentication, recovery InvitationRecovery, r organization.StoreResult) (InvitationResendResult, error) {
	out := InvitationResendResult{StoreResult: r}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	b := recovery.Binding
	if r.Receipt.Binding != b || r.Receipt.Feature == nil || r.Receipt.Feature.Operation != organization.InvitationResend.Descriptor() {
		return out, organization.ErrUnavailable
	}
	var effect delivery.IntentID
	err := s.actor.repository.pool.Raw().QueryRow(bounded, `SELECT delivery_effect_id FROM organization.command_effects WHERE command_id=$1 AND tenant_id=$2 AND organization_id=$3 AND invitation_id=$4 AND user_id=$5 AND actor_id=$6 AND operation=$7 AND before_version=$8::numeric AND after_version=$9::numeric`, string(b.CommandID), string(b.TenantID), string(recovery.OrganizationID), b.RecordID, string(b.UserID), string(b.ActorID), b.OperationID, strconv.FormatUint(r.Receipt.Feature.BeforeVersion, 10), strconv.FormatUint(r.Receipt.Feature.AfterVersion, 10)).Scan(&effect)
	if err != nil {
		return out, storageError(bounded, err)
	}
	i := organization.InvitationDelivery{Invitation: organization.Invitation{TenantID: b.TenantID, RecipientUserID: b.UserID}, EffectID: effect}
	metadata, err := s.repository.deliveryMetadata(bounded, identity.UserID(b.ActorID), i)
	if err != nil {
		return out, err
	}
	// Status policy is another external callback. Repeat the existing current
	// session/manager/scoped authority and query fence before releasing it.
	latest, err := s.Recover(bounded, a, recovery)
	if err != nil {
		return out, err
	}
	if latest.Receipt.Outcome != identity.CommitOutcomeCommitted || latest.Receipt.Binding != r.Receipt.Binding || latest.Receipt.Feature == nil || *latest.Receipt.Feature != *r.Receipt.Feature {
		return out, organization.ErrUnavailable
	}
	out.Delivery = &InvitationDeliveryStatus{EffectID: effect, State: metadata.State}
	return out, nil
}
