package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

// InvitationResendOperationRequest selects an exact pending invitation through
// one original initiating key. The native owner allocates the command, preserves
// its recipient, role and exclusive expiry, and atomically supersedes its proof.
// Matching retries recover original metadata without preparing another command,
// issuing another successor, renewing validity or redispatching delivery.
// CorrelationID is diagnostic, not initiating intent or execution authority.
type InvitationResendOperationRequest struct {
	Authentication                         Authentication
	IdempotencyKey                         identity.IdempotencyKey
	OrganizationID, InvitationID           ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// Validate checks bounded syntax and custody presence without IO, clock reads,
// authentication, key admission or proof issuance. OrganizationVersion is a
// read-only epoch; InvitationVersion must leave room for the pending successor
// and its later terminal transition, matching PrepareResend's native contract.
func (r InvitationResendOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || !safeID(string(r.InvitationID)) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 || r.InvitationVersion >= ^uint64(0)-1 {
		return ErrInvalidInput
	}
	return nil
}

// Format hides credentials, initiating keys and invitation selectors.
func (InvitationResendOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationResendOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (InvitationResendOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (InvitationResendOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// InvitationResendOperationResult retains the original command outcome even if
// a later authorized delivery-status read fails. DeliveryState describes only
// this command's original delivery, not the invitation's latest successor.
// Zero means no authorized observation; never infer Queued from it. A nonzero
// state is usable only with a committed receipt and nil error; Accepted is not
// Delivered, and an unknown provider outcome never authorizes redispatch.
// This projection contains no invitation proof or delivery effect identifier.
type InvitationResendOperationResult struct {
	StoreResult
	DeliveryState delivery.DeliveryState
}
