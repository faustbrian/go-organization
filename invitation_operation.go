package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// InvitationSendOperationRequest is a transport-neutral initiating-key send.
// The durable owner allocates command and invitation IDs. The exact original
// key binds organization/version and the intended user's existing verified
// email identifier; it never binds a submitted email address or claimed actor.
// Role and expiry retain the native InvitationConfig policy. Matching retries
// recover only the original outcome, without refreshing authority, allocating
// replacement installed IDs, generating another proof or redelivering it.
// CorrelationID is diagnostic input, not initiating intent or replay authority.
type InvitationSendOperationRequest struct {
	Authentication        Authentication
	IdempotencyKey        identity.IdempotencyKey
	OrganizationID        ID
	OrganizationVersion   uint64
	RecipientUserID       identity.UserID
	RecipientIdentifierID identity.IdentifierID
	CorrelationID         string
}

// Validate checks bounded syntax and custody presence without IO, allocation,
// authentication, recipient verification, key admission or execution authority.
func (r InvitationSendOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || r.OrganizationVersion == 0 || !safeID(string(r.RecipientUserID)) || !safeID(string(r.RecipientIdentifierID)) {
		return ErrInvalidInput
	}
	return nil
}

// Format hides initiating keys, credentials and recipient selectors.
func (InvitationSendOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationSendOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (InvitationSendOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (InvitationSendOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
