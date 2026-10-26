package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// InvitationExpireOperationRequest selects an exact pending invitation for
// naturally repeatable terminal expiry, without a client key, caller command ID
// or recipient proof. The native owner allocates the original command, admits
// the current owner/administrator and checks Reason against the original
// InvitationConfig.ExpirationReasons. Existing explicit preparation is unchanged.
//
// Repetition must disclose only actual matching original command metadata under
// current original-manager/session authority, never infer success from expired
// state. Changed organization epoch or reason conflicts; an unknown outcome does
// not authorize another execution. CorrelationID is diagnostic, not part of the
// natural selection or execution authority. Results use StoreResult.
type InvitationExpireOperationRequest struct {
	Authentication                         Authentication
	OrganizationID, InvitationID           ID
	OrganizationVersion, InvitationVersion uint64
	Reason                                 identity.PolicyReason
	CorrelationID                          string
}

// Validate checks bounded syntax and borrowed credential presence without IO,
// authentication, authorization, command allocation or historical lookup. Both
// versions are positive and below MaxUint64, preserving native expiry's current
// organization guard and space for the terminal invitation increment. Reason
// retains the original InvitationConfig's 64-byte non-secret-code syntax; only
// that configured owner can authorize a registered reason. Validation alone
// grants neither terminal expiry nor historical disclosure authority.
func (r InvitationExpireOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.OrganizationID)) || !safeID(string(r.InvitationID)) || !validOperationVersions(r.OrganizationVersion, r.InvitationVersion) || r.InvitationVersion == 0 || !safeID(string(r.Reason)) || len(r.Reason) > 64 {
		return ErrInvalidInput
	}
	return nil
}

// Format hides borrowed credentials, exact invitation selectors and reason.
func (InvitationExpireOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationExpireOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (InvitationExpireOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (InvitationExpireOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
