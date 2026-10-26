package organization

import "fmt"

// InvitationCancelOperationRequest selects one exact pending invitation for a
// naturally repeatable cancellation, without a client key or command ID. The
// native owner allocates the original command and authenticates the current
// owner/administrator independently of the invitation recipient. Recipient
// withdrawal must not prevent revocation; no recipient credential or proof is
// requested. Existing explicit preparation/execution contracts are unchanged.
//
// A repeat must reconcile actual matching original command metadata under
// current tenant, actor and organization authority, never infer success from a
// cancelled/absent row or execute again. Unknown outcomes remain unknown until
// the existing native owner classifies them. CorrelationID is diagnostic, not
// part of the natural selection or execution authority. Results use StoreResult.
type InvitationCancelOperationRequest struct {
	Authentication                         Authentication
	OrganizationID, InvitationID           ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// Validate checks bounded syntax and borrowed credential presence without IO,
// authentication, authorization, command allocation or historical lookup. Both
// versions are positive and below MaxUint64: the invitation needs one terminal
// increment, while the organization bound preserves the existing native cancel
// profile's currentDomain guard even though cancellation does not advance it.
// Validation alone never grants revocation or historical disclosure authority.
func (r InvitationCancelOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.OrganizationID)) || !safeID(string(r.InvitationID)) || !validOperationVersions(r.OrganizationVersion, r.InvitationVersion) || r.InvitationVersion == 0 {
		return ErrInvalidInput
	}
	return nil
}

// Format hides borrowed credentials and exact invitation selectors.
func (InvitationCancelOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationCancelOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (InvitationCancelOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (InvitationCancelOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
