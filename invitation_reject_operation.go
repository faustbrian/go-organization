package organization

import "fmt"

// InvitationRejectOperationRequest selects one exact pending invitation for a
// naturally repeatable rejection, without a client key, caller command ID or
// invitation proof. The native owner allocates the command and authenticates
// the current verified intended recipient. Neither organization membership nor
// manager/Get permission substitutes for that recipient's current authority.
// Existing explicit preparation/execution contracts remain unchanged.
//
// A repeat must reconcile actual matching original command metadata under
// current tenant, session and verified-recipient authority, never infer success
// from a rejected/absent row or execute again. Unknown outcomes require existing
// native classification, not another mutation attempt. CorrelationID is
// diagnostic, not natural selection or execution authority. Results use StoreResult.
type InvitationRejectOperationRequest struct {
	Authentication                         Authentication
	OrganizationID, InvitationID           ID
	OrganizationVersion, InvitationVersion uint64
	CorrelationID                          string
}

// Validate checks bounded syntax and borrowed credential presence without IO,
// authentication, authorization, command allocation or historical lookup. Both
// versions are positive and below MaxUint64: the invitation needs one terminal
// increment, while the organization bound preserves the existing native reject
// profile's currentDomain guard even though rejection does not advance it.
// Validation alone grants neither rejection nor historical disclosure authority.
func (r InvitationRejectOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.OrganizationID)) || !safeID(string(r.InvitationID)) || !validOperationVersions(r.OrganizationVersion, r.InvitationVersion) || r.InvitationVersion == 0 {
		return ErrInvalidInput
	}
	return nil
}

// Format hides borrowed credentials and exact invitation selectors.
func (InvitationRejectOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationRejectOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (InvitationRejectOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (InvitationRejectOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
