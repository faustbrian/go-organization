package organization

import "fmt"

// LeaveMemberOperationRequest is a natural-repeat self-leave selection at an
// exact original organization version. The native owner derives the human from
// Authentication, captures that member's version and allocates the command;
// there is no target, client key or caller command ID. Authentication is borrowed
// opaque custody. CorrelationID is diagnostic, not natural intent or authority.
// A repeat must reconcile actual original metadata; absent membership cannot
// prove success, unknown work must not be replayed and old intent cannot remove
// a readmitted membership. Results use StoreResult, never a new membership grant.
type LeaveMemberOperationRequest struct {
	Authentication      Authentication
	OrganizationID      ID
	OrganizationVersion uint64
	CorrelationID       string
}

// Validate checks bounded syntax and credential presence without IO, current
// authentication/membership, policy, last-owner checks, command allocation or
// outcome lookup. OrganizationVersion is positive and below MaxUint64, leaving
// room for the existing leave transition. Canonical IDs remain owner-validated;
// this syntax check neither normalizes identity nor grants historical access.
func (r LeaveMemberOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.OrganizationID)) || !validOperationVersions(r.OrganizationVersion, 0) {
		return ErrInvalidInput
	}
	return nil
}

// Format hides borrowed credentials and exact self-leave selectors.
func (LeaveMemberOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.LeaveMemberOperationRequest(redacted)"))
}

// MarshalJSON rejects implicit export of request custody.
func (LeaveMemberOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of request custody.
func (LeaveMemberOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
