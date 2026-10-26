package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// CreateTeamOperationRequest selects original-key creation of one empty team.
// OrganizationID, the caller-chosen canonical TeamID, exact organization version
// and bounded Name retain CreateTeamRequest's semantics. Authentication selects
// the actual actor; no caller command, actor override or membership is supplied.
// The native owner allocates the command and enforces current manager/session
// authority, canonical IDs, configured team limits and atomic effects.
//
// Matching key/intent retries classify only the original command under current
// disclosure authority, including from a fresh session or reconstructed service.
// Changed team ID, name or version conflicts. An unknown outcome never permits
// new execution or renewed authority. Credentials and the one required key are
// opaque borrowed custody; CorrelationID is diagnostic rather than key intent.
// Existing explicit preparation/execution APIs and StoreResult are unchanged.
type CreateTeamOperationRequest struct {
	Authentication         Authentication
	IdempotencyKey         identity.IdempotencyKey
	OrganizationID, TeamID ID
	OrganizationVersion    uint64
	Name, CorrelationID    string
}

// Validate checks bounded syntax and credential/key presence without IO,
// authentication, canonical-ID policy, authorization, key admission or command
// allocation. Name retains the existing 1..256-byte bounded-text contract and
// OrganizationVersion must leave room for the native policy-epoch increment.
// Syntax alone proves neither team creation nor original-history authority.
func (r CreateTeamOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || !safeID(string(r.TeamID)) || !validOperationVersions(r.OrganizationVersion, 0) || !boundedText(r.Name, 256) {
		return ErrInvalidInput
	}
	return nil
}

// Format redacts credential, key and request metadata from diagnostics.
func (CreateTeamOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.CreateTeamOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport or persistence of direct custody.
func (CreateTeamOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of direct custody.
func (CreateTeamOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
