package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// UpdateTeamOperationRequest selects original-key replacement of a team's bounded
// name at exact organization/team epochs. The owner allocates the command, not
// the team ID. Matching key/intent retries recover only the original outcome;
// changed IDs, versions or name conflict and unknown outcomes never reexecute.
// Authentication and the required key are borrowed opaque custody. Syntax alone
// confers no current team-write, session, membership or disclosure authority.
type UpdateTeamOperationRequest struct {
	Authentication                   Authentication
	IdempotencyKey                   identity.IdempotencyKey
	OrganizationID, TeamID           ID
	OrganizationVersion, TeamVersion uint64
	Name, CorrelationID              string
}

// DeleteTeamOperationRequest naturally repeats exact-version terminal deletion,
// without a key or caller command. Only actual original effect correlation and
// the original native receipt establish prior success; a retired/absent ID alone
// never does. Deletion cannot revive the team or retained membership bindings.
// Current manager/session, actual team-write and outcome-query policy still
// apply. Retain an unknown result's original binding for explicit recovery:
// natural syntax cannot identify an unattached or uncommitted command.
type DeleteTeamOperationRequest struct {
	Authentication                   Authentication
	OrganizationID, TeamID           ID
	OrganizationVersion, TeamVersion uint64
	CorrelationID                    string
}

// Validate checks bounded syntax and custody without IO or owner authority.
// Name retains UpdateTeamRequest's UTF-8, trimmed 1..256-byte contract.
func (r UpdateTeamOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validTeamLifecycleOperation(r.Authentication, r.OrganizationID, r.TeamID, r.OrganizationVersion, r.TeamVersion, r.CorrelationID) || !boundedText(r.Name, 256) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact positive incrementable epochs without manufacturing
// execution or historical-disclosure authority from a terminal row.
func (r DeleteTeamOperationRequest) Validate() error {
	if !validTeamLifecycleOperation(r.Authentication, r.OrganizationID, r.TeamID, r.OrganizationVersion, r.TeamVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validTeamLifecycleOperation(a Authentication, org, team ID, orgVersion, teamVersion uint64, correlation string) bool {
	return validOperationAuthentication(a, correlation) && safeID(string(org)) && safeID(string(team)) && validOperationVersions(orgVersion, teamVersion) && teamVersion > 0
}

// Format redacts credentials, key and request metadata from diagnostics.
func (UpdateTeamOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.UpdateTeamOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of custody.
func (UpdateTeamOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (UpdateTeamOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and request metadata from diagnostics.
func (DeleteTeamOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.DeleteTeamOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of custody.
func (DeleteTeamOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (DeleteTeamOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
