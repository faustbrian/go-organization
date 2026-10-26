package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// AddTeamMemberOperationRequest admits one exact organization membership to one
// team under an original key. All four versions retain TeamMemberRequest's
// semantics: zero MembershipVersion means never bound; otherwise supply the
// retained binding version. The owner allocates the command, not the target IDs.
// Matching keys recover only the original outcome under current manager/session
// authority. Changed IDs or versions conflict; unknown results never reexecute.
// Authentication and the required key are borrowed opaque custody.
type AddTeamMemberOperationRequest struct {
	Authentication                                                                 Authentication
	IdempotencyKey                                                                 identity.IdempotencyKey
	OrganizationID, TeamID                                                         ID
	UserID                                                                         identity.UserID
	OrganizationVersion, TeamVersion, OrganizationMemberVersion, MembershipVersion uint64
	CorrelationID                                                                  string
}

// RemoveTeamMemberOperationRequest naturally repeats an exact team binding
// removal, with no client key or command. Original retained effect correlation,
// not absence alone, identifies success. Current manager/session authority and
// native disclosure checks apply on every attempt. A newer organization
// admission or team binding cannot be removed using these old versions.
// Retain an unknown result's binding for explicit original recovery: natural
// syntax cannot identify an uncommitted or unattached command.
type RemoveTeamMemberOperationRequest struct {
	Authentication                                                                 Authentication
	OrganizationID, TeamID                                                         ID
	UserID                                                                         identity.UserID
	OrganizationVersion, TeamVersion, OrganizationMemberVersion, MembershipVersion uint64
	CorrelationID                                                                  string
}

// Validate checks bounded syntax and custody without IO, current authority,
// canonical-ID policy, key admission or command allocation.
func (r AddTeamMemberOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validTeamMemberOperation(r.Authentication, r.OrganizationID, r.TeamID, r.UserID, r.OrganizationVersion, r.TeamVersion, r.OrganizationMemberVersion, r.MembershipVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact positive binding syntax without manufacturing replay
// authority from an absent or tombstoned membership.
func (r RemoveTeamMemberOperationRequest) Validate() error {
	if r.MembershipVersion == 0 || !validTeamMemberOperation(r.Authentication, r.OrganizationID, r.TeamID, r.UserID, r.OrganizationVersion, r.TeamVersion, r.OrganizationMemberVersion, r.MembershipVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validTeamMemberOperation(a Authentication, org, team ID, user identity.UserID, orgVersion, teamVersion, memberVersion, bindingVersion uint64, correlation string) bool {
	return validOperationAuthentication(a, correlation) && safeID(string(org)) && safeID(string(team)) && safeID(string(user)) && validOperationVersions(orgVersion, bindingVersion) && teamVersion > 0 && teamVersion < ^uint64(0) && memberVersion > 0
}

// Format redacts credentials, key and request metadata from diagnostics.
func (AddTeamMemberOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.AddTeamMemberOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of custody.
func (AddTeamMemberOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (AddTeamMemberOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and request metadata from diagnostics.
func (RemoveTeamMemberOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.RemoveTeamMemberOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of custody.
func (RemoveTeamMemberOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (RemoveTeamMemberOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
