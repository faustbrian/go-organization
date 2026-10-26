package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// AssignTeamDynamicRoleOperationRequest binds one original key to a custom role
// for an exact current team. Obtain organization, role, team and binding epochs
// from GetDynamicRole with TargetTeamID. BindingVersion zero means never assigned;
// otherwise use the retained live/tombstone version. The native owner allocates
// the command, not these identities. Actual permission also requires compatible
// current organization/team membership: this request never names a human target
// or grants management authority. Matching keys disclose original outcomes under
// current manager/session, role-action and query policy, never renewed execution.
// Authentication/key are borrowed opaque custody, not proof of authorization.
type AssignTeamDynamicRoleOperationRequest struct {
	Authentication                                                Authentication
	IdempotencyKey                                                identity.IdempotencyKey
	OrganizationID, RoleID, TeamID                                ID
	OrganizationVersion, RoleVersion, TeamVersion, BindingVersion uint64
	CorrelationID                                                 string
}

// RevokeTeamDynamicRoleOperationRequest naturally repeats revocation of one
// exact team-role binding, without a key or caller command. Only correlated
// original effects and the real native receipt establish success, never an
// absent/inactive binding. Old epochs cannot reach a later assignment or revive
// a terminal team or incompatible membership. Current manager/session, actual
// role-action and query authority remain required. Unknown outcomes do not
// authorize replay; retain their original binding for explicit recovery when
// natural syntax cannot identify an unattached or uncommitted command.
type RevokeTeamDynamicRoleOperationRequest struct {
	Authentication                                                Authentication
	OrganizationID, RoleID, TeamID                                ID
	OrganizationVersion, RoleVersion, TeamVersion, BindingVersion uint64
	CorrelationID                                                 string
}

// Validate checks bounded syntax and key custody without IO, canonical-ID
// policy, current authentication, catalog lookup or execution authority.
func (r AssignTeamDynamicRoleOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validTeamRoleBindingOperation(r.Authentication, r.OrganizationID, r.RoleID, r.TeamID, r.OrganizationVersion, r.RoleVersion, r.TeamVersion, r.BindingVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact positive binding syntax, not original-history ownership
// or current native team, manager, session, role-action or query authority.
func (r RevokeTeamDynamicRoleOperationRequest) Validate() error {
	if r.BindingVersion == 0 || !validTeamRoleBindingOperation(r.Authentication, r.OrganizationID, r.RoleID, r.TeamID, r.OrganizationVersion, r.RoleVersion, r.TeamVersion, r.BindingVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validTeamRoleBindingOperation(a Authentication, org, role, team ID, orgVersion, roleVersion, teamVersion, bindingVersion uint64, correlation string) bool {
	// Preserve TeamRoleBindingRequest's bounds. Unlike direct assignment's
	// observed member epoch, team mutation advances the shared team epoch.
	return validOperationAuthentication(a, correlation) && safeID(string(org)) && safeID(string(role)) && !Role(role).Valid() && safeID(string(team)) && validOperationVersions(orgVersion, bindingVersion) && roleVersion > 0 && roleVersion < ^uint64(0) && teamVersion > 0 && teamVersion < ^uint64(0)
}

// Format redacts credentials, original key and exact team-assignment intent.
func (AssignTeamDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.AssignTeamDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (AssignTeamDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (AssignTeamDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and exact original team-binding selectors.
func (RevokeTeamDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.RevokeTeamDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (RevokeTeamDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (RevokeTeamDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
