package organization

import (
	"fmt"

	identity "github.com/faustbrian/go-identity"
)

// AssignDynamicRoleOperationRequest binds one original key to an exact direct
// custom-role assignment for a current organization member. BindingVersion zero
// selects a never-assigned binding; otherwise use the observed live/tombstone
// version. The native owner allocates the command, not the role or target IDs.
// Matching keys recover only original metadata under current manager/session,
// actual role-action and query authority. They never renew a grant or reexecute
// an unknown outcome. Authentication/key are borrowed opaque custody; syntax
// alone proves neither current membership, a registered role nor permission.
type AssignDynamicRoleOperationRequest struct {
	Authentication                                                              Authentication
	IdempotencyKey                                                              identity.IdempotencyKey
	OrganizationID, RoleID                                                      ID
	UserID                                                                      identity.UserID
	OrganizationVersion, RoleVersion, OrganizationMemberVersion, BindingVersion uint64
	CorrelationID                                                               string
}

// RevokeDynamicRoleOperationRequest naturally repeats revocation of one exact
// direct binding, without a key or caller command. Original effect correlation
// and the actual native receipt, never absence/tombstones alone, prove success.
// A newer assignment or organization admission cannot be revoked by these old
// epochs. Current manager/session, actual role-action and outcome-query authority
// still apply. Retain an unknown result's original binding for explicit recovery:
// natural syntax cannot identify an unattached or uncommitted command.
type RevokeDynamicRoleOperationRequest struct {
	Authentication                                                              Authentication
	OrganizationID, RoleID                                                      ID
	UserID                                                                      identity.UserID
	OrganizationVersion, RoleVersion, OrganizationMemberVersion, BindingVersion uint64
	CorrelationID                                                               string
}

// Validate checks bounded syntax/custody without IO, canonical-ID policy,
// authentication, catalog lookup, command allocation or execution authority.
func (r AssignDynamicRoleOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validRoleBindingOperation(r.Authentication, r.OrganizationID, r.RoleID, r.UserID, r.OrganizationVersion, r.RoleVersion, r.OrganizationMemberVersion, r.BindingVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact positive binding syntax, not original-history ownership
// or current authority. The observed membership epoch is positive-only.
func (r RevokeDynamicRoleOperationRequest) Validate() error {
	if r.BindingVersion == 0 || !validRoleBindingOperation(r.Authentication, r.OrganizationID, r.RoleID, r.UserID, r.OrganizationVersion, r.RoleVersion, r.OrganizationMemberVersion, r.BindingVersion, r.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validRoleBindingOperation(a Authentication, org, role ID, user identity.UserID, orgVersion, roleVersion, memberVersion, bindingVersion uint64, correlation string) bool {
	// RoleBindingRequest observes membership without incrementing its version.
	// Preserve that admission epoch's positive-only bound, unlike the binding's
	// incrementable epoch; revocation/assignment cannot renew old membership.
	return validOperationAuthentication(a, correlation) && safeID(string(org)) && safeID(string(role)) && !Role(role).Valid() && safeID(string(user)) && validOperationVersions(orgVersion, bindingVersion) && roleVersion > 0 && roleVersion < ^uint64(0) && memberVersion > 0
}

// Format redacts credentials, original key and exact assignment intent.
func (AssignDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.AssignDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (AssignDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (AssignDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and exact original binding selectors.
func (RevokeDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.RevokeDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (RevokeDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (RevokeDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
