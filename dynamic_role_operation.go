package organization

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// CreateDynamicRoleOperationRequest binds one original key to a chosen role ID,
// exact organization epoch, bounded name and ordered statements. The native
// owner allocates the command; creation has no prior role epoch. Matching retries
// recover only the original outcome, never execute again after an unknown result.
// Authentication/key and Statements are borrowed custody: an executing adapter
// must copy the complete intent before callbacks. Validate grants no authority
// and cannot decide membership in the deployment's immutable permission catalog.
type CreateDynamicRoleOperationRequest struct {
	Authentication         Authentication
	IdempotencyKey         identity.IdempotencyKey
	OrganizationID, RoleID ID
	OrganizationVersion    uint64
	Name, CorrelationID    string
	Statements             []RoleStatement
}

// UpdateDynamicRoleOperationRequest replaces the complete name and ordered
// statements at exact organization/role epochs under one original key. Empty
// statements intentionally grant nothing; replacement affects existing bindings.
// Borrowed custody must be frozen before callbacks. Current manager/session,
// role-write, catalog and original-outcome query authority remain native-owned.
type UpdateDynamicRoleOperationRequest struct {
	Authentication                   Authentication
	IdempotencyKey                   identity.IdempotencyKey
	OrganizationID, RoleID           ID
	OrganizationVersion, RoleVersion uint64
	Name, CorrelationID              string
	Statements                       []RoleStatement
}

// DeleteDynamicRoleOperationRequest naturally repeats terminal retirement at
// exact organization/role epochs, without a key, caller command or replacement.
// Retirement denies all bindings and cannot reuse the role ID. Only matching
// original effect correlation and the actual native receipt prove prior success;
// a missing/deleted role alone never does. Current manager/session, role-write
// and query authority still apply. Retain an unknown result's original binding
// for explicit recovery; natural syntax cannot identify an unattached command.
type DeleteDynamicRoleOperationRequest struct {
	Authentication                   Authentication
	OrganizationID, RoleID           ID
	OrganizationVersion, RoleVersion uint64
	CorrelationID                    string
}

// Validate checks bounded syntax and custody without IO, catalog or authority.
func (r CreateDynamicRoleOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validDynamicRoleOperation(r.Authentication, r.OrganizationID, r.RoleID, r.OrganizationVersion, 0, r.CorrelationID) || !boundedText(r.Name, 256) || !validDynamicRoleOperationStatements(r.Statements) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact incrementable epochs and complete replacement syntax.
func (r UpdateDynamicRoleOperationRequest) Validate() error {
	if r.IdempotencyKey == (identity.IdempotencyKey{}) || !validDynamicRoleOperation(r.Authentication, r.OrganizationID, r.RoleID, r.OrganizationVersion, r.RoleVersion, r.CorrelationID) || r.RoleVersion == 0 || !boundedText(r.Name, 256) || !validDynamicRoleOperationStatements(r.Statements) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact terminal selectors, not execution or disclosure rights.
func (r DeleteDynamicRoleOperationRequest) Validate() error {
	if !validDynamicRoleOperation(r.Authentication, r.OrganizationID, r.RoleID, r.OrganizationVersion, r.RoleVersion, r.CorrelationID) || r.RoleVersion == 0 {
		return ErrInvalidInput
	}
	return nil
}

func validDynamicRoleOperation(a Authentication, org, role ID, orgVersion, roleVersion uint64, correlation string) bool {
	return validOperationAuthentication(a, correlation) && safeID(string(org)) && safeID(string(role)) && !Role(role).Valid() && validOperationVersions(orgVersion, roleVersion)
}

func validDynamicRoleOperationStatements(statements []RoleStatement) bool {
	// Preserve ValidateRoleStatements' native 64-statement/8192-byte command
	// field contract without inventing a neutral permission catalog. The adapter
	// must still validate registered permissions before preparation/evaluation.
	if len(statements) > 64 {
		return false
	}
	seen := make(map[RoleStatement]struct{}, len(statements))
	for _, statement := range statements {
		if !safeID(statement.PermissionID) || !safeID(string(statement.ResourceID)) || strings.ContainsAny(string(statement.ResourceID), "*?") || statement.Effect != authorization.Allow && statement.Effect != authorization.Deny {
			return false
		}
		if _, duplicate := seen[statement]; duplicate {
			return false
		}
		seen[statement] = struct{}{}
	}
	wire, err := json.Marshal(statements)
	return err == nil && len(wire) <= 8192
}

// Format redacts credentials, original key and replacement intent.
func (CreateDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.CreateDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (CreateDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (CreateDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials, original key and replacement intent.
func (UpdateDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.UpdateDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (UpdateDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (UpdateDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and exact historical selectors.
func (DeleteDynamicRoleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.DeleteDynamicRoleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental export of borrowed custody.
func (DeleteDynamicRoleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of custody.
func (DeleteDynamicRoleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
