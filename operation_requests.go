package organization

import (
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// CreateOperationRequest is the transport-neutral keyed create operation.
// The durable owner allocates the organization and command IDs only when the
// original scoped key is admitted. Matching retries recover that command;
// changed intent conflicts, and unknown outcomes never allocate another ID.
// Authentication and the single required key are opaque borrowed custody.
// Name/Slug use CreateRequest's bounds; no tenant or actor override exists.
type CreateOperationRequest struct {
	Authentication            Authentication
	IdempotencyKey            identity.IdempotencyKey
	Name, Slug, CorrelationID string
}

// AddMemberOperationRequest is the transport-neutral keyed membership admission.
// Expected versions and role have MemberRequest's semantics. A retry preserves
// the original key and intent; it does not obtain a fresh authority observation
// or alter a retained command after an ambiguous result.
type AddMemberOperationRequest struct {
	Authentication                     Authentication
	IdempotencyKey                     identity.IdempotencyKey
	OrganizationID                     ID
	UserID                             identity.UserID
	Role                               Role
	OrganizationVersion, MemberVersion uint64
	CorrelationID                      string
}

// RemoveMemberOperationRequest is a naturally repeatable exact-version removal,
// not a keyed operation. There is deliberately no client key or command ID.
// The durable owner retains its original natural-request correlation and
// historical receipt; an absent membership alone cannot prove prior success.
// Current authentication/authorization and last-owner protection still apply
// to every attempt and historical disclosure.
type RemoveMemberOperationRequest struct {
	Authentication                     Authentication
	OrganizationID                     ID
	UserID                             identity.UserID
	OrganizationVersion, MemberVersion uint64
	CorrelationID                      string
}

// OperationRecoveryRequest asks only for the original safe command outcome.
// Binding is original correlation, never execution or result-access authority.
// Current authentication and disclosure policy must be checked by the owner;
// recovery must not rebuild, resubmit or renew the original mutation.
type OperationRecoveryRequest struct {
	Authentication Authentication
	Binding        identity.CommandBinding
}

// Validate checks bounded syntax and custody presence without owner IO,
// authentication, authorization, key admission or command allocation.
func (r CreateOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !boundedText(r.Name, 256) || !validSlug(r.Slug) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks bounded syntax; it does not prove current membership,
// authority, expected versions or durable outcome.
func (r AddMemberOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || !safeID(string(r.UserID)) || !r.Role.Valid() || !validOperationVersions(r.OrganizationVersion, r.MemberVersion) {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks bounded exact-version removal syntax without inventing
// replay authority from an absent or tombstoned membership.
func (r RemoveMemberOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.OrganizationID)) || !safeID(string(r.UserID)) || !validOperationVersions(r.OrganizationVersion, r.MemberVersion) || r.MemberVersion == 0 {
		return ErrInvalidInput
	}
	return nil
}

// Validate limits recovery to this selected profile and original tenant scope.
// A structurally valid binding still confers no disclosure permission.
func (r OperationRecoveryRequest) Validate() error {
	op := Operation(r.Binding.OperationID)
	if op != Create && op != AddMember && op != RemoveMember || r.Binding.ActorKind != authorization.SubjectUser || r.Binding.TenantID != r.Authentication.TenantID || r.Binding.ValidateFor(op.Descriptor()) != nil || !validOperationAuthentication(r.Authentication, r.Binding.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validOperationAuthentication(a Authentication, correlation string) bool {
	if !safeID(string(a.TenantID)) || !safeID(correlation) {
		return false
	}
	_, err := session.ParseToken(a.Bearer.Token())
	return err == nil
}

func validOperationVersions(organization, member uint64) bool {
	return organization > 0 && organization < ^uint64(0) && member < ^uint64(0)
}

// Format redacts credentials, keys and request values from diagnostics.
func (CreateOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.CreateOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport/persistence of direct custody.
func (CreateOperationRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export of direct custody.
func (CreateOperationRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts credentials, keys and request values from diagnostics.
func (AddMemberOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.AddMemberOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport/persistence of direct custody.
func (AddMemberOperationRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export of direct custody.
func (AddMemberOperationRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts credentials and request values from diagnostics.
func (RemoveMemberOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.RemoveMemberOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport/persistence of direct custody.
func (RemoveMemberOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of direct custody.
func (RemoveMemberOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// Format redacts credentials and original command correlation.
func (OperationRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.OperationRecoveryRequest(redacted)"))
}

// MarshalJSON rejects accidental transport/persistence of direct custody.
func (OperationRecoveryRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export of direct custody.
func (OperationRecoveryRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
