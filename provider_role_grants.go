package organization

import (
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ProviderRoleGrantScope identifies one provider's custom role grants to one
// member. Application-owned direct and team grants have separate ownership.
type ProviderRoleGrantScope struct {
	TenantID       identity.TenantID
	OrganizationID ID
	UserID         identity.UserID
	ProviderID     ID
}

// ProviderRoleGrantInput describes an authoritative complete provider-owned set.
// Use the original durable sign-in start time and the issuer's verified assertion
// issue time; retries must retain both. A non-nil empty RoleIDs withdraws this
// source's grants. Nil means there is no authoritative replacement, so it is
// rejected. Current membership, provider and role policy must be fenced by the
// transaction owner; these values do not authenticate or authorize a mutation.
type ProviderRoleGrantInput struct {
	Scope                 ProviderRoleGrantScope
	MemberVersion         uint64
	MappingVersion        uint64
	OriginalFlowStartedAt time.Time
	AssertedAt            time.Time
	RoleIDs               []ID
}

// ProviderRoleGrantSet is an immutable, tenant-scoped replacement value. Its
// zero value is invalid. It never contains static organization roles.
type ProviderRoleGrantSet struct{ input ProviderRoleGrantInput }

// NewProviderRoleGrantSet validates and snapshots a configuration-mapped set of
// at most 100 distinct custom role IDs. It does not interpret provider claims,
// check that the role definitions are active, grant roles or write storage.
func NewProviderRoleGrantSet(input ProviderRoleGrantInput) (ProviderRoleGrantSet, error) {
	scope := input.Scope
	if !safeID(string(scope.TenantID)) || !safeID(string(scope.OrganizationID)) ||
		!safeID(string(scope.UserID)) || !safeID(string(scope.ProviderID)) ||
		input.MemberVersion == 0 || input.MappingVersion == 0 {
		return ProviderRoleGrantSet{}, ErrInvalidInput
	}
	// Use PostgreSQL's timestamp precision so a round-trip cannot turn two
	// distinct checkpoint comparisons into equal values or accept a replay.
	input.OriginalFlowStartedAt = input.OriginalFlowStartedAt.UTC()
	input.AssertedAt = input.AssertedAt.UTC()
	if !providerRoleGrantTime(input.OriginalFlowStartedAt) || !providerRoleGrantTime(input.AssertedAt) ||
		input.RoleIDs == nil || len(input.RoleIDs) > 100 {
		return ProviderRoleGrantSet{}, ErrInvalidInput
	}
	input.RoleIDs = slices.Clone(input.RoleIDs)
	slices.Sort(input.RoleIDs)
	for i, id := range input.RoleIDs {
		if !safeID(string(id)) || Role(id).Valid() || (i > 0 && input.RoleIDs[i-1] == id) {
			return ProviderRoleGrantSet{}, ErrInvalidInput
		}
	}
	return ProviderRoleGrantSet{input: input}, nil
}

func providerRoleGrantTime(value time.Time) bool {
	return value.Year() >= 1970 && value.Year() <= 9999 && value.Nanosecond()%1000 == 0
}

// Value returns the original scope and checkpoints plus a detached, sorted role
// set. The zero value returns false; it is not an empty withdrawal.
func (s ProviderRoleGrantSet) Value() (ProviderRoleGrantInput, bool) {
	if s.input.Scope.ProviderID == "" {
		return ProviderRoleGrantInput{}, false
	}
	input := s.input
	input.RoleIDs = slices.Clone(input.RoleIDs)
	return input, true
}

// CheckReplacement checks one stored predecessor from the exact same scope.
// It rejects provider, member or tenant substitution, and rejects policy or
// membership regression, older issuer evidence, and an equal/older original
// flow. An equal issuer timestamp is permitted for distinct ordered flows
// because token timestamps can have second precision. The caller must obtain
// the predecessor under its write fence; only durable recovery establishes the
// outcome of replay. A genuinely absent predecessor is handled by the caller.
func (s ProviderRoleGrantSet) CheckReplacement(previous ProviderRoleGrantSet) error {
	if s.input.Scope.ProviderID == "" || previous.input.Scope != s.input.Scope {
		return ErrInvalidInput
	}
	if s.input.MemberVersion < previous.input.MemberVersion || s.input.MappingVersion < previous.input.MappingVersion ||
		!s.input.OriginalFlowStartedAt.After(previous.input.OriginalFlowStartedAt) || s.input.AssertedAt.Before(previous.input.AssertedAt) {
		return ErrConflict
	}
	return nil
}
