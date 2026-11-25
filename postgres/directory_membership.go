package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

const directoryMembershipField = "organization.directory-membership"

// DirectoryMembershipSource identifies a case-sensitive User resource of one
// configured provider connection and its exact local organization member.
// Source selectors carry no authentication or permission.
type DirectoryMembershipSource struct {
	TenantID                             identity.TenantID
	OrganizationID                       organization.ID
	UserID                               identity.UserID
	ProviderID, ConnectionID, ResourceID organization.ID
}

func (s DirectoryMembershipSource) validate() bool {
	return scope(string(s.TenantID)) && scope(string(s.OrganizationID)) && scope(string(s.UserID)) &&
		scope(string(s.ProviderID)) && scope(string(s.ConnectionID)) && scope(string(s.ResourceID))
}

// RecordID returns opaque child correlation for this exact, case-sensitive
// source without IO or a current membership contribution. It is stable across
// contribution versions and actions. Invalid selectors return
// organization.ErrInvalidInput and no ID. This identity grants no authority and
// is not an original receipt; callers must independently authorize recovery and
// verify the original command.
func (s DirectoryMembershipSource) RecordID() (string, error) {
	if !s.validate() {
		return "", organization.ErrInvalidInput
	}
	selectors, err := json.Marshal(s)
	if err != nil {
		return "", organization.ErrInvalidInput
	}
	record := directoryMembershipDigest("organization.directory-membership.source.v1", selectors)
	return hex.EncodeToString(record[:]), nil
}

func (s DirectoryMembershipSource) organizationQuery() organization.CredentialAuthorityQuery {
	return organization.CredentialAuthorityQuery{TenantID: s.TenantID, OrganizationID: s.OrganizationID}
}

// DirectoryMembershipAction selects one contribution transition. The zero
// value is invalid; a grant is never permission to withdraw (or vice versa).
type DirectoryMembershipAction uint8

const (
	// DirectoryMembershipGrant adds an exact source to an ordinary directory member.
	DirectoryMembershipGrant DirectoryMembershipAction = iota + 1
	// DirectoryMembershipWithdraw retires an active exact source contribution.
	DirectoryMembershipWithdraw
)

// DirectoryMembershipInput freezes the owner, target and optimistic membership
// and contribution versions for one exact service-account child. Grant needs
// the exact active User. Withdraw requires User to be zero: an independent
// account block must not prevent permanent removal of a source grant.
// Zero versions mean absence, not "any version". Capacity applies when the
// directory creates the first effective membership, never during withdrawal.
type DirectoryMembershipInput struct {
	Source                                    DirectoryMembershipSource
	ActorID                                   identity.ActorID
	User                                      identity.User
	Organization                              organization.CredentialAuthorityObservation
	MemberVersion, MemberAuthorizationVersion uint64
	ExpectedVersion                           uint64
	Action                                    DirectoryMembershipAction
	MaximumMembers, MaximumPerUser            uint64
}

// DirectoryMembershipUpdate is detached command input, not authority or an
// original receipt. It can be copied concurrently; its zero value is invalid.
type DirectoryMembershipUpdate struct {
	state *directoryMembershipUpdateState
}

type directoryMembershipUpdateState struct {
	input    DirectoryMembershipInput
	recordID string
	digest   [32]byte
}

// NewDirectoryMembershipUpdate validates and freezes input before binding it
// into the original child. It does not authenticate the source or perform IO.
func NewDirectoryMembershipUpdate(i DirectoryMembershipInput) (DirectoryMembershipUpdate, error) {
	s := i.Source
	recordID, err := s.RecordID()
	if err != nil || !scope(string(i.ActorID)) {
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	if i.Organization.Validate(s.organizationQuery(), time.Now().UTC()) != nil ||
		(i.MemberVersion == 0) != (i.MemberAuthorizationVersion == 0) || i.ExpectedVersion == math.MaxUint64 ||
		(i.MemberVersion == 0 && i.ExpectedVersion != 0) {
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	switch i.Action {
	case DirectoryMembershipGrant:
		if i.User.Validate(s.TenantID) != nil || i.User.ID != s.UserID || i.User.Status != identity.StatusActive || i.MaximumMembers == 0 || i.MaximumPerUser == 0 {
			return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
		}
	case DirectoryMembershipWithdraw:
		if i.User != (identity.User{}) {
			return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
		}
		if i.ExpectedVersion == 0 {
			return DirectoryMembershipUpdate{}, organization.ErrForbidden
		}
	default:
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(i)
	if err != nil {
		return DirectoryMembershipUpdate{}, organization.ErrInvalidInput
	}
	state := &directoryMembershipUpdateState{input: i, recordID: recordID, digest: directoryMembershipDigest("organization.directory-membership.update.v1", wire)}
	return DirectoryMembershipUpdate{state: state}, nil
}

func directoryMembershipDigest(purpose string, data []byte) [32]byte {
	return sha256.Sum256(append([]byte(purpose+"\x00"), data...))
}

// RecordID is bounded opaque child correlation, stable across source versions
// and actions. It cannot replace exact command or authentication evidence.
func (u DirectoryMembershipUpdate) RecordID() string {
	if u.state == nil {
		return ""
	}
	return u.state.recordID
}

// BeforeVersion is the expected contribution version, or zero for an absent
// contribution or invalid update. It is not the effective member version.
func (u DirectoryMembershipUpdate) BeforeVersion() uint64 {
	if u.state == nil {
		return 0
	}
	return u.state.input.ExpectedVersion
}

// AfterVersion is the next contribution version, or zero for an invalid update.
func (u DirectoryMembershipUpdate) AfterVersion() uint64 {
	if u.state == nil {
		return 0
	}
	return u.state.input.ExpectedVersion + 1
}

// Field returns the detached digest to bind before the child is reserved.
func (u DirectoryMembershipUpdate) Field() (identity.FeatureField, error) {
	if u.state == nil {
		return identity.FeatureField{}, organization.ErrInvalidInput
	}
	return identity.FeatureField{Name: directoryMembershipField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(u.state.digest[:])}}, nil
}

func (DirectoryMembershipSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryMembershipSource(redacted)"))
}

func (DirectoryMembershipInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryMembershipInput(redacted)"))
}

func (DirectoryMembershipUpdate) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryMembershipUpdate(redacted)"))
}

func directoryMembershipOperation(action DirectoryMembershipAction) identity.FeatureOperation {
	op := identity.FeatureOperation{Owner: "sso", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}
	if action == DirectoryMembershipGrant {
		op.OperationID = "identity.sso.directory-sync.apply-user-admission"
		op.SchemaID = "sso.directory-user-admission"
	} else {
		op.OperationID = "identity.sso.directory-sync.apply-user-deprovision"
		op.SchemaID = "sso.directory-user-deprovision"
	}
	return op
}

func requireDirectoryMembershipBinding(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryMembershipUpdate) error {
	if update.state == nil {
		return identity.ForbiddenError{}
	}
	if _, ok := owner.(kernel.FeatureCommitContributor); !ok {
		return identity.ForbiddenError{}
	}
	b, registration, lifecycle, err := w.FeatureScope(owner)
	if err != nil {
		return identity.ForbiddenError{}
	}
	i := update.state.input
	op := directoryMembershipOperation(i.Action)
	descriptor := kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: op.SchemaID, Version: 1}
	if registration.Contributor != descriptor || registration.Operation != op ||
		b.TenantID != i.Source.TenantID || b.UserID != i.Source.UserID || b.ActorKind != authorization.SubjectServiceAccount || b.ActorID != i.ActorID || b.RecordID != update.RecordID() ||
		lifecycle.BeforeVersion != update.BeforeVersion() || lifecycle.AfterVersion != update.AfterVersion() {
		return identity.ForbiddenError{}
	}
	spec, ok := command.Feature()
	if !ok || spec.Binding != b || spec.Operation != op {
		return identity.ForbiddenError{}
	}
	matches := 0
	for _, field := range spec.Fields {
		if field.Name != directoryMembershipField {
			continue
		}
		if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, update.state.digest[:]) {
			return identity.ForbiddenError{}
		}
		matches++
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
