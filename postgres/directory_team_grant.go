package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

const directoryTeamGrantField = "organization.directory-team-membership"

// DirectoryTeamGrantScope is one case-sensitive source contribution to one
// pre-existing member/team. IDs retain their exact spelling and are bounded by
// identity's directory-ID contract. Scope metadata is not external authority.
type DirectoryTeamGrantScope struct {
	TenantID                          identity.TenantID
	OrganizationID                    organization.ID
	ProviderID, ConnectionID, GroupID organization.ID
	TeamID                            organization.ID
	UserID                            identity.UserID
}

func (s DirectoryTeamGrantScope) validate() bool {
	return scope(string(s.TenantID)) && scope(string(s.OrganizationID)) && scope(string(s.ProviderID)) &&
		scope(string(s.ConnectionID)) && scope(string(s.GroupID)) && scope(string(s.TeamID)) && scope(string(s.UserID))
}

// RecordID identifies the complete case-sensitive source scope without IO or a
// current grant. It preserves the existing v1 update identity for original-command
// recovery after withdrawal. This opaque correlation is not authority or a receipt.
// Invalid scopes return an empty identity and ErrInvalidInput.
func (s DirectoryTeamGrantScope) RecordID() (string, error) {
	if !s.validate() {
		return "", organization.ErrInvalidInput
	}
	source, err := json.Marshal(s)
	if err != nil {
		return "", organization.ErrInvalidInput
	}
	record := sha256.Sum256(append([]byte("organization.directory-team-source.v1\x00"), source...))
	return hex.EncodeToString(record[:]), nil
}

// DirectoryTeamGrantInput freezes a membership-only add or withdrawal. All
// observed target versions must still match at application. ExpectedVersion is
// the independent source-row epoch, with zero meaning an absent row. Distinct
// admitted commands always advance that epoch, including retained withdrawals;
// original-command replay/recovery belongs to the identity coordinator.
// ActorID must be the SSO owner's already admitted service account, not a user.
type DirectoryTeamGrantInput struct {
	Scope                                     DirectoryTeamGrantScope
	ActorID                                   identity.ActorID
	User                                      identity.User
	OrganizationVersion, CredentialVersion    uint64
	MemberVersion, MemberAuthorizationVersion uint64
	TeamVersion, ExpectedVersion              uint64
	Active                                    bool
}

// DirectoryTeamGrantUpdate is immutable command input, not authentication or a
// receipt. Construct it with NewDirectoryTeamGrantUpdate; zero is invalid.
type DirectoryTeamGrantUpdate struct{ state *directoryTeamGrantState }

type directoryTeamGrantState struct {
	input    DirectoryTeamGrantInput
	recordID string
	digest   [32]byte
}

// NewDirectoryTeamGrantUpdate bounds input before hashing and snapshots one
// exact source operation. It performs no IO or permission admission.
func NewDirectoryTeamGrantUpdate(input DirectoryTeamGrantInput) (DirectoryTeamGrantUpdate, error) {
	if !input.Scope.validate() || !scope(string(input.ActorID)) || input.User.Validate(input.Scope.TenantID) != nil ||
		input.User.ID != input.Scope.UserID || input.User.Status != identity.StatusActive || input.OrganizationVersion == 0 ||
		input.CredentialVersion == 0 || input.MemberVersion == 0 || input.MemberAuthorizationVersion == 0 ||
		input.TeamVersion == 0 || input.ExpectedVersion == math.MaxUint64 {
		return DirectoryTeamGrantUpdate{}, organization.ErrInvalidInput
	}
	recordID, err := input.Scope.RecordID()
	if err != nil {
		return DirectoryTeamGrantUpdate{}, err
	}
	wire, err := json.Marshal(input)
	if err != nil {
		return DirectoryTeamGrantUpdate{}, organization.ErrInvalidInput
	}
	digest := sha256.Sum256(append([]byte("organization.directory-team-update.v1\x00"), wire...))
	return DirectoryTeamGrantUpdate{&directoryTeamGrantState{input: input, recordID: recordID, digest: digest}}, nil
}

// RecordID identifies the complete source scope, independent of action and
// version. It is bounded opaque correlation, never an authority credential.
func (u DirectoryTeamGrantUpdate) RecordID() string {
	if u.state == nil {
		return ""
	}
	return u.state.recordID
}

// BeforeVersion returns the expected source epoch, or zero for invalid input.
func (u DirectoryTeamGrantUpdate) BeforeVersion() uint64 {
	if u.state == nil {
		return 0
	}
	return u.state.input.ExpectedVersion
}

// AfterVersion returns the next source epoch, or zero for invalid input.
func (u DirectoryTeamGrantUpdate) AfterVersion() uint64 {
	if u.state == nil {
		return 0
	}
	return u.state.input.ExpectedVersion + 1
}

// Field returns detached digest bytes to bind into the original child command.
// It discloses no source identifiers and grants no apply authority.
func (u DirectoryTeamGrantUpdate) Field() (identity.FeatureField, error) {
	if u.state == nil {
		return identity.FeatureField{}, organization.ErrInvalidInput
	}
	return identity.FeatureField{Name: directoryTeamGrantField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: bytes.Clone(u.state.digest[:])}}, nil
}

func (DirectoryTeamGrantUpdate) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamGrantUpdate(redacted)"))
}
func (DirectoryTeamGrantScope) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamGrantScope(redacted)"))
}
func (DirectoryTeamGrantInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamGrantInput(redacted)"))
}

func directoryTeamGrantOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso", OperationID: "identity.sso.directory-sync.apply-child", SchemaID: "sso.directory-team-membership", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser, VersionPolicy: identity.FeatureVersionSequential}
}

func requireDirectoryTeamGrantBinding(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamGrantUpdate) error {
	if update.state == nil {
		return identity.ForbiddenError{}
	}
	b, registration, lifecycle, err := w.FeatureScope(owner)
	spec, ok := command.Feature()
	i := update.state.input
	descriptor := kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.directory-team-membership", Version: 1}
	if err != nil || !ok || registration.Contributor != descriptor || registration.Operation != directoryTeamGrantOperation() ||
		spec.Operation != registration.Operation || spec.Binding != b || b.TenantID != i.Scope.TenantID || b.UserID != i.Scope.UserID ||
		b.ActorKind != authorization.SubjectServiceAccount || b.ActorID != i.ActorID || b.RecordID != update.RecordID() ||
		lifecycle.BeforeVersion != update.BeforeVersion() || lifecycle.AfterVersion != update.AfterVersion() {
		return identity.ForbiddenError{}
	}
	_, final := owner.(kernel.FeatureCommitContributor)
	if !final {
		return identity.ForbiddenError{}
	}
	matches := 0
	for _, field := range spec.Fields {
		if field.Name == directoryTeamGrantField {
			if field.Value.Kind != identity.FeatureBytes || !bytes.Equal(field.Value.Bytes, update.state.digest[:]) {
				return identity.ForbiddenError{}
			}
			matches++
		}
	}
	if matches != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// ApplyDirectoryTeamGrantUpdate changes only the exact source row in the SSO
// child participant's original Work. It requires that participant's final
// commit phase, unchanged command custody and exact source digest. The SSO
// owner must already admit and fence its service-account permission, provider,
// connection and mapping generation; this method cannot establish those facts.
// Call after SSO identity locks, propagate every error, and call
// RequireDirectoryTeamGrantUpdate in CheckFeatureCommit. No local membership,
// team policy, role grant, cursor, audit or organization epoch is mutated here.
func (r *Repository) ApplyDirectoryTeamGrantUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamGrantUpdate) error {
	if r == nil || r.pool == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := requireDirectoryTeamGrantBinding(w, owner, command, update); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i := update.state.input
	if err := r.requireDirectoryTeamGrantTarget(ctx, w, owner, i); err != nil {
		return err
	}
	s := i.Scope
	args := []any{string(s.TenantID), string(s.OrganizationID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID), string(s.UserID), strconv.FormatUint(update.AfterVersion(), 10), strconv.FormatUint(i.MemberVersion, 10), i.Active}
	var affected int64
	var err error
	if i.ExpectedVersion == 0 {
		affected, err = w.Exec(ctx, `INSERT INTO organization.directory_team_grants(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id,version,organization_member_version,active)
VALUES($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10) ON CONFLICT DO NOTHING`, args...)
	} else {
		args = append(args, strconv.FormatUint(i.ExpectedVersion, 10))
		affected, err = w.Exec(ctx, `UPDATE organization.directory_team_grants SET version=$8::numeric,organization_member_version=$9::numeric,active=$10
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND group_id=$5 AND team_id=$6 AND user_id=$7 AND version=$11::numeric`, args...)
	}
	if err != nil {
		return err
	}
	if affected != 1 {
		return identity.ConflictError{}
	}
	return r.RequireDirectoryTeamGrantUpdate(ctx, w, owner, command, update)
}

// RequireDirectoryTeamGrantUpdate verifies the exact provisional source effect
// and original target fences during the selected SSO participant's synchronous
// Apply or final CheckFeatureCommit invocation. FeatureScope remains available
// in both phases; Apply-only command custody is separately checked by Apply.
// This read-only fence neither renews admission nor proves external source
// validity. Propagate errors so the coordinator rolls back all child effects.
func (r *Repository) RequireDirectoryTeamGrantUpdate(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamGrantUpdate) error {
	if r == nil || r.pool == nil || ctx == nil {
		return identity.ForbiddenError{}
	}
	if err := requireDirectoryTeamGrantBinding(w, owner, command, update); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i := update.state.input
	if err := r.requireDirectoryTeamGrantTarget(ctx, w, owner, i); err != nil {
		return err
	}
	return requireDirectoryTeamGrantRow(ctx, w, update)
}

func requireDirectoryTeamGrantRow(ctx context.Context, w kernel.Work, update DirectoryTeamGrantUpdate) error {
	i := update.state.input
	s := i.Scope
	rows, err := w.Query(ctx, `SELECT version::text,organization_member_version::text,active FROM organization.directory_team_grants
WHERE tenant_id=$1 AND organization_id=$2 AND provider_id=$3 AND connection_id=$4 AND group_id=$5 AND team_id=$6 AND user_id=$7 FOR SHARE`, string(s.TenantID), string(s.OrganizationID), string(s.ProviderID), string(s.ConnectionID), string(s.GroupID), string(s.TeamID), string(s.UserID))
	var version, member string
	var active bool
	if err := one(rows, err, &version, &member, &active); err != nil {
		return err
	}
	if version != strconv.FormatUint(update.AfterVersion(), 10) || member != strconv.FormatUint(i.MemberVersion, 10) || active != i.Active {
		return identity.ForbiddenError{}
	}
	return nil
}

func (r *Repository) requireDirectoryTeamGrantTarget(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, i DirectoryTeamGrantInput) error {
	if err := w.RequireActiveTargetUser(ctx, owner, i.User); err != nil {
		return err
	}
	s := i.Scope
	var version, credential string
	rows, err := w.Query(ctx, `SELECT version::text,credential_version::text FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2 AND state='active' FOR SHARE`, string(s.TenantID), string(s.OrganizationID))
	if err := one(rows, err, &version, &credential); err != nil {
		return err
	}
	if version != strconv.FormatUint(i.OrganizationVersion, 10) || credential != strconv.FormatUint(i.CredentialVersion, 10) {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT t.version::text FROM organization.teams t JOIN organization.team_identities ti USING(tenant_id,organization_id,team_id)
WHERE t.tenant_id=$1 AND t.organization_id=$2 AND t.team_id=$3 AND ti.deleted_version IS NULL FOR SHARE OF t,ti`, string(s.TenantID), string(s.OrganizationID), string(s.TeamID))
	if err := one(rows, err, &version); err != nil {
		return err
	}
	if version != strconv.FormatUint(i.TeamVersion, 10) {
		return identity.ForbiddenError{}
	}
	var member, authorizationVersion string
	rows, err = w.Query(ctx, `SELECT version::text,authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active' FOR SHARE`, string(s.TenantID), string(s.OrganizationID), string(s.UserID))
	if err := one(rows, err, &member, &authorizationVersion); err != nil {
		return err
	}
	if member != strconv.FormatUint(i.MemberVersion, 10) || authorizationVersion != strconv.FormatUint(i.MemberAuthorizationVersion, 10) {
		return identity.ForbiddenError{}
	}
	scoped, err := OrganizationAuthorityScope(s.TenantID, s.OrganizationID, s.UserID)
	if err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, scoped, i.MemberAuthorizationVersion, r.maximum); err != nil {
		return authorityError(err)
	}
	return nil
}
