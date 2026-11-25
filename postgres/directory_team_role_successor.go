package postgres

import (
	"context"
	"encoding/binary"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// RecordDirectoryTeamRoleSuccessor records the owner version verified by this
// role child's exact original Work. Call after Apply in the same transaction,
// retaining the original final fences. Install the role successor migration
// first. Ordinary Group and legacy role writers remain unchanged.
func (r *Repository) RecordDirectoryTeamRoleSuccessor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, update DirectoryTeamRoleUpdate, locked DirectoryTeamRoleLock) error {
	if r == nil || r.pool == nil || ctx == nil || locked.state == nil || !locked.state.applied {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if err := requireDirectoryTeamRoleLock(w, owner, command, update, locked); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	selected := update.state.grant.state.input
	spec, _ := command.Feature() // The exact role Work and original command were checked above.
	binding := spec.Binding
	digest := directoryTeamRoleSuccessorBinding(update.state.source, binding)
	_, err := w.Exec(ctx, recordDirectoryMembershipSuccessorSQL,
		string(binding.CommandID), string(binding.TenantID), string(selected.Scope.OrganizationID), string(binding.UserID), string(binding.ActorID), binding.OperationID, digest[:],
		strconv.FormatUint(update.state.grant.BeforeVersion(), 10), strconv.FormatUint(update.state.grant.AfterVersion(), 10),
		strconv.FormatUint(selected.OrganizationVersion, 10), strconv.FormatUint(locked.state.organizationVersion, 10), strconv.FormatUint(selected.CredentialVersion, 10))
	return storageError(ctx, err)
}

// RecoverDirectoryTeamRoleSuccessor changes only the organization version of
// a still-valid original owner observation. The original committed receipt
// must already have been independently authenticated by the kernel. A changed
// role/source, unrecorded effect, or unrelated later owner version denies.
func (r *Repository) RecoverDirectoryTeamRoleSuccessor(ctx context.Context, source DirectoryTeamRoleSource, original organization.CredentialAuthorityObservation, receipt identity.CommandResult) (organization.CredentialAuthorityObservation, error) {
	var zero organization.CredentialAuthorityObservation
	if r == nil || r.pool == nil || ctx == nil {
		return zero, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	q := organization.CredentialAuthorityQuery{TenantID: source.Scope.TenantID, OrganizationID: source.Scope.OrganizationID}
	if original.Validate(q, time.Now().UTC()) != nil || !directoryTeamRoleSuccessorMatches(source, receipt) {
		return zero, organization.ErrForbidden
	}
	return r.recoverDirectorySuccessor(ctx, q, original, receipt, directoryTeamRoleSuccessorBinding(source, receipt.Binding))
}

func directoryTeamRoleSuccessorMatches(source DirectoryTeamRoleSource, receipt identity.CommandResult) bool {
	record, err := source.Scope.RecordID()
	binding := receipt.Binding
	return err == nil && scope(string(source.MemberResourceID)) && scope(string(source.RoleID)) &&
		source.ProviderVersion != 0 && source.MappingVersion != 0 && source.ConnectionVersion != 0 &&
		binding.RecordID == record && binding.TenantID == source.Scope.TenantID && binding.UserID == source.Scope.UserID &&
		binding.ActorKind == authorization.SubjectServiceAccount && receipt.Outcome == identity.CommitOutcomeCommitted &&
		receipt.Feature != nil && receipt.Feature.Operation == directoryTeamGrantOperation() && receipt.Validate() == nil
}

func directoryTeamRoleSuccessorBinding(source DirectoryTeamRoleSource, binding identity.CommandBinding) [32]byte {
	command := directoryMembershipSuccessorBinding(binding)
	framed := append([]byte(nil), command[:]...)
	for _, field := range [...]string{string(source.Scope.OrganizationID), string(source.Scope.ProviderID), string(source.Scope.ConnectionID),
		string(source.Scope.GroupID), string(source.Scope.TeamID), string(source.MemberResourceID), string(source.RoleID)} {
		framed = binary.AppendUvarint(framed, uint64(len(field)))
		framed = append(framed, field...)
	}
	framed = binary.AppendUvarint(framed, source.ProviderVersion)
	framed = binary.AppendUvarint(framed, source.MappingVersion)
	framed = binary.AppendUvarint(framed, source.ConnectionVersion)
	return directoryMembershipDigest("organization.directory-team-role.successor-binding.v1", framed)
}
