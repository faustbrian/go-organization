package postgres

import (
	"context"
	"encoding/binary"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// The identity coordinator globally claims each CommandID before opening Work,
// so this effect can use the existing command_effects primary key.
const recordDirectoryMembershipSuccessorSQL = `INSERT INTO organization.command_effects
 (command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,
  directory_org_before,directory_org_after,directory_credential_version)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10::numeric,$11::numeric,$12::numeric)`

const recoverDirectoryMembershipSuccessorSQL = `SELECT e.directory_org_after::text FROM organization.command_effects e
 JOIN organization.organizations o USING(tenant_id,organization_id)
 WHERE e.command_id=$1 AND e.tenant_id=$2 AND e.organization_id=$3 AND e.user_id=$4 AND e.actor_id=$5 AND e.operation=$6 AND e.fingerprint=$7
 AND e.before_version=$8::numeric AND e.after_version=$9::numeric AND e.directory_org_before=$10::numeric AND e.directory_credential_version=$11::numeric
 AND o.state='active' AND o.version=e.directory_org_after AND o.credential_version=e.directory_credential_version`

// RecordDirectoryMembershipSuccessor records the organization version actually
// produced by this User child's original Work, including a contribution-only
// change that leaves the organization version unchanged. Call once after Apply
// in the same Work; propagate failure and retain all original final fences.
// This opt-in operation requires DirectoryMembershipSuccessorMigrationSource.
// It creates no command outcome or independently committed receipt.
func (r *Repository) RecordDirectoryMembershipSuccessor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, effect DirectoryMembershipEffect) error {
	if r == nil || r.pool == nil || ctx == nil || effect.state == nil || effect.state.work != w || effect.state.command != command {
		return identity.ForbiddenError{}
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	p := effect.state
	update := DirectoryMembershipUpdate{state: p.update}
	if err := requireDirectoryMembershipBinding(w, owner, command, update); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	i := p.update.input
	if err := requireDirectoryMembershipDeadline(ctx, w, i); err != nil {
		return err
	}
	feature, _ := command.Feature() // The exact binding and kind were checked above.
	b := feature.Binding
	digest := directoryMembershipSuccessorBinding(b)
	_, err := w.Exec(ctx, recordDirectoryMembershipSuccessorSQL,
		string(b.CommandID), string(b.TenantID), string(i.Source.OrganizationID), string(b.UserID), string(b.ActorID), b.OperationID, digest[:],
		strconv.FormatUint(update.BeforeVersion(), 10), strconv.FormatUint(update.AfterVersion(), 10),
		strconv.FormatUint(i.Organization.Version, 10), strconv.FormatUint(p.organizationVersion, 10), strconv.FormatUint(i.Organization.CredentialVersion, 10))
	return storageError(ctx, err)
}

// RecoverDirectoryMembershipSuccessor binds an exact, independently authorized
// committed User receipt to its persisted organization effect. The result
// changes only Version on the original owner-only observation; its timestamps
// and credential version are unchanged. Not-present, mismatched, superseded or
// expired input returns zero evidence. The consumer must still fence the exact
// successor inside subsequent Work. Kernel recovery, not this method, owns
// receipt and audit-event authenticity.
func (r *Repository) RecoverDirectoryMembershipSuccessor(ctx context.Context, source DirectoryMembershipSource, original organization.CredentialAuthorityObservation, receipt identity.CommandResult) (organization.CredentialAuthorityObservation, error) {
	var zero organization.CredentialAuthorityObservation
	if r == nil || r.pool == nil || ctx == nil {
		return zero, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	record, err := source.RecordID()
	b := receipt.Binding
	q := source.organizationQuery()
	if err != nil || b.RecordID != record || b.TenantID != source.TenantID || b.UserID != source.UserID || b.ActorKind != authorization.SubjectServiceAccount ||
		receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Validate() != nil || original.Validate(q, time.Now().UTC()) != nil {
		return zero, organization.ErrForbidden
	}
	switch receipt.Feature.Operation {
	case directoryMembershipOperation(DirectoryMembershipGrant), directoryMembershipOperation(DirectoryMembershipWithdraw):
	default:
		return zero, organization.ErrForbidden
	}
	return r.recoverDirectorySuccessor(ctx, q, original, receipt, directoryMembershipSuccessorBinding(b))
}

func (r *Repository) recoverDirectorySuccessor(ctx context.Context, q organization.CredentialAuthorityQuery, original organization.CredentialAuthorityObservation, receipt identity.CommandResult, digest [32]byte) (organization.CredentialAuthorityObservation, error) {
	var zero organization.CredentialAuthorityObservation
	ctx, cancel := context.WithTimeout(ctx, min(r.maximum, time.Until(original.ValidUntil)))
	defer cancel()
	b := receipt.Binding
	var after string
	err := r.pool.Raw().QueryRow(ctx, recoverDirectoryMembershipSuccessorSQL,
		string(b.CommandID), string(b.TenantID), string(q.OrganizationID), string(b.UserID), string(b.ActorID), b.OperationID, digest[:],
		strconv.FormatUint(receipt.Feature.BeforeVersion, 10), strconv.FormatUint(receipt.Feature.AfterVersion, 10),
		strconv.FormatUint(original.Version, 10), strconv.FormatUint(original.CredentialVersion, 10)).Scan(&after)
	if original.Validate(q, time.Now().UTC()) != nil {
		return zero, organization.ErrForbidden
	}
	if err != nil {
		return zero, storageError(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	version, err := positive(after)
	if err != nil || version != original.Version && (original.Version == math.MaxUint64 || version != original.Version+1) {
		return zero, organization.ErrUnavailable
	}
	original.Version = version
	return original, nil
}

func directoryMembershipSuccessorBinding(b identity.CommandBinding) [32]byte {
	// Keep v1 framing independent of future changes to the public JSON shape.
	// Both callers validate the required service-account kind and User profile.
	var framed []byte
	for _, field := range [...]string{string(b.CommandID), string(b.TenantID), string(b.UserID), string(b.ActorID), b.OperationID,
		b.PolicyID, strconv.FormatUint(b.PolicyVersion, 10), b.SchemaID, strconv.FormatUint(uint64(b.SchemaVersion), 10), b.CorrelationID, b.RecordID} {
		framed = binary.AppendUvarint(framed, uint64(len(field)))
		framed = append(framed, field...)
	}
	return directoryMembershipDigest("organization.directory-membership.successor-binding.v1", framed)
}
