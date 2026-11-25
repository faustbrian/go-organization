package postgres

import (
	"bytes"
	"context"
	"math"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipCommittedChild pairs one exact User source with its
// independently authenticated original committed receipt. It grants no authority.
type DirectoryMembershipCommittedChild struct {
	Source  DirectoryMembershipSource
	Receipt identity.CommandResult
}

const validateDirectoryMembershipSuccessorChainSQL = `SELECT
 e.command_id,e.user_id,e.actor_id,e.operation,e.fingerprint,
 e.before_version::text,e.after_version::text,
 e.directory_org_before::text,e.directory_org_after::text,e.directory_credential_version::text
 FROM organization.command_effects e
 JOIN organization.organizations o USING(tenant_id,organization_id)
 WHERE e.command_id=ANY($1::text[]) AND e.tenant_id=$2 AND e.organization_id=$3
 AND e.directory_credential_version=$4::numeric
 AND o.state='active' AND o.version=$5::numeric AND o.credential_version=$4::numeric`

// ValidateDirectoryMembershipSuccessorChain verifies 1..1000 original ordered
// User children against their durable effects and the current active owner.
// Children must share one tenant, organization, provider, connection, service
// actor and original batch correlation. Contribution-only changes may retain
// the organization version; effective changes advance it exactly once.
//
// The caller independently authenticates every receipt and owns which exact
// contiguous observed batch prefix these User children represent; Group effects
// may interleave in that prefix. This check authenticates neither the caller nor
// its selection. It performs one bounded primary read, preserves current's
// original freshness, returns no authority and never renews an observation.
// Subsequent protected Work must still fence the exact current owner facts.
// Inputs must not be mutated concurrently. Missing, mismatched, expired or
// superseded evidence fails closed.
func (r *Repository) ValidateDirectoryMembershipSuccessorChain(ctx context.Context, current organization.CredentialAuthorityObservation, children []DirectoryMembershipCommittedChild) error {
	if r == nil || r.pool == nil || ctx == nil || len(children) == 0 || len(children) > 1000 {
		return organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	query := organization.CredentialAuthorityQuery{TenantID: current.TenantID, OrganizationID: current.OrganizationID}
	if current.Validate(query, time.Now().UTC()) != nil {
		return organization.ErrForbidden
	}

	first := children[0]
	commandIDs := make([]string, len(children))
	indices := make(map[string]int, len(children))
	for i, child := range children {
		source, receipt := child.Source, child.Receipt
		binding := receipt.Binding
		record, err := source.RecordID()
		if err != nil || source.TenantID != current.TenantID || source.OrganizationID != current.OrganizationID ||
			source.ProviderID != first.Source.ProviderID || source.ConnectionID != first.Source.ConnectionID ||
			binding.TenantID != source.TenantID || binding.UserID != source.UserID || binding.RecordID != record ||
			binding.ActorKind != authorization.SubjectServiceAccount || binding.ActorID != first.Receipt.Binding.ActorID ||
			binding.CorrelationID == "" || binding.CorrelationID != first.Receipt.Binding.CorrelationID ||
			receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Validate() != nil {
			return organization.ErrForbidden
		}
		switch receipt.Feature.Operation {
		case directoryMembershipOperation(DirectoryMembershipGrant), directoryMembershipOperation(DirectoryMembershipWithdraw):
		default:
			return organization.ErrForbidden
		}
		commandID := string(binding.CommandID)
		if _, exists := indices[commandID]; exists {
			return organization.ErrForbidden
		}
		commandIDs[i], indices[commandID] = commandID, i
	}

	ctx, cancel := context.WithTimeout(ctx, min(r.maximum, time.Until(current.ValidUntil)))
	defer cancel()
	rows, err := r.pool.Raw().Query(ctx, validateDirectoryMembershipSuccessorChainSQL,
		commandIDs, string(current.TenantID), string(current.OrganizationID),
		strconv.FormatUint(current.CredentialVersion, 10), strconv.FormatUint(current.Version, 10))
	if err != nil {
		return storageError(ctx, err)
	}
	defer rows.Close()
	type transition struct {
		before, after uint64
		seen          bool
	}
	transitions := make([]transition, len(children))
	for rows.Next() {
		var commandID, userID, actorID, operation, before, after, organizationBefore, organizationAfter, credentialVersion string
		var fingerprint []byte
		if err := rows.Scan(&commandID, &userID, &actorID, &operation, &fingerprint,
			&before, &after, &organizationBefore, &organizationAfter, &credentialVersion); err != nil {
			return storageError(ctx, err)
		}
		index, exists := indices[commandID]
		if !exists || transitions[index].seen {
			return organization.ErrForbidden
		}
		receipt := children[index].Receipt
		binding := receipt.Binding
		digest := directoryMembershipSuccessorBinding(binding)
		if userID != string(binding.UserID) || actorID != string(binding.ActorID) || operation != binding.OperationID ||
			!bytes.Equal(fingerprint, digest[:]) || before != strconv.FormatUint(receipt.Feature.BeforeVersion, 10) ||
			after != strconv.FormatUint(receipt.Feature.AfterVersion, 10) || credentialVersion != strconv.FormatUint(current.CredentialVersion, 10) {
			return organization.ErrForbidden
		}
		beforeVersion, beforeErr := positive(organizationBefore)
		afterVersion, afterErr := positive(organizationAfter)
		if beforeErr != nil || afterErr != nil ||
			afterVersion != beforeVersion && (beforeVersion == math.MaxUint64 || afterVersion != beforeVersion+1) {
			return organization.ErrForbidden
		}
		transitions[index] = transition{before: beforeVersion, after: afterVersion, seen: true}
	}
	if err := rows.Err(); err != nil {
		return storageError(ctx, err)
	}
	for i, transition := range transitions {
		if !transition.seen || i > 0 && transition.before != transitions[i-1].after {
			return organization.ErrForbidden
		}
	}
	if transitions[len(transitions)-1].after != current.Version || current.Validate(query, time.Now().UTC()) != nil {
		return organization.ErrForbidden
	}
	return ctx.Err()
}
