package postgres

import (
	"bytes"
	"context"
	"fmt"
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

// DirectorySourceCommittedChild binds an exact original User or role receipt
// to the source selected by the caller. It grants no authority. A zero child
// is invalid; the kernel must independently authenticate the receipt.
type DirectorySourceCommittedChild struct {
	partition     directorySuccessorPartition
	binding       identity.CommandBinding
	digest        [32]byte
	before, after uint64
}

type directorySuccessorPartition struct {
	tenant                             identity.TenantID
	organization, provider, connection organization.ID
}

// DirectorySuccessorSourceScope names the source and service account that own
// the original admission. Matching it confers no permission or freshness.
type DirectorySuccessorSourceScope struct {
	TenantID                                 identity.TenantID
	OrganizationID, ProviderID, ConnectionID organization.ID
	ActorID                                  identity.ActorID
}

// MatchesSource reports whether this child belongs to the exact sealed source.
func (c DirectorySourceCommittedChild) MatchesSource(s DirectorySuccessorSourceScope) bool {
	return c.binding.CommandID != "" && c.binding.ActorID == s.ActorID &&
		c.partition == (directorySuccessorPartition{s.TenantID, s.OrganizationID, s.ProviderID, s.ConnectionID})
}

func (DirectorySourceCommittedChild) Format(s fmt.State, _ rune) {
	_, _ = fmt.Fprint(s, "postgres.DirectorySourceCommittedChild(redacted)")
}

// NewDirectoryMembershipCommittedChild prepares the User variant of a mixed
// prefix proof without storing references into the receipt.
func NewDirectoryMembershipCommittedChild(source DirectoryMembershipSource, receipt identity.CommandResult) (DirectorySourceCommittedChild, error) {
	binding := receipt.Binding
	record, err := source.RecordID()
	if err != nil || binding.TenantID != source.TenantID || binding.UserID != source.UserID || binding.RecordID != record ||
		binding.ActorKind != authorization.SubjectServiceAccount || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil || receipt.Validate() != nil {
		return DirectorySourceCommittedChild{}, organization.ErrForbidden
	}
	switch receipt.Feature.Operation {
	case directoryMembershipOperation(DirectoryMembershipGrant), directoryMembershipOperation(DirectoryMembershipWithdraw):
	default:
		return DirectorySourceCommittedChild{}, organization.ErrForbidden
	}
	return DirectorySourceCommittedChild{
		partition: directorySuccessorPartition{source.TenantID, source.OrganizationID, source.ProviderID, source.ConnectionID},
		binding:   binding, digest: directoryMembershipSuccessorBinding(binding),
		before: receipt.Feature.BeforeVersion, after: receipt.Feature.AfterVersion,
	}, nil
}

// NewDirectoryTeamRoleCommittedChild prepares the exact role variant of a
// mixed prefix proof. Ordinary Group receipts cannot supply a role effect.
func NewDirectoryTeamRoleCommittedChild(source DirectoryTeamRoleSource, receipt identity.CommandResult) (DirectorySourceCommittedChild, error) {
	if !directoryTeamRoleSuccessorMatches(source, receipt) {
		return DirectorySourceCommittedChild{}, organization.ErrForbidden
	}
	s := source.Scope
	return DirectorySourceCommittedChild{
		partition: directorySuccessorPartition{s.TenantID, s.OrganizationID, s.ProviderID, s.ConnectionID},
		binding:   receipt.Binding, digest: directoryTeamRoleSuccessorBinding(source, receipt.Binding),
		before: receipt.Feature.BeforeVersion, after: receipt.Feature.AfterVersion,
	}, nil
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
	prefix := make([]DirectorySourceCommittedChild, len(children))
	for i, child := range children {
		mapped, err := NewDirectoryMembershipCommittedChild(child.Source, child.Receipt)
		if err != nil {
			return err
		}
		prefix[i] = mapped
	}
	return r.ValidateDirectorySourceSuccessorChain(ctx, current, prefix)
}

// ValidateDirectorySourceSuccessorChain verifies the ordered original User
// and role transitions against one current active organization observation.
// The caller authenticates each receipt and supplies all authority-changing
// children in the observed prefix; ordinary Group work may interleave. The
// same scoped actor and batch correlation must hold for every child. This
// comparison neither issues new evidence nor extends the original deadline.
func (r *Repository) ValidateDirectorySourceSuccessorChain(ctx context.Context, current organization.CredentialAuthorityObservation, children []DirectorySourceCommittedChild) error {
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
		binding := child.binding
		if child.partition.tenant != current.TenantID || child.partition.organization != current.OrganizationID ||
			child.partition != first.partition || binding.CommandID == "" || binding.ActorID != first.binding.ActorID ||
			binding.CorrelationID == "" || binding.CorrelationID != first.binding.CorrelationID {
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
		child := children[index]
		binding := child.binding
		if userID != string(binding.UserID) || actorID != string(binding.ActorID) || operation != binding.OperationID ||
			!bytes.Equal(fingerprint, child.digest[:]) || before != strconv.FormatUint(child.before, 10) ||
			after != strconv.FormatUint(child.after, 10) || credentialVersion != strconv.FormatUint(current.CredentialVersion, 10) {
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
