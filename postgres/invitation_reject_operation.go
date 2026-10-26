package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// Reject initiates a naturally repeatable exact-version invitation rejection.
// It allocates the command internally and uses the existing native preparation
// and execution once. The current verified intended recipient needs neither
// membership, manager/Get permission nor an invitation proof. Network is the
// transport's trusted canonical full client address. Install the optional
// InvitationRejectOperationMigrationSource before selecting this API.
//
// Reconstructed matching committed requests return the actual original receipt
// under current recipient/session authority. CorrelationID is diagnostic only;
// a rejected/absent row or legacy NULL correlation is never historical success.
// Unknown execution returns immediately without another attempt. Retain its
// receipt binding for existing Recover: a committed-effect lookup cannot identify
// an unattached or uncommitted original from natural request syntax alone.
func (s *InvitationService) Reject(ctx context.Context, r organization.InvitationRejectOperationRequest, network string) (out organization.StoreResult, err error) {
	if s == nil || s.root == nil || ctx == nil || r.Validate() != nil || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	observed, _, err := s.observeInvitationRecovery(ctx, r.Authentication, "")
	if err != nil {
		return out, err
	}
	actor, err := observed.Session.Bindings()
	if err != nil {
		return out, organization.ErrForbidden
	}
	if previous, found, err := s.rejectionOutcome(ctx, r, actor.UserID); err != nil || found {
		return previous, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	prepared, err := s.PrepareReject(ctx, organization.InvitationRejectRequest{Authentication: r.Authentication, CommandID: id, ID: r.InvitationID, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, InvitationVersion: r.InvitationVersion, CorrelationID: r.CorrelationID}, network)
	if err != nil {
		if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
			if previous, found, lookupErr := s.rejectionOutcome(ctx, r, actor.UserID); lookupErr != nil || found {
				return previous, lookupErr
			}
		}
		return out, err
	}
	// Opt-in correlation stays in the existing atomic effect. Raw explicit
	// rejection retains its original INSERT and needs no optional migration.
	prepared.state.naturalReject = true
	out, err = s.Execute(ctx, prepared)
	if errors.Is(err, organization.ErrConflict) {
		// Only a real effect can identify a concurrent natural-request winner.
		// The terminal pending/version fence, not row state alone, arbitrates it.
		if previous, found, lookupErr := s.rejectionOutcome(ctx, r, actor.UserID); lookupErr != nil || found {
			return previous, lookupErr
		}
	}
	return out, err
}

// The partial unique index bounds this lookup to one actual rejection of the
// exact invitation epoch. The authenticated actor is its intended recipient;
// original organization correlation cannot be inferred from today's epoch.
const rejectionOperationLookupSQL = `SELECT command_id,reject_organization_version::text
FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3
AND before_version=$4::numeric AND operation='identity.organization.invitation.reject'
AND actor_id=$5 AND user_id=$5 LIMIT 2`

func (s *InvitationService) rejectionOutcome(ctx context.Context, r organization.InvitationRejectOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	// Rejection is recipient-owned. ReadInvitation's native recipient branch
	// resolves verified eligibility without requiring organization Get/management.
	view, err := s.repository.ReadInvitation(ctx, organization.InvitationQuery{Operation: organization.InvitationReject, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, InvitationID: r.InvitationID, ActorID: actor, RecipientUserID: actor})
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	i := view.Record.Invitation
	if i.RecipientUserID != actor || view.RecipientUser.ID != actor || view.RecipientUser.Status != identity.StatusActive || view.RecipientIdentifier.ID != i.RecipientIdentifierID || view.RecipientIdentifier.Version != i.RecipientIdentifierVersion || !view.RecipientIdentifier.Verified {
		return organization.StoreResult{}, false, organization.ErrForbidden
	}
	rows, err := s.actor.repository.pool.Raw().Query(ctx, rejectionOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), string(r.InvitationID), strconv.FormatUint(r.InvitationVersion, 10), string(actor))
	if err != nil {
		return organization.StoreResult{}, false, storageError(ctx, err)
	}
	var id identity.CommandID
	var version *string
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id, &version) != nil || count > 1 {
			rows.Close()
			return organization.StoreResult{}, false, organization.ErrUnavailable
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return organization.StoreResult{}, false, storageError(ctx, readErr)
	}
	if count == 0 {
		return organization.StoreResult{}, false, nil
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil || version == nil {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	if *version != strconv.FormatUint(r.OrganizationVersion, 10) || i.Status != organization.InvitationRejected || i.Version != r.InvitationVersion+1 || i.IssuedVersion != r.InvitationVersion {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	p := &invitationPhase{service: s, input: organization.CommandInput{Operation: organization.InvitationReject}}
	if err := p.compose(); err != nil {
		return organization.StoreResult{}, false, invitationPublicError(err)
	}
	query := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, UserID: actor, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationReject), RecordID: string(r.InvitationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(query.TenantID), Subject: authorization.Subject{Kind: query.ActorKind, ID: authorization.SubjectID(actor)}, Action: authorization.Action(query.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(actor)}}}
	original, err := p.coordinator.QueryCommand(ctx, query, caller)
	if err != nil {
		return organization.StoreResult{}, false, invitationPublicError(err)
	}
	if original.Validate() != nil || original.Binding.ValidateFor(organization.InvitationReject.Descriptor()) != nil || original.Feature == nil || *original.Feature != organization.InvitationReject.Descriptor() {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	out, err := s.Recover(ctx, r.Authentication, InvitationRecovery{Binding: original.Binding, OrganizationID: r.OrganizationID})
	if err == nil && (out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != r.InvitationVersion || out.Receipt.Feature.AfterVersion != r.InvitationVersion+1) {
		err = organization.ErrUnavailable
	}
	return out, true, invitationPublicError(err)
}
