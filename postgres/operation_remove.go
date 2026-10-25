package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// RemoveMember preserves the canonical non-keyed repeat contract. Exact
// organization/target versions arbitrate competing native removals; a repeat
// can disclose only a real matching command effect and its original kernel
// receipt under current authentication and disclosure policy. Absence alone is
// not success. A newer re-admission never becomes removable through old input.
// Unknown execution is returned without another mutation attempt.
func (s *OperationService) RemoveMember(ctx context.Context, r organization.RemoveMemberOperationRequest, network string) (out organization.StoreResult, err error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.source.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	actor, err := state.actor(ctx, r.Authentication)
	if err != nil {
		return out, err
	}
	if previous, found, err := state.removalOutcome(ctx, r, actor); err != nil || found {
		return previous, err
	}
	service, err := state.compose(nil)
	if err != nil {
		return out, err
	}
	id, err := identity.NewCommandID()
	if err != nil {
		return out, organization.ErrUnavailable
	}
	prepared, err := service.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion, MemberVersion: r.MemberVersion, CorrelationID: r.CorrelationID}, network)
	if err != nil {
		// Another identical request may have committed between the bounded
		// first lookup and preparation. Reconcile its actual native effect;
		// do not interpret inactive membership or stale versions as success.
		if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
			if previous, found, lookupErr := state.removalOutcome(ctx, r, actor); lookupErr != nil || found {
				return previous, lookupErr
			}
		}
		return out, err
	}
	out, err = service.Execute(ctx, prepared)
	if errors.Is(err, organization.ErrConflict) {
		if previous, found, lookupErr := state.removalOutcome(ctx, r, actor); lookupErr != nil || found {
			return previous, lookupErr
		}
	}
	return out, err
}

// The partial index supplies an exact tenant/org/epoch probe. Actor and target
// are filters over at most one committed removal for that aggregate epoch;
// they are not client-selected history or permission to fabricate a receipt.
const removalOperationLookupSQL = `SELECT command_id FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.member.remove' AND actor_id=$4 AND user_id=$5
LIMIT 2`

func (s *operationServiceState) removalOutcome(ctx context.Context, r organization.RemoveMemberOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	if _, err := s.source.Get(ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: r.CorrelationID}); err != nil {
		return organization.StoreResult{}, false, err
	}
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, removalOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10), string(actor), string(r.UserID))
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	var id identity.CommandID
	count := 0
	for rows.Next() {
		count++
		if rows.Scan(&id) != nil || count > 1 {
			rows.Close()
			return organization.StoreResult{}, false, organization.ErrUnavailable
		}
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return organization.StoreResult{}, false, operationError(ctx, readErr)
	}
	if count == 0 {
		return organization.StoreResult{}, false, nil
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	view, err := s.source.participant.repository.Read(ctx, organization.Query{Operation: organization.RemoveMember, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, ActorID: actor, TargetID: r.UserID})
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	if view.Target.Active || view.Target.Version != r.MemberVersion+1 {
		return organization.StoreResult{}, false, organization.ErrConflict
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, UserID: r.UserID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: string(organization.RemoveMember), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Coordinator.QueryPolicy.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Tenant: authorization.TenantID(r.Authentication.TenantID), Action: authorization.Action(organization.RemoveMember), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(r.UserID)}}}
	service, err := s.compose(nil)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	original, err := service.config.Coordinator.QueryCommand(ctx, q, caller)
	if err != nil {
		return organization.StoreResult{}, false, operationError(ctx, err)
	}
	if original.Binding.ValidateFor(organization.RemoveMember.Descriptor()) != nil {
		return organization.StoreResult{}, false, organization.ErrUnavailable
	}
	out, err := service.Recover(ctx, r.Authentication, Recovery{Binding: original.Binding})
	return out, true, operationError(ctx, err)
}
