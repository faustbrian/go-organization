package postgres

import (
	"context"
	"errors"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// LeaveMember removes only the currently authenticated human from the selected
// exact organization epoch. It allocates the command internally and uses the
// existing protected leave transition. A natural repeat discloses only an actual
// original receipt under current verified-self and disclosure policy, including
// after departure. Absence alone is not success; old intent conflicts with an
// active readmission. Unknown execution is returned without another attempt.
// Install one LeaveOperationLookup migration variant before enabling this API.
func (s *OperationService) LeaveMember(ctx context.Context, r organization.LeaveMemberOperationRequest, network string) (out organization.StoreResult, err error) {
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
	if previous, found, err := state.leaveOutcome(ctx, r, actor); err != nil || found {
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
	prepared, err := service.PrepareLeaveMember(ctx, organization.LeaveRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, CorrelationID: r.CorrelationID}, network)
	if err == nil {
		out, err = service.Execute(ctx, prepared)
	}
	// A matching contender may commit between lookup, preparation and execution.
	// Reconcile only an actual committed effect, never an absent membership or an
	// unknown attempt; no fresh command is executed by the lookup/recovery path.
	if errors.Is(err, organization.ErrConflict) || errors.Is(err, organization.ErrForbidden) {
		if previous, found, lookupErr := state.leaveOutcome(ctx, r, actor); lookupErr != nil || found {
			return previous, lookupErr
		}
	}
	return out, err
}

const leaveOperationLookupSQL = `SELECT command_id FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.member.leave' AND actor_id=$4 AND user_id=$4
LIMIT 2`

func (s *operationServiceState) leaveOutcome(ctx context.Context, r organization.LeaveMemberOperationRequest, actor identity.UserID) (organization.StoreResult, bool, error) {
	rows, err := s.source.participant.repository.pool.Raw().Query(ctx, leaveOperationLookupSQL, string(r.Authentication.TenantID), string(r.OrganizationID), strconv.FormatUint(r.OrganizationVersion, 10), string(actor))
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
	service, err := s.compose(nil)
	if err != nil {
		return organization.StoreResult{}, false, err
	}
	q := identity.RecoveryQuery{CommandID: id, TenantID: r.Authentication.TenantID, UserID: actor, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, OperationID: string(organization.LeaveMember), RecordID: string(r.OrganizationID)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(service.config.Core.PolicyVersion), CorrelationID: r.CorrelationID, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Tenant: authorization.TenantID(r.Authentication.TenantID), Action: authorization.Action(organization.LeaveMember), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(actor)}}}
	original, err := service.config.Coordinator.QueryCommand(ctx, q, caller)
	if err != nil {
		return organization.StoreResult{}, true, operationError(ctx, err)
	}
	out, err := service.recoverLeaveOperation(ctx, r.Authentication, original.Binding, true)
	return out, true, operationError(ctx, err)
}
