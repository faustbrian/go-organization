package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func activeOrganizationIntent(r organization.ActiveOrganizationOperationRequest) []identity.FeatureField {
	return []identity.FeatureField{text("active.session", r.SessionID), text("active.organization", string(r.OrganizationID))}
}

// SetActiveOrganization binds one original key to exact session and requested
// organization/absence, never observed CAS/authority. A retained matching key
// recovers status under current exact-session authority; it cannot re-prepare,
// renew or replay a selection. The existing coordinator is the sole journal.
func (s *OperationService) SetActiveOrganization(ctx context.Context, r organization.ActiveOrganizationOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	if s.state().source.participant.selection == nil {
		return organization.StoreResult{}, organization.ErrForbidden
	}
	return s.state().keyed(ctx, r.Authentication, organization.ActiveSet, r.IdempotencyKey, activeOrganizationIntent(r), network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareActiveSet(ctx, organization.ActiveOrganizationRequest{Authentication: r.Authentication, CommandID: id, SessionID: r.SessionID, OrganizationID: r.OrganizationID, CorrelationID: r.CorrelationID})
	})
}

// GetActiveOrganization delegates current selected authority and policy to the
// native owner; it returns no selection metadata on any denied read.
func (s *OperationService) GetActiveOrganization(ctx context.Context, r organization.ActiveOrganizationReadRequest) (organization.ActiveOrganizationView, error) {
	if s == nil || s.state == nil {
		return organization.ActiveOrganizationView{}, organization.ErrInvalidInput
	}
	return s.state().source.GetActiveOrganization(ctx, r)
}
