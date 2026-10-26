package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// CreateTeam admits one original key for creation of an empty team with the
// chosen canonical ID, exact organization version and bounded name. The existing
// native team owner enforces current manager/session authority, quotas and the
// atomic team, organization-epoch, audit and lifecycle effects. No organization
// or team ID is allocated by this operation; the command remains owner-allocated.
//
// Matching key/intent retries recover only the original outcome under current
// disclosure authority, never prepare another team, renew authority or execute
// again after an unknown result. Network is the trusted canonical client IP.
func (s *OperationService) CreateTeam(ctx context.Context, r organization.CreateTeamOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("team-id", string(r.TeamID)), number("version", r.OrganizationVersion), text("name", r.Name)}
	return s.state().keyed(ctx, r.Authentication, organization.CreateTeam, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, Name: r.Name, CorrelationID: r.CorrelationID})
	})
}
