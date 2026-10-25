package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// Update admits one original key for bounded name/slug replacement at the exact
// expected organization version. The existing native metadata owner checks
// current owner/administrator authority and performs the protected transition.
// Matching retries recover the original outcome under current disclosure
// authority, never prepare newer metadata, renew authority or execute again.
// Network must be the transport's trusted canonical full client address.
func (s *OperationService) Update(ctx context.Context, r organization.UpdateOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), number("version", r.OrganizationVersion), text("name", r.Name), text("slug", r.Slug)}
	return s.state().keyed(ctx, r.Authentication, organization.Update, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, Name: r.Name, Slug: r.Slug, CorrelationID: r.CorrelationID})
	})
}
