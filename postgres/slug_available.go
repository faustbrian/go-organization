package postgres

import (
	"context"

	organization "github.com/faustbrian/go-organization"
)

var _ organization.OrganizationSlugReader = (*Repository)(nil)

// SlugAvailable checks one candidate through the existing authenticated core
// and current primary session/policy owners, without membership requirements.
// It returns no organization identity and never reserves a slug or executes a
// command. Create/update retain their authoritative uniqueness checks.
func (s *Service) SlugAvailable(ctx context.Context, request organization.SlugAvailableRequest) (organization.SlugAvailableResult, error) {
	if s == nil {
		return organization.SlugAvailableResult{}, organization.ErrInvalidInput
	}
	return s.core.SlugAvailable(ctx, request)
}

// SlugAvailable delegates the existing authenticated advisory read to the
// borrowed source Service. It neither admits a request key nor allocates an
// organization/command, and retains the source's current-authority checks.
func (s *OperationService) SlugAvailable(ctx context.Context, request organization.SlugAvailableRequest) (organization.SlugAvailableResult, error) {
	if s == nil || s.state == nil {
		return organization.SlugAvailableResult{}, organization.ErrInvalidInput
	}
	return s.state().source.SlugAvailable(ctx, request)
}

// ReadOrganizationSlug implements a trusted current primary occupancy read,
// not an authentication endpoint. Existing UNIQUE(tenant_id,slug) includes
// archived rows, so filtering by active state would report occupied names free.
// The indexed existence query returns no organization ID/metadata, holds no
// reservation and releases its resources before the core's final admission.
func (r *Repository) ReadOrganizationSlug(ctx context.Context, query organization.OrganizationSlugQuery) (organization.OrganizationSlugAvailability, error) {
	// Reuse native create/update's slug syntax; the fixed valid name selects
	// only that existing validator's candidate-slug contract, not new metadata.
	if ctx == nil || r == nil || r.pool == nil || !scope(string(query.TenantID)) || !validMetadata("slug-availability", query.Slug) {
		return organization.OrganizationSlugAvailability{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	result := organization.OrganizationSlugAvailability{TenantID: query.TenantID, Slug: query.Slug}
	err := r.pool.Raw().QueryRow(bounded, `SELECT NOT EXISTS(SELECT 1 FROM organization.organizations WHERE tenant_id=$1 AND slug=$2)`, string(query.TenantID), query.Slug).Scan(&result.Available)
	if err != nil {
		return organization.OrganizationSlugAvailability{}, storageError(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return organization.OrganizationSlugAvailability{}, err
	}
	return result, nil
}
