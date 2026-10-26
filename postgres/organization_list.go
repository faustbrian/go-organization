package postgres

import (
	"context"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	organization "github.com/faustbrian/go-organization"
)

var _ organization.OrganizationListReader = (*Repository)(nil)

// ListOrganizations reads current visible organizations for the authenticated
// human, never a caller-selected subject. It uses the existing primary session,
// membership, scoped authority and per-organization policy owners. Core repeats
// live admission after callbacks without extending original observation expiry.
func (s *Service) ListOrganizations(ctx context.Context, request organization.ListOrganizationsRequest) (organization.ListOrganizationsResult, error) {
	if s == nil {
		return organization.ListOrganizationsResult{}, organization.ErrInvalidInput
	}
	return s.core.ListOrganizations(ctx, request)
}

// ListOrganizations delegates the current authenticated subject's bounded
// listing to the borrowed source Service. Limit remains explicitly required;
// no request-key admission, organization allocation or authority cache is added.
func (s *OperationService) ListOrganizations(ctx context.Context, request organization.ListOrganizationsRequest) (organization.ListOrganizationsResult, error) {
	if s == nil || s.state == nil {
		return organization.ListOrganizationsResult{}, organization.ErrInvalidInput
	}
	return s.state().source.ListOrganizations(ctx, request)
}

// ReadOrganizations is a trusted current primary projection, not an
// authentication endpoint. MaximumRows is the selected per-user cap (1..1000);
// one additional matching candidate detects cap violations without false EOF.
// The existing active (tenant,user,organization) membership index supports the
// exclusive C-collation keyset. Rows close before borrowing the authority owner,
// so a one-connection pool cannot deadlock on its own open cursor. No caller
// callback runs in a transaction or under an organization lock.
func (r *Repository) ReadOrganizations(ctx context.Context, query organization.OrganizationListQuery) ([]organization.OrganizationListEntry, error) {
	if ctx == nil || r == nil || r.pool == nil || !scope(string(query.TenantID)) || !scope(string(query.ActorID)) || query.After != "" && !scope(string(query.After)) || query.MaximumRows < 1 || query.MaximumRows > 1000 {
		return nil, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	rows, err := r.pool.Raw().Query(bounded, `SELECT o.organization_id,o.slug,o.name,o.version::text,m.role,m.version::text,m.authorization_version::text
FROM organization.memberships m JOIN organization.organizations o USING(tenant_id,organization_id)
WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.state='active' AND o.state='active' AND m.organization_id>$3 COLLATE "C"
ORDER BY m.organization_id COLLATE "C" LIMIT $4`, string(query.TenantID), string(query.ActorID), string(query.After), int32(query.MaximumRows+1))
	if err != nil {
		return nil, storageError(bounded, err)
	}
	defer rows.Close()
	entries := make([]organization.OrganizationListEntry, 0)
	for rows.Next() {
		entry := organization.OrganizationListEntry{}
		var version, member, epoch string
		if err = rows.Scan(&entry.Organization.ID, &entry.Organization.Slug, &entry.Organization.Name, &version, &entry.Member.Role, &member, &epoch); err != nil {
			return nil, storageError(bounded, err)
		}
		entry.Organization.TenantID, entry.Organization.Active = query.TenantID, true
		entry.Member.TenantID, entry.Member.OrganizationID, entry.Member.UserID, entry.Member.Active = query.TenantID, entry.Organization.ID, query.ActorID, true
		if entry.Organization.Version, err = positive(version); err != nil {
			return nil, err
		}
		if entry.Member.Version, err = positive(member); err != nil {
			return nil, err
		}
		if entry.Member.AuthorizationVersion, err = positive(epoch); err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	if err = rows.Err(); err != nil {
		return nil, storageError(bounded, err)
	}
	rows.Close()
	store, err := authority.NewAuthorityStore(r.pool.Raw(), r.maximum)
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	for _, entry := range entries {
		scope, err := OrganizationAuthorityScope(query.TenantID, entry.Organization.ID, query.ActorID)
		if err != nil {
			return nil, err
		}
		current, err := store.Get(bounded, scope)
		if err != nil {
			return nil, publicTeamAuthorityError(err)
		}
		if current.Version != entry.Member.AuthorizationVersion {
			return nil, organization.ErrForbidden
		}
	}
	if err = bounded.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}
