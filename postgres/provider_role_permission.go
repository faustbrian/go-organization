package postgres

import (
	"context"
	"strconv"

	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// NewRepositoryWithProviderRoleGrants selects provider grants in effective
// permission reads alongside existing direct and, when separately selected,
// team roles. Apply ProviderRoleGrantMigrationSource before use. The caller must
// compose the owner that keeps provider source generation and mapping current.
// Missing schema or current member authority does not fall back to a partial
// permission view. Administrative role listings and mutations are unchanged.
func NewRepositoryWithProviderRoleGrants(pool *database.Pool, config Config) (*Repository, error) {
	repository, err := NewRepository(pool, config)
	if err != nil {
		return nil, err
	}
	repository.providerRoleGrants = true
	return repository, nil
}

func (r *Repository) queryProviderRolePermissions(ctx context.Context, q organization.Query, v organization.View) (pgx.Rows, error) {
	query := effectiveProviderRolesSQL
	if q.IncludeTeamRoles {
		query = effectiveProviderTeamRolesSQL
	}
	return r.pool.Raw().Query(ctx, query, string(q.TenantID), string(q.OrganizationID), q.RoleCursor, int32(q.Limit+1), string(q.ActorID),
		strconv.FormatUint(v.Organization.Version, 10), strconv.FormatUint(v.Actor.Version, 10), strconv.FormatUint(v.Actor.AuthorizationVersion, 10))
}

// Take the first 129 exact member keys before applying any source status
// filters. This bounds work even with stale snapshots; overflow withholds the
// entire role set rather than accidentally ignoring a provider-owned deny.
const providerRoleProjectionSQL = `WITH current_member AS MATERIALIZED (
 SELECT m.version FROM organization.memberships m JOIN organization.organizations o USING(tenant_id,organization_id)
 WHERE m.tenant_id=$1 AND m.organization_id=$2 AND m.user_id=$5 AND m.state='active' AND o.state='active'
   AND o.version=$6::numeric AND m.version=$7::numeric AND m.authorization_version=$8::numeric
), grant_window AS MATERIALIZED (
 SELECT provider_id,provider_generation,mapping_version,organization_member_version,role_ids
 FROM organization.provider_role_grants
 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$5
 ORDER BY provider_id LIMIT 129
), provider_roles AS (
 SELECT DISTINCT unnest(g.role_ids) AS role_id
 FROM grant_window g CROSS JOIN current_member m
 JOIN organization.provider_role_sources s ON s.tenant_id=$1 AND s.organization_id=$2 AND s.provider_id=g.provider_id
 WHERE s.active AND g.provider_generation=s.generation AND g.mapping_version=s.mapping_version
   AND g.organization_member_version=m.version
)
SELECT r.role_id,r.name,r.version::text,r.statements FROM organization.custom_roles r CROSS JOIN current_member m
WHERE r.tenant_id=$1 AND r.organization_id=$2 AND r.state='active' AND r.role_id>$3 COLLATE "C"
 AND (SELECT count(*) FROM grant_window)<=128
 AND (EXISTS(SELECT 1 FROM organization.role_bindings b
 WHERE b.tenant_id=r.tenant_id AND b.organization_id=r.organization_id AND b.role_id=r.role_id AND b.user_id=$5
   AND b.state='active' AND b.organization_member_version=m.version)
 OR EXISTS(SELECT 1 FROM provider_roles p WHERE p.role_id=r.role_id)`

const providerRoleProjectionOrder = ` ORDER BY r.role_id COLLATE "C" LIMIT $4`

const effectiveProviderRolesSQL = providerRoleProjectionSQL + `)` + providerRoleProjectionOrder
const effectiveProviderTeamRolesSQL = providerRoleProjectionSQL + ` OR ` + effectiveTeamRoleExists + `)` + providerRoleProjectionOrder
