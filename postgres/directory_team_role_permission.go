package postgres

import (
	"context"
	"fmt"
	"strconv"

	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamRoleSource is the exact configured edge, target, and recorded
// source versions to check against current primary authority.
type DirectoryTeamRoleSource struct {
	Scope                           DirectoryTeamGrantScope
	MemberResourceID, RoleID        organization.ID
	ProviderVersion, MappingVersion uint64
	ConnectionVersion               uint64
}

func (DirectoryTeamRoleSource) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.DirectoryTeamRoleSource(redacted)"))
}

// DirectoryTeamRoleAuthority checks an ordered batch of at most 128 claims.
// Return one result per input, using the current configured exact Group edge,
// role mapping, provider and connection. False must be authoritative; return
// an error for unavailable or ambiguous evidence. Positive results require
// owner reads within this call, not cached decisions or extended freshness.
// The claims are detached. The callback must be safe for concurrent calls and
// obey cancellation; it runs after SQL rows close, without a held lock.
type DirectoryTeamRoleAuthority func(context.Context, []DirectoryTeamRoleSource) ([]bool, error)

// WithDirectoryTeamRoles returns an independently configured repository.
// Only opted-in team permission reads consult the additional role projection;
// local, direct, and any already enabled federation grants keep working.
// Apply DirectoryTeamRoleMigrationSource before use.
func (r *Repository) WithDirectoryTeamRoles(authority DirectoryTeamRoleAuthority) (*Repository, error) {
	if r == nil || r.pool == nil || authority == nil {
		return nil, organization.ErrInvalidInput
	}
	configured := *r
	configured.directoryTeamRoles = authority
	return &configured, nil
}

const maximumDirectoryTeamRoleSources = 128

func (r *Repository) currentDirectoryTeamRoles(ctx context.Context, q organization.Query, v organization.View) ([]string, error) {
	rows, err := r.pool.Raw().Query(ctx, directoryTeamRoleCandidatesSQL, string(q.TenantID), string(q.OrganizationID), string(q.ActorID),
		strconv.FormatUint(v.Organization.Version, 10), strconv.FormatUint(v.Actor.Version, 10), strconv.FormatUint(v.Actor.AuthorizationVersion, 10), maximumDirectoryTeamRoleSources+1)
	if err != nil {
		return nil, storageError(ctx, err)
	}
	defer rows.Close()
	var sources []DirectoryTeamRoleSource
	for rows.Next() {
		if len(sources) >= maximumDirectoryTeamRoleSources {
			return nil, organization.ErrForbidden
		}
		source := DirectoryTeamRoleSource{Scope: DirectoryTeamGrantScope{TenantID: q.TenantID, OrganizationID: q.OrganizationID, UserID: q.ActorID}}
		var provider, mapping, connection string
		var overflow bool
		if err := rows.Scan(&source.Scope.ProviderID, &source.Scope.ConnectionID, &source.Scope.GroupID, &source.Scope.TeamID,
			&source.MemberResourceID, &source.RoleID, &provider, &mapping, &connection, &overflow); err != nil {
			return nil, organization.ErrUnavailable
		}
		if overflow {
			return nil, organization.ErrForbidden
		}
		source.ProviderVersion, err = positive(provider)
		if err != nil {
			return nil, err
		}
		source.MappingVersion, err = positive(mapping)
		if err != nil {
			return nil, err
		}
		source.ConnectionVersion, err = positive(connection)
		if err != nil {
			return nil, err
		}
		sources = append(sources, source)
	}
	if err := rows.Err(); err != nil {
		return nil, storageError(ctx, err)
	}
	rows.Close()
	if len(sources) == 0 {
		return nil, nil
	}
	// Retain the authoritative role identities separately; the callback receives
	// a detached slice and cannot substitute another role by editing it.
	roles := make([]organization.ID, len(sources))
	for i, source := range sources {
		roles[i] = source.RoleID
	}
	current, err := r.directoryTeamRoles(ctx, sources)
	if err != nil || len(current) != len(roles) || ctx.Err() != nil {
		return nil, organization.ErrUnavailable
	}
	active := make([]string, 0, len(roles))
	for i, role := range roles {
		if current[i] {
			active = append(active, string(role))
		}
	}
	// The final role query naturally deduplicates roles shared by several paths.
	return active, nil
}

// Bound the exact member's retained keys before current-state filtering. Fail
// closed on overflow rather than silently dropping a directory-derived deny.
const directoryTeamRoleCandidatesSQL = `WITH candidates AS MATERIALIZED (
 SELECT * FROM organization.directory_team_role_grants
 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3
 ORDER BY provider_id,connection_id,group_id,team_id LIMIT $7
)
SELECT d.provider_id::text,d.connection_id::text,d.group_id::text,d.team_id::text,d.member_resource_id::text,d.role_id::text,
 d.provider_version::text,d.mapping_version::text,d.connection_version::text,false
FROM candidates d
JOIN organization.directory_team_grants g USING(tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id)
JOIN organization.organizations o USING(tenant_id,organization_id)
JOIN organization.memberships m USING(tenant_id,organization_id,user_id)
JOIN organization.teams t USING(tenant_id,organization_id,team_id)
JOIN organization.team_identities i USING(tenant_id,organization_id,team_id)
JOIN organization.team_role_bindings b USING(tenant_id,organization_id,team_id,role_id)
WHERE g.active AND g.version=d.grant_version AND g.organization_member_version=m.version
 AND o.state='active' AND o.version=$4::numeric AND m.state='active'
 AND m.version=$5::numeric AND m.authorization_version=$6::numeric
 AND i.deleted_version IS NULL AND b.state='active' AND b.version=d.binding_version
 AND (SELECT count(*) FROM candidates)<$7
UNION ALL
SELECT '','','','','','','','','',true
FROM (SELECT count(*) AS total FROM candidates) retained WHERE total=$7`
