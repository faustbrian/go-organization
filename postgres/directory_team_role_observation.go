package postgres

import (
	"context"

	organization "github.com/faustbrian/go-organization"
)

// ObserveDirectoryTeamRoleBinding reads one exact active native custom-role
// binding from the primary, requiring an active role and existing nondeleted
// team. Scope identifies its tenant, organization and team; source metadata is
// not authenticated here. This trusted persistence API performs no caller
// admission, grants no session or source authority, and must not be exposed
// directly to HTTP. The original Work must still recheck the selected binding
// and its current organization, member, user and source fences.
// Reads are bounded, uncached and retain no snapshot locks. Missing, foreign or
// inactive selections return zero and ErrForbidden; invalid inputs return zero
// and ErrInvalidInput. Storage failures and cancellation preserve zero output.
func (r *Repository) ObserveDirectoryTeamRoleBinding(ctx context.Context, s DirectoryTeamGrantScope, roleID organization.ID) (uint64, error) {
	if r == nil || r.pool == nil || ctx == nil || !s.validate() || !scope(string(roleID)) {
		return 0, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	var raw string
	err := r.pool.Raw().QueryRow(ctx, directoryTeamRoleObservationSQL, string(s.TenantID), string(s.OrganizationID), string(s.TeamID), string(roleID)).Scan(&raw)
	if err != nil {
		return 0, storageError(ctx, err)
	}
	version, err := positive(raw)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return version, nil
}

const directoryTeamRoleObservationSQL = `SELECT b.version::text
FROM organization.team_role_bindings b
JOIN organization.custom_roles r USING(tenant_id,organization_id,role_id)
JOIN organization.teams t USING(tenant_id,organization_id,team_id)
JOIN organization.team_identities ti USING(tenant_id,organization_id,team_id)
WHERE b.tenant_id=$1 AND b.organization_id=$2 AND b.team_id=$3 AND b.role_id=$4
 AND b.state='active' AND r.state='active' AND ti.deleted_version IS NULL`
