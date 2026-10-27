package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// TeamRoleBindingRevokeOperationLookupMigrationSource extends existing atomic
// effects with nullable team-only original selectors after TeamRoleBindingMigrationSource,
// at an unused permanent version. Legacy and direct effects remain NULL; missing
// bindings cannot reconstruct history. Raw explicit writers need no optional
// schema. The transactional index build blocks writes: select a bounded operator
// maintenance window with lock/transaction timeouts before activation.
type TeamRoleBindingRevokeOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns one atomic forward migration without IO or partial results.
func (s TeamRoleBindingRevokeOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_team_role_revoke_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN revoke_team_role_id identity.directory_id,
 ADD COLUMN revoke_team_role_version identity.version,
 ADD COLUMN revoke_team_id identity.directory_id,
 ADD COLUMN revoke_team_version identity.version,
 ADD COLUMN revoke_team_binding_version identity.version,
 ADD CONSTRAINT organization_team_role_revoke_scope CHECK(
  (revoke_team_role_id IS NULL AND revoke_team_role_version IS NULL AND revoke_team_id IS NULL AND revoke_team_version IS NULL AND revoke_team_binding_version IS NULL) OR
  (operation='identity.organization.role.revoke' AND before_version>0 AND before_version<18446744073709551615 AND revoke_team_role_id IS NOT NULL AND revoke_team_role_version IS NOT NULL AND revoke_team_role_version<18446744073709551615 AND revoke_team_id IS NOT NULL AND revoke_team_version IS NOT NULL AND revoke_team_version<18446744073709551615 AND revoke_team_binding_version IS NOT NULL AND revoke_team_binding_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_team_role_revoke
 ON organization.command_effects(tenant_id,organization_id,before_version)
 WHERE operation='identity.organization.role.revoke' AND revoke_team_id IS NOT NULL;`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
