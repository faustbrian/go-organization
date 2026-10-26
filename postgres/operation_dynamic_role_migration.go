package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DynamicRoleDeleteOperationLookupMigrationSource adds nullable exact original
// delete selectors to existing command effects after DynamicRoleMigrationSource,
// at an unused permanent version. Legacy effects remain NULL; terminal role rows
// cannot backfill original intent. Raw explicit writers remain compatible without
// this optional schema. The transactional index build blocks writes: activate in
// a bounded maintenance window with lock/transaction timeouts. No new journal,
// permission source or backfill is introduced.
type DynamicRoleDeleteOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns one atomic forward migration without IO or partial results.
func (s DynamicRoleDeleteOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_role_delete_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN delete_role_id identity.directory_id,
 ADD COLUMN delete_role_version identity.version,
 ADD CONSTRAINT organization_role_delete_operation_scope CHECK(
  (delete_role_id IS NULL AND delete_role_version IS NULL) OR
  (operation='identity.organization.role.delete' AND before_version>0 AND before_version<18446744073709551615 AND delete_role_id IS NOT NULL AND delete_role_version IS NOT NULL AND delete_role_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_role_delete
 ON organization.command_effects(tenant_id,organization_id,before_version)
 WHERE operation='identity.organization.role.delete' AND delete_role_id IS NOT NULL;`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
