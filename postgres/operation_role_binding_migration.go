package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// RoleBindingRevokeOperationLookupMigrationSource extends existing atomic effects
// with nullable original direct-revocation selectors after DynamicRoleMigrationSource,
// at an unused permanent version. Legacy effects remain NULL: absent/inactive
// bindings cannot backfill original intent. Raw explicit direct/team writers
// need no optional schema. The transactional index build blocks writes; use a
// bounded maintenance window with lock/transaction timeouts before activation.
// No new journal, cache, permission source or authority is introduced.
type RoleBindingRevokeOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns one atomic forward migration without IO or partial results.
func (s RoleBindingRevokeOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_role_binding_revoke_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN revoke_role_id identity.directory_id,
 ADD COLUMN revoke_role_version identity.version,
 ADD COLUMN revoke_member_version identity.version,
 ADD COLUMN revoke_binding_version identity.version,
 ADD CONSTRAINT organization_role_binding_revoke_scope CHECK(
  (revoke_role_id IS NULL AND revoke_role_version IS NULL AND revoke_member_version IS NULL AND revoke_binding_version IS NULL) OR
  (operation='identity.organization.role.revoke' AND before_version>0 AND before_version<18446744073709551615 AND revoke_role_id IS NOT NULL AND revoke_role_version IS NOT NULL AND revoke_role_version<18446744073709551615 AND revoke_member_version IS NOT NULL AND revoke_binding_version IS NOT NULL AND revoke_binding_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_role_revoke
 ON organization.command_effects(tenant_id,organization_id,before_version)
 WHERE operation='identity.organization.role.revoke' AND revoke_role_id IS NOT NULL;`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
