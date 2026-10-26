package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// TeamDeleteOperationLookupMigrationSource adds nullable exact natural-delete
// correlation to the existing effect after the organization/team lifecycle
// migrations, at an unused permanent version. Existing effects remain NULL;
// terminal state cannot backfill their original admission. Raw explicit team
// commands remain compatible without this optional migration. The transactional
// index build blocks writes: use a bounded operator maintenance window with
// lock/transaction timeouts before activation. No journal or authority is added.
type TeamDeleteOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns one atomic forward migration without IO or partial results.
func (s TeamDeleteOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_team_delete_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN delete_team_id identity.directory_id,
 ADD COLUMN delete_team_version identity.version,
 ADD CONSTRAINT organization_team_delete_operation_scope CHECK(
  (delete_team_id IS NULL AND delete_team_version IS NULL) OR
  (operation='identity.organization.team.delete' AND before_version>0 AND before_version<18446744073709551615 AND delete_team_id IS NOT NULL AND delete_team_version IS NOT NULL AND delete_team_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_team_delete
 ON organization.command_effects(tenant_id,organization_id,before_version)
 WHERE operation='identity.organization.team.delete' AND delete_team_id IS NOT NULL;`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
