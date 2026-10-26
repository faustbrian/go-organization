package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationCancelOperationMigrationSource adds exact natural-repeat correlation
// to existing cancellation effects after all installed invitation migrations.
// Allocate one unused permanent version. Existing effects remain unchanged and
// nullable: their original organization epoch cannot be reconstructed safely.
// Raw explicit cancellation stays compatible with old and new installations.
//
// The transactional index build blocks table writes. Apply it in a bounded
// operator maintenance window with configured transaction/lock timeouts, before
// enabling Cancel; this is not automatic runtime activation or a new journal.
type InvitationCancelOperationMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only migration without IO. Invalid versions and
// nil/cancelled contexts fail without returning a partial migration.
func (s InvitationCancelOperationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_cancel_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN cancel_organization_version identity.version,
 ADD CONSTRAINT organization_cancel_operation_scope CHECK(
  cancel_organization_version IS NULL OR
  (operation='identity.organization.invitation.cancel' AND cancel_organization_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_invitation_cancel
 ON organization.command_effects(tenant_id,organization_id,invitation_id,before_version)
 WHERE operation='identity.organization.invitation.cancel';`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
