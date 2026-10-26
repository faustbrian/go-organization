package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationRejectOperationMigrationSource adds exact natural-repeat correlation
// to existing rejection effects after the selected invitation migrations. It
// does not require the optional cancellation-operation migration. Allocate one
// unused permanent version. Existing effects retain NULL correlation because
// today's organization epoch cannot reconstruct their original admission.
// Raw explicit rejection remains independent of this optional migration.
//
// The transactional index build blocks writes. Apply it in an explicit bounded
// operator maintenance window with transaction/lock timeouts before enabling
// Reject, not as automatic runtime activation. This introduces no new journal.
type InvitationRejectOperationMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only migration without IO. Invalid versions and
// nil/cancelled contexts fail without returning a partial migration.
func (s InvitationRejectOperationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_reject_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN reject_organization_version identity.version,
 ADD CONSTRAINT organization_reject_operation_scope CHECK(
  reject_organization_version IS NULL OR
  (operation='identity.organization.invitation.reject' AND reject_organization_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_invitation_reject
 ON organization.command_effects(tenant_id,organization_id,invitation_id,before_version)
 WHERE operation='identity.organization.invitation.reject';`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
