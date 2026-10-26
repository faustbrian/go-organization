package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// InvitationExpireOperationMigrationSource adds natural-repeat correlation to
// existing expiry effects after the selected invitation migrations. Allocate
// one unused permanent version. Existing effects remain NULL: neither today's
// organization version nor terminal reason proves their original admission.
// Raw PrepareExpire/Execute remains independent of this optional migration.
//
// The transactional index build blocks writes. Apply it in a bounded operator
// maintenance window with transaction/lock timeouts before enabling Expire.
// The partial index enforces a single terminal effect for an invitation epoch;
// it is not a separate journal or automatic runtime activation.
type InvitationExpireOperationMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only migration without IO. Invalid versions and
// nil/cancelled contexts fail without returning partial work.
func (s InvitationExpireOperationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_invitation_expire_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN expire_organization_version identity.version,
 ADD COLUMN expire_reason text COLLATE "C",
 ADD CONSTRAINT organization_expire_operation_scope CHECK(
  (expire_organization_version IS NULL AND expire_reason IS NULL) OR
  (operation='identity.organization.invitation.expire' AND expire_organization_version IS NOT NULL AND expire_organization_version<18446744073709551615 AND expire_reason IS NOT NULL AND octet_length(expire_reason) BETWEEN 1 AND 64)
 );
CREATE UNIQUE INDEX organization_repeat_invitation_expire
 ON organization.command_effects(tenant_id,organization_id,invitation_id,before_version)
 WHERE operation='identity.organization.invitation.expire';`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
