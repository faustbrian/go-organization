package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// TeamMemberOperationLookupMigrationSource adds exact natural-removal selectors
// to existing command effects after the organization/team migrations. Choose an
// unused permanent version. Existing effects stay NULL: current rows do not prove
// their original team/admission versions. Raw explicit APIs need no migration.
// The transactional partial-index build blocks writes; install with bounded
// lock/transaction timeouts in an operator maintenance window before activation.
// This adds no journal, backfill, authority source or automatic runtime selection.
type TeamMemberOperationLookupMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only atomic migration without IO. Invalid versions
// and nil/cancelled contexts fail without returning partial work.
func (s TeamMemberOperationLookupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_team_member_operation", migrations.TransactionModeDefault, `ALTER TABLE organization.command_effects
 ADD COLUMN remove_team_id identity.directory_id,
 ADD COLUMN remove_team_version identity.version,
 ADD COLUMN remove_org_member_version identity.version,
 ADD COLUMN remove_membership_version identity.version,
 ADD CONSTRAINT organization_team_member_removal_scope CHECK(
  (remove_team_id IS NULL AND remove_team_version IS NULL AND remove_org_member_version IS NULL AND remove_membership_version IS NULL) OR
  (operation='identity.organization.team.member-remove' AND before_version>0 AND before_version<18446744073709551615 AND remove_team_id IS NOT NULL AND remove_team_version IS NOT NULL AND remove_team_version<18446744073709551615 AND remove_org_member_version IS NOT NULL AND remove_membership_version IS NOT NULL AND remove_membership_version<18446744073709551615)
 );
CREATE UNIQUE INDEX organization_repeat_team_member_removal
 ON organization.command_effects(tenant_id,organization_id,before_version)
 WHERE operation='identity.organization.team.member-remove' AND remove_team_id IS NOT NULL;`, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}
