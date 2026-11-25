package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipSuccessorMigrationSource extends command effects before
// enabling opt-in directory successor recording. Assign a new permanent version
// after the directory membership migration. The metadata-only ALTER takes a
// bounded exclusive lock; retry failure before enabling the new writer. Legacy
// rows and writers leave these nullable columns untouched. No historical effect
// can be inferred or backfilled, and roll-forward retains recorded evidence.
type DirectoryMembershipSuccessorMigrationSource struct{ Version uint64 }

// Load returns the forward-only schema expansion without contacting storage.
func (s DirectoryMembershipSuccessorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > math.MaxInt64 {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(migrations.Version(s.Version), "organization_directory_membership_successor", migrations.TransactionModeDefault, directoryMembershipSuccessorSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// Existing rows necessarily have three NULLs. Enforce the shape for writes
// without validation scanning retained command history during the rollout.
const directoryMembershipSuccessorSQL = `SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
ALTER TABLE organization.command_effects
 ADD COLUMN directory_org_before identity.version,
 ADD COLUMN directory_org_after identity.version,
 ADD COLUMN directory_credential_version identity.version,
 ADD CONSTRAINT organization_directory_membership_successor_scope CHECK (
  (directory_org_before IS NULL AND directory_org_after IS NULL AND directory_credential_version IS NULL)
  OR (operation IN ('identity.sso.directory-sync.apply-user-admission','identity.sso.directory-sync.apply-user-deprovision')
      AND directory_org_before IS NOT NULL AND directory_org_after IS NOT NULL AND directory_credential_version IS NOT NULL
      AND directory_org_after IN (directory_org_before,directory_org_before+1))
 ) NOT VALID;`
