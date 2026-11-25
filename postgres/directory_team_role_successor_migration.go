package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamRoleSuccessorMigrationSource expands the existing directory
// effect check before mixed writers record role successors. Assign its own
// permanent version after DirectoryMembershipSuccessorMigrationSource. The
// bounded metadata change retains all published rows and needs no backfill.
type DirectoryTeamRoleSuccessorMigrationSource struct{ Version uint64 }

func (s DirectoryTeamRoleSuccessorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > math.MaxInt64 {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(migrations.Version(s.Version), "organization_directory_team_role_successor", migrations.TransactionModeDefault, directoryTeamRoleSuccessorSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The role profile shares its operation with ordinary Group membership. The
// writer, not that operation label, binds the exact role source and live Work.
const directoryTeamRoleSuccessorSQL = `SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
ALTER TABLE organization.command_effects
 DROP CONSTRAINT organization_directory_membership_successor_scope,
 ADD CONSTRAINT organization_directory_successor_scope CHECK (
  (directory_org_before IS NULL AND directory_org_after IS NULL AND directory_credential_version IS NULL)
  OR (operation IN ('identity.sso.directory-sync.apply-user-admission','identity.sso.directory-sync.apply-user-deprovision','identity.sso.directory-sync.apply-child')
      AND directory_org_before IS NOT NULL AND directory_org_after IS NOT NULL AND directory_credential_version IS NOT NULL
      AND directory_org_after IN (directory_org_before,directory_org_before+1))
 ) NOT VALID;`
