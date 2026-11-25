package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamRoleMigrationSource installs empty role eligibility after the
// directory team grant and native team role histories. Run it before selecting
// role reads or writes. No existing source becomes permission-bearing.
type DirectoryTeamRoleMigrationSource struct{ Version migrations.Version }

func (s DirectoryTeamRoleMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "organization_directory_team_role_grants", migrations.TransactionModeDefault, directoryTeamRoleMigrationSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{step}, nil
}

// The new table is empty. Its member-first permanent key bounds enumeration;
// referenced tables get short FK locks, not an installed-table scan or rewrite.
const directoryTeamRoleMigrationSQL = `SET LOCAL lock_timeout = '2s';
CREATE TABLE organization.directory_team_role_grants (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 group_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 member_resource_id identity.directory_id NOT NULL,
 role_id identity.directory_id NOT NULL,
 grant_version identity.version NOT NULL,
 binding_version identity.version NOT NULL,
 provider_version identity.version NOT NULL,
 mapping_version identity.version NOT NULL,
 connection_version identity.version NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,user_id,provider_id,connection_id,group_id,team_id),
 FOREIGN KEY(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id)
  REFERENCES organization.directory_team_grants(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id)
);`
