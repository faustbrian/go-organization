package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryTeamGrantMigrationSource adds an empty, opt-in membership-only source
// table after TeamLifecycleMigrationSource and CredentialAuthorityMigrationSource.
// Install before enabling the SSO child writer/observer. Old binaries and local
// grants are untouched; no backfill is required. Tombstones are retained, so
// reverting callers does not lose provenance and no destructive Down is offered.
type DirectoryTeamGrantMigrationSource struct{ Version migrations.Version }

func (s DirectoryTeamGrantMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_directory_team_grants", migrations.TransactionModeDefault, directoryTeamGrantSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// Only the new empty table is indexed. Referenced keys acquire bounded locks;
// there is no scan, rewrite, trigger or index build on an installed table.
const directoryTeamGrantSQL = `SET LOCAL lock_timeout = '2s';
CREATE TABLE organization.directory_team_grants (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 group_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 organization_member_version identity.version NOT NULL,
 active boolean NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,provider_id,connection_id,group_id,team_id,user_id),
 FOREIGN KEY(tenant_id,organization_id,team_id) REFERENCES organization.team_identities(tenant_id,organization_id,team_id),
 FOREIGN KEY(tenant_id,organization_id,user_id) REFERENCES organization.memberships(tenant_id,organization_id,user_id)
);`
