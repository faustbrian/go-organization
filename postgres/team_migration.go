package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// TeamMigrationSource adds only teams and version-bound membership tombstones.
// Allocate Version after the installed organization migrations. No organization
// or member backfill, legacy checksum change or session selection is performed.
type TeamMigrationSource struct{ Version migrations.Version }

func (s TeamMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_teams", migrations.TransactionModeDefault, teamSchemaSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const teamSchemaSQL = `CREATE TABLE organization.teams(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 256),
 version identity.version NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,team_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id)
);
CREATE TABLE organization.team_memberships(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 state text NOT NULL CHECK(state IN('active','removed')),
 version identity.version NOT NULL,
 organization_member_version identity.version NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,team_id,user_id),
 FOREIGN KEY(tenant_id,organization_id,team_id) REFERENCES organization.teams(tenant_id,organization_id,team_id),
 FOREIGN KEY(tenant_id,organization_id,user_id) REFERENCES organization.memberships(tenant_id,organization_id,user_id)
);
CREATE INDEX organization_team_mine ON organization.team_memberships(tenant_id,organization_id,user_id,team_id) WHERE state='active';`
