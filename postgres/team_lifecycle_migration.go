package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// TeamLifecycleMigrationSource preserves installed membership migration bytes.
// Apply after TeamMigrationSource before selecting LifecycleVersion 1. Retained
// identities are immutable deletion tombstones, not a second authority engine.
// Existing readers deny deleted teams because only live teams remain in teams.
type TeamLifecycleMigrationSource struct{ Version migrations.Version }

func (s TeamLifecycleMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_team_lifecycle", migrations.TransactionModeDefault, teamLifecycleSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const teamLifecycleSQL = `CREATE TABLE organization.team_identities(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 team_id identity.directory_id NOT NULL,
 deleted_version identity.version,
 PRIMARY KEY(tenant_id,organization_id,team_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id)
);
INSERT INTO organization.team_identities(tenant_id,organization_id,team_id) SELECT tenant_id,organization_id,team_id FROM organization.teams;
ALTER TABLE organization.teams ADD CONSTRAINT organization_team_identity FOREIGN KEY(tenant_id,organization_id,team_id) REFERENCES organization.team_identities(tenant_id,organization_id,team_id);
DO $$ DECLARE original_fk text; BEGIN
 SELECT conname INTO STRICT original_fk FROM pg_constraint WHERE conrelid='organization.team_memberships'::regclass AND confrelid='organization.teams'::regclass AND contype='f';
 EXECUTE format('ALTER TABLE organization.team_memberships DROP CONSTRAINT %I',original_fk);
END $$;
ALTER TABLE organization.team_memberships ADD CONSTRAINT organization_team_member_identity FOREIGN KEY(tenant_id,organization_id,team_id) REFERENCES organization.team_identities(tenant_id,organization_id,team_id);
CREATE FUNCTION organization.guard_team_identity_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE retired identity.version;
BEGIN
 INSERT INTO organization.team_identities(tenant_id,organization_id,team_id) VALUES(NEW.tenant_id,NEW.organization_id,NEW.team_id) ON CONFLICT DO NOTHING;
 SELECT deleted_version INTO STRICT retired FROM organization.team_identities WHERE tenant_id=NEW.tenant_id AND organization_id=NEW.organization_id AND team_id=NEW.team_id FOR SHARE;
 IF retired IS NOT NULL THEN RAISE unique_violation USING MESSAGE='team identity is retired'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER organization_team_identity_insert BEFORE INSERT ON organization.teams FOR EACH ROW EXECUTE FUNCTION organization.guard_team_identity_insert();`
