package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// ProviderRoleGrantMigrationSource adds separately owned provider grants. Apply
// after DynamicRoleMigrationSource and before opting a reader into those grants.
// Existing bindings are unchanged; no backfill or data rewrite is required.
type ProviderRoleGrantMigrationSource struct{ Version migrations.Version }

func (s ProviderRoleGrantMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(s.Version, "organization_provider_role_grants", migrations.TransactionModeDefault, providerRoleGrantSchema, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{migration}, nil
}

// Both tables start empty. Bound the wait on the existing referenced tables;
// disabling a source does not require rewriting every linked member's grants.
const providerRoleGrantSchema = `SET LOCAL lock_timeout = '2s';
CREATE TABLE organization.provider_role_sources (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 generation identity.version NOT NULL,
 mapping_version identity.version NOT NULL,
 active boolean NOT NULL,
 PRIMARY KEY (tenant_id, organization_id, provider_id),
 FOREIGN KEY (tenant_id, organization_id) REFERENCES organization.organizations(tenant_id, organization_id)
);
CREATE TABLE organization.provider_role_grants (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 provider_id identity.directory_id NOT NULL,
 provider_generation identity.version NOT NULL,
 mapping_version identity.version NOT NULL,
 organization_member_version identity.version NOT NULL,
 flow_started_at timestamptz NOT NULL,
 assertion_issued_at timestamptz NOT NULL,
 role_ids text[] NOT NULL CHECK (cardinality(role_ids) <= 100),
 PRIMARY KEY (tenant_id, organization_id, user_id, provider_id),
 FOREIGN KEY (tenant_id, organization_id, user_id) REFERENCES organization.memberships(tenant_id, organization_id, user_id),
 FOREIGN KEY (tenant_id, organization_id, provider_id) REFERENCES organization.provider_role_sources(tenant_id, organization_id, provider_id)
);
CREATE INDEX organization_provider_role_grant_source_policy
ON organization.provider_role_grants(tenant_id,organization_id,provider_id,provider_generation,mapping_version)
WHERE cardinality(role_ids)>0;`
