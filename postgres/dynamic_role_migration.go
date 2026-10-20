package postgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
	"math"
)

// DynamicRoleMigrationSource adds direct custom roles and membership-bound role
// assignments without changing installed migration bytes or existing roles.
// Install after MigrationSource, before enabling DynamicRoleConfig. Deleted role
// rows remain bounded tombstones and are never recreated or reassigned.
type DynamicRoleMigrationSource struct{ Version migrations.Version }

func (s DynamicRoleMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_dynamic_roles", migrations.TransactionModeDefault, dynamicRoleSchemaSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const dynamicRoleSchemaSQL = `CREATE TABLE organization.custom_roles(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 role_id identity.directory_id NOT NULL CHECK(role_id NOT IN('owner','administrator','member')),
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 256),
 version identity.version NOT NULL,
 state text NOT NULL CHECK(state IN('active','deleted')),
 statements text NOT NULL CHECK(octet_length(statements)<=8192),
 PRIMARY KEY(tenant_id,organization_id,role_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id)
);
CREATE TABLE organization.role_bindings(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 role_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 organization_member_version identity.version NOT NULL,
 state text NOT NULL CHECK(state IN('active','removed')),
 PRIMARY KEY(tenant_id,organization_id,role_id,user_id),
 FOREIGN KEY(tenant_id,organization_id,role_id) REFERENCES organization.custom_roles(tenant_id,organization_id,role_id),
 FOREIGN KEY(tenant_id,organization_id,user_id) REFERENCES organization.memberships(tenant_id,organization_id,user_id)
);
CREATE INDEX organization_role_member ON organization.role_bindings(tenant_id,organization_id,user_id,role_id) WHERE state='active';`
