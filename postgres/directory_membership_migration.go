package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DirectoryMembershipMigrationSource installs empty, opt-in directory membership
// provenance after the existing organization history. Allocate a fresh Version
// and install this schema before enabling directory membership writers. Existing
// membership writers and mixed base runtimes remain unaffected: this extension
// does not backfill, rewrite, or attach triggers to their tables.
//
// Installation takes a short, bounded lock on the referenced membership table;
// retry an aborted migration before enabling callers. Membership incarnations
// and source tombstones retain their original resource identity. Recovery is
// roll-forward, with no destructive Down that could discard that provenance.
type DirectoryMembershipMigrationSource struct{ Version uint64 }

func (s DirectoryMembershipMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > math.MaxInt64 {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(migrations.Version(s.Version), "organization_directory_membership_grants", migrations.TransactionModeDefault, directoryMembershipSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The only FK identifies an existing membership, not its mutable incarnation.
// Keeping member_version in the source PK preserves retired incarnations without
// rebinding their resource. The active partial index serves the authoritative
// remaining-source EXISTS check while its caller holds the canonical member lock;
// retained tombstones must not widen the work of a current-authority lookup.
const directoryMembershipSQL = `SET LOCAL lock_timeout = '2s';
SET LOCAL statement_timeout = '5s';
CREATE TABLE organization.directory_membership_grants (
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 member_version identity.version NOT NULL,
 provider_id identity.directory_id NOT NULL,
 connection_id identity.directory_id NOT NULL,
 resource_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 active boolean NOT NULL,
 PRIMARY KEY(tenant_id,organization_id,user_id,member_version,provider_id,connection_id),
 FOREIGN KEY(tenant_id,organization_id,user_id) REFERENCES organization.memberships(tenant_id,organization_id,user_id)
);
CREATE INDEX organization_directory_membership_active
 ON organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version)
 WHERE active;`
