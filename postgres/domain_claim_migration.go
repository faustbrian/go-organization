package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DomainClaimMigrationSource adds reservation custody after MigrationSource.
// Apply before selecting DomainConfig. Existing migration bytes and existing
// organization/member rows are unchanged. No ownership proof or routing exists.
type DomainClaimMigrationSource struct{ Version migrations.Version }

func (s DomainClaimMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	m, e := migrations.NewMigration(s.Version, "organization_domain_reservations", migrations.TransactionModeDefault, domainClaimSQL, "")
	if e != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const domainClaimSQL = `CREATE TABLE organization.domain_claims(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 claim_id identity.directory_id NOT NULL,
 canonical_domain text COLLATE "C" NOT NULL CHECK(octet_length(canonical_domain) BETWEEN 3 AND 253 AND canonical_domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' AND split_part(canonical_domain,'.',-1) ~ '[a-z]'),
 state text NOT NULL CHECK(state IN('requested','withdrawn')),
 version identity.version NOT NULL CHECK((state='requested' AND version=1) OR (state='withdrawn' AND version=2)),
 PRIMARY KEY(tenant_id,organization_id,claim_id),
 FOREIGN KEY(tenant_id,organization_id) REFERENCES organization.organizations(tenant_id,organization_id)
);
-- Global across tenants: a losing writer learns only the generic conflict.
CREATE UNIQUE INDEX organization_domain_active_unique ON organization.domain_claims(canonical_domain) WHERE state='requested';`
