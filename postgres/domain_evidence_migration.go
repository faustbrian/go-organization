package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// DomainEvidenceMigrationSource adds immutable authoritative proof history
// after DomainClaimMigrationSource. Existing reservation bytes remain unchanged.
// Install before configuring DomainEvidenceSource. The identity coordinator is
// still the only command journal; these rows contain domain results, not retries.
type DomainEvidenceMigrationSource struct{ Version migrations.Version }

func (s DomainEvidenceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_domain_evidence", migrations.TransactionModeDefault, domainEvidenceSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

const domainEvidenceSQL = `ALTER TABLE organization.domain_claims ADD COLUMN proof_retired boolean NOT NULL DEFAULT false;
UPDATE organization.domain_claims c SET proof_retired=true FROM organization.organizations o WHERE o.tenant_id=c.tenant_id AND o.organization_id=c.organization_id AND (c.state='withdrawn' OR o.state<>'active');
CREATE FUNCTION organization.retire_domain_proofs() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.state='active' AND NEW.state<>'active' THEN
  UPDATE organization.domain_claims SET proof_retired=true WHERE tenant_id=NEW.tenant_id AND organization_id=NEW.organization_id AND NOT proof_retired;
 END IF;
 RETURN NEW;
END $$;
-- Database ownership includes old archive writers: restoring an organization
-- must never resurrect proof observed before its terminal lifecycle boundary.
CREATE TRIGGER organization_retire_domain_proofs AFTER UPDATE OF state ON organization.organizations FOR EACH ROW EXECUTE FUNCTION organization.retire_domain_proofs();
CREATE FUNCTION organization.guard_domain_proof_retirement() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.proof_retired AND NOT NEW.proof_retired THEN RAISE check_violation USING MESSAGE='domain proof identity is retired'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER organization_guard_domain_proof_retirement BEFORE UPDATE OF proof_retired ON organization.domain_claims FOR EACH ROW EXECUTE FUNCTION organization.guard_domain_proof_retirement();
CREATE TABLE organization.domain_evidence(
 tenant_id identity.directory_id NOT NULL,
 organization_id identity.directory_id NOT NULL,
 claim_id identity.directory_id NOT NULL,
 canonical_domain text COLLATE "C" NOT NULL,
 claim_version identity.version NOT NULL CHECK(claim_version=1),
 proof_version identity.version NOT NULL CHECK(proof_version IN(1,2)),
 method text NOT NULL CHECK(method IN('dns-txt','https')),
 observed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL CHECK(expires_at>observed_at),
 revoked boolean NOT NULL CHECK((proof_version=1 AND NOT revoked) OR (proof_version=2 AND revoked)),
 command_id text NOT NULL UNIQUE,
 PRIMARY KEY(tenant_id,organization_id,claim_id,proof_version),
 FOREIGN KEY(tenant_id,organization_id,claim_id) REFERENCES organization.domain_claims(tenant_id,organization_id,claim_id)
);`
