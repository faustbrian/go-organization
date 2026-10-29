package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// CredentialAuthorityMigrationSource optionally adds independent credential
// revocation to the existing organization rows. Allocate Version after the
// installed organization history. Existing default/member-only bootstraps do
// not require this extension. The transactional ALTER takes an exclusive table
// lock; apply under a bounded migration context and deployment lock budget.
// Existing rows begin at one; supplied positive insert epochs remain intact for
// trusted imports. No previously published migration or checksum is modified.
// Recovery is roll-forward: removing this invariant could revive revoked keys.
type CredentialAuthorityMigrationSource struct{ Version migrations.Version }

func (s CredentialAuthorityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "organization_credential_authority", migrations.TransactionModeDefault, credentialAuthoritySQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{m}, nil
}

// The row owns its credential epoch so pre-extension lifecycle writers cannot
// archive and restore an independent key back into validity (SI-02). Policy and
// membership writers retain their existing aggregate version ownership.
const credentialAuthoritySQL = `ALTER TABLE organization.organizations
 ADD COLUMN credential_version identity.version NOT NULL DEFAULT 1;
CREATE FUNCTION organization.enforce_credential_epoch_transition() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $credential_epoch$
BEGIN
 IF NEW.credential_version IS DISTINCT FROM OLD.credential_version THEN
  RAISE EXCEPTION 'organization credential epoch is transition-owned'
   USING ERRCODE='23514', CONSTRAINT='organization_credential_epoch_transition';
 END IF;
 IF NEW.state IS DISTINCT FROM OLD.state AND NEW.state IN ('archived','deleted') THEN
  IF OLD.credential_version = 18446744073709551615 THEN
   RAISE EXCEPTION 'organization credential epoch exhausted' USING ERRCODE='22003';
  END IF;
  NEW.credential_version := OLD.credential_version + 1;
 END IF;
 RETURN NEW;
END;
$credential_epoch$;
CREATE TRIGGER organization_credential_epoch_transition
 BEFORE UPDATE ON organization.organizations
 FOR EACH ROW EXECUTE FUNCTION organization.enforce_credential_epoch_transition();`
