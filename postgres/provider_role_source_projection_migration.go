package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
	organization "github.com/faustbrian/go-organization"
)

// ProviderRoleSourceProjectionMigrationSource installs the organization-owned
// storage API for a federation provider's grant source. Install after
// ProviderRoleGrantMigrationSource and before the federation owner's projection
// trigger. Retiring a source with retained grants advances organization policy
// at commit, after the provider owner's existing authority fences. It neither
// enumerates providers nor seeds authority.
type ProviderRoleSourceProjectionMigrationSource struct{ Version migrations.Version }

func (s ProviderRoleSourceProjectionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, organization.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(s.Version, "organization_provider_role_source_projection", migrations.TransactionModeDefault, providerRoleSourceProjectionSQL, "")
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return []migrations.Migration{migration}, nil
}

// A provider owner calls this in its own authoritative transition, in the same
// transaction. It projects non-secret grant eligibility; it doesn't change any
// provider record, membership, or application grant. Preserve the last retired
// generation so an old provider row cannot restore grants after reinstallation.
const providerRoleSourceProjectionSQL = `SET LOCAL lock_timeout='2s';
CREATE FUNCTION organization.invalidate_provider_role_source_policy() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $policy$
DECLARE
  policy_version numeric;
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM organization.provider_role_grants
    WHERE tenant_id=OLD.tenant_id AND organization_id=OLD.organization_id AND provider_id=OLD.provider_id
      AND provider_generation=OLD.generation AND mapping_version=OLD.mapping_version AND cardinality(role_ids)>0
  ) THEN
    RETURN NULL;
  END IF;
  -- Provider owners retain their original final authority fence. Defer this
  -- policy change until commit and never wait behind an opposite lock order
  -- held by an application writer or a provider callback.
  SELECT version INTO policy_version FROM organization.organizations
  WHERE tenant_id=OLD.tenant_id AND organization_id=OLD.organization_id AND state='active'
  FOR NO KEY UPDATE NOWAIT;
  IF NOT FOUND THEN
    -- Archive/deletion already makes the organization's authority unusable.
    RETURN NULL;
  END IF;
  IF policy_version=18446744073709551615 THEN
    RAISE EXCEPTION 'organization policy epoch exhausted' USING ERRCODE='22003';
  END IF;
  UPDATE organization.organizations SET version=version+1
  WHERE tenant_id=OLD.tenant_id AND organization_id=OLD.organization_id
    AND state='active' AND version=policy_version AND version<18446744073709551615;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'organization policy invalidation did not advance' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$policy$;
CREATE CONSTRAINT TRIGGER organization_provider_role_source_policy
AFTER UPDATE ON organization.provider_role_sources
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (OLD.active AND (
  NEW.generation IS DISTINCT FROM OLD.generation OR NEW.mapping_version IS DISTINCT FROM OLD.mapping_version OR NOT NEW.active
)) EXECUTE FUNCTION organization.invalidate_provider_role_source_policy();
CREATE FUNCTION organization.project_provider_role_source(
  tenant text, org text, provider text, source_generation numeric, source_mapping numeric, eligible boolean
) RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $project$
BEGIN
  INSERT INTO organization.provider_role_sources AS prior
  (tenant_id,organization_id,provider_id,generation,mapping_version,active)
  VALUES (tenant,org,provider,source_generation,source_mapping,eligible)
  ON CONFLICT (tenant_id,organization_id,provider_id) DO UPDATE SET
  generation=EXCLUDED.generation,mapping_version=EXCLUDED.mapping_version,active=EXCLUDED.active
  WHERE prior.mapping_version<=EXCLUDED.mapping_version AND (
    prior.generation<EXCLUDED.generation OR (
      prior.generation=EXCLUDED.generation AND prior.mapping_version=EXCLUDED.mapping_version
      AND (prior.active OR NOT EXCLUDED.active)
    )
  );
  IF NOT FOUND THEN
    RAISE EXCEPTION 'provider role source checkpoint would rewind' USING ERRCODE='23514';
  END IF;
END;
$project$;`
