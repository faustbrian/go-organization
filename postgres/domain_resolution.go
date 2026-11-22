package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// ResolveDomainProof returns the detached current organization-owned proof for
// an exact canonical domain and tenant. This uncached primary read is only for
// trusted native composition, not public discovery or human authentication.
// Absent, foreign, expired, retired and revoked authority all return ErrForbidden;
// invalid scope/input returns ErrInvalidInput. Context cancellation is preserved.
// The result grants neither routing nor login authority: consumers must bind
// the exact proof and revalidate it through GetDomainProof at their boundary.
func (r *Repository) ResolveDomainProof(ctx context.Context, tenant identity.TenantID, domain string) (organization.DomainProof, error) {
	canonical, err := organization.CanonicalDomain(domain)
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || !scope(string(tenant)) || err != nil || canonical != domain {
		return organization.DomainProof{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	proof, err := scanDomainProof(r.pool.Raw().QueryRow(bounded, resolveDomainProofSQL, string(tenant), domain))
	if err != nil {
		return organization.DomainProof{}, storageError(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return organization.DomainProof{}, err
	}
	return proof, nil
}

// The existing global partial unique index bounds the requested canonical claim
// to one row before tenant/proof acceptance; history is joined only by its exact
// scope identity. Keep this read on the existing custody/proof truth, not a route
// table, and use the primary's exclusive expiry rather than a caller clock.
const resolveDomainProofSQL = `SELECT ` + proofColumns + `
FROM organization.domain_claims c
JOIN organization.organizations o USING(tenant_id,organization_id)
JOIN LATERAL (
 SELECT current.* FROM organization.domain_evidence current
 WHERE current.tenant_id=c.tenant_id AND current.organization_id=c.organization_id
 AND current.claim_id=c.claim_id
 ORDER BY current.proof_version DESC LIMIT 1
) e ON true
WHERE c.tenant_id=$1 AND c.canonical_domain=$2 AND c.state='requested'
AND NOT c.proof_retired AND o.state='active'
AND e.canonical_domain=c.canonical_domain AND e.claim_version=c.version
AND NOT e.revoked AND e.expires_at>clock_timestamp()`
