package postgres

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
)

// DomainEvidenceService binds private current human authentication to the exact
// argument-free recovery contract. Each call reauthenticates and rechecks current
// primary membership/policy; neither command IDs nor proof values confer access.
// Borrowed Service and observer must outlive calls. It starts no goroutines.
// Do not copy after first use; independent commands use independent facades.
type DomainEvidenceService struct {
	service        *Service
	authentication organization.Authentication
	network        string
	// mu owns preparation custody only, never results or durable authority.
	// No observer, policy or database call runs while held.
	mu        sync.Mutex
	preparing bool
	prepared  PreparedCommand
	recovery  *Recovery
}

var _ organization.DomainEvidenceTransition = (*DomainEvidenceService)(nil)
var _ organization.DomainProofReader = (*DomainEvidenceService)(nil)
var _ organization.DomainProofReader = (*Repository)(nil)

func (*DomainEvidenceService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.DomainEvidenceService(redacted)"))
}
func (*DomainEvidenceService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (*DomainEvidenceService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// DomainEvidence selects this finite native profile. Observation is configured
// on ContributorConfig.DomainEvidence, never supplied by an untrusted request.
// Optional original Recovery scope enables exact not-committed/unknown recovery
// after process loss. It grants nothing without current original-actor authority.
func (s *Service) DomainEvidence(a organization.Authentication, network string, recovery ...Recovery) (*DomainEvidenceService, error) {
	if s == nil || s.participant == nil || s.core == nil || s.participant.config.DomainEvidence == nil || s.config.Core.Domains.EvidenceMaximumAge == 0 || !scope(string(a.TenantID)) || len(recovery) > 1 {
		return nil, organization.ErrInvalidInput
	}
	bound := &DomainEvidenceService{service: s, authentication: a, network: network}
	if len(recovery) == 1 {
		b := recovery[0].Binding
		if b.TenantID != a.TenantID || !isEvidenceMutation(organization.Operation(b.OperationID)) || b.ValidateFor(organization.Operation(b.OperationID).Descriptor()) != nil {
			return nil, organization.ErrInvalidInput
		}
		copy := recovery[0]
		bound.recovery = &copy
	}
	return bound, nil
}

// Prepare freezes one external observation without opening a transaction. Save
// Command().Input().Binding as safe recovery scope; preserve CommandID on retry.
func (s *DomainEvidenceService) Prepare(ctx context.Context, r organization.DomainEvidenceRequest) (organization.DomainEvidenceCommand, error) {
	if s == nil || s.service == nil || ctx == nil {
		return organization.DomainEvidenceCommand{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.service.config.Core.MaximumDuration)
	defer cancel()
	r.Claim.Authentication = s.authentication
	return s.prepare(bounded, func() (organization.DomainEvidenceCommand, error) {
		return s.service.core.PrepareDomainEvidence(bounded, r, s.service.participant.config.DomainEvidence.observer)
	})
}

// PrepareRevocation freezes the exact original proof for terminal revocation.
func (s *DomainEvidenceService) PrepareRevocation(ctx context.Context, r organization.DomainEvidenceRequest, key organization.DomainProofKey) (organization.DomainEvidenceCommand, error) {
	if s == nil || s.service == nil || ctx == nil {
		return organization.DomainEvidenceCommand{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.service.config.Core.MaximumDuration)
	defer cancel()
	r.Claim.Authentication = s.authentication
	return s.prepare(bounded, func() (organization.DomainEvidenceCommand, error) {
		return s.service.core.PrepareRevokeDomainEvidence(bounded, r, key)
	})
}

func (s *DomainEvidenceService) prepare(ctx context.Context, build func() (organization.DomainEvidenceCommand, error)) (out organization.DomainEvidenceCommand, err error) {
	if ctx == nil {
		return out, organization.ErrInvalidInput
	}
	s.mu.Lock()
	if s.preparing || s.prepared.state != nil || s.recovery != nil {
		s.mu.Unlock()
		return out, organization.ErrConflict
	}
	s.preparing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.preparing = false; s.mu.Unlock() }()
	out, err = build()
	if err != nil {
		return out, err
	}
	native, err := s.service.participant.mapCommand(out.Command())
	if err != nil {
		return organization.DomainEvidenceCommand{}, err
	}
	prepared, err := s.service.prepareMapped(ctx, out.Command(), native, s.network)
	if err != nil {
		return organization.DomainEvidenceCommand{}, err
	}
	s.mu.Lock()
	s.prepared = prepared
	s.mu.Unlock()
	return out, nil
}

// ApplyDomainEvidence attempts only this facade's immutable prepared command.
// Replay retains its original counter plan and never calls the observer again.
func (s *DomainEvidenceService) ApplyDomainEvidence(ctx context.Context, c organization.DomainEvidenceCommand) (organization.DomainEvidenceResult, error) {
	if s == nil || s.service == nil || ctx == nil {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.service.config.Core.MaximumDuration)
	defer cancel()
	x, err := c.Command().Input()
	if err != nil || !isEvidenceMutation(x.Operation) || x.Binding.TenantID != s.authentication.TenantID {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	// The command's original bearer remains bound to its original session. The
	// facade's current credential independently authorizes this invocation.
	current, err := s.service.core.GetDomainClaim(bounded, organization.DomainClaimReadRequest{Authentication: s.authentication, OrganizationID: x.Organization.ID, ClaimID: x.DomainClaim.ID, CorrelationID: x.Binding.CorrelationID})
	if err != nil {
		return organization.DomainEvidenceResult{}, err
	}
	if current.Actor.UserID != identity.UserID(x.Binding.ActorID) {
		return organization.DomainEvidenceResult{}, organization.ErrForbidden
	}
	s.mu.Lock()
	prepared := s.prepared
	s.mu.Unlock()
	if prepared.state == nil || prepared.state.core != c.Command() {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	result, err := s.service.Execute(bounded, prepared)
	return s.result(bounded, result, err)
}

// RecoverDomainEvidence reauthenticates the current original actor and queries
// the sole coordinator; historical proof is returned only when committed.
func (s *DomainEvidenceService) RecoverDomainEvidence(ctx context.Context, id identity.CommandID) (organization.DomainEvidenceResult, error) {
	if s == nil || s.service == nil || ctx == nil {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(id)); err != nil {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.service.config.Core.MaximumDuration)
	defer cancel()
	// As with the existing invocation-scoped UnitOfWork, recovery requires the
	// exact original safe binding. A bare command ID never permits global lookup
	// or reconstructing authority from retained domain rows.
	var binding identity.CommandBinding
	s.mu.Lock()
	if s.recovery != nil {
		binding = s.recovery.Binding
	} else if s.prepared.state != nil {
		binding = s.prepared.state.binding
	}
	s.mu.Unlock()
	if binding.CommandID == "" || binding.CommandID != id {
		return organization.DomainEvidenceResult{}, organization.ErrInvalidInput
	}
	result, err := s.service.Recover(bounded, s.authentication, Recovery{Binding: binding})
	return s.result(bounded, result, err)
}

func (s *DomainEvidenceService) result(ctx context.Context, result organization.StoreResult, err error) (organization.DomainEvidenceResult, error) {
	out := organization.DomainEvidenceResult{StoreResult: result}
	if result.Receipt.Outcome == identity.CommitOutcomeInProgress {
		// The coordinator owns the pending attempt; it has proved neither
		// commit nor rollback. Domain consumers must reconcile, not observe again.
		out.Receipt = unknown(result.Receipt.Binding)
		return out, identity.UnknownCommitError{CommandID: result.Receipt.Binding.CommandID}
	}
	if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	p, readErr := s.service.participant.repository.proofForCommand(ctx, result.Receipt.Binding.CommandID)
	if readErr != nil {
		out.Receipt = unknown(result.Receipt.Binding)
		return out, readErr
	}
	out.Proof = p
	return out, nil
}

// GetDomainProof requires exact current primary proof and current management,
// membership, organization and authenticated-session authority before release.
func (s *DomainEvidenceService) GetDomainProof(ctx context.Context, key organization.DomainProofKey) (organization.DomainProof, error) {
	if s == nil || s.service == nil || ctx == nil || key.TenantID != s.authentication.TenantID {
		return organization.DomainProof{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.service.config.Core.MaximumDuration)
	defer cancel()
	q := organization.DomainClaimReadRequest{Authentication: s.authentication, OrganizationID: key.OrganizationID, ClaimID: key.ClaimID, CorrelationID: "domain-proof-read"}
	initial, err := s.service.core.GetDomainClaim(bounded, q)
	if err != nil {
		return organization.DomainProof{}, err
	}
	p, err := s.service.participant.repository.GetDomainProof(bounded, key)
	if err != nil {
		return organization.DomainProof{}, err
	}
	final, err := s.service.core.GetDomainClaim(bounded, q)
	if err != nil {
		return organization.DomainProof{}, err
	}
	if final.Organization != initial.Organization || final.Actor != initial.Actor || final.DomainClaim != initial.DomainClaim {
		return organization.DomainProof{}, organization.ErrForbidden
	}
	// Recheck current proof after policy callbacks; use primary time in that read.
	again, err := s.service.participant.repository.GetDomainProof(bounded, key)
	if err != nil || again != p {
		if err != nil {
			return organization.DomainProof{}, err
		}
		return organization.DomainProof{}, organization.ErrForbidden
	}
	return p, nil
}

const proofColumns = `e.tenant_id,e.organization_id,e.claim_id,e.canonical_domain,e.claim_version::text,e.proof_version::text,e.method,e.observed_at,e.expires_at,e.revoked`

type proofScanner interface{ Scan(...any) error }

func scanDomainProof(row proofScanner) (organization.DomainProof, error) {
	var p organization.DomainProof
	var claim, proof string
	var tenant, org, claimID, method string
	// identity/postgres WorkRows accepts closed primitive destinations, not
	// named string types or caller RowScanner hooks. Convert only after decoding.
	if err := row.Scan(&tenant, &org, &claimID, &p.Domain, &claim, &proof, &method, &p.ObservedAt, &p.ExpiresAt, &p.Revoked); err != nil {
		return p, err
	}
	p.TenantID = identity.TenantID(tenant)
	p.OrganizationID = organization.ID(org)
	p.ClaimID = organization.ID(claimID)
	p.Method = organization.DomainMethod(method)
	var err error
	if p.ClaimVersion, err = positive(claim); err != nil {
		return organization.DomainProof{}, err
	}
	if p.ProofVersion, err = positive(proof); err != nil {
		return organization.DomainProof{}, err
	}
	p.ObservedAt = p.ObservedAt.UTC()
	p.ExpiresAt = p.ExpiresAt.UTC()
	return p, nil
}

// GetDomainProof reads exact current primary domain/org/claim authority. It is
// an internal service-to-service authority port, not human authentication; use
// DomainEvidenceService for the authenticated membership/session facade.
func (r *Repository) GetDomainProof(ctx context.Context, key organization.DomainProofKey) (organization.DomainProof, error) {
	if r == nil || r.pool == nil || r.pool.Raw() == nil || ctx == nil || !validProof(organization.DomainProof(key)) || key.Revoked {
		return organization.DomainProof{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, r.maximum)
	defer cancel()
	p, err := scanDomainProof(r.pool.Raw().QueryRow(bounded, `SELECT `+proofColumns+` FROM organization.domain_evidence e JOIN organization.domain_claims c USING(tenant_id,organization_id,claim_id) JOIN organization.organizations o USING(tenant_id,organization_id) WHERE e.tenant_id=$1 AND e.organization_id=$2 AND e.claim_id=$3 AND e.proof_version=$4::numeric AND c.canonical_domain=e.canonical_domain AND c.version=e.claim_version AND c.state='requested' AND NOT c.proof_retired AND o.state='active' AND NOT e.revoked AND e.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM organization.domain_evidence successor WHERE successor.tenant_id=e.tenant_id AND successor.organization_id=e.organization_id AND successor.claim_id=e.claim_id AND successor.proof_version>e.proof_version)`, string(key.TenantID), string(key.OrganizationID), string(key.ClaimID), strconv.FormatUint(key.ProofVersion, 10)))
	if err != nil {
		return organization.DomainProof{}, storageError(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return organization.DomainProof{}, err
	}
	if p != organization.DomainProof(key) || !time.Now().Before(p.ExpiresAt) {
		return organization.DomainProof{}, organization.ErrForbidden
	}
	return p, nil
}
func (r *Repository) proofForCommand(ctx context.Context, id identity.CommandID) (organization.DomainProof, error) {
	p, err := scanDomainProof(r.pool.Raw().QueryRow(ctx, `SELECT `+proofColumns+` FROM organization.domain_evidence e WHERE command_id=$1`, string(id)))
	if err != nil {
		return organization.DomainProof{}, storageError(ctx, err)
	}
	return p, nil
}

func validProof(p organization.DomainProof) bool {
	domain, err := organization.CanonicalDomain(p.Domain)
	return err == nil && domain == p.Domain && scope(string(p.TenantID)) && scope(string(p.OrganizationID)) && scope(string(p.ClaimID)) && p.ClaimVersion == 1 && (p.ProofVersion == 1 && !p.Revoked || p.ProofVersion == 2 && p.Revoked) && (p.Method == organization.DomainDNS || p.Method == organization.DomainHTTPS) && !p.ObservedAt.IsZero() && p.ExpiresAt.After(p.ObservedAt) && p.ObservedAt == p.ObservedAt.UTC().Truncate(time.Microsecond) && p.ExpiresAt == p.ExpiresAt.UTC().Truncate(time.Microsecond)
}
func (p *Contributor) decodeDomainEvidence(c *nativeCommand, t func(string) string, n func(string) uint64) error {
	proof := organization.DomainProof{TenantID: c.spec.Binding.TenantID, OrganizationID: c.org.ID, ClaimID: c.domainClaim.ID, Domain: c.domainClaim.Domain, ClaimVersion: c.domainClaim.Version, ProofVersion: n("proof-version"), Method: organization.DomainMethod(t("proof-method")), Revoked: c.operation == organization.RevokeDomainProof}
	var err error
	proof.ObservedAt, err = time.Parse(time.RFC3339Nano, t("proof-observed"))
	if err != nil {
		return organization.ErrInvalidInput
	}
	proof.ExpiresAt, err = time.Parse(time.RFC3339Nano, t("proof-expires"))
	if err != nil || !validProof(proof) || p.config.Domains.EvidenceMaximumAge == 0 || proof.ExpiresAt.Sub(proof.ObservedAt) > p.config.Domains.EvidenceMaximumAge || !p.config.DomainEvidence.valid(c.spec.Binding, proof, t("proof-seal")) {
		return organization.ErrInvalidInput
	}
	c.domainProof = proof
	return nil
}

func (p *Contributor) requireEvidenceClaim(ctx context.Context, w kernel.Work, c nativeCommand) error {
	var domain, state, version string
	var retired bool
	rows, err := w.Query(ctx, `SELECT canonical_domain,state,version::text,proof_retired FROM organization.domain_claims WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 FOR UPDATE`, string(c.spec.Binding.TenantID), string(c.org.ID), string(c.domainClaim.ID))
	if err = one(rows, err, &domain, &state, &version, &retired); err != nil {
		return err
	}
	if domain != c.domainProof.Domain || state != "requested" || retired || version != strconv.FormatUint(c.domainProof.ClaimVersion, 10) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *Contributor) mutateDomainEvidence(ctx context.Context, w kernel.Work, c nativeCommand) error {
	if err := p.requireEvidenceClaim(ctx, w, c); err != nil {
		return err
	}
	proof := c.domainProof
	var count int64
	rows, err := w.Query(ctx, `SELECT count(*) FROM organization.domain_evidence WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3`, string(proof.TenantID), string(proof.OrganizationID), string(proof.ClaimID))
	if err = one(rows, err, &count); err != nil {
		return err
	}
	if count != int64(proof.ProofVersion-1) {
		return identity.ConflictError{}
	}
	if proof.Revoked {
		original, err := scanDomainProofWork(ctx, w, proof)
		if err != nil {
			return err
		}
		original.ProofVersion = 2
		original.Revoked = true
		if original != proof {
			return identity.ConflictError{}
		}
	}
	n, err := w.Exec(ctx, `INSERT INTO organization.domain_evidence(tenant_id,organization_id,claim_id,canonical_domain,claim_version,proof_version,method,observed_at,expires_at,revoked,command_id) VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`, string(proof.TenantID), string(proof.OrganizationID), string(proof.ClaimID), proof.Domain, strconv.FormatUint(proof.ClaimVersion, 10), strconv.FormatUint(proof.ProofVersion, 10), string(proof.Method), proof.ObservedAt, proof.ExpiresAt, proof.Revoked, string(c.spec.Binding.CommandID))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	n, err = w.Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric AND state='active'`, string(proof.TenantID), string(proof.OrganizationID), strconv.FormatUint(c.org.Version, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ConflictError{}
	}
	return nil
}
func scanDomainProofWork(ctx context.Context, w kernel.Work, p organization.DomainProof) (organization.DomainProof, error) {
	rows, err := w.Query(ctx, `SELECT `+proofColumns+` FROM organization.domain_evidence e WHERE tenant_id=$1 AND organization_id=$2 AND claim_id=$3 AND proof_version=1`, string(p.TenantID), string(p.OrganizationID), string(p.ClaimID))
	if err != nil {
		return organization.DomainProof{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return organization.DomainProof{}, identity.ForbiddenError{}
	}
	result, err := scanDomainProof(rows)
	if err != nil {
		return organization.DomainProof{}, err
	}
	if rows.Next() {
		return organization.DomainProof{}, identity.UnavailableError{}
	}
	if err = rows.Err(); err != nil {
		return organization.DomainProof{}, err
	}
	return result, nil
}
func (p *Contributor) checkDomainEvidenceCommit(ctx context.Context, w kernel.Work, c nativeCommand) error {
	if err := p.requireEvidenceClaim(ctx, w, c); err != nil {
		return err
	}
	var count int64
	rows, err := w.Query(ctx, `SELECT count(*) FROM organization.domain_evidence WHERE command_id=$1 AND proof_version=$2::numeric`, string(c.spec.Binding.CommandID), strconv.FormatUint(c.domainProof.ProofVersion, 10))
	if err = one(rows, err, &count); err != nil {
		return err
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}
