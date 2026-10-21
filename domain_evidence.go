package organization

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

const (
	// ApplyDomainProof admits one trusted observation for an existing claim.
	ApplyDomainProof Operation = "identity.organization.domain.evidence.apply"
	// RevokeDomainProof terminally retires that exact proof without observing.
	RevokeDomainProof Operation = "identity.organization.domain.evidence.revoke"
)

// DomainMethod names the explicitly supported observer profiles. A method name
// is not verification: only the configured trusted observer may produce evidence.
type DomainMethod string

const (
	DomainDNS   DomainMethod = "dns-txt"
	DomainHTTPS DomainMethod = "https"
)

// DomainProof is an organization-owned immutable authoritative snapshot, not a
// bearer grant. Current use requires GetDomainProof; historical command recovery
// intentionally returns the original snapshot even after expiry or revocation.
// Times are UTC microseconds (PostgreSQL precision); expiry is exclusive.
type DomainProof struct {
	TenantID                   identity.TenantID
	OrganizationID, ClaimID    ID
	Domain                     string
	ClaimVersion, ProofVersion uint64
	Method                     DomainMethod
	ObservedAt, ExpiresAt      time.Time
	Revoked                    bool
}

// DomainProofKey binds every authority dimension of an exact proof. Zero is
// invalid. Construct it by converting an authority-issued DomainProof; changing
// any field never selects a different authority or renews its freshness.
type DomainProofKey DomainProof

// DomainProofReader consults primary current authority, never a cached allow.
type DomainProofReader interface {
	GetDomainProof(context.Context, DomainProofKey) (DomainProof, error)
}

// DomainEvidenceTransition is invocation-scoped authenticated transition custody.
// Apply attempts an already observed exact command; Recover never observes or
// reexecutes it. Unknown and not-committed outcomes carry no proof.
type DomainEvidenceTransition interface {
	ApplyDomainEvidence(context.Context, DomainEvidenceCommand) (DomainEvidenceResult, error)
	RecoverDomainEvidence(context.Context, identity.CommandID) (DomainEvidenceResult, error)
}

// DomainEvidenceResult retains the sole identity command outcome. Proof is set
// only for committed outcomes and is the identical original historical proof.
type DomainEvidenceResult struct {
	StoreResult
	Proof DomainProof
}

// DomainObservation is a trusted observer's bounded outcome for the exact claim.
// The observer, not a request field or method label, must verify the external
// challenge. Raw challenge material must not be returned, logged or persisted.
type DomainObservation struct {
	Claim                 DomainClaim
	Method                DomainMethod
	ObservedAt, ExpiresAt time.Time
	Verified              bool
}

// DomainEvidenceObserver is a deployment-selected external observation seam,
// called once outside all durable locks. It is not a competing proof authority.
// DNS/HTTPS adapters must enforce their own bounded challenge verification.
// Implementations must honor cancellation and support concurrent invocations.
type DomainEvidenceObserver interface {
	ObserveDomain(context.Context, DomainClaim) (DomainObservation, error)
}

// DomainEvidenceRequest selects an existing requested claim and exact current
// proof version. This finite profile issues once (zero -> one), then optionally
// terminally revokes (one -> two); renewal/takeover requires a new claim identity.
type DomainEvidenceRequest struct {
	Claim        DomainClaimRequest
	ProofVersion uint64
}

// DomainEvidenceCommand is immutable organization-issued observation custody.
// Zero is invalid. Persist its safe Recovery binding before Apply; never repeat
// an external observation to recover an ambiguous outcome.
type DomainEvidenceCommand struct{ command Command }

// Command exposes the trusted storage-neutral projection for native composition,
// never another observation or a caller-constructible mutation grant.
func (c DomainEvidenceCommand) Command() Command { return c.command }
func (DomainEvidenceCommand) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.DomainEvidenceCommand(redacted)"))
}
func (DomainEvidenceCommand) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DomainEvidenceCommand) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func evidenceMutation(op Operation) bool { return op == ApplyDomainProof || op == RevokeDomainProof }

// PrepareDomainEvidence performs one explicitly trusted observation after current
// claim/session/policy admission. Execute must fence the original expiry again
// after lock waits. An observer failure leaves no durable command or authority.
func (s *Service) PrepareDomainEvidence(ctx context.Context, r DomainEvidenceRequest, observer DomainEvidenceObserver) (out DomainEvidenceCommand, err error) {
	defer func() {
		if recover() != nil {
			out, err = DomainEvidenceCommand{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || observer == nil || r.ProofVersion != 0 || s.config.Domains.EvidenceMaximumAge == 0 {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	c, err := s.prepareDomain(bounded, r.Claim, ApplyDomainProof)
	if err != nil {
		return out, err
	}
	x := c.state.input
	observation, err := observer.ObserveDomain(bounded, x.DomainClaim)
	if err != nil {
		return out, publicError(bounded, err)
	}
	now := s.config.Clock.Now()
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if !observation.Verified || observation.Claim != x.DomainClaim || observation.Method != DomainDNS && observation.Method != DomainHTTPS || observation.ObservedAt.IsZero() || observation.ObservedAt.After(now) || !observation.ExpiresAt.After(now) || !observation.ExpiresAt.After(observation.ObservedAt) || observation.ExpiresAt.Sub(observation.ObservedAt) > s.config.Domains.EvidenceMaximumAge || x.Session.ValidateAt(now) != nil {
		return out, ErrForbidden
	}
	p := DomainProof{TenantID: x.Binding.TenantID, OrganizationID: x.Organization.ID, ClaimID: x.DomainClaim.ID, Domain: x.DomainClaim.Domain, ClaimVersion: x.DomainClaim.Version, ProofVersion: 1, Method: observation.Method, ObservedAt: observation.ObservedAt.UTC().Truncate(time.Microsecond), ExpiresAt: observation.ExpiresAt.UTC().Truncate(time.Microsecond)}
	if !p.ExpiresAt.After(now) {
		return out, ErrForbidden
	}
	c.state.input.DomainProof = p
	return DomainEvidenceCommand{command: c}, nil
}

// PrepareRevokeDomainEvidence freezes terminal revocation of the exact primary
// proof. It performs no external observation and cannot refresh original times.
func (s *Service) PrepareRevokeDomainEvidence(ctx context.Context, r DomainEvidenceRequest, key DomainProofKey) (out DomainEvidenceCommand, err error) {
	defer func() {
		if recover() != nil {
			out, err = DomainEvidenceCommand{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || r.ProofVersion != 1 || s.config.Domains.EvidenceMaximumAge == 0 {
		return DomainEvidenceCommand{}, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	c, err := s.prepareDomain(bounded, r.Claim, RevokeDomainProof)
	if err != nil {
		return DomainEvidenceCommand{}, err
	}
	reader, ok := s.repository.(DomainProofReader)
	if !ok {
		return DomainEvidenceCommand{}, ErrUnavailable
	}
	p, err := reader.GetDomainProof(bounded, key)
	if err != nil {
		return DomainEvidenceCommand{}, publicError(bounded, err)
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	x := c.state.input
	if p != DomainProof(key) || p.TenantID != x.Binding.TenantID || p.OrganizationID != x.Organization.ID || p.ClaimID != x.DomainClaim.ID || p.Domain != x.DomainClaim.Domain || p.ClaimVersion != x.DomainClaim.Version || p.ProofVersion != r.ProofVersion || p.Revoked || x.Session.ValidateAt(s.config.Clock.Now()) != nil {
		return DomainEvidenceCommand{}, ErrForbidden
	}
	p.ProofVersion++
	p.Revoked = true
	c.state.input.DomainProof = p
	return DomainEvidenceCommand{command: c}, nil
}
