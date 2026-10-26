package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// Archive admits an original key through the selected native owner/action-proof
// profile. Its exact native preparation retains signed proof custody, original
// observations and rate facts; execution atomically archives the organization,
// cancels pending invitations and consumes the original proof. Matching retries
// disclose only original metadata under current session and owner authority.
func (s *OperationService) Archive(ctx context.Context, r organization.LifecycleOperationRequest, network string) (organization.StoreResult, error) {
	return s.lifecycle(ctx, r, network, organization.Archive)
}

// Restore requires a fresh native restore-bound password proof and an archived
// organization at the exact version. It restores surviving rights without
// reviving cancelled invitations or other terminal child authority. Matching
// keys recover the original outcome without renewing or consuming authority.
func (s *OperationService) Restore(ctx context.Context, r organization.LifecycleOperationRequest, network string) (organization.StoreResult, error) {
	return s.lifecycle(ctx, r, network, organization.Restore)
}

func (s *OperationService) lifecycle(ctx context.Context, r organization.LifecycleOperationRequest, network string, op organization.Operation) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	state := s.state()
	return state.keyedPrepared(ctx, r.Authentication, op, r.IdempotencyKey, lifecycleOperationFields(r, state.source.config.Core.Lifecycle), network, func(ctx context.Context, service *Service, id identity.CommandID) (PreparedCommand, error) {
		request := organization.LifecycleRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, Reason: r.Reason, CorrelationID: r.CorrelationID, Proof: r.Proof}
		if op == organization.Archive {
			return service.PrepareArchive(ctx, request, network)
		}
		return service.PrepareRestore(ctx, request, network)
	})
}

// The complete public proof projection belongs to the request intent, not the
// retained ciphertext. The password owner alone authenticates provenance and
// one-time consumption. UTC text preserves exact instants, including subsecond
// changes, without making a retry's correlation ID part of mutation identity.
func lifecycleOperationFields(r organization.LifecycleOperationRequest, policy organization.LifecycleConfig) []identity.FeatureField {
	p := r.Proof.Proof
	return []identity.FeatureField{
		text("id", string(r.OrganizationID)), number("version", r.OrganizationVersion), text("reason", r.Reason),
		number("lifecycle-policy-version", policy.Version), text("lifecycle-proof-audience", policy.ProofAudience),
		text("proof-id", string(p.ID)), text("proof-tenant", p.Tenant), text("proof-subject", p.Subject),
		text("proof-method", p.Method), number("proof-assurance", uint64(p.Assurance)), text("proof-purpose", string(p.Purpose)),
		text("proof-audience", p.Audience), text("proof-issued", p.IssuedAt.UTC().Format(time.RFC3339Nano)), text("proof-expiry", p.ExpiresAt.UTC().Format(time.RFC3339Nano)),
		text("proof-session", r.Proof.SessionID), number("proof-session-version", r.Proof.SessionVersion), text("proof-action", r.Proof.Action),
	}
}
