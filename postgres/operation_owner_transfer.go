package postgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

// OwnerTransfer admits one original key through the existing native transfer
// and password action-proof owners. The authenticated current owner transfers
// to an existing active member at the exact organization and both membership
// versions; the former owner becomes a member. Signed original proof custody,
// current session/factor fences and atomic role/authority/audit/outbox effects
// remain owned by PrepareOwnerTransfer and Execute. Matching retries recover
// only the original outcome under current disclosure policy, including the
// original former owner while still a current member. They never prepare or
// execute again, replace the proof or renew original authority. Network must
// be the transport's trusted canonical full client address.
func (s *OperationService) OwnerTransfer(ctx context.Context, r organization.OwnerTransferOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	state := s.state()
	return state.keyedPrepared(ctx, r.Authentication, organization.OwnerTransfer, r.IdempotencyKey, ownerTransferOperationFields(r, state.source.config.Core.OwnerTransferAudience), network, func(ctx context.Context, service *Service, id identity.CommandID) (PreparedCommand, error) {
		return service.PrepareOwnerTransfer(ctx, organization.OwnerTransferRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, TargetUserID: r.TargetUserID, OrganizationVersion: r.OrganizationVersion, SourceVersion: r.SourceVersion, TargetVersion: r.TargetVersion, CorrelationID: r.CorrelationID, Proof: r.Proof}, network)
	})
}

// The visible proof projection is complete request intent, never provenance or
// a substitute for the native password owner's signed one-use custody. UTC text
// preserves exact instants; retry diagnostics are not new mutation identity.
func ownerTransferOperationFields(r organization.OwnerTransferOperationRequest, audience string) []identity.FeatureField {
	p := r.Proof.Proof
	return []identity.FeatureField{
		text("id", string(r.OrganizationID)), text("target", string(r.TargetUserID)), number("version", r.OrganizationVersion), number("source-version", r.SourceVersion), number("target-version", r.TargetVersion),
		text("owner-transfer-proof-audience", audience),
		text("proof-id", string(p.ID)), text("proof-tenant", p.Tenant), text("proof-subject", p.Subject),
		text("proof-method", p.Method), number("proof-assurance", uint64(p.Assurance)), text("proof-purpose", string(p.Purpose)),
		text("proof-audience", p.Audience), text("proof-issued", p.IssuedAt.UTC().Format(time.RFC3339Nano)), text("proof-expiry", p.ExpiresAt.UTC().Format(time.RFC3339Nano)),
		text("proof-session", r.Proof.SessionID), number("proof-session-version", r.Proof.SessionVersion), text("proof-action", r.Proof.Action),
	}
}
