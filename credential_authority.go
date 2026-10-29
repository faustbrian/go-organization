package organization

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CredentialAuthorityQuery selects trusted current storage facts, not a public
// authorization endpoint. An empty ActorID requests organization ownership only;
// a nonempty ActorID requires that actual user's current active membership.
type CredentialAuthorityQuery struct {
	TenantID       identity.TenantID
	OrganizationID ID
	ActorID        identity.UserID
}

// Validate rejects malformed identifiers without canonicalizing them or granting
// permission. Canonical-ID policy remains the composing consumer's responsibility.
func (q CredentialAuthorityQuery) Validate() error {
	if !safeID(string(q.TenantID)) || !safeID(string(q.OrganizationID)) || q.ActorID != "" && !safeID(string(q.ActorID)) {
		return ErrInvalidInput
	}
	return nil
}

// CredentialAuthorityObservation is a trusted, uncached active-owner projection.
// Version is current aggregate/policy authority; CredentialVersion is a separate
// durable revocation epoch. Member/role changes advance the former, not the latter;
// archive/delete advance the latter and restoration must never rewind it.
// Actor is zero for owner-only queries and the exact current member otherwise.
// Times retain the original read's freshness, bounded by twenty seconds from its
// start. Copying/retrying this value cannot renew validity. Neither this value
// nor its structural validation authenticates a key or grants any permission.
type CredentialAuthorityObservation struct {
	TenantID          identity.TenantID
	OrganizationID    ID
	Version           uint64
	CredentialVersion uint64
	Actor             Member
	ReadStartedAt     time.Time
	VerifiedAt        time.Time
	ValidUntil        time.Time
}

// Validate checks exact requested bindings and original bounded freshness at now.
// Consumers must still fence current storage state at their protected operation
// and independently enforce credential authentication and current policy.
func (o CredentialAuthorityObservation) Validate(q CredentialAuthorityQuery, now time.Time) error {
	if err := q.Validate(); err != nil {
		return err
	}
	if o.TenantID != q.TenantID || o.OrganizationID != q.OrganizationID || o.Version == 0 || o.CredentialVersion == 0 || now.IsZero() || o.ReadStartedAt.IsZero() || o.VerifiedAt.IsZero() || o.ReadStartedAt.After(o.VerifiedAt) || o.VerifiedAt.After(now) || !now.Before(o.ValidUntil) || !o.VerifiedAt.Before(o.ValidUntil) || o.ValidUntil.After(o.ReadStartedAt.Add(20*time.Second)) {
		return ErrForbidden
	}
	if q.ActorID == "" {
		if o.Actor != (Member{}) {
			return ErrForbidden
		}
	} else if o.Actor.TenantID != q.TenantID || o.Actor.OrganizationID != q.OrganizationID || o.Actor.UserID != q.ActorID || !o.Actor.Active || !o.Actor.Role.Valid() || o.Actor.Version == 0 || o.Actor.AuthorizationVersion == 0 {
		return ErrForbidden
	}
	return nil
}

// CredentialAuthorityReader exposes storage facts to trusted credential owners.
// Failure returns a zero observation; no creator identity is inferred. Existing
// member-only Repository reads retain their separate authentication workflow.
type CredentialAuthorityReader interface {
	ObserveCredentialAuthority(context.Context, CredentialAuthorityQuery) (CredentialAuthorityObservation, error)
}
