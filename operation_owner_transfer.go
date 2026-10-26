package organization

import (
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// OwnerTransferOperationRequest is the original-key ownership transfer to an
// existing active member. The authenticated session determines the source;
// OrganizationVersion, SourceVersion and TargetVersion retain the exact
// OwnerTransferRequest semantics. The former owner becomes RoleMember.
// The native owner allocates the command ID and authenticates and atomically
// consumes the original action-bound password proof. Matching retries classify
// only that original command without preparing or executing again, replacing
// the proof or renewing authority. Changed target, versions, complete proof or
// selected configuration conflicts. Authentication and the single required key
// are opaque borrowed custody; this projection never establishes authority.
type OwnerTransferOperationRequest struct {
	Authentication                                    Authentication
	IdempotencyKey                                    identity.IdempotencyKey
	OrganizationID                                    ID
	TargetUserID                                      identity.UserID
	OrganizationVersion, SourceVersion, TargetVersion uint64
	CorrelationID                                     string
	Proof                                             authentication.ReauthenticationProof
}

// Validate checks bounded syntax without IO, a trusted clock, current owner or
// session authentication, proof provenance, key admission or command allocation.
// An expired original proof remains representable for historical classification;
// execution still requires the native owner's signed fresh proof and authority.
func (r OwnerTransferOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || !safeID(string(r.TargetUserID)) || !validOperationVersions(r.OrganizationVersion, r.SourceVersion) || r.SourceVersion == 0 || !validOperationVersions(r.TargetVersion, 0) {
		return ErrInvalidInput
	}
	p := r.Proof
	if _, err := authentication.NewProof(authentication.ProofSpec(p.Proof)); err != nil || p.Proof.Tenant != string(r.Authentication.TenantID) || p.Proof.Method != "password" || p.Proof.Assurance != authentication.AssuranceSingleFactor || p.Proof.Purpose != "identity.password.verify" || p.SessionVersion == 0 || len(p.SessionID) == 0 || len(p.SessionID) > 128 || p.Action != string(OwnerTransfer) {
		return ErrInvalidInput
	}
	// ReauthenticationProof requires 1..128 visible ASCII session bytes. Check
	// syntax without inventing a trusted clock from the supplied issuance time.
	for _, b := range []byte(p.SessionID) {
		if b < 33 || b > 126 {
			return ErrInvalidInput
		}
	}
	return nil
}

// Format redacts credentials, key, proof and request metadata from diagnostics.
func (OwnerTransferOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.OwnerTransferOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport or persistence of direct custody.
func (OwnerTransferOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of direct custody.
func (OwnerTransferOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
