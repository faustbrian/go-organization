package organization

import (
	"fmt"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// LifecycleOperationRequest is the transport-neutral original-key archive or
// restore request. OrganizationVersion and the required visible-ASCII Reason
// retain LifecycleRequest's exact semantics. The native owner allocates the
// command ID and authenticates the original action-bound proof; this projection
// never confers authority. Matching retries recover only that original command,
// without preparing again, consuming another proof or renewing any observation.
// Changed organization, version, reason, complete proof or configuration must
// conflict. Authentication and the initiating key are borrowed opaque custody.
type LifecycleOperationRequest struct {
	Authentication        Authentication
	IdempotencyKey        identity.IdempotencyKey
	OrganizationID        ID
	OrganizationVersion   uint64
	Reason, CorrelationID string
	Proof                 authentication.ReauthenticationProof
}

// Validate checks bounded syntax without IO, trusted clock observations,
// authentication, proof provenance, key admission or command allocation. An
// expired original projection remains syntactically valid for historical
// matching-key recovery; fresh execution still requires the native signed proof,
// current session/owner, exact action and original exclusive deadline.
func (r LifecycleOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(string(r.OrganizationID)) || !validOperationVersions(r.OrganizationVersion, 0) || !validLifecycleReason(r.Reason) {
		return ErrInvalidInput
	}
	p := r.Proof
	if _, err := authentication.NewProof(authentication.ProofSpec(p.Proof)); err != nil || p.Proof.Tenant != string(r.Authentication.TenantID) || p.Proof.Method != "password" || p.Proof.Assurance != authentication.AssuranceSingleFactor || p.Proof.Purpose != "identity.password.verify" || p.SessionVersion == 0 || len(p.SessionID) == 0 || len(p.SessionID) > 128 || !lifecycleMutation(Operation(p.Action)) {
		return ErrInvalidInput
	}
	// ReauthenticationProof's public contract requires 1..128 visible ASCII
	// session bytes. Validate its syntax without supplying request-controlled
	// issuance time to Proof.Validate's trusted-clock authority contract.
	for _, b := range []byte(p.SessionID) {
		if b < 33 || b > 126 {
			return ErrInvalidInput
		}
	}
	return nil
}

// Format redacts proof, credentials, key and request metadata from diagnostics.
func (LifecycleOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.LifecycleOperationRequest(redacted)"))
}

// MarshalJSON rejects accidental transport or persistence of direct custody.
func (LifecycleOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text and map-key export of direct custody.
func (LifecycleOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
