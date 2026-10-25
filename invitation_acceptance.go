package organization

import (
	"context"
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// InvitationAcceptAdmission is non-authoritative original preparation metadata
// for a synchronous transport gate. Binding identifies the caller's original
// command and intended verified recipient; ChallengeID is the authenticated
// issuer's original capability ID, not a proof, fingerprint or submitted value.
// ChallengeLifetime is signed ExpiresAt-IssuedAt, never remaining time or a new
// configuration lifetime. These values neither consume proof nor grant access.
type InvitationAcceptAdmission struct {
	Binding           identity.CommandBinding
	OrganizationID    ID
	ChallengeID       string
	ChallengeLifetime time.Duration
}

// PreparedInvitationAcceptance is one opaque original native acceptance. A
// transport obtains it before handler middleware, admits its original rate
// facts, then executes that same preparation only after all additional gates.
// Admission returns a copy of authenticated original metadata without IO or
// renewed authority; it neither consumes proof nor executes. Execute requires a
// non-nil bounded context and retains the native current authority, original
// session/expiry, one-use and transaction fences. It never prepares again.
// Copies/aliases share serial-use custody and must not execute concurrently.
// Implementations reject implicit serialization and redact diagnostics; the
// handle contains no caller-exportable credential or proof. This is not a
// durable recovery handle: save Admission's full binding/organization instead.
type PreparedInvitationAcceptance interface {
	Admission() (InvitationAcceptAdmission, error)
	Execute(context.Context) (StoreResult, error)
}

// InvitationAcceptAdmitter is an additional synchronous transport admission
// gate, invoked once outside SQL after native acceptance preparation and before
// executing that exact preparation. A nil callback is invalid; errors, panics
// or cancellation deny execution. Implementations must honor ctx, must not start
// detached work, and must support concurrent independent requests. Returning nil
// does not replace native current authority, expiry or one-use final fences.
type InvitationAcceptAdmitter func(context.Context, InvitationAcceptAdmission) error

// InvitationAcceptRecoveryRequest selects only exact original acceptance
// history. Binding and OrganizationID are safe correlation saved from the native
// preparation/result, not authority. Current authentication must independently
// resolve the original actor and intended verified recipient. There is no proof,
// request key, new execution or bare-command-ID lookup in this request.
type InvitationAcceptRecoveryRequest struct {
	Authentication Authentication
	Binding        identity.CommandBinding
	OrganizationID ID
}

// Validate checks bounded once-request custody without IO or cryptographic
// verification. It never transfers or consumes Proof. The proof's 32..4096-byte
// boundary is the invitation.accept request contract; a valid shape is not
// authority. Existing explicit preparation retains its own independent checks.
func (r InvitationAcceptRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || !safeID(string(r.ID)) || !safeID(string(r.OrganizationID)) || r.OrganizationVersion == 0 || r.InvitationVersion == 0 || r.Proof.ValidateBounds(32, 4096) != nil {
		return ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks closed original-acceptance correlation and bounded rate facts,
// not their authenticity or current permission. The lifetime ceiling follows
// InvitationConfig's 30-day maximum; signed original issuance can be shorter.
func (r InvitationAcceptAdmission) Validate() error {
	if !validInvitationAcceptBinding(r.Binding) || !safeID(string(r.OrganizationID)) || !safeID(r.ChallengeID) || r.ChallengeLifetime <= 0 || r.ChallengeLifetime > 30*24*time.Hour {
		return ErrInvalidInput
	}
	return nil
}

// Validate checks exact acceptance/tenant correlation and authentication syntax
// only. Historical disclosure still belongs to the native recovery owner.
func (r InvitationAcceptRecoveryRequest) Validate() error {
	if !validInvitationAcceptBinding(r.Binding) || !safeID(string(r.OrganizationID)) || r.Binding.TenantID != r.Authentication.TenantID || !validOperationAuthentication(r.Authentication, r.Binding.CorrelationID) {
		return ErrInvalidInput
	}
	return nil
}

func validInvitationAcceptBinding(b identity.CommandBinding) bool {
	return b.ValidateFor(InvitationAccept.Descriptor()) == nil && b.ActorKind == authorization.SubjectUser && b.ActorID == identity.ActorID(b.UserID)
}

// Format redacts preparation correlation and challenge metadata.
func (InvitationAcceptAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationAcceptAdmission(redacted)"))
}

// MarshalJSON rejects implicit export; transports own explicit safe wire types.
func (InvitationAcceptAdmission) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export.
func (InvitationAcceptAdmission) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts the borrowed synchronous admission callback.
func (InvitationAcceptAdmitter) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationAcceptAdmitter(redacted)"))
}

// MarshalJSON rejects implicit callback persistence or transport.
func (InvitationAcceptAdmitter) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit callback export.
func (InvitationAcceptAdmitter) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts current credentials and original recovery correlation.
func (InvitationAcceptRecoveryRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.InvitationAcceptRecoveryRequest(redacted)"))
}

// MarshalJSON rejects accidental credential/recovery custody serialization.
func (InvitationAcceptRecoveryRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit credential/recovery custody export.
func (InvitationAcceptRecoveryRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
