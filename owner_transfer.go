package organization

import (
	"context"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// OwnerTransfer atomically exchanges the authenticated owner's role with an
// existing nonowner member. It never creates membership or adds another owner.
const OwnerTransfer Operation = "identity.organization.owner-transfer"

// OwnerTransferRequest binds the organization policy epoch and both membership
// versions. The source is always the authenticated session subject, never an
// actor supplied by the caller. TargetUserID must identify a different active
// member or administrator in the same organization. The former owner becomes
// RoleMember; both membership and scoped authorization versions advance.
// Preserve CommandID and the prepared command for retries or exact recovery.
type OwnerTransferRequest struct {
	Authentication                                    Authentication
	CommandID                                         identity.CommandID
	OrganizationID                                    ID
	TargetUserID                                      identity.UserID
	OrganizationVersion, SourceVersion, TargetVersion uint64
	CorrelationID                                     string
	// Proof is the original password owner's operation-bound reauthentication
	// projection, not authenticated merely by these visible fields. The native
	// primary owner must authenticate and consume its exact original record.
	Proof authentication.ReauthenticationProof
}

// PrepareOwnerTransfer requires a fresh, current session and current owner
// membership. Preparation writes nothing. The adapter must protect both exact
// memberships, target identity and session through its sole commit boundary.
func (s *Service) PrepareOwnerTransfer(ctx context.Context, r OwnerTransferRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	validVersion := func(v uint64) bool { return v != 0 && v != ^uint64(0) }
	if s == nil || ctx == nil || !safeID(string(r.OrganizationID)) || !safeID(string(r.TargetUserID)) || !safeID(r.CorrelationID) || !validVersion(r.OrganizationVersion) || !validVersion(r.SourceVersion) || !validVersion(r.TargetVersion) {
		return out, ErrInvalidInput
	}
	if _, err = identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	if s.config.OwnerTransferAudience == "" {
		return out, ErrForbidden
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, err := s.authenticate(bounded, r.Authentication)
	if err != nil {
		return out, err
	}
	if actor == r.TargetUserID || !s.validOwnerTransferProof(observed, r.Proof, s.config.Clock.Now()) {
		return out, ErrForbidden
	}
	v, err := s.repository.Read(bounded, Query{Operation: OwnerTransfer, TenantID: r.Authentication.TenantID, ActorID: actor, OrganizationID: r.OrganizationID, TargetID: r.TargetUserID})
	if err != nil {
		return out, publicError(bounded, err)
	}
	if !validView(v, r.Authentication.TenantID, r.OrganizationID, actor) || v.Actor.Role != RoleOwner || !v.Target.Active || !v.Target.Role.Valid() || v.Target.Role == RoleOwner || v.Target.UserID != r.TargetUserID || v.Target.OrganizationID != r.OrganizationID || v.Target.TenantID != r.Authentication.TenantID || v.Target.AuthorizationVersion == 0 || v.TargetUser.Validate(r.Authentication.TenantID) != nil || v.TargetUser.ID != r.TargetUserID || v.TargetUser.Status != identity.StatusActive {
		return out, ErrForbidden
	}
	if err = s.authorize(bounded, actor, r.Authentication.TenantID, r.OrganizationID, v.Organization.Version, OwnerTransfer, r.CorrelationID); err != nil {
		return out, err
	}
	if err = bounded.Err(); err != nil {
		return out, err
	}
	if !s.validOwnerTransferProof(observed, r.Proof, s.config.Clock.Now()) {
		return out, ErrForbidden
	}
	if v.Organization.Version != r.OrganizationVersion || v.Actor.Version != r.SourceVersion || v.Target.Version != r.TargetVersion {
		return out, ErrConflict
	}
	command := s.command(r.CommandID, OwnerTransfer, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, v.Target, v.TargetUser, RoleMember)
	command.state.input.OwnerTransferProof = r.Proof
	return command, nil
}

// REFERENCE_CONFIGURATION's freshness operation matrix assigns ownership
// transfer a 15-minute primary-proof ceiling, independent of normal session
// freshness. Structural validation here is not the native owner's signature
// verification, current credential fencing or transactional one-use consumption.
func (s *Service) validOwnerTransferProof(observed session.GetResult, proof authentication.ReauthenticationProof, now time.Time) bool {
	if observed.ValidateAt(now) != nil {
		return false
	}
	life, err := observed.Session.Lifetime(now)
	if err != nil || !life.Fresh || s.config.OwnerTransferAudience == "" {
		return false
	}
	spec, err := observed.Session.Bindings()
	return err == nil && proof.Proof.Method == "password" && proof.Proof.Assurance == authentication.AssuranceSingleFactor && proof.Validate(authentication.ReauthenticationUse{ProofUse: authentication.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "identity.password.verify", Audience: s.config.OwnerTransferAudience, Now: now}, SessionID: spec.SessionID, SessionVersion: spec.Version, Action: string(OwnerTransfer), MaximumAge: 15 * time.Minute}) == nil
}

func validOwnerTransferAudience(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}
