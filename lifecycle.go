package organization

import (
	"context"
	"fmt"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const (
	Archive Operation = "identity.organization.archive"
	Restore Operation = "identity.organization.restore"
)

// LifecycleConfig selects native archive/restore, not hard deletion or external
// integration cascades. Zero disables it. Version1 requires the same explicit
// signed-proof audience in both operation-specific password primary sources.
type LifecycleConfig struct {
	Version       uint64
	ProofAudience string
}

// Validate accepts the disabled zero policy or the explicit version1 audience.
func (c LifecycleConfig) Validate() error {
	if c == (LifecycleConfig{}) {
		return nil
	}
	if c.Version != 1 || !validOwnerTransferAudience(c.ProofAudience) {
		return ErrInvalidInput
	}
	return nil
}

// LifecycleState is current primary state, never authority inferred from a
// retained receipt. Deleted organizations are not discoverable in this profile.
type LifecycleState string

const (
	LifecycleActive   LifecycleState = "active"
	LifecycleArchived LifecycleState = "archived"
)

// LifecycleRequest changes one exact organization policy version. Reason is a
// bounded visible-ASCII code, not free text. Proof must be freshly issued for
// this exact action, current owner and session by the actual password owner.
// Copies of visible proof fields do not authenticate their signed provenance.
type LifecycleRequest struct {
	Authentication        Authentication
	CommandID             identity.CommandID
	OrganizationID        ID
	OrganizationVersion   uint64
	Reason, CorrelationID string
	Proof                 authentication.ReauthenticationProof
}

func (LifecycleRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.LifecycleRequest(redacted)"))
}
func (LifecycleRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (LifecycleRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

func lifecycleMutation(op Operation) bool { return op == Archive || op == Restore }

// GetLifecycle exposes active/archived metadata only to a current owner with a
// genuine session and current organization.get policy. Ordinary reads continue
// denying archived organizations. Use this exact version to prepare restoration.
func (s *Service) GetLifecycle(ctx context.Context, r ReadRequest) (out View, err error) {
	defer func() {
		if recover() != nil {
			out, err = View{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil {
		return out, ErrInvalidInput
	}
	if s.config.Lifecycle.Version != 1 {
		return out, ErrForbidden
	}
	if !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || r.Limit != 0 || r.Cursor != "" {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil {
		return out, ErrInvalidInput
	}
	_, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	q := Query{Operation: Get, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, ActorID: actor, Lifecycle: true}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validLifecycleOwner(v, q) {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, Get, r.CorrelationID); e != nil {
		return out, e
	}
	observed, currentActor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	fresh, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if currentActor != actor || !validLifecycleOwner(fresh, q) || fresh.Organization != v.Organization || fresh.Actor != v.Actor || fresh.LifecycleState != v.LifecycleState || observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	return fresh, nil
}

// PrepareArchive freezes owner admission without changing authority. Execute
// atomically denies the organization and terminally cancels pending invitations.
func (s *Service) PrepareArchive(ctx context.Context, r LifecycleRequest) (Command, error) {
	return s.prepareLifecycle(ctx, r, Archive)
}

// PrepareRestore enables only surviving native child state. It never recreates
// removed members, deleted teams/roles, withdrawn claims or canceled invitations.
func (s *Service) PrepareRestore(ctx context.Context, r LifecycleRequest) (Command, error) {
	return s.prepareLifecycle(ctx, r, Restore)
}

func (s *Service) prepareLifecycle(ctx context.Context, r LifecycleRequest, op Operation) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil {
		return out, ErrInvalidInput
	}
	if s.config.Lifecycle.Version != 1 {
		return out, ErrForbidden
	}
	if !safeID(string(r.OrganizationID)) || !safeID(r.CorrelationID) || !validLifecycleReason(r.Reason) || r.OrganizationVersion == 0 || r.OrganizationVersion == ^uint64(0) {
		return out, ErrInvalidInput
	}
	if _, e := identity.ParseCommandID(string(r.CommandID)); e != nil {
		return out, ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	if s.config.ValidateCanonicalID(bounded, r.OrganizationID) != nil {
		return out, ErrInvalidInput
	}
	observed, actor, e := s.authenticate(bounded, r.Authentication)
	if e != nil {
		return out, e
	}
	if !s.validLifecycleProof(observed, r.Proof, op, s.config.Clock.Now()) {
		return out, ErrForbidden
	}
	q := Query{Operation: op, TenantID: r.Authentication.TenantID, OrganizationID: r.OrganizationID, ActorID: actor, Lifecycle: true}
	v, e := s.repository.Read(bounded, q)
	if e != nil {
		return out, publicError(bounded, e)
	}
	if !validLifecycleOwner(v, q) {
		return out, ErrForbidden
	}
	if e = s.authorize(bounded, actor, q.TenantID, q.OrganizationID, v.Organization.Version, op, r.CorrelationID); e != nil {
		return out, e
	}
	if e = bounded.Err(); e != nil {
		return out, e
	}
	if !s.validLifecycleProof(observed, r.Proof, op, s.config.Clock.Now()) {
		return out, ErrForbidden
	}
	if v.Organization.Version != r.OrganizationVersion {
		return out, ErrConflict
	}
	if op == Archive && v.LifecycleState != LifecycleActive || op == Restore && v.LifecycleState != LifecycleArchived {
		return out, ErrConflict
	}
	out = s.command(r.CommandID, op, r.CorrelationID, observed, r.Authentication.Bearer, v.Organization, v.Actor, Member{}, identity.User{ID: actor, TenantID: q.TenantID}, "")
	out.state.input.Binding.SchemaID = op.Descriptor().SchemaID
	out.state.input.Lifecycle = s.config.Lifecycle
	out.state.input.LifecycleState = v.LifecycleState
	out.state.input.LifecycleReason = r.Reason
	out.state.input.LifecycleProof = r.Proof
	return out, nil
}

func validLifecycleOwner(v View, q Query) bool {
	o, a := v.Organization, v.Actor
	return o.ID == q.OrganizationID && o.TenantID == q.TenantID && o.Version > 0 && validSlug(o.Slug) && boundedText(o.Name, 256) && (v.LifecycleReason == "" || validLifecycleReason(v.LifecycleReason)) && v.OwnerCount > 0 && a.UserID == q.ActorID && a.OrganizationID == o.ID && a.TenantID == o.TenantID && a.Role == RoleOwner && a.Active && a.Version > 0 && a.AuthorizationVersion > 0 && (v.LifecycleState == LifecycleActive && o.Active || v.LifecycleState == LifecycleArchived && !o.Active)
}

func validLifecycleReason(reason string) bool {
	if len(reason) < 1 || len(reason) > 64 {
		return false
	}
	for _, b := range []byte(reason) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func (s *Service) validLifecycleProof(observed session.GetResult, proof authentication.ReauthenticationProof, op Operation, now time.Time) bool {
	if observed.ValidateAt(now) != nil || !lifecycleMutation(op) {
		return false
	}
	life, e := observed.Session.Lifetime(now)
	if e != nil || !life.Fresh {
		return false
	}
	b, e := observed.Session.Bindings()
	// REFERENCE_CONFIGURATION session.fresh_for assigns sensitive operations a
	// 15-minute ceiling. Native password custody still verifies/consumes the
	// signed record and current credential in the one protected Work.
	return e == nil && proof.Proof.Method == "password" && proof.Proof.Assurance == authentication.AssuranceSingleFactor && proof.Validate(authentication.ReauthenticationUse{ProofUse: authentication.ProofUse{Tenant: string(b.TenantID), Subject: string(b.UserID), Purpose: "identity.password.verify", Audience: s.config.Lifecycle.ProofAudience, Now: now}, SessionID: b.SessionID, SessionVersion: b.Version, Action: string(op), MaximumAge: 15 * time.Minute}) == nil
}
