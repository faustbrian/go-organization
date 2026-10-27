package organization

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const (
	// ActiveSet changes only the exact authenticated session's selection.
	ActiveSet Operation = "identity.organization.active-set"
	// ActiveGet reads the exact authenticated session's current selection.
	ActiveGet Operation = "identity.organization.active-get"
)

// ActiveOrganizationRequest selects an organization, or explicit absence when
// OrganizationID is empty. SessionID must equal the submitted bearer's stable
// session; its CAS is observed once and frozen, never caller supplied. Preserve
// CommandID after uncertainty and recover rather than prepare another attempt.
type ActiveOrganizationRequest struct {
	Authentication Authentication
	CommandID      identity.CommandID
	SessionID      string
	OrganizationID ID
	CorrelationID  string
}

// ActiveOrganizationOperationRequest is stable keyed intent: exact session and
// requested organization or explicit absence. Observed versions are not intent.
// A matching retained key recovers its original command, never prepares anew.
type ActiveOrganizationOperationRequest struct {
	Authentication Authentication
	IdempotencyKey identity.IdempotencyKey
	SessionID      string
	OrganizationID ID
	CorrelationID  string
}

// ActiveOrganizationReadRequest has no user/session override: the submitted
// bearer selects the exact session, without authority or activity renewal.
type ActiveOrganizationReadRequest struct {
	Authentication Authentication
	CorrelationID  string
}

// ActiveOrganizationView is current non-secret selection, not an access grant.
// Unselected sessions have zero Organization/Member; denials return a zero view.
type ActiveOrganizationView struct {
	SessionID      string
	SessionVersion uint64
	Selected       bool
	Organization   Organization
	Member         Member
}

// NewActiveOrganizationService explicitly enables password/bearer selection.
// The borrowed session owner must fence every original dimension and current
// selected organization/member on each read. NewService and all other operation
// profiles retain their existing admission; no dimensions are stripped.
func NewActiveOrganizationService(sessions *session.SessionService, repository Repository, policy authorization.Service, c Config) (*Service, error) {
	s, err := NewService(sessions, repository, policy, c)
	if err == nil {
		s.activeOrganization = true
	}
	return s, err
}

// OrganizationSessionScope derives the canonical owned key for exact tenant
// and organization IDs. Length framing prevents tuple ambiguity; hashing keeps
// two maximum IDs within session's bounded namespace. It grants no authority.
func OrganizationSessionScope(tenant identity.TenantID, org ID) (string, error) {
	if !safeID(string(tenant)) || !safeID(string(org)) {
		return "", ErrInvalidInput
	}
	digest := sha256.Sum256([]byte("golib.organization.session.v1\x00" + strconv.Itoa(len(tenant)) + ":" + string(tenant) + strconv.Itoa(len(org)) + ":" + string(org)))
	return "organization:" + hex.EncodeToString(digest[:]), nil
}

// Validate checks syntax and custody presence, never current authority.
func (r ActiveOrganizationOperationRequest) Validate() error {
	if !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.IdempotencyKey == (identity.IdempotencyKey{}) || !safeID(r.SessionID) || r.OrganizationID != "" && !safeID(string(r.OrganizationID)) {
		return ErrInvalidInput
	}
	return nil
}

func (s *Service) authenticateActive(ctx context.Context, a Authentication) (session.GetResult, session.SessionSpec, error) {
	if s == nil || !s.activeOrganization {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	if !safeID(string(a.TenantID)) {
		return session.GetResult{}, session.SessionSpec{}, ErrInvalidInput
	}
	token, err := session.ParseToken(a.Bearer.Token())
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	observed, err := s.sessions.Get(ctx, session.GetRequest{TenantID: a.TenantID, Credential: credential})
	if err != nil {
		return session.GetResult{}, session.SessionSpec{}, publicError(ctx, err)
	}
	spec, err := observed.Session.Bindings()
	if err != nil || observed.ValidateAt(s.config.Clock.Now()) != nil || spec.TenantID != a.TenantID || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "password" || spec.Authentication.Proof.Assurance != authentication.AssuranceSingleFactor {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	v, err := spec.Authority.Bindings()
	if err != nil || v.Factor.Present || v.Passkey.Present {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	if _, err := observed.Session.CSRFState().Bindings(); err == nil {
		return session.GetResult{}, session.SessionSpec{}, ErrForbidden
	}
	return observed, spec, nil
}

// PrepareActiveSet freezes target membership/policy and the exact session CAS.
// Native execution must repeat custody and current authority in one Work around
// the session effect. Empty organization means clear, never a default target.
func (s *Service) PrepareActiveSet(ctx context.Context, r ActiveOrganizationRequest) (out Command, err error) {
	defer func() {
		if recover() != nil {
			out, err = Command{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !safeID(r.SessionID) || !validOperationAuthentication(r.Authentication, r.CorrelationID) || r.OrganizationID != "" && !safeID(string(r.OrganizationID)) {
		return out, ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return out, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	start := s.config.Clock.Now()
	observed, spec, err := s.authenticateActive(ctx, r.Authentication)
	if err != nil {
		return out, err
	}
	if spec.SessionID != r.SessionID {
		return out, ErrForbidden
	}
	var view View
	if r.OrganizationID != "" {
		if s.config.ValidateCanonicalID(ctx, r.OrganizationID) != nil {
			return out, ErrInvalidInput
		}
		view, err = s.repository.Read(ctx, Query{Operation: Get, TenantID: r.Authentication.TenantID, ActorID: spec.UserID, OrganizationID: r.OrganizationID})
		if err != nil {
			return out, publicError(ctx, err)
		}
		if !validView(view, r.Authentication.TenantID, r.OrganizationID, spec.UserID) {
			return out, ErrForbidden
		}
	}
	if err = s.authorize(ctx, spec.UserID, r.Authentication.TenantID, r.OrganizationID, view.Organization.Version, ActiveSet, r.CorrelationID); err != nil {
		return out, err
	}
	until := observed.ValidUntil()
	if limit := start.Add(20 * time.Second); limit.Before(until) {
		until = limit
	}
	// PostgreSQL precision may shorten, never round up this original deadline.
	until = until.UTC().Truncate(time.Microsecond)
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil || !s.config.Clock.Now().Before(until) {
		return out, ErrForbidden
	}
	op := ActiveSet.Descriptor()
	b := identity.CommandBinding{CommandID: r.CommandID, TenantID: spec.TenantID, UserID: spec.UserID, ActorID: identity.ActorID(spec.UserID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, PolicyID: s.config.PolicyID, PolicyVersion: s.config.PolicyVersion, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, RecordID: strings.Clone(spec.SessionID), CorrelationID: strings.Clone(r.CorrelationID)}
	selection := session.ActiveOrganizationSelection{SessionID: spec.SessionID, TenantID: spec.TenantID, SessionVersion: session.SessionVersion(spec.Version), OrganizationID: string(r.OrganizationID)}
	if r.OrganizationID != "" {
		key, _ := OrganizationSessionScope(spec.TenantID, r.OrganizationID)
		selection.Authority = session.AuthorityBinding{ScopeKey: key, Version: view.Organization.Version}
	}
	transition, err := session.NewOrganizationSelectionCommand(b, observed.Session, selection)
	if err != nil {
		return out, ErrForbidden
	}
	return Command{state: &commandState{owner: s, input: CommandInput{Binding: b, Operation: ActiveSet, Organization: view.Organization, Actor: view.Actor, TargetUser: identity.User{ID: spec.UserID, TenantID: spec.TenantID}, Session: observed, Bearer: r.Authentication.Bearer, MaximumMembers: s.config.MaximumMembers, MaximumPerUser: s.config.MaximumPerUser, MaximumPerTenant: s.config.MaximumPerTenant, ActiveOrganization: transition, ActiveOrganizationValidUntil: until}}}, nil
}

// GetActive requires current membership, owner aggregate epoch and action policy
// for every selected read. Unrelated organization changes do not invalidate it.
func (s *Service) GetActive(ctx context.Context, r ActiveOrganizationReadRequest) (out ActiveOrganizationView, err error) {
	defer func() {
		if recover() != nil {
			out, err = ActiveOrganizationView{}, ErrUnavailable
		}
	}()
	if s == nil || ctx == nil || !validOperationAuthentication(r.Authentication, r.CorrelationID) {
		return out, ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.MaximumDuration)
	defer cancel()
	observed, spec, err := s.authenticateActive(ctx, r.Authentication)
	if err != nil {
		return out, err
	}
	v, _ := spec.Authority.Bindings()
	var view View
	if v.Organization.Present {
		id := ID(v.ActiveOrganizationID)
		view, err = s.repository.Read(ctx, Query{Operation: Get, TenantID: spec.TenantID, ActorID: spec.UserID, OrganizationID: id})
		if err != nil {
			return out, publicError(ctx, err)
		}
		key, keyErr := OrganizationSessionScope(spec.TenantID, id)
		if keyErr != nil || !validView(view, spec.TenantID, id, spec.UserID) || v.Organization.Binding != (session.AuthorityBinding{ScopeKey: key, Version: view.Organization.Version}) {
			return out, ErrForbidden
		}
	}
	if err = s.authorize(ctx, spec.UserID, spec.TenantID, view.Organization.ID, view.Organization.Version, ActiveGet, r.CorrelationID); err != nil {
		return out, err
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if observed.ValidateAt(s.config.Clock.Now()) != nil {
		return out, ErrForbidden
	}
	return ActiveOrganizationView{SessionID: spec.SessionID, SessionVersion: spec.Version, Selected: v.Organization.Present, Organization: view.Organization, Member: view.Actor}, nil
}

func (ActiveOrganizationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.ActiveOrganizationRequest(redacted)"))
}
func (ActiveOrganizationRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ActiveOrganizationRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (ActiveOrganizationOperationRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.ActiveOrganizationOperationRequest(redacted)"))
}
func (ActiveOrganizationOperationRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ActiveOrganizationOperationRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ActiveOrganizationReadRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.ActiveOrganizationReadRequest(redacted)"))
}
func (ActiveOrganizationReadRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (ActiveOrganizationReadRequest) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
