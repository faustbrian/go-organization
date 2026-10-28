package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"slices"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// OperationCustodyConfig is closed native encryption configuration for safe
// original request correlation. Keys are copied and have no public projection.
// Keep retained envelope keys while any original mapping needs recovery; active
// key rotation must not discard them. Zero configuration is invalid.
type OperationCustodyConfig struct {
	active string
	keys   func() map[string][]byte
}

// NewOperationCustodyConfig validates one selected AES-256 envelope key and up
// to sixteen retained keys without IO. It copies caller-owned material; neither
// raw session bearers nor client idempotency keys enter retained ciphertext.
func NewOperationCustodyConfig(active string, keys map[string][]byte) (OperationCustodyConfig, error) {
	if !scope(active) || len(keys) == 0 || len(keys) > 16 || len(keys[active]) != 32 {
		return OperationCustodyConfig{}, organization.ErrInvalidInput
	}
	owned := make(map[string][]byte, len(keys))
	for id, material := range keys {
		if !scope(id) || len(material) != 32 {
			return OperationCustodyConfig{}, organization.ErrInvalidInput
		}
		owned[id] = bytes.Clone(material)
	}
	return OperationCustodyConfig{active: active, keys: func() map[string][]byte {
		copy := make(map[string][]byte, len(owned))
		for id, material := range owned {
			copy[id] = bytes.Clone(material)
		}
		return copy
	}}, nil
}

// OperationServiceConfig opts into direct create/update/add/role-update,
// selected archive/restore and repeat removal using
// the existing Service's real native owners. ConfigurationID is a fixed trusted
// deployment profile (1..128 bytes), not request data; change it for material
// selected-policy changes. Coordinator/RequestKeys select the sole existing
// kernel journal and immutable mapping, with current query/admission policy.
// NewOrganizationID is a bounded concurrency-safe canonical-ID source, called
// only for missing-key preparation candidates; races may discard candidates.
// No callback runs under SQL locks. Pools, services and policies remain borrowed.
// This opt-in profile selects native default audit limits and the fixed native
// lifecycle contributor; it does not inherit private custom registry limits.
type OperationServiceConfig struct {
	ConfigurationID   string
	Coordinator       kernel.CoordinatorConfig
	RequestKeys       kernel.RequestKeyConfig
	Custody           OperationCustodyConfig
	NewOrganizationID func(context.Context) (organization.ID, error)
}

// OperationService provides storage-neutral request signatures usable directly
// by an optional HTTP integration. It owns no competing journal, session engine
// or retry store and starts no goroutines. Matching keyed retries recover only
// the exact original outcome; they never prepare or execute fresh authority.
// Concurrent calls use isolated native participants. It borrows the source
// Service and primary for its lifetime; no Close or background cleanup is owned.
type OperationService struct{ state func() *operationServiceState }

type operationServiceState struct {
	source *Service
	config OperationServiceConfig
	crypto *envelope.Service
}

// NewOperationService validates composition without SQL, callbacks or mutation.
// Existing RequestKeyMigrationSource and RequestKeyPreparationMigrationSource
// must be installed. OperationLookupMigrationSource supplies removal's bounded
// natural-request lookup; no client Idempotency-Key exists for removal.
func NewOperationService(source *Service, c OperationServiceConfig) (*OperationService, error) {
	if source == nil || source.participant == nil || !scope(c.ConfigurationID) || c.Custody.keys == nil || c.NewOrganizationID == nil || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil || c.Coordinator.QueryPolicy.PolicyVersion != source.config.Core.PolicyVersion || c.Coordinator.AdmissionPolicy.PolicyVersion != source.config.Core.PolicyVersion || c.RequestKeys.Policy.PolicyVersion != source.config.Core.PolicyVersion {
		return nil, organization.ErrInvalidInput
	}
	if _, err := kernel.NewCoordinatorWithRequestKeys(source.participant.repository.pool, source.config.Registry, c.Coordinator, c.RequestKeys); err != nil {
		return nil, organization.ErrInvalidInput
	}
	keys := c.Custody.keys()
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	provider, err := keyring.New(keys)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	c.Coordinator.RetainedFingerprintKeys = cloneInvitationFingerprintKeys(c.Coordinator.RetainedFingerprintKeys)
	query, admission := *c.Coordinator.QueryPolicy, *c.Coordinator.AdmissionPolicy
	c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &query, &admission
	state := &operationServiceState{source: source, config: c, crypto: crypto}
	return &OperationService{state: func() *operationServiceState { return state }}, nil
}

// Create admits one original scoped key, allocates a canonical organization ID,
// and executes the existing native organization/owner transition. Retry uses
// current-authorized original recovery, never another ID or fresh preparation.
// Network must be the transport's trusted canonical full client address.
func (s *OperationService) Create(ctx context.Context, r organization.CreateOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	state := s.state()
	fields := []identity.FeatureField{text("name", r.Name), text("slug", r.Slug)}
	return state.keyed(ctx, r.Authentication, organization.Create, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		org, err := state.config.NewOrganizationID(ctx)
		if err != nil {
			return organization.Command{}, operationError(ctx, err)
		}
		return service.core.PrepareCreate(ctx, organization.CreateRequest{Authentication: r.Authentication, CommandID: id, ID: org, Name: r.Name, Slug: r.Slug, CorrelationID: r.CorrelationID})
	})
}

// AddMember atomically admits one exact target/role/version request through the
// existing native member, authority, protected-risk, audit and lifecycle owners.
// Matching keys recover even after the original organization epoch advances.
func (s *OperationService) AddMember(ctx context.Context, r organization.AddMemberOperationRequest, network string) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	fields := []identity.FeatureField{text("id", string(r.OrganizationID)), text("target", string(r.UserID)), text("role", string(r.Role)), number("version", r.OrganizationVersion), number("member-version", r.MemberVersion)}
	return s.state().keyed(ctx, r.Authentication, organization.AddMember, r.IdempotencyKey, fields, network, func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
		return service.core.PrepareAddMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: id, OrganizationID: r.OrganizationID, UserID: r.UserID, Role: r.Role, OrganizationVersion: r.OrganizationVersion, MemberVersion: r.MemberVersion, CorrelationID: r.CorrelationID})
	})
}

// Get delegates current authenticated/authorized bounded primary reading to the
// existing owner. HTTP rate.safe remains the selected transport owner's policy;
// direct callers explicitly select the existing uncached native read policy.
func (s *OperationService) Get(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.Get(ctx, r)
}

// ListMembers delegates the existing exclusive UserID cursor and bounded page
// contract; it neither caches authority nor mutates session activity.
func (s *OperationService) ListMembers(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	if s == nil || s.state == nil {
		return organization.View{}, organization.ErrInvalidInput
	}
	return s.state().source.ListMembers(ctx, r)
}

// RecoverOperation authenticates current disclosure authority and reconciles
// only the exact original safe binding. It never executes or renews a command.
func (s *OperationService) RecoverOperation(ctx context.Context, r organization.OperationRecoveryRequest) (organization.StoreResult, error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	state := s.state()
	if organization.Operation(r.Binding.OperationID) == organization.LeaveMember {
		service, err := state.compose(nil)
		if err != nil {
			return organization.StoreResult{}, err
		}
		return service.recoverLeaveOperation(ctx, r.Authentication, r.Binding, false)
	}
	if organization.Operation(r.Binding.OperationID) == organization.RemoveMember {
		return state.source.Recover(ctx, r.Authentication, Recovery{Binding: r.Binding})
	}
	p := &operationInvocation{state: state, op: organization.Operation(r.Binding.OperationID)}
	service, err := state.compose(p)
	if err != nil {
		return organization.StoreResult{}, err
	}
	p.service = service
	return service.Recover(ctx, r.Authentication, Recovery{Binding: r.Binding})
}

type operationInvocation struct {
	state                   *operationServiceState
	service                 *Service
	intent                  identity.RequestIntent
	op                      organization.Operation
	original                organization.Command
	retainedPreparedCommand PreparedCommand
	failure                 error
	prepare                 func(context.Context, *Service, identity.CommandID) (organization.Command, error)
}

func (s *operationServiceState) compose(p *operationInvocation) (*Service, error) {
	actor := *s.source.participant
	if p != nil {
		if p.prepare != nil {
			actor.operationInput = p.prepareInput
		}
		actor.operationRestore = p.restoreInput
	}
	// A Work binds the exact per-invocation participant, so it needs its own
	// immutable registry. This finite profile selects audit's native defaults
	// and the lifecycle owner's fixed/default-only schema, not callback adapters.
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{actor.repository.directory, audit, lifecycle, s.source.config.Risk, &actor})
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	coordinator, err := kernel.NewCoordinatorWithRequestKeys(actor.repository.pool, registry, s.config.Coordinator, s.config.RequestKeys)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	config := s.source.config
	config.Coordinator, config.Registry = coordinator, registry
	return NewService(&actor, config)
}

func (s *operationServiceState) keyed(ctx context.Context, auth organization.Authentication, op organization.Operation, key identity.IdempotencyKey, fields []identity.FeatureField, network string, prepare func(context.Context, *Service, identity.CommandID) (organization.Command, error)) (out organization.StoreResult, err error) {
	return s.keyedPreparation(ctx, auth, op, key, fields, network, prepare, nil)
}

func (s *operationServiceState) keyedPrepared(ctx context.Context, auth organization.Authentication, op organization.Operation, key identity.IdempotencyKey, fields []identity.FeatureField, network string, prepare func(context.Context, *Service, identity.CommandID) (PreparedCommand, error)) (organization.StoreResult, error) {
	return s.keyedPreparation(ctx, auth, op, key, fields, network, nil, prepare)
}

func (s *operationServiceState) keyedPreparation(ctx context.Context, auth organization.Authentication, op organization.Operation, key identity.IdempotencyKey, fields []identity.FeatureField, network string, prepare func(context.Context, *Service, identity.CommandID) (organization.Command, error), prepareNative func(context.Context, *Service, identity.CommandID) (PreparedCommand, error)) (out organization.StoreResult, err error) {
	if !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.source.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = organization.ErrUnavailable
		}
	}()
	actor, err := s.actor(ctx, auth)
	if err != nil {
		return out, err
	}
	fields = append(slices.Clone(fields), text("configuration", s.config.ConfigurationID))
	intent, err := identity.NewRequestIntent(fields)
	if err != nil {
		return out, organization.ErrInvalidInput
	}
	p := &operationInvocation{state: s, intent: intent, op: op, prepare: prepare}
	if prepareNative != nil {
		p.prepare = func(ctx context.Context, service *Service, id identity.CommandID) (organization.Command, error) {
			prepared, err := prepareNative(ctx, service, id)
			if err != nil {
				return organization.Command{}, err
			}
			if prepared.state == nil || prepared.state.owner != service {
				return organization.Command{}, organization.ErrInvalidInput
			}
			p.retainedPreparedCommand = prepared
			return prepared.state.core, nil
		}
	}
	p.service, err = s.compose(p)
	if err != nil {
		return out, err
	}
	scope := kernel.RequestKeyScope{TenantID: auth.TenantID, ActorID: identity.ActorID(actor), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: string(op)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.RequestKeys.Policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(auth.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(actor)}, Action: authorization.Action(op), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(op)}}}
	k, wire, err := p.service.config.Coordinator.ResolvePreparedRequestKey(ctx, scope, key, intent, caller, kernel.FeatureRegistration{Contributor: p.service.participant.Descriptor(), Operation: op.Descriptor()}, p.service.participant)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			// The kernel deliberately redacts preparation callback errors. This
			// synchronous native phase retains its own already classified domain
			// denial before any mapping/journal/domain write, not a SQL failure.
			return out, operationError(ctx, p.failure)
		}
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) {
			if x, inputErr := p.original.Input(); inputErr == nil && x.Binding.CommandID == unknown.CommandID {
				out = operationCorrelation(x.Binding)
				out.Receipt.Outcome = identity.CommitOutcomeUnknown
				out.Receipt.Feature = &identity.FeatureReceipt{Operation: op.Descriptor()}
			}
		}
		return out, operationError(ctx, err)
	}
	binding, err := p.restoreInput(ctx, k, wire)
	if err != nil {
		return out, err
	}
	x, originalErr := p.original.Input()
	if originalErr == nil && x.Binding == binding {
		// Lifecycle's password-owned signed framing cannot be reconstructed by
		// MapCommand. Keep the exact native preparation admitted for this key;
		// discarded contenders and matching retries never execute their candidate.
		prepared := p.retainedPreparedCommand
		if prepared.state == nil {
			prepared, err = p.service.prepare(ctx, p.original, network)
			if err != nil {
				return operationCorrelation(binding), err
			}
		}
		return p.service.Execute(ctx, prepared)
	}
	out, err = p.service.Recover(ctx, auth, Recovery{Binding: binding})
	// Exact-session selection requires current disclosure authority even for
	// correlation; a sibling or denied caller must receive no original binding.
	if out.Receipt.Binding.CommandID == "" && op != organization.ActiveSet {
		// Confirmed original mapping is correlation only. Missing/denied
		// journals retain the kernel's error, not an invented NotCommitted or
		// successful receipt, and never permit new execution under this key.
		out = operationCorrelation(binding)
	}
	return out, operationError(ctx, err)
}

func operationNetwork(network string) bool {
	ip, err := netip.ParseAddr(network)
	return err == nil && ip.Zone() == "" && ip.Unmap().String() == network
}

func operationCorrelation(b identity.CommandBinding) organization.StoreResult {
	return mutationResult(b, identity.CommandResult{Binding: b})
}

func (s *operationServiceState) actor(ctx context.Context, auth organization.Authentication) (identity.UserID, error) {
	token, err := session.ParseToken(auth.Bearer.Token())
	if err != nil {
		return "", organization.ErrForbidden
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		return "", organization.ErrForbidden
	}
	observed, err := s.source.config.Sessions.Get(ctx, session.GetRequest{TenantID: auth.TenantID, Credential: credential})
	if err != nil {
		return "", operationError(ctx, err)
	}
	if observed.ValidateAt(s.source.config.Core.Clock.Now()) != nil {
		return "", organization.ErrForbidden
	}
	b, err := observed.Session.Bindings()
	if err != nil || b.TenantID != auth.TenantID || b.Authentication.Kind != session.AuthenticationVerified {
		return "", organization.ErrForbidden
	}
	return b.UserID, nil
}

// PrepareRequestKey is the existing kernel's original-input hook. Only an
// isolated exact contributor created by OperationService has invocation input;
// ordinary native participants reject this optional callback. No risk debit,
// protected mutation or bearer persistence occurs in this preparation phase.
func (p *Contributor) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	if p == nil || p.operationInput == nil {
		return nil, organization.ErrInvalidInput
	}
	return p.operationInput(ctx, b, intent)
}

// RestoreRequestKey implements only the kernel's opt-in original-mapping
// recovery decoder. It authenticates native ciphertext and complete original
// scope without preparation, owner reads, entropy, deadline renewal or effects.
// Ordinary native contributors reject it and preserve generic recovery privacy.
func (p *Contributor) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	if p == nil || p.operationRestore == nil || ctx == nil {
		return identity.CommandBinding{}, organization.ErrInvalidInput
	}
	return p.operationRestore(ctx, b, wire)
}

func (p *operationInvocation) prepareInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	expected, _ := p.intent.Fields()
	actual, ok := intent.Fields()
	if !ok || !reflect.DeepEqual(expected, actual) || b.Feature != (kernel.FeatureRegistration{Contributor: p.service.participant.Descriptor(), Operation: p.op.Descriptor()}) {
		return nil, organization.ErrInvalidInput
	}
	command, err := p.prepare(ctx, p.service, b.Admission.CommandID)
	if err != nil {
		p.failure = err
		return nil, err
	}
	x, err := command.Input()
	if err != nil || x.Binding.CommandID != b.Admission.CommandID || x.Binding.TenantID != b.Scope.TenantID || x.Binding.ActorID != b.Scope.ActorID || x.Binding.OperationID != b.Scope.RouteID {
		return nil, organization.ErrForbidden
	}
	p.original = command
	plain, err := json.Marshal(operationStoredBinding(x.Binding))
	defer clear(plain)
	if err != nil || len(plain) > 4096 {
		return nil, organization.ErrInvalidInput
	}
	aad, err := p.inputContext(b)
	if err != nil {
		return nil, err
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.state.config.Custody.active, Context: aad})
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	return sealed.MarshalBinary()
}

// Alias only the safe original binding inside authenticated native ciphertext;
// this deliberately does not serialize a command, session, bearer or client key.
type operationStoredBinding identity.CommandBinding

func (p *operationInvocation) inputContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if b.Namespace != p.state.config.RequestKeys.Namespace || b.Scope.Method != "POST" || b.Scope.RouteID != string(p.op) || b.Feature != (kernel.FeatureRegistration{Contributor: p.service.participant.Descriptor(), Operation: p.op.Descriptor()}) || b.PolicyVersion != p.state.config.RequestKeys.Policy.PolicyVersion || b.Admission.CommandID == "" || b.Admission.FingerprintKeyVersion == 0 || b.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, organization.ErrInvalidInput
	}
	wire, err := json.Marshal(struct {
		Namespace     string
		Scope         kernel.RequestKeyScope
		Admission     kernel.RequestKeyAdmission
		Feature       kernel.FeatureRegistration
		Policy        uint64
		Intent        [32]byte
		Configuration string
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.state.config.ConfigurationID})
	if err != nil {
		return envelope.Context{}, organization.ErrInvalidInput
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "organization-operation-input-v1", "binding": hex.EncodeToString(digest[:])})
}

func (p *operationInvocation) restoreInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	if len(wire) == 0 || len(wire) > 16384 {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	aad, err := p.inputContext(b)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	plain, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > 4096 {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	var stored operationStoredBinding
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&stored) != nil {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	binding := identity.CommandBinding(stored)
	if binding.CommandID != b.Admission.CommandID || binding.TenantID != b.Scope.TenantID || binding.ActorID != b.Scope.ActorID || binding.ActorKind != b.Scope.ActorKind || binding.OperationID != b.Scope.RouteID || binding.PolicyID != p.state.source.config.Core.PolicyID || binding.PolicyVersion != p.state.source.config.Core.PolicyVersion || binding.ValidateFor(p.op.Descriptor()) != nil {
		return identity.CommandBinding{}, organization.ErrUnavailable
	}
	return binding, nil
}

func operationError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	for _, known := range []error{organization.ErrInvalidInput, organization.ErrForbidden, organization.ErrConflict, organization.ErrLastOwner, organization.ErrLimit, organization.ErrUnavailable, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known
		}
	}
	var forbidden identity.ForbiddenError
	var conflict identity.ConflictError
	var unknown identity.UnknownCommitError
	switch {
	case errors.As(err, &unknown):
		return unknown
	case errors.As(err, &forbidden):
		return organization.ErrForbidden
	case errors.As(err, &conflict):
		return organization.ErrConflict
	default:
		return organization.ErrUnavailable
	}
}

// Format prevents traversal of borrowed source owners and secret configuration.
func (OperationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.OperationService(redacted)"))
}

// MarshalJSON rejects implicit export of runtime owners.
func (OperationService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects implicit export of runtime owners.
func (OperationService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// Format redacts encryption key custody.
func (OperationCustodyConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.OperationCustodyConfig(redacted)"))
}

// MarshalJSON rejects implicit key export.
func (OperationCustodyConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects implicit key export.
func (OperationCustodyConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// Format redacts coordinator keys, callbacks and borrowed policies.
func (OperationServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.OperationServiceConfig(redacted)"))
}

// MarshalJSON rejects implicit configuration export.
func (OperationServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// MarshalText rejects implicit configuration export.
func (OperationServiceConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
