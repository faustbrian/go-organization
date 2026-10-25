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
	"reflect"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// InvitationOperationServiceConfig selects original-key send on the borrowed
// native invitation service. ConfigurationID names the immutable deployment
// policy, including borrowed callback/owner configuration. Change it for material
// profile changes and retain the original profile and custody keys for recovery.
// NewInvitationID is bounded and concurrency-safe; races may discard candidates.
// It runs outside SQL and must not perform domain mutation or proof generation.
type InvitationOperationServiceConfig struct {
	ConfigurationID string
	RequestKeys     kernel.RequestKeyConfig
	Custody         OperationCustodyConfig
	NewInvitationID func(context.Context) (organization.ID, error)
}

// InvitationOperationService admits one original initiating key through the
// existing kernel mapping and invitation engine. It starts no goroutines and
// borrows all native owners. Retries only recover/classify original metadata;
// they never rebuild execution authority or disclose/redeliver invitation proof.
type InvitationOperationService struct {
	state func() *invitationOperationState
}

type invitationOperationState struct {
	source  *InvitationService
	config  InvitationOperationServiceConfig
	crypto  *envelope.Service
	profile [32]byte
}

// NewInvitationOperationService validates composition without SQL or callbacks.
// Install request-key, original preparation and exact expiry migrations first.
func NewInvitationOperationService(source *InvitationService, config InvitationOperationServiceConfig) (*InvitationOperationService, error) {
	if source == nil || source.actor == nil || !scope(config.ConfigurationID) || config.Custody.keys == nil || config.NewInvitationID == nil {
		return nil, organization.ErrInvalidInput
	}
	if config.RequestKeys.Policy.PolicyVersion != source.config.Core.PolicyVersion {
		return nil, organization.ErrInvalidInput
	}
	keys := config.Custody.keys()
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
	profile, err := invitationOperationProfile(source.config)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	state := &invitationOperationState{source: source, config: config, crypto: crypto, profile: profile}
	if _, err := state.invocation(); err != nil {
		return nil, organization.ErrInvalidInput
	}
	return &InvitationOperationService{state: func() *invitationOperationState { return state }}, nil
}

// Send selects an exact existing verified recipient and current owner. Network
// is the transport's trusted canonical full client address. An absent original
// claim remains Unknown before its immutable deadline; after primary expiry the
// sole kernel can irreversibly refuse that ID and return metadata-only noncommit.
// No classification permits retrying effects under the same key or command ID.
func (s *InvitationOperationService) Send(ctx context.Context, r organization.InvitationSendOperationRequest, network string) (out organization.StoreResult, err error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.source.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = organization.StoreResult{}, organization.ErrUnavailable
		}
	}()
	observed, _, err := state.source.observeInvitationRecovery(ctx, r.Authentication, "")
	if err != nil {
		return out, err
	}
	actor, err := observed.Session.Bindings()
	if err != nil {
		return out, organization.ErrForbidden
	}
	intent, err := identity.NewRequestIntent([]identity.FeatureField{text("id", string(r.OrganizationID)), number("version", r.OrganizationVersion), text("target", string(r.RecipientUserID)), text("recipient-identifier", string(r.RecipientIdentifierID)), text("role", string(organization.RoleMember)), text("configuration", state.config.ConfigurationID), text("send-profile", hex.EncodeToString(state.profile[:]))})
	if err != nil {
		return out, organization.ErrInvalidInput
	}
	p, err := state.invocation()
	if err != nil {
		return out, invitationPublicError(err)
	}
	p.request, p.intent = r, intent
	scope := kernel.RequestKeyScope{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: string(organization.InvitationSend)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(state.config.RequestKeys.Policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(scope.TenantID), Subject: authorization.Subject{Kind: scope.ActorKind, ID: authorization.SubjectID(scope.ActorID)}, Action: authorization.Action(scope.RouteID), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}}}
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			return out, operationError(ctx, p.failure)
		}
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) && p.original.Spec.Binding.CommandID == unknown.CommandID {
			out = invitationOperationCorrelation(p.original)
			out.Receipt.Outcome = identity.CommitOutcomeUnknown
		}
		return out, operationError(ctx, err)
	}
	original, err := p.decodeInput(ctx, binding, wire)
	if err != nil {
		return out, err
	}
	if input, inputErr := p.command.Input(); inputErr == nil && input.Binding == original.Spec.Binding {
		// Only this invocation's acknowledged winning mapping retains genuine
		// private session authority. Candidates losing arbitration cannot execute.
		prepared, err := state.source.prepare(ctx, p.command, network)
		if err != nil {
			return invitationOperationCorrelation(original), err
		}
		return state.source.Execute(ctx, prepared)
	}
	return state.source.recoverMappedInvitationSend(ctx, r.Authentication, p, original)
}

// These native send fields affect retained intent/custody, not a new policy
// engine. Opaque borrowed policy/signing/resolver/canonical-ID collaborators are
// named by ConfigurationID and must remain immutable for that profile's lifetime.
func invitationOperationProfile(c InvitationServiceConfig) ([32]byte, error) {
	type profile sessionpg.IdentifierAdmissionConfig
	wire, err := json.Marshal([]any{c.Core.PolicyID, c.Core.PolicyVersion, c.Core.MaximumDuration, c.Core.MaximumMembers, c.Core.MaximumPerUser, c.Core.MaximumPerTenant, profile(c.Admission.Profile), c.Admission.Session.Schema, c.Admission.Session.MaximumDuration, c.Invitation.Audience, c.Invitation.Lifetime, c.Invitation.MaximumPending, c.Issuer.Crypto.Issuer, c.Issuer.Crypto.Limits, c.Issuer.Crypto.Skew, c.Issuer.Audience, c.Issuer.CurrentReplayKeyVersion, c.Issuer.PreparationTimeout, c.Preparation.Deployment, c.Preparation.ActiveEnvelopeKey, c.Delivery.Policy, c.Delivery.PolicyVersion, c.Delivery.ProviderVersion, c.Delivery.StatusPolicyVersion, c.Delivery.TemplateID, c.Delivery.TemplateVersion, c.Delivery.LocaleChain, c.Delivery.Endpoint, c.Delivery.ScopeKey})
	defer clear(wire)
	if err != nil {
		return [32]byte{}, organization.ErrInvalidInput
	}
	return sha256.Sum256(wire), nil
}

type invitationOperationInvocation struct {
	*invitationPhase
	state    *invitationOperationState
	request  organization.InvitationSendOperationRequest
	intent   identity.RequestIntent
	command  organization.Command
	original invitationOperationInput
	// Supplied only after authenticated original decoding and current native
	// disclosure checks, never by the pure restoration callbacks.
	recoveryOrganization organization.ID
	failure              error
}

var _ kernel.RequestKeyExpiryContributor = (*invitationOperationInvocation)(nil)

func (p *invitationOperationInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return recoverInvitationParticipant(ctx, w, p, p.recoveryOrganization)
}

func (s *invitationOperationState) invocation() (*invitationOperationInvocation, error) {
	p := &invitationOperationInvocation{state: s, invitationPhase: &invitationPhase{service: s.source, input: organization.CommandInput{Operation: organization.InvitationSend}}}
	audit, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return nil, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return nil, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.source.actor.repository.directory, audit, lifecycle, s.source.config.Risk, p, s.source.issuer, s.source.config.Delivery.Owner})
	if err != nil {
		return nil, err
	}
	p.registry = registry
	p.coordinator, err = kernel.NewCoordinatorWithRequestKeys(s.source.actor.repository.pool, registry, s.source.config.Coordinator, s.config.RequestKeys)
	return p, err
}

func (p *invitationOperationInvocation) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: organization.InvitationSend.Descriptor()}
}

// Request custody is deliberately code-free. It contains the complete original
// native feature input, verified identifier and earliest original deadline, not
// a serializable session, bearer, initiating key, invitation proof or work lease.
type invitationOperationInput struct {
	Schema                                  uint32
	Spec                                    identity.FeatureCommandSpec
	OrganizationID                          organization.ID
	OrganizationVersion                     uint64
	RecipientUser                           identity.User
	RecipientIdentifier                     identity.Identifier
	SessionUntil, InvitationUntil, Deadline time.Time
}

// This local input budget bounds authenticated JSON before decoding, below the
// kernel's 1MiB custody ceiling. Oversized native input denies, never truncates.
const maximumInvitationOperationInput = 64 << 10

func (p *invitationOperationInvocation) PrepareRequestKey(ctx context.Context, binding kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	want, _ := p.intent.Fields()
	got, ok := intent.Fields()
	if !ok || !reflect.DeepEqual(want, got) || p.request.Validate() != nil {
		return nil, organization.ErrInvalidInput
	}
	if _, err := p.inputContext(binding); err != nil {
		return nil, err
	}
	id, err := p.state.config.NewInvitationID(ctx)
	if err != nil {
		p.failure = operationError(ctx, err)
		return nil, p.failure
	}
	r := p.request
	command, err := p.state.source.root.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: r.Authentication, CommandID: binding.Admission.CommandID, ID: id, OrganizationID: r.OrganizationID, OrganizationVersion: r.OrganizationVersion, RecipientUserID: r.RecipientUserID, RecipientIdentifierID: r.RecipientIdentifierID, CorrelationID: r.CorrelationID})
	if err != nil {
		p.failure = err
		return nil, err
	}
	x, err := command.Input()
	if err != nil || x.Binding.TenantID != binding.Scope.TenantID || x.Binding.ActorID != binding.Scope.ActorID || x.Binding.ActorKind != binding.Scope.ActorKind {
		return nil, organization.ErrForbidden
	}
	phase := &invitationPhase{service: p.state.source, input: x}
	if err = phase.mapCommand(); err != nil {
		return nil, invitationPublicError(err)
	}
	spec, ok := phase.command.Feature()
	if !ok {
		return nil, organization.ErrUnavailable
	}
	deadline := x.Session.ValidUntil()
	if x.Invitation.Record.ExpiresAt.Before(deadline) {
		deadline = x.Invitation.Record.ExpiresAt
	}
	original := invitationOperationInput{Schema: 1, Spec: spec, OrganizationID: x.Organization.ID, OrganizationVersion: x.Organization.Version, RecipientUser: x.TargetUser, RecipientIdentifier: x.Invitation.RecipientIdentifier, SessionUntil: x.Session.ValidUntil(), InvitationUntil: x.Invitation.Record.ExpiresAt, Deadline: deadline}
	plain, err := json.Marshal(original)
	defer clear(plain)
	if err != nil || len(plain) > maximumInvitationOperationInput {
		return nil, organization.ErrUnavailable
	}
	aad, err := p.inputContext(binding)
	if err != nil {
		return nil, err
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.state.config.Custody.active, Context: aad})
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	wire, err := sealed.MarshalBinary()
	if err == nil {
		p.command, p.original = command, original
	}
	return wire, err
}

func (p *invitationOperationInvocation) inputContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if ctx := p.state; ctx == nil || b.Namespace != ctx.config.RequestKeys.Namespace || b.Scope.Method != "POST" || b.Scope.ActorKind != authorization.SubjectUser || b.Scope.RouteID != string(organization.InvitationSend) || b.Feature != p.registration() || b.PolicyVersion != ctx.source.config.Core.PolicyVersion || b.Admission.CommandID == "" || b.Admission.FingerprintKeyVersion == 0 || b.IntentDigest == ([32]byte{}) {
		return envelope.Context{}, organization.ErrUnavailable
	}
	wire, err := json.Marshal(struct {
		Namespace       string
		Scope           kernel.RequestKeyScope
		Admission       kernel.RequestKeyAdmission
		Feature         kernel.FeatureRegistration
		Policy          uint64
		Intent, Profile [32]byte
		Configuration   string
	}{b.Namespace, b.Scope, b.Admission, b.Feature, b.PolicyVersion, b.IntentDigest, p.state.profile, p.state.config.ConfigurationID})
	if err != nil {
		return envelope.Context{}, organization.ErrUnavailable
	}
	digest := sha256.Sum256(wire)
	return envelope.NewContext(map[string]string{"profile": "organization-invitation-input-v1", "binding": hex.EncodeToString(digest[:])})
}

func (p *invitationOperationInvocation) decodeInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (invitationOperationInput, error) {
	var out invitationOperationInput
	if ctx == nil || ctx.Err() != nil || len(wire) == 0 || len(wire) > maximumInvitationOperationInput*3/2 {
		return out, organization.ErrUnavailable
	}
	aad, err := p.inputContext(b)
	if err != nil {
		return out, err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return out, organization.ErrUnavailable
	}
	plain, err := p.state.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) == 0 || len(plain) > maximumInvitationOperationInput {
		return out, organization.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	var original invitationOperationInput
	if decoder.Decode(&original) != nil {
		return out, organization.ErrUnavailable
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return out, organization.ErrUnavailable
	}
	binding := original.Spec.Binding
	if original.Schema != 1 || original.Spec.Operation != organization.InvitationSend.Descriptor() || binding.ValidateFor(organization.InvitationSend.Descriptor()) != nil || binding.CommandID != b.Admission.CommandID || binding.TenantID != b.Scope.TenantID || binding.ActorID != b.Scope.ActorID || binding.ActorKind != b.Scope.ActorKind || binding.OperationID != b.Scope.RouteID || binding.PolicyID != p.state.source.config.Core.PolicyID || binding.PolicyVersion != b.PolicyVersion || !scope(string(original.OrganizationID)) || original.OrganizationVersion == 0 || original.RecipientUser.ID != binding.UserID || original.RecipientUser.Validate(binding.TenantID) != nil || original.RecipientUser.Status != identity.StatusActive || original.RecipientIdentifier.Validate(binding.UserID) != nil || original.RecipientIdentifier.Kind != identity.IdentifierEmail || !original.RecipientIdentifier.Verified || original.SessionUntil.IsZero() || original.InvitationUntil.IsZero() {
		return out, organization.ErrUnavailable
	}
	if _, err := identity.NewFeatureCommand(original.Spec); err != nil {
		return out, organization.ErrUnavailable
	}
	deadline := original.SessionUntil
	if original.InvitationUntil.Before(deadline) {
		deadline = original.InvitationUntil
	}
	if !deadline.Equal(original.Deadline) {
		return out, organization.ErrUnavailable
	}
	fields := map[string]identity.FeatureValue{}
	for _, field := range original.Spec.Fields {
		fields[field.Name] = field.Value
	}
	for name, expected := range map[string]identity.FeatureValue{
		"organization.id":                           {Kind: identity.FeatureText, Text: string(original.OrganizationID)},
		"organization.version":                      {Kind: identity.FeatureUint64, Uint64: original.OrganizationVersion},
		"organization.role":                         {Kind: identity.FeatureText, Text: string(organization.RoleMember)},
		"organization.recipient-identifier":         {Kind: identity.FeatureText, Text: string(original.RecipientIdentifier.ID)},
		"organization.recipient-identifier-version": {Kind: identity.FeatureUint64, Uint64: original.RecipientIdentifier.Version},
		"organization.session-until":                {Kind: identity.FeatureText, Text: original.SessionUntil.UTC().Format(time.RFC3339Nano)},
		"organization.invitation-expires-at":        {Kind: identity.FeatureTime, Time: original.InvitationUntil},
	} {
		if !reflect.DeepEqual(fields[name], expected) {
			return out, organization.ErrUnavailable
		}
	}
	return original, nil
}

func (p *invitationOperationInvocation) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	original, err := p.decodeInput(ctx, b, wire)
	if err != nil {
		return identity.CommandBinding{}, err
	}
	return original.Spec.Binding, nil
}

func (p *invitationOperationInvocation) RestoreRequestKeyExpiry(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, time.Time, error) {
	original, err := p.decodeInput(ctx, b, wire)
	if err != nil {
		return identity.CommandBinding{}, time.Time{}, err
	}
	return original.Spec.Binding, original.Deadline, nil
}

func invitationOperationCorrelation(original invitationOperationInput) organization.StoreResult {
	return organization.StoreResult{OrganizationID: original.OrganizationID, InvitationID: organization.ID(original.Spec.Binding.RecordID), MemberID: original.Spec.Binding.UserID, Receipt: identity.CommandResult{Binding: original.Spec.Binding, Feature: &identity.FeatureReceipt{Operation: organization.InvitationSend.Descriptor()}}}
}

func (InvitationOperationServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.InvitationOperationServiceConfig(redacted)"))
}
func (InvitationOperationServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationOperationServiceConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationOperationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.InvitationOperationService(redacted)"))
}
func (InvitationOperationService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationOperationService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
