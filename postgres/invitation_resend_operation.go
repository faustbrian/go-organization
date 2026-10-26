package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// Resend admits one original initiating key for the exact pending invitation
// and versions. The existing native owner preserves its recipient, role and
// exclusive expiry and atomically supersedes its proof with one delivery intent.
// Matching keys only reconcile the original command under current manager and
// recipient authority; they never prepare, sign, send or renew authority again.
// Network is the transport's trusted canonical full client address. The result
// projects authorized original delivery state, never proof or effect identity.
func (s *InvitationOperationService) Resend(ctx context.Context, r organization.InvitationResendOperationRequest, network string) (out organization.InvitationResendOperationResult, err error) {
	if s == nil || s.state == nil || ctx == nil || r.Validate() != nil || !operationNetwork(network) {
		return out, organization.ErrInvalidInput
	}
	state := s.state()
	ctx, cancel := context.WithTimeout(ctx, state.source.config.Core.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, err = organization.InvitationResendOperationResult{}, organization.ErrUnavailable
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
	intent, err := identity.NewRequestIntent(resendOperationFields(r, state))
	if err != nil {
		return out, organization.ErrInvalidInput
	}
	p, err := state.resendInvocation()
	if err != nil {
		return out, invitationPublicError(err)
	}
	p.request, p.intent, p.network = r, intent, network
	scope := kernel.RequestKeyScope{TenantID: r.Authentication.TenantID, ActorID: identity.ActorID(actor.UserID), ActorKind: authorization.SubjectUser, Method: "POST", RouteID: string(organization.InvitationResend)}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(state.config.RequestKeys.Policy.PolicyVersion), Request: authorization.Request{Tenant: authorization.TenantID(scope.TenantID), Subject: authorization.Subject{Kind: scope.ActorKind, ID: authorization.SubjectID(scope.ActorID)}, Action: authorization.Action(scope.RouteID), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(scope.RouteID)}}}
	binding, wire, err := p.coordinator.ResolvePreparedRequestKey(ctx, scope, r.IdempotencyKey, intent, caller, p.registration(), p)
	defer clear(wire)
	if err != nil {
		if p.failure != nil {
			return out, operationError(ctx, p.failure)
		}
		var unknown identity.UnknownCommitError
		if errors.As(err, &unknown) && p.original.Spec.Binding.CommandID == unknown.CommandID {
			out.StoreResult = resendOperationCorrelation(p.original)
			out.Receipt.Outcome = identity.CommitOutcomeUnknown
		}
		return out, operationError(ctx, err)
	}
	original, err := p.decodeInput(ctx, binding, wire)
	if err != nil {
		return out, err
	}
	if p.prepared.state != nil && p.prepared.state.input.Binding == original.Spec.Binding {
		// Only the acknowledged original winner executes its exact native rate,
		// session and recipient preparation. No reconstruction supplies authority.
		result, failure := state.source.ExecuteResend(ctx, p.prepared)
		return p.finalizeResult(ctx, p.prepared.state.recipient, result, failure)
	}
	return p.recoverOriginal(ctx, r.Authentication, original)
}

func resendOperationFields(r organization.InvitationResendOperationRequest, s *invitationOperationState) []identity.FeatureField {
	return []identity.FeatureField{text("id", string(r.OrganizationID)), text("invitation-id", string(r.InvitationID)), number("version", r.OrganizationVersion), number("invitation-version", r.InvitationVersion), text("configuration", s.config.ConfigurationID), text("resend-profile", hex.EncodeToString(s.profile[:]))}
}

func resendOperationResult(result InvitationResendResult, err error) organization.InvitationResendOperationResult {
	out := organization.InvitationResendOperationResult{StoreResult: result.StoreResult}
	if err == nil && result.Receipt.Outcome == identity.CommitOutcomeCommitted && result.Delivery != nil {
		out.DeliveryState = result.Delivery.State
	}
	return out
}

func (p *invitationResendOperationInvocation) finalizeResult(ctx context.Context, recipient kernel.RecipientRecord, result InvitationResendResult, failure error) (organization.InvitationResendOperationResult, error) {
	if failure != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Delivery == nil {
		return resendOperationResult(result, failure), failure
	}
	// Delivery status invokes policy callbacks, while committed-command recovery
	// does not revisit recipient participants. Recheck the existing directory
	// owner's exact security snapshot after those callbacks, without renewing it.
	current, err := p.state.source.repository.resolveRecipient(ctx, result.Receipt.Binding.TenantID, result.Receipt.Binding.UserID, recipient.Identifier.ID)
	if err == nil && (current.User != recipient.User || current.Identifier != recipient.Identifier || current.Verification != recipient.Verification || current.UserAuthorityVersion != recipient.UserAuthorityVersion || current.IdentifierAuthorityVersion != recipient.IdentifierAuthorityVersion || current.CredentialAuthorityVersion != recipient.CredentialAuthorityVersion) {
		err = organization.ErrForbidden
	}
	if err == nil {
		err = ctx.Err()
	}
	return resendOperationResult(result, err), err
}

type invitationResendOperationInvocation struct {
	*invitationPhase
	state                *invitationOperationState
	request              organization.InvitationResendOperationRequest
	intent               identity.RequestIntent
	network              string
	prepared             PreparedInvitation
	original             invitationResendOperationInput
	recoveryOrganization organization.ID
	failure              error
}

var _ kernel.RequestKeyExpiryContributor = (*invitationResendOperationInvocation)(nil)

func (s *invitationOperationState) resendInvocation() (*invitationResendOperationInvocation, error) {
	p := &invitationResendOperationInvocation{state: s, invitationPhase: &invitationPhase{service: s.source, input: organization.CommandInput{Operation: organization.InvitationResend}}}
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

func (p *invitationResendOperationInvocation) registration() kernel.FeatureRegistration {
	return kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: organization.InvitationResend.Descriptor()}
}

func (p *invitationResendOperationInvocation) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return recoverInvitationParticipant(ctx, w, p, p.recoveryOrganization)
}

// Distinct resend framing keeps every installed Send envelope byte/identity
// unchanged. Only code-free native fields and immutable recipient/deadline
// correlation enter authenticated ciphertext, never bearer, proof or client key.
type invitationResendOperationInput struct {
	Schema                                  uint32
	Spec                                    identity.FeatureCommandSpec
	OrganizationID                          organization.ID
	OrganizationVersion, InvitationVersion  uint64
	RecipientUser                           identity.User
	RecipientIdentifier                     identity.Identifier
	CreatedBy                               identity.UserID
	SessionUntil, InvitationUntil, Deadline time.Time
}

func (p *invitationResendOperationInvocation) PrepareRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, intent identity.RequestIntent) ([]byte, error) {
	want, _ := p.intent.Fields()
	got, ok := intent.Fields()
	if !ok || !reflect.DeepEqual(want, got) || p.request.Validate() != nil {
		return nil, organization.ErrInvalidInput
	}
	if _, err := p.inputContext(b); err != nil {
		return nil, err
	}
	r := p.request
	prepared, err := p.state.source.PrepareResend(ctx, organization.InvitationResendRequest{Authentication: r.Authentication, CommandID: b.Admission.CommandID, OrganizationID: r.OrganizationID, ID: r.InvitationID, OrganizationVersion: r.OrganizationVersion, InvitationVersion: r.InvitationVersion, CorrelationID: r.CorrelationID}, p.network)
	if err != nil {
		p.failure = err
		return nil, err
	}
	x := prepared.state.input
	spec, ok := prepared.state.command.Feature()
	if !ok || x.Binding != spec.Binding || x.Binding.CommandID != b.Admission.CommandID || x.Binding.TenantID != b.Scope.TenantID || x.Binding.ActorID != b.Scope.ActorID || x.Binding.ActorKind != b.Scope.ActorKind {
		return nil, organization.ErrForbidden
	}
	deadline := x.Session.ValidUntil()
	if x.Invitation.Record.ExpiresAt.Before(deadline) {
		deadline = x.Invitation.Record.ExpiresAt
	}
	original := invitationResendOperationInput{Schema: 1, Spec: spec, OrganizationID: x.Organization.ID, OrganizationVersion: x.Organization.Version, InvitationVersion: x.Invitation.Record.Version, RecipientUser: x.TargetUser, RecipientIdentifier: x.Invitation.RecipientIdentifier, CreatedBy: x.Invitation.Record.CreatedBy, SessionUntil: x.Session.ValidUntil(), InvitationUntil: x.Invitation.Record.ExpiresAt, Deadline: deadline}
	plain, err := json.Marshal(original)
	defer clear(plain)
	if err != nil || len(plain) > maximumInvitationOperationInput {
		return nil, organization.ErrUnavailable
	}
	aad, err := p.inputContext(b)
	if err != nil {
		return nil, err
	}
	sealed, err := p.state.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.state.config.Custody.active, Context: aad})
	if err != nil {
		return nil, organization.ErrUnavailable
	}
	wire, err := sealed.MarshalBinary()
	if err == nil {
		p.prepared, p.original = prepared, original
	}
	return wire, err
}

func (p *invitationResendOperationInvocation) inputContext(b kernel.RequestKeyPreparationBinding) (envelope.Context, error) {
	if s := p.state; s == nil || b.Namespace != s.config.RequestKeys.Namespace || b.Scope.Method != "POST" || b.Scope.ActorKind != authorization.SubjectUser || b.Scope.RouteID != string(organization.InvitationResend) || b.Feature != p.registration() || b.PolicyVersion != s.source.config.Core.PolicyVersion || b.Admission.CommandID == "" || b.Admission.FingerprintKeyVersion == 0 || b.IntentDigest == ([32]byte{}) {
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
	return envelope.NewContext(map[string]string{"profile": "organization-invitation-resend-input-v1", "binding": hex.EncodeToString(digest[:])})
}

func (p *invitationResendOperationInvocation) decodeInput(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (out invitationResendOperationInput, err error) {
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
	var original invitationResendOperationInput
	var trailing any
	if decoder.Decode(&original) != nil || decoder.Decode(&trailing) != io.EOF {
		return out, organization.ErrUnavailable
	}
	binding := original.Spec.Binding
	if original.Schema != 1 || original.Spec.Operation != organization.InvitationResend.Descriptor() || binding.ValidateFor(organization.InvitationResend.Descriptor()) != nil || binding.CommandID != b.Admission.CommandID || binding.TenantID != b.Scope.TenantID || binding.ActorID != b.Scope.ActorID || binding.ActorKind != b.Scope.ActorKind || binding.OperationID != b.Scope.RouteID || binding.PolicyID != p.state.source.config.Core.PolicyID || binding.PolicyVersion != b.PolicyVersion || !scope(string(original.OrganizationID)) || original.OrganizationVersion == 0 || original.InvitationVersion == 0 || original.InvitationVersion >= ^uint64(0)-1 || !scope(string(original.CreatedBy)) || original.RecipientUser.ID != binding.UserID || original.RecipientUser.Validate(binding.TenantID) != nil || original.RecipientUser.Status != identity.StatusActive || original.RecipientIdentifier.Validate(binding.UserID) != nil || original.RecipientIdentifier.Kind != identity.IdentifierEmail || !original.RecipientIdentifier.Verified || original.SessionUntil.IsZero() || original.InvitationUntil.IsZero() {
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
	fields := make(map[string]identity.FeatureValue, len(original.Spec.Fields))
	for _, field := range original.Spec.Fields {
		fields[field.Name] = field.Value
	}
	for name, expected := range map[string]identity.FeatureValue{
		"organization.id":                           {Kind: identity.FeatureText, Text: string(original.OrganizationID)},
		"organization.version":                      {Kind: identity.FeatureUint64, Uint64: original.OrganizationVersion},
		"organization.role":                         {Kind: identity.FeatureText, Text: string(organization.RoleMember)},
		"organization.invitation-version":           {Kind: identity.FeatureUint64, Uint64: original.InvitationVersion},
		"organization.invitation-issued-version":    {Kind: identity.FeatureUint64, Uint64: original.InvitationVersion},
		"organization.invitation-recipient":         {Kind: identity.FeatureText, Text: string(binding.UserID)},
		"organization.invitation-created-by":        {Kind: identity.FeatureText, Text: string(original.CreatedBy)},
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

func (p *invitationResendOperationInvocation) RestoreRequestKey(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, error) {
	original, err := p.decodeInput(ctx, b, wire)
	return original.Spec.Binding, err
}

func (p *invitationResendOperationInvocation) RestoreRequestKeyExpiry(ctx context.Context, b kernel.RequestKeyPreparationBinding, wire []byte) (identity.CommandBinding, time.Time, error) {
	original, err := p.decodeInput(ctx, b, wire)
	return original.Spec.Binding, original.Deadline, err
}

func resendOperationCorrelation(original invitationResendOperationInput) organization.StoreResult {
	return organization.StoreResult{OrganizationID: original.OrganizationID, InvitationID: organization.ID(original.Spec.Binding.RecordID), MemberID: original.Spec.Binding.UserID, Receipt: identity.CommandResult{Binding: original.Spec.Binding, Feature: &identity.FeatureReceipt{Operation: organization.InvitationResend.Descriptor()}}}
}

func (p *invitationResendOperationInvocation) recoverOriginal(ctx context.Context, a organization.Authentication, original invitationResendOperationInput) (out organization.InvitationResendOperationResult, err error) {
	s, b := p.state.source, original.Spec.Binding
	if a.TenantID != b.TenantID {
		return out, organization.ErrForbidden
	}
	observed, credential, err := s.observeInvitationRecovery(ctx, a, b.ActorID)
	if err != nil {
		return out, err
	}
	view, err := s.core.Get(ctx, organization.ReadRequest{Authentication: a, OrganizationID: original.OrganizationID, CorrelationID: b.CorrelationID})
	if err != nil {
		return out, err
	}
	if view.Actor.Role != organization.RoleOwner && view.Actor.Role != organization.RoleAdministrator {
		return out, organization.ErrForbidden
	}
	current, err := s.repository.ReadInvitation(ctx, organization.InvitationQuery{Operation: organization.InvitationResend, TenantID: b.TenantID, ActorID: identity.UserID(b.ActorID), OrganizationID: original.OrganizationID, InvitationID: organization.ID(b.RecordID)})
	if err != nil {
		return out, err
	}
	i := current.Record.Invitation
	if current.Organization != view.Organization || current.Actor != view.Actor || i.RecipientUserID != b.UserID || i.RecipientIdentifierID != original.RecipientIdentifier.ID || i.RecipientIdentifierVersion != original.RecipientIdentifier.Version || i.CreatedBy != original.CreatedBy || i.Role != organization.RoleMember || !i.ExpiresAt.Equal(original.InvitationUntil) || current.RecipientUser.Status != identity.StatusActive || current.RecipientIdentifier != original.RecipientIdentifier {
		return out, organization.ErrForbidden
	}
	actorBinding := b
	actorBinding.RecordID = string(original.OrganizationID)
	admission := &recoveryInput{binding: actorBinding, observed: observed, credential: credential, organization: view.Organization, member: view.Actor}
	caller := authorization.DecisionContext{PolicyRevision: authorization.Revision(s.config.Core.PolicyVersion), CorrelationID: b.CorrelationID, Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{Kind: b.ActorKind, ID: authorization.SubjectID(b.ActorID)}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "organization", ID: authorization.ResourceID(original.OrganizationID), Attributes: authorization.Attributes{"organization.policy-version": authorization.StringValue(strconv.FormatUint(view.Organization.Version, 10))}}, Environment: authorization.Environment{Time: s.config.Core.Clock.Now()}}}
	decision, err := s.config.Authorization.Decide(ctx, caller)
	if err != nil {
		return out, organization.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != caller.PolicyRevision {
		return out, organization.ErrForbidden
	}
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
	p.recoveryOrganization = original.OrganizationID
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	receipt, recoveryErr := p.coordinator.ExpirePreparedFeatureCommand(ctx, query, caller, p.registration(), p)
	native := Service{participant: s.actor, config: ServiceConfig{Core: s.config.Core, Sessions: s.config.Sessions}}
	if err := native.revalidateRecovery(ctx, admission); err != nil {
		return out, err
	}
	recipient, err := s.repository.resolveRecipient(ctx, b.TenantID, b.UserID, original.RecipientIdentifier.ID)
	if err != nil {
		return out, err
	}
	if recipient.User != current.RecipientUser || recipient.Identifier != current.RecipientIdentifier || observed.ValidateAt(s.config.Core.Clock.Now()) != nil {
		return out, organization.ErrForbidden
	}
	if receipt.Binding != b {
		if recoveryErr != nil && receipt.Binding == (identity.CommandBinding{}) {
			return out, invitationPublicError(recoveryErr)
		}
		return out, organization.ErrUnavailable
	}
	out.StoreResult = resendOperationCorrelation(original)
	out.Receipt = receipt
	if recoveryErr != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, invitationPublicError(recoveryErr)
	}
	result, err := s.resendDelivery(ctx, a, InvitationRecovery{Binding: b, OrganizationID: original.OrganizationID}, out.StoreResult)
	return p.finalizeResult(ctx, recipient, result, err)
}
