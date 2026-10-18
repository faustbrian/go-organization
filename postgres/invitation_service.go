package postgres

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// InvitationDeliveryConfig borrows actual encrypted delivery/status owners and
// selects their exact retained provider/policy/template profile. Policy dedupe
// must cover invitation lifetime+24h. Endpoint is an HTTPS origin/path with no
// query, userinfo or fragment; the sole token parameter is generated privately.
// LocaleChain is copied. No sender or provider call occurs before commitment.
type InvitationDeliveryConfig struct {
	Owner                          *deliverypg.Contributor
	Status                         *deliverypg.EnqueueService
	Renderer                       *delivery.TemplateRenderer
	Policy                         delivery.Config
	PolicyVersion, ProviderVersion uint64
	// StatusPolicyVersion is EnqueueConfig.PolicyVersion (authorization), not
	// the provider's retained delivery Config profile selected by PolicyVersion.
	StatusPolicyVersion uint64
	TemplateID          string
	TemplateVersion     uint32
	LocaleChain         []string
	Endpoint            string
	ScopeKey            [32]byte
}

// InvitationServiceConfig selects the finite genuine-password-session profile.
// Coordinator is the existing kernel's configuration, not an application UOW;
// each immutable prepared invocation enlists its native phase in that sole
// kernel with actual capability, audit, risk and paired-lifecycle owners.
// Session/issuer/envelope keys and borrowed owners must outlive pending work.
// Install membership, invitation-read and invitation-capability migrations plus
// all selected shared owner migrations before invoking this service.
type InvitationServiceConfig struct {
	Core          organization.Config
	Invitation    organization.InvitationConfig
	Admission     ContributorConfig
	Sessions      *session.SessionService
	Authorization authorization.Service
	Coordinator   kernel.CoordinatorConfig
	Risk          *riskpg.Repository
	Issuer        issuerpg.IssuerConfig
	Preparation   issuerpg.IssuancePreparationConfig
	Delivery      InvitationDeliveryConfig
}

func (InvitationServiceConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.InvitationServiceConfig(redacted)"))
}
func (InvitationServiceConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationServiceConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// InvitationService owns native send/accept composition, never another token
// engine, journal, provider or authentication authority. It starts no goroutine.
// Configuration is immutable; independent preparations may run concurrently,
// while each PreparedInvitation is serial-use and preserves original custody.
type InvitationService struct {
	core       *organization.Service
	root       *organization.InvitationService
	repository *InvitationRepository
	actor      *Contributor
	issuer     *issuerpg.Issuer
	codec      *issuerpg.IssuancePreparationCodec
	crypto     *secretenvelope.Service
	config     InvitationServiceConfig
}

// NewInvitationService validates the exact owned graph without SQL or signing.
// It borrows the primary, session/policy/risk/delivery owners and creates only
// the existing native owners' immutable cryptographic composition.
func NewInvitationService(repository *Repository, c InvitationServiceConfig) (*InvitationService, error) {
	if len(c.Coordinator.RetainedFingerprintKeys) < 1 || len(c.Coordinator.RetainedFingerprintKeys) > 32 || c.Coordinator.QueryPolicy == nil || c.Coordinator.AdmissionPolicy == nil {
		return nil, organization.ErrInvalidInput
	}
	if repository == nil || c.Sessions == nil || c.Authorization == nil || c.Risk == nil || c.Delivery.Owner == nil || c.Delivery.Status == nil || c.Delivery.Renderer == nil || c.Delivery.ScopeKey == ([32]byte{}) || c.Delivery.Policy.Validate() != nil || c.Delivery.Policy.DedupeTTL < c.Invitation.Lifetime+24*time.Hour || c.Issuer.Audience != c.Invitation.Audience || c.Issuer.Crypto.Limits.MaxLifetime < c.Invitation.Lifetime || c.Delivery.PolicyVersion == 0 || c.Delivery.ProviderVersion == 0 || c.Delivery.StatusPolicyVersion == 0 || !scope(c.Delivery.TemplateID) || c.Delivery.TemplateVersion == 0 || len(c.Delivery.LocaleChain) < 1 || len(c.Delivery.LocaleChain) > 8 {
		return nil, organization.ErrInvalidInput
	}
	u, err := url.Parse(c.Delivery.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(c.Delivery.Endpoint) > 1024 {
		return nil, organization.ErrInvalidInput
	}
	for _, locale := range c.Delivery.LocaleChain {
		if !scope(locale) {
			return nil, organization.ErrInvalidInput
		}
	}
	if c.Core.PolicyID != c.Admission.PolicyID || c.Core.PolicyVersion != c.Admission.PolicyVersion || c.Core.MaximumMembers != c.Admission.MaximumMembers || c.Core.MaximumPerUser != c.Admission.MaximumPerUser || c.Core.MaximumPerTenant != c.Admission.MaximumPerTenant {
		return nil, organization.ErrInvalidInput
	}
	actor, err := NewContributor(repository, c.Admission)
	if err != nil {
		return nil, err
	}
	issuer, err := issuerpg.NewIssuer(c.Issuer)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	codec, err := issuerpg.NewIssuancePreparationCodec(issuer, c.Preparation)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	provider, err := keyring.New(c.Preparation.EnvelopeKeys)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	crypto, err := secretenvelope.NewService(provider)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	verifier, err := capability.NewService(c.Issuer.Crypto)
	if err != nil {
		return nil, organization.ErrInvalidInput
	}
	read, err := NewInvitationRepository(repository, c.Delivery.Status, InvitationRepositoryConfig{DeliveryPolicyVersion: c.Delivery.StatusPolicyVersion})
	if err != nil {
		return nil, err
	}
	base, err := organization.NewService(c.Sessions, repository, c.Authorization, c.Core)
	if err != nil {
		return nil, err
	}
	root, err := organization.NewInvitationService(base, read, verifier, c.Invitation)
	if err != nil {
		return nil, err
	}
	c.Admission = actor.config
	c.Delivery.LocaleChain = slices.Clone(c.Delivery.LocaleChain)
	c.Coordinator.RetainedFingerprintKeys = cloneInvitationFingerprintKeys(c.Coordinator.RetainedFingerprintKeys)
	if c.Coordinator.QueryPolicy != nil {
		copy := *c.Coordinator.QueryPolicy
		c.Coordinator.QueryPolicy = &copy
	}
	if c.Coordinator.AdmissionPolicy != nil {
		copy := *c.Coordinator.AdmissionPolicy
		c.Coordinator.AdmissionPolicy = &copy
	}
	// The owners above snapshot secret maps; the service retains no caller map
	// aliases or second mutable key authority after construction.
	c.Issuer.RetainedReplayKeys = nil
	c.Preparation.EnvelopeKeys = nil
	c.Preparation.VerificationKeys = nil
	return &InvitationService{core: base, root: root, repository: read, actor: actor, issuer: issuer, codec: codec, crypto: crypto, config: c}, nil
}

func cloneInvitationFingerprintKeys(in map[uint32][32]byte) map[uint32][32]byte {
	out := make(map[uint32][32]byte, len(in))
	for version, key := range in {
		out[version] = key
	}
	return out
}

func (InvitationDeliveryConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.InvitationDeliveryConfig(redacted)"))
}
func (InvitationDeliveryConfig) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationDeliveryConfig) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.InvitationService(redacted)"))
}
func (InvitationService) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (InvitationService) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// PreparedInvitation retains one exact native invocation. Copies share its
// original one-transfer generation custody; do not execute copies concurrently.
// Retry this value unchanged after known retryable outcomes; unknown commits
// require its safe Recovery scope, never a new ID or replacement proof.
type PreparedInvitation struct{ state *invitationPhase }

func (PreparedInvitation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("organization.postgres.PreparedInvitation(redacted)"))
}
func (PreparedInvitation) MarshalJSON() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}
func (PreparedInvitation) MarshalText() ([]byte, error) {
	return nil, organization.ErrSensitiveSerialization
}

// PrepareSend freezes the genuine owner and exact existing verified recipient.
// Signing and encrypted delivery generation occur only in acknowledged native
// protected preparation when Execute is called, never in this method.
func (s *InvitationService) PrepareSend(ctx context.Context, r organization.InvitationSendRequest, network string) (PreparedInvitation, error) {
	if s == nil {
		return PreparedInvitation{}, organization.ErrInvalidInput
	}
	c, err := s.root.PrepareSend(ctx, r)
	if err != nil {
		return PreparedInvitation{}, err
	}
	return s.prepare(ctx, c, network)
}

// PrepareAccept verifies the original retained issued envelope and replay-key
// identity, not a fingerprint inferred from presented proof. It does not consume
// or grant membership; the sole native transaction owns those effects.
func (s *InvitationService) PrepareAccept(ctx context.Context, r organization.InvitationAcceptRequest, network string) (PreparedInvitation, error) {
	if s == nil {
		return PreparedInvitation{}, organization.ErrInvalidInput
	}
	c, err := s.root.PrepareAccept(ctx, r)
	if err != nil {
		return PreparedInvitation{}, err
	}
	return s.prepare(ctx, c, network)
}

func (s *InvitationService) prepare(ctx context.Context, c organization.Command, network string) (PreparedInvitation, error) {
	if ctx == nil {
		return PreparedInvitation{}, organization.ErrInvalidInput
	}
	bounded, cancel := context.WithTimeout(ctx, s.config.Core.MaximumDuration)
	defer cancel()
	x, err := c.Input()
	if err != nil {
		return PreparedInvitation{}, err
	}
	p := &invitationPhase{service: s, root: c, input: x}
	if err = p.mapCommand(); err != nil {
		return PreparedInvitation{}, invitationPublicError(err)
	}
	var at time.Time
	if err = s.actor.repository.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return PreparedInvitation{}, storageError(bounded, err)
	}
	p.command, p.counters, err = s.config.Risk.PrepareCommandCounters(p.command, risk.Subject{Actor: string(x.Binding.ActorID), Resource: x.Binding.RecordID, Network: network}, at.UTC())
	if err != nil {
		return PreparedInvitation{}, organization.ErrForbidden
	}
	p.occurred = at.UTC()
	p.recipient, err = s.repository.resolveRecipient(bounded, x.Binding.TenantID, x.Binding.UserID, x.Invitation.Record.RecipientIdentifierID)
	if err != nil {
		return PreparedInvitation{}, err
	}
	if p.recipient.User != x.TargetUser || p.recipient.Identifier != x.Invitation.RecipientIdentifier {
		return PreparedInvitation{}, organization.ErrConflict
	}
	if x.Operation == organization.InvitationAccept {
		if err = p.loadCapability(bounded); err != nil {
			return PreparedInvitation{}, invitationPublicError(err)
		}
	}
	if err = p.compose(); err != nil {
		return PreparedInvitation{}, invitationPublicError(err)
	}
	return PreparedInvitation{state: p}, nil
}

// Execute preserves original expiry and opaque command identity. It exposes
// only metadata even on successful replay; no capability is redelivered.
func (s *InvitationService) Execute(ctx context.Context, p PreparedInvitation) (organization.StoreResult, error) {
	if s == nil || ctx == nil || p.state == nil || p.state.service != s {
		return organization.StoreResult{}, organization.ErrInvalidInput
	}
	return s.core.Execute(ctx, p.state.root, p.state)
}

func (s *InvitationService) Get(ctx context.Context, r organization.InvitationReadRequest) (organization.InvitationDelivery, error) {
	if s == nil {
		return organization.InvitationDelivery{}, organization.ErrInvalidInput
	}
	return s.root.Get(ctx, r)
}
func (s *InvitationService) List(ctx context.Context, r organization.InvitationReadRequest) (organization.InvitationPage, error) {
	if s == nil {
		return organization.InvitationPage{}, organization.ErrInvalidInput
	}
	return s.root.List(ctx, r)
}
