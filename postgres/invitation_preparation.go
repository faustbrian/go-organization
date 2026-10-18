package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// The sole kernel's preparation_journal contract caps authenticated output at
// 1MiB. Leave 4KiB for the envelope around the bounded private JSON payload.
const maximumInvitationOutput = 1 << 20

type invitationExecution struct {
	issuance   issuerpg.PreparedIssuance
	delivery   deliverypg.PreparedDelivery
	digest     [32]byte
	generation uint64
}
type invitationAdmission struct{ phase *invitationPhase }

var _ kernel.FeatureAdmissionPreparationContributor = (*invitationPhase)(nil)

func (a *invitationAdmission) Check(ctx context.Context) error {
	if a == nil || a.phase == nil || ctx == nil {
		return identity.InvalidInputError{Field: "invitation"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	p := a.phase
	now := p.service.config.Core.Clock.Now()
	if p.input.Session.ValidateAt(now) != nil || !now.Before(p.input.Invitation.Record.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}
func (a *invitationAdmission) Generate(ctx context.Context, generation uint64) ([]byte, error) {
	if err := a.Check(ctx); err != nil {
		return nil, err
	}
	return a.phase.generate(ctx, generation)
}
func (p *invitationPhase) PrepareFeatureAdmission(ctx context.Context, c identity.Command) (kernel.FeaturePreparationAdmission, error) {
	if c != p.command || p.input.Operation != organization.InvitationSend {
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	a := &invitationAdmission{p}
	return a, a.Check(ctx)
}
func (p *invitationPhase) RestoreFeatureAdmission(ctx context.Context, c identity.Command, generation uint64, wire []byte) (kernel.FeaturePreparationAdmission, error) {
	if _, _, err := p.RestoreFeaturePreparation(ctx, c, generation, wire); err != nil {
		return nil, err
	}
	a := &invitationAdmission{p}
	return a, a.Check(ctx)
}
func (p *invitationPhase) ValidateFeaturePreparation(c identity.Command, plan kernel.CommandPlan) error {
	if p.input.Operation != organization.InvitationSend {
		return identity.InvalidInputError{Field: "invitation"}
	}
	return p.ValidateFeatureCommand(c, plan)
}
func (*invitationPhase) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, identity.InvalidInputError{Field: "invitation"}
}
func (p *invitationPhase) RestoreFeaturePreparation(ctx context.Context, c identity.Command, generation uint64, wire []byte) (identity.Command, kernel.CommandPlan, error) {
	if c != p.command || p.input.Operation != organization.InvitationSend {
		return identity.Command{}, kernel.CommandPlan{}, identity.InvalidInputError{Field: "invitation"}
	}
	if err := p.restore(ctx, generation, wire); err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	plan, err := p.plan(true)
	return c, plan, err
}

// These aliases are private encrypted-checkpoint wire shapes only. The public
// owners deliberately reject implicit export of trusted custody; neither this
// plaintext nor its fields are exposed as command metadata or stored unsealed.
type invitationStoredGrant kernel.CapabilityPlan
type invitationStoredQuery kernel.RecipientQuery
type invitationStoredRecipient struct {
	Query                                                                        invitationStoredQuery
	User                                                                         identity.User
	Identifier                                                                   identity.Identifier
	Verification                                                                 identity.Verification
	UserAuthorityVersion, IdentifierAuthorityVersion, CredentialAuthorityVersion uint64
	ObservedAt                                                                   time.Time
}

func storedInvitationRecipient(r kernel.RecipientRecord) invitationStoredRecipient {
	return invitationStoredRecipient{invitationStoredQuery(r.Query), r.User, r.Identifier, r.Verification, r.UserAuthorityVersion, r.IdentifierAuthorityVersion, r.CredentialAuthorityVersion, r.ObservedAt}
}
func (r invitationStoredRecipient) record() kernel.RecipientRecord {
	return kernel.RecipientRecord{Query: kernel.RecipientQuery(r.Query), User: r.User, Identifier: r.Identifier, Verification: r.Verification, UserAuthorityVersion: r.UserAuthorityVersion, IdentifierAuthorityVersion: r.IdentifierAuthorityVersion, CredentialAuthorityVersion: r.CredentialAuthorityVersion, ObservedAt: r.ObservedAt}
}

type invitationOutput struct {
	Schema                     uint32
	Spec                       identity.FeatureCommandSpec
	Recipient                  invitationStoredRecipient
	IssuanceContributor        kernel.ContributorDescriptor
	Grant                      invitationStoredGrant
	IssuanceWire, DeliveryWire []byte
}

func (p *invitationPhase) outputContext(generation uint64) (envelope.Context, error) {
	if generation == 0 {
		return envelope.Context{}, identity.InvalidInputError{Field: "invitation"}
	}
	frame, err := json.Marshal(struct {
		Binding                                  identity.CommandBinding
		Generation                               uint64
		Deployment, Audience, Endpoint, Template string
		TemplateVersion                          uint32
		Provider, Policy                         uint64
	}{p.input.Binding, generation, p.service.config.Preparation.Deployment, p.service.config.Invitation.Audience, p.service.config.Delivery.Endpoint, p.service.config.Delivery.TemplateID, p.service.config.Delivery.TemplateVersion, p.service.config.Delivery.ProviderVersion, p.service.config.Delivery.PolicyVersion})
	defer clear(frame)
	if err != nil {
		return envelope.Context{}, identity.InvalidInputError{Field: "invitation"}
	}
	digest := sha256.Sum256(frame)
	return envelope.NewContext(map[string]string{"profile": "organization-invitation-output-v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:])})
}
func (p *invitationPhase) generate(ctx context.Context, generation uint64) (out []byte, err error) {
	if ctx == nil || generation == 0 {
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	x := p.input
	b := x.Binding
	i := x.Invitation.Record
	now := p.occurred.UTC().Truncate(time.Second)
	payload := capability.Payload{Version: 1, Issuer: p.service.config.Issuer.Crypto.Issuer, Audiences: []string{p.service.config.Invitation.Audience}, Subject: string(b.UserID), Resource: b.RecordID, Operation: organization.InvitationAccept.Descriptor().OperationID, IssuedAt: now, NotBefore: now, ExpiresAt: i.ExpiresAt, Tenant: string(b.TenantID), CorrelationID: string(b.CommandID), MaxUses: 1, Caveats: map[string]string{"organization.id": string(i.OrganizationID), "organization.invitation-version": "1", "organization.role": "member", "organization.recipient-identifier": string(i.RecipientIdentifierID), "organization.recipient-identifier-version": strconv.FormatUint(i.RecipientIdentifierVersion, 10)}}
	issued, err := p.service.issuer.Prepare(ctx, b, []capability.Payload{payload})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = issued.TransferForDelivery(context.Background(), 0, func(context.Context, []byte) error { return nil })
		}
	}()
	plan, err := issued.Plan()
	if err != nil || len(plan.Grants) != 1 {
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	var deliveryWire []byte
	defer func() { clear(deliveryWire) }()
	issueWire, err := p.service.codec.CheckpointPreparation(ctx, issued, generation, func(ctx context.Context, index uint16, token []byte) error {
		if index != 0 || len(deliveryWire) != 0 {
			return identity.InvalidInputError{Field: "invitation"}
		}
		message, e := p.prepareDelivery(ctx, token)
		if e != nil {
			return e
		}
		deliveryWire, e = p.service.config.Delivery.Owner.CheckpointPreparation(ctx, message, generation)
		return e
	})
	defer clear(issueWire)
	if err != nil {
		return nil, err
	}
	if len(deliveryWire) == 0 {
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	spec, _ := p.command.Feature()
	stored := invitationOutput{Schema: 1, Spec: spec, Recipient: storedInvitationRecipient(p.recipient), IssuanceContributor: plan.Contributor, Grant: invitationStoredGrant(plan.Grants[0]), IssuanceWire: issueWire, DeliveryWire: deliveryWire}
	plain, err := json.Marshal(stored)
	defer clear(plain)
	if err != nil || len(plain) > maximumInvitationOutput-4096 {
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return nil, err
	}
	sealed, err := p.service.crypto.Encrypt(ctx, envelope.EncryptRequest{Plaintext: plain, KeyReference: p.service.config.Preparation.ActiveEnvelopeKey, Context: aad})
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	out, err = sealed.MarshalBinary()
	if err != nil || len(out) > maximumInvitationOutput {
		clear(out)
		return nil, identity.InvalidInputError{Field: "invitation"}
	}
	return out, nil
}
func (p *invitationPhase) restore(ctx context.Context, generation uint64, wire []byte) error {
	bad := func() error { return identity.InvalidInputError{Field: "invitation"} }
	if ctx == nil || len(wire) == 0 || len(wire) > maximumInvitationOutput {
		return bad()
	}
	aad, err := p.outputContext(generation)
	if err != nil {
		return err
	}
	sealed, err := envelope.ParseEnvelope(wire)
	if err != nil {
		return bad()
	}
	plain, err := p.service.crypto.Decrypt(ctx, envelope.DecryptRequest{Envelope: sealed, Context: aad})
	defer clear(plain)
	if err != nil || len(plain) > maximumInvitationOutput-4096 {
		return bad()
	}
	var stored invitationOutput
	defer func() { clear(stored.IssuanceWire); clear(stored.DeliveryWire) }()
	d := json.NewDecoder(bytes.NewReader(plain))
	d.DisallowUnknownFields()
	if d.Decode(&stored) != nil {
		return bad()
	}
	var extra any
	if d.Decode(&extra) != io.EOF || stored.Schema != 1 || len(stored.IssuanceWire) == 0 || len(stored.DeliveryWire) == 0 {
		return bad()
	}
	canonical, err := json.Marshal(stored)
	defer clear(canonical)
	if err != nil || !bytes.Equal(canonical, plain) {
		return bad()
	}
	spec, _ := p.command.Feature()
	expected, err := json.Marshal(spec)
	defer clear(expected)
	original, otherErr := json.Marshal(stored.Spec)
	defer clear(original)
	if err != nil || otherErr != nil || !bytes.Equal(expected, original) {
		return bad()
	}
	expectedRecipient, err := json.Marshal(storedInvitationRecipient(p.recipient))
	defer clear(expectedRecipient)
	originalRecipient, otherErr := json.Marshal(stored.Recipient)
	defer clear(originalRecipient)
	if err != nil || otherErr != nil || !bytes.Equal(expectedRecipient, originalRecipient) || stored.Recipient.record().Validate() != nil {
		return bad()
	}
	g := kernel.CapabilityPlan(stored.Grant)
	if string(g.Purpose) != organization.InvitationAccept.Descriptor().OperationID || !g.ExpiresAt.Equal(p.input.Invitation.Record.ExpiresAt) || g.MaxUses != 1 {
		return bad()
	}
	issued, err := p.service.codec.RestorePreparation(ctx, p.input.Binding, generation, kernel.CapabilityIssuancePlan{Contributor: stored.IssuanceContributor, Grants: []kernel.CapabilityPlan{g}}, stored.IssuanceWire)
	if err != nil {
		return err
	}
	message, err := p.service.config.Delivery.Owner.RestorePreparation(ctx, p.input.Binding, generation, stored.DeliveryWire)
	if err != nil {
		return err
	}
	plan, err := message.Plan()
	if err != nil || len(plan.Intents) != 1 || plan.Intents[0].SubjectID != string(p.input.Binding.UserID) || plan.Intents[0].Purpose != string(g.Purpose) || !plan.Intents[0].ExpiresAt.Equal(g.ExpiresAt) {
		return bad()
	}
	p.execution = &invitationExecution{issuance: issued, delivery: message, digest: invitationDigest(wire), generation: generation}
	return nil
}
func (p *invitationPhase) prepareDelivery(ctx context.Context, token []byte) (deliverypg.PreparedDelivery, error) {
	c := p.service.config.Delivery
	if len(token) == 0 || len(token) > 2048-len(c.Endpoint)-7 {
		return deliverypg.PreparedDelivery{}, identity.InvalidInputError{Field: "invitation"}
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return deliverypg.PreparedDelivery{}, identity.InvalidInputError{Field: "invitation"}
	}
	query := u.Query()
	query.Set("token", string(token))
	u.RawQuery = query.Encode()
	if len(u.String()) > 2048 {
		return deliverypg.PreparedDelivery{}, identity.InvalidInputError{Field: "invitation"}
	}
	frame, err := json.Marshal(struct {
		Binding             identity.CommandBinding
		Address, Identifier string
		Version             uint64
	}{p.input.Binding, p.recipient.Identifier.CanonicalValue, string(p.recipient.Identifier.ID), p.recipient.Identifier.Version})
	defer clear(frame)
	if err != nil {
		return deliverypg.PreparedDelivery{}, identity.InvalidInputError{Field: "invitation"}
	}
	mac := hmac.New(sha256.New, c.ScopeKey[:])
	_, _ = mac.Write([]byte("organization-invitation-recipient-v1\x00"))
	_, _ = mac.Write(frame)
	r := delivery.Recipient{Channel: delivery.ChannelEmail, Address: p.recipient.Identifier.CanonicalValue, ScopeDigest: hex.EncodeToString(mac.Sum(nil))}
	m := delivery.Message{Purpose: organization.InvitationAccept.Descriptor().OperationID, Channel: delivery.ChannelEmail, Recipient: r, TemplateID: c.TemplateID, TemplateVersion: uint64(c.TemplateVersion), LocaleChain: c.LocaleChain, Variables: []delivery.TemplateVariable{{Name: "link", Kind: "url", URLValue: u.String(), Sensitive: true}}}
	rendered, err := c.Renderer.Render(ctx, m)
	if err != nil {
		return deliverypg.PreparedDelivery{}, identity.InvalidInputError{Field: "invitation"}
	}
	return c.Owner.Prepare(ctx, p.input.Binding, []deliverypg.IntentInput{{Purpose: m.Purpose, SubjectID: string(p.input.Binding.UserID), TemplateID: c.TemplateID, TemplateVersion: c.TemplateVersion, ProviderConfigVersion: c.ProviderVersion, ExpiresAt: p.input.Invitation.Record.ExpiresAt, Recipient: r, Rendered: rendered}})
}
