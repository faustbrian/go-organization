package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestInvitationOperationRequiresActualNativeOwners(t *testing.T) {
	if s, err := NewInvitationOperationService(nil, InvitationOperationServiceConfig{}); s != nil || !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("missing native invitation owners admitted", err)
	}
	var s *InvitationOperationService
	if out, err := s.Send(t.Context(), organization.InvitationSendOperationRequest{}, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) || out.Receipt.Binding.CommandID != "" {
		t.Fatal("zero direct send manufactured authority", err)
	}
	for _, value := range []any{InvitationOperationService{}, InvitationOperationServiceConfig{ConfigurationID: "private-profile-marker"}} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("direct invitation custody serialized", err)
		}
		if text, ok := value.(interface{ MarshalText() ([]byte, error) }); !ok {
			t.Fatal("missing text custody boundary")
		} else if _, err := text.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("direct invitation custody exported as text", err)
		}
		if rendered := fmt.Sprintf("%#v", value); !strings.Contains(rendered, "redacted") || strings.Contains(rendered, "private-profile-marker") {
			t.Fatal("native invitation diagnostics leaked custody")
		}
	}
}

// Codec-only partition: there are deliberately no sessions, repository, risk,
// issuer, policy or ID allocator. Genuine authority and effects are exercised by
// the actual PostgreSQL consumer, not manufactured by this decoder fixture.
func invitationOperationCodec(t testing.TB) (*invitationOperationInvocation, kernel.RequestKeyPreparationBinding, invitationOperationInput, func([]byte) []byte) {
	t.Helper()
	provider, err := keyring.New(map[string][]byte{"synthetic-custody": bytes.Repeat([]byte{0x73}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	state := &invitationOperationState{source: &InvitationService{config: InvitationServiceConfig{Core: organization.Config{PolicyID: "organization", PolicyVersion: 9}}}, config: InvitationOperationServiceConfig{ConfigurationID: "original-send-v1", RequestKeys: kernel.RequestKeyConfig{Namespace: "original-send"}, Custody: OperationCustodyConfig{active: "synthetic-custody"}}, crypto: crypto, profile: [32]byte{1}}
	p := &invitationOperationInvocation{state: state, invitationPhase: &invitationPhase{}}
	binding := identity.CommandBinding{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant", UserID: "recipient", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationSend), PolicyID: "organization", PolicyVersion: 9, SchemaID: organization.InvitationSend.Descriptor().SchemaID, SchemaVersion: 1, RecordID: "invitation", CorrelationID: "original-send"}
	until := time.Date(2026, 1, 1, 0, 0, 20, 0, time.UTC)
	original := invitationOperationInput{Schema: 1, OrganizationID: "organization", OrganizationVersion: 1, RecipientUser: identity.User{ID: "recipient", TenantID: "tenant", Status: identity.StatusActive, Version: 1}, RecipientIdentifier: identity.Identifier{ID: "verified-identifier", UserID: "recipient", Kind: identity.IdentifierEmail, CanonicalValue: "recipient@example.invalid", Verified: true, Primary: true, Version: 1}, SessionUntil: until, InvitationUntil: until.Add(time.Hour), Deadline: until}
	original.Spec = identity.FeatureCommandSpec{Binding: binding, Operation: organization.InvitationSend.Descriptor(), Fields: []identity.FeatureField{text("id", string(original.OrganizationID)), number("version", original.OrganizationVersion), text("role", string(organization.RoleMember)), text("recipient-identifier", string(original.RecipientIdentifier.ID)), number("recipient-identifier-version", original.RecipientIdentifier.Version), text("session-until", original.SessionUntil.Format(time.RFC3339Nano)), {Name: "organization.invitation-expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: original.InvitationUntil}}}}
	b := kernel.RequestKeyPreparationBinding{Namespace: "original-send", Scope: kernel.RequestKeyScope{TenantID: "tenant", ActorID: "owner", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: string(organization.InvitationSend)}, Admission: kernel.RequestKeyAdmission{CommandID: binding.CommandID, FingerprintKeyVersion: 1}, Feature: p.registration(), PolicyVersion: 9, IntentDigest: [32]byte{2}}
	seal := func(plain []byte) []byte {
		t.Helper()
		return sealInvitationOperationInput(t, p, b, plain)
	}
	return p, b, original, seal
}

func sealInvitationOperationInput(t testing.TB, p *invitationOperationInvocation, b kernel.RequestKeyPreparationBinding, plain []byte) []byte {
	t.Helper()
	aad, err := p.inputContext(b)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := p.state.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: plain, KeyReference: "synthetic-custody", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestInvitationOperationRestoresOnlyExactAuthenticatedOriginal(t *testing.T) {
	p, b, original, seal := invitationOperationCodec(t)
	plain, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	wire := seal(plain)
	if got, err := p.RestoreRequestKey(t.Context(), b, wire); err != nil || got != original.Spec.Binding {
		t.Fatal("exact authenticated original binding not restored", err)
	}
	if got, until, err := p.RestoreRequestKeyExpiry(t.Context(), b, wire); err != nil || got != original.Spec.Binding || !until.Equal(original.Deadline) {
		t.Fatal("original earliest deadline changed", err)
	}
	for name, alter := range map[string]func(*kernel.RequestKeyPreparationBinding){
		"namespace":       func(b *kernel.RequestKeyPreparationBinding) { b.Namespace = "other" },
		"tenant":          func(b *kernel.RequestKeyPreparationBinding) { b.Scope.TenantID = "other" },
		"actor":           func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorID = "other" },
		"actor-kind":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorKind = authorization.SubjectServiceAccount },
		"method":          func(b *kernel.RequestKeyPreparationBinding) { b.Scope.Method = "PUT" },
		"route":           func(b *kernel.RequestKeyPreparationBinding) { b.Scope.RouteID = "other" },
		"command":         func(b *kernel.RequestKeyPreparationBinding) { b.Admission.CommandID = "AgICAgICAgICAgICAgICAg" },
		"fingerprint-key": func(b *kernel.RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		"feature":         func(b *kernel.RequestKeyPreparationBinding) { b.Feature.Contributor.Version++ },
		"policy":          func(b *kernel.RequestKeyPreparationBinding) { b.PolicyVersion++ },
		"intent":          func(b *kernel.RequestKeyPreparationBinding) { b.IntentDigest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			alter(&changed)
			got, until, err := p.RestoreRequestKeyExpiry(t.Context(), changed, wire)
			if err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
				t.Fatal("foreign custody disclosed original binding/deadline")
			}
		})
	}
	for _, mutation := range []func(*invitationOperationInput){
		func(o *invitationOperationInput) { o.Deadline = o.Deadline.Add(time.Second) },
		func(o *invitationOperationInput) {
			o.SessionUntil = o.SessionUntil.Add(time.Hour)
			o.Deadline = o.SessionUntil
		},
		func(o *invitationOperationInput) { o.InvitationUntil = o.InvitationUntil.Add(time.Hour) },
		func(o *invitationOperationInput) { o.RecipientIdentifier.Version++ },
		func(o *invitationOperationInput) { o.OrganizationVersion++ },
		func(o *invitationOperationInput) { o.Spec.Binding.UserID = "other" },
	} {
		changed := original
		mutation(&changed)
		plain, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		if got, until, err := p.RestoreRequestKeyExpiry(t.Context(), b, seal(plain)); err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
			t.Fatal("inconsistent authenticated original accepted")
		}
	}
	for _, plain := range [][]byte{[]byte("null"), []byte("{"), []byte(`{"Schema":18446744073709551616}`), append(bytes.Clone(plain), []byte(` {"extra":true}`)...), bytes.Repeat([]byte("x"), maximumInvitationOperationInput+1)} {
		if got, until, err := p.RestoreRequestKeyExpiry(t.Context(), b, seal(plain)); err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
			t.Fatal("malformed authenticated original accepted")
		}
	}
	for _, change := range []func(*invitationOperationState){func(s *invitationOperationState) { s.config.ConfigurationID = "replacement" }, func(s *invitationOperationState) { s.profile[0]++ }} {
		state := *p.state
		change(&state)
		decoder := *p
		decoder.state = &state
		if got, err := decoder.RestoreRequestKey(t.Context(), b, wire); err == nil || got != (identity.CommandBinding{}) {
			t.Fatal("replacement configuration authenticated original input")
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if got, until, err := p.RestoreRequestKeyExpiry(canceled, b, wire); err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
		t.Fatal("canceled decoding disclosed original")
	}
}

func FuzzInvitationOperationOriginalDecoder(f *testing.F) {
	p, b, original, seal := invitationOperationCodec(f)
	plain, err := json.Marshal(original)
	if err != nil {
		f.Fatal(err)
	}
	valid := seal(plain)
	for _, input := range [][]byte{nil, valid, plain, []byte("{"), []byte(`{"Schema":18446744073709551616}`), []byte("\xff"), bytes.Repeat([]byte("x"), maximumInvitationOperationInput+1)} {
		for mode := uint8(0); mode < 4; mode++ {
			f.Add(input, mode)
		}
	}
	f.Fuzz(func(t *testing.T, input []byte, mode uint8) {
		if len(input) > maximumInvitationOperationInput*3/2 {
			return
		}
		binding := b
		decoder := *p
		state := *p.state
		decoder.state = &state
		wire := input
		switch mode % 4 {
		case 1:
			if len(input) != 0 {
				wire = sealInvitationOperationInput(t, p, b, input)
				defer clear(wire)
			}
		case 2:
			binding.Scope.TenantID = "foreign"
		case 3:
			state.config.ConfigurationID = "replacement"
		}
		got, until, err := decoder.RestoreRequestKeyExpiry(t.Context(), binding, wire)
		if err != nil {
			if got != (identity.CommandBinding{}) || !until.IsZero() || !errors.Is(err, organization.ErrUnavailable) {
				t.Fatal("rejected original disclosed custody or unclassified error")
			}
			return
		}
		if mode%4 >= 2 || got.ValidateFor(organization.InvitationSend.Descriptor()) != nil || got.CommandID != b.Admission.CommandID || got.TenantID != b.Scope.TenantID || got.ActorID != b.Scope.ActorID || got.ActorKind != b.Scope.ActorKind || got.PolicyVersion != b.PolicyVersion || until.IsZero() {
			t.Fatal("decoder accepted foreign or inconsistent original input")
		}
	})
}
