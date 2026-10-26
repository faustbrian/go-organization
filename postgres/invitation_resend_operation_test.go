package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

type keyedResender interface {
	Resend(context.Context, organization.InvitationResendOperationRequest, string) (organization.InvitationResendOperationResult, error)
}

func resendOperationCodec(t testing.TB) (*invitationResendOperationInvocation, kernel.RequestKeyPreparationBinding, invitationResendOperationInput) {
	t.Helper()
	send, b, before, _ := invitationOperationCodec(t)
	p := &invitationResendOperationInvocation{state: send.state, invitationPhase: &invitationPhase{}}
	b.Scope.RouteID, b.Feature = string(organization.InvitationResend), p.registration()
	before.Spec.Binding.OperationID = string(organization.InvitationResend)
	before.Spec.Binding.SchemaID = organization.InvitationResend.Descriptor().SchemaID
	original := invitationResendOperationInput{Schema: 1, Spec: before.Spec, OrganizationID: before.OrganizationID, OrganizationVersion: ^uint64(0), InvitationVersion: 3, RecipientUser: before.RecipientUser, RecipientIdentifier: before.RecipientIdentifier, CreatedBy: "owner", SessionUntil: before.SessionUntil, InvitationUntil: before.InvitationUntil, Deadline: before.Deadline}
	original.Spec.Operation = organization.InvitationResend.Descriptor()
	original.Spec.Fields = []identity.FeatureField{text("id", string(original.OrganizationID)), number("version", original.OrganizationVersion), text("role", string(organization.RoleMember)), number("invitation-version", original.InvitationVersion), number("invitation-issued-version", original.InvitationVersion), text("invitation-recipient", string(original.RecipientUser.ID)), text("invitation-created-by", string(original.CreatedBy)), text("recipient-identifier", string(original.RecipientIdentifier.ID)), number("recipient-identifier-version", original.RecipientIdentifier.Version), text("session-until", original.SessionUntil.UTC().Format(time.RFC3339Nano)), {Name: "organization.invitation-expires-at", Value: identity.FeatureValue{Kind: identity.FeatureTime, Time: original.InvitationUntil}}}
	return p, b, original
}

func sealResendOperation(t testing.TB, p *invitationResendOperationInvocation, b kernel.RequestKeyPreparationBinding, plain []byte) []byte {
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

func TestInvitationResendOperationIntentRetainsExactRequest(t *testing.T) {
	p, _, _ := resendOperationCodec(t)
	r := organization.InvitationResendOperationRequest{OrganizationID: "organization", InvitationID: "invitation", OrganizationVersion: ^uint64(0), InvitationVersion: 3, CorrelationID: "original"}
	intent, err := identity.NewRequestIntent(resendOperationFields(r, p.state))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := intent.Fields()
	for name, change := range map[string]func(*organization.InvitationResendOperationRequest){
		"organization":         func(r *organization.InvitationResendOperationRequest) { r.OrganizationID = "other" },
		"invitation":           func(r *organization.InvitationResendOperationRequest) { r.InvitationID = "other" },
		"organization-version": func(r *organization.InvitationResendOperationRequest) { r.OrganizationVersion-- },
		"invitation-version":   func(r *organization.InvitationResendOperationRequest) { r.InvitationVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			other, err := identity.NewRequestIntent(resendOperationFields(changed, p.state))
			if err != nil {
				t.Fatal(err)
			}
			got, _ := other.Fields()
			if reflect.DeepEqual(got, want) {
				t.Fatal("changed resend intent discarded")
			}
		})
	}
	r.CorrelationID = "retry"
	other, err := identity.NewRequestIntent(resendOperationFields(r, p.state))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := other.Fields()
	if !reflect.DeepEqual(got, want) {
		t.Fatal("diagnostic correlation changed initiating identity")
	}
	for _, change := range []func(*invitationOperationState){func(s *invitationOperationState) { s.config.ConfigurationID += "x" }, func(s *invitationOperationState) { s.profile[0]++ }} {
		copy := *p.state
		change(&copy)
		other, err := identity.NewRequestIntent(resendOperationFields(r, &copy))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := other.Fields()
		if reflect.DeepEqual(got, want) {
			t.Fatal("changed resend configuration discarded")
		}
	}
}

func TestInvitationResendOperationCodecPreservesOriginalOnly(t *testing.T) {
	p, b, original := resendOperationCodec(t)
	plain, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	wire := sealResendOperation(t, p, b, plain)
	got, until, err := p.RestoreRequestKeyExpiry(t.Context(), b, wire)
	if err != nil || got != original.Spec.Binding || !until.Equal(original.Deadline) {
		t.Fatal("original resend binding/deadline changed", err)
	}
	if got, err := p.RestoreRequestKey(t.Context(), b, wire); err != nil || got != original.Spec.Binding {
		t.Fatal("original resend correlation not restored", err)
	}
	for name, mutate := range map[string]func(*kernel.RequestKeyPreparationBinding){
		"namespace":   func(b *kernel.RequestKeyPreparationBinding) { b.Namespace += "x" },
		"actor":       func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorID += "x" },
		"tenant":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.TenantID += "x" },
		"kind":        func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorKind = "other" },
		"method":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.Method = "PUT" },
		"route":       func(b *kernel.RequestKeyPreparationBinding) { b.Scope.RouteID = string(organization.InvitationSend) },
		"command":     func(b *kernel.RequestKeyPreparationBinding) { b.Admission.CommandID += "x" },
		"fingerprint": func(b *kernel.RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		"registration": func(b *kernel.RequestKeyPreparationBinding) {
			b.Feature.Operation = organization.InvitationSend.Descriptor()
		},
		"policy": func(b *kernel.RequestKeyPreparationBinding) { b.PolicyVersion++ },
		"intent": func(b *kernel.RequestKeyPreparationBinding) { b.IntentDigest[0]++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			mutate(&changed)
			got, until, err := p.RestoreRequestKeyExpiry(t.Context(), changed, wire)
			if err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
				t.Fatal("rebound resend custody disclosed original metadata")
			}
		})
	}
	send, sendBinding, sendOriginal, sealSend := invitationOperationCodec(t)
	legacy, err := json.Marshal(sendOriginal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.RestoreRequestKey(t.Context(), b, sealSend(legacy)); err == nil {
		t.Fatal("resend decoder enrolled legacy Send ciphertext")
	}
	if _, err := send.RestoreRequestKey(t.Context(), sendBinding, wire); err == nil {
		t.Fatal("legacy Send decoder enrolled resend ciphertext")
	}
}

func TestInvitationResendOperationCodecRejectsContradictoryOriginal(t *testing.T) {
	for name, mutate := range map[string]func(*invitationResendOperationInput){
		"schema":               func(o *invitationResendOperationInput) { o.Schema++ },
		"operation":            func(o *invitationResendOperationInput) { o.Spec.Operation = organization.InvitationSend.Descriptor() },
		"binding":              func(o *invitationResendOperationInput) { o.Spec.Binding.UserID += "x" },
		"organization":         func(o *invitationResendOperationInput) { o.OrganizationID += "x" },
		"organization-version": func(o *invitationResendOperationInput) { o.OrganizationVersion-- },
		"invitation-version":   func(o *invitationResendOperationInput) { o.InvitationVersion++ },
		"overflow-version":     func(o *invitationResendOperationInput) { o.InvitationVersion = ^uint64(0) - 1 },
		"creator":              func(o *invitationResendOperationInput) { o.CreatedBy += "x" },
		"recipient":            func(o *invitationResendOperationInput) { o.RecipientUser.ID += "x" },
		"identifier":           func(o *invitationResendOperationInput) { o.RecipientIdentifier.Version++ },
		"verified":             func(o *invitationResendOperationInput) { o.RecipientIdentifier.Verified = false },
		"session":              func(o *invitationResendOperationInput) { o.SessionUntil = o.SessionUntil.Add(time.Second) },
		"expiry":               func(o *invitationResendOperationInput) { o.InvitationUntil = o.InvitationUntil.Add(time.Second) },
		"deadline":             func(o *invitationResendOperationInput) { o.Deadline = o.Deadline.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			p, b, original := resendOperationCodec(t)
			mutate(&original)
			plain, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			got, until, err := p.RestoreRequestKeyExpiry(t.Context(), b, sealResendOperation(t, p, b, plain))
			if err == nil || got != (identity.CommandBinding{}) || !until.IsZero() {
				t.Fatal("contradictory resend original accepted")
			}
		})
	}
	p, b, original := resendOperationCodec(t)
	plain, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(`{}`), append(append([]byte(nil), plain...), []byte(` {}`)...), append([]byte(`{"unknown":true,`), plain[1:]...)} {
		if _, err := p.RestoreRequestKey(t.Context(), b, sealResendOperation(t, p, b, bad)); err == nil {
			t.Fatal("malformed authenticated resend custody accepted")
		}
	}
	for _, bad := range [][]byte{nil, []byte("bad-envelope"), make([]byte, maximumInvitationOperationInput*3/2+1)} {
		if _, err := p.RestoreRequestKey(t.Context(), b, bad); err == nil {
			t.Fatal("hostile resend envelope accepted")
		}
	}
}

func TestInvitationResendOperationProjectionPreservesKnownCommit(t *testing.T) {
	_, _, original := resendOperationCodec(t)
	known := resendOperationCorrelation(original)
	known.Receipt.Outcome = identity.CommitOutcomeCommitted
	result := InvitationResendResult{StoreResult: known, Delivery: &InvitationDeliveryStatus{EffectID: "must-not-project-effect", State: delivery.StateQueued}}
	for _, failure := range []error{nil, organization.ErrUnavailable} {
		out := resendOperationResult(result, failure)
		if !reflect.DeepEqual(out.StoreResult, known) || failure == nil && out.DeliveryState != delivery.StateQueued || failure != nil && out.DeliveryState != 0 {
			t.Fatal("delivery-status failure erased known commit or invented observation")
		}
		wire, err := json.Marshal(out)
		if err != nil || strings.Contains(string(wire), "must-not-project-effect") {
			t.Fatal("neutral resend projection disclosed effect identity")
		}
	}
	result.Receipt.Outcome = identity.CommitOutcomeUnknown
	if out := resendOperationResult(result, nil); out.DeliveryState != 0 || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("unknown resend invented authorized delivery")
	}
}

func FuzzInvitationResendOperationEnvelope(f *testing.F) {
	p, b, original := resendOperationCodec(f)
	plain, err := json.Marshal(original)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealResendOperation(f, p, b, plain))
	f.Add([]byte("invalid"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		out, err := p.decodeInput(t.Context(), b, wire)
		if err == nil && !reflect.DeepEqual(out, original) || err != nil && out.Spec.Binding != (identity.CommandBinding{}) {
			t.Fatal("hostile resend custody changed original correlation")
		}
	})
}

func TestInvitationResendOperationRequiresNativeCustody(t *testing.T) {
	for _, service := range []*InvitationOperationService{nil, {}} {
		resender, ok := any(service).(keyedResender)
		if !ok {
			t.Fatal("native original-key resend operation is missing")
		}
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := resender.Resend(ctx, organization.InvitationResendOperationRequest{}, "127.0.0.1")
			if !errors.Is(err, organization.ErrInvalidInput) || out != (organization.InvitationResendOperationResult{}) {
				t.Fatal("missing native resend custody manufactured authority")
			}
		}
	}
}
