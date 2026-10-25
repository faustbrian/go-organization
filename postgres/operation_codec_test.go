package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func operationCodecFixture(t testing.TB) (*operationInvocation, kernel.RequestKeyPreparationBinding, identity.CommandBinding) {
	t.Helper()
	custody, err := NewOperationCustodyConfig("current", map[string][]byte{"current": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := keyring.New(custody.keys())
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p := &operationInvocation{op: organization.Create, service: &Service{participant: new(Contributor)}, state: &operationServiceState{source: &Service{config: ServiceConfig{Core: organization.Config{PolicyID: "selected-policy", PolicyVersion: 9}}}, crypto: crypto, config: OperationServiceConfig{ConfigurationID: "selected-config", Custody: custody, RequestKeys: kernel.RequestKeyConfig{Namespace: "operation-codec", Policy: kernel.CommandQueryPolicy{PolicyVersion: 9}}}}}
	b := kernel.RequestKeyPreparationBinding{Namespace: "operation-codec", Scope: kernel.RequestKeyScope{TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectUser, Method: "POST", RouteID: string(organization.Create)}, Admission: kernel.RequestKeyAdmission{CommandID: id, FingerprintKeyVersion: 1}, Feature: kernel.FeatureRegistration{Contributor: p.service.participant.Descriptor(), Operation: organization.Create.Descriptor()}, PolicyVersion: 9, IntentDigest: [32]byte{1}}
	original := identity.CommandBinding{CommandID: id, TenantID: "tenant", ActorID: "actor", ActorKind: authorization.SubjectUser, UserID: "actor", RecordID: "organization", OperationID: string(organization.Create), PolicyID: "selected-policy", PolicyVersion: 9, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "original"}
	if original.ValidateFor(organization.Create.Descriptor()) != nil {
		t.Fatal("invalid fixture binding")
	}
	return p, b, original
}

func sealOperationFixture(t testing.TB, p *operationInvocation, b kernel.RequestKeyPreparationBinding, plain []byte) []byte {
	t.Helper()
	aad, err := p.inputContext(b)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := p.state.crypto.Encrypt(context.Background(), envelope.EncryptRequest{Plaintext: plain, KeyReference: "current", Context: aad})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := sealed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestOperationCodecPreservesOnlyExactOriginalBinding(t *testing.T) {
	p, b, original := operationCodecFixture(t)
	plain, err := json.Marshal(operationStoredBinding(original))
	if err != nil {
		t.Fatal(err)
	}
	wire := sealOperationFixture(t, p, b, plain)
	if got, err := p.restoreInput(t.Context(), b, wire); err != nil || got != original {
		t.Fatal("original correlation was not restored", err)
	}
	for name, mutate := range map[string]func(*kernel.RequestKeyPreparationBinding){
		"actor":       func(b *kernel.RequestKeyPreparationBinding) { b.Scope.ActorID = "other" },
		"tenant":      func(b *kernel.RequestKeyPreparationBinding) { b.Scope.TenantID = "other" },
		"command":     func(b *kernel.RequestKeyPreparationBinding) { b.Admission.CommandID, _ = identity.NewCommandID() },
		"intent":      func(b *kernel.RequestKeyPreparationBinding) { b.IntentDigest[1]++ },
		"fingerprint": func(b *kernel.RequestKeyPreparationBinding) { b.Admission.FingerprintKeyVersion++ },
		"policy":      func(b *kernel.RequestKeyPreparationBinding) { b.PolicyVersion++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := b
			mutate(&changed)
			if got, err := p.restoreInput(t.Context(), changed, wire); err == nil || got != (identity.CommandBinding{}) {
				t.Fatal("rebound original custody accepted")
			}
		})
	}
	p.state.config.ConfigurationID = "changed-config"
	if _, err := p.restoreInput(t.Context(), b, wire); err == nil {
		t.Fatal("changed selected configuration accepted")
	}
}

func TestOperationCodecRejectsMalformedAuthenticatedPayload(t *testing.T) {
	p, b, original := operationCodecFixture(t)
	plain, _ := json.Marshal(operationStoredBinding(original))
	changed := original
	changed.RecordID = ""
	invalid, _ := json.Marshal(operationStoredBinding(changed))
	for _, payload := range [][]byte{[]byte(`{}`), append(bytes.Clone(plain), []byte(` {}`)...), append([]byte(`{"unknown":true,`), plain[1:]...), invalid, bytes.Repeat([]byte{' '}, 4097)} {
		wire := sealOperationFixture(t, p, b, payload)
		if got, err := p.restoreInput(t.Context(), b, wire); !errors.Is(err, organization.ErrUnavailable) || got != (identity.CommandBinding{}) {
			t.Fatal("malformed authenticated binding escaped", err)
		}
	}
	for _, wire := range [][]byte{nil, []byte("malformed-envelope"), bytes.Repeat([]byte{'x'}, 16385)} {
		if _, err := p.restoreInput(t.Context(), b, wire); err == nil {
			t.Fatal("unbounded or malformed ciphertext accepted")
		}
	}
}

func TestOperationCustodyCopiesSourceAndProjectionKeys(t *testing.T) {
	material := bytes.Repeat([]byte{42}, 32)
	c, err := NewOperationCustodyConfig("current", map[string][]byte{"current": material})
	if err != nil {
		t.Fatal(err)
	}
	clear(material)
	one := c.keys()
	if one["current"][0] != 42 {
		t.Fatal("caller mutation changed retained encryption key")
	}
	clear(one["current"])
	if c.keys()["current"][0] != 42 {
		t.Fatal("projection mutation changed retained encryption key")
	}
}

func FuzzOperationEnvelopeRecovery(f *testing.F) {
	p, b, original := operationCodecFixture(f)
	plain, _ := json.Marshal(operationStoredBinding(original))
	f.Add(sealOperationFixture(f, p, b, plain), uint8(0))
	f.Add([]byte("invalid"), uint8(1))
	f.Add([]byte{}, uint8(2))
	f.Fuzz(func(t *testing.T, wire []byte, changed uint8) {
		if len(wire) > 32768 {
			return
		}
		binding := b
		if changed%2 != 0 {
			binding.IntentDigest[0] ^= 0x80
		}
		got, err := p.restoreInput(t.Context(), binding, wire)
		if err == nil && (got != original || changed%2 != 0) {
			t.Fatal("hostile ciphertext changed original correlation")
		}
		if err != nil && got != (identity.CommandBinding{}) {
			t.Fatal("failed codec retained partial correlation")
		}
	})
}
