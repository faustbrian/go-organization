package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

type admissionObserver struct{}

func (admissionObserver) ObserveDomain(context.Context, organization.DomainClaim) (organization.DomainObservation, error) {
	return organization.DomainObservation{}, organization.ErrForbidden
}

func TestDomainEvidenceAdmissionAuthenticatesEveryProofDimension(t *testing.T) {
	source, err := NewDomainEvidenceSource(admissionObserver{}, [32]byte{0x71})
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{TenantID: "tenant", RecordID: "org", CommandID: "command"}
	at := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	proof := organization.DomainProof{TenantID: "tenant", OrganizationID: "org", ClaimID: "claim", Domain: "example.com", ClaimVersion: 1, ProofVersion: 1, Method: organization.DomainDNS, ObservedAt: at, ExpiresAt: at.Add(time.Hour)}
	signature := source.seal(binding, proof)
	if !source.valid(binding, proof, signature) {
		t.Fatal("original admission rejected")
	}
	for _, mutate := range []func(*organization.DomainProof){func(p *organization.DomainProof) { p.TenantID = "other" }, func(p *organization.DomainProof) { p.OrganizationID = "other" }, func(p *organization.DomainProof) { p.ClaimID = "other" }, func(p *organization.DomainProof) { p.Domain = "other.example" }, func(p *organization.DomainProof) { p.ClaimVersion++ }, func(p *organization.DomainProof) { p.ProofVersion++ }, func(p *organization.DomainProof) { p.Method = organization.DomainHTTPS }, func(p *organization.DomainProof) { p.ObservedAt = p.ObservedAt.Add(time.Microsecond) }, func(p *organization.DomainProof) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) }, func(p *organization.DomainProof) { p.Revoked = true }} {
		changed := proof
		mutate(&changed)
		if source.valid(binding, changed, signature) {
			t.Fatal("changed proof dimension forged admission")
		}
	}
	changed := binding
	changed.CommandID = "another"
	if source.valid(changed, proof, signature) {
		t.Fatal("signature crossed command identity")
	}
	other, _ := NewDomainEvidenceSource(admissionObserver{}, [32]byte{0x72})
	if other.valid(binding, proof, signature) || source.valid(binding, proof, "malformed") || source.valid(binding, proof, "") {
		t.Fatal("untrusted source or malformed signature admitted")
	}
	if got := fmt.Sprintf("%+v", source); !strings.Contains(got, "redacted") {
		t.Fatal("source formatting exposed custody")
	}
	if _, err = json.Marshal(source); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("source serialized")
	}
}

func TestDomainEvidenceSourceRejectsInvalidZero(t *testing.T) {
	if _, err := NewDomainEvidenceSource(nil, [32]byte{1}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("nil source admitted")
	}
	if _, err := NewDomainEvidenceSource(admissionObserver{}, [32]byte{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero key admitted")
	}
	var source *DomainEvidenceSource
	if source.valid(identity.CommandBinding{}, organization.DomainProof{}, "") {
		t.Fatal("zero source verified")
	}
	var service Service
	if _, err := service.DomainEvidence(organization.Authentication{}, ""); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero service admitted evidence")
	}
	var reader Repository
	if _, err := reader.GetDomainProof(t.Context(), organization.DomainProofKey{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero repository admitted proof")
	}
	var bound DomainEvidenceService
	if _, err := bound.Prepare(t.Context(), organization.DomainEvidenceRequest{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero facade prepared")
	}
	if _, err := bound.ApplyDomainEvidence(t.Context(), organization.DomainEvidenceCommand{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero facade applied")
	}
	if _, err := bound.RecoverDomainEvidence(t.Context(), ""); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero facade recovered")
	}
	if _, err := bound.GetDomainProof(t.Context(), organization.DomainProofKey{}); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("zero facade disclosed")
	}
}

func TestDomainEvidencePendingCustodyGrantsNoProof(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	binding := identity.CommandBinding{CommandID: id, OperationID: string(organization.ApplyDomainProof)}
	result, err := new(DomainEvidenceService).result(t.Context(), organization.StoreResult{Receipt: identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeInProgress, RetryAfter: time.Second}}, nil)
	var unknown identity.UnknownCommitError
	if !errors.As(err, &unknown) || unknown.CommandID != id || result.Receipt.Outcome != identity.CommitOutcomeUnknown || result.Receipt.Binding != binding || result.Proof != (organization.DomainProof{}) {
		t.Fatal("pending observation inferred authority", err)
	}
}
