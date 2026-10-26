package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func ownerTransferOperationRequest(t testing.TB) organization.OwnerTransferOperationRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-owner-transfer-operation"))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	return organization.OwnerTransferOperationRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		IdempotencyKey: key, OrganizationID: "org", TargetUserID: "member", OrganizationVersion: 2, SourceVersion: 1, TargetVersion: 1, CorrelationID: "transfer",
		Proof: authentication.ReauthenticationProof{Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant", Subject: "owner", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "identity.password.verify", Audience: "organization-action", IssuedAt: at, ExpiresAt: at.Add(5 * time.Minute)}, SessionID: "session", SessionVersion: 1, Action: string(organization.OwnerTransfer)},
	}
}

func TestOwnerTransferOperationRequestPreservesOriginalProofSyntax(t *testing.T) {
	r := ownerTransferOperationRequest(t)
	// Historical classification must still represent an expired original proof;
	// syntax validation cannot supply a request-controlled trusted clock.
	if err := r.Validate(); err != nil {
		t.Fatal("original owner-transfer syntax rejected", err)
	}
	maximum := r
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.TargetUserID = identity.UserID(strings.Repeat("u", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.OrganizationVersion, maximum.SourceVersion, maximum.TargetVersion = ^uint64(0)-1, ^uint64(0)-1, ^uint64(0)-1
	maximum.Proof.SessionID, maximum.Proof.SessionVersion = strings.Repeat("s", 128), ^uint64(0)
	if err := maximum.Validate(); err != nil {
		t.Fatal("bounded owner-transfer syntax rejected", err)
	}
	for name, change := range map[string]func(*organization.OwnerTransferOperationRequest){
		"missing key":    func(r *organization.OwnerTransferOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing tenant": func(r *organization.OwnerTransferOperationRequest) { r.Authentication.TenantID = "" },
		"invalid bearer": func(r *organization.OwnerTransferOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing org": func(r *organization.OwnerTransferOperationRequest) { r.OrganizationID = "" },
		"long org": func(r *organization.OwnerTransferOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"invalid org":    func(r *organization.OwnerTransferOperationRequest) { r.OrganizationID = "\xff" },
		"missing target": func(r *organization.OwnerTransferOperationRequest) { r.TargetUserID = "" },
		"long target": func(r *organization.OwnerTransferOperationRequest) {
			r.TargetUserID = identity.UserID(strings.Repeat("u", 129))
		},
		"missing correlation":     func(r *organization.OwnerTransferOperationRequest) { r.CorrelationID = "" },
		"missing org version":     func(r *organization.OwnerTransferOperationRequest) { r.OrganizationVersion = 0 },
		"missing source version":  func(r *organization.OwnerTransferOperationRequest) { r.SourceVersion = 0 },
		"missing target version":  func(r *organization.OwnerTransferOperationRequest) { r.TargetVersion = 0 },
		"overflow org version":    func(r *organization.OwnerTransferOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"overflow source version": func(r *organization.OwnerTransferOperationRequest) { r.SourceVersion = ^uint64(0) },
		"overflow target version": func(r *organization.OwnerTransferOperationRequest) { r.TargetVersion = ^uint64(0) },
		"missing proof":           func(r *organization.OwnerTransferOperationRequest) { r.Proof = authentication.ReauthenticationProof{} },
		"foreign proof tenant":    func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.Tenant = "other" },
		"missing proof subject":   func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.Subject = "" },
		"invalid proof id":        func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.ID = "short" },
		"wrong method":            func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.Method = "passkey" },
		"wrong assurance": func(r *organization.OwnerTransferOperationRequest) {
			r.Proof.Proof.Assurance = authentication.AssuranceMultiFactor
		},
		"wrong purpose": func(r *organization.OwnerTransferOperationRequest) {
			r.Proof.Proof.Purpose = "identity.password.change"
		},
		"missing audience":     func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.Audience = "" },
		"invalid audience":     func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.Audience = "org\n" },
		"missing issuance":     func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.IssuedAt = time.Time{} },
		"empty proof lifetime": func(r *organization.OwnerTransferOperationRequest) { r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt },
		"excess proof lifetime": func(r *organization.OwnerTransferOperationRequest) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt.Add(24*time.Hour + time.Nanosecond)
		},
		"missing session":         func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionID = "" },
		"long session":            func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionID = strings.Repeat("s", 129) },
		"space session":           func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionID = "with space" },
		"unicode session":         func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionID = "sëssion" },
		"missing session version": func(r *organization.OwnerTransferOperationRequest) { r.Proof.SessionVersion = 0 },
		"foreign action":          func(r *organization.OwnerTransferOperationRequest) { r.Proof.Action = string(organization.Archive) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid owner-transfer syntax accepted")
			}
		})
	}
}

func assertOwnerTransferOperationCustody(t testing.TB, r organization.OwnerTransferOperationRequest) {
	t.Helper()
	for _, value := range []any{r, &r} {
		if got := fmt.Sprintf("%+v %#v %s", value, value, value); got != "organization.OwnerTransferOperationRequest(redacted) organization.OwnerTransferOperationRequest(redacted) organization.OwnerTransferOperationRequest(redacted)" {
			t.Fatal("owner-transfer request escaped diagnostic redaction")
		}
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("owner-transfer custody serialized")
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("owner-transfer custody exported as text")
	}
}

func TestOwnerTransferOperationRequestCustody(t *testing.T) {
	assertOwnerTransferOperationCustody(t, ownerTransferOperationRequest(t))
}

func TestOwnerTransferOperationRecoveryRetainsExactOriginalScope(t *testing.T) {
	r := organization.OperationRecoveryRequest{
		Authentication: ownerTransferOperationRequest(t).Authentication,
		Binding:        identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: string(organization.OwnerTransfer), RecordID: "org", PolicyID: "organization", PolicyVersion: 1, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "original-transfer"},
	}
	if err := r.Validate(); err != nil {
		t.Fatal("original source/target transfer recovery rejected", err)
	}
	for name, change := range map[string]func(*organization.OperationRecoveryRequest){
		"foreign tenant": func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
		"workload actor": func(r *organization.OperationRecoveryRequest) {
			r.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		"missing target":           func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "" },
		"missing original command": func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
		"wrong schema":             func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization" },
		"unsupported operation":    func(r *organization.OperationRecoveryRequest) { r.Binding.OperationID = "identity.organization.delete" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid transfer recovery accepted")
			}
		})
	}
}

func FuzzOwnerTransferOperationRequestBoundary(f *testing.F) {
	for _, value := range []string{"org", "", "\x00", "\xff", "with space", "é", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		for field := range uint8(10) {
			f.Add(field, value, uint64(1))
		}
	}
	f.Add(uint8(8), "version", ^uint64(0))
	f.Fuzz(func(t *testing.T, field uint8, value string, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := ownerTransferOperationRequest(t)
		switch field % 10 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.TargetUserID = identity.UserID(value)
		case 2:
			r.CorrelationID = value
		case 3:
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		case 4:
			r.Proof.Proof.ID = authentication.ProofID(value)
		case 5:
			r.Proof.Proof.Audience = value
		case 6:
			r.Proof.SessionID = value
		case 7:
			r.OrganizationVersion = version
		case 8:
			r.SourceVersion = version
		case 9:
			r.TargetVersion = version
		}
		if err := r.Validate(); err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("owner-transfer boundary returned an open error")
		}
		assertOwnerTransferOperationCustody(t, r)
	})
}
