package organization_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func invitationAcceptSyntax(t *testing.T) (organization.InvitationAcceptRequest, capability.Service) {
	t.Helper()
	_, auth, at, _, _ := policyFixture(t)
	crypto := invitationCrypto(t, at)
	proof, _, err := crypto.Issue(t.Context(), capability.Payload{Version: 1, Issuer: "organization-test", Audiences: []string{"organization-invitation"}, Subject: "actor", Resource: "invitation-a", Operation: string(organization.InvitationAccept), ID: "original-invitation-challenge", Tenant: "tenant-a", MaxUses: 1, ExpiresAt: at.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r := organization.InvitationAcceptRequest{Authentication: auth, CommandID: identity.CommandID("AAAAAAAAAAAAAAAAAAAAAQ"), ID: "invitation-a", OrganizationID: "org", OrganizationVersion: 1, InvitationVersion: 1, Proof: proof, CorrelationID: "accept"}
	return r, crypto
}

func TestInvitationAcceptRequestBoundsAreNonConsuming(t *testing.T) {
	r, crypto := invitationAcceptSyntax(t)
	validator, ok := any(r).(interface{ Validate() error })
	if !ok {
		t.Fatal("once invitation acceptance has no bounded neutral request validation")
	}
	if err := validator.Validate(); err != nil {
		t.Fatal("valid once request rejected", err)
	}
	if _, err := crypto.Verify(context.Background(), r.Proof, capability.Purpose(organization.InvitationAccept), "organization-invitation"); err != nil {
		t.Fatal("syntax validation consumed proof custody", err)
	}
	maximum := r
	maximum.OrganizationVersion, maximum.InvitationVersion = ^uint64(0), ^uint64(0)
	maximum.ID, maximum.OrganizationID = organization.ID(strings.Repeat("i", 128)), organization.ID(strings.Repeat("o", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	if err := maximum.Validate(); err != nil {
		t.Fatal("valid expected-version/ID bounds rejected", err)
	}
	for name, change := range map[string]func(*organization.InvitationAcceptRequest){
		"missing command":      func(r *organization.InvitationAcceptRequest) { r.CommandID = "" },
		"noncanonical command": func(r *organization.InvitationAcceptRequest) { r.CommandID = "AAAAAAAAAAAAAAAAAAAAAR" },
		"missing proof":        func(r *organization.InvitationAcceptRequest) { r.Proof = capability.Proof{} },
		"missing organization": func(r *organization.InvitationAcceptRequest) { r.OrganizationID = "" },
		"long organization": func(r *organization.InvitationAcceptRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"missing invitation":           func(r *organization.InvitationAcceptRequest) { r.ID = "" },
		"control invitation":           func(r *organization.InvitationAcceptRequest) { r.ID = "invitation\n" },
		"invalid Unicode":              func(r *organization.InvitationAcceptRequest) { r.ID = "\xff" },
		"missing organization version": func(r *organization.InvitationAcceptRequest) { r.OrganizationVersion = 0 },
		"missing invitation version":   func(r *organization.InvitationAcceptRequest) { r.InvitationVersion = 0 },
		"invalid bearer": func(r *organization.InvitationAcceptRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant":      func(r *organization.InvitationAcceptRequest) { r.Authentication.TenantID = "" },
		"missing correlation": func(r *organization.InvitationAcceptRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := r
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid once request custody accepted")
			}
		})
	}
}

func TestInvitationAcceptRequestRejectsAuthenticProofBeyondIngressLimit(t *testing.T) {
	r, ordinary := invitationAcceptSyntax(t)
	if r.Validate() != nil {
		t.Fatal("ordinary bounded once request rejected")
	}
	if _, err := ordinary.Verify(t.Context(), r.Proof, capability.Purpose(organization.InvitationAccept), "organization-invitation"); err != nil {
		t.Fatal("ordinary control proof is not authentic", err)
	}
	_, _, at, _, _ := policyFixture(t)
	signer, err := capability.NewHMACSHA256Signer("wide-ingress", bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := capability.NewHMACSHA256Verifier(bytes.Repeat([]byte{0x62}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := capability.NewKeySet([]capability.Key{{Issuer: "organization-test", ID: "wide-ingress", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	limits := capability.DefaultLimits()
	limits.MaxTokenBytes = 8192
	wide, err := capability.NewService(capability.ServiceConfig{Issuer: "organization-test", Signer: signer, Resolver: keys, Clock: at.Now, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	payload := capability.Payload{Version: 1, Issuer: "organization-test", Audiences: []string{"organization-invitation"}, Subject: "actor", Resource: "invitation-a", Operation: string(organization.InvitationAccept), ID: "original-invitation-challenge", Tenant: "tenant-a", MaxUses: 1, IssuedAt: at.Now(), NotBefore: at.Now(), ExpiresAt: at.Now().Add(time.Hour), Caveats: map[string]string{}}
	for index := range 8 {
		payload.Caveats[string(rune('a'+index))] = strings.Repeat("x", 512)
	}
	token, err := capability.Issue(t.Context(), payload, signer, limits)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) <= 4096 || len(token) > 8192 {
		t.Fatal("authentic proof fixture did not cross the exact consumer ingress limit")
	}
	r.Proof, err = capability.ParseProof(token, limits)
	if err != nil {
		t.Fatal("explicit wider parser rejected authentic proof", err)
	}
	if _, err := wide.Verify(t.Context(), r.Proof, capability.Purpose(organization.InvitationAccept), "organization-invitation"); err != nil {
		t.Fatal("wider issuer did not authenticate oversized proof", err)
	}
	if !errors.Is(r.Validate(), organization.ErrInvalidInput) {
		t.Fatal("neutral once request widened its proof ingress beyond4096bytes")
	}
	if _, err := wide.Verify(t.Context(), r.Proof, capability.Purpose(organization.InvitationAccept), "organization-invitation"); err != nil {
		t.Fatal("rejected syntax consumed original proof custody", err)
	}
}

func invitationAcceptAdmission() organization.InvitationAcceptAdmission {
	return organization.InvitationAcceptAdmission{Binding: identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant-a", UserID: "actor", ActorID: "actor", ActorKind: authorization.SubjectUser, OperationID: string(organization.InvitationAccept), RecordID: "invitation-a", PolicyID: "organization", PolicyVersion: 1, SchemaID: "organization-invitation-accept", SchemaVersion: 1, CorrelationID: "accept"}, OrganizationID: "org", ChallengeID: "original-invitation-challenge", ChallengeLifetime: time.Hour}
}

// This is a compile-time consumer contract, not native authority or execution
// evidence. The genuine PostgreSQL consumer supplies and exercises the handle.
func invitationAcceptancePortContract(prepared organization.PreparedInvitationAcceptance) {
	var _ func() (organization.InvitationAcceptAdmission, error) = prepared.Admission
	var _ func(context.Context) (organization.StoreResult, error) = prepared.Execute
}

func TestInvitationAcceptanceAdmissionAndRecoveryRetainExactScope(t *testing.T) {
	a := invitationAcceptAdmission()
	r, _ := invitationAcceptSyntax(t)
	recovery := organization.InvitationAcceptRecoveryRequest{Authentication: r.Authentication, Binding: a.Binding, OrganizationID: a.OrganizationID}
	if a.Validate() != nil || recovery.Validate() != nil {
		t.Fatal("valid original acceptance metadata rejected")
	}
	for name, change := range map[string]func(*organization.InvitationAcceptAdmission){
		"missing organization": func(a *organization.InvitationAcceptAdmission) { a.OrganizationID = "" },
		"long organization": func(a *organization.InvitationAcceptAdmission) {
			a.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"missing challenge": func(a *organization.InvitationAcceptAdmission) { a.ChallengeID = "" },
		"long challenge":    func(a *organization.InvitationAcceptAdmission) { a.ChallengeID = strings.Repeat("c", 129) },
		"missing lifetime":  func(a *organization.InvitationAcceptAdmission) { a.ChallengeLifetime = 0 },
		"negative lifetime": func(a *organization.InvitationAcceptAdmission) { a.ChallengeLifetime = -time.Nanosecond },
		"long lifetime": func(a *organization.InvitationAcceptAdmission) {
			a.ChallengeLifetime = 30*24*time.Hour + time.Nanosecond
		},
		"wrong operation": func(a *organization.InvitationAcceptAdmission) {
			a.Binding.OperationID = string(organization.InvitationSend)
		},
		"wrong schema": func(a *organization.InvitationAcceptAdmission) { a.Binding.SchemaID = "organization-invitation-send" },
		"wrong actor":  func(a *organization.InvitationAcceptAdmission) { a.Binding.ActorID = "owner" },
		"workload actor": func(a *organization.InvitationAcceptAdmission) {
			a.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		"missing command": func(a *organization.InvitationAcceptAdmission) { a.Binding.CommandID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := a
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("malformed acceptance admission accepted")
			}
		})
	}
	for name, change := range map[string]func(*organization.InvitationAcceptRecoveryRequest){
		"foreign tenant":       func(r *organization.InvitationAcceptRecoveryRequest) { r.Authentication.TenantID = "other" },
		"missing organization": func(r *organization.InvitationAcceptRecoveryRequest) { r.OrganizationID = "" },
		"wrong actor":          func(r *organization.InvitationAcceptRecoveryRequest) { r.Binding.ActorID = "owner" },
		"wrong operation": func(r *organization.InvitationAcceptRecoveryRequest) {
			r.Binding.OperationID = string(organization.InvitationSend)
		},
		"missing original binding": func(r *organization.InvitationAcceptRecoveryRequest) { r.Binding = identity.CommandBinding{} },
		"invalid current bearer": func(r *organization.InvitationAcceptRecoveryRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := recovery
			change(&changed)
			if !errors.Is(changed.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid original acceptance recovery scope accepted")
			}
		})
	}
	// The original signed interval, not a fifteen-minute minimum or remaining
	// time, is admission metadata: delayed issuance may leave a shorter interval.
	for _, lifetime := range []time.Duration{time.Nanosecond, 30 * 24 * time.Hour} {
		valid := a
		valid.ChallengeLifetime = lifetime
		if valid.Validate() != nil {
			t.Fatal("bounded positive original interval rejected")
		}
	}
}

func TestInvitationAcceptanceDoesNotSerializeCustody(t *testing.T) {
	r, _ := invitationAcceptSyntax(t)
	a := invitationAcceptAdmission()
	recovery := organization.InvitationAcceptRecoveryRequest{Authentication: r.Authentication, Binding: a.Binding, OrganizationID: a.OrganizationID}
	admit := organization.InvitationAcceptAdmitter(func(context.Context, organization.InvitationAcceptAdmission) error { return nil })
	for _, value := range []any{r, a, recovery, admit} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("acceptance custody serialized")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("acceptance custody serialized as text")
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(verb, value)
			if !strings.Contains(text, "redacted") || strings.Contains(text, r.Authentication.Bearer.Token()) || strings.Contains(text, a.ChallengeID) {
				t.Fatal("acceptance diagnostic exposed custody")
			}
		}
	}
}

func FuzzInvitationAcceptanceBoundary(f *testing.F) {
	for _, value := range []string{"invitation", "", "é", "\xff", "\n", " spaced", strings.Repeat("x", 128), strings.Repeat("x", 129), "AAAAAAAAAAAAAAAAAAAAAQ"} {
		for _, mode := range []uint8{0, 1, 2, 4, 8, 16, 32, 64, 128} {
			f.Add(value, uint64(1), uint64(1), int64(time.Hour), mode)
		}
	}
	f.Add("invitation", uint64(0), ^uint64(0), int64(-1), uint8(255))
	f.Fuzz(func(t *testing.T, value string, orgVersion, invVersion uint64, lifetime int64, mode uint8) {
		if len(value) > 4096 {
			return
		}
		r, _ := invitationAcceptSyntax(t)
		r.OrganizationVersion, r.InvitationVersion = orgVersion, invVersion
		if mode&1 != 0 {
			r.ID = organization.ID(value)
		}
		if mode&2 != 0 {
			r.OrganizationID = organization.ID(value)
		}
		if mode&4 != 0 {
			r.CorrelationID = value
		}
		if mode&8 != 0 {
			r.Authentication.TenantID = identity.TenantID(value)
		}
		if mode&16 != 0 {
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		}
		if mode&32 != 0 {
			r.CommandID = identity.CommandID(value)
		}
		if mode&64 != 0 {
			r.Proof = capability.Proof{}
		}
		a := invitationAcceptAdmission()
		a.ChallengeLifetime = time.Duration(lifetime)
		if mode&128 != 0 {
			a.ChallengeID = value
			a.Binding.OperationID = value
		}
		recovery := organization.InvitationAcceptRecoveryRequest{Authentication: r.Authentication, Binding: a.Binding, OrganizationID: r.OrganizationID}
		for _, request := range []interface{ Validate() error }{r, a, recovery} {
			if err := request.Validate(); err != nil && !errors.Is(err, organization.ErrInvalidInput) {
				t.Fatal("unclassified acceptance syntax error")
			}
		}
		safe := func(s string) bool {
			return s != "" && len(s) <= 128 && utf8.ValidString(s) && !strings.ContainsFunc(s, func(c rune) bool { return c <= ' ' || c == 127 })
		}
		if r.Validate() == nil && (!safe(string(r.ID)) || !safe(string(r.OrganizationID)) || !safe(r.CorrelationID) || orgVersion == 0 || invVersion == 0 || mode&64 != 0) {
			t.Fatal("once request escaped scope/version/proof bounds")
		}
		if a.Validate() == nil && (a.Binding.OperationID != string(organization.InvitationAccept) || a.Binding.ActorID != identity.ActorID(a.Binding.UserID) || !safe(a.ChallengeID) || lifetime <= 0 || time.Duration(lifetime) > 30*24*time.Hour) {
			t.Fatal("acceptance admission escaped original binding/interval bounds")
		}
		if recovery.Validate() == nil && (recovery.Authentication.TenantID != recovery.Binding.TenantID || recovery.Binding.OperationID != string(organization.InvitationAccept)) {
			t.Fatal("recovery escaped original actor/tenant operation")
		}
		for _, value := range []any{r, a, recovery} {
			if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
				t.Fatal("hostile acceptance custody serialized")
			}
			if text := fmt.Sprintf("%#v", value); !strings.Contains(text, "redacted") {
				t.Fatal("hostile acceptance custody exposed")
			}
		}
	})
}
