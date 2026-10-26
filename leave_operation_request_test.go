package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func leaveOperationRequest() organization.LeaveMemberOperationRequest {
	return organization.LeaveMemberOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, OrganizationID: "organization", OrganizationVersion: 7, CorrelationID: "leave"}
}

func TestLeaveMemberOperationRequestPreservesExactSelfSelection(t *testing.T) {
	r := leaveOperationRequest()
	for _, version := range []uint64{1, ^uint64(0) - 1} {
		selected := r
		selected.OrganizationVersion = version
		if err := selected.Validate(); err != nil {
			t.Fatal("supported original organization version rejected", err)
		}
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	if err := maximum.Validate(); err != nil {
		t.Fatal("maximum bounded self-leave selection rejected", err)
	}
	for name, change := range map[string]func(*organization.LeaveMemberOperationRequest){
		"zero":                  func(r *organization.LeaveMemberOperationRequest) { *r = organization.LeaveMemberOperationRequest{} },
		"missing-tenant":        func(r *organization.LeaveMemberOperationRequest) { r.Authentication.TenantID = "" },
		"foreign-tenant-syntax": func(r *organization.LeaveMemberOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
		"long-tenant": func(r *organization.LeaveMemberOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing-bearer": func(r *organization.LeaveMemberOperationRequest) {
			r.Authentication.Bearer = authentication.BearerCredential{}
		},
		"invalid-bearer": func(r *organization.LeaveMemberOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing-organization": func(r *organization.LeaveMemberOperationRequest) { r.OrganizationID = "" },
		"invalid-organization": func(r *organization.LeaveMemberOperationRequest) { r.OrganizationID = "org\n" },
		"invalid-utf8":         func(r *organization.LeaveMemberOperationRequest) { r.OrganizationID = "\xff" },
		"long-organization": func(r *organization.LeaveMemberOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"zero-version":          func(r *organization.LeaveMemberOperationRequest) { r.OrganizationVersion = 0 },
		"no-terminal-increment": func(r *organization.LeaveMemberOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing-correlation":   func(r *organization.LeaveMemberOperationRequest) { r.CorrelationID = "" },
		"invalid-correlation":   func(r *organization.LeaveMemberOperationRequest) { r.CorrelationID = "leave request" },
		"control-correlation":   func(r *organization.LeaveMemberOperationRequest) { r.CorrelationID = "leave\x7f" },
		"long-correlation":      func(r *organization.LeaveMemberOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid natural self-leave selection accepted")
			}
		})
	}
	// IDs are not normalized by syntax validation, and correlation is only
	// diagnostic. Neither a new correlation nor a valid version proves history.
	r.OrganizationID, r.CorrelationID = "üser", "reconstructed-attempt"
	if err := r.Validate(); err != nil || r.OrganizationID != "üser" {
		t.Fatal("self-leave syntax changed exact identity or invented history", err)
	}
}

func TestLeaveMemberOperationRequestRejectsCustodyExport(t *testing.T) {
	r := leaveOperationRequest()
	for _, value := range []any{r, &r} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("self-leave request exported borrowed credentials or selectors")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, value) != "organization.LeaveMemberOperationRequest(redacted)" {
				t.Fatal("self-leave diagnostics disclosed request custody")
			}
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("self-leave request exported text custody")
	}
}

func leaveOperationRecovery() organization.OperationRecoveryRequest {
	return organization.OperationRecoveryRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		Binding:        identity.CommandBinding{CommandID: "AAAAAAAAAAAAAAAAAAAAAQ", TenantID: "tenant", UserID: "member", ActorID: "member", ActorKind: authorization.SubjectUser, OperationID: string(organization.LeaveMember), RecordID: "org", PolicyID: "organization", PolicyVersion: 1, SchemaID: "organization-membership", SchemaVersion: 1, CorrelationID: "leave"},
	}
}

func TestLeaveMemberOperationRecoveryRequiresExactSelf(t *testing.T) {
	r := leaveOperationRecovery()
	if err := r.Validate(); err != nil {
		t.Fatal("exact original self-leave recovery syntax rejected", err)
	}
	for name, change := range map[string]func(*organization.OperationRecoveryRequest){
		"other-target":   func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "other" },
		"other-actor":    func(r *organization.OperationRecoveryRequest) { r.Binding.ActorID = "other" },
		"foreign-tenant": func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
		"workload-actor": func(r *organization.OperationRecoveryRequest) {
			r.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		"missing-command": func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
		"missing-record":  func(r *organization.OperationRecoveryRequest) { r.Binding.RecordID = "" },
		"wrong-schema":    func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "other" },
		"zero-policy":     func(r *organization.OperationRecoveryRequest) { r.Binding.PolicyVersion = 0 },
		"missing-bearer": func(r *organization.OperationRecoveryRequest) {
			r.Authentication.Bearer = authentication.BearerCredential{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("unsafe original self-leave recovery syntax accepted")
			}
		})
	}
	// Structural self-binding is not authentication of the presented bearer.
	// The native owner must still match both IDs to its current verified human.
	r.Binding.UserID, r.Binding.ActorID = "another-self", "another-self"
	if err := r.Validate(); err != nil {
		t.Fatal("syntax validation invented current-principal authority", err)
	}
}

func FuzzLeaveMemberOperationRequestValidation(f *testing.F) {
	for _, value := range []string{"organization", "üser", "", "\xff", "bad identifier", "bad\nidentifier", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		for _, version := range []uint64{0, 1, ^uint64(0) - 1, ^uint64(0)} {
			f.Add(value, uint8(0), version)
		}
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := leaveOperationRequest()
		r.OrganizationVersion = version
		switch mode % 3 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.CorrelationID = value
		case 2:
			r.Authentication.TenantID = identity.TenantID(value)
		}
		valid := value != "" && len(value) <= 128 && utf8.ValidString(value) && version > 0 && version < ^uint64(0)
		for _, character := range value {
			if character <= ' ' || character == 127 {
				valid = false
			}
		}
		err := r.Validate()
		if (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("self-leave syntax violated bounded identifier/version contract")
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("fuzzed self-leave request serialized custody")
		}
	})
}
