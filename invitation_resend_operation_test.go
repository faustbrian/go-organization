package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestInvitationResendOperationPreservesExactOriginalSelection(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("original-resend"))
	if err != nil {
		t.Fatal(err)
	}
	r := organization.InvitationResendOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "org", InvitationID: "invitation", OrganizationVersion: ^uint64(0), InvitationVersion: ^uint64(0) - 2, CorrelationID: "resend"}
	if err := r.Validate(); err != nil {
		t.Fatal("read-only organization epoch or last advanceable invitation rejected", err)
	}
	for name, change := range map[string]func(*organization.InvitationResendOperationRequest){
		"no-key":    func(r *organization.InvitationResendOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"no-tenant": func(r *organization.InvitationResendOperationRequest) { r.Authentication.TenantID = "" },
		"bad-bearer": func(r *organization.InvitationResendOperationRequest) {
			r.Authentication.Bearer = auth.NewBearerCredential("bad")
		},
		"no-org":         func(r *organization.InvitationResendOperationRequest) { r.OrganizationID = "" },
		"no-invitation":  func(r *organization.InvitationResendOperationRequest) { r.InvitationID = "" },
		"bad-invitation": func(r *organization.InvitationResendOperationRequest) { r.InvitationID = "bad invitation" },
		"long-org": func(r *organization.InvitationResendOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"bad-utf8":         func(r *organization.InvitationResendOperationRequest) { r.InvitationID = "\xff" },
		"no-org-version":   func(r *organization.InvitationResendOperationRequest) { r.OrganizationVersion = 0 },
		"no-inv-version":   func(r *organization.InvitationResendOperationRequest) { r.InvitationVersion = 0 },
		"no-terminal-room": func(r *organization.InvitationResendOperationRequest) { r.InvitationVersion = ^uint64(0) - 1 },
		"terminal":         func(r *organization.InvitationResendOperationRequest) { r.InvitationVersion = ^uint64(0) },
		"no-correlation":   func(r *organization.InvitationResendOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid original resend selection accepted")
			}
		})
	}
	if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("resend request serialized custody")
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("resend request exported text custody")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, r) != "organization.InvitationResendOperationRequest(redacted)" {
			t.Fatal("resend request diagnostic disclosed custody")
		}
	}
}

func FuzzInvitationResendOperationValidation(f *testing.F) {
	for _, value := range []string{"invitation", "üser", "", "\xff", "bad identifier", "bad\nidentifier", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		for _, version := range []uint64{0, 1, ^uint64(0) - 2, ^uint64(0) - 1, ^uint64(0)} {
			f.Add(value, uint8(0), version)
		}
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		key, _ := identity.NewIdempotencyKey([]byte("synthetic-fuzz-resend"))
		r := organization.InvitationResendOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "org", InvitationID: "invitation", OrganizationVersion: ^uint64(0), InvitationVersion: version, CorrelationID: "resend"}
		switch mode % 4 {
		case 0:
			r.InvitationID = organization.ID(value)
		case 1:
			r.OrganizationID = organization.ID(value)
		case 2:
			r.CorrelationID = value
		case 3:
			r.Authentication.TenantID = identity.TenantID(value)
		}
		err := r.Validate()
		valid := value != "" && len(value) <= 128 && utf8.ValidString(value) && version > 0 && version < ^uint64(0)-1
		for _, r := range value {
			if r <= ' ' || r == 127 {
				valid = false
			}
		}
		if (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("resend selection violated bounded identifier/version contract")
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("fuzzed request serialized custody")
		}
	})
}
