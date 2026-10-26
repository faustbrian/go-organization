package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func expireOperationRequest() organization.InvitationExpireOperationRequest {
	return organization.InvitationExpireOperationRequest{
		Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")},
		OrganizationID: "org", InvitationID: "invitation", OrganizationVersion: 7, InvitationVersion: 3,
		Reason: "security-withdrawal", CorrelationID: "expire",
	}
}

func TestInvitationExpireOperationPreservesExactNaturalSelection(t *testing.T) {
	r := expireOperationRequest()
	for _, version := range []uint64{1, ^uint64(0) - 1} {
		selected := r
		selected.OrganizationVersion, selected.InvitationVersion = version, version
		if err := selected.Validate(); err != nil {
			t.Fatal("supported exact expiry versions rejected", err)
		}
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.InvitationID = organization.ID(strings.Repeat("i", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.Reason = identity.PolicyReason(strings.Repeat("r", 64))
	if err := maximum.Validate(); err != nil {
		t.Fatal("bounded expiry selection rejected", err)
	}
	for name, change := range map[string]func(*organization.InvitationExpireOperationRequest){
		"missing-tenant": func(r *organization.InvitationExpireOperationRequest) { r.Authentication.TenantID = "" },
		"invalid-tenant": func(r *organization.InvitationExpireOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
		"long-tenant": func(r *organization.InvitationExpireOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing-bearer": func(r *organization.InvitationExpireOperationRequest) {
			r.Authentication = organization.Authentication{TenantID: "tenant"}
		},
		"invalid-bearer": func(r *organization.InvitationExpireOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing-organization": func(r *organization.InvitationExpireOperationRequest) { r.OrganizationID = "" },
		"long-organization": func(r *organization.InvitationExpireOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"invalid-organization": func(r *organization.InvitationExpireOperationRequest) { r.OrganizationID = "org\n" },
		"missing-invitation":   func(r *organization.InvitationExpireOperationRequest) { r.InvitationID = "" },
		"long-invitation": func(r *organization.InvitationExpireOperationRequest) {
			r.InvitationID = organization.ID(strings.Repeat("i", 129))
		},
		"invalid-invitation":               func(r *organization.InvitationExpireOperationRequest) { r.InvitationID = "invitation\x7f" },
		"invalid-utf8":                     func(r *organization.InvitationExpireOperationRequest) { r.InvitationID = "\xff" },
		"missing-organization-version":     func(r *organization.InvitationExpireOperationRequest) { r.OrganizationVersion = 0 },
		"unsupported-organization-maximum": func(r *organization.InvitationExpireOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing-invitation-version":       func(r *organization.InvitationExpireOperationRequest) { r.InvitationVersion = 0 },
		"no-terminal-increment":            func(r *organization.InvitationExpireOperationRequest) { r.InvitationVersion = ^uint64(0) },
		"missing-reason":                   func(r *organization.InvitationExpireOperationRequest) { r.Reason = "" },
		"free-form-reason":                 func(r *organization.InvitationExpireOperationRequest) { r.Reason = "remove invitation please" },
		"long-reason": func(r *organization.InvitationExpireOperationRequest) {
			r.Reason = identity.PolicyReason(strings.Repeat("r", 65))
		},
		"invalid-reason":      func(r *organization.InvitationExpireOperationRequest) { r.Reason = "security\nwithdrawal" },
		"invalid-utf8-reason": func(r *organization.InvitationExpireOperationRequest) { r.Reason = "\xff" },
		"missing-correlation": func(r *organization.InvitationExpireOperationRequest) { r.CorrelationID = "" },
		"invalid-correlation": func(r *organization.InvitationExpireOperationRequest) { r.CorrelationID = "expiry request" },
		"long-correlation":    func(r *organization.InvitationExpireOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid natural expiry selection accepted")
			}
		})
	}
	// Syntax does not authorize a reason: only the original InvitationConfig's
	// registered allowlist can do that. Correlation is diagnostic, not intent.
	r.Reason, r.CorrelationID = "configured-by-original-owner", "reconstructed-attempt"
	if err := r.Validate(); err != nil {
		t.Fatal("syntax validation invented a reason policy or attempt identity", err)
	}
}

func TestInvitationExpireOperationRejectsCustodyExport(t *testing.T) {
	r := expireOperationRequest()
	for _, value := range []any{r, &r} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("expiry request serialized credential or selector custody")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, value) != "organization.InvitationExpireOperationRequest(redacted)" {
				t.Fatal("expiry diagnostics disclosed request custody")
			}
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("expiry request exported text custody")
	}
}

func FuzzInvitationExpireOperationValidation(f *testing.F) {
	for _, value := range []string{"invitation", "üser", "", "\xff", "bad identifier", "bad\nidentifier", strings.Repeat("x", 64), strings.Repeat("x", 65), strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		for _, version := range []uint64{0, 1, ^uint64(0) - 1, ^uint64(0)} {
			f.Add(value, uint8(0), version)
		}
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := expireOperationRequest()
		r.OrganizationVersion, r.InvitationVersion = version, version
		limit := 128
		switch mode % 5 {
		case 0:
			r.InvitationID = organization.ID(value)
		case 1:
			r.OrganizationID = organization.ID(value)
		case 2:
			r.CorrelationID = value
		case 3:
			r.Authentication.TenantID = identity.TenantID(value)
		case 4:
			r.Reason, limit = identity.PolicyReason(value), 64
		}
		valid := value != "" && len(value) <= limit && utf8.ValidString(value) && version > 0 && version < ^uint64(0)
		for _, character := range value {
			if character <= ' ' || character == 127 {
				valid = false
			}
		}
		err := r.Validate()
		if (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("expiry selection violated bounded identifier/version/reason contract")
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("fuzzed expiry request serialized custody")
		}
	})
}
