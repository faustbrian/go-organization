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

func rejectOperationRequest() organization.InvitationRejectOperationRequest {
	return organization.InvitationRejectOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, OrganizationID: "org", InvitationID: "invitation", OrganizationVersion: 7, InvitationVersion: 3, CorrelationID: "reject"}
}

func TestInvitationRejectOperationPreservesExactNaturalSelection(t *testing.T) {
	r := rejectOperationRequest()
	for _, version := range []uint64{1, ^uint64(0) - 1} {
		selected := r
		selected.OrganizationVersion, selected.InvitationVersion = version, version
		if err := selected.Validate(); err != nil {
			t.Fatal("supported exact rejection versions rejected", err)
		}
	}
	maximum := r
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.InvitationID = organization.ID(strings.Repeat("i", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	if err := maximum.Validate(); err != nil {
		t.Fatal("bounded rejection selection rejected", err)
	}
	for name, change := range map[string]func(*organization.InvitationRejectOperationRequest){
		"missing-tenant": func(r *organization.InvitationRejectOperationRequest) { r.Authentication.TenantID = "" },
		"invalid-tenant": func(r *organization.InvitationRejectOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
		"long-tenant": func(r *organization.InvitationRejectOperationRequest) {
			r.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 129))
		},
		"missing-bearer": func(r *organization.InvitationRejectOperationRequest) {
			r.Authentication = organization.Authentication{TenantID: "tenant"}
		},
		"invalid-bearer": func(r *organization.InvitationRejectOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing-organization": func(r *organization.InvitationRejectOperationRequest) { r.OrganizationID = "" },
		"long-organization": func(r *organization.InvitationRejectOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"invalid-organization": func(r *organization.InvitationRejectOperationRequest) { r.OrganizationID = "org\n" },
		"missing-invitation":   func(r *organization.InvitationRejectOperationRequest) { r.InvitationID = "" },
		"long-invitation": func(r *organization.InvitationRejectOperationRequest) {
			r.InvitationID = organization.ID(strings.Repeat("i", 129))
		},
		"invalid-invitation":               func(r *organization.InvitationRejectOperationRequest) { r.InvitationID = "invitation\x7f" },
		"invalid-utf8":                     func(r *organization.InvitationRejectOperationRequest) { r.InvitationID = "\xff" },
		"missing-organization-version":     func(r *organization.InvitationRejectOperationRequest) { r.OrganizationVersion = 0 },
		"unsupported-organization-maximum": func(r *organization.InvitationRejectOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"missing-invitation-version":       func(r *organization.InvitationRejectOperationRequest) { r.InvitationVersion = 0 },
		"no-terminal-increment":            func(r *organization.InvitationRejectOperationRequest) { r.InvitationVersion = ^uint64(0) },
		"missing-correlation":              func(r *organization.InvitationRejectOperationRequest) { r.CorrelationID = "" },
		"invalid-correlation":              func(r *organization.InvitationRejectOperationRequest) { r.CorrelationID = "reject request" },
		"long-correlation":                 func(r *organization.InvitationRejectOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid natural rejection selection accepted")
			}
		})
	}
	r.CorrelationID = "reconstructed-attempt"
	if err := r.Validate(); err != nil {
		t.Fatal("diagnostic correlation prevented natural repetition", err)
	}
}

func TestInvitationRejectOperationRejectsCustodyExport(t *testing.T) {
	r := rejectOperationRequest()
	for _, value := range []any{r, &r} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("rejection request serialized credential or selector custody")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, value) != "organization.InvitationRejectOperationRequest(redacted)" {
				t.Fatal("rejection diagnostics disclosed request custody")
			}
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("rejection request exported text custody")
	}
}

func FuzzInvitationRejectOperationValidation(f *testing.F) {
	for _, value := range []string{"invitation", "üser", "", "\xff", "bad identifier", "bad\nidentifier", strings.Repeat("x", 128), strings.Repeat("x", 129)} {
		for _, version := range []uint64{0, 1, ^uint64(0) - 1, ^uint64(0)} {
			f.Add(value, uint8(0), version)
		}
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := rejectOperationRequest()
		r.OrganizationVersion, r.InvitationVersion = version, version
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
		valid := value != "" && len(value) <= 128 && utf8.ValidString(value) && version > 0 && version < ^uint64(0)
		for _, character := range value {
			if character <= ' ' || character == 127 {
				valid = false
			}
		}
		err := r.Validate()
		if (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("rejection selection violated bounded identifier/version contract")
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("fuzzed rejection request serialized custody")
		}
	})
}
