package organization_test

import (
	"encoding/base64"
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

func TestInvitationSendOperationRequestRetainsExactInitiatingCustody(t *testing.T) {
	key, err := identity.NewIdempotencyKey([]byte("original-invitation-send"))
	if err != nil {
		t.Fatal(err)
	}
	r := organization.InvitationSendOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "organization", OrganizationVersion: 1, RecipientUserID: "recipient", RecipientIdentifierID: "verified-email", CorrelationID: "send"}
	if err := r.Validate(); err != nil {
		t.Fatal("valid original-key invitation request rejected", err)
	}
	maximum := r
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.RecipientUserID = identity.UserID(strings.Repeat("u", 128))
	maximum.RecipientIdentifierID = identity.IdentifierID(strings.Repeat("i", 128))
	maximum.OrganizationVersion = ^uint64(0)
	if err := maximum.Validate(); err != nil {
		t.Fatal("read-only expected organization version or maximum identifiers rejected", err)
	}
	for name, change := range map[string]func(*organization.InvitationSendOperationRequest){
		"missing key": func(r *organization.InvitationSendOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"invalid bearer": func(r *organization.InvitationSendOperationRequest) {
			r.Authentication.Bearer = authentication.NewBearerCredential("bad")
		},
		"missing tenant":       func(r *organization.InvitationSendOperationRequest) { r.Authentication.TenantID = "" },
		"missing organization": func(r *organization.InvitationSendOperationRequest) { r.OrganizationID = "" },
		"oversized organization": func(r *organization.InvitationSendOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("x", 129))
		},
		"missing version":   func(r *organization.InvitationSendOperationRequest) { r.OrganizationVersion = 0 },
		"missing recipient": func(r *organization.InvitationSendOperationRequest) { r.RecipientUserID = "" },
		"oversized recipient": func(r *organization.InvitationSendOperationRequest) {
			r.RecipientUserID = identity.UserID(strings.Repeat("x", 129))
		},
		"missing identifier": func(r *organization.InvitationSendOperationRequest) { r.RecipientIdentifierID = "" },
		"invalid identifier": func(r *organization.InvitationSendOperationRequest) { r.RecipientIdentifierID = "bad identifier" },
		"oversized identifier": func(r *organization.InvitationSendOperationRequest) {
			r.RecipientIdentifierID = identity.IdentifierID(strings.Repeat("x", 129))
		},
		"missing correlation": func(r *organization.InvitationSendOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := r
			change(&invalid)
			if !errors.Is(invalid.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid initiating custody accepted")
			}
		})
	}
	if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("initiating request serialized")
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("initiating request serialized as text")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		rendered := fmt.Sprintf(format, r)
		if !strings.Contains(rendered, "redacted") || strings.Contains(rendered, r.Authentication.Bearer.Token()) || strings.Contains(rendered, "verified-email") {
			t.Fatal("initiating request diagnostics leaked custody")
		}
	}
}

func FuzzInvitationSendOperationRequestValidation(f *testing.F) {
	for _, value := range []string{"recipient", "", "üser", "\xff", "bad identifier", "bad\nidentifier", "\x00", "\x7f", strings.Repeat("i", 128), strings.Repeat("i", 129), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "bad"} {
		for mode := uint8(0); mode < 7; mode++ {
			f.Add(value, mode, uint64(1))
		}
	}
	f.Add("recipient", uint8(0), uint64(0))
	f.Add("recipient", uint8(0), ^uint64(0))
	f.Add("00000000000000000000000000000000000000000000", uint8(19), uint64(100))
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		key, err := identity.NewIdempotencyKey([]byte("synthetic-fuzz-invitation-send"))
		if err != nil {
			t.Fatal("fuzz key construction failed")
		}
		r := organization.InvitationSendOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: authentication.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "organization", OrganizationVersion: version, RecipientUserID: "recipient", RecipientIdentifierID: "verified-email", CorrelationID: "send"}
		selector := mode % 7
		switch selector {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.RecipientUserID = identity.UserID(value)
		case 2:
			r.RecipientIdentifierID = identity.IdentifierID(value)
		case 3:
			r.CorrelationID = value
		case 4:
			r.Authentication.TenantID = identity.TenantID(value)
		case 5:
			r.Authentication.Bearer = authentication.NewBearerCredential(value)
		case 6:
			r.IdempotencyKey = identity.IdempotencyKey{}
		}
		err = r.Validate()
		if err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("unclassified validation error")
		}
		if err == nil {
			if version == 0 || selector == 6 {
				t.Fatal("missing version or initiating key accepted")
			}
			if selector < 5 {
				if value == "" || len(value) > 128 || !utf8.ValidString(value) {
					t.Fatal("invalid identifier boundary accepted")
				}
				for _, character := range value {
					if character <= ' ' || character == 127 {
						t.Fatal("identifier control accepted")
					}
				}
			} else {
				decoded, decodeErr := base64.RawURLEncoding.Strict().DecodeString(value)
				if decodeErr != nil || len(decoded) < 32 || len(decoded) > 64 || base64.RawURLEncoding.EncodeToString(decoded) != value {
					t.Fatal("noncanonical bearer accepted")
				}
			}
		}
		if _, err := json.Marshal(r); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("request custody serialized")
		}
		if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("request custody exported as text")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if fmt.Sprintf(format, r) != "organization.InvitationSendOperationRequest(redacted)" {
				t.Fatal("request custody diagnostic changed")
			}
		}
	})
}
