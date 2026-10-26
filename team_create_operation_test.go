package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func teamCreateOperationRequest(t testing.TB) organization.CreateTeamOperationRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-team-create"))
	if err != nil {
		t.Fatal(err)
	}
	return organization.CreateTeamOperationRequest{Authentication: organization.Authentication{TenantID: "tenant", Bearer: auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}, IdempotencyKey: key, OrganizationID: "org", TeamID: "team", OrganizationVersion: 7, Name: "Engineering team", CorrelationID: "team-create"}
}

func TestCreateTeamOperationRequestPreservesChosenIDAndExactIntent(t *testing.T) {
	r := teamCreateOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	maximum := r
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.TeamID = organization.ID(strings.Repeat("t", 128))
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("a", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.Name = strings.Repeat("n", 256)
	maximum.OrganizationVersion = ^uint64(0) - 1
	if err := maximum.Validate(); err != nil {
		t.Fatal("bounded team intent rejected", err)
	}
	for name, change := range map[string]func(*organization.CreateTeamOperationRequest){
		"missing-key":    func(r *organization.CreateTeamOperationRequest) { r.IdempotencyKey = identity.IdempotencyKey{} },
		"missing-tenant": func(r *organization.CreateTeamOperationRequest) { r.Authentication.TenantID = "" },
		"invalid-tenant": func(r *organization.CreateTeamOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
		"invalid-bearer": func(r *organization.CreateTeamOperationRequest) {
			r.Authentication.Bearer = auth.NewBearerCredential("bad")
		},
		"missing-org": func(r *organization.CreateTeamOperationRequest) { r.OrganizationID = "" },
		"long-org": func(r *organization.CreateTeamOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"invalid-org":                 func(r *organization.CreateTeamOperationRequest) { r.OrganizationID = "org\n" },
		"missing-team":                func(r *organization.CreateTeamOperationRequest) { r.TeamID = "" },
		"long-team":                   func(r *organization.CreateTeamOperationRequest) { r.TeamID = organization.ID(strings.Repeat("t", 129)) },
		"invalid-team":                func(r *organization.CreateTeamOperationRequest) { r.TeamID = "team\x7f" },
		"invalid-utf8-team":           func(r *organization.CreateTeamOperationRequest) { r.TeamID = "\xff" },
		"zero-org-version":            func(r *organization.CreateTeamOperationRequest) { r.OrganizationVersion = 0 },
		"unincrementable-org-version": func(r *organization.CreateTeamOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"empty-name":                  func(r *organization.CreateTeamOperationRequest) { r.Name = "" },
		"long-name":                   func(r *organization.CreateTeamOperationRequest) { r.Name = strings.Repeat("n", 257) },
		"padded-name":                 func(r *organization.CreateTeamOperationRequest) { r.Name = " team " },
		"control-name":                func(r *organization.CreateTeamOperationRequest) { r.Name = "team\tname" },
		"invalid-utf8-name":           func(r *organization.CreateTeamOperationRequest) { r.Name = "\xff" },
		"empty-correlation":           func(r *organization.CreateTeamOperationRequest) { r.CorrelationID = "" },
		"long-correlation":            func(r *organization.CreateTeamOperationRequest) { r.CorrelationID = strings.Repeat("c", 129) },
		"invalid-correlation":         func(r *organization.CreateTeamOperationRequest) { r.CorrelationID = "team create" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid original team selection accepted")
			}
		})
	}
	// Syntax retains the exact chosen ID and name, not an allocation or a grant.
	r.TeamID, r.Name, r.CorrelationID = "another-team", "Entwicklung", "another-attempt"
	if err := r.Validate(); err != nil {
		t.Fatal("syntax invented original-key execution authority", err)
	}
}

func TestCreateTeamOperationRecoveryRetainsSelfActorAndOriginalOrganization(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := organization.CreateTeam.Descriptor()
	r := organization.OperationRecoveryRequest{Authentication: teamCreateOperationRequest(t).Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "owner", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: "org", SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-team"}}
	if err := r.Validate(); err != nil {
		t.Fatal("exact team-create history syntax rejected", err)
	}
	for name, change := range map[string]func(*organization.OperationRecoveryRequest){
		"foreign-tenant": func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "other" },
		"nonself-user":   func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "member" },
		"workload": func(r *organization.OperationRecoveryRequest) {
			r.Binding.ActorKind = authorization.SubjectServiceAccount
		},
		"missing-command": func(r *organization.OperationRecoveryRequest) { r.Binding.CommandID = "" },
		"wrong-schema":    func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization" },
		"team-read-has-no-mutation-recovery": func(r *organization.OperationRecoveryRequest) {
			r.Binding.OperationID = string(organization.GetTeam)
		},
		"team-update-remains-separate": func(r *organization.OperationRecoveryRequest) {
			r.Binding.OperationID = string(organization.UpdateTeam)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("unsupported recovery scope accepted")
			}
		})
	}
}

func TestCreateTeamOperationRejectsCustodyExport(t *testing.T) {
	r := teamCreateOperationRequest(t)
	for _, value := range []any{r, &r} {
		if _, err := json.Marshal(value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("team request exported credential/key custody")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, value) != "organization.CreateTeamOperationRequest(redacted)" {
				t.Fatal("team diagnostics disclosed custody")
			}
		}
	}
	if _, err := r.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
		t.Fatal("team request exported text custody")
	}
}

func FuzzCreateTeamOperationValidation(f *testing.F) {
	for _, value := range []string{"team", "Engineering team", "üser", "", "\xff", " team ", "bad\nname", strings.Repeat("x", 128), strings.Repeat("x", 129), strings.Repeat("n", 256), strings.Repeat("n", 257)} {
		for _, version := range []uint64{0, 1, ^uint64(0) - 1, ^uint64(0)} {
			f.Add(value, uint8(0), version)
		}
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := teamCreateOperationRequest(t)
		r.OrganizationVersion = version
		name := mode%5 == 4
		switch mode % 5 {
		case 0:
			r.TeamID = organization.ID(value)
		case 1:
			r.OrganizationID = organization.ID(value)
		case 2:
			r.Authentication.TenantID = identity.TenantID(value)
		case 3:
			r.CorrelationID = value
		case 4:
			r.Name = value
		}
		limit := 128
		if name {
			limit = 256
		}
		valid := value != "" && len(value) <= limit && utf8.ValidString(value) && version > 0 && version < ^uint64(0)
		if name && strings.TrimSpace(value) != value {
			valid = false
		}
		for _, character := range value {
			if character < 32 || character == 127 || !name && character == ' ' {
				valid = false
			}
		}
		if err := r.Validate(); (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("team intent violated bounded name/scope/version contract")
		}
	})
}
