package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func teamLifecycleOperationRequest(t testing.TB) organization.UpdateTeamOperationRequest {
	t.Helper()
	r := teamCreateOperationRequest(t)
	return organization.UpdateTeamOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: "org", TeamID: "engineering", OrganizationVersion: 7, TeamVersion: 2, Name: "Platform", CorrelationID: "team-lifecycle"}
}
func deleteLifecycleRequest(r organization.UpdateTeamOperationRequest) organization.DeleteTeamOperationRequest {
	return organization.DeleteTeamOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, TeamVersion: r.TeamVersion, CorrelationID: r.CorrelationID}
}

func TestTeamLifecycleOperationBoundedExactIntentAndCustody(t *testing.T) {
	r := teamLifecycleOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := deleteLifecycleRequest(r).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*organization.UpdateTeamOperationRequest){
		"org": func(r *organization.UpdateTeamOperationRequest) { r.OrganizationID = "" }, "team": func(r *organization.UpdateTeamOperationRequest) { r.TeamID = "bad team" }, "utf8": func(r *organization.UpdateTeamOperationRequest) { r.TeamID = "\xff" }, "long team": func(r *organization.UpdateTeamOperationRequest) { r.TeamID = organization.ID(strings.Repeat("a", 129)) }, "correlation": func(r *organization.UpdateTeamOperationRequest) { r.CorrelationID = "" }, "authentication": func(r *organization.UpdateTeamOperationRequest) { r.Authentication = organization.Authentication{} }, "zero org": func(r *organization.UpdateTeamOperationRequest) { r.OrganizationVersion = 0 }, "zero team": func(r *organization.UpdateTeamOperationRequest) { r.TeamVersion = 0 }, "overflow org": func(r *organization.UpdateTeamOperationRequest) { r.OrganizationVersion = ^uint64(0) }, "overflow team": func(r *organization.UpdateTeamOperationRequest) { r.TeamVersion = ^uint64(0) },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) || !errors.Is(deleteLifecycleRequest(bad).Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid exact lifecycle intent accepted")
			}
		})
	}
	for _, name := range []string{"", " padded ", "bad\nname", "\xff", strings.Repeat("n", 257)} {
		bad := r
		bad.Name = name
		if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
			t.Fatal("invalid replacement name accepted")
		}
	}
	bad := r
	bad.IdempotencyKey = identity.IdempotencyKey{}
	if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
		t.Fatal("missing rename key accepted")
	}
	maximum := r
	maximum.OrganizationID = organization.ID(strings.Repeat("o", 128))
	maximum.TeamID = organization.ID(strings.Repeat("t", 128))
	maximum.Name = strings.Repeat("n", 256)
	maximum.OrganizationVersion = ^uint64(0) - 1
	maximum.TeamVersion = ^uint64(0) - 1
	if err := maximum.Validate(); err != nil {
		t.Fatal("existing native bounds narrowed", err)
	}
	if err := deleteLifecycleRequest(maximum).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		value any
		label string
	}{{r, "UpdateTeamOperationRequest"}, {&r, "UpdateTeamOperationRequest"}, {deleteLifecycleRequest(r), "DeleteTeamOperationRequest"}} {
		if _, err := json.Marshal(item.value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("lifecycle credential/key custody exported")
		}
		if _, err := item.value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("lifecycle text custody exported")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, item.value) != "organization."+item.label+"(redacted)" {
				t.Fatal("diagnostics exposed lifecycle custody")
			}
		}
	}
}

func TestTeamLifecycleOperationRecoveryRequiresOriginalSelfBinding(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []organization.Operation{organization.UpdateTeam, organization.DeleteTeam} {
		d := op.Descriptor()
		r := organization.OperationRecoveryRequest{Authentication: teamCreateOperationRequest(t).Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", ActorID: "owner", ActorKind: authorization.SubjectUser, UserID: "owner", OperationID: d.OperationID, RecordID: "org", SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-team-lifecycle"}}
		if err := r.Validate(); err != nil {
			t.Fatalf("exact original team lifecycle recovery rejected: %v", err)
		}
		for _, change := range []func(*organization.OperationRecoveryRequest){func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "member" }, func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "foreign" }, func(r *organization.OperationRecoveryRequest) {
			r.Binding.ActorKind = authorization.SubjectServiceAccount
		}, func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization-membership" }} {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("foreign/nonself lifecycle history accepted")
			}
		}
	}
}

func FuzzTeamLifecycleOperationValidation(f *testing.F) {
	for _, value := range []string{"engineering", "Platform team", "", "\xff", " padded ", "bad\n", strings.Repeat("x", 128), strings.Repeat("n", 256)} {
		f.Add(value, uint8(0), uint64(1))
	}
	f.Fuzz(func(t *testing.T, value string, mode uint8, version uint64) {
		if len(value) > 4096 {
			return
		}
		r := teamLifecycleOperationRequest(t)
		r.OrganizationVersion = version
		r.TeamVersion = version
		name := mode%5 == 4
		switch mode % 5 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.TeamID = organization.ID(value)
		case 2:
			r.CorrelationID = value
		case 3:
			r.Authentication.TenantID = identity.TenantID(value)
		case 4:
			r.Name = value
		}
		limit := 128
		if name {
			limit = 256
		}
		valid := len(value) > 0 && len(value) <= limit && utf8.ValidString(value) && version > 0 && version < ^uint64(0)
		if name && strings.TrimSpace(value) != value {
			valid = false
		}
		for _, ch := range value {
			if ch < 32 || ch == 127 || !name && ch == ' ' {
				valid = false
			}
		}
		if err := r.Validate(); (err == nil) != valid || err != nil && !errors.Is(err, organization.ErrInvalidInput) {
			t.Fatal("lifecycle bounded intent contract violated")
		}
		if !name {
			if err := deleteLifecycleRequest(r).Validate(); (err == nil) != valid {
				t.Fatal("natural selector bounds diverged")
			}
		}
	})
}
