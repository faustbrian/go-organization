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

func teamRoleBindingOperationRequest(t testing.TB) organization.AssignTeamDynamicRoleOperationRequest {
	t.Helper()
	r := teamCreateOperationRequest(t)
	return organization.AssignTeamDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: "org", RoleID: "reader", TeamID: "engineering", OrganizationVersion: 7, RoleVersion: 2, TeamVersion: 3, CorrelationID: "team-role-assignment"}
}

func revokeTeamRoleOperation(r organization.AssignTeamDynamicRoleOperationRequest) organization.RevokeTeamDynamicRoleOperationRequest {
	return organization.RevokeTeamDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, TeamVersion: r.TeamVersion, BindingVersion: r.BindingVersion, CorrelationID: r.CorrelationID}
}

func TestTeamRoleBindingOperationExactIntentBounds(t *testing.T) {
	r := teamRoleBindingOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid original-key team assignment rejected", err)
	}
	if !errors.Is(revokeTeamRoleOperation(r).Validate(), organization.ErrInvalidInput) {
		t.Fatal("zero binding cannot identify an original team revocation")
	}
	r.BindingVersion = 4
	if err := revokeTeamRoleOperation(r).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*organization.AssignTeamDynamicRoleOperationRequest){
		"authentication": func(r *organization.AssignTeamDynamicRoleOperationRequest) {
			r.Authentication = organization.Authentication{}
		},
		"tenant": func(r *organization.AssignTeamDynamicRoleOperationRequest) {
			r.Authentication.TenantID = "foreign tenant"
		},
		"organization": func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.OrganizationID = "" },
		"long organization": func(r *organization.AssignTeamDynamicRoleOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"role":                 func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleID = "bad role" },
		"static owner":         func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleID = "owner" },
		"static administrator": func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleID = "administrator" },
		"static member":        func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleID = "member" },
		"invalid utf8":         func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleID = "\xff" },
		"team":                 func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.TeamID = "engineering\n" },
		"long team": func(r *organization.AssignTeamDynamicRoleOperationRequest) {
			r.TeamID = organization.ID(strings.Repeat("t", 129))
		},
		"zero organization epoch":     func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.OrganizationVersion = 0 },
		"overflow organization epoch": func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"zero role epoch":             func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleVersion = 0 },
		"overflow role epoch":         func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.RoleVersion = ^uint64(0) },
		"zero team epoch":             func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.TeamVersion = 0 },
		"overflow team epoch":         func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.TeamVersion = ^uint64(0) },
		"overflow binding epoch":      func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.BindingVersion = ^uint64(0) },
		"correlation":                 func(r *organization.AssignTeamDynamicRoleOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) || !errors.Is(revokeTeamRoleOperation(bad).Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid exact team-role binding intent admitted")
			}
		})
	}
	bad := r
	bad.IdempotencyKey = identity.IdempotencyKey{}
	if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
		t.Fatal("team assignment without original key admitted")
	}
	maximum := r
	maximum.OrganizationID, maximum.RoleID, maximum.TeamID = organization.ID(strings.Repeat("o", 128)), organization.ID(strings.Repeat("r", 128)), organization.ID(strings.Repeat("t", 128))
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("a", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.OrganizationVersion, maximum.RoleVersion, maximum.TeamVersion, maximum.BindingVersion = ^uint64(0)-1, ^uint64(0)-1, ^uint64(0)-1, ^uint64(0)-1
	if maximum.Validate() != nil || revokeTeamRoleOperation(maximum).Validate() != nil {
		t.Fatal("existing native incrementable team-binding bounds narrowed")
	}
	for _, version := range []uint64{0, 1, 7, ^uint64(0) - 1} {
		valid := r
		valid.BindingVersion = version
		if valid.Validate() != nil {
			t.Fatal("team assignment binding epoch narrowed")
		}
	}
}

func TestTeamRoleBindingOperationCustodyAndExistingRecovery(t *testing.T) {
	r := teamRoleBindingOperationRequest(t)
	r.BindingVersion = 1
	x := revokeTeamRoleOperation(r)
	for _, item := range []struct {
		value any
		label string
	}{{r, "AssignTeamDynamicRoleOperationRequest"}, {&r, "AssignTeamDynamicRoleOperationRequest"}, {x, "RevokeTeamDynamicRoleOperationRequest"}, {&x, "RevokeTeamDynamicRoleOperationRequest"}} {
		if _, err := json.Marshal(item.value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("team-role binding custody exported as JSON")
		}
		if _, err := item.value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("team-role binding custody exported as text")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, item.value) != "organization."+item.label+"(redacted)" {
				t.Fatal("team-role binding diagnostics exposed custody")
			}
		}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	// Raw team role commands already use role.assign/revoke with the actual
	// human actor as UserID. No team identity is a human recovery target.
	for _, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		d := op.Descriptor()
		recovery := organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", ActorID: "owner", ActorKind: authorization.SubjectUser, UserID: "owner", OperationID: d.OperationID, RecordID: "org", SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-team-role-binding"}}
		if err := recovery.Validate(); err != nil {
			t.Fatal("existing raw team-role recovery syntax narrowed", err)
		}
		for _, change := range []func(*organization.OperationRecoveryRequest){
			func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "foreign" },
			func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "" },
			func(r *organization.OperationRecoveryRequest) {
				r.Binding.ActorKind = authorization.SubjectServiceAccount
			},
			func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization-membership" },
			func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaVersion++ },
			func(r *organization.OperationRecoveryRequest) { r.Binding.PolicyVersion = 0 },
			func(r *organization.OperationRecoveryRequest) {
				r.Binding.OperationID = string(organization.GetDynamicRole)
			},
		} {
			bad := recovery
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("foreign/malformed or unsupported original binding admitted")
			}
		}
	}
}

func FuzzTeamRoleBindingOperationValidation(f *testing.F) {
	f.Add("reader", uint8(1), uint64(7), uint64(2), uint64(3), uint64(0))
	f.Add("member", uint8(1), uint64(1), uint64(1), uint64(1), uint64(1))
	f.Add("engineering", uint8(2), uint64(1), uint64(1), ^uint64(0), uint64(1))
	f.Add("bad value", uint8(3), uint64(0), ^uint64(0), uint64(0), ^uint64(0))
	f.Add("\xff", uint8(0), uint64(1), uint64(1), uint64(1), uint64(1))
	f.Fuzz(func(t *testing.T, value string, mode uint8, orgVersion, roleVersion, teamVersion, bindingVersion uint64) {
		if len(value) > 512 {
			return
		}
		r := teamRoleBindingOperationRequest(t)
		r.OrganizationVersion, r.RoleVersion, r.TeamVersion, r.BindingVersion = orgVersion, roleVersion, teamVersion, bindingVersion
		switch mode % 5 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.RoleID = organization.ID(value)
		case 2:
			r.TeamID = organization.ID(value)
		case 3:
			r.CorrelationID = value
		case 4:
			r.Authentication.TenantID = identity.TenantID(value)
		}
		valid := len(value) > 0 && len(value) <= 128 && utf8.ValidString(value) && orgVersion > 0 && orgVersion < ^uint64(0) && roleVersion > 0 && roleVersion < ^uint64(0) && teamVersion > 0 && teamVersion < ^uint64(0) && bindingVersion < ^uint64(0)
		for _, ch := range value {
			if ch <= 32 || ch == 127 {
				valid = false
			}
		}
		if mode%5 == 1 && organization.Role(value).Valid() {
			valid = false
		}
		if (r.Validate() == nil) != valid || (revokeTeamRoleOperation(r).Validate() == nil) != (valid && bindingVersion > 0) {
			t.Fatal("team-role binding syntax diverged from native epochs or exact selectors")
		}
	})
}
