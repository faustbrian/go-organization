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

func roleBindingOperationRequest(t testing.TB) organization.AssignDynamicRoleOperationRequest {
	t.Helper()
	r := teamCreateOperationRequest(t)
	return organization.AssignDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: "org", RoleID: "reader", UserID: "member", OrganizationVersion: 7, RoleVersion: 2, OrganizationMemberVersion: 3, CorrelationID: "direct-role-assignment"}
}

func revokeRoleOperation(r organization.AssignDynamicRoleOperationRequest) organization.RevokeDynamicRoleOperationRequest {
	return organization.RevokeDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, BindingVersion: r.BindingVersion, CorrelationID: r.CorrelationID}
}

func TestRoleBindingOperationExactIntentBounds(t *testing.T) {
	r := roleBindingOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid original-key direct assignment rejected", err)
	}
	if !errors.Is(revokeRoleOperation(r).Validate(), organization.ErrInvalidInput) {
		t.Fatal("zero binding cannot identify an original revocation")
	}
	r.BindingVersion = 4
	if err := revokeRoleOperation(r).Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*organization.AssignDynamicRoleOperationRequest){
		"authentication": func(r *organization.AssignDynamicRoleOperationRequest) {
			r.Authentication = organization.Authentication{}
		},
		"tenant":       func(r *organization.AssignDynamicRoleOperationRequest) { r.Authentication.TenantID = "foreign tenant" },
		"organization": func(r *organization.AssignDynamicRoleOperationRequest) { r.OrganizationID = "" },
		"long organization": func(r *organization.AssignDynamicRoleOperationRequest) {
			r.OrganizationID = organization.ID(strings.Repeat("o", 129))
		},
		"role":                 func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleID = "bad role" },
		"static owner":         func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleID = "owner" },
		"static administrator": func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleID = "administrator" },
		"static member":        func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleID = "member" },
		"invalid utf8":         func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleID = "\xff" },
		"target":               func(r *organization.AssignDynamicRoleOperationRequest) { r.UserID = "member\n" },
		"long target": func(r *organization.AssignDynamicRoleOperationRequest) {
			r.UserID = identity.UserID(strings.Repeat("u", 129))
		},
		"zero organization epoch":        func(r *organization.AssignDynamicRoleOperationRequest) { r.OrganizationVersion = 0 },
		"overflow organization epoch":    func(r *organization.AssignDynamicRoleOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"zero role epoch":                func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleVersion = 0 },
		"overflow role epoch":            func(r *organization.AssignDynamicRoleOperationRequest) { r.RoleVersion = ^uint64(0) },
		"zero observed membership epoch": func(r *organization.AssignDynamicRoleOperationRequest) { r.OrganizationMemberVersion = 0 },
		"overflow binding epoch":         func(r *organization.AssignDynamicRoleOperationRequest) { r.BindingVersion = ^uint64(0) },
		"correlation":                    func(r *organization.AssignDynamicRoleOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) || !errors.Is(revokeRoleOperation(bad).Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid exact direct-binding intent admitted")
			}
		})
	}
	bad := r
	bad.IdempotencyKey = identity.IdempotencyKey{}
	if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
		t.Fatal("assignment without original key admitted")
	}
	maximum := r
	maximum.OrganizationID, maximum.RoleID = organization.ID(strings.Repeat("o", 128)), organization.ID(strings.Repeat("r", 128))
	maximum.UserID = identity.UserID(strings.Repeat("u", 128))
	maximum.Authentication.TenantID = identity.TenantID(strings.Repeat("t", 128))
	maximum.CorrelationID = strings.Repeat("c", 128)
	maximum.OrganizationVersion, maximum.RoleVersion, maximum.BindingVersion = ^uint64(0)-1, ^uint64(0)-1, ^uint64(0)-1
	maximum.OrganizationMemberVersion = ^uint64(0)
	if maximum.Validate() != nil || revokeRoleOperation(maximum).Validate() != nil {
		t.Fatal("existing native bounds or observed membership epoch narrowed")
	}
	// Both initial assignment and reassignment use a caller-observed binding
	// epoch; positive syntax does not say whether it is live or a tombstone.
	for _, version := range []uint64{0, 1, 7, ^uint64(0) - 1} {
		valid := r
		valid.BindingVersion = version
		if valid.Validate() != nil {
			t.Fatal("assignment binding epoch narrowed")
		}
	}
}

func TestRoleBindingOperationCustodyAndTargetRecovery(t *testing.T) {
	r := roleBindingOperationRequest(t)
	r.BindingVersion = 1
	x := revokeRoleOperation(r)
	for _, item := range []struct {
		value any
		label string
	}{{r, "AssignDynamicRoleOperationRequest"}, {&r, "AssignDynamicRoleOperationRequest"}, {x, "RevokeDynamicRoleOperationRequest"}, {&x, "RevokeDynamicRoleOperationRequest"}} {
		if _, err := json.Marshal(item.value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("direct-binding custody exported as JSON")
		}
		if _, err := item.value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("direct-binding custody exported as text")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, item.value) != "organization."+item.label+"(redacted)" {
				t.Fatal("direct-binding diagnostics exposed custody")
			}
		}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		d := op.Descriptor()
		recovery := organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", ActorID: "owner", ActorKind: authorization.SubjectUser, UserID: "member", OperationID: d.OperationID, RecordID: "org", SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-role-binding"}}
		for _, target := range []identity.UserID{"member", "owner"} {
			valid := recovery
			valid.Binding.UserID = target
			if err := valid.Validate(); err != nil {
				t.Fatal("native direct-target recovery syntax narrowed", err)
			}
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

func FuzzRoleBindingOperationValidation(f *testing.F) {
	f.Add("reader", uint8(1), uint64(7), uint64(2), uint64(3), uint64(0))
	f.Add("member", uint8(1), uint64(1), uint64(1), ^uint64(0), uint64(1))
	f.Add("member", uint8(2), uint64(1), uint64(1), ^uint64(0), uint64(1))
	f.Add("bad value", uint8(3), uint64(0), ^uint64(0), uint64(0), ^uint64(0))
	f.Add("\xff", uint8(0), uint64(1), uint64(1), uint64(1), uint64(1))
	f.Fuzz(func(t *testing.T, value string, mode uint8, orgVersion, roleVersion, memberVersion, bindingVersion uint64) {
		if len(value) > 512 {
			return
		}
		r := roleBindingOperationRequest(t)
		r.OrganizationVersion, r.RoleVersion, r.OrganizationMemberVersion, r.BindingVersion = orgVersion, roleVersion, memberVersion, bindingVersion
		switch mode % 5 {
		case 0:
			r.OrganizationID = organization.ID(value)
		case 1:
			r.RoleID = organization.ID(value)
		case 2:
			r.UserID = identity.UserID(value)
		case 3:
			r.CorrelationID = value
		case 4:
			r.Authentication.TenantID = identity.TenantID(value)
		}
		valid := len(value) > 0 && len(value) <= 128 && utf8.ValidString(value) && orgVersion > 0 && orgVersion < ^uint64(0) && roleVersion > 0 && roleVersion < ^uint64(0) && memberVersion > 0 && bindingVersion < ^uint64(0)
		for _, ch := range value {
			if ch <= 32 || ch == 127 {
				valid = false
			}
		}
		if mode%5 == 1 && organization.Role(value).Valid() {
			valid = false
		}
		if (r.Validate() == nil) != valid || (revokeRoleOperation(r).Validate() == nil) != (valid && bindingVersion > 0) {
			t.Fatal("direct-role binding syntax diverged from native epochs or exact selectors")
		}
	})
}
