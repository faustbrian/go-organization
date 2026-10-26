package organization_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func dynamicRoleOperationRequest(t testing.TB) organization.CreateDynamicRoleOperationRequest {
	t.Helper()
	r := teamCreateOperationRequest(t)
	return organization.CreateDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: "org", RoleID: "reader", OrganizationVersion: 7, Name: "Document reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "role-operation"}
}

func updateDynamicRoleOperation(r organization.CreateDynamicRoleOperationRequest) organization.UpdateDynamicRoleOperationRequest {
	return organization.UpdateDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: r.IdempotencyKey, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion, RoleVersion: 2, Name: r.Name, Statements: r.Statements, CorrelationID: r.CorrelationID}
}

func deleteDynamicRoleOperation(r organization.UpdateDynamicRoleOperationRequest) organization.DeleteDynamicRoleOperationRequest {
	return organization.DeleteDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion, RoleVersion: r.RoleVersion, CorrelationID: r.CorrelationID}
}

func TestDynamicRoleOperationRequestBounds(t *testing.T) {
	r := dynamicRoleOperationRequest(t)
	if err := r.Validate(); err != nil {
		t.Fatal("valid original-key create request rejected", err)
	}
	u := updateDynamicRoleOperation(r)
	if u.Validate() != nil || deleteDynamicRoleOperation(u).Validate() != nil {
		t.Fatal("valid update/delete rejected")
	}
	for name, change := range map[string]func(*organization.CreateDynamicRoleOperationRequest){
		"authentication": func(r *organization.CreateDynamicRoleOperationRequest) {
			r.Authentication = organization.Authentication{}
		},
		"org":                  func(r *organization.CreateDynamicRoleOperationRequest) { r.OrganizationID = "" },
		"role":                 func(r *organization.CreateDynamicRoleOperationRequest) { r.RoleID = "bad role" },
		"static owner":         func(r *organization.CreateDynamicRoleOperationRequest) { r.RoleID = "owner" },
		"static administrator": func(r *organization.CreateDynamicRoleOperationRequest) { r.RoleID = "administrator" },
		"static member":        func(r *organization.CreateDynamicRoleOperationRequest) { r.RoleID = "member" },
		"long role": func(r *organization.CreateDynamicRoleOperationRequest) {
			r.RoleID = organization.ID(strings.Repeat("r", 129))
		},
		"invalid utf8":       func(r *organization.CreateDynamicRoleOperationRequest) { r.RoleID = "\xff" },
		"zero org epoch":     func(r *organization.CreateDynamicRoleOperationRequest) { r.OrganizationVersion = 0 },
		"overflow org epoch": func(r *organization.CreateDynamicRoleOperationRequest) { r.OrganizationVersion = ^uint64(0) },
		"correlation":        func(r *organization.CreateDynamicRoleOperationRequest) { r.CorrelationID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) || !errors.Is(updateDynamicRoleOperation(bad).Validate(), organization.ErrInvalidInput) || !errors.Is(deleteDynamicRoleOperation(updateDynamicRoleOperation(bad)).Validate(), organization.ErrInvalidInput) {
				t.Fatal("invalid exact CRUD selectors admitted")
			}
		})
	}
	for _, version := range []uint64{0, ^uint64(0)} {
		bad := u
		bad.RoleVersion = version
		if bad.Validate() == nil || deleteDynamicRoleOperation(bad).Validate() == nil {
			t.Fatal("invalid role epoch admitted")
		}
	}
	for _, name := range []string{"", " padded ", "bad\nname", "\xff", strings.Repeat("n", 257)} {
		bad := r
		bad.Name = name
		if bad.Validate() == nil || updateDynamicRoleOperation(bad).Validate() == nil {
			t.Fatal("invalid role name admitted")
		}
	}
	bad := r
	bad.IdempotencyKey = identity.IdempotencyKey{}
	if bad.Validate() == nil || updateDynamicRoleOperation(bad).Validate() == nil {
		t.Fatal("missing original key admitted")
	}
	maximum := r
	maximum.OrganizationID, maximum.RoleID = organization.ID(strings.Repeat("o", 128)), organization.ID(strings.Repeat("r", 128))
	maximum.OrganizationVersion = ^uint64(0) - 1
	maximum.Name = strings.Repeat("n", 256)
	maxUpdate := updateDynamicRoleOperation(maximum)
	maxUpdate.RoleVersion = ^uint64(0) - 1
	if maximum.Validate() != nil || maxUpdate.Validate() != nil || deleteDynamicRoleOperation(maxUpdate).Validate() != nil {
		t.Fatal("native intrinsic bounds narrowed")
	}
}

func TestDynamicRoleOperationStatementIntentBounds(t *testing.T) {
	r := dynamicRoleOperationRequest(t)
	// Catalog membership is not neutral syntax: the actual native immutable
	// ceiling decides whether this syntactically safe permission exists.
	r.Statements[0].PermissionID = "not-in-a-catalog"
	if r.Validate() != nil {
		t.Fatal("neutral validator invented a permission catalog")
	}
	r.Statements = append(r.Statements, organization.RoleStatement{PermissionID: "not-in-a-catalog", ResourceID: "one", Effect: authorization.Deny})
	original := slices.Clone(r.Statements)
	if r.Validate() != nil || !reflect.DeepEqual(r.Statements, original) {
		t.Fatal("allow/deny coexistence or statement order changed")
	}
	for _, statements := range [][]organization.RoleStatement{nil, {}} {
		r.Statements = statements
		if r.Validate() != nil || updateDynamicRoleOperation(r).Validate() != nil {
			t.Fatal("empty native deny-all replacement rejected")
		}
	}
	for _, statement := range []organization.RoleStatement{
		{PermissionID: "", ResourceID: "one", Effect: authorization.Allow},
		{PermissionID: "bad permission", ResourceID: "one", Effect: authorization.Allow},
		{PermissionID: strings.Repeat("p", 129), ResourceID: "one", Effect: authorization.Allow},
		{PermissionID: "read", ResourceID: "", Effect: authorization.Allow},
		{PermissionID: "read", ResourceID: "*", Effect: authorization.Allow},
		{PermissionID: "read", ResourceID: "one?", Effect: authorization.Allow},
		{PermissionID: "read", ResourceID: "\xff", Effect: authorization.Allow},
		{PermissionID: "read", ResourceID: "one", Effect: authorization.Outcome(255)},
	} {
		r.Statements = []organization.RoleStatement{statement}
		if r.Validate() == nil || updateDynamicRoleOperation(r).Validate() == nil {
			t.Fatal("invalid intrinsic statement admitted")
		}
	}
	r.Statements = []organization.RoleStatement{original[0], original[0]}
	if r.Validate() == nil {
		t.Fatal("duplicate exact statement admitted")
	}
	r.Statements = make([]organization.RoleStatement, 65)
	for i := range r.Statements {
		r.Statements[i] = organization.RoleStatement{PermissionID: fmt.Sprintf("permission-%02d", i), ResourceID: "one", Effect: authorization.Allow}
	}
	if r.Validate() == nil {
		t.Fatal("more than 64 statements admitted")
	}
	r.Statements = make([]organization.RoleStatement, 16)
	for i := range r.Statements {
		r.Statements[i] = organization.RoleStatement{PermissionID: fmt.Sprintf("permission-%02d", i), ResourceID: authorization.ResourceID(strings.Repeat("<", 128)), Effect: authorization.Allow}
	}
	if r.Validate() == nil || updateDynamicRoleOperation(r).Validate() == nil {
		t.Fatal("JSON-escaped projection exceeded native byte ceiling")
	}
	// Fill a valid 64-statement projection to the exact existing native JSON
	// field limit, then cross it by one byte without crossing an ID bound.
	r.Statements = make([]organization.RoleStatement, 64)
	for i := range r.Statements {
		r.Statements[i] = organization.RoleStatement{PermissionID: fmt.Sprintf("permission-%02d", i), ResourceID: "r", Effect: authorization.Allow}
	}
	wire, err := json.Marshal(r.Statements)
	if err != nil {
		t.Fatal(err)
	}
	remaining := 8192 - len(wire)
	for i := range r.Statements {
		n := min(remaining, 127)
		r.Statements[i].ResourceID += authorization.ResourceID(strings.Repeat("r", n))
		remaining -= n
	}
	wire, err = json.Marshal(r.Statements)
	if remaining != 0 || err != nil || len(wire) != 8192 || r.Validate() != nil || updateDynamicRoleOperation(r).Validate() != nil {
		t.Fatal("exact encoded statement limit narrowed", len(wire), err)
	}
	for i := range r.Statements {
		if len(r.Statements[i].ResourceID) < 128 {
			r.Statements[i].ResourceID += "r"
			break
		}
	}
	if r.Validate() == nil || updateDynamicRoleOperation(r).Validate() == nil {
		t.Fatal("oversized encoded statement projection admitted")
	}
}

func TestDynamicRoleOperationCustodyAndOriginalRecovery(t *testing.T) {
	r := dynamicRoleOperationRequest(t)
	for _, item := range []struct {
		value any
		label string
	}{{r, "CreateDynamicRoleOperationRequest"}, {&r, "CreateDynamicRoleOperationRequest"}, {updateDynamicRoleOperation(r), "UpdateDynamicRoleOperationRequest"}, {deleteDynamicRoleOperation(updateDynamicRoleOperation(r)), "DeleteDynamicRoleOperationRequest"}} {
		if _, err := json.Marshal(item.value); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("CRUD credential/key/statement custody exported")
		}
		if _, err := item.value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("CRUD text custody exported")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if fmt.Sprintf(format, item.value) != "organization."+item.label+"(redacted)" {
				t.Fatal("CRUD diagnostics exposed custody")
			}
		}
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		d := op.Descriptor()
		recovery := organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: identity.CommandBinding{CommandID: id, TenantID: "tenant", ActorID: "owner", ActorKind: authorization.SubjectUser, UserID: "owner", OperationID: d.OperationID, RecordID: "org", SchemaID: d.SchemaID, SchemaVersion: d.SchemaVersion, PolicyID: "organization", PolicyVersion: 1, CorrelationID: "original-role"}}
		if err := recovery.Validate(); err != nil {
			t.Fatal("exact original CRUD binding rejected", err)
		}
		for _, change := range []func(*organization.OperationRecoveryRequest){
			func(r *organization.OperationRecoveryRequest) { r.Binding.UserID = "member" },
			func(r *organization.OperationRecoveryRequest) { r.Authentication.TenantID = "foreign" },
			func(r *organization.OperationRecoveryRequest) {
				r.Binding.ActorKind = authorization.SubjectServiceAccount
			},
			func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaID = "organization-membership" },
			func(r *organization.OperationRecoveryRequest) { r.Binding.SchemaVersion++ },
			func(r *organization.OperationRecoveryRequest) { r.Binding.PolicyVersion = 0 },
		} {
			bad := recovery
			change(&bad)
			if !errors.Is(bad.Validate(), organization.ErrInvalidInput) {
				t.Fatal("foreign/nonself or malformed original history admitted")
			}
		}
	}
}

func FuzzDynamicRoleOperationValidation(f *testing.F) {
	f.Add("read", "one", uint8(authorization.Allow), uint8(1), uint64(7))
	f.Add("read", "*", uint8(authorization.Deny), uint8(64), uint64(1))
	f.Add("", "\xff", uint8(255), uint8(65), ^uint64(0))
	f.Fuzz(func(t *testing.T, permission, resource string, effect, count uint8, epoch uint64) {
		if len(permission) > 256 || len(resource) > 256 {
			return
		}
		r := dynamicRoleOperationRequest(t)
		r.OrganizationVersion = epoch
		r.Statements = make([]organization.RoleStatement, int(count))
		for i := range r.Statements {
			r.Statements[i] = organization.RoleStatement{PermissionID: permission, ResourceID: authorization.ResourceID(resource), Effect: authorization.Outcome(effect)}
		}
		safe := func(s string) bool {
			if len(s) < 1 || len(s) > 128 || !utf8.ValidString(s) {
				return false
			}
			for _, c := range s {
				if c <= 32 || c == 127 {
					return false
				}
			}
			return true
		}
		valid := epoch > 0 && epoch < ^uint64(0) && count <= 1
		if count == 1 {
			valid = valid && safe(permission) && safe(resource) && !strings.ContainsAny(resource, "*?") && (authorization.Outcome(effect) == authorization.Allow || authorization.Outcome(effect) == authorization.Deny)
		}
		if (r.Validate() == nil) != valid || (updateDynamicRoleOperation(r).Validate() == nil) != valid {
			t.Fatal("intrinsic statement/epoch syntax diverged")
		}
	})
}
