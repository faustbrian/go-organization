package organization

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
)

func TestDynamicRoleCatalogAndDenyPrecedence(t *testing.T) {
	c := DynamicRoleConfig{Version: 1, MaximumRoles: 4, Catalog: []Permission{{ID: "invoice-read", Action: "invoice.read", ResourceType: "invoice"}}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	role := DynamicRole{ID: "reader", Statements: []RoleStatement{{PermissionID: "invoice-read", ResourceID: "invoice-1", Effect: authorization.Allow}}}
	request := authorization.Request{Tenant: "tenant", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "member"}, Action: "invoice.read", Resource: authorization.Resource{Type: "invoice", ID: "invoice-1"}}
	decision, err := evaluateRoles(context.Background(), c, []DynamicRole{role}, request, 7)
	if err != nil || decision.Outcome != authorization.Allow || decision.Revision != 7 {
		t.Fatalf("registered exact permission: %+v %v", decision, err)
	}
	role.Statements = append(role.Statements, RoleStatement{PermissionID: "invoice-read", ResourceID: "invoice-1", Effect: authorization.Deny})
	decision, err = evaluateRoles(context.Background(), c, []DynamicRole{role}, request, 8)
	if err != nil || decision.Outcome != authorization.Deny {
		t.Fatalf("explicit deny lost: %+v %v", decision, err)
	}
	role.Statements[0].PermissionID = "unknown"
	if _, err = evaluateRoles(context.Background(), c, []DynamicRole{role}, request, 8); !errors.Is(err, ErrForbidden) {
		t.Fatal("unknown stored statement granted access", err)
	}
	c.Catalog[0].Action = authorization.Action(CreateDynamicRole)
	if err = c.Validate(); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("custom role expanded management authority", err)
	}
}

func TestDynamicRoleCommandProjectionCannotMutateOriginal(t *testing.T) {
	catalog := []Permission{{ID: "read", Action: "document.read", ResourceType: "document"}}
	statements := []RoleStatement{{PermissionID: "read", ResourceID: "one", Effect: authorization.Allow}}
	c := Command{state: &commandState{input: CommandInput{DynamicRole: DynamicRole{Statements: statements}, DynamicRoles: DynamicRoleConfig{Version: 1, MaximumRoles: 1, Catalog: catalog}}}}
	x, e := c.Input()
	if e != nil {
		t.Fatal(e)
	}
	x.DynamicRole.Statements[0].Effect = authorization.Deny
	x.DynamicRoles.Catalog[0].Action = "document.delete"
	again, e := c.Input()
	if e != nil || again.DynamicRole.Statements[0].Effect != authorization.Allow || again.DynamicRoles.Catalog[0].Action != "document.read" {
		t.Fatal("projection changed retained command intent", e)
	}
}

func FuzzDynamicRoleStatementBoundary(f *testing.F) {
	f.Add("read", "one", uint8(authorization.Allow))
	f.Add("unknown", "one", uint8(authorization.Allow))
	f.Add("read", "*", uint8(authorization.Deny))
	f.Add("read", "", uint8(authorization.Allow))
	f.Fuzz(func(t *testing.T, permission, resource string, effect uint8) {
		if len(permission) > 256 || len(resource) > 256 {
			return
		}
		c := DynamicRoleConfig{Version: 1, MaximumRoles: 1, Catalog: []Permission{{ID: "read", Action: "document.read", ResourceType: "document"}}}
		s := RoleStatement{PermissionID: permission, ResourceID: authorization.ResourceID(resource), Effect: authorization.Outcome(effect)}
		valid := permission == "read" && safeID(resource) && !strings.ContainsAny(resource, "*?") && (s.Effect == authorization.Allow || s.Effect == authorization.Deny)
		if (ValidateRoleStatements(c, []RoleStatement{s}) == nil) != valid {
			t.Fatal("invalid statement admitted or valid exact statement rejected")
		}
	})
}
