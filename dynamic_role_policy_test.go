package organization_test

import (
	"errors"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	"testing"
	"time"
)

func policyRoleConfig() organization.DynamicRoleConfig {
	return organization.DynamicRoleConfig{Version: 1, MaximumRoles: 2, Catalog: []organization.Permission{{ID: "read", Action: "document.read", ResourceType: "document"}}}
}
func TestDynamicRolePreparedIntentOwnsRequestAndProjection(t *testing.T) {
	config := policyRoleConfig()
	s, a, _, owner, _ := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{}, config)
	owner.view.Target = organization.Member{}
	owner.view.TargetUser = identity.User{}
	owner.view.DynamicRole = organization.DynamicRole{ID: "reader", OrganizationID: "org", TenantID: "tenant-a"}
	statements := []organization.RoleStatement{{PermissionID: "read", ResourceID: "one", Effect: authorization.Allow}}
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.PrepareCreateDynamicRole(t.Context(), organization.DynamicRoleRequest{Authentication: a, CommandID: id, OrganizationID: "org", RoleID: "reader", OrganizationVersion: 7, Name: "Reader", Statements: statements, CorrelationID: "roles"})
	if e != nil {
		t.Fatal(e)
	}
	config.Catalog[0].Action = "document.delete"
	statements[0].Effect = authorization.Deny
	x, e := c.Input()
	if e != nil {
		t.Fatal(e)
	}
	x.DynamicRole.Statements[0].ResourceID = "two"
	x.DynamicRoles.Catalog[0].Action = "document.delete"
	x, e = c.Input()
	if e != nil || x.DynamicRole.Statements[0].ResourceID != "one" || x.DynamicRole.Statements[0].Effect != authorization.Allow || x.DynamicRoles.Catalog[0].Action != "document.read" {
		t.Fatal("retained role intent was mutable", e)
	}
}

func TestDynamicRolePermissionRevalidatesPolicyAndSession(t *testing.T) {
	for _, variant := range []string{"allow", "epoch-during-policy", "member-during-policy", "expires-during-policy", "policy-denied", "unknown-statement"} {
		t.Run(variant, func(t *testing.T) {
			s, a, at, owner, policy := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{}, policyRoleConfig())
			owner.view.DynamicRoles = []organization.DynamicRole{{ID: "reader", TenantID: "tenant-a", OrganizationID: "org", Version: 1, Name: "Reader", Statements: []organization.RoleStatement{{PermissionID: "read", ResourceID: "one", Effect: authorization.Allow}}}}
			switch variant {
			case "epoch-during-policy":
				policy.beforeReturn = func() { owner.view.Organization.Version++ }
			case "member-during-policy":
				policy.beforeReturn = func() { owner.view.Actor.Active = false }
			case "expires-during-policy":
				policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
			case "policy-denied":
				policy.outcome = authorization.Deny
			case "unknown-statement":
				owner.view.DynamicRoles[0].Statements[0].PermissionID = "unknown"
			}
			d, e := s.CheckPermission(t.Context(), organization.PermissionCheckRequest{Authentication: a, OrganizationID: "org", OrganizationVersion: 7, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "roles"})
			if variant == "allow" {
				if e != nil || d.Outcome != authorization.Allow || d.Revision != 7 {
					t.Fatal("current registered role denied", e)
				}
			} else if !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("stale or unknown authority allowed", e)
			}
		})
	}
}

func TestDynamicRoleBindingReadRejectsForeignMalformedAndLateMetadata(t *testing.T) {
	for _, variant := range []string{"absent", "live", "tombstone", "foreign-binding-tenant", "foreign-binding-org", "foreign-binding-role", "foreign-binding-user", "malformed-absent", "foreign-target-user", "missing-target-version", "late-epoch", "late-member", "late-session"} {
		t.Run(variant, func(t *testing.T) {
			s, a, at, owner, policy := policyFixtureConfig(t, organization.TeamConfig{}, organization.DomainConfig{}, policyRoleConfig())
			owner.view.DynamicRole = organization.DynamicRole{ID: "reader", OrganizationID: "org", TenantID: "tenant-a", Name: "Reader", Version: 1}
			owner.view.RoleBinding = organization.RoleBinding{RoleID: "reader", OrganizationID: "org", TenantID: "tenant-a", UserID: "target", Version: 3, OrganizationMemberVersion: 2, Active: true}
			switch variant {
			case "absent":
				owner.view.RoleBinding.Version = 0
				owner.view.RoleBinding.OrganizationMemberVersion = 0
				owner.view.RoleBinding.Active = false
			case "tombstone":
				owner.view.RoleBinding.Active = false
			case "foreign-binding-tenant":
				owner.view.RoleBinding.TenantID = "foreign"
			case "foreign-binding-org":
				owner.view.RoleBinding.OrganizationID = "foreign"
			case "foreign-binding-role":
				owner.view.RoleBinding.RoleID = "foreign"
			case "foreign-binding-user":
				owner.view.RoleBinding.UserID = "foreign"
			case "malformed-absent":
				owner.view.RoleBinding.Version = 0
			case "foreign-target-user":
				owner.view.TargetUser.ID = "foreign"
			case "missing-target-version":
				owner.view.Target.Version = 0
			case "late-epoch":
				policy.beforeReturn = func() { owner.view.Organization.Version++ }
			case "late-member":
				policy.beforeReturn = func() { owner.view.Actor.Active = false }
			case "late-session":
				policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
			}
			got, e := s.GetDynamicRole(t.Context(), organization.DynamicRoleReadRequest{Authentication: a, OrganizationID: "org", RoleID: "reader", TargetUserID: "target", CorrelationID: "binding-read"})
			if variant == "absent" || variant == "live" || variant == "tombstone" {
				if e != nil || got.Target.UserID != "target" || got.RoleBinding.UserID != "target" {
					t.Fatal("valid current binding metadata denied", e)
				}
			} else if !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("foreign, malformed or stale binding metadata disclosed", e)
			}
		})
	}
}
