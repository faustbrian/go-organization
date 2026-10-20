package organization_test

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func FuzzTeamRoleRequestBoundary(f *testing.F) {
	for _, id := range []string{"engineering", "", "foreign", "bad team", "\x00", strings.Repeat("x", 129), "Équipe"} {
		f.Add(id)
	}
	f.Fuzz(func(t *testing.T, id string) {
		if len(id) > 512 {
			return
		}
		c := policyRoleConfig()
		c.TeamBindingsVersion = 1
		s, a, _, owner, _ := policyFixtureConfig(t, organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}, organization.DomainConfig{}, c)
		owner.view.Team = organization.Team{ID: "engineering", OrganizationID: "org", TenantID: "tenant-a", Name: "Engineering", Version: 3}
		owner.view.DynamicRole = organization.DynamicRole{ID: "reader", OrganizationID: "org", TenantID: "tenant-a", Name: "Reader", Version: 1}
		owner.view.TeamRoleBinding = organization.TeamRoleBinding{TeamID: "engineering", RoleID: "reader", OrganizationID: "org", TenantID: "tenant-a"}
		command, e := identity.NewCommandID()
		if e != nil {
			t.Fatal(e)
		}
		_, e = s.PrepareAssignTeamDynamicRole(t.Context(), organization.TeamRoleBindingRequest{Authentication: a, CommandID: command, OrganizationID: "org", RoleID: "reader", TeamID: organization.ID(id), OrganizationVersion: 7, RoleVersion: 1, TeamVersion: 3, CorrelationID: "team-role-boundary"})
		valid := len(id) > 0 && len(id) <= 128 && utf8.ValidString(id)
		for _, r := range id {
			if r <= ' ' || r == 127 {
				valid = false
			}
		}
		if !valid {
			if !errors.Is(e, organization.ErrInvalidInput) || owner.reads != 0 {
				t.Fatal("invalid team target reached owner", e)
			}
		} else if id == "engineering" {
			if e != nil {
				t.Fatal("valid team target denied", e)
			}
		} else if !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("foreign team projection accepted", e)
		}
	})
}

func TestTeamRoleDisabledAndMixedTargetsFailClosed(t *testing.T) {
	s, a, _, owner, _ := policyFixture(t)
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.PrepareAssignTeamDynamicRole(t.Context(), organization.TeamRoleBindingRequest{Authentication: a, CommandID: id, OrganizationID: "org", RoleID: "reader", TeamID: "engineering", OrganizationVersion: 7, RoleVersion: 1, TeamVersion: 1, CorrelationID: "disabled"}); !errors.Is(e, organization.ErrInvalidInput) || owner.reads != 0 {
		t.Fatal("disabled team role reached storage", e)
	}
	c := policyRoleConfig()
	c.TeamBindingsVersion = 1
	s, a, _, owner, _ = policyFixtureConfig(t, organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}, organization.DomainConfig{}, c)
	for _, r := range []organization.DynamicRoleReadRequest{{Authentication: a, OrganizationID: "org", RoleID: "reader", TargetUserID: "target", TargetTeamID: "engineering", CorrelationID: "mixed"}, {Authentication: a, OrganizationID: "org", TargetTeamID: "engineering", Limit: 10, CorrelationID: "list"}} {
		if r.RoleID != "" {
			_, e = s.GetDynamicRole(t.Context(), r)
		} else {
			_, e = s.ListDynamicRoles(t.Context(), r)
		}
		if !errors.Is(e, organization.ErrInvalidInput) || owner.reads != 0 {
			t.Fatal("ambiguous/list team selector reached storage", e)
		}
	}
}
