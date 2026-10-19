package organization_test

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestUpdateMemberFreezesExactStaticRoleTransition(t *testing.T) {
	s, a, _, owner, policy := policyFixture(t)
	r := memberRequest(t, a)
	r.Role = organization.RoleAdministrator
	c, err := s.PrepareUpdateMember(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	x, err := c.Input()
	if err != nil || x.Operation != organization.UpdateMember || x.Target != owner.view.Target || x.Actor != owner.view.Actor || x.Role != r.Role || x.Binding.UserID != r.UserID || x.Binding.ActorID != "actor" || x.Organization.Version != 7 || owner.writes != 0 {
		t.Fatal("role update lost exact actor, target or role intent", err)
	}
	if policy.last.Request.Action != authorization.Action(organization.UpdateMember) || policy.last.Request.Resource.ID != "org" || !reflect.DeepEqual(policy.last.Request.Resource.Attributes["organization.policy-version"], authorization.StringValue("7")) {
		t.Fatal("role update did not use current organization policy")
	}
	got, err := s.Execute(t.Context(), c, outcomeOwner(func(c organization.Command) (organization.StoreResult, error) {
		got, err := owner.Execute(t.Context(), c)
		got.Receipt.AuditEventID = "role-update-audit"
		return got, err
	}))
	if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 7 || got.Receipt.Feature.AfterVersion != 8 {
		t.Fatal("role update receipt did not describe exact organization transition", err)
	}
}

func TestUpdateMemberRejectsUnauthorizedStaleAndUnsafeRoles(t *testing.T) {
	for _, scenario := range []string{"member-actor", "removed-actor", "administrator-owner-target", "administrator-owner-grant", "administrator-self-owner", "last-owner", "noop", "unknown-role", "zero-member-version", "overflow-member-version", "stale-member", "stale-org", "removed-target", "foreign-target", "foreign-user", "suspended-target", "zero-target-authority", "unknown-target-role", "denied-policy", "policy-expired-session"} {
		t.Run(scenario, func(t *testing.T) {
			s, a, clock, owner, policy := policyFixture(t)
			r := memberRequest(t, a)
			r.Role = organization.RoleMember
			want := organization.ErrForbidden
			switch scenario {
			case "member-actor":
				owner.view.Actor.Role = organization.RoleMember
			case "removed-actor":
				owner.view.Actor.Active = false
			case "administrator-owner-target":
				owner.view.Actor.Role = organization.RoleAdministrator
			case "administrator-owner-grant":
				owner.view.Actor.Role, owner.view.Target.Role, r.Role = organization.RoleAdministrator, organization.RoleMember, organization.RoleOwner
			case "administrator-self-owner":
				owner.view.Actor.Role = organization.RoleAdministrator
				owner.view.Target, owner.view.TargetUser.ID, r.UserID = owner.view.Actor, "actor", "actor"
				r.MemberVersion, r.Role = 1, organization.RoleOwner
			case "last-owner":
				owner.view.OwnerCount, want = 1, organization.ErrLastOwner
			case "noop":
				r.Role, want = organization.RoleOwner, organization.ErrConflict
			case "unknown-role":
				r.Role, want = "custom-admin", organization.ErrInvalidInput
			case "zero-member-version":
				r.MemberVersion, want = 0, organization.ErrInvalidInput
			case "overflow-member-version":
				r.MemberVersion, want = ^uint64(0), organization.ErrInvalidInput
			case "stale-member":
				r.MemberVersion, want = 1, organization.ErrConflict
			case "stale-org":
				r.OrganizationVersion, want = 6, organization.ErrConflict
			case "removed-target":
				owner.view.Target.Active = false
			case "foreign-target":
				owner.view.Target.OrganizationID = "other"
			case "foreign-user":
				owner.view.TargetUser.TenantID = "other"
			case "suspended-target":
				owner.view.TargetUser.Status = identity.StatusSuspended
			case "zero-target-authority":
				owner.view.Target.AuthorizationVersion = 0
			case "unknown-target-role":
				owner.view.Target.Role = "custom-owner"
			case "denied-policy":
				policy.outcome = authorization.Deny
			case "policy-expired-session":
				policy.beforeReturn = func() { clock.now = clock.now.Add(30 * time.Second) }
			}
			if c, err := s.PrepareUpdateMember(t.Context(), r); !errors.Is(err, want) || c != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("unsafe role transition was prepared", err, want)
			}
		})
	}
}

func TestUpdateMemberAdministratorCanChangeNonownerAndDemoteSelf(t *testing.T) {
	for _, self := range []bool{false, true} {
		s, a, _, owner, _ := policyFixture(t)
		owner.view.Actor.Role = organization.RoleAdministrator
		r := memberRequest(t, a)
		owner.view.Target.Role, r.Role = organization.RoleMember, organization.RoleAdministrator
		if self {
			owner.view.Target, owner.view.TargetUser.ID, r.UserID = owner.view.Actor, "actor", "actor"
			r.MemberVersion, r.Role = 1, organization.RoleMember
		}
		if _, err := s.PrepareUpdateMember(t.Context(), r); err != nil {
			t.Fatal("authorized static administrator role transition denied", err)
		}
	}
}
