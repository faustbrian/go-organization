package organization_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func leaveRequest(t *testing.T, a organization.Authentication) organization.LeaveRequest {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return organization.LeaveRequest{Authentication: a, CommandID: id, OrganizationID: "org", OrganizationVersion: 7, CorrelationID: "self-leave"}
}

func TestLeaveBindsAuthenticatedSelfForEveryStaticRole(t *testing.T) {
	for _, role := range []organization.Role{organization.RoleMember, organization.RoleAdministrator, organization.RoleOwner} {
		t.Run(string(role), func(t *testing.T) {
			s, a, _, owner, policy := policyFixture(t)
			owner.view.Actor.Role = role
			owner.view.Target = owner.view.Actor
			owner.view.TargetUser = identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 3}
			r := leaveRequest(t, a)
			c, err := s.PrepareLeaveMember(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			x, err := c.Input()
			if err != nil || x.Operation != organization.LeaveMember || x.Binding.OperationID != "identity.organization.member.leave" || x.Binding.ActorID != "actor" || x.Binding.UserID != "actor" || x.Target != x.Actor || x.TargetUser.ID != "actor" || x.Organization.Version != 7 || x.Role != "" {
				t.Fatal("leave substituted target, role, or original binding", err)
			}
			if policy.last.Request.Action != authorization.Action(organization.LeaveMember) || policy.last.Request.Resource.ID != "org" {
				t.Fatal("leave aliased management policy")
			}
			result, err := s.Execute(t.Context(), c, outcomeOwner(func(command organization.Command) (organization.StoreResult, error) {
				result, err := owner.Execute(t.Context(), command)
				result.Receipt.AuditEventID = "leave-audit"
				return result, err
			}))
			if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.MemberID != "actor" || result.Receipt.Feature.BeforeVersion != 7 || result.Receipt.Feature.AfterVersion != 8 {
				t.Fatal("leave lost original outcome", err)
			}
		})
	}
}

func TestLeaveRejectsUnsafeOrForeignAuthority(t *testing.T) {
	for _, variant := range []string{"zero", "overflow", "stale", "last-owner", "removed", "foreign-org", "foreign-self", "foreign-user", "suspended-self", "wrong-self", "inconsistent-self", "policy", "expired", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			s, a, at, owner, policy := policyFixture(t)
			owner.view.Target = owner.view.Actor
			owner.view.TargetUser = identity.User{ID: "actor", TenantID: "tenant-a", Status: identity.StatusActive, Version: 3}
			r := leaveRequest(t, a)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := organization.ErrForbidden
			switch variant {
			case "zero":
				r.OrganizationVersion = 0
				want = organization.ErrInvalidInput
			case "overflow":
				r.OrganizationVersion = ^uint64(0)
				want = organization.ErrInvalidInput
			case "stale":
				r.OrganizationVersion--
				want = organization.ErrConflict
			case "last-owner":
				owner.view.OwnerCount = 1
				want = organization.ErrLastOwner
			case "removed":
				owner.view.Actor.Active = false
			case "foreign-org":
				owner.view.Organization.TenantID = "other"
			case "foreign-self":
				owner.view.Target.TenantID = "other"
			case "foreign-user":
				owner.view.TargetUser.TenantID = "other"
			case "suspended-self":
				owner.view.TargetUser.Status = identity.StatusSuspended
			case "wrong-self":
				owner.view.Target.UserID = "target"
			case "inconsistent-self":
				owner.view.Target.Version++
			case "policy":
				policy.outcome = authorization.Deny
			case "expired":
				policy.beforeReturn = func() { at.now = at.now.Add(20 * time.Second) }
			case "canceled":
				policy.beforeReturn = cancel
				want = context.Canceled
			}
			c, err := s.PrepareLeaveMember(ctx, r)
			if !errors.Is(err, want) || c != (organization.Command{}) || owner.writes != 0 {
				t.Fatal("unsafe leave admitted", err)
			}
		})
	}
}
