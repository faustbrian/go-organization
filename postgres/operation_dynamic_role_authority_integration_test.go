//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
)

func TestDynamicRoleOperationDeleteAuthorizesBeforeClassification(t *testing.T) {
	for _, mode := range []string{"action denied", "query denied", "late role"} {
		t.Run(mode, func(t *testing.T) {
			f := dynamicRoleOperationFixture(t, true)
			r := createRoleOperationRequest(t, f)
			plain := slugNativeOperationService(t, f.service)
			if _, err := plain.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			u := updateRoleOperationRequest(t, r, 3, 1)
			if _, err := plain.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
			x := deleteRoleOperationRequest(u)
			x.OrganizationVersion = 5
			if _, err := plain.DeleteDynamicRole(f.ctx, x, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			policy := &dynamicRoleOperationPolicy{denyAction: mode == "action denied", denyQuery: mode == "query denied"}
			withdrawn := false
			if mode == "late role" {
				policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if withdrawn || c.Request.Resource.Type != "organization" {
						return nil
					}
					p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-role-delete-lookup-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := f.service.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
			}
			if mode != "query denied" {
				x.RoleVersion++
			}
			out, err := leaveOperationPolicyFacade(t, f, policy, nil).DeleteDynamicRole(f.ctx, x, "127.0.0.1")
			if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || !policy.actionSeen.Load() || mode == "late role" && !withdrawn {
				t.Fatal("role deletion classified history without current actual action authority", err)
			}
		})
	}
}

func TestDynamicRoleOperationRecoveryFencesFinalCallbacks(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole} {
		for _, stage := range []string{"management", "query"} {
			t.Run(string(op)+"/"+stage, func(t *testing.T) {
				f := dynamicRoleOperationFixture(t, true)
				r := createRoleOperationRequest(t, f)
				f.add(t, "org-test-basic", "second", organization.RoleOwner, 2)
				r.OrganizationVersion = 3
				plain := leaveOperationPolicyFacade(t, f, new(dynamicRoleOperationPolicy), nil)
				original, err := plain.CreateDynamicRole(f.ctx, r, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				u := updateRoleOperationRequest(t, r, 4, 1)
				epoch := uint64(4)
				if op != organization.CreateDynamicRole {
					original, err = plain.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
					epoch = 5
				}
				if err == nil && op == organization.DeleteDynamicRole {
					original, err = plain.DeleteDynamicRole(f.ctx, deleteRoleOperationRequest(u), "127.0.0.1")
					epoch = 6
				}
				if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
				calls, required := 0, 1
				if op == organization.DeleteDynamicRole {
					required = 2
				}
				managementSeen, querySeen, withdrawn := false, false, false
				policy := new(dynamicRoleOperationPolicy)
				policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if withdrawn || c.Request.Action != authorization.Action(op) {
						return nil
					}
					switch string(c.Request.Resource.Type) {
					case "organization":
						calls++
						if calls < required {
							return nil
						}
						managementSeen = true
						if stage != "management" {
							return nil
						}
					case "identity.user":
						if stage != "query" || !managementSeen {
							return nil
						}
						querySeen = true
					default:
						return nil
					}
					p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-original-role-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := f.service.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
				s := leaveOperationPolicyFacade(t, f, policy, nil)
				var out organization.StoreResult
				switch op {
				case organization.CreateDynamicRole:
					out, err = s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
				case organization.UpdateDynamicRole:
					out, err = s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
				case organization.DeleteDynamicRole:
					out, err = s.DeleteDynamicRole(f.ctx, deleteRoleOperationRequest(u), "127.0.0.1")
				}
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("late authority callback disclosed original role outcome", err)
				}
			})
		}
	}
}

func TestDynamicRoleOperationForeignAndWithdrawnManagers(t *testing.T) {
	f := dynamicRoleOperationFixture(t, true)
	r := createRoleOperationRequest(t, f)
	s := slugNativeOperationService(t, f.service)
	original, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, actor := range []string{"member", "outsider"} {
		bad := r
		bad.Authentication = f.auth("org-test-basic", actor)
		if out, err := s.CreateDynamicRole(f.ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager adopted custom-role history", err)
		}
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: bad.Authentication, Binding: original.Receipt.Binding}); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("different principal recovered owner history", err)
		}
	}
	foreign := r
	foreign.Authentication = f.auth("org-test-scope", "owner")
	if out, err := s.CreateDynamicRole(f.ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted custom-role history", err)
	}
	unknown := r
	unknown.OrganizationVersion = 3
	unknown.RoleID = "unknown"
	unknown.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("unknown-role-permission"))
	unknown.Statements = []organization.RoleStatement{{PermissionID: "not-registered", ResourceID: "one", Effect: authorization.Allow}}
	if _, err := s.CreateDynamicRole(f.ctx, unknown, "127.0.0.1"); !errors.Is(err, organization.ErrInvalidInput) {
		t.Fatal("facade bypassed actual immutable catalog", err)
	}
}
