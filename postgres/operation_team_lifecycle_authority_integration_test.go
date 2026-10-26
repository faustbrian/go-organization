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

type teamLifecycleOperationPolicy struct {
	before                func(context.Context, authorization.DecisionContext) error
	denyAction, denyQuery bool
	actionSeen            bool
}

func (p *teamLifecycleOperationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	if c.Request.Action == authorization.Action(organization.CreateTeam) || c.Request.Action == authorization.Action(organization.UpdateTeam) || c.Request.Action == authorization.Action(organization.DeleteTeam) {
		if c.Request.Resource.Type == "organization" {
			p.actionSeen = true
			if p.denyAction {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
			}
		}
		if c.Request.Resource.Type == "identity.user" && p.denyQuery {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
		}
		if p.before != nil {
			if err := p.before(ctx, c); err != nil {
				return authorization.Decision{}, err
			}
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestTeamLifecycleOperationDeleteAuthorizesBeforeClassification(t *testing.T) {
	for _, mode := range []string{"action denied", "query denied", "late role"} {
		t.Run(mode, func(t *testing.T) {
			f := teamLifecycleOperationFixture(t, true)
			r := teamLifecycleOperationRequest(t, f)
			plain := slugNativeOperationService(t, f.service)
			if _, err := plain.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			f.add(t, "org-test-basic", "second", organization.RoleOwner, 5)
			x := teamDeleteOperationRequest(r)
			x.OrganizationVersion = 6
			if _, err := plain.DeleteTeam(f.ctx, x, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			policy := &teamLifecycleOperationPolicy{denyAction: mode == "action denied", denyQuery: mode == "query denied"}
			withdrawn := false
			if mode == "late role" {
				policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if withdrawn || c.Request.Resource.Type != "organization" {
						return nil
					}
					p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 7, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-deletion-lookup-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := f.service.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
			}
			if mode != "query denied" {
				x.TeamVersion++
			}
			out, err := leaveOperationPolicyFacade(t, f, policy, nil).DeleteTeam(f.ctx, x, "127.0.0.1")
			if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || !policy.actionSeen || mode == "late role" && !withdrawn {
				t.Fatal("deletion classified original history without current action authority", err)
			}
		})
	}
}

func TestTeamLifecycleOperationRecoveryRevalidatesFinalPolicyCallbacks(t *testing.T) {
	for _, op := range []organization.Operation{organization.CreateTeam, organization.UpdateTeam, organization.DeleteTeam} {
		for _, stage := range []string{"management", "query"} {
			t.Run(string(op)+"/"+stage, func(t *testing.T) {
				f := teamLifecycleOperationFixture(t, true)
				r := teamLifecycleOperationRequest(t, f)
				f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
				r.OrganizationVersion = 5
				plain := leaveOperationPolicyFacade(t, f, teamMemberWriteWithoutOrganizationRead{}, nil)
				var original organization.StoreResult
				var err error
				epoch := uint64(6)
				var create organization.CreateTeamOperationRequest
				if op == organization.CreateTeam {
					create = teamCreateRequest(t, f, "org-test-basic", "second-team", "callback-create", 5)
					original, err = plain.CreateTeam(f.ctx, create, "127.0.0.1")
				} else {
					original, err = plain.UpdateTeam(f.ctx, r, "127.0.0.1")
					if err == nil && op == organization.DeleteTeam {
						original, err = plain.DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
						epoch = 7
					}
				}
				if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
				calls, required := 0, 1
				if op == organization.DeleteTeam {
					required = 2
				}
				managementSeen, querySeen, withdrawn := false, false, false
				policy := new(teamLifecycleOperationPolicy)
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
					p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-lifecycle-recovery-manager"}, "127.0.0.1")
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
				case organization.CreateTeam:
					out, err = s.CreateTeam(f.ctx, create, "127.0.0.1")
				case organization.UpdateTeam:
					out, err = s.UpdateTeam(f.ctx, r, "127.0.0.1")
				case organization.DeleteTeam:
					out, err = s.DeleteTeam(f.ctx, teamDeleteOperationRequest(r), "127.0.0.1")
				}
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn actual manager received original lifecycle outcome", err)
				}
			})
		}
	}
}
