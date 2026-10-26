//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func directRoleBindingDisclosureFixture(t *testing.T) naturalDisclosureFixture {
	t.Helper()
	f, r := directRoleBindingFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	if _, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
	x := revokeDirectRoleBindingRequest(r)
	x.OrganizationVersion = 5
	c := naturalDisclosureFixture{f: f, op: organization.RevokeDynamicRole, epoch: 6, user: r.UserID, terminalPrefix: "SELECT version::text,organization_member_version::text,state='active' FROM organization.role_bindings"}
	c.invoke = func(s *organizationpg.OperationService, selector string) (organization.StoreResult, error) {
		changed := x
		switch selector {
		case "id":
			changed.RoleID = "different-role"
		case "version":
			changed.RoleVersion++
		case "target":
			changed.UserID = "outsider"
		case "admission":
			changed.OrganizationMemberVersion++
		case "binding":
			changed.BindingVersion++
		case "actor":
			changed.Authentication = f.auth("org-test-basic", "second")
		}
		return s.RevokeDynamicRole(f.ctx, changed, "127.0.0.1")
	}
	var err error
	c.original, err = c.invoke(s, "")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDirectRoleBindingOperationQueryBeforeHistoryClassification(t *testing.T) {
	for _, selector := range []string{"id", "version", "target", "admission", "binding", "actor"} {
		t.Run(selector, func(t *testing.T) {
			c := directRoleBindingDisclosureFixture(t)
			actor := identity.UserID("owner")
			if selector == "actor" {
				actor = "second"
			}
			policy := &naturalDisclosurePolicy{op: c.op, actor: actor, user: c.user, command: c.original.Receipt.Binding.CommandID, denyQuery: true}
			out, err := c.invoke(leaveOperationPolicyFacade(t, c.f, policy, nil), selector)
			if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || policy.queries.Load() == 0 || policy.wrongScope.Load() {
				t.Fatalf("query-denied direct history classified: queries=%d wrong_scope=%t outcome=%v error=%v", policy.queries.Load(), policy.wrongScope.Load(), out.Receipt.Outcome, err)
			}
		})
	}
}

func TestDirectRoleBindingOperationQueryWithdrawalCannotClassify(t *testing.T) {
	for _, withdrawal := range []string{"manager", "expiry"} {
		t.Run(withdrawal, func(t *testing.T) {
			c := directRoleBindingDisclosureFixture(t)
			clock := new(naturalDisclosureClock)
			policy := &naturalDisclosurePolicy{op: c.op, actor: "owner", user: c.user, command: c.original.Receipt.Binding.CommandID}
			fired := false
			policy.beforeQuery = func(ctx context.Context) error {
				if fired {
					return nil
				}
				fired = true
				if withdrawal == "expiry" {
					clock.offset.Store(int64(time.Minute))
					return nil
				}
				p, err := c.f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: c.f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: c.epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "direct-history-manager-withdrawal"}, "127.0.0.1")
				if err != nil {
					return err
				}
				out, err := c.f.service.Execute(ctx, p)
				if err != nil {
					return err
				}
				if out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					return organization.ErrUnavailable
				}
				return nil
			}
			out, err := c.invoke(leaveOperationPolicyFacade(t, c.f, policy, clock), "version")
			if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || !fired || policy.queries.Load() == 0 || policy.wrongScope.Load() {
				t.Fatal("withdrawn query classified direct history", err)
			}
		})
	}
}

func TestDirectRoleBindingOperationFinalBindingReadFenced(t *testing.T) {
	for _, withdrawal := range []string{"manager", "expiry"} {
		t.Run(withdrawal, func(t *testing.T) {
			c := directRoleBindingDisclosureFixture(t)
			f := c.f
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			barrier := &naturalTerminalReadBarrier{prefix: c.terminalPrefix, ready: make(chan struct{}, 1), release: release}
			pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(config *database.PoolConfig) error {
				config.ConnConfig.Database = f.database
				config.ConnConfig.Tracer = barrier
				return nil
			}})
			if err != nil {
				t.Fatal("terminal-read fixture connection failed")
			}
			defer func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := pool.Close(ctx); err != nil {
					t.Error(err)
				}
			}()
			copy := *f
			copy.pool = pool
			copy.compose(t)
			clock := new(naturalDisclosureClock)
			s := leaveOperationPolicyFacade(t, &copy, new(directRoleBindingPolicy), clock)
			type result struct {
				out organization.StoreResult
				err error
			}
			done := make(chan result, 1)
			go func() { out, err := c.invoke(s, ""); done <- result{out, err} }()
			select {
			case <-barrier.ready:
			case got := <-done:
				t.Fatal("final binding read not reached", got.err)
			case <-f.ctx.Done():
				unblock()
				<-done
				t.Fatal("bounded final binding read expired")
			}
			if withdrawal == "expiry" {
				clock.offset.Store(int64(time.Minute))
			} else {
				p, e := f.service.PrepareUpdateMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: c.epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "direct-terminal-manager-withdrawal"}, "127.0.0.1")
				if e != nil {
					unblock()
					<-done
					t.Fatal(e)
				}
				out, e := f.service.Execute(f.ctx, p)
				if e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					unblock()
					<-done
					t.Fatal("actual manager withdrawal", e)
				}
			}
			unblock()
			got := <-done
			if !errors.Is(got.err, organization.ErrForbidden) || got.out != (organization.StoreResult{}) {
				t.Fatal("final binding IO outlived initial admission", got.err)
			}
		})
	}
}

func TestDirectRoleBindingOperationActionAndForeignAuthority(t *testing.T) {
	f, r := directRoleBindingFixture(t, true)
	s := slugNativeOperationService(t, f.service)
	original, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	x := revokeDirectRoleBindingRequest(r)
	for _, actor := range []string{"member", "outsider"} {
		bad := r
		bad.Authentication = f.auth("org-test-basic", actor)
		if out, err := s.AssignDynamicRole(f.ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager adopted assignment", err)
		}
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: bad.Authentication, Binding: original.Receipt.Binding}); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("different actor recovered assignment", err)
		}
	}
	foreign := r
	foreign.Authentication = f.auth("org-test-scope", "owner")
	if out, err := s.AssignDynamicRole(f.ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted assignment", err)
	}
	denied := leaveOperationPolicyFacade(t, f, &directRoleBindingPolicy{denyAction: true}, nil)
	if out, err := denied.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) {
		t.Fatal("manager bypassed actual revoke action", err)
	}
	if _, err := s.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	x.BindingVersion++
	if out, err := denied.RevokeDynamicRole(f.ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) {
		t.Fatal("action-denied manager classified old selectors", err)
	}
}

func TestDirectRoleBindingOperationAssignmentRecoveryFencesQueryCallback(t *testing.T) {
	for _, withdrawal := range []string{"manager", "expiry"} {
		t.Run(withdrawal, func(t *testing.T) {
			f, r := directRoleBindingFixture(t, true)
			s := leaveOperationPolicyFacade(t, f, new(directRoleBindingPolicy), nil)
			if _, err := s.AssignDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
			clock := new(naturalDisclosureClock)
			policy := new(directRoleBindingPolicy)
			fired := false
			policy.before = func(ctx context.Context, c authorization.DecisionContext) error {
				if fired || c.Request.Action != authorization.Action(organization.AssignDynamicRole) || c.Request.Resource.Type != "identity.user" {
					return nil
				}
				fired = true
				if withdrawal == "expiry" {
					clock.offset.Store(int64(time.Minute))
					return nil
				}
				p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 5, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-assignment-query"}, "127.0.0.1")
				if err != nil {
					return err
				}
				out, err := f.service.Execute(ctx, p)
				if err != nil {
					return err
				}
				if out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					return organization.ErrUnavailable
				}
				return nil
			}
			out, err := leaveOperationPolicyFacade(t, f, policy, clock).AssignDynamicRole(f.ctx, r, "127.0.0.1")
			if !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted || !fired {
				t.Fatal("assignment query callback retained withdrawn authority", err)
			}
		})
	}
}
