//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type naturalDisclosureFixture struct {
	f              *orgFixture
	op             organization.Operation
	original       organization.StoreResult
	epoch          uint64
	user           identity.UserID
	terminalPrefix string
	invoke         func(*organizationpg.OperationService, string) (organization.StoreResult, error)
}

func newNaturalDisclosureFixture(t *testing.T, kind string) naturalDisclosureFixture {
	t.Helper()
	var c naturalDisclosureFixture
	var err error
	switch kind {
	case "role delete":
		f := dynamicRoleOperationFixture(t, true)
		r := createRoleOperationRequest(t, f)
		s := slugNativeOperationService(t, f.service)
		if _, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		u := updateRoleOperationRequest(t, r, 3, 1)
		if _, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
		x := deleteRoleOperationRequest(u)
		x.OrganizationVersion = 5
		c = naturalDisclosureFixture{f: f, op: organization.DeleteDynamicRole, epoch: 6, user: "owner", terminalPrefix: "SELECT version::text,state FROM organization.custom_roles"}
		c.invoke = func(s *organizationpg.OperationService, selector string) (organization.StoreResult, error) {
			r := x
			switch selector {
			case "id":
				r.RoleID = "different-role"
			case "version":
				r.RoleVersion++
			case "actor":
				r.Authentication = f.auth("org-test-basic", "second")
			}
			return s.DeleteDynamicRole(f.ctx, r, "127.0.0.1")
		}
	case "team delete":
		f := teamLifecycleOperationFixture(t, true)
		r := teamLifecycleOperationRequest(t, f)
		s := slugNativeOperationService(t, f.service)
		if _, err := s.UpdateTeam(f.ctx, r, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		f.add(t, "org-test-basic", "second", organization.RoleOwner, 5)
		x := teamDeleteOperationRequest(r)
		x.OrganizationVersion = 6
		c = naturalDisclosureFixture{f: f, op: organization.DeleteTeam, epoch: 7, user: "owner", terminalPrefix: "SELECT deleted_version::text,EXISTS(SELECT 1 FROM organization.teams"}
		c.invoke = func(s *organizationpg.OperationService, selector string) (organization.StoreResult, error) {
			r := x
			switch selector {
			case "id":
				r.TeamID = "different-team"
			case "version":
				r.TeamVersion++
			case "actor":
				r.Authentication = f.auth("org-test-basic", "second")
			}
			return s.DeleteTeam(f.ctx, r, "127.0.0.1")
		}
	case "team remove":
		f := teamMemberOperationFixture(t, true)
		r := teamMemberOperationRequest(t, f)
		s := slugNativeOperationService(t, f.service)
		if _, err := s.AddTeamMember(f.ctx, r, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
		x := removeTeamMemberOperationRequest(r)
		x.OrganizationVersion = 5
		c = naturalDisclosureFixture{f: f, op: organization.RemoveTeamMember, epoch: 6, user: "member", terminalPrefix: "SELECT version::text,organization_member_version::text,state='active' FROM organization.team_memberships"}
		c.invoke = func(s *organizationpg.OperationService, selector string) (organization.StoreResult, error) {
			r := x
			switch selector {
			case "id":
				r.TeamID = "different-team"
			case "version":
				r.TeamVersion++
			case "target":
				r.UserID = "outsider"
			case "admission":
				r.OrganizationMemberVersion++
			case "binding":
				r.MembershipVersion++
			case "actor":
				r.Authentication = f.auth("org-test-basic", "second")
			}
			return s.RemoveTeamMember(f.ctx, r, "127.0.0.1")
		}
	default:
		t.Fatal("unknown natural disclosure fixture")
	}
	c.original, err = c.invoke(slugNativeOperationService(t, c.f.service), "")
	if err != nil || c.original.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual original natural transition", err)
	}
	return c
}

type naturalDisclosurePolicy struct {
	op          organization.Operation
	actor, user identity.UserID
	command     identity.CommandID
	denyQuery   bool
	beforeQuery func(context.Context) error
	queries     atomic.Int32
	wrongScope  atomic.Bool
}

func (p *naturalDisclosurePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	if c.Request.Action == authorization.Action(p.op) && c.Request.Resource.Type == "identity.user" {
		p.queries.Add(1)
		id, _ := c.Request.Resource.Attributes["identity.command.id"].String()
		if c.Request.Subject.ID != authorization.SubjectID(p.actor) || c.Request.Resource.ID != authorization.ResourceID(p.user) || id != string(p.command) {
			p.wrongScope.Store(true)
		}
		if p.beforeQuery != nil {
			if err := p.beforeQuery(ctx); err != nil {
				return authorization.Decision{}, err
			}
		}
		if p.denyQuery {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestNaturalOperationQueryPolicyPrecedesHistoryClassification(t *testing.T) {
	for _, kind := range []string{"role delete", "team delete", "team remove"} {
		selectors := []string{"id", "version", "actor"}
		if kind == "team remove" {
			selectors = append(selectors, "target", "admission", "binding")
		}
		for _, selector := range selectors {
			t.Run(kind+"/"+selector, func(t *testing.T) {
				c := newNaturalDisclosureFixture(t, kind)
				actor := identity.UserID("owner")
				if selector == "actor" {
					actor = "second"
				}
				policy := &naturalDisclosurePolicy{op: c.op, actor: actor, user: c.user, command: c.original.Receipt.Binding.CommandID, denyQuery: true}
				out, err := c.invoke(leaveOperationPolicyFacade(t, c.f, policy, nil), selector)
				if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || policy.queries.Load() == 0 || policy.wrongScope.Load() {
					t.Fatalf("query-denied history was classified before actual original query: query=%d wrong_scope=%t outcome=%v error=%v", policy.queries.Load(), policy.wrongScope.Load(), out.Receipt.Outcome, err)
				}
			})
		}
	}
}

func TestNaturalOperationQueryCallbackCannotClassifyWithdrawnHistory(t *testing.T) {
	for _, kind := range []string{"role delete", "team delete", "team remove"} {
		for _, withdrawal := range []string{"manager", "expiry"} {
			t.Run(kind+"/"+withdrawal, func(t *testing.T) {
				c := newNaturalDisclosureFixture(t, kind)
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
					p, err := c.f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: c.f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: c.epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-during-history-query"}, "127.0.0.1")
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
					t.Fatalf("query callback withdrawal classified history: fired=%t query=%d wrong_scope=%t outcome=%v error=%v", fired, policy.queries.Load(), policy.wrongScope.Load(), out.Receipt.Outcome, err)
				}
			})
		}
	}
}

type naturalTerminalReadBarrier struct {
	prefix  string
	ready   chan struct{}
	release <-chan struct{}
	seen    atomic.Bool
}

func (b *naturalTerminalReadBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(q.SQL, b.prefix) && b.seen.CompareAndSwap(false, true) {
		b.ready <- struct{}{}
		select {
		case <-b.release:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*naturalTerminalReadBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type naturalDisclosureClock struct{ offset atomic.Int64 }

func (c *naturalDisclosureClock) Now() time.Time {
	return time.Now().Add(time.Duration(c.offset.Load()))
}

func TestNaturalOperationFinalReadCannotOutliveAdmission(t *testing.T) {
	for _, kind := range []string{"role delete", "team delete", "team remove"} {
		for _, withdrawal := range []string{"manager", "expiry"} {
			t.Run(kind+"/"+withdrawal, func(t *testing.T) {
				c := newNaturalDisclosureFixture(t, kind)
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
				facade := leaveOperationPolicyFacade(t, &copy, fixturePolicy{}, clock)
				type result struct {
					out organization.StoreResult
					err error
				}
				done := make(chan result, 1)
				go func() { out, err := c.invoke(facade, ""); done <- result{out, err} }()
				select {
				case <-barrier.ready:
				case got := <-done:
					t.Fatal("terminal IO barrier not reached", got.err)
				case <-f.ctx.Done():
					unblock()
					<-done
					t.Fatal("bounded terminal-read barrier expired")
				}
				if withdrawal == "expiry" {
					clock.offset.Store(int64(time.Minute))
				} else {
					p, err := f.service.PrepareUpdateMember(f.ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: c.epoch, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-during-terminal-read"}, "127.0.0.1")
					if err != nil {
						unblock()
						<-done
						t.Fatal(err)
					}
					out, err := f.service.Execute(f.ctx, p)
					if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						unblock()
						<-done
						t.Fatal("actual current manager withdrawal failed", err)
					}
				}
				unblock()
				got := <-done
				if !errors.Is(got.err, organization.ErrForbidden) || got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatalf("terminal IO outlived current admission: outcome=%v error=%v", got.out.Receipt.Outcome, got.err)
				}
			})
		}
	}
}
