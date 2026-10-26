//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func dynamicRoleOperationFixture(t *testing.T, optional bool) *orgFixture {
	t.Helper()
	f := teamLifecycleOperationFixture(t, false)
	sources := []migrations.Source{organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306}}
	if optional {
		sources = append(sources, organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: 323})
	}
	installDynamicRoleOperationSources(t, f, sources...)
	f.dynamicRoles = customRoleConfig()
	f.dynamicRoles.TeamBindingsVersion = 1
	f.compose(t)
	return f
}

func installDynamicRoleOperationSources(t *testing.T, f *orgFixture, sources ...migrations.Source) {
	t.Helper()
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("dynamic_role_operation")
	if err != nil {
		t.Fatal(err)
	}
	var history migrationList
	for _, source := range sources {
		steps, err := source.Load(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, steps...)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal(err)
	}
}

func installDynamicRoleDeleteOperationMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	installDynamicRoleOperationSources(t, f, organizationpg.DynamicRoleMigrationSource{Version: 305}, organizationpg.TeamRoleBindingMigrationSource{Version: 306}, organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: 323})
}

func createRoleOperationRequest(t *testing.T, f *orgFixture) organization.CreateDynamicRoleOperationRequest {
	t.Helper()
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	key, err := identity.NewIdempotencyKey([]byte("original-role-create"))
	if err != nil {
		t.Fatal(err)
	}
	return organization.CreateDynamicRoleOperationRequest{Authentication: f.auth("org-test-basic", "owner"), IdempotencyKey: key, OrganizationID: metadataOrganization, RoleID: "reader", OrganizationVersion: 2, Name: "Document reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "original-role-create"}
}

func updateRoleOperationRequest(t *testing.T, r organization.CreateDynamicRoleOperationRequest, epoch, version uint64) organization.UpdateDynamicRoleOperationRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("original-role-update"))
	if err != nil {
		t.Fatal(err)
	}
	return organization.UpdateDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: key, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: epoch, RoleVersion: version, Name: "Reader with explicit deny", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}, {PermissionID: "document-read", ResourceID: "one", Effect: authorization.Deny}}, CorrelationID: "original-role-update"}
}

func deleteRoleOperationRequest(r organization.UpdateDynamicRoleOperationRequest) organization.DeleteDynamicRoleOperationRequest {
	return organization.DeleteDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion + 1, RoleVersion: r.RoleVersion + 1, CorrelationID: "natural-role-delete"}
}

type dynamicRoleOperationPolicy struct {
	before                func(context.Context, authorization.DecisionContext) error
	denyAction, denyQuery bool
	actionSeen            atomic.Bool
}

func (p *dynamicRoleOperationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	if c.Request.Action == authorization.Action(organization.CreateDynamicRole) || c.Request.Action == authorization.Action(organization.UpdateDynamicRole) || c.Request.Action == authorization.Action(organization.DeleteDynamicRole) {
		if c.Request.Resource.Type == "organization" {
			p.actionSeen.Store(true)
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

func TestDynamicRoleOperationRoleWriteWithoutOrganizationRead(t *testing.T) {
	f := dynamicRoleOperationFixture(t, true)
	r := createRoleOperationRequest(t, f)
	s := leaveOperationPolicyFacade(t, f, new(dynamicRoleOperationPolicy), nil)
	if _, err := s.Get(f.ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "deny-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("general org read not actually denied", err)
	}
	created, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, created) {
		t.Fatal("role-create original recovery required unrelated org read", err)
	}
	u := updateRoleOperationRequest(t, r, 3, 1)
	updated, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, updated) {
		t.Fatal("role-update original recovery required unrelated org read", err)
	}
	x := deleteRoleOperationRequest(u)
	deleted, err := s.DeleteDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.DeleteDynamicRole(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
		t.Fatal("role-delete original recovery required unrelated org read", err)
	}
	for _, original := range []organization.StoreResult{created, updated, deleted} {
		if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("facade role recovery required unrelated org read", err)
		}
	}
	config := f.configuration
	config.Authorization = new(dynamicRoleOperationPolicy)
	legacy, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: created.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("raw legacy recovery permission changed", err)
	}
}

func TestDynamicRoleOperationOriginalCRUDAndEffectivePermission(t *testing.T) {
	f := dynamicRoleOperationFixture(t, true)
	r := createRoleOperationRequest(t, f)
	s := leaveOperationPolicyFacade(t, f, new(dynamicRoleOperationPolicy), nil)
	created, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
	if err != nil || created.Receipt.Feature == nil || created.Receipt.Feature.BeforeVersion != 2 || created.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("actual role create", err)
	}
	q := organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetUserID: "member", CorrelationID: "role-discovery"}
	v, err := s.GetDynamicRole(f.ctx, q)
	if err != nil || v.DynamicRole.ID != r.RoleID || v.DynamicRole.Version != 1 || !reflect.DeepEqual(v.DynamicRole.Statements, r.Statements) {
		t.Fatal("chosen role intent differs", err)
	}
	p, err := f.service.PrepareAssignDynamicRole(f.ctx, organization.RoleBindingRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: 3, RoleVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "existing-direct-owner"}, "127.0.0.1")
	commitRole(t, f, p, err)
	committedTeam(t, f, createTeam(t, f, "org-test-basic", "engineering", 4))
	p, err = f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, "org-test-basic", 5), "127.0.0.1")
	commitRole(t, f, p, err)
	teamRead := q
	teamRead.TargetUserID, teamRead.TargetTeamID = "", "engineering"
	v, err = s.GetDynamicRole(f.ctx, teamRead)
	if err != nil {
		t.Fatal(err)
	}
	p, err = f.service.PrepareAssignTeamDynamicRole(f.ctx, organization.TeamRoleBindingRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: "engineering", OrganizationVersion: 6, RoleVersion: 1, TeamVersion: v.Team.Version, CorrelationID: "existing-team-owner"}, "127.0.0.1")
	commitRole(t, f, p, err)
	check := organization.PermissionCheckRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, OrganizationVersion: 7, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "actual-permission"}
	assertPermission := func(want authorization.Outcome) {
		t.Helper()
		d, err := s.CheckPermission(f.ctx, check)
		if err != nil || d.Outcome != want || d.Revision != authorization.Revision(check.OrganizationVersion) {
			t.Fatal("actual effective direct/team decision differs", err)
		}
	}
	assertPermission(authorization.Allow)
	page, err := s.ListDynamicRoles(f.ctx, organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, Limit: 1, CorrelationID: "list-roles"})
	if err != nil || len(page.DynamicRoles) != 1 || page.DynamicRoles[0].ID != r.RoleID {
		t.Fatal("actual role list", err)
	}
	u := updateRoleOperationRequest(t, r, 7, 1)
	updated, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
	if err != nil || updated.Receipt.Feature.BeforeVersion != 7 || updated.Receipt.Feature.AfterVersion != 8 {
		t.Fatal("actual replacement", err)
	}
	if _, err := s.CheckPermission(f.ctx, check); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("stale allow survived replacement", err)
	}
	check.OrganizationVersion = 8
	assertPermission(authorization.Deny)
	for _, change := range []func(*organization.UpdateDynamicRoleOperationRequest){
		func(r *organization.UpdateDynamicRoleOperationRequest) { r.Name = "changed" },
		func(r *organization.UpdateDynamicRoleOperationRequest) { r.RoleID = "other" },
		func(r *organization.UpdateDynamicRoleOperationRequest) { r.RoleVersion++ },
		func(r *organization.UpdateDynamicRoleOperationRequest) { r.OrganizationVersion++ },
		func(r *organization.UpdateDynamicRoleOperationRequest) { slices.Reverse(r.Statements) },
	} {
		changed := u
		changed.Statements = slices.Clone(u.Statements)
		change(&changed)
		if _, err := s.UpdateDynamicRole(f.ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed exact replacement intent adopted key", err)
		}
	}
	x := deleteRoleOperationRequest(u)
	deleted, err := s.DeleteDynamicRole(f.ctx, x, "127.0.0.1")
	if err != nil || deleted.Receipt.Feature.BeforeVersion != 8 || deleted.Receipt.Feature.AfterVersion != 9 {
		t.Fatal("actual terminal retirement", err)
	}
	check.OrganizationVersion = 9
	assertPermission(authorization.Deny)
	if _, err := s.GetDynamicRole(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("terminal role exposed as live", err)
	}
	page, err = s.ListDynamicRoles(f.ctx, organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, Limit: 1, CorrelationID: "list-retired-roles"})
	if err != nil || len(page.DynamicRoles) != 0 {
		t.Fatal("terminal role retained in live page", err)
	}
	for _, original := range []organization.StoreResult{created, updated, deleted} {
		fresh := leaveOperationPolicyFacade(t, f, new(dynamicRoleOperationPolicy), nil)
		out, err := fresh.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding})
		if err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("reconstructed original role history differs", err)
		}
	}
	x.CorrelationID = "reconstructed-diagnostic"
	if out, err := s.DeleteDynamicRole(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
		t.Fatal("natural exact repeat lost original receipt", err)
	}
	bad := x
	bad.RoleVersion++
	if _, err := s.DeleteDynamicRole(f.ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("changed terminal role epoch adopted success", err)
	}
	var activeBindings, roleVersion int
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,state,(SELECT count(*) FROM organization.role_bindings WHERE state='active')+(SELECT count(*) FROM organization.team_role_bindings WHERE state='active') FROM organization.custom_roles`).Scan(&roleVersion, &state, &activeBindings); err != nil || roleVersion != 3 || state != "deleted" || activeBindings != 2 {
		t.Fatal("retirement rewrote retained binding identity", err)
	}
	reuse := r
	reuse.OrganizationVersion = 9
	reuse.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("retired-role-reuse"))
	if out, err := s.CreateDynamicRole(f.ctx, reuse, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("retired role ID reused", err)
	}
	reuse.RoleID = "second"
	reuse.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("second-role"))
	if _, err := s.CreateDynamicRole(f.ctx, reuse, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	reuse.RoleID, reuse.OrganizationVersion = "over-limit", 10
	reuse.IdempotencyKey, _ = identity.NewIdempotencyKey([]byte("over-role-limit"))
	if out, err := s.CreateDynamicRole(f.ctx, reuse, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("retired role stopped counting toward native limit", err)
	}
}

func TestDynamicRoleOperationFreezesStatementIntentBeforeCallbacks(t *testing.T) {
	for _, updating := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "update"}[updating], func(t *testing.T) {
			f := dynamicRoleOperationFixture(t, true)
			r := createRoleOperationRequest(t, f)
			if updating {
				if _, err := slugNativeOperationService(t, f.service).CreateDynamicRole(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			u := updateRoleOperationRequest(t, r, 3, 1)
			borrowed := r.Statements
			if updating {
				borrowed = u.Statements
			}
			original := slices.Clone(borrowed)
			mutated := false
			policy := new(dynamicRoleOperationPolicy)
			policy.before = func(_ context.Context, c authorization.DecisionContext) error {
				if !mutated && c.Request.Resource.Type == "identity.request-admission" {
					borrowed[0].ResourceID = "rewritten-by-callback"
					mutated = true
				}
				return nil
			}
			s := leaveOperationPolicyFacade(t, f, policy, nil)
			var out organization.StoreResult
			var err error
			if updating {
				out, err = s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
			} else {
				out, err = s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
			}
			if err != nil || !mutated || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("statement callback fixture did not execute", err)
			}
			v, err := s.GetDynamicRole(f.ctx, organization.DynamicRoleReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, CorrelationID: "frozen-intent"})
			if err != nil || !reflect.DeepEqual(v.DynamicRole.Statements, original) {
				t.Fatal("callback rewrote original keyed statement intent", err)
			}
			if updating {
				u.Statements = original
				again, err := s.UpdateDynamicRole(f.ctx, u, "127.0.0.1")
				if err != nil || !reflect.DeepEqual(again, out) {
					t.Fatal("original immutable replacement key no longer matches", err)
				}
			} else {
				r.Statements = original
				again, err := s.CreateDynamicRole(f.ctx, r, "127.0.0.1")
				if err != nil || !reflect.DeepEqual(again, out) {
					t.Fatal("original immutable create key no longer matches", err)
				}
			}
		})
	}
}

func TestDynamicRoleOperationLegacyWritersAndUncorrelatedTombstone(t *testing.T) {
	for _, optional := range []bool{false, true} {
		t.Run(map[bool]string{false: "without optional schema", true: "legacy tombstone lacks original selectors"}[optional], func(t *testing.T) {
			f := dynamicRoleOperationFixture(t, optional)
			r := createRoleOperationRequest(t, f)
			p := prepareRole(t, f, 2)
			commitRole(t, f, p, nil)
			u := organization.DynamicRoleRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: 3, RoleVersion: 1, Name: "Legacy replacement", Statements: r.Statements, CorrelationID: "legacy-role-update"}
			p, err := f.service.PrepareUpdateDynamicRole(f.ctx, u, "127.0.0.1")
			commitRole(t, f, p, err)
			u.CommandID = commandID(t)
			u.OrganizationVersion = 4
			u.RoleVersion = 2
			u.Name = ""
			u.Statements = nil
			p, err = f.service.PrepareDeleteDynamicRole(f.ctx, u, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			out, err := f.service.Execute(f.ctx, p)
			if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("legacy writer now requires optional schema", err)
			}
			if _, err := f.service.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: out.Receipt.Binding}); err != nil {
				t.Fatal("legacy original recovery changed", err)
			}
			if optional {
				var correlated int
				if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE delete_role_id IS NOT NULL`).Scan(&correlated); err != nil || correlated != 0 {
					t.Fatal("unmarked writer invented original correlation", err)
				}
				x := organization.DeleteDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: 4, RoleVersion: 2, CorrelationID: "uncorrelated-natural-delete"}
				if out, err := slugNativeOperationService(t, f.service).DeleteDynamicRole(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("legacy tombstone inferred original natural success", err)
				}
			}
		})
	}
}
