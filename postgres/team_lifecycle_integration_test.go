//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func lifecycleFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303}, organizationpg.TeamLifecycleMigrationSource{Version: 304})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 10, LifecycleVersion: 1}
	f.compose(t)
	return f
}

func TestTeamLifecycleRollbackAndUnknown(t *testing.T) {
	for _, op := range []organization.Operation{organization.UpdateTeam, organization.DeleteTeam} {
		t.Run(string(op), func(t *testing.T) {
			f := lifecycleFixture(t)
			tenant := "org-test-rollback"
			f.create(t, tenant)
			committedTeam(t, f, createTeam(t, f, tenant, "engineering", 1))
			prepare := func(service *organizationpg.Service) (organizationpg.PreparedCommand, error) {
				if op == organization.UpdateTeam {
					return service.PrepareUpdateTeam(f.ctx, lifecycleUpdate(t, f, tenant, 2, 1), "127.0.0.1")
				}
				return service.PrepareDeleteTeam(f.ctx, lifecycleDelete(t, f, tenant, 2, 1), "127.0.0.1")
			}
			p, e := prepare(f.service)
			if e != nil {
				t.Fatal(e)
			}
			_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.reject_team_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled team lifecycle rollback'; END $$; CREATE TRIGGER reject_team_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.reject_team_lifecycle()`)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("lifecycle failure retained team transition", e)
			}
			var name string
			var epoch, teamVersion int
			var retired bool
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT t.name,t.version::integer,o.version::integer,i.deleted_version IS NOT NULL FROM organization.teams t JOIN organization.organizations o USING(tenant_id,organization_id) JOIN organization.team_identities i USING(tenant_id,organization_id,team_id) WHERE t.tenant_id=$1`, tenant).Scan(&name, &teamVersion, &epoch, &retired); e != nil || name != "engineering" || teamVersion != 1 || epoch != 2 || retired {
				t.Fatal("rollback retained name, epoch or tombstone", e)
			}
			_, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER reject_team_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION organization.reject_team_lifecycle()`)
			if e != nil {
				t.Fatal(e)
			}
			lossy, fault := f.lostCommitService(t)
			p, e = prepare(lossy)
			if e != nil {
				t.Fatal(e)
			}
			recovery, e := p.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			fault.armed.Store(true)
			got, e := lossy.Execute(f.ctx, p)
			if e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("lost acknowledgement claimed outcome", e)
			}
			for range 2 {
				got, e = f.service.Recover(f.ctx, f.auth(tenant, "owner"), recovery)
				if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != recovery.Binding {
					t.Fatal("exact lifecycle recovery", e)
				}
			}
			var effects int
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation=$2`, tenant, string(op)).Scan(&effects); e != nil || effects != 1 {
				t.Fatal("lifecycle recovery replayed mutation", e)
			}
		})
	}
}

func TestTeamLifecyclePopulatedUpgradeAndLegacyPaths(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	p, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	legacy := f.service
	steps, e := (organizationpg.TeamLifecycleMigrationSource{Version: 304}).Load(f.ctx)
	if e != nil {
		t.Fatal(e)
	}
	c, e := pgx.ParseConfig(f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	c.Database = f.database
	db := stdlib.OpenDB(*c)
	defer db.Close()
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	runner, e := migrations.NewRunner(append(append(migrationList(nil), f.history...), steps...), backend)
	if e != nil {
		t.Fatal(e)
	}
	for range 2 {
		if _, e = runner.Up(f.ctx); e != nil {
			t.Fatal("populated lifecycle upgrade", e)
		}
	}
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, TeamID: "engineering", Limit: 10, CorrelationID: "legacy-team"}
	v, e := legacy.ListTeamMembers(f.ctx, q)
	if e != nil || len(v.TeamMembers) != 1 || v.Team.Version != 2 || v.Organization.Version != 4 {
		t.Fatal("upgrade changed existing bindings", e)
	}
	f.teams.LifecycleVersion = 1
	f.compose(t)
	p, e = f.service.PrepareDeleteTeam(f.ctx, lifecycleDelete(t, f, tenant, 4, 2), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	if _, e = legacy.ListTeamMembers(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("legacy member query revived deleted team", e)
	}
	q.TeamID = ""
	v, e = legacy.ListMyTeams(f.ctx, q)
	if e != nil || len(v.Teams) != 0 {
		t.Fatal("legacy mine query revived deleted team", e)
	}
	// Exercise the exact SQL shape of the delivered old writer as well as the
	// still-enabled membership-only native service after the forward migration.
	if _, e = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.teams(tenant_id,organization_id,team_id,name,version) VALUES($1,$2,'engineering','Resurrected',1)`, tenant, string(metadataOrganization)); e == nil {
		t.Fatal("old insert bypassed permanent retired identity")
	}
	old, e := legacy.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 5, TeamID: "engineering", Name: "Resurrected", CorrelationID: "legacy-create"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := legacy.Execute(f.ctx, old); (!errors.Is(e, organization.ErrConflict) && !errors.Is(e, organization.ErrUnavailable)) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("legacy service recreated retired ID", e)
	}
	var retained, retired int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.team_memberships WHERE tenant_id=$1),(SELECT count(*) FROM organization.team_identities WHERE tenant_id=$1 AND deleted_version=3)`, tenant).Scan(&retained, &retired); e != nil || retained != 1 || retired != 1 {
		t.Fatal("delete fanned out or lost terminal identity", e)
	}
}

func TestTeamLifecycleCurrentAuthority(t *testing.T) {
	for _, op := range []organization.Operation{organization.UpdateTeam, organization.DeleteTeam} {
		for _, withdrawal := range []string{"session", "member", "scoped"} {
			t.Run(string(op)+"/"+withdrawal, func(t *testing.T) {
				f := lifecycleFixture(t)
				tenant := "org-test-target"
				f.create(t, tenant)
				committedTeam(t, f, createTeam(t, f, tenant, "engineering", 1))
				var p organizationpg.PreparedCommand
				var e error
				if op == organization.UpdateTeam {
					p, e = f.service.PrepareUpdateTeam(f.ctx, lifecycleUpdate(t, f, tenant, 2, 1), "127.0.0.1")
				} else {
					p, e = f.service.PrepareDeleteTeam(f.ctx, lifecycleDelete(t, f, tenant, 2, 1), "127.0.0.1")
				}
				if e != nil {
					t.Fatal(e)
				}
				switch withdrawal {
				case "session":
					_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='owner'`, tenant)
				case "member":
					_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
				case "scoped":
					scope, se := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "owner")
					if se != nil {
						t.Fatal(se)
					}
					_, e = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second)
				}
				if e != nil {
					t.Fatal(e)
				}
				if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("withdrawn lifecycle authority committed", e)
				}
			})
		}
	}
}

type lifecycleGetWithdrawal struct {
	f     *orgFixture
	armed bool
}

func (p *lifecycleGetWithdrawal) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if p.armed && c.Request.Action == authorization.Action(organization.GetTeam) {
		p.armed = false
		if _, e := p.f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`); e != nil {
			return authorization.Decision{}, e
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}
func TestTeamExactGetRevalidatesCurrentSession(t *testing.T) {
	f := lifecycleFixture(t)
	f.create(t, "org-test-basic")
	committedTeam(t, f, createTeam(t, f, "org-test-basic", "engineering", 1))
	c := f.configuration
	c.Authorization = &lifecycleGetWithdrawal{f: f, armed: true}
	s, e := organizationpg.NewService(f.participant, c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.GetTeam(f.ctx, organization.TeamReadRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: metadataOrganization, TeamID: "engineering", CorrelationID: "late-get"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("exact get retained withdrawn session", e)
	}
}

func TestTeamLifecycleRecoveryRevalidatesAfterQuery(t *testing.T) {
	for _, op := range []organization.Operation{organization.UpdateTeam, organization.DeleteTeam} {
		for _, withdrawal := range []string{"session", "member", "epoch"} {
			t.Run(string(op)+"/"+withdrawal, func(t *testing.T) {
				f := lifecycleFixture(t)
				tenant := "org-test-basic"
				f.create(t, tenant)
				f.add(t, tenant, "second", organization.RoleAdministrator, 1)
				committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
				var p organizationpg.PreparedCommand
				var e error
				if op == organization.UpdateTeam {
					r := lifecycleUpdate(t, f, tenant, 3, 1)
					r.Authentication = f.auth(tenant, "second")
					p, e = f.service.PrepareUpdateTeam(f.ctx, r, "127.0.0.1")
				} else {
					r := lifecycleDelete(t, f, tenant, 3, 1)
					r.Authentication = f.auth(tenant, "second")
					p, e = f.service.PrepareDeleteTeam(f.ctx, r, "127.0.0.1")
				}
				if e != nil {
					t.Fatal(e)
				}
				committedTeam(t, f, p)
				handle, e := p.Recovery()
				if e != nil {
					t.Fatal(e)
				}
				policy := &recoveryWithdrawalPolicy{fixture: f, operation: op, stage: "query", withdrawal: withdrawal, armed: true}
				c := f.configuration
				c.Authorization = policy
				c.Coordinator, e = kernel.NewCoordinator(f.pool, c.Registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 1}})
				if e != nil {
					t.Fatal(e)
				}
				service, e := organizationpg.NewService(f.participant, c)
				if e != nil {
					t.Fatal(e)
				}
				got, e := service.Recover(f.ctx, f.auth(tenant, "second"), handle)
				if !policy.fired || !errors.Is(e, organization.ErrForbidden) || got != (organization.StoreResult{}) {
					t.Fatal("lifecycle recovery disclosed after authority withdrawal", e, got.Receipt.Outcome)
				}
			})
		}
	}
}
func lifecycleUpdate(t *testing.T, f *orgFixture, tenant string, orgVersion, teamVersion uint64) organization.UpdateTeamRequest {
	t.Helper()
	return organization.UpdateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: orgVersion, TeamID: "engineering", TeamVersion: teamVersion, Name: "Platform", CorrelationID: "team-lifecycle"}
}
func lifecycleDelete(t *testing.T, f *orgFixture, tenant string, orgVersion, teamVersion uint64) organization.DeleteTeamRequest {
	t.Helper()
	return organization.DeleteTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: orgVersion, TeamID: "engineering", TeamVersion: teamVersion, CorrelationID: "team-lifecycle"}
}

func TestNativeTeamLifecycle(t *testing.T) {
	f := lifecycleFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	p, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, TeamID: "engineering", CorrelationID: "exact-team"}
	v, e := f.service.GetTeam(f.ctx, q)
	if e != nil || v.Team.Version != 2 || v.Organization.Version != 4 {
		t.Fatal("exact native team", e)
	}
	update := lifecycleUpdate(t, f, tenant, 4, 2)
	p, e = f.service.PrepareUpdateTeam(f.ctx, update, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	v, e = f.service.GetTeam(f.ctx, q)
	if e != nil || v.Team.Name != "Platform" || v.Team.Version != 3 || v.Organization.Version != 5 {
		t.Fatal("bounded versioned team update", e)
	}
	update.CommandID = commandID(t)
	update.OrganizationVersion = 5
	update.TeamVersion = 3
	if _, e = f.service.PrepareUpdateTeam(f.ctx, update, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("team name noop created transition", e)
	}
	deletion, e := f.service.PrepareDeleteTeam(f.ctx, lifecycleDelete(t, f, tenant, 5, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	handle, e := deletion.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, deletion)
	if _, e = f.service.GetTeam(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("deleted exact team accessible", e)
	}
	q.Limit = 10
	q.Authentication = f.auth(tenant, "member")
	if _, e = f.service.ListTeamMembers(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("deleted team retained member access", e)
	}
	q.TeamID = ""
	v, e = f.service.ListMyTeams(f.ctx, q)
	if e != nil || len(v.Teams) != 0 {
		t.Fatal("deleted team retained mine authority", e)
	}
	again := createTeam(t, f, tenant, "engineering", 6)
	if got, e := f.service.Execute(f.ctx, again); !errors.Is(e, organization.ErrConflict) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("deleted ID recreated", e)
	}
	remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 6, UserID: "member", MemberVersion: 1, CorrelationID: "deleted-member"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, remove)
	add, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 7, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "deleted-reentry"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, add)
	q.TeamID = "engineering"
	if _, e = f.service.ListTeamMembers(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("organization reentry restored deleted team", e)
	}
	for range 2 {
		got, e := f.service.Recover(f.ctx, f.auth(tenant, "owner"), handle)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != handle.Binding {
			t.Fatal("terminal deletion lost historical recovery", e)
		}
	}
}

func TestTeamLifecycleContentionAndScope(t *testing.T) {
	f := lifecycleFixture(t)
	tenant := "org-test-race"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	update := lifecycleUpdate(t, f, tenant, 3, 1)
	u, e := f.service.PrepareUpdateTeam(f.ctx, update, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	d, e := f.service.PrepareDeleteTeam(f.ctx, lifecycleDelete(t, f, tenant, 3, 1), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	a, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan organization.StoreResult, 3)
	failures := make(chan error, 3)
	for _, p := range []organizationpg.PreparedCommand{u, d, a} {
		wg.Go(func() { got, e := f.service.Execute(f.ctx, p); results <- got; failures <- e })
	}
	wg.Wait()
	close(results)
	close(failures)
	commits := 0
	for r := range results {
		if r.Receipt.Outcome == identity.CommitOutcomeCommitted {
			commits++
		}
	}
	if commits != 1 {
		t.Fatal("competing graph/metadata/delete committed", commits)
	}
	for e := range failures {
		if e != nil && !errors.Is(e, organization.ErrConflict) {
			t.Fatal("contention escaped stable conflict", e)
		}
	}
	// Scope/role checks occur before a retained version can authorize anything.
	for _, auth := range []organization.Authentication{f.auth(tenant, "member"), f.auth(tenant, "outsider"), f.auth("org-test-scope", "owner")} {
		update.Authentication = auth
		update.CommandID = commandID(t)
		if _, e = f.service.PrepareUpdateTeam(f.ctx, update, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("unauthorized team update", e)
		}
		r := lifecycleDelete(t, f, tenant, 3, 1)
		r.Authentication = auth
		if _, e = f.service.PrepareDeleteTeam(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("unauthorized team delete", e)
		}
	}
}
