//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestNativeTeams(t *testing.T) {
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 2}
	f.compose(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	p, err := f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 2, TeamID: "engineering", Name: "Engineering", CorrelationID: "team-create"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got, err := f.service.Execute(f.ctx, p)
		if err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.AfterVersion != 3 {
			t.Fatal("team create/replay", err)
		}
	}
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, Limit: 1, CorrelationID: "teams"}
	view, err := f.service.ListTeams(f.ctx, q)
	if err != nil || len(view.Teams) != 1 || view.Teams[0].ID != "engineering" || view.Organization.Version != 3 {
		t.Fatal("team primary list", err)
	}
	add := organization.TeamMemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 3, TeamID: "engineering", TeamVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "team-add"}
	p, err = f.service.PrepareAddTeamMember(f.ctx, add, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.AfterVersion != 4 {
		t.Fatal("team add", err)
	}
	q.Authentication = f.auth(tenant, "member")
	mine, err := f.service.ListMyTeams(f.ctx, q)
	if err != nil || len(mine.Teams) != 1 {
		t.Fatal("actual member teams", err)
	}
	q.TeamID = "engineering"
	members, err := f.service.ListTeamMembers(f.ctx, q)
	if err != nil || len(members.TeamMembers) != 1 || members.TeamMembers[0].UserID != "member" {
		t.Fatal("team members", err)
	}
	add.CommandID = commandID(t)
	add.OrganizationVersion = 4
	add.TeamVersion = 2
	add.MembershipVersion = 1
	p, err = f.service.PrepareRemoveTeamMember(f.ctx, add, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.service.Execute(f.ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("remove team member", err)
	}
	if _, err = f.service.ListTeamMembers(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed team member retained access", err)
	}
	q.TeamID = ""
	mine, err = f.service.ListMyTeams(f.ctx, q)
	if err != nil || len(mine.Teams) != 0 {
		t.Fatal("removed team member retained mine entry", err)
	}
	q.Authentication = f.auth(tenant, "outsider")
	if _, err = f.service.ListTeams(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("nonmember access", err)
	}
	q.Authentication = f.auth("org-test-scope", "owner")
	if _, err = f.service.ListTeams(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("cross-tenant access", err)
	}
}

func teamFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := newOrgFixture(t, organizationpg.TeamMigrationSource{Version: 303})
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 1}
	f.compose(t)
	return f
}
func createTeam(t *testing.T, f *orgFixture, tenant, name string, epoch uint64) organizationpg.PreparedCommand {
	t.Helper()
	p, e := f.service.PrepareCreateTeam(f.ctx, organization.CreateTeamRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: epoch, TeamID: organization.ID(name), Name: name, CorrelationID: "team-create"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func teamAddRequest(t *testing.T, f *orgFixture, tenant string, epoch uint64) organization.TeamMemberRequest {
	t.Helper()
	return organization.TeamMemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: epoch, TeamID: "engineering", TeamVersion: 1, UserID: "member", OrganizationMemberVersion: 1, CorrelationID: "team-add"}
}
func committedTeam(t *testing.T, f *orgFixture, p organizationpg.PreparedCommand) {
	t.Helper()
	if got, e := f.service.Execute(f.ctx, p); e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("team mutation not committed", e, got.Receipt.Outcome)
	}
}

func TestTeamsBoundedPaginationAndDuplicateContention(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-race"
	f.create(t, tenant)
	first := createTeam(t, f, tenant, "engineering", 1)
	second := createTeam(t, f, tenant, "engineering", 1)
	var wg sync.WaitGroup
	out := make(chan organization.StoreResult, 2)
	errs := make(chan error, 2)
	for _, p := range []organizationpg.PreparedCommand{first, second} {
		wg.Go(func() { r, e := f.service.Execute(f.ctx, p); out <- r; errs <- e })
	}
	wg.Wait()
	close(out)
	close(errs)
	winners := 0
	for r := range out {
		if r.Receipt.Outcome == identity.CommitOutcomeCommitted {
			winners++
		}
	}
	if winners != 1 {
		t.Fatal("duplicate concurrent teams committed", winners)
	}
	failed := 0
	for e := range errs {
		if e != nil {
			if !errors.Is(e, organization.ErrConflict) {
				t.Fatal(e)
			}
			failed++
		}
	}
	if failed != 1 {
		t.Fatal("duplicate did not conflict")
	}
	committedTeam(t, f, createTeam(t, f, tenant, "operations", 2))
	p := createTeam(t, f, tenant, "over-quota", 3)
	if r, e := f.service.Execute(f.ctx, p); !errors.Is(e, organization.ErrForbidden) || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("team quota bypass", e)
	}
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, Limit: 1, CorrelationID: "team-page"}
	v, e := f.service.ListTeams(f.ctx, q)
	if e != nil || len(v.Teams) != 1 || v.Teams[0].ID != "engineering" || v.NextTeamCursor != "engineering" {
		t.Fatal("first stable page", e)
	}
	q.Cursor = v.NextTeamCursor
	v, e = f.service.ListTeams(f.ctx, q)
	if e != nil || len(v.Teams) != 1 || v.Teams[0].ID != "operations" || v.NextTeamCursor != "" {
		t.Fatal("exclusive final page", e)
	}
}

func TestTeamMembershipContentionQuotasAndOrganizationReentry(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	f.add(t, tenant, "second", organization.RoleAdministrator, 2)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 3))
	r := teamAddRequest(t, f, tenant, 4)
	p, e := f.service.PrepareAddTeamMember(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	r.CommandID = commandID(t)
	other, e := f.service.PrepareAddTeamMember(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan organization.StoreResult, 2)
	errs := make(chan error, 2)
	for _, p := range []organizationpg.PreparedCommand{p, other} {
		wg.Go(func() { got, e := f.service.Execute(f.ctx, p); results <- got; errs <- e })
	}
	wg.Wait()
	close(results)
	close(errs)
	commits := 0
	for r := range results {
		if r.Receipt.Outcome == identity.CommitOutcomeCommitted {
			commits++
		}
	}
	if commits != 1 {
		t.Fatal("duplicate member contention", commits)
	}
	for e := range errs {
		if e != nil && !errors.Is(e, organization.ErrConflict) {
			t.Fatal(e)
		}
	}
	r = teamAddRequest(t, f, tenant, 5)
	r.UserID = "second"
	r.TeamVersion = 2
	p, e = f.service.PrepareAddTeamMember(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); !errors.Is(e, organization.ErrForbidden) || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("team member quota bypass", e)
	}
	remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 5, UserID: "member", MemberVersion: 1, CorrelationID: "org-remove"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, remove)
	q := organization.TeamReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: metadataOrganization, TeamID: "engineering", Limit: 10, CorrelationID: "reentry"}
	if _, e = f.service.ListTeamMembers(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("removed org member retained team", e)
	}
	add, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 6, UserID: "member", MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "org-readd"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, add)
	if _, e = f.service.ListTeamMembers(f.ctx, q); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("reentry resurrected old team", e)
	}
	q.TeamID = ""
	v, e := f.service.ListMyTeams(f.ctx, q)
	if e != nil || len(v.Teams) != 0 {
		t.Fatal("reentry resurrected mine", e)
	}
	r = teamAddRequest(t, f, tenant, 7)
	r.TeamVersion = 2
	r.OrganizationMemberVersion = 3
	r.MembershipVersion = 1
	p, e = f.service.PrepareAddTeamMember(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	q.TeamID = "engineering"
	v, e = f.service.ListTeamMembers(f.ctx, q)
	if e != nil || len(v.TeamMembers) != 1 || v.TeamMembers[0].Version != 2 || v.TeamMembers[0].OrganizationMemberVersion != 3 {
		t.Fatal("explicit re-admission failed", e)
	}
}

func TestTeamPreparedAuthorityWithdrawal(t *testing.T) {
	for _, variant := range []string{"session", "actor-membership", "actor-authority", "target-membership", "target-identity", "target-authority"} {
		t.Run(variant, func(t *testing.T) {
			f := teamFixture(t)
			tenant := "org-test-target"
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
			p, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			switch variant {
			case "session":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "actor-membership":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND user_id='owner'`, tenant)
			case "target-membership":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id=$1 AND user_id='member'`, tenant)
			case "target-identity":
				_, e = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id='member'`, tenant)
			case "actor-authority", "target-authority":
				user := identity.UserID("owner")
				if variant == "target-authority" {
					user = "member"
				}
				scope, se := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, user)
				if se != nil {
					t.Fatal(se)
				}
				_, e = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second)
			}
			if e != nil {
				t.Fatal(e)
			}
			got, e := f.service.Execute(f.ctx, p)
			if e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("withdrawn authority committed team", e, got.Receipt.Outcome)
			}
			var count, epoch int
			if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.team_memberships),version::integer FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&count, &epoch); e != nil || count != 0 || epoch != 3 {
				t.Fatal("denial retained effect", e)
			}
		})
	}
}

func TestTeamRollbackAndUnknownRecovery(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-rollback"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	p, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.team_fail_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle failure'; END $$; CREATE TRIGGER team_fail_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.team_fail_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	if got, e := f.service.Execute(f.ctx, p); e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("lifecycle failure committed", e)
	}
	_, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER team_fail_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION public.team_fail_lifecycle()`)
	if e != nil {
		t.Fatal(e)
	}
	var epoch, authority, bindings int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT o.version::integer,m.authorization_version::integer,(SELECT count(*) FROM organization.team_memberships) FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND m.user_id='member'`, tenant).Scan(&epoch, &authority, &bindings); e != nil || epoch != 3 || authority != 1 || bindings != 0 {
		t.Fatal("rollback retained graph or policy", e)
	}
	service, fault := f.lostCommitService(t)
	r := teamAddRequest(t, f, tenant, 3)
	p, e = service.PrepareAddTeamMember(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	fault.armed.Store(true)
	got, e := service.Execute(f.ctx, p)
	if e == nil || !fault.lost.Load() || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("lost commit did not report unknown", e, got.Receipt.Outcome)
	}
	for range 2 {
		got, e = f.service.Recover(f.ctx, f.auth(tenant, "owner"), recovery)
		if e != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Binding != recovery.Binding {
			t.Fatal("team recovery failed", e)
		}
	}
	var audits, events, effects int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.outcome=$2 AND r.action='identity.organization.add_team_member'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='team.membership_changed.v1'),(SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND operation='identity.organization.team.member-add')`, tenant, int16(audit.OutcomeSucceeded)).Scan(&audits, &events, &effects); e != nil || audits != 1 || events != 1 || effects != 1 {
		t.Fatal("recovery duplicated committed effects", e, audits, events, effects)
	}
}

func TestTeamForwardMigrationPreservesPopulatedOrganizations(t *testing.T) {
	f := newOrgFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	steps, e := (organizationpg.TeamMigrationSource{Version: 303}).Load(f.ctx)
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
			t.Fatal(e)
		}
	}
	view, e := f.service.ListMembers(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: metadataOrganization, Limit: 10, CorrelationID: "legacy"})
	if e != nil || view.Organization.Version != 2 || len(view.Members) != 2 {
		t.Fatal("forward migration altered existing authority", e)
	}
	f.teams = organization.TeamConfig{Version: 1, MaximumTeams: 2, MaximumMembers: 2}
	f.compose(t)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	for _, sql := range []string{`INSERT INTO organization.team_memberships VALUES('org-test-scope','01ARZ3NDEKTSV4RRFFQ69G5FAV','engineering','member','active',1,1)`, `INSERT INTO organization.team_memberships VALUES('org-test-basic','other','engineering','member','active',1,1)`, `INSERT INTO organization.team_memberships VALUES('org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','engineering','outsider','active',1,1)`} {
		if _, e = f.pool.Raw().Exec(f.ctx, sql); e == nil {
			t.Fatal("cross scope membership persisted")
		}
	}
}

type teamReadWithdrawal struct {
	f     *orgFixture
	armed bool
	mode  string
}

func (p *teamReadWithdrawal) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if p.armed && c.Request.Action == authorization.Action(organization.ListTeams) {
		p.armed = false
		statement := `UPDATE organization.memberships SET state='removed',version=version+1 WHERE tenant_id='org-test-basic' AND user_id='owner'`
		if p.mode == "session" {
			statement = `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`
		}
		if _, e := p.f.pool.Raw().Exec(ctx, statement); e != nil {
			return authorization.Decision{}, e
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}
func TestTeamReadRevalidatesAfterPolicy(t *testing.T) {
	for _, mode := range []string{"session", "membership"} {
		t.Run(mode, func(t *testing.T) {
			f := teamFixture(t)
			f.create(t, "org-test-basic")
			committedTeam(t, f, createTeam(t, f, "org-test-basic", "engineering", 1))
			policy := &teamReadWithdrawal{f: f, armed: true, mode: mode}
			c := f.configuration
			c.Authorization = policy
			service, e := organizationpg.NewService(f.participant, c)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = service.ListTeams(f.ctx, organization.TeamReadRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: metadataOrganization, Limit: 10, CorrelationID: "late-read"}); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("withdrawn read authority disclosed team", e)
			}
		})
	}
}

func TestTeamAdministratorAndScopeAdmission(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "second", organization.RoleAdministrator, 1)
	f.add(t, tenant, "member", organization.RoleMember, 2)
	r := organization.CreateTeamRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 3, TeamID: "engineering", Name: "Engineering", CorrelationID: "admin-team"}
	p, e := f.service.PrepareCreateTeam(f.ctx, r, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	a := teamAddRequest(t, f, tenant, 4)
	a.Authentication = f.auth(tenant, "second")
	p, e = f.service.PrepareAddTeamMember(f.ctx, a, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	a.OrganizationVersion = 5
	a.TeamVersion = 2
	a.MembershipVersion = 1
	a.CommandID = commandID(t)
	p, e = f.service.PrepareRemoveTeamMember(f.ctx, a, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	committedTeam(t, f, p)
	r.OrganizationVersion = 6
	r.CommandID = commandID(t)
	r.TeamID = "another"
	r.Authentication = f.auth(tenant, "member")
	if _, e = f.service.PrepareCreateTeam(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("member created team", e)
	}
	r.Authentication = f.auth("org-test-scope", "owner")
	if _, e = f.service.PrepareCreateTeam(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("cross tenant create", e)
	}
	a.Authentication = f.auth(tenant, "owner")
	a.OrganizationVersion = 6
	a.TeamVersion = 3
	a.MembershipVersion = 0
	a.UserID = "outsider"
	a.CommandID = commandID(t)
	if _, e = f.service.PrepareAddTeamMember(f.ctx, a, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("outsider admitted to team", e)
	}
	f.create(t, "org-test-scope")
	f.add(t, "org-test-scope", "outsider", organization.RoleMember, 1)
	if _, e = f.service.PrepareAddTeamMember(f.ctx, a, "127.0.0.1"); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("other organization member joined team", e)
	}
	a.UserID = "member"
	a.MembershipVersion = 2
	a.OrganizationVersion = 5
	if _, e = f.service.PrepareAddTeamMember(f.ctx, a, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("stale org policy admitted", e)
	}
}

func TestTeamSessionAuthorityAtProtectedCommit(t *testing.T) {
	f := teamFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	p, e := f.service.PrepareAddTeamMember(f.ctx, teamAddRequest(t, f, tenant, 3), "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	// Model a same-Work downstream write withdrawing the original session after
	// domain application. The native contributor's final admission must see it.
	_, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.team_withdraw_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=NEW.tenant_id AND user_id='owner'; RETURN NEW; END $$; CREATE TRIGGER team_withdraw_session AFTER INSERT ON organization.team_memberships FOR EACH ROW EXECUTE FUNCTION organization.team_withdraw_session()`)
	if e != nil {
		t.Fatal(e)
	}
	got, e := f.service.Execute(f.ctx, p)
	if e == nil || got.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("session withdrawn during Work committed", e, got.Receipt.Outcome)
	}
	var bindings, epoch int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.team_memberships),version::integer FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&bindings, &epoch); e != nil || bindings != 0 || epoch != 3 {
		t.Fatal("failed final admission retained effects", e)
	}
}

func TestTeamDisabledAndConfiguration(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	r := organization.CreateTeamRequest{Authentication: f.auth("org-test-basic", "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 1, TeamID: "disabled", Name: "Disabled", CorrelationID: "disabled"}
	if _, e := f.service.PrepareCreateTeam(f.ctx, r, "127.0.0.1"); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("omitted teams configuration enabled operation", e)
	}
	if _, e := f.service.ListMyTeams(f.ctx, organization.TeamReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, Limit: 1, CorrelationID: "disabled"}); !errors.Is(e, organization.ErrInvalidInput) {
		t.Fatal("omitted teams configuration enabled read", e)
	}
	for _, invalid := range []organization.TeamConfig{{Version: 1}, {Version: 1, MaximumTeams: 10001, MaximumMembers: 1}, {MaximumTeams: 1, MaximumMembers: 1}, {Version: 1, MaximumTeams: 1, MaximumMembers: 100001}} {
		c := f.configuration
		c.Core.Teams = invalid
		if _, e := organizationpg.NewService(f.participant, c); !errors.Is(e, organization.ErrInvalidInput) {
			t.Fatal("invalid or mismatched team startup policy accepted", e)
		}
	}
}
