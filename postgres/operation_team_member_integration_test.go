//go:build integration

package postgres_test

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

type teamMemberWriteWithoutOrganizationRead struct{}

func (teamMemberWriteWithoutOrganizationRead) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestTeamMemberOperationTeamWriteIndependentOfOrganizationRead(t *testing.T) {
	for _, variant := range []string{"initial removal", "admission recovery", "removal recovery"} {
		t.Run(variant, func(t *testing.T) {
			f := teamMemberOperationFixture(t, true)
			r := teamMemberOperationRequest(t, f)
			s := leaveOperationPolicyFacade(t, f, teamMemberWriteWithoutOrganizationRead{}, nil)
			if _, err := s.Get(f.ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "denied-org-read"}); !errors.Is(err, organization.ErrForbidden) {
				t.Fatal("org read was not actually denied", err)
			}
			added, err := s.AddTeamMember(f.ctx, r, "127.0.0.1")
			if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("team-write-only admission failed", err)
			}
			if variant == "admission recovery" {
				out, err := s.AddTeamMember(f.ctx, r, "127.0.0.1")
				if err != nil || !reflect.DeepEqual(out, added) {
					t.Fatal("team-write original admission required organization read", err)
				}
				if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: added.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, added) {
					t.Fatal("explicit team admission recovery required org read", err)
				}
				config := f.configuration
				config.Authorization = teamMemberWriteWithoutOrganizationRead{}
				legacy, err := organizationpg.NewService(f.participant, config)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := legacy.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: added.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
					t.Fatal("legacy raw recovery policy silently changed", err)
				}
				return
			}
			x := removeTeamMemberOperationRequest(r)
			if variant == "initial removal" {
				out, err := s.RemoveTeamMember(f.ctx, x, "127.0.0.1")
				if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("team-write original removal required organization read", err)
				}
				return
			}
			removed, err := slugNativeOperationService(t, f.service).RemoveTeamMember(f.ctx, x, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			out, err := s.RemoveTeamMember(f.ctx, x, "127.0.0.1")
			if err != nil || !reflect.DeepEqual(out, removed) {
				t.Fatal("team-write removal history required organization read", err)
			}
			if out, err := s.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: removed.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, removed) {
				t.Fatal("explicit team removal recovery required org read", err)
			}
		})
	}
}

type teamMemberLookupPolicy struct {
	before                func(context.Context, authorization.DecisionContext) error
	denyAction, denyQuery bool
	actionSeen            bool
}

func (p *teamMemberLookupPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
	}
	if c.Request.Action == authorization.Action(organization.RemoveTeamMember) {
		if c.Request.Resource.Type == "organization" {
			p.actionSeen = true
			if p.before != nil {
				if err := p.before(ctx, c); err != nil {
					return authorization.Decision{}, err
				}
			}
			if p.denyAction {
				return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
			}
		}
		if c.Request.Resource.Type == "identity.user" && p.denyQuery {
			return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, ctx.Err()
		}
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func TestTeamMemberOperationLookupAuthorizesAndFencesBeforeClassification(t *testing.T) {
	for _, variant := range []string{"action denied", "query denied", "late role withdrawal"} {
		t.Run(variant, func(t *testing.T) {
			f := teamMemberOperationFixture(t, true)
			r := teamMemberOperationRequest(t, f)
			plain := slugNativeOperationService(t, f.service)
			if _, err := plain.AddTeamMember(f.ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			f.add(t, "org-test-basic", "second", organization.RoleOwner, 4)
			x := removeTeamMemberOperationRequest(r)
			x.OrganizationVersion = 5
			if _, err := plain.RemoveTeamMember(f.ctx, x, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
			policy := &teamMemberLookupPolicy{denyAction: variant == "action denied", denyQuery: variant == "query denied"}
			withdrawn := false
			if variant == "late role withdrawal" {
				policy.before = func(ctx context.Context, _ authorization.DecisionContext) error {
					if withdrawn {
						return nil
					}
					p, err := f.service.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: f.auth("org-test-basic", "second"), CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: "owner", MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-team-lookup-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := f.service.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
			}
			if variant != "query denied" {
				x.TeamVersion++
			} // Would otherwise disclose a changed-selector conflict.
			out, err := leaveOperationPolicyFacade(t, f, policy, nil).RemoveTeamMember(f.ctx, x, "127.0.0.1")
			if !errors.Is(err, organization.ErrForbidden) || out != (organization.StoreResult{}) || !policy.actionSeen || variant == "late role withdrawal" && !withdrawn {
				t.Fatal("team lookup classified history without current action authority", err)
			}
		})
	}
}

func TestTeamMemberOperationMappingLossRemainsUnknown(t *testing.T) {
	f := teamMemberOperationFixture(t, true)
	r := teamMemberOperationRequest(t, f)
	source, fault := f.lostCommitService(t)
	fault.count.Store(1)
	fault.armed.Store(true)
	unknown, err := slugNativeOperationService(t, source).AddTeamMember(f.ctx, r, "127.0.0.1")
	if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
		t.Fatal("mapping response loss lost original correlation", err)
	}
	for range 2 {
		out, err := slugNativeOperationService(t, f.service).AddTeamMember(f.ctx, r, "127.0.0.1")
		var ambiguity identity.UnknownCommitError
		if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding != unknown.Receipt.Binding || ambiguity.CommandID != unknown.Receipt.Binding.CommandID {
			t.Fatal("mapped original with no journal did not remain unknown", out.Receipt.Outcome, err)
		}
	}
	out, err := slugNativeOperationService(t, f.service).RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: unknown.Receipt.Binding})
	var ambiguity identity.UnknownCommitError
	if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding != unknown.Receipt.Binding {
		t.Fatal("explicit mapped recovery invented terminal result", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var journals, claims, bindings int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.team_memberships)`, raw).Scan(&journals, &claims, &bindings); err != nil || journals != 0 || claims != 0 || bindings != 0 {
		t.Fatal("mapping uncertainty reached execution", err)
	}
}

// Seeded effects test only the owned migration/access path, never receipts or
// organization authority. The exact query must remain bounded on populated data.
func TestTeamMemberOperationPopulatedMigrationIndexAndInterruption(t *testing.T) {
	f := teamMemberOperationFixture(t, false)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) SELECT translate(rtrim(encode(int8send(n)||int8send(71),'base64'),'='),'+/','-_'),'org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','member','owner','identity.organization.team.member-remove',decode(repeat('01',32),'hex'),n+10,n+11 FROM generate_series(1::bigint,4000::bigint) n`); err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.TeamMemberOperationLookupMigrationSource{Version: 322}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.command_effects IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	blocked, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(f.ctx)
	if _, err := blocked.Exec(f.ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = blocked.Exec(f.ctx, steps[0].UpSQL())
	var lock *pgconn.PgError
	if !errors.As(err, &lock) || lock.Code != "55P03" {
		t.Fatal("operator lock budget not enforced", err)
	}
	if err := blocked.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var partial bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='organization' AND table_name='command_effects' AND column_name='remove_team_id') OR to_regclass('organization.organization_repeat_team_member_removal') IS NOT NULL`).Scan(&partial); err != nil || partial {
		t.Fatal("interrupted optional migration retained schema", err)
	}
	installTeamMemberOperationMigration(t, f)
	var nullable int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE remove_team_id IS NULL AND remove_team_version IS NULL AND remove_org_member_version IS NULL AND remove_membership_version IS NULL`).Scan(&nullable); err != nil || nullable != 4000 {
		t.Fatal("migration backfilled legacy selectors", err)
	}
	id := commandID(t)
	const insert = `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version,remove_team_id,remove_team_version,remove_org_member_version,remove_membership_version) VALUES($1,'org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','member','owner','identity.organization.team.member-remove',decode(repeat('02',32),'hex'),100000,100001,'engineering',1,1,1)`
	if _, err := f.pool.Raw().Exec(f.ctx, insert, string(id)); err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, insert, string(commandID(t)))
	var duplicate *pgconn.PgError
	if !errors.As(err, &duplicate) || duplicate.Code != "23505" || duplicate.ConstraintName != "organization_repeat_team_member_removal" {
		t.Fatal("correlated org epoch not unique", err)
	}
	for _, sql := range []string{`UPDATE organization.command_effects SET remove_team_version=18446744073709551615 WHERE command_id=$1`, `UPDATE organization.command_effects SET remove_membership_version=18446744073709551615 WHERE command_id=$1`, `UPDATE organization.command_effects SET remove_org_member_version=NULL WHERE command_id=$1`, `UPDATE organization.command_effects SET operation='identity.organization.team.member-add' WHERE command_id=$1`} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql, string(id)); err == nil {
			t.Fatal("invalid correlated selector accepted")
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, `EXPLAIN (ANALYZE,BUFFERS) SELECT command_id,remove_team_id,remove_team_version::text,remove_org_member_version::text,remove_membership_version::text,actor_id,user_id FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric AND operation='identity.organization.team.member-remove' AND remove_team_id IS NOT NULL LIMIT 2`, "org-test-basic", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "100000")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	err = rows.Err()
	rows.Close()
	if err != nil || !strings.Contains(plan.String(), "organization_repeat_team_member_removal") {
		t.Fatal("exact history lookup missed bounded index", err, plan.String())
	}
	t.Logf("isolated 4000 legacy / 1 correlated effects, exact lookup plan:\n%s", plan.String())
}

func teamMemberOperationFixture(t *testing.T, migration bool) *orgFixture {
	t.Helper()
	f := teamCreateOperationFixture(t)
	if migration {
		installTeamMemberOperationMigration(t, f)
	}
	return f
}

func installTeamMemberOperationMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("team_member_operation")
	if err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.TeamMemberOperationLookupMigrationSource{Version: 322}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("team member optional correlation migration", err)
	}
}

func teamMemberOperationRequest(t *testing.T, f *orgFixture) organization.AddTeamMemberOperationRequest {
	t.Helper()
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	committedTeam(t, f, createTeam(t, f, tenant, "engineering", 2))
	key, err := identity.NewIdempotencyKey([]byte("original-team-member"))
	if err != nil {
		t.Fatal(err)
	}
	return organization.AddTeamMemberOperationRequest{Authentication: f.auth(tenant, "owner"), IdempotencyKey: key, OrganizationID: metadataOrganization, TeamID: "engineering", UserID: "member", OrganizationVersion: 3, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-member-operation"}
}

func removeTeamMemberOperationRequest(r organization.AddTeamMemberOperationRequest) organization.RemoveTeamMemberOperationRequest {
	return organization.RemoveTeamMemberOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion + 1, TeamVersion: r.TeamVersion + 1, OrganizationMemberVersion: r.OrganizationMemberVersion, MembershipVersion: r.MembershipVersion + 1, CorrelationID: "team-member-removal"}
}

func TestTeamMemberOperationOriginalAndExactBinding(t *testing.T) {
	f := teamMemberOperationFixture(t, true)
	r := teamMemberOperationRequest(t, f)
	s := slugNativeOperationService(t, f.service)
	added, err := s.AddTeamMember(f.ctx, r, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted || added.Receipt.Feature == nil || added.Receipt.Feature.BeforeVersion != 3 || added.Receipt.Feature.AfterVersion != 4 || added.MemberID != r.UserID {
		t.Fatal("original admission", err)
	}
	q := organization.TeamReadRequest{Authentication: f.auth("org-test-basic", "member"), OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "actual-team-read"}
	if v, err := s.ListMyTeams(f.ctx, q); err != nil || len(v.Teams) != 1 || v.Teams[0].ID != r.TeamID || v.Teams[0].Version != 2 {
		t.Fatal("actual own teams", err)
	}
	q.TeamID = r.TeamID
	if v, err := s.ListTeamMembers(f.ctx, q); err != nil || len(v.TeamMembers) != 1 || v.TeamMembers[0].UserID != r.UserID || v.TeamMembers[0].Version != 1 || v.TeamMembers[0].OrganizationMemberVersion != 1 {
		t.Fatal("actual exact team membership", err)
	}
	for _, change := range []func(*organization.AddTeamMemberOperationRequest){
		func(r *organization.AddTeamMemberOperationRequest) { r.TeamID = "other" }, func(r *organization.AddTeamMemberOperationRequest) { r.UserID = "second" }, func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.TeamVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationMemberVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.MembershipVersion++ },
	} {
		bad := r
		change(&bad)
		if _, err := s.AddTeamMember(f.ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed admission intent accepted", err)
		}
	}
	removedRequest := removeTeamMemberOperationRequest(r)
	removed, err := s.RemoveTeamMember(f.ctx, removedRequest, "127.0.0.1")
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted || removed.Receipt.Feature == nil || removed.Receipt.Feature.BeforeVersion != 4 || removed.Receipt.Feature.AfterVersion != 5 {
		t.Fatal("natural removal", err)
	}
	for range 2 {
		rebuilt := slugNativeOperationService(t, f.service)
		if out, err := rebuilt.AddTeamMember(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, added) {
			t.Fatal("admission retry changed original", err)
		}
		if out, err := rebuilt.RemoveTeamMember(f.ctx, removedRequest, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, removed) {
			t.Fatal("natural retry changed original", err)
		}
		if out, err := rebuilt.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: removed.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, removed) {
			t.Fatal("explicit original removal", err)
		}
	}
	if _, err := s.ListTeamMembers(f.ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed team member retained member-list", err)
	}
	q.TeamID = ""
	if v, err := s.ListMyTeams(f.ctx, q); err != nil || len(v.Teams) != 0 {
		t.Fatal("removed team retained mine", err)
	}
	for _, change := range []func(*organization.RemoveTeamMemberOperationRequest){
		func(r *organization.RemoveTeamMemberOperationRequest) { r.TeamID = "other" }, func(r *organization.RemoveTeamMemberOperationRequest) { r.UserID = "second" }, func(r *organization.RemoveTeamMemberOperationRequest) { r.OrganizationMemberVersion++ }, func(r *organization.RemoveTeamMemberOperationRequest) { r.TeamVersion++ }, func(r *organization.RemoveTeamMemberOperationRequest) { r.MembershipVersion++ },
	} {
		bad := removedRequest
		change(&bad)
		if out, err := s.RemoveTeamMember(f.ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed removal adopted original", err)
		}
	}
	// A later binding cannot be removed through an old naturally repeated request.
	key, err := identity.NewIdempotencyKey([]byte("readmit-team-member"))
	if err != nil {
		t.Fatal(err)
	}
	next := r
	next.IdempotencyKey = key
	next.OrganizationVersion = 5
	next.TeamVersion = 3
	next.MembershipVersion = 2
	if out, err := s.AddTeamMember(f.ctx, next, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("new exact binding", err)
	}
	if _, err := s.RemoveTeamMember(f.ctx, removedRequest, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("old removal reached newer binding", err)
	}
	var effects int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.member-remove'`).Scan(&effects); err != nil || effects != 1 {
		t.Fatal("removal history duplicated", effects, err)
	}
}

func TestTeamMemberOperationLegacyCorrelationAndMigration(t *testing.T) {
	f := teamMemberOperationFixture(t, false)
	r := teamMemberOperationRequest(t, f)
	// Explicit legacy preparation never requires the optional correlation schema.
	p, err := f.service.PrepareAddTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: 3, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: r.CorrelationID}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	x := removeTeamMemberOperationRequest(r)
	p, err = f.service.PrepareRemoveTeamMember(f.ctx, organization.TeamMemberRequest{Authentication: x.Authentication, CommandID: commandID(t), OrganizationID: x.OrganizationID, TeamID: x.TeamID, UserID: x.UserID, OrganizationVersion: x.OrganizationVersion, TeamVersion: x.TeamVersion, OrganizationMemberVersion: x.OrganizationMemberVersion, MembershipVersion: x.MembershipVersion, CorrelationID: x.CorrelationID}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	committedTeam(t, f, p)
	installTeamMemberOperationMigration(t, f)
	if out, err := slugNativeOperationService(t, f.service).RemoveTeamMember(f.ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy history invented original exact binding", err)
	}
	var legacy int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.member-remove' AND remove_team_id IS NULL AND remove_team_version IS NULL AND remove_org_member_version IS NULL AND remove_membership_version IS NULL`).Scan(&legacy); err != nil || legacy != 1 {
		t.Fatal("legacy correlation backfilled", err)
	}
	for _, sql := range []string{`UPDATE organization.command_effects SET remove_team_id='engineering' WHERE operation='identity.organization.team.member-remove'`, `UPDATE organization.command_effects SET remove_team_id='engineering',remove_team_version=1,remove_org_member_version=1,remove_membership_version=1 WHERE operation='identity.organization.team.member-add'`} {
		if _, err := f.pool.Raw().Exec(f.ctx, sql); err == nil {
			t.Fatal("partial or wrong-operation correlation accepted")
		}
	}
}

func TestTeamMemberOperationRollbackAndNaturalContention(t *testing.T) {
	for _, variant := range []string{"add-audit", "add-outbox", "remove-audit", "remove-outbox", "contention"} {
		t.Run(variant, func(t *testing.T) {
			f := teamMemberOperationFixture(t, true)
			r := teamMemberOperationRequest(t, f)
			s := slugNativeOperationService(t, f.service)
			if variant == "contention" {
				if _, err := s.AddTeamMember(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				x := removeTeamMemberOperationRequest(r)
				start := make(chan struct{})
				results := make(chan organization.StoreResult, 2)
				var wg sync.WaitGroup
				for range 2 {
					wg.Go(func() { <-start; out, _ := s.RemoveTeamMember(f.ctx, x, "127.0.0.1"); results <- out })
				}
				close(start)
				wg.Wait()
				close(results)
				var winner organization.StoreResult
				for out := range results {
					if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
						if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(out, winner) {
							t.Fatal("natural contenders committed different original removals")
						}
						winner = out
					}
				}
				if winner.Receipt.Binding.CommandID == "" {
					t.Fatal("no initial natural contender committed")
				}
				if out, err := s.RemoveTeamMember(f.ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, winner) {
					t.Fatal("contention lost original", err)
				}
				return
			}
			remove := variant == "remove-audit" || variant == "remove-outbox"
			action := "identity.organization.add_team_member"
			if remove {
				if _, err := s.AddTeamMember(f.ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
				action = "identity.organization.remove_team_member"
			}
			table, condition := "audit.records", "NEW.action='"+action+"' AND NEW.outcome=1"
			if variant == "add-outbox" || variant == "remove-outbox" {
				table = "outbox_messages"
				condition = "NEW.topic='team.membership_changed.v1'"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.fail_team_member_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled team member failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_member_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_team_member_operation()`); err != nil {
				t.Fatal(err)
			}
			var out organization.StoreResult
			var failure error
			if remove {
				out, failure = s.RemoveTeamMember(f.ctx, removeTeamMemberOperationRequest(r), "127.0.0.1")
			} else {
				out, failure = s.AddTeamMember(f.ctx, r, "127.0.0.1")
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `DROP TRIGGER fail_team_member_operation ON `+table+`;DROP FUNCTION organization.fail_team_member_operation()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required effect failure committed membership", failure)
			}
			var epoch, effects int
			var active bool
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT version::integer,(SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.team.member-remove'),EXISTS(SELECT 1 FROM organization.team_memberships WHERE state='active') FROM organization.organizations WHERE tenant_id='org-test-basic'`).Scan(&epoch, &effects, &active); err != nil || effects != 0 || remove && (epoch != 4 || !active) || !remove && (epoch != 3 || active) {
				t.Fatal("rollback retained member/authority/effects", err)
			}
		})
	}
}
