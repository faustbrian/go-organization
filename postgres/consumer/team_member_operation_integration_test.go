//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type teamMemberLookupTraceKey struct{}
type teamMemberLookupBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *teamMemberLookupBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT command_id,remove_team_id") && strings.Contains(data.SQL, "identity.organization.team.member-remove") {
		return context.WithValue(ctx, teamMemberLookupTraceKey{}, true)
	}
	return ctx
}
func (b *teamMemberLookupBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(teamMemberLookupTraceKey{}).(bool)
	if !selected || data.Err != nil || data.CommandTag.RowsAffected() != 0 || b.observed.Add(1) > 2 {
		return
	}
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func TestOrganizationGenuineTeamMemberOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "team-member-operation")
}

type teamMemberAdmissionEvaluator struct{}

func (*teamMemberAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if r.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.AddTeamMember) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.AddTeamMember) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

func exerciseGenuineTeamMembership(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication, logout reference.SessionService) {
	t.Helper()
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7001}, organizationpg.TeamMemberOperationLookupMigrationSource{Version: 7002}} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, steps...)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("actual team membership migrations", err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "team-member-consumer", Revision: 9, Evaluator: new(teamMemberAdmissionEvaluator)})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	source := func(primary *database.Pool, policy authorization.Service) *organizationpg.Service {
		return teamCreateConsumerSource(t, primary, sessions, profile, lookup, keys, material, policy)
	}
	build := func(primary *database.Pool, policy authorization.Service) *organizationpg.OperationService {
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("team-member-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("team-member-consumer", map[string][]byte{"team-member-consumer": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		s, err := organizationpg.NewOperationService(source(primary, policy), organizationpg.OperationServiceConfig{ConfigurationID: "team-member-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	newID := func() organization.ID {
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		return organization.ID(id)
	}
	commit := func(s *organizationpg.Service, p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := s.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("real team setup", err)
		}
	}
	setup := func(label string, role organization.Role) organization.AddTeamMemberOperationRequest {
		org, team := newID(), newID()
		s := source(pool, authorize)
		p, err := s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Team membership consumer", Slug: "team-member-" + label, CorrelationID: "team-member-setup"}, "127.0.0.1")
		commit(s, p, err)
		p, err = s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: role, CorrelationID: "team-member-setup"}, "127.0.0.1")
		commit(s, p, err)
		p, err = s.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, TeamID: team, Name: "Engineering", CorrelationID: "team-member-setup"}, "127.0.0.1")
		commit(s, p, err)
		key, err := identity.NewIdempotencyKey([]byte("team-member-original-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return organization.AddTeamMemberOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, TeamID: team, UserID: memberID, OrganizationVersion: 3, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-member-original"}
	}
	removeRequest := func(r organization.AddTeamMemberOperationRequest) organization.RemoveTeamMemberOperationRequest {
		return organization.RemoveTeamMemberOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion + 1, TeamVersion: r.TeamVersion + 1, OrganizationMemberVersion: r.OrganizationMemberVersion, MembershipVersion: r.MembershipVersion + 1, CorrelationID: "team-member-natural-removal"}
	}
	assertEffects := func(out organization.StoreResult, op organization.Operation) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		action := "identity.organization.add_team_member"
		if op == organization.RemoveTeamMember {
			action = "identity.organization.remove_team_member"
		}
		var effects, audits, events int
		err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.action=$4 AND r.outcome=1),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$3 AND m.topic='team.membership_changed.v1')`, string(out.Receipt.Binding.CommandID), string(op), raw, action).Scan(&effects, &audits, &events)
		if err != nil || effects != 1 || audits != 1 || events != 1 {
			t.Fatal("original membership lost singleton effects", effects, audits, events, err)
		}
	}
	assertBinding := func(r organization.AddTeamMemberOperationRequest, epoch, teamVersion, bindingVersion, admissionVersion int, active bool) {
		t.Helper()
		var actualEpoch, actualTeam, actualBinding, actualAdmission int
		var actualActive bool
		err := db.QueryRowContext(ctx, `SELECT o.version::integer,t.version::integer,tm.version::integer,tm.organization_member_version::integer,tm.state='active' FROM organization.organizations o JOIN organization.teams t USING(tenant_id,organization_id) JOIN organization.team_memberships tm USING(tenant_id,organization_id,team_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND t.team_id=$3 AND tm.user_id=$4`, string(owner.TenantID), string(r.OrganizationID), string(r.TeamID), string(memberID)).Scan(&actualEpoch, &actualTeam, &actualBinding, &actualAdmission, &actualActive)
		if err != nil || actualEpoch != epoch || actualTeam != teamVersion || actualBinding != bindingVersion || actualAdmission != admissionVersion || actualActive != active {
			t.Fatal("exact team admission/epoch diverged", actualEpoch, actualTeam, actualBinding, actualAdmission, actualActive, err)
		}
	}
	assertNoTeams := func(r organization.AddTeamMemberOperationRequest) {
		t.Helper()
		s := build(pool, authorize)
		q := organization.TeamReadRequest{Authentication: member, OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "team-member-invalidation"}
		v, err := s.ListMyTeams(ctx, q)
		if err != nil || len(v.Teams) != 0 {
			t.Fatal("stale team membership revived", err)
		}
		q.TeamID = r.TeamID
		if _, err := s.ListTeamMembers(ctx, q); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("stale binding retained team reader", err)
		}
	}
	r := setup("original", organization.RoleMember)
	if _, err := build(pool, authorize).Get(ctx, organization.ReadRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, CorrelationID: "team-write-without-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("organization read was not actually denied", err)
	}
	original, err := build(pool, authorize).AddTeamMember(ctx, r, "127.0.0.1")
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.MemberID != memberID || original.OrganizationID != r.OrganizationID || original.Receipt.Feature == nil || original.Receipt.Feature.BeforeVersion != 3 || original.Receipt.Feature.AfterVersion != 4 {
		t.Fatal("genuine original-key admission", err)
	}
	assertEffects(original, organization.AddTeamMember)
	assertBinding(r, 4, 2, 1, 1, true)
	q := organization.TeamReadRequest{Authentication: member, OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "genuine-team-read"}
	if v, err := build(pool, authorize).ListMyTeams(ctx, q); err != nil || len(v.Teams) != 1 || v.Teams[0].ID != r.TeamID {
		t.Fatal("actual member own teams", err)
	}
	q.TeamID = r.TeamID
	if v, err := build(pool, authorize).ListTeamMembers(ctx, q); err != nil || len(v.TeamMembers) != 1 || v.TeamMembers[0].UserID != memberID || v.TeamMembers[0].Version != 1 || v.TeamMembers[0].OrganizationMemberVersion != 1 {
		t.Fatal("actual member team-members", err)
	}
	r.Authentication = signinOwner()
	r.CorrelationID = "fresh-reconstructed-team-member"
	if out, err := build(pool, authorize).AddTeamMember(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, original) {
		t.Fatal("fresh session changed original admission", err)
	}
	for _, change := range []func(*organization.AddTeamMemberOperationRequest){func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationID = newID() }, func(r *organization.AddTeamMemberOperationRequest) { r.TeamID = newID() }, func(r *organization.AddTeamMemberOperationRequest) { r.UserID = ownerID }, func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.TeamVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.OrganizationMemberVersion++ }, func(r *organization.AddTeamMemberOperationRequest) { r.MembershipVersion++ }} {
		bad := r
		change(&bad)
		if _, err := build(pool, authorize).AddTeamMember(ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed team admission intent accepted", err)
		}
	}
	for _, a := range []organization.Authentication{member, {TenantID: "foreign", Bearer: r.Authentication.Bearer}} {
		bad := r
		bad.Authentication = a
		if out, err := build(pool, authorize).AddTeamMember(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager/foreign actor adopted original admission", err)
		}
	}
	// Remove/readmit the organization member through its real owner. The retained
	// active team row must not become authority for the new organization admission.
	s := source(pool, authorize)
	p, err := s.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, UserID: memberID, OrganizationVersion: 4, MemberVersion: 1, CorrelationID: "remove-org-admission"}, "127.0.0.1")
	commit(s, p, err)
	p, err = s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 5, MemberVersion: 2, CorrelationID: "readmit-org-admission"}, "127.0.0.1")
	commit(s, p, err)
	assertNoTeams(r)
	next := r
	next.OrganizationVersion = 6
	next.TeamVersion = 2
	next.OrganizationMemberVersion = 3
	next.MembershipVersion = 1
	next.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("exact-new-org-admission"))
	if err != nil {
		t.Fatal(err)
	}
	readmitted, err := build(pool, authorize).AddTeamMember(ctx, next, "127.0.0.1")
	if err != nil || readmitted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("new exact organization admission denied", err)
	}
	assertBinding(next, 7, 3, 2, 3, true)
	x := removeRequest(next)
	removed, err := build(pool, authorize).RemoveTeamMember(ctx, x, "127.0.0.1")
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted || removed.Receipt.Feature == nil || removed.Receipt.Feature.BeforeVersion != 7 || removed.Receipt.Feature.AfterVersion != 8 {
		t.Fatal("genuine natural removal", err)
	}
	assertEffects(removed, organization.RemoveTeamMember)
	assertBinding(next, 8, 4, 3, 3, false)
	assertNoTeams(next)
	for range 2 {
		reconstructed := build(pool, authorize)
		if out, err := reconstructed.RemoveTeamMember(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, removed) {
			t.Fatal("natural reconstruction changed original removal", err)
		}
		if out, err := reconstructed.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: x.Authentication, Binding: removed.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, removed) {
			t.Fatal("explicit original team removal", err)
		}
		if out, err := reconstructed.AddTeamMember(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("old admission receipt changed after binding removal", err)
		}
	}
	for _, change := range []func(*organization.RemoveTeamMemberOperationRequest){func(r *organization.RemoveTeamMemberOperationRequest) { r.TeamID = newID() }, func(r *organization.RemoveTeamMemberOperationRequest) { r.UserID = ownerID }, func(r *organization.RemoveTeamMemberOperationRequest) { r.OrganizationVersion++ }, func(r *organization.RemoveTeamMemberOperationRequest) { r.TeamVersion++ }, func(r *organization.RemoveTeamMemberOperationRequest) { r.OrganizationMemberVersion++ }, func(r *organization.RemoveTeamMemberOperationRequest) { r.MembershipVersion++ }} {
		bad := x
		change(&bad)
		if out, err := build(pool, authorize).RemoveTeamMember(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed removal adopted original", err)
		}
	}
	for _, a := range []organization.Authentication{member, {TenantID: "foreign", Bearer: x.Authentication.Bearer}} {
		bad := x
		bad.Authentication = a
		if out, err := build(pool, authorize).RemoveTeamMember(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager/foreign actor adopted original removal", err)
		}
	}
	for _, label := range []string{"add-audit", "add-outbox", "remove-audit", "remove-outbox"} {
		t.Run("atomic rollback "+label, func(t *testing.T) {
			request := setup(label, organization.RoleMember)
			remove := strings.HasPrefix(label, "remove-")
			if remove {
				if _, err := build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			action := "identity.organization.add_team_member"
			if remove {
				action = "identity.organization.remove_team_member"
			}
			table, condition := "audit.records", "NEW.action='"+action+"' AND NEW.outcome=1"
			if strings.HasSuffix(label, "outbox") {
				table = "outbox_messages"
				condition = "NEW.topic='team.membership_changed.v1'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.fail_team_member_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled team membership effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_member_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_team_member_operation()`); err != nil {
				t.Fatal(err)
			}
			var out organization.StoreResult
			var failure error
			if remove {
				out, failure = build(pool, authorize).RemoveTeamMember(ctx, removeRequest(request), "127.0.0.1")
			} else {
				out, failure = build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1")
			}
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_team_member_operation ON `+table+`;DROP FUNCTION organization.fail_team_member_operation()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required effect failure committed team membership", failure)
			}
			if remove {
				assertBinding(request, 4, 2, 1, 1, true)
			} else {
				var bindings, epoch, effects int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.team_memberships WHERE organization_id=$1),(SELECT version FROM organization.organizations WHERE organization_id=$1),(SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.team.member-add')`, string(request.OrganizationID)).Scan(&bindings, &epoch, &effects); err != nil || bindings != 0 || epoch != 3 || effects != 0 {
					t.Fatal("aborted admission retained authority/effect", err)
				}
				if got, err := build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1"); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, out) {
					t.Fatal("aborted keyed original reexecuted", err)
				}
			}
		})
	}
	t.Run("legacy raw removal cannot invent natural history", func(t *testing.T) {
		request := setup("legacy", organization.RoleMember)
		if _, err := build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		x := removeRequest(request)
		plain := source(pool, authorize)
		p, err := plain.PrepareRemoveTeamMember(ctx, organization.TeamMemberRequest{Authentication: x.Authentication, CommandID: commandID(t), OrganizationID: x.OrganizationID, TeamID: x.TeamID, UserID: x.UserID, OrganizationVersion: x.OrganizationVersion, TeamVersion: x.TeamVersion, OrganizationMemberVersion: x.OrganizationMemberVersion, MembershipVersion: x.MembershipVersion, CorrelationID: x.CorrelationID}, "127.0.0.1")
		commit(plain, p, err)
		if out, err := build(pool, authorize).RemoveTeamMember(ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("legacy terminal binding became natural success", err)
		}
		var legacy int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.team.member-remove' AND remove_team_id IS NULL`, string(request.OrganizationID)).Scan(&legacy); err != nil || legacy != 1 {
			t.Fatal("raw removal unexpectedly gained optional correlation", err)
		}
	})
	for _, label := range []string{"mapping-loss", "add-commit-loss", "remove-commit-loss"} {
		t.Run(label, func(t *testing.T) {
			request := setup(label, organization.RoleMember)
			remove := label == "remove-commit-loss"
			if remove {
				if _, err := build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			fault := new(commitResponseLoss)
			primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
					if err != nil {
						return nil, err
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := primary.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			fault.count.Store(-1)
			if label == "mapping-loss" {
				fault.count.Store(1)
			}
			if remove {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			var unknown organization.StoreResult
			if remove {
				unknown, err = build(primary, authorize).RemoveTeamMember(ctx, removeRequest(request), "127.0.0.1")
			} else {
				unknown, err = build(primary, authorize).AddTeamMember(ctx, request, "127.0.0.1")
			}
			var ambiguity identity.UnknownCommitError
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" || errors.As(err, &ambiguity) && ambiguity.CommandID != unknown.Receipt.Binding.CommandID {
				t.Fatal("lost COMMIT discarded exact original correlation", err)
			}
			for range 2 {
				var out organization.StoreResult
				if remove {
					out, err = build(pool, authorize).RemoveTeamMember(ctx, removeRequest(request), "127.0.0.1")
				} else {
					out, err = build(pool, authorize).AddTeamMember(ctx, request, "127.0.0.1")
				}
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown retry allocated a new command")
				}
				if label == "mapping-loss" {
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping ambiguity granted execution", err)
					}
				} else {
					if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("lost committed membership did not recover", err)
					}
					op := organization.AddTeamMember
					if remove {
						op = organization.RemoveTeamMember
					}
					assertEffects(out, op)
				}
			}
			if label == "mapping-loss" {
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims, bindings int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.team_memberships WHERE organization_id=$2)`, raw, string(request.OrganizationID)).Scan(&journals, &claims, &bindings); err != nil || journals != 0 || claims != 0 || bindings != 0 {
					t.Fatal("mapping-only ambiguity created domain execution", err)
				}
			}
		})
	}
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyed admission contention", true: "natural removal contention"}[remove], func(t *testing.T) {
			r := setup(map[bool]string{false: "add-race", true: "remove-race"}[remove], organization.RoleMember)
			if remove {
				if _, err := build(pool, authorize).AddTeamMember(ctx, r, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			start := make(chan struct{})
			primary := pool
			var barrier *teamMemberLookupBarrier
			var unblock func()
			if remove {
				release := make(chan struct{})
				var once sync.Once
				unblock = func() { once.Do(func() { close(release) }) }
				defer unblock()
				barrier = &teamMemberLookupBarrier{ready: make(chan struct{}, 2), release: release}
				var err error
				primary, err = database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
					c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
					c.ConnConfig.Tracer = barrier
					return nil
				}})
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if err := primary.Close(cleanup); err != nil {
						t.Error(err)
					}
				}()
			}
			results := make(chan organization.StoreResult, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					<-start
					var out organization.StoreResult
					if remove {
						out, _ = build(primary, authorize).RemoveTeamMember(ctx, removeRequest(r), "127.0.0.1")
					} else {
						out, _ = build(pool, authorize).AddTeamMember(ctx, r, "127.0.0.1")
					}
					results <- out
				})
			}
			close(start)
			if remove {
				for range 2 {
					select {
					case <-barrier.ready:
					case <-results:
						unblock()
						wg.Wait()
						t.Fatal("natural removal returned before both original empty lookups")
					case <-ctx.Done():
						unblock()
						wg.Wait()
						t.Fatal("bounded original lookup barrier expired")
					}
				}
				unblock()
			}
			wg.Wait()
			close(results)
			var winner organization.StoreResult
			for out := range results {
				if remove && out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("losing natural contender did not recover actual winner")
				}
				if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(out, winner) {
						t.Fatal("contenders committed different originals")
					}
					winner = out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("neither initial contender committed")
			}
			op := organization.AddTeamMember
			if remove {
				op = organization.RemoveTeamMember
			}
			assertEffects(winner, op)
			if remove {
				assertBinding(r, 5, 3, 2, 1, false)
			} else {
				assertBinding(r, 4, 2, 1, 1, true)
			}
			var effects int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(r.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 1 {
				t.Fatal("initial contention duplicated protected mutation", effects, err)
			}
		})
	}
	var independentOrg organization.ID
	for _, remove := range []bool{false, true} {
		for _, stage := range []string{"management", "query"} {
			t.Run(map[bool]string{false: "add", true: "remove"}[remove]+" late manager "+stage, func(t *testing.T) {
				selected := setup(map[bool]string{false: "add", true: "remove"}[remove]+"-withdraw-"+stage, organization.RoleOwner)
				out, err := build(pool, authorize).AddTeamMember(ctx, selected, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				op, epoch := organization.AddTeamMember, uint64(4)
				if remove {
					out, err = build(pool, authorize).RemoveTeamMember(ctx, removeRequest(selected), "127.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					op, epoch = organization.RemoveTeamMember, 5
				}
				hook := &invitationCancellationPolicy{base: authorize}
				managementSeen, querySeen, withdrawn := false, false, false
				managementCalls, recoveryAdmission := 0, 1
				if remove {
					recoveryAdmission = 2
				}
				hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
					if withdrawn || d.Request.Action != authorization.Action(op) {
						return nil
					}
					switch string(d.Request.Resource.Type) {
					case "organization":
						managementCalls++
						// Natural removal authorizes lookup first. Arm only after
						// native Recover captures its own admission, not before the
						// preliminary QueryCommand or its earlier policy callback.
						if managementCalls < recoveryAdmission {
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
					plain := source(pool, authorize)
					p, err := plain.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: selected.OrganizationID, OrganizationVersion: epoch, UserID: ownerID, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-team-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					changed, err := plain.Execute(ctx, p)
					withdrawn = err == nil && changed.Receipt.Outcome == identity.CommitOutcomeCommitted
					if !withdrawn {
						return organization.ErrUnavailable
					}
					return nil
				}
				var denied organization.StoreResult
				if remove {
					denied, err = build(pool, hook).RemoveTeamMember(ctx, removeRequest(selected), "127.0.0.1")
				} else {
					denied, err = build(pool, hook).AddTeamMember(ctx, selected, "127.0.0.1")
				}
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || managementCalls < recoveryAdmission || stage == "query" && !querySeen || denied.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn manager disclosed team original", err)
				}
				assertEffects(out, op)
				independentOrg = selected.OrganizationID
			})
		}
	}
	t.Run("actual SignOut denies saved admission and removal", func(t *testing.T) {
		fresh := signinOwner()
		r.Authentication = fresh
		x.Authentication = fresh
		if out, err := build(pool, authorize).RemoveTeamMember(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, removed) {
			t.Fatal("fresh session lost original before logout", err)
		}
		token, err := session.ParseToken(fresh.Bearer.Token())
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialBearer, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "team-member-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual source logout", err)
		}
		if out, err := build(pool, authorize).AddTeamMember(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered admission", err)
		}
		if out, err := build(pool, authorize).RemoveTeamMember(ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered removal", err)
		}
		if _, err := build(pool, authorize).ListTeamMembers(ctx, organization.TeamReadRequest{Authentication: member, OrganizationID: independentOrg, TeamID: func() organization.ID {
			var id string
			if err := db.QueryRowContext(ctx, `SELECT team_id FROM organization.teams WHERE organization_id=$1`, string(independentOrg)).Scan(&id); err != nil {
				t.Fatal(err)
			}
			return organization.ID(id)
		}(), Limit: 10, CorrelationID: "independent-team-owner"}); err != nil {
			t.Fatal("logout revoked independent owner", err)
		}
		assertEffects(original, organization.AddTeamMember)
		assertEffects(removed, organization.RemoveTeamMember)
	})
}
