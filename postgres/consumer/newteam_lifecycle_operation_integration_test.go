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

	auditpg "github.com/faustbrian/go-audit/postgres"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

func TestOrganizationGenuineTeamLifecycleOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "team-lifecycle-operation")
}

type teamLifecycleAdmissionEvaluator struct{}

func (*teamLifecycleAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if r.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (r.Action == authorization.Action(organization.UpdateTeam) || r.Action == authorization.Action(organization.CreateTeam)) && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type teamDeleteLookupTraceKey struct{}
type teamDeleteLookupBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *teamDeleteLookupBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT command_id,delete_team_id") && strings.Contains(data.SQL, "identity.organization.team.delete") {
		return context.WithValue(ctx, teamDeleteLookupTraceKey{}, true)
	}
	return ctx
}
func (b *teamDeleteLookupBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(teamDeleteLookupTraceKey{}).(bool)
	if !selected || data.Err != nil || data.CommandTag.RowsAffected() != 0 || b.observed.Add(1) > 2 {
		return
	}
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func teamLifecycleConsumerSource(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, authorize authorization.Service) *organizationpg.Service {
	t.Helper()
	repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	teams := organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 100, LifecycleVersion: 1}
	participant, err := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams})
	if err != nil {
		t.Fatal(err)
	}
	policy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, participant})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func exerciseGenuineTeamLifecycleOperations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication, logout reference.SessionService) {
	t.Helper()
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7001}, organizationpg.TeamLifecycleMigrationSource{Version: 7002}, organizationpg.TeamDeleteOperationLookupMigrationSource{Version: 7003}} {
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
		t.Fatal(err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "team-lifecycle-consumer", Revision: 9, Evaluator: new(teamLifecycleAdmissionEvaluator)})
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
		return teamLifecycleConsumerSource(t, primary, sessions, profile, lookup, keys, material, policy)
	}
	build := func(primary *database.Pool, policy authorization.Service) *organizationpg.OperationService {
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("team-lifecycle-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("team-lifecycle-consumer", map[string][]byte{"team-lifecycle-consumer": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		s, err := organizationpg.NewOperationService(source(primary, policy), organizationpg.OperationServiceConfig{ConfigurationID: "team-lifecycle-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
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
			t.Fatal(err)
		}
	}
	setup := func(label string, role organization.Role) (organization.UpdateTeamOperationRequest, organization.StoreResult) {
		org, team := newID(), newID()
		s := source(pool, authorize)
		p, err := s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Team lifecycle consumer", Slug: "team-life-" + label, CorrelationID: "team-lifecycle-setup"}, "127.0.0.1")
		commit(s, p, err)
		p, err = s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: role, CorrelationID: "team-lifecycle-setup"}, "127.0.0.1")
		commit(s, p, err)
		key, err := identity.NewIdempotencyKey([]byte("original-team-create-" + label))
		if err != nil {
			t.Fatal(err)
		}
		r := organization.CreateTeamOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, TeamID: team, OrganizationVersion: 2, Name: "Engineering", CorrelationID: "team-lifecycle-setup"}
		created, err := build(pool, authorize).CreateTeam(ctx, r, "127.0.0.1")
		if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("published team creation setup", err)
		}
		if out, err := build(pool, authorize).CreateTeam(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, created) {
			t.Fatal("published CreateTeam original requires general org read", err)
		}
		p, err = s.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, TeamID: team, UserID: memberID, OrganizationVersion: 3, TeamVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "team-lifecycle-setup"}, "127.0.0.1")
		commit(s, p, err)
		key, err = identity.NewIdempotencyKey([]byte("original-team-rename-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return organization.UpdateTeamOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, TeamID: team, OrganizationVersion: 4, TeamVersion: 2, Name: "Platform", CorrelationID: "original-team-rename"}, created
	}
	deletion := func(r organization.UpdateTeamOperationRequest) organization.DeleteTeamOperationRequest {
		return organization.DeleteTeamOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: r.OrganizationVersion + 1, TeamVersion: r.TeamVersion + 1, CorrelationID: "original-team-delete"}
	}
	assertEffects := func(out organization.StoreResult, op organization.Operation) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		topic, action := "team.updated.v1", "identity.organization.update_team"
		if op == organization.DeleteTeam {
			topic, action = "team.deleted.v1", "identity.organization.delete_team"
		}
		var effects, audits, events int
		err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.action=$4 AND r.outcome=1),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$3 AND m.topic=$5)`, string(out.Receipt.Binding.CommandID), string(op), raw, action, topic).Scan(&effects, &audits, &events)
		if err != nil || effects != 1 || audits != 1 || events != 1 {
			t.Fatal("lifecycle original lost singleton required effects", err)
		}
	}
	assertState := func(r organization.UpdateTeamOperationRequest, epoch, teamVersion, retired int, name string) {
		t.Helper()
		var actualEpoch, actualVersion, actualRetired, binding, admission, authority int
		var actualName string
		var active bool
		err := db.QueryRowContext(ctx, `SELECT o.version::integer,coalesce(t.version,0)::integer,coalesce(t.name,''),coalesce(i.deleted_version,0)::integer,tm.version::integer,tm.organization_member_version::integer,tm.state='active',m.authorization_version::integer FROM organization.organizations o JOIN organization.team_identities i USING(tenant_id,organization_id) LEFT JOIN organization.teams t USING(tenant_id,organization_id,team_id) JOIN organization.team_memberships tm USING(tenant_id,organization_id,team_id) JOIN organization.memberships m USING(tenant_id,organization_id,user_id) WHERE o.organization_id=$1 AND i.team_id=$2 AND tm.user_id=$3`, string(r.OrganizationID), string(r.TeamID), string(memberID)).Scan(&actualEpoch, &actualVersion, &actualName, &actualRetired, &binding, &admission, &active, &authority)
		if err != nil || actualEpoch != epoch || actualVersion != teamVersion || actualRetired != retired || actualName != name || binding != 1 || admission != 1 || !active || authority != 2 {
			t.Fatal("rename/delete changed retained admission or wrong terminal state", err)
		}
	}
	r, created := setup("original", organization.RoleMember)
	if _, err := build(pool, authorize).Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, CorrelationID: "denied-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("org read not actually denied", err)
	}
	renamed, err := build(pool, authorize).UpdateTeam(ctx, r, "127.0.0.1")
	if err != nil || renamed.Receipt.Outcome != identity.CommitOutcomeCommitted || renamed.Receipt.Feature == nil || renamed.Receipt.Feature.BeforeVersion != 4 || renamed.Receipt.Feature.AfterVersion != 5 {
		t.Fatal("genuine keyed rename", err)
	}
	assertEffects(renamed, organization.UpdateTeam)
	assertState(r, 5, 3, 0, "Platform")
	q := organization.TeamReadRequest{Authentication: member, OrganizationID: r.OrganizationID, Limit: 10, CorrelationID: "member-rename-view"}
	if v, err := build(pool, authorize).ListMyTeams(ctx, q); err != nil || len(v.Teams) != 1 || v.Teams[0].ID != r.TeamID || v.Teams[0].Name != "Platform" || v.Teams[0].Version != 3 {
		t.Fatal("genuine member cannot observe rename", err)
	}
	if v, err := build(pool, authorize).GetTeam(ctx, organization.TeamReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, TeamID: r.TeamID, CorrelationID: "manager-renamed-team"}); err != nil || v.Team.Name != "Platform" {
		t.Fatal("actual exact team read", err)
	}
	r.Authentication = signinOwner()
	r.CorrelationID = "fresh-reconstructed-rename"
	if out, err := build(pool, authorize).UpdateTeam(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, renamed) {
		t.Fatal("fresh rename retry changed original", err)
	}
	for _, change := range []func(*organization.UpdateTeamOperationRequest){func(r *organization.UpdateTeamOperationRequest) { r.OrganizationID = newID() }, func(r *organization.UpdateTeamOperationRequest) { r.TeamID = newID() }, func(r *organization.UpdateTeamOperationRequest) { r.OrganizationVersion++ }, func(r *organization.UpdateTeamOperationRequest) { r.TeamVersion++ }, func(r *organization.UpdateTeamOperationRequest) { r.Name = "Other" }} {
		bad := r
		change(&bad)
		if _, err := build(pool, authorize).UpdateTeam(ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed original rename intent accepted", err)
		}
	}
	x := deletion(r)
	deleted, err := build(pool, authorize).DeleteTeam(ctx, x, "127.0.0.1")
	if err != nil || deleted.Receipt.Outcome != identity.CommitOutcomeCommitted || deleted.Receipt.Feature == nil || deleted.Receipt.Feature.BeforeVersion != 5 || deleted.Receipt.Feature.AfterVersion != 6 {
		t.Fatal("genuine natural terminal deletion", err)
	}
	assertEffects(deleted, organization.DeleteTeam)
	assertState(r, 6, 0, 4, "")
	for range 2 {
		rebuilt := build(pool, authorize)
		if out, err := rebuilt.DeleteTeam(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
			t.Fatal("reconstructed terminal original changed", err)
		}
		for _, original := range []organization.StoreResult{created, renamed, deleted} {
			if out, err := rebuilt.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
				t.Fatal("fresh explicit team history failed without general read", err)
			}
		}
	}
	q.TeamID = r.TeamID
	if _, err := build(pool, authorize).ListTeamMembers(ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("terminal team retained member access", err)
	}
	q.TeamID = ""
	if v, err := build(pool, authorize).ListMyTeams(ctx, q); err != nil || len(v.Teams) != 0 {
		t.Fatal("terminal team retained own-team view", err)
	}
	for _, change := range []func(*organization.DeleteTeamOperationRequest){func(r *organization.DeleteTeamOperationRequest) { r.TeamID = newID() }, func(r *organization.DeleteTeamOperationRequest) { r.TeamVersion++ }, func(r *organization.DeleteTeamOperationRequest) { r.OrganizationVersion++ }} {
		bad := x
		change(&bad)
		if out, err := build(pool, authorize).DeleteTeam(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed natural selector adopted successful history", err)
		}
	}
	key, err := identity.NewIdempotencyKey([]byte("retired-team-reuse"))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := build(pool, authorize).CreateTeam(ctx, organization.CreateTeamOperationRequest{Authentication: r.Authentication, IdempotencyKey: key, OrganizationID: r.OrganizationID, TeamID: r.TeamID, OrganizationVersion: 6, Name: "Replacement", CorrelationID: "retired-id-reuse"}, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("retired team ID revived", err)
	}
	for _, a := range []organization.Authentication{member, {TenantID: "foreign", Bearer: r.Authentication.Bearer}} {
		bad := r
		bad.Authentication = a
		if out, err := build(pool, authorize).UpdateTeam(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager/tenant adopted rename original", err)
		}
		badDelete := x
		badDelete.Authentication = a
		if out, err := build(pool, authorize).DeleteTeam(ctx, badDelete, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("nonmanager/tenant adopted deletion original", err)
		}
	}
	// Organization re-admission cannot revive retained bindings to a retired ID.
	plain := source(pool, authorize)
	p, err := plain.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: memberID, MemberVersion: 1, CorrelationID: "retired-org-departure"}, "127.0.0.1")
	commit(plain, p, err)
	p, err = plain.PrepareAddMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 7, UserID: memberID, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "retired-org-readmission"}, "127.0.0.1")
	commit(plain, p, err)
	if v, err := build(pool, authorize).ListMyTeams(ctx, q); err != nil || len(v.Teams) != 0 {
		t.Fatal("readmission revived retired binding", err)
	}
	for _, label := range []string{"rename-audit", "rename-outbox", "delete-audit", "delete-outbox"} {
		t.Run("atomic rollback "+label, func(t *testing.T) {
			selected, _ := setup(label, organization.RoleMember)
			deleting := strings.HasPrefix(label, "delete")
			if deleting {
				if _, err := build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			action, topic := "identity.organization.update_team", "team.updated.v1"
			if deleting {
				action, topic = "identity.organization.delete_team", "team.deleted.v1"
			}
			table, condition := "audit.records", "NEW.action='"+action+"' AND NEW.outcome=1"
			if strings.HasSuffix(label, "outbox") {
				table = "outbox_messages"
				condition = "NEW.topic='" + topic + "'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.fail_team_lifecycle_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled lifecycle effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_team_lifecycle_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_team_lifecycle_operation()`); err != nil {
				t.Fatal(err)
			}
			var out organization.StoreResult
			var failure error
			if deleting {
				out, failure = build(pool, authorize).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
			} else {
				out, failure = build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1")
			}
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_team_lifecycle_operation ON `+table+`;DROP FUNCTION organization.fail_team_lifecycle_operation()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required effect failure committed lifecycle mutation", failure)
			}
			if deleting {
				assertState(selected, 5, 3, 0, "Platform")
			} else {
				assertState(selected, 4, 2, 0, "Engineering")
				if got, err := build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1"); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, out) {
					t.Fatal("aborted keyed rename reexecuted", err)
				}
			}
		})
	}
	t.Run("legacy tombstone is not original natural history", func(t *testing.T) {
		selected, _ := setup("legacy", organization.RoleMember)
		s := source(pool, authorize)
		p, err := s.PrepareDeleteTeam(ctx, organization.DeleteTeamRequest{Authentication: selected.Authentication, CommandID: commandID(t), OrganizationID: selected.OrganizationID, TeamID: selected.TeamID, OrganizationVersion: 4, TeamVersion: 2, CorrelationID: "raw-legacy-delete"}, "127.0.0.1")
		commit(s, p, err)
		request := organization.DeleteTeamOperationRequest{Authentication: selected.Authentication, OrganizationID: selected.OrganizationID, TeamID: selected.TeamID, OrganizationVersion: 4, TeamVersion: 2, CorrelationID: "legacy-natural-repeat"}
		if out, err := build(pool, authorize).DeleteTeam(ctx, request, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("legacy tombstone invented original success", err)
		}
		var nullable int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.team.delete' AND delete_team_id IS NULL AND delete_team_version IS NULL`, string(selected.OrganizationID)).Scan(&nullable); err != nil || nullable != 1 {
			t.Fatal("raw deletion invented optional correlation", err)
		}
	})
	for _, label := range []string{"mapping-loss", "rename-commit-loss", "delete-commit-loss"} {
		t.Run(label, func(t *testing.T) {
			selected, _ := setup(label, organization.RoleMember)
			deleting := label == "delete-commit-loss"
			if deleting {
				if _, err := build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1"); err != nil {
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
			if deleting {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			var unknown organization.StoreResult
			if deleting {
				unknown, err = build(primary, authorize).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
			} else {
				unknown, err = build(primary, authorize).UpdateTeam(ctx, selected, "127.0.0.1")
			}
			var ambiguity identity.UnknownCommitError
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" || errors.As(err, &ambiguity) && ambiguity.CommandID != unknown.Receipt.Binding.CommandID {
				t.Fatal("actual lost COMMIT lost original lifecycle scope", err)
			}
			for range 2 {
				var out organization.StoreResult
				if deleting {
					out, err = build(pool, authorize).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
				} else {
					out, err = build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1")
				}
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown retry allocated another command")
				}
				if label == "mapping-loss" {
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only history invented terminal outcome", err)
					}
				} else {
					if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("committed lifecycle command not recovered", err)
					}
					op := organization.UpdateTeam
					if deleting {
						op = organization.DeleteTeam
					}
					assertEffects(out, op)
				}
			}
			if label == "mapping-loss" {
				assertState(selected, 4, 2, 0, "Engineering")
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&journals, &claims); err != nil || journals != 0 || claims != 0 {
					t.Fatal("mapping ambiguity reached execution custody", err)
				}
			}
		})
	}
	for _, deleting := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyed rename contention", true: "natural delete contention"}[deleting], func(t *testing.T) {
			selected, _ := setup(map[bool]string{false: "rename-race", true: "delete-race"}[deleting], organization.RoleMember)
			if deleting {
				if _, err := build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			primary := pool
			var barrier *teamDeleteLookupBarrier
			var unblock func()
			if deleting {
				release := make(chan struct{})
				var once sync.Once
				unblock = func() { once.Do(func() { close(release) }) }
				defer unblock()
				barrier = &teamDeleteLookupBarrier{ready: make(chan struct{}, 2), release: release}
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
			start := make(chan struct{})
			results := make(chan organization.StoreResult, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() {
					<-start
					var out organization.StoreResult
					if deleting {
						out, _ = build(primary, authorize).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
					} else {
						out, _ = build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1")
					}
					results <- out
				})
			}
			close(start)
			if deleting {
				for range 2 {
					select {
					case <-barrier.ready:
					case <-results:
						unblock()
						wg.Wait()
						t.Fatal("delete returned before both actual empty history lookups")
					case <-ctx.Done():
						unblock()
						wg.Wait()
						t.Fatal("bounded delete lookup barrier expired")
					}
				}
				unblock()
			}
			wg.Wait()
			close(results)
			var winner organization.StoreResult
			for out := range results {
				if deleting && out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("losing natural delete did not recover actual winner")
				}
				if out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(out, winner) {
						t.Fatal("initial contenders committed different originals")
					}
					winner = out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("neither initial contender committed")
			}
			op := organization.UpdateTeam
			if deleting {
				op = organization.DeleteTeam
				assertState(selected, 6, 0, 4, "")
			} else {
				assertState(selected, 5, 3, 0, "Platform")
			}
			assertEffects(winner, op)
			var effects int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(selected.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 1 {
				t.Fatal("initial contention duplicated effects before repair", err)
			}
		})
	}
	var independentOrg, independentTeam organization.ID
	for _, deleting := range []bool{false, true} {
		for _, stage := range []string{"management", "query"} {
			t.Run(map[bool]string{false: "rename", true: "delete"}[deleting]+" late manager "+stage, func(t *testing.T) {
				selected, _ := setup(map[bool]string{false: "rename", true: "delete"}[deleting]+"-withdraw-"+stage, organization.RoleOwner)
				original, err := build(pool, authorize).UpdateTeam(ctx, selected, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				op, epoch := organization.UpdateTeam, uint64(5)
				if deleting {
					original, err = build(pool, authorize).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					op, epoch = organization.DeleteTeam, 6
				}
				hook := &invitationCancellationPolicy{base: authorize}
				managementCalls, required := 0, 1
				if deleting {
					required = 2
				}
				managementSeen, querySeen, withdrawn := false, false, false
				hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
					if withdrawn || d.Request.Action != authorization.Action(op) {
						return nil
					}
					switch string(d.Request.Resource.Type) {
					case "organization":
						managementCalls++
						if managementCalls < required {
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
					s := source(pool, authorize)
					p, err := s.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: selected.OrganizationID, OrganizationVersion: epoch, UserID: ownerID, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-original-team-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := s.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
				var out organization.StoreResult
				if deleting {
					out, err = build(pool, hook).DeleteTeam(ctx, deletion(selected), "127.0.0.1")
				} else {
					out, err = build(pool, hook).UpdateTeam(ctx, selected, "127.0.0.1")
				}
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn manager obtained historical lifecycle receipt", err)
				}
				assertEffects(original, op)
				if !deleting {
					independentOrg, independentTeam = selected.OrganizationID, selected.TeamID
				}
			})
		}
	}
	t.Run("actual SignOut denies saved lifecycle originals", func(t *testing.T) {
		fresh := signinOwner()
		r.Authentication = fresh
		x.Authentication = fresh
		if out, err := build(pool, authorize).DeleteTeam(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
			t.Fatal("fresh original lost before real logout", err)
		}
		token, err := session.ParseToken(fresh.Bearer.Token())
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialBearer, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "team-lifecycle-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual lifecycle source logout", err)
		}
		if out, err := build(pool, authorize).UpdateTeam(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered rename", err)
		}
		if out, err := build(pool, authorize).DeleteTeam(ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered terminal deletion", err)
		}
		if v, err := build(pool, authorize).GetTeam(ctx, organization.TeamReadRequest{Authentication: member, OrganizationID: independentOrg, TeamID: independentTeam, CorrelationID: "independent-team-owner"}); err != nil || v.Team.Name != "Platform" {
			t.Fatal("logout revoked independent live-team owner", err)
		}
		assertEffects(renamed, organization.UpdateTeam)
		assertEffects(deleted, organization.DeleteTeam)
	})
}
