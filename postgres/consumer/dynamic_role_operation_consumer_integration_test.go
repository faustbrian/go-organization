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
	"slices"
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

func TestOrganizationGenuineDynamicRoleOperationConsumer(t *testing.T) {
	// baselineRiskPolicy's privileged-operation budget is 20 attempts. Give
	// independent scenario cohorts fresh databases and genuine signup rather
	// than exhausting each other's setup budget or weakening the native policy.
	for _, cohort := range []string{"outcomes", "authority"} {
		t.Run(cohort, func(t *testing.T) {
			exerciseGenuinePasswordConsumer(t, "dynamic-role-operation-"+cohort)
		})
	}
}

type dynamicRoleOperationAdmissionEvaluator struct{}

func (*dynamicRoleOperationAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if r.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (r.Action == authorization.Action(organization.CreateDynamicRole) || r.Action == authorization.Action(organization.UpdateDynamicRole)) && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type dynamicRoleDeleteLookupTraceKey struct{}
type dynamicRoleDeleteLookupBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *dynamicRoleDeleteLookupBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT command_id,delete_role_id") && strings.Contains(data.SQL, "identity.organization.role.delete") {
		return context.WithValue(ctx, dynamicRoleDeleteLookupTraceKey{}, true)
	}
	return ctx
}
func (b *dynamicRoleDeleteLookupBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(dynamicRoleDeleteLookupTraceKey{}).(bool)
	if !selected || data.Err != nil || data.CommandTag.RowsAffected() != 0 || b.observed.Add(1) > 2 {
		return
	}
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func dynamicRoleOperationConsumerSource(t *testing.T, pool *database.Pool, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, keys map[string][32]byte, material func(string) []byte, authorize authorization.Service) *organizationpg.Service {
	t.Helper()
	repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	teams := organization.TeamConfig{Version: 1, MaximumTeams: 10, MaximumMembers: 100, LifecycleVersion: 1}
	roles := customRoleConfig()
	roles.TeamBindingsVersion = 1
	participant, err := organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, DynamicRoles: roles})
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
	s, err := organizationpg.NewService(participant, organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, Teams: teams, DynamicRoles: roles, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}}, Sessions: sessions, Authorization: authorize, Risk: counters, Coordinator: coordinator, Registry: registry})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func exerciseGenuineDynamicRoleOperations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication, logout reference.SessionService, authorityOnly bool) {
	t.Helper()
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7001}, organizationpg.TeamLifecycleMigrationSource{Version: 7002}, organizationpg.DynamicRoleMigrationSource{Version: 7003}, organizationpg.TeamRoleBindingMigrationSource{Version: 7004}, organizationpg.DynamicRoleDeleteOperationLookupMigrationSource{Version: 7005}} {
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
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "dynamic-role-operation-consumer", Revision: 9, Evaluator: new(dynamicRoleOperationAdmissionEvaluator)})
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
		return dynamicRoleOperationConsumerSource(t, primary, sessions, profile, lookup, keys, material, policy)
	}
	build := func(primary *database.Pool, policy authorization.Service) *organizationpg.OperationService {
		query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
		requestKeys, err := kernel.NewRequestKeyConfig("dynamic-role-operation-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("dynamic-role-operation-consumer", map[string][]byte{"dynamic-role-operation-consumer": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		s, err := organizationpg.NewOperationService(source(primary, policy), organizationpg.OperationServiceConfig{ConfigurationID: "dynamic-role-operation-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
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
	key := func(label string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte("role-operation-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	commit := func(t *testing.T, s *organizationpg.Service, p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		if out, err := s.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			// Report only native disposition/counts, never custody or opaque keys,
			// when a genuine setup command is rejected before its scenario starts.
			handle, handleErr := p.Recovery()
			raw, decodeErr := base64.RawURLEncoding.DecodeString(string(handle.Binding.CommandID))
			var allowed bool
			var peak int
			readErr := db.QueryRowContext(ctx, `SELECT c.allowed,max(s.value)::integer FROM risk_store.counter_charges c JOIN risk_store.counter_snapshots s USING(command_id) WHERE c.command_id=$1 GROUP BY c.allowed`, raw).Scan(&allowed, &peak)
			t.Fatalf("actual raw setup owner: operation=%s counter_recorded=%t counter_allowed=%t counter_peak=%d outcome=%v error=%v", handle.Binding.OperationID, handleErr == nil && decodeErr == nil && readErr == nil, allowed, peak, out.Receipt.Outcome, err)
		}
	}
	setup := func(t *testing.T, label string, memberRole organization.Role) organization.CreateDynamicRoleOperationRequest {
		org, role := newID(), newID()
		s := source(pool, authorize)
		p, err := s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Dynamic role operation consumer", Slug: "role-operation-" + label, CorrelationID: "role-operation-setup"}, "127.0.0.1")
		commit(t, s, p, err)
		p, err = s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: memberRole, CorrelationID: "role-operation-setup"}, "127.0.0.1")
		commit(t, s, p, err)
		return organization.CreateDynamicRoleOperationRequest{Authentication: owner, IdempotencyKey: key("create-" + label), OrganizationID: org, RoleID: role, OrganizationVersion: 2, Name: "Document reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "original-role-create"}
	}
	update := func(r organization.CreateDynamicRoleOperationRequest, epoch, version uint64) organization.UpdateDynamicRoleOperationRequest {
		return organization.UpdateDynamicRoleOperationRequest{Authentication: r.Authentication, IdempotencyKey: key("update-" + string(r.RoleID)), OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: epoch, RoleVersion: version, Name: "Reader with explicit deny", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}, {PermissionID: "document-read", ResourceID: "one", Effect: authorization.Deny}}, CorrelationID: "original-role-update"}
	}
	deletion := func(r organization.UpdateDynamicRoleOperationRequest) organization.DeleteDynamicRoleOperationRequest {
		return organization.DeleteDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: r.OrganizationVersion + 1, RoleVersion: r.RoleVersion + 1, CorrelationID: "natural-role-delete"}
	}
	assertEffects := func(out organization.StoreResult, op organization.Operation) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		topic := map[organization.Operation]string{organization.CreateDynamicRole: "organization.role_created.v1", organization.UpdateDynamicRole: "organization.role_updated.v1", organization.DeleteDynamicRole: "organization.role_deleted.v1"}[op]
		var effects, audits, events int
		err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.action=$2 AND r.outcome=1),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$3 AND m.topic=$4)`, string(out.Receipt.Binding.CommandID), string(op), raw, topic).Scan(&effects, &audits, &events)
		if err != nil || effects != 1 || audits != 1 || events != 1 {
			t.Fatal("original role lost singleton required effects", err)
		}
	}
	assertState := func(r organization.CreateDynamicRoleOperationRequest, epoch, version int, state string) {
		t.Helper()
		var actualEpoch, actualVersion int
		var actualState string
		err := db.QueryRowContext(ctx, `SELECT o.version::integer,coalesce(r.version,0)::integer,coalesce(r.state,'') FROM organization.organizations o LEFT JOIN organization.custom_roles r ON r.tenant_id=o.tenant_id AND r.organization_id=o.organization_id AND r.role_id=$2 WHERE o.organization_id=$1`, string(r.OrganizationID), string(r.RoleID)).Scan(&actualEpoch, &actualVersion, &actualState)
		if err != nil || actualEpoch != epoch || actualVersion != version || actualState != state {
			t.Fatal("actual role state/epoch differs", err)
		}
	}
	r := setup(t, "original", organization.RoleMember)
	s := build(pool, authorize)
	if _, err := s.Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, CorrelationID: "denied-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("general org read not actually denied", err)
	}
	created, err := s.CreateDynamicRole(ctx, r, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine role create", err)
	}
	assertEffects(created, organization.CreateDynamicRole)
	assertState(r, 3, 1, "active")
	q := organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetUserID: memberID, CorrelationID: "actual-role-read"}
	v, err := s.GetDynamicRole(ctx, q)
	if err != nil || v.DynamicRole.ID != r.RoleID || v.DynamicRole.Name != r.Name || !reflect.DeepEqual(v.DynamicRole.Statements, r.Statements) {
		t.Fatal("chosen canonical role intent differs", err)
	}
	page, err := s.ListDynamicRoles(ctx, organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, Limit: 1, CorrelationID: "role-page"})
	if err != nil || len(page.DynamicRoles) != 1 || page.DynamicRoles[0].ID != r.RoleID {
		t.Fatal("actual current role list", err)
	}
	plain := source(pool, authorize)
	p, err := plain.PrepareAssignDynamicRole(ctx, organization.RoleBindingRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: r.OrganizationID, RoleID: r.RoleID, OrganizationVersion: 3, RoleVersion: 1, UserID: memberID, OrganizationMemberVersion: v.Target.Version, CorrelationID: "existing-direct-role-owner"}, "127.0.0.1")
	commit(t, plain, p, err)
	team := newID()
	p, err = plain.PrepareCreateTeam(ctx, organization.CreateTeamRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 4, TeamID: team, Name: "Engineering", CorrelationID: "existing-team-owner"}, "127.0.0.1")
	commit(t, plain, p, err)
	p, err = plain.PrepareAddTeamMember(ctx, organization.TeamMemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 5, TeamID: team, TeamVersion: 1, UserID: memberID, OrganizationMemberVersion: 1, CorrelationID: "existing-team-admission-owner"}, "127.0.0.1")
	commit(t, plain, p, err)
	teamRead := q
	teamRead.TargetUserID = ""
	teamRead.TargetTeamID = team
	v, err = s.GetDynamicRole(ctx, teamRead)
	if err != nil {
		t.Fatal(err)
	}
	p, err = plain.PrepareAssignTeamDynamicRole(ctx, organization.TeamRoleBindingRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: r.OrganizationID, RoleID: r.RoleID, TeamID: team, OrganizationVersion: 6, RoleVersion: 1, TeamVersion: v.Team.Version, CorrelationID: "existing-team-role-owner"}, "127.0.0.1")
	commit(t, plain, p, err)
	check := organization.PermissionCheckRequest{Authentication: member, OrganizationID: r.OrganizationID, OrganizationVersion: 7, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "genuine-permission"}
	permission := func(want authorization.Outcome) {
		t.Helper()
		d, err := build(pool, authorize).CheckPermission(ctx, check)
		if err != nil || d.Outcome != want || d.Revision != authorization.Revision(check.OrganizationVersion) {
			t.Fatal("actual effective permission differs", err)
		}
	}
	permission(authorization.Allow)
	nonManager := update(r, 7, 1)
	nonManager.Authentication = member
	if out, err := s.UpdateDynamicRole(ctx, nonManager, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("application role granted static management", err)
	}
	foreign := r
	foreign.Authentication.TenantID = "foreign-tenant"
	if out, err := s.CreateDynamicRole(ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted role original", err)
	}
	check.ResourceID = "other"
	permission(authorization.Deny)
	check.ResourceID = "one"
	ownerCheck := check
	ownerCheck.Authentication = owner
	if d, err := s.CheckPermission(ctx, ownerCheck); err != nil || d.Outcome != authorization.Deny {
		t.Fatal("static management role implied application permission", err)
	}
	u := update(r, 7, 1)
	updated, err := s.UpdateDynamicRole(ctx, u, "127.0.0.1")
	if err != nil || updated.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine role replacement", err)
	}
	assertEffects(updated, organization.UpdateDynamicRole)
	assertState(r, 8, 2, "active")
	if _, err := s.CheckPermission(ctx, check); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("stale policy retained allow", err)
	}
	check.OrganizationVersion = 8
	permission(authorization.Deny)
	r.Authentication = signinOwner()
	u.Authentication = r.Authentication
	if out, err := build(pool, authorize).CreateDynamicRole(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, created) {
		t.Fatal("fresh create original recovery", err)
	}
	if out, err := build(pool, authorize).UpdateDynamicRole(ctx, u, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, updated) {
		t.Fatal("fresh update original recovery", err)
	}
	for _, change := range []func(*organization.UpdateDynamicRoleOperationRequest){func(r *organization.UpdateDynamicRoleOperationRequest) { r.OrganizationID = newID() }, func(r *organization.UpdateDynamicRoleOperationRequest) { r.RoleID = newID() }, func(r *organization.UpdateDynamicRoleOperationRequest) { r.OrganizationVersion++ }, func(r *organization.UpdateDynamicRoleOperationRequest) { r.RoleVersion++ }, func(r *organization.UpdateDynamicRoleOperationRequest) { r.Name = "Other" }, func(r *organization.UpdateDynamicRoleOperationRequest) { slices.Reverse(r.Statements) }} {
		bad := u
		bad.Statements = slices.Clone(u.Statements)
		change(&bad)
		if _, err := s.UpdateDynamicRole(ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("changed original role intent adopted key", err)
		}
	}
	x := deletion(u)
	deleted, err := s.DeleteDynamicRole(ctx, x, "127.0.0.1")
	if err != nil || deleted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine natural retirement", err)
	}
	assertEffects(deleted, organization.DeleteDynamicRole)
	assertState(r, 9, 3, "deleted")
	check.OrganizationVersion = 9
	permission(authorization.Deny)
	if _, err := s.GetDynamicRole(ctx, q); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("retired role exposed live", err)
	}
	for range 2 {
		fresh := build(pool, authorize)
		if out, err := fresh.DeleteDynamicRole(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
			t.Fatal("reconstructed natural original changed", err)
		}
		for _, original := range []organization.StoreResult{created, updated, deleted} {
			if out, err := fresh.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
				t.Fatal("fresh reconstructed original role receipt differs", err)
			}
		}
	}
	for _, change := range []func(*organization.DeleteDynamicRoleOperationRequest){func(r *organization.DeleteDynamicRoleOperationRequest) { r.RoleID = newID() }, func(r *organization.DeleteDynamicRoleOperationRequest) { r.OrganizationVersion++ }, func(r *organization.DeleteDynamicRoleOperationRequest) { r.RoleVersion++ }} {
		bad := x
		change(&bad)
		if out, err := s.DeleteDynamicRole(ctx, bad, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed terminal selector adopted original success", err)
		}
	}
	reuse := r
	reuse.OrganizationVersion = 9
	reuse.IdempotencyKey = key("retired-id")
	if out, err := s.CreateDynamicRole(ctx, reuse, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("retired canonical role ID reused", err)
	}
	p, err = plain.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 9, UserID: memberID, MemberVersion: 1, CorrelationID: "retired-role-member-removal"}, "127.0.0.1")
	commit(t, plain, p, err)
	p, err = plain.PrepareAddMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 10, UserID: memberID, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "retired-role-readmission"}, "127.0.0.1")
	commit(t, plain, p, err)
	check.OrganizationVersion = 11
	permission(authorization.Deny)
	var directBindings, teamBindings int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.role_bindings WHERE organization_id=$1 AND state='active'),(SELECT count(*) FROM organization.team_role_bindings WHERE organization_id=$1 AND state='active')`, string(r.OrganizationID)).Scan(&directBindings, &teamBindings); err != nil || directBindings != 1 || teamBindings != 1 {
		t.Fatal("retirement/readmission rewrote retained role bindings", err)
	}
	reuse.RoleID = newID()
	reuse.OrganizationVersion = 11
	reuse.IdempotencyKey = key("second-retained-role")
	if _, err := s.CreateDynamicRole(ctx, reuse, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	reuse.RoleID = newID()
	reuse.OrganizationVersion = 12
	reuse.IdempotencyKey = key("over-retained-role-limit")
	if out, err := s.CreateDynamicRole(ctx, reuse, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("retired role stopped counting toward native maximum", err)
	}

	scenario := func(t *testing.T, label string, op organization.Operation, memberRole organization.Role) (organization.CreateDynamicRoleOperationRequest, organization.UpdateDynamicRoleOperationRequest) {
		r := setup(t, label, memberRole)
		u := update(r, 3, 1)
		if op != organization.CreateDynamicRole {
			if _, err := build(pool, authorize).CreateDynamicRole(ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
		}
		if op == organization.DeleteDynamicRole {
			if _, err := build(pool, authorize).UpdateDynamicRole(ctx, u, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
		}
		return r, u
	}
	invoke := func(s *organizationpg.OperationService, r organization.CreateDynamicRoleOperationRequest, u organization.UpdateDynamicRoleOperationRequest, op organization.Operation) (organization.StoreResult, error) {
		switch op {
		case organization.CreateDynamicRole:
			return s.CreateDynamicRole(ctx, r, "127.0.0.1")
		case organization.UpdateDynamicRole:
			return s.UpdateDynamicRole(ctx, u, "127.0.0.1")
		default:
			return s.DeleteDynamicRole(ctx, deletion(u), "127.0.0.1")
		}
	}
	operations := []organization.Operation{organization.CreateDynamicRole, organization.UpdateDynamicRole, organization.DeleteDynamicRole}
	if !authorityOnly {
		for i, op := range operations {
			for _, boundary := range []string{"audit", "outbox"} {
				t.Run(string(op)+" rollback "+boundary, func(t *testing.T) {
					selected, replacement := scenario(t, "rollback-"+string(rune('a'+i))+"-"+boundary, op, organization.RoleMember)
					table, condition := "audit.records", "NEW.action='"+string(op)+"' AND NEW.outcome=1"
					if boundary == "outbox" {
						table = "public.identity_outbox_bindings"
						condition = "true"
					}
					if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.fail_role_operation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled role effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_role_operation BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_role_operation()`); err != nil {
						t.Fatal(err)
					}
					out, failure := invoke(build(pool, authorize), selected, replacement, op)
					if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_role_operation ON `+table+`;DROP FUNCTION organization.fail_role_operation()`); err != nil {
						t.Fatal(err)
					}
					if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
						t.Fatal("required role effect failure committed", failure)
					}
					state := "active"
					if i == 0 {
						state = ""
					}
					assertState(selected, 2+i, i, state)
					var effects int
					if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(selected.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 0 {
						t.Fatal("failed role transition retained original effect", err)
					}
					if op != organization.DeleteDynamicRole {
						if again, err := invoke(build(pool, authorize), selected, replacement, op); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(again, out) {
							t.Fatal("aborted original key reexecuted", err)
						}
					}
				})
			}
		}
		t.Run("legacy terminal role lacks natural original", func(t *testing.T) {
			selected, replacement := scenario(t, "legacy", organization.DeleteDynamicRole, organization.RoleMember)
			x := deletion(replacement)
			s := source(pool, authorize)
			p, err := s.PrepareDeleteDynamicRole(ctx, organization.DynamicRoleRequest{Authentication: selected.Authentication, CommandID: commandID(t), OrganizationID: selected.OrganizationID, RoleID: selected.RoleID, OrganizationVersion: x.OrganizationVersion, RoleVersion: x.RoleVersion, CorrelationID: "legacy-explicit-role-delete"}, "127.0.0.1")
			commit(t, s, p, err)
			if out, err := build(pool, authorize).DeleteDynamicRole(ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("legacy tombstone manufactured natural receipt", err)
			}
			var nullable int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.role.delete' AND delete_role_id IS NULL AND delete_role_version IS NULL`, string(selected.OrganizationID)).Scan(&nullable); err != nil || nullable != 1 {
				t.Fatal("legacy writer invented optional original selectors", err)
			}
		})
		for _, label := range []string{"create-mapping-loss", "create-commit-loss", "update-mapping-loss", "update-commit-loss", "delete-commit-loss"} {
			t.Run(label, func(t *testing.T) {
				op, index := organization.CreateDynamicRole, 0
				if strings.HasPrefix(label, "update") {
					op, index = organization.UpdateDynamicRole, 1
				}
				if strings.HasPrefix(label, "delete") {
					op, index = organization.DeleteDynamicRole, 2
				}
				selected, replacement := scenario(t, label, op, organization.RoleMember)
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
				mapping := strings.Contains(label, "mapping")
				fault.count.Store(-1)
				if mapping {
					fault.count.Store(1)
				}
				if op == organization.DeleteDynamicRole {
					fault.count.Store(0)
				}
				fault.armed.Store(true)
				unknown, err := invoke(build(primary, authorize), selected, replacement, op)
				if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
					t.Fatal("actual public role COMMIT loss discarded original scope", err)
				}
				for range 2 {
					out, err := invoke(build(pool, authorize), selected, replacement, op)
					if out.Receipt.Binding != unknown.Receipt.Binding {
						t.Fatal("unknown public role retry changed original")
					}
					if mapping {
						var ambiguity identity.UnknownCommitError
						if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
							t.Fatal("mapping-only role request invented terminal outcome", err)
						}
					} else {
						if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
							t.Fatal("lost committed role outcome not recovered", err)
						}
						assertEffects(out, op)
					}
				}
				if mapping {
					state := "active"
					if index == 0 {
						state = ""
					}
					assertState(selected, 2+index, index, state)
					raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
					if err != nil {
						t.Fatal(err)
					}
					var journals, claims int
					if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&journals, &claims); err != nil || journals != 0 || claims != 0 {
						t.Fatal("mapping-only role request reached execution custody", err)
					}
				}
			})
		}
		for index, op := range operations {
			t.Run(string(op)+" initial contention", func(t *testing.T) {
				selected, replacement := scenario(t, "contention-"+string(rune('a'+index)), op, organization.RoleMember)
				primary := pool
				var barrier *dynamicRoleDeleteLookupBarrier
				var unblock func()
				if op == organization.DeleteDynamicRole {
					release := make(chan struct{})
					var once sync.Once
					unblock = func() { once.Do(func() { close(release) }) }
					defer unblock()
					barrier = &dynamicRoleDeleteLookupBarrier{ready: make(chan struct{}, 2), release: release}
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
				services := []*organizationpg.OperationService{build(primary, authorize), build(primary, authorize)}
				start := make(chan struct{})
				type result struct {
					out organization.StoreResult
					err error
				}
				results := make(chan result, 2)
				var wg sync.WaitGroup
				for i := range 2 {
					wg.Go(func() {
						<-start
						out, err := invoke(services[i], selected, replacement, op)
						results <- result{out, err}
					})
				}
				close(start)
				if op == organization.DeleteDynamicRole {
					for range 2 {
						select {
						case <-barrier.ready:
						case <-results:
							unblock()
							wg.Wait()
							t.Fatal("natural delete returned before both actual empty original lookups")
						case <-ctx.Done():
							unblock()
							wg.Wait()
							t.Fatal("bounded natural delete lookup barrier expired")
						}
					}
					unblock()
				}
				wg.Wait()
				close(results)
				var winner organization.StoreResult
				for got := range results {
					if op == organization.DeleteDynamicRole && (got.err != nil || got.out.Receipt.Outcome != identity.CommitOutcomeCommitted) {
						t.Fatal("initial natural loser did not recover actual winner", got.err)
					}
					if got.err == nil && got.out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("initial keyed contender returned no original")
					}
					if got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
						if got.err != nil {
							t.Fatal(got.err)
						}
						if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(winner, got.out) {
							t.Fatal("initial contenders committed different originals")
						}
						winner = got.out
					}
				}
				if winner.Receipt.Binding.CommandID == "" {
					t.Fatal("neither initial contender committed")
				}
				state := "active"
				if op == organization.DeleteDynamicRole {
					state = "deleted"
				}
				assertState(selected, 3+index, 1+index, state)
				assertEffects(winner, op)
				var effects int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(selected.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 1 {
					t.Fatal("initial contention duplicated effects before any repair", err)
				}
			})
		}
		t.Run("callback cannot rewrite borrowed original statements", func(t *testing.T) {
			selected, replacement := scenario(t, "callback-intent", organization.UpdateDynamicRole, organization.RoleMember)
			original := slices.Clone(replacement.Statements)
			mutated := false
			hook := &invitationCancellationPolicy{base: authorize}
			hook.before = func(_ context.Context, c authorization.DecisionContext) error {
				if !mutated && c.Request.Action == authorization.Action(organization.UpdateDynamicRole) && c.Request.Resource.Type == "identity.request-admission" {
					replacement.Statements[0].ResourceID = "rewritten-by-callback"
					mutated = true
				}
				return nil
			}
			out, err := build(pool, hook).UpdateDynamicRole(ctx, replacement, "127.0.0.1")
			if err != nil || !mutated || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("actual callback intent fixture did not execute", err)
			}
			v, err := build(pool, authorize).GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: selected.Authentication, OrganizationID: selected.OrganizationID, RoleID: selected.RoleID, CorrelationID: "immutable-public-intent"})
			if err != nil || !reflect.DeepEqual(v.DynamicRole.Statements, original) {
				t.Fatal("public policy callback rewrote native original intent", err)
			}
			replacement.Statements = original
			if again, err := build(pool, authorize).UpdateDynamicRole(ctx, replacement, "127.0.0.1"); err != nil || !reflect.DeepEqual(again, out) {
				t.Fatal("immutable original no longer matched key", err)
			}
		})
		return
	}
	var independentOrg, independentRole organization.ID
	for index, op := range operations {
		for _, stage := range []string{"management", "query"} {
			t.Run(string(op)+" late manager "+stage, func(t *testing.T) {
				selected, replacement := scenario(t, "late-"+string(rune('a'+index))+"-"+stage, op, organization.RoleOwner)
				original, err := invoke(build(pool, authorize), selected, replacement, op)
				if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(err)
				}
				hook := &invitationCancellationPolicy{base: authorize}
				managementCalls, required := 0, 1
				if op == organization.DeleteDynamicRole {
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
					p, err := s.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: selected.OrganizationID, OrganizationVersion: uint64(3 + index), UserID: ownerID, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-original-role-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := s.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
				out, err := invoke(build(pool, hook), selected, replacement, op)
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn genuine manager received original role history", err)
				}
				assertEffects(original, op)
				if op == organization.UpdateDynamicRole {
					independentOrg, independentRole = selected.OrganizationID, selected.RoleID
				}
			})
		}
	}
	t.Run("actual SignOut denies saved role originals", func(t *testing.T) {
		fresh := signinOwner()
		r.Authentication = fresh
		u.Authentication = fresh
		x.Authentication = fresh
		if out, err := build(pool, authorize).DeleteDynamicRole(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, deleted) {
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
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "dynamic-role-operation-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual role source SignOut", err)
		}
		for _, original := range []organization.StoreResult{created, updated, deleted} {
			if out, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: fresh, Binding: original.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("logged-out actor recovered saved role original", err)
			}
		}
		if out, err := build(pool, authorize).UpdateDynamicRole(ctx, u, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered keyed role update", err)
		}
		if out, err := build(pool, authorize).DeleteDynamicRole(ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out actor recovered natural deletion", err)
		}
		if v, err := build(pool, authorize).GetDynamicRole(ctx, organization.DynamicRoleReadRequest{Authentication: member, OrganizationID: independentOrg, RoleID: independentRole, CorrelationID: "independent-role-owner"}); err != nil || v.DynamicRole.ID != independentRole {
			t.Fatal("logout revoked independent live-role manager", err)
		}
		assertEffects(created, organization.CreateDynamicRole)
		assertEffects(updated, organization.UpdateDynamicRole)
		assertEffects(deleted, organization.DeleteDynamicRole)
	})
}
