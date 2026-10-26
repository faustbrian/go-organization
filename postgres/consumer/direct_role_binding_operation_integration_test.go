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

func TestOrganizationGenuineDirectRoleBindingOperationConsumer(t *testing.T) {
	// Each bounded cohort gets real signup and the unchanged native privileged
	// attempt budget, rather than sharing exhausted setup counters or raising it.
	for _, cohort := range []string{"outcomes", "authority"} {
		t.Run(cohort, func(t *testing.T) { exerciseGenuinePasswordConsumer(t, "direct-role-binding-operation-"+cohort) })
	}
}

type directRoleBindingAdmissionEvaluator struct{}

func (*directRoleBindingAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if r.Action == authorization.Action(organization.Get) {
		return authorization.Decision{Outcome: authorization.Deny}, nil
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (r.Action == authorization.Action(organization.CreateDynamicRole) || r.Action == authorization.Action(organization.AssignDynamicRole)) && r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type directRoleBindingQueryPolicy struct {
	base          authorization.Service
	op            organization.Operation
	actor, target identity.UserID
	command       identity.CommandID
	seen          int
	wrong         bool
}

func (p *directRoleBindingQueryPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(p.op) && c.Request.Resource.Type == "identity.user" {
		p.seen++
		id, _ := c.Request.Resource.Attributes["identity.command.id"].String()
		p.wrong = p.wrong || c.Request.Subject.ID != authorization.SubjectID(p.actor) || c.Request.Resource.ID != authorization.ResourceID(p.target) || id != string(p.command)
		return authorization.Decision{Outcome: authorization.Deny, Revision: 9}, ctx.Err()
	}
	return p.base.Decide(ctx, c)
}

type directRoleRevokeLookupKey struct{}
type directRoleRevokeLookupBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *directRoleRevokeLookupBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(q.SQL, "SELECT command_id,revoke_role_id") && strings.Contains(q.SQL, "identity.organization.role.revoke") {
		return context.WithValue(ctx, directRoleRevokeLookupKey{}, true)
	}
	return ctx
}
func (b *directRoleRevokeLookupBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, q pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(directRoleRevokeLookupKey{}).(bool)
	if !selected || q.Err != nil || q.CommandTag.RowsAffected() != 0 || b.observed.Add(1) > 2 {
		return
	}
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func exerciseGenuineDirectRoleBindings(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication, logout reference.SessionService, authorityOnly bool) {
	t.Helper()
	var history migrationList
	for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.TeamMigrationSource{Version: 7001}, organizationpg.TeamLifecycleMigrationSource{Version: 7002}, organizationpg.DynamicRoleMigrationSource{Version: 7003}, organizationpg.TeamRoleBindingMigrationSource{Version: 7004}, organizationpg.RoleBindingRevokeOperationLookupMigrationSource{Version: 7005}} {
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
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "direct-role-binding-consumer", Revision: 9, Evaluator: new(directRoleBindingAdmissionEvaluator)})
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
		requestKeys, err := kernel.NewRequestKeyConfig("direct-role-binding-consumer", keys["request"], query)
		if err != nil {
			t.Fatal(err)
		}
		custody, err := organizationpg.NewOperationCustodyConfig("direct-role-binding-consumer", map[string][]byte{"direct-role-binding-consumer": material("delivery-envelope")})
		if err != nil {
			t.Fatal(err)
		}
		s, err := organizationpg.NewOperationService(source(primary, policy), organizationpg.OperationServiceConfig{ConfigurationID: "direct-role-binding-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
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
		k, err := identity.NewIdempotencyKey([]byte("direct-binding-" + label))
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
			t.Fatal("actual raw setup owner", err)
		}
	}
	setup := func(t *testing.T, label string, memberRole organization.Role) organization.AssignDynamicRoleOperationRequest {
		t.Helper()
		org, role := newID(), newID()
		s := source(pool, authorize)
		p, err := s.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Direct role binding consumer", Slug: "direct-binding-" + label, CorrelationID: "direct-binding-setup"}, "127.0.0.1")
		commit(t, s, p, err)
		p, err = s.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: memberID, Role: memberRole, CorrelationID: "direct-binding-setup"}, "127.0.0.1")
		commit(t, s, p, err)
		if _, err := build(pool, authorize).CreateDynamicRole(ctx, organization.CreateDynamicRoleOperationRequest{Authentication: owner, IdempotencyKey: key("create-" + label), OrganizationID: org, RoleID: role, OrganizationVersion: 2, Name: "Document reader", Statements: []organization.RoleStatement{{PermissionID: "document-read", ResourceID: "one", Effect: authorization.Allow}}, CorrelationID: "binding-role-create"}, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
		return organization.AssignDynamicRoleOperationRequest{Authentication: owner, IdempotencyKey: key("assign-" + label), OrganizationID: org, RoleID: role, UserID: memberID, OrganizationVersion: 3, RoleVersion: 1, OrganizationMemberVersion: 1, CorrelationID: "original-direct-assignment"}
	}
	revocation := func(r organization.AssignDynamicRoleOperationRequest) organization.RevokeDynamicRoleOperationRequest {
		return organization.RevokeDynamicRoleOperationRequest{Authentication: r.Authentication, OrganizationID: r.OrganizationID, RoleID: r.RoleID, UserID: r.UserID, OrganizationVersion: r.OrganizationVersion + 1, RoleVersion: r.RoleVersion, OrganizationMemberVersion: r.OrganizationMemberVersion, BindingVersion: r.BindingVersion + 1, CorrelationID: "natural-direct-revocation"}
	}
	assertEffects := func(out organization.StoreResult, op organization.Operation) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		topic := "organization.role_assigned.v1"
		if op == organization.RevokeDynamicRole {
			topic = "organization.role_revoked.v1"
		}
		var effects, audits, events int
		err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1 AND operation=$2),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$3 AND r.action=$2 AND r.outcome=1),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$3 AND m.topic=$4)`, string(out.Receipt.Binding.CommandID), string(op), raw, topic).Scan(&effects, &audits, &events)
		if err != nil || effects != 1 || audits != 1 || events != 1 {
			t.Fatal("binding original lost singleton required effects", err)
		}
	}
	assertState := func(r organization.AssignDynamicRoleOperationRequest, epoch, version int, state string) {
		t.Helper()
		var actualEpoch, actualVersion int
		var actualState string
		err := db.QueryRowContext(ctx, `SELECT o.version::integer,coalesce(b.version,0)::integer,coalesce(b.state,'') FROM organization.organizations o LEFT JOIN organization.role_bindings b ON b.tenant_id=o.tenant_id AND b.organization_id=o.organization_id AND b.role_id=$2 AND b.user_id=$3 WHERE o.organization_id=$1`, string(r.OrganizationID), string(r.RoleID), string(r.UserID)).Scan(&actualEpoch, &actualVersion, &actualState)
		if err != nil || actualEpoch != epoch || actualVersion != version || actualState != state {
			t.Fatal("binding state/epoch differs", err)
		}
	}
	r := setup(t, "original", organization.RoleMember)
	s := build(pool, authorize)
	if _, err := s.Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, CorrelationID: "deny-unrelated-org-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("org read not actually denied", err)
	}
	assigned, err := s.AssignDynamicRole(ctx, r, "127.0.0.1")
	if err != nil || assigned.Receipt.Outcome != identity.CommitOutcomeCommitted || assigned.Receipt.Binding.UserID != memberID {
		t.Fatal("genuine original direct assignment", err)
	}
	assertEffects(assigned, organization.AssignDynamicRole)
	assertState(r, 4, 1, "active")
	q := organization.DynamicRoleReadRequest{Authentication: owner, OrganizationID: r.OrganizationID, RoleID: r.RoleID, TargetUserID: memberID, CorrelationID: "chosen-direct-selectors"}
	v, err := s.GetDynamicRole(ctx, q)
	if err != nil || v.DynamicRole.ID != r.RoleID || v.DynamicRole.Version != 1 || v.Target.Version != 1 || !v.RoleBinding.Active || v.RoleBinding.Version != 1 || v.RoleBinding.OrganizationMemberVersion != 1 {
		t.Fatal("actual chosen binding selectors differ", err)
	}
	check := organization.PermissionCheckRequest{Authentication: member, OrganizationID: r.OrganizationID, OrganizationVersion: 4, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "genuine-direct-permission"}
	permission := func(want authorization.Outcome) {
		t.Helper()
		d, err := build(pool, authorize).CheckPermission(ctx, check)
		if err != nil || d.Outcome != want || d.Revision != authorization.Revision(check.OrganizationVersion) {
			t.Fatal("actual direct target permission differs", err)
		}
	}
	permission(authorization.Allow)
	check.ResourceID = "other"
	permission(authorization.Deny)
	check.ResourceID = "one"
	for _, field := range []string{"organization", "role", "target", "org-epoch", "role-epoch", "member-epoch", "binding-epoch"} {
		bad := r
		switch field {
		case "organization":
			bad.OrganizationID = newID()
		case "role":
			bad.RoleID = newID()
		case "target":
			bad.UserID = ownerID
		case "org-epoch":
			bad.OrganizationVersion++
		case "role-epoch":
			bad.RoleVersion++
		case "member-epoch":
			bad.OrganizationMemberVersion++
		case "binding-epoch":
			bad.BindingVersion++
		}
		if out, err := s.AssignDynamicRole(ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed assignment intent adopted original key", err)
		}
	}
	foreign := r
	foreign.Authentication.TenantID = "foreign-tenant"
	if out, err := s.AssignDynamicRole(ctx, foreign, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("foreign tenant adopted direct original", err)
	}
	bad := r
	bad.Authentication = member
	if out, err := s.AssignDynamicRole(ctx, bad, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("application role implied management authority", err)
	}
	x := revocation(r)
	revoked, err := s.RevokeDynamicRole(ctx, x, "127.0.0.1")
	if err != nil || revoked.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("genuine natural direct revocation", err)
	}
	assertEffects(revoked, organization.RevokeDynamicRole)
	assertState(r, 5, 2, "removed")
	check.OrganizationVersion = 5
	permission(authorization.Deny)
	r.Authentication = signinOwner()
	x.Authentication = r.Authentication
	for range 2 {
		fresh := build(pool, authorize)
		if out, err := fresh.AssignDynamicRole(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, assigned) {
			t.Fatal("fresh reconstructed assignment original differs", err)
		}
		if out, err := fresh.RevokeDynamicRole(ctx, x, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, revoked) {
			t.Fatal("fresh reconstructed natural original differs", err)
		}
		for _, original := range []organization.StoreResult{assigned, revoked} {
			if out, err := fresh.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, original) {
				t.Fatal("fresh explicit nonself original differs", err)
			}
		}
	}
	for _, selector := range []string{"role", "target", "role-epoch", "member-epoch", "binding-epoch"} {
		changed := x
		switch selector {
		case "role":
			changed.RoleID = newID()
		case "target":
			changed.UserID = ownerID
		case "role-epoch":
			changed.RoleVersion++
		case "member-epoch":
			changed.OrganizationMemberVersion++
		case "binding-epoch":
			changed.BindingVersion++
		}
		policy := &directRoleBindingQueryPolicy{base: authorize, op: organization.RevokeDynamicRole, actor: ownerID, target: memberID, command: revoked.Receipt.Binding.CommandID}
		out, err := build(pool, policy).RevokeDynamicRole(ctx, changed, "127.0.0.1")
		if !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted || policy.seen == 0 || policy.wrong {
			t.Fatal("query-denied changed selector disclosed direct history", err)
		}
	}
	// Reassignment and readmission each have their own exact binding/admission;
	// old natural requests cannot reach them and old grants cannot revive.
	next := r
	next.IdempotencyKey = key("new-assignment")
	next.OrganizationVersion = 5
	next.BindingVersion = 2
	if _, err := s.AssignDynamicRole(ctx, next, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	assertState(r, 6, 3, "active")
	if _, err := s.RevokeDynamicRole(ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("old revoke reached reassignment", err)
	}
	plain := source(pool, authorize)
	p, err := plain.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 6, UserID: memberID, MemberVersion: 1, CorrelationID: "old-binding-admission-removal"}, "127.0.0.1")
	commit(t, plain, p, err)
	p, err = plain.PrepareAddMember(ctx, organization.MemberRequest{Authentication: r.Authentication, CommandID: commandID(t), OrganizationID: r.OrganizationID, OrganizationVersion: 7, UserID: memberID, MemberVersion: 2, Role: organization.RoleMember, CorrelationID: "new-binding-admission"}, "127.0.0.1")
	commit(t, plain, p, err)
	check.OrganizationVersion = 8
	permission(authorization.Deny)
	if _, err := s.RevokeDynamicRole(ctx, x, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("old revoke reached readmission", err)
	}
	v, err = s.GetDynamicRole(ctx, q)
	if err != nil || v.Target.Version != 3 || !v.RoleBinding.Active || v.RoleBinding.Version != 3 || v.RoleBinding.OrganizationMemberVersion != 1 {
		t.Fatal("readmission rewrote retained binding", err)
	}
	if !authorityOnly {
		exerciseDirectRoleBindingOutcomes(t, ctx, pool, db, authorize, build, source, setup, revocation, commit, assertEffects, assertState)
		return
	}
	for _, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		for _, stage := range []string{"management", "query"} {
			t.Run(string(op)+" late manager "+stage, func(t *testing.T) {
				selected := setup(t, "late-"+string(op[len("identity.organization.role."):])+"-"+stage, organization.RoleOwner)
				original, err := build(pool, authorize).AssignDynamicRole(ctx, selected, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				epoch := uint64(4)
				if op == organization.RevokeDynamicRole {
					original, err = build(pool, authorize).RevokeDynamicRole(ctx, revocation(selected), "127.0.0.1")
					if err != nil {
						t.Fatal(err)
					}
					epoch = 5
				}
				hook := &invitationCancellationPolicy{base: authorize}
				managementCalls, required := 0, 1
				if op == organization.RevokeDynamicRole {
					// Natural lookup has its own earlier admission/query. Select
					// native Recover's callback, after its observation is captured.
					required = 2
				}
				withdrawn, managementSeen, querySeen := false, false, false
				hook.before = func(ctx context.Context, c authorization.DecisionContext) error {
					if withdrawn || c.Request.Action != authorization.Action(op) {
						return nil
					}
					if c.Request.Resource.Type == "organization" {
						managementCalls++
						if managementCalls < required {
							return nil
						}
						managementSeen = true
						if stage != "management" {
							return nil
						}
					} else if c.Request.Resource.Type == "identity.user" {
						if stage != "query" || !managementSeen {
							return nil
						}
						querySeen = true
					} else {
						return nil
					}
					s := source(pool, authorize)
					p, err := s.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: member, CommandID: commandID(t), OrganizationID: selected.OrganizationID, OrganizationVersion: epoch, UserID: ownerID, MemberVersion: 1, Role: organization.RoleMember, CorrelationID: "withdraw-direct-history-manager"}, "127.0.0.1")
					if err != nil {
						return err
					}
					out, err := s.Execute(ctx, p)
					withdrawn = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
					return err
				}
				var out organization.StoreResult
				if op == organization.AssignDynamicRole {
					out, err = build(pool, hook).AssignDynamicRole(ctx, selected, "127.0.0.1")
				} else {
					out, err = build(pool, hook).RevokeDynamicRole(ctx, revocation(selected), "127.0.0.1")
				}
				if !errors.Is(err, organization.ErrForbidden) || !withdrawn || !managementSeen || stage == "query" && !querySeen || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn genuine manager received original binding history", err)
				}
				assertEffects(original, op)
			})
		}
	}
	t.Run("actual SignOut denies saved direct originals", func(t *testing.T) {
		fresh := signinOwner()
		if out, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: fresh, Binding: revoked.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, revoked) {
			t.Fatal("fresh direct original lost before logout", err)
		}
		token, err := session.ParseToken(fresh.Bearer.Token())
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialBearer, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: fresh.TenantID, CommandID: commandID(t), CorrelationID: "direct-role-binding-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual direct binding SignOut", err)
		}
		for _, original := range []organization.StoreResult{assigned, revoked} {
			if out, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: fresh, Binding: original.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("signed-out credential disclosed original direct history", err)
			}
		}
		if d, err := build(pool, authorize).CheckPermission(ctx, organization.PermissionCheckRequest{Authentication: fresh, OrganizationID: r.OrganizationID, OrganizationVersion: 8, Action: "document.read", ResourceType: "document", ResourceID: "one", CorrelationID: "signed-out-check"}); err == nil || d.Outcome == authorization.Allow {
			t.Fatal("signed-out credential retained permission", err)
		}
		if out, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: signinOwner(), Binding: revoked.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, revoked) {
			t.Fatal("logout broke independent genuine session recovery", err)
		}
	})
}

func exerciseDirectRoleBindingOutcomes(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, authorize authorization.Service,
	build func(*database.Pool, authorization.Service) *organizationpg.OperationService,
	source func(*database.Pool, authorization.Service) *organizationpg.Service,
	setup func(*testing.T, string, organization.Role) organization.AssignDynamicRoleOperationRequest,
	revocation func(organization.AssignDynamicRoleOperationRequest) organization.RevokeDynamicRoleOperationRequest,
	commit func(*testing.T, *organizationpg.Service, organizationpg.PreparedCommand, error),
	assertEffects func(organization.StoreResult, organization.Operation),
	assertState func(organization.AssignDynamicRoleOperationRequest, int, int, string)) {
	t.Helper()
	scenario := func(t *testing.T, label string, op organization.Operation) organization.AssignDynamicRoleOperationRequest {
		t.Helper()
		r := setup(t, label, organization.RoleMember)
		if op == organization.RevokeDynamicRole {
			if _, err := build(pool, authorize).AssignDynamicRole(ctx, r, "127.0.0.1"); err != nil {
				t.Fatal(err)
			}
		}
		return r
	}
	invoke := func(s *organizationpg.OperationService, r organization.AssignDynamicRoleOperationRequest, op organization.Operation) (organization.StoreResult, error) {
		if op == organization.AssignDynamicRole {
			return s.AssignDynamicRole(ctx, r, "127.0.0.1")
		}
		return s.RevokeDynamicRole(ctx, revocation(r), "127.0.0.1")
	}
	for i, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		for _, boundary := range []string{"audit", "outbox"} {
			t.Run(string(op)+" rollback "+boundary, func(t *testing.T) {
				r := scenario(t, "rollback-"+string(rune('a'+i))+"-"+boundary, op)
				table, condition := "audit.records", "NEW.action='"+string(op)+"' AND NEW.outcome=1"
				if boundary == "outbox" {
					table = "public.identity_outbox_bindings"
					condition = "true"
				}
				if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.fail_direct_binding() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION 'controlled direct binding failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_direct_binding BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.fail_direct_binding()`); err != nil {
					t.Fatal(err)
				}
				out, failure := invoke(build(pool, authorize), r, op)
				if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER fail_direct_binding ON `+table+`;DROP FUNCTION organization.fail_direct_binding()`); err != nil {
					t.Fatal(err)
				}
				if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required binding effect failure committed", failure)
				}
				state := ""
				if i == 1 {
					state = "active"
				}
				assertState(r, 3+i, i, state)
				var effects int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(r.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 0 {
					t.Fatal("failed binding retained original correlation", err)
				}
				if op == organization.AssignDynamicRole {
					if again, err := invoke(build(pool, authorize), r, op); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(again, out) {
						t.Fatal("aborted assignment original key reexecuted", err)
					}
				}
			})
		}
	}
	t.Run("legacy uncorrelated tombstone is not success", func(t *testing.T) {
		r := scenario(t, "legacy", organization.RevokeDynamicRole)
		x := revocation(r)
		s := source(pool, authorize)
		p, err := s.PrepareRevokeDynamicRole(ctx, organization.RoleBindingRequest{Authentication: x.Authentication, CommandID: commandID(t), OrganizationID: x.OrganizationID, RoleID: x.RoleID, UserID: x.UserID, OrganizationVersion: x.OrganizationVersion, RoleVersion: x.RoleVersion, OrganizationMemberVersion: x.OrganizationMemberVersion, BindingVersion: x.BindingVersion, CorrelationID: "legacy-direct-revoke"}, "127.0.0.1")
		commit(t, s, p, err)
		if out, err := build(pool, authorize).RevokeDynamicRole(ctx, x, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("legacy tombstone invented natural direct receipt", err)
		}
		var nullable int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation='identity.organization.role.revoke' AND revoke_role_id IS NULL AND revoke_role_version IS NULL AND revoke_member_version IS NULL AND revoke_binding_version IS NULL`, string(r.OrganizationID)).Scan(&nullable); err != nil || nullable != 1 {
			t.Fatal("legacy explicit writer invented optional intent", err)
		}
	})
	for _, label := range []string{"assign-mapping-loss", "assign-commit-loss", "revoke-commit-loss"} {
		t.Run(label, func(t *testing.T) {
			op, index := organization.AssignDynamicRole, 0
			if strings.HasPrefix(label, "revoke") {
				op, index = organization.RevokeDynamicRole, 1
			}
			r := scenario(t, label, op)
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
			if op == organization.RevokeDynamicRole {
				fault.count.Store(0)
			}
			fault.armed.Store(true)
			unknown, err := invoke(build(primary, authorize), r, op)
			if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
				t.Fatal("actual direct binding COMMIT loss discarded original", err)
			}
			for range 2 {
				out, err := invoke(build(pool, authorize), r, op)
				if out.Receipt.Binding != unknown.Receipt.Binding {
					t.Fatal("unknown binding retry allocated new command")
				}
				if mapping {
					var ambiguity identity.UnknownCommitError
					if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only direct assignment invented execution", err)
					}
				} else {
					if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("lost committed binding outcome not recovered", err)
					}
					assertEffects(out, op)
				}
			}
			out, err := build(pool, authorize).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: unknown.Receipt.Binding})
			if mapping {
				var ambiguity identity.UnknownCommitError
				if !errors.As(err, &ambiguity) || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
					t.Fatal("explicit mapping-only original invented result", err)
				}
				assertState(r, 3, 0, "")
				raw, err := base64.RawURLEncoding.DecodeString(string(unknown.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims, effects int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects WHERE command_id=$2)`, raw, string(unknown.Receipt.Binding.CommandID)).Scan(&journals, &claims, &effects); err != nil || journals != 0 || claims != 0 || effects != 0 {
					t.Fatal("mapping-only binding reached domain execution", err)
				}
			} else if err != nil || out.Receipt.Binding != unknown.Receipt.Binding || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("explicit original lost binding COMMIT differs", err)
			} else {
				state := "active"
				if index == 1 {
					state = "removed"
				}
				assertState(r, 4+index, 1+index, state)
			}
		})
	}
	for index, op := range []organization.Operation{organization.AssignDynamicRole, organization.RevokeDynamicRole} {
		t.Run(string(op)+" initial contention", func(t *testing.T) {
			r := scenario(t, "contention-"+string(rune('a'+index)), op)
			primary := pool
			var barrier *directRoleRevokeLookupBarrier
			var unblock func()
			if op == organization.RevokeDynamicRole {
				release := make(chan struct{})
				var once sync.Once
				unblock = func() { once.Do(func() { close(release) }) }
				defer unblock()
				barrier = &directRoleRevokeLookupBarrier{ready: make(chan struct{}, 2), release: release}
				var err error
				primary, err = database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
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
			s := build(primary, authorize)
			start := make(chan struct{})
			type result struct {
				out organization.StoreResult
				err error
			}
			results := make(chan result, 2)
			var wg sync.WaitGroup
			for range 2 {
				wg.Go(func() { <-start; out, err := invoke(s, r, op); results <- result{out, err} })
			}
			close(start)
			if barrier != nil {
				for range 2 {
					select {
					case <-barrier.ready:
					case <-ctx.Done():
						unblock()
						wg.Wait()
						t.Fatal("bounded empty-original contention barrier expired")
					}
				}
				unblock()
			}
			wg.Wait()
			close(results)
			var winner organization.StoreResult
			for got := range results {
				if got.err == nil && got.out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("initial binding contender had no original result")
				}
				if got.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					if got.err != nil {
						t.Fatal("committed contender errored", got.err)
					}
					if winner.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(winner, got.out) {
						t.Fatal("initial successes used different binding originals")
					}
					winner = got.out
				}
			}
			if winner.Receipt.Binding.CommandID == "" {
				t.Fatal("no initial binding contender committed")
			}
			state := "active"
			if index == 1 {
				state = "removed"
			}
			assertState(r, 4+index, 1+index, state)
			assertEffects(winner, op)
			var effects int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE organization_id=$1 AND operation=$2`, string(r.OrganizationID), string(op)).Scan(&effects); err != nil || effects != 1 {
				t.Fatal("initial binding contenders duplicated effects before repair", err)
			}
		})
	}
}
