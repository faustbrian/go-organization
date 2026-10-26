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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineDirectMemberRoleConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-member-role")
}

// Request-key admission is an application policy selection, independent of the
// existing native session, scoped membership and owner-transition decisions.
type memberRoleAdmissionEvaluator struct{}

func (*memberRoleAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.UpdateMember) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.UpdateMember) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

type memberRoleOperation interface {
	UpdateMember(context.Context, organization.UpdateMemberOperationRequest, string) (organization.StoreResult, error)
}

func exerciseGenuineDirectMemberRoles(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, source *organizationpg.Service, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, newSource func(*database.Pool) *organizationpg.Service) {
	t.Helper()
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-member-role-consumer", Revision: 9, Evaluator: new(memberRoleAdmissionEvaluator)})
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
	query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("organization-member-role-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("organization-member-role", map[string][]byte{"organization-member-role": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	build := func(native *organizationpg.Service, configuration string) *organizationpg.OperationService {
		s, err := organizationpg.NewOperationService(native, organizationpg.OperationServiceConfig{ConfigurationID: configuration, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
			allocations.Add(1)
			return "", organization.ErrUnavailable
		}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	current := func(p *database.Pool) *organizationpg.OperationService {
		return build(newSource(p), "organization-member-role-v1")
	}
	// A runtime interface check lets this actual genuine-consumer test expose the
	// missing public method before its implementation, without a compile failure.
	if _, ok := any(current(pool)).(memberRoleOperation); !ok {
		t.Fatal("native original-key member-role operation is missing")
	}
	update := func(s *organizationpg.OperationService, r organization.UpdateMemberOperationRequest) (organization.StoreResult, error) {
		return any(s).(memberRoleOperation).UpdateMember(ctx, r, "127.0.0.1")
	}
	key := func(value string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	commit := func(p organizationpg.PreparedCommand, err error) organization.StoreResult {
		t.Helper()
		if err != nil {
			t.Fatal("genuine member-role setup preparation failed", err)
		}
		out, err := source.Execute(ctx, p)
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine member-role setup failed", err)
		}
		return out
	}
	create := func(slug string) organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		org := organization.ID(id)
		commit(source.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Keyed static roles", Slug: slug, CorrelationID: "role-create"}, "127.0.0.1"))
		commit(source.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "role-add"}, "127.0.0.1"))
		return org
	}
	request := func(org organization.ID, actor organization.Authentication, target identity.UserID, role organization.Role, epoch, version uint64, label string) organization.UpdateMemberOperationRequest {
		return organization.UpdateMemberOperationRequest{Authentication: actor, IdempotencyKey: key("keyed-role-" + label), OrganizationID: org, UserID: target, Role: role, OrganizationVersion: epoch, MemberVersion: version, CorrelationID: "keyed-role-" + label}
	}
	assertRole := func(org organization.ID, user identity.UserID, role organization.Role, epoch, version uint64, owners, effects int) {
		t.Helper()
		var gotRole, state string
		var gotEpoch, gotVersion, gotAuthority uint64
		var gotOwners, members, gotEffects int
		err := db.QueryRowContext(ctx, `SELECT o.version::text,m.version::text,m.authorization_version::text,m.role,m.state,o.owner_count,o.member_count,(SELECT count(*) FROM organization.command_effects e WHERE e.tenant_id=o.tenant_id AND e.organization_id=o.organization_id AND e.operation=$4) FROM organization.organizations o JOIN organization.memberships m USING(tenant_id,organization_id) WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3`, string(owner.TenantID), string(org), string(user), string(organization.UpdateMember)).Scan(&gotEpoch, &gotVersion, &gotAuthority, &gotRole, &state, &gotOwners, &members, &gotEffects)
		if err != nil || gotEpoch != epoch || gotVersion != version || gotAuthority != version || gotRole != string(role) || state != "active" || gotOwners != owners || members != 2 || gotEffects != effects {
			t.Fatal("keyed role transition changed versions/counts/effects", err, gotEpoch, gotVersion, gotAuthority, gotOwners, members, gotEffects)
		}
		scope, err := organizationpg.OrganizationAuthorityScope(owner.TenantID, org, user)
		if err != nil {
			t.Fatal(err)
		}
		store, err := authority.NewAuthorityStore(pool.Raw(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		live, err := store.Get(ctx, scope)
		if err != nil || live.Version != version {
			t.Fatal("keyed role scoped authority diverged", err)
		}
	}
	assertEffects := func(out organization.StoreResult, committed bool) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal("invalid original role command")
		}
		var effects, events, audits, charges int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='membership.role_changed.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.command_id=$2 AND a.action='identity.organization.change_member_role'),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$2)`, string(out.Receipt.Binding.CommandID), raw).Scan(&effects, &events, &audits, &charges); err != nil {
			t.Fatal(err)
		}
		want := 0
		if committed {
			want = 1
		}
		// Kernel-owned admission charges and canonical failure audit survive an
		// aborted domain transaction. Only protected role/lifecycle work rolls back.
		if effects != want || events != want || audits != 1 || charges != 1 {
			t.Fatal("original role effects/audit/admission repeated or vanished", effects, events, audits, charges)
		}
	}
	assertRecovered := func(r organization.UpdateMemberOperationRequest, original organization.StoreResult) {
		t.Helper()
		r.CorrelationID = "retry-retains-original"
		got, err := update(current(pool), r)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("restart role retry did not retain exact original receipt", err)
		}
		got, err = current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding})
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("explicit role history changed original metadata", err)
		}
		assertEffects(original, true)
	}
	org := create("keyed-member-role")
	independent := create("keyed-independent-role")
	r := request(org, owner, memberID, organization.RoleAdministrator, 2, 1, "owner-promotes")
	original, err := update(current(pool), r)
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.OrganizationID != org || original.MemberID != memberID || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("owner keyed member-role update failed", err)
	}
	assertRole(org, memberID, organization.RoleAdministrator, 3, 2, 1, 1)
	assertRecovered(r, original)
	for name, change := range map[string]func(*organization.UpdateMemberOperationRequest){
		"role":                 func(r *organization.UpdateMemberOperationRequest) { r.Role = organization.RoleOwner },
		"organization":         func(r *organization.UpdateMemberOperationRequest) { r.OrganizationID = independent },
		"target":               func(r *organization.UpdateMemberOperationRequest) { r.UserID = ownerID },
		"organization-version": func(r *organization.UpdateMemberOperationRequest) { r.OrganizationVersion++ },
		"member-version":       func(r *organization.UpdateMemberOperationRequest) { r.MemberVersion++ },
	} {
		t.Run("changed-"+name, func(t *testing.T) {
			changed := r
			change(&changed)
			if _, err := update(current(pool), changed); !errors.Is(err, organization.ErrConflict) {
				t.Fatal("same role key changed original intent", err)
			}
		})
	}
	if _, err := update(build(source, "organization-member-role-v2"), r); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("changed role configuration adopted original key", err)
	}
	view, err := current(pool).ListMembers(ctx, organization.ReadRequest{Authentication: member, OrganizationID: org, Limit: 10, CorrelationID: "promoted-role-read"})
	if err != nil || view.Actor.Role != organization.RoleAdministrator || view.Actor.AuthorizationVersion != 2 || len(view.Members) != 2 {
		t.Fatal("promoted role missing from current native read", err)
	}
	commit(source.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 3, Name: "Administrator action", Slug: "keyed-admin-action", CorrelationID: "role-privilege"}, "127.0.0.1"))
	for _, denied := range []organization.UpdateMemberOperationRequest{
		request(org, member, memberID, organization.RoleOwner, 4, 2, "admin-escalation"),
		request(org, member, ownerID, organization.RoleMember, 4, 1, "admin-owner"),
	} {
		if _, err := update(current(pool), denied); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("administrator gained owner mutation authority", err)
		}
	}
	if _, err := update(current(pool), request(org, owner, ownerID, organization.RoleMember, 4, 1, "last-owner")); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("keyed role update demoted last owner", err)
	}
	self := request(org, member, memberID, organization.RoleMember, 4, 2, "admin-self-demotes")
	selfResult, err := update(current(pool), self)
	if err != nil || selfResult.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("administrator keyed self-demotion failed", err)
	}
	assertRole(org, memberID, organization.RoleMember, 5, 3, 1, 2)
	assertRecovered(self, selfResult)
	stale := r
	stale.IdempotencyKey = key("fresh-key-stale-role")
	if _, err := update(current(pool), stale); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("fresh role key refreshed stale expected versions", err)
	}
	noop := request(org, owner, memberID, organization.RoleMember, 5, 3, "no-op-role")
	if _, err := update(current(pool), noop); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("identical static role advanced native versions", err)
	}
	foreign := r
	foreign.Authentication.TenantID = "foreign-tenant"
	if got, err := update(current(pool), foreign); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("foreign tenant bearer disclosed original role correlation", err)
	}
	if _, err := source.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: member, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 5, Name: "Denied", Slug: "denied", CorrelationID: "role-withdrawn"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("self-demotion retained management authority", err)
	}
	assertRecovered(r, original)
	assertRole(independent, memberID, organization.RoleMember, 2, 1, 1, 0)
	// Owner-role transitions use the same static engine; this is not the
	// separate ownership-transfer operation or its proof/MFA profile.
	owners := create("keyed-owner-transitions")
	promote := request(owners, owner, memberID, organization.RoleOwner, 2, 1, "second-owner")
	promoted, err := update(current(pool), promote)
	if err != nil {
		t.Fatal("owner static promotion failed", err)
	}
	assertRole(owners, memberID, organization.RoleOwner, 3, 2, 2, 1)
	demote := request(owners, owner, ownerID, organization.RoleAdministrator, 3, 1, "owner-self-demotes")
	demoted, err := update(current(pool), demote)
	if err != nil {
		t.Fatal("nonfinal owner keyed self-demotion failed", err)
	}
	assertRole(owners, ownerID, organization.RoleAdministrator, 4, 2, 1, 2)
	assertRecovered(demote, demoted)
	assertRecovered(promote, promoted)
	// A removed actor cannot use exact self-history as an authority bypass.
	commit(source.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: memberID, OrganizationVersion: 5, MemberVersion: 3, CorrelationID: "remove-self-history"}, "127.0.0.1"))
	if got, err := update(current(pool), self); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("removed actor disclosed keyed self-history", err)
	}
	if got, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: member, Binding: selfResult.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("removed actor explicitly disclosed self-history", err)
	}

	// Two actual preparation reads precede admission; identical concurrent keys
	// must converge on one retained command, while two distinct owner-demotion
	// keys share the native aggregate's last-owner/version serialization.
	contend := func(org organization.ID, first, second organization.UpdateMemberOperationRequest, sameKey bool) {
		t.Helper()
		release := make(chan struct{})
		trace := &updateReadBarrier{ready: make(chan struct{}, 2), release: release}
		primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
			c.ConnConfig.Tracer = trace
			return nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := primary.Close(cleanup); err != nil {
				t.Error(err)
			}
		}()
		type result struct {
			out organization.StoreResult
			err error
		}
		results := make(chan result, 2)
		var workers sync.WaitGroup
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer workers.Wait()
		defer unblock()
		for _, candidate := range []organization.UpdateMemberOperationRequest{first, second} {
			s := current(primary)
			workers.Add(1)
			go func() { defer workers.Done(); out, err := update(s, candidate); results <- result{out, err} }()
		}
		for range 2 {
			select {
			case <-trace.ready:
			case early := <-results:
				t.Fatal("role contention ended before both primary reads", early.err)
			case <-ctx.Done():
				t.Fatal("role contention source barrier expired")
			}
		}
		unblock()
		a, b := <-results, <-results
		if sameKey {
			winner, err := update(current(pool), first)
			if err != nil || winner.Receipt.Validate() != nil || winner.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("same role key failed to converge", err)
			}
			for _, attempt := range []result{a, b} {
				if attempt.out.Receipt.Binding != winner.Receipt.Binding || attempt.err == nil && !reflect.DeepEqual(attempt.out, winner) {
					t.Fatal("same role key changed original command", attempt.err)
				}
			}
			assertRole(org, memberID, organization.RoleAdministrator, 3, 2, 1, 1)
			assertRecovered(first, winner)
		} else {
			commits := 0
			for _, attempt := range []result{a, b} {
				if attempt.err == nil && attempt.out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					commits++
					assertEffects(attempt.out, true)
				} else if !errors.Is(attempt.err, organization.ErrConflict) && !errors.Is(attempt.err, organization.ErrLastOwner) {
					t.Fatal("owner contention failed outside native safety decisions", attempt.err)
				}
			}
			var owners, members, epoch, effects int
			if err := db.QueryRowContext(ctx, `SELECT owner_count,member_count,version::integer,(SELECT count(*) FROM organization.command_effects e WHERE e.tenant_id=o.tenant_id AND e.organization_id=o.organization_id AND e.operation=$3) FROM organization.organizations o WHERE tenant_id=$1 AND organization_id=$2`, string(owner.TenantID), string(org), string(organization.UpdateMember)).Scan(&owners, &members, &epoch, &effects); err != nil || commits != 1 || owners != 1 || members != 2 || epoch != 4 || effects != 2 {
				t.Fatal("contended keyed owner transitions violated last-owner safety", err, commits, owners, members, epoch, effects)
			}
		}
	}
	sameOrg := create("keyed-role-contention")
	same := request(sameOrg, owner, memberID, organization.RoleAdministrator, 2, 1, "same-key-race")
	contend(sameOrg, same, same, true)
	lastOrg := create("keyed-last-owner-contention")
	if _, err := update(current(pool), request(lastOrg, owner, memberID, organization.RoleOwner, 2, 1, "race-second-owner")); err != nil {
		t.Fatal(err)
	}
	contend(lastOrg, request(lastOrg, owner, ownerID, organization.RoleMember, 3, 1, "race-owner-one"), request(lastOrg, member, memberID, organization.RoleMember, 3, 2, "race-owner-two"), false)

	rolledOrg := create("keyed-role-rollback")
	rolled := request(rolledOrg, owner, memberID, organization.RoleAdministrator, 2, 1, "rollback")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.keyed_role_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled keyed role rollback'; END $$; CREATE TRIGGER keyed_role_rollback BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.keyed_role_rollback()`); err != nil {
		t.Fatal(err)
	}
	aborted, abortErr := update(current(pool), rolled)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER keyed_role_rollback ON public.identity_outbox_bindings; DROP FUNCTION organization.keyed_role_rollback()`); err != nil {
		t.Fatal(err)
	}
	if abortErr == nil || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("protected role rollback not definitive", abortErr)
	}
	assertRole(rolledOrg, memberID, organization.RoleMember, 2, 1, 1, 0)
	assertEffects(aborted, false)
	for range 2 {
		got, err := update(current(pool), rolled)
		if !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, aborted) {
			t.Fatal("aborted role key reexecuted or changed original noncommit", err)
		}
		got, err = current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: aborted.Receipt.Binding})
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, aborted) {
			t.Fatal("aborted role recovery changed original failure", err)
		}
	}
	assertRole(rolledOrg, memberID, organization.RoleMember, 2, 1, 1, 0)
	assertEffects(aborted, false)
	for _, mappingOnly := range []bool{false, true} {
		label := "lost-commit"
		if mappingOnly {
			label = "mapping-only"
		}
		t.Run(label, func(t *testing.T) {
			faultOrg := create("keyed-role-" + label)
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
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if err := primary.Close(cleanup); err != nil {
					t.Error(err)
				}
			}()
			faultRequest := request(faultOrg, owner, memberID, organization.RoleAdministrator, 2, 1, label)
			fault.count.Store(-1)
			if mappingOnly {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			out, err := update(current(primary), faultRequest)
			if !fault.lost.Load() || err == nil || out.Receipt.Binding.CommandID == "" || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("real role COMMIT loss did not retain unknown original", err, out.Receipt.Outcome)
			}
			var unknown identity.UnknownCommitError
			for range 2 {
				got, err := update(current(pool), faultRequest)
				if got.Receipt.Binding != out.Receipt.Binding {
					t.Fatal("unknown role retry allocated a new command")
				}
				if mappingOnly {
					if !errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only role retry invented outcome/reexecution", err)
					}
				} else {
					if err != nil || got.Receipt.Validate() != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("committed role receipt not recovered", err)
					}
					assertEffects(got, true)
				}
			}
			got, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: out.Receipt.Binding})
			if got.Receipt.Binding != out.Receipt.Binding || mappingOnly && (!errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("explicit unknown role recovery diverged", err)
			}
			if mappingOnly {
				assertRole(faultOrg, memberID, organization.RoleMember, 2, 1, 1, 0)
				raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal(err)
				}
				var journals, claims, charges, audits, events int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&journals, &claims, &charges, &audits, &events); err != nil || journals != 0 || claims != 0 || charges != 0 || audits != 0 || events != 0 {
					t.Fatal("mapping-only role produced protected effects", err, journals, claims, charges, audits, events)
				}
				generic, err := source.Recover(ctx, owner, organizationpg.Recovery{Binding: out.Receipt.Binding})
				var forbidden identity.ForbiddenError
				if !errors.As(err, &forbidden) || generic.Receipt.Binding.CommandID != "" {
					t.Fatal("mapped role changed generic missing-journal privacy", err)
				}
			} else {
				assertRole(faultOrg, memberID, organization.RoleAdministrator, 3, 2, 1, 1)
			}
		})
	}
	withdrawOrg := create("keyed-role-authority")
	withdraw := request(withdrawOrg, owner, memberID, organization.RoleAdministrator, 2, 1, "scoped-authority")
	withdrawn, err := update(current(pool), withdraw)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := organizationpg.OrganizationAuthorityScope(owner.TenantID, withdrawOrg, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AdvanceAuthority(ctx, pool.Raw(), scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := update(current(pool), withdraw); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn scope disclosed keyed role history", err)
	}
	if _, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: withdrawn.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn scope disclosed explicit role history", err)
	}
	assertRole(withdrawOrg, memberID, organization.RoleAdministrator, 3, 2, 1, 1)
	assertEffects(withdrawn, true)
	if allocations.Load() != 0 {
		t.Fatal("role update allocated organization identities", allocations.Load())
	}
	assertRecovered(r, original)
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(owner.TenantID), string(ownerID)); err != nil {
		t.Fatal(err)
	}
	if got, err := update(current(pool), r); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("revoked session disclosed original role command", err)
	}
	if got, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: original.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("revoked session explicitly disclosed role history", err)
	}
}
