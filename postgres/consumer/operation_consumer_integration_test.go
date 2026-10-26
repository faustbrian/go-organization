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

	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestOrganizationGenuineDirectOperationsConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-operations")
}

func TestOrganizationGenuineDirectUnknownCommitConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-domain-unknown")
}

func TestOrganizationGenuineDirectMappingOnlyRecoveryConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-mapping-only")
}

func TestOrganizationGenuineDirectContentionConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-contention")
}

func TestOrganizationGenuineDirectRemovalContentionConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-removal-contention")
}

type removalLookupTraceKey struct{}
type removalLookupBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *removalLookupBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT command_id FROM organization.command_effects\n") && strings.Contains(data.SQL, "operation='identity.organization.member.remove'") {
		return context.WithValue(ctx, removalLookupTraceKey{}, true)
	}
	return ctx
}

func (b *removalLookupBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	selected, _ := ctx.Value(removalLookupTraceKey{}).(bool)
	if !selected || data.Err != nil || data.CommandTag.RowsAffected() != 0 || b.observed.Add(1) > 2 {
		return
	}
	// Query completion proves an actual empty primary result, not a mocked
	// repository answer. Hold both first lookups before either can prepare or
	// commit removal; subsequent reconciliation uses the real driver unchanged.
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func exerciseConcurrentDirectRemoval(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, owner organization.Authentication, org organization.ID, member identity.UserID, service func(*database.Pool) *organizationpg.OperationService) {
	t.Helper()
	release := make(chan struct{})
	trace := &removalLookupBarrier{ready: make(chan struct{}, 2), release: release}
	primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal("isolated concurrent removal primary unavailable", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if primary.Close(cleanup) != nil {
			t.Error("concurrent removal primary cleanup failed")
		}
	})
	first, second := service(primary), service(primary)
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
	for i, candidate := range []*organizationpg.OperationService{first, second} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			r := organization.RemoveMemberOperationRequest{Authentication: owner, OrganizationID: org, UserID: member, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: []string{"remove-race-first", "remove-race-second"}[i]}
			out, err := candidate.RemoveMember(ctx, r, "127.0.0.1")
			results <- result{out, err}
		}()
	}
	for range 2 {
		select {
		case <-trace.ready:
		case early := <-results:
			t.Fatal("removal returned before both absent-effect reads completed", early.err)
		case <-ctx.Done():
			t.Fatal("bounded concurrent removal lookup barrier expired")
		}
	}
	unblock()
	a, b := <-results, <-results
	if a.err != nil || b.err != nil || a.out.Receipt.Validate() != nil || b.out.Receipt.Validate() != nil || a.out.Receipt.Outcome != identity.CommitOutcomeCommitted || !reflect.DeepEqual(a.out, b.out) {
		t.Fatal("losing non-keyed removal did not recover the winner's actual receipt", a.err, b.err)
	}
	if a.out.Receipt.Feature == nil || a.out.Receipt.Feature.BeforeVersion != 2 || a.out.Receipt.Feature.AfterVersion != 3 || a.out.Receipt.Binding.OperationID != string(organization.RemoveMember) || a.out.OrganizationID != org || a.out.MemberID != member {
		t.Fatal("concurrent removal changed original transition scope")
	}
	var effects int
	var command identity.CommandID
	if err := db.QueryRowContext(ctx, `SELECT count(*),min(command_id) FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND operation=$3`, string(owner.TenantID), string(org), string(organization.RemoveMember)).Scan(&effects, &command); err != nil || effects != 1 || command != a.out.Receipt.Binding.CommandID {
		t.Fatal("concurrent requests duplicated removal or returned a fabricated winner", err)
	}
	var orgVersion, memberVersion, state string
	if err := db.QueryRowContext(ctx, `SELECT o.version::text,m.version::text,m.state FROM organization.organizations o JOIN organization.memberships m ON m.tenant_id=o.tenant_id AND m.organization_id=o.organization_id WHERE o.tenant_id=$1 AND o.organization_id=$2 AND m.user_id=$3`, string(owner.TenantID), string(org), string(member)).Scan(&orgVersion, &memberVersion, &state); err != nil || orgVersion != "3" || memberVersion != "2" || state != "removed" {
		t.Fatal("concurrent repeat advanced durable generations twice", err)
	}
	actual, err := service(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: a.out.Receipt.Binding})
	if err != nil || !reflect.DeepEqual(actual, a.out) {
		t.Fatal("concurrent winner did not match original owner-authorized recovery", err)
	}
}

func exerciseGenuineDirectOperations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, source *organizationpg.Service, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, profile string, newSource func(*database.Pool) *organizationpg.Service) {
	t.Helper()
	if profile == "direct-member-role" {
		exerciseGenuineDirectMemberRoles(t, ctx, pool, db, source, owner, member, ownerID, memberID, keys, material, newSource)
		return
	}
	if profile == "direct-update-operations" || profile == "direct-update-contention" {
		exerciseGenuineDirectUpdates(t, ctx, pool, db, source, owner, member, ownerID, memberID, keys, material, newSource, profile)
		return
	}
	base, err := (organizationpg.MigrationSource{Version: 7000}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	index, err := (organizationpg.OperationLookupMigrationSource{Version: 7001}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(append(base, index...)), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("direct-operation lookup migration failed", err)
	}
	authorize, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("organization-direct-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("organization-direct", map[string][]byte{"organization-direct": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	ready, release := make(chan struct{}, 2), make(chan struct{})
	buildService := func(source *organizationpg.Service) *organizationpg.OperationService {
		service, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "organization-direct-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
			id, err := identity.NewSubjectID()
			allocations.Add(1)
			if profile == "direct-contention" {
				select {
				case ready <- struct{}{}:
				case <-ctx.Done():
					return "", ctx.Err()
				}
				select {
				case <-release:
				case <-ctx.Done():
					return "", ctx.Err()
				}
			}
			return organization.ID(id), errors.Join(ctx.Err(), err)
		}})
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	newService := func() *organizationpg.OperationService { return buildService(source) }
	service := newService()
	key := func(raw string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if profile == "direct-contention" {
		r := organization.CreateOperationRequest{Authentication: owner, IdempotencyKey: key("direct-contended-create"), Name: "Contended consumer", Slug: "contended-consumer", CorrelationID: "contended"}
		type result struct {
			out organization.StoreResult
			err error
		}
		results := make(chan result, 2)
		for _, candidate := range []*organizationpg.OperationService{newService(), newService()} {
			go func() {
				out, err := candidate.Create(ctx, r, "127.0.0.1")
				results <- result{out, err}
			}()
		}
		for range 2 {
			select {
			case <-ready:
			case <-ctx.Done():
				close(release)
				t.Fatal("contended preparation did not reach bounded barrier")
			}
		}
		close(release)
		first, second := <-results, <-results
		committed, err := newService().Create(ctx, r, "127.0.0.1")
		if err != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted || allocations.Load() != 2 {
			t.Fatal("contending candidates did not converge on the actual original", err)
		}
		for _, attempt := range []result{first, second} {
			if attempt.out.Receipt.Binding != committed.Receipt.Binding || attempt.err == nil && !reflect.DeepEqual(attempt.out, committed) {
				t.Fatal("contention changed original custody or fabricated successful outcome", attempt.err)
			}
		}
		var organizations, effects int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.organizations),(SELECT count(*) FROM organization.command_effects)`).Scan(&organizations, &effects); err != nil || organizations != 1 || effects != 1 {
			t.Fatal("contending key duplicated native transition", err)
		}
		return
	}
	if profile == "direct-domain-unknown" || profile == "direct-mapping-only" {
		fault := new(commitResponseLoss)
		faultPool, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
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
			t.Fatal("isolated fault primary unavailable", err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if faultPool.Close(cleanup) != nil {
				t.Error("owned fault pool cleanup failed")
			}
		})
		faultService := buildService(newSource(faultPool))
		// Original helper loses its second acknowledged COMMIT. Here mapping,
		// reservation and mutation are three commits: -1 selects mutation;
		// +1 selects mapping before any journal or domain attempt exists.
		fault.count.Store(-1)
		if profile == "direct-mapping-only" {
			fault.count.Store(1)
		}
		fault.armed.Store(true)
		r := organization.CreateOperationRequest{Authentication: owner, IdempotencyKey: key("direct-unknown-create"), Name: "Unknown consumer", Slug: "unknown-consumer", CorrelationID: "unknown"}
		out, err := faultService.Create(ctx, r, "127.0.0.1")
		var unknown identity.UnknownCommitError
		if !fault.lost.Load() || err == nil || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding.CommandID == "" || errors.As(err, &unknown) && out.Receipt.Binding.CommandID != unknown.CommandID {
			t.Fatal("lost acknowledged commit did not preserve original unknown correlation", out.Receipt.Outcome, err)
		}
		recovered, err := newService().Create(ctx, r, "127.0.0.1")
		if allocations.Load() != 1 || recovered.Receipt.Binding != out.Receipt.Binding {
			t.Fatal("original key selected a fresh ID or changed original binding")
		}
		if profile == "direct-mapping-only" {
			if !errors.As(err, &unknown) || recovered.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("mapped original without a journal lost explicit unresolved outcome", recovered.Receipt.Outcome, err)
			}
			direct, directErr := newService().RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: out.Receipt.Binding})
			if !errors.As(directErr, &unknown) || direct.Receipt.Outcome != identity.CommitOutcomeUnknown || direct.Receipt.Binding != out.Receipt.Binding || allocations.Load() != 1 {
				t.Fatal("explicit mapped-original recovery lost its actual unknown scope", directErr)
			}
			generic, genericErr := source.Recover(ctx, owner, organizationpg.Recovery{Binding: out.Receipt.Binding})
			var genericForbidden identity.ForbiddenError
			if !errors.As(genericErr, &genericForbidden) || generic.Receipt.Binding.CommandID != "" {
				t.Fatal("generic absent-journal privacy changed", genericErr)
			}
			if denied, err := newService().RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: member, Binding: out.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || denied.Receipt.Binding.CommandID != "" {
				t.Fatal("foreign current actor obtained original correlation", err)
			}
			raw, decodeErr := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
			if decodeErr != nil {
				t.Fatal(decodeErr)
			}
			var journals, claims, effects, organizations int
			if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects),(SELECT count(*) FROM organization.organizations)`, raw).Scan(&journals, &claims, &effects, &organizations); err != nil || journals != 0 || claims != 0 || effects != 0 || organizations != 0 {
				t.Fatal("mapping-only recovery created a journal or domain effect", err)
			}
			return
		}
		if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original lost mutation did not recover its actual committed result", err)
		}
		var effects int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE command_id=$1`, string(out.Receipt.Binding.CommandID)).Scan(&effects); err != nil || effects != 1 {
			t.Fatal("unknown recovery repeated or lost the original protected effects", err)
		}
		return
	}
	create := organization.CreateOperationRequest{Authentication: owner, IdempotencyKey: key("direct-create"), Name: "Direct consumer", Slug: "direct-consumer", CorrelationID: "create"}
	created, err := service.Create(ctx, create, "127.0.0.1")
	if err != nil || created.Receipt.Outcome != identity.CommitOutcomeCommitted || created.OrganizationID == "" || created.MemberID != ownerID {
		t.Fatal("original keyed create failed", err)
	}
	create.CorrelationID = "create-retry"
	for i := 0; i < 2; i++ {
		out, err := newService().Create(ctx, create, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(out, created) {
			t.Fatal("keyed restart did not preserve original committed create", err)
		}
	}
	if allocations.Load() != 1 {
		t.Fatal("keyed create retry allocated another organization identity")
	}
	changed := create
	changed.Slug = "changed-intent"
	if _, err := service.Create(ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("same key changed body allocated another create", err)
	}
	read := organization.ReadRequest{Authentication: owner, OrganizationID: created.OrganizationID, CorrelationID: "read"}
	if view, err := service.Get(ctx, read); err != nil || view.Actor.UserID != ownerID || view.Organization.Version != 1 {
		t.Fatal("creator could not use real native read", err)
	}
	add := organization.AddMemberOperationRequest{Authentication: owner, IdempotencyKey: key("direct-add"), OrganizationID: created.OrganizationID, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "add"}
	if profile == "direct-removal-contention" {
		added, err := service.AddMember(ctx, add, "127.0.0.1")
		if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("concurrent removal member setup failed", err)
		}
		exerciseConcurrentDirectRemoval(t, ctx, pool, db, owner, created.OrganizationID, memberID, func(p *database.Pool) *organizationpg.OperationService { return buildService(newSource(p)) })
		return
	}
	rollback := add
	rollback.IdempotencyKey = key("direct-rollback-add")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.direct_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'controlled direct operation rollback'; END $$; CREATE TRIGGER direct_rollback BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.direct_rollback()`); err != nil {
		t.Fatal("protected failure fixture unavailable", err)
	}
	aborted, rollbackErr := service.AddMember(ctx, rollback, "127.0.0.1")
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER direct_rollback ON public.identity_outbox_bindings; DROP FUNCTION organization.direct_rollback()`); err != nil {
		t.Fatal("protected failure fixture cleanup failed", err)
	}
	if rollbackErr == nil || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("protected failure escaped definitive rollback", aborted.Receipt.Outcome, rollbackErr)
	}
	if recovered, err := newService().AddMember(ctx, rollback, "127.0.0.1"); !errors.Is(err, organization.ErrUnavailable) || recovered.Receipt.Binding != aborted.Receipt.Binding || recovered.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("original failed key changed its retained failure after dependency recovery", recovered.Receipt.Outcome, err)
	}
	var partial int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(owner.TenantID), string(created.OrganizationID), string(memberID)).Scan(&partial); err != nil || partial != 0 {
		t.Fatal("rolled back member authority survived", err)
	}
	added, err := service.AddMember(ctx, add, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("keyed member admission failed", err)
	}
	if out, err := newService().AddMember(ctx, add, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, added) {
		t.Fatal("keyed add restart selected changed current versions", err)
	}
	add.Role = organization.RoleAdministrator
	if _, err := service.AddMember(ctx, add, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("same admission key changed role", err)
	}
	read.Authentication, read.Limit = member, 10
	if view, err := service.ListMembers(ctx, read); err != nil || len(view.Members) != 2 {
		t.Fatal("admitted member could not list native memberships", err)
	}
	denied := add
	denied.Authentication, denied.IdempotencyKey, denied.UserID = member, key("direct-member-cannot-add"), ownerID
	denied.OrganizationVersion, denied.MemberVersion = 2, 1
	if _, err := service.AddMember(ctx, denied, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("ordinary member gained mutation authority or lost typed denial", err)
	}
	remove := organization.RemoveMemberOperationRequest{Authentication: owner, OrganizationID: created.OrganizationID, UserID: memberID, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "remove"}
	removed, err := service.RemoveMember(ctx, remove, "127.0.0.1")
	if err != nil || removed.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("non-keyed exact removal failed", err)
	}
	remove.CorrelationID = "repeat-remove"
	if out, err := newService().RemoveMember(ctx, remove, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, removed) {
		t.Fatal("repeat removal did not recover real original receipt", err)
	}
	read.Limit = 0
	if _, err := service.Get(ctx, read); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("removed human retained organization authority", err)
	}
	last := organization.RemoveMemberOperationRequest{Authentication: owner, OrganizationID: created.OrganizationID, UserID: ownerID, OrganizationVersion: 3, MemberVersion: 1, CorrelationID: "last-owner"}
	if _, err := service.RemoveMember(ctx, last, "127.0.0.1"); !errors.Is(err, organization.ErrLastOwner) {
		t.Fatal("last owner was removed", err)
	}
	var organizations, memberships, removals int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.organizations),(SELECT count(*) FROM organization.memberships WHERE state='active'),(SELECT count(*) FROM organization.command_effects WHERE operation=$1)`, string(organization.RemoveMember)).Scan(&organizations, &memberships, &removals); err != nil || organizations != 1 || memberships != 1 || removals != 1 {
		t.Fatal("retries duplicated original durable effects", err)
	}
	readmit := organization.AddMemberOperationRequest{Authentication: owner, IdempotencyKey: key("direct-readmit"), OrganizationID: created.OrganizationID, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 3, MemberVersion: 2, CorrelationID: "readmit"}
	if admitted, err := newService().AddMember(ctx, readmit, "127.0.0.1"); err != nil || admitted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("new native member generation was not admitted", err)
	}
	if _, err := newService().RemoveMember(ctx, remove, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("old repeat removed or fabricated success for re-admitted member", err)
	}
	if view, err := newService().ListMembers(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: created.OrganizationID, Limit: 10, CorrelationID: "after-stale-repeat"}); err != nil || len(view.Members) != 2 || view.Organization.Version != 4 {
		t.Fatal("stale repeat changed current admitted authority", err)
	}
	crossTenant := create
	crossTenant.Authentication.TenantID = "other-tenant"
	if out, err := newService().Create(ctx, crossTenant, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" || allocations.Load() != 1 {
		t.Fatal("cross-tenant bearer obtained original-key custody", err)
	}
	// Fault-injected withdrawal changes the actual session owner's stored row;
	// no alternate authentication engine or fabricated denied observation is used.
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(owner.TenantID), string(ownerID)); err != nil {
		t.Fatal("native session withdrawal fixture failed", err)
	}
	if out, err := newService().Create(ctx, create, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" || allocations.Load() != 1 {
		t.Fatal("revoked current session recovered or reprepared original key", err)
	}
}
