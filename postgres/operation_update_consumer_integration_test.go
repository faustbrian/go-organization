//go:build integration

package postgres_test

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
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func TestOrganizationGenuineDirectUpdateConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-update-operations")
}

func TestOrganizationGenuineDirectUpdateContentionConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "direct-update-contention")
}

// The existing consumer policy selects create/add key admission only. This
// finite application profile additionally selects Update through the actual
// authorization engine; native current session/membership/action fences remain
// the original owner and independently decide each update and disclosure.
type updateAdmissionEvaluator struct{}

func (*updateAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.Update) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.Update) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

func exerciseGenuineDirectUpdates(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, source *organizationpg.Service, owner, member organization.Authentication, ownerID, memberID identity.UserID, keys map[string][32]byte, material func(string) []byte, newSource func(*database.Pool) *organizationpg.Service, profile string) {
	t.Helper()
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-update-consumer", Revision: 9, Evaluator: new(updateAdmissionEvaluator)})
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
	requestKeys, err := kernel.NewRequestKeyConfig("organization-update-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("organization-update", map[string][]byte{"organization-update": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	var createdOrganizations int32
	build := func(source *organizationpg.Service) *organizationpg.OperationService {
		s, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "organization-update-consumer-v1", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(ctx context.Context) (organization.ID, error) {
			allocations.Add(1)
			id, err := identity.NewSubjectID()
			return organization.ID(id), errors.Join(ctx.Err(), err)
		}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	key := func(value string) identity.IdempotencyKey {
		k, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	create := func(slug string) organization.ID {
		out, err := build(source).Create(ctx, organization.CreateOperationRequest{Authentication: owner, IdempotencyKey: key("create-" + slug), Name: "Update consumer", Slug: slug, CorrelationID: "create-update"}, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("update setup creation failed", err)
		}
		createdOrganizations++
		return out.OrganizationID
	}
	request := func(org organization.ID, version uint64, suffix string) organization.UpdateOperationRequest {
		return organization.UpdateOperationRequest{Authentication: owner, IdempotencyKey: key("update-" + suffix), OrganizationID: org, OrganizationVersion: version, Name: "Updated " + suffix, Slug: "updated-" + suffix, CorrelationID: "update-" + suffix}
	}
	if profile == "direct-update-contention" {
		exerciseConcurrentDirectUpdate(t, ctx, pool, db, owner, create("contended-update"), request, func(p *database.Pool) *organizationpg.OperationService { return build(newSource(p)) })
		if allocations.Load() != createdOrganizations {
			t.Fatal("contended Update allocated an organization identity", allocations.Load())
		}
		return
	}
	assertState := func(org organization.ID, name, slug, version string, effects int) {
		t.Helper()
		var n, s, v string
		var count int
		if err := db.QueryRowContext(ctx, `SELECT name,slug,version::text,(SELECT count(*) FROM organization.command_effects e WHERE e.tenant_id=o.tenant_id AND e.organization_id=o.organization_id AND e.operation=$3) FROM organization.organizations o WHERE tenant_id=$1 AND organization_id=$2`, string(owner.TenantID), string(org), string(organization.Update)).Scan(&n, &s, &v, &count); err != nil || n != name || s != slug || v != version || count != effects {
			t.Fatal("keyed metadata changed durable state or repeated effects", err, v, count)
		}
	}
	org := create("direct-update")
	r := request(org, 1, "owner")
	committed, err := build(source).Update(ctx, r, "127.0.0.1")
	if err != nil || committed.Receipt.Validate() != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted || committed.Receipt.Feature.BeforeVersion != 1 || committed.Receipt.Feature.AfterVersion != 2 || committed.MemberID != ownerID || committed.OrganizationID != org {
		t.Fatal("owner keyed update did not commit exact original transition", err)
	}
	r.CorrelationID = "retry-keeps-original"
	if got, err := build(newSource(pool)).Update(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, committed) {
		t.Fatal("restart retry did not preserve original metadata receipt", err)
	}
	for name, change := range map[string]func(*organization.UpdateOperationRequest){
		"name":         func(r *organization.UpdateOperationRequest) { r.Name = "Changed intent" },
		"slug":         func(r *organization.UpdateOperationRequest) { r.Slug = "changed-intent" },
		"organization": func(r *organization.UpdateOperationRequest) { r.OrganizationID = "different-organization" },
		"version":      func(r *organization.UpdateOperationRequest) { r.OrganizationVersion = 2 },
	} {
		t.Run("changed-"+name, func(t *testing.T) {
			changed := r
			change(&changed)
			if _, err := build(source).Update(ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
				t.Fatal("same Update key changed original intent", err)
			}
		})
	}
	stale := request(org, 1, "stale")
	if _, err := build(source).Update(ctx, stale, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("fresh key admitted stale metadata", err)
	}
	noop := r
	noop.IdempotencyKey, noop.OrganizationVersion = key("update-noop"), 2
	if _, err := build(source).Update(ctx, noop, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("no-op replacement advanced metadata", err)
	}
	create("occupied-update-slug")
	collision := request(org, 2, "collision")
	collision.Slug = "occupied-update-slug"
	if _, err := build(source).Update(ctx, collision, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("keyed update stole existing tenant slug", err)
	}
	assertState(org, r.Name, r.Slug, "2", 1)
	added, err := build(source).AddMember(ctx, organization.AddMemberOperationRequest{Authentication: owner, IdempotencyKey: key("update-member"), OrganizationID: org, UserID: memberID, Role: organization.RoleMember, OrganizationVersion: 2, CorrelationID: "update-member"}, "127.0.0.1")
	if err != nil || added.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("update member setup failed", err)
	}
	denied := request(org, 3, "member")
	denied.Authentication = member
	if _, err := build(source).Update(ctx, denied, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("ordinary member obtained keyed metadata authority", err)
	}
	changeRole := func(role organization.Role, version, memberVersion uint64) {
		t.Helper()
		prepared, err := source.PrepareUpdateMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, UserID: memberID, Role: role, OrganizationVersion: version, MemberVersion: memberVersion, CorrelationID: "update-role"}, "127.0.0.1")
		if err != nil {
			t.Fatal("real role setup failed", err)
		}
		if out, err := source.Execute(ctx, prepared); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("real role transition failed", err)
		}
	}
	changeRole(organization.RoleAdministrator, 3, 1)
	admin := request(org, 4, "administrator")
	admin.Authentication = member
	adminResult, err := build(source).Update(ctx, admin, "127.0.0.1")
	if err != nil || adminResult.Receipt.Outcome != identity.CommitOutcomeCommitted || adminResult.Receipt.Feature.BeforeVersion != 4 || adminResult.Receipt.Feature.AfterVersion != 5 {
		t.Fatal("current administrator keyed update failed", err)
	}
	changeRole(organization.RoleMember, 5, 2)
	if _, err := build(newSource(pool)).Update(ctx, admin, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("demoted actor disclosed original management result", err)
	}
	if _, err := build(source).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: member, Binding: adminResult.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("explicit recovery bypassed withdrawn current role", err)
	}
	if got, err := build(source).Update(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, committed) {
		t.Fatal("owner retry reprepared against later metadata version", err)
	}
	assertState(org, admin.Name, admin.Slug, "6", 2)
	var audits, events int
	if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND r.action='identity.organization.update' AND r.record_id IN ($2,$3)),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND m.topic='organization.updated.v1')`, string(owner.TenantID), committed.Receipt.AuditEventID, adminResult.Receipt.AuditEventID).Scan(&audits, &events); err != nil || audits != 2 || events != 2 {
		t.Fatal("keyed metadata lost or repeated protected audit/lifecycle effects", err, audits, events)
	}
	var unchanged int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND version=1 AND authorization_version=1 AND role='owner' AND state='active'`, string(owner.TenantID), string(org), string(ownerID)).Scan(&unchanged); err != nil || unchanged != 1 {
		t.Fatal("metadata update changed owner membership authority", err)
	}
	for _, mappingOnly := range []bool{false, true} {
		label := "lost-commit"
		if mappingOnly {
			label = "mapping-only"
		}
		t.Run(label, func(t *testing.T) {
			faultOrg := create(label)
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
				t.Fatal("update fault primary unavailable", err)
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if primary.Close(cleanup) != nil {
					t.Error("update fault pool cleanup failed")
				}
			})
			faultRequest := request(faultOrg, 1, label)
			faultService := build(newSource(primary))
			fault.count.Store(-1)
			if mappingOnly {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			out, err := faultService.Update(ctx, faultRequest, "127.0.0.1")
			var unknown identity.UnknownCommitError
			if !fault.lost.Load() || err == nil || out.Receipt.Binding.CommandID == "" || out.Receipt.Outcome != identity.CommitOutcomeUnknown || errors.As(err, &unknown) && unknown.CommandID != out.Receipt.Binding.CommandID {
				t.Fatal("lost Update acknowledgment lost original unknown correlation", err)
			}
			for range 2 {
				recovered, err := build(newSource(pool)).Update(ctx, faultRequest, "127.0.0.1")
				if recovered.Receipt.Binding != out.Receipt.Binding {
					t.Fatal("Update retry allocated another original command")
				}
				if mappingOnly {
					if !errors.As(err, &unknown) || recovered.Receipt.Outcome != identity.CommitOutcomeUnknown {
						t.Fatal("mapping-only Update claimed an outcome or reexecution grant", err)
					}
				} else if err != nil || recovered.Receipt.Validate() != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("lost committed Update did not recover real journal", err)
				}
			}
			explicit, err := build(source).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: out.Receipt.Binding})
			if explicit.Receipt.Binding != out.Receipt.Binding || mappingOnly && (!errors.As(err, &unknown) || explicit.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || explicit.Receipt.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("explicit Update recovery diverged from original mapping/journal", err)
			}
			if mappingOnly {
				assertState(faultOrg, "Update consumer", label, "1", 0)
				raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
				if err != nil {
					t.Fatal("invalid original command correlation")
				}
				var journals, claims int
				if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1)`, raw).Scan(&journals, &claims); err != nil || journals != 0 || claims != 0 {
					t.Fatal("mapped-only Update created a journal or execution claim", err)
				}
				generic, err := source.Recover(ctx, owner, organizationpg.Recovery{Binding: out.Receipt.Binding})
				var forbidden identity.ForbiddenError
				if !errors.As(err, &forbidden) || generic.Receipt.Binding.CommandID != "" {
					t.Fatal("mapped Update changed generic absent-journal privacy", err)
				}
			} else {
				assertState(faultOrg, faultRequest.Name, faultRequest.Slug, "2", 1)
			}
		})
	}
	withdrawOrg := create("withdrawn-update-authority")
	withdraw := request(withdrawOrg, 1, "authority")
	withdrawResult, err := build(source).Update(ctx, withdraw, "127.0.0.1")
	if err != nil || withdrawResult.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("scoped authority setup update failed", err)
	}
	scope, err := organizationpg.OrganizationAuthorityScope(owner.TenantID, withdrawOrg, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	// Withdraw the authorization owner's actual scoped evidence without changing
	// this user's valid session or native owner-membership snapshot.
	if _, err := authority.AdvanceAuthority(ctx, pool.Raw(), scope, 1, time.Second); err != nil {
		t.Fatal("scoped authorization withdrawal failed", err)
	}
	if _, err := build(newSource(pool)).Update(ctx, withdraw, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn scoped authority disclosed original keyed Update", err)
	}
	if _, err := build(source).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: withdrawResult.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("withdrawn scoped authority disclosed explicit Update recovery", err)
	}
	assertState(withdrawOrg, withdraw.Name, withdraw.Slug, "2", 1)
	// A distinct organization retains its current authority, so the next denial
	// independently witnesses the actual session-owner withdrawal.
	if got, err := build(source).Update(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, committed) {
		t.Fatal("unrelated scoped withdrawal changed valid owner recovery", err)
	}
	if allocations.Load() != createdOrganizations {
		t.Fatal("Update retry allocated an organization identity", allocations.Load())
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(owner.TenantID), string(ownerID)); err != nil {
		t.Fatal("actual Update session withdrawal failed", err)
	}
	if got, err := build(source).Update(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("revoked session recovered original Update custody", err)
	}
}

type updateReadTraceKey struct{}
type updateReadBarrier struct {
	ready    chan struct{}
	release  <-chan struct{}
	observed atomic.Int32
}

func (b *updateReadBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(data.SQL, "SELECT o.slug,o.name,o.version::text,o.owner_count::text,a.role,a.version::text,a.authorization_version::text\nFROM organization.organizations") {
		return context.WithValue(ctx, updateReadTraceKey{}, true)
	}
	return ctx
}

func (b *updateReadBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if selected, _ := ctx.Value(updateReadTraceKey{}).(bool); !selected || data.Err != nil || data.CommandTag.RowsAffected() == 0 || b.observed.Add(1) > 2 {
		return
	}
	// Both actual primary preparation reads finish before either candidate
	// admits the key. No SQL locks or fabricated repository answers are involved.
	b.ready <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
}

func exerciseConcurrentDirectUpdate(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, owner organization.Authentication, org organization.ID, request func(organization.ID, uint64, string) organization.UpdateOperationRequest, build func(*database.Pool) *organizationpg.OperationService) {
	t.Helper()
	release := make(chan struct{})
	trace := &updateReadBarrier{ready: make(chan struct{}, 2), release: release}
	primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal("contended Update primary unavailable", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if primary.Close(cleanup) != nil {
			t.Error("contended Update cleanup failed")
		}
	})
	first, second := build(primary), build(primary)
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
	r := request(org, 1, "contention")
	for _, s := range []*organizationpg.OperationService{first, second} {
		workers.Add(1)
		go func() { defer workers.Done(); out, err := s.Update(ctx, r, "127.0.0.1"); results <- result{out, err} }()
	}
	for range 2 {
		select {
		case <-trace.ready:
		case early := <-results:
			t.Fatal("contended Update ended before both real source reads", early.err)
		case <-ctx.Done():
			t.Fatal("bounded Update source-read barrier expired")
		}
	}
	unblock()
	a, b := <-results, <-results
	original, err := build(pool).Update(ctx, r, "127.0.0.1")
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("contended Update did not converge on original receipt", err)
	}
	for _, attempt := range []result{a, b} {
		if attempt.out.Receipt.Binding != original.Receipt.Binding || attempt.err == nil && !reflect.DeepEqual(attempt.out, original) {
			t.Fatal("contended Update changed original command/outcome", attempt.err)
		}
	}
	var effects int
	var command identity.CommandID
	if err := db.QueryRowContext(ctx, `SELECT count(*),min(command_id) FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND operation=$3`, string(owner.TenantID), string(org), string(organization.Update)).Scan(&effects, &command); err != nil || effects != 1 || command != original.Receipt.Binding.CommandID {
		t.Fatal("contended Update duplicated durable transition", err)
	}
	view, err := build(pool).Get(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "contention-read"})
	if err != nil || view.Organization.Version != 2 || view.Organization.Name != r.Name || view.Organization.Slug != r.Slug {
		t.Fatal("contended Update receipt differs from actual metadata", err)
	}
}
