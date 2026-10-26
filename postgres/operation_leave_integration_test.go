//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
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
	"github.com/jackc/pgx/v5/stdlib"
)

func leaveOperationFixture(t *testing.T) *orgFixture {
	t.Helper()
	return newOrgFixture(t, organizationpg.LeaveOperationLookupTransactionalMigrationSource{Version: 301})
}

func leaveOperationRequest(f *orgFixture, tenant, actor string, version uint64) organization.LeaveMemberOperationRequest {
	return organization.LeaveMemberOperationRequest{Authentication: f.auth(tenant, actor), OrganizationID: metadataOrganization, OrganizationVersion: version, CorrelationID: "natural-self-leave"}
}

func TestLeaveOperationOriginalRepeatAndReadmission(t *testing.T) {
	f := leaveOperationFixture(t)
	for i, role := range []organization.Role{organization.RoleMember, organization.RoleAdministrator, organization.RoleOwner} {
		tenant := []string{"org-test-basic", "org-test-scope", "org-test-race"}[i]
		f.create(t, tenant)
		f.add(t, tenant, "member", role, 1)
		r := leaveOperationRequest(f, tenant, "member", 2)
		facade := slugNativeOperationService(t, f.service)
		original, err := facade.LeaveMember(f.ctx, r, "127.0.0.1")
		if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.Receipt.Binding.UserID != "member" || original.Receipt.Binding.ActorID != "member" || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
			t.Fatal("actual self-leave did not commit exact effect", err)
		}
		assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
		r.CorrelationID = "repeat-new-diagnostic"
		for range 2 {
			out, err := slugNativeOperationService(t, f.service).LeaveMember(f.ctx, r, "127.0.0.1")
			if err != nil || !reflect.DeepEqual(out, original) {
				t.Fatal("natural repeat lost original receipt", err)
			}
		}
		recovery := organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding}
		if out, err := facade.RecoverOperation(f.ctx, recovery); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("departed self cannot recover exact metadata", err)
		}
		if _, err := f.service.Recover(f.ctx, r.Authentication, organizationpg.Recovery{Binding: recovery.Binding}); !errors.Is(err, organization.ErrForbidden) {
			t.Fatal("legacy membership recovery was weakened", err)
		}
		readmitAfterLeave(t, f, tenant, 3)
		if _, err := facade.LeaveMember(f.ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) {
			t.Fatal("old intent admitted readmitted membership", err)
		}
		if out, err := facade.RecoverOperation(f.ctx, recovery); err != nil || !reflect.DeepEqual(out, original) {
			t.Fatal("readmission blocked historical metadata", err)
		}
		assertLeaveState(t, f, tenant, "member", "active", "4", 1)
	}
}

func TestLeaveOperationContentionConvergesOneEffect(t *testing.T) {
	f := leaveOperationFixture(t)
	tenant := "org-test-basic"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	r := leaveOperationRequest(f, tenant, "member", 2)
	facade := slugNativeOperationService(t, f.service)
	type result struct {
		out organization.StoreResult
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() { out, err := facade.LeaveMember(f.ctx, r, "127.0.0.1"); results <- result{out, err} })
	}
	wg.Wait()
	close(results)
	var original organization.StoreResult
	for got := range results {
		if got.err != nil || got.out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("identical contended leave did not reconcile", got.err)
		}
		if original.Receipt.Binding.CommandID != "" && !reflect.DeepEqual(original, got.out) {
			t.Fatal("contended leave returned different originals")
		}
		original = got.out
	}
	assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
}

func TestLeaveOperationAdmissionDenialsAndAbsence(t *testing.T) {
	for _, variant := range []string{"last-owner", "stale", "outsider", "tenant", "revoked", "policy", "absence"} {
		t.Run(variant, func(t *testing.T) {
			f := leaveOperationFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			r := leaveOperationRequest(f, tenant, "owner", 1)
			want := organization.ErrForbidden
			if variant == "last-owner" {
				want = organization.ErrLastOwner
			} else {
				f.add(t, tenant, "member", organization.RoleMember, 1)
				r = leaveOperationRequest(f, tenant, "member", 2)
			}
			service := f.service
			switch variant {
			case "stale":
				r.OrganizationVersion = 1
				want = organization.ErrConflict
			case "outsider":
				r.Authentication = f.auth(tenant, "outsider")
			case "tenant":
				r.Authentication.TenantID = "org-test-scope"
			case "revoked":
				if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='member'`, tenant); err != nil {
					t.Fatal(err)
				}
			case "policy":
				service = listPolicyService(t, f, &leaveOperationPolicy{callback: func(context.Context, authorization.DecisionContext, int) (authorization.Outcome, error) {
					return authorization.Deny, nil
				}})
			case "absence":
				prepared, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: metadataOrganization, OrganizationVersion: 2, UserID: "member", MemberVersion: 1, CorrelationID: "absence-is-not-success"}, "127.0.0.1")
				if err != nil {
					t.Fatal(err)
				}
				committedTeam(t, f, prepared)
			}
			if out, err := slugNativeOperationService(t, service).LeaveMember(f.ctx, r, "127.0.0.1"); !errors.Is(err, want) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("invalid self departure admitted or absence treated as success", err)
			}
			var count int
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.member.leave'`).Scan(&count); err != nil || count != 0 {
				t.Fatal("denied leave created an effect", err)
			}
		})
	}
}

type leaveOperationPolicy struct {
	calls    map[string]int
	callback func(context.Context, authorization.DecisionContext, int) (authorization.Outcome, error)
}

func (p *leaveOperationPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if c.Request.Action == authorization.Action(organization.LeaveMember) {
		if p.calls == nil {
			p.calls = make(map[string]int)
		}
		p.calls[string(c.Request.Resource.Type)]++
		outcome, err := p.callback(ctx, c, p.calls[string(c.Request.Resource.Type)])
		return authorization.Decision{Outcome: outcome, Revision: 1}, err
	}
	return (fixturePolicy{}).Decide(ctx, c)
}

func leaveOperationPolicyFacade(t *testing.T, f *orgFixture, policy authorization.Service, trustedClock clock.Clock) *organizationpg.OperationService {
	t.Helper()
	config := f.configuration
	config.Authorization = policy
	if trustedClock != nil {
		config.Core.Clock = trustedClock
	}
	source, err := organizationpg.NewService(f.participant, config)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: config.Core.Clock, PolicyVersion: 1}
	keys, err := kernel.NewRequestKeyConfig("leave-test", [32]byte{0x51}, query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("leave-test", map[string][]byte{"leave-test": bytes.Repeat([]byte{0x52}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	facade, err := organizationpg.NewOperationService(source, organizationpg.OperationServiceConfig{ConfigurationID: "leave-test", Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x53}}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: keys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) { return "", organization.ErrUnavailable }})
	if err != nil {
		t.Fatal(err)
	}
	return facade
}

type leaveShiftClock struct{ offset time.Duration }

func (c *leaveShiftClock) Now() time.Time { return time.Now().Add(c.offset) }

func TestLeaveOperationRecoveryFences(t *testing.T) {
	for _, variant := range []string{"denied", "final-policy", "final-session", "query-session", "query-epoch", "query-scoped-authority", "query-missing-authority", "original-freshness", "readmission", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			f := leaveOperationFixture(t)
			tenant := "org-test-basic"
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			r := leaveOperationRequest(f, tenant, "member", 2)
			original, err := slugNativeOperationService(t, f.service).LeaveMember(f.ctx, r, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			trustedClock := &leaveShiftClock{}
			fired := false
			policy := &leaveOperationPolicy{callback: func(ctx context.Context, c authorization.DecisionContext, n int) (authorization.Outcome, error) {
				org := c.Request.Resource.Type == "organization"
				if variant == "denied" && org {
					fired = true
					return authorization.Deny, nil
				}
				if variant == "final-policy" && org && n == 2 {
					fired = true
					return authorization.Deny, nil
				}
				match := variant == "final-session" && org && n == 2 || variant == "original-freshness" && org && n == 2 || variant == "readmission" && org || variant == "canceled" && org || !org && (variant == "query-session" || variant == "query-epoch" || variant == "query-scoped-authority" || variant == "query-missing-authority")
				if !match || fired {
					return authorization.Allow, nil
				}
				fired = true
				var err error
				switch variant {
				case "final-session", "query-session":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id='member'`, tenant)
				case "query-epoch":
					_, err = f.pool.Raw().Exec(ctx, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1`, tenant)
				case "query-scoped-authority":
					scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "member")
					if e != nil {
						return 0, e
					}
					_, err = authority.AdvanceAuthority(ctx, f.pool.Raw(), scope, 2, time.Second)
				case "query-missing-authority":
					scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), metadataOrganization, "member")
					if e != nil {
						return 0, e
					}
					_, err = f.pool.Raw().Exec(ctx, `DELETE FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id='member'`, tenant, scope.PolicyNamespace)
				case "original-freshness":
					trustedClock.offset = time.Minute
				case "readmission":
					readmitAfterLeave(t, f, tenant, 3)
				case "canceled":
					cancel()
				}
				return authorization.Allow, err
			}}
			facade := leaveOperationPolicyFacade(t, f, policy, trustedClock)
			out, err := facade.RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: original.Receipt.Binding})
			want := organization.ErrForbidden
			if variant == "canceled" {
				want = context.Canceled
			}
			if !fired || !errors.Is(err, want) || out != (organization.StoreResult{}) {
				t.Fatal("withdrawn self-history admission disclosed receipt", variant, fired, err)
			}
		})
	}
}

func TestLeaveOperationLostAcknowledgement(t *testing.T) {
	f := leaveOperationFixture(t)
	tenant := "org-test-unknown"
	f.create(t, tenant)
	f.add(t, tenant, "member", organization.RoleMember, 1)
	source, fault := f.lostCommitService(t)
	r := leaveOperationRequest(f, tenant, "member", 2)
	fault.armed.Store(true)
	unknown, err := slugNativeOperationService(t, source).LeaveMember(f.ctx, r, "127.0.0.1")
	if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
		t.Fatal("lost acknowledgement discarded original unknown", err)
	}
	assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
	facade := slugNativeOperationService(t, f.service)
	actual, err := facade.LeaveMember(f.ctx, r, "127.0.0.1")
	if err != nil || actual.Receipt.Outcome != identity.CommitOutcomeCommitted || actual.Receipt.Binding != unknown.Receipt.Binding {
		t.Fatal("natural repeat did not resolve exact original lost commit", err)
	}
	if out, err := facade.RecoverOperation(f.ctx, organization.OperationRecoveryRequest{Authentication: r.Authentication, Binding: unknown.Receipt.Binding}); err != nil || !reflect.DeepEqual(out, actual) {
		t.Fatal("full-binding lost commit recovery differs", err)
	}
	assertLeaveState(t, f, tenant, "member", "removed", "3", 1)
}

func TestLeaveOperationAtomicEffectsRollback(t *testing.T) {
	for _, boundary := range []string{"audit", "outbox"} {
		t.Run(boundary, func(t *testing.T) {
			f := leaveOperationFixture(t)
			tenant := "org-test-rollback"
			f.create(t, tenant)
			f.add(t, tenant, "member", organization.RoleMember, 1)
			table := "audit.records"
			body := `IF NEW.outcome=1 AND NEW.action='identity.organization.remove_member' THEN RAISE EXCEPTION 'synthetic leave failure'; END IF; RETURN NEW;`
			if boundary == "outbox" {
				table = "public.identity_outbox_bindings"
				body = `RAISE EXCEPTION 'synthetic leave failure';`
			}
			if _, err := f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.operation_leave_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$; CREATE TRIGGER operation_leave_fail BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION public.operation_leave_fail()`); err != nil {
				t.Fatal(err)
			}
			r := leaveOperationRequest(f, tenant, "member", 2)
			out, err := slugNativeOperationService(t, f.service).LeaveMember(f.ctx, r, "127.0.0.1")
			if err == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required publication failure committed leave", err)
			}
			assertLeaveState(t, f, tenant, "member", "active", "2", 0)
			var version string
			if err := f.pool.Raw().QueryRow(f.ctx, `SELECT authorization_version::text FROM organization.memberships WHERE tenant_id=$1 AND user_id='member'`, tenant).Scan(&version); err != nil || version != "1" {
				t.Fatal("failed leave advanced scoped authority", err)
			}
		})
	}
}

// This is an isolated physical access-path/migration check. Synthetic retained
// effects are not evidence of authenticated leave; the tests above and the
// genuine public consumer exercise actual protected transitions.
func TestLeaveOperationPopulatedLookupMigration(t *testing.T) {
	f := newOrgFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version)
SELECT translate(rtrim(encode(int8send(n)||int8send(23),'base64'),'='),'+/','-_'),
'plan-tenant','plan-'||lpad(n::text,8,'0'),'self','self',
CASE WHEN n%4=0 THEN 'identity.organization.member.leave' ELSE 'identity.organization.member.add' END,
decode(repeat('ab',32),'hex'),7,8 FROM generate_series(1::bigint,20000::bigint) n`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	const lookup = `SELECT command_id FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.member.leave' AND actor_id=$4 AND user_id=$4
LIMIT 2`
	read := func() operationLookupPlan {
		t.Helper()
		var wire []byte
		if err := f.pool.Raw().QueryRow(f.ctx, "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+lookup, "plan-tenant", "plan-00010000", "7", "self").Scan(&wire); err != nil {
			t.Fatal(err)
		}
		var reports []struct{ Plan operationLookupPlan }
		if err := json.Unmarshal(wire, &reports); err != nil || len(reports) != 1 {
			t.Fatal("invalid native lookup plan", err)
		}
		return reports[0].Plan
	}
	var before operationLookupPlan
	for range 3 {
		before = read()
	}
	steps, err := (organizationpg.LeaveOperationLookupMigrationSource{Version: 1}).Load(f.ctx)
	if err != nil || len(steps) != 1 || steps[0].TransactionMode() != migrations.TransactionModeNone {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("self_leave_independent")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(steps), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("populated concurrent lookup installation", err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("independent migration replay", err)
	}
	var after operationLookupPlan
	for range 3 {
		after = read()
	}
	var indexed func(operationLookupPlan) bool
	indexed = func(p operationLookupPlan) bool {
		if p.Index == "organization_repeat_leave" {
			return true
		}
		for _, child := range p.Plans {
			if indexed(child) {
				return true
			}
		}
		return false
	}
	if before.Rows != 1 || after.Rows != 1 || !indexed(after) || after.examined() > 1 || after.examined() >= before.examined() {
		t.Fatal("unforced native planner did not select bounded same-result lookup", before.examined(), after.examined())
	}
	var indexBytes, heapBytes int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_size('organization.organization_repeat_leave'),pg_relation_size('organization.command_effects')`).Scan(&indexBytes, &heapBytes); err != nil || indexBytes <= 0 {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','legacy-tenant','legacy-org','self','self','identity.organization.member.leave',decode(repeat('ab',32),'hex'),1,2)`); err != nil {
		t.Fatal("native append incompatible with additive index", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) VALUES('AAAAAAAAAAAAAAAAAAAAAg','legacy-tenant','legacy-org','other','other','identity.organization.member.leave',decode(repeat('ab',32),'hex'),1,2)`); err == nil {
		t.Fatal("exact leave epoch guard admitted duplicate effect")
	}
	t.Logf("retained effects 20000/leaves 5000; unforced examined %.0f -> %.0f; leave index bytes %d / heap bytes %d", before.examined(), after.examined(), indexBytes, heapBytes)
}
