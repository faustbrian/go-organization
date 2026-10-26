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

func TestOrganizationGenuineLifecycleOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "lifecycle-operation")
}

type lifecycleOperation interface {
	Archive(context.Context, organization.LifecycleOperationRequest, string) (organization.StoreResult, error)
	Restore(context.Context, organization.LifecycleOperationRequest, string) (organization.StoreResult, error)
}

// Request-key route admission is application-owned, not a substitute for the
// native current owner and the password owner's signed action proof.
type lifecycleOperationEvaluator struct{}

func (*lifecycleOperationEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	op := organization.Operation(r.Action)
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && (op == organization.Archive || op == organization.Restore) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(op) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}

func exerciseGenuineLifecycleOperations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, source *organizationpg.Service, invitations *organizationpg.InvitationService, owner, recipient organization.Authentication, ownerID, recipientID identity.UserID, live issued, profile *lifecycleConsumer, keys map[string][32]byte, material func(string) []byte) {
	t.Helper()
	if profile == nil || profile.newServicePool == nil {
		t.Fatal("genuine lifecycle operation composition missing")
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-lifecycle-operation", Revision: 9, Evaluator: new(lifecycleOperationEvaluator)})
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
	requestKeys, err := kernel.NewRequestKeyConfig("organization-lifecycle-operation", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("lifecycle-operation", map[string][]byte{"lifecycle-operation": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	build := func(primary *database.Pool, configuration string) *organizationpg.OperationService {
		s, err := organizationpg.NewOperationService(profile.newServicePool(primary), organizationpg.OperationServiceConfig{ConfigurationID: configuration, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, Custody: custody, NewOrganizationID: func(context.Context) (organization.ID, error) {
			allocations.Add(1)
			return "", organization.ErrUnavailable
		}})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	current := func(primary *database.Pool) *organizationpg.OperationService {
		return build(primary, "organization-lifecycle-v1")
	}
	if _, ok := any(current(pool)).(lifecycleOperation); !ok {
		t.Fatal("native original-key archive/restore operation is missing")
	}
	mutate := func(s *organizationpg.OperationService, op organization.Operation, r organization.LifecycleOperationRequest) (organization.StoreResult, error) {
		if op == organization.Archive {
			return any(s).(lifecycleOperation).Archive(ctx, r, "127.0.0.1")
		}
		return any(s).(lifecycleOperation).Restore(ctx, r, "127.0.0.1")
	}
	commit := func(p organizationpg.PreparedCommand, err error) {
		t.Helper()
		if err != nil {
			t.Fatal("genuine lifecycle setup preparation", err)
		}
		if out, err := source.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine lifecycle setup commit", err)
		}
	}
	view := func(org organization.ID) organization.View {
		t.Helper()
		v, err := source.GetLifecycle(ctx, organization.ReadRequest{Authentication: owner, OrganizationID: org, CorrelationID: "keyed-lifecycle-read"})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	create := func(label string) organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		org := organization.ID(id)
		commit(source.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: org, Name: "Original keyed lifecycle", Slug: "keyed-lifecycle-" + label, CorrelationID: "lifecycle-setup"}, "127.0.0.1"))
		return org
	}
	request := func(org organization.ID, op organization.Operation, label string) organization.LifecycleOperationRequest {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte("original-lifecycle-" + label))
		if err != nil {
			t.Fatal(err)
		}
		return organization.LifecycleOperationRequest{Authentication: owner, IdempotencyKey: key, OrganizationID: org, OrganizationVersion: view(org).Organization.Version, Reason: "maintenance", CorrelationID: "original-lifecycle-" + label, Proof: profile.proof(owner, op)}
	}
	assertState := func(org organization.ID, state organization.LifecycleState, version uint64, effects int) {
		t.Helper()
		v := view(org)
		var count int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND operation IN ($3,$4)`, string(owner.TenantID), string(org), string(organization.Archive), string(organization.Restore)).Scan(&count); err != nil || v.LifecycleState != state || v.Organization.Version != version || count != effects {
			t.Fatal("keyed lifecycle state/version/effects diverged", err, v.LifecycleState, v.Organization.Version, count)
		}
	}
	assertEffects := func(out organization.StoreResult, committed, admitted bool) {
		t.Helper()
		raw, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var effects, events, audits, charges int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),(SELECT count(*) FROM identity_outbox_bindings WHERE command_id=$2),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$2),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$2)`, string(out.Receipt.Binding.CommandID), raw).Scan(&effects, &events, &audits, &charges); err != nil {
			t.Fatal(err)
		}
		protected, canonical := 0, 0
		if committed {
			protected = 1
		}
		if admitted {
			canonical = 1
		}
		if effects != protected || events != protected || audits != canonical || charges != canonical {
			t.Fatal("original lifecycle effects/admission/audit repeated or diverged", effects, events, audits, charges)
		}
	}
	assertOriginal := func(op organization.Operation, r organization.LifecycleOperationRequest, original organization.StoreResult) {
		t.Helper()
		r.CorrelationID = "retry-must-retain-original"
		got, err := mutate(current(pool), op, r)
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("restart lifecycle retry changed original metadata", err)
		}
		got, err = current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: original.Receipt.Binding})
		if err != nil || !reflect.DeepEqual(got, original) {
			t.Fatal("explicit lifecycle recovery changed original outcome", err)
		}
		assertEffects(original, true, true)
	}
	assertProof := func(r organization.LifecycleOperationRequest, out organization.StoreResult, consumed bool) {
		t.Helper()
		command, err := base64.RawURLEncoding.Strict().DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var got bool
		if err := db.QueryRowContext(ctx, `SELECT coalesce(consumed_command_id=$2 AND consumed_purpose=$3 AND consumed_at IS NOT NULL,false) FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(r.Proof.Proof.ID), command, r.Proof.Action).Scan(&got); err != nil || got != consumed {
			t.Fatal("keyed lifecycle original proof consumption diverged", err)
		}
	}
	org := live.org
	commit(source.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 1, UserID: profile.memberID, Role: organization.RoleMember, CorrelationID: "surviving-member"}, "127.0.0.1"))
	warm, err := source.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: org, OrganizationVersion: 2, Name: "Must not survive archive", Slug: "warm-lifecycle", CorrelationID: "warm-lifecycle"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	archive := request(org, organization.Archive, "archive")
	original, err := mutate(current(pool), organization.Archive, archive)
	if err != nil || original.Receipt.Validate() != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted || original.Receipt.Feature.BeforeVersion != 2 || original.Receipt.Feature.AfterVersion != 3 {
		t.Fatal("original-key genuine archive failed", err)
	}
	assertState(org, organization.LifecycleArchived, 3, 1)
	assertProof(archive, original, true)
	assertOriginal(organization.Archive, archive, original)
	if out, err := source.Execute(ctx, warm); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("warm operation survived original-key archive", err)
	}
	if _, err := source.Get(ctx, organization.ReadRequest{Authentication: profile.member, OrganizationID: org, CorrelationID: "archived-read"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("archived member retained current rights", err)
	}
	var invitationState string
	if err := db.QueryRowContext(ctx, `SELECT state FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(owner.TenantID), string(live.id)).Scan(&invitationState); err != nil || invitationState != "cancelled" {
		t.Fatal("keyed archive did not cancel genuine issued invitation", err)
	}
	for name, change := range map[string]func(*organization.LifecycleOperationRequest){
		"reason":         func(r *organization.LifecycleOperationRequest) { r.Reason = "changed" },
		"version":        func(r *organization.LifecycleOperationRequest) { r.OrganizationVersion++ },
		"proof-id":       func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.ID += "x" },
		"proof-audience": func(r *organization.LifecycleOperationRequest) { r.Proof.Proof.Audience = "other-audience" },
		"proof-action":   func(r *organization.LifecycleOperationRequest) { r.Proof.Action = string(organization.Restore) },
		"proof-issued": func(r *organization.LifecycleOperationRequest) {
			r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(-time.Second)
		},
		"proof-expiry": func(r *organization.LifecycleOperationRequest) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.ExpiresAt.Add(time.Second)
		},
		"proof-session":         func(r *organization.LifecycleOperationRequest) { r.Proof.SessionID += "changed" },
		"proof-session-version": func(r *organization.LifecycleOperationRequest) { r.Proof.SessionVersion++ },
	} {
		t.Run("changed-"+name, func(t *testing.T) {
			changed := archive
			change(&changed)
			if _, err := mutate(current(pool), organization.Archive, changed); !errors.Is(err, organization.ErrConflict) {
				t.Fatal("same lifecycle key changed original proof/intent", err)
			}
		})
	}
	if _, err := mutate(build(pool, "organization-lifecycle-v2"), organization.Archive, archive); !errors.Is(err, organization.ErrConflict) {
		t.Fatal("changed lifecycle configuration adopted original mapping", err)
	}
	restore := request(org, organization.Restore, "restore")
	restored, err := mutate(current(pool), organization.Restore, restore)
	if err != nil || restored.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("fresh action-bound keyed restore failed", err)
	}
	assertState(org, organization.LifecycleActive, 4, 2)
	assertProof(restore, restored, true)
	assertOriginal(organization.Restore, restore, restored)
	assertOriginal(organization.Archive, archive, original)
	consumed := archive
	consumed.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("fresh-key-consumed-original-proof"))
	if err != nil {
		t.Fatal(err)
	}
	consumed.OrganizationVersion = 4
	consumedResult, consumedErr := mutate(current(pool), organization.Archive, consumed)
	if !errors.Is(consumedErr, organization.ErrForbidden) || consumedResult.Receipt.Outcome != identity.CommitOutcomeNotCommitted || consumedResult.Receipt.Binding.CommandID == "" || consumedResult.Receipt.Binding.CommandID == original.Receipt.Binding.CommandID {
		t.Fatal("fresh key reused consumed original action proof", consumedErr, consumedResult.Receipt.Outcome)
	}
	// Signed provenance can be prepared again; only the protected transaction
	// owns atomic one-use rejection. Its truthful failed-command binding is not
	// disclosure of the original operation or renewed proof authority.
	assertState(org, organization.LifecycleActive, 4, 2)
	assertProof(archive, original, true)
	assertProof(consumed, consumedResult, false)
	for _, authentication := range []organization.Authentication{profile.member, {TenantID: "foreign-tenant", Bearer: owner.Bearer}} {
		denied := archive
		denied.Authentication = authentication
		// Keep the public request syntactically valid so the foreign-tenant case
		// reaches genuine session isolation rather than the DTO's mismatch check.
		denied.Proof.Proof.Tenant = string(authentication.TenantID)
		if got, err := mutate(current(pool), organization.Archive, denied); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
			t.Fatal("foreign/nonowner actor disclosed original lifecycle history", err)
		}
	}
	if _, err := source.Get(ctx, organization.ReadRequest{Authentication: profile.member, OrganizationID: org, CorrelationID: "restored-member"}); err != nil {
		t.Fatal("restore did not revive surviving membership", err)
	}
	if _, err := source.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: org, CorrelationID: "unjoined-recipient"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("restore created recipient membership", err)
	}
	if _, err := invitations.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: live.id, OrganizationID: org, OrganizationVersion: 4, InvitationVersion: 1, Proof: live.proof, CorrelationID: "cancelled-original"}, "127.0.0.1"); err == nil {
		t.Fatal("restore revived cancelled original invitation proof")
	}
	// Real protected rollback retains native failure audit/admitted charge, but
	// no lifecycle domain transition and no password-proof consumption.
	rolledOrg := create("rollback")
	rolled := request(rolledOrg, organization.Archive, "rollback")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.keyed_lifecycle_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled lifecycle rollback'; END $$; CREATE TRIGGER keyed_lifecycle_rollback BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.keyed_lifecycle_rollback()`); err != nil {
		t.Fatal(err)
	}
	aborted, abortErr := mutate(current(pool), organization.Archive, rolled)
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER keyed_lifecycle_rollback ON public.identity_outbox_bindings; DROP FUNCTION organization.keyed_lifecycle_rollback()`); err != nil {
		t.Fatal(err)
	}
	if abortErr == nil || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("lifecycle rollback did not retain definitive noncommit", abortErr)
	}
	assertState(rolledOrg, organization.LifecycleActive, 1, 0)
	assertProof(rolled, aborted, false)
	assertEffects(aborted, false, true)
	for range 2 {
		got, err := mutate(current(pool), organization.Archive, rolled)
		if !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(got, aborted) {
			t.Fatal("rolled-back lifecycle key reexecuted or changed original result", err)
		}
		got, err = current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: aborted.Receipt.Binding})
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) || !reflect.DeepEqual(got, aborted) {
			t.Fatal("explicit rolled-back lifecycle recovery changed original failure", err)
		}
	}
	for _, mappingOnly := range []bool{true, false} {
		label := "lost-commit"
		if mappingOnly {
			label = "mapping-only"
		}
		t.Run(label, func(t *testing.T) {
			faultOrg := create(label)
			r := request(faultOrg, organization.Archive, label)
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
			if mappingOnly {
				fault.count.Store(1)
			}
			fault.armed.Store(true)
			out, err := mutate(current(primary), organization.Archive, r)
			if !fault.lost.Load() || err == nil || out.Receipt.Binding.CommandID == "" || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("actual lifecycle COMMIT loss lost original unknown", err, out.Receipt.Outcome)
			}
			for range 2 {
				got, err := mutate(current(pool), organization.Archive, r)
				var unknown identity.UnknownCommitError
				if got.Receipt.Binding != out.Receipt.Binding || mappingOnly && (!errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
					t.Fatal("lost lifecycle response retry invented another command/outcome", err)
				}
			}
			got, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: out.Receipt.Binding})
			var unknown identity.UnknownCommitError
			if got.Receipt.Binding != out.Receipt.Binding || mappingOnly && (!errors.As(err, &unknown) || got.Receipt.Outcome != identity.CommitOutcomeUnknown) || !mappingOnly && (err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted) {
				t.Fatal("explicit lifecycle COMMIT-loss recovery diverged", err)
			}
			if mappingOnly {
				assertState(faultOrg, organization.LifecycleActive, 1, 0)
				assertProof(r, out, false)
				assertEffects(out, false, false)
			} else {
				assertState(faultOrg, organization.LifecycleArchived, 2, 1)
				assertProof(r, out, true)
				assertEffects(out, true, true)
			}
		})
	}
	contended := create("contention")
	contend := request(contended, organization.Archive, "contention")
	var wg sync.WaitGroup
	type attempt struct {
		out organization.StoreResult
		err error
	}
	results := make(chan attempt, 2)
	start := make(chan struct{})
	for range 2 {
		service := current(pool)
		wg.Go(func() {
			<-start
			out, err := mutate(service, organization.Archive, contend)
			results <- attempt{out, err}
		})
	}
	close(start)
	wg.Wait()
	first, second := <-results, <-results
	// Prove an actual contender committed before the stable retry; that retry
	// must not conceal a zero-winner run by performing the first transition.
	assertState(contended, organization.LifecycleArchived, 2, 1)
	winner, err := mutate(current(pool), organization.Archive, contend)
	if err != nil || winner.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("same-key lifecycle contention did not converge on original metadata", err)
	}
	for _, candidate := range []attempt{first, second} {
		if candidate.err == nil {
			if !reflect.DeepEqual(candidate.out, winner) {
				t.Fatal("successful lifecycle contender changed original metadata")
			}
			continue
		}
		// A concurrent archive may invalidate a still-running preparation or
		// current disclosure snapshot. Denial is not a noncommit conclusion or
		// permission to renew/reexecute; a stable same-key retry above reconciles
		// only the original outcome.
		var unknown identity.UnknownCommitError
		isUnknown := errors.As(candidate.err, &unknown)
		isDenied := errors.Is(candidate.err, organization.ErrForbidden) || errors.Is(candidate.err, organization.ErrConflict)
		if !isUnknown && !isDenied || candidate.out.Receipt.Binding.CommandID != "" && candidate.out.Receipt.Binding != winner.Receipt.Binding {
			t.Fatal("lifecycle contender changed original custody or denial", candidate.err)
		}
		if isUnknown {
			if candidate.out.Receipt.Outcome != identity.CommitOutcomeUnknown || candidate.out.Receipt.Binding != winner.Receipt.Binding || candidate.out.Receipt.Feature == nil || candidate.out.Receipt.Feature.Operation != organization.Archive.Descriptor() {
				t.Fatal("unknown lifecycle contender invented an outcome", candidate.out.Receipt.Outcome)
			}
		} else if candidate.out.Receipt.Outcome != identity.CommitOutcomeInvalid || candidate.out.Receipt.Feature != nil {
			t.Fatal("denied lifecycle contender disclosed history or fabricated an outcome", candidate.err, candidate.out.Receipt.Outcome)
		}
	}
	assertState(contended, organization.LifecycleArchived, 2, 1)
	assertProof(contend, winner, true)
	assertEffects(winner, true, true)
	// Current scoped authority withdrawal denies both mapped and explicit history
	// without changing the already committed original lifecycle effect.
	scope, err := organizationpg.OrganizationAuthorityScope(owner.TenantID, contended, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.AdvanceAuthority(ctx, pool.Raw(), scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if got, err := mutate(current(pool), organization.Archive, contend); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Feature != nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted || got.Receipt.Binding.CommandID != "" && got.Receipt.Binding != winner.Receipt.Binding {
		t.Fatal("withdrawn owner scope disclosed lifecycle history", err)
	}
	if got, err := current(pool).RecoverOperation(ctx, organization.OperationRecoveryRequest{Authentication: owner, Binding: winner.Receipt.Binding}); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("withdrawn owner scope explicitly disclosed lifecycle history", err)
	}
	if allocations.Load() != 0 {
		t.Fatal("lifecycle operation allocated organization identities")
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND user_id=$2`, string(owner.TenantID), string(ownerID)); err != nil {
		t.Fatal(err)
	}
	if got, err := mutate(current(pool), organization.Archive, archive); !errors.Is(err, organization.ErrForbidden) || got.Receipt.Binding.CommandID != "" {
		t.Fatal("revoked session disclosed original lifecycle mapping", err)
	}
}
