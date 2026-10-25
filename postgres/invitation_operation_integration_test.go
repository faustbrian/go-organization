//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestOrganizationGenuineInvitationOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "operation")
}

func exerciseGenuineInvitationOperations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, organizations *organizationpg.Service, native *organizationpg.InvitationService, newNative func(*database.Pool) *organizationpg.InvitationService, nativeConfig organizationpg.InvitationServiceConfig, worker *deliverypg.Worker, mailbox *registrationMailbox, limits capability.Limits, owner, recipient organization.Authentication, recipientID identity.UserID, identifier identity.IdentifierID, keys map[string][32]byte, material func(string) []byte, signinOwner func() organization.Authentication) {
	t.Helper()
	// The coordinator supports microsecond-exact leases through one minute.
	// Select this finite profile before any original command, never by modifying
	// a live journal. Production and all retained sibling profiles stay unchanged.
	nativeConfig.Coordinator.LeaseDuration = 2 * time.Second
	newNative = func(primary *database.Pool) *organizationpg.InvitationService {
		t.Helper()
		repository, err := organizationpg.NewRepository(primary, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		service, err := organizationpg.NewInvitationService(repository, nativeConfig)
		if err != nil {
			t.Fatal(err)
		}
		return service
	}
	native = newNative(pool)
	// The public Reference fixture already installs original request custody.
	// This opt-in forward step adds only the kernel's exact typed expiry fence.
	history, err := (kernel.RequestKeyExpiryMigrationSource{Base: kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 1800}, Version: 1801}, Version: 1802}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_invitation_operation_kernel")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(history[len(history)-1:]), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("actual mapped-origin expiry migration failed", err)
	}
	baseline, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	// The retained baseline deliberately has no request-admission grant for
	// invitation send. This finite profile opts in through the real engine;
	// native owner/session/recipient/domain policy remains independent.
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-invitation-operation", Revision: 9, Evaluator: new(invitationSendAdmissionEvaluator)})
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
	ownerToken, err := session.ParseToken(owner.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	ownerCredential, err := session.NewCredential(session.CredentialBearer, ownerToken)
	if err != nil {
		t.Fatal(err)
	}
	ownerSession, err := nativeConfig.Sessions.Get(ctx, session.GetRequest{TenantID: owner.TenantID, Credential: ownerCredential})
	if err != nil {
		t.Fatal(err)
	}
	ownerBinding, err := ownerSession.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	admission := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Tenant: authorization.TenantID(owner.TenantID), Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: authorization.SubjectID(ownerBinding.UserID)}, Action: authorization.Action(organization.InvitationSend), Resource: authorization.Resource{Type: "identity.request-admission", ID: authorization.ResourceID(organization.InvitationSend)}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	if decision, err := baseline.Decide(ctx, admission); err != nil || decision.Outcome != authorization.Deny {
		t.Fatal("retained baseline unexpectedly admits keyed invitation send", err)
	}
	if decision, err := authorize.Decide(ctx, admission); err != nil || decision.Outcome != authorization.Allow || decision.Revision != 9 {
		t.Fatal("explicit keyed invitation admission profile not selected", err)
	}
	query := kernel.CommandQueryPolicy{Authorization: authorize, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("organization-invitation-operation", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("original-invitation", map[string][]byte{"original-invitation": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	var candidateBarrier func(context.Context) error
	operationConfig := organizationpg.InvitationOperationServiceConfig{ConfigurationID: "original-invitation-v1", RequestKeys: requestKeys, Custody: custody, NewInvitationID: func(ctx context.Context) (organization.ID, error) {
		allocations.Add(1)
		id, err := identity.NewSubjectID()
		if err == nil && candidateBarrier != nil {
			err = candidateBarrier(ctx)
		}
		return organization.ID(id), errors.Join(ctx.Err(), err)
	}}
	build := func(source *organizationpg.InvitationService) *organizationpg.InvitationOperationService {
		t.Helper()
		s, err := organizationpg.NewInvitationOperationService(source, operationConfig)
		if err != nil {
			t.Fatal("actual original-send composition rejected", err)
		}
		return s
	}
	key := func(name string) identity.IdempotencyKey {
		t.Helper()
		key, err := identity.NewIdempotencyKey([]byte(name))
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	create := func(slug string) organization.ID {
		t.Helper()
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		p, err := organizations.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(id), Name: "Original invitation consumer", Slug: slug, CorrelationID: "original-invitation-create"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := organizations.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine owner organization setup failed", err)
		}
		return organization.ID(id)
	}
	request := func(org organization.ID, name string) organization.InvitationSendOperationRequest {
		return organization.InvitationSendOperationRequest{Authentication: owner, IdempotencyKey: key(name), OrganizationID: org, OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifier, CorrelationID: name}
	}
	assertNoEffects := func(out organization.StoreResult) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var journals, invitations, grants, effects, deliveries, charges, audits int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$3),(SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$2 AND origin_command_id=$4),(SELECT count(*) FROM organization.command_effects WHERE command_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$2 AND command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1)`, raw, string(owner.TenantID), string(out.InvitationID), string(out.Receipt.Binding.CommandID)).Scan(&journals, &invitations, &grants, &effects, &deliveries, &charges, &audits); err != nil || journals != 0 || invitations != 0 || grants != 0 || effects != 0 || deliveries != 0 || charges != 0 || audits != 0 {
			t.Fatal("mapping-only origin created protected effects", err)
		}
	}
	// Lose acknowledgement of the real immutable mapping COMMIT, before any
	// native preparation/journal. This is not a fabricated missing-row handle.
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
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("owned invitation fault pool cleanup failed", err)
		}
	})
	mapped := request(create("original-mapping-only"), "original-mapping-only")
	faulted := build(newNative(faultPool))
	fault.count.Store(1)
	fault.armed.Store(true)
	original, err := faulted.Send(ctx, mapped, "127.0.0.1")
	var unknown identity.UnknownCommitError
	if !fault.lost.Load() || !errors.As(err, &unknown) || original.Receipt.Outcome != identity.CommitOutcomeUnknown || original.Receipt.Binding.CommandID == "" || original.InvitationID == "" || original.OrganizationID != mapped.OrganizationID {
		t.Fatal("mapping-only original did not retain explicit unknown custody", original.Receipt.Outcome, err)
	}
	assertNoEffects(original)
	restarted := build(newNative(pool))
	if out, err := restarted.Send(ctx, mapped, "127.0.0.1"); !errors.As(err, &unknown) || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding != original.Receipt.Binding || out.InvitationID != original.InvitationID || allocations.Load() != 1 {
		t.Fatal("live mapping was re-prepared or relabeled noncommit", err)
	}
	// Retain an actual native invocation for the same original IDs before expiry.
	// It must never gain authority merely because mapped recovery later refuses ID.
	delayed, err := native.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: original.Receipt.Binding.CommandID, ID: original.InvitationID, OrganizationID: mapped.OrganizationID, OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifier, CorrelationID: mapped.CorrelationID}, "127.0.0.1")
	if err != nil {
		t.Fatal("actual delayed native invitation preparation failed", err)
	}
	// The genuine session owner caps each original read admission at20s. Wait
	// past both retained preparations; the kernel still proves expiry by DB clock.
	timer := time.NewTimer(21 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	owner = signinOwner()
	mapped.Authentication = owner
	expired, err := build(newNative(pool)).Send(ctx, mapped, "127.0.0.1")
	if err != nil || expired.Receipt.Outcome != identity.CommitOutcomeNotCommitted || expired.Receipt.Binding != original.Receipt.Binding || expired.InvitationID != original.InvitationID || allocations.Load() != 1 {
		t.Fatal("expired actual mapped origin lacks definitive original noncommit", expired.Receipt.Outcome, err)
	}
	if out, err := native.Execute(ctx, delayed); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("delayed native invocation escaped original admission expiry", err)
	}
	assertNoEffects(original)
	rawOriginal, _ := base64.RawURLEncoding.DecodeString(string(original.Receipt.Binding.CommandID))
	var retired, private bool
	if err := db.QueryRowContext(ctx, `SELECT retired,tenant_id IS NULL AND purpose IS NULL AND fingerprint IS NULL AND safe_fields IS NULL AND octet_length(request_key_expiry_fingerprint)=32 FROM identity.identity_command_id_claims WHERE command_id=$1`, rawOriginal).Scan(&retired, &private); err != nil || !retired || !private {
		t.Fatal("actual original noncommit lacks irreversible privacy-safe global fence", err)
	}
	if out, err := native.Recover(ctx, owner, organizationpg.InvitationRecovery{Binding: original.Receipt.Binding, OrganizationID: mapped.OrganizationID}); err == nil || out.Receipt.Binding.CommandID != "" {
		t.Fatal("generic original recovery disclosed typed refusal", err)
	}
	if out, err := build(newNative(pool)).Send(ctx, mapped, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, expired) || allocations.Load() != 1 {
		t.Fatal("restarted refusal changed original custody", err)
	}
	// Fresh key: genuine verified recipient -> actual encrypted delivery -> exact
	// existing native acceptance -> current member read, without an HTTP adapter.
	r := request(create("original-send-journey"), "original-send-journey")
	r.Authentication = owner
	sent, err := restarted.Send(ctx, r, "127.0.0.1")
	if err != nil || sent.Receipt.Outcome != identity.CommitOutcomeCommitted || sent.InvitationID == "" {
		t.Fatal("actual keyed invitation send failed", sent.Receipt.Outcome, err)
	}
	r.CorrelationID = "different-retry-correlation"
	for range 2 {
		if out, err := build(newNative(pool)).Send(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, sent) {
			t.Fatal("restarted retry changed original send or redelivered proof", err)
		}
	}
	for _, alter := range []func(*organization.InvitationSendOperationRequest){func(r *organization.InvitationSendOperationRequest) { r.OrganizationVersion++ }, func(r *organization.InvitationSendOperationRequest) { r.OrganizationID = mapped.OrganizationID }, func(r *organization.InvitationSendOperationRequest) {
		r.RecipientUserID = identity.UserID(sent.Receipt.Binding.ActorID)
	}, func(r *organization.InvitationSendOperationRequest) { r.RecipientIdentifierID = "different-identifier" }} {
		changed := r
		alter(&changed)
		if out, err := restarted.Send(ctx, changed, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Binding.CommandID != "" {
			t.Fatal("changed original intent retained original key/custody", err)
		}
	}
	for _, alter := range []func(*organizationpg.InvitationServiceConfig){func(c *organizationpg.InvitationServiceConfig) { c.Invitation.Lifetime = 24 * time.Hour }, func(c *organizationpg.InvitationServiceConfig) { c.Delivery.Endpoint += "-replacement" }} {
		c := nativeConfig
		alter(&c)
		repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		source, err := organizationpg.NewInvitationService(repository, c)
		if err != nil {
			t.Fatal("valid changed send profile rejected by native constructor", err)
		}
		if out, err := build(source).Send(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrConflict) || out.Receipt.Binding.CommandID != "" {
			t.Fatal("changed immutable expiry/delivery profile adopted original key", err)
		}
	}
	if result, err := worker.ProcessOne(ctx); err != nil || !result.Claimed {
		t.Fatal("actual encrypted invitation delivery not processed", err)
	}
	mailbox.mu.Lock()
	link := mailbox.body
	mailbox.body = ""
	mailbox.mu.Unlock()
	u, err := url.Parse(link)
	if err != nil || u.Query().Get("token") == "" {
		t.Fatal("captured actual invitation proof absent")
	}
	proof, err := capability.ParseProof(u.Query().Get("token"), limits)
	if err != nil {
		t.Fatal("captured actual proof invalid")
	}
	encoded, err := json.Marshal(sent)
	if err != nil || strings.Contains(string(encoded), u.Query().Get("token")) || strings.Contains(string(encoded), owner.Bearer.Token()) {
		t.Fatal("safe original send result disclosed proof/session custody")
	}
	var recipientAddress string
	if err := db.QueryRowContext(ctx, `SELECT canonical_value FROM identity.identifiers WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(owner.TenantID), string(recipientID), string(identifier)).Scan(&recipientAddress); err != nil {
		t.Fatal(err)
	}
	var safeFields, ciphertext []byte
	rawSent, _ := base64.RawURLEncoding.DecodeString(string(sent.Receipt.Binding.CommandID))
	if err := db.QueryRowContext(ctx, `SELECT safe_fields,request_preparation_ciphertext FROM identity.request_key_mappings WHERE command_id=$1`, rawSent).Scan(&safeFields, &ciphertext); err != nil || len(ciphertext) == 0 {
		t.Fatal("original mapping lost encrypted native custody", err)
	}
	for _, field := range [][]byte{encoded, safeFields, ciphertext} {
		for _, private := range []string{recipientAddress, owner.Bearer.Token(), u.Query().Get("token")} {
			if strings.Contains(string(field), private) {
				t.Fatal("native metadata/custody storage exposed address or credential plaintext")
			}
		}
	}
	p, err := native.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), OrganizationID: r.OrganizationID, ID: sent.InvitationID, OrganizationVersion: 1, InvitationVersion: 1, Proof: proof, CorrelationID: "original-send-accept"}, "127.0.0.1")
	if err != nil {
		t.Fatal("existing exact native acceptance rejected", err)
	}
	accepted, err := native.Execute(ctx, p)
	if err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("existing exact native acceptance failed", err)
	}
	acceptedID, _ := base64.RawURLEncoding.DecodeString(string(accepted.Receipt.Binding.CommandID))
	var paired, invitationEvent, membershipEvent int
	if err := db.QueryRowContext(ctx, `SELECT count(*),count(*) FILTER(WHERE m.topic='invitation.accepted.v1'),count(*) FILTER(WHERE m.topic='membership.created.v1') FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$1`, acceptedID).Scan(&paired, &invitationEvent, &membershipEvent); err != nil || paired != 2 || invitationEvent != 1 || membershipEvent != 1 {
		t.Fatal("existing acceptance lost atomic paired lifecycle", err)
	}
	if v, err := organizations.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: r.OrganizationID, CorrelationID: "original-send-member-read"}); err != nil || !v.Actor.Active || v.Actor.UserID != recipientID {
		t.Fatal("genuine accepted recipient cannot read membership", err)
	}
	if result, err := worker.ProcessOne(ctx); err != nil || result.Claimed {
		t.Fatal("keyed retries/recovery redelivered invitation proof", err)
	}
	if out, err := build(newNative(pool)).Send(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, sent) {
		t.Fatal("accepted member epoch replaced original send history", err)
	}
	assertSend := func(stage string, out organization.StoreResult, committed bool) {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var invitations, grants, effects, events, audits, charges int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$3),(SELECT count(*) FROM organization.command_effects WHERE command_id=$3),(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$4 AND m.topic='invitation.created.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.command_id=$4 AND a.action='identity.organization.create_invitation'),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$4)`, string(owner.TenantID), string(out.InvitationID), string(out.Receipt.Binding.CommandID), raw).Scan(&invitations, &grants, &effects, &events, &audits, &charges); err != nil {
			t.Fatal(err)
		}
		want := 0
		if committed {
			want = 1
		}
		// Kernel Abort/recovery terminalization retains the original protected
		// attempt and canonical failure audit even when all domain work rolls back.
		// Only successful domain/capability/lifecycle effects must be absent.
		if invitations != want || grants != want || effects != want || events != want || audits != 1 || charges != 1 {
			t.Fatalf("native send cardinality at %s: committed=%t want-effects=%d invitations=%d grants=%d effects=%d events=%d audits=%d charges=%d", stage, committed, want, invitations, grants, effects, events, audits, charges)
		}
		outcome, reason := audit.OutcomeFailed, "provider_unavailable"
		if committed {
			outcome, reason = audit.OutcomeSucceeded, "completed"
		}
		var exactAudit int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records a ON a.record_id=b.event_id WHERE b.command_id=$1 AND a.action='identity.organization.create_invitation' AND a.tenant_id=$2 AND a.actor_id=$3 AND a.subject_type='invitation' AND a.subject_id=$4 AND a.correlation_id=$5 AND a.outcome=$6 AND convert_from(a.canonical_record,'UTF8')::jsonb->>'reason_code'=$7`, raw, string(out.Receipt.Binding.TenantID), string(out.Receipt.Binding.ActorID), string(out.InvitationID), out.Receipt.Binding.CorrelationID, outcome, reason).Scan(&exactAudit); err != nil || exactAudit != 1 {
			t.Fatalf("native send audit lost original identity/outcome at %s: matched=%d error=%v", stage, exactAudit, err)
		}
	}
	assertSend("genuine-journey", sent, true)
	// Two actual missing-key candidates may allocate discarded IDs. Only the
	// acknowledged winner can generate/charge/apply, and both observe its IDs.
	contending := request(create("original-send-contention"), "original-send-contention")
	ready, release := make(chan struct{}, 2), make(chan struct{})
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	candidateBarrier = func(ctx context.Context) error {
		select {
		case ready <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	type sendResult struct {
		out organization.StoreResult
		err error
	}
	results := make(chan sendResult, 2)
	var callers sync.WaitGroup
	callers.Add(2)
	t.Cleanup(func() { unblock(); callers.Wait() })
	concurrent := build(newNative(pool))
	before := allocations.Load()
	for range 2 {
		go func() {
			defer callers.Done()
			out, err := concurrent.Send(ctx, contending, "127.0.0.1")
			results <- sendResult{out, err}
		}()
	}
	for range 2 {
		select {
		case <-ready:
		case failed := <-results:
			t.Fatal("actual missing-key contender did not reach bounded read-only candidate", failed.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	unblock()
	a, b := <-results, <-results
	callers.Wait()
	candidateBarrier = nil
	winner, err := build(newNative(pool)).Send(ctx, contending, "127.0.0.1")
	if err != nil || winner.Receipt.Outcome != identity.CommitOutcomeCommitted || allocations.Load() != before+2 {
		t.Fatal("actual contenders did not converge on original send", err)
	}
	for _, attempt := range []sendResult{a, b} {
		if attempt.out.Receipt.Binding != winner.Receipt.Binding || attempt.out.InvitationID != winner.InvitationID || attempt.err == nil && attempt.out.Receipt.Outcome == identity.CommitOutcomeCommitted && !reflect.DeepEqual(attempt.out, winner) {
			t.Fatal("concurrent key selected different original custody", attempt.err)
		}
	}
	assertSend("contention", winner, true)
	// Fail the real protected lifecycle write after capability/delivery staging.
	rolled := request(create("original-send-rollback"), "original-send-rollback")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.invitation_operation_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled original invitation rollback'; END $$; CREATE TRIGGER invitation_operation_rollback BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.invitation_operation_rollback()`); err != nil {
		t.Fatal(err)
	}
	aborted, abortErr := build(newNative(pool)).Send(ctx, rolled, "127.0.0.1")
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER invitation_operation_rollback ON public.identity_outbox_bindings; DROP FUNCTION organization.invitation_operation_rollback()`); err != nil {
		t.Fatal(err)
	}
	if abortErr == nil || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("actual original send rollback lacks definitive noncommit", aborted.Receipt.Outcome, abortErr)
	}
	assertSend("protected-write-rollback", aborted, false)
	if out, err := build(newNative(pool)).Send(ctx, rolled, "127.0.0.1"); !errors.Is(err, organization.ErrUnavailable) || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted || out.Receipt.Binding != aborted.Receipt.Binding {
		t.Fatal("known rollback key rebuilt send execution", err)
	}
	assertSend("protected-write-rollback-replay", aborted, false)
	// Work deliberately uses PgConn.ExecParams, bypassing pgx QueryTracer. A
	// test-owned AFTER INSERT notice marks the actual native domain write and
	// arms the existing protocol fault for its next successful COMMIT only.
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.invitation_operation_commit_notice() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE NOTICE 'controlled original invitation commit armed'; RETURN NEW; END $$; CREATE TRIGGER invitation_operation_commit_notice AFTER INSERT ON organization.invitations FOR EACH ROW EXECUTE FUNCTION organization.invitation_operation_commit_notice()`); err != nil {
		t.Fatal(err)
	}
	fault.lost.Store(false)
	fault.armed.Store(false)
	fault.count.Store(0)
	commitPool, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.OnNotice = func(_ *pgconn.PgConn, notice *pgconn.Notice) {
			if notice.Message == "controlled original invitation commit armed" {
				fault.count.Store(1)
				fault.armed.Store(true)
			}
		}
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
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := commitPool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	lost := request(create("original-send-commit-loss"), "original-send-commit-loss")
	unknownSend, err := build(newNative(commitPool)).Send(ctx, lost, "127.0.0.1")
	if _, cleanupErr := pool.Raw().Exec(ctx, `DROP TRIGGER invitation_operation_commit_notice ON organization.invitations; DROP FUNCTION organization.invitation_operation_commit_notice()`); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if !fault.lost.Load() || !errors.As(err, &unknown) || unknownSend.Receipt.Outcome != identity.CommitOutcomeUnknown {
		t.Fatal("actual send COMMIT acknowledgement loss was not original Unknown", err)
	}
	reconciled, err := build(newNative(pool)).Send(ctx, lost, "127.0.0.1")
	if err != nil || reconciled.Receipt.Outcome != identity.CommitOutcomeCommitted || reconciled.Receipt.Binding != unknownSend.Receipt.Binding {
		t.Fatal("restarted keyed send did not reconcile actual committed native send", err)
	}
	assertSend("commit-acknowledgement-loss", reconciled, true)
	// A genuine deferred native constraint fails at COMMIT, not before mapping
	// or output preparation. Reconciliation remains solely with the kernel.
	beforeCommit := request(create("original-send-commit-rollback"), "original-send-commit-rollback")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.invitation_operation_commit_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled original invitation COMMIT rollback'; END $$; CREATE CONSTRAINT TRIGGER invitation_operation_commit_rollback AFTER INSERT ON organization.invitations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION organization.invitation_operation_commit_rollback()`); err != nil {
		t.Fatal(err)
	}
	commitAborted, commitErr := build(newNative(pool)).Send(ctx, beforeCommit, "127.0.0.1")
	if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER invitation_operation_commit_rollback ON organization.invitations; DROP FUNCTION organization.invitation_operation_commit_rollback()`); err != nil {
		t.Fatal(err)
	}
	if commitErr == nil || commitAborted.Receipt.Outcome == identity.CommitOutcomeCommitted || commitAborted.Receipt.Binding.CommandID == "" {
		t.Fatal("failed actual COMMIT was misreported", commitErr)
	}
	rawCommit, _ := base64.RawURLEncoding.DecodeString(string(commitAborted.Receipt.Binding.CommandID))
	for {
		var expired bool
		var until, now time.Time
		if err := db.QueryRowContext(ctx, `SELECT lease_until<=clock_timestamp(),lease_until,clock_timestamp() FROM identity.commands WHERE command_id=$1 AND state='pending'`, rawCommit).Scan(&expired, &until, &now); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		wait := time.NewTimer(until.Sub(now) + time.Millisecond)
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			t.Fatal(ctx.Err())
		}
	}
	noncommit, err := build(newNative(pool)).Send(ctx, beforeCommit, "127.0.0.1")
	if !errors.Is(err, organization.ErrUnavailable) || noncommit.Receipt.Outcome != identity.CommitOutcomeNotCommitted || noncommit.Receipt.Binding != commitAborted.Receipt.Binding {
		var state, generation string
		var live, attached bool
		var profile int
		if diagnosticErr := db.QueryRowContext(ctx, `SELECT state,generation::text,lease_until>clock_timestamp(),command_plan IS NOT NULL,coalesce(preparation_profile,0) FROM identity.commands WHERE command_id=$1`, rawCommit).Scan(&state, &generation, &live, &attached, &profile); diagnosticErr != nil {
			t.Fatal("COMMIT rollback safe diagnostic failed", diagnosticErr)
		}
		nativeResult, nativeErr := newNative(pool).Recover(ctx, owner, organizationpg.InvitationRecovery{Binding: commitAborted.Receipt.Binding, OrganizationID: beforeCommit.OrganizationID})
		t.Fatalf("COMMIT rollback outcome=%d retry=%s error=%v native-outcome=%d native-error=%v state=%s generation=%s live=%t attached=%t preparation-profile=%d", noncommit.Receipt.Outcome, noncommit.Receipt.RetryAfter, err, nativeResult.Receipt.Outcome, nativeErr, state, generation, live, attached, profile)
	}
	assertSend("commit-rollback", noncommit, false)
	// Current disclosure authority is required even for known committed history.
	foreign := r
	foreign.Authentication = recipient
	if out, err := restarted.Send(ctx, foreign, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" {
		t.Fatal("foreign actor obtained original key history", err)
	}
	foreign = r
	foreign.Authentication.TenantID = "foreign-tenant"
	if out, err := restarted.Send(ctx, foreign, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" {
		t.Fatal("foreign tenant obtained original key history", err)
	}
	token, err := session.ParseToken(owner.Bearer.Token())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := nativeConfig.Sessions.Get(ctx, session.GetRequest{TenantID: owner.TenantID, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := current.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(owner.TenantID), bound.SessionID); err != nil {
		t.Fatal(err)
	}
	if out, err := restarted.Send(ctx, r, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" {
		t.Fatal("revoked genuine owner session disclosed original send", err)
	}
	owner = signinOwner()
	r.Authentication = owner
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(owner.TenantID), string(recipientID), string(identifier)); err != nil {
		t.Fatal(err)
	}
	denied, deniedErr := build(newNative(pool)).Send(ctx, r, "127.0.0.1")
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(owner.TenantID), string(recipientID), string(identifier)); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(deniedErr, organization.ErrForbidden) || denied.Receipt.Binding.CommandID != "" {
		t.Fatal("replaced verified identifier disclosed original send", deniedErr)
	}
	// A current query callback can advance organization authority after its
	// first native read. Use the real metadata owner, not a forged stale snapshot;
	// final native revalidation must withhold the original receipt on that call.
	latePolicy := &invitationCancellationPolicy{base: baseline}
	lateConfig := nativeConfig
	lateQuery := *nativeConfig.Coordinator.QueryPolicy
	lateQuery.Authorization = latePolicy
	lateConfig.Coordinator.QueryPolicy = &lateQuery
	lateRepository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	lateSource, err := organizationpg.NewInvitationService(lateRepository, lateConfig)
	if err != nil {
		t.Fatal(err)
	}
	lateService := build(lateSource)
	late := request(create("original-send-late-policy"), "original-send-late-policy")
	lateSent, err := lateService.Send(ctx, late, "127.0.0.1")
	if err != nil || lateSent.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("late query authority setup failed", err)
	}
	var advanced atomic.Bool
	latePolicy.before = func(ctx context.Context, d authorization.DecisionContext) error {
		if d.Request.Action != authorization.Action(organization.InvitationSend) || d.Request.Resource.Type != "identity.user" || !advanced.CompareAndSwap(false, true) {
			return nil
		}
		update, err := organizations.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: late.OrganizationID, OrganizationVersion: 1, Name: "Current policy successor", Slug: "original-send-late-successor", CorrelationID: "original-send-policy-successor"}, "127.0.0.1")
		if err != nil {
			return err
		}
		out, err := organizations.Execute(ctx, update)
		if err == nil && out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			return organization.ErrUnavailable
		}
		return err
	}
	if out, err := lateService.Send(ctx, late, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) || out.Receipt.Binding.CommandID != "" || !advanced.Load() {
		t.Fatal("late current organization authority change disclosed stale original receipt", err)
	}
	latePolicy.before = nil
	if out, err := lateService.Send(ctx, late, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, lateSent) {
		t.Fatal("fresh current disclosure did not retain original send after policy epoch advancement", err)
	}
	assertSend("late-authority", lateSent, true)
	// Change only the recipient identifier inside the real query callback: owner
	// and organization epochs remain unchanged, so the recipient final fence is
	// the boundary that must withhold historical metadata.
	var recipientChanged atomic.Bool
	var originalIdentifierVersion string
	latePolicy.before = func(ctx context.Context, d authorization.DecisionContext) error {
		if d.Request.Action != authorization.Action(organization.InvitationSend) || d.Request.Resource.Type != "identity.user" || !recipientChanged.CompareAndSwap(false, true) {
			return nil
		}
		return pool.Raw().QueryRow(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 RETURNING (version-1)::text`, string(owner.TenantID), string(recipientID), string(identifier)).Scan(&originalIdentifierVersion)
	}
	lateRecipient, lateRecipientErr := lateService.Send(ctx, late, "127.0.0.1")
	latePolicy.before = nil
	if originalIdentifierVersion != "" {
		tag, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=$4::numeric WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4::numeric+1`, string(owner.TenantID), string(recipientID), string(identifier), originalIdentifierVersion)
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("late recipient original version was not restored exactly", err)
		}
	}
	if !recipientChanged.Load() || originalIdentifierVersion == "" || !errors.Is(lateRecipientErr, organization.ErrForbidden) || lateRecipient != (organization.StoreResult{}) {
		t.Fatal("late recipient withdrawal disclosed original send metadata", lateRecipientErr)
	}
	if out, err := lateService.Send(ctx, late, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, lateSent) {
		t.Fatal("restored current recipient did not retain unchanged original send", err)
	}
	assertSend("late-recipient", lateSent, true)
}

type invitationSendAdmissionEvaluator struct{}

func (*invitationSendAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if ctx.Err() != nil {
		return authorization.Decision{}, ctx.Err()
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.InvitationSend) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.InvitationSend) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}
