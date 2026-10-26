//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineInvitationResendOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "resend-operation")
}

// Retain the public interface assertion so the same real consumer can prove the
// missing boundary against the previously published native module.
type invitationResendOperationPort interface {
	Resend(context.Context, organization.InvitationResendOperationRequest, string) (organization.InvitationResendOperationResult, error)
}

func exerciseInvitationResendOperations(t *testing.T, f invitationResendConsumer, db *sql.DB, keys map[string][32]byte, material func(string) []byte) {
	t.Helper()
	ctx, pool := f.ctx, f.pool
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
		t.Fatal("mapped resend expiry migration", err)
	}
	snapshot, err := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-resend-operation", Revision: 9, Evaluator: new(invitationResendAdmissionEvaluator)})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("organization-resend-operation", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	custody, err := organizationpg.NewOperationCustodyConfig("original-resend", map[string][]byte{"original-resend": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	var allocations atomic.Int32
	config := organizationpg.InvitationOperationServiceConfig{ConfigurationID: "original-resend-v1", RequestKeys: requestKeys, Custody: custody, NewInvitationID: func(context.Context) (organization.ID, error) {
		allocations.Add(1)
		return "", errors.New("resend must retain the existing invitation identity")
	}}
	build := func(source *organizationpg.InvitationService, configuration string) invitationResendOperationPort {
		t.Helper()
		c := config
		c.ConfigurationID = configuration
		owner, err := organizationpg.NewInvitationOperationService(source, c)
		if err != nil {
			t.Fatal("actual keyed resend composition", err)
		}
		port, ok := any(owner).(invitationResendOperationPort)
		if !ok {
			t.Fatal("native original-key resend operation is missing")
		}
		return port
	}
	service := build(f.service, config.ConfigurationID)
	request := func(inv issued, key string) organization.InvitationResendOperationRequest {
		t.Helper()
		original, err := identity.NewIdempotencyKey([]byte(key))
		if err != nil {
			t.Fatal(err)
		}
		return organization.InvitationResendOperationRequest{Authentication: f.owner, IdempotencyKey: original, OrganizationID: inv.org, InvitationID: inv.id, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "original-resend"}
	}
	read := func(inv issued) organization.InvitationDelivery {
		t.Helper()
		out, err := f.service.Get(ctx, organization.InvitationReadRequest{Authentication: f.owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "resend-current"})
		if err != nil {
			t.Fatal("current owner invitation", err)
		}
		return out
	}
	proof := func() capability.Proof {
		t.Helper()
		if _, err := f.worker.ProcessOne(ctx); err != nil {
			t.Fatal("successor encrypted delivery", err)
		}
		f.mailbox.mu.Lock()
		body := f.mailbox.body
		f.mailbox.body = ""
		f.mailbox.mu.Unlock()
		link, err := url.Parse(body)
		if err != nil || link.Query().Get("token") == "" {
			t.Fatal("successor proof not delivered")
		}
		p, err := capability.ParseProof(link.Query().Get("token"), f.limits)
		if err != nil {
			t.Fatal("delivered successor proof invalid")
		}
		return p
	}
	accept := func(inv issued, version, orgVersion uint64) (organization.StoreResult, error) {
		p, err := f.service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: orgVersion, InvitationVersion: version, Proof: inv.proof, CorrelationID: "resend-accept"}, "127.0.0.1")
		if err != nil {
			return organization.StoreResult{}, err
		}
		return f.service.Execute(ctx, p)
	}
	effects := func(out organization.InvitationResendOperationResult, count int) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
		if err != nil || len(id) == 0 {
			t.Fatal("original command correlation unavailable")
		}
		var mutations, grants, events, audits, deliveries int
		err = pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),
 (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.resent.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.resend_invitation' AND r.outcome=1),
 (SELECT count(*) FROM organization.command_effects e JOIN identity.delivery_intents d ON d.effect_id=e.delivery_effect_id AND d.tenant_id=e.tenant_id WHERE e.command_id=$1)`, string(out.Receipt.Binding.CommandID), id).Scan(&mutations, &grants, &events, &audits, &deliveries)
		if err != nil || mutations != count || grants != count || events != count || audits != count || deliveries != count {
			t.Fatal("keyed resend atomic conservation", mutations, grants, events, audits, deliveries, err)
		}
	}
	t.Run("original key rotates once and recovers original delivery", func(t *testing.T) {
		inv := f.populated
		before := read(inv)
		r := request(inv, "resend-original")
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.DeliveryState != delivery.StateQueued || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("original keyed successor not committed", err)
		}
		effects(out, 1)
		signs := f.signer.calls.Load()
		after := read(inv)
		if after.Invitation.Version != 2 || after.Invitation.IssuedVersion != 2 || after.Invitation.RecipientUserID != before.Invitation.RecipientUserID || after.Invitation.RecipientIdentifierID != before.Invitation.RecipientIdentifierID || after.Invitation.Role != before.Invitation.Role || !after.Invitation.ExpiresAt.Equal(before.Invitation.ExpiresAt) {
			t.Fatal("resend changed original target, role or exclusive deadline")
		}
		if old, err := accept(inv, 2, 1); err == nil || old.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("predecessor proof survived rotation")
		}
		r.CorrelationID = "retry-diagnostic-only"
		retry, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(out, retry) || f.signer.calls.Load() != signs {
			t.Fatal("reconstructed retry changed original successor", err)
		}
		inv.proof = proof()
		// After provider acceptance the first command's original state must not
		// be replaced by the latest successor's freshly queued delivery.
		next := request(inv, "resend-successor")
		next.InvitationVersion = 2
		second, err := service.Resend(ctx, next, "127.0.0.1")
		if err != nil || second.Receipt.Outcome != identity.CommitOutcomeCommitted || second.Receipt.Binding.CommandID == out.Receipt.Binding.CommandID {
			t.Fatal("second original not independent", err)
		}
		signs = f.signer.calls.Load()
		original, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err != nil || original.Receipt.Binding != out.Receipt.Binding || original.DeliveryState != delivery.StateAccepted || f.signer.calls.Load() != signs {
			t.Fatal("retry lost original delivery observation", err)
		}
		inv.proof = proof()
		accepted, err := accept(inv, 3, 1)
		if err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("successor recipient acceptance failed", err)
		}
		if replay, err := accept(inv, 3, 1); err == nil || replay.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("successor accepted twice")
		}
		signs = f.signer.calls.Load()
		acceptedOriginal, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err != nil || acceptedOriginal.Receipt.Binding != out.Receipt.Binding || acceptedOriginal.Receipt.Feature == nil || *acceptedOriginal.Receipt.Feature != *out.Receipt.Feature || acceptedOriginal.DeliveryState != delivery.StateAccepted || f.signer.calls.Load() != signs {
			t.Fatal("acceptance replaced or reexecuted original keyed resend", err)
		}
		effects(out, 1)
		effects(second, 1)
	})
	t.Run("changed intent and deployment cannot reuse original key", func(t *testing.T) {
		inv := f.issue("keyed-resend-intent")
		r := request(inv, "resend-intent")
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		signs := f.signer.calls.Load()
		for _, change := range []func(*organization.InvitationResendOperationRequest){func(r *organization.InvitationResendOperationRequest) { r.InvitationVersion++ }, func(r *organization.InvitationResendOperationRequest) { r.OrganizationVersion++ }, func(r *organization.InvitationResendOperationRequest) { r.InvitationID = "foreign" }, func(r *organization.InvitationResendOperationRequest) { r.OrganizationID = "foreign" }} {
			bad := r
			change(&bad)
			if result, err := service.Resend(ctx, bad, "127.0.0.1"); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("changed original resend intent admitted")
			}
		}
		if result, err := build(f.newService(pool), "different-profile").Resend(ctx, r, "127.0.0.1"); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed deployment replay admitted")
		}
		if f.signer.calls.Load() != signs {
			t.Fatal("rejected retry issued another proof")
		}
		effects(out, 1)
		_ = proof()
	})
	t.Run("known commit survives unavailable delivery observation", func(t *testing.T) {
		inv := f.issue("keyed-resend-status")
		r := request(inv, "resend-status")
		f.statusPolicy.before = func(_ context.Context, d authorization.DecisionContext) error {
			if d.Request.Action == "identity.delivery.status-get" {
				return organization.ErrUnavailable
			}
			return nil
		}
		defer func() { f.statusPolicy.before = nil }()
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err == nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.DeliveryState != 0 {
			t.Fatal("status failure erased commitment or invented delivery")
		}
		signs := f.signer.calls.Load()
		retry, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err == nil || retry.Receipt.Binding != out.Receipt.Binding || retry.Receipt.Outcome != identity.CommitOutcomeCommitted || retry.DeliveryState != 0 || f.signer.calls.Load() != signs {
			t.Fatal("failed original status lookup redispatched or erased commitment")
		}
		f.statusPolicy.before = nil
		if recovered, err := service.Resend(ctx, r, "127.0.0.1"); err != nil || recovered.DeliveryState != delivery.StateQueued {
			t.Fatal("original status recovery failed", err)
		}
		effects(out, 1)
		_ = proof()
	})
	t.Run("late recipient withdrawal preserves commitment without delivery disclosure", func(t *testing.T) {
		for _, stage := range []string{"initial", "retry"} {
			t.Run(stage, func(t *testing.T) {
				inv := f.issue("keyed-resend-late-" + stage)
				r := request(inv, "resend-late-"+stage)
				var original organization.InvitationResendOperationResult
				if stage == "retry" {
					var err error
					original, err = service.Resend(ctx, r, "127.0.0.1")
					if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("late retry setup", err)
					}
				}
				changed := false
				f.statusPolicy.before = func(ctx context.Context, d authorization.DecisionContext) error {
					if changed || d.Request.Action != "identity.delivery.status-get" {
						return nil
					}
					_, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID))
					changed = err == nil
					return err
				}
				defer func() { f.statusPolicy.before = nil }()
				out, failure := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
				f.statusPolicy.before = nil
				if changed {
					if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID)); err != nil {
						t.Fatal("late recipient fixture restore", err)
					}
				}
				if !changed || failure == nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.DeliveryState != 0 {
					t.Fatal("late recipient withdrawal disclosed delivery or erased known commitment", failure)
				}
				if stage == "retry" && out.Receipt.Binding != original.Receipt.Binding {
					t.Fatal("late denial lost original correlation")
				}
				effects(out, 1)
				inv.proof = proof()
				if accepted, err := accept(inv, 2, 1); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("late projection denial revoked committed successor", err)
				}
			})
		}
	})
	t.Run("read only maximum organization epoch still resends", func(t *testing.T) {
		inv := f.issue("keyed-resend-org-max")
		if _, err := pool.Raw().Exec(ctx, `UPDATE organization.organizations SET version=18446744073709551615 WHERE tenant_id=$1 AND organization_id=$2`, string(baselineTenant), string(inv.org)); err != nil {
			t.Fatal(err)
		}
		r := request(inv, "resend-org-max")
		r.OrganizationVersion = ^uint64(0)
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("read-only maximum organization epoch rejected resend", err)
		}
		if got := read(inv); got.Invitation.Version != 2 {
			t.Fatal("maximum-epoch resend lost successor")
		}
		var epoch string
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(baselineTenant), string(inv.org)).Scan(&epoch); err != nil || epoch != strconv.FormatUint(^uint64(0), 10) {
			t.Fatal("resend incremented read-only organization epoch", err)
		}
		inv.proof = proof()
		if result, err := accept(inv, 2, ^uint64(0)); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("acceptance overflow protection was relaxed")
		}
		effects(out, 1)
	})
	t.Run("administrator retains original recovery but removal denies it", func(t *testing.T) {
		inv := f.issue("keyed-resend-admin")
		admin := f.administrator
		add, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: admin.id, Role: organization.RoleAdministrator, CorrelationID: "resend-add-admin"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := f.organizations.Execute(ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("administrator admission", err)
		}
		r := request(inv, "resend-admin")
		r.Authentication, r.OrganizationVersion = admin.authentication, 2
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.DeliveryState != delivery.StateQueued {
			t.Fatal("administrator keyed resend", err)
		}
		if _, err := f.service.Get(ctx, organization.InvitationReadRequest{Authentication: admin.authentication, OrganizationID: inv.org, ID: inv.id, CorrelationID: "admin-metadata-denial"}); err == nil {
			t.Fatal("resend widened owner-only metadata")
		}
		r.Authentication = admin.signin()
		if retry, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(retry, out) {
			t.Fatal("administrator original recovery incorrectly owner-only", err)
		}
		remove, err := f.organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: admin.id, MemberVersion: 1, CorrelationID: "resend-remove-admin"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.organizations.Execute(ctx, remove); err != nil {
			t.Fatal(err)
		}
		if retry, err := service.Resend(ctx, r, "127.0.0.1"); err == nil || retry != (organization.InvitationResendOperationResult{}) {
			t.Fatal("removed administrator disclosed original resend")
		}
		effects(out, 1)
		inv.proof = proof()
		if accepted, err := accept(inv, 2, 3); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("management withdrawal revoked recipient successor", err)
		}
	})
	t.Run("recipient withdrawal and expired grant never renew", func(t *testing.T) {
		inv := f.issue("keyed-resend-recipient")
		r := request(inv, "resend-recipient")
		out, err := service.Resend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		signs := f.signer.calls.Load()
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		retry, failure := service.Resend(ctx, r, "127.0.0.1")
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		if failure == nil || retry != (organization.InvitationResendOperationResult{}) || f.signer.calls.Load() != signs {
			t.Fatal("changed recipient identifier recovered original grant")
		}
		effects(out, 1)
		_ = proof()
		expired := f.issue("keyed-resend-expired")
		if _, err := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(expired.id)); err != nil {
			t.Fatal(err)
		}
		signs = f.signer.calls.Load()
		if result, err := service.Resend(ctx, request(expired, "resend-expired"), "127.0.0.1"); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted || f.signer.calls.Load() != signs {
			t.Fatal("expired invitation gained a successor")
		}
	})
	t.Run("rollback retains predecessor and cannot redispatch original", func(t *testing.T) {
		inv := f.issue("keyed-resend-rollback")
		r := request(inv, "resend-rollback")
		if _, err := pool.Raw().Exec(ctx, `ALTER TABLE organization.command_effects ADD CONSTRAINT resend_operation_failure_fixture CHECK(operation<>'identity.organization.invitation.resend') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		out, failure := service.Resend(ctx, r, "127.0.0.1")
		if _, err := pool.Raw().Exec(ctx, `ALTER TABLE organization.command_effects DROP CONSTRAINT resend_operation_failure_fixture`); err != nil {
			t.Fatal(err)
		}
		if failure == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted || out.DeliveryState != 0 {
			t.Fatal("rollback fabricated committed delivery")
		}
		signs := f.signer.calls.Load()
		retry, _ := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if retry.Receipt.Outcome == identity.CommitOutcomeCommitted || retry.DeliveryState != 0 || f.signer.calls.Load() != signs {
			t.Fatal("rolled-back original was reexecuted")
		}
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.resend'`, string(inv.id)).Scan(&n); err != nil || n != 0 {
			t.Fatal("rollback retained resend effects", err)
		}
		if accepted, err := accept(inv, 1, 1); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("rollback consumed predecessor proof", err)
		}
	})
	t.Run("real lost commit response recovers keyed original only", func(t *testing.T) {
		inv := f.issue("keyed-resend-lost-ack")
		r := request(inv, "resend-lost-ack")
		fault := new(commitResponseLoss)
		primary, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
			c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
			c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
				if err != nil {
					return nil, err
				}
				return &resendCommitConn{lossyCommitConn: &lossyCommitConn{Conn: conn, fault: fault}}, nil
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
		out, failure := build(f.newService(primary), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if failure == nil || !fault.lost.Load() || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.DeliveryState != 0 {
			t.Fatal("real lost COMMIT response not unknown", out.Receipt.Outcome, failure)
		}
		signs := f.signer.calls.Load()
		r.Authentication = f.signinOwner()
		recovered, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.DeliveryState != delivery.StateQueued || f.signer.calls.Load() != signs {
			t.Fatal("keyed COMMIT recovery failed or reissued", err)
		}
		effects(recovered, 1)
		inv.proof = proof()
		if accepted, err := accept(inv, 2, 1); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("recovered successor unusable", err)
		}
	})
	t.Run("contending original keys produce one successor", func(t *testing.T) {
		inv := f.issue("keyed-resend-contention")
		r := request(inv, "resend-contention")
		signs := f.signer.calls.Load()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { <-start; _, _ = service.Resend(ctx, r, "127.0.0.1") })
		}
		close(start)
		wg.Wait()
		var version, issuedVersion string
		var originals int
		if err := pool.Raw().QueryRow(ctx, `SELECT version::text,issued_version::text,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.resend') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&version, &issuedVersion, &originals); err != nil || version != "2" || issuedVersion != "2" || originals != 1 || f.signer.calls.Load() != signs+1 {
			t.Fatal("contending calls did not themselves commit exactly one successor", err)
		}
		out, err := build(f.newService(pool), config.ConfigurationID).Resend(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.DeliveryState != delivery.StateQueued || f.signer.calls.Load() != signs+1 {
			t.Fatal("contended original not singleton", err)
		}
		effects(out, 1)
		if got := read(inv); got.Invitation.Version != 2 {
			t.Fatal("contention produced multiple successors")
		}
		inv.proof = proof()
		if accepted, err := accept(inv, 2, 1); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("contended successor unusable", err)
		}
	})
	t.Run("lost mapping acknowledgement never starts original execution", func(t *testing.T) {
		inv := f.issue("keyed-resend-mapping-loss")
		r := request(inv, "resend-mapping-loss")
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
		faulted := build(f.newService(primary), config.ConfigurationID)
		signs := f.signer.calls.Load()
		fault.count.Store(1)
		fault.armed.Store(true)
		out, failure := faulted.Resend(ctx, r, "127.0.0.1")
		var unknown identity.UnknownCommitError
		if !fault.lost.Load() || !errors.As(failure, &unknown) || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Receipt.Binding.CommandID == "" || out.InvitationID != inv.id || out.DeliveryState != 0 {
			t.Fatal("mapping-only original lost explicit unknown correlation", failure)
		}
		noExecution := func() {
			t.Helper()
			raw, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
			if err != nil {
				t.Fatal(err)
			}
			var journals, effects, grants, events, deliveries, charges, audits int
			if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM identity.commands WHERE command_id=$1),
 (SELECT count(*) FROM organization.command_effects WHERE command_id=$2),
 (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$2),
 (SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),
 (SELECT count(*) FROM identity.delivery_intents WHERE command_id=$1),
 (SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),
 (SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1)`, raw, string(out.Receipt.Binding.CommandID)).Scan(&journals, &effects, &grants, &events, &deliveries, &charges, &audits); err != nil || journals != 0 || effects != 0 || grants != 0 || events != 0 || deliveries != 0 || charges != 0 || audits != 0 || f.signer.calls.Load() != signs {
				t.Fatal("mapping-only original created protected execution", err)
			}
		}
		noExecution()
		restarted := build(f.newService(pool), config.ConfigurationID)
		if retry, err := restarted.Resend(ctx, r, "127.0.0.1"); !errors.As(err, &unknown) || retry.Receipt.Outcome != identity.CommitOutcomeUnknown || retry.Receipt.Binding != out.Receipt.Binding || retry.DeliveryState != 0 {
			t.Fatal("matching live mapping reconstructed execution or fabricated noncommit", err)
		}
		noExecution()
		// The native session owner bounds each original observation to 20s.
		// Wait past it; only the kernel's DB-clock expiry may refuse this ID.
		timer := time.NewTimer(21 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		expired, err := restarted.Resend(ctx, r, "127.0.0.1")
		if err != nil || expired.Receipt.Outcome != identity.CommitOutcomeNotCommitted || expired.Receipt.Binding != out.Receipt.Binding || expired.DeliveryState != 0 {
			t.Fatal("expired original mapping not definitively refused", err)
		}
		noExecution()
		// Even a freshly authorized explicit native preparation cannot reuse
		// the command identity that the sole kernel has now refused.
		delayed, err := f.service.PrepareResend(ctx, organization.InvitationResendRequest{Authentication: f.owner, CommandID: out.Receipt.Binding.CommandID, OrganizationID: inv.org, ID: inv.id, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: r.CorrelationID}, "127.0.0.1")
		if err != nil {
			t.Fatal("fresh delayed native preparation", err)
		}
		if result, err := f.service.ExecuteResend(ctx, delayed); err == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted || result.Delivery != nil {
			t.Fatal("refused mapped original resurrected native execution")
		}
		noExecution()
		if got := read(inv); got.Invitation.Version != 1 || got.Invitation.IssuedVersion != 1 {
			t.Fatal("mapping-only refusal changed predecessor")
		}
		if accepted, err := accept(inv, 1, 1); err != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("never-started mapping consumed predecessor", err)
		}
	})
	if allocations.Load() != 0 {
		t.Fatal("resend allocated a new invitation identity")
	}
}

type invitationResendAdmissionEvaluator struct{}

func (*invitationResendAdmissionEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if string(r.Tenant) == baselineTenant && r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Action == authorization.Action(organization.InvitationResend) && r.Resource.Type == "identity.request-admission" && r.Resource.ID == authorization.ResourceID(organization.InvitationResend) {
		return authorization.Decision{Outcome: authorization.Allow}, nil
	}
	return new(baselineEvaluator).Evaluate(ctx, r)
}
