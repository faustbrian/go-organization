//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineInvitationRejectOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "reject-operation")
}

// Each withdrawal owns a fresh real recipient: its authoritative identifier
// epochs are never reset to make another scenario's credentials usable again.
func TestOrganizationGenuineInvitationRejectWithdrawalConsumer(t *testing.T) {
	for _, stage := range []string{"management", "query"} {
		t.Run(stage, func(t *testing.T) {
			exerciseGenuinePasswordConsumer(t, "reject-operation-"+stage)
		})
	}
}

type invitationRejectOperationPort interface {
	Reject(context.Context, organization.InvitationRejectOperationRequest, string) (organization.StoreResult, error)
}

func exerciseInvitationRejectOperations(t *testing.T, f invitationResendConsumer, db *sql.DB, withdrawal string) {
	t.Helper()
	ctx, pool := f.ctx, f.pool
	port := func(s *organizationpg.InvitationService) invitationRejectOperationPort {
		t.Helper()
		p, ok := any(s).(invitationRejectOperationPort)
		if !ok {
			t.Fatal("native initiating recipient rejection is missing")
		}
		return p
	}
	service := port(f.service)
	request := func(inv issued) organization.InvitationRejectOperationRequest {
		return organization.InvitationRejectOperationRequest{Authentication: f.recipient, OrganizationID: inv.org, InvitationID: inv.id, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "natural-reject"}
	}
	accept := func(inv issued) (organizationpg.PreparedInvitation, error) {
		return f.service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "reject-predecessor"}, "127.0.0.1")
	}
	assertEffects := func(inv issued, result organization.StoreResult) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(result.Receipt.Binding.CommandID))
		if err != nil || len(id) == 0 {
			t.Fatal("original rejection correlation unavailable")
		}
		var effects, events, audits, members int
		err = pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.reject'),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.rejected.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.reject_invitation' AND r.outcome=1),
 (SELECT count(*) FROM organization.memberships WHERE tenant_id=$3 AND organization_id=$4 AND user_id=$5 AND state='active')`, string(inv.id), id, string(baselineTenant), string(inv.org), string(f.recipientID)).Scan(&effects, &events, &audits, &members)
		if err != nil || effects != 1 || events != 1 || audits != 1 || members != 0 {
			t.Fatal("rejection failed singleton/no-membership conservation", effects, events, audits, members, err)
		}
	}
	// Raw rejection must remain usable before the new optional correlation.
	legacy := f.issue("reject-legacy")
	p, err := f.service.PrepareReject(ctx, organization.InvitationRejectRequest{Authentication: f.recipient, CommandID: commandID(t), ID: legacy.id, OrganizationID: legacy.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "legacy-reject"}, "127.0.0.1")
	if err != nil {
		t.Fatal("raw rejection before optional migration", err)
	}
	legacyResult, err := f.service.Execute(ctx, p)
	if err != nil || legacyResult.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("raw rejection required optional schema", err)
	}
	history, err := (organizationpg.InvitationRejectOperationMigrationSource{Version: 7011}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_natural_reject")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(history), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("populated rejection correlation migration/replay", err)
		}
	}
	if out, err := service.Reject(ctx, request(legacy), "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy terminal state fabricated original correlation")
	}
	assertEffects(legacy, legacyResult)
	if withdrawal != "" {
		inv := f.populated
		r := request(inv)
		original, err := service.Reject(ctx, r, "127.0.0.1")
		if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("original recipient rejection before withdrawal", err)
		}
		hook := &invitationCancellationPolicy{base: f.configuration.Authorization}
		fired, withdrawn := false, false
		hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
			resource := "organization"
			if strings.TrimPrefix(withdrawal, "-") == "query" {
				resource = "identity.user"
			}
			if fired || d.Request.Action != authorization.Action(organization.InvitationReject) || string(d.Request.Resource.Type) != resource {
				return nil
			}
			fired = true
			tag, err := pool.Raw().Exec(ctx, `WITH withdrawn AS (UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 RETURNING user_id) UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM withdrawn)`, string(baselineTenant), string(f.recipientID))
			withdrawn = err == nil && tag.RowsAffected() == 1
			if !withdrawn {
				return organization.ErrUnavailable
			}
			return nil
		}
		c := f.configuration
		c.Authorization = hook
		q := *c.Coordinator.QueryPolicy
		q.Authorization = hook
		c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &q
		repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		selected, err := organizationpg.NewInvitationService(repository, c)
		if err != nil {
			t.Fatal(err)
		}
		out, err := port(selected).Reject(ctx, r, "127.0.0.1")
		if err == nil || !fired || !withdrawn || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("late withdrawn recipient obtained original rejection", err)
		}
		assertEffects(inv, original)
		return
	}

	t.Run("intended nonmember rejects and recovers original", func(t *testing.T) {
		inv := f.populated
		before, err := accept(inv)
		if err != nil {
			t.Fatal("actual predecessor was not admissible", err)
		}
		r := request(inv)
		out, err := service.Reject(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.Operation != organization.InvitationReject.Descriptor() || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("intended nonmember could not reject", err)
		}
		if got, err := f.service.Execute(ctx, before); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("prepared predecessor survived rejection")
		}
		if _, err := accept(inv); err == nil {
			t.Fatal("reconstructed acceptance admitted rejected proof")
		}
		r.Authentication, r.CorrelationID = f.signinRecipient(), "new-diagnostic"
		if got, err := port(f.newService(pool)).Reject(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("reconstructed natural repeat replaced original outcome", err)
		}
		for _, variant := range []string{"org-version", "invitation-version", "organization", "invitation", "tenant", "manager", "other-recipient"} {
			changed := r
			switch variant {
			case "org-version":
				changed.OrganizationVersion++
			case "invitation-version":
				changed.InvitationVersion++
			case "organization":
				changed.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
			case "invitation":
				changed.InvitationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
			case "tenant":
				changed.Authentication.TenantID = "foreign"
			case "manager":
				changed.Authentication = f.owner
			case "other-recipient":
				changed.Authentication = f.administrator.authentication
			}
			if got, err := service.Reject(ctx, changed, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("changed recipient/selector disclosed rejection", variant)
			}
		}
		added, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: f.administrator.id, Role: organization.RoleMember, CorrelationID: "reject-later-org-epoch"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.organizations.Execute(ctx, added); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual org epoch did not advance", err)
		}
		if got, err := port(f.newService(pool)).Reject(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("later org epoch lost original rejection", err)
		}
		assertEffects(inv, out)
	})

	for _, boundary := range []string{"audit", "outbox"} {
		t.Run("atomic rollback "+boundary, func(t *testing.T) {
			inv := f.issue("natural-reject-" + boundary)
			table, condition := "audit.records", "NEW.action='identity.organization.reject_invitation' AND NEW.outcome=1"
			if boundary == "outbox" {
				table, condition = "public.outbox_messages", "NEW.topic='invitation.rejected.v1'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_natural_rejection() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled rejection effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_natural_rejection BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.reject_natural_rejection()`); err != nil {
				t.Fatal(err)
			}
			out, failure := service.Reject(ctx, request(inv), "127.0.0.1")
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_natural_rejection ON `+table+`; DROP FUNCTION organization.reject_natural_rejection()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("required rejection effect failed without rollback", failure)
			}
			var state string
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.reject') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "pending" || effects != 0 {
				t.Fatal("failed rejection retained effects", err)
			}
			p, err := accept(inv)
			if err != nil {
				t.Fatal("rollback invalidated original proof", err)
			}
			if got, err := f.service.Execute(ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("rollback consumed predecessor", err)
			}
		})
	}

	t.Run("final commit loss recovers original", func(t *testing.T) {
		inv := f.issue("natural-reject-commit-loss")
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
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := primary.Close(cleanup); err != nil {
				t.Error(err)
			}
		}()
		r := request(inv)
		unknown, err := port(f.newService(primary)).Reject(ctx, r, "127.0.0.1")
		if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("lost final rejection commit was not unknown", unknown.Receipt.Outcome, err)
		}
		r.Authentication = f.signinRecipient()
		out, err := port(f.newService(pool)).Reject(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != unknown.Receipt.Binding {
			t.Fatal("rejection did not reconcile actual original", err)
		}
		assertEffects(inv, out)
	})

	t.Run("contending natural requests commit before later recovery", func(t *testing.T) {
		inv := f.issue("natural-reject-contention")
		r := request(inv)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { <-start; _, _ = service.Reject(ctx, r, "127.0.0.1") })
		}
		close(start)
		wg.Wait()
		var state string
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.reject') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "rejected" || effects != 1 {
			t.Fatal("initial contenders did not themselves commit once", err)
		}
		out, err := port(f.newService(pool)).Reject(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("winning rejection could not be recovered", err)
		}
		assertEffects(inv, out)
	})

	t.Run("acceptance and rejection have one actual winner", func(t *testing.T) {
		inv := f.issue("natural-reject-accept-race")
		p, err := accept(inv)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; _, _ = f.service.Execute(ctx, p) })
		wg.Go(func() { <-start; _, _ = service.Reject(ctx, request(inv), "127.0.0.1") })
		close(start)
		wg.Wait()
		var state string
		var effects, members int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.reject')),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(f.recipientID)).Scan(&state, &effects, &members); err != nil || effects != 1 || state != "accepted" && state != "rejected" || (state == "accepted") != (members == 1) {
			t.Fatal("accept/reject race did not conserve one terminal winner", err)
		}
		out, err := port(f.newService(pool)).Reject(ctx, request(inv), "127.0.0.1")
		if state == "accepted" {
			if err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("accepted invitation fabricated rejection history")
			}
		} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual winning rejection not recoverable", err)
		}
	})

	t.Run("withdrawn recipient cannot initiate or recover rejection", func(t *testing.T) {
		rejected, pending := f.issue("natural-reject-withdrawn-history"), f.issue("natural-reject-withdrawn-pending")
		original, err := service.Reject(ctx, request(rejected), "127.0.0.1")
		if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		tag, err := pool.Raw().Exec(ctx, `WITH withdrawn AS (UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 RETURNING user_id) UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM withdrawn)`, string(baselineTenant), string(f.recipientID))
		if err != nil || tag.RowsAffected() != 1 {
			t.Fatal("actual recipient withdrawal failed", err)
		}
		for _, inv := range []issued{rejected, pending} {
			if got, err := port(f.newService(pool)).Reject(ctx, request(inv), "127.0.0.1"); err == nil || got.Receipt.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("withdrawn recipient executed or disclosed rejection", err)
			}
		}
		assertEffects(rejected, original)
		var state string
		if err := pool.Raw().QueryRow(ctx, `SELECT state FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(pending.id)).Scan(&state); err != nil || state != "pending" {
			t.Fatal("denied withdrawal changed pending invitation", err)
		}
	})
}
