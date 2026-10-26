//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net"
	"os"
	"reflect"
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

func TestOrganizationGenuineInvitationCancelOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "cancel-operation")
}

type invitationCancelOperationPort interface {
	Cancel(context.Context, organization.InvitationCancelOperationRequest, string) (organization.StoreResult, error)
}

// Permission to manage invitations does not imply permission to read the full
// organization view. Only this external policy decision is controlled.
type invitationCancelWithoutReadPolicy struct{ authorization.Service }

func (p invitationCancelWithoutReadPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	out, err := p.Service.Decide(ctx, d)
	if d.Request.Action == authorization.Action(organization.Get) {
		out.Outcome = authorization.Deny
	}
	return out, err
}

func exerciseInvitationCancelOperations(t *testing.T, f invitationResendConsumer, db *sql.DB) {
	t.Helper()
	ctx, pool := f.ctx, f.pool
	port := func(s *organizationpg.InvitationService) invitationCancelOperationPort {
		t.Helper()
		p, ok := any(s).(invitationCancelOperationPort)
		if !ok {
			t.Fatal("native natural-repeat cancellation is missing")
		}
		return p
	}
	service := port(f.service)
	request := func(inv issued) organization.InvitationCancelOperationRequest {
		return organization.InvitationCancelOperationRequest{Authentication: f.owner, OrganizationID: inv.org, InvitationID: inv.id, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "natural-cancel"}
	}
	accept := func(inv issued) (organizationpg.PreparedInvitation, error) {
		return f.service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "natural-cancel-predecessor"}, "127.0.0.1")
	}
	assertEffects := func(inv issued, original organization.StoreResult) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(original.Receipt.Binding.CommandID))
		if err != nil || len(id) == 0 {
			t.Fatal("original cancellation correlation absent")
		}
		var mutations, events, audits int
		err = pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.cancel'),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.cancelled.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.cancel_invitation' AND r.outcome=1)`, string(inv.id), id).Scan(&mutations, &events, &audits)
		if err != nil || mutations != 1 || events != 1 || audits != 1 {
			t.Fatal("cancellation lost singleton atomic history", mutations, events, audits, err)
		}
	}
	// Preserve real raw cancellation before the optional migration. Its original
	// organization version cannot be inferred later from a terminal invitation.
	legacy := f.issue("cancel-legacy")
	prepared, err := f.service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: f.owner, CommandID: commandID(t), ID: legacy.id, OrganizationID: legacy.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "legacy-cancel"}, "127.0.0.1")
	if err != nil {
		t.Fatal("raw cancellation before optional migration", err)
	}
	legacyResult, err := f.service.Execute(ctx, prepared)
	if err != nil || legacyResult.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("raw cancellation required optional schema", err)
	}
	history, err := (organizationpg.InvitationCancelOperationMigrationSource{Version: 7010}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_natural_cancel")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(history), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("populated natural-cancel migration/replay", err)
		}
	}
	if out, err := service.Cancel(ctx, request(legacy), "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy terminal row fabricated original correlation")
	}
	assertEffects(legacy, legacyResult)

	t.Run("invitation permission does not require organization read permission", func(t *testing.T) {
		inv := f.issue("natural-cancel-without-read")
		c := f.configuration
		policy := invitationCancelWithoutReadPolicy{Service: c.Authorization}
		c.Authorization = policy
		q := *c.Coordinator.QueryPolicy
		q.Authorization = policy
		c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &q
		repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		selected, err := organizationpg.NewInvitationService(repository, c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		out, err := port(selected).Cancel(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("invitation-only manager could not cancel", err)
		}
		reconstructed, err := organizationpg.NewInvitationService(repository, c)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := port(reconstructed).Cancel(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("invitation-only manager could not recover original cancellation", err)
		}
		assertEffects(inv, out)
	})

	t.Run("original cancellation and reconstructed exact repeat", func(t *testing.T) {
		inv := f.populated
		old, err := accept(inv)
		if err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		out, err := service.Cancel(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.Operation != organization.InvitationCancel.Descriptor() || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("initiating cancellation did not commit", err)
		}
		if got, err := f.service.Execute(ctx, old); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("prepared predecessor survived cancellation")
		}
		if _, err := accept(inv); err == nil {
			t.Fatal("old invitation proof was admitted after cancellation")
		}
		r.Authentication = f.signinOwner()
		r.CorrelationID = "different-diagnostic"
		retry, err := port(f.newService(pool)).Cancel(ctx, r, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(retry, out) {
			t.Fatal("natural repeat did not return actual original metadata", err)
		}
		for _, variant := range []string{"org-version", "invitation-version", "organization", "invitation", "tenant", "recipient"} {
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
			case "recipient":
				changed.Authentication = f.recipient
			}
			if got, err := service.Cancel(ctx, changed, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("changed selector disclosed original cancellation", variant)
			}
		}
		added, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: f.administrator.id, Role: organization.RoleAdministrator, CorrelationID: "cancel-later-org-epoch"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.organizations.Execute(ctx, added); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual organization epoch did not advance", err)
		}
		if got, err := port(f.newService(pool)).Cancel(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("later organization epoch lost original cancellation", err)
		}
		assertEffects(inv, out)
	})

	for _, boundary := range []string{"audit", "outbox"} {
		t.Run("atomic rollback "+boundary, func(t *testing.T) {
			inv := f.issue("natural-cancel-" + boundary)
			table, condition := "audit.records", "NEW.action='identity.organization.cancel_invitation' AND NEW.outcome=1"
			if boundary == "outbox" {
				table, condition = "public.outbox_messages", "NEW.topic='invitation.cancelled.v1'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_natural_cancel() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled cancellation effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_natural_cancel BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.reject_natural_cancel()`); err != nil {
				t.Fatal(err)
			}
			out, failure := service.Cancel(ctx, request(inv), "127.0.0.1")
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_natural_cancel ON `+table+`; DROP FUNCTION organization.reject_natural_cancel()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed required effect did not roll back", failure)
			}
			var state string
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.cancel') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "pending" || effects != 0 {
				t.Fatal("rollback retained cancellation effects", err)
			}
			p, err := accept(inv)
			if err != nil {
				t.Fatal("rollback invalidated predecessor proof", err)
			}
			if got, err := f.service.Execute(ctx, p); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("rollback consumed predecessor", err)
			}
		})
	}

	t.Run("final commit loss recovers original without execution", func(t *testing.T) {
		inv := f.issue("natural-cancel-commit-loss")
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
		unknown, err := port(f.newService(primary)).Cancel(ctx, r, "127.0.0.1")
		if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("lost final commit response was not unknown", unknown.Receipt.Outcome, err)
		}
		r.Authentication = f.signinOwner()
		out, err := port(f.newService(pool)).Cancel(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != unknown.Receipt.Binding {
			t.Fatal("unknown outcome did not reconcile actual original", err)
		}
		assertEffects(inv, out)
	})

	t.Run("same-selector contention commits before later recovery", func(t *testing.T) {
		inv := f.issue("natural-cancel-contention")
		r := request(inv)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { <-start; _, _ = service.Cancel(ctx, r, "127.0.0.1") })
		}
		close(start)
		wg.Wait()
		var state string
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.cancel') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "cancelled" || effects != 1 {
			t.Fatal("initial contenders did not commit exactly once", err)
		}
		out, err := port(f.newService(pool)).Cancel(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("contended original unavailable", err)
		}
		assertEffects(inv, out)
	})

	t.Run("acceptance versus natural cancellation has one winner", func(t *testing.T) {
		inv := f.issue("natural-cancel-accept-race")
		p, err := accept(inv)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; _, _ = f.service.Execute(ctx, p) })
		wg.Go(func() { <-start; _, _ = service.Cancel(ctx, request(inv), "127.0.0.1") })
		close(start)
		wg.Wait()
		var state string
		var effects, members int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.cancel')),
 (SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active')
 FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(f.recipientID)).Scan(&state, &effects, &members); err != nil || effects != 1 || state != "accepted" && state != "cancelled" || (state == "accepted") != (members == 1) {
			t.Fatal("accept/cancel contention lacked a consistent winner", err)
		}
		out, err := port(f.newService(pool)).Cancel(ctx, request(inv), "127.0.0.1")
		if state == "accepted" {
			if err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("accepted state was fabricated as cancelled")
			}
		} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("winning cancellation could not be recovered", err)
		}
	})

	for _, stage := range []string{"management", "query"} {
		t.Run("late manager withdrawal during repeat "+stage, func(t *testing.T) {
			inv := f.issue("natural-cancel-late-" + stage)
			admin := f.administrator
			p, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: admin.id, Role: organization.RoleAdministrator, CorrelationID: "cancel-add-admin"}, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if out, err := f.organizations.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			r := request(inv)
			r.Authentication, r.OrganizationVersion = admin.authentication, 2
			original, err := service.Cancel(ctx, r, "127.0.0.1")
			if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("administrator could not initiate cancellation", err)
			}
			// Another genuine manager cannot adopt this actor's original effect.
			other := r
			other.Authentication = f.owner
			if out, err := service.Cancel(ctx, other, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("different manager adopted original cancellation")
			}
			hook := &invitationCancellationPolicy{base: f.configuration.Authorization}
			fired := false
			removed := false
			hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
				resource := "organization"
				if stage == "query" {
					resource = "identity.user"
				}
				if fired || d.Request.Action != authorization.Action(organization.InvitationCancel) || string(d.Request.Resource.Type) != resource {
					return nil
				}
				fired = true
				p, err := f.organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: admin.id, MemberVersion: 1, CorrelationID: "cancel-remove-admin"}, "127.0.0.1")
				if err != nil {
					return err
				}
				out, err := f.organizations.Execute(ctx, p)
				removed = err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted
				if !removed {
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
			out, err := port(selected).Cancel(ctx, r, "127.0.0.1")
			if err == nil || !fired || !removed || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("withdrawn manager obtained original metadata", err)
			}
			assertEffects(inv, original)
		})
	}

	t.Run("recipient withdrawal cannot prevent cancellation or repeat", func(t *testing.T) {
		inv := f.issue("natural-cancel-recipient-withdrawal")
		if _, err := pool.Raw().Exec(ctx, `WITH withdrawn AS (UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 RETURNING user_id) UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM withdrawn)`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		out, err := service.Cancel(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("recipient withdrawal prevented revocation", err)
		}
		retry, err := port(f.newService(pool)).Cancel(ctx, r, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(out, retry) {
			t.Fatal("recipient withdrawal prevented exact original recovery", err)
		}
		assertEffects(inv, out)
	})
}
