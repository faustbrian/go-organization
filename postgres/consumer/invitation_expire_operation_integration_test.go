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
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineInvitationExpireOperationConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "expire-operation")
}

type invitationExpireOperationPort interface {
	Expire(context.Context, organization.InvitationExpireOperationRequest, string) (organization.StoreResult, error)
}

// Permission to manage invitations does not imply permission to read the full
// organization view. Only this external policy decision is controlled.
type invitationExpireWithoutReadPolicy struct{ authorization.Service }

func (p invitationExpireWithoutReadPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	out, err := p.Service.Decide(ctx, d)
	if d.Request.Action == authorization.Action(organization.Get) {
		out.Outcome = authorization.Deny
	}
	return out, err
}

func exerciseInvitationExpireOperations(t *testing.T, f invitationResendConsumer, db *sql.DB, logout reference.SessionService) {
	t.Helper()
	if logout == nil {
		t.Fatal("actual session-owner logout was not selected")
	}
	ctx, pool := f.ctx, f.pool
	port := func(s *organizationpg.InvitationService) invitationExpireOperationPort {
		t.Helper()
		p, ok := any(s).(invitationExpireOperationPort)
		if !ok {
			t.Fatal("native natural-repeat expiry is missing")
		}
		return p
	}
	service := port(f.service)
	request := func(inv issued) organization.InvitationExpireOperationRequest {
		return organization.InvitationExpireOperationRequest{Authentication: f.owner, OrganizationID: inv.org, InvitationID: inv.id, OrganizationVersion: 1, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "natural-expire"}
	}
	accept := func(inv issued) (organizationpg.PreparedInvitation, error) {
		return f.service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "natural-expire-predecessor"}, "127.0.0.1")
	}
	assertEffects := func(inv issued, original organization.StoreResult) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(original.Receipt.Binding.CommandID))
		if err != nil || len(id) == 0 {
			t.Fatal("original expiry correlation absent")
		}
		var mutations, events, audits int
		err = pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.expire'),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.expired.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.expire_invitation' AND r.outcome=1)`, string(inv.id), id).Scan(&mutations, &events, &audits)
		if err != nil || mutations != 1 || events != 1 || audits != 1 {
			t.Fatal("expiry lost singleton atomic history", mutations, events, audits, err)
		}
	}
	// Preserve real raw expiry before the optional migration. Its original
	// organization version cannot be inferred later from a terminal invitation.
	legacy := f.issue("expire-legacy")
	prepared, err := f.service.PrepareExpire(ctx, organization.InvitationExpireRequest{Authentication: f.owner, CommandID: commandID(t), ID: legacy.id, OrganizationID: legacy.org, OrganizationVersion: 1, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "legacy-expire"}, "127.0.0.1")
	if err != nil {
		t.Fatal("raw expiry before optional migration", err)
	}
	legacyResult, err := f.service.Execute(ctx, prepared)
	if err != nil || legacyResult.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("raw expiry required optional schema", err)
	}
	history, err := (organizationpg.InvitationExpireOperationMigrationSource{Version: 7010}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization_natural_expire")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(history), backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("populated natural-expire migration/replay", err)
		}
	}
	if out, err := service.Expire(ctx, request(legacy), "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy terminal row fabricated original correlation")
	}
	assertEffects(legacy, legacyResult)
	var logoutRequest organization.InvitationExpireOperationRequest
	var logoutOriginal organization.StoreResult

	t.Run("invitation permission does not require organization read permission", func(t *testing.T) {
		inv := f.issue("natural-expire-without-read")
		c := f.configuration
		policy := invitationExpireWithoutReadPolicy{Service: c.Authorization}
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
		out, err := port(selected).Expire(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("invitation-only manager could not expire", err)
		}
		reconstructed, err := organizationpg.NewInvitationService(repository, c)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := port(reconstructed).Expire(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("invitation-only manager could not recover original expiry", err)
		}
		assertEffects(inv, out)
	})

	t.Run("original expiry and reconstructed exact repeat", func(t *testing.T) {
		inv := f.populated
		old, err := accept(inv)
		if err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		out, err := service.Expire(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.Operation != organization.InvitationExpire.Descriptor() || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
			t.Fatal("initiating expiry did not commit", err)
		}
		logoutRequest, logoutOriginal = r, out
		if got, err := f.service.Execute(ctx, old); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("prepared predecessor survived expiry")
		}
		if _, err := accept(inv); err == nil {
			t.Fatal("old invitation proof was admitted after expiry")
		}
		r.Authentication = f.signinOwner()
		r.CorrelationID = "different-diagnostic"
		retry, err := port(f.newService(pool)).Expire(ctx, r, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(retry, out) {
			t.Fatal("natural repeat did not return actual original metadata", err)
		}
		for _, variant := range []string{"reason", "unregistered-reason", "org-version", "invitation-version", "organization", "invitation", "tenant", "recipient"} {
			changed := r
			switch variant {
			case "reason":
				changed.Reason = "administrative-cleanup"
			case "unregistered-reason":
				changed.Reason = "unregistered"
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
			if got, err := service.Expire(ctx, changed, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("changed selector disclosed original expiry", variant)
			}
		}
		added, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: f.administrator.id, Role: organization.RoleAdministrator, CorrelationID: "expire-later-org-epoch"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if got, err := f.organizations.Execute(ctx, added); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual organization epoch did not advance", err)
		}
		if got, err := port(f.newService(pool)).Expire(ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, out) {
			t.Fatal("later organization epoch lost original expiry", err)
		}
		assertEffects(inv, out)
	})

	for _, boundary := range []string{"audit", "outbox"} {
		t.Run("atomic rollback "+boundary, func(t *testing.T) {
			inv := f.issue("natural-expire-" + boundary)
			table, condition := "audit.records", "NEW.action='identity.organization.expire_invitation' AND NEW.outcome=1"
			if boundary == "outbox" {
				table, condition = "public.outbox_messages", "NEW.topic='invitation.expired.v1'"
			}
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_natural_expire() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled expiry effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_natural_expire BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.reject_natural_expire()`); err != nil {
				t.Fatal(err)
			}
			out, failure := service.Expire(ctx, request(inv), "127.0.0.1")
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_natural_expire ON `+table+`; DROP FUNCTION organization.reject_natural_expire()`); err != nil {
				t.Fatal(err)
			}
			if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("failed required effect did not roll back", failure)
			}
			var state string
			var effects int
			if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.expire') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "pending" || effects != 0 {
				t.Fatal("rollback retained expiry effects", err)
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
		inv := f.issue("natural-expire-commit-loss")
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
		unknown, err := port(f.newService(primary)).Expire(ctx, r, "127.0.0.1")
		if err == nil || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown {
			t.Fatal("lost final commit response was not unknown", unknown.Receipt.Outcome, err)
		}
		r.Authentication = f.signinOwner()
		out, err := port(f.newService(pool)).Expire(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != unknown.Receipt.Binding {
			t.Fatal("unknown outcome did not reconcile actual original", err)
		}
		assertEffects(inv, out)
	})

	t.Run("same-selector contention commits before later recovery", func(t *testing.T) {
		inv := f.issue("natural-expire-contention")
		r := request(inv)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 2 {
			wg.Go(func() { <-start; _, _ = service.Expire(ctx, r, "127.0.0.1") })
		}
		close(start)
		wg.Wait()
		var state string
		var effects int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.expire') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); err != nil || state != "expired" || effects != 1 {
			t.Fatal("initial contenders did not commit exactly once", err)
		}
		out, err := port(f.newService(pool)).Expire(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("contended original unavailable", err)
		}
		assertEffects(inv, out)
	})

	t.Run("acceptance versus natural expiry has one winner", func(t *testing.T) {
		inv := f.issue("natural-expire-accept-race")
		p, err := accept(inv)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; _, _ = f.service.Execute(ctx, p) })
		wg.Go(func() { <-start; _, _ = service.Expire(ctx, request(inv), "127.0.0.1") })
		close(start)
		wg.Wait()
		var state string
		var effects, members int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,
 (SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.expire')),
 (SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active')
 FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(f.recipientID)).Scan(&state, &effects, &members); err != nil || effects != 1 || state != "accepted" && state != "expired" || (state == "accepted") != (members == 1) {
			t.Fatal("accept/expire contention lacked a consistent winner", err)
		}
		out, err := port(f.newService(pool)).Expire(ctx, request(inv), "127.0.0.1")
		if state == "accepted" {
			if err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("accepted state was fabricated as expired")
			}
		} else if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("winning expiry could not be recovered", err)
		}
	})

	for _, stage := range []string{"management", "query"} {
		t.Run("late manager withdrawal during repeat "+stage, func(t *testing.T) {
			inv := f.issue("natural-expire-late-" + stage)
			admin := f.administrator
			p, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: admin.id, Role: organization.RoleAdministrator, CorrelationID: "expire-add-admin"}, "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if out, err := f.organizations.Execute(ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal(err)
			}
			r := request(inv)
			r.Authentication, r.OrganizationVersion = admin.authentication, 2
			original, err := service.Expire(ctx, r, "127.0.0.1")
			if err != nil || original.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("administrator could not initiate expiry", err)
			}
			// Another genuine manager cannot adopt this actor's original effect.
			other := r
			other.Authentication = f.owner
			if out, err := service.Expire(ctx, other, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("different manager adopted original expiry")
			}
			hook := &invitationCancellationPolicy{base: f.configuration.Authorization}
			fired := false
			removed := false
			managementSeen := false
			finalQuerySeen := false
			hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
				if fired || d.Request.Action != authorization.Action(organization.InvitationExpire) {
					return nil
				}
				switch string(d.Request.Resource.Type) {
				case "organization":
					managementSeen = true
					if stage != "management" {
						return nil
					}
				case "identity.user":
					// Expire first queries original metadata before Recover takes
					// its admission snapshot. Only Recover's query after the
					// organization callback exercises the final disclosure fence.
					if stage != "query" || !managementSeen {
						return nil
					}
					finalQuerySeen = true
				default:
					return nil
				}
				fired = true
				p, err := f.organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: admin.id, MemberVersion: 1, CorrelationID: "expire-remove-admin"}, "127.0.0.1")
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
			out, err := port(selected).Expire(ctx, r, "127.0.0.1")
			if err == nil || !fired || !removed || !managementSeen || stage == "query" && !finalQuerySeen || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
				t.Fatal("withdrawn manager obtained original metadata", err)
			}
			assertEffects(inv, original)
		})
	}

	t.Run("recipient withdrawal cannot prevent expiry or repeat", func(t *testing.T) {
		inv := f.issue("natural-expire-recipient-withdrawal")
		if _, err := pool.Raw().Exec(ctx, `WITH withdrawn AS (UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 RETURNING user_id) UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM withdrawn)`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		out, err := service.Expire(ctx, r, "127.0.0.1")
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("recipient withdrawal prevented revocation", err)
		}
		retry, err := port(f.newService(pool)).Expire(ctx, r, "127.0.0.1")
		if err != nil || !reflect.DeepEqual(out, retry) {
			t.Fatal("recipient withdrawal prevented exact original recovery", err)
		}
		assertEffects(inv, out)
	})
	t.Run("actual fresh session logout denies original history", func(t *testing.T) {
		logoutRequest.Authentication = f.signinOwner()
		if got, err := port(f.newService(pool)).Expire(ctx, logoutRequest, "127.0.0.1"); err != nil || !reflect.DeepEqual(got, logoutOriginal) {
			t.Fatal("fresh session lost original expiry before logout", err)
		}
		token, err := session.ParseToken(logoutRequest.Authentication.Bearer.Token())
		if err != nil {
			t.Fatal(err)
		}
		credential, err := session.NewCredential(session.CredentialBearer, token)
		if err != nil {
			t.Fatal(err)
		}
		out, err := logout.SignOut(ctx, session.SignOutRequest{TenantID: logoutRequest.Authentication.TenantID, CommandID: commandID(t), CorrelationID: "expiry-signout", Transport: session.CredentialBearer, Credential: credential}, session.CSRFToken{})
		if err != nil || !out.SignedOut || out.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual expiry source session logout failed", err)
		}
		if got, err := port(f.newService(pool)).Expire(ctx, logoutRequest, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("logged-out original actor recovered expiry")
		}
		assertEffects(f.populated, logoutOriginal)
	})
}
