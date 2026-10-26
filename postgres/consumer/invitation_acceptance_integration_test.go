//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineInvitationAcceptanceConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "acceptance")
}

// This continues real signup, verification and password signin through actual
// native send, encrypted delivery, once-only acceptance and original recovery.
func exerciseGenuineInvitationAcceptance(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, organizations *organizationpg.Service, source *organizationpg.InvitationService, restart func(*database.Pool) *organizationpg.InvitationService, config organizationpg.InvitationServiceConfig, worker *deliverypg.Worker, mailbox *registrationMailbox, limits capability.Limits, owner, recipient organization.Authentication, recipientID identity.UserID, identifier identity.IdentifierID) {
	t.Helper()
	native := directInvitationAcceptance(t, source)
	twoPhase := twoPhaseInvitationAcceptance(t, source)
	verifier, err := capability.NewService(config.Issuer.Crypto)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(slug string) organization.InvitationAcceptRequest {
		t.Helper()
		org, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		created, err := organizations.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(org), Name: "Neutral invitation acceptance", Slug: slug, CorrelationID: slug}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if result, err := organizations.Execute(ctx, created); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine acceptance organization setup failed", err)
		}
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := source.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(id), OrganizationID: organization.ID(org), OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifier, CorrelationID: slug}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if result, err := source.Execute(ctx, prepared); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine acceptance invitation send failed", err)
		}
		if result, err := worker.ProcessOne(ctx); err != nil || !result.Claimed {
			t.Fatal("actual encrypted acceptance invitation was not delivered", err)
		}
		mailbox.mu.Lock()
		body := mailbox.body
		mailbox.body = ""
		mailbox.mu.Unlock()
		link, err := url.Parse(body)
		if err != nil || link.Query().Get("token") == "" {
			t.Fatal("actual acceptance delivery lacks proof")
		}
		proof, err := capability.ParseProof(link.Query().Get("token"), limits)
		if err != nil {
			t.Fatal("actual acceptance proof rejected")
		}
		return organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), OrganizationID: organization.ID(org), ID: organization.ID(id), OrganizationVersion: 1, InvitationVersion: 1, Proof: proof, CorrelationID: slug + "-accept"}
	}
	checkAdmission := func(r organization.InvitationAcceptRequest, callback func(context.Context, organization.InvitationAcceptAdmission) error) organization.InvitationAcceptAdmitter {
		t.Helper()
		grant, err := verifier.Verify(ctx, r.Proof, capability.Purpose(organization.InvitationAccept), config.Invitation.Audience)
		if err != nil {
			t.Fatal("original issued acceptance proof was not authenticated", err)
		}
		original := grant.Payload()
		return func(call context.Context, admission organization.InvitationAcceptAdmission) error {
			if admission.Validate() != nil || admission.Binding.CommandID != r.CommandID || admission.Binding.RecordID != string(r.ID) || admission.Binding.UserID != recipientID || admission.Binding.ActorID != identity.ActorID(recipientID) || admission.OrganizationID != r.OrganizationID || admission.ChallengeID != original.ID || admission.ChallengeLifetime != original.ExpiresAt.Sub(original.IssuedAt) || admission.Binding.CorrelationID != r.CorrelationID {
				t.Fatal("neutral admission changed authenticated original custody")
			}
			if _, ok := call.Deadline(); !ok {
				t.Fatal("neutral admission callback has no bounded deadline")
			}
			return callback(call, admission)
		}
	}
	// Scalar evidence is scoped to the caller's original command, not unrelated
	// signup/signin audit or the invitation's original issuance transaction.
	effects := func(r organization.InvitationAcceptRequest) [6]int {
		t.Helper()
		raw, err := base64.RawURLEncoding.DecodeString(string(r.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var counts [6]int
		if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM identity.commands WHERE command_id=$1),(SELECT count(*) FROM organization.command_effects WHERE command_id=$2),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$1),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$3 AND organization_id=$4 AND user_id=$5 AND state='active')`, raw, string(r.CommandID), string(r.Authentication.TenantID), string(r.OrganizationID), string(recipientID)).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5]); err != nil {
			t.Fatal(err)
		}
		return counts
	}
	admitted := func(context.Context, organization.InvitationAcceptAdmission) error { return nil }
	t.Run("two-phase-original-custody", func(t *testing.T) {
		r := issue("neutral-two-phase")
		before := effects(r)
		prepared, err := twoPhase.PrepareAcceptance(ctx, r, "127.0.0.1")
		if err != nil || prepared == nil {
			t.Fatal("genuine two-phase preparation failed", err)
		}
		admission, err := prepared.Admission()
		if err != nil {
			t.Fatal(err)
		}
		if err := checkAdmission(r, admitted)(ctx, admission); err != nil {
			t.Fatal(err)
		}
		if again, err := prepared.Admission(); err != nil || again != admission || effects(r) != before {
			t.Fatal("metadata read prepared again, consumed proof or created native effects", err)
		}
		if _, err := json.Marshal(prepared); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("opaque two-phase handle serialized original custody", err)
		}
		text, ok := prepared.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatal("opaque handle lacks text custody rejection")
		}
		if _, err := text.MarshalText(); !errors.Is(err, organization.ErrSensitiveSerialization) {
			t.Fatal("opaque handle exported original text custody", err)
		}
		if rendered := fmt.Sprintf("%#v", prepared); !strings.Contains(rendered, "redacted") || strings.Contains(rendered, admission.ChallengeID) || strings.Contains(rendered, string(r.CommandID)) {
			t.Fatal("opaque handle exposed original preparation")
		}
		if result, err := prepared.Execute(nil); !errors.Is(err, organization.ErrInvalidInput) || !reflect.DeepEqual(result, organization.StoreResult{}) || effects(r) != before {
			t.Fatal("nil execution context consumed original preparation", err)
		}
		// A middleware/rate denial simply drops the handle. There is no detached
		// execution, journal or proof consumption before this explicit call.
		result, err := prepared.Execute(ctx)
		if err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Binding != admission.Binding {
			t.Fatal("two-phase execution did not retain exact original preparation", result.Receipt.Outcome, err)
		}
		after := effects(r)
		if replay, err := prepared.Execute(ctx); err != nil || !reflect.DeepEqual(replay, result) || effects(r) != after {
			t.Fatal("serial original handle replay changed outcome or effects", err)
		}
		if recovered, err := directInvitationAcceptance(t, restart(pool)).RecoverAccept(ctx, organization.InvitationAcceptRecoveryRequest{Authentication: recipient, Binding: admission.Binding, OrganizationID: r.OrganizationID}); err != nil || !reflect.DeepEqual(recovered, result) || effects(r) != after {
			t.Fatal("two-phase original recovery changed history", err)
		}
	})
	t.Run("two-phase-final-recipient-fence", func(t *testing.T) {
		r := issue("neutral-two-phase-withdrawal")
		prepared, err := twoPhase.PrepareAcceptance(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(recipient.TenantID), string(recipientID), string(identifier)); err != nil {
			t.Fatal(err)
		}
		result, executeErr := prepared.Execute(ctx)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(recipient.TenantID), string(recipientID), string(identifier)); err != nil {
			t.Fatal(err)
		}
		if executeErr == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("two-phase handle renewed withdrawn recipient authority", result.Receipt.Outcome, executeErr)
		}
		counts := effects(r)
		if counts[1] != 0 || counts[2] != 0 || counts[5] != 0 {
			t.Fatal("two-phase withdrawal retained protected acceptance effects")
		}
	})
	for _, mode := range []string{"error", "panic", "cancel", "identifier", "session", "organization"} {
		t.Run("admission-"+mode, func(t *testing.T) {
			r := issue("neutral-accept-" + mode)
			before := effects(r)
			denied := errors.New("bounded transport admission denied")
			call, cancel := context.WithCancel(ctx)
			defer cancel()
			fired := false
			var restore func()
			gate := checkAdmission(r, func(call context.Context, _ organization.InvitationAcceptAdmission) error {
				fired = true
				switch mode {
				case "error":
					return denied
				case "panic":
					panic("private-admission-panic-marker")
				case "cancel":
					cancel()
				case "identifier":
					if _, err := pool.Raw().Exec(call, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND identifier_id=$2`, string(recipient.TenantID), string(identifier)); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						_, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND identifier_id=$2`, string(recipient.TenantID), string(identifier))
						if err != nil {
							t.Fatal(err)
						}
					}
				case "organization":
					if _, err := pool.Raw().Exec(call, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, string(recipient.TenantID), string(r.OrganizationID)); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						_, err := pool.Raw().Exec(ctx, `UPDATE organization.organizations SET version=version-1 WHERE tenant_id=$1 AND organization_id=$2`, string(recipient.TenantID), string(r.OrganizationID))
						if err != nil {
							t.Fatal(err)
						}
					}
				case "session":
					token, err := session.ParseToken(recipient.Bearer.Token())
					if err != nil {
						t.Fatal(err)
					}
					credential, err := session.NewCredential(session.CredentialBearer, token)
					if err != nil {
						t.Fatal(err)
					}
					current, err := config.Sessions.Get(call, session.GetRequest{TenantID: recipient.TenantID, Credential: credential})
					if err != nil {
						t.Fatal(err)
					}
					binding, err := current.Session.Bindings()
					if err != nil {
						t.Fatal(err)
					}
					if _, err := pool.Raw().Exec(call, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(recipient.TenantID), binding.SessionID); err != nil {
						t.Fatal(err)
					}
					restore = func() {
						_, err := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='active' WHERE tenant_id=$1 AND session_id=$2`, string(recipient.TenantID), binding.SessionID)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				return nil
			})
			out, err := native.Accept(call, r, "127.0.0.1", gate)
			if restore != nil {
				restore()
			}
			if !fired || err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("late denied admission committed acceptance", out.Receipt.Outcome, err)
			}
			if mode == "error" && err != denied {
				t.Fatal("transport admission error identity was lost")
			}
			if mode == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("callback cancellation was not retained", err)
			}
			if mode == "error" || mode == "panic" || mode == "cancel" {
				if !reflect.DeepEqual(out, organization.StoreResult{}) || effects(r) != before {
					t.Fatal("rejected transport admission consumed original execution")
				}
				if retry, err := native.Accept(ctx, r, "127.0.0.1", checkAdmission(r, admitted)); err != nil || retry.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("rejected pre-execution admission consumed the original proof or command", err)
				}
			} else {
				// Native final-fence denials may retain their sole owner journal and
				// failure audit/charge, but never protected domain/grant effects.
				counts := effects(r)
				if counts[1] != 0 || counts[2] != 0 || counts[5] != 0 {
					t.Fatal("withdrawn original authority retained protected acceptance effects")
				}
			}
		})
	}
	committed := issue("neutral-accept-committed")
	// Current configuration is deliberately not the original signed lifetime.
	// Native preparation must still authenticate the retained original envelope.
	short := config
	short.Invitation.Lifetime = config.Invitation.Lifetime / 2
	repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	shortSource, err := organizationpg.NewInvitationService(repository, short)
	if err != nil {
		t.Fatal(err)
	}
	var original organization.InvitationAcceptAdmission
	gate := checkAdmission(committed, func(_ context.Context, admission organization.InvitationAcceptAdmission) error {
		original = admission
		return nil
	})
	out, err := directInvitationAcceptance(t, shortSource).Accept(ctx, committed, "127.0.0.1", gate)
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Binding != original.Binding {
		t.Fatal("neutral native acceptance failed", out.Receipt.Outcome, err)
	}
	if original.ChallengeLifetime == short.Invitation.Lifetime {
		t.Fatal("admission replaced signed original lifetime with current configuration")
	}
	if member, err := organizations.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: committed.OrganizationID, CorrelationID: "neutral-accept-member"}); err != nil || member.Actor.UserID != recipientID || member.Actor.Role != organization.RoleMember {
		t.Fatal("accepted recipient lacks current native membership", err)
	}
	before := effects(committed)
	recovery := organization.InvitationAcceptRecoveryRequest{Authentication: recipient, Binding: original.Binding, OrganizationID: original.OrganizationID}
	recovered, err := directInvitationAcceptance(t, restart(pool)).RecoverAccept(ctx, recovery)
	if err != nil || !reflect.DeepEqual(recovered, out) || effects(committed) != before {
		t.Fatal("restart neutral recovery changed original outcome/effects", err)
	}
	called := false
	if result, err := native.Accept(ctx, committed, "127.0.0.1", func(context.Context, organization.InvitationAcceptAdmission) error { called = true; return nil }); !errors.Is(err, organization.ErrConflict) || result.Receipt.Outcome == identity.CommitOutcomeCommitted || called {
		t.Fatal("once endpoint inferred replay success or readmitted consumed invitation", err)
	}
	foreign := recovery
	foreign.Authentication = owner
	if result, err := native.RecoverAccept(ctx, foreign); !errors.Is(err, organization.ErrForbidden) || !reflect.DeepEqual(result, organization.StoreResult{}) {
		t.Fatal("neutral recovery disclosed original recipient history to owner", err)
	}
	foreign = recovery
	foreign.OrganizationID = "foreign-organization"
	if result, err := native.RecoverAccept(ctx, foreign); !errors.Is(err, organization.ErrForbidden) || !reflect.DeepEqual(result, organization.StoreResult{}) {
		t.Fatal("neutral recovery trusted substituted owning organization", err)
	}
	changed := issue("neutral-accept-changed-intent")
	changed.CommandID = committed.CommandID
	if result, err := native.Accept(ctx, changed, "127.0.0.1", checkAdmission(changed, admitted)); !errors.Is(err, organization.ErrConflict) || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("same original command accepted changed invitation intent", err)
	}
	rolled := issue("neutral-accept-rollback")
	if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.neutral_accept_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='accepted' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled neutral acceptance rollback'; END IF; RETURN NEW; END $$; CREATE TRIGGER neutral_accept_rollback BEFORE UPDATE ON organization.invitations FOR EACH ROW EXECUTE FUNCTION organization.neutral_accept_rollback()`); err != nil {
		t.Fatal(err)
	}
	var rollbackAdmission organization.InvitationAcceptAdmission
	aborted, err := native.Accept(ctx, rolled, "127.0.0.1", checkAdmission(rolled, func(_ context.Context, admission organization.InvitationAcceptAdmission) error {
		rollbackAdmission = admission
		return nil
	}))
	if _, cleanupErr := pool.Raw().Exec(ctx, `DROP TRIGGER neutral_accept_rollback ON organization.invitations; DROP FUNCTION organization.neutral_accept_rollback()`); cleanupErr != nil {
		t.Fatal(cleanupErr)
	}
	if !errors.Is(err, organization.ErrUnavailable) || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted || aborted.Receipt.Binding != rollbackAdmission.Binding {
		t.Fatal("neutral acceptance rollback lost original outcome", aborted.Receipt.Outcome, err)
	}
	rollbackEvidence := effects(rolled)
	if rollbackEvidence[1] != 0 || rollbackEvidence[2] != 0 || rollbackEvidence[5] != 0 {
		t.Fatal("rollback retained protected acceptance effects")
	}
	rollbackRecovery := organization.InvitationAcceptRecoveryRequest{Authentication: recipient, Binding: rollbackAdmission.Binding, OrganizationID: rolled.OrganizationID}
	if result, err := directInvitationAcceptance(t, restart(pool)).RecoverAccept(ctx, rollbackRecovery); !errors.Is(err, organization.ErrUnavailable) || !reflect.DeepEqual(result, aborted) || effects(rolled) != rollbackEvidence {
		t.Fatal("unjoined rollback recovery changed original outcome", result.Receipt.Outcome, err)
	}
	rolled.CommandID = commandID(t)
	if result, err := native.Accept(ctx, rolled, "127.0.0.1", checkAdmission(rolled, admitted)); !errors.Is(err, organization.ErrConflict) || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("terminal rollback grant was reused by new command", err)
	}
	lost := issue("neutral-accept-commit-loss")
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
			t.Error(err)
		}
	})
	var lostAdmission organization.InvitationAcceptAdmission
	unknown, err := directInvitationAcceptance(t, restart(faultPool)).Accept(ctx, lost, "127.0.0.1", checkAdmission(lost, func(_ context.Context, admission organization.InvitationAcceptAdmission) error {
		lostAdmission = admission
		fault.armed.Store(true)
		return nil
	}))
	if !fault.lost.Load() || err == nil || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding != lostAdmission.Binding {
		t.Fatal("actual neutral acceptance COMMIT loss was not unknown", unknown.Receipt.Outcome, err)
	}
	if result, err := directInvitationAcceptance(t, restart(pool)).RecoverAccept(ctx, organization.InvitationAcceptRecoveryRequest{Authentication: recipient, Binding: lostAdmission.Binding, OrganizationID: lost.OrganizationID}); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Binding != lostAdmission.Binding || result.InvitationID != lost.ID {
		t.Fatal("restart neutral recovery did not reconcile actual committed original", result.Receipt.Outcome, err)
	}
	if result, err := worker.ProcessOne(ctx); err != nil || result.Claimed {
		t.Fatal("neutral acceptance/recovery redelivered invitation proof", err)
	}
}
