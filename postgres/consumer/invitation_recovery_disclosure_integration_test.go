//go:build integration

package consumer_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

func TestOrganizationGenuineInvitationRecoveryDisclosureConsumer(t *testing.T) {
	exerciseGenuinePasswordConsumer(t, "recovery-disclosure")
}

// Reuse actual signup/verification/password sessions, native send, encrypted
// delivery and exact acceptance; only the late policy callback controls the
// administrative withdrawal. No fake session or reconstructed proof is used.
func exerciseGenuineInvitationRecoveryDisclosure(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, organizations *organizationpg.Service, native *organizationpg.InvitationService, newNative func(*database.Pool) *organizationpg.InvitationService, config organizationpg.InvitationServiceConfig, worker *deliverypg.Worker, mailbox *registrationMailbox, limits capability.Limits, owner, recipient organization.Authentication, recipientID identity.UserID, identifier identity.IdentifierID, signinOwner, signinRecipient func() organization.Authentication) {
	t.Helper()
	type history struct {
		handle organizationpg.InvitationRecovery
		result organization.StoreResult
	}
	var histories []history
	issue := func(slug string, accept, rollback bool) history {
		t.Helper()
		org, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		created, err := organizations.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(org), Name: "Invitation recovery disclosure", Slug: slug, CorrelationID: slug}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := organizations.Execute(ctx, created); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine disclosure organization setup failed", err)
		}
		id, err := identity.NewSubjectID()
		if err != nil {
			t.Fatal(err)
		}
		send, err := native.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(id), OrganizationID: organization.ID(org), OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifier, CorrelationID: slug}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, err := send.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		sent, err := native.Execute(ctx, send)
		if err != nil || sent.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine disclosure send failed", err)
		}
		histories = append(histories, history{handle, sent})
		if result, err := worker.ProcessOne(ctx); err != nil || !result.Claimed {
			t.Fatal("actual encrypted disclosure invitation was not delivered", err)
		}
		mailbox.mu.Lock()
		body := mailbox.body
		mailbox.body = ""
		mailbox.mu.Unlock()
		link, err := url.Parse(body)
		if err != nil || link.Query().Get("token") == "" {
			t.Fatal("actual disclosure invitation delivery lacks proof")
		}
		proof, err := capability.ParseProof(link.Query().Get("token"), limits)
		if err != nil {
			t.Fatal("actual captured disclosure invitation proof rejected")
		}
		if !accept {
			return history{handle, sent}
		}
		prepared, err := native.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), OrganizationID: organization.ID(org), ID: organization.ID(id), OrganizationVersion: 1, InvitationVersion: 1, Proof: proof, CorrelationID: slug + "-accept"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, err = prepared.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		if rollback {
			if _, err := pool.Raw().Exec(ctx, `CREATE FUNCTION organization.disclosure_accept_rollback() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled disclosure acceptance rollback'; END $$; CREATE TRIGGER disclosure_accept_rollback BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION organization.disclosure_accept_rollback()`); err != nil {
				t.Fatal(err)
			}
		}
		accepted, acceptErr := native.Execute(ctx, prepared)
		if rollback {
			if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER disclosure_accept_rollback ON public.identity_outbox_bindings; DROP FUNCTION organization.disclosure_accept_rollback()`); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(acceptErr, organization.ErrUnavailable) || accepted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("actual disclosure acceptance rollback was not definitive", acceptErr)
			}
			var joined int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3`, string(recipient.TenantID), org, string(recipientID)).Scan(&joined); err != nil || joined != 0 {
				t.Fatal("rolled-back accepting recipient unexpectedly joined", err)
			}
		} else if acceptErr != nil || accepted.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("actual disclosure acceptance failed", acceptErr)
		}
		histories = append(histories, history{handle, accepted})
		return history{handle, accepted}
	}
	sent := issue("disclosure-sent", false, false)
	accepted := issue("disclosure-accepted", true, false)
	rolledBack := issue("disclosure-rolled-back", true, true)
	// All evidence counts are scoped to these original commands. A fresh genuine
	// password signin may legitimately create its own audit/session evidence.
	evidence := func() map[identity.CommandID][6]int {
		t.Helper()
		result := make(map[identity.CommandID][6]int)
		for _, h := range histories {
			id := h.handle.Binding.CommandID
			raw, err := base64.RawURLEncoding.DecodeString(string(id))
			if err != nil {
				t.Fatal(err)
			}
			var counts [6]int
			if err := db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),(SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$2),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$2),(SELECT count(*) FROM risk_store.counter_charges WHERE command_id=$2),(SELECT generation::bigint FROM identity.commands WHERE command_id=$2)`, string(id), raw).Scan(&counts[0], &counts[1], &counts[2], &counts[3], &counts[4], &counts[5]); err != nil {
				t.Fatal(err)
			}
			result[id] = counts
		}
		return result
	}
	originalEvidence := evidence()
	base := config.Authorization
	currentOwner, currentRecipient := owner, recipient
	restore := func(statement string, args ...any) error {
		tag, err := pool.Raw().Exec(ctx, statement, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("controlled disclosure restore did not match original version")
		}
		return nil
	}
	for _, tc := range []struct {
		name, stage, change string
		history             history
	}{
		{"send-management-session", "management", "session", sent},
		{"send-query-owner", "query", "owner", sent},
		{"send-query-organization", "query", "organization", sent},
		{"accept-management-session", "management", "session", accepted},
		{"accept-query-organization", "query", "organization", accepted},
		{"accept-query-membership", "query", "membership", accepted},
		{"accept-query-identifier", "query", "identifier", accepted},
		{"unjoined-accept-query-session", "query", "session", rolledBack},
		{"unjoined-accept-query-identifier", "query", "identifier", rolledBack},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.history
			a := currentOwner
			if h.handle.Binding.OperationID == string(organization.InvitationAccept) {
				a = currentRecipient
			}
			policy := &invitationCancellationPolicy{base: base}
			selected := config
			selected.Authorization = policy
			query := *selected.Coordinator.QueryPolicy
			query.Authorization = policy
			selected.Coordinator.QueryPolicy = &query
			repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			recovery, err := organizationpg.NewInvitationService(repository, selected)
			if err != nil {
				t.Fatal(err)
			}
			check := func(source *organizationpg.InvitationService, authentication organization.Authentication) {
				t.Helper()
				out, err := source.Recover(ctx, authentication, h.handle)
				failed := h.result.Receipt.Outcome == identity.CommitOutcomeNotCommitted
				if (failed && !errors.Is(err, organization.ErrUnavailable)) || (!failed && err != nil) || !reflect.DeepEqual(out, h.result) {
					t.Fatal("legitimate current recovery changed exact original history", out.Receipt.Outcome, err)
				}
			}
			check(recovery, a)
			var managed, fired atomic.Bool
			var undo func() error
			policy.before = func(call context.Context, d authorization.DecisionContext) error {
				if d.Request.Action != authorization.Action(h.handle.Binding.OperationID) {
					return nil
				}
				management := d.Request.Resource.Type == "organization" && d.Request.Resource.ID == authorization.ResourceID(h.handle.OrganizationID)
				if management {
					managed.Store(true)
				}
				// Send's earlier origin lookup is not the final disclosure query.
				match := tc.stage == "management" && management || tc.stage == "query" && managed.Load() && d.Request.Resource.Type == "identity.user"
				if !match || !fired.CompareAndSwap(false, true) {
					return nil
				}
				b := h.handle.Binding
				switch tc.change {
				case "session":
					token, err := session.ParseToken(a.Bearer.Token())
					if err != nil {
						return err
					}
					credential, err := session.NewCredential(session.CredentialBearer, token)
					if err != nil {
						return err
					}
					current, err := config.Sessions.Get(call, session.GetRequest{TenantID: a.TenantID, Credential: credential})
					if err != nil {
						return err
					}
					bound, err := current.Session.Bindings()
					if err != nil {
						return err
					}
					_, err = pool.Raw().Exec(call, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(a.TenantID), bound.SessionID)
					return err
				case "organization":
					var version string
					if err := pool.Raw().QueryRow(call, `UPDATE organization.organizations SET version=version+1 WHERE tenant_id=$1 AND organization_id=$2 RETURNING (version-1)::text`, string(b.TenantID), string(h.handle.OrganizationID)).Scan(&version); err != nil {
						return err
					}
					undo = func() error {
						return restore(`UPDATE organization.organizations SET version=$3::numeric WHERE tenant_id=$1 AND organization_id=$2 AND version=$3::numeric+1`, string(b.TenantID), string(h.handle.OrganizationID), version)
					}
				case "owner", "membership":
					var version, role string
					if err := pool.Raw().QueryRow(call, `UPDATE organization.memberships SET version=version+1,role=CASE WHEN role='owner' THEN 'member' ELSE role END WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 RETURNING (version-1)::text,CASE WHEN user_id=$4 THEN 'owner' ELSE role END`, string(b.TenantID), string(h.handle.OrganizationID), string(b.ActorID), string(sent.handle.Binding.ActorID)).Scan(&version, &role); err != nil {
						return err
					}
					undo = func() error {
						return restore(`UPDATE organization.memberships SET version=$4::numeric,role=$5 WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND version=$4::numeric+1`, string(b.TenantID), string(h.handle.OrganizationID), string(b.ActorID), version, role)
					}
				case "identifier":
					var version string
					if err := pool.Raw().QueryRow(call, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 RETURNING (version-1)::text`, string(b.TenantID), string(recipientID), string(identifier)).Scan(&version); err != nil {
						return err
					}
					undo = func() error {
						return restore(`UPDATE identity.identifiers SET version=$4::numeric WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 AND version=$4::numeric+1`, string(b.TenantID), string(recipientID), string(identifier), version)
					}
				}
				return nil
			}
			out, recoverErr := recovery.Recover(ctx, a, h.handle)
			policy.before = nil
			if undo != nil {
				if err := undo(); err != nil {
					t.Fatal("controlled disclosure withdrawal did not restore", err)
				}
			}
			if tc.change == "session" && fired.Load() {
				if h.handle.Binding.OperationID == string(organization.InvitationSend) {
					currentOwner = signinOwner()
					a = currentOwner
				} else {
					currentRecipient = signinRecipient()
					a = currentRecipient
				}
			}
			if !fired.Load() || !errors.Is(recoverErr, organization.ErrForbidden) || out != (organization.StoreResult{}) {
				t.Fatal("late authority withdrawal disclosed invitation history", "callback", fired.Load(), "outcome", out.Receipt.Outcome, "error", recoverErr)
			}
			check(newNative(pool), a)
		})
	}
	if !reflect.DeepEqual(originalEvidence, evidence()) {
		t.Fatal("metadata recovery reexecuted an original command or changed protected evidence")
	}
	if result, err := worker.ProcessOne(ctx); err != nil || result.Claimed {
		t.Fatal("disclosure recovery regenerated or redelivered invitation proof", err)
	}
}
