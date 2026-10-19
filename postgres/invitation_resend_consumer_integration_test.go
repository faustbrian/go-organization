//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

type issued struct {
	org, id organization.ID
	proof   capability.Proof
}

type invitationResendAdministrator struct {
	authentication organization.Authentication
	id             identity.UserID
	signin         func() organization.Authentication
}

// This continuation borrows the existing actual signup/session/issuance graph.
// Only the documented provider sender and fault boundary are controlled.
type invitationResendConsumer struct {
	ctx                          context.Context
	pool                         *database.Pool
	organizations                *organizationpg.Service
	service                      *organizationpg.InvitationService
	configuration                organizationpg.InvitationServiceConfig
	newService                   func(*database.Pool) *organizationpg.InvitationService
	issue                        func(string) issued
	worker                       *deliverypg.Worker
	mailbox                      *registrationMailbox
	limits                       capability.Limits
	owner, recipient             organization.Authentication
	ownerID, recipientID         identity.UserID
	signinOwner, signinRecipient func() organization.Authentication
	administrator                invitationResendAdministrator
	populated                    issued
	statusPolicy                 *invitationCancellationPolicy
	signer                       *invitationResendSigner
}

func exerciseInvitationResend(t *testing.T, f invitationResendConsumer) {
	t.Helper()
	ctx, pool, service := f.ctx, f.pool, f.service
	request := func(inv issued) organization.InvitationResendRequest {
		return organization.InvitationResendRequest{Authentication: f.owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "invitation-resend"}
	}
	proof := func() capability.Proof {
		t.Helper()
		if _, err := f.worker.ProcessOne(ctx); err != nil {
			t.Fatal("successor encrypted delivery", err)
		}
		f.mailbox.mu.Lock()
		link := f.mailbox.body
		f.mailbox.body = ""
		f.mailbox.mu.Unlock()
		u, err := url.Parse(link)
		if err != nil || u.Query().Get("token") == "" {
			t.Fatal("successor proof not delivered")
		}
		p, err := capability.ParseProof(u.Query().Get("token"), f.limits)
		if err != nil {
			t.Fatal("successor proof invalid")
		}
		return p
	}
	accept := func(inv issued, version, orgVersion uint64) organizationpg.PreparedInvitation {
		t.Helper()
		p, err := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, InvitationVersion: version, OrganizationVersion: orgVersion, Proof: inv.proof, CorrelationID: "resend-accept"}, "127.0.0.1")
		if err != nil {
			t.Fatal("genuine accept preparation", err)
		}
		return p
	}
	assertEffects := func(handle organizationpg.InvitationRecovery, count int) {
		t.Helper()
		command, err := base64.RawURLEncoding.DecodeString(string(handle.Binding.CommandID))
		if err != nil {
			t.Fatal(err)
		}
		var effects, grants, events, audits, deliveries int
		err = pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),
 (SELECT count(*) FROM public.capability_identity_one_use WHERE origin_command_id=$1),
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$2 AND m.topic='invitation.resent.v1'),
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$2 AND r.action='identity.organization.resend_invitation' AND r.outcome=1),
 (SELECT count(*) FROM organization.command_effects e JOIN identity.delivery_intents d ON d.effect_id=e.delivery_effect_id AND d.tenant_id=e.tenant_id WHERE e.command_id=$1)`, string(handle.Binding.CommandID), command).Scan(&effects, &grants, &events, &audits, &deliveries)
		if err != nil || effects != count || grants != count || events != count || audits != count || deliveries != count {
			t.Fatal("resend atomic effect conservation", effects, grants, events, audits, deliveries, err)
		}
	}
	t.Run("live proof supersession and original history", func(t *testing.T) {
		inv := f.populated
		before, err := service.Get(ctx, organization.InvitationReadRequest{Authentication: f.owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "resend-before"})
		if err != nil || before.Invitation.Version != 1 || before.Invitation.IssuedVersion != 1 {
			t.Fatal("populated migration changed first issuance", err)
		}
		old := accept(inv, 1, 1)
		for _, variant := range []string{"recipient", "tenant", "organization", "stale-org", "stale-invitation"} {
			r := request(inv)
			switch variant {
			case "recipient":
				r.Authentication = f.recipient
			case "tenant":
				r.Authentication.TenantID = "foreign"
			case "organization":
				r.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
			case "stale-org":
				r.OrganizationVersion++
			case "stale-invitation":
				r.InvitationVersion++
			}
			if _, err := service.PrepareResend(ctx, r, "127.0.0.1"); err == nil {
				t.Fatal("unsafe resend admitted", variant)
			}
		}
		p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, err := p.Recovery()
		if err != nil {
			t.Fatal(err)
		}
		out, err := service.ExecuteResend(ctx, p)
		if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 || out.Delivery == nil || out.Delivery.State != delivery.StateQueued || out.Delivery.EffectID == before.EffectID {
			var started, retained, final bool
			id, _ := base64.RawURLEncoding.DecodeString(string(handle.Binding.CommandID))
			diagnostic := pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation IS NOT NULL,preparation_ciphertext IS NOT NULL,command_plan IS NOT NULL FROM identity.commands WHERE command_id=$1`, id).Scan(&started, &retained, &final)
			t.Log("redacted preparation boundary", "expiryUTC", before.Invitation.ExpiresAt.Location() == time.UTC, "signs", f.signer.calls.Load(), "started", started, "retained", retained, "final", final, "observation-error", diagnostic != nil)
			t.Fatal("exact resend not committed/queued", err)
		}
		signs := f.signer.calls.Load()
		if got, err := service.Execute(ctx, old); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("prepared predecessor consumed after supersession")
		}
		if _, err := f.newService(pool).PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, InvitationVersion: 2, OrganizationVersion: 1, Proof: inv.proof, CorrelationID: "old-proof-new-version"}, "127.0.0.1"); err == nil {
			t.Fatal("old proof admitted under successor version")
		}
		after, err := service.Get(ctx, organization.InvitationReadRequest{Authentication: f.owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "resend-after"})
		if err != nil || after.Invitation.Version != 2 || after.Invitation.IssuedVersion != 2 || !after.Invitation.ExpiresAt.Equal(before.Invitation.ExpiresAt) || after.Invitation.CreatedBy != before.Invitation.CreatedBy || after.Invitation.RecipientUserID != before.Invitation.RecipientUserID || after.Invitation.Role != organization.RoleMember {
			t.Fatal("resend retargeted or renewed invitation", err)
		}
		if retry, err := service.ExecuteResend(ctx, p); err != nil || retry.Receipt.AuditEventID != out.Receipt.AuditEventID || retry.Delivery == nil || *retry.Delivery != *out.Delivery {
			t.Fatal("original retry issued again", err)
		}
		if f.signer.calls.Load() != signs {
			t.Fatal("original retry regenerated a proof")
		}
		inv.proof = proof()
		// A later resend must not replace the original command's delivery identity.
		r := request(inv)
		r.InvitationVersion = 2
		second, err := service.PrepareResend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		next, err := service.ExecuteResend(ctx, second)
		if err != nil || next.Delivery == nil || next.Delivery.EffectID == out.Delivery.EffectID {
			t.Fatal("second resend lost original effect isolation", err)
		}
		inv.proof = proof()
		if got, err := service.Execute(ctx, accept(inv, 3, 1)); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.Feature.BeforeVersion != 3 || got.Receipt.Feature.AfterVersion != 4 {
			t.Fatal("successor proof did not create membership", err)
		}
		wire, err := json.Marshal(handle)
		if err != nil {
			t.Fatal(err)
		}
		var recovered organizationpg.InvitationRecovery
		if json.Unmarshal(wire, &recovered) != nil {
			t.Fatal("safe original correlation failed")
		}
		signs = f.signer.calls.Load()
		history, err := f.newService(pool).RecoverResend(ctx, f.signinOwner(), recovered)
		if err != nil || history.Receipt.AuditEventID != out.Receipt.AuditEventID || history.Delivery == nil || history.Delivery.EffectID != out.Delivery.EffectID || history.Delivery.State != delivery.StateAccepted {
			t.Fatal("recovery substituted latest invitation delivery", err)
		}
		if f.signer.calls.Load() != signs {
			t.Fatal("reconstruction regenerated a proof")
		}
		if _, err := f.newService(pool).RecoverResend(ctx, f.recipient, recovered); err == nil {
			t.Fatal("recipient recovered manager resend")
		}
		wrong := recovered
		wrong.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
		if _, err := f.newService(pool).RecoverResend(ctx, f.owner, wrong); err == nil {
			t.Fatal("foreign organization recovered original resend")
		}
		assertEffects(handle, 1)
		if got, err := f.worker.ProcessOne(ctx); err != nil || got.Claimed {
			t.Fatal("recovery redelivered original or successor", err)
		}
	})
	t.Run("rollback keeps predecessor usable", func(t *testing.T) {
		inv := f.issue("resend-rollback")
		p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, _ := p.Recovery()
		if _, err = pool.Raw().Exec(ctx, `ALTER TABLE organization.command_effects ADD CONSTRAINT resend_failure_fixture CHECK(operation<>'identity.organization.invitation.resend') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		out, failure := service.ExecuteResend(ctx, p)
		if _, err = pool.Raw().Exec(ctx, `ALTER TABLE organization.command_effects DROP CONSTRAINT resend_failure_fixture`); err != nil {
			t.Fatal(err)
		}
		if failure == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted || out.Delivery != nil {
			t.Fatal("failed resend fabricated a committed delivery")
		}
		assertEffects(handle, 0)
		if got, err := service.Execute(ctx, accept(inv, 1, 1)); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("rollback revoked predecessor", err)
		}
	})
	for _, terminal := range []string{"cancel", "reject", "expire"} {
		t.Run("later issued terminal "+terminal, func(t *testing.T) {
			inv := f.issue("resend-terminal-" + terminal)
			p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
			if err != nil {
				t.Fatal(err)
			}
			if out, err := service.ExecuteResend(ctx, p); err != nil || out.Delivery == nil {
				t.Fatal(err)
			}
			inv.proof = proof()
			var terminalCommand organizationpg.PreparedInvitation
			switch terminal {
			case "cancel":
				terminalCommand, err = service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: f.owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 2, CorrelationID: "resend-terminal"}, "127.0.0.1")
			case "reject":
				terminalCommand, err = service.PrepareReject(ctx, organization.InvitationRejectRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 2, CorrelationID: "resend-terminal"}, "127.0.0.1")
			case "expire":
				terminalCommand, err = service.PrepareExpire(ctx, organization.InvitationExpireRequest{Authentication: f.owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 2, Reason: "security-withdrawal", CorrelationID: "resend-terminal"}, "127.0.0.1")
			}
			if err != nil {
				t.Fatal("terminal after resend preparation", err)
			}
			if out, err := service.Execute(ctx, terminalCommand); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature.BeforeVersion != 2 || out.Receipt.Feature.AfterVersion != 3 {
				t.Fatal("later issued terminal did not advance exactly once", err)
			}
			metadata, err := service.Get(ctx, organization.InvitationReadRequest{Authentication: f.owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "resend-terminal-read"})
			if err != nil || metadata.Invitation.Version != 3 || metadata.Invitation.IssuedVersion != 2 || metadata.Invitation.Status == organization.InvitationPending {
				t.Fatal("terminal generation metadata lost", err)
			}
			r := request(inv)
			r.InvitationVersion = 3
			if _, err := service.PrepareResend(ctx, r, "127.0.0.1"); err == nil {
				t.Fatal("terminal state resurrected by resend")
			}
			if _, err := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: f.recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 2, Proof: inv.proof, CorrelationID: "resend-terminal-proof"}, "127.0.0.1"); err == nil {
				t.Fatal("terminal successor proof accepted")
			}
		})
	}
	t.Run("natural deadline cannot renew", func(t *testing.T) {
		inv := f.issue("resend-deadline")
		if _, err := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(inv.id)); err != nil {
			t.Fatal(err)
		}
		signs := f.signer.calls.Load()
		if _, err := service.PrepareResend(ctx, request(inv), "127.0.0.1"); err == nil {
			t.Fatal("elapsed grant renewed by resend")
		}
		if signs != f.signer.calls.Load() {
			t.Fatal("denied expiry generated proof")
		}
	})
	t.Run("current recipient identifier version fenced", func(t *testing.T) {
		inv := f.issue("resend-recipient-version")
		p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		out, failure := service.ExecuteResend(ctx, p)
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND kind='email'`, string(baselineTenant), string(f.recipientID)); err != nil {
			t.Fatal(err)
		}
		if failure == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted || out.Delivery != nil {
			t.Fatal("withdrawn original recipient version executed resend")
		}
		handle, _ := p.Recovery()
		assertEffects(handle, 0)
		if out, err := service.Execute(ctx, accept(inv, 1, 1)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("recipient denial corrupted predecessor", err)
		}
	})
	t.Run("accept versus resend contention", func(t *testing.T) {
		inv := f.issue("resend-race")
		p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		old := accept(inv, 1, 1)
		var wins atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, command := range []organizationpg.PreparedInvitation{p, old} {
			wg.Add(1)
			go func(command organizationpg.PreparedInvitation) {
				defer wg.Done()
				<-start
				out, err := service.Execute(ctx, command)
				if err == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					wins.Add(1)
				}
			}(command)
		}
		close(start)
		wg.Wait()
		var state string
		var effects, members int
		if err := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.resend')),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(f.recipientID)).Scan(&state, &effects, &members); err != nil || wins.Load() != 1 || effects != 1 || state != "accepted" && state != "pending" || (state == "accepted") != (members == 1) {
			t.Fatal("accept/resend created two authorities", err)
		}
		if state == "pending" {
			inv.proof = proof()
			if out, err := service.Execute(ctx, accept(inv, 2, 1)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("winning resend unusable", err)
			}
		}
	})
	t.Run("administrator result and current authority", func(t *testing.T) {
		inv := f.issue("resend-admin")
		admin := f.administrator
		add, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: admin.id, Role: organization.RoleAdministrator, CorrelationID: "resend-add-admin"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if out, err := f.organizations.Execute(ctx, add); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(err)
		}
		r := request(inv)
		r.Authentication = admin.authentication
		r.OrganizationVersion = 2
		p, err := service.PrepareResend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal("genuine administrator resend", err)
		}
		out, err := service.ExecuteResend(ctx, p)
		if err != nil || out.Delivery == nil || out.Delivery.State != delivery.StateQueued {
			t.Fatal("administrator lacks bounded delivery result", err)
		}
		if _, err := service.Get(ctx, organization.InvitationReadRequest{Authentication: admin.authentication, OrganizationID: inv.org, ID: inv.id, CorrelationID: "admin-read-denied"}); err == nil {
			t.Fatal("resend widened owner-only metadata")
		}
		handle, _ := p.Recovery()
		if got, err := f.newService(pool).RecoverResend(ctx, admin.signin(), handle); err != nil || got.Delivery == nil || got.Delivery.EffectID != out.Delivery.EffectID {
			t.Fatal("administrator original recovery", err)
		}
		inv.proof = proof()
		r = request(inv)
		r.Authentication = admin.authentication
		r.OrganizationVersion = 2
		r.InvitationVersion = 2
		stale, err := service.PrepareResend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		remove, err := f.organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: admin.id, MemberVersion: 1, CorrelationID: "resend-remove-admin"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.organizations.Execute(ctx, remove); err != nil {
			t.Fatal(err)
		}
		if got, err := service.ExecuteResend(ctx, stale); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted || got.Delivery != nil {
			t.Fatal("removed administrator executed resend")
		}
		if _, err := service.RecoverResend(ctx, admin.authentication, handle); err == nil {
			t.Fatal("removed administrator disclosed historical resend")
		}
		if got, err := service.Execute(ctx, accept(inv, 2, 3)); err != nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("authority denial revoked prior recipient proof", err)
		}
	})
	t.Run("known commit survives delivery metadata failure", func(t *testing.T) {
		inv := f.issue("resend-status-failure")
		f.statusPolicy.before = func(_ context.Context, d authorization.DecisionContext) error {
			if d.Request.Action == "identity.delivery.status-get" {
				return organization.ErrUnavailable
			}
			return nil
		}
		defer func() { f.statusPolicy.before = nil }()
		p, err := service.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		out, failure := service.ExecuteResend(ctx, p)
		if failure == nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Delivery != nil {
			t.Fatal("metadata failure erased executed commit or invented state")
		}
		handle, _ := p.Recovery()
		got, failure := service.RecoverResend(ctx, f.owner, handle)
		if failure == nil || got.Receipt.Outcome != identity.CommitOutcomeCommitted || got.Receipt.AuditEventID != out.Receipt.AuditEventID || got.Delivery != nil {
			t.Fatal("metadata failure erased known commit or invented state")
		}
		f.statusPolicy.before = nil
		inv.proof = proof()
	})
	t.Run("status callback withdraws current manager", func(t *testing.T) {
		inv := f.issue("resend-late-status")
		admin := f.administrator
		add, err := f.organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: admin.id, Role: organization.RoleAdministrator, CorrelationID: "resend-late-add"}, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.organizations.Execute(ctx, add); err != nil {
			t.Fatal(err)
		}
		r := request(inv)
		r.Authentication = admin.authentication
		r.OrganizationVersion = 2
		p, err := service.PrepareResend(ctx, r, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		fired := false
		f.statusPolicy.before = func(ctx context.Context, d authorization.DecisionContext) error {
			if fired || d.Request.Action != "identity.delivery.status-get" {
				return nil
			}
			fired = true
			remove, err := f.organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: f.owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: admin.id, MemberVersion: 1, CorrelationID: "resend-late-remove"}, "127.0.0.1")
			if err != nil {
				return err
			}
			_, err = f.organizations.Execute(ctx, remove)
			return err
		}
		defer func() { f.statusPolicy.before = nil }()
		out, failure := service.ExecuteResend(ctx, p)
		f.statusPolicy.before = nil
		if !fired || failure == nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Delivery != nil {
			t.Fatal("late manager withdrawal disclosed status or erased commit")
		}
		handle, _ := p.Recovery()
		assertEffects(handle, 1)
		inv.proof = proof()
		if out, err := service.Execute(ctx, accept(inv, 2, 3)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("late disclosure denial revoked committed successor", err)
		}
	})
	t.Run("lost final commit response recovers original only", func(t *testing.T) {
		inv := f.issue("resend-lost-ack")
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
		current := f.newService(primary)
		p, err := current.PrepareResend(ctx, request(inv), "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		handle, _ := p.Recovery()
		out, err := current.ExecuteResend(ctx, p)
		if err == nil || !fault.lost.Load() || out.Receipt.Outcome != identity.CommitOutcomeUnknown || out.Delivery != nil {
			t.Fatal("lost final COMMIT not unknown", out.Receipt.Outcome, err)
		}
		recovered, err := f.newService(pool).RecoverResend(ctx, f.signinOwner(), handle)
		if err != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Delivery == nil || recovered.Delivery.State != delivery.StateQueued {
			t.Fatal("code-free lost-COMMIT recovery", err)
		}
		assertEffects(handle, 1)
		inv.proof = proof()
		if out, err := service.Execute(ctx, accept(inv, 2, 1)); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("recovered successor unusable", err)
		}
	})
}

// The dedicated connection arms the existing response-loss transport only once
// final domain effects are written; acknowledged preparation has earlier commits.
// No domain SQL, transaction or coordinator outcome is replaced by this fault.
type resendCommitConn struct{ *lossyCommitConn }

func (c *resendCommitConn) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("INSERT INTO organization.command_effects")) {
		c.fault.count.Store(1)
		c.fault.armed.Store(true)
	}
	return c.Conn.Write(p)
}

// The real signer still authenticates every original grant; this counter only
// detects regeneration hidden behind an otherwise idempotent storage outcome.
type invitationResendSigner struct {
	capability.Signer
	calls atomic.Int32
}

func (s *invitationResendSigner) Sign(ctx context.Context, message []byte) ([]byte, error) {
	s.calls.Add(1)
	return s.Signer.Sign(ctx, message)
}
