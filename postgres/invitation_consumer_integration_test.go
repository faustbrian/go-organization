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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// The caller has just registered, confirmed and signed in both users through
// actual public identity HTTP/services. This continuation reuses those exact
// primary users and sessions, never SQL-created credentials or proof JSON.
func exerciseGenuineInvitations(t *testing.T, ctx context.Context, pool *database.Pool, db *sql.DB, organizations *organizationpg.Service, sessions *session.SessionService, profile sessionpg.IdentifierAdmissionConfig, lookup session.DigestKey, owner, recipient organization.Authentication, ownerID, recipientID identity.UserID, origin string, keys map[string][32]byte, material func(string) []byte, signinRecipient, signinOwner func() organization.Authentication, selectedProfile string, lifecycle *lifecycleConsumer, administrators ...invitationResendAdministrator) {
	t.Helper()
	readSteps, err := (organizationpg.InvitationMigrationSource{Version: 7001}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	capSteps, err := (organizationpg.InvitationCapabilityMigrationSource{Version: 7002}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	baseSteps, err := (organizationpg.MigrationSource{Version: 7000}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("organization")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationList(append(append(baseSteps, readSteps...), capSteps...)), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("populated organization invitation upgrade failed", err)
	}
	policy, err := fixtureAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Authorization: policy, Clock: clock.System{}, PolicyVersion: 9}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}
	provider, err := keyring.New(map[string][]byte{"delivery-envelope": material("delivery-envelope")})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	deliveryPolicy := delivery.DefaultConfig()
	deliveryPolicy.DedupeTTL = 72 * time.Hour
	deliveryPolicy.Production = true
	custody := deliverypg.ContributorConfig{Deployment: "deployment", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: keys["delivery-digest"]}, ActiveEnvelopeKeyID: "delivery-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{2: {Provider: "invitation-mailbox", PolicyVersion: 2}}}
	templates := []delivery.Template{{ID: "organization-invitation", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{origin}, MaxRenderedBytes: 4096}}
	statusPolicy := &invitationCancellationPolicy{base: policy}
	status, err := deliverypg.NewEnqueueService(ctx, pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: coordinator, PolicyID: "organization", PolicyVersion: 9, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: keys["delivery-namespace"], Policies: map[uint64]delivery.Config{2: deliveryPolicy}, StateTracking: true}, crypto, statusPolicy, templates)
	if err != nil {
		t.Fatal("invitation delivery graph rejected", err)
	}
	deliverer, err := deliverypg.NewContributor(custody, crypto)
	if err != nil {
		t.Fatal(err)
	}
	renderer, err := delivery.NewTemplateRenderer(templates)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := capability.NewHMACSHA256Signer("local-baseline", material("capability-signing"))
	if err != nil {
		t.Fatal(err)
	}
	countedSigner := &invitationResendSigner{Signer: signer}
	if selectedProfile == "resend" {
		signer = countedSigner
	}
	verifier, err := capability.NewHMACSHA256Verifier(material("capability-signing"))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: origin, ID: "local-baseline", Verifier: verifier}})
	if err != nil {
		t.Fatal(err)
	}
	limits := capability.DefaultLimits()
	limits.MaxLifetime = 48 * time.Hour
	riskPolicy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: riskPolicy, Keys: []risk.CounterDigestKey{digest}}, EnforceLockouts: true})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	configuration := organizationpg.InvitationServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000, ValidateCanonicalID: func(ctx context.Context, id organization.ID) error {
		_, err := identity.ParseSubjectID(string(id))
		return errors.Join(ctx.Err(), err)
	}}, Invitation: organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100}, Admission: organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, PolicyID: "organization", PolicyVersion: 9, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000}, Sessions: sessions, Authorization: policy, Coordinator: coordinator, Risk: counters, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: origin, Signer: signer, Resolver: resolver, Clock: time.Now, Limits: limits}, Audience: "organization-invitation", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: keys["capability-replay"]}, PreparationTimeout: time.Second}, Preparation: issuerpg.IssuancePreparationConfig{Deployment: "organization-invitation", ActiveEnvelopeKey: "capability-envelope", EnvelopeKeys: map[string][]byte{"capability-envelope": material("capability-envelope")}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "local-baseline", HMAC: material("capability-signing")}}, Clock: time.Now}, Delivery: organizationpg.InvitationDeliveryConfig{Owner: deliverer, Status: status, Renderer: renderer, Policy: deliveryPolicy, PolicyVersion: 2, ProviderVersion: 2, StatusPolicyVersion: 9, TemplateID: "organization-invitation", TemplateVersion: 1, LocaleChain: []string{"en"}, ScopeKey: keys["verification-scope"], Endpoint: origin + "/invitation"}}
	if selectedProfile == "expire" || selectedProfile == "resend" || selectedProfile == "lifecycle" {
		configuration.Invitation.ExpirationReasons = []identity.PolicyReason{"security-withdrawal", "administrative-cleanup"}
	}
	service, err := organizationpg.NewInvitationService(repository, configuration)
	if err != nil {
		t.Fatal("actual invitation composition rejected", err)
	}
	newService := func(primary *database.Pool) *organizationpg.InvitationService {
		t.Helper()
		r, e := organizationpg.NewRepository(primary, organizationpg.Config{MaximumDuration: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		s, e := organizationpg.NewInvitationService(r, configuration)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	identifiers, err := directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: baselineTenant, UserID: recipientID, MaximumIdentifiers: 128})
	if err != nil || len(identifiers.Identifiers) != 1 || !identifiers.Identifiers[0].Verified {
		t.Fatal("genuine recipient identifier unavailable", err)
	}
	mailbox := &registrationMailbox{}
	worker, err := status.NewWorker(deliverypg.WorkerConfig{ProviderConfigVersion: 2, Scope: authorization.DecisionContext{PolicyRevision: 9, CorrelationID: "invitation-worker", Request: authorization.Request{Tenant: baselineTenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "invitation-worker"}, Action: "identity.delivery.process", Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "invitation-worker"}}}}, mailbox)
	if err != nil {
		t.Fatal(err)
	}
	sendInvitation := func(orgID organization.ID, orgVersion uint64) issued {
		t.Helper()
		i, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		prepared, e := service.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(i), OrganizationID: orgID, OrganizationVersion: orgVersion, RecipientUserID: recipientID, RecipientIdentifierID: identifiers.Identifiers[0].ID, CorrelationID: "invitation-send"}, "127.0.0.1")
		if e != nil {
			t.Fatal("genuine owner invitation prepare failed", e)
		}
		result, e := service.Execute(ctx, prepared)
		if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.InvitationID != organization.ID(i) {
			t.Fatal("actual invitation send failed", result.Receipt.Outcome, e)
		}
		metadata, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: orgID, ID: organization.ID(i), CorrelationID: "invitation-read"})
		if e != nil || metadata.State != delivery.StateQueued || metadata.Invitation.Status != organization.InvitationPending || metadata.Invitation.CreatedBy != ownerID {
			t.Fatal("durable queued invitation metadata missing", e)
		}
		if _, e = worker.ProcessOne(ctx); e != nil {
			t.Fatal("actual encrypted invitation delivery failed", e)
		}
		mailbox.mu.Lock()
		link := mailbox.body
		mailbox.body = ""
		mailbox.mu.Unlock()
		u, e := url.Parse(link)
		if e != nil || u.Query().Get("token") == "" {
			t.Fatal("invitation sender did not receive capability")
		}
		proof, e := capability.ParseProof(u.Query().Get("token"), limits)
		if e != nil {
			t.Fatal("delivered capability invalid")
		}
		return issued{orgID, organization.ID(i), proof}
	}
	issue := func(slug string) issued {
		t.Helper()
		o, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		created, e := organizations.PrepareCreate(ctx, organization.CreateRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(o), Slug: slug, Name: "Invitation consumer", CorrelationID: "invitation-create"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := organizations.Execute(ctx, created); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine owner organization failed", e)
		}
		return sendInvitation(organization.ID(o), 1)
	}
	if selectedProfile == "resend" || selectedProfile == "lifecycle" {
		populated := issue("resend-populated")
		var history migrationList
		for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}, organizationpg.InvitationCancellationMigrationSource{Version: 7005}, organizationpg.InvitationRecipientIndexMigrationSource{Version: 7006}, organizationpg.InvitationRejectionMigrationSource{Version: 7007}, organizationpg.InvitationExpiryMigrationSource{Version: 7008}, organizationpg.InvitationResendMigrationSource{Version: 7009}} {
			steps, e := source.Load(ctx)
			if e != nil {
				t.Fatal(e)
			}
			history = append(history, steps...)
		}
		if selectedProfile == "lifecycle" {
			for _, source := range []migrations.Source{organizationpg.DynamicRoleMigrationSource{Version: 7010}, organizationpg.TeamRoleBindingMigrationSource{Version: 7011}, organizationpg.DomainClaimMigrationSource{Version: 7012}, organizationpg.LifecycleMigrationSource{Version: 7013}} {
				steps, e := source.Load(ctx)
				if e != nil {
					t.Fatal(e)
				}
				history = append(history, steps...)
			}
		}
		runner, e := migrations.NewRunner(history, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("populated resend upgrade", e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("resend migration replay", e)
		}
		if selectedProfile == "lifecycle" {
			exerciseGenuineLifecycle(t, ctx, pool, organizations, service, owner, recipient, recipientID, signinOwner, populated, sendInvitation, lifecycle)
			return
		}
		if len(administrators) != 1 {
			t.Fatal("genuine third administrator missing")
		}
		exerciseInvitationResend(t, invitationResendConsumer{ctx: ctx, pool: pool, organizations: organizations, service: service, configuration: configuration, newService: newService, issue: issue, worker: worker, mailbox: mailbox, limits: limits, owner: owner, recipient: recipient, ownerID: ownerID, recipientID: recipientID, signinOwner: signinOwner, signinRecipient: signinRecipient, administrator: administrators[0], populated: populated, statusPolicy: statusPolicy, signer: countedSigner})
		return
	}
	if selectedProfile == "expire" {
		populated := issue("expire-populated")
		var history migrationList
		for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}, organizationpg.InvitationCancellationMigrationSource{Version: 7005}, organizationpg.InvitationRecipientIndexMigrationSource{Version: 7006}, organizationpg.InvitationRejectionMigrationSource{Version: 7007}, organizationpg.InvitationExpiryMigrationSource{Version: 7008}} {
			steps, e := source.Load(ctx)
			if e != nil {
				t.Fatal(e)
			}
			history = append(history, steps...)
		}
		runner, e := migrations.NewRunner(history, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("populated explicit expiry upgrade", e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("explicit expiry migration replay", e)
		}
		request := func(inv issued) organization.InvitationExpireRequest {
			return organization.InvitationExpireRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "expire-pending"}
		}
		t.Run("live proof terminal expiry", func(t *testing.T) {
			inv := populated
			for _, variant := range []string{"recipient", "tenant", "org", "stale-org", "stale-invitation", "unregistered-reason"} {
				r := request(inv)
				switch variant {
				case "recipient":
					r.Authentication = recipient
				case "tenant":
					r.Authentication.TenantID = "foreign"
				case "org":
					r.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
				case "stale-org":
					r.OrganizationVersion++
				case "stale-invitation":
					r.InvitationVersion++
				case "unregistered-reason":
					r.Reason = "unregistered"
				}
				if _, e := service.PrepareExpire(ctx, r, "127.0.0.1"); e == nil {
					t.Fatal("unauthorized expiry admitted", variant)
				}
			}
			accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "expire-predecessor"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			expireRequest := request(inv)
			prepared, e := service.PrepareExpire(ctx, expireRequest, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			changed := expireRequest
			changed.Reason = "administrative-cleanup"
			changedPreparation, e := service.PrepareExpire(ctx, changed, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			result, e := service.Execute(ctx, prepared)
			if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Feature.BeforeVersion != 1 || result.Receipt.Feature.AfterVersion != 2 {
				t.Fatal("genuine explicit expiry failed", e)
			}
			if r, e := service.Execute(ctx, accept); e == nil || r.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("expired original proof committed membership")
			}
			if _, e := newService(pool).PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "expire-reconstructed"}, "127.0.0.1"); e == nil {
				t.Fatal("reconstructed service admitted expired proof")
			}
			metadata, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "expire-metadata"})
			if e != nil || metadata.Invitation.Status != organization.InvitationExpired || metadata.Invitation.Version != 2 || !time.Now().Before(metadata.Invitation.ExpiresAt) {
				t.Fatal("explicit expiry confused with natural projection", e)
			}
			page, e := service.List(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, Limit: 10, CorrelationID: "expire-list"})
			if e != nil || len(page.Invitations) != 1 || page.Invitations[0].Invitation.Status != organization.InvitationExpired || page.Invitations[0].Invitation.Version != 2 {
				t.Fatal("owner list lost explicit expiry", e)
			}
			mine, e := service.ListMine(ctx, organization.InvitationListMineRequest{Authentication: recipient, Limit: 10, CorrelationID: "expire-list-mine"})
			if e != nil || len(mine.Invitations) != 1 || mine.Invitations[0].Status != organization.InvitationExpired || mine.Invitations[0].Version != 2 {
				t.Fatal("recipient list lost explicit expiry", e)
			}
			if r, e := service.Execute(ctx, prepared); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted || r.Receipt.AuditEventID != result.Receipt.AuditEventID {
				t.Fatal("original expiry retry changed", e)
			}
			if _, e := service.Execute(ctx, changedPreparation); !errors.Is(e, organization.ErrConflict) {
				t.Fatal("same command accepted changed registered reason", e)
			}
			handle, e := prepared.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			if r, e := newService(pool).Recover(ctx, owner, handle); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("proof-free expiry recovery", e)
			}
			if _, e := newService(pool).Recover(ctx, recipient, handle); e == nil {
				t.Fatal("recipient recovered administrative expiry")
			}
			var members, effects, events, audits, orgVersion int
			var reason string
			id, e := base64.RawURLEncoding.DecodeString(string(result.Receipt.Binding.CommandID))
			if e != nil {
				t.Fatal(e)
			}
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),(SELECT count(*) FROM organization.command_effects WHERE command_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$5 AND m.topic='invitation.expired.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$5 AND r.action='identity.organization.expire_invitation' AND r.outcome=1),(SELECT version::integer FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2),expiry_reason FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$6`, string(baselineTenant), string(inv.org), string(recipientID), string(result.Receipt.Binding.CommandID), id, string(inv.id)).Scan(&members, &effects, &events, &audits, &orgVersion, &reason); e != nil || members != 0 || effects != 1 || events != 1 || audits != 1 || orgVersion != 1 || reason != "security-withdrawal" {
				t.Fatal("expiry atomic effects or reason missing", e)
			}
		})
		t.Run("natural projection becomes terminal once", func(t *testing.T) {
			inv := issue("expire-natural")
			if _, e := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(inv.id)); e != nil {
				t.Fatal(e)
			}
			before, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "expire-natural-before"})
			if e != nil || before.Invitation.Status != organization.InvitationExpired || before.Invitation.Version != 1 {
				t.Fatal("natural projection wrote terminal metadata", e)
			}
			prepared, e := service.PrepareExpire(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			if out, e := service.Execute(ctx, prepared); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("elapsed pending row could not terminalize", e)
			}
			after, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "expire-natural-after"})
			if e != nil || after.Invitation.Status != organization.InvitationExpired || after.Invitation.Version != 2 {
				t.Fatal("terminal expiry indistinguishable from projection", e)
			}
			if _, e := service.PrepareExpire(ctx, request(inv), "127.0.0.1"); e == nil {
				t.Fatal("terminal expiry admitted twice")
			}
		})
		t.Run("accept versus expire contention", func(t *testing.T) {
			inv := issue("expire-race")
			expire, e := service.PrepareExpire(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-expire-race"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			var wg sync.WaitGroup
			var wins atomic.Int32
			for _, p := range []organizationpg.PreparedInvitation{expire, accept} {
				wg.Add(1)
				go func(p organizationpg.PreparedInvitation) {
					defer wg.Done()
					out, e := service.Execute(ctx, p)
					if e == nil && out.Receipt.Outcome == identity.CommitOutcomeCommitted {
						wins.Add(1)
					}
				}(p)
			}
			wg.Wait()
			var state string
			var effects, members int
			if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.expire')),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(recipientID)).Scan(&state, &effects, &members); e != nil || wins.Load() != 1 || effects != 1 || state != "accepted" && state != "expired" || (state == "accepted") != (members == 1) {
				t.Fatal("accept/expire did not select one terminal outcome", e)
			}
		})
		for _, boundary := range []string{"audit", "event"} {
			t.Run("expiry rollback "+boundary, func(t *testing.T) {
				inv := issue("expire-rollback-" + boundary)
				prepared, e := service.PrepareExpire(ctx, request(inv), "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				table, condition := "audit.records", "NEW.action='identity.organization.expire_invitation' AND NEW.outcome=1"
				if boundary == "event" {
					table, condition = "public.outbox_messages", "NEW.topic='invitation.expired.v1'"
				}
				if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION organization.expiry_failure_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled expiry effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER expiry_failure_fixture BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.expiry_failure_fixture()`); e != nil {
					t.Fatal(e)
				}
				out, failure := service.Execute(ctx, prepared)
				if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER expiry_failure_fixture ON `+table+`; DROP FUNCTION organization.expiry_failure_fixture()`); e != nil {
					t.Fatal(e)
				}
				if failure == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("required expiry effect failure committed")
				}
				var state string
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.expire') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); e != nil || state != "pending" || effects != 0 {
					t.Fatal("failed expiry retained terminal effects", e)
				}
				accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-expiry-rollback"}, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				if out, e := service.Execute(ctx, accept); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("expiry rollback invalidated original proof", e)
				}
			})
		}
		t.Run("expiry lost commit acknowledgment", func(t *testing.T) {
			inv := issue("expire-lost-ack")
			fault := new(commitResponseLoss)
			faultPool, e := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
					if e != nil {
						return nil, e
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := faultPool.Close(cleanup); e != nil {
					t.Error(e)
				}
			}()
			faultService := newService(faultPool)
			prepared, e := faultService.PrepareExpire(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			handle, e := prepared.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			wire, e := json.Marshal(handle)
			if e != nil {
				t.Fatal(e)
			}
			var restored organizationpg.InvitationRecovery
			if json.Unmarshal(wire, &restored) != nil || restored != handle {
				t.Fatal("expiry correlation lost")
			}
			fault.armed.Store(true)
			out, e := faultService.Execute(ctx, prepared)
			if e == nil || !fault.lost.Load() || out.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("lost expiry acknowledgment not unknown", e)
			}
			if r, e := newService(pool).Recover(ctx, signinOwner(), restored); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted || r.Receipt.Binding != restored.Binding {
				t.Fatal("fresh-session proof-free expiry recovery", e)
			}
		})
		for _, stage := range []string{"execute", "management", "query", "replay"} {
			t.Run("expiry current administrator "+stage, func(t *testing.T) {
				inv := issue("expire-admin-" + stage)
				add, e := organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: recipientID, Role: organization.RoleAdministrator, CorrelationID: "expire-add-admin"}, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				if out, e := organizations.Execute(ctx, add); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(e)
				}
				hook := &invitationCancellationPolicy{base: policy}
				c := configuration
				c.Authorization = hook
				q := *configuration.Coordinator.QueryPolicy
				q.Authorization = hook
				c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &q
				current, e := organizationpg.NewInvitationService(repository, c)
				if e != nil {
					t.Fatal(e)
				}
				r := request(inv)
				r.Authentication = recipient
				r.OrganizationVersion = 2
				prepared, e := current.PrepareExpire(ctx, r, "127.0.0.1")
				if e != nil {
					t.Fatal("administrator expiry prepare", e)
				}
				if stage != "execute" {
					if out, e := current.Execute(ctx, prepared); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("administrator expiry", e)
					}
				}
				fired := false
				hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
					resource := "organization"
					if stage == "query" {
						resource = "identity.user"
					}
					if fired || d.Request.Action != authorization.Action(organization.InvitationExpire) || string(d.Request.Resource.Type) != resource {
						return nil
					}
					fired = true
					remove, e := organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: recipientID, MemberVersion: 1, CorrelationID: "expire-remove-admin"}, "127.0.0.1")
					if e != nil {
						return e
					}
					_, e = organizations.Execute(ctx, remove)
					return e
				}
				if stage == "execute" || stage == "replay" {
					if out, e := current.Execute(ctx, prepared); e == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
						t.Fatal("removed administrator executed/disclosed expiry", e)
					}
				} else {
					handle, e := prepared.Recovery()
					if e != nil {
						t.Fatal(e)
					}
					if out, e := current.Recover(ctx, recipient, handle); e == nil || out.Receipt.Outcome != identity.CommitOutcomeInvalid {
						t.Fatal("late removed administrator recovered expiry", e)
					}
				}
				if !fired {
					t.Fatal("authority withdrawal oracle did not run")
				}
			})
		}
		return
	}
	if selectedProfile == "reject" {
		var history migrationList
		for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}, organizationpg.InvitationCancellationMigrationSource{Version: 7005}, organizationpg.InvitationRecipientIndexMigrationSource{Version: 7006}, organizationpg.InvitationRejectionMigrationSource{Version: 7007}} {
			steps, e := source.Load(ctx)
			if e != nil {
				t.Fatal(e)
			}
			history = append(history, steps...)
		}
		populated := issue("reject-populated")
		acceptedBeforeUpgrade := issue("reject-already-accepted")
		acceptBeforeUpgrade, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: acceptedBeforeUpgrade.id, OrganizationID: acceptedBeforeUpgrade.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: acceptedBeforeUpgrade.proof, CorrelationID: "reject-before-upgrade"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := service.Execute(ctx, acceptBeforeUpgrade); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("existing acceptance before schema upgrade", e)
		}
		runner, e := migrations.NewRunner(history, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("populated rejection upgrade", e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("rejection migration replay", e)
		}
		if v, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: acceptedBeforeUpgrade.org, ID: acceptedBeforeUpgrade.id, CorrelationID: "reject-preserve-accepted"}); e != nil || v.Invitation.Status != organization.InvitationAccepted || v.Invitation.Version != 2 {
			t.Fatal("rejection migration changed accepted history", e)
		}
		request := func(inv issued) organization.InvitationRejectRequest {
			return organization.InvitationRejectRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "reject-pending"}
		}
		t.Run("genuine recipient terminal rejection", func(t *testing.T) {
			inv := populated
			for _, variant := range []string{"owner", "tenant", "organization", "stale-org", "stale-invitation"} {
				r := request(inv)
				switch variant {
				case "owner":
					r.Authentication = owner
				case "tenant":
					r.Authentication.TenantID = "foreign"
				case "organization":
					r.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAA"
				case "stale-org":
					r.OrganizationVersion++
				case "stale-invitation":
					r.InvitationVersion++
				}
				if _, e := service.PrepareReject(ctx, r, "127.0.0.1"); e == nil {
					t.Fatal("unauthorized rejection admitted", variant)
				}
			}
			accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "reject-predecessor"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			prepared, e := service.PrepareReject(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal("public genuine recipient rejection prepare", e)
			}
			result, e := service.Execute(ctx, prepared)
			if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Feature.BeforeVersion != 1 || result.Receipt.Feature.AfterVersion != 2 {
				t.Fatal("recipient rejection failed", e)
			}
			if r, e := service.Execute(ctx, accept); e == nil || r.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("rejected original capability accepted")
			}
			if _, e := newService(pool).PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "reject-reconstructed"}, "127.0.0.1"); e == nil {
				t.Fatal("reconstructed service accepted rejected proof")
			}
			if r, e := service.Execute(ctx, prepared); e != nil || r.Receipt.AuditEventID != result.Receipt.AuditEventID || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("keyed rejection retry changed", e)
			}
			handle, e := prepared.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			if r, e := newService(pool).Recover(ctx, recipient, handle); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("code-free rejection recovery", e)
			}
			if _, e := newService(pool).Recover(ctx, owner, handle); e == nil {
				t.Fatal("owner recovered recipient command")
			}
			metadata, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "rejected-metadata"})
			if e != nil || metadata.Invitation.Status != organization.InvitationRejected || metadata.Invitation.Version != 2 {
				t.Fatal("rejected metadata missing", e)
			}
			mine, e := service.ListMine(ctx, organization.InvitationListMineRequest{Authentication: recipient, Limit: 10, CorrelationID: "rejected-list-mine"})
			foundRejected := false
			for _, i := range mine.Invitations {
				if i.ID == inv.id && i.Status == organization.InvitationRejected {
					foundRejected = true
				}
			}
			if e != nil || !foundRejected {
				t.Fatal("rejected recipient listing missing", e)
			}
			var members, effects, audits, events, orgVersion int
			id, e := base64.RawURLEncoding.DecodeString(string(result.Receipt.Binding.CommandID))
			if e != nil {
				t.Fatal(e)
			}
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),(SELECT count(*) FROM organization.command_effects WHERE command_id=$4),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$5 AND r.action='identity.organization.reject_invitation' AND r.actor_id=$3 AND r.subject_id=$6 AND r.outcome=1),(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$5 AND m.topic='invitation.rejected.v1'),version::integer FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(baselineTenant), string(inv.org), string(recipientID), string(result.Receipt.Binding.CommandID), id, string(inv.id)).Scan(&members, &effects, &audits, &events, &orgVersion); e != nil || members != 0 || effects != 1 || audits != 1 || events != 1 || orgVersion != 1 {
				t.Fatal("rejection changed membership/organization or lost atomic effects", e)
			}
		})
		t.Run("accept versus reject contention", func(t *testing.T) {
			inv := issue("reject-race")
			reject, e := service.PrepareReject(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-reject-race"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			var wg sync.WaitGroup
			var wins atomic.Int32
			for _, p := range []organizationpg.PreparedInvitation{reject, accept} {
				wg.Add(1)
				go func(p organizationpg.PreparedInvitation) {
					defer wg.Done()
					r, e := service.Execute(ctx, p)
					if e == nil && r.Receipt.Outcome == identity.CommitOutcomeCommitted {
						wins.Add(1)
					}
				}(p)
			}
			wg.Wait()
			var state string
			var members, effects int
			if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active'),(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$4 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.reject')) FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$4`, string(baselineTenant), string(inv.org), string(recipientID), string(inv.id)).Scan(&state, &members, &effects); e != nil || wins.Load() != 1 || effects != 1 || state != "accepted" && state != "rejected" || (state == "accepted") != (members == 1) {
				t.Fatal("accept/reject did not select exactly one terminal effect", e)
			}
		})
		for _, boundary := range []string{"audit", "event"} {
			t.Run("rejection rollback "+boundary, func(t *testing.T) {
				inv := issue("reject-rollback-" + boundary)
				prepared, e := service.PrepareReject(ctx, request(inv), "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				table, condition := "audit.records", "NEW.action='identity.organization.reject_invitation' AND NEW.outcome=1"
				if boundary == "event" {
					table, condition = "public.outbox_messages", "NEW.topic='invitation.rejected.v1'"
				}
				if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_terminal_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled rejection effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_terminal_fixture BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.reject_terminal_fixture()`); e != nil {
					t.Fatal(e)
				}
				result, failure := service.Execute(ctx, prepared)
				if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER reject_terminal_fixture ON `+table+`; DROP FUNCTION organization.reject_terminal_fixture()`); e != nil {
					t.Fatal(e)
				}
				if failure == nil || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("required rejection effect failure committed")
				}
				var state string
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation='identity.organization.invitation.reject') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant)).Scan(&state, &effects); e != nil || state != "pending" || effects != 0 {
					t.Fatal("rejection rollback retained terminal effect", e)
				}
				accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-reject-rollback"}, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				if r, e := service.Execute(ctx, accept); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("rollback consumed original invitation proof", e)
				}
			})
		}
		t.Run("rejection lost commit acknowledgment", func(t *testing.T) {
			inv := issue("reject-lost-ack")
			fault := new(commitResponseLoss)
			faultPool, e := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
					if e != nil {
						return nil, e
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := faultPool.Close(cleanup); e != nil {
					t.Error(e)
				}
			}()
			faultService := newService(faultPool)
			prepared, e := faultService.PrepareReject(ctx, request(inv), "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			handle, e := prepared.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			wire, e := json.Marshal(handle)
			if e != nil {
				t.Fatal(e)
			}
			var restored organizationpg.InvitationRecovery
			if json.Unmarshal(wire, &restored) != nil || restored != handle {
				t.Fatal("safe rejection correlation changed")
			}
			fault.armed.Store(true)
			result, e := faultService.Execute(ctx, prepared)
			if e == nil || !fault.lost.Load() || result.Receipt.Outcome != identity.CommitOutcomeUnknown {
				t.Fatal("lost rejection acknowledgment was not unknown", e)
			}
			if r, e := newService(pool).Recover(ctx, signinRecipient(), restored); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted || r.Receipt.Binding != restored.Binding {
				t.Fatal("fresh-session code-free rejection recovery failed", e)
			}
		})
		for _, withdrawal := range []string{"session", "identifier", "organization", "expiry"} {
			t.Run("rejection current authority "+withdrawal, func(t *testing.T) {
				inv := issue("reject-withdraw-" + withdrawal)
				actual := signinRecipient()
				r := request(inv)
				r.Authentication = actual
				prepared, e := service.PrepareReject(ctx, r, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				// This controlled fixture withdraws primary authority after genuine
				// public preparation; it never fabricates a credential or grant.
				switch withdrawal {
				case "session":
					token, e := session.ParseToken(actual.Bearer.Token())
					if e != nil {
						t.Fatal(e)
					}
					credential, e := session.NewCredential(session.CredentialBearer, token)
					if e != nil {
						t.Fatal(e)
					}
					observed, e := sessions.Get(ctx, session.GetRequest{TenantID: actual.TenantID, Credential: credential})
					if e != nil {
						t.Fatal(e)
					}
					b, e := observed.Session.Bindings()
					if e != nil {
						t.Fatal(e)
					}
					_, e = pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(baselineTenant), b.SessionID)
					if e != nil {
						t.Fatal(e)
					}
				case "identifier":
					_, e = pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(baselineTenant), string(recipientID), string(identifiers.Identifiers[0].ID))
					if e != nil {
						t.Fatal(e)
					}
					defer func() {
						if _, e := pool.Raw().Exec(ctx, `UPDATE identity.identifiers SET version=version-1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3`, string(baselineTenant), string(recipientID), string(identifiers.Identifiers[0].ID)); e != nil {
							t.Error(e)
						}
					}()
				case "organization":
					update, e := organizations.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, Name: "Changed rejection policy", Slug: "reject-updated", CorrelationID: "reject-policy-change"}, "127.0.0.1")
					if e != nil {
						t.Fatal(e)
					}
					if out, e := organizations.Execute(ctx, update); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal(e)
					}
				case "expiry":
					if _, e := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(inv.id)); e != nil {
						t.Fatal(e)
					}
				}
				if out, e := service.Execute(ctx, prepared); e == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
					t.Fatal("withdrawn authority committed rejection")
				}
			})
		}
		for _, resource := range []string{"organization", "identity.user"} {
			t.Run("rejection recovery late session "+resource, func(t *testing.T) {
				inv := issue("reject-recovery-" + strings.ReplaceAll(resource, ".", "-"))
				actual := signinRecipient()
				r := request(inv)
				r.Authentication = actual
				prepared, e := service.PrepareReject(ctx, r, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				if out, e := service.Execute(ctx, prepared); e != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal(e)
				}
				handle, e := prepared.Recovery()
				if e != nil {
					t.Fatal(e)
				}
				token, e := session.ParseToken(actual.Bearer.Token())
				if e != nil {
					t.Fatal(e)
				}
				credential, e := session.NewCredential(session.CredentialBearer, token)
				if e != nil {
					t.Fatal(e)
				}
				observed, e := sessions.Get(ctx, session.GetRequest{TenantID: actual.TenantID, Credential: credential})
				if e != nil {
					t.Fatal(e)
				}
				b, e := observed.Session.Bindings()
				if e != nil {
					t.Fatal(e)
				}
				hook := &invitationCancellationPolicy{base: policy}
				c := configuration
				c.Authorization = hook
				q := *configuration.Coordinator.QueryPolicy
				q.Authorization = hook
				c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &q
				current, e := organizationpg.NewInvitationService(repository, c)
				if e != nil {
					t.Fatal(e)
				}
				fired := false
				hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
					if fired || d.Request.Action != authorization.Action(organization.InvitationReject) || string(d.Request.Resource.Type) != resource {
						return nil
					}
					fired = true
					_, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(baselineTenant), b.SessionID)
					return e
				}
				if out, e := current.Recover(ctx, actual, handle); e == nil || out.Receipt.Outcome != identity.CommitOutcomeInvalid || !fired {
					t.Fatal("late session withdrawal disclosed rejection receipt", e)
				}
			})
		}
		return
	}
	if selectedProfile == "mine" {
		first, second, third := issue("mine-pending"), issue("mine-cancelled"), issue("mine-accepted")
		var history migrationList
		for _, source := range []migrations.Source{organizationpg.MigrationSource{Version: 7000}, organizationpg.InvitationMigrationSource{Version: 7001}, organizationpg.InvitationCapabilityMigrationSource{Version: 7002}, organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}, organizationpg.InvitationCancellationMigrationSource{Version: 7005}, organizationpg.InvitationRecipientIndexMigrationSource{Version: 7006}} {
			steps, e := source.Load(ctx)
			if e != nil {
				t.Fatal(e)
			}
			history = append(history, steps...)
		}
		runner, e := migrations.NewRunner(history, backend)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("populated recipient-index migration", e)
		}
		if _, e = runner.Up(ctx); e != nil {
			t.Fatal("recipient-index migration replay", e)
		}
		cancel, e := service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "mine-cancel"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := service.Execute(ctx, cancel); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(e)
		}
		accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: third.id, OrganizationID: third.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: third.proof, CorrelationID: "mine-accept"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := service.Execute(ctx, accept); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal(e)
		}
		for _, inv := range []issued{first, second} {
			if _, e := organizations.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: inv.org, CorrelationID: "mine-no-membership"}); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("recipient fixture unexpectedly has membership", e)
			}
		}
		request := organization.InvitationListMineRequest{Authentication: recipient, Limit: 1, CorrelationID: "mine"}
		var found []organization.Invitation
		var firstCursor organization.InvitationCursor
		for range 4 {
			page, e := service.ListMine(ctx, request)
			if e != nil {
				t.Fatal("genuine recipient listing", e)
			}
			if len(page.Invitations) != 1 {
				t.Fatal("recipient page lost expected record")
			}
			found = append(found, page.Invitations...)
			if page.NextCursor == "" {
				break
			}
			if firstCursor == "" {
				firstCursor = page.NextCursor
			}
			request.Cursor = page.NextCursor
		}
		expected := []organization.ID{first.id, second.id, third.id}
		sort.Slice(expected, func(a, b int) bool { return expected[a] < expected[b] })
		if len(found) != 3 {
			t.Fatal("recipient listing did not terminate exactly")
		}
		for n, i := range found {
			if i.ID != expected[n] || i.RecipientUserID != recipientID {
				t.Fatal("recipient keyset lost scope/order")
			}
		}
		statuses := map[organization.ID]organization.InvitationStatus{}
		for _, i := range found {
			statuses[i.ID] = i.Status
		}
		if statuses[first.id] != organization.InvitationPending || statuses[second.id] != organization.InvitationCancelled || statuses[third.id] != organization.InvitationAccepted {
			t.Fatal("recipient lifecycle visibility silently filtered")
		}
		wire, e := json.Marshal(found)
		if e != nil || strings.Contains(string(wire), "@") || strings.Contains(string(wire), "Proof") || strings.Contains(string(wire), "Ciphertext") || strings.Contains(string(wire), "CanonicalValue") {
			t.Fatal("recipient metadata leaked secret/address")
		}
		if page, e := service.ListMine(ctx, organization.InvitationListMineRequest{Authentication: owner, Limit: 200, CorrelationID: "mine-other-user"}); e != nil || len(page.Invitations) != 0 {
			t.Fatal("creator listed another recipient's invitation", e)
		}
		wrong := organization.InvitationListMineRequest{Authentication: owner, Limit: 1, Cursor: firstCursor, CorrelationID: "mine-cursor-scope"}
		if _, e := service.ListMine(ctx, wrong); !errors.Is(e, organization.ErrInvalidInput) {
			t.Fatal("recipient cursor transferred to creator", e)
		}
		wrong.Authentication = recipient
		wrong.Authentication.TenantID = "foreign-tenant"
		if _, e := service.ListMine(ctx, wrong); e == nil {
			t.Fatal("recipient bearer crossed tenant")
		}
		for _, invalid := range []organization.InvitationListMineRequest{{Authentication: recipient, Limit: 201, CorrelationID: "mine-invalid"}, {Authentication: recipient, Limit: 1, Cursor: organization.InvitationCursor(strings.Repeat("x", 513)), CorrelationID: "mine-invalid"}} {
			if _, e := service.ListMine(ctx, invalid); !errors.Is(e, organization.ErrInvalidInput) {
				t.Fatal("unbounded recipient request admitted", e)
			}
		}
		if _, e := pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(first.id)); e != nil {
			t.Fatal(e)
		}
		page, e := service.ListMine(ctx, organization.InvitationListMineRequest{Authentication: recipient, Limit: 200, CorrelationID: "mine-expired"})
		if e != nil {
			t.Fatal(e)
		}
		for _, i := range page.Invitations {
			if i.ID == first.id && i.Status != organization.InvitationExpired {
				t.Fatal("recipient expiry projection stale")
			}
		}
		t.Run("list mine bounded native query plan", func(t *testing.T) { exerciseInvitationMinePlan(t, ctx, pool, newService, recipient, third.id) })
		for _, withdrawal := range []string{"cancel", "session"} {
			for _, stage := range []int{1, 2} {
				t.Run("list mine late "+withdrawal+strconv.Itoa(stage), func(t *testing.T) {
					inv := issue("mine-late-" + withdrawal + strconv.Itoa(stage))
					actual := recipient
					var sessionID string
					if withdrawal == "session" {
						actual = signinRecipient()
						parsed, e := session.ParseToken(actual.Bearer.Token())
						if e != nil {
							t.Fatal(e)
						}
						credential, e := session.NewCredential(session.CredentialBearer, parsed)
						if e != nil {
							t.Fatal(e)
						}
						current, e := sessions.Get(ctx, session.GetRequest{TenantID: actual.TenantID, Credential: credential})
						if e != nil {
							t.Fatal(e)
						}
						bindings, e := current.Session.Bindings()
						if e != nil {
							t.Fatal(e)
						}
						sessionID = bindings.SessionID
					}
					hook := &invitationCancellationPolicy{base: policy}
					calls := 0
					hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
						if d.Request.Action != authorization.Action(organization.InvitationListMine) {
							return nil
						}
						calls++
						if calls != stage {
							return nil
						}
						if d.Request.Resource.Type != "identity.user" || string(d.Request.Resource.ID) != string(recipientID) || string(d.Request.Subject.ID) != string(recipientID) {
							return identity.ForbiddenError{}
						}
						if withdrawal == "session" {
							_, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(baselineTenant), sessionID)
							return e
						}
						p, e := service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "mine-late-cancel"}, "127.0.0.1")
						if e != nil {
							return e
						}
						_, e = service.Execute(ctx, p)
						return e
					}
					c := configuration
					c.Authorization = hook
					selected, e := organizationpg.NewInvitationService(repository, c)
					if e != nil {
						t.Fatal(e)
					}
					result, e := selected.ListMine(ctx, organization.InvitationListMineRequest{Authentication: actual, Limit: 200, CorrelationID: "mine-late"})
					if e == nil || len(result.Invitations) != 0 || result.NextCursor != "" || calls < stage {
						t.Fatal("late recipient/session withdrawal released stale partial page", e)
					}
				})
			}
		}
		t.Run("list mine current identifier withdrawal", func(t *testing.T) {
			hook := &invitationCancellationPolicy{base: policy}
			fired := false
			hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
				if fired || d.Request.Action != authorization.Action(organization.InvitationListMine) {
					return nil
				}
				fired = true
				// Controlled withdrawal of the actual directory owner's verified
				// identifier/epoch, never a replacement session or identity reader.
				_, e := pool.Raw().Exec(ctx, `WITH withdrawn AS (UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=verification_version+1,version=version+1 WHERE tenant_id=$1 AND user_id=$2 AND identifier_id=$3 RETURNING user_id) UPDATE identity.users SET identifier_version=identifier_version+1 WHERE tenant_id=$1 AND user_id IN(SELECT user_id FROM withdrawn)`, string(baselineTenant), string(recipientID), string(identifiers.Identifiers[0].ID))
				return e
			}
			c := configuration
			c.Authorization = hook
			selected, e := organizationpg.NewInvitationService(repository, c)
			if e != nil {
				t.Fatal(e)
			}
			result, e := selected.ListMine(ctx, organization.InvitationListMineRequest{Authentication: recipient, Limit: 200, CorrelationID: "mine-identifier-withdrawal"})
			if e == nil || !fired || len(result.Invitations) != 0 || result.NextCursor != "" {
				t.Fatal("withdrawn verified identifier released stale page", e)
			}
			state, e := directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: baselineTenant, UserID: recipientID, MaximumIdentifiers: 128})
			if e != nil || state.AuthorityVersion <= 1 || len(state.Identifiers) != 1 || state.Identifiers[0].Verified {
				t.Fatal("actual identifier authority oracle did not withdraw", e)
			}
		})
		return
	}
	if selectedProfile == "cancel" {
		cancelSteps, err := (organizationpg.InvitationCancellationMigrationSource{Version: 7005}).Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// A real issued row must survive the forward lifecycle extension.
		populated := issue("invitation-cancel-populated")
		history := append(append(baseSteps, readSteps...), capSteps...)
		for _, source := range []migrations.Source{organizationpg.TeamMigrationSource{Version: 7003}, organizationpg.TeamLifecycleMigrationSource{Version: 7004}} {
			steps, err := source.Load(ctx)
			if err != nil {
				t.Fatal(err)
			}
			history = append(history, steps...)
		}
		runner, err = migrations.NewRunner(migrationList(append(history, cancelSteps...)), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = runner.Up(ctx); err != nil {
			t.Fatal("populated cancellation upgrade", err)
		}
		if _, err = runner.Up(ctx); err != nil {
			t.Fatal("cancellation migration replay", err)
		}
		if metadata, err := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: populated.org, ID: populated.id, CorrelationID: "cancel-upgrade"}); err != nil || metadata.Invitation.Status != organization.InvitationPending || metadata.Invitation.Version != 1 {
			t.Fatal("forward cancellation migration changed pending row", err)
		}
		// Withdraw a genuinely delivered grant without borrowing recipient proof as
		// administrator authority. The already prepared accept must lose atomically.
		t.Run("cancel genuine pending invitation", func(t *testing.T) {
			inv := issue("invitation-cancel")
			for _, denied := range []string{"nonmember", "foreign-tenant", "cross-org", "stale-org", "stale-invitation"} {
				r := organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "cancel-denied"}
				switch denied {
				case "nonmember":
					r.Authentication = recipient
				case "foreign-tenant":
					r.Authentication.TenantID = "foreign-tenant"
				case "cross-org":
					r.OrganizationID = populated.org
				case "stale-org":
					r.OrganizationVersion++
				case "stale-invitation":
					r.InvitationVersion++
				}
				if _, e := service.PrepareCancel(ctx, r, "127.0.0.1"); e == nil {
					t.Fatal("invalid native cancellation admitted", denied)
				}
			}
			accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "cancel-predecessor"}, "127.0.0.1")
			if e != nil {
				t.Fatal("genuine predecessor acceptance prepare", e)
			}
			cancel, e := service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "cancel-pending"}, "127.0.0.1")
			if e != nil {
				t.Fatal("genuine cancellation prepare", e)
			}
			result, e := service.Execute(ctx, cancel)
			if e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted || result.Receipt.Feature.BeforeVersion != 1 || result.Receipt.Feature.AfterVersion != 2 {
				t.Fatal("genuine cancellation failed", e)
			}
			if r, e := service.Execute(ctx, accept); e == nil || r.Receipt.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("cancelled predecessor proof committed")
			}
			if _, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "cancel-predecessor-retry"}, "127.0.0.1"); e == nil {
				t.Fatal("cancelled proof prepared again")
			}
			metadata, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: inv.org, ID: inv.id, CorrelationID: "cancel-metadata"})
			if e != nil || metadata.Invitation.Status != organization.InvitationCancelled || metadata.Invitation.Version != 2 {
				t.Fatal("cancelled terminal metadata missing", e)
			}
			proofVerifier, e := capability.NewService(configuration.Issuer.Crypto)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = proofVerifier.Verify(ctx, inv.proof, capability.Purpose(organization.InvitationAccept), configuration.Invitation.Audience); e != nil {
				t.Fatal("test did not retain cryptographically valid predecessor", e)
			}
			if r, e := service.Execute(ctx, cancel); e != nil || r.Receipt.Binding != result.Receipt.Binding || r.Receipt.AuditEventID != result.Receipt.AuditEventID || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("original cancellation replay changed", e)
			}
			handle, e := cancel.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			if r, e := newService(pool).Recover(ctx, owner, handle); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
				t.Fatal("metadata-only cancelled recovery failed", e)
			}
			wrong := handle
			wrong.OrganizationID = populated.org
			if _, e := newService(pool).Recover(ctx, owner, wrong); e == nil {
				t.Fatal("cancel recovery trusted caller-substituted organization")
			}
			id, e := base64.RawURLEncoding.DecodeString(string(result.Receipt.Binding.CommandID))
			if e != nil {
				t.Fatal(e)
			}
			var effects, events, members, audits int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$5 AND m.topic='invitation.cancelled.v1'),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$5 AND r.action='identity.organization.cancel_invitation' AND r.actor_id=$6 AND r.subject_id=$7 AND r.outcome=$8)`, string(result.Receipt.Binding.CommandID), string(baselineTenant), string(inv.org), string(recipientID), id, string(ownerID), string(inv.id), int16(audit.OutcomeSucceeded)).Scan(&effects, &events, &members, &audits); e != nil || effects != 1 || events != 1 || members != 0 || audits != 1 {
				t.Fatal("cancel duplicate effect or leaked membership", e)
			}
			if _, e := service.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 2, CorrelationID: "cancel-terminal"}, "127.0.0.1"); e == nil {
				t.Fatal("terminal cancellation was prepared again")
			}
		})
		for _, race := range []string{"accept-cancel", "cancel-cancel"} {
			t.Run("cancel contention "+race, func(t *testing.T) {
				inv := issue("invitation-" + race)
				cancelRequest := organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "cancel-race"}
				left, e := service.PrepareCancel(ctx, cancelRequest, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				var right organizationpg.PreparedInvitation
				if race == "accept-cancel" {
					right, e = service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-race"}, "127.0.0.1")
				} else {
					cancelRequest.CommandID = commandID(t)
					right, e = service.PrepareCancel(ctx, cancelRequest, "127.0.0.1")
				}
				if e != nil {
					t.Fatal(e)
				}
				start := make(chan struct{})
				results := make(chan organization.StoreResult, 2)
				for _, prepared := range []organizationpg.PreparedInvitation{left, right} {
					go func() { <-start; result, _ := service.Execute(ctx, prepared); results <- result }()
				}
				close(start)
				wins := 0
				for range 2 {
					if (<-results).Receipt.Outcome == identity.CommitOutcomeCommitted {
						wins++
					}
				}
				if wins != 1 {
					t.Fatal("terminal contention did not have exactly one winner", wins)
				}
				var terminal string
				var count, active int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id=$1 AND operation IN('identity.organization.invitation.accept','identity.organization.invitation.cancel')),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$2 AND organization_id=$3 AND user_id=$4 AND state='active') FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$1`, string(inv.id), string(baselineTenant), string(inv.org), string(recipientID)).Scan(&terminal, &count, &active); e != nil || count != 1 || terminal != "accepted" && terminal != "cancelled" || (terminal == "accepted") != (active == 1) {
					t.Fatal("terminal contention retained inconsistent effects", e)
				}
			})
		}
		for _, boundary := range []string{"audit", "outbox"} {
			t.Run("cancel atomic "+boundary+" failure", func(t *testing.T) {
				inv := issue("invitation-cancel-" + boundary)
				request := organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "cancel-rollback"}
				prepared, e := service.PrepareCancel(ctx, request, "127.0.0.1")
				if e != nil {
					t.Fatal(e)
				}
				table, condition := "audit.records", "NEW.action='identity.organization.cancel_invitation' AND NEW.outcome=1"
				if boundary == "outbox" {
					table, condition = "public.outbox_messages", "NEW.topic='invitation.cancelled.v1'"
				}
				if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_cancel_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='controlled cancellation effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_cancel_fixture BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION organization.reject_cancel_fixture()`); e != nil {
					t.Fatal(e)
				}
				result, failure := service.Execute(ctx, prepared)
				if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER reject_cancel_fixture ON `+table+`; DROP FUNCTION organization.reject_cancel_fixture()`); e != nil {
					t.Fatal(e)
				}
				if failure == nil || result.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("required cancellation effect failure did not roll back", failure)
				}
				var state string
				var effects int
				if e := pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE command_id=$1) FROM organization.invitations WHERE tenant_id=$2 AND invitation_id=$3`, string(request.CommandID), string(baselineTenant), string(inv.id)).Scan(&state, &effects); e != nil || state != "pending" || effects != 0 {
					t.Fatal("failed cancellation retained terminal effect", e)
				}
				accept, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: inv.proof, CorrelationID: "accept-after-cancel-rollback"}, "127.0.0.1")
				if e != nil {
					t.Fatal("cancel rollback consumed predecessor proof", e)
				}
				if result, e := service.Execute(ctx, accept); e != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
					t.Fatal("predecessor proof unusable after cancellation rollback", e)
				}
			})
		}
		for _, stage := range []string{"execute", "management", "query", "replay"} {
			for _, withdrawal := range []string{"member", "session", "epoch"} {
				if stage == "replay" && withdrawal != "member" {
					continue
				}
				t.Run("cancel current authority "+stage+" "+withdrawal, func(t *testing.T) {
					inv := issue("cancel-" + stage + "-" + withdrawal)
					admin := recipient
					if withdrawal == "session" {
						admin = signinRecipient()
					} // Withdraw only an additional genuinely issued session.
					add, e := organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 1, UserID: recipientID, Role: organization.RoleAdministrator, CorrelationID: "cancel-admin"}, "127.0.0.1")
					if e != nil {
						t.Fatal(e)
					}
					if r, e := organizations.Execute(ctx, add); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
						t.Fatal("genuine administrator admission", e)
					}
					token, e := session.ParseToken(admin.Bearer.Token())
					if e != nil {
						t.Fatal(e)
					}
					credential, e := session.NewCredential(session.CredentialBearer, token)
					if e != nil {
						t.Fatal(e)
					}
					observed, e := sessions.Get(ctx, session.GetRequest{TenantID: admin.TenantID, Credential: credential})
					if e != nil {
						t.Fatal(e)
					}
					bound, e := observed.Session.Bindings()
					if e != nil {
						t.Fatal(e)
					}
					hook := &invitationCancellationPolicy{base: policy}
					c := configuration
					c.Authorization = hook
					q := *configuration.Coordinator.QueryPolicy
					q.Authorization = hook
					c.Coordinator.QueryPolicy, c.Coordinator.AdmissionPolicy = &q, &q
					current, e := organizationpg.NewInvitationService(repository, c)
					if e != nil {
						t.Fatal(e)
					}
					prepared, e := current.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: admin, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 2, InvitationVersion: 1, CorrelationID: "cancel-current"}, "127.0.0.1")
					if e != nil {
						t.Fatal("genuine administrator cancel prepare", e)
					}
					if stage != "execute" {
						if r, e := current.Execute(ctx, prepared); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
							t.Fatal("genuine administrator cancellation", e)
						}
					}
					fired := false
					hook.before = func(ctx context.Context, d authorization.DecisionContext) error {
						resource := "organization"
						if stage == "query" {
							resource = "identity.user"
						}
						if fired || d.Request.Action != authorization.Action(organization.InvitationCancel) || d.Request.Resource.Type != authorization.ResourceType(resource) {
							return nil
						}
						fired = true
						switch withdrawal {
						case "session":
							_, e := pool.Raw().Exec(ctx, `UPDATE session_store.sessions SET state='revoked' WHERE tenant_id=$1 AND session_id=$2`, string(admin.TenantID), bound.SessionID)
							return e
						case "epoch":
							p, e := organizations.PrepareUpdate(ctx, organization.UpdateRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, Name: "Changed cancellation policy", Slug: "changed-" + stage + "-" + withdrawal, CorrelationID: "cancel-policy-change"}, "127.0.0.1")
							if e != nil {
								return e
							}
							_, e = organizations.Execute(ctx, p)
							return e
						default:
							p, e := organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: inv.org, OrganizationVersion: 2, UserID: recipientID, MemberVersion: 1, CorrelationID: "cancel-admin-removal"}, "127.0.0.1")
							if e != nil {
								return e
							}
							_, e = organizations.Execute(ctx, p)
							return e
						}
					}
					if stage == "execute" || stage == "replay" {
						r, e := current.Execute(ctx, prepared)
						if e == nil || r.Receipt.Outcome == identity.CommitOutcomeCommitted {
							t.Fatal("withdrawn administrator committed cancellation")
						}
					} else {
						handle, e := prepared.Recovery()
						if e != nil {
							t.Fatal(e)
						}
						if r, e := current.Recover(ctx, admin, handle); !errors.Is(e, organization.ErrForbidden) || r.Receipt.Outcome != identity.CommitOutcomeInvalid {
							t.Fatal("late authority withdrawal disclosed retained cancellation", e)
						}
					}
					if !fired {
						t.Fatal("current authority oracle did not execute")
					}
				})
			}
		}
		t.Run("cancel lost acknowledgment recovery", func(t *testing.T) {
			inv := issue("invitation-cancel-lost-ack")
			fault := new(commitResponseLoss)
			faultPool, e := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
					conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
					if e != nil {
						return nil, e
					}
					return &lossyCommitConn{Conn: conn, fault: fault}, nil
				}
				return nil
			}})
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if e := faultPool.Close(cleanup); e != nil {
					t.Error(e)
				}
			}()
			faultService := newService(faultPool)
			prepared, e := faultService.PrepareCancel(ctx, organization.InvitationCancelRequest{Authentication: owner, CommandID: commandID(t), ID: inv.id, OrganizationID: inv.org, OrganizationVersion: 1, InvitationVersion: 1, CorrelationID: "cancel-lost-ack"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
			handle, e := prepared.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			wire, e := json.Marshal(handle)
			if e != nil {
				t.Fatal(e)
			}
			var restored organizationpg.InvitationRecovery
			if json.Unmarshal(wire, &restored) != nil || restored != handle {
				t.Fatal("cancel recovery correlation changed")
			}
			fault.armed.Store(true)
			result, e := faultService.Execute(ctx, prepared)
			if e == nil || !fault.lost.Load() || result.Receipt.Outcome != identity.CommitOutcomeUnknown || result.Receipt.Binding != restored.Binding {
				t.Fatal("cancel lost acknowledgment not unknown", e)
			}
			if recovered, e := newService(pool).Recover(ctx, signinOwner(), restored); e != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Receipt.Binding != restored.Binding {
				t.Fatal("genuine fresh-session metadata-only cancel recovery", e)
			}
		})
		return
	}
	first, second := issue("invitation-first"), issue("invitation-second")
	wrongStatusProfile := configuration
	wrongStatusProfile.Delivery.StatusPolicyVersion = 2 // delivery profile is2; authorization revision is9.
	wrongStatusService, err := organizationpg.NewInvitationService(repository, wrongStatusProfile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = wrongStatusService.Get(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: first.org, ID: first.id, CorrelationID: "wrong-status-profile"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("mismatched status authorization revision was inferred or ignored", err)
	}
	// Populated metadata-only legacy rows must not infer original envelope or
	// replay identity from a presented proof, even when that proof is genuine.
	var originalEnvelope []byte
	var originalReplay int64
	if err = pool.Raw().QueryRow(ctx, `SELECT capability_envelope,capability_replay_key_version FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id)).Scan(&originalEnvelope, &originalReplay); err != nil {
		t.Fatal(err)
	}
	defer clear(originalEnvelope)
	if _, err = pool.Raw().Exec(ctx, `UPDATE organization.invitations SET capability_envelope=NULL,capability_replay_key_version=NULL WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id)); err != nil {
		t.Fatal(err)
	}
	if _, err = service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-legacy-row"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("legacy row inferred original issued capability", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE organization.invitations SET capability_envelope=$3,capability_replay_key_version=$4 WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id), originalEnvelope, originalReplay); err != nil {
		t.Fatal("legacy partition restoration failed", err)
	}
	// Controlled time partition on an actual delivered pending invitation. Save
	// and restore its original timestamps; no proof/session authority is invented.
	var originalCreated, originalExpires time.Time
	if err = pool.Raw().QueryRow(ctx, `SELECT created_at,expires_at FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id)).Scan(&originalCreated, &originalExpires); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=clock_timestamp()-interval '2 hours',expires_at=date_trunc('second',clock_timestamp()-interval '1 second') WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id)); err != nil {
		t.Fatal(err)
	}
	if _, err = service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-expired"}, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("expired durable invitation admitted", err)
	}
	if _, err = pool.Raw().Exec(ctx, `UPDATE organization.invitations SET created_at=$3,expires_at=$4 WHERE tenant_id=$1 AND invitation_id=$2`, string(baselineTenant), string(second.id), originalCreated, originalExpires); err != nil {
		t.Fatal("time partition restoration failed", err)
	}
	assertAccepted := func(command identity.CommandID, invitation issued, beforeMember, afterMember string) {
		t.Helper()
		id, err := base64.RawURLEncoding.DecodeString(string(command))
		if err != nil {
			t.Fatal(err)
		}
		var total, primary, secondary int
		err = pool.Raw().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE b.event_index=0 AND m.topic='invitation.accepted.v1' AND convert_from(m.payload,'UTF8')::jsonb->>'subject_type'='invitation' AND convert_from(m.payload,'UTF8')::jsonb->>'subject_id'=$3 AND convert_from(m.payload,'UTF8')::jsonb->>'before_version'='1' AND convert_from(m.payload,'UTF8')::jsonb->>'after_version'='2'),count(*) FILTER(WHERE b.event_index=1 AND m.topic='membership.created.v1' AND convert_from(m.payload,'UTF8')::jsonb->>'subject_type'='organization' AND convert_from(m.payload,'UTF8')::jsonb->>'subject_id'=$4 AND convert_from(m.payload,'UTF8')::jsonb->>'user_id'=$5 AND convert_from(m.payload,'UTF8')::jsonb->>'before_version'=$6 AND convert_from(m.payload,'UTF8')::jsonb->>'after_version'=$7) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$2`, string(baselineTenant), id, string(invitation.id), string(invitation.org), string(recipientID), beforeMember, afterMember).Scan(&total, &primary, &secondary)
		if err != nil || total != 2 || primary != 1 || secondary != 1 {
			t.Fatal("acceptance did not persist exact invitation and actual-membership lifecycle pair", total, primary, secondary, err)
		}
		var audits int
		if err = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND r.action='identity.organization.accept_invitation' AND r.outcome=$3 AND r.actor_id=$4 AND r.subject_id=$5`, string(baselineTenant), id, int16(audit.OutcomeSucceeded), string(recipientID), string(invitation.id)).Scan(&audits); err != nil || audits != 1 {
			t.Fatal("successful invitation audit missing or duplicated", err)
		}
	}
	acceptID := commandID(t)
	request := organization.InvitationAcceptRequest{Authentication: recipient, CommandID: acceptID, ID: first.id, OrganizationID: first.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: first.proof, CorrelationID: "invitation-accept"}
	wrong := request
	wrong.Proof = second.proof
	if _, err = service.PrepareAccept(ctx, wrong, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("wrong-row proof substitution was not denied", err)
	}
	wrong = request
	wrong.Authentication = owner
	if _, err = service.PrepareAccept(ctx, wrong, "127.0.0.1"); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("authenticated wrong recipient accepted invitation", err)
	}
	prepared, err := service.PrepareAccept(ctx, request, "127.0.0.1")
	if err != nil {
		t.Fatal("intended genuine recipient rejected", err)
	}
	other := request
	other.CommandID = commandID(t)
	concurrent, err := service.PrepareAccept(ctx, other, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make([]organization.StoreResult, 2)
	failures := make([]error, 2)
	for n, p := range []organizationpg.PreparedInvitation{prepared, concurrent} {
		wg.Add(1)
		go func(n int, p organizationpg.PreparedInvitation) {
			defer wg.Done()
			results[n], failures[n] = service.Execute(ctx, p)
		}(n, p)
	}
	wg.Wait()
	winner := -1
	for n, r := range results {
		if r.Receipt.Outcome == identity.CommitOutcomeCommitted && failures[n] == nil {
			if winner != -1 {
				t.Fatal("concurrent acceptance committed twice")
			}
			winner = n
		}
	}
	if winner < 0 {
		t.Fatal("no concurrent acceptance committed", failures[0], failures[1])
	}
	winnerPrepared := []organizationpg.PreparedInvitation{prepared, concurrent}[winner]
	winnerID := []identity.CommandID{request.CommandID, other.CommandID}[winner]
	if r, e := service.Execute(ctx, winnerPrepared); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("same-command acceptance replay failed", e)
	}
	assertAccepted(winnerID, first, "0", "1")
	if page, e := service.List(ctx, organization.InvitationReadRequest{Authentication: owner, OrganizationID: first.org, Limit: 10, CorrelationID: "invitation-list"}); e != nil || len(page.Invitations) != 1 || page.Invitations[0].Invitation.Status != organization.InvitationAccepted {
		t.Fatal("owner invitation metadata unavailable after acceptance", e)
	}
	if _, e := service.Get(ctx, organization.InvitationReadRequest{Authentication: recipient, OrganizationID: first.org, ID: first.id, CorrelationID: "recipient-metadata"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("selected owner-only invitation metadata broadened", e)
	}
	secondRequest := organization.InvitationAcceptRequest{Authentication: recipient, CommandID: winnerID, ID: second.id, OrganizationID: second.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-accept"}
	changed, e := service.PrepareAccept(ctx, secondRequest, "127.0.0.1")
	if e != nil {
		t.Fatal("second genuine valid invocation could not prepare", e)
	}
	if _, e = service.Execute(ctx, changed); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("same command accepted changed valid invitation intent", e)
	}
	if _, e = organizations.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: first.org, CorrelationID: "invitation-access"}); e != nil {
		t.Fatal("accepted actual recipient lacks membership access", e)
	}
	if _, e = organizations.Get(ctx, organization.ReadRequest{Authentication: recipient, OrganizationID: second.org, CorrelationID: "invitation-denial"}); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("conflicting invitation granted other organization access", e)
	}
	// Existing membership is not an implicit accept. A membership mutation after
	// preparation conflicts under protected admission and cannot consume proof.
	// After actual removal, a newly issued invitation creates member version
	// 2->3, while its independent invitation aggregate transitions 1->2.
	stale, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-existing-member"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	added, e := organizations.PrepareAddMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: second.org, OrganizationVersion: 1, UserID: recipientID, Role: organization.RoleMember, CorrelationID: "invitation-concurrent-add"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := organizations.Execute(ctx, added); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual concurrent membership setup failed", e)
	}
	if r, e := service.Execute(ctx, stale); !errors.Is(e, organization.ErrConflict) || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("changed current membership accepted stale invitation", r.Receipt.Outcome, e)
	}
	if _, e = service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 2, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-existing-member"}, "127.0.0.1"); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("existing member implicitly accepted invitation", e)
	}
	removed, e := organizations.PrepareRemoveMember(ctx, organization.MemberRequest{Authentication: owner, CommandID: commandID(t), OrganizationID: second.org, OrganizationVersion: 2, UserID: recipientID, MemberVersion: 1, CorrelationID: "invitation-concurrent-remove"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if r, e := organizations.Execute(ctx, removed); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal(e)
	}
	released, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: second.id, OrganizationID: second.org, OrganizationVersion: 3, InvitationVersion: 1, Proof: second.proof, CorrelationID: "invitation-released"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = service.Execute(ctx, released); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("new command reused terminal-released proof", e)
	}
	if r, e := service.Execute(ctx, stale); e != nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("original failed acceptance did not retain NotCommitted", r.Receipt.Outcome, e)
	}
	freshTombstone := sendInvitation(second.org, 3)
	tombstoneID := commandID(t)
	tombstone, e := service.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: tombstoneID, ID: freshTombstone.id, OrganizationID: second.org, OrganizationVersion: 3, InvitationVersion: 1, Proof: freshTombstone.proof, CorrelationID: "invitation-tombstone"}, "127.0.0.1")
	if e != nil {
		t.Fatal("new genuine invitation could not admit removed member", e)
	}
	if r, e := service.Execute(ctx, tombstone); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual removed-member invitation admission failed", e)
	}
	assertAccepted(tombstoneID, freshTombstone, "2", "3")
	var invited int
	if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3 AND state='active'`, string(baselineTenant), string(first.org), string(recipientID)).Scan(&invited); e != nil || invited != 1 {
		t.Fatal("actual membership not unique", e)
	}
	// Lose only the actual domain transaction's successful COMMIT response.
	// The safe handle is serialized before execution and restored on a new
	// service, authenticated by another actual password signin/session.
	lost := issue("invitation-lost-ack")
	fault := new(commitResponseLoss)
	faultPool, e := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
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
	if e != nil {
		t.Fatal("isolated lost-ack connection unavailable", e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := faultPool.Close(cleanup); err != nil {
			t.Error("invitation fault-pool cleanup failed")
		}
	})
	faultService := newService(faultPool)
	lostPrepared, e := faultService.PrepareAccept(ctx, organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: lost.id, OrganizationID: lost.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: lost.proof, CorrelationID: "invitation-lost-ack"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	handle, e := lostPrepared.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(handle)
	if e != nil {
		t.Fatal("safe invitation recovery handle not persistable", e)
	}
	var restored organizationpg.InvitationRecovery
	if json.Unmarshal(wire, &restored) != nil || restored != handle {
		t.Fatal("safe invitation recovery scope changed in storage")
	}
	fault.armed.Store(true)
	unknown, e := faultService.Execute(ctx, lostPrepared)
	if !fault.lost.Load() || e == nil || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding != handle.Binding {
		t.Fatal("actual invitation lost commit acknowledgment not unknown", unknown.Receipt.Outcome, e)
	}
	freshRecipient := signinRecipient()
	restarted := newService(pool)
	recovered, e := restarted.Recover(ctx, freshRecipient, restored)
	if e != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted || recovered.Receipt.Binding != restored.Binding || recovered.InvitationID != lost.id {
		t.Fatal("restart-safe invitation recovery did not resolve actual committed acceptance", recovered.Receipt.Outcome, e)
	}
	assertAccepted(restored.Binding.CommandID, lost, "0", "1")
	wrongHandle := restored
	wrongHandle.OrganizationID = second.org
	if _, e = restarted.Recover(ctx, freshRecipient, wrongHandle); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("recovery trusted caller-substituted organization", e)
	}
	if _, e = restarted.Recover(ctx, owner, restored); !errors.Is(e, organization.ErrForbidden) {
		t.Fatal("historical receipt replaced original actor authentication", e)
	}
	// A failure of the actual owning invitation write must roll back provisional
	// one-use consumption, membership, scoped authority and both lifecycle rows.
	rolled := issue("invitation-rollback")
	rollbackRequest := organization.InvitationAcceptRequest{Authentication: recipient, CommandID: commandID(t), ID: rolled.id, OrganizationID: rolled.org, OrganizationVersion: 1, InvitationVersion: 1, Proof: rolled.proof, CorrelationID: "invitation-rollback"}
	rollbackPrepared, e := service.PrepareAccept(ctx, rollbackRequest, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION organization.reject_invitation_accept_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.state='accepted' THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='controlled invitation acceptance failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_invitation_accept_fixture BEFORE UPDATE ON organization.invitations FOR EACH ROW EXECUTE FUNCTION organization.reject_invitation_accept_fixture()`); e != nil {
		t.Fatal("rollback fault setup failed", e)
	}
	aborted, e := service.Execute(ctx, rollbackPrepared)
	if e == nil || aborted.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("protected invitation write failure not rolled back", aborted.Receipt.Outcome, e)
	}
	if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER reject_invitation_accept_fixture ON organization.invitations; DROP FUNCTION organization.reject_invitation_accept_fixture()`); e != nil {
		t.Fatal("rollback fault cleanup failed", e)
	}
	var members, effects int
	var state string
	if e = pool.Raw().QueryRow(ctx, `SELECT state,(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND organization_id=$2 AND user_id=$3),(SELECT count(*) FROM organization.command_effects WHERE command_id=$4) FROM organization.invitations WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$5`, string(baselineTenant), string(rolled.org), string(recipientID), string(rollbackRequest.CommandID), string(rolled.id)).Scan(&state, &members, &effects); e != nil || state != "pending" || members != 0 || effects != 0 {
		t.Fatal("rolled-back accept retained domain effects", e)
	}
	rollbackID, e := base64.RawURLEncoding.DecodeString(string(rollbackRequest.CommandID))
	if e != nil {
		t.Fatal(e)
	}
	rollbackScope, e := organizationpg.OrganizationAuthorityScope(baselineTenant, rolled.org, recipientID)
	if e != nil {
		t.Fatal(e)
	}
	var outboxes, authorities int
	if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$2),(SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$3 AND subject_id=$4)`, string(baselineTenant), rollbackID, string(rollbackScope.PolicyNamespace), string(recipientID)).Scan(&outboxes, &authorities); e != nil || outboxes != 0 || authorities != 0 {
		t.Fatal("rollback retained lifecycle or scoped authority", e)
	}
	rollbackRequest.CommandID = commandID(t)
	retry, e := service.PrepareAccept(ctx, rollbackRequest, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := service.Execute(ctx, retry); !errors.Is(e, organization.ErrConflict) {
		t.Fatal("new command reused terminal-released rollback proof", e)
	}
	if r, e := service.Execute(ctx, rollbackPrepared); e != nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("rollback replay changed retained failure", r.Receipt.Outcome, e)
	}
	var uses int
	var capabilityState string
	if e = pool.Raw().QueryRow(ctx, `SELECT c.state,c.uses FROM public.capability_identity_one_use c JOIN organization.invitations i ON i.tenant_id=c.tenant_id AND i.capability_envelope=c.proof_fingerprint WHERE i.tenant_id=$1 AND i.invitation_id=$2 AND c.purpose='identity.organization.invitation.accept'`, string(baselineTenant), string(rolled.id)).Scan(&capabilityState, &uses); e != nil || capabilityState != "released" || uses != 0 {
		t.Fatal("failed acceptance did not terminal-release unused original grant", capabilityState, uses, e)
	}
	if result, e := worker.ProcessOne(ctx); e != nil || result.Claimed {
		t.Fatal("replay/recovery or denied acceptance redelivered a capability", e)
	}
	// Preparation is durable before the organization row exists. Neither an
	// interrupted output checkpoint nor final attachment may make a safe handle
	// depend on in-memory command/proof custody for historical recovery.
	for _, stage := range []string{"checkpoint-output", "attach-final-plan"} {
		t.Run("restart missing-row send "+stage, func(t *testing.T) {
			i, e := identity.NewSubjectID()
			if e != nil {
				t.Fatal(e)
			}
			p, e := service.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: commandID(t), ID: organization.ID(i), OrganizationID: rolled.org, OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifiers.Identifiers[0].ID, CorrelationID: "interrupted-invitation-send"}, "127.0.0.1")
			if e != nil {
				t.Fatal("genuine interrupted-send preparation failed", e)
			}
			handle, e := p.Recovery()
			if e != nil {
				t.Fatal(e)
			}
			wire, e := json.Marshal(handle)
			if e != nil {
				t.Fatal(e)
			}
			var restored organizationpg.InvitationRecovery
			if json.Unmarshal(wire, &restored) != nil || restored != handle {
				t.Fatal("interrupted-send safe correlation changed in storage")
			}
			condition := "NEW.preparation_ciphertext IS NOT NULL AND OLD.preparation_ciphertext IS NULL"
			if stage == "attach-final-plan" {
				condition = "NEW.command_plan IS NOT NULL AND OLD.command_plan IS NULL"
			}
			if _, e = pool.Raw().Exec(ctx, `CREATE FUNCTION identity.reject_invitation_prepare_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.purpose='identity.organization.invitation-send' AND `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='controlled invitation preparation interruption'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_invitation_prepare_fixture BEFORE UPDATE ON identity.commands FOR EACH ROW EXECUTE FUNCTION identity.reject_invitation_prepare_fixture()`); e != nil {
				t.Fatal("preparation fault setup failed", e)
			}
			unknown, failure := service.Execute(ctx, p)
			if _, e = pool.Raw().Exec(ctx, `DROP TRIGGER reject_invitation_prepare_fixture ON identity.commands; DROP FUNCTION identity.reject_invitation_prepare_fixture()`); e != nil {
				t.Fatal("preparation fault cleanup failed", e)
			}
			if failure == nil || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding != handle.Binding {
				t.Fatal("acknowledged interrupted send not unknown", unknown.Receipt.Outcome, failure)
			}
			id, e := base64.RawURLEncoding.DecodeString(string(handle.Binding.CommandID))
			if e != nil {
				t.Fatal(e)
			}
			var started, declared, output bool
			var generation string
			if e = pool.Raw().QueryRow(ctx, `SELECT preparation_started_generation IS NOT NULL,preparation_declaration IS NOT NULL,preparation_ciphertext IS NOT NULL,generation::text FROM identity.commands WHERE command_id=$1 AND command_plan IS NULL`, id).Scan(&started, &declared, &output, &generation); e != nil || !started || !declared || output != (stage == "attach-final-plan") {
				t.Fatal("fault did not retain exact acknowledged preparation stage", e)
			}
			var domains, grants, deliveries int
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM organization.invitations WHERE tenant_id=$1 AND invitation_id=$2),(SELECT count(*) FROM public.capability_identity_one_use WHERE tenant_id=$1 AND origin_command_id=$4),(SELECT count(*) FROM public.identity_outbox_bindings WHERE tenant_id=$1 AND command_id=$3)`, string(baselineTenant), string(i), id, string(handle.Binding.CommandID)).Scan(&domains, &grants, &deliveries); e != nil || domains != 0 || grants != 0 || deliveries != 0 {
				t.Fatal("preparation-only interruption retained domain effects", e)
			}
			freshOwner := signinOwner()
			restarted := newService(pool)
			wrong := restored
			wrong.OrganizationID = first.org // This actor also owns the substituted organization.
			if _, e := restarted.Recover(ctx, freshOwner, wrong); !errors.Is(e, organization.ErrForbidden) {
				t.Fatal("missing-row recovery trusted another owned organization", e)
			}
			var afterWrong string
			if e = pool.Raw().QueryRow(ctx, `SELECT generation::text FROM identity.commands WHERE command_id=$1`, id).Scan(&afterWrong); e != nil || afterWrong != generation {
				t.Fatal("wrong organization reconciled original preparation", e)
			}
			live, e := restarted.Recover(ctx, freshOwner, restored)
			if e != nil || live.Receipt.Binding != restored.Binding || live.Receipt.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("new-service missing-row recovery did not observe live original send", live.Receipt.Outcome, e)
			}
			// Only this fixture's lease is expired; the existing kernel must prove
			// noncommit under its own journal locks, not infer it from a missing row.
			if _, e = pool.Raw().Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); e != nil {
				t.Fatal(e)
			}
			terminal, e := restarted.Recover(ctx, signinOwner(), restored)
			if !errors.Is(e, organization.ErrUnavailable) || terminal.Receipt.Binding != restored.Binding || terminal.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("new-service missing-row send did not reconcile through original coordinator", terminal.Receipt.Outcome, e)
			}
			retained, e := newService(pool).Recover(ctx, signinOwner(), restored)
			if !errors.Is(e, organization.ErrUnavailable) || retained.Receipt.Binding != restored.Binding || retained.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
				t.Fatal("classified noncommit metadata was mistaken for a current query denial", retained.Receipt.Outcome, e)
			}
			if result, e := worker.ProcessOne(ctx); e != nil || result.Claimed {
				t.Fatal("interrupted-send metadata recovery generated or delivered custody", e)
			}
		})
	}
	t.Run("current external policy at execute", func(t *testing.T) {
		evaluator := &revocableInvitationEvaluator{}
		snapshot, e := authorization.NewSnapshot(9, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "organization-current-invitation", Revision: 9, Evaluator: evaluator})
		if e != nil {
			t.Fatal(e)
		}
		engine, e := authorization.NewEngine(snapshot)
		if e != nil {
			t.Fatal(e)
		}
		current, e := authorization.NewDecisionService(engine)
		if e != nil {
			t.Fatal(e)
		}
		c := configuration
		c.Authorization = current
		s, e := organizationpg.NewInvitationService(repository, c)
		if e != nil {
			t.Fatal(e)
		}
		i, e := identity.NewSubjectID()
		if e != nil {
			t.Fatal(e)
		}
		command := commandID(t)
		p, e := s.PrepareSend(ctx, organization.InvitationSendRequest{Authentication: owner, CommandID: command, ID: organization.ID(i), OrganizationID: rolled.org, OrganizationVersion: 1, RecipientUserID: recipientID, RecipientIdentifierID: identifiers.Identifiers[0].ID, CorrelationID: "current-invitation-policy"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		evaluator.denied.Store(true)
		if _, e = s.Execute(ctx, p); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("changed external action policy did not deny prepared native send", e)
		}
		var rows int
		id, _ := base64.RawURLEncoding.DecodeString(string(command))
		if e = pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.identity_command_id_claims WHERE command_id=$1`, id).Scan(&rows); e != nil || rows != 0 {
			t.Fatal("external policy denial reached native reservation or generation", e)
		}
	})
}

// This application decision is deliberately mutable independently of durable
// identity/session/organization authority. The actual authorization engine must
// reevaluate it; native authority fences cannot stand in for that decision.
type revocableInvitationEvaluator struct{ denied atomic.Bool }

type invitationCancellationPolicy struct {
	base   authorization.Service
	before func(context.Context, authorization.DecisionContext) error
}

func (p *invitationCancellationPolicy) Decide(ctx context.Context, d authorization.DecisionContext) (authorization.Decision, error) {
	if p.before != nil {
		if err := p.before(ctx, d); err != nil {
			return authorization.Decision{}, err
		}
	}
	return p.base.Decide(ctx, d)
}

func (p *revocableInvitationEvaluator) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	if p.denied.Load() && r.Action == "identity.organization.invitation-send" {
		return authorization.Decision{Outcome: authorization.Deny}, ctx.Err()
	}
	return (&baselineEvaluator{}).Evaluate(ctx, r)
}
