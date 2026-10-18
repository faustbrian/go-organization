//go:build integration

package postgres_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This controlled storage partition proves native recipient and delivery-owner
// read composition, not actual invitation send/consume or genuine authentication.
func TestInvitationRepositoryUsesCurrentRecipientAndNativeDeliveryMetadata(t *testing.T) {
	history, err := (deliverypg.MigrationSource{Base: organizationpg.MigrationSource{Version: 300}, Version: 301, WorkerVersion: 302, PolicyVersion: 303, KeyedVersion: 304, StateVersion: 305}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f := newOrgFixture(t, migrationList(history[1:]), organizationpg.InvitationMigrationSource{Version: 400})
	p := f.create(t, "org-test-basic")
	out, err := f.service.Execute(f.ctx, p)
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("organization fixture failed", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('org-test-basic','member','recipient-email','email','recipient@example.invalid',true,true,1,2,1,clock_timestamp())`); err != nil {
		t.Fatal("controlled verified recipient setup failed", err)
	}
	provider, err := keyring.New(map[string][]byte{"invitation-envelope": bytes.Repeat([]byte{0x64}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := secretenvelope.NewService(provider)
	if err != nil {
		t.Fatal(err)
	}
	policy := delivery.DefaultConfig()
	status, err := deliverypg.NewEnqueueService(f.ctx, f.pool, deliverypg.EnqueueConfig{Custody: deliverypg.ContributorConfig{Deployment: "organization-invitation", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {0x62}}, ActiveEnvelopeKeyID: "invitation-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "capture", PolicyVersion: 1}}}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x63}}}, PolicyID: "organization", PolicyVersion: 1, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: [32]byte{0x65}, Policies: map[uint64]delivery.Config{1: policy}, StateTracking: true}, envelope, fixturePolicy{}, []delivery.Template{{ID: "metadata", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "metadata fixture", ContentType: "text/plain", MaxRenderedBytes: 128}})
	if err != nil {
		t.Fatal("real delivery owner failed", err)
	}
	base, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	repository, err := organizationpg.NewInvitationRepository(base, status, organizationpg.InvitationRepositoryConfig{DeliveryPolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	const org = organization.ID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	query := organization.InvitationQuery{Operation: organization.InvitationSend, TenantID: "org-test-basic", ActorID: "owner", RecipientUserID: "member", OrganizationID: org, InvitationID: "invitation-a", RecipientIdentifierID: "recipient-email"}
	snapshot, err := repository.ReadInvitation(f.ctx, query)
	if err != nil || snapshot.Actor.Role != organization.RoleOwner || snapshot.RecipientUser.ID != "member" || snapshot.RecipientIdentifier.ID != "recipient-email" || !snapshot.RecipientIdentifier.Verified || snapshot.PendingCount != 0 {
		t.Fatal("native current verified recipient projection failed", err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "metadata", Request: authorization.Request{Tenant: "org-test-basic", Subject: authorization.Subject{Kind: authorization.SubjectUser, ID: "owner"}, Action: "identity.delivery.enqueue", Resource: authorization.Resource{Type: "identity.user", ID: "member"}, Environment: authorization.Environment{Time: time.Now().UTC()}}}
	b := identity.CommandBinding{CommandID: commandID(t), TenantID: "org-test-basic", UserID: "member", ActorID: "owner", ActorKind: authorization.SubjectUser, OperationID: deliverypg.EnqueueOperation().OperationID, PolicyID: "organization", PolicyVersion: 1, SchemaID: deliverypg.EnqueueOperation().SchemaID, SchemaVersion: 1, CorrelationID: "metadata"}
	queued, err := status.Enqueue(f.ctx, deliverypg.EnqueueCommandRequest{Binding: b, ActorScope: caller, IdentifierID: "recipient-email", ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC().Add(time.Hour), Message: delivery.Message{Purpose: "organization-metadata", Channel: delivery.ChannelEmail, TemplateID: "metadata", TemplateVersion: 1, LocaleChain: []string{"en"}}, IdempotencyKey: string(b.CommandID)})
	if err != nil || !queued.Queued {
		t.Fatal("real native queued intent missing", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.invitations(tenant_id,organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,expires_at,delivery_effect_id) VALUES('org-test-basic',$1,'invitation-a','member','recipient-email',1,'owner','member','pending',1,$2,$3)`, string(org), time.Now().UTC().Truncate(time.Second).Add(time.Hour), string(queued.IntentID)); err != nil {
		t.Fatal("controlled invitation metadata setup failed", err)
	}
	query.Operation = organization.InvitationGet
	snapshot, err = repository.ReadInvitation(f.ctx, query)
	if err != nil || snapshot.Record.State != delivery.StateQueued || snapshot.Record.EffectID != queued.IntentID {
		t.Fatal("metadata was not read from real delivery owner", err)
	}
	page, err := repository.ListInvitations(f.ctx, organization.InvitationQuery{Operation: organization.InvitationList, TenantID: query.TenantID, ActorID: query.ActorID, OrganizationID: org, Limit: 1})
	if err != nil || len(page.Invitations) != 1 || page.Invitations[0] != snapshot.Record {
		t.Fatal("current metadata list failed", err)
	}
	query.ActorID = "outsider"
	if _, err = repository.ReadInvitation(f.ctx, query); err == nil {
		t.Fatal("nonmember read invitation")
	}
	query.Operation = organization.InvitationAccept
	query.ActorID = "member"
	query.RecipientUserID = "member"
	query.RecipientIdentifierID = ""
	snapshot, err = repository.ReadInvitation(f.ctx, query)
	if err != nil || snapshot.Target.Active || snapshot.RecipientUser.ID != "member" {
		t.Fatal("intended nonmember recipient could not prepare acceptance read", err)
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE identity.identifiers SET verified=false,is_primary=false,verification_state=3,verification_version=2,version=2 WHERE tenant_id='org-test-basic' AND user_id='member' AND identifier_id='recipient-email'`); err != nil {
		t.Fatal(err)
	}
	if _, err = repository.ReadInvitation(f.ctx, query); err == nil {
		t.Fatal("revoked identifier retained recipient admission")
	}
}
