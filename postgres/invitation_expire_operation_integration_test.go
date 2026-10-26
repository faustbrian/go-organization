//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	issuerpg "github.com/faustbrian/go-capability/postgres/identity"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

// Native adapter isolation uses the existing SQL-backed identity/session fixture
// and seeded pending metadata. It does not claim signup or capability issuance;
// the separate public consumer proves those through their actual owners.
func expiryOperationFixture(t *testing.T) (*orgFixture, *organizationpg.InvitationService, func() *organizationpg.InvitationService) {
	t.Helper()
	deliverySteps, err := (deliverypg.MigrationSource{Base: organizationpg.MigrationSource{Version: 300}, Version: 310, WorkerVersion: 311, PolicyVersion: 312, KeyedVersion: 313, StateVersion: 314}).Load(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f := newOrgFixture(t, organizationpg.InvitationMigrationSource{Version: 301}, organizationpg.InvitationCapabilityMigrationSource{Version: 302}, organizationpg.InvitationCancellationMigrationSource{Version: 303}, organizationpg.InvitationRejectionMigrationSource{Version: 304}, organizationpg.InvitationExpiryMigrationSource{Version: 305}, migrationList(deliverySteps[1:]))
	f.create(t, "org-test-basic")
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	material := bytes.Repeat([]byte{0x67}, 32)
	signing := bytes.Repeat([]byte{0x6a}, 32)
	provider, err := keyring.New(map[string][]byte{"expiry-envelope": material})
	check(err)
	envelope, err := secretenvelope.NewService(provider)
	check(err)
	query := kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &query, AdmissionPolicy: &query}
	policy := delivery.DefaultConfig()
	policy.DedupeTTL = 72 * time.Hour
	custody := deliverypg.ContributorConfig{Deployment: "expiry-native", CurrentDigestKeyVersion: 1, RetainedDigestKeys: map[uint32][32]byte{1: {0x68}}, ActiveEnvelopeKeyID: "expiry-envelope", PreparationTimeout: time.Second, ProviderProfiles: map[uint64]deliverypg.ProviderProfile{1: {Provider: "capture", PolicyVersion: 1}}}
	templates := []delivery.Template{{ID: "expiry", Version: 1, Channel: delivery.ChannelEmail, Locale: "en", Body: "{{.link}}", ContentType: "text/plain", RequiredVariables: []string{"link"}, VariableSchema: []delivery.VariableSchema{{Name: "link", Kind: "url", Sensitive: true}}, AllowedOrigins: []string{"https://expiry.example.invalid"}, MaxRenderedBytes: 4096}}
	status, err := deliverypg.NewEnqueueService(f.ctx, f.pool, deliverypg.EnqueueConfig{Custody: custody, Coordinator: coordinator, PolicyID: "organization", PolicyVersion: 1, AuditRetentionVersion: 1, Timeout: 4 * time.Second, NamespaceKey: [32]byte{0x69}, Policies: map[uint64]delivery.Config{1: policy}, StateTracking: true}, envelope, fixturePolicy{}, templates)
	check(err)
	owner, err := deliverypg.NewContributor(custody, envelope)
	check(err)
	renderer, err := delivery.NewTemplateRenderer(templates)
	check(err)
	signer, err := capability.NewHMACSHA256Signer("expiry-signing", signing)
	check(err)
	verifier, err := capability.NewHMACSHA256Verifier(signing)
	check(err)
	resolver, err := capability.NewKeySet([]capability.Key{{Issuer: "https://expiry.example.invalid", ID: "expiry-signing", Verifier: verifier}})
	check(err)
	limits := capability.DefaultLimits()
	limits.MaxLifetime = 48 * time.Hour
	c := organizationpg.InvitationServiceConfig{Core: f.configuration.Core, Invitation: organization.InvitationConfig{Audience: "organization-invitation", Lifetime: 48 * time.Hour, MaximumPending: 100, ExpirationReasons: []identity.PolicyReason{"security-withdrawal", "administrative-cleanup"}}, Admission: organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}, Profile: f.profile, LookupKeys: map[uint32]session.DigestKey{1: f.key}, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: 1000}, Sessions: f.sessions, Authorization: fixturePolicy{}, Coordinator: coordinator, Risk: f.configuration.Risk, Issuer: issuerpg.IssuerConfig{Crypto: capability.ServiceConfig{Issuer: "https://expiry.example.invalid", Signer: signer, Resolver: resolver, Clock: time.Now, Limits: limits}, Audience: "organization-invitation", CurrentReplayKeyVersion: 1, RetainedReplayKeys: map[uint32][32]byte{1: {0x70}}, PreparationTimeout: time.Second}, Preparation: issuerpg.IssuancePreparationConfig{Deployment: "expiry-native", ActiveEnvelopeKey: "expiry-envelope", EnvelopeKeys: map[string][]byte{"expiry-envelope": material}, VerificationKeys: []issuerpg.PreparationVerificationKey{{ID: "expiry-signing", HMAC: signing}}, Clock: time.Now}, Delivery: organizationpg.InvitationDeliveryConfig{Owner: owner, Status: status, Renderer: renderer, Policy: policy, PolicyVersion: 1, ProviderVersion: 1, StatusPolicyVersion: 1, TemplateID: "expiry", TemplateVersion: 1, LocaleChain: []string{"en"}, ScopeKey: [32]byte{0x71}, Endpoint: "https://expiry.example.invalid/invitation"}}
	build := func() *organizationpg.InvitationService {
		r, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
		check(err)
		s, err := organizationpg.NewInvitationService(r, c)
		check(err)
		return s
	}
	return f, build(), build
}

func seedExpiryInvitation(t *testing.T, f *orgFixture, id string) organization.InvitationExpireOperationRequest {
	t.Helper()
	_, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.invitations(tenant_id,organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,expires_at,delivery_effect_id) VALUES('org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV',$1,'member','historical-email',1,'owner','member','pending',1,date_trunc('second',clock_timestamp())+interval '1 hour',repeat('1',64))`, id)
	if err != nil {
		t.Fatal(err)
	}
	return organization.InvitationExpireOperationRequest{Authentication: f.auth("org-test-basic", "owner"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", InvitationID: organization.ID(id), OrganizationVersion: 1, InvitationVersion: 1, Reason: "security-withdrawal", CorrelationID: "native-expiry"}
}

func applyExpiryOperationMigration(t *testing.T, f *orgFixture) {
	t.Helper()
	c, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	c.Database = f.database
	db := stdlib.OpenDB(*c)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	backend, err = backend.ForNamespace("natural_expiry")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(organizationpg.InvitationExpireOperationMigrationSource{Version: 306}, backend)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := runner.Up(f.ctx); err != nil {
			t.Fatal("populated optional expiry migration/replay", err)
		}
	}
}

func TestInvitationExpireOperationNativeOriginalAndAtomicCorrelation(t *testing.T) {
	f, native, rebuild := expiryOperationFixture(t)
	legacy := seedExpiryInvitation(t, f, "legacy")
	p, err := native.PrepareExpire(f.ctx, organization.InvitationExpireRequest{Authentication: legacy.Authentication, CommandID: commandID(t), ID: legacy.InvitationID, OrganizationID: legacy.OrganizationID, OrganizationVersion: 1, InvitationVersion: 1, Reason: legacy.Reason, CorrelationID: "legacy-expiry"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := native.Execute(f.ctx, p); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("raw expiry required optional migration", err)
	}
	applyExpiryOperationMigration(t, f)
	if out, err := native.Expire(f.ctx, legacy, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("legacy terminal effect invented original correlation")
	}
	missing := seedExpiryInvitation(t, f, "no-history")
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.invitations SET state='expired',version=2,expired_at=clock_timestamp(),expiry_reason='security-withdrawal' WHERE invitation_id='no-history'`); err != nil {
		t.Fatal(err)
	}
	if got, err := native.Expire(f.ctx, missing, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("terminal row without command history became a receipt")
	}
	r := seedExpiryInvitation(t, f, "natural")
	out, err := native.Expire(f.ctx, r, "127.0.0.1")
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted || out.Receipt.Feature == nil || out.Receipt.Feature.BeforeVersion != 1 || out.Receipt.Feature.AfterVersion != 2 {
		t.Fatal("natural expiry did not commit", err)
	}
	r.CorrelationID = "reconstructed"
	if got, err := rebuild().Expire(f.ctx, r, "127.0.0.1"); err != nil || !reflect.DeepEqual(out, got) {
		t.Fatal("reconstructed expiry lost actual original", err)
	}
	for _, variant := range []string{"reason", "epoch", "recipient", "unregistered"} {
		changed := r
		want := organization.ErrConflict
		switch variant {
		case "reason":
			changed.Reason = "administrative-cleanup"
		case "epoch":
			changed.OrganizationVersion++
		case "recipient":
			changed.Authentication = f.auth("org-test-basic", "member")
			want = organization.ErrForbidden
		case "unregistered":
			changed.Reason = "unregistered"
			want = organization.ErrInvalidInput
		}
		if got, err := native.Expire(f.ctx, changed, "127.0.0.1"); !errors.Is(err, want) || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("changed selection disclosed original", variant, err)
		}
	}
	id, err := base64.RawURLEncoding.DecodeString(string(out.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var effects, events, audits, members, version int
	var reason, epoch string
	err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE invitation_id='natural'),(SELECT count(*) FROM identity_outbox_bindings b JOIN outbox_messages m ON m.id=b.effect_id WHERE b.command_id=$1 AND m.topic='invitation.expired.v1'),(SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.command_id=$1 AND r.action='identity.organization.expire_invitation' AND r.outcome=1),(SELECT member_count FROM organization.organizations WHERE tenant_id='org-test-basic'),(SELECT version FROM organization.organizations WHERE tenant_id='org-test-basic'),expire_reason,expire_organization_version::text FROM organization.command_effects WHERE invitation_id='natural'`, id).Scan(&effects, &events, &audits, &members, &version, &reason, &epoch)
	if err != nil || effects != 1 || events != 1 || audits != 1 || members != 1 || version != 1 || reason != string(r.Reason) || epoch != "1" {
		t.Fatal("expiry lost atomic singleton effects or changed membership", err)
	}
	// Failure after terminal UPDATE must roll back the correlated effect too.
	rollback := seedExpiryInvitation(t, f, "rollback")
	_, err = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION organization.expiry_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.topic='invitation.expired.v1' THEN RAISE EXCEPTION 'controlled expiry effect failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER expiry_fail BEFORE INSERT ON outbox_messages FOR EACH ROW EXECUTE FUNCTION organization.expiry_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	failed, failure := native.Expire(f.ctx, rollback, "127.0.0.1")
	_, err = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER expiry_fail ON outbox_messages; DROP FUNCTION organization.expiry_fail()`)
	if err != nil {
		t.Fatal(err)
	}
	if failure == nil || failed.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("failed required effect committed expiry", failure)
	}
	var state string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,(SELECT count(*) FROM organization.command_effects WHERE invitation_id='rollback') FROM organization.invitations WHERE invitation_id='rollback'`).Scan(&state, &effects); err != nil || state != "pending" || effects != 0 {
		t.Fatal("rollback retained terminal row or original correlation", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization_sessions.sessions SET state='revoked' WHERE tenant_id='org-test-basic' AND user_id='owner'`); err != nil {
		t.Fatal(err)
	}
	if got, err := rebuild().Expire(f.ctx, r, "127.0.0.1"); err == nil || got.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("revoked original session disclosed expiry")
	}
}

// The bounded storage probe measures this exact unique partial correlation
// index, not production performance. Seeded historical effects are no receipts.
func TestInvitationExpireOperationIndexAndNullableUpgrade(t *testing.T) {
	f, _, _ := expiryOperationFixture(t)
	const fill = `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version) SELECT translate(rtrim(encode(int8send(n)||int8send(19),'base64'),'='),'+/','-_'),'org-test-basic','01ARZ3NDEKTSV4RRFFQ69G5FAV','seed-invitation-'||n,'owner','owner','identity.organization.invitation.expire',decode(repeat('01',32),'hex'),1,2 FROM generate_series(1::bigint,4000::bigint) n`
	if _, err := f.pool.Raw().Exec(f.ctx, fill); err != nil {
		t.Fatal(err)
	}
	// The exact forward migration must fail within the operator's lock budget,
	// leaving neither correlation columns nor a partial index on interruption.
	steps, err := (organizationpg.InvitationExpireOperationMigrationSource{Version: 306}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.command_effects IN ACCESS SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	blocked, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(f.ctx)
	if _, err := blocked.Exec(f.ctx, `SET LOCAL lock_timeout='50ms'`); err != nil {
		t.Fatal(err)
	}
	_, err = blocked.Exec(f.ctx, steps[0].UpSQL())
	var locked *pgconn.PgError
	if !errors.As(err, &locked) || locked.Code != "55P03" {
		t.Fatal("operator lock budget did not bound index migration", err)
	}
	if err := blocked.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var partial bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='organization' AND table_name='command_effects' AND column_name='expire_reason') OR to_regclass('organization.organization_repeat_invitation_expire') IS NOT NULL`).Scan(&partial); err != nil || partial {
		t.Fatal("interrupted migration retained partial schema", err)
	}
	applyExpiryOperationMigration(t, f)
	var nullable int
	var size int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE expire_organization_version IS NULL AND expire_reason IS NULL AND operation='identity.organization.invitation.expire'`).Scan(&nullable); err != nil || nullable != 4000 {
		t.Fatal("populated upgrade invented correlation", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	rows, err := f.pool.Raw().Query(f.ctx, `EXPLAIN (ANALYZE,BUFFERS) SELECT command_id,expire_organization_version::text,expire_reason FROM organization.command_effects WHERE tenant_id=$1 AND organization_id=$2 AND invitation_id=$3 AND before_version=$4::numeric AND operation='identity.organization.invitation.expire' AND actor_id=$5 AND user_id=$5 LIMIT 2`, "org-test-basic", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "seed-invitation-17", "1", "owner")
	if err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	rows.Close()
	if rows.Err() != nil || !strings.Contains(plan.String(), "organization_repeat_invitation_expire") {
		t.Fatal("exact lookup did not use owned bounded index", rows.Err(), plan.String())
	}
	var tableSize, allIndexes int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_size('organization.organization_repeat_invitation_expire'),pg_relation_size('organization.command_effects'),pg_indexes_size('organization.command_effects')`).Scan(&size, &tableSize, &allIndexes); err != nil || size <= 0 {
		t.Fatal("physical index storage unavailable", size, err)
	}
	t.Logf("isolated PostgreSQL 4000 expiry effects: partial index %d bytes, table %d bytes, total indexes %d bytes; exact lookup plan:\n%s", size, tableSize, allIndexes, plan.String())
	// These immutable effect rows add one index entry per expiry; unrelated
	// operations are excluded. No covering columns or new update/HOT dependency.
	_, err = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version) SELECT $1,tenant_id,organization_id,invitation_id,user_id,actor_id,operation,fingerprint,before_version,after_version FROM organization.command_effects WHERE invitation_id='seed-invitation-17'`, string(commandID(t)))
	var duplicate *pgconn.PgError
	if !errors.As(err, &duplicate) || duplicate.Code != "23505" || duplicate.ConstraintName != "organization_repeat_invitation_expire" {
		t.Fatal("exact invitation epoch was not uniquely fenced", err)
	}
	for _, invalid := range []string{
		`UPDATE organization.command_effects SET expire_organization_version=1 WHERE invitation_id='seed-invitation-17'`,
		`UPDATE organization.command_effects SET expire_reason='security-withdrawal' WHERE invitation_id='seed-invitation-17'`,
		`UPDATE organization.command_effects SET expire_organization_version=18446744073709551615,expire_reason='security-withdrawal' WHERE invitation_id='seed-invitation-17'`,
	} {
		if _, err := f.pool.Raw().Exec(f.ctx, invalid); err == nil {
			t.Fatal("partial/unsupported original correlation was admitted")
		}
	}
}
