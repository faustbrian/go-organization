//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
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
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

type migrationList []migrations.Migration

func (s migrationList) Load(ctx context.Context) ([]migrations.Migration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}

type fixturePolicy struct{}

func (fixturePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	if c.PolicyRevision != 1 || c.Request.Subject.Kind != authorization.SubjectUser || !strings.HasPrefix(string(c.Request.Tenant), "org-test-") {
		return authorization.Decision{Outcome: authorization.Deny, Revision: 1}, nil
	}
	return authorization.Decision{Outcome: authorization.Allow, Revision: 1}, nil
}

type orgFixture struct {
	ctx            context.Context
	pool           *database.Pool
	service        *organizationpg.Service
	sessions       *session.SessionService
	key            session.DigestKey
	authentication map[string]organization.Authentication
	profile        sessionpg.IdentifierAdmissionConfig
	participant    *organizationpg.Contributor
	configuration  organizationpg.ServiceConfig
	dsn            string
	database       string
}

func migrationBundle(t *testing.T, version migrations.Version, name string, files fs.FS, prefix string) migrations.Migration {
	t.Helper()
	entries, e := fs.ReadDir(files, ".")
	if e != nil {
		t.Fatal(e)
	}
	var sql strings.Builder
	sql.WriteString(prefix)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			t.Fatal("unexpected native migration entry")
		}
		wire, e := fs.ReadFile(files, entry.Name())
		if e != nil {
			t.Fatal(e)
		}
		sql.WriteString("\n")
		sql.WriteString(strings.Split(string(wire), "-- +migrations Down")[0])
	}
	m, e := migrations.NewMigration(version, name, migrations.TransactionModeDefault, sql.String(), "")
	if e != nil {
		t.Fatal(e)
	}
	return m
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	dsn := os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Fatal("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN must identify the task-owned isolated PostgreSQL fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("isolated PostgreSQL unavailable")
	}
	var preexistingRoles bool
	if e = admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention'))`).Scan(&preexistingRoles); e != nil || preexistingRoles {
		_ = admin.Close(ctx)
		t.Fatal("isolated fixture requires native audit roles to be absent")
	}
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	name := "organization_test_" + strings.ReplaceAll(string(id), "-", "_")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		t.Fatal("isolated database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("owned database cleanup failed")
		}
		// The fixture requires a task-owned cluster: audit's fixed roles are
		// cluster-wide, so remove them only after this fixture database is gone.
		for _, role := range []string{"audit_writer", "audit_reader", "audit_retention"} {
			if _, e := admin.Exec(cleanup, "DROP ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
				t.Error("owned audit role cleanup failed")
			}
		}
		_ = admin.Close(cleanup)
	})
	config, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid isolated DSN")
	}
	config.Database = name
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { _ = db.Close() })
	tenants := []identity.TenantID{"org-test-basic", "org-test-rollback", "org-test-target", "org-test-race", "org-test-scope", "org-test-unknown"}
	base := kernel.StatusMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 10, GlobalAuthorityID: "organization-tests", TenantIDs: tenants}, Version: 11}, Version: 12}
	history, e := base.Load(ctx)
	if e != nil {
		t.Fatal(e)
	}
	add := func(source migrations.Source) {
		t.Helper()
		more, e := source.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		history = append(history, more...)
	}
	add(sessionpg.MigrationSource{Schema: "organization_sessions", Version: 20})
	m, e := authority.AuthoritySchemaMigration(30)
	if e != nil {
		t.Fatal(e)
	}
	converted, e := migrations.NewMigration(30, m.Name, migrations.TransactionModeDefault, m.Up, "")
	if e != nil {
		t.Fatal(e)
	}
	history = append(history, converted)
	add(riskpg.LockoutMigrationSource{Base: riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "organization_risk", Version: 40}, Version: 41}, Version: 42}, Version: 43}, Version: 44})
	history = append(history, migrationBundle(t, 200, "organization_native_audit", auditpg.Migrations(), auditpg.FreshInstallPreflightSQL()), migrationBundle(t, 201, "organization_native_outbox", outboxpg.Migrations(), ""), migrationBundle(t, 202, "organization_native_lifecycle", lifecyclepg.Migrations(), ""))
	add(organizationpg.MigrationSource{Version: 300})
	backend, e := migrationpg.New(db)
	if e != nil {
		t.Fatal(e)
	}
	runner, e := migrations.NewRunner(migrationList(history), backend)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("native migration installation failed", e)
	}
	if _, e = runner.Up(ctx); e != nil {
		t.Fatal("migration replay failed", e)
	}
	pool, e := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error { c.ConnConfig.Database = name; return nil }})
	if e != nil {
		t.Fatal("native pool unavailable")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e := pool.Close(cleanup); e != nil {
			t.Error("owned pool cleanup failed")
		}
	})
	f := &orgFixture{ctx: ctx, pool: pool, dsn: dsn, database: name, authentication: map[string]organization.Authentication{}, profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "organization-tests", PolicyNamespace: "users", Audience: "organization-test", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}}
	f.key, e = session.NewDigestKey(1, bytes.Repeat([]byte{0x41}, 32))
	if e != nil {
		t.Fatal(e)
	}
	for _, tenant := range tenants {
		for _, user := range []identity.UserID{"owner", "second", "member", "outsider"} {
			f.seedUser(t, tenant, user)
		}
	}
	f.sessions, e = sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}, Profile: f.profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: f.profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{f.key}}})
	if e != nil {
		t.Fatal(e)
	}
	f.compose(t)
	return f
}

func (f *orgFixture) compose(t *testing.T) {
	f.composeWithTenantLimit(t, 1000)
}

func (f *orgFixture) composeWithTenantLimit(t *testing.T, maximum uint64) {
	t.Helper()
	pool := f.pool
	repository, e := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	f.participant, e = organizationpg.NewContributor(repository, organizationpg.ContributorConfig{Session: sessionpg.Config{Schema: "organization_sessions", MaximumDuration: time.Second}, Profile: f.profile, LookupKeys: map[uint32]session.DigestKey{1: f.key}, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: maximum})
	if e != nil {
		t.Fatal(e)
	}
	counters := nativeRisk(t)
	domain, e := kernel.NewRepository(pool, kernel.Config{MaximumDuration: 2 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	audits, e := auditpg.NewIdentityContributor(auditpg.Config{})
	if e != nil {
		t.Fatal(e)
	}
	outbox, e := lifecyclepg.NewContributor()
	if e != nil {
		t.Fatal(e)
	}
	registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, outbox, counters, f.participant})
	if e != nil {
		t.Fatal(e)
	}
	coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {0x45}}, QueryPolicy: &kernel.CommandQueryPolicy{Authorization: fixturePolicy{}, Clock: clock.System{}, PolicyVersion: 1}})
	if e != nil {
		t.Fatal(e)
	}
	f.configuration = organizationpg.ServiceConfig{Core: organization.Config{Clock: clock.System{}, MaximumDuration: 4 * time.Second, PolicyID: "organization", PolicyVersion: 1, MaximumMembers: 100, MaximumPerUser: 100, MaximumPerTenant: maximum, ValidateCanonicalID: func(_ context.Context, id organization.ID) error {
		if id == "" {
			return errors.New("invalid")
		}
		return nil
	}}, Sessions: f.sessions, Authorization: fixturePolicy{}, Risk: counters, Coordinator: coordinator, Registry: registry}
	f.service, e = organizationpg.NewService(f.participant, f.configuration)
	if e != nil {
		t.Fatal(e)
	}
}

func nativeRisk(t *testing.T) *riskpg.Repository {
	t.Helper()
	policy, e := risk.NewPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if e != nil {
		t.Fatal(e)
	}
	key, e := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{0x42}, 32))
	if e != nil {
		t.Fatal(e)
	}
	evidence, e := risk.NewEvidenceKey(1, bytes.Repeat([]byte{0x43}, 32), bytes.Repeat([]byte{0x44}, 32))
	if e != nil {
		t.Fatal(e)
	}
	r, e := riskpg.NewRepository(riskpg.Config{Schema: "organization_risk", PolicyVersion: 1, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"test": bytes.Repeat([]byte{0x46}, 32)}, CurrentEnvelopeKey: "test", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}, EnforceLockouts: true})
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func (f *orgFixture) seedUser(t *testing.T, tenant identity.TenantID, user identity.UserID) {
	t.Helper()
	if _, e := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',1);`, string(tenant), string(user)); e != nil {
		t.Fatal("identity fixture failed", e)
	}
	if _, e := f.pool.Raw().Exec(f.ctx, `INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES($1,$2,'password',1,'identity/password',1,true)`, string(tenant), string(user)); e != nil {
		t.Fatal("credential fixture failed", e)
	}
	policyScope := authority.AuthorityScope{TenantID: authorization.TenantID(tenant), PolicyNamespace: "users", SubjectID: authorization.SubjectID(user)}
	if _, e := authority.InitializeAuthority(f.ctx, f.pool.Raw(), policyScope, time.Second); e != nil {
		t.Fatal(e)
	}
	remember, e := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	keys, e := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "organization-tests", TenantID: tenant}, user)
	if e != nil {
		t.Fatal(e)
	}
	sessionID, family := "session-"+string(user), "family-"+string(user)
	sk, e := sessionpg.SessionAuthorityKeys(tenant, user, family, sessionID)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := policyScope.Key()
	if e != nil {
		t.Fatal(e)
	}
	bind := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
	authoritySpec := session.AuthoritySnapshotSpec{Global: bind(keys.Global), Tenant: bind(keys.Tenant), User: bind(keys.User), Identifier: bind(keys.Identifier), Credential: bind(keys.Credential), SessionFamily: bind(sk.Family), Session: bind(sk.Session), Authorization: bind(pk)}
	vector, e := session.NewAuthoritySnapshot(authoritySpec)
	if e != nil {
		t.Fatal(e)
	}
	token, e := session.NewToken(32)
	if e != nil {
		t.Fatal(e)
	}
	digest, e := token.Digest(f.key, string(tenant))
	if e != nil {
		t.Fatal(e)
	}
	wire, e := token.Reveal()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	metadata := session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: string(tenant), Subject: string(user), Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: f.profile.Audience, IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password", CredentialVersion: 1}
	record, e := session.NewSession(session.SessionSpec{SessionID: sessionID, FamilyID: family, TenantID: tenant, UserID: user, Audience: f.profile.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: vector, Lookup: digest, Authentication: metadata, IssuedAt: now, LastActivityAt: now})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = record.Bindings(); e != nil {
		t.Fatal(e)
	}
	resolved, _ := remember.Bindings()
	payload, e := json.Marshal(map[string]any{"Schema": 1, "SessionID": sessionID, "FamilyID": family, "TenantID": tenant, "UserID": user, "Audience": f.profile.Audience, "Version": uint64(1), "FamilyVersion": uint64(1), "Remember": resolved, "Authority": authoritySpec, "Lookup": digest, "Authentication": metadata, "IssuedAt": now, "LastActivityAt": now})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization_sessions.families(tenant_id,family_id,user_id,version,state,issued_at) VALUES($1,$2,$3,1,'active',$4)`, string(tenant), family, string(user), now.Format("2006-01-02T15:04:05.000000000Z")); e != nil {
		t.Fatal(e)
	}
	if _, e = f.pool.Raw().Exec(f.ctx, `INSERT INTO organization_sessions.sessions(tenant_id,session_id,user_id,family_id,version,family_version,state,digest_version,digest,expires_at,record) VALUES($1,$2,$3,$4,1,1,'active',1,$5,$6,$7)`, string(tenant), sessionID, string(user), family, digest.Sum[:], now.Add(30*time.Minute).Format("2006-01-02T15:04:05.000000000Z"), payload); e != nil {
		t.Fatal(e)
	}
	f.authentication[string(tenant)+":"+string(user)] = organization.Authentication{TenantID: tenant, Bearer: auth.NewBearerCredential(wire)}
}

func commandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, e := identity.NewCommandID()
	if e != nil {
		t.Fatal(e)
	}
	return id
}
func (f *orgFixture) auth(tenant, user string) organization.Authentication {
	return f.authentication[tenant+":"+user]
}
func (f *orgFixture) create(t *testing.T, tenant string) organizationpg.PreparedCommand {
	t.Helper()
	p, e := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Slug: "example", Name: "Example", CorrelationID: "organization-test"}, "127.0.0.1")
	if e != nil {
		t.Fatal("prepare create", e)
	}
	r, e := f.service.Execute(f.ctx, p)
	if e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("create did not commit", r.Receipt.Outcome, e)
	}
	return p
}
func (f *orgFixture) add(t *testing.T, tenant, user string, role organization.Role, version uint64) organizationpg.PreparedCommand {
	t.Helper()
	p, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: identity.UserID(user), Role: role, OrganizationVersion: version, CorrelationID: "organization-test"}, "127.0.0.1")
	if e != nil {
		t.Fatal("prepare member", e)
	}
	r, e := f.service.Execute(f.ctx, p)
	if e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("member did not commit", r.Receipt.Outcome, e)
	}
	return p
}

func TestOrganizationPostgresMembership(t *testing.T) {
	f := newOrgFixture(t)
	t.Run("create_replay_recovery_membership_removal", func(t *testing.T) {
		tenant := "org-test-basic"
		created := f.create(t, tenant)
		again, e := f.service.Execute(f.ctx, created)
		if e != nil || again.Receipt.Outcome != identity.CommitOutcomeCommitted || again.Receipt.Feature.AfterVersion != 1 {
			t.Fatal("identical replay changed outcome", e)
		}
		recovery, e := created.Recovery()
		if e != nil {
			t.Fatal(e)
		}
		restarted, e := organizationpg.NewService(f.participant, f.configuration)
		if e != nil {
			t.Fatal(e)
		}
		recovered, e := restarted.Recover(f.ctx, f.auth(tenant, "owner"), recovery)
		if e != nil || recovered.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("scoped restart recovery failed", e)
		}
		f.add(t, tenant, "second", organization.RoleOwner, 1)
		page, e := f.service.ListMembers(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Limit: 1, CorrelationID: "page"})
		if e != nil || len(page.Members) != 1 || page.Members[0].UserID != "owner" || page.NextCursor != "owner" {
			t.Fatal("first stable page", e)
		}
		page, e = f.service.ListMembers(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Cursor: page.NextCursor, Limit: 1, CorrelationID: "page"})
		if e != nil || len(page.Members) != 1 || page.Members[0].UserID != "second" || page.NextCursor != "" {
			t.Fatal("second stable page", e)
		}
		remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "owner", OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "remove"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		r, e := f.service.Execute(f.ctx, remove)
		if e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("remove failed", e)
		}
		if _, e = f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CorrelationID: "denied"}); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("removed actor retained organization access", e)
		}
		last, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "second", OrganizationVersion: 3, MemberVersion: 1, CorrelationID: "last-owner"}, "127.0.0.1")
		if !errors.Is(e, organization.ErrLastOwner) || last != (organizationpg.PreparedCommand{}) {
			t.Fatal("last owner removal admitted", e)
		}
		var users, epochs string
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT u.authority_version::text,a.version::text FROM identity.users u JOIN authorization_subject_authorities a ON a.tenant_id=u.tenant_id AND a.subject_id=u.user_id AND a.policy_namespace='users' WHERE u.tenant_id=$1 AND u.user_id='owner'`, tenant).Scan(&users, &epochs); e != nil || users != "1" || epochs != "1" {
			t.Fatal("organization removal changed global user authority", e)
		}
		var count int
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1`, tenant).Scan(&count); e != nil || count != 3 {
			t.Fatal("replay duplicated protected effects", e)
		}
	})
	t.Run("stale_target_and_outbox_failure_rollback", func(t *testing.T) {
		tenant := "org-test-target"
		f.create(t, tenant)
		p, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "member", Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "target"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.pool.Raw().Exec(f.ctx, `UPDATE identity.users SET status='suspended',version=version+1 WHERE tenant_id=$1 AND user_id='member'`, tenant); e != nil {
			t.Fatal(e)
		}
		r, e := f.service.Execute(f.ctx, p)
		if e == nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("stale target admitted", r.Receipt.Outcome, e)
		}
		var count int
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND user_id='member'`, tenant).Scan(&count); e != nil || count != 0 {
			t.Fatal("target denial left membership", e)
		}
		tenant = "org-test-rollback"
		f.create(t, tenant)
		p, e = f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "member", Role: organization.RoleMember, OrganizationVersion: 1, CorrelationID: "rollback"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.pool.Raw().Exec(f.ctx, `CREATE FUNCTION public.organization_test_fail_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic lifecycle failure'; END $$; CREATE TRIGGER organization_test_fail_lifecycle BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION public.organization_test_fail_lifecycle()`); e != nil {
			t.Fatal(e)
		}
		r, e = f.service.Execute(f.ctx, p)
		if e == nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("lifecycle failure did not prove rollback", r.Receipt.Outcome, e)
		}
		if _, e = f.pool.Raw().Exec(f.ctx, `DROP TRIGGER organization_test_fail_lifecycle ON public.identity_outbox_bindings; DROP FUNCTION public.organization_test_fail_lifecycle()`); e != nil {
			t.Fatal(e)
		}
		var version string
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT version::text FROM organization.organizations WHERE tenant_id=$1`, tenant).Scan(&version); e != nil || version != "1" {
			t.Fatal("failed lifecycle committed organization epoch", e)
		}
		scope, e := organizationpg.OrganizationAuthorityScope(identity.TenantID(tenant), "01ARZ3NDEKTSV4RRFFQ69G5FAV", "member")
		if e != nil {
			t.Fatal(e)
		}
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM authorization_subject_authorities WHERE tenant_id=$1 AND policy_namespace=$2 AND subject_id='member'`, tenant, scope.PolicyNamespace).Scan(&count); e != nil || count != 0 {
			t.Fatal("failed lifecycle committed target epoch", e)
		}
		r, e = f.service.Execute(f.ctx, p)
		// The coordinator returns the retained terminal receipt without
		// replaying its original error (reservePreparedCommand/journalTerminal).
		recovery, recoveryErr := p.Recovery()
		if e != nil || recoveryErr != nil || r.Receipt.Outcome != identity.CommitOutcomeNotCommitted || r.Receipt.Binding != recovery.Binding {
			t.Fatal("aborted replay retried effects", e)
		}
		if e = f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND user_id='member'`, tenant).Scan(&count); e != nil || count != 0 {
			t.Fatal("aborted replay created membership", e)
		}
	})
	t.Run("concurrent_owner_removal_serializes", func(t *testing.T) {
		tenant := "org-test-race"
		f.create(t, tenant)
		f.add(t, tenant, "second", organization.RoleOwner, 1)
		commands := make([]organizationpg.PreparedCommand, 2)
		for i, pair := range [][2]string{{"owner", "second"}, {"second", "owner"}} {
			var e error
			commands[i], e = f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, pair[0]), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: identity.UserID(pair[1]), OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "race"}, "127.0.0.1")
			if e != nil {
				t.Fatal(e)
			}
		}
		var wg sync.WaitGroup
		outcomes := make(chan identity.CommitOutcome, 2)
		start := make(chan struct{})
		for _, p := range commands {
			wg.Add(1)
			go func() { defer wg.Done(); <-start; r, _ := f.service.Execute(f.ctx, p); outcomes <- r.Receipt.Outcome }()
		}
		close(start)
		wg.Wait()
		close(outcomes)
		committed := 0
		for o := range outcomes {
			if o == identity.CommitOutcomeCommitted {
				committed++
			}
		}
		if committed != 1 {
			t.Fatal("owner race did not select exactly one winner")
		}
		var owners int
		if e := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.memberships WHERE tenant_id=$1 AND role='owner' AND state='active'`, tenant).Scan(&owners); e != nil || owners != 1 {
			t.Fatal("owner invariant lost", e)
		}
	})
	t.Run("unknown_commit_response_recovers_without_reexecution", func(t *testing.T) { testUnknownCommit(t, f) })
	t.Run("scope_and_readmission_preserve_authority", func(t *testing.T) {
		tenant := "org-test-scope"
		created := f.create(t, tenant)
		recovery, e := created.Recovery()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.service.Recover(f.ctx, f.auth(tenant, "outsider"), recovery); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("another actor observed command result", e)
		}
		request := organization.ReadRequest{Authentication: f.auth(tenant, "outsider"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CorrelationID: "scope"}
		if _, e = f.service.Get(f.ctx, request); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("nonmember accessed existing organization", e)
		}
		request.Authentication = f.auth(tenant, "owner")
		request.Authentication.TenantID = "org-test-basic"
		if _, e = f.service.Get(f.ctx, request); e == nil {
			t.Fatal("foreign tenant accepted bearer")
		}
		f.add(t, tenant, "member", organization.RoleMember, 1)
		second, e := f.service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", Slug: "other", Name: "Other", CorrelationID: "scope"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := f.service.Execute(f.ctx, second); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("second organization failed", e)
		}
		request = organization.ReadRequest{Authentication: f.auth(tenant, "member"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", CorrelationID: "scope"}
		if _, e = f.service.Get(f.ctx, request); !errors.Is(e, organization.ErrForbidden) {
			t.Fatal("membership leaked across organizations", e)
		}
		remove, e := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "member", OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "remove"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := f.service.Execute(f.ctx, remove); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("member removal failed", e)
		}
		readmit, e := f.service.PrepareAddMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", UserID: "member", Role: organization.RoleMember, OrganizationVersion: 3, MemberVersion: 2, CorrelationID: "readmit"}, "127.0.0.1")
		if e != nil {
			t.Fatal(e)
		}
		if r, e := f.service.Execute(f.ctx, readmit); e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("tombstone readmission failed", e)
		}
		request.OrganizationID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
		v, e := f.service.Get(f.ctx, request)
		if e != nil || v.Actor.Version != 3 || v.Actor.AuthorizationVersion != 3 || v.Organization.Version != 4 {
			t.Fatal("readmission reset durable versions", e)
		}
	})
}
