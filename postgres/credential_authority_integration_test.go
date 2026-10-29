//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func installCredentialAuthority(t *testing.T, f *orgFixture) {
	t.Helper()
	additional, err := (organizationpg.CredentialAuthorityMigrationSource{Version: 12000}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.Database = f.database
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(append(append(migrationList(nil), f.history...), additional...), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("populated credential authority migration", err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("credential authority migration replay", err)
	}
}

func TestCredentialAuthorityPostgresOwnerSurvivesCreatorRemoval(t *testing.T) {
	f := newOrgFixture(t)
	const tenant = "org-test-basic"
	f.create(t, tenant)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reader, ok := any(repository).(organization.CredentialAuthorityReader)
	if !ok {
		t.Fatal("native repository lacks owner-only authority")
	}
	q := organization.CredentialAuthorityQuery{TenantID: tenant, OrganizationID: metadataOrganization}
	if o, err := reader.ObserveCredentialAuthority(f.ctx, q); err == nil || o != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("missing optional migration returned positive facts", err)
	}
	installCredentialAuthority(t, f)
	before, err := reader.ObserveCredentialAuthority(f.ctx, q)
	if err != nil || before.Version != 1 || before.CredentialVersion != 1 || before.Actor != (organization.Member{}) || before.Validate(q, time.Now()) != nil {
		t.Fatal("owner-only observation", err)
	}
	f.add(t, tenant, "second", organization.RoleOwner, 1)
	actorQuery := q
	actorQuery.ActorID = "owner"
	member, err := reader.ObserveCredentialAuthority(f.ctx, actorQuery)
	if err != nil || member.Actor.UserID != "owner" || !member.Actor.Active || member.Version != 2 || member.CredentialVersion != 1 {
		t.Fatal("actual current member", err)
	}
	changeRole, err := f.service.PrepareUpdateMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: "owner", Role: organization.RoleAdministrator, OrganizationVersion: 2, MemberVersion: 1, CorrelationID: "credential-creator-role"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.service.Execute(f.ctx, changeRole); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual member role transition", err)
	}
	member, err = reader.ObserveCredentialAuthority(f.ctx, actorQuery)
	if err != nil || member.Version != 3 || member.CredentialVersion != 1 || member.Actor.Version != 2 || member.Actor.Role != organization.RoleAdministrator {
		t.Fatal("role transition changed independent credential authority", err)
	}
	remove, err := f.service.PrepareRemoveMember(f.ctx, organization.MemberRequest{Authentication: f.auth(tenant, "second"), CommandID: commandID(t), OrganizationID: metadataOrganization, UserID: "owner", OrganizationVersion: 3, MemberVersion: 2, CorrelationID: "credential-creator-removal"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := f.service.Execute(f.ctx, remove); err != nil || result.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("actual creator removal", err)
	}
	after, err := reader.ObserveCredentialAuthority(f.ctx, q)
	if err != nil || after.Version != 4 || after.CredentialVersion != before.CredentialVersion || after.Actor != (organization.Member{}) {
		t.Fatal("creator removal revoked independent owner authority", err)
	}
	if o, err := reader.ObserveCredentialAuthority(f.ctx, actorQuery); !errors.Is(err, organization.ErrForbidden) || o != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("removed creator retained authority", err)
	}
	if _, err := repository.Read(f.ctx, organization.Query{Operation: organization.Get, TenantID: tenant, OrganizationID: metadataOrganization, ActorID: "owner"}); !errors.Is(err, organization.ErrForbidden) {
		t.Fatal("existing member-only read changed", err)
	}
	actorQuery.ActorID = "second"
	if o, err := reader.ObserveCredentialAuthority(f.ctx, actorQuery); err != nil || o.Actor.UserID != "second" || o.Validate(actorQuery, time.Now()) != nil {
		t.Fatal("remaining actual member denied", err)
	}
	for _, invalid := range []organization.CredentialAuthorityQuery{{TenantID: "other", OrganizationID: q.OrganizationID}, {TenantID: tenant, OrganizationID: "absent"}, {TenantID: tenant, OrganizationID: q.OrganizationID, ActorID: "outsider"}, {}} {
		if o, err := reader.ObserveCredentialAuthority(f.ctx, invalid); err == nil || o != (organization.CredentialAuthorityObservation{}) {
			t.Fatal("invalid authority disclosed facts", err)
		}
	}
	cancelled, cancel := context.WithCancel(f.ctx)
	cancel()
	if o, err := reader.ObserveCredentialAuthority(cancelled, q); !errors.Is(err, context.Canceled) || o != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("cancelled observation disclosed facts", err)
	}
	scope, err := organizationpg.OrganizationAuthorityScope(q.TenantID, q.OrganizationID, "second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.AdvanceAuthority(f.ctx, f.pool.Raw(), scope, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if o, err := reader.ObserveCredentialAuthority(f.ctx, actorQuery); !errors.Is(err, organization.ErrForbidden) || o != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("stale scoped authorization disclosed member facts", err)
	}
}

func TestCredentialAuthorityNativeArchiveRestoreKeepsRevocation(t *testing.T) {
	f := newOwnerFixture(t, true)
	tenant := transferTenants["org-test-basic"]
	f.create(t, tenant)
	installCredentialAuthority(t, f.orgFixture)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reader := any(repository).(organization.CredentialAuthorityReader)
	q := organization.CredentialAuthorityQuery{TenantID: identity.TenantID(tenant), OrganizationID: metadataOrganization}
	before, err := reader.ObserveCredentialAuthority(f.ctx, q)
	if err != nil || before.CredentialVersion != 1 {
		t.Fatal("initial native owner", err)
	}
	commitRole(t, f.orgFixture, lifecycleCommand(t, f, tenant, organization.Archive), nil)
	if o, err := reader.ObserveCredentialAuthority(f.ctx, q); !errors.Is(err, organization.ErrForbidden) || o != (organization.CredentialAuthorityObservation{}) {
		t.Fatal("native archive retained owner authority", err)
	}
	commitRole(t, f.orgFixture, lifecycleCommand(t, f, tenant, organization.Restore), nil)
	after, err := reader.ObserveCredentialAuthority(f.ctx, q)
	if err != nil || after.CredentialVersion != 2 || after.Version != 3 {
		t.Fatal("native restoration revived prior key epoch", err)
	}
}

func TestCredentialAuthorityMixedOldWritersCannotRewindEpoch(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	installCredentialAuthority(t, f)
	repository, err := organizationpg.NewRepository(f.pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	reader := any(repository).(organization.CredentialAuthorityReader)
	q := organization.CredentialAuthorityQuery{TenantID: "org-test-basic", OrganizationID: metadataOrganization}
	for _, step := range []struct {
		state string
		epoch string
	}{{"archived", "2"}, {"active", "2"}, {"archived", "3"}, {"archived", "3"}, {"deleted", "4"}} {
		// This is the pre-extension lifecycle writer's shape: it knows only state
		// and aggregate version and never supplies the credential epoch.
		if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state=$3,version=version+1 WHERE tenant_id=$1 AND organization_id=$2`, string(q.TenantID), string(q.OrganizationID), step.state); err != nil {
			t.Fatal("old lifecycle writer", err)
		}
		var epoch string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT credential_version::text FROM organization.organizations WHERE tenant_id=$1 AND organization_id=$2`, string(q.TenantID), string(q.OrganizationID)).Scan(&epoch); err != nil || epoch != step.epoch {
			t.Fatal("terminal transition epoch", step.state, epoch, err)
		}
		o, err := reader.ObserveCredentialAuthority(f.ctx, q)
		if step.state == "active" {
			if err != nil || o.CredentialVersion != 2 {
				t.Fatal("restore rewound independent key epoch", err)
			}
		} else if !errors.Is(err, organization.ErrForbidden) || o != (organization.CredentialAuthorityObservation{}) {
			t.Fatal("inactive owner disclosed authority", err)
		}
	}
	for _, value := range []string{"1", "5"} {
		_, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET credential_version=$3::numeric WHERE tenant_id=$1 AND organization_id=$2`, string(q.TenantID), string(q.OrganizationID), value)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23514" || pg.ConstraintName != "organization_credential_epoch_transition" {
			t.Fatal("manual epoch rewrite accepted or wrong error", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.organizations(tenant_id,organization_id,slug,name,state,version,member_count,owner_count,credential_version) VALUES('org-test-basic','source-epoch','source-epoch','Imported','active',1,1,1,18446744073709551615)`); err != nil {
		t.Fatal("valid source epoch rejected", err)
	}
	_, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.organizations SET state='archived',version=version+1 WHERE tenant_id='org-test-basic' AND organization_id='source-epoch'`)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "22003" {
		t.Fatal("credential epoch overflow not rejected", err)
	}
	var state, epoch string
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT state,credential_version::text FROM organization.organizations WHERE tenant_id='org-test-basic' AND organization_id='source-epoch'`).Scan(&state, &epoch); err != nil || state != "active" || epoch != "18446744073709551615" {
		t.Fatal("overflow partially changed owner", err)
	}
}
