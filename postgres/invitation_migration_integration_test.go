//go:build integration

package postgres_test

import (
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This is a controlled persistence-invariant fixture, not invitation issuance,
// capability consumption, delivery or genuine consumer acceptance evidence.
func TestInvitationMigrationPreservesMembershipAndEnforcesScope(t *testing.T) {
	f := newOrgFixture(t)
	p := f.create(t, "org-test-basic")
	out, err := f.service.Execute(f.ctx, p)
	if err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("existing organization profile changed", err)
	}
	// Install after a genuine organization commit has populated both membership
	// rows and the existing participant-effect table touched by the new ALTER.
	additional, err := (organizationpg.InvitationMigrationSource{Version: 301}).Load(f.ctx)
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
		t.Fatal("populated invitation migration failed", err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("populated migration replay failed", err)
	}
	const insert = `INSERT INTO organization.invitations(tenant_id,organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,expires_at,delivery_effect_id) VALUES($1,$2,$3,'member','recipient-email',1,'owner',$4,$5,$6,$7,$8)`
	org := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	expires := time.Now().UTC().Truncate(time.Second).Add(48 * time.Hour)
	if _, err = f.pool.Raw().Exec(f.ctx, insert, "org-test-basic", org, "invitation-a", "member", "pending", 1, expires, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal("pending invitation could not persist", err)
	}
	for _, variant := range []string{"duplicate", "cross-tenant", "cross-organization", "privileged-role", "invented-status", "wrong-version", "invalid-effect"} {
		t.Run(variant, func(t *testing.T) {
			tenant, organization, id, role, state, version, effect := "org-test-basic", org, "invitation-b", "member", "pending", 1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			switch variant {
			case "duplicate":
				id = "invitation-a"
			case "cross-tenant":
				tenant = "org-test-scope"
			case "cross-organization":
				organization = "missing"
			case "privileged-role":
				role = "owner"
			case "invented-status":
				state = "cancelled"
			case "wrong-version":
				version = 2
			case "invalid-effect":
				effect = "proof-or-address"
			}
			if _, err := f.pool.Raw().Exec(f.ctx, insert, tenant, organization, id, role, state, version, expires, effect); err == nil {
				t.Fatal("invalid invitation persisted")
			}
		})
	}
	var invitations, members, orgVersion int
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.invitations),member_count,version::integer FROM organization.organizations WHERE tenant_id='org-test-basic' AND organization_id=$1`, org).Scan(&invitations, &members, &orgVersion); err != nil || invitations != 1 || members != 1 || orgVersion != 1 {
		t.Fatal("invalid invitations changed domain state", err)
	}
	// The next forward migration must preserve populated metadata-only rows,
	// without manufacturing an original issued capability for those rows.
	capabilitySteps, err := (organizationpg.InvitationCapabilityMigrationSource{Version: 302}).Load(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err = migrations.NewRunner(append(append(append(migrationList(nil), f.history...), additional...), capabilitySteps...), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("populated original-issuance upgrade failed", err)
	}
	if _, err = runner.Up(f.ctx); err != nil {
		t.Fatal("original-issuance migration replay failed", err)
	}
	var legacy bool
	if err = f.pool.Raw().QueryRow(f.ctx, `SELECT capability_envelope IS NULL AND capability_replay_key_version IS NULL FROM organization.invitations WHERE tenant_id='org-test-basic' AND invitation_id='invitation-a'`).Scan(&legacy); err != nil || !legacy {
		t.Fatal("migration invented capability custody for legacy row", err)
	}
	for _, statement := range []string{
		`UPDATE organization.invitations SET capability_replay_key_version=1`,
		`UPDATE organization.invitations SET capability_envelope=decode(repeat('01',32),'hex')`,
		`UPDATE organization.invitations SET capability_envelope=decode(repeat('00',32),'hex'),capability_replay_key_version=1`,
		`UPDATE organization.invitations SET capability_envelope=decode(repeat('01',32),'hex'),capability_replay_key_version=4294967296`,
	} {
		if _, err = f.pool.Raw().Exec(f.ctx, statement); err == nil {
			t.Fatal("invalid private issuance pair persisted")
		}
	}
	if _, err = f.pool.Raw().Exec(f.ctx, `UPDATE organization.invitations SET capability_envelope=decode(repeat('01',32),'hex'),capability_replay_key_version=1`); err != nil {
		t.Fatal("valid original issuance reference rejected", err)
	}
}
