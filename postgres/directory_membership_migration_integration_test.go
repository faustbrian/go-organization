//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestDirectoryMembershipMigrationSourceValidation(t *testing.T) {
	for _, version := range []uint64{0, math.MaxInt64 + 1, math.MaxUint64} {
		steps, err := (organizationpg.DirectoryMembershipMigrationSource{Version: version}).Load(t.Context())
		if !errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0 {
			t.Fatal("invalid migration version accepted", version, err)
		}
	}
	source := organizationpg.DirectoryMembershipMigrationSource{Version: 301}
	if steps, err := source.Load(nil); !errors.Is(err, organization.ErrInvalidInput) || len(steps) != 0 {
		t.Fatal("nil migration context accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if steps, err := source.Load(ctx); !errors.Is(err, context.Canceled) || len(steps) != 0 {
		t.Fatal("canceled migration context accepted", err)
	}
}

// This is a populated native-schema upgrade, not SCIM provisioning acceptance.
func TestDirectoryMembershipMigrationPreservesPopulatedMembershipAndSourceHistory(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	f.add(t, "org-test-basic", "member", organization.RoleMember, 1)
	snapshot := func() string {
		t.Helper()
		var state string
		if err := f.pool.Raw().QueryRow(f.ctx, `SELECT jsonb_build_object(
 'organizations',(SELECT jsonb_agg(to_jsonb(o) ORDER BY tenant_id,organization_id) FROM organization.organizations o),
 'memberships',(SELECT jsonb_agg(to_jsonb(m) ORDER BY tenant_id,organization_id,user_id) FROM organization.memberships m),
 'effects',(SELECT jsonb_agg(to_jsonb(e) ORDER BY command_id) FROM organization.command_effects e))::text`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := snapshot()
	steps, err := (organizationpg.DirectoryMembershipMigrationSource{Version: 301}).Load(f.ctx)
	if err != nil || len(steps) != 1 {
		t.Fatal("directory membership migration unavailable", err)
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history := append(append(migrationList(nil), f.history...), steps...)
	runner, err := migrations.NewRunner(history, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated source-only upgrade failed", err)
	}
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("native upgrade replay failed", err)
	}
	var grants int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.directory_membership_grants`).Scan(&grants); err != nil || grants != 0 || snapshot() != before {
		t.Fatal("additive migration changed legacy authority or invented source grants", err)
	}
	const insert = `INSERT INTO organization.directory_membership_grants(tenant_id,organization_id,user_id,member_version,provider_id,connection_id,resource_id,version,active) VALUES($1,$2,$3,$4::numeric,$5,$6,$7,$8::numeric,$9)`
	valid := []any{"org-test-basic", string(metadataOrganization), "member", "1", "provider-a", "connection-a", "resource-a", "1", true}
	if _, err := f.pool.Raw().Exec(f.ctx, insert, valid...); err != nil {
		t.Fatal("valid source grant rejected", err)
	}
	for _, tc := range []struct {
		name, code string
		column     int
		value      any
	}{
		{"duplicate-source", "23505", 6, "resource-rebound"},
		{"cross-tenant", "23503", 0, "org-test-scope"},
		{"cross-organization", "23503", 1, "missing"},
		{"missing-membership", "23503", 2, "outsider"},
		{"invalid-member-version", "23514", 3, "0"},
		{"overflow-member-version", "23514", 3, "18446744073709551616"},
		{"empty-provider", "23514", 4, ""},
		{"empty-connection", "23514", 5, ""},
		{"empty-resource", "23514", 6, ""},
		{"invalid-source-version", "23514", 7, "0"},
		{"overflow-source-version", "23514", 7, "18446744073709551616"},
		{"missing-active", "23502", 8, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := append([]any(nil), valid...)
			values[tc.column] = tc.value
			_, err := f.pool.Raw().Exec(f.ctx, insert, values...)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != tc.code {
				t.Fatal("source invariant not enforced", err)
			}
		})
	}
	for column := range valid {
		values := append([]any(nil), valid...)
		values[column] = nil
		if _, err := f.pool.Raw().Exec(f.ctx, insert, values...); err == nil {
			t.Fatal("source identity accepted null column", column)
		}
	}
	// Distinct source owners and membership incarnations retain independent rows.
	for _, change := range []struct {
		column int
		value  any
	}{{4, "provider-b"}, {5, "connection-b"}, {3, "2"}} {
		values := append([]any(nil), valid...)
		values[change.column] = change.value
		if _, err := f.pool.Raw().Exec(f.ctx, insert, values...); err != nil {
			t.Fatal("independent source or member incarnation collided", err)
		}
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `UPDATE organization.directory_membership_grants SET active=false,version=2 WHERE provider_id='provider-a' AND connection_id='connection-a' AND member_version=1`); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.directory_membership_grants WHERE resource_id='resource-a' AND ((member_version=1 AND provider_id='provider-a' AND connection_id='connection-a' AND NOT active AND version=2) OR active)`).Scan(&retained); err != nil || retained != 4 || snapshot() != before {
		t.Fatal("source lifecycle changed local membership or lost independent history", retained, err)
	}
	// A pre-extension contributor still writes the original membership schema.
	f.add(t, "org-test-basic", "outsider", organization.RoleMember, 2)
	var sourceForLocal int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.directory_membership_grants WHERE user_id='outsider'`).Scan(&sourceForLocal); err != nil || sourceForLocal != 0 {
		t.Fatal("legacy member write acquired implicit directory provenance", err)
	}
}

func TestDirectoryMembershipMigrationNativeRollbackAndReplay(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := backend.AcquireCommand(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer owned.Release(f.ctx)
	base, err := owned.ReadLedger(f.ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	steps, err := (organizationpg.DirectoryMembershipMigrationSource{Version: 301}).Load(f.ctx)
	if err != nil || len(steps) != 1 {
		t.Fatal(err)
	}
	failure, err := migrations.NewMigration(302, "directory_membership_deliberate_failure", migrations.TransactionModeDefault, "SELECT 1/0;", "")
	if err != nil {
		t.Fatal(err)
	}
	request := func(id string, digest byte, suffix []migrations.Migration) migrationpg.CommandRequest {
		return migrationpg.CommandRequest{ID: id, Fingerprint: [32]byte{1}, IdempotencyDigest: [32]byte{digest}, Histories: []migrationpg.CommandHistory{{Source: append(append([]migrations.Migration(nil), f.history...), suffix...), Base: base}}, Batches: []migrationpg.CommandBatch{{Migrations: suffix}}}
	}
	failed := request("organization_directory_membership_rollback", 1, append(append([]migrations.Migration(nil), steps...), failure))
	if progress, err := owned.Execute(f.ctx, failed); err == nil || progress.Complete() || len(progress.Receipts()) != 0 {
		t.Fatal("failed native upgrade gained committed progress", err)
	}
	var exists bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('organization.directory_membership_grants') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatal("interrupted native batch left source schema", err)
	}
	if ledger, err := owned.ReadLedger(f.ctx, ""); err != nil || !reflect.DeepEqual(ledger, base) {
		t.Fatal("interrupted native batch changed installed history", err)
	}
	good := request("organization_directory_membership_commit", 2, steps)
	committed, err := owned.Execute(f.ctx, good)
	if err != nil || !committed.Complete() || len(committed.Receipts()) != 1 {
		t.Fatal("native source upgrade did not commit", err)
	}
	if replayed, err := owned.Execute(f.ctx, good); err != nil || !reflect.DeepEqual(replayed, committed) {
		t.Fatal("native source upgrade replay changed receipt or reran DDL", err)
	}
}

func TestDirectoryMembershipMigrationBoundsReferencedTableLock(t *testing.T) {
	f := newOrgFixture(t)
	f.create(t, "org-test-basic")
	steps, err := (organizationpg.DirectoryMembershipMigrationSource{Version: 301}).Load(f.ctx)
	if err != nil || len(steps) != 1 {
		t.Fatal(err)
	}
	blocker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(f.ctx)
	if _, err := blocker.Exec(f.ctx, `LOCK TABLE organization.memberships IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	candidate, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Rollback(f.ctx)
	_, err = candidate.Exec(f.ctx, steps[0].UpSQL())
	var lock *pgconn.PgError
	if !errors.As(err, &lock) || lock.Code != "55P03" {
		t.Fatal("upgrade did not honor its referenced-table lock budget", err)
	}
	if err := candidate.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('organization.directory_membership_grants') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatal("lock-budget abort left partial source schema", err)
	}
}
