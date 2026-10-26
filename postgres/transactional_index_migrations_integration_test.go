//go:build integration

package postgres_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// This checks actual transactional index/ledger/receipt ownership, not signup,
// invitation issuance or request authentication. The native fixture owns cleanup.
func TestTransactionalIndexMigrationsDurableCommandAtomicity(t *testing.T) {
	f := newOrgFixture(t, organizationpg.InvitationMigrationSource{Version: 301})
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
	owned, err := backend.AcquireCommand(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := owned.Release(cleanup); err != nil {
			t.Error("migration command ownership release failed", err)
		}
	}()
	base, err := owned.ReadLedger(f.ctx, "")
	if err != nil || len(base) != len(f.history) {
		t.Fatal("native base history unavailable", err)
	}
	var indexes []migrations.Migration
	for _, source := range []migrations.Source{organizationpg.OperationLookupTransactionalMigrationSource{Version: 302}, organizationpg.InvitationRecipientIndexTransactionalMigrationSource{Version: 303}} {
		steps, err := source.Load(f.ctx)
		if err != nil || len(steps) != 1 {
			t.Fatal("transactional native index source unavailable", err)
		}
		indexes = append(indexes, steps...)
	}
	request := func(id string, digest byte, suffix []migrations.Migration) migrationpg.CommandRequest {
		return migrationpg.CommandRequest{ID: id, Fingerprint: [32]byte{1}, IdempotencyDigest: [32]byte{digest}, Histories: []migrationpg.CommandHistory{{Source: append(append([]migrations.Migration(nil), f.history...), suffix...), Base: base}}, Batches: []migrationpg.CommandBatch{{Migrations: suffix}}}
	}
	failure, err := migrations.NewMigration(304, "transactional_index_deliberate_failure", migrations.TransactionModeDefault, "SELECT 1/0;", "")
	if err != nil {
		t.Fatal(err)
	}
	failed := request("organization_index_rollback_0001", 1, append(append([]migrations.Migration(nil), indexes...), failure))
	progress, err := owned.Execute(f.ctx, failed)
	if err == nil || progress.Complete() || len(progress.Receipts()) != 0 {
		t.Fatal("failed index batch gained a durable receipt", err)
	}
	stored, exists, err := owned.ReadProgress(f.ctx, failed.ID)
	if err != nil || !exists || stored.Complete() || len(stored.Receipts()) != 0 {
		t.Fatal("rollback did not retain exact zero-receipt native checkpoint", err)
	}
	var count int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='organization' AND c.relname IN ('organization_repeat_removal','organization_invitation_recipient_page')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("rolled-back batch retained an index", err)
	}
	ledger, err := owned.ReadLedger(f.ctx, "")
	if err != nil || !reflect.DeepEqual(ledger, base) {
		t.Fatal("rolled-back index batch changed original ledger", err)
	}
	// Repeating the exact failed command may retry its uncommitted SQL, but
	// cannot create either protected index or a receipt from the aborted batch.
	if retried, err := owned.Execute(f.ctx, failed); err == nil || retried.Complete() || len(retried.Receipts()) != 0 {
		t.Fatal("failed original retry invented durable progress", err)
	}
	good := request("organization_index_commit_0001", 2, indexes)
	committed, err := owned.Execute(f.ctx, good)
	if err != nil || !committed.Complete() || len(committed.Receipts()) != 2 {
		t.Fatal("atomic native index command failed", err)
	}
	for i, receipt := range committed.Receipts() {
		if receipt.Namespace != "" || receipt.Record.Dirty() || receipt.Record.Version() != indexes[i].Version() || receipt.Record.Name() != indexes[i].Name() || receipt.Record.Checksum() != indexes[i].Checksum() {
			t.Fatal("native receipt lost exact transactional index identity")
		}
	}
	inspect := func() []uint32 {
		t.Helper()
		var identities []uint32
		for _, expected := range []struct {
			name, table, predicate string
			unique                 bool
			columns                []string
		}{
			{"organization_repeat_removal", "command_effects", "(operation = 'identity.organization.member.remove'::text)", true, []string{"tenant_id", "organization_id", "before_version"}},
			{"organization_invitation_recipient_page", "invitations", "", false, []string{"tenant_id", "recipient_user_id", "recipient_identifier_id", "recipient_identifier_version", "invitation_id"}},
		} {
			var oid uint32
			var unique, valid, ready, exactCollations bool
			var table, predicate, method string
			var columns []string
			err := f.pool.Raw().QueryRow(f.ctx, `SELECT c.oid,i.indisunique,i.indisvalid,i.indisready,t.relname,coalesce(pg_catalog.pg_get_expr(i.indpred,i.indrelid),''),am.amname,
 ARRAY(SELECT a.attname::text FROM unnest(i.indkey) WITH ORDINALITY k(attnum,pos) JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.pos),
 ARRAY(SELECT unnest(i.indcollation))=ARRAY(SELECT CASE WHEN a.attname='invitation_id' THEN 'pg_catalog."C"'::regcollation::oid ELSE a.attcollation END FROM unnest(i.indkey) WITH ORDINALITY k(attnum,pos) JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum ORDER BY k.pos)
 FROM pg_catalog.pg_index i JOIN pg_catalog.pg_class c ON c.oid=i.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_class t ON t.oid=i.indrelid JOIN pg_catalog.pg_am am ON am.oid=c.relam WHERE n.nspname='organization' AND c.relname=$1`, expected.name).Scan(&oid, &unique, &valid, &ready, &table, &predicate, &method, &columns, &exactCollations)
			if err != nil || unique != expected.unique || !valid || !ready || !exactCollations || table != expected.table || predicate != expected.predicate || method != "btree" || !reflect.DeepEqual(columns, expected.columns) {
				t.Fatal("committed native index identity/predicate/collation invalid", expected.name, err, unique, valid, ready, exactCollations, table, predicate, method, columns)
			}
			identities = append(identities, oid)
		}
		return identities
	}
	identities := inspect()
	// The SQL deliberately has no IF NOT EXISTS: reapplying a committed CREATE
	// INDEX would fail. Exact receipts and unchanged physical OIDs prove replay.
	for range 2 {
		replayed, err := owned.Execute(f.ctx, good)
		if err != nil || !reflect.DeepEqual(replayed, committed) || !reflect.DeepEqual(inspect(), identities) {
			t.Fatal("original command retry reapplied indexes or changed metadata", err)
		}
	}
	stored, exists, err = owned.ReadProgress(f.ctx, good.ID)
	if err != nil || !exists || !reflect.DeepEqual(stored, committed) {
		t.Fatal("durable index recovery lost original metadata", err)
	}
}
