//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

type operationLookupPlan struct {
	NodeType string                `json:"Node Type"`
	Index    string                `json:"Index Name"`
	Rows     float64               `json:"Actual Rows"`
	Loops    float64               `json:"Actual Loops"`
	Filtered float64               `json:"Rows Removed by Filter"`
	Hits     int64                 `json:"Shared Hit Blocks"`
	Reads    int64                 `json:"Shared Read Blocks"`
	Plans    []operationLookupPlan `json:"Plans"`
}

func (p operationLookupPlan) examined() float64 {
	n := float64(0)
	if p.NodeType == "Seq Scan" || p.NodeType == "Index Scan" || p.NodeType == "Index Only Scan" || p.NodeType == "Bitmap Heap Scan" {
		n = (p.Rows + p.Filtered) * p.Loops
	}
	for _, child := range p.Plans {
		n += child.examined()
	}
	return n
}

func (p operationLookupPlan) indexed() bool {
	if p.Index == "organization_repeat_removal" {
		return true
	}
	for _, child := range p.Plans {
		if child.indexed() {
			return true
		}
	}
	return false
}

// This bounded isolated physical-history fixture is an access-path/migration
// check, not evidence that synthetic rows are authenticated domain transitions.
// Genuine original-receipt replay is covered by the separate public consumer.
func TestOperationLookupPopulatedMigrationAndBoundedQuery(t *testing.T) {
	f := newOrgFixture(t)
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version)
SELECT translate(rtrim(encode(int8send(n)||int8send(19),'base64'),'='),'+/','-_'),
'plan-tenant','plan-'||lpad(n::text,8,'0'),'target','actor',
CASE WHEN n%4=0 THEN 'identity.organization.member.remove' ELSE 'identity.organization.member.add' END,
decode(repeat('ab',32),'hex'),7,8 FROM generate_series(1::bigint,20000::bigint) n`); err != nil {
		t.Fatal("owned operation history setup failed", err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	// Same parameterized shape and scalar bindings as removalOutcome's exact
	// natural lookup, including its constant predicate for partial-index use.
	const sql = `SELECT command_id FROM organization.command_effects
WHERE tenant_id=$1 AND organization_id=$2 AND before_version=$3::numeric
AND operation='identity.organization.member.remove' AND actor_id=$4 AND user_id=$5
LIMIT 2`
	args := []any{"plan-tenant", "plan-00010000", "7", "actor", "target"}
	read := func() (operationLookupPlan, float64) {
		t.Helper()
		var wire []byte
		if err := f.pool.Raw().QueryRow(f.ctx, "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); err != nil {
			t.Fatal(err)
		}
		var reports []struct {
			Plan          operationLookupPlan
			ExecutionTime float64 `json:"Execution Time"`
		}
		if json.Unmarshal(wire, &reports) != nil || len(reports) != 1 {
			t.Fatal("invalid owned plan report")
		}
		return reports[0].Plan, reports[0].ExecutionTime
	}
	var baseline operationLookupPlan
	var baselineMS float64
	for range 3 {
		baseline, baselineMS = read()
	}
	db := stdlib.OpenDB(*f.pool.Raw().Config().ConnConfig)
	defer db.Close()
	steps, err := (organizationpg.OperationLookupMigrationSource{Version: 301}).Load(f.ctx)
	if err != nil || len(steps) != 1 || steps[0].TransactionMode() != migrations.TransactionModeNone {
		t.Fatal("lookup migration did not select actual nontransactional lane", err)
	}
	backend, err := migrationpg.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(append(append(migrationList(nil), f.history...), steps...), backend)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated concurrent index migration failed", err)
	}
	build := time.Since(started)
	if _, err := runner.Up(f.ctx); err != nil {
		t.Fatal("populated migration replay failed", err)
	}
	var indexed operationLookupPlan
	var indexedMS float64
	for range 3 {
		indexed, indexedMS = read()
	}
	var indexBytes, heapBytes, allIndexes, partialRows, allRows int64
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT pg_relation_size('organization.organization_repeat_removal'),pg_relation_size('organization.command_effects'),pg_indexes_size('organization.command_effects'),(SELECT count(*) FROM organization.command_effects WHERE operation='identity.organization.member.remove'),(SELECT count(*) FROM organization.command_effects)`).Scan(&indexBytes, &heapBytes, &allIndexes, &partialRows, &allRows); err != nil {
		t.Fatal(err)
	}
	if baseline.Rows != 1 || indexed.Rows != 1 || !indexed.indexed() || indexed.examined() > 1 || indexed.examined() >= baseline.examined() || partialRows != 5000 || allRows != 20000 || indexBytes == 0 {
		t.Fatal("new owned lookup did not preserve bounded original selection", baseline.Rows, indexed.Rows, baseline.examined(), indexed.examined(), partialRows, allRows)
	}
	// Existing writer shape remains valid after the populated additive install.
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','legacy-tenant','legacy-org','target','actor','identity.organization.member.remove',decode(repeat('ab',32),'hex'),1,2)`); err != nil {
		t.Fatal("old native append shape no longer compatible", err)
	}
	t.Logf("isolated history%d/removals%d; warm third samples baseline scan%.0f buffers%d %.3fms; indexed scan%.0f buffers%d %.3fms; newindexbytes%d heapbytes%d allindexesbytes%d; concurrent runner build%s", allRows, partialRows, baseline.examined(), baseline.Hits+baseline.Reads, baselineMS, indexed.examined(), indexed.Hits+indexed.Reads, indexedMS, indexBytes, heapBytes, allIndexes, build)
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := db.PingContext(cleanup); err != nil {
		t.Fatal("migration runner did not release its borrowed database", err)
	}
}
