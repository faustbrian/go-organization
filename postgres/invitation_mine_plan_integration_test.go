//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type invitationMineQueryTrace struct {
	mu   sync.Mutex
	sql  string
	args []any
}

func (t *invitationMineQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(d.SQL, "/* organization.invitation.list-mine */") {
		t.mu.Lock()
		t.sql, t.args = d.SQL, append([]any(nil), d.Args...)
		t.mu.Unlock()
	}
	return ctx
}
func (*invitationMineQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

type invitationMinePlanNode struct {
	NodeType  string                   `json:"Node Type"`
	IndexName string                   `json:"Index Name"`
	Rows      float64                  `json:"Actual Rows"`
	Loops     float64                  `json:"Actual Loops"`
	Filtered  float64                  `json:"Rows Removed by Filter"`
	Hits      int64                    `json:"Shared Hit Blocks"`
	Reads     int64                    `json:"Shared Read Blocks"`
	Plans     []invitationMinePlanNode `json:"Plans"`
}

func (n invitationMinePlanNode) examined() float64 {
	total := float64(0)
	// Count only heap/index scan tuple visits, not inclusive parent outputs.
	switch n.NodeType {
	case "Seq Scan", "Index Scan", "Index Only Scan", "Bitmap Heap Scan":
		total = (n.Rows + n.Filtered) * n.Loops
	}
	for _, p := range n.Plans {
		total += p.examined()
	}
	return total
}
func (n invitationMinePlanNode) usesIndex() bool {
	if n.IndexName == "organization_invitation_recipient_page" {
		return true
	}
	for _, p := range n.Plans {
		if p.usesIndex() {
			return true
		}
	}
	return false
}

// This bounded isolated storage-volume diagnostic is not issuance evidence for
// the added history rows. All sessions and the three functional invitations
// remain the genuine public consumer's actual signup/issue/accept/cancel output.
func exerciseInvitationMinePlan(t *testing.T, ctx context.Context, pool *database.Pool, newService func(*database.Pool) *organizationpg.InvitationService, recipient organization.Authentication, original organization.ID) {
	t.Helper()
	const fixtureIDs = `SELECT translate(rtrim(encode(int8send(n)||int8send(17),'base64'),'='),'+/','-_') FROM generate_series(1::bigint,20000::bigint) n`
	_, err := pool.Raw().Exec(ctx, `INSERT INTO organization.invitations(tenant_id,organization_id,invitation_id,recipient_user_id,recipient_identifier_id,recipient_identifier_version,created_by,role,state,version,created_at,expires_at,accepted_at,delivery_effect_id)
SELECT i.tenant_id,i.organization_id,translate(rtrim(encode(int8send(n)||int8send(17),'base64'),'='),'+/','-_'),i.recipient_user_id,
CASE WHEN n%20=0 THEN i.recipient_identifier_id ELSE 'plan-prior-email' END,i.recipient_identifier_version,i.created_by,i.role,i.state,i.version,i.created_at,i.expires_at,i.accepted_at,i.delivery_effect_id
FROM organization.invitations i CROSS JOIN generate_series(1::bigint,20000::bigint) n WHERE i.tenant_id=$1 AND i.invitation_id=$2`, string(recipient.TenantID), string(original))
	if err != nil {
		t.Fatal("recipient query volume setup", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := pool.Raw().Exec(cleanup, `DELETE FROM organization.invitations WHERE tenant_id=$1 AND invitation_id IN(`+fixtureIDs+`)`, string(recipient.TenantID)); e != nil {
			t.Error("recipient plan fixture cleanup", e)
		}
	}()
	if _, err = pool.Raw().Exec(ctx, `ANALYZE organization.invitations`); err != nil {
		t.Fatal(err)
	}
	trace := new(invitationMineQueryTrace)
	observed, err := database.Connect(ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
		c.ConnConfig.Tracer = trace
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if e := observed.Close(cleanup); e != nil {
			t.Error(e)
		}
	}()
	page, err := newService(observed).ListMine(ctx, organization.InvitationListMineRequest{Authentication: recipient, Limit: 200, CorrelationID: "mine-plan"})
	if err != nil || len(page.Invitations) != 200 || page.NextCursor == "" {
		t.Fatal("actual recipient query volume page", err)
	}
	trace.mu.Lock()
	sql, args := trace.sql, append([]any(nil), trace.args...)
	trace.mu.Unlock()
	if sql == "" {
		t.Fatal("actual recipient query not captured")
	}
	decode := func(wire []byte) invitationMinePlanNode {
		t.Helper()
		var plan []struct{ Plan invitationMinePlanNode }
		if e := json.Unmarshal(wire, &plan); e != nil || len(plan) != 1 {
			t.Fatal("invalid actual query plan", e)
		}
		return plan[0].Plan
	}
	var indexed invitationMinePlanNode
	for range 2 {
		var wire []byte
		if e := pool.Raw().QueryRow(ctx, "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); e != nil {
			t.Fatal(e)
		}
		indexed = decode(wire)
	}
	var indexBytes, heapBytes, indexesBytes int64
	if err = pool.Raw().QueryRow(ctx, `SELECT pg_relation_size('organization.organization_invitation_recipient_page'),pg_relation_size('organization.invitations'),pg_indexes_size('organization.invitations')`).Scan(&indexBytes, &heapBytes, &indexesBytes); err != nil {
		t.Fatal(err)
	}
	// Temporarily remove only this owned index inside an isolated diagnostic
	// transaction, then roll back: compare the exact captured SQL/bindings under
	// the normal planner, without forcing an index or changing the public schema.
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `DROP INDEX organization.organization_invitation_recipient_page`); err != nil {
		t.Fatal(err)
	}
	var baseline invitationMinePlanNode
	for range 2 {
		var wire []byte
		if e := tx.QueryRow(ctx, "EXPLAIN(ANALYZE,BUFFERS,FORMAT JSON) "+sql, args...).Scan(&wire); e != nil {
			t.Fatal(e)
		}
		baseline = decode(wire)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if indexed.Rows != 201 || baseline.Rows != 201 || !indexed.usesIndex() || indexed.examined() > 201 || indexed.examined() >= baseline.examined() {
		t.Fatal("actual recipient access path did not preserve bounded result or reduce examined work", indexed.Rows, baseline.Rows, indexed.examined(), baseline.examined())
	}
	t.Logf("isolated recipient history20003, current identifier1, page200+1: indexed scan-tuples%.0f/root-buffers%d; same SQL without new index%.0f/%d; indexbytes%d heapbytes%d allindexesbytes%d", indexed.examined(), indexed.Hits+indexed.Reads, baseline.examined(), baseline.Hits+baseline.Reads, indexBytes, heapBytes, indexesBytes)
}
