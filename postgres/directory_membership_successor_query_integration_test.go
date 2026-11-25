//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
)

type directorySuccessorQuery struct {
	sql     string
	args    []any
	started time.Time
	elapsed time.Duration
	err     error
	oids    []uint32
	formats []int16
	values  [][]byte
}

type directorySuccessorQueryTrace struct {
	mu       sync.Mutex
	disabled bool
	writes   []*directorySuccessorQuery
	reads    []*directorySuccessorQuery
	err      error
}

type directorySuccessorTraceKey struct{}

// Work uses explicit-codec ExecParams below pgx.QueryTracer. As in go-sso's
// provider query fixture, observe its Parse/Bind frames without changing them.
type directorySuccessorWireConn struct {
	net.Conn
	trace   *directorySuccessorQueryTrace
	started bool
	pending []byte
	insert  *pgproto3.Parse
}

func (c *directorySuccessorWireConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.trace.mu.Lock()
	defer c.trace.mu.Unlock()
	if c.trace.disabled || c.trace.err != nil {
		return n, err
	}
	c.pending = append(c.pending, p[:n]...)
	for {
		if !c.started {
			if len(c.pending) < 4 {
				break
			}
			size := int(binary.BigEndian.Uint32(c.pending[:4]))
			if size < 8 || size > 16<<20 {
				c.trace.err = fmt.Errorf("invalid fixture startup frame")
				break
			}
			if len(c.pending) < size {
				break
			}
			c.pending, c.started = c.pending[size:], true
			continue
		}
		if len(c.pending) < 5 {
			break
		}
		size := int(binary.BigEndian.Uint32(c.pending[1:5])) + 1
		if size < 5 || size > 16<<20 {
			c.trace.err = fmt.Errorf("invalid fixture query frame")
			break
		}
		if len(c.pending) < size {
			break
		}
		frame := c.pending[:size]
		switch frame[0] {
		case 'P':
			var parse pgproto3.Parse
			if err := parse.Decode(frame[5:]); err != nil {
				c.trace.err = fmt.Errorf("invalid fixture Parse frame")
				break
			}
			c.insert = nil
			if strings.HasPrefix(strings.TrimSpace(parse.Query), "INSERT INTO organization.command_effects") && strings.Contains(parse.Query, "directory_org_after") {
				c.insert = &parse
			}
		case 'B':
			var bind pgproto3.Bind
			if err := bind.Decode(frame[5:]); err != nil {
				c.trace.err = fmt.Errorf("invalid fixture Bind frame")
				break
			}
			if c.insert == nil || bind.PreparedStatement != c.insert.Name {
				break
			}
			if len(c.insert.ParameterOIDs) != 12 || len(bind.Parameters) != 12 || len(bind.ParameterFormatCodes) != 12 {
				c.trace.err = fmt.Errorf("unexpected native successor binding shape")
				break
			}
			query := &directorySuccessorQuery{sql: c.insert.Query, oids: append([]uint32(nil), c.insert.ParameterOIDs...), formats: append([]int16(nil), bind.ParameterFormatCodes...), values: make([][]byte, 12), args: make([]any, 12)}
			for i, parameter := range bind.Parameters {
				query.values[i] = append([]byte(nil), parameter...)
				if query.formats[i] != 1 || i != 6 && query.oids[i] != 25 || i == 6 && query.oids[i] != 17 {
					c.trace.err = fmt.Errorf("unexpected native successor OID or format")
				}
				if i == 6 {
					query.args[i] = append([]byte(nil), parameter...)
				} else {
					query.args[i] = string(parameter)
				}
			}
			c.trace.writes = append(c.trace.writes, query)
			c.insert = nil
		}
		c.pending = c.pending[size:]
	}
	return n, err
}

func (trace *directorySuccessorQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	if trace.disabled || !strings.Contains(data.SQL, "organization.command_effects") || !strings.Contains(data.SQL, "directory_org_after") {
		return ctx
	}
	query := &directorySuccessorQuery{sql: data.SQL, args: append([]any(nil), data.Args...), started: time.Now()}
	if !strings.HasPrefix(strings.TrimSpace(data.SQL), "SELECT") {
		return ctx
	}
	trace.reads = append(trace.reads, query)
	return context.WithValue(ctx, directorySuccessorTraceKey{}, query)
}

func (trace *directorySuccessorQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	query, ok := ctx.Value(directorySuccessorTraceKey{}).(*directorySuccessorQuery)
	if !ok {
		return
	}
	trace.mu.Lock()
	defer trace.mu.Unlock()
	query.elapsed, query.err = time.Since(query.started), data.Err
}

func directorySuccessorPlan(t *testing.T, rows pgx.Rows, err error) string {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line + "\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return plan.String()
}

func directorySuccessorInsertSample(t *testing.T, ctx context.Context, pool *database.Pool, query directorySuccessorQuery) time.Duration {
	t.Helper()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	values := append([][]byte(nil), query.values...)
	values[0] = []byte(commandID(t))
	started := time.Now()
	result := tx.Conn().PgConn().ExecParams(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+query.sql, values, query.oids, query.formats, nil).Read()
	elapsed := time.Since(started)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	var plan strings.Builder
	for _, row := range result.Rows {
		if len(row) != 1 {
			t.Fatal("unexpected native insert plan result")
		}
		plan.Write(row[0])
		plan.WriteByte('\n')
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	t.Log("rollback-only insert plan:\n" + plan.String())
	return elapsed
}

// This opt-in check measures the new statements, not an application SLA. The
// isolated fixture retains 20,000 legacy effects with 90/10 tenant skew and a
// dense organization, using the existing primary key and normal planner.
func TestDirectoryMembershipSuccessorRepresentativeQueryCost(t *testing.T) {
	if os.Getenv("GOLIB_ORGANIZATION_DIRECTORY_SUCCESSOR_PERFORMANCE") != "1" {
		t.Skip("explicit representative query measurement only")
	}
	f := newOrgFixture(t,
		organizationpg.CredentialAuthorityMigrationSource{Version: 305},
		organizationpg.DirectoryMembershipMigrationSource{Version: 306},
		organizationpg.DirectoryMembershipSuccessorMigrationSource{Version: 307},
	)
	f.create(t, "org-test-basic")
	if _, err := f.pool.Raw().Exec(f.ctx, `INSERT INTO organization.command_effects(command_id,tenant_id,organization_id,user_id,actor_id,operation,fingerprint,before_version,after_version)
SELECT translate(rtrim(encode(int8send(n)||int8send(7301),'base64'),'='),'+/','-_'),
 CASE WHEN n<=18000 THEN 'org-test-basic' ELSE 'org-test-target' END,
 CASE WHEN n%20=0 THEN 'measurement-sparse-org' ELSE $1 END,
 CASE WHEN n%10=0 THEN 'outsider' ELSE 'member' END,'directory-service','measurement.history',decode(repeat('01',32),'hex'),n+100,n+101
FROM generate_series(1::bigint,20000::bigint) n`, string(metadataOrganization)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(f.ctx, `ANALYZE organization.command_effects`); err != nil {
		t.Fatal(err)
	}
	trace := new(directorySuccessorQueryTrace)
	pool, err := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 1, Configure: func(config *database.PoolConfig) error {
		config.ConnConfig.Database, config.ConnConfig.Tracer = f.database, trace
		config.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &directorySuccessorWireConn{Conn: conn, trace: trace}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	tracedFixture := *f
	tracedFixture.pool = pool
	store, err := organizationpg.NewRepository(pool, organizationpg.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	source := organizationpg.DirectoryMembershipSource{TenantID: "org-test-basic", OrganizationID: metadataOrganization, UserID: "member", ProviderID: "provider-one", ConnectionID: "connection-one", ResourceID: "resource-one"}
	original, err := store.ObserveCredentialAuthority(f.ctx, organization.CredentialAuthorityQuery{TenantID: source.TenantID, OrganizationID: source.OrganizationID})
	if err != nil {
		t.Fatal(err)
	}
	input := organizationpg.DirectoryMembershipInput{Source: source, ActorID: "directory-service", Organization: original,
		User:   identity.User{TenantID: source.TenantID, ID: source.UserID, Status: identity.StatusActive, Version: 1},
		Action: organizationpg.DirectoryMembershipGrant, MaximumMembers: 20, MaximumPerUser: 10}
	owner := &directoryMembershipWorkOwner{repository: store, recordSuccessor: true}
	coordinator, command, plan := directoryMembershipNativeWork(t, &tracedFixture, owner, input)
	started := time.Now()
	receipt, err := executeDirectoryTeamNative(f.ctx, coordinator, command, plan)
	operationElapsed := time.Since(started)
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted || receipt.Feature == nil {
		t.Fatal("original native User child did not commit", receipt.Outcome, err)
	}
	successor, err := store.RecoverDirectoryMembershipSuccessor(f.ctx, source, original, receipt)
	want := original
	want.Version++
	if err != nil || successor != want {
		t.Fatal("recovery did not return exact committed organization successor", err)
	}
	trace.mu.Lock()
	trace.disabled = true
	writes, reads := trace.writes, trace.reads
	traceError := trace.err
	trace.mu.Unlock()
	if traceError != nil {
		t.Fatal(traceError)
	}
	if len(writes) != 1 || len(reads) != 1 || reads[0].err != nil || reads[0].elapsed <= 0 {
		t.Fatal("successor adds one original effect write and one recovery read", len(writes), len(reads))
	}
	if len(writes[0].args) != 12 || len(reads[0].args) != 11 {
		t.Fatal("unexpected production binding shape", len(writes[0].args), len(reads[0].args))
	}
	for queryIndex, query := range []*directorySuccessorQuery{writes[0], reads[0]} {
		t.Log("captured production SQL:", query.sql)
		if len(query.oids) != 0 {
			t.Logf("actual Work wire OIDs=%v formats=%v; exact encoded values retained for replay", query.oids, query.formats)
		}
		for i, arg := range query.args {
			if i < 6 {
				if _, ok := arg.(string); !ok {
					t.Fatal("scope and command bindings must retain native strings", i+1)
				}
			}
			if i == 6 {
				if fingerprint, ok := arg.([]byte); !ok || len(fingerprint) != 32 {
					t.Fatal("fingerprint binding must retain native bytea", i+1)
				}
			}
			if i >= 7 {
				decimal, ok := arg.(string)
				value, err := strconv.ParseUint(decimal, 10, 64)
				if !ok || err != nil || strconv.FormatUint(value, 10) != decimal {
					t.Fatal("numeric version binding is not a canonical decimal string", i+1)
				}
			}
			if fingerprint, ok := arg.([]byte); ok {
				t.Logf("binding $%d: %T length=%d", i+1, arg, len(fingerprint))
			} else {
				t.Logf("binding $%d: %T=%v", i+1, arg, arg)
			}
		}
		connection, err := pool.Raw().Acquire(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		description, describeErr := connection.Conn().Prepare(f.ctx, "directory_successor_measurement_"+strconv.Itoa(queryIndex), query.sql)
		connection.Release()
		if describeErr != nil {
			t.Fatal(describeErr)
		}
		t.Logf("server-inferred parameter OIDs=%v (25=text, 17=bytea, 1700=numeric); Work write replay retains the actual wire OIDs above", description.ParamOIDs)
	}
	var version, columns, indexes string
	var count int64
	if err := pool.Raw().QueryRow(f.ctx, `SELECT version(),
 (SELECT count(*) FROM organization.command_effects),
 (SELECT string_agg(column_name||':'||udt_name,', ' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='organization' AND table_name='command_effects'),
 (SELECT string_agg(indexdef,E'\n' ORDER BY indexname) FROM pg_indexes WHERE schemaname='organization' AND tablename='command_effects')`).Scan(&version, &count, &columns, &indexes); err != nil {
		t.Fatal(err)
	}
	t.Logf("engine=%s effects=%d; 20000 synthetic legacy rows; 90/10 tenant skew; 95%% dense organization; single local client; no production equivalence claimed\ncolumns=%s\nindexes=%s", version, count, columns, indexes)
	t.Logf("native child elapsed=%s; recovery read=%s; writes/child=1 reads/recovery=1; insert has no separate native timing, measured below with exact wire bindings", operationElapsed, reads[0].elapsed)
	for _, scope := range []string{"hit", "missing-scope"} {
		args := append([]any(nil), reads[0].args...)
		if scope == "missing-scope" {
			args[1] = "org-test-target"
		}
		rows, err := pool.Raw().Query(f.ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) "+reads[0].sql, args...)
		readPlan := directorySuccessorPlan(t, rows, err)
		// EXPLAIN renders the bound fingerprint in its Filter text.
		readPlan = strings.ReplaceAll(readPlan, fmt.Sprintf("%x", args[6]), "[redacted]")
		effectSequentialScan := strings.Contains(readPlan, "Seq Scan on command_effects") || strings.Contains(readPlan, "Seq Scan on organization.command_effects")
		if effectSequentialScan || !strings.Contains(readPlan, "command_effects_pkey") || !strings.Contains(readPlan, "Index") {
			t.Fatal("recovery did not retain bounded existing-primary-key access", readPlan)
		}
		t.Log(scope + " plan:\n" + readPlan)
		var samples [3]time.Duration
		for i := range samples {
			started := time.Now()
			var after string
			err := pool.Raw().QueryRow(f.ctx, reads[0].sql, args...).Scan(&after)
			samples[i] = time.Since(started)
			if scope == "hit" && (err != nil || after != strconv.FormatUint(want.Version, 10)) || scope == "missing-scope" && !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("representative exact-key recovery result changed", scope, err)
			}
		}
		t.Logf("%s warm client samples=%v; statements/call=1", scope, samples)
	}
	var insertSamples [3]time.Duration
	for i := range insertSamples {
		insertSamples[i] = directorySuccessorInsertSample(t, f.ctx, pool, *writes[0])
	}
	var afterCount int64
	if err := pool.Raw().QueryRow(f.ctx, `SELECT count(*) FROM organization.command_effects`).Scan(&afterCount); err != nil || afterCount != count {
		t.Fatal("rollback-only insert measurement retained effects", afterCount, count, err)
	}
	t.Logf("rollback-only insert EXPLAIN client samples=%v; distinct command IDs; all effects rolled back; server execution and buffers appear in plans", insertSamples)
}
