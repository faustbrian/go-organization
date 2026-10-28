//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	database "github.com/faustbrian/go-postgres"
)

// Work uses pgconn directly, outside pgx's QueryTracer. Observe the actual
// bounded frontend Parse and successful backend INSERT acknowledgement, then
// cancel or lose this same connection's next server COMMIT acknowledgement.
// Earlier mapping/reservation transactions cannot arm either fault.
type selectionWireFault struct {
	cancel         context.CancelFunc
	observed, lost atomic.Bool
}

type selectionWireConn struct {
	net.Conn
	fault           *selectionWireFault
	front, pending  []byte
	startup         bool
	selected, armed atomic.Bool
}

func (c *selectionWireConn) Write(p []byte) (int, error) {
	if len(c.front)+len(p) > 1<<20 {
		return 0, errors.New("bounded fixture frontend message exceeded")
	}
	c.front = append(c.front, p...)
	for {
		if !c.startup {
			if len(c.front) < 4 {
				break
			}
			length := binary.BigEndian.Uint32(c.front[:4])
			if length < 8 || length > 1<<20 {
				return 0, errors.New("invalid fixture startup frame")
			}
			size := int(length)
			if len(c.front) < size {
				break
			}
			c.front = c.front[size:]
			c.startup = true
			continue
		}
		if len(c.front) < 5 {
			break
		}
		length := binary.BigEndian.Uint32(c.front[1:5])
		if length < 4 || length > 1<<20 {
			return 0, errors.New("invalid fixture frontend frame")
		}
		size := int(length)
		if len(c.front) < size+1 {
			break
		}
		frame := c.front[:size+1]
		var query []byte
		if frame[0] == 'P' {
			body := frame[5:]
			if end := bytes.IndexByte(body, 0); end >= 0 {
				body = body[end+1:]
				if end = bytes.IndexByte(body, 0); end >= 0 {
					query = body[:end]
				}
			}
		} else if frame[0] == 'Q' {
			query = bytes.TrimSuffix(frame[5:], []byte{0})
		}
		if bytes.Contains(query, []byte(".organization_selections")) && strings.HasPrefix(strings.TrimSpace(string(query)), "INSERT INTO") {
			c.selected.Store(true)
		}
		c.front = c.front[size+1:]
	}
	return c.Conn.Write(p)
}

func (c *selectionWireConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
			return 0, err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, errors.New("invalid fixture backend frame")
		}
		frame := make([]byte, int(size)+1)
		copy(frame, header[:])
		if _, err := io.ReadFull(c.Conn, frame[5:]); err != nil {
			return 0, err
		}
		if frame[0] == 'C' && string(frame[5:]) == "INSERT 0 1\x00" && c.selected.Swap(false) {
			if c.fault.observed.CompareAndSwap(false, true) && c.fault.cancel != nil {
				c.fault.cancel()
			}
			c.armed.Store(true)
		}
		if frame[0] == 'C' && string(frame[5:]) == "COMMIT\x00" && c.armed.Load() && c.fault.cancel == nil && c.fault.lost.CompareAndSwap(false, true) {
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (f *activeOrganizationFixture) selectionFaultPool(t *testing.T, fault *selectionWireFault) *database.Pool {
	t.Helper()
	pool, err := database.Connect(f.ctx, database.Config{DSN: os.Getenv("GOLIB_ORGANIZATION_TEST_POSTGRES_DSN"), MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.pool.Raw().Config().ConnConfig.Database
		if c.ConnConfig.TLSConfig != nil {
			return errors.New("wire fixture requires explicit plaintext loopback")
		}
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
			if err != nil {
				return nil, err
			}
			return &selectionWireConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func (f *activeOrganizationFixture) exerciseSelectionCancellation(t *testing.T, target organization.ID) {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	fault := &selectionWireFault{cancel: cancel}
	pool := f.selectionFaultPool(t, fault)
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := pool.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	before := f.record(t, f.member)
	service := f.native(t, pool)
	prepared, err := service.PrepareActiveOrganization(f.ctx, organization.ActiveOrganizationRequest{Authentication: f.member, CommandID: commandID(t), SessionID: before.SessionID, OrganizationID: target, CorrelationID: "cancel-after-session-cas"}, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	original, err := prepared.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Execute(ctx, prepared)
	if err == nil || !fault.observed.Load() || result.Receipt.Binding != original.Binding || result.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("precommit cancellation did not reach actual selection write/rollback", err)
	}
	if after := f.record(t, f.member); !reflect.DeepEqual(before, after) {
		t.Fatal("precommit cancellation retained session/family mutation")
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(original.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var evidence, audits, outboxes int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.organization_selections WHERE command_id=$1),(SELECT count(*) FROM audit.records a JOIN audit.identity_command_bindings b ON b.event_id=a.record_id WHERE b.command_id=$1 AND a.outcome=1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&evidence, &audits, &outboxes); err != nil || evidence != 0 || audits != 0 || outboxes != 0 {
		t.Fatal("canceled actual Work retained successful effects", err)
	}
}

func (f *activeOrganizationFixture) exerciseSelectionCommitLoss(t *testing.T, first, second organization.ID) {
	t.Helper()
	fault := new(selectionWireFault)
	pool := f.selectionFaultPool(t, fault)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := pool.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	current := f.record(t, f.member)
	request := organization.ActiveOrganizationOperationRequest{Authentication: f.member, IdempotencyKey: selectionKey(t, "target-commit-loss-selection"), SessionID: current.SessionID, OrganizationID: second, CorrelationID: "target-commit-loss"}
	unknown, err := f.operations(t, pool).SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err == nil || !fault.observed.Load() || !fault.lost.Load() || unknown.Receipt.Outcome != identity.CommitOutcomeUnknown || unknown.Receipt.Binding.CommandID == "" {
		t.Fatal("target server COMMIT acknowledgement loss not preserved", err)
	}
	fresh := f.operations(t, f.pool)
	committed, err := fresh.SetActiveOrganization(f.ctx, request, "127.0.0.1")
	if err != nil || committed.Receipt.Validate() != nil || committed.Receipt.Outcome != identity.CommitOutcomeCommitted || committed.Receipt.Binding != unknown.Receipt.Binding || committed.Receipt.Feature == nil || committed.Receipt.Feature.BeforeVersion != current.Version || committed.Receipt.Feature.AfterVersion != current.Version+1 {
		t.Fatal("fresh original-key recovery lost actual target history", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(string(committed.Receipt.Binding.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var evidence, audits, outboxes int
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM session_store.organization_selections WHERE command_id=$1),(SELECT count(*) FROM audit.records a JOIN audit.identity_command_bindings b ON b.event_id=a.record_id WHERE a.action='identity.organization.active-set' AND b.command_id=$1 AND a.outcome=1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&evidence, &audits, &outboxes); err != nil || evidence != 1 || audits != 1 || outboxes != 1 {
		t.Fatal("target commit/recovery did not retain one required effect set", err)
	}
	later := request
	later.IdempotencyKey = selectionKey(t, "post-lost-commit-switch")
	later.OrganizationID = first
	later.CorrelationID = "post-lost-commit-switch"
	if out, err := fresh.SetActiveOrganization(f.ctx, later, "127.0.0.1"); err != nil || out.Receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("later selection after committed loss", err)
	}
	if history, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, request, "127.0.0.1"); err != nil || !reflect.DeepEqual(history, committed) {
		t.Fatal("original history changed after later selection", err)
	}
	if view, err := fresh.GetActiveOrganization(f.ctx, organization.ActiveOrganizationReadRequest{Authentication: f.member, CorrelationID: "post-history-current-read"}); err != nil || view.Organization.ID != first {
		t.Fatal("historical recovery replayed old selection", err)
	}
}

func (f *activeOrganizationFixture) exerciseSelectionIdenticalKeyContention(t *testing.T, target organization.ID) {
	t.Helper()
	current := f.record(t, f.member)
	request := organization.ActiveOrganizationOperationRequest{Authentication: f.member, IdempotencyKey: selectionKey(t, "concurrent-identical-selection"), SessionID: current.SessionID, OrganizationID: target, CorrelationID: "concurrent-identical-selection"}
	type result struct {
		out organization.StoreResult
		err error
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 2 {
		service := f.operations(t, f.pool)
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			out, err := service.SetActiveOrganization(f.ctx, request, "127.0.0.1")
			results <- result{out, err}
		}()
	}
	close(start)
	workers.Wait()
	a, b := <-results, <-results
	// A still-running winner may yield the existing coordinator's InProgress.
	// Only a matching-key retry may reconcile it; no candidate may execute twice.
	if a.err != nil {
		a.out, a.err = f.operations(t, f.pool).SetActiveOrganization(f.ctx, request, "127.0.0.1")
	}
	if b.err != nil {
		b.out, b.err = f.operations(t, f.pool).SetActiveOrganization(f.ctx, request, "127.0.0.1")
	}
	if a.err != nil || b.err != nil || a.out.Receipt.Outcome != identity.CommitOutcomeCommitted || !reflect.DeepEqual(a.out, b.out) {
		t.Fatal("identical keyed contenders did not recover one original", a.err, b.err)
	}
	if got := f.record(t, f.member); got.Version != current.Version+1 {
		t.Fatal("identical keyed contenders changed selection twice")
	}
	changed := request
	changed.OrganizationID = ""
	if out, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, changed, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed target reused original key", err)
	}
	changed = request
	f.spareMember = f.signinMember()
	changed.SessionID = f.record(t, f.spareMember).SessionID
	if out, err := f.operations(t, f.pool).SetActiveOrganization(f.ctx, changed, "127.0.0.1"); err == nil || out.Receipt.Outcome == identity.CommitOutcomeCommitted {
		t.Fatal("changed exact session reused original key", err)
	}
}
