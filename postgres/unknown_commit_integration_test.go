//go:build integration

package postgres_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	organization "github.com/faustbrian/go-organization"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	database "github.com/faustbrian/go-postgres"
)

// commitResponseLoss withholds only the second successful COMMIT response after
// arming: reservation commits first, then the domain/audit/outbox transaction.
// Seeing PostgreSQL's CommandComplete proves server commit before client loss.
// No background goroutine or substitute coordinator participates in the fault.
type commitResponseLoss struct {
	armed atomic.Bool
	count atomic.Int32
	lost  atomic.Bool
}

type lossyCommitConn struct {
	net.Conn
	fault   *commitResponseLoss
	pending []byte
}

func (c *lossyCommitConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) == 0 {
		var header [5]byte
		if _, e := io.ReadFull(c.Conn, header[:]); e != nil {
			return 0, e
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16<<20 {
			return 0, errors.New("invalid fixture PostgreSQL message size")
		}
		frame := make([]byte, int(size)+1)
		copy(frame, header[:])
		if _, e := io.ReadFull(c.Conn, frame[5:]); e != nil {
			return 0, e
		}
		if header[0] == 'C' && string(frame[5:]) == "COMMIT\x00" && c.fault.armed.Load() && c.fault.count.Add(1) == 2 {
			c.fault.lost.Store(true)
			_ = c.Conn.Close()
			return 0, io.EOF
		}
		c.pending = frame
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

func (f *orgFixture) lostCommitService(t *testing.T) (*organizationpg.Service, *commitResponseLoss) {
	t.Helper()
	fault := new(commitResponseLoss)
	pool, e := database.Connect(f.ctx, database.Config{DSN: f.dsn, MaxConns: 2, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = f.database
		c.ConnConfig.DialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
			conn, e := (&net.Dialer{}).DialContext(ctx, network, address)
			if e != nil {
				return nil, e
			}
			return &lossyCommitConn{Conn: conn, fault: fault}, nil
		}
		return nil
	}})
	if e != nil {
		t.Fatal("fault connection unavailable", e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := pool.Close(ctx); e != nil {
			t.Error("fault pool cleanup failed")
		}
	})
	copy := *f
	copy.pool = pool
	copy.compose(t)
	return copy.service, fault
}

func testUnknownCommit(t *testing.T, f *orgFixture) {
	t.Helper()
	service, fault := f.lostCommitService(t)
	tenant := "org-test-unknown"
	p, e := service.PrepareCreate(f.ctx, organization.CreateRequest{Authentication: f.auth(tenant, "owner"), CommandID: commandID(t), ID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", Slug: "unknown", Name: "Unknown commit", CorrelationID: "unknown"}, "127.0.0.1")
	if e != nil {
		t.Fatal(e)
	}
	recovery, e := p.Recovery()
	if e != nil {
		t.Fatal(e)
	}
	fault.armed.Store(true)
	r, e := service.Execute(f.ctx, p)
	if !fault.lost.Load() || e == nil || r.Receipt.Outcome != identity.CommitOutcomeUnknown || r.Receipt.Binding != recovery.Binding {
		t.Fatal("lost committed response did not preserve unknown outcome", r.Receipt.Outcome, e)
	}
	// Recovery uses another service and direct primary connections, never the
	// prepared bearer or a reconstruction/re-execution of the original command.
	r, e = f.service.Recover(f.ctx, f.auth(tenant, "owner"), recovery)
	if e != nil || r.Receipt.Outcome != identity.CommitOutcomeCommitted || r.Receipt.Binding != recovery.Binding {
		t.Fatal("authoritative recovery did not resolve committed transaction", r.Receipt.Outcome, e)
	}
	var effects, members int
	if e = f.pool.Raw().QueryRow(f.ctx, `SELECT (SELECT count(*) FROM organization.command_effects WHERE tenant_id=$1),(SELECT count(*) FROM organization.memberships WHERE tenant_id=$1)`, tenant).Scan(&effects, &members); e != nil || effects != 1 || members != 1 {
		t.Fatal("recovery duplicated organization effects", e)
	}
	view, e := f.service.Get(f.ctx, organization.ReadRequest{Authentication: f.auth(tenant, "owner"), OrganizationID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", CorrelationID: "unknown-read"})
	if e != nil || view.Organization.Version != 1 {
		t.Fatal("committed organization unavailable after recovery", e)
	}
}
