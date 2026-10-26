//go:build integration

package consumer_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
)

// These unchanged private fixture helpers are retained on each side of the
// test-module boundary; they add no production API, store or authority.
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
