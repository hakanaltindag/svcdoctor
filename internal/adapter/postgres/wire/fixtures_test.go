package wire

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// A scripted peer, not a PostgreSQL server.
//
// It replays bytes a test chose and records what arrived, which is all that is
// needed to drive svcdoctor's state machine through outcomes a real server would
// take a container and a configuration file to produce. Nothing here parses SQL,
// authenticates anybody or keeps state between connections.
//
// A loopback listener rather than net.Pipe, for the reason internal/probe/tls's
// fixtures already document: net.Pipe is unbuffered and fully synchronous, so
// both sides of a TLS handshake block writing while waiting to write, and the
// handshake deadlocks. These tests therefore skip where loopback sockets are
// forbidden.

// peer is one scripted connection.
type peer struct {
	addr net.Addr

	mu       sync.Mutex
	received []byte
	accepted int
}

// scriptedPeer starts a listener that hands each accepted connection to serve.
//
// serve is given the connection and the peer, and owns closing it.
func scriptedPeer(t *testing.T, serve func(net.Conn, *peer)) *peer {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	p := &peer{addr: ln.Addr()}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			p.mu.Lock()
			p.accepted++
			p.mu.Unlock()
			go serve(conn, p)
		}
	}()
	return p
}

// dial connects to the peer and closes the connection when the test ends.
func (p *peer) dial(t *testing.T) net.Conn {
	t.Helper()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", p.addr.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// record appends bytes the peer received, so a test can assert on exactly what
// svcdoctor put on the wire.
func (p *peer) record(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.received = append(p.received, b...)
}

// bytesReceived returns a copy of everything the peer has read so far.
func (p *peer) bytesReceived() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, len(p.received))
	copy(out, p.received)
	return out
}

// waitForBytes blocks until the peer has recorded at least n bytes.
//
// The client returns as soon as its write completes, which can be before the
// peer's goroutine has read it. Polling for the byte count rather than sleeping
// keeps the test deterministic instead of merely usually right.
func (p *peer) waitForBytes(t *testing.T, n int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(p.bytesReceived()) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("peer received %d bytes, want at least %d", len(p.bytesReceived()), n)
}

// readN reads exactly n bytes into the peer's record.
func readN(conn net.Conn, p *peer, n int) bool {
	buf := make([]byte, n)
	total := 0
	for total < n {
		read, err := conn.Read(buf[total:])
		total += read
		if err != nil {
			return false
		}
	}
	p.record(buf)
	return true
}

// respondToSSLRequest consumes the eight-byte SSLRequest and writes reply.
func respondToSSLRequest(conn net.Conn, p *peer, reply []byte) bool {
	if !readN(conn, p, 8) {
		return false
	}
	_, err := conn.Write(reply)
	return err == nil
}

// frame builds a server message: type byte, length including itself, body.
func frame(kind byte, body []byte) []byte {
	out := []byte{kind}
	// Bounded before the conversion: a fixture body is never near the limit,
	// and an unchecked int->uint32 is the shape of a real framing bug.
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

// authFrame builds an Authentication message for a code, with optional payload.
func authFrame(code uint32, payload []byte) []byte {
	body := binary.BigEndian.AppendUint32(nil, code)
	return frame(MsgAuthentication, append(body, payload...))
}

// errorFields builds an ErrorResponse body from (code, value) pairs.
func errorFields(pairs ...string) []byte {
	var body []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		body = append(body, pairs[i][0])
		body = append(body, pairs[i+1]...)
		body = append(body, 0)
	}
	return append(body, 0)
}

// ctx returns a context bounded well above any fixture's needs, so a hang fails
// the test rather than the suite.
func testContext(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}
