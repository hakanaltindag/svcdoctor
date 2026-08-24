package wire

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Conn drives one RESP2 exchange at a time over a connection somebody else
// established.
//
// It never dials, never performs a TLS handshake and never closes what it was
// given: ownership of the socket belongs to the caller, exactly as it does in
// the PostgreSQL and Kafka wire packages (ADR 0021).
type Conn struct {
	conn net.Conn
	rd   *reader
}

// NewConn wraps a live connection.
func NewConn(conn net.Conn) *Conn {
	return &Conn{conn: conn, rd: newReader(conn)}
}

// The three commands svcdoctor may send, pre-encoded where they are constant.
//
// HELLO and PING are constants rather than built at each call, which is not a
// micro-optimization: a constant cannot acquire an argument by accident. The
// zero-argument HELLO frame in particular is the whole of ADR 0064's structural
// defence, and a byte-for-byte test compares against this exact value.
var (
	// helloFrame is `HELLO` with no arguments. No protocol version, no AUTH, no
	// SETNAME. See doc.go and ADR 0064 section 3.
	helloFrame = []byte("*1\r\n$5\r\nHELLO\r\n")

	// pingFrame is `PING` with no arguments. A message argument would be echoed
	// back and would add a peer-controlled value to the reply for no evidence.
	pingFrame = []byte("*1\r\n$4\r\nPING\r\n")
)

// encodeCommand builds a RESP2 array of bulk strings.
//
// It is unexported and has exactly one production caller, encodeAuth. HELLO and
// PING do not use it because they have nothing to encode.
func encodeCommand(parts ...string) ([]byte, error) {
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: a command needs at least a name", ErrInvalidInput)
	}
	out := []byte(fmt.Sprintf("*%d\r\n", len(parts)))
	for _, p := range parts {
		out = append(out, fmt.Sprintf("$%d\r\n", len(p))...)
		out = append(out, p...)
		out = append(out, '\r', '\n')
	}
	return out, nil
}

// exchange writes one command and reads exactly one reply.
//
// # One command, one reply, no pipelining
//
// Nothing in the frozen journey benefits from pipelining, and a pipelined
// exchange would make "which reply belonged to which command" a thing the
// adapter has to reason about. Each step here is a complete round trip.
//
// # The budget is per reply
//
// begin resets it, so three small replies on one connection do not accumulate
// towards a refusal.
func (c *Conn) exchange(ctx context.Context, timeout time.Duration, frame []byte) (reply, error) {
	ctx, cancel := withStepTimeout(ctx, timeout)
	defer cancel()

	release := bindDeadline(ctx, c.conn)
	defer release()

	if _, err := c.conn.Write(frame); err != nil {
		return reply{}, err
	}

	c.rd.begin()
	return c.rd.readReply()
}

// withStepTimeout narrows a context by the caller's per-step budget.
//
// A zero timeout means the caller's own context is the only bound, which is the
// same contract every other adapter's step timeout has.
func withStepTimeout(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// bindDeadline mirrors the PostgreSQL wire package's helper, and for the same
// reason: a context that ends while a read is parked must unblock the read, and
// the call must leave no deadline behind on a connection it hands on.
//
// The watcher goroutine is awaited before the deadline is cleared, so the
// documented invariant — on return, this call has left no deadline behind — is
// true whatever order the runtime chose.
func bindDeadline(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	return func() {
		close(done)
		<-stopped
		_ = conn.SetDeadline(time.Time{})
	}
}
