package tcp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"

	"github.com/hakanaltindag/svcdoctor/internal/probe"
)

// These two tests use a loopback listener this test creates and controls. That
// is not an uncontrolled network dependency: nothing outside the process is
// contacted, and no name is resolved. They exist because the fake dialer cannot
// prove the two things that only the real network stack can — that SystemDialer
// actually connects, and that a genuinely refused connection is classified the
// way the error-number mapping claims.
//
// If the environment forbids even a loopback listener the tests skip rather than
// fail, because that is a property of the sandbox and not of svcdoctor.

func loopbackListener(t *testing.T) net.Listener {
	t.Helper()

	// ListenConfig rather than net.Listen, so that even the test listener is
	// context-aware. The noctx linter enforces this repository-wide.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	return ln
}

func TestSystemDialerConnectsToALoopbackListener(t *testing.T) {
	ln := loopbackListener(t)
	defer func() { _ = ln.Close() }()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", ln.Addr(), err)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, err := Connect(ctx, SystemDialer{}, "loopback.test:0", addr, probe.SweepScope{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = r.Close() }()

	if got := r.Evidence().State(); got != domain.StatePass {
		t.Fatalf("state = %s, want PASS", got)
	}
	if !r.Connected() {
		t.Fatal("the real dialer produced no transferable connection")
	}

	// The transferred connection is the one the listener accepted.
	conn, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	select {
	case server := <-accepted:
		defer func() { _ = server.Close() }()
		if conn.LocalAddr().String() != server.RemoteAddr().String() {
			t.Errorf("transferred connection %s is not the accepted one %s",
				conn.LocalAddr(), server.RemoteAddr())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the listener never accepted the connection")
	}
}

// TestSystemDialerClassifiesARealRefusal validates the error-number mapping
// against an actual refused connection, which is the one classification a fake
// cannot honestly stand in for: it asserts that this platform's refusal really
// does reach errors.Is(err, syscall.ECONNREFUSED).
func TestSystemDialerClassifiesARealRefusal(t *testing.T) {
	ln := loopbackListener(t)

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", ln.Addr(), err)
	}
	// Closing the listener frees the port; nothing is listening on it now.
	if err := ln.Close(); err != nil {
		t.Fatalf("closing the listener: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	r, err := Connect(ctx, SystemDialer{}, "loopback.test:0", addr, probe.SweepScope{})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = r.Close() }()

	e := r.Evidence()
	if e.State() != domain.StateFail {
		t.Fatalf("state = %s, want FAIL", e.State())
	}
	if e.FailureClass() != domain.FailureTCPConnectionRefused {
		t.Errorf("failure class = %s, want TCP_CONNECTION_REFUSED; "+
			"this platform reports a refused connection in a form the mapping does not recognize",
			e.FailureClass())
	}
	if r.Connected() {
		t.Error("a refused attempt produced a connection")
	}
}
