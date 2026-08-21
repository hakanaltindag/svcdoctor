package tls

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// These tests are the proof that the connection-ownership invariant of ADR 0021
// holds across the layer boundary. Each one fails if the probe starts dialing,
// closing a connection it handed on, or leaking one it kept.

// TestHandshakeUsesTheConnectionItWasGiven is the invariant that makes every
// other measurement meaningful. The TLS connection must sit on the same socket
// the caller established — if the probe could redial, every fact measured at L1
// and L2 would describe a connection the handshake never used.
func TestHandshakeUsesTheConnectionItWasGiven(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	localBefore := raw.LocalAddr().String()
	remoteBefore := raw.RemoteAddr().String()

	r := handshake(t, raw, f.params(ca, "server.test"))

	wrapped, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn reported nothing to take after a verified handshake")
	}
	defer func() { _ = wrapped.Close() }()

	if got := wrapped.LocalAddr().String(); got != localBefore {
		t.Errorf("local address changed from %s to %s: the probe opened a different socket",
			localBefore, got)
	}
	if got := wrapped.RemoteAddr().String(); got != remoteBefore {
		t.Errorf("remote address changed from %s to %s", remoteBefore, got)
	}
}

// TestSuccessfulHandshakeIsNotClosedByTheProbe is the forbidden lifecycle stated
// as a test: handshake, measure, close would force the next stage to reconnect.
func TestSuccessfulHandshakeIsNotClosedByTheProbe(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	r := handshake(t, raw, f.params(ca, "server.test"))

	if raw.closes != 0 {
		t.Fatalf("the probe closed the connection it handshook over (%d closes)", raw.closes)
	}
	if !r.Connected() {
		t.Error("Connected() = false after a successful handshake")
	}
}

// TestTransferredTLSConnectionIsUsable is the point of the exercise: the
// connection handed to the next stage has to carry protocol bytes.
func TestTransferredTLSConnectionIsUsable(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))

	conn, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn reported nothing to take")
	}
	defer func() { _ = conn.Close() }()

	const message = "protocol handshake would go here"
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("writing over the transferred connection: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := net.Conn(conn).Read(buf); err != nil {
		t.Fatalf("reading from the transferred connection: %v", err)
	}
	if got := string(buf); got != message {
		t.Errorf("read %q, want %q", got, message)
	}
}

func TestTakeConnIsSingleUse(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))

	if _, ok := r.TakeConn(); !ok {
		t.Fatal("the first TakeConn failed")
	}
	if conn, ok := r.TakeConn(); ok || conn != nil {
		t.Error("the second TakeConn handed out the same connection again")
	}
}

func TestCloseBeforeTransferReleasesTheConnection(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	r, err := Handshake(context.Background(), raw, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if raw.closes != 1 {
		t.Errorf("underlying closes = %d, want 1: closing the wrapper must close the socket", raw.closes)
	}
	if r.Connected() {
		t.Error("Connected() is still true after Close")
	}
	if _, ok := r.TakeConn(); ok {
		t.Error("a closed connection was handed out")
	}
}

// TestCloseAfterTransferDoesNothing is what makes "defer r.Close()" correct in
// every path, including the one where the connection was handed on.
func TestCloseAfterTransferDoesNothing(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	r, err := Handshake(context.Background(), raw, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	conn, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}

	if err := r.Close(); err != nil {
		t.Errorf("Close after transfer returned %v, want nil", err)
	}
	if raw.closes != 0 {
		t.Fatalf("Close closed a connection the caller owns (%d closes)", raw.closes)
	}

	if err := conn.Close(); err != nil {
		t.Errorf("closing the taken connection: %v", err)
	}
	if raw.closes != 1 {
		t.Errorf("underlying closes = %d, want 1", raw.closes)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	r, err := Handshake(context.Background(), raw, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := r.Close(); err != nil {
			t.Errorf("Close %d returned %v, want nil", i+1, err)
		}
	}
	if raw.closes != 1 {
		t.Errorf("underlying closes = %d, want exactly 1", raw.closes)
	}
}

// TestFailedHandshakeClosesTheConnection is the leak guard that matters most in
// practice: a topology sweep over unreachable endpoints must not accumulate
// sockets.
func TestFailedHandshakeClosesTheConnection(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	params := f.params(ca, "server.test")
	params.RootCAs = x509.NewCertPool() // trusts nothing, so verification fails

	r, err := Handshake(context.Background(), raw, params)
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	if raw.closes != 1 {
		t.Errorf("closes = %d, want 1: a failed handshake must release the connection", raw.closes)
	}
	if r.Connected() {
		t.Error("a failed handshake reports a connection to transfer")
	}
	if conn, ok := r.TakeConn(); ok || conn != nil {
		t.Error("a failed handshake handed out a connection")
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close on a failed attempt returned %v, want nil", err)
	}
	if raw.closes != 1 {
		t.Errorf("closes = %d after Close, want still 1", raw.closes)
	}
	if r.Evidence().State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", r.Evidence().State())
	}
}

// TestEvidenceConstructionFailureClosesTheConnection covers the path that would
// otherwise leak: a completed handshake followed by evidence that cannot be
// built. Input validation should make it unreachable, which is why the
// observation is constructed directly.
func TestEvidenceConstructionFailureClosesTheConnection(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	params := f.params(ca, "server.test")

	// A zero StartedAt is rejected by domain.NewEvidence.
	r, err := newResult(observation{
		params: params,
		conn:   cryptotls.Client(raw, params.config()),
	})

	if err == nil {
		t.Fatal("expected evidence construction to fail")
	}
	if r != nil {
		t.Error("a result was returned alongside an error")
	}
	if raw.closes != 1 {
		t.Errorf("closes = %d, want 1: the connection leaked when evidence failed", raw.closes)
	}
}

// TestEvidenceOutlivesTheConnection separates the two lifetimes: the handshake
// still succeeded after the socket is gone, because it did.
func TestEvidenceOutlivesTheConnection(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r, err := Handshake(context.Background(), f.conn, f.params(ca, "server.test"))
	if err != nil {
		t.Fatalf("Handshake: %v", err)
	}

	before := r.Evidence()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := r.Evidence()

	if after.State() != domain.StatePass {
		t.Errorf("state = %s after closing, want PASS", after.State())
	}
	if before.ID() != after.ID() {
		t.Error("the evidence changed when the connection was closed")
	}
	if r.Connected() {
		t.Error("Connected() is still true after Close")
	}
}

// TestGraphHoldsEvidenceWhileTheConnectionStaysLive is the boundary in one test:
// the graph takes the fact, the Result keeps the resource, neither knows about
// the other.
func TestGraphHoldsEvidenceWhileTheConnectionStaysLive(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	raw := &countingConn{Conn: f.conn}
	r := handshake(t, raw, f.params(ca, "server.test"))

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(r.Evidence()); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if graph.Len() != 1 {
		t.Fatalf("graph holds %d nodes, want 1", graph.Len())
	}
	if raw.closes != 0 {
		t.Error("recording the evidence closed the connection")
	}
	conn, ok := r.TakeConn()
	if !ok {
		t.Fatal("the connection could not be taken after its evidence was recorded")
	}
	// The caller owns it now, so the caller closes it.
	if err := conn.Close(); err != nil {
		t.Errorf("closing the taken connection: %v", err)
	}
}
