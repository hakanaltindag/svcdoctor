package tcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// These tests are the proof that the connection-ownership invariant is real
// rather than documented. Each one fails if the probe reverts to
// "dial, measure, close".

// TestSuccessfulConnectionIsNotClosedByTheProbe is the invariant itself. If this
// fails, the next stage has to dial again, and every measured fact starts
// describing a connection the protocol exchange never used.
func TestSuccessfulConnectionIsNotClosedByTheProbe(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

	if conn.closes != 0 {
		t.Fatalf("the probe closed the connection it established (%d closes)", conn.closes)
	}
	if !r.Connected() {
		t.Error("Connected() = false after a successful attempt")
	}
}

// TestTakeConnTransfersOwnership proves the transfer is real: the caller gets a
// usable connection, and the Result stops claiming it.
func TestTakeConnTransfersOwnership(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

	taken, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn reported nothing to take after a successful attempt")
	}
	if taken != conn {
		t.Error("TakeConn returned a different connection than the one established")
	}
	if r.Connected() {
		t.Error("Connected() is still true after the connection was taken")
	}
	if conn.closes != 0 {
		t.Errorf("the connection was closed during the transfer (%d closes)", conn.closes)
	}
}

// TestTransferredConnectionIsUsable is the point of the whole exercise. A
// transferred connection has to carry bytes, or "ownership transfer" is
// bookkeeping over a dead socket.
func TestTransferredConnectionIsUsable(t *testing.T) {
	client, server := pipePair(t)
	r := connect(t, &fakeDialer{conn: client}, addrPort(t, "10.0.0.1:9092"))

	taken, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn reported nothing to take")
	}

	const message = "protocol handshake would go here"
	go func() {
		_ = taken.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = taken.Write([]byte(message))
	}()

	buf := make([]byte, len(message))
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("reading from the transferred connection: %v", err)
	}
	if got := string(buf); got != message {
		t.Errorf("read %q, want %q", got, message)
	}
}

// TestTakeConnIsSingleUse removes the ambiguity two owners would create.
func TestTakeConnIsSingleUse(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

	if _, ok := r.TakeConn(); !ok {
		t.Fatal("the first TakeConn failed")
	}
	if taken, ok := r.TakeConn(); ok || taken != nil {
		t.Error("the second TakeConn handed out the same connection again")
	}
}

// TestCloseBeforeTransferReleasesTheConnection covers the abandoned-success
// path: a caller that decides it does not want the connection must be able to
// release it.
func TestCloseBeforeTransferReleasesTheConnection(t *testing.T) {
	conn := newFakeConn(t)
	r, err := Connect(context.Background(), &fakeDialer{conn: conn}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if conn.closes != 1 {
		t.Errorf("closes = %d, want 1", conn.closes)
	}
	if r.Connected() {
		t.Error("Connected() is still true after Close")
	}
	if _, ok := r.TakeConn(); ok {
		t.Error("a closed connection was handed out")
	}
}

// TestCloseAfterTransferDoesNothing is what makes "defer r.Close()" correct in
// every path. Closing here would break a connection the caller now owns and is
// using.
func TestCloseAfterTransferDoesNothing(t *testing.T) {
	conn := newFakeConn(t)
	r, err := Connect(context.Background(), &fakeDialer{conn: conn}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	taken, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}

	if err := r.Close(); err != nil {
		t.Errorf("Close after transfer returned %v, want nil", err)
	}
	if conn.closes != 0 {
		t.Fatalf("Close closed a connection the caller owns (%d closes)", conn.closes)
	}

	// The caller closes it, exactly once, because it owns it.
	if err := taken.Close(); err != nil {
		t.Errorf("closing the taken connection: %v", err)
	}
	if conn.closes != 1 {
		t.Errorf("closes = %d, want 1", conn.closes)
	}
}

// TestCloseIsIdempotent lets a caller defer Close and also close explicitly
// without closing the underlying connection twice.
func TestCloseIsIdempotent(t *testing.T) {
	conn := newFakeConn(t)
	r, err := Connect(context.Background(), &fakeDialer{conn: conn}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := r.Close(); err != nil {
			t.Errorf("Close %d returned %v, want nil", i+1, err)
		}
	}
	if conn.closes != 1 {
		t.Errorf("closes = %d, want exactly 1", conn.closes)
	}
}

// TestFailedAttemptOwnsNothing proves a failure leaks no resource and that the
// ownership API is safe to call unconditionally.
func TestFailedAttemptOwnsNothing(t *testing.T) {
	r, err := Connect(context.Background(),
		&fakeDialer{err: errors.New("refused")}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if r.Connected() {
		t.Error("a failed attempt claims a connection")
	}
	if taken, ok := r.TakeConn(); ok || taken != nil {
		t.Error("a failed attempt handed out a connection")
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close on a failed attempt returned %v, want nil", err)
	}
	if got := r.Evidence().State(); got != domain.StateFail {
		t.Errorf("state = %s, want FAIL", got)
	}
}

// TestEvidenceOutlivesTheConnection separates the two lifetimes. The evidence
// still says the attempt succeeded after the socket is gone, because it did.
func TestEvidenceOutlivesTheConnection(t *testing.T) {
	conn := newFakeConn(t)
	r, err := Connect(context.Background(), &fakeDialer{conn: conn}, testEndpoint, addrPort(t, "10.0.0.1:9092"))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	before := r.Evidence()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	after := r.Evidence()

	if after.State() != domain.StatePass {
		t.Errorf("state = %s after closing, want PASS: the attempt still succeeded", after.State())
	}
	if before.ID() != after.ID() {
		t.Error("the evidence changed when the connection was closed")
	}
	if r.Connected() {
		t.Error("Connected() is still true after Close")
	}
}

// TestEvidenceConstructionFailureClosesTheConnection covers the path that would
// otherwise leak a socket: a dial that succeeded followed by evidence that
// cannot be built. Input validation should make it unreachable, which is why the
// observation is constructed directly here.
func TestEvidenceConstructionFailureClosesTheConnection(t *testing.T) {
	conn := newFakeConn(t)

	// A zero StartedAt is rejected by domain.NewEvidence.
	r, err := newResult(observation{
		addr: addrPort(t, "10.0.0.1:9092"),
		conn: conn,
	}, testEndpoint)

	if err == nil {
		t.Fatal("expected evidence construction to fail")
	}
	if r != nil {
		t.Error("a result was returned alongside an error")
	}
	if conn.closes != 1 {
		t.Errorf("closes = %d, want 1: the connection leaked when evidence failed", conn.closes)
	}
}

// TestGraphHoldsEvidenceWhileTheConnectionStaysLive is the boundary in one test.
// The graph takes the fact; the Result keeps the resource; neither knows about
// the other.
func TestGraphHoldsEvidenceWhileTheConnectionStaysLive(t *testing.T) {
	conn := newFakeConn(t)
	r := connect(t, &fakeDialer{conn: conn}, addrPort(t, "10.0.0.1:9092"))

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
	if conn.closes != 0 {
		t.Error("recording the evidence closed the connection")
	}
	if !r.Connected() {
		t.Error("recording the evidence lost the connection")
	}

	// And the connection is still transferable afterwards.
	if _, ok := r.TakeConn(); !ok {
		t.Error("the connection could not be taken after its evidence was recorded")
	}
}
