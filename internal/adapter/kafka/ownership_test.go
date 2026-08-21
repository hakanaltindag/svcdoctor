package kafka

import (
	"context"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// These tests fail if the adapter ever starts dialing, closes a connection it
// handed on, or leaks one it kept. They assert on real sockets and close counts.

// dialedPaths builds transport continuations and returns the registry holding
// the sockets, so a test can watch what happens to each one.
func dialedPaths(
	t *testing.T, b *broker, addresses ...string,
) (*transport.Result, *domain.GraphBuilder, *connRegistry) {
	t.Helper()

	if len(addresses) == 0 {
		addresses = []string{"10.0.0.1"}
	}
	registry := &connRegistry{}
	builder := domain.NewGraphBuilder()

	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host: "primary.internal", Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, addresses)},
		Dialer:   brokerDialer{target: b.addr, conns: registry},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, builder, registry
}

func openCount(conns []*countingConn) int {
	open := 0
	for _, conn := range conns {
		if conn.closeCount() == 0 {
			open++
		}
	}
	return open
}

// TestExchangeUsesTheMeasuredConnection is the invariant of the whole phase: the
// protocol runs over the socket the transport evidence describes, and the
// adapter never opens one of its own.
func TestExchangeUsesTheMeasuredConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker)

	established := registry.all()
	if len(established) != 1 {
		t.Fatalf("transport established %d connections, want 1", len(established))
	}
	measured := established[0].LocalAddr().String()

	result := run(t, paths, builder, Params{})

	sessions := result.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(sessions))
	}
	conn, ok := sessions[0].TakeConn()
	if !ok {
		t.Fatal("the session has no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if got := conn.LocalAddr().String(); got != measured {
		t.Errorf("protocol ran on %s, want the measured socket %s", got, measured)
	}
	if got := broker.requestCount(); got != 1 {
		t.Errorf("broker saw %d requests, want exactly 1: the adapter must not redial", got)
	}
	if len(registry.all()) != 1 {
		t.Error("a second connection was established")
	}
}

// TestSuccessfulExchangeLeavesTheConnectionOpen is what makes Phase 3.2 possible:
// SASL has to continue on this socket rather than dial a new one.
func TestSuccessfulExchangeLeavesTheConnectionOpen(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker)

	result := run(t, paths, builder, Params{})

	if got := openCount(registry.all()); got != 1 {
		t.Errorf("%d connections remain open, want 1", got)
	}
	if !result.Sessions()[0].Available() {
		t.Error("the session reports no connection to continue from")
	}
}

// TestTransferredConnectionStillCarriesBytes proves the handoff is worth
// something: another Kafka request can be written on it.
func TestTransferredConnectionStillCarriesBytes(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, _ := dialedPaths(t, broker)

	result := run(t, paths, builder, Params{})

	conn, ok := result.Sessions()[0].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Errorf("writing over the transferred connection: %v", err)
	}
}

// TestExchangeClearsItsOwnDeadline checks the detail that would otherwise bite
// the next phase: a deadline left on the socket would expire somebody else's
// request.
func TestExchangeClearsItsOwnDeadline(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, _ := dialedPaths(t, broker)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := Run(ctx, builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	conn, ok := result.Sessions()[0].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	// The exchange's deadline is gone, so this write is bounded only by what the
	// caller sets now.
	time.Sleep(30 * time.Millisecond)
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Errorf("the exchange left a deadline on the connection: %v", err)
	}
}

func TestBrokenExchangeClosesTheConnection(t *testing.T) {
	broker := newBroker(t, peerSpeaksHTTP)
	paths, builder, registry := dialedPaths(t, broker)

	result := run(t, paths, builder, Params{})

	if got := openCount(registry.all()); got != 0 {
		t.Errorf("%d connections remain open after a broken exchange, want 0", got)
	}
	if len(result.Sessions()) != 0 {
		t.Error("a broken exchange produced a session")
	}
}

func TestTakeConnIsSingleUse(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, _ := dialedPaths(t, broker)

	session := run(t, paths, builder, Params{}).Sessions()[0]

	first, ok := session.TakeConn()
	if !ok {
		t.Fatal("the first TakeConn failed")
	}
	defer func() { _ = first.Close() }()

	if second, ok := session.TakeConn(); ok || second != nil {
		t.Error("the second TakeConn handed out the same connection again")
	}
}

func TestCloseBeforeTransferClosesExactlyOnce(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker)

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := result.Close(); err != nil {
			t.Errorf("Close %d returned %v, want nil", i+1, err)
		}
	}
	if got := registry.all()[0].closeCount(); got != 1 {
		t.Errorf("closes = %d, want exactly 1", got)
	}
	if result.Sessions()[0].Available() {
		t.Error("a session is still available after Close")
	}
}

func TestCloseAfterTransferDoesNotCloseCallerConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker)

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	conn, ok := result.Sessions()[0].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	established := registry.all()[0]

	if err := result.Close(); err != nil {
		t.Errorf("Close after transfer returned %v, want nil", err)
	}
	if got := established.closeCount(); got != 0 {
		t.Fatalf("closes = %d: Close closed a connection the caller owns", got)
	}

	if err := conn.Close(); err != nil {
		t.Errorf("closing the taken connection: %v", err)
	}
	if got := established.closeCount(); got != 1 {
		t.Errorf("closes = %d, want 1", got)
	}
}

// TestAbandoningTheResultReleasesEverything covers the caller that wanted the
// evidence and not the sessions.
func TestAbandoningTheResultReleasesEverything(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker, "10.0.0.1", "10.0.0.2", "10.0.0.3")

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := len(result.Sessions()); got != 3 {
		t.Fatalf("sessions = %d, want 3", got)
	}

	if err := result.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := openCount(registry.all()); got != 0 {
		t.Errorf("%d connections remain open after abandoning the result", got)
	}
}

// TestTakingOneSessionLeavesTheOthersToTheResult is the ordinary caller pattern.
func TestTakingOneSessionLeavesTheOthersToTheResult(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker, "10.0.0.1", "10.0.0.2", "10.0.0.3")

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	conn, ok := result.Sessions()[1].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	if err := result.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := openCount(registry.all()); got != 1 {
		t.Errorf("%d connections remain open, want only the taken one", got)
	}
}

// TestTransportOwnershipIsTransferred proves the handoff is complete: after the
// adapter has run, the transport result no longer holds the sockets, so closing
// it cannot close a connection the adapter handed on.
func TestTransportOwnershipIsTransferred(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, registry := dialedPaths(t, broker)

	result := run(t, paths, builder, Params{})

	if paths.Continuations()[0].Available() {
		t.Error("the transport continuation still claims the connection")
	}
	if err := paths.Close(); err != nil {
		t.Errorf("closing the transport result: %v", err)
	}
	if got := openCount(registry.all()); got != 1 {
		t.Errorf("closing the transport result closed the adapter's connection")
	}
	if !result.Sessions()[0].Available() {
		t.Error("the session lost its connection")
	}
}

// TestUnavailablePathIsSkippedWithoutEvidence covers a caller that already took
// a connection: the adapter has nothing to say about an exchange it could not
// attempt, and must not invent a node for it.
func TestUnavailablePathIsSkippedWithoutEvidence(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder, _ := dialedPaths(t, broker)

	taken, ok := paths.Continuations()[0].TakeConn()
	if !ok {
		t.Fatal("precondition failed: the continuation had no connection")
	}
	defer func() { _ = taken.Close() }()

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if len(result.Sessions()) != 0 {
		t.Error("a session was produced for a path with no connection")
	}
	graph := freeze(t, builder)
	if _, present := graph.Node("kafka.api_versions/primary.internal:9092/10.0.0.1"); present {
		t.Error("evidence was recorded for an exchange that never happened")
	}
	if got := broker.requestCount(); got != 0 {
		t.Errorf("broker saw %d requests, want 0", got)
	}
}
