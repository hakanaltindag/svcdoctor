package kafka

import (
	"context"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// These tests fail if the handshake ever starts dialing, keeps a socket it has
// nothing to send on, closes one it handed over, or leaks one it kept. They
// assert on real sockets and close counts, because the invariant they protect —
// that every Kafka fact describes the connection the transport measured — is
// invisible to a test that only checks return values.

// TestHandshakeUsesTheMeasuredConnection is the invariant of the whole vertical
// slice, now four layers deep: DNS, TCP, ApiVersions and SaslHandshake all
// describe one socket.
func TestHandshakeUsesTheMeasuredConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker)

	established := registry.all()
	if len(established) != 1 {
		t.Fatalf("transport established %d connections, want 1", len(established))
	}
	measured := established[0].LocalAddr().String()

	result := runHandshake(t, sessions, builder, SASLParams{})

	handshakeSessions := result.Sessions()
	if len(handshakeSessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(handshakeSessions))
	}
	conn, ok := handshakeSessions[0].TakeConn()
	if !ok {
		t.Fatal("the handshake session has no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if got := conn.LocalAddr().String(); got != measured {
		t.Errorf("the handshake ran on %s, want the measured socket %s", got, measured)
	}
	if got := len(registry.all()); got != 1 {
		t.Errorf("%d connections were established, want 1: the adapter must not redial", got)
	}
	if got := broker.requestCount(); got != 1 {
		t.Errorf("broker saw %d ApiVersions requests, want 1", got)
	}
	if got := broker.saslRequestCount(); got != 1 {
		t.Errorf("broker saw %d handshakes, want 1", got)
	}
}

// TestBothExchangesShareOneConnection is the same claim seen from the peer: one
// accepted connection carried both requests.
func TestBothExchangesShareOneConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker, "10.0.0.1", "10.0.0.2")

	runHandshake(t, sessions, builder, SASLParams{})

	if got := len(registry.all()); got != 2 {
		t.Errorf("%d connections were established, want one per address", got)
	}
	if got := broker.requestCount(); got != 2 {
		t.Errorf("ApiVersions requests = %d, want 2", got)
	}
	if got := broker.saslRequestCount(); got != 2 {
		t.Errorf("handshakes = %d, want 2", got)
	}
}

// TestAcceptedHandshakeKeepsTheConnection is what makes authentication possible
// later: it has to continue on this socket rather than dial a new one.
func TestAcceptedHandshakeKeepsTheConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{})

	if got := openCount(registry.all()); got != 1 {
		t.Errorf("%d connections remain open, want 1", got)
	}
	if !result.Sessions()[0].Available() {
		t.Error("the session reports no connection to continue from")
	}
}

// TestRejectedMechanismClosesTheConnection is the distinction this step draws
// differently from ApiVersions, and the reason is protocol state rather than
// evidence state: after a handshake the broker accepts only that mechanism's
// continuation, so a rejected mechanism leaves a socket with nothing that may be
// sent on it.
func TestRejectedMechanismClosesTheConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASLError(33))
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{})

	if got := openCount(registry.all()); got != 0 {
		t.Errorf("%d connections remain open after a rejected mechanism, want 0", got)
	}
	if len(result.Sessions()) != 0 {
		t.Error("a rejected mechanism produced a session")
	}
}

// TestConnectionLifetimeIsNotDrivenByEvidenceState proves the rule above is
// about the protocol rather than about FAIL. The same broker error-code shape
// keeps its connection at L4 and loses it at L5, because only one of those two
// sockets has a defined next message.
func TestConnectionLifetimeIsNotDrivenByEvidenceState(t *testing.T) {
	broker := newBroker(t, peerAnswersWithError, withErrorCode(35))
	paths, builder, registry := dialedPaths(t, broker)

	apiVersions, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = apiVersions.Close() })

	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")
	if evidence.State() != domain.StateFail {
		t.Fatalf("precondition: ApiVersions state = %s, want FAIL", evidence.State())
	}
	if got := openCount(registry.all()); got != 1 {
		t.Error("a FAIL at L4 closed a connection that any request could still follow")
	}
	if len(apiVersions.Sessions()) != 1 {
		t.Fatal("a broker error code at L4 discarded a usable session")
	}
}

// TestBrokenHandshakeClosesTheConnection covers the ambiguous case: nobody knows
// what state the socket is in, so nobody may inherit it.
func TestBrokenHandshakeClosesTheConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSpeaksHTTP))
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{})

	if got := openCount(registry.all()); got != 0 {
		t.Errorf("%d connections remain open after a broken handshake, want 0", got)
	}
	if len(result.Sessions()) != 0 {
		t.Error("a broken handshake produced a session")
	}
}

// TestTimedOutHandshakeClosesTheConnection covers the local-budget case, where
// the socket may still hold an answer nobody read.
func TestTimedOutHandshakeClosesTheConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSaysNothing))
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{ExchangeTimeout: 30 * time.Millisecond})

	if got := openCount(registry.all()); got != 0 {
		t.Errorf("%d connections remain open after a timeout, want 0", got)
	}
	if len(result.Sessions()) != 0 {
		t.Error("a timed-out handshake produced a session")
	}
}

// TestApiVersionsOwnershipIsTransferred proves the handoff between the two Kafka
// steps is complete: after the handshake, closing the ApiVersions result cannot
// close a connection the handshake kept.
func TestApiVersionsOwnershipIsTransferred(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{})

	if sessions.Sessions()[0].Available() {
		t.Error("the ApiVersions session still claims the connection")
	}
	if err := sessions.Close(); err != nil {
		t.Errorf("closing the ApiVersions result: %v", err)
	}
	if got := openCount(registry.all()); got != 1 {
		t.Error("closing the ApiVersions result closed the handshake's connection")
	}
	if !result.Sessions()[0].Available() {
		t.Error("the handshake session lost its connection")
	}
}

// TestHandshakeClearsItsOwnDeadline checks the detail that would otherwise bite
// authentication: a deadline left on the socket would expire somebody else's
// request.
func TestHandshakeClearsItsOwnDeadline(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := SASLHandshake(ctx, builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	conn, ok := result.Sessions()[0].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	time.Sleep(30 * time.Millisecond)
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Errorf("the handshake left a deadline on the connection: %v", err)
	}
}

func TestHandshakeTakeConnIsSingleUse(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	session := runHandshake(t, sessions, builder, SASLParams{}).Sessions()[0]

	first, ok := session.TakeConn()
	if !ok {
		t.Fatal("the first TakeConn failed")
	}
	defer func() { _ = first.Close() }()

	if second, ok := session.TakeConn(); ok || second != nil {
		t.Error("the second TakeConn handed out the same connection again")
	}
}

func TestHandshakeCloseBeforeTransferClosesExactlyOnce(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
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

func TestHandshakeCloseAfterTransferDoesNotCloseCallerConnection(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker)

	result, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
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

// TestAbandoningTheHandshakeResultReleasesEverything covers the caller that
// wanted the evidence and not the sessions.
func TestAbandoningTheHandshakeResultReleasesEverything(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, registry := apiVersionsSessions(t, broker, "10.0.0.1", "10.0.0.2", "10.0.0.3")

	result, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
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

// TestUnavailableSessionIsSkippedWithoutEvidence covers a caller that already
// took a connection: the handshake has nothing to say about an exchange it could
// not attempt, and must not invent a node for it.
func TestUnavailableSessionIsSkippedWithoutEvidence(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	taken, ok := sessions.Sessions()[0].TakeConn()
	if !ok {
		t.Fatal("precondition failed: the session had no connection")
	}
	defer func() { _ = taken.Close() }()

	result := runHandshake(t, sessions, builder, SASLParams{})

	if len(result.Sessions()) != 0 {
		t.Error("a session was produced for a path with no connection")
	}
	if _, present := freeze(t, builder).Node(handshakeNodeID); present {
		t.Error("evidence was recorded for an exchange that never happened")
	}
	if got := broker.saslRequestCount(); got != 0 {
		t.Errorf("broker saw %d handshakes, want 0", got)
	}
}

// TestNoSkippedNodesAreInvented pins the deliberate absence: this step records
// what it observed and nothing about paths it never received. Whether a service
// step that never ran deserves a SKIPPED node is an open question with an owner
// that does not exist yet, and answering it here by accident would settle it
// (ADR 0025 section 9, ADR 0026).
func TestNoSkippedNodesAreInvented(t *testing.T) {
	answering := newBroker(t, peerAnswers)
	silent := newBroker(t, peerHangsUp)

	builder := domain.NewGraphBuilder()
	good := apiVersionsSessionsAt(t, builder, answering, "primary.internal", "10.0.0.1")
	// The second endpoint's ApiVersions exchange breaks, so it yields no
	// session and the handshake never learns the address existed.
	_ = apiVersionsSessionsAt(t, builder, silent, "secondary.internal", "10.0.0.2")

	result, err := SASLHandshake(
		context.Background(), builder, good.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph := freeze(t, builder)

	for _, evidence := range graph.Nodes() {
		if evidence.State() == domain.StateSkipped {
			t.Errorf("node %s is SKIPPED: this step invented one", evidence.ID())
		}
	}
	if _, present := graph.Node("kafka.sasl_handshake/secondary.internal:9092/10.0.0.2"); present {
		t.Error("a handshake node exists for a path the step never received")
	}
}
