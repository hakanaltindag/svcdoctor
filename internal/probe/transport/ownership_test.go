package transport

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// These tests exist to fail if a future refactor reintroduces the forbidden
// architecture: measure a connection, close it, and let the next layer dial
// again. They assert on real sockets and close counts rather than on mock
// expectations.

func openCount(conns []*countingConn) int {
	open := 0
	for _, conn := range conns {
		if conn.closeCount() == 0 {
			open++
		}
	}
	return open
}

// TestContinuationIsTheMeasuredConnection is the invariant of the whole phase:
// what the caller continues over is the socket the evidence describes.
func TestContinuationIsTheMeasuredConnection(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	established := dialer.established()
	if len(established) != 1 {
		t.Fatalf("established %d connections, want 1", len(established))
	}

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1", len(continuations))
	}
	conn, ok := continuations[0].TakeConn()
	if !ok {
		t.Fatal("no connection was retained")
	}
	defer func() { _ = conn.Close() }()

	if got, want := conn.LocalAddr().String(), established[0].LocalAddr().String(); got != want {
		t.Errorf("continuation local address = %s, want %s: a different socket was handed on", got, want)
	}
	if established[0].closeCount() != 0 {
		t.Error("the measured connection was closed before it was handed on")
	}
}

// TestTransferredConnectionCarriesBytes proves the handoff is worth something:
// the continuation is a working TLS session, not a closed descriptor.
func TestTransferredConnectionCarriesBytes(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1", len(continuations))
	}
	conn, ok := continuations[0].TakeConn()
	if !ok {
		t.Fatal("no connection was retained")
	}
	defer func() { _ = conn.Close() }()

	const message = "the protocol exchange would start here"
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("writing over the continuation: %v", err)
	}

	buf := make([]byte, len(message))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("reading from the continuation: %v", err)
	}
	if got := string(buf); got != message {
		t.Errorf("read %q, want %q", got, message)
	}
}

// TestEveryCompletedPathIsOfferedAndNoneIsChosen is the continuation policy:
// the chain hands back what worked and expresses no preference, because
// preferring one working path over another is client policy it has no basis for.
func TestEveryCompletedPathIsOfferedAndNoneIsChosen(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2", "10.0.0.3"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	established := dialer.established()
	if len(established) != 3 {
		t.Fatalf("established %d connections, want 3", len(established))
	}
	if got := openCount(established); got != 3 {
		t.Errorf("%d connections remain open, want all 3: the chain must not discard working paths", got)
	}

	continuations := result.Continuations()
	if len(continuations) != 3 {
		t.Fatalf("continuations = %d, want 3", len(continuations))
	}

	// The order is the evidence order, and every entry is equally available:
	// nothing here marks one of them as the choice.
	seen := map[string]bool{}
	for _, continuation := range continuations {
		if !continuation.Available() {
			t.Errorf("continuation %s is not available to take", continuation.Address())
		}
		seen[continuation.Address().Addr().String()] = true
	}
	for _, address := range []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"} {
		if !seen[address] {
			t.Errorf("%s completed but was not offered as a continuation", address)
		}
	}
}

// TestCanonicalOrderIsNotAFamilyPreference is the regression guard for the
// design this phase corrected. Canonical address ordering puts every IPv4
// address before every IPv6 one, so a chain that retained "the first successful
// path" would silently behave as an IPv4 preference. Both families must be
// offered.
func TestCanonicalOrderIsNotAFamilyPreference(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "2001:db8::1", "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	families := map[bool]bool{}
	for _, continuation := range result.Continuations() {
		families[continuation.Address().Addr().Is4()] = true
	}
	if !families[true] || !families[false] {
		t.Errorf("both families completed but only one was offered: %v", families)
	}
}

func TestFailedTCPLeavesNoConnection(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.1")
	result, _ := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	if len(result.Continuations()) != 0 {
		t.Error("a refused attempt reported a connection")
	}
	if err := result.Close(); err != nil {
		t.Errorf("Close on an empty result returned %v, want nil", err)
	}
}

// TestFailedTLSClosesTheUnderlyingConnection checks the handoff's error path:
// the TCP connection was established and must not survive a rejected handshake.
func TestFailedTLSClosesTheUnderlyingConnection(t *testing.T) {
	peer := newTLSPeer(t, []string{"other.internal"})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	established := dialer.established()
	if len(established) != 1 {
		t.Fatalf("established %d connections, want 1", len(established))
	}
	if got := established[0].closeCount(); got != 1 {
		t.Errorf("closes = %d, want 1: a rejected handshake must release its socket", got)
	}
	if len(result.Continuations()) != 0 {
		t.Error("a rejected handshake was retained")
	}
}

func TestTakeConnIsSingleUse(t *testing.T) {
	dialer := newScriptedDialer(t)
	result, _ := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	continuation := result.Continuations()[0]

	first, ok := continuation.TakeConn()
	if !ok {
		t.Fatal("the first TakeConn failed")
	}
	defer func() { _ = first.Close() }()

	if second, ok := continuation.TakeConn(); ok || second != nil {
		t.Error("the second TakeConn handed out the same connection again")
	}
}

func TestCloseBeforeTransferClosesExactlyOnce(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, tcpParams(resolving(t, "10.0.0.1"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	conn := dialer.conn(t, "10.0.0.1")
	for i := 0; i < 3; i++ {
		if err := result.Close(); err != nil {
			t.Errorf("Close %d returned %v, want nil", i+1, err)
		}
	}
	if got := conn.closeCount(); got != 1 {
		t.Errorf("closes = %d, want exactly 1", got)
	}
	if result.Continuations()[0].Available() {
		t.Error("a continuation is still available after Close")
	}
}

func TestCloseAfterTransferDoesNotCloseCallerConnection(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, tcpParams(resolving(t, "10.0.0.1"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	conn, ok := result.Continuations()[0].TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	established := dialer.conn(t, "10.0.0.1")

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

// TestAbandoningTheResultReleasesEverything covers the caller who wanted the
// evidence and not the connection.
func TestAbandoningTheResultReleasesEverything(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if err := result.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := openCount(dialer.established()); got != 0 {
		t.Errorf("%d connections remain open after abandoning the result", got)
	}
}

// TestEvidenceOutlivesTheConnections separates the two lifetimes: the graph is
// still complete and readable after every socket is gone.
func TestEvidenceOutlivesTheConnections(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.2")
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := result.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	graph := freeze(t, builder)
	if graph.Len() != 3 {
		t.Fatalf("graph holds %v, want DNS plus two TCP nodes", nodeIDs(graph))
	}
	if node(t, graph, "tcp.connect/primary.internal:9092/10.0.0.1").State() != domain.StatePass {
		t.Error("the successful attempt stopped being a fact when its socket closed")
	}
}

// TestNoConnectionReachesTheCanonicalOutput is the structural half: nothing that
// gets serialized can hold a live resource.
func TestNoConnectionReachesTheCanonicalOutput(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	_, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	allowed := map[string]bool{
		"id": true, "subject": true, "layer": true, "step": true, "state": true,
		"failureClass": true, "attributes": true, "startedAt": true, "duration": true,
	}
	for _, evidence := range graph.Nodes() {
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		for _, forbidden := range []string{"127.0.0.1:", "LocalAddr", "RemoteAddr", "fd"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Errorf("node %s leaks connection detail %q: %s", evidence.ID(), forbidden, encoded)
			}
		}
		fields := map[string]json.RawMessage{}
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		for field := range fields {
			if !allowed[field] {
				t.Errorf("node %s carries an unexpected field %q", evidence.ID(), field)
			}
		}
	}
}

// TestErrorPathReleasesRetainedConnection covers the leak that would otherwise
// be invisible: a sweep that retained a connection and then failed.
//
// The collision is arranged by pre-recording the second address's TCP node, so
// the chain's own AddEvidence fails after the first address was already
// retained.
func TestErrorPathReleasesRetainedConnection(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	clashing, err := domain.NewEvidence(domain.EvidenceInput{
		ID:        "tcp.connect/primary.internal:9092/10.0.0.2",
		Subject:   mustSubject(t, "10.0.0.2:9092"),
		Layer:     domain.LayerTCP,
		Step:      "tcp.connect",
		State:     domain.StatePass,
		StartedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := builder.AddEvidence(clashing); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}

	result, err := Run(context.Background(), builder, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))
	if err == nil {
		t.Fatal("expected the duplicate identifier to fail the run")
	}
	if result != nil {
		t.Error("a result was returned alongside an error")
	}
	if got := openCount(dialer.established()); got != 0 {
		t.Errorf("%d connections remain open after a failed run", got)
	}
}

// TestCancelledSweepLeaksNothing checks the budget path for the same property.
func TestCancelledSweepLeaksNothing(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Run(ctx, builder, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := result.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := openCount(dialer.established()); got != 0 {
		t.Errorf("%d connections remain open after a cancelled sweep", got)
	}
}

func (d *scriptedDialer) established() []*countingConn {
	d.mu.Lock()
	defer d.mu.Unlock()

	conns := make([]*countingConn, 0, len(d.conns))
	for _, conn := range d.conns {
		conns = append(conns, conn)
	}
	return conns
}

func mustSubject(t *testing.T, ref string) domain.Subject {
	t.Helper()

	subject, err := domain.NewEndpointSubject(ref)
	if err != nil {
		t.Fatalf("NewEndpointSubject(%q): %v", ref, err)
	}
	return subject
}

// TestTakingOnePathLeavesTheOthersToTheResult is the ordinary caller pattern:
// choose a path, close the rest by closing the Result, and keep the one taken.
func TestTakingOnePathLeavesTheOthersToTheResult(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2", "10.0.0.3"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// A caller with no preference of its own still has to choose deliberately.
	chosen := result.Continuations()[1]
	conn, ok := chosen.TakeConn()
	if !ok {
		t.Fatal("TakeConn failed")
	}
	defer func() { _ = conn.Close() }()

	if err := result.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	established := dialer.established()
	if got := openCount(established); got != 1 {
		t.Errorf("%d connections remain open after closing the result, want only the taken one", got)
	}
	// And the one still open is usable.
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, err := conn.Write([]byte("still alive")); err != nil {
		t.Errorf("the taken connection was closed with the others: %v", err)
	}
}

// TestClosingOneContinuationLeavesTheOthers covers releasing a path early
// without giving up the rest.
func TestClosingOneContinuationLeavesTheOthers(t *testing.T) {
	dialer := newScriptedDialer(t)
	result, _ := run(t, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))

	continuations := result.Continuations()
	if len(continuations) != 2 {
		t.Fatalf("continuations = %d, want 2", len(continuations))
	}

	if err := continuations[0].Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if continuations[0].Available() {
		t.Error("a closed continuation is still available")
	}
	if !continuations[1].Available() {
		t.Error("closing one continuation closed another")
	}
	if got := openCount(dialer.established()); got != 1 {
		t.Errorf("%d connections remain open, want 1", got)
	}
}
