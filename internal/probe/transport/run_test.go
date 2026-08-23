package transport

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// --- single address -------------------------------------------------------

func TestSingleAddressTCPPass(t *testing.T) {
	dialer := newScriptedDialer(t)
	result, graph := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	if graph.Len() != 2 {
		t.Fatalf("graph holds %v, want a DNS node and one TCP node", nodeIDs(graph))
	}
	dnsNode := node(t, graph, "dns.lookup/primary.internal")
	tcpNode := node(t, graph, "tcp.connect/primary.internal:9092/10.0.0.1")

	if dnsNode.State() != domain.StatePass {
		t.Errorf("dns state = %s, want PASS", dnsNode.State())
	}
	if tcpNode.State() != domain.StatePass {
		t.Errorf("tcp state = %s, want PASS", tcpNode.State())
	}
	if parents := graph.Parents(tcpNode.ID()); len(parents) != 1 || parents[0] != dnsNode.ID() {
		t.Errorf("tcp parents = %v, want [%s]", parents, dnsNode.ID())
	}
	if len(result.Continuations()) != 1 {
		t.Error("a successful TCP path left no connection to continue from")
	}
}

func TestSingleAddressTCPFail(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.1")
	result, graph := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	tcpNode := node(t, graph, "tcp.connect/primary.internal:9092/10.0.0.1")
	if tcpNode.State() != domain.StateFail {
		t.Errorf("tcp state = %s, want FAIL", tcpNode.State())
	}
	if tcpNode.FailureClass() != domain.FailureTCPConnectionRefused {
		t.Errorf("tcp failure = %s, want TCP_CONNECTION_REFUSED", tcpNode.FailureClass())
	}
	if len(result.Continuations()) != 0 {
		t.Error("a refused connection was retained")
	}
}

func TestSingleAddressTLSPass(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	tlsNode := node(t, graph, "tls.handshake/primary.internal:9092/10.0.0.1")
	if tlsNode.State() != domain.StatePass {
		t.Fatalf("tls state = %s (%s), want PASS", tlsNode.State(), tlsNode.FailureClass())
	}
	if parents := graph.Parents(tlsNode.ID()); len(parents) != 1 ||
		parents[0] != domain.EvidenceID("tcp.connect/primary.internal:9092/10.0.0.1") {
		t.Errorf("tls parents = %v, want the TCP node", parents)
	}
	if len(result.Continuations()) != 1 {
		t.Error("a completed handshake left no connection to continue from")
	}
}

func TestSingleAddressTLSFail(t *testing.T) {
	peer := newTLSPeer(t, []string{"other.internal"}) // certificate is for a different name
	dialer := &loopbackDialer{target: peer.addr}

	result, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	tlsNode := node(t, graph, "tls.handshake/primary.internal:9092/10.0.0.1")
	if tlsNode.State() != domain.StateFail {
		t.Errorf("tls state = %s, want FAIL", tlsNode.State())
	}
	if tlsNode.FailureClass() != domain.FailureTLSHostnameMismatch {
		t.Errorf("tls failure = %s, want TLS_HOSTNAME_MISMATCH", tlsNode.FailureClass())
	}
	if node(t, graph, "tcp.connect/primary.internal:9092/10.0.0.1").State() != domain.StatePass {
		t.Error("the TCP node should still record a successful connection")
	}
	if len(result.Continuations()) != 0 {
		t.Error("a failed handshake was retained as a continuation")
	}
}

// --- multiple addresses ---------------------------------------------------

// TestEveryAddressIsAttempted is the diagnostic premise of the whole chain: a
// working address must never stop svcdoctor from inspecting the rest.
func TestEveryAddressIsAttempted(t *testing.T) {
	dialer := newScriptedDialer(t)
	_, graph := run(t, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2", "2001:db8::1"), dialer))

	for _, address := range []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"} {
		id := "tcp.connect/primary.internal:9092/" + address
		if node(t, graph, id).State() != domain.StatePass {
			t.Errorf("%s did not record a successful attempt", id)
		}
	}
	if got := len(dialer.attempts()); got != 3 {
		t.Errorf("dial attempts = %d, want 3", got)
	}
}

// TestBrokenAddressIsNotHiddenByWorkingOnes is the same premise stated as the
// failure it prevents.
func TestBrokenAddressIsNotHiddenByWorkingOnes(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.2")
	result, graph := run(t, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2", "10.0.0.3"), dialer))

	states := map[string]domain.State{
		"10.0.0.1": domain.StatePass,
		"10.0.0.2": domain.StateFail,
		"10.0.0.3": domain.StatePass,
	}
	for address, want := range states {
		got := node(t, graph, "tcp.connect/primary.internal:9092/"+address).State()
		if got != want {
			t.Errorf("%s state = %s, want %s", address, got, want)
		}
	}
	if len(result.Continuations()) != 2 {
		t.Errorf("continuations = %d, want the two working addresses",
			len(result.Continuations()))
	}
}

func TestAllAddressesFail(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.1", "10.0.0.2")
	result, graph := run(t, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))

	if graph.Len() != 3 {
		t.Fatalf("graph holds %v, want DNS plus two TCP nodes", nodeIDs(graph))
	}
	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		if node(t, graph, "tcp.connect/primary.internal:9092/"+address).State() != domain.StateFail {
			t.Errorf("%s should have failed", address)
		}
	}
	if len(result.Continuations()) != 0 {
		t.Error("nothing succeeded, so nothing should be retained")
	}
}

// TestMixedFamiliesAreBothAttempted checks that neither address family is
// preferred, skipped or treated as unusual.
func TestMixedFamiliesAreBothAttempted(t *testing.T) {
	dialer := newScriptedDialer(t)
	_, graph := run(t, tcpParams(resolving(t, "2001:db8::1", "10.0.0.1"), dialer))

	for _, id := range []string{
		"tcp.connect/primary.internal:9092/10.0.0.1",
		"tcp.connect/primary.internal:9092/2001:db8::1",
	} {
		if node(t, graph, id).State() != domain.StatePass {
			t.Errorf("%s was not attempted successfully", id)
		}
	}
}

func TestSeveralAddressesReachTLS(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1", "10.0.0.2"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		id := "tls.handshake/primary.internal:9092/" + address
		if got := node(t, graph, id).State(); got != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", id, got)
		}
	}
	// Both handshakes completed, so both are offered as continuations and the
	// chain picks neither.
	if got := len(result.Continuations()); got != 2 {
		t.Fatalf("continuations = %d, want 2", got)
	}
	established := dialer.established()
	if len(established) != 2 {
		t.Fatalf("established %d connections, want 2", len(established))
	}
	for i, conn := range established {
		if conn.closeCount() != 0 {
			t.Errorf("connection %d was closed although its path completed", i)
		}
	}
}

// TestFailedPathDoesNotBecomeTheContinuation covers the case where one address
// completes TLS and another fails it: the evidence records both, and the
// continuation is the path that actually works.
func TestFailedPathDoesNotBecomeTheContinuation(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{
		target: peer.addr,
		refuse: map[string]bool{"10.0.0.1": true},
	}

	result, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1", "10.0.0.2"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	if got := node(t, graph, "tcp.connect/primary.internal:9092/10.0.0.1").State(); got != domain.StateFail {
		t.Errorf("first address state = %s, want FAIL", got)
	}
	if got := node(t, graph, "tls.handshake/primary.internal:9092/10.0.0.2").State(); got != domain.StatePass {
		t.Errorf("second address TLS state = %s, want PASS", got)
	}

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want only the path that completed", len(continuations))
	}
	if got := continuations[0].Address().Addr().String(); got != "10.0.0.2" {
		t.Errorf("continuation address = %s, want 10.0.0.2", got)
	}
	if want := domain.EvidenceID("tls.handshake/primary.internal:9092/10.0.0.2"); continuations[0].Evidence() != want {
		t.Errorf("continuation evidence = %q, want %q", continuations[0].Evidence(), want)
	}
}

// --- skipped semantics ----------------------------------------------------

// TestTLSIsSkippedAfterTCPFailure covers the case where the downstream subject
// is known: the address exists, so the report can say TLS was not attempted and
// point at what stopped it.
func TestTLSIsSkippedAfterTCPFailure(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr, refuse: map[string]bool{"10.0.0.1": true}}

	_, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	tcpID := domain.EvidenceID("tcp.connect/primary.internal:9092/10.0.0.1")
	skipped := node(t, graph, "tls.handshake/primary.internal:9092/10.0.0.1")

	if skipped.State() != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", skipped.State())
	}
	if skipped.FailureClass() != domain.FailureExecSkippedPrerequisiteFailed {
		t.Errorf("failure class = %s, want EXEC_SKIPPED_PREREQUISITE_FAILED", skipped.FailureClass())
	}
	if blockers := graph.BlockedBy(skipped.ID()); len(blockers) != 1 || blockers[0] != tcpID {
		t.Errorf("blocked by %v, want [%s]", blockers, tcpID)
	}
	if skipped.AttributeCount() != 0 {
		t.Error("a step that never ran must not carry observations")
	}
	// Not "zero", which is a measurement a real step can produce. A step that
	// never ran timed nothing at all, and domain.Elapsed keeps the two apart.
	if skipped.Elapsed().IsMeasured() {
		t.Error("a step that never ran carries a measurement")
	}
}

func TestNoTLSNodeWhenTLSWasNotRequested(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.1")
	_, graph := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	if _, ok := graph.Node("tls.handshake/primary.internal:9092/10.0.0.1"); ok {
		t.Error("a TLS node was recorded although TLS was never requested")
	}
}

// TestNoDownstreamNodesWithoutAnAddress is the case where the downstream
// subject never existed. Inventing an address to hang a skipped node on would
// be a synthetic fact, so the failed lookup is the whole record.
func TestNoDownstreamNodesWithoutAnAddress(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, graph := run(t, Params{
		Host: testHost, Port: testPort, Resolver: &fakeResolver{}, Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	if graph.Len() != 1 {
		t.Fatalf("graph holds %v, want only the DNS node", nodeIDs(graph))
	}
	dnsNode := node(t, graph, "dns.lookup/primary.internal")
	if dnsNode.State() != domain.StateFail {
		t.Errorf("dns state = %s, want FAIL", dnsNode.State())
	}
	if dnsNode.FailureClass() != domain.FailureDNSNoAddress {
		t.Errorf("dns failure = %s, want DNS_NO_ADDRESS", dnsNode.FailureClass())
	}
	if len(result.Continuations()) != 0 {
		t.Error("nothing was resolved, so nothing should be retained")
	}
	if len(dialer.established()) != 0 {
		t.Error("a connection was attempted although no address was resolved")
	}
}

func TestDNSFailureStopsTheSweep(t *testing.T) {
	dialer := newScriptedDialer(t)
	resolver := &fakeResolver{err: &net.DNSError{Err: "server misbehaving", IsTemporary: true}}

	_, graph := run(t, tcpParams(resolver, dialer))

	if graph.Len() != 1 {
		t.Fatalf("graph holds %v, want only the DNS node", nodeIDs(graph))
	}
	if got := node(t, graph, "dns.lookup/primary.internal").FailureClass(); got != domain.FailureDNSResolverFailure {
		t.Errorf("dns failure = %s, want DNS_RESOLVER_FAILURE", got)
	}
	if len(dialer.attempts()) != 0 {
		t.Error("addresses were dialed although the lookup failed")
	}
}

// --- budget ---------------------------------------------------------------

// TestCancellationRecordsUnattemptedAddresses proves the claim discipline holds
// across the chain: svcdoctor running out of time is never a statement about
// the target.
func TestCancellationRecordsUnattemptedAddresses(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := Run(ctx, builder, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	graph := freeze(t, builder)
	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		skipped := node(t, graph, "tcp.connect/primary.internal:9092/"+address)
		if skipped.State() != domain.StateSkipped {
			t.Errorf("%s state = %s, want SKIPPED", address, skipped.State())
		}
		if skipped.FailureClass() != domain.FailureExecCancelled {
			t.Errorf("%s failure = %s, want EXEC_CANCELLED", address, skipped.FailureClass())
		}
	}
	if len(dialer.attempts()) != 0 {
		t.Error("addresses were dialed after cancellation")
	}
	if len(result.Continuations()) != 0 {
		t.Error("a cancelled sweep retained a connection")
	}
}

func TestExpiredDeadlineIsLocalNotRemote(t *testing.T) {
	dialer := newScriptedDialer(t)
	builder := domain.NewGraphBuilder()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	result, err := Run(ctx, builder, tcpParams(resolving(t, "10.0.0.1"), dialer))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	skipped := node(t, freeze(t, builder), "tcp.connect/primary.internal:9092/10.0.0.1")
	if skipped.State() != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", skipped.State())
	}
	if skipped.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure = %s, want EXEC_LOCAL_TIMEOUT", skipped.FailureClass())
	}
	if skipped.FailureClass() == domain.FailureTCPConnectionTimeout {
		t.Error("a local budget expiry was reported as a remote timeout")
	}
}

// TestStepTimeoutBoundsOneAddress shows why the per-step bound exists: a slow
// address must not consume the budget every later address needs.
func TestStepTimeoutBoundsOneAddress(t *testing.T) {
	dialer := newScriptedDialer(t)
	dialer.err = context.DeadlineExceeded

	params := tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer)
	params.StepTimeout = 20 * time.Millisecond

	_, graph := run(t, params)

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		attempted := node(t, graph, "tcp.connect/primary.internal:9092/"+address)
		if attempted.State() != domain.StateUnknown {
			t.Errorf("%s state = %s, want UNKNOWN", address, attempted.State())
		}
		if attempted.FailureClass() != domain.FailureExecLocalTimeout {
			t.Errorf("%s failure = %s, want EXEC_LOCAL_TIMEOUT", address, attempted.FailureClass())
		}
	}
	if got := len(dialer.attempts()); got != 2 {
		t.Errorf("dial attempts = %d, want both addresses attempted", got)
	}
}

// --- determinism ----------------------------------------------------------

// TestGraphIsIdenticalForEquivalentRuns pins that the recorded evidence depends
// on the facts and not on iteration order or on which address answered first.
func TestGraphIsIdenticalForEquivalentRuns(t *testing.T) {
	encode := func(t *testing.T, values ...string) string {
		t.Helper()

		dialer := newScriptedDialer(t, "10.0.0.2")
		_, graph := run(t, tcpParams(resolving(t, values...), dialer))

		nodes := graph.Nodes()
		shapes := make([]string, 0, len(nodes))
		for _, e := range nodes {
			shapes = append(shapes, e.ID().String()+"|"+e.State().String()+"|"+e.FailureClass().String())
		}
		encoded, err := json.Marshal(shapes)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return string(encoded)
	}

	// The DNS probe canonicalizes its answers, so a resolver that returns the
	// same set in a different order must produce the same graph.
	forward := encode(t, "10.0.0.1", "10.0.0.2", "10.0.0.3")
	shuffled := encode(t, "10.0.0.3", "10.0.0.1", "10.0.0.2")

	if forward != shuffled {
		t.Errorf("resolver order changed the graph:\n got %s\nwant %s", shuffled, forward)
	}
}

func TestAddressesAreAttemptedInCanonicalOrder(t *testing.T) {
	dialer := newScriptedDialer(t)
	run(t, tcpParams(resolving(t, "2001:db8::1", "10.0.0.2", "10.0.0.1"), dialer))

	want := []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"}
	attempts := dialer.attempts()
	if len(attempts) != len(want) {
		t.Fatalf("attempts = %v, want %v", attempts, want)
	}
	for i, address := range want {
		if got := attempts[i].Addr().String(); got != address {
			t.Errorf("attempt %d = %s, want %s", i, got, address)
		}
	}
}

// --- what the chain refuses to decide -------------------------------------

// TestChainEmitsNoJudgement is the layering guard. The chain records facts; it
// has no status, no severity and no finding, and adding one would move
// diagnosis into orchestration.
func TestChainEmitsNoJudgement(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.2")
	result, graph := run(t, tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer))

	var chainResult any = result
	if _, ok := chainResult.(interface{ Status() string }); ok {
		t.Error("the chain exposes an overall status")
	}
	if _, ok := chainResult.(interface{ Healthy() bool }); ok {
		t.Error("the chain judges health")
	}
	if _, ok := chainResult.(interface{ Best() *Continuation }); ok {
		t.Error("the chain ranks its continuations")
	}

	// The graph carries both outcomes, unaggregated.
	states := map[domain.State]int{}
	for _, e := range graph.Nodes() {
		states[e.State()]++
	}
	if states[domain.StatePass] == 0 || states[domain.StateFail] == 0 {
		t.Errorf("expected both a pass and a failure to survive as facts, got %v", states)
	}
}

// --- invalid input --------------------------------------------------------

func TestRunRejectsUnusableInput(t *testing.T) {
	dialer := newScriptedDialer(t)
	resolver := resolving(t, "10.0.0.1")

	tests := map[string]Params{
		"empty host":       {Port: testPort, Resolver: resolver, Dialer: dialer},
		"zero port":        {Host: testHost, Resolver: resolver, Dialer: dialer},
		"no resolver":      {Host: testHost, Port: testPort, Dialer: dialer},
		"no dialer":        {Host: testHost, Port: testPort, Resolver: resolver},
		"negative timeout": {Host: testHost, Port: testPort, Resolver: resolver, Dialer: dialer, StepTimeout: -time.Second},
	}

	for name, params := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := Run(context.Background(), domain.NewGraphBuilder(), params)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want ErrInvalidInput", err)
			}
			if result != nil {
				t.Error("a result was produced for unusable input")
			}
		})
	}
}

func TestRunRejectsNilBuilder(t *testing.T) {
	result, err := Run(context.Background(), nil, tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if result != nil {
		t.Error("a result was produced without a graph builder")
	}
}

//nolint:staticcheck // passing a nil context is exactly what this guard is for.
func TestRunRejectsNilContext(t *testing.T) {
	result, err := Run(nil, domain.NewGraphBuilder(), tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if result != nil {
		t.Error("a result was produced without a context")
	}
}

// TestTransportOutcomesAreNotChainErrors pins the boundary between a diagnostic
// fact and an operational error.
func TestTransportOutcomesAreNotChainErrors(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.1")
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, tcpParams(resolving(t, "10.0.0.1"), dialer))
	if err != nil {
		t.Fatalf("a refused connection became a chain error: %v", err)
	}
	defer func() { _ = result.Close() }()

	if node(t, freeze(t, builder), "tcp.connect/primary.internal:9092/10.0.0.1").State() != domain.StateFail {
		t.Error("the refusal was not recorded as evidence")
	}
}

// TestNoRuntimeErrorProseReachesEvidence guards ADR 0010 at the chain level.
func TestNoRuntimeErrorProseReachesEvidence(t *testing.T) {
	const canary = "chain-canary-198.51.100.7"

	dialer := newScriptedDialer(t)
	dialer.err = errors.New(canary)

	_, graph := run(t, tcpParams(resolving(t, "10.0.0.1"), dialer))

	for _, e := range graph.Nodes() {
		encoded, err := e.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if strings.Contains(string(encoded), canary) {
			t.Errorf("node %s carries dial error prose: %s", e.ID(), encoded)
		}
	}
}
