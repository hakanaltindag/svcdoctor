package transport

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	tlsprobe "github.com/hakanaltindag/svcdoctor/internal/probe/tls"
)

// These tests pin one structural invariant of the chain:
//
//	A TCP node has a TLS child if and only if the sweep's plan requested TLS.
//
// It holds in every branch, including the ones where nothing was attempted: a
// requested handshake that could not run is recorded as a SKIPPED TLS node
// blocked by the TCP node that produced no connection, and a plan that asked for
// no TLS never mints a TLS node at all.
//
// # Why this is load-bearing beyond transport
//
// The chain has always behaved this way, but the property was emergent rather
// than stated, and something outside this package now depends on it. A rule
// reading a frozen graph has to know what "reaching the endpoint" required
// before it can say the endpoint was not reached: TCP success is the terminal
// success of a plaintext plan and is *not* enough when TLS was required. The
// execution plan is not stored in the graph as a value, so the only truthful
// answer available to a reader is this invariant.
//
// Phase 3.5 established the reachability policy on exactly that reading (ADR
// 0034 section 4). These tests exist so that the reading cannot quietly stop
// being true — a chain change that dropped the SKIPPED TLS node would leave the
// policy silently interpreting a TLS-required sweep as a plaintext one, which
// is the failure mode of a diagnostic tool reporting a passing endpoint that no
// client can use.
//
// They assert transport's own behaviour and add nothing to it.

// tlsChildren returns the TLS nodes recorded under one TCP node.
func tlsChildren(t *testing.T, graph domain.Graph, tcpNode domain.EvidenceID) []domain.Evidence {
	t.Helper()

	var out []domain.Evidence
	for _, child := range graph.Children(tcpNode) {
		evidence, ok := graph.Node(child)
		if !ok {
			t.Fatalf("child %s of %s is not in the graph", child, tcpNode)
		}
		if evidence.Step() == tlsprobe.StepHandshake {
			out = append(out, evidence)
		}
	}
	return out
}

// tcpNodes returns every TCP node in the graph.
func tcpNodes(graph domain.Graph) []domain.Evidence {
	var out []domain.Evidence
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() == domain.LayerTCP {
			out = append(out, evidence)
		}
	}
	return out
}

// TestPlaintextPlanMintsNoTLSNode covers both TCP outcomes: a plan that asked
// for no TLS produces no TLS node whether the connection succeeded or failed.
//
// The failing case is the one that matters. It is the branch a reader could
// otherwise confuse with a TLS-required sweep whose handshake never ran.
func TestPlaintextPlanMintsNoTLSNode(t *testing.T) {
	dialer := newScriptedDialer(t, "10.0.0.2")
	params := tcpParams(resolving(t, "10.0.0.1", "10.0.0.2"), dialer)

	_, graph := run(t, params)

	connections := tcpNodes(graph)
	if len(connections) != 2 {
		t.Fatalf("tcp nodes = %d, want 2", len(connections))
	}

	states := map[domain.State]int{}
	for _, connection := range connections {
		states[connection.State()]++
		if children := tlsChildren(t, graph, connection.ID()); len(children) != 0 {
			t.Errorf("%s (%s) has TLS children %v; a plaintext plan mints none",
				connection.ID(), connection.State(), children)
		}
	}
	if states[domain.StatePass] != 1 || states[domain.StateFail] != 1 {
		t.Fatalf("states = %v, want one PASS and one FAIL so both branches are covered", states)
	}
}

// TestTLSPlanMintsATLSNodeUnderEveryTCPNode is the other half of the
// biconditional, and the branch that carries it is the failing one: a refused
// connection still records the handshake that was required and did not happen.
func TestTLSPlanMintsATLSNodeUnderEveryTCPNode(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{
		target: peer.addr,
		refuse: map[string]bool{"10.0.0.2": true},
	}

	params := Params{
		Host:     testHost,
		Port:     testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2"),
		Dialer:   dialer,
		TLS:      &TLSOptions{RootCAs: peer.pool},
	}
	_, graph := run(t, params)

	connections := tcpNodes(graph)
	if len(connections) != 2 {
		t.Fatalf("tcp nodes = %d, want 2", len(connections))
	}

	sawSkipped, sawPass := false, false
	for _, connection := range connections {
		children := tlsChildren(t, graph, connection.ID())
		if len(children) != 1 {
			t.Fatalf("%s (%s) has %d TLS children, want exactly 1: a required handshake is "+
				"recorded even when it could not run", connection.ID(), connection.State(), len(children))
		}

		handshake := children[0]
		switch connection.State() {
		case domain.StatePass:
			sawPass = true
			if handshake.State() != domain.StatePass {
				t.Errorf("%s: tls state = %s, want PASS", handshake.ID(), handshake.State())
			}
		case domain.StateFail:
			sawSkipped = true
			if handshake.State() != domain.StateSkipped {
				t.Errorf("%s: tls state = %s, want SKIPPED", handshake.ID(), handshake.State())
			}
			if handshake.FailureClass() != domain.FailureExecSkippedPrerequisiteFailed {
				t.Errorf("%s: failure = %s, want EXEC_SKIPPED_PREREQUISITE_FAILED",
					handshake.ID(), handshake.FailureClass())
			}
			// The blocker is what actually owns the failure. Diagnosis follows
			// this edge rather than counting the SKIPPED node as a second cause.
			blockers := graph.BlockedBy(handshake.ID())
			if len(blockers) != 1 || blockers[0] != connection.ID() {
				t.Errorf("%s: blockedBy = %v, want the TCP node %s",
					handshake.ID(), blockers, connection.ID())
			}
		}
	}
	if !sawPass || !sawSkipped {
		t.Fatalf("both branches must be covered: pass=%v skipped=%v", sawPass, sawSkipped)
	}
}

// TestASweepWithNoAddressesRecordsNeitherLayer states the one case where the
// invariant says nothing, so that its boundary is known rather than assumed.
//
// A lookup that produced no address mints no TCP node, and therefore no TLS
// node, whatever the plan asked for. The terminal layer of such a sweep is not
// observable — and it does not need to be: nothing was reachable at L1, so no
// reader has to know what L3 would have required. ADR 0034 section 4 records the
// gap and why it is immaterial.
func TestASweepWithNoAddressesRecordsNeitherLayer(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})

	params := Params{
		Host:     testHost,
		Port:     testPort,
		Resolver: resolving(t),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	}
	_, graph := run(t, params)

	lookup := node(t, graph, "dns.lookup/"+testHost)
	if lookup.State() != domain.StateFail {
		t.Errorf("dns state = %s, want FAIL", lookup.State())
	}
	if got := len(tcpNodes(graph)); got != 0 {
		t.Errorf("tcp nodes = %d, want 0", got)
	}
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() == domain.LayerTLS {
			t.Errorf("%s exists; a sweep that resolved nothing records no TLS node", evidence.ID())
		}
	}
}
