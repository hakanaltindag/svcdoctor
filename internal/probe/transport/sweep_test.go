package transport

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	dnsprobe "github.com/hakanaltindag/svcdoctor/internal/probe/dns"
)

// These tests cover the reason this phase exists: a run may legitimately measure
// one hostname more than once, and until now the second measurement could not be
// recorded at all.

func scope(t *testing.T, label string) probe.SweepScope {
	t.Helper()

	s, err := probe.NewSweepScope(label)
	if err != nil {
		t.Fatalf("NewSweepScope(%q): %v", label, err)
	}
	return s
}

// --- the blocker, and its removal -------------------------------------------

// TestUnscopedSweepsOfOneHostStillCollide preserves the existing semantics.
//
// Two unscoped sweeps really do describe the same measurement, so the graph is
// right to reject the second. This phase does not weaken that; it gives a caller
// a way to say the two measurements are different.
func TestUnscopedSweepsOfOneHostStillCollide(t *testing.T) {
	builder := domain.NewGraphBuilder()
	params := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))

	first, err := Run(context.Background(), builder, params)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := Run(context.Background(), builder, params)
	if second != nil {
		defer func() { _ = second.Close() }()
	}
	if err == nil {
		t.Fatal("a second unscoped sweep of one host was accepted")
	}
	if !errors.Is(err, domain.ErrInvalidGraph) {
		t.Errorf("error = %v, want one wrapping ErrInvalidGraph", err)
	}
}

// TestTwoScopedSweepsOfOneHostCoexist is the blocker removed.
//
// This is the Phase 3.4 case: a bootstrap sweep resolves a name, and a later
// topology sweep resolves it again because the cluster advertised it.
func TestTwoScopedSweepsOfOneHostCoexist(t *testing.T) {
	builder := domain.NewGraphBuilder()

	bootstrap := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))

	topology := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))
	topology.Scope = scope(t, "topology")

	first, err := Run(context.Background(), builder, bootstrap)
	if err != nil {
		t.Fatalf("bootstrap sweep: %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := Run(context.Background(), builder, topology)
	if err != nil {
		t.Fatalf("topology sweep: %v", err)
	}
	defer func() { _ = second.Close() }()

	graph := freeze(t, builder)

	// Both lookups are present, and the unscoped one kept its historical form.
	node(t, graph, "dns.lookup/primary.internal")
	node(t, graph, "dns.lookup/topology/primary.internal")

	lookups := 0
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == dnsprobe.StepLookup {
			lookups++
		}
	}
	if lookups != 2 {
		t.Errorf("dns nodes = %d, want 2", lookups)
	}
}

// TestSameScopeTwiceStillCollides: a scope distinguishes sweeps, and repeating
// one is repeating the same sweep.
func TestSameScopeTwiceStillCollides(t *testing.T) {
	builder := domain.NewGraphBuilder()
	params := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))
	params.Scope = scope(t, "topology")

	first, err := Run(context.Background(), builder, params)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	defer func() { _ = first.Close() }()

	second, err := Run(context.Background(), builder, params)
	if second != nil {
		defer func() { _ = second.Close() }()
	}
	if err == nil {
		t.Fatal("the same scope was accepted twice for one host")
	}
}

// --- propagation ------------------------------------------------------------

// TestScopePropagatesThroughEveryLayer: one sweep, one scope. No probe invents
// its own, and none is left unscoped.
func TestScopePropagatesThroughEveryLayer(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
		Scope:    scope(t, "topology"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	graph := freeze(t, builder)

	node(t, graph, "dns.lookup/topology/primary.internal")
	node(t, graph, "tcp.connect/topology/primary.internal:9092/10.0.0.1")
	node(t, graph, "tls.handshake/topology/primary.internal:9092/10.0.0.1")

	for _, evidence := range graph.Nodes() {
		if !strings.Contains(evidence.ID().String(), "/topology/") {
			t.Errorf("%s is not scoped; a sweep must scope every layer it produces", evidence.ID())
		}
	}
}

// TestScopeAlsoReachesSkippedNodes: a TLS node that never ran belongs to the
// sweep that would have run it.
func TestScopeAlsoReachesSkippedNodes(t *testing.T) {
	builder := domain.NewGraphBuilder()
	dialer := newScriptedDialer(t, "10.0.0.1")

	result, err := Run(context.Background(), builder, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   dialer,
		TLS:      &TLSOptions{},
		Scope:    scope(t, "topology"),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	graph := freeze(t, builder)
	skipped := node(t, graph, "tls.handshake/topology/primary.internal:9092/10.0.0.1")
	if skipped.State() != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", skipped.State())
	}
}

// TestDifferentScopesProduceFullyDistinctChains: nothing is shared between two
// sweeps of one endpoint — not the lookup, not the connect, not the handshake.
func TestDifferentScopesProduceFullyDistinctChains(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	builder := domain.NewGraphBuilder()

	for _, label := range []string{"bootstrap", "topology"} {
		result, err := Run(context.Background(), builder, Params{
			Host: testHost, Port: testPort,
			Resolver: resolving(t, "10.0.0.1"),
			Dialer:   &loopbackDialer{target: peer.addr},
			TLS:      &TLSOptions{RootCAs: peer.pool},
			Scope:    scope(t, label),
		})
		if err != nil {
			t.Fatalf("%s sweep: %v", label, err)
		}
		defer func() { _ = result.Close() }()
	}

	graph := freeze(t, builder)
	if got := graph.Len(); got != 6 {
		t.Errorf("graph holds %d nodes, want 6: two complete three-layer chains", got)
	}

	seen := map[domain.EvidenceID]struct{}{}
	for _, evidence := range graph.Nodes() {
		if _, duplicate := seen[evidence.ID()]; duplicate {
			t.Fatalf("identifier %s appears twice", evidence.ID())
		}
		seen[evidence.ID()] = struct{}{}
	}
}

// --- what a scope must never touch ------------------------------------------

// TestScopeReachesNeitherSubjectNorAttributes is the containment guarantee.
//
// A scope names an execution. What was observed is unchanged by who asked, so
// the scope belongs in the identifier and nowhere else. If it leaked into a
// subject, two measurements of one host would start describing two hosts.
func TestScopeReachesNeitherSubjectNorAttributes(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	builder := domain.NewGraphBuilder()

	const label = "sweep-canary-9f3a"
	result, err := Run(context.Background(), builder, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1"),
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
		Scope:    scope(t, label),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	for _, evidence := range freeze(t, builder).Nodes() {
		if strings.Contains(evidence.Subject().Ref(), label) {
			t.Errorf("%s: the scope reached the subject %q", evidence.ID(), evidence.Subject().Ref())
		}
		for key, value := range evidence.Attributes() {
			if strings.Contains(key.String(), label) {
				t.Errorf("%s: the scope reached attribute key %s", evidence.ID(), key)
			}
			if strings.Contains(renderAttr(value), label) {
				t.Errorf("%s: the scope reached attribute %s", evidence.ID(), key)
			}
		}
	}
}

// renderAttr flattens an attribute value for substring searching.
func renderAttr(v domain.AttrValue) string {
	if s, ok := v.Str(); ok {
		return s
	}
	if h, ok := v.Host(); ok {
		return h
	}
	if list, ok := v.StringList(); ok {
		return strings.Join(list, ",")
	}
	if list, ok := v.HostList(); ok {
		return strings.Join(list, ",")
	}
	return ""
}

// --- the derivation parent --------------------------------------------------

// TestSweepWithoutParentIsStillARoot preserves the existing graph shape.
func TestSweepWithoutParentIsStillARoot(t *testing.T) {
	builder := domain.NewGraphBuilder()
	result, err := Run(context.Background(), builder,
		tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	graph := freeze(t, builder)
	lookup := node(t, graph, "dns.lookup/primary.internal")
	if parents := graph.Parents(lookup.ID()); len(parents) != 0 {
		t.Errorf("parents = %v, want none: an unparented sweep is a root", parents)
	}
}

// TestSweepDerivesFromItsCause covers the Phase 3.4 shape: a measurement that
// exists because an earlier observation caused it.
func TestSweepDerivesFromItsCause(t *testing.T) {
	builder := domain.NewGraphBuilder()

	// A prior sweep, standing in for whatever caused the second one.
	cause, err := Run(context.Background(), builder,
		tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	defer func() { _ = cause.Close() }()

	causeID := domain.EvidenceID("tcp.connect/primary.internal:9092/10.0.0.1")
	node(t, freeze(t, builder), causeID.String())

	derived := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))
	derived.Scope = scope(t, "topology")
	derived.Parent = causeID

	second, err := Run(context.Background(), builder, derived)
	if err != nil {
		t.Fatalf("derived sweep: %v", err)
	}
	defer func() { _ = second.Close() }()

	graph := freeze(t, builder)

	lookupID := domain.EvidenceID("dns.lookup/topology/primary.internal")
	parents := graph.Parents(lookupID)
	if len(parents) != 1 || parents[0] != causeID {
		t.Fatalf("lookup parents = %v, want exactly %s", parents, causeID)
	}

	// The chain below the lookup is unchanged: TCP still derives from DNS.
	tcpID := domain.EvidenceID("tcp.connect/topology/primary.internal:9092/10.0.0.1")
	tcpParents := graph.Parents(tcpID)
	if len(tcpParents) != 1 || tcpParents[0] != lookupID {
		t.Errorf("tcp parents = %v, want the scoped lookup %s", tcpParents, lookupID)
	}
}

// TestAbsentParentIsAnInvocationError, not fabricated evidence.
//
// A parent that is not in the graph means the caller wired something wrong. The
// run stops and says so; it does not invent a node to hang the edge on.
func TestAbsentParentIsAnInvocationError(t *testing.T) {
	builder := domain.NewGraphBuilder()

	params := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))
	params.Parent = domain.EvidenceID("kafka.broker_advertised/nowhere")

	result, err := Run(context.Background(), builder, params)
	if result != nil {
		defer func() { _ = result.Close() }()
	}
	if err == nil {
		t.Fatal("a sweep derived from an absent node was accepted")
	}
	if !errors.Is(err, domain.ErrInvalidGraph) {
		t.Errorf("error = %v, want one wrapping ErrInvalidGraph", err)
	}

	// No synthetic node was created to satisfy the edge.
	graph := freeze(t, builder)
	if _, ok := graph.Node(params.Parent); ok {
		t.Error("the absent parent was fabricated into the graph")
	}
}

// TestParentDoesNotImplyProvenance states what the edge means, and what it does
// not.
//
// It records derivation: this measurement exists because that node did. It says
// nothing about how the subject entered the run, and no attribute claims
// otherwise. REPORT_SCHEMA.md forbids reading provenance out of graph shape, and
// this field does not change that.
func TestParentDoesNotImplyProvenance(t *testing.T) {
	builder := domain.NewGraphBuilder()

	cause, err := Run(context.Background(), builder,
		tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	defer func() { _ = cause.Close() }()

	derived := tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t))
	derived.Scope = scope(t, "topology")
	derived.Parent = domain.EvidenceID("dns.lookup/primary.internal")

	second, err := Run(context.Background(), builder, derived)
	if err != nil {
		t.Fatalf("derived sweep: %v", err)
	}
	defer func() { _ = second.Close() }()

	for _, evidence := range freeze(t, builder).Nodes() {
		for key := range evidence.Attributes() {
			switch key {
			case "origin", "sweep", "sweep.scope", "transport.origin", "discovered":
				t.Errorf("%s records %s: a scope is not provenance", evidence.ID(), key)
			}
		}
	}
}
