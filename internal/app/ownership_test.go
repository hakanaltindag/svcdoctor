package app

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The ADR 0042 ownership boundary, measured on a real PostgreSQL run.
//
// The Kafka half of this boundary lives in internal/adapter/kafka, where the
// deep chain that forces it is actually produced. This half covers the case that
// is PostgreSQL's alone: a `tls.handshake` node that carries the generic step
// name while belonging to the service, because PostgreSQL negotiates encryption
// in band.
//
// The traversal below is duplicated from that file on purpose. Sharing it would
// mean shipping it as production code, and the traversal is the future rule's
// core — which ADR 0042 does not authorize.

// requestedSweep is the traversal ADR 0042 section 7 authorizes: from an anchor,
// direct lookup children, their direct connect children, their direct handshake
// children, and stop.
func requestedSweep(g domain.Graph, anchor domain.EvidenceID) map[domain.EvidenceID]bool {
	owned := map[domain.EvidenceID]bool{}

	descend := func(from domain.EvidenceID, step domain.Step) []domain.EvidenceID {
		var out []domain.EvidenceID
		for _, id := range g.Children(from) {
			if n, ok := g.Node(id); ok && n.Step() == step {
				owned[id] = true
				out = append(out, id)
			}
		}
		return out
	}

	for _, lookup := range descend(anchor, vocabulary.StepDNSLookup) {
		for _, connect := range descend(lookup, vocabulary.StepTCPConnect) {
			descend(connect, vocabulary.StepTLSHandshake)
		}
	}
	return owned
}

// everyDescendant is the naive rule ADR 0042 rejected.
func everyDescendant(g domain.Graph, from domain.EvidenceID) map[domain.EvidenceID]bool {
	seen := map[domain.EvidenceID]bool{}
	var walk func(domain.EvidenceID)
	walk = func(id domain.EvidenceID) {
		for _, child := range g.Children(id) {
			if seen[child] {
				continue
			}
			seen[child] = true
			walk(child)
		}
	}
	walk(from)
	return seen
}

// TestPostgresInBandTLSIsNotRequestedTargetTransport is the PostgreSQL half of
// the ownership boundary.
//
// A `tls.handshake` node produced after `postgres.ssl_request` carries the same
// step name as a generic transport handshake and is not one. The adapter parents
// it to the negotiation rather than to TCP — deliberately, so that "PostgreSQL
// asked for the upgrade" is not lost — and that edge is what keeps it
// service-owned.
//
// This is why ADR 0042 rejected bounding the walk by *layer*: postgres.ssl_request
// is at L3, so an L0-to-L3 descent would have swallowed it.
func TestPostgresInBandTLSIsNotRequestedTargetTransport(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1", "2001:db8::1")}, speakingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)

	handshakes := nodesWithStep(graph, vocabulary.StepTLSHandshake)
	if len(handshakes) == 0 {
		t.Fatal("no tls.handshake node was produced; this test no longer measures " +
			"the case it was written for")
	}

	descendants := everyDescendant(graph, anchor.ID())
	owned := requestedSweep(graph, anchor.ID())

	for _, h := range handshakes {
		// The hazard: it *is* below the anchor.
		if !descendants[h.ID()] {
			t.Fatalf("%s is not a descendant of the anchor; the shape changed", h.ID())
		}
		// The boundary: it is not owned.
		if owned[h.ID()] {
			t.Errorf("%s is owned by requested-target transport; PostgreSQL's in-band "+
				"handshake belongs to the service (ADR 0042 section 7)", h.ID())
		}
		// And the reason, asserted rather than assumed.
		parents := graph.Parents(h.ID())
		if len(parents) != 1 {
			t.Fatalf("%s has %d parents, want 1", h.ID(), len(parents))
		}
		parent, ok := graph.Node(parents[0])
		if !ok {
			t.Fatalf("parent %s is not in the graph", parents[0])
		}
		if parent.Step() != servicepostgres.StepSSLRequest {
			t.Errorf("%s parents to step %s, want %s", h.ID(), parent.Step(),
				servicepostgres.StepSSLRequest)
		}
	}
}

// TestTheRequestedSweepOwnsExactlyTheTransportChain pins both directions of the
// boundary on one graph.
//
// Under-owning is as much a defect as over-owning: an anchor that bought no
// transport evidence would be ceremony.
func TestTheRequestedSweepOwnsExactlyTheTransportChain(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1", "2001:db8::1")}, speakingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)
	owned := requestedSweep(graph, anchor.ID())

	// Owned: the lookup and both connects.
	for _, step := range []domain.Step{vocabulary.StepDNSLookup, vocabulary.StepTCPConnect} {
		for _, n := range nodesWithStep(graph, step) {
			if !owned[n.ID()] {
				t.Errorf("%s (%s) is not owned; it is requested-target transport", n.ID(), step)
			}
		}
	}

	// Not owned: everything a service produced.
	for _, n := range graph.Nodes() {
		switch n.Step() {
		case vocabulary.StepDNSLookup, vocabulary.StepTCPConnect:
			continue
		case vocabulary.StepTargetRequested:
			if owned[n.ID()] {
				t.Error("the anchor owns itself; the walk starts at it, it is not in it")
			}
		default:
			if owned[n.ID()] {
				t.Errorf("%s (%s) is owned by requested-target transport; only the "+
					"transport chain is", n.ID(), n.Step())
			}
		}
	}

	if got, want := len(owned), 3; got != want {
		t.Errorf("owned %d nodes, want %d (one lookup, two connects)", got, want)
	}
}

// TestOwnershipUsesNoIdentifierText is the mechanical half of "no EvidenceID
// parsing".
//
// The traversal above reads Children, Node and Step. It never inspects the text
// of an identifier, and the proof is that renaming every identifier in the graph
// would not change its answer. That cannot be asserted directly, so this asserts
// the property it rests on: ownership is decided entirely by edges and steps,
// both of which are typed values rather than substrings.
func TestOwnershipUsesNoIdentifierText(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, speakingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)
	owned := requestedSweep(graph, anchor.ID())

	// Every owned node is reachable from the anchor by a typed edge walk, and
	// every one carries a transport step. If ownership depended on identifier
	// text, a node could be owned without either being true.
	for id := range owned {
		n, ok := graph.Node(id)
		if !ok {
			t.Fatalf("owned node %s is not in the graph", id)
		}
		switch n.Step() {
		case vocabulary.StepDNSLookup, vocabulary.StepTCPConnect, vocabulary.StepTLSHandshake:
		default:
			t.Errorf("%s has step %s; the walk is typed by step and cannot own it",
				id, n.Step())
		}
	}
}
