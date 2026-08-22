package kafka

import (
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The ADR 0042 ownership boundary, measured against a real Kafka graph.
//
// # Why this test lives here
//
// ADR 0042 draws the line between generic requested-target transport and
// service-discovered transport at *direct* parentage of a sweep root. The case
// that forced that shape is Kafka's: an advertised sweep is a **transitive
// descendant** of the bootstrap target, so a rule owning "every transport node
// below the anchor" would diagnose a discovered broker and duplicate
// KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE.
//
// That hazard cannot be reproduced in a PostgreSQL graph, which is only four
// levels deep. It needs the real chain — bootstrap transport, ApiVersions, SASL,
// Metadata, an advertisement and the sweep derived from it — and this package is
// where that chain is actually produced.
//
// # What is real and what is simulated, stated honestly
//
// Everything except one edge is real: the bootstrap sweep, the protocol
// exchanges, the advertisement and the advertised sweep are all produced by
// production code from a real peer.
//
// **Kafka has no composition root**, so nothing in production yet mints a
// requested-target anchor for a bootstrap run. These tests add that one node and
// the one edge a future composition root would add — exactly what
// internal/app does for PostgreSQL today — and assert the boundary holds around
// real evidence. When Kafka composition lands, the simulation should be deleted
// and these assertions pointed at the production graph.
//
// # Why the walk is duplicated in a test rather than shared
//
// The identical traversal appears in internal/app's ownership test. Sharing it
// would mean shipping it as production code, and the traversal *is* the future
// rule's core — which ADR 0042 does not authorize and Phase 4.9a has not yet
// specified. Twenty duplicated lines in two test files is the cheaper mistake.

// anchorFor mints the node a future Kafka composition root would mint, and
// parents the bootstrap sweep to it.
//
// It reproduces exactly what internal/app.recordRequestedTarget does: L0,
// SubjectKindTarget, PASS, no attributes, no parent.
func anchorFor(
	t *testing.T, builder *domain.GraphBuilder, endpoint string, bootstrapLookup domain.EvidenceID,
) domain.EvidenceID {
	t.Helper()

	subject, err := domain.NewTargetSubject(endpoint)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           probe.EvidenceID(vocabulary.StepTargetRequested, endpoint),
		Subject:      subject,
		Layer:        domain.LayerInput,
		Step:         vocabulary.StepTargetRequested,
		State:        domain.StatePass,
		FailureClass: domain.FailureNone,
		StartedAt:    time.Now(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	if err := builder.AddParent(bootstrapLookup, evidence.ID()); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	return evidence.ID()
}

// requestedSweep is the traversal ADR 0042 section 7 authorizes.
//
// From an anchor: direct children that are lookups, their direct children that
// are connects, their direct children that are handshakes. Three levels, typed by
// step, and it stops. It never asks what a node is about and never reads an
// identifier.
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

// everyDescendant is the naive rule ADR 0042 rejected, kept so the test can show
// that the hazard is real rather than hypothetical.
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

// idsWithStep returns every node of one step, by graph API only.
func idsWithStep(g domain.Graph, step domain.Step) []domain.EvidenceID {
	var out []domain.EvidenceID
	for _, n := range g.Nodes() {
		if n.Step() == step {
			out = append(out, n.ID())
		}
	}
	return out
}

// TestAnAdvertisedSweepIsTransitivelyBelowTheTargetButNotOwnedByIt is the
// central ADR 0042 assertion.
//
// Both halves matter. The first shows the naive rule would capture a discovered
// broker's transport, which is the duplication ADR 0034 resolved. The second
// shows the authorized traversal does not.
func TestAnAdvertisedSweepIsTransitivelyBelowTheTargetButNotOwnedByIt(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(peer)
	_ = measure(t, target, tcpPlan(resolver, dialer))

	bootstrapLookup := probe.EvidenceID(vocabulary.StepDNSLookup, "primary.internal")
	anchor := anchorFor(t, target.builder, "primary.internal:9092", bootstrapLookup)
	graph := freeze(t, target.builder)

	broker := brokerByNode(t, target, 1, "broker-1.internal")
	advertisedLookup := domain.EvidenceID(scopedLookupID(t, broker))
	advertisedConnect := domain.EvidenceID(scopedConnectID(t, broker, "10.20.0.1"))

	// The hazard is real: the advertised sweep IS below the anchor.
	descendants := everyDescendant(graph, anchor)
	if !descendants[advertisedLookup] {
		t.Fatal("the advertised lookup is not a descendant of the target; this test no " +
			"longer measures the case it was written for")
	}
	if !descendants[advertisedConnect] {
		t.Fatal("the advertised connect is not a descendant of the target")
	}

	// The authorized traversal excludes it.
	owned := requestedSweep(graph, anchor)
	if owned[advertisedLookup] {
		t.Error("the advertised lookup is owned by requested-target transport; " +
			"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE owns that evidence (ADR 0034 section 3)")
	}
	if owned[advertisedConnect] {
		t.Error("the advertised connect is owned by requested-target transport")
	}

	// And it still owns the bootstrap sweep, which is the point of existing.
	if !owned[bootstrapLookup] {
		t.Error("the bootstrap lookup is not owned; the anchor bought nothing")
	}
	if !owned[probe.EvidenceID(vocabulary.StepTCPConnect, "primary.internal:9092", "10.0.0.1")] {
		t.Error("the bootstrap connect is not owned")
	}
	if !owned[probe.EvidenceID(vocabulary.StepTLSHandshake, "primary.internal:9092", "10.0.0.1")] {
		t.Error("the bootstrap handshake is not owned")
	}
}

// TestAnAdvertisedSweepRootParentsToItsAdvertisement is the invariant that makes
// the boundary structural rather than conventional.
//
// The advertised lookup does not merely happen to sit elsewhere: it is parented
// to the advertisement that caused it, by production code that has no access to
// any anchor identifier. MeasureAdvertised derives the parent from the
// advertisement it is iterating, so this package could not mis-parent a sweep to
// a target even if it tried.
func TestAnAdvertisedSweepRootParentsToItsAdvertisement(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	_ = measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	graph := freeze(t, target.builder)

	for _, advertised := range []struct {
		nodeID int32
		host   string
	}{{1, "broker-1.internal"}, {2, "broker-2.internal"}} {
		broker := brokerByNode(t, target, advertised.nodeID, advertised.host)
		lookup := domain.EvidenceID(scopedLookupID(t, broker))

		parents := graph.Parents(lookup)
		if len(parents) != 1 {
			t.Fatalf("advertised lookup %s has %d parents, want 1", lookup, len(parents))
		}
		parent, ok := graph.Node(parents[0])
		if !ok {
			t.Fatalf("parent %s is not in the graph", parents[0])
		}
		if parent.Step() != servicekafka.StepBrokerAdvertised {
			t.Errorf("advertised lookup parents to step %s, want %s",
				parent.Step(), servicekafka.StepBrokerAdvertised)
		}
	}
}

// TestNoAdvertisedSweepIsEverAGraphRoot pins why rootness was rejected as a
// discriminator.
//
// ADR 0042 could have said "a sweep with no parent is the requested one". It
// does not, because that is provenance read off graph shape and because nothing
// enforces it. This asserts the stronger, enforceable property the record chose
// instead: a discovered sweep always declares its cause.
func TestNoAdvertisedSweepIsEverAGraphRoot(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	_ = measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	graph := freeze(t, target.builder)
	broker := brokerByNode(t, target, 1, "broker-1.internal")

	if parents := graph.Parents(domain.EvidenceID(scopedLookupID(t, broker))); len(parents) == 0 {
		t.Error("an advertised sweep is a graph root; it must declare its cause")
	}
}

// TestKafkaMintsNoRequestedTargetAnchor records the limitation this file works
// around, so that it is visible rather than implied.
//
// Kafka has no composition root. Nothing in production mints an anchor for a
// bootstrap run, which is why the tests above add one themselves. If this ever
// fails, Kafka composition has landed and the simulation should be replaced by
// the real graph.
func TestKafkaMintsNoRequestedTargetAnchor(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	_ = measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	graph := freeze(t, target.builder)
	if found := idsWithStep(graph, vocabulary.StepTargetRequested); len(found) != 0 {
		t.Errorf("Kafka produced %v; a composition root now exists and these tests "+
			"should measure it instead of simulating one", found)
	}
}

// TestAKafkaBootstrapSweepWouldBeDiagnosableAndAnAdvertisedOneWouldNot is the
// forward-compatibility assertion for ADR 0043.
//
// Kafka has no composition root, so no generic finding can be produced for a
// bootstrap run today. What can be checked now is the property those rules will
// depend on when it exists: that the bootstrap sweep and the advertised sweep are
// distinguishable by the same structural test, on a real graph, with no service
// knowledge involved.
//
// The test states it as the rules do — direct parentage of the sweep root — and
// deliberately does not import internal/diagnosis/transport. Diagnosis may not
// import an adapter, and an adapter test reaching for a rule would invert the
// dependency the boundary exists to keep.
func TestAKafkaBootstrapSweepWouldBeDiagnosableAndAnAdvertisedOneWouldNot(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	_ = measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	bootstrapLookup := probe.EvidenceID(vocabulary.StepDNSLookup, "primary.internal")
	anchor := anchorFor(t, target.builder, "primary.internal:9092", bootstrapLookup)
	graph := freeze(t, target.builder)

	// The rules' ownership test, written out: a sweep is the operator's exactly
	// when its DNS root is a direct child of a requested-target anchor.
	ownedBy := func(lookup domain.EvidenceID) bool {
		for _, id := range graph.Children(anchor) {
			if id == lookup {
				node, ok := graph.Node(id)
				return ok && node.Step() == vocabulary.StepDNSLookup
			}
		}
		return false
	}

	if !ownedBy(bootstrapLookup) {
		t.Error("the bootstrap sweep is not owned by the requested target; once Kafka " +
			"composition exists, generic DNS/TCP diagnosis would say nothing about it")
	}

	broker := brokerByNode(t, target, 1, "broker-1.internal")
	advertisedLookup := domain.EvidenceID(scopedLookupID(t, broker))
	if ownedBy(advertisedLookup) {
		t.Error("the advertised sweep is owned by the requested target; generic diagnosis " +
			"would duplicate KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE")
	}

	// And the bootstrap sweep has the shape the rules descend through, so the
	// ownership test is not passing on an empty subtree.
	connects := 0
	for _, id := range graph.Children(bootstrapLookup) {
		if node, ok := graph.Node(id); ok && node.Step() == vocabulary.StepTCPConnect {
			connects++
		}
	}
	if connects == 0 {
		t.Error("the bootstrap sweep has no connection nodes; the assertion is vacuous")
	}
}
