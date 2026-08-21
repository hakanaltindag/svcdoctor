package kafka

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// These tests cover what Phase 3.4 measures: one scoped transport sweep per
// advertisement, derived from the advertisement that caused it.
//
// The cases that look redundant are the point of the phase. Two advertisements
// naming one endpoint, one node identifier at two endpoints, two hostnames at
// one address — each stays two measurements, because measurement identity is not
// subject identity. See ADR 0033.

// --- one advertised endpoint ------------------------------------------------

// TestOneAdvertisedHostnameIsMeasured is the simple case, end to end.
func TestOneAdvertisedHostnameIsMeasured(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))

	if result.Considered() != 1 || result.Measured() != 1 {
		t.Fatalf("considered = %d, measured = %d, want 1 and 1",
			result.Considered(), result.Measured())
	}

	broker := brokerByNode(t, target, 1, "broker-1.internal")
	graph := freeze(t, target.builder)

	lookup := node(t, graph, scopedLookupID(t, broker))
	if lookup.State() != domain.StatePass {
		t.Errorf("dns state = %s, want PASS", lookup.State())
	}
	connect := node(t, graph, scopedConnectID(t, broker, "10.20.0.1"))
	if connect.State() != domain.StatePass {
		t.Errorf("tcp state = %s, want PASS", connect.State())
	}
}

// TestMultipleAdvertisedEndpointsEachGetASweep: three brokers, three sweeps.
func TestMultipleAdvertisedEndpointsEachGetASweep(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(3, "broker-3.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2").
		resolving(t, "broker-3.internal", "10.20.0.3")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 3 {
		t.Fatalf("measured = %d, want 3", result.Measured())
	}

	graph := freeze(t, target.builder)
	// Three scoped lookups, plus the bootstrap sweep's unscoped one.
	if got := len(nodesWithStep(graph, "dns.lookup")); got != 4 {
		t.Errorf("dns nodes = %d, want 4 (three advertised, one bootstrap)", got)
	}
	if got := len(dialer.attempts()); got != 3 {
		t.Errorf("dial attempts = %d, want 3", got)
	}
}

// --- the cases that must not be deduplicated --------------------------------

// TestBootstrapEndpointAdvertisedBackIsMeasuredAgain is the case ADR 0032 was
// written for, arriving in production for the first time.
//
// A single-listener cluster advertises the host the operator typed. The
// bootstrap sweep measured it before authentication; this phase measures it
// again, for a different reason and at a different moment. Both measurements are
// true, so both are in the graph — the second neither reuses nor overwrites the
// first.
func TestBootstrapEndpointAdvertisedBackIsMeasuredAgain(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, authHost, 9092))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, authHost, authAddress)
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 1 {
		t.Fatalf("measured = %d, want 1: the bootstrap endpoint must be measured again",
			result.Measured())
	}

	broker := brokerByNode(t, target, 1, authHost)
	graph := freeze(t, target.builder)

	// The bootstrap nodes are untouched, in their historical unscoped form.
	bootstrapLookup := node(t, graph, "dns.lookup/"+authHost)
	node(t, graph, "tcp.connect/"+authEndpoint+"/"+authAddress)

	// And the topology measurement is beside them, scoped and separately parented.
	topologyLookup := node(t, graph, scopedLookupID(t, broker))
	node(t, graph, scopedConnectID(t, broker, authAddress))

	if topologyLookup.ID() == bootstrapLookup.ID() {
		t.Fatal("the two lookups share an identifier; one measurement was lost")
	}
	if topologyLookup.Subject().Ref() != bootstrapLookup.Subject().Ref() {
		t.Errorf("subjects differ (%q vs %q): a scope must not change what was observed",
			topologyLookup.Subject().Ref(), bootstrapLookup.Subject().Ref())
	}

	// The bootstrap lookup is still a root; the topology one derives from the
	// advertisement.
	if parents := graph.Parents(bootstrapLookup.ID()); len(parents) != 0 {
		t.Errorf("the bootstrap lookup gained parents %v", parents)
	}
	parents := graph.Parents(topologyLookup.ID())
	if len(parents) != 1 || parents[0] != broker.Evidence() {
		t.Errorf("topology lookup parents = %v, want the advertisement %s",
			parents, broker.Evidence())
	}
}

// TestSameHostDifferentPortsAreTwoSweeps: one hostname, two listeners.
//
// DNS is therefore repeated for one name under two scopes, which is exactly what
// Phase 3.3b exists to permit. Deduplicating the lookup by hostname would drop a
// real measurement.
func TestSameHostDifferentPortsAreTwoSweeps(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker.internal", 9092),
		advertisedBroker(1, "broker.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2", result.Measured())
	}

	if got := len(resolver.lookups()); got != 2 {
		t.Errorf("lookups = %d, want 2: DNS must not be deduplicated by hostname", got)
	}

	graph := freeze(t, target.builder)
	seen := map[domain.EvidenceID]struct{}{}
	for _, broker := range target.brokers {
		lookup := node(t, graph, scopedLookupID(t, broker))
		if _, duplicate := seen[lookup.ID()]; duplicate {
			t.Fatalf("both advertisements produced %s", lookup.ID())
		}
		seen[lookup.ID()] = struct{}{}

		endpoint, _ := broker.Endpoint()
		connect := node(t, graph, scopedConnectID(t, broker, "10.20.0.1"))
		if !strings.Contains(connect.ID().String(), endpoint) {
			t.Errorf("%s does not name its endpoint %s", connect.ID(), endpoint)
		}
	}
}

// TestSameEndpointFromTwoNodeIDsIsTwoSweeps.
//
// Two node identifiers claiming one address is a misconfiguration that routes
// clients to the wrong broker, and it is precisely the thing somebody runs a
// diagnostic tool to find. Both advertisements are causes, so both are measured:
// nothing here picks the lower node identifier, the first entry, or the
// lexicographically smaller identifier.
func TestSameEndpointFromTwoNodeIDsIsTwoSweeps(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(2, "broker.internal", 9093),
		advertisedBroker(1, "broker.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2: one advertisement must not be dropped", result.Measured())
	}
	if got := len(dialer.attempts()); got != 2 {
		t.Errorf("dial attempts = %d, want 2", got)
	}

	graph := freeze(t, target.builder)
	first := brokerByNode(t, target, 1, "broker.internal")
	second := brokerByNode(t, target, 2, "broker.internal")

	firstLookup := node(t, graph, scopedLookupID(t, first))
	secondLookup := node(t, graph, scopedLookupID(t, second))
	if firstLookup.ID() == secondLookup.ID() {
		t.Fatal("both node identifiers produced one lookup")
	}

	// Each sweep derives from its own advertisement, so neither cause is
	// silently attributed to the other.
	for broker, lookup := range map[domain.EvidenceID]domain.Evidence{
		first.Evidence():  firstLookup,
		second.Evidence(): secondLookup,
	} {
		parents := graph.Parents(lookup.ID())
		if len(parents) != 1 || parents[0] != broker {
			t.Errorf("%s parents = %v, want %s", lookup.ID(), parents, broker)
		}
	}
}

// TestSameNodeIDWithTwoEndpointsIsTwoSweeps: a node identifier is not an
// execution target, so it cannot deduplicate one either.
func TestSameNodeIDWithTwoEndpointsIsTwoSweeps(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-a.internal", 9093),
		advertisedBroker(1, "broker-b.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-a.internal", "10.20.0.1").
		resolving(t, "broker-b.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2", result.Measured())
	}

	graph := freeze(t, target.builder)
	node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "broker-a.internal"), "10.20.0.1"))
	node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "broker-b.internal"), "10.20.0.2"))
}

// TestTwoHostnamesOneAddressStayTwoMeasurements.
//
// A resolved address is not execution identity. The DNS facts differ, the TLS
// identity would differ, the routing intent differs and the advertised endpoints
// differ — collapsing on the address would erase all four to save one dial.
func TestTwoHostnamesOneAddressStayTwoMeasurements(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-a.internal", 9093),
		advertisedBroker(2, "broker-b.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-a.internal", "127.0.0.1").
		resolving(t, "broker-b.internal", "127.0.0.1")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2", result.Measured())
	}
	if got := len(dialer.attempts()); got != 2 {
		t.Errorf("dial attempts = %d, want 2: one address is not one execution", got)
	}

	graph := freeze(t, target.builder)
	first := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "broker-a.internal"), "127.0.0.1"))
	second := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 2, "broker-b.internal"), "127.0.0.1"))
	if first.ID() == second.ID() {
		t.Fatal("one address collapsed two measurements")
	}
	if first.Subject().Ref() != second.Subject().Ref() {
		t.Errorf("subjects differ (%q vs %q): both attempts reached the same address",
			first.Subject().Ref(), second.Subject().Ref())
	}
}

// TestDuplicateAdvertisementsCollapseInPhase33NotHere states the fact-dedup
// boundary: Phase 3.3 decides what a fact is, and this phase runs once per fact.
//
// A byte-identical repetition is one advertisement, so it is one sweep — because
// the layer above collapsed it, not because this one did.
func TestDuplicateAdvertisementsCollapseInPhase33NotHere(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker.internal", 9093),
		advertisedBroker(1, "broker.internal", 9093),
	)
	if got := len(target.brokers); got != 1 {
		t.Fatalf("advertisements = %d, want 1: Phase 3.3 no longer collapses identical entries", got)
	}

	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 1 {
		t.Errorf("measured = %d, want 1 sweep for the 1 fact", result.Measured())
	}
}

// --- ordering and determinism -----------------------------------------------

// TestReversedAdvertisementOrderProducesTheSameNodes: execution order is the
// broker's, and the graph is not.
func TestReversedAdvertisementOrderProducesTheSameNodes(t *testing.T) {
	forward := measuredIdentifiers(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(3, "broker-3.internal", 9093),
	)
	reversed := measuredIdentifiers(t,
		advertisedBroker(3, "broker-3.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(1, "broker-1.internal", 9093),
	)

	if len(forward) != len(reversed) {
		t.Fatalf("identifier counts differ: %v vs %v", forward, reversed)
	}
	for i := range forward {
		if forward[i] != reversed[i] {
			t.Errorf("identifier %d differs: %q vs %q", i, forward[i], reversed[i])
		}
	}
}

// measuredIdentifiers runs a whole topology and returns every transport
// identifier the advertised sweeps produced, in the graph's canonical order.
func measuredIdentifiers(t *testing.T, advertised ...kmsg.MetadataResponseBroker) []string {
	t.Helper()

	target := discoveredTopology(t, advertised...)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2").
		resolving(t, "broker-3.internal", "10.20.0.3")

	measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	var ids []string
	for _, evidence := range freeze(t, target.builder).Nodes() {
		if strings.Contains(evidence.ID().String(), advertisedScopePrefix) {
			ids = append(ids, evidence.ID().String())
		}
	}
	return ids
}

// --- failures do not stop the run -------------------------------------------

// TestDNSFailureDoesNotStopLaterAdvertisements.
func TestDNSFailureDoesNotStopLaterAdvertisements(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "missing.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		failing("missing.internal", &net.DNSError{Err: "no such host", IsNotFound: true}).
		resolving(t, "broker-2.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2: a failure must not end the run", result.Measured())
	}

	graph := freeze(t, target.builder)
	failed := node(t, graph, scopedLookupID(t, brokerByNode(t, target, 1, "missing.internal")))
	if failed.State() != domain.StateFail {
		t.Errorf("dns state = %s, want FAIL", failed.State())
	}
	if failed.FailureClass() != domain.FailureDNSNoAddress {
		t.Errorf("dns failure = %s, want DNS_NO_ADDRESS", failed.FailureClass())
	}

	// The healthy endpoint behind it was still measured, to the layer below.
	node(t, graph, scopedConnectID(t, brokerByNode(t, target, 2, "broker-2.internal"), "10.20.0.2"))
}

// TestTCPRefusalDoesNotStopLaterAdvertisements.
func TestTCPRefusalDoesNotStopLaterAdvertisements(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer, "10.20.0.1")

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2", result.Measured())
	}

	graph := freeze(t, target.builder)
	refused := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "broker-1.internal"), "10.20.0.1"))
	if refused.State() != domain.StateFail {
		t.Errorf("tcp state = %s, want FAIL", refused.State())
	}
	reached := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 2, "broker-2.internal"), "10.20.0.2"))
	if reached.State() != domain.StatePass {
		t.Errorf("tcp state = %s, want PASS", reached.State())
	}
}

// TestTLSVerificationFailureDoesNotStopLaterAdvertisements.
//
// The first advertised host is measured against a certificate that names the
// second, so the handshake genuinely fails verification rather than being made
// to fail by a flag.
func TestTLSVerificationFailureDoesNotStopLaterAdvertisements(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-a.internal", 9093),
		advertisedBroker(2, "broker-b.internal", 9093),
	)
	peer := newAdvertisedTLSPeer(t, "broker-b.internal")
	resolver := newHostResolver().
		resolving(t, "broker-a.internal", "10.20.0.1").
		resolving(t, "broker-b.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tlsPlan(resolver, dialer, peer))
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2", result.Measured())
	}

	graph := freeze(t, target.builder)
	rejected := node(t, graph, scopedHandshakeID(t, brokerByNode(t, target, 1, "broker-a.internal"), "10.20.0.1"))
	if rejected.State() != domain.StateFail {
		t.Errorf("tls state = %s, want FAIL for a certificate naming another host", rejected.State())
	}
	accepted := node(t, graph, scopedHandshakeID(t, brokerByNode(t, target, 2, "broker-b.internal"), "10.20.0.2"))
	if accepted.State() != domain.StatePass {
		t.Errorf("tls state = %s, want PASS", accepted.State())
	}
}

// --- TLS -------------------------------------------------------------------

// TestTLSIsExecutedOnlyWhenThePlanAsksForIt: the plan is the whole mechanism.
func TestTLSIsExecutedOnlyWhenThePlanAsksForIt(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		withTLS bool
	}{
		{"plan asks for TLS", true},
		{"plan does not", false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
			resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")

			var plan TransportPlan
			if testCase.withTLS {
				peer := newAdvertisedTLSPeer(t, "broker-1.internal")
				plan = tlsPlan(resolver, newAdvertisedDialer(peer), peer)
			} else {
				plan = tcpPlan(resolver, newAdvertisedDialer(newAdvertisedPeer(t)))
			}

			measure(t, target, plan)
			graph := freeze(t, target.builder)

			handshakes := len(advertisedNodesWithStep(graph, "tls.handshake"))
			if testCase.withTLS && handshakes != 1 {
				t.Errorf("tls nodes = %d, want 1", handshakes)
			}
			if !testCase.withTLS && handshakes != 0 {
				t.Errorf("tls nodes = %d, want 0: TLS must not be inferred", handshakes)
			}
		})
	}
}

// TestTLSVerifiesTheAdvertisedNameNotTheResolvedAddress.
//
// The advertised host resolves to a loopback address, and the peer's certificate
// names the host. A handshake that used the address as its identity could not
// pass, so a PASS here is the assertion.
func TestTLSVerifiesTheAdvertisedNameNotTheResolvedAddress(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedTLSPeer(t, "broker-1.internal")
	resolver := newHostResolver().resolving(t, "broker-1.internal", "127.0.0.1")
	dialer := newAdvertisedDialer(peer)

	measure(t, target, tlsPlan(resolver, dialer, peer))

	graph := freeze(t, target.builder)
	broker := brokerByNode(t, target, 1, "broker-1.internal")
	handshake := node(t, graph, scopedHandshakeID(t, broker, "127.0.0.1"))
	if handshake.State() != domain.StatePass {
		t.Fatalf("tls state = %s, want PASS: the advertised name must be the verified identity",
			handshake.State())
	}

	verified, ok := handshake.Attribute("tls.verified")
	if !ok {
		t.Fatal("the handshake recorded no verification result")
	}
	if value, _ := verified.Bool(); !value {
		t.Error("tls.verified = false; the advertised hostname was not the identity checked")
	}
}

// --- address families -------------------------------------------------------

// TestIPv4LiteralIsMeasured.
func TestIPv4LiteralIsMeasured(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "10.20.0.7", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "10.20.0.7", "10.20.0.7")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 1 {
		t.Fatalf("measured = %d, want 1", result.Measured())
	}

	graph := freeze(t, target.builder)
	node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "10.20.0.7"), "10.20.0.7"))
}

// TestIPv6LiteralIsMeasured: the advertised endpoint is bracketed, and the
// address component of the identifier is not.
func TestIPv6LiteralIsMeasured(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "2001:db8::7", 9093))
	broker := brokerByNode(t, target, 1, "2001:db8::7")
	if endpoint, _ := broker.Endpoint(); endpoint != "[2001:db8::7]:9093" {
		t.Fatalf("endpoint = %q, want a bracketed IPv6 literal", endpoint)
	}

	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "2001:db8::7", "2001:db8::7")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Measured() != 1 {
		t.Fatalf("measured = %d, want 1", result.Measured())
	}

	graph := freeze(t, target.builder)
	node(t, graph, scopedConnectID(t, broker, "2001:db8::7"))
}

// TestDualStackMeasuresBothFamiliesAndSelectsNeither.
//
// The chain attempts every resolved address, and this phase adds no preference:
// no first-answer shortcut, no family ranking, and no chosen path handed back.
func TestDualStackMeasuresBothFamiliesAndSelectsNeither(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1", "2001:db8::1")
	dialer := newAdvertisedDialer(peer)

	measure(t, target, tcpPlan(resolver, dialer))

	if got := len(dialer.attempts()); got != 2 {
		t.Fatalf("dial attempts = %d, want both families measured", got)
	}

	graph := freeze(t, target.builder)
	broker := brokerByNode(t, target, 1, "broker-1.internal")
	for _, address := range []string{"10.20.0.1", "2001:db8::1"} {
		connect := node(t, graph, scopedConnectID(t, broker, address))
		if connect.State() != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", connect.ID(), connect.State())
		}
	}

	// Both sockets were established and both were released; neither family was
	// promoted to a continuation the caller keeps.
	if got := len(dialer.established()); got != 2 {
		t.Errorf("established = %d, want 2", got)
	}
}

// --- unusable advertisements ------------------------------------------------

// TestUnusableAdvertisementIsSkippedWithoutFabricatedEvidence.
//
// Phase 3.3 already recorded the problem on the advertisement node. There is
// nothing to resolve and nothing to dial, and a SKIPPED transport node would need
// a subject the cluster never advertised.
func TestUnusableAdvertisementIsSkippedWithoutFabricatedEvidence(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "", 9093),
		advertisedBroker(2, "broker-2.internal", 0),
		advertisedBroker(3, "broker-3.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-3.internal", "10.20.0.3")
	dialer := newAdvertisedDialer(peer)

	result := measure(t, target, tcpPlan(resolver, dialer))
	if result.Considered() != 3 {
		t.Errorf("considered = %d, want 3", result.Considered())
	}
	if result.Measured() != 1 {
		t.Fatalf("measured = %d, want 1: only the usable advertisement is executable",
			result.Measured())
	}
	if got := len(resolver.lookups()); got != 1 {
		t.Errorf("lookups = %d, want 1: an unusable advertisement must not be resolved", got)
	}

	graph := freeze(t, target.builder)
	for _, evidence := range graph.Nodes() {
		switch evidence.Layer() {
		case domain.LayerDNS, domain.LayerTCP, domain.LayerTLS:
			if strings.Contains(evidence.ID().String(), "broker-2.internal") {
				t.Errorf("%s: transport evidence was fabricated for an unusable advertisement",
					evidence.ID())
			}
		}
	}
}

// TestNoAdvertisementsIsNotAnError: an empty cluster description is a fact, not
// a defect.
func TestNoAdvertisementsIsNotAnError(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	target.brokers = nil

	result := measure(t, target, tcpPlan(newHostResolver(), newAdvertisedDialer(newAdvertisedPeer(t))))
	if result.Considered() != 0 || result.Measured() != 0 {
		t.Errorf("considered = %d, measured = %d, want 0 and 0",
			result.Considered(), result.Measured())
	}
}

// --- budget -----------------------------------------------------------------

// TestCancellationStopsTheRunAndFabricatesNothing.
//
// A caller's expired budget is svcdoctor's fact, not the cluster's. The
// advertisements the loop never reached receive no evidence at all: a node
// claiming a remote failure would be exactly the false positive the claim
// discipline exists to prevent.
func TestCancellationStopsTheRunAndFabricatesNothing(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	result := measureWith(ctx, t, target, tcpPlan(resolver, dialer))
	if result.Considered() != 0 || result.Measured() != 0 {
		t.Fatalf("considered = %d, measured = %d, want nothing attempted",
			result.Considered(), result.Measured())
	}
	if got := len(resolver.lookups()); got != 0 {
		t.Errorf("lookups = %d, want 0", got)
	}

	graph := freeze(t, target.builder)
	for _, evidence := range graph.Nodes() {
		if strings.Contains(evidence.ID().String(), advertisedScopePrefix) {
			t.Errorf("%s: a sweep that never started produced evidence", evidence.ID())
		}
	}
}

// TestStepTimeoutBoundsEachProbeRatherThanTheWholeRun.
//
// One advertised endpoint black-holes its connection attempt. The step budget
// ends that attempt, and the endpoint behind it is still measured — which is the
// property that makes a per-advertisement budget unnecessary.
func TestStepTimeoutBoundsEachProbeRatherThanTheWholeRun(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "blackhole.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "blackhole.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")

	dialer := &blackholeDialer{
		advertisedDialer: newAdvertisedDialer(peer),
		blackhole:        "10.20.0.1",
	}

	plan := TransportPlan{Resolver: resolver, Dialer: dialer, StepTimeout: 50 * time.Millisecond}
	result := measureWith(t.Context(), t, target, plan)
	if result.Measured() != 2 {
		t.Fatalf("measured = %d, want 2: one slow endpoint must not consume the run",
			result.Measured())
	}

	graph := freeze(t, target.builder)
	stalled := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 1, "blackhole.internal"), "10.20.0.1"))
	if stalled.State() == domain.StatePass {
		t.Error("the black-holed attempt passed")
	}
	reached := node(t, graph, scopedConnectID(t, brokerByNode(t, target, 2, "broker-2.internal"), "10.20.0.2"))
	if reached.State() != domain.StatePass {
		t.Errorf("tcp state = %s, want PASS", reached.State())
	}
}

// blackholeDialer blocks until the context ends for one address.
type blackholeDialer struct {
	*advertisedDialer
	blackhole string
}

func (d *blackholeDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if addr.Addr().String() == d.blackhole {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return d.advertisedDialer.DialTCP(ctx, addr)
}

// --- invocation errors ------------------------------------------------------

// TestInvocationDefectsAreErrorsNotEvidence draws the line section 19 of the
// phase brief draws: a defect in the caller is an error, and every target-side
// outcome is evidence.
func TestInvocationDefectsAreErrorsNotEvidence(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(newAdvertisedPeer(t))

	for _, testCase := range []struct {
		name    string
		ctx     context.Context
		builder *domain.GraphBuilder
		plan    TransportPlan
	}{
		{"nil context", nil, target.builder, tcpPlan(resolver, dialer)},
		{"nil builder", t.Context(), nil, tcpPlan(resolver, dialer)},
		{"no resolver", t.Context(), target.builder, TransportPlan{Dialer: dialer}},
		{"no dialer", t.Context(), target.builder, TransportPlan{Resolver: resolver}},
		{
			"negative step timeout", t.Context(), target.builder,
			TransportPlan{Resolver: resolver, Dialer: dialer, StepTimeout: -time.Second},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := MeasureAdvertised(testCase.ctx, testCase.builder, target.brokers, testCase.plan)
			if err == nil {
				t.Fatal("the call was accepted")
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("error = %v, want one wrapping ErrInvalidInput", err)
			}
		})
	}

	// And nothing was measured by any of them.
	if got := len(resolver.lookups()); got != 0 {
		t.Errorf("lookups = %d, want 0", got)
	}
}

// TestAnAdvertisementWithNoEvidenceNodeIsAnInvocationError.
//
// A usable advertisement that names no node has no truthful derivation edge, and
// a sweep with a silently missing edge is exactly the evidence a later rule would
// have needed. Only Metadata can construct one of these, so this is a defect
// rather than a fact.
func TestAnAdvertisementWithNoEvidenceNodeIsAnInvocationError(t *testing.T) {
	builder := domain.NewGraphBuilder()
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(newAdvertisedPeer(t))

	orphan := DiscoveredBroker{nodeID: 1, host: "broker-1.internal", port: 9093, usable: true}

	_, err := MeasureAdvertised(
		t.Context(), builder, []DiscoveredBroker{orphan}, tcpPlan(resolver, dialer))
	if err == nil {
		t.Fatal("an advertisement with no evidence node was measured")
	}
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("error = %v, want one wrapping ErrInvalidInput", err)
	}
	if got := len(resolver.lookups()); got != 0 {
		t.Errorf("lookups = %d, want 0: the defect must be caught before any I/O", got)
	}
}

// TestAnAbsentParentIsAnErrorAndCreatesNothing: the derivation parent must
// already be in the graph, and a missing one is not papered over.
func TestAnAbsentParentIsAnErrorAndCreatesNothing(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")
	dialer := newAdvertisedDialer(newAdvertisedPeer(t))

	// A fresh builder does not hold the advertisement the brokers name.
	builder := domain.NewGraphBuilder()

	_, err := MeasureAdvertised(t.Context(), builder, target.brokers, tcpPlan(resolver, dialer))
	if err == nil {
		t.Fatal("a sweep parented to an absent node was accepted")
	}
	if !errors.Is(err, domain.ErrInvalidGraph) {
		t.Errorf("error = %v, want one wrapping ErrInvalidGraph", err)
	}

	graph := freeze(t, builder)
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == StepBrokerAdvertised {
			t.Errorf("%s: the absent parent was fabricated to hang an edge on", evidence.ID())
		}
	}
}
