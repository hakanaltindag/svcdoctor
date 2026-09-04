package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Malformed-graph defence.
//
// domain.Graph already enforces structural validity, so these are graphs that
// are structurally valid and semantically unexpected: shapes no current producer
// creates, but that a future contract drift could. The rule must fail safe —
// prefer no finding over an invented claim — and must not panic.

func TestUnexpectedSweepShapesWithholdEveryClaim(t *testing.T) {
	tests := []struct {
		name  string
		build func(*builder, domain.EvidenceID)
	}{
		{
			// An advertisement is either a name or an address. A lookup *and* a
			// resolution-free connection beneath one is a graph no producer
			// makes, and the rule cannot tell which half describes the endpoint.
			//
			// A TCP node alone beneath an advertisement is **not** here: since
			// ADR 0059 that is the shape a broker advertising an address
			// produces, it is recognized, and TestALiteralAdvertisementIsOwned
			// pins that it yields a finding rather than silence.
			name: "a lookup and a direct connection beneath one advertisement",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.node("tcp.connect/direct/10.20.0.2", "10.20.0.2:9093",
					domain.LayerTCP, "tcp.connect", domain.StateFail,
					domain.FailureTCPConnectionRefused, ad, nil)
			},
		},
		{
			name: "a protocol node beneath the lookup instead of a connection",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.node("kafka.api_versions/x", "10.20.0.1:9093",
					domain.LayerProtocol, "kafka.api_versions", domain.StateFail,
					domain.FailureProtocolUnexpectedResponse, l, nil)
			},
		},
		{
			name: "two handshakes beneath one connection",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(l, "10.20.0.1", 9093, domain.StatePass, domain.FailureNone)
				b.node("tls.handshake/a", "10.20.0.1:9093", domain.LayerTLS, "tls.handshake",
					domain.StateFail, domain.FailureTLSHostnameMismatch, c, nil)
				b.node("tls.handshake/b", "10.20.0.1:9093", domain.LayerTLS, "tls.handshake",
					domain.StateFail, domain.FailureTLSUnknownAuthority, c, nil)
			},
		},
		{
			// An advertisement with two exchanges above it leaves no defensible
			// answer to which one the finding should cite as the successful half.
			name: "two metadata exchanges above one advertisement",
			build: func(b *builder, ad domain.EvidenceID) {
				second := b.node(
					"kafka.metadata/other:9092/10.0.0.9", "other:9092",
					domain.LayerTopology, "kafka.metadata", domain.StatePass,
					domain.FailureNone, "", nil)
				if err := b.inner.AddParent(ad, second); err != nil {
					b.t.Fatalf("second exchange parent: %v", err)
				}
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				b.connect(l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
			},
		},
		{
			// A handshake that neither completed nor was skipped for a
			// prerequisite, beneath a connection that failed. The chain never
			// produces it; if it appeared, the sweep would be unresolved for a
			// reason with no causal owner to cite.
			name: "an unfinished handshake beneath a failed connection",
			build: func(b *builder, ad domain.EvidenceID) {
				l := b.lookup(ad, "broker-2.internal", domain.StatePass, domain.FailureNone)
				c := b.connect(
					l, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
				b.handshake(c, "10.20.0.1", 9093, domain.StateUnknown, domain.FailureExecLocalTimeout)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := newBuilder(t)
			exchange := b.metadata(domain.StatePass)
			advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
			tc.build(b, advertisement)
			none(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
		})
	}
}

// TestAMixedTerminalLayerWithholdsRatherThanClaims covers the one shape where
// the terminal-layer quantifier is observable: the biconditional is violated, so
// some connections have a handshake beneath them and one does not.
//
// The universal reading resolves it to TCP, the passing connection counts as
// having reached the terminal layer, and the rule withholds. The alternative
// reading would report an endpoint unreachable on the strength of a graph that
// already broke its own invariant.
func TestAMixedTerminalLayerWithholdsRatherThanClaims(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.advertised(exchange, 2, "broker-2.internal:9093")
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)

	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)
	b.skippedHandshake(refused, "10.20.0.1", 9093)
	b.connect(lookup, "10.20.0.2", 9093, domain.StatePass, domain.FailureNone) // no handshake node

	none(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
}

// TestAnEmptyGraphProducesNothing is the trivial guard: a rule that walks a graph
// with no Kafka evidence in it must return nothing rather than fail.
func TestAnEmptyGraphProducesNothing(t *testing.T) {
	graph, err := domain.NewGraphBuilder().Freeze()
	if err != nil {
		t.Fatalf("freezing an empty graph: %v", err)
	}
	none(t, AdvertisedEndpointUnreachable(rctx(graph)))
}

// TestAnAdvertisementWithNoNodeIDStillProducesAFinding proves the broker phrase
// is prose decoration and never a precondition of the claim.
func TestAnAdvertisementWithNoNodeIDStillProducesAFinding(t *testing.T) {
	b := newBuilder(t)
	exchange := b.metadata(domain.StatePass)
	advertisement := b.node(
		"kafka.broker_advertised/no-node-id", "broker-2.internal:9093",
		domain.LayerTopology, "kafka.broker_advertised", domain.StatePass,
		domain.FailureNone, exchange, nil)
	lookup := b.lookup(advertisement, "broker-2.internal", domain.StatePass, domain.FailureNone)
	refused := b.connect(lookup, "10.20.0.1", 9093, domain.StateFail, domain.FailureTCPConnectionRefused)

	f := only(t, AdvertisedEndpointUnreachable(rctx(b.freeze())))
	confirmed(t, f)
	wantRefs(t, f, exchange, advertisement, refused)
}
