package kafka

import (
	"fmt"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// The fixtures build the graph shapes internal/adapter/kafka and
// internal/probe/transport produce, by hand.
//
// They are hand-built rather than driven through the real producers on purpose.
// The rule's contract is "given this frozen shape, claim exactly this", and a
// test that reached for the adapter would make a diagnosis test depend on a
// package diagnosis may not import — and would make the failure shapes this rule
// must withhold on (a budget skip, a resolver failure, a malformed graph)
// expensive or impossible to produce.
//
// TestFixturesMatchTheShapeTransportProduces in the transport-facing tests keeps
// them honest about the real thing where it matters: the terminal-layer
// biconditional and the blockedBy attribution.

// clock returns deterministic, distinct timestamps so evidence ordering never
// depends on wall time.
var origin = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// builder accumulates the nodes and edges of one fixture graph.
type builder struct {
	t     *testing.T
	inner *domain.GraphBuilder
	seq   int
}

func newBuilder(t *testing.T) *builder {
	t.Helper()
	return &builder{t: t, inner: domain.NewGraphBuilder()}
}

// node records one evidence node and its parent, if any.
func (b *builder) node(
	id string,
	subject string,
	layer domain.Layer,
	step domain.Step,
	state domain.State,
	class domain.FailureClass,
	parent domain.EvidenceID,
	attributes map[domain.AttributeKey]domain.AttrValue,
) domain.EvidenceID {
	b.t.Helper()

	sub, err := domain.NewEndpointSubject(subject)
	if err != nil {
		b.t.Fatalf("subject %q: %v", subject, err)
	}
	b.seq++
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(id),
		Subject:      sub,
		Layer:        layer,
		Step:         step,
		State:        state,
		FailureClass: class,
		Attributes:   attributes,
		StartedAt:    origin.Add(time.Duration(b.seq) * time.Millisecond),
		Elapsed:      domain.Measured(time.Millisecond),
	})
	if err != nil {
		b.t.Fatalf("evidence %q: %v", id, err)
	}
	if err := b.inner.AddEvidence(evidence); err != nil {
		b.t.Fatalf("adding %q: %v", id, err)
	}
	if parent != "" {
		if err := b.inner.AddParent(evidence.ID(), parent); err != nil {
			b.t.Fatalf("parent of %q: %v", id, err)
		}
	}
	return evidence.ID()
}

func (b *builder) blockedBy(skipped, blocker domain.EvidenceID) {
	b.t.Helper()
	if err := b.inner.AddBlockedBy(skipped, blocker); err != nil {
		b.t.Fatalf("blocked-by %q -> %q: %v", skipped, blocker, err)
	}
}

func (b *builder) freeze() domain.Graph {
	b.t.Helper()
	graph, err := b.inner.Freeze()
	if err != nil {
		b.t.Fatalf("freezing graph: %v", err)
	}
	return graph
}

// metadata records a kafka.metadata exchange node.
func (b *builder) metadata(state domain.State) domain.EvidenceID {
	b.t.Helper()
	class := domain.FailureNone
	if state == domain.StateFail {
		class = domain.FailureProtocolUnexpectedResponse
	}
	return b.node(
		"kafka.metadata/primary.internal:9092/10.0.0.1", "primary.internal:9092",
		domain.LayerTopology, servicekafka.StepMetadata, state, class, "", nil)
}

// advertised records one kafka.broker_advertised node under an exchange.
func (b *builder) advertised(
	exchange domain.EvidenceID, nodeID int64, endpoint string,
) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		fmt.Sprintf("kafka.broker_advertised/primary.internal:9092/10.0.0.1/%d/%s", nodeID, endpoint),
		endpoint, domain.LayerTopology, servicekafka.StepBrokerAdvertised,
		domain.StatePass, domain.FailureNone, exchange,
		map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrBrokerNodeID: domain.IntAttr(nodeID),
		})
}

// unusableAdvertised records the FAIL node Phase 3.3 produces for an
// advertisement no client can act on. No sweep hangs beneath it.
func (b *builder) unusableAdvertised(exchange domain.EvidenceID, nodeID int64) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		fmt.Sprintf("kafka.broker_advertised/primary.internal:9092/10.0.0.1/%d/unusable", nodeID),
		"primary.internal:9092", domain.LayerTopology, servicekafka.StepBrokerAdvertised,
		domain.StateFail, domain.FailureProtocolUnexpectedResponse, exchange,
		map[domain.AttributeKey]domain.AttrValue{
			servicekafka.AttrBrokerNodeID: domain.IntAttr(nodeID),
		})
}

// lookup records the scoped DNS root of one advertisement's sweep.
func (b *builder) lookup(
	advertisement domain.EvidenceID, host string, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		fmt.Sprintf("dns.lookup/advertised.%s/%s", shortOf(advertisement), host),
		host, domain.LayerDNS, "dns.lookup", state, class, advertisement, nil)
}

// connect records one TCP node under a lookup.
func (b *builder) connect(
	lookup domain.EvidenceID, addr string, port int, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		fmt.Sprintf("tcp.connect/%s/%s", shortOf(lookup), addr),
		fmt.Sprintf("%s:%d", addr, port), domain.LayerTCP, "tcp.connect", state, class, lookup, nil)
}

// handshake records one TLS node under a TCP node.
func (b *builder) handshake(
	connection domain.EvidenceID, addr string, port int, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	b.t.Helper()
	return b.node(
		fmt.Sprintf("tls.handshake/%s/%s", shortOf(connection), addr),
		fmt.Sprintf("%s:%d", addr, port), domain.LayerTLS, "tls.handshake", state, class, connection, nil)
}

// skippedHandshake records the SKIPPED TLS node the chain mints under a TCP node
// that produced no connection, naming that node as its blocker.
func (b *builder) skippedHandshake(
	connection domain.EvidenceID, addr string, port int,
) domain.EvidenceID {
	b.t.Helper()
	id := b.handshake(
		connection, addr, port, domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed)
	b.blockedBy(id, connection)
	return id
}

// shortOf makes a per-node suffix that keeps generated identifiers unique
// without encoding anything the rule reads. Nothing parses these.
func shortOf(id domain.EvidenceID) string {
	sum := 0
	for _, c := range []byte(id) {
		sum = sum*31 + int(c)
	}
	return fmt.Sprintf("%08x", uint32(sum)) //nolint:gosec // fixture label only
}
