//go:build integration

package kafka

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7 against the real three-broker cluster.
//
// The rest of this suite bootstraps from `localhost`, so the resolving shape is
// already covered everywhere. What is not covered is the shape this phase added:
// a bootstrap target given as an address, which resolves nothing and must still
// walk the whole journey to Metadata and sweep the topology.
//
// The cluster's certificates carry `IP:127.0.0.1`, so a bare-address bootstrap
// verifies against a real IP SAN rather than skipping verification.

// TestAnAddressBootstrapWalksTheWholeJourney is the headline: real cluster, real
// socket, real SCRAM, no resolution.
func TestAnAddressBootstrapWalksTheWholeJourney(t *testing.T) {
	o := composed(t)
	o.host = "127.0.0.1"
	o.serverName = ""

	result := diagnose(t, o)
	report := result.Report()

	// No resolution happened, and none is claimed.
	for _, node := range report.Graph().Nodes() {
		if node.Step() == vocabulary.StepDNSLookup && isBootstrapLookup(t, report, node) {
			t.Fatalf("an address bootstrap produced %s", node.ID())
		}
	}
	for _, f := range report.Findings() {
		if strings.HasPrefix(string(f.Code()), "DNS_") {
			t.Errorf("an address bootstrap produced %s", f.Code())
		}
	}

	// Non-vacuity: the run really reached Metadata over that socket, which is
	// the whole Kafka BASIC journey (ADR 0052).
	metadata := nodesOf(result, servicekafka.StepMetadata)
	if len(metadata) != 1 || metadata[0].State() != domain.StatePass {
		t.Fatalf("kafka.metadata = %v, want one PASS: the run proved nothing", metadata)
	}

	// And the requested target is the address, in both projections.
	want := "127.0.0.1:" + strconv.Itoa(int(o.port))
	if got := report.Target().Requested(); got != want {
		t.Fatalf("report target = %q, want %q", got, want)
	}
	anchors := nodesOf(result, vocabulary.StepTargetRequested)
	if len(anchors) != 1 || anchors[0].Subject().Ref() != want {
		t.Fatalf("anchor subject = %v, want %q", anchors, want)
	}
}

// The bootstrap sweep hangs straight off the anchor, with no L1 node between —
// the ADR 0059 shape, on a real graph rather than a fixture.
func TestAnAddressBootstrapConnectsStraightFromTheAnchor(t *testing.T) {
	o := composed(t)
	o.host = "127.0.0.1"
	o.serverName = ""

	result := diagnose(t, o)
	graph := result.Report().Graph()

	anchors := nodesOf(result, vocabulary.StepTargetRequested)
	if len(anchors) != 1 {
		t.Fatalf("anchors = %d, want 1", len(anchors))
	}
	anchor := anchors[0]

	children := graph.Children(anchor.ID())
	if len(children) == 0 {
		t.Fatal("the anchor caused no sweep")
	}
	for _, id := range children {
		child, ok := graph.Node(id)
		if !ok {
			t.Fatalf("the graph does not hold %s", id)
		}
		if child.Step() != vocabulary.StepTCPConnect {
			t.Fatalf("the anchor's child is %s, want %s", child.Step(), vocabulary.StepTCPConnect)
		}
	}
}

// A bare address verifies against the cluster certificate's IP SAN, with no
// server-name override and with verification on.
func TestAnAddressBootstrapVerifiesAnIPSAN(t *testing.T) {
	o := composed(t)
	o.host = "127.0.0.1"
	o.serverName = ""

	result := diagnose(t, o)
	handshakes := nodesOf(result, vocabulary.StepTLSHandshake)

	checked := 0
	for _, node := range handshakes {
		name, ok := node.Attribute("tls.server_name")
		if !ok {
			continue
		}
		host, _ := name.Host()
		if host != "127.0.0.1" {
			continue // an advertised endpoint's own identity
		}
		checked++
		if node.State() != domain.StatePass {
			t.Fatalf("tls.handshake against the IP SAN = %s (%s), want PASS",
				node.State(), node.FailureClass())
		}
		verified, ok := node.Attribute("tls.verified")
		if !ok {
			t.Fatal("the handshake recorded no tls.verified attribute")
		}
		if b, _ := verified.Bool(); !b {
			t.Fatal("a bare-address handshake did not verify the peer")
		}
	}
	if checked == 0 {
		t.Fatal("no handshake verified the bare address; the test proves nothing")
	}
}

// The address bootstrap still authenticates exactly once, so first-class literal
// support did not widen credential authority or add an attempt.
func TestAnAddressBootstrapAuthenticatesOnce(t *testing.T) {
	o := composed(t)
	o.host = "127.0.0.1"
	o.serverName = ""

	result := diagnose(t, o)

	attempts := nodesOf(result, servicekafka.StepSASLAuthenticate)
	if len(attempts) != 1 {
		t.Fatalf("kafka.sasl_authenticate nodes = %d, want exactly 1", len(attempts))
	}
	if attempts[0].State() != domain.StatePass {
		t.Fatalf("authentication state = %s, want PASS", attempts[0].State())
	}
}

// A shareable report from an address bootstrap leaks neither the bootstrap
// address nor any advertised endpoint.
func TestAnAddressBootstrapRedactsCleanly(t *testing.T) {
	o := composed(t)
	o.host = "127.0.0.1"
	o.serverName = ""

	report := diagnose(t, o).Report()
	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := mustJSON(t, shareable)

	if strings.Contains(encoded, "127.0.0.1") {
		t.Errorf("the shareable report leaks the bootstrap address:\n%s", encoded)
	}
	for _, node := range report.Graph().Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		host, _, _ := strings.Cut(node.Subject().Ref(), ":")
		if host == "" || host == "localhost" {
			continue
		}
		if strings.Contains(encoded, host) {
			t.Errorf("the shareable report leaks the advertised endpoint %q", host)
		}
	}
}

// isBootstrapLookup reports whether a lookup belongs to the requested target
// rather than to an advertised endpoint's own sweep.
//
// The cluster advertises names, so advertised lookups legitimately exist even
// when the bootstrap target was an address; the property under test is about the
// bootstrap sweep alone.
func isBootstrapLookup(t *testing.T, report domain.Report, node domain.Evidence) bool {
	t.Helper()

	graph := report.Graph()
	for _, parent := range graph.Parents(node.ID()) {
		p, ok := graph.Node(parent)
		if !ok {
			continue
		}
		if p.Step() == vocabulary.StepTargetRequested {
			return true
		}
	}
	return false
}

// TestTheClusterIsReachableByAddress is the environment precondition for the
// tests above, kept separate so a failure says which half broke.
func TestTheClusterIsReachableByAddress(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(bootstrapPort))))
	if err != nil {
		t.Fatalf("the fixture cluster is not reachable at 127.0.0.1:%d: %v", bootstrapPort, err)
	}
	_ = conn.Close()
}
