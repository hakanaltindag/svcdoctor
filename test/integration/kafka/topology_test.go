//go:build integration

package kafka

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"

	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// TestOneBadBrokerProducesOneFinding: two brokers fine, one unreachable.
func TestOneBadBrokerProducesOneFinding(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	reconfigure(t, "broker-2", "ADV_2=localhost:29999")

	r := pass(t, defaults(t))
	r.writeArtifact(t, "multi-broker-one-bad")

	if len(r.nodes(servicekafka.StepBrokerAdvertised)) != 3 {
		t.Fatalf("advertisements = %d, want 3", len(r.nodes(servicekafka.StepBrokerAdvertised)))
	}
	if len(r.findings) != 1 {
		t.Fatalf("findings = %v, want exactly one broker-scoped finding", r.codes())
	}
	if got := r.findings[0].Subject().Ref(); got != "localhost:29999" {
		t.Errorf("subject = %q, want the unreachable advertisement", got)
	}
	if got := r.report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("summary = %s, want PROBLEMS_FOUND", got)
	}
	t.Logf("one bad broker -> %s", r.findings[0].Summary())
}

// TestAllBadBrokersProduceOneFindingEach is the anti-aggregate case.
//
// Every advertised endpoint is unreachable and the cluster is nevertheless
// demonstrably up — it answered Metadata over a measured path in this very run.
// A "cluster down" finding would be false, so three broker-scoped findings are
// the only honest output.
func TestAllBadBrokersProduceOneFindingEach(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	compose(t, []string{
		"ADV_1=localhost:19999", "ADV_2=localhost:29999", "ADV_3=localhost:39999",
	}, "up", "-d", "--force-recreate")
	waitReady(t)

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "multi-broker-all-bad")

	if len(r.findings) != 3 {
		t.Fatalf("findings = %v, want one per unreachable advertisement", r.codes())
	}
	subjects := map[string]bool{}
	for _, f := range r.findings {
		if f.Code() != diagnosiskafka.CodeAdvertisedEndpointUnreachable {
			t.Errorf("unexpected code %s", f.Code())
		}
		if f.Severity() != domain.SeverityError {
			t.Errorf("severity = %s; it must not vary with how many brokers failed", f.Severity())
		}
		subjects[f.Subject().Ref()] = true
		for _, banned := range []string{"cluster", "down", "unavailable"} {
			if strings.Contains(strings.ToLower(f.Summary()), banned) {
				t.Errorf("summary makes a cluster-level claim: %q", f.Summary())
			}
		}
	}
	if len(subjects) != 3 {
		t.Errorf("subjects = %v, want three distinct advertisements", subjects)
	}
	// The bootstrap path is untouched: the cluster answered.
	assertBootstrapHealthy(t, r)
	t.Logf("three unreachable advertisements -> %d broker-scoped findings, no aggregate",
		len(r.findings))
}

// countingDialer records every TCP connection actually opened.
type countingDialer struct {
	mu    sync.Mutex
	local []string
}

func (d *countingDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	conn, err := (tcp.SystemDialer{}).DialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.local = append(d.local, conn.LocalAddr().String())
	d.mu.Unlock()
	return conn, nil
}

func (d *countingDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.local)
}

// TestOneConnectionCarriesEveryProtocolStep is the connection-ownership proof.
//
// ApiVersions, SaslHandshake, SaslAuthenticate and Metadata are four exchanges,
// and a client that redialed between them would open four sockets. The adapter
// structurally cannot: it receives live connections from the transport chain and
// has no dialer of its own. This measures it anyway, against a real broker,
// because "cannot" is a claim about code and this is a claim about behaviour.
func TestOneConnectionCarriesEveryProtocolStep(t *testing.T) {
	dialer := &countingDialer{}
	o := defaults(t)
	o.dialer = dialer
	o.sweep = false // count the bootstrap path only
	o.stopAfterAuth = false

	r := pass(t, o)

	// localhost is dual-stack here, so the chain measures both addresses: two
	// connections, and no more, for four protocol exchanges plus the handshake.
	addresses := len(r.byLayer(domain.LayerTCP))
	if got := dialer.count(); got != addresses {
		t.Errorf("dialled %d times for %d measured addresses; a redial happened between steps",
			got, addresses)
	}

	// And the exchanges really did run.
	for _, step := range []domain.Step{
		"kafka.api_versions", "kafka.sasl_handshake", "kafka.sasl_authenticate",
		servicekafka.StepMetadata,
	} {
		if len(r.nodes(step)) == 0 {
			t.Fatalf("%s did not run; the proof would be vacuous", step)
		}
	}

	// Every socket is distinct, so the count is connections rather than reuse of
	// one local port.
	seen := map[string]bool{}
	for _, local := range dialer.local {
		if seen[local] {
			t.Errorf("local address %s was reported twice", local)
		}
		seen[local] = true
	}
	t.Logf("%d TCP connections for %d addresses, carrying 4 protocol exchanges: %v",
		dialer.count(), addresses, dialer.local)
}

// TestRealKafkaCannotAdvertiseAnUnusableEndpoint records what the cluster does
// with the two configurations that would produce KAFKA_ADVERTISED_ENDPOINT_UNUSABLE.
//
// It is a negative result and it is worth having: the finding exists, it is unit
// tested, and this says a correctly functioning Apache Kafka 4.0 broker is not
// the thing that will produce it.
func TestRealKafkaCannotAdvertiseAnUnusableEndpoint(t *testing.T) {
	t.Cleanup(func() { restore(t) })

	// Port 0: Kafka substitutes the port the listener actually bound.
	reconfigure(t, "broker-2", "ADV_2=localhost:0")
	r := pass(t, defaults(t))

	for _, node := range r.nodes(servicekafka.StepBrokerAdvertised) {
		if strings.HasSuffix(node.Subject().Ref(), ":0") {
			t.Errorf("the broker advertised %q; Kafka was expected to substitute the bound port",
				node.Subject().Ref())
		}
		if node.State() != domain.StatePass {
			t.Errorf("advertisement %s = %s; a usable endpoint was expected",
				node.Subject().Ref(), node.State())
		}
	}
	for _, f := range r.findings {
		if f.Code() == diagnosiskafka.CodeAdvertisedEndpointUnusable {
			t.Errorf("an unusable finding was produced from a real broker: %s", f.Summary())
		}
	}
	t.Logf("advertised.listeners=localhost:0 became %v", r.advertisedEndpoints())
}
