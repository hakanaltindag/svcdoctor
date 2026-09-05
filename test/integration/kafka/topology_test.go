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
//
// This is the flagship branch-specific scenario, against a real KRaft cluster
// with a real broker reconfigured to advertise an address nothing listens on.
// Phase 10.2 added the second half: the per-endpoint claim is unchanged, and a
// topology-scoped observation now says what became of the other two.
func TestOneBadBrokerProducesOneFinding(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	reconfigure(t, "broker-2", "ADV_2=localhost:29999")

	r := pass(t, defaults(t))
	r.writeArtifact(t, "multi-broker-one-bad")

	if len(r.nodes(servicekafka.StepBrokerAdvertised)) != 3 {
		t.Fatalf("advertisements = %d, want 3", len(r.nodes(servicekafka.StepBrokerAdvertised)))
	}

	unreachable := r.withCode(diagnosiskafka.CodeAdvertisedEndpointUnreachable)
	if len(unreachable) != 1 {
		t.Fatalf("findings = %v, want exactly one broker-scoped finding", r.codes())
	}
	if got := unreachable[0].Subject().Ref(); got != "localhost:29999" {
		t.Errorf("subject = %q, want the unreachable advertisement", got)
	}
	if got := r.report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("summary = %s, want PROBLEMS_FOUND", got)
	}

	// The Phase 10.2 contrast, measured rather than synthesized.
	scope := r.withCode(diagnosiskafka.CodeAdvertisedTopologyReachability)
	if len(scope) != 1 {
		t.Fatalf("topology observations = %d, want 1: %v", len(scope), r.codes())
	}
	if got := scope[0].Severity(); got != domain.SeverityInfo {
		t.Errorf("severity = %s, want INFO; a count is never a cluster verdict", got)
	}
	want := "1 of the 3 broker endpoints this cluster advertised could not be reached " +
		"from this vantage point; the other 2 were reached"
	if scope[0].Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", scope[0].Summary(), want)
	}

	// **No suitability hypothesis**, because two advertised endpoints really were
	// reached from this vantage point and that contradicts the claim. This is the
	// assertion that stops the phase's most attractive overclaim from shipping.
	if got := r.withCode(diagnosiskafka.CodeAdvertisedTopologyUnsuitable); len(got) != 0 {
		t.Errorf("a suitability hypothesis was emitted beside two reachable peers: %q",
			got[0].Summary())
	}

	assertNoTopologyOverclaim(t, r)
	t.Logf("one bad broker -> %s | %s", unreachable[0].Summary(), scope[0].Summary())
}

// TestAllBadBrokersProduceOneFindingEach is the anti-aggregate case.
//
// Every advertised endpoint is unreachable and the cluster is nevertheless
// demonstrably up — it answered Metadata over a measured path in this very run.
// A "cluster down" finding would be false, so three broker-scoped findings plus
// one count and one hypothesis are the only honest output.
//
// # This is the advertised-listener scenario, and what it may say
//
// The fixture is exactly the shape section 46 of the phase brief describes: the
// bootstrap address is reachable and metadata returns broker addresses that are
// definitively unreachable from the client. What svcdoctor may conclude is a
// CONFIRMED unreachability per endpoint, a CONFIRMED count over the complete
// set, and a MEDIUM hypothesis that the advertised endpoints may not suit this
// client's network. What it may not conclude is that any configuration is wrong,
// and assertNoTopologyOverclaim holds that against the real output.
func TestAllBadBrokersProduceOneFindingEach(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	compose(t, []string{
		"ADV_1=localhost:19999", "ADV_2=localhost:29999", "ADV_3=localhost:39999",
	}, "up", "-d", "--force-recreate")
	waitReady(t)

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "multi-broker-all-bad")

	unreachable := r.withCode(diagnosiskafka.CodeAdvertisedEndpointUnreachable)
	if len(unreachable) != 3 {
		t.Fatalf("findings = %v, want one per unreachable advertisement", r.codes())
	}
	subjects := map[string]bool{}
	for _, f := range unreachable {
		if f.Severity() != domain.SeverityError {
			t.Errorf("severity = %s; it must not vary with how many brokers failed", f.Severity())
		}
		subjects[f.Subject().Ref()] = true
	}
	if len(subjects) != 3 {
		t.Errorf("subjects = %v, want three distinct advertisements", subjects)
	}

	scope := r.withCode(diagnosiskafka.CodeAdvertisedTopologyReachability)
	if len(scope) != 1 {
		t.Fatalf("topology observations = %d, want 1: %v", len(scope), r.codes())
	}
	want := "None of the 3 broker endpoints this cluster advertised could be reached " +
		"from this vantage point"
	if scope[0].Summary() != want {
		t.Errorf("summary =\n  %q\nwant\n  %q", scope[0].Summary(), want)
	}
	if got := scope[0].Severity(); got != domain.SeverityInfo {
		t.Errorf("severity = %s; three failures are not a reason to escalate a count", got)
	}

	suspect := r.withCode(diagnosiskafka.CodeAdvertisedTopologyUnsuitable)
	if len(suspect) != 1 {
		t.Fatalf("suitability hypotheses = %d, want 1: %v", len(suspect), r.codes())
	}
	if got := suspect[0].Kind(); got != domain.FindingKindHypothesis {
		t.Errorf("kind = %s, want HYPOTHESIS", got)
	}
	if got := suspect[0].Confidence(); got != domain.ConfidenceMedium {
		t.Errorf("confidence = %s, want MEDIUM. Routing, packet filtering and a "+
			"broker-side outage are all unexcluded here, on a real cluster, and "+
			"svcdoctor measured none of them.", got)
	}
	if suspect[0].Discriminator() == "" {
		t.Error("the hypothesis names no observation that would settle it")
	}
	if len(suspect[0].Recommendations()) == 0 {
		t.Error("the hypothesis carries no next-evidence recommendation")
	}

	// The bootstrap path is untouched: the cluster answered.
	assertBootstrapHealthy(t, r)
	assertNoTopologyOverclaim(t, r)
	t.Logf("three unreachable advertisements -> %d endpoint findings, 1 count, 1 hypothesis",
		len(unreachable))
	t.Logf("  count:      %s", scope[0].Summary())
	t.Logf("  hypothesis: %s", suspect[0].Summary())
	t.Logf("  next:       %s", suspect[0].Recommendations()[0].Action())
}

// assertNoTopologyOverclaim runs the phase's refusal list against real output.
//
// The corpus asserts these over synthetic graphs. This asserts them over prose
// produced from a real cluster's real Metadata response, which is the only place
// a peer-supplied value could actually have reached a claim.
func assertNoTopologyOverclaim(t *testing.T, r *run) {
	t.Helper()

	var prose strings.Builder
	for _, f := range r.findings {
		prose.WriteString(f.Summary())
		prose.WriteString("\n")
		prose.WriteString(f.Detail())
		prose.WriteString("\n")
		prose.WriteString(f.Discriminator())
		for _, rec := range f.Recommendations() {
			prose.WriteString("\n")
			prose.WriteString(rec.Action())
		}
		prose.WriteString("\n")
	}
	lowered := strings.ToLower(prose.String())

	for _, banned := range []struct{ phrase, why string }{
		{"the cluster is down", "the cluster answered Metadata over a measured path in this run"},
		{"cluster is degraded", "cluster health is not observed"},
		{"cluster is unreachable", "the bootstrap path reached it"},
		{"advertised.listeners is", "no broker setting was read"},
		{"is misconfigured", "a configuration verdict on a value nobody observed"},
		{"a firewall is", "no firewall was observed and none could be"},
		{"firewall is blocking", "the same, in the active voice"},
		{"the broker is down", "a refused connection distinguishes neither a host nor a process"},
		{"broker process", "no process was observed, only an endpoint"},
		{"wrong password", "no credential was evaluated by any advertised endpoint"},
		{"quorum", "nothing about cluster membership was observed"},
		{"partition", "no partition state was requested"},
		{"this proves", "the contrast excludes one alternative and proves nothing"},
		{"the only explanation", "several alternatives remain unexcluded"},
		{"restart", "svcdoctor recommends restarting nothing"},
	} {
		if strings.Contains(lowered, banned.phrase) {
			t.Errorf("real-cluster output contains %q.\n\n%s\n\n--- prose ---\n%s",
				banned.phrase, banned.why, prose.String())
		}
	}
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
