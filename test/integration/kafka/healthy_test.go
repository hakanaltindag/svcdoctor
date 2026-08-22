//go:build integration

package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// TestHealthyCluster is the baseline: a real 3-broker KRaft cluster with nothing
// wrong with it. The strongest assertion here is the absence of findings.
func TestHealthyCluster(t *testing.T) {
	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "healthy")

	// --- transport, protocol, auth all reached ---
	for _, want := range []struct {
		step  domain.Step
		count int
	}{
		{"dns.lookup", 1},
		{"kafka.api_versions", 1},
		{"kafka.sasl_handshake", 1},
		{"kafka.sasl_authenticate", 1},
		{servicekafka.StepMetadata, 1},
	} {
		nodes := r.nodes(want.step)
		if len(nodes) < want.count {
			t.Fatalf("%s nodes = %d, want at least %d", want.step, len(nodes), want.count)
		}
		if nodes[0].State() != domain.StatePass {
			t.Errorf("%s = %s (%s), want PASS",
				want.step, nodes[0].State(), nodes[0].FailureClass())
		}
	}

	// --- the cluster the brokers actually are ---
	advertised := r.nodes(servicekafka.StepBrokerAdvertised)
	if len(advertised) != 3 {
		t.Fatalf("advertised brokers = %d, want 3", len(advertised))
	}

	seen := map[int64]string{}
	for _, node := range advertised {
		if node.State() != domain.StatePass {
			t.Errorf("advertisement %s = %s, want PASS", node.Subject().Ref(), node.State())
		}
		value, ok := node.Attribute(servicekafka.AttrBrokerNodeID)
		if !ok {
			t.Fatalf("advertisement %s carries no node identifier", node.Subject().Ref())
		}
		id, _ := value.Int()
		seen[id] = node.Subject().Ref()
	}
	for _, id := range []int64{1, 2, 3} {
		if _, ok := seen[id]; !ok {
			t.Errorf("node identifier %d is missing; got %v", id, seen)
		}
	}
	t.Logf("advertised topology: %v", seen)

	// --- every advertised endpoint was measured and reached ---
	if len(r.byLayer(domain.LayerTCP)) < 4 {
		t.Errorf("tcp nodes = %d, want at least 4 (bootstrap plus three sweeps)",
			len(r.byLayer(domain.LayerTCP)))
	}
	for _, node := range r.graph.Nodes() {
		switch node.State() {
		case domain.StateFail, domain.StateUnknown:
			t.Errorf("healthy cluster produced %s at %s %s (%s) on %s",
				node.State(), node.Layer(), node.Step(), node.FailureClass(), node.Subject().Ref())
		case domain.StatePass, domain.StateDegraded, domain.StateSkipped:
		}
	}

	// --- and therefore no findings at all ---
	if len(r.findings) != 0 {
		t.Errorf("findings = %v, want none on a healthy cluster", r.codes())
	}
	if got := r.report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("summary status = %s, want OK", got)
	}
	if got := r.report.Summary().UnknownEvidenceCount(); got != 0 {
		t.Errorf("unknown evidence = %d, want 0", got)
	}

	// --- the shareable form is valid and complete ---
	if got := r.shareable.Graph().Len(); got != r.graph.Len() {
		t.Errorf("shareable graph has %d nodes, local has %d", got, r.graph.Len())
	}
	counts := r.shareable.Security().Redactions()
	if counts.Hostname == 0 && counts.IPAddress == 0 {
		t.Error("redaction replaced no identity at all; the report cannot be right")
	}
	t.Logf("redactions: %+v", counts)
}

// TestControllerIsReported checks that the exchange records a controller the
// cluster actually has. It does not assert *which* broker: the controller moves
// on election, which is exactly why ADR 0034 refuses to use it in diagnosis.
func TestControllerIsReported(t *testing.T) {
	r := pass(t, defaults(t))

	exchange := r.nodes(servicekafka.StepMetadata)
	if len(exchange) != 1 {
		t.Fatalf("metadata nodes = %d, want 1", len(exchange))
	}
	value, ok := exchange[0].Attribute("kafka.metadata.controller_id")
	if !ok {
		t.Fatal("the exchange records no controller identifier")
	}
	id, _ := value.Int()
	if id < 1 || id > 3 {
		t.Errorf("controller id = %d, want one of the three brokers", id)
	}
	t.Logf("controller id = %d", id)

	brokerCount, ok := exchange[0].Attribute("kafka.metadata.broker_count")
	if !ok {
		t.Fatal("the exchange records no broker count")
	}
	count, _ := brokerCount.Int()
	if count != 3 {
		t.Errorf("broker count = %d, want 3", count)
	}

	if _, unrepresentable := exchange[0].Attribute("kafka.metadata.unrepresentable_entry_count"); unrepresentable {
		t.Error("a real broker produced an unrepresentable advertisement; " +
			"that is recorded as an open gap and would change its priority")
	}
}
