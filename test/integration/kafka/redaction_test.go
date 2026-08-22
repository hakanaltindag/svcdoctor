//go:build integration

package kafka

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
)

// Redaction over reports built from a real cluster.
//
// The unit suite proves redaction against hand-built graphs. This proves it
// against the graph a real run produces, which is larger, has real identifiers
// with real hostnames inside them, and has whatever shape the cluster happened
// to report.

// TestShareableReportFromARealClusterIsUsableAndClean.
func TestShareableReportFromARealClusterIsUsableAndClean(t *testing.T) {
	r := pass(t, defaults(t))

	local := mustJSON(t, r.report)
	shareable := mustJSON(t, r.shareable)

	// The control: the local report really does carry the identities.
	for _, identity := range []string{"127.0.0.1", "validation-host.svcdoctor.test"} {
		if !strings.Contains(local, identity) {
			t.Fatalf("LOCAL_FULL does not contain %q; the leak check would be vacuous", identity)
		}
	}

	// Identity is gone.
	for _, identity := range []string{"127.0.0.1", "validation-host.svcdoctor.test", saslSecret} {
		if strings.Contains(shareable, identity) {
			t.Errorf("SHAREABLE report contains %q", identity)
		}
	}

	// Structure survives: same graph size, every reference resolves, diagnostic
	// facts intact.
	if r.shareable.Graph().Len() != r.graph.Len() {
		t.Errorf("shareable graph = %d nodes, local = %d",
			r.shareable.Graph().Len(), r.graph.Len())
	}
	for _, f := range r.shareable.Findings() {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := r.shareable.Graph().Node(ref); !ok {
				t.Errorf("finding %s references %s, absent from the redacted graph", f.Code(), ref)
			}
		}
	}
	var states, steps int
	for _, node := range r.shareable.Graph().Nodes() {
		if node.State() != domain.StateUnknown {
			states++
		}
		if node.Step() != "" {
			steps++
		}
	}
	if states == 0 || steps == 0 {
		t.Error("redaction destroyed diagnostic content")
	}

	counts := r.shareable.Security().Redactions()
	t.Logf("redactions: hostname=%d ip=%d evidenceId=%d prose=%d",
		counts.Hostname, counts.IPAddress, counts.EvidenceID, counts.Prose)
	if counts.EvidenceID != r.graph.Len() {
		t.Errorf("evidence identifiers remapped = %d, want all %d", counts.EvidenceID, r.graph.Len())
	}

	// Broker node identifiers survive, which is what keeps a shared report
	// readable once hostnames are pseudonyms.
	var withNodeID int
	for _, node := range r.shareable.Graph().Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		if _, ok := node.Attribute(servicekafka.AttrBrokerNodeID); ok {
			withNodeID++
		}
	}
	if withNodeID != 3 {
		t.Errorf("advertisements keeping a node identifier = %d, want 3", withNodeID)
	}
}

// TestRedactionIsIdempotentOnARealReport.
func TestRedactionIsIdempotentOnARealReport(t *testing.T) {
	r := pass(t, defaults(t))

	again, err := redaction.Redact(r.shareable)
	if err != nil {
		t.Fatalf("redacting a shareable report: %v", err)
	}
	if mustJSON(t, again) != mustJSON(t, r.shareable) {
		t.Error("redaction is not idempotent on a report built from a real cluster")
	}
}

// TestRealHostnamesDoNotTripTheResidualScan is the open Phase 3.7.5 limitation,
// checked against the names a real deployment uses.
//
// An identity whose text also occurs in ordinary report text still fails closed.
// The names here are the ones this environment produces plus a set of realistic
// production shapes; if any of them tripped it, the limitation would stop being
// theoretical and would block release rather than sit in the backlog.
func TestRealHostnamesDoNotTripTheResidualScan(t *testing.T) {
	r := pass(t, defaults(t))
	if _, err := redaction.Redact(r.report); err != nil {
		t.Fatalf("a report from a real cluster could not be redacted: %v", err)
	}
	t.Logf("redacted a %d-node real-cluster report with hostnames %v",
		r.graph.Len(), r.advertisedEndpoints())
}
