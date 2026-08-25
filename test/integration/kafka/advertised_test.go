//go:build integration

package kafka

import (
	"strings"
	"testing"

	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/test/harness"
)

// The advertised-listener scenarios: a real cluster that answers, and then
// reports an endpoint the client cannot use. This is the failure svcdoctor was
// built to explain, and every case here is produced by broker configuration.

// unreachableFindings returns the advertised-endpoint findings and their subjects.
func unreachableFindings(r *run) []domain.Finding {
	var out []domain.Finding
	for _, f := range r.findings {
		if f.Code() == diagnosiskafka.CodeAdvertisedEndpointUnreachable {
			out = append(out, f)
		}
	}
	return out
}

// assertBootstrapHealthy pins the contrast half: the cluster answered.
func assertBootstrapHealthy(t *testing.T, r *run) {
	t.Helper()
	for _, step := range []domain.Step{
		"kafka.api_versions", "kafka.sasl_handshake", "kafka.sasl_authenticate",
		servicekafka.StepMetadata,
	} {
		nodes := r.nodes(step)
		if len(nodes) == 0 {
			t.Fatalf("%s is missing; the bootstrap path did not complete", step)
		}
		if nodes[0].State() != domain.StatePass {
			t.Fatalf("%s = %s, want PASS: the finding's contrast half must hold",
				step, nodes[0].State())
		}
	}
}

// refKinds summarises what a finding cites, by layer and state.
func refKinds(r *run, f domain.Finding) []string {
	var out []string
	for _, ref := range f.EvidenceRefs() {
		node, ok := r.graph.Node(ref)
		if !ok {
			out = append(out, "DANGLING")
			continue
		}
		out = append(out, node.Layer().String()+"/"+node.State().String()+"/"+node.FailureClass().String())
	}
	return out
}

// TestAdvertisedDNSFailure: the cluster advertises a name that does not resolve.
func TestAdvertisedDNSFailure(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	reconfigure(t, "broker-2", "ADV_2=broker-2.svcdoctor-nonexistent.invalid:9092")

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "advertised-dns-failure")

	assertBootstrapHealthy(t, r)

	findings := unreachableFindings(r)
	if len(findings) != 1 {
		t.Fatalf("unreachable findings = %d, want exactly 1: %v", len(findings), r.codes())
	}
	f := findings[0]

	if f.Kind() != domain.FindingKindConfirmed || f.Severity() != domain.SeverityError ||
		f.Confidence() != domain.ConfidenceHigh {
		t.Errorf("finding = %s/%s/%s, want CONFIRMED/ERROR/HIGH",
			f.Kind(), f.Severity(), f.Confidence())
	}
	if !f.VantageDependent() {
		t.Error("vantageDependent = false; reachability is relative to where svcdoctor ran")
	}
	if !strings.HasPrefix(f.Subject().Ref(), "broker-2.svcdoctor-nonexistent.invalid") {
		t.Errorf("subject = %q, want the advertised endpoint", f.Subject().Ref())
	}

	// Exactly the ADR 0034 causal set: the exchange, the advertisement, the DNS
	// failure. Nothing fabricated below L1.
	kinds := refKinds(r, f)
	if len(kinds) != 3 {
		t.Errorf("evidence refs = %v, want metadata + advertisement + DNS", kinds)
	}
	var sawDNSFail bool
	for _, ref := range f.EvidenceRefs() {
		node, _ := r.graph.Node(ref)
		if node.Layer() == domain.LayerDNS && node.State() == domain.StateFail {
			sawDNSFail = true
		}
		if node.Layer() == domain.LayerTCP || node.Layer() == domain.LayerTLS {
			t.Errorf("finding cites %s evidence; nothing below L1 was measured", node.Layer())
		}
	}
	if !sawDNSFail {
		t.Errorf("finding does not cite a failed lookup: %v", kinds)
	}

	// No TCP or TLS node exists at all for that sweep.
	for _, node := range r.graph.Nodes() {
		if strings.Contains(node.Subject().Ref(), "svcdoctor-nonexistent") &&
			node.Layer() != domain.LayerDNS && node.Layer() != domain.LayerTopology {
			t.Errorf("fabricated %s evidence for an unresolvable name", node.Layer())
		}
	}

	// The hostname is gone from the shareable form.
	if leaks(t, r) {
		t.Error("the shareable report leaks the advertised hostname")
	}
}

// TestAdvertisedTCPRefused: the name resolves, nothing listens on the port.
func TestAdvertisedTCPRefused(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	reconfigure(t, "broker-2", "ADV_2=localhost:29999")

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "advertised-tcp-refused")

	assertBootstrapHealthy(t, r)

	// K-H1 (harness). The two halves are asserted together because the finding
	// only means anything as a contrast: the cluster answered on the bootstrap
	// path, and an endpoint it advertised cannot be reached from here.
	//
	// The credential bound is the security half. Bootstrap authentication
	// authority does not extend to a discovered broker (ADR 0050), so the sweep
	// over advertised endpoints must contain no credential-bearing step at all.
	harness.Assert(t, harness.Subject{
		Name:               "K-H1 bootstrap ok, advertised unreachable",
		Report:             r.report,
		CredentialAttempts: advertisedCredentialAttempts(r),
	}, harness.Expectation{
		Summary: harness.Status(domain.SummaryStatusProblemsFound),
		Nodes: []harness.Node{
			{
				Step:         servicekafka.StepMetadata,
				State:        domain.StatePass,
				FailureClass: domain.FailureNone,
			},
			{
				Step:         servicekafka.StepSASLAuthenticate,
				State:        domain.StatePass,
				FailureClass: domain.FailureNone,
			},
		},
		RequireFindings: []domain.FindingCode{
			diagnosiskafka.CodeAdvertisedEndpointUnreachable,
		},
		// The bootstrap path authenticated and answered. Nothing here is a
		// credential outcome or a protocol outcome.
		ForbidFindings: []domain.FindingCode{
			diagnosiskafka.CodeCredentialsRejected,
			diagnosiskafka.CodeMetadataNotCompleted,
		},
		// PASS is existential and FAIL is universal (ADR 0051): one unreachable
		// advertised endpoint is not a statement about the cluster, and svcdoctor
		// never authenticated to the endpoint it could not reach.
		ForbidProse: []string{
			"cluster is unhealthy", "cluster is down", "cluster unhealthy",
			"authentication failed", "credential was rejected",
			"the cluster cannot be used",
		},
		MaxCredentialAttempts: harness.Count(0),
	})

	findings := unreachableFindings(r)
	if len(findings) != 1 {
		t.Fatalf("unreachable findings = %d, want exactly 1: %v", len(findings), r.codes())
	}
	f := findings[0]

	if f.Kind() != domain.FindingKindConfirmed {
		t.Errorf("kind = %s, want CONFIRMED", f.Kind())
	}

	// The blocker owns the failure. A TLS handshake was required, so each failed
	// TCP node has a SKIPPED TLS child beneath it; those must not be cited.
	var tcpFails, tlsSkips int
	for _, ref := range f.EvidenceRefs() {
		node, _ := r.graph.Node(ref)
		switch {
		case node.Layer() == domain.LayerTCP && node.State() == domain.StateFail:
			tcpFails++
		case node.State() == domain.StateSkipped &&
			node.FailureClass() == domain.FailureExecSkippedPrerequisiteFailed:
			tlsSkips++
		}
	}
	if tcpFails == 0 {
		t.Errorf("finding cites no failed connection: %v", refKinds(r, f))
	}
	if tlsSkips != 0 {
		t.Errorf("finding cites %d prerequisite-skipped node(s); the blocker owns the failure",
			tlsSkips)
	}

	// And the skipped handshakes do exist in the graph, blocked by their TCP node.
	var skipped int
	for _, node := range r.graph.Nodes() {
		if node.Layer() == domain.LayerTLS && node.State() == domain.StateSkipped {
			skipped++
			if len(r.graph.BlockedBy(node.ID())) == 0 {
				t.Errorf("skipped handshake %s names no blocker", node.ID())
			}
		}
	}
	if skipped == 0 {
		t.Error("no skipped handshake was recorded; the TLS plan should mint one per path")
	}
	t.Logf("cited %d TCP failures; %d skipped handshakes recorded and not cited", tcpFails, skipped)
}

// TestAdvertisedTLSFailure: the endpoint accepts a connection and presents a
// certificate for a different name.
func TestAdvertisedTLSFailure(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	// broker-2 serves a certificate whose SAN is not-the-broker.invalid.
	reconfigure(t, "broker-2", "KS_2=/certs/wrongname.p12")

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "advertised-tls-failure")

	assertBootstrapHealthy(t, r)

	findings := unreachableFindings(r)
	if len(findings) != 1 {
		t.Fatalf("unreachable findings = %d, want exactly 1: %v", len(findings), r.codes())
	}
	f := findings[0]

	var tlsFails int
	for _, ref := range f.EvidenceRefs() {
		node, _ := r.graph.Node(ref)
		if node.Layer() == domain.LayerTLS && node.State() == domain.StateFail {
			tlsFails++
			if node.FailureClass() != domain.FailureTLSHostnameMismatch {
				t.Logf("TLS failure class = %s", node.FailureClass())
			}
		}
		if node.Layer() == domain.LayerTCP && node.State() == domain.StatePass {
			t.Errorf("finding cites a passing TCP node; the handshake owns this failure")
		}
	}
	if tlsFails == 0 {
		t.Errorf("finding cites no failed handshake: %v", refKinds(r, f))
	}
	if !strings.Contains(f.Summary(), "L3") {
		t.Errorf("summary does not name the failing layer: %q", f.Summary())
	}
	t.Logf("summary: %s", f.Summary())
}

// TestPartialAddressSuccessWithholdsTheFinding is the policy case that matters
// most, and the environment produces it naturally.
//
// broker-2's port is published on IPv4 only, so `localhost` resolves to two
// addresses of which one refuses the connection. A client that selects the
// working address succeeds, so the endpoint is not unreachable and no finding
// may be produced — while the failing path stays visible in the evidence.
func TestPartialAddressSuccessWithholdsTheFinding(t *testing.T) {
	t.Cleanup(func() { restore(t) })
	reconfigure(t, "broker-2", "PORTS_2=127.0.0.1:29192:9092")

	r := pass(t, defaults(t))
	r.describe(t)
	r.writeArtifact(t, "partial-address-success")

	assertBootstrapHealthy(t, r)

	// The failure really happened...
	var failedPaths, passedPaths int
	for _, node := range r.graph.Nodes() {
		if node.Layer() != domain.LayerTCP || !strings.Contains(node.Subject().Ref(), "29192") {
			continue
		}
		switch node.State() {
		case domain.StateFail:
			failedPaths++
		case domain.StatePass:
			passedPaths++
		default:
		}
	}
	if failedPaths == 0 || passedPaths == 0 {
		t.Skipf("the environment did not produce a mixed dual-stack result "+
			"(%d failed, %d passed); partial-address policy is covered by unit tests",
			failedPaths, passedPaths)
	}
	t.Logf("dual-stack: %d path(s) failed, %d path(s) succeeded", failedPaths, passedPaths)

	// ...and no unreachable claim was made about it.
	for _, f := range unreachableFindings(r) {
		if strings.Contains(f.Subject().Ref(), "29192") {
			t.Errorf("a partially reachable endpoint produced %s: %s", f.Code(), f.Summary())
		}
	}
}

// leaks reports whether any advertised hostname survives redaction.
func leaks(t *testing.T, r *run) bool {
	t.Helper()
	encoded := mustJSON(t, r.shareable)
	for _, node := range r.graph.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		host, _, _ := strings.Cut(node.Subject().Ref(), ":")
		if host == "" || host == "localhost" {
			continue // not identity, or shared with the target
		}
		if strings.Contains(encoded, host) {
			t.Errorf("shareable report contains %q", host)
			return true
		}
	}
	return false
}

// advertisedCredentialAttempts counts credential-bearing steps beneath every
// advertised endpoint.
//
// # Why the scenario derives it and the harness only bounds it
//
// Which steps carry a credential is Kafka knowledge — `kafka.sasl_handshake`
// negotiates a mechanism and `kafka.sasl_authenticate` presents the secret —
// and the harness must not hold it. No counter was added to production code:
// this reads the graph the run already produced.
func advertisedCredentialAttempts(r *run) *int {
	credentialBearing := map[domain.Step]bool{
		servicekafka.StepSASLHandshake:    true,
		servicekafka.StepSASLAuthenticate: true,
	}
	n := 0
	for _, advertisement := range r.nodes(servicekafka.StepBrokerAdvertised) {
		for _, id := range descendantsOf(r.graph, advertisement.ID()) {
			node, ok := r.graph.Node(id)
			if ok && credentialBearing[node.Step()] {
				n++
			}
		}
	}
	return &n
}
