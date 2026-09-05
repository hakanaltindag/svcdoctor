package diagnosis_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The Kafka half of the production-path harness, added in Phase 10.2.
//
// It exists for the reason harness_test.go's own doc comment gives: the engine's
// tests prove the machinery and these prove the *pipeline*. Nothing here builds
// a finding by hand, nothing stubs a layer, and the rule set is the one
// internal/app wires rather than a convenient subset — which
// TestTheKafkaCorpusUsesTheProductionRuleSet checks by name.

// kafkaRules is the Kafka composition root's rule set, minus the boundary that
// diagnose adds for every scenario.
//
// It is written out rather than imported because internal/app is not importable
// from a test that also wants to build graphs by hand. The guard in
// test/security pins internal/app's list; this pins that this corpus runs the
// same one, and TestTheKafkaCorpusUsesTheProductionRuleSet fails if they drift.
func kafkaRules() []namedRule {
	return []namedRule{
		{"transport/dns", diagnosistransport.DNS},
		{"transport/tcp", diagnosistransport.TCP},
		{"transport/tls", diagnosistransport.TLS},
		{"kafka/protocol", diagnosiskafka.Protocol},
		{"kafka/advertised-endpoint", diagnosiskafka.AdvertisedEndpointUnreachable},
		{"kafka/unusable-advertisement", diagnosiskafka.UnusableAdvertisement},
		{"kafka/advertised-topology", diagnosiskafka.AdvertisedTopologyReachability},
		{"kafka/advertised-suitability", diagnosiskafka.AdvertisedTopologyUnsuitable},
	}
}

// diagnoseKafka drives graph -> engine -> report -> renderers as the Kafka
// composition root does.
//
// It differs from diagnose in exactly two values — the run's service and the
// target — and both matter. The terminal renderer's topology line is selected by
// service (ADR 0052 section 5), so a report labelled postgres would render no
// topology counts at all and the agreement test below would pass vacuously.
func diagnoseKafka(t *testing.T, g domain.Graph, incomplete bool) run {
	t.Helper()

	set := diagnosis.NewRuleSet().Add("diag/failure-boundary", diagnosis.FailureBoundary)
	for _, r := range kafkaRules() {
		set.Add(r.id, r.rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		t.Fatalf("freezing the rule set: %v", err)
	}

	vantage, err := domain.NewLocalVantage("test-host")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph:      g,
		Vantage:    vantage,
		Incomplete: incomplete,
	})

	runMeta, err := domain.NewRunMetadata("0.0.0-test", fixedStart, time.Second, "kafka")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget("bootstrap.example:9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: runMeta, Target: target, Vantage: vantage,
		Graph: g, Findings: outcome.Findings(), Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	return run{graph: g, outcome: outcome, report: report, shareable: shareable}
}

// codes returns the finding codes a run produced, in canonical order.
func (r run) codes() []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(r.report.Findings()))
	for _, f := range r.report.Findings() {
		out = append(out, f.Code())
	}
	return out
}

// findingsWithCode returns every finding carrying one code.
func (r run) findingsWithCode(code domain.FindingCode) []domain.Finding {
	var out []domain.Finding
	for _, f := range r.report.Findings() {
		if f.Code() == code {
			out = append(out, f)
		}
	}
	return out
}

// --- the Kafka graph builder ------------------------------------------------

// kafkaSpec builds the graph shapes internal/adapter/kafka and
// internal/probe/transport produce for a Kafka run.
//
// It is hand-built for the reason internal/diagnosis/kafka's own fixtures are:
// a corpus that reached for the adapter could not produce the shapes it most
// needs — a cancelled sweep, a resolver failure, a hostile advertisement —
// and would couple the reasoning tests to a package diagnosis may not import.
type kafkaSpec struct {
	*graphSpec

	// bootstrap is the requested-target anchor every generic transport rule
	// descends from.
	bootstrap domain.EvidenceID

	// exchange is the kafka.metadata node, once metadata has been recorded.
	exchange domain.EvidenceID

	seq int
}

// newKafkaGraph starts a run against the documentation-reserved bootstrap
// endpoint.
func newKafkaGraph(t *testing.T) *kafkaSpec {
	t.Helper()
	s := &kafkaSpec{graphSpec: newGraph(t)}
	s.bootstrap = s.node("k-target", "bootstrap.example:9092", domain.LayerInput,
		string(vocabulary.StepTargetRequested), domain.StatePass)
	return s
}

// bootstrapPath records DNS, TCP and TLS for the endpoint the operator named.
func (s *kafkaSpec) bootstrapPath(dns, tcp, tls domain.State) *kafkaSpec {
	s.t.Helper()

	lookup := s.node("k-boot-dns", "bootstrap.example:9092", domain.LayerDNS,
		string(vocabulary.StepDNSLookup), dns)
	s.parent(lookup, s.bootstrap)
	if dns != domain.StatePass {
		return s
	}

	connect := s.node("k-boot-tcp", "10.0.0.1:9092", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), tcp)
	s.parent(connect, lookup)
	if tcp != domain.StatePass {
		return s
	}

	handshake := s.node("k-boot-tls", "10.0.0.1:9092", domain.LayerTLS,
		string(vocabulary.StepTLSHandshake), tls)
	s.parent(handshake, connect)
	return s
}

// protocolStage records one of the Kafka bootstrap protocol steps.
func (s *kafkaSpec) protocolStage(
	id string, layer domain.Layer, step domain.Step, state domain.State, class domain.FailureClass,
) domain.EvidenceID {
	s.t.Helper()
	node := s.nodeWithClass(id, "10.0.0.1:9092", layer, string(step), state, class)
	s.parent(node, "k-boot-tls")
	return node
}

// metadata records the kafka.metadata exchange over the bootstrap path.
func (s *kafkaSpec) metadata(state domain.State, class domain.FailureClass) *kafkaSpec {
	s.t.Helper()
	s.exchange = s.nodeWithClass("k-metadata", "10.0.0.1:9092", domain.LayerTopology,
		string(servicekafka.StepMetadata), state, class)
	s.parent(s.exchange, "k-boot-tls")
	return s
}

// advertisedOutcome is what a fixture wants one advertised endpoint to become.
type advertisedOutcome int

const (
	// advReachedPlain resolves and connects, with no TLS in the plan.
	advReachedPlain advertisedOutcome = iota

	// advReachedTLS resolves, connects and completes a handshake.
	advReachedTLS

	// advTCPRefused resolves and is refused.
	advTCPRefused

	// advDNSFails does not resolve.
	advDNSFails

	// advTLSIdentityMismatch connects and fails hostname verification.
	advTLSIdentityMismatch

	// advNotMeasured is left UNKNOWN by svcdoctor's own budget.
	advNotMeasured

	// advCancelled is left UNKNOWN by cancellation.
	advCancelled

	// advUnusable is an advertisement no client could act on.
	advUnusable
)

// advertise records one broker advertisement and the sweep beneath it.
//
// The host is taken from the caller so that a fixture can advertise a
// documentation name, an address literal, a loopback address or something
// hostile, which several scenarios below need.
// The evidence identifiers are derived from nodeID and not from the order the
// fixture happened to call this, so that permuting the calls produces the *same*
// graph rather than a differently labelled one. K-P13 asserts that discovery
// order does not change the output, and it could only assert that against a
// fixture whose labels do not move with the order either.
func (s *kafkaSpec) advertise(
	nodeID int, host string, port int, outcome advertisedOutcome,
) domain.EvidenceID {
	s.t.Helper()
	s.seq = nodeID

	endpoint := fmt.Sprintf("%s:%d", host, port)
	if outcome == advUnusable {
		// The producer records the pair as the cluster stated it, unrepaired.
		ad := s.nodeWithClass(fmt.Sprintf("k-ad-%d", s.seq), endpoint, domain.LayerTopology,
			string(servicekafka.StepBrokerAdvertised), domain.StateFail,
			domain.FailureProtocolUnexpectedResponse)
		s.parent(ad, s.exchange)
		return ad
	}

	ad := s.node(fmt.Sprintf("k-ad-%d", s.seq), endpoint, domain.LayerTopology,
		string(servicekafka.StepBrokerAdvertised), domain.StatePass)
	s.parent(ad, s.exchange)

	addr := fmt.Sprintf("10.30.0.%d:%d", nodeID, port)
	dnsID := fmt.Sprintf("k-ad-%d-dns", s.seq)
	tcpID := fmt.Sprintf("k-ad-%d-tcp", s.seq)
	tlsID := fmt.Sprintf("k-ad-%d-tls", s.seq)

	if outcome == advDNSFails {
		lookup := s.nodeWithClass(dnsID, host, domain.LayerDNS,
			string(vocabulary.StepDNSLookup), domain.StateFail, domain.FailureDNSNXDomain)
		s.parent(lookup, ad)
		return ad
	}

	lookup := s.node(dnsID, host, domain.LayerDNS, string(vocabulary.StepDNSLookup),
		domain.StatePass)
	s.parent(lookup, ad)

	switch outcome {
	case advReachedPlain:
		connect := s.node(tcpID, addr, domain.LayerTCP, string(vocabulary.StepTCPConnect),
			domain.StatePass)
		s.parent(connect, lookup)
	case advReachedTLS:
		connect := s.node(tcpID, addr, domain.LayerTCP, string(vocabulary.StepTCPConnect),
			domain.StatePass)
		s.parent(connect, lookup)
		handshake := s.node(tlsID, addr, domain.LayerTLS, string(vocabulary.StepTLSHandshake),
			domain.StatePass)
		s.parent(handshake, connect)
	case advTCPRefused:
		connect := s.nodeWithClass(tcpID, addr, domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateFail,
			domain.FailureTCPConnectionRefused)
		s.parent(connect, lookup)
	case advTLSIdentityMismatch:
		connect := s.node(tcpID, addr, domain.LayerTCP, string(vocabulary.StepTCPConnect),
			domain.StatePass)
		s.parent(connect, lookup)
		handshake := s.nodeWithClass(tlsID, addr, domain.LayerTLS,
			string(vocabulary.StepTLSHandshake), domain.StateFail,
			domain.FailureTLSHostnameMismatch)
		s.parent(handshake, connect)
	case advNotMeasured:
		connect := s.nodeWithClass(tcpID, addr, domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateUnknown,
			domain.FailureExecLocalTimeout)
		s.parent(connect, lookup)
	case advCancelled:
		connect := s.nodeWithClass(tcpID, addr, domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateUnknown,
			domain.FailureExecCancelled)
		s.parent(connect, lookup)
	case advDNSFails, advUnusable:
	}
	return ad
}

// The Kafka step names the corpus records, aliased so a fixture reads as a
// journey rather than as a package-qualified constant on every line.
const (
	kafkaStepAPIVersions      = servicekafka.StepAPIVersions
	kafkaStepSASLHandshake    = servicekafka.StepSASLHandshake
	kafkaStepSASLAuthenticate = servicekafka.StepSASLAuthenticate
)

// healthyThroughMetadata is the prefix every topology scenario shares.
func healthyThroughMetadata(t *testing.T) *kafkaSpec {
	t.Helper()

	s := newKafkaGraph(t)
	s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
	s.protocolStage("k-apiversions", domain.LayerProtocol, servicekafka.StepAPIVersions,
		domain.StatePass, domain.FailureNone)
	s.protocolStage("k-handshake", domain.LayerAuth, servicekafka.StepSASLHandshake,
		domain.StatePass, domain.FailureNone)
	s.protocolStage("k-auth", domain.LayerAuth, servicekafka.StepSASLAuthenticate,
		domain.StatePass, domain.FailureNone)
	s.metadata(domain.StatePass, domain.FailureNone)
	return s
}
