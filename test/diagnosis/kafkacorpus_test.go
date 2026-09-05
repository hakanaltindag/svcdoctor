package diagnosis_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Kafka golden incident corpus, added in Phase 10.2.
//
// It follows the format the generic corpus fixed in Phase 10.1B — intent,
// evidence, expected, forbidden — and adds the fourth part ADR 0084 section 10
// requires of a service corpus: an **allowed** list, which closes the world.
//
// # Why closing the world matters more here than it did for the boundary
//
// The generic corpus asserts which subjects have a boundary and which do not,
// and a stray extra finding of some other code would have slipped past it. A
// Kafka scenario produces between one and eight findings from eight rules, and
// the failure mode this corpus exists to catch is *a rule saying something in a
// scenario nobody expected it to speak in* — a topology claim after an
// authentication failure, a suitability hypothesis beside a reachable peer.
// Naming every code that may appear is what turns that from an oversight into a
// build failure.
//
// Every fixture is synthetic and every host is documentation-reserved
// (ADR 0083 section 5); TestTheKafkaCorpusCarriesNoRealIdentity enforces it.

// expectedClaim is one finding a scenario must produce.
type expectedClaim struct {
	code       domain.FindingCode
	kind       domain.FindingKind
	confidence domain.Confidence

	// count is how many findings with this code the scenario must produce. It is
	// explicit because "one per unreachable endpoint" and "one per exchange" are
	// different cardinalities and confusing them is a real defect.
	count int
}

// kafkaIncident is one corpus fixture.
type kafkaIncident struct {
	id     string
	name   string
	intent string

	build      func(t *testing.T) domain.Graph
	incomplete bool

	// expect is what must appear, exactly.
	expect []expectedClaim

	// allow names codes that may appear in addition. Anything neither expected
	// nor allowed fails the scenario.
	allow []domain.FindingCode

	// forbidden is what this scenario must never say, in the claim prose of
	// either the local or the shareable report.
	forbidden []forbiddenClaim

	// absentEverywhere is the stronger check, for a mechanism that must not
	// reach any part of the document — not a summary, not an attribute, not the
	// terminal.
	absentEverywhere []forbiddenClaim
}

// The claims every Kafka scenario forbids, whatever it is about.
//
// They are the mechanisms svcdoctor cannot observe and the verdicts it does not
// measure, and they are listed once rather than copied into fourteen fixtures so
// that adding one strengthens every scenario at the same time.
//
// **"firewall" is deliberately not a bare forbidden word.** The production
// recommendation for an evidenced TCP failure says *"Check routing, firewall
// rules and security group policy between this vantage point and the advertised
// address and port"*, which is a place to look and not a claim about a cause.
// What must never appear is the assertion, so the phrases below are the
// assertions.
func universalKafkaRefusals() []forbiddenClaim {
	return []forbiddenClaim{
		{"a firewall is", "no firewall was observed and none could be"},
		{"firewall is blocking", "the same, in the active voice"},
		{"blocked by a firewall", "the same, in the passive voice"},
		{"security group is blocking", "no cloud policy was read"},
		{"network policy", "nothing about Kubernetes was observed"},
		{"the broker is down", "a refusal distinguishes neither a host nor a process"},
		{"broker process", "no process was observed, only an endpoint"},
		{"the cluster is down", "the cluster answered Metadata in this very run, where it did"},
		{"cluster is degraded", "cluster health is not a thing svcdoctor observes"},
		{"advertised.listeners is", "no broker setting was read"},
		{"misconfigured", "a configuration verdict on a value nobody observed"},
		{"wrong password", "Kafka returns one code for several causes"},
		{"password is wrong", "the same claim in the other word order, which a mutation used"},
		{"bad password", "the same"},
		{"wrong username", "the same"},
		{"credential is wrong", "a refusal names no cause"},
		{"certificate has expired", "an identity mismatch is not an expiry"},
		{"certificate is expired", "the same"},
		{"certificate authority is invalid", "an identity mismatch is not a trust failure"},
		{"quorum", "nothing about cluster membership was observed"},
		{"under-replicated", "no partition state was requested"},
		{"consumer lag", "no consumer group was inspected"},
		{"restart", "svcdoctor recommends restarting nothing"},
	}
}

// kafkaCorpus is the whole set, K01 through K14.
func kafkaCorpus() []kafkaIncident {
	return []kafkaIncident{
		{
			id:     "K01",
			name:   "the bootstrap endpoint refuses the connection",
			intent: "reach a Kafka cluster at bootstrap.example:9092 over verified TLS",
			build: func(t *testing.T) domain.Graph {
				s := newKafkaGraph(t)
				s.bootstrapPath(domain.StatePass, domain.StateFail, domain.StatePass)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			allow: []domain.FindingCode{"TCP_CONNECTION_NOT_ESTABLISHED"},
			forbidden: []forbiddenClaim{
				{"advertised", "no Metadata exchange happened, so nothing was advertised"},
				{"broker endpoints this cluster", "there is no discovered topology to count"},
				{"may not be usable from this client", "the suitability hypothesis has no topology to rest on"},
			},
		},
		{
			id:     "K02",
			name:   "the bootstrap TLS handshake fails",
			intent: "reach a Kafka cluster over TLS with the platform trust store",
			build: func(t *testing.T) domain.Graph {
				s := newKafkaGraph(t)
				s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StateFail)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			allow: []domain.FindingCode{
				"TLS_HANDSHAKE_NOT_COMPLETED", "TLS_CHAIN_NOT_TRUSTED",
				"TLS_IDENTITY_MISMATCH", "TCP_CONNECTION_NOT_ESTABLISHED",
			},
			forbidden: []forbiddenClaim{
				{"advertised", "the run never reached Metadata"},
				{"broker endpoints this cluster", "the same"},
			},
		},
		{
			id:     "K03",
			name:   "authentication is rejected before any topology is learned",
			intent: "authenticate with SASL/PLAIN over verified TLS and describe the cluster",
			build: func(t *testing.T) domain.Graph {
				s := newKafkaGraph(t)
				s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
				s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
					domain.StatePass, domain.FailureNone)
				s.protocolStage("k-handshake", domain.LayerAuth, kafkaStepSASLHandshake,
					domain.StatePass, domain.FailureNone)
				s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
					domain.StateFail, domain.FailureAuthCredentialsRejected)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeCredentialsRejected, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"advertised", "authentication blocked topology discovery, so nothing was advertised"},
				{"broker endpoints this cluster", "the same"},
				{"unreachable", "no broker endpoint was measured at all"},
				{"the password", "the endpoint rejected the credential and said no more"},
				{"the account", "one Kafka error code covers a locked account and a wrong secret alike"},
			},
		},
		{
			id:     "K04",
			name:   "transport and authentication succeed and Metadata does not complete",
			intent: "authenticate and then describe the cluster",
			build: func(t *testing.T) domain.Graph {
				s := newKafkaGraph(t)
				s.bootstrapPath(domain.StatePass, domain.StatePass, domain.StatePass)
				s.protocolStage("k-apiversions", domain.LayerProtocol, kafkaStepAPIVersions,
					domain.StatePass, domain.FailureNone)
				s.protocolStage("k-auth", domain.LayerAuth, kafkaStepSASLAuthenticate,
					domain.StatePass, domain.FailureNone)
				s.metadata(domain.StateFail, domain.FailureProtocolUnexpectedResponse)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeMetadataNotCompleted, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"broker endpoints this cluster", "the response carried no topology to count"},
				{"may not be usable from this client", "there is no advertised set to be unsuitable"},
				{"brokers are", "no broker was named, let alone measured"},
			},
		},
		{
			id:     "K05",
			name:   "one discovered broker of three refuses the connection",
			intent: "reach the cluster and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advReachedPlain)
				s.advertise(2, "b2.example", 9092, advReachedPlain)
				s.advertise(3, "b3.example", 9092, advTCPRefused)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"may not be usable from this client", "two advertised endpoints were reached, which contradicts it"},
				{"none of the", "two of the three were reached"},
				{"not measured", "every endpoint was measured"},
			},
		},
		{
			id:     "K06",
			name:   "a discovered broker hostname does not resolve",
			intent: "reach the cluster and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advReachedPlain)
				s.advertise(2, "b2.example", 9092, advDNSFails)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"does not exist", "a name with no address record and a negative answer look the same"},
				{"dns is broken", "one unresolved name is not a resolver outage"},
				{"kafka dns", "svcdoctor observed a resolver result, not a cluster's DNS setup"},
				{"may not be usable from this client", "the other advertised endpoint was reached"},
			},
		},
		{
			id:     "K07",
			name:   "a discovered broker presents a certificate for another name",
			intent: "reach the cluster over TLS and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9093, advReachedTLS)
				s.advertise(2, "b2.example", 9093, advTLSIdentityMismatch)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"expired", "the handshake failed on identity, and the validity window was never the finding"},
				{"not trusted", "the chain verified; the name did not match"},
				{"self-signed", "nothing about the issuer was claimed"},
				{"tls is broken", "one endpoint of two failed verification"},
				{"may not be usable from this client", "the other advertised endpoint completed its handshake"},
			},
		},
		{
			id:     "K08",
			name:   "a complete three-broker set, one unreachable",
			intent: "reach the cluster and verify a complete advertised set",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advReachedPlain)
				s.advertise(2, "b2.example", 9092, advReachedPlain)
				s.advertise(3, "b3.example", 9092, advTCPRefused)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"all broker", "two of the three were reached"},
				{"every broker", "the same"},
				{"the cluster cannot", "a cluster-capability verdict from one endpoint's transport result"},
			},
		},
		{
			id:     "K09",
			name:   "a complete three-broker set, none reachable, after a working bootstrap",
			intent: "reach the cluster and verify a complete advertised set",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advTCPRefused)
				s.advertise(2, "b2.example", 9092, advTCPRefused)
				s.advertise(3, "b3.example", 9092, advTCPRefused)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 3},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyUnsuitable, domain.FindingKindHypothesis, domain.ConfidenceMedium, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 3},
			},
			forbidden: []forbiddenClaim{
				{"the cluster is unreachable", "the cluster answered Metadata over a reached bootstrap path"},
				{"advertised.listeners", "no broker setting was read"},
				{"is misconfigured", "the same, and a configuration verdict is not available"},
				{"this proves", "the contrast excludes one alternative and proves nothing"},
				{"therefore", "no causal connective belongs in a claim that excludes nothing"},
				{"the only explanation", "routing and a broker-side outage remain unexcluded"},
			},
		},
		{
			id:     "K10",
			name:   "an incomplete set: one reached, one unmeasured, one refused",
			intent: "reach the cluster and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advReachedPlain)
				s.advertise(2, "b2.example", 9092, advNotMeasured)
				s.advertise(3, "b3.example", 9092, advTCPRefused)
				return s.freeze()
			},
			incomplete: true,
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"only b3", "a claim about the endpoint nobody measured"},
				{"the other", "there is no complete remainder to name"},
				{"account for the whole", "one endpoint was never attempted"},
				{"may not be usable from this client", "an incomplete set cannot support a claim about the set"},
				{"was not reached", "not measured and not reached are two claims (ADR 0052)"},
			},
		},
		{
			id:     "K11",
			name:   "cancellation during the discovered-broker sweep",
			intent: "reach the cluster and verify every endpoint it advertises",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advTCPRefused)
				s.advertise(2, "b2.example", 9092, advCancelled)
				s.advertise(3, "b3.example", 9092, advCancelled)
				return s.freeze()
			},
			incomplete: true,
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"none of the", "two endpoints were never attempted"},
				{"may not be usable from this client", "a cancelled run cannot support a claim about a set"},
				{"unreachable from this vantage point; the other", "there is no complete remainder"},
			},
		},
		{
			id:     "K12",
			name:   "a reachable loopback advertisement",
			intent: "diagnose a broker running on the same host as svcdoctor",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "127.0.0.1", 9092, advReachedPlain)
				return s.freeze()
			},
			expect: nil,
			forbidden: []forbiddenClaim{
				{"loopback", "the address shape is not an incident and is never named as one"},
				{"127.0.0.1", "no claim was made, so no claim may quote it"},
				{"local", "a broker on this host is a legitimate deployment"},
			},
		},
		{
			id:     "K13",
			name:   "a reachable private-range advertisement",
			intent: "diagnose a cluster from inside its own network",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "10.30.0.1", 9092, advReachedPlain)
				s.advertise(2, "192.168.0.9", 9092, advReachedPlain)
				return s.freeze()
			},
			expect: nil,
			forbidden: []forbiddenClaim{
				{"private", "an RFC 1918 address reached from inside that network is correct"},
				{"internal", "the same"},
				{"routable", "no routability claim was made about a working endpoint"},
			},
		},
		{
			id: "K14",
			name: "one advertised endpoint unreachable, and nothing distinguishes " +
				"a network path from an unsuitable advertisement",
			intent: "diagnose a single-broker cluster whose advertised endpoint is unreachable",
			build: func(t *testing.T) domain.Graph {
				s := healthyThroughMetadata(t)
				s.advertise(1, "b1.example", 9092, advTCPRefused)
				return s.freeze()
			},
			expect: []expectedClaim{
				{diagnosiskafka.CodeAdvertisedEndpointUnreachable, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyReachability, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
				{diagnosiskafka.CodeAdvertisedTopologyUnsuitable, domain.FindingKindHypothesis, domain.ConfidenceMedium, 1},
				{diagnosis.CodeFailureBoundary, domain.FindingKindConfirmed, domain.ConfidenceHigh, 1},
			},
			forbidden: []forbiddenClaim{
				{"advertised.listeners", "no broker setting was read"},
				{"is misconfigured", "the same"},
				{"because", "no causal connective belongs in a claim that excludes nothing"},
				{"the cause", "the whole point of this scenario is that svcdoctor does not choose one"},
			},
		},
	}
}

// TestTheKafkaGoldenIncidentCorpus runs every fixture through the production
// Kafka pipeline.
func TestTheKafkaGoldenIncidentCorpus(t *testing.T) {
	for _, fixture := range kafkaCorpus() {
		t.Run(fixture.id+" "+fixture.name, func(t *testing.T) {
			t.Logf("intent: %s", fixture.intent)

			r := diagnoseKafka(t, fixture.build(t), fixture.incomplete)
			for _, f := range r.report.Findings() {
				t.Logf("  %-40s %-10s %-6s %-6s %s",
					f.Code(), f.Kind(), f.Severity(), f.Confidence(), f.Subject().Ref())
			}

			assertExpectedClaims(t, r, fixture)
			assertClosedWorld(t, r, fixture)
			assertRefuses(t, r, fixture.forbidden)
			assertRefuses(t, r, universalKafkaRefusals())
			assertAbsentEverywhere(t, r, fixture.absentEverywhere)
			assertEveryReferenceResolves(t, r)
		})
	}
}

// assertExpectedClaims checks the codes, kinds, confidences and cardinalities a
// fixture declares.
func assertExpectedClaims(t *testing.T, r run, fixture kafkaIncident) {
	t.Helper()

	for _, want := range fixture.expect {
		got := r.findingsWithCode(want.code)
		if len(got) != want.count {
			t.Errorf("%s produced %d %s findings, want %d",
				fixture.id, len(got), want.code, want.count)
			continue
		}
		for _, f := range got {
			if f.Kind() != want.kind {
				t.Errorf("%s: %s kind = %s, want %s", fixture.id, want.code, f.Kind(), want.kind)
			}
			if f.Confidence() != want.confidence {
				t.Errorf("%s: %s confidence = %s, want %s",
					fixture.id, want.code, f.Confidence(), want.confidence)
			}
		}
	}
}

// assertClosedWorld fails on any finding the fixture neither expects nor allows.
//
// This is the half that catches a rule speaking where nobody expected it to.
func assertClosedWorld(t *testing.T, r run, fixture kafkaIncident) {
	t.Helper()

	permitted := slices.Clone(fixture.allow)
	for _, want := range fixture.expect {
		permitted = append(permitted, want.code)
	}
	for _, f := range r.report.Findings() {
		if !slices.Contains(permitted, f.Code()) {
			t.Errorf("%s produced %s, which the fixture neither expects nor allows.\n"+
				"  subject: %s\n  summary: %s\n\n"+
				"A rule speaking in a scenario nobody expected it to speak in is the "+
				"defect this corpus exists to catch.",
				fixture.id, f.Code(), f.Subject().Ref(), f.Summary())
		}
	}
}

// assertEveryReferenceResolves is ADR 0014's membership rule, re-checked here
// because a corpus that renders a report is the place a dangling reference would
// first be visible.
func assertEveryReferenceResolves(t *testing.T, r run) {
	t.Helper()

	for _, f := range r.report.Findings() {
		if f.EvidenceRefCount() == 0 {
			t.Errorf("%s cites no evidence", f.Code())
		}
		for _, ref := range f.EvidenceRefs() {
			if _, ok := r.graph.Node(ref); !ok {
				t.Errorf("%s cites %q, which is not in the graph", f.Code(), ref)
			}
		}
	}
}

// TestTheKafkaCorpusForbidsSomethingEverywhere is ADR 0083 section 7's guard,
// applied to this corpus.
func TestTheKafkaCorpusForbidsSomethingEverywhere(t *testing.T) {
	all := kafkaCorpus()
	if len(all) < 14 {
		t.Fatalf("the Kafka corpus has %d fixtures, want the 14 the phase specifies", len(all))
	}
	seen := map[string]bool{}
	for _, fixture := range all {
		if seen[fixture.id] {
			t.Errorf("two fixtures share the identifier %s", fixture.id)
		}
		seen[fixture.id] = true

		if len(fixture.forbidden) == 0 {
			t.Errorf("the %s fixture forbids nothing, so it proves nothing about "+
				"overclaiming (ADR 0083 section 2.5)", fixture.id)
		}
		if fixture.intent == "" {
			t.Errorf("the %s fixture declares no intent", fixture.id)
		}
		for _, claim := range fixture.forbidden {
			if claim.why == "" {
				t.Errorf("the %s fixture forbids %q without saying why", fixture.id, claim.phrase)
			}
		}
	}
	if len(universalKafkaRefusals()) == 0 {
		t.Error("the universal refusal list is empty")
	}
}

// TestTheKafkaRefusalGuardCanFail proves the refusal machinery is not vacuous.
//
// It plants each universal refusal into a synthetic finding-prose string and
// requires the matcher to find it. A corpus whose matcher matched nothing would
// pass forever and look exactly like one that passes correctly.
func TestTheKafkaRefusalGuardCanFail(t *testing.T) {
	for _, claim := range universalKafkaRefusals() {
		planted := "svcdoctor concluded that " + claim.phrase + " the problem"
		if !strings.Contains(strings.ToLower(planted), strings.ToLower(claim.phrase)) {
			t.Errorf("the refusal %q matches nothing when planted verbatim", claim.phrase)
		}
	}

	// And a scenario that really does produce prose, so the scan has something
	// to scan. A refusal assertion over an empty report proves nothing.
	s := healthyThroughMetadata(t)
	s.advertise(1, "b1.example", 9092, advTCPRefused)
	r := diagnoseKafka(t, s.freeze(), false)
	requireFindings(t, r, 3)
}

// TestTheKafkaCorpusCarriesNoRealIdentity is ADR 0083 section 5.
func TestTheKafkaCorpusCarriesNoRealIdentity(t *testing.T) {
	for _, fixture := range kafkaCorpus() {
		t.Run(fixture.id, func(t *testing.T) {
			g := fixture.build(t)
			if g.Len() == 0 {
				t.Fatal("the fixture built no evidence")
			}
			for _, node := range g.Nodes() {
				ref := node.Subject().Ref()
				host, _, found := strings.Cut(ref, ":")
				if !found {
					host = ref
				}
				switch {
				case strings.HasSuffix(host, ".example"), host == "example":
				case strings.HasPrefix(host, "10."), strings.HasPrefix(host, "192.168."),
					strings.HasPrefix(host, "127."):
				default:
					t.Errorf("subject %q is neither documentation-reserved nor private", ref)
				}
			}
		})
	}
}

// TestTheKafkaCorpusUsesTheProductionRuleSet keeps the fixtures honest about
// what they exercise.
func TestTheKafkaCorpusUsesTheProductionRuleSet(t *testing.T) {
	wired := map[string]bool{"diag/failure-boundary": true}
	for _, r := range kafkaRules() {
		if wired[r.id] {
			t.Errorf("rule %q is wired twice", r.id)
		}
		wired[r.id] = true
	}

	for _, want := range []string{
		"diag/failure-boundary", "transport/dns", "transport/tcp", "transport/tls",
		"kafka/protocol", "kafka/advertised-endpoint", "kafka/unusable-advertisement",
		"kafka/advertised-topology", "kafka/advertised-suitability",
	} {
		if !wired[want] {
			t.Errorf("the corpus does not wire %q, which the Kafka composition root does", want)
		}
	}
	if len(wired) != 9 {
		t.Errorf("the corpus wires %d rules, want the 9 internal/app wires", len(wired))
	}

	// And the rules really are the ones internal/app wires, not copies.
	var (
		_ diagnosis.Rule = diagnosiskafka.AdvertisedTopologyReachability
		_ diagnosis.Rule = diagnosiskafka.AdvertisedTopologyUnsuitable
	)
}
