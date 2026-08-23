package terminal

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The sixteen Kafka scenarios, each rendered whole and compared byte for byte.

// The journey steps, abbreviated so a fixture reads as a journey.
var (
	tcp      = vocabulary.StepTCPConnect
	tlsStep  = vocabulary.StepTLSHandshake
	versions = servicekafka.StepAPIVersions
	mech     = servicekafka.StepSASLHandshake
	auth     = servicekafka.StepSASLAuthenticate
	meta     = servicekafka.StepMetadata
)

// discovery is the credential-free part every bootstrap path performs.
func discovery() []stage {
	return []stage{passed(tcp, 190), passed(tlsStep, 1700), passed(versions, 155), passed(mech, 88)}
}

// withAuth appends the stages only the continued path holds.
func withAuth(extra ...stage) []stage {
	return append(discovery(), extra...)
}

// healthyKafka is one bootstrap path that obtains metadata, and two brokers.
func healthyKafka(t *testing.T) *kafkaGraph {
	t.Helper()
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
	one := g.advertisement(1, "broker-1.internal:9093", domain.StatePass, domain.FailureNone)
	g.sweep(one, "broker-1.internal:9093", "198.51.100.21:9093", passed(vocabulary.StepDNSLookup, 160),
		[]stage{passed(tcp, 130), passed(tlsStep, 709)})
	two := g.advertisement(2, "broker-2.internal:9093", domain.StatePass, domain.FailureNone)
	g.sweep(two, "broker-2.internal:9093", "198.51.100.22:9093", passed(vocabulary.StepDNSLookup, 150),
		[]stage{passed(tcp, 141), passed(tlsStep, 688)})
	return g
}

// stopAt builds a bootstrap journey that ends on one non-passing stage.
func stopAt(t *testing.T, s stage, before ...stage) *kafkaGraph {
	t.Helper()
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, append(before, s)...)
	return g
}

// kafkaFinding builds one finding with the layer its owning rule assigns.
func kafkaFinding(
	t *testing.T, code string, severity domain.Severity, layer domain.Layer, subject string,
) domain.Finding {
	t.Helper()

	subj, err := domain.NewEndpointSubject(subject)
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	recommendation, err := domain.NewRecommendation("Check the thing the finding names")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	f, err := domain.NewFinding(domain.FindingInput{
		Code: domain.FindingCode(code), Kind: domain.FindingKindConfirmed,
		Severity: severity, Confidence: domain.ConfidenceHigh, Layer: layer,
		Subject: subj, Summary: "A one-line summary", Detail: "A detail line.",
		EvidenceRefs:    []domain.EvidenceID{"dns.lookup/kafka.internal"},
		Recommendations: []domain.Recommendation{recommendation},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

func TestKafkaGoldenTerminalOutput(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		report     func(*testing.T) domain.Report
		incomplete bool
	}{
		{
			// 1. A healthy PLAIN run: metadata obtained, every broker reached.
			name: "healthy PLAIN", file: "kafka-healthy-plain.txt",
			report: func(t *testing.T) domain.Report { return healthyKafka(t).report() },
		},
		{
			// 2. SCRAM-SHA-256 renders identically: the mechanism is a protocol
			// parameter, and no stage row names it. Which mechanism was
			// negotiated is an attribute on the node and a fact in the JSON, not
			// a word in the tree.
			name: "healthy SCRAM-SHA-256", file: "kafka-healthy-scram.txt",
			report: func(t *testing.T) domain.Report { return healthyKafka(t).report() },
		},
		{
			// 3. No credential configured: OK, complete, WARN, no metadata.
			name: "no credential", file: "kafka-no-credential.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, skipped(auth, domain.FailureExecRequiredInputMissing), discovery()...)
				return g.report(kafkaFinding(t, "KAFKA_CREDENTIAL_NOT_CONFIGURED",
					domain.SeverityWarn, domain.LayerAuth, addrOne))
			},
		},
		{
			// 4. The broker rejected the credential.
			name: "wrong credential", file: "kafka-wrong-credential.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, failed(auth, domain.FailureAuthCredentialsRejected, 120), discovery()...)
				return g.report(kafkaFinding(t, "KAFKA_CREDENTIALS_REJECTED",
					domain.SeverityError, domain.LayerAuth, addrOne))
			},
		},
		{
			// 5. svcdoctor cannot perform the mechanism. UNKNOWN, not FAIL: the
			// endpoint was not asked and nothing about it was proven.
			name: "mechanism unsupported by svcdoctor", file: "kafka-mechanism-unsupported.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t,
					unknownAt(auth, domain.FailureAuthMechanismUnsupported, domain.Unmeasured()),
					discovery()...)
				return g.report(kafkaFinding(t, "KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR",
					domain.SeverityInfo, domain.LayerAuth, addrOne))
			},
		},
		{
			// 6. The endpoint does not offer the mechanism that was asked for.
			name: "mechanism not offered", file: "kafka-mechanism-not-offered.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, failed(mech, domain.FailureAuthMechanismNotOffered, 70),
					passed(tcp, 190), passed(tlsStep, 1700), passed(versions, 155))
				return g.report(kafkaFinding(t, "KAFKA_AUTH_MECHANISM_NOT_OFFERED",
					domain.SeverityError, domain.LayerAuth, addrOne))
			},
		},
		{
			// 7. The channel was not verified, so the policy withheld the
			// credential and zero bytes derived from it were written.
			name: "credential withheld", file: "kafka-credential-withheld.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, skipped(auth, domain.FailureExecSkippedByPolicy), discovery()...)
				return g.report(kafkaFinding(t, "KAFKA_CREDENTIAL_WITHHELD",
					domain.SeverityWarn, domain.LayerAuth, addrOne))
			},
		},
		{
			// 8. Peer verification failed. **Not** a rejected credential: the
			// server's proof did not verify, so svcdoctor refuses to say the
			// password was wrong.
			name: "peer verification failure", file: "kafka-peer-verification.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, failed(auth, domain.FailureAuthPeerVerificationFailed, 130),
					discovery()...)
				return g.report(kafkaFinding(t, "KAFKA_PEER_VERIFICATION_FAILED",
					domain.SeverityError, domain.LayerAuth, addrOne))
			},
		},
		{
			// 9. The capability exchange itself broke.
			name: "API versions failure", file: "kafka-apiversions-failure.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, failed(versions, domain.FailureProtocolPeerClosed, 40),
					passed(tcp, 190), passed(tlsStep, 1700))
				return g.report(kafkaFinding(t, "KAFKA_API_VERSIONS_NOT_COMPLETED",
					domain.SeverityError, domain.LayerProtocol, addrOne))
			},
		},
		{
			// 10. Authentication passed and the Metadata exchange broke.
			name: "Metadata failure", file: "kafka-metadata-failure.txt",
			report: func(t *testing.T) domain.Report {
				g := stopAt(t, failed(meta, domain.FailureProtocolMalformedResponse, 60),
					withAuth(passed(auth, 94))...)
				return g.report(kafkaFinding(t, "KAFKA_METADATA_NOT_COMPLETED",
					domain.SeverityError, domain.LayerTopology, addrOne))
			},
		},
		{
			// 11. Every advertised endpoint refused: 0 of 2 reached.
			name: "advertised endpoint unreachable", file: "kafka-advertised-unreachable.txt",
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				for _, b := range []struct {
					id            int64
					name, address string
				}{
					{1, "broker-1.internal:9093", "198.51.100.21:9093"},
					{2, "broker-2.internal:9093", "198.51.100.22:9093"},
				} {
					ad := g.advertisement(b.id, b.name, domain.StatePass, domain.FailureNone)
					g.sweep(ad, b.name, b.address, passed(vocabulary.StepDNSLookup, 160),
						[]stage{failed(tcp, domain.FailureTCPConnectionRefused, 210)})
				}
				return g.report(
					kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
						domain.SeverityError, domain.LayerTCP, "broker-1.internal:9093"),
					kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
						domain.SeverityError, domain.LayerTCP, "broker-2.internal:9093"))
			},
		},
		{
			// 12. The cluster named an endpoint it could not state usably. No
			// sweep runs, and the advertisement is not "not measured": there was
			// nothing to measure.
			name: "unusable advertisement", file: "kafka-unusable-advertisement.txt",
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				g.advertisement(7, "broker-7.internal:0",
					domain.StateFail, domain.FailureProtocolUnexpectedResponse)
				ok := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(ok, "broker-1.internal:9093", "198.51.100.21:9093", passed(vocabulary.StepDNSLookup, 160),
					[]stage{passed(tcp, 130), passed(tlsStep, 709)})
				return g.report(kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNUSABLE",
					domain.SeverityError, domain.LayerTopology, "broker-7.internal:0"))
			},
		},
		{
			// 13. One broker reached, one refused. Complete: both verdicts were
			// positively observed.
			name: "partial advertised reachability", file: "kafka-advertised-partial.txt",
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				one := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(one, "broker-1.internal:9093", "198.51.100.21:9093",
					passed(vocabulary.StepDNSLookup, 160),
					[]stage{passed(tcp, 130), passed(tlsStep, 709)})
				two := g.advertisement(2, "broker-2.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(two, "broker-2.internal:9093", "198.51.100.22:9093", passed(vocabulary.StepDNSLookup, 150),
					[]stage{failed(tcp, domain.FailureTCPConnectionRefused, 210)})
				return g.report(kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
					domain.SeverityError, domain.LayerTCP, "broker-2.internal:9093"))
			},
		},
		{
			// 14. One broker reached, one svcdoctor's budget never finished
			// measuring. `not measured`, never `not reached`, and the run is
			// INCOMPLETE.
			name: "incomplete advertised sweep", file: "kafka-advertised-incomplete.txt",
			incomplete: true,
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				one := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(one, "broker-1.internal:9093", "198.51.100.21:9093",
					passed(vocabulary.StepDNSLookup, 160),
					[]stage{passed(tcp, 130), passed(tlsStep, 709)})
				two := g.advertisement(2, "broker-2.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(two, "broker-2.internal:9093", "198.51.100.22:9093", passed(vocabulary.StepDNSLookup, 150),
					[]stage{unknownAt(tcp, domain.FailureExecLocalTimeout, measured(80000))})
				return g.report()
			},
		},
		{
			// 15. Two resolved bootstrap addresses, one selected. The unselected
			// one is measured through discovery and carries no failure.
			name: "multiple bootstrap paths", file: "kafka-multipath.txt",
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				g.bootstrapPath(addrTwo, discovery()...)
				ad := g.advertisement(1, "broker-1.internal:9093",
					domain.StatePass, domain.FailureNone)
				g.sweep(ad, "broker-1.internal:9093", "198.51.100.21:9093", passed(vocabulary.StepDNSLookup, 160),
					[]stage{passed(tcp, 130), passed(tlsStep, 709)})
				return g.report()
			},
		},
		{
			// 16. The shareable projection of a Kafka report. Built here rather
			// than through internal/security/redaction, which a renderer may not
			// import: the endpoints are already pseudonyms and the header comes
			// from the report's own security metadata.
			name: "shareable", file: "kafka-shareable.txt",
			report: func(t *testing.T) domain.Report {
				g := newKafkaGraph(t)
				g.b.shareable = true
				g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
				ad := g.advertisement(2, "host-002:9093", domain.StatePass, domain.FailureNone)
				g.sweep(ad, "host-002:9093", "host-004:9093", passed(vocabulary.StepDNSLookup, 160),
					[]stage{failed(tcp, domain.FailureTCPConnectionRefused, 210)})
				return g.report(kafkaFinding(t, "KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE",
					domain.SeverityError, domain.LayerTCP, "host-002:9093"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireKafkaGolden(t, tt.file, renderKafka(t, tt.report(t), tt.incomplete))
		})
	}
}

// TestKafkaRenderingIsByteIdenticalAcrossRepeats re-renders every case.
func TestKafkaRenderingIsByteIdenticalAcrossRepeats(t *testing.T) {
	report := healthyKafka(t).report()
	first := renderKafka(t, report, false)
	for range 50 {
		if got := renderKafka(t, report, false); got != first {
			t.Fatal("re-rendering the same Kafka report produced different bytes")
		}
	}
	if strings.Count(first, "Path ") != 3 {
		t.Errorf("expected one bootstrap path and two advertised paths:\n%s", first)
	}
}
