package terminal

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7 — rendering a run that resolved nothing.
//
// The renderer is told which of the two shapes it has by the graph, never by
// inspecting a subject string or parsing an evidence identifier. These tests
// pin that both shapes render, that neither invents the other's rows, and that
// an IPv6 endpoint survives with exactly one pair of brackets.

// literalKafka builds a Kafka graph whose bootstrap target was an address: no
// L1 node, and the connection is the root of its path.
func literalKafka(t *testing.T, target, address string) *kafkaGraph {
	t.Helper()
	g := &kafkaGraph{t: t, b: newBuilder(t)}
	g.b.service = "kafka"
	g.b.requested = target
	// bootstrap stays empty: chain() from "" makes the connection a root, which
	// is exactly what a resolution-free sweep produces.
	g.chain("", address,
		passed(vocabulary.StepTCPConnect, 900),
		passed(vocabulary.StepTLSHandshake, 4000),
		passed(servicekafka.StepAPIVersions, 1200),
		passed(servicekafka.StepSASLHandshake, 800),
		passed(servicekafka.StepSASLAuthenticate, 2100),
		passed(servicekafka.StepMetadata, 1500),
	)
	return g
}

// A literal requested target renders no DNS row, because there is no DNS node.
func TestALiteralTargetRendersNoDNSRow(t *testing.T) {
	for _, tc := range []struct{ target, address string }{
		{"10.20.30.40:9093", "10.20.30.40:9093"},
		{"[2001:db8::40]:9093", "[2001:db8::40]:9093"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			g := literalKafka(t, tc.target, tc.address)
			out := renderKafka(t, g.report(), false)

			if strings.Contains(out, "DNS") {
				t.Fatalf("a literal run rendered a DNS row:\n%s", out)
			}
			if !strings.Contains(out, tc.target) {
				t.Fatalf("the requested target is missing:\n%s", out)
			}
			if !strings.Contains(out, "TCP") {
				t.Fatalf("the transport path did not render:\n%s", out)
			}
		})
	}
}

// A name still renders its DNS row. Removing the row unconditionally would pass
// the test above and lose a real measurement.
func TestANamedTargetStillRendersItsDNSRow(t *testing.T) {
	g := healthyKafka(t)
	out := renderKafka(t, g.report(), false)

	if !strings.Contains(out, "DNS") {
		t.Fatalf("a named run lost its DNS row:\n%s", out)
	}
}

// An IPv6 endpoint keeps exactly one pair of brackets everywhere it appears, and
// no line ever shows a bare colon-separated IPv6 host and port.
func TestIPv6EndpointsRenderBracketSafe(t *testing.T) {
	g := literalKafka(t, "[2001:db8::40]:9093", "[2001:db8::40]:9093")
	out := renderKafka(t, g.report(), false)

	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "2001:db8::40") {
			continue
		}
		if strings.Contains(line, "[[") || strings.Contains(line, "]]") {
			t.Errorf("double brackets: %q", line)
		}
		if strings.Contains(line, "2001:db8::40:9093") {
			t.Errorf("an unbracketed IPv6 endpoint: %q", line)
		}
		if !strings.Contains(line, "[2001:db8::40]") {
			t.Errorf("an IPv6 host without brackets: %q", line)
		}
	}
}

// --- advertised literals ---------------------------------------------------

// kafkaWithMetadata is one bootstrap path that obtained metadata, and no
// advertisements: each test below adds exactly the ones it is about.
func kafkaWithMetadata(t *testing.T) *kafkaGraph {
	t.Helper()
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, withAuth(passed(auth, 94), passed(meta, 90))...)
	return g
}

// literalSweep records the resolution-free sweep of one advertisement: the
// connection hangs straight off it, with no lookup between.
func (g *kafkaGraph) literalSweep(ad domain.EvidenceID, address string, stages ...stage) {
	g.t.Helper()
	g.chain(ad, address, stages...)
}

// A reachable advertised literal counts as reached. Reading "no lookup" as "not
// measured" would have understated every cluster that advertises addresses.
func TestAReachedAdvertisedLiteralIsCountedReached(t *testing.T) {
	g := kafkaWithMetadata(t)
	ad := g.advertisement(1, "10.20.30.41:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(ad, "10.20.30.41:9093",
		passed(vocabulary.StepTCPConnect, 700),
		passed(vocabulary.StepTLSHandshake, 3000),
	)

	out := renderKafka(t, g.report(), false)
	if !strings.Contains(out, "1 of 1 advertised broker endpoints reached") {
		t.Fatalf("the topology line did not count the literal as reached:\n%s", out)
	}
	if strings.Contains(out, "not measured") {
		t.Fatalf("a measured literal was reported as not measured:\n%s", out)
	}
}

// An unreachable advertised literal is reached-count 0, and still not "not
// measured": the two remain distinct.
func TestAnUnreachableAdvertisedLiteralIsNotCalledUnmeasured(t *testing.T) {
	g := kafkaWithMetadata(t)
	ad := g.advertisement(1, "10.20.30.41:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(ad, "10.20.30.41:9093",
		failed(vocabulary.StepTCPConnect, domain.FailureTCPConnectionRefused, 700),
		skipped(vocabulary.StepTLSHandshake, domain.FailureExecSkippedPrerequisiteFailed),
	)

	out := renderKafka(t, g.report(), false)
	if !strings.Contains(out, "0 of 1 advertised broker endpoints reached") {
		t.Fatalf("the topology line is wrong:\n%s", out)
	}
	if strings.Contains(out, "not measured") {
		t.Fatalf("a positively-observed failure was reported as not measured:\n%s", out)
	}
}

// An advertisement whose sweep never began is still "not measured". The literal
// shape must not have collapsed that distinction.
func TestAnAdvertisementWithNoSweepIsStillNotMeasured(t *testing.T) {
	g := kafkaWithMetadata(t)
	g.advertisement(1, "10.20.30.41:9093", domain.StatePass, domain.FailureNone)

	out := renderKafka(t, g.report(), false)
	if !strings.Contains(out, "not measured") {
		t.Fatalf("an unswept advertisement lost its 'not measured' marker:\n%s", out)
	}
}

// A locally-timed-out literal advertisement is not measured, never unreachable.
func TestALocallyTimedOutAdvertisedLiteralIsNotMeasured(t *testing.T) {
	g := kafkaWithMetadata(t)
	ad := g.advertisement(1, "10.20.30.41:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(ad, "10.20.30.41:9093",
		unknownAt(vocabulary.StepTCPConnect, domain.FailureExecLocalTimeout,
			domain.Measured(10*time.Second)),
	)

	out := renderKafka(t, g.report(), false)
	if !strings.Contains(out, "not measured") {
		t.Fatalf("a local timeout was not reported as unmeasured:\n%s", out)
	}
	if strings.Contains(out, "1 of 1 advertised broker endpoints reached") {
		t.Fatalf("a local timeout was counted as reached:\n%s", out)
	}
}

// The topology counts one coherent set whatever kind each advertisement is.
func TestAMixedAdvertisedTopologyCountsOneSet(t *testing.T) {
	g := kafkaWithMetadata(t)

	named := g.advertisement(1, "broker1.internal:9093", domain.StatePass, domain.FailureNone)
	g.sweep(named, "broker1.internal", "198.51.100.20:9093",
		passed(vocabulary.StepDNSLookup, 1500),
		[]stage{
			passed(vocabulary.StepTCPConnect, 700),
			passed(vocabulary.StepTLSHandshake, 3000),
		})

	four := g.advertisement(2, "10.20.30.42:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(four, "10.20.30.42:9093",
		passed(vocabulary.StepTCPConnect, 700),
		passed(vocabulary.StepTLSHandshake, 3000),
	)

	six := g.advertisement(3, "[2001:db8::42]:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(six, "[2001:db8::42]:9093",
		failed(vocabulary.StepTCPConnect, domain.FailureTCPConnectionRefused, 700),
		skipped(vocabulary.StepTLSHandshake, domain.FailureExecSkippedPrerequisiteFailed),
	)

	out := renderKafka(t, g.report(), false)
	if !strings.Contains(out, "2 of 3 advertised broker endpoints reached") {
		t.Fatalf("the mixed topology did not count as one set:\n%s", out)
	}
	for _, want := range []string{"broker1.internal:9093", "10.20.30.42:9093", "[2001:db8::42]:9093"} {
		if !strings.Contains(out, want) {
			t.Errorf("the topology omits %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[[") || strings.Contains(out, "]]") {
		t.Errorf("double brackets in a mixed topology:\n%s", out)
	}
}

// The renderer must reach both shapes without parsing an identifier or a
// subject. A literal advertisement renders its transport rows, and no DNS row.
func TestAnAdvertisedLiteralRendersTransportWithoutADNSRow(t *testing.T) {
	g := kafkaWithMetadata(t)
	ad := g.advertisement(1, "10.20.30.41:9093", domain.StatePass, domain.FailureNone)
	g.literalSweep(ad, "10.20.30.41:9093",
		failed(vocabulary.StepTCPConnect, domain.FailureTCPConnectionRefused, 700),
		skipped(vocabulary.StepTLSHandshake, domain.FailureExecSkippedPrerequisiteFailed),
	)

	out := renderKafka(t, g.report(), false)
	block := advertisementBlock(t, out, "10.20.30.41:9093")
	if strings.Contains(block, "DNS") {
		t.Fatalf("a literal advertisement rendered a DNS row:\n%s", block)
	}
	if !strings.Contains(block, "TCP_CONNECTION_REFUSED") {
		t.Fatalf("the advertised literal's transport did not render:\n%s", block)
	}
}

// advertisementBlock returns the lines belonging to one advertisement, so a test
// about one endpoint cannot accidentally read a sibling's rows.
func advertisementBlock(t *testing.T, out, endpoint string) string {
	t.Helper()

	start := strings.Index(out, endpoint)
	if start < 0 {
		t.Fatalf("the output does not mention %s:\n%s", endpoint, out)
	}
	rest := out[start+len(endpoint):]
	if end := strings.Index(rest, "Advertised broker"); end >= 0 {
		rest = rest[:end]
	}
	if end := strings.Index(rest, "\nFindings"); end >= 0 {
		rest = rest[:end]
	}
	return rest
}
