package transport

import (
	"strconv"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The ADR 0043 acceptance matrix, row by row.
//
// Rows 20 through 25 — ownership — are proved here for the shapes a fixture can
// express, and again in internal/app and internal/adapter/kafka against graphs
// the production code actually produced. Rows 26 through 30 — report and
// redaction — belong to those packages entirely, because a rule cannot assemble
// a report.

// --- DNS, rows 1 to 6 ----------------------------------------------------------

func TestDNSFailureClassMapping(t *testing.T) {
	cases := []struct {
		name  string
		class domain.FailureClass
		want  domain.FindingCode
	}{
		{"row 1: no usable address", domain.FailureDNSNoAddress, CodeNameNotResolved},
		{"row 2: resolver timed out", domain.FailureDNSTimeout, CodeResolutionFailed},
		{"row 3: resolver failed", domain.FailureDNSResolverFailure, CodeResolutionFailed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			graph := requestedDNS(t, domain.StateFail, c.class)

			finding := requireOne(t, DNS(rctx(graph)), c.want)

			if got, want := finding.Subject().Ref(), "db.example.com:5432"; got != want {
				t.Errorf("subject = %q, want the logical endpoint %q", got, want)
			}
			if got := finding.Subject().Kind(); got != domain.SubjectKindTarget {
				t.Errorf("subject kind = %s, want TARGET", got)
			}
			if got := finding.Kind(); got != domain.FindingKindConfirmed {
				t.Errorf("kind = %s, want CONFIRMED", got)
			}
			if got := finding.Severity(); got != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got)
			}
			if got := finding.Confidence(); got != domain.ConfidenceHigh {
				t.Errorf("confidence = %s, want HIGH", got)
			}
			if !finding.VantageDependent() {
				t.Error("vantageDependent = false; resolution depends on this host's resolver")
			}
			if got := finding.Layer(); got != domain.LayerDNS {
				t.Errorf("layer = %s, want L1", got)
			}

			// The lookup alone: minimal sufficient proof.
			refs := finding.EvidenceRefs()
			if len(refs) != 1 || refs[0] != "dns.lookup/db.example.com" {
				t.Errorf("refs = %v, want the lookup node alone", refs)
			}

			// TCP withholds on the same graph: no connection was measured.
			requireNone(t, TCP(rctx(graph)))
		})
	}
}

func TestDNSWithholdsOnEveryNonFailure(t *testing.T) {
	cases := []struct {
		name  string
		state domain.State
		class domain.FailureClass
	}{
		{"row 4: budget expired", domain.StateUnknown, domain.FailureExecLocalTimeout},
		{"row 5: cancelled", domain.StateUnknown, domain.FailureExecCancelled},
		{"row 6: resolved", domain.StatePass, domain.FailureNone},
		{"skipped", domain.StateSkipped, domain.FailureExecSkippedPrerequisiteFailed},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			graph := requestedDNS(t, c.state, c.class)
			requireNone(t, DNS(rctx(graph)))
			requireNone(t, TCP(rctx(graph)))
		})
	}
}

// TestDNSWithholdsOnAnUnauthorizedClass pins the closed vocabulary.
//
// DNS_NXDOMAIN is the case that matters: the class exists, no producer emits it,
// and ADR 0043 wrote no mapping for it. A rule that guessed would be claiming
// non-existence — the exact claim the DNS probe refuses to make.
func TestDNSWithholdsOnAnUnauthorizedClass(t *testing.T) {
	for _, class := range []domain.FailureClass{
		domain.FailureDNSNXDomain,
		domain.FailureTCPConnectionRefused,
		domain.FailureProtocolMalformedResponse,
	} {
		t.Run(class.String(), func(t *testing.T) {
			requireNone(t, DNS(rctx(requestedDNS(t, domain.StateFail, class))))
		})
	}
}

// --- TCP, rows 7 to 19 ---------------------------------------------------------

func TestTCPAllPathsFailProducesOneFinding(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []connectOutcome
	}{
		{"row 7: one address refused", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused)}},
		{"row 8: all refused", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			fail("10.0.0.2", domain.FailureTCPConnectionRefused)}},
		{"row 9: all timed out", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionTimeout),
			fail("10.0.0.2", domain.FailureTCPConnectionTimeout)}},
		{"row 10: all network-unreachable", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPNetworkUnreachable),
			fail("10.0.0.2", domain.FailureTCPNetworkUnreachable)}},
		{"row 11: refused and timed out", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			fail("10.0.0.2", domain.FailureTCPConnectionTimeout)}},
		{"row 12: reset and host-unreachable", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionReset),
			fail("10.0.0.2", domain.FailureTCPHostUnreachable)}},
		{"refused and unclassifiable", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			fail("10.0.0.2", domain.FailureTCPConnectionFailed)}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			graph := requestedTCP(t, c.outcomes...)

			finding := requireOne(t, TCP(rctx(graph)), CodeConnectionNotEstablished)

			if got, want := finding.Subject().Ref(), "db.example.com:5432"; got != want {
				t.Errorf("subject = %q, want the logical endpoint %q", got, want)
			}
			if got := finding.Severity(); got != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got)
			}
			if got := finding.Layer(); got != domain.LayerTCP {
				t.Errorf("layer = %s, want L2", got)
			}
			if !finding.VantageDependent() {
				t.Error("vantageDependent = false")
			}

			// The lookup plus every failed connection, and nothing else.
			if got, want := len(finding.EvidenceRefs()), len(c.outcomes)+1; got != want {
				t.Errorf("got %d refs %v, want %d", got, finding.EvidenceRefs(), want)
			}

			// DNS withholds on the same graph: the lookup passed.
			requireNone(t, DNS(rctx(graph)))
		})
	}
}

// TestMixedFailureClassesProduceOneStableCode is the ADR 0043 section 5 promise,
// stated as a property rather than as four separate rows.
//
// Every pairing of authorized classes must yield the same public code. If any
// combination produced a different one, the machine contract would depend on
// which address family happened to fail how.
func TestMixedFailureClassesProduceOneStableCode(t *testing.T) {
	classes := []domain.FailureClass{
		domain.FailureTCPConnectionRefused,
		domain.FailureTCPConnectionReset,
		domain.FailureTCPConnectionTimeout,
		domain.FailureTCPNetworkUnreachable,
		domain.FailureTCPHostUnreachable,
		domain.FailureTCPConnectionFailed,
	}

	for _, first := range classes {
		for _, second := range classes {
			graph := requestedTCP(t,
				fail("10.0.0.1", first),
				fail("10.0.0.2", second),
			)
			finding := requireOne(t, TCP(rctx(graph)), CodeConnectionNotEstablished)
			if got := len(finding.EvidenceRefs()); got != 3 {
				t.Errorf("%s + %s: got %d refs, want 3", first, second, got)
			}
		}
	}
}

func TestTCPWithholdsWhenAnyPathSucceeds(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []connectOutcome
	}{
		{"row 13: IPv4 fails, IPv6 works", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			pass("[2001:db8::1]")}},
		{"row 14: IPv4 works, IPv6 fails", []connectOutcome{
			pass("10.0.0.1"),
			fail("[2001:db8::1]", domain.FailureTCPConnectionTimeout)}},
		{"row 19: one works, nineteen fail", oneOfTwenty(t)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireNone(t, TCP(rctx(requestedTCP(t, c.outcomes...))))
		})
	}
}

func TestTCPWithholdsWhenMeasurementIsIncomplete(t *testing.T) {
	cases := []struct {
		name     string
		outcomes []connectOutcome
	}{
		{"row 15: one failed, one never answered", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			unknown("10.0.0.2", domain.FailureExecLocalTimeout)}},
		{"row 15b: one failed, one cancelled", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			unknown("10.0.0.2", domain.FailureExecCancelled)}},
		{"row 15c: one failed, one never attempted", []connectOutcome{
			fail("10.0.0.1", domain.FailureTCPConnectionRefused),
			skipped("10.0.0.2", domain.FailureExecCancelled)}},
		{"row 16: all unknown", []connectOutcome{
			unknown("10.0.0.1", domain.FailureExecLocalTimeout),
			unknown("10.0.0.2", domain.FailureExecLocalTimeout)}},
		{"dialer told us nothing", []connectOutcome{
			unknown("10.0.0.1", domain.FailureNone)}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireNone(t, TCP(rctx(requestedTCP(t, c.outcomes...))))
		})
	}
}

// TestTCPWithholdsOnAnUnauthorizedFailureClass pins the closed vocabulary on the
// other rule.
func TestTCPWithholdsOnAnUnauthorizedFailureClass(t *testing.T) {
	graph := requestedTCP(t,
		fail("10.0.0.1", domain.FailureTCPConnectionRefused),
		fail("10.0.0.2", domain.FailureProtocolPeerClosed),
	)
	requireNone(t, TCP(rctx(graph)))
}

// TestRow17DNSFailureLeavesNoTCPClaim pins that a failed lookup produces the DNS
// finding and nothing at L2.
func TestRow17DNSFailureLeavesNoTCPClaim(t *testing.T) {
	graph := requestedDNS(t, domain.StateFail, domain.FailureDNSNoAddress)

	requireOne(t, DNS(rctx(graph)), CodeNameNotResolved)
	requireNone(t, TCP(rctx(graph)))
}

// TestRow18ManyAddressesStillProduceOneFinding pins the aggregation unit.
func TestRow18ManyAddressesStillProduceOneFinding(t *testing.T) {
	graph := requestedTCP(t, twentyFailures(t)...)

	finding := requireOne(t, TCP(rctx(graph)), CodeConnectionNotEstablished)
	if got := len(finding.EvidenceRefs()); got != 21 {
		t.Errorf("got %d refs, want 21 (twenty connections and the lookup)", got)
	}
}

// TestRow20ADNSNodeWithNoAnchorIsNotOwned is the guard that ownership comes from
// the anchor and not from the step.
//
// This is the graph every run produced before ADR 0042, and the graph any future
// sweep that declares a different cause will produce. The rules must be inert on
// it.
func TestRow20ADNSNodeWithNoAnchorIsNotOwned(t *testing.T) {
	b := newBuilder(t)
	lookup := b.lookup("", "db.example.com", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.0.0.1", domain.StateFail, domain.FailureTCPConnectionRefused)
	graph := b.freeze()

	requireNone(t, DNS(rctx(graph)))
	requireNone(t, TCP(rctx(graph)))
}

// TestRows21And22ADiscoveredSweepIsNotOwned reproduces the Kafka shape.
//
// The advertised sweep hangs off a service node, so it is not a direct child of
// any anchor. Here it is not even below one; internal/adapter/kafka proves the
// harder case, where it *is* transitively below a target and still not owned.
func TestRows21And22ADiscoveredSweepIsNotOwned(t *testing.T) {
	b := newBuilder(t)
	advertisement := b.node("", "service.discovered/broker-1", "service.discovered",
		domain.LayerTopology, domain.StatePass, domain.FailureNone)
	lookup := b.lookup(advertisement, "broker-1.internal", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.20.0.1", domain.StateFail, domain.FailureTCPConnectionRefused)
	graph := b.freeze()

	requireNone(t, DNS(rctx(graph)))
	requireNone(t, TCP(rctx(graph)))
}

// TestAServiceNodeBeneathAConnectionIsNotDiagnosed is the PostgreSQL in-band
// shape, reduced to its structure.
//
// A node beneath a requested connection — the negotiation, and the handshake
// beneath that — is outside the walk, which stops at L2. Row 25 in
// internal/app proves it on the real graph.
func TestAServiceNodeBeneathAConnectionIsNotDiagnosed(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	connect := b.connect(lookup, "10.0.0.1", domain.StatePass, domain.FailureNone)
	negotiation := b.node(connect, "service.negotiate/10.0.0.1", "service.negotiate",
		domain.LayerTLS, domain.StatePass, domain.FailureNone)
	b.node(negotiation, "handshake/10.0.0.1", "handshake",
		domain.LayerTLS, domain.StateFail, domain.FailureTLSHostnameMismatch)
	graph := b.freeze()

	// The connection passed, so no TCP claim; and nothing below it is reachable.
	requireNone(t, DNS(rctx(graph)))
	requireNone(t, TCP(rctx(graph)))
}

// --- shapes the rules must refuse to recognize ---------------------------------

// TestAnUnrecognizedShapeWithholdsEverything pins that diagnosis does not guess.
func TestAnUnrecognizedShapeWithholdsEverything(t *testing.T) {
	t.Run("an anchor child that is not a lookup", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		b.node(anchor, "something.else/x", "something.else",
			domain.LayerDNS, domain.StateFail, domain.FailureDNSNoAddress)
		graph := b.freeze()

		requireNone(t, DNS(rctx(graph)))
		requireNone(t, TCP(rctx(graph)))
	})

	t.Run("two lookups under one anchor", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		b.lookup(anchor, "db.example.com", domain.StateFail, domain.FailureDNSNoAddress)
		b.lookup(anchor, "other.example.com", domain.StateFail, domain.FailureDNSNoAddress)
		graph := b.freeze()

		requireNone(t, DNS(rctx(graph)))
		requireNone(t, TCP(rctx(graph)))
	})

	t.Run("a lookup child that is not a connection", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.anchor("db.example.com:5432")
		lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
		b.node(lookup, "something.else/x", "something.else",
			domain.LayerTCP, domain.StateFail, domain.FailureTCPConnectionRefused)
		graph := b.freeze()

		requireNone(t, DNS(rctx(graph)))
		requireNone(t, TCP(rctx(graph)))
	})

	t.Run("an anchor with no sweep", func(t *testing.T) {
		b := newBuilder(t)
		b.anchor("db.example.com:5432")
		graph := b.freeze()

		requireNone(t, DNS(rctx(graph)))
		requireNone(t, TCP(rctx(graph)))
	})
}

// TestAnAnchorShapedNodeWithTheWrongFieldsIsNotAnAnchor pins that the predicate
// is all three properties the producer commits to.
func TestAnAnchorShapedNodeWithTheWrongFieldsIsNotAnAnchor(t *testing.T) {
	t.Run("wrong layer", func(t *testing.T) {
		b := newBuilder(t)
		subject, err := domain.NewTargetSubject("db.example.com:5432")
		if err != nil {
			t.Fatalf("NewTargetSubject: %v", err)
		}
		anchor := b.add(domain.EvidenceInput{
			ID:        "target.requested/db.example.com:5432",
			Subject:   subject,
			Layer:     domain.LayerDNS, // not L0
			Step:      vocabulary.StepTargetRequested,
			State:     domain.StatePass,
			StartedAt: b.now,
		}, "")
		b.lookup(anchor, "db.example.com", domain.StateFail, domain.FailureDNSNoAddress)

		requireNone(t, DNS(rctx(b.freeze())))
	})

	t.Run("wrong subject kind", func(t *testing.T) {
		b := newBuilder(t)
		anchor := b.add(domain.EvidenceInput{
			ID:        "target.requested/db.example.com:5432",
			Subject:   b.endpointSubject("db.example.com:5432"), // ENDPOINT, not TARGET
			Layer:     domain.LayerInput,
			Step:      vocabulary.StepTargetRequested,
			State:     domain.StatePass,
			StartedAt: b.now,
		}, "")
		b.lookup(anchor, "db.example.com", domain.StateFail, domain.FailureDNSNoAddress)

		requireNone(t, DNS(rctx(b.freeze())))
	})
}

// --- helpers -------------------------------------------------------------------

func twentyFailures(t *testing.T) []connectOutcome {
	t.Helper()

	classes := []domain.FailureClass{
		domain.FailureTCPConnectionRefused,
		domain.FailureTCPConnectionTimeout,
		domain.FailureTCPHostUnreachable,
		domain.FailureTCPNetworkUnreachable,
	}
	out := make([]connectOutcome, 0, 20)
	for i := range 20 {
		out = append(out, fail(address(i), classes[i%len(classes)]))
	}
	return out
}

func oneOfTwenty(t *testing.T) []connectOutcome {
	t.Helper()

	out := twentyFailures(t)
	out[7] = pass(address(7))
	return out
}

func address(i int) string {
	return "10.0.0." + strconv.Itoa(100+i)
}
