package terminal

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The insecure-TLS projection, ADR 0058 section 14.1 and ADR 0060 section 6.
//
// # The defect these close
//
// Before Phase 6.8A this renderer contained no reference to
// TLSVerificationDisabled or tls.verified, so two runs — one that verified the
// peer's certificate against a supplied CA, one that verified nothing at all —
// produced byte-identical output down to `✓ PASS  TLS`. Nothing in the document
// was false and the impression it left was.
//
// # Two readings, on purpose
//
//	header  security.tlsVerificationDisabled   the run-level fact
//	row     the node's own tls.verified        one handshake at a time
//
// They come from different places so that a fixture can make them disagree,
// which is the only way to write a guard that a renderer inventing either from
// the other would fail. In production they agree because one option produced
// both.

// insecureKafka is the healthy run with verification switched off everywhere.
func insecureKafka(t *testing.T) *kafkaGraph {
	t.Helper()
	g := newKafkaGraph(t)
	g.b.tlsVerificationDisabled = true
	g.bootstrapPath(addrOne,
		passed(tcp, 190), unverified(tlsStep, 1700), passed(versions, 155),
		passed(mech, 88), passed(auth, 94), passed(meta, 90))
	one := g.advertisement(1, "broker-1.internal:9093", domain.StatePass, domain.FailureNone)
	g.sweep(one, "broker-1.internal:9093", "198.51.100.21:9093",
		passed(vocabulary.StepDNSLookup, 160),
		[]stage{passed(tcp, 130), unverified(tlsStep, 709)})
	return g
}

// TestTheInsecureRunIsRenderedWhole is the golden, and it is the guard that
// catches a projection regression as a diff rather than as a missing substring.
func TestTheInsecureRunIsRenderedWhole(t *testing.T) {
	requireKafkaGolden(t, "kafka-insecure-tls.txt",
		renderKafka(t, insecureKafka(t).report(), false))
}

// TestTheInsecureRunIsRenderedWholeWhenShared is the same run shared.
//
// The security fact must survive redaction: the reader who was not at the
// terminal is exactly the reader who cannot otherwise know that no identity was
// established, and a shared report that dropped it would be the more misleading
// of the two documents.
func TestTheInsecureRunIsRenderedWholeWhenShared(t *testing.T) {
	g := insecureKafka(t)
	g.b.shareable = true
	requireKafkaGolden(t, "kafka-insecure-tls-shareable.txt",
		renderKafka(t, g.report(), false))
}

// TestAVerifiedRunAndAnUnverifiedRunDifferInTheTerminal is the defect itself,
// stated as an assertion.
//
// It compares two whole documents rather than looking for a phrase, because the
// failure was never a wrong word — it was two different security postures
// rendering the same bytes.
func TestAVerifiedRunAndAnUnverifiedRunDifferInTheTerminal(t *testing.T) {
	verified := renderKafka(t, healthyKafka(t).report(), false)
	insecure := renderKafka(t, insecureKafka(t).report(), false)

	if verified == insecure {
		t.Fatal("a run that verified the peer and a run that verified nothing " +
			"render identically; the terminal is concealing the whole of " +
			"--tls-insecure (ADR 0058 section 14.1)")
	}
}

// TestTheHeaderStatesDisabledVerification pins the header, its wording and its
// placement.
func TestTheHeaderStatesDisabledVerification(t *testing.T) {
	lines := strings.Split(renderKafka(t, insecureKafka(t).report(), false), "\n")

	if len(lines) < 2 {
		t.Fatalf("output has %d lines", len(lines))
	}
	if !strings.HasPrefix(lines[0], "svcdoctor · kafka ·") {
		t.Errorf("line 1 = %q, want the run banner first", lines[0])
	}
	if !strings.Contains(lines[1], "Peer verification disabled") {
		t.Errorf("line 2 = %q, want the security annotation directly under the banner", lines[1])
	}
}

// TestTheHeaderIsAbsentWhenVerificationHappened is the control.
//
// An annotation that appeared on every run would say nothing. This is also what
// keeps every pre-existing golden byte-identical.
func TestTheHeaderIsAbsentWhenVerificationHappened(t *testing.T) {
	if got := renderKafka(t, healthyKafka(t).report(), false); strings.Contains(
		got, "Peer verification disabled") {
		t.Errorf("a verified run announces disabled verification:\n%s", got)
	}
}

// TestTheHandshakeRowSaysVerificationWasDisabled pins the row.
//
// The TLS row must carry the note and must still be a PASS row: the handshake
// completed, and downgrading it would claim the endpoint did something wrong.
func TestTheHandshakeRowSaysVerificationWasDisabled(t *testing.T) {
	row := tlsRow(t, renderKafka(t, insecureKafka(t).report(), false))

	if !strings.Contains(row, unverifiedPeer) {
		t.Errorf("TLS row = %q, want it to carry %q", row, unverifiedPeer)
	}
	if !strings.Contains(row, "PASS") {
		t.Errorf("TLS row = %q, want it to remain a PASS row: the operator asked "+
			"for this and the endpoint did nothing wrong", row)
	}
}

// TestDisabledVerificationIsNotAFinding is the claim-discipline half of ADR 0060
// section 6.
//
// An operator who deliberately disabled verification has not found a target-side
// problem. Turning their own choice into an ERROR would change the exit code,
// which would make `--tls-insecure` unusable in exactly the situation it exists
// for.
func TestDisabledVerificationIsNotAFinding(t *testing.T) {
	report := insecureKafka(t).report()
	if len(report.Findings()) != 0 {
		t.Fatalf("the fixture has %d findings; this test asserts about a run with none",
			len(report.Findings()))
	}

	got := renderKafka(t, report, false)
	if !strings.Contains(got, "Findings\n  none") {
		t.Errorf("disabled verification produced a finding:\n%s", got)
	}
	if !strings.Contains(got, "status     OK") {
		t.Errorf("disabled verification changed the status:\n%s", got)
	}
}

// TestTheRowNeverClaimsVerificationHappened is the overclaim guard.
//
// The whole point is that an unverified handshake must not read as an
// authenticated peer. These are the words that would say it did.
func TestTheRowNeverClaimsVerificationHappened(t *testing.T) {
	got := renderKafka(t, insecureKafka(t).report(), false)
	for _, forbidden := range []string{
		"verified", "trusted", "authenticated", "identity confirmed",
	} {
		if strings.Contains(strings.ToLower(got), forbidden) {
			t.Errorf("an unverified run's output contains %q:\n%s", forbidden, got)
		}
	}
}

// TestTheRowFollowsTheNodeAndNotTheHeader is the anti-invention guard.
//
// A renderer that stamped the note onto every TLS row whenever the run-level
// boolean was set would pass every other test here. This one sets the header
// fact and leaves the node verified, and the row must stay clean — because a
// future per-endpoint plan would make exactly that combination real, and a
// renderer that guessed would then be wrong about which handshake was which.
func TestTheRowFollowsTheNodeAndNotTheHeader(t *testing.T) {
	g := newKafkaGraph(t)
	g.b.tlsVerificationDisabled = true
	g.bootstrapPath(addrOne, passed(tcp, 190), passed(tlsStep, 1700))

	got := renderKafka(t, g.report(), false)
	if !strings.Contains(got, "Peer verification disabled") {
		t.Error("the header did not read the run-level fact")
	}
	if strings.Contains(tlsRow(t, got), unverifiedPeer) {
		t.Error("the TLS row was annotated from the run-level flag rather than " +
			"from the node's own tls.verified")
	}
}

// TestTheHeaderFollowsTheReportAndNotTheNodes is the mirror.
//
// A renderer that derived the header by scanning for an unverified handshake
// would also pass most of this file, and would then be silent on a run whose
// TCP attempt failed before any handshake existed — which is precisely the run
// where an operator most needs to be told what their flags asked for.
func TestTheHeaderFollowsTheReportAndNotTheNodes(t *testing.T) {
	g := newKafkaGraph(t)
	g.b.tlsVerificationDisabled = true
	g.bootstrapPath(addrOne, failed(tcp, domain.FailureTCPConnectionRefused, 190))

	if got := renderKafka(t, g.report(), false); !strings.Contains(
		got, "Peer verification disabled") {
		t.Errorf("no handshake happened and the header went silent:\n%s", got)
	}
}

// TestAFailedHandshakeKeepsItsFailureClass guards the note column's priority.
//
// `tls.verified` is false for a failed handshake too, so the naive annotation
// would replace `TLS_UNKNOWN_AUTHORITY` — the actionable fact — with a note
// about a setting the operator did not use.
func TestAFailedHandshakeKeepsItsFailureClass(t *testing.T) {
	g := newKafkaGraph(t)
	g.bootstrapPath(addrOne, passed(tcp, 190), stage{
		step: tlsStep, state: domain.StateFail,
		class: domain.FailureTLSUnknownAuthority, elapsed: measured(900),
		attrs: map[domain.AttributeKey]domain.AttrValue{
			vocabulary.AttrTLSVerified: domain.BoolAttr(false),
		},
	})

	row := tlsRow(t, renderKafka(t, g.report(), false))
	if !strings.Contains(row, "TLS_UNKNOWN_AUTHORITY") {
		t.Errorf("TLS row = %q, want the failure class", row)
	}
	if strings.Contains(row, unverifiedPeer) {
		t.Errorf("TLS row = %q, want the failure class rather than the "+
			"disabled-verification note: nothing was disabled here", row)
	}
}

// TestANonHandshakeRowIsNeverAnnotated guards the absent-attribute branch.
func TestANonHandshakeRowIsNeverAnnotated(t *testing.T) {
	got := renderKafka(t, insecureKafka(t).report(), false)
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, unverifiedPeer) && !strings.Contains(line, "TLS") {
			t.Errorf("a non-handshake row carries the note: %q", line)
		}
	}
}

// TestAdvertisedHandshakesAreAnnotatedToo is why the row reads the node.
//
// A Kafka run sweeps every advertised broker with the same options, so those
// handshakes are unverified as well — and they are the ones an operator is least
// likely to have thought about.
func TestAdvertisedHandshakesAreAnnotatedToo(t *testing.T) {
	got := renderKafka(t, insecureKafka(t).report(), false)

	count := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, unverifiedPeer) {
			count++
		}
	}
	if count != 2 {
		t.Errorf("%d annotated rows, want 2 (the bootstrap handshake and the "+
			"advertised broker's):\n%s", count, got)
	}
}

// tlsRow returns the first TLS stage row of a rendered document.
func tlsRow(t *testing.T, document string) string {
	t.Helper()
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "✓") || strings.HasPrefix(trimmed, "✗") {
			if strings.Contains(line, " TLS ") || strings.HasSuffix(strings.TrimRight(line, " "), " TLS") {
				return line
			}
		}
	}
	t.Fatalf("no TLS row in:\n%s", document)
	return ""
}

// renderKafka is defined in kafkagolden_test.go; this keeps the compiler honest
// about the render.Input shape the goldens use.
var _ = render.Input{}
