package transport

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7 — the requested-target rules on a sweep that resolved nothing.
//
// The shape is `target.requested -> tcp.connect [-> tls.handshake]`, with no L1
// node, because an address literal needed no resolution (ADR 0059). Two
// properties are load-bearing and neither is a matter of presentation:
//
//   - **No DNS claim may fire.** Not suppressed downstream, not hidden by a
//     renderer, not filtered by inspecting a host string: the rule has no node to
//     read, so the claim is unreachable.
//   - **TCP and TLS must still be owned.** Making a failing stage reachable
//     without an owner is exactly what ADR 0054 forbids, and this shape made both
//     reachable.

// literalSweep builds the resolution-free shape: an anchor and its connections.
func literalSweep(t *testing.T, endpoint string, outcomes ...connectOutcome) domain.Graph {
	t.Helper()

	b := newBuilder(t)
	anchor := b.anchor(endpoint)
	for _, o := range outcomes {
		b.connect(anchor, o.address, o.state, o.class)
	}
	return b.freeze()
}

// --- DNS: structurally unreachable ---------------------------------------

// Every DNS failure class, on a graph with no lookup. The rule must find nothing
// to read, whatever an operator's target looked like.
func TestNoDNSFindingCanFireForAResolutionFreeSweep(t *testing.T) {
	for _, endpoint := range []string{"10.0.0.1:5432", "[2001:db8::1]:9092", "[::1]:5432"} {
		t.Run(endpoint, func(t *testing.T) {
			g := literalSweep(t, endpoint,
				fail("10.0.0.1", domain.FailureTCPConnectionRefused))

			if findings := DNS(rctx(g)); len(findings) != 0 {
				t.Fatalf("DNS produced %d findings for a sweep that resolved nothing: %v",
					len(findings), findings)
			}
		})
	}
}

// The absence is structural, not accidental: the graph holds no L1 node at all,
// so there is nothing a DNS rule could read even if one tried.
func TestAResolutionFreeSweepHoldsNoDNSNode(t *testing.T) {
	g := literalSweep(t, "10.0.0.1:5432", fail("10.0.0.1", domain.FailureTCPConnectionRefused))

	for _, node := range g.Nodes() {
		if node.Layer() == domain.LayerDNS || node.Step() == vocabulary.StepDNSLookup {
			t.Fatalf("the fixture holds an L1 node: %s", node.ID())
		}
	}
}

// The DNS rule still fires for a name. Removing the claim entirely would pass
// the test above and lose a real diagnosis.
func TestTheDNSRuleStillFiresForAName(t *testing.T) {
	g := requestedDNS(t, domain.StateFail, domain.FailureDNSNoAddress)

	findings := DNS(rctx(g))
	if len(findings) != 1 || findings[0].Code() != CodeNameNotResolved {
		t.Fatalf("DNS findings = %v, want one %s", findings, CodeNameNotResolved)
	}
}

// --- TCP: owned, with truthful prose -------------------------------------

func TestALiteralTCPFailureIsOwned(t *testing.T) {
	g := literalSweep(t, "10.0.0.1:5432", fail("10.0.0.1", domain.FailureTCPConnectionRefused))

	findings := TCP(rctx(g))
	if len(findings) != 1 {
		t.Fatalf("TCP findings = %d, want 1: a reachable failing stage must have an owner", len(findings))
	}
	f := findings[0]
	if f.Code() != CodeConnectionNotEstablished {
		t.Fatalf("code = %s, want %s", f.Code(), CodeConnectionNotEstablished)
	}
	if f.Layer() != domain.LayerTCP {
		t.Fatalf("layer = %s, want L2: a missing L1 observation must not promote TCP", f.Layer())
	}
	if f.Subject().Ref() != "10.0.0.1:5432" {
		t.Fatalf("subject = %q, want the requested target", f.Subject().Ref())
	}
}

// The claim cites the connections and nothing else. With no lookup there is no
// denominator node to cite, and citing one that does not exist would be a
// dangling reference the report would refuse.
func TestALiteralTCPFindingCitesOnlyItsConnections(t *testing.T) {
	g := literalSweep(t, "10.0.0.1:5432", fail("10.0.0.1", domain.FailureTCPConnectionRefused))

	refs := TCP(rctx(g))[0].EvidenceRefs()
	if len(refs) != 1 {
		t.Fatalf("refs = %v, want exactly the connection", refs)
	}
	if _, ok := g.Node(refs[0]); !ok {
		t.Fatalf("the finding cites %s, which the graph does not hold", refs[0])
	}
}

// The prose must not describe resolution that did not happen. This is the
// sentence the shipped binary printed for `--host 127.0.0.1`.
func TestALiteralTCPFindingClaimsNoResolution(t *testing.T) {
	literal := TCP(rctx(literalSweep(t, "10.0.0.1:5432",
		fail("10.0.0.1", domain.FailureTCPConnectionRefused))))[0]

	for _, forbidden := range []string{
		"the hostname resolved",
		"hostname",
		"resolved to",
	} {
		if strings.Contains(literal.Detail(), forbidden) {
			t.Errorf("the literal detail says %q:\n%s", forbidden, literal.Detail())
		}
	}
	if !strings.Contains(literal.Detail(), "No name was resolved") {
		t.Errorf("the literal detail does not state that nothing was resolved:\n%s", literal.Detail())
	}
}

// The named shape keeps its own sentence, so the two are genuinely distinguished
// rather than both replaced by a vaguer one that is true of neither.
func TestANamedTCPFindingStillDescribesResolution(t *testing.T) {
	g := requestedTCP(t, fail("10.0.0.1", domain.FailureTCPConnectionRefused))

	findings := TCP(rctx(g))
	if len(findings) != 1 {
		t.Fatalf("TCP findings = %d, want 1", len(findings))
	}
	if !strings.Contains(findings[0].Detail(), "Every address the hostname resolved to") {
		t.Errorf("the named detail lost its sentence:\n%s", findings[0].Detail())
	}
}

// Both shapes carry one code. A second code here would split the machine
// contract on something an operator does not act on differently.
func TestBothShapesShareOneCode(t *testing.T) {
	literal := TCP(rctx(literalSweep(t, "10.0.0.1:5432",
		fail("10.0.0.1", domain.FailureTCPConnectionRefused))))[0]
	named := TCP(rctx(requestedTCP(t, fail("10.0.0.1", domain.FailureTCPConnectionRefused))))[0]

	if literal.Code() != named.Code() {
		t.Fatalf("codes diverged: %s vs %s", literal.Code(), named.Code())
	}
	if literal.Summary() != named.Summary() {
		t.Fatalf("summaries diverged:\n%s\n%s", literal.Summary(), named.Summary())
	}
}

// The aggregation rule is unchanged: anything other than "every connection
// failed" withholds, on the literal shape exactly as on the named one.
func TestLiteralTCPAggregationIsUnchanged(t *testing.T) {
	tests := map[string][]connectOutcome{
		"a passing connection": {pass("10.0.0.1")},
		"an unknown connection": {
			unknown("10.0.0.1", domain.FailureExecLocalTimeout)},
		"a skipped connection": {
			skipped("10.0.0.1", domain.FailureExecSkippedPrerequisiteFailed)},
		"no connections at all": {},
		"an unauthorized class": {
			fail("10.0.0.1", domain.FailureProtocolPeerClosed)},
	}
	for name, outcomes := range tests {
		t.Run(name, func(t *testing.T) {
			if findings := TCP(rctx(literalSweep(t, "10.0.0.1:5432", outcomes...))); len(findings) != 0 {
				t.Fatalf("TCP produced %v, want none", findings)
			}
		})
	}
}

// --- TLS: owned on the literal shape -------------------------------------

func TestALiteralTLSFailureIsOwned(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("10.0.0.1:9093")
	connect := b.connect(anchor, "10.0.0.1", domain.StatePass, domain.FailureNone)
	b.node(connect, "tls.handshake/10.0.0.1:9093", vocabulary.StepTLSHandshake,
		domain.LayerTLS, domain.StateFail, domain.FailureTLSHostnameMismatch)

	findings := TLS(rctx(b.freeze()))
	if len(findings) != 1 {
		t.Fatalf("TLS findings = %d, want 1: a reachable failing handshake must have an owner",
			len(findings))
	}
	if findings[0].Code() != CodeTLSIdentityMismatch {
		t.Fatalf("code = %s, want %s", findings[0].Code(), CodeTLSIdentityMismatch)
	}
	if findings[0].Layer() != domain.LayerTLS {
		t.Fatalf("layer = %s, want L3", findings[0].Layer())
	}
}

// Every authorized class produces its own code on the literal shape, so no
// subset of the five is quietly unowned there.
func TestEveryTLSClaimSurvivesTheLiteralShape(t *testing.T) {
	classes := map[domain.FailureClass]domain.FindingCode{
		domain.FailureTLSPeerNotTLS:             CodeTLSEndpointDoesNotSpeakTLS,
		domain.FailureTLSHostnameMismatch:       CodeTLSIdentityMismatch,
		domain.FailureTLSUnknownAuthority:       CodeTLSChainNotTrusted,
		domain.FailureTLSCertificateExpired:     CodeTLSCertificateNotValidNow,
		domain.FailureTLSHandshakeFailure:       CodeTLSHandshakeNotCompleted,
		domain.FailureTLSCertificateNotYetValid: CodeTLSCertificateNotValidNow,
	}
	for class, want := range classes {
		t.Run(class.String(), func(t *testing.T) {
			b := newBuilder(t)
			anchor := b.anchor("10.0.0.1:9093")
			connect := b.connect(anchor, "10.0.0.1", domain.StatePass, domain.FailureNone)
			b.node(connect, "tls.handshake/10.0.0.1:9093", vocabulary.StepTLSHandshake,
				domain.LayerTLS, domain.StateFail, class)

			findings := TLS(rctx(b.freeze()))
			if len(findings) != 1 || findings[0].Code() != want {
				t.Fatalf("findings = %v, want one %s", findings, want)
			}
		})
	}
}

// --- shapes that are still refused ---------------------------------------

// An anchor holding both a lookup and a direct connection is a graph no producer
// makes. It is refused rather than half-read, so nothing claims either.
func TestAMixedSweepShapeWithholdsEveryClaim(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("db.example.com:5432")
	lookup := b.lookup(anchor, "db.example.com", domain.StatePass, domain.FailureNone)
	b.connect(lookup, "10.0.0.1", domain.StateFail, domain.FailureTCPConnectionRefused)
	b.connect(anchor, "10.0.0.2", domain.StateFail, domain.FailureTCPConnectionRefused)
	g := b.freeze()

	if findings := TCP(rctx(g)); len(findings) != 0 {
		t.Errorf("TCP produced %v for a mixed shape, want none", findings)
	}
	if findings := DNS(rctx(g)); len(findings) != 0 {
		t.Errorf("DNS produced %v for a mixed shape, want none", findings)
	}
	if findings := TLS(rctx(g)); len(findings) != 0 {
		t.Errorf("TLS produced %v for a mixed shape, want none", findings)
	}
}

// An anchor child that is neither a lookup nor a connection is still refused.
func TestAnUnrecognizedAnchorChildStillWithholds(t *testing.T) {
	b := newBuilder(t)
	anchor := b.anchor("10.0.0.1:5432")
	b.node(anchor, "kafka.api_versions/x", "kafka.api_versions",
		domain.LayerProtocol, domain.StateFail, domain.FailureProtocolPeerClosed)
	g := b.freeze()

	if findings := TCP(rctx(g)); len(findings) != 0 {
		t.Fatalf("TCP produced %v, want none", findings)
	}
}

// Several connections under one anchor is a shape nothing produces — one literal
// is one address — but reading it is safe and withholding would lose a real
// claim, so the aggregation is applied rather than the shape refused.
func TestSeveralLiteralConnectionsAggregateNormally(t *testing.T) {
	g := literalSweep(t, "10.0.0.1:5432",
		fail("10.0.0.1", domain.FailureTCPConnectionRefused),
		fail("10.0.0.2", domain.FailureTCPConnectionTimeout))

	findings := TCP(rctx(g))
	if len(findings) != 1 {
		t.Fatalf("TCP findings = %d, want 1", len(findings))
	}
	if len(findings[0].EvidenceRefs()) != 2 {
		t.Fatalf("refs = %v, want both connections", findings[0].EvidenceRefs())
	}

	partial := literalSweep(t, "10.0.0.1:5432",
		fail("10.0.0.1", domain.FailureTCPConnectionRefused),
		pass("10.0.0.2"))
	if findings := TCP(rctx(partial)); len(findings) != 0 {
		t.Fatalf("a partial success produced %v, want none", findings)
	}
}
