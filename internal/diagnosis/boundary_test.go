package diagnosis

import (
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a, ADR 0079: the failure boundary.
//
// The six shapes of ADR 0079 section 2.5 are covered here, each in its own test,
// because they are requirements rather than illustrations. The two properties
// that carry the most weight are the negative ones: an all-PASS subject has no
// boundary, and an unmeasured tail invents none.

func boundaryOf(t *testing.T, g domain.Graph, ref string) (Boundary, bool) {
	t.Helper()
	return BoundaryFor(g, endpointSubject(t, ref))
}

func requireBoundary(t *testing.T, g domain.Graph, ref string) Boundary {
	t.Helper()
	b, ok := boundaryOf(t, g, ref)
	if !ok {
		t.Fatalf("no boundary for %s, want one", ref)
	}
	return b
}

// TestDIAG011LinearBoundary is ADR 0079 section 2.5's first shape, and the
// prompt's case A: DNS passes, TCP fails, TLS is blocked.
func TestDIAG011LinearBoundary(t *testing.T) {
	g, _ := linearGraph(t)

	b := requireBoundary(t, g, "one.example:5432")

	if got, ok := b.LastConfirmedGood(); !ok || got != "a-dns" {
		t.Errorf("last confirmed-good = %q (ok=%v), want a-dns", got, ok)
	}
	if got := b.FirstEvidencedFailure(); got != "a-tcp" {
		t.Errorf("first evidenced failure = %q, want a-tcp", got)
	}
	if got := b.Blocked(); !slices.Equal(got, []domain.EvidenceID{"a-tls"}) {
		t.Errorf("blocked = %v, want [a-tls]", got)
	}
	if got := b.NotMeasured(); !slices.Equal(got, []domain.EvidenceID{"a-tls"}) {
		t.Errorf("not measured = %v, want [a-tls]", got)
	}
	if b.Subject().Ref() != "one.example:5432" {
		t.Errorf("subject = %s", b.Subject())
	}
}

// TestDIAG012TheBlockedStepDoesNotBecomeTheFailure is the prompt's case A
// negative half and mutation M12.
//
// The TLS step did not run. It is not a second failure, it is not the first
// failure, and it is not evidence that TLS is broken. Reading it as any of those
// is how a report grows three fabricated failures under one real one — the
// mistake docs/FINDINGS.md section 5 already forbids and this generalizes.
func TestDIAG012TheBlockedStepDoesNotBecomeTheFailure(t *testing.T) {
	g, _ := linearGraph(t)

	b := requireBoundary(t, g, "one.example:5432")

	if b.FirstEvidencedFailure() == "a-tls" {
		t.Fatal("a blocked descendant was reported as the first evidenced failure")
	}
	if slices.Contains(b.Blocked(), b.FirstEvidencedFailure()) {
		t.Error("the failure appears in its own blocked set")
	}
	if last, ok := b.LastConfirmedGood(); ok && last == "a-tls" {
		t.Error("a blocked step was reported as confirmed good")
	}
}

// TestDIAG012AnUnknownIsNeitherHalf is the prompt's case B.
//
// DNS passes and TCP reaches no conclusion. There is no definitive failure, so
// there is no boundary — not a weak one, and not one standing at DNS. ADR 0079
// section 2.2 requires a FAIL or a DEGRADED, and an UNKNOWN is neither.
func TestDIAG012AnUnknownIsNeitherHalf(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("b-dns", "two.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.unknown("b-tcp", "two.example:5432", domain.LayerTCP, "tcp.connect")
	s.parent(tcp, dns)
	g := s.freeze()

	if b, ok := boundaryOf(t, g, "two.example:5432"); ok {
		t.Fatalf("an UNKNOWN produced a boundary: last=%v first=%q",
			mustLast(b), b.FirstEvidencedFailure())
	}
}

// TestDIAG011BranchesAreScopedSeparately is the prompt's case C and ADR 0079
// section 2.5's branch-specific and divergent-sibling shapes.
//
// Two endpoints fail at different layers. That is two boundaries, and merging
// them would produce one summary that is true of neither.
func TestDIAG011BranchesAreScopedSeparately(t *testing.T) {
	s := newSpec(t)
	aDNS := s.endpoint("c-a-dns", "a.example:9092", domain.LayerDNS, "dns.lookup", domain.StatePass)
	aTCP := s.endpoint("c-a-tcp", "a.example:9092", domain.LayerTCP, "tcp.connect", domain.StatePass)
	aTLS := s.endpoint("c-a-tls", "a.example:9092", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(aTCP, aDNS)
	s.parent(aTLS, aTCP)

	bDNS := s.endpoint("c-b-dns", "b.example:9092", domain.LayerDNS, "dns.lookup", domain.StatePass)
	bTCP := s.endpoint("c-b-tcp", "b.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	s.parent(bTCP, bDNS)
	g := s.freeze()

	all := Boundaries(g)
	if len(all) != 2 {
		t.Fatalf("got %d boundaries, want 2 (one per subject)", len(all))
	}

	first := requireBoundary(t, g, "a.example:9092")
	if got := first.FirstEvidencedFailure(); got != "c-a-tls" {
		t.Errorf("endpoint a failed at %q, want c-a-tls", got)
	}
	if got, _ := first.LastConfirmedGood(); got != "c-a-tcp" {
		t.Errorf("endpoint a last good = %q, want c-a-tcp (the deepest PASS above it)", got)
	}

	second := requireBoundary(t, g, "b.example:9092")
	if got := second.FirstEvidencedFailure(); got != "c-b-tcp" {
		t.Errorf("endpoint b failed at %q, want c-b-tcp", got)
	}

	// Canonical order, so a report built from these is byte-stable.
	if all[0].Subject().Ref() != "a.example:9092" || all[1].Subject().Ref() != "b.example:9092" {
		t.Errorf("boundaries are not in canonical subject order: %s then %s",
			all[0].Subject(), all[1].Subject())
	}
}

// TestP12AllPassProducesNoBoundary is property P12 and the prompt's case D.
func TestP12AllPassProducesNoBoundary(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("d-dns", "ok.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("d-tcp", "ok.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	tls := s.endpoint("d-tls", "ok.example:5432", domain.LayerTLS, "tls.handshake", domain.StatePass)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	g := s.freeze()

	if got := Boundaries(g); len(got) != 0 {
		t.Fatalf("an all-PASS graph produced %d boundaries, want none", len(got))
	}
	if _, ok := boundaryOf(t, g, "ok.example:5432"); ok {
		t.Error("an all-PASS subject has a boundary")
	}
}

// TestTheFirstNodeFailingLeavesNoConfirmedGood is the prompt's case E.
//
// The failure exists and is reported. The other half does not, and is reported
// as absent rather than filled in: "everything up to here worked" would be a
// stronger claim than the evidence carries when nothing worked at all.
func TestTheFirstNodeFailingLeavesNoConfirmedGood(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("e-dns", "gone.example:5432", domain.LayerDNS, "dns.lookup", domain.StateFail)
	tcp := s.endpoint("e-tcp", "gone.example:5432", domain.LayerTCP, "tcp.connect", domain.StateSkipped)
	s.parent(tcp, dns)
	s.blockedBy(tcp, dns)
	g := s.freeze()

	b := requireBoundary(t, g, "gone.example:5432")

	if got := b.FirstEvidencedFailure(); got != "e-dns" {
		t.Errorf("first evidenced failure = %q, want e-dns", got)
	}
	if got, ok := b.LastConfirmedGood(); ok {
		t.Errorf("last confirmed-good = %q, want none", got)
	}
	if got := b.Blocked(); !slices.Equal(got, []domain.EvidenceID{"e-tcp"}) {
		t.Errorf("blocked = %v, want [e-tcp]", got)
	}
}

// TestP13CancellationFabricatesNoBoundary is property P13 and the prompt's case
// F, and it is the RAB18 lesson in its structural form.
//
// A run whose budget expired leaves UNKNOWN tails. Less evidence must never
// produce a stronger statement, so the tail produces nothing: no boundary for
// the unmeasured subject, and no change to the boundary of a subject that was
// measured.
func TestP13CancellationFabricatesNoBoundary(t *testing.T) {
	base, _ := linearGraph(t)
	before := requireBoundary(t, base, "one.example:5432")

	s := newSpec(t)
	dns := s.endpoint("a-dns", "one.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("a-tcp", "one.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	tls := s.endpoint("a-tls", "one.example:5432", domain.LayerTLS, "tls.handshake", domain.StateSkipped)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.blockedBy(tls, tcp)

	// A second endpoint the run never got to. Every one of its steps ended
	// UNKNOWN with a local-budget class.
	s.unknown("f-dns", "never.example:5432", domain.LayerDNS, "dns.lookup")
	s.unknown("f-tcp", "never.example:5432", domain.LayerTCP, "tcp.connect")
	g := s.freeze()

	if _, ok := boundaryOf(t, g, "never.example:5432"); ok {
		t.Fatal("a subject that was never measured produced a boundary")
	}
	if got := len(Boundaries(g)); got != 1 {
		t.Fatalf("got %d boundaries, want 1; the unmeasured subject added one", got)
	}

	// ADR 0079 section 7: adding a subject that was never attempted does not
	// change any existing boundary.
	after := requireBoundary(t, g, "one.example:5432")
	if after.FirstEvidencedFailure() != before.FirstEvidencedFailure() {
		t.Errorf("the measured subject's failure moved: %q -> %q",
			before.FirstEvidencedFailure(), after.FirstEvidencedFailure())
	}
	if beforeGood, _ := before.LastConfirmedGood(); beforeGood != mustLast(after) {
		t.Errorf("the measured subject's last good moved: %q -> %q",
			beforeGood, mustLast(after))
	}

	// And the boundary is a pure function of the graph: repeating the call
	// cannot move it, which is what makes an incomplete run's report stable.
	repeated := renderBoundaries(Boundaries(g))
	for range 16 {
		if again := renderBoundaries(Boundaries(g)); again != repeated {
			t.Fatalf("Boundaries is not a pure function of the graph:\n%s\n%s",
				repeated, again)
		}
	}
}

// TestASkippedStepAboveTheFailureIsNotTheFailure closes the gap the Phase 10.1A
// mutation suite found.
//
// TestDIAG011LinearBoundary looked like it covered "SKIPPED is not a failure",
// and it did not: in that fixture the SKIPPED step is *below* the failure, so the
// walk stops before reaching it and a mutation admitting SKIPPED changed nothing.
// The case that discriminates is a step declined at a shallower layer than the
// one that actually failed — a policy skip above a real failure — because there
// the two answers differ.
//
// The shape is not hypothetical. A run that declines to send a credential over
// an unverified channel records a SKIPPED authentication and goes on to measure
// what it can; if that skip could become a boundary, the report would name the
// wrong layer and svcdoctor's own policy would read as the target's fault.
func TestASkippedStepAboveTheFailureIsNotTheFailure(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("s-dns", "skip.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("s-tcp", "skip.example:5432", domain.LayerTCP, "tcp.connect", domain.StateSkipped)
	tls := s.endpoint("s-tls", "skip.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	g := s.freeze()

	b := requireBoundary(t, g, "skip.example:5432")

	if got := b.FirstEvidencedFailure(); got != "s-tls" {
		t.Errorf("first evidenced failure = %q, want s-tls; a step that did not run is "+
			"not a failure, whichever layer it sits at", got)
	}
	if got, ok := b.LastConfirmedGood(); !ok || got != "s-dns" {
		t.Errorf("last confirmed-good = %q (ok=%v), want s-dns; a SKIPPED step is not "+
			"confirmed good either", got, ok)
	}
	if got := b.NotMeasured(); !slices.Equal(got, []domain.EvidenceID{"s-tcp"}) {
		t.Errorf("not measured = %v, want [s-tcp]", got)
	}
}

// TestAnUnknownStepAboveTheFailureIsNotTheFailure is the same shape for the
// other not-measured state, and for the same reason.
func TestAnUnknownStepAboveTheFailureIsNotTheFailure(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("v-dns", "budget.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.unknown("v-tcp", "budget.example:5432", domain.LayerTCP, "tcp.connect")
	tls := s.endpoint("v-tls", "budget.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	g := s.freeze()

	b := requireBoundary(t, g, "budget.example:5432")

	if got := b.FirstEvidencedFailure(); got != "v-tls" {
		t.Errorf("first evidenced failure = %q, want v-tls", got)
	}
	if got, ok := b.LastConfirmedGood(); !ok || got != "v-dns" {
		t.Errorf("last confirmed-good = %q (ok=%v), want v-dns", got, ok)
	}
}

// TestTheBoundaryFollowsLayerOrderNotIdentifierOrder closes the second gap the
// mutation suite found.
//
// domain.Graph returns nodes in EvidenceID lexical order, and every earlier
// fixture here happened to name its nodes so that identifier order and layer
// order agreed — so removing the layer sort changed nothing and the mutation
// survived. Identifier order is an artefact of how a producer names things;
// layer order is the domain's own, and ADR 0079 section 2.2 defines both halves
// of a boundary in terms of it.
//
// The identifiers below are chosen so the two orders disagree: sorted by
// identifier the failure comes first, sorted by layer it comes last.
func TestTheBoundaryFollowsLayerOrderNotIdentifierOrder(t *testing.T) {
	s := newSpec(t)
	// Identifier order: a-auth, m-tcp, z-dns.
	// Layer order:      z-dns (L1), m-tcp (L2), a-auth (L5).
	dns := s.endpoint("z-dns", "order.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("m-tcp", "order.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	auth := s.endpoint("a-auth", "order.example:5432", domain.LayerAuth, "auth.exchange", domain.StateFail)
	s.parent(tcp, dns)
	s.parent(auth, tcp)
	g := s.freeze()

	// The premise: the graph really does hand them over in the disagreeing order.
	var asStored []domain.EvidenceID
	for _, node := range g.Nodes() {
		asStored = append(asStored, node.ID())
	}
	if want := []domain.EvidenceID{"a-auth", "m-tcp", "z-dns"}; !slices.Equal(asStored, want) {
		t.Fatalf("the graph returned %v, want %v; this fixture no longer discriminates",
			asStored, want)
	}

	b := requireBoundary(t, g, "order.example:5432")

	if got := b.FirstEvidencedFailure(); got != "a-auth" {
		t.Errorf("first evidenced failure = %q, want a-auth", got)
	}
	if got, ok := b.LastConfirmedGood(); !ok || got != "m-tcp" {
		t.Errorf("last confirmed-good = %q (ok=%v), want m-tcp — the deepest PASS above "+
			"the failure by layer, not the first node by identifier", got, ok)
	}
}

// TestDegradedIsAFailureHalf pins ADR 0079 section 2.2's exact wording: the
// first evidenced failure is the shallowest FAIL **or DEGRADED**.
//
// A DEGRADED node is a positively observed problem, unlike UNKNOWN and SKIPPED,
// so it belongs on the failure side of the contrast.
func TestDegradedIsAFailureHalf(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("g-dns", "deg.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tls := s.endpoint("g-tls", "deg.example:5432", domain.LayerTLS, "tls.handshake", domain.StateDegraded)
	s.parent(tls, dns)
	g := s.freeze()

	b := requireBoundary(t, g, "deg.example:5432")
	if got := b.FirstEvidencedFailure(); got != "g-tls" {
		t.Errorf("first evidenced failure = %q, want g-tls", got)
	}
}

// TestAPassBelowTheFailureIsNotTheLastConfirmedGood pins the half of ADR 0079
// section 2.2 that makes the pair a contrast rather than two loose facts.
//
// A deeper step that somehow passed is not "the last thing that worked before it
// broke", and citing it would describe a chain that did not happen.
func TestAPassBelowTheFailureIsNotTheLastConfirmedGood(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("h-dns", "odd.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.endpoint("h-tcp", "odd.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	auth := s.endpoint("h-auth", "odd.example:5432", domain.LayerAuth, "auth.exchange", domain.StatePass)
	s.parent(tcp, dns)
	s.parent(auth, tcp)
	g := s.freeze()

	b := requireBoundary(t, g, "odd.example:5432")
	if got, _ := b.LastConfirmedGood(); got != "h-dns" {
		t.Errorf("last confirmed-good = %q, want h-dns; the deeper PASS is below the failure", got)
	}
}

// TestTheBoundaryIsDerivedFromEvidenceAndNothingElse guards the conceptual
// ownership question ADR 0079 raises and the Phase 10.1a prompt asks to settle.
//
// A boundary is computed from the graph. It reads no Finding, so there is no
// route by which a finding could feed a boundary that then produces a finding.
// The chain is evidence to boundary to finding, one way, and no hypothesis is
// derived from another hypothesis.
//
// The structural half — that this file's production sibling names no finding
// type — is asserted by the vocabulary guard in test/security. This is the
// behavioural half: the same graph gives the same boundary regardless of what
// any rule concluded about it.
func TestTheBoundaryIsDerivedFromEvidenceAndNothingElse(t *testing.T) {
	g, subject := linearGraph(t)

	want := requireBoundary(t, g, "one.example:5432")

	// Run a rule set over the same graph that produces findings about the very
	// nodes the boundary cites, then recompute. Nothing may move.
	engine := engineOf(t, func(ctx RuleContext) []domain.Finding {
		return []domain.Finding{findingAbout(t, "TCP_CONNECTION_REFUSED", subject,
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh,
			"nothing accepted a connection on that port from here", "a-tcp")}
	})
	if got := engine.Diagnose(RuleContext{Graph: g}); len(got) != 1 {
		t.Fatalf("the fixture rule produced %d findings, want 1", len(got))
	}

	again := requireBoundary(t, g, "one.example:5432")
	if again.FirstEvidencedFailure() != want.FirstEvidencedFailure() {
		t.Error("the boundary changed once a finding existed about the same evidence")
	}
	if mustLast(again) != mustLast(want) {
		t.Error("the boundary's confirmed-good half changed once a finding existed")
	}
}

// TestBoundariesAreRepeatable is the determinism half over the boundary walk.
//
// Repeated because Go randomizes map iteration per range, and BlockedChain
// inverts the blocked-by relation through a map. A single pass would pass by
// luck.
func TestBoundariesAreRepeatable(t *testing.T) {
	s := newSpec(t)
	for _, ref := range []string{"m1.example:5432", "m2.example:5432", "m3.example:5432"} {
		dns := s.endpoint(ref[:2]+"-dns", ref, domain.LayerDNS, "dns.lookup", domain.StatePass)
		tcp := s.endpoint(ref[:2]+"-tcp", ref, domain.LayerTCP, "tcp.connect", domain.StateFail)
		tls := s.endpoint(ref[:2]+"-tls", ref, domain.LayerTLS, "tls.handshake", domain.StateSkipped)
		s.parent(tcp, dns)
		s.parent(tls, tcp)
		s.blockedBy(tls, tcp)
	}
	g := s.freeze()

	first := renderBoundaries(Boundaries(g))
	for i := range 64 {
		if again := renderBoundaries(Boundaries(g)); again != first {
			t.Fatalf("iteration %d differed:\n%s\n%s", i, first, again)
		}
	}
}

func mustLast(b Boundary) domain.EvidenceID {
	id, _ := b.LastConfirmedGood()
	return id
}

// renderBoundaries flattens boundaries into one comparable string.
func renderBoundaries(bs []Boundary) string {
	out := ""
	for _, b := range bs {
		last, _ := b.LastConfirmedGood()
		out += b.Subject().String() + "|" + string(last) + "|" + string(b.FirstEvidencedFailure()) + "|"
		for _, id := range b.Blocked() {
			out += string(id) + ","
		}
		out += "|"
		for _, id := range b.NotMeasured() {
			out += string(id) + ","
		}
		out += "\n"
	}
	return out
}
