package diagnosis_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Phase 10.1B production-path scenarios, S01 through S10.
//
// Each drives a frozen graph through the real registry, the real report and the
// real renderers. What they assert is not "the engine computed a boundary" —
// internal/diagnosis proves that — but that the boundary a *report* carries says
// the right thing and refuses to say the wrong one.

// TestS01BoundaryAtTCPWithTLSBlocked is the shape every claim-discipline rule in
// this project was written against.
func TestS01BoundaryAtTCPWithTLSBlocked(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s1-dns", "a.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s1-tcp", "a.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	tls := s.node("s1-tls", "a.example:5432", domain.LayerTLS, "tls.handshake", domain.StateSkipped)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.blocked(tls, tcp)

	r := diagnose(t, s.freeze(), false)
	got := r.boundaries(t)

	if len(got) != 1 {
		t.Fatalf("got %d boundaries, want 1", len(got))
	}
	b := got["a.example:5432"]
	if b.IsZero() {
		t.Fatal("no boundary for the failing endpoint")
	}
	if want := []domain.EvidenceID{"s1-dns", "s1-tcp"}; !slices.Equal(b.EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want both halves %v", b.EvidenceRefs(), want)
	}
	if b.Layer() != domain.LayerTCP {
		t.Errorf("Layer = %s, want L2 — the first evidenced failure's own", b.Layer())
	}
	if !strings.Contains(b.Summary(), "dns") || !strings.Contains(b.Summary(), "tcp") {
		t.Errorf("Summary = %q, want it to name both stages", b.Summary())
	}

	// The blocked TLS step is cited by nothing and claimed about by nothing.
	if slices.Contains(b.EvidenceRefs(), "s1-tls") {
		t.Error("the boundary cites the step that never ran")
	}
	rendered := r.terminal(t)
	if strings.Contains(rendered, "TLS failed") || strings.Contains(rendered, "tls stage") {
		t.Errorf("the report makes a TLS claim:\n%s", rendered)
	}
}

// TestS02BoundaryAtTLSWithAuthBlocked is the prompt's second shape, and the one
// where the forbidden claim is the most tempting.
func TestS02BoundaryAtTLSWithAuthBlocked(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s2-dns", "b.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s2-tcp", "b.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	tls := s.node("s2-tls", "b.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	auth := s.node("s2-auth", "b.example:5432", domain.LayerAuth, "auth.exchange", domain.StateSkipped)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.parent(auth, tls)
	s.blocked(auth, tls)

	r := diagnose(t, s.freeze(), false)
	b := r.boundaries(t)["b.example:5432"]

	if b.IsZero() {
		t.Fatal("no boundary")
	}
	if want := []domain.EvidenceID{"s2-tcp", "s2-tls"}; !slices.Equal(b.EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want %v", b.EvidenceRefs(), want)
	}
	if b.Layer() != domain.LayerTLS {
		t.Errorf("Layer = %s, want L3", b.Layer())
	}

	// Authentication was never attempted. Nothing in the report may say it
	// failed, and nothing may say it succeeded.
	rendered := strings.ToLower(r.terminal(t))
	for _, forbidden := range []string{
		"authentication failed", "auth failed", "credential was rejected",
		"authentication succeeded",
	} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the report claims %q about a step that never ran", forbidden)
		}
	}
}

// TestS03TwoBranchesFailingAtDifferentLayers is the branch-scoping contract.
//
// Collapsing these into one "network problem" is the false summary ADR 0079
// exists to prevent, and it is what a run-level boundary would have produced.
func TestS03TwoBranchesFailingAtDifferentLayers(t *testing.T) {
	s := newGraph(t)
	aDNS := s.node("s3-a-dns", "a.example:9092", domain.LayerDNS, "dns.lookup", domain.StatePass)
	aTCP := s.node("s3-a-tcp", "a.example:9092", domain.LayerTCP, "tcp.connect", domain.StatePass)
	aTLS := s.node("s3-a-tls", "a.example:9092", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(aTCP, aDNS)
	s.parent(aTLS, aTCP)

	bDNS := s.node("s3-b-dns", "b.example:9092", domain.LayerDNS, "dns.lookup", domain.StatePass)
	bTCP := s.node("s3-b-tcp", "b.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	s.parent(bTCP, bDNS)

	r := diagnose(t, s.freeze(), false)
	got := r.boundaries(t)

	if len(got) != 2 {
		t.Fatalf("got %d boundaries, want 2 — one per branch", len(got))
	}
	if layer := got["a.example:9092"].Layer(); layer != domain.LayerTLS {
		t.Errorf("branch a boundary is at %s, want L3", layer)
	}
	if layer := got["b.example:9092"].Layer(); layer != domain.LayerTCP {
		t.Errorf("branch b boundary is at %s, want L2", layer)
	}
	if got["a.example:9092"].Subject() == got["b.example:9092"].Subject() {
		t.Error("the two boundaries share a subject")
	}
}

// TestS04AllPassProducesNoBoundary is the negative case, and the one a rule
// eager to say something would break first.
func TestS04AllPassProducesNoBoundary(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s4-dns", "ok.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s4-tcp", "ok.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	tls := s.node("s4-tls", "ok.example:5432", domain.LayerTLS, "tls.handshake", domain.StatePass)
	s.parent(tcp, dns)
	s.parent(tls, tcp)

	r := diagnose(t, s.freeze(), false)

	if got := r.boundaries(t); len(got) != 0 {
		t.Fatalf("a healthy run produced %d boundaries", len(got))
	}
	if got := len(r.report.Findings()); got != 0 {
		t.Errorf("a healthy run produced %d findings, want none", got)
	}
	if got := r.report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", got)
	}
}

// TestS05AnUnknownProducesNoDefinitiveBoundary is the epistemic core.
//
// UNKNOWN is not a definitive failure. A run that could not measure TCP has no
// boundary at all — not a weak one, and not one standing at DNS.
func TestS05AnUnknownProducesNoDefinitiveBoundary(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s5-dns", "c.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s5-tcp", "c.example:5432", domain.LayerTCP, "tcp.connect", domain.StateUnknown)
	s.parent(tcp, dns)
	g := s.freeze()

	r := diagnose(t, g, false)

	if got := r.boundaries(t); len(got) != 0 {
		t.Fatalf("an UNKNOWN produced %d boundaries: %v", len(got), got)
	}
	// And diagnosis did not touch the state on its way past.
	if got := stateOf(t, g, "s5-tcp"); got != domain.StateUnknown {
		t.Errorf("the UNKNOWN node is now %s", got)
	}
}

// TestS06FirstMeasuredNodeFailingLeavesNoFabricatedLastGood is the
// represent-the-absence contract.
func TestS06FirstMeasuredNodeFailingLeavesNoFabricatedLastGood(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s6-dns", "gone.example:5432", domain.LayerDNS, "dns.lookup", domain.StateFail)
	tcp := s.node("s6-tcp", "gone.example:5432", domain.LayerTCP, "tcp.connect", domain.StateSkipped)
	s.parent(tcp, dns)
	s.blocked(tcp, dns)

	r := diagnose(t, s.freeze(), false)
	b := r.boundaries(t)["gone.example:5432"]

	if b.IsZero() {
		t.Fatal("no boundary; a definitive failure exists")
	}
	if want := []domain.EvidenceID{"s6-dns"}; !slices.Equal(b.EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want only the failure %v — there is no good half",
			b.EvidenceRefs(), want)
	}
	if !strings.Contains(b.Detail(), "no confirmed-good stage") {
		t.Errorf("Detail = %q, want the absence stated rather than filled in", b.Detail())
	}
	if !strings.Contains(b.Summary(), "first stage measured") {
		t.Errorf("Summary = %q, want it to say the first measured stage failed", b.Summary())
	}
}

// TestS07CancellationProducesNoCompletenessClaim is the RAB18 lesson at the
// pipeline level.
func TestS07CancellationProducesNoCompletenessClaim(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s7-dns", "d.example:9092", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s7-tcp", "d.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	s.parent(tcp, dns)
	// A second endpoint the run never reached.
	s.node("s7-never", "e.example:9092", domain.LayerTCP, "tcp.connect", domain.StateUnknown)
	g := s.freeze()

	complete := diagnose(t, g, false)
	cut := diagnose(t, g, true)

	// The unmeasured endpoint gets no boundary either way.
	for name, r := range map[string]run{"complete": complete, "incomplete": cut} {
		got := r.boundaries(t)
		if len(got) != 1 {
			t.Fatalf("%s: got %d boundaries, want 1", name, len(got))
		}
		if _, present := got["e.example:9092"]; present {
			t.Errorf("%s: the never-measured endpoint got a boundary", name)
		}
	}

	// Incompleteness is a fact about svcdoctor and changes no claim about the
	// target: the two reports' findings are byte-identical.
	if a, b := encode(t, complete.report.Findings()), encode(t, cut.report.Findings()); a != b {
		t.Errorf("marking the run incomplete changed the findings:\n%s\n%s", a, b)
	}

	// And nothing anywhere describes the measured set as complete.
	rendered := strings.ToLower(cut.terminal(t))
	for _, forbidden := range []string{"all endpoints", "every endpoint", "only ", "all of the"} {
		if strings.Contains(rendered, forbidden) {
			t.Errorf("the report claims completeness with %q:\n%s", forbidden, rendered)
		}
	}
}

// TestS08TwoRulesOneConclusionConverge drives convergence through the pipeline.
func TestS08TwoRulesOneConclusionConverge(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s8-dns", "f.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s8-tcp", "f.example:5432", domain.LayerTCP, "tcp.connect", domain.StateFail)
	s.parent(tcp, dns)
	g := s.freeze()

	subject, err := domain.NewEndpointSubject("f.example:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	claim := func(ref domain.EvidenceID, summary string) diagnosis.Rule {
		return func(diagnosis.RuleContext) []domain.Finding {
			f, err := domain.NewFinding(domain.FindingInput{
				Code: "TCP_CONNECTION_REFUSED", Kind: domain.FindingKindConfirmed,
				Severity: domain.SeverityError, Confidence: domain.ConfidenceHigh,
				Layer: domain.LayerTCP, Subject: subject, Summary: summary,
				EvidenceRefs: []domain.EvidenceID{ref},
			})
			if err != nil {
				t.Fatalf("NewFinding: %v", err)
			}
			return []domain.Finding{f}
		}
	}

	r := diagnose(t, g, false,
		namedRule{"test/route-one", claim("s8-tcp", "one route to the claim")},
		namedRule{"test/route-two", claim("s8-dns", "another route to the claim")})

	var merged []domain.Finding
	for _, f := range r.report.Findings() {
		if f.Code() == "TCP_CONNECTION_REFUSED" {
			merged = append(merged, f)
		}
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings for one conclusion, want 1: %v", len(merged), merged)
	}
	if want := []domain.EvidenceID{"s8-dns", "s8-tcp"}; !slices.Equal(merged[0].EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want the union %v", merged[0].EvidenceRefs(), want)
	}
}

// TestS09SameCodeDifferentSubjectStaysTwoResults is convergence's other half.
func TestS09SameCodeDifferentSubjectStaysTwoResults(t *testing.T) {
	s := newGraph(t)
	first := s.node("s9-a", "a.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	second := s.node("s9-b", "b.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	g := s.freeze()

	claim := func(ref domain.EvidenceID, subjectRef string) diagnosis.Rule {
		return func(diagnosis.RuleContext) []domain.Finding {
			subject, err := domain.NewEndpointSubject(subjectRef)
			if err != nil {
				t.Fatalf("NewEndpointSubject: %v", err)
			}
			f, err := domain.NewFinding(domain.FindingInput{
				Code: "TCP_CONNECTION_REFUSED", Kind: domain.FindingKindConfirmed,
				Severity: domain.SeverityError, Confidence: domain.ConfidenceHigh,
				Layer: domain.LayerTCP, Subject: subject,
				Summary:      "identical prose about two different endpoints",
				EvidenceRefs: []domain.EvidenceID{ref},
			})
			if err != nil {
				t.Fatalf("NewFinding: %v", err)
			}
			return []domain.Finding{f}
		}
	}

	r := diagnose(t, g, false,
		namedRule{"test/a", claim(first, "a.example:9092")},
		namedRule{"test/b", claim(second, "b.example:9092")})

	subjects := map[string]bool{}
	for _, f := range r.report.Findings() {
		if f.Code() == "TCP_CONNECTION_REFUSED" {
			subjects[f.Subject().Ref()] = true
		}
	}
	if len(subjects) != 2 {
		t.Fatalf("two subjects produced %d results: %v", len(subjects), subjects)
	}
}

// TestS10ContradictionDoesNotRaiseConfidence drives the admission ladder through
// the pipeline rather than in isolation.
//
// The rule below consults its own basis honestly: with contradicting evidence
// present the ladder caps it at LOW, and a claim it cannot support at all is not
// emitted. What this proves is that the pipeline carries the ladder's answer
// unchanged, rather than a report reconstructing confidence for itself.
func TestS10ContradictionDoesNotRaiseConfidence(t *testing.T) {
	s := newGraph(t)
	good := s.node("s10-dns", "g.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	also := s.node("s10-tcp", "g.example:5432", domain.LayerTCP, "tcp.connect", domain.StatePass)
	against := s.node("s10-tls", "g.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	g := s.freeze()

	subject, err := domain.NewEndpointSubject("g.example:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}

	ladderRule := func(contradicting bool) diagnosis.Rule {
		return func(ctx diagnosis.RuleContext) []domain.Finding {
			builder := diagnosis.NewBasis().Support(good, also)
			if contradicting {
				builder = builder.Contradict(against)
			}
			basis, err := builder.Freeze(ctx.Graph)
			if err != nil {
				t.Fatalf("Freeze: %v", err)
			}
			confidence, err := diagnosis.AdmitConfidence(
				domain.FindingKindHypothesis, diagnosis.AuthorityNone, basis)
			if err != nil {
				t.Fatalf("AdmitConfidence: %v", err)
			}
			f, err := domain.NewFinding(domain.FindingInput{
				Code: "TCP_CONNECTION_REFUSED", Kind: domain.FindingKindHypothesis,
				Severity: domain.SeverityWarn, Confidence: confidence,
				Layer: domain.LayerTCP, Subject: subject,
				Summary:       "the endpoint may not be usable from this vantage point",
				Discriminator: "whether the address is routable from this network",
				EvidenceRefs:  basis.Supporting(),
			})
			if err != nil {
				t.Fatalf("NewFinding: %v", err)
			}
			return []domain.Finding{f}
		}
	}

	clean := diagnose(t, g, false, namedRule{"test/ladder", ladderRule(false)})
	dirty := diagnose(t, g, false, namedRule{"test/ladder", ladderRule(true)})

	confidenceOf := func(r run) domain.Confidence {
		for _, f := range r.report.Findings() {
			if f.Code() == "TCP_CONNECTION_REFUSED" {
				return f.Confidence()
			}
		}
		t.Fatal("the hypothesis was not emitted at all")
		return domain.ConfidenceUnspecified
	}

	before, after := confidenceOf(clean), confidenceOf(dirty)
	if before != domain.ConfidenceMedium {
		t.Errorf("two converging observations gave %s, want MEDIUM", before)
	}
	if after >= before {
		t.Errorf("contradicting evidence moved confidence %s -> %s", before, after)
	}
	if after != domain.ConfidenceLow {
		t.Errorf("with contradicting evidence confidence is %s, want LOW", after)
	}
}

// TestS11ASkippedStageAboveTheFailureIsNotTheBoundary closes the gap the Phase
// 10.1B mutation suite found.
//
// S01 and S06 both looked like they covered "SKIPPED is not a definitive
// failure", and neither did: in both, the skipped step sits *below* the failure,
// so the layer-ordered walk stops before reaching it and a mutation admitting
// SKIPPED changed nothing. The case that discriminates is a stage declined at a
// shallower layer than the one that actually failed.
//
// The shape is not hypothetical. A run that declines to send a credential over
// an unverified channel records a SKIPPED authentication and goes on to measure
// what it can; if that skip could become a boundary, the report would name the
// wrong stage and svcdoctor's own policy would read as the target's fault.
func TestS11ASkippedStageAboveTheFailureIsNotTheBoundary(t *testing.T) {
	s := newGraph(t)
	dns := s.node("s11-dns", "k.example:5432", domain.LayerDNS, "dns.lookup", domain.StatePass)
	tcp := s.node("s11-tcp", "k.example:5432", domain.LayerTCP, "tcp.connect", domain.StateSkipped)
	tls := s.node("s11-tls", "k.example:5432", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(tcp, dns)
	s.parent(tls, tcp)

	r := diagnose(t, s.freeze(), false)
	b := r.boundaries(t)["k.example:5432"]

	if b.IsZero() {
		t.Fatal("no boundary")
	}
	if b.Layer() != domain.LayerTLS {
		t.Errorf("the boundary is at %s, want L3; a stage that did not run is not a "+
			"failure, whichever layer it sits at", b.Layer())
	}
	if want := []domain.EvidenceID{"s11-dns", "s11-tls"}; !slices.Equal(b.EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want %v — the skipped stage is neither half",
			b.EvidenceRefs(), want)
	}
	if slices.Contains(b.EvidenceRefs(), "s11-tcp") {
		t.Error("the boundary cites the stage that did not run")
	}
}
