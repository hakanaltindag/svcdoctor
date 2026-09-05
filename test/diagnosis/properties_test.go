package diagnosis_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 10.1B properties over the activated pipeline.
//
// The monotonic epistemic property is the general form of the lesson this
// project has learned twice: **less evidence must never produce a stronger
// claim**. It is checked here by degradation rather than by construction —
// take a graph, weaken it, and require the output to weaken with it — because
// that is the direction real runs move in when a budget expires or a step is
// cancelled.

// claimStrength orders what a report says about a subject, weakest first.
//
// It is a test-only ordering and deliberately coarse: the property is that
// weakening evidence cannot move a report *up* this list, and a finer scale
// would invite arguing about rungs instead of about the direction.
type claimStrength int

const (
	strengthNothing claimStrength = iota
	strengthBoundaryWithoutContrast
	strengthBoundaryWithContrast
)

func (s claimStrength) String() string {
	switch s {
	case strengthNothing:
		return "no claim"
	case strengthBoundaryWithoutContrast:
		return "a boundary with no confirmed-good half"
	case strengthBoundaryWithContrast:
		return "a boundary contrasting two measured stages"
	}
	return "unknown"
}

// strengthFor reads what the report claims about one subject.
func strengthFor(t *testing.T, r run, subjectRef string) claimStrength {
	t.Helper()

	b, present := r.boundaries(t)[subjectRef]
	if !present {
		return strengthNothing
	}
	if len(b.EvidenceRefs()) >= 2 {
		return strengthBoundaryWithContrast
	}
	return strengthBoundaryWithoutContrast
}

// chain builds dns -> tcp -> tls for one subject with the given states.
func chain(t *testing.T, dnsState, tcpState, tlsState domain.State) domain.Graph {
	t.Helper()

	s := newGraph(t)
	dns := s.node("m-dns", "m.example:5432", domain.LayerDNS,
		string(vocabulary.StepDNSLookup), dnsState)
	tcp := s.node("m-tcp", "m.example:5432", domain.LayerTCP,
		string(vocabulary.StepTCPConnect), tcpState)
	tls := s.node("m-tls", "m.example:5432", domain.LayerTLS,
		string(vocabulary.StepTLSHandshake), tlsState)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	return s.freeze()
}

// TestMonotonicEpistemicProperty is the section 34 contract.
//
// Each row degrades one node of the row above it — a measured state becomes an
// unmeasured one — and the claim must never get stronger.
func TestMonotonicEpistemicProperty(t *testing.T) {
	const subject = "m.example:5432"

	steps := []struct {
		name                         string
		dns, tcp, tls                domain.State
		want                         claimStrength
		whyDegradingCannotStrengthen string
	}{
		{
			"everything measured, TLS failed",
			domain.StatePass, domain.StatePass, domain.StateFail,
			strengthBoundaryWithContrast,
			"the strongest thing a boundary says: two measured stages, contrasted",
		},
		{
			"TCP became unmeasured",
			domain.StatePass, domain.StateUnknown, domain.StateFail,
			strengthBoundaryWithContrast,
			"the contrast survives because DNS is still a measured success below the failure",
		},
		{
			"DNS became unmeasured too",
			domain.StateUnknown, domain.StateUnknown, domain.StateFail,
			strengthBoundaryWithoutContrast,
			"nothing succeeded, so the confirmed-good half is reported absent",
		},
		{
			"the failure itself became unmeasured",
			domain.StateUnknown, domain.StateUnknown, domain.StateUnknown,
			strengthNothing,
			"no definitive failure remains, so there is no boundary at all",
		},
	}

	previous := strengthBoundaryWithContrast
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			r := diagnose(t, chain(t, step.dns, step.tcp, step.tls), true)

			got := strengthFor(t, r, subject)
			if got != step.want {
				t.Errorf("claim = %s, want %s", got, step.want)
			}
			if got > previous {
				t.Errorf("degrading evidence strengthened the claim: %s -> %s.\n\n"+
					"Less evidence must never produce a stronger statement.\n%s",
					previous, got, step.whyDegradingCannotStrengthen)
			}
			previous = got
		})
	}
}

// TestDeletingCitedEvidenceNeverStrengthensTheClaim is the same property from
// the other direction: remove a node rather than weaken it.
func TestDeletingCitedEvidenceNeverStrengthensTheClaim(t *testing.T) {
	const subject = "m.example:5432"

	full := diagnose(t, chain(t, domain.StatePass, domain.StatePass, domain.StateFail), false)
	strong := strengthFor(t, full, subject)
	if strong != strengthBoundaryWithContrast {
		t.Fatalf("the baseline claim is %s; the degradation below would prove nothing", strong)
	}

	// The same graph with the confirmed-good half simply absent.
	s := newGraph(t)
	tcp := s.node("m-tcp", subject, domain.LayerTCP,
		string(vocabulary.StepTCPConnect), domain.StatePass)
	tls := s.node("m-tls", subject, domain.LayerTLS,
		string(vocabulary.StepTLSHandshake), domain.StateFail)
	s.parent(tls, tcp)
	partial := diagnose(t, s.freeze(), false)

	if got := strengthFor(t, partial, subject); got > strong {
		t.Errorf("removing a node strengthened the claim: %s -> %s", strong, got)
	}
}

// TestContradictionMonotonicity is section 35: adding contradictory evidence
// never increases confidence, severity or specificity.
func TestContradictionMonotonicity(t *testing.T) {
	g := chain(t, domain.StatePass, domain.StatePass, domain.StateFail)

	subject, err := domain.NewEndpointSubject("m.example:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}

	rule := func(contradicting bool) diagnosis.Rule {
		return func(ctx diagnosis.RuleContext) []domain.Finding {
			builder := diagnosis.NewBasis().Support("m-dns", "m-tcp")
			if contradicting {
				builder = builder.Contradict("m-tls")
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

	pick := func(r run) domain.Finding {
		for _, f := range r.report.Findings() {
			if f.Code() == "TCP_CONNECTION_REFUSED" {
				return f
			}
		}
		t.Fatal("the hypothesis was not emitted")
		return domain.Finding{}
	}

	clean := pick(diagnose(t, g, false, namedRule{"test/ladder", rule(false)}))
	dirty := pick(diagnose(t, g, false, namedRule{"test/ladder", rule(true)}))

	if dirty.Confidence() > clean.Confidence() {
		t.Errorf("contradiction raised confidence: %s -> %s",
			clean.Confidence(), dirty.Confidence())
	}
	if dirty.Severity() > clean.Severity() {
		t.Errorf("contradiction raised severity: %s -> %s", clean.Severity(), dirty.Severity())
	}
	if dirty.Kind() == domain.FindingKindConfirmed && clean.Kind() == domain.FindingKindHypothesis {
		t.Error("contradiction promoted a hypothesis to a proof")
	}
}

// TestRecommendationMonotonicity is section 36, checked structurally.
//
// The strength ladder is REMEDIATION -> NEXT_EVIDENCE -> nothing, and evidence
// can only move a recommendation down it. Phase 10.1B emits no recommendation of
// its own, so what is proven here is that the gate which will govern them
// already refuses every upward move.
func TestRecommendationMonotonicity(t *testing.T) {
	remediation, err := diagnosis.NewAdvice(diagnosis.AdviceInput{
		Kind:      diagnosis.AdviceKindRemediation,
		Safety:    diagnosis.SafetyConfigChange,
		Action:    "correct the configured address so it is reachable from this network",
		Rationale: "the address was advertised and no connection to it succeeded",
	})
	if err != nil {
		t.Fatalf("NewAdvice: %v", err)
	}

	// As the claim weakens, the remediation must stop being admissible. The
	// order below is strongest-first.
	weakening := []struct {
		kind       domain.FindingKind
		confidence domain.Confidence
	}{
		{domain.FindingKindConfirmed, domain.ConfidenceHigh},
		{domain.FindingKindConfirmed, domain.ConfidenceMedium},
		{domain.FindingKindConfirmed, domain.ConfidenceLow},
		{domain.FindingKindHypothesis, domain.ConfidenceHigh},
		{domain.FindingKindHypothesis, domain.ConfidenceMedium},
		{domain.FindingKindHypothesis, domain.ConfidenceLow},
	}

	admitted := true
	for _, step := range weakening {
		err := diagnosis.AdmitAdvice(step.kind, step.confidence, remediation)
		nowAdmitted := err == nil
		if nowAdmitted && !admitted {
			t.Errorf("%s at %s re-admitted a remediation that a stronger claim was "+
				"refused; recommendation strength must never increase as evidence weakens",
				step.kind, step.confidence)
		}
		admitted = nowAdmitted
	}
	if admitted {
		t.Error("a LOW hypothesis still admits a remediation")
	}
}

// TestABoundaryDoesNotChangeAHealthyExitCode is section 28.
//
// The boundary is INFO, and INFO never sets PROBLEMS_FOUND. What this guards is
// the case that would otherwise be invisible: a graph with a failing node that
// no service rule owns. Before Phase 10.1B that reported status OK with no
// findings; it must still report OK, now with one INFO finding.
func TestABoundaryDoesNotChangeAHealthyExitCode(t *testing.T) {
	// A failing node with no service rule wired to explain it.
	g := chain(t, domain.StatePass, domain.StatePass, domain.StateFail)
	r := diagnose(t, g, false)

	if len(r.report.Findings()) != 1 {
		t.Fatalf("got %d findings, want exactly the boundary: %v",
			len(r.report.Findings()), r.report.Findings())
	}
	if got := r.report.Findings()[0].Severity(); got != domain.SeverityInfo {
		t.Fatalf("the boundary is %s, want INFO", got)
	}
	if got := r.report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK.\n\n"+
			"A derived informational boundary must not turn an otherwise "+
			"non-problem report into exit 1.", got)
	}

	// And an all-PASS run is unchanged in every respect.
	healthy := diagnose(t, chain(t, domain.StatePass, domain.StatePass, domain.StatePass), false)
	if got := len(healthy.report.Findings()); got != 0 {
		t.Errorf("a healthy run produced %d findings", got)
	}
	if got := healthy.report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("a healthy run reports %s", got)
	}
}

// TestARulePanicLosesOnlyThatRulesOutput is section 29, through the pipeline.
func TestARulePanicLosesOnlyThatRulesOutput(t *testing.T) {
	g := chain(t, domain.StatePass, domain.StatePass, domain.StateFail)

	const secret = "hunter2-this-must-not-appear-anywhere"
	panicking := func(diagnosis.RuleContext) []domain.Finding { panic(secret) }

	r := diagnose(t, g, false, namedRule{"test/panics", panicking})

	// The boundary survived, so one rule's defect did not destroy the rest.
	if got := r.boundaries(t); len(got) != 1 {
		t.Fatalf("got %d boundaries after a rule panicked, want 1", len(got))
	}
	if !r.outcome.Failed() {
		t.Error("the panicking rule was not recorded as a failure")
	}
	failures := r.outcome.Failures()
	if len(failures) != 1 || failures[0].Rule() != "test/panics" {
		t.Errorf("Failures() = %v, want exactly the panicking rule", failures)
	}

	// The panic value reaches no output surface.
	for name, text := range map[string]string{
		"canonical JSON": r.canonicalJSON(t),
		"shareable JSON": r.shareableJSON(t),
		"terminal":       r.terminal(t),
	} {
		if strings.Contains(text, secret) {
			t.Errorf("the panic value reached the %s output:\n%s", name, text)
		}
	}

	// And the evidence is untouched: a defective rule degrades a report rather
	// than corrupting one.
	if got := stateOf(t, g, "m-tls"); got != domain.StateFail {
		t.Errorf("the graph changed during a panicking evaluation: m-tls is %s", got)
	}
	if g.Len() != 3 {
		t.Errorf("the graph has %d nodes after a panic, want 3", g.Len())
	}
}

// TestTheActivatedPipelineIsDeterministic repeats the Phase 10.1a determinism
// proof after activation, and across GOMAXPROCS.
func TestTheActivatedPipelineIsDeterministic(t *testing.T) {
	s := newGraph(t)
	for _, addr := range []string{"10.0.0.3", "10.0.0.1", "10.0.0.2"} {
		dns := s.node("d-dns-"+addr, addr+":5432", domain.LayerDNS,
			string(vocabulary.StepDNSLookup), domain.StatePass)
		tcp := s.node("d-tcp-"+addr, addr+":5432", domain.LayerTCP,
			string(vocabulary.StepTCPConnect), domain.StateFail)
		tls := s.node("d-tls-"+addr, addr+":5432", domain.LayerTLS,
			string(vocabulary.StepTLSHandshake), domain.StateSkipped)
		s.parent(tcp, dns)
		s.parent(tls, tcp)
		s.blocked(tls, tcp)
	}
	g := s.freeze()

	first := diagnose(t, g, false)
	wantJSON := first.canonicalJSON(t)
	wantShareable := first.shareableJSON(t)
	wantTerminal := first.terminal(t)

	original := runtime.GOMAXPROCS(0)
	t.Cleanup(func() { runtime.GOMAXPROCS(original) })

	for _, procs := range []int{1, 2, 4, original} {
		runtime.GOMAXPROCS(procs)
		for i := range 16 {
			again := diagnose(t, g, false)
			if got := again.canonicalJSON(t); got != wantJSON {
				t.Fatalf("GOMAXPROCS=%d iteration %d: canonical JSON differed:\n%s\n%s",
					procs, i, wantJSON, got)
			}
			if got := again.shareableJSON(t); got != wantShareable {
				t.Fatalf("GOMAXPROCS=%d iteration %d: shareable JSON differed", procs, i)
			}
			if got := again.terminal(t); got != wantTerminal {
				t.Fatalf("GOMAXPROCS=%d iteration %d: terminal output differed", procs, i)
			}
		}
	}

	// Three failing subjects, three boundaries, in canonical order.
	if got := len(first.boundaries(t)); got != 3 {
		t.Errorf("got %d boundaries, want 3", got)
	}
}

// TestDiagnosisCreatesNoEvidenceAndAltersNone is the section 4 invariant:
// diagnosis may derive claims and may not derive facts.
func TestDiagnosisCreatesNoEvidenceAndAltersNone(t *testing.T) {
	g := chain(t, domain.StatePass, domain.StatePass, domain.StateFail)

	before := encode(t, g.Nodes())
	beforeLen := g.Len()

	r := diagnose(t, g, false)
	if len(r.report.Findings()) == 0 {
		t.Fatal("nothing was diagnosed; this assertion would be vacuous")
	}

	if got := encode(t, g.Nodes()); got != before {
		t.Errorf("diagnosis changed the evidence:\nbefore %s\nafter  %s", before, got)
	}
	if g.Len() != beforeLen {
		t.Errorf("diagnosis changed the node count: %d -> %d", beforeLen, g.Len())
	}
	// The report's own graph is the same one, node for node.
	if got := r.report.Graph().Len(); got != beforeLen {
		t.Errorf("the report's graph has %d nodes, want %d", got, beforeLen)
	}

	// Every cited reference resolves, which the report validates and this
	// restates against the graph the caller still holds.
	for _, f := range r.report.Findings() {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := g.Node(ref); !ok {
				t.Errorf("finding %s cites %q, which diagnosis must not have invented",
					f.Code(), ref)
			}
		}
	}
}

// TestTheBoundaryProseIsIndependentOfEvidenceAttributes is ADR 0081 section 2.7
// at the one place Phase 10.1B put new prose into a report.
//
// The boundary interpolates exactly two values and both are svcdoctor's own
// closed vocabulary — domain.Layer.Label(). An evidence attribute is where a
// peer-supplied string legitimately arrives, and the property is that no such
// value can change a byte of what the boundary says.
//
// It is checked by substitution rather than by substring absence, for the reason
// Phase 10.1a recorded: a short hostile value is a substring of ordinary English,
// so "the value does not appear" is not checkable while "the value changes
// nothing" is.
func TestTheBoundaryProseIsIndependentOfEvidenceAttributes(t *testing.T) {
	build := func(t *testing.T, attrValue string) run {
		t.Helper()

		key, err := domain.NewAttributeKey("peer.message")
		if err != nil {
			t.Fatalf("NewAttributeKey: %v", err)
		}
		subject, err := domain.NewEndpointSubject("p.example:5432")
		if err != nil {
			t.Fatalf("NewEndpointSubject: %v", err)
		}
		step, err := domain.NewStep(string(vocabulary.StepTCPConnect))
		if err != nil {
			t.Fatalf("NewStep: %v", err)
		}

		builder := domain.NewGraphBuilder()
		good, err := domain.NewEvidence(domain.EvidenceInput{
			ID: "p-dns", Subject: subject, Layer: domain.LayerDNS,
			Step: domain.Step(vocabulary.StepDNSLookup), State: domain.StatePass,
			FailureClass: domain.FailureNone, StartedAt: fixedStart,
			Elapsed: domain.Measured(0),
		})
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		bad, err := domain.NewEvidence(domain.EvidenceInput{
			ID: "p-tcp", Subject: subject, Layer: domain.LayerTCP, Step: step,
			State: domain.StateFail, FailureClass: domain.FailureTCPConnectionRefused,
			Attributes: map[domain.AttributeKey]domain.AttrValue{key: domain.StringAttr(attrValue)},
			StartedAt:  fixedStart, Elapsed: domain.Measured(0),
		})
		if err != nil {
			t.Fatalf("NewEvidence: %v", err)
		}
		for _, e := range []domain.Evidence{good, bad} {
			if err := builder.AddEvidence(e); err != nil {
				t.Fatalf("AddEvidence: %v", err)
			}
		}
		if err := builder.AddParent("p-tcp", "p-dns"); err != nil {
			t.Fatalf("AddParent: %v", err)
		}
		g, err := builder.Freeze()
		if err != nil {
			t.Fatalf("Freeze: %v", err)
		}
		return diagnose(t, g, false)
	}

	reference := claimProse(build(t, "reference").report.Findings())
	if reference == "" {
		t.Fatal("the boundary produced no prose; this property would be vacuous")
	}

	for _, hostile := range []string{
		"ERROR: connection from 10.1.2.3 rejected by policy",
		"<script>alert(1)</script>",
		"a firewall is blocking this connection",
		strings.Repeat("A", 200),
		"%s %v %d",
	} {
		if got := claimProse(build(t, hostile).report.Findings()); got != reference {
			t.Errorf("a peer-supplied attribute changed the boundary's prose.\n"+
				"value:     %q\ngot:       %q\nreference: %q", hostile, got, reference)
		}
	}
}
