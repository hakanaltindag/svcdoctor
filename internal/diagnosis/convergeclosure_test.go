package diagnosis

import (
	"encoding/json"
	"slices"
	"strconv"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.2A: the convergence closure suite, C01 through C10.
//
// Phase 10.1B fixed Summary and Detail as the RuleID tie-break winner and
// defended it on the premise that once Code, Subject and Layer match, two routes
// state one claim and only the wording differs. Phase 10.2 built the first
// service rules that falsify the premise — a rule may name in its prose
// something its subject does not carry — and Phase 10.2A measured three
// reachable production shapes where the tie-break published a claim no rule
// made.
//
// The contract now is: **semantic identity is candidacy, and the candidacy test
// covers every field a merged finding *takes* rather than *reconciles*.** These
// tests are that contract, stated so a service author can read them instead of
// reading the merge implementation.
//
// The load-bearing one is C06. Every other property here could be satisfied by
// an implementation that still consulted a rule's name somewhere; C06 permutes
// the names and requires the bytes not to move.

// claimAt builds one finding, with everything a merge might take from it under
// the caller's control.
func claimAt(
	t *testing.T, layer domain.Layer, summary, detail, discriminator string,
	kind domain.FindingKind, severity domain.Severity, confidence domain.Confidence,
	vantage bool, refs ...domain.EvidenceID,
) domain.Finding {
	t.Helper()

	subject, err := domain.NewEndpointSubject("closure.example:5432")
	if err != nil {
		t.Fatalf("NewEndpointSubject: %v", err)
	}
	f, err := domain.NewFinding(domain.FindingInput{
		Code: "TCP_CONNECTION_REFUSED", Kind: kind, Severity: severity,
		Confidence: confidence, Layer: layer, Subject: subject,
		Summary: summary, Detail: detail, Discriminator: discriminator,
		EvidenceRefs: refs, VantageDependent: vantage,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// simpleClaim is claimAt with the fields no test below varies.
func simpleClaim(t *testing.T, summary, detail string, refs ...domain.EvidenceID) domain.Finding {
	t.Helper()
	return claimAt(t, domain.LayerTCP, summary, detail, "",
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh, true, refs...)
}

// --- C01: identical prose converges ------------------------------------------

// TestC01SameIdentityAndIdenticalProseConverges.
//
// This is the case convergence exists for, and it is not hypothetical: Kafka's
// `KAFKA_AUTH_MECHANISM_NOT_OFFERED` reaches one endpoint from two protocol
// steps with byte-identical summary, detail and recommendations, and the merged
// finding cites both nodes.
func TestC01SameIdentityAndIdenticalProseConverges(t *testing.T) {
	const (
		summary = "nothing accepted a connection on that port from this vantage point"
		detail  = "the same detail, written once and shared by both routes"
	)

	merged, err := Converge([]AttributedFinding{
		{Rule: "z/second", Finding: simpleClaim(t, summary, detail, "c-two")},
		{Rule: "a/first", Finding: simpleClaim(t, summary, detail, "c-one")},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1", len(merged))
	}
	if merged[0].Summary() != summary || merged[0].Detail() != detail {
		t.Errorf("prose changed on merge: %q / %q", merged[0].Summary(), merged[0].Detail())
	}
	if want := []domain.EvidenceID{"c-one", "c-two"}; !slices.Equal(merged[0].EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want the union %v", merged[0].EvidenceRefs(), want)
	}
}

// --- C02: a differing layer does not converge --------------------------------

// TestC02SameIdentityDifferentLayerDoesNotConverge is Phase 10.1B's precondition,
// re-asserted so the closure suite covers the whole key.
//
// `POSTGRES_CONNECTION_NOT_PERMITTED` is the production instance: two rules, one
// endpoint, L4 and L5 on purpose.
func TestC02SameIdentityDifferentLayerDoesNotConverge(t *testing.T) {
	const (
		summary = "the server refused the connection"
		detail  = "one sentence, two anchors"
	)

	merged, err := Converge([]AttributedFinding{
		{Rule: "a/protocol", Finding: claimAt(t, domain.LayerProtocol, summary, detail, "",
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh, false, "c-l4")},
		{Rule: "b/auth", Finding: claimAt(t, domain.LayerAuth, summary, detail, "",
			domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh, false, "c-l5")},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("got %d findings, want 2; a layer is not chosen by a tie-break", len(merged))
	}
	layers := []domain.Layer{merged[0].Layer(), merged[1].Layer()}
	slices.Sort(layers)
	if !slices.Equal(layers, []domain.Layer{domain.LayerProtocol, domain.LayerAuth}) {
		t.Errorf("layers = %v, want each finding filed where its rule anchored it", layers)
	}
}

// --- C03 and C04: differing prose does not converge --------------------------

// TestC03SameIdentityMateriallyDifferentSummaryDoesNotConverge.
//
// The two sentences below are the shape Phase 10.2A measured in production: one
// names broker node 2 and the other broker node 7, under a subject that carries
// only the endpoint. Merging them published one sentence over both brokers'
// evidence, and the other broker's claim disappeared.
func TestC03SameIdentityMateriallyDifferentSummaryDoesNotConverge(t *testing.T) {
	const (
		first  = "the endpoint could not be reached, for broker node 2"
		second = "the endpoint could not be reached, for broker node 7"
		detail = "the same detail either way"
	)

	merged, err := Converge([]AttributedFinding{
		{Rule: "a/one", Finding: simpleClaim(t, first, detail, "c-two")},
		{Rule: "a/one", Finding: simpleClaim(t, second, detail, "c-seven")},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("got %d findings, want 2; a sentence a reader acts on is not chosen "+
			"by a tie-break", len(merged))
	}

	// Each claim keeps its own evidence. A merge that kept one sentence and both
	// nodes would be worse than either finding alone.
	for _, f := range merged {
		switch f.Summary() {
		case first:
			if !slices.Equal(f.EvidenceRefs(), []domain.EvidenceID{"c-two"}) {
				t.Errorf("%q cites %v, want only its own node", first, f.EvidenceRefs())
			}
		case second:
			if !slices.Equal(f.EvidenceRefs(), []domain.EvidenceID{"c-seven"}) {
				t.Errorf("%q cites %v, want only its own node", second, f.EvidenceRefs())
			}
		default:
			t.Errorf("an unexpected sentence survived: %q", f.Summary())
		}
	}
}

// TestC04SameIdentityMateriallyDifferentDetailDoesNotConverge.
//
// The summary carries the headline and the detail carries what a reader needs
// to act. A merge that agreed on the headline and picked one of two details
// would publish a specific explanation that half the evidence contradicts.
func TestC04SameIdentityMateriallyDifferentDetailDoesNotConverge(t *testing.T) {
	const summary = "the endpoint could not be reached"

	merged, err := Converge([]AttributedFinding{
		{Rule: "a/one", Finding: simpleClaim(t, summary,
			"every measured address refused the connection", "c-one")},
		{Rule: "b/two", Finding: simpleClaim(t, summary,
			"one address refused and the rest were never attempted", "c-two")},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("got %d findings, want 2; a detail is not chosen by a tie-break", len(merged))
	}
}

// TestC03AndC04TheKindAbsorptionCannotSmuggleAWeakerClaimIn is the sharpest
// shape Phase 10.2A found, and the reason the closure was not optional.
//
// A CONFIRMED claim about one broker and a HYPOTHESIS about another shared an
// endpoint. The unset discriminator folded into the set one, CONFIRMED absorbed
// HYPOTHESIS, the discriminator was cleared, and the report stated that an
// endpoint whose paths were never finished measuring *could not be reached*.
// Less evidence produced a stronger claim.
func TestC03AndC04TheKindAbsorptionCannotSmuggleAWeakerClaimIn(t *testing.T) {
	confirmed := claimAt(t, domain.LayerTopology,
		"the endpoint could not be reached, for broker node 2", "every path failed", "",
		domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh, true, "c-two")
	hypothesis := claimAt(t, domain.LayerTopology,
		"the endpoint may be unreachable, for broker node 7", "one path failed, the rest were not measured",
		"re-run with a larger execution budget",
		domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceLow, true, "c-seven")

	merged, err := Converge([]AttributedFinding{
		{Rule: "a/one", Finding: confirmed},
		{Rule: "a/one", Finding: hypothesis},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 2 {
		t.Fatalf("got %d findings, want 2", len(merged))
	}
	for _, f := range merged {
		if f.Kind() == domain.FindingKindHypothesis {
			if f.Discriminator() == "" {
				t.Error("the hypothesis lost the question that would settle it")
			}
			if f.Confidence() != domain.ConfidenceLow {
				t.Errorf("the hypothesis was promoted to %s", f.Confidence())
			}
		}
	}
}

// --- C05 and C06: neither wiring nor naming reaches the output ---------------

// TestC05RegistrationOrderCannotChooseProse.
func TestC05RegistrationOrderCannotChooseProse(t *testing.T) {
	const (
		summary = "one claim, reached two ways"
		detail  = "one detail, written twice"
	)
	forward := []AttributedFinding{
		{Rule: "a/one", Finding: simpleClaim(t, summary, detail, "c-one")},
		{Rule: "z/two", Finding: simpleClaim(t, summary, detail, "c-two")},
	}
	reverse := []AttributedFinding{forward[1], forward[0]}

	a, err := Converge(forward)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	b, err := Converge(reverse)
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if encodeFindings(t, a) != encodeFindings(t, b) {
		t.Errorf("input order changed the output:\n%s\n%s",
			encodeFindings(t, a), encodeFindings(t, b))
	}
}

// TestC06ARuleIDRenameCannotChangeAnything is the property this phase exists to
// establish, and it is stated structurally rather than by example.
//
// A rule identity is svcdoctor's internal name for a piece of code. It is not in
// the report (ADR 0080 section 2.5), no consumer can see it, and renaming one is
// a refactor. A diagnostic claim that moved when a rule was renamed would mean
// the report encoded a fact about svcdoctor's source tree, which is not a fact
// about the target.
//
// The test takes an input that exercises every merge behaviour at once —
// merging, not merging on layer, not merging on prose, kind absorption,
// severity and confidence maxima, the vantage OR, the discriminator, and a
// recommendation union — and rewrites every rule identity through several
// permutations, including ones that reverse the original alphabetical order. The
// encoded output must not move by a byte.
func TestC06ARuleIDRenameCannotChangeAnything(t *testing.T) {
	build := func(names []RuleID) []AttributedFinding {
		const (
			shared       = "one claim, reached two ways"
			sharedDetail = "one detail, written twice"
		)
		return []AttributedFinding{
			{Rule: names[0], Finding: withAdvice(t, claimAt(t, domain.LayerTCP, shared, sharedDetail, "",
				domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceLow, false, "c-one"),
				"look at the first thing")},
			{Rule: names[1], Finding: withAdvice(t, claimAt(t, domain.LayerTCP, shared, sharedDetail, "",
				domain.FindingKindConfirmed, domain.SeverityError, domain.ConfidenceHigh, true, "c-two"),
				"look at the second thing")},
			{Rule: names[2], Finding: claimAt(t, domain.LayerDNS, "a claim at another layer",
				"its own detail", "", domain.FindingKindConfirmed, domain.SeverityInfo,
				domain.ConfidenceMedium, false, "c-three")},
			{Rule: names[3], Finding: claimAt(t, domain.LayerTCP, "a different claim at the same layer",
				"and a different detail", "what would settle it",
				domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceMedium,
				false, "c-four")},
		}
	}

	naming := [][]RuleID{
		{"a/one", "b/two", "c/three", "d/four"},
		{"d/one", "c/two", "b/three", "a/four"},
		{"z/last", "y/next", "x/then", "w/first"},
		{"same/name", "same/name", "same/name", "same/name"},
		{"aaaaa/aaaaa", "aaaaa/aaaab", "aaaaa/aaaac", "aaaaa/aaaad"},
	}

	var want string
	for i, names := range naming {
		merged, err := Converge(build(names))
		if err != nil {
			t.Fatalf("Converge with %v: %v", names, err)
		}
		got := encodeFindings(t, merged)
		if i == 0 {
			want = got
			// Non-vacuity: the input really does merge and really does keep the
			// incompatible members apart.
			if len(merged) != 3 {
				t.Fatalf("the fixture produced %d findings, want 3 — one merged pair "+
					"and two that must stay apart", len(merged))
			}
			continue
		}
		if got != want {
			t.Fatalf("renaming the rules to %v changed the canonical output.\n"+
				"want %s\n got %s\n\nA rule identity is svcdoctor's private name for a "+
				"piece of code. A claim that moves when it is renamed is a claim about "+
				"the source tree (ADR 0081 section 2.6a).", names, want, got)
		}
	}
}

// TestC06TheRenamePropertyHoldsForRecommendationOrderToo isolates the one place
// a rule identity could still have leaked after the prose preconditions landed.
//
// The recommendation union is the only merged field whose *order* is visible,
// and it used to be "the winner's first, then the rest by RuleID". Two rules
// whose advice differs would therefore have produced a different array order
// under a rename.
func TestC06TheRenamePropertyHoldsForRecommendationOrderToo(t *testing.T) {
	const (
		summary = "one claim, two pieces of advice"
		detail  = "one detail"
	)
	build := func(first, second RuleID) []domain.Recommendation {
		merged, err := Converge([]AttributedFinding{
			{Rule: first, Finding: withAdvice(t,
				simpleClaim(t, summary, detail, "c-one"), "look at the first thing")},
			{Rule: second, Finding: withAdvice(t,
				simpleClaim(t, summary, detail, "c-two"), "look at the second thing")},
		})
		if err != nil {
			t.Fatalf("Converge: %v", err)
		}
		if len(merged) != 1 {
			t.Fatalf("got %d findings, want 1", len(merged))
		}
		return merged[0].Recommendations()
	}

	forward := build("a/one", "z/two")
	reversed := build("z/one", "a/two")
	if len(forward) != 2 {
		t.Fatalf("the union has %d actions, want 2", len(forward))
	}
	for i := range forward {
		if forward[i].Action() != reversed[i].Action() {
			t.Fatalf("renaming the rules reordered the advice:\n%v\n%v",
				actionsOf(forward), actionsOf(reversed))
		}
	}
}

// --- C08, C09, C10: what must not have changed -------------------------------

// TestC08TheProductionConvergenceStillMerges pins the one shape that really
// converges in production, at this layer.
//
// Kafka reaches `KAFKA_AUTH_MECHANISM_NOT_OFFERED` about one endpoint from the
// SASL handshake step and the SASL authenticate step, with byte-identical
// summary, detail and recommendation. That is a genuine two-routes-one-claim
// case and the closure must not have broken it; the service-level assertion is
// in internal/diagnosis/kafka.
func TestC08TheProductionConvergenceStillMerges(t *testing.T) {
	const (
		summary = "The Kafka endpoint did not offer the SASL mechanism this run asked for"
		detail  = "The endpoint answered the handshake and reported that the named " +
			"mechanism is not one it offers."
		advice = "Check the mechanisms the listener serving this address and port enables"
	)

	merged, err := Converge([]AttributedFinding{
		{Rule: "kafka/protocol", Finding: withAdvice(t,
			claimAt(t, domain.LayerAuth, summary, detail, "", domain.FindingKindConfirmed,
				domain.SeverityError, domain.ConfidenceHigh, false, "c-handshake"), advice)},
		{Rule: "kafka/protocol", Finding: withAdvice(t,
			claimAt(t, domain.LayerAuth, summary, detail, "", domain.FindingKindConfirmed,
				domain.SeverityError, domain.ConfidenceHigh, false, "c-authenticate"), advice)},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1; two routes writing one sentence are one claim",
			len(merged))
	}
	if want := []domain.EvidenceID{"c-authenticate", "c-handshake"}; !slices.Equal(
		merged[0].EvidenceRefs(), want) {
		t.Errorf("EvidenceRefs = %v, want the union %v", merged[0].EvidenceRefs(), want)
	}
	if len(merged[0].Recommendations()) != 1 {
		t.Errorf("the identical advice was not deduplicated: %v",
			actionsOf(merged[0].Recommendations()))
	}
}

// TestC09TheEvidenceUnionIsDeterministicAndComplete.
//
// Merging exists to make a claim rest on every route that reached it. Losing a
// reference would make the merged finding weaker than either input, and an
// order-dependent union would make the report depend on how the engine happened
// to visit the rules.
func TestC09TheEvidenceUnionIsDeterministicAndComplete(t *testing.T) {
	const (
		summary = "one claim, reached many ways"
		detail  = "one detail"
	)

	var in []AttributedFinding
	want := []domain.EvidenceID{}
	for i := 0; i < 8; i++ {
		ref := domain.EvidenceID("c-route-" + strconv.Itoa(i))
		want = append(want, ref)
		in = append(in, AttributedFinding{
			Rule:    RuleID("r/rule-" + strconv.Itoa(i)),
			Finding: simpleClaim(t, summary, detail, ref),
		})
	}
	slices.Sort(want)

	for _, order := range [][]int{
		{0, 1, 2, 3, 4, 5, 6, 7}, {7, 6, 5, 4, 3, 2, 1, 0}, {3, 0, 7, 1, 5, 2, 6, 4},
	} {
		shuffled := make([]AttributedFinding, 0, len(in))
		for _, i := range order {
			shuffled = append(shuffled, in[i])
		}
		merged, err := Converge(shuffled)
		if err != nil {
			t.Fatalf("Converge: %v", err)
		}
		if len(merged) != 1 {
			t.Fatalf("order %v produced %d findings, want 1", order, len(merged))
		}
		if !slices.Equal(merged[0].EvidenceRefs(), want) {
			t.Errorf("order %v produced %v, want %v", order, merged[0].EvidenceRefs(), want)
		}
	}
}

// TestC10ConfidenceReconciliationIsUnchanged.
//
// The closure changed which findings merge. It changed nothing about how the
// ones that do merge reconcile their reconciled fields, and this says so for the
// field most easily broken: confidence is the maximum, never a count.
func TestC10ConfidenceReconciliationIsUnchanged(t *testing.T) {
	const (
		summary = "one claim, reached many ways"
		detail  = "one detail"
	)

	var in []AttributedFinding
	for i := 0; i < 6; i++ {
		in = append(in, AttributedFinding{
			Rule: RuleID("r/rule-" + strconv.Itoa(i)),
			Finding: claimAt(t, domain.LayerTCP, summary, detail, "",
				domain.FindingKindHypothesis, domain.SeverityWarn, domain.ConfidenceMedium,
				false, domain.EvidenceID("c-route-"+strconv.Itoa(i))),
		})
		merged, err := Converge(in)
		if err != nil {
			t.Fatalf("Converge: %v", err)
		}
		if len(merged) != 1 {
			t.Fatalf("%d routes produced %d findings, want 1", len(in), len(merged))
		}
		if got := merged[0].Confidence(); got != domain.ConfidenceMedium {
			t.Fatalf("%d MEDIUM routes produced %s; convergence is MEDIUM and does not "+
				"accumulate", len(in), got)
		}
		if got := merged[0].Severity(); got != domain.SeverityWarn {
			t.Fatalf("%d WARN routes produced %s", len(in), got)
		}
		if got := merged[0].Kind(); got != domain.FindingKindHypothesis {
			t.Fatalf("%d hypotheses produced %s", len(in), got)
		}
	}
}

// --- helpers ------------------------------------------------------------------

// withAdvice returns f with one recommendation attached.
func withAdvice(t *testing.T, f domain.Finding, action string) domain.Finding {
	t.Helper()

	rec, err := domain.NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	out, err := domain.NewFinding(domain.FindingInput{
		Code: f.Code(), Kind: f.Kind(), Severity: f.Severity(), Confidence: f.Confidence(),
		Layer: f.Layer(), Subject: f.Subject(), Summary: f.Summary(), Detail: f.Detail(),
		Discriminator: f.Discriminator(), EvidenceRefs: f.EvidenceRefs(),
		VantageDependent: f.VantageDependent(),
		Recommendations:  []domain.Recommendation{rec},
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return out
}

func actionsOf(in []domain.Recommendation) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, r.Action())
	}
	return out
}

func encodeFindings(t *testing.T, in []domain.Finding) string {
	t.Helper()

	out, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return string(out)
}
