package kubernetes_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// TestEachDeniedReadIsNamedByItsBoundedOperation.
//
// # The operation is the only thing that distinguishes two F2 findings
//
// They share a code, a subject, a layer, a severity and a confidence, so if the
// operation did not reach the prose the report would carry two byte-identical
// sentences — and convergence, whose Detail precondition keeps them apart, would
// merge them into one claim covering two refusals it could not name.
//
// The value comes from a closed svcdoctor-owned map. There is no HTTP method, no
// path and no URL anywhere in it: one would put the API server's identity into
// canonical data and would make prose depend on a string the client library
// composed.
func TestEachDeniedReadIsNamedByItsBoundedOperation(t *testing.T) {
	cases := map[domain.Step]string{
		servicekubernetes.StepService:             "SERVICE_GET",
		servicekubernetes.StepPodSet:              "POD_LIST",
		servicekubernetes.StepEndpointPublication: "ENDPOINTSLICE_LIST",
	}

	for step, operation := range cases {
		spec := healthy()
		switch step {
		case servicekubernetes.StepService:
			spec.service = denied(servicekubernetes.StepService)
			spec.podSet = skipped(servicekubernetes.StepPodSet,
				domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
			spec.publication = skipped(servicekubernetes.StepEndpointPublication,
				domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
		case servicekubernetes.StepPodSet:
			spec.podSet = denied(servicekubernetes.StepPodSet)
		case servicekubernetes.StepEndpointPublication:
			spec.publication = denied(servicekubernetes.StepEndpointPublication)
		}

		finding := single(t, findingsWithCode(spec.evaluate(t), f2))
		if !strings.Contains(finding.Summary(), operation) {
			t.Errorf("the %s refusal's summary does not name %s: %s",
				step, operation, finding.Summary())
		}
		if !strings.Contains(finding.Detail(), operation) {
			t.Errorf("the %s refusal's detail does not name %s", step, operation)
		}
		for _, other := range cases {
			if other == operation {
				continue
			}
			if strings.Contains(finding.Summary()+finding.Detail(), other) {
				t.Errorf("the %s refusal names %s, which is a different read",
					step, other)
			}
		}
	}
}

// TestTwoDeniedReadsProduceTwoDistinguishableFindings.
//
// ADR 0094 section 10.9 shape B: two denied operations are **two findings**,
// because the Detail differs and ADR 0081 section 2.2b makes Detail a merge
// precondition. That is the correct outcome and not a defect — two reads were
// refused and two things are being said — and it is only true if the two really
// do differ, which is what this asserts.
func TestTwoDeniedReadsProduceTwoDistinguishableFindings(t *testing.T) {
	spec := healthy()
	spec.podSet = denied(servicekubernetes.StepPodSet)
	spec.publication = denied(servicekubernetes.StepEndpointPublication)

	findings := findingsWithCode(spec.evaluate(t), f2)
	if len(findings) != 2 {
		t.Fatalf("%d findings, want 2", len(findings))
	}
	first, second := findings[0], findings[1]

	// Same identity, so they are convergence candidates.
	if first.Code() != second.Code() || first.Subject().Ref() != second.Subject().Ref() {
		t.Fatal("the two refusals do not share a semantic identity; the merge " +
			"precondition this test is about would never be consulted")
	}
	if first.Layer() != second.Layer() {
		t.Fatal("the two refusals differ by layer; they would stay apart for a reason " +
			"other than the one ADR 0094 section 10.9 shape B names")
	}

	// And a Detail that differs, which is what keeps them apart.
	if first.Detail() == second.Detail() {
		t.Error("the two refusals carry byte-identical details, so convergence would " +
			"merge them into one claim that names one read while citing two")
	}
	if first.Summary() == second.Summary() {
		t.Error("the two refusals carry byte-identical summaries; a reader would see " +
			"the same sentence twice with no way to tell which read each is about")
	}
	if first.EvidenceRefs()[0] == second.EvidenceRefs()[0] {
		t.Error("the two refusals cite the same node")
	}
}

// TestTheTwoPublicationDetailVariantsAreExactAndExclusive.
//
// ADR 0094 section 2.7 froze **two** Detail variants from a closed two-value
// map, and section 10.9 shape C records that they *cannot co-occur*: one Service
// has one publication node and one slice count, so the two are mutually
// exclusive by construction and there is no convergence hazard.
//
// The all-terminating sentence is appended to the second variant alone, which
// makes it a conditional clause of that variant rather than a third one: it is
// the sentence that stops "no ready endpoint" being read as "no traffic".
func TestTheTwoPublicationDetailVariantsAreExactAndExclusive(t *testing.T) {
	noSlice := healthy()
	noSlice.publication = publicationNode(publicationCounts{})
	variantA := single(t, findingsWithCode(noSlice.evaluate(t), f4)).Detail()

	noneReady := healthy()
	noneReady.publication = publicationNode(
		publicationCounts{slices: 2, endpoints: 5, ready: 0})
	variantB := single(t, findingsWithCode(noneReady.evaluate(t), f4)).Detail()

	if variantA == variantB {
		t.Fatal("the two variants are byte-identical; a reader cannot tell 'nothing was " +
			"published' from 'something was published and none of it is ready'")
	}
	if !strings.Contains(
		variantA, "No EndpointSlice associated with this Service was published",
	) {
		t.Errorf("variant A does not state that nothing was published:\n%s", variantA)
	}
	if !strings.Contains(variantB, "no endpoint among them reports itself ready") {
		t.Errorf("variant B does not state that nothing is ready:\n%s", variantB)
	}
	// Variant A must not describe endpoints, because there were no slices to
	// hold any.
	if strings.Contains(variantA, "among them") {
		t.Errorf("variant A describes endpoints in slices that do not exist:\n%s", variantA)
	}

	const terminatingNote = "Every endpoint in that set reports itself terminating"

	allTerminating := healthy()
	allTerminating.publication = publicationNode(
		publicationCounts{slices: 1, endpoints: 3, ready: 0, terminating: 3})
	withNote := single(t, findingsWithCode(allTerminating.evaluate(t), f4)).Detail()
	if !strings.Contains(withNote, terminatingNote) {
		t.Errorf("an all-terminating set does not say so, and silence there would let "+
			"'no ready endpoint' be read as 'no traffic':\n%s", withNote)
	}
	if !strings.HasPrefix(withNote, variantB) {
		t.Error("the all-terminating note is not an addition to variant B; it is a " +
			"conditional clause of that variant rather than a third one")
	}

	// The note is withheld everywhere it is not exactly true.
	for name, counts := range map[string]publicationCounts{
		"some terminating": {slices: 1, endpoints: 3, ready: 0, terminating: 1},
		"none terminating": {slices: 1, endpoints: 3, ready: 0, terminating: 0},
		"more terminating than endpoints, which no adapter path produces": {
			slices: 1, endpoints: 2, ready: 0, terminating: 5},
	} {
		spec := healthy()
		spec.publication = publicationNode(counts)
		detail := single(t, findingsWithCode(spec.evaluate(t), f4)).Detail()
		if strings.Contains(detail, terminatingNote) {
			t.Errorf("%s: the all-terminating note was appended to a set that is not "+
				"all terminating", name)
		}
	}

	// And it is never appended to variant A, where there is no endpoint set to
	// be terminating.
	emptySliceTerminating := healthy()
	emptySliceTerminating.publication = publicationNode(
		publicationCounts{slices: 0, endpoints: 0, terminating: 0})
	if strings.Contains(
		single(t, findingsWithCode(emptySliceTerminating.evaluate(t), f4)).Detail(),
		terminatingNote,
	) {
		t.Error("variant A carries the all-terminating note")
	}
}

// TestTheRulesAreDeterministicUnderEvidencePermutation.
//
// A rule's output must not depend on the order nodes were added to the graph.
// The graph's own ordering is canonical, so this is a property the rules get for
// free — which is exactly why it is worth pinning: a rule that started walking
// insertion order would lose it silently, and the symptom would be a report that
// differs between two runs of the same measurement.
//
// It permutes the insertion of all five nodes and requires byte-identical
// findings, prose included.
func TestTheRulesAreDeterministicUnderEvidencePermutation(t *testing.T) {
	permutations := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{1, 4, 0, 3, 2},
		{3, 2, 4, 0, 1},
	}

	checked := 0
	for name, spec := range everyScenario() {
		// The scenarios that omit a node have a different arity; their shapes
		// are covered by the matrix.
		omits := false
		for _, n := range spec.nodes() {
			if n.omit {
				omits = true
			}
		}
		if omits {
			continue
		}

		var want string
		for i, order := range permutations {
			got := renderFindings(evaluateGraph(t, spec.build(t, order)))
			if i == 0 {
				want = got
				continue
			}
			if got != want {
				t.Errorf("%s: insertion order %v produced\n%s\nwant\n%s",
					name, order, got, want)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no scenario was permuted; this guard would pass vacuously")
	}
}

// TestRepeatedEvaluationIsByteIdentical.
//
// The rules read maps — the attribute table on each node — so a value that
// escaped through map iteration would show up as a result that differs between
// two evaluations of one frozen graph. Running each scenario several times is
// the cheapest way to see it.
func TestRepeatedEvaluationIsByteIdentical(t *testing.T) {
	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)
		want := renderFindings(evaluateGraph(t, graph))
		for i := 0; i < 8; i++ {
			if got := renderFindings(evaluateGraph(t, graph)); got != want {
				t.Fatalf("%s: evaluation %d differs\n%s\nwant\n%s", name, i, got, want)
			}
		}
	}
}

// renderFindings serializes everything a finding carries that a consumer sees.
func renderFindings(findings []domain.Finding) string {
	var b strings.Builder
	for _, finding := range findings {
		b.WriteString(string(finding.Code()))
		b.WriteString("|")
		b.WriteString(finding.Kind().String())
		b.WriteString("|")
		b.WriteString(finding.Severity().String())
		b.WriteString("|")
		b.WriteString(finding.Confidence().String())
		b.WriteString("|")
		b.WriteString(finding.Layer().String())
		b.WriteString("|")
		b.WriteString(finding.Subject().Ref())
		b.WriteString("|")
		b.WriteString(finding.Summary())
		b.WriteString("|")
		b.WriteString(finding.Detail())
		b.WriteString("|")
		for _, ref := range finding.EvidenceRefs() {
			b.WriteString(string(ref))
			b.WriteString(",")
		}
		b.WriteString("|")
		for _, recommendation := range finding.Recommendations() {
			b.WriteString(recommendation.Action())
			b.WriteString("~")
			b.WriteString(recommendation.Rationale())
			b.WriteString("~")
			b.WriteString(recommendation.Safety().String())
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	return b.String()
}
