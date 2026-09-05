package terminal

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// Phase 10.4B: the terminal shows a recommendation's classification.
//
// The renderer decides nothing here. Everything it prints comes from a closed
// enumeration the domain defines or from a boolean, and an unclassified
// recommendation is printed exactly as it was before this phase — because there
// is nothing to say about it, and inventing a classification would be diagnosis.

var updateNextEvidence = flag.Bool(
	"update-next-evidence", false, "rewrite the Phase 10.4B golden files")

func classified(
	t *testing.T, action string, kind domain.RecommendationKind,
	safety domain.SafetyClass, rationale string, selfCollectable bool,
) domain.Recommendation {
	t.Helper()
	r, err := domain.NewClassifiedRecommendation(domain.RecommendationInput{
		Action: action, Kind: kind, Safety: safety,
		Rationale: rationale, SelfCollectable: selfCollectable,
	})
	if err != nil {
		t.Fatalf("NewClassifiedRecommendation: %v", err)
	}
	return r
}

func unclassified(t *testing.T, action string) domain.Recommendation {
	t.Helper()
	r, err := domain.NewRecommendation(action)
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	return r
}

func findingWithAdvice(t *testing.T, recs ...domain.Recommendation) domain.Finding {
	t.Helper()
	subj, err := domain.NewEndpointSubject("10.0.0.10:5432")
	if err != nil {
		t.Fatalf("NewSubject: %v", err)
	}
	f, err := domain.NewFinding(domain.FindingInput{
		Code:         "POSTGRES_CONNECTION_LIMIT_REACHED",
		Kind:         domain.FindingKindConfirmed,
		Severity:     domain.SeverityError,
		Confidence:   domain.ConfidenceHigh,
		Layer:        domain.LayerAuth,
		Subject:      subj,
		Summary:      "A one-line summary",
		Detail:       "A detail line.",
		EvidenceRefs: []domain.EvidenceID{"tcp"},

		Recommendations: recs,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return f
}

// TestGoldenNextEvidenceRendering is the byte-for-byte record of the one output
// change this phase makes.
//
// Three recommendations on one finding, chosen to cover every branch of
// adviceTag in a single fixture: a next-evidence observation svcdoctor could
// take, one it could not, and an unclassified string that must render exactly as
// it did before Phase 10.4B.
func TestGoldenNextEvidenceRendering(t *testing.T) {
	b := healthyGraph(t)
	f := findingWithAdvice(t,
		classified(t, "Compare the addresses this network routes with the advertised ones",
			domain.RecommendationKindNextEvidence, domain.SafetyCompare,
			"The advertised address and the routable set are the two halves of the question.",
			false),
		classified(t, "Re-run with a larger execution budget",
			domain.RecommendationKindNextEvidence, domain.SafetyObserve,
			"The unmeasured paths were never attempted, so their outcome is unknown.",
			true),
		unclassified(t, "Review this endpoint's log for the session it refused"),
	)
	text := rendered(t, render.Input{Report: b.report(f)})

	path := filepath.Join("testdata", "next-evidence-classified.txt")
	if *updateNextEvidence {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed testdata path.
	if err != nil {
		t.Fatalf("reading %s: %v (run with -update-next-evidence)", path, err)
	}
	if text != string(want) {
		t.Errorf("%s does not match.\n--- want ---\n%s\n--- got ---\n%s", path, want, text)
	}
}

// TestTheRendererShowsClassificationWithoutDeciding pins the properties the
// golden cannot state, because a golden proves what the bytes are and not why.
func TestTheRendererShowsClassificationWithoutDeciding(t *testing.T) {
	b := healthyGraph(t)

	// An unclassified recommendation gets no tag and no rationale line. A
	// renderer that guessed NEXT_EVIDENCE for an unreviewed string would be
	// diagnosing.
	plain := rendered(t, render.Input{
		Report: b.report(findingWithAdvice(t, unclassified(t, "Review the endpoint log"))),
	})
	if strings.Contains(plain, "NEXT_EVIDENCE") || strings.Contains(plain, "[") {
		t.Errorf("an unclassified recommendation acquired a classification:\n%s", plain)
	}

	// A next-evidence recommendation svcdoctor cannot take is **shown**, not
	// hidden. Suppressing it would leave an operator believing svcdoctor had
	// nothing to suggest, which is the opposite of the point (ADR 0086 §2.4).
	cannot := rendered(t, render.Input{
		Report: b.report(findingWithAdvice(t, classified(t,
			"Read pg_stat_activity and compare it with the configured limits",
			domain.RecommendationKindNextEvidence, domain.SafetyObserve,
			"It is the observation that separates the explanations.", false))),
	})
	for _, want := range []string{
		"Read pg_stat_activity", "NEXT_EVIDENCE", "OBSERVE", "you must collect",
	} {
		if !strings.Contains(cannot, want) {
			t.Errorf("the rendering omits %q:\n%s", want, cannot)
		}
	}

	// And the two self-collectability answers are distinguishable, because a
	// reader has to be able to tell "a different run could" from "you must".
	can := rendered(t, render.Input{
		Report: b.report(findingWithAdvice(t, classified(t,
			"Re-run with a larger execution budget",
			domain.RecommendationKindNextEvidence, domain.SafetyObserve,
			"The unmeasured paths were never attempted.", true))),
	})
	if !strings.Contains(can, "svcdoctor can collect") {
		t.Errorf("a self-collectable observation is not marked as one:\n%s", can)
	}
	if strings.Contains(can, "you must collect") {
		t.Errorf("a self-collectable observation is marked as operator-only:\n%s", can)
	}
}

// TestTheRendererDoesNotReorderRecommendations is the ordering half.
//
// The rule wrote them in an order; the renderer prints that order. Sorting by
// safety class, by self-collectability or by anything else would be the renderer
// asserting a priority no rule stated.
func TestTheRendererDoesNotReorderRecommendations(t *testing.T) {
	b := healthyGraph(t)
	first := classified(t, "ZZZ last alphabetically, first in the rule",
		domain.RecommendationKindNextEvidence, domain.SafetyCompare, "Because.", false)
	second := classified(t, "AAA first alphabetically, second in the rule",
		domain.RecommendationKindNextEvidence, domain.SafetyObserve, "Because.", true)

	text := rendered(t, render.Input{Report: b.report(findingWithAdvice(t, first, second))})
	if strings.Index(text, "ZZZ last") > strings.Index(text, "AAA first") {
		t.Errorf("the renderer reordered the recommendations:\n%s", text)
	}
}
