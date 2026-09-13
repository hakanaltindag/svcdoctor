package diagnosis_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The execution half of the Phase 13.1B guard set.
//
// test/security/recommendationclassification_test.go proves the corpus is
// complete and that every classified row survives construction. That is a
// statement about the table and the model. These two are statements about what
// the **production rules actually attach**, driven over the same corpora
// TestNBE021EveryHypothesisDiscriminatorHasStructuredNextEvidence uses.
//
// The pair is deliberate. A table alone could be right about what the
// classification should be and wrong about whether production applies it; an
// execution test alone sees only what the corpora reach. Neither is sufficient and
// the record says so rather than implying the coverage is total.

// TestEveryProducedRecommendationIsClassified drives the production rule sets
// over the production corpora and inspects what they attached.
//
// This is the guard that would catch a migration that edited a table and forgot
// the call site: the metadata has to arrive on a recommendation a rule really
// built, from a graph a fixture really produced.
//
// **It carries no exemption since Phase 13.1C.** It used to hold a nine-entry
// table keyed by action text — named by action rather than by finding code,
// because three of the nine shared a code with a recommendation Phase 13.1B had
// already classified, so a code-level list would have exempted too much. All nine
// sentences were reviewed, rewritten and classified, so the table is deleted
// rather than emptied and the assertion below is unconditional.
func TestEveryProducedRecommendationIsClassified(t *testing.T) {
	var produced, classified int

	check := func(t *testing.T, findings []domain.Finding) {
		t.Helper()
		for _, f := range findings {
			for _, r := range f.Recommendations() {
				produced++
				if !r.Classified() {
					t.Errorf("%s produced the unclassified recommendation %q.\n\n"+
						"ADR 0097 section 2.1: a production rule may not decline to "+
						"classify its own advice, and Phase 13.1C left no exemption "+
						"list. Route it through the package's advise helper.",
						f.Code(), r.Action())
					continue
				}
				classified++
				if r.Kind() != domain.RecommendationKindNextEvidence {
					t.Errorf("%s produced a %s recommendation; every production "+
						"recommendation is NEXT_EVIDENCE (ADR 0097 section 2.2)",
						f.Code(), r.Kind())
				}
				if !r.Safety().ChangesNothing() {
					t.Errorf("%s produced advice classified %s, which changes the target",
						f.Code(), r.Safety())
				}
				if strings.TrimSpace(r.Rationale()) == "" {
					t.Errorf("%s produced classified advice with no rationale", f.Code())
				}
			}
		}
	}

	for _, fixture := range kafkaCorpus() {
		t.Run("kafka/"+fixture.id, func(t *testing.T) {
			r := diagnoseKafka(t, fixture.build(t), fixture.incomplete)
			check(t, r.report.Findings())
		})
	}
	for _, fixture := range pgCorpus() {
		t.Run("postgres/"+fixture.id, func(t *testing.T) {
			r := diagnosePostgres(t, fixture.build(t), fixture.incomplete)
			check(t, r.report.Findings())
		})
	}
	// The generic corpus needs its rule set named, because `diagnose` takes one;
	// transportAndBoundary() is the production set TestTheGoldenIncidentCorpus
	// drives, so this sees exactly the transport recommendations that corpus
	// reaches.
	for _, fixture := range corpus() {
		t.Run("generic/"+fixture.name, func(t *testing.T) {
			r := diagnose(t, fixture.build(t), fixture.incomplete, transportAndBoundary()...)
			check(t, r.report.Findings())
		})
	}

	if produced == 0 {
		t.Fatal("the corpora produced no recommendation at all; this guard would pass vacuously")
	}
	if classified != produced {
		t.Fatalf("the corpora produced %d recommendations and only %d are classified; "+
			"every production recommendation is classified since Phase 13.1C",
			produced, classified)
	}
	t.Logf("%d recommendations produced, %d classified, 0 exempt", produced, classified)
}

// TestClassifyingOneConstantOnceKeepsConvergenceNeutral is the ADR 0097 section
// 2.3 property, stated as the three cases convergence can see.
//
// The recommendation union deduplicates on the **whole five-field value**, which
// is what makes a classification change either invisible or visible as two
// findings rather than as one with a value nobody stated. Under "one constant, one
// classification" only the first case is reachable in production.
func TestClassifyingOneConstantOnceKeepsConvergenceNeutral(t *testing.T) {
	const action = "Check the thing the finding names"

	build := func(t *testing.T, safety diagnosis.SafetyClass, rationale string) domain.Recommendation {
		t.Helper()
		got := diagnosis.Recommend(diagnosis.AdviceInput{
			Kind:      diagnosis.AdviceKindNextEvidence,
			Safety:    safety,
			Action:    action,
			Rationale: rationale,
		}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
		if len(got) != 1 {
			t.Fatalf("construction produced %d recommendations, want 1", len(got))
		}
		return got[0]
	}

	t.Run("same action same metadata is one value", func(t *testing.T) {
		a := build(t, diagnosis.SafetyObserve, "Because it discriminates.")
		b := build(t, diagnosis.SafetyObserve, "Because it discriminates.")
		if a != b {
			t.Error("two identically classified recommendations are not equal, so dedup " +
				"would keep both and a merged finding would list the same advice twice")
		}
		if len(map[domain.Recommendation]struct{}{a: {}, b: {}}) != 1 {
			t.Error("the two do not collapse in a set keyed on the value")
		}
	})

	t.Run("same action different safety stays distinguishable", func(t *testing.T) {
		a := build(t, diagnosis.SafetyObserve, "Because it discriminates.")
		b := build(t, diagnosis.SafetyVerify, "Because it discriminates.")
		if a == b {
			t.Error("two differently classified recommendations are equal, so dedup would " +
				"keep whichever arrived first and publish a safety class the other rule " +
				"never attached — the Phase 10.2A defect (ADR 0081 section 2.2b)")
		}
	})

	t.Run("same action different rationale stays distinguishable", func(t *testing.T) {
		a := build(t, diagnosis.SafetyObserve, "Because it discriminates.")
		b := build(t, diagnosis.SafetyObserve, "Because of something else.")
		if a == b {
			t.Error("the rationale is not part of the value, so dedup could drop one of " +
				"two differently reasoned recommendations")
		}
	})

	t.Run("classified and unclassified stay distinguishable", func(t *testing.T) {
		classified := build(t, diagnosis.SafetyObserve, "Because it discriminates.")
		legacy, err := domain.NewRecommendation(action)
		if err != nil {
			t.Fatalf("NewRecommendation: %v", err)
		}
		if classified == legacy {
			t.Error("a classified and an unclassified recommendation with the same action " +
				"are equal; the mixed list Kafka produces while REC-021 is deferred " +
				"would then collapse to one")
		}
	})
}
