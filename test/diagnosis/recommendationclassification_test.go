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

// deferredActions are the nine Phase 13.1C owns, by their action text.
//
// Named by action rather than by finding code, because that is the granularity of
// what remains: three of the nine share a finding code with a recommendation this
// phase classified, so a code-level list would exempt too much.
var deferredActions = map[string]string{
	"Establish verified TLS to this endpoint, or review the trust context this run used, " +
		"then re-run": "REC-012",
	"Check whether the advertised hostname resolves from this vantage point, and what the " +
		"broker publishes in advertised.listeners": "REC-021",
	"Establish a verified TLS channel to this endpoint before presenting a credential, or " +
		"re-run with the transport policy this run is meant to use": "REC-031",
	"Diagnose this endpoint with a client that performs the authentication method it " +
		"demands, or configure a mechanism svcdoctor performs for the role this run used": "REC-034",
	"Re-run against a role whose password is printable ASCII, or diagnose this endpoint " +
		"with a client that implements the full mechanism": "REC-036",
	"Enable TLS for this endpoint and supply the trust material that verifies it, then run " +
		"again": "REC-052",
	"Grant the diagnostic identity permission to run PING, or diagnose with an identity " +
		"that already has it": "REC-055",
	"Enable SASL PLAIN on this endpoint, or diagnose it with a client that implements the " +
		"mechanisms it offers": "REC-064",
	"Grant this user permissions on the virtual host, for example with rabbitmqctl " +
		"set_permissions": "REC-067",
}

// TestEveryProducedRecommendationIsClassifiedExceptTheNine drives the production
// rule sets over the production corpora and inspects what they attached.
//
// This is the guard that would catch a migration that edited a table and forgot
// the call site: the metadata has to arrive on a recommendation a rule really
// built, from a graph a fixture really produced.
func TestEveryProducedRecommendationIsClassifiedExceptTheNine(t *testing.T) {
	var produced, classified, exempt int
	seenExempt := map[string]bool{}

	check := func(t *testing.T, findings []domain.Finding) {
		t.Helper()
		for _, f := range findings {
			for _, r := range f.Recommendations() {
				produced++
				if rec, deferred := deferredActions[r.Action()]; deferred {
					exempt++
					seenExempt[rec] = true
					if r.Classified() {
						t.Errorf("%s carries %s, which Phase 13.1A reserved for 13.1C, "+
							"and it is classified %s/%s.\n\n"+
							"Phase 13.1B is metadata-only for the 55 it migrated and "+
							"read-only for these nine; classifying one here settles a "+
							"sentence whose meaning 13.1C reviews.",
							f.Code(), rec, r.Kind(), r.Safety())
					}
					continue
				}
				if !r.Classified() {
					t.Errorf("%s produced the unclassified recommendation %q.\n\n"+
						"ADR 0097 section 2.1: a production rule may not decline to "+
						"classify its own advice, and this action is not one of the nine "+
						"Phase 13.1C owns. Route it through the package's advise helper.",
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
	if classified == 0 {
		t.Fatal("the corpora produced no classified recommendation; the migration is invisible here")
	}
	t.Logf("%d recommendations produced: %d classified, %d exempt (%d distinct of the nine)",
		produced, classified, exempt, len(seenExempt))
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
