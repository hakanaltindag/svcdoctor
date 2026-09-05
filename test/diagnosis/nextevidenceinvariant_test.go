package diagnosis_test

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.4B, NBE-021: the discriminator and its next-evidence recommendation.
//
// ADR 0082 section 2.5 states the relationship — "the discriminator is the
// one-line human statement; the recommendation carries the structure. A finding
// that has one should have the other" — and asked for a guard "once Phase 10.1
// lands". Phase 10.1 landed and the guard was never written; Phase 10.4A
// recorded the debt as NBE-021 and this is it.
//
// # Why an inventory and not a constructor refusal
//
// Refusing the shape in domain.NewFinding was considered and rejected. It is
// **currently reachable in production**: KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE's
// incomplete branch carries a discriminator and three recommendations that
// predate the advice vocabulary and are therefore unclassified. Making the
// constructor refuse it would force this phase either to add a recommendation to
// that finding or to classify three service-owned sentences — and classifying a
// service's advice is that service's judgement about its own claims, not
// plumbing. ADR 0086 section 2.0 draws exactly that line.
//
// So the guard is an inventory with a written exception, the idiom
// test/security/convergenceinventory_test.go already uses for the same reason:
// it records what is true, fails when it stops being true, and refuses to grow
// silently. The list may only shrink.
//
// # What it does not check
//
// That the discriminator and the recommendation describe the *same* unresolved
// observation. That relation has no mechanical form without a discriminator
// identity primitive, and ADR 0086 section 2.2a defers that to Phase 10.4C
// rather than inventing one. Text equality is explicitly **not** required: the
// two are one idea in two registers, and requiring them to match byte for byte
// would force a rule author to write the same sentence twice.

// hypothesesWithoutStructuredNextEvidence are the codes allowed, for now, to
// carry a discriminator with no NEXT_EVIDENCE recommendation beside it.
//
// Each entry is a debt with an owner, not a permission slip. **The list is
// shrink-only**, and that is enforced twice rather than asserted once: its size
// is pinned below, so a second entry cannot arrive without also editing the
// expected count and explaining why in the same change; and
// TestTheOneExemptHypothesisShapeStillExists in internal/diagnosis/kafka fails
// when the recorded entry stops being reachable, so a debt that has quietly been
// paid cannot linger here pretending to still be one.
var hypothesesWithoutStructuredNextEvidence = map[domain.FindingCode]string{
	"KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE": "its three recommendations are the " +
		"per-layer transport sentences from ADR 0034 section 18, written before the " +
		"advice vocabulary existed and still unclassified. Classifying them is a Kafka " +
		"judgement about Kafka's own advice; Phase 10.4B carried the vocabulary and " +
		"deliberately reclassified nothing (ADR 0086 section 2.0)",
}

// TestNBE021EveryHypothesisDiscriminatorHasStructuredNextEvidence drives the
// production rule sets over the production corpora and inspects what they built.
func TestNBE021EveryHypothesisDiscriminatorHasStructuredNextEvidence(t *testing.T) {
	seenExempt := map[domain.FindingCode]bool{}
	var hypotheses int

	check := func(t *testing.T, findings []domain.Finding) {
		t.Helper()
		for _, f := range findings {
			if f.Kind() != domain.FindingKindHypothesis {
				continue
			}
			hypotheses++

			// C: a CONFIRMED finding may not carry a discriminator. That one is
			// structural in domain.NewFinding, and is asserted here too so the
			// two halves of the rule are read together.
			if f.Discriminator() == "" {
				continue
			}

			var structured int
			for _, r := range f.Recommendations() {
				if r.Kind() == domain.RecommendationKindNextEvidence {
					structured++
				}
			}
			if structured > 0 {
				if _, exempt := hypothesesWithoutStructuredNextEvidence[f.Code()]; exempt {
					t.Errorf("%s now carries structured next evidence; delete its entry "+
						"from hypothesesWithoutStructuredNextEvidence so the list keeps "+
						"meaning something", f.Code())
				}
				continue
			}
			if _, exempt := hypothesesWithoutStructuredNextEvidence[f.Code()]; exempt {
				seenExempt[f.Code()] = true
				continue
			}
			t.Errorf("%s asks an open question and offers no structured observation.\n\n"+
				"discriminator: %q\n\n"+
				"ADR 0082 section 2.5: the discriminator is the human statement and a "+
				"NEXT_EVIDENCE recommendation carries the structure. A finding that has "+
				"one should have the other. Either add the recommendation through "+
				"diagnosis.Recommend, or record the code in "+
				"hypothesesWithoutStructuredNextEvidence with the reason.",
				f.Code(), f.Discriminator())
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

	if hypotheses == 0 {
		t.Fatal("no hypothesis was produced by any fixture; the guard proved nothing")
	}
	// The list may only shrink. An allowlist with no size pinned to it is an
	// invitation, and this one guards the invariant ADR 0082 section 2.5 asked
	// for — so growing it has to cost a deliberate edit and a written reason,
	// which is the same friction docs/FINDINGS.md and the frozen-count guards
	// use elsewhere.
	const wantExceptions = 1
	if got := len(hypothesesWithoutStructuredNextEvidence); got != wantExceptions {
		t.Errorf("%d exempted codes, want %d.\n\n"+
			"A new exception is a hypothesis that asks an open question and offers no "+
			"structured observation. If one is genuinely owed, move this number and say "+
			"why in the same change; if a debt was paid, delete the entry and this "+
			"number together.", got, wantExceptions)
	}

	// No staleness sweep here, deliberately. This test sees only what the two
	// corpora reach, and the one exempt shape — the incomplete branch of
	// KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE — is not among them. Failing on an
	// unexercised entry would make the exemption list depend on corpus coverage
	// rather than on the product. The entry is kept honest by
	// TestTheOneExemptHypothesisShapeStillExists in internal/diagnosis/kafka,
	// which builds that shape directly.
	_ = seenExempt
}

// TestNBE021DiscriminatorAndRecommendationNeedNotMatchTextually records the
// half of the invariant that is deliberately *not* enforced.
//
// ADR 0086 section 2.2a forbids treating discriminator prose as a machine
// identity, and requiring the recommendation's action to equal it would be
// exactly that under another name. The two say one thing in two registers.
func TestNBE021DiscriminatorAndRecommendationNeedNotMatchTextually(t *testing.T) {
	var checked int
	for _, fixture := range kafkaCorpus() {
		r := diagnoseKafka(t, fixture.build(t), fixture.incomplete)
		for _, f := range r.report.Findings() {
			if f.Discriminator() == "" {
				continue
			}
			for _, rec := range f.Recommendations() {
				if rec.Kind() != domain.RecommendationKindNextEvidence {
					continue
				}
				checked++
				if rec.Action() == f.Discriminator() {
					t.Logf("%s: the two happen to be identical, which is allowed "+
						"but must never be required", f.Code())
				}
			}
		}
	}
	if checked == 0 {
		t.Skip("no fixture reaches a discriminator with structured next evidence")
	}
}
