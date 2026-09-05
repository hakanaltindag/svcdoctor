package diagnosis

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.4B: Advice -> domain.Recommendation, and nothing lost on the way.

// TestAdviceProjectionPreservesEveryField is the phase's central property,
// driven over every value each field can take rather than over a sample.
//
// The defect it exists to prevent is the one Phase 10.4A measured: a projection
// that carries the action and silently drops the other four. A field added to
// Advice without a line here will fail the arity check below.
func TestAdviceProjectionPreservesEveryField(t *testing.T) {
	// Every producible (kind, safety) pair, plus both self-collectability
	// answers where the kind admits them. Exhaustive rather than sampled: the
	// vocabularies are small and a missed pair is exactly how a mapping rots.
	var cases []AdviceInput
	for _, safety := range []SafetyClass{SafetyObserve, SafetyVerify, SafetyCompare} {
		for _, self := range []bool{false, true} {
			cases = append(cases, AdviceInput{
				Kind: AdviceKindNextEvidence, Safety: safety,
				Action:          "Observe the thing with " + safety.String(),
				Rationale:       "Because " + safety.String() + " separates them.",
				SelfCollectable: self,
			})
		}
	}
	for _, safety := range []SafetyClass{
		SafetyObserve, SafetyVerify, SafetyCompare, SafetyConfigChange,
	} {
		cases = append(cases, AdviceInput{
			Kind: AdviceKindRemediation, Safety: safety,
			Action:    "Change the thing with " + safety.String(),
			Rationale: "Because the evidence proves it.",
		})
	}

	for _, in := range cases {
		advice, err := NewAdvice(in)
		if err != nil {
			t.Fatalf("NewAdvice(%+v): %v", in, err)
		}
		got, err := advice.Recommendation()
		if err != nil {
			t.Fatalf("Recommendation(%+v): %v", in, err)
		}
		if got.Action() != in.Action {
			t.Errorf("action lost: %q != %q", got.Action(), in.Action)
		}
		if got.Kind() != in.Kind {
			t.Errorf("kind lost: %s != %s", got.Kind(), in.Kind)
		}
		if got.Safety() != in.Safety {
			t.Errorf("safety lost: %s != %s", got.Safety(), in.Safety)
		}
		if got.Rationale() != in.Rationale {
			t.Errorf("rationale lost: %q != %q", got.Rationale(), in.Rationale)
		}
		if got.SelfCollectable() != in.SelfCollectable {
			t.Errorf("selfCollectable lost: %v != %v",
				got.SelfCollectable(), in.SelfCollectable)
		}
		if !got.Classified() {
			t.Error("a projected advice is not classified")
		}
	}
}

// TestTheProjectionIsTotalOverTheProducibleVocabulary states the arity property
// the loop above relies on.
//
// Advice has five fields and domain.Recommendation has five. If either grows,
// this fails and a contributor has to decide whether the new field belongs in
// the report — which is the decision Phases 10.1b through 10.3 each deferred by
// accident.
func TestTheProjectionIsTotalOverTheProducibleVocabulary(t *testing.T) {
	const wantFields = 5
	if got := adviceFieldCount(); got != wantFields {
		t.Errorf("Advice has %d fields, want %d; if a field was added, decide whether "+
			"it reaches the report and extend Advice.Recommendation", got, wantFields)
	}
	if got := recommendationFieldCount(); got != wantFields {
		t.Errorf("domain.Recommendation has %d fields, want %d", got, wantFields)
	}

	// Every producible safety class projects; the three unreachable ones cannot
	// even be constructed.
	for c := SafetyClass(0); c <= SafetySecurityWeakening; c++ {
		_, err := NewAdvice(AdviceInput{
			Kind: AdviceKindRemediation, Safety: c,
			Action: "Do it", Rationale: "Because.",
		})
		if c.Producible() != (err == nil) {
			t.Errorf("%s: Producible()=%v but NewAdvice err=%v", c, c.Producible(), err)
		}
	}
}

// TestTheZeroAdviceProjectsNothing keeps an invalid value from becoming a
// report field.
func TestTheZeroAdviceProjectsNothing(t *testing.T) {
	var zero Advice
	if _, err := zero.Recommendation(); err == nil {
		t.Error("the zero Advice projected into a recommendation")
	}
}

// TestRecommendRefusesRatherThanDowngrading is the guardrail-deleting-itself
// case, at the one call every rule now uses.
//
// A refused suggestion yields no recommendation. Emitting an unclassified string
// because the classified one was rejected would keep the advice and lose the
// refusal, which is worse than saying nothing.
func TestRecommendRefusesRatherThanDowngrading(t *testing.T) {
	remediation := AdviceInput{
		Kind: AdviceKindRemediation, Safety: SafetyConfigChange,
		Action: "Correct the advertised listener", Rationale: "The evidence proves it.",
	}
	// Below CONFIRMED/HIGH the confidence gate refuses it outright.
	for _, tc := range []struct {
		kind       domain.FindingKind
		confidence domain.Confidence
	}{
		{domain.FindingKindHypothesis, domain.ConfidenceHigh},
		{domain.FindingKindConfirmed, domain.ConfidenceMedium},
		{domain.FindingKindConfirmed, domain.ConfidenceLow},
	} {
		if got := Recommend(remediation, tc.kind, tc.confidence); got != nil {
			t.Errorf("%s/%s produced %d recommendation(s) for a refused remediation",
				tc.kind, tc.confidence, len(got))
		}
	}
	got := Recommend(remediation, domain.FindingKindConfirmed, domain.ConfidenceHigh)
	if len(got) != 1 || !got[0].Classified() {
		t.Fatalf("a CONFIRMED/HIGH remediation was not produced: %+v", got)
	}

	// An unsafe class never reaches a report through this path either.
	if got := Recommend(AdviceInput{
		Kind: AdviceKindRemediation, Safety: SafetyRestart,
		Action: "Restart the broker", Rationale: "Because.",
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh); got != nil {
		t.Error("a RESTART recommendation reached a report")
	}
}
