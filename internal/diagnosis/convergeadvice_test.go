package diagnosis

import (
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.4B: recommendation convergence after the four fields arrived.
//
// This is the phase's critical regression surface, and it is critical for a
// specific measured reason. Until 10.4B a recommendation *was* its action, so
// deduplicating the union on `Action()` deduplicated the value. It is now five
// fields, two of which — kind and safety — are the difference between "look at
// this" and "change this". Keying on the action alone would have kept whichever
// copy arrived first and dropped a differently classified one, publishing a
// classification no rule attached to that sentence. That is Phase 10.2A's defect
// in a new field: a merged value nobody stated.

// withRecommendations returns f carrying exactly the given advice.
func withRecommendations(
	t *testing.T, f domain.Finding, recs ...domain.Recommendation,
) domain.Finding {
	t.Helper()
	out, err := domain.NewFinding(domain.FindingInput{
		Code: f.Code(), Kind: f.Kind(), Severity: f.Severity(), Confidence: f.Confidence(),
		Layer: f.Layer(), Subject: f.Subject(), Summary: f.Summary(), Detail: f.Detail(),
		Discriminator: f.Discriminator(), EvidenceRefs: f.EvidenceRefs(),
		VantageDependent: f.VantageDependent(), Recommendations: recs,
	})
	if err != nil {
		t.Fatalf("NewFinding: %v", err)
	}
	return out
}

func classifiedRec(
	t *testing.T, action string, kind domain.RecommendationKind,
	safety domain.SafetyClass, rationale string, self bool,
) domain.Recommendation {
	t.Helper()
	r, err := domain.NewClassifiedRecommendation(domain.RecommendationInput{
		Action: action, Kind: kind, Safety: safety, Rationale: rationale,
		SelfCollectable: self,
	})
	if err != nil {
		t.Fatalf("NewClassifiedRecommendation: %v", err)
	}
	return r
}

// mergedAdvice converges two findings that share an identity and returns the
// merged recommendation list.
func mergedAdvice(t *testing.T, a, b domain.Recommendation) []domain.Recommendation {
	t.Helper()
	const (
		summary = "nothing accepted a connection on that port from this vantage point"
		detail  = "the same detail, written once and shared by both routes"
	)
	merged, err := Converge([]AttributedFinding{
		{Rule: "z/second", Finding: withRecommendations(
			t, simpleClaim(t, summary, detail, "c-two"), b)},
		{Rule: "a/first", Finding: withRecommendations(
			t, simpleClaim(t, summary, detail, "c-one"), a)},
	})
	if err != nil {
		t.Fatalf("Converge: %v", err)
	}
	if len(merged) != 1 {
		t.Fatalf("got %d findings, want 1 merged", len(merged))
	}
	return merged[0].Recommendations()
}

// TestRecommendationsCollapseOnlyOnFullSemanticEquality is cases 1 to 6.
func TestRecommendationsCollapseOnlyOnFullSemanticEquality(t *testing.T) {
	const (
		action    = "Compare the connections in use with the configured limits"
		other     = "Review this endpoint's log"
		rationale = "It is the observation that separates the explanations."
	)
	base := func() domain.Recommendation {
		return classifiedRec(t, action, domain.RecommendationKindNextEvidence,
			domain.SafetyCompare, rationale, false)
	}

	for _, tc := range []struct {
		name string
		a, b domain.Recommendation
		want int
		why  string
	}{
		{
			name: "1 every field equal",
			a:    base(), b: base(), want: 1,
			why: "one recommendation stated twice is one recommendation",
		},
		{
			name: "2 same action, different kind",
			a:    base(),
			b: classifiedRec(t, action, domain.RecommendationKindRemediation,
				domain.SafetyConfigChange, rationale, false),
			want: 2,
			why:  "an observation and a change are not one suggestion",
		},
		{
			name: "3 same action, different safety",
			a:    base(),
			b: classifiedRec(t, action, domain.RecommendationKindNextEvidence,
				domain.SafetyObserve, rationale, false),
			want: 2,
			why:  "the blast radius is what a reader consults before acting",
		},
		{
			name: "4 same action, different rationale",
			a:    base(),
			b: classifiedRec(t, action, domain.RecommendationKindNextEvidence,
				domain.SafetyCompare, "A different reason entirely.", false),
			want: 2,
			why:  "two reasons are two claims about why the observation helps",
		},
		{
			name: "5 same action, different selfCollectable",
			a:    base(),
			b: classifiedRec(t, action, domain.RecommendationKindNextEvidence,
				domain.SafetyCompare, rationale, true),
			want: 2,
			why:  "'a different run could take this' and 'you must' are opposite answers",
		},
		{
			name: "6 different action",
			a:    base(),
			b: classifiedRec(t, other, domain.RecommendationKindNextEvidence,
				domain.SafetyObserve, rationale, false),
			want: 2,
			why:  "deterministic coexistence",
		},
		{
			name: "a classified and an unclassified copy of one sentence",
			a:    base(),
			b: func() domain.Recommendation {
				r, err := domain.NewRecommendation(action)
				if err != nil {
					t.Fatalf("NewRecommendation: %v", err)
				}
				return r
			}(),
			want: 2,
			why:  "silence about a classification is not the classification",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := mergedAdvice(t, tc.a, tc.b)
			if len(got) != tc.want {
				t.Errorf("%d recommendations after merge, want %d — %s\ngot: %+v",
					len(got), tc.want, tc.why, got)
			}
			// Whatever survived must be a value one of the inputs actually
			// carried. A merged recommendation assembled from parts of two is
			// the failure mode this whole test exists for.
			for _, r := range got {
				if r != tc.a && r != tc.b {
					t.Errorf("a recommendation appeared that no input stated: %+v", r)
				}
			}
		})
	}
}

// TestTheRecommendationUnionIsOrderInvariant is case 7, driven one field at a
// time.
//
// The union is the one merged field that can see the order its members were
// visited in, so it is the one that could leak a rule's registration order into
// user-visible output. ADR 0081 section 2.6a forbids that, and Phase 10.4B had
// to extend compareByContent to the four new fields to keep it true: two
// findings differing only in a recommendation's kind used to compare equal, and
// an equal comparison leaves the order to the sort and therefore to input order.
//
// **Each case differs in exactly one field**, deliberately. A fixture that
// differed in two would still pass with one of them dropped from the
// comparison, which is precisely how the first version of this test let a
// mutation through: it varied kind *and* rationale, so ignoring kind changed
// nothing.
func TestTheRecommendationUnionIsOrderInvariant(t *testing.T) {
	const (
		summary   = "nothing accepted a connection on that port from this vantage point"
		detail    = "the same detail, written once and shared by both routes"
		action    = "Compare the connections in use with the configured limits"
		rationale = "It is the observation that separates the explanations."
	)
	base := classifiedRec(t, action, domain.RecommendationKindNextEvidence,
		domain.SafetyCompare, rationale, false)

	for _, tc := range []struct {
		field string
		other domain.Recommendation
	}{
		{"action", classifiedRec(t, "A different observation entirely",
			domain.RecommendationKindNextEvidence, domain.SafetyCompare, rationale, false)},
		{"kind", classifiedRec(t, action, domain.RecommendationKindRemediation,
			domain.SafetyCompare, rationale, false)},
		{"safety", classifiedRec(t, action, domain.RecommendationKindNextEvidence,
			domain.SafetyObserve, rationale, false)},
		{"rationale", classifiedRec(t, action, domain.RecommendationKindNextEvidence,
			domain.SafetyCompare, "A different reason entirely.", false)},
		{"selfCollectable", classifiedRec(t, action, domain.RecommendationKindNextEvidence,
			domain.SafetyCompare, rationale, true)},
	} {
		t.Run("differing in "+tc.field, func(t *testing.T) {
			// **The same evidence reference on both**, which is what makes
			// this test reach the code it is about. joinAdvice is the *last*
			// tie-break in compareByContent; differing refs decide the order
			// before it is ever consulted, so a fixture with distinct refs
			// passes no matter what joinAdvice ignores. That is exactly how the
			// first version of this test let NBE-M11 through.
			in := []AttributedFinding{
				{Rule: "a/first", Finding: withRecommendations(
					t, simpleClaim(t, summary, detail, "c-one"), base)},
				{Rule: "z/second", Finding: withRecommendations(
					t, simpleClaim(t, summary, detail, "c-one"), tc.other)},
			}
			forward := mustConverge(t, in)
			reversed := mustConverge(t, []AttributedFinding{in[1], in[0]})

			got := forward[0].Recommendations()
			if len(got) != 2 {
				t.Fatalf("%d recommendations, want 2 coexisting; a difference in %s "+
					"collapsed", len(got), tc.field)
			}
			if !slices.Equal(actionsOf(got), actionsOf(reversed[0].Recommendations())) ||
				got[0] != reversed[0].Recommendations()[0] {
				t.Errorf("the recommendation order depends on input order when only %s "+
					"differs; compareByContent does not distinguish that field",
					tc.field)
			}

			// And renaming the rules changes nothing, the property in its
			// strongest form.
			renamed := mustConverge(t, []AttributedFinding{
				{Rule: "zzz/last", Finding: in[0].Finding},
				{Rule: "aaa/first", Finding: in[1].Finding},
			})
			if renamed[0].Recommendations()[0] != got[0] {
				t.Errorf("renaming a rule changed the recommendation order when only "+
					"%s differs", tc.field)
			}
		})
	}
}
