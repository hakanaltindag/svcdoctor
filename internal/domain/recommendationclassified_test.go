package domain

import (
	"encoding/json"
	"errors"
	"testing"
)

// Phase 10.4B: the four classification fields on domain.Recommendation.

// TestRecommendationVocabulariesAreComplete is the name-table walk that used to
// live in internal/diagnosis, moved down with the types it covers.
func TestRecommendationVocabulariesAreComplete(t *testing.T) {
	for k := RecommendationKind(0); int(k) < len(recommendationKindNames); k++ {
		if recommendationKindNames[k] == "" {
			t.Errorf("RecommendationKind(%d) has no name", k)
		}
	}
	if len(recommendationKindNames) != 3 {
		t.Errorf("%d kinds, want 2 plus the zero value", len(recommendationKindNames)-1)
	}
	for c := SafetyClass(0); int(c) < len(safetyClassNames); c++ {
		if safetyClassNames[c] == "" {
			t.Errorf("SafetyClass(%d) has no name", c)
		}
	}
	// Seven classes, frozen by ADR 0082 section 2.2, plus the zero value.
	if len(safetyClassNames) != 8 {
		t.Errorf("%d safety classes, want 7 plus the zero value", len(safetyClassNames)-1)
	}
	if got := SafetyClass(99).String(); got != "SafetyClass(99)" {
		t.Errorf("out-of-range String() = %q", got)
	}
	if got := RecommendationKind(99).String(); got != "RecommendationKind(99)" {
		t.Errorf("out-of-range String() = %q", got)
	}
}

// TestTheThreeUnreachableClassesAreUnreachableAtTheReportBoundary is the
// strengthening Phase 10.4B bought by moving Producible down.
//
// Before the move, RESTART was refused only by diagnosis.NewAdvice, so it bound
// the one path that went through it. It is now refused where a value would enter
// a report, which is every path.
func TestTheThreeUnreachableClassesAreUnreachableAtTheReportBoundary(t *testing.T) {
	for _, class := range []SafetyClass{
		SafetyRestart, SafetyDisruptive, SafetySecurityWeakening,
	} {
		_, err := NewClassifiedRecommendation(RecommendationInput{
			Action: "Do the thing", Kind: RecommendationKindRemediation,
			Safety: class, Rationale: "Because.",
		})
		if !errors.Is(err, ErrInvalidValue) {
			t.Errorf("%s was accepted at the report boundary: %v", class, err)
		}
	}
}

// TestClassificationIsAllOrNothing is the "valid but semantically false" gate.
//
// A half-classified recommendation is the shape the constructor exists to
// refuse: a rationale or a safety class with no kind claims a review that never
// happened.
func TestClassificationIsAllOrNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   RecommendationInput
	}{
		{"no kind", RecommendationInput{
			Action: "Look", Safety: SafetyObserve, Rationale: "Because."}},
		{"no safety", RecommendationInput{
			Action: "Look", Kind: RecommendationKindNextEvidence, Rationale: "Because."}},
		{"no rationale", RecommendationInput{
			Action: "Look", Kind: RecommendationKindNextEvidence, Safety: SafetyObserve}},
		{"no action", RecommendationInput{
			Kind: RecommendationKindNextEvidence, Safety: SafetyObserve, Rationale: "Because."}},
		{"next evidence that changes the target", RecommendationInput{
			Action: "Look", Kind: RecommendationKindNextEvidence,
			Safety: SafetyConfigChange, Rationale: "Because."}},
		{"a self-collectable remediation", RecommendationInput{
			Action: "Change it", Kind: RecommendationKindRemediation,
			Safety: SafetyConfigChange, Rationale: "Because.", SelfCollectable: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewClassifiedRecommendation(tc.in); err == nil {
				t.Error("accepted a half-classified or contradictory recommendation")
			}
		})
	}
}

// TestAnUnclassifiedRecommendationEncodesExactlyAsBefore is the additive-at-v1
// property, stated in bytes.
func TestAnUnclassifiedRecommendationEncodesExactlyAsBefore(t *testing.T) {
	r, err := NewRecommendation("Review this endpoint's log")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	if r.Classified() {
		t.Error("an action-only recommendation reports itself classified")
	}
	got, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	const want = `{"action":"Review this endpoint's log"}`
	if string(got) != want {
		t.Errorf("unclassified encoding moved.\n got: %s\nwant: %s", got, want)
	}
}

// TestAClassifiedRecommendationEncodesEveryField pins the new shape, including
// the one field whose false is meaningful.
func TestAClassifiedRecommendationEncodesEveryField(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   RecommendationInput
		want string
	}{
		{
			name: "next evidence svcdoctor cannot take",
			in: RecommendationInput{
				Action: "Compare usage with the configured limits",
				Kind:   RecommendationKindNextEvidence, Safety: SafetyCompare,
				Rationale: "It separates the explanations.", SelfCollectable: false,
			},
			want: `{"action":"Compare usage with the configured limits",` +
				`"kind":"NEXT_EVIDENCE","safety":"COMPARE",` +
				`"rationale":"It separates the explanations.","selfCollectable":false}`,
		},
		{
			name: "next evidence a different run could take",
			in: RecommendationInput{
				Action: "Re-run with a larger execution budget",
				Kind:   RecommendationKindNextEvidence, Safety: SafetyObserve,
				Rationale: "The paths were never attempted.", SelfCollectable: true,
			},
			want: `{"action":"Re-run with a larger execution budget",` +
				`"kind":"NEXT_EVIDENCE","safety":"OBSERVE",` +
				`"rationale":"The paths were never attempted.","selfCollectable":true}`,
		},
		{
			// selfCollectable is omitted, because the constructor already
			// refuses a self-collectable remediation and a constant false
			// would be noise.
			name: "a remediation",
			in: RecommendationInput{
				Action: "Correct the advertised listener",
				Kind:   RecommendationKindRemediation, Safety: SafetyConfigChange,
				Rationale: "The evidence proves the address is wrong.",
			},
			want: `{"action":"Correct the advertised listener",` +
				`"kind":"REMEDIATION","safety":"CONFIG_CHANGE",` +
				`"rationale":"The evidence proves the address is wrong."}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewClassifiedRecommendation(tc.in)
			if err != nil {
				t.Fatalf("NewClassifiedRecommendation: %v", err)
			}
			got, err := json.Marshal(r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("encoding mismatch.\n got: %s\nwant: %s", got, tc.want)
			}
			// Every accessor returns what was supplied.
			if r.Action() != tc.in.Action || r.Kind() != tc.in.Kind ||
				r.Safety() != tc.in.Safety || r.Rationale() != tc.in.Rationale ||
				r.SelfCollectable() != tc.in.SelfCollectable {
				t.Error("an accessor does not return what the constructor was given")
			}
			if !r.Classified() {
				t.Error("a classified recommendation reports itself unclassified")
			}
		})
	}
}

// TestTheZeroRecommendationStaysInvalid guards the accessor that changed.
//
// IsZero used to be a struct comparison. A classified recommendation has four
// more fields, and an *unclassified* one has three of them at their zero value —
// so a struct comparison would still work, but it would break the moment a
// non-comparable field is added. Testing the action alone states the intent.
func TestTheZeroRecommendationStaysInvalid(t *testing.T) {
	var zero Recommendation
	if !zero.IsZero() {
		t.Error("the zero Recommendation reports valid")
	}
	if _, err := json.Marshal(zero); err == nil {
		t.Error("the zero Recommendation marshalled")
	}
	unclassified, err := NewRecommendation("Look at the log")
	if err != nil {
		t.Fatalf("NewRecommendation: %v", err)
	}
	if unclassified.IsZero() {
		t.Error("an unclassified recommendation reports itself the zero value")
	}
}

// TestRationaleObeysTheEstablishedProseContract holds the new prose field to
// exactly the contract every other prose field already has.
//
// `validateIdentifier` is the repository's one text gate — non-empty, valid
// UTF-8, no surrounding whitespace, no control characters — and `rationale` goes
// through it for the same reason `action`, `summary` and `detail` do. Anything a
// consumer must not receive in one of those must not arrive in this one either.
//
// **Length is deliberately not asserted, because nothing in the model bounds
// it.** No prose field in `internal/domain` has a length limit; adding one to
// this field alone would be a new, inconsistent contract, and bounding all of
// them is the open cross-service question `docs/BACKLOG.md` already tracks as
// "sanitising renderer observation values". Out of scope here, and recorded
// rather than silently half-fixed.
func TestRationaleObeysTheEstablishedProseContract(t *testing.T) {
	classified := func(rationale string) error {
		_, err := NewClassifiedRecommendation(RecommendationInput{
			Action: "Look", Kind: RecommendationKindNextEvidence,
			Safety: SafetyObserve, Rationale: rationale,
		})
		return err
	}
	for _, tc := range []struct{ name, value string }{
		{"empty", ""},
		{"a NUL", "line one\x00line two"},
		{"a newline", "line one\nline two"},
		{"leading whitespace", "  padded"},
		{"trailing whitespace", "padded  "},
		{"invalid UTF-8", "bad\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := classified(tc.value); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("a rationale with %s was accepted: %v", tc.name, err)
			}
			// The same value in the action, so the two prose fields cannot
			// drift apart in strictness.
			if _, err := NewRecommendation(tc.value); !errors.Is(err, ErrInvalidValue) {
				t.Errorf("an action with %s was accepted: %v", tc.name, err)
			}
		})
	}
	if err := classified("A perfectly ordinary sentence."); err != nil {
		t.Errorf("a valid rationale was refused: %v", err)
	}
}
