package domain

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzClassifiedRecommendation drives the constructor and the encoder over
// arbitrary input, on the modified surface Phase 10.4B introduced.
//
// Two properties, and neither depends on the input being sensible:
//
//   - **a constructed value round-trips its own accessors.** Anything the
//     constructor accepts must come back out unchanged, because the whole phase
//     is about not losing fields.
//   - **an accepted value always marshals.** A value the model admits but the
//     encoder rejects would be a report that cannot be written, discovered at
//     the worst moment.
//
// It also pins that the encoder never emits a raw control character, which is
// the property the prose gate exists for.
func FuzzClassifiedRecommendation(f *testing.F) {
	f.Add("Look at the log", "Because it separates them.", uint8(1), uint8(1), true)
	f.Add("", "", uint8(0), uint8(0), false)
	f.Add("Compare\x00two", "why", uint8(2), uint8(4), false)
	f.Add(strings.Repeat("a", 300), "why", uint8(1), uint8(3), true)
	f.Add("  padded  ", "why", uint8(1), uint8(2), false)

	f.Fuzz(func(t *testing.T, action, rationale string, kind, safety uint8, self bool) {
		in := RecommendationInput{
			Action:          action,
			Kind:            RecommendationKind(kind),
			Safety:          SafetyClass(safety),
			Rationale:       rationale,
			SelfCollectable: self,
		}
		r, err := NewClassifiedRecommendation(in)
		if err != nil {
			// A refusal is a fine outcome; it must simply not have produced a
			// usable value on the way.
			if !r.IsZero() {
				t.Fatalf("a refused input produced a non-zero recommendation: %+v", r)
			}
			return
		}

		if r.Action() != in.Action || r.Rationale() != in.Rationale ||
			r.Kind() != in.Kind || r.Safety() != in.Safety ||
			r.SelfCollectable() != in.SelfCollectable {
			t.Fatalf("a field changed through the constructor: in=%+v out=%+v", in, r)
		}
		if !r.Classified() {
			t.Fatal("an accepted classified recommendation reports itself unclassified")
		}

		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("an accepted recommendation does not marshal: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("the encoding is not valid JSON: %v", err)
		}
		if decoded["action"] != in.Action {
			t.Fatalf("the encoded action differs: %v != %q", decoded["action"], in.Action)
		}
		// selfCollectable is emitted only for next evidence, where its false is
		// meaningful. Everywhere else its absence is the point.
		_, present := decoded["selfCollectable"]
		if present != (in.Kind == RecommendationKindNextEvidence) {
			t.Fatalf("selfCollectable present=%v for kind %s", present, in.Kind)
		}
	})
}

// FuzzUnclassifiedRecommendationEncoding pins that the old shape is still the
// old shape for every input the old constructor accepts.
func FuzzUnclassifiedRecommendationEncoding(f *testing.F) {
	f.Add("Review the log")
	f.Add("")
	f.Add("a\x00b")

	f.Fuzz(func(t *testing.T, action string) {
		r, err := NewRecommendation(action)
		if err != nil {
			return
		}
		if r.Classified() {
			t.Fatal("an action-only recommendation reports itself classified")
		}
		encoded, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("an accepted recommendation does not marshal: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("the encoding is not valid JSON: %v", err)
		}
		if len(decoded) != 1 {
			t.Fatalf("an unclassified recommendation encoded %d members, want 1: %s",
				len(decoded), encoded)
		}
	})
}
