package redaction

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.4B: the four new recommendation fields under redaction.
//
// A new prose field added while the redactor keeps rebuilding the old shape is
// the classic redaction hole, and this file exists because the redactor really
// did rebuild the old shape: it called NewRecommendation(action), which would
// have dropped kind, safety and self-collectability from every shareable report
// and — far worse — carried the rationale through untransformed had it survived
// at all.
//
// The fixture in redact_test.go now carries one classified and one unclassified
// recommendation, with canaries in both prose fields of the classified one, so
// every assertion in that file covers both shapes too.

// TestTheRationaleIsRedactedLikeEveryOtherProseField is the hostile case.
//
// It checks the **serialized** shareable report as well as the object, because a
// field redacted in the model and re-emitted from somewhere else is still a
// leak, and serialization is what actually leaves the process.
func TestTheRationaleIsRedactedLikeEveryOtherProseField(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	var withRationale int
	for _, f := range shareable.Findings() {
		for _, r := range f.Recommendations() {
			for _, canary := range allCanaries {
				if strings.Contains(r.Action(), canary) {
					t.Errorf("recommendation action leaked %q: %q", canary, r.Action())
				}
				if strings.Contains(r.Rationale(), canary) {
					t.Errorf("recommendation rationale leaked %q: %q", canary, r.Rationale())
				}
			}
			if r.Rationale() != "" {
				withRationale++
			}
		}
	}
	if withRationale == 0 {
		t.Fatal("no rationale survived redaction; the assertions above proved nothing")
	}

	encoded, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, canary := range allCanaries {
		if strings.Contains(string(encoded), canary) {
			t.Errorf("the serialized shareable report leaked %q", canary)
		}
	}
}

// TestRedactionPreservesTheClassification is the other half, and it is the one
// the pre-10.4B redactor would have failed.
//
// Kind, safety and self-collectability are a closed enumeration, a closed
// enumeration and a boolean. None can carry an identity, so none is transformed
// — and none may be dropped either, because a shareable report that cannot say
// "this is an observation, not a change" is less useful than a local one for no
// security gain at all.
func TestRedactionPreservesTheClassification(t *testing.T) {
	local := localReport(t)
	shareable := mustRedact(t, local)

	type shape struct {
		classified      bool
		kind            domain.RecommendationKind
		safety          domain.SafetyClass
		selfCollectable bool
	}
	shapesOf := func(r domain.Report) []shape {
		var out []shape
		for _, f := range r.Findings() {
			for _, rec := range f.Recommendations() {
				out = append(out, shape{
					rec.Classified(), rec.Kind(), rec.Safety(), rec.SelfCollectable(),
				})
			}
		}
		return out
	}

	before, after := shapesOf(local), shapesOf(shareable)
	if len(before) == 0 {
		t.Fatal("the fixture carries no recommendation")
	}
	if len(before) != len(after) {
		t.Fatalf("redaction changed the recommendation count: %d -> %d",
			len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("recommendation %d changed classification under redaction: %+v -> %+v",
				i, before[i], after[i])
		}
	}

	// And at least one of them really was classified, so the comparison is not
	// vacuously true over two unclassified values.
	var anyClassified bool
	for _, s := range after {
		if s.classified {
			anyClassified = true
		}
	}
	if !anyClassified {
		t.Fatal("no classified recommendation survived; the comparison proved nothing")
	}
}

// TestRedactionNeverInventsAClassification keeps the two shapes apart.
//
// If the redactor rebuilt every recommendation through the classified
// constructor it would have to invent a kind, and an invented kind is a claim
// about advice nobody reviewed. The fixture's second recommendation is
// unclassified precisely so this can be asserted.
func TestRedactionNeverInventsAClassification(t *testing.T) {
	shareable := mustRedact(t, localReport(t))

	var unclassified int
	for _, f := range shareable.Findings() {
		for _, r := range f.Recommendations() {
			if !r.Classified() {
				unclassified++
				if r.Rationale() != "" || r.Safety() != domain.SafetyUnspecified {
					t.Errorf("an unclassified recommendation acquired fields: %+v", r)
				}
			}
		}
	}
	if unclassified == 0 {
		t.Fatal("redaction classified every recommendation; it must classify none")
	}
}
