package redis

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 13.1B: the classification the production rules actually attach.
//
// test/security/recommendationclassification_test.go proves the frozen corpus is
// complete and that every row survives construction; that is a statement about a
// table. This is the statement about the wiring, and the Phase 13.1B mutation
// suite is why it exists: eight mutations of a call site survived a table-only
// guard set, because a table cannot notice that a rule stopped passing it.
//
// The expectation is keyed on the action text, which is the only identity a
// recommendation has (ADR 0097 section 2.3 refuses adding another), and every
// action here is a package constant this file names rather than a literal.

// redisClassification is the frozen per-action expectation. Every action the
// package produces is here; Phase 13.1C left no exemption.
var redisClassification = map[string]classificationExpectation{
	recommendProtocolNotEstablished:     {diagnosis.SafetyObserve, false},
	recommendCredentialNotConfigured:    {diagnosis.SafetyObserve, false},
	recommendCredentialsRejected:        {diagnosis.SafetyVerify, false},
	recommendAuthenticationNotCompleted: {diagnosis.SafetyObserve, false},
	recommendEndpointNotServing:         {diagnosis.SafetyObserve, false},
	recommendPingNotCompleted:           {diagnosis.SafetyObserve, false},
	recommendSentinel:                   {diagnosis.SafetyObserve, false},
	// Phase 13.1C.
	recommendCredentialWithheld:  {diagnosis.SafetyObserve, false},
	recommendCommandNotPermitted: {diagnosis.SafetyVerify, false},
}

func TestEveryProducedRecommendationCarriesItsFrozenClassification(t *testing.T) {
	assertFrozenClassification(t, everyFindingShapeFindings(t),
		redisClassification, nil)
}

// everyFindingShapeFindings flattens the producer matrix this package already
// enumerates.
func everyFindingShapeFindings(t *testing.T) []domain.Finding {
	t.Helper()
	var out []domain.Finding
	for _, shape := range everyFindingShape(t) {
		out = append(out, shape.findings...)
	}
	return out
}

// classificationExpectation is what one action must carry.
//
// The maps above use unkeyed literals — `{safety, selfCollectable}` — because a
// keyed one triples the width of a fifty-row table and the two fields are never
// ambiguous about which is which.
type classificationExpectation struct {
	safety          diagnosis.SafetyClass
	selfCollectable bool
}

// assertFrozenClassification is the shared body. It lives in each rule package
// rather than in one place because a rule package may not import another's
// constants, and a generic helper elsewhere would need the whole expectation
// passed in anyway.
//
// `mayCarryNone` names the codes for which an empty recommendation list is the
// designed answer. Everything else with none is the silent-drop shape:
// diagnosis.Recommend returns nil on any error, so a misclassification deletes a
// recommendation rather than failing a build.
func assertFrozenClassification(
	t *testing.T,
	findings []domain.Finding,
	want map[string]classificationExpectation,
	mayCarryNone map[domain.FindingCode]string,
) {
	t.Helper()
	if len(findings) == 0 {
		t.Fatal("the producer matrix yielded no finding; this guard would pass vacuously")
	}

	seen := map[string]bool{}
	for _, f := range findings {
		if len(f.Recommendations()) == 0 {
			if _, allowed := mayCarryNone[f.Code()]; !allowed {
				t.Errorf("%s carries no recommendation at all, and it is not one of the "+
					"codes for which that is the designed answer; diagnosis.Recommend "+
					"drops an invalid classification silently, so an absent "+
					"recommendation is the shape this guard exists to catch", f.Code())
			}
			continue
		}
		for _, r := range f.Recommendations() {
			action := r.Action()
			seen[action] = true

			expect, known := want[action]
			if !known {
				t.Errorf("%s produced the action %q, which is not in the frozen "+
					"classification.\n\n"+
					"ADR 0097 section 2.1: a production rule may not decline to classify "+
					"its own advice, and Phase 13.1C left no exemption list to add it "+
					"to. Classify it, deliberately.", f.Code(), action)
				continue
			}
			if !r.Classified() {
				t.Errorf("%s produced %q unclassified; every production "+
					"recommendation is classified since Phase 13.1C, so a call site "+
					"stopped passing the classification", f.Code(), action)
				continue
			}
			if r.Kind() != domain.RecommendationKindNextEvidence {
				t.Errorf("%s produced %q as %s, want NEXT_EVIDENCE", f.Code(), action, r.Kind())
			}
			if r.Safety() != expect.safety {
				t.Errorf("%s produced %q classified %s, want %s",
					f.Code(), action, r.Safety(), expect.safety)
			}
			if !r.Safety().ChangesNothing() {
				t.Errorf("%s produced %q classified %s, which changes the target",
					f.Code(), action, r.Safety())
			}
			if r.SelfCollectable() != expect.selfCollectable {
				t.Errorf("%s produced %q with selfCollectable=%v, want %v; "+
					"true means svcdoctor can take the observation under its current "+
					"authority, never that it could be programmed to",
					f.Code(), action, r.SelfCollectable(), expect.selfCollectable)
			}
			if r.Rationale() == "" {
				t.Errorf("%s produced %q with no rationale", f.Code(), action)
			}
		}
	}

	for action := range want {
		if !seen[action] {
			t.Errorf("the producer matrix never produced %q, so its row asserts nothing; "+
				"either the matrix lost a shape or the constant is unreachable", action)
		}
	}
}
