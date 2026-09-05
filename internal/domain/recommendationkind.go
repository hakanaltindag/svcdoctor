package domain

import (
	"encoding/json"
	"fmt"
)

// RecommendationKind distinguishes an observation to take from a change to make.
//
// It is the vocabulary ADR 0082 section 2.1 froze, and it lives here rather than
// in internal/diagnosis because it is **serialized**. A closed enumeration that
// reaches the canonical report is part of the report model, and the package that
// owns the report model owns its validation and its wire spelling. Phase 10.4B
// moved it down for exactly that reason; internal/diagnosis keeps its
// `AdviceKind` name as a type **alias**, so there is one vocabulary and no
// mapping that could drift.
//
// The zero RecommendationKind is RecommendationKindUnspecified, and it is a real
// answer: most recommendations in the tree predate the advice vocabulary and were
// never classified. Unspecified means "nobody said", never "next evidence".
type RecommendationKind uint8

const (
	// RecommendationKindUnspecified is the zero value and is not a kind.
	//
	// A recommendation carrying it is *unclassified*: it was built from an action
	// string alone, through NewRecommendation. That is truthful output, and it
	// serializes as the absence of the field rather than as a default.
	RecommendationKindUnspecified RecommendationKind = iota

	// RecommendationKindNextEvidence is an observation that would discriminate
	// between the explanations that remain.
	RecommendationKindNextEvidence

	// RecommendationKindRemediation is a change to make, and it requires much
	// stronger evidence: CONFIRMED and HIGH, and nothing less (ADR 0082 section
	// 2.3 rule 1). That gate needs a finding in hand and therefore lives in
	// internal/diagnosis, not here.
	RecommendationKindRemediation
)

// recommendationKindNames is indexed by RecommendationKind. Keep it aligned with
// the const block above; TestRecommendationKindNamesCoverAllKinds fails if the
// two drift apart.
var recommendationKindNames = [...]string{
	RecommendationKindUnspecified:  "UNSPECIFIED",
	RecommendationKindNextEvidence: "NEXT_EVIDENCE",
	RecommendationKindRemediation:  "REMEDIATION",
}

// Valid reports whether k is a defined kind. RecommendationKindUnspecified is
// not: it is the absence of a classification rather than one of them.
func (k RecommendationKind) Valid() bool {
	return k != RecommendationKindUnspecified && int(k) < len(recommendationKindNames)
}

// String returns the symbolic name. It never fails.
func (k RecommendationKind) String() string {
	if int(k) >= len(recommendationKindNames) {
		return fmt.Sprintf("RecommendationKind(%d)", uint8(k))
	}
	return recommendationKindNames[k]
}

// MarshalJSON emits the symbolic name.
//
// It refuses the unspecified value rather than emitting "UNSPECIFIED", because
// an unclassified recommendation omits the field entirely; reaching this method
// with the zero value means a caller marshalled a kind it should not have.
func (k RecommendationKind) MarshalJSON() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: recommendation kind %s", ErrInvalidValue, k)
	}
	return json.Marshal(k.String())
}

// SafetyClass is what taking a recommendation would cost, ordered by blast
// radius.
//
// The seven are frozen by ADR 0082 section 2.2. The first three change nothing
// and are the classes a diagnostic tool should overwhelmingly produce; the last
// three are **unreachable by construction** and exist so that the prohibition is
// nameable and testable rather than merely absent.
//
// It lives here for the same reason RecommendationKind does — it is serialized —
// and internal/diagnosis aliases it under its original name.
//
// The zero SafetyClass is SafetyUnspecified.
type SafetyClass uint8

const (
	// SafetyUnspecified is the zero value and is not a class.
	SafetyUnspecified SafetyClass = iota

	// SafetyObserve means reading something that already exists.
	SafetyObserve

	// SafetyVerify means checking a claim, changing nothing.
	SafetyVerify

	// SafetyCompare means contrasting two observations.
	SafetyCompare

	// SafetyConfigChange means changing configuration, taking effect on reload
	// or reconnect.
	SafetyConfigChange

	// SafetyRestart means restarting a component. Unreachable: svcdoctor does
	// not tell anyone to restart anything.
	SafetyRestart

	// SafetyDisruptive means interrupting service or risking data. Unreachable.
	SafetyDisruptive

	// SafetySecurityWeakening means reducing a security property. Unreachable,
	// and the sharpest of the three: svcdoctor must never recommend disabling
	// the verification it exists to perform.
	SafetySecurityWeakening
)

// safetyClassNames is indexed by SafetyClass. Keep it aligned with the const
// block above; TestSafetyClassNamesCoverAllClasses fails if the two drift apart.
var safetyClassNames = [...]string{
	SafetyUnspecified:       "UNSPECIFIED",
	SafetyObserve:           "OBSERVE",
	SafetyVerify:            "VERIFY",
	SafetyCompare:           "COMPARE",
	SafetyConfigChange:      "CONFIG_CHANGE",
	SafetyRestart:           "RESTART",
	SafetyDisruptive:        "DISRUPTIVE",
	SafetySecurityWeakening: "SECURITY_WEAKENING",
}

// Valid reports whether c is a defined class. SafetyUnspecified is not.
func (c SafetyClass) Valid() bool {
	return c != SafetyUnspecified && int(c) < len(safetyClassNames)
}

// String returns the symbolic name. It never fails.
func (c SafetyClass) String() string {
	if int(c) >= len(safetyClassNames) {
		return fmt.Sprintf("SafetyClass(%d)", uint8(c))
	}
	return safetyClassNames[c]
}

// Producible reports whether any producer may construct advice in this class.
//
// Three classes are false, permanently until an ADR says otherwise. They are in
// the vocabulary so that the report model can *classify* advice and so that a
// future phase which genuinely needs one has to add it deliberately, against a
// record. That friction is the point (ADR 0082 section 2.3 rule 2).
//
// Phase 10.4B moved this predicate down from internal/diagnosis with the type,
// and the move **strengthened** it: the refusal now runs at the report boundary,
// so it holds for every construction path rather than only for the ones that go
// through diagnosis.NewAdvice.
func (c SafetyClass) Producible() bool {
	switch c {
	case SafetyObserve, SafetyVerify, SafetyCompare, SafetyConfigChange:
		return true
	case SafetyUnspecified, SafetyRestart, SafetyDisruptive, SafetySecurityWeakening:
		return false
	}
	return false
}

// ChangesNothing reports whether taking the advice alters the target.
//
// The three read-only classes are the ceiling for a next-evidence
// recommendation, which by definition observes rather than changes.
func (c SafetyClass) ChangesNothing() bool {
	switch c {
	case SafetyObserve, SafetyVerify, SafetyCompare:
		return true
	default:
		return false
	}
}

// MarshalJSON emits the symbolic name, refusing the unspecified value for the
// same reason RecommendationKind does.
func (c SafetyClass) MarshalJSON() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("%w: safety class %s", ErrInvalidValue, c)
	}
	return json.Marshal(c.String())
}
