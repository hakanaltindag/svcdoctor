package domain

import (
	"encoding/json"
	"fmt"
)

// Recommendation is one suggested next action attached to a finding.
//
// It is inert report data. It is not a task, not a script, and not something
// svcdoctor executes: there is no command to run, no remediation to apply, and
// no workflow to advance. A reader decides what to do with it.
//
// # The four classification fields, and why they arrived late
//
// ADR 0082 section 2.1 decided them in Phase 10.0 and this type's own doc
// comment anticipated them — "a struct rather than a bare string so that the
// encoded form is an object from the outset, which lets fields such as a
// reference link or a remediation risk be added later". Phases 10.1b, 10.2 and
// 10.3 each declined to move them, and Phase 10.4A measured what that cost: both
// service packages built a fully classified, fully guarded diagnosis.Advice, ran
// every guardrail over it, and then threw four of its five fields away here. A
// consumer could not tell an observation from a change, which is the distinction
// the whole safety model rests on. Phase 10.4B closes it.
//
// # Classified and unclassified recommendations both exist, on purpose
//
// Two constructors, and the difference is honest rather than transitional:
//
//   - NewRecommendation takes an action alone and produces an **unclassified**
//     recommendation. Most of the tree's recommendations are this: they predate
//     the advice vocabulary and were never routed through diagnosis.NewAdvice.
//   - NewClassifiedRecommendation takes the full five and validates them.
//
// An unclassified recommendation serializes **without** the four fields, so the
// report says "nobody classified this" by omission rather than by defaulting.
// Defaulting an unset kind to NEXT_EVIDENCE would be the semantically false
// value this type exists to refuse: it would assert that an unreviewed string
// changes nothing.
//
// Classifying the remaining producers is each service's own judgement about its
// own advice, not plumbing, and is deliberately not done here.
//
// The zero Recommendation is invalid. Use one of the two constructors.
type Recommendation struct {
	action          string
	kind            RecommendationKind
	safety          SafetyClass
	rationale       string
	selfCollectable bool
}

// RecommendationInput carries the values NewClassifiedRecommendation validates.
type RecommendationInput struct {
	// Action is one line of human-readable text. Never a command to execute.
	Action string

	// Kind says whether this is an observation to take or a change to make.
	Kind RecommendationKind

	// Safety is what taking it would cost.
	Safety SafetyClass

	// Rationale says why this observation discriminates, or why this change
	// follows from the evidence.
	Rationale string

	// SelfCollectable reports whether svcdoctor could take this observation
	// itself in some run.
	//
	// **It is report metadata and never authorization.** True does not mean
	// svcdoctor will collect it, may collect it, or has collected it: diagnosis
	// performs no I/O (ADR 0078 section 2.6), there is no automatic collection,
	// and nothing in the product reads this field as an instruction. It means a
	// differently configured run could — "re-run with a larger execution budget"
	// is the shape of it (ADR 0082 section 2.4, ADR 0086 section 2.6).
	//
	// It is meaningless on a remediation, and the constructor rejects it there.
	SelfCollectable bool
}

// NewRecommendation validates a suggested action and returns an **unclassified**
// recommendation.
//
// The action is a single line of human-readable text. It is validated only as a
// value: nothing here contacts a network, resolves a link, or checks that the
// advice is applicable.
//
// It is not deprecated and is not a legacy path. A producer that has not decided
// what kind and safety class its advice carries should say so by omission rather
// than guess, and this is how.
func NewRecommendation(action string) (Recommendation, error) {
	if err := validateIdentifier("recommendation action", action); err != nil {
		return Recommendation{}, err
	}
	return Recommendation{action: action}, nil
}

// NewClassifiedRecommendation validates a fully classified recommendation.
//
// It enforces, at the **report boundary**, every guardrail ADR 0082 section 2.3
// states that can be checked without a finding in hand. That placement is the
// point: before Phase 10.4B the refusals lived only in diagnosis.NewAdvice, so
// they bound the one path that happened to go through it. Now they bind every
// path that can reach a report.
//
//  1. Classification is all-or-nothing. A rationale or a safety class without a
//     kind is a half-classified value, and a half-classified value is exactly
//     the "valid but semantically false" shape this constructor exists to
//     refuse. Unclassified is spelled NewRecommendation.
//  2. The three high-blast-radius classes are refused outright.
//  3. Next evidence must change nothing, so its class is one of the three
//     read-only ones.
//  4. SelfCollectable describes an observation, and svcdoctor takes no
//     remediation at all.
//  5. Advice must say why. A suggestion with no stated reason cannot be reviewed
//     or rejected.
//
// The one guardrail absent here is the confidence gate — a REMEDIATION needs a
// CONFIRMED finding at HIGH — because it needs the finding. It stays in
// diagnosis.AdmitAdvice.
func NewClassifiedRecommendation(in RecommendationInput) (Recommendation, error) {
	if err := validateIdentifier("recommendation action", in.Action); err != nil {
		return Recommendation{}, err
	}
	if !in.Kind.Valid() {
		return Recommendation{}, fmt.Errorf(
			"%w: recommendation kind %s; a classified recommendation states its kind, "+
				"and an unclassified one is built with NewRecommendation",
			ErrInvalidValue, in.Kind)
	}
	if !in.Safety.Valid() {
		return Recommendation{}, fmt.Errorf(
			"%w: safety class %s", ErrInvalidValue, in.Safety)
	}
	if !in.Safety.Producible() {
		return Recommendation{}, fmt.Errorf(
			"%w: no producer may construct %s advice; the class exists so the "+
				"prohibition is nameable, and lifting it is an ADR (ADR 0082 section 2.3 "+
				"rule 2)", ErrInvalidValue, in.Safety)
	}
	if in.Kind == RecommendationKindNextEvidence && !in.Safety.ChangesNothing() {
		return Recommendation{}, fmt.Errorf(
			"%w: %s advice is classified %s; an observation that changes the target is "+
				"a remediation wearing the wrong label (ADR 0082 section 2.4)",
			ErrInvalidValue, in.Kind, in.Safety)
	}
	if in.Kind == RecommendationKindRemediation && in.SelfCollectable {
		return Recommendation{}, fmt.Errorf(
			"%w: SelfCollectable describes an observation svcdoctor could take, and "+
				"svcdoctor takes no remediation at all", ErrInvalidValue)
	}
	if err := validateIdentifier("recommendation rationale", in.Rationale); err != nil {
		return Recommendation{}, err
	}

	return Recommendation{
		action:          in.Action,
		kind:            in.Kind,
		safety:          in.Safety,
		rationale:       in.Rationale,
		selfCollectable: in.SelfCollectable,
	}, nil
}

// Action returns the suggested action text.
func (r Recommendation) Action() string { return r.action }

// Kind returns whether this is an observation or a change, which is
// RecommendationKindUnspecified on an unclassified recommendation.
func (r Recommendation) Kind() RecommendationKind { return r.kind }

// Safety returns what taking it would cost, which is SafetyUnspecified on an
// unclassified recommendation.
func (r Recommendation) Safety() SafetyClass { return r.safety }

// Rationale returns why it discriminates, or why it follows, which is empty on
// an unclassified recommendation.
func (r Recommendation) Rationale() string { return r.rationale }

// SelfCollectable reports whether svcdoctor could take this observation itself.
//
// It is meaningful only on a classified next-evidence recommendation; elsewhere
// it is false because nothing set it, which is why the encoded form omits it.
// **It authorizes nothing.** See RecommendationInput.SelfCollectable.
func (r Recommendation) SelfCollectable() bool { return r.selfCollectable }

// Classified reports whether the four semantic fields were supplied.
func (r Recommendation) Classified() bool { return r.kind.Valid() }

// IsZero reports whether r is the invalid zero Recommendation.
//
// It tests the action alone, deliberately: an unclassified recommendation is a
// valid value with three zero fields, and a zero-struct comparison would call it
// invalid.
func (r Recommendation) IsZero() bool { return r.action == "" }

// String returns the action text.
func (r Recommendation) String() string {
	if r.IsZero() {
		return "<invalid recommendation>"
	}
	return r.action
}

// recommendationJSON is the encoded shape.
//
// The four additions are `omitempty` so that an unclassified recommendation
// encodes exactly as it did before Phase 10.4B — byte for byte — and a consumer
// reading `action` alone is unaffected. That is the additive-at-v1 contract of
// docs/REPORT_SCHEMA.md section 1 and ADR 0083 section 2.1.
type recommendationJSON struct {
	Action          string             `json:"action"`
	Kind            RecommendationKind `json:"kind,omitempty"`
	Safety          SafetyClass        `json:"safety,omitempty"`
	Rationale       string             `json:"rationale,omitempty"`
	SelfCollectable *bool              `json:"selfCollectable,omitempty"`
}

// MarshalJSON emits the recommendation as an object.
//
// A custom marshaler is required rather than merely convenient: the fields are
// unexported to keep the value immutable, so the default encoding would be "{}".
//
// # Why selfCollectable is a pointer
//
// It is the one new field whose **false** is meaningful. "svcdoctor cannot take
// this observation" is the honest and frequent answer (ADR 0082 section 2.4), so
// omitting it would erase information; but emitting `false` on an *unclassified*
// recommendation would assert that answer where nobody gave one. A pointer
// distinguishes the two: present-and-false on a next-evidence recommendation,
// absent everywhere else.
//
// It is emitted only for next evidence, because the constructor already refuses
// a self-collectable remediation, so the field would be a constant false there.
func (r Recommendation) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: zero Recommendation", ErrInvalidValue)
	}
	out := recommendationJSON{
		Action:    r.action,
		Kind:      r.kind,
		Safety:    r.safety,
		Rationale: r.rationale,
	}
	if r.kind == RecommendationKindNextEvidence {
		selfCollectable := r.selfCollectable
		out.SelfCollectable = &selfCollectable
	}
	return json.Marshal(out)
}
