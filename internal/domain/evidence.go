package domain

import (
	"encoding/json"
	"fmt"
	"time"
)

// EvidenceInput carries the values NewEvidence validates.
//
// It exists so that constructing evidence names its fields at the call site.
// Nine positional arguments of which several are small integers and two are
// times would be trivially easy to transpose, and a transposition would produce
// silently wrong evidence rather than a compile error.
//
// It is a parameter object, not a builder: it is read once by NewEvidence and
// has no methods, no fluent API, and no bearing on the resulting value after
// construction.
type EvidenceInput struct {
	// ID identifies this node within the run. Required.
	ID EvidenceID

	// Subject says what the evidence is about. Required.
	Subject Subject

	// Layer is the diagnostic layer the step belongs to. Required.
	Layer Layer

	// Step names the operation that produced the evidence. Required.
	Step Step

	// State is the outcome. Required; the zero value is StateUnknown.
	State State

	// FailureClass explains a non-passing outcome. Leave as FailureNone when
	// there is nothing to classify.
	FailureClass FailureClass

	// Attributes carries normalized facts. Optional. The map and its contents
	// are copied, so the caller may reuse or mutate the map afterwards.
	Attributes map[AttributeKey]AttrValue

	// StartedAt is when the step began. Required, and normalized to UTC.
	StartedAt time.Time

	// Duration is how long the step took. Must not be negative.
	Duration time.Duration
}

// Evidence is one normalized, service-neutral diagnostic fact.
//
// It is the contract between the code that collects facts and the code that
// reasons about them. Probes and adapters normalize their producer-shaped
// results into evidence; diagnosis and renderers read nothing else.
//
// What it deliberately cannot hold:
//
//   - severity, confidence, a recommendation, or a finding code, because those
//     are interpretations and interpretation is diagnosis work
//   - a protocol client object, a connection, an error value, or any other raw
//     runtime type, because ADR 0010 keeps the canonical model free of them
//   - a secret, because normalized attributes accept only primitives and
//     credential material has no primitive form worth recording
//
// Those exclusions are enforced by the shape of the type rather than by
// convention: there is no field and no constructor argument that could carry
// them.
//
// Evidence behaves as a value. It is built once by NewEvidence and never
// changes: there are no setters, and no accessor hands out a reference through
// which recorded evidence could be edited.
//
// Relationships between nodes are not modelled here. Parent edges, blocking
// relationships, and traversal belong to the graph, which is separate work.
//
// The zero Evidence is invalid. Use NewEvidence.
type Evidence struct {
	id           EvidenceID
	subject      Subject
	layer        Layer
	step         Step
	state        State
	failureClass FailureClass
	attributes   map[AttributeKey]AttrValue
	startedAt    time.Time
	duration     time.Duration
}

// NewEvidence validates in and returns the resulting Evidence.
//
// Beyond validating each field, it rejects two state and failure-class
// combinations that would make a report self-contradictory:
//
//   - PASS with a failure class. A step that passed did not fail.
//   - FAIL without a failure class. A failure that cannot say what failed is
//     not reportable, and a reader could not act on it.
//
// DEGRADED, UNKNOWN, and SKIPPED accept either. All three have legitimate
// classified and unclassified cases: a certificate expiring next week is
// degraded with no matching class, an ambiguous peer response is unknown with no
// class, while a local budget expiring or a policy skip do have one. Rejecting
// those would overfit the model to today's examples.
func NewEvidence(in EvidenceInput) (Evidence, error) {
	if err := validateIdentifier("evidence id", string(in.ID)); err != nil {
		return Evidence{}, err
	}
	if in.Subject.IsZero() {
		return Evidence{}, fmt.Errorf("%w: evidence requires a subject", ErrInvalidValue)
	}
	if !in.Subject.Kind().Valid() {
		return Evidence{}, fmt.Errorf("%w: subject kind %s", ErrInvalidValue, in.Subject.Kind())
	}
	if !in.Layer.Valid() {
		return Evidence{}, fmt.Errorf("%w: layer %s", ErrInvalidValue, in.Layer)
	}
	if err := validateDottedName("step", string(in.Step)); err != nil {
		return Evidence{}, err
	}
	if !in.State.Valid() {
		return Evidence{}, fmt.Errorf("%w: state %s", ErrInvalidValue, in.State)
	}
	if !in.FailureClass.Valid() {
		return Evidence{}, fmt.Errorf("%w: failure class %s", ErrInvalidValue, in.FailureClass)
	}

	switch {
	case in.State == StatePass && in.FailureClass != FailureNone:
		return Evidence{}, fmt.Errorf(
			"%w: state PASS must not carry failure class %s", ErrInvalidValue, in.FailureClass)
	case in.State == StateFail && in.FailureClass == FailureNone:
		return Evidence{}, fmt.Errorf(
			"%w: state FAIL requires a failure class", ErrInvalidValue)
	}

	if in.StartedAt.IsZero() {
		return Evidence{}, fmt.Errorf("%w: evidence requires a start time", ErrInvalidValue)
	}
	if in.Duration < 0 {
		return Evidence{}, fmt.Errorf("%w: duration %s must not be negative", ErrInvalidValue, in.Duration)
	}

	attributes, err := copyAttributes(in.Attributes)
	if err != nil {
		return Evidence{}, err
	}

	return Evidence{
		id:           in.ID,
		subject:      in.Subject,
		layer:        in.Layer,
		step:         in.Step,
		state:        in.State,
		failureClass: in.FailureClass,
		attributes:   attributes,
		// UTC matches the normalization TimeAttr already applies, so an instant
		// encodes identically wherever it was produced, and drops the monotonic
		// reading, which is meaningless once serialized.
		startedAt: in.StartedAt.UTC(),
		duration:  in.Duration,
	}, nil
}

// copyAttributes validates every key and value and returns an owned copy, so
// that the caller's map cannot alter recorded evidence afterwards.
func copyAttributes(in map[AttributeKey]AttrValue) (map[AttributeKey]AttrValue, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[AttributeKey]AttrValue, len(in))
	for key, value := range in {
		if err := validateDottedName("attribute key", string(key)); err != nil {
			return nil, err
		}
		if !value.Valid() {
			return nil, fmt.Errorf("%w: attribute %q has no value", ErrInvalidValue, key)
		}
		out[key] = value
	}
	return out, nil
}

// ID returns the identifier of this node.
func (e Evidence) ID() EvidenceID { return e.id }

// Subject returns what the evidence is about.
func (e Evidence) Subject() Subject { return e.subject }

// Layer returns the diagnostic layer.
func (e Evidence) Layer() Layer { return e.layer }

// Step returns the operation that produced the evidence.
func (e Evidence) Step() Step { return e.step }

// State returns the outcome.
func (e Evidence) State() State { return e.state }

// FailureClass returns the classification of a non-passing outcome, or
// FailureNone.
func (e Evidence) FailureClass() FailureClass { return e.failureClass }

// StartedAt returns when the step began, in UTC.
func (e Evidence) StartedAt() time.Time { return e.startedAt }

// Duration returns how long the step took.
func (e Evidence) Duration() time.Duration { return e.duration }

// IsZero reports whether e is the invalid zero Evidence.
func (e Evidence) IsZero() bool { return e.id == "" && e.subject.IsZero() }

// Attribute returns one attribute and whether it is present.
//
// This is the access path for a diagnosis rule reading a specific fact. It
// copies nothing, because AttrValue is a value type whose only slice is copied
// by AttrValue.StringList.
func (e Evidence) Attribute(key AttributeKey) (AttrValue, bool) {
	v, ok := e.attributes[key]
	return v, ok
}

// AttributeCount returns how many attributes are recorded.
//
// It lets a caller test for emptiness without paying for the copy that
// Attributes makes.
func (e Evidence) AttributeCount() int { return len(e.attributes) }

// Attributes returns a copy of all attributes.
//
// This is the enumeration path, for a renderer walking every fact. The copy is
// what stops a reader from editing recorded evidence through the returned map.
func (e Evidence) Attributes() map[AttributeKey]AttrValue {
	if len(e.attributes) == 0 {
		return nil
	}
	out := make(map[AttributeKey]AttrValue, len(e.attributes))
	for key, value := range e.attributes {
		out[key] = value
	}
	return out
}

// String returns a compact readable rendering for logs and debugging. The
// canonical form is MarshalJSON.
func (e Evidence) String() string {
	if e.IsZero() {
		return "<invalid evidence>"
	}
	s := e.id.String() + " " + e.layer.String() + " " + e.step.String() + " " + e.state.String()
	if e.failureClass != FailureNone {
		s += " " + e.failureClass.String()
	}
	return s
}

// evidenceJSON is the wire shape of an Evidence.
//
// failureClass is omitted when nothing failed, because the report schema states
// that it is meaningless on a passing node. attributes is omitted when empty
// rather than encoded as "{}", so an absent fact and an empty set of facts are
// not confused.
//
// Attribute ordering is deterministic without extra work: encoding/json sorts
// map keys, and AttributeKey is a string kind.
type evidenceJSON struct {
	ID           EvidenceID                 `json:"id"`
	Subject      Subject                    `json:"subject"`
	Layer        Layer                      `json:"layer"`
	Step         Step                       `json:"step"`
	State        State                      `json:"state"`
	FailureClass *FailureClass              `json:"failureClass,omitempty"`
	Attributes   map[AttributeKey]AttrValue `json:"attributes,omitempty"`
	StartedAt    string                     `json:"startedAt"`
	Duration     string                     `json:"duration"`
}

// MarshalJSON emits the canonical representation of one evidence node.
//
// A custom marshaler is required rather than merely convenient: the fields are
// unexported so that evidence cannot be edited after construction, and the
// default encoding of such a struct is "{}".
//
// Durations use Go duration syntax such as "12ms", matching DurationAttr, so
// that the same quantity is written the same way everywhere in a report.
func (e Evidence) MarshalJSON() ([]byte, error) {
	if e.IsZero() {
		return nil, fmt.Errorf("%w: zero Evidence", ErrInvalidValue)
	}

	out := evidenceJSON{
		ID:         e.id,
		Subject:    e.subject,
		Layer:      e.layer,
		Step:       e.step,
		State:      e.state,
		Attributes: e.attributes,
		StartedAt:  e.startedAt.Format(time.RFC3339Nano),
		Duration:   e.duration.String(),
	}
	if e.failureClass != FailureNone {
		out.FailureClass = &e.failureClass
	}

	return json.Marshal(out)
}
