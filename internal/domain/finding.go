package domain

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// FindingInput carries the values NewFinding validates.
//
// It exists so that constructing a finding names its fields at the call site.
// Several arguments are small enumerations of the same underlying kind, and a
// transposed pair would produce a silently wrong finding rather than a compile
// error.
//
// It is a parameter object, not a builder: NewFinding reads it once, and it has
// no bearing on the resulting value afterwards.
type FindingInput struct {
	// Code identifies the finding. Required.
	Code FindingCode

	// Kind says how strongly the evidence supports the claim. Required.
	Kind FindingKind

	// Severity is the impact. Required.
	Severity Severity

	// Confidence is the epistemic strength. Required.
	Confidence Confidence

	// Layer is the diagnostic layer the finding concerns. Required, and supplied
	// by the caller rather than derived from Code, so that the core never holds
	// a code-to-layer mapping that every new service would have to edit.
	Layer Layer

	// Subject is what the finding is about. Optional: a finding may concern the
	// run as a whole rather than one endpoint.
	Subject Subject

	// Summary is a single line stating the finding. Required.
	Summary string

	// Detail is optional longer prose and may span several lines.
	Detail string

	// EvidenceRefs are the evidence nodes that produced this finding. At least
	// one is required. Duplicates are removed and the result is sorted.
	EvidenceRefs []EvidenceID

	// Recommendations are optional suggested next actions.
	Recommendations []Recommendation

	// VantageDependent marks a finding whose validity depends on where the
	// evidence was collected from.
	VantageDependent bool

	// Discriminator states what additional evidence would confirm or reject a
	// hypothesis. Only meaningful when Kind is HYPOTHESIS.
	Discriminator string
}

// Finding is one conclusion drawn from evidence.
//
// It is the output of diagnosis and an input to a report. It is a value: built
// once by NewFinding, never changed, with no setters and no accessor that hands
// out a mutable reference.
//
// What it deliberately cannot hold:
//
//   - a Graph or any Evidence value. A finding points at evidence by identifier
//     and nothing more; see the evidence reference section below.
//   - an error value, a connection, or any raw runtime or protocol object, for
//     the same reason canonical evidence excludes them (ADR 0010).
//   - an exit code or any mapping to one. Severity is data; turning findings into
//     a process status is defined in docs/SCOPE.md and happens at the report and
//     CLI boundary.
//
// # Evidence references
//
// A finding names the exact evidence identifiers that produced it, so a reader
// can answer "why did svcdoctor say this?" from the report alone, without
// rerunning any probe. That is why at least one reference is required: a finding
// that cannot point at its evidence is not reportable.
//
// The identifiers are validated individually. Whether each one resolves to a node
// in the graph is a cross-object invariant that this type deliberately does not
// check, because doing so would make every finding depend on a graph. See
// ADR 0014.
//
// # Claim discipline
//
// The model makes disciplined claims expressible; it does not enforce diagnosis
// policy. Rules such as "an unsupported capability is not a target failure" and
// "do not invent downstream claims when the prerequisite layer failed" govern
// which finding a rule chooses to construct, not whether the value is
// structurally valid. See docs/FINDINGS.md section 4. This constructor rejects
// only combinations that contradict themselves.
//
// The zero Finding is invalid. Use NewFinding.
type Finding struct {
	code             FindingCode
	kind             FindingKind
	severity         Severity
	confidence       Confidence
	layer            Layer
	subject          Subject
	summary          string
	detail           string
	evidenceRefs     []EvidenceID
	recommendations  []Recommendation
	vantageDependent bool
	discriminator    string
}

// NewFinding validates in and returns the resulting Finding.
//
// Beyond validating each field it rejects one self-contradictory combination:
// a CONFIRMED finding carrying a discriminator. A discriminator states what
// would settle an open question, and a confirmed finding has none to settle.
//
// A HYPOTHESIS without a discriminator is accepted. docs/REPORT_SCHEMA.md says
// the model "allows" one and docs/FINDINGS.md says to "prefer" stating it;
// neither requires it, and inventing a hard requirement here would be diagnosis
// policy rather than structural validation.
func NewFinding(in FindingInput) (Finding, error) {
	if !in.Code.Valid() {
		return Finding{}, fmt.Errorf("%w: finding code %q", ErrInvalidValue, in.Code)
	}
	if !in.Kind.Valid() {
		return Finding{}, fmt.Errorf("%w: finding kind %s", ErrInvalidValue, in.Kind)
	}
	if !in.Severity.Valid() {
		return Finding{}, fmt.Errorf("%w: severity %s", ErrInvalidValue, in.Severity)
	}
	if !in.Confidence.Valid() {
		return Finding{}, fmt.Errorf("%w: confidence %s", ErrInvalidValue, in.Confidence)
	}
	if !in.Layer.Valid() {
		return Finding{}, fmt.Errorf("%w: layer %s", ErrInvalidValue, in.Layer)
	}
	// Subject is optional, but a supplied one must be well formed.
	if !in.Subject.IsZero() && !in.Subject.Kind().Valid() {
		return Finding{}, fmt.Errorf("%w: subject kind %s", ErrInvalidValue, in.Subject.Kind())
	}
	if err := validateIdentifier("finding summary", in.Summary); err != nil {
		return Finding{}, err
	}
	if in.Detail != "" {
		if err := validateProse("finding detail", in.Detail); err != nil {
			return Finding{}, err
		}
	}
	if in.Discriminator != "" {
		if err := validateIdentifier("finding discriminator", in.Discriminator); err != nil {
			return Finding{}, err
		}
	}
	if in.Kind == FindingKindConfirmed && in.Discriminator != "" {
		return Finding{}, fmt.Errorf(
			"%w: a CONFIRMED finding must not carry a discriminator", ErrInvalidValue)
	}

	refs, err := normalizeEvidenceRefs(in.EvidenceRefs)
	if err != nil {
		return Finding{}, err
	}

	recommendations, err := copyRecommendations(in.Recommendations)
	if err != nil {
		return Finding{}, err
	}

	return Finding{
		code:             in.Code,
		kind:             in.Kind,
		severity:         in.Severity,
		confidence:       in.Confidence,
		layer:            in.Layer,
		subject:          in.Subject,
		summary:          in.Summary,
		detail:           in.Detail,
		evidenceRefs:     refs,
		recommendations:  recommendations,
		vantageDependent: in.VantageDependent,
		discriminator:    in.Discriminator,
	}, nil
}

// normalizeEvidenceRefs validates, deduplicates and sorts the references.
//
// Duplicates are removed rather than rejected: a rule may legitimately assemble
// references from two sources that name the same node, and the set of evidence
// it points at is unchanged. Sorting makes the encoded finding byte-stable no
// matter what order the rule collected them in.
func normalizeEvidenceRefs(in []EvidenceID) ([]EvidenceID, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf(
			"%w: a finding must reference at least one piece of evidence", ErrInvalidValue)
	}

	seen := make(map[EvidenceID]struct{}, len(in))
	out := make([]EvidenceID, 0, len(in))
	for _, id := range in {
		if err := validateIdentifier("evidence reference", string(id)); err != nil {
			return nil, err
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	slices.Sort(out)
	return out, nil
}

// copyRecommendations validates and returns an owned copy, so that the caller's
// slice cannot alter a recorded finding afterwards.
func copyRecommendations(in []Recommendation) ([]Recommendation, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]Recommendation, 0, len(in))
	for _, r := range in {
		if r.IsZero() {
			return nil, fmt.Errorf("%w: recommendation has no action", ErrInvalidValue)
		}
		out = append(out, r)
	}
	return out, nil
}

// validateProse checks optional multi-line text. Newlines are allowed because
// detail is prose; other control characters are not, because they corrupt JSON
// and terminal output.
func validateProse(label, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s must be valid UTF-8", ErrInvalidValue, label)
	}
	if strings.TrimSpace(s) == "" {
		return fmt.Errorf("%w: %s must not be blank", ErrInvalidValue, label)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidValue, label)
	}
	for _, r := range s {
		if r != '\n' && unicode.IsControl(r) {
			return fmt.Errorf("%w: %s must not contain control characters", ErrInvalidValue, label)
		}
	}
	return nil
}

// Code returns the machine-consumed identifier.
func (f Finding) Code() FindingCode { return f.code }

// Kind returns how strongly the evidence supports the claim.
func (f Finding) Kind() FindingKind { return f.kind }

// Severity returns the impact.
func (f Finding) Severity() Severity { return f.severity }

// Confidence returns the epistemic strength.
func (f Finding) Confidence() Confidence { return f.confidence }

// Layer returns the diagnostic layer the finding concerns.
func (f Finding) Layer() Layer { return f.layer }

// Subject returns what the finding is about, which may be the zero Subject.
func (f Finding) Subject() Subject { return f.subject }

// Summary returns the single-line statement of the finding.
func (f Finding) Summary() string { return f.summary }

// Detail returns the longer prose, which may be empty.
func (f Finding) Detail() string { return f.detail }

// Discriminator returns what additional evidence would settle a hypothesis,
// which is empty for a confirmed finding.
func (f Finding) Discriminator() string { return f.discriminator }

// VantageDependent reports whether the finding's validity depends on where the
// evidence was collected from.
//
// It is a flag, not a copy of the vantage. The report carries the actual
// Vantage once, and duplicating it on every finding would create a second place
// for it to be wrong. What a finding needs to say is only whether its
// interpretation is tied to that position: an unreachable advertised endpoint
// may be genuinely unreachable from a laptop and perfectly reachable from an
// in-cluster pod, and a reader must not mistake the first for a statement about
// the service.
func (f Finding) VantageDependent() bool { return f.vantageDependent }

// IsZero reports whether f is the invalid zero Finding.
func (f Finding) IsZero() bool { return f.code == "" && f.summary == "" }

// EvidenceRefCount returns how many evidence references the finding carries.
//
// It lets a caller check the count without paying for the copy EvidenceRefs
// makes.
func (f Finding) EvidenceRefCount() int { return len(f.evidenceRefs) }

// EvidenceRefs returns a copy of the referenced evidence identifiers, sorted.
func (f Finding) EvidenceRefs() []EvidenceID {
	return copyIDs(f.evidenceRefs)
}

// Recommendations returns a copy of the suggested next actions.
func (f Finding) Recommendations() []Recommendation {
	if len(f.recommendations) == 0 {
		return nil
	}
	return slices.Clone(f.recommendations)
}

// String returns a compact readable rendering for logs and debugging. The
// canonical form is MarshalJSON.
func (f Finding) String() string {
	if f.IsZero() {
		return "<invalid finding>"
	}
	return fmt.Sprintf("%s %s %s/%s %s: %s",
		f.code, f.layer, f.severity, f.confidence, f.kind, f.summary)
}

// findingJSON is the wire shape of a Finding.
//
// Optional fields are omitted when they carry no information, so a reader is not
// shown empty strings and empty arrays. vantageDependent is always present,
// because false is a meaningful statement rather than an absent one.
type findingJSON struct {
	Code             FindingCode      `json:"code"`
	Kind             FindingKind      `json:"kind"`
	Severity         Severity         `json:"severity"`
	Confidence       Confidence       `json:"confidence"`
	Layer            Layer            `json:"layer"`
	Subject          *Subject         `json:"subject,omitempty"`
	Summary          string           `json:"summary"`
	Detail           string           `json:"detail,omitempty"`
	EvidenceRefs     []EvidenceID     `json:"evidenceRefs"`
	Recommendations  []Recommendation `json:"recommendations,omitempty"`
	VantageDependent bool             `json:"vantageDependent"`
	Discriminator    string           `json:"discriminator,omitempty"`
}

// MarshalJSON emits the canonical representation of one finding.
//
// A custom marshaler is required rather than merely convenient: the fields are
// unexported so that a finding cannot be edited after construction, and the
// default encoding of such a struct is "{}".
//
// Every enumeration is written as its symbolic name, never an ordinal, so that
// adding a level later cannot shift the meaning of an existing report.
func (f Finding) MarshalJSON() ([]byte, error) {
	if f.IsZero() {
		return nil, fmt.Errorf("%w: zero Finding", ErrInvalidValue)
	}

	out := findingJSON{
		Code:             f.code,
		Kind:             f.kind,
		Severity:         f.severity,
		Confidence:       f.confidence,
		Layer:            f.layer,
		Summary:          f.summary,
		Detail:           f.detail,
		EvidenceRefs:     f.evidenceRefs,
		Recommendations:  f.recommendations,
		VantageDependent: f.vantageDependent,
		Discriminator:    f.discriminator,
	}
	if !f.subject.IsZero() {
		out.Subject = &f.subject
	}

	return json.Marshal(out)
}
