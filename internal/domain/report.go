package domain

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// SchemaVersion is the version of the canonical report contract this package
// produces.
//
// It is a constant rather than a caller-supplied field. A report always encodes
// the schema it was actually written against, so there is no way for a caller to
// label a report with a version it does not implement. Changing it is a
// deliberate edit here, accompanied by the schema decision docs/REPORT_SCHEMA.md
// section 1 requires.
const SchemaVersion = 1

// ErrInvalidReport reports that a report's parts do not agree with each other.
//
// It is distinct from ErrInvalidValue: that one means a single value cannot be
// represented, while this one means every value is individually fine but the
// assembly is not. A finding referencing evidence that is not in the graph fails
// this way.
var ErrInvalidReport = errors.New("invalid report")

// ReportInput carries the values NewReport validates and assembles.
//
// There is deliberately no Summary field. The summary is derived from Graph and
// Findings; accepting one would allow a report whose summary contradicts its own
// contents. See ADR 0015.
type ReportInput struct {
	// Run holds the execution facts of the run. Required.
	Run RunMetadata

	// Target describes what was inspected. Required.
	Target Target

	// Vantage records where probes ran from. Required.
	Vantage Vantage

	// Graph is the frozen evidence graph. It is a Graph and never a
	// GraphBuilder, per ADR 0013.
	Graph Graph

	// Findings are the conclusions diagnosis produced. Optional: a run that
	// found nothing wrong still produces a report. The slice is copied and
	// reordered canonically.
	Findings []Finding

	// Security records how the run was configured. Required.
	Security ReportSecurity
}

// Report is the canonical result of one diagnostic run.
//
// It assembles and validates already-produced diagnostic data. It does not
// diagnose: it creates no findings, infers no causes, performs no I/O, and never
// mutates the graph it was given. Everything it adds is aggregation over data it
// already holds.
//
// A report is immutable. It is built once by NewReport, has no setters, and no
// accessor returns a reference through which its contents could be edited.
//
// # What it does not do
//
// It performs no redaction. A report is produced unredacted for local use;
// making one safe to share is a transformation that does not exist yet, and
// ReportSecurity refuses to claim otherwise.
//
// It also holds no secret. No field accepts a security.Secret or a
// security.Credential, which is why this package needs no dependency on
// internal/security.
//
// The zero Report is invalid. Use NewReport.
type Report struct {
	run      RunMetadata
	target   Target
	vantage  Vantage
	graph    Graph
	findings []Finding
	summary  Summary
	security ReportSecurity
}

// NewReport validates in, derives the summary and returns the report.
//
// # Cross-object integrity
//
// Every evidence identifier referenced by every finding must resolve to a node
// in the graph. A single dangling reference fails the whole construction: the
// finding is not dropped, the reference is not removed, and the graph is not
// touched. A report that quietly discarded either would be describing a run that
// did not happen.
//
// This is the only place the check can live. A Finding validates that its
// identifiers are well formed but deliberately never takes a Graph, so the
// report is the first thing holding both sides. See ADR 0014.
//
// Findings are trusted to be internally valid, because NewFinding already
// established that; this constructor checks only what needs both sides.
func NewReport(in ReportInput) (Report, error) {
	if in.Run.IsZero() {
		return Report{}, fmt.Errorf("%w: report requires run metadata", ErrInvalidValue)
	}
	if in.Target.IsZero() {
		return Report{}, fmt.Errorf("%w: report requires a target", ErrInvalidValue)
	}
	if in.Vantage.IsZero() {
		return Report{}, fmt.Errorf("%w: report requires a vantage", ErrInvalidValue)
	}
	if in.Security.IsZero() {
		return Report{}, fmt.Errorf("%w: report requires security metadata", ErrInvalidValue)
	}

	findings := slices.Clone(in.Findings)
	for i, f := range findings {
		if f.IsZero() {
			return Report{}, fmt.Errorf("%w: finding %d is the zero value", ErrInvalidValue, i)
		}
	}

	if err := validateEvidenceRefs(in.Graph, findings); err != nil {
		return Report{}, err
	}

	SortFindings(findings)

	return Report{
		run:      in.Run,
		target:   in.Target,
		vantage:  in.Vantage,
		graph:    in.Graph,
		findings: findings,
		summary:  deriveSummary(in.Graph, findings),
		security: in.Security,
	}, nil
}

// validateEvidenceRefs enforces the ADR 0014 acceptance criterion.
func validateEvidenceRefs(g Graph, findings []Finding) error {
	for _, f := range findings {
		for _, ref := range f.EvidenceRefs() {
			if _, ok := g.Node(ref); !ok {
				return fmt.Errorf(
					"%w: finding %s references evidence %q that is not in the graph",
					ErrInvalidReport, f.Code(), ref)
			}
		}
	}
	return nil
}

// SortFindings puts findings in canonical order, in place.
//
// Insertion order is not canonical: diagnosis evaluates a set of rules whose
// order is a wiring detail, and a report must be byte-stable for the same
// content regardless of it.
//
// The order is most severe first, then earliest layer, which puts the earliest
// broken layer near the top where docs/FINDINGS.md section 5 wants it. The
// remaining keys exist to make the order total rather than to rank anything:
//
//	severity descending
//	layer ascending
//	code ascending
//	subject reference ascending
//	summary ascending
//	joined evidence references ascending
//
// Two findings equal on all six are treated as equivalent for ordering.
//
// It is exported because the report and the diagnosis engine both need this
// order, and a second implementation of it could disagree with this one.
func SortFindings(findings []Finding) {
	slices.SortStableFunc(findings, func(a, b Finding) int {
		if c := cmp.Compare(b.Severity(), a.Severity()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Layer(), b.Layer()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Code(), b.Code()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Subject().Ref(), b.Subject().Ref()); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Summary(), b.Summary()); c != 0 {
			return c
		}
		return cmp.Compare(joinIDs(a.EvidenceRefs()), joinIDs(b.EvidenceRefs()))
	})
}

// joinIDs renders a sorted identifier list as one comparable string.
func joinIDs(ids []EvidenceID) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = string(id)
	}
	return strings.Join(parts, "\x00")
}

// Run returns the execution facts of the run.
func (r Report) Run() RunMetadata { return r.run }

// Target returns what was inspected.
func (r Report) Target() Target { return r.target }

// Vantage returns where probes ran from.
func (r Report) Vantage() Vantage { return r.vantage }

// Graph returns the frozen evidence graph.
//
// Graph is immutable and every accessor on it copies, so handing it back cannot
// let a caller alter the report.
func (r Report) Graph() Graph { return r.graph }

// Findings returns a copy of the findings in canonical order.
func (r Report) Findings() []Finding {
	if len(r.findings) == 0 {
		return nil
	}
	return slices.Clone(r.findings)
}

// FindingCount returns how many findings the report holds.
func (r Report) FindingCount() int { return len(r.findings) }

// Summary returns the derived aggregation.
func (r Report) Summary() Summary { return r.summary }

// Security returns the metadata a reader needs to interpret the report.
func (r Report) Security() ReportSecurity { return r.security }

// IsZero reports whether r is the invalid zero Report.
func (r Report) IsZero() bool { return r.run.IsZero() && r.target.IsZero() }

// String returns a compact readable rendering for logs. The canonical form is
// MarshalJSON.
func (r Report) String() string {
	if r.IsZero() {
		return "<invalid report>"
	}
	return fmt.Sprintf("svcdoctor report: service=%s target=%s status=%s findings=%d evidence=%d",
		r.run.Service(), r.target, r.summary.Status(), len(r.findings), r.graph.Len())
}

// evidenceRelationJSON is one node's relationships in the encoded report.
type evidenceRelationJSON struct {
	ID        EvidenceID   `json:"id"`
	Parents   []EvidenceID `json:"parents,omitempty"`
	BlockedBy []EvidenceID `json:"blockedBy,omitempty"`
}

// evidenceSectionJSON is the encoded evidence graph.
//
// Nodes and relationships are separate sections rather than relationships being
// attached to each node. ADR 0013 makes relationships graph-owned rather than a
// property of a fact, and this keeps the encoded form saying the same thing.
// It also leaves Evidence.MarshalJSON as the single definition of how a node is
// written, instead of restating those fields here where the two could drift.
// See ADR 0016.
type evidenceSectionJSON struct {
	Nodes         []Evidence             `json:"nodes"`
	Relationships []evidenceRelationJSON `json:"relationships,omitempty"`
}

// runSectionJSON is the encoded run section.
//
// It repeats two facts that RunMetadata does not own, because
// docs/REPORT_SCHEMA.md section 2 places them here as well as in security. They
// are stored once, in ReportSecurity, and written into both sections from that
// one value, so the two can never disagree.
type runSectionJSON struct {
	SvcdoctorVersion        string     `json:"svcdoctorVersion"`
	StartedAt               string     `json:"startedAt"`
	Duration                string     `json:"duration"`
	Service                 ServiceID  `json:"service"`
	TLSVerificationDisabled bool       `json:"tlsVerificationDisabled"`
	OutputMode              OutputMode `json:"outputMode"`
}

// reportJSON is the wire shape of a Report. The field order matches the top-level
// contract in docs/REPORT_SCHEMA.md.
type reportJSON struct {
	SchemaVersion int                 `json:"schemaVersion"`
	Run           runSectionJSON      `json:"run"`
	Target        Target              `json:"target"`
	Vantage       Vantage             `json:"vantage"`
	Evidence      evidenceSectionJSON `json:"evidence"`
	Findings      []Finding           `json:"findings"`
	Summary       Summary             `json:"summary"`
	Security      ReportSecurity      `json:"security"`
}

// MarshalJSON emits the canonical report.
//
// The report owns this shape. Graph has no MarshalJSON of its own: its in-memory
// API and the report contract are separate concerns, and giving Graph a public
// encoding would create a second serialization to keep in step with this one for
// no consumer. See ADR 0016.
//
// The encoding is deterministic. Nodes and relationships follow the graph's
// canonical EvidenceID order, findings follow the canonical finding order, and
// no map is iterated, so the same content always produces the same bytes.
func (r Report) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: zero Report", ErrInvalidValue)
	}

	nodes := r.graph.Nodes()
	relationships := make([]evidenceRelationJSON, 0, len(nodes))
	for _, node := range nodes {
		parents := r.graph.Parents(node.ID())
		blockedBy := r.graph.BlockedBy(node.ID())
		if len(parents) == 0 && len(blockedBy) == 0 {
			continue
		}
		relationships = append(relationships, evidenceRelationJSON{
			ID:        node.ID(),
			Parents:   parents,
			BlockedBy: blockedBy,
		})
	}

	findings := r.findings
	if findings == nil {
		findings = []Finding{}
	}

	return json.Marshal(reportJSON{
		SchemaVersion: SchemaVersion,
		Run: runSectionJSON{
			SvcdoctorVersion:        r.run.SvcdoctorVersion(),
			StartedAt:               r.run.StartedAt().Format(time.RFC3339Nano),
			Duration:                r.run.Duration().String(),
			Service:                 r.run.Service(),
			TLSVerificationDisabled: r.security.TLSVerificationDisabled(),
			OutputMode:              r.security.OutputMode(),
		},
		Target:   r.target,
		Vantage:  r.vantage,
		Evidence: evidenceSectionJSON{Nodes: nodes, Relationships: relationships},
		Findings: findings,
		Summary:  r.summary,
		Security: r.security,
	})
}
