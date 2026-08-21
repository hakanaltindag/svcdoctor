package domain

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// SummaryStatus is the report's overall outcome.
//
// The vocabulary is deliberately two values, taken directly from the exit code
// contract in docs/SCOPE.md rather than invented: exit 0 is "no ERROR/CRITICAL
// finding exists" and exit 1 is "ERROR/CRITICAL findings exist". Anything richer
// would be a health taxonomy no document defines.
//
// # OK is not a claim of health
//
// SummaryStatusOK means exactly one thing: no finding reached ERROR or CRITICAL.
// It does not mean the target is healthy. A run where most checks were skipped
// for lack of privilege produces no errors and is not a clean bill of health,
// which is why Summary reports skipped and unknown evidence counts alongside the
// status. Both must be read together. See docs/REPORT_SCHEMA.md section 8.
//
// The status covers exit codes 0 and 1 only. Codes 2, 3 and 4 describe usage
// errors, internal failures and partial runs, none of which a report can observe
// about itself.
//
// The zero SummaryStatus is SummaryStatusUnspecified.
type SummaryStatus uint8

const (
	// SummaryStatusUnspecified is the zero value and is not a status.
	SummaryStatusUnspecified SummaryStatus = iota

	// SummaryStatusOK means no finding reached ERROR or CRITICAL.
	SummaryStatusOK

	// SummaryStatusProblemsFound means at least one finding is ERROR or CRITICAL.
	SummaryStatusProblemsFound
)

// summaryStatusNames is indexed by SummaryStatus. Keep it aligned with the const
// block above; TestSummaryStatusNamesCoverAllValues fails if the two drift.
var summaryStatusNames = [...]string{
	SummaryStatusUnspecified:   "UNSPECIFIED",
	SummaryStatusOK:            "OK",
	SummaryStatusProblemsFound: "PROBLEMS_FOUND",
}

// Valid reports whether s is a defined status. SummaryStatusUnspecified is not.
func (s SummaryStatus) Valid() bool {
	return s != SummaryStatusUnspecified && int(s) < len(summaryStatusNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (s SummaryStatus) String() string {
	if int(s) >= len(summaryStatusNames) {
		return "SummaryStatus(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return summaryStatusNames[s]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (s SummaryStatus) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("%w: SummaryStatus(%d)", ErrInvalidValue, uint8(s))
	}
	return []byte(strconv.Quote(summaryStatusNames[s])), nil
}

// SeverityCounts is how many findings a report holds at each severity.
//
// It is a struct rather than a map so that the encoded form has a fixed shape
// and a fixed field order, with no key-ordering question and no missing keys for
// a consumer to handle.
type SeverityCounts struct {
	Info     int `json:"info"`
	Warn     int `json:"warn"`
	Error    int `json:"error"`
	Critical int `json:"critical"`
}

// Total returns how many findings were counted.
func (c SeverityCounts) Total() int { return c.Info + c.Warn + c.Error + c.Critical }

// Summary aggregates a report's evidence and findings.
//
// It aggregates facts and infers nothing. Every value here is a count or a
// selection over data the report already holds; no value is a new conclusion.
// Deciding what a failure means is diagnosis, and diagnosis has already run by
// the time a summary exists.
//
// There is deliberately no exported constructor. A summary is derived by the
// report from the graph and the findings it was given. If a caller could supply
// one, a report could claim two findings while its summary counted five, and
// nothing would say which was right. See ADR 0015.
//
// The zero Summary is invalid.
type Summary struct {
	status                  SummaryStatus
	firstBrokenLayer        Layer
	findingCountsBySeverity SeverityCounts
	skippedEvidenceCount    int
	unknownEvidenceCount    int
}

// deriveSummary aggregates a frozen graph and a set of findings.
//
// The rules are exactly these, and nothing else is inferred:
//
//   - status is PROBLEMS_FOUND when any finding is ERROR or CRITICAL, otherwise OK.
//   - firstBrokenLayer is the lowest layer holding evidence in state FAIL.
//     UNKNOWN and SKIPPED are not failures, and a blocked-by reference is not a
//     failure either: it explains why a step did not run, and treating it as one
//     would manufacture the downstream failures docs/FINDINGS.md section 5 exists
//     to prevent. When several nodes fail at one layer it is still that layer.
//     When nothing failed, the layer is unset and the field is omitted.
//   - findingCountsBySeverity counts findings, not evidence.
//   - skippedEvidenceCount and unknownEvidenceCount count evidence nodes, so a
//     report where much was never checked cannot be mistaken for a clean one.
func deriveSummary(g Graph, findings []Finding) Summary {
	s := Summary{status: SummaryStatusOK}

	for _, f := range findings {
		switch f.Severity() {
		case SeverityInfo:
			s.findingCountsBySeverity.Info++
		case SeverityWarn:
			s.findingCountsBySeverity.Warn++
		case SeverityError:
			s.findingCountsBySeverity.Error++
			s.status = SummaryStatusProblemsFound
		case SeverityCritical:
			s.findingCountsBySeverity.Critical++
			s.status = SummaryStatusProblemsFound
		case SeverityUnspecified:
			// Unreachable: NewFinding rejects an unspecified severity.
		}
	}

	for _, e := range g.Nodes() {
		switch e.State() {
		case StateFail:
			if s.firstBrokenLayer == LayerUnspecified || e.Layer() < s.firstBrokenLayer {
				s.firstBrokenLayer = e.Layer()
			}
		case StateSkipped:
			s.skippedEvidenceCount++
		case StateUnknown:
			s.unknownEvidenceCount++
		case StatePass, StateDegraded:
			// Neither is a failure and neither is an unperformed check.
		}
	}

	return s
}

// Status returns the overall outcome.
func (s Summary) Status() SummaryStatus { return s.status }

// FirstBrokenLayer returns the lowest layer with positively evidenced failure,
// or LayerUnspecified when nothing failed.
func (s Summary) FirstBrokenLayer() Layer { return s.firstBrokenLayer }

// FindingCountsBySeverity returns how many findings were recorded at each severity.
func (s Summary) FindingCountsBySeverity() SeverityCounts { return s.findingCountsBySeverity }

// SkippedEvidenceCount returns how many evidence nodes were not executed.
func (s Summary) SkippedEvidenceCount() int { return s.skippedEvidenceCount }

// UnknownEvidenceCount returns how many evidence nodes could not be determined.
func (s Summary) UnknownEvidenceCount() int { return s.unknownEvidenceCount }

// IsZero reports whether s is the invalid zero Summary.
func (s Summary) IsZero() bool { return s == Summary{} }

// MarshalJSON emits the summary as an object.
//
// firstBrokenLayer is omitted when nothing failed, so an absent field means "no
// evidenced failure" rather than "failed at some unnamed layer". The counts are
// always present, because zero is a meaningful answer.
func (s Summary) MarshalJSON() ([]byte, error) {
	if !s.status.Valid() {
		return nil, fmt.Errorf("%w: summary has no status", ErrInvalidValue)
	}

	out := struct {
		Status                  SummaryStatus  `json:"status"`
		FirstBrokenLayer        *Layer         `json:"firstBrokenLayer,omitempty"`
		FindingCountsBySeverity SeverityCounts `json:"findingCountsBySeverity"`
		SkippedEvidenceCount    int            `json:"skippedEvidenceCount"`
		UnknownEvidenceCount    int            `json:"unknownEvidenceCount"`
	}{
		Status:                  s.status,
		FindingCountsBySeverity: s.findingCountsBySeverity,
		SkippedEvidenceCount:    s.skippedEvidenceCount,
		UnknownEvidenceCount:    s.unknownEvidenceCount,
	}
	if s.firstBrokenLayer.Valid() {
		out.FirstBrokenLayer = &s.firstBrokenLayer
	}

	return json.Marshal(out)
}
