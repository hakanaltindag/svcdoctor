package domain

import (
	"fmt"
	"strconv"
)

// Severity is how much a finding matters.
//
// The four levels are locked by docs/REPORT_SCHEMA.md section 7.2. Do not add
// levels without evidence from implementation.
//
// Severity is impact, not epistemic strength and not evidence state. It is
// independent of Confidence: a CRITICAL finding held with LOW confidence and a
// WARN finding held with HIGH confidence are both meaningful, and the two must
// never be collapsed into one number.
//
// Severity is also not an exit code. Mapping findings to a process exit status
// is defined in docs/SCOPE.md and belongs to the report and CLI boundary, so
// this type deliberately offers no such method.
//
// # Ordering
//
// The constants are declared in ascending order of impact, and that order is
// intentional and part of the contract: INFO < WARN < ERROR < CRITICAL. A report
// summary needs to name the highest severity present, so the values must not be
// reordered. No comparison method is provided, because Go's ordinary operators
// already work and no consumer needs more than that yet.
//
// The zero Severity is SeverityUnspecified, which is invalid. If INFO were the
// zero value, a finding whose severity was never set would silently present as
// harmless, which is the wrong direction to fail in.
type Severity uint8

const (
	// SeverityUnspecified is the zero value and is not a severity.
	SeverityUnspecified Severity = iota

	// SeverityInfo records something worth stating that needs no action.
	SeverityInfo

	// SeverityWarn records a real problem that is not currently breaking use.
	SeverityWarn

	// SeverityError records something that prevents correct use.
	SeverityError

	// SeverityCritical records an error with severe or broad impact.
	SeverityCritical
)

// severityNames is indexed by Severity. Keep it aligned with the const block
// above; TestSeverityNamesCoverAllLevels fails if the two drift apart.
var severityNames = [...]string{
	SeverityUnspecified: "UNSPECIFIED",
	SeverityInfo:        "INFO",
	SeverityWarn:        "WARN",
	SeverityError:       "ERROR",
	SeverityCritical:    "CRITICAL",
}

// Valid reports whether s is a defined level. SeverityUnspecified is not.
func (s Severity) Valid() bool {
	return s != SeverityUnspecified && int(s) < len(severityNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (s Severity) String() string {
	if int(s) >= len(severityNames) {
		return "Severity(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return severityNames[s]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (s Severity) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("%w: Severity(%d)", ErrInvalidValue, uint8(s))
	}
	return []byte(strconv.Quote(severityNames[s])), nil
}
