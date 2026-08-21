package domain

import (
	"fmt"
	"strconv"
)

// Confidence is how strongly the evidence supports a finding.
//
// The three levels are locked by docs/REPORT_SCHEMA.md section 7.3. They are
// ordinal labels, never numbers:
//
//   - HIGH — direct, strongly matching evidence.
//   - MEDIUM — multiple consistent indirect signals.
//   - LOW — plausible, but meaningful alternative explanations remain.
//
// # Not a probability
//
// Confidence must never be expressed or rendered as a percentage, a ratio, or a
// probability. svcdoctor does not compute one, and a number would imply a
// calibration the tool cannot justify: "0.92" invites arithmetic that the
// underlying judgement does not support. The type is an enumeration precisely so
// that no arithmetic is possible on it.
//
// # Independent of Severity
//
// Confidence is epistemic strength; Severity is impact. They are deliberately
// separate enums and must not be coupled or combined into a single score.
//
// The zero Confidence is ConfidenceUnspecified, which is invalid. There is no
// honest default level of belief, so an unset value is a construction bug rather
// than a weak claim.
type Confidence uint8

const (
	// ConfidenceUnspecified is the zero value and is not a level.
	ConfidenceUnspecified Confidence = iota

	// ConfidenceLow means the claim is plausible, but meaningful alternative
	// explanations remain.
	ConfidenceLow

	// ConfidenceMedium means several consistent indirect signals agree.
	ConfidenceMedium

	// ConfidenceHigh means the evidence is direct and strongly matching.
	ConfidenceHigh
)

// confidenceNames is indexed by Confidence. Keep it aligned with the const block
// above; TestConfidenceNamesCoverAllLevels fails if the two drift apart.
var confidenceNames = [...]string{
	ConfidenceUnspecified: "UNSPECIFIED",
	ConfidenceLow:         "LOW",
	ConfidenceMedium:      "MEDIUM",
	ConfidenceHigh:        "HIGH",
}

// Valid reports whether c is a defined level. ConfidenceUnspecified is not.
func (c Confidence) Valid() bool {
	return c != ConfidenceUnspecified && int(c) < len(confidenceNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (c Confidence) String() string {
	if int(c) >= len(confidenceNames) {
		return "Confidence(" + strconv.FormatUint(uint64(c), 10) + ")"
	}
	return confidenceNames[c]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (c Confidence) MarshalJSON() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("%w: Confidence(%d)", ErrInvalidValue, uint8(c))
	}
	return []byte(strconv.Quote(confidenceNames[c])), nil
}
