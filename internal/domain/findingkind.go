package domain

import (
	"fmt"
	"strconv"
)

// FindingKind says how strongly the evidence supports a finding's claim.
//
// There are exactly two kinds, locked by docs/REPORT_SCHEMA.md section 7.1.
// A hypothesis is a finding with a different kind, not a separate report type.
//
// The zero FindingKind is FindingKindUnspecified, which is invalid. Unlike an
// unset State, which honestly reads as "could not be determined", there is no
// safe default here: silently treating an unset kind as CONFIRMED would turn a
// missing decision into an assertion.
type FindingKind uint8

const (
	// FindingKindUnspecified is the zero value and is not a kind.
	FindingKindUnspecified FindingKind = iota

	// FindingKindConfirmed means the stated condition is directly supported by
	// sufficient evidence.
	//
	// It does not mean an absolute root cause has been proven. A confirmed
	// finding may establish a symptom or a condition without explaining the
	// whole incident: "this advertised endpoint is unreachable from here" can be
	// confirmed while why it is unreachable remains unknown. Root-cause language
	// stays conservative regardless of kind. See docs/FINDINGS.md section 4.
	FindingKindConfirmed

	// FindingKindHypothesis means the evidence is suggestive but realistic
	// alternative explanations remain.
	//
	// A hypothesis should say what additional evidence would settle it, which is
	// what makes it actionable rather than a hedge. See Finding.Discriminator.
	FindingKindHypothesis
)

// findingKindNames is indexed by FindingKind. Keep it aligned with the const
// block above; TestFindingKindNamesCoverAllKinds fails if the two drift apart.
var findingKindNames = [...]string{
	FindingKindUnspecified: "UNSPECIFIED",
	FindingKindConfirmed:   "CONFIRMED",
	FindingKindHypothesis:  "HYPOTHESIS",
}

// Valid reports whether k is a defined kind. FindingKindUnspecified is not.
func (k FindingKind) Valid() bool {
	return k != FindingKindUnspecified && int(k) < len(findingKindNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (k FindingKind) String() string {
	if int(k) >= len(findingKindNames) {
		return "FindingKind(" + strconv.FormatUint(uint64(k), 10) + ")"
	}
	return findingKindNames[k]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal.
func (k FindingKind) MarshalJSON() ([]byte, error) {
	if !k.Valid() {
		return nil, fmt.Errorf("%w: FindingKind(%d)", ErrInvalidValue, uint8(k))
	}
	return []byte(strconv.Quote(findingKindNames[k])), nil
}
