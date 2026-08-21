package domain

import (
	"fmt"
	"strconv"
)

// State is the outcome of one diagnostic step.
//
// The five states are locked by docs/REPORT_SCHEMA.md. UNKNOWN and SKIPPED are
// not PASS and must never be collapsed into it: "I could not measure it" and
// "it works" are different claims, and conflating them is how a diagnostic tool
// becomes untrustworthy.
//
// The zero State is StateUnknown.
type State uint8

const (
	// StateUnknown means the result could not be determined. It is the zero
	// value. Examples: svcdoctor does not support the capability, the local
	// execution budget expired before a conclusion, peer behavior was ambiguous.
	StateUnknown State = iota

	// StatePass means the checked condition was positively verified.
	StatePass

	// StateFail means failure was positively evidenced.
	StateFail

	// StateDegraded means the condition works, but a meaningful problem or
	// reduced condition was observed.
	StateDegraded

	// StateSkipped means the step was intentionally not executed. Examples: a
	// prerequisite layer failed, policy prevented execution, privilege was
	// insufficient, a scope or depth rule prevented execution.
	StateSkipped
)

// stateNames is indexed by State. Keep it aligned with the const block above;
// TestStateNamesCoverAllStates fails if the two drift apart.
var stateNames = [...]string{
	StateUnknown:  "UNKNOWN",
	StatePass:     "PASS",
	StateFail:     "FAIL",
	StateDegraded: "DEGRADED",
	StateSkipped:  "SKIPPED",
}

// Valid reports whether s is one of the five defined states.
func (s State) Valid() bool {
	return int(s) < len(stateNames)
}

// String returns the canonical symbolic name, or a Go-convention rendering of
// an out-of-range value. It never fails.
func (s State) String() string {
	if !s.Valid() {
		return "State(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return stateNames[s]
}

// MarshalJSON emits the symbolic name so that the report contract is a stable
// string rather than an enum ordinal that could shift.
func (s State) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("%w: State(%d)", ErrInvalidValue, uint8(s))
	}
	return []byte(strconv.Quote(stateNames[s])), nil
}
