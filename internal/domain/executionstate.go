package domain

import (
	"fmt"
	"strconv"
)

// ExecutionState is how orchestration disposed of one target.
//
// # It is not State, and the difference is the whole point
//
// State — PASS, FAIL, DEGRADED, UNKNOWN, SKIPPED — describes a measurement.
// This describes what the runner did with a target, and the two are orthogonal:
//
//	ExecutionState = COMPLETED   and   the report contains FAIL
//
// is the ordinary outcome of a successful diagnosis of a broken endpoint.
// svcdoctor did its job; the target has a problem. Merging the vocabularies, or
// letting either borrow the other's words, would destroy exactly that
// distinction — so a target is never `FAILED` at run level and never
// `NOT_STARTED` at evidence level (ADR 0074 section 4.1).
//
// # Why four, and not six
//
// ADR 0074 section 4.3 declined to split NOT_STARTED by reason. A run stops
// scheduling once, for one reason, and recording that reason on each of four
// hundred queued targets is four hundred copies of a single fact. It is recorded
// once, as the run's StoppedReason.
//
// The zero ExecutionState is ExecutionStateUnspecified and is not a state.
type ExecutionState uint8

const (
	// ExecutionStateUnspecified is the zero value and is not a state.
	ExecutionStateUnspecified ExecutionState = iota

	// ExecutionStateCompleted means the runner called the composition root and
	// it returned a report. It says nothing about what the report contains.
	ExecutionStateCompleted

	// ExecutionStateNotStarted means the runner never called it. The target
	// acquires no evidence graph at all: nothing was measured, so nothing is
	// recorded (ADR 0073 section 5).
	ExecutionStateNotStarted

	// ExecutionStateCancelled means the target was called and the **run** ended
	// it — the run deadline or a signal. Whatever its composition root returned
	// is kept.
	//
	// A target cut short by its *own* budget is ExecutionStateCompleted: it ran
	// to the end of its own budget and produced its own truthful incomplete
	// report, which is the report's business rather than orchestration's.
	ExecutionStateCancelled

	// ExecutionStateExecutionFailed means the target was called and returned an
	// error, or could not be called at all.
	//
	// It is svcdoctor's own failure, never the target's. A credential that could
	// not be resolved lands here and is not an authentication rejection.
	ExecutionStateExecutionFailed
)

// executionStateNames is indexed by ExecutionState. Keep it aligned with the
// const block above; TestExecutionStateNamesCoverAllValues fails if the two drift.
var executionStateNames = [...]string{
	ExecutionStateUnspecified:     "UNSPECIFIED",
	ExecutionStateCompleted:       "COMPLETED",
	ExecutionStateNotStarted:      "NOT_STARTED",
	ExecutionStateCancelled:       "CANCELLED",
	ExecutionStateExecutionFailed: "EXECUTION_FAILED",
}

// Valid reports whether s is a defined state. ExecutionStateUnspecified is not.
func (s ExecutionState) Valid() bool {
	return s != ExecutionStateUnspecified && int(s) < len(executionStateNames)
}

// String returns the symbolic name, or a Go-convention rendering of an
// out-of-range value. It never fails.
func (s ExecutionState) String() string {
	if int(s) >= len(executionStateNames) {
		return "ExecutionState(" + strconv.FormatUint(uint64(s), 10) + ")"
	}
	return executionStateNames[s]
}

// MarshalJSON emits the symbolic name so the contract is a stable string.
func (s ExecutionState) MarshalJSON() ([]byte, error) {
	if !s.Valid() {
		return nil, fmt.Errorf("%w: ExecutionState(%d)", ErrInvalidValue, uint8(s))
	}
	return []byte(strconv.Quote(executionStateNames[s])), nil
}

// ExecutionErrorClass is why svcdoctor could not produce a report for a target.
//
// Two members, because configuration errors never reach execution at all —
// ADR 0074 section 9 requires a whole configuration to validate before any
// target is dialled, so the only failures reachable here are svcdoctor-local
// ones during a run.
//
// The zero ExecutionErrorClass is ExecutionErrorUnspecified and is not a class.
type ExecutionErrorClass uint8

const (
	// ExecutionErrorUnspecified is the zero value and is not a class.
	ExecutionErrorUnspecified ExecutionErrorClass = iota

	// ExecutionErrorCredentialResolution means the credential reference was well
	// formed and preflighted, and the material behind it could not be obtained
	// when the target ran.
	//
	// **This is not an authentication rejection.** No byte reached the endpoint,
	// so nothing was learned about it, and no service finding may describe it.
	ExecutionErrorCredentialResolution

	// ExecutionErrorInternal means a composition root returned an error instead
	// of a report, which means one of svcdoctor's own invariants failed.
	ExecutionErrorInternal
)

// executionErrorClassNames is indexed by ExecutionErrorClass.
//
// CREDENTIAL_RESOLUTION classifies a credential svcdoctor could *not* obtain;
// this package holds no credential at all and imports nothing that defines one.
//
//nolint:gosec // G101: these are the names of execution-error classes.
var executionErrorClassNames = [...]string{
	ExecutionErrorUnspecified:          "UNSPECIFIED",
	ExecutionErrorCredentialResolution: "CREDENTIAL_RESOLUTION",
	ExecutionErrorInternal:             "INTERNAL",
}

// Valid reports whether c is a defined class.
func (c ExecutionErrorClass) Valid() bool {
	return c != ExecutionErrorUnspecified && int(c) < len(executionErrorClassNames)
}

// String returns the symbolic name. It never fails.
func (c ExecutionErrorClass) String() string {
	if int(c) >= len(executionErrorClassNames) {
		return "ExecutionErrorClass(" + strconv.FormatUint(uint64(c), 10) + ")"
	}
	return executionErrorClassNames[c]
}

// MarshalJSON emits the symbolic name.
func (c ExecutionErrorClass) MarshalJSON() ([]byte, error) {
	if !c.Valid() {
		return nil, fmt.Errorf("%w: ExecutionErrorClass(%d)", ErrInvalidValue, uint8(c))
	}
	return []byte(strconv.Quote(executionErrorClassNames[c])), nil
}

// StoppedReason is why a run stopped scheduling before every target started.
//
// Recorded once, on the run, rather than on each queued target — ADR 0074
// section 4.3. A reader who wants to know why a particular target never ran
// reads it here, and every NOT_STARTED target says the same thing about itself,
// which is what a closed vocabulary should do.
//
// The zero StoppedReason is StoppedReasonNone, which is valid and means the run
// scheduled everything it had.
type StoppedReason uint8

const (
	// StoppedReasonNone means scheduling was not cut short. It is the zero value
	// and the ordinary case.
	StoppedReasonNone StoppedReason = iota

	// StoppedReasonRunBudgetExhausted means the run's own deadline passed.
	StoppedReasonRunBudgetExhausted

	// StoppedReasonCancelled means the caller cancelled the run — an operator's
	// interrupt, or a context the CLI was handed.
	StoppedReasonCancelled
)

// stoppedReasonNames is indexed by StoppedReason.
var stoppedReasonNames = [...]string{
	StoppedReasonNone:               "NONE",
	StoppedReasonRunBudgetExhausted: "RUN_BUDGET_EXHAUSTED",
	StoppedReasonCancelled:          "CANCELLED",
}

// Valid reports whether r is a defined reason. StoppedReasonNone is valid.
func (r StoppedReason) Valid() bool { return int(r) < len(stoppedReasonNames) }

// String returns the symbolic name. It never fails.
func (r StoppedReason) String() string {
	if int(r) >= len(stoppedReasonNames) {
		return "StoppedReason(" + strconv.FormatUint(uint64(r), 10) + ")"
	}
	return stoppedReasonNames[r]
}

// MarshalJSON emits the symbolic name.
func (r StoppedReason) MarshalJSON() ([]byte, error) {
	if !r.Valid() {
		return nil, fmt.Errorf("%w: StoppedReason(%d)", ErrInvalidValue, uint8(r))
	}
	return []byte(strconv.Quote(stoppedReasonNames[r])), nil
}
