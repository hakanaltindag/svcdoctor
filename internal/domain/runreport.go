package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// RunSchemaVersion is the version of the aggregate document this package
// produces.
//
// # It is not SchemaVersion, and must never be derived from it
//
// Two documents, two version numbers, two lifecycles. SchemaVersion describes
// one target's canonical report; this describes the document that wraps many of
// them. Coupling them would mean a change to one forced a version bump in the
// other, telling consumers their parsers were obsolete when nothing they read
// had changed (ADR 0074 section 3).
//
// **Adding this constant does not change SchemaVersion**, which stays 1. The
// single-target report gains no field, not even a kind discriminator: making a
// *different* document identifiable is not a cost every existing consumer should
// pay.
const RunSchemaVersion = 1

// RunKind identifies the aggregate document.
//
// It exists on this document and on no other. A consumer distinguishes an
// aggregate from a single-target report by its presence, which is why the
// single-target report needed no corresponding field.
const RunKind = "run"

// ErrInvalidRunReport reports that an aggregate's parts do not agree.
var ErrInvalidRunReport = errors.New("invalid run report")

// TargetResult is what one target's execution produced.
//
// # The presence rules are invariants, not conventions
//
//	COMPLETED         report,    no error
//	CANCELLED         report,    no error
//	NOT_STARTED       neither
//	EXECUTION_FAILED  no report, an error
//
// NewTargetResult refuses every other combination, so a result claiming a target
// never started while carrying its report is unconstructable rather than merely
// unexpected.
//
// # What it deliberately does not carry
//
// No credential, no credential reference, no environment variable name, no
// secret file path, no configuration and no service parameters. ADR 0074
// section 8.3 keeps all of those out of the canonical report, and the way that
// holds is that there is no field to put them in.
//
// The zero TargetResult is invalid.
type TargetResult struct {
	targetID   string
	service    ServiceID
	state      ExecutionState
	report     Report
	incomplete bool
	errClass   ExecutionErrorClass
	errMessage string
}

// CompletedTarget records a target whose composition root returned a report.
//
// incomplete is that run's own Result.Incomplete(). It travels beside the report
// rather than inside it for the reason render.Input already gives: a report
// cannot observe its own partiality, so whether svcdoctor finished measuring is
// a fact about the run and is held next to it.
func CompletedTarget(
	targetID string, service ServiceID, report Report, incomplete bool,
) (TargetResult, error) {
	return reportBearingTarget(targetID, service, ExecutionStateCompleted, report, incomplete)
}

// CancelledTarget records a target the run ended while it was in flight.
//
// It carries a report because a cancelled composition root still returns one:
// the transport chain records what it measured, the graph is frozen, diagnosis
// runs over it, and Incomplete is true. Discarding that would throw away
// measurements that were made.
func CancelledTarget(
	targetID string, service ServiceID, report Report, incomplete bool,
) (TargetResult, error) {
	return reportBearingTarget(targetID, service, ExecutionStateCancelled, report, incomplete)
}

func reportBearingTarget(
	targetID string, service ServiceID, state ExecutionState, report Report, incomplete bool,
) (TargetResult, error) {
	if err := checkTargetIdentity(targetID, service); err != nil {
		return TargetResult{}, err
	}
	if report.IsZero() {
		return TargetResult{}, fmt.Errorf(
			"%w: a %s target requires a report", ErrInvalidRunReport, state)
	}
	return TargetResult{
		targetID:   targetID,
		service:    service,
		state:      state,
		report:     report,
		incomplete: incomplete,
	}, nil
}

// NotStartedTarget records a target the runner never called.
//
// It carries no report, and that is the contract rather than an omission.
// ADR 0073 section 5: nothing was measured, so nothing is recorded — the same
// reasoning ADR 0059 applies to an address literal, where absence is the
// truthful representation because every state a node can carry describes how an
// operation went, and none of them means "there was nothing to attempt".
func NotStartedTarget(targetID string, service ServiceID) (TargetResult, error) {
	if err := checkTargetIdentity(targetID, service); err != nil {
		return TargetResult{}, err
	}
	return TargetResult{
		targetID: targetID,
		service:  service,
		state:    ExecutionStateNotStarted,
	}, nil
}

// FailedTarget records a target svcdoctor could not execute.
//
// message must already be safe to serialize: no secret, no credential reference
// name, no file path. This constructor cannot check that — a string is a string
// — so the guarantee lives with the caller and is proven by canary tests over
// every rendered surface.
func FailedTarget(
	targetID string, service ServiceID, class ExecutionErrorClass, message string,
) (TargetResult, error) {
	if err := checkTargetIdentity(targetID, service); err != nil {
		return TargetResult{}, err
	}
	if !class.Valid() {
		return TargetResult{}, fmt.Errorf(
			"%w: execution error class %s", ErrInvalidRunReport, class)
	}
	if message == "" {
		return TargetResult{}, fmt.Errorf(
			"%w: a failed target requires a message", ErrInvalidRunReport)
	}
	return TargetResult{
		targetID:   targetID,
		service:    service,
		state:      ExecutionStateExecutionFailed,
		errClass:   class,
		errMessage: message,
	}, nil
}

func checkTargetIdentity(targetID string, service ServiceID) error {
	if targetID == "" {
		return fmt.Errorf("%w: a target result requires a target id", ErrInvalidRunReport)
	}
	if !service.Valid() {
		return fmt.Errorf("%w: service id %q", ErrInvalidRunReport, service)
	}
	return nil
}

// TargetID returns the identifier the operator wrote.
func (r TargetResult) TargetID() string { return r.targetID }

// Service returns which service was inspected.
func (r TargetResult) Service() ServiceID { return r.service }

// ExecutionState returns how orchestration disposed of this target.
func (r TargetResult) ExecutionState() ExecutionState { return r.state }

// Report returns the canonical report, which is the zero Report when there is none.
func (r TargetResult) Report() Report { return r.report }

// HasReport reports whether a report exists.
func (r TargetResult) HasReport() bool { return !r.report.IsZero() }

// Incomplete reports whether svcdoctor's own execution limit stopped this
// target short. It is meaningful only when a report exists.
func (r TargetResult) Incomplete() bool { return r.incomplete }

// ExecutionErrorClass returns the closed classification, or the unspecified
// class when the target did not fail locally.
func (r TargetResult) ExecutionErrorClass() ExecutionErrorClass { return r.errClass }

// ExecutionErrorMessage returns the safe message, or the empty string.
func (r TargetResult) ExecutionErrorMessage() string { return r.errMessage }

// HasProblems reports whether this target's report reached PROBLEMS_FOUND.
//
// It is a fold over a status the report already derived, never a fresh severity
// scan: a second opinion here could contradict the report it is describing,
// which is the failure ADR 0015 exists to prevent.
func (r TargetResult) HasProblems() bool {
	return r.HasReport() && r.report.Summary().Status() == SummaryStatusProblemsFound
}

// IsZero reports whether r is the invalid zero TargetResult.
func (r TargetResult) IsZero() bool { return r.state == ExecutionStateUnspecified }

// RunSummary aggregates a run's target results.
//
// Every value is a count or a fold over data the aggregate already holds. There
// is deliberately no exported constructor: a summary is derived by the run
// report from the results it was given, so it cannot claim two completed targets
// while the list holds five (ADR 0015, applied one level up).
//
// The zero RunSummary is invalid.
type RunSummary struct {
	targets           int
	completed         int
	notStarted        int
	cancelled         int
	executionFailed   int
	withProblems      int
	incompleteReports int
	status            SummaryStatus
	incomplete        bool
}

// deriveRunSummary counts a finished run.
//
// # The words that are absent
//
// No target is counted as healthy or unhealthy, up, down, reachable or
// available. SummaryStatus already says why: OK means exactly that no finding
// reached ERROR or CRITICAL, and it does not mean the target is healthy. A run
// summary that said "3 services healthy" would make a claim the underlying
// report explicitly refuses to make, four levels down (ADR 0074 section 5.1).
func deriveRunSummary(results []TargetResult) RunSummary {
	s := RunSummary{targets: len(results), status: SummaryStatusOK}

	for _, result := range results {
		switch result.ExecutionState() {
		case ExecutionStateCompleted:
			s.completed++
		case ExecutionStateNotStarted:
			s.notStarted++
			s.incomplete = true
		case ExecutionStateCancelled:
			s.cancelled++
			s.incomplete = true
		case ExecutionStateExecutionFailed:
			s.executionFailed++
			s.incomplete = true
		case ExecutionStateUnspecified:
			// Unreachable: every constructor sets a state.
		}

		if result.HasProblems() {
			s.withProblems++
			s.status = SummaryStatusProblemsFound
		}
		if result.HasReport() && result.Incomplete() {
			s.incompleteReports++
			s.incomplete = true
		}
	}

	return s
}

// Targets returns how many targets the configuration declared.
func (s RunSummary) Targets() int { return s.targets }

// Completed returns how many targets produced a report normally.
func (s RunSummary) Completed() int { return s.completed }

// NotStarted returns how many targets were never called.
func (s RunSummary) NotStarted() int { return s.notStarted }

// Cancelled returns how many in-flight targets the run ended.
func (s RunSummary) Cancelled() int { return s.cancelled }

// ExecutionFailed returns how many targets svcdoctor could not execute.
func (s RunSummary) ExecutionFailed() int { return s.executionFailed }

// WithProblems returns how many targets' reports reached PROBLEMS_FOUND.
func (s RunSummary) WithProblems() int { return s.withProblems }

// IncompleteReports returns how many targets were cut short by an execution budget.
func (s RunSummary) IncompleteReports() int { return s.incompleteReports }

// Status returns PROBLEMS_FOUND when any target's report did, otherwise OK.
func (s RunSummary) Status() SummaryStatus { return s.status }

// Incomplete reports that the run did not measure everything it set out to.
//
// It is orthogonal to Status, exactly as Result.Incomplete() is orthogonal to a
// single report's status. A run can be OK and incomplete, PROBLEMS_FOUND and
// complete, or either and neither.
func (s RunSummary) Incomplete() bool { return s.incomplete }

// IsZero reports whether s is the invalid zero RunSummary.
func (s RunSummary) IsZero() bool { return s == RunSummary{} }

// MarshalJSON emits the summary as an object with a fixed shape.
func (s RunSummary) MarshalJSON() ([]byte, error) {
	if !s.status.Valid() {
		return nil, fmt.Errorf("%w: run summary has no status", ErrInvalidValue)
	}
	return json.Marshal(struct {
		Targets           int           `json:"targets"`
		Completed         int           `json:"completed"`
		NotStarted        int           `json:"notStarted"`
		Cancelled         int           `json:"cancelled"`
		ExecutionFailed   int           `json:"executionFailed"`
		WithProblems      int           `json:"withProblems"`
		IncompleteReports int           `json:"incompleteReports"`
		Status            SummaryStatus `json:"status"`
		Incomplete        bool          `json:"incomplete"`
	}{
		Targets:           s.targets,
		Completed:         s.completed,
		NotStarted:        s.notStarted,
		Cancelled:         s.cancelled,
		ExecutionFailed:   s.executionFailed,
		WithProblems:      s.withProblems,
		IncompleteReports: s.incompleteReports,
		Status:            s.status,
		Incomplete:        s.incomplete,
	})
}

// RunReportInput carries the values NewRunReport validates and assembles.
//
// There is deliberately no Summary field, for ADR 0015's reason one level up.
type RunReportInput struct {
	// SvcdoctorVersion is the version that produced the aggregate. Required.
	SvcdoctorVersion string

	// StartedAt is when the run began. Required; normalized to UTC.
	StartedAt time.Time

	// Duration is how long the run took.
	Duration time.Duration

	// Concurrency is how many targets ran at once. Required, at least 1.
	Concurrency int

	// OutputMode records whether this is the truthful local document or the
	// shareable derivative. Required.
	OutputMode OutputMode

	// StoppedReason records why scheduling stopped, or None.
	StoppedReason StoppedReason

	// Targets are the results, in declared configuration order. Required.
	//
	// The slice is copied and **never reordered**: ADR 0073 section 6 makes
	// declared order the contract, and a constructor that sorted would be the
	// one place a later reader could not see it happening.
	Targets []TargetResult
}

// RunReport is the canonical result of one multi-target run.
//
// It wraps target reports and never merges them. Each embedded Report is the
// value its composition root produced — same fields, same order, same
// schemaVersion 1 — so a consumer that parses svcdoctor reports today parses
// targets[i].report with no change (ADR 0074 section 2.1).
//
// # What it does not do
//
// It diagnoses nothing. It creates no finding, compares no two targets, infers
// no relationship between services and computes no root cause. There is no
// cross-target diagnosis anywhere in svcdoctor, and this type is where someone
// would most plausibly add one.
//
// It performs no redaction. internal/security/redaction derives a shareable
// aggregate; this type refuses to claim one it was not given.
//
// The zero RunReport is invalid. Use NewRunReport.
type RunReport struct {
	svcdoctorVersion string
	startedAt        time.Time
	duration         time.Duration
	concurrency      int
	outputMode       OutputMode
	stoppedReason    StoppedReason
	targets          []TargetResult
	summary          RunSummary
}

// NewRunReport validates in, derives the summary and returns the aggregate.
func NewRunReport(in RunReportInput) (RunReport, error) {
	if err := validateIdentifier("svcdoctor version", in.SvcdoctorVersion); err != nil {
		return RunReport{}, err
	}
	if in.StartedAt.IsZero() {
		return RunReport{}, fmt.Errorf("%w: a run requires a start time", ErrInvalidValue)
	}
	if in.Duration < 0 {
		return RunReport{}, fmt.Errorf(
			"%w: run duration %s must not be negative", ErrInvalidValue, in.Duration)
	}
	if in.Concurrency < 1 {
		return RunReport{}, fmt.Errorf(
			"%w: run concurrency %d must be at least 1", ErrInvalidValue, in.Concurrency)
	}
	if !in.OutputMode.Valid() {
		return RunReport{}, fmt.Errorf("%w: output mode %s", ErrInvalidValue, in.OutputMode)
	}
	if !in.StoppedReason.Valid() {
		return RunReport{}, fmt.Errorf("%w: stopped reason %s", ErrInvalidValue, in.StoppedReason)
	}
	if len(in.Targets) == 0 {
		return RunReport{}, fmt.Errorf(
			"%w: a run report requires at least one target result", ErrInvalidRunReport)
	}

	seen := make(map[string]struct{}, len(in.Targets))
	for _, result := range in.Targets {
		if result.IsZero() {
			return RunReport{}, fmt.Errorf(
				"%w: a target result has no execution state", ErrInvalidRunReport)
		}
		if _, duplicate := seen[result.TargetID()]; duplicate {
			return RunReport{}, fmt.Errorf(
				"%w: target id %q appears twice", ErrInvalidRunReport, result.TargetID())
		}
		seen[result.TargetID()] = struct{}{}
	}

	targets := slices.Clone(in.Targets)
	return RunReport{
		svcdoctorVersion: in.SvcdoctorVersion,
		startedAt:        in.StartedAt.UTC(),
		duration:         in.Duration,
		concurrency:      in.Concurrency,
		outputMode:       in.OutputMode,
		stoppedReason:    in.StoppedReason,
		targets:          targets,
		summary:          deriveRunSummary(targets),
	}, nil
}

// SvcdoctorVersion returns the version that produced the aggregate.
func (r RunReport) SvcdoctorVersion() string { return r.svcdoctorVersion }

// StartedAt returns when the run began, in UTC.
func (r RunReport) StartedAt() time.Time { return r.startedAt }

// Duration returns how long the run took.
func (r RunReport) Duration() time.Duration { return r.duration }

// Concurrency returns how many targets ran at once.
func (r RunReport) Concurrency() int { return r.concurrency }

// OutputMode returns whether this is the local or the shareable document.
func (r RunReport) OutputMode() OutputMode { return r.outputMode }

// StoppedReason returns why scheduling stopped, or StoppedReasonNone.
func (r RunReport) StoppedReason() StoppedReason { return r.stoppedReason }

// Targets returns the results in declared configuration order.
func (r RunReport) Targets() []TargetResult { return slices.Clone(r.targets) }

// Summary returns the derived counts.
func (r RunReport) Summary() RunSummary { return r.summary }

// IsZero reports whether r is the invalid zero RunReport.
func (r RunReport) IsZero() bool { return r.svcdoctorVersion == "" && len(r.targets) == 0 }

// runSectionJSON is the wire shape of the run block.
type runReportRunJSON struct {
	SvcdoctorVersion string         `json:"svcdoctorVersion"`
	StartedAt        string         `json:"startedAt"`
	Duration         string         `json:"duration"`
	Concurrency      int            `json:"concurrency"`
	OutputMode       OutputMode     `json:"outputMode"`
	StoppedReason    *StoppedReason `json:"stoppedReason,omitempty"`
}

// targetResultJSON is the wire shape of one target result.
//
// report, incomplete and executionError are pointers so that each is **absent**
// rather than zero when it does not apply. A consumer reading `"report": null`
// on a never-started target would have to know that null means "not measured";
// an absent key says it structurally.
type targetResultJSON struct {
	TargetID       string              `json:"targetId"`
	Service        ServiceID           `json:"service"`
	ExecutionState ExecutionState      `json:"executionState"`
	Report         *Report             `json:"report,omitempty"`
	Incomplete     *bool               `json:"incomplete,omitempty"`
	ExecutionError *executionErrorJSON `json:"executionError,omitempty"`
}

type executionErrorJSON struct {
	Class   ExecutionErrorClass `json:"class"`
	Message string              `json:"message"`
}

// MarshalJSON emits one target result.
func (r TargetResult) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: zero TargetResult", ErrInvalidValue)
	}

	out := targetResultJSON{
		TargetID:       r.targetID,
		Service:        r.service,
		ExecutionState: r.state,
	}
	if r.HasReport() {
		report := r.report
		incomplete := r.incomplete
		out.Report = &report
		out.Incomplete = &incomplete
	}
	if r.errClass.Valid() {
		out.ExecutionError = &executionErrorJSON{Class: r.errClass, Message: r.errMessage}
	}
	return json.Marshal(out)
}

// runReportJSON is the wire shape of the aggregate.
type runReportJSON struct {
	SchemaVersion int              `json:"schemaVersion"`
	Kind          string           `json:"kind"`
	Run           runReportRunJSON `json:"run"`
	Targets       []TargetResult   `json:"targets"`
	Summary       RunSummary       `json:"summary"`
}

// MarshalJSON emits the canonical aggregate.
//
// The encoding is deterministic: targets follow declared configuration order, no
// map is iterated, and each embedded report serializes through its own
// deterministic MarshalJSON. The same content always produces the same bytes
// apart from the run's own start time and duration, which are measurements.
func (r RunReport) MarshalJSON() ([]byte, error) {
	if r.IsZero() {
		return nil, fmt.Errorf("%w: zero RunReport", ErrInvalidValue)
	}

	run := runReportRunJSON{
		SvcdoctorVersion: r.svcdoctorVersion,
		StartedAt:        r.startedAt.Format(time.RFC3339Nano),
		Duration:         r.duration.String(),
		Concurrency:      r.concurrency,
		OutputMode:       r.outputMode,
	}
	// Omitted when scheduling ran to completion, so an absent key means "nothing
	// cut this run short" rather than "some unnamed reason".
	if r.stoppedReason != StoppedReasonNone {
		reason := r.stoppedReason
		run.StoppedReason = &reason
	}

	return json.Marshal(runReportJSON{
		SchemaVersion: RunSchemaVersion,
		Kind:          RunKind,
		Run:           run,
		Targets:       r.targets,
		Summary:       r.summary,
	})
}
