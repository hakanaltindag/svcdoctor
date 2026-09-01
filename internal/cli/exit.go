package cli

import (
	"errors"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/secret"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
)

// The process status contract from docs/SCOPE.md.
//
// The report carries no exit code and never will: severity is data, and mapping
// a report to a process status is the command's job (ADR 0014). These constants
// are that mapping's whole vocabulary.
const (
	// ExitOK means a report exists, execution completed, and no ERROR or
	// CRITICAL finding was produced.
	//
	// **It does not mean a PostgreSQL session was established.** A run against
	// an endpoint demanding authentication with no credential configured exits
	// here, with a WARN finding and no session — see ADR 0046 and ADR 0048
	// section 9.
	ExitOK = 0

	// ExitProblemsFound means a report exists, execution completed, and at least
	// one finding reached ERROR or CRITICAL.
	//
	// svcdoctor worked. The problem is the target's.
	ExitProblemsFound = 1

	// ExitUsage means svcdoctor was invoked with something it cannot act on. No
	// report exists.
	ExitUsage = 2

	// ExitInternal means svcdoctor itself failed and produced no usable report.
	ExitInternal = 3

	// ExitIncomplete means a report exists but svcdoctor's own execution did not
	// finish — a cancellation, the caller's deadline, or a per-step budget
	// expiring (ADR 0047).
	//
	// It outranks ExitProblemsFound, because incompleteness qualifies every
	// conclusion in the report.
	ExitIncomplete = 4
)

// ExitCode maps one run onto a process status.
//
// It is pure, total, and the only place the mapping exists. No caller
// second-guesses it and nothing else in this package returns a bare integer.
//
// # The precedence is docs/SCOPE.md's, not this function's
//
//	3 > 2 > 4 > 1 > 0
//
// Two of those orderings are load-bearing and easy to get backwards.
//
// **4 outranks 1.** A run that was cut short and *also* found an ERROR exits 4,
// and keeps the finding in the report. The reasoning is docs/SCOPE.md's own:
// incompleteness qualifies every conclusion, so reporting the ERROR as if the
// picture were complete would overstate what was measured. This is the single
// most likely thing to implement wrongly, and TestExitCodeMatrix pins it.
//
// **2 and 3 are classified, not ranked.** They are decided by which error came
// back, so their relative order never arises at runtime; the ordering in the
// contract exists to say that a tool failure is reported as a tool failure even
// where a usage error could also be argued.
//
// # What it must never read
//
// Not a finding, not a severity, not a finding code, not the graph, not whether
// a session was established, and not how many paths were measured. Severity
// reaches this function only through Summary().Status(), which the report
// derived once from its own findings (ADR 0015) — a second severity scan here
// would be a second opinion that could disagree with the report it is describing.
//
// In particular there is **no special case for
// POSTGRES_CREDENTIAL_NOT_CONFIGURED**. It exits 0 because its report already
// says status OK and a complete run, not because this function recognizes it.
func ExitCode(result app.Result, err error) int {
	switch {
	case err == nil:
		// The ordinary path. Fall through to the report-bearing cases below.
	case errors.Is(err, ErrUsage), errors.Is(err, app.ErrInvalidInput):
		return ExitUsage
	default:
		return ExitInternal
	}

	if result.Incomplete() {
		return ExitIncomplete
	}
	if result.Report().Summary().Status() == domain.SummaryStatusProblemsFound {
		return ExitProblemsFound
	}
	return ExitOK
}

// RunExitCode maps one multi-target run onto a process status.
//
// It is pure, total, and the only place the aggregate mapping exists. It reads
// the run summary and nothing else — not a finding, not a severity, not a
// finding code, not a graph, not which targets are which service. Severity
// reaches it only through statuses the embedded reports already derived, so this
// function cannot form a second opinion that contradicts the document it is
// describing.
//
// # The vocabulary is unchanged, and no code was added
//
// docs/SCOPE.md's five codes, applied to a set (ADR 0074 section 6):
//
//	0  the run completed and no target's report reached PROBLEMS_FOUND
//	1  the run completed and at least one did
//	2  a configuration or usage error; no target was dialled
//	3  svcdoctor failed and produced no usable aggregate
//	4  an aggregate exists and the run is incomplete
//
// The precedence is docs/SCOPE.md's own, unchanged: 3 > 2 > 4 > 1 > 0.
//
// # 4 outranks 1, and that is the worked case
//
// One target with a real authentication failure, one cut short locally, one
// success, exits **4**. Incompleteness qualifies every conclusion, so reporting
// the authentication failure as though the picture were complete would overstate
// what was measured. The finding stays in the report, in full. This is the same
// ordering ExitCode already applies to a single run, and TestRunExitCodeMatrix
// pins it.
//
// # EXECUTION_FAILED contributes to 4, never to 3
//
// A single target failing locally does not make the aggregate unusable: the
// other targets were measured and their reports are truthful. Code 3 is reserved
// for the case where **no** usable aggregate exists, which is what
// docs/SCOPE.md says it means.
func RunExitCode(report domain.RunReport, err error) int {
	switch {
	case err == nil:
		// The ordinary path. Fall through to the report-bearing cases below.
	case errors.Is(err, ErrUsage), errors.Is(err, app.ErrInvalidInput),
		errors.Is(err, config.ErrConfig), errors.Is(err, secret.ErrResolution),
		errors.Is(err, services.ErrPreflight):
		// A configuration defect is a usage error: the operator wrote something
		// svcdoctor cannot act on, nothing was dialled, and no report exists.
		//
		// # services.ErrPreflight is here for the same reason as the other three
		//
		// Phase 9.2A measured a zoned host and a missing `tls.ca_file` reaching a
		// runner and surfacing as EXECUTION_FAILED / INTERNAL at exit 4 — a typo
		// reported as "svcdoctor's own invariant failed", and reported with the
		// code that tells a pipeline to retry. Both are values the operator wrote,
		// both are refused by the leaf commands at exit 2, and
		// services.PreflightAll now refuses them here before any target is
		// dialled. ADR 0077 §2.5.
		//
		// # Why a credential-reference failure belongs here and not at 3
		//
		// secret.ErrResolution reaches this function from exactly one place:
		// PreflightAll, before any target is dialled. ADR 0072 section 5 and the
		// Phase 9.0 terminology both classify that as a **configuration error** —
		// "a defect in the file or in a credential reference at preflight. Exit
		// 2, zero targets dialled, no report" — because an environment variable
		// the operator has not exported is something they wrote, not something
		// svcdoctor got wrong.
		//
		// Exit 3 means svcdoctor itself failed. Reporting a missing variable that
		// way tells a CI pipeline the tool is broken when the tool worked
		// perfectly and the environment is what is incomplete.
		//
		// The *other* ErrResolution path — a reference that resolved at preflight
		// and failed at execution — never arrives here. It is captured inside a
		// TargetResult as EXECUTION_FAILED, the run still produces an aggregate,
		// and that aggregate is what decides the code. So this branch cannot
		// swallow a genuine execution failure.
		return ExitUsage
	default:
		return ExitInternal
	}

	if report.IsZero() {
		// No aggregate and no error is a defect in the caller rather than a
		// diagnosis. Reporting it as OK would be the worst available answer.
		return ExitInternal
	}
	if report.Summary().Incomplete() {
		return ExitIncomplete
	}
	if report.Summary().Status() == domain.SummaryStatusProblemsFound {
		return ExitProblemsFound
	}
	return ExitOK
}
