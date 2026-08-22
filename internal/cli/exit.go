package cli

import (
	"errors"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
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
