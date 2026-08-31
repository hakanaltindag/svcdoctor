package terminal

import (
	"fmt"
	"io"
	"strings"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// WriteRun presents one multi-target run.
//
// # It composes; it does not re-render
//
// Every target that produced a report is shown by Write — the same function a
// leaf command uses — so a target inside an aggregate reads exactly as it does
// on its own. What this adds is the run frame: which target each section
// belongs to, what happened to the targets that produced no report, and the
// factual counts.
//
// # What it may not do
//
// It creates no finding, computes no severity, chooses no root cause, compares
// no two targets and infers no relationship between services. There is no
// cross-target diagnosis anywhere in svcdoctor, and a renderer — which holds a
// presentation and no evidence — is the last place one could be made
// legitimately (ADR 0074 section 7.1).
//
// It also does not decide the exit code. The command does that, from the
// structured aggregate, and a renderer that recomputed it could disagree with
// the status the same run reported.
func WriteRun(w io.Writer, report domain.RunReport) error {
	if report.IsZero() {
		return fmt.Errorf("terminal: cannot render the zero RunReport")
	}

	if _, err := fmt.Fprintf(w, "svcdoctor · run · %d targets\n",
		report.Summary().Targets()); err != nil {
		return err
	}

	for _, result := range report.Targets() {
		if err := writeTargetSection(w, report, result); err != nil {
			return err
		}
	}

	return writeRunSummary(w, report)
}

// writeTargetSection renders one target, however it ended.
//
// # The three non-completed dispositions read differently on purpose
//
// ADR 0074 section 7.2 generalizes ADR 0052's rule: *not measured* is never
// collapsed into *not reached*. A target that was never started, one the run
// cancelled, and one svcdoctor could not execute are three different facts, and
// a reader who cannot tell them apart will read all three as "it is down".
func writeTargetSection(w io.Writer, report domain.RunReport, result domain.TargetResult) error {
	header := fmt.Sprintf("\n── %s · %s · %s\n",
		result.TargetID(), result.Service(), executionLabel(result.ExecutionState()))
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}

	switch result.ExecutionState() {
	case domain.ExecutionStateCompleted, domain.ExecutionStateCancelled:
		// The existing single-target renderer, unchanged, indented under its
		// heading so the aggregate frame stays visually distinct from the report.
		var buf strings.Builder
		if err := Write(&buf, render.Input{
			Report:     result.Report(),
			Incomplete: result.Incomplete(),
		}); err != nil {
			return err
		}
		// The shared indent helper trims trailing newlines, so one is restored
		// to keep the sections separated.
		if _, err := io.WriteString(w, indent(buf.String(), "  ")+"\n"); err != nil {
			return err
		}

	case domain.ExecutionStateNotStarted:
		reason := "the run ended before this target was started"
		if r := report.StoppedReason(); r != domain.StoppedReasonNone {
			reason = notStartedReason(r)
		}
		// No evidence, no findings, no result block: nothing was measured, so
		// nothing is shown. Printing an empty findings section here would invite
		// the reading that svcdoctor looked and found nothing.
		if _, err := fmt.Fprintf(w, "  not started · %s\n", reason); err != nil {
			return err
		}

	case domain.ExecutionStateExecutionFailed:
		if _, err := fmt.Fprintf(w, "  svcdoctor could not run this target · %s\n",
			result.ExecutionErrorMessage()); err != nil {
			return err
		}
		if _, err := io.WriteString(w,
			"  nothing was measured, so nothing is claimed about this endpoint\n"); err != nil {
			return err
		}

	case domain.ExecutionStateUnspecified:
		return fmt.Errorf("terminal: target %q has no execution state", result.TargetID())
	}
	return nil
}

// writeRunSummary prints the factual counts.
//
// Counts and nothing else. No target is described as healthy or unhealthy, up,
// down, reachable or available: SummaryStatus already refuses that claim four
// levels down, and a summary line that made it would be the one place svcdoctor
// says something its evidence does not support (ADR 0074 section 5.1).
func writeRunSummary(w io.Writer, report domain.RunReport) error {
	s := report.Summary()

	if _, err := io.WriteString(w, "\nRun\n"); err != nil {
		return err
	}

	rows := [][2]string{
		{"targets", fmt.Sprint(s.Targets())},
		{"completed", fmt.Sprint(s.Completed())},
	}
	// Only non-zero dispositions are listed. A run where everything completed
	// should not need a reader to scan four zeroes to see that.
	if s.NotStarted() > 0 {
		rows = append(rows, [2]string{"not started", fmt.Sprint(s.NotStarted())})
	}
	if s.Cancelled() > 0 {
		rows = append(rows, [2]string{"cancelled", fmt.Sprint(s.Cancelled())})
	}
	if s.ExecutionFailed() > 0 {
		rows = append(rows, [2]string{"execution failed", fmt.Sprint(s.ExecutionFailed())})
	}
	rows = append(rows,
		[2]string{"with problems", fmt.Sprint(s.WithProblems())},
		[2]string{"status", runStatusLabel(s)},
		[2]string{"execution", runExecutionLabel(s)},
	)
	if reason := report.StoppedReason(); reason != domain.StoppedReasonNone {
		rows = append(rows, [2]string{"stopped", stoppedLabel(reason)})
	}

	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "  %s  %s\n", row[0], row[1]); err != nil {
			return err
		}
	}
	return nil
}

// runStatusLabel states what the status means, because the word alone misleads.
//
// `OK` means no ERROR or CRITICAL finding was produced. It does not mean every
// target is healthy, and it does not mean every target ran — which is why the
// execution row sits beside it and why both must be read together.
func runStatusLabel(s domain.RunSummary) string {
	if s.Status() == domain.SummaryStatusProblemsFound {
		return fmt.Sprintf("PROBLEMS_FOUND  %d of %d targets reported a target-side problem",
			s.WithProblems(), s.Targets())
	}
	return "OK  no target-side error was proven"
}

// runExecutionLabel says whether svcdoctor finished measuring.
//
// Orthogonal to status, and printed separately for that reason: a run can be OK
// and incomplete, which is the combination an operator most needs to notice.
func runExecutionLabel(s domain.RunSummary) string {
	if !s.Incomplete() {
		return "complete"
	}
	parts := make([]string, 0, 3)
	if s.NotStarted() > 0 {
		parts = append(parts, fmt.Sprintf("%d never started", s.NotStarted()))
	}
	if s.Cancelled() > 0 {
		parts = append(parts, fmt.Sprintf("%d cancelled", s.Cancelled()))
	}
	if s.ExecutionFailed() > 0 {
		parts = append(parts, fmt.Sprintf("%d could not be run", s.ExecutionFailed()))
	}
	if s.IncompleteReports() > 0 {
		parts = append(parts, fmt.Sprintf("%d cut short", s.IncompleteReports()))
	}
	return "incomplete  " + strings.Join(parts, ", ")
}

// executionLabel names a disposition in an operator's words.
func executionLabel(state domain.ExecutionState) string {
	switch state {
	case domain.ExecutionStateCompleted:
		return "diagnosed"
	case domain.ExecutionStateNotStarted:
		return "not started"
	case domain.ExecutionStateCancelled:
		return "cancelled"
	case domain.ExecutionStateExecutionFailed:
		return "not run"
	case domain.ExecutionStateUnspecified:
		return "unknown"
	default:
		return "unknown"
	}
}

// notStartedReason explains, once per target, why scheduling never reached it.
func notStartedReason(reason domain.StoppedReason) string {
	switch reason {
	case domain.StoppedReasonRunBudgetExhausted:
		return "the run's own time budget expired before this target was started"
	case domain.StoppedReasonCancelled:
		return "the run was cancelled before this target was started"
	case domain.StoppedReasonNone:
		return "the run ended before this target was started"
	default:
		return "the run ended before this target was started"
	}
}

// stoppedLabel names why scheduling stopped.
func stoppedLabel(reason domain.StoppedReason) string {
	switch reason {
	case domain.StoppedReasonRunBudgetExhausted:
		return "the run's time budget expired; this says nothing about any target"
	case domain.StoppedReasonCancelled:
		return "cancelled; this says nothing about any target"
	case domain.StoppedReasonNone:
		return "not stopped"
	default:
		return "not stopped"
	}
}
