// Package render holds what a renderer is given.
//
// It is one type and no behaviour, on purpose. Every renderer in this repository
// takes the same input, and that input is the smallest thing that lets it
// present without becoming orchestration: the report to show, and the one run
// fact that is deliberately not in it.
package render

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// Input is one finished run, as a renderer sees it.
//
// # Why the report is already projected
//
// The command chooses between the truthful LOCAL_FULL report and the
// SHAREABLE_REDACTED derivative *before* a renderer runs, so a renderer receives
// whichever was selected and cannot tell the difference except by reading the
// report's own security metadata. That is what keeps redaction a single
// transformation at the output boundary rather than a thing each renderer might
// do differently (ADR 0018, ADR 0048 section 6).
//
// # Why Incomplete travels beside the report rather than inside it
//
// A report cannot observe its own partiality — docs/REPORT_SCHEMA.md section 8
// keeps exit codes 2, 3 and 4 out of the summary for exactly that reason — so
// whether svcdoctor finished measuring is a fact about the *run*, held by
// app.Result and passed here as presentation metadata.
//
// A renderer must not re-derive it by scanning the graph for UNKNOWN nodes. The
// predicate that produces it is more than that (ADR 0047): a passing session
// settles the question even when another path ended on a local budget, and a
// cancellation after everything succeeded still counts. A renderer that
// recomputed it would disagree with the exit code the same run produced.
//
// # What is deliberately absent
//
// No app.Result, no credential, no CLI parameters, no redaction configuration,
// no adapter state and no error. A renderer that held any of them could
// reintroduce an identity the redaction step removed, or start deciding
// something that is not presentation.
type Input struct {
	// Report is the projection to present, already chosen by the command.
	Report domain.Report

	// Incomplete reports that svcdoctor's own execution limit stopped the run
	// short of what it set out to measure.
	Incomplete bool
}
