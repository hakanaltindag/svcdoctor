// Package terminal renders a finished report for a person to read.
//
// It presents and does nothing else. It performs no I/O beyond the writer it is
// given, reads no environment, opens no file, chooses no exit code, applies no
// redaction and produces no finding. A depguard rule denies it the application,
// the adapters, the probes, diagnosis, security and redaction, so the boundary
// is enforced rather than remembered.
//
// # What the output has to keep apart
//
// Three facts, and collapsing any two of them publishes something false:
//
//	status      what target-side findings were proven
//	session     whether a PostgreSQL session was established
//	execution   whether svcdoctor finished measuring
//
// A run with no credential against an endpoint demanding SCRAM is `OK`, complete,
// carries a WARN, and established **no session** (ADR 0046). A run whose own
// budget expired is `OK` with nothing proven and **incomplete** (ADR 0047). A
// single word cannot say either of those, so this renderer never tries.
//
// # No colour, and nothing carried by a glyph alone
//
// Every glyph is followed by its word, so the output means the same thing piped,
// redirected, copied into a ticket, or read in a terminal that cannot draw it.
// v0.1 has no colour, no TTY detection and no width query, which is also what
// makes the bytes identical in every one of those places.
package terminal

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// Write renders one run and writes it to w.
//
// # The document is built before a byte is written
//
// A report that failed halfway through rendering must not leave half a diagnosis
// on stdout for someone to read as the whole thing, so the text is assembled in
// memory and committed once — the same discipline the JSON renderer uses, for
// the same reason.
//
// # It returns a write error and nothing else
//
// Rendering is otherwise total. An unknown step falls back to its canonical
// name, a missing optional field renders as absent, and a graph shape this
// package did not anticipate produces the rows it can rather than an error:
// refusing to render a report is worse than rendering the part that is true, and
// diagnosing a malformed graph is not a renderer's job.
func Write(w io.Writer, in render.Input) error {
	if w == nil {
		return fmt.Errorf("writing the report: no writer")
	}

	var out bytes.Buffer
	writeHeader(&out, in.Report)
	writeStages(&out, in.Report)
	writeFindings(&out, in.Report)
	writeResult(&out, in)

	if _, err := w.Write(trimTrailingSpace(out.Bytes())); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}
	return nil
}

// trimTrailingSpace removes the padding tabwriter leaves at the end of a row.
//
// Column alignment pads every cell including the last, so a row whose final
// columns are empty ends in spaces nobody can see. They make golden files fragile
// against editors that strip whitespace, they fail `git diff --check`, and they
// are invisible in the terminal — which is the worst combination for something a
// test compares byte for byte.
func trimTrailingSpace(document []byte) []byte {
	lines := bytes.Split(document, []byte("\n"))
	for i, line := range lines {
		lines[i] = bytes.TrimRight(line, " \t")
	}
	return bytes.Join(lines, []byte("\n"))
}

// writeHeader names the run and, when it applies, says the report is shareable.
//
// The shareable indicator comes from the report's own security metadata, never
// from noticing that the target looks like a pseudonym. A renderer that guessed
// from the text would label a real host named `host-001` as redacted, and would
// stay silent if redaction ever changed its pseudonym scheme.
func writeHeader(out *bytes.Buffer, report domain.Report) {
	_, _ = fmt.Fprintf(out, "svcdoctor · %s · %s\n",
		report.Run().Service(), report.Target().Requested())

	if report.Security().OutputMode() == domain.OutputModeShareableRedacted {
		_, _ = fmt.Fprint(out, "Shareable report · identities redacted\n")
	}
	_, _ = fmt.Fprintln(out)
}

// writeStages renders the logical target's stages, then each concrete path.
func writeStages(out *bytes.Buffer, report domain.Report) {
	graph := report.Graph()

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, node := range targetStages(graph) {
		writeStageRow(tw, "  ", stageLine{
			state:    stateGlyph(node.State()),
			label:    stepLabel(node.Step()),
			note:     failureNote(node),
			duration: formatDuration(node.Duration()),
		})
	}
	_ = tw.Flush()

	paths := collectPaths(graph)
	if len(paths) == 0 {
		_, _ = fmt.Fprintln(out)
		return
	}

	for _, p := range paths {
		marker := ""
		if p.continued {
			marker = " · continued"
		}
		_, _ = fmt.Fprintf(out, "\n  Path %s%s\n", p.subject.Ref(), marker)

		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		for _, line := range stageLines(p) {
			writeStageRow(tw, "    ", line)
		}
		_ = tw.Flush()
	}
	_, _ = fmt.Fprintln(out)
}

// writeStageRow emits one aligned row. Empty columns stay empty rather than
// rendering a placeholder that could be mistaken for a measurement.
func writeStageRow(tw *tabwriter.Writer, indent string, line stageLine) {
	_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%s\t%s\t\n",
		indent, line.state, line.label, line.duration, line.note)
}

// writeResult renders the three facts, separately, always.
//
// # `OK` never appears alone
//
// It always carries "no target-side error was proven", because `OK` on its own
// reads as "everything worked" and means something much narrower: no finding
// reached ERROR or CRITICAL. A reader who takes it for success on a run that
// established no session has been misled by the output rather than by the
// diagnosis (ADR 0048 section 9).
//
// # Session and execution are never omitted
//
// Not when a session was established, not when the run completed, not when there
// are no findings. A section that printed them only sometimes would make their
// absence meaningful, and a reader would have to know which absence meant what.
func writeResult(out *bytes.Buffer, in render.Input) {
	report := in.Report
	summary := report.Summary()

	_, _ = fmt.Fprintln(out, "Result")
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)

	status, gloss := "", ""
	switch summary.Status() {
	case domain.SummaryStatusOK:
		status, gloss = "OK", "no target-side error was proven"
	case domain.SummaryStatusProblemsFound:
		status = "PROBLEMS FOUND"
	default:
		status = summary.Status().String()
	}
	_, _ = fmt.Fprintf(tw, "  status\t%s\t%s\t\n", status, gloss)

	session := "NOT established"
	if sessionEstablished(report.Graph()) {
		session = "established"
	}
	_, _ = fmt.Fprintf(tw, "  session\t%s\t\t\n", session)

	execution, executionGloss := "complete", ""
	if in.Incomplete {
		execution = "INCOMPLETE"
		executionGloss = "svcdoctor did not finish the intended measurement"
	}
	_, _ = fmt.Fprintf(tw, "  execution\t%s\t%s\t\n", execution, executionGloss)

	// Only when the summary set one. A layer is the lowest that holds a FAIL
	// node; deriving one from an UNKNOWN would turn svcdoctor's own budget into
	// a claim that a layer broke.
	if layer := summary.FirstBrokenLayer(); layer != domain.LayerUnspecified {
		_, _ = fmt.Fprintf(tw, "  first break\t%s\t%s\t\n", layer.String(), layer.Label())
	}

	// **The authoritative elapsed time, from the run's own metadata.** Never the
	// sum of the stage durations: orchestration gaps sit between stages, so a
	// sum understates a real run, and on a concurrent sweep it would overstate
	// one. TestTotalDurationComesFromRunMetadata guards it.
	_, _ = fmt.Fprintf(tw, "  duration\t%s\t\t\n", formatDuration(report.Run().Duration()))
	_ = tw.Flush()
}

// indent prefixes every line of a block, so multi-line prose from a finding
// keeps its own shape without this package re-wrapping it.
//
// There is deliberately no width-aware wrapping: it would need the terminal
// width, which makes the output depend on where it was rendered and stops the
// bytes being identical piped and interactive.
func indent(text, prefix string) string {
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
