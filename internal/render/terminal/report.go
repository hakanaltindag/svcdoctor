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

	view := viewFor(in.Report)

	var out bytes.Buffer
	writeHeader(&out, in.Report)
	writeStages(&out, in.Report, view)
	writeFindings(&out, in.Report)
	writeResult(&out, in, view)

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

// writeHeader names the run and states the security facts that qualify all of it.
//
// # Both indicators come from the report's own security metadata
//
// Never from noticing that the target looks like a pseudonym, and never from a
// flag: a renderer that guessed from the text would label a real host named
// `host-001` as redacted, and would stay silent if redaction ever changed its
// pseudonym scheme. `security` is the one authority, which is also what makes
// the text and the canonical JSON incapable of disagreeing.
//
// # Why disabled verification belongs in the header
//
// It qualifies every row below it, so it cannot sit beside any one of them.
// Before Phase 6.8A the terminal said nothing at all, and two runs — one that
// verified the peer's certificate against a supplied CA, one that verified
// nothing — rendered byte-for-byte identically down to `✓ PASS  TLS`. Nothing in
// that document was false and the impression it left was, which is the same
// failure ADR 0048 section 9 fixed for a bare `OK`.
//
// **It is not a finding and not a failure.** The operator asked for this, the
// endpoint did nothing wrong, the status stays `OK` and the exit code is
// unchanged. What it says is what an unverified handshake actually proves: the
// channel is encrypted, and nobody established who is on the other end of it.
// ADR 0060 section 6 records why an ERROR finding was declined.
func writeHeader(out *bytes.Buffer, report domain.Report) {
	_, _ = fmt.Fprintf(out, "svcdoctor · %s · %s\n",
		report.Run().Service(), report.Target().Requested())

	if report.Security().OutputMode() == domain.OutputModeShareableRedacted {
		_, _ = fmt.Fprint(out, "Shareable report · identities redacted\n")
	}
	// After the shareable banner, and on its own line. A shared report keeps it:
	// the fact qualifies the diagnosis, and a reader who was not at the terminal
	// is exactly the reader who cannot otherwise know.
	if report.Security().TLSVerificationDisabled() {
		_, _ = fmt.Fprint(out,
			"Peer verification disabled · TLS proves the channel is encrypted, not who answered\n")
	}
	_, _ = fmt.Fprintln(out)
}

// writeStages renders the logical target, its bootstrap paths, and then the
// topology those paths discovered.
//
// # Three levels, and the third is what Kafka needed
//
//	target        the requested name and its resolution
//	  path        one concrete address the operator's endpoint resolved to
//	    stage     what was measured over it
//	advertised    one endpoint the cluster named
//	  path        one concrete address that name resolved to
//	    stage     what was measured over it
//
// The two `path` levels look alike and mean different things, and that is
// exactly why they are rendered apart rather than as siblings. A bootstrap path
// is an address for the endpoint the operator asked about; an advertised path is
// an address for an endpoint a peer named, which svcdoctor measures at transport
// and never authenticates (ADR 0050). Presenting them in one list would say the
// operator asked about a broker they have never heard of.
//
// A service with no advertisement step renders the first two levels and nothing
// else, byte for byte as before.
func writeStages(out *bytes.Buffer, report domain.Report, view serviceView) {
	graph := report.Graph()

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, node := range targetStages(graph, view) {
		writeStageRow(tw, "  ", stageLine{
			state:    stateGlyph(node.State()),
			label:    stepLabel(node.Step()),
			note:     failureNote(node),
			duration: formatElapsed(node.Elapsed()),
		})
	}
	_ = tw.Flush()

	paths := collectPaths(graph, view)
	advertisements := collectAdvertisements(graph, view)

	if len(paths) == 0 && len(advertisements) == 0 {
		_, _ = fmt.Fprintln(out)
		return
	}

	for _, p := range paths {
		writePath(out, p, view, "  ")
	}
	writeAdvertisements(out, advertisements, view)
	_, _ = fmt.Fprintln(out)
}

// writePath renders one concrete attempt and its stages.
func writePath(out *bytes.Buffer, p path, view serviceView, indent string) {
	marker := ""
	if p.continued {
		marker = " · continued"
	}
	_, _ = fmt.Fprintf(out, "\n%sPath %s%s\n", indent, p.subject.Ref(), marker)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, line := range stageLines(p, view) {
		writeStageRow(tw, indent+"  ", line)
	}
	_ = tw.Flush()
}

// writeAdvertisements renders the topology the run discovered.
//
// # Each advertisement carries enough context to correlate, and no more
//
// The heading names the service's own identifier for the peer — Kafka's broker
// node id — beside the endpoint subject. Both survive redaction: the node id
// names a position in a cluster rather than a host, and the subject is a
// pseudonym in a shareable report. **No EvidenceID is printed**, here or
// anywhere: identifiers are the machine surface and belong to the JSON.
//
// # What never appears beneath one
//
// An authentication row. A discovered endpoint receives credential-free DNS, TCP
// and TLS and nothing else (ADR 0050), so a credential or authentication stage
// under an advertisement would mean the sweep had grown a second hop. This
// renderer does not filter such a row out — it renders what the graph holds, and
// a test asserts the graph never holds one, because hiding it would conceal the
// security failure instead of reporting it.
func writeAdvertisements(out *bytes.Buffer, advertisements []advertisement, view serviceView) {
	for _, a := range advertisements {
		_, _ = fmt.Fprintf(out, "\n  %s\n", advertisementHeading(a, view))

		tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		writeStageRow(tw, "    ", stageLine{
			state:    stateGlyph(a.node.State()),
			label:    stepLabel(a.node.Step()),
			note:     failureNote(a.node),
			duration: formatElapsed(a.node.Elapsed()),
		})
		if a.hasLookup {
			writeStageRow(tw, "    ", stageLine{
				state:    stateGlyph(a.lookup.State()),
				label:    stepLabel(a.lookup.Step()),
				note:     failureNote(a.lookup),
				duration: formatElapsed(a.lookup.Elapsed()),
			})
		}
		_ = tw.Flush()

		for _, p := range a.paths {
			writePath(out, p, advertisedView(view), "    ")
		}
	}
}

// advertisementHeading names one discovered endpoint.
//
// The identifier is included only when the advertisement actually carries it. An
// advertisement the cluster stated unusably may have no identity to show, and
// inventing a placeholder would make an absent fact look like a present one.
func advertisementHeading(a advertisement, view serviceView) string {
	heading := view.advertisementLabel
	if heading == "" {
		heading = stepLabel(a.node.Step())
	}
	if view.advertisementIdentity != "" {
		if value, ok := a.node.Attribute(view.advertisementIdentity); ok {
			heading += " " + value.String()
		}
	}
	return heading + " · " + a.node.Subject().Ref()
}

// writeStageRow emits one aligned row. Empty columns stay empty rather than
// rendering a placeholder that could be mistaken for a measurement.
func writeStageRow(tw *tabwriter.Writer, indent string, line stageLine) {
	_, _ = fmt.Fprintf(tw, "%s%s\t%s\t%s\t%s\t\n",
		indent, line.state, line.label, line.duration, line.note)
}

// writeResult renders the four axes, separately, always.
//
// # Four facts, and collapsing any two of them publishes something false
//
//	status      what target-side findings were proven
//	outcome     whether the service's terminal exchange succeeded
//	topology    what discovery measured, when the run discovered anything
//	execution   whether svcdoctor finished measuring
//
// ADR 0052 section 6 fixes them as independent, and every combination a reader
// might think impossible is reachable. `OK` beside `Kafka metadata NOT obtained`
// is a run with no credential against an endpoint that demands one. `PROBLEMS
// FOUND` beside `Kafka metadata obtained` is a healthy bootstrap broker
// advertising an endpoint nothing can reach. `OK` beside `INCOMPLETE` is
// svcdoctor's own budget expiring with nothing proven wrong.
//
// # `OK` never appears alone
//
// It always carries "no target-side error was proven", because `OK` on its own
// reads as "everything worked" and means something much narrower: no finding
// reached ERROR or CRITICAL. A reader who takes it for success on a run that
// obtained no metadata has been misled by the output rather than by the
// diagnosis (ADR 0048 section 9).
//
// # `outcome` replaced `session`, and the label is the claim
//
// Kafka has no session establishment: no ReadyForQuery, no server message
// meaning *"the connection is now ready for ordinary work"*. A `session` label
// carrying a metadata value would be worse than either word alone, which is why
// ADR 0052 section 2 generalized the label rather than varying only its value.
// PostgreSQL's phrasing is unchanged; its label is not.
//
// # `outcome` and `execution` are never omitted
//
// Not when the outcome was reached, not when the run completed, not when there
// are no findings. A section that printed them only sometimes would make their
// absence meaningful, and a reader would have to know which absence meant what.
// `topology` is the one line that *is* conditional, and its condition is
// structural: a run that recorded no advertisements has no topology to count,
// and printing `0 of 0` would invite a reader to think discovery found nothing
// when discovery may never have run.
func writeResult(out *bytes.Buffer, in render.Input, view serviceView) {
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

	notes := activeNotes(report.Graph(), view)
	if view.outcomeStep != "" && !notesReplaceOutcome(notes) {
		outcome := view.outcomeNotReached
		if outcomeReached(report.Graph(), view) {
			outcome = view.outcomeReached
		}
		_, _ = fmt.Fprintf(tw, "  outcome\t%s\t\t\n", outcome)
	}

	// Endpoint-reported facts, before the execution lines. They are observations
	// and the block they sit in is the one a reader scans for facts rather than
	// for verdicts.
	for _, line := range observationLines(report.Graph(), view) {
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t\t\n", line.label, line.value)
	}

	if line, ok := topologyLine(report.Graph(), view); ok {
		_, _ = fmt.Fprintf(tw, "  topology\t%s\t\t\n", line)
	}

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

	// The conditional statements last, outside the aligned block, because each is
	// prose rather than a field. They exist for the two silences a reader would
	// misread: a cluster-mode endpoint with no findings, and a run that stopped
	// at a Sentinel.
	for _, note := range notes {
		_, _ = fmt.Fprintln(out)
		for _, line := range note.lines {
			_, _ = fmt.Fprintf(out, "  %s\n", line)
		}
	}
}

// renderedObservation is one endpoint-reported fact, ready to print.
type renderedObservation struct {
	label string
	value string
}

// observationLines reads the observations a service declared.
//
// **The last node at the step wins.** A Redis endpoint that demanded
// authentication refuses the first HELLO and only answers the second, so reading
// the first would report an identity nobody obtained.
func observationLines(graph domain.Graph, view serviceView) []renderedObservation {
	var out []renderedObservation
	for _, observation := range view.observations {
		node, ok := lastNodeAt(graph, observation.step)
		if !ok {
			continue
		}
		value, ok := node.Attribute(observation.key)
		if !ok {
			continue
		}
		text := ""
		switch {
		case observation.render != nil:
			text = observation.render(value)
		default:
			// **Str first, then the value's own rendering.**
			//
			// AttrValue.Str reports only for the plain string kind, and until
			// Phase 8.2 every observation happened to be one. RabbitMQ has two
			// kinds that are not: the negotiated Tune values are integers, and
			// the virtual host and cluster name are identity-classed so that
			// redaction can pseudonymize them. Falling through to String() shows
			// both.
			//
			// It is safe for an identity because redaction runs over the domain
			// values *before* this renderer sees them: a shareable report reaches
			// here already carrying pseudonyms, so rendering what the value holds
			// cannot leak what it held.
			if str, ok := value.Str(); ok {
				text = str
			} else {
				text = value.String()
			}
		}
		if text == "" {
			continue
		}
		out = append(out, renderedObservation{label: observation.label, value: text})
	}
	return out
}

// activeNotes returns the conditional statements whose condition holds.
func activeNotes(graph domain.Graph, view serviceView) []conditionalNote {
	var out []conditionalNote
	for _, note := range view.notes {
		node, ok := lastNodeAt(graph, note.step)
		if !ok {
			continue
		}
		value, ok := node.Attribute(note.key)
		if !ok {
			continue
		}
		str, ok := value.Str()
		if !ok || str != note.value {
			continue
		}
		out = append(out, note)
	}
	return out
}

func notesReplaceOutcome(notes []conditionalNote) bool {
	for _, note := range notes {
		if note.replacesOutcome {
			return true
		}
	}
	return false
}

// lastNodeAt returns the final node recorded at one step.
func lastNodeAt(graph domain.Graph, step domain.Step) (domain.Evidence, bool) {
	var found domain.Evidence
	ok := false
	for _, node := range graph.Nodes() {
		if node.Step() == step {
			found, ok = node, true
		}
	}
	return found, ok
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
