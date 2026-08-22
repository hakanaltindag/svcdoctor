// Package json writes a report as the canonical svcdoctor JSON artifact.
//
// It is a renderer, and it is the smallest one this repository will ever have:
// the report already owns its wire shape (ADR 0016), so there is nothing here to
// decide and nothing to keep in step. What this package contributes is a place
// where "who writes output bytes" lives, so that the terminal renderer arriving
// in Phase 5.3 is a sibling of this file rather than a refactor of the command.
//
// # What it must never grow into
//
// No wrapper object, no envelope, no CLI DTO, and no field this package
// invents. A shape like
//
//	{"report": {...}, "incomplete": true, "exitCode": 4}
//
// is forbidden by ADR 0048 section 5: it would displace schemaVersion from the
// top level and create a second schema to keep in step with the canonical one.
// `Result.Incomplete()` reaches a machine consumer through the **process exit
// code**, because a report cannot observe its own partiality
// (docs/REPORT_SCHEMA.md section 8).
//
// It also derives nothing. It does not read findings, does not decide whether a
// session was established, does not compute an exit code and does not redact.
// Redaction is an output-boundary transformation the command applies to the
// report *before* a renderer sees it, so a renderer able to redact could produce
// shareable-looking bytes whose own security metadata disagreed (ADR 0018).
package json

import (
	stdjson "encoding/json"
	"fmt"
	"io"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Write encodes report and writes it to w, followed by exactly one newline.
//
// # Compact, and one trailing newline
//
// Compact because this is a machine artifact: `--output json` exists to be
// redirected into a file or piped into a tool, and a reader who wants it
// readable has `jq`. The single trailing newline makes the stream line-oriented,
// so a shell that appends to a log or reads it back does not have to special
// case the last byte.
//
// # Determinism
//
// domain.Report.MarshalJSON is already deterministic — nodes and relationships
// follow the graph's canonical order, findings follow canonical finding order,
// and no map is iterated. This function adds nothing that could vary, which is
// why re-encoding the same report always produces the same bytes.
//
// # The encoding happens before the first byte is written
//
// A report that failed to encode must not leave half an artifact on stdout, so
// the whole document is built in memory and then written once. Reports are
// small, and a partially written JSON object is worse than no output at all for
// the automation this format exists to serve.
func Write(w io.Writer, report domain.Report) error {
	if w == nil {
		return fmt.Errorf("writing the report: no writer")
	}

	// json.Marshal calls the report's own MarshalJSON. Nothing here reimplements
	// the schema, which is what keeps this package unable to drift from it.
	encoded, err := stdjson.Marshal(report)
	if err != nil {
		return fmt.Errorf("encoding the report: %w", err)
	}

	encoded = append(encoded, '\n')
	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("writing the report: %w", err)
	}
	return nil
}
