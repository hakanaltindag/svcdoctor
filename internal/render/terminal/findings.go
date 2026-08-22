package terminal

import (
	"bytes"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// writeFindings renders every finding the report holds.
//
// # Every one, always
//
// There is no filter here, and in particular none keyed on the summary status. A
// WARN on an `OK` report is the case ADR 0046 created deliberately — the endpoint
// demanded authentication and the run had none — and it is the whole reason the
// operator is reading this. Hiding it because the status looked fine would turn
// the one output that could explain a missing session into a blank space.
//
// # In the order the report already has
//
// domain.NewReport canonicalizes findings, so this preserves that order rather
// than imposing one. A renderer that re-sorted by its own idea of priority would
// give the same run two orders depending on which output form was chosen, and
// the JSON's order is the one a consumer already sees.
//
// # It repeats what the finding says and adds nothing
//
// Code, severity, subject, summary, detail and recommendations, as written. No
// prose is generated here, no FailureClass is translated into a sentence, and no
// cause is named that the finding did not name. Those words were argued over in
// the ADRs that authorized each code, and a renderer rewording them would be
// making a diagnostic claim in a presentation layer.
func writeFindings(out *bytes.Buffer, report domain.Report) {
	_, _ = fmt.Fprintln(out, "Findings")

	findings := report.Findings()
	if len(findings) == 0 {
		_, _ = fmt.Fprint(out, "  none\n\n")
		return
	}

	for _, finding := range findings {
		_, _ = fmt.Fprintf(out, "  %s  %s  %s\n",
			severityGlyph(finding.Severity()), finding.Code(), finding.Subject().Ref())

		if summary := finding.Summary(); summary != "" {
			_, _ = fmt.Fprintln(out, indent(summary, "    "))
		}
		if detail := finding.Detail(); detail != "" {
			_, _ = fmt.Fprintln(out, indent(detail, "    "))
		}
		for _, recommendation := range finding.Recommendations() {
			if action := recommendation.Action(); action != "" {
				_, _ = fmt.Fprintf(out, "    → %s\n", action)
			}
		}

		// The count, not the identifiers. A reader who needs the exact nodes has
		// the JSON, where the references are machine-usable; a column of
		// `postgres.ssl_request/db.internal:5432/10.0.0.1` in a terminal is
		// noise that pushes the prose off the screen.
		if refs := finding.EvidenceRefCount(); refs > 0 {
			_, _ = fmt.Fprintf(out, "    evidence: %d\n", refs)
		}
		_, _ = fmt.Fprintln(out)
	}
}
