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
				_, _ = fmt.Fprintf(out, "    → %s%s\n", action, adviceTag(recommendation))
			}
			if rationale := recommendation.Rationale(); rationale != "" {
				_, _ = fmt.Fprintln(out, indent(rationale, "      "))
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

// adviceTag renders a recommendation's classification, or nothing at all.
//
// It is a **closed map over closed enumerations**, which is the property that
// keeps it presentation rather than diagnosis: every branch is a value the
// domain defines, nothing is derived from prose, and an unclassified
// recommendation gets no tag because there is nothing to report about it. A
// renderer inventing "NEXT_EVIDENCE" for an unclassified string would be
// diagnosing, which docs/ARCHITECTURE.md forbids.
//
// # What it deliberately does not do
//
// It does not reorder, rank, group or hide anything. In particular a
// recommendation is **never** hidden because SelfCollectable is false — that is
// the common and useful case (ADR 0082 section 2.4), and suppressing it would
// leave an operator with the impression that svcdoctor had nothing to suggest.
// The flag is shown, not obeyed.
//
// The two words are chosen to be read at a glance and to survive a monochrome
// terminal: "svcdoctor can collect" says a differently configured run could take
// the observation, and "you must collect" says it cannot.
func adviceTag(r domain.Recommendation) string {
	if !r.Classified() {
		return ""
	}
	tag := "  [" + r.Kind().String() + " / " + r.Safety().String()
	if r.Kind() == domain.RecommendationKindNextEvidence {
		if r.SelfCollectable() {
			tag += " / svcdoctor can collect"
		} else {
			tag += " / you must collect"
		}
	}
	return tag + "]"
}
