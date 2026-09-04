package diagnosis

import (
	"errors"
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ErrInvalidRuleOutput reports that a rule produced a finding the graph does not
// support.
var ErrInvalidRuleOutput = errors.New("invalid rule output")

// ValidateFinding checks one finding against the graph it claims to rest on.
//
// # Rule output is untrusted input
//
// Not because a rule is hostile — every rule is in this repository and is
// reviewed — but because a rule is code, code has defects, and ADR 0083 section
// 2.3 fixes what happens when one does: invalid output is **rejected, not
// repaired**. There is no path where a finding is partially trusted, no field is
// filled in on a rule's behalf, and nothing is dropped from a finding to make
// the rest of it acceptable. A defective rule loses its whole claim.
//
// # What it checks, and what it deliberately does not
//
// It checks the one cross-object invariant a finding cannot check for itself:
// that every evidence identifier it cites resolves to a node in this graph.
// domain.NewFinding validates a reference as a *value* and stops there, because
// checking membership would make every finding depend on a graph (ADR 0014).
//
// It does not re-check what domain.NewFinding already refused — an invalid code,
// an unspecified confidence, a CONFIRMED finding carrying a discriminator — and
// it does not judge whether the claim is a good one. Whether a rule was right to
// say something is what its own tests and the golden corpus are for; this is the
// structural backstop underneath them.
//
// # It is not the report's check, and does not replace it
//
// domain.Report validates evidence membership at assembly and stays the
// authority (ADR 0014). This exists so that a defect can be caught and the
// offending rule's output discarded *before* it reaches assembly, where the only
// remaining response would be to fail the whole report.
func ValidateFinding(f domain.Finding, g domain.Graph) error {
	if f.IsZero() {
		return fmt.Errorf("%w: the zero Finding", ErrInvalidRuleOutput)
	}

	refs := f.EvidenceRefs()
	if len(refs) == 0 {
		return fmt.Errorf(
			"%w: %s references no evidence; a finding that cannot point at its evidence "+
				"is not reportable", ErrInvalidRuleOutput, f.Code())
	}
	for i, ref := range refs {
		if _, ok := g.Node(ref); !ok {
			return fmt.Errorf(
				"%w: %s cites evidence %q, which is not in the graph; a reader cannot "+
					"check a claim whose evidence is not in the report (ADR 0014)",
				ErrInvalidRuleOutput, f.Code(), ref)
		}
		// domain.NewFinding sorts and deduplicates, so a repeat here means the
		// finding was assembled by hand rather than built through it.
		if i > 0 && refs[i-1] == ref {
			return fmt.Errorf(
				"%w: %s cites evidence %q twice; findings are built through "+
					"domain.NewFinding, which deduplicates",
				ErrInvalidRuleOutput, f.Code(), ref)
		}
	}
	return nil
}

// ValidateFindings checks every finding and reports the first failure.
//
// It stops at the first, deliberately. A rule set that produced one structurally
// invalid finding has a defect, and the response is the same whether it produced
// one or nine; enumerating the rest would be a debugging convenience bought with
// a slower failure path in the case that matters.
func ValidateFindings(findings []domain.Finding, g domain.Graph) error {
	for _, f := range findings {
		if err := ValidateFinding(f, g); err != nil {
			return err
		}
	}
	return nil
}
