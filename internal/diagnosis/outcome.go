package diagnosis

import (
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// RuleFailure records that one rule's output was discarded.
//
// It names the rule and nothing else. In particular it does not carry the panic
// value, the recovered error, or a stack trace: a panic value can hold anything
// the panicking code had in hand, and this type is read by a composition root
// that assembles a document designed to be shared. ADR 0083 section 2.3 makes
// the failure svcdoctor's own, and the honest report of it is that svcdoctor did
// not finish — not a transcript of how it fell over.
//
// The zero RuleFailure is invalid.
type RuleFailure struct {
	rule RuleID
}

// Rule returns the identity of the rule whose output was discarded.
func (f RuleFailure) Rule() RuleID { return f.rule }

// IsZero reports whether f is the invalid zero RuleFailure.
func (f RuleFailure) IsZero() bool { return f.rule == "" }

// String returns a readable rendering for a test failure message.
//
// It is not user-facing output. A rule failure is a defect in svcdoctor and
// reaches an operator only as an incomplete run, never as prose.
func (f RuleFailure) String() string {
	if f.IsZero() {
		return "<no rule failure>"
	}
	return "rule " + f.rule.String() + " failed and its output was discarded"
}

// Outcome is everything one evaluation produced.
//
// It carries the findings and, separately, the rules whose output was thrown
// away. The two are separate because they are claims about different things: a
// finding is a claim about the target, and a failure is a claim about svcdoctor.
// ADR 0083 section 2.3 forbids the second from ever becoming the first.
//
// The zero Outcome is valid: no findings, no failures.
type Outcome struct {
	findings []domain.Finding
	failures []RuleFailure
}

// Findings returns a copy of the findings, in canonical order.
func (o Outcome) Findings() []domain.Finding {
	if len(o.findings) == 0 {
		return nil
	}
	return slices.Clone(o.findings)
}

// Failures returns a copy of the rule failures, in evaluation order.
func (o Outcome) Failures() []RuleFailure {
	if len(o.failures) == 0 {
		return nil
	}
	return slices.Clone(o.failures)
}

// Failed reports whether any rule's output was discarded.
//
// A caller that sees true must treat the run as incomplete. That is the whole
// operator-visible consequence of a diagnostic defect: the report is truthful
// and partial, which is what exit code 4 already means. No new exit code exists
// and none is authorized (ADR 0083 section 2.3, ADR 0077 section 2.1).
func (o Outcome) Failed() bool { return len(o.failures) > 0 }
