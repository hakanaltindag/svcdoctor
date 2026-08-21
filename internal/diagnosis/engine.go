package diagnosis

import (
	"slices"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Engine evaluates a fixed set of rules against an evidence graph.
//
// It is deliberately small. It holds rules, runs them, collects what they
// return, and orders the result. It makes no diagnostic judgement of its own:
// it does not filter, rank, merge, or suppress findings, and it knows nothing
// about any service.
//
// There is no registration mechanism, no plugin discovery and no dispatch table.
// Rules arrive as arguments, which is the same explicit composition-root wiring
// ADR 0009 chose for services.
//
// An Engine is immutable once built: it copies the rules it is given, has no
// method that changes them, and evaluation writes nothing back. That makes
// Diagnose safe to call repeatedly and concurrently on one Engine.
//
// The zero Engine is valid and has no rules.
type Engine struct {
	rules []Rule
}

// NewEngine returns an engine that evaluates rules in the order given.
//
// The slice is copied, so a caller cannot change an engine's behaviour after
// building it. Nil entries are rejected rather than skipped: a nil rule is a
// wiring mistake, and quietly ignoring it would produce a report missing
// findings nobody noticed were absent.
func NewEngine(rules ...Rule) Engine {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		out = append(out, r)
	}
	return Engine{rules: slices.Clip(out)}
}

// RuleCount returns how many rules the engine will evaluate.
func (e Engine) RuleCount() int { return len(e.rules) }

// Diagnose evaluates every rule against g and returns the findings.
//
// The result is in the canonical order defined by domain.SortFindings, which is
// the same order a report uses. Rules are evaluated in wiring order, but that
// order does not reach the output: reordering the rule set produces the same
// findings in the same sequence, so how the engine was assembled cannot change
// what a report looks like.
//
// Findings are returned exactly as the rules produced them. The engine does not
// deduplicate: two rules reporting the same conclusion means the rule set says
// something twice, and deciding which of two findings to discard would require
// defining when two findings are the same conclusion, which no document does.
// Dropping one could also remove a real finding that merely looked similar. See
// ADR 0017.
//
// Diagnose returns no error. Rules read a frozen in-memory graph and have
// nothing operational to fail at; see Rule.
//
// The graph is not modified. domain.Graph exposes no mutation and copies on
// read, so this is a property of the type rather than a promise made here.
func (e Engine) Diagnose(g domain.Graph) []domain.Finding {
	var findings []domain.Finding
	for _, rule := range e.rules {
		findings = append(findings, rule(g)...)
	}
	if len(findings) == 0 {
		return nil
	}

	domain.SortFindings(findings)
	return findings
}
