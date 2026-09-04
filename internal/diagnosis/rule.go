package diagnosis

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// Rule derives findings from frozen, already-collected evidence.
//
// It is a function type rather than an interface because a rule is a pure
// function and nothing about it needs to be anything more. A rule that needs
// configuration is a closure over it:
//
//	func certExpiringSoon(within time.Duration) Rule {
//	    return func(ctx RuleContext) []domain.Finding { ... }
//	}
//
// A rule's identity is not part of this type. A function value cannot carry one
// honestly — every rule has the same Go type — so identity is paired with a rule
// at the composition root, by RuleSet.Add. See RuleID.
//
// # Why RuleContext is the only argument
//
// The argument was domain.Graph until Phase 10.1a. ADR 0080 section 2.1 widened
// it to a struct carrying three frozen facts, and the widening is a contract
// change made once so that the next admitted fact is a field rather than a
// second rule type. See RuleContext for what those three are and for the much
// longer list of what is deliberately absent, which is the security model.
//
// The rejected shapes are still rejected. A context.Context has nothing to
// cancel and would invite I/O. A ServiceID would hand the engine a service name
// to branch on, which is the coupling docs/ARCHITECTURE.md section 8 exists to
// prevent: a service rule is simply a rule that is only wired in for that
// service. A Report would be circular, because a report contains the findings a
// rule produces.
//
// # No error result
//
// A rule reads a frozen in-memory graph, so it has nothing operational to fail
// at: no connection to lose, no file to miss, no deadline to exceed. An error
// result would exist only to be always nil.
//
// The one thing that can go wrong is a rule trying to build a Finding that
// domain.NewFinding rejects, and that is a defect in the rule rather than a
// diagnostic outcome. A rule must not respond by quietly returning fewer
// findings: silently omitting a conclusion is the failure mode the project's
// claim discipline exists to prevent. Rules are responsible for constructing
// valid findings, and their own tests are where that is established.
//
// A rule that panics has its output discarded whole and marks the run
// incomplete; see Engine.Evaluate and ADR 0083 section 2.3. That is a backstop
// for a defect, not a way to signal one.
//
// # Obligations
//
// A rule must:
//
//   - treat the graph as read-only, which the type already enforces
//   - reference only evidence identifiers present in that graph
//   - return findings built through domain.NewFinding, never assembled by hand
//   - be deterministic: the same context must produce the same findings
//   - tolerate the zero RuleContext, which describes a run that measured nothing
//
// It must not read a state it did not find, upgrade UNKNOWN or SKIPPED into
// FAIL, treat absent evidence as contradicting evidence, or copy a peer-supplied
// string into a finding's prose. Those are ADR 0078 section 2.3, ADR 0081
// sections 2.4 and 2.7; the shared vocabulary in this package exists so a rule
// can express them rather than re-derive them.
//
// Returning nil is normal and means the rule found nothing to report.
type Rule func(ctx RuleContext) []domain.Finding
