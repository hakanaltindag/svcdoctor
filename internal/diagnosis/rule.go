package diagnosis

import "github.com/hakanaltindag/svcdoctor/internal/domain"

// Rule derives findings from a frozen evidence graph.
//
// It is a function type rather than an interface because a rule is a pure
// function and nothing about it needs to be anything more. A rule that needs
// configuration is a closure over it:
//
//	func certExpiringSoon(within time.Duration) Rule {
//	    return func(g domain.Graph) []domain.Finding { ... }
//	}
//
// # Why the graph is the only argument
//
// Everything the contract could also carry was considered and left out because
// nothing needs it:
//
//   - RunMetadata and Vantage describe the run, not the evidence. A rule that
//     marks a finding vantage-dependent is stating that its own kind of claim
//     depends on network position, which it knows without being shown the vantage.
//   - ServiceID would hand the engine a service name to branch on, which is the
//     coupling docs/ARCHITECTURE.md section 8 exists to prevent. A service rule is
//     simply a rule that is only wired in for that service.
//   - Report would be circular: a report contains the findings a rule produces.
//   - A context value has nothing to cancel. Evaluation is in-memory and bounded
//     by the size of the graph.
//
// Adding an argument later is a contract change, so the contract starts at what
// the first real rules actually need. See ADR 0017.
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
// # Obligations
//
// A rule must:
//
//   - treat the graph as read-only, which the type already enforces
//   - reference only evidence identifiers present in that graph
//   - return findings built through domain.NewFinding, never assembled by hand
//   - be deterministic: the same graph must produce the same findings
//
// Returning nil is normal and means the rule found nothing to report.
type Rule func(g domain.Graph) []domain.Finding
