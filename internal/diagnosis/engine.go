package diagnosis

import (
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Engine evaluates a fixed set of rules against an evidence graph.
//
// It is deliberately small. It holds a frozen Registry, runs its rules, collects
// what they return, and orders the result. It makes no diagnostic judgement of
// its own: it does not filter, rank or suppress findings, and it knows nothing
// about any service.
//
// There is no plugin discovery and no dispatch table. Rules arrive in a Registry
// assembled at a composition root, which is the same explicit wiring ADR 0009
// chose for services.
//
// An Engine is immutable once built: the Registry it holds has no mutation
// methods and evaluation writes nothing back. That makes Evaluate safe to call
// repeatedly and concurrently on one Engine, which is what a fleet run of up to
// 512 targets does with a single shared rule set.
//
// The zero Engine is valid and has no rules.
type Engine struct {
	registry Registry
}

// NewEngine returns an engine that evaluates the registry's rules.
//
// It cannot fail. Every way a rule set can be wrong — an unparseable identity, a
// nil rule, two rules claiming one identity — is refused by RuleSet.Add and
// rechecked by RuleSet.Freeze, so a Registry that exists is already valid. That
// is where ADR 0080 section 2.4's rejection lives: strictly earlier than engine
// construction, at the point that names the offending call, and still entirely
// at wiring time where an operator can never reach it.
func NewEngine(registry Registry) Engine {
	return Engine{registry: registry}
}

// RuleCount returns how many rules the engine will evaluate.
func (e Engine) RuleCount() int { return e.registry.Len() }

// Registry returns the rules the engine holds.
func (e Engine) Registry() Registry { return e.registry }

// Evaluate runs every rule against ctx and returns the findings and any rule
// failures.
//
// The findings are in the canonical order defined by domain.SortFindings, which
// is the same order a report uses. Rules are evaluated in registration order,
// but that order does not reach the output: reordering the rule set produces the
// same findings in the same sequence, so how the engine was assembled cannot
// change what a report looks like.
//
// # Convergence
//
// Two rules reaching one conclusion produce one finding carrying both routes'
// evidence. ADR 0081 section 2.1 supplies the identity that makes that
// definable, section 2.2 the merge, and Phase 10.1b clarified the part section
// 2.2 left open: identity is a candidacy test, not a licence. Findings that
// share an identity but disagree about a field a consumer parses stay separate.
// See Converge and mergeable.
//
// Merging is why Evaluate needs identities at all. A finding carries no rule
// name — nothing in the report does (ADR 0080 section 2.5) — so the attribution
// exists only inside this function, long enough to break a tie deterministically
// and then be discarded.
//
// # Rule failure
//
// A rule that panics is a defect in svcdoctor, not a fact about the target. Its
// output is discarded whole rather than partially trusted — half a rule's
// findings are not a weaker version of its conclusion, they are an arbitrary
// prefix of one — and evaluation continues, because a report missing one rule's
// findings is closer to the truth than no report at all.
//
// The failure is recorded in the Outcome so a composition root can mark the run
// incomplete. It never becomes a finding: a finding is a claim about the target,
// and svcdoctor falling over is a claim about svcdoctor (ADR 0083 section 2.3).
// The panic value is not captured, because it can hold anything the panicking
// code had in hand and this document is designed to be shared.
//
// The graph is not modified. domain.Graph exposes no mutation and copies on
// read, so this is a property of the type rather than a promise made here.
func (e Engine) Evaluate(ctx RuleContext) Outcome {
	var out Outcome
	var produced []AttributedFinding

	for _, rule := range e.registry.rules {
		findings, ok := evaluateOne(rule, ctx)
		if !ok {
			out.failures = append(out.failures, RuleFailure{rule: rule.id})
			continue
		}
		for _, f := range findings {
			produced = append(produced, AttributedFinding{Rule: rule.id, Finding: f})
		}
	}
	if len(produced) == 0 {
		return out
	}

	merged, err := Converge(produced)
	if err != nil {
		// Convergence refuses only on rule output it cannot reconcile — a zero
		// finding, an unattributed one, or a group whose partitioning left a
		// field it must not choose. Every one is a defect in svcdoctor, so the
		// response is ADR 0083 section 2.3's: discard rather than repair, and
		// let the run be incomplete. Discarding *everything* is deliberate,
		// because the failure is in the reconciliation across rules and there is
		// no principled subset to keep.
		out.findings = nil
		out.failures = append(out.failures, RuleFailure{rule: convergenceFailure})
		return out
	}

	out.findings = merged
	domain.SortFindings(out.findings)
	return out
}

// convergenceFailure names the engine itself in a RuleFailure.
//
// A convergence defect belongs to no single rule — it is a disagreement between
// them — so attributing it to one would name a rule that may be blameless. The
// identity is well formed so that every consumer of RuleFailure keeps working,
// and it is owned by "diag", the namespace generic machinery already uses.
const convergenceFailure RuleID = "diag/convergence"

// Diagnose runs every rule against ctx and returns the findings alone.
//
// It is Evaluate with the failure list dropped, and it exists because most
// callers — every rule test in the tree — have no run to mark incomplete. It is
// one implementation, not a second contract.
//
// Production code must not use it: discarding the failure list there would turn
// a diagnostic defect into a silently shorter report, which is precisely what
// ADR 0083 section 2.3 refuses. TestDIAG041ProductionEvaluatesRatherThanDiagnoses
// fails the build if a production file outside this package calls it.
func (e Engine) Diagnose(ctx RuleContext) []domain.Finding {
	return e.Evaluate(ctx).findings
}

// evaluateOne runs one rule and converts a panic into a discarded result.
//
// The recovered value is deliberately not returned. Nothing in svcdoctor may act
// on it: it is not a diagnostic outcome, it is not rendered, and it is not
// stored. Naming the rule is the whole of what a caller needs, because the whole
// of the response is "discard this rule's output and mark the run incomplete".
//
// The findings slice is built inside the deferred recovery's scope so that a
// rule which panics after returning some findings loses all of them. A partial
// slice is not a partial conclusion.
func evaluateOne(rule RegisteredRule, ctx RuleContext) (findings []domain.Finding, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			findings, ok = nil, false
		}
	}()
	return rule.eval(ctx), true
}
