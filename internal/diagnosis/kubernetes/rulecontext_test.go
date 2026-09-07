package kubernetes_test

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskubernetes "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// namedRule pairs a rule with the identity the composition root wires it under.
type namedRule struct {
	id   string
	eval diagnosis.Rule
}

// productionRules is the Kubernetes composition root's own rule set, minus the
// generic boundary every service adds.
//
// It is written out rather than imported because internal/app cannot be reached
// from a package internal/app itself imports. `TestTheProductionRootWiresExactly
// TheseRules` in test/security pins that the two agree.
func productionRules() []namedRule {
	return []namedRule{
		{"kubernetes/acquisition", diagnosiskubernetes.Acquisition},
		{"kubernetes/backends", diagnosiskubernetes.Backends},
	}
}

// TestBothKubernetesRulesSatisfyTheRuleContract is the compile-time assertion.
//
// Assigning each entry point to a diagnosis.Rule is what makes "these are rules"
// a fact the compiler checks. Doing it in the test rather than in the production
// file is the pattern every other service package uses: the rule packages do not
// import the engine's Rule type for the sole purpose of asserting against it.
func TestBothKubernetesRulesSatisfyTheRuleContract(t *testing.T) {
	rules := productionRules()
	if len(rules) != 2 {
		t.Fatalf("%d Kubernetes rules, want 2.\n\n"+
			"ADR 0094 section 2.10 froze the production rule count at 22 -> 24: one "+
			"acquisition rule and one publication rule. A third would be a decision.",
			len(rules))
	}
	for _, rule := range rules {
		if rule.eval == nil {
			t.Errorf("%s is nil", rule.id)
		}
		if _, err := diagnosis.NewRuleID(rule.id); err != nil {
			t.Errorf("%s is not a valid rule identity: %v", rule.id, err)
		}
	}
}

// TestEveryKubernetesRuleToleratesTheZeroRuleContext.
//
// The zero RuleContext describes a run that measured nothing: an empty graph, an
// unset vantage, and a run that was not cut short. diagnosis.Rule's contract
// requires every rule to tolerate it, because a rule that panics on an empty
// graph is a rule that panics on a run that measured nothing — which is exactly
// what a cancellation before the first request produces.
func TestEveryKubernetesRuleToleratesTheZeroRuleContext(t *testing.T) {
	for _, rule := range productionRules() {
		findings := rule.eval(diagnosis.RuleContext{})
		if len(findings) != 0 {
			t.Errorf("%s produced %d findings from the zero context, want 0",
				rule.id, len(findings))
		}
	}
}

// TestNoKubernetesRuleReadsTheRuleContextBeyondItsGraph.
//
// # Why this is asserted rather than left to review
//
// `RuleContext` carries three fields and two of them are traps for a rule of
// this shape. `Vantage` would let a Kubernetes claim become position-dependent,
// which none of the four is: what an API server answers does not change with
// where the question came from. `Incomplete` is svcdoctor's statement about its
// **own execution**, and a rule that consulted it would be deciding a
// Kubernetes-set question from a run-level fact — while the per-set completeness
// these rules actually need is carried on the nodes themselves, which is a
// strictly more precise answer.
//
// So the property is that neither field can change what the rules say, and it is
// driven over a matrix rather than argued.
func TestNoKubernetesRuleReadsTheRuleContextBeyondItsGraph(t *testing.T) {
	vantage, err := domain.NewLocalVantage("some-host")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)

		base := renderCodes(t, graph, diagnosis.RuleContext{Graph: graph})
		for variant, ctx := range map[string]diagnosis.RuleContext{
			"vantage set":       {Graph: graph, Vantage: vantage},
			"incomplete":        {Graph: graph, Incomplete: true},
			"vantage and both":  {Graph: graph, Vantage: vantage, Incomplete: true},
			"explicit complete": {Graph: graph, Incomplete: false},
		} {
			got := renderCodes(t, graph, ctx)
			if got != base {
				t.Errorf("%s: %s changed the findings from %s to %s.\n\n"+
					"A Kubernetes rule reads the graph. Vantage would make an API "+
					"server's answer depend on where it was asked from, and Incomplete "+
					"is a run-level fact where these rules need a per-set one.",
					name, variant, base, got)
			}
		}
	}
}

func renderCodes(t *testing.T, _ domain.Graph, ctx diagnosis.RuleContext) string {
	t.Helper()

	out := ""
	for _, rule := range productionRules() {
		for _, finding := range rule.eval(ctx) {
			out += string(finding.Code()) + "|" + finding.Summary() + "|" + finding.Detail() + ";"
		}
	}
	return out
}
