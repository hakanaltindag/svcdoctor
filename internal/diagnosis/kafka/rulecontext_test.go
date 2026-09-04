package kafka

import (
	"strconv"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// rctx wraps a graph in the context a rule now receives.
//
// Phase 10.1a widened diagnosis.Rule from a graph to a RuleContext (ADR 0080
// section 2.1). Every rule in this package reads the graph and nothing else, so
// the tests below say so once, here, rather than repeating a struct literal at
// every call site: a test that had to name Vantage and Incomplete would imply
// this package's rules consult them, and none does.
//
// The zero values are deliberate. An unset vantage and a run that was not cut
// short are what a rule must tolerate, and every test in this package therefore
// exercises that case.
func rctx(g domain.Graph) diagnosis.RuleContext {
	return diagnosis.RuleContext{Graph: g}
}

// testEngine wires rules into an engine under synthetic identities.
//
// Phase 10.1a made a rule set an identified, frozen collection rather than a
// bare variadic list (ADR 0080 sections 2.4 and 2.5). The identities a
// composition root uses are pinned by its own guard; a rule test cares which
// rules ran and in what order they were wired, not what they were called, so
// this names them positionally and keeps the assertion at the call site about
// the findings.
//
// It panics rather than taking a *testing.T because several callers build an
// engine outside a test body. Freezing a hand-written list of distinct
// identities cannot fail, so a panic here is a defect in this helper.
func testEngine(rules ...diagnosis.Rule) diagnosis.Engine {
	set := diagnosis.NewRuleSet()
	for i, rule := range rules {
		set.Add("test/rule-"+strconv.Itoa(i), rule)
	}
	registry, err := set.Freeze()
	if err != nil {
		panic("testEngine: " + err.Error())
	}
	return diagnosis.NewEngine(registry)
}
