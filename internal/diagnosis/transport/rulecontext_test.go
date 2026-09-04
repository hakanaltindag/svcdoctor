package transport

import (
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
