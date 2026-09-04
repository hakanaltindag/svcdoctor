package security

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// ruleContextFor wraps a graph in the context a rule receives.
//
// Phase 10.1a widened diagnosis.Rule from a graph to a RuleContext (ADR 0080
// section 2.1). Every rule this corpus drives reads the graph and nothing else,
// so the wrapping is written once here rather than at each call site: naming
// Vantage or Incomplete at a leakage assertion would imply those fields carry
// something a redaction test must check, and they carry nothing a rule in this
// tree reads.
func ruleContextFor(g domain.Graph) diagnosis.RuleContext {
	return diagnosis.RuleContext{Graph: g}
}
