// Package redis derives Redis and Valkey findings from a frozen evidence graph.
//
// It performs no I/O, holds no connection, imports no adapter and reads no
// protocol type. Every rule here is a pure function of the graph, and every
// claim it makes is one the producer already committed to as a state, a failure
// class or an attribute drawn from a closed set.
//
// # What no rule in this package may do
//
//   - read a peer's error message text. It cannot: the graph carries a
//     normalized prefix and never the message (ADR 0066).
//   - conclude an implementation from an observation, or compare versions.
//   - turn `role=replica` into a finding. Without an expected-role contract that
//     is an observation of exactly the kind PostgreSQL BASIC already froze as
//     one, and `TestNoRedisFindingAssertsAnExpectation` fails the build if a rule
//     starts.
//   - turn `mode=cluster` into a cluster-health claim. v1 measures no topology,
//     and "not measured" is never collapsed into anything else (ADR 0052).
//   - claim a cause for a condition the endpoint merely named. `LOADING` proves
//     the endpoint said it is loading; it does not prove the server is down,
//     that data was lost, or that a disk is slow.
package redis

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// build assembles a finding, folding the constructor's error.
//
// Every caller supplies a constant code, a validated domain value taken from a
// node the graph already accepted, and prose built from constants plus values
// drawn from closed sets. The error is therefore unreachable, and
// TestEveryAuthorizedShapeBuildsAValidFinding drives the whole matrix so the
// omission is proven rather than assumed.
//
// A rule must not respond to a rejected finding by quietly returning fewer:
// silently omitting a conclusion is the failure mode the project's claim
// discipline exists to prevent. That is why this returns a bool the callers
// propagate and the test asserts is never false.
func build(in domain.FindingInput) (domain.Finding, bool) {
	finding, err := domain.NewFinding(in)
	if err != nil {
		return domain.Finding{}, false
	}
	return finding, true
}

// recommend wraps one action, dropping it only if the constant were malformed.
// advise wraps one classified observation.
//
// **Every recommendation this package produces is NEXT_EVIDENCE**, and its safety
// class is one of the three read-only ones: each asks a reader to look at a
// server log, an ACL configuration or the endpoint's own state, and none asks for
// a change. `diagnosis.NewAdvice` refuses the three high-blast-radius classes
// outright and refuses a next-evidence recommendation that changes anything, so
// the property holds by construction (ADR 0097 section 2.1, ADR 0082 section 2.3).
//
// Every Redis finding is CONFIRMED at HIGH, which is what AdmitAdvice is handed.
func advise(
	safety diagnosis.SafetyClass, action, rationale string,
) []domain.Recommendation {
	return diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:   diagnosis.AdviceKindNextEvidence,
		Safety: safety,
		Action: action,
		// svcdoctor cannot take any of these. The journey is HELLO, AUTH and one
		// keyless command, so an ACL configuration, an ACL log, a connection log
		// and the endpoint's current state are all outside it — and re-pointing
		// the run at a data endpoint needs an address svcdoctor was not given,
		// because Sentinel discovery is refused (ADR 0065).
		SelfCollectable: false,
		Rationale:       rationale,
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
}

// nodesAt returns every node recorded at one step, in graph order.
func nodesAt(g domain.Graph, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, node := range g.Nodes() {
		if node.Step() == step {
			out = append(out, node)
		}
	}
	return out
}

// stringAttr reads a string attribute, or reports that the node does not carry
// it.
//
// Absence is a real answer everywhere it is used here: a HELLO node that was
// refused carries no mode, and a rule must be able to tell "the endpoint said
// standalone" from "svcdoctor never found out".
func stringAttr(node domain.Evidence, key domain.AttributeKey) (string, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return "", false
	}
	return value.Str()
}
