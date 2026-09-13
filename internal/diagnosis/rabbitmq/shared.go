// Package rabbitmq derives RabbitMQ findings from a frozen evidence graph.
//
// It performs no I/O, holds no connection, imports no adapter and reads no
// protocol type. Every rule here is a pure function of the graph, and every
// claim it makes is one the producer already committed to as a state, a failure
// class or an attribute drawn from a closed set.
//
// # What no rule in this package may do
//
//   - read a peer's reply text. It cannot: the graph carries a normalized
//     outcome constant and never the message (ADR 0069 §2).
//   - say "wrong password", "unknown user" or "disabled user". RabbitMQ returns
//     a byte-identical refusal for all three and for a host-based restriction,
//     and equalises the timing deliberately (ADR 0068 §4).
//   - infer a cause for a capacity ceiling. A limit outcome proves the endpoint
//     said a ceiling was reached; it does not prove the ceiling is too low, that
//     demand is abnormal, or that the condition still holds a second later.
//   - turn a version, a heartbeat, a frame size or a cluster name into a
//     finding. Without an expected-state contract those are observations of
//     exactly the kind PostgreSQL BASIC already froze as ones (ADR 0069 §8).
//   - claim a measured VHOST_DOWN condition. 541 was source-proven and never
//     live-measured, so no normalized detail is authorized for it.
package rabbitmq

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// build assembles a finding, folding the constructor's error.
//
// Every caller supplies a constant code, a validated domain value taken from a
// node the graph already accepted, and prose built from constants plus values
// drawn from closed sets. The error is therefore unreachable, and a test drives
// the whole matrix so the omission is proven rather than assumed.
//
// A rule must not respond to a rejected finding by quietly returning fewer:
// silently omitting a conclusion is the failure mode the project's claim
// discipline exists to prevent.
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
// class is one of the three read-only ones: each asks a reader to look at the
// broker's log, a virtual-host name, a configured limit or this run's own flags,
// and none asks for a change. `diagnosis.NewAdvice` refuses the three
// high-blast-radius classes outright and refuses a next-evidence recommendation
// that changes anything, so the property is structural (ADR 0097 section 2.1,
// ADR 0082 section 2.3).
//
// Every RabbitMQ finding is CONFIRMED at HIGH, which is what AdmitAdvice is
// handed.
func advise(
	safety diagnosis.SafetyClass, action, rationale string,
) []domain.Recommendation {
	return diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:   diagnosis.AdviceKindNextEvidence,
		Safety: safety,
		Action: action,
		// svcdoctor cannot take any of these. The journey is Connection.Start,
		// one credential-bearing frame and Connection.Open, and it opens no
		// channel — so the broker's log, its virtual-host list and its node,
		// vhost and user limits are all outside what this client observes. The
		// two that name svcdoctor's own flags are still not self-collectable: a
		// credential and trust material are inputs a run is given, not ones it
		// can obtain.
		SelfCollectable: false,
		Rationale:       rationale,
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
}

// recommend wraps one unclassified action.
//
// **The remaining legacy construction site in this package**, and it serves only
// the two actions Phase 13.1C owns: `recommendMechanismNotOffered`, whose "enable
// SASL PLAIN on this endpoint" carries no TLS condition, and
// `recommendVHostAccessRefused`, which asks for a permission grant and names an
// administrative command. ADR 0097 section 2.1 forbids a production rule from
// declining to classify its advice; this exemption is temporary and named in the
// Phase 13.1B allowlist.
func recommend(action string) []domain.Recommendation {
	recommendation, err := domain.NewRecommendation(action)
	if err != nil {
		return nil
	}
	return []domain.Recommendation{recommendation}
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

// identityAttr reads an identity-classed string attribute.
//
// It is separate from stringAttr because AttrValue.Str reports only for the
// plain string kind: an identity carries the same text under a different kind so
// that redaction can pseudonymize it, and reading it through the wrong accessor
// silently yields nothing.
func identityAttr(node domain.Evidence, key domain.AttributeKey) (string, bool) {
	value, ok := node.Attribute(key)
	if !ok || value.Kind() != domain.AttrKindIdentity {
		return "", false
	}
	return value.String(), true
}

// boolAttr reads a boolean attribute.
func boolAttr(node domain.Evidence, key domain.AttributeKey) (bool, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return false, false
	}
	return value.Bool()
}
