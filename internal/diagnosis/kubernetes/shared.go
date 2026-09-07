// Package kubernetes derives Kubernetes Service findings from a frozen evidence
// graph.
//
// It performs no I/O, opens no connection, imports no adapter, imports no
// `k8s.io` package and reads no Kubernetes type. Every rule here is a pure
// function of the graph, and every claim it makes is one the producer already
// committed to as a state, a failure class or an attribute drawn from a closed
// set (ADR 0094 §2.12).
//
// # The two rules, and why two rather than four
//
// ADR 0094 §2.8 divides the four codes into two categories that are never
// collapsed:
//
//   - **Acquisition** — what svcdoctor could obtain. `KUBERNETES_SERVICE_NOT_
//     FOUND` and `KUBERNETES_API_ACCESS_DENIED`, both read from a structured API
//     outcome on a node.
//   - **Semantic** — what Kubernetes records. `KUBERNETES_SERVICE_SELECTS_NO_
//     PODS` and `KUBERNETES_SERVICE_NO_READY_ENDPOINT`, both read from a
//     **complete** enumeration.
//
// A rule per category rather than per code is what ADR 0094 §2.10 froze as
// "22 → 24", and it is also what keeps each rule's preconditions in one place:
// the semantic rule's Service gate — the Service exists, has a selector, and has
// a supported type — is one gate that both of its codes need.
//
// # What no rule in this package may do
//
//   - read a Kubernetes message. It cannot: the graph carries closed enums and
//     integers, and `Status.Message`, `Status.details.causes[].message` and every
//     condition message are never read anywhere in the tree (ADR 0094 §2.8).
//   - read a label key or a label value, a Pod name, an endpoint address, a
//     slice name or a node name. None of them is in the graph, by design
//     (ADR 0094 §11.2), so no prose here can carry one.
//   - state a cause. A `403` proves a read was refused; it does not prove that
//     RBAC is misconfigured. A complete empty Pod list proves the selector
//     matched nothing; it does not prove the selector is wrong, that a workload
//     is missing, or that any Pod is unhealthy.
//   - equate publication with reachability. **The wording is "publishes", never
//     "reachable"** (ADR 0093 §2.5): topology-aware routing, traffic policies and
//     the all-terminating case each break that equation, in both directions.
//   - emit a universal claim over an incomplete set. An enumeration that stopped
//     at a ceiling, at a `410`, at a cancellation or at a failed request is
//     **incomplete and never empty**, and no "zero", "all", "none" or "only"
//     claim may be made from one (ADR 0094 §2.5).
//   - re-derive EndpointSlice readiness. `k8s.ready_endpoint_count` already is
//     the effective-ready count, decided by `conditions.ready` alone with nil
//     read as true, and re-deriving it from `serving` or `terminating` would
//     silently change meaning for a Service with `publishNotReadyAddresses`
//     (ADR 0094 §2.6).
package kubernetes

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// build assembles a finding, folding the constructor's error.
//
// Every caller supplies a constant code, a validated domain value taken from a
// node the graph already accepted, and prose built from constants plus values
// drawn from closed sets. The error is therefore unreachable, and
// TestEveryAuthorizedKubernetesShapeBuildsAValidFinding drives the whole matrix
// so the omission is proven rather than assumed.
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

// advise wraps one next observation, dropping it only if the constant were
// malformed.
//
// **Every recommendation this package produces is NEXT_EVIDENCE**, and its
// safety class is one of the read-only three. `diagnosis.NewAdvice` refuses the
// three high-blast-radius classes outright and refuses a next-evidence
// recommendation that changes anything, so "no Kubernetes recommendation is a
// remediation" is a property of the construction path rather than a rule
// somebody has to remember (ADR 0094 §2.7, ADR 0082 §2.3).
func advise(safety diagnosis.SafetyClass, action, rationale string) []domain.Recommendation {
	return diagnosis.Recommend(diagnosis.AdviceInput{
		Kind:   diagnosis.AdviceKindNextEvidence,
		Safety: safety,
		Action: action,
		// svcdoctor cannot take any of these in any run. It reads three objects
		// through three bounded requests and holds no model of what a cluster
		// was meant to contain, so claiming a differently configured run could
		// collect this would be an invitation nobody can accept.
		SelfCollectable: false,
		Rationale:       rationale,
	}, domain.FindingKindConfirmed, domain.ConfidenceHigh)
}

// nodeAt returns the single node recorded at one step, or reports its absence.
//
// A Kubernetes run measures **one** Service through **one** path, so each of the
// five steps appears at most once (ADR 0094 §2.9). More than one is a graph no
// producer in this repository makes, and this returns false for it rather than
// choosing: choosing would make the output depend on traversal order, and the
// honest answer to "which Service is this about" in a graph holding two is that
// there is not one.
func nodeAt(g domain.Graph, step domain.Step) (domain.Evidence, bool) {
	var (
		found domain.Evidence
		seen  int
	)
	for _, node := range g.Nodes() {
		if node.Step() == step {
			found = node
			seen++
		}
	}
	if seen != 1 {
		return domain.Evidence{}, false
	}
	return found, true
}

// boolAttr reads a boolean attribute, or reports that the node does not carry
// it.
//
// **Absence is never read as false.** A node whose read was denied carries no
// completeness attribute at all, and treating that as "not complete" would
// happen to be right while a node whose read was *skipped* would be treated the
// same way — so every caller here requires the attribute to be present *and*
// true, and an absent one withholds the claim rather than deciding it.
func boolAttr(node domain.Evidence, key domain.AttributeKey) (bool, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return false, false
	}
	return value.Bool()
}

// intAttr reads an integer attribute, or reports that the node does not carry
// it.
//
// Absence is not zero, for the reason absence is not false. A count svcdoctor
// never recorded is not a count of nothing.
func intAttr(node domain.Evidence, key domain.AttributeKey) (int64, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return 0, false
	}
	return value.Int()
}

// stringAttr reads a string attribute, or reports that the node does not carry
// it.
func stringAttr(node domain.Evidence, key domain.AttributeKey) (string, bool) {
	value, ok := node.Attribute(key)
	if !ok {
		return "", false
	}
	return value.Str()
}

// serviceGate is the Service-shaped precondition both semantic codes share.
//
// All four conditions are required and each withholds for its own reason:
//
//  1. **the Service node is PASS.** A Service that was not read is not a Service
//     whose backends can be described. A `NotFound` gets F1, a `Forbidden` gets
//     F2, and neither gets a semantic claim.
//  2. **its type is one svcdoctor supports for backend publication** — ClusterIP
//     (including headless), NodePort or LoadBalancer. `ExternalName` publishes no
//     backend at all, and an unrecognized type becomes `UNKNOWN`, which is
//     treated as unsupported: **an unrecognized value never unlocks behaviour**
//     (ADR 0094 §2.4).
//  3. **its selector is present and non-empty.** An empty selector map is
//     selector-less, **not match-all** — that single misreading is the one that
//     would turn a correctly configured selector-less Service into a claim that
//     its backends vanished.
//  4. **the attributes are actually there.** A Service node that failed carries
//     no type and no selector fact, so an absent attribute withholds rather than
//     defaulting.
//
// It reads `k8s.service_headless` deliberately **not at all**: `clusterIP: None`
// is a deliberate configuration, never a fault, and ADR 0094 §11.1 marks that
// attribute rendering-only permanently.
func serviceGate(node domain.Evidence) bool {
	if node.State() != domain.StatePass {
		return false
	}

	serviceType, ok := stringAttr(node, servicekubernetes.AttrServiceType)
	if !ok || !supportsBackendPublication(serviceType) {
		return false
	}

	selectorPresent, ok := boolAttr(node, servicekubernetes.AttrSelectorPresent)
	return ok && selectorPresent
}

// supportsBackendPublication reports whether a Service type has backends
// svcdoctor may describe.
//
// It is a closed allowlist rather than a denylist of `ExternalName`, so a type
// this build does not recognize — a future one, or a hostile `spec.type` the
// adapter already normalized to `UNKNOWN` — falls outside it and produces
// nothing.
func supportsBackendPublication(serviceType string) bool {
	switch serviceType {
	case servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer:
		return true
	default:
		return false
	}
}
