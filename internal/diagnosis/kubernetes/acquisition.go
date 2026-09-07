package kubernetes

import (
	"fmt"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// CodeServiceNotFound reports that the Kubernetes API answered the Service read
// with `NotFound`.
//
// # The claim stops at "the API reported"
//
// A `NotFound` can also be returned in some authorization configurations, so
// *"it does not exist"* is a stronger statement than the response supports. The
// finding says what the API reported, at the time of that one observation, and
// stops there.
//
// **Permanently forbidden** (ADR 0094 §2.7): *the Service was deleted* · *it
// never existed* · *the namespace is wrong* · *the context is wrong* · *the
// deployment failed* · any claim about what the operator meant. Absence may be
// exactly what somebody intended, and svcdoctor reports observed state and never
// violated intent (ADR 0083 §2.6).
//
// # Why ERROR
//
// The declared target does not exist at the place it was looked for, so nothing
// further about it is measurable. `POSTGRES_DATABASE_NOT_FOUND` is the precedent
// and it is ERROR.
const CodeServiceNotFound domain.FindingCode = "KUBERNETES_SERVICE_NOT_FOUND"

// CodeAPIAccessDenied reports that the Kubernetes API refused this run's
// identity one of the reads the diagnosis needed.
//
// # It is WARN with an UNKNOWN node, never an ERROR
//
// The target did not fail. **svcdoctor's measurement was blocked**, which is a
// statement about this run's authorization and not about the cluster, and a
// least-privilege Role that omits one of the three reads is a correct
// configuration under which the Service works perfectly.
// `REDIS_COMMAND_NOT_PERMITTED` is the precedent, and it is WARN for the same
// reason.
//
// **Permanently forbidden** (ADR 0094 §2.7): *RBAC is misconfigured* · *the
// ServiceAccount lacks the right Role* · *cluster policy is wrong* · *request
// cluster-admin* — **and never that the objects are absent.** A `403` says the
// read was refused. It says nothing about why the policy was authored that way,
// and nothing at all about what the read would have returned.
//
// # One code for three operations
//
// The claim is identical in kind at each of them, and the discriminating value
// is a closed svcdoctor-owned enum carried in the prose — which is ADR 0069 §6's
// division applied again: the class explains the kind of break, the sentinel
// explains which one. Two denied reads produce **two findings** rather than one
// merged one, because the Detail differs and ADR 0081 §2.2b makes Detail a merge
// precondition. That is the correct outcome and not a defect: two reads were
// refused, and two things are being said.
const CodeAPIAccessDenied domain.FindingCode = "KUBERNETES_API_ACCESS_DENIED"

// The prose, held as constants so that no part of it can come from anywhere
// else.
//
// **Nothing a cluster chose is interpolated into any of it.** The only value
// that ever reaches these strings is an operation name from the closed map
// below, which is a constant svcdoctor declared. The namespace and the Service
// name travel on the subject and on the referenced evidence, where redaction
// transforms them (ADR 0081 §2.7, docs/FINDINGS.md §3.1 rule 15).
const (
	summaryServiceNotFound = "The Kubernetes API reported that no Service of this name exists " +
		"in this namespace"

	// **Stated positively, and that is a rule this repository already made.**
	//
	// The first version of this sentence listed the claims the finding refuses
	// to make — that the Service was deleted, that it never existed, that the
	// namespace is wrong — in order to deny each one. Phase 10.3 ruled on
	// exactly that shape for PostgreSQL's `53300`: naming a claim to deny it
	// puts the words in the report, and a substring scan cannot tell a quotation
	// from an assertion, which is precisely why the report must contain neither.
	// TestNoKubernetesFindingEverExceedsItsClaimCeiling found this one on the
	// day it was written.
	detailServiceNotFound = "This restates what the API server answered when the Service was " +
		"read, at the time of that one observation, and nothing more.\n" +
		"The answer describes one moment. svcdoctor holds no record of what this cluster " +
		"contained before the run and no expectation of what it was meant to contain, so an " +
		"absence it observes may be an absence somebody arranged. Some authorization " +
		"configurations answer a read this way too.\n" +
		"Nothing below this read was attempted, so this run says nothing about which Pods " +
		"would have been selected or which endpoints would have been published."

	recommendServiceNotFound = "Verify the namespace and Service name this run declared " +
		"against the cluster it was pointed at"

	rationaleServiceNotFound = "svcdoctor read one namespace and one name because the target " +
		"declared them, and it holds no record of what the cluster contains beside them, so " +
		"whether the declaration or the object is the surprising half is the one thing this " +
		"observation cannot settle."

	summaryAPIAccessDenied = "The Kubernetes API denied this run's identity the %s read, so " +
		"that measurement was not made"

	detailAPIAccessDenied = "The API server accepted this run's identity and refused this one " +
		"read for it.\n" +
		"This is an authorization decision about one read. It is not a failure of the " +
		"cluster, and it is not a statement that what the read would have returned is " +
		"absent: the set that read would have produced is unavailable, which is a different " +
		"fact from empty.\n" +
		"svcdoctor did not retry the read and did not ask for it a second way. Every " +
		"conclusion that would have rested on it is withheld.\n" +
		"The read that was denied was %s."

	recommendAPIAccessDenied = "Verify whether the identity this run used is authorized to " +
		"perform this read in this namespace"

	rationaleAPIAccessDenied = "The refusal is the only thing this run observed about that " +
		"read, so what the read would have returned and why the policy answers this way are " +
		"both outside what was measured."
)

// deniedOperations is the closed map from a denied read's step to the
// svcdoctor-owned operation name the finding states.
//
// **Three entries and no fourth is reachable**, because svcdoctor performs
// exactly three API operations (ADR 0094 §2.5) and `k8s.target` and
// `k8s.api_access` cannot carry an authorization refusal: a `403` means the
// identity was accepted, so the api_access node passes and the refusal belongs
// to the operation that received it.
//
// # Why the names are declared here rather than read from anywhere
//
// They are report prose, and the package that writes prose owns its spelling.
// The acquisition layer holds the same three names for its own audit purposes,
// and diagnosis may not import it — an adapter's types never cross into
// diagnosis. `TestTheDeniedOperationNamesMatchTheAcquisitionVocabulary` compares
// the two from outside both, so the duplication cannot drift silently.
//
// A raw HTTP method and path is what these replace. One would put a URL — and
// with it the API server's identity — into canonical data, and would make the
// finding's prose depend on a string the client library composed.
var deniedOperations = map[domain.Step]string{
	servicekubernetes.StepService:             "SERVICE_GET",
	servicekubernetes.StepPodSet:              "POD_LIST",
	servicekubernetes.StepEndpointPublication: "ENDPOINTSLICE_LIST",
}

// deniedOperationOrder fixes the order two denied reads are reported in.
//
// Findings are sorted canonically by the report, so this does not decide the
// output order; it decides the order this rule *constructs* them in, which keeps
// the rule's own behaviour independent of `Graph.Nodes()` and makes a test that
// permutes evidence insertion able to assert an exact slice rather than a set.
//
// It is the journey's order — the Service, then the Pods, then the published
// endpoints — because that is the order the reads were issued in.
var deniedOperationOrder = []domain.Step{
	servicekubernetes.StepService,
	servicekubernetes.StepPodSet,
	servicekubernetes.StepEndpointPublication,
}

// Acquisition reports what svcdoctor could and could not obtain from the
// Kubernetes API.
//
// It is a diagnosis.Rule. The signature is not stated as one here for the reason
// the sibling rules across the tree give: the assertion lives in the package's
// own boundary test, where a compile-time check does not cost an import cycle.
//
// # It produces two codes and never a third
//
// `KUBERNETES_SERVICE_NOT_FOUND` from a structured `NotFound` on the Service
// read, and `KUBERNETES_API_ACCESS_DENIED` from a structured `Forbidden` on any
// of the three reads. **Every other API outcome produces nothing here**: a
// `401`, a `410`, a `5xx`, a `429`, a timeout, a reset and a cancellation are
// acquisition failures that already carry an existing failure class on their own
// node, and `DIAG_FAILURE_BOUNDARY` localizes them generically (ADR 0094 §2.8).
//
// **A `401` is emphatically not a `403`.** Authentication and authorization are
// different answers that send an operator to different places, and collapsing
// them would be the tool inventing a distinction the API server did not make —
// in the direction that names an innocent policy.
//
// # Nothing here is read from prose
//
// The two admission predicates are a state and a failure class, both of which
// the adapter derived from an HTTP status and a `metav1.StatusReason` through
// `apierrors`. There is no string to match, no message to parse and no error
// text to search: a Go error whose text happens to contain "not found" cannot
// reach this rule, because the graph carries no error text at all.
func Acquisition(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	var out []domain.Finding
	if finding, ok := serviceNotFound(g); ok {
		out = append(out, finding)
	}
	out = append(out, accessDenied(g)...)
	if len(out) == 0 {
		return nil
	}
	return out
}

// serviceNotFound builds F1 when the Service read was answered with `NotFound`.
//
// # The predicate is exact, and it is scoped to one step
//
//	step  == k8s.service
//	state == FAIL
//	class == RESOURCE_NOT_FOUND
//
// **The step scope is load-bearing rather than tidy.** A `LIST` can also be
// answered `404` — a namespace that does not exist is the ordinary way — and the
// adapter maps that to the same state and class on the Pod-set or the
// publication node. Without the step scope this rule would announce that the
// *Service* was not found because a *Pod list* was, which is a claim about a
// different object.
//
// The class is the one the adapter assigns to `apierrors.IsNotFound` and to
// nothing else, so the finding's authority is the API's own `StatusReason` with
// no string anywhere in the path.
func serviceNotFound(g domain.Graph) (domain.Finding, bool) {
	node, ok := nodeAt(g, servicekubernetes.StepService)
	if !ok {
		return domain.Finding{}, false
	}
	if node.State() != domain.StateFail ||
		node.FailureClass() != domain.FailureResourceNotFound {
		return domain.Finding{}, false
	}

	return build(domain.FindingInput{
		Code: CodeServiceNotFound,
		// It restates a measured state and infers nothing, so there is no open
		// question and no discriminator — domain.NewFinding refuses one on a
		// CONFIRMED finding, and there would be nothing for it to settle.
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityError,
		Confidence: domain.ConfidenceHigh,
		// The claim's own layer, taken from the node it cites. The Service read
		// happened at L6 and ADR 0094 §10.3 freezes it there; reading it from
		// the node is what keeps the claim and its evidence from disagreeing.
		// It is deliberately not L0 — this is not a statement about the target
		// declaration — and not L5, which is where the API server's acceptance
		// of the identity was established.
		Layer:   node.Layer(),
		Subject: node.Subject(),
		Summary: summaryServiceNotFound,
		Detail:  detailServiceNotFound,
		// The API server's answer does not depend on where svcdoctor sits. It is
		// a statement about one namespace in one cluster, and a run from another
		// network position that reached the same API server would get the same
		// answer.
		VantageDependent: false,
		// **The Service node only**, which is ADR 0094 §10.3's frozen membership
		// and is minimal sufficient proof: that node alone carries the state,
		// the class and the declared namespace and name. Citing the api_access
		// node would add a fact the claim does not rest on.
		EvidenceRefs: []domain.EvidenceID{node.ID()},
		Recommendations: advise(
			diagnosis.SafetyVerify, recommendServiceNotFound, rationaleServiceNotFound),
	})
}

// accessDenied builds one F2 per read the API server refused.
//
// # Why it iterates rather than stopping at the first
//
// The Pod read and the EndpointSlice read are **siblings under the Service node,
// not a chain** (ADR 0094 §2.9), so both can be denied in one run and each
// refusal is its own fact. Reporting only the first would erase the second, and
// the second is what withholds the other semantic finding.
//
// # The predicate, and why UNKNOWN rather than FAIL
//
//	state == UNKNOWN
//	class == AUTHZ_NOT_PERMITTED
//
// The adapter maps `apierrors.IsForbidden` to exactly that pair and maps nothing
// else to it. UNKNOWN is the deliberate half: a denied read is a measurement
// that was not made, not a target that failed, and putting it on the FAIL side
// would let "svcdoctor was not allowed to look" become "there is nothing there".
func accessDenied(g domain.Graph) []domain.Finding {
	var out []domain.Finding
	for _, step := range deniedOperationOrder {
		node, ok := nodeAt(g, step)
		if !ok {
			continue
		}
		if node.State() != domain.StateUnknown ||
			node.FailureClass() != domain.FailureAuthzNotPermitted {
			continue
		}
		// A step with no name in the closed map has no bounded identity to
		// publish, so the claim is withheld entirely rather than made without
		// one or made with the step string as a fallback. Unreachable today —
		// deniedOperationOrder is the map's own key set — and it fails closed
		// if that ever stops being true.
		operation, named := deniedOperations[step]
		if !named {
			continue
		}

		finding, built := build(domain.FindingInput{
			Code:       CodeAPIAccessDenied,
			Kind:       domain.FindingKindConfirmed,
			Severity:   domain.SeverityWarn,
			Confidence: domain.ConfidenceHigh,
			// **The layer of the denied read**, taken from the node this claim
			// cites rather than written as a constant. All three reads sit at
			// L6, which ADR 0094 §10.3 freezes and a test pins — so two refusals
			// in one run share a layer and are kept apart by their Detail alone.
			//
			// Reading it from the node is what keeps the claim and its evidence
			// from disagreeing. Phase 10.1B found the other shape in PostgreSQL:
			// a finding published at L5 while citing an L4 node, decided by an
			// alphabet.
			Layer:            node.Layer(),
			Subject:          node.Subject(),
			Summary:          fmt.Sprintf(summaryAPIAccessDenied, operation),
			Detail:           fmt.Sprintf(detailAPIAccessDenied, operation),
			VantageDependent: false,
			EvidenceRefs:     []domain.EvidenceID{node.ID()},
			Recommendations: advise(
				diagnosis.SafetyVerify, recommendAPIAccessDenied, rationaleAPIAccessDenied),
		})
		if !built {
			continue
		}
		out = append(out, finding)
	}
	return out
}
