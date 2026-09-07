package kubernetes

import (
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// CodeSelectsNoPods reports that a complete, server-filtered Pod list for this
// Service's own selector came back empty.
//
// # The claim is the measurement, and the measurement is bounded
//
// The API server evaluated the Service's own selector, at read time, and
// returned nothing. That is exact Kubernetes selector semantics rather than a
// reimplementation of them, and the completeness precondition is what makes the
// universal quantifier admissible at all: an enumeration that stopped at a page
// ceiling, an object budget, a `410`, a cancellation or a failed request is
// **incomplete and never empty**, and supports no claim of this shape.
//
// **Permanently forbidden** (ADR 0094 §2.7): *the selector is wrong* · *the
// Deployment is missing* · *the Pods crashed* · *the Pods are unhealthy* ·
// *traffic has no backend* · *the Service is unavailable* · *the application is
// down* · *the namespace is wrong*. Many configurations produce this
// observation; svcdoctor measured one of them and chooses none.
//
// **The known true-but-intentional shape is recorded rather than argued away**:
// a workload deliberately scaled to zero produces this finding, truthfully. The
// detail says the selector matched nothing without saying that it should have
// matched something (ADR 0083 §2.6).
//
// # Why ERROR rather than WARN
//
// Two reasons, both answered against the question rather than by intuition.
// **Temporal risk is low**: label matching is evaluated by the API server at
// read time, not published by an eventually-consistent controller, so this is
// not an observation likely to be stale a second later. And **the impact is
// identical to `KUBERNETES_SERVICE_NO_READY_ENDPOINT`'s** — a Service with no
// backend candidates has no possible ready backend — so two findings describing
// one impact at two severities would make severity describe the *route to the
// conclusion* rather than the conclusion (docs/FINDINGS.md §3.1 rule 5).
const CodeSelectsNoPods domain.FindingCode = "KUBERNETES_SERVICE_SELECTS_NO_PODS"

// CodeNoReadyEndpoint reports that a complete set of the EndpointSlices
// Kubernetes associates with this Service published no ready endpoint.
//
// # Publication is not reachability, and the wording never blurs them
//
// **The word is "publishes", never "reachable"** (ADR 0093 §2.5). Topology-aware
// routing, traffic policies, mesh interception and the all-terminating case each
// break the equation between publication and reachability, in both directions —
// and the last of them breaks it in the direction that matters most here: a
// `serving=true, ready=false, terminating=true` endpoint is not dead, and Service
// proxies may still route to such endpoints when every available endpoint is
// terminating. **No ready endpoint is therefore not "no traffic"**, and where
// the set is entirely terminating the detail says so, because silence there
// would mislead.
//
// **Permanently forbidden** (ADR 0094 §2.7): *the Service is unreachable* ·
// *clients cannot connect* · *the application is unavailable* · *the Pods are
// unhealthy* · *the readiness probe failed* · *the EndpointSlice controller is
// broken* · *kube-proxy is broken* · *a NetworkPolicy blocks traffic* · *the
// network is broken* · *the selector is wrong* — **and any word implying
// persistence.** svcdoctor connected to nothing: it read three objects.
//
// # Readiness is consumed, never re-derived
//
// The count this rule reads is already effective-ready, decided by
// `conditions.ready` alone with nil read as **true**. It consults no `serving`,
// no `terminating`, no `targetRef`, no address and no Pod, because `ready`
// already *is* Kubernetes' shortcut for "serving and not terminating" and
// re-deriving it would silently change meaning for a Service with
// `publishNotReadyAddresses: true` (ADR 0094 §2.6). Re-deriving it here would
// also put EndpointSlice protocol semantics inside diagnosis, which is the
// adapter's job.
const CodeNoReadyEndpoint domain.FindingCode = "KUBERNETES_SERVICE_NO_READY_ENDPOINT"

// The prose, held as constants so that no part of it can come from anywhere
// else.
//
// **Nothing a cluster chose is interpolated into any of it, and neither is any
// count.** No label key, no label value, no Pod name, no slice name, no endpoint
// address and no `managed-by` string is in the graph to begin with (ADR 0094
// §11.2), and the counts these rules read decide *which* constant is emitted
// rather than being rendered into one. That keeps every sentence a fixed string
// a test can pin byte for byte.
const (
	summarySelectsNoPods = "This Service's selector matched no Pod in its namespace at the " +
		"time of these API observations"

	// **Stated positively**, for the reason detailServiceNotFound records: the
	// first version listed the claims this finding refuses to make in order to
	// deny them, and a report must contain neither the assertion nor the
	// quotation.
	detailSelectsNoPods = "The API server evaluated this Service's own selector and returned " +
		"an empty list, and the enumeration was complete: every page was followed, none " +
		"remained, and no budget was reached.\n" +
		"That is the whole of the claim. Many arrangements produce this same observation — " +
		"among them a workload deliberately held at zero replicas, and a selector doing " +
		"precisely what it was written to do — and svcdoctor measured the result without " +
		"observing which arrangement produced it.\n" +
		"svcdoctor listed no other Pods and compared no labels of its own. It asked the API " +
		"server the Service's own question and reports the answer."

	recommendSelectsNoPods = "Compare this Service's selector with the labels on the Pods " +
		"intended to back it"

	rationaleSelectsNoPods = "The selector and the workload are the two halves of this match " +
		"and svcdoctor observed only the result of putting them together, so which half " +
		"differs from what was intended is the one thing this observation cannot show."

	summaryNoReadyEndpoint = "Kubernetes published no ready endpoint for this Service at the " +
		"time of these API observations"

	// Variant A of the closed two-value map: nothing was published at all.
	detailNoReadyEndpointNoSlice = "No EndpointSlice associated with this Service was " +
		"published, and the enumeration was complete: every page was followed, none " +
		"remained, and no budget was reached.\n" +
		"This states what Kubernetes publishes and not whether anything can be reached. " +
		"svcdoctor connected to no endpoint, no cluster IP and no Pod, so it makes no claim " +
		"about whether traffic flows, about any backend's condition, or about the components " +
		"that publish endpoints."

	// Variant B of the closed two-value map: slices exist and none of their
	// endpoints is ready.
	detailNoReadyEndpointNoneReady = "EndpointSlices associated with this Service were " +
		"published and no endpoint among them reports itself ready. The enumeration was " +
		"complete: every page was followed, none remained, and no budget was reached.\n" +
		"This states what Kubernetes publishes and not whether anything can be reached. " +
		"svcdoctor connected to no endpoint, no cluster IP and no Pod, so it makes no claim " +
		"about whether traffic flows, about any backend's condition, or about the components " +
		"that publish endpoints."

	// The all-terminating note, appended to variant B alone.
	//
	// It exists because "no ready endpoint" is compatible with traffic still
	// being routed: Kubernetes Service proxies may route to terminating
	// endpoints when every available endpoint is terminating, and staying silent
	// about that would let a reader take this finding for the stronger claim it
	// refuses to make (ADR 0094 §2.6).
	detailNoReadyEndpointAllTerminating = "\nEvery endpoint in that set reports itself " +
		"terminating. Such an endpoint is not necessarily out of service: where all of a " +
		"Service's endpoints are terminating, a proxy may still route to them."

	recommendNoReadyEndpoint = "Compare the readiness the backing Pods report with the " +
		"endpoints published for this Service"

	rationaleNoReadyEndpoint = "Endpoint publication is a controller's output and Pod " +
		"readiness is its input, and svcdoctor read only the output, so whether the two " +
		"currently agree is what would separate a backend that reports itself unready from " +
		"a publication that has not caught up."
)

// Backends reports what Kubernetes records about this Service's backends.
//
// It is a diagnosis.Rule.
//
// # Two codes, one Service gate
//
// Both `KUBERNETES_SERVICE_SELECTS_NO_PODS` and
// `KUBERNETES_SERVICE_NO_READY_ENDPOINT` need the same four things to be true of
// the Service before either may be considered — it was read, its type supports
// backend publication, its selector is present, and it is non-empty — so the
// gate is evaluated once. See serviceGate.
//
// # A PASS produces nothing, and that is the point
//
// A Service with matching Pods and at least one ready endpoint has nothing to
// report here. The evidence nodes carry the counts; a finding restating that
// everything measured looked ordinary would be an "all good" line in a document
// nobody reads to the end.
//
// # The two branches are independent
//
// A denied or incomplete Pod enumeration withholds the selector finding and
// leaves the publication finding alone, and the reverse holds too. The Pod set
// and the slice set are siblings under the Service node rather than a chain
// (ADR 0094 §2.9), and erasing one branch's conclusion because the other branch
// failed would discard evidence svcdoctor already holds.
func Backends(ctx diagnosis.RuleContext) []domain.Finding {
	g := ctx.Graph

	service, ok := nodeAt(g, servicekubernetes.StepService)
	if !ok || !serviceGate(service) {
		return nil
	}

	var out []domain.Finding
	selectsNothing := false
	if finding, ok := selectsNoPods(g, service); ok {
		out = append(out, finding)
		selectsNothing = true
	}
	if finding, ok := noReadyEndpoint(g, service, selectsNothing); ok {
		out = append(out, finding)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// selectsNoPods builds F3 when a complete selector-filtered Pod list was empty.
//
// # Every condition, and why each is load-bearing
//
//  1. **The Service gate passed.** Without a selector there is no selector
//     result, and reading a selector-less Service's empty Pod branch as "matched
//     nothing" is the single misreading ADR 0094 §2.4 exists to prevent. The
//     adapter does not even issue the list in that case, so the node is SKIPPED
//     — but the gate is checked here too, because a rule that relies on an
//     upstream layer never producing a shape is a rule that is right by accident.
//  2. **The Pod node is PASS.** A denied, failed, cancelled or skipped
//     enumeration is not an empty one.
//  3. **`k8s.pod_set_complete` is present and true.** This is the predicate that
//     admits a universal claim, and it is checked as well as the state rather
//     than instead of it: the two are produced by different code paths in the
//     adapter, and requiring both means neither alone can be weakened into
//     admitting an incomplete set.
//  4. **`k8s.pod_observed_count` is present and exactly zero.** Present, because
//     an absent count is not a count of nothing; exactly zero, because "at most
//     one" or "fewer than two" would be a threshold, and this finding states a
//     measurement rather than crossing one.
func selectsNoPods(g domain.Graph, service domain.Evidence) (domain.Finding, bool) {
	pods, ok := nodeAt(g, servicekubernetes.StepPodSet)
	if !ok || pods.State() != domain.StatePass {
		return domain.Finding{}, false
	}

	complete, ok := boolAttr(pods, servicekubernetes.AttrPodSetComplete)
	if !ok || !complete {
		return domain.Finding{}, false
	}
	observed, ok := intAttr(pods, servicekubernetes.AttrPodObservedCount)
	if !ok || observed != 0 {
		return domain.Finding{}, false
	}

	return build(domain.FindingInput{
		Code:       CodeSelectsNoPods,
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityError,
		Confidence: domain.ConfidenceHigh,
		// The layer of the enumeration this claim is about, taken from the node
		// it cites rather than written as a constant.
		Layer:   pods.Layer(),
		Subject: pods.Subject(),
		Summary: summarySelectsNoPods,
		Detail:  detailSelectsNoPods,
		// The API server evaluated the selector. Where svcdoctor sat while
		// asking changed nothing about the answer.
		VantageDependent: false,
		// **Both nodes, and both are load-bearing** — the test ADR 0078 §2.3
		// rule 1 states: delete either from the graph and the claim stops
		// standing up. The Service node carries the selector's presence and the
		// type that made the read admissible; the Pod-set node carries the
		// completeness and the count.
		EvidenceRefs: []domain.EvidenceID{service.ID(), pods.ID()},
		Recommendations: advise(
			diagnosis.SafetyCompare, recommendSelectsNoPods, rationaleSelectsNoPods),
	})
}

// noReadyEndpoint builds F4 when a complete associated slice set published no
// ready endpoint.
//
// # Every condition, and why each is load-bearing
//
//  1. **The Service gate passed**, for the reason F3's first condition gives.
//  2. **`selectsNothing` is false.** ADR 0094 §10.3 makes F3 and F4 **disjoint**,
//     so the publication claim is withheld exactly where the selector claim was
//     made. See the note below on how that condition is expressed.
//  3. **The publication node is PASS.**
//  4. **`k8s.slice_set_complete` is present and true.** As in F3, checked
//     alongside the state rather than instead of it. It also covers the endpoint
//     budget: an enumeration stopped by the aggregate endpoint ceiling is not
//     complete, so a truncated set can never produce this finding.
//  5. **`k8s.ready_endpoint_count` is present and exactly zero.** One ready
//     endpoint suppresses the finding, and a `ready` field the API server did not
//     set was already counted as ready by the adapter.
//
// # How disjointness is expressed, and why it is not "at least one Pod"
//
// ADR 0094 §10.3 lists F4's precondition as *"at least one Pod was selected (so
// F3 and F4 are disjoint)"*. Read literally, that would also withhold F4
// whenever the Pod branch was **denied or incomplete** — because "at least one
// Pod was selected" is then not established — and §10.8 says the opposite in a
// table it states normatively: *"Pod set incomplete → **no F3.** The slice branch
// is unaffected"*, symmetrically with *"EndpointSlice set incomplete → **no F4.**
// The Pod branch is unaffected"*, under the rule that **one branch failing never
// erases the other branch's independent evidence**.
//
// The two are reconciled by implementing the parenthetical, which is the
// condition's stated purpose: **F4 is withheld exactly when F3 was admitted.**
// That is byte-for-byte the literal reading wherever the Pod set is complete —
// the only case in which "at least one Pod was selected" can be established at
// all — and it keeps the branches independent everywhere else. A run whose Pod
// list was refused while its slice list completed still holds complete,
// authoritative evidence about publication, and withholding a proven claim
// because an unrelated read was denied would be the erasure §10.8 forbids.
func noReadyEndpoint(
	g domain.Graph, service domain.Evidence, selectsNothing bool,
) (domain.Finding, bool) {
	if selectsNothing {
		return domain.Finding{}, false
	}

	publication, ok := nodeAt(g, servicekubernetes.StepEndpointPublication)
	if !ok || publication.State() != domain.StatePass {
		return domain.Finding{}, false
	}

	complete, ok := boolAttr(publication, servicekubernetes.AttrSliceSetComplete)
	if !ok || !complete {
		return domain.Finding{}, false
	}
	ready, ok := intAttr(publication, servicekubernetes.AttrReadyEndpointCount)
	if !ok || ready != 0 {
		return domain.Finding{}, false
	}

	detail, ok := publicationDetail(publication)
	if !ok {
		return domain.Finding{}, false
	}

	return build(domain.FindingInput{
		Code:       CodeNoReadyEndpoint,
		Kind:       domain.FindingKindConfirmed,
		Severity:   domain.SeverityError,
		Confidence: domain.ConfidenceHigh,
		Layer:      publication.Layer(),
		Subject:    publication.Subject(),
		Summary:    summaryNoReadyEndpoint,
		Detail:     detail,
		// What a controller published is not a function of where svcdoctor
		// stood. Whether the published endpoints can be *reached* from here
		// would be — and that is the claim this finding refuses to make.
		VantageDependent: false,
		// Both nodes, both load-bearing, for F3's reason.
		EvidenceRefs: []domain.EvidenceID{service.ID(), publication.ID()},
		Recommendations: advise(
			diagnosis.SafetyCompare, recommendNoReadyEndpoint, rationaleNoReadyEndpoint),
	})
}

// publicationDetail chooses between the two frozen detail variants.
//
// # A closed two-value map, and they are mutually exclusive by construction
//
//	slices == 0   ->  no associated EndpointSlice was published
//	slices >  0   ->  slices were published and no endpoint among them is ready
//
// They are *distinct observations supporting one bounded conclusion*, which is
// why they share a finding code and why no fifth code is needed: `NO_
// ENDPOINTSLICE` and `ENDPOINTS_NOT_READY` would split one operator question in
// two (ADR 0094 §4).
//
// Because they can never co-occur — one Service has one publication node and one
// slice count — there is no convergence hazard here at all: the two variants can
// never both be produced in a run, so two findings carrying incompatible details
// under one identity is a shape this rule cannot reach.
//
// The all-terminating sentence is appended to the second variant only, and only
// when there is a non-empty endpoint set every member of which reports itself
// terminating. It is a sentence and not a count: rendering *how many* would put
// a cluster's cardinality into prose, and the reader's question is whether "no
// ready endpoint" here means "nothing is serving", which the sentence answers.
//
// It returns false when the slice count is absent, which withholds the finding.
// Unreachable while the adapter records the six publication counts together, and
// failing closed is the right answer to a node that carries a ready count with
// no slice count: the two variants are decided by a fact that would be missing.
func publicationDetail(publication domain.Evidence) (string, bool) {
	slices, ok := intAttr(publication, servicekubernetes.AttrSliceCount)
	if !ok {
		return "", false
	}
	if slices == 0 {
		return detailNoReadyEndpointNoSlice, true
	}

	detail := detailNoReadyEndpointNoneReady
	if allEndpointsTerminating(publication) {
		detail += detailNoReadyEndpointAllTerminating
	}
	return detail, true
}

// allEndpointsTerminating reports that the set is non-empty and every endpoint
// in it reports itself terminating.
//
// Both counts must be present. An absent one is not a zero, and the note is
// simply not appended rather than being appended on a guess — a note that says
// "every endpoint is terminating" on the strength of two absent numbers would be
// the tool inventing the one nuance it added the note to avoid inventing.
//
// `terminating` is stable in the Kubernetes API only from v1.26 while the
// supported floor is v1.21, so on an older server the field is absent, the
// adapter's frozen nil semantics count it as zero, and this correctly says
// nothing.
func allEndpointsTerminating(publication domain.Evidence) bool {
	endpoints, ok := intAttr(publication, servicekubernetes.AttrEndpointCount)
	if !ok || endpoints == 0 {
		return false
	}
	terminating, ok := intAttr(publication, servicekubernetes.AttrTerminatingEndpointCount)
	if !ok {
		return false
	}
	return terminating == endpoints
}
