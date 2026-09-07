package kubernetes_test

import (
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// The diagnosis-layer properties, K-P01 through K-P15.
//
// They are the half of ADR 0094 section 13.5's P1–P15 that belongs to a rule.
// The acquisition half — that an `exec` config never executes, that credential
// authority stays API-server-only, that cancellation stops pagination, that a
// budget marks a set incomplete — is Phase 12.1B's and is proven against a
// hermetic API server there.
//
// Each one is stated over a generated space rather than over a fixture, because
// the value of a property is that it holds for inputs nobody thought of.

// everyState is the closed set a Kubernetes node can carry.
func everyState() []domain.State {
	return []domain.State{
		domain.StatePass, domain.StateFail, domain.StateDegraded,
		domain.StateUnknown, domain.StateSkipped,
	}
}

// everyFailureClass is every class the Kubernetes adapter can assign, plus
// several it cannot, so that a rule reading a class it should not recognize is
// visible.
func everyFailureClass() []domain.FailureClass {
	return []domain.FailureClass{
		domain.FailureNone,
		domain.FailureResourceNotFound,
		domain.FailureAuthzNotPermitted,
		domain.FailureAuthCredentialsRejected,
		domain.FailureExecDepthLimit,
		domain.FailureExecCancelled,
		domain.FailureExecLocalTimeout,
		domain.FailureExecSkippedPrerequisiteFailed,
		domain.FailureExecUnsupportedBySvcdoctor,
		domain.FailureProtocolUnexpectedResponse,
		domain.FailureTCPConnectionFailed,
		domain.FailureTLSUnknownAuthority,
		domain.FailureResourceLimitReached,
		domain.FailureAuthzDenied,
	}
}

// TestKP01AnIncompletePodSetNeverProducesASelectorClaim.
//
// Driven over every state and class, with the count held at zero and the
// completeness flag false. An incomplete enumeration is **incomplete and never
// empty**, and supports no "zero", "all", "none" or "only" claim of any kind —
// which is Kafka Phase 10.2's rule, unchanged, in a third domain.
func TestKP01AnIncompletePodSetNeverProducesASelectorClaim(t *testing.T) {
	checked := 0
	for _, state := range everyState() {
		for _, class := range everyFailureClass() {
			if !admissible(state, class) {
				continue
			}
			spec := healthy()
			spec.podSet = node{
				step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
				state: state, failureClass: class,
				attributes: map[domain.AttributeKey]domain.AttrValue{
					servicekubernetes.AttrPodSetComplete:   domain.BoolAttr(false),
					servicekubernetes.AttrPodObservedCount: domain.IntAttr(0),
				},
			}
			checked++
			if hasCode(spec.evaluate(t), f3) {
				t.Errorf("state %s + class %s: an incomplete Pod set produced a "+
					"selector claim", state, class)
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing was checked; this guard would pass vacuously")
	}
}

// TestKP02AnIncompleteSliceSetNeverProducesAPublicationClaim.
func TestKP02AnIncompleteSliceSetNeverProducesAPublicationClaim(t *testing.T) {
	checked := 0
	for _, state := range everyState() {
		for _, class := range everyFailureClass() {
			if !admissible(state, class) {
				continue
			}
			for _, slices := range []int64{0, 1, 256} {
				spec := healthy()
				spec.publication = node{
					step:  servicekubernetes.StepEndpointPublication,
					layer: domain.LayerTopology, state: state, failureClass: class,
					attributes: map[domain.AttributeKey]domain.AttrValue{
						servicekubernetes.AttrSliceSetComplete:   domain.BoolAttr(false),
						servicekubernetes.AttrSliceCount:         domain.IntAttr(slices),
						servicekubernetes.AttrEndpointCount:      domain.IntAttr(0),
						servicekubernetes.AttrReadyEndpointCount: domain.IntAttr(0),
					},
				}
				checked++
				if hasCode(spec.evaluate(t), f4) {
					t.Errorf("state %s + class %s + %d slices: an incomplete slice set "+
						"produced a publication claim", state, class, slices)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("nothing was checked; this guard would pass vacuously")
	}
}

// TestKP03AuthenticationFailureNeverBecomesAnAuthorizationClaim.
//
// **401 is not 403**, and this is the property that says so from every angle the
// graph offers. A `401` fails the api_access node with a credentials-rejected
// class; nothing about it may reach `KUBERNETES_API_ACCESS_DENIED`, which is a
// claim about a policy decision made by a server that accepted the identity.
//
// Collapsing the two would be svcdoctor inventing a distinction the API server
// did not make, in the direction that names an innocent policy.
func TestKP03AuthenticationFailureNeverBecomesAnAuthorizationClaim(t *testing.T) {
	// The api_access node carrying a rejection, on every state.
	for _, state := range everyState() {
		if !admissible(state, domain.FailureAuthCredentialsRejected) {
			continue
		}
		spec := healthy()
		spec.apiAccess = node{
			step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
			state: state, failureClass: domain.FailureAuthCredentialsRejected,
		}
		if hasCode(spec.evaluate(t), f2) {
			t.Errorf("api_access in state %s with a rejected credential produced an "+
				"authorization claim", state)
		}
	}

	// And each of the three reads carrying a rejection rather than a refusal.
	for _, step := range []domain.Step{
		servicekubernetes.StepService,
		servicekubernetes.StepPodSet,
		servicekubernetes.StepEndpointPublication,
	} {
		for _, state := range everyState() {
			if !admissible(state, domain.FailureAuthCredentialsRejected) {
				continue
			}
			spec := healthy()
			rejected := node{
				step: step, layer: domain.LayerTopology,
				state: state, failureClass: domain.FailureAuthCredentialsRejected,
			}
			switch step {
			case servicekubernetes.StepService:
				spec.service = rejected
			case servicekubernetes.StepPodSet:
				spec.podSet = rejected
			case servicekubernetes.StepEndpointPublication:
				spec.publication = rejected
			}
			if hasCode(spec.evaluate(t), f2) {
				t.Errorf("%s in state %s with a rejected credential produced an "+
					"authorization claim", step, state)
			}
		}
	}
}

// TestKP04OnlyAStructuredNotFoundOnTheServiceReadProducesTheAbsenceClaim.
//
// The predicate is a state and a failure class the adapter derived from an HTTP
// status and a `metav1.StatusReason`. Nothing else may reach it — including the
// same class on a different node, which is the reachable mistake: a `LIST`
// answered `404` is the ordinary way a namespace that does not exist reports
// itself, and it says nothing about the Service.
func TestKP04OnlyAStructuredNotFoundOnTheServiceReadProducesTheAbsenceClaim(t *testing.T) {
	// The class on the wrong node, in every state.
	for _, step := range []domain.Step{
		servicekubernetes.StepTarget,
		servicekubernetes.StepAPIAccess,
		servicekubernetes.StepPodSet,
		servicekubernetes.StepEndpointPublication,
	} {
		for _, state := range everyState() {
			if !admissible(state, domain.FailureResourceNotFound) {
				continue
			}
			spec := healthy()
			wrong := node{
				step: step, layer: domain.LayerTopology,
				state: state, failureClass: domain.FailureResourceNotFound,
			}
			switch step {
			case servicekubernetes.StepTarget:
				wrong.layer = domain.LayerInput
				spec.target = wrong
			case servicekubernetes.StepAPIAccess:
				wrong.layer = domain.LayerAuth
				spec.apiAccess = wrong
			case servicekubernetes.StepPodSet:
				spec.podSet = wrong
			case servicekubernetes.StepEndpointPublication:
				spec.publication = wrong
			}
			if hasCode(spec.evaluate(t), f1) {
				t.Errorf("%s in state %s carrying RESOURCE_NOT_FOUND produced the "+
					"Service-absence claim; only the Service read may", step, state)
			}
		}
	}

	// And the right node in the wrong state, or with the wrong class.
	for _, state := range everyState() {
		for _, class := range everyFailureClass() {
			if !admissible(state, class) {
				continue
			}
			admits := state == domain.StateFail &&
				class == domain.FailureResourceNotFound

			spec := healthy()
			spec.service = node{
				step: servicekubernetes.StepService, layer: domain.LayerTopology,
				state: state, failureClass: class,
			}
			if got := hasCode(spec.evaluate(t), f1); got != admits {
				t.Errorf("service read in state %s with class %s produced the absence "+
					"claim = %v, want %v", state, class, got, admits)
			}
		}
	}
}

// TestKP05ASelectorLessServiceNeverProducesEitherSemanticClaim.
//
// **An empty selector map is selector-less, not match-all.** That single
// misreading is the one that would turn a correctly configured selector-less
// Service into a claim that its backends vanished, so it is driven over every
// combination of what the two enumerations might have carried had they run.
func TestKP05ASelectorLessServiceNeverProducesEitherSemanticClaim(t *testing.T) {
	for _, pods := range []int64{0, 1, 4000} {
		for _, counts := range []publicationCounts{
			{}, {slices: 1, endpoints: 1}, {slices: 2, endpoints: 4, ready: 0},
		} {
			spec := healthy()
			spec.service = serviceNode(servicekubernetes.ServiceTypeClusterIP, false, 0)
			spec.podSet = podSetNode(true, pods)
			spec.publication = publicationNode(counts)

			findings := spec.evaluate(t)
			if hasCode(findings, f3) || hasCode(findings, f4) {
				t.Errorf("a selector-less Service produced %v", codesOf(findings))
			}
		}
	}
}

// TestKP06AnUnsupportedServiceTypeNeverProducesEitherSemanticClaim.
//
// `ExternalName` publishes no backend at all, and an unrecognized type — a
// future one, or a hostile `spec.type` the adapter normalized to `UNKNOWN` — is
// treated as unsupported. **An unrecognized value never unlocks behaviour**, and
// the check is an allowlist rather than a denylist so that a type nobody
// anticipated falls outside it by default.
func TestKP06AnUnsupportedServiceTypeNeverProducesEitherSemanticClaim(t *testing.T) {
	unsupported := []string{
		servicekubernetes.ServiceTypeExternalName,
		servicekubernetes.ServiceTypeUnknown,
		"", "clusterip", "ClusterIp", "CLUSTERIP", "Headless", "Ingress",
		"ClusterIP\x00", " ClusterIP", "ClusterIP ", "\x1b[31mClusterIP",
	}

	for _, serviceType := range unsupported {
		spec := healthy()
		spec.service = serviceNode(serviceType, true, 2)
		spec.podSet = podSetNode(true, 0)
		spec.publication = publicationNode(publicationCounts{})

		findings := spec.evaluate(t)
		if hasCode(findings, f3) || hasCode(findings, f4) {
			t.Errorf("Service type %q produced %v; the supported set is exactly "+
				"ClusterIP, NodePort and LoadBalancer", serviceType, codesOf(findings))
		}
	}

	// The complement, so the allowlist is not vacuously narrow.
	for _, serviceType := range []string{
		servicekubernetes.ServiceTypeClusterIP,
		servicekubernetes.ServiceTypeNodePort,
		servicekubernetes.ServiceTypeLoadBalancer,
	} {
		spec := healthy()
		spec.service = serviceNode(serviceType, true, 2)
		spec.podSet = podSetNode(true, 0)
		if !hasCode(spec.evaluate(t), f3) {
			t.Errorf("Service type %q produced no selector claim; the supported types "+
				"must actually be supported", serviceType)
		}
	}
}

// TestKP07AnyReadyEndpointSuppressesThePublicationClaim.
//
// One is enough. The claim is an existence claim over the published set, so a
// threshold of any kind would be this finding grading a cluster rather than
// restating what it publishes.
func TestKP07AnyReadyEndpointSuppressesThePublicationClaim(t *testing.T) {
	for _, ready := range []int64{1, 2, 7, 10000} {
		spec := healthy()
		spec.publication = publicationNode(publicationCounts{
			slices: 4, endpoints: 10000, ready: ready, terminating: 10000 - ready,
		})
		if hasCode(spec.evaluate(t), f4) {
			t.Errorf("%d ready endpoints still produced a no-ready-endpoint claim", ready)
		}
	}
}

// TestKP08AnyMatchingPodSuppressesTheSelectorClaim.
func TestKP08AnyMatchingPodSuppressesTheSelectorClaim(t *testing.T) {
	for _, pods := range []int64{1, 2, 500, 4000} {
		spec := healthy()
		spec.podSet = podSetNode(true, pods)
		if hasCode(spec.evaluate(t), f3) {
			t.Errorf("%d matching Pods still produced a selector claim", pods)
		}
	}
}

// TestKP09TheTwoSemanticClaimsAreDisjoint.
//
// ADR 0094 section 10.3 makes them so, and this drives every combination of the
// two branches to show that no input produces both.
//
// It also drives the case the disjointness is *not* about: a Pod branch that was
// denied or incomplete leaves the publication claim alone, because the two sets
// are siblings under the Service node rather than a chain and one branch failing
// never erases the other's independent evidence (ADR 0094 section 10.8).
func TestTestKP09TheTwoSemanticClaimsAreDisjoint(t *testing.T) {
	podBranches := map[string]node{
		"complete and empty": podSetNode(true, 0),
		"complete with pods": podSetNode(true, 3),
		"incomplete":         podSetNode(false, 0),
		"denied":             denied(servicekubernetes.StepPodSet),
		"skipped":            skipped(servicekubernetes.StepPodSet, domain.FailureExecCancelled, servicekubernetes.StepService),
		"answered 404":       {step: servicekubernetes.StepPodSet, layer: domain.LayerTopology, state: domain.StateFail, failureClass: domain.FailureResourceNotFound},
	}
	sliceBranches := map[string]node{
		"no slice":   publicationNode(publicationCounts{}),
		"none ready": publicationNode(publicationCounts{slices: 1, endpoints: 2, ready: 0}),
		"one ready":  publicationNode(publicationCounts{slices: 1, endpoints: 2, ready: 1}),
		"incomplete": publicationNode(publicationCounts{slices: 1, incomplete: true}),
		"denied":     denied(servicekubernetes.StepEndpointPublication),
		"skipped":    skipped(servicekubernetes.StepEndpointPublication, domain.FailureExecCancelled, servicekubernetes.StepService),
	}

	for podName, pods := range podBranches {
		for sliceName, slices := range sliceBranches {
			spec := healthy()
			spec.podSet = pods
			spec.publication = slices
			findings := spec.evaluate(t)

			if hasCode(findings, f3) && hasCode(findings, f4) {
				t.Errorf("%s + %s produced both semantic claims; ADR 0094 section 10.3 "+
					"makes them disjoint so that one impact is never described twice at "+
					"one severity", podName, sliceName)
			}

			// The independence half: with the Pod branch unable to establish a
			// selector claim, the publication branch answers for itself.
			independent := podName == "incomplete" || podName == "denied" ||
				podName == "skipped" || podName == "answered 404"
			publishes := sliceName == "no slice" || sliceName == "none ready"
			if independent && publishes && !hasCode(findings, f4) {
				t.Errorf("%s + %s withheld the publication claim; the slice branch holds "+
					"complete authoritative evidence and one branch failing never erases "+
					"the other's (ADR 0094 section 10.8)", podName, sliceName)
			}
		}
	}
}

// TestKP10AnUnknownAttributeCanNeverStrengthenAClaim.
//
// Less evidence must never produce a stronger claim. This adds attribute keys no
// Kubernetes node carries, with values a rule might be tempted by, and requires
// the findings to be byte-identical to the run without them.
func TestKP10AnUnknownAttributeCanNeverStrengthenAClaim(t *testing.T) {
	extras := map[domain.AttributeKey]domain.AttrValue{
		"k8s.pod_ready_count":    domain.IntAttr(0),
		"k8s.replicas":           domain.IntAttr(0),
		"k8s.pod_phase":          domain.StringAttr("CrashLoopBackOff"),
		"k8s.reachable":          domain.BoolAttr(false),
		"k8s.selector_matches":   domain.BoolAttr(false),
		"k8s.serving_count":      domain.IntAttr(0),
		"k8s.endpoint_addresses": domain.StringListAttr("10.0.0.1"),
		"k8s.status_message":     domain.StringAttr("services not found"),
	}

	for name, spec := range everyScenario() {
		want := renderFindings(spec.evaluate(t))

		enriched := spec
		for _, target := range []*node{
			&enriched.target, &enriched.apiAccess, &enriched.service,
			&enriched.podSet, &enriched.publication,
		} {
			if target.omit {
				continue
			}
			merged := map[domain.AttributeKey]domain.AttrValue{}
			for key, value := range target.attributes {
				merged[key] = value
			}
			for key, value := range extras {
				merged[key] = value
			}
			target.attributes = merged
		}

		if got := renderFindings(enriched.evaluate(t)); got != want {
			t.Errorf("%s: unknown attributes changed the findings.\n\ngot\n%s\nwant\n%s",
				name, got, want)
		}
	}
}

// K-P11 (no relation producer is activated) and K-P12 (the rules import nothing
// below diagnosis) are **source properties**, not behavioural ones, so they live
// in test/security with the repository's other architecture guards:
// TestNoKubernetesRuleActivatesAnEvidenceRelation and
// TestTheKubernetesRulesImportNothingBelowDiagnosis. They were written here
// first and moved when `depguard`'s `diagnosis-is-pure` list refused `os` from
// this package, tests included — which is the rule working: a package that must
// not read a file must not read one in order to prove that it does not.

// TestKP13EveryRecommendationSurvivesTheSafetyValidator.
//
// It is checked inside the contract test too; this states it as a property over
// the generated space rather than over the frozen table, because the validator
// is what stops a helpful contributor pasting the command they debugged with.
func TestKP13EveryRecommendationSurvivesTheSafetyValidator(t *testing.T) {
	checked := 0
	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			for _, recommendation := range finding.Recommendations() {
				checked++
				if err := diagnosis.ValidateActionText(recommendation.Action()); err != nil {
					t.Errorf("%s/%s: %v", name, finding.Code(), err)
				}
				if err := diagnosis.ValidateActionText(recommendation.Rationale()); err != nil {
					// A rationale is prose too, and the same rules apply to it:
					// it is report-visible since Phase 10.4B.
					t.Errorf("%s/%s rationale: %v", name, finding.Code(), err)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no recommendation was checked; this guard would pass vacuously")
	}
}

// TestKP14TheRulesMutateNothing.
//
// A rule receives a frozen graph and the type already enforces it, so this
// asserts the observable consequence: evaluating twice, in either order, leaves
// both rules producing what they produced alone.
func TestKP14TheRulesMutateNothing(t *testing.T) {
	for name, spec := range everyScenario() {
		graph := spec.build(t, nil)
		ctx := diagnosis.RuleContext{Graph: graph}

		rules := productionRules()
		acquisitionFirst := renderFindings(append(
			append([]domain.Finding{}, rules[0].eval(ctx)...), rules[1].eval(ctx)...))
		backendsFirst := renderFindings(append(
			append([]domain.Finding{}, rules[1].eval(ctx)...), rules[0].eval(ctx)...))

		// The same findings, in whichever order they were computed.
		if sortedLines(acquisitionFirst) != sortedLines(backendsFirst) {
			t.Errorf("%s: running the rules in the other order changed the result.\n\n"+
				"%s\nvs\n%s", name, acquisitionFirst, backendsFirst)
		}
		if got := len(graph.Nodes()); got != len(spec.build(t, nil).Nodes()) {
			t.Errorf("%s: the graph changed size during evaluation", name)
		}
	}
}

// TestKP15NoScenarioProducesMoreFindingsThanItsEvidenceAdmits.
//
// The absolute ceiling: one F1, at most two F2 in a run where the Service read
// succeeded, one F3 and one F4 — and F3 and F4 never together. Anything above it
// means a rule started producing a finding per something other than a node.
func TestKP15NoScenarioProducesMoreFindingsThanItsEvidenceAdmits(t *testing.T) {
	for name, spec := range everyScenario() {
		counts := map[domain.FindingCode]int{}
		for _, finding := range spec.evaluate(t) {
			counts[finding.Code()]++
		}
		if counts[f1] > 1 {
			t.Errorf("%s produced %d absence claims; there is one Service read", name, counts[f1])
		}
		if counts[f2] > 2 {
			t.Errorf("%s produced %d refusal claims; at most two reads can be refused in "+
				"one run, because a refused Service read stops the other two", name, counts[f2])
		}
		if counts[f3] > 1 {
			t.Errorf("%s produced %d selector claims; there is one Pod enumeration",
				name, counts[f3])
		}
		if counts[f4] > 1 {
			t.Errorf("%s produced %d publication claims; there is one slice enumeration",
				name, counts[f4])
		}
	}
}

func sortedLines(s string) string {
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	for i := 1; i < len(lines); i++ {
		for j := i; j > 0 && lines[j] < lines[j-1]; j-- {
			lines[j], lines[j-1] = lines[j-1], lines[j]
		}
	}
	return strings.Join(lines, "\n")
}
