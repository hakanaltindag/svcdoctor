package kubernetes_test

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// Diagnosis-layer fuzzing.
//
// # What is fuzzed, and what deliberately is not
//
// The **normalized attribute space** — the Service type string, the two boolean
// shapes, and the six counts — plus the states and failure classes the five
// nodes can carry. That is the whole of a rule's input, so it is the whole of
// what a rule can be surprised by.
//
// Kubernetes objects, the API transport and pagination are **not** fuzzed here.
// They are Phase 12.1B's and are fuzzed there against a hermetic server, over
// five targets. A rule never sees one.
//
// The invariants below are the ones that must hold for *every* input, including
// the ones nobody would write: no panic, a deterministic result, never a fifth
// code, never a universal claim from an incomplete set, never an unsafe
// recommendation, and never a fuzz-supplied byte in prose.

// FuzzTheKubernetesRulesOverTheNormalizedAttributeSpace.
func FuzzTheKubernetesRulesOverTheNormalizedAttributeSpace(f *testing.F) {
	// The seeds are the reachable shapes, so the corpus starts where the
	// contract lives rather than at zero.
	f.Add("ClusterIP", true, true, int64(0), true, int64(0), int64(0), int64(0), int64(0), uint8(0))
	f.Add("ClusterIP", true, true, int64(3), true, int64(1), int64(2), int64(2), int64(0), uint8(0))
	f.Add("ClusterIP", true, false, int64(0), false, int64(0), int64(0), int64(0), int64(0), uint8(1))
	f.Add("ExternalName", false, true, int64(0), true, int64(0), int64(0), int64(0), int64(0), uint8(2))
	f.Add("NodePort", true, true, int64(1), true, int64(2), int64(4), int64(0), int64(4), uint8(3))
	f.Add("LoadBalancer", true, true, int64(0), true, int64(0), int64(0), int64(0), int64(0), uint8(4))
	f.Add("UNKNOWN", true, true, int64(0), true, int64(0), int64(0), int64(0), int64(0), uint8(5))
	f.Add("", false, false, int64(-1), false, int64(-1), int64(-1), int64(-1), int64(-1), uint8(6))
	// A three-byte Service type, kept as a seed because it is where the first
	// version of this target failed — on a defect in the *check* rather than in
	// the rules. See closedProse.
	f.Add("clu", true, true, int64(0), true, int64(0), int64(0), int64(0), int64(0), uint8(3))

	// The closed prose set, computed once from the deterministic matrix. See
	// closedProse for why this replaced a substring scan.
	allowed := closedProse(f)

	f.Fuzz(func(
		t *testing.T,
		serviceType string,
		selectorPresent bool,
		podsComplete bool, podCount int64,
		slicesComplete bool, sliceCount, endpointCount, readyCount, terminatingCount int64,
		shape uint8,
	) {
		// A hostile Service type is the one string a rule reads, so it is
		// bounded here only to keep the corpus readable — the rule itself
		// applies an allowlist and needs no bound.
		if len(serviceType) > 256 {
			t.Skip()
		}

		spec := fuzzSpec(
			serviceType, selectorPresent,
			podsComplete, podCount,
			slicesComplete, sliceCount, endpointCount, readyCount, terminatingCount,
			shape)

		graph := spec.build(t, nil)
		findings := evaluateGraph(t, graph)

		// Deterministic: the same frozen graph gives the same bytes.
		if first, second := renderFindings(findings),
			renderFindings(evaluateGraph(t, graph)); first != second {
			t.Fatalf("two evaluations of one graph differ:\n%s\nvs\n%s", first, second)
		}

		permitted := map[domain.FindingCode]bool{f1: true, f2: true, f3: true, f4: true}
		counts := map[domain.FindingCode]int{}

		for _, finding := range findings {
			if !permitted[finding.Code()] {
				t.Fatalf("produced %s, which is not one of the four frozen codes",
					finding.Code())
			}
			counts[finding.Code()]++

			// **Nothing the fuzzer supplied reaches prose**, stated as
			// membership in a closed set rather than as a substring scan.
			if prose := proseOf(finding); !allowed[prose] {
				t.Fatalf("%s produced prose the deterministic matrix never does, so "+
					"something the fuzzer supplied reached it.\n\n--- prose ---\n%s",
					finding.Code(), prose)
			}

			// Every recommendation is a next observation that changes nothing.
			for _, recommendation := range finding.Recommendations() {
				if recommendation.Kind() != diagnosis.AdviceKindNextEvidence {
					t.Fatalf("%s produced a %s recommendation",
						finding.Code(), recommendation.Kind())
				}
				switch recommendation.Safety() {
				case diagnosis.SafetyObserve, diagnosis.SafetyVerify, diagnosis.SafetyCompare:
				default:
					t.Fatalf("%s produced a %s recommendation",
						finding.Code(), recommendation.Safety())
				}
				if recommendation.SelfCollectable() {
					t.Fatalf("%s claims svcdoctor could take its own next observation",
						finding.Code())
				}
			}
		}

		// The arity ceiling: one of each semantic claim, and never both.
		if counts[f3] > 1 || counts[f4] > 1 || counts[f1] > 1 {
			t.Fatalf("produced %v; there is one of each node", counts)
		}
		if counts[f3] > 0 && counts[f4] > 0 {
			t.Fatalf("produced both semantic claims; ADR 0094 section 10.3 makes them " +
				"disjoint")
		}

		// **Incomplete never becomes a universal claim.** This is the invariant
		// the whole completeness contract exists for, and the fuzzer reaches it
		// from every combination of counts.
		if !podsComplete && counts[f3] > 0 {
			t.Fatalf("an incomplete Pod set produced a selector claim")
		}
		if !slicesComplete && counts[f4] > 0 {
			t.Fatalf("an incomplete slice set produced a publication claim")
		}
		if !selectorPresent && (counts[f3] > 0 || counts[f4] > 0) {
			t.Fatalf("a selector-less Service produced a semantic claim")
		}
		if readyCount > 0 && counts[f4] > 0 {
			t.Fatalf("%d ready endpoints still produced a no-ready-endpoint claim",
				readyCount)
		}
		if podCount > 0 && counts[f3] > 0 {
			t.Fatalf("%d matching Pods still produced a selector claim", podCount)
		}
		switch serviceType {
		case servicekubernetes.ServiceTypeClusterIP,
			servicekubernetes.ServiceTypeNodePort,
			servicekubernetes.ServiceTypeLoadBalancer:
		default:
			if counts[f3] > 0 || counts[f4] > 0 {
				t.Fatalf("Service type %q produced a semantic claim; the supported set "+
					"is exactly ClusterIP, NodePort and LoadBalancer", serviceType)
			}
		}
	})
}

// fuzzSpec assembles one graph from the fuzzed attribute space.
//
// `shape` selects among the reachable node outcomes, so the fuzzer explores the
// state and failure-class space as well as the counts. It is taken modulo the
// number of shapes, which is what lets the corpus supply any byte.
func fuzzSpec(
	serviceType string, selectorPresent bool,
	podsComplete bool, podCount int64,
	slicesComplete bool, sliceCount, endpointCount, readyCount, terminatingCount int64,
	shape uint8,
) graphSpec {
	spec := healthy()

	spec.service = serviceNode(serviceType, selectorPresent, 1)
	spec.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodSetComplete:   domain.BoolAttr(podsComplete),
			servicekubernetes.AttrPodObservedCount: domain.IntAttr(podCount),
		},
	}
	if !podsComplete {
		spec.podSet.state = domain.StateUnknown
		spec.podSet.failureClass = domain.FailureExecDepthLimit
	}
	spec.publication = node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrSliceSetComplete:         domain.BoolAttr(slicesComplete),
			servicekubernetes.AttrSliceCount:               domain.IntAttr(sliceCount),
			servicekubernetes.AttrEndpointCount:            domain.IntAttr(endpointCount),
			servicekubernetes.AttrReadyEndpointCount:       domain.IntAttr(readyCount),
			servicekubernetes.AttrTerminatingEndpointCount: domain.IntAttr(terminatingCount),
		},
	}
	if !slicesComplete {
		spec.publication.state = domain.StateUnknown
		spec.publication.failureClass = domain.FailureExecDepthLimit
	}

	switch shape % 7 {
	case 1:
		spec.service = serviceNotFound()
		spec.podSet = skipped(servicekubernetes.StepPodSet,
			domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
		spec.publication = skipped(servicekubernetes.StepEndpointPublication,
			domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	case 2:
		spec.service = denied(servicekubernetes.StepService)
		spec.podSet = skipped(servicekubernetes.StepPodSet,
			domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
		spec.publication = skipped(servicekubernetes.StepEndpointPublication,
			domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	case 3:
		spec.podSet = denied(servicekubernetes.StepPodSet)
	case 4:
		spec.publication = denied(servicekubernetes.StepEndpointPublication)
	case 5:
		spec.apiAccess = node{
			step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
			state: domain.StateFail, failureClass: domain.FailureAuthCredentialsRejected,
		}
	case 6:
		spec.podSet = denied(servicekubernetes.StepPodSet)
		spec.publication = denied(servicekubernetes.StepEndpointPublication)
	}
	return spec
}

// closedProse is every sentence the rules can produce, computed from the
// deterministic matrix.
//
// # Why membership rather than a substring scan
//
// The first version of this target asserted that the fuzzed Service type did not
// appear in the prose, and the fuzzer refuted it in nine seconds — with `"clu"`,
// which is a substring of *"the cluster"* in one of the frozen details. **The
// rules were right and the check was wrong**: a substring scan over English
// cannot tell an interpolation from a coincidence, and lengthening the minimum
// would only move the coincidence.
//
// Membership in a closed set is strictly stronger and has no collisions. Every
// sentence these rules can emit is a package constant or a `Sprintf` over one of
// three operation names, so the 44 deterministic scenarios already produce all of
// them — and any prose outside that set is, by construction, prose something
// else composed.
func closedProse(t testing.TB) map[string]bool {
	t.Helper()

	out := map[string]bool{}
	for _, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			out[proseOf(finding)] = true
		}
	}
	if len(out) == 0 {
		t.Fatal("the deterministic matrix produced no prose; this invariant would " +
			"reject everything and the failure would name the wrong cause")
	}
	return out
}
