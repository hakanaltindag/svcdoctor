package diagnosis_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskubernetes "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Kubernetes corpus: convergence, the failure boundary, the rendered
// artifacts, and the refusals.
//
// Everything here runs the production rule set over graphs the production
// adapter built, and inspects what a consumer actually receives — the canonical
// JSON, the shareable projection and the terminal output. A claim that appears
// in one and not the others is still a claim svcdoctor made.

// --- convergence -------------------------------------------------------------

// TestTwoDeniedReadsSurviveConvergenceAsTwoFindings is ADR 0094 section 10.9
// shape B, driven through the real `Converge`.
//
// # Why this is the shape that needed checking
//
// Both findings share a code and a subject, so they are convergence
// **candidates**: `SemanticIdentity` is `(Code, Subject)` and a Kubernetes run
// has exactly one subject. They also share a layer, a severity, a confidence and
// an empty discriminator. The only thing keeping them apart is the Detail, which
// ADR 0081 section 2.2b made a merge **precondition** — and if the operation
// name ever stopped reaching the prose, the two would merge into one claim
// naming one read while citing two.
//
// That is precisely the defect Phase 10.2A found three of in Kafka, so it is
// asserted here rather than reasoned about.
func TestTwoDeniedReadsSurviveConvergenceAsTwoFindings(t *testing.T) {
	result := backedService(t)
	result.Pods = failedList(client.OperationListPods, client.FailureForbidden)
	result.Publication = failedList(
		client.OperationListEndpointSlices, client.FailureForbidden)
	result.PublicationFacts = client.PublicationFacts{}

	r := diagnoseKubernetes(t, result)

	var denied []domain.Finding
	for _, finding := range r.report.Findings() {
		if finding.Code() == diagnosiskubernetes.CodeAPIAccessDenied {
			denied = append(denied, finding)
		}
	}
	if len(denied) != 2 {
		t.Fatalf("the report carries %d refusal findings, want 2.\n\n"+
			"Two reads were refused and two things are being said. Merging them would "+
			"publish one sentence naming one read while citing evidence from both, "+
			"which is the defect ADR 0081 section 2.2b exists to prevent.", len(denied))
	}

	// Same identity, so convergence really did consider them.
	if diagnosis.IdentityOf(denied[0]) != diagnosis.IdentityOf(denied[1]) {
		t.Fatal("the two refusals do not share a semantic identity, so this test would " +
			"pass without convergence ever having been asked the question")
	}

	// And between them they name both reads, each exactly once.
	prose := denied[0].Summary() + denied[0].Detail() +
		denied[1].Summary() + denied[1].Detail()
	for _, operation := range []string{"POD_LIST", "ENDPOINTSLICE_LIST"} {
		if !strings.Contains(prose, operation) {
			t.Errorf("neither refusal names %s", operation)
		}
	}
	if strings.Contains(denied[0].Summary(), "SERVICE_GET") ||
		strings.Contains(denied[1].Summary(), "SERVICE_GET") {
		t.Error("a refusal names the Service read, which succeeded")
	}
}

// TestAnIdenticalKubernetesFindingConvergesToOne is shape A.
//
// The complement of the test above: where two routes really do state one claim,
// byte for byte, convergence merges them and the evidence is the union. It is
// driven by wiring the same rule twice under two identities, which is the only
// way to reach the shape — a Kubernetes run holds one of each node — and it
// proves that the separation above comes from the prose rather than from the
// rules being unable to converge at all.
func TestAnIdenticalKubernetesFindingConvergesToOne(t *testing.T) {
	result := backedService(t)
	result.Pods = completeList(client.OperationListPods, 0)

	graph := recordAcquisition(t, result)
	r := diagnose(t, graph, false,
		namedRule{"kubernetes/backends", diagnosiskubernetes.Backends},
		namedRule{"kubernetes/backends-again", diagnosiskubernetes.Backends},
	)

	var selector []domain.Finding
	for _, finding := range r.report.Findings() {
		if finding.Code() == diagnosiskubernetes.CodeSelectsNoPods {
			selector = append(selector, finding)
		}
	}
	if len(selector) != 1 {
		t.Fatalf("two byte-identical claims produced %d findings, want 1; convergence "+
			"is what makes the same conclusion by two routes one conclusion",
			len(selector))
	}
	if got := len(selector[0].EvidenceRefs()); got != 2 {
		t.Errorf("the merged finding cites %d nodes, want 2 (the Service and the Pod set)",
			got)
	}
}

// TestRenamingTheKubernetesRulesChangesNoByte is ADR 0081 section 2.6a,
// instantiated for a fifth service.
//
// `RuleID` reaches no merged field at all, so the identities a composition root
// chooses are documentation rather than semantics. It is asserted here because a
// new service is exactly when somebody might reach for a rule name to break a
// tie.
func TestRenamingTheKubernetesRulesChangesNoByte(t *testing.T) {
	for name, result := range kubernetesCorpusResults(t) {
		graph := recordAcquisition(t, result)

		asWired := diagnose(t, graph, result.Incomplete(), kubernetesRules()...)
		renamed := diagnose(t, graph, result.Incomplete(),
			namedRule{"zzz-last/acquisition", diagnosiskubernetes.Acquisition},
			namedRule{"aaa-first/backends", diagnosiskubernetes.Backends},
		)

		if asWired.canonicalJSON(t) != renamed.canonicalJSON(t) {
			t.Errorf("%s: renaming the rules changed the canonical JSON", name)
		}
	}
}

// --- the failure boundary ----------------------------------------------------

// TestTheGenericFailureBoundaryLocalizesAKubernetesRun.
//
// No Kubernetes-specific boundary algorithm exists and none is authorized. The
// generic one needs only *a* PASS at a strictly lower layer, and a Kubernetes
// graph provides one at L0 — which is what ADR 0094 section 10.7 means by "both
// absences are deliberate and neither breaks the boundary", L1 through L4 being
// unused.
//
// The rows below are the reachable boundary shapes and the layers they sit
// between.
func TestTheGenericFailureBoundaryLocalizesAKubernetesRun(t *testing.T) {
	unauthorized := backedService(t)
	unauthorized.APIAccess = failedStage(client.FailureUnauthorized)
	unauthorized.Service = skippedStage(client.SkipAPIAccessFailed)
	unauthorized.ServiceFacts = client.ServiceFacts{}
	unauthorized.Pods = skippedList(client.OperationListPods, client.SkipAPIAccessFailed)
	unauthorized.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipAPIAccessFailed)

	notFound := backedService(t)
	notFound.Service = failedStage(client.FailureNotFound)
	notFound.ServiceFacts = client.ServiceFacts{}
	notFound.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
	notFound.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipServiceUnavailable)

	denied := backedService(t)
	denied.Pods = failedList(client.OperationListPods, client.FailureForbidden)

	cases := map[string]struct {
		result   client.Result
		expected bool
		lastGood domain.Layer
		failedAt domain.Layer
	}{
		"a healthy run has no boundary": {
			result: backedService(t), expected: false,
		},
		"a rejected identity fails at L5, after the L0 anchor passed": {
			result: unauthorized, expected: true,
			lastGood: domain.LayerInput, failedAt: domain.LayerAuth,
		},
		"an absent Service fails at L6, after the L5 access passed": {
			result: notFound, expected: true,
			lastGood: domain.LayerAuth, failedAt: domain.LayerTopology,
		},
		"a denied read is UNKNOWN and is therefore not a boundary": {
			result: denied, expected: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := diagnoseKubernetes(t, tc.result)
			boundaries := r.boundaries(t)

			if !tc.expected {
				if len(boundaries) != 0 {
					t.Fatalf("produced %d boundaries, want none.\n\n"+
						"A step that did not run is not a failure, and UNKNOWN is neither "+
						"half of a boundary.", len(boundaries))
				}
				return
			}
			if len(boundaries) != 1 {
				t.Fatalf("produced %d boundaries, want 1; a Kubernetes run has one subject",
					len(boundaries))
			}

			var boundary domain.Finding
			for _, f := range boundaries {
				boundary = f
			}
			if got := boundary.Layer(); got != tc.failedAt {
				t.Errorf("the boundary is at %s, want %s", got, tc.failedAt)
			}
			// The last-good half is named in the summary, from the generic
			// vocabulary. Checking it is what shows that the L1-L4 gap does not
			// break the contrast.
			if !strings.Contains(boundary.Summary(), tc.lastGood.Label()) {
				t.Errorf("the boundary does not name %s as the last good stage: %s",
					tc.lastGood.Label(), boundary.Summary())
			}
		})
	}
}

// TestAKubernetesFindingAndTheBoundaryCoexistWithoutOverridingEachOther.
//
// Two findings about one subject at one layer, with different codes, so
// convergence never considers them. `KUBERNETES_SERVICE_NOT_FOUND` states what
// happened and `DIAG_FAILURE_BOUNDARY` states where observation stopped
// succeeding; both are true and neither is the other's cause.
func TestAKubernetesFindingAndTheBoundaryCoexistWithoutOverridingEachOther(t *testing.T) {
	result := backedService(t)
	result.Service = failedStage(client.FailureNotFound)
	result.ServiceFacts = client.ServiceFacts{}
	result.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
	result.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipServiceUnavailable)

	r := diagnoseKubernetes(t, result)
	codes := findingCodes(r)

	if codes[diagnosiskubernetes.CodeServiceNotFound] != 1 {
		t.Errorf("the absence claim is absent: %v", codes)
	}
	if codes[diagnosis.CodeFailureBoundary] != 1 {
		t.Errorf("the boundary is absent: %v", codes)
	}
	if len(codes) != 2 {
		t.Errorf("produced %v, want exactly the two", codes)
	}

	// The severities are independent: the boundary is INFO because it describes
	// *where*, and the Kubernetes claim is ERROR because that is the impact of
	// what it states.
	for _, finding := range r.report.Findings() {
		switch finding.Code() {
		case diagnosis.CodeFailureBoundary:
			if finding.Severity() != domain.SeverityInfo {
				t.Errorf("the boundary is %s, want INFO", finding.Severity())
			}
		case diagnosiskubernetes.CodeServiceNotFound:
			if finding.Severity() != domain.SeverityError {
				t.Errorf("the absence claim is %s, want ERROR", finding.Severity())
			}
		}
	}
}

// --- the rendered artifacts ---------------------------------------------------

// TestTheKubernetesCanonicalJSONIsDeterministicAndCarriesNoNewShape.
//
// Two properties in one pass, because both are about the document a consumer
// parses. It must be byte-identical across evaluations of one measurement, and
// it must contain only the existing Finding representation — no Kubernetes
// section, no raw object, no new field.
func TestTheKubernetesCanonicalJSONIsDeterministicAndCarriesNoNewShape(t *testing.T) {
	for name, result := range kubernetesCorpusResults(t) {
		t.Run(name, func(t *testing.T) {
			graph := recordAcquisition(t, result)

			want := diagnose(t, graph, result.Incomplete(), kubernetesRules()...).canonicalJSON(t)
			for i := 0; i < 4; i++ {
				got := diagnose(
					t, graph, result.Incomplete(), kubernetesRules()...).canonicalJSON(t)
				if got != want {
					t.Fatalf("render %d differs from the first", i)
				}
			}

			// The schema is unchanged, which is what "additive vocabulary" means:
			// four finding codes and two rules are new, and not one field is.
			if !strings.Contains(want, `"schemaVersion":1`) {
				t.Errorf("the canonical JSON does not declare schema version 1")
			}
			// `"status":` is deliberately absent from this list: the report's own
			// summary carries one, and forbidding the substring would forbid a
			// field that predates Kubernetes by ten phases. What is forbidden is
			// the shape of a Kubernetes *object*.
			for _, forbidden := range []string{
				`"pods":`, `"endpointSlices":`, `"kubernetes":`,
				`"apiVersion":`, `"metadata":`, `"spec":`, `"kind":"Status"`,
				`"labels":`, `"selector":`, `"conditions":`,
			} {
				if strings.Contains(want, forbidden) {
					t.Errorf("the canonical JSON carries %s; a Kubernetes report is the "+
						"existing report shape and nothing more", forbidden)
				}
			}
		})
	}
}

// TestTheShareableProjectionOfAKubernetesReportStillReads.
//
// docs/FINDINGS.md section 3.1 rule 16: read the finding with every host and
// name replaced before deciding it reads well. The namespace and the Service
// name are `AttrKindIdentity`, so redaction pseudonymizes them — and the prose,
// which carries neither, is unchanged.
func TestTheShareableProjectionOfAKubernetesReportStillReads(t *testing.T) {
	for name, result := range kubernetesCorpusResults(t) {
		t.Run(name, func(t *testing.T) {
			r := diagnoseKubernetes(t, result)

			local := claimProse(r.report.Findings())
			shareable := claimProse(r.shareable.Findings())
			if local != shareable {
				t.Errorf("redaction changed a Kubernetes finding's prose.\n\n"+
					"A finding whose prose must be rewritten to be shareable is a finding "+
					"that will leak the day somebody edits it (docs/FINDINGS.md section "+
					"3.1 rule 15).\n\nlocal:\n%s\n\nshareable:\n%s", local, shareable)
			}

			for _, leaked := range []string{"payments-api", "payments"} {
				if strings.Contains(r.shareableJSON(t), leaked) {
					t.Errorf("the shareable projection still carries %q", leaked)
				}
			}
		})
	}
}

// TestTheTerminalRendersKubernetesFindingsWithoutAServiceSpecificBranch.
//
// The renderer's `serviceView` table has no Kubernetes row, so a Kubernetes
// report renders through the zero view — an empty journey, no outcome line, no
// advertisement level — and the findings block, which is service-neutral. Phase
// 12.1C changes **no renderer file**, and this is the assertion that says the
// output is nonetheless correct rather than merely unchanged.
func TestTheTerminalRendersKubernetesFindingsWithoutAServiceSpecificBranch(t *testing.T) {
	result := backedService(t)
	result.Pods = completeList(client.OperationListPods, 0)

	terminal := diagnoseKubernetes(t, result).terminal(t)

	for _, want := range []string{
		"KUBERNETES_SERVICE_SELECTS_NO_PODS",
		"selector matched no Pod",
		"Compare this Service's selector",
	} {
		if !strings.Contains(terminal, want) {
			t.Errorf("the terminal output does not contain %q:\n%s", want, terminal)
		}
	}
	// And nothing a cluster chose leaks into it.
	for _, control := range []string{"\x1b[31m", "\r"} {
		if strings.Contains(terminal, control) {
			t.Errorf("the terminal output contains %q", control)
		}
	}
}

// --- the refusals -------------------------------------------------------------

// TestTheKubernetesFalsePositiveCorpus is release-blocking.
//
// Every other test asks whether svcdoctor said the right thing; this asks
// whether it refused to say the wrong one, which is the property that decays
// silently. Each row is a scenario a real cluster produces and a list of claims
// that must appear nowhere in what svcdoctor *says* — the summary, the detail,
// the discriminator and the recommendations, in both the local and the shareable
// report.
func TestTheKubernetesFalsePositiveCorpus(t *testing.T) {
	notFound := backedService(t)
	notFound.Service = failedStage(client.FailureNotFound)
	notFound.ServiceFacts = client.ServiceFacts{}
	notFound.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
	notFound.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipServiceUnavailable)

	denied := backedService(t)
	denied.Pods = failedList(client.OperationListPods, client.FailureForbidden)

	scaledToZero := backedService(t)
	scaledToZero.Pods = completeList(client.OperationListPods, 0)

	allTerminating := backedService(t)
	allTerminating.PublicationFacts = client.PublicationFacts{
		Slices: 1, Endpoints: 3, ReadyEndpoints: 0, TerminatingEndpoints: 3,
	}

	truncated := backedService(t)
	truncated.Pods = truncatedList(client.OperationListPods, client.StopObjectLimit, 4000)
	truncated.Publication = truncatedList(
		client.OperationListEndpointSlices, client.StopEndpointLimit, 256)
	truncated.PublicationFacts = client.PublicationFacts{
		Slices: 256, Endpoints: 10000, ReadyEndpoints: 0,
	}

	cases := map[string]struct {
		result    client.Result
		forbidden []forbiddenClaim
	}{
		"K-FP01 an absent Service is not a history and not an operator mistake": {
			result: notFound,
			forbidden: []forbiddenClaim{
				{"was deleted", "svcdoctor did not observe the Service existing and " +
					"then stopping; a NotFound is one moment"},
				{"never existed", "the same, in the other direction"},
				{"namespace is wrong", "svcdoctor does not know what the operator meant"},
				{"create the Service", "absence may be exactly what somebody arranged"},
			},
		},
		"K-FP02 a denied read is never emptiness": {
			result: denied,
			forbidden: []forbiddenClaim{
				{"no Pods", "the set the read would have produced is unavailable, which " +
					"is a different fact from empty"},
				{"selector matched", "nothing was matched because nothing was listed"},
				{"RBAC", "a 403 says the read was refused, not why the policy says so"},
				{"cluster-admin", "svcdoctor never recommends widening a permission"},
			},
		},
		"K-FP03 a workload deliberately held at zero is reported, not judged": {
			result: scaledToZero,
			forbidden: []forbiddenClaim{
				{"selector is wrong", "a selector doing exactly what it was written to " +
					"do produces this observation"},
				{"Deployment", "svcdoctor read no Deployment"},
				{"unhealthy", "svcdoctor read no Pod field at all"},
				{"unreachable", "svcdoctor connected to nothing"},
			},
		},
		"K-FP04 no ready endpoint is not no traffic": {
			result: allTerminating,
			forbidden: []forbiddenClaim{
				{"unreachable", "a proxy may still route to terminating endpoints"},
				{"cannot connect", "svcdoctor connected to nothing"},
				{"application is unavailable", "publication is not availability"},
				{"readiness probe", "svcdoctor read no probe and no Pod condition"},
			},
		},
		"K-FP05 a truncated enumeration supports no universal claim": {
			result: truncated,
			forbidden: []forbiddenClaim{
				{"selector matched no Pod", "the Pod enumeration reached svcdoctor's own " +
					"object budget and its count is observed-so-far, not a total"},
				{"published no ready endpoint", "the slice enumeration reached the " +
					"endpoint ceiling and its counts are not totals"},
				{"no Pod", "no universal claim may be made over an incomplete set"},
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertRefuses(t, diagnoseKubernetes(t, tc.result), tc.forbidden)
		})
	}
}

// TestNoKubernetesRunEverMentionsAMechanismItCannotObserve.
//
// The stronger check, over the whole document rather than over the claims: a
// mechanism svcdoctor never observes has no business in an evidence attribute
// either, because an attribute is where an adapter-invented string would arrive.
func TestNoKubernetesRunEverMentionsAMechanismItCannotObserve(t *testing.T) {
	forbidden := []forbiddenClaim{
		{"kube-proxy", "svcdoctor observed no proxy"},
		{"NetworkPolicy", "svcdoctor observed no NetworkPolicy"},
		{"Cilium", "svcdoctor observed no CNI"},
		{"CrashLoopBackOff", "no Pod field is in the graph"},
		{"OOMKilled", "no Pod field is in the graph"},
		{"ImagePullBackOff", "no Pod field is in the graph"},
		{"Ingress", "svcdoctor read no Ingress"},
		{"Gateway", "svcdoctor read no Gateway"},
		{"kubelet", "svcdoctor observed no kubelet"},
		{"etcd", "svcdoctor observed no etcd"},
	}

	for name, result := range kubernetesCorpusResults(t) {
		t.Run(name, func(t *testing.T) {
			assertAbsentEverywhere(t, diagnoseKubernetes(t, result), forbidden)
		})
	}
}

// kubernetesCorpusResults is the acquisition set every whole-document property
// runs over.
//
// It is deliberately smaller than the rule package's 44-scenario matrix: these
// are the shapes a real cluster produces, and each one is rendered three times,
// so the set is chosen for coverage of the *rendered* document rather than of
// the admission predicates.
func kubernetesCorpusResults(t *testing.T) map[string]client.Result {
	t.Helper()

	out := map[string]client.Result{}
	out["ready backends"] = backedService(t)

	notFound := backedService(t)
	notFound.Service = failedStage(client.FailureNotFound)
	notFound.ServiceFacts = client.ServiceFacts{}
	notFound.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
	notFound.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipServiceUnavailable)
	out["absent Service"] = notFound

	denied := backedService(t)
	denied.Pods = failedList(client.OperationListPods, client.FailureForbidden)
	denied.Publication = failedList(
		client.OperationListEndpointSlices, client.FailureForbidden)
	denied.PublicationFacts = client.PublicationFacts{}
	out["both list reads refused"] = denied

	selectsNothing := backedService(t)
	selectsNothing.Pods = completeList(client.OperationListPods, 0)
	out["selector matched nothing"] = selectsNothing

	noSlice := backedService(t)
	noSlice.Publication = completeList(client.OperationListEndpointSlices, 0)
	noSlice.PublicationFacts = client.PublicationFacts{}
	out["nothing published"] = noSlice

	terminating := backedService(t)
	terminating.PublicationFacts = client.PublicationFacts{
		Slices: 1, Endpoints: 3, ReadyEndpoints: 0, TerminatingEndpoints: 3,
	}
	out["everything terminating"] = terminating

	unauthorized := backedService(t)
	unauthorized.APIAccess = client.Stage{
		Attempted: true, Failure: client.FailureUnauthorized,
		StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
	unauthorized.Service = skippedStage(client.SkipAPIAccessFailed)
	unauthorized.ServiceFacts = client.ServiceFacts{}
	unauthorized.Pods = skippedList(client.OperationListPods, client.SkipAPIAccessFailed)
	unauthorized.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipAPIAccessFailed)
	unauthorized.PublicationFacts = client.PublicationFacts{}
	out["identity not accepted"] = unauthorized

	truncated := backedService(t)
	truncated.Pods = truncatedList(client.OperationListPods, client.StopObjectLimit, 4000)
	out["Pod enumeration truncated"] = truncated

	selectorLess := backedService(t)
	selectorLess.ServiceFacts = client.ServiceFacts{Type: "ClusterIP"}
	selectorLess.Pods = skippedList(client.OperationListPods, client.SkipSelectorLess)
	selectorLess.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipSelectorLess)
	selectorLess.PublicationFacts = client.PublicationFacts{}
	out["selector-less Service"] = selectorLess

	return out
}
