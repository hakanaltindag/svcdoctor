package diagnosis_test

import (
	"strings"
	"testing"
	"time"

	adapterkubernetes "github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskubernetes "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The Kubernetes half of the production-path harness, added in Phase 12.1C.
//
// # It drives the real producer, and that is the point
//
// `internal/diagnosis/kubernetes`'s own tests build graphs directly, because a
// rule's input is a graph and because they must reach shapes the adapter cannot
// currently produce. This file states the complementary property: the rules
// agree with the graphs `internal/adapter/kubernetes.Record` **actually emits**
// from an acquisition result.
//
// That is the coupling nothing else checks. The rules read a state, a failure
// class and seven attribute keys; the adapter decides all of them. A change on
// either side that looked harmless in isolation — a Forbidden mapped to FAIL
// instead of UNKNOWN, a completeness flag recorded only when true — would break
// diagnosis silently, and every unit test on both sides would still pass.
//
// It is the same shape as the Kafka and PostgreSQL corpora, and it is deliberately
// **not** a second copy of the short-circuit matrix: the exhaustive matrix lives
// with the rules, and this drives the acquisition shapes a real cluster produces.

// kubernetesRules is the Kubernetes composition root's rule set, minus the
// boundary that `diagnose` adds for every scenario.
//
// It is written out rather than imported because internal/app is not importable
// from a test that also builds graphs by hand.
// TestTheKubernetesCompositionRootWiresExactlyThreeRules in test/security pins
// internal/app's own list, and this pins that the corpus runs the same one.
func kubernetesRules() []namedRule {
	return []namedRule{
		{"kubernetes/acquisition", diagnosiskubernetes.Acquisition},
		{"kubernetes/backends", diagnosiskubernetes.Backends},
	}
}

var kubernetesStart = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

// kubernetesTarget is the declared target every acquisition result in this file
// carries.
func kubernetesTarget(t *testing.T) client.Target {
	t.Helper()
	return client.Target{
		InCluster:   true,
		Namespace:   "payments",
		ServiceName: "payments-api",
	}
}

// recordAcquisition turns an acquisition result into the graph production would
// build from it.
func recordAcquisition(t *testing.T, result client.Result) domain.Graph {
	t.Helper()

	builder := domain.NewGraphBuilder()
	if _, err := adapterkubernetes.Record(builder, result, kubernetesStart); err != nil {
		t.Fatalf("Record: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

// okStage is a stage that ran and succeeded.
func okStage() client.Stage {
	return client.Stage{Attempted: true, StartedAt: kubernetesStart, Elapsed: time.Millisecond}
}

// failedStage is a stage that ran and produced a classified failure.
func failedStage(failure client.Failure) client.Stage {
	return client.Stage{
		Attempted: true, Failure: failure,
		StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
}

// skippedStage is a stage that never ran.
func skippedStage(reason client.SkipReason) client.Stage {
	return client.Stage{Attempted: false, Skip: reason}
}

// completeList is an enumeration that followed every page.
func completeList(op client.Operation, observed int) client.Enumeration {
	return client.Enumeration{
		Op: op, Attempted: true, Stop: client.StopComplete, Pages: 1,
		Observed: observed, StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
}

// truncatedList is an enumeration svcdoctor's own ceiling stopped.
func truncatedList(op client.Operation, stop client.StopReason, observed int) client.Enumeration {
	return client.Enumeration{
		Op: op, Attempted: true, Stop: stop, Pages: 8,
		Observed: observed, StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
}

// failedList is an enumeration a request-level failure ended.
func failedList(op client.Operation, failure client.Failure) client.Enumeration {
	return client.Enumeration{
		Op: op, Attempted: true, Stop: client.StopRequestFailed, Failure: failure,
		StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
}

// skippedList is an enumeration that was never issued.
func skippedList(op client.Operation, reason client.SkipReason) client.Enumeration {
	return client.Enumeration{Op: op, Attempted: false, Skip: reason}
}

// backedService is an acquisition that read everything and found backends.
func backedService(t *testing.T) client.Result {
	t.Helper()
	return client.Result{
		Target:    kubernetesTarget(t),
		Authority: client.Authority{Mode: "IN_CLUSTER"},
		APIAccess: okStage(),
		Service:   okStage(),
		ServiceFacts: client.ServiceFacts{
			Type: "ClusterIP", SelectorPresent: true, SelectorKeyCount: 2,
		},
		Pods:        completeList(client.OperationListPods, 3),
		Publication: completeList(client.OperationListEndpointSlices, 1),
		PublicationFacts: client.PublicationFacts{
			Slices: 1, Endpoints: 3, ReadyEndpoints: 3,
		},
		Requests: 3,
	}
}

// diagnoseKubernetes drives one acquisition result through the production
// pipeline.
func diagnoseKubernetes(t *testing.T, result client.Result) run {
	t.Helper()
	return diagnose(t, recordAcquisition(t, result), result.Incomplete(), kubernetesRules()...)
}

// findingCodes reduces a run's findings to a set.
func findingCodes(r run) map[domain.FindingCode]int {
	out := map[domain.FindingCode]int{}
	for _, finding := range r.report.Findings() {
		out[finding.Code()]++
	}
	return out
}

// TestTheKubernetesCorpusUsesTheProductionRuleSet.
//
// A corpus that ran a convenient subset would prove nothing about production.
// This is the same non-vacuity check the Kafka and PostgreSQL corpora carry.
func TestTheKubernetesCorpusUsesTheProductionRuleSet(t *testing.T) {
	rules := kubernetesRules()
	if len(rules) != 2 {
		t.Fatalf("%d Kubernetes rules in the corpus, want 2", len(rules))
	}
	want := map[string]bool{"kubernetes/acquisition": true, "kubernetes/backends": true}
	for _, rule := range rules {
		if !want[rule.id] {
			t.Errorf("%s is not one of the two production rules", rule.id)
		}
		if rule.rule == nil {
			t.Errorf("%s is nil", rule.id)
		}
	}
}

// TestTheRulesAgreeWithTheGraphTheAdapterActuallyProduces.
//
// The rows are acquisition results a real cluster can produce, and the exact
// Kubernetes findings each one must yield. `DIAG_FAILURE_BOUNDARY` is checked
// separately, because it is generic machinery whose behaviour is not this
// phase's contract.
func TestTheRulesAgreeWithTheGraphTheAdapterActuallyProduces(t *testing.T) {
	notFound := backedService(t)
	notFound.Service = failedStage(client.FailureNotFound)
	notFound.ServiceFacts = client.ServiceFacts{}
	notFound.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
	notFound.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipServiceUnavailable)

	serviceDenied := notFound
	serviceDenied.Service = failedStage(client.FailureForbidden)

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

	podsDenied := backedService(t)
	podsDenied.Pods = failedList(client.OperationListPods, client.FailureForbidden)

	slicesDenied := backedService(t)
	slicesDenied.Publication = failedList(
		client.OperationListEndpointSlices, client.FailureForbidden)
	slicesDenied.PublicationFacts = client.PublicationFacts{}

	bothDenied := podsDenied
	bothDenied.Publication = slicesDenied.Publication
	bothDenied.PublicationFacts = client.PublicationFacts{}

	selectsNothing := backedService(t)
	selectsNothing.Pods = completeList(client.OperationListPods, 0)

	noSlice := backedService(t)
	noSlice.Publication = completeList(client.OperationListEndpointSlices, 0)
	noSlice.PublicationFacts = client.PublicationFacts{}

	noneReady := backedService(t)
	noneReady.PublicationFacts = client.PublicationFacts{
		Slices: 2, Endpoints: 4, ReadyEndpoints: 0, TerminatingEndpoints: 4,
	}
	noneReady.Publication = completeList(client.OperationListEndpointSlices, 2)

	podsTruncated := backedService(t)
	podsTruncated.Pods = truncatedList(client.OperationListPods, client.StopObjectLimit, 4000)

	podsTruncatedAtZero := backedService(t)
	podsTruncatedAtZero.Pods = truncatedList(
		client.OperationListPods, client.StopPageLimit, 0)

	slicesExpired := backedService(t)
	slicesExpired.Publication = client.Enumeration{
		Op: client.OperationListEndpointSlices, Attempted: true,
		Stop: client.StopResourceExpired, Failure: client.FailureResourceExpired,
		StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
	slicesExpired.PublicationFacts = client.PublicationFacts{}

	slicesCancelled := backedService(t)
	slicesCancelled.Publication = client.Enumeration{
		Op: client.OperationListEndpointSlices, Attempted: true,
		Stop: client.StopCancelled, StartedAt: kubernetesStart, Elapsed: time.Millisecond,
	}
	slicesCancelled.PublicationFacts = client.PublicationFacts{}

	selectorLess := backedService(t)
	selectorLess.ServiceFacts = client.ServiceFacts{Type: "ClusterIP", SelectorPresent: false}
	selectorLess.Pods = skippedList(client.OperationListPods, client.SkipSelectorLess)
	selectorLess.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipSelectorLess)
	selectorLess.PublicationFacts = client.PublicationFacts{}

	externalName := selectorLess
	externalName.ServiceFacts = client.ServiceFacts{Type: "ExternalName"}
	externalName.Pods = skippedList(client.OperationListPods, client.SkipUnsupportedServiceType)
	externalName.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipUnsupportedServiceType)

	unknownType := backedService(t)
	unknownType.ServiceFacts = client.ServiceFacts{
		Type: "UNKNOWN", SelectorPresent: true, SelectorKeyCount: 1,
	}
	unknownType.Pods = skippedList(client.OperationListPods, client.SkipUnsupportedServiceType)
	unknownType.Publication = skippedList(
		client.OperationListEndpointSlices, client.SkipUnsupportedServiceType)
	unknownType.PublicationFacts = client.PublicationFacts{}

	headlessEmpty := backedService(t)
	headlessEmpty.ServiceFacts = client.ServiceFacts{
		Type: "ClusterIP", Headless: true, SelectorPresent: true, SelectorKeyCount: 1,
	}
	headlessEmpty.Pods = completeList(client.OperationListPods, 0)

	cases := map[string]struct {
		result client.Result
		want   map[domain.FindingCode]int
	}{
		"a Service with ready backends": {
			backedService(t), map[domain.FindingCode]int{},
		},
		"the API reported the Service absent": {
			notFound, map[domain.FindingCode]int{diagnosiskubernetes.CodeServiceNotFound: 1},
		},
		"the Service read was refused": {
			serviceDenied, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeAPIAccessDenied: 1},
		},
		"the identity was not accepted at all": {
			unauthorized, map[domain.FindingCode]int{},
		},
		"the Pod read was refused": {
			podsDenied, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeAPIAccessDenied: 1},
		},
		"the slice read was refused": {
			slicesDenied, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeAPIAccessDenied: 1},
		},
		"both list reads were refused": {
			bothDenied, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeAPIAccessDenied: 2},
		},
		"the selector matched nothing": {
			selectsNothing, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeSelectsNoPods: 1},
		},
		"nothing was published": {
			noSlice, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeNoReadyEndpoint: 1},
		},
		"everything published is terminating": {
			noneReady, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeNoReadyEndpoint: 1},
		},
		"the Pod enumeration hit the object budget": {
			podsTruncated, map[domain.FindingCode]int{},
		},
		"the Pod enumeration hit the page ceiling with nothing seen": {
			podsTruncatedAtZero, map[domain.FindingCode]int{},
		},
		"the slice enumeration's continue token expired": {
			slicesExpired, map[domain.FindingCode]int{},
		},
		"the slice enumeration was cancelled": {
			slicesCancelled, map[domain.FindingCode]int{},
		},
		"the Service selects nothing by label": {
			selectorLess, map[domain.FindingCode]int{},
		},
		"the Service is an ExternalName": {
			externalName, map[domain.FindingCode]int{},
		},
		"the Service's type is one this build does not recognize": {
			unknownType, map[domain.FindingCode]int{},
		},
		"a headless Service whose selector matched nothing": {
			headlessEmpty, map[domain.FindingCode]int{
				diagnosiskubernetes.CodeSelectsNoPods: 1},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := findingCodes(diagnoseKubernetes(t, tc.result))
			delete(got, diagnosis.CodeFailureBoundary)

			if len(got) != len(tc.want) {
				t.Fatalf("produced %v, want %v", got, tc.want)
			}
			for code, count := range tc.want {
				if got[code] != count {
					t.Errorf("produced %d %s, want %d", got[code], code, count)
				}
			}
		})
	}
}

// TestAnIncompleteEnumerationNeverProducesAUniversalClaim, driven through the
// producer at every stop reason it can record.
//
// This is the property that decays silently. Every one of these produces an
// `Observed` of zero — the enumeration stopped before seeing anything — and the
// zero is *observed so far* rather than a total. A rule that read the count
// without the completeness flag would emit a universal claim from every one of
// them.
func TestAnIncompleteEnumerationNeverProducesAUniversalClaim(t *testing.T) {
	stops := []client.StopReason{
		client.StopPageLimit,
		client.StopObjectLimit,
		client.StopEndpointLimit,
		client.StopResourceExpired,
		client.StopCancelled,
		client.StopRequestFailed,
	}

	for _, stop := range stops {
		t.Run("pods/"+stop.String(), func(t *testing.T) {
			result := backedService(t)
			result.Pods = truncatedList(client.OperationListPods, stop, 0)
			if findingCodes(diagnoseKubernetes(t, result))[diagnosiskubernetes.CodeSelectsNoPods] != 0 {
				t.Errorf("%s produced a selector claim from an incomplete set", stop)
			}
		})
		t.Run("slices/"+stop.String(), func(t *testing.T) {
			result := backedService(t)
			result.Publication = truncatedList(client.OperationListEndpointSlices, stop, 0)
			result.PublicationFacts = client.PublicationFacts{}
			if findingCodes(diagnoseKubernetes(t, result))[diagnosiskubernetes.CodeNoReadyEndpoint] != 0 {
				t.Errorf("%s produced a publication claim from an incomplete set", stop)
			}
		})
	}
}

// TestEveryClientFailureIsClassifiedByTheRulesOrDeliberatelyIgnored.
//
// The client's failure vocabulary is closed and has twelve members. Exactly two
// of them earn a Kubernetes finding, on exactly the nodes ADR 0094 section 2.8
// admits; the other ten are acquisition failures carrying an existing failure
// class, and produce none.
//
// Driving the whole enum is what makes "a thirteenth failure produces nothing"
// a fact rather than a hope: a new member arrives with no row here and lands in
// the default, which asserts silence.
func TestEveryClientFailureIsClassifiedByTheRulesOrDeliberatelyIgnored(t *testing.T) {
	failures := []client.Failure{
		client.FailureNone,
		client.FailureUnauthorized,
		client.FailureForbidden,
		client.FailureNotFound,
		client.FailureResourceExpired,
		client.FailureAPIError,
		client.FailureTransport,
		client.FailureTLSUnknownAuthority,
		client.FailureTLSHostnameMismatch,
		client.FailureTLSCertificateExpired,
		client.FailureTimeout,
		client.FailureCancelled,
	}

	for _, failure := range failures {
		t.Run("service/"+failure.String(), func(t *testing.T) {
			result := backedService(t)
			if failure != client.FailureNone {
				result.Service = failedStage(failure)
				result.ServiceFacts = client.ServiceFacts{}
				result.Pods = skippedList(
					client.OperationListPods, client.SkipServiceUnavailable)
				result.Publication = skippedList(
					client.OperationListEndpointSlices, client.SkipServiceUnavailable)
				result.PublicationFacts = client.PublicationFacts{}
			}

			got := findingCodes(diagnoseKubernetes(t, result))
			delete(got, diagnosis.CodeFailureBoundary)

			var want map[domain.FindingCode]int
			switch failure {
			case client.FailureNotFound:
				want = map[domain.FindingCode]int{diagnosiskubernetes.CodeServiceNotFound: 1}
			case client.FailureForbidden:
				want = map[domain.FindingCode]int{diagnosiskubernetes.CodeAPIAccessDenied: 1}
			default:
				want = map[domain.FindingCode]int{}
			}

			if len(got) != len(want) {
				t.Fatalf("%s produced %v, want %v.\n\n"+
					"Only a structured NotFound on the Service read and a structured "+
					"Forbidden on one of the three reads earn a Kubernetes code; every "+
					"other API outcome is an acquisition failure on its node "+
					"(ADR 0094 section 2.8).", failure, got, want)
			}
			for code, count := range want {
				if got[code] != count {
					t.Errorf("%s produced %d %s, want %d", failure, got[code], code, count)
				}
			}
		})
	}
}

// TestTheDeniedOperationNamesMatchTheAcquisitionVocabulary.
//
// # The one duplicated string set in the phase, and why it is duplicated
//
// `client.Operation` holds `SERVICE_GET`, `POD_LIST` and `ENDPOINTSLICE_LIST`
// for its own audit purposes, and `internal/diagnosis/kubernetes` holds the same
// three as **report prose**. Diagnosis may not import an adapter, so the two
// cannot share a constant — the package that writes prose owns its spelling, and
// an adapter's types never cross into diagnosis.
//
// That leaves exactly one drift risk: renaming an operation in one place and not
// the other, which would make a report say `POD_LIST` while every log, test and
// audit trail below it said something else. This test is the only thing in the
// tree that can see both, and it compares them by driving a real refusal at each
// operation and requiring the finding's prose to carry `Operation.String()`.
//
// It is named in `internal/diagnosis/kubernetes/acquisition.go`'s own doc
// comment, which is what makes that comment a statement about the build rather
// than about somebody's intentions.
func TestTheDeniedOperationNamesMatchTheAcquisitionVocabulary(t *testing.T) {
	cases := map[client.Operation]func(client.Result) client.Result{
		client.OperationGetService: func(r client.Result) client.Result {
			r.Service = failedStage(client.FailureForbidden)
			r.ServiceFacts = client.ServiceFacts{}
			r.Pods = skippedList(client.OperationListPods, client.SkipServiceUnavailable)
			r.Publication = skippedList(
				client.OperationListEndpointSlices, client.SkipServiceUnavailable)
			r.PublicationFacts = client.PublicationFacts{}
			return r
		},
		client.OperationListPods: func(r client.Result) client.Result {
			r.Pods = failedList(client.OperationListPods, client.FailureForbidden)
			return r
		},
		client.OperationListEndpointSlices: func(r client.Result) client.Result {
			r.Publication = failedList(
				client.OperationListEndpointSlices, client.FailureForbidden)
			r.PublicationFacts = client.PublicationFacts{}
			return r
		},
	}

	for operation, deny := range cases {
		name := operation.String()
		t.Run(name, func(t *testing.T) {
			r := diagnoseKubernetes(t, deny(backedService(t)))

			var refusal domain.Finding
			for _, finding := range r.report.Findings() {
				if finding.Code() == diagnosiskubernetes.CodeAPIAccessDenied {
					refusal = finding
				}
			}
			if refusal.IsZero() {
				t.Fatalf("a refused %s produced no refusal finding", name)
			}

			prose := refusal.Summary() + "\n" + refusal.Detail()
			if !strings.Contains(prose, name) {
				t.Errorf("the refusal does not carry the acquisition layer's own name "+
					"for this operation, %q.\n\n"+
					"The two sets are declared separately because diagnosis may not "+
					"import an adapter. This test is the only thing that can see both, "+
					"so a rename in one place and not the other lands here or nowhere."+
					"\n\n--- prose ---\n%s", name, prose)
			}
		})
	}

	// And the vocabulary itself has exactly the three operations the contract
	// froze, so a fourth arrives with a decision rather than by accident.
	if got := client.OperationNone.String(); got != "NONE" {
		t.Errorf("the zero Operation renders as %q, want NONE", got)
	}
	for _, unnamed := range []client.Operation{4, 200} {
		if !strings.HasPrefix(unnamed.String(), "Operation(") {
			t.Errorf("Operation(%d) renders as %q; an out-of-range value must not "+
				"borrow a real operation's name", unnamed, unnamed.String())
		}
	}
}
