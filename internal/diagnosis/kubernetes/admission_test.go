package kubernetes_test

import (
	"testing"
	"time"

	diagnosiskubernetes "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

const (
	f1 = diagnosiskubernetes.CodeServiceNotFound
	f2 = diagnosiskubernetes.CodeAPIAccessDenied
	f3 = diagnosiskubernetes.CodeSelectsNoPods
	f4 = diagnosiskubernetes.CodeNoReadyEndpoint
)

// everyScenario is the short-circuit and coexistence matrix, by name.
//
// It is a map rather than a slice because every consumer of it iterates for a
// property that holds over all of them and none cares about order. The exact
// findings each one must produce are asserted in
// TestTheShortCircuitMatrixProducesExactlyTheseFindings; the other tests reuse
// the same set to prove properties across it.
func everyScenario() map[string]graphSpec {
	scenarios := map[string]graphSpec{}

	// --- the ordinary outcomes -------------------------------------------
	scenarios["everything read and backed"] = healthy()

	// --- F1, the Service read ---------------------------------------------
	notFound := healthy()
	notFound.service = serviceNotFound()
	notFound.podSet = skipped(servicekubernetes.StepPodSet,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	notFound.publication = skipped(servicekubernetes.StepEndpointPublication,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	scenarios["service not found"] = notFound

	// --- F2, at each of the three reads ------------------------------------
	serviceDenied := notFound
	serviceDenied.service = denied(servicekubernetes.StepService)
	scenarios["service read denied"] = serviceDenied

	podsDenied := healthy()
	podsDenied.podSet = denied(servicekubernetes.StepPodSet)
	scenarios["pod read denied, publication healthy"] = podsDenied

	slicesDenied := healthy()
	slicesDenied.publication = denied(servicekubernetes.StepEndpointPublication)
	scenarios["slice read denied, pods healthy"] = slicesDenied

	bothDenied := healthy()
	bothDenied.podSet = denied(servicekubernetes.StepPodSet)
	bothDenied.publication = denied(servicekubernetes.StepEndpointPublication)
	scenarios["both list reads denied"] = bothDenied

	// F2 on the Pod read beside a publication that itself has nothing ready:
	// the branches are independent, so the slice claim survives.
	podsDeniedNoReady := healthy()
	podsDeniedNoReady.podSet = denied(servicekubernetes.StepPodSet)
	podsDeniedNoReady.publication = publicationNode(
		publicationCounts{slices: 2, endpoints: 4, ready: 0})
	scenarios["pod read denied, no ready endpoint"] = podsDeniedNoReady

	// F2 on the slice read beside a Pod set that is complete and empty: the
	// selector claim survives.
	slicesDeniedNoPods := healthy()
	slicesDeniedNoPods.podSet = podSetNode(true, 0)
	slicesDeniedNoPods.publication = denied(servicekubernetes.StepEndpointPublication)
	scenarios["slice read denied, selector matched nothing"] = slicesDeniedNoPods

	// --- 401 and every other API outcome, which earn no Kubernetes code -----
	unauthorized := healthy()
	unauthorized.apiAccess = node{
		step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
		state: domain.StateFail, failureClass: domain.FailureAuthCredentialsRejected,
	}
	unauthorized.service = skipped(servicekubernetes.StepService,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepAPIAccess)
	unauthorized.podSet = skipped(servicekubernetes.StepPodSet,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepAPIAccess)
	unauthorized.publication = skipped(servicekubernetes.StepEndpointPublication,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepAPIAccess)
	scenarios["401 unauthorized"] = unauthorized

	transportFailure := unauthorized
	transportFailure.apiAccess = node{
		step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
		state: domain.StateFail, failureClass: domain.FailureTCPConnectionFailed,
	}
	scenarios["api server unreachable"] = transportFailure

	serviceServerError := healthy()
	serviceServerError.service = node{
		step: servicekubernetes.StepService, layer: domain.LayerTopology,
		state: domain.StateUnknown, failureClass: domain.FailureProtocolUnexpectedResponse,
	}
	serviceServerError.podSet = skipped(servicekubernetes.StepPodSet,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	serviceServerError.publication = skipped(servicekubernetes.StepEndpointPublication,
		domain.FailureExecSkippedPrerequisiteFailed, servicekubernetes.StepService)
	scenarios["service read answered 5xx"] = serviceServerError

	serviceTimeout := serviceServerError
	serviceTimeout.service = node{
		step: servicekubernetes.StepService, layer: domain.LayerTopology,
		state: domain.StateUnknown, failureClass: domain.FailureExecLocalTimeout,
	}
	scenarios["service read timed out"] = serviceTimeout

	// A LIST answered 404 — the ordinary way a namespace that does not exist
	// reports itself. It carries the same state and class as the Service GET's
	// own 404, on a different node, and must not become F1.
	podList404 := healthy()
	podList404.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StateFail, failureClass: domain.FailureResourceNotFound,
	}
	scenarios["pod list answered 404"] = podList404

	sliceList404 := healthy()
	sliceList404.publication = node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: domain.StateFail, failureClass: domain.FailureResourceNotFound,
	}
	scenarios["slice list answered 404"] = sliceList404

	// --- F3 ----------------------------------------------------------------
	selectsNothing := healthy()
	selectsNothing.podSet = podSetNode(true, 0)
	scenarios["selector matched no pod"] = selectsNothing

	// --- F4, both detail variants ------------------------------------------
	noSlice := healthy()
	noSlice.publication = publicationNode(publicationCounts{})
	scenarios["no endpoint slice published"] = noSlice

	noneReady := healthy()
	noneReady.publication = publicationNode(
		publicationCounts{slices: 2, endpoints: 5, ready: 0})
	scenarios["slices published, none ready"] = noneReady

	allTerminating := healthy()
	allTerminating.publication = publicationNode(
		publicationCounts{slices: 1, endpoints: 3, ready: 0, terminating: 3})
	scenarios["slices published, all terminating"] = allTerminating

	someTerminating := healthy()
	someTerminating.publication = publicationNode(
		publicationCounts{slices: 1, endpoints: 3, ready: 0, terminating: 1})
	scenarios["slices published, some terminating"] = someTerminating

	oneReady := healthy()
	oneReady.publication = publicationNode(
		publicationCounts{slices: 3, endpoints: 9, ready: 1, terminating: 8})
	scenarios["one ready endpoint among many terminating"] = oneReady

	// --- F3 and F4 together, which the contract makes unreachable -----------
	nothingAnywhere := healthy()
	nothingAnywhere.podSet = podSetNode(true, 0)
	nothingAnywhere.publication = publicationNode(publicationCounts{})
	scenarios["no pod and no slice"] = nothingAnywhere

	// --- incompleteness, every stop reason ----------------------------------
	podsIncomplete := healthy()
	podsIncomplete.podSet = podSetNode(false, 0)
	scenarios["pod set incomplete at zero"] = podsIncomplete

	podsIncompleteNonZero := healthy()
	podsIncompleteNonZero.podSet = podSetNode(false, 4000)
	scenarios["pod set incomplete at a ceiling"] = podsIncompleteNonZero

	slicesIncomplete := healthy()
	slicesIncomplete.publication = publicationNode(
		publicationCounts{slices: 0, incomplete: true})
	scenarios["slice set incomplete at zero"] = slicesIncomplete

	slicesIncompleteNoneReady := healthy()
	slicesIncompleteNoneReady.publication = publicationNode(
		publicationCounts{slices: 256, endpoints: 10000, ready: 0, incomplete: true})
	scenarios["slice set incomplete with none ready"] = slicesIncompleteNoneReady

	bothIncompleteEmpty := healthy()
	bothIncompleteEmpty.podSet = podSetNode(false, 0)
	bothIncompleteEmpty.publication = publicationNode(
		publicationCounts{incomplete: true})
	scenarios["both sets incomplete at zero"] = bothIncompleteEmpty

	// --- the Service's own shape --------------------------------------------
	for name, spec := range serviceShapeScenarios() {
		scenarios[name] = spec
	}

	// --- structurally odd graphs --------------------------------------------
	for name, spec := range malformedScenarios() {
		scenarios[name] = spec
	}

	return scenarios
}

// serviceShapeScenarios are the Services whose own shape decides what may be
// said.
func serviceShapeScenarios() map[string]graphSpec {
	scenarios := map[string]graphSpec{}

	// A selector-less Service. The adapter issues neither list, so both nodes
	// are SKIPPED as unsupported-by-svcdoctor rather than as a prerequisite
	// failure — nothing failed, there was simply nothing of that kind to
	// measure.
	selectorLess := healthy()
	selectorLess.service = serviceNode(servicekubernetes.ServiceTypeClusterIP, false, 0)
	selectorLess.podSet = skipped(servicekubernetes.StepPodSet,
		domain.FailureExecUnsupportedBySvcdoctor, servicekubernetes.StepService)
	selectorLess.publication = skipped(servicekubernetes.StepEndpointPublication,
		domain.FailureExecUnsupportedBySvcdoctor, servicekubernetes.StepService)
	scenarios["selector-less service"] = selectorLess

	// The same Service with reads that somehow ran and came back empty. The
	// adapter does not produce this today; the rule must still refuse, because
	// "an empty selector map is match-all" is the one misreading the whole
	// contract is built to prevent.
	selectorLessButRead := healthy()
	selectorLessButRead.service = serviceNode(servicekubernetes.ServiceTypeClusterIP, false, 0)
	selectorLessButRead.podSet = podSetNode(true, 0)
	selectorLessButRead.publication = publicationNode(publicationCounts{})
	scenarios["selector-less service whose reads ran empty"] = selectorLessButRead

	externalName := healthy()
	externalName.service = serviceNode(servicekubernetes.ServiceTypeExternalName, false, 0)
	externalName.podSet = skipped(servicekubernetes.StepPodSet,
		domain.FailureExecUnsupportedBySvcdoctor, servicekubernetes.StepService)
	externalName.publication = skipped(servicekubernetes.StepEndpointPublication,
		domain.FailureExecUnsupportedBySvcdoctor, servicekubernetes.StepService)
	scenarios["external name service"] = externalName

	externalNameButRead := healthy()
	externalNameButRead.service = serviceNode(servicekubernetes.ServiceTypeExternalName, true, 1)
	externalNameButRead.podSet = podSetNode(true, 0)
	externalNameButRead.publication = publicationNode(publicationCounts{})
	scenarios["external name service whose reads ran empty"] = externalNameButRead

	unknownType := healthy()
	unknownType.service = serviceNode(servicekubernetes.ServiceTypeUnknown, true, 2)
	unknownType.podSet = podSetNode(true, 0)
	unknownType.publication = publicationNode(publicationCounts{})
	scenarios["unrecognized service type"] = unknownType

	// A headless Service is a ClusterIP with no cluster IP. It is a deliberate
	// configuration and never a fault, and it is fully supported.
	headless := healthy()
	headless.service = serviceNode(servicekubernetes.ServiceTypeClusterIP, true, 1)
	headless.service.attributes[servicekubernetes.AttrServiceHeadless] = domain.BoolAttr(true)
	headless.podSet = podSetNode(true, 0)
	scenarios["headless service selecting nothing"] = headless

	nodePort := healthy()
	nodePort.service = serviceNode(servicekubernetes.ServiceTypeNodePort, true, 1)
	nodePort.publication = publicationNode(publicationCounts{slices: 1, endpoints: 2})
	scenarios["node port service with nothing ready"] = nodePort

	loadBalancer := healthy()
	loadBalancer.service = serviceNode(servicekubernetes.ServiceTypeLoadBalancer, true, 1)
	loadBalancer.podSet = podSetNode(true, 0)
	scenarios["load balancer service selecting nothing"] = loadBalancer

	return scenarios
}

// malformedScenarios are graphs no producer in this repository makes.
//
// They exist because "the rule fails closed on a shape nobody makes today" is
// exactly the property that stops being true when somebody makes one, and
// because a rule that is right only because of what an upstream layer happens to
// emit is right by accident.
func malformedScenarios() map[string]graphSpec {
	scenarios := map[string]graphSpec{}

	// A Pod set that passed and carries a count with no completeness flag. An
	// absent flag is not a true one.
	countWithoutCompleteness := healthy()
	countWithoutCompleteness.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodObservedCount: domain.IntAttr(0),
		},
	}
	scenarios["pod count with no completeness flag"] = countWithoutCompleteness

	// The reverse: complete, with no count. An absent count is not zero.
	completenessWithoutCount := healthy()
	completenessWithoutCount.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodSetComplete: domain.BoolAttr(true),
		},
	}
	scenarios["pod completeness flag with no count"] = completenessWithoutCount

	readyWithoutSliceCount := healthy()
	readyWithoutSliceCount.publication = node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrSliceSetComplete:   domain.BoolAttr(true),
			servicekubernetes.AttrReadyEndpointCount: domain.IntAttr(0),
		},
	}
	scenarios["ready count with no slice count"] = readyWithoutSliceCount

	sliceCountWithoutReady := healthy()
	sliceCountWithoutReady.publication = node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrSliceSetComplete: domain.BoolAttr(true),
			servicekubernetes.AttrSliceCount:       domain.IntAttr(0),
		},
	}
	scenarios["slice count with no ready count"] = sliceCountWithoutReady

	// A Service node that passed and carries no shape at all.
	serviceWithoutShape := healthy()
	serviceWithoutShape.service = node{
		step: servicekubernetes.StepService, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
	}
	serviceWithoutShape.podSet = podSetNode(true, 0)
	scenarios["service node with no shape attributes"] = serviceWithoutShape

	// The Service node absent entirely.
	noServiceNode := healthy()
	noServiceNode.service = node{omit: true}
	noServiceNode.podSet = podSetNode(true, 0)
	scenarios["no service node at all"] = noServiceNode

	// Nothing but the anchor.
	onlyAnchor := healthy()
	onlyAnchor.apiAccess = node{omit: true}
	onlyAnchor.service = node{omit: true}
	onlyAnchor.podSet = node{omit: true}
	onlyAnchor.publication = node{omit: true}
	scenarios["only the target anchor"] = onlyAnchor

	// A negative count, which no adapter path produces and which must not
	// satisfy "exactly zero".
	negativePods := healthy()
	negativePods.podSet = podSetNode(true, -1)
	scenarios["negative pod count"] = negativePods

	negativeReady := healthy()
	negativeReady.publication = publicationNode(
		publicationCounts{slices: 1, endpoints: 1, ready: -1})
	scenarios["negative ready count"] = negativeReady

	// A Service node that **failed** and yet carries a full shape.
	//
	// No producer makes it: a Service read that did not succeed records no type
	// and no selector. It is here because the Service gate checks the state
	// *and* the attributes, and without this row the state half is equivalent to
	// nothing — which is exactly what a mutation measured.
	failedServiceWithShape := healthy()
	failedServiceWithShape.service = serviceNode(
		servicekubernetes.ServiceTypeClusterIP, true, 2)
	failedServiceWithShape.service.state = domain.StateFail
	failedServiceWithShape.service.failureClass = domain.FailureResourceNotFound
	failedServiceWithShape.podSet = podSetNode(true, 0)
	failedServiceWithShape.publication = publicationNode(publicationCounts{})
	scenarios["failed service node carrying a full shape"] = failedServiceWithShape

	// The same for a denied Service read.
	deniedServiceWithShape := healthy()
	deniedServiceWithShape.service = serviceNode(
		servicekubernetes.ServiceTypeClusterIP, true, 2)
	deniedServiceWithShape.service.state = domain.StateUnknown
	deniedServiceWithShape.service.failureClass = domain.FailureAuthzNotPermitted
	deniedServiceWithShape.podSet = podSetNode(true, 0)
	deniedServiceWithShape.publication = publicationNode(publicationCounts{})
	scenarios["denied service node carrying a full shape"] = deniedServiceWithShape

	// A Pod node that did **not** pass and yet claims completeness.
	//
	// The selector claim requires the state and the flag, and the two come from
	// different code paths in the adapter. Without this row the state half is
	// equivalent to nothing.
	unfinishedButComplete := healthy()
	unfinishedButComplete.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StateUnknown, failureClass: domain.FailureExecCancelled,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodSetComplete:   domain.BoolAttr(true),
			servicekubernetes.AttrPodObservedCount: domain.IntAttr(0),
		},
	}
	scenarios["unfinished pod node claiming completeness"] = unfinishedButComplete

	// The same for the publication node.
	unfinishedSlicesButComplete := healthy()
	unfinishedSlicesButComplete.publication = node{
		step: servicekubernetes.StepEndpointPublication, layer: domain.LayerTopology,
		state: domain.StateFail, failureClass: domain.FailureTCPConnectionFailed,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrSliceSetComplete:   domain.BoolAttr(true),
			servicekubernetes.AttrSliceCount:         domain.IntAttr(0),
			servicekubernetes.AttrEndpointCount:      domain.IntAttr(0),
			servicekubernetes.AttrReadyEndpointCount: domain.IntAttr(0),
		},
	}
	scenarios["unfinished slice node claiming completeness"] = unfinishedSlicesButComplete

	// A refusal class on a node in a state that is not UNKNOWN.
	//
	// `AUTHZ_NOT_PERMITTED` is a **shared** class: PostgreSQL records it as FAIL
	// for `POSTGRES_CONNECTION_NOT_PERMITTED`, where it means the endpoint made a
	// decision about the connection. Here it means a measurement was blocked, and
	// the two are told apart by the state. A rule reading the class alone would
	// be reading a class whose state means something else.
	refusalAsFailure := healthy()
	refusalAsFailure.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StateFail, failureClass: domain.FailureAuthzNotPermitted,
	}
	scenarios["refusal class carried as a failure"] = refusalAsFailure

	// The refusal class on a node that has no bounded operation name.
	//
	// `k8s.api_access` cannot carry one — a 403 means the identity was accepted,
	// so that node passes — and if it ever did, the claim has no operation to
	// state and is withheld entirely rather than made without one.
	refusalWithoutOperation := healthy()
	refusalWithoutOperation.apiAccess = node{
		step: servicekubernetes.StepAPIAccess, layer: domain.LayerAuth,
		state: domain.StateUnknown, failureClass: domain.FailureAuthzNotPermitted,
	}
	scenarios["refusal on a node with no bounded operation"] = refusalWithoutOperation

	// A completeness flag carried as a string rather than a boolean. The typed
	// accessor refuses it, and the claim is withheld rather than coerced.
	stringCompleteness := healthy()
	stringCompleteness.podSet = node{
		step: servicekubernetes.StepPodSet, layer: domain.LayerTopology,
		state: domain.StatePass, failureClass: domain.FailureNone,
		attributes: map[domain.AttributeKey]domain.AttrValue{
			servicekubernetes.AttrPodSetComplete:   domain.StringAttr("true"),
			servicekubernetes.AttrPodObservedCount: domain.IntAttr(0),
		},
	}
	scenarios["completeness carried as a string"] = stringCompleteness

	return scenarios
}

// TestTheShortCircuitMatrixProducesExactlyTheseFindings is the phase's central
// assertion.
//
// Every row states the exact finding multiset a scenario produces, so an added
// claim and a lost one both fail here. There is no "at least" anywhere in it.
func TestTheShortCircuitMatrixProducesExactlyTheseFindings(t *testing.T) {
	expected := map[string][]domain.FindingCode{
		// --- ordinary ---
		"everything read and backed": {},

		// --- F1 ---
		"service not found": {f1},

		// --- F2 ---
		"service read denied":                         {f2},
		"pod read denied, publication healthy":        {f2},
		"slice read denied, pods healthy":             {f2},
		"both list reads denied":                      {f2, f2},
		"pod read denied, no ready endpoint":          {f2, f4},
		"slice read denied, selector matched nothing": {f2, f3},

		// --- no Kubernetes code at all ---
		"401 unauthorized":          {},
		"api server unreachable":    {},
		"service read answered 5xx": {},
		"service read timed out":    {},
		"pod list answered 404":     {},
		"slice list answered 404":   {},

		// --- F3 ---
		"selector matched no pod": {f3},

		// --- F4 ---
		"no endpoint slice published":               {f4},
		"slices published, none ready":              {f4},
		"slices published, all terminating":         {f4},
		"slices published, some terminating":        {f4},
		"one ready endpoint among many terminating": {},

		// --- F3 suppresses F4, because ADR 0094 makes them disjoint ---
		"no pod and no slice": {f3},

		// --- incompleteness ---
		"pod set incomplete at zero":           {},
		"pod set incomplete at a ceiling":      {},
		"slice set incomplete at zero":         {},
		"slice set incomplete with none ready": {},
		"both sets incomplete at zero":         {},

		// --- Service shape ---
		"selector-less service":                       {},
		"selector-less service whose reads ran empty": {},
		"external name service":                       {},
		"external name service whose reads ran empty": {},
		"unrecognized service type":                   {},
		"headless service selecting nothing":          {f3},
		"node port service with nothing ready":        {f4},
		"load balancer service selecting nothing":     {f3},

		// --- malformed ---
		"pod count with no completeness flag":   {},
		"pod completeness flag with no count":   {},
		"ready count with no slice count":       {},
		"slice count with no ready count":       {},
		"service node with no shape attributes": {},
		"no service node at all":                {},
		"only the target anchor":                {},
		"negative pod count":                    {},
		"negative ready count":                  {},
		"completeness carried as a string":      {},

		// --- malformed shapes that make a guard non-equivalent ---
		//
		// Each of these was added because a mutation survived without it. They
		// are shapes no producer makes, and that is the point: a rule that is
		// right only because of what an upstream layer happens to emit is right
		// by accident.
		"failed service node carrying a full shape":   {f1},
		"denied service node carrying a full shape":   {f2},
		"unfinished pod node claiming completeness":   {},
		"unfinished slice node claiming completeness": {},
		"refusal class carried as a failure":          {},
		"refusal on a node with no bounded operation": {},
	}

	scenarios := everyScenario()
	if len(scenarios) != len(expected) {
		t.Fatalf("%d scenarios and %d expectations; every scenario needs a row",
			len(scenarios), len(expected))
	}

	for name, spec := range scenarios {
		want, declared := expected[name]
		if !declared {
			t.Errorf("scenario %q has no expectation", name)
			continue
		}
		t.Run(name, func(t *testing.T) {
			only(t, spec.evaluate(t), want...)
		})
	}
}

// TestNoScenarioEverProducesAFifthKubernetesCode.
//
// The budget is four and it is not a guideline. Nothing in the matrix — not a
// malformed node, not a hostile count, not a shape no producer makes — may cause
// a rule to reach for a code that is not one of them.
func TestNoScenarioEverProducesAFifthKubernetesCode(t *testing.T) {
	permitted := map[domain.FindingCode]bool{f1: true, f2: true, f3: true, f4: true}

	for name, spec := range everyScenario() {
		for _, finding := range spec.evaluate(t) {
			if !permitted[finding.Code()] {
				t.Errorf("%s produced %s, which is not one of the four codes ADR 0094 "+
					"section 2.7 froze", name, finding.Code())
			}
		}
	}
}

// TestAGraphHoldingTwoNodesAtOneStepProducesNothing.
//
// # Why a rule refuses rather than chooses
//
// A Kubernetes run measures **one** Service through **one** path, so each of the
// five steps appears at most once (ADR 0094 §2.9) — a property of
// `internal/app/kubernetes.go`, which continues exactly one acquisition. A graph
// offering two Service nodes has no defensible answer to which one a claim is
// about, and a rule that picked one would make the output depend on traversal
// order.
//
// It cannot be reached through the fixture, whose identifiers would collide, so
// it is built directly. That is the point: this is the shape that appears the
// day somebody adds a second read, and the rules must produce nothing rather
// than something arbitrary.
func TestAGraphHoldingTwoNodesAtOneStepProducesNothing(t *testing.T) {
	subject, err := domain.NewTargetSubject(fixtureSubject)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}

	builder := domain.NewGraphBuilder()
	for i, spec := range []struct {
		id    string
		state domain.State
		class domain.FailureClass
	}{
		{"k8s.service/one", domain.StateFail, domain.FailureResourceNotFound},
		{"k8s.service/two", domain.StateFail, domain.FailureResourceNotFound},
	} {
		evidence, err := domain.NewEvidence(domain.EvidenceInput{
			ID:           domain.EvidenceID(spec.id),
			Subject:      subject,
			Layer:        domain.LayerTopology,
			Step:         servicekubernetes.StepService,
			State:        spec.state,
			FailureClass: spec.class,
			StartedAt:    fixtureStart,
			Elapsed:      domain.Measured(time.Duration(i+1) * time.Millisecond),
		})
		if err != nil {
			t.Fatalf("NewEvidence(%s): %v", spec.id, err)
		}
		if err := builder.AddEvidence(evidence); err != nil {
			t.Fatalf("AddEvidence(%s): %v", spec.id, err)
		}
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	if findings := evaluateGraph(t, graph); len(findings) != 0 {
		t.Errorf("two Service nodes produced %v, want nothing.\n\n"+
			"Choosing one would make the claim depend on traversal order, and the "+
			"honest answer to \"which Service is this about\" in a graph holding two is "+
			"that there is not one.", codesOf(findings))
	}
}
