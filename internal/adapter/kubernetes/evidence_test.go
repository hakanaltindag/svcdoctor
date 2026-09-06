package kubernetes_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	adapterkubernetes "github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes"
	"github.com/hakanaltindag/svcdoctor/internal/adapter/kubernetes/client"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

func target() client.Target {
	return client.Target{
		Kubeconfig: "/etc/svcdoctor/kubeconfig", Context: "prod-eu",
		Namespace: "payments", ServiceName: "payments-api",
	}
}

func healthyResult() client.Result {
	started := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	return client.Result{
		Target: target(),
		Authority: client.Authority{
			Mode: servicekubernetes.AuthModeToken, Context: "prod-eu",
		},
		APIAccess: client.Stage{Attempted: true, StartedAt: started, Elapsed: 5 * time.Millisecond},
		Service:   client.Stage{Attempted: true, StartedAt: started, Elapsed: 5 * time.Millisecond},
		ServiceFacts: client.ServiceFacts{
			Type:            servicekubernetes.ServiceTypeClusterIP,
			SelectorPresent: true, SelectorKeyCount: 2,
		},
		Pods: client.Enumeration{
			Op: client.OperationListPods, Attempted: true, Stop: client.StopComplete,
			Pages: 1, Observed: 3, StartedAt: started, Elapsed: time.Millisecond,
		},
		Publication: client.Enumeration{
			Op: client.OperationListEndpointSlices, Attempted: true, Stop: client.StopComplete,
			Pages: 1, Observed: 1, StartedAt: started, Elapsed: time.Millisecond,
		},
		PublicationFacts: client.PublicationFacts{
			Slices: 1, Endpoints: 3, ReadyEndpoints: 2, TerminatingEndpoints: 1,
		},
		Requests: 3,
	}
}

func record(t *testing.T, result client.Result) domain.Graph {
	t.Helper()
	builder := domain.NewGraphBuilder()
	if _, err := adapterkubernetes.Record(
		builder, result, time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC),
	); err != nil {
		t.Fatalf("recording evidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("freezing: %v", err)
	}
	return graph
}

func node(t *testing.T, graph domain.Graph, step domain.Step) domain.Evidence {
	t.Helper()
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == step {
			return evidence
		}
	}
	t.Fatalf("no node with step %s", step)
	return domain.Evidence{}
}

// TestTheGraphIsAlwaysFiveNodesInTheFrozenShape.
//
// A graph whose shape changed with the outcome would make "the slice read did not
// happen" indistinguishable from "the slice read was never part of this run".
// Every acquisition records five nodes, whatever happened.
func TestTheGraphIsAlwaysFiveNodesInTheFrozenShape(t *testing.T) {
	for _, test := range []struct {
		name   string
		result client.Result
	}{
		{"a healthy run", healthyResult()},
		{"a run that failed at API access", func() client.Result {
			result := healthyResult()
			result.APIAccess = client.Stage{
				Attempted: true, Failure: client.FailureUnauthorized,
			}
			result.Service = client.Stage{Skip: client.SkipAPIAccessFailed}
			result.Pods = client.Enumeration{
				Op: client.OperationListPods, Skip: client.SkipAPIAccessFailed,
			}
			result.Publication = client.Enumeration{
				Op: client.OperationListEndpointSlices, Skip: client.SkipAPIAccessFailed,
			}
			return result
		}()},
		{"a selector-less Service", func() client.Result {
			result := healthyResult()
			result.ServiceFacts.SelectorPresent = false
			result.ServiceFacts.SelectorKeyCount = 0
			result.Pods = client.Enumeration{
				Op: client.OperationListPods, Skip: client.SkipSelectorLess,
			}
			result.Publication = client.Enumeration{
				Op: client.OperationListEndpointSlices, Skip: client.SkipSelectorLess,
			}
			return result
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			graph := record(t, test.result)
			if got := len(graph.Nodes()); got != 5 {
				t.Fatalf("the graph holds %d nodes, want 5", got)
			}

			steps := map[domain.Step]bool{}
			for _, evidence := range graph.Nodes() {
				steps[evidence.Step()] = true
				if evidence.Subject().Kind() != domain.SubjectKindTarget {
					t.Errorf("%s has subject kind %s, want TARGET",
						evidence.Step(), evidence.Subject().Kind())
				}
				if got, want := evidence.Subject().Ref(),
					"service/payments/payments-api"; got != want {
					t.Errorf("%s subject is %q, want %q", evidence.Step(), got, want)
				}
			}
			for _, step := range []domain.Step{
				servicekubernetes.StepTarget,
				servicekubernetes.StepAPIAccess,
				servicekubernetes.StepService,
				servicekubernetes.StepPodSet,
				servicekubernetes.StepEndpointPublication,
			} {
				if !steps[step] {
					t.Errorf("the graph has no %s node", step)
				}
			}
		})
	}
}

// TestTheLayersAreL0L5AndThreeAtL6.
//
// L1 through L3 are unused because transport belongs to the client library, and
// L4 is unused because the Kubernetes API has no separate capability-discovery
// step. Neither absence breaks the failure boundary, which needs only *a* PASS at
// a strictly lower layer — and L0 provides one.
func TestTheLayersAreL0L5AndThreeAtL6(t *testing.T) {
	graph := record(t, healthyResult())
	want := map[domain.Step]domain.Layer{
		servicekubernetes.StepTarget:              domain.LayerInput,
		servicekubernetes.StepAPIAccess:           domain.LayerAuth,
		servicekubernetes.StepService:             domain.LayerTopology,
		servicekubernetes.StepPodSet:              domain.LayerTopology,
		servicekubernetes.StepEndpointPublication: domain.LayerTopology,
	}
	for step, layer := range want {
		if got := node(t, graph, step).Layer(); got != layer {
			t.Errorf("%s is at %s, want %s", step, got, layer)
		}
	}
}

// TestThePodAndSliceSetsAreSiblingsUnderTheService.
//
// It is what makes the graph a DAG rather than a list, and it is what lets a
// denied Pod list leave the EndpointSlice evidence intact.
func TestThePodAndSliceSetsAreSiblingsUnderTheService(t *testing.T) {
	graph := record(t, healthyResult())
	service := node(t, graph, servicekubernetes.StepService)
	access := node(t, graph, servicekubernetes.StepAPIAccess)
	anchor := node(t, graph, servicekubernetes.StepTarget)

	for step, parent := range map[domain.Step]domain.EvidenceID{
		servicekubernetes.StepAPIAccess:           anchor.ID(),
		servicekubernetes.StepService:             access.ID(),
		servicekubernetes.StepPodSet:              service.ID(),
		servicekubernetes.StepEndpointPublication: service.ID(),
	} {
		parents := graph.Parents(node(t, graph, step).ID())
		if len(parents) != 1 || parents[0] != parent {
			t.Errorf("%s has parents %v, want [%s]", step, parents, parent)
		}
	}
	if got := len(graph.Parents(anchor.ID())); got != 0 {
		t.Errorf("the anchor has %d parents; nothing caused the operator to ask", got)
	}
}

// TestNoPerPodOrPerEndpointNodeExists is the cardinality guarantee.
//
// A Service with four thousand backends produces the same five nodes as one with
// none. Per-object nodes would make the graph, the report and every renderer
// scale with a cluster's size for a rendering no diagnosis depends on.
func TestNoPerPodOrPerEndpointNodeExists(t *testing.T) {
	result := healthyResult()
	result.Pods.Observed = 4000
	result.PublicationFacts = client.PublicationFacts{
		Slices: 40, Endpoints: 4000, ReadyEndpoints: 3999, TerminatingEndpoints: 1,
	}
	if got := len(record(t, result).Nodes()); got != 5 {
		t.Errorf("a 4000-backend Service produced %d nodes, want 5", got)
	}
}

// TestTheAttributeSetIsExactlyWhatWasFrozen.
//
// ADR 0094 section 11.1 enumerated the normalized attributes and said what
// consumes each. This is that table, executable. A seventeenth key is a contract
// change, not an implementation detail, and this is where it has to be argued.
func TestTheAttributeSetIsExactlyWhatWasFrozen(t *testing.T) {
	result := healthyResult()
	result.PublicationFacts.ExternallyManaged = true
	result.PublicationFacts.ExcludedByOwnerUID = 2
	graph := record(t, result)

	// The node column is the frozen table's, not the implementation's. ADR 0094
	// §11.1 places the two identity keys on `k8s.service`; the anchor carries
	// none, exactly as the transport anchor carries none (ADR 0042 §6).
	want := map[domain.Step][]domain.AttributeKey{
		servicekubernetes.StepTarget: {},
		servicekubernetes.StepAPIAccess: {
			servicekubernetes.AttrAuthMode,
			servicekubernetes.AttrContext,
		},
		servicekubernetes.StepService: {
			servicekubernetes.AttrNamespace,
			servicekubernetes.AttrServiceName,
			servicekubernetes.AttrServiceType,
			servicekubernetes.AttrServiceHeadless,
			servicekubernetes.AttrSelectorPresent,
			servicekubernetes.AttrSelectorKeyCount,
		},
		servicekubernetes.StepPodSet: {
			servicekubernetes.AttrPodSetComplete,
			servicekubernetes.AttrPodObservedCount,
		},
		servicekubernetes.StepEndpointPublication: {
			servicekubernetes.AttrSliceSetComplete,
			servicekubernetes.AttrSliceCount,
			servicekubernetes.AttrEndpointCount,
			servicekubernetes.AttrReadyEndpointCount,
			servicekubernetes.AttrTerminatingEndpointCount,
			servicekubernetes.AttrSliceExcludedByOwnerUIDCount,
			servicekubernetes.AttrSliceExternallyManaged,
		},
	}

	total := 0
	for step, keys := range want {
		evidence := node(t, graph, step)
		attributes := evidence.Attributes()
		if got := len(attributes); got != len(keys) {
			t.Errorf("%s carries %d attributes, want %d: %v", step, got, len(keys), attributes)
		}
		for _, key := range keys {
			if _, ok := attributes[key]; !ok {
				t.Errorf("%s is missing %s", step, key)
			}
		}
		total += len(keys)
	}
	// **Seventeen keys, and the enumeration is what decides.** ADR 0094 §11.1's
	// table lists seventeen rows, each naming its consumer, while its own heading
	// says "fifteen" and its closing sentence and ADR 0094 §2.9 say "sixteen".
	// No source anywhere enumerates fifteen or sixteen items, so the counts are
	// clerical and the table is the contract. This test is written from the
	// table — node column included — so a future edit reconciles to the record
	// rather than to the code.
	if total != 17 {
		t.Errorf("the frozen attribute set holds %d keys, want 17", total)
	}
}

// TestIdentityAttributesAreIdentityKinded.
//
// AttrKindIdentity is what makes structural redaction work without a
// Kubernetes-specific mechanism: the redactor dispatches on the kind and never on
// a key, so a namespace recorded as a plain string would survive into a shareable
// report.
func TestIdentityAttributesAreIdentityKinded(t *testing.T) {
	graph := record(t, healthyResult())
	for _, test := range []struct {
		step domain.Step
		key  domain.AttributeKey
	}{
		{servicekubernetes.StepService, servicekubernetes.AttrNamespace},
		{servicekubernetes.StepService, servicekubernetes.AttrServiceName},
		{servicekubernetes.StepAPIAccess, servicekubernetes.AttrContext},
	} {
		value, ok := node(t, graph, test.step).Attribute(test.key)
		if !ok {
			t.Fatalf("%s is missing", test.key)
		}
		if value.Kind() != domain.AttrKindIdentity {
			t.Errorf("%s is %s, want identity: structural redaction dispatches on the kind",
				test.key, value.Kind())
		}
	}

	// The auth mode is deliberately a plain string: it is a category svcdoctor
	// declared, not a name from the environment, and pseudonymizing it would
	// remove the one authority fact a shared report needs.
	mode, _ := node(t, graph, servicekubernetes.StepAPIAccess).
		Attribute(servicekubernetes.AttrAuthMode)
	if mode.Kind() != domain.AttrKindString {
		t.Errorf("the auth mode is %s, want string", mode.Kind())
	}
}

// TestNoFilesystemPathOrAPIServerAddressReachesEvidence.
//
// The kubeconfig path, the token file path and the API server's host and port are
// all held by the acquisition result. None of them is evidence: the first two are
// filesystem paths and the third binds the credential and is not the run's
// identity.
func TestNoFilesystemPathOrAPIServerAddressReachesEvidence(t *testing.T) {
	result := healthyResult()
	result.Target.Kubeconfig = "/etc/svcdoctor/secret-cluster-kubeconfig"
	graph := record(t, result)

	encoded, err := json.Marshal(graph.Nodes())
	if err != nil {
		t.Fatalf("encoding the graph: %v", err)
	}
	for _, forbidden := range []string{
		"/etc/svcdoctor", "kubeconfig", "https://", "443", "server",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("the evidence carries %q:\n%s", forbidden, encoded)
		}
	}
}

// TestTheStateMappingKeepsDeniedApartFromAbsent.
//
// # The single worst mistake this contract exists to prevent
//
// A 403 says svcdoctor was not allowed to look. A 404 says the API server states
// the object is not there. Collapsing them would let "not allowed to look" become
// "there is nothing there", and every universal claim built on the second would
// be false.
func TestTheStateMappingKeepsDeniedApartFromAbsent(t *testing.T) {
	tests := []struct {
		name      string
		failure   client.Failure
		wantState domain.State
		wantClass domain.FailureClass
	}{
		{"401", client.FailureUnauthorized, domain.StateFail,
			domain.FailureAuthCredentialsRejected},
		{"403", client.FailureForbidden, domain.StateUnknown,
			domain.FailureAuthzNotPermitted},
		{"404", client.FailureNotFound, domain.StateFail, domain.FailureResourceNotFound},
		{"410", client.FailureResourceExpired, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse},
		{"5xx", client.FailureAPIError, domain.StateUnknown,
			domain.FailureProtocolUnexpectedResponse},
		{"transport", client.FailureTransport, domain.StateFail,
			domain.FailureTCPConnectionFailed},
		{"unknown authority", client.FailureTLSUnknownAuthority, domain.StateFail,
			domain.FailureTLSUnknownAuthority},
		{"timeout", client.FailureTimeout, domain.StateUnknown,
			domain.FailureExecLocalTimeout},
		{"cancelled", client.FailureCancelled, domain.StateUnknown,
			domain.FailureExecCancelled},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := healthyResult()
			result.Service = client.Stage{Attempted: true, Failure: test.failure}
			graph := record(t, result)
			service := node(t, graph, servicekubernetes.StepService)

			if got := service.State(); got != test.wantState {
				t.Errorf("state is %s, want %s", got, test.wantState)
			}
			if got := service.FailureClass(); got != test.wantClass {
				t.Errorf("failure class is %s, want %s", got, test.wantClass)
			}
			// A failed Service read carries no **observation**: there was nothing
			// to have observed. It still carries the two identity keys, which
			// are inputs the target declared and are true either way — and the
			// run whose read was denied is the one whose reader most needs them.
			for _, observation := range []domain.AttributeKey{
				servicekubernetes.AttrServiceType,
				servicekubernetes.AttrServiceHeadless,
				servicekubernetes.AttrSelectorPresent,
				servicekubernetes.AttrSelectorKeyCount,
			} {
				if _, ok := service.Attribute(observation); ok {
					t.Errorf("a failed Service read carries the observation %s", observation)
				}
			}
			for _, declared := range []domain.AttributeKey{
				servicekubernetes.AttrNamespace,
				servicekubernetes.AttrServiceName,
			} {
				if _, ok := service.Attribute(declared); !ok {
					t.Errorf("a failed Service read lost the declared input %s", declared)
				}
			}
		})
	}
}

// TestAnIncompleteEnumerationIsUnknownAndNeverPassing.
//
// A count is authoritative only when its completeness flag is true, and the node
// state says the same thing a second way: an enumeration that stopped at a
// ceiling is UNKNOWN with svcdoctor's own depth-limit class, because it is a
// measurement that did not finish rather than a target that failed.
func TestAnIncompleteEnumerationIsUnknownAndNeverPassing(t *testing.T) {
	for _, stop := range []client.StopReason{
		client.StopPageLimit, client.StopObjectLimit, client.StopEndpointLimit,
	} {
		result := healthyResult()
		result.Pods.Stop = stop
		result.Pods.Observed = 4000
		graph := record(t, result)
		pods := node(t, graph, servicekubernetes.StepPodSet)

		if pods.State() != domain.StateUnknown {
			t.Errorf("%v produced state %s, want UNKNOWN", stop, pods.State())
		}
		if pods.FailureClass() != domain.FailureExecDepthLimit {
			t.Errorf("%v produced class %s, want EXEC_DEPTH_LIMIT", stop, pods.FailureClass())
		}
		complete, ok := pods.Attribute(servicekubernetes.AttrPodSetComplete)
		if !ok {
			t.Fatal("the completeness attribute is missing")
		}
		if value, _ := complete.Bool(); value {
			t.Errorf("%v was recorded as complete", stop)
		}
		// The count is still recorded — it is observed so far, not a total — and
		// it is never zero just because the set is incomplete.
		observed, _ := pods.Attribute(servicekubernetes.AttrPodObservedCount)
		if value, _ := observed.Int(); value != 4000 {
			t.Errorf("observed count is %d, want 4000", value)
		}
	}
}

// TestASkippedStageIsBlockedByWhatStoppedIt.
//
// A blocked-by reference says something a parent edge does not: the parent is
// where the node sits in the journey, and the blocker is why it never happened.
func TestASkippedStageIsBlockedByWhatStoppedIt(t *testing.T) {
	result := healthyResult()
	result.APIAccess = client.Stage{Attempted: true, Failure: client.FailureUnauthorized}
	result.Service = client.Stage{Skip: client.SkipAPIAccessFailed}
	result.Pods = client.Enumeration{
		Op: client.OperationListPods, Skip: client.SkipAPIAccessFailed,
	}
	result.Publication = client.Enumeration{
		Op: client.OperationListEndpointSlices, Skip: client.SkipAPIAccessFailed,
	}

	graph := record(t, result)
	access := node(t, graph, servicekubernetes.StepAPIAccess)

	for _, step := range []domain.Step{
		servicekubernetes.StepService,
		servicekubernetes.StepPodSet,
		servicekubernetes.StepEndpointPublication,
	} {
		evidence := node(t, graph, step)
		if evidence.State() != domain.StateSkipped {
			t.Errorf("%s is %s, want SKIPPED", step, evidence.State())
		}
		blockers := graph.BlockedBy(evidence.ID())
		if len(blockers) != 1 || blockers[0] != access.ID() {
			t.Errorf("%s is blocked by %v, want [%s]", step, blockers, access.ID())
		}
		// A stage that never ran records no observation. `k8s.service` still
		// carries the two identity keys the target declared, which are inputs
		// rather than measurements; the two enumerations carry nothing at all,
		// because every key on them is a count of something never counted.
		want := 0
		if step == servicekubernetes.StepService {
			want = 2
		}
		if got := evidence.AttributeCount(); got != want {
			t.Errorf("%s carries %d attributes for a stage that never ran, want %d",
				step, got, want)
		}
	}
}

// TestASkippedStageIsNeverAnEmptySet.
//
// A skipped enumeration records no count at all, so there is no number for a
// consumer to read as zero. That is the strongest form of the rule: not "zero
// with a flag", but no observation at all.
func TestASkippedStageIsNeverAnEmptySet(t *testing.T) {
	result := healthyResult()
	result.Pods = client.Enumeration{
		Op: client.OperationListPods, Skip: client.SkipSelectorLess,
	}
	graph := record(t, result)
	pods := node(t, graph, servicekubernetes.StepPodSet)

	if _, ok := pods.Attribute(servicekubernetes.AttrPodObservedCount); ok {
		t.Error("a skipped Pod enumeration recorded an observed count")
	}
	if _, ok := pods.Attribute(servicekubernetes.AttrPodSetComplete); ok {
		t.Error("a skipped Pod enumeration recorded a completeness flag")
	}
	if pods.FailureClass() != domain.FailureExecUnsupportedBySvcdoctor {
		t.Errorf("a selector-less skip is classified %s, want EXEC_UNSUPPORTED_BY_SVCDOCTOR",
			pods.FailureClass())
	}
	// It is elapsed-unmeasured rather than instantaneous.
	if _, measured := pods.Elapsed().Duration(); measured {
		t.Error("a skipped stage reported a measured duration")
	}
}

// TestTheContextIsAbsentRatherThanEmptyInCluster.
//
// There is no context in-cluster, and recording an empty one would say a choice
// was made that was not.
func TestTheContextIsAbsentRatherThanEmptyInCluster(t *testing.T) {
	result := healthyResult()
	result.Authority = client.Authority{Mode: servicekubernetes.AuthModeInCluster}
	graph := record(t, result)
	access := node(t, graph, servicekubernetes.StepAPIAccess)

	if _, ok := access.Attribute(servicekubernetes.AttrContext); ok {
		t.Error("an in-cluster run recorded a context")
	}
	mode, _ := access.Attribute(servicekubernetes.AttrAuthMode)
	if value, _ := mode.Str(); value != servicekubernetes.AuthModeInCluster {
		t.Errorf("auth mode is %q, want IN_CLUSTER", value)
	}
}

// TestTheSameResultAlwaysProducesTheSameGraph is canonical determinism.
func TestTheSameResultAlwaysProducesTheSameGraph(t *testing.T) {
	result := healthyResult()
	first, err := json.Marshal(record(t, result).Nodes())
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for i := 0; i < 8; i++ {
		next, err := json.Marshal(record(t, result).Nodes())
		if err != nil {
			t.Fatalf("encoding: %v", err)
		}
		if string(next) != string(first) {
			t.Fatalf("run %d produced different bytes", i)
		}
	}
}
