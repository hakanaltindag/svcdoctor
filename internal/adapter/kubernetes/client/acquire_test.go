package client

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

func acquire(t *testing.T, server *apiServer) Result {
	t.Helper()
	result, err := Acquire(context.Background(),
		Params{Target: targetFor(tokenKubeconfig(t, server))})
	if err != nil {
		t.Fatalf("acquiring: %v", err)
	}
	return result
}

// TestTheNominalRunIssuesExactlyThreeRequests is the round-trip contract.
//
// # Why the count is asserted and not computed
//
// The frozen ceiling of seventeen — one Service GET plus eight Pod pages plus
// eight EndpointSlice pages — is only meaningful if nothing else issues a
// request. Arithmetic cannot see a discovery call, an API version negotiation or
// a redirect the library follows on svcdoctor's behalf, and each of those would
// break the budget silently. A counting server can.
func TestTheNominalRunIssuesExactlyThreeRequests(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{pods: pods(2)}}
	server.slicePages = []scriptedPage{{slices: []discoveryv1.EndpointSlice{
		slice("payments-api-abcde", "uid-1", endpoint(ptr(true), nil, nil)),
	}}}

	result := acquire(t, server)

	if got := server.requestCount(); got != 3 {
		t.Errorf("the API server received %d requests, want exactly 3", got)
	}
	if result.Requests != 3 {
		t.Errorf("the result counted %d requests, want 3", result.Requests)
	}
	if result.Requests > MaxRequests {
		t.Errorf("%d requests exceeds the frozen ceiling of %d", result.Requests, MaxRequests)
	}
}

// TestClientConstructionPerformsNoDiscovery is ADR 0094 section 2.5's "no
// discovery, no version negotiation".
//
// `k8s.io/client-go/discovery` is *linked* into the binary, transitively, by the
// typed clients' scheme — which is why this has to be a behavioural assertion
// rather than a linker check. Building both typed clients and then issuing
// nothing must reach the API server zero times.
func TestClientConstructionPerformsNoDiscovery(t *testing.T) {
	server := newAPIServer(t)
	if _, err := Connect(targetFor(tokenKubeconfig(t, server)), security.Credential{}); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("building the clients issued %d requests, want 0.\n\n"+
			"The seventeen-round-trip ceiling assumes client construction costs nothing. "+
			"A discovery or version-negotiation call would break it silently.", got)
	}
}

// TestEachRequestHasTheExactShapeTheContractFroze checks the three requests
// svcdoctor is responsible for.
//
// It asserts svcdoctor's own obligations — the namespace, the resource, the
// name, the two label selectors and the explicit limit — and deliberately not
// client-go's internals.
func TestEachRequestHasTheExactShapeTheContractFroze(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{}}

	acquire(t, server)
	recorded := server.recorded()
	if len(recorded) != 3 {
		t.Fatalf("recorded %d requests, want 3", len(recorded))
	}

	get := recorded[0]
	if get.method != http.MethodGet {
		t.Errorf("the Service read used %s, want GET", get.method)
	}
	if want := "/api/v1/namespaces/payments/services/payments-api"; get.path != want {
		t.Errorf("Service path is %q, want %q", get.path, want)
	}

	podList := recorded[1]
	if want := "/api/v1/namespaces/payments/pods"; podList.path != want {
		t.Errorf("Pod list path is %q, want %q", podList.path, want)
	}
	// The Service's own selector, serialized by apimachinery. Two keys, sorted,
	// comma-joined — which is exact Kubernetes semantics rather than a string
	// svcdoctor built.
	if want := "app=payments,tier=api"; podList.query.Get("labelSelector") != want {
		t.Errorf("Pod labelSelector is %q, want %q", podList.query.Get("labelSelector"), want)
	}
	if want := "500"; podList.query.Get("limit") != want {
		t.Errorf("Pod limit is %q, want %q", podList.query.Get("limit"), want)
	}

	sliceList := recorded[2]
	if want := "/apis/discovery.k8s.io/v1/namespaces/payments/endpointslices"; sliceList.path != want {
		t.Errorf("EndpointSlice list path is %q, want %q", sliceList.path, want)
	}
	if want := "kubernetes.io/service-name=payments-api"; sliceList.query.Get("labelSelector") != want {
		t.Errorf("EndpointSlice labelSelector is %q, want %q",
			sliceList.query.Get("labelSelector"), want)
	}
	if want := "500"; sliceList.query.Get("limit") != want {
		t.Errorf("EndpointSlice limit is %q, want %q", sliceList.query.Get("limit"), want)
	}
	// Nothing svcdoctor did not ask for.
	for _, request := range recorded {
		if request.query.Get("watch") != "" || request.query.Get("resourceVersion") != "" {
			t.Errorf("request %s carried an unexpected parameter: %v", request.path, request.query)
		}
	}
}

// TestTheContinueTokenIsPropagatedByteForByte keeps pagination honest.
//
// A token is opaque server state. Re-encoding it, trimming it or reconstructing
// it would silently sample a different position, and the enumeration would still
// look complete.
func TestTheContinueTokenIsPropagatedByteForByte(t *testing.T) {
	// A token-shaped opaque string, deliberately: a real continue token is
	// base64-ish and carries the characters most likely to be mangled by a
	// re-encode.
	const token = "eyJ2IjoibWV0YS5rOHMuaW8vdjEi/+=fixture" //nolint:gosec // an opaque pagination token, not a credential
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{
		{pods: pods(1), continueToken: token},
		{pods: pods(1)},
	}
	server.slicePages = []scriptedPage{{}}

	result := acquire(t, server)
	if !result.Pods.Complete() {
		t.Fatalf("the Pod set is not complete: %+v", result.Pods)
	}

	recorded := server.recorded()
	first, second := recorded[1], recorded[2]
	if got := second.query.Get("continue"); got != token {
		t.Errorf("the continue token was sent as %q, want %q byte for byte", got, token)
	}
	// The first page must carry none.
	if got := first.query.Get("continue"); got != "" {
		t.Errorf("the first page carried a continue token %q", got)
	}
	// **Every other parameter must be identical.** metav1.ListOptions.Continue
	// requires a token to be used "with identical query parameters (except for
	// the value of continue)", and a server may reject one that is not — so a
	// continuation that quietly changed the limit or the selector would be
	// continuing a list nobody started.
	for _, parameter := range []string{"limit", "labelSelector"} {
		if first.query.Get(parameter) != second.query.Get(parameter) {
			t.Errorf("%s changed between pages: %q then %q", parameter,
				first.query.Get(parameter), second.query.Get(parameter))
		}
	}
}

// TestTheThreeAPIStatusesEachProduceTheirOwnAcquisitionState.
//
// 401, 403 and 404 are the three the contract distinguishes, and each has to
// land somewhere different: a 401 fails API access, a 403 records a denied read
// that is **not** emptiness, and a 404 is the API server stating that no Service
// of this name exists.
func TestTheThreeAPIStatusesEachProduceTheirOwnAcquisitionState(t *testing.T) {
	tests := []struct {
		name   string
		code   int32
		reason metav1.StatusReason
		assert func(t *testing.T, result Result)
	}{
		{
			name:   "401 fails API access and blocks everything below it",
			code:   http.StatusUnauthorized,
			reason: metav1.StatusReasonUnauthorized,
			assert: func(t *testing.T, result Result) {
				if result.APIAccess.Failure != FailureUnauthorized {
					t.Errorf("API access failure is %v, want UNAUTHORIZED",
						result.APIAccess.Failure)
				}
				if result.Service.Attempted {
					t.Error("the Service read was recorded as attempted")
				}
				for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
					if enumeration.Skip != SkipAPIAccessFailed {
						t.Errorf("%s skip is %v, want API_ACCESS_FAILED",
							enumeration.Op, enumeration.Skip)
					}
				}
			},
		},
		{
			name:   "403 leaves API access passing and denies one read",
			code:   http.StatusForbidden,
			reason: metav1.StatusReasonForbidden,
			assert: func(t *testing.T, result Result) {
				if !result.APIAccess.OK() {
					t.Errorf("API access did not pass: %+v", result.APIAccess)
				}
				if result.Service.Failure != FailureForbidden {
					t.Errorf("Service failure is %v, want FORBIDDEN", result.Service.Failure)
				}
				// A denied read is never emptiness: neither set may be presented
				// as complete-and-empty.
				for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
					if enumeration.Complete() {
						t.Errorf("%s was reported complete after a denied Service read",
							enumeration.Op)
					}
					if enumeration.Observed != 0 || enumeration.Attempted {
						t.Errorf("%s claims an observation it never made: %+v",
							enumeration.Op, enumeration)
					}
				}
			},
		},
		{
			name:   "404 is the API server stating the Service does not exist",
			code:   http.StatusNotFound,
			reason: metav1.StatusReasonNotFound,
			assert: func(t *testing.T, result Result) {
				if !result.APIAccess.OK() {
					t.Errorf("API access did not pass: %+v", result.APIAccess)
				}
				if result.Service.Failure != FailureNotFound {
					t.Errorf("Service failure is %v, want NOT_FOUND", result.Service.Failure)
				}
			},
		},
		{
			name:   "500 is an acquisition failure that claims nothing",
			code:   http.StatusInternalServerError,
			reason: metav1.StatusReasonInternalError,
			assert: func(t *testing.T, result Result) {
				if result.Service.Failure != FailureAPIError {
					t.Errorf("Service failure is %v, want API_ERROR", result.Service.Failure)
				}
				if !result.Incomplete() {
					t.Error("a 5xx left the run complete; nothing was measured")
				}
			},
		},
		{
			name:   "429 is not retried",
			code:   http.StatusTooManyRequests,
			reason: metav1.StatusReasonTooManyRequests,
			assert: func(t *testing.T, result Result) {
				if result.Requests != 1 {
					t.Errorf("a 429 produced %d requests; svcdoctor retries nothing, because "+
						"a retry loop turns one bounded diagnosis into monitoring",
						result.Requests)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAPIServer(t)
			server.serviceStatus = &metav1.Status{
				Code: test.code, Reason: test.reason, Message: "fixture",
			}
			result := acquire(t, server)
			test.assert(t, result)
			if len(result.Target.Namespace) == 0 {
				t.Error("the result forgot what it was about")
			}
		})
	}
}

// TestAHostileStatusMessageNeverReachesTheResult is the structural half of
// ADR 0094 section 2.8.
//
// Status.Message is attacker-influenceable text. svcdoctor never reads it, so
// ANSI escapes, CRLF, a token-shaped value, a URL with credentials and a
// filesystem path cannot reach a normalized value — not because they are escaped
// but because nothing looks at them.
func TestAHostileStatusMessageNeverReachesTheResult(t *testing.T) {
	const hostile = "\x1b[31mDENIED\x1b[0m\r\nBearer sk-live-abcdefghijklmnop " +
		"https://user:pass@evil.invalid/x /etc/shadow"

	server := newAPIServer(t)
	server.serviceStatus = &metav1.Status{
		Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden, Message: hostile,
	}
	result := acquire(t, server)

	if result.Service.Failure != FailureForbidden {
		t.Fatalf("the status was misclassified as %v", result.Service.Failure)
	}
	rendered := renderResult(result)
	for _, fragment := range []string{
		"\x1b[", "\r\n", "sk-live", "evil.invalid", "/etc/shadow", "DENIED",
	} {
		if strings.Contains(rendered, fragment) {
			t.Errorf("the acquisition result carries %q from Status.Message:\n%s",
				fragment, rendered)
		}
	}
}

// renderResult formats everything a Result carries, for leakage assertions.
//
// It uses %#v deliberately: a value that reached any field, exported or not,
// appears here. A test that only formatted the exported ones would pass for want
// of looking.
func renderResult(result Result) string {
	return strings.Join([]string{
		sprintf("%#v", result),
		sprintf("%+v", result),
		result.Service.Failure.String(),
		result.Pods.Stop.String(),
		result.Publication.Stop.String(),
	}, "\n")
}

// TestASelectorLessServiceIssuesNeitherListAndIsNeverMatchAll.
//
// # The mistake this exists to prevent
//
// Reading an absent or empty selector as "matches everything" would list every
// Pod in the namespace and call them this Service's backends — turning a
// correctly configured selector-less Service into a claim that its backends
// vanished. An empty map is selector-less, identically to an absent one.
func TestASelectorLessServiceIssuesNeitherListAndIsNeverMatchAll(t *testing.T) {
	for _, selector := range []map[string]string{nil, {}} {
		server := newAPIServer(t)
		service := selectorService("uid-1")
		service.Spec.Selector = selector
		server.service = service

		result := acquire(t, server)

		if got := server.requestCount(); got != 1 {
			t.Errorf("a selector-less Service issued %d requests, want 1: no Pod list and no "+
				"EndpointSlice list", got)
		}
		if result.ServiceFacts.SelectorPresent {
			t.Error("an empty or absent selector was reported as present")
		}
		if result.ServiceFacts.SelectorKeyCount != 0 {
			t.Errorf("selector key count is %d, want 0", result.ServiceFacts.SelectorKeyCount)
		}
		for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
			if enumeration.Attempted {
				t.Errorf("%s was issued for a selector-less Service", enumeration.Op)
			}
			if enumeration.Skip != SkipSelectorLess {
				t.Errorf("%s skip is %v, want SELECTOR_LESS", enumeration.Op, enumeration.Skip)
			}
			// A skipped list is not an empty one.
			if enumeration.Complete() {
				t.Errorf("%s was reported complete without being issued", enumeration.Op)
			}
		}
		// Nothing was left unmeasured, so the run is not incomplete.
		if result.Incomplete() {
			t.Error("a selector-less Service made the run incomplete; there was nothing there " +
				"to measure, which is not the same as failing to measure it")
		}
	}
}

// TestAnExternalNameServiceIsUnsupportedAndNotAFailure.
//
// ExternalName publishes no backend: no selector, no endpoints, no proxying.
// Absent slices there are **correct**, so neither list is issued and nothing
// about the absence is a fault.
func TestAnExternalNameServiceIsUnsupportedAndNotAFailure(t *testing.T) {
	server := newAPIServer(t)
	service := selectorService("uid-1")
	service.Spec.Type = corev1.ServiceTypeExternalName
	service.Spec.Selector = nil
	service.Spec.ClusterIP = ""
	server.service = service

	result := acquire(t, server)

	if got := server.requestCount(); got != 1 {
		t.Errorf("an ExternalName Service issued %d requests, want 1", got)
	}
	if got := result.ServiceFacts.Type; got != servicekubernetes.ServiceTypeExternalName {
		t.Errorf("type is %q, want ExternalName", got)
	}
	if !result.Service.OK() {
		t.Errorf("the Service read failed: %+v", result.Service)
	}
	for _, enumeration := range []Enumeration{result.Pods, result.Publication} {
		if enumeration.Skip != SkipUnsupportedServiceType {
			t.Errorf("%s skip is %v, want UNSUPPORTED_SERVICE_TYPE",
				enumeration.Op, enumeration.Skip)
		}
	}
	if result.Incomplete() {
		t.Error("an ExternalName Service made the run incomplete")
	}
}

// TestTheServiceTypeMatrixIsExactlyTheFrozenOne.
//
// The three selector-backed types are fully supported for backend publication.
// ExternalName is not. **An unrecognized type never unlocks behaviour**: it
// produces fewer reads and fewer claims, which is the safe direction for a value
// svcdoctor did not write.
func TestTheServiceTypeMatrixIsExactlyTheFrozenOne(t *testing.T) {
	tests := []struct {
		serviceType  corev1.ServiceType
		clusterIP    string
		wantType     string
		wantHeadless bool
		wantRequests int
	}{
		{corev1.ServiceTypeClusterIP, "10.0.0.1", servicekubernetes.ServiceTypeClusterIP, false, 3},
		{corev1.ServiceTypeClusterIP, corev1.ClusterIPNone, servicekubernetes.ServiceTypeClusterIP, true, 3},
		{corev1.ServiceTypeNodePort, "10.0.0.1", servicekubernetes.ServiceTypeNodePort, false, 3},
		{corev1.ServiceTypeLoadBalancer, "10.0.0.1", servicekubernetes.ServiceTypeLoadBalancer, false, 3},
		{corev1.ServiceTypeExternalName, "", servicekubernetes.ServiceTypeExternalName, false, 1},
		{corev1.ServiceType("SuperCluster"), "10.0.0.1", servicekubernetes.ServiceTypeUnknown, false, 1},
		{corev1.ServiceType(""), "10.0.0.1", servicekubernetes.ServiceTypeClusterIP, false, 3},
	}

	for _, test := range tests {
		t.Run(string(test.serviceType)+"/"+test.clusterIP, func(t *testing.T) {
			server := newAPIServer(t)
			service := selectorService("uid-1")
			service.Spec.Type = test.serviceType
			service.Spec.ClusterIP = test.clusterIP
			server.service = service
			server.podPages = []scriptedPage{{}}
			server.slicePages = []scriptedPage{{}}

			result := acquire(t, server)

			if got := result.ServiceFacts.Type; got != test.wantType {
				t.Errorf("type is %q, want %q", got, test.wantType)
			}
			if got := result.ServiceFacts.Headless; got != test.wantHeadless {
				t.Errorf("headless is %v, want %v", got, test.wantHeadless)
			}
			if got := server.requestCount(); got != test.wantRequests {
				t.Errorf("issued %d requests, want %d", got, test.wantRequests)
			}
			// A headless Service is never a failure.
			if !result.Service.OK() {
				t.Errorf("the Service read failed: %+v", result.Service)
			}
		})
	}
}

// TestADeniedPodListLeavesTheEndpointSliceEvidenceIntact is branch independence.
//
// The two sets answer different questions and are siblings rather than a chain.
// Erasing one because the other was denied would discard evidence svcdoctor
// already holds — and would make the report say less than the run measured.
func TestADeniedPodListLeavesTheEndpointSliceEvidenceIntact(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{status: &metav1.Status{
		Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
	}}}
	server.slicePages = []scriptedPage{{slices: []discoveryv1.EndpointSlice{
		slice("payments-api-abcde", "uid-1", endpoint(ptr(true), nil, nil)),
	}}}

	result := acquire(t, server)

	if result.Pods.Failure != FailureForbidden {
		t.Errorf("Pod failure is %v, want FORBIDDEN", result.Pods.Failure)
	}
	if result.Pods.Complete() {
		t.Error("a denied Pod list was reported complete")
	}
	if !result.Publication.Attempted {
		t.Fatal("the EndpointSlice read did not run after a denied Pod list")
	}
	if !result.Publication.Complete() {
		t.Errorf("the EndpointSlice set is not complete: %+v", result.Publication)
	}
	if got := result.PublicationFacts.ReadyEndpoints; got != 1 {
		t.Errorf("ready endpoints is %d, want 1", got)
	}
}

// TestADeniedSliceListLeavesThePodEvidenceIntact is the mirror image.
func TestADeniedSliceListLeavesThePodEvidenceIntact(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{pods: pods(3)}}
	server.slicePages = []scriptedPage{{status: &metav1.Status{
		Code: http.StatusForbidden, Reason: metav1.StatusReasonForbidden,
	}}}

	result := acquire(t, server)

	if !result.Pods.Complete() {
		t.Errorf("the Pod set is not complete: %+v", result.Pods)
	}
	if got := result.Pods.Observed; got != 3 {
		t.Errorf("observed %d Pods, want 3", got)
	}
	if result.Publication.Failure != FailureForbidden {
		t.Errorf("slice failure is %v, want FORBIDDEN", result.Publication.Failure)
	}
	if result.Publication.Complete() {
		t.Error("a denied EndpointSlice list was reported complete")
	}
}

// Helpers for building API fixtures.

func pods(n int) []corev1.Pod {
	out := make([]corev1.Pod, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments", Name: sprintf("payments-api-%d", i),
		}})
	}
	return out
}

func slice(name, ownerUID string, endpoints ...discoveryv1.Endpoint) discoveryv1.EndpointSlice {
	out := discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments",
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: "payments-api"},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Port: ptr(int32(8080))}},
		Endpoints:   endpoints,
	}
	if ownerUID != "" {
		out.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1", Kind: "Service", Name: "payments-api", UID: types.UID(ownerUID),
		}}
	}
	return out
}

var endpointCounter int

func endpoint(ready, serving, terminating *bool) discoveryv1.Endpoint {
	endpointCounter++
	return discoveryv1.Endpoint{
		Addresses: []string{sprintf("10.244.0.%d", endpointCounter%250)},
		Conditions: discoveryv1.EndpointConditions{
			Ready: ready, Serving: serving, Terminating: terminating,
		},
	}
}

func ptr[T any](v T) *T { return &v }

// sprintf is fmt.Sprintf, named once so the fixtures read as data.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// TestNormalizeServiceReadsAnEmptyMapAsSelectorLess.
//
// # Why this cannot be an HTTP fixture test
//
// `corev1.ServiceSpec.Selector` carries `json:"selector,omitempty"`, so an empty
// map does not survive serialization: it is omitted on the way out and decodes as
// nil on the way in. The hermetic server therefore cannot deliver the case, and a
// mutation reading `!= nil` instead of `len() > 0` survived every test that went
// through it.
//
// A real API server has the same property, which is why this is a narrow
// completeness test rather than a claim that the empty-map shape is reachable
// over the wire. What it pins is the rule itself: **absent and empty are one
// fact**, and neither is match-all.
func TestNormalizeServiceReadsAnEmptyMapAsSelectorLess(t *testing.T) {
	for _, test := range []struct {
		name            string
		selector        map[string]string
		wantPresent     bool
		wantKeyCount    int
		wantPodsPlanned bool
	}{
		{"absent", nil, false, 0, false},
		{"empty", map[string]string{}, false, 0, false},
		{"one key", map[string]string{"app": "x"}, true, 1, true},
		{"two keys", map[string]string{"app": "x", "tier": "api"}, true, 2, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := selectorService("uid-1")
			service.Spec.Selector = test.selector
			facts := normalizeService(service)

			if facts.SelectorPresent != test.wantPresent {
				t.Errorf("selector present is %v, want %v",
					facts.SelectorPresent, test.wantPresent)
			}
			if facts.SelectorKeyCount != test.wantKeyCount {
				t.Errorf("selector key count is %d, want %d",
					facts.SelectorKeyCount, test.wantKeyCount)
			}
			pods, slices := plannedReads(facts)
			if pods != test.wantPodsPlanned || slices != test.wantPodsPlanned {
				t.Errorf("planned reads are (pods=%v, slices=%v), want both %v",
					pods, slices, test.wantPodsPlanned)
			}
		})
	}
}
