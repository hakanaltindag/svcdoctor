package client

import (
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"

	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// TestTheNilConditionSemanticsAreExactlyTheFrozenOnes.
//
//	ready       nil => true
//	serving     nil => true
//	terminating nil => false
//
// The asymmetry is Kubernetes' own: an endpoint that says nothing about
// termination is not terminating, and one that says nothing about readiness is
// ready. Reading `ready: nil` as false is the mutation that would turn every
// endpoint on a pre-v1.26 server, and every endpoint a third-party controller
// publishes without conditions, into "not ready".
func TestTheNilConditionSemanticsAreExactlyTheFrozenOnes(t *testing.T) {
	for _, test := range []struct {
		name string
		got  bool
		want bool
	}{
		{"ready nil is true", EffectiveReady(nil), true},
		{"ready true is true", EffectiveReady(ptr(true)), true},
		{"ready false is false", EffectiveReady(ptr(false)), false},
		{"serving nil is true", EffectiveServing(nil), true},
		{"serving true is true", EffectiveServing(ptr(true)), true},
		{"serving false is false", EffectiveServing(ptr(false)), false},
		{"terminating nil is false", EffectiveTerminating(nil), false},
		{"terminating true is true", EffectiveTerminating(ptr(true)), true},
		{"terminating false is false", EffectiveTerminating(ptr(false)), false},
	} {
		if test.got != test.want {
			t.Errorf("%s: got %v", test.name, test.got)
		}
	}
}

// TestEffectiveReadyConsultsReadyAndNothingElse.
//
// # The case that matters
//
// A `serving=true, ready=false, terminating=true` endpoint is **not ready** and
// is **not dead**: Service proxies may still route to such endpoints when every
// available endpoint is terminating. Counting it as ready would misreport a
// draining backend as a healthy one; treating its existence as "nothing is
// serving" would be the opposite error. svcdoctor counts it as not ready and
// records the termination separately, and says nothing else about it at all.
func TestEffectiveReadyConsultsReadyAndNothingElse(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{slices: []discoveryv1.EndpointSlice{
		slice("payments-api-a", "uid-1",
			// The draining endpoint: serving, not ready, terminating.
			endpoint(ptr(false), ptr(true), ptr(true)),
			// An endpoint with no conditions at all: ready by the nil rule.
			endpoint(nil, nil, nil),
			// Plainly not ready, and not terminating either.
			endpoint(ptr(false), ptr(false), nil),
		),
	}}}

	result := acquire(t, server)

	facts := result.PublicationFacts
	if facts.Endpoints != 3 {
		t.Errorf("counted %d endpoints, want 3", facts.Endpoints)
	}
	if facts.ReadyEndpoints != 1 {
		t.Errorf("counted %d ready endpoints, want 1 — only the nil-condition one is ready",
			facts.ReadyEndpoints)
	}
	if facts.TerminatingEndpoints != 1 {
		t.Errorf("counted %d terminating endpoints, want 1", facts.TerminatingEndpoints)
	}
	if !result.Publication.Complete() {
		t.Errorf("the publication is not complete: %+v", result.Publication)
	}
}

// TestServiceAssociationIsByLabelAndOwnerUID.
//
// # What the UID guard is for
//
// A Service may be deleted and recreated between the GET and the LIST. The
// `kubernetes.io/service-name` label is **name**-based, so association by label
// alone would silently cross generations and report the old Service's endpoints
// as the new one's. The owner reference carries the UID, which closes the race
// for free — no fourth API call, and no re-GET that would only move it.
//
// **The name is never consulted.** A matching owner name with a different UID is
// exactly the case this exists to catch.
func TestServiceAssociationIsByLabelAndOwnerUID(t *testing.T) {
	tests := []struct {
		name         string
		slice        discoveryv1.EndpointSlice
		wantAdmitted int
		wantExcluded int
	}{
		{
			name:         "the owner UID matches",
			slice:        slice("a", "uid-1", endpoint(ptr(true), nil, nil)),
			wantAdmitted: 1,
		},
		{
			name:         "the owner name matches and the UID does not",
			slice:        slice("a", "uid-OLD-GENERATION", endpoint(ptr(true), nil, nil)),
			wantExcluded: 1,
		},
		{
			name: "no owner reference at all is admitted by label",
			// A Service may legitimately publish slices it does not own, and
			// refusing them would make svcdoctor disagree with kube-proxy.
			slice:        slice("a", "", endpoint(ptr(true), nil, nil)),
			wantAdmitted: 1,
		},
		{
			name: "an owner that is not a Service is ignored",
			slice: func() discoveryv1.EndpointSlice {
				s := slice("a", "", endpoint(ptr(true), nil, nil))
				s.OwnerReferences = []metav1.OwnerReference{{
					APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "x", UID: types.UID("other"),
				}}
				return s
			}(),
			wantAdmitted: 1,
		},
		{
			name: "a Service owner from another API version is ignored",
			slice: func() discoveryv1.EndpointSlice {
				s := slice("a", "", endpoint(ptr(true), nil, nil))
				s.OwnerReferences = []metav1.OwnerReference{{
					APIVersion: "v2", Kind: "Service", Name: "payments-api",
					UID: types.UID("uid-OLD"),
				}}
				return s
			}(),
			wantAdmitted: 1,
		},
		{
			name: "several owners, the Service one decides",
			slice: func() discoveryv1.EndpointSlice {
				s := slice("a", "", endpoint(ptr(true), nil, nil))
				s.OwnerReferences = []metav1.OwnerReference{
					{APIVersion: "apps/v1", Kind: "Deployment", Name: "d", UID: "d"},
					{APIVersion: "v1", Kind: "Service", Name: "payments-api", UID: "uid-OLD"},
				}
				return s
			}(),
			wantExcluded: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := newAPIServer(t)
			server.service = selectorService("uid-1")
			server.podPages = []scriptedPage{{}}
			server.slicePages = []scriptedPage{{
				slices: []discoveryv1.EndpointSlice{test.slice},
			}}

			result := acquire(t, server)
			facts := result.PublicationFacts

			if facts.Slices != test.wantAdmitted {
				t.Errorf("admitted %d slices, want %d", facts.Slices, test.wantAdmitted)
			}
			if facts.ExcludedByOwnerUID != test.wantExcluded {
				t.Errorf("excluded %d slices, want %d",
					facts.ExcludedByOwnerUID, test.wantExcluded)
			}
			if facts.ReadyEndpoints != test.wantAdmitted {
				t.Errorf("counted %d ready endpoints, want %d",
					facts.ReadyEndpoints, test.wantAdmitted)
			}
			// Excluding a slice does not make the enumeration incomplete: it was
			// enumerated and found not to belong.
			if !result.Publication.Complete() {
				t.Errorf("the publication is not complete: %+v", result.Publication)
			}
		})
	}
}

// TestAThirdPartyManagedSliceIsAdmittedAndDisclosed.
//
// `endpointslice.kubernetes.io/managed-by` does not gate admission: a slice
// carrying the authoritative Service association is a published backend, and
// excluding it would make svcdoctor's answer disagree with kube-proxy's. The
// managing entity is a **disclosure** a reader needs in order to interpret the
// answer, recorded as a boolean rather than as the manager's own name, which is
// operator-controlled text.
func TestAThirdPartyManagedSliceIsAdmittedAndDisclosed(t *testing.T) {
	for index, test := range []struct {
		manager  string
		wantFlag bool
	}{
		{"", false},
		{"endpointslice-controller.k8s.io", false},
		{"endpointslicemirroring-controller.k8s.io", false},
		{"third-party-canary-9f2c", true},
		{"\x1b[31mevil\x1b[0m", true},
	} {
		// The subtest is named by position rather than by the manager, because
		// t.TempDir() derives a directory name from the test name and the
		// kubeconfig path lives in the Result — which would make the leakage
		// assertion below match the test's own scaffolding.
		t.Run("manager-"+strconv.Itoa(index), func(t *testing.T) {
			server := newAPIServer(t)
			server.service = selectorService("uid-1")
			server.podPages = []scriptedPage{{}}
			published := slice("payments-api-a", "uid-1", endpoint(ptr(true), nil, nil))
			if test.manager != "" {
				published.Labels[discoveryv1.LabelManagedBy] = test.manager
			}
			server.slicePages = []scriptedPage{{
				slices: []discoveryv1.EndpointSlice{published},
			}}

			result := acquire(t, server)

			if got := result.PublicationFacts.Slices; got != 1 {
				t.Errorf("admitted %d slices, want 1: managed-by never gates admission", got)
			}
			if got := result.PublicationFacts.ExternallyManaged; got != test.wantFlag {
				t.Errorf("externally managed is %v, want %v", got, test.wantFlag)
			}
			// The manager's own name is never retained, whatever it holds.
			if rendered := renderResult(result); strings.Contains(rendered, "canary-9f2c") ||
				strings.Contains(rendered, "\x1b[") {
				t.Errorf("the manager's name reached the result:\n%s", rendered)
			}
		})
	}
}

// TestDuplicateEndpointsNeverInflateACount.
//
// An endpoint may legitimately appear in more than one slice, and dual-stack
// guarantees separate slices per family. A count that double-counted a
// dual-stack backend would be a number nobody could reconcile with `kubectl`, so
// deduplication is by `targetRef` where present and by the address tuple
// otherwise.
func TestDuplicateEndpointsNeverInflateACount(t *testing.T) {
	withRef := func(name string) discoveryv1.Endpoint {
		return discoveryv1.Endpoint{
			Addresses:  []string{"10.244.0.9"},
			Conditions: discoveryv1.EndpointConditions{Ready: ptr(true)},
			TargetRef: &corev1.ObjectReference{
				Namespace: "payments", Name: name, UID: types.UID("pod-" + name),
			},
		}
	}

	ipv4 := slice("payments-api-a", "uid-1", withRef("pod-1"), withRef("pod-2"))
	ipv6 := slice("payments-api-b", "uid-1", withRef("pod-1"), withRef("pod-2"))
	ipv6.AddressType = discoveryv1.AddressTypeIPv6

	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{
		slices: []discoveryv1.EndpointSlice{ipv4, ipv6},
	}}

	result := acquire(t, server)
	facts := result.PublicationFacts

	if facts.Slices != 2 {
		t.Errorf("admitted %d slices, want 2", facts.Slices)
	}
	if facts.Endpoints != 2 {
		t.Errorf("counted %d endpoints, want 2: one dual-stack backend is one backend",
			facts.Endpoints)
	}
	if facts.ReadyEndpoints != 2 {
		t.Errorf("counted %d ready endpoints, want 2", facts.ReadyEndpoints)
	}
}

// TestListOrderNeverReachesANormalizedValue.
//
// The API's list order is not part of the contract, and it must not decide what
// svcdoctor reports. It can: where the endpoint ceiling truncates an enumeration,
// which endpoints were counted depends entirely on the order they arrived in.
// The same objects in any order must produce the same numbers.
func TestListOrderNeverReachesANormalizedValue(t *testing.T) {
	build := func(order []int) []discoveryv1.EndpointSlice {
		all := []discoveryv1.EndpointSlice{
			slice("payments-api-a", "uid-1",
				readyEndpoint("10.244.0.1", true), readyEndpoint("10.244.0.2", false)),
			slice("payments-api-b", "uid-1",
				readyEndpoint("10.244.0.3", true), readyEndpoint("10.244.0.4", true)),
			slice("payments-api-c", "uid-1", readyEndpoint("10.244.0.5", false)),
		}
		out := make([]discoveryv1.EndpointSlice, 0, len(order))
		for _, index := range order {
			out = append(out, all[index])
		}
		return out
	}

	run := func(t *testing.T, order []int, budgets Budgets) PublicationFacts {
		t.Helper()
		server := newAPIServer(t)
		server.service = selectorService("uid-1")
		server.podPages = []scriptedPage{{}}
		server.slicePages = []scriptedPage{{slices: build(order)}}
		return acquireWithBudgets(t, server, budgets).PublicationFacts
	}

	permutations := [][]int{{0, 1, 2}, {2, 1, 0}, {1, 0, 2}, {2, 0, 1}}

	// Unbounded: every permutation sees every endpoint.
	reference := run(t, permutations[0], Budgets{})
	for _, order := range permutations[1:] {
		if got := run(t, order, Budgets{}); got != reference {
			t.Errorf("permutation %v produced %+v, want %+v", order, got, reference)
		}
	}

	// Truncated: this is where an unsorted implementation diverges, because the
	// three endpoints that fit depend on arrival order.
	truncated := Budgets{MaxEndpoints: 3}
	referenceTruncated := run(t, permutations[0], truncated)
	for _, order := range permutations[1:] {
		if got := run(t, order, truncated); got != referenceTruncated {
			t.Errorf("under the endpoint ceiling, permutation %v produced %+v, want %+v",
				order, got, referenceTruncated)
		}
	}
}

func readyEndpoint(address string, ready bool) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{address},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr(ready)},
	}
}

// TestEndpointOrderWithinASliceNeverReachesANormalizedValue.
//
// # The permutation the slice-level test cannot make
//
// The test above permutes **slices**, which exercises the slice sort and leaves
// the endpoint sort untouched — a mutation that removed the endpoint sort
// survived it. Endpoints inside one slice arrive in whatever order the API
// returned them, and under the endpoint ceiling *which* of them were counted
// depends entirely on that order.
//
// So this permutes endpoints within a single slice and truncates, which is the
// only shape where the second sort is observable.
func TestEndpointOrderWithinASliceNeverReachesANormalizedValue(t *testing.T) {
	// Five endpoints, three of them ready, deliberately interleaved so that any
	// three-element prefix of an unsorted permutation gives a different ready
	// count.
	all := []discoveryv1.Endpoint{
		readyEndpoint("10.244.0.1", true),
		readyEndpoint("10.244.0.2", false),
		readyEndpoint("10.244.0.3", true),
		readyEndpoint("10.244.0.4", false),
		readyEndpoint("10.244.0.5", true),
	}

	run := func(t *testing.T, order []int) PublicationFacts {
		t.Helper()
		endpoints := make([]discoveryv1.Endpoint, 0, len(order))
		for _, index := range order {
			endpoints = append(endpoints, all[index])
		}
		server := newAPIServer(t)
		server.service = selectorService("uid-1")
		server.podPages = []scriptedPage{{}}
		server.slicePages = []scriptedPage{{slices: []discoveryv1.EndpointSlice{
			slice("payments-api-a", "uid-1", endpoints...),
		}}}
		// Three of five, so the sort decides which three are counted.
		return acquireWithBudgets(t, server, Budgets{MaxEndpoints: 3}).PublicationFacts
	}

	permutations := [][]int{
		{0, 1, 2, 3, 4},
		{4, 3, 2, 1, 0},
		{2, 0, 4, 1, 3},
		{1, 4, 0, 3, 2},
	}

	reference := run(t, permutations[0])
	if reference.Endpoints != 3 {
		t.Fatalf("the fixture did not truncate: %+v", reference)
	}
	for _, order := range permutations[1:] {
		if got := run(t, order); got != reference {
			t.Errorf("permutation %v produced %+v, want %+v.\n\n"+
				"Under the endpoint ceiling, which endpoints were counted must not depend "+
				"on the order the API returned them in.", order, got, reference)
		}
	}
}
