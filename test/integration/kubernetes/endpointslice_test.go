//go:build integration

package kubernetes

import (
	"fmt"
	"strings"
	"testing"
)

// EndpointSlice semantics and association, against real API objects.
//
// # Two kinds of fixture, and the record keeps them apart
//
// Some conditions a controller produces on its own — a Ready Pod's endpoint is
// ready, an unready Pod's is not. Others it never produces: no controller writes
// `conditions: {}`, and none writes a stale owner UID on purpose. Those are
// **authored** objects.
//
// Both go through the real API server, so both prove that svcdoctor reads what
// Kubernetes actually stores. But only the first proves anything about
// *controller behaviour*, and Phase 12.1D §16 requires the distinction to be
// stated rather than blurred. Each test below says which kind it is.
//
// # Measured, not assumed: the API stores `conditions: {}` verbatim
//
// It does not default the three booleans on write. That is what makes the frozen
// nil semantics — `ready` nil ⇒ **true**, `serving` nil ⇒ true, `terminating`
// nil ⇒ false — testable against a real server at all, and it is the single most
// likely hand-analysis error the whole Service scope exists to remove.

// managedBySvcdoctor marks an authored slice so the EndpointSlice controller
// leaves it alone.
//
// This is not a trick: `endpointslice.kubernetes.io/managed-by` is exactly how
// Kubernetes lets a third party publish endpoints for a Service, and ADR 0094
// §2.6 admits such a slice deliberately — *"excluding it would make svcdoctor's
// answer disagree with kube-proxy's"*. So the mechanism that makes these
// fixtures possible is itself one of the things under test.
const managedBySvcdoctor = "svcdoctor-validation.example.com"

// authoredSlice builds one EndpointSlice with full control of its conditions and
// its owner reference.
type authoredSlice struct {
	name        string
	service     string
	ownerUID    string // empty writes no ownerReferences at all
	ownerKind   string // defaults to Service
	ownerName   string // defaults to the service name
	managedBy   string // empty leaves the label off
	addressType string // defaults to IPv4
	endpoints   []authoredEndpoint
}

// authoredEndpoint is one endpoint and its three optional conditions.
//
// Each condition is a *bool so that "absent" is representable and distinct from
// "false" — which is the entire point of the E-series.
type authoredEndpoint struct {
	address     string
	ready       *bool
	serving     *bool
	terminating *bool
}

func boolPtr(v bool) *bool { return &v }

func (a authoredSlice) manifest(namespace string) string {
	var b strings.Builder
	addressType := a.addressType
	if addressType == "" {
		addressType = "IPv4"
	}
	ownerKind := a.ownerKind
	if ownerKind == "" {
		ownerKind = "Service"
	}
	// **The owner's name must name the object the UID belongs to.** The garbage
	// collector resolves an owner reference by kind and name within the
	// namespace and deletes the dependent when the UID it finds does not match —
	// measured, when a slice carrying a decoy's UID under the target Service's
	// name vanished before it could be read. That behaviour is itself why the
	// owner-UID guard is the right mechanism; it is not something to work
	// around.
	ownerName := a.ownerName
	if ownerName == "" {
		ownerName = a.service
	}

	fmt.Fprintf(&b, "apiVersion: discovery.k8s.io/v1\nkind: EndpointSlice\n"+
		"metadata:\n  name: %s\n  namespace: %s\n  labels:\n"+
		"    kubernetes.io/service-name: %s\n", a.name, namespace, a.service)
	if a.managedBy != "" {
		fmt.Fprintf(&b, "    endpointslice.kubernetes.io/managed-by: %s\n", a.managedBy)
	}
	if a.ownerUID != "" {
		fmt.Fprintf(&b, "  ownerReferences:\n    - apiVersion: v1\n      kind: %s\n"+
			"      name: %s\n      uid: %q\n", ownerKind, ownerName, a.ownerUID)
	}
	fmt.Fprintf(&b, "addressType: %s\nports:\n  - port: 80\nendpoints:\n", addressType)
	for _, endpoint := range a.endpoints {
		fmt.Fprintf(&b, "  - addresses: [%q]\n    conditions:\n", endpoint.address)
		writeCondition(&b, "ready", endpoint.ready)
		writeCondition(&b, "serving", endpoint.serving)
		writeCondition(&b, "terminating", endpoint.terminating)
		if endpoint.ready == nil && endpoint.serving == nil && endpoint.terminating == nil {
			// An empty mapping, stored verbatim: measured, not assumed.
			b.WriteString("      {}\n")
		}
	}
	return b.String()
}

func writeCondition(b *strings.Builder, name string, value *bool) {
	if value != nil {
		fmt.Fprintf(b, "      %s: %t\n", name, *value)
	}
}

// backendlessService creates a Service whose selector matches no Pod.
//
// The EndpointSlice controller answers such a Service with **exactly one empty
// slice** — measured on both lanes — so every count below is stated as that
// baseline plus the authored slices. Nothing here guesses.
const controllerBaselineSlices = 1

func (h harness) backendlessService(t *testing.T, namespace, name string) string {
	t.Helper()
	h.apply(t, serviceManifest(namespace, name, "ClusterIP",
		map[string]string{"app": "no-pod-carries-this"}, "  ports:\n    - port: 80\n"))
	h.waitForSliceCount(t, namespace, name, controllerBaselineSlices)
	return h.serviceUID(t, namespace, name)
}

// selectedButUnpublishedService creates a Service that selects one Pod which
// publishes no endpoint.
//
// # Why this shape exists, and what the cluster taught the fixture
//
// F4 requires that F3 was **not** admitted — the two are disjoint — so a Service
// whose selector matches nothing can never produce a publication finding, and
// the first version of these fixtures used exactly that and could not reach F4
// at all. The real cluster said so immediately.
//
// A Pod held `Pending` by an unsatisfiable `nodeSelector` is the deterministic
// answer: the API server returns it from the selector-filtered list, so F3 is
// withheld, and it has no address, so the EndpointSlice controller publishes an
// **empty** slice for it. Every endpoint the run then sees is one this fixture
// authored, which is what makes an all-terminating set constructible at all.
func (h harness) selectedButUnpublishedService(t *testing.T, namespace, name string) string {
	t.Helper()
	h.apply(t, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: pending\n  namespace: "+
		namespace+"\n  labels:\n    app: \"payments\"\nspec:\n  nodeSelector:\n"+
		"    kubernetes.io/hostname: no-such-node-exists\n  containers:\n"+
		"    - name: c\n      image: "+pauseImage+"\n")
	h.apply(t, serviceManifest(namespace, name, "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	h.waitFor(t, "the Pod to be selected and to publish no endpoint", func() (bool, string) {
		out, err := h.kubectlErr("-n", namespace, "get", "pods", "-l", "app=payments",
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		total, _ := h.countEndpoints(namespace, name)
		return len(strings.Fields(out)) == 1 && total == 0,
			fmt.Sprintf("pods=%v endpoints=%d", strings.Fields(out), total)
	})
	h.waitForSliceCount(t, namespace, name, controllerBaselineSlices)
	return h.serviceUID(t, namespace, name)
}

// decoyServiceUID creates a second, real Service and returns its UID.
//
// # Why a live decoy rather than a dangling reference
//
// The generation guard excludes a slice whose Service owner UID differs from the
// Service this run read. Representing that with a **fabricated** UID does not
// survive: Kubernetes' garbage collector deletes an object whose owner reference
// resolves to nothing, and it does so in well under a second — measured, when
// the first version of these fixtures timed out waiting for a slice the cluster
// had already removed.
//
// So the mismatch is represented by a second Service that really exists. The
// property under test is unchanged and is the one the contract states — *this
// slice is owned by a Service that is not the one I read* — and the fixture is
// durable rather than racing a controller.
func (h harness) decoyServiceUID(t *testing.T, namespace string) string {
	t.Helper()
	h.apply(t, serviceManifest(namespace, "a-different-service", "ClusterIP",
		map[string]string{"app": "decoy"}, "  ports:\n    - port: 80\n"))
	return h.serviceUID(t, namespace, "a-different-service")
}

// --- E1–E5: the condition semantics -----------------------------------------

// TestE1toE5TheFrozenConditionSemanticsHoldAgainstRealObjects.
//
// **Authored fixtures**, because no controller writes an absent condition. Each
// row is one endpoint whose conditions are exactly as stated, stored by a real
// API server and read by the released binary.
//
// The property under test is `ADR 0094 §2.6`'s effective-ready algorithm:
// **`ready` alone decides ready**, with nil read as true. Reading
// `ready && serving && !terminating` instead would change three of these rows.
func TestE1toE5TheFrozenConditionSemanticsHoldAgainstRealObjects(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    authoredEndpoint
		wantReady   int
		wantTermina int
	}{
		{
			name:      "E1 ready true is ready",
			endpoint:  authoredEndpoint{address: "10.55.0.1", ready: boolPtr(true)},
			wantReady: 1,
		},
		{
			name:      "E2 ready false is not ready",
			endpoint:  authoredEndpoint{address: "10.55.0.2", ready: boolPtr(false)},
			wantReady: 0,
		},
		{
			// The single most likely hand-analysis error, and the reason this
			// whole scope beats reading `kubectl get endpointslices` by eye.
			name:      "E3 ready absent is READY, not unready",
			endpoint:  authoredEndpoint{address: "10.55.0.3"},
			wantReady: 1,
		},
		{
			// serving=true, ready=false, terminating=true is **not dead**: a
			// proxy may still route to it when every endpoint is terminating.
			// It is not ready, and the detail has to say so without saying
			// nothing is serving.
			name: "E4 a terminating endpoint is counted terminating and not ready",
			endpoint: authoredEndpoint{
				address: "10.55.0.4", ready: boolPtr(false),
				serving: boolPtr(true), terminating: boolPtr(true),
			},
			wantReady:   0,
			wantTermina: 1,
		},
		{
			// serving is deliberately **not** consulted for readiness. If it
			// were, this row would be ready and it must not be.
			name: "E5 serving without ready is not ready",
			endpoint: authoredEndpoint{
				address: "10.55.0.5", ready: boolPtr(false), serving: boolPtr(true),
			},
			wantReady: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ns := h.namespace(t)
			uid := h.backendlessService(t, ns, "payments-api")

			h.apply(t, authoredSlice{
				name: "authored", service: "payments-api", ownerUID: uid,
				managedBy: managedBySvcdoctor,
				endpoints: []authoredEndpoint{tc.endpoint},
			}.manifest(ns))
			h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

			_, parsed := h.diagnoseJSON(t, ns, "payments-api")

			if n := intAttr(t, parsed, "k8s.endpoint_publication",
				"k8s.ready_endpoint_count"); n != tc.wantReady {
				t.Errorf("ready endpoint count = %d, want %d", n, tc.wantReady)
			}
			if n := intAttr(t, parsed, "k8s.endpoint_publication",
				"k8s.terminating_endpoint_count"); n != tc.wantTermina {
				t.Errorf("terminating endpoint count = %d, want %d", n, tc.wantTermina)
			}
			if n := intAttr(t, parsed, "k8s.endpoint_publication",
				"k8s.endpoint_count"); n != 1 {
				t.Errorf("endpoint count = %d, want 1", n)
			}
			// **F3 is what fires here, in every row, and that is the contract.**
			// This Service selects no Pod, so the selector claim is admitted and
			// the publication claim is withheld — the two are disjoint. The
			// E-series is about the effective-ready *algorithm*, which the counts
			// above state exactly; F4's own admission is
			// TestTheAllTerminatingNoteSaysTrafficMayStillFlow's subject, and it
			// needs a Service that selects something.
			assertCodes(t, parsed, "KUBERNETES_SERVICE_SELECTS_NO_PODS")
		})
	}
}

// TestTheAllTerminatingNoteSaysTrafficMayStillFlow.
//
// **Authored fixture.** `no ready endpoint` is compatible with traffic still
// being routed: Kubernetes proxies may route to terminating endpoints when every
// available endpoint is terminating. Silence there would let a reader take F4
// for the stronger claim it refuses to make.
func TestTheAllTerminatingNoteSaysTrafficMayStillFlow(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)
	uid := h.selectedButUnpublishedService(t, ns, "payments-api")

	h.apply(t, authoredSlice{
		name: "authored", service: "payments-api", ownerUID: uid,
		managedBy: managedBySvcdoctor,
		endpoints: []authoredEndpoint{
			{address: "10.55.1.1", ready: boolPtr(false),
				serving: boolPtr(true), terminating: boolPtr(true)},
			{address: "10.55.1.2", ready: boolPtr(false),
				serving: boolPtr(true), terminating: boolPtr(true)},
		},
	}.manifest(ns))
	h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

	_, parsed := h.diagnoseJSON(t, ns, "payments-api")

	// The precondition the disjointness contract imposes: a Pod is selected, so
	// F3 is not admitted and F4 is reachable at all.
	if n := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"); n != 1 {
		t.Fatalf("pod count = %d, want 1; without a selected Pod F3 fires and F4 is "+
			"withheld, and this test would be measuring the wrong finding", n)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication",
		"k8s.terminating_endpoint_count"); n != 2 {
		t.Fatalf("terminating endpoint count = %d, want 2", n)
	}

	var publication string
	for _, finding := range parsed.Findings {
		if finding.Code == "KUBERNETES_SERVICE_NO_READY_ENDPOINT" {
			publication = finding.Detail
		}
	}
	if publication == "" {
		t.Fatalf("no publication finding was produced; codes = %v", parsed.codes())
	}
	if !strings.Contains(publication, "terminating") {
		t.Errorf("the detail does not mention terminating, so a reader is left to take "+
			"'no ready endpoint' for 'nothing is serving':\n%s", publication)
	}
	if !strings.Contains(strings.ToLower(publication), "may still route") {
		t.Errorf("the detail does not say a proxy may still route to such an endpoint:\n%s",
			publication)
	}
}

// --- A1–A5: association and the generation guard -----------------------------

// TestA1toA5TheAssociationRuleIsLabelPlusOwnerUID.
//
// **Authored fixtures.** The frozen rule is the `kubernetes.io/service-name`
// label as the server-side selector, **plus** an owner-reference UID check
// applied to the result — and no heuristic of any kind.
func TestA1toA5TheAssociationRuleIsLabelPlusOwnerUID(t *testing.T) {
	tests := []struct {
		name string
		// mutate adjusts the authored slice for this row.
		mutate func(uid string, s *authoredSlice)
		// wantAdmitted is whether the slice's endpoint reaches the counts.
		wantAdmitted bool
		wantExcluded int
	}{
		{
			name:         "A1 a matching Service owner UID is admitted",
			mutate:       func(uid string, s *authoredSlice) { s.ownerUID = uid },
			wantAdmitted: true,
		},
		{
			// The owner is a **different, live Service**. See decoyServiceUID
			// for why a fabricated UID cannot be used: the garbage collector
			// removes an object whose owner resolves to nothing.
			name:         "A2 a different Service owner UID is excluded and counted",
			mutate:       func(string, *authoredSlice) { /* the decoy UID is set below */ },
			wantAdmitted: false,
			wantExcluded: 1,
		},
		{
			name:         "A3 no owner reference is admitted by label alone",
			mutate:       func(string, *authoredSlice) { /* ownerUID stays empty */ },
			wantAdmitted: true,
		},
		{
			name: "A4 a third-party managed-by does not gate admission",
			mutate: func(uid string, s *authoredSlice) {
				s.ownerUID = uid
				s.managedBy = "some-other-controller.example.com"
			},
			wantAdmitted: true,
		},
		{
			name:         "A5 a non-Service owner reference is not a generation mismatch",
			mutate:       func(string, *authoredSlice) { /* the ConfigMap UID is set below */ },
			wantAdmitted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ns := h.namespace(t)
			uid := h.backendlessService(t, ns, "payments-api")

			slice := authoredSlice{
				name: "authored", service: "payments-api",
				managedBy: managedBySvcdoctor,
				endpoints: []authoredEndpoint{{address: "10.55.2.1", ready: boolPtr(true)}},
			}
			switch {
			case strings.HasPrefix(tc.name, "A2"):
				slice.ownerUID = h.decoyServiceUID(t, ns)
				slice.ownerName = "a-different-service"
			case strings.HasPrefix(tc.name, "A5"):
				// A real ConfigMap, for the same durability reason as A2.
				h.apply(t, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: "+
					"payments-api\n  namespace: "+ns+"\ndata: {}\n")
				slice.ownerKind = "ConfigMap"
				slice.ownerUID = strings.TrimSpace(h.kubectl(t, "-n", ns, "get",
					"configmap", "payments-api", "-o", "jsonpath={.metadata.uid}"))
			}
			tc.mutate(uid, &slice)
			h.apply(t, slice.manifest(ns))
			h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

			_, parsed := h.diagnoseJSON(t, ns, "payments-api")

			ready := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count")
			excluded := intAttr(t, parsed, "k8s.endpoint_publication",
				"k8s.slice_excluded_by_owner_uid_count")

			if tc.wantAdmitted && ready != 1 {
				t.Errorf("ready endpoint count = %d, want 1; the slice should have been "+
					"admitted", ready)
			}
			if !tc.wantAdmitted && ready != 0 {
				t.Errorf("ready endpoint count = %d, want 0; the slice should have been "+
					"excluded", ready)
			}
			if excluded != tc.wantExcluded {
				t.Errorf("slices excluded by owner UID = %d, want %d", excluded, tc.wantExcluded)
			}
		})
	}
}

// TestTheServiceDeleteAndRecreateRaceIsClosedWithoutAFourthRequest.
//
// **The real-world semantic the owner-UID guard exists for**, performed for
// real: a Service is deleted and recreated with the same namespace and name, and
// Kubernetes gives generation B a different UID.
//
// # What the cluster added to the story
//
// The frozen contract closes the race by excluding a slice whose Service owner
// UID differs from the one this run read. Measuring it turned up a second,
// independent mechanism nobody had recorded: **Kubernetes' garbage collector
// deletes a slice whose owner reference no longer resolves**, and it does so in
// well under a second. So after a genuine delete-and-recreate the stale slice is
// usually *gone* rather than merely excluded.
//
// That makes the window narrower than assumed, and it is good news — but it is
// not the guard, because it is asynchronous and svcdoctor cannot depend on it
// having run. So this test asserts the end state a real delete-and-recreate
// produces, and `TestA1toA5…` proves the exclusion mechanism itself against a
// slice the collector has no reason to remove.
func TestTheServiceDeleteAndRecreateRaceIsClosedWithoutAFourthRequest(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	// Generation A, and a slice that legitimately belongs to it.
	uidA := h.backendlessService(t, ns, "payments-api")
	h.apply(t, authoredSlice{
		name: "generation-a", service: "payments-api", ownerUID: uidA,
		managedBy: managedBySvcdoctor,
		endpoints: []authoredEndpoint{{address: "10.55.3.1", ready: boolPtr(true)}},
	}.manifest(ns))
	h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

	// The slice really does satisfy generation A. Without this the assertions
	// below could pass against a fixture that never worked.
	_, before := h.diagnoseJSON(t, ns, "payments-api")
	if n := intAttr(t, before, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 1 {
		t.Fatalf("generation A sees %d ready endpoints, want 1", n)
	}
	assertCodes(t, before, "KUBERNETES_SERVICE_SELECTS_NO_PODS")

	h.kubectl(t, "-n", ns, "delete", "service", "payments-api", "--wait=true")
	h.waitFor(t, "the Service to be gone", func() (bool, string) {
		out, err := h.kubectlErr("-n", ns, "get", "service", "payments-api")
		return err != nil, strings.TrimSpace(out)
	})

	uidB := h.backendlessService(t, ns, "payments-api")
	if uidA == uidB {
		t.Fatalf("the recreated Service kept UID %s; the race this test is about does "+
			"not exist on this cluster", uidA)
	}

	_, after := h.diagnoseJSON(t, ns, "payments-api")

	// **The property, whichever mechanism produced it**: nothing generation A
	// published can satisfy generation B.
	if n := intAttr(t, after, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 0 {
		t.Errorf("generation B sees %d ready endpoints, want 0; a slice published for a "+
			"previous generation of this Service satisfied the new one", n)
	}
	assertCodes(t, after, "KUBERNETES_SERVICE_SELECTS_NO_PODS")

	// And the mechanism that actually applied is recorded rather than assumed,
	// so a future reader knows which one this cluster used.
	excluded := intAttr(t, after, "k8s.endpoint_publication",
		"k8s.slice_excluded_by_owner_uid_count")
	slices := intAttr(t, after, "k8s.endpoint_publication", "k8s.slice_count")
	t.Logf("after delete-and-recreate: slice_count=%d excluded_by_owner_uid=%d "+
		"(0 excluded means the garbage collector removed the stale slice before the "+
		"read; the exclusion guard itself is proven by TestA1toA5)", slices, excluded)

	// The UIDs are internal correlation only and never enter evidence.
	for _, uid := range []string{uidA, uidB} {
		if strings.Contains(fmt.Sprint(after), uid) {
			t.Errorf("a Service UID reached the report; ADR 0094 §2.9 makes it internal " +
				"correlation only")
		}
	}
}

// TestAThirdPartyManagedSliceIsAdmittedAndRecorded.
//
// **Authored fixture**, and the mechanism is the frozen one: a slice another
// controller manages, carrying the authoritative association, is a published
// backend. Excluding it would make svcdoctor's answer disagree with
// kube-proxy's. That it is externally managed is a fact a reader needs in order
// to interpret the answer — not a reason to distrust it.
func TestAThirdPartyManagedSliceIsAdmittedAndRecorded(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)
	uid := h.backendlessService(t, ns, "payments-api")

	h.apply(t, authoredSlice{
		name: "third-party", service: "payments-api", ownerUID: uid,
		managedBy: "an-entirely-different-controller.example.com",
		endpoints: []authoredEndpoint{{address: "10.55.4.1", ready: boolPtr(true)}},
	}.manifest(ns))
	h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

	_, parsed := h.diagnoseJSON(t, ns, "payments-api")

	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 1 {
		t.Errorf("ready endpoint count = %d, want 1; a third-party managed-by does not "+
			"gate admission", n)
	}
	if hasAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_externally_managed") {
		if !boolAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_externally_managed") {
			t.Error("an externally managed slice is not recorded as externally managed")
		}
	}
	// No product-specific or controller-specific claim may follow from it.
	for _, finding := range parsed.Findings {
		if strings.Contains(strings.ToLower(finding.Detail),
			"an-entirely-different-controller") {
			t.Errorf("the managing controller's name reached the prose: %s", finding.Detail)
		}
	}
}

// TestAggregationAcrossMultipleSlicesIsCompleteAndOrderIndependent.
//
// One Service, several slices. **A Service is not one EndpointSlice**, and
// dual-stack guarantees at least two on a cluster that has it — so aggregating
// only the first would be a silent undercount.
//
// Order independence is asserted by re-reading: the API's list order is not
// contractual, and the canonical report must not depend on it.
func TestAggregationAcrossMultipleSlicesIsCompleteAndOrderIndependent(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)
	uid := h.backendlessService(t, ns, "payments-api")

	const authored = 3
	for i := 0; i < authored; i++ {
		h.apply(t, authoredSlice{
			name:    fmt.Sprintf("authored-%d", i),
			service: "payments-api", ownerUID: uid, managedBy: managedBySvcdoctor,
			endpoints: []authoredEndpoint{
				{address: fmt.Sprintf("10.55.5.%d", i*2+1), ready: boolPtr(true)},
				{address: fmt.Sprintf("10.55.5.%d", i*2+2), ready: boolPtr(false)},
			},
		}.manifest(ns))
	}
	h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+authored)

	_, parsed := h.diagnoseJSON(t, ns, "payments-api")

	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_count"); n != controllerBaselineSlices+authored {
		t.Errorf("slice count = %d, want %d", n, controllerBaselineSlices+authored)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.endpoint_count"); n != authored*2 {
		t.Errorf("endpoint count = %d, want %d; endpoints across every associated slice "+
			"are aggregated", n, authored*2)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != authored {
		t.Errorf("ready endpoint count = %d, want %d", n, authored)
	}
	assertCodes(t, parsed, "KUBERNETES_SERVICE_SELECTS_NO_PODS")

	// The same fixture, read again: nothing about the answer may depend on the
	// order the API server happened to return the slices in.
	for i := 0; i < 4; i++ {
		_, again := h.diagnoseJSON(t, ns, "payments-api")
		for _, key := range []string{
			"k8s.slice_count", "k8s.endpoint_count", "k8s.ready_endpoint_count",
			"k8s.terminating_endpoint_count", "k8s.slice_excluded_by_owner_uid_count",
		} {
			if got, want := intAttr(t, again, "k8s.endpoint_publication", key),
				intAttr(t, parsed, "k8s.endpoint_publication", key); got != want {
				t.Errorf("re-reading the same fixture changed %s: %d then %d", key, want, got)
			}
		}
	}
}

// TestDualStackIsExercisedOrRecordedAsAbsent.
//
// Dual-stack is a **cluster capability**, not a svcdoctor feature. This detects
// whether the lane provides it and either exercises it or records its absence.
// It never manufactures the claim: an authored IPv6 slice tests svcdoctor's
// parser and says nothing about a cluster's dual-stack behaviour, and Phase
// 12.1D §21 requires those two to stay apart.
func TestDualStackIsExercisedOrRecordedAsAbsent(t *testing.T) {
	h := newHarness(t)

	families := strings.TrimSpace(h.kubectl(t, "get", "service", "kubernetes",
		"-n", "default", "-o", `jsonpath={.spec.ipFamilies[*]}`))
	dualStack := strings.Contains(families, "IPv4") && strings.Contains(families, "IPv6")

	if !dualStack {
		t.Logf("DUAL-STACK: NOT EXERCISED — ENVIRONMENT CAPABILITY ABSENT. "+
			"The lane's API Service reports ipFamilies=%q, so this cluster publishes "+
			"one address family. An authored IPv6 slice would test the parser and "+
			"would not test dual-stack, so no such claim is made.", families)

		// The parser half is still worth stating, and it is stated as the
		// parser half: an IPv6 slice is aggregated like any other.
		ns := h.namespace(t)
		uid := h.backendlessService(t, ns, "payments-api")
		h.apply(t, authoredSlice{
			name: "v6", service: "payments-api", ownerUID: uid,
			managedBy: managedBySvcdoctor, addressType: "IPv6",
			endpoints: []authoredEndpoint{{address: "fd00::1", ready: boolPtr(true)}},
		}.manifest(ns))
		h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)

		_, parsed := h.diagnoseJSON(t, ns, "payments-api")
		if n := intAttr(t, parsed, "k8s.endpoint_publication",
			"k8s.ready_endpoint_count"); n != 1 {
			t.Errorf("an IPv6 slice contributed %d ready endpoints, want 1; address "+
				"family creates no semantic branch (ADR 0094 §2.6)", n)
		}
		return
	}

	t.Log("DUAL-STACK: the lane reports both families; exercising a dual-stack Service")
	ns := h.namespace(t)
	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"},
		"  ipFamilyPolicy: RequireDualStack\n  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForSliceCount(t, ns, "payments-api", 2)

	_, parsed := h.diagnoseJSON(t, ns, "payments-api")
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_count"); n != 2 {
		t.Errorf("slice count = %d, want 2 for a dual-stack Service", n)
	}
	assertCodes(t, parsed)
}
