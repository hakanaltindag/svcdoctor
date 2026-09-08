//go:build integration

package kubernetes

import (
	"strings"
	"testing"
)

// The seven Service shapes, against a real API server and a real EndpointSlice
// controller.
//
// These are Phase 12.1D's K1–K7. Each asserts the **frozen** admission of the
// four findings — not that svcdoctor produced something, but that it produced
// exactly what ADR 0094 §2.7 says and nothing else.

// TestK1AHealthyClusterIPServiceProducesNoFinding.
//
// The baseline, and the one that would be easiest to pass for the wrong reason:
// a run that failed early also produces no Kubernetes finding. So the evidence
// is asserted too — three complete reads, one matched Pod, one ready endpoint —
// which a broken run cannot produce.
func TestK1AHealthyClusterIPServiceProducesNoFinding(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	if got.code != 0 {
		t.Errorf("exit = %d, want 0\nstderr: %s", got.code, got.stderr)
	}
	assertCodes(t, parsed)

	if status := parsed.Summary.Status; status != "OK" {
		t.Errorf("summary = %s, want OK", status)
	}
	for _, step := range []string{
		"k8s.target", "k8s.api_access", "k8s.service", "k8s.pod_set",
		"k8s.endpoint_publication",
	} {
		if state := parsed.node(t, step).State; state != "PASS" {
			t.Errorf("%s = %s, want PASS", step, state)
		}
	}
	if !boolAttr(t, parsed, "k8s.pod_set", "k8s.pod_set_complete") {
		t.Error("the Pod set is not complete")
	}
	if !boolAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_set_complete") {
		t.Error("the slice set is not complete")
	}
	if n := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"); n != 1 {
		t.Errorf("pod count = %d, want 1", n)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n < 1 {
		t.Errorf("ready endpoint count = %d, want at least 1", n)
	}
	if got := stringAttr(t, parsed, "k8s.service", "k8s.service_type"); got != "ClusterIP" {
		t.Errorf("service type = %s, want ClusterIP", got)
	}
}

// TestK2AnAbsentServiceIsReportedByTheAPIsOwnStatusReason.
//
// The claim rests on `metav1.StatusReason` `NotFound` through `apierrors`, never
// on `Status.Message`. A real 404 is the only way to prove the normalization
// path reads the structured field the contract names.
func TestK2AnAbsentServiceIsReportedByTheAPIsOwnStatusReason(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	got, parsed := h.diagnoseJSON(t, ns, "a-service-that-was-never-created")

	assertCodes(t, parsed, "KUBERNETES_SERVICE_NOT_FOUND")
	if got.code != 1 {
		t.Errorf("exit = %d, want 1 (a target-side problem was proven)\nstderr: %s",
			got.code, got.stderr)
	}

	service := parsed.node(t, "k8s.service")
	if service.State != "FAIL" {
		t.Errorf("k8s.service = %s, want FAIL", service.State)
	}
	if service.Failure != "RESOURCE_NOT_FOUND" {
		t.Errorf("failure class = %s, want RESOURCE_NOT_FOUND", service.Failure)
	}

	// Short-circuiting, measured: the two downstream reads do not run.
	for _, step := range []string{"k8s.pod_set", "k8s.endpoint_publication"} {
		node := parsed.node(t, step)
		if node.State != "SKIPPED" {
			t.Errorf("%s = %s, want SKIPPED; a Service that does not exist has no "+
				"selector to evaluate and no slices to associate", step, node.State)
		}
	}

	// The API server's own prose for a 404 names the resource. It must not be
	// quoted anywhere.
	assertNoProseLeak(t, got, `services "a-service-that-was-never-created" not found`)
	if !strings.Contains(parsed.Findings[0].Summary, "no Service") {
		t.Errorf("the finding does not state the claim: %q", parsed.Findings[0].Summary)
	}
	for _, forbidden := range []string{"was deleted", "never existed", "namespace is wrong"} {
		if strings.Contains(parsed.Findings[0].Detail, forbidden) {
			t.Errorf("the detail carries the forbidden claim %q", forbidden)
		}
	}
}

// TestK3ASelectorMatchingNoPodProducesTheSelectorClaimAlone.
//
// **The F3/F4 disjointness gate, case A**, against a real cluster: a complete
// Pod set at zero and a publication set with no ready endpoint produce F3 and
// **not** F4. The frozen contract says one impact is never described twice at
// one severity, and this is where a real controller could have contradicted it.
func TestK3ASelectorMatchingNoPodProducesTheSelectorClaimAlone(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "a-label-no-pod-carries"}, "  ports:\n    - port: 80\n"))
	h.waitForReadyEndpoints(t, ns, "payments-api", 0)

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	assertCodes(t, parsed, "KUBERNETES_SERVICE_SELECTS_NO_PODS")
	if got.code != 1 {
		t.Errorf("exit = %d, want 1\nstderr: %s", got.code, got.stderr)
	}
	if n := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"); n != 0 {
		t.Errorf("pod count = %d, want 0", n)
	}
	if !boolAttr(t, parsed, "k8s.pod_set", "k8s.pod_set_complete") {
		t.Fatal("the Pod set is incomplete, so this scenario proves nothing about F3")
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 0 {
		t.Fatalf("ready endpoint count = %d, want 0; F4's own precondition is not met, "+
			"so the disjointness this test exists for is not being exercised", n)
	}
	if !boolAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_set_complete") {
		t.Fatal("the slice set is incomplete, so F4 was withheld for the wrong reason " +
			"and disjointness is not what this run measured")
	}
}

// TestK4APodSelectedWithNoReadyEndpointProducesThePublicationClaimAlone.
//
// **Disjointness case B.** The fixture establishes the state through the API
// rather than assuming it from a Pod phase: it waits until the controller has
// published a slice and until zero of its endpoints are ready.
//
// The Pod is made permanently unready by a readiness probe that cannot succeed,
// which is `PHASE121A…§13.2`'s own fixture design — *"deliberately not built on
// a zero-matching-Pod Service, which would test the fixture rather than the
// contract"*.
func TestK4APodSelectedWithNoReadyEndpointProducesThePublicationClaimAlone(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, `apiVersion: v1
kind: Pod
metadata:
  name: backend
  namespace: `+ns+`
  labels:
    app: "payments"
spec:
  containers:
    - name: c
      image: `+pauseImage+`
      readinessProbe:
        exec:
          command: ["/false-command-that-does-not-exist"]
        initialDelaySeconds: 0
        periodSeconds: 1
        failureThreshold: 1
`)
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	// Ground truth, from the API: a slice exists, it carries exactly one
	// endpoint, and that endpoint is not ready. Waiting on the Pod's phase would
	// be waiting on the wrong object, and waiting only for "zero ready" is
	// satisfied by an empty slice — see waitForEndpointCounts.
	h.waitForSliceCount(t, ns, "payments-api", 1)
	h.waitForEndpointCounts(t, ns, "payments-api", 1, 0)

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	assertCodes(t, parsed, "KUBERNETES_SERVICE_NO_READY_ENDPOINT")
	if got.code != 1 {
		t.Errorf("exit = %d, want 1\nstderr: %s", got.code, got.stderr)
	}
	if n := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"); n != 1 {
		t.Fatalf("pod count = %d, want 1; without a selected Pod this is K3 rather "+
			"than K4 and proves nothing about disjointness", n)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.slice_count"); n != 1 {
		t.Errorf("slice count = %d, want 1", n)
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.endpoint_count"); n < 1 {
		t.Errorf("endpoint count = %d, want at least 1; the detail variant this "+
			"scenario is about is 'published and none ready'", n)
	}

	// The claim ceiling, on the finding a real controller produced.
	detail := parsed.Findings[0].Detail + parsed.Findings[0].Summary
	for _, forbidden := range []string{
		"unreachable", "cannot connect", "unavailable", "unhealthy", "down",
		"network", "readiness probe",
	} {
		if strings.Contains(strings.ToLower(detail), forbidden) {
			t.Errorf("the publication claim carries the forbidden word %q:\n%s",
				forbidden, detail)
		}
	}
	if !strings.Contains(strings.ToLower(detail), "publish") {
		t.Errorf("the claim does not say what it is about — publication:\n%s", detail)
	}
}

// TestK5ASelectorLessServiceProducesNoSemanticFinding.
//
// An **empty selector map is selector-less, not match-all** (ADR 0094 §2.4), so
// F3 is structurally unreachable and F4 is withheld. A real Service with no
// selector is the case where a client-side filter would have produced a claim.
func TestK5ASelectorLessServiceProducesNoSemanticFinding(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	// A Pod that any match-all reading would have selected.
	h.apply(t, podManifest(ns, "unrelated", map[string]string{"app": "something-else"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP", nil,
		"  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "unrelated")

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	assertCodes(t, parsed)
	if got.code != 0 {
		t.Errorf("exit = %d, want 0\nstderr: %s", got.code, got.stderr)
	}
	if boolAttr(t, parsed, "k8s.service", "k8s.selector_present") {
		t.Error("a Service with no selector is recorded as carrying one")
	}
	for _, step := range []string{"k8s.pod_set", "k8s.endpoint_publication"} {
		if state := parsed.node(t, step).State; state != "SKIPPED" {
			t.Errorf("%s = %s, want SKIPPED; a selector-less Service has no selector "+
				"result and no associated publication to enumerate", step, state)
		}
	}
}

// TestK6AnExternalNameServiceProducesNoSemanticFinding.
//
// `ExternalName` is unsupported for backend publication and reported as such;
// absent slices there are correct rather than a fault.
func TestK6AnExternalNameServiceProducesNoSemanticFinding(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ExternalName", nil,
		"  externalName: example.invalid\n"))

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	assertCodes(t, parsed)
	if got.code != 0 {
		t.Errorf("exit = %d, want 0\nstderr: %s", got.code, got.stderr)
	}
	if got := stringAttr(t, parsed, "k8s.service", "k8s.service_type"); got != "ExternalName" {
		t.Errorf("service type = %s, want ExternalName", got)
	}
	for _, step := range []string{"k8s.pod_set", "k8s.endpoint_publication"} {
		if state := parsed.node(t, step).State; state != "SKIPPED" {
			t.Errorf("%s = %s, want SKIPPED", step, state)
		}
	}
}

// TestK7AHeadlessSelectorBackedServiceIsDiagnosedNormally.
//
// `clusterIP: None` with a selector is a **fully supported** backend
// publication, and the case most likely to be mistaken for selector-less. It
// must produce the ordinary semantic model and no false finding.
func TestK7AHeadlessSelectorBackedServiceIsDiagnosedNormally(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"},
		"  clusterIP: None\n  ports:\n    - port: 80\n"))

	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	assertCodes(t, parsed)
	if got.code != 0 {
		t.Errorf("exit = %d, want 0\nstderr: %s", got.code, got.stderr)
	}
	if !boolAttr(t, parsed, "k8s.service", "k8s.service_headless") {
		t.Error("a headless Service is not recorded as headless")
	}
	if !boolAttr(t, parsed, "k8s.service", "k8s.selector_present") {
		t.Error("a headless selector-backed Service is recorded as selector-less; that " +
			"is the misreading ADR 0094 §2.4 exists to prevent")
	}
	for _, step := range []string{"k8s.pod_set", "k8s.endpoint_publication"} {
		if state := parsed.node(t, step).State; state != "PASS" {
			t.Errorf("%s = %s, want PASS; a headless Service publishes backends and is "+
				"neither selector-less nor ExternalName", step, state)
		}
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 1 {
		t.Errorf("ready endpoint count = %d, want 1", n)
	}
}
