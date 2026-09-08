//go:build integration

package kubernetes

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// In-cluster authentication, from inside the cluster.
//
// # The gap this closes
//
// Phase 12.1C.2 proved every one of `--in-cluster`'s *refusals* — with a
// kubeconfig, with a context, with either token source — and could prove no
// execution at all, because the mode needs a projected ServiceAccount and a
// hermetic test has none. That was recorded as a limitation rather than papered
// over.
//
// This closes it the only way it can be closed: svcdoctor runs **inside a Pod**,
// as a ServiceAccount holding exactly the three frozen permissions, reading the
// projected token and CA from the standard paths.
//
// # What it must produce
//
// The same evidence and the same findings as the equivalent external kubeconfig
// run. In-cluster is a way of obtaining a credential, not a different product.

// TestInClusterAuthenticationDiagnosesFromInsideThePod.
//
// The image is built locally from the repository's own binary and loaded into
// the kind node. Nothing is pushed and nothing is published: Phase 12.1D §12.
func TestInClusterAuthenticationDiagnosesFromInsideThePod(t *testing.T) {
	h := newHarness(t)
	requireBinaries(t, "docker", "kind")

	cluster := os.Getenv("SVCDOCTOR_KIND_CLUSTER")
	if cluster == "" {
		t.Fatal("SVCDOCTOR_KIND_CLUSTER is not set; the in-cluster lane needs to know " +
			"which kind cluster to load the image into. Run this suite through " +
			"`make integration-kubernetes`.")
	}

	ns := h.namespace(t)

	// The Service under test, and a Pod backing it, so the run has something
	// with a complete and healthy shape to report.
	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	// The identity svcdoctor will run as: exactly the frozen three permissions.
	// restrictedIdentity also mints a token, which this test does not use — the
	// projected one is the point — and creating it costs nothing.
	h.restrictedIdentity(t, ns, "in-cluster", frozenRules)

	image := buildAndLoadImage(t, cluster)

	// A Job, not a Deployment: svcdoctor runs, reports and exits (ADR 0062 §9).
	h.apply(t, `apiVersion: batch/v1
kind: Job
metadata:
  name: svcdoctor
  namespace: `+ns+`
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: in-cluster
      automountServiceAccountToken: true
      containers:
        - name: svcdoctor
          image: `+image+`
          imagePullPolicy: Never
          args:
            - diagnose
            - kubernetes
            - --in-cluster
            - --namespace
            - `+ns+`
            - --service-name
            - payments-api
            - --output
            - json
`)

	h.waitFor(t, "the svcdoctor Job to finish", func() (bool, string) {
		out, err := h.kubectlErr("-n", ns, "get", "job", "svcdoctor",
			"-o", `jsonpath={.status.succeeded}/{.status.failed}`)
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return strings.TrimSpace(out) != "/" && strings.TrimSpace(out) != "",
			"succeeded/failed = " + strings.TrimSpace(out)
	})

	logs := h.kubectl(t, "-n", ns, "logs", "job/svcdoctor")
	succeeded := strings.TrimSpace(h.kubectl(t, "-n", ns, "get", "job", "svcdoctor",
		"-o", "jsonpath={.status.succeeded}"))
	if succeeded != "1" {
		t.Fatalf("the in-cluster Job did not succeed (succeeded=%q).\nlogs:\n%s",
			succeeded, logs)
	}

	parsed := parseReport(t, run{stdout: logs})

	if mode := stringAttr(t, parsed, "k8s.api_access", "k8s.auth_mode"); mode != "IN_CLUSTER" {
		t.Errorf("auth mode = %s, want IN_CLUSTER", mode)
	}
	assertCodes(t, parsed)
	for _, step := range []string{
		"k8s.target", "k8s.api_access", "k8s.service", "k8s.pod_set",
		"k8s.endpoint_publication",
	} {
		if state := parsed.node(t, step).State; state != "PASS" {
			t.Errorf("%s = %s in-cluster, want PASS", step, state)
		}
	}
	if n := intAttr(t, parsed, "k8s.endpoint_publication", "k8s.ready_endpoint_count"); n != 1 {
		t.Errorf("ready endpoint count = %d in-cluster, want 1", n)
	}

	// The projected token must not appear in what the Pod wrote.
	if strings.Contains(logs, "BEGIN") || strings.Contains(logs, "eyJhbGciOi") {
		t.Error("the in-cluster output carries credential-shaped material")
	}
	// In-cluster derives kubernetes.default.svc rather than reading the
	// injected address into the report; no context is published either.
	if hasAttr(t, parsed, "k8s.api_access", "k8s.context") {
		t.Error("an in-cluster run published a context; a context names a kubeconfig " +
			"entry and has no meaning here")
	}

	// The same Service, read from outside with the lane's own kubeconfig, must
	// produce the same findings and the same counts. In-cluster is a way of
	// obtaining a credential, not a different product.
	_, external := h.diagnoseJSON(t, ns, "payments-api")
	assertCodes(t, external)
	for _, key := range []string{
		"k8s.slice_count", "k8s.endpoint_count", "k8s.ready_endpoint_count",
		"k8s.terminating_endpoint_count", "k8s.slice_excluded_by_owner_uid_count",
	} {
		if got, want := intAttr(t, parsed, "k8s.endpoint_publication", key),
			intAttr(t, external, "k8s.endpoint_publication", key); got != want {
			t.Errorf("in-cluster and external disagree on %s: %d and %d", key, got, want)
		}
	}
	if got, want := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"),
		intAttr(t, external, "k8s.pod_set", "k8s.pod_observed_count"); got != want {
		t.Errorf("in-cluster and external disagree on the Pod count: %d and %d", got, want)
	}
}

// buildAndLoadImage builds a minimal image around the suite's binary and loads
// it into the kind node.
//
// It is built here rather than by the Makefile so the **same binary** every
// other scenario invokes is the one that runs inside the Pod. Nothing is
// pushed; `kind load` copies it into the node's own image store.
func buildAndLoadImage(t *testing.T, cluster string) string {
	t.Helper()

	// **A different binary, named explicitly rather than implied.** Every other
	// scenario runs the host's binary; a container runs Linux, so the Makefile
	// cross-compiles a second one from the same source tree and names it here.
	// Pretending one file served both would be the kind of quiet inaccuracy this
	// phase exists to remove — so the variable is required, not defaulted.
	binary := os.Getenv(envLinuxBinary)
	if binary == "" {
		t.Fatalf("%s is not set; the in-cluster lane runs svcdoctor inside a Linux "+
			"container and needs a Linux build of the same source tree. Run this "+
			"suite through `make integration-kubernetes`.", envLinuxBinary)
	}
	dir := t.TempDir()

	// The binary is copied rather than referenced: a Docker build context has to
	// contain what the Dockerfile copies.
	body, err := os.ReadFile(binary)
	if err != nil {
		t.Fatalf("reading %s: %v", binary, err)
	}
	if err := os.WriteFile(dir+"/svcdoctor", body, 0o755); err != nil {
		t.Fatalf("staging the binary: %v", err)
	}
	// `scratch` is enough: the binary is static (CGO_ENABLED=0) and svcdoctor
	// runs no subprocess, so there is nothing else to put in the image.
	if err := os.WriteFile(dir+"/Dockerfile", []byte(
		"FROM scratch\nCOPY svcdoctor /svcdoctor\nUSER 65532:65532\n"+
			"ENTRYPOINT [\"/svcdoctor\"]\n"), 0o600); err != nil {
		t.Fatalf("writing the Dockerfile: %v", err)
	}

	const image = "svcdoctor-integration:in-cluster"
	// The node runs the host's architecture, and the Makefile cross-compiles for
	// linux/$(go env GOARCH), so the two agree by construction.
	if out, err := exec.Command("docker", "build",
		"--platform", "linux/"+runtime.GOARCH, "-t", image, dir).CombinedOutput(); err != nil {
		t.Fatalf("building the in-cluster image: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "image", "rm", "-f", image).Run()
	})

	if out, err := exec.Command("kind", "load", "docker-image", image,
		"--name", cluster).CombinedOutput(); err != nil {
		t.Fatalf("loading the image into kind: %v\n%s", err, out)
	}
	return image
}

// requireBinaries fails the test when a tool the lane needs is unreachable.
//
// A skipped in-cluster lane is a **failure**, not a pass: Phase 12.1D §46 makes
// it a mandatory gate, and §39 forbids turning an absent capability into green.
func requireBinaries(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatalf("%s is not on PATH; the in-cluster lane cannot run without it, "+
				"and a skipped mandatory gate is not a pass", name)
		}
	}
}
