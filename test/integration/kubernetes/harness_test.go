//go:build integration

// Package kubernetes is Phase 12.1D's real-cluster validation suite.
//
// # What makes a test here different from every other Kubernetes test
//
// Everything else in the tree answers a question about svcdoctor. This suite
// answers a question about **Kubernetes**: does the frozen model survive contact
// with a real API server, a real authorizer, a real EndpointSlice controller and
// real list pagination?
//
// So the rule is the one Phase 12.1D §6 states: the primary assertions run
// against a real API server, reached by the **released binary** through
// client-go. `httptest`, a fake clientset and a static JSON fixture are all
// still valuable — `test/fleet` and `internal/adapter/kubernetes/client` are
// full of them — and none of them can answer this phase's question, because each
// one replaces the component under test.
//
// # The binary, not `go run`
//
// One binary is built once by the Makefile and its SHA-256 is recorded. Every
// scenario in a lane invokes that same file, so a difference between two
// scenarios cannot be a difference between two builds.
//
// # kubectl is the fixture tool and never the product's dependency
//
// The harness shells out to `kubectl` to create objects and to wait on
// conditions. svcdoctor does not, and `TestNoKubectlIsRequiredAtRuntime` proves
// it by running a diagnosis with a `PATH` that cannot resolve the binary.
package kubernetes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The environment the Makefile lane provides.
//
// Each is required rather than defaulted: a suite that invented a kubeconfig
// path would silently validate whatever cluster happened to be current, which is
// exactly the failure mode `--context` is mandatory to prevent.
const (
	envBinary     = "SVCDOCTOR_BIN"
	envKubeconfig = "SVCDOCTOR_KUBECONFIG"
	envContext    = "SVCDOCTOR_KUBE_CONTEXT"

	// envLinuxBinary names a Linux build of the same source tree, used only by
	// the in-cluster lane, which runs svcdoctor inside a container.
	envLinuxBinary = "SVCDOCTOR_LINUX_BIN"
)

// waitTimeout bounds every readiness poll.
//
// Phase 9.1C's fixture lesson, applied: **no `sleep`**. Every wait names a
// condition and a deadline, and reports what it last observed when it expires —
// a fixture that fails silently is the defect that cost that phase a release.
const waitTimeout = 120 * time.Second

// run is one invocation of the svcdoctor binary.
type run struct {
	code   int
	stdout string
	stderr string
}

// harness carries the lane's environment.
type harness struct {
	binary     string
	kubeconfig string
	context    string
}

// newHarness reads the lane's environment and refuses to guess any of it.
func newHarness(t *testing.T) harness {
	t.Helper()

	h := harness{
		binary:     os.Getenv(envBinary),
		kubeconfig: os.Getenv(envKubeconfig),
		context:    os.Getenv(envContext),
	}
	for name, value := range map[string]string{
		envBinary: h.binary, envKubeconfig: h.kubeconfig, envContext: h.context,
	} {
		if value == "" {
			t.Fatalf("%s is not set.\n\nRun this suite through `make integration-kubernetes`, "+
				"which builds the binary, creates the cluster and exports the three "+
				"variables. A suite that defaulted any of them would validate whichever "+
				"cluster happened to be current.", name)
		}
	}
	if _, err := os.Stat(h.binary); err != nil {
		t.Fatalf("%s=%s does not exist: %v", envBinary, h.binary, err)
	}
	return h
}

// diagnose runs `svcdoctor diagnose kubernetes` with the lane's authority.
func (h harness) diagnose(t *testing.T, namespace, service string, extra ...string) run {
	t.Helper()
	args := []string{
		"diagnose", "kubernetes",
		"--kubeconfig", h.kubeconfig,
		"--context", h.context,
		"--namespace", namespace,
		"--service-name", service,
	}
	return h.exec(t, "", append(args, extra...)...)
}

// exec runs the binary with the given stdin and arguments.
//
// The environment is deliberately **empty apart from PATH and HOME**. svcdoctor
// reads no environment variable in a leaf command, and passing the caller's
// environment would let a stray `KUBECONFIG` make a passing test meaningless.
func (h harness) exec(t *testing.T, stdin string, args ...string) run {
	t.Helper()
	return h.execWithEnv(t, stdin, os.Environ(), args...)
}

func (h harness) execWithEnv(t *testing.T, stdin string, env []string, args ...string) run {
	t.Helper()

	cmd := exec.Command(h.binary, args...)
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case asExitError(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running %s: %v", h.binary, err)
	}
	return run{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func asExitError(err error, target **exec.ExitError) bool {
	if e, ok := err.(*exec.ExitError); ok {
		*target = e
		return true
	}
	return false
}

// report is the parsed canonical JSON one run produced.
type report struct {
	Evidence struct {
		Nodes []struct {
			Step       string `json:"step"`
			State      string `json:"state"`
			Layer      string `json:"layer"`
			BlockedBy  string `json:"blockedBy"`
			Failure    string `json:"failureClass"`
			Attributes map[string]struct {
				Kind  string          `json:"kind"`
				Value json.RawMessage `json:"value"`
			} `json:"attributes"`
		} `json:"nodes"`
	} `json:"evidence"`
	Findings []struct {
		Code     string `json:"code"`
		Kind     string `json:"kind"`
		Severity string `json:"severity"`
		Detail   string `json:"detail"`
		Summary  string `json:"summary"`
	} `json:"findings"`
	Summary struct {
		Status string `json:"status"`
	} `json:"summary"`
}

// diagnoseJSON runs a diagnosis and parses its canonical report.
func (h harness) diagnoseJSON(t *testing.T, namespace, service string, extra ...string) (run, report) {
	t.Helper()
	got := h.diagnose(t, namespace, service, append([]string{"--output", "json"}, extra...)...)
	return got, parseReport(t, got)
}

func parseReport(t *testing.T, got run) report {
	t.Helper()
	var parsed report
	if err := json.Unmarshal([]byte(got.stdout), &parsed); err != nil {
		t.Fatalf("the run produced no parseable report: %v\nexit %d\nstdout:\n%s\nstderr:\n%s",
			err, got.code, got.stdout, got.stderr)
	}
	return parsed
}

// codes returns the finding codes a report carries, in report order.
func (r report) codes() []string {
	out := make([]string, 0, len(r.Findings))
	for _, finding := range r.Findings {
		out = append(out, finding.Code)
	}
	return out
}

// node returns one evidence node by step.
func (r report) node(t *testing.T, step string) struct {
	Step       string `json:"step"`
	State      string `json:"state"`
	Layer      string `json:"layer"`
	BlockedBy  string `json:"blockedBy"`
	Failure    string `json:"failureClass"`
	Attributes map[string]struct {
		Kind  string          `json:"kind"`
		Value json.RawMessage `json:"value"`
	} `json:"attributes"`
} {
	t.Helper()
	for _, n := range r.Evidence.Nodes {
		if n.Step == step {
			return n
		}
	}
	t.Fatalf("the report carries no %s node; it has %v", step, r.steps())
	panic("unreachable")
}

func (r report) steps() []string {
	out := make([]string, 0, len(r.Evidence.Nodes))
	for _, n := range r.Evidence.Nodes {
		out = append(out, n.Step)
	}
	return out
}

// intAttr reads a bounded integer attribute from a node.
func intAttr(t *testing.T, r report, step, key string) int {
	t.Helper()
	attr, ok := r.node(t, step).Attributes[key]
	if !ok {
		t.Fatalf("%s carries no %s", step, key)
	}
	var value int
	if err := json.Unmarshal(attr.Value, &value); err != nil {
		t.Fatalf("%s.%s is not an integer: %v", step, key, err)
	}
	return value
}

// boolAttr reads a boolean attribute from a node.
func boolAttr(t *testing.T, r report, step, key string) bool {
	t.Helper()
	attr, ok := r.node(t, step).Attributes[key]
	if !ok {
		t.Fatalf("%s carries no %s", step, key)
	}
	var value bool
	if err := json.Unmarshal(attr.Value, &value); err != nil {
		t.Fatalf("%s.%s is not a boolean: %v", step, key, err)
	}
	return value
}

// stringAttr reads a string attribute from a node.
func stringAttr(t *testing.T, r report, step, key string) string {
	t.Helper()
	attr, ok := r.node(t, step).Attributes[key]
	if !ok {
		t.Fatalf("%s carries no %s", step, key)
	}
	var value string
	if err := json.Unmarshal(attr.Value, &value); err != nil {
		t.Fatalf("%s.%s is not a string: %v", step, key, err)
	}
	return value
}

// hasAttr reports whether a node carries a key at all.
func hasAttr(t *testing.T, r report, step, key string) bool {
	t.Helper()
	_, ok := r.node(t, step).Attributes[key]
	return ok
}

// --- kubectl, the fixture tool -----------------------------------------------

// kubectl runs one kubectl command against the lane's cluster and fails the test
// on a non-zero exit.
func (h harness) kubectl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := h.kubectlErr(args...)
	if err != nil {
		t.Fatalf("kubectl %s failed: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// kubectlErr runs one kubectl command and returns its combined output.
func (h harness) kubectlErr(args ...string) (string, error) {
	full := append([]string{"--kubeconfig", h.kubeconfig, "--context", h.context}, args...)
	cmd := exec.Command("kubectl", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// apply pipes a manifest into `kubectl apply`.
func (h harness) apply(t *testing.T, manifest string) {
	t.Helper()
	cmd := exec.Command("kubectl",
		"--kubeconfig", h.kubeconfig, "--context", h.context, "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("applying a manifest failed: %v\n%s\n--- manifest\n%s", err, out, manifest)
	}
}

// namespace creates a deterministic, collision-safe namespace and schedules its
// deletion.
//
// The name is derived from the test rather than randomized, so a failed run
// leaves an inspectable namespace whose name says which test made it. Deletion
// is asynchronous — namespace finalization is slow and nothing later depends on
// it having finished.
func (h harness) namespace(t *testing.T) string {
	t.Helper()

	name := "svcd-" + strings.ToLower(strings.NewReplacer(
		"/", "-", "_", "-", " ", "-", "#", "-", ".", "-",
	).Replace(t.Name()))
	if len(name) > 60 {
		name = name[:60]
	}
	name = strings.Trim(name, "-")

	// A rerun must not fail on a namespace a previous run left behind.
	_, _ = h.kubectlErr("delete", "namespace", name, "--ignore-not-found",
		"--wait=true", "--timeout=120s")
	h.kubectl(t, "create", "namespace", name)

	t.Cleanup(func() {
		if t.Failed() {
			h.dumpDiagnostics(t, name)
		}
		_, _ = h.kubectlErr("delete", "namespace", name, "--ignore-not-found", "--wait=false")
	})
	return name
}

// dumpDiagnostics prints bounded, namespace-scoped state when a test fails.
//
// **Scoped to the fixture namespace and to three kinds**, per Phase 12.1D §40.
// No Secret, no ServiceAccount token, no kubeconfig material and nothing
// cluster-wide: a diagnostic that leaked a credential to a CI log would be a
// worse defect than the one it was printed to explain.
func (h harness) dumpDiagnostics(t *testing.T, namespace string) {
	t.Helper()
	for _, kind := range []string{"service", "pod", "endpointslice"} {
		out, err := h.kubectlErr("-n", namespace, "get", kind, "-o", "wide")
		if err != nil {
			out = fmt.Sprintf("(kubectl get %s failed: %v)", kind, err)
		}
		t.Logf("--- %s in %s ---\n%s", kind, namespace, strings.TrimSpace(out))
	}
}

// waitFor polls a condition under a bounded deadline.
//
// No `sleep`: the caller names what it is waiting for and what it last saw, so
// an expiry says which ground truth never arrived rather than "not ready".
func (h harness) waitFor(t *testing.T, what string, condition func() (bool, string)) {
	t.Helper()

	deadline := time.Now().Add(waitTimeout)
	last := "(nothing observed yet)"
	for time.Now().Before(deadline) {
		ok, observed := condition()
		if observed != "" {
			last = observed
		}
		if ok {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %s.\nlast observed: %s", waitTimeout, what, last)
}

// waitForPodReady blocks until a Pod reports Ready through the API.
func (h harness) waitForPodReady(t *testing.T, namespace, pod string) {
	t.Helper()
	h.waitFor(t, "pod/"+pod+" to report Ready", func() (bool, string) {
		out, err := h.kubectlErr("-n", namespace, "get", "pod", pod,
			"-o", `jsonpath={.status.conditions[?(@.type=="Ready")].status}`)
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		return strings.TrimSpace(out) == "True", "Ready=" + strings.TrimSpace(out)
	})
}

// waitForReadyEndpoints blocks until the controller publishes `want` ready
// endpoints for a Service.
//
// It reads the **API's own ground truth** — the EndpointSlices' conditions —
// rather than a Pod phase, because what F4 is about is what Kubernetes
// publishes, and a Ready Pod whose slice has not been written yet is exactly the
// race a `sleep` would paper over.
func (h harness) waitForReadyEndpoints(t *testing.T, namespace, service string, want int) {
	t.Helper()
	h.waitFor(t, fmt.Sprintf("%d ready endpoint(s) published for %s", want, service),
		func() (bool, string) {
			total, ready := h.countEndpoints(namespace, service)
			return ready == want, fmt.Sprintf("endpoints=%d ready=%d", total, ready)
		})
}

// waitForEndpointCounts blocks until the API publishes exactly `wantTotal`
// endpoints of which exactly `wantReady` are ready.
//
// # Why the total is waited on and not only the ready count
//
// The first version of the K4 fixture waited for **zero ready endpoints**, and
// the wait was satisfied instantly — by a slice the controller had created and
// not yet populated, while the Pod was still `ContainerCreating`. Zero ready was
// true for the wrong reason, and svcdoctor correctly reported the *no endpoint
// published* variant of F4 rather than the *published and none ready* variant
// the scenario exists to exercise.
//
// That is the failure mode Phase 12.1D §8 forbids a `sleep` for, arriving
// through a condition that was simply too weak. A scenario about unready
// endpoints has to wait until endpoints exist **and** none of them is ready.
func (h harness) waitForEndpointCounts(
	t *testing.T, namespace, service string, wantTotal, wantReady int,
) {
	t.Helper()
	h.waitFor(t, fmt.Sprintf("%d endpoint(s) of which %d ready, for %s",
		wantTotal, wantReady, service),
		func() (bool, string) {
			total, ready := h.countEndpoints(namespace, service)
			return total == wantTotal && ready == wantReady,
				fmt.Sprintf("endpoints=%d ready=%d", total, ready)
		})
}

// countEndpoints counts the endpoints the API publishes for a Service, and how
// many of them are ready.
//
// `conditions.ready` absent is counted as **true**, which is the frozen nil
// semantics — the fixture reads the API the way the contract says the API means
// it, so a fixture that disagreed with production would show up as a fixture
// disagreement rather than as a passing test.
func (h harness) countEndpoints(namespace, service string) (total, ready int) {
	out, err := h.kubectlErr("-n", namespace, "get", "endpointslice",
		"-l", "kubernetes.io/service-name="+service, "-o", "json")
	if err != nil {
		return -1, -1
	}
	var list struct {
		Items []struct {
			Endpoints []struct {
				Conditions map[string]*bool `json:"conditions"`
			} `json:"endpoints"`
		} `json:"items"`
	}
	if json.Unmarshal([]byte(out), &list) != nil {
		return -1, -1
	}
	for _, slice := range list.Items {
		for _, endpoint := range slice.Endpoints {
			total++
			value, present := endpoint.Conditions["ready"]
			if !present || value == nil || *value {
				ready++
			}
		}
	}
	return total, ready
}

// waitForSliceCount blocks until the API lists `want` slices for a Service.
func (h harness) waitForSliceCount(t *testing.T, namespace, service string, want int) {
	t.Helper()
	h.waitFor(t, fmt.Sprintf("%d EndpointSlice(s) for %s", want, service),
		func() (bool, string) {
			out, err := h.kubectlErr("-n", namespace, "get", "endpointslice",
				"-l", "kubernetes.io/service-name="+service,
				"-o", "jsonpath={.items[*].metadata.name}")
			if err != nil {
				return false, strings.TrimSpace(out)
			}
			names := strings.Fields(out)
			return len(names) == want, fmt.Sprintf("slices=%v", names)
		})
}

// serviceUID reads a Service's UID, for the owner-reference fixtures.
func (h harness) serviceUID(t *testing.T, namespace, service string) string {
	t.Helper()
	return strings.TrimSpace(h.kubectl(t, "-n", namespace, "get", "service", service,
		"-o", "jsonpath={.metadata.uid}"))
}

// --- fixtures ----------------------------------------------------------------

// pauseImage is the workload every Pod fixture runs.
//
// It is `pause` because no fixture in this suite needs a Pod to *do* anything:
// svcdoctor connects to no Pod, so what a fixture has to produce is an API
// object in a state, and the cheapest container that reaches Ready is the
// honest choice. It also keeps the pagination lane affordable.
const pauseImage = "registry.k8s.io/pause:3.10"

// podManifest is one Ready-capable Pod carrying the given labels.
func podManifest(namespace, name string, labels map[string]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: %s\n  namespace: %s\n",
		name, namespace)
	if len(labels) > 0 {
		b.WriteString("  labels:\n")
		for _, key := range sortedKeys(labels) {
			fmt.Fprintf(&b, "    %s: %q\n", key, labels[key])
		}
	}
	fmt.Fprintf(&b, "spec:\n  containers:\n    - name: c\n      image: %s\n", pauseImage)
	return b.String()
}

// serviceManifest is one Service of the given type and selector.
func serviceManifest(namespace, name, serviceType string, selector map[string]string,
	extraSpec string,
) string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: v1\nkind: Service\nmetadata:\n  name: %s\n  namespace: %s\n",
		name, namespace)
	b.WriteString("spec:\n")
	if serviceType != "" {
		fmt.Fprintf(&b, "  type: %s\n", serviceType)
	}
	if selector != nil {
		b.WriteString("  selector:\n")
		for _, key := range sortedKeys(selector) {
			fmt.Fprintf(&b, "    %s: %q\n", key, selector[key])
		}
	}
	b.WriteString(extraSpec)
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// --- assertions --------------------------------------------------------------

// assertCodes requires the report's Kubernetes findings to be exactly `want`.
//
// It compares the **Kubernetes** codes only. `DIAG_FAILURE_BOUNDARY` is generic
// and its presence depends on where a run stopped, which is not what any
// scenario here is about.
func assertCodes(t *testing.T, got report, want ...string) {
	t.Helper()

	var kubernetes []string
	for _, code := range got.codes() {
		if strings.HasPrefix(code, "KUBERNETES_") {
			kubernetes = append(kubernetes, code)
		}
	}
	if len(kubernetes) != len(want) {
		t.Fatalf("Kubernetes findings = %v, want %v", kubernetes, want)
	}
	for i := range want {
		if kubernetes[i] != want[i] {
			t.Fatalf("Kubernetes findings = %v, want %v", kubernetes, want)
		}
	}
}

// assertNoProseLeak fails if a marker a fixture planted reaches any output.
func assertNoProseLeak(t *testing.T, got run, markers ...string) {
	t.Helper()
	combined := got.stdout + got.stderr
	for _, marker := range markers {
		if strings.Contains(combined, marker) {
			t.Errorf("the output carries %q, which came from cluster-supplied data.\n%s",
				marker, combined)
		}
	}
}

// repoRoot is the repository root, for reaching the Makefile-built binary.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}
