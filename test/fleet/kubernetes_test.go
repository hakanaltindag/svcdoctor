package fleet_test

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/cli"
)

// The exit codes, named from the package that owns the mapping rather than
// written as integers here. A test that hard-coded 1 would still pass if the
// contract changed underneath it.
const (
	exitOK            = cli.ExitOK
	exitProblemsFound = cli.ExitProblemsFound
	exitIncomplete    = cli.ExitIncomplete
)

// blackBox is everything an operator can observe from one invocation.
type blackBox struct {
	code   int
	stdout string
	stderr string
}

// runCLI drives the real command with real arguments.
func runCLI(t *testing.T, ctx context.Context, args ...string) blackBox {
	t.Helper()
	return runCLIWithStdin(t, ctx, "", args...)
}

// runCLIWithStdin is runCLI with credential material on the input stream.
//
// Phase 12.1C.2 needed it: `--token-stdin` is the one leaf source that reads
// stdin, and a suite that could not supply one could not exercise half the
// Kubernetes credential surface.
func runCLIWithStdin(t *testing.T, ctx context.Context, stdin string, args ...string) blackBox {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.New(strings.NewReader(stdin), &stdout, &stderr, "test").Run(ctx, args)
	return blackBox{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// writeConfig writes one run configuration and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing the configuration: %v", err)
	}
	return path
}

// itoa renders a small positive integer without reaching for strconv, which
// keeps the fixture's JSON assembly obviously constant.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// Phase 12.1C's public behaviour change, measured through the real command
// surface.
//
// # Why this package exists
//
// It is a hermetic, cross-package end-to-end suite: the CLI, the fleet
// scheduler, the composition root, the adapter and the two rules, driven by real
// arguments against a real HTTPS server that answers as a Kubernetes API server
// would.
//
// It is deliberately **not** in `internal/cli`. `depguard`'s
// `cli-composes-and-does-not-conclude` list denies `net/http` there — *"the
// command performs no network I/O of its own"* — and that rule is right, so the
// test moved rather than the rule. It is not in `test/integration` either,
// because nothing here needs Docker or a real cluster: `kind` closure is Phase
// 12.1D's.
//
// # What changed, exactly
//
// Before 12.1C a Kubernetes target produced a complete evidence graph and **zero
// findings**, so it exited 0 whatever it observed — a Service that does not
// exist, a read that was refused, a Service with no backends, all of them exit
// 0. That was ADR 0094 section 2.12's split working as designed, and it is what
// made this phase's diff the entire behavioural change.
//
// After it, the four admitted findings participate in the **existing generic**
// exit policy: `RunExitCode` reads the aggregate's own summary and nothing else
// — not a finding, not a severity, not a finding code, and not which service a
// target is. There is no `if kubernetes` anywhere in the mapping and none is
// authorized.
//
// So these tests do not assert a Kubernetes exit rule. They assert that the
// generic one now has something to act on, and they record the measured values
// rather than a number chosen in advance.

// kubernetesAPI starts a hermetic API server and returns a kubeconfig pointing
// at it.
//
// It is a TLS server with a real certificate, because the Kubernetes client
// verifies one on every path — `insecure-skip-tls-verify` is refused as a
// configuration error before anything is sent — so a plaintext fixture could not
// be reached at all.
func kubernetesAPI(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
	})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}

	document := "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n    server: " + server.URL + "\n" +
		"    certificate-authority: " + caPath + "\n" +
		"users:\n- name: u\n  user:\n    token: fixture-token\n" +
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n" +
		"current-context: prod\n"

	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the kubeconfig: %v", err)
	}
	return path
}

// kubernetesRunConfig writes a one-target run for a Kubernetes Service.
func kubernetesRunConfig(t *testing.T, kubeconfig string) string {
	t.Helper()
	return writeConfig(t, "version: 1\ntargets:\n"+
		"  - id: payments\n    type: kubernetes\n    config:\n"+
		"      kubeconfig: "+kubeconfig+"\n"+
		"      context: prod\n      namespace: payments\n"+
		"      service_name: payments-api\n")
}

// apiHandler answers the three reads with whatever each scenario needs.
//
// The routing is on the path prefix rather than on an exact match, because the
// client composes the URL and this fixture's business is the *answer* rather
// than the shape of the request — which `internal/adapter/kubernetes/client`
// proves against its own hermetic server.
func apiHandler(service, pods, slices func(http.ResponseWriter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/endpointslices"):
			slices(w)
		case strings.Contains(r.URL.Path, "/pods"):
			pods(w)
		default:
			service(w)
		}
	}
}

func writeStatus(code int, reason string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure",` +
			`"reason":"` + reason + `","code":` + itoa(code) + `}`))
	}
}

func writeJSON(body string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

const (
	clusterIPService = `{"kind":"Service","apiVersion":"v1",` +
		`"metadata":{"name":"payments-api","namespace":"payments","uid":"svc-uid"},` +
		`"spec":{"type":"ClusterIP","clusterIP":"10.0.0.1","selector":{"app":"payments"}}}`

	emptyPodList = `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[]}`

	onePodList = `{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[` +
		`{"metadata":{"name":"p1","namespace":"payments"}}]}`

	emptySliceList = `{"kind":"EndpointSliceList","apiVersion":"discovery.k8s.io/v1",` +
		`"metadata":{},"items":[]}`

	readySliceList = `{"kind":"EndpointSliceList","apiVersion":"discovery.k8s.io/v1",` +
		`"metadata":{},"items":[{"metadata":{"name":"s1","namespace":"payments",` +
		`"labels":{"kubernetes.io/service-name":"payments-api"},` +
		`"ownerReferences":[{"kind":"Service","name":"payments-api","uid":"svc-uid"}]},` +
		`"addressType":"IPv4","endpoints":[{"addresses":["10.1.0.1"],` +
		`"conditions":{"ready":true}}]}]}`

	unreadySliceList = `{"kind":"EndpointSliceList","apiVersion":"discovery.k8s.io/v1",` +
		`"metadata":{},"items":[{"metadata":{"name":"s1","namespace":"payments",` +
		`"labels":{"kubernetes.io/service-name":"payments-api"},` +
		`"ownerReferences":[{"kind":"Service","name":"payments-api","uid":"svc-uid"}]},` +
		`"addressType":"IPv4","endpoints":[{"addresses":["10.1.0.1"],` +
		`"conditions":{"ready":false}}]}]}`
)

// TestTheKubernetesExitBehaviourIsTheGenericOne.
//
// Each row is a scenario a real cluster produces, the finding codes it yields,
// and the exit code the **existing** mapping assigns. The exit codes are
// measured rather than chosen: `RunExitCode` reads the aggregate summary, so
// these rows record what that mapping already does with the severities ADR 0094
// froze.
func TestTheKubernetesExitBehaviourIsTheGenericOne(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    int
		codes   []string
		absent  []string
	}{
		{
			name: "a Service with a ready endpoint produces no Kubernetes finding",
			handler: apiHandler(
				writeJSON(clusterIPService),
				writeJSON(onePodList),
				writeJSON(readySliceList)),
			want:   exitOK,
			absent: []string{"KUBERNETES_"},
		},
		{
			name: "an absent Service is an ERROR finding and a target-side problem",
			handler: apiHandler(
				writeStatus(http.StatusNotFound, "NotFound"),
				writeJSON(emptyPodList),
				writeJSON(emptySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NOT_FOUND"},
		},
		{
			// **Measured as 4, not 0**, and the reason is 12.1B's rather than
			// this phase's. A refused list was *attempted* and did not complete,
			// so `client.Result.Incomplete()` is true and exit 4 outranks
			// everything below it. The WARN finding therefore never decides this
			// invocation's status at all — incompleteness qualifies every
			// conclusion in the report, which is exactly what docs/SCOPE.md's
			// precedence says it should do.
			name: "a refused read leaves the run incomplete, which outranks its WARN finding",
			handler: apiHandler(
				writeJSON(clusterIPService),
				writeStatus(http.StatusForbidden, "Forbidden"),
				writeJSON(readySliceList)),
			want:  exitIncomplete,
			codes: []string{"KUBERNETES_API_ACCESS_DENIED"},
			absent: []string{
				"KUBERNETES_SERVICE_SELECTS_NO_PODS",
			},
		},
		{
			name: "a selector matching nothing is an ERROR finding",
			handler: apiHandler(
				writeJSON(clusterIPService),
				writeJSON(emptyPodList),
				writeJSON(readySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_SELECTS_NO_PODS"},
			absent: []string{
				"KUBERNETES_SERVICE_NO_READY_ENDPOINT",
			},
		},
		{
			name: "nothing published is an ERROR finding",
			handler: apiHandler(
				writeJSON(clusterIPService),
				writeJSON(onePodList),
				writeJSON(emptySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NO_READY_ENDPOINT"},
		},
		{
			name: "published but nothing ready is an ERROR finding",
			handler: apiHandler(
				writeJSON(clusterIPService),
				writeJSON(onePodList),
				writeJSON(unreadySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NO_READY_ENDPOINT"},
		},
		{
			// **Measured as 0, and it is a recorded limitation rather than a
			// defect this phase may fix.**
			//
			// ADR 0094 §10.4 refuses a `401` a Kubernetes finding code
			// deliberately: it is authentication rather than authorization, and
			// `DIAG_FAILURE_BOUNDARY` localizes it. That boundary is INFO,
			// because it describes *where* observation stopped rather than how
			// bad it is — so no ERROR or CRITICAL finding exists, the summary
			// status is OK, the run is complete (a 401 is an answer), and the
			// generic mapping returns 0.
			//
			// Every other service has a credential-rejection finding at ERROR;
			// Kubernetes has none, because the four-code budget is frozen. The
			// behaviour is **unchanged by Phase 12.1C** — before it, this
			// invocation exited 0 with no finding at all — and closing it needs a
			// fifth code, which ADR 0094 §7 makes a decision with its own record.
			// It is recorded in docs/BACKLOG.md rather than smuggled in here.
			name: "an unaccepted identity earns no Kubernetes finding, and exits 0",
			handler: apiHandler(
				writeStatus(http.StatusUnauthorized, "Unauthorized"),
				writeJSON(emptyPodList),
				writeJSON(emptySliceList)),
			want:   exitOK,
			absent: []string{"KUBERNETES_"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config := kubernetesRunConfig(t, kubernetesAPI(t, tc.handler))
			got := runCLI(t, context.Background(), "run", "--config", config, "--output", "json")

			if got.code != tc.want {
				t.Errorf("exit = %d, want %d.\n\nstdout:\n%s\nstderr:\n%s",
					got.code, tc.want, got.stdout, got.stderr)
			}
			for _, code := range tc.codes {
				if !strings.Contains(got.stdout, code) {
					t.Errorf("the report does not carry %s:\n%s", code, got.stdout)
				}
			}
			for _, code := range tc.absent {
				if strings.Contains(got.stdout, code) {
					t.Errorf("the report carries %s and should not:\n%s", code, got.stdout)
				}
			}
			if got.stdout == "" {
				t.Error("no report was written to stdout")
			}
		})
	}
}

// TestAMixedFleetKeepsItsTargetsApart.
//
// # Why this is worth its own test
//
// Kubernetes is the first service whose findings are about objects rather than
// about an endpoint svcdoctor connected to, and a Kubernetes claim leaking into
// another target's report — or the reverse — would be a category error nothing
// else in the tree would catch.
//
// Convergence is per report and identity is `(Code, Subject)`, so cross-target
// merging is structurally impossible; this asserts the observable consequence
// over a real mixed run, and it also asserts the property ADR 0073 gives every
// fleet run: **independent targets, no fail-fast**, so one target's outcome
// changes nothing about another's.
func TestAMixedFleetKeepsItsTargetsApart(t *testing.T) {
	kubeconfig := kubernetesAPI(t, apiHandler(
		writeJSON(clusterIPService), writeJSON(emptyPodList), writeJSON(readySliceList)))

	config := writeConfig(t, "version: 1\nrun:\n  concurrency: 2\ntargets:\n"+
		"  - id: payments-cluster\n    type: kubernetes\n    config:\n"+
		"      kubeconfig: "+kubeconfig+"\n"+
		"      context: prod\n      namespace: payments\n"+
		"      service_name: payments-api\n"+
		"  - id: orders-cache\n    type: redis\n    host: t.invalid\n"+
		"    timeout: 5s\n    step_timeout: 4s\n    tls:\n      mode: disable\n")

	got := runCLI(t, context.Background(), "run", "--config", config, "--output", "json")

	var aggregate struct {
		Targets []struct {
			TargetID string `json:"targetId"`
			Service  string `json:"service"`
			Report   struct {
				Findings []struct {
					Code    string `json:"code"`
					Subject struct {
						Ref string `json:"ref"`
					} `json:"subject"`
				} `json:"findings"`
			} `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &aggregate); err != nil {
		t.Fatalf("decoding the aggregate: %v\n%s", err, got.stdout)
	}
	if len(aggregate.Targets) != 2 {
		t.Fatalf("the aggregate holds %d targets, want 2", len(aggregate.Targets))
	}

	seen := map[string]bool{}
	for _, target := range aggregate.Targets {
		seen[target.Service] = true
		for _, finding := range target.Report.Findings {
			kubernetes := strings.HasPrefix(finding.Code, "KUBERNETES_")

			switch target.Service {
			case "kubernetes":
				if strings.HasPrefix(finding.Code, "REDIS_") ||
					strings.HasPrefix(finding.Code, "DNS_") {
					t.Errorf("the Kubernetes target carries %s, which belongs to the "+
						"other target", finding.Code)
				}
				if kubernetes && !strings.HasPrefix(finding.Subject.Ref, "service/") {
					t.Errorf("a Kubernetes finding's subject is %q; one target is one "+
						"Service", finding.Subject.Ref)
				}
			default:
				if kubernetes {
					t.Errorf("the %s target carries %s.\n\n"+
						"Targets are independent and convergence is per report, so a "+
						"Kubernetes claim reaching another service's report would be a "+
						"category error nothing else would catch.",
						target.Service, finding.Code)
				}
			}
		}
	}
	if !seen["kubernetes"] || !seen["redis"] {
		t.Errorf("the mixed fleet did not run both services: %v", seen)
	}

	// One target failing changes nothing about the other's execution.
	for _, target := range aggregate.Targets {
		if target.TargetID == "" {
			t.Error("a target carries no identity")
		}
	}
}

// TestTheKubernetesFleetTargetStillDialsOnlyTheAPIServer.
//
// A regression guard on the phase's central architectural claim, from the
// outside. **Diagnosis adds no API request**: it reads a frozen graph, so a run
// that produces four findings makes exactly the same three round trips as the
// same run made before any rule existed.
//
// It is counted at the server rather than asserted from the source, because a
// linker check cannot say it and a source scan would only prove that nobody
// wrote the obvious thing.
func TestTheKubernetesFleetTargetStillDialsOnlyTheAPIServer(t *testing.T) {
	var requests int
	counting := func(w http.ResponseWriter, r *http.Request) {
		requests++
		apiHandler(
			writeJSON(clusterIPService), writeJSON(emptyPodList), writeJSON(emptySliceList),
		)(w, r)
	}

	config := kubernetesRunConfig(t, kubernetesAPI(t, counting))
	got := runCLI(t, context.Background(), "run", "--config", config, "--output", "json")

	if !strings.Contains(got.stdout, "KUBERNETES_SERVICE_SELECTS_NO_PODS") {
		t.Fatalf("the run produced no Kubernetes finding, so the count below would be "+
			"the count for a run that concluded nothing:\n%s", got.stdout)
	}
	if requests != 3 {
		t.Errorf("the run made %d API requests, want exactly 3.\n\n"+
			"Diagnosis reads a frozen graph and performs no I/O (ADR 0078 section 2.6). "+
			"A fourth request would mean a rule went back to the API server, which is "+
			"the architecture violation this phase must not commit.", requests)
	}
}
