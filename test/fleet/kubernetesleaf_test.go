package fleet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 12.1C.2's public surface, driven end to end through
// `svcdoctor diagnose kubernetes`.
//
// # Why this suite is here and not in internal/cli
//
// `depguard`'s `cli-composes-and-does-not-conclude` denies `net/http` in that
// package — *"the command performs no network I/O of its own"* — and the rule is
// right, so the test moved rather than the rule. `internal/cli`'s own
// `kubernetes_test.go` holds everything decidable without a server: the ten-flag
// surface, the refused surface, the defaults, and every refusal the parse path
// reaches.
//
// It is not in `test/integration` either. Nothing here needs Docker or a real
// cluster: `kind` closure is Phase 12.1D's, and no Kubernetes distribution is
// graded until then.
//
// # What it proves that nothing else can
//
// Four things, each of which is only true of the *entry point* rather than of a
// layer beneath it. That an invalid invocation reaches a running API server
// **zero times**, counted at the server rather than argued from the code. That an
// `exec` credential plugin never executes when the leaf command is the caller —
// the Phase 12.1B release gate, re-proven at the surface an operator actually
// types. That the leaf and `run --config` produce the **same report** for the
// same Service. And that the bearer token itself is unobservable: two different
// tokens against an identical server produce byte-identical output.

// --- fixtures ---------------------------------------------------------------

// writeKubeconfig assembles one kubeconfig around a caller-supplied user block.
//
// The user block is the only thing that varies across the authentication modes
// and the refused constructs, so it is the only thing a caller supplies. Every
// other line is identical, which keeps a refusal attributable to the construct
// under test rather than to the shape of the document.
func writeKubeconfig(t *testing.T, dir, server, caPath, userBlock string) string {
	t.Helper()

	document := "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n    server: " + server + "\n" +
		"    certificate-authority: " + caPath + "\n" +
		"users:\n- name: u\n  user:\n" + userBlock +
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n"

	path := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the kubeconfig: %v", err)
	}
	return path
}

// writeTemp writes one file into the test's own directory and returns its path.
func writeTemp(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// clientCertificate generates a client certificate and key.
//
// It is generated rather than committed because it authenticates nothing: the
// hermetic server requests no client certificate, so what this exercises is
// svcdoctor's own path — that mode C is selected from the kubeconfig, that the
// private key travels as a masked secret, and that the run completes.
func clientCertificate(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svcdoctor-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}

	certPath = filepath.Join(dir, "client.crt")
	keyPath = filepath.Join(dir, "client.key")
	writeOrFail(t, certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	writeOrFail(t, keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath
}

func writeOrFail(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// healthyHandler answers the three reads as a Service with a ready backend.
func healthyHandler() http.HandlerFunc {
	return apiHandler(
		writeJSON(clusterIPService), writeJSON(onePodList), writeJSON(readySliceList))
}

// leafArgs is the invocation every test varies from.
func leafArgs(kubeconfig string, extra ...string) []string {
	base := []string{
		"diagnose", "kubernetes",
		"--kubeconfig", kubeconfig,
		"--context", "prod",
		"--namespace", "payments",
		"--service-name", "payments-api",
		"--output", "json",
	}
	return append(base, extra...)
}

// --- the four reachable authentication modes --------------------------------

// TestEveryReachableAuthenticationModeRunsThroughTheLeaf.
//
// `PHASE121A…§6.1` admits four modes and `PHASE121C1…§6` decides which need a
// flag. Three are reachable hermetically and each is driven here; the fourth,
// in-cluster, needs a projected ServiceAccount and is proven by its refusals in
// `internal/cli` and by 12.1D on a real cluster.
//
// **Modes B and C take no flag at all**, which is the point: the invocation is
// byte-identical to mode A's and only the kubeconfig differs. A `--client-cert`
// pair would have made these three invocations three different shapes and let a
// leaf express an identity a `run --config` target cannot.
func TestEveryReachableAuthenticationModeRunsThroughTheLeaf(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := clientCertificate(t, dir)
	tokenPath := writeTemp(t, "token", "a-token-in-a-file\n")

	tests := []struct {
		name      string
		userBlock string
		extra     []string
	}{
		{
			name:      "A: an explicit bearer token from a file",
			userBlock: "    {}\n",
			extra:     []string{"--token-file", writeTemp(t, "declared", "declared-token")},
		},
		{
			name:      "A: an explicit bearer token from stdin",
			userBlock: "    {}\n",
			extra:     []string{"--token-stdin"},
		},
		{
			name:      "B: a kubeconfig tokenFile, which svcdoctor reads itself",
			userBlock: "    tokenFile: " + tokenPath + "\n",
		},
		{
			name: "C: a kubeconfig client certificate and key",
			userBlock: "    client-certificate: " + certPath + "\n" +
				"    client-key: " + keyPath + "\n",
		},
		{
			name:      "the kubeconfig's own inline token",
			userBlock: "    token: fixture-token\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(healthyHandler())
			t.Cleanup(server.Close)

			modeDir := t.TempDir()
			caPath := filepath.Join(modeDir, "ca.crt")
			writeOrFail(t, caPath, pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
			}))
			kubeconfig := writeKubeconfig(t, modeDir, server.URL, caPath, tc.userBlock)

			got := runLeaf(t, "a-token-on-stdin", leafArgs(kubeconfig, tc.extra...)...)

			if got.code != exitOK {
				t.Errorf("exit = %d, want %d.\nstdout:\n%s\nstderr:\n%s",
					got.code, exitOK, got.stdout, got.stderr)
			}
			if got.stdout == "" {
				t.Fatal("no report was written to stdout")
			}
			if strings.Contains(got.stdout, "KUBERNETES_") {
				t.Errorf("a Service with a ready backend produced a Kubernetes finding:\n%s",
					got.stdout)
			}
		})
	}
}

// --- the release gate: exec auth never executes -----------------------------

// TestAnExecCredentialPluginNeverExecutesThroughTheLeaf is a RELEASE GATE.
//
// Phase 12.1B proved it at the client boundary. This proves it at the surface an
// operator actually types, which is the one place the guarantee has to hold: a
// kubeconfig arrives from a cluster admin, a CI secret or a support bundle, and
// running whatever it names would make svcdoctor a remote code execution vector
// for anyone who can put a file on the host.
//
// Four things are asserted together, because any one alone is weaker than it
// looks: the invocation is refused as a **configuration error**, the sentinel
// file **does not exist**, the API server counted **zero** requests, and the
// plugin's command, arguments and environment appear in **no** output stream.
func TestAnExecCredentialPluginNeverExecutesThroughTheLeaf(t *testing.T) {
	server := httptest.NewTLSServer(healthyHandler())
	t.Cleanup(server.Close)

	var requests atomic.Int64
	counting := httptest.NewTLSServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			healthyHandler()(w, r)
		}))
	t.Cleanup(counting.Close)

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "the-plugin-ran")
	caPath := filepath.Join(dir, "ca.crt")
	writeOrFail(t, caPath, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: counting.Certificate().Raw,
	}))

	// Two markers the kubeconfig carries and no output may. They are named for
	// what they are — plugin arguments and plugin environment — rather than for
	// what they resemble, because neither is a credential.
	const pluginArgumentMarker = "svcdoctor-exec-argument-that-must-not-leak"
	const pluginEnvMarker = "svcdoctor-exec-env-that-must-not-leak"

	kubeconfig := writeKubeconfig(t, dir, counting.URL, caPath,
		"    exec:\n"+
			"      apiVersion: client.authentication.k8s.io/v1\n"+
			"      command: /bin/sh\n"+
			"      args:\n"+
			"        - -c\n"+
			"        - touch "+sentinel+" # "+pluginArgumentMarker+"\n"+
			"      env:\n"+
			"        - name: SVCDOCTOR_EXEC_PROBE\n"+
			"          value: "+pluginEnvMarker+"\n")

	got := runLeaf(t, "", leafArgs(kubeconfig)...)

	if got.code != exitUsage {
		t.Errorf("exit = %d, want %d.\n\nAn exec credential plugin is a configuration "+
			"error, refused before any network operation — not a run that fails.\n"+
			"stdout:\n%s\nstderr:\n%s", got.code, exitUsage, got.stdout, got.stderr)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("THE EXEC PLUGIN RAN. The sentinel file exists.\n\n" +
			"svcdoctor must never execute a command a configuration file names " +
			"(ADR 0094 §2.2). This is a release gate.")
	}
	if n := requests.Load(); n != 0 {
		t.Errorf("the API server received %d requests; a refused kubeconfig is decided "+
			"before anything is dialled", n)
	}

	combined := got.stdout + got.stderr
	for _, leaked := range []string{pluginArgumentMarker, pluginEnvMarker, "/bin/sh"} {
		if strings.Contains(combined, leaked) {
			t.Errorf("the refusal echoed %q from the kubeconfig.\n\n"+
				"A refused construct is named by kind, never by content: quoting it "+
				"puts attacker-chosen text in a report.\noutput: %s", leaked, combined)
		}
	}
}

// --- the no-request failure matrix ------------------------------------------

// TestNoInvalidInvocationReachesTheAPIServer.
//
// Every row is a configuration defect, and every one must exit 2 having sent
// **nothing**. The counter is the assertion: a refusal that happened for the
// right reason but after a request would still be a credential presented, a
// connection logged and, against a real control plane, an audit entry.
//
// The rows are `PHASE121C1…§12`'s matrix. Where the defect is in the kubeconfig
// the file is written against the counting server, so a run that ignored the
// refusal would reach it.
func TestNoInvalidInvocationReachesTheAPIServer(t *testing.T) {
	type row struct {
		name      string
		userBlock string
		clusterAd string
		args      func(kubeconfig string) []string
	}

	full := func(extra ...string) func(string) []string {
		return func(kubeconfig string) []string { return leafArgs(kubeconfig, extra...) }
	}

	rows := []row{
		{
			name: "neither a kubeconfig nor in-cluster",
			args: func(string) []string {
				return []string{"diagnose", "kubernetes",
					"--namespace", "payments", "--service-name", "payments-api"}
			},
		},
		{
			name: "a kubeconfig and in-cluster together",
			args: func(kubeconfig string) []string {
				return []string{"diagnose", "kubernetes", "--in-cluster",
					"--kubeconfig", kubeconfig,
					"--namespace", "payments", "--service-name", "payments-api"}
			},
		},
		{
			name: "a kubeconfig with no context",
			args: func(kubeconfig string) []string {
				return []string{"diagnose", "kubernetes", "--kubeconfig", kubeconfig,
					"--namespace", "payments", "--service-name", "payments-api"}
			},
		},
		{
			name: "a context in-cluster",
			args: func(string) []string {
				return []string{"diagnose", "kubernetes", "--in-cluster", "--context", "prod",
					"--namespace", "payments", "--service-name", "payments-api"}
			},
		},
		{
			// Overridden below by naming a context that does not exist.
			name: "a context the kubeconfig does not name",
			args: full(),
		},
		{
			name: "no namespace",
			args: func(kubeconfig string) []string {
				return []string{"diagnose", "kubernetes", "--kubeconfig", kubeconfig,
					"--context", "prod", "--service-name", "payments-api"}
			},
		},
		{
			name: "no service name",
			args: func(kubeconfig string) []string {
				return []string{"diagnose", "kubernetes", "--kubeconfig", kubeconfig,
					"--context", "prod", "--namespace", "payments"}
			},
		},
		{
			name: "both token sources",
			args: func(kubeconfig string) []string {
				return leafArgs(kubeconfig,
					"--token-file", writeTemp(t, "t", "a-token"), "--token-stdin")
			},
		},
		{
			name: "a token file in-cluster",
			args: func(string) []string {
				return []string{"diagnose", "kubernetes", "--in-cluster",
					"--namespace", "payments", "--service-name", "payments-api",
					"--token-file", writeTemp(t, "t2", "a-token")}
			},
		},
		{
			name: "a token on stdin in-cluster",
			args: func(string) []string {
				return []string{"diagnose", "kubernetes", "--in-cluster",
					"--namespace", "payments", "--service-name", "payments-api",
					"--token-stdin"}
			},
		},
		{
			name:      "an empty token file",
			userBlock: "    {}\n",
			args:      full("--token-file", writeTemp(t, "empty", "")),
		},
		{
			name:      "an empty token on stdin",
			userBlock: "    {}\n",
			args:      full("--token-stdin"),
		},
		{
			name: "a token beside a kubeconfig identity",
			args: full("--token-file", writeTemp(t, "second", "a-second-identity")),
		},
		{
			name: "an auth-provider",
			userBlock: "    auth-provider:\n" +
				"      name: oidc\n      config:\n        idp-issuer-url: https://issuer.invalid\n",
			args: full(),
		},
		{
			name:      "impersonation",
			userBlock: "    token: fixture-token\n    as: someone-else\n",
			args:      full(),
		},
		{
			name:      "basic authentication",
			userBlock: "    username: admin\n    password: hunter2\n",
			args:      full(),
		},
		{
			name:      "a proxy URL",
			userBlock: "    token: fixture-token\n",
			clusterAd: "    proxy-url: http://proxy.invalid:3128\n",
			args:      full(),
		},
		{
			name:      "insecure-skip-tls-verify",
			userBlock: "    token: fixture-token\n",
			clusterAd: "    insecure-skip-tls-verify: true\n",
			args:      full(),
		},
		{
			name:      "an unreadable token file",
			userBlock: "    {}\n",
			args:      full("--token-file", filepath.Join(t.TempDir(), "absent")),
		},
		{
			name:      "an output format that does not exist",
			userBlock: "    token: fixture-token\n",
			args:      full("--output", "yaml"),
		},
		{
			name:      "a non-positive timeout",
			userBlock: "    token: fixture-token\n",
			args:      full("--timeout", "0s"),
		},
	}

	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					healthyHandler()(w, r)
				}))
			t.Cleanup(server.Close)

			dir := t.TempDir()
			caPath := filepath.Join(dir, "ca.crt")
			writeOrFail(t, caPath, pem.EncodeToMemory(&pem.Block{
				Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
			}))

			userBlock := tc.userBlock
			if userBlock == "" {
				userBlock = "    token: fixture-token\n"
			}
			document := "apiVersion: v1\nkind: Config\n" +
				"clusters:\n- name: c\n  cluster:\n    server: " + server.URL + "\n" +
				"    certificate-authority: " + caPath + "\n" + tc.clusterAd +
				"users:\n- name: u\n  user:\n" + userBlock +
				"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n"
			kubeconfig := filepath.Join(dir, "kubeconfig")
			writeOrFail(t, kubeconfig, []byte(document))

			args := tc.args(kubeconfig)
			if tc.name == "a context the kubeconfig does not name" {
				args = leafArgs(kubeconfig)
				for i, value := range args {
					if value == "prod" {
						args[i] = "a-context-that-does-not-exist"
					}
				}
			}

			got := runLeaf(t, "", args...)

			if got.code != exitUsage {
				t.Errorf("exit = %d, want %d; a configuration defect is something the "+
					"operator wrote.\nstdout:\n%s\nstderr:\n%s",
					got.code, exitUsage, got.stdout, got.stderr)
			}
			if n := requests.Load(); n != 0 {
				t.Errorf("the API server received %d requests.\n\n"+
					"An invalid configuration is decided before anything is dialled: "+
					"the alternative is a credential presented and an audit entry "+
					"written for a run that could never complete.", n)
			}
			if got.stdout != "" {
				t.Errorf("a refused invocation wrote a report to stdout:\n%s", got.stdout)
			}
		})
	}
}

// --- the four findings, and the exit contract -------------------------------

// TestTheLeafCommandReachesEveryKubernetesFinding.
//
// The same scenarios `TestTheKubernetesExitBehaviourIsTheGenericOne` drives
// through `run --config`, driven through the leaf. The exit codes are the
// **generic** mapping's: nothing in `internal/cli/kubernetes.go` reads a finding,
// a severity or a code, so what this pins is that the new entry point delegates
// rather than deciding.
func TestTheLeafCommandReachesEveryKubernetesFinding(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		want    int
		codes   []string
		absent  []string
	}{
		{
			name:    "a Service with a ready endpoint",
			handler: healthyHandler(),
			want:    exitOK,
			absent:  []string{"KUBERNETES_"},
		},
		{
			name: "an absent Service",
			handler: apiHandler(writeStatus(http.StatusNotFound, "NotFound"),
				writeJSON(emptyPodList), writeJSON(emptySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NOT_FOUND"},
		},
		{
			name: "a refused Pod list",
			handler: apiHandler(writeJSON(clusterIPService),
				writeStatus(http.StatusForbidden, "Forbidden"), writeJSON(readySliceList)),
			want:   exitIncomplete,
			codes:  []string{"KUBERNETES_API_ACCESS_DENIED"},
			absent: []string{"KUBERNETES_SERVICE_SELECTS_NO_PODS"},
		},
		{
			name: "a selector matching nothing",
			handler: apiHandler(writeJSON(clusterIPService),
				writeJSON(emptyPodList), writeJSON(readySliceList)),
			want:   exitProblemsFound,
			codes:  []string{"KUBERNETES_SERVICE_SELECTS_NO_PODS"},
			absent: []string{"KUBERNETES_SERVICE_NO_READY_ENDPOINT"},
		},
		{
			name: "nothing published",
			handler: apiHandler(writeJSON(clusterIPService),
				writeJSON(onePodList), writeJSON(emptySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NO_READY_ENDPOINT"},
		},
		{
			name: "published but nothing ready",
			handler: apiHandler(writeJSON(clusterIPService),
				writeJSON(onePodList), writeJSON(unreadySliceList)),
			want:  exitProblemsFound,
			codes: []string{"KUBERNETES_SERVICE_NO_READY_ENDPOINT"},
		},
		{
			// The recorded limitation, pinned at the new entry point too.
			// ADR 0094 §10.4 refuses a 401 a Kubernetes code deliberately and
			// DIAG_FAILURE_BOUNDARY localizes it at INFO, so the summary is OK
			// and the run is complete. It is CONTRACT-CONFORMANT and closing it
			// needs a fifth code with its own record.
			name: "an unaccepted identity",
			handler: apiHandler(writeStatus(http.StatusUnauthorized, "Unauthorized"),
				writeJSON(emptyPodList), writeJSON(emptySliceList)),
			want:   exitOK,
			absent: []string{"KUBERNETES_"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kubeconfig := kubernetesAPI(t, tc.handler)
			got := runLeaf(t, "", leafArgs(kubeconfig)...)

			if got.code != tc.want {
				t.Errorf("exit = %d, want %d.\nstdout:\n%s\nstderr:\n%s",
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
		})
	}
}

// --- entry-point equivalence ------------------------------------------------

// TestTheLeafAndTheFleetProduceTheSameReport.
//
// **This is the strongest stable boundary the architecture offers**, and it is
// the repository's own: ADR 0074 §2.1 makes the aggregate *wrap* rather than
// merge, and `TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun` already
// asserts byte identity for Redis. So the comparison here is byte identity of
// the canonical report, with timings blanked because a duration is a measurement
// rather than content.
//
// It is not an incidental-decoration comparison: the whole report is compared,
// including the evidence graph, every finding, every severity, every confidence,
// every recommendation and the summary. If the leaf had duplicated acquisition,
// wired a different rule set, or reached a different budget, a byte would move.
func TestTheLeafAndTheFleetProduceTheSameReport(t *testing.T) {
	scenarios := map[string]http.HandlerFunc{
		"healthy": healthyHandler(),
		"service not found": apiHandler(writeStatus(http.StatusNotFound, "NotFound"),
			writeJSON(emptyPodList), writeJSON(emptySliceList)),
		"api access denied": apiHandler(writeJSON(clusterIPService),
			writeStatus(http.StatusForbidden, "Forbidden"), writeJSON(readySliceList)),
		"selects no pods": apiHandler(writeJSON(clusterIPService),
			writeJSON(emptyPodList), writeJSON(readySliceList)),
		"no ready endpoint": apiHandler(writeJSON(clusterIPService),
			writeJSON(onePodList), writeJSON(unreadySliceList)),
	}

	for name, handler := range scenarios {
		t.Run(name, func(t *testing.T) {
			kubeconfig := kubernetesAPI(t, handler)

			leaf := runLeaf(t, "", leafArgs(kubeconfig)...)
			fleet := runCLI(t, context.Background(),
				"run", "--config", kubernetesRunConfig(t, kubeconfig), "--output", "json")

			if leaf.stdout == "" || fleet.stdout == "" {
				t.Fatalf("one entry point produced no report.\nleaf: %q\nfleet: %q",
					leaf.stdout, fleet.stdout)
			}

			leafReport := normalizeJSON(t, []byte(leaf.stdout))
			embedded := embeddedTargetReport(t, []byte(fleet.stdout))

			// Non-vacuity: the documents compared must actually be reports
			// carrying the evidence this phase is about. Two empty strings are
			// equal, and that would prove nothing at all.
			for _, marker := range []string{
				`"schemaVersion"`, "k8s.api_access", "k8s.service", "service/payments",
			} {
				if !strings.Contains(leafReport, marker) {
					t.Fatalf("the leaf report does not contain %s; the comparison below "+
						"would be vacuous:\n%s", marker, leafReport)
				}
			}

			if leafReport != embedded {
				t.Errorf("the two entry points produced different reports.\n\n"+
					"One Service is one target and one report through both entry points "+
					"(ADR 0094 §2.10). A difference here means the leaf reached a "+
					"different acquisition, a different rule set or a different budget.\n"+
					"--- leaf\n%s\n--- embedded in the run\n%s", leafReport, embedded)
			}

			// The finding multiset, asserted separately so a failure says which
			// half moved rather than printing two documents.
			if got, want := findingCodesIn(t, leafReport), findingCodesIn(t, embedded); !equalStrings(
				got, want) {
				t.Errorf("the finding multisets differ: leaf %v, fleet %v", got, want)
			}
		})
	}
}

// --- secret non-observability -----------------------------------------------

// TestTheBearerTokenValueIsUnobservable.
//
// Two different tokens, one identical hermetic server, one identical invocation
// otherwise. The canonical output must be **byte-identical**, which is the
// property Phase 9.1C settled on as the honest one: a secret equal to a value
// the report must carry is indistinguishable, so what is pinned is that changing
// the credential changes no byte of the answer.
//
// It is asserted in both output modes and in the shareable projection, because a
// leak that only appeared in one of the three would be the one nobody looked at.
func TestTheBearerTokenValueIsUnobservable(t *testing.T) {
	const first = "svcdoctor-first-bearer-token-value"
	const second = "svcdoctor-second-bearer-token-value-that-is-longer"

	for _, mode := range [][]string{
		{"--output", "json"},
		{"--output", "text"},
		{"--output", "json", "--shareable"},
	} {
		t.Run(strings.Join(mode, " "), func(t *testing.T) {
			run := func(token string) blackBox {
				server := httptest.NewTLSServer(healthyHandler())
				t.Cleanup(server.Close)

				dir := t.TempDir()
				caPath := filepath.Join(dir, "ca.crt")
				writeOrFail(t, caPath, pem.EncodeToMemory(&pem.Block{
					Type: "CERTIFICATE", Bytes: server.Certificate().Raw,
				}))
				kubeconfig := writeKubeconfig(t, dir, server.URL, caPath, "    {}\n")

				args := []string{
					"diagnose", "kubernetes",
					"--kubeconfig", kubeconfig, "--context", "prod",
					"--namespace", "payments", "--service-name", "payments-api",
					"--token-stdin",
				}
				return runLeaf(t, token, append(args, mode...)...)
			}

			a, b := run(first), run(second)

			if a.code != b.code {
				t.Errorf("two tokens produced two exit codes: %d and %d", a.code, b.code)
			}
			if got, want := blankVarying(a.stdout), blankVarying(b.stdout); got != want {
				t.Errorf("changing the bearer token changed the report.\n"+
					"--- first\n%s\n--- second\n%s", got, want)
			}

			for _, token := range []string{first, second} {
				for stream, body := range map[string]string{
					"stdout": a.stdout + b.stdout,
					"stderr": a.stderr + b.stderr,
				} {
					if strings.Contains(body, token) {
						t.Errorf("the bearer token appears in %s", stream)
					}
				}
			}
			// Not a prefix, not a suffix, not a length. Each would be a
			// derived fact that buys a reader nothing and an attacker
			// something.
			for _, fragment := range []string{first[:12], second[:12]} {
				if strings.Contains(a.stdout+a.stderr+b.stdout+b.stderr, fragment) {
					t.Errorf("a fragment of the bearer token (%q) appears in the output",
						fragment)
				}
			}
		})
	}
}

// --- the output half, which the token property alone cannot see ------------

// TestTheLeafOutputFlagsActuallyReachTheRenderer.
//
// # Why this exists beside every other test in this file
//
// The Phase 12.1C.2 mutation harness found two survivors here, and both are
// worth recording because they are the same shape: a *comparison* between two
// runs cannot see a bug that affects both runs identically.
//
// `TestTheBearerTokenValueIsUnobservable` drives `--output text` and
// `--output json` and `--shareable`. But it compares one run against another, so
// a command that ignored `--output` and always rendered JSON, or ignored
// `--shareable` and always produced the local report, produced two identical
// outputs and passed. This asserts the absolute facts instead: **text is text,
// JSON is JSON, and shareable is redacted.**
func TestTheLeafOutputFlagsActuallyReachTheRenderer(t *testing.T) {
	kubeconfig := kubernetesAPI(t, healthyHandler())
	base := []string{
		"diagnose", "kubernetes",
		"--kubeconfig", kubeconfig, "--context", "prod",
		"--namespace", "payments", "--service-name", "payments-api",
	}

	t.Run("json is JSON", func(t *testing.T) {
		got := runLeaf(t, "", append(base, "--output", "json")...)
		if got.code != exitOK {
			t.Fatalf("exit = %d: %s", got.code, got.stderr)
		}
		var document map[string]any
		if err := json.Unmarshal([]byte(got.stdout), &document); err != nil {
			t.Fatalf("--output json did not produce JSON: %v\n%s", err, got.stdout)
		}
		if _, ok := document["schemaVersion"]; !ok {
			t.Errorf("the JSON artifact carries no schemaVersion:\n%s", got.stdout)
		}
	})

	t.Run("text is not JSON", func(t *testing.T) {
		got := runLeaf(t, "", append(base, "--output", "text")...)
		if got.code != exitOK {
			t.Fatalf("exit = %d: %s", got.code, got.stderr)
		}
		if got.stdout == "" {
			t.Fatal("--output text produced nothing")
		}
		var document map[string]any
		if json.Unmarshal([]byte(got.stdout), &document) == nil {
			t.Errorf("--output text produced a JSON document, so the flag reached no "+
				"renderer:\n%s", got.stdout)
		}
		// The terminal rendering names the Service it was asked about, which the
		// JSON artifact also does — so the discriminator is the *shape*, and the
		// assertion above is the one that matters. This only confirms the
		// rendering is the product's rather than an empty string.
		if !strings.Contains(got.stdout, "payments") {
			t.Errorf("the terminal rendering does not name the Service:\n%s", got.stdout)
		}
	})

	t.Run("shareable is redacted and local is not", func(t *testing.T) {
		local := runLeaf(t, "", append(base, "--output", "json")...)
		shared := runLeaf(t, "", append(base, "--output", "json", "--shareable")...)

		if local.code != exitOK || shared.code != exitOK {
			t.Fatalf("exits %d and %d: %s / %s",
				local.code, shared.code, local.stderr, shared.stderr)
		}
		if blankVarying(local.stdout) == blankVarying(shared.stdout) {
			t.Fatalf("--shareable produced the same document as the local report, so "+
				"the flag reached no projection.\n%s", shared.stdout)
		}

		// The narrow, checkable facts: the local report says it is local and
		// names the Service; the shareable one says it is redacted and does not.
		if !strings.Contains(local.stdout, "LOCAL_FULL") {
			t.Errorf("the local report is not labelled LOCAL_FULL:\n%s", local.stdout)
		}
		if !strings.Contains(shared.stdout, "SHAREABLE_REDACTED") {
			t.Errorf("the shareable report is not labelled SHAREABLE_REDACTED:\n%s",
				shared.stdout)
		}
		if strings.Contains(shared.stdout, "payments-api") {
			t.Errorf("the shareable report still names the Service; a Kubernetes name is "+
				"AttrKindIdentity and structural redaction transforms it:\n%s",
				shared.stdout)
		}
		if !strings.Contains(local.stdout, "payments-api") {
			t.Errorf("the local report does not name the Service, so the assertion above "+
				"proves nothing:\n%s", local.stdout)
		}
	})
}

// --- hostile remote prose ---------------------------------------------------

// TestHostileAPIProseNeverReachesTheReport.
//
// ADR 0094 §2.8: API errors are normalized from **structured information only** —
// the HTTP status and `metav1.StatusReason`, through `apierrors`.
// `Status.Message`, `status.details.causes[].message` and every condition message
// are never read, matched, parsed or interpolated.
//
// The server here returns a reason svcdoctor does act on beside a message
// designed to be quoted: markup, an injected finding code, a shell fragment and
// an ANSI escape. None of it may appear anywhere, in any output mode.
func TestHostileAPIProseNeverReachesTheReport(t *testing.T) {
	const hostile = "</findings><script>alert(1)</script> KUBERNETES_SERVICE_NOT_FOUND " +
		"$(rm -rf /) \\u001b[31m svcdoctor-hostile-marker"

	hostileStatus := func(code int, reason string) func(http.ResponseWriter) {
		return func(w http.ResponseWriter) {
			w.WriteHeader(code)
			body, err := json.Marshal(map[string]any{
				"kind": "Status", "apiVersion": "v1", "status": "Failure",
				"reason": reason, "code": code, "message": hostile,
				"details": map[string]any{
					"name": hostile, "group": hostile,
					"causes": []any{map[string]any{"message": hostile, "field": hostile}},
				},
			})
			if err != nil {
				panic(err)
			}
			_, _ = w.Write(body)
		}
	}

	tests := map[string]http.HandlerFunc{
		"a hostile 404": apiHandler(hostileStatus(http.StatusNotFound, "NotFound"),
			writeJSON(emptyPodList), writeJSON(emptySliceList)),
		"a hostile 403": apiHandler(writeJSON(clusterIPService),
			hostileStatus(http.StatusForbidden, "Forbidden"), writeJSON(readySliceList)),
		"a hostile 500": apiHandler(hostileStatus(http.StatusInternalServerError, "InternalError"),
			writeJSON(emptyPodList), writeJSON(emptySliceList)),
	}

	for name, handler := range tests {
		for _, mode := range [][]string{
			{"--output", "json"},
			{"--output", "text"},
			{"--output", "json", "--shareable"},
		} {
			t.Run(name+" "+strings.Join(mode, " "), func(t *testing.T) {
				kubeconfig := kubernetesAPI(t, handler)
				args := leafArgs(kubeconfig)[:len(leafArgs(kubeconfig))-2]
				got := runLeaf(t, "", append(args, mode...)...)

				combined := got.stdout + got.stderr
				for _, fragment := range []string{
					"svcdoctor-hostile-marker", "<script>", "alert(1)",
					"rm -rf", "</findings>",
				} {
					if strings.Contains(combined, fragment) {
						t.Errorf("hostile remote prose reached the output: %q\n\n"+
							"An API error is normalized from the status and the "+
							"StatusReason only; a message is data a cluster chose "+
							"and svcdoctor never quotes it.\noutput:\n%s",
							fragment, combined)
					}
				}
			})
		}
	}
}

// --- helpers ----------------------------------------------------------------

// exitUsage names the code from the package that owns the mapping.
const exitUsage = 2

// runLeaf drives `svcdoctor diagnose kubernetes` with real arguments and the
// given stdin.
func runLeaf(t *testing.T, stdin string, args ...string) blackBox {
	t.Helper()
	return runCLIWithStdin(t, context.Background(), stdin, args...)
}

// normalizeJSON blanks the fields that are measurements rather than content and
// re-renders the document deterministically.
func normalizeJSON(t *testing.T, raw []byte) string {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal report: %v\nbody: %s", err, raw)
	}
	blankMeasurements(generic)
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

// embeddedTargetReport extracts the single target's report from an aggregate.
func embeddedTargetReport(t *testing.T, aggregate []byte) string {
	t.Helper()
	var document struct {
		Targets []struct {
			Report json.RawMessage `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(aggregate, &document); err != nil {
		t.Fatalf("unmarshal aggregate: %v\nbody: %s", err, aggregate)
	}
	if len(document.Targets) != 1 {
		t.Fatalf("the aggregate holds %d targets, want 1", len(document.Targets))
	}
	return normalizeJSON(t, document.Targets[0].Report)
}

// blankMeasurements replaces every timestamp and duration, recursively.
//
// A duration is a measurement rather than content, and two runs of the same
// scenario legitimately differ in one. Everything else is compared.
func blankMeasurements(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key := range typed {
			switch key {
			case "startedAt", "duration":
				typed[key] = "<varies>"
			default:
				blankMeasurements(typed[key])
			}
		}
	case []any:
		for _, item := range typed {
			blankMeasurements(item)
		}
	}
}

// blankVarying removes the run-to-run variation from a rendered artifact.
//
// # The first version of this was wrong, and it made two tests vacuous
//
// It split the body on whitespace and replaced any field containing a digit that
// ended in "s" or contained "T". A JSON report is **one line**, so the whole
// document was one field, and it matched — every JSON comparison in this file
// was comparing "<varies>" with "<varies>". The Phase 12.1C.2 mutation harness
// found it the direct way: a command that ignored --shareable produced two
// identical documents and the guard could not see it.
//
// So the two shapes are now handled as the two shapes they are. A JSON artifact
// is parsed and normalized structurally, which changes exactly the two keys that
// are measurements. Anything else is scrubbed by pattern, on the values that
// really do vary — a duration, an RFC 3339 timestamp, and the hermetic server's
// ephemeral port.
func blankVarying(body string) string {
	var document map[string]any
	if err := json.Unmarshal([]byte(body), &document); err == nil {
		blankMeasurements(document)
		out, err := json.MarshalIndent(document, "", "  ")
		if err == nil {
			return string(out)
		}
	}
	return varyingText.ReplaceAllString(body, "<varies>")
}

// varyingText matches the values a terminal rendering carries that differ
// between two runs of the same scenario.
//
// A duration with any unit, an RFC 3339 timestamp, and a loopback address with
// an ephemeral port. Nothing else: a pattern broad enough to swallow a report is
// a pattern that proves two reports equal whatever they say.
var varyingText = regexp.MustCompile(
	`[0-9]+(\.[0-9]+)?(ns|µs|ms|s|m|h)\b` +
		`|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z?` +
		`|127\.0\.0\.1:[0-9]+`)

// findingCodesIn returns every finding code in a normalized report, sorted.
func findingCodesIn(t *testing.T, report string) []string {
	t.Helper()
	var document struct {
		Findings []struct {
			Code string `json:"code"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(report), &document); err != nil {
		// A terminal rendering is not JSON; the caller only passes reports.
		t.Fatalf("unmarshal findings: %v", err)
	}
	out := make([]string, 0, len(document.Findings))
	for _, finding := range document.Findings {
		out = append(out, finding.Code)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
