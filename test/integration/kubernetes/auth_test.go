//go:build integration

package kubernetes

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real authentication and real authorization.
//
// # Why the RBAC lane cannot be simulated
//
// A 403 from an `httptest` handler proves that svcdoctor normalizes a status
// code. It proves nothing about whether the **three permissions ADR 0094 §2.5
// froze are the three permissions svcdoctor actually needs** — that is a
// property of the API server's authorizer meeting svcdoctor's requests, and the
// only way to be wrong about it is to never ask a real one.
//
// So every identity here is a real ServiceAccount holding a real namespaced
// Role, and every denial is the API server's own.

// frozenRules are the exact permissions ADR 0094 §2.5 requires.
//
// Three resources, two verbs, one namespace. No ClusterRole and no
// cluster-scoped grant: if a scenario needed one, the frozen RBAC minimum would
// be wrong, and that is a blocker rather than a fixture detail.
var frozenRules = map[string][]string{
	"services":       {"get"},
	"pods":           {"list"},
	"endpointslices": {"list"},
}

// identity is a ServiceAccount, its kubeconfig and its token file.
type identity struct {
	kubeconfig string
	context    string
	tokenPath  string
	token      string
}

// restrictedIdentity creates a ServiceAccount holding exactly `rules`, mints a
// token for it, and writes a **credential-free** kubeconfig pointing at the same
// cluster.
//
// The kubeconfig carries no user credential at all, so the token svcdoctor
// presents is unambiguously the one this function minted — which is also what
// makes `--token-file` and `--token-stdin` real tests rather than tests of
// whatever the file happened to contain.
func (h harness) restrictedIdentity(
	t *testing.T, namespace, name string, rules map[string][]string,
) identity {
	t.Helper()

	h.apply(t, "apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: "+name+
		"\n  namespace: "+namespace+"\n")

	role := "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata:\n  name: " +
		name + "\n  namespace: " + namespace + "\nrules:\n"
	if len(rules) == 0 {
		// A Role with no rule is legal and grants nothing. It exists so the
		// binding is real even when every read is denied.
		role += "  []\n"
	}
	for _, resource := range sortedKeys(map[string]string{
		"services": "", "pods": "", "endpointslices": "",
	}) {
		verbs, ok := rules[resource]
		if !ok {
			continue
		}
		group := `""`
		if resource == "endpointslices" {
			group = `"discovery.k8s.io"`
		}
		role += "  - apiGroups: [" + group + "]\n    resources: [\"" + resource +
			"\"]\n    verbs: [\"" + strings.Join(verbs, `", "`) + "\"]\n"
	}
	h.apply(t, role)

	h.apply(t, "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n  name: "+
		name+"\n  namespace: "+namespace+"\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n"+
		"  kind: Role\n  name: "+name+"\nsubjects:\n  - kind: ServiceAccount\n    name: "+
		name+"\n    namespace: "+namespace+"\n")

	token := strings.TrimSpace(h.kubectl(t, "-n", namespace, "create", "token", name,
		"--duration=1h"))
	if token == "" {
		t.Fatal("the TokenRequest API returned an empty token")
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeFileOrFail(t, tokenPath, token)

	caPath := filepath.Join(dir, "ca.crt")
	writeFileOrFail(t, caPath, h.clusterCA(t))

	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeFileOrFail(t, kubeconfig, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: "+h.serverURL(t)+"\n"+
		"    certificate-authority: "+caPath+"\n"+
		"users:\n- name: u\n  user: {}\n"+
		"contexts:\n- name: restricted\n  context:\n    cluster: c\n    user: u\n")

	// The binding is asynchronous in principle; wait until the authorizer really
	// answers as configured rather than assuming it does.
	h.waitFor(t, "the RBAC binding for "+name+" to take effect", func() (bool, string) {
		out, err := h.kubectlErr("auth", "can-i", "get", "services",
			"--as", "system:serviceaccount:"+namespace+":"+name, "-n", namespace)
		want := "yes"
		if _, granted := rules["services"]; !granted {
			want = "no"
		}
		if err != nil && want == "yes" {
			return false, strings.TrimSpace(out)
		}
		return strings.TrimSpace(out) == want, "can-i get services = " + strings.TrimSpace(out)
	})

	return identity{kubeconfig: kubeconfig, context: "restricted",
		tokenPath: tokenPath, token: token}
}

func writeFileOrFail(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// clusterCA returns the lane cluster's CA bundle in PEM.
func (h harness) clusterCA(t *testing.T) string {
	t.Helper()
	encoded := strings.TrimSpace(h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.clusters[?(@.name=="`+h.clusterName(t)+`")].cluster.certificate-authority-data}`))
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decoding the cluster CA: %v", err)
	}
	return string(decoded)
}

// serverURL returns the lane cluster's API server URL.
func (h harness) serverURL(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.clusters[?(@.name=="`+h.clusterName(t)+`")].cluster.server}`))
}

// clusterName returns the cluster the lane's context selects.
func (h harness) clusterName(t *testing.T) string {
	t.Helper()
	return strings.TrimSpace(h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.contexts[?(@.name=="`+h.context+`")].context.cluster}`))
}

// diagnoseAs runs a diagnosis under a restricted identity's kubeconfig.
func (h harness) diagnoseAs(
	t *testing.T, id identity, namespace, service string, extra ...string,
) (run, report) {
	t.Helper()
	args := append([]string{
		"diagnose", "kubernetes",
		"--kubeconfig", id.kubeconfig,
		"--context", id.context,
		"--namespace", namespace,
		"--service-name", service,
		"--output", "json",
		"--token-file", id.tokenPath,
	}, extra...)
	got := h.exec(t, "", args...)
	return got, parseReport(t, got)
}

// --- the RBAC matrix ---------------------------------------------------------

// TestR1R2R3RealRBACProducesTheBoundedAccessDeniedFinding.
//
// One row per denied operation. The assertion is not merely that F2 appears — it
// is the whole shape the frozen contract predicts for each denial, and two parts
// of that shape are things a real API server could have contradicted.
//
// # Branch independence, confirmed against a real authorizer
//
// `PHASE121A…§10.8` states that **one branch failing never erases the other
// branch's independent evidence**, and Phase 12.1C's reconciliation resolved the
// §10.3 tension in that rule's favour. So a denied Pod list withholds F3 and
// leaves the publication claim alone; a denied slice list withholds F4 and
// leaves the selector claim alone. Both rows below therefore expect **two**
// findings, and getting one would mean the reconciliation was wrong.
//
// # The exit codes differ between the rows, and the reason is completeness
//
// Measured rather than assumed. A denied **Service** read short-circuits: the
// two downstream reads never run, so they are `SKIPPED` with
// `EXEC_SKIPPED_PREREQUISITE_FAILED` and nothing was left half-measured. The run
// is *complete*, F2 is WARN, and the generic mapping returns **0**.
//
// A denied **list** is different: the enumeration was attempted and did not
// finish, so the result is incomplete and exit **4** outranks everything below
// it. Nothing Kubernetes-specific decides either; both are `docs/SCOPE.md`'s
// precedence applied to two different completeness states.
func TestR1R2R3RealRBACProducesTheBoundedAccessDeniedFinding(t *testing.T) {
	tests := []struct {
		name string
		// grant is the subset of the frozen minimum this identity holds.
		grant map[string][]string
		// deniedStep is the evidence node the API server refuses.
		deniedStep string
		// stillReads are the nodes that must still PASS, proving one branch
		// failing never erases another's independent evidence.
		stillReads []string
		// shortCircuited are the nodes that never run at all.
		shortCircuited []string
		// wantCodes is the exact Kubernetes finding set, in report order.
		wantCodes []string
		// withheld is the universal finding the denied branch makes impossible.
		withheld string
		// wantExit is the measured process status.
		wantExit int
	}{
		{
			name:           "R1 the Service read is denied",
			grant:          map[string][]string{"pods": {"list"}, "endpointslices": {"list"}},
			deniedStep:     "k8s.service",
			shortCircuited: []string{"k8s.pod_set", "k8s.endpoint_publication"},
			wantCodes:      []string{"KUBERNETES_API_ACCESS_DENIED"},
			withheld:       "KUBERNETES_SERVICE_NOT_FOUND",
			wantExit:       0,
		},
		{
			name: "R2 the Pod list is denied",
			grant: map[string][]string{
				"services": {"get"}, "endpointslices": {"list"},
			},
			deniedStep: "k8s.pod_set",
			stillReads: []string{"k8s.service", "k8s.endpoint_publication"},
			wantCodes: []string{
				"KUBERNETES_SERVICE_NO_READY_ENDPOINT", "KUBERNETES_API_ACCESS_DENIED",
			},
			withheld: "KUBERNETES_SERVICE_SELECTS_NO_PODS",
			wantExit: 4,
		},
		{
			name:       "R3 the EndpointSlice list is denied",
			grant:      map[string][]string{"services": {"get"}, "pods": {"list"}},
			deniedStep: "k8s.endpoint_publication",
			stillReads: []string{"k8s.service", "k8s.pod_set"},
			wantCodes: []string{
				"KUBERNETES_SERVICE_SELECTS_NO_PODS", "KUBERNETES_API_ACCESS_DENIED",
			},
			withheld: "KUBERNETES_SERVICE_NO_READY_ENDPOINT",
			wantExit: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ns := h.namespace(t)

			// A Service whose selector matches nothing and whose publication is
			// empty, so **both** universal findings are admissible on their own
			// evidence. That is what makes the withheld assertion meaningful:
			// the one that is missing is missing because its branch was denied,
			// not because its own precondition failed.
			h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
				map[string]string{"app": "nothing-matches-this"},
				"  ports:\n    - port: 80\n"))
			h.waitForReadyEndpoints(t, ns, "payments-api", 0)

			id := h.restrictedIdentity(t, ns, "restricted", tc.grant)
			got, parsed := h.diagnoseAs(t, id, ns, "payments-api")

			assertCodes(t, parsed, tc.wantCodes...)

			denied := parsed.node(t, tc.deniedStep)
			if denied.State != "UNKNOWN" {
				t.Errorf("%s = %s, want UNKNOWN; the target did not fail, svcdoctor's "+
					"measurement was blocked", tc.deniedStep, denied.State)
			}
			if denied.Failure != "AUTHZ_NOT_PERMITTED" {
				t.Errorf("%s failure class = %s, want AUTHZ_NOT_PERMITTED",
					tc.deniedStep, denied.Failure)
			}

			// **One branch failing never erases the other's evidence.**
			for _, step := range tc.stillReads {
				if state := parsed.node(t, step).State; state != "PASS" {
					t.Errorf("%s = %s, want PASS; the Pod set and the slice set are "+
						"siblings under the Service node rather than a chain", step, state)
				}
			}
			// A Service that could not be read has no selector to evaluate and
			// no slices to associate, so neither read is attempted at all.
			for _, step := range tc.shortCircuited {
				node := parsed.node(t, step)
				if node.State != "SKIPPED" {
					t.Errorf("%s = %s, want SKIPPED", step, node.State)
				}
				if node.Failure != "EXEC_SKIPPED_PREREQUISITE_FAILED" {
					t.Errorf("%s failure class = %s, want EXEC_SKIPPED_PREREQUISITE_FAILED",
						step, node.Failure)
				}
			}

			// A denied read is never an empty set.
			for _, code := range parsed.codes() {
				if code == tc.withheld {
					t.Errorf("the run published %s from a branch the API server refused; "+
						"unavailable is not empty", tc.withheld)
				}
			}

			// The API server's 403 prose names the ServiceAccount and the verb.
			// None of it may be quoted.
			assertNoProseLeak(t, got,
				"system:serviceaccount:", "is forbidden", "cannot list resource")
			for _, finding := range parsed.Findings {
				if finding.Code != "KUBERNETES_API_ACCESS_DENIED" {
					continue
				}
				for _, forbidden := range []string{"RBAC", "cluster-admin", "Role"} {
					if strings.Contains(finding.Detail, forbidden) {
						t.Errorf("the refusal names %q; ADR 0094 §2.7 forbids it", forbidden)
					}
				}
			}

			if got.code != tc.wantExit {
				t.Errorf("exit = %d, want %d", got.code, tc.wantExit)
			}
		})
	}
}

// TestTheFrozenRBACMinimumIsSufficient.
//
// The other direction, and the one that would make ADR 0094 §2.5 wrong if it
// failed: an identity holding **exactly** the three frozen permissions and
// nothing else completes a whole diagnosis.
func TestTheFrozenRBACMinimumIsSufficient(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	id := h.restrictedIdentity(t, ns, "minimum", frozenRules)
	got, parsed := h.diagnoseAs(t, id, ns, "payments-api")

	assertCodes(t, parsed)
	if got.code != 0 {
		t.Fatalf("exit = %d, want 0.\n\nThe three permissions ADR 0094 §2.5 froze are "+
			"not sufficient for a real API server, which is a contract defect rather "+
			"than a fixture one.\nstderr: %s", got.code, got.stderr)
	}
	for _, step := range []string{"k8s.service", "k8s.pod_set", "k8s.endpoint_publication"} {
		if state := parsed.node(t, step).State; state != "PASS" {
			t.Errorf("%s = %s under the frozen minimum, want PASS", step, state)
		}
	}
}

// --- the credential-bearing modes -------------------------------------------

// TestTokenFileAuthenticatesAgainstTheRealAPIServer is mode A by file.
func TestTokenFileAuthenticatesAgainstTheRealAPIServer(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForReadyEndpoints(t, ns, "payments-api", 0)

	id := h.restrictedIdentity(t, ns, "tokenfile", frozenRules)
	got, parsed := h.diagnoseAs(t, id, ns, "payments-api")

	if mode := stringAttr(t, parsed, "k8s.api_access", "k8s.auth_mode"); mode != "TOKEN" {
		t.Errorf("auth mode = %s, want TOKEN", mode)
	}
	assertCodes(t, parsed, "KUBERNETES_SERVICE_SELECTS_NO_PODS")
	assertNoTokenLeak(t, got, id.token)
}

// TestTokenStdinAuthenticatesAgainstTheRealAPIServer is mode A by pipe.
//
// The token enters through stdin alone. It is never an argument, so it is never
// in this process's `argv` and never in the child's.
func TestTokenStdinAuthenticatesAgainstTheRealAPIServer(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForReadyEndpoints(t, ns, "payments-api", 0)

	id := h.restrictedIdentity(t, ns, "tokenstdin", frozenRules)

	got := h.exec(t, id.token,
		"diagnose", "kubernetes",
		"--kubeconfig", id.kubeconfig, "--context", id.context,
		"--namespace", ns, "--service-name", "payments-api",
		"--output", "json", "--token-stdin")
	parsed := parseReport(t, got)

	if mode := stringAttr(t, parsed, "k8s.api_access", "k8s.auth_mode"); mode != "TOKEN" {
		t.Errorf("auth mode = %s, want TOKEN", mode)
	}
	assertCodes(t, parsed, "KUBERNETES_SERVICE_SELECTS_NO_PODS")
	assertNoTokenLeak(t, got, id.token)
}

// TestClientCertificateAuthenticatesAgainstTheRealAPIServer is mode C, reached
// where the frozen contract says it is reached: **through the kubeconfig**.
//
// kind's own generated kubeconfig authenticates with a client certificate and
// key, so this is the lane's ordinary credential and needs no fixture at all.
// There is no `--client-cert` flag and this test would not compile if there were
// one — the whole point of refusing the pair is that a leaf cannot express an
// identity a configuration file cannot.
func TestClientCertificateAuthenticatesAgainstTheRealAPIServer(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	got, parsed := h.diagnoseJSON(t, ns, "payments-api")

	if mode := stringAttr(t, parsed, "k8s.api_access", "k8s.auth_mode"); mode != "CLIENT_CERT" {
		t.Fatalf("auth mode = %s, want CLIENT_CERT; this lane's kubeconfig is expected "+
			"to authenticate with a certificate", mode)
	}
	assertCodes(t, parsed)
	if got.code != 0 {
		t.Errorf("exit = %d, want 0", got.code)
	}

	// The private key is in the kubeconfig this run read. Nothing derived from
	// it may appear in the output.
	for _, marker := range []string{
		"PRIVATE KEY", "BEGIN CERTIFICATE", "client-key", "client-certificate",
	} {
		if strings.Contains(got.stdout+got.stderr, marker) {
			t.Errorf("the output carries %q, which came from the kubeconfig", marker)
		}
	}
}

// TestAnUnauthenticatedIdentityEarnsNoKubernetesFinding measures the recorded
// limitation against a real API server rather than a fixture.
//
// A token the API server rejects is a **401**. ADR 0094 §10.4 refuses it a
// Kubernetes finding code deliberately: it is authentication rather than
// authorization, and `DIAG_FAILURE_BOUNDARY` localizes it at INFO. So the run is
// complete, the summary is OK, and the generic mapping returns **0**.
//
// This is measured here so that the release decision in the Phase 12.1D record
// rests on an observation rather than on a fixture's idea of what a 401 is.
func TestAnUnauthenticatedIdentityEarnsNoKubernetesFinding(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	// A syntactically well-formed bearer token the API server will not accept.
	// It is not a real credential and authenticates as nobody.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	writeFileOrFail(t, tokenPath, "not-a-token-this-api-server-issued")
	caPath := filepath.Join(dir, "ca.crt")
	writeFileOrFail(t, caPath, h.clusterCA(t))
	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeFileOrFail(t, kubeconfig, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: "+h.serverURL(t)+"\n"+
		"    certificate-authority: "+caPath+"\n"+
		"users:\n- name: u\n  user: {}\n"+
		"contexts:\n- name: anon\n  context:\n    cluster: c\n    user: u\n")

	got := h.exec(t, "",
		"diagnose", "kubernetes",
		"--kubeconfig", kubeconfig, "--context", "anon",
		"--namespace", ns, "--service-name", "payments-api",
		"--output", "json", "--token-file", tokenPath)
	parsed := parseReport(t, got)

	assertCodes(t, parsed)
	if got.code != 0 {
		t.Errorf("exit = %d.\n\nThe recorded limitation is that a 401 exits 0. A "+
			"different code here means the behaviour changed and the limitation "+
			"record is stale.\nstderr: %s", got.code, got.stderr)
	}
	if status := parsed.Summary.Status; status != "OK" {
		t.Errorf("summary = %s, want OK", status)
	}

	// What it *does* produce: a failed api_access node carrying the credential
	// rejection, and the generic boundary localizing it.
	access := parsed.node(t, "k8s.api_access")
	if access.State != "FAIL" {
		t.Errorf("k8s.api_access = %s, want FAIL", access.State)
	}
	if access.Failure != "AUTH_CREDENTIALS_REJECTED" {
		t.Errorf("failure class = %s, want AUTH_CREDENTIALS_REJECTED", access.Failure)
	}
	boundary := false
	for _, code := range parsed.codes() {
		if code == "DIAG_FAILURE_BOUNDARY" {
			boundary = true
		}
	}
	if !boundary {
		t.Error("no DIAG_FAILURE_BOUNDARY was produced, so nothing tells the operator " +
			"where observation stopped — which is the whole reason a 401 needs no " +
			"Kubernetes code of its own")
	}
	assertNoTokenLeak(t, got, "not-a-token-this-api-server-issued")
}

// assertNoTokenLeak fails if bearer-token material reaches any stream.
//
// The whole token and a twelve-byte prefix, because a length, a hash or a prefix
// is a derived fact that buys a reader nothing and an attacker something.
func assertNoTokenLeak(t *testing.T, got run, token string) {
	t.Helper()
	combined := got.stdout + got.stderr
	if strings.Contains(combined, token) {
		t.Error("the bearer token appears in the output")
	}
	if len(token) > 12 && strings.Contains(combined, token[:12]) {
		t.Error("a prefix of the bearer token appears in the output")
	}
}
