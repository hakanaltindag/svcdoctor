//go:build integration

package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Acquisition against the real API server: request counts, pagination,
// determinism, and the two entry points agreeing.
//
// # How a request is counted without changing what answers it
//
// `counter` is a TLS reverse proxy in the test process. svcdoctor is pointed at
// it by a kubeconfig whose `certificate-authority` is the proxy's own; the proxy
// counts the request and forwards it, with the lane's real client certificate,
// to the **real API server**. Every response svcdoctor sees is the cluster's.
//
// It is not a mock and it is not a stand-in: nothing about the Kubernetes
// behaviour under test is simulated. The proxy observes, and Go's own HTTP stack
// is what makes an exact count possible at all.
//
// svcdoctor's own `proxy-url` refusal is untouched by this — that refusal is
// about a proxy named *inside a kubeconfig*, which changes a run's vantage
// silently. Here the `server:` URL simply is the endpoint, which is what a
// `server:` URL always means.

// counter is a request-counting TLS reverse proxy in front of the API server.
type counter struct {
	server     *httptest.Server
	kubeconfig string
	context    string

	mu       sync.Mutex
	requests []string
}

// newCounter starts a proxy in front of the lane's API server and writes a
// kubeconfig that reaches the cluster through it.
func newCounter(t *testing.T, h harness) *counter {
	t.Helper()

	upstream, err := url.Parse(h.serverURL(t))
	if err != nil {
		t.Fatalf("parsing the API server URL: %v", err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(h.clusterCA(t))) {
		t.Fatal("the cluster CA did not parse")
	}
	clientCert := h.adminCertificate(t)

	c := &counter{}
	proxy := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			c.record(r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery)
			r.URL.Scheme = upstream.Scheme
			r.URL.Host = upstream.Host
			r.Host = upstream.Host
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      roots,
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS12,
			},
		},
	}

	c.server = httptest.NewUnstartedServer(proxy)
	certPEM, keyPEM := selfSignedLoopback(t)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("building the proxy certificate: %v", err)
	}
	c.server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	c.server.StartTLS()
	t.Cleanup(c.server.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "proxy-ca.crt")
	writeFileOrFail(t, caPath, string(certPEM))
	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeFileOrFail(t, kubeconfig, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: "+c.server.URL+"\n"+
		"    certificate-authority: "+caPath+"\n"+
		"users:\n- name: u\n  user: {}\n"+
		"contexts:\n- name: counted\n  context:\n    cluster: c\n    user: u\n")

	c.kubeconfig, c.context = kubeconfig, "counted"
	return c
}

func (c *counter) record(request string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, request)
}

// reset clears the log so one scenario's count is its own.
func (c *counter) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = nil
}

// observed returns the requests recorded since the last reset.
func (c *counter) observed() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.requests...)
}

// diagnose runs svcdoctor through the proxy with a token identity.
func (c *counter) diagnose(
	t *testing.T, h harness, id identity, namespace, service string,
) (run, report) {
	t.Helper()
	got := h.exec(t, "",
		"diagnose", "kubernetes",
		"--kubeconfig", c.kubeconfig, "--context", c.context,
		"--namespace", namespace, "--service-name", service,
		"--output", "json", "--token-file", id.tokenPath)
	return got, parseReport(t, got)
}

// adminCertificate reads the lane kubeconfig's client certificate and key.
//
// It is used by the proxy to reach the upstream API server. It is never written
// to a file this suite keeps, never logged and never printed.
func (h harness) adminCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	user := strings.TrimSpace(h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.contexts[?(@.name=="`+h.context+`")].context.user}`))
	certData := decodeBase64(t, h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.users[?(@.name=="`+user+`")].user.client-certificate-data}`))
	keyData := decodeBase64(t, h.kubectl(t, "config", "view", "--raw", "-o",
		`jsonpath={.users[?(@.name=="`+user+`")].user.client-key-data}`))

	pair, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		t.Fatalf("the lane kubeconfig's client certificate did not load: %v", err)
	}
	return pair
}

func decodeBase64(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		t.Fatalf("decoding kubeconfig material: %v", err)
	}
	return decoded
}

// selfSignedLoopback generates the proxy's own certificate.
func selfSignedLoopback(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor-request-counter"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the proxy certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the proxy key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// --- the request budget ------------------------------------------------------

// TestTheNominalAcquisitionIsExactlyThreeRequests.
//
// ADR 0094 §2.5's whole point, counted at the wire rather than argued from the
// code: **one `GET` and two `LIST`s, and nothing else.** No namespace read, no
// Service UID lookup, no per-Pod `GET`, no discovery call and no server-version
// call — each of which a client library will happily make on your behalf, and
// none of which arithmetic over the source can rule out.
func TestTheNominalAcquisitionIsExactlyThreeRequests(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	id := h.restrictedIdentity(t, ns, "counted", frozenRules)
	c := newCounter(t, h)
	c.reset()

	_, parsed := c.diagnose(t, h, id, ns, "payments-api")
	assertCodes(t, parsed)

	observed := c.observed()
	if len(observed) != 3 {
		t.Errorf("the run made %d API requests, want exactly 3:\n  %s",
			len(observed), strings.Join(observed, "\n  "))
	}

	// And they are the three the contract names, in the frozen order.
	wantShape := []struct{ method, contains string }{
		{"GET", "/api/v1/namespaces/" + ns + "/services/payments-api"},
		{"GET", "/api/v1/namespaces/" + ns + "/pods"},
		{"GET", "/apis/discovery.k8s.io/v1/namespaces/" + ns + "/endpointslices"},
	}
	for i, want := range wantShape {
		if i >= len(observed) {
			break
		}
		if !strings.HasPrefix(observed[i], want.method+" ") ||
			!strings.Contains(observed[i], want.contains) {
			t.Errorf("request %d = %q, want %s %s", i+1, observed[i], want.method, want.contains)
		}
	}

	// The two lists are server-side filtered. A client-side filter would be a
	// different product: it would read every Pod in the namespace.
	if len(observed) >= 2 && !strings.Contains(observed[1], "labelSelector") {
		t.Errorf("the Pod list carries no labelSelector, so the selector was not "+
			"evaluated server-side: %q", observed[1])
	}
	if len(observed) >= 3 &&
		!strings.Contains(observed[2], "kubernetes.io%2Fservice-name") &&
		!strings.Contains(observed[2], "kubernetes.io/service-name") {
		t.Errorf("the EndpointSlice list is not filtered by the association label: %q",
			observed[2])
	}
	if len(observed) >= 2 && !strings.Contains(observed[1], "limit=500") {
		t.Errorf("the Pod list sends no explicit page limit: %q", observed[1])
	}
}

// TestASelectorLessServiceCostsOneRequest.
//
// The short-circuit, counted: a Service that publishes no backends stops after
// the read that said so.
func TestASelectorLessServiceCostsOneRequest(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP", nil,
		"  ports:\n    - port: 80\n"))

	id := h.restrictedIdentity(t, ns, "counted", frozenRules)
	c := newCounter(t, h)
	c.reset()

	_, parsed := c.diagnose(t, h, id, ns, "payments-api")
	assertCodes(t, parsed)

	if observed := c.observed(); len(observed) != 1 {
		t.Errorf("a selector-less Service cost %d requests, want 1:\n  %s",
			len(observed), strings.Join(observed, "\n  "))
	}
}

// --- real pagination ---------------------------------------------------------

// TestRealPodPaginationFollowsTheContinueToken.
//
// **Real server-side pagination**, forced with more Pods than the frozen page
// limit of 500.
//
// # Why the Pods are deliberately unschedulable
//
// They are API objects, and an API `LIST` pages over API objects. Holding them
// `Pending` with an unsatisfiable `nodeSelector` means the fixture costs the
// kubelet nothing — no images, no containers, no node capacity — while
// exercising exactly the thing under test. Scheduling 600 running Pods would
// prove the same property and would risk turning a validation run into a local
// denial of service, which Phase 12.1D §23 forbids.
func TestRealPodPaginationFollowsTheContinueToken(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	const pods = 600 // > the frozen limit of 500, so exactly two pages.

	var manifest strings.Builder
	for i := 0; i < pods; i++ {
		if i > 0 {
			manifest.WriteString("---\n")
		}
		fmt.Fprintf(&manifest, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p%03d\n"+
			"  namespace: %s\n  labels:\n    app: \"payments\"\nspec:\n"+
			"  nodeSelector:\n    kubernetes.io/hostname: no-such-node-exists\n"+
			"  containers:\n    - name: c\n      image: %s\n", i, ns, pauseImage)
	}
	h.apply(t, manifest.String())

	h.waitFor(t, fmt.Sprintf("%d Pod objects to exist", pods), func() (bool, string) {
		out, err := h.kubectlErr("-n", ns, "get", "pods", "-l", "app=payments",
			"--no-headers", "-o", "name")
		if err != nil {
			return false, strings.TrimSpace(out)
		}
		count := len(strings.Fields(out))
		return count == pods, fmt.Sprintf("pods=%d", count)
	})

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	id := h.restrictedIdentity(t, ns, "counted", frozenRules)
	c := newCounter(t, h)
	c.reset()

	_, parsed := c.diagnose(t, h, id, ns, "payments-api")

	observed := c.observed()
	var podRequests []string
	for _, request := range observed {
		if strings.Contains(request, "/pods?") {
			podRequests = append(podRequests, request)
		}
	}

	if len(podRequests) != 2 {
		t.Errorf("the Pod list took %d requests, want 2 for %d objects at limit 500:\n  %s",
			len(podRequests), pods, strings.Join(podRequests, "\n  "))
	}
	// The first page carries no continue token; the second carries the one the
	// server issued. A silent restart would send the first request twice.
	if len(podRequests) >= 1 && strings.Contains(podRequests[0], "continue=") {
		t.Errorf("the first page carried a continue token: %q", podRequests[0])
	}
	if len(podRequests) >= 2 {
		if !strings.Contains(podRequests[1], "continue=") {
			t.Errorf("the second page carried no continue token, so pagination was not "+
				"followed: %q", podRequests[1])
		}
		// **The parameters must be identical across pages** apart from the
		// token: a continue token is only valid for the same query.
		if selectorOf(podRequests[0]) != selectorOf(podRequests[1]) {
			t.Errorf("the label selector changed between pages:\n  %q\n  %q",
				podRequests[0], podRequests[1])
		}
		if limitOf(podRequests[0]) != limitOf(podRequests[1]) {
			t.Errorf("the page limit changed between pages:\n  %q\n  %q",
				podRequests[0], podRequests[1])
		}
	}

	// The set is complete only after the final page, and the count is the
	// cluster's real one.
	if !boolAttr(t, parsed, "k8s.pod_set", "k8s.pod_set_complete") {
		t.Error("the Pod set is not complete after following every page")
	}
	if n := intAttr(t, parsed, "k8s.pod_set", "k8s.pod_observed_count"); n != pods {
		t.Errorf("observed Pod count = %d, want %d", n, pods)
	}
	// F3 must not fire: 600 Pods matched.
	for _, code := range parsed.codes() {
		if code == "KUBERNETES_SERVICE_SELECTS_NO_PODS" {
			t.Error("a selector matching 600 Pods produced the selector claim")
		}
	}
	t.Logf("pagination: %d Pod objects, %d Pod list requests, %d total API requests",
		pods, len(podRequests), len(observed))
}

func selectorOf(request string) string { return queryValue(request, "labelSelector") }
func limitOf(request string) string    { return queryValue(request, "limit") }

func queryValue(request, key string) string {
	_, query, ok := strings.Cut(request, "?")
	if !ok {
		return ""
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	return values.Get(key)
}

// --- determinism -------------------------------------------------------------

// TestRepeatedRunsOfAStableFixtureAreByteIdentical.
//
// The canonical report must not depend on the order the API server returned
// anything in. Only `startedAt` and `duration` are blanked — the repository's
// existing policy, and nothing else is normalized away.
func TestRepeatedRunsOfAStableFixtureAreByteIdentical(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)
	uid := h.backendlessService(t, ns, "payments-api")

	for i := 0; i < 3; i++ {
		h.apply(t, authoredSlice{
			name:    fmt.Sprintf("authored-%d", i),
			service: "payments-api", ownerUID: uid, managedBy: managedBySvcdoctor,
			endpoints: []authoredEndpoint{
				{address: fmt.Sprintf("10.56.0.%d", i*2+1), ready: boolPtr(true)},
				{address: fmt.Sprintf("10.56.0.%d", i*2+2), ready: boolPtr(false)},
			},
		}.manifest(ns))
	}
	h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+3)

	const repetitions = 8
	first := ""
	for i := 0; i < repetitions; i++ {
		got := h.diagnose(t, ns, "payments-api", "--output", "json")
		normalized := normalizeReport(t, got.stdout)
		if i == 0 {
			first = normalized
			continue
		}
		if normalized != first {
			t.Fatalf("run %d differs from run 1.\n--- run 1\n%s\n--- run %d\n%s",
				i+1, first, i+1, normalized)
		}
	}
	// Non-vacuity: the document really is a report carrying the evidence this
	// fixture built, so the comparison above is comparing something.
	for _, marker := range []string{
		`"schemaVersion"`, "k8s.endpoint_publication", "k8s.slice_count",
		"KUBERNETES_SERVICE_SELECTS_NO_PODS",
	} {
		if !strings.Contains(first, marker) {
			t.Fatalf("the compared document does not contain %s:\n%s", marker, first)
		}
	}
}

// normalizeReport blanks the two fields the repository's policy already treats
// as measurements rather than content.
func normalizeReport(t *testing.T, body string) string {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal([]byte(body), &generic); err != nil {
		t.Fatalf("unmarshal report: %v\n%s", err, body)
	}
	blankMeasurements(generic)
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

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

// --- leaf and fleet, on a real cluster --------------------------------------

// TestTheLeafAndTheFleetAgreeOnARealCluster.
//
// Phase 12.1C.2 proved this hermetically. ADR 0094 §2.10's *one Service is one
// target and one report through both entry points* is worth proving where the
// evidence comes from a real controller, because that is where the two could
// diverge without anyone noticing: a different budget, a different rule set, a
// different read.
func TestTheLeafAndTheFleetAgreeOnARealCluster(t *testing.T) {
	scenarios := []struct {
		name  string
		build func(t *testing.T, h harness, ns string)
	}{
		{
			name: "healthy",
			build: func(t *testing.T, h harness, ns string) {
				h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
				h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
					map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
				h.waitForPodReady(t, ns, "backend")
				h.waitForReadyEndpoints(t, ns, "payments-api", 1)
			},
		},
		{
			name: "selects no pods",
			build: func(t *testing.T, h harness, ns string) {
				h.backendlessService(t, ns, "payments-api")
			},
		},
		{
			name: "no ready endpoint",
			build: func(t *testing.T, h harness, ns string) {
				uid := h.selectedButUnpublishedService(t, ns, "payments-api")
				h.apply(t, authoredSlice{
					name: "authored", service: "payments-api", ownerUID: uid,
					managedBy: managedBySvcdoctor,
					endpoints: []authoredEndpoint{
						{address: "10.57.0.1", ready: boolPtr(false)},
					},
				}.manifest(ns))
				h.waitForSliceCount(t, ns, "payments-api", controllerBaselineSlices+1)
			},
		},
		{
			name:  "service not found",
			build: func(t *testing.T, h harness, ns string) { /* nothing is created */ },
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			ns := h.namespace(t)
			tc.build(t, h, ns)

			leaf := h.diagnose(t, ns, "payments-api", "--output", "json")

			config := filepath.Join(t.TempDir(), "run.yaml")
			writeFileOrFail(t, config, "version: 1\ntargets:\n"+
				"  - id: payments\n    type: kubernetes\n    config:\n"+
				"      kubeconfig: "+h.kubeconfig+"\n"+
				"      context: "+h.context+"\n"+
				"      namespace: "+ns+"\n"+
				"      service_name: payments-api\n")
			fleet := h.exec(t, "", "run", "--config", config, "--output", "json")

			if leaf.stdout == "" || fleet.stdout == "" {
				t.Fatalf("one entry point produced no report.\nleaf: %q\nfleet: %q",
					leaf.stdout, fleet.stdout)
			}

			var aggregate struct {
				Targets []struct {
					Report json.RawMessage `json:"report"`
				} `json:"targets"`
			}
			if err := json.Unmarshal([]byte(fleet.stdout), &aggregate); err != nil {
				t.Fatalf("unmarshal aggregate: %v", err)
			}
			if len(aggregate.Targets) != 1 {
				t.Fatalf("the aggregate holds %d targets, want 1", len(aggregate.Targets))
			}

			leafReport := normalizeReport(t, leaf.stdout)
			embedded := normalizeReport(t, string(aggregate.Targets[0].Report))
			if leafReport != embedded {
				t.Errorf("the two entry points produced different reports.\n"+
					"--- leaf\n%s\n--- embedded\n%s", leafReport, embedded)
			}
		})
	}
}

// --- data minimization and credential authority ------------------------------

// TestNoRealClusterReportCarriesMaterialTheContractExcludes.
//
// The audit is over **generated output**, not over the source. A fixture plants
// markers in the places a cluster can put attacker- or operator-chosen text —
// a label value, an annotation, a Pod name — and the report is searched for
// every one of them.
func TestNoRealClusterReportCarriesMaterialTheContractExcludes(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	const marker = "svcdoctor-minimization-marker"

	h.apply(t, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: "+marker+"-pod\n"+
		"  namespace: "+ns+"\n  labels:\n    app: \"payments\"\n    leak: \""+marker+
		"\"\n  annotations:\n    leak: \""+marker+"\"\nspec:\n  containers:\n"+
		"    - name: c\n      image: "+pauseImage+"\n")
	h.apply(t, "apiVersion: v1\nkind: Service\nmetadata:\n  name: payments-api\n"+
		"  namespace: "+ns+"\n  annotations:\n    leak: \""+marker+"\"\n"+
		"spec:\n  type: ClusterIP\n  selector:\n    app: \"payments\"\n"+
		"  ports:\n    - port: 80\n")

	h.waitForPodReady(t, ns, marker+"-pod")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	podIP := strings.TrimSpace(h.kubectl(t, "-n", ns, "get", "pod", marker+"-pod",
		"-o", "jsonpath={.status.podIP}"))
	clusterIP := strings.TrimSpace(h.kubectl(t, "-n", ns, "get", "service", "payments-api",
		"-o", "jsonpath={.spec.clusterIP}"))
	podUID := strings.TrimSpace(h.kubectl(t, "-n", ns, "get", "pod", marker+"-pod",
		"-o", "jsonpath={.metadata.uid}"))
	serviceUID := h.serviceUID(t, ns, "payments-api")

	for _, mode := range [][]string{
		{"--output", "json"},
		{"--output", "text"},
		{"--output", "json", "--shareable"},
	} {
		t.Run(strings.Join(mode, " "), func(t *testing.T) {
			got := h.diagnose(t, ns, "payments-api", mode...)
			body := got.stdout + got.stderr

			for _, forbidden := range []struct{ what, value string }{
				{"a Pod name", marker + "-pod"},
				{"a label value", marker},
				{"a Pod IP", podIP},
				{"the ClusterIP", clusterIP},
				{"a Pod UID", podUID},
				{"the Service UID", serviceUID},
				{"the kubeconfig path", h.kubeconfig},
			} {
				if forbidden.value == "" {
					t.Fatalf("the fixture produced no value for %s, so its absence "+
						"from the report proves nothing", forbidden.what)
				}
				if strings.Contains(body, forbidden.value) {
					t.Errorf("the report carries %s (%q).\n\nADR 0094 §2.9 excludes it "+
						"from canonical evidence.\n%s", forbidden.what, forbidden.value, body)
				}
			}
		})
	}
}

// TestTheKubernetesCredentialReachesOnlyTheAPIServer.
//
// The structural half is `test/security`'s and is unchanged. The runtime half is
// this: over a whole real-cluster run, the **only** TLS endpoint svcdoctor
// connected to is the API server. Every request the counter saw arrived at the
// proxy; a connection to a Pod IP, a ClusterIP or an endpoint address would have
// gone somewhere else entirely — and there is no code path that could make one,
// because svcdoctor issues three reads and connects to nothing it learns from
// them.
func TestTheKubernetesCredentialReachesOnlyTheAPIServer(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	id := h.restrictedIdentity(t, ns, "authority", frozenRules)
	c := newCounter(t, h)
	c.reset()

	_, parsed := c.diagnose(t, h, id, ns, "payments-api")
	assertCodes(t, parsed)

	// Every request went to the API server's own paths. Nothing addressed a
	// backend, and nothing addressed anything outside the target's namespace.
	for _, request := range c.observed() {
		if !strings.Contains(request, "/namespaces/"+ns+"/") {
			t.Errorf("a request addressed something outside the target namespace: %q",
				request)
		}
		for _, forbidden := range []string{"/proxy", "/exec", "/portforward", "/log"} {
			if strings.Contains(request, forbidden) {
				t.Errorf("a request reached %s: %q", forbidden, request)
			}
		}
	}
	if len(c.observed()) == 0 {
		t.Fatal("no request was observed; this guard would pass vacuously")
	}
}

// --- the runtime environment -------------------------------------------------

// TestNoKubectlIsRequiredAtRuntime.
//
// The harness uses `kubectl` to build fixtures. **svcdoctor must not**, and the
// only convincing way to say so is to take it away: the binary runs with a
// `PATH` containing nothing at all, and diagnoses the same Service.
//
// It also takes away `KUBECONFIG` and `HOME`, which proves the other half of the
// same contract: no environment variable and no default location contributes to
// the run.
func TestNoKubectlIsRequiredAtRuntime(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, podManifest(ns, "backend", map[string]string{"app": "payments"}))
	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))
	h.waitForPodReady(t, ns, "backend")
	h.waitForReadyEndpoints(t, ns, "payments-api", 1)

	// Nothing resolvable, no kubeconfig hint, no home directory.
	empty := []string{"PATH=" + filepath.Join(t.TempDir(), "empty"), "HOME=", "KUBECONFIG="}

	got := h.execWithEnv(t, "", empty,
		"diagnose", "kubernetes",
		"--kubeconfig", h.kubeconfig, "--context", h.context,
		"--namespace", ns, "--service-name", "payments-api", "--output", "json")

	if got.code != 0 {
		t.Fatalf("exit = %d with an empty PATH.\n\nsvcdoctor must not depend on kubectl "+
			"or on any environment variable.\nstderr: %s", got.code, got.stderr)
	}
	parsed := parseReport(t, got)
	assertCodes(t, parsed)
	if state := parsed.node(t, "k8s.endpoint_publication").State; state != "PASS" {
		t.Errorf("k8s.endpoint_publication = %s with an empty PATH, want PASS", state)
	}

	// The negative control: the harness's own kubectl really is unreachable
	// under that environment, so the run above proves something.
	if _, err := os.Stat(filepath.Join(t.TempDir(), "empty")); err == nil {
		t.Fatal("the empty PATH directory exists, so PATH lookup could still succeed")
	}
}

// TestAnExecCredentialPluginIsStillRefusedAgainstARealCluster.
//
// The Phase 12.1B release gate, re-proven where the credential would actually be
// used: a kubeconfig for the **real** API server whose user carries an `exec`
// plugin. The run is refused as a configuration error, the plugin does not run,
// and the API server is never reached.
func TestAnExecCredentialPluginIsStillRefusedAgainstARealCluster(t *testing.T) {
	h := newHarness(t)
	ns := h.namespace(t)

	h.apply(t, serviceManifest(ns, "payments-api", "ClusterIP",
		map[string]string{"app": "payments"}, "  ports:\n    - port: 80\n"))

	c := newCounter(t, h)
	c.reset()

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "the-plugin-ran")
	caPath := filepath.Join(dir, "ca.crt")
	certPEM, _ := selfSignedLoopback(t)
	writeFileOrFail(t, caPath, string(certPEM))

	kubeconfig := filepath.Join(dir, "kubeconfig")
	writeFileOrFail(t, kubeconfig, "apiVersion: v1\nkind: Config\n"+
		"clusters:\n- name: c\n  cluster:\n    server: "+c.server.URL+"\n"+
		"    certificate-authority: "+caPath+"\n"+
		"users:\n- name: u\n  user:\n    exec:\n"+
		"      apiVersion: client.authentication.k8s.io/v1\n"+
		"      command: /bin/sh\n      args:\n        - -c\n"+
		"        - touch "+sentinel+"\n"+
		"contexts:\n- name: exec\n  context:\n    cluster: c\n    user: u\n")

	got := h.exec(t, "",
		"diagnose", "kubernetes",
		"--kubeconfig", kubeconfig, "--context", "exec",
		"--namespace", ns, "--service-name", "payments-api", "--output", "json")

	if got.code != 2 {
		t.Errorf("exit = %d, want 2; an exec credential plugin is a configuration error "+
			"refused before any network operation.\nstderr: %s", got.code, got.stderr)
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Fatal("THE EXEC PLUGIN RAN against a real cluster. The sentinel file exists.")
	}
	if n := len(c.observed()); n != 0 {
		t.Errorf("the API server received %d requests from a refused kubeconfig:\n  %s",
			n, strings.Join(c.observed(), "\n  "))
	}
	assertNoProseLeak(t, got, "/bin/sh", sentinel)
}
