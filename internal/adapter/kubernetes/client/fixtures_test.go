package client

import (
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
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// The hermetic Kubernetes API server every acquisition test runs against.
//
// # Why a real HTTP server and not a fake clientset
//
// ADR 0094 section 2.11 requires it, and the reason is that a fake clientset
// bypasses the transport, the pagination and the status codes — which is most of
// what needs proving. Everything this phase is about lives below the typed
// client's surface: whether a `limit` was actually sent, whether a continue token
// was propagated byte for byte, whether a 410 ends an enumeration, whether client
// construction quietly performs a discovery round trip, and whether a refused
// kubeconfig reaches the network at all. A fake would answer none of those.
//
// It serves **TLS**, deliberately. svcdoctor refuses a plaintext API server URL
// because every supported mode ends with a credential on the wire, so a test
// running against http:// would be exercising a path production cannot take.
// The server's own certificate is written out as the kubeconfig's certificate
// authority, which means every test also verifies a real chain.

// apiServer is a scripted, request-counting Kubernetes API server.
type apiServer struct {
	t    *testing.T
	http *httptest.Server

	mu       sync.Mutex
	requests []recordedRequest

	// service is returned by the Service GET when serviceStatus is zero.
	service *corev1.Service

	// serviceStatus, when non-zero, is returned instead of the Service.
	serviceStatus *metav1.Status

	// podPages and slicePages are consumed in order, one per request.
	podPages   []scriptedPage
	slicePages []scriptedPage

	// caPath is the file holding the server's own certificate.
	caPath string

	// beforeRespond runs inside the handler, with the 1-based request number,
	// before the response is written.
	//
	// It is how a cancellation test becomes deterministic: waiting for a request
	// count from another goroutine races the whole acquisition, which finishes in
	// under a millisecond against a loopback server. Cancelling *from inside the
	// handler* happens at a known point in the sequence, every time.
	beforeRespond func(request int)
}

// scriptedPage is one list response.
//
// Either a page of items with an optional continue token, or a status to fail
// with. Scripting the pages rather than computing them is what lets a test say
// "the fourth page returns 410" without inventing a cluster that would do that.
type scriptedPage struct {
	pods          []corev1.Pod
	slices        []discoveryv1.EndpointSlice
	continueToken string
	status        *metav1.Status
}

// recordedRequest is everything a test may assert about one round trip.
type recordedRequest struct {
	method string
	path   string
	query  url.Values
}

// newAPIServer starts a TLS API server and writes its certificate out.
func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	server := &apiServer{t: t}
	server.http = httptest.NewTLSServer(http.HandlerFunc(server.handle))
	t.Cleanup(server.http.Close)

	certificate := server.http.Certificate()
	pemBytes := pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	server.caPath = filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(server.caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("writing the API server certificate: %v", err)
	}
	return server
}

// URL is the API server's address.
func (s *apiServer) URL() string { return s.http.URL }

// requestCount is how many round trips reached the server.
//
// It counts **every** request, including any the library might make on its own —
// which is the point: a discovery call svcdoctor did not ask for shows up here
// and nowhere else.
func (s *apiServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func (s *apiServer) recorded() []recordedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordedRequest, len(s.requests))
	copy(out, s.requests)
	return out
}

func (s *apiServer) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, recordedRequest{
		method: r.Method, path: r.URL.Path, query: r.URL.Query(),
	})
	index := len(s.requests)
	hook := s.beforeRespond
	s.mu.Unlock()

	if hook != nil {
		hook(index)
	}

	switch {
	case isServicePath(r.URL.Path):
		s.serveService(w)
	case isPodPath(r.URL.Path):
		s.servePods(w)
	case isSlicePath(r.URL.Path):
		s.serveSlices(w)
	default:
		// Anything else is a request svcdoctor did not intend to make. Answering
		// 404 rather than something usable keeps an accidental discovery call
		// visible in the assertions rather than silently satisfied.
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, "no such path")
	}
}

func (s *apiServer) serveService(w http.ResponseWriter) {
	if s.serviceStatus != nil {
		writeStatus(w, s.serviceStatus.Code, s.serviceStatus.Reason,
			s.serviceStatus.Message)
		return
	}
	service := s.service
	if service == nil {
		writeStatus(w, http.StatusNotFound, metav1.StatusReasonNotFound, "services \"x\" not found")
		return
	}
	service.TypeMeta = metav1.TypeMeta{APIVersion: "v1", Kind: "Service"}
	writeJSON(w, http.StatusOK, service)
}

func (s *apiServer) servePods(w http.ResponseWriter) {
	page, ok := s.nextPage(&s.podPages)
	if !ok {
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError,
			"the test scripted no further Pod page")
		return
	}
	if page.status != nil {
		writeStatus(w, page.status.Code, page.status.Reason, page.status.Message)
		return
	}
	writeJSON(w, http.StatusOK, &corev1.PodList{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"},
		ListMeta: metav1.ListMeta{Continue: page.continueToken},
		Items:    page.pods,
	})
}

func (s *apiServer) serveSlices(w http.ResponseWriter) {
	page, ok := s.nextPage(&s.slicePages)
	if !ok {
		writeStatus(w, http.StatusInternalServerError, metav1.StatusReasonInternalError,
			"the test scripted no further EndpointSlice page")
		return
	}
	if page.status != nil {
		writeStatus(w, page.status.Code, page.status.Reason, page.status.Message)
		return
	}
	writeJSON(w, http.StatusOK, &discoveryv1.EndpointSliceList{
		TypeMeta: metav1.TypeMeta{APIVersion: "discovery.k8s.io/v1", Kind: "EndpointSliceList"},
		ListMeta: metav1.ListMeta{Continue: page.continueToken},
		Items:    page.slices,
	})
}

func (s *apiServer) nextPage(pages *[]scriptedPage) (scriptedPage, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(*pages) == 0 {
		return scriptedPage{}, false
	}
	page := (*pages)[0]
	*pages = (*pages)[1:]
	return page, true
}

func isServicePath(path string) bool {
	return len(path) > len("/api/v1/namespaces/") &&
		path[:len("/api/v1/namespaces/")] == "/api/v1/namespaces/" &&
		containsSegment(path, "services")
}

func isPodPath(path string) bool {
	return containsSegment(path, "pods")
}

func isSlicePath(path string) bool {
	return containsSegment(path, "endpointslices")
}

func containsSegment(path, segment string) bool {
	for _, part := range splitPath(path) {
		if part == segment {
			return true
		}
	}
	return false
}

func splitPath(path string) []string {
	var out []string
	current := ""
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if current != "" {
				out = append(out, current)
			}
			current = ""
			continue
		}
		current += string(path[i])
	}
	if current != "" {
		out = append(out, current)
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// writeStatus answers with a metav1.Status, which is how a real API server
// reports every error.
//
// The message is written out on purpose, and several tests put hostile bytes in
// it: the contract is that svcdoctor never reads it, so a test that could not
// send one would prove nothing.
func writeStatus(w http.ResponseWriter, code int32, reason metav1.StatusReason, message string) {
	writeJSON(w, int(code), &metav1.Status{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
		Status:   metav1.StatusFailure,
		Code:     code,
		Reason:   reason,
		Message:  message,
	})
}

// kubeconfig builds one kubeconfig document.
//
// It is written as text rather than marshalled from clientcmdapi, because the
// thing under test is svcdoctor's reading of a file an operator wrote, and a
// round trip through the library's own types would test the library.
type kubeconfig struct {
	server         string
	caPath         string
	caData         string
	contextName    string
	userName       string
	userBlock      string
	extraContexts  string
	currentContext string
}

func (k kubeconfig) write(t *testing.T) string {
	t.Helper()
	contextName := k.contextName
	if contextName == "" {
		contextName = "prod"
	}
	userName := k.userName
	if userName == "" {
		userName = "operator"
	}
	authority := "    certificate-authority: " + k.caPath + "\n"
	if k.caData != "" {
		authority = "    certificate-authority-data: " + k.caData + "\n"
	}
	userBlock := k.userBlock
	if userBlock == "" {
		userBlock = "    token: fixture-bearer-token\n"
	}

	document := "apiVersion: v1\n" +
		"kind: Config\n" +
		"clusters:\n" +
		"- name: cluster\n" +
		"  cluster:\n" +
		"    server: " + k.server + "\n" +
		authority +
		"users:\n" +
		"- name: " + userName + "\n" +
		"  user:\n" +
		userBlock +
		"contexts:\n" +
		"- name: " + contextName + "\n" +
		"  context:\n" +
		"    cluster: cluster\n" +
		"    user: " + userName + "\n" +
		k.extraContexts +
		"current-context: " + k.currentContext + "\n"

	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the kubeconfig: %v", err)
	}
	return path
}

// tokenKubeconfig is the shorthand every acquisition test uses.
func tokenKubeconfig(t *testing.T, server *apiServer) string {
	t.Helper()
	return kubeconfig{server: server.URL(), caPath: server.caPath}.write(t)
}

// targetFor is the shorthand target every acquisition test uses.
func targetFor(path string) Target {
	return Target{
		Kubeconfig:  path,
		Context:     "prod",
		Namespace:   "payments",
		ServiceName: "payments-api",
	}
}

// selectorService is a ClusterIP Service with a two-key selector.
func selectorService(uid string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "payments", Name: "payments-api", UID: types.UID(uid),
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeClusterIP,
			ClusterIP: "10.0.0.1",
			Selector:  map[string]string{"app": "payments", "tier": "api"},
		},
	}
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// clientCertificate mints a throwaway client certificate and key.
//
// Self-signed and never verified by the fixture server, which is correct for what
// it proves: that svcdoctor resolves a client key as a secret, binds it to the
// API endpoint, reveals it exactly once and hands it to the transport. Whether a
// real API server would accept it is a real-cluster question and belongs to
// Phase 12.1D.
func clientCertificate(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "svcdoctor-fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a client certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling a client key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func mustHostPort(t *testing.T, raw string) (string, uint16) {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	port, err := serverPort(parsed)
	if err != nil {
		t.Fatalf("port of %q: %v", raw, err)
	}
	return parsed.Hostname(), port
}
