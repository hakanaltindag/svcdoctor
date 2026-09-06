package client

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// inClusterFixture writes projected ServiceAccount material and points at the
// hermetic server.
//
// The seam exists so that in-cluster mode is testable without a pod, a kubelet or
// a developer machine that happens to have a cluster. Production reads the two
// standard paths and the two variables the kubelet injects; nothing else about
// the mode differs.
func inClusterFixture(t *testing.T, server *apiServer) inClusterSource {
	t.Helper()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "token")
	if err := os.WriteFile(tokenPath, []byte("projected-token\n"), 0o600); err != nil {
		t.Fatalf("writing the projected token: %v", err)
	}
	parsed, err := url.Parse(server.URL())
	if err != nil {
		t.Fatalf("parsing the server URL: %v", err)
	}
	return inClusterSource{
		host:      parsed.Hostname(),
		port:      parsed.Port(),
		tokenPath: tokenPath,
		caPath:    server.caPath,
		// The hermetic server's certificate covers its own loopback address and
		// not the API Service's name. Production always verifies InClusterHost;
		// TestTheInClusterSourceVerifiesTheAPIServiceName is what says so.
		serverName: parsed.Hostname(),
	}
}

// TestInClusterModeReadsItsOwnTokenAndReachesTheAPIServer.
//
// **svcdoctor reads the projected token itself**, exactly as it reads a
// kubeconfig tokenFile, and rest.Config.BearerTokenFile is never set. That
// declines client-go's token-refreshing transport deliberately: a refresh is a
// reread on a schedule svcdoctor does not control, inside a process that runs
// once and exits. One diagnosis needs one token.
func TestInClusterModeReadsItsOwnTokenAndReachesTheAPIServer(t *testing.T) {
	server := newAPIServer(t)
	server.service = selectorService("uid-1")
	server.podPages = []scriptedPage{{}}
	server.slicePages = []scriptedPage{{}}

	target := Target{InCluster: true, Namespace: "payments", ServiceName: "payments-api"}
	connection, err := connectFrom(target, security.Credential{}, inClusterFixture(t, server))
	if err != nil {
		t.Fatalf("connecting in-cluster: %v", err)
	}
	if got := connection.Authority().Mode; got != servicekubernetes.AuthModeInCluster {
		t.Errorf("auth mode is %q, want %q", got, servicekubernetes.AuthModeInCluster)
	}

	result, err := acquireWith(context.Background(), connection, target, DefaultBudgets)
	if err != nil {
		t.Fatalf("acquiring in-cluster: %v", err)
	}
	if !result.Service.OK() {
		t.Fatalf("the Service read failed: %+v", result.Service)
	}
	if got := server.requestCount(); got != 3 {
		t.Errorf("issued %d requests, want 3", got)
	}
}

// TestInClusterModeBindsToTheAPIServiceName.
//
// The logical endpoint is `kubernetes.default.svc:443` — the API Service's own
// fully qualified name, which is true in every cluster. The connection is made to
// whatever KUBERNETES_SERVICE_HOST names, which is that Service's cluster IP.
// Binding the credential to the name while connecting to the address is the same
// logical-endpoint rule every other service in svcdoctor follows.
//
// It is also the identity TLS verifies against, which is stronger than trusting
// whichever SAN happens to cover the cluster IP.
func TestInClusterModeBindsToTheAPIServiceName(t *testing.T) {
	target := Target{InCluster: true, Namespace: "payments", ServiceName: "payments-api"}
	authority, err := Inspect(target, false)
	if err != nil {
		t.Fatalf("inspecting an in-cluster target: %v", err)
	}
	if got := authority.Endpoint.Host(); got != InClusterHost {
		t.Errorf("endpoint host is %q, want %q", got, InClusterHost)
	}
	if got := authority.Endpoint.Port(); got != InClusterPort {
		t.Errorf("endpoint port is %d, want %d", got, InClusterPort)
	}
	if authority.Context != "" {
		t.Errorf("an in-cluster authority names context %q; there is no context there",
			authority.Context)
	}
}

// TestInspectingAnInClusterTargetReadsNothing.
//
// A configuration must be checkable on a laptop. The projected token, the
// projected CA and KUBERNETES_SERVICE_HOST exist only inside a pod, so inspection
// resolves the logical endpoint from the mode itself and touches nothing —
// which is what lets `svcdoctor run --config` validate a file that will run in a
// cluster it is not currently inside.
func TestInspectingAnInClusterTargetReadsNothing(t *testing.T) {
	// Deliberately hostile: variables that would make a naive implementation
	// think it is in a pod, pointing at an address nothing is listening on.
	t.Setenv("KUBERNETES_SERVICE_HOST", "127.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "1")

	authority, err := Inspect(
		Target{InCluster: true, Namespace: "n", ServiceName: "s"}, false)
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if got := authority.Endpoint.Host(); got != InClusterHost {
		t.Errorf("the endpoint came from the environment: %q", got)
	}
}

// TestInClusterModeRefusesASecondIdentity.
//
// A target credential beside the pod's ServiceAccount is two identities, and
// svcdoctor refuses the ambiguity rather than ranking them.
func TestInClusterModeRefusesASecondIdentity(t *testing.T) {
	target := Target{InCluster: true, Namespace: "n", ServiceName: "s"}
	if _, err := Inspect(target, true); err == nil ||
		!strings.Contains(err.Error(), "second identity") {
		t.Fatalf("a target credential was accepted in-cluster: %v", err)
	}

	endpoint, err := security.NewEndpoint(InClusterHost, InClusterPort)
	if err != nil {
		t.Fatalf("building the endpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, "", security.NewSecret("t"))
	if err != nil {
		t.Fatalf("building the credential: %v", err)
	}
	if _, err := Connect(target, credential); err == nil ||
		!strings.Contains(err.Error(), "second identity") {
		t.Fatalf("Connect accepted a target credential in-cluster: %v", err)
	}
}

// TestInClusterModeOutsideAClusterFailsSafely.
//
// Running with `in_cluster: true` on a machine that is not a pod must say so,
// rather than falling back to a kubeconfig or to an anonymous identity.
func TestInClusterModeOutsideAClusterFailsSafely(t *testing.T) {
	target := Target{InCluster: true, Namespace: "n", ServiceName: "s"}
	_, err := connectFrom(target, security.Credential{}, inClusterSource{
		tokenPath: inClusterTokenPath, caPath: inClusterCAPath,
	})
	if err == nil {
		t.Fatal("in-cluster mode succeeded outside a cluster")
	}
	if !strings.Contains(err.Error(), "not running in a Kubernetes pod") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}
}

// TestAnEmptyProjectedTokenIsRefused keeps an empty credential from being sent.
func TestAnEmptyProjectedTokenIsRefused(t *testing.T) {
	server := newAPIServer(t)
	source := inClusterFixture(t, server)
	if err := os.WriteFile(source.tokenPath, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("rewriting the token: %v", err)
	}

	_, err := connectFrom(
		Target{InCluster: true, Namespace: "n", ServiceName: "s"},
		security.Credential{}, source)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("an empty projected token was accepted: %v", err)
	}
	if got := server.requestCount(); got != 0 {
		t.Errorf("the API server received %d requests, want 0", got)
	}
}

// TestATokenIsTrimmedAtItsEndsAndNowhereElse.
//
// A token file written by `kubectl` or by the kubelet's projected volume ends in
// a newline, and sending that byte makes every request fail with a header the
// server rejects. A bearer token is otherwise opaque, so nothing about its
// interior is touched.
func TestATokenIsTrimmedAtItsEndsAndNowhereElse(t *testing.T) {
	for _, test := range []struct{ raw, want string }{
		{"abc\n", "abc"},
		{"  abc  ", "abc"},
		{"\r\nabc\r\n", "abc"},
		{"abc", "abc"},
		{"a b c\n", "a b c"},
		{"   \n\t", ""},
		{"", ""},
	} {
		if got := trimTokenBytes([]byte(test.raw)); got != test.want {
			t.Errorf("trimTokenBytes(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

// TestTheInClusterSourceVerifiesTheAPIServiceName pins what production does.
//
// The end-to-end in-cluster test above has to relax the verified identity so that
// a hermetic certificate is usable at all, which would otherwise leave the real
// behaviour untested. This asserts it directly: the standard projected paths, the
// two injected variables, and the API Service's own name as the verified
// identity.
func TestTheInClusterSourceVerifiesTheAPIServiceName(t *testing.T) {
	source := defaultInClusterSource()
	if source.serverName != InClusterHost {
		t.Errorf("the verified identity is %q, want %q", source.serverName, InClusterHost)
	}
	if source.tokenPath != inClusterTokenPath {
		t.Errorf("the token path is %q, want the standard projected one", source.tokenPath)
	}
	if source.caPath != inClusterCAPath {
		t.Errorf("the CA path is %q, want the standard projected one", source.caPath)
	}

	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	if got := defaultInClusterSource().host; got != "10.96.0.1" {
		t.Errorf("the host is %q; it comes from KUBERNETES_SERVICE_HOST", got)
	}
}

// TestAnIPv6APIServiceAddressIsBracketed keeps a dual-stack cluster working.
func TestAnIPv6APIServiceAddressIsBracketed(t *testing.T) {
	for _, test := range []struct{ host, port, want string }{
		{"10.96.0.1", "443", "10.96.0.1:443"},
		{"fd00::1", "443", "[fd00::1]:443"},
		{"[fd00::1]", "443", "[fd00::1]:443"},
	} {
		if got := joinHostPort(test.host, test.port); got != test.want {
			t.Errorf("joinHostPort(%q, %q) = %q, want %q",
				test.host, test.port, got, test.want)
		}
	}
}
