package kubernetes_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	fleetkafka "github.com/hakanaltindag/svcdoctor/internal/fleet/services/kafka"
	fleetkubernetes "github.com/hakanaltindag/svcdoctor/internal/fleet/services/kubernetes"
	fleetpostgres "github.com/hakanaltindag/svcdoctor/internal/fleet/services/postgres"
	fleetrabbitmq "github.com/hakanaltindag/svcdoctor/internal/fleet/services/rabbitmq"
	fleetredis "github.com/hakanaltindag/svcdoctor/internal/fleet/services/redis"
)

// The Kubernetes fleet target, decoded through the real loader.
//
// Every test here goes through config.Load with the production registry, because
// what is under test is a configuration file an operator writes — not a struct
// somebody constructed. A Kubernetes target is also the first whose validity
// depends on a second file, so the fixture writes a real kubeconfig.

func registry(t *testing.T) *config.Registry {
	t.Helper()
	// The production set, so a Kubernetes target is decoded exactly as
	// `svcdoctor run --config` decodes one — including the messages a
	// misspelled `type:` produces.
	r, err := config.NewRegistry(
		fleetpostgres.Factory{}, fleetkafka.Factory{}, fleetredis.Factory{},
		fleetrabbitmq.Factory{}, fleetkubernetes.Factory{},
	)
	if err != nil {
		t.Fatalf("building the registry: %v", err)
	}
	return r
}

// writeKubeconfig produces a valid kubeconfig naming an https server.
func writeKubeconfig(t *testing.T, server, userBlock string) string {
	t.Helper()
	if userBlock == "" {
		userBlock = "    token: fixture-token\n"
	}
	document := "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n    server: " + server + "\n" +
		"users:\n- name: u\n  user:\n" + userBlock +
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n" +
		"current-context: prod\n"
	path := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the kubeconfig: %v", err)
	}
	return path
}

func load(t *testing.T, document string) (config.Config, error) {
	t.Helper()
	return config.Load([]byte(document), "test.yaml", registry(t))
}

func kubernetesDocument(kubeconfig, extra string) string {
	return "version: 1\n" +
		"targets:\n" +
		"  - id: payments\n" +
		"    type: kubernetes\n" +
		"    config:\n" +
		"      kubeconfig: " + kubeconfig + "\n" +
		"      context: prod\n" +
		"      namespace: payments\n" +
		"      service_name: payments-api\n" +
		extra
}

// TestAKubernetesTargetNamesNoHostAndDerivesItsEndpoint.
//
// # The shape, and why it is this one
//
// A Kubernetes target is asked about a **Service object**, not about a host an
// operator typed. The API server is derived from the authority the target already
// names — the kubeconfig context's `server` URL — so writing a host would be a
// field nobody reads. ADR 0060's discipline is that an inert input is refused
// rather than accepted, because an operator who wrote it believes it did
// something.
//
// The generic contract is satisfied rather than relaxed: the derived endpoint
// goes through exactly the checks a written host does, and nothing downstream can
// tell the two apart.
func TestAKubernetesTargetNamesNoHostAndDerivesItsEndpoint(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "")

	cfg, err := load(t, kubernetesDocument(kubeconfig, ""))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if len(cfg.Targets) != 1 {
		t.Fatalf("loaded %d targets, want 1", len(cfg.Targets))
	}
	target := cfg.Targets[0]

	if got, want := target.Host, "api.cluster.internal"; got != want {
		t.Errorf("host is %q, want %q — derived from the kubeconfig cluster", got, want)
	}
	if got, want := target.Port, uint16(6443); got != want {
		t.Errorf("port is %d, want %d", got, want)
	}
	if got := target.Service; got != fleetkubernetes.Kind {
		t.Errorf("service is %q, want %q", got, fleetkubernetes.Kind)
	}

	// A server URL with no port takes the scheme's own default, which is the
	// number the factory declares.
	cfg, err = load(t, kubernetesDocument(
		writeKubeconfig(t, "https://api.cluster.internal", ""), ""))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	if got := cfg.Targets[0].Port; got != fleetkubernetes.DefaultPort {
		t.Errorf("port is %d, want the declared default of %d",
			got, fleetkubernetes.DefaultPort)
	}
}

// TestEveryInertFieldIsRefusedRatherThanIgnored.
//
// Each of these would be read by nothing. Accepting one lets an operator believe
// they configured — or deliberately relaxed — something that was never consulted,
// which is the failure ADR 0060 made an exit-2 refusal.
func TestEveryInertFieldIsRefusedRatherThanIgnored(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "")

	tests := []struct {
		name  string
		extra string
		names string
	}{
		{"a host", "    host: api.cluster.internal\n", "no effect for a \"kubernetes\" target"},
		{"a port", "    port: 6443\n", "no effect for a \"kubernetes\" target"},
		{"tls.ca_file", "    tls:\n      ca_file: /etc/ca.pem\n", "kubeconfig's\ncertificate-authority"},
		{"tls.server_name", "    tls:\n      server_name: api\n", "verifies the identity"},
		{"tls.insecure", "    tls:\n      insecure: true\n", "does not disable API server"},
		{"tls.mode disable", "    tls:\n      mode: disable\n", "always speaks TLS"},
		{"a username", "    credentials:\n      username: admin\n", "carries no username"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := "version: 1\n" +
				"targets:\n" +
				"  - id: payments\n" +
				"    type: kubernetes\n" +
				test.extra +
				"    config:\n" +
				"      kubeconfig: " + kubeconfig + "\n" +
				"      context: prod\n" +
				"      namespace: payments\n" +
				"      service_name: payments-api\n"

			_, err := load(t, document)
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			for _, fragment := range strings.Split(test.names, "\n") {
				if !strings.Contains(err.Error(), fragment) {
					t.Errorf("the refusal reads %q, want it to mention %q", err, fragment)
				}
			}
		})
	}
}

// TestTheKubernetesConfigRefusesEveryShapeTheContractForbids.
func TestTheKubernetesConfigRefusesEveryShapeTheContractForbids(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "")

	tests := []struct {
		name   string
		config string
		names  string
	}{
		{
			name:   "no namespace",
			config: "      kubeconfig: " + kubeconfig + "\n      context: prod\n      service_name: s\n",
			names:  "a namespace is required",
		},
		{
			name:   "no service name",
			config: "      kubeconfig: " + kubeconfig + "\n      context: prod\n      namespace: n\n",
			names:  "a service name is required",
		},
		{
			name:   "no context",
			config: "      kubeconfig: " + kubeconfig + "\n      namespace: n\n      service_name: s\n",
			names:  "context is required",
		},
		{
			name:   "no authority",
			config: "      namespace: n\n      service_name: s\n",
			names:  "kubeconfig path or in-cluster mode is required",
		},
		{
			name: "both authorities",
			config: "      kubeconfig: " + kubeconfig +
				"\n      context: prod\n      in_cluster: true\n      namespace: n\n      service_name: s\n",
			names: "mutually exclusive",
		},
		{
			name:   "a context in-cluster",
			config: "      in_cluster: true\n      context: prod\n      namespace: n\n      service_name: s\n",
			names:  "no meaning in-cluster",
		},
		{
			name:   "an unknown field",
			config: "      kubeconfig: " + kubeconfig + "\n      context: prod\n      namespace: n\n      service_name: s\n      selector: app=x\n",
			names:  "selector",
		},
		{
			name:   "an absent kubeconfig",
			config: "      kubeconfig: /nonexistent/kubeconfig\n      context: prod\n      namespace: n\n      service_name: s\n",
			names:  "cannot be read",
		},
		{
			name:   "an unknown context",
			config: "      kubeconfig: " + kubeconfig + "\n      context: staging\n      namespace: n\n      service_name: s\n",
			names:  "no context named",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			document := "version: 1\ntargets:\n  - id: payments\n    type: kubernetes\n" +
				"    config:\n" + test.config
			_, err := load(t, document)
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			if !strings.Contains(err.Error(), test.names) {
				t.Errorf("the refusal reads %q, want it to mention %q", err, test.names)
			}
			if !errors.Is(err, config.ErrConfig) {
				t.Errorf("error is %v, want a configuration error", err)
			}
		})
	}
}

// TestAProhibitedKubeconfigFailsTheWholeConfiguration is the exit-2 property.
//
// # Why this has to happen at decode
//
// A kubeconfig carrying an `exec` credential plugin is a **configuration** error:
// nothing was measured, and ADR 0074 section 9 requires the whole configuration
// to validate before any target is dialled. Deferring it to execution would make
// it one target's execution failure at exit 4 — "svcdoctor itself failed" — which
// is precisely the defect Phase 9.1C found in the credential path.
//
// It also has to fail the **whole** document rather than one target, because a
// configuration error means zero targets are dialled.
func TestAProhibitedKubeconfigFailsTheWholeConfiguration(t *testing.T) {
	for _, test := range []struct{ name, userBlock, names string }{
		{"exec", "    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: /bin/true\n", "exec credential plugin"},
		{"auth-provider", "    auth-provider:\n      name: gcp\n", "auth-provider"},
		{"impersonation", "    token: t\n    as: admin\n", "impersonation"},
		{"basic auth", "    username: a\n    password: b\n", "basic authentication"},
		{"anonymous", "    {}\n", "anonymously"},
	} {
		t.Run(test.name, func(t *testing.T) {
			kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", test.userBlock)
			document := "version: 1\n" +
				"targets:\n" +
				"  - id: orders\n" +
				"    type: postgres\n" +
				"    host: orders.internal\n" +
				"    credentials:\n      username: app\n" +
				kubernetesTargetBlock(kubeconfig)

			_, err := load(t, document)
			if err == nil {
				t.Fatalf("%s was accepted", test.name)
			}
			if !strings.Contains(err.Error(), test.names) {
				t.Errorf("the refusal reads %q, want it to mention %q", err, test.names)
			}
			// The whole configuration failed, so the PostgreSQL target above it
			// is not dialled either.
			if !errors.Is(err, config.ErrConfig) {
				t.Errorf("error is %v, want a configuration error", err)
			}
		})
	}
}

func kubernetesTargetBlock(kubeconfig string) string {
	return "  - id: payments\n" +
		"    type: kubernetes\n" +
		"    config:\n" +
		"      kubeconfig: " + kubeconfig + "\n" +
		"      context: prod\n" +
		"      namespace: payments\n" +
		"      service_name: payments-api\n"
}

// TestATargetTokenIsRefusedBesideAKubeconfigCredential.
//
// Two identities in one target is an ambiguity svcdoctor refuses rather than
// ranks. A configuration that authenticates as whichever credential a tool
// happens to prefer is one nobody can audit.
func TestATargetTokenIsRefusedBesideAKubeconfigCredential(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "")
	document := "version: 1\ntargets:\n  - id: payments\n    type: kubernetes\n" +
		"    credentials:\n      password:\n        env: K8S_TOKEN\n" +
		"    config:\n" +
		"      kubeconfig: " + kubeconfig + "\n" +
		"      context: prod\n      namespace: n\n      service_name: s\n"

	if _, err := load(t, document); err == nil ||
		!strings.Contains(err.Error(), "more than one credential") {
		t.Fatalf("two credentials were accepted: %v", err)
	}
}

// TestATargetTokenAloneIsAccepted is the positive half.
//
// A kubeconfig user with no credential of its own, plus a credential reference on
// the target, is mode A — the bearer token an operator keeps outside the file.
func TestATargetTokenAloneIsAccepted(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "    {}\n")
	document := "version: 1\ntargets:\n  - id: payments\n    type: kubernetes\n" +
		"    credentials:\n      password:\n        env: K8S_TOKEN\n" +
		"    config:\n" +
		"      kubeconfig: " + kubeconfig + "\n" +
		"      context: prod\n      namespace: n\n      service_name: s\n"

	cfg, err := load(t, document)
	if err != nil {
		t.Fatalf("a target-supplied token was refused: %v", err)
	}
	if got := cfg.Targets[0].Credentials.Password.Kind(); got != config.SourceEnv {
		t.Errorf("the credential source is %v, want env", got)
	}
	// The credential will be bound to the derived API endpoint, so the two must
	// agree by construction.
	if cfg.Targets[0].Host != "api.cluster.internal" {
		t.Errorf("host is %q", cfg.Targets[0].Host)
	}
}

// TestAnInClusterTargetNeedsNoFileAndBindsToTheAPIServiceName.
//
// A configuration must be checkable on a laptop: the projected token, the
// projected CA and KUBERNETES_SERVICE_HOST exist only inside a pod. So an
// in-cluster target's logical endpoint is the API Service's own fully qualified
// name, which is true in every cluster, and the material is resolved at
// execution.
func TestAnInClusterTargetNeedsNoFileAndBindsToTheAPIServiceName(t *testing.T) {
	document := "version: 1\ntargets:\n  - id: payments\n    type: kubernetes\n" +
		"    config:\n      in_cluster: true\n      namespace: payments\n" +
		"      service_name: payments-api\n"

	cfg, err := load(t, document)
	if err != nil {
		t.Fatalf("an in-cluster target was refused: %v", err)
	}
	if got, want := cfg.Targets[0].Host, "kubernetes.default.svc"; got != want {
		t.Errorf("host is %q, want %q", got, want)
	}
	if got := cfg.Targets[0].Port; got != 443 {
		t.Errorf("port is %d, want 443", got)
	}
}

// TestAnInClusterTargetRefusesASecondIdentity.
func TestAnInClusterTargetRefusesASecondIdentity(t *testing.T) {
	document := "version: 1\ntargets:\n  - id: payments\n    type: kubernetes\n" +
		"    credentials:\n      password:\n        env: K8S_TOKEN\n" +
		"    config:\n      in_cluster: true\n      namespace: n\n      service_name: s\n"

	if _, err := load(t, document); err == nil ||
		!strings.Contains(err.Error(), "second identity") {
		t.Fatalf("a target credential was accepted in-cluster: %v", err)
	}
}

// TestTheFourExistingServicesAreUnchanged is the compatibility guarantee.
//
// Adding a fifth service must not require a new field, change a default or move
// an error for any of the four. This decodes one target of each kind through the
// registry that now holds five and asserts the values are the ones they have
// always had.
func TestTheFourExistingServicesAreUnchanged(t *testing.T) {
	document := "version: 1\n" +
		"targets:\n" +
		"  - id: orders\n    type: postgres\n    host: orders.internal\n" +
		"    credentials:\n      username: app\n" +
		"  - id: events\n    type: kafka\n    host: broker.internal\n" +
		"    config:\n      sasl_mechanism: PLAIN\n" +
		"  - id: cache\n    type: redis\n    host: cache.internal\n" +
		"  - id: queue\n    type: rabbitmq\n    host: queue.internal\n"

	cfg, err := load(t, document)
	if err != nil {
		t.Fatalf("the four existing services no longer decode: %v", err)
	}
	want := []struct {
		id      string
		service string
		port    uint16
	}{
		{"orders", "postgres", 5432},
		{"events", "kafka", 9092},
		{"cache", "redis", 6379},
		{"queue", "rabbitmq", 5672},
	}
	if len(cfg.Targets) != len(want) {
		t.Fatalf("loaded %d targets, want %d", len(cfg.Targets), len(want))
	}
	for i, expected := range want {
		target := cfg.Targets[i]
		if target.ID.String() != expected.id {
			t.Errorf("target %d is %q, want %q", i, target.ID, expected.id)
		}
		if target.Service != expected.service {
			t.Errorf("target %q is %q, want %q", target.ID, target.Service, expected.service)
		}
		if target.Port != expected.port {
			t.Errorf("target %q has port %d, want the unchanged default %d",
				target.ID, target.Port, expected.port)
		}
	}
}

// TestDeclaredOrderIsUnchangedByAKubernetesTarget.
//
// Targets keep their declared order, and adding a service that derives its
// endpoint must not reorder anything or make ordering depend on which services a
// file mixes.
func TestDeclaredOrderIsUnchangedByAKubernetesTarget(t *testing.T) {
	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443", "")
	document := "version: 1\n" +
		"targets:\n" +
		"  - id: orders\n    type: postgres\n    host: orders.internal\n" +
		"    credentials:\n      username: app\n" +
		kubernetesTargetBlock(kubeconfig) +
		"  - id: events\n    type: kafka\n    host: broker.internal\n" +
		"    config:\n      sasl_mechanism: PLAIN\n"

	for run := 0; run < 5; run++ {
		cfg, err := load(t, document)
		if err != nil {
			t.Fatalf("loading: %v", err)
		}
		got := []string{}
		for _, target := range cfg.Targets {
			got = append(got, target.ID.String())
		}
		if want := []string{"orders", "payments", "events"}; !equal(got, want) {
			t.Fatalf("run %d produced order %v, want %v", run, got, want)
		}
	}
}

func equal(a, b []string) bool {
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

// TestTheRegistryListsKubernetesAsASupportedService.
//
// A misspelled `type:` lists what is available, which is what distinguishes a
// typo from a service this build does not have.
func TestTheRegistryListsKubernetesAsASupportedService(t *testing.T) {
	_, err := load(t, "version: 1\ntargets:\n  - id: x\n    type: kubernets\n    host: h\n")
	if err == nil {
		t.Fatal("a misspelled service type was accepted")
	}
	if !strings.Contains(err.Error(), "kubernetes") {
		t.Errorf("the refusal does not list kubernetes: %v", err)
	}
}

// TestAClientCertificateKubeconfigIsAccepted covers mode C at the config layer.
//
// It exists because `kind` and `kubeadm` kubeconfigs authenticate this way, and a
// contract that refused it would make real-cluster validation unachievable.
func TestAClientCertificateKubeconfigIsAccepted(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "client.crt")
	keyPath := filepath.Join(directory, "client.key")
	certPEM, keyPEM := clientCertificate(t)
	for path, content := range map[string]string{certPath: certPEM, keyPath: keyPEM} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil { //nolint:gosec // t.TempDir
			t.Fatalf("writing %s: %v", path, err)
		}
	}

	kubeconfig := writeKubeconfig(t, "https://api.cluster.internal:6443",
		"    client-certificate: "+certPath+"\n    client-key: "+keyPath+"\n")
	if _, err := load(t, kubernetesDocument(kubeconfig, "")); err != nil {
		t.Fatalf("a client-certificate kubeconfig was refused: %v", err)
	}
}

func clientCertificate(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling a key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// TestNoNetworkIsTouchedWhileDecoding.
//
// Decoding a configuration reads the kubeconfig and nothing else. A server that
// fails the test if it is reached is the only way to state that as a measurement.
func TestNoNetworkIsTouchedWhileDecoding(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("decoding a configuration reached the API server")
	}))
	defer server.Close()

	kubeconfig := writeKubeconfig(t, server.URL, "")
	if _, err := load(t, kubernetesDocument(kubeconfig, "")); err != nil {
		t.Fatalf("loading: %v", err)
	}
}
