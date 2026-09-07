package app_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	servicekubernetes "github.com/hakanaltindag/svcdoctor/internal/service/kubernetes"
)

// A Kubernetes composition-root fixture.
//
// It is deliberately thinner than the adapter's: everything about the API
// protocol is proven in internal/adapter/kubernetes/client against a hermetic
// server, and what is left for this layer is the report — its target, its
// service, its findings, its schema and its redaction.

func kubernetesFixture(t *testing.T, handler http.HandlerFunc) app.KubernetesTarget {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	directory := t.TempDir()
	caPath := filepath.Join(directory, "ca.crt")
	certificate := server.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("writing the CA: %v", err)
	}

	document := "apiVersion: v1\nkind: Config\n" +
		"clusters:\n- name: c\n  cluster:\n    server: " + server.URL + "\n" +
		"    certificate-authority: " + caPath + "\n" +
		"users:\n- name: u\n  user:\n    token: fixture-token\n" +
		"contexts:\n- name: prod\n  context:\n    cluster: c\n    user: u\n" +
		"current-context: prod\n"
	path := filepath.Join(directory, "kubeconfig")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatalf("writing the kubeconfig: %v", err)
	}

	return app.KubernetesTarget{
		Kubeconfig: path, Context: "prod",
		Namespace: "payments", ServiceName: "payments-api",
	}
}

func notFoundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure",` +
			`"reason":"NotFound","code":404,"message":"services \"payments-api\" not found"}`))
	}
}

func runKubernetes(t *testing.T, target app.KubernetesTarget) app.Result {
	t.Helper()
	result, err := app.DiagnoseKubernetes(context.Background(), app.KubernetesParams{
		Target:  target,
		Vantage: testVantage(t),
		Version: "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnoseKubernetes: %v", err)
	}
	return result
}

func testVantage(t *testing.T) domain.Vantage {
	t.Helper()
	vantage, err := domain.NewLocalVantage("test-host")
	if err != nil {
		t.Fatalf("building a vantage: %v", err)
	}
	return vantage
}

// TestAKubernetesRunReportsWhatTheAPIAnswered is Phase 12.1C's boundary, and it
// replaces Phase 12.1B's.
//
// # It was the opposite assertion one phase ago
//
// Until Phase 12.1C this was `TestAKubernetesRunProducesNoFindingAtAll`: ADR
// 0094 section 2.12 split the work so that 12.1B landed acquisition with
// byte-identical output for every existing service and **no finding for the new
// one**, which made 12.1C's diff the entire behavioural change. That premise is
// now deliberately gone, so the assertion is turned around rather than deleted.
//
// What it states now is the shape of that change on the simplest reachable
// scenario: a Service the API server reports as absent yields exactly two
// findings — the Kubernetes claim and the generic boundary that localizes it —
// on the same five-node graph, and the summary moves off OK for the first time.
func TestAKubernetesRunReportsWhatTheAPIAnswered(t *testing.T) {
	target := kubernetesFixture(t, notFoundHandler())
	result := runKubernetes(t, target)

	codes := map[domain.FindingCode]bool{}
	for _, finding := range result.Report().Findings() {
		codes[finding.Code()] = true
	}
	for _, want := range []domain.FindingCode{
		"KUBERNETES_SERVICE_NOT_FOUND", "DIAG_FAILURE_BOUNDARY",
	} {
		if !codes[want] {
			t.Errorf("a Service the API reported absent produced no %s; got %v", want, codes)
		}
	}
	if got := len(codes); got != 2 {
		t.Errorf("produced %d distinct finding codes, want 2: %v.\n\n"+
			"The Pod and EndpointSlice reads did not run, and a step that did not run is "+
			"neither proven to work nor proven to fail.", got, codes)
	}

	// The evidence is unchanged by 12.1C; only the conclusions are new.
	if got := len(result.Report().Graph().Nodes()); got != 5 {
		t.Errorf("the graph holds %d nodes, want 5", got)
	}
	if got := result.Report().Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("summary status is %s, want PROBLEMS_FOUND: the Service read produced an "+
			"ERROR finding, and the generic summary derives the status from it with no "+
			"Kubernetes special case", got)
	}
	if result.Incomplete() {
		t.Error("a 404 is an answer, so the run is complete; only svcdoctor's own budget " +
			"stopping the measurement makes it incomplete")
	}
}

// TestTheReportTargetIsTheServiceAndNotTheAPIServer.
//
// The API server's host and port bind the credential. Publishing them as the
// run's identity would turn a report into a control-plane inventory.
func TestTheReportTargetIsTheServiceAndNotTheAPIServer(t *testing.T) {
	target := kubernetesFixture(t, notFoundHandler())
	report := runKubernetes(t, target).Report()

	if got, want := report.Target().Requested(), "service/payments/payments-api"; got != want {
		t.Errorf("the report target is %q, want %q", got, want)
	}
	if got := report.Run().Service().String(); got != servicekubernetes.ServiceID {
		t.Errorf("the run service is %q, want %q", got, servicekubernetes.ServiceID)
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encoding the report: %v", err)
	}
	for _, forbidden := range []string{
		"127.0.0.1", "https://", target.Kubeconfig, "fixture-token", "certificate-authority",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("the report carries %q", forbidden)
		}
	}
}

// TestTheSchemaVersionsDoNotMove.
//
// ADR 0094 section 2.10 froze both at 1, and a fifth service is exactly the
// change most likely to move one by accident.
func TestTheSchemaVersionsDoNotMove(t *testing.T) {
	if domain.SchemaVersion != 1 {
		t.Errorf("SchemaVersion is %d, want 1", domain.SchemaVersion)
	}
	if domain.RunSchemaVersion != 1 {
		t.Errorf("RunSchemaVersion is %d, want 1", domain.RunSchemaVersion)
	}
}

// TestAKubernetesReportRedactsToAShareableOne.
//
// Privacy needs no new mechanism: the namespace, the Service name and the context
// are AttrKindIdentity, whose definition already covers *"a named resource"*, so
// structural redaction transforms them by dispatching on the kind. This proves
// the whole path rather than the intent — including that redaction does not fail
// closed on a shape it has never seen.
func TestAKubernetesReportRedactsToAShareableOne(t *testing.T) {
	target := kubernetesFixture(t, notFoundHandler())
	report := runKubernetes(t, target).Report()

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("redacting a Kubernetes report: %v", err)
	}

	encoded, err := json.Marshal(shareable)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for _, identifying := range []string{"payments", "payments-api", "prod"} {
		if strings.Contains(string(encoded), identifying) {
			t.Errorf("the shareable report still carries %q:\n%s", identifying, encoded)
		}
	}
	// The auth mode survives, because it is a category svcdoctor declared rather
	// than a name from the environment — and it is the one authority fact a
	// reader of a shared report needs.
	if !strings.Contains(string(encoded), servicekubernetes.AuthModeToken) {
		t.Error("the shareable report lost the authentication mode")
	}
}

// TestAnInvalidKubernetesTargetIsAnInputErrorAndNotAReport.
//
// A refused kubeconfig is a configuration error: nothing was measured, so there
// is nothing to report. It maps to the existing usage-error path and exit 2.
func TestAnInvalidKubernetesTargetIsAnInputErrorAndNotAReport(t *testing.T) {
	for _, test := range []struct {
		name   string
		target app.KubernetesTarget
	}{
		{"no namespace", app.KubernetesTarget{
			Kubeconfig: "/k", Context: "c", ServiceName: "s",
		}},
		{"both authorities", app.KubernetesTarget{
			Kubeconfig: "/k", Context: "c", InCluster: true,
			Namespace: "n", ServiceName: "s",
		}},
		{"an absent kubeconfig", app.KubernetesTarget{
			Kubeconfig: filepath.Join(t.TempDir(), "absent"), Context: "c",
			Namespace: "n", ServiceName: "s",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := app.DiagnoseKubernetes(context.Background(), app.KubernetesParams{
				Target: test.target, Vantage: testVantage(t), Version: "0.0.0-test",
			})
			if err == nil {
				t.Fatal("an invalid target produced a report")
			}
			if !errors.Is(err, app.ErrInvalidInput) {
				t.Errorf("error is %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestInspectingATargetResolvesTheAPIServerWithoutConnecting.
//
// It is what lets a fleet configuration be validated on a machine that has the
// kubeconfig and none of the network.
func TestInspectingATargetResolvesTheAPIServerWithoutConnecting(t *testing.T) {
	target := kubernetesFixture(t, func(http.ResponseWriter, *http.Request) {
		t.Error("inspection reached the network")
	})

	host, port, err := app.InspectKubernetesTarget(target, false)
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if host != "127.0.0.1" {
		t.Errorf("host is %q, want the kubeconfig cluster's own", host)
	}
	if port == 0 {
		t.Error("no port was derived")
	}
}

// TestAnUnreachableAPIServerStillProducesAReport.
//
// Every diagnostic outcome is a report. A control plane that cannot be reached is
// a measurement svcdoctor made, not a run it could not perform — the same
// distinction every other composition root keeps between an error and a fact.
func TestAnUnreachableAPIServerStillProducesAReport(t *testing.T) {
	target := kubernetesFixture(t, func(http.ResponseWriter, *http.Request) {})

	// A listener that existed long enough to have an address and then stopped, so
	// the connection is refused rather than hanging.
	closed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	document, err := os.ReadFile(target.Kubeconfig)
	if err != nil {
		t.Fatalf("reading the kubeconfig: %v", err)
	}
	//nolint:gosec // the path is the fixture's own t.TempDir kubeconfig
	if err := os.WriteFile(
		target.Kubeconfig, []byte(replaceServer(string(document), closedURL)), 0o600,
	); err != nil {
		t.Fatalf("rewriting the kubeconfig: %v", err)
	}

	result := runKubernetes(t, target)

	if got := len(result.Report().Graph().Nodes()); got != 5 {
		t.Errorf("the graph holds %d nodes, want 5", got)
	}
	access := findNode(t, result.Report().Graph(), servicekubernetes.StepAPIAccess)
	if access.State() == domain.StatePass {
		t.Error("an unreachable API server produced a passing api_access node")
	}
	if access.FailureClass() == domain.FailureNone {
		t.Error("an unreachable API server produced no failure class")
	}
	// **No Kubernetes finding**, and that is ADR 0094 section 2.8's admission
	// rule holding. A control plane that could not be reached is an acquisition
	// failure carrying an existing failure class on its own node; it is not one
	// of the four claims about somebody's Service, and DIAG_FAILURE_BOUNDARY is
	// what localizes it.
	for _, finding := range result.Report().Findings() {
		if strings.HasPrefix(string(finding.Code()), "KUBERNETES_") {
			t.Errorf("an unreachable API server produced %s.\n\n"+
				"Only a structured NotFound on the Service read and a structured Forbidden "+
				"on one of the three reads earn a Kubernetes code. Every other API outcome "+
				"is an acquisition failure on its node.", finding.Code())
		}
	}
}

func findNode(t *testing.T, graph domain.Graph, step domain.Step) domain.Evidence {
	t.Helper()
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == step {
			return evidence
		}
	}
	t.Fatalf("no %s node", step)
	return domain.Evidence{}
}

func replaceServer(document, url string) string {
	lines := strings.Split(document, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "server:") {
			lines[i] = "    server: " + url
		}
	}
	return strings.Join(lines, "\n")
}
