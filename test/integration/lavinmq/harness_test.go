//go:build integration

package lavinmq

import (
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicerabbitmq "github.com/hakanaltindag/svcdoctor/internal/service/rabbitmq"
)

// The LavinMQ BASIC validation harness.
//
// # Why this is a separate package from the RabbitMQ suite
//
// LavinMQ is a different implementation of the same protocol, not another
// RabbitMQ version. These scenarios exist to prove svcdoctor's journey is
// vendor-neutral, so they must run without a RabbitMQ broker existing at all. A
// shared package would let a LavinMQ assertion quietly depend on one.
//
// # It drives the same production code
//
// Every scenario calls app.DiagnoseRabbitMQ — the same entry point, the same
// adapter, the same diagnosis rules. There is no LavinMQ branch anywhere in the
// journey, and TestNoVendorBranchExistsInTheJourney holds the tree to that.

const (
	portAMQP  = 56680
	portAMQPS = 56681
	portHTTP  = 56682
)

const (
	userDefault = "guest"
	passDefault = "guest"
	userNoPerm  = "noperm"
	passNoPerm  = "noperm-pw"
	vhostLimit  = "limited" // max-connections 0
	vhostAbsent = "no-such-vhost"
)

// The fixture shares the RabbitMQ environment's throwaway certificate, so a TLS
// scenario that passes there and fails here has a vendor difference as its only
// remaining explanation.
const (
	certPath   = "../rabbitmq/env/certs/server.crt"
	probeePath = "../rabbitmq/env/probe.py"
	serverName = "rabbit.svcdoctor.test"
)

// groundTruthJourney walks the frozen journey with the scratch AMQP client.
func groundTruthJourney(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{probeePath}, args...)
	out, err := exec.Command("python3", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ground truth journey %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func peerTextOf(truth string) string {
	i := strings.Index(truth, " text=")
	if i < 0 {
		return ""
	}
	return truth[i+len(" text="):]
}

// pinnedImage is the version docs/COMPATIBILITY.md is allowed to name.
func pinnedImage(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("env/compose.yaml")
	if err != nil {
		t.Fatalf("reading the compose file: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "image:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "image:"))
		}
	}
	t.Fatal("no image found in the compose file")
	return ""
}

type runOptions struct {
	host     string
	port     uint16
	vhost    string
	username string
	password string
	tls      *transport.TLSOptions
	timeout  time.Duration
}

func run(t *testing.T, opts runOptions) app.Result {
	t.Helper()

	host := opts.host
	if host == "" {
		host = "127.0.0.1"
	}
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}

	var credential security.Credential
	if opts.password != "" {
		endpoint, err := security.NewEndpoint(host, opts.port)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		credential, err = security.NewCredential(
			endpoint, opts.username, security.NewSecret(opts.password))
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
	}

	vantage, err := local.Vantage()
	if err != nil {
		t.Fatalf("local.Vantage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := app.DiagnoseRabbitMQ(ctx, app.RabbitMQParams{
		Host:        host,
		Port:        opts.port,
		VHost:       opts.vhost,
		Username:    opts.username,
		Credential:  credential,
		Resolver:    dns.SystemResolver{},
		Dialer:      tcp.SystemDialer{},
		TLS:         opts.tls,
		StepTimeout: 8 * time.Second,
		Vantage:     vantage,
		Version:     "integration",
	})
	if err != nil {
		t.Fatalf("DiagnoseRabbitMQ: %v", err)
	}
	return result
}

func trustFixtureCA(t *testing.T) *transport.TLSOptions {
	t.Helper()
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading %s: %v", certPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s carried no certificate", certPath)
	}
	return &transport.TLSOptions{ServerName: serverName, RootCAs: pool}
}

// --- graph helpers ----------------------------------------------------------

func nodesAt(t *testing.T, result app.Result, step domain.Step) []domain.Evidence {
	t.Helper()
	var out []domain.Evidence
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == step {
			out = append(out, node)
		}
	}
	return out
}

func oneNodeAt(t *testing.T, result app.Result, step domain.Step) domain.Evidence {
	t.Helper()
	nodes := nodesAt(t, result, step)
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes at %s, want exactly 1", len(nodes), step)
	}
	return nodes[0]
}

func hasNodeAt(t *testing.T, result app.Result, step domain.Step) bool {
	t.Helper()
	return len(nodesAt(t, result, step)) > 0
}

func attrText(t *testing.T, node domain.Evidence, key domain.AttributeKey) string {
	t.Helper()
	value, ok := node.Attribute(key)
	if !ok {
		return ""
	}
	return value.String()
}

func codes(result app.Result) []string {
	var out []string
	for _, finding := range result.Report().Findings() {
		out = append(out, finding.Code().String())
	}
	return out
}

func hasCode(result app.Result, code domain.FindingCode) bool {
	for _, finding := range result.Report().Findings() {
		if finding.Code() == code {
			return true
		}
	}
	return false
}

func reportText(result app.Result) string {
	var sb strings.Builder
	for _, finding := range result.Report().Findings() {
		sb.WriteString(finding.Summary())
		sb.WriteString(" ")
		sb.WriteString(finding.Detail())
		for _, r := range finding.Recommendations() {
			sb.WriteString(" ")
			sb.WriteString(r.Action())
		}
	}
	for _, node := range result.Report().Graph().Nodes() {
		for key, value := range node.Attributes() {
			sb.WriteString(" " + string(key) + "=" + value.String())
		}
	}
	return sb.String()
}

// peerOnlyMarkers are spans that appear in a broker's reply text and in nothing
// svcdoctor can say on its own. LavinMQ's own phrasing is included.
var peerOnlyMarkers = []string{
	"NOT_ALLOWED",
	"ACCESS_REFUSED - ",
	"doesn't have access",
	"is reached",
	"refused for user",
}

func assertNoRawPeerText(t *testing.T, result app.Result, peerText string) {
	t.Helper()
	text := reportText(result)
	if peerText != "" && strings.Contains(text, peerText) {
		t.Errorf("the peer's exact reply text reached the report:\n  %q", peerText)
	}
	for _, marker := range peerOnlyMarkers {
		if strings.Contains(text, marker) {
			t.Errorf("raw peer reply text escaped the wire package: %q appears in the report",
				marker)
		}
	}
}

var (
	stepStart = servicerabbitmq.StepConnectionStart
	stepAuth  = servicerabbitmq.StepAuthentication
	stepOpen  = servicerabbitmq.StepConnectionOpen
	stepTCP   = domain.Step("tcp.connect")
	stepTLS   = domain.Step("tls.handshake")
)
