//go:build integration

package rabbitmq

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

// The RabbitMQ BASIC validation harness.
//
// # It drives the product, not a shortcut
//
// Every scenario calls app.DiagnoseRabbitMQ — the same entry point
// `svcdoctor diagnose rabbitmq` calls. A harness that sequenced the adapter
// itself would prove the adapter works and say nothing about whether the product
// does, and the composition root is where the credential policy, the transport
// plan and the endpoint authority actually live.
//
// # Ground truth comes from something that is not svcdoctor
//
// Each scenario establishes what is true independently first — through
// `rabbitmqctl`, or through env/groundtruth.py, a scratch AMQP client written
// for this phase that shares no code with the implementation under test. A suite
// that only compared svcdoctor against itself would pass just as happily against
// a broker that had silently changed underneath it.

// The published ports from env/compose.yaml. One constant per listener, so a
// scenario names the broker it means rather than a number.
const (
	portAMQP    = 56672 // 4.2.0, plaintext
	portAMQPS   = 56671 // 4.2.0, TLS
	portMgmt    = 56673 // 4.2.0, management HTTP — RAB-18 targets it as AMQP
	port313     = 56674 // 3.13.7, plaintext
	port313TLS  = 56675 // 3.13.7, TLS
	port409     = 56676 // 4.0.9, plaintext
	port409TLS  = 56677 // 4.0.9, TLS
	portStopped = 56678 // 4.2.0, stopped by RAB-16
)

// The fixture's principals, created by `make rabbitmq-users`.
const (
	userApp     = "app"
	passApp     = "app-pw"
	userNoPerm  = "noperm"
	passNoPerm  = "noperm-pw"
	vhostLimit  = "limited" // max-connections 0
	vhostAbsent = "no-such-vhost"
)

// certPath is the fixture CA, which is also the broker's own certificate.
const certPath = "env/certs/server.crt"

// serverName is the identity the fixture certificate actually carries.
const serverName = "rabbit.svcdoctor.test"

// containerFor names the container behind a plaintext port, for ground truth.
func containerFor(port uint16) string {
	switch port {
	case portAMQP, portAMQPS, portMgmt:
		return "svcd-rabbit"
	case port313, port313TLS:
		return "svcd-rabbit-313"
	case port409, port409TLS:
		return "svcd-rabbit-409"
	case portStopped:
		return "svcd-rabbit-stop"
	}
	return ""
}

// rabbitmqctl establishes ground truth through the broker's own admin tool.
//
// It runs as the `rabbitmq` user deliberately. `docker exec` defaults to root,
// and an Erlang command run as root before the server has written its cookie
// creates `/var/lib/rabbitmq/.erlang.cookie` owned by root with mode 0400 — the
// server, running as uid 999, then cannot read it and exits. A root-owned probe
// would break the very broker it is asking about.
func rabbitmqctl(t *testing.T, container string, args ...string) string {
	t.Helper()
	full := append([]string{"exec", "-u", "rabbitmq", container, "rabbitmqctl", "-q"}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Fatalf("ground truth %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// groundTruthJourney walks the frozen journey with the scratch AMQP client and
// returns its one-line verdict.
//
// This is the independent measurement. The client is Python, it shares no code
// with svcdoctor, and it speaks only the five methods the contract allows.
func groundTruthJourney(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"env/probe.py"}, args...)
	out, err := exec.Command("python3", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ground truth journey %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// pinnedImages are the versions docs/COMPATIBILITY.md is allowed to name.
//
// They are read from the compose file rather than repeated, so a bumped image
// cannot leave a stale version claim in the documentation.
func pinnedImages(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("env/compose.yaml")
	if err != nil {
		t.Fatalf("reading the compose file: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "image:") {
			image := strings.TrimSpace(strings.TrimPrefix(line, "image:"))
			if !contains(out, image) {
				out = append(out, image)
			}
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// --- the product entry point ------------------------------------------------

type runOptions struct {
	host     string
	port     uint16
	vhost    string
	username string
	password string

	// credentialEndpoint overrides the endpoint the credential is bound to.
	// Only the authority scenarios set it; everything else binds to the target.
	credentialHost string
	credentialPort uint16

	tls         *transport.TLSOptions
	timeout     time.Duration
	stepTimeout time.Duration
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
	stepTimeout := opts.stepTimeout
	if stepTimeout == 0 {
		// Above three seconds on purpose: RabbitMQ delays several refusals by
		// exactly that long, and a shorter budget would report the delay as a
		// local timeout instead of the refusal it is (ADR 0070 §8).
		stepTimeout = 8 * time.Second
	}

	var credential security.Credential
	if opts.password != "" {
		ch, cp := opts.credentialHost, opts.credentialPort
		if ch == "" {
			ch, cp = host, opts.port
		}
		endpoint, err := security.NewEndpoint(ch, cp)
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
		StepTimeout: stepTimeout,
		Vantage:     vantage,
		Version:     "integration",
	})
	if err != nil {
		t.Fatalf("DiagnoseRabbitMQ: %v", err)
	}
	return result
}

// runExpectingRefusal drives the same entry point and returns the error instead
// of failing on it.
//
// The credential-authority checks refuse before the run begins, so the refusal
// is a returned error rather than a report — which is the point: nothing was
// measured because nothing was allowed to start.
func runExpectingRefusal(t *testing.T, opts runOptions) error {
	t.Helper()

	host := opts.host
	if host == "" {
		host = "127.0.0.1"
	}
	ch, cp := opts.credentialHost, opts.credentialPort
	if ch == "" {
		ch, cp = host, opts.port
	}
	endpoint, err := security.NewEndpoint(ch, cp)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, opts.username, security.NewSecret(opts.password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	vantage, err := local.Vantage()
	if err != nil {
		t.Fatalf("local.Vantage: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	_, err = app.DiagnoseRabbitMQ(ctx, app.RabbitMQParams{
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
	return err
}

// trustFixtureCA builds a TLS plan that verifies against the fixture
// certificate and asks for the identity that certificate actually carries.
func trustFixtureCA(t *testing.T) *transport.TLSOptions {
	t.Helper()
	return &transport.TLSOptions{
		ServerName: serverName,
		RootCAs:    poolFrom(t, certPath),
	}
}

// trustRogueCA builds a TLS plan that trusts a certificate the broker does not
// present, which is what makes RAB-08 a real chain failure.
func trustRogueCA(t *testing.T) *transport.TLSOptions {
	t.Helper()
	return &transport.TLSOptions{
		ServerName: serverName,
		RootCAs:    poolFrom(t, "env/certs/rogue.crt"),
	}
}

func poolFrom(t *testing.T, path string) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("%s carried no certificate", path)
	}
	return pool
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

func attrOf(t *testing.T, node domain.Evidence, key domain.AttributeKey) (string, bool) {
	t.Helper()
	value, ok := node.Attribute(key)
	if !ok {
		return "", false
	}
	return value.Str()
}

// attrText renders an attribute regardless of its underlying type.
//
// The negotiation window is stored with domain.IntAttr and the graceful-close
// flag with domain.BoolAttr, so Str() is empty for both. Scenarios compare the
// rendered form, which is what a renderer and an operator actually see.
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

func findingFor(t *testing.T, result app.Result, code domain.FindingCode) domain.Finding {
	t.Helper()
	for _, finding := range result.Report().Findings() {
		if finding.Code() == code {
			return finding
		}
	}
	t.Fatalf("no %s finding; got %v", code, codes(result))
	return domain.Finding{}
}

// reportText concatenates every operator-visible string a report carries.
//
// It is what the leak and forbidden-claim assertions scan, because a phrase that
// reaches any of these reaches an operator.
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

// peerTextOf extracts the reply_text the ground-truth probe measured.
//
// Scenarios feed it to assertNoRawPeerText, which is what turns "no obvious
// fragment leaked" into "the exact sentence this broker actually sent is absent".
func peerTextOf(truth string) string {
	i := strings.Index(truth, " text=")
	if i < 0 {
		return ""
	}
	return truth[i+len(" text="):]
}

// peerOnlyMarkers are spans that appear in a broker's reply text and in nothing
// svcdoctor can say on its own.
//
// The list is deliberately narrow. `ACCESS_REFUSED` on its own would be a false
// positive, because svcdoctor's **own** normalized outcome constant
// VHOST_ACCESS_REFUSED contains it — so the marker carries the `" - "` the
// symbolic-name prefix always has and the constant never does. Likewise the
// report may truthfully say "was not found" in its own words; only the peer
// writes "NOT_ALLOWED".
var peerOnlyMarkers = []string{
	"NOT_ALLOWED",
	"ACCESS_REFUSED - ",
	"refused for user",
	"doesn't have access",
	"is reached",
	"broker logfile",
}

// assertNoRawPeerText is the contract every refusal scenario shares.
//
// RabbitMQ interpolates the virtual host and the username into its reply text,
// and an authorization backend may append arbitrary bytes to it. ADR 0069 §3
// keeps every one of those bytes inside the wire package, so the normalized
// outcome is the only thing that crosses. This proves the consequence on a real
// broker rather than in a unit test: whatever the endpoint actually said, none
// of its prose is in the report.
//
// peerText is the sentence the ground-truth probe measured, or "" when the
// scenario has none to offer.
func assertNoRawPeerText(t *testing.T, result app.Result, peerText string) {
	t.Helper()
	text := reportText(result)

	if peerText != "" && strings.Contains(text, peerText) {
		t.Errorf("the peer's exact reply text reached the report:\n  %q", peerText)
	}
	for _, marker := range peerOnlyMarkers {
		if strings.Contains(text, marker) {
			t.Errorf("raw peer reply text escaped the wire package: %q appears in the report\n"+
				"ADR 0069 §3 keeps every byte of reply_text inside internal/adapter/rabbitmq/wire",
				marker)
		}
	}
}

// The steps, re-exported for readability in the scenarios.
var (
	stepStart = servicerabbitmq.StepConnectionStart
	stepAuth  = servicerabbitmq.StepAuthentication
	stepOpen  = servicerabbitmq.StepConnectionOpen
	stepDNS   = domain.Step("dns.lookup")
	stepTCP   = domain.Step("tcp.connect")
	stepTLS   = domain.Step("tls.handshake")
)
