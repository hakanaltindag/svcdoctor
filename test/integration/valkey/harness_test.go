//go:build integration

package valkey

import (
	"context"
	"fmt"
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
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// The Valkey BASIC validation harness.
//
// # It drives the product, not a shortcut
//
// Every scenario calls app.DiagnoseRedis — the same entry point
// `svcdoctor diagnose redis` calls — the same command, because ADR 0066
// section 6 freezes one CLI surface for both implementations. A harness that sequenced the adapter itself
// would prove the adapter works and say nothing about whether the product does,
// and the composition root is where the credential policy, the path selection
// and the Sentinel stop actually live.
//
// # Ground truth comes from valkey-cli, before svcdoctor is asked
//
// Each scenario that asserts something about the server establishes it
// independently first, through `docker exec ... valkey-cli`. That ordering is the
// point: a suite that only compared svcdoctor against itself would pass just as
// happily against a server that had silently changed underneath it.

// The published ports from env/compose.yaml. One constant per server, so a
// scenario names the server it means rather than a number.
const (
	portBaseline = 56479 // no auth, plaintext
	portPassword = 56480 // requirepass
	portACL      = 56481 // the ACL matrix
	portTLS      = 56482 // TLS, tls-auth-clients no
	portReplica  = 56484
	portCluster  = 56485
)

// pinnedImage is the version docs/COMPATIBILITY.md is allowed to name.
//
// It is read from the compose file rather than repeated, so a bumped image
// cannot leave a stale version claim in the documentation.
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

// groundTruth runs a command inside a fixture container and returns its output.
//
// It is how a scenario establishes what is true before svcdoctor is asked. The
// command is valkey-cli, which is not svcdoctor and shares no code with it.
func groundTruth(t *testing.T, container string, args ...string) string {
	t.Helper()
	full := append([]string{"exec", container, "valkey-cli"}, args...)
	out, err := exec.Command("docker", full...).CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Fatalf("ground truth %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// run diagnoses one endpoint through the product entry point.
type runOptions struct {
	host     string
	port     uint16
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
		timeout = 10 * time.Second
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

	result, err := app.DiagnoseRedis(ctx, app.RedisParams{
		Host:        host,
		Port:        opts.port,
		Username:    opts.username,
		Credential:  credential,
		Resolver:    dns.SystemResolver{},
		Dialer:      tcp.SystemDialer{},
		TLS:         opts.tls,
		StepTimeout: 5 * time.Second,
		Vantage:     vantage,
		Version:     "integration",
	})
	if err != nil {
		t.Fatalf("DiagnoseRedis: %v", err)
	}
	return result
}

// --- graph helpers ---------------------------------------------------------

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

// findingText concatenates every operator-visible string a report carries.
//
// It is what the leak and claim assertions scan, because a phrase that reaches
// any of these reaches an operator.
func findingText(result app.Result) string {
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

// assertNoKeyspaceCommandReached is the contract every scenario shares.
//
// The structural guards prove no key can be named. This proves the consequence
// on a real server: whatever the scenario did, the endpoint's command statistics
// show no keyspace command from this run.
// # One documented exclusion, and the evidence for it
//
// `cmdstat_cluster` is excluded on the cluster-mode node. The bundled `search`
// module polls `CLUSTER SLOTS` on its own, once a second, which the container
// log shows as a continuous stream of "Got no slots in CLUSTER SLOTS". Counting
// it would attribute a module's own housekeeping to svcdoctor.
//
// The exclusion is narrow and it is not a hole: the structural guard
// TestNoRedisProductionFileNamesAForbiddenCommand proves svcdoctor cannot name
// CLUSTER at all, and every other server in this environment still asserts it.
func assertNoKeyspaceCommandReached(t *testing.T, container string) {
	t.Helper()
	stats := groundTruth(t, container, "INFO", "commandstats")
	forbidden := []string{
		"cmdstat_get", "cmdstat_set", "cmdstat_del", "cmdstat_exists",
		"cmdstat_type", "cmdstat_scan", "cmdstat_keys", "cmdstat_role",
		"cmdstat_cluster", "cmdstat_select", "cmdstat_reset",
	}
	if container == "svcd-valkey-cluster" {
		filtered := forbidden[:0:0]
		for _, name := range forbidden {
			if name != "cmdstat_cluster" {
				filtered = append(filtered, name)
			}
		}
		forbidden = filtered
	}
	for _, forbidden := range forbidden {
		if strings.Contains(stats, forbidden) {
			t.Errorf("the endpoint recorded %s; Redis BASIC names no key and sends only "+
				"HELLO, AUTH and PING", forbidden)
		}
	}
}

// The steps, re-exported for readability in the scenarios.
var (
	stepHello = serviceredis.StepHello
	stepAuth  = serviceredis.StepAuthentication
	stepPing  = serviceredis.StepPing
	stepDNS   = domain.Step("dns.lookup")
	stepTCP   = domain.Step("tcp.connect")
	stepTLS   = domain.Step("tls.handshake")
)

// authCalls reads the AUTH counter out of INFO commandstats.
func authCalls(stats string) int {
	for _, line := range strings.Split(stats, "\n") {
		if !strings.HasPrefix(line, "cmdstat_auth:") {
			continue
		}
		for _, field := range strings.Split(line, ",") {
			value := strings.TrimPrefix(field, "cmdstat_auth:")
			if strings.HasPrefix(value, "calls=") {
				var n int
				_, _ = fmt.Sscan(strings.TrimPrefix(value, "calls="), &n)
				return n
			}
		}
	}
	return 0
}
