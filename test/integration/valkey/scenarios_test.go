//go:build integration

package valkey

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"

	diagnosisredis "github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// The Valkey BASIC validation suite.
//
// # The same production adapter, and nothing else
//
// Every import above is the Redis one: internal/adapter/redis via
// app.DiagnoseRedis, internal/diagnosis/redis, internal/service/redis. There is
// no Valkey adapter, no Valkey vocabulary and no Valkey rule, and
// TestNoProductionCodeBranchesOnImplementationName fails the build if one
// appears. This suite exists to prove that is honest rather than convenient:
// the same code meets a genuinely different implementation and says so.

// V-00 — no authentication, plaintext.
func TestV00NoAuthBaseline(t *testing.T) {
	if got := groundTruth(t, "svcd-valkey", "PING"); got != "PONG" {
		t.Fatalf("ground truth: the baseline server answered %q, want PONG", got)
	}

	result := run(t, runOptions{port: portBaseline})

	if got := oneNodeAt(t, result, stepHello).State(); got != domain.StatePass {
		t.Errorf("hello state = %s, want PASS", got)
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", got)
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("a healthy baseline produced findings %v", codes(result))
	}
	assertNoKeyspaceCommandReached(t, "svcd-valkey")
}

// V-01 — the endpoint identifies itself as Valkey, and svcdoctor says so.
//
// This is the scenario ADR 0066 section 4 exists for. The operator's command was
// `diagnose redis`; the report must not repeat the verb back to them as a fact.
func TestV01ServerIdentityIsValkey(t *testing.T) {
	truth := groundTruth(t, "svcd-valkey", "HELLO")
	if !strings.Contains(truth, "valkey") {
		t.Fatalf("ground truth: HELLO did not report valkey:\n%s", truth)
	}

	result := run(t, runOptions{port: portBaseline})

	node := oneNodeAt(t, result, stepHello)
	server, ok := attrOf(t, node, serviceredis.AttrServer)
	if !ok {
		t.Fatal("no observed server identity was recorded")
	}
	if server != "valkey" {
		t.Fatalf("observed server = %q, want valkey.\n\n"+
			"The CLI verb is `redis`. If this ever reads `redis` against a Valkey "+
			"endpoint, identity has been inferred from the command rather than "+
			"observed from the endpoint (ADR 0066 section 4).", server)
	}

	// The version is carried and never interpreted.
	version, ok := attrOf(t, node, serviceredis.AttrServerVersion)
	if !ok || version == "" {
		t.Fatal("no observed version was recorded")
	}
	if !strings.Contains(truth, version) {
		t.Errorf("recorded version %q does not appear in the endpoint's own reply", version)
	}
}

// V-02, V-03 — ACL authentication, and a credential the endpoint rejects.
func TestV02V03ACLAuthentication(t *testing.T) {
	if got := groundTruth(t, "svcd-valkey-acl", "AUTH", "app", "app-pw"); got != "OK" {
		t.Fatalf("ground truth: AUTH app answered %q, want OK", got)
	}
	rejected := groundTruth(t, "svcd-valkey-acl", "AUTH", "app", "not-the-password")
	if !strings.HasPrefix(rejected, "WRONGPASS") {
		t.Fatalf("ground truth: a wrong credential answered %q, want WRONGPASS", rejected)
	}

	t.Run("V-02 correct over TLS", func(t *testing.T) {
		result := run(t, runOptions{
			host: "127.0.0.1", port: portTLS, password: "tls-pw", tls: trustFixtureCA(t),
		})
		if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StatePass {
			t.Fatalf("authentication state = %s, want PASS", got)
		}
		if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
			t.Fatalf("ping state = %s, want PASS", got)
		}
	})

	t.Run("V-03 rejected", func(t *testing.T) {
		result := run(t, runOptions{
			host: "127.0.0.1", port: portTLS,
			username: "app", password: "not-the-password", tls: trustFixtureCA(t),
		})
		node := oneNodeAt(t, result, stepAuth)
		if node.FailureClass() != domain.FailureAuthCredentialsRejected {
			t.Fatalf("failure class = %s, want AUTH_CREDENTIALS_REJECTED", node.FailureClass())
		}
		if !hasCode(result, diagnosisredis.CodeCredentialsRejected) {
			t.Fatalf("findings %v, want REDIS_CREDENTIALS_REJECTED", codes(result))
		}
		text := strings.ToLower(findingText(result))
		if strings.Contains(text, "not-the-password") {
			t.Fatal("the credential appeared in the report")
		}
		if strings.Contains(text, "wrong password") && !strings.Contains(text, "cannot tell which") {
			t.Error("the report asserts a cause Valkey merges, exactly as Redis does")
		}
	})
}

// V-04 — the usability probe.
func TestV04Ping(t *testing.T) {
	result := run(t, runOptions{port: portBaseline})
	node := oneNodeAt(t, result, stepPing)
	if node.State() != domain.StatePass {
		t.Fatalf("ping state = %s, want PASS", node.State())
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("a passing probe produced findings %v; the claim is the node", codes(result))
	}
}

// V-05 — TLS with a verified identity.
func TestV05TLSVerified(t *testing.T) {
	result := run(t, runOptions{host: "127.0.0.1", port: portTLS, tls: trustFixtureCA(t)})
	node := oneNodeAt(t, result, stepTLS)
	if node.State() != domain.StatePass {
		t.Fatalf("tls state = %s, want PASS", node.State())
	}
	verified, ok := node.Attribute(domain.AttributeKey("tls.verified"))
	if !ok {
		t.Fatal("the handshake node records no tls.verified")
	}
	if value, _ := verified.Bool(); !value {
		t.Error("tls.verified = false on a run that trusted the fixture CA")
	}
}

// V-06 — a replica reports its role, and nothing turns it into a problem.
func TestV06ReplicaRoleIsObservationOnly(t *testing.T) {
	truth := groundTruth(t, "svcd-valkey-replica", "HELLO")
	if !strings.Contains(truth, "replica") {
		t.Fatalf("ground truth: the replica did not report a replica role:\n%s", truth)
	}

	result := run(t, runOptions{port: portReplica})
	node := oneNodeAt(t, result, stepHello)
	if role, _ := attrOf(t, node, serviceredis.AttrRole); role != "replica" {
		t.Fatalf("observed role = %q, want replica", role)
	}
	if len(result.Report().Findings()) != 0 {
		t.Fatalf("role=replica produced findings %v; it is an observation", codes(result))
	}
}

// V-07 — a cluster-mode node completes the journey, and no topology is measured.
func TestV07ClusterModeDirectNode(t *testing.T) {
	truth := groundTruth(t, "svcd-valkey-cluster", "HELLO")
	if !strings.Contains(truth, "cluster") {
		t.Fatalf("ground truth: the cluster node did not report cluster mode:\n%s", truth)
	}

	result := run(t, runOptions{port: portCluster})
	node := oneNodeAt(t, result, stepHello)
	if mode, _ := attrOf(t, node, serviceredis.AttrMode); mode != "cluster" {
		t.Fatalf("observed mode = %q, want cluster", mode)
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", got)
	}
	if len(result.Report().Findings()) != 0 {
		t.Fatalf("mode=cluster produced findings %v; topology is not measured", codes(result))
	}
	for _, n := range result.Report().Graph().Nodes() {
		step := n.Step().String()
		if strings.Contains(step, "topology") || strings.Contains(step, "shard") ||
			strings.Contains(step, "slot") {
			t.Errorf("a topology node %s exists; v1 measures none", step)
		}
	}
	assertNoKeyspaceCommandReached(t, "svcd-valkey-cluster")
}

// V-08 — the credential policy holds identically against Valkey.
func TestV08PlaintextCredentialWithheld(t *testing.T) {
	groundTruth(t, "svcd-valkey-pw", "-a", "s3cr3t-pw", "CONFIG", "RESETSTAT")

	result := run(t, runOptions{port: portPassword, password: "s3cr3t-pw"})

	node := oneNodeAt(t, result, stepAuth)
	if node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Fatalf("failure class = %s, want EXEC_SKIPPED_BY_POLICY", node.FailureClass())
	}
	if !hasCode(result, diagnosisredis.CodeCredentialWithheld) {
		t.Fatalf("findings %v, want REDIS_CREDENTIAL_WITHHELD", codes(result))
	}
	if strings.Contains(findingText(result), "s3cr3t-pw") {
		t.Fatal("the credential appeared in the report")
	}

	after := groundTruth(t, "svcd-valkey-pw", "-a", "s3cr3t-pw", "INFO", "commandstats")
	if got := authCalls(after); got != 1 {
		t.Fatalf("the endpoint recorded %d AUTH calls, want exactly 1 (this reading's own)", got)
	}
}

// --- TLS helpers ----------------------------------------------------------

func fixtureCAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile("env/certs/server.crt")
	if err != nil {
		t.Fatalf("reading the fixture certificate: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the fixture certificate did not parse")
	}
	return pool
}

func trustFixtureCA(t *testing.T) *transport.TLSOptions {
	t.Helper()
	return &transport.TLSOptions{
		RootCAs:    fixtureCAPool(t),
		ServerName: "valkey.svcdoctor.test",
	}
}
