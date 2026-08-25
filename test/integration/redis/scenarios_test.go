//go:build integration

package redis

import (
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	diagnosisredis "github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
	"github.com/hakanaltindag/svcdoctor/test/harness"
)

// R-00 — the baseline. Plaintext, no authentication, nothing configured.
func TestR00NoAuthBaseline(t *testing.T) {
	if got := groundTruth(t, "svcd-redis", "PING"); got != "PONG" {
		t.Fatalf("ground truth: the baseline server answered %q, want PONG", got)
	}

	result := run(t, runOptions{port: portBaseline})

	if got := oneNodeAt(t, result, stepHello).State(); got != domain.StatePass {
		t.Errorf("hello state = %s, want PASS", got)
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", got)
	}
	if hasNodeAt(t, result, stepAuth) {
		t.Error("an endpoint that demanded nothing produced an authentication node")
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a complete run reported incomplete")
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("a healthy baseline produced findings %v; a passing probe is the node, "+
			"not a finding", codes(result))
	}

	node := oneNodeAt(t, result, stepHello)
	if server, _ := attrOf(t, node, serviceredis.AttrServer); server != "redis" {
		t.Errorf("observed server = %q, want redis", server)
	}
	if mode, _ := attrOf(t, node, serviceredis.AttrMode); mode != "standalone" {
		t.Errorf("observed mode = %q, want standalone", mode)
	}
	if role, _ := attrOf(t, node, serviceredis.AttrRole); role != "master" {
		t.Errorf("observed role = %q, want master", role)
	}

	assertNoKeyspaceCommandReached(t, "svcd-redis")
}

// R-01 — requirepass, correct credential, over TLS so the policy permits it.
//
// The plaintext password server exists for R-02 and R-13; a *successful*
// authentication needs a verified channel, which is what the TLS server is for.
func TestR01RequirepassCorrectOverTLS(t *testing.T) {
	if got := groundTruth(t, "svcd-redis-tls", "--tls", "--cacert",
		"/etc/redis-certs/server.crt", "-a", "tls-pw", "PING"); !strings.Contains(got, "PONG") {
		t.Fatalf("ground truth: the TLS server answered %q, want PONG", got)
	}

	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS, password: "tls-pw", tls: trustFixtureCA(t),
	})

	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StatePass {
		t.Fatalf("tls state = %s, want PASS", got)
	}
	if got := oneNodeAt(t, result, stepAuth).State(); got != domain.StatePass {
		t.Fatalf("authentication state = %s, want PASS", got)
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Fatalf("ping state = %s, want PASS", got)
	}
	// The endpoint refused the first HELLO, so a second one collected the
	// identity. Two nodes, distinguishable, never an amendment of the first.
	if got := len(nodesAt(t, result, stepHello)); got != 2 {
		t.Fatalf("got %d hello nodes, want 2 (the second after authentication)", got)
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	assertNoKeyspaceCommandReached(t, "svcd-redis-tls")
}

// R-02, R-04, R-05 — the three conditions Redis merges into one reply.
//
// Ground truth first: redis-cli is asked all three, and the replies are compared
// to each other. They are byte-identical, which is why svcdoctor is forbidden
// from naming a cause.
func TestR02R04R05MergedAuthenticationFailures(t *testing.T) {
	wrongPassword := groundTruth(t, "svcd-redis-acl", "AUTH", "app", "definitely-not-the-password")
	unknownUser := groundTruth(t, "svcd-redis-acl", "AUTH", "ghost", "ghost-pw")
	disabledUser := groundTruth(t, "svcd-redis-acl", "AUTH", "disabled", "disabled-pw")

	if wrongPassword != unknownUser || unknownUser != disabledUser {
		t.Fatalf("ground truth: the three replies differ.\n wrong password: %q\n unknown user:  %q\n disabled user: %q",
			wrongPassword, unknownUser, disabledUser)
	}
	if !strings.HasPrefix(wrongPassword, "WRONGPASS") {
		t.Fatalf("ground truth: expected WRONGPASS, got %q", wrongPassword)
	}

	for _, tc := range []struct {
		name     string
		username string
		password string
	}{
		{"R-02 wrong password", "app", "definitely-not-the-password"},
		{"R-04 unknown user", "ghost", "ghost-pw"},
		{"R-05 disabled user", "disabled", "disabled-pw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The reset is the last thing before svcdoctor runs, so the count
			// read afterwards is svcdoctor's own plus the reading connection.
			resetAuthStats(t)

			result := run(t, runOptions{
				host: "127.0.0.1", port: portTLS,
				username: tc.username, password: tc.password, tls: trustFixtureCA(t),
			})

			// R-H1 (harness). All three inputs above produce a byte-identical
			// WRONGPASS, which the ground-truth comparison at the top of this
			// test just proved. So the contract is: say the endpoint rejected
			// what was presented, and name none of the three causes.
			harness.Assert(t, harness.Subject{
				Name:               "R-H1 " + tc.name,
				Report:             result.Report(),
				Incomplete:         result.Incomplete(),
				CredentialAttempts: authAttempts(t),
			}, harness.Expectation{
				Summary: harness.Status(domain.SummaryStatusProblemsFound),
				Nodes: []harness.Node{
					{
						Step:         stepAuth,
						State:        domain.StateFail,
						FailureClass: domain.FailureAuthCredentialsRejected,
					},
					{
						Step:         stepPing,
						State:        domain.StateSkipped,
						FailureClass: domain.FailureExecSkippedPrerequisiteFailed,
					},
				},
				RequireFindings: []domain.FindingCode{diagnosisredis.CodeCredentialsRejected},
				ForbidFindings:  []domain.FindingCode{diagnosisredis.CodeCommandNotPermitted},
				// The detail deliberately *enumerates* the three causes in
				// order to say svcdoctor cannot tell them apart, so the
				// enumeration is the honest refusal and must not be banned.
				// What is banned is the assertive form of each — naming one of
				// the three as what happened.
				RequireProse: []string{"cannot tell which of the three occurred"},
				ForbidProse: []string{
					"the password is wrong", "the password is incorrect",
					"the user does not exist", "no such user",
					"the user is disabled", "the account is disabled",
					"redis is unhealthy",
				},
				ForbidSecrets:         []string{tc.password},
				MaxCredentialAttempts: harness.Count(1),
			})
		})
	}
}

// R-03 — an ACL user that may run the probe.
func TestR03ACLUserWithPermission(t *testing.T) {
	if got := groundTruth(t, "svcd-redis-acl", "AUTH", "app", "app-pw"); got != "OK" {
		t.Fatalf("ground truth: AUTH app answered %q, want OK", got)
	}
	// The ACL server is plaintext, so a successful credentialed run is measured
	// on the TLS server instead. What R-03 proves here is the ACL matrix itself,
	// which the ground truth above establishes, plus that svcdoctor withholds
	// rather than sending over a channel that does not satisfy the policy.
	result := run(t, runOptions{port: portACL, username: "app", password: "app-pw"})
	if got := oneNodeAt(t, result, stepAuth).FailureClass(); got != domain.FailureExecSkippedByPolicy {
		t.Fatalf("failure class = %s, want EXEC_SKIPPED_BY_POLICY", got)
	}
}

// R-06 — the nopass semantics ADR 0064 section 5 rests on.
//
// This is the scenario that proves the two AUTH forms are not interchangeable,
// and it is proved by the server rather than by reading the source.
func TestR06NopassSemantics(t *testing.T) {
	twoArg := groundTruth(t, "svcd-redis-acl", "AUTH", "default", "any-nonsense-at-all")
	oneArg := groundTruth(t, "svcd-redis-acl", "AUTH", "any-nonsense-at-all")

	if twoArg != "OK" {
		t.Fatalf("ground truth: AUTH default <garbage> answered %q, want OK.\n\n"+
			"ADR 0064 section 6 rests on this: a +OK never means the credential is "+
			"correct.", twoArg)
	}
	if !strings.Contains(oneArg, "without any password configured") {
		t.Fatalf("ground truth: the one-argument form answered %q, want the "+
			"no-password-configured error", oneArg)
	}
	if twoArg == oneArg {
		t.Fatal("ground truth: the two AUTH forms answered identically; ADR 0064 " +
			"section 5's reason for sending the operator's form verbatim would be false")
	}
}

// R-07 — an authenticated identity that may not run the probe.
func TestR07PingNotPermitted(t *testing.T) {
	truth := groundTruth(t, "svcd-redis-acl", "--no-auth-warning",
		"-u", "redis://noperm:noperm-pw@127.0.0.1:6379", "PING")
	if !strings.HasPrefix(truth, "NOPERM") {
		t.Fatalf("ground truth: noperm's PING answered %q, want NOPERM", truth)
	}

	// The same least-privilege user, now over TLS where the credential-transport
	// policy permits svcdoctor to authenticate at all. Before the `noperm` user
	// was declared on the TLS server this run authenticated as `default` and the
	// NOPERM path was never measured end to end.
	truthTLS := groundTruth(t, "svcd-redis-tls", "--tls",
		"--cacert", "/etc/redis-certs/server.crt", "--no-auth-warning",
		"--user", "noperm", "--pass", "noperm-pw", "PING")
	if !strings.HasPrefix(truthTLS, "NOPERM") {
		t.Fatalf("ground truth: noperm's PING over TLS answered %q, want NOPERM", truthTLS)
	}

	resetAuthStats(t)

	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS,
		username: "noperm", password: "noperm-pw", tls: trustFixtureCA(t),
	})

	// R-H2 (harness). Authentication succeeded and the probe was refused for
	// this identity. That is an authorization answer about one command, not a
	// service failure and not a credential failure — so the status stays OK and
	// the run stays complete.
	harness.Assert(t, harness.Subject{
		Name:               "R-H2 noperm",
		Report:             result.Report(),
		Incomplete:         result.Incomplete(),
		CredentialAttempts: authAttempts(t),
	}, harness.Expectation{
		Summary:    harness.Status(domain.SummaryStatusOK),
		Incomplete: harness.Complete(),
		Nodes: []harness.Node{
			{
				Step:         stepAuth,
				State:        domain.StatePass,
				FailureClass: domain.FailureNone,
			},
			{
				Step:         stepPing,
				State:        domain.StateUnknown,
				FailureClass: domain.FailureAuthzDenied,
			},
		},
		RequireFindings: []domain.FindingCode{diagnosisredis.CodeCommandNotPermitted},
		ForbidFindings: []domain.FindingCode{
			diagnosisredis.CodeCredentialsRejected,
			diagnosisredis.CodePingNotCompleted,
			diagnosisredis.CodeEndpointNotServing,
		},
		ForbidProse: []string{
			"redis is unhealthy", "the service failed", "wrong password",
			"credential was rejected", "the endpoint is down",
		},
		ForbidSecrets:         []string{"noperm-pw"},
		MaxCredentialAttempts: harness.Count(1),
	})
}

// authAttempts reads the endpoint's own AUTH counter and returns what svcdoctor
// contributed.
//
// # The measurement excludes the instrument
//
// Reading `INFO commandstats` requires authenticating, so the reading itself
// increments the counter it is reading — the defect R-13 already recorded. The
// reset happens before svcdoctor runs and the reading happens after, so the
// total is svcdoctor's attempts plus exactly one for this call.
func authAttempts(t *testing.T) *int {
	t.Helper()
	stats := tlsGroundTruth(t, "INFO", "commandstats")
	n := authCalls(stats) - 1
	if n < 0 {
		n = 0
	}
	return &n
}

// R-08 — TLS with a verified identity.
func TestR08TLSVerified(t *testing.T) {
	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS, tls: trustFixtureCA(t),
	})
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

// R-09 — a certificate no trust source accepts.
func TestR09TLSUnknownAuthority(t *testing.T) {
	rogue := x509.NewCertPool()
	pem, err := os.ReadFile("env/certs/rogue.crt")
	if err != nil {
		t.Fatalf("reading the rogue certificate: %v", err)
	}
	if !rogue.AppendCertsFromPEM(pem) {
		t.Fatal("the rogue certificate did not parse")
	}

	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS,
		tls: &transport.TLSOptions{RootCAs: rogue, ServerName: "redis.svcdoctor.test"},
	})
	node := oneNodeAt(t, result, stepTLS)
	if node.FailureClass() != domain.FailureTLSUnknownAuthority {
		t.Fatalf("failure class = %s, want TLS_UNKNOWN_AUTHORITY", node.FailureClass())
	}
	if hasNodeAt(t, result, stepHello) {
		t.Error("a failed handshake produced a protocol node")
	}
}

// R-10 — a trusted certificate for the wrong name.
//
// Trust and identity are different facts, and this is the scenario that keeps
// them apart: the chain verifies and the name does not match.
func TestR10TLSHostnameMismatch(t *testing.T) {
	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS,
		tls: &transport.TLSOptions{
			RootCAs:    fixtureCAPool(t),
			ServerName: "not-the-name.svcdoctor.test",
		},
	})
	node := oneNodeAt(t, result, stepTLS)
	if node.FailureClass() != domain.FailureTLSHostnameMismatch {
		t.Fatalf("failure class = %s, want TLS_HOSTNAME_MISMATCH; trust and identity "+
			"must not collapse into one another", node.FailureClass())
	}
}

// R-11 — an IPv4 literal resolves nothing and records no DNS node.
func TestR11IPv4LiteralCreatesNoDNSNode(t *testing.T) {
	result := run(t, runOptions{host: "127.0.0.1", port: portBaseline})
	if hasNodeAt(t, result, stepDNS) {
		t.Fatal("an address literal produced a dns.lookup node; ADR 0059 makes the " +
			"absence structural rather than suppressed")
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", got)
	}
}

// R-12 — the same for IPv6, when the environment genuinely provides it.
//
// It is skipped rather than faked when loopback IPv6 does not reach the
// published port: a scenario that quietly rewrote itself to IPv4 would report a
// pass for something nobody measured.
func TestR12IPv6Literal(t *testing.T) {
	conn, err := net.DialTimeout("tcp", "[::1]:56379", 2*time.Second)
	if err != nil {
		t.Skipf("this environment does not publish the fixture on ::1 (%v); "+
			"skipping rather than measuring IPv4 and calling it IPv6", err)
	}
	_ = conn.Close()

	result := run(t, runOptions{host: "::1", port: portBaseline})
	if hasNodeAt(t, result, stepDNS) {
		t.Fatal("an IPv6 literal produced a dns.lookup node")
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", got)
	}
}

// R-13 — a credential and a plaintext channel. Zero credential bytes.
func TestR13PlaintextCredentialWithheld(t *testing.T) {
	// The counter is reset first, and the reset is the last thing that happens
	// before svcdoctor runs.
	//
	// An earlier version of this scenario compared a before and an after reading
	// and failed: `redis-cli -a` authenticates, so the *reading* incremented the
	// counter it was reading. The measurement has to exclude the instrument.
	groundTruth(t, "svcd-redis-pw", "-a", "s3cr3t-pw", "CONFIG", "RESETSTAT")

	result := run(t, runOptions{port: portPassword, password: "s3cr3t-pw"})

	node := oneNodeAt(t, result, stepAuth)
	if node.State() != domain.StateSkipped ||
		node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Fatalf("state/class = %s/%s, want SKIPPED/EXEC_SKIPPED_BY_POLICY",
			node.State(), node.FailureClass())
	}
	if !hasCode(result, diagnosisredis.CodeCredentialWithheld) {
		t.Fatalf("findings %v, want REDIS_CREDENTIAL_WITHHELD", codes(result))
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: withholding is svcdoctor's decision, not a "+
			"target defect", result.Report().Summary().Status())
	}
	if strings.Contains(findingText(result), "s3cr3t-pw") {
		t.Fatal("the credential appeared in the report")
	}

	// The endpoint's own accounting. Exactly one AUTH exists afterwards, and it
	// is this reading's own: svcdoctor contributed none.
	after := groundTruth(t, "svcd-redis-pw", "-a", "s3cr3t-pw", "INFO", "commandstats")
	if got := authCalls(after); got != 1 {
		t.Fatalf("the endpoint recorded %d AUTH calls, want exactly 1 (this reading's "+
			"own).\n\nA policy refusal must write zero credential bytes.", got)
	}
}

// R-14 — TLS with verification disabled is still an unverified channel.
func TestR14TLSInsecureCredentialWithheld(t *testing.T) {
	result := run(t, runOptions{
		host: "127.0.0.1", port: portTLS, password: "tls-pw",
		tls: &transport.TLSOptions{InsecureSkipVerify: true},
	})

	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StatePass {
		t.Fatalf("tls state = %s, want PASS: the handshake completes, it just proves "+
			"nothing about who answered", got)
	}
	node := oneNodeAt(t, result, stepAuth)
	if node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Fatalf("failure class = %s, want EXEC_SKIPPED_BY_POLICY", node.FailureClass())
	}
	if !result.Report().Security().TLSVerificationDisabled() {
		t.Error("the report does not record that verification was disabled")
	}
	if strings.Contains(findingText(result), "tls-pw") {
		t.Fatal("the credential appeared in the report")
	}
}

// R-15 — a replica reports its role, and nothing turns it into a problem.
func TestR15ReplicaRoleIsObservationOnly(t *testing.T) {
	truth := groundTruth(t, "svcd-redis-replica", "HELLO")
	if !strings.Contains(truth, "replica") {
		t.Fatalf("ground truth: the replica's HELLO did not report a replica role:\n%s", truth)
	}

	result := run(t, runOptions{port: portReplica})

	node := oneNodeAt(t, result, stepHello)
	if role, _ := attrOf(t, node, serviceredis.AttrRole); role != "replica" {
		t.Fatalf("observed role = %q, want replica", role)
	}
	if len(result.Report().Findings()) != 0 {
		t.Fatalf("role=replica produced findings %v; without an expected-role contract "+
			"it is an observation", codes(result))
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
}

// R-16 — a cluster-mode node completes the BASIC journey, and no topology is
// measured.
func TestR16ClusterModeDirectNode(t *testing.T) {
	truth := groundTruth(t, "svcd-redis-cluster", "HELLO")
	if !strings.Contains(truth, "cluster") {
		t.Fatalf("ground truth: the cluster node's HELLO did not report cluster mode:\n%s", truth)
	}

	result := run(t, runOptions{port: portCluster})

	node := oneNodeAt(t, result, stepHello)
	if mode, _ := attrOf(t, node, serviceredis.AttrMode); mode != "cluster" {
		t.Fatalf("observed mode = %q, want cluster", mode)
	}
	if got := oneNodeAt(t, result, stepPing).State(); got != domain.StatePass {
		t.Errorf("ping state = %s, want PASS: a keyless command is never redirected", got)
	}
	if len(result.Report().Findings()) != 0 {
		t.Fatalf("mode=cluster produced findings %v; topology is not measured", codes(result))
	}
	for _, n := range result.Report().Graph().Nodes() {
		step := n.Step().String()
		if strings.Contains(step, "topology") || strings.Contains(step, "shard") ||
			strings.Contains(step, "slot") || strings.Contains(step, "node") {
			t.Errorf("a topology node %s exists; v1 measures none", step)
		}
	}
	assertNoKeyspaceCommandReached(t, "svcd-redis-cluster")
}

// R-17 — the Sentinel guard, against a real Sentinel.
//
// This is the scenario the guard exists for: the Sentinel answers PING, so
// without it the run would report a healthy data endpoint.
func TestR17SentinelDetection(t *testing.T) {
	if got := groundTruth(t, "svcd-redis-sentinel", "-p", "26379", "PING"); got != "PONG" {
		t.Fatalf("ground truth: the Sentinel answered %q, want PONG.\n\n"+
			"If a Sentinel stopped answering PING, the guard's whole reason would "+
			"have changed.", got)
	}

	result := run(t, runOptions{port: portSentinel})

	node := oneNodeAt(t, result, stepHello)
	if mode, _ := attrOf(t, node, serviceredis.AttrMode); mode != "sentinel" {
		t.Fatalf("observed mode = %q, want sentinel", mode)
	}
	if _, ok := attrOf(t, node, serviceredis.AttrRole); ok {
		t.Error("a Sentinel reply carries no role field")
	}
	if !hasCode(result, diagnosisredis.CodeEndpointIsSentinel) {
		t.Fatalf("findings %v, want REDIS_ENDPOINT_IS_SENTINEL", codes(result))
	}
	if hasNodeAt(t, result, stepPing) {
		t.Fatal("the run probed usability on a Sentinel; the journey must stop at the guard")
	}
	if hasNodeAt(t, result, stepAuth) {
		t.Fatal("the run reached the credential boundary on a Sentinel")
	}
	if result.Report().Summary().Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", result.Report().Summary().Status())
	}

	// The finding names quorum and health **in order to disclaim them**, which is
	// the honest thing for it to do: an operator who reaches a Sentinel will
	// wonder about both. So the assertion is that neither is claimed, not that
	// neither is mentioned — the same distinction the diagnosis suite draws for
	// the merged WRONGPASS causes.
	text := strings.ToLower(findingText(result))
	for _, word := range []string{"quorum", "unhealthy"} {
		if !strings.Contains(text, word) {
			continue
		}
		if !strings.Contains(text, "not a claim") {
			t.Errorf("the report mentions %q about a Sentinel without disclaiming it", word)
		}
	}
	for _, forbidden := range []string{"sentinel is healthy", "quorum is met", "redis is healthy"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the report claims %q, which svcdoctor did not measure", forbidden)
		}
	}
}

// R-18 — a local budget expiring is not a remote failure.
//
// INJECTED: the endpoint is a listener that accepts and never answers. It is
// labelled injected because nothing organic produced it.
func TestR18LocalTimeoutIsNotARemoteFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn // accepted, never answered
		}
	}()

	addr := listener.Addr().(*net.TCPAddr)
	result := run(t, runOptions{
		host: "127.0.0.1", port: uint16(addr.Port), timeout: 3 * time.Second,
	})

	node := oneNodeAt(t, result, stepHello)
	if node.State() != domain.StateUnknown {
		t.Fatalf("hello state = %s, want UNKNOWN", node.State())
	}
	switch node.FailureClass() {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
	default:
		t.Fatalf("failure class = %s, want a local execution class", node.FailureClass())
	}
	if !result.Incomplete() {
		t.Error("a run cut short by its own budget must report incomplete")
	}
	if hasCode(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Error("a local budget produced a target-side finding")
	}
}

// R-19 — a refused connection stays vantage-relative.
//
// INJECTED: a port nothing listens on.
func TestR19ConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	_ = listener.Close() // the port is now closed

	result := run(t, runOptions{host: "127.0.0.1", port: uint16(addr.Port)})

	node := oneNodeAt(t, result, stepTCP)
	if node.State() != domain.StateFail {
		t.Fatalf("tcp state = %s, want FAIL", node.State())
	}
	if node.FailureClass() != domain.FailureTCPConnectionRefused {
		t.Fatalf("failure class = %s, want TCP_CONNECTION_REFUSED", node.FailureClass())
	}
	if hasNodeAt(t, result, stepHello) {
		t.Error("a refused connection produced a protocol node")
	}
}

// R-20 — the Redis default, tls-auth-clients yes.
//
// svcdoctor presents no client certificate (ADR 0064 section 8), so the
// connection cannot be used. What this scenario pins is that the failure is
// truthful and imprecise rather than an overclaim.
//
// # A measured correction to ADR 0064 section 8
//
// That section predicted the outcome would be a handshake alert landing on
// TLS_HANDSHAKE_FAILURE. Measured here against Redis 8.2.1, it is not: under
// TLS 1.3 the client finishes the handshake before the server evaluates the
// certificate it asked for, so **the handshake passes and the server closes the
// connection on the first read**. Ground truth agrees — `redis-cli --tls`
// without a client certificate reports "Server closed the connection".
//
// The decision is unaffected: mTLS stays deferred, and the case is still
// truthful-but-imprecise rather than an overclaim. Only the predicted landing
// spot was wrong, and it is recorded here rather than quietly corrected.
func TestR20MutualTLSRequiredIsATruthfulFailure(t *testing.T) {
	truth := groundTruth(t, "svcd-redis-mtls", "--tls", "--cacert",
		"/etc/redis-certs/server.crt", "PING")
	if !strings.Contains(truth, "closed") && !strings.Contains(truth, "reset") {
		t.Fatalf("ground truth: a certificate-less client got %q; this scenario assumes "+
			"the server refuses one", truth)
	}

	result := run(t, runOptions{
		host: "127.0.0.1", port: portMTLS, tls: trustFixtureCA(t),
	})

	// The handshake completes. That is not svcdoctor being wrong: an encrypted
	// channel really was established, and the server's objection arrives after it.
	if got := oneNodeAt(t, result, stepTLS).State(); got != domain.StatePass {
		t.Fatalf("tls state = %s, want PASS under TLS 1.3", got)
	}

	node := oneNodeAt(t, result, stepHello)
	if node.State() != domain.StateFail {
		t.Fatalf("hello state = %s, want FAIL", node.State())
	}
	if node.FailureClass() != domain.FailureProtocolPeerClosed {
		t.Fatalf("failure class = %s, want PROTOCOL_PEER_CLOSED", node.FailureClass())
	}
	if !hasCode(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Fatalf("findings %v, want REDIS_PROTOCOL_NOT_ESTABLISHED", codes(result))
	}

	text := strings.ToLower(findingText(result))
	for _, forbidden := range []string{"unhealthy", "server is down", "wrong password",
		"certificate is untrusted"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the report claims %q about an exchange that did not complete", forbidden)
		}
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

// trustFixtureCA trusts the fixture certificate and verifies the name it holds.
//
// The connection is made to 127.0.0.1 because the fixture name is not in any
// resolver, and the identity is verified against the name because that is what
// the certificate carries. --host decides where svcdoctor connects and
// --tls-server-name decides whose identity it expects there (ADR 0058); this is
// that surface, used as an operator would.
func trustFixtureCA(t *testing.T) *transport.TLSOptions {
	t.Helper()
	return &transport.TLSOptions{
		RootCAs:    fixtureCAPool(t),
		ServerName: "redis.svcdoctor.test",
	}
}

// authCalls reads the AUTH counter out of INFO commandstats.
func authCalls(stats string) int {
	for _, line := range strings.Split(stats, "\n") {
		if !strings.HasPrefix(line, "cmdstat_auth:") {
			continue
		}
		for _, field := range strings.Split(line, ",") {
			if strings.HasPrefix(field, "cmdstat_auth:calls=") {
				var n int
				_, _ = fmt.Sscan(strings.TrimPrefix(field, "cmdstat_auth:calls="), &n)
				return n
			}
			if strings.HasPrefix(field, "calls=") {
				var n int
				_, _ = fmt.Sscan(strings.TrimPrefix(field, "calls="), &n)
				return n
			}
		}
	}
	return 0
}

// tlsGroundTruth runs one redis-cli command against the TLS server as default.
func tlsGroundTruth(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"--tls", "--cacert", "/etc/redis-certs/server.crt",
		"--no-auth-warning", "-a", "tls-pw"}, args...)
	return groundTruth(t, "svcd-redis-tls", full...)
}

// resetAuthStats zeroes the TLS server's command counters.
func resetAuthStats(t *testing.T) {
	t.Helper()
	tlsGroundTruth(t, "CONFIG", "RESETSTAT")
}
