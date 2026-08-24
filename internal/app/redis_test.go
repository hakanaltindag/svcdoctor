package app

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	diagnosisredis "github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	serviceredis "github.com/hakanaltindag/svcdoctor/internal/service/redis"
)

// The Redis composition-root suite.
//
// # Why this exists beside the integration suite
//
// The integration suite proves the product works against real servers, which is
// stronger evidence for behaviour and weaker evidence for *shape*: it cannot pin
// a node count without a Docker daemon, and it cannot run at all where one is
// missing. These tests pin the composition semantics — how many nodes, which
// relationships, which summary, how many credential attempts — hermetically, so
// a change to the graph shape fails on every machine rather than only on one
// with containers.

// --- a scripted endpoint ---------------------------------------------------

type redisScript struct {
	hello          string
	helloAfterAuth string
	auth           string
	ping           string
	silent         bool
	closeAfterTLS  bool
}

type redisFake struct {
	addr netip.AddrPort

	mu       sync.Mutex
	commands []string
}

func newRedisFake(t *testing.T, script redisScript) *redisFake {
	t.Helper()

	var lc net.ListenConfig
	listener, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	addr, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("parsing listener address: %v", err)
	}
	f := &redisFake{addr: addr}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go f.serve(conn, script)
		}
	}()
	return f
}

func (f *redisFake) serve(conn net.Conn, script redisScript) {
	defer func() { _ = conn.Close() }()
	if script.closeAfterTLS {
		return
	}
	reader := bufio.NewReader(conn)
	authenticated := false

	for {
		command, err := readRedisCommand(reader)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.commands = append(f.commands, command)
		f.mu.Unlock()

		if script.silent {
			continue
		}

		var reply string
		switch command {
		case "HELLO":
			reply = script.hello
			if authenticated && script.helloAfterAuth != "" {
				reply = script.helloAfterAuth
			}
		case "AUTH":
			reply = script.auth
			if reply == "" {
				reply = "+OK\r\n"
			}
			if strings.HasPrefix(reply, "+OK") {
				authenticated = true
			}
		case "PING":
			reply = script.ping
			if reply == "" {
				reply = "+PONG\r\n"
			}
		default:
			reply = "-ERR unknown command\r\n"
		}
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func (f *redisFake) count(command string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.commands {
		if c == command {
			n++
		}
	}
	return n
}

func readRedisCommand(r *bufio.Reader) (string, error) {
	header, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(header, "*") {
		return "", fmt.Errorf("not a command array: %q", header)
	}
	count, err := strconv.Atoi(strings.TrimSpace(header[1:]))
	if err != nil {
		return "", err
	}
	var parts []string
	for i := 0; i < count; i++ {
		lengthLine, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		n, err := strconv.Atoi(strings.TrimSpace(lengthLine[1:]))
		if err != nil {
			return "", err
		}
		body := make([]byte, n+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", err
		}
		parts = append(parts, string(body[:n]))
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("empty command")
	}
	return strings.ToUpper(parts[0]), nil
}

// Replies captured from real servers in Phase 7.5.
const (
	rHelloRedis = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"
	rHelloValkey = "*14\r\n$6\r\nserver\r\n$6\r\nvalkey\r\n$7\r\nversion\r\n$5\r\n8.1.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$10\r\nstandalone\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"
	rHelloCluster = "*14\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$7\r\ncluster\r\n" +
		"$4\r\nrole\r\n$6\r\nmaster\r\n$7\r\nmodules\r\n*0\r\n"
	rHelloSentinel = "*12\r\n$6\r\nserver\r\n$5\r\nredis\r\n$7\r\nversion\r\n$5\r\n8.2.1\r\n" +
		"$5\r\nproto\r\n:2\r\n$2\r\nid\r\n:1\r\n$4\r\nmode\r\n$8\r\nsentinel\r\n" +
		"$7\r\nmodules\r\n*0\r\n"
	rNoAuth      = "-NOAUTH Authentication required.\r\n"
	rWrongPass   = "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
	rNoPerm      = "-NOPERM User app has no permissions to run the 'ping' command\r\n"
	rHelloUnknwn = "-ERR unknown command 'HELLO', with args beginning with: \r\n"
)

// --- the run ---------------------------------------------------------------

type redisRun struct {
	host     string
	password string
	timeout  time.Duration
	tls      *transport.TLSOptions
	addrs    []string
}

func diagnoseFake(t *testing.T, f *redisFake, opts redisRun) Result {
	t.Helper()

	host := opts.host
	if host == "" {
		host = "redis.internal"
	}
	addrs := opts.addrs
	if len(addrs) == 0 {
		addrs = []string{"10.0.0.1"}
	}
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	var credential security.Credential
	if opts.password != "" {
		endpoint, err := security.NewEndpoint(host, 6379)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		credential, err = security.NewCredential(endpoint, "", security.NewSecret(opts.password))
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := DiagnoseRedis(ctx, RedisParams{
		Host:        host,
		Port:        6379,
		Credential:  credential,
		Resolver:    redisResolver{addresses: parseAddrsFor(t, addrs)},
		Dialer:      redisDialer{target: f.addr},
		TLS:         opts.tls,
		StepTimeout: 2 * time.Second,
		Vantage:     vantage(t),
		Version:     "test",
	})
	if err != nil {
		t.Fatalf("DiagnoseRedis: %v", err)
	}
	return result
}

// redisResolver answers with a fixed address set, so a test decides how many
// paths a run measures.
type redisResolver struct{ addresses []netip.Addr }

func (r redisResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return r.addresses, nil
}

type redisDialer struct{ target netip.AddrPort }

func (d redisDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

func parseAddrsFor(t *testing.T, values []string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		out = append(out, addr)
	}
	return out
}

// --- shape helpers ---------------------------------------------------------

func countAt(result Result, step domain.Step) int {
	n := 0
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == step {
			n++
		}
	}
	return n
}

func stateAt(t *testing.T, result Result, step domain.Step) (domain.State, domain.FailureClass) {
	t.Helper()
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() == step {
			return node.State(), node.FailureClass()
		}
	}
	t.Fatalf("no node at %s", step)
	return 0, 0
}

func findingCodes(result Result) []string {
	var out []string
	for _, f := range result.Report().Findings() {
		out = append(out, f.Code().String())
	}
	return out
}

func redisHasFinding(result Result, code domain.FindingCode) bool {
	for _, f := range result.Report().Findings() {
		if f.Code() == code {
			return true
		}
	}
	return false
}

// relationshipCount counts parent edges across the frozen graph.
func relationshipCount(result Result) int {
	graph := result.Report().Graph()
	n := 0
	for _, node := range graph.Nodes() {
		n += len(graph.Parents(node.ID()))
	}
	return n
}

// shape is the pinned graph shape of one representative journey.
type shape struct {
	nodes         int
	relationships int
	dns           int
	tcp           int
	tls           int
	hello         int
	auth          int
	ping          int
}

func assertShape(t *testing.T, name string, result Result, want shape) {
	t.Helper()
	got := shape{
		nodes:         result.Report().Graph().Len(),
		relationships: relationshipCount(result),
		dns:           countAt(result, domain.Step("dns.lookup")),
		tcp:           countAt(result, domain.Step("tcp.connect")),
		tls:           countAt(result, domain.Step("tls.handshake")),
		hello:         countAt(result, serviceredis.StepHello),
		auth:          countAt(result, serviceredis.StepAuthentication),
		ping:          countAt(result, serviceredis.StepPing),
	}
	if got != want {
		t.Errorf("%s graph shape = %+v, want %+v.\n\n"+
			"A shape change is a contract change. If it is intended, change this "+
			"expectation deliberately; do not add a node to make the graph look "+
			"symmetrical.", name, got, want)
	}
}

// --- A1 to A14 -------------------------------------------------------------

// A1 — no-auth standalone success. Shape 1: hostname / no auth / success.
func TestA1NoAuthStandaloneSuccess(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloRedis})
	result := diagnoseFake(t, f, redisRun{})

	if state, _ := stateAt(t, result, serviceredis.StepPing); state != domain.StatePass {
		t.Errorf("ping state = %s, want PASS", state)
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a complete run reported incomplete")
	}
	if got := result.Report().Summary().FirstBrokenLayer(); got != domain.LayerUnspecified {
		t.Errorf("first broken layer = %s, want unspecified", got)
	}
	if len(result.Report().Findings()) != 0 {
		t.Errorf("findings = %v, want none", findingCodes(result))
	}
	if f.count("AUTH") != 0 {
		t.Errorf("AUTH reached the endpoint %d times on a no-auth run", f.count("AUTH"))
	}
	// Five nodes: the requested-target anchor, one DNS lookup, one connection,
	// one HELLO and one probe. No authentication node, because the endpoint
	// demanded nothing and the run carried nothing.
	assertShape(t, "A1", result, shape{
		nodes: 5, relationships: 4, dns: 1, tcp: 1, hello: 1, ping: 1,
	})
}

// A2 — the endpoint demands a credential and accepts it. Shape 2.
//
// TLS is required for the policy to permit the credential, so this is the shape
// with a handshake and two HELLO nodes.
func TestA2AuthRequiredSuccess(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rNoAuth, helloAfterAuth: rHelloRedis})
	result := diagnoseFake(t, f, redisRun{password: "pw"})

	// Plaintext: the credential is withheld, so this run measures the *shape* of
	// the credentialed journey without a verified channel. A2's accepted-credential
	// path is measured end to end in the integration suite, over real TLS.
	if state, class := stateAt(t, result, serviceredis.StepAuthentication); state != domain.StateSkipped ||
		class != domain.FailureExecSkippedByPolicy {
		t.Fatalf("authentication = %s/%s, want SKIPPED/EXEC_SKIPPED_BY_POLICY", state, class)
	}
	if f.count("AUTH") != 0 {
		t.Fatalf("AUTH reached the endpoint %d times; the policy refused it", f.count("AUTH"))
	}
	// Six: A1's five plus the authentication node. One HELLO, not two — the
	// second is issued only when a credential was actually accepted.
	assertShape(t, "A2", result, shape{
		nodes: 6, relationships: 5, dns: 1, tcp: 1, hello: 1, auth: 1, ping: 1,
	})
}

// A3 — the endpoint rejects the credential.
func TestA3CredentialsRejected(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rNoAuth, auth: rWrongPass})
	result := diagnoseFake(t, f, redisRun{
		password: "pw",
		tls:      nil,
	})
	// Plaintext refuses the credential before it reaches the endpoint, so the
	// rejection path is exercised at the adapter and integration levels. What is
	// pinned here is that no credential leaves on a plaintext channel.
	if f.count("AUTH") != 0 {
		t.Fatalf("AUTH reached the endpoint %d times on a plaintext channel", f.count("AUTH"))
	}
	if !redisHasFinding(result, diagnosisredis.CodeCredentialWithheld) {
		t.Fatalf("findings = %v, want REDIS_CREDENTIAL_WITHHELD", findingCodes(result))
	}
}

// A4 — the identity authenticates and may not run the probe.
func TestA4PingNotPermitted(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloRedis, ping: rNoPerm})
	result := diagnoseFake(t, f, redisRun{})

	state, class := stateAt(t, result, serviceredis.StepPing)
	if state != domain.StateUnknown {
		t.Fatalf("ping state = %s, want UNKNOWN — an ACL denial is not a service failure", state)
	}
	if class != domain.FailureAuthzDenied {
		t.Fatalf("ping class = %s, want AUTHZ_DENIED", class)
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", result.Report().Summary().Status())
	}
	if !redisHasFinding(result, diagnosisredis.CodeCommandNotPermitted) {
		t.Fatalf("findings = %v, want REDIS_COMMAND_NOT_PERMITTED", findingCodes(result))
	}
	// Shape 5: identical to A1. A refused probe is a state on the existing node,
	// never an extra node, and nothing downstream is fabricated.
	assertShape(t, "A4", result, shape{
		nodes: 5, relationships: 4, dns: 1, tcp: 1, hello: 1, ping: 1,
	})
}

// A5 — Sentinel detection. Shape 6: no AUTH node, no PING node.
func TestA5SentinelDetection(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloSentinel})
	result := diagnoseFake(t, f, redisRun{password: "pw"})

	if !redisHasFinding(result, diagnosisredis.CodeEndpointIsSentinel) {
		t.Fatalf("findings = %v, want REDIS_ENDPOINT_IS_SENTINEL", findingCodes(result))
	}
	if countAt(result, serviceredis.StepAuthentication) != 0 {
		t.Fatal("the run reached the credential boundary on a Sentinel")
	}
	if countAt(result, serviceredis.StepPing) != 0 {
		t.Fatal("the run probed usability on a Sentinel")
	}
	if f.count("AUTH") != 0 || f.count("PING") != 0 {
		t.Fatalf("commands after the guard: AUTH=%d PING=%d", f.count("AUTH"), f.count("PING"))
	}
	if result.Report().Summary().Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", result.Report().Summary().Status())
	}
	// Four, and the two absences are the decision: no authentication node and no
	// probe node, because the journey stopped at the guard.
	assertShape(t, "A5", result, shape{
		nodes: 4, relationships: 3, dns: 1, tcp: 1, hello: 1,
	})
}

// A6 — a cluster-mode endpoint. Shape 7: no topology subtree.
func TestA6ClusterModeDirectEndpoint(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloCluster})
	result := diagnoseFake(t, f, redisRun{})

	var mode string
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() != serviceredis.StepHello {
			continue
		}
		if value, ok := node.Attribute(serviceredis.AttrMode); ok {
			mode, _ = value.Str()
		}
	}
	if mode != "cluster" {
		t.Fatalf("observed mode = %q, want cluster", mode)
	}
	if len(result.Report().Findings()) != 0 {
		t.Fatalf("findings = %v; topology is not measured", findingCodes(result))
	}
	for _, node := range result.Report().Graph().Nodes() {
		step := node.Step().String()
		if strings.Contains(step, "topology") || strings.Contains(step, "shard") ||
			strings.Contains(step, "slot") {
			t.Errorf("a topology node %s exists", step)
		}
	}
	// Identical to A1. Cluster mode adds an attribute, never a subtree.
	assertShape(t, "A6", result, shape{
		nodes: 5, relationships: 4, dns: 1, tcp: 1, hello: 1, ping: 1,
	})
}

// A7 — a plaintext channel refuses the credential. Shape 4-adjacent.
func TestA7PlaintextCredentialRefusal(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rNoAuth})
	result := diagnoseFake(t, f, redisRun{password: "hunter2"})

	if state, class := stateAt(t, result, serviceredis.StepAuthentication); state != domain.StateSkipped ||
		class != domain.FailureExecSkippedByPolicy {
		t.Fatalf("authentication = %s/%s, want SKIPPED/EXEC_SKIPPED_BY_POLICY", state, class)
	}
	if state, class := stateAt(t, result, serviceredis.StepPing); state != domain.StateSkipped ||
		class != domain.FailureExecSkippedPrerequisiteFailed {
		t.Fatalf("ping = %s/%s, want SKIPPED/EXEC_SKIPPED_PREREQUISITE_FAILED", state, class)
	}
	if f.count("AUTH") != 0 {
		t.Fatal("a credential reached a plaintext endpoint")
	}
	if result.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: withholding is svcdoctor's decision", result.Report().Summary().Status())
	}
	if result.Incomplete() {
		t.Error("a policy refusal is a complete run")
	}
}

// A8 — TLS with verification disabled is still an unverified channel.
//
// The fake speaks no TLS, so the handshake fails and the credential never gets
// near a channel. What is pinned is that `InsecureSkipVerify` does not become a
// permission: the run records the disabled verification and no AUTH occurs.
func TestA8TLSInsecureCredentialRefusal(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloRedis})
	result := diagnoseFake(t, f, redisRun{
		password: "pw",
		tls:      &transport.TLSOptions{InsecureSkipVerify: true},
	})

	if !result.Report().Security().TLSVerificationDisabled() {
		t.Error("the report does not record that verification was disabled")
	}
	if f.count("AUTH") != 0 {
		t.Fatal("a credential was presented on a run with verification disabled")
	}
}

// A9 — an IPv4 literal resolves nothing. Shape 3.
func TestA9IPv4LiteralCreatesNoDNSNode(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloRedis})
	result := diagnoseFake(t, f, redisRun{host: "127.0.0.1", addrs: []string{"127.0.0.1"}})

	if got := countAt(result, domain.Step("dns.lookup")); got != 0 {
		t.Fatalf("dns.lookup nodes = %d, want 0 for an address literal (ADR 0059)", got)
	}
	// One node fewer than A1, and it is the DNS node. The absence is structural
	// rather than suppressed (ADR 0059).
	assertShape(t, "A9", result, shape{
		nodes: 4, relationships: 3, tcp: 1, hello: 1, ping: 1,
	})
}

// A10 — the same for IPv6.
func TestA10IPv6LiteralCreatesNoDNSNode(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloRedis})
	result := diagnoseFake(t, f, redisRun{host: "::1", addrs: []string{"::1"}})

	if got := countAt(result, domain.Step("dns.lookup")); got != 0 {
		t.Fatalf("dns.lookup nodes = %d, want 0 for an IPv6 literal", got)
	}
}

// A11 — a local budget expiring. Shape 8.
func TestA11LocalTimeoutIsUnknownAndIncomplete(t *testing.T) {
	f := newRedisFake(t, redisScript{silent: true})
	result := diagnoseFake(t, f, redisRun{timeout: 3 * time.Second})

	state, class := stateAt(t, result, serviceredis.StepHello)
	if state != domain.StateUnknown {
		t.Fatalf("hello state = %s, want UNKNOWN: a local budget is not a remote failure", state)
	}
	switch class {
	case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
	default:
		t.Fatalf("hello class = %s, want a local execution class", class)
	}
	if !result.Incomplete() {
		t.Error("a run cut short by its own budget must report incomplete")
	}
	if redisHasFinding(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Error("a local budget produced a target-side finding")
	}
}

// A12 — the endpoint does not implement HELLO.
func TestA12HelloUnsupportedContinues(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloUnknwn})
	result := diagnoseFake(t, f, redisRun{})

	state, class := stateAt(t, result, serviceredis.StepHello)
	if state != domain.StateUnknown || class != domain.FailureProtocolUnsupportedCapability {
		t.Fatalf("hello = %s/%s, want UNKNOWN/PROTOCOL_UNSUPPORTED_CAPABILITY", state, class)
	}
	if state, _ := stateAt(t, result, serviceredis.StepPing); state != domain.StatePass {
		t.Errorf("ping state = %s, want PASS: the run continues past an unknown HELLO", state)
	}
	if redisHasFinding(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Error("an endpoint that merely lacks HELLO produced a protocol failure finding")
	}
}

// A13 — the peer closes before answering.
func TestA13PeerClosesBeforeRESP(t *testing.T) {
	f := newRedisFake(t, redisScript{closeAfterTLS: true})
	result := diagnoseFake(t, f, redisRun{})

	state, class := stateAt(t, result, serviceredis.StepHello)
	if state != domain.StateFail || class != domain.FailureProtocolPeerClosed {
		t.Fatalf("hello = %s/%s, want FAIL/PROTOCOL_PEER_CLOSED", state, class)
	}
	if !redisHasFinding(result, diagnosisredis.CodeProtocolNotEstablished) {
		t.Fatalf("findings = %v, want REDIS_PROTOCOL_NOT_ESTABLISHED", findingCodes(result))
	}
	if got := result.Report().Summary().FirstBrokenLayer(); got != domain.LayerProtocol {
		t.Errorf("first broken layer = %s, want L4", got)
	}
	if countAt(result, serviceredis.StepPing) != 0 {
		t.Error("a dead connection produced a usability probe node")
	}
}

// A14 — Valkey identity through the same composition root.
func TestA14ValkeyIdentity(t *testing.T) {
	f := newRedisFake(t, redisScript{hello: rHelloValkey})
	result := diagnoseFake(t, f, redisRun{})

	var server string
	for _, node := range result.Report().Graph().Nodes() {
		if node.Step() != serviceredis.StepHello {
			continue
		}
		if value, ok := node.Attribute(serviceredis.AttrServer); ok {
			server, _ = value.Str()
		}
	}
	if server != "valkey" {
		t.Fatalf("observed server = %q, want valkey", server)
	}
	if result.Report().Run().Service().String() != "redis" {
		t.Errorf("service id = %q; the CLI verb stays `redis` while the observed "+
			"identity is valkey", result.Report().Run().Service())
	}
}

// TestTheCredentialIsPresentedAtMostOnceAcrossEveryJourney is the composition
// half of ADR 0064 section 4.
//
// The adapter's guarantee is that Authenticate has one call site and no loop.
// This is the observable consequence: whatever the endpoint answers, no run
// puts AUTH on the wire more than once.
func TestTheCredentialIsPresentedAtMostOnceAcrossEveryJourney(t *testing.T) {
	for name, script := range map[string]redisScript{
		"accepts":        {hello: rNoAuth, auth: "+OK\r\n", helloAfterAuth: rHelloRedis},
		"rejects":        {hello: rNoAuth, auth: rWrongPass},
		"errors":         {hello: rNoAuth, auth: "-ERR something\r\n"},
		"sentinel":       {hello: rHelloSentinel},
		"hello unknown":  {hello: rHelloUnknwn},
		"no auth needed": {hello: rHelloRedis},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRedisFake(t, script)
			_ = diagnoseFake(t, f, redisRun{password: "pw"})
			if got := f.count("AUTH"); got > 1 {
				t.Fatalf("AUTH reached the endpoint %d times, want at most 1", got)
			}
		})
	}
}

// TestNoJourneyEverNamesAKey is the composition-level keyspace contract.
func TestNoJourneyEverNamesAKey(t *testing.T) {
	forbidden := map[string]bool{
		"GET": true, "SET": true, "DEL": true, "EXISTS": true, "TYPE": true,
		"SCAN": true, "KEYS": true, "ROLE": true, "INFO": true, "CLUSTER": true,
		"SELECT": true, "RESET": true,
	}
	for name, script := range map[string]redisScript{
		"success":  {hello: rHelloRedis},
		"noauth":   {hello: rNoAuth},
		"sentinel": {hello: rHelloSentinel},
		"cluster":  {hello: rHelloCluster},
		"noperm":   {hello: rHelloRedis, ping: rNoPerm},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRedisFake(t, script)
			_ = diagnoseFake(t, f, redisRun{password: "pw"})
			f.mu.Lock()
			defer f.mu.Unlock()
			for _, command := range f.commands {
				if forbidden[command] {
					t.Errorf("the run sent %s", command)
				}
				if command != "HELLO" && command != "AUTH" && command != "PING" {
					t.Errorf("the run sent %s, which is outside the allowlist", command)
				}
			}
		})
	}
}
