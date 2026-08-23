//go:build integration

package postgres

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7, against real servers.
//
// The rest of this suite has always targeted `127.0.0.1`, so it has been
// exercising the address-literal path since Phase 4 without anybody saying so.
// These tests make the two shapes explicit and measure both against the same
// running PostgreSQL: an address resolves nothing, a name resolves, and both
// reach `ReadyForQuery`.
//
// # The hostname used, and why it is `localhost`
//
// It is the one name guaranteed to resolve on any machine that can run this
// suite, and the containers publish on every interface, so both of its addresses
// accept a connection. That is deliberately *more* than the literal case
// exercises: a real multi-address sweep, over a real resolver, with two real
// sockets.
//
// The fixture certificate carries `DNS:localhost`, `IP:127.0.0.1` and `IP:::1`,
// so every shape below verifies against a real SAN of the right kind: a name
// against a DNS SAN, and each address against its own IP SAN. That is the part a
// fixture cannot fake, and it is why the certificate gained the IPv6 SAN in this
// phase.
const pgHostname = "localhost"

// literalParams is runParams with the host and port replaced, so a literal and a
// name differ in exactly one input.
func hostParams(t *testing.T, host string, port uint16, plan postgres.TLSPlan) app.PostgresParams {
	t.Helper()

	vantage, err := domain.NewLocalVantage("svcdoctor-integration")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	params := app.PostgresParams{
		Host: host, Port: port,
		Role: scramRole, Database: database,
		Resolver: dns.SystemResolver{}, Dialer: tcp.SystemDialer{},
		TLS:         plan,
		StepTimeout: 10 * time.Second,
		Vantage:     vantage,
		Version:     "0.1.0-integration",
	}
	if plan == postgres.TLSRequired {
		params.TLSOptions = postgres.TLSOptions{ServerName: host, RootCAs: rootCAs(t)}
	}
	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = credential
	return params
}

func diagnose(t *testing.T, params app.PostgresParams) domain.Report {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	result, err := app.DiagnosePostgres(ctx, params)
	if err != nil {
		t.Fatalf("DiagnosePostgres(%s): %v", params.Host, err)
	}
	return result.Report()
}

func stepsPresent(report domain.Report) map[domain.Step]int {
	out := map[domain.Step]int{}
	for _, node := range report.Graph().Nodes() {
		out[node.Step()]++
	}
	return out
}

// TestAppSkipsResolutionForALiteral is the headline, measured rather than
// asserted from a fixture: a real run against a real server, over a real socket,
// that performed no name resolution and says so.
func TestAppSkipsResolutionForALiteral(t *testing.T) {
	report := diagnose(t, hostParams(t, pgHost, pgTLSPort, postgres.TLSRequired))

	steps := stepsPresent(report)
	if n := steps[vocabulary.StepDNSLookup]; n != 0 {
		t.Fatalf("a literal target produced %d dns.lookup nodes, want 0", n)
	}
	for _, node := range report.Graph().Nodes() {
		if node.Layer() == domain.LayerDNS {
			t.Fatalf("a literal target produced an L1 node: %s", node.ID())
		}
	}

	// Non-vacuity: the run really did reach a session over that socket.
	if n := steps[servicepostgres.StepSession]; n != 1 {
		t.Fatalf("session nodes = %d, want 1: the run did not get far enough to prove anything", n)
	}
	for _, node := range report.Graph().Nodes() {
		if node.Step() == servicepostgres.StepSession && node.State() != domain.StatePass {
			t.Fatalf("session state = %s, want PASS", node.State())
		}
	}

	// And no finding says anything about a hostname.
	for _, f := range report.Findings() {
		if strings.HasPrefix(string(f.Code()), "DNS_") {
			t.Errorf("a literal run produced %s", f.Code())
		}
		if strings.Contains(f.Summary()+f.Detail(), "hostname") {
			t.Errorf("%s mentions a hostname on a run with no name in it", f.Code())
		}
	}
}

// TestAppResolvesAHostname is the other half, against the same server: a name
// still produces a real L1 measurement with real answers.
func TestAppResolvesAHostname(t *testing.T) {
	if _, err := net.LookupHost(pgHostname); err != nil {
		t.Skipf("%s does not resolve in this environment: %v", pgHostname, err)
	}

	report := diagnose(t, hostParams(t, pgHostname, pgTLSPort, postgres.TLSRequired))

	lookups := 0
	for _, node := range report.Graph().Nodes() {
		if node.Step() != vocabulary.StepDNSLookup {
			continue
		}
		lookups++
		if node.State() != domain.StatePass {
			t.Fatalf("dns.lookup state = %s (%s), want PASS", node.State(), node.FailureClass())
		}
		answers, ok := node.Attribute("dns.answers")
		if !ok {
			t.Fatal("a passing lookup recorded no answers")
		}
		list, _ := answers.HostList()
		if len(list) == 0 {
			t.Fatal("a passing lookup recorded an empty answer list")
		}
		t.Logf("%s resolved to %v", pgHostname, list)
	}
	if lookups != 1 {
		t.Fatalf("dns.lookup nodes = %d, want 1", lookups)
	}

	// The session still establishes, so the resolving shape is not merely
	// present but working.
	sessions := 0
	for _, node := range report.Graph().Nodes() {
		if node.Step() == servicepostgres.StepSession && node.State() == domain.StatePass {
			sessions++
		}
	}
	if sessions == 0 {
		t.Fatal("the hostname run established no session")
	}
}

// TestAppMeasuresAnIPv6Literal is real IPv6, over a real socket, against the
// real server.
//
// The containers publish on `[::]`, so `::1` reaches them. If this environment
// has no IPv6 loopback the test skips rather than pretending: an unreachable
// address family is a property of the machine, not of svcdoctor.
func TestAppMeasuresAnIPv6Literal(t *testing.T) {
	if !ipv6LoopbackReachable(t, pgTLSPort) {
		t.Skip("no IPv6 loopback route to the fixture in this environment")
	}

	report := diagnose(t, hostParams(t, "::1", pgTLSPort, postgres.TLSRequired))

	if report.Target().Requested() != "[::1]:"+strconv.Itoa(int(pgTLSPort)) {
		t.Fatalf("report target = %q, want a bracketed IPv6 endpoint", report.Target().Requested())
	}
	for _, node := range report.Graph().Nodes() {
		if node.Step() == vocabulary.StepDNSLookup {
			t.Fatalf("an IPv6 literal produced %s", node.ID())
		}
		ref := node.Subject().Ref()
		if strings.Contains(ref, "[[") || strings.Contains(ref, "]]") {
			t.Errorf("%s has a double-bracketed subject %q", node.ID(), ref)
		}
	}

	// The handshake verified `::1` against the certificate's IPv6 SAN — a real
	// IP-SAN verification, in the family that is easiest to get wrong.
	handshakes := 0
	for _, node := range report.Graph().Nodes() {
		if node.Step() != vocabulary.StepTLSHandshake {
			continue
		}
		handshakes++
		if node.State() != domain.StatePass {
			t.Fatalf("tls.handshake state = %s (%s), want PASS against the IPv6 SAN",
				node.State(), node.FailureClass())
		}
		name, ok := node.Attribute("tls.server_name")
		if !ok {
			t.Fatal("the handshake recorded no server name")
		}
		if got, _ := name.Host(); got != "::1" {
			t.Fatalf("tls.server_name = %q, want the bare literal \"::1\"", got)
		}
		verified, ok := node.Attribute("tls.verified")
		if !ok {
			t.Fatal("the handshake recorded no tls.verified attribute")
		}
		if b, _ := verified.Bool(); !b {
			t.Fatal("the IPv6 handshake did not verify the peer")
		}
	}
	if handshakes == 0 {
		t.Fatal("the IPv6 run performed no handshake")
	}

	sessions := 0
	for _, node := range report.Graph().Nodes() {
		if node.Step() == servicepostgres.StepSession && node.State() == domain.StatePass {
			sessions++
		}
	}
	if sessions == 0 {
		t.Fatal("the IPv6 literal run established no session")
	}
}

// TestALiteralAndItsNameReachTheSameServer measures both shapes against the same
// listener in one test, so the comparison is a fact rather than an inference
// across two runs.
func TestALiteralAndItsNameReachTheSameServer(t *testing.T) {
	if _, err := net.LookupHost(pgHostname); err != nil {
		t.Skipf("%s does not resolve in this environment: %v", pgHostname, err)
	}

	literal := diagnose(t, hostParams(t, pgHost, pgTLSPort, postgres.TLSRequired))
	named := diagnose(t, hostParams(t, pgHostname, pgTLSPort, postgres.TLSRequired))

	if stepsPresent(literal)[vocabulary.StepDNSLookup] != 0 {
		t.Error("the literal run resolved something")
	}
	if stepsPresent(named)[vocabulary.StepDNSLookup] != 1 {
		t.Error("the hostname run resolved nothing")
	}

	// Both establish a session, and both report OK: the difference between the
	// two shapes is one L1 node, not the outcome.
	for name, report := range map[string]domain.Report{"literal": literal, "hostname": named} {
		if report.Summary().Status() != domain.SummaryStatusOK {
			t.Errorf("%s run status = %s, want OK: %v",
				name, report.Summary().Status(), codesIn(report))
		}
	}
}

// ipv6LoopbackReachable reports whether this machine can actually reach the
// fixture over `::1`.
func ipv6LoopbackReachable(t *testing.T, port uint16) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp6", net.JoinHostPort("::1", strconv.Itoa(int(port))))
	if err != nil {
		t.Logf("IPv6 loopback probe: %v", err)
		return false
	}
	_ = conn.Close()
	return true
}
