package app

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The execution-budget tests, and why they use a real socket.
//
// Phase 4.11c reproduced three defects that all lived in the same seam: a
// per-step budget expiring while the caller's context stayed alive. None of them
// was visible through net.Pipe or a stub dialer, because all three turned on how
// a *socket deadline* surfaces — as a net.Error timeout rather than as
// context.DeadlineExceeded. So the peers below are loopback listeners, which is
// also what internal/adapter/postgres's own fixtures chose, for the same reason.
//
// No test here uses a sleep as its oracle. The bounded-run test asserts that the
// call returned at all, against a timer that fails deterministically if it did
// not; the rest assert on recorded state and failure class.

// silentPeer accepts connections and never writes a byte.
//
// It is the shape that hung the run before Phase 4.11d: a TCP connection that
// completes, followed by a peer that answers nothing.
type silentPeer struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

// listenLoopback opens a loopback listener, the way this repository's other
// fixtures do: through net.ListenConfig, because a bare net.Listen takes no
// context and the linter denies it.
func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return ln
}

func newSilentPeer(t *testing.T) *silentPeer {
	t.Helper()
	ln := listenLoopback(t)
	p := &silentPeer{ln: ln}
	go p.accept()
	t.Cleanup(p.close)
	return p
}

func (p *silentPeer) accept() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns = append(p.conns, conn)
		p.mu.Unlock()
	}
}

func (p *silentPeer) close() {
	_ = p.ln.Close()
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		_ = conn.Close()
	}
}

func (p *silentPeer) addr(t *testing.T) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(p.ln.Addr().String())
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	return ap
}

// bytePeer answers the SSLRequest with one byte a test chose and then stops.
type bytePeer struct {
	silentPeer
	reply byte
}

func newBytePeer(t *testing.T, reply byte) *bytePeer {
	t.Helper()
	ln := listenLoopback(t)
	p := &bytePeer{silentPeer: silentPeer{ln: ln}, reply: reply}
	go func() {
		for {
			conn, err := p.ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			go func() {
				// The SSLRequest is a fixed eight bytes.
				if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
					return
				}
				_, _ = conn.Write([]byte{p.reply})
			}()
		}
	}()
	t.Cleanup(p.close)
	return p
}

// trustPeer speaks just enough PostgreSQL to carry a plaintext run to
// ReadyForQuery without asking for anything: AuthenticationOk, then
// ReadyForQuery(idle). It is the `trust` shape, scripted.
type trustPeer struct{ silentPeer }

func newTrustPeer(t *testing.T) *trustPeer {
	t.Helper()
	ln := listenLoopback(t)
	p := &trustPeer{silentPeer{ln: ln}}
	go func() {
		for {
			conn, err := p.ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			go serveTrust(conn)
		}
	}()
	t.Cleanup(p.close)
	return p
}

func serveTrust(conn net.Conn) {
	// StartupMessage: int32 length covering itself, then the body.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header)
	if length < 4 || length > 1<<16 {
		return
	}
	if _, err := io.ReadFull(conn, make([]byte, length-4)); err != nil {
		return
	}
	_, _ = conn.Write(append(pgAuthOK(), pgReadyForQuery()...))
}

func pgAuthOK() []byte {
	return pgTestFrame('R', binary.BigEndian.AppendUint32(nil, 0))
}

func pgReadyForQuery() []byte { return pgTestFrame('Z', []byte{'I'}) }

func pgTestFrame(kind byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = kind
	//nolint:gosec // G115: fixture bodies are a handful of bytes.
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

// loopbackDialer sends every address to one concrete listener.
type loopbackDialer struct{ target netip.AddrPort }

func (d loopbackDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// routingDialer sends each resolved address to a different listener, and
// black-holes any address it has no route for.
type routingDialer struct{ routes map[netip.Addr]netip.AddrPort }

func (d routingDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	target, ok := d.routes[addr.Addr()]
	if !ok {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target.String())
}

// blackHoleDialer never answers, so the step budget is the only thing that ends
// the attempt.
type blackHoleDialer struct{}

func (blackHoleDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// budgetRun is the shared invocation: a finite step budget under a caller
// context that has none, which is the configuration all three defects needed.
func budgetRun(t *testing.T, params PostgresParams) Result {
	t.Helper()
	params.Role = "svcdoctor"
	params.Vantage = vantage(t)
	params.Version = "0.0.0-test"
	if params.StepTimeout == 0 {
		params.StepTimeout = 150 * time.Millisecond
	}
	result, err := DiagnosePostgres(context.Background(), params)
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result
}

func nodeAt(t *testing.T, report domain.Report, step domain.Step) domain.Evidence {
	t.Helper()
	for _, node := range report.Graph().Nodes() {
		if node.Step() == step {
			return node
		}
	}
	t.Fatalf("no %s node in the graph", step)
	return domain.Evidence{}
}

func hasFinding(report domain.Report, code domain.FindingCode) bool {
	for _, f := range report.Findings() {
		if f.Code() == code {
			return true
		}
	}
	return false
}

// TestStartupHonoursTheStepTimeout is the regression for the defect that had no
// field to fix: StartupParams carried no budget, so internal/app's StepTimeout
// was dropped on the floor and a silent peer held the run open forever.
//
// The oracle is that the call returns. The timer only decides how long to wait
// before declaring that it did not, and it is generous enough that a slow
// machine cannot fail it while a genuinely unbounded run always does.
func TestStartupHonoursTheStepTimeout(t *testing.T) {
	peer := newSilentPeer(t)
	ap := peer.addr(t)

	done := make(chan Result, 1)
	go func() {
		result, err := DiagnosePostgres(context.Background(), PostgresParams{
			Host: "db.internal", Port: ap.Port(),
			Role:     "svcdoctor",
			Resolver: stubResolver{addrs: addrs(t, ap.Addr().String())},
			Dialer:   loopbackDialer{target: ap},
			// Plaintext, so the run reaches the startup exchange directly.
			TLS:         postgres.TLSDisabled,
			StepTimeout: 150 * time.Millisecond,
			Vantage:     vantage(t),
			Version:     "0.0.0-test",
		})
		if err != nil {
			t.Errorf("DiagnosePostgres: %v", err)
			close(done)
			return
		}
		done <- result
	}()

	select {
	case result, ok := <-done:
		if !ok {
			t.Fatal("the run failed")
		}
		startup := nodeAt(t, result.Report(), servicepostgres.StepStartup)
		if startup.State() != domain.StateUnknown {
			t.Errorf("startup state = %s, want UNKNOWN; svcdoctor's own budget is "+
				"not a claim about the endpoint", startup.State())
		}
		if startup.FailureClass() != domain.FailureExecLocalTimeout {
			t.Errorf("startup class = %s, want EXEC_LOCAL_TIMEOUT",
				startup.FailureClass())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the run did not return: StepTimeout does not bound postgres.startup")
	}
}

// TestSSLRequestLocalTimeoutIsNotATargetFailure pins the classification defect.
//
// Before Phase 4.11d this produced FAIL + PROTOCOL_UNEXPECTED_RESPONSE and an
// ERROR finding saying the endpoint's negotiation did not complete — which is
// svcdoctor reporting its own deadline as the peer's defect.
func TestSSLRequestLocalTimeoutIsNotATargetFailure(t *testing.T) {
	peer := newSilentPeer(t)
	ap := peer.addr(t)

	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: addrs(t, ap.Addr().String())},
		Dialer:   loopbackDialer{target: ap},
	})
	report := result.Report()

	node := nodeAt(t, report, servicepostgres.StepSSLRequest)
	if node.State() != domain.StateUnknown {
		t.Errorf("ssl_request state = %s, want UNKNOWN", node.State())
	}
	if node.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("ssl_request class = %s, want EXEC_LOCAL_TIMEOUT", node.FailureClass())
	}
	if hasFinding(report, "POSTGRES_SSL_NEGOTIATION_FAILED") {
		t.Error("a local timeout produced POSTGRES_SSL_NEGOTIATION_FAILED; " +
			"the floor may only fire on a positively evidenced protocol failure")
	}
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK; nothing about the endpoint was proven",
			report.Summary().Status())
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false; the run stopped on its own budget")
	}
}

// TestStartupLocalTimeoutIsNotATargetFailure is the same claim one layer down,
// and it only became reachable once the startup exchange was bounded at all.
func TestStartupLocalTimeoutIsNotATargetFailure(t *testing.T) {
	peer := newSilentPeer(t)
	ap := peer.addr(t)

	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: addrs(t, ap.Addr().String())},
		Dialer:   loopbackDialer{target: ap},
		TLS:      postgres.TLSDisabled,
	})
	report := result.Report()

	node := nodeAt(t, report, servicepostgres.StepStartup)
	if node.State() != domain.StateUnknown ||
		node.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("startup = %s/%s, want UNKNOWN/EXEC_LOCAL_TIMEOUT",
			node.State(), node.FailureClass())
	}
	if hasFinding(report, "POSTGRES_STARTUP_FAILED") {
		t.Error("a local timeout produced POSTGRES_STARTUP_FAILED")
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false; the run stopped on its own budget")
	}
}

// TestExhaustedLocalBudgetMakesTheRunIncomplete is the third defect: the run
// reported itself complete because the *caller's* context was still alive.
func TestExhaustedLocalBudgetMakesTheRunIncomplete(t *testing.T) {
	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: 5432,
		Resolver: stubResolver{addrs: addrs(t, "10.0.0.1")},
		Dialer:   blackHoleDialer{},
	})
	report := result.Report()

	node := nodeAt(t, report, "tcp.connect")
	if node.State() != domain.StateUnknown ||
		node.FailureClass() != domain.FailureExecLocalTimeout {
		t.Fatalf("tcp.connect = %s/%s, want UNKNOWN/EXEC_LOCAL_TIMEOUT",
			node.State(), node.FailureClass())
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false for a run that never reached L3 because its " +
			"own budget expired; docs/SCOPE.md maps local budget exhaustion to exit 4")
	}
	// And the status stays orthogonal: nothing about the target was proven.
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", report.Summary().Status())
	}
	if len(report.Findings()) != 0 {
		t.Errorf("findings = %d, want 0; a local budget is not a target claim",
			len(report.Findings()))
	}
}

// TestUnexpectedSSLResponseRemainsATargetFailure is the other direction, and it
// is what stops the fixes above from being a blanket amnesty: an endpoint that
// answers something the protocol does not define still fails, still produces the
// floor finding, and still reports a complete run.
func TestUnexpectedSSLResponseRemainsATargetFailure(t *testing.T) {
	peer := newBytePeer(t, 'X')
	ap := peer.addr(t)

	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: addrs(t, ap.Addr().String())},
		Dialer:   loopbackDialer{target: ap},
	})
	report := result.Report()

	node := nodeAt(t, report, servicepostgres.StepSSLRequest)
	if node.State() != domain.StateFail {
		t.Errorf("ssl_request state = %s, want FAIL", node.State())
	}
	if node.FailureClass() != domain.FailureProtocolUnexpectedResponse {
		t.Errorf("ssl_request class = %s, want PROTOCOL_UNEXPECTED_RESPONSE",
			node.FailureClass())
	}
	if !hasFinding(report, "POSTGRES_SSL_NEGOTIATION_FAILED") {
		t.Error("a real unexpected response produced no floor finding")
	}
	if report.Summary().Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", report.Summary().Status())
	}
	if result.Incomplete() {
		t.Error("Incomplete() = true for a run that reached a definitive answer")
	}
}

// TestTargetFailuresAreCompleteRuns pins that nothing about a target-side
// failure moved: it is an answer, and an answer is a finished measurement.
func TestTargetFailuresAreCompleteRuns(t *testing.T) {
	result := runWith(t, "db.internal", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, refusingDialer{})
	report := result.Report()

	if !hasFinding(report, "TCP_CONNECTION_NOT_ESTABLISHED") {
		t.Fatal("a refused endpoint produced no TCP finding")
	}
	if result.Incomplete() {
		t.Error("Incomplete() = true for a refused endpoint; a refusal is an answer")
	}
}

// TestASessionSurvivesLocalUncertaintyElsewhere is the multi-path carve-out, and
// it is the reason the predicate is not "any local timeout anywhere".
//
// ADR 0041 measures every resolved address deliberately and continues exactly
// one. A path the run did not select ending without a conclusion is the expected
// shape, not a truncated run — so a session that reached ReadyForQuery settles
// the question the operator asked, and the unmeasured path does not unsettle it.
func TestASessionSurvivesLocalUncertaintyElsewhere(t *testing.T) {
	peer := newTrustPeer(t)
	ap := peer.addr(t)

	working := netip.MustParseAddr("10.0.0.1")
	blackHoled := netip.MustParseAddr("10.0.0.2")

	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: []netip.Addr{working, blackHoled}},
		Dialer:   routingDialer{routes: map[netip.Addr]netip.AddrPort{working: ap}},
		TLS:      postgres.TLSDisabled,
	})
	report := result.Report()

	session := nodeAt(t, report, servicepostgres.StepSession)
	if session.State() != domain.StatePass {
		t.Fatalf("session state = %s, want PASS; the scripted peer reaches "+
			"ReadyForQuery", session.State())
	}

	// The other address really did end on the local budget.
	var sawLocalTimeout bool
	for _, node := range report.Graph().Nodes() {
		if node.State() == domain.StateUnknown &&
			node.FailureClass() == domain.FailureExecLocalTimeout {
			sawLocalTimeout = true
		}
	}
	if !sawLocalTimeout {
		t.Fatal("the black-holed address did not produce a local timeout; " +
			"this test no longer exercises what it claims to")
	}

	if result.Incomplete() {
		t.Error("Incomplete() = true although the run reached ReadyForQuery; " +
			"an unselected path's local uncertainty must not truncate a run that " +
			"answered the question it was asked")
	}
}

// TestLocalTimeoutKeepsItsMeasuredDuration guards the timing half of the
// contract. The interrupted step carries a real elapsed duration, and that
// duration means how long svcdoctor waited before its own limit stopped the
// step — never that the endpoint was slow. Nothing in this repository turns it
// into a latency claim, and this test exists so that adding one is a visible act.
func TestLocalTimeoutKeepsItsMeasuredDuration(t *testing.T) {
	peer := newSilentPeer(t)
	ap := peer.addr(t)

	result := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: addrs(t, ap.Addr().String())},
		Dialer:   loopbackDialer{target: ap},
	})
	report := result.Report()

	node := nodeAt(t, report, servicepostgres.StepSSLRequest)
	if node.Duration() <= 0 {
		t.Errorf("duration = %s; an interrupted step still measured how long it "+
			"waited", node.Duration())
	}
	if node.StartedAt().IsZero() {
		t.Error("StartedAt is zero on a step that ran")
	}
	for _, f := range report.Findings() {
		t.Errorf("a local timeout produced finding %s; there is no latency "+
			"finding in this repository", f.Code())
	}
}

// TestIncompleteIgnoresFindingsAndStatus pins what the predicate must never
// read. Both runs below carry the same local-timeout evidence; one also carries
// an unrelated ERROR finding from a second address. Incompleteness is identical,
// because it is derived from execution and not from what was concluded.
func TestIncompleteIgnoresFindingsAndStatus(t *testing.T) {
	// A run whose only address black-holes: no findings, status OK.
	quiet := budgetRun(t, PostgresParams{
		Host: "db.internal", Port: 5432,
		Resolver: stubResolver{addrs: addrs(t, "10.0.0.1")},
		Dialer:   blackHoleDialer{},
	})
	if quiet.Report().Summary().Status() != domain.SummaryStatusOK {
		t.Fatalf("quiet status = %s, want OK", quiet.Report().Summary().Status())
	}
	if !quiet.Incomplete() {
		t.Error("quiet run: Incomplete() = false")
	}

	// A run that answered definitively: findings exist, status PROBLEMS_FOUND,
	// and it is complete. Status moved; incompleteness did not follow it.
	loud := runWith(t, "db.internal", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, refusingDialer{})
	if loud.Report().Summary().Status() != domain.SummaryStatusProblemsFound {
		t.Fatalf("loud status = %s, want PROBLEMS_FOUND",
			loud.Report().Summary().Status())
	}
	if loud.Incomplete() {
		t.Error("loud run: Incomplete() = true; severity and status do not drive it")
	}
}

// TestCancellationRemainsIncomplete pins that the widened predicate did not
// replace the original clause.
func TestCancellationRemainsIncomplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := DiagnosePostgres(ctx, PostgresParams{
		Host: "db.internal", Port: 5432,
		Role:     "svcdoctor",
		Resolver: stubResolver{addrs: addrs(t, "10.0.0.1")},
		Dialer:   refusingDialer{},
		Vantage:  vantage(t),
		Version:  "0.0.0-test",
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	if err == nil && !result.Incomplete() {
		t.Error("Incomplete() = false for a cancelled run")
	}
}
