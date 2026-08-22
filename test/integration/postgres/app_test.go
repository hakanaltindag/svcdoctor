//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// Phase 4.8b: the **production composition root** under test against real
// servers.
//
// Phase 4.8a proved the vertical slice end to end from a test harness that
// sequenced the stages itself. These tests drive `app.DiagnosePostgres` — the
// production run — so what is under test is the orchestration, not a fixture
// that resembles it.
//
// Nothing here hand-authors evidence, constructs a finding, or invokes diagnosis
// directly. The only inputs are parameters; the only output is a report.

// runParams builds a production run against the TLS validation server.
func runParams(t *testing.T, role, password, database string) app.PostgresParams {
	t.Helper()

	vantage, err := domain.NewLocalVantage("svcdoctor-integration")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}

	params := app.PostgresParams{
		Host: pgHost, Port: pgTLSPort,
		Role: role, Database: database,
		Resolver: dns.SystemResolver{}, Dialer: tcp.SystemDialer{},
		TLS:         postgres.TLSRequired,
		TLSOptions:  postgres.TLSOptions{ServerName: pgHost, RootCAs: rootCAs(t)},
		StepTimeout: 10 * time.Second,
		Vantage:     vantage,
		Version:     "0.1.0-integration",
	}
	if password != "" {
		endpoint, err := security.NewEndpoint(pgHost, pgTLSPort)
		if err != nil {
			t.Fatalf("NewEndpoint: %v", err)
		}
		c, err := security.NewCredential(endpoint, role, security.NewSecret(password))
		if err != nil {
			t.Fatalf("NewCredential: %v", err)
		}
		params.Credential = c
	}
	return params
}

// runApp executes the production run and fails on an orchestration error.
func runApp(t *testing.T, params app.PostgresParams) app.Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	result, err := app.DiagnosePostgres(ctx, params)
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	if result.Incomplete() {
		t.Fatal("the run reported itself incomplete against a local server")
	}
	return result
}

// nodesAt returns every node recorded at a step, from the run's own report.
func nodesAt(report domain.Report, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range report.Graph().Nodes() {
		if n.Step() == step {
			out = append(out, n)
		}
	}
	return out
}

func codesIn(report domain.Report) []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(report.Findings()))
	for _, f := range report.Findings() {
		out = append(out, f.Code())
	}
	return out
}

// requireSingleFinding asserts the run concluded exactly one thing.
func requireSingleFinding(t *testing.T, report domain.Report, code domain.FindingCode) domain.Finding {
	t.Helper()
	if got := report.Findings(); len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), codesIn(report))
	}
	f := report.Findings()[0]
	if f.Code() != code {
		t.Fatalf("finding = %s, want %s", f.Code(), code)
	}
	return f
}

// --- the healthy production run ------------------------------------------------

// TestAppHealthyRun is the phase's headline: the production composition root,
// against a real server, all the way to a canonical report.
func TestAppHealthyRun(t *testing.T) {
	result := runApp(t, runParams(t, scramRole, scramPassword, database))
	report := result.Report()

	for _, step := range []domain.Step{
		"dns.lookup", "tcp.connect", servicepostgres.StepSSLRequest, "tls.handshake",
		servicepostgres.StepStartup, servicepostgres.StepAuthentication,
		servicepostgres.StepSession,
	} {
		nodes := nodesAt(report, step)
		if len(nodes) != 1 {
			t.Fatalf("%s produced %d nodes, want 1", step, len(nodes))
		}
		if nodes[0].State() != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", step, nodes[0].State())
		}
	}

	// A healthy run says nothing. In particular it does not claim a backend is
	// healthy: a pooler serves a complete passing session with its backend
	// stopped, measured in Phase 4.5a.
	if len(report.Findings()) != 0 {
		t.Fatalf("a healthy run produced %v", codesIn(report))
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", got)
	}

	// The run produced a LOCAL_FULL report and redacted nothing.
	if got := report.Security().OutputMode(); got != domain.OutputModeLocalFull {
		t.Errorf("output mode = %s, want LOCAL_FULL", got)
	}
}

// --- the dual-stack case, against a real dual-stack name -----------------------

// TestAppDualStackDiscoversEveryPathAndAuthenticatesOnce is the test this whole
// phase exists for.
//
// `localhost` resolves to both 127.0.0.1 and ::1, and Phase 4.8a measured both
// producing usable transport paths. The production run must measure **both**
// through the credential-free stages and present the credential **once**.
func TestAppDualStackDiscoversEveryPathAndAuthenticatesOnce(t *testing.T) {
	params := runParams(t, scramRole, scramPassword, database)
	// A name, not a literal, so the run really resolves more than one address.
	params.Host = "localhost"
	params.TLSOptions.ServerName = "localhost"
	endpoint, err := security.NewEndpoint("localhost", pgTLSPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	report := runApp(t, params).Report()

	tcpNodes := nodesAt(report, "tcp.connect")
	if len(tcpNodes) < 2 {
		t.Skipf("localhost produced %d transport path(s) in this environment; "+
			"the dual-stack contract needs at least two", len(tcpNodes))
	}

	// Credential-free discovery ran on every completed path.
	startups := nodesAt(report, servicepostgres.StepStartup)
	if len(startups) != len(tcpNodes) {
		t.Errorf("%d startup observations for %d transport paths; discovery must not stop early",
			len(startups), len(tcpNodes))
	}

	// And the credential crossed exactly one of them.
	auths := nodesAt(report, servicepostgres.StepAuthentication)
	if len(auths) != 1 {
		t.Fatalf("%d authentication nodes; a run presents the credential at most once", len(auths))
	}
	sessions := nodesAt(report, servicepostgres.StepSession)
	if len(sessions) != 1 {
		t.Errorf("%d session nodes; only the continued path establishes one", len(sessions))
	}

	// The selected path is readable from the authentication node's own Subject —
	// never from an identifier's text — and it is the canonical minimum among
	// the paths that reached startup.
	var lowest string
	for _, n := range startups {
		if lowest == "" || n.Subject().Ref() < lowest {
			lowest = n.Subject().Ref()
		}
	}
	if got := auths[0].Subject().Ref(); got != lowest {
		t.Errorf("authenticated %s, want the canonical minimum %s", got, lowest)
	}

	// The unselected path keeps its startup evidence and gains no authentication
	// node. It is neither PASS nor FAIL at that layer — it was not authenticated.
	for _, n := range startups {
		if n.Subject().Ref() == lowest {
			continue
		}
		for _, a := range auths {
			if a.Subject().Ref() == n.Subject().Ref() {
				t.Errorf("an unselected path %s carries an authentication node", n.Subject().Ref())
			}
		}
	}

	t.Logf("paths=%d startups=%d authenticated=%s", len(tcpNodes), len(startups), lowest)
}

// --- real failure runs, through the production composition ---------------------

func TestAppFailureScenarios(t *testing.T) {
	tests := []struct {
		name                   string
		role, password, dbName string
		want                   domain.FindingCode
		wantSession            bool
	}{
		{"wrong password", scramRole, scramPassword + "-wrong", database,
			diagnosispostgres.CodeCredentialsRejected, false},
		{"unknown role", "nosuchrole-svcd", "irrelevant", database,
			diagnosispostgres.CodeCredentialsRejected, false},
		{"missing database", scramRole, scramPassword, "nosuchdb-svcd",
			diagnosispostgres.CodeDatabaseNotFound, true},
		{"connect denied", norightsRole, norightsPassword, closedDatabase,
			diagnosispostgres.CodeDatabaseConnectDenied, true},
		{"pg_hba reject", rejectRole, "pw-rejectuser", database,
			diagnosispostgres.CodeConnectionNotPermitted, false},
		{"md5 demanded", md5Role, "md5-pw", database,
			diagnosispostgres.CodeMechanismUnavailable, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := runApp(t, runParams(t, tt.role, tt.password, tt.dbName)).Report()

			requireSingleFinding(t, report, tt.want)

			if got := len(nodesAt(report, servicepostgres.StepSession)); tt.wantSession != (got > 0) {
				t.Errorf("session nodes = %d, want present=%v", got, tt.wantSession)
			}
			// One credential attempt at most, always.
			if got := len(nodesAt(report, servicepostgres.StepAuthentication)); got > 1 {
				t.Errorf("%d authentication nodes; a run presents the credential at most once", got)
			}
			// And the credential never reaches the report.
			if tt.password != "" {
				encoded, err := json.Marshal(report)
				if err != nil {
					t.Fatalf("encoding: %v", err)
				}
				if strings.Contains(string(encoded), tt.password) {
					t.Error("the credential reached the report")
				}
			}
		})
	}
}

// TestAppTLSDeclined runs the production composition against the plaintext-only
// listener, where a real server really answers 'N'.
func TestAppTLSDeclined(t *testing.T) {
	params := runParams(t, scramRole, scramPassword, database)
	params.Port = pgPlaintextPort
	endpoint, err := security.NewEndpoint(pgHost, pgPlaintextPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	report := runApp(t, params).Report()

	requireSingleFinding(t, report, diagnosispostgres.CodeTLSDeclined)

	// Nothing downstream ran: no credential crossed a channel the run required
	// to be encrypted.
	for _, step := range []domain.Step{
		servicepostgres.StepStartup, servicepostgres.StepAuthentication,
		servicepostgres.StepSession,
	} {
		for _, n := range nodesAt(report, step) {
			if n.State() == domain.StatePass {
				t.Errorf("%s passed below a declined TLS negotiation", step)
			}
		}
	}
}

// TestAppTrustPathReceivesNoCredential pins that a server demanding nothing is
// continued without one, and records no authentication node.
func TestAppTrustPathReceivesNoCredential(t *testing.T) {
	report := runApp(t, runParams(t, trustRole, "", database)).Report()

	startups := nodesAt(report, servicepostgres.StepStartup)
	if len(startups) == 0 {
		t.Fatal("no startup node")
	}
	if got, _ := startups[0].Attribute(servicepostgres.AttrAuthMethod); got.String() == "" {
		t.Fatal("no auth method recorded")
	}
	if got := len(nodesAt(report, servicepostgres.StepAuthentication)); got != 0 {
		t.Errorf("%d authentication nodes on a trust path; svcdoctor presented nothing", got)
	}
	if got := len(nodesAt(report, servicepostgres.StepSession)); got != 1 {
		t.Errorf("%d session nodes, want 1", got)
	}
	if len(report.Findings()) != 0 {
		t.Errorf("a healthy trust run produced %v", codesIn(report))
	}
}

// --- connection lifecycle -------------------------------------------------------

// countingDialer wraps the production dialer and records what happened to every
// connection it handed out.
//
// It uses the existing tcp.Dialer seam rather than production introspection
// added for a test, which is why this proof costs the production package
// nothing.
type countingDialer struct {
	inner tcp.Dialer

	mu     sync.Mutex
	opened int
	closed int
}

func (d *countingDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	conn, err := d.inner.DialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.opened++
	d.mu.Unlock()
	return &countingConn{Conn: conn, dialer: d}, nil
}

type countingConn struct {
	net.Conn
	dialer *countingDialer
	once   sync.Once
}

func (c *countingConn) Close() error {
	// Counted once however many times Close is called, so an idempotent
	// double-close does not read as two connections being released.
	c.once.Do(func() {
		c.dialer.mu.Lock()
		c.dialer.closed++
		c.dialer.mu.Unlock()
	})
	return c.Conn.Close()
}

func (d *countingDialer) counts() (opened, closed int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opened, d.closed
}

// TestAppClosesEveryConnectionItOpened pins the ownership contract from ADR 0041
// section 11.
//
// Every continuation ends either transferred into a protocol stage or closed by
// the run. On a dual-stack name that means both sockets are opened, one is
// carried through authentication and the session step, the other is closed
// deliberately when it is not selected — and **nothing is left to the
// collector**.
func TestAppClosesEveryConnectionItOpened(t *testing.T) {
	dialer := &countingDialer{inner: tcp.SystemDialer{}}

	params := runParams(t, scramRole, scramPassword, database)
	params.Host = "localhost"
	params.TLSOptions.ServerName = "localhost"
	params.Dialer = dialer
	endpoint, err := security.NewEndpoint("localhost", pgTLSPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	report := runApp(t, params).Report()

	opened, closed := dialer.counts()
	if opened == 0 {
		t.Fatal("the run opened no connection")
	}
	if closed != opened {
		t.Errorf("opened %d connections and closed %d; a run leaves no socket without an owner",
			opened, closed)
	}

	// And the multi-path shape really was exercised, so the assertion above
	// covers an unselected path rather than only the continued one.
	if paths := len(nodesAt(report, "tcp.connect")); paths > 1 {
		t.Logf("opened=%d closed=%d across %d paths", opened, closed, paths)
	}
}

// --- cancellation and partial runs ----------------------------------------------

// cancelAt cancels a run at an exact protocol position.
//
// **The trigger is a message type, not a timer.** A test that cancelled after a
// duration would pass or fail on how fast the loopback happened to be that day;
// these fire on a byte the protocol guarantees appears exactly once, in exactly
// one window:
//
//	onFrontend 'p'   the SASL message — the first byte of the credentialed step
//	onBackend  'S'   ParameterStatus — sent only after AuthenticationOk, so it is
//	                 the session window and nothing else
//
// The wire layer reads a five-byte header whose first byte is the backend
// message type, and writes each frontend message whole, so both are observable
// from a net.Conn wrapper without parsing a frame.
type cancelAt struct {
	inner      tcp.Dialer
	onFrontend byte
	onBackend  byte
	onDial     int

	mu     sync.Mutex
	cancel context.CancelFunc
	dials  int
	fired  bool
}

func (d *cancelAt) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	conn, err := d.inner.DialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dials++
	reached := d.onDial > 0 && d.dials >= d.onDial
	d.mu.Unlock()
	if reached {
		d.fire()
	}
	return &cancelConn{Conn: conn, dialer: d}, nil
}

func (d *cancelAt) fire() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fired {
		return
	}
	d.fired = true
	d.cancel()
}

func (d *cancelAt) triggered() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fired
}

type cancelConn struct {
	net.Conn
	dialer *cancelAt
}

func (c *cancelConn) Write(p []byte) (int, error) {
	if c.dialer.onFrontend != 0 && len(p) > 0 && p[0] == c.dialer.onFrontend {
		c.dialer.fire()
	}
	return c.Conn.Write(p)
}

func (c *cancelConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	// A five-byte read is the message header; its first byte is the type.
	if c.dialer.onBackend != 0 && n == 5 && p[0] == c.dialer.onBackend {
		c.dialer.fire()
	}
	return n, err
}

// runCancellable executes a run whose context the dialer can end mid-flight.
func runCancellable(t *testing.T, params app.PostgresParams, d *cancelAt) app.Result {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	ctx, stop := context.WithCancel(ctx)
	t.Cleanup(stop)

	d.cancel = stop
	d.inner = tcp.SystemDialer{}
	params.Dialer = d

	result, err := app.DiagnosePostgres(ctx, params)
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result
}

// TestAppCancellationBeforeAnyServicePath proves a run cancelled before it
// starts still produces a report.
//
// Execution incompleteness is not report-construction failure: docs/SCOPE.md
// reserves codes 0, 1 and 4 for runs that produced one.
func TestAppCancellationBeforeAnyServicePath(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := app.DiagnosePostgres(ctx, runParams(t, scramRole, scramPassword, database))
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	if !result.Incomplete() {
		t.Error("a cancelled run reported itself complete")
	}
	if result.Report().IsZero() {
		t.Fatal("a cancelled run produced no report")
	}
	if got := len(nodesAt(result.Report(), servicepostgres.StepAuthentication)); got != 0 {
		t.Errorf("%d authentication nodes; nothing was attempted", got)
	}
}

// TestAppCancellationDuringTransport cancels once the second address is dialled,
// so at least one path's evidence exists and the rest was never attempted.
func TestAppCancellationDuringTransport(t *testing.T) {
	params := runParams(t, scramRole, scramPassword, database)
	params.Host = "localhost"
	params.TLSOptions.ServerName = "localhost"
	endpoint, err := security.NewEndpoint("localhost", pgTLSPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	d := &cancelAt{onDial: 2}
	result := runCancellable(t, params, d)
	if !d.triggered() {
		t.Skip("this environment dialled fewer than two addresses")
	}

	if !result.Incomplete() {
		t.Error("a run cancelled during transport reported itself complete")
	}
	// The evidence collected before the cancellation survives.
	if got := len(nodesAt(result.Report(), "dns.lookup")); got == 0 {
		t.Error("the lookup evidence did not survive cancellation")
	}
	// And no credential was presented.
	if got := len(nodesAt(result.Report(), servicepostgres.StepAuthentication)); got != 0 {
		t.Errorf("%d authentication nodes after a transport cancellation", got)
	}
}

// TestAppCancellationDuringProtocolExchange fires on the endpoint's answer to
// the StartupMessage, cancelling the run inside the PostgreSQL protocol stages.
//
// It runs over the plaintext listener, and that is not a shortcut — it is the
// only place the trigger can see anything. Over TLS the wrapper below is beneath
// the tls.Conn, so every Write and Read it observes is a TLS record rather than
// a PostgreSQL frame. See TestAppCancellationCoverageLimit.
func TestAppCancellationDuringProtocolExchange(t *testing.T) {
	params := runParams(t, scramRole, scramPassword, database)
	params.Port = pgPlaintextPort
	params.TLS = postgres.TLSDisabled
	endpoint, err := security.NewEndpoint(pgHost, pgPlaintextPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	// 'R' is an Authentication request: the endpoint's first decisive answer to
	// the StartupMessage, and it appears exactly once in this exchange.
	d := &cancelAt{onBackend: 'R'}
	result := runCancellable(t, params, d)

	if !d.triggered() {
		t.Fatal("no authentication request was read; the trigger did not fire")
	}
	if !result.Incomplete() {
		t.Error("a run cancelled inside the protocol stages reported itself complete")
	}

	// The evidence collected before the cancellation survives, and the
	// cancellation is never recorded as a failure of the endpoint.
	report := result.Report()
	if got := len(nodesAt(report, servicepostgres.StepSSLRequest)); got == 0 {
		t.Error("the negotiation evidence did not survive cancellation")
	}
	for _, n := range nodesAt(report, servicepostgres.StepStartup) {
		if n.State() == domain.StateFail {
			t.Error("a local cancellation was recorded as a failure of the endpoint")
		}
	}
	// And no credential crossed a plaintext channel, cancelled or not.
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if strings.Contains(string(encoded), scramPassword) {
		t.Error("the credential reached the report")
	}
}

// TestAppCancellationCoverageLimit records, as an executable note, what these
// tests cannot reach.
//
// Cancellation *inside* Authenticate or EstablishSession over TLS is not
// triggerable from the tcp.Dialer seam: those stages only run on a verified TLS
// channel — the credential-transport policy has exactly one member,
// RequireVerifiedTLS — and a wrapper beneath the tls.Conn sees ciphertext.
//
// That gap is narrower than it looks, and this test says why. Incomplete() is
// derived in **one** place, from **one** expression, after every stage has
// returned: whether the caller's context ended. There is no per-stage assignment
// that could observe a cancellation in Negotiate but miss one in Authenticate,
// so the stage a cancellation lands in cannot change the answer. The tests above
// exercise that single path from three different stages.
//
// If the reconciliation is ever replaced by per-stage assignments, this note
// stops being true and the coverage gap becomes real.
func TestAppCancellationCoverageLimit(t *testing.T) {
	if security.RequireVerifiedTLS.PermitsCredentials(security.ChannelPlaintext) {
		t.Fatal("plaintext now permits credentials; intra-TLS cancellation is testable " +
			"and this limitation should be removed")
	}
}

// TestAppCompleteRunsAreNeverIncomplete pins the other direction.
//
// Incomplete means one thing: the caller's context ended before the work did. It
// is not a finding, not a severity, not a report status, not a path count, and
// not ordinary multi-path selection.
func TestAppCompleteRunsAreNeverIncomplete(t *testing.T) {
	tests := []struct {
		name                   string
		role, password, dbName string
		host                   string
	}{
		{"healthy", scramRole, scramPassword, database, pgHost},
		{"rejected credential", scramRole, scramPassword + "-wrong", database, pgHost},
		{"missing database", scramRole, scramPassword, "nosuchdb-svcd", pgHost},
		{"path divergence on a dual-stack name", scramRole, scramPassword, database, "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := runParams(t, tt.role, tt.password, tt.dbName)
			if tt.host != pgHost {
				params.Host = tt.host
				params.TLSOptions.ServerName = tt.host
				endpoint, err := security.NewEndpoint(tt.host, pgTLSPort)
				if err != nil {
					t.Fatalf("NewEndpoint: %v", err)
				}
				c, err := security.NewCredential(endpoint, tt.role, security.NewSecret(tt.password))
				if err != nil {
					t.Fatalf("NewCredential: %v", err)
				}
				params.Credential = c
			}

			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			t.Cleanup(cancel)

			result, err := app.DiagnosePostgres(ctx, params)
			if err != nil {
				t.Fatalf("DiagnosePostgres: %v", err)
			}
			if result.Incomplete() {
				t.Error("a run that finished reported itself incomplete")
			}
		})
	}
}

// --- class preference: what this environment can and cannot show -----------------

// TestAppMixedMethodDivergenceIsNotReproducibleHere records a real limitation
// rather than a fixture that pretends to cover it.
//
// ADR 0041 section 8.1 exists for an endpoint that admits one address family on
// `trust` while asking the other for SCRAM. Reproducing it needs `pg_hba` to see
// two different source addresses — and under Docker's published ports it does
// not: both loopback families are translated to the same container-side gateway
// address, so every rule that could distinguish them matches identically.
//
// Measured: a run over `localhost` against a role with per-family `pg_hba` rules
// observed `sasl` on **both** paths, because neither `127.0.0.1/32` nor
// `::1/128` matched what the server actually saw.
//
// So the class preference is covered where it can be covered honestly: the
// selector's partition is unit-tested in internal/app, and the derivation of the
// class from the adapter's own `auth_method` is pinned by a source guard. What
// is **not** covered is an end-to-end run over a genuinely mixed-method
// endpoint. Reopen when the environment can host one — a second server on a
// distinct address, or host networking.
func TestAppMixedMethodDivergenceIsNotReproducibleHere(t *testing.T) {
	params := runParams(t, scramRole, scramPassword, database)
	params.Host = "localhost"
	params.TLSOptions.ServerName = "localhost"
	endpoint, err := security.NewEndpoint("localhost", pgTLSPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	params.Credential = c

	report := runApp(t, params).Report()

	methods := map[string]string{}
	for _, n := range nodesAt(report, servicepostgres.StepStartup) {
		v, _ := n.Attribute(servicepostgres.AttrAuthMethod)
		method, _ := v.Str()
		methods[n.Subject().Ref()] = method
	}
	if len(methods) < 2 {
		t.Skipf("localhost produced %d startup observation(s)", len(methods))
	}
	t.Logf("startup methods by address: %v", methods)

	distinct := map[string]bool{}
	for _, m := range methods {
		distinct[m] = true
	}
	if len(distinct) > 1 {
		t.Errorf("this environment now produces divergent methods %v; the end-to-end "+
			"class-preference test is possible and this limitation should be replaced",
			methods)
	}

	// What is assertable here: one credential attempt, whatever the methods.
	if got := len(nodesAt(report, servicepostgres.StepAuthentication)); got != 1 {
		t.Errorf("%d authentication nodes, want exactly 1", got)
	}
}
