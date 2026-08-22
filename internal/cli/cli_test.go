package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"go/parser"
	"go/printer"
	"go/token"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The command boundary's tests, and why they run real diagnoses.
//
// Every app.Result below comes from internal/app measuring a real socket, never
// from a hand-authored report: Result's fields are unexported precisely so that
// nothing can mint one claiming a status its evidence does not support, and a
// test that reached around that would be asserting against a fiction. The peers
// are loopback listeners, which is what internal/app's own budget tests use.
//
// The seam (App.diagnosePostgres) is used for the cases that are about *the
// command* — parsing, routing, exit codes, stdout discipline — where running a
// diagnosis would only add a network to something that has no network in it.

// --- fixtures -----------------------------------------------------------------

type peer struct {
	ln     net.Listener
	mu     sync.Mutex
	conns  []net.Conn
	handle func(net.Conn)
}

func newPeer(t *testing.T, handle func(net.Conn)) *peer {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &peer{ln: ln, handle: handle}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			p.conns = append(p.conns, conn)
			p.mu.Unlock()
			if p.handle != nil {
				go p.handle(conn)
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, conn := range p.conns {
			_ = conn.Close()
		}
	})
	return p
}

func (p *peer) addrPort(t *testing.T) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(p.ln.Addr().String())
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	return ap
}

// trustHandler speaks just enough PostgreSQL to reach ReadyForQuery without
// asking for anything.
func trustHandler(conn net.Conn) {
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
	_, _ = conn.Write(append(
		frame('R', binary.BigEndian.AppendUint32(nil, 0)),
		frame('Z', []byte{'I'})...))
}

// scramHandler demands SCRAM-SHA-256 and never gets the chance to perform it.
//
// It exists so the product invariant this whole phase turns on — a WARN finding
// with status OK, a complete run and no session — is reachable deterministically
// rather than only against Docker. A mutation pass found that gap: deriving the
// exit code from FindingCount() instead of the summary's status escaped every
// unit test, because no unit fixture carried a finding on an OK report.
func scramHandler(conn net.Conn) {
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
	// AuthenticationSASL: code 10, then a NUL-terminated mechanism list ended by
	// an empty string.
	body := binary.BigEndian.AppendUint32(nil, 10)
	body = append(body, "SCRAM-SHA-256"...)
	body = append(body, 0, 0)
	_, _ = conn.Write(frame('R', body))
}

func frame(kind byte, body []byte) []byte {
	out := make([]byte, 5+len(body))
	out[0] = kind
	//nolint:gosec // G115: fixture bodies are a handful of bytes.
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

type stubResolver struct{ addrs []netip.Addr }

func (r stubResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return r.addrs, nil
}

type toPeer struct{ target netip.AddrPort }

func (d toPeer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

type routed struct{ routes map[netip.Addr]netip.AddrPort }

func (d routed) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	target, ok := d.routes[addr.Addr()]
	if !ok {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", target.String())
}

type blackHole struct{}

func (blackHole) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// runReal produces a genuine Result by measuring a real socket.
func runReal(t *testing.T, params app.PostgresParams) app.Result {
	t.Helper()
	// **Not "svcdoctor".** That word appears in finding prose, so a role named
	// after the tool makes redaction fail closed — deliberately, and pinned by
	// test/security's TestAToolWordAsARoleNameFailsClosed. These fixtures need a
	// role that redacts cleanly; the refusal has its own test below.
	params.Role = "app"
	params.Version = "0.0.0-test"
	if params.StepTimeout == 0 {
		params.StepTimeout = 150 * time.Millisecond
	}
	if params.Vantage.IsZero() {
		v, err := domain.NewLocalVantage("svcdoctor-test")
		if err != nil {
			t.Fatalf("NewLocalVantage: %v", err)
		}
		params.Vantage = v
	}
	result, err := app.DiagnosePostgres(context.Background(), params)
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result
}

// The four report-bearing shapes the exit contract distinguishes.

func resultOKComplete(t *testing.T) app.Result {
	t.Helper()
	p := newPeer(t, trustHandler)
	ap := p.addrPort(t)
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: []netip.Addr{ap.Addr()}},
		Dialer:   toPeer{target: ap},
		TLS:      adapterpostgres.TLSDisabled,
	})
}

func resultProblemsComplete(t *testing.T) app.Result {
	t.Helper()
	// A peer that answers the SSLRequest with a byte the protocol does not
	// define: FAIL, PROTOCOL_UNEXPECTED_RESPONSE, one ERROR finding.
	p := newPeer(t, func(conn net.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
			return
		}
		_, _ = conn.Write([]byte{'X'})
	})
	ap := p.addrPort(t)
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: []netip.Addr{ap.Addr()}},
		Dialer:   toPeer{target: ap},
	})
}

// resultWarnComplete is the load-bearing product shape: the endpoint demanded
// authentication, this run had none, and nothing about the endpoint is broken.
func resultWarnComplete(t *testing.T) app.Result {
	t.Helper()
	p := newPeer(t, scramHandler)
	ap := p.addrPort(t)
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver: stubResolver{addrs: []netip.Addr{ap.Addr()}},
		Dialer:   toPeer{target: ap},
		TLS:      adapterpostgres.TLSDisabled,
	})
}

func resultOKIncomplete(t *testing.T) app.Result {
	t.Helper()
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: 5432,
		Resolver:    stubResolver{addrs: []netip.Addr{mustAddr(t, "10.0.0.1")}},
		Dialer:      blackHole{},
		StepTimeout: 80 * time.Millisecond,
	})
}

// resultProblemsIncomplete is the collision the exit contract turns on: an
// endpoint-scoped ERROR on one address, and another address svcdoctor's own
// budget never finished measuring.
func resultProblemsIncomplete(t *testing.T) app.Result {
	t.Helper()
	p := newPeer(t, func(conn net.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
			return
		}
		_, _ = conn.Write([]byte{'X'})
	})
	ap := p.addrPort(t)
	bad := mustAddr(t, "10.0.0.2")
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Resolver:    stubResolver{addrs: []netip.Addr{ap.Addr(), bad}},
		Dialer:      routed{routes: map[netip.Addr]netip.AddrPort{ap.Addr(): ap}},
		StepTimeout: 80 * time.Millisecond,
	})
}

// harness runs the command with a scripted result and captures both streams.
type harness struct {
	stdout, stderr bytes.Buffer
	app            *App
	captured       app.PostgresParams
	calls          int
}

func newHarness(result app.Result, runErr error) *harness {
	h := &harness{}
	h.app = &App{Stdout: &h.stdout, Stderr: &h.stderr, Version: "0.0.0-test"}
	h.app.diagnosePostgres = func(_ context.Context, p app.PostgresParams) (app.Result, error) {
		h.calls++
		h.captured = p
		return result, runErr
	}
	return h
}

func (h *harness) run(args ...string) int {
	return h.app.Run(context.Background(), args)
}

// --- command dispatch ---------------------------------------------------------

func TestCommandDispatch(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout bool // the artifact stream carries something
		wantStderr bool
	}{
		{"no arguments", nil, ExitUsage, false, true},
		{"root help", []string{"--help"}, ExitOK, true, false},
		{"root help short", []string{"-h"}, ExitOK, true, false},
		{"version", []string{"--version"}, ExitOK, true, false},
		{"diagnose help", []string{"diagnose", "--help"}, ExitOK, true, false},
		{"postgres help", []string{"diagnose", "postgres", "--help"}, ExitOK, true, false},
		{"unknown action", []string{"triage", "postgres"}, ExitUsage, false, true},
		{"diagnose with no service", []string{"diagnose"}, ExitUsage, false, true},
		{"unknown service", []string{"diagnose", "redis"}, ExitUsage, false, true},
		// The rejected service-first shape, and the reserved namespaces.
		//
		// **Each carries otherwise-valid flags on purpose.** An earlier version
		// of this table passed them incomplete, so a mutation that routed
		// `postgres` straight to the PostgreSQL command still exited 2 — for the
		// missing --user, not for the rejected route — and the guard proved
		// nothing. With the flags complete, the only way to reach exit 2 is to
		// refuse the route, and h.calls proves the application was never reached.
		{"service first", []string{"postgres", "--host", "db", "--user", "app"},
			ExitUsage, false, true},
		{"service first with action", []string{"postgres", "diagnose", "--host", "db", "--user", "app"},
			ExitUsage, false, true},
		{"unknown service with valid flags", []string{"diagnose", "redis", "--host", "db", "--user", "app"},
			ExitUsage, false, true},
		{"inspect is not exposed", []string{"inspect", "postgres", "--host", "db", "--user", "app"},
			ExitUsage, false, true},
		{"kafka is not exposed", []string{"diagnose", "kafka", "--host", "db", "--user", "app"},
			ExitUsage, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(app.Result{}, nil)
			code := h.run(tt.args...)

			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			if got := h.stdout.Len() > 0; got != tt.wantStdout {
				t.Errorf("stdout non-empty = %v, want %v (%q)", got, tt.wantStdout, h.stdout.String())
			}
			if got := h.stderr.Len() > 0; got != tt.wantStderr {
				t.Errorf("stderr non-empty = %v, want %v (%q)", got, tt.wantStderr, h.stderr.String())
			}
			if tt.wantCode == ExitUsage && h.calls != 0 {
				t.Error("an invalid invocation reached the application")
			}
		})
	}
}

func TestVersionIsTheConfiguredValue(t *testing.T) {
	h := newHarness(app.Result{}, nil)
	if code := h.run("--version"); code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	if got := strings.TrimSpace(h.stdout.String()); got != "0.0.0-test" {
		t.Errorf("version = %q, want %q", got, "0.0.0-test")
	}
}

// TestHelpDocumentsOnlyWhatExists keeps help and implementation in step.
//
// Help that advertises a flag the build does not have is a support ticket. The
// forbidden list is the surface ADR 0049 refuses outright or defers: a literal
// --password, environment variables, an interactive prompt, and the Phase 5.3
// renderer's flags.
//
// The literal --password is matched with a boundary, because --password-file and
// --password-stdin legitimately contain it as a prefix.
func TestHelpDocumentsOnlyWhatExists(t *testing.T) {
	literalPassword := regexp.MustCompile(`--password([^-\w]|$)`)

	for _, args := range [][]string{{"--help"}, {"diagnose", "--help"}, {"diagnose", "postgres", "--help"}} {
		h := newHarness(app.Result{}, nil)
		h.run(args...)
		text := h.stdout.String()

		if literalPassword.MatchString(text) {
			t.Errorf("`%s` help offers a literal --password; ADR 0049 refuses it outright",
				strings.Join(args, " "))
		}
		for _, word := range []string{
			"PGPASSWORD", "SVCDOCTOR_PASSWORD", "environment variable",
			"prompt", "--color", "--verbose", "inspect", "kafka",
		} {
			if strings.Contains(text, word) {
				t.Errorf("`%s` help mentions %q, which is refused or deferred",
					strings.Join(args, " "), word)
			}
		}
		// Absolute safety claims are not this tool's to make about someone
		// else's filesystem and pipeline (ADR 0049). Matched on whole words, so
		// that --tls-insecure does not read as a claim that something is secure.
		for _, claim := range []string{"safer", "secure", "protected"} {
			if regexp.MustCompile(`\b` + claim + `\b`).MatchString(text) {
				t.Errorf("`%s` help claims %q about a credential source",
					strings.Join(args, " "), claim)
			}
		}
	}
}

// TestNoLiteralPasswordFlagExists is the behavioural half: help could be right
// and the flag could still be registered.
func TestNoLiteralPasswordFlagExists(t *testing.T) {
	for _, args := range [][]string{
		{"--password", "hunter2"},
		{"--password=hunter2"},
	} {
		h := newHarness(app.Result{}, nil)
		full := append([]string{"diagnose", "postgres", "--host", "db", "--user", "app"}, args...)
		code := h.run(full...)

		if code != ExitUsage {
			t.Errorf("%v: exit = %d, want %d; a literal password flag must not exist",
				args, code, ExitUsage)
		}
		if h.calls != 0 {
			t.Errorf("%v: the application ran", args)
		}
		if strings.Contains(h.stderr.String(), "hunter2") {
			t.Errorf("%v: the rejection echoed the value", args)
		}
	}
}

// --- flags --------------------------------------------------------------------

func TestInvalidInvocations(t *testing.T) {
	base := []string{"diagnose", "postgres"}
	tests := []struct {
		name string
		args []string
	}{
		{"missing host", []string{"--user", "app"}},
		{"missing user", []string{"--host", "db"}},
		{"port zero", []string{"--host", "db", "--user", "app", "--port", "0"}},
		{"port above range", []string{"--host", "db", "--user", "app", "--port", "65536"}},
		{"port negative", []string{"--host", "db", "--user", "app", "--port", "-1"}},
		{"port not a number", []string{"--host", "db", "--user", "app", "--port", "abc"}},
		{"timeout malformed", []string{"--host", "db", "--user", "app", "--timeout", "soon"}},
		{"timeout zero", []string{"--host", "db", "--user", "app", "--timeout", "0"}},
		{"timeout negative", []string{"--host", "db", "--user", "app", "--timeout", "-1s"}},
		{"step timeout malformed", []string{"--host", "db", "--user", "app", "--step-timeout", "soon"}},
		{"step timeout zero", []string{"--host", "db", "--user", "app", "--step-timeout", "0"}},
		{"step timeout negative", []string{"--host", "db", "--user", "app", "--step-timeout", "-1s"}},
		{"tls mode unknown", []string{"--host", "db", "--user", "app", "--tls", "prefer"}},
		{"tls mode verify-full", []string{"--host", "db", "--user", "app", "--tls", "verify-full"}},
		{"output unknown", []string{"--host", "db", "--user", "app", "--output", "yaml"}},
		{"unknown flag", []string{"--host", "db", "--user", "app", "--sslmode", "require"}},
		{"positional argument", []string{"--host", "db", "--user", "app", "extra"}},
		{"ca file missing", []string{"--host", "db", "--user", "app", "--tls-ca-file", "/nonexistent/ca.pem"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(app.Result{}, nil)
			code := h.run(append(append([]string{}, base...), tt.args...)...)

			if code != ExitUsage {
				t.Errorf("exit = %d, want %d", code, ExitUsage)
			}
			if h.stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty: an invalid invocation writes no artifact",
					h.stdout.String())
			}
			if h.stderr.Len() == 0 {
				t.Error("stderr is empty; an operator needs to know what was wrong")
			}
			if h.calls != 0 {
				t.Error("the application ran despite invalid input")
			}
		})
	}
}

func TestParametersAreBuiltFromFlags(t *testing.T) {
	h := newHarness(resultOKComplete(t), nil)
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	writeCA(t, caPath)

	code := h.run("diagnose", "postgres",
		"--host", "db.internal",
		"--port", "6432",
		"--user", "app",
		"--database", "appdb",
		"--timeout", "45s",
		"--step-timeout", "3s",
		"--tls", "require",
		"--tls-ca-file", caPath,
		"--tls-server-name", "db.example",
		"--tls-insecure",
	)
	if code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}

	got := h.captured
	if got.Host != "db.internal" || got.Port != 6432 {
		t.Errorf("endpoint = %s:%d", got.Host, got.Port)
	}
	if got.Role != "app" || got.Database != "appdb" {
		t.Errorf("identity = %s/%s", got.Role, got.Database)
	}
	if got.StepTimeout != 3*time.Second {
		t.Errorf("StepTimeout = %s, want 3s; the per-step budget must reach the run",
			got.StepTimeout)
	}
	if got.TLS != adapterpostgres.TLSRequired {
		t.Errorf("TLS = %v, want TLSRequired", got.TLS)
	}
	if got.TLSOptions.ServerName != "db.example" {
		t.Errorf("ServerName = %q", got.TLSOptions.ServerName)
	}
	if got.TLSOptions.RootCAs == nil {
		t.Error("RootCAs is nil; --tls-ca-file was not loaded")
	}
	if !got.TLSOptions.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = false; --tls-insecure was not applied")
	}
	if got.Vantage.IsZero() {
		t.Error("vantage is zero; it must come from internal/platform/local")
	}
	if got.Vantage.Source() != domain.VantageSourceLocalHost {
		t.Errorf("vantage source = %s, want LOCAL_HOST", got.Vantage.Source())
	}
	if got.Version != "0.0.0-test" {
		t.Errorf("Version = %q; the report records svcdoctor's own version", got.Version)
	}
	// **No credential in Phase 5.1**, and nothing in the CLI can build one.
	if !got.Credential.IsZero() {
		t.Error("a credential reached the parameters; Phase 5.1 carries none")
	}
}

func TestDefaults(t *testing.T) {
	h := newHarness(resultOKComplete(t), nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	got := h.captured

	if got.Port != 5432 {
		t.Errorf("default port = %d, want 5432", got.Port)
	}
	if got.StepTimeout != 10*time.Second {
		t.Errorf("default step timeout = %s, want 10s", got.StepTimeout)
	}
	if got.TLS != adapterpostgres.TLSRequired {
		t.Error("default TLS plan is not require; encryption must not be opt-in")
	}
	if got.TLSOptions.InsecureSkipVerify {
		t.Error("verification is disabled by default")
	}
	if got.TLSOptions.RootCAs != nil {
		t.Error("a trust source was invented; nil means the system store")
	}
	// Database stays empty. svcdoctor invents no client-side `database = user`:
	// the wire omits the parameter and the server defaults it, so the report
	// reflects exactly what was sent.
	if got.Database != "" {
		t.Errorf("default database = %q, want empty", got.Database)
	}
}

func TestDefaultRootTimeoutBoundsTheRun(t *testing.T) {
	// The whole-run budget is not a parameter, so it is observed through the
	// context the application receives.
	h := &harness{}
	h.app = &App{Stdout: &h.stdout, Stderr: &h.stderr, Version: "0.0.0-test"}
	var deadline time.Time
	var hasDeadline bool
	h.app.diagnosePostgres = func(ctx context.Context, _ app.PostgresParams) (app.Result, error) {
		deadline, hasDeadline = ctx.Deadline()
		return resultOKComplete(t), nil
	}

	before := time.Now()
	if code := h.app.Run(context.Background(), []string{
		"diagnose", "postgres", "--host", "db", "--user", "app",
	}); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	if !hasDeadline {
		t.Fatal("the application ran with no deadline; --timeout must bound the run")
	}
	if budget := deadline.Sub(before); budget < 29*time.Second || budget > 31*time.Second {
		t.Errorf("root budget = %s, want ~30s", budget)
	}
}

func TestTLSDisableMaps(t *testing.T) {
	h := newHarness(resultOKComplete(t), nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--tls", "disable"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	if h.captured.TLS != adapterpostgres.TLSDisabled {
		t.Errorf("TLS = %v, want TLSDisabled", h.captured.TLS)
	}
}

func TestCAFileContentsNeverReachAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-cert.pem")
	const canary = "CANARY-THIS-IS-FILE-CONTENT"
	if err := os.WriteFile(path, []byte(canary), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	h := newHarness(app.Result{}, nil)
	code := h.run("diagnose", "postgres", "--host", "db", "--user", "app", "--tls-ca-file", path)
	if code != ExitUsage {
		t.Fatalf("exit = %d, want %d", code, ExitUsage)
	}
	if strings.Contains(h.stderr.String(), canary) {
		t.Error("the error echoed the file's contents")
	}
	if !strings.Contains(h.stderr.String(), path) {
		t.Error("the error does not name the path; an operator cannot fix it")
	}
}

func writeCA(t *testing.T, path string) {
	t.Helper()
	// A real self-signed certificate, generated here rather than pasted, so the
	// fixture cannot rot into something x509 stops accepting. Verification
	// itself belongs to internal/probe/tls; all this proves is that the CLI
	// loaded a trust source.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// --- output routing -----------------------------------------------------------

func TestReportProducingRunsWriteOnlyTheArtifact(t *testing.T) {
	tests := []struct {
		name   string
		result func(*testing.T) app.Result
		want   int
	}{
		{"ok and complete", resultOKComplete, ExitOK},
		{"problems and complete", resultProblemsComplete, ExitProblemsFound},
		{"ok and incomplete", resultOKIncomplete, ExitIncomplete},
		{"problems and incomplete", resultProblemsIncomplete, ExitIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHarness(tt.result(t), nil)
			code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
				"--output", "json")

			if code != tt.want {
				t.Errorf("exit = %d, want %d", code, tt.want)
			}
			if h.stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty for a run that produced a report",
					h.stderr.String())
			}

			var decoded map[string]any
			if err := json.Unmarshal(h.stdout.Bytes(), &decoded); err != nil {
				t.Fatalf("stdout is not valid JSON: %v", err)
			}
			if decoded["schemaVersion"] != float64(domain.SchemaVersion) {
				t.Errorf("schemaVersion = %v, want %d", decoded["schemaVersion"], domain.SchemaVersion)
			}
			// The canonical artifact and nothing wrapped around it.
			for _, invented := range []string{"report", "incomplete", "exitCode", "sessionEstablished"} {
				if _, ok := decoded[invented]; ok {
					t.Errorf("the JSON carries %q; the artifact is the canonical report alone",
						invented)
				}
			}
			if !bytes.HasSuffix(h.stdout.Bytes(), []byte("\n")) {
				t.Error("the artifact does not end with a newline")
			}
			if bytes.Contains(h.stdout.Bytes(), []byte("\x1b[")) {
				t.Error("the artifact contains an ANSI escape")
			}
		})
	}
}

// TestIncompleteIsNotInTheReport pins the asymmetry ADR 0048 chose deliberately.
func TestIncompleteIsNotInTheReport(t *testing.T) {
	result := resultOKIncomplete(t)
	if !result.Incomplete() {
		t.Fatal("the fixture is not incomplete; this test proves nothing")
	}

	h := newHarness(result, nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--output", "json"); code != ExitIncomplete {
		t.Fatalf("exit = %d, want %d", code, ExitIncomplete)
	}
	if strings.Contains(h.stdout.String(), "incomplete") {
		t.Error("the report mentions incompleteness; a report cannot observe its own partiality " +
			"(docs/REPORT_SCHEMA.md section 8) and machines read exit code 4")
	}
}

func TestTheArtifactIsDeterministic(t *testing.T) {
	result := resultProblemsComplete(t)
	first := newHarness(result, nil)
	second := newHarness(result, nil)
	first.run("diagnose", "postgres", "--host", "db", "--user", "app")
	second.run("diagnose", "postgres", "--host", "db", "--user", "app")

	if first.stdout.String() != second.stdout.String() {
		t.Error("the same report produced different bytes")
	}
}

func TestInternalFailureWritesNoArtifact(t *testing.T) {
	h := newHarness(app.Result{}, errors.New("the graph could not be frozen"))
	code := h.run("diagnose", "postgres", "--host", "db", "--user", "app")

	if code != ExitInternal {
		t.Errorf("exit = %d, want %d", code, ExitInternal)
	}
	if h.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty when no usable report exists", h.stdout.String())
	}
	if h.stderr.Len() == 0 {
		t.Error("stderr is empty for an internal failure")
	}
}

func TestApplicationInputErrorIsAnInvocationError(t *testing.T) {
	// internal/app rejecting its parameters is the same class of fact as this
	// package rejecting a flag, one layer down.
	h := newHarness(app.Result{}, app.ErrInvalidInput)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app"); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
	if h.stdout.Len() != 0 {
		t.Error("an invalid-input failure wrote an artifact")
	}
}

// --- the product invariant ----------------------------------------------------

// TestNoCredentialIsNotAnInvocationError is the Phase 5.1 product acceptance.
//
// A run with no credential is a valid, useful diagnosis, not a usage mistake.
// The CLI neither prompts, nor reads an environment variable, nor rejects it —
// it passes a zero credential and lets the endpoint's own demand produce the
// finding.
func TestNoCredentialIsNotAnInvocationError(t *testing.T) {
	result := resultWarnComplete(t)

	// The fixture must actually be the WARN-on-an-OK-report shape, or this test
	// proves only that a clean run exits 0.
	if result.Report().FindingCount() == 0 {
		t.Fatal("the fixture produced no finding; the endpoint did not demand authentication")
	}
	if got := result.Report().Summary().Status(); got != domain.SummaryStatusOK {
		t.Fatalf("fixture status = %s, want OK", got)
	}
	if result.Incomplete() {
		t.Fatal("the fixture is incomplete; nothing was cancelled")
	}

	h := newHarness(result, nil)
	code := h.run("diagnose", "postgres", "--host", "db", "--user", "app")

	if code != ExitOK {
		t.Fatalf("exit = %d, want %d; a WARN on an OK report is not a target-side error",
			code, ExitOK)
	}
	if h.calls != 1 {
		t.Fatalf("the application ran %d times, want 1", h.calls)
	}
	if !h.captured.Credential.IsZero() {
		t.Error("a credential was constructed; Phase 5.1 has no credential source")
	}
}

// TestTheCLINeverInspectsFindingCodes proves the exit code is derived from the
// report's own summary rather than from a code this package recognizes.
//
// A WARN finding with status OK exits 0 — not because the CLI knows what
// POSTGRES_CREDENTIAL_NOT_CONFIGURED is, but because the report already says the
// run completed and proved no target-side error.
func TestTheCLINeverInspectsFindingCodes(t *testing.T) {
	for _, name := range []string{"postgres.go", "exit.go", "root.go"} {
		code := sourceWithoutComments(t, name)
		for _, forbidden := range []string{
			"POSTGRES_", "KAFKA_", "DNS_NAME", "TCP_CONNECTION",
			"SeverityError", "SeverityWarn", "SeverityCritical", "SeverityInfo",
			"Findings()", "FindingCount()", "FindingCode",
		} {
			if strings.Contains(code, forbidden) {
				t.Errorf("%s references %q in code; the command reads Summary().Status() "+
					"and never a finding or a severity", name, forbidden)
			}
		}
	}
}

// sourceWithoutComments returns a file's code with every comment removed.
//
// The distinction matters: this package's comments discuss
// POSTGRES_CREDENTIAL_NOT_CONFIGURED at length, because explaining *why* the
// exit code ignores it is the point. What must not exist is a reference in the
// code itself.
func sourceWithoutComments(t *testing.T, name string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", name, err)
	}
	var out strings.Builder
	if err := printer.Fprint(&out, fset, parsed); err != nil {
		t.Fatalf("printing %s: %v", name, err)
	}
	return out.String()
}

// --- shareable output ---------------------------------------------------------

// runWithStdin drives the command with credential material on the injected
// input, so the stdin path is exercised without a subprocess.
func (h *harness) runWithStdin(stdin string, args ...string) int {
	h.app.In = strings.NewReader(stdin)
	return h.app.Run(context.Background(), args)
}

func decode(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	return out
}

func outputMode(t *testing.T, decoded map[string]any) string {
	t.Helper()
	security, ok := decoded["security"].(map[string]any)
	if !ok {
		t.Fatal("the report has no security section")
	}
	mode, _ := security["outputMode"].(string)
	return mode
}

// TestShareableSelectsTheRedactedProjection covers the flag's whole effect.
func TestShareableSelectsTheRedactedProjection(t *testing.T) {
	result := resultProblemsComplete(t)

	local := newHarness(result, nil)
	if code := local.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--output", "json"); code != ExitProblemsFound {
		t.Fatalf("local exit = %d: %s", code, local.stderr.String())
	}
	shared := newHarness(result, nil)
	if code := shared.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--shareable", "--output", "json"); code != ExitProblemsFound {
		t.Fatalf("shareable exit = %d: %s", code, shared.stderr.String())
	}

	localDoc := decode(t, local.stdout.Bytes())
	sharedDoc := decode(t, shared.stdout.Bytes())

	if got := outputMode(t, localDoc); got != domain.OutputModeLocalFull.String() {
		t.Errorf("default output mode = %s, want LOCAL_FULL", got)
	}
	if got := outputMode(t, sharedDoc); got != domain.OutputModeShareableRedacted.String() {
		t.Errorf("--shareable output mode = %s, want SHAREABLE_REDACTED", got)
	}

	// Both remain the canonical report: same schema version, same top-level
	// keys, no wrapper and no invented field.
	for name, doc := range map[string]map[string]any{"local": localDoc, "shareable": sharedDoc} {
		if doc["schemaVersion"] != float64(domain.SchemaVersion) {
			t.Errorf("%s: schemaVersion = %v", name, doc["schemaVersion"])
		}
		for _, invented := range []string{"report", "incomplete", "exitCode", "shareable", "sessionEstablished"} {
			if _, ok := doc[invented]; ok {
				t.Errorf("%s: the artifact carries %q", name, invented)
			}
		}
	}
	if shared.stderr.Len() != 0 {
		t.Errorf("stderr = %q; --shareable announces nothing", shared.stderr.String())
	}
}

// TestShareableCannotChangeTheExitCode is load-bearing.
//
// Redaction changes what a shared copy reveals, never what was concluded. A run
// that exits 1 locally must exit 1 shared, or the flag would be able to hide a
// problem from a pipeline.
func TestShareableCannotChangeTheExitCode(t *testing.T) {
	tests := []struct {
		name   string
		result func(*testing.T) app.Result
		want   int
	}{
		{"healthy", resultOKComplete, ExitOK},
		{"warning only", resultWarnComplete, ExitOK},
		{"target error", resultProblemsComplete, ExitProblemsFound},
		{"incomplete", resultOKIncomplete, ExitIncomplete},
		{"incomplete with an error", resultProblemsIncomplete, ExitIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.result(t)

			local := newHarness(result, nil)
			localCode := local.run("diagnose", "postgres", "--host", "db", "--user", "app")
			shared := newHarness(result, nil)
			sharedCode := shared.run("diagnose", "postgres", "--host", "db", "--user", "app",
				"--shareable")

			if localCode != tt.want || sharedCode != tt.want {
				t.Errorf("exit local = %d, shareable = %d, want %d",
					localCode, sharedCode, tt.want)
			}
			if shared.stdout.Len() == 0 {
				t.Error("the shareable run produced no artifact")
			}
		})
	}
}

// TestShareablePreservesTheDiagnosis pins what redaction may not touch.
func TestShareablePreservesTheDiagnosis(t *testing.T) {
	result := resultProblemsComplete(t)

	local := newHarness(result, nil)
	local.run("diagnose", "postgres", "--host", "db", "--user", "app", "--output", "json")
	shared := newHarness(result, nil)
	shared.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--shareable", "--output", "json")

	localDoc := decode(t, local.stdout.Bytes())
	sharedDoc := decode(t, shared.stdout.Bytes())

	// The summary is re-derived by redaction rather than copied, so equality
	// here is a statement about the diagnosis surviving, not about a memcpy.
	if !reflect.DeepEqual(localDoc["summary"], sharedDoc["summary"]) {
		t.Errorf("the summary changed under redaction:\n local: %v\n shared: %v",
			localDoc["summary"], sharedDoc["summary"])
	}

	localFindings, _ := localDoc["findings"].([]any)
	sharedFindings, _ := sharedDoc["findings"].([]any)
	if len(localFindings) != len(sharedFindings) || len(sharedFindings) == 0 {
		t.Fatalf("findings: local %d, shared %d", len(localFindings), len(sharedFindings))
	}
	for i := range localFindings {
		l, _ := localFindings[i].(map[string]any)
		s, _ := sharedFindings[i].(map[string]any)
		for _, field := range []string{"code", "kind", "severity", "confidence", "layer", "vantageDependent"} {
			if l[field] != s[field] {
				t.Errorf("finding %d: %s changed under redaction: %v -> %v",
					i, field, l[field], s[field])
			}
		}
	}

	// Timings are not identity and are not touched.
	localNodes := nodesByStep(t, localDoc)
	sharedNodes := nodesByStep(t, sharedDoc)
	for step, ln := range localNodes {
		sn, ok := sharedNodes[step]
		if !ok {
			t.Errorf("step %s vanished under redaction", step)
			continue
		}
		for _, field := range []string{"startedAt", "durationMs", "duration", "state", "failureClass"} {
			if lv, ok := ln[field]; ok && lv != sn[field] {
				t.Errorf("%s: %s changed under redaction: %v -> %v", step, field, lv, sn[field])
			}
		}
	}
}

func nodesByStep(t *testing.T, doc map[string]any) map[string]map[string]any {
	t.Helper()
	evidence, ok := doc["evidence"].(map[string]any)
	if !ok {
		t.Fatal("no evidence section")
	}
	raw, _ := evidence["nodes"].([]any)
	out := map[string]map[string]any{}
	for _, n := range raw {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		step, _ := node["step"].(string)
		out[step] = node
	}
	return out
}

// TestTheLocalReportSurvivesRedaction proves the projection is derivative.
//
// If redaction mutated its input, the truthful report the exit code was derived
// from would be gone by the time anything else looked at it.
func TestTheLocalReportSurvivesRedaction(t *testing.T) {
	result := resultProblemsComplete(t)

	before, err := json.Marshal(result.Report())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	h := newHarness(result, nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--shareable"); code != ExitProblemsFound {
		t.Fatalf("exit = %d", code)
	}

	after, err := json.Marshal(result.Report())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("deriving the shareable report mutated the local one")
	}
}

// TestShareableIsAppliedOnce guards against a second pass.
//
// redaction.Redact is idempotent — a SHAREABLE_REDACTED report is returned
// unchanged rather than pseudonymized into host-002 — so double redaction would
// not corrupt the output. This asserts the stronger property directly: the
// command applies it once, and the renderer cannot apply it at all.
func TestShareableIsAppliedOnce(t *testing.T) {
	result := resultProblemsComplete(t)
	first := newHarness(result, nil)
	first.run("diagnose", "postgres", "--host", "db", "--user", "app", "--shareable")
	second := newHarness(result, nil)
	second.run("diagnose", "postgres", "--host", "db", "--user", "app", "--shareable")

	if first.stdout.String() != second.stdout.String() {
		t.Error("two shareable runs of one report produced different bytes")
	}
	if strings.Contains(sourceWithoutComments(t, "postgres.go"), "redaction.Redact") &&
		strings.Count(sourceWithoutComments(t, "postgres.go"), "redaction.Redact") != 1 {
		t.Error("redaction is applied more than once")
	}
}

// --- the credential path through the command ---------------------------------

// TestCredentialReachesTheParameters covers both sources end to end.
func TestCredentialReachesTheParameters(t *testing.T) {
	t.Run("from a file", func(t *testing.T) {
		h := newHarness(resultOKComplete(t), nil)
		path := writeFile(t, "hunter2\n")
		if code := h.run("diagnose", "postgres", "--host", "db.internal", "--user", "app",
			"--output", "json", "--password-file", path); code != ExitOK {
			t.Fatalf("exit = %d: %s", code, h.stderr.String())
		}
		requireBoundCredential(t, h)
	})

	t.Run("from stdin", func(t *testing.T) {
		h := newHarness(resultOKComplete(t), nil)
		if code := h.runWithStdin("hunter2\n", "diagnose", "postgres",
			"--host", "db.internal", "--user", "app", "--output", "json",
			"--password-stdin"); code != ExitOK {
			t.Fatalf("exit = %d: %s", code, h.stderr.String())
		}
		requireBoundCredential(t, h)
	})
}

func requireBoundCredential(t *testing.T, h *harness) {
	t.Helper()
	if h.calls != 1 {
		t.Fatalf("the application ran %d times", h.calls)
	}
	// **The credential path adds no chatter.** Reading a secret is not an event
	// worth announcing, and a line like "password loaded" before the artifact
	// would make stdout unparseable for the pipeline the flag exists to serve.
	if h.stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", h.stderr.String())
	}
	if !json.Valid(h.stdout.Bytes()) {
		t.Errorf("stdout is not valid JSON; something was written beside the artifact: %q",
			h.stdout.String())
	}
	if h.captured.Credential.IsZero() {
		t.Fatal("no credential reached the parameters")
	}
	endpoint, err := security.NewEndpoint("db.internal", 5432)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	if _, err := h.captured.Credential.SecretFor(endpoint); err != nil {
		t.Errorf("the credential is not bound to the requested endpoint: %v", err)
	}
}

// TestNoCredentialSourceLeavesTheParametersUnchanged is the Phase 5.1
// regression: adding credential support must not make one required.
func TestNoCredentialSourceLeavesTheParametersUnchanged(t *testing.T) {
	h := newHarness(resultWarnComplete(t), nil)
	code := h.runWithStdin("material-nobody-asked-for",
		"diagnose", "postgres", "--host", "db", "--user", "app")

	if code != ExitOK {
		t.Fatalf("exit = %d, want %d", code, ExitOK)
	}
	if !h.captured.Credential.IsZero() {
		t.Error("a credential appeared without a source flag")
	}
}

// TestTheCredentialNeverReachesAnyStream is the security sweep at this boundary.
func TestTheCredentialNeverReachesAnyStream(t *testing.T) {
	const canary = "CANARY-PASSWORD-8f3a1c"

	for _, mode := range []string{"local", "shareable"} {
		for _, source := range []string{"file", "stdin"} {
			h := newHarness(resultOKComplete(t), nil)
			args := []string{"diagnose", "postgres", "--host", "db.internal", "--user", "app"}
			if mode == "shareable" {
				args = append(args, "--shareable")
			}

			var code int
			if source == "file" {
				code = h.run(append(args, "--password-file", writeFile(t, canary+"\n"))...)
			} else {
				code = h.runWithStdin(canary+"\n", append(args, "--password-stdin")...)
			}
			if code != ExitOK {
				t.Fatalf("%s/%s: exit = %d: %s", mode, source, code, h.stderr.String())
			}

			if strings.Contains(h.stdout.String(), canary) {
				t.Errorf("%s/%s: the credential reached stdout", mode, source)
			}
			if strings.Contains(h.stderr.String(), canary) {
				t.Errorf("%s/%s: the credential reached stderr", mode, source)
			}
		}
	}
}

// TestTheCLINeverRevealsASecret pins the Reveal boundary in this package.
func TestTheCLINeverRevealsASecret(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		code := sourceWithoutComments(t, name)
		for _, forbidden := range []string{"Reveal", "SecretFor", "os.Getenv", "os.Stdin"} {
			if strings.Contains(code, forbidden) {
				t.Errorf("%s references %q; the CLI constructs a Secret and never opens it, "+
					"reads no environment, and takes its input through App.In", name, forbidden)
			}
		}
	}
}

// TestRedactionFailingClosedIsAnInternalFailure pins ADR 0048's output-failure
// path against the one condition that really triggers it.
//
// A role named after the tool collides with the word finding prose uses, so the
// residual scan refuses rather than emit a report whose promise is false
// (test/security pins the refusal itself). The command must surface that as an
// output failure with **nothing on stdout**: a half-redacted artifact is the one
// thing worse than no artifact, because a caller who received one would share it.
func TestRedactionFailingClosedIsAnInternalFailure(t *testing.T) {
	p := newPeer(t, func(conn net.Conn) {
		if _, err := io.ReadFull(conn, make([]byte, 8)); err != nil {
			return
		}
		_, _ = conn.Write([]byte{'X'})
	})
	ap := p.addrPort(t)

	result, err := app.DiagnosePostgres(context.Background(), app.PostgresParams{
		Host: "db.internal", Port: ap.Port(),
		Role:     "svcdoctor", // collides with the word used in finding prose
		Resolver: stubResolver{addrs: []netip.Addr{ap.Addr()}},
		Dialer:   toPeer{target: ap},
		Vantage:  mustVantage(t),
		Version:  "0.0.0-test", StepTimeout: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	if len(result.Report().Findings()) == 0 {
		t.Fatal("the run produced no finding; the collision is not reproduced")
	}

	// Locally it renders fine: nothing about the run failed.
	local := newHarness(result, nil)
	if code := local.run("diagnose", "postgres", "--host", "db", "--user", "app"); code != ExitProblemsFound {
		t.Fatalf("local exit = %d, want %d", code, ExitProblemsFound)
	}

	shared := newHarness(result, nil)
	code := shared.run("diagnose", "postgres", "--host", "db", "--user", "app", "--shareable")
	if code != ExitInternal {
		t.Errorf("exit = %d, want %d; a refused redaction is an output failure",
			code, ExitInternal)
	}
	if shared.stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty; no partially redacted report may escape",
			shared.stdout.String())
	}
	if shared.stderr.Len() == 0 {
		t.Error("stderr is empty; the operator is not told why nothing was produced")
	}
}

func mustVantage(t *testing.T) domain.Vantage {
	t.Helper()
	v, err := domain.NewLocalVantage("svcdoctor-test")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	return v
}

// TestShareablePreservesAWarning closes the gap a mutation pass found.
//
// Every other shareable test used a report carrying an ERROR or none at all, so
// a projection that quietly returned the *unredacted* report whenever a warning
// was present went unnoticed — which would leak identity on exactly the run an
// operator is most likely to share, the one where nothing is broken.
func TestShareablePreservesAWarning(t *testing.T) {
	result := resultWarnComplete(t)
	if result.Report().Summary().FindingCountsBySeverity().Warn == 0 {
		t.Fatal("the fixture carries no warning; this test proves nothing")
	}

	h := newHarness(result, nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--shareable", "--output", "json"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}

	doc := decode(t, h.stdout.Bytes())
	if got := outputMode(t, doc); got != domain.OutputModeShareableRedacted.String() {
		t.Errorf("output mode = %s, want SHAREABLE_REDACTED; the warning suppressed redaction",
			got)
	}
	if counts, _ := doc["summary"].(map[string]any); counts != nil {
		severities, _ := counts["findingCountsBySeverity"].(map[string]any)
		if severities["warn"] == float64(0) {
			t.Error("the warning did not survive redaction")
		}
	}
}

// closeTrackingReader reports whether anything closed it.
type closeTrackingReader struct {
	*strings.Reader
	closed bool
}

func (c *closeTrackingReader) Close() error {
	c.closed = true
	return nil
}

// TestTheCLINeverClosesItsInput pins a hazard unit tests could not see.
//
// A strings.Reader is not an io.Closer, so a mutation that closed stdin when it
// could was invisible to every other test here — while in production it would
// close the process's own standard input, which the CLI does not own and a shell
// pipeline may still be writing to.
func TestTheCLINeverClosesItsInput(t *testing.T) {
	in := &closeTrackingReader{Reader: strings.NewReader("hunter2\n")}
	h := newHarness(resultOKComplete(t), nil)
	h.app.In = in

	if code := h.app.Run(context.Background(), []string{
		"diagnose", "postgres", "--host", "db", "--user", "app", "--password-stdin",
	}); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	if in.closed {
		t.Error("the command closed its input; stdin belongs to the process, not to svcdoctor")
	}
}
