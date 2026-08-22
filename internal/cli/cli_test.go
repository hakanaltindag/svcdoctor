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
	"strings"
	"sync"
	"testing"
	"time"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
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
	params.Role = "svcdoctor"
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

func TestHelpDocumentsNoUnimplementedSurface(t *testing.T) {
	// Help that advertises a flag Phase 5.1 does not implement is a support
	// ticket. Phase 5.2 adds the credential flags and --shareable; until then
	// they must not appear.
	forbidden := []string{
		"--password", "--password-file", "--password-stdin",
		"--shareable", "--color", "--verbose", "inspect", "kafka",
	}
	for _, args := range [][]string{{"--help"}, {"diagnose", "--help"}, {"diagnose", "postgres", "--help"}} {
		h := newHarness(app.Result{}, nil)
		h.run(args...)
		text := h.stdout.String()
		for _, word := range forbidden {
			if strings.Contains(text, word) {
				t.Errorf("`%s` help mentions %q, which Phase 5.1 does not implement",
					strings.Join(args, " "), word)
			}
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
		{"output text is not yet implemented", []string{"--host", "db", "--user", "app", "--output", "text"}},
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
			code := h.run("diagnose", "postgres", "--host", "db", "--user", "app")

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
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app"); code != ExitIncomplete {
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
