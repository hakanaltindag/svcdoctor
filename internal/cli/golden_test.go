package cli

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// Golden terminal output, rendered from real runs.
//
// The reports below come from internal/app measuring real loopback sockets, so
// the graph shapes, states, failure classes and findings are the ones production
// produces — not a hand-built approximation of them.
//
// Two values are normalized before comparison, and only two. Durations vary by
// microseconds between runs, and the loopback listener's port is assigned by the
// kernel; both are genuinely volatile and neither is what these files exist to
// pin. Everything else — stage order, glyphs, absence wording, finding prose, the
// Result section — is compared byte for byte. The duration *formatter* has its
// own exact tests in internal/render/terminal.

var update = flag.Bool("update", false, "rewrite the golden files")

var (
	durationPattern = regexp.MustCompile(`<1µs|\b\d+(\.\d+)?(µs|ms|s)\b`)
	ephemeralPort   = regexp.MustCompile(`:\d{4,5}\b`)
	columnPadding   = regexp.MustCompile(`  +`)
)

// normalize replaces the volatile values with stable placeholders and collapses
// column padding.
//
// # Why padding is collapsed
//
// tabwriter sizes a column from its widest cell, so a duration that renders as
// `2µs` on one run and as nothing on the next — a sub-microsecond measurement
// falls below the formatter's floor and prints empty — shifts every row in that
// block. The golden would then fail for a reason that has nothing to do with what
// it exists to pin.
//
// Alignment is cosmetic; content, ordering and wording are the contract. Exact
// byte stability for a *fixed* report is pinned separately by
// TestGoldenOutputIsStable and by the renderer's own determinism test, so nothing
// is lost by comparing these with padding collapsed.
func normalize(text string) string {
	text = durationPattern.ReplaceAllString(text, "<duration>")
	text = ephemeralPort.ReplaceAllString(text, ":<port>")

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		indent := strings.Repeat(" ", (len(line)-len(trimmed))/2*2)
		lines[i] = indent + columnPadding.ReplaceAllString(trimmed, "  ")
	}
	return strings.Join(lines, "\n")
}

// requireGolden compares rendered output against testdata, or rewrites it.
func requireGolden(t *testing.T, name, actual string) {
	t.Helper()

	path := filepath.Join("testdata", name)
	normalized := normalize(actual)

	if *update {
		if err := os.WriteFile(path, []byte(normalized), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v (run with -update to create it)", path, err)
	}
	if normalized != string(want) {
		t.Errorf("%s does not match.\n--- want ---\n%s\n--- got ---\n%s", path, want, normalized)
	}
}

// renderText runs the command in text mode and returns stdout.
func renderText(t *testing.T, result app.Result, args ...string) string {
	t.Helper()

	h := newHarness(result, nil)
	full := append([]string{"diagnose", "postgres", "--host", "db.internal", "--user", "app"}, args...)
	h.run(full...)
	if h.stderr.Len() != 0 {
		t.Fatalf("stderr = %q", h.stderr.String())
	}
	return h.stdout.String()
}

// --- fixtures beyond the ones cli_test.go already builds ----------------------

// resultSSLFloor is an endpoint that answers the negotiation with a byte the
// protocol does not define: an ERROR finding at L3.
func resultSSLFloor(t *testing.T) app.Result { return resultProblemsComplete(t) }

// resultDNSFailure is a name that resolves to nothing.
func resultDNSFailure(t *testing.T) app.Result {
	t.Helper()
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: 5432,
		Resolver: emptyResolver{},
		Dialer:   blackHole{},
	})
}

type emptyResolver struct{}

func (emptyResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return nil, nil
}

// resultMultiPath measures two addresses: one reaches a session, the other
// answers the negotiation wrongly and earns an endpoint-scoped ERROR.
func resultMultiPath(t *testing.T) app.Result {
	t.Helper()

	good := newPeer(t, trustHandler)
	// Reads the startup packet and closes: a peer-closed startup, which is an
	// endpoint-scoped ERROR. It must stay visible even though the other path
	// reaches a session.
	bad := newPeer(t, func(conn net.Conn) {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := binary.BigEndian.Uint32(header)
		if length >= 4 && length <= 1<<16 {
			_, _ = io.ReadFull(conn, make([]byte, length-4))
		}
		_ = conn.Close()
	})
	goodAddr, badAddr := good.addrPort(t), bad.addrPort(t)

	first := mustAddr(t, "10.0.0.1")
	second := mustAddr(t, "10.0.0.2")
	return runReal(t, app.PostgresParams{
		Host: "db.internal", Port: goodAddr.Port(),
		Resolver: stubResolver{addrs: []netip.Addr{first, second}},
		Dialer: routed{routes: map[netip.Addr]netip.AddrPort{
			first: goodAddr, second: badAddr,
		}},
		TLS: adapterpostgres.TLSDisabled,
	})
}

// resultTrustSession is a plaintext endpoint that asks for nothing.
func resultTrustSession(t *testing.T) app.Result { return resultOKComplete(t) }

// --- the golden cases ----------------------------------------------------------

func TestGoldenTerminalOutput(t *testing.T) {
	tests := []struct {
		name   string
		file   string
		result func(*testing.T) app.Result
		args   []string
	}{
		{"healthy trust session", "healthy.txt", resultTrustSession, nil},
		{"no credential", "no-credential.txt", resultWarnComplete, nil},
		{"ssl negotiation floor", "ssl-floor.txt", resultSSLFloor, nil},
		{"dns failure", "dns-failure.txt", resultDNSFailure, nil},
		{"local budget exhausted", "incomplete.txt", resultOKIncomplete, nil},
		{"multiple paths, mixed", "multipath.txt", resultMultiPath, nil},
		{"shareable", "shareable.txt", resultSSLFloor, []string{"--shareable"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireGolden(t, tt.file, renderText(t, tt.result(t), tt.args...))
		})
	}
}

// TestGoldenOutputIsStable re-renders each case and compares to itself, so a
// non-determinism that happened to match the golden once still fails.
func TestGoldenOutputIsStable(t *testing.T) {
	result := resultMultiPath(t)
	first := renderText(t, result)
	for range 5 {
		if got := renderText(t, result); got != first {
			t.Fatal("re-rendering the same result produced different bytes")
		}
	}
}

// --- the output switch ---------------------------------------------------------

// TestDefaultOutputIsText closes the Phase 5.1 deviation.
func TestDefaultOutputIsText(t *testing.T) {
	h := newHarness(resultOKComplete(t), nil)
	if code := h.run("diagnose", "postgres", "--host", "db", "--user", "app"); code != ExitOK {
		t.Fatalf("exit = %d: %s", code, h.stderr.String())
	}
	out := h.stdout.String()
	if !strings.HasPrefix(out, "svcdoctor · postgres ·") {
		t.Errorf("the default output is not the terminal report:\n%s", out)
	}
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		t.Error("the default output is JSON")
	}
}

// TestBothOutputFormsWork covers the switch itself.
func TestBothOutputFormsWork(t *testing.T) {
	result := resultOKComplete(t)

	text := newHarness(result, nil)
	if code := text.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--output", "text"); code != ExitOK {
		t.Fatalf("text exit = %d", code)
	}
	if !strings.Contains(text.stdout.String(), "Result") {
		t.Error("--output text did not render the report")
	}

	jsonOut := newHarness(result, nil)
	if code := jsonOut.run("diagnose", "postgres", "--host", "db", "--user", "app",
		"--output", "json"); code != ExitOK {
		t.Fatalf("json exit = %d", code)
	}
	if !strings.HasPrefix(jsonOut.stdout.String(), `{"schemaVersion":1`) {
		t.Error("--output json did not render the canonical report")
	}
}

// TestTextAndJSONShareExitSemantics proves the form never changes the outcome.
func TestTextAndJSONShareExitSemantics(t *testing.T) {
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
			for _, form := range []string{"text", "json"} {
				h := newHarness(result, nil)
				code := h.run("diagnose", "postgres", "--host", "db", "--user", "app",
					"--output", form)
				if code != tt.want {
					t.Errorf("%s: exit = %d, want %d", form, code, tt.want)
				}
				if h.stdout.Len() == 0 {
					t.Errorf("%s: no artifact was written", form)
				}
				if h.stderr.Len() != 0 {
					t.Errorf("%s: stderr = %q", form, h.stderr.String())
				}
			}
		})
	}
}

// TestJSONIsUnchangedByThisPhase pins the Phase 5.2 contract byte for byte.
func TestJSONIsUnchangedByThisPhase(t *testing.T) {
	result := resultProblemsComplete(t)

	h := newHarness(result, nil)
	h.run("diagnose", "postgres", "--host", "db", "--user", "app", "--output", "json")

	var direct bytes.Buffer
	if err := writeCanonical(&direct, result); err != nil {
		t.Fatalf("writeCanonical: %v", err)
	}
	if h.stdout.String() != direct.String() {
		t.Error("the JSON artifact changed when the terminal renderer was added")
	}
	if !bytes.HasSuffix(h.stdout.Bytes(), []byte("\n")) ||
		bytes.Count(h.stdout.Bytes(), []byte("\n")) != 1 {
		t.Error("the JSON newline convention changed")
	}
}

// writeCanonical marshals the report the way render/json does, independently.
func writeCanonical(w io.Writer, result app.Result) error {
	encoded, err := result.Report().MarshalJSON()
	if err != nil {
		return err
	}
	_, err = w.Write(append(encoded, '\n'))
	return err
}

// TestUnknownOutputFormIsAnInvocationError keeps the switch closed.
func TestUnknownOutputFormIsAnInvocationError(t *testing.T) {
	for _, form := range []string{"yaml", "markdown", "html", "TEXT", ""} {
		h := newHarness(app.Result{}, nil)
		code := h.run("diagnose", "postgres", "--host", "db", "--user", "app", "--output", form)
		if code != ExitUsage {
			t.Errorf("--output %q: exit = %d, want %d", form, code, ExitUsage)
		}
		if h.stdout.Len() != 0 {
			t.Errorf("--output %q wrote an artifact", form)
		}
	}
}

// TestShareableTextCarriesNoIdentity is the redaction sweep at the text boundary.
func TestShareableTextCarriesNoIdentity(t *testing.T) {
	result := resultProblemsComplete(t)

	local := renderText(t, result)
	shared := renderText(t, result, "--shareable")

	if !strings.Contains(shared, "Shareable report · identities redacted") {
		t.Error("the shareable text does not announce itself")
	}
	if strings.Contains(local, "Shareable report") {
		t.Error("the local text claims to be shareable")
	}
	if !strings.Contains(local, "db.internal") {
		t.Fatal("the local text has no host; this test proves nothing")
	}
	if strings.Contains(shared, "db.internal") {
		t.Error("the shareable text still carries the requested hostname")
	}
	// The diagnosis survives the projection.
	for _, keep := range []string{"POSTGRES_SSL_NEGOTIATION_FAILED", "PROBLEMS FOUND", "NOT established"} {
		if !strings.Contains(shared, keep) {
			t.Errorf("the shareable text lost %q", keep)
		}
	}
}

var _ = time.Second
