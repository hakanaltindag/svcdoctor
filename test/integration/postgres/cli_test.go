//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The CLI against the real servers, through the real binary.
//
// Everything below builds cmd/svcdoctor and runs it as a process, because the
// contract Phase 5.1 exists to establish is a *process* contract: which stream
// carries the artifact, what the exit status is, and whether stdout stays
// parseable. A test that called internal/cli in-process would prove the routing
// and prove nothing about `$?`, which is the half automation depends on.
//
// internal/cli's own tests cover parsing, parameter construction and the exit
// mapping against scripted results; these cover the parts only a real endpoint
// and a real process can show.

// binary builds the command once per run and returns its path.
func binary(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "svcdoctor")
	build := exec.Command("go", "build", "-o", path, "./cmd/svcdoctor")
	build.Dir = repoRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the command: %v\n%s", err, out)
	}
	return path
}

// invocation is one run of the built command.
type invocation struct {
	stdout string
	stderr string
	code   int
}

func runCLI(t *testing.T, bin string, args ...string) invocation {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := cmd.ProcessState.ExitCode()
	if err != nil && code < 0 {
		t.Fatalf("running the command: %v\nstderr: %s", err, stderr.String())
	}
	return invocation{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

// canonical decodes stdout and asserts the artifact contract.
func (inv invocation) canonical(t *testing.T) map[string]any {
	t.Helper()

	if inv.stderr != "" {
		t.Errorf("stderr = %q, want empty for a run that produced a report", inv.stderr)
	}
	if !strings.HasSuffix(inv.stdout, "\n") {
		t.Error("the artifact does not end with a newline")
	}
	if strings.Contains(inv.stdout, "\x1b[") {
		t.Error("the artifact contains an ANSI escape")
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(inv.stdout), &decoded); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, inv.stdout)
	}
	if decoded["schemaVersion"] != float64(1) {
		t.Errorf("schemaVersion = %v, want 1", decoded["schemaVersion"])
	}
	for _, invented := range []string{"report", "incomplete", "exitCode", "sessionEstablished"} {
		if _, ok := decoded[invented]; ok {
			t.Errorf("the artifact carries %q; it is the canonical report alone", invented)
		}
	}
	return decoded
}

func summaryStatus(t *testing.T, decoded map[string]any) string {
	t.Helper()
	summary, ok := decoded["summary"].(map[string]any)
	if !ok {
		t.Fatal("the report has no summary")
	}
	status, _ := summary["status"].(string)
	return status
}

// findingCodes lists the codes the report carries, in order.
func findingCodes(t *testing.T, decoded map[string]any) []string {
	t.Helper()
	raw, _ := decoded["findings"].([]any)
	var out []string
	for _, f := range raw {
		finding, ok := f.(map[string]any)
		if !ok {
			continue
		}
		code, _ := finding["code"].(string)
		out = append(out, code)
	}
	return out
}

// sessionEstablished derives the fact structurally, the way a renderer must:
// a postgres.session node in state PASS. Never from the status, never from the
// exit code, never by parsing an identifier.
func sessionEstablished(t *testing.T, decoded map[string]any) bool {
	t.Helper()

	evidence, ok := decoded["evidence"].(map[string]any)
	if !ok {
		t.Fatal("the report has no evidence section")
	}
	nodes, _ := evidence["nodes"].([]any)
	for _, n := range nodes {
		node, ok := n.(map[string]any)
		if !ok {
			continue
		}
		if node["step"] == string(servicepostgres.StepSession) &&
			node["state"] == domain.StatePass.String() {
			return true
		}
	}
	return false
}

// certPath is the trust material the validation server presents, the same file
// rootCAs loads for the in-process suite.
func certPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("env", "certs", "server.crt")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("validation certificate not generated: %v", err)
	}
	return path
}

// TestCLIHealthyTrustEndpoint is the whole spine against a working server.
func TestCLIHealthyTrustEndpoint(t *testing.T) {
	bin := binary(t)

	// The validation server's pg_hba grants trustuser `trust` over TLS, which is
	// where a healthy no-credential session is reachable. The plaintext container
	// runs its own default configuration and demands SCRAM.
	inv := runCLI(t, bin, "diagnose", "postgres",
		"--host", pgHost,
		"--port", strconv.Itoa(pgTLSPort),
		"--user", trustRole,
		"--database", database,
		"--tls-ca-file", certPath(t),
		"--tls-server-name", pgHost,
		"--timeout", "30s",
	)

	decoded := inv.canonical(t)
	if got := summaryStatus(t, decoded); got != "OK" {
		t.Errorf("status = %s, want OK", got)
	}
	if !sessionEstablished(t, decoded) {
		t.Error("no passing session node; a trust endpoint should reach ReadyForQuery")
	}
	if codes := findingCodes(t, decoded); len(codes) != 0 {
		t.Errorf("a healthy run produced %v", codes)
	}
	if inv.code != 0 {
		t.Errorf("exit = %d, want 0", inv.code)
	}
}

// TestCLINoCredentialAgainstSCRAM is the Phase 5.1 product acceptance.
//
// The CLI has no credential source. A real SCRAM endpoint therefore produces a
// WARN, an OK status, a complete run and **no session** — and exits 0. That
// combination is the one ADR 0048 makes normative for the future renderer, and
// this test proves the report already carries every fact it will need.
func TestCLINoCredentialAgainstSCRAM(t *testing.T) {
	bin := binary(t)

	inv := runCLI(t, bin, "diagnose", "postgres",
		"--host", pgHost,
		"--port", strconv.Itoa(pgTLSPort),
		"--user", scramRole,
		"--database", database,
		"--tls-ca-file", certPath(t),
		"--tls-server-name", pgHost,
		"--timeout", "30s",
	)

	decoded := inv.canonical(t)

	// The constant, not the spelling: one source of truth for the code, which is
	// what TestPostgreSQLFindingCodesLiveOnlyInDiagnosis enforces. What this test
	// proves is that the value reaches the JSON a machine consumer reads.
	want := string(diagnosispostgres.CodeCredentialNotConfigured)
	codes := findingCodes(t, decoded)
	if len(codes) != 1 || codes[0] != want {
		t.Fatalf("findings = %v, want exactly [%s]", codes, want)
	}
	findings, _ := decoded["findings"].([]any)
	finding, _ := findings[0].(map[string]any)
	if finding["severity"] != "WARN" {
		t.Errorf("severity = %v, want WARN", finding["severity"])
	}
	if finding["kind"] != "CONFIRMED" {
		t.Errorf("kind = %v, want CONFIRMED", finding["kind"])
	}

	// The three facts a renderer must present separately, all present and all
	// disagreeing with each other in exactly the way ADR 0048 anticipates.
	if got := summaryStatus(t, decoded); got != "OK" {
		t.Errorf("status = %s, want OK: the endpoint did nothing wrong", got)
	}
	if sessionEstablished(t, decoded) {
		t.Error("a session was established without a credential")
	}
	if inv.code != 0 {
		t.Errorf("exit = %d, want 0: a WARN is not a target-side error", inv.code)
	}
}

// TestCLITargetSideProblemExitsOne covers the other report-bearing status.
func TestCLITargetSideProblemExitsOne(t *testing.T) {
	bin := binary(t)

	// The plaintext server declines the SSL negotiation this run requires.
	inv := runCLI(t, bin, "diagnose", "postgres",
		"--host", pgHost,
		"--port", strconv.Itoa(pgPlaintextPort),
		"--user", trustRole,
		"--tls", "require",
		"--timeout", "30s",
	)

	decoded := inv.canonical(t)
	if got := summaryStatus(t, decoded); got != "PROBLEMS_FOUND" {
		t.Errorf("status = %s, want PROBLEMS_FOUND", got)
	}
	if sessionEstablished(t, decoded) {
		t.Error("a session was established through a refused negotiation")
	}
	if inv.code != 1 {
		t.Errorf("exit = %d, want 1", inv.code)
	}
}

// TestCLIIncompleteRunExitsFour proves the asymmetry: the report is on stdout
// and valid, and the only place incompleteness is stated is the exit status.
func TestCLIIncompleteRunExitsFour(t *testing.T) {
	bin := binary(t)

	// A routable address that never answers, with budgets short enough to be
	// deterministic. 203.0.113.0/24 is TEST-NET-3 and is not routed anywhere.
	inv := runCLI(t, bin, "diagnose", "postgres",
		"--host", "203.0.113.1",
		"--user", "app",
		"--timeout", "20s",
		"--step-timeout", "2s",
	)

	decoded := inv.canonical(t)
	if inv.code != 4 {
		t.Fatalf("exit = %d, want 4; stdout: %s", inv.code, inv.stdout)
	}
	// The report says what it measured and never that the run was cut short.
	if strings.Contains(inv.stdout, `"incomplete"`) {
		t.Error("the report claims incompleteness; that is the exit code's job")
	}
	summary, _ := decoded["summary"].(map[string]any)
	if summary["unknownEvidenceCount"] == float64(0) {
		t.Error("no UNKNOWN evidence; this run did not exercise a local budget")
	}
}

// TestCLIInvalidInvocationWritesNothingToStdout is the automation contract's
// other half: a pipeline redirecting stdout gets an empty file, not a fragment.
func TestCLIInvalidInvocationWritesNothingToStdout(t *testing.T) {
	bin := binary(t)

	for _, args := range [][]string{
		{"diagnose", "postgres", "--user", "app"},
		{"diagnose", "postgres", "--host", "db"},
		{"diagnose", "postgres", "--host", "db", "--user", "app", "--port", "0"},
		{"diagnose", "postgres", "--host", "db", "--user", "app", "--tls", "prefer"},
		{"postgres", "--host", "db"},
		{"inspect", "postgres"},
		{"diagnose", "kafka"},
	} {
		inv := runCLI(t, bin, args...)
		if inv.code != 2 {
			t.Errorf("%v: exit = %d, want 2", args, inv.code)
		}
		if inv.stdout != "" {
			t.Errorf("%v: stdout = %q, want empty", args, inv.stdout)
		}
		if inv.stderr == "" {
			t.Errorf("%v: stderr is empty", args)
		}
	}
}

// TestCLIHelpAndVersionGoToStdout pins the one case where stdout carries
// something that is not a report: output the operator explicitly asked for.
func TestCLIHelpAndVersionGoToStdout(t *testing.T) {
	bin := binary(t)

	for _, args := range [][]string{
		{"--help"}, {"--version"}, {"diagnose", "--help"}, {"diagnose", "postgres", "--help"},
	} {
		inv := runCLI(t, bin, args...)
		if inv.code != 0 {
			t.Errorf("%v: exit = %d, want 0", args, inv.code)
		}
		if inv.stdout == "" {
			t.Errorf("%v: stdout is empty", args)
		}
		if inv.stderr != "" {
			t.Errorf("%v: stderr = %q, want empty", args, inv.stderr)
		}
	}
}

// TestCLIInterruptStillProducesAReport pins ADR 0048 section 8.
//
// Interrupting a run is not an error. internal/app freezes whatever evidence it
// collected, diagnoses it and returns a report; Result.Incomplete() becomes
// true; the process writes the partial report to stdout and exits 4.
//
// # There is no race in the product, and one in the test
//
// Once the signal handler is installed, whether SIGINT lands before the first
// dial or during it makes no difference: the root context ends the same way and
// the outcome is identical. The race is the window between exec and the first
// statement of main, where the default disposition still terminates the process
// — microseconds normally, longer on a loaded machine, and this test failed
// exactly once that way while the suite was competing with a mutation run.
//
// So a signal that killed the process is treated as "sent too early" and retried
// rather than reported as a product failure, which would be a false accusation.
// The oracle is unchanged: exit 4 with a valid report.
func TestCLIInterruptStillProducesAReport(t *testing.T) {
	bin := binary(t)

	const attempts = 3
	for attempt := 1; attempt <= attempts; attempt++ {
		inv, killed := interrupt(t, bin, time.Duration(attempt)*500*time.Millisecond)
		if killed {
			t.Logf("attempt %d: the signal arrived before the handler was installed", attempt)
			continue
		}

		if inv.code != 4 {
			t.Fatalf("exit = %d, want 4; an interrupted run is incomplete, not failed.\nstderr: %s",
				inv.code, inv.stderr)
		}
		decoded := inv.canonical(t)
		// The evidence it did collect is still there and still true.
		if _, ok := decoded["evidence"]; !ok {
			t.Error("the partial report carries no evidence section")
		}
		if got := summaryStatus(t, decoded); got == "" {
			t.Error("the partial report has no summary status")
		}
		return
	}
	t.Fatalf("the process was killed by the signal on all %d attempts", attempts)
}

// interrupt starts a long run, signals it after settle, and reports what
// happened. killed is true when the process died from the signal instead of
// handling it, which is a test-side startup race rather than a product outcome.
func interrupt(t *testing.T, bin string, settle time.Duration) (inv invocation, killed bool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// TEST-NET-3, which is not routed, with budgets long enough that only the
	// signal can end the run.
	cmd := exec.CommandContext(ctx, bin, "diagnose", "postgres",
		"--host", "203.0.113.1", "--user", "app",
		"--timeout", "60s", "--step-timeout", "50s")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the command: %v", err)
	}
	time.Sleep(settle)
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signalling: %v", err)
	}
	_ = cmd.Wait()

	code := cmd.ProcessState.ExitCode()
	return invocation{stdout: stdout.String(), stderr: stderr.String(), code: code}, code < 0
}
