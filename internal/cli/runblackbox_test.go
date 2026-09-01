package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Phase 9.1C sections 18 and 19: the exit contract through the real command
// surface rather than through RunExitCode.
//
// # Why this exists beside TestRunExitCodeMatrix
//
// That test calls RunExitCode with hand-built aggregates. It is the right test
// for the *mapping* and it is exhaustive over it. What it cannot see is
// everything between an operator's arguments and that function: whether the
// argument parser reaches it at all, whether an aggregate was actually produced,
// which stream each byte went to, and whether a renderer quietly recomputed
// anything.
//
// So these drive App.Run with real arguments and real configuration files, and
// assert the integer, the stream ownership and the presence or absence of a
// report together — because a correct code with the report on stderr is still
// broken, and each of those has a different cause.
//
// # Which codes are reachable here, stated plainly
//
//	0  needs a service that answers correctly, so it is owned by the Docker
//	   integration suite (test/integration/multitarget) and not fabricated here
//	1  a target-side problem: an unresolvable name is one
//	2  a configuration or credential-reference defect
//	3  svcdoctor itself failing, or the forced abort of ADR 0073 section 7.2
//	4  an incomplete run: cancellation, or a budget expiring
//
// Pretending to reach 0 without a service would mean stubbing the composition
// root, at which point the test would be about the stub.

// blackBox runs one invocation and returns everything an operator can observe.
type blackBox struct {
	code   int
	stdout string
	stderr string
}

func runCLI(t *testing.T, ctx context.Context, args ...string) blackBox {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := newTestApp(&stdout, &stderr).Run(ctx, args)
	return blackBox{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// unresolvableConfig builds a run whose targets cannot resolve.
//
// `.invalid` is reserved by RFC 2606 and never resolves, so this reaches a
// definite, fast, network-free failure on every machine.
func unresolvableConfig(t *testing.T, targets int) string {
	t.Helper()
	doc := "version: 1\nrun:\n  concurrency: 2\ntargets:\n"
	for i := range targets {
		doc += "  - id: t" + string(rune('a'+i)) + "\n    type: redis\n" +
			"    host: t.invalid\n    timeout: 5s\n    step_timeout: 4s\n" +
			"    tls:\n      mode: disable\n"
	}
	return writeConfig(t, doc)
}

// TestMTR02BlackBoxExitOne is exit 1 through the real surface.
func TestMTR02BlackBoxExitOne(t *testing.T) {
	got := runCLI(t, context.Background(), "run", "--config", unresolvableConfig(t, 2))

	if got.code != ExitProblemsFound {
		t.Errorf("exit = %d, want %d; an unresolvable name is a target-side problem "+
			"and svcdoctor worked", got.code, ExitProblemsFound)
	}
	assertReportOnStdoutOnly(t, got)
}

// TestMTR03BlackBoxExitTwo covers every configuration and credential defect that
// reaches the exit mapping, and proves each dials nothing.
func TestMTR03BlackBoxExitTwo(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		args func(t *testing.T) []string
	}{
		{
			name: "no --config at all",
			args: func(*testing.T) []string { return []string{"run"} },
		},
		{
			name: "--config - is not stdin",
			args: func(*testing.T) []string { return []string{"run", "--config", "-"} },
		},
		{
			name: "a configuration file that does not exist",
			args: func(*testing.T) []string {
				return []string{"run", "--config", filepath.Join(dir, "absent.yaml")}
			},
		},
		{
			name: "an unknown output form",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", unresolvableConfig(t, 1), "--output", "xml"}
			},
		},
		{
			name: "concurrency zero",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", unresolvableConfig(t, 1), "--concurrency", "0"}
			},
		},
		{
			name: "concurrency above the maximum",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", unresolvableConfig(t, 1), "--concurrency", "17"}
			},
		},
		{
			name: "a malformed document",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", writeConfig(t, "version: 1\ntargets:\n\t- id: a\n")}
			},
		},
		{
			name: "an unknown field",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", writeConfig(t,
					"version: 1\nbogus: x\ntargets:\n  - id: a\n    type: redis\n    host: a.invalid\n")}
			},
		},
		{
			name: "a plaintext password",
			args: func(t *testing.T) []string {
				return []string{"run", "--config", writeConfig(t,
					"version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.invalid\n"+
						"    credentials:\n      username: u\n      password: hunter2\n")}
			},
		},
		{
			name: "a credential reference that does not resolve at preflight",
			args: func(t *testing.T) []string {
				os.Unsetenv("SVCDOCTOR_BLACKBOX_ABSENT")
				return []string{"run", "--config", writeConfig(t,
					"version: 1\ntargets:\n  - id: a\n    type: redis\n    host: a.invalid\n"+
						"    credentials:\n      username: u\n      password:\n"+
						"        env: SVCDOCTOR_BLACKBOX_ABSENT\n")}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := runCLI(t, context.Background(), tc.args(t)...)

			if got.code != ExitUsage {
				t.Errorf("exit = %d, want %d", got.code, ExitUsage)
			}
			if got.stdout != "" {
				t.Errorf("a refusal wrote %d bytes to stdout; no report exists, so "+
					"nothing belongs there: %q", len(got.stdout), got.stdout)
			}
			if got.stderr == "" {
				t.Error("a refusal wrote nothing to stderr, so an operator is told nothing")
			}
		})
	}
}

// TestMTR05AndR06BlackBoxExitFour is exit 4 through cancellation.
//
// The context is cancelled before the command runs, so scheduling stops
// immediately and every target is NOT_STARTED. An aggregate still exists — that
// is the whole point of code 4 — and it must be on stdout.
func TestMTR05AndR06BlackBoxExitFour(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := runCLI(t, ctx, "run", "--config", unresolvableConfig(t, 3))

	if got.code != ExitIncomplete {
		t.Fatalf("exit = %d, want %d; a cancelled run is incomplete and is not a "+
			"failure of svcdoctor", got.code, ExitIncomplete)
	}
	assertReportOnStdoutOnly(t, got)

	// The aggregate must be truthful about what was not measured.
	if !strings.Contains(got.stdout, "not") {
		t.Errorf("the aggregate does not distinguish unmeasured targets: %q", got.stdout)
	}
}

// TestExitFourOutranksOneThroughTheRealSurface is section 18's required worked
// scenario, end to end: a target-side problem beside an unmeasured target.
//
// The run must produce, in one aggregate, a target that reached PROBLEMS_FOUND
// and a target that was never started. The exit code must then be 4 and not 1,
// because incompleteness qualifies every conclusion — and the ERROR finding must
// survive in the report, because downgrading it would be discarding a
// measurement that was actually made.
//
// # Why the scenario is built from two local sockets
//
// The precondition this test needs is that **the run budget expires before the
// dispatcher has offered every target**. Nothing in the scheduler guarantees
// that: `dispatch` walks the declared order and stops when the run context is
// done, so whether any target is left NOT_STARTED depends entirely on how long
// the earlier targets take. That is a property of the machine's network, not of
// the scheduler, and it must therefore be constructed rather than hoped for.
//
// The original construction pointed sixty targets at the blackholed address
// 10.255.255.1 and assumed each would block for its step budget. It held on a
// developer's machine and **failed the v0.4.0 release source gate**, where
// GitHub's runner has no route to 10.0.0.0/8 at all: every connect failed
// immediately, all sixty-one targets were dispatched inside the 400 ms budget,
// nothing was left unstarted, and the scenario the test claimed to exercise
// never arose. Measured locally afterwards, the same failure reproduced at
// roughly 1% under GOMAXPROCS=1. A test whose precondition depends on how a
// particular network fails an unreachable address is a test that reports the
// network.
//
// So both halves are now local sockets with no routing, DNS or timing
// assumption in them:
//
//	refused   a loopback port with nothing listening: connect fails at once,
//	          which is a definite ERROR and reaches PROBLEMS_FOUND
//	blocked   a listener that accepts and never answers: the connect succeeds
//	          and the journey then blocks until that target's own step budget
//	          expires, on every machine
//
// # The margin, stated as arithmetic rather than as a hope
//
// One instant target, then 20 targets that each take **at least** the 150 ms
// step budget, at concurrency 1, under a 600 ms run budget. At most four of the
// blocked targets can start, so at least sixteen cannot. The bound is one-sided:
// nothing can make a blocked target return early, because the peer never sends a
// byte — so a slower machine leaves *more* targets unstarted, never fewer. That
// is what makes this deterministic rather than lucky.
func TestExitFourOutranksOneThroughTheRealSurface(t *testing.T) {
	const (
		blockedTargets = 20
		wantUnstarted  = 10 // Well under the sixteen the arithmetic guarantees.
	)

	problemPort := refusedPort(t)
	_, blockedPort, err := net.SplitHostPort(tarpit(t))
	if err != nil {
		t.Fatalf("tarpit address: %v", err)
	}

	doc := "version: 1\nrun:\n  concurrency: 1\ntargets:\n" +
		"  - id: refused\n    type: redis\n    host: 127.0.0.1\n" +
		"    port: " + problemPort + "\n    timeout: 200ms\n    step_timeout: 150ms\n" +
		"    tls:\n      mode: disable\n"
	for i := range blockedTargets {
		doc += "  - id: blocked" + zeroPad(i) + "\n    type: redis\n    host: 127.0.0.1\n" +
			"    port: " + blockedPort + "\n    timeout: 200ms\n    step_timeout: 150ms\n" +
			"    tls:\n      mode: disable\n"
	}

	// The run budget is deliberately *above* the largest target budget, because
	// ADR 0073 section 4.4 refuses the reverse — a run bounded below its own
	// targets guarantees every one of them is cut short.
	got := runCLI(t, context.Background(), "run", "--config", writeConfig(t, doc),
		"--timeout", "600ms", "--output", "json")

	if got.code != ExitIncomplete {
		t.Fatalf("exit = %d, want %d", got.code, ExitIncomplete)
	}

	var aggregate struct {
		Targets []struct {
			ExecutionState string `json:"executionState"`
			Report         *struct {
				Findings []struct {
					Severity string `json:"severity"`
				} `json:"findings"`
			} `json:"report"`
		} `json:"targets"`
		Summary struct {
			WithProblems int  `json:"withProblems"`
			NotStarted   int  `json:"notStarted"`
			Incomplete   bool `json:"incomplete"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(got.stdout), &aggregate); err != nil {
		t.Fatalf("the aggregate is not valid JSON: %v", err)
	}

	// Both halves of the scenario are asserted as *constructed*, not as merely
	// present. A run that left one target unstarted by luck would satisfy a
	// `> 0` check while proving nothing about the construction above.
	if aggregate.Summary.NotStarted < wantUnstarted {
		t.Fatalf("only %d of %d targets were left unstarted, want at least %d.\n\n"+
			"At concurrency 1 a 600 ms run budget cannot reach past four 150 ms "+
			"targets, so this means the blocked targets did not block — the "+
			"scenario was not constructed and what follows would prove nothing.",
			aggregate.Summary.NotStarted, blockedTargets+1, wantUnstarted)
	}
	if aggregate.Summary.WithProblems == 0 {
		t.Fatal("no target reached PROBLEMS_FOUND, so 4-outranks-1 was not exercised")
	}
	if !aggregate.Summary.Incomplete {
		t.Error("the run is not marked incomplete")
	}

	// The finding is kept in full. Downgrading the report to match the exit code
	// would be discarding a measurement that was made.
	problems := 0
	for _, target := range aggregate.Targets {
		if target.Report == nil {
			continue
		}
		for _, finding := range target.Report.Findings {
			if finding.Severity == "ERROR" || finding.Severity == "CRITICAL" {
				problems++
			}
		}
	}
	if problems == 0 {
		t.Error("the aggregate reports problems but carries no ERROR finding, so the " +
			"finding was dropped when the run became incomplete")
	}
}

// tarpit is a listener that accepts connections and never answers them.
//
// A target pointed here completes its TCP connect and then blocks until its own
// step budget expires. That is the deterministic half of the scenario above: it
// depends on loopback and on nothing else — no route to an unreachable network,
// no resolver, and no assumption about how a particular kernel fails a connect.
//
// Accepted connections are held rather than dropped. Releasing one would close
// it, which would end the peer's read early and hand back exactly the timing
// dependence this exists to remove. A connection still in the listen backlog is
// already established from the client's side, so the accept loop keeping up is
// not part of the contract either.
//
// # Why each connection is drained, when nothing here reads a protocol
//
// Because closing a socket that still holds unread data makes the kernel send
// **RST** rather than FIN, and a port retired that way can poison the next
// listener the kernel hands out on it: every connect to the reused port is reset
// immediately instead of being accepted. Measured, in the first version of this
// helper — one iteration in roughly 130 saw *all* of its blocked targets
// complete at once, which is the same "the scenario was not constructed" failure
// this test was rewritten to remove, arriving by a different route.
//
// Draining costs nothing and changes nothing the peer observes: it is still
// waiting for a *reply*, and no byte is ever written back to it.
func tarpit(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
			go func() { _, _ = io.Copy(io.Discard, conn) }()
		}
	}()

	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range held {
			_ = conn.Close()
		}
	})

	return listener.Addr().String()
}

// refusedPort returns a loopback port with nothing listening on it.
//
// Bound and then closed, so the port is known to have been free and is known not
// to be served. A connect reaches ECONNREFUSED immediately, which is a definite
// target-side ERROR and needs no network beyond loopback.
func refusedPort(t *testing.T) string {
	t.Helper()

	var config net.ListenConfig
	listener, err := config.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatalf("address: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return port
}

// TestMTE20AConfigurationErrorDialsNothing is section 19.
//
// A four-target configuration whose third target is malformed. Nothing may run:
// not the first two, which are perfectly valid and come earlier in the file.
//
// # How "nothing ran" is established
//
// By the clock and by the absence of any output. The valid targets point at a
// blackholed address with a multi-second budget, so a run that started them
// could not return in milliseconds. A run that returns immediately, with no
// aggregate and exit 2, did not dial.
//
// # Why two kinds of defect, and not just one
//
// They are refused by *different passes*, and only one of them exercises the
// per-target validation loop. An unknown field is caught by the strict decode,
// before any target is looked at; an out-of-range port is caught inside
// validateTarget, target by target. Mutation C38 — which makes that loop skip a
// bad target and carry on with the rest — is invisible to the unknown-field case
// and survived it, because the run never reached the loop at all.
func TestMTE20AConfigurationErrorDialsNothing(t *testing.T) {
	// Two valid targets ahead of the defect, one behind it. The blackholed
	// addresses and long budgets are what make "did it dial?" measurable.
	const template = `
version: 1
targets:
  - id: first
    type: redis
    host: 10.255.255.1
    timeout: 30s
    step_timeout: 20s
    tls:
      mode: disable
  - id: second
    type: redis
    host: 10.255.255.2
    timeout: 30s
    step_timeout: 20s
    tls:
      mode: disable
  - id: third
    type: redis
    host: 10.255.255.3
%s
  - id: fourth
    type: redis
    host: 10.255.255.4
    timeout: 30s
    step_timeout: 20s
    tls:
      mode: disable
`

	tests := []struct {
		name    string
		defect  string
		locator string
		pass    string
	}{
		{
			name:    "an unknown field, refused by the strict decode",
			defect:  "    bogus_field: yes",
			locator: "bogus_field",
			pass:    "the strict decode, before any target is validated",
		},
		{
			name:    "an out-of-range port, refused inside target validation",
			defect:  "    port: 99999",
			locator: "99999",
			pass:    "the per-target validation loop",
		},
		//nolint:gosec // G101: a configuration this test feeds to the parser in
		// order to watch it be refused, not a credential.
		{
			name:    "a plaintext secret where a reference belongs, refused by its type",
			defect:  "    credentials:\n      username: u\n      password: hunter2",
			locator: "exactly one source",
			pass:    "the credential reference's own decoder",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := fmt.Sprintf(template, strings.ReplaceAll(tc.defect, "\\n", "\n"))

			started := time.Now()
			got := runCLI(t, context.Background(), "run", "--config", writeConfig(t, doc))
			elapsed := time.Since(started)

			if got.code != ExitUsage {
				t.Errorf("exit = %d, want %d", got.code, ExitUsage)
			}
			if got.stdout != "" {
				t.Errorf("a partial aggregate was produced: %q", got.stdout)
			}
			if !strings.Contains(got.stderr, tc.locator) {
				t.Errorf("stderr does not locate the defect (%s): %q", tc.pass, got.stderr)
			}
			if elapsed > 3*time.Second {
				t.Errorf("the refusal took %s; the valid targets ahead of the "+
					"malformed one were dialled before it was noticed", elapsed)
			}
		})
	}
}

// assertReportOnStdoutOnly is the stream-ownership half of every exit case.
//
// ADR 0048 section 7: a run that produces a report writes the report to stdout
// and nothing to stderr. The two are asserted together because a correct exit
// code with the artifact on the wrong stream still breaks every pipeline that
// consumes it.
func assertReportOnStdoutOnly(t *testing.T, got blackBox) {
	t.Helper()
	if got.stdout == "" {
		t.Error("no aggregate on stdout, though one exists")
	}
	if got.stderr != "" {
		t.Errorf("a run that produced a report also wrote to stderr: %q", got.stderr)
	}
}

// zeroPad formats a small index as a two-digit suffix for a target identifier.
func zeroPad(n int) string {
	return fmt.Sprintf("%02d", n)
}
