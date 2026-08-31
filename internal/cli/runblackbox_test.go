package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
// The run budget is set so low that scheduling stops partway, which produces
// both a PROBLEMS_FOUND target and a NOT_STARTED one in a single aggregate. The
// finding must survive in the report while the code says 4, because
// incompleteness qualifies every conclusion.
func TestExitFourOutranksOneThroughTheRealSurface(t *testing.T) {
	// The first target fails fast and definitely: an unresolvable name is an
	// ERROR, so it reaches PROBLEMS_FOUND. Every later target points at a
	// blackholed address and burns its whole 200 ms budget, so a 400 ms run
	// budget is exhausted long before the list is finished and the tail is left
	// NOT_STARTED. Concurrency 1 makes the ordering deterministic.
	//
	// The run budget is deliberately *above* the largest target budget, because
	// ADR 0073 section 4.4 refuses the reverse — a run bounded below its own
	// targets guarantees every one of them is cut short.
	doc := "version: 1\nrun:\n  concurrency: 1\ntargets:\n" +
		"  - id: resolves-not\n    type: redis\n    host: t.invalid\n" +
		"    timeout: 200ms\n    step_timeout: 100ms\n    tls:\n      mode: disable\n"
	for i := range 60 {
		doc += "  - id: slow" + zeroPad(i) + "\n    type: redis\n    host: 10.255.255.1\n" +
			"    timeout: 200ms\n    step_timeout: 100ms\n    tls:\n      mode: disable\n"
	}

	got := runCLI(t, context.Background(), "run", "--config", writeConfig(t, doc),
		"--timeout", "400ms", "--output", "json")

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

	if aggregate.Summary.NotStarted == 0 {
		t.Fatal("no target was left unstarted, so this scenario did not arise")
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
