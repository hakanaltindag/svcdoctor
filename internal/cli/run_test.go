package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
)

// The `svcdoctor run` command surface, its exit mapping and its precedence.
//
// Every end-to-end case below uses `.invalid` hostnames, which RFC 6761 reserves
// and which no resolver will answer. So a real run happens — real DNS probe,
// real transport chain, real diagnosis, real report — with no Docker, no
// fixture and no reachable endpoint. What it proves is composition; what it
// deliberately does not prove is protocol behaviour, which the service suites
// already own.

// writeConfig puts a configuration in a temporary file.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "services.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// fourUnreachableTargets is one target per service, none of them resolvable.
const fourUnreachableTargets = `
version: 1
run:
  concurrency: 2
targets:
  - id: orders-db
    type: postgres
    host: orders-db.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
  - id: events
    type: kafka
    host: events.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    config:
      sasl_mechanism: PLAIN
  - id: cache
    type: redis
    host: cache.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
  - id: queue
    type: rabbitmq
    host: queue.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
`

// TestRunExecutesEveryTargetInDeclaredOrder is the command's happy path.
//
// Every target fails at DNS, which is a *diagnostic* outcome: each execution
// COMPLETED and each report carries a DNS finding. That is the distinction the
// whole phase rests on, exercised through the real command.
func TestRunExecutesEveryTargetInDeclaredOrder(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"run", "--config", writeConfig(t, fourUnreachableTargets), "--output", "json",
	})

	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want nothing; a run that produces a report writes none",
			stderr.String())
	}
	// Unresolvable names are a proven target-side problem, so the run completed
	// and found problems.
	if code != ExitProblemsFound {
		t.Errorf("exit = %d, want %d", code, ExitProblemsFound)
	}

	var document struct {
		SchemaVersion int    `json:"schemaVersion"`
		Kind          string `json:"kind"`
		Run           struct {
			Concurrency int `json:"concurrency"`
		} `json:"run"`
		Targets []struct {
			TargetID       string `json:"targetId"`
			Service        string `json:"service"`
			ExecutionState string `json:"executionState"`
			Report         *struct {
				SchemaVersion int `json:"schemaVersion"`
			} `json:"report"`
		} `json:"targets"`
		Summary struct {
			Targets      int    `json:"targets"`
			Completed    int    `json:"completed"`
			WithProblems int    `json:"withProblems"`
			Status       string `json:"status"`
			Incomplete   bool   `json:"incomplete"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("the aggregate is not valid JSON: %v", err)
	}

	if document.Kind != domain.RunKind {
		t.Errorf("kind = %q, want %q", document.Kind, domain.RunKind)
	}
	if document.SchemaVersion != domain.RunSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", document.SchemaVersion, domain.RunSchemaVersion)
	}
	if document.Run.Concurrency != 2 {
		t.Errorf("concurrency = %d, want the configured 2", document.Run.Concurrency)
	}

	want := []string{"orders-db", "events", "cache", "queue"}
	got := make([]string, 0, len(document.Targets))
	for _, target := range document.Targets {
		got = append(got, target.TargetID)
		if target.ExecutionState != "COMPLETED" {
			t.Errorf("target %q: state = %s, want COMPLETED; an unresolvable name is a "+
				"diagnosis, not an execution failure", target.TargetID, target.ExecutionState)
		}
		if target.Report == nil {
			t.Errorf("target %q: no embedded report", target.TargetID)
			continue
		}
		// The embedded report keeps its own schema version, untouched.
		if target.Report.SchemaVersion != domain.SchemaVersion {
			t.Errorf("target %q: report schemaVersion = %d, want %d",
				target.TargetID, target.Report.SchemaVersion, domain.SchemaVersion)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("target order = %v, want declared order %v", got, want)
	}

	if document.Summary.Targets != 4 || document.Summary.Completed != 4 {
		t.Errorf("summary = %+v, want 4 declared and 4 completed", document.Summary)
	}
	if document.Summary.Status != "PROBLEMS_FOUND" {
		t.Errorf("status = %q, want PROBLEMS_FOUND", document.Summary.Status)
	}
	if document.Summary.Incomplete {
		t.Error("every target completed; the run is not incomplete")
	}
}

// TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun is ADR 0074 §2.1.
//
// The aggregate wraps; it does not merge. A consumer that parses svcdoctor
// reports today parses targets[i].report with no change.
func TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun(t *testing.T) {
	const body = `
version: 1
targets:
  - id: solo
    type: redis
    host: solo.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
`
	var runStdout, runStderr bytes.Buffer
	newTestApp(&runStdout, &runStderr).Run(context.Background(), []string{
		"run", "--config", writeConfig(t, body), "--output", "json",
	})

	var leafStdout, leafStderr bytes.Buffer
	newTestApp(&leafStdout, &leafStderr).Run(context.Background(), []string{
		"diagnose", "redis", "--host", "solo.invalid", "--tls", "disable",
		"--timeout", "5s", "--step-timeout", "4s", "--output", "json",
	})

	embedded := embeddedReport(t, runStdout.Bytes(), 0)
	leaf := normalizeReport(t, leafStdout.Bytes())

	if embedded != leaf {
		t.Errorf("the embedded report differs from the same single-target run:\n"+
			"--- embedded\n%s\n--- leaf\n%s", embedded, leaf)
	}
}

// embeddedReport extracts one target's report, normalized.
func embeddedReport(t *testing.T, aggregate []byte, index int) string {
	t.Helper()
	var document struct {
		Targets []struct {
			Report json.RawMessage `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(aggregate, &document); err != nil {
		t.Fatalf("unmarshal aggregate: %v", err)
	}
	if index >= len(document.Targets) {
		t.Fatalf("target %d is absent", index)
	}
	return normalizeReport(t, document.Targets[index].Report)
}

// normalizeReport blanks the fields that are measurements rather than content.
func normalizeReport(t *testing.T, raw []byte) string {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	blankTimings(generic)
	out, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

// blankTimings replaces every timestamp and duration, recursively.
func blankTimings(value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key := range typed {
			switch key {
			case "startedAt", "duration":
				typed[key] = "<varies>"
			default:
				blankTimings(typed[key])
			}
		}
	case []any:
		for _, item := range typed {
			blankTimings(item)
		}
	}
}

// TestAConfigurationErrorDialsNothing is ADR 0074 section 9 and §36.
//
// Three valid targets and one malformed. Not one of the valid ones runs: the
// alternative is 17 spent authentications on a run that cannot complete, each of
// which is logged, counted, and in directory-backed deployments a step toward
// lockout.
func TestAConfigurationErrorDialsNothing(t *testing.T) {
	const body = `
version: 1
targets:
  - id: first
    type: redis
    host: first.invalid
  - id: second
    type: redis
    host: second.invalid
  - id: third
    type: redis
    host: third.invalid
    bogus_field: 1
  - id: fourth
    type: redis
    host: fourth.invalid
`
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	code := app.Run(context.Background(), []string{"run", "--config", writeConfig(t, body)})

	if code != ExitUsage {
		t.Errorf("exit = %d, want %d for a configuration error", code, ExitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want nothing; a configuration error produces no report",
			stdout.String())
	}
	// The decode refuses the field before the target loop assigns identities, so
	// the locator is the line rather than the target id. That is the honest
	// answer: the defect is at a position in the file.
	if !strings.Contains(stderr.String(), "line ") {
		t.Errorf("stderr = %q, want the offending line named", stderr.String())
	}
	if !strings.Contains(stderr.String(), "bogus_field") {
		t.Errorf("stderr = %q, want the offending field named", stderr.String())
	}
	// And it names no internal Go type, which an operator cannot act on.
	if strings.Contains(stderr.String(), "config.") {
		t.Errorf("stderr = %q, want no internal type name", stderr.String())
	}
	// No aggregate at all, so there is nothing that could describe a target as
	// having been measured.
	if strings.Contains(stdout.String(), "targets") {
		t.Error("a partial aggregate was emitted")
	}
}

// TestRunExitCodeMatrix pins the aggregate mapping and its precedence.
//
// It is the aggregate analogue of TestExitCodeMatrix, and it exists for the same
// reason: 4 outranking 1 is the single most likely thing to implement backwards.
func TestRunExitCodeMatrix(t *testing.T) {
	tests := []struct {
		name    string
		results []domain.TargetResult
		err     error
		want    int
	}{
		{
			name: "usage error, no report",
			err:  usagef("--config is required"),
			want: ExitUsage,
		},
		{
			name: "configuration error, no report",
			err:  config.InvalidField("targets[0].host", "a host is required"),
			want: ExitUsage,
		},
		{
			name: "internal error, no report",
			err:  errors.New("something failed inside svcdoctor"),
			want: ExitInternal,
		},
		{
			name: "no report and no error is itself a defect",
			want: ExitInternal,
		},
		{
			name:    "all complete, nothing found",
			results: []domain.TargetResult{completed(t, "a", false, false)},
			want:    ExitOK,
		},
		{
			name:    "complete, a target-side problem",
			results: []domain.TargetResult{completed(t, "a", true, false)},
			want:    ExitProblemsFound,
		},
		{
			name:    "a never-started target makes the run incomplete",
			results: []domain.TargetResult{completed(t, "a", false, false), notStarted(t, "b")},
			want:    ExitIncomplete,
		},
		{
			name:    "a cancelled target makes the run incomplete",
			results: []domain.TargetResult{cancelled(t, "a")},
			want:    ExitIncomplete,
		},
		{
			name:    "an execution failure makes the run incomplete, never internal",
			results: []domain.TargetResult{completed(t, "a", false, false), failed(t, "b")},
			want:    ExitIncomplete,
		},
		{
			name:    "an incomplete report makes the run incomplete",
			results: []domain.TargetResult{completed(t, "a", false, true)},
			want:    ExitIncomplete,
		},
		{
			// The ADR 0074 §6.1 worked case: one remote authentication failure,
			// one local timeout, one success.
			name: "4 outranks 1",
			results: []domain.TargetResult{
				completed(t, "auth-failure", true, false),
				completed(t, "cut-short", false, true),
				completed(t, "fine", false, false),
			},
			want: ExitIncomplete,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var report domain.RunReport
			if len(tt.results) > 0 {
				report = runReport(t, tt.results)
			}
			if got := RunExitCode(report, tt.err); got != tt.want {
				t.Errorf("RunExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestTheWorkedCaseKeepsItsFinding proves 4 does not discard what was measured.
func TestTheWorkedCaseKeepsItsFinding(t *testing.T) {
	report := runReport(t, []domain.TargetResult{
		completed(t, "auth-failure", true, false),
		completed(t, "cut-short", false, true),
		completed(t, "fine", false, false),
	})

	if got := RunExitCode(report, nil); got != ExitIncomplete {
		t.Fatalf("exit = %d, want %d", got, ExitIncomplete)
	}
	if got := report.Summary().WithProblems(); got != 1 {
		t.Errorf("WithProblems = %d, want 1; the finding stays in the report", got)
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND; incompleteness qualifies it rather "+
			"than erasing it", got)
	}
}

// TestCLIOverridePrecedence is §31.
//
//	CLI flag  >  the config's run: block  >  the built-in default
func TestCLIOverridePrecedence(t *testing.T) {
	const withRunBlock = `
version: 1
run:
  concurrency: 3
  timeout: 9s
targets:
  - id: solo
    type: redis
    host: solo.invalid
    timeout: 5s
    step_timeout: 4s
`
	const withoutRunBlock = `
version: 1
targets:
  - id: solo
    type: redis
    host: solo.invalid
    timeout: 5s
    step_timeout: 4s
`

	t.Run("the config beats the default", func(t *testing.T) {
		cmd := parseRunOrFail(t, "--config", writeConfig(t, withRunBlock))
		if got := cmd.config.Run.Concurrency; got != 3 {
			t.Errorf("concurrency = %d, want the file's 3", got)
		}
		if got := cmd.config.Run.Timeout; got != 9*time.Second {
			t.Errorf("timeout = %s, want the file's 9s", got)
		}
	})

	t.Run("the default applies when the file is silent", func(t *testing.T) {
		cmd := parseRunOrFail(t, "--config", writeConfig(t, withoutRunBlock))
		if got := cmd.config.Run.Concurrency; got != config.DefaultConcurrency {
			t.Errorf("concurrency = %d, want the default %d", got, config.DefaultConcurrency)
		}
		if got := cmd.config.Run.Timeout; got != 0 {
			t.Errorf("timeout = %s, want unset", got)
		}
	})

	t.Run("the flag beats the config", func(t *testing.T) {
		cmd := parseRunOrFail(t,
			"--config", writeConfig(t, withRunBlock), "--concurrency", "7", "--timeout", "20s")
		if got := cmd.config.Run.Concurrency; got != 7 {
			t.Errorf("concurrency = %d, want the flag's 7", got)
		}
		if got := cmd.config.Run.Timeout; got != 20*time.Second {
			t.Errorf("timeout = %s, want the flag's 20s", got)
		}
	})

	t.Run("an override is validated exactly as a config value is", func(t *testing.T) {
		path := writeConfig(t, withRunBlock)
		for _, args := range [][]string{
			{"--config", path, "--concurrency", "0"},
			{"--config", path, "--concurrency", "-1"},
			{"--config", path, "--concurrency", "17"},
			{"--config", path, "--timeout", "0s"},
			{"--config", path, "--timeout", "-5s"},
			// Below the target's own 5s budget, so that target could never
			// complete.
			{"--config", path, "--timeout", "1s"},
		} {
			var stdout, stderr bytes.Buffer
			app := newTestApp(&stdout, &stderr)
			if _, err := app.parseRun(args); err == nil {
				t.Errorf("%v was accepted", args)
			}
		}
	})
}

func parseRunOrFail(t *testing.T, args ...string) runCommand {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)
	cmd, err := app.parseRun(args)
	if err != nil {
		t.Fatalf("parseRun(%v): %v", args, err)
	}
	return cmd
}

// TestRunRefusesAnUnknownOutputForm keeps the two output modes closed.
func TestRunRefusesAnUnknownOutputForm(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)
	code := app.Run(context.Background(), []string{
		"run", "--config", writeConfig(t, fourUnreachableTargets), "--output", "yaml",
	})
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

// TestTheTerminalRunOutputDistinguishesDispositions is ADR 0074 §7.2.
func TestTheTerminalRunOutputDistinguishesDispositions(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	code := app.Run(context.Background(), []string{
		"run", "--config", writeConfig(t, fourUnreachableTargets),
	})
	if code != ExitProblemsFound {
		t.Fatalf("exit = %d, want %d", code, ExitProblemsFound)
	}

	out := stdout.String()
	for _, id := range []string{"orders-db", "events", "cache", "queue"} {
		if !strings.Contains(out, id) {
			t.Errorf("the terminal output does not name target %q", id)
		}
	}
	if !strings.Contains(out, "Run\n") {
		t.Error("the terminal output has no run summary")
	}
	// The words the summary may never use.
	for _, forbidden := range []string{"healthy", "unhealthy", "root cause"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Errorf("the run output contains %q, which svcdoctor's evidence does not support",
				forbidden)
		}
	}
}

// ---------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------

func runReport(t *testing.T, results []domain.TargetResult) domain.RunReport {
	t.Helper()
	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: "test",
		StartedAt:        time.Unix(0, 0).UTC(),
		Concurrency:      1,
		OutputMode:       domain.OutputModeLocalFull,
		Targets:          results,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}
	return report
}

// stubReport reuses the report factories the single-target exit matrix already
// uses, so every status here was derived by internal/app measuring a real socket
// rather than asserted into existence by a test.
func stubReport(t *testing.T, problems bool) domain.Report {
	t.Helper()
	if problems {
		return resultProblemsComplete(t).Report()
	}
	return resultOKComplete(t).Report()
}

func completed(t *testing.T, id string, problems, incomplete bool) domain.TargetResult {
	t.Helper()
	result, err := domain.CompletedTarget(
		id, domain.ServiceID("redis"), stubReport(t, problems), incomplete)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}
	return result
}

func cancelled(t *testing.T, id string) domain.TargetResult {
	t.Helper()
	result, err := domain.CancelledTarget(
		id, domain.ServiceID("redis"), stubReport(t, false), true)
	if err != nil {
		t.Fatalf("CancelledTarget: %v", err)
	}
	return result
}

func notStarted(t *testing.T, id string) domain.TargetResult {
	t.Helper()
	result, err := domain.NotStartedTarget(id, domain.ServiceID("redis"))
	if err != nil {
		t.Fatalf("NotStartedTarget: %v", err)
	}
	return result
}

func failed(t *testing.T, id string) domain.TargetResult {
	t.Helper()
	result, err := domain.FailedTarget(id, domain.ServiceID("redis"),
		domain.ExecutionErrorCredentialResolution,
		"the credential named by a env reference could not be resolved: not set")
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	return result
}

// TestNeitherRunSummaryBranchDescribesTargetsAsHealthy is ADR 0074 section 5.1.
//
// # Why this renders directly rather than through the command
//
// The forbidden vocabulary lives in two branches — one for OK and one for
// PROBLEMS_FOUND — and a command-level test can only reach the branch its
// fixture happens to produce. Every offline scenario available here reaches
// PROBLEMS_FOUND, so mutation B29 planted "N targets healthy" in the OK branch
// and survived the whole matrix.
//
// So both branches are rendered here, from reports internal/app produced by
// measuring a real socket, and the wording guard covers both.
func TestNeitherRunSummaryBranchDescribesTargetsAsHealthy(t *testing.T) {
	branches := map[string]domain.RunReport{
		"OK":               runReport(t, []domain.TargetResult{completed(t, "fine", false, false)}),
		"PROBLEMS_FOUND":   runReport(t, []domain.TargetResult{completed(t, "broken", true, false)}),
		"incomplete":       runReport(t, []domain.TargetResult{notStarted(t, "never-ran")}),
		"execution failed": runReport(t, []domain.TargetResult{failed(t, "unresolvable")}),
	}

	for name, report := range branches {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := renderterminal.WriteRun(&out, report); err != nil {
				t.Fatalf("WriteRun: %v", err)
			}
			rendered := out.String()
			if rendered == "" {
				t.Fatal("nothing was rendered; this case would pass vacuously")
			}

			for _, forbidden := range []string{
				"healthy", "unhealthy", "up", "down", "reachable", "available", "root cause",
			} {
				if containsWord(rendered, forbidden) {
					t.Errorf("the %s summary contains %q.\n\n"+
						"SummaryStatus already refuses that claim four levels down: OK means "+
						"no finding reached ERROR or CRITICAL, and it does not mean a target "+
						"is healthy.\n%s", name, forbidden, rendered)
				}
			}
		})
	}

	// And the two status branches really are both reached, so the loop above is
	// not asserting twice against one of them.
	var okOut, problemOut bytes.Buffer
	if err := renderterminal.WriteRun(&okOut, branches["OK"]); err != nil {
		t.Fatalf("WriteRun: %v", err)
	}
	if err := renderterminal.WriteRun(&problemOut, branches["PROBLEMS_FOUND"]); err != nil {
		t.Fatalf("WriteRun: %v", err)
	}
	if !strings.Contains(okOut.String(), "status  OK") {
		t.Errorf("the OK branch was not rendered:\n%s", okOut.String())
	}
	if !strings.Contains(problemOut.String(), "status  PROBLEMS_FOUND") {
		t.Errorf("the PROBLEMS_FOUND branch was not rendered:\n%s", problemOut.String())
	}
}

// containsWord reports a whole-word match, case-insensitively.
//
// Whole words, because "up" is a substring of "supported" and "setup", and a
// guard that fires on ordinary English gets weakened until it fires on nothing.
func containsWord(haystack, word string) bool {
	lower := strings.ToLower(haystack)
	target := strings.ToLower(word)
	isWordRune := func(r rune) bool {
		return ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') || r == '-'
	}
	for _, field := range strings.FieldsFunc(lower, func(r rune) bool {
		return !isWordRune(r)
	}) {
		if field == target {
			return true
		}
	}
	return false
}
