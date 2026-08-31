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
)

// Secret containment across a whole multi-target run.
//
// Every case plants the same canary and then hunts for it on every surface an
// operator or a pipeline can see: stdout in both forms, stderr, the shareable
// derivative, and the execution-error path. A run is the first thing in
// svcdoctor that holds several credentials at once, so these are the tests that
// have to be exhaustive rather than representative.

// runCanary is the value that must never appear anywhere.
const runCanary = "hunter2-RUN-CANARY-8b3e1f"

// configWithCredentials builds a two-target configuration reading real secrets.
func configWithCredentials(t *testing.T, secretPath string) string {
	t.Helper()
	return writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: from-env
    type: redis
    host: from-env.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
      password:
        env: SVCDOCTOR_RUN_CANARY
  - id: from-file
    type: redis
    host: from-file.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
      password:
        file: %s
`, secretPath))
}

func writeSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestMTS01NoSecretReachesAnyRunSurface is MT-S01 through MT-S03.
//
// Both credential sources, both output forms, both output modes, and stderr.
func TestMTS01NoSecretReachesAnyRunSurface(t *testing.T) {
	t.Setenv("SVCDOCTOR_RUN_CANARY", runCanary)
	secretPath := writeSecretFile(t, runCanary)
	path := configWithCredentials(t, secretPath)

	invocations := [][]string{
		{"run", "--config", path},
		{"run", "--config", path, "--output", "json"},
		{"run", "--config", path, "--shareable"},
		{"run", "--config", path, "--output", "json", "--shareable"},
	}

	for _, args := range invocations {
		t.Run(strings.Join(args[3:], " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			newTestApp(&stdout, &stderr).Run(context.Background(), args)

			for name, surface := range map[string]string{
				"stdout": stdout.String(),
				"stderr": stderr.String(),
			} {
				if strings.Contains(surface, runCanary) {
					t.Errorf("the secret appeared on %s", name)
				}
			}
			if stdout.Len() == 0 {
				t.Fatal("no output at all; this case would pass vacuously")
			}
		})
	}
}

// TestMTS10NoCredentialReferenceReachesTheReport is ADR 0072 section 10.
//
// The split is deliberate and both halves are asserted: a reference name may
// reach stderr, because a variable svcdoctor cannot read has to be nameable to
// the person fixing it — and it must never reach the canonical report, which is
// attached to tickets and pasted into chats.
func TestMTS10NoCredentialReferenceReachesTheReport(t *testing.T) {
	secretPath := writeSecretFile(t, runCanary)
	// The variable is deliberately absent, so preflight refuses the run.
	os.Unsetenv("SVCDOCTOR_RUN_CANARY")

	var stdout, stderr bytes.Buffer
	code := newTestApp(&stdout, &stderr).Run(context.Background(), []string{
		"run", "--config", configWithCredentials(t, secretPath), "--output", "json",
	})

	// Preflight failed, so no aggregate exists at all.
	if code != ExitInternal && code != ExitUsage {
		t.Errorf("exit = %d, want a pre-execution refusal", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want no report", stdout.String())
	}
	// stderr names the reference, which is what the operator needs.
	if !strings.Contains(stderr.String(), "SVCDOCTOR_RUN_CANARY") {
		t.Errorf("stderr = %q, want the variable named so it can be fixed", stderr.String())
	}
	if strings.Contains(stderr.String(), runCanary) {
		t.Error("stderr carried a secret value")
	}
}

// TestAResolutionFailureDuringExecutionNamesNoReference is MT-S10's other half,
// and §37 and §38's TOCTOU case.
//
// Preflight succeeds; the source disappears; Resolve fails during the run. The
// target becomes EXECUTION_FAILED, the aggregate exists, and the reference name
// is nowhere in it.
func TestAResolutionFailureDuringExecutionNamesNoReference(t *testing.T) {
	secretPath := writeSecretFile(t, runCanary)
	path := writeConfig(t, fmt.Sprintf(`
version: 1
run:
  concurrency: 1
targets:
  - id: vanishing
    type: redis
    host: vanishing.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
    credentials:
      username: svcdoctor
      password:
        file: %s
  - id: unaffected
    type: redis
    host: unaffected.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
`, secretPath))

	// Preflight will succeed against the file that exists now. Removing it here,
	// between LoadFile and Execute, is not possible from outside — so the file is
	// removed after parse and before execute by driving the two halves directly,
	// which is exactly the window ADR 0072 §5.3 records as irreducible.
	var stdout, stderr bytes.Buffer
	app := newTestApp(&stdout, &stderr)

	command, err := app.parseRun([]string{"--config", path, "--output", "json"})
	if err != nil {
		t.Fatalf("parseRun: %v", err)
	}
	// The source vanishes after the configuration was read and validated.
	if err := os.Remove(secretPath); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	report, err := app.executeRun(context.Background(), command.config)
	if err != nil {
		// Preflight runs inside executeRun, so a missing file is caught there and
		// the whole run is refused. That is the frozen all-or-nothing behaviour
		// and it is equally correct; what must not happen is a service
		// authentication finding.
		if strings.Contains(err.Error(), "AUTH") || strings.Contains(err.Error(), "rejected") {
			t.Errorf("a missing credential was reported as an authentication failure: %v", err)
		}
		if strings.Contains(err.Error(), runCanary) {
			t.Error("the refusal carried a secret value")
		}
		return
	}

	// If the run did proceed, the target failed locally and named no reference.
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	document := string(encoded)
	for _, forbidden := range []string{runCanary, secretPath, "SVCDOCTOR_RUN_CANARY"} {
		if strings.Contains(document, forbidden) {
			t.Errorf("the aggregate serialized %q", forbidden)
		}
	}
}

// TestTheAggregateSerializesNoConfigurationSurface is MT-S08 and MT-S09.
//
// No raw configuration, no config path, no credential reference, no service
// parameters. The aggregate has no field for any of them, and this proves it
// over the bytes rather than trusting the shape.
func TestTheAggregateSerializesNoConfigurationSurface(t *testing.T) {
	t.Setenv("SVCDOCTOR_RUN_CANARY", runCanary)
	secretPath := writeSecretFile(t, runCanary)
	path := configWithCredentials(t, secretPath)

	var stdout, stderr bytes.Buffer
	newTestApp(&stdout, &stderr).Run(context.Background(), []string{
		"run", "--config", path, "--output", "json",
	})
	document := stdout.String()
	if document == "" {
		t.Fatal("no output; this test would pass vacuously")
	}

	//nolint:gosec // G101: this map is the *hunt list* — every entry is a value
	// that must NOT appear in the aggregate. The canary is a test fixture, and
	// finding it here would mean this test is doing its job.
	forbidden := map[string]string{
		runCanary:              "the secret value",
		secretPath:             "the credential file path",
		"SVCDOCTOR_RUN_CANARY": "the environment variable name",
		path:                   "the configuration file path",
		"version: 1":           "the raw configuration",
		"step_timeout":         "a configuration field name",
		"sasl_mechanism":       "a configuration field name",
	}
	for value, what := range forbidden {
		if strings.Contains(document, value) {
			t.Errorf("the aggregate serialized %s (%q)", what, value)
		}
	}
}

// TestShareableUsesOnePseudonymTableForTheWholeRun is ADR 0074 section 8.1.
//
// Two targets naming the same host must receive the **same** pseudonym. Redacting
// each target independently would give one real host two names — and could give
// two different hosts one name, which is a correlation the redactor invented.
func TestShareableUsesOnePseudonymTableForTheWholeRun(t *testing.T) {
	const shared = "shared-endpoint.invalid"
	path := writeConfig(t, fmt.Sprintf(`
version: 1
targets:
  - id: orders
    type: redis
    host: %s
    port: 6379
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
  - id: billing
    type: redis
    host: %s
    port: 6380
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
  - id: elsewhere
    type: redis
    host: other-endpoint.invalid
    timeout: 5s
    step_timeout: 4s
    tls:
      mode: disable
`, shared, shared))

	var stdout, stderr bytes.Buffer
	newTestApp(&stdout, &stderr).Run(context.Background(), []string{
		"run", "--config", path, "--output", "json", "--shareable",
	})

	document := stdout.String()
	if document == "" {
		t.Fatal("no output")
	}

	// The real hostnames are gone.
	for _, host := range []string{shared, "other-endpoint.invalid"} {
		if strings.Contains(document, host) {
			t.Errorf("the shareable aggregate still contains %q", host)
		}
	}
	// And so are the operator's target identifiers.
	for _, id := range []string{"orders", "billing", "elsewhere"} {
		if strings.Contains(document, `"targetId":"`+id+`"`) {
			t.Errorf("the shareable aggregate still names target %q", id)
		}
	}

	var parsed struct {
		Targets []struct {
			TargetID string          `json:"targetId"`
			Report   json.RawMessage `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Targets) != 3 {
		t.Fatalf("got %d targets, want 3", len(parsed.Targets))
	}

	// Target identifiers are numbered in declared order.
	for i, target := range parsed.Targets {
		want := fmt.Sprintf("target-%03d", i+1)
		if target.TargetID != want {
			t.Errorf("target %d: id = %q, want %q", i, target.TargetID, want)
		}
	}

	// The two targets on one host share a pseudonym; the third does not.
	first := hostPseudonym(t, parsed.Targets[0].Report)
	second := hostPseudonym(t, parsed.Targets[1].Report)
	third := hostPseudonym(t, parsed.Targets[2].Report)

	if first == "" || second == "" || third == "" {
		t.Fatalf("could not extract pseudonyms: %q %q %q", first, second, third)
	}
	if first != second {
		t.Errorf("one host received two pseudonyms across the run: %q and %q", first, second)
	}
	if third == first {
		t.Errorf("two different hosts received one pseudonym (%q); the redactor invented "+
			"a correlation", third)
	}
}

// hostPseudonym reads a report's requested target back out.
func hostPseudonym(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var report struct {
		Target struct {
			Requested string `json:"requested"`
		} `json:"target"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	host, _, _ := strings.Cut(report.Target.Requested, ":")
	return host
}

// TestShareableIsRefusedNothingAndProducesAWholeDocument guards the fail-closed
// property: a redaction that could not complete returns nothing rather than a
// half-transformed aggregate.
func TestShareableProducesAWholeDocument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := newTestApp(&stdout, &stderr).Run(context.Background(), []string{
		"run", "--config", writeConfig(t, fourUnreachableTargets),
		"--output", "json", "--shareable",
	})
	if code == ExitInternal {
		t.Fatalf("the shareable projection failed: %s", stderr.String())
	}

	var parsed struct {
		Run struct {
			OutputMode string `json:"outputMode"`
		} `json:"run"`
		Targets []json.RawMessage `json:"targets"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Run.OutputMode != "SHAREABLE_REDACTED" {
		t.Errorf("outputMode = %q, want SHAREABLE_REDACTED", parsed.Run.OutputMode)
	}
	if len(parsed.Targets) != 4 {
		t.Errorf("got %d targets, want all 4", len(parsed.Targets))
	}
}
