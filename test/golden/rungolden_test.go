package golden_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 9.1C section 24: the aggregate's serialized shape, pinned.
//
// # Why this lives in test/ rather than beside the renderer
//
// The shareable fixture needs internal/security/redaction, and a depguard rule
// forbids anything under internal/render from importing it — a renderer that
// could redact could contradict the security metadata of the report it is
// describing. The rule is right, and these fixtures span domain, render and
// redaction, so they belong in the cross-package location CLAUDE.md names for
// exactly that case rather than in a hole cut in the guard.
//
// # Why the aggregate needs goldens of its own
//
// Every embedded report already has them. What had none was the *envelope* —
// the run block, the execution states, the presence rules that make a
// never-started target carry no report, the summary counts and the ordering.
// Those are the fields a consumer parses first and the ones a refactor is most
// likely to change silently, because no test compared them as a document.
//
// A golden is the right shape for it: any change to the wire format shows up as
// a diff a reviewer reads, rather than as an assertion someone has to think to
// write.
//
// # The fixtures are deterministic by construction
//
// Every timestamp and duration is fixed, so there is nothing to normalize and
// the file on disk is exactly what a consumer would receive. A fixture holding a
// normalized placeholder would be a fixture that could not detect a format
// change in the field it normalized.

var updateRunGolden = flag.Bool("update-run-golden", false,
	"rewrite the aggregate golden files")

// fixedStart is every fixture's run start. UTC, and not "now".
var fixedStart = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// TestG1ToG6TheAggregateGoldens is the six scenarios section 24 requires.
func TestG1ToG6TheAggregateGoldens(t *testing.T) {
	tests := []struct {
		golden string
		build  func(t *testing.T) domain.RunReport
	}{
		{"g1-all-completed.json", g1AllCompleted},
		{"g2-diagnostic-failure.json", g2DiagnosticFailure},
		{"g3-execution-failure.json", g3ExecutionFailure},
		{"g4-cancelled-and-not-started.json", g4CancelledAndNotStarted},
		{"g5-four-services.json", g5FourServices},
		{"g6-shareable-mixed.json", g6ShareableMixed},
	}

	for _, tc := range tests {
		t.Run(tc.golden, func(t *testing.T) {
			var buf bytes.Buffer
			if err := renderjson.WriteRun(&buf, tc.build(t)); err != nil {
				t.Fatalf("WriteRun: %v", err)
			}
			requireRunGolden(t, tc.golden, buf.String())

			// A golden that is not valid JSON would be pinned just as happily as
			// one that is, so validity is asserted separately.
			if !json.Valid(buf.Bytes()) {
				t.Error("the aggregate is not valid JSON")
			}
		})
	}
}

// TestTheEmbeddedReportSchemaVersionIsStillOne is section 24's guard.
//
// The aggregate has its own version. Adding one must not have changed the
// other, and this reads the number out of the serialized document rather than
// out of the constant — because a consumer reads the document.
func TestTheEmbeddedReportSchemaVersionIsStillOne(t *testing.T) {
	var buf bytes.Buffer
	if err := renderjson.WriteRun(&buf, g5FourServices(t)); err != nil {
		t.Fatalf("WriteRun: %v", err)
	}

	var aggregate struct {
		SchemaVersion int    `json:"schemaVersion"`
		Kind          string `json:"kind"`
		Targets       []struct {
			Report *struct {
				SchemaVersion int `json:"schemaVersion"`
			} `json:"report"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(buf.Bytes(), &aggregate); err != nil {
		t.Fatalf("decoding: %v", err)
	}

	if aggregate.SchemaVersion != domain.RunSchemaVersion {
		t.Errorf("the aggregate declares schemaVersion %d, want %d",
			aggregate.SchemaVersion, domain.RunSchemaVersion)
	}
	if aggregate.Kind != domain.RunKind {
		t.Errorf("the aggregate declares kind %q, want %q", aggregate.Kind, domain.RunKind)
	}

	embedded := 0
	for _, target := range aggregate.Targets {
		if target.Report == nil {
			continue
		}
		embedded++
		if target.Report.SchemaVersion != domain.SchemaVersion {
			t.Errorf("an embedded report declares schemaVersion %d, want %d; the "+
				"single-target contract must be unchanged by the aggregate",
				target.Report.SchemaVersion, domain.SchemaVersion)
		}
	}
	if embedded == 0 {
		t.Fatal("no embedded report, so this proves nothing")
	}
}

func g1AllCompleted(t *testing.T) domain.RunReport {
	t.Helper()
	return aggregate(t, domain.StoppedReasonNone,
		goldenCompleted(t, "orders-db", "postgres", "orders-db.internal:5432", false, false),
		goldenCompleted(t, "cache", "redis", "cache.internal:6379", false, false),
	)
}

func g2DiagnosticFailure(t *testing.T) domain.RunReport {
	t.Helper()
	return aggregate(t, domain.StoppedReasonNone,
		goldenCompleted(t, "orders-db", "postgres", "orders-db.internal:5432", true, false),
		goldenCompleted(t, "cache", "redis", "cache.internal:6379", false, false),
	)
}

func g3ExecutionFailure(t *testing.T) domain.RunReport {
	t.Helper()
	return aggregate(t, domain.StoppedReasonNone,
		goldenCompleted(t, "orders-db", "postgres", "orders-db.internal:5432", false, false),
		goldenFailed(t, "cache", "redis"),
	)
}

func g4CancelledAndNotStarted(t *testing.T) domain.RunReport {
	t.Helper()
	return aggregate(t, domain.StoppedReasonCancelled,
		goldenCompleted(t, "orders-db", "postgres", "orders-db.internal:5432", false, false),
		goldenCancelled(t, "events", "kafka", "kafka-1.internal:9093"),
		goldenNotStarted(t, "queue", "rabbitmq"),
	)
}

func g5FourServices(t *testing.T) domain.RunReport {
	t.Helper()
	return aggregate(t, domain.StoppedReasonNone,
		goldenCompleted(t, "orders-db", "postgres", "orders-db.internal:5432", false, false),
		goldenCompleted(t, "events", "kafka", "kafka-1.internal:9093", true, false),
		goldenCompleted(t, "cache", "redis", "cache.internal:6379", false, true),
		goldenCompleted(t, "queue", "rabbitmq", "queue.internal:5672", false, false),
	)
}

func g6ShareableMixed(t *testing.T) domain.RunReport {
	t.Helper()
	redacted, err := redaction.RedactRun(g4CancelledAndNotStarted(t))
	if err != nil {
		t.Fatalf("RedactRun: %v", err)
	}
	return redacted
}

// aggregate assembles a run report with fixed timing.
func aggregate(
	t *testing.T, stopped domain.StoppedReason, results ...domain.TargetResult,
) domain.RunReport {
	t.Helper()
	report, err := domain.NewRunReport(domain.RunReportInput{
		SvcdoctorVersion: "0.2.0",
		StartedAt:        fixedStart,
		Duration:         1500 * time.Millisecond,
		Concurrency:      4,
		OutputMode:       domain.OutputModeLocalFull,
		StoppedReason:    stopped,
		Targets:          results,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}
	return report
}

func goldenCompleted(
	t *testing.T, id, service, endpoint string, problems, incomplete bool,
) domain.TargetResult {
	t.Helper()
	result, err := domain.CompletedTarget(id, domain.ServiceID(service),
		goldenReport(t, service, endpoint, problems), incomplete)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}
	return result
}

func goldenCancelled(t *testing.T, id, service, endpoint string) domain.TargetResult {
	t.Helper()
	result, err := domain.CancelledTarget(id, domain.ServiceID(service),
		goldenReport(t, service, endpoint, false), true)
	if err != nil {
		t.Fatalf("CancelledTarget: %v", err)
	}
	return result
}

func goldenNotStarted(t *testing.T, id, service string) domain.TargetResult {
	t.Helper()
	result, err := domain.NotStartedTarget(id, domain.ServiceID(service))
	if err != nil {
		t.Fatalf("NotStartedTarget: %v", err)
	}
	return result
}

func goldenFailed(t *testing.T, id, service string) domain.TargetResult {
	t.Helper()
	result, err := domain.FailedTarget(id, domain.ServiceID(service),
		domain.ExecutionErrorCredentialResolution,
		"the credential named by a env reference could not be resolved: "+
			"the environment variable is not set")
	if err != nil {
		t.Fatalf("FailedTarget: %v", err)
	}
	return result
}

// goldenReport builds a small, fully-determined canonical report.
//
// One evidence node and at most one finding: the embedded report's own shape is
// pinned by that renderer's goldens, and repeating it here would create a second
// place for the same claims to drift.
func goldenReport(t *testing.T, service, endpoint string, problems bool) domain.Report {
	t.Helper()

	subject, err := domain.NewTargetSubject(endpoint)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}

	state, failure := domain.StatePass, domain.FailureNone
	if problems {
		state, failure = domain.StateFail, domain.FailureTCPConnectionRefused
	}
	evidence, err := domain.NewEvidence(domain.EvidenceInput{
		ID:           domain.EvidenceID(string(vocabulary.StepTCPConnect) + "/" + endpoint),
		Subject:      subject,
		Layer:        domain.LayerTCP,
		Step:         vocabulary.StepTCPConnect,
		State:        state,
		FailureClass: failure,
		StartedAt:    fixedStart,
		Elapsed:      domain.Measured(12 * time.Millisecond),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	builder := domain.NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var findings []domain.Finding
	if problems {
		recommendation, err := domain.NewRecommendation(
			"Check that the service is listening on this port")
		if err != nil {
			t.Fatalf("NewRecommendation: %v", err)
		}
		finding, err := domain.NewFinding(domain.FindingInput{
			Code:            domain.FindingCode("TCP_CONNECTION_NOT_ESTABLISHED"),
			Kind:            domain.FindingKindConfirmed,
			Severity:        domain.SeverityError,
			Confidence:      domain.ConfidenceHigh,
			Layer:           domain.LayerTCP,
			Subject:         subject,
			Summary:         "No TCP connection was established to this endpoint",
			Detail:          "The connection attempt was actively refused.",
			EvidenceRefs:    []domain.EvidenceID{evidence.ID()},
			Recommendations: []domain.Recommendation{recommendation},
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		findings = append(findings, finding)
	}

	runMeta, err := domain.NewRunMetadata("0.2.0", fixedStart, 120*time.Millisecond,
		domain.ServiceID(service))
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(endpoint)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("runner.internal")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      runMeta,
		Target:   target,
		Vantage:  vantage,
		Graph:    graph,
		Findings: findings,
		Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// requireRunGolden compares a rendered aggregate against testdata byte for byte.
func requireRunGolden(t *testing.T, name, actual string) {
	t.Helper()

	path := filepath.Join("testdata", name)
	if *updateRunGolden {
		if err := os.MkdirAll("testdata", 0o750); err != nil {
			t.Fatalf("creating testdata: %v", err)
		}
		if err := os.WriteFile(path, []byte(actual), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		return
	}

	want, err := os.ReadFile(path) //nolint:gosec // G304: a fixed testdata path.
	if err != nil {
		t.Fatalf("reading %s: %v (run with -update-run-golden to create it)", path, err)
	}
	if actual != string(want) {
		t.Errorf("%s does not match.\n--- want ---\n%s\n--- got ---\n%s", path, want, actual)
	}
}
