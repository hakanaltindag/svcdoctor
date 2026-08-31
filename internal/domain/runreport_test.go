package domain

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The aggregate's own invariants, tested where they live.
//
// # Why this file was written in Phase 9.1C rather than 9.1B
//
// It was missing. `RunReport`, `TargetResult` and `RunSummary` arrived in 9.1B
// with thorough coverage in `internal/fleet/run` and `internal/cli` — through
// the scheduler that builds them and the command that renders them. Nothing
// tested them directly.
//
// That is a real gap rather than a stylistic one. The presence rules and the
// derived summary are *domain* invariants: they must hold for every caller,
// including a future one that is not the scheduler. A test that reaches them
// through the scheduler proves they hold for the values the scheduler happens to
// produce, which is a smaller claim, and it cannot exercise the combinations the
// constructors exist to refuse — the scheduler never attempts them.
//
// The Phase 9.1 contract traceability reconciliation is what surfaced it: MT-R10
// and MT-R13 had no owner in this package.

func fixedTime() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }

// minimalReport builds the smallest valid canonical report.
func minimalReport(t *testing.T, endpoint string, problems bool) Report {
	t.Helper()

	subject, err := NewTargetSubject(endpoint)
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}
	state, failure := StatePass, FailureNone
	if problems {
		state, failure = StateFail, FailureTCPConnectionRefused
	}
	evidence, err := NewEvidence(EvidenceInput{
		ID:           EvidenceID("tcp.connect/" + endpoint),
		Subject:      subject,
		Layer:        LayerTCP,
		Step:         "tcp.connect",
		State:        state,
		FailureClass: failure,
		StartedAt:    fixedTime(),
		Elapsed:      Unmeasured(),
	})
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}
	builder := NewGraphBuilder()
	if err := builder.AddEvidence(evidence); err != nil {
		t.Fatalf("AddEvidence: %v", err)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var findings []Finding
	if problems {
		recommendation, err := NewRecommendation("Check that the service is listening")
		if err != nil {
			t.Fatalf("NewRecommendation: %v", err)
		}
		finding, err := NewFinding(FindingInput{
			Code:            FindingCode("TCP_CONNECTION_NOT_ESTABLISHED"),
			Kind:            FindingKindConfirmed,
			Severity:        SeverityError,
			Confidence:      ConfidenceHigh,
			Layer:           LayerTCP,
			Subject:         subject,
			Summary:         "No TCP connection was established to this endpoint",
			Detail:          "The connection attempt was actively refused.",
			EvidenceRefs:    []EvidenceID{evidence.ID()},
			Recommendations: []Recommendation{recommendation},
		})
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		findings = append(findings, finding)
	}

	runMeta, err := NewRunMetadata("test", fixedTime(), 0, ServiceID("redis"))
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := NewTarget(endpoint)
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := NewLocalVantage("runner.internal")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	security, err := NewReportSecurity(OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}
	report, err := NewReport(ReportInput{
		Run: runMeta, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestMTR10ExecutionStatePresenceInvariants is the table ADR 0074 froze.
//
//	COMPLETED         report,    no error
//	CANCELLED         report,    no error
//	NOT_STARTED       neither
//	EXECUTION_FAILED  no report, an error
//
// Each constructor is asked to build the combination it must refuse, and the
// refusal is the assertion. A result claiming a target never started while
// carrying its report has to be *unconstructable*, not merely unexpected: the
// scheduler's `mustNotStarted` fallback exists precisely because a defect there
// must surface as a result rather than as a panic, and that only works if the
// domain says no.
func TestMTR10ExecutionStatePresenceInvariants(t *testing.T) {
	report := minimalReport(t, "db.internal:5432", false)
	service := ServiceID("redis")

	t.Run("a completed target requires a report", func(t *testing.T) {
		if _, err := CompletedTarget("a", service, Report{}, false); err == nil {
			t.Error("a COMPLETED target was built with no report; the state claims a " +
				"measurement was made")
		}
	})

	t.Run("a cancelled target requires a report", func(t *testing.T) {
		if _, err := CancelledTarget("a", service, Report{}, true); err == nil {
			t.Error("a CANCELLED target was built with no report; a cancelled " +
				"composition root still returns what it measured")
		}
	})

	t.Run("a never-started target carries neither", func(t *testing.T) {
		result, err := NotStartedTarget("a", service)
		if err != nil {
			t.Fatalf("NotStartedTarget: %v", err)
		}
		if result.HasReport() {
			t.Error("a NOT_STARTED target carries a report; nothing was measured, so " +
				"nothing may be recorded")
		}
		if result.ExecutionErrorMessage() != "" {
			t.Error("a NOT_STARTED target carries an execution error; not being " +
				"started is not a failure")
		}
		if result.ExecutionErrorClass().Valid() {
			t.Error("a NOT_STARTED target carries an execution error class")
		}
	})

	t.Run("a failed target requires a message", func(t *testing.T) {
		if _, err := FailedTarget("a", service, ExecutionErrorInternal, ""); err == nil {
			t.Error("an EXECUTION_FAILED target was built with no message")
		}
	})

	t.Run("a failed target requires a valid class", func(t *testing.T) {
		if _, err := FailedTarget("a", service, ExecutionErrorClass(200), "x"); err == nil {
			t.Error("an EXECUTION_FAILED target was built with an unknown class")
		}
	})

	t.Run("a failed target carries no report", func(t *testing.T) {
		result, err := FailedTarget("a", service, ExecutionErrorInternal, "it broke")
		if err != nil {
			t.Fatalf("FailedTarget: %v", err)
		}
		if result.HasReport() {
			t.Error("an EXECUTION_FAILED target carries a report; no byte reached the " +
				"endpoint, so there is nothing to report about it")
		}
	})

	t.Run("every constructor requires an identity", func(t *testing.T) {
		cases := map[string]func() error{
			"completed, empty id":    func() error { _, e := CompletedTarget("", service, report, false); return e },
			"completed, bad service": func() error { _, e := CompletedTarget("a", ServiceID("NOPE"), report, false); return e },
			"not started, empty id":  func() error { _, e := NotStartedTarget("", service); return e },
			"failed, empty id":       func() error { _, e := FailedTarget("", service, ExecutionErrorInternal, "x"); return e },
		}
		for name, build := range cases {
			if err := build(); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
	})

	t.Run("the zero TargetResult is invalid", func(t *testing.T) {
		if !(TargetResult{}).IsZero() {
			t.Error("the zero TargetResult does not report itself as zero")
		}
		if _, err := json.Marshal(TargetResult{}); err == nil {
			t.Error("the zero TargetResult serialized; it has no execution state")
		}
	})
}

// TestMTR13TheRunSummaryIsDerivedAndCannotBeSupplied is ADR 0015 one level up.
//
// # Two claims, and the second is the one that matters
//
// That the counts are correct is the easy half. The load-bearing half is that
// there is **no way to state them independently**: `RunReportInput` has no
// Summary field, `RunSummary` has no exported constructor, and every field is
// unexported. A summary that could be supplied could contradict the results it
// describes — "3 completed" beside five results — and a reader has no way to
// tell which is lying.
func TestMTR13TheRunSummaryIsDerivedAndCannotBeSupplied(t *testing.T) {
	ok := minimalReport(t, "fine.internal:6379", false)
	bad := minimalReport(t, "broken.internal:6379", true)
	service := ServiceID("redis")

	completed := func(id string, report Report, incomplete bool) TargetResult {
		result, err := CompletedTarget(id, service, report, incomplete)
		if err != nil {
			t.Fatalf("CompletedTarget: %v", err)
		}
		return result
	}
	notStarted := func(id string) TargetResult {
		result, err := NotStartedTarget(id, service)
		if err != nil {
			t.Fatalf("NotStartedTarget: %v", err)
		}
		return result
	}
	cancelled := func(id string) TargetResult {
		result, err := CancelledTarget(id, service, ok, true)
		if err != nil {
			t.Fatalf("CancelledTarget: %v", err)
		}
		return result
	}
	failed := func(id string) TargetResult {
		result, err := FailedTarget(id, service, ExecutionErrorCredentialResolution, "no")
		if err != nil {
			t.Fatalf("FailedTarget: %v", err)
		}
		return result
	}

	report, err := NewRunReport(RunReportInput{
		SvcdoctorVersion: "test",
		StartedAt:        fixedTime(),
		Concurrency:      4,
		OutputMode:       OutputModeLocalFull,
		StoppedReason:    StoppedReasonCancelled,
		Targets: []TargetResult{
			completed("one", ok, false),
			completed("two", bad, false),
			completed("three", ok, true),
			cancelled("four"),
			notStarted("five"),
			failed("six"),
		},
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}

	summary := report.Summary()
	checks := map[string]struct{ got, want int }{
		"targets":           {summary.Targets(), 6},
		"completed":         {summary.Completed(), 3},
		"cancelled":         {summary.Cancelled(), 1},
		"notStarted":        {summary.NotStarted(), 1},
		"executionFailed":   {summary.ExecutionFailed(), 1},
		"withProblems":      {summary.WithProblems(), 1},
		"incompleteReports": {summary.IncompleteReports(), 2},
	}
	for name, check := range checks {
		if check.got != check.want {
			t.Errorf("%s = %d, want %d", name, check.got, check.want)
		}
	}

	// The dispositions partition the targets exactly.
	if total := summary.Completed() + summary.Cancelled() + summary.NotStarted() +
		summary.ExecutionFailed(); total != summary.Targets() {
		t.Errorf("the dispositions sum to %d over %d targets; they must partition it",
			total, summary.Targets())
	}

	if summary.Status() != SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND: one embedded report reached it",
			summary.Status())
	}
	if !summary.Incomplete() {
		t.Error("a run holding a cancelled, a never-started and a failed target is " +
			"not marked incomplete")
	}

	// Incompleteness is orthogonal to status, exactly as it is for one report.
	allFine, err := NewRunReport(RunReportInput{
		SvcdoctorVersion: "test", StartedAt: fixedTime(), Concurrency: 1,
		OutputMode: OutputModeLocalFull,
		Targets:    []TargetResult{completed("one", ok, true)},
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}
	if allFine.Summary().Status() != SummaryStatusOK || !allFine.Summary().Incomplete() {
		t.Error("OK + incomplete must be representable: it means svcdoctor's own " +
			"execution budget stopped the measurement, not that anything is wrong")
	}
}

// TestNewRunReportRefusesAnInconsistentAggregate covers the envelope's own rules.
func TestNewRunReportRefusesAnInconsistentAggregate(t *testing.T) {
	ok := minimalReport(t, "fine.internal:6379", false)
	service := ServiceID("redis")
	one, err := CompletedTarget("one", service, ok, false)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}

	base := func() RunReportInput {
		return RunReportInput{
			SvcdoctorVersion: "test",
			StartedAt:        fixedTime(),
			Concurrency:      1,
			OutputMode:       OutputModeLocalFull,
			Targets:          []TargetResult{one},
		}
	}

	cases := map[string]func(*RunReportInput){
		"no version":            func(in *RunReportInput) { in.SvcdoctorVersion = "" },
		"no start time":         func(in *RunReportInput) { in.StartedAt = time.Time{} },
		"negative duration":     func(in *RunReportInput) { in.Duration = -time.Second },
		"concurrency below one": func(in *RunReportInput) { in.Concurrency = 0 },
		"invalid output mode":   func(in *RunReportInput) { in.OutputMode = OutputMode(99) },
		"invalid stop reason":   func(in *RunReportInput) { in.StoppedReason = StoppedReason(99) },
		"no targets":            func(in *RunReportInput) { in.Targets = nil },
		"a zero target result":  func(in *RunReportInput) { in.Targets = []TargetResult{{}} },
		"duplicate target ids": func(in *RunReportInput) {
			in.Targets = []TargetResult{one, one}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := base()
			mutate(&in)
			if _, err := NewRunReport(in); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// TestTheAggregateNeverReordersItsTargets is ADR 0073 §6, at the one place a
// later reader could not see it happening.
//
// The constructor copies the slice. If it sorted — by identifier, by state, by
// anything — declared configuration order would stop being the contract, and the
// change would be invisible from outside because both orders are plausible.
func TestTheAggregateNeverReordersItsTargets(t *testing.T) {
	ok := minimalReport(t, "fine.internal:6379", false)
	service := ServiceID("redis")

	// Declared in an order that is neither sorted by identifier nor grouped by
	// execution state, so any sort at all changes it.
	declared := []string{"zulu", "alpha", "mike", "bravo"}
	results := make([]TargetResult, 0, len(declared))
	for i, id := range declared {
		var (
			result TargetResult
			err    error
		)
		switch i % 3 {
		case 0:
			result, err = FailedTarget(id, service, ExecutionErrorInternal, "no")
		case 1:
			result, err = CompletedTarget(id, service, ok, false)
		default:
			result, err = NotStartedTarget(id, service)
		}
		if err != nil {
			t.Fatalf("building %q: %v", id, err)
		}
		results = append(results, result)
	}

	report, err := NewRunReport(RunReportInput{
		SvcdoctorVersion: "test", StartedAt: fixedTime(), Concurrency: 2,
		OutputMode: OutputModeLocalFull, Targets: results,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}

	for i, result := range report.Targets() {
		if result.TargetID() != declared[i] {
			t.Fatalf("target %d is %q, want the declared %q", i, result.TargetID(), declared[i])
		}
	}

	// And the serialized document agrees, which is what a consumer reads.
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	previous := -1
	for _, id := range declared {
		at := strings.Index(string(encoded), `"targetId":"`+id+`"`)
		if at < 0 {
			t.Fatalf("target %q is absent from the document", id)
		}
		if at < previous {
			t.Errorf("target %q appears before its predecessor in the document", id)
		}
		previous = at
	}
}

// TestTheAggregateMutatesNeitherItsInputNorItsOutput proves the copies are real.
//
// `Targets()` returning the internal slice would let a renderer sort the
// aggregate in place, and every later reader would see the sorted order without
// anything having recorded that it happened.
func TestTheAggregateMutatesNeitherItsInputNorItsOutput(t *testing.T) {
	ok := minimalReport(t, "fine.internal:6379", false)
	service := ServiceID("redis")

	first, err := CompletedTarget("first", service, ok, false)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}
	second, err := CompletedTarget("second", service, ok, false)
	if err != nil {
		t.Fatalf("CompletedTarget: %v", err)
	}

	input := []TargetResult{first, second}
	report, err := NewRunReport(RunReportInput{
		SvcdoctorVersion: "test", StartedAt: fixedTime(), Concurrency: 1,
		OutputMode: OutputModeLocalFull, Targets: input,
	})
	if err != nil {
		t.Fatalf("NewRunReport: %v", err)
	}

	// Mutating the caller's slice must not reach the aggregate.
	input[0], input[1] = input[1], input[0]
	if got := report.Targets()[0].TargetID(); got != "first" {
		t.Errorf("the aggregate followed a mutation of the caller's slice: %q", got)
	}

	// Mutating what Targets() returned must not reach it either.
	handed := report.Targets()
	handed[0], handed[1] = handed[1], handed[0]
	if got := report.Targets()[0].TargetID(); got != "first" {
		t.Errorf("Targets() handed out the internal slice: %q", got)
	}
}
