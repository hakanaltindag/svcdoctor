package run_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
)

// The Phase 9.0 execution matrix, MT-E01 through MT-E20.
//
// Every case below runs against the deterministic fake runner: no Docker, no
// network, no sleep-and-hope. The four-service composition is proven separately.

// TestMTE01AllTargetsComplete is MT-E01.
func TestMTE01AllTargetsComplete(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta")

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got, want := len(report.Targets()), 4; got != want {
		t.Fatalf("len(Targets) = %d, want %d", got, want)
	}
	for _, result := range report.Targets() {
		if got := result.ExecutionState(); got != domain.ExecutionStateCompleted {
			t.Errorf("target %q: state = %s, want COMPLETED", result.TargetID(), got)
		}
		if !result.HasReport() {
			t.Errorf("target %q: no report", result.TargetID())
		}
	}

	summary := report.Summary()
	if summary.Targets() != 4 || summary.Completed() != 4 {
		t.Errorf("summary = %+v, want 4 declared and 4 completed", summary)
	}
	if summary.Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK", summary.Status())
	}
	if summary.Incomplete() {
		t.Error("a run where everything completed must not be incomplete")
	}
	if report.StoppedReason() != domain.StoppedReasonNone {
		t.Errorf("StoppedReason = %s, want NONE", report.StoppedReason())
	}
}

// TestMTE02RemoteAuthFailureIsACompletedExecution is MT-E02, and it is the
// distinction ADR 0074 section 4.1 exists for.
//
// A rejected credential means svcdoctor executed the whole diagnostic journey
// successfully and the endpoint said no. The execution is COMPLETED; the
// *report* carries the failure.
func TestMTE02RemoteAuthFailureIsACompletedExecution(t *testing.T) {
	h := newHarness(t, "alpha", "bravo").behave("bravo", behaveProblems)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	bravo := targetByID(t, report, "bravo")
	if got := bravo.ExecutionState(); got != domain.ExecutionStateCompleted {
		t.Errorf("state = %s, want COMPLETED; a remote refusal is a successful diagnosis", got)
	}
	if !bravo.HasProblems() {
		t.Error("the report must carry the diagnostic failure")
	}
	if bravo.ExecutionErrorClass().Valid() {
		t.Errorf("a completed target must carry no execution error, got %s",
			bravo.ExecutionErrorClass())
	}

	summary := report.Summary()
	if summary.WithProblems() != 1 {
		t.Errorf("WithProblems = %d, want 1", summary.WithProblems())
	}
	if summary.Status() != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", summary.Status())
	}
	// A diagnostic failure is not incompleteness: svcdoctor measured everything
	// it set out to and found a problem.
	if summary.Incomplete() {
		t.Error("a completed run with a diagnostic failure is not incomplete")
	}
}

// TestMTE03LocalTimeoutIsCompletedAndIncomplete is MT-E03.
//
// A target cut short by its own budget produced its own truthful report. That is
// COMPLETED with Incomplete true — orchestration has nothing to add.
func TestMTE03LocalTimeoutIsCompletedAndIncomplete(t *testing.T) {
	h := newHarness(t, "alpha", "bravo").behave("bravo", behaveIncomplete)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	bravo := targetByID(t, report, "bravo")
	if got := bravo.ExecutionState(); got != domain.ExecutionStateCompleted {
		t.Errorf("state = %s, want COMPLETED; its own budget ended it, not the run's", got)
	}
	if !bravo.Incomplete() {
		t.Error("want Incomplete true")
	}
	if got := report.Summary().IncompleteReports(); got != 1 {
		t.Errorf("IncompleteReports = %d, want 1", got)
	}
	if !report.Summary().Incomplete() {
		t.Error("a run holding an incomplete report is incomplete")
	}
	// Nothing stopped scheduling: every target ran.
	if report.StoppedReason() != domain.StoppedReasonNone {
		t.Errorf("StoppedReason = %s, want NONE", report.StoppedReason())
	}
}

// TestMTE04CredentialResolutionFailure is MT-E04, and MT-S's most important
// truthfulness case.
//
// A credential that could not be obtained is svcdoctor's own failure. No byte
// reached the endpoint, so there is no report, no fabricated DNS/TCP/TLS
// evidence, and nothing that could be read as the endpoint rejecting anything.
func TestMTE04CredentialResolutionFailure(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie").
		withCredential("bravo", "BRAVO_PASSWORD").
		resolveFails("bravo", errors.New("credential env BRAVO_PASSWORD: not set"))

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	bravo := targetByID(t, report, "bravo")
	if got := bravo.ExecutionState(); got != domain.ExecutionStateExecutionFailed {
		t.Errorf("state = %s, want EXECUTION_FAILED", got)
	}
	if got := bravo.ExecutionErrorClass(); got != domain.ExecutionErrorCredentialResolution {
		t.Errorf("class = %s, want CREDENTIAL_RESOLUTION", got)
	}
	if bravo.HasReport() {
		t.Error("a target that never reached its endpoint must carry no report; " +
			"fabricating one would claim measurements nobody made")
	}
	if bravo.HasProblems() {
		t.Error("a local failure must not count as a diagnostic problem")
	}

	// The runner was never called for bravo, so nothing was dialled.
	for _, id := range h.runner.starts() {
		if id == "bravo" {
			t.Error("the runner was invoked for a target whose credential failed to resolve")
		}
	}

	// And the unrelated targets ran regardless.
	for _, id := range []string{"alpha", "charlie"} {
		if got := targetByID(t, report, id).ExecutionState(); got != domain.ExecutionStateCompleted {
			t.Errorf("target %q: state = %s, want COMPLETED", id, got)
		}
	}
	if !report.Summary().Incomplete() {
		t.Error("a run holding an execution failure is incomplete")
	}
}

// TestAnExecutionErrorMessageNamesNoCredentialReference is ADR 0074 §4.2.
//
// # The split it protects
//
// A resolver's ordinary Error() names the reference on purpose: an environment
// variable svcdoctor cannot read has to be nameable to the person fixing it. That
// message is for stderr. The canonical report gets the safe form, because a
// report is attached to tickets and pasted into chats.
//
// The scheduler asks for the safe form and **fails closed**: an error that offers
// none gets a fixed sentence rather than its own text, so a future error type
// cannot leak by omission.
func TestAnExecutionErrorMessageNamesNoCredentialReference(t *testing.T) {
	const reference = "VERY_DISTINCTIVE_VARIABLE_NAME"

	h := newHarness(t, "alpha").
		withCredential("alpha", "ALPHA_PASSWORD").
		resolveFails("alpha", &resolutionError{reference: reference, reason: "not set"})

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	alpha := targetByID(t, report, "alpha")
	if got := alpha.ExecutionState(); got != domain.ExecutionStateExecutionFailed {
		t.Fatalf("state = %s, want EXECUTION_FAILED", got)
	}
	if strings.Contains(alpha.ExecutionErrorMessage(), reference) {
		t.Errorf("the execution error names the credential reference: %q",
			alpha.ExecutionErrorMessage())
	}
	if alpha.ExecutionErrorMessage() == "" {
		t.Error("want a message explaining what happened")
	}

	// And it is absent from the serialized document too.
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), reference) {
		t.Error("the aggregate serialized a credential reference name")
	}
}

// TestAnErrorWithNoSafeFormIsNotEchoed proves the fail-closed default.
func TestAnErrorWithNoSafeFormIsNotEchoed(t *testing.T) {
	const leak = "SOME_UNSAFE_DETAIL_A_FUTURE_ERROR_MIGHT_CARRY"

	h := newHarness(t, "alpha").
		withCredential("alpha", "ALPHA_PASSWORD").
		resolveFails("alpha", errors.New(leak))

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	message := targetByID(t, report, "alpha").ExecutionErrorMessage()
	if strings.Contains(message, leak) {
		t.Errorf("an error with no SafeMessage was echoed verbatim: %q.\n\n"+
			"Defaulting to err.Error() means every future error type leaks by omission.",
			message)
	}
}

// TestMTE05RunBudgetExhaustedBeforeAllTargetsStart is MT-E05.
func TestMTE05RunBudgetExhaustedBeforeAllTargetsStart(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta").
		concurrency(1).
		runTimeout(120*time.Millisecond).
		behave("alpha", behaveBlockUntilCancelled)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// alpha was running when the budget expired.
	alpha := targetByID(t, report, "alpha")
	if got := alpha.ExecutionState(); got != domain.ExecutionStateCancelled {
		t.Errorf("alpha state = %s, want CANCELLED", got)
	}
	if !alpha.HasReport() {
		t.Error("a cancelled target keeps whatever its composition root measured")
	}

	// The rest never started, and carry nothing.
	for _, id := range []string{"bravo", "charlie", "delta"} {
		result := targetByID(t, report, id)
		if got := result.ExecutionState(); got != domain.ExecutionStateNotStarted {
			t.Errorf("target %q: state = %s, want NOT_STARTED", id, got)
		}
		if result.HasReport() {
			t.Errorf("target %q: a never-started target must carry no report", id)
		}
		if result.ExecutionErrorClass().Valid() {
			t.Errorf("target %q: a never-started target carries no execution error", id)
		}
	}

	if got := report.StoppedReason(); got != domain.StoppedReasonRunBudgetExhausted {
		t.Errorf("StoppedReason = %s, want RUN_BUDGET_EXHAUSTED", got)
	}
	if !report.Summary().Incomplete() {
		t.Error("want an incomplete run")
	}
	// No remote failure was inferred from a local budget expiring.
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s; a run budget expiring proves nothing about any target",
			report.Summary().Status())
	}
}

// TestMTR15NeverStartedTargetsInvokeNothing is MT-E17, proven by counting.
//
// The strongest form of "no fabricated evidence" is that neither the runner nor
// the resolver was called at all.
func TestMTR15NeverStartedTargetsInvokeNothing(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta").
		concurrency(1).
		runTimeout(100*time.Millisecond).
		withCredential("bravo", "BRAVO_PASSWORD").
		withCredential("charlie", "CHARLIE_PASSWORD").
		behave("alpha", behaveBlockUntilCancelled)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	for _, id := range []string{"bravo", "charlie", "delta"} {
		if got := targetByID(t, report, id).ExecutionState(); got != domain.ExecutionStateNotStarted {
			t.Fatalf("target %q: state = %s, want NOT_STARTED", id, got)
		}
		if got := h.resolver.callCount(id); got != 0 {
			t.Errorf("target %q: the resolver was called %d times for a never-started target",
				id, got)
		}
	}
	if got := h.runner.starts(); len(got) != 1 || got[0] != "alpha" {
		t.Errorf("runner starts = %v, want only alpha", got)
	}
}

// TestMTE06CancellationWithCompletedActiveAndQueued is MT-E06.
func TestMTE06CancellationWithCompletedActiveAndQueued(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta").
		concurrency(1).
		behave("bravo", behaveBlockUntilCancelled)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel once bravo is in flight: alpha has completed, bravo is active, and
	// charlie and delta are still queued.
	go func() {
		waitFor(t, func() bool { return len(h.runner.starts()) >= 2 })
		cancel()
	}()

	report, err := h.execute(ctx)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got := targetByID(t, report, "alpha").ExecutionState(); got != domain.ExecutionStateCompleted {
		t.Errorf("alpha = %s, want COMPLETED; a completed result is kept", got)
	}
	if got := targetByID(t, report, "bravo").ExecutionState(); got != domain.ExecutionStateCancelled {
		t.Errorf("bravo = %s, want CANCELLED", got)
	}
	for _, id := range []string{"charlie", "delta"} {
		if got := targetByID(t, report, id).ExecutionState(); got != domain.ExecutionStateNotStarted {
			t.Errorf("%s = %s, want NOT_STARTED", id, got)
		}
	}
	if got := report.StoppedReason(); got != domain.StoppedReasonCancelled {
		t.Errorf("StoppedReason = %s, want CANCELLED", got)
	}
	// The operator stopped svcdoctor. Nothing about any endpoint was learned, so
	// nothing about any endpoint is claimed.
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Errorf("status = %s; cancellation is not a target-side problem",
			report.Summary().Status())
	}
}

// TestMTE08AndD02CompletionOrderNeverReachesTheReport is MT-E07 and MT-D02.
//
// The scenario forces completion order D, B, A, C while the declared order is
// A, B, C, D. Nothing in the output may reflect the former.
func TestMTE08AndD02CompletionOrderNeverReachesTheReport(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta").concurrency(4)

	// Gate each target so completion order is chosen rather than raced.
	gates := map[string]chan struct{}{
		"alpha": make(chan struct{}), "bravo": make(chan struct{}),
		"charlie": make(chan struct{}), "delta": make(chan struct{}),
	}
	h.runner.gate = gates

	go func() {
		// Every target must be in flight before any is released, or the pool
		// would serialise them and the ordering would prove nothing.
		waitFor(t, func() bool { return len(h.runner.starts()) == 4 })
		for _, id := range []string{"delta", "bravo", "alpha", "charlie"} {
			close(gates[id])
			waitFor(t, func() bool { return containsString(h.runner.completions(), id) })
		}
	}()

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got, want := h.runner.completions(),
		[]string{"delta", "bravo", "alpha", "charlie"}; !equalStrings(got, want) {
		t.Fatalf("the scenario did not achieve the intended completion order: %v", got)
	}
	if got, want := ids(report), []string{"alpha", "bravo", "charlie", "delta"}; !equalStrings(got, want) {
		t.Errorf("report order = %v, want declared order %v", got, want)
	}
}

// TestMTE09DuplicateEndpointsAreDistinctExecutions is MT-E08.
func TestMTE09DuplicateEndpointsAreDistinctExecutions(t *testing.T) {
	h := newHarness(t, "orders", "billing")
	for i := range h.cfg.Targets {
		h.cfg.Targets[i].Host = "db.example.com"
		h.cfg.Targets[i].Port = 5432
	}

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if got, want := len(report.Targets()), 2; got != want {
		t.Fatalf("len(Targets) = %d, want %d; endpoints are never deduplicated", got, want)
	}
	if got := len(h.runner.starts()); got != 2 {
		t.Errorf("the runner ran %d times, want 2; two logical targets are two executions", got)
	}
	first, second := report.Targets()[0], report.Targets()[1]
	if first.TargetID() == second.TargetID() {
		t.Error("the two results collapsed into one identity")
	}
}

// TestMTE10SameReferenceResolvesIndependently is MT-E09.
//
// The references are identical; the authorities are not. Each target receives
// its own credential object, bound to its own endpoint.
func TestMTE10SameReferenceResolvesIndependently(t *testing.T) {
	h := newHarness(t, "orders", "billing").
		withCredential("orders", "SHARED_PASSWORD").
		withCredential("billing", "SHARED_PASSWORD")

	if _, err := h.execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Two resolutions, not one shared result.
	for _, id := range []string{"orders", "billing"} {
		if got := h.resolver.callCount(id); got != 1 {
			t.Errorf("target %q: resolver called %d times, want exactly 1", id, got)
		}
	}

	orders, ok := h.runner.credentialFor("orders")
	if !ok {
		t.Fatal("no credential recorded for orders")
	}
	billing, ok := h.runner.credentialFor("billing")
	if !ok {
		t.Fatal("no credential recorded for billing")
	}

	if orders.Endpoint().Equal(billing.Endpoint()) {
		t.Fatal("two targets on different hosts received one endpoint")
	}
	// Neither credential is usable at the other's endpoint. A shared object
	// would fail here.
	if _, err := orders.SecretFor(billing.Endpoint()); err == nil {
		t.Error("orders' credential was usable at billing's endpoint")
	}
}

// TestMTE02NoFailFastOnDiagnosticOrExecutionFailure is MT-E13 and MT-E14.
//
// A success, a diagnostic failure, a local execution failure, and a success. The
// fourth must run: one broken target must not hide the ones after it, which is
// the entire reason an operator put them in one file.
func TestMTE02NoFailFastOnDiagnosticOrExecutionFailure(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie", "delta").
		concurrency(1).
		behave("bravo", behaveProblems).
		withCredential("charlie", "CHARLIE_PASSWORD").
		resolveFails("charlie", errors.New("credential env CHARLIE_PASSWORD: not set"))

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	want := map[string]domain.ExecutionState{
		"alpha":   domain.ExecutionStateCompleted,
		"bravo":   domain.ExecutionStateCompleted,
		"charlie": domain.ExecutionStateExecutionFailed,
		"delta":   domain.ExecutionStateCompleted,
	}
	for id, state := range want {
		if got := targetByID(t, report, id).ExecutionState(); got != state {
			t.Errorf("target %q: state = %s, want %s", id, got, state)
		}
	}
	if !containsString(h.runner.starts(), "delta") {
		t.Error("delta never ran; one target's failure must not stop unrelated targets")
	}
	// And a runner error is the same story.
	if got := report.Summary().ExecutionFailed(); got != 1 {
		t.Errorf("ExecutionFailed = %d, want 1", got)
	}
}

// TestARunnerErrorIsAnExecutionFailure covers the composition-root error path.
func TestARunnerErrorIsAnExecutionFailure(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie").behave("bravo", behaveError)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	bravo := targetByID(t, report, "bravo")
	if got := bravo.ExecutionState(); got != domain.ExecutionStateExecutionFailed {
		t.Errorf("state = %s, want EXECUTION_FAILED", got)
	}
	if got := bravo.ExecutionErrorClass(); got != domain.ExecutionErrorInternal {
		t.Errorf("class = %s, want INTERNAL", got)
	}
	if bravo.HasReport() {
		t.Error("a runner that returned an error produced no report")
	}
	if got := targetByID(t, report, "charlie").ExecutionState(); got != domain.ExecutionStateCompleted {
		t.Error("a runner error stopped an unrelated target")
	}
}

// TestMTE17RunDeadlineDominatesTargetDeadline is MT-E15.
//
// A target budget can never extend the run's, because the target context is
// derived from the run's rather than from the root.
func TestMTE17RunDeadlineDominatesTargetDeadline(t *testing.T) {
	const runBudget = 200 * time.Millisecond

	h := newHarness(t, "alpha").
		runTimeout(runBudget).
		targetTimeout("alpha", time.Hour).
		behave("alpha", behaveHang)

	start := time.Now()
	report, err := h.execute(context.Background())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if elapsed > 5*time.Second {
		t.Fatalf("the run took %s; a one-hour target budget extended the run's", elapsed)
	}

	deadline, ok := h.runner.deadlineFor("alpha")
	if !ok {
		t.Fatal("the target received no deadline")
	}
	if remaining := time.Until(deadline); remaining > time.Minute {
		t.Errorf("the target's effective deadline is %s away; it must be bounded by the "+
			"run's %s budget", remaining, runBudget)
	}
	if got := targetByID(t, report, "alpha").ExecutionState(); got != domain.ExecutionStateCancelled {
		t.Errorf("state = %s, want CANCELLED", got)
	}
}

// TestATargetDeadlineDoesNotCancelSiblings is MT-E16.
func TestATargetDeadlineDoesNotCancelSiblings(t *testing.T) {
	h := newHarness(t, "alpha", "bravo", "charlie").
		concurrency(1).
		targetTimeout("alpha", 80*time.Millisecond).
		behave("alpha", behaveHang)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// alpha ended on its own budget, so it COMPLETED with an incomplete report.
	alpha := targetByID(t, report, "alpha")
	if got := alpha.ExecutionState(); got != domain.ExecutionStateCompleted {
		t.Errorf("alpha = %s, want COMPLETED; its own budget ended it", got)
	}
	if !alpha.Incomplete() {
		t.Error("alpha's report should be incomplete")
	}
	// The siblings are untouched.
	for _, id := range []string{"bravo", "charlie"} {
		if got := targetByID(t, report, id).ExecutionState(); got != domain.ExecutionStateCompleted {
			t.Errorf("%s = %s, want COMPLETED; a target's own timeout must not cancel a sibling",
				id, got)
		}
	}
	if got := report.StoppedReason(); got != domain.StoppedReasonNone {
		t.Errorf("StoppedReason = %s, want NONE; scheduling was not what stopped", got)
	}
}

// TestTheStepTimeoutReachesTheRunnerUnchanged covers the third budget level.
//
// The scheduler passes the frozen value through and implements no step timing of
// its own: ADR 0073 section 13's hierarchy is run -> target -> the service's own
// step budget, and only the first two are this package's.
func TestTheStepTimeoutReachesTheRunnerUnchanged(t *testing.T) {
	h := newHarness(t, "alpha")
	h.cfg.Targets[0].StepTimeout = 7 * time.Second

	if _, err := h.execute(context.Background()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := h.runner.stepTimeoutFor("alpha"); got != 7*time.Second {
		t.Errorf("the runner received step timeout %s, want 7s", got)
	}
}

// TestMTE11AndE13AndE14Concurrency is MT-E10, MT-E11 and MT-E12.
func TestMTE11AndE13AndE14Concurrency(t *testing.T) {
	t.Run("concurrency 1", func(t *testing.T) {
		h := newHarness(t, "alpha", "bravo", "charlie").concurrency(1)
		if _, err := h.execute(context.Background()); err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got := h.runner.maxActive.Load(); got != 1 {
			t.Errorf("max simultaneous runners = %d, want 1", got)
		}
		// At concurrency 1 the start order is the declared order, which is what
		// makes the sequential reference a reference.
		if got, want := h.runner.starts(), []string{"alpha", "bravo", "charlie"}; !equalStrings(got, want) {
			t.Errorf("start order = %v, want %v", got, want)
		}
	})

	t.Run("maximum concurrency is accepted", func(t *testing.T) {
		h := newHarness(t, "alpha").concurrency(config.MaxConcurrency)
		report, err := h.execute(context.Background())
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if got := report.Concurrency(); got != config.MaxConcurrency {
			t.Errorf("recorded concurrency = %d, want %d", got, config.MaxConcurrency)
		}
	})

	t.Run("invalid concurrency is refused before anything runs", func(t *testing.T) {
		for _, value := range []int{0, -1, config.MaxConcurrency + 1} {
			h := newHarness(t, "alpha").concurrency(value)
			_, err := h.execute(context.Background())
			if !errors.Is(err, run.ErrRun) {
				t.Errorf("concurrency %d: err = %v, want a run refusal", value, err)
			}
			if got := len(h.runner.starts()); got != 0 {
				t.Errorf("concurrency %d: %d targets ran despite an invalid value", value, got)
			}
		}
	})
}

// TestMTE12MaxConcurrencyIsObserved is MT-E11's substantive half.
//
// Substantially more targets than workers, and an independent atomic counter
// inside the runner. Reading the scheduler's own bookkeeping would prove only
// that it agrees with itself.
func TestMTE12MaxConcurrencyIsObserved(t *testing.T) {
	for _, workers := range []int{1, 2, 4, config.MaxConcurrency} {
		t.Run(fmt.Sprintf("concurrency=%d", workers), func(t *testing.T) {
			ids := make([]string, 0, 64)
			for i := range 64 {
				ids = append(ids, fmt.Sprintf("t%02d", i))
			}
			h := newHarness(t, ids...).concurrency(workers)

			if _, err := h.execute(context.Background()); err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := int(h.runner.maxActive.Load()); got > workers {
				t.Errorf("observed %d simultaneous runners, want at most %d", got, workers)
			}
			if got := len(h.runner.starts()); got != len(ids) {
				t.Errorf("%d targets ran, want %d", got, len(ids))
			}
		})
	}
}

// TestConcurrencyOneMatchesTheSequentialReference is MT-E20 and §22.
//
// The concurrent executor at concurrency 1 must be indistinguishable from the
// sequential reference. This is the permanent regression that keeps the two from
// drifting.
func TestConcurrencyOneMatchesTheSequentialReference(t *testing.T) {
	scenario := func(t *testing.T) *harness {
		return newHarness(t, "alpha", "bravo", "charlie", "delta").
			behave("bravo", behaveProblems).
			behave("charlie", behaveIncomplete).
			withCredential("delta", "DELTA_PASSWORD").
			resolveFails("delta", errors.New("credential env DELTA_PASSWORD: not set"))
	}

	sequential, err := scenario(t).concurrency(1).executeSequential(context.Background())
	if err != nil {
		t.Fatalf("ExecuteSequential: %v", err)
	}
	concurrent, err := scenario(t).concurrency(1).execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if diff := compareStructurally(t, sequential, concurrent); diff != "" {
		t.Errorf("concurrency 1 differs from the sequential reference:\n%s", diff)
	}
}

// TestConcurrencyFourMatchesConcurrencyOne is §23.
//
// The same deterministic scenario at 1 and at 4. Wall-clock differs; canonical
// meaning must not.
func TestConcurrencyFourMatchesConcurrencyOne(t *testing.T) {
	scenario := func(t *testing.T, workers int) *harness {
		return newHarness(t, "alpha", "bravo", "charlie", "delta", "echo", "foxtrot").
			concurrency(workers).
			behave("bravo", behaveProblems).
			behave("delta", behaveIncomplete).
			withCredential("echo", "ECHO_PASSWORD").
			resolveFails("echo", errors.New("credential env ECHO_PASSWORD: not set"))
	}

	one, err := scenario(t, 1).execute(context.Background())
	if err != nil {
		t.Fatalf("Execute(1): %v", err)
	}
	four, err := scenario(t, 4).execute(context.Background())
	if err != nil {
		t.Fatalf("Execute(4): %v", err)
	}

	if diff := compareStructurally(t, one, four); diff != "" {
		t.Errorf("concurrency 4 differs from concurrency 1:\n%s", diff)
	}
}

// TestRepeatedRunsAreStructurallyIdentical is MT-D05's stability half.
//
// The same scenario, run many times at a concurrency that genuinely interleaves.
// Any dependence on goroutine scheduling shows up as a difference.
func TestRepeatedRunsAreStructurallyIdentical(t *testing.T) {
	build := func(t *testing.T) *harness {
		return newHarness(t, "alpha", "bravo", "charlie", "delta", "echo").
			concurrency(4).
			behave("charlie", behaveProblems)
	}

	first, err := build(t).execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	for i := range 20 {
		next, err := build(t).execute(context.Background())
		if err != nil {
			t.Fatalf("Execute #%d: %v", i, err)
		}
		if diff := compareStructurally(t, first, next); diff != "" {
			t.Fatalf("run #%d differs:\n%s", i, diff)
		}
	}
}

// TestMTD01DeclaredOrderIsPreservedThroughExecution is MT-D01 and MT-D04.
func TestMTD01DeclaredOrderIsPreservedThroughExecution(t *testing.T) {
	declared := []string{"zulu", "alpha", "mike", "bravo", "yankee"}
	h := newHarness(t, declared...).concurrency(4)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := ids(report); !equalStrings(got, declared) {
		t.Errorf("report order = %v, want declared order %v", got, declared)
	}
	// Not sorted, and not by service or status either — all five share a service.
	if got := ids(report); equalStrings(got, []string{"alpha", "bravo", "mike", "yankee", "zulu"}) {
		t.Error("results came back sorted; declared order is the contract")
	}
}

// TestDeclaredOrderSurvivesMixedExecutionStates is MT-D01's harder half.
//
// # Why the simple ordering test was not enough
//
// TestMTD01 declares five targets that all COMPLETE, so a sort by execution
// state is a no-op on it — `sort.SliceStable` preserves the order of equal keys.
// Mutation B08 planted exactly that sort and survived the whole matrix.
//
// This scenario mixes all four dispositions, so any ordering derived from state,
// status or completion rather than from the file changes the answer.
func TestDeclaredOrderSurvivesMixedExecutionStates(t *testing.T) {
	// Declared so that every "helpful" ordering — by state, by status, by id —
	// differs from the file's.
	h := newHarness(t, "zulu", "alpha", "mike", "bravo", "yankee", "charlie").
		concurrency(1).
		runTimeout(400*time.Millisecond).
		behave("alpha", behaveProblems).
		withCredential("mike", "MIKE_PASSWORD").
		resolveFails("mike", errors.New("credential env MIKE_PASSWORD: not set")).
		behave("bravo", behaveBlockUntilCancelled)

	report, err := h.execute(context.Background())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	declared := []string{"zulu", "alpha", "mike", "bravo", "yankee", "charlie"}
	if got := ids(report); !equalStrings(got, declared) {
		t.Errorf("report order = %v, want the declared order %v", got, declared)
	}

	// The scenario is only meaningful if it genuinely produced mixed states.
	states := map[domain.ExecutionState]int{}
	for _, result := range report.Targets() {
		states[result.ExecutionState()]++
	}
	if len(states) < 3 {
		t.Fatalf("the scenario produced %d distinct states (%v); it must mix them or "+
			"an ordering derived from state would be a no-op here", len(states), states)
	}

	// And no ordering derived from state would produce the same answer.
	byState := slices.Clone(report.Targets())
	sort.SliceStable(byState, func(i, j int) bool {
		return byState[i].ExecutionState() < byState[j].ExecutionState()
	})
	sorted := make([]string, 0, len(byState))
	for _, result := range byState {
		sorted = append(sorted, result.TargetID())
	}
	if equalStrings(sorted, declared) {
		t.Fatal("sorting by execution state produces the declared order, so this test " +
			"cannot distinguish the two")
	}
}

// TestAnUnregisteredServiceStopsTheRunBeforeAnythingExecutes covers the
// registry's own refusal.
func TestAnUnregisteredServiceStopsTheRunBeforeAnythingExecutes(t *testing.T) {
	h := newHarness(t, "alpha", "bravo")
	h.cfg.Targets[1].Service = "mysql"

	_, err := h.execute(context.Background())
	if !errors.Is(err, run.ErrRun) {
		t.Fatalf("err = %v, want a run refusal", err)
	}
	if got := len(h.runner.starts()); got != 0 {
		t.Errorf("%d targets ran; an unregistered service must stop the run before "+
			"anything is dialled", got)
	}
}

// TestTheRunnerRegistryRefusesAmbiguity mirrors config.Registry's discipline.
func TestTheRunnerRegistryRefusesAmbiguity(t *testing.T) {
	if _, err := run.NewRegistry(newFakeRunner("a"), newFakeRunner("a")); err == nil {
		t.Error("registering one kind twice was accepted")
	}
	if _, err := run.NewRegistry(nil); err == nil {
		t.Error("a nil runner was accepted")
	}
	if _, err := run.NewRegistry(newFakeRunner("")); err == nil {
		t.Error("an empty kind was accepted")
	}
}

// TestParamsAreValidatedBeforeAnythingRuns covers the remaining refusals.
func TestParamsAreValidatedBeforeAnythingRuns(t *testing.T) {
	base := newHarness(t, "alpha")

	tests := []struct {
		name   string
		mutate func(*run.Params)
	}{
		{"no registry", func(p *run.Params) { p.Registry = nil }},
		{"no resolver", func(p *run.Params) { p.Resolver = nil }},
		{"no version", func(p *run.Params) { p.Version = "" }},
		{"no targets", func(p *run.Params) { p.Config.Targets = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := base.params()
			tt.mutate(&params)
			if _, err := run.Execute(context.Background(), params); err == nil {
				t.Error("want a refusal")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func targetByID(t *testing.T, report domain.RunReport, id string) domain.TargetResult {
	t.Helper()
	for _, result := range report.Targets() {
		if result.TargetID() == id {
			return result
		}
	}
	t.Fatalf("no target %q in the report", id)
	return domain.TargetResult{}
}

func ids(report domain.RunReport) []string {
	out := make([]string, 0, len(report.Targets()))
	for _, result := range report.Targets() {
		out = append(out, result.TargetID())
	}
	return out
}

// compareStructurally compares two runs' canonical meaning.
//
// It serializes both and blanks the two fields that are legitimately
// time-varying: when the run started and how long it took. Everything else —
// every state, every report, every count, the order — must be byte-identical.
//
// Comparing serialized form rather than field by field is deliberate: it is what
// a consumer actually reads, so a difference this misses is a difference nobody
// can observe.
func compareStructurally(t *testing.T, a, b domain.RunReport) string {
	t.Helper()
	left, right := canonicalJSON(t, a), canonicalJSON(t, b)
	if left == right {
		return ""
	}
	return fmt.Sprintf("--- first\n%s\n--- second\n%s", left, right)
}

func canonicalJSON(t *testing.T, report domain.RunReport) string {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if runSection, ok := generic["run"].(map[string]any); ok {
		runSection["startedAt"] = "<varies>"
		runSection["duration"] = "<varies>"
		// Concurrency is excluded because it is the one field that is *supposed*
		// to differ: the aggregate records the pool size the run actually used.
		// It describes how the run was executed, not what it found, and it is
		// none of the things §23 names as a defect — state, report, summary,
		// ordering or exit outcome.
		runSection["concurrency"] = "<by design>"
	}

	normalized, err := json.MarshalIndent(generic, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return string(normalized)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

// waitFor spins until cond holds, or fails the test.
//
// A polling helper rather than a sleep: a fixed sleep is either too short and
// flaky or too long and slow, and this is neither.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Error("timed out waiting for a condition")
}
