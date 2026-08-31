package run_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
)

// Phase 9.1C scheduler stress: concurrency, scale, determinism and cancellation
// under load.
//
// # Why fakes rather than services, restated for the scale cases
//
// Every property here is about scheduling. Running 512 targets against real
// endpoints would measure Docker, and would make the 512-target case a test
// nobody runs. The fake runner is a real Runner implementation returning real
// domain.Report values through the real constructors, so the scheduler cannot
// tell it from a service — it just answers instantly.

// targetIDs generates n valid target identifiers in declared order.
//
// Zero-padded so that declared order and lexical order coincide. That is
// deliberate: a test whose declared order was already sorted could not
// distinguish "order preserved" from "order sorted", so the tests that care
// about the difference use unsorted identifiers explicitly.
func targetIDs(n int) []string {
	out := make([]string, 0, n)
	for i := range n {
		out = append(out, fmt.Sprintf("t%04d", i))
	}
	return out
}

// TestMTE11AndE12ConcurrencyIsBoundedAtEveryPoolSize is section 12.
//
// It measures four things independently of the scheduler's own bookkeeping:
// peak simultaneous runners, starts, completions and results. A bound inferred
// from the scheduler's counters would prove only that they agree with
// themselves, so the peak comes from an atomic the fake owns.
func TestMTE11AndE12ConcurrencyIsBoundedAtEveryPoolSize(t *testing.T) {
	const targets = 64

	for _, workers := range []int{1, 2, 4, 8, 16} {
		t.Run(fmt.Sprintf("concurrency %d", workers), func(t *testing.T) {
			h := newHarness(t, targetIDs(targets)...).concurrency(workers)
			// Every target blocks until `workers` of them are inside Run
			// together, so the peak below is a measured fact rather than a race
			// that happened to go the right way.
			h.runner.barrier = make(chan struct{})
			h.runner.barrierWidth = workers

			report, err := h.execute(context.Background())
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}

			peak := int(h.runner.maxActive.Load())
			if peak > workers {
				t.Errorf("peak simultaneous runners = %d, above the configured %d",
					peak, workers)
			}
			if peak != workers {
				t.Errorf("peak simultaneous runners = %d at concurrency %d; the pool "+
					"never reached its configured width, so the upper bound above "+
					"would hold vacuously", peak, workers)
			}

			if got := len(h.runner.starts()); got != targets {
				t.Errorf("%d targets started, want %d", got, targets)
			}
			if got := len(h.runner.completions()); got != targets {
				t.Errorf("%d targets completed, want %d", got, targets)
			}
			if got := len(report.Targets()); got != targets {
				t.Errorf("%d results, want %d", got, targets)
			}

			assertNoLostOrDuplicatedTarget(t, report, targets)
			assertDeclaredOrder(t, report)
			if got := report.Summary().Completed(); got != targets {
				t.Errorf("summary counts %d completed, want %d", got, targets)
			}
		})
	}
}

// assertNoLostOrDuplicatedTarget proves the result set is exactly the target set.
func assertNoLostOrDuplicatedTarget(t *testing.T, report domain.RunReport, want int) {
	t.Helper()

	seen := make(map[string]int, want)
	for _, result := range report.Targets() {
		seen[result.TargetID()]++
		if result.ExecutionState() == domain.ExecutionStateUnspecified {
			t.Errorf("target %q has no execution state", result.TargetID())
		}
	}
	if len(seen) != want {
		t.Errorf("%d distinct target ids in the aggregate, want %d", len(seen), want)
	}
	for id, count := range seen {
		if count != 1 {
			t.Errorf("target %q appears %d times", id, count)
		}
	}
}

// assertDeclaredOrder proves the aggregate is in declared configuration order.
func assertDeclaredOrder(t *testing.T, report domain.RunReport) {
	t.Helper()
	results := report.Targets()
	for i, result := range results {
		if want := fmt.Sprintf("t%04d", i); result.TargetID() != want {
			t.Fatalf("result %d is %q, want %q: declared order was not preserved",
				i, result.TargetID(), want)
		}
	}
}

// TestMTE22TheTargetMaximumExecutes is section 13.
//
// max-1, max and max+1. The first two run; the third must be refused by the
// configuration boundary before a runner or a resolver is ever constructed,
// which is asserted in TestTheTargetMaximumIsRefusedBeforeAnythingExecutes.
func TestMTE22TheTargetMaximumExecutes(t *testing.T) {
	for _, count := range []int{config.MaxTargets - 1, config.MaxTargets} {
		t.Run(fmt.Sprintf("%d targets", count), func(t *testing.T) {
			h := newHarness(t, targetIDs(count)...).concurrency(16)

			started := time.Now()
			report, err := h.execute(context.Background())
			elapsed := time.Since(started)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}

			if got := len(report.Targets()); got != count {
				t.Fatalf("%d results, want %d", got, count)
			}
			assertNoLostOrDuplicatedTarget(t, report, count)
			assertDeclaredOrder(t, report)

			summary := report.Summary()
			if summary.Targets() != count || summary.Completed() != count {
				t.Errorf("summary reconciles to %d/%d, want %d completed of %d",
					summary.Completed(), summary.Targets(), count, count)
			}
			if summary.NotStarted()+summary.Cancelled()+summary.ExecutionFailed() != 0 {
				t.Error("a target was not completed in a run with no failures scripted")
			}
			if summary.Incomplete() {
				t.Error("the run reports itself incomplete with every target completed")
			}

			// Recorded rather than asserted against a threshold: a wall-clock
			// bound would be a machine-speed test, and Phase 9.1C section 13 asks
			// that measurements not become stronger safety claims.
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatalf("marshalling the aggregate: %v", err)
			}
			t.Logf("%d targets: %s, aggregate %d bytes (%d bytes/target)",
				count, elapsed.Round(time.Millisecond), len(encoded), len(encoded)/count)
		})
	}
}

// TestTheTargetMaximumIsRefusedBeforeAnythingExecutes is max+1.
//
// The refusal belongs to the configuration boundary, which is what makes
// ADR 0074 section 9's "zero targets dialled" structural: there is no path from
// an over-large file to a runner, because the file never becomes a Config.
func TestTheTargetMaximumIsRefusedBeforeAnythingExecutes(t *testing.T) {
	var doc = "version: 1\ntargets:\n"
	for i := range config.MaxTargets + 1 {
		doc += fmt.Sprintf("  - id: t%04d\n    type: testsvc\n    host: h%04d.example.com\n", i, i)
	}

	_, err := config.Load([]byte(doc), "stress.yaml", credentialRegistry(t))
	if err == nil {
		t.Fatalf("%d targets was accepted; the maximum is %d",
			config.MaxTargets+1, config.MaxTargets)
	}
	var configErr *config.Error
	if !errors.As(err, &configErr) {
		t.Fatalf("returned %T rather than a classified configuration error", err)
	}
}

// TestMTD05AndD07RepeatedRunsAreStable is section 14.
//
// One hundred repetitions of one scenario, at a concurrency high enough that
// completion order varies between them, compared as normalized JSON. Everything
// except the run's own start time and duration must be identical.
//
// It detects map iteration order, worker completion order reaching the output,
// pseudonym instability, summary instability and target ordering drift — each of
// which would show up as a differing document rather than as a targeted
// assertion, which is why the comparison is over the whole encoded aggregate.
func TestMTD05AndD07RepeatedRunsAreStable(t *testing.T) {
	const repetitions = 100

	var first string
	for run := range repetitions {
		h := newHarness(t, targetIDs(24)...).concurrency(8)
		// A mixture of dispositions, so the comparison covers more than a run in
		// which every target does the same thing.
		h.behave("t0003", behaveProblems)
		h.behave("t0007", behaveIncomplete)
		h.behave("t0011", behaveError)
		h.behave("t0017", behaveProblems)

		report, err := h.execute(context.Background())
		if err != nil {
			t.Fatalf("repetition %d: %v", run, err)
		}

		encoded := canonicalJSON(t, report)
		if run == 0 {
			first = encoded
			continue
		}
		if encoded != first {
			t.Fatalf("repetition %d differs from the first:\n first: %s\n  this: %s",
				run, first, encoded)
		}
	}
}

// TestMTD02RandomizedCompletionOrderNeverReachesTheOutput is section 15.
//
// Each seed drives a deterministic pseudo-random gate release order, so targets
// finish in an order the scheduler did not choose and could not predict. The
// aggregate must be the same document every time.
//
// The seed is deterministic and reported on failure, so a failing case is
// reproducible rather than a story about a flake. There is no sleep anywhere:
// ordering comes from closing gates in sequence, which is a happens-before
// relationship rather than a hope about timing.
func TestMTD02RandomizedCompletionOrderNeverReachesTheOutput(t *testing.T) {
	const (
		seeds   = 40
		targets = 12
	)

	var expected string
	for seed := range uint64(seeds) {
		// A seeded PCG rather than crypto/rand, deliberately: the point is a
		// completion order that is varied *and reproducible*, so a failing seed
		// can be re-run. Unpredictability would make failures unrepeatable,
		// which is the opposite of what this needs.
		//nolint:gosec // G404: determinism is the requirement, not secrecy.
		order := rand.New(rand.NewPCG(seed, 0x9E3779B97F4A7C15)).Perm(targets)

		h := newHarness(t, targetIDs(targets)...).concurrency(targets)
		h.runner.gate = map[string]chan struct{}{}
		for _, id := range targetIDs(targets) {
			h.runner.gate[id] = make(chan struct{})
		}

		done := make(chan domain.RunReport, 1)
		errs := make(chan error, 1)
		go func() {
			report, err := h.execute(context.Background())
			if err != nil {
				errs <- err
				return
			}
			done <- report
		}()

		// Release in the permuted order. Every target has a worker, so each
		// release completes one target before the next is released.
		for _, index := range order {
			close(h.runner.gate[fmt.Sprintf("t%04d", index)])
		}

		var report domain.RunReport
		select {
		case report = <-done:
		case err := <-errs:
			t.Fatalf("seed %d: %v", seed, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("seed %d: the run did not finish", seed)
		}

		assertDeclaredOrder(t, report)

		encoded := canonicalJSON(t, report)
		if seed == 0 {
			expected = encoded
			continue
		}
		if encoded != expected {
			t.Fatalf("seed %d produced a different aggregate (release order %v):\n"+
				" want: %s\n  got: %s", seed, order, expected, encoded)
		}
	}
}

// TestMTE06CancellationLifecycleMatrix is section 16.
//
// One run holding all four lifecycle states at the instant of cancellation:
// already completed, actively running, and queued behind a full pool. Each must
// land in its own frozen disposition, and a never-started target must have
// touched neither the resolver nor the runner.
func TestMTE06CancellationLifecycleMatrix(t *testing.T) {
	// Six targets, one worker: the first completes, the second blocks and is
	// cancelled in flight, the remaining four are never offered.
	h := newHarness(t, "done", "active", "queued-a", "queued-b", "queued-c", "queued-d").
		concurrency(1)
	h.behave("active", behaveBlockUntilCancelled)
	for _, id := range []string{"done", "active", "queued-a", "queued-b", "queued-c", "queued-d"} {
		h.withCredential(id, "SHARED")
	}

	ctx, cancel := context.WithCancel(context.Background())

	reports := make(chan domain.RunReport, 1)
	errs := make(chan error, 1)
	go func() {
		report, err := h.execute(ctx)
		if err != nil {
			errs <- err
			return
		}
		reports <- report
	}()

	// Wait until the second target is actually running, so the cancellation
	// lands on a real in-flight target rather than on a race.
	waitFor(t, func() bool { return len(h.runner.starts()) == 2 })
	cancel()

	var report domain.RunReport
	select {
	case report = <-reports:
	case err := <-errs:
		t.Fatalf("Execute: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("the run did not finish after cancellation")
	}

	states := map[string]domain.ExecutionState{}
	for _, result := range report.Targets() {
		states[result.TargetID()] = result.ExecutionState()
	}

	if got := states["done"]; got != domain.ExecutionStateCompleted {
		t.Errorf("the already-completed target became %s; completing is not undone "+
			"by a later cancellation", got)
	}
	if got := states["active"]; got != domain.ExecutionStateCancelled {
		t.Errorf("the in-flight target became %s, want CANCELLED", got)
	}
	for _, id := range []string{"queued-a", "queued-b", "queued-c", "queued-d"} {
		if got := states[id]; got != domain.ExecutionStateNotStarted {
			t.Errorf("queued target %q became %s, want NOT_STARTED", id, got)
		}
	}

	// A never-started target has no report, invoked no runner and — the part
	// that matters most — invoked no resolver, so no secret was read for a
	// target that was never going to run.
	for _, result := range report.Targets() {
		if result.ExecutionState() != domain.ExecutionStateNotStarted {
			continue
		}
		id := result.TargetID()
		if result.HasReport() {
			t.Errorf("never-started target %q carries a report", id)
		}
		if n := h.resolver.callCount(id); n != 0 {
			t.Errorf("never-started target %q resolved its credential %d times", id, n)
		}
		for _, started := range h.runner.starts() {
			if started == id {
				t.Errorf("never-started target %q reached the runner", id)
			}
		}
	}

	if reason := report.StoppedReason(); reason != domain.StoppedReasonCancelled {
		t.Errorf("stopped reason %s, want CANCELLED", reason)
	}
	// A cancelled run is incomplete and says nothing about any endpoint.
	if !report.Summary().Incomplete() {
		t.Error("a run with cancelled and never-started targets is not incomplete")
	}
	if report.Summary().Status() != domain.SummaryStatusOK {
		t.Error("cancellation produced a PROBLEMS_FOUND status; the operator stopped " +
			"svcdoctor, and the endpoints did nothing")
	}
}

// TestCancellationAtEveryPointInTheLifecycle covers section 16's timing list.
//
// Cancelling immediately, during resolution, during execution and after most
// targets have finished must each produce a valid aggregate with no fabricated
// evidence and no panic.
func TestCancellationAtEveryPointInTheLifecycle(t *testing.T) {
	tests := []struct {
		name   string
		cancel func(t *testing.T, h *harness, cancel context.CancelFunc)
	}{
		{
			name: "immediately after start",
			cancel: func(_ *testing.T, _ *harness, cancel context.CancelFunc) {
				cancel()
			},
		},
		{
			name: "once a target is running",
			cancel: func(t *testing.T, h *harness, cancel context.CancelFunc) {
				waitFor(t, func() bool { return len(h.runner.starts()) >= 1 })
				cancel()
			},
		},
		{
			name: "after most targets have completed",
			cancel: func(t *testing.T, h *harness, cancel context.CancelFunc) {
				waitFor(t, func() bool { return len(h.runner.completions()) >= 4 })
				cancel()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, targetIDs(8)...).concurrency(1)
			h.behave("t0005", behaveBlockUntilCancelled)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			reports := make(chan domain.RunReport, 1)
			errs := make(chan error, 1)
			go func() {
				report, err := h.execute(ctx)
				if err != nil {
					errs <- err
					return
				}
				reports <- report
			}()

			tc.cancel(t, h, cancel)

			select {
			case report := <-reports:
				assertNoLostOrDuplicatedTarget(t, report, 8)
				assertDeclaredOrder(t, report)
				assertNoFabricatedEvidence(t, report)
			case err := <-errs:
				t.Fatalf("Execute: %v", err)
			case <-time.After(30 * time.Second):
				t.Fatal("the run did not finish after cancellation")
			}
		})
	}
}

// assertNoFabricatedEvidence proves the presence invariants hold after a
// cancellation: a never-started target carries no report and no execution error.
func assertNoFabricatedEvidence(t *testing.T, report domain.RunReport) {
	t.Helper()
	for _, result := range report.Targets() {
		switch result.ExecutionState() {
		case domain.ExecutionStateNotStarted:
			if result.HasReport() {
				t.Errorf("never-started target %q carries a report", result.TargetID())
			}
			if result.ExecutionErrorMessage() != "" {
				t.Errorf("never-started target %q carries an execution error",
					result.TargetID())
			}
		case domain.ExecutionStateExecutionFailed:
			if result.HasReport() {
				t.Errorf("failed target %q carries a report", result.TargetID())
			}
		case domain.ExecutionStateCompleted, domain.ExecutionStateCancelled:
			if !result.HasReport() {
				t.Errorf("target %q is %s with no report",
					result.TargetID(), result.ExecutionState())
			}
		case domain.ExecutionStateUnspecified:
			t.Errorf("target %q has no execution state", result.TargetID())
		}
	}
}

// TestMTE17DeadlineRaceStress is section 17.
//
// Budgets are set close enough together that which one fires first varies
// between iterations. The properties are the ones that must hold whichever wins:
// exactly one result per target, no panic, no missing result, and a run that
// terminates.
//
// Under `-race` this is also where a double write to a result slot would surface.
func TestMTE17DeadlineRaceStress(t *testing.T) {
	budgets := []struct {
		name          string
		run, target   time.Duration
		alsoCancelAt  time.Duration
		blockedTarget string
	}{
		{name: "run budget equals target budget", run: 25 * time.Millisecond, target: 25 * time.Millisecond},
		{name: "target budget just under the run's", run: 30 * time.Millisecond, target: 25 * time.Millisecond},
		{name: "run budget just under the target's", run: 25 * time.Millisecond, target: 30 * time.Millisecond},
		{name: "cancellation races the run budget", run: 25 * time.Millisecond, target: 25 * time.Millisecond, alsoCancelAt: 25 * time.Millisecond},
	}

	for _, tc := range budgets {
		t.Run(tc.name, func(t *testing.T) {
			for iteration := range 25 {
				h := newHarness(t, targetIDs(8)...).concurrency(4).runTimeout(tc.run)
				for _, id := range targetIDs(8) {
					h.targetTimeout(id, tc.target)
				}
				// Two targets outlive the budgets, so the deadline is what stops
				// them rather than their own completion.
				h.behave("t0002", behaveHang)
				h.behave("t0006", behaveBlockUntilCancelled)

				ctx, cancel := context.WithCancel(context.Background())
				if tc.alsoCancelAt > 0 {
					timer := time.AfterFunc(tc.alsoCancelAt, cancel)
					defer timer.Stop()
				}

				report, err := h.execute(ctx)
				cancel()
				if err != nil {
					t.Fatalf("iteration %d: %v", iteration, err)
				}

				assertNoLostOrDuplicatedTarget(t, report, 8)
				assertDeclaredOrder(t, report)
				assertNoFabricatedEvidence(t, report)

				// A local budget expiring is not a remote failure. Nothing in
				// this run reached an endpoint, so nothing may claim one did.
				if report.Summary().Status() != domain.SummaryStatusOK {
					t.Fatalf("iteration %d: a budget expiry produced PROBLEMS_FOUND; "+
						"a local deadline is not proof of remote failure", iteration)
				}
			}
		})
	}
}

// TestMTE16ATargetTimeoutDoesNotCancelASibling pins the isolation half of the
// budget contract.
//
// # The siblings have to still be running, and that is the whole test
//
// The obvious version gives one target a short budget and three others no
// special behaviour. It passes against a scheduler that cancels every sibling
// when one times out, because instant-returning siblings have already finished
// by the time the slow one expires — mutation C28 survived exactly that.
//
// So the siblings are held open until the slow target has demonstrably timed
// out, and only then released. If a target-local deadline reached the run
// context, they would come back cancelled and incomplete instead of completed.
func TestMTE16ATargetTimeoutDoesNotCancelASibling(t *testing.T) {
	for iteration := range 10 {
		h := newHarness(t, "slow", "held-a", "held-b", "held-c").concurrency(4)
		h.behave("slow", behaveHang)
		h.targetTimeout("slow", 20*time.Millisecond)
		for _, id := range []string{"held-a", "held-b", "held-c"} {
			h.behave(id, behaveBlockUntilReleased)
		}

		reports := make(chan domain.RunReport, 1)
		errs := make(chan error, 1)
		go func() {
			report, err := h.execute(context.Background())
			if err != nil {
				errs <- err
				return
			}
			reports <- report
		}()

		// The slow target's own budget expires while all three siblings are
		// still inside Run.
		waitFor(t, func() bool { return containsString(h.runner.completions(), "slow") })
		close(h.runner.release)

		var report domain.RunReport
		select {
		case report = <-reports:
		case err := <-errs:
			t.Fatalf("iteration %d: %v", iteration, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("iteration %d: the run did not finish", iteration)
		}

		for _, result := range report.Targets() {
			if result.TargetID() == "slow" {
				continue
			}
			if got := result.ExecutionState(); got != domain.ExecutionStateCompleted {
				t.Fatalf("iteration %d: sibling %q became %s when only \"slow\" timed "+
					"out; a target-local deadline reached the run context",
					iteration, result.TargetID(), got)
			}
			if result.Incomplete() {
				t.Fatalf("iteration %d: sibling %q was marked incomplete by another "+
					"target's deadline", iteration, result.TargetID())
			}
		}
	}
}

// TestAPreCancelledRunTouchesNothing covers the race window runOne guards.
//
// # The window, and why nothing else sees it
//
// The dispatcher stops offering work once the run context is done, so in the
// ordinary cancellation path a queued target is never handed to a worker and
// runOne is never entered for it. runOne's own `if e.runCtx.Err() != nil` guard
// exists for the instant *between* those two facts: Go's select chooses
// uniformly at random when several cases are ready, so a dispatcher whose
// context is already done can still hand out one more index.
//
// Every existing cancellation test misses it, because none of them enters that
// window — which is why mutations C21 and C22, both of which delete the guard,
// survived the whole suite.
//
// Starting from an already-cancelled context puts the dispatcher in exactly that
// state on its first iteration. Repetition covers the randomness: the guard is
// the only thing preventing a dial, so a run that resolves or runs anything here
// has lost the property.
func TestAPreCancelledRunTouchesNothing(t *testing.T) {
	const iterations = 60

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for iteration := range iterations {
		h := newHarness(t, targetIDs(4)...).concurrency(4)
		for _, id := range targetIDs(4) {
			h.withCredential(id, "SHARED_PASSWORD")
		}

		report, err := h.execute(ctx)
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}

		if starts := h.runner.starts(); len(starts) != 0 {
			t.Fatalf("iteration %d: a cancelled run reached the runner for %v; no "+
				"target may be dialled after the run has ended", iteration, starts)
		}
		for _, id := range targetIDs(4) {
			if n := h.resolver.callCount(id); n != 0 {
				t.Fatalf("iteration %d: target %q resolved its credential %d times "+
					"in a cancelled run; a secret must not be read for a target that "+
					"is not going to run", iteration, id, n)
			}
		}
		for _, result := range report.Targets() {
			if got := result.ExecutionState(); got != domain.ExecutionStateNotStarted {
				t.Fatalf("iteration %d: target %q is %s in a run cancelled before it "+
					"began", iteration, result.TargetID(), got)
			}
		}
	}
}

// TestNoGoroutineIsLeakedAcrossRepeatedRuns is section 33's owned-resource half.
//
// # Why the count is compared across a plateau rather than before and after one
//
// Go's runtime keeps goroutines alive for reasons this package does not control
// — the testing package's own, garbage collection, the network poller. A single
// before/after comparison catches those as false positives and misses a slow
// leak entirely.
//
// So a batch of runs is performed first to reach a steady state, the count is
// taken, a much larger batch follows, and the count must not have grown. A
// scheduler leaking one goroutine per run would add hundreds; noise does not
// accumulate.
func TestNoGoroutineIsLeakedAcrossRepeatedRuns(t *testing.T) {
	execute := func() {
		h := newHarness(t, targetIDs(8)...).concurrency(4)
		h.behave("t0003", behaveIncomplete)
		if _, err := h.execute(context.Background()); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	}

	for range 20 {
		execute()
	}
	settle()
	baseline := runtime.NumGoroutine()

	for range 200 {
		execute()
	}
	settle()
	after := runtime.NumGoroutine()

	// A generous absolute allowance, because the assertion that matters is
	// "did not grow by 200".
	if after > baseline+10 {
		t.Errorf("goroutines went from %d to %d across 200 runs; the scheduler is "+
			"leaking one per run", baseline, after)
	}
}

// TestNoGoroutineIsLeakedAfterCancellation is the same property on the path
// where a leak is most likely: workers abandoned mid-flight.
func TestNoGoroutineIsLeakedAfterCancellation(t *testing.T) {
	execute := func() {
		h := newHarness(t, targetIDs(8)...).concurrency(4)
		h.behave("t0002", behaveBlockUntilCancelled)
		h.behave("t0005", behaveBlockUntilCancelled)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			waitFor(t, func() bool { return len(h.runner.starts()) >= 2 })
			cancel()
		}()
		if _, err := h.execute(ctx); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	}

	for range 10 {
		execute()
	}
	settle()
	baseline := runtime.NumGoroutine()

	for range 100 {
		execute()
	}
	settle()
	after := runtime.NumGoroutine()

	if after > baseline+10 {
		t.Errorf("goroutines went from %d to %d across 100 cancelled runs",
			baseline, after)
	}
}

// settle gives finished goroutines a chance to be reaped before counting.
func settle() {
	for range 5 {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
}
