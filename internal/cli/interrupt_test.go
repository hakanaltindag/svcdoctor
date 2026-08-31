package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The two-stage interrupt contract, ADR 0073 section 7.2.
//
// # Why this is a seam test rather than a real signal test
//
// Phase 9.1C section 32 permits either, and asks that the choice be stated.
// Delivering a real SIGINT means building a binary, starting a subprocess,
// racing to send the signal after the run has begun but before it ends, and
// doing so on a platform where the signal exists. Every one of those is a
// portability or timing hazard, and the property under test — *what svcdoctor
// decides when a second signal arrives* — is not about signal delivery at all.
//
// So delivery is exercised where it lives, in cmd/svcdoctor, by
// TestTheDeliveryChannelHoldsBothStages below and by the compiler; and the
// decision is exercised here, deterministically, with no subprocess and no
// sleep-based synchronization.

// watcher drives WatchInterrupts with channels a test controls completely.
type watcher struct {
	app     *App
	stderr  *bytes.Buffer
	signals chan os.Signal
	done    chan struct{}

	mu      sync.Mutex
	aborted []int

	// cancelled closes when the watcher cancels the run's context. A channel
	// rather than a bool so a test can wait for stage one to actually land
	// instead of assuming a buffered send was already processed.
	cancelled chan struct{}
	cancelOne sync.Once

	finished chan struct{}
}

func newWatcher() *watcher {
	stderr := &bytes.Buffer{}
	w := &watcher{
		app:       &App{Stderr: stderr, Version: "test"},
		stderr:    stderr,
		signals:   make(chan os.Signal, 2),
		done:      make(chan struct{}),
		cancelled: make(chan struct{}),
		finished:  make(chan struct{}),
	}
	return w
}

func (w *watcher) start() {
	go func() {
		defer close(w.finished)
		w.app.WatchInterrupts(w.done, w.signals, w.cancel, w.abort)
	}()
}

func (w *watcher) cancel() {
	w.cancelOne.Do(func() { close(w.cancelled) })
}

// awaitCancel blocks until stage one has run, so a test never races a buffered
// signal send against the watcher's first select.
func (w *watcher) awaitCancel(t *testing.T) {
	t.Helper()
	select {
	case <-w.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("the first interrupt never cancelled the run's context")
	}
}

func (w *watcher) abort(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.aborted = append(w.aborted, code)
}

func (w *watcher) abortCodes() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]int(nil), w.aborted...)
}

func (w *watcher) didCancel() bool {
	select {
	case <-w.cancelled:
		return true
	default:
		return false
	}
}

// await waits for the watcher goroutine to return, and fails rather than hangs.
func (w *watcher) await(t *testing.T) {
	t.Helper()
	select {
	case <-w.finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the interrupt watcher did not return")
	}
}

// TestMTE07AFirstInterruptCancelsAndASecondAborts is the frozen contract in one
// test: stage one cancels and prints nothing, stage two exits 3 and says so.
func TestMTE07AFirstInterruptCancelsAndASecondAborts(t *testing.T) {
	w := newWatcher()
	w.start()

	w.signals <- syscall.SIGINT
	w.awaitCancel(t)

	// The abort path is what releases the watcher, so waiting for it is the
	// synchronization. No sleep decides anything here.
	w.signals <- syscall.SIGINT
	w.await(t)

	aborted := w.abortCodes()
	if len(aborted) != 1 {
		t.Fatalf("abort was called %d times, want exactly 1", len(aborted))
	}
	if aborted[0] != ExitInternal {
		t.Errorf("a forced abort exited %d, want %d", aborted[0], ExitInternal)
	}
	if got := w.stderr.String(); !strings.Contains(got, "forcibly aborted") {
		t.Errorf("stderr = %q, want it to say the run was forcibly aborted", got)
	}
}

// TestAFirstInterruptAloneNeitherAbortsNorPrints pins stage one's silence.
//
// A run the operator stopped is reported through the aggregate and exit 4. If
// this path printed, every graceful Ctrl-C would put a line on stderr that
// ADR 0048 section 7 reserves for failures.
func TestAFirstInterruptAloneNeitherAbortsNorPrints(t *testing.T) {
	w := newWatcher()
	w.start()

	w.signals <- syscall.SIGINT
	w.awaitCancel(t)

	// The run finishes gracefully after observing the cancellation.
	close(w.done)
	w.await(t)

	if aborted := w.abortCodes(); len(aborted) != 0 {
		t.Errorf("abort was called %v after a single interrupt; it must not be", aborted)
	}
	if got := w.stderr.String(); got != "" {
		t.Errorf("stderr = %q after one interrupt, want nothing: being asked to stop "+
			"is not a failure", got)
	}
}

// TestAnUninterruptedRunReleasesTheWatcher proves the ordinary path costs
// nothing: no signal ever arrives, the run returns, the goroutine exits.
func TestAnUninterruptedRunReleasesTheWatcher(t *testing.T) {
	w := newWatcher()
	w.start()

	close(w.done)
	w.await(t)

	if w.didCancel() {
		t.Error("an uninterrupted run had its context cancelled")
	}
	if aborted := w.abortCodes(); len(aborted) != 0 {
		t.Errorf("an uninterrupted run aborted with %v", aborted)
	}
}

// TestTheWatcherDoesNotWaitOnTheCancelledContext is the regression for the
// defect this function was written around.
//
// The obvious implementation waits on the run's context in both stages. That
// looks right and is not: after stage one the watcher has cancelled the context
// itself, so stage two's wait returns immediately and the second interrupt is
// never observed. This test fails against that implementation, because the
// abort never happens.
//
// It differs from the first test only in that the second signal is sent after a
// real scheduling gap rather than immediately, which is the window in which a
// context-based implementation would already have returned.
func TestTheWatcherDoesNotWaitOnTheCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stderr := &bytes.Buffer{}
	app := &App{Stderr: stderr, Version: "test"}

	signals := make(chan os.Signal, 2)
	done := make(chan struct{})
	aborted := make(chan int, 1)
	finished := make(chan struct{})

	go func() {
		defer close(finished)
		app.WatchInterrupts(done, signals, cancel, func(code int) { aborted <- code })
	}()

	signals <- syscall.SIGINT

	// Wait for the cancellation to actually land, so the second signal is sent
	// strictly after the context is done. A watcher that selected on ctx.Done()
	// in stage two has already returned by now.
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the first interrupt never cancelled the context")
	}

	signals <- syscall.SIGINT

	select {
	case code := <-aborted:
		if code != ExitInternal {
			t.Errorf("abort code %d, want %d", code, ExitInternal)
		}
	case <-finished:
		t.Fatal("the watcher returned without aborting: it waited on the context it had " +
			"just cancelled, so the second interrupt was never observed")
	case <-time.After(5 * time.Second):
		t.Fatal("the second interrupt was not observed")
	}
}

// TestTheAbortMessageMakesNoClaimAboutAnyTarget keeps stage two's one line
// honest. An aborted run measured nothing further, so it may not describe an
// endpoint's condition.
func TestTheAbortMessageMakesNoClaimAboutAnyTarget(t *testing.T) {
	forbidden := []string{
		"healthy", "unhealthy", "unreachable", "down", "failed to connect",
		"refused", "timed out",
	}
	lower := strings.ToLower(abortMessage)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Errorf("the abort message says %q; an aborted run observed nothing", word)
		}
	}
	if !strings.Contains(lower, "no report") {
		t.Error("the abort message does not say that no report was produced")
	}
}
