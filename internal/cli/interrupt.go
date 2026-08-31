package cli

import (
	"context"
	"fmt"
	"os"
)

// abortMessage is the one line a forcibly aborted run writes.
//
// It says what svcdoctor did and makes no claim about any endpoint. A run
// aborted at the operator's insistence measured nothing further, and the process
// is leaving without an aggregate, so describing a target here would be
// describing something that was never observed.
const abortMessage = "svcdoctor: the run was forcibly aborted; no report was produced"

// WatchInterrupts implements ADR 0073 section 7.2's two-stage interrupt
// contract.
//
// # The first signal is not an error, and the second is not a diagnosis
//
//	first    cancel the run's context and let it finish truthfully
//	second   stop immediately, exit 3, one line on stderr
//
// The first signal reaches every probe through the context the run already
// threads: queued targets become NOT_STARTED, in-flight ones are cancelled and
// keep whatever they measured, the aggregate is emitted, and the process exits
// 4 (ADR 0073 section 7.1). Nothing is printed, because being asked to stop is
// not a failure.
//
// The second signal means the operator asked twice and the graceful path did not
// convince them. svcdoctor produced no usable diagnosis, which is precisely what
// docs/SCOPE.md says exit 3 means.
//
// # Why exit 3 rather than the default disposition
//
// Leaving the second signal to Go's default handler terminates with status 130,
// which is outside the 0-4 vocabulary the whole exit contract is stated in. A CI
// script that switches on svcdoctor's exit code would meet a value no document
// defines. ADR 0073 section 7.2 rejected that explicitly, and this is where the
// rejection is implemented.
//
// # Why `done` is a separate channel and not the run's context
//
// It has to be, and getting this wrong is the whole difficulty of the function.
// After the first signal this goroutine has *itself* cancelled the context, so
// the context is done from that instant onward — waiting on it to learn whether
// the run finished would return immediately, every time, and the second signal
// would never be observed. `done` is closed by the caller when Run returns,
// which is the only event that actually means "the graceful path completed".
//
// # Why this is here rather than in cmd/svcdoctor
//
// The exit code and the message are decisions, and ADR 0048 section 3 puts every
// decision in this package. cmd/svcdoctor supplies the channel, the cancel
// function and the terminating action; it chooses none of the three values.
//
// # Before Phase 9.1C the second signal was swallowed entirely
//
// cmd/svcdoctor used signal.NotifyContext, which keeps its handler installed for
// the process's whole life. The second interrupt therefore cancelled an
// already-cancelled context and did nothing at all, so an operator who wanted
// out could not get out and Go's default handler never ran either. That was a
// gap against a frozen decision rather than a deliberate deferral, and no test
// covered it because no run test owned a signal.
//
// It returns as soon as `done` closes, so an ordinary run releases it without a
// signal ever arriving.
func (a *App) WatchInterrupts(
	done <-chan struct{},
	signals <-chan os.Signal,
	cancel context.CancelFunc,
	abort func(code int),
) {
	select {
	case <-done:
		return
	case <-signals:
		cancel()
	}

	select {
	case <-done:
		// The run observed the cancellation, wrote its aggregate and returned an
		// exit code. Nothing further to do.
		return
	case <-signals:
		_, _ = fmt.Fprintln(a.Stderr, abortMessage)
		abort(ExitInternal)
	}
}
