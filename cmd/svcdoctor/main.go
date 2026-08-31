// Command svcdoctor diagnoses service connectivity from where it is run.
//
// This file is process bootstrap and nothing else: it builds the root context,
// arranges for signals to reach it, hands both to internal/cli, and exits with
// the status that comes back. Every decision — what the arguments mean, what to
// write, where to write it, which exit code applies, and what a second interrupt
// means — belongs to internal/cli (ADR 0048 section 3).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hakanaltindag/svcdoctor/internal/cli"
)

// interruptBuffer is how many signals the delivery channel holds.
//
// Two, because the contract has two stages and os/signal drops a signal rather
// than blocking when the buffer is full. A single-slot channel could discard the
// second interrupt while the first was still being handled, which is precisely
// the one that must not be lost.
const interruptBuffer = 2

func main() {
	// **The root context is created here and nowhere else.** The first signal
	// cancels it, cancellation reaches every probe through the context the run
	// already threads, and no probe, adapter, diagnosis rule or renderer
	// installs a handler of its own.
	//
	// Interrupting a run is not an error: internal/app freezes whatever evidence
	// it collected, diagnoses it and returns a report, `Result.Incomplete()`
	// becomes true, and the process exits 4 with the partial report on stdout
	// (ADR 0047, ADR 0048 section 8).
	//
	// A *second* signal aborts with exit 3 and no report (ADR 0073 section 7.2).
	// signal.NotifyContext cannot express that — it collapses every signal onto
	// one cancellation and swallows the rest — so the two stages are delivered
	// on a channel and decided by internal/cli.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	signals := make(chan os.Signal, interruptBuffer)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	// Resolved once, here, and handed down. internal/cli prints this value for
	// --version and records the same one in the report, so the two cannot
	// disagree. See version.go.
	app := cli.New(os.Stdin, os.Stdout, os.Stderr, resolvedVersion())

	// done closes when Run returns. It is what tells the watcher the graceful
	// path finished; the context cannot, because after the first signal the
	// watcher has cancelled it itself.
	done := make(chan struct{})
	go app.WatchInterrupts(done, signals, cancel, os.Exit)

	code := app.Run(ctx, os.Args[1:])
	close(done)
	os.Exit(code)
}
