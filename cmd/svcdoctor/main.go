// Command svcdoctor diagnoses service connectivity from where it is run.
//
// This file is process bootstrap and nothing else: it builds the root context,
// arranges for a signal to cancel it, hands both to internal/cli, and exits with
// the status that comes back. Every decision — what the arguments mean, what to
// write, where to write it, and which exit code applies — belongs to
// internal/cli (ADR 0048 section 3).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hakanaltindag/svcdoctor/internal/cli"
)

func main() {
	// **The root context is created here and nowhere else.** A signal cancels
	// it, cancellation reaches every probe through the context the run already
	// threads, and no probe, adapter, diagnosis rule or renderer installs a
	// handler of its own.
	//
	// Interrupting a run is not an error: internal/app freezes whatever evidence
	// it collected, diagnoses it and returns a report, `Result.Incomplete()`
	// becomes true, and the process exits 4 with the partial report on stdout
	// (ADR 0047, ADR 0048 section 8).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Resolved once, here, and handed down. internal/cli prints this value for
	// --version and records the same one in the report, so the two cannot
	// disagree. See version.go.
	os.Exit(cli.New(os.Stdin, os.Stdout, os.Stderr, resolvedVersion()).Run(ctx, os.Args[1:]))
}
