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

// version is svcdoctor's own version, recorded in every report's run metadata.
//
// A plain package variable so a release build can set it with
// `-ldflags "-X main.version=..."`, and a development default so a build from
// source is honest about what it is rather than claiming a release. No build-info
// reflection, no semver library, and no git invocation at runtime: the value has
// to be deterministic, because it lands in the report.
var version = "dev"

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

	os.Exit(cli.New(os.Stdout, os.Stderr, version).Run(ctx, os.Args[1:]))
}
