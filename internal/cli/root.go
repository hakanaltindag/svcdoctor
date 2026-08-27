// Package cli is svcdoctor's command boundary.
//
// It parses arguments, validates what an operator asked for, builds the
// application's parameters, runs one diagnosis, selects an output form and
// decides the process status. It owns the last of those alone: a renderer never
// chooses an exit code and a command never formats a finding (ADR 0048 section
// 3).
//
// # What it may reach for, and what it may not
//
// This is the composition layer, so it names concrete things on purpose: the
// system resolver and dialer, the PostgreSQL TLS plan, the local vantage
// producer. That is the single explicit wiring point ADR 0009 permits, and it is
// not a registry — there is no map from a service name to a constructor, no
// init-time registration and no reflection.
//
// It must never import internal/diagnosis. Rules run inside the application over
// frozen evidence; a command that could call one could produce a finding nobody
// measured.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/hakanaltindag/svcdoctor/internal/app"
)

// App is one invocation's environment.
//
// The writers are injected rather than taken from the process so that the whole
// command boundary — routing, exit codes, the JSON artifact — is testable
// without a subprocess, and so that stdout discipline is provable rather than
// asserted.
type App struct {
	// In carries credential material when --password-stdin selects it, and is
	// read for nothing else. It is a field rather than os.Stdin so the credential
	// path is testable without a subprocess, and so nothing in this package can
	// read the process's input by reaching around the boundary.
	In io.Reader

	// Stdout receives the report artifact, and nothing else.
	Stdout io.Writer

	// Stderr receives usage errors and internal failures, and nothing else. A
	// run that produces a report writes nothing here (ADR 0048 section 7).
	Stderr io.Writer

	// Version is reported by --version and recorded in the report's run
	// metadata.
	Version string

	// diagnosePostgres and diagnoseKafka are the seams, and they are deliberately
	// two functions rather than one interface with two implementations.
	//
	// They exist so that argument parsing, parameter construction, output
	// routing and the exit-code decision can be tested against a scripted result
	// instead of a live server — the parts of this package that have nothing to
	// do with either protocol and would otherwise be reachable only through
	// Docker.
	//
	// **Neither is a plugin point.** They are unexported, each has exactly one
	// production value, and each names a concrete function. A third service gets
	// a third command with its own wiring, which is the extensibility ADR 0009
	// asked for; it does not get a slot in a registry here. Two fields side by
	// side is what "no central conditional dispatch" looks like when there are
	// two services: the dispatch is the switch in diagnose, at one place, and
	// nothing about PostgreSQL is reachable from the Kafka command or the
	// reverse.
	diagnosePostgres func(context.Context, app.PostgresParams) (app.Result, error)
	diagnoseKafka    func(context.Context, app.KafkaParams) (app.Result, error)
	diagnoseRedis    func(context.Context, app.RedisParams) (app.Result, error)
	diagnoseRabbitMQ func(context.Context, app.RabbitMQParams) (app.Result, error)
}

// New builds the production command environment.
func New(stdin io.Reader, stdout, stderr io.Writer, version string) *App {
	return &App{
		In:               stdin,
		Stdout:           stdout,
		Stderr:           stderr,
		Version:          version,
		diagnosePostgres: app.DiagnosePostgres,
		diagnoseKafka:    app.DiagnoseKafka,
		diagnoseRedis:    app.DiagnoseRedis,
		diagnoseRabbitMQ: app.DiagnoseRabbitMQ,
	}
}

// Run dispatches one invocation and returns the process status.
//
// args excludes the program name. The context is the root one, already carrying
// signal cancellation from cmd/svcdoctor; this package derives the run's
// deadline from it and never replaces it.
//
// # Dispatch is action-first, and a switch
//
// `svcdoctor diagnose postgres`. ADR 0041 fixed the shape and partially
// supersedes ADR 0011, whose reason survives: each service owns its own flags,
// help and validation, so `diagnose postgres` and `diagnose kafka` share the word
// `diagnose`, the exit mapping, the credential sources and the output switch —
// and no service knowledge at all.
//
// `inspect` is **not routed**. ADR 0041 reserved the namespace and deferred its
// output contract; a branch that parsed it and then refused would be a product
// surface that does nothing.
//
// `diagnose kafka` is routed as of Phase 6.4C. It waited for three things and
// not for convenience: a composition root to call, an owner for every
// production-reachable FAIL outcome (ADR 0054), and a renderer that presents a
// discovered broker as a discovered broker rather than as an endpoint the
// operator named (ADR 0052 section 5).
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.usageRoot(a.Stderr)
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help", "help":
		// Requested help is the artifact of that invocation, so it goes to
		// stdout and succeeds. Help printed *because* something was wrong is a
		// diagnostic about the invocation and goes to stderr with a 2, below.
		a.usageRoot(a.Stdout)
		return ExitOK

	case "--version", "-version":
		_, _ = fmt.Fprintln(a.Stdout, a.Version)
		return ExitOK

	case "diagnose":
		return a.diagnose(ctx, args[1:])

	default:
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: unknown command %q\n\n", args[0])
		a.usageRoot(a.Stderr)
		return ExitUsage
	}
}

// diagnose routes one service under the diagnose action.
func (a *App) diagnose(ctx context.Context, args []string) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: diagnose needs a service\n\n")
		a.usageDiagnose(a.Stderr)
		return ExitUsage
	}

	switch args[0] {
	case "-h", "--help":
		a.usageDiagnose(a.Stdout)
		return ExitOK

	case "postgres":
		return a.diagnosePostgresCommand(ctx, args[1:])

	case "kafka":
		return a.diagnoseKafkaCommand(ctx, args[1:])

	case "redis":
		return a.diagnoseRedisCommand(ctx, args[1:])

	case "rabbitmq":
		return a.diagnoseRabbitMQCommand(ctx, args[1:])

	default:
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: unknown service %q\n\n", args[0])
		a.usageDiagnose(a.Stderr)
		return ExitUsage
	}
}
