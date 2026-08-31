package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/config"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/run"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/secret"
	"github.com/hakanaltindag/svcdoctor/internal/fleet/services"
	fleetkafka "github.com/hakanaltindag/svcdoctor/internal/fleet/services/kafka"
	fleetpostgres "github.com/hakanaltindag/svcdoctor/internal/fleet/services/postgres"
	fleetrabbitmq "github.com/hakanaltindag/svcdoctor/internal/fleet/services/rabbitmq"
	fleetredis "github.com/hakanaltindag/svcdoctor/internal/fleet/services/redis"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// runCommand is one parsed `svcdoctor run` invocation.
type runCommand struct {
	output    string
	shareable bool
	config    config.Config
}

// runFlagOverrides are the CLI values that beat the configuration.
//
// A pointer per field so that "not written" is distinguishable from "written as
// the zero value". `--concurrency 0` must be refused, and it cannot be if an
// absent flag and an explicit zero look the same.
type runFlagOverrides struct {
	timeout     *time.Duration
	concurrency *int
}

// diagnoseRunCommand executes one multi-target run end to end.
//
// # The shape is `svcdoctor run --config <file>`
//
// Action-first, a sibling of `diagnose` and of the reserved `inspect`, and
// consistent with ADR 0041. `svcdoctor diagnose --config` was rejected because
// `diagnose` requires a service word and a flag in the service position makes it
// two commands; `diagnose batch` was rejected because `batch` would sit exactly
// where `postgres` sits without being a service, which is the confusion ADR 0041
// removed (ADR 0074 section 10.1).
//
// # The four leaf commands are untouched
//
// They keep their flags, defaults, help, exit codes and credential sources. This
// command is additive, and internal/cli/fleetregression_test.go asserts that
// surface by surface.
func (a *App) runCommandEntry(ctx context.Context, args []string) int {
	command, err := a.parseRun(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return RunExitCode(domain.RunReport{}, err)
	}

	report, runErr := a.executeRun(ctx, command.config)
	code := RunExitCode(report, runErr)
	if runErr != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", runErr)
		return code
	}

	projected, err := projectRun(report, command.shareable)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	if err := a.renderRun(command.output, projected); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	return code
}

// parseRun turns arguments into one run's configuration.
//
// # The flag set is the frozen surface and nothing else
//
// Every flag here is run-global. There is deliberately no `--host`, `--port`,
// `--vhost`, `--broker`, `--username`, `--type` or `--target`: a flag that
// edited one target would mean the file no longer describes the run, and with N
// targets it could not say which one it edited. Target data comes from the
// configuration (ADR 0074 section 10.2).
//
// There is no `--password-file`, `--password-stdin` or `--password-env` either.
// One ambient CLI secret available to N targets is precisely the
// cross-contamination ADR 0072 section 7 exists to prevent; credentials come
// from per-target references only.
//
// And there is no `--target` or `--filter`: ADR 0074 section 10.4 leaves
// filtering out of v1 and reserves no flag name for it.
func (a *App) parseRun(args []string) (runCommand, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		path        = fs.String("config", "", "the configuration file to run")
		timeout     = fs.Duration("timeout", 0, "bound on the whole run")
		concurrency = fs.Int("concurrency", 0, "how many targets to run at once")
		output      = fs.String("output", "text", `"text" or "json"`)
		shareable   = fs.Bool("shareable", false, "produce the shareable redacted report")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usageRun(a.Stdout)
			return runCommand{}, errHelpRequested
		}
		return runCommand{}, usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return runCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *path == "" {
		return runCommand{}, usagef("--config is required")
	}
	// ADR 0074 section 10.3: a configuration comes from a regular file. `-` is
	// not stdin, because in fleet mode stdin cannot be both the file describing
	// which secrets to use and a channel a secret would arrive on — and deciding
	// which by position is the ambiguity ADR 0049 §2 refuses to resolve.
	if *path == "-" {
		return runCommand{}, usagef(
			"--config - is not supported; a configuration is read from a regular file, so " +
				"that the artifact which produced a report still exists after the run")
	}
	if err := checkOutput(*output); err != nil {
		return runCommand{}, err
	}

	overrides := runFlagOverrides{}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "timeout":
			overrides.timeout = timeout
		case "concurrency":
			overrides.concurrency = concurrency
		}
	})

	cfg, err := config.LoadFile(*path, fleetConfigRegistry())
	if err != nil {
		return runCommand{}, err
	}
	if cfg, err = applyRunOverrides(cfg, overrides); err != nil {
		return runCommand{}, err
	}

	return runCommand{output: *output, shareable: *shareable, config: cfg}, nil
}

// applyRunOverrides implements the precedence, in one place.
//
//	CLI flag  >  the config's `run:` block  >  the built-in default
//
// The config loader has already resolved the second and third, so this only has
// to apply the first — which is why precedence is decided once, here, and the
// scheduler reads a single number.
//
// An override is validated exactly as the configuration's own value is. There is
// no path by which `--concurrency 0` is accepted because it arrived on the
// command line rather than in the file.
func applyRunOverrides(cfg config.Config, overrides runFlagOverrides) (config.Config, error) {
	if overrides.concurrency != nil {
		value := *overrides.concurrency
		switch {
		case value == 0:
			return config.Config{}, usagef(
				"--concurrency 0 is not a value; it is refused rather than read as " +
					"\"unlimited\" or as \"use the default\"")
		case value < 1 || value > config.MaxConcurrency:
			return config.Config{}, usagef(
				"--concurrency %d must be between 1 and %d", value, config.MaxConcurrency)
		}
		cfg.Run.Concurrency = value
	}

	if overrides.timeout != nil {
		value := *overrides.timeout
		if value <= 0 {
			return config.Config{}, usagef("--timeout %s must be positive", value)
		}
		// ADR 0073 §4.4, applied to the override: a run budget below the largest
		// target budget guarantees every target is cut short by a configuration
		// that looks deliberate.
		for _, target := range cfg.Targets {
			if target.Timeout > value {
				return config.Config{}, usagef(
					"--timeout %s is below the %s timeout of target %q, so that target could "+
						"never complete", value, target.Timeout, target.ID)
			}
		}
		cfg.Run.Timeout = value
	}

	return cfg, nil
}

// executeRun wires the run and performs it.
//
// # This is the single composition point
//
// The four services are named here, once, and nowhere else in the execution
// path. That is ADR 0009's explicit registration: a fifth service adds one entry
// to each registry below and requires no edit to the scheduler, the aggregate,
// the renderer or the exit mapping.
func (a *App) executeRun(ctx context.Context, cfg config.Config) (domain.RunReport, error) {
	// The vantage is a platform fact, collected once for the whole run so that
	// every target's report names the same one — which is what makes the reports
	// inside one aggregate comparable.
	vantage, err := local.Vantage()
	if err != nil {
		return domain.RunReport{}, usagef("%v", err)
	}

	env := services.Environment{
		Resolver: dns.SystemResolver{},
		Dialer:   tcp.SystemDialer{},
		Vantage:  vantage,
		Version:  a.Version,
	}

	registry, err := run.NewRegistry(
		fleetpostgres.Factory{Env: env},
		fleetkafka.Factory{Env: env},
		fleetredis.Factory{Env: env},
		fleetrabbitmq.Factory{Env: env},
	)
	if err != nil {
		return domain.RunReport{}, err
	}

	resolver := secret.NewResolver()

	// ADR 0072 §5: preflight proves every credential reference resolvable and
	// retains no value. It runs **before** the scheduler, so a run with one
	// missing variable dials nothing rather than executing 49 targets and failing
	// on the 50th.
	if err := resolver.PreflightAll(cfg); err != nil {
		return domain.RunReport{}, err
	}

	return run.Execute(ctx, run.Params{
		Config:   cfg,
		Registry: registry,
		Resolver: resolver,
		Version:  a.Version,
	})
}

// fleetConfigRegistry builds the configuration-side registry.
//
// Zero-valued factories: decoding and validating a configuration needs no
// resolver, no dialer and no vantage, which is what lets a file be checked on a
// machine that has none of the secrets and none of the network.
func fleetConfigRegistry() *config.Registry {
	registry, err := config.NewRegistry(
		fleetpostgres.Factory{},
		fleetkafka.Factory{},
		fleetredis.Factory{},
		fleetrabbitmq.Factory{},
	)
	if err != nil {
		// Unreachable: the four kinds are distinct constants with non-zero
		// default ports, and NewRegistry rejects only duplicates, nils and zero
		// ports.
		panic("fleet config registry: " + err.Error())
	}
	return registry
}

// projectRun selects the output form of a finished aggregate.
//
// The whole of `--shareable` for a run, in one place, exactly as project does
// for a single report. Redaction is applied at most once, here, by the command —
// never by a renderer, which cannot even import it.
//
// RedactRun builds a new aggregate through the ordinary domain constructors and
// leaves its input untouched, so the LOCAL_FULL document the exit code was
// derived from is still intact after this returns.
func projectRun(report domain.RunReport, shareable bool) (domain.RunReport, error) {
	if !shareable {
		return report, nil
	}
	redacted, err := redaction.RedactRun(report)
	if err != nil {
		return domain.RunReport{}, fmt.Errorf("deriving the shareable run report: %w", err)
	}
	return redacted, nil
}

// renderRun writes the aggregate in the chosen form.
//
// Both forms receive the same already-projected document, so `--shareable` means
// the same thing in either, and neither renderer chooses an exit code: that was
// decided above, from the structured result.
func (a *App) renderRun(output string, report domain.RunReport) error {
	switch output {
	case outputJSON:
		return renderjson.WriteRun(a.Stdout, report)
	default:
		return renderterminal.WriteRun(a.Stdout, report)
	}
}
