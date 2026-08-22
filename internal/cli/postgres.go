package cli

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	adapterpostgres "github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	renderjson "github.com/hakanaltindag/svcdoctor/internal/render/json"
)

// maxCAFileSize bounds the trust material this command will read.
//
// A PEM bundle of system-CA size is well under this; anything larger is much
// more likely to be the wrong file than a trust store, and failing loudly beats
// reading an arbitrary amount of a file an operator pointed at by mistake.
const maxCAFileSize = 1 << 20

// errHelpRequested is not a failure. It says the parse ended because help was
// asked for, and the caller has already written it to stdout.
var errHelpRequested = errors.New("help requested")

// postgresCommand is one parsed invocation.
//
// It carries the run's parameters and the one value that is not part of them:
// the whole-run deadline, which bounds the call rather than travelling inside it.
type postgresCommand struct {
	params  app.PostgresParams
	timeout time.Duration
}

// diagnosePostgresCommand runs one PostgreSQL diagnosis end to end.
//
// # The shape of the whole boundary, in order
//
//	parse and validate    → invalid invocation stops here, exit 2, nothing on stdout
//	build the parameters  → including the local vantage, a platform fact
//	derive the deadline   → a child of the signal context, never a replacement
//	run one diagnosis     → internal/app owns everything below this line
//	choose the exit code  → from the report's own summary and Incomplete()
//	write the artifact    → canonical JSON, stdout, once
//
// The order matters at two points. Nothing reaches stdout until the run has
// produced a report, so a failed invocation cannot leave half an artifact for a
// pipeline to parse. And the exit code is decided from the result rather than
// from anything this function noticed on the way.
func (a *App) diagnosePostgresCommand(ctx context.Context, args []string) int {
	command, err := a.parsePostgres(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitCode(app.Result{}, err)
	}

	// The whole-run budget hangs off the root context, so a signal still ends
	// the run early and the earlier of the two wins. Per-step budgets remain
	// subordinate and are carried inside the parameters (ADR 0041 section 12).
	runCtx, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	result, runErr := a.diagnosePostgres(runCtx, command.params)
	code := ExitCode(result, runErr)
	if runErr != nil {
		// No report exists, so none is written. A target-side problem never
		// arrives here — it is a fact in a report, not an error (ADR 0048
		// section 7).
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", runErr)
		return code
	}

	if err := renderjson.Write(a.Stdout, result.Report()); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	return code
}

// parsePostgres turns arguments into one run's parameters.
//
// Every rejection is a usage error, and every one of them happens before the
// application is called: an invalid port, a zero timeout or an unreadable trust
// file are facts about the invocation, and spending a connection to discover
// them would report svcdoctor's own input as the endpoint's behaviour.
func (a *App) parsePostgres(args []string) (postgresCommand, error) {
	fs := flag.NewFlagSet("diagnose postgres", flag.ContinueOnError)
	// The FlagSet prints nothing. This package routes help and errors itself,
	// because the destination depends on why they are being printed.
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		host        = fs.String("host", "", "the endpoint to diagnose")
		port        = fs.Uint("port", 5432, "the port to connect to")
		user        = fs.String("user", "", "the role to connect as")
		database    = fs.String("database", "", "the database to select")
		timeout     = fs.Duration("timeout", 30*time.Second, "bound on the whole run")
		stepTimeout = fs.Duration("step-timeout", 10*time.Second, "bound on each exchange")
		tlsMode     = fs.String("tls", "require", `"require" or "disable"`)
		caFile      = fs.String("tls-ca-file", "", "PEM trust source")
		serverName  = fs.String("tls-server-name", "", "identity to verify")
		insecure    = fs.Bool("tls-insecure", false, "do not verify the endpoint's identity")
		output      = fs.String("output", "json", `"json"`)
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usagePostgres(a.Stdout)
			return postgresCommand{}, errHelpRequested
		}
		return postgresCommand{}, usagef("%v", err)
	}
	// A positional argument is a mistake worth naming. Silently ignoring it
	// would run a diagnosis the operator did not describe.
	if fs.NArg() > 0 {
		return postgresCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *host == "" {
		return postgresCommand{}, usagef("--host is required")
	}
	if *user == "" {
		// No fallback to the operating-system user. Diagnosing as whoever
		// happens to be logged in would make the report ambiguous about the
		// role it actually declared, which is the one thing the startup node
		// exists to record.
		return postgresCommand{}, usagef("--user is required")
	}

	// Structural, not left to the network: a port outside the range never
	// produces a truthful connection failure, it produces a confusing one.
	if *port == 0 || *port > math.MaxUint16 {
		return postgresCommand{}, usagef("--port %d is outside 1-65535", *port)
	}
	if *timeout <= 0 {
		return postgresCommand{}, usagef("--timeout %s must be positive", *timeout)
	}
	if *stepTimeout <= 0 {
		return postgresCommand{}, usagef("--step-timeout %s must be positive", *stepTimeout)
	}

	plan, err := tlsPlan(*tlsMode)
	if err != nil {
		return postgresCommand{}, err
	}
	roots, err := trustSource(*caFile)
	if err != nil {
		return postgresCommand{}, err
	}
	if err := checkOutput(*output); err != nil {
		return postgresCommand{}, err
	}

	// The vantage is a platform fact and is collected here, once, from the
	// platform boundary. A host that cannot name itself stops the run: an empty
	// vantage would make every finding's "from this vantage point" meaningless.
	vantage, err := local.Vantage()
	if err != nil {
		return postgresCommand{}, usagef("%v", err)
	}

	return postgresCommand{
		timeout: *timeout,
		params: app.PostgresParams{
			Host:     *host,
			Port:     uint16(*port),
			Role:     *user,
			Database: *database,

			// **Credential is deliberately left at its zero value**, and
			// internal/security is deliberately not imported by this package in
			// Phase 5.1 — so no credential can be constructed here even by
			// accident. That is a product state rather than a gap: an endpoint
			// demanding authentication produces
			// POSTGRES_CREDENTIAL_NOT_CONFIGURED, a truthful WARN with status OK
			// and exit 0, so the CLI never has to acquire something it was not
			// given. ADR 0049 decides how one arrives in Phase 5.2, and nothing
			// in this function's shape has to change for it.

			Resolver: dns.SystemResolver{},
			Dialer:   tcp.SystemDialer{},

			TLS: plan,
			TLSOptions: adapterpostgres.TLSOptions{
				ServerName:         *serverName,
				RootCAs:            roots,
				InsecureSkipVerify: *insecure,
			},

			// TransportPolicy is deliberately left at its zero value. The type
			// has exactly one member, RequireVerifiedTLS, so there is no choice
			// to expose and forgetting refuses rather than permits.

			StepTimeout: *stepTimeout,
			Vantage:     vantage,
			Version:     a.Version,
		},
	}, nil
}

// tlsPlan maps the flag onto the adapter's plan.
//
// Two values, mirroring TLSPlan itself. libpq's six are deliberately not
// reproduced: `verify-ca` and `verify-full` are already expressed by the trust
// source and the verified identity, and `prefer` is refused outright because
// falling back from a failed handshake to a working plaintext one would swallow
// the expired certificate or untrusted chain a diagnostic run exists to find
// (ADR 0036 section 4).
func tlsPlan(mode string) (adapterpostgres.TLSPlan, error) {
	switch mode {
	case "require":
		return adapterpostgres.TLSRequired, nil
	case "disable":
		return adapterpostgres.TLSDisabled, nil
	default:
		return 0, usagef(`--tls %q must be "require" or "disable"`, mode)
	}
}

// checkOutput validates the output form.
//
// **Only JSON exists in Phase 5.1.** ADR 0048 settles the v0.1 surface as
// `text|json` with `text` as the default, and the terminal renderer that would
// honour it is Phase 5.3. Accepting `text` and printing something improvised
// would ship a renderer nobody reviewed; accepting it and failing internally
// would report svcdoctor as broken when the operator did nothing wrong. So it is
// rejected as an invocation error that names the reason, and the default is the
// one form that exists.
func checkOutput(output string) error {
	switch output {
	case "json":
		return nil
	case "text":
		return usagef("--output text is not implemented yet; use --output json")
	default:
		return usagef(`--output %q must be "json"`, output)
	}
}

// trustSource loads the PEM trust material, or reports that it could not.
//
// A nil pool means the system trust store, which is what the adapter documents
// and what an operator who passed no flag asked for.
//
// # The path may appear in an error; the contents never do
//
// A file svcdoctor cannot use has to be nameable or the operator cannot fix it.
// Its bytes are a different matter: a trust file holds no secret, but the rule
// that file contents never reach an error message is worth keeping uniform with
// ADR 0049 rather than reasoned about per file.
func trustSource(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, usagef("--tls-ca-file %s cannot be read: %v", path, statReason(err))
	}
	if info.Size() > maxCAFileSize {
		return nil, usagef("--tls-ca-file %s is larger than %d bytes", path, maxCAFileSize)
	}

	pem, err := os.ReadFile(path) //nolint:gosec // G304: the path is the operator's own flag, bounded above.
	if err != nil {
		return nil, usagef("--tls-ca-file %s cannot be read: %v", path, statReason(err))
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, usagef("--tls-ca-file %s contains no PEM certificate", path)
	}
	return pool, nil
}

// statReason reduces a filesystem error to its cause without echoing the path a
// second time or carrying anything the file held.
func statReason(err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "no such file"
	case errors.Is(err, os.ErrPermission):
		return "permission denied"
	default:
		return "unreadable"
	}
}
