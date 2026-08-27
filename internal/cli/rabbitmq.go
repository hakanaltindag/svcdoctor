package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// rabbitmqCommand is one parsed `diagnose rabbitmq` invocation.
type rabbitmqCommand struct {
	timeout   time.Duration
	output    string
	shareable bool
	params    app.RabbitMQParams
}

// diagnoseRabbitMQCommand runs one RabbitMQ diagnosis end to end.
//
// It is the fourth sibling of the PostgreSQL, Kafka and Redis commands and has
// the same shape for the same reason: each service owns its flags, help and
// validation, and the four share the word `diagnose`, the exit mapping, the
// credential sources and the output switch — and no service knowledge at all.
//
// **One command diagnoses every AMQP 0-9-1 broker.** The verb never becomes a
// claim: which implementation answered is read from the endpoint's own
// Connection.Start and rendered from the report.
func (a *App) diagnoseRabbitMQCommand(ctx context.Context, args []string) int {
	command, err := a.parseRabbitMQ(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitCode(app.Result{}, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	result, runErr := a.diagnoseRabbitMQ(runCtx, command.params)
	code := ExitCode(result, runErr)
	if runErr != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", runErr)
		return code
	}

	report, err := project(result.Report(), command.shareable)
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	if err := a.render(command.output,
		render.Input{Report: report, Incomplete: result.Incomplete()}); err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitInternal
	}
	return code
}

// parseRabbitMQ turns arguments into one run's parameters.
//
// # The flag set is the frozen surface and nothing else
//
// No `--mechanism`: there is exactly one, and a selector would imply a fallback
// ladder that ADR 0068 §2 refuses. No `--heartbeat`, `--frame-max` or
// `--channel-max`: ADR 0070 fixes all three, and a knob for a frozen value is a
// knob for a decision the operator cannot usefully make. No `--queue`,
// `--exchange`, `--publish` or `--consume`: BASIC names no resource. No
// `--management-*`: the management API is a second protocol on a second port
// with its own authorization surface, and ADR 0067 §8 keeps it out entirely,
// including its flag namespace. No `--cluster`, `--node` or `--discovery`: AMQP
// 0-9-1 offers no discovery to decline. No `--connection-name`: it would put an
// operator-supplied string in the broker's connection list for no evidence.
//
// `--vhost` defaults to `/` rather than being required. The virtual host is
// rendered either way, so the default is a stated assumption rather than an
// unstated one — and a refusal naming a defaulted virtual host says so
// (ADR 0067 §3.1).
//
// `--username` is optional and is never synthesized. svcdoctor does not supply
// `guest`: doing so would present a credential the operator did not choose, and
// against a default RabbitMQ it would sometimes work, which is worse.
func (a *App) parseRabbitMQ(args []string) (rabbitmqCommand, error) {
	fs := flag.NewFlagSet("diagnose rabbitmq", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		host        = fs.String("host", "", "the endpoint to diagnose")
		port        = fs.Uint("port", 5672, "the port to connect to")
		vhost       = fs.String("vhost", "", "the virtual host to open")
		username    = fs.String("username", "", "the identity to authenticate as")
		timeout     = fs.Duration("timeout", 30*time.Second, "bound on the whole run")
		stepTimeout = fs.Duration("step-timeout", 10*time.Second, "bound on each exchange")
		tlsMode     = fs.String("tls", "require", `"require" or "disable"`)
		caFile      = fs.String("tls-ca-file", "", "PEM trust source")
		serverName  = fs.String("tls-server-name", "", "identity to verify")
		insecure    = fs.Bool("tls-insecure", false, "do not verify the endpoint's identity")
		output      = fs.String("output", "text", `"text" or "json"`)

		passwordFile  = fs.String("password-file", "", "read the credential from a file")
		passwordStdin = fs.Bool("password-stdin", false, "read the credential from stdin")

		shareable = fs.Bool("shareable", false, "produce the shareable redacted report")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usageRabbitMQ(a.Stdout)
			return rabbitmqCommand{}, errHelpRequested
		}
		return rabbitmqCommand{}, usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return rabbitmqCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *host == "" {
		return rabbitmqCommand{}, usagef("--host is required")
	}
	target, err := checkHost(*host)
	if err != nil {
		return rabbitmqCommand{}, err
	}
	if *port == 0 || *port > math.MaxUint16 {
		return rabbitmqCommand{}, usagef("--port %d is outside 1-65535", *port)
	}
	if *timeout <= 0 {
		return rabbitmqCommand{}, usagef("--timeout %s must be positive", *timeout)
	}
	if *stepTimeout <= 0 {
		return rabbitmqCommand{}, usagef("--step-timeout %s must be positive", *stepTimeout)
	}
	// **The floor is three seconds and it is not arbitrary.** Several RabbitMQ
	// refusal paths hold the socket open for exactly that long on purpose, so a
	// shorter budget would report a broker's deliberate delay as svcdoctor's own
	// deadline expiring — an UNKNOWN where a FAIL was measurable (ADR 0070 §8).
	if *stepTimeout <= 3*time.Second {
		return rabbitmqCommand{}, usagef(
			"--step-timeout %s must exceed 3s: RabbitMQ delays several refusals by "+
				"exactly that long, and a shorter budget reports the delay as a local "+
				"timeout instead of the refusal it is", *stepTimeout)
	}
	if len(*vhost) > app.MaxVHostBytes {
		return rabbitmqCommand{}, usagef(
			"--vhost is %d bytes, above the %d byte protocol maximum",
			len(*vhost), app.MaxVHostBytes)
	}

	tlsEnabled, err := rabbitmqTLSEnabled(*tlsMode)
	if err != nil {
		return rabbitmqCommand{}, err
	}
	// Refused, not ignored. ADR 0060's contract, from the one file that holds it
	// for every service.
	if err := refuseInertTLSFlags(tlsFlags{
		disabled:   !tlsEnabled,
		caFile:     *caFile,
		serverName: *serverName,
		insecure:   *insecure,
	}); err != nil {
		return rabbitmqCommand{}, err
	}
	roots, err := trustSource(*caFile)
	if err != nil {
		return rabbitmqCommand{}, err
	}
	if err := checkOutput(*output); err != nil {
		return rabbitmqCommand{}, err
	}

	sources := credentialSources{file: *passwordFile, fromStdin: *passwordStdin}
	if err := sources.validate(); err != nil {
		return rabbitmqCommand{}, err
	}
	secret, err := a.readSecret(sources)
	if err != nil {
		return rabbitmqCommand{}, err
	}
	credential, err := credentialFor(target, uint16(*port), *username, secret)
	if err != nil {
		return rabbitmqCommand{}, err
	}

	vantage, err := local.Vantage()
	if err != nil {
		return rabbitmqCommand{}, usagef("%v", err)
	}

	return rabbitmqCommand{
		timeout:   *timeout,
		output:    *output,
		shareable: *shareable,
		params: app.RabbitMQParams{
			Host:     target,
			Port:     uint16(*port),
			VHost:    *vhost,
			Username: *username,

			Credential: credential,

			Resolver: dns.SystemResolver{},
			Dialer:   tcp.SystemDialer{},

			TLS: redisTLSOptions(tlsEnabled, *serverName, roots, *insecure),

			StepTimeout: *stepTimeout,
			Vantage:     vantage,
			Version:     a.Version,
		},
	}, nil
}

// rabbitmqTLSEnabled reads the two-valued `--tls` flag.
//
// The same two words every other service accepts, and no third. RabbitMQ TLS is
// a separate listening port rather than an in-band negotiation, so "require"
// means an ordinary handshake on the port the operator named — it does not mean
// svcdoctor will look for a TLS port, and nothing infers TLS from the port
// number (ADR 0067 §3).
func rabbitmqTLSEnabled(mode string) (bool, error) {
	switch mode {
	case "require":
		return true, nil
	case "disable":
		return false, nil
	default:
		return false, usagef(`--tls %q must be "require" or "disable"`, mode)
	}
}
