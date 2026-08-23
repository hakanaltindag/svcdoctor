package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/app"
	"github.com/hakanaltindag/svcdoctor/internal/platform/local"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// kafkaCommand is one parsed invocation.
type kafkaCommand struct {
	params  app.KafkaParams
	timeout time.Duration

	// output names the form to render: "text" or "json".
	output string

	// shareable selects the output projection. It is an *output* decision and
	// deliberately never reaches internal/app.
	shareable bool
}

// diagnoseKafkaCommand runs one Kafka diagnosis end to end.
//
// It is the sibling of diagnosePostgresCommand and has the same shape on
// purpose: parse and validate, derive the deadline, run one diagnosis, choose
// the exit code from the result, then write the artifact. Nothing reaches stdout
// until a report exists, and the exit code is decided before the output
// projection is chosen — so a run cannot exit differently because it was
// rendered for sharing.
//
// The two commands share the exit mapping, the credential sources, the output
// switch and the redaction projection, and share no service knowledge at all.
// That is ADR 0041's shape: each service owns its flags, help and validation.
func (a *App) diagnoseKafkaCommand(ctx context.Context, args []string) int {
	command, err := a.parseKafka(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitCode(app.Result{}, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	result, runErr := a.diagnoseKafka(runCtx, command.params)
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

// parseKafka turns arguments into one run's parameters.
func (a *App) parseKafka(args []string) (kafkaCommand, error) {
	fs := flag.NewFlagSet("diagnose kafka", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		host        = fs.String("host", "", "the bootstrap endpoint to diagnose")
		port        = fs.Uint("port", 9092, "the port to connect to")
		mechanism   = fs.String("sasl-mechanism", "", "the SASL mechanism to propose")
		user        = fs.String("user", "", "the principal to authenticate as")
		timeout     = fs.Duration("timeout", 30*time.Second, "bound on the whole run")
		stepTimeout = fs.Duration("step-timeout", 10*time.Second, "bound on each exchange")
		tlsMode     = fs.String("tls", "require", `"require" or "disable"`)
		caFile      = fs.String("tls-ca-file", "", "PEM trust source")
		serverName  = fs.String("tls-server-name", "", "identity to verify")
		insecure    = fs.Bool("tls-insecure", false, "do not verify the endpoint's identity")
		output      = fs.String("output", "text", `"text" or "json"`)

		passwordFile  = fs.String("password-file", "", "read the credential from a file")
		passwordStdin = fs.Bool("password-stdin", false, "read the credential from stdin")
		shareable     = fs.Bool("shareable", false, "produce the shareable redacted report")
	)

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			a.usageKafka(a.Stdout)
			return kafkaCommand{}, errHelpRequested
		}
		return kafkaCommand{}, usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return kafkaCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *host == "" {
		return kafkaCommand{}, usagef("--host is required")
	}
	target, err := checkHost(*host)
	if err != nil {
		return kafkaCommand{}, err
	}
	if *port == 0 || *port > math.MaxUint16 {
		return kafkaCommand{}, usagef("--port %d is outside 1-65535", *port)
	}
	if *timeout <= 0 {
		return kafkaCommand{}, usagef("--timeout %s must be positive", *timeout)
	}
	if *stepTimeout <= 0 {
		return kafkaCommand{}, usagef("--step-timeout %s must be positive", *stepTimeout)
	}
	if err := checkMechanism(*mechanism); err != nil {
		return kafkaCommand{}, err
	}
	if err := checkOutput(*output); err != nil {
		return kafkaCommand{}, err
	}

	plan, err := kafkaTLSPlan(*tlsMode, *serverName, *caFile, *insecure)
	if err != nil {
		return kafkaCommand{}, err
	}

	sources := credentialSources{file: *passwordFile, fromStdin: *passwordStdin}
	if err := sources.validate(); err != nil {
		return kafkaCommand{}, err
	}
	if err := checkKafkaIdentity(*user, sources); err != nil {
		return kafkaCommand{}, err
	}
	secret, err := a.readSecret(sources)
	if err != nil {
		return kafkaCommand{}, err
	}
	// Bound to the logical endpoint the operator named, and to nothing else.
	// ADR 0050 makes the composition root refuse anything differently bound, so
	// a credential naming a resolved address or an advertised broker cannot be
	// constructed here and travel.
	credential, err := credentialFor(target, uint16(*port), *user, secret)
	if err != nil {
		return kafkaCommand{}, err
	}

	vantage, err := local.Vantage()
	if err != nil {
		return kafkaCommand{}, usagef("%v", err)
	}

	return kafkaCommand{
		timeout:   *timeout,
		output:    *output,
		shareable: *shareable,
		params: app.KafkaParams{
			Host:      target,
			Port:      uint16(*port),
			Mechanism: *mechanism,

			Credential: credential,

			Resolver: dns.SystemResolver{},
			Dialer:   tcp.SystemDialer{},

			TLS: plan,

			// TransportPolicy is deliberately left at its zero value. The type
			// has exactly one member, RequireVerifiedTLS, so there is no choice
			// to expose and forgetting refuses rather than permits.

			StepTimeout: *stepTimeout,
			Vantage:     vantage,
			Version:     a.Version,
		},
	}, nil
}

// checkMechanism validates the SASL mechanism name against RFC 4422 section 3.1.
//
// # Verbatim, uppercase, never folded
//
// `plain` is refused with a usage error naming `PLAIN` rather than silently
// uppercased. Folding here would be harmless on its own and would put a second,
// looser matching rule beside the exact-match whitelist that actually gates the
// credential in internal/adapter/kafka — and two matching rules that disagree is
// how that guard fails quietly (ADR 0057 section 3).
//
// # A mechanism svcdoctor cannot perform is accepted
//
// Naming one sends no secret and costs the broker no authentication attempt. The
// answer is either "this listener does not offer it" or "it does, and svcdoctor
// cannot perform it" — the second is UNKNOWN, an INFO finding and exit 0, with
// zero bytes derived from a credential. Refusing GSSAPI here would remove the
// only way to ask what a broker wants (ADR 0057 section 4).
func checkMechanism(mechanism string) error {
	if mechanism == "" {
		return usagef("--sasl-mechanism is required; svcdoctor never chooses one for you")
	}
	if len(mechanism) > 20 {
		return usagef("--sasl-mechanism %q is longer than 20 characters", mechanism)
	}
	for i := 0; i < len(mechanism); i++ {
		c := mechanism[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		case c >= 'a' && c <= 'z':
			return usagef(
				"--sasl-mechanism %q must be uppercase; SASL mechanism names are registered "+
					"in uppercase, so write %q", mechanism, strings.ToUpper(mechanism))
		default:
			return usagef(
				"--sasl-mechanism %q may contain only A-Z, 0-9, hyphen and underscore",
				mechanism)
		}
	}
	return nil
}

// checkKafkaIdentity refuses the two combinations that would mislead.
//
// Kafka's identity travels only inside the SASL exchange, so a run with no
// credential sends none. PostgreSQL differs and correctly so: its role travels
// in the StartupMessage, which every run sends (ADR 0057 section 5).
func checkKafkaIdentity(user string, sources credentialSources) error {
	configured := sources.file != "" || sources.fromStdin
	switch {
	case configured && user == "":
		return usagef("--user is required with a credential source; " +
			"the credential has no identity to authenticate as")
	case !configured && user != "":
		return usagef("--user has no effect without --password-file or --password-stdin; " +
			"a Kafka run sends an identity only inside the SASL exchange")
	}
	return nil
}

// kafkaTLSPlan builds the run's transport-encryption plan.
//
// # Kafka's TLS is out of band, so a nil plan is the whole of "disable"
//
// PostgreSQL negotiates encryption inside its own protocol, so its adapter takes
// a plan and options separately. Kafka negotiates none: the generic transport
// chain performs an ordinary TLS handshake, or does not (ADR 0053). Nothing here
// infers TLS from the port, the hostname or Kafka convention.
//
// # The trust flags are refused rather than ignored when there is no handshake
//
// `--tls disable --tls-ca-file ca.pem` describes a run that has no handshake to
// apply the trust source to. Accepting it silently would let an operator believe
// they configured trust for a plaintext run.
func kafkaTLSPlan(
	mode, serverName, caFile string, insecure bool,
) (*transport.TLSOptions, error) {
	switch mode {
	case "require":
	case "disable":
		switch {
		case caFile != "":
			return nil, usagef("--tls-ca-file has no effect with --tls disable")
		case serverName != "":
			return nil, usagef("--tls-server-name has no effect with --tls disable")
		case insecure:
			return nil, usagef("--tls-insecure has no effect with --tls disable")
		}
		return nil, nil
	default:
		return nil, usagef(`--tls %q must be "require" or "disable"`, mode)
	}

	roots, err := trustSource(caFile)
	if err != nil {
		return nil, err
	}
	return &transport.TLSOptions{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
	}, nil
}
