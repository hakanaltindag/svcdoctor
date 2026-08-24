package cli

import (
	"context"
	"crypto/x509"
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
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/render"
)

// redisCommand is one parsed `diagnose redis` invocation.
type redisCommand struct {
	timeout   time.Duration
	output    string
	shareable bool
	params    app.RedisParams
}

// diagnoseRedisCommand runs one Redis or Valkey diagnosis end to end.
//
// It is the third sibling of diagnosePostgresCommand and diagnoseKafkaCommand
// and has the same shape for the same reason: each service owns its flags, help
// and validation, and the three share the word `diagnose`, the exit mapping, the
// credential sources and the output switch — and no service knowledge at all.
//
// **One command diagnoses both implementations.** ADR 0066 section 6 freezes
// that, and the verb never becomes a claim: which implementation answered is
// read from the endpoint's own HELLO reply and rendered from the report.
func (a *App) diagnoseRedisCommand(ctx context.Context, args []string) int {
	command, err := a.parseRedis(args)
	if errors.Is(err, errHelpRequested) {
		return ExitOK
	}
	if err != nil {
		_, _ = fmt.Fprintf(a.Stderr, "svcdoctor: %v\n", err)
		return ExitCode(app.Result{}, err)
	}

	runCtx, cancel := context.WithTimeout(ctx, command.timeout)
	defer cancel()

	result, runErr := a.diagnoseRedis(runCtx, command.params)
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

// parseRedis turns arguments into one run's parameters.
//
// # The flag set is the two existing ones, minus what Redis does not have
//
// No `--db`: BASIC names no key, so the database index is unobservable and a
// flag for it would imply a keyspace scope svcdoctor does not have. No
// `--resp-version`: v1 speaks RESP2 and a flag would be a knob for a capability
// that does not exist. No `--expected-role`, `--expected-server`, `--cluster` or
// `--sentinel`: service behaviour is discovered from the endpoint's own HELLO
// reply and never declared by the operator. No `--probe-command`: the terminal
// step is named after the command it runs, and a flag would make that name lie.
//
// `--username` is optional, and its absence is meaningful rather than defaulted:
// it selects the one-argument AUTH form, which behaves differently from the
// two-argument form against a `nopass` user (ADR 0064 section 5).
func (a *App) parseRedis(args []string) (redisCommand, error) {
	fs := flag.NewFlagSet("diagnose redis", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}

	var (
		host        = fs.String("host", "", "the endpoint to diagnose")
		port        = fs.Uint("port", 6379, "the port to connect to")
		username    = fs.String("username", "", "the ACL user to authenticate as")
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
			a.usageRedis(a.Stdout)
			return redisCommand{}, errHelpRequested
		}
		return redisCommand{}, usagef("%v", err)
	}
	if fs.NArg() > 0 {
		return redisCommand{}, usagef("unexpected argument %q", fs.Arg(0))
	}

	if *host == "" {
		return redisCommand{}, usagef("--host is required")
	}
	target, err := checkHost(*host)
	if err != nil {
		return redisCommand{}, err
	}
	if *port == 0 || *port > math.MaxUint16 {
		return redisCommand{}, usagef("--port %d is outside 1-65535", *port)
	}
	if *timeout <= 0 {
		return redisCommand{}, usagef("--timeout %s must be positive", *timeout)
	}
	if *stepTimeout <= 0 {
		return redisCommand{}, usagef("--step-timeout %s must be positive", *stepTimeout)
	}

	tlsEnabled, err := redisTLSEnabled(*tlsMode)
	if err != nil {
		return redisCommand{}, err
	}
	// Refused, not ignored. ADR 0060's contract, from the one file that holds
	// it for every service.
	if err := refuseInertTLSFlags(tlsFlags{
		disabled:   !tlsEnabled,
		caFile:     *caFile,
		serverName: *serverName,
		insecure:   *insecure,
	}); err != nil {
		return redisCommand{}, err
	}
	roots, err := trustSource(*caFile)
	if err != nil {
		return redisCommand{}, err
	}
	if err := checkOutput(*output); err != nil {
		return redisCommand{}, err
	}

	sources := credentialSources{file: *passwordFile, fromStdin: *passwordStdin}
	if err := sources.validate(); err != nil {
		return redisCommand{}, err
	}
	secret, err := a.readSecret(sources)
	if err != nil {
		return redisCommand{}, err
	}
	credential, err := credentialFor(target, uint16(*port), *username, secret)
	if err != nil {
		return redisCommand{}, err
	}

	vantage, err := local.Vantage()
	if err != nil {
		return redisCommand{}, usagef("%v", err)
	}

	return redisCommand{
		timeout:   *timeout,
		output:    *output,
		shareable: *shareable,
		params: app.RedisParams{
			Host:     target,
			Port:     uint16(*port),
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

// redisTLSEnabled reads the two-valued `--tls` flag.
//
// The same two words every other service accepts, and no third. Redis TLS is a
// separate listening port rather than an in-band negotiation, so "require" here
// means an ordinary handshake on the port the operator named — it does not mean
// svcdoctor will look for a TLS port, and nothing infers TLS from the port
// number or from a URI scheme (ADR 0024).
func redisTLSEnabled(mode string) (bool, error) {
	switch mode {
	case "require":
		return true, nil
	case "disable":
		return false, nil
	default:
		return false, usagef(`--tls %q must be "require" or "disable"`, mode)
	}
}

// redisTLSOptions builds the transport plan, or nil for a plaintext run.
//
// Nil rather than a disabled option struct, because the generic chain reads nil
// as "perform no handshake" and a struct carrying InsecureSkipVerify on a run
// that performs no handshake is exactly the inert configuration ADR 0060
// refuses.
func redisTLSOptions(
	enabled bool, serverName string, roots *x509.CertPool, insecure bool,
) *transport.TLSOptions {
	if !enabled {
		return nil
	}
	return &transport.TLSOptions{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
	}
}
