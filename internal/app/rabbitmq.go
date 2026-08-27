package app

import (
	"context"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/rabbitmq"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosisrabbitmq "github.com/hakanaltindag/svcdoctor/internal/diagnosis/rabbitmq"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// DefaultVHost is RabbitMQ's own `default_vhost`, and svcdoctor's default.
//
// ADR 0067 §3.1 defaults rather than requires it: the virtual host is rendered
// either way, so a defaulted `/` is a stated assumption rather than an unstated
// one. The one bad case — a refusal naming a virtual host the operator never
// chose — is made self-explaining by recording that the default was used.
const DefaultVHost = "/"

// MaxVHostBytes is the protocol maximum for a virtual host name.
//
// Re-exported so the CLI can refuse oversized operator input at the flag
// boundary, where a refusal can be explained, without importing the adapter.
const MaxVHostBytes = rabbitmq.MaxVHostBytes

// RabbitMQParams describes one RabbitMQ diagnostic run.
//
// **One parameter type for every AMQP 0-9-1 broker.** Which implementation
// answered is an observation the report carries, never an input that changes
// what svcdoctor does — the same shape ADR 0066 froze for Redis and Valkey.
type RabbitMQParams struct {
	// Host and Port are the logical endpoint the operator asked about.
	//
	// **This pair is the credential authority boundary**, and no resolved
	// address ever replaces it. It is also not widened by the virtual host:
	// Connection.Start-Ok carries the credential and Connection.Open names the
	// vhost, in that order, so a vhost-scoped authority would have to gate a
	// transmission that already happened (ADR 0068 §6).
	Host string
	Port uint16

	// VHost is the virtual host to open. Empty means DefaultVHost.
	VHost string

	// Username is the identity presented in the SASL PLAIN response.
	Username string

	// Credential authenticates at the logical endpoint above. It may be zero.
	Credential security.Credential

	// Resolver and Dialer are the probes' seams, so a caller may run the whole
	// composition without a network. Required.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS is the transport-encryption plan. Nil means the run speaks plaintext.
	//
	// RabbitMQ negotiates no encryption in band — a TLS listener is a separate
	// port — so this is ordinary out-of-band transport TLS and the generic chain
	// performs it. Nothing infers TLS from the port number (ADR 0067 §3).
	TLS *transport.TLSOptions

	// TransportPolicy decides whether the credential may cross the channel the
	// selected path established. The zero value requires verified TLS, so a
	// caller that never set it refuses rather than permits.
	TransportPolicy security.CredentialTransportPolicy

	// StepTimeout optionally bounds each probe call and each protocol exchange.
	StepTimeout time.Duration

	// Vantage records where the probes ran from.
	Vantage domain.Vantage

	// Version is svcdoctor's own version, recorded in the run metadata.
	Version string
}

func (p RabbitMQParams) validate() error {
	switch {
	case p.Host == "":
		return fmt.Errorf("%w: host must not be empty", ErrInvalidInput)
	case p.Port == 0:
		return fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	case p.Resolver == nil:
		return fmt.Errorf("%w: resolver must not be nil", ErrInvalidInput)
	case p.Dialer == nil:
		return fmt.Errorf("%w: dialer must not be nil", ErrInvalidInput)
	case p.Vantage.IsZero():
		return fmt.Errorf("%w: vantage must not be zero", ErrInvalidInput)
	case p.Version == "":
		return fmt.Errorf("%w: version must not be empty", ErrInvalidInput)
	case p.StepTimeout < 0:
		return fmt.Errorf("%w: step timeout %s must not be negative",
			ErrInvalidInput, p.StepTimeout)
	case len(p.vhost()) > rabbitmq.MaxVHostBytes:
		// Refused before a connection is opened. The protocol's `path` domain
		// caps a virtual host at 127 bytes, and truncating would send a
		// *different* virtual host than the report names.
		return fmt.Errorf("%w: virtual host of %d bytes exceeds the %d byte protocol maximum",
			ErrInvalidInput, len(p.vhost()), rabbitmq.MaxVHostBytes)
	}
	if !p.Credential.IsZero() {
		endpoint, err := p.endpoint()
		if err != nil {
			return err
		}
		if !p.Credential.Endpoint().Equal(endpoint) {
			// **The composition root may not rebind a credential.** This is the
			// first of two independent authority checks; the adapter's SecretFor
			// call is the second, and removing either one alone still fails the
			// suite.
			return fmt.Errorf("%w: credential is bound to %s, not to %s",
				ErrInvalidInput, p.Credential.Endpoint(), endpoint)
		}
	}
	return nil
}

func (p RabbitMQParams) endpoint() (security.Endpoint, error) {
	endpoint, err := security.NewEndpoint(p.Host, p.Port)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return endpoint, nil
}

// vhost resolves the virtual host, defaulting to `/`.
func (p RabbitMQParams) vhost() string {
	if p.VHost == "" {
		return DefaultVHost
	}
	return p.VHost
}

// DiagnoseRabbitMQ measures one RabbitMQ endpoint and reports what it found.
//
// # It discovers broadly and authenticates narrowly
//
// Every resolved address is measured through DNS, TCP, TLS when the plan asks
// for it, and the AMQP 0-9-1 protocol header exchange. All of that is
// credential-free, so measuring a second path costs the endpoint a connection
// and **not** an authentication attempt. Exactly one path then continues past
// the credential boundary.
//
// # One connection past that boundary, and no way back
//
// There is no redial, no reconnect and no second authentication anywhere in this
// function. They are not forbidden by a check that could be reset; they are
// unwritten, and a structural guard asserts their absence.
//
// # Errors, and what is not one
//
// An error means the run could not be performed: unusable input, or an invariant
// failure such as a graph that rejected a node. **Every diagnostic outcome is a
// report**, including one where nothing connected, the credential was rejected,
// or the virtual host was refused.
func DiagnoseRabbitMQ(ctx context.Context, params RabbitMQParams) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	host, err := normalizeHost(params.Host)
	if err != nil {
		return Result{}, err
	}
	params.Host = host
	if err := params.validate(); err != nil {
		return Result{}, err
	}

	startedAt := time.Now()
	builder := domain.NewGraphBuilder()
	target := logicalTarget{host: params.Host, port: params.Port}

	if err := measureRabbitMQ(ctx, builder, target, params); err != nil {
		return Result{}, err
	}

	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	// A passing Connection.Open-Ok is deliberately **not** used to short-circuit
	// incompleteness. A run whose selected path opened while another path's
	// protocol exchange timed out locally really did leave something unmeasured,
	// and saying so is the honest answer.
	incomplete := incompleteRun(ctx, graph, false)

	findings := diagnosis.NewEngine(
		diagnosistransport.DNS,
		diagnosistransport.TCP,
		diagnosistransport.TLS,
		diagnosisrabbitmq.ConnectionStart,
		diagnosisrabbitmq.Authentication,
		diagnosisrabbitmq.ConnectionOpen,
	).Diagnose(graph)

	report, err := buildRabbitMQReport(graph, findings, target, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	return Result{report: report, incomplete: incomplete}, nil
}

// measureRabbitMQ performs every network stage and records what happened.
func measureRabbitMQ(
	ctx context.Context, builder *domain.GraphBuilder, target logicalTarget,
	params RabbitMQParams,
) error {
	requested, err := recordRequestedTarget(builder, target, time.Now())
	if err != nil {
		return err
	}

	// DNS, TCP and — when the plan asks for it — TLS, for every resolved
	// address. An IP-literal target resolves nothing and records no dns.lookup
	// node at all, which is what makes a DNS finding structurally unreachable
	// for one rather than suppressed (ADR 0059).
	sweep, err := transport.Run(ctx, builder, transport.Params{
		Host:        params.Host,
		Port:        params.Port,
		Resolver:    params.Resolver,
		Dialer:      params.Dialer,
		TLS:         params.TLS,
		StepTimeout: params.StepTimeout,
		Parent:      requested,
	})
	if err != nil {
		return fmt.Errorf("transport discovery: %w", err)
	}
	defer func() { _ = sweep.Close() }()

	if len(sweep.Continuations()) == 0 {
		return nil
	}

	protocol, err := rabbitmq.Start(ctx, builder, sweep.Continuations(), rabbitmq.Params{
		VHost:           params.vhost(),
		VHostDefaulted:  params.VHost == "",
		Username:        params.Username,
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("rabbitmq protocol discovery: %w", err)
	}
	defer closeRabbitMQSessions(protocol.Sessions())

	return continueOneRabbitMQPath(ctx, builder, protocol.Sessions(), params)
}

func closeRabbitMQSessions(sessions []*rabbitmq.Session) {
	for _, session := range sessions {
		_ = session.Close()
	}
}

// continueOneRabbitMQPath selects at most one path and takes it through the
// credential boundary.
//
// # At most one credential-bearing attempt, by construction
//
// This function calls rabbitmq.Authenticate at most once, with one session, and
// no loop, index or second candidate is in scope after the selection. An attempt
// that cannot be written cannot become a default (ADR 0068 §5).
func continueOneRabbitMQPath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	sessions []*rabbitmq.Session,
	params RabbitMQParams,
) error {
	if len(sessions) == 0 {
		return nil
	}

	candidates := make([]candidate[*rabbitmq.Session], 0, len(sessions))
	for _, session := range sessions {
		candidates = append(candidates, candidate[*rabbitmq.Session]{
			address: session.Address(),
			result:  session,
			// The adapter's own answer, never a literal here: ADR 0041 §8.1
			// partitions candidates by whether the endpoint demanded
			// authentication, and a composition root that decided that itself
			// would be inventing evidence.
			authRequired: session.AuthRequired(),
		})
	}

	chosen := selectPath(candidates, !params.Credential.IsZero())
	for i := range candidates {
		if i != chosen {
			_ = candidates[i].result.Close()
		}
	}
	if chosen == -1 {
		return nil
	}
	selected := candidates[chosen].result

	if ctx.Err() != nil {
		// The budget ended before the credentialed step. Nothing is attempted
		// and nothing is recorded: unattempted work is not a target failure.
		return nil
	}

	endpoint, err := params.endpoint()
	if err != nil {
		return err
	}

	if err := rabbitmq.Authenticate(ctx, builder, selected, rabbitmq.AuthParams{
		Endpoint:        endpoint,
		Credential:      params.Credential,
		Username:        params.Username,
		Policy:          params.TransportPolicy,
		ExchangeTimeout: params.StepTimeout,
	}); err != nil {
		return fmt.Errorf("authenticating at %s: %w", selected.Address(), err)
	}

	// **The virtual host is only requested on an authenticated connection.**
	//
	// A run that presented nothing, was refused, or had its credential withheld
	// has no authenticated connection to open one on. Recording an open node
	// anyway would claim an exchange nobody performed, and the first broken
	// layer already owns the break.
	if !selected.Authenticated() {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}

	return rabbitmq.Open(ctx, builder, selected, rabbitmq.OpenParams{
		ExchangeTimeout: params.StepTimeout,
	})
}

// buildRabbitMQReport assembles the canonical report.
func buildRabbitMQReport(
	graph domain.Graph, findings []domain.Finding, target logicalTarget,
	params RabbitMQParams, startedAt time.Time,
) (domain.Report, error) {
	service, err := domain.NewServiceID("rabbitmq")
	if err != nil {
		return domain.Report{}, fmt.Errorf("building service id: %w", err)
	}
	run, err := domain.NewRunMetadata(params.Version, startedAt, time.Since(startedAt), service)
	if err != nil {
		return domain.Report{}, fmt.Errorf("building run metadata: %w", err)
	}
	reportTarget, err := target.target()
	if err != nil {
		return domain.Report{}, fmt.Errorf("building target: %w", err)
	}
	// **Gated on the plan, not on the option alone.** A plaintext run performs no
	// handshake, so it has no verification to have disabled, and reporting true
	// there would be a TLS fact about a run that attempted none (ADR 0060).
	insecure := params.TLS != nil && params.TLS.InsecureSkipVerify
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, insecure, false)
	if err != nil {
		return domain.Report{}, fmt.Errorf("building report security: %w", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run:      run,
		Target:   reportTarget,
		Vantage:  params.Vantage,
		Graph:    graph,
		Findings: findings,
		Security: reportSecurity,
	})
	if err != nil {
		return domain.Report{}, fmt.Errorf("building report: %w", err)
	}
	return report, nil
}
