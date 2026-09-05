package app

import (
	"context"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/redis"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosisredis "github.com/hakanaltindag/svcdoctor/internal/diagnosis/redis"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// RedisParams describes one Redis or Valkey diagnostic run.
//
// **One parameter type for both implementations.** ADR 0066 section 6 freezes
// one adapter and one command, because every step of the frozen journey behaves
// identically on each. Which implementation answered is an observation the
// report carries, never an input that changes what svcdoctor does.
type RedisParams struct {
	// Host and Port are the logical endpoint the operator asked about.
	//
	// **This pair is the credential authority boundary**, and no resolved
	// address ever replaces it. One lookup producing five addresses produces
	// five connections that are all still this one authorized endpoint
	// (ADR 0028 section 2).
	Host string
	Port uint16

	// Username is the ACL user, or empty for the one-argument AUTH form.
	//
	// Empty is passed through as empty. `default` is never synthesized: the two
	// AUTH forms have different observable behaviour against a `nopass` user
	// (ADR 0064 section 5).
	Username string

	// Credential authenticates at the logical endpoint above.
	//
	// It may be zero. An endpoint that demands no authentication is never asked
	// for one, and a run that carries none still records why it did not
	// authenticate rather than leaving a graph indistinguishable from a
	// cancelled one.
	Credential security.Credential

	// Resolver and Dialer are the probes' seams, so a caller may run the whole
	// composition without a network. Required.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS is the transport-encryption plan. Nil means the run speaks plaintext.
	//
	// Redis negotiates no encryption in band — `tls-port` listens in addition to
	// `port` and there is no equivalent of SSLRequest — so this is ordinary
	// out-of-band transport TLS and the generic chain performs it, exactly as it
	// does for Kafka. Nothing infers TLS from the port or from a URI scheme
	// (ADR 0024).
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

func (p RedisParams) validate() error {
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
	}
	if !p.Credential.IsZero() {
		endpoint, err := p.endpoint()
		if err != nil {
			return err
		}
		if !p.Credential.Endpoint().Equal(endpoint) {
			// The composition root may not rebind a credential. It is checked
			// rather than promised, which is how ADR 0050 section 4's rule
			// became a test in the Kafka root and is why it is one here.
			return fmt.Errorf("%w: credential is bound to %s, not to %s",
				ErrInvalidInput, p.Credential.Endpoint(), endpoint)
		}
	}
	return nil
}

func (p RedisParams) endpoint() (security.Endpoint, error) {
	endpoint, err := security.NewEndpoint(p.Host, p.Port)
	if err != nil {
		return security.Endpoint{}, fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	return endpoint, nil
}

// DiagnoseRedis measures one Redis or Valkey endpoint and reports what it found.
//
// # It discovers broadly and authenticates narrowly
//
// Every resolved address is measured through DNS, TCP, TLS when the plan asks
// for it, and a zero-argument HELLO. All of that is credential-free, so
// measuring a second path costs the endpoint a connection and **not** an
// authentication attempt. Exactly one path then continues past the credential
// boundary.
//
// # Errors, and what is not one
//
// An error means the run could not be performed: unusable input, or an invariant
// failure such as a graph that rejected a node. **Every diagnostic outcome is a
// report**, including one where nothing connected, the credential was rejected,
// or the endpoint turned out to be a Sentinel.
func DiagnoseRedis(ctx context.Context, params RedisParams) (Result, error) {
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

	if err := measureRedis(ctx, builder, target, params); err != nil {
		return Result{}, err
	}

	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	// Redis has no session, so there is no "established" fact to short-circuit
	// incompleteness with. A PASS on the terminal probe is the nearest thing,
	// and it is deliberately **not** used that way: a run whose PING passed on
	// the selected path while another path's HELLO timed out locally really did
	// leave something unmeasured, and saying so is the honest answer.
	incomplete := incompleteRun(ctx, graph, false)

	// Each rule is wired in under a stable identity; see the note in
	// diagnosePostgres for why the identity is written here rather than
	// exported from the rule's own package.
	registry, err := diagnosis.NewRuleSet().
		// The generic failure boundary, wired first because it is the only rule
		// here that is about the shape of the whole graph rather than about one
		// stage. It restates measured states and infers nothing (ADR 0079).
		Add("diag/failure-boundary", diagnosis.FailureBoundary).
		Add("transport/dns", diagnosistransport.DNS).
		Add("transport/tcp", diagnosistransport.TCP).
		Add("transport/tls", diagnosistransport.TLS).
		Add("redis/hello", diagnosisredis.Hello).
		Add("redis/sentinel", diagnosisredis.Sentinel).
		Add("redis/authentication", diagnosisredis.Authentication).
		Add("redis/ping", diagnosisredis.Ping).
		Freeze()
	if err != nil {
		return Result{}, err
	}

	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph:      graph,
		Vantage:    params.Vantage,
		Incomplete: incomplete,
	})

	report, err := buildRedisReport(graph, outcome.Findings(), target, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	// A discarded rule makes the run incomplete; see diagnosePostgres.
	return Result{report: report, incomplete: incomplete || outcome.Failed()}, nil
}

// measureRedis performs every network stage and records what happened.
func measureRedis(
	ctx context.Context, builder *domain.GraphBuilder, target logicalTarget, params RedisParams,
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

	protocol, err := redis.Run(ctx, builder, sweep.Continuations(), redis.Params{
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("redis capability discovery: %w", err)
	}
	defer func() { _ = protocol.Close() }()

	return continueOneRedisPath(ctx, builder, protocol.Sessions(), params)
}

// continueOneRedisPath selects at most one path and takes it through the
// credential boundary.
//
// # At most one credential-bearing attempt, by construction
//
// This function calls redis.Authenticate at most once, with one session, and no
// loop, index or second candidate is in scope after the selection. An attempt
// that cannot be written cannot become a default (ADR 0064 section 4).
func continueOneRedisPath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	sessions []*redis.Session,
	params RedisParams,
) error {
	if len(sessions) == 0 {
		return nil
	}

	candidates := make([]candidate[*redis.Session], 0, len(sessions))
	for _, session := range sessions {
		candidates = append(candidates, candidate[*redis.Session]{
			address:      session.Address(),
			result:       session,
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

	// **The Sentinel guard, before the credential.**
	//
	// A Sentinel answers every command in the allowlist, so without this it
	// would complete the journey and report as a healthy data endpoint. The run
	// stops here: no AUTH, no PING, and therefore no credential presented to an
	// endpoint the operator did not mean to authenticate against. The finding
	// that says so is diagnosisredis.Sentinel's, from the mode this HELLO node
	// already carries. See ADR 0065 section 7.
	if selected.IsSentinel() {
		return nil
	}

	endpoint, err := params.endpoint()
	if err != nil {
		return err
	}

	// An endpoint that never demanded authentication and a run that carries no
	// credential need no authentication node: nothing was asked for and nothing
	// was withheld. Every other combination records one.
	if !selected.AuthRequired() && params.Credential.IsZero() {
		return redis.Ping(ctx, builder, selected, redis.Params{
			ExchangeTimeout: params.StepTimeout,
		})
	}

	if err := redis.Authenticate(ctx, builder, selected, redis.AuthParams{
		Endpoint:        endpoint,
		Credential:      params.Credential,
		Username:        params.Username,
		Policy:          params.TransportPolicy,
		ExchangeTimeout: params.StepTimeout,
	}); err != nil {
		return fmt.Errorf("authenticating at %s: %w", selected.Address(), err)
	}

	// The identity the first HELLO could not collect, now that the connection is
	// authenticated. Conditional, and the condition is proven rather than
	// assumed: `helloCommand` returns before it builds the reply map when the
	// connection is unauthenticated, so an endpoint that demanded a credential
	// has told svcdoctor nothing about itself yet.
	if selected.Authenticated() && selected.Hello().AuthRequired() {
		if err := redis.Identify(ctx, builder, selected, redis.Params{
			ExchangeTimeout: params.StepTimeout,
		}); err != nil {
			return fmt.Errorf("identifying %s: %w", selected.Address(), err)
		}
		// The second HELLO may have revealed a Sentinel that the first, refused,
		// HELLO could not. Stopping here still leaves the credential already
		// presented — which is unavoidable, because the endpoint would not say
		// what it was until it had been — and it stops PING from reporting a
		// Sentinel as a serving endpoint.
		if selected.IsSentinel() {
			return nil
		}
	}

	return redis.Ping(ctx, builder, selected, redis.Params{
		ExchangeTimeout: params.StepTimeout,
	})
}

// buildRedisReport assembles the canonical report.
func buildRedisReport(
	graph domain.Graph, findings []domain.Finding, target logicalTarget,
	params RedisParams, startedAt time.Time,
) (domain.Report, error) {
	service, err := domain.NewServiceID("redis")
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
