package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// ErrInvalidInput reports that a run was asked for with something it cannot use.
//
// It is the only error class this package defines, and it separates the two
// kinds of failure the way every layer below already does: unusable input is a
// defect in the caller and comes back as an error; a refused connection, a
// rejected credential or an absent database is a fact about the target and comes
// back as evidence in the report.
var ErrInvalidInput = errors.New("invalid run input")

// PostgresParams describes one PostgreSQL diagnostic run.
//
// It is a parameter object rather than a config bag: every field is something
// orchestration genuinely needs, and nothing here is a second copy of a value an
// adapter already owns.
type PostgresParams struct {
	// Host and Port are the logical endpoint the operator asked about.
	//
	// **This pair is the credential authority boundary**, and no resolved
	// address ever replaces it. One lookup producing five addresses produces
	// five connections that are all still this one authorized endpoint; a
	// credential bound to a concrete address does not authorize this endpoint
	// even when the name resolves to it, because resolution is a runtime fact
	// that changes, differs per vantage and can be attacker-influenced
	// (ADR 0028 section 2).
	Host string
	Port uint16

	// Role and Database are the identities the StartupMessage declares.
	Role     string
	Database string

	// Credential authenticates Role at the logical endpoint above.
	//
	// It may be zero. A server that demands no authentication never asks for
	// one, and a run that has none simply does not reach the credentialed step
	// — see DiagnosePostgres.
	Credential security.Credential

	// Resolver and Dialer are the probes' seams, so a caller may run the whole
	// composition without a network. Required.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS and TLSOptions are the transport-encryption plan for the in-band
	// PostgreSQL negotiation. The zero TLSPlan requires TLS.
	TLS        postgres.TLSPlan
	TLSOptions postgres.TLSOptions

	// TransportPolicy decides whether the credential may cross the channel a
	// path established. The zero value requires verified TLS, so a caller that
	// never set it refuses rather than permits.
	TransportPolicy security.CredentialTransportPolicy

	// StepTimeout optionally bounds each individual exchange. The caller's
	// context bounds the run regardless, and whichever is earlier wins.
	StepTimeout time.Duration

	// Vantage records where the probes ran from. Collecting it belongs to the
	// platform boundary, so it arrives as input rather than being read here.
	Vantage domain.Vantage

	// Version is svcdoctor's own version, recorded in the run metadata.
	Version string
}

func (p PostgresParams) validate() error {
	switch {
	case p.Host == "":
		return fmt.Errorf("%w: host must not be empty", ErrInvalidInput)
	case p.Port == 0:
		return fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	case p.Role == "":
		return fmt.Errorf("%w: role must not be empty", ErrInvalidInput)
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
	return nil
}

// Result is what one run produced.
//
// Two values, because the product boundary needs exactly two things: what was
// concluded, and whether the run got to conclude it. **No exit code lives here**
// — mapping a report to a process status is defined in docs/SCOPE.md and belongs
// to the CLI (ADR 0014 keeps the same separation on findings).
type Result struct {
	report     domain.Report
	incomplete bool
}

// Report returns the canonical LOCAL_FULL report.
func (r Result) Report() domain.Report { return r.report }

// Incomplete reports that the run stopped before measuring everything it set out
// to, because the caller's context ended — a cancellation or an exhausted
// execution budget.
//
// It is not a statement about the target. The evidence that was collected is in
// the report and remains true; what is missing was never attempted. docs/SCOPE.md
// maps this to exit code 4, and that mapping happens above this package.
func (r Result) Incomplete() bool { return r.incomplete }

// DiagnosePostgres measures one PostgreSQL endpoint and reports what it found.
//
// # It discovers broadly and authenticates narrowly
//
// Every resolved address is measured through DNS, TCP, the in-band SSLRequest
// negotiation, TLS and the StartupMessage. All of that is credential-free: the
// startup exchange discloses the role, because the protocol has no anonymous
// startup, and presents no secret and no proof. So measuring a second path costs
// the target a connection and **not** an authentication attempt.
//
// That is what makes per-path divergence observable before any credential is
// presented. `pg_hba.conf` selects behaviour by source address, so one family may
// be offered SCRAM while another is refused outright — and the refusal lands on
// that path's startup node as `28000`, with no authentication node at all.
//
// Then exactly one path continues. See ADR 0041 sections 5 through 9.
//
// # Errors, and what is not one
//
// An error means the run could not be performed: unusable input, or an invariant
// failure such as a graph that rejected a node. **Every diagnostic outcome is a
// report**, including one where nothing connected — a refused endpoint, a
// rejected credential and an absent database are facts about the target, and a
// caller that received an error instead of a report would have lost them.
func DiagnosePostgres(ctx context.Context, params PostgresParams) (Result, error) {
	if ctx == nil {
		return Result{}, fmt.Errorf("%w: context must not be nil", ErrInvalidInput)
	}
	if err := params.validate(); err != nil {
		return Result{}, err
	}

	startedAt := time.Now()
	builder := domain.NewGraphBuilder()

	// One value, two projections. The anchor's subject and the report's target
	// are both rendered from this and never from each other, which is what keeps
	// them from drifting. See logicalTarget.
	target := logicalTarget{host: params.Host, port: params.Port}

	if err := measurePostgres(ctx, builder, target, params); err != nil {
		return Result{}, err
	}

	// **One reconciliation, from one source.** A run is incomplete exactly when
	// the caller's context ended before the work did — a cancellation or an
	// exhausted budget — whether that happened between paths, before the
	// credentialed step, or inside Negotiate, Startup, Authenticate or
	// EstablishSession. Reading it once here catches all of them, where
	// assignments scattered through the stages would each have to remember to.
	//
	// It is derived from nothing else: not from findings, not from severity, not
	// from the report's status, not from how many paths were found, and not from
	// which one was selected.
	incomplete := ctx.Err() != nil

	// The graph is complete. Everything after this point is a pure
	// transformation of it, and nothing below performs I/O.
	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	findings := diagnosis.NewEngine(
		diagnosispostgres.SSLRequest,
		diagnosispostgres.Startup,
		diagnosispostgres.Authentication,
		diagnosispostgres.Session,
	).Diagnose(graph)

	report, err := buildReport(graph, findings, target, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	return Result{report: report, incomplete: incomplete}, nil
}

// measurePostgres performs every network stage and records what happened.
//
// It reports only whether the run could be performed. Whether it *finished* is
// read from the context once, by the caller — see DiagnosePostgres.
func measurePostgres(
	ctx context.Context, builder *domain.GraphBuilder, target logicalTarget, params PostgresParams,
) error {
	// The run records what it was asked about before it measures anything. This
	// is the only evidence this package creates, and it is created here — after
	// validation, before measurement — so that a cancelled run still carries the
	// target it was asked about alongside whatever it managed to measure.
	requested, err := recordRequestedTarget(builder, target, time.Now())
	if err != nil {
		return err
	}

	// DNS and TCP for every resolved address. TLS is deliberately **not**
	// requested from the chain: PostgreSQL negotiates encryption in band, so the
	// handshake belongs after SSLRequest and internal/adapter/postgres performs
	// it on the same socket.
	//
	// **Parent declares the sweep's cause**, and the chain records the edge. A
	// sweep the operator asked for hangs off the requested-target anchor; a sweep
	// a service caused hangs off the service evidence that caused it. That
	// declaration is what lets a future generic rule tell the two apart without
	// provenance, an identifier parse or a service switch (ADR 0042 sections 7
	// and 9).
	sweep, err := transport.Run(ctx, builder, transport.Params{
		Host:        params.Host,
		Port:        params.Port,
		Resolver:    params.Resolver,
		Dialer:      params.Dialer,
		StepTimeout: params.StepTimeout,
		Parent:      requested,
	})
	if err != nil {
		return fmt.Errorf("transport discovery: %w", err)
	}
	// Whatever ownership was never transferred into a protocol stage is released
	// here, on every path out of this function. A connection nobody took is a
	// socket with no reader and no owner.
	defer func() { _ = sweep.Close() }()

	candidates, err := discover(ctx, builder, sweep.Continuations(), params)
	if err != nil {
		return err
	}

	// A run that carries a credential prefers a path on which that credential
	// can be exercised; one that carries none prefers a path it can carry to
	// ReadyForQuery. See selectPath.
	chosen := selectPath(candidates, !params.Credential.IsZero())
	// Every path that will not continue is closed now, deliberately. This is
	// application ownership policy and not a protocol requirement: nothing
	// obliges a client to close an idle socket promptly, and nothing is left to
	// the collector (ADR 0021, ADR 0041 section 11).
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
		_ = selected.Close()
		return nil
	}

	return continuePath(ctx, builder, selected, params)
}

// discover runs the credential-free stages on every completed transport path.
//
// **It does not stop at the first success.** Measuring the others is what makes a
// per-path difference visible, and it is free of credential cost.
func discover(
	ctx context.Context,
	builder *domain.GraphBuilder,
	paths []*transport.Continuation,
	params PostgresParams,
) ([]candidate[*postgres.StartupResult], error) {
	var candidates []candidate[*postgres.StartupResult]

	for _, path := range paths {
		if ctx.Err() != nil {
			// Stop starting new work. The paths not reached are simply not
			// measured; no node is minted for them, because a node would claim
			// an observation nobody made. That the run ended early is read from
			// the context once, at the end, rather than carried up from here.
			return candidates, nil
		}

		address := path.Address()

		session, err := postgres.Negotiate(ctx, builder, path, postgres.Params{
			TLS:         params.TLS,
			TLSOptions:  params.TLSOptions,
			StepTimeout: params.StepTimeout,
		})
		if err != nil {
			return nil, fmt.Errorf("negotiating %s: %w", address, err)
		}

		result, err := postgres.Startup(ctx, builder, session, postgres.StartupParams{
			User:     params.Role,
			Database: params.Database,
		})
		// A negotiation that left nothing usable, and a startup that failed,
		// both recorded their evidence and closed what they held. Closing the
		// session again is a no-op once its connection was taken.
		_ = session.Close()
		if err != nil {
			return nil, fmt.Errorf("starting up on %s: %w", address, err)
		}
		if result == nil {
			// A recorded non-passing outcome. The path keeps its evidence and
			// is not a candidate to continue.
			continue
		}

		candidates = append(candidates, candidate[*postgres.StartupResult]{
			address: address,
			result:  result,
			// The adapter's own normalized answer. "ok" is an endpoint stating
			// it wants no authentication at all; anything else is a demand.
			authRequired: result.AuthMethod() != authMethodNone,
		})
	}

	return candidates, nil
}

// continuePath takes the one selected path through the credential boundary.
//
// # At most one credential-bearing attempt, by construction
//
// This function is called once per run, with one path, and calls Authenticate
// once. There is no loop, no index and no second candidate in scope — the same
// shape ADR 0028 chose for the adapter, for the same reason: an attempt that
// cannot be written cannot become a default.
//
// # No retry and no fallback
//
// A failed authentication ends the credentialed part of the run. svcdoctor does
// not try the next address, does not try another mechanism, does not downgrade
// the channel and does not present the credential again. A fallback would spend
// a second attempt against whatever counts them, and would obscure the peer's
// clearest assertion — which is the reason ADR 0036 section 4 refused to
// reproduce `sslmode=prefer`.
func continuePath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	selected *postgres.StartupResult,
	params PostgresParams,
) error {
	// A server that demands authentication when the run carries no credential is
	// not asked for one. Nothing is presented, so nothing is recorded, and the
	// startup node's own postgres.auth_method already says what was wanted.
	if params.Credential.IsZero() && selected.AuthMethod() != authMethodNone {
		_ = selected.Close()
		return nil
	}

	authenticated, err := postgres.Authenticate(
		ctx, builder, selected, params.Credential, postgres.AuthParams{
			TransportPolicy: params.TransportPolicy,
			ExchangeTimeout: params.StepTimeout,
		})
	if err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}
	if authenticated == nil {
		// A recorded non-passing outcome, and the connection is already closed.
		// No session is established over an authentication that did not pass.
		return nil
	}

	// Terminal: the session step consumes the connection and closes it on every
	// outcome, and returns none.
	if _, err := postgres.EstablishSession(ctx, builder, authenticated, postgres.SessionParams{
		ReadTimeout: params.StepTimeout,
	}); err != nil {
		return fmt.Errorf("establishing session: %w", err)
	}
	return nil
}

// authMethodNone is the normalized name for an endpoint that demands no
// authentication. A path like that is continued without a credential being
// presented, and no credential is ever sent to one for uniformity.
const authMethodNone = "ok"

// buildReport assembles the canonical LOCAL_FULL report.
//
// **It never constructs a shareable one.** domain.NewReportSecurity refuses
// OutputModeShareableRedacted outright, and internal/security/redaction is the
// only thing that may produce it — from a finished local report, at the output
// boundary, after diagnosis has run on truthful evidence (ADR 0018).
func buildReport(
	graph domain.Graph, findings []domain.Finding, target logicalTarget,
	params PostgresParams, startedAt time.Time,
) (domain.Report, error) {
	service, err := domain.NewServiceID("postgres")
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
	reportSecurity, err := domain.NewReportSecurity(
		domain.OutputModeLocalFull, params.TLSOptions.InsecureSkipVerify, false)
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
