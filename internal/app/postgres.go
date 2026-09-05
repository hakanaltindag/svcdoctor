package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
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
// to, because svcdoctor's own execution limit ended it — a cancellation, the
// caller's deadline, or a per-step budget expiring.
//
// It is not a statement about the target, and it is orthogonal to the report's
// status. A run can be `PROBLEMS_FOUND` and complete, `OK` and incomplete, or
// either and neither: status answers *was a target-side ERROR condition
// diagnosed*, and this answers *did svcdoctor finish measuring*. The evidence
// that was collected is in the report and remains true; what is missing was
// never determined. docs/SCOPE.md maps this to exit code 4, and that mapping
// happens above this package.
//
// See incompleteRun for the exact predicate and why it is that one.
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
	// L0 input normalization, before validation, so that every later layer —
	// including the credential binding check inside validate — sees one canonical
	// spelling of the host. See normalizeHost and ADR 0059.
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

	// One value, two projections. The anchor's subject and the report's target
	// are both rendered from this and never from each other, which is what keeps
	// them from drifting. See logicalTarget.
	target := logicalTarget{host: params.Host, port: params.Port}

	established, err := measurePostgres(ctx, builder, target, params)
	if err != nil {
		return Result{}, err
	}

	// The graph is complete. Everything after this point is a pure
	// transformation of it, and nothing below performs I/O.
	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	// **One reconciliation, from one place.** See incompleteRun for the whole
	// definition. It is derived from the caller's context, from whether a
	// session was established, and from the states and failure classes on the
	// frozen graph — and from nothing else: not from findings, not from
	// severity, not from the report's status, not from how many paths were
	// found, and not from which one was selected.
	incomplete := incompleteRun(ctx, graph, established)

	// Generic transport rules first, then the service's, which is the order the
	// layers were measured in. **Wiring order does not reach the output** — the
	// engine returns findings in canonical order regardless (ADR 0017) — so this
	// is for a reader of the composition, not for the report.
	//
	// The generic rules are wired exactly like the service's: no wrapper, no
	// precedence, no pre-diagnosis special case. They are inert on a graph with no
	// requested-target anchor and cannot reach service-owned evidence, so nothing
	// arbitrates between the two sets (ADR 0043 sections 1 and 9).
	//
	// Each rule is wired in under a stable identity. The identity is written
	// here rather than exported from the rule's own package because this is the
	// only place that decides which rules run together, and duplicate detection
	// is a property of the set rather than of any rule in it (ADR 0080 section
	// 2.4). TestDIAG021EachCompositionRootWiresTheRulesItDeclares pins the list,
	// so a spelling cannot drift between the four roots that share the generic
	// transport rules.
	registry, err := diagnosis.NewRuleSet().
		// The generic failure boundary, wired first because it is the only rule
		// here that is about the shape of the whole graph rather than about one
		// stage. It restates measured states and infers nothing (ADR 0079).
		Add("diag/failure-boundary", diagnosis.FailureBoundary).
		Add("transport/dns", diagnosistransport.DNS).
		Add("transport/tcp", diagnosistransport.TCP).
		Add("postgres/ssl-request", diagnosispostgres.SSLRequest).
		Add("postgres/tls", diagnosispostgres.TLS).
		Add("postgres/startup", diagnosispostgres.Startup).
		Add("postgres/authentication", diagnosispostgres.Authentication).
		Add("postgres/session", diagnosispostgres.Session).
		// The one topology-shaped PostgreSQL rule, wired last because it is the
		// only one here that is about the whole address set rather than about
		// one address's own stage. It is inert on a target that resolved to a
		// single address, which is nearly every run (ADR 0085 section 2).
		Add("postgres/admission-scope", diagnosispostgres.AdmissionScope).
		Freeze()
	if err != nil {
		return Result{}, err
	}

	outcome := diagnosis.NewEngine(registry).Evaluate(diagnosis.RuleContext{
		Graph:      graph,
		Vantage:    params.Vantage,
		Incomplete: incomplete,
	})

	report, err := buildReport(graph, outcome.Findings(), target, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	// A rule whose output was discarded means svcdoctor did not finish its own
	// reasoning, which is what an incomplete run says and what exit 4 already
	// means. It is never a finding: a finding is a claim about the target, and
	// this is a claim about svcdoctor (ADR 0083 section 2.3).
	return Result{report: report, incomplete: incomplete || outcome.Failed()}, nil
}

// incompleteRun reports that svcdoctor's own execution limit stopped this run
// short of the outcome it set out to measure.
//
// # The definition
//
// A run is incomplete when the caller's context ended, **or** when no session
// was established and some step that was entered ended UNKNOWN because a local
// budget expired or the run was cancelled.
//
// # Why the caller's context alone was not enough
//
// It was the whole definition until Phase 4.11d, and it missed the case
// PostgresParams.StepTimeout exists to create. A per-step budget expiring leaves
// the caller's context untouched, so a run against an endpoint that never
// answered a SYN reported `findings: []`, `status: OK` and a complete run —
// measured. docs/SCOPE.md defines exit code 4 as cancellation **or local
// execution budget exhaustion**, and the per-step budget is the second of those.
//
// ADR 0043 section 6 withholds `TCP_CONNECTION_NOT_ESTABLISHED` on a sweep that
// did not prove every path fails, and rests that on `Result.Incomplete()` saying
// the run was cut short. This is what makes that premise true.
//
// # Why a passing session settles it, and nothing weaker
//
// A run that reached ReadyForQuery answered the question it was asked, and local
// uncertainty on a path it did not use does not unmake that: ADR 0041 measures
// every path deliberately and continues exactly one, so an unselected path is
// expected to end without a conclusion. Anything weaker than a passing session
// is not a substitute — a session node that is itself UNKNOWN because the read
// budget expired is precisely the case this must catch.
//
// # Why UNKNOWN and not SKIPPED
//
// UNKNOWN means a step was entered and could not be determined. A SKIPPED node
// carrying a local class means an address was never tried, which the transport
// chain records only after seeing the caller's context already done — so that
// case is covered by the first clause and counting it here would say nothing
// new.
//
// # What it must never depend on
//
// Not finding severity, not the report's status, not the number of paths, not
// which path was selected, and not any identifier's spelling: the predicate
// reads State and FailureClass through domain accessors and nothing else. A
// target-side failure at any layer, a rejected credential, an absent database, a
// credential withheld by policy and a run configured with no credential are all
// complete runs — each of them is an answer.
func incompleteRun(ctx context.Context, graph domain.Graph, established bool) bool {
	if ctx.Err() != nil {
		return true
	}
	if established {
		return false
	}
	for _, node := range graph.Nodes() {
		if node.State() != domain.StateUnknown {
			continue
		}
		switch node.FailureClass() {
		case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
			return true
		}
	}
	return false
}

// measurePostgres performs every network stage and records what happened.
//
// It reports whether the run could be performed, and whether it reached an
// established session. Whether it *finished* is reconciled once, by the caller —
// see incompleteRun.
func measurePostgres(
	ctx context.Context, builder *domain.GraphBuilder, target logicalTarget, params PostgresParams,
) (bool, error) {
	// The run records what it was asked about before it measures anything. This
	// is the only evidence this package creates, and it is created here — after
	// validation, before measurement — so that a cancelled run still carries the
	// target it was asked about alongside whatever it managed to measure.
	requested, err := recordRequestedTarget(builder, target, time.Now())
	if err != nil {
		return false, err
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
		return false, fmt.Errorf("transport discovery: %w", err)
	}
	// Whatever ownership was never transferred into a protocol stage is released
	// here, on every path out of this function. A connection nobody took is a
	// socket with no reader and no owner.
	defer func() { _ = sweep.Close() }()

	candidates, err := discover(ctx, builder, sweep.Continuations(), params)
	if err != nil {
		return false, err
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
		return false, nil
	}

	selected := candidates[chosen].result
	if ctx.Err() != nil {
		// The budget ended before the credentialed step. Nothing is attempted
		// and nothing is recorded: unattempted work is not a target failure.
		_ = selected.Close()
		return false, nil
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
			// The same budget every other stage receives. It was missing until
			// Phase 4.11d, and its absence was not visible here: the field did
			// not exist, so nothing looked wrong at this call site while the
			// step ran unbounded.
			ExchangeTimeout: params.StepTimeout,
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
//
// # What the bool means
//
// That a session was established: the run reached ReadyForQuery on this path.
// It is typed control flow rather than a second reading of the graph, and it is
// the one fact incompleteRun needs that the evidence states per node and not per
// run. Every non-passing outcome — a rejected credential, an absent database, an
// authentication svcdoctor could not perform, a read budget that expired — is
// false here and fully recorded as evidence, which stays the canonical account.
func continuePath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	selected *postgres.StartupResult,
	params PostgresParams,
) (bool, error) {
	// A run carrying no credential still enters the authentication step. It used
	// to return here, which left nothing in the graph and made a run against an
	// endpoint demanding SCRAM report itself healthy — and made that graph
	// indistinguishable from one cancelled at this exact point. The adapter now
	// records the condition as evidence, because that is where the fact is known
	// and where a producer may state it (ADR 0046).
	authenticated, err := postgres.Authenticate(
		ctx, builder, selected, params.Credential, postgres.AuthParams{
			TransportPolicy: params.TransportPolicy,
			ExchangeTimeout: params.StepTimeout,
		})
	if err != nil {
		return false, fmt.Errorf("authenticating: %w", err)
	}
	if authenticated == nil {
		// A recorded non-passing outcome, and the connection is already closed.
		// No session is established over an authentication that did not pass.
		return false, nil
	}

	// Terminal: the session step consumes the connection and closes it on every
	// outcome. A nil result is a recorded non-passing outcome, which is an answer
	// about the endpoint and not an incomplete run — unless the node itself says
	// a local budget ended it, which incompleteRun reads from the graph.
	session, err := postgres.EstablishSession(ctx, builder, authenticated, postgres.SessionParams{
		ReadTimeout: params.StepTimeout,
	})
	if err != nil {
		return false, fmt.Errorf("establishing session: %w", err)
	}
	return session != nil, nil
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
	// **Gated on the plan, not on the option alone.** TLSOptions configures the
	// handshake TLSRequired performs and is ignored under TLSDisabled, so a
	// plaintext run that was handed InsecureSkipVerify disabled no verification:
	// there was none to disable. Reporting true there would be a TLS fact about a
	// run that attempted no TLS, and a reader correcting for it would have to know
	// to cross-check the graph for a handshake node.
	//
	// The CLI now refuses that combination outright (ADR 0060), which makes this
	// unreachable from the command line. It is still asserted here, because
	// internal/app is its own boundary and a truthful report is its contract
	// rather than a consequence of who happened to call it. Kafka's
	// buildKafkaReport gates the identical boolean the identical way.
	insecure := params.TLS == postgres.TLSRequired && params.TLSOptions.InsecureSkipVerify
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
