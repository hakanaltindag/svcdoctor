package app

import (
	"context"
	"fmt"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosiskafka "github.com/hakanaltindag/svcdoctor/internal/diagnosis/kafka"
	diagnosistransport "github.com/hakanaltindag/svcdoctor/internal/diagnosis/transport"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// KafkaParams describes one Kafka diagnostic run.
//
// It is the sibling of PostgresParams and is deliberately shaped the same way:
// every field is something orchestration genuinely needs, and nothing here is a
// second copy of a value an adapter already owns.
type KafkaParams struct {
	// Host and Port are the bootstrap endpoint the operator asked about.
	//
	// **This pair is the credential authority boundary, and a Metadata response
	// cannot widen it.** A broker the cluster advertises is an endpoint the
	// operator never named, learned from peer-supplied data over a channel that
	// proves the identity of one broker and says nothing about cluster
	// membership. It receives credential-free DNS, TCP and TLS and nothing else.
	// See ADR 0050.
	Host string
	Port uint16

	// Mechanism is the SASL mechanism to ask the bootstrap broker about.
	//
	// It is required, and it is required because the Kafka protocol has no
	// "list your mechanisms" request: a client proposes one and the broker's
	// answer carries the list. A mechanism name is a protocol parameter drawn
	// from a public registry, like a TLS server name — naming one sends nothing
	// secret and costs the broker no authentication attempt (ADR 0026).
	Mechanism string

	// Credential authenticates at the logical bootstrap endpoint above.
	//
	// It may be zero. A run that carries none still reaches the authentication
	// step, which records EXEC_REQUIRED_INPUT_MISSING rather than leaving a
	// graph indistinguishable from one cancelled at that point (Phase 6.1c-P1).
	//
	// When it is non-zero it **must** be bound to Host:Port. validate refuses
	// anything else, which is how ADR 0050 section 4's "the composition root may
	// not rebind" becomes a check rather than a promise.
	Credential security.Credential

	// Resolver and Dialer are the probes' seams, so a caller may run the whole
	// composition without a network. Required.
	//
	// The advertised sweep receives the same two values, because svcdoctor must
	// resolve an advertised name the way a client would, from this vantage.
	Resolver dns.Resolver
	Dialer   tcp.Dialer

	// TLS is the transport-encryption plan. Nil means the run speaks plaintext
	// and stops after TCP on every path, bootstrap and advertised alike.
	//
	// Kafka negotiates no encryption in band, so this is ordinary out-of-band
	// transport TLS and the generic chain performs it. Nothing infers TLS from
	// the port, from the hostname or from convention: ADR 0011 refuses to infer
	// a service from a port and ADR 0024 refuses to infer TLS from one.
	TLS *transport.TLSOptions

	// TransportPolicy decides whether the credential may cross the channel the
	// selected bootstrap path established. The zero value requires verified TLS,
	// so a caller that never set it refuses rather than permits.
	TransportPolicy security.CredentialTransportPolicy

	// StepTimeout optionally bounds each individual probe call and each protocol
	// exchange. The caller's context bounds the run regardless, and whichever is
	// earlier wins.
	StepTimeout time.Duration

	// Vantage records where the probes ran from. Collecting it belongs to the
	// platform boundary, so it arrives as input rather than being read here.
	Vantage domain.Vantage

	// Version is svcdoctor's own version, recorded in the run metadata.
	Version string
}

func (p KafkaParams) validate() error {
	switch {
	case p.Host == "":
		return fmt.Errorf("%w: host must not be empty", ErrInvalidInput)
	case p.Port == 0:
		return fmt.Errorf("%w: port must not be zero", ErrInvalidInput)
	case p.Mechanism == "":
		return fmt.Errorf("%w: mechanism must not be empty", ErrInvalidInput)
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
	return p.validateCredentialBinding()
}

// validateCredentialBinding refuses a credential bound anywhere but the logical
// endpoint this run was asked about.
//
// # Why the composition root checks this, when the adapter already does
//
// `kafka.Authenticate` calls `credential.SecretFor(endpoint)` with the endpoint
// derived from the session, and a mismatch there is already an error rather than
// evidence. That check is the last line and it works. This one is the first, and
// it exists because ADR 0050 section 4 names *this* layer as the only one that
// could rebind: `security.NewCredential` is unrestricted by design, so a
// credential naming a resolved address, an advertised broker or an unrelated
// host is constructible and would travel all the way to the wire boundary before
// anything refused it.
//
// Refusing at the door means a mis-bound credential costs the target zero
// connections and zero authentication attempts, and it means the invariant is
// stated where the ADR states it.
//
// **It is an input defect, not a diagnostic result.** It comes back as
// ErrInvalidInput and never as evidence: an evidence node saying "the wrong
// credential was offered" would be svcdoctor reporting on its own caller
// (ADR 0028 section 2).
func (p KafkaParams) validateCredentialBinding() error {
	if p.Credential.IsZero() {
		return nil
	}
	endpoint, err := security.NewEndpoint(p.Host, p.Port)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidInput, err)
	}
	if !p.Credential.Endpoint().Equal(endpoint) {
		return fmt.Errorf(
			"%w: the credential is bound to a different endpoint than the run's target",
			ErrInvalidInput)
	}
	return nil
}

// DiagnoseKafka measures one Kafka bootstrap endpoint and the topology it
// advertises, and reports what it found.
//
// # The journey
//
//	target.requested
//	  └── dns.lookup
//	        ├── tcp.connect [addr A] ── tls.handshake        every resolved address
//	        └── tcp.connect [addr B] ── tls.handshake
//	                 │
//	                 ├── kafka.api_versions                  every completed path
//	                 └── kafka.sasl_handshake                every completed path
//	  ------------------- credential boundary -------------------
//	                       └── kafka.sasl_authenticate       at most ONE path
//	                             └── kafka.metadata
//	                                   └── kafka.broker_advertised   × N
//	                                         └── dns.lookup          credential-free
//	                                               └── tcp.connect
//	                                                     └── tls.handshake
//
// # It discovers broadly and authenticates narrowly
//
// Every resolved address is measured through DNS, TCP, TLS, ApiVersions and the
// SASL handshake. All of that is credential-free, and the handshake is
// credential-free as a property of the Kafka protocol rather than as a promise:
// a SaslHandshake request carries a mechanism name and nothing else — no
// identity, no password, no token. So measuring a second path costs the broker a
// connection and **not** an authentication attempt, which is what makes per-path
// divergence observable before any secret exists in the run.
//
// Then exactly one path continues. See selectBootstrapPath and ADR 0028.
//
// # Discovery may create evidence; discovery must not create secret authority
//
// Metadata PASS permits topology *measurement*. It authorizes nothing. The
// advertised sweep is `kafka.MeasureAdvertised`, whose parameters cannot hold a
// credential, a secret, an identity, a mechanism or an authenticated session,
// and which sends no Kafka byte to any endpoint it measures. A broker that
// advertises `attacker.example:9093` therefore receives DNS, TCP and TLS and
// nothing else, whatever certificate it presents — TLS proves endpoint identity,
// never cluster membership. See ADR 0050.
//
// # What Metadata PASS proves
//
// That an authenticated, authorized Kafka API call succeeded against **the one
// broker that answered**. Not that the cluster is reachable, usable or healthy,
// and not that any advertised broker is any of those. ADR 0052 fixes the
// vocabulary the renderer will use for it.
//
// # Errors, and what is not one
//
// An error means the run could not be performed: unusable input, a credential
// bound to a different endpoint, or an invariant failure such as a graph that
// rejected a node. **Every diagnostic outcome is a report** — a refused
// endpoint, a mechanism svcdoctor cannot perform, a run holding no credential, a
// credential the policy withheld, a credential the broker rejected, a Metadata
// exchange that broke and an unreachable advertised broker are all facts about
// the target, and a caller that received an error instead of a report would have
// lost them.
func DiagnoseKafka(ctx context.Context, params KafkaParams) (Result, error) {
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

	// One value, two projections: the anchor's subject and the report's target
	// are both rendered from this and never from each other. See logicalTarget.
	target := logicalTarget{host: params.Host, port: params.Port}

	if err := measureKafka(ctx, builder, target, params); err != nil {
		return Result{}, err
	}

	// The graph is complete. Everything after this point is a pure
	// transformation of it, and nothing below performs I/O.
	graph, err := builder.Freeze()
	if err != nil {
		return Result{}, fmt.Errorf("freezing the evidence graph: %w", err)
	}

	// **One reconciliation, from one place**, and it is Kafka's own predicate
	// rather than PostgreSQL's. Kafka has no single terminal fact that settles
	// completeness, because advertised reachability is half of what the command
	// promised to measure. See incompleteKafkaRun and ADR 0051.
	incomplete := incompleteKafkaRun(ctx, graph)

	// Generic transport rules first, then the service's, which is the order the
	// layers were measured in. **Wiring order does not reach the output** — the
	// engine returns findings in canonical order regardless (ADR 0017) — so this
	// is for a reader of the composition, not for the report.
	//
	// The three generic rules are inert on evidence they do not own: each
	// descends from the requested-target anchor by direct parentage, so the
	// advertised sweeps — which hang off `kafka.broker_advertised` — are
	// unreachable from them and stay owned by the Kafka rule that claims them
	// outright. Nothing arbitrates between the two sets, and the engine
	// deduplicates nothing (ADR 0043 section 9, ADR 0053 section 8).
	findings := diagnosis.NewEngine(
		diagnosistransport.DNS,
		diagnosistransport.TCP,
		diagnosistransport.TLS,
		diagnosiskafka.Protocol,
		diagnosiskafka.AdvertisedEndpointUnreachable,
		diagnosiskafka.UnusableAdvertisement,
	).Diagnose(graph)

	report, err := buildKafkaReport(graph, findings, target, params, startedAt)
	if err != nil {
		return Result{}, err
	}
	return Result{report: report, incomplete: incomplete}, nil
}

// measureKafka performs every network stage and records what happened.
//
// It returns only an error, deliberately. Whether the run reached Metadata is a
// fact the graph already states on one node, and a bool carried up beside it
// would be a second representation of it — free to drift, and tempting to
// consume instead of the evidence. ADR 0051's predicate reads the node.
func measureKafka(
	ctx context.Context, builder *domain.GraphBuilder, target logicalTarget, params KafkaParams,
) error {
	// The run records what it was asked about before it measures anything. This
	// is the only evidence this package creates, and it is created here — after
	// validation, before measurement — so that a cancelled run still carries the
	// target it was asked about alongside whatever it managed to measure.
	requested, err := recordRequestedTarget(builder, target, time.Now())
	if err != nil {
		return err
	}

	// DNS, TCP and — when the plan asks for it — TLS, for every resolved
	// address. Unlike PostgreSQL, TLS **is** requested from the chain: Kafka
	// negotiates no encryption in band, so the handshake is ordinary transport
	// work and belongs to the layer that owns transport (ADR 0053).
	//
	// **Parent declares the sweep's cause**, and the chain records the edge. A
	// sweep the operator asked for hangs off the requested-target anchor, which
	// is what lets the three generic rules identify it without provenance, an
	// identifier parse or a service switch (ADR 0042 sections 7 and 9).
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
	// Whatever ownership was never transferred into a protocol stage is released
	// here, on every path out of this function.
	defer func() { _ = sweep.Close() }()

	// **The chain hands back only paths that completed everything the plan
	// asked for.** With a TLS plan that means the handshake produced a
	// connection, so a path whose TLS failed, or whose TLS ended UNKNOWN because
	// a local budget expired, is structurally absent here rather than filtered
	// out below. Its evidence is in the graph and the generic TLS rule owns it.
	if len(sweep.Continuations()) == 0 {
		return nil
	}

	protocol, err := kafka.Run(ctx, builder, sweep.Continuations(), kafka.Params{
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("kafka capability discovery: %w", err)
	}
	defer func() { _ = protocol.Close() }()
	if len(protocol.Sessions()) == 0 {
		return nil
	}

	// A mechanism name is not a credential, so every path is asked. The answer
	// is what makes "this listener offers PLAIN and that one does not" visible,
	// and it costs the broker nothing that a log would record as an
	// authentication attempt.
	handshake, err := kafka.SASLHandshake(ctx, builder, protocol.Sessions(), kafka.SASLParams{
		Mechanism:       params.Mechanism,
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("kafka mechanism discovery: %w", err)
	}
	defer func() { _ = handshake.Close() }()

	return continueOneBootstrapPath(ctx, builder, handshake.Sessions(), params)
}

// continueOneBootstrapPath selects at most one path and takes it through the
// credential boundary.
//
// # At most one credential-bearing attempt, by construction
//
// This function calls kafka.Authenticate at most once, with one session, and no
// loop, index or second candidate is in scope after the selection. That is the
// same shape ADR 0028 chose for the adapter, for the same reason: an attempt
// that cannot be written cannot become a default.
//
// # No retry and no fallback
//
// A refused, rejected or unattempted authentication ends the credentialed part
// of the run. svcdoctor does not try the next address, does not try another
// mechanism, does not downgrade the channel and does not present the credential
// again. **A credential-bearing retry is not an L2 or L3 transport retry**: it
// spends a second attempt against whatever counts them, and in a
// directory-backed deployment it is a second step towards lockout. Adding one
// would need its own security decision (ADR 0028).
func continueOneBootstrapPath(
	ctx context.Context,
	builder *domain.GraphBuilder,
	sessions []*kafka.HandshakeSession,
	params KafkaParams,
) error {
	candidates := make([]candidate[*kafka.HandshakeSession], 0, len(sessions))
	for _, session := range sessions {
		candidates = append(candidates, candidate[*kafka.HandshakeSession]{
			address: session.Address(),
			result:  session,
		})
	}

	chosen := selectBootstrapPath(candidates)
	// Every path that will not continue is closed now, deliberately. This is
	// application ownership policy and not a protocol requirement: nothing
	// obliges a client to close an idle socket promptly, and nothing is left to
	// the collector (ADR 0021, ADR 0041 section 11). The HandshakeResult's own
	// Close is still deferred above as a backstop, and both are idempotent.
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
		// and nothing is recorded: unattempted work is not a target failure, and
		// a SKIPPED node here would be indistinguishable from a run that had no
		// credential to present. That the run ended early is read from the
		// context once, by incompleteKafkaRun.
		_ = selected.Close()
		return nil
	}

	// The one call in this repository that can present a Kafka credential.
	//
	// Everything that decides whether a byte derived from the secret is written
	// happens inside it, in a fixed order that is the security contract: the
	// mechanism guard, then whether the run holds a credential at all, then the
	// channel policy, then the endpoint binding, then SecretFor, then the wire
	// package's single Reveal. Each is a precondition for the next, and the
	// first four each record their own truthful node and return normally
	// (ADR 0030, Phase 6.1a, Phase 6.1c-P1).
	//
	// Composition supplies the policy and does not second-guess it. There is no
	// Kafka bypass and no "the operator supplied a credential, so sending it is
	// fine" branch: the channel remains authoritative.
	auth, err := kafka.Authenticate(ctx, builder, selected, params.Credential, kafka.AuthParams{
		TransportPolicy: params.TransportPolicy,
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}
	// Authenticate consumes the session in every outcome, including the ones
	// that send nothing, so this releases only a connection it kept.
	defer func() { _ = auth.Close() }()

	session, ok := auth.Session()
	if !ok {
		// A recorded non-passing outcome, and the connection is already closed.
		// Nothing continues over an authentication that did not pass.
		return nil
	}

	return describeTopology(ctx, builder, session, params)
}

// describeTopology asks the authenticated broker what the cluster looks like,
// and then measures the transport of what it named.
//
// # Metadata is a question, not a grant
//
// It reads the cluster's description and changes no protocol state, so the
// connection it consumes is exactly as usable afterwards. What it produces is
// evidence: one exchange node, and one advertisement node per broker the
// response carried. Those nodes authorize nothing.
func describeTopology(
	ctx context.Context,
	builder *domain.GraphBuilder,
	session *kafka.AuthenticatedSession,
	params KafkaParams,
) error {
	topology, err := kafka.Metadata(ctx, builder, session, kafka.MetadataParams{
		ExchangeTimeout: params.StepTimeout,
	})
	if err != nil {
		return fmt.Errorf("describing the cluster: %w", err)
	}
	defer func() { _ = topology.Close() }()

	// **Metadata PASS is the transition that permits topology measurement**, and
	// it is read from the adapter's own typed answer rather than from the graph:
	// a still-usable session is handed back only when the exchange completed,
	// which is exactly when the exchange node is PASS and exactly when
	// advertisements were recorded (ADR 0051 section 15).
	//
	// An exchange that broke leaves no advertisement to measure, and measuring
	// nothing would still be wrong to attempt: the sweep exists to answer a
	// question about a topology this run never learned.
	if _, obtained := topology.Session(); !obtained {
		return nil
	}

	// Credential-free DNS, TCP and TLS for every advertised endpoint, and
	// nothing else. No ApiVersions, no SaslHandshake, no SaslAuthenticate and no
	// second Metadata is sent to a discovered broker.
	//
	// The guarantee is structural rather than promised: this call's parameters
	// are a graph builder, a list of advertisements and a transport plan, and
	// none of them can hold a credential, a secret, an identity, a mechanism or
	// a session. There is no parameter for a credential to occupy. See ADR 0050.
	//
	// It closes every connection it opens and returns no continuation, so the
	// sweep leaks nothing and nothing downstream can reuse an advertised socket.
	if _, err := kafka.MeasureAdvertised(ctx, builder, topology.Brokers(), kafka.TransportPlan{
		Resolver:    params.Resolver,
		Dialer:      params.Dialer,
		TLS:         advertisedTLSPlan(params.TLS),
		StepTimeout: params.StepTimeout,
	}); err != nil {
		return fmt.Errorf("measuring advertised endpoints: %w", err)
	}
	return nil
}

// advertisedTLSPlan derives the advertised sweep's TLS plan from the run's.
//
// # It is the same plan, and that is the point
//
// TLS is attempted for an advertised endpoint if and only if it was attempted
// for the bootstrap endpoint, with the same trust source, the same version
// bounds and the same verification mode. Nothing is inferred from the advertised
// port, the advertised hostname or Kafka convention: a Metadata response does
// not say whether a listener is PLAINTEXT, SSL, SASL_PLAINTEXT or SASL_SSL, and
// every available shortcut is a guess dressed as a fact (ADR 0033).
//
// # One field is deliberately not inherited, and it is an identity
//
// `ServerName` is an override that names **one** endpoint. When an operator sets
// it, they are saying which identity the certificate at the *bootstrap* endpoint
// must carry. Copying that name onto every advertised sweep would verify
// broker-2's certificate against the bootstrap's name and report an identity
// mismatch that no client would ever see — managed Kafka routinely serves a
// distinct certificate per broker endpoint.
//
// Clearing it restores the chain's default, which is to verify against the
// advertised hostname: the identity a real client checks when it connects there.
// So the sweep verifies harder, not less — each endpoint against its own name
// rather than all of them against one.
//
// This is the same reasoning ADR 0050 applies to a credential, one layer down: a
// value authorized for the endpoint the operator named does not travel to an
// endpoint a peer named. `RootCAs`, the version bounds and `InsecureSkipVerify`
// are run-wide trust configuration rather than endpoint identity, so they do
// travel — and `InsecureSkipVerify` is recorded on the report either way.
//
// The copy is a value copy, so the caller's options are never mutated.
func advertisedTLSPlan(options *transport.TLSOptions) *transport.TLSOptions {
	if options == nil {
		return nil
	}
	plan := *options
	plan.ServerName = ""
	return &plan
}

// selectBootstrapPath returns the index of the path that receives the run's one
// authentication attempt, or -1 when there is nothing to continue.
//
// # Why there is no class partition here
//
// PostgreSQL's selector partitions candidates by whether the endpoint demanded
// authentication, because a PostgreSQL path reaches startup whether or not it
// does. **A Kafka candidate cannot be in the other class.** The only way to hold
// a `HandshakeSession` is for the broker to have accepted the named mechanism,
// and a listener with no SASL rejects the handshake and produces no session at
// all. Partitioning by a property every candidate shares would be a branch that
// never runs, and a reader would reasonably conclude the other class means
// something.
//
// # Canonical order is a tie-break, and that distinction is the decision
//
// By the time this runs, **every** candidate has been measured through DNS, TCP,
// TLS, ApiVersions and the SASL handshake, and whatever distinguishes them — a
// different API range, a listener that offers a different mechanism, a broker
// mid-upgrade — is already recorded as evidence. Canonical order decides only
// which of several already-measured, already-comparable paths receives the one
// credential a run is allowed to present.
//
// So the ordering is deterministic tie-breaking, not a statement that IPv4 is
// preferred, healthier, faster or primary. ADR 0024 removed exactly this
// ordering from the *transport chain*, where it would have been an invisible
// address-family preference among paths nothing had compared yet; ADR 0041
// section 9 carries the full contrast.
//
// # What it must not depend on
//
// Not the order the paths were discovered in, not map iteration, not goroutine
// completion, not latency, not which handshake completed first, and not the
// resolver's ordering — which is unavailable anyway, because the DNS probe sorts
// canonically before anything downstream sees an address.
//
// The function is pure and total: same input set, same answer, every time,
// whatever order the slice arrives in.
func selectBootstrapPath[T any](candidates []candidate[T]) int {
	return canonicalMinimum(candidates, func(candidate[T]) bool { return true })
}

// buildKafkaReport assembles the canonical LOCAL_FULL report.
//
// **It never constructs a shareable one.** domain.NewReportSecurity refuses
// OutputModeShareableRedacted outright, and internal/security/redaction is the
// only thing that may produce it — from a finished local report, at the output
// boundary, after diagnosis has run on truthful evidence (ADR 0018).
func buildKafkaReport(
	graph domain.Graph, findings []domain.Finding, target logicalTarget,
	params KafkaParams, startedAt time.Time,
) (domain.Report, error) {
	service, err := domain.NewServiceID("kafka")
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
	// The insecure flag describes the run, and the run is one plan: the
	// advertised sweep inherits InsecureSkipVerify from the same options, so one
	// recorded boolean is true of every handshake this run performed.
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
