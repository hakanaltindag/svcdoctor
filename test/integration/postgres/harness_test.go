//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/diagnosis"
	diagnosispostgres "github.com/hakanaltindag/svcdoctor/internal/diagnosis/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
)

// The Phase 4.8a test composition boundary.
//
// # This is a test harness, not svcdoctor's architecture
//
// It sequences production stages and owns nothing else. **No production
// composition root exists**, deliberately: `internal/app` and `cmd/svcdoctor`
// are empty, and the decisions an orchestrator needs — which path is
// authenticated and why, whether more than one ever is, where the whole-run
// budget lives, whether a run emits a shareable report — are deferred to
// ADR 0041. ADR 0028 §1 says so in as many words: *"Today the only caller is a
// test; when application orchestration exists it selects and records why."*
//
// So this file is that test caller. Nothing here may be promoted to production
// by copying: it makes fixture-local assumptions a real run cannot make.
//
// # What it drives
//
//	transport.Run              real resolver, real dialer, DNS + TCP
//	  -> postgres.Negotiate    real SSLRequest, real TLS handshake
//	  -> postgres.Startup      real StartupMessage
//	  -> postgres.Authenticate real SCRAM-SHA-256
//	  -> postgres.EstablishSession
//	  -> builder.Freeze()      the real graph, no hand-authored node
//	  -> diagnosis rules       the real rules, unmodified
//	  -> domain.NewReport      the real report
//
// Redaction is applied by the tests that need it, after the report exists —
// never before diagnosis, which must run on truthful internal evidence.

// requireSingleContinuation returns the one completed transport path, and fails
// loudly on any other count.
//
// **This is a fixture precondition, not svcdoctor's production path-selection
// policy.** The validation server is reached over a loopback name that resolves
// to exactly one address, so "which path" is not a question here — and asserting
// that, rather than indexing, is what keeps it from silently becoming one.
//
// ADR 0024 §3 removed "the first path in canonical address order" from the
// transport chain precisely because it was an invisible IPv4 preference nobody
// chose. Writing `paths[0]` here would reintroduce it one layer up. Production
// selection remains deferred to ADR 0041.
func requireSingleContinuation(t *testing.T, result *transport.Result) *transport.Continuation {
	t.Helper()

	paths := result.Continuations()
	switch len(paths) {
	case 0:
		t.Skip("no TCP path reached the validation server; is it running?")
	case 1:
	default:
		t.Fatalf("the fixture produced %d transport paths; this harness has no basis for "+
			"choosing among them, and production selection is deferred to ADR 0041", len(paths))
	}
	return paths[0]
}

// scenario is one end-to-end run against the validation environment.
type scenario struct {
	// port selects the listener: the TLS server, or the plaintext-only one.
	port uint16

	plan     postgres.TLSPlan
	insecure bool
	// trustCA pins the generated certificate. False with TLSRequired means the
	// handshake is expected not to verify.
	trustCA bool

	role     string
	password string // empty means no credential is presented
	database string
}

// outcome is everything one run produced, in the order it was produced.
type outcome struct {
	graph    domain.Graph
	findings []domain.Finding
	report   domain.Report
}

// run drives the whole vertical slice and returns the real artifacts.
//
// Every stage is the production one. The only thing this function adds is
// sequencing and the ownership discipline each stage's contract already
// specifies: a stage that returns nil has already closed what it held, and a
// stage that returns a value hands it to the next.
func run(t *testing.T, s scenario) outcome {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	builder := domain.NewGraphBuilder()

	// DNS + TCP. TLS is deliberately not requested from the chain: PostgreSQL
	// negotiates encryption in band, so the handshake belongs after SSLRequest
	// and internal/adapter/postgres performs it.
	transportResult, err := transport.Run(ctx, builder, transport.Params{
		Host:     pgHost,
		Port:     s.port,
		Resolver: dns.SystemResolver{},
		Dialer:   tcp.SystemDialer{},
		// A per-step bound, so one black-holed address cannot consume the run.
		// The whole-run budget is an application-orchestration concern and does
		// not exist yet.
		StepTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = transportResult.Close() })

	path := requireSingleContinuation(t, transportResult)

	options := postgres.TLSOptions{ServerName: pgHost}
	switch {
	case s.insecure:
		options.InsecureSkipVerify = true
	case s.trustCA:
		options.RootCAs = rootCAs(t)
	}

	// SSLRequest, and the TLS handshake when the server agrees.
	session, err := postgres.Negotiate(ctx, builder, path, postgres.Params{
		TLS: s.plan, TLSOptions: options, StepTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	// Startup. A dead session records a SKIPPED node and returns nothing, which
	// is evidence rather than an error.
	// StartupParams carries identity only; the exchange is bounded by ctx.
	startupResult, err := postgres.Startup(ctx, builder, session, postgres.StartupParams{
		User: s.role, Database: s.database,
	})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}

	if startupResult != nil {
		t.Cleanup(func() { _ = startupResult.Close() })
		authenticated := authenticate(t, ctx, builder, startupResult, s)
		if authenticated != nil {
			t.Cleanup(func() { _ = authenticated.Close() })
			// The session step is terminal: it consumes the connection and
			// closes it on every outcome, and returns none.
			if _, err := postgres.EstablishSession(
				ctx, builder, authenticated, postgres.SessionParams{
					ReadTimeout: 10 * time.Second,
				}); err != nil {
				t.Fatalf("EstablishSession: %v", err)
			}
		}
	}

	// The graph is complete. Everything after this point is a pure
	// transformation of it.
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	findings := diagnosis.NewEngine(
		diagnosispostgres.SSLRequest,
		diagnosispostgres.Startup,
		diagnosispostgres.Authentication,
		diagnosispostgres.Session,
	).Diagnose(graph)

	return outcome{graph: graph, findings: findings, report: reportOf(t, graph, findings, s)}
}

// authenticate presents the credential when the scenario has one.
//
// A server that demanded nothing is handled by the adapter itself, which returns
// an authenticated session with no authentication node recorded — svcdoctor
// presented nothing, so claiming a passing authentication would be an overclaim.
func authenticate(
	t *testing.T, ctx context.Context, builder *domain.GraphBuilder,
	result *postgres.StartupResult, s scenario,
) *postgres.AuthenticatedSession {
	t.Helper()

	var c security.Credential
	if s.password != "" {
		c = credentialFor(t, s.port, s.role, s.password)
	}

	authenticated, err := postgres.Authenticate(ctx, builder, result, c, postgres.AuthParams{
		ExchangeTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	return authenticated
}

// credentialFor binds a credential to the logical endpoint, never to an address.
func credentialFor(t *testing.T, port uint16, role, password string) security.Credential {
	t.Helper()

	endpoint, err := security.NewEndpoint(pgHost, port)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, role, security.NewSecret(password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return c
}

// reportOf assembles the real report. NewReport validates that every finding's
// evidence reference resolves in the graph, so a dangling one fails here.
func reportOf(
	t *testing.T, graph domain.Graph, findings []domain.Finding, s scenario,
) domain.Report {
	t.Helper()

	target, err := domain.NewTarget(endpointLabel(s.port))
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage("svcdoctor-integration")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	service, err := domain.NewServiceID("postgres")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata("0.1.0-integration", time.Now(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	security, err := domain.NewReportSecurity(domain.OutputModeLocalFull, s.insecure, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage,
		Graph: graph, Findings: findings, Security: security,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

func endpointLabel(port uint16) string {
	if port == pgPlaintextPort {
		return pgHost + ":55433"
	}
	return pgHost + ":55432"
}

// --- assertions over the real graph -----------------------------------------

// node returns the single node at a step, and whether one exists.
//
// It reads Step() off the evidence rather than parsing an identifier: an
// EvidenceID is identity and carries no semantics anything may recover.
func (o outcome) node(t *testing.T, step domain.Step) (domain.Evidence, bool) {
	t.Helper()

	var found domain.Evidence
	count := 0
	for _, n := range o.graph.Nodes() {
		if n.Step() == step {
			found = n
			count++
		}
	}
	if count > 1 {
		t.Fatalf("the graph holds %d %s nodes; this harness expects one", count, step)
	}
	return found, count == 1
}

// requireNode fails when the step is absent.
func (o outcome) requireNode(t *testing.T, step domain.Step) domain.Evidence {
	t.Helper()
	n, ok := o.node(t, step)
	if !ok {
		t.Fatalf("no %s node in the real graph", step)
	}
	return n
}

// requireAbsent fails when the step produced a node at all.
func (o outcome) requireAbsent(t *testing.T, step domain.Step) {
	t.Helper()
	if _, ok := o.node(t, step); ok {
		t.Fatalf("%s ran, and the preceding failure should have stopped it", step)
	}
}

// requireState pins a step's outcome and its classification.
func (o outcome) requireState(
	t *testing.T, step domain.Step, state domain.State, class domain.FailureClass,
) domain.Evidence {
	t.Helper()

	n := o.requireNode(t, step)
	if n.State() != state {
		t.Errorf("%s state = %s, want %s", step, n.State(), state)
	}
	if n.FailureClass() != class {
		t.Errorf("%s failure class = %s, want %s", step, n.FailureClass(), class)
	}
	return n
}

// requireOneFinding pins that diagnosis produced exactly one, and its code.
func (o outcome) requireOneFinding(t *testing.T, code domain.FindingCode) domain.Finding {
	t.Helper()

	if len(o.findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1: %v", len(o.findings), o.codes())
	}
	if o.findings[0].Code() != code {
		t.Fatalf("finding = %s, want %s", o.findings[0].Code(), code)
	}
	return o.findings[0]
}

func (o outcome) requireNoFindings(t *testing.T) {
	t.Helper()
	if len(o.findings) != 0 {
		t.Fatalf("want no finding, got %v", o.codes())
	}
}

func (o outcome) codes() []domain.FindingCode {
	out := make([]domain.FindingCode, 0, len(o.findings))
	for _, f := range o.findings {
		out = append(out, f.Code())
	}
	return out
}

// stringAttr reads a normalized attribute off a real node.
func stringAttr(t *testing.T, n domain.Evidence, key domain.AttributeKey) string {
	t.Helper()
	v, ok := n.Attribute(key)
	if !ok {
		return ""
	}
	s, _ := v.Str()
	return s
}

// requireParentChain walks the real graph structurally and asserts that each
// step derives from the one before it.
//
// It reads Parents() and Step(), never an identifier: an EvidenceID is identity,
// and recovering a parent, a step or an ordering from its text would make the
// graph's shape a function of a naming convention.
func (o outcome) requireParentChain(t *testing.T, chain []domain.Step) {
	t.Helper()

	for i := 1; i < len(chain); i++ {
		child := o.requireNode(t, chain[i])
		want := o.requireNode(t, chain[i-1])

		var linked bool
		for _, id := range o.graph.Parents(child.ID()) {
			parent, ok := o.graph.Node(id)
			if ok && parent.ID() == want.ID() {
				linked = true
			}
		}
		if !linked {
			t.Errorf("%s does not derive from %s in the real graph", chain[i], chain[i-1])
		}
	}
}

// requireNoSuccessfulNodeAtOrBelow asserts that a terminal failure really
// stopped the run.
//
// A PASS node at or after the given step would mean network I/O happened after
// something that should have blocked it — which is the failure mode the whole
// short-circuit contract exists to prevent, and the one a composed run is the
// first place to be able to observe.
func (o outcome) requireNoSuccessfulNodeAtOrBelow(t *testing.T, from domain.Step) {
	t.Helper()

	downstream := map[domain.Step]bool{}
	found := false
	for _, step := range []domain.Step{
		servicepostgres.StepSSLRequest, "tls.handshake", servicepostgres.StepStartup,
		servicepostgres.StepAuthentication, servicepostgres.StepSession,
	} {
		if step == from {
			found = true
		}
		if found {
			downstream[step] = true
		}
	}
	if !found {
		t.Fatalf("%s is not a PostgreSQL step this helper knows", from)
	}

	for _, n := range o.graph.Nodes() {
		if downstream[n.Step()] && n.State() == domain.StatePass {
			t.Errorf("%s passed below a terminal failure", n.Step())
		}
	}
}
