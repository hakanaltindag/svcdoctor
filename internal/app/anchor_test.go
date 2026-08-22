package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	servicepostgres "github.com/hakanaltindag/svcdoctor/internal/service/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The requested-target anchor, exercised through the production run.
//
// Every test here calls app.DiagnosePostgres. Nothing hand-authors evidence and
// nothing constructs a graph directly, because what ADR 0042 decided is a
// property of *a run*, and a hand-built graph would prove only that a test can
// build one.
//
// The network is faked at the two seams the parameters already expose — a
// Resolver and a Dialer — which is what makes NXDOMAIN, an all-refused endpoint,
// a dual-stack name and a cancelled run deterministic here rather than dependent
// on a container that cannot reproduce some of them at all.

// stubResolver answers from a fixed table.
type stubResolver struct {
	addrs []netip.Addr
	err   error
}

func (r stubResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	return r.addrs, r.err
}

// refusingDialer refuses every address, which is what a closed port looks like.
type refusingDialer struct{}

func (refusingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
}

// speakingDialer accepts the connection and then says nothing a PostgreSQL
// client would recognize.
//
// That is deliberate: these tests are about transport structure and the anchor
// above it, so the protocol stages need to be *reached* and then to fail
// truthfully. A pipe whose far end is closed produces exactly that.
type speakingDialer struct{}

func (speakingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

func addrs(t *testing.T, in ...string) []netip.Addr {
	t.Helper()
	out := make([]netip.Addr, 0, len(in))
	for _, s := range in {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		out = append(out, a)
	}
	return out
}

func vantage(t *testing.T) domain.Vantage {
	t.Helper()
	v, err := domain.NewLocalVantage("svcdoctor-unit")
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	return v
}

// runWith executes a production run against a faked network.
func runWith(t *testing.T, host string, port uint16, r stubResolver, d interface {
	DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
},
) Result {
	t.Helper()
	return runCtxWith(t, context.Background(), host, port, r, d)
}

func runCtxWith(t *testing.T, ctx context.Context, host string, port uint16,
	r stubResolver, d interface {
		DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
	},
) Result {
	t.Helper()

	result, err := DiagnosePostgres(ctx, PostgresParams{
		Host: host, Port: port,
		Role:     "svcdoctor",
		Resolver: r, Dialer: d,
		StepTimeout: time.Second,
		Vantage:     vantage(t),
		Version:     "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result
}

// anchors returns every requested-target node in a graph.
func anchors(g domain.Graph) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range g.Nodes() {
		if n.Step() == vocabulary.StepTargetRequested {
			out = append(out, n)
		}
	}
	return out
}

func requireOneAnchor(t *testing.T, g domain.Graph) domain.Evidence {
	t.Helper()
	found := anchors(g)
	if len(found) != 1 {
		t.Fatalf("got %d requested-target nodes, want exactly 1", len(found))
	}
	return found[0]
}

// nodesWithStep returns every node of one step, using graph APIs only.
func nodesWithStep(g domain.Graph, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, n := range g.Nodes() {
		if n.Step() == step {
			out = append(out, n)
		}
	}
	return out
}

// TestTheAnchorHasTheShapeADR0042Fixed pins every field of the node at once.
//
// Fields are asserted together rather than in six tests because they are one
// decision: a node that is PASS but at L1, or at L0 but with an endpoint
// subject, is not a partially correct anchor — it is a different node.
func TestTheAnchorHasTheShapeADR0042Fixed(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, speakingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)

	if got := anchor.Layer(); got != domain.LayerInput {
		t.Errorf("layer = %s, want %s: the anchor is an input fact, not a measurement",
			got, domain.LayerInput)
	}
	if got := anchor.Subject().Kind(); got != domain.SubjectKindTarget {
		t.Errorf("subject kind = %s, want %s: the anchor is about the logical target, "+
			"never one resolved address", got, domain.SubjectKindTarget)
	}
	if got, want := anchor.Subject().Ref(), "db.example.com:5432"; got != want {
		t.Errorf("subject = %q, want %q", got, want)
	}
	if got := anchor.State(); got != domain.StatePass {
		t.Errorf("state = %s, want PASS", got)
	}
	if got := anchor.FailureClass(); got != domain.FailureNone {
		t.Errorf("failure class = %s, want none", got)
	}
	if got := anchor.AttributeCount(); got != 0 {
		t.Errorf("anchor carries %d attributes, want 0: the subject is the whole fact "+
			"(ADR 0042 section 6)", got)
	}
	if parents := graph.Parents(anchor.ID()); len(parents) != 0 {
		t.Errorf("anchor has parents %v, want none: nothing caused the operator to ask",
			parents)
	}
	if blockers := graph.BlockedBy(anchor.ID()); len(blockers) != 0 {
		t.Errorf("anchor is blocked by %v, want nothing", blockers)
	}
}

// TestTheRequestedSweepIsADirectChildOfTheAnchor is the invariant a future
// generic rule will stand on.
//
// Direct, not transitive. ADR 0042 section 7 records why: a Kafka advertised
// sweep is a transitive descendant of the bootstrap target, so "every dns.lookup
// below the anchor" would diagnose a discovered broker and duplicate the Kafka
// finding that owns it.
func TestTheRequestedSweepIsADirectChildOfTheAnchor(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, speakingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)

	lookups := nodesWithStep(graph, vocabulary.StepDNSLookup)
	if len(lookups) != 1 {
		t.Fatalf("got %d lookups, want 1", len(lookups))
	}

	parents := graph.Parents(lookups[0].ID())
	if len(parents) != 1 || parents[0] != anchor.ID() {
		t.Fatalf("lookup parents = %v, want exactly [%s]", parents, anchor.ID())
	}

	// And the edge is visible from the other side, because the walk a rule
	// performs starts at the anchor.
	children := graph.Children(anchor.ID())
	if len(children) != 1 || children[0] != lookups[0].ID() {
		t.Fatalf("anchor children = %v, want exactly [%s]", children, lookups[0].ID())
	}
}

// TestTheAnchorSurvivesAFailureAtEveryLayer covers the cases the anchor exists
// for.
//
// A run that fails at DNS is the one Phase 4.9a could not diagnose: the graph
// held a single FAIL lookup, and the requested host:port appeared in no subject
// anywhere. The anchor is what makes the logical endpoint recoverable when there
// is no TCP node to take a port from.
func TestTheAnchorSurvivesAFailureAtEveryLayer(t *testing.T) {
	cases := []struct {
		name     string
		resolver stubResolver
		dialer   interface {
			DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
		}
		wantTCPNodes int
	}{
		{
			name:     "NXDOMAIN",
			resolver: stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}},
			dialer:   refusingDialer{},
		},
		{
			name:     "resolver answers with no address",
			resolver: stubResolver{},
			dialer:   refusingDialer{},
		},
		{
			name:         "every address refuses",
			resolver:     stubResolver{addrs: addrs(t, "10.0.0.1", "10.0.0.2")},
			dialer:       refusingDialer{},
			wantTCPNodes: 2,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := runWith(t, "db.example.com", 5432, c.resolver, c.dialer)
			graph := result.Report().Graph()

			anchor := requireOneAnchor(t, graph)
			if got, want := anchor.Subject().Ref(), "db.example.com:5432"; got != want {
				t.Errorf("subject = %q, want %q: the logical endpoint must stay "+
					"recoverable when nothing was reached", got, want)
			}
			if got := anchor.State(); got != domain.StatePass {
				t.Errorf("state = %s, want PASS: a target-side failure is not an "+
					"input failure", got)
			}
			if got := len(nodesWithStep(graph, vocabulary.StepTCPConnect)); got != c.wantTCPNodes {
				t.Errorf("got %d tcp.connect nodes, want %d", got, c.wantTCPNodes)
			}

			// No node was invented for work that did not happen.
			if got := len(nodesWithStep(graph, vocabulary.StepTLSHandshake)); got != 0 {
				t.Errorf("got %d tls.handshake nodes, want 0", got)
			}
		})
	}
}

// TestOneAnchorPerRunNotOnePerAddress pins cardinality against the most likely
// mistake.
//
// The anchor describes the logical endpoint. A dual-stack name resolving to two
// addresses is still one thing the operator asked about, and minting one anchor
// per address would turn the subject into a resolved address by the back door.
func TestOneAnchorPerRunNotOnePerAddress(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1", "10.0.0.2", "2001:db8::1")},
		refusingDialer{})
	graph := result.Report().Graph()

	requireOneAnchor(t, graph)

	if got := len(nodesWithStep(graph, vocabulary.StepDNSLookup)); got != 1 {
		t.Errorf("got %d requested lookups, want 1", got)
	}
	if got := len(nodesWithStep(graph, vocabulary.StepTCPConnect)); got != 3 {
		t.Errorf("got %d tcp.connect nodes, want 3: paths are per address, the anchor "+
			"is not", got)
	}
}

// TestCancellationDoesNotDowngradeTheAnchor pins ADR 0042 section 1 against the
// tempting mistake.
//
// The anchor is minted after validation and before measurement, so a run
// cancelled later keeps it. Downgrading it to UNKNOWN would say the *input* could
// not be determined, which is false: what was cancelled is the measurement, and
// Result.Incomplete already reports that.
func TestCancellationDoesNotDowngradeTheAnchor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := runCtxWith(t, ctx, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, refusingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)
	if got := anchor.State(); got != domain.StatePass {
		t.Errorf("state = %s, want PASS after cancellation", got)
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false; a cancelled run reports incompleteness there, " +
			"not on the anchor")
	}
}

// TestTheAnchorIsDeterministic pins that identity comes from the input and
// nothing else.
//
// No clock, no random source, no address family, no discovery order. Two runs of
// one target must mint the same identifier, or a report cannot be diffed against
// its predecessor.
func TestTheAnchorIsDeterministic(t *testing.T) {
	first := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1", "10.0.0.2")}, refusingDialer{})
	second := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.2", "10.0.0.1")}, refusingDialer{})

	a := requireOneAnchor(t, first.Report().Graph())
	b := requireOneAnchor(t, second.Report().Graph())

	if a.ID() != b.ID() {
		t.Errorf("identifiers differ across runs: %s vs %s", a.ID(), b.ID())
	}
	if a.Subject().Ref() != b.Subject().Ref() {
		t.Errorf("subjects differ across runs: %q vs %q", a.Subject().Ref(), b.Subject().Ref())
	}
}

// TestTheAnchorStepMintsOneComponent pins ADR 0032 section 3's injectivity
// caveat for the new producer.
//
// The scheme stays injective only because a step mints a fixed number of
// components. A step that minted one component for a hostname and two for
// something else would break every scoped identifier in the repository, silently.
func TestTheAnchorStepMintsOneComponent(t *testing.T) {
	for _, host := range []string{"db.example.com", "10.0.0.1", "2001:db8::1", "db/weird%host"} {
		target := logicalTarget{host: host, port: 5432}
		id := string(target.evidenceID())

		prefix := vocabulary.StepTargetRequested.String() + "/"
		if len(id) <= len(prefix) || id[:len(prefix)] != prefix {
			t.Fatalf("identifier %q does not start with %q", id, prefix)
		}
		// Exactly one separator: the one after the step. Any component
		// containing a separator is escaped by the encoder, so a second
		// unescaped one would mean a second component.
		if got := countSeparators(id); got != 1 {
			t.Errorf("host %q produced %d components in %q, want 1", host, got, id)
		}
	}
}

func countSeparators(id string) int {
	n := 0
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			n++
		}
	}
	return n
}

// TestTheRunReportsWhatItCouldNotReach is the ADR 0043 report integration.
//
// This is the failure the CLI release gate was opened for. Before these rules the
// same runs produced complete evidence, a correct firstBrokenLayer and an empty
// findings array beside `status: OK` — a report that reads as healthy while
// naming a broken layer.
//
// It runs the production composition, so what is under test is the wiring as much
// as the rules.
func TestTheRunReportsWhatItCouldNotReach(t *testing.T) {
	cases := []struct {
		name     string
		resolver stubResolver
		dialer   interface {
			DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
		}
		wantCode  domain.FindingCode
		wantLayer domain.Layer
	}{
		{
			name:      "the name does not resolve",
			resolver:  stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}},
			dialer:    refusingDialer{},
			wantCode:  "DNS_NAME_NOT_RESOLVED",
			wantLayer: domain.LayerDNS,
		},
		{
			name:      "every address refuses",
			resolver:  stubResolver{addrs: addrs(t, "10.0.0.1", "2001:db8::1")},
			dialer:    refusingDialer{},
			wantCode:  "TCP_CONNECTION_NOT_ESTABLISHED",
			wantLayer: domain.LayerTCP,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := runWith(t, "db.example.com", 5432, c.resolver, c.dialer)
			report := result.Report()

			findings := report.Findings()
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want exactly 1: %v", len(findings), findings)
			}
			finding := findings[0]

			if got := finding.Code(); got != c.wantCode {
				t.Errorf("code = %s, want %s", got, c.wantCode)
			}
			if got := finding.Severity(); got != domain.SeverityError {
				t.Errorf("severity = %s, want ERROR", got)
			}
			if got := finding.Layer(); got != c.wantLayer {
				t.Errorf("layer = %s, want %s", got, c.wantLayer)
			}

			// The subject is the operator's endpoint, and it agrees with the
			// anchor and the report envelope. This is what ADR 0042 bought.
			anchor := requireOneAnchor(t, report.Graph())
			if got := finding.Subject().Ref(); got != anchor.Subject().Ref() {
				t.Errorf("finding subject %q and anchor subject %q disagree",
					got, anchor.Subject().Ref())
			}
			if got := finding.Subject().Ref(); got != report.Target().Requested() {
				t.Errorf("finding subject %q and report target %q disagree",
					got, report.Target().Requested())
			}

			// The report no longer reads as healthy.
			if got := report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
				t.Errorf("status = %s, want PROBLEMS_FOUND", got)
			}
			// And firstBrokenLayer is unchanged: it is derived from evidence,
			// never from findings.
			if got := report.Summary().FirstBrokenLayer(); got != c.wantLayer {
				t.Errorf("firstBrokenLayer = %s, want %s", got, c.wantLayer)
			}

			// Every reference resolves in the report's own graph.
			for _, ref := range finding.EvidenceRefs() {
				if _, ok := report.Graph().Node(ref); !ok {
					t.Errorf("evidence ref %s is not in the graph", ref)
				}
			}
		})
	}
}

// TestPartialSuccessProducesNoGenericTCPFinding is the withholding rule on a real
// run, and the case where the report's two views legitimately differ.
//
// One family fails and the other connects. No TCP finding fires, because a client
// selecting the working path succeeds — but firstBrokenLayer still reports L2,
// because a path did positively fail. Both are correct and a renderer must be
// ready for the combination.
func TestPartialSuccessProducesNoGenericTCPFinding(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1", "2001:db8::1")}, &oneWorkingDialer{})
	report := result.Report()

	for _, f := range report.Findings() {
		if f.Code() == "TCP_CONNECTION_NOT_ESTABLISHED" {
			t.Error("a TCP finding fired while one address connected")
		}
	}

	// The failed path is still in the graph. Withholding a finding is not
	// withholding information.
	failures := 0
	for _, n := range nodesWithStep(report.Graph(), vocabulary.StepTCPConnect) {
		if n.State() == domain.StateFail {
			failures++
		}
	}
	if failures != 1 {
		t.Errorf("got %d failed connections in the graph, want 1", failures)
	}
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerTCP {
		t.Errorf("firstBrokenLayer = %s, want L2 — evidence-derived and unchanged", got)
	}
}

// TestCancellationProducesNoTargetFinding pins that an incomplete run makes no
// claim about the target.
func TestCancellationProducesNoTargetFinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := runCtxWith(t, ctx, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, refusingDialer{})
	report := result.Report()

	if got := len(report.Findings()); got != 0 {
		t.Errorf("a cancelled run produced %d findings, want none", got)
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false; that is where an unfinished run is reported")
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s; a cancelled run found no target problem", got)
	}
}

// TestTheRunReportsAFailedInBandHandshake is the ADR 0044 report integration.
//
// This was the last transport silence in a PostgreSQL run. The same graph
// previously produced `findings: []` beside `status: OK` and `firstBrokenLayer:
// L3` — a report that read as healthy while naming a broken layer.
//
// It runs the production composition, so the wiring is under test as much as the
// rule.
func TestTheRunReportsAFailedInBandHandshake(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, sslThenGarbageDialer{})
	report := result.Report()

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1: %v", len(findings), findings)
	}
	finding := findings[0]

	if got := finding.Code(); got != "POSTGRES_TLS_UPGRADE_NOT_HONORED" {
		t.Errorf("code = %s, want POSTGRES_TLS_UPGRADE_NOT_HONORED", got)
	}
	if got := finding.Severity(); got != domain.SeverityError {
		t.Errorf("severity = %s, want ERROR", got)
	}
	if got := finding.Layer(); got != domain.LayerTLS {
		t.Errorf("layer = %s, want L3", got)
	}

	// Endpoint-scoped: the concrete address, not the logical target. This is the
	// deliberate difference from the generic transport findings, whose subject is
	// the anchor's logical endpoint.
	anchor := requireOneAnchor(t, report.Graph())
	if finding.Subject().Ref() == anchor.Subject().Ref() {
		t.Errorf("subject %q equals the logical target; a PostgreSQL finding is about "+
			"the concrete endpoint", finding.Subject().Ref())
	}

	// The report no longer reads as healthy, and firstBrokenLayer is untouched.
	if got := report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", got)
	}
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerTLS {
		t.Errorf("firstBrokenLayer = %s, want L3", got)
	}

	for _, ref := range finding.EvidenceRefs() {
		if _, ok := report.Graph().Node(ref); !ok {
			t.Errorf("evidence ref %s is not in the graph", ref)
		}
	}
}

// TestNoGenericTLSFindingIsProduced pins the deferral that remains.
//
// PostgreSQL now owns its in-band handshake, and generic requested-target TLS is
// still undecided — no production run even produces a handshake beneath a
// requested tcp.connect. A bare TLS_ code appearing anywhere would mean that
// deferral had been closed without a record.
func TestNoGenericTLSFindingIsProduced(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, sslThenGarbageDialer{})

	for _, f := range result.Report().Findings() {
		code := string(f.Code())
		if len(code) >= 4 && code[:4] == "TLS_" {
			t.Errorf("finding %s exists; generic TLS is deferred", code)
		}
	}

	// Non-vacuous: the handshake really did fail.
	handshakes := nodesWithStep(result.Report().Graph(), vocabulary.StepTLSHandshake)
	if len(handshakes) != 1 || handshakes[0].State() != domain.StateFail {
		t.Fatalf("expected one failed handshake, got %v", handshakes)
	}
}

// TestTheAnchorDoesNotDisturbTheSummary pins that an L0 PASS node changes no
// existing interpretation.
//
// firstBrokenLayer is the lowest layer holding a FAIL node. The anchor is never
// FAIL, so it cannot become one — but "cannot" is worth measuring, because the
// alternative is a report that starts claiming the input layer broke.
func TestTheAnchorDoesNotDisturbTheSummary(t *testing.T) {
	cases := []struct {
		name     string
		resolver stubResolver
		dialer   interface {
			DialTCP(context.Context, netip.AddrPort) (net.Conn, error)
		}
		want domain.Layer
	}{
		{
			name:     "dns failure breaks at L1",
			resolver: stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}},
			dialer:   refusingDialer{},
			want:     domain.LayerDNS,
		},
		{
			name:     "tcp failure breaks at L2",
			resolver: stubResolver{addrs: addrs(t, "10.0.0.1")},
			dialer:   refusingDialer{},
			want:     domain.LayerTCP,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := runWith(t, "db.example.com", 5432, c.resolver, c.dialer)
			summary := result.Report().Summary()

			if got := summary.FirstBrokenLayer(); got != c.want {
				t.Errorf("firstBrokenLayer = %s, want %s", got, c.want)
			}
			if summary.FirstBrokenLayer() == domain.LayerInput {
				t.Error("firstBrokenLayer is L0; the anchor must never be a broken layer")
			}
		})
	}
}

// TestTheAnchorAndTheReportTargetCannotDrift is the single-authority property.
//
// Two canonical contracts render the requested endpoint: the report envelope and
// the graph. ADR 0042 section 12 makes neither authoritative over the other —
// both project from one typed value — and this is what would fail if a second
// normalization appeared.
func TestTheAnchorAndTheReportTargetCannotDrift(t *testing.T) {
	hosts := []struct {
		name string
		host string
		port uint16
		want string
	}{
		{"hostname", "db.example.com", 5432, "db.example.com:5432"},
		{"ipv4 literal", "10.0.0.1", 5432, "10.0.0.1:5432"},
		{"ipv6 literal", "2001:db8::1", 5432, "[2001:db8::1]:5432"},
		{"ipv6 loopback", "::1", 6432, "[::1]:6432"},
		{"non-default port", "db.example.com", 65535, "db.example.com:65535"},
	}

	for _, h := range hosts {
		t.Run(h.name, func(t *testing.T) {
			result := runWith(t, h.host, h.port,
				stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}},
				refusingDialer{})
			report := result.Report()

			anchor := requireOneAnchor(t, report.Graph())

			if got := anchor.Subject().Ref(); got != h.want {
				t.Errorf("anchor subject = %q, want %q", got, h.want)
			}
			if got := report.Target().Requested(); got != h.want {
				t.Errorf("report target = %q, want %q", got, h.want)
			}
			if anchor.Subject().Ref() != report.Target().Requested() {
				t.Fatalf("anchor subject %q and report target %q disagree; they must "+
					"project from one value", anchor.Subject().Ref(),
					report.Target().Requested())
			}
		})
	}
}

// TestTheProjectionsAreOneFunction is the structural half of the property above.
//
// Equality on five inputs is evidence; sharing the implementation is proof. If
// the two projections were computed separately, the IPv6 bracketing rule would
// be written twice and could be corrected once.
func TestTheProjectionsAreOneFunction(t *testing.T) {
	target := logicalTarget{host: "2001:db8::1", port: 5432}

	reportTarget, err := target.target()
	if err != nil {
		t.Fatalf("target(): %v", err)
	}
	subject, err := domain.NewTargetSubject(target.label())
	if err != nil {
		t.Fatalf("NewTargetSubject: %v", err)
	}

	if reportTarget.Requested() != subject.Ref() {
		t.Fatalf("projections differ: %q vs %q", reportTarget.Requested(), subject.Ref())
	}
	if got, want := subject.Ref(), "[2001:db8::1]:5432"; got != want {
		t.Errorf("label = %q, want %q; IPv6 must be bracketed", got, want)
	}
}

// TestUnusableInputNeverBecomesEvidence pins that a caller defect stays an error.
//
// A FAIL anchor would be the tool blaming the target for the operator's typo,
// and it would give firstBrokenLayer an L0 to report. There is no report at all
// on this path, which is the strongest possible form of that guarantee.
func TestUnusableInputNeverBecomesEvidence(t *testing.T) {
	cases := []struct {
		name   string
		params PostgresParams
	}{
		{"empty host", PostgresParams{Port: 5432, Role: "r"}},
		{"zero port", PostgresParams{Host: "db.example.com", Role: "r"}},
		{"empty role", PostgresParams{Host: "db.example.com", Port: 5432}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			params := c.params
			params.Resolver = stubResolver{}
			params.Dialer = refusingDialer{}
			params.Vantage = vantage(t)
			params.Version = "0.0.0-test"

			result, err := DiagnosePostgres(context.Background(), params)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
			if result.Report().Graph().Len() != 0 {
				t.Error("a report was produced for unusable input")
			}
		})
	}
}

// TestTheAnchorIsRecordedBeforeMeasurement documents the ordering the
// cancellation case depends on, by showing what a run produces when the resolver
// itself is what fails.
func TestTheAnchorIsRecordedBeforeMeasurement(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{err: fmt.Errorf("resolver exploded")}, refusingDialer{})
	graph := result.Report().Graph()

	anchor := requireOneAnchor(t, graph)
	lookups := nodesWithStep(graph, vocabulary.StepDNSLookup)
	if len(lookups) != 1 {
		t.Fatalf("got %d lookups, want 1", len(lookups))
	}
	if got := lookups[0].State(); got == domain.StatePass {
		t.Fatalf("lookup state = PASS, want a non-passing state")
	}
	if parents := graph.Parents(lookups[0].ID()); len(parents) != 1 || parents[0] != anchor.ID() {
		t.Errorf("a failed sweep still declares its cause: parents = %v", parents)
	}
}

// oneWorkingDialer accepts the first address it is given and refuses the rest,
// which is what a dual-stack endpoint with one usable family looks like.
type oneWorkingDialer struct{ used bool }

func (d *oneWorkingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	if d.used {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	}
	d.used = true
	client, server := net.Pipe()
	_ = server.Close()
	return client, nil
}

// sslThenGarbageDialer answers the SSLRequest with 'S' and then speaks something
// that is not a TLS record, which fails the in-band handshake.
type sslThenGarbageDialer struct{}

func (sslThenGarbageDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request := make([]byte, 8)
		if _, err := server.Read(request); err != nil {
			return
		}
		if _, err := server.Write([]byte{'S'}); err != nil {
			return
		}
		hello := make([]byte, 4096)
		if _, err := server.Read(hello); err != nil {
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()
	return client, nil
}

// --- ADR 0046: the run reaches authentication with nothing to present ----------

// scramDemandingDialer answers a StartupMessage by demanding SCRAM, so the run
// reaches the authentication step with nothing to present.
//
// The plan is TLSDisabled, so no SSLRequest is sent and the first thing this
// peer sees is the startup packet. Plaintext is deliberate: with no credential
// the transport policy never gets a question to answer, which is the ordering
// ADR 0046 fixed.
type scramDemandingDialer struct{}

func (scramDemandingDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		startup := make([]byte, 4096)
		if _, err := server.Read(startup); err != nil {
			return
		}
		_, _ = server.Write(authenticationSASL())
	}()
	return client, nil
}

// authenticationSASL is an AuthenticationSASL message naming SCRAM-SHA-256.
//
// Written out rather than computed, and the length is the part worth checking:
// 4 bytes of authentication code, 13 of mechanism name and 2 terminators is 19,
// plus the 4-byte length field, which PostgreSQL counts, makes 23. The run that
// parses it is what proves the number right — the first draft of this fixture
// said 27 and the run rejected it.
func authenticationSASL() []byte {
	return []byte{
		'R',         // AuthenticationRequest
		0, 0, 0, 23, // length, including itself
		0, 0, 0, 10, // AuthenticationSASL
		'S', 'C', 'R', 'A', 'M', '-', 'S', 'H', 'A', '-', '2', '5', '6',
		0, // end of this mechanism name
		0, // end of the mechanism list
	}
}

// runNoCredential executes a production run carrying no credential over a
// plaintext plan.
func runNoCredential(t *testing.T, ctx context.Context) Result {
	t.Helper()

	result, err := DiagnosePostgres(ctx, PostgresParams{
		Host: "db.example.com", Port: 5432,
		Role:     "svcdoctor",
		Resolver: stubResolver{addrs: addrs(t, "10.0.0.1")}, Dialer: scramDemandingDialer{},
		TLS:         postgres.TLSDisabled,
		StepTimeout: 2 * time.Second,
		Vantage:     vantage(t),
		Version:     "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	return result
}

// TestARunWithNoCredentialSaysSo is the ADR 0046 report integration.
//
// Before this, the same run reported `findings: []`, `status: OK` and no broken
// layer at all — every measured step passed, and the absence of a session was
// invisible.
func TestARunWithNoCredentialSaysSo(t *testing.T) {
	result := runNoCredential(t, context.Background())
	report := result.Report()

	auth := nodesWithStep(report.Graph(), servicepostgres.StepAuthentication)
	if len(auth) != 1 {
		t.Fatalf("got %d authentication nodes, want 1", len(auth))
	}
	if got := auth[0].State(); got != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", got)
	}
	if got := auth[0].FailureClass(); got != domain.FailureExecRequiredInputMissing {
		t.Errorf("class = %s, want EXEC_REQUIRED_INPUT_MISSING", got)
	}

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(findings), findings)
	}
	if got := findings[0].Code(); got != "POSTGRES_CREDENTIAL_NOT_CONFIGURED" {
		t.Errorf("code = %s, want POSTGRES_CREDENTIAL_NOT_CONFIGURED", got)
	}
	if got := findings[0].Severity(); got != domain.SeverityWarn {
		t.Errorf("severity = %s, want WARN", got)
	}

	// The endpoint did nothing wrong, so the report does not say it did. The
	// finding is what makes the run's own limitation visible.
	if got := report.Summary().Status(); got != domain.SummaryStatusOK {
		t.Errorf("status = %s, want OK: nothing about the target is broken", got)
	}
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerUnspecified {
		t.Errorf("firstBrokenLayer = %s, want unset: no evidence failed", got)
	}
	if result.Incomplete() {
		t.Error("Incomplete() = true; the run finished everything it could do")
	}

	// No session, and no credential attempt.
	if got := len(nodesWithStep(report.Graph(), servicepostgres.StepSession)); got != 0 {
		t.Errorf("got %d session nodes, want 0", got)
	}
}

// TestCancellationBeforeAuthenticationIsNotAMissingCredential is the distinction
// ADR 0046 exists to make mechanically.
//
// Both runs stop before authentication completes. Before this phase their graphs
// were identical, and any rule that inferred "no credential" from the absence of
// an authentication node would have claimed it about a cancelled run too.
func TestCancellationBeforeAuthenticationIsNotAMissingCredential(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := runNoCredential(t, ctx)
	report := result.Report()

	for _, f := range report.Findings() {
		if f.Code() == "POSTGRES_CREDENTIAL_NOT_CONFIGURED" {
			t.Error("a cancelled run was reported as having no credential configured")
		}
	}
	if !result.Incomplete() {
		t.Error("Incomplete() = false; a cancelled run reports incompleteness there")
	}

	// And the graphs genuinely differ: the cancelled run records no
	// missing-input node, which is what makes the two distinguishable.
	for _, n := range nodesWithStep(report.Graph(), servicepostgres.StepAuthentication) {
		if n.FailureClass() == domain.FailureExecRequiredInputMissing {
			t.Error("a cancelled run recorded a missing-input authentication node")
		}
	}
}

// TestATrustEndpointNeedsNoCredential pins that the absence is irrelevant when
// nothing was asked for.
func TestATrustEndpointNeedsNoCredential(t *testing.T) {
	result, err := DiagnosePostgres(context.Background(), PostgresParams{
		Host: "db.example.com", Port: 5432,
		Role:     "svcdoctor",
		Resolver: stubResolver{addrs: addrs(t, "10.0.0.1")}, Dialer: trustDialer{},
		TLS:         postgres.TLSDisabled,
		StepTimeout: 2 * time.Second,
		Vantage:     vantage(t),
		Version:     "0.0.0-test",
	})
	if err != nil {
		t.Fatalf("DiagnosePostgres: %v", err)
	}
	report := result.Report()

	for _, f := range report.Findings() {
		if f.Code() == "POSTGRES_CREDENTIAL_NOT_CONFIGURED" {
			t.Error("a trust endpoint produced a missing-credential finding")
		}
	}
	for _, n := range nodesWithStep(report.Graph(), servicepostgres.StepAuthentication) {
		if n.FailureClass() == domain.FailureExecRequiredInputMissing {
			t.Errorf("a trust endpoint recorded %s", n.FailureClass())
		}
	}
}

// trustDialer answers a StartupMessage with AuthenticationOk, so no credential
// is ever wanted.
type trustDialer struct{}

func (trustDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		startup := make([]byte, 4096)
		if _, err := server.Read(startup); err != nil {
			return
		}
		_, _ = server.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
	}()
	return client, nil
}

// TestTheRunReportsAFailedNegotiation is the ADR 0045 report integration.
func TestTheRunReportsAFailedNegotiation(t *testing.T) {
	result := runWith(t, "db.example.com", 5432,
		stubResolver{addrs: addrs(t, "10.0.0.1")}, httpDialer{})
	report := result.Report()

	findings := report.Findings()
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(findings), findings)
	}
	if got := findings[0].Code(); got != "POSTGRES_SSL_NEGOTIATION_FAILED" {
		t.Errorf("code = %s, want POSTGRES_SSL_NEGOTIATION_FAILED", got)
	}
	if got := report.Summary().Status(); got != domain.SummaryStatusProblemsFound {
		t.Errorf("status = %s, want PROBLEMS_FOUND", got)
	}
	if got := report.Summary().FirstBrokenLayer(); got != domain.LayerTLS {
		t.Errorf("firstBrokenLayer = %s, want L3", got)
	}
}

// httpDialer answers the SSLRequest the way an HTTP server would — the most
// ordinary wrong-port mistake there is.
type httpDialer struct{}

func (httpDialer) DialTCP(context.Context, netip.AddrPort) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer func() { _ = server.Close() }()
		request := make([]byte, 8)
		if _, err := server.Read(request); err != nil {
			return
		}
		_, _ = server.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}()
	return client, nil
}
