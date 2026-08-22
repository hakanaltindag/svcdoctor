package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
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

// TestNoGenericTransportFindingExists pins the boundary of this phase.
//
// ADR 0042 authorizes a node and no claim. A run that fails at DNS, TCP or TLS
// still produces no transport finding, and that gap stays visible rather than
// being closed by an unauthorized rule.
func TestNoGenericTransportFindingExists(t *testing.T) {
	for _, c := range []struct {
		name     string
		resolver stubResolver
	}{
		{"dns failure", stubResolver{err: &net.DNSError{Err: "no such host", IsNotFound: true}}},
		{"tcp failure", stubResolver{addrs: addrs(t, "10.0.0.1")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			result := runWith(t, "db.example.com", 5432, c.resolver, refusingDialer{})

			for _, f := range result.Report().Findings() {
				code := string(f.Code())
				for _, prefix := range []string{"DNS_", "TCP_", "TLS_", "TARGET_"} {
					if len(code) >= len(prefix) && code[:len(prefix)] == prefix {
						t.Errorf("finding %s exists; generic transport diagnosis is "+
							"Phase 4.9a and is not authorized here", code)
					}
				}
			}
		})
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
