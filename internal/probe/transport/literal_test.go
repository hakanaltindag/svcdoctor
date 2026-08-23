package transport

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// Phase 6.7 — a sweep of an address literal performs no resolution and records
// none.
//
// The defect these tests close was measured against the shipped binary: a
// literal target produced a `dns.lookup` node in PASS with a measured duration
// and the literal echoed back as an answer, for work that never happened.

// countingResolver fails the test if anything asks it to resolve.
//
// It is the strongest available statement of the property: not "no DNS node was
// recorded", which a producer could satisfy while still querying, but "no query
// was made". A literal is already an address, and asking a resolver about one
// costs a round trip and can return something different from what the operator
// typed.
type countingResolver struct {
	t     *testing.T
	calls int
}

func (r *countingResolver) LookupAddresses(context.Context, string) ([]netip.Addr, error) {
	r.t.Helper()
	r.calls++
	r.t.Error("a resolver was asked to resolve an address literal")
	return nil, errors.New("the resolver must not be reached")
}

func literalRun(t *testing.T, host string, opts *TLSOptions, dialer *scriptedDialer) domain.Graph {
	t.Helper()

	builder := domain.NewGraphBuilder()
	result, err := Run(context.Background(), builder, Params{
		Host:     host,
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   dialer,
		TLS:      opts,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

func stepsOf(g domain.Graph) []domain.Step {
	out := make([]domain.Step, 0, len(g.Nodes()))
	for _, node := range g.Nodes() {
		out = append(out, node.Step())
	}
	return out
}

func TestALiteralSweepPerformsNoResolutionAndRecordsNone(t *testing.T) {
	for _, host := range []string{"10.0.0.1", "2001:db8::1", "::1", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			graph := literalRun(t, host, nil, newScriptedDialer(t))

			for _, node := range graph.Nodes() {
				if node.Step() == vocabulary.StepDNSLookup {
					t.Fatalf("a literal sweep recorded %s: no resolution happened", node.ID())
				}
				if node.Layer() == domain.LayerDNS {
					t.Fatalf("a literal sweep recorded an L1 node: %s", node.ID())
				}
			}
			if len(graph.Nodes()) == 0 {
				t.Fatal("the sweep recorded nothing at all")
			}
		})
	}
}

// The address dialled is the literal itself, and exactly once. Nothing widens it
// into a set and nothing substitutes a resolved value for it.
func TestALiteralSweepDialsExactlyTheAddressItWasGiven(t *testing.T) {
	for host, want := range map[string]string{
		"10.0.0.1":              "10.0.0.1",
		"2001:db8::1":           "2001:db8::1",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"::ffff:192.0.2.1":      "192.0.2.1",
	} {
		t.Run(host, func(t *testing.T) {
			dialer := newScriptedDialer(t)
			literalRun(t, host, nil, dialer)

			attempts := dialer.attempts()
			if len(attempts) != 1 {
				t.Fatalf("attempts = %d, want exactly 1: %v", len(attempts), attempts)
			}
			if got := attempts[0].Addr().String(); got != want {
				t.Fatalf("dialled %s, want %s", got, want)
			}
			if attempts[0].Port() != testPort {
				t.Fatalf("port = %d, want %d", attempts[0].Port(), testPort)
			}
		})
	}
}

// The connection nodes derive from whatever caused the sweep. With no DNS node
// to carry the edge, the connections carry it, so a caller that declared a cause
// still gets a connected graph.
func TestALiteralSweepParentsItsConnectionsToTheCause(t *testing.T) {
	builder := domain.NewGraphBuilder()

	cause, err := domain.NewEvidence(domain.EvidenceInput{
		ID:        "target.requested/10.0.0.1:9092",
		Subject:   mustTargetSubject(t, "10.0.0.1:9092"),
		Layer:     domain.LayerInput,
		Step:      vocabulary.StepTargetRequested,
		State:     domain.StatePass,
		StartedAt: time.Now(),
		Elapsed:   domain.Unmeasured(),
	})
	if err != nil {
		t.Fatalf("building the cause: %v", err)
	}
	if err := builder.AddEvidence(cause); err != nil {
		t.Fatalf("recording the cause: %v", err)
	}

	result, err := Run(context.Background(), builder, Params{
		Host:     "10.0.0.1",
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   newScriptedDialer(t),
		Parent:   cause.ID(),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	children := graph.Children(cause.ID())
	if len(children) != 1 {
		t.Fatalf("children of the cause = %d, want 1: %v", len(children), children)
	}
	child, ok := graph.Node(children[0])
	if !ok {
		t.Fatalf("the graph does not hold %s", children[0])
	}
	if child.Step() != vocabulary.StepTCPConnect {
		t.Fatalf("the cause's child is %s, want %s", child.Step(), vocabulary.StepTCPConnect)
	}
}

// An unparented literal sweep leaves its connection a graph root rather than
// failing. A name behaves the same way, one node higher.
func TestAnUnparentedLiteralSweepProducesARoot(t *testing.T) {
	graph := literalRun(t, "10.0.0.1", nil, newScriptedDialer(t))

	roots := 0
	for _, node := range graph.Nodes() {
		if len(graph.Parents(node.ID())) == 0 {
			roots++
			if node.Step() != vocabulary.StepTCPConnect {
				t.Fatalf("the root is %s, want %s", node.Step(), vocabulary.StepTCPConnect)
			}
		}
	}
	if roots != 1 {
		t.Fatalf("roots = %d, want 1", roots)
	}
}

// A name still resolves. The literal path must not have become the only path.
func TestANameStillResolves(t *testing.T) {
	builder := domain.NewGraphBuilder()
	resolver := resolving(t, "10.0.0.5")

	result, err := Run(context.Background(), builder, Params{
		Host:     testHost,
		Port:     testPort,
		Resolver: resolver,
		Dialer:   newScriptedDialer(t),
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if resolver.calls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolver.calls)
	}
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	lookups := 0
	for _, node := range graph.Nodes() {
		if node.Step() == vocabulary.StepDNSLookup {
			lookups++
		}
	}
	if lookups != 1 {
		t.Fatalf("lookups for a name = %d, want 1 (steps: %v)", lookups, stepsOf(graph))
	}
}

// The TLS handshake still hangs off the connection, so the terminal layer of a
// literal path is the same as a named one's.
func TestALiteralSweepStillReachesTLS(t *testing.T) {
	peer := newTLSPeer(t, []string{"primary.internal"})
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host:     "10.0.0.1",
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool, InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var connect, handshake domain.Evidence
	for _, node := range graph.Nodes() {
		switch node.Step() {
		case vocabulary.StepTCPConnect:
			connect = node
		case vocabulary.StepTLSHandshake:
			handshake = node
		}
	}
	if connect.IsZero() || handshake.IsZero() {
		t.Fatalf("the literal sweep did not reach TLS: %v", stepsOf(graph))
	}
	parents := graph.Parents(handshake.ID())
	if len(parents) != 1 || parents[0] != connect.ID() {
		t.Fatalf("the handshake hangs from %v, want %s", parents, connect.ID())
	}
}

// The identity a raw address verifies against is the bare literal.
//
// **Never the bracketed endpoint form.** `[2001:db8::1]` is a rendering of a
// host and a port together; sending it as a server name would ask for an
// identity no certificate can carry, and would turn every IPv6 literal run into
// a verification failure that looks like the peer's fault. ADR 0058 section 6
// pins what the standard library then does with a bare literal.
func TestTheIdentityForARawAddressIsTheBareLiteral(t *testing.T) {
	for host, want := range map[string]string{
		"10.0.0.1":              "10.0.0.1",
		"2001:db8::1":           "2001:db8::1",
		"2001:0db8:0:0:0:0:0:1": "2001:db8::1",
		"::1":                   "::1",
	} {
		t.Run(host, func(t *testing.T) {
			h, err := probe.ParseHost(host)
			if err != nil {
				t.Fatalf("ParseHost: %v", err)
			}
			p := Params{Host: h.String(), Port: testPort, TLS: &TLSOptions{}}
			got := p.tlsParams(netip.MustParseAddrPort("[2001:db8::1]:9092")).ServerName

			if got != want {
				t.Fatalf("ServerName = %q, want %q", got, want)
			}
			if strings.ContainsAny(got, "[]") {
				t.Fatalf("ServerName %q is bracketed", got)
			}
		})
	}
}

// An explicit server name overrides the identity and is not itself canonicalized
// as an address: connect by address, verify the name.
func TestAnExplicitServerNameOverridesTheLiteralIdentity(t *testing.T) {
	p := Params{
		Host: "10.20.30.40",
		Port: testPort,
		TLS:  &TLSOptions{ServerName: "kafka.internal"},
	}
	got := p.tlsParams(netip.MustParseAddrPort("10.20.30.40:9092")).ServerName
	if got != "kafka.internal" {
		t.Fatalf("ServerName = %q, want the override", got)
	}
}

// The identity never comes from the address that was reached. For a name that is
// ADR 0058's rule; for a literal the two happen to coincide, so the property is
// pinned where they differ.
func TestTheIdentityIsNeverTheReachedAddress(t *testing.T) {
	p := Params{Host: testHost, Port: testPort, TLS: &TLSOptions{}}
	got := p.tlsParams(netip.MustParseAddrPort("10.0.0.9:9092")).ServerName
	if got != testHost {
		t.Fatalf("ServerName = %q, want %q: a resolved address is not an identity", got, testHost)
	}
}

// A host the chain cannot measure truthfully is refused before any socket
// exists, so a zoned literal never reaches a dialler.
func TestTheChainRefusesAHostItCannotMeasure(t *testing.T) {
	builder := domain.NewGraphBuilder()
	_, err := Run(context.Background(), builder, Params{
		Host:     "fe80::1%en0",
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   newScriptedDialer(t),
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Run error = %v, want ErrInvalidInput", err)
	}
	graph, freezeErr := builder.Freeze()
	if freezeErr == nil && len(graph.Nodes()) != 0 {
		t.Fatalf("a refused host produced evidence: %v", stepsOf(graph))
	}
}

// The endpoint label a literal run scopes its nodes by is bracket-correct and
// round-trips, in both families.
func TestTheLiteralEndpointLabelIsBracketSafe(t *testing.T) {
	for host, want := range map[string]string{
		"10.0.0.1":    "10.0.0.1:9092",
		"2001:db8::1": "[2001:db8::1]:9092",
		"::1":         "[::1]:9092",
	} {
		p := Params{Host: host, Port: 9092}
		if got := p.endpoint(); got != want {
			t.Errorf("endpoint() for %q = %q, want %q", host, got, want)
		}
	}
}

// tls.Params must accept a bare literal as an identity; a rejection here would
// make every address target fail before the handshake.
func TestTLSParamsAcceptABareLiteralIdentity(t *testing.T) {
	p := Params{Host: "2001:db8::1", Port: 9092, TLS: &TLSOptions{}}
	params := p.tlsParams(netip.MustParseAddrPort("[2001:db8::1]:9092"))
	if _, ok := any(params).(tls.Params); !ok {
		t.Fatal("tlsParams did not produce tls.Params")
	}
	if params.Endpoint != "[2001:db8::1]:9092" {
		t.Fatalf("Endpoint = %q, want the bracketed endpoint", params.Endpoint)
	}
}

func mustTargetSubject(t *testing.T, ref string) domain.Subject {
	t.Helper()
	s, err := domain.NewTargetSubject(ref)
	if err != nil {
		t.Fatalf("NewTargetSubject(%q): %v", ref, err)
	}
	return s
}

// Verification is not silently relaxed for an address target.
//
// This is the mutation that survived the first pass of the Phase 6.7 matrix:
// nothing stopped the chain from setting InsecureSkipVerify for a literal, which
// is exactly the shortcut somebody reaches for when an IP fails to verify. The
// result would be a handshake that looks like it verified an endpoint's identity
// and did not, with tls.verified recording the truth on a node nobody reads
// twice.
func TestVerificationIsNeverRelaxedForAnAddressTarget(t *testing.T) {
	for _, host := range []string{"10.0.0.1", "2001:db8::1", "primary.internal"} {
		p := Params{Host: host, Port: testPort, TLS: &TLSOptions{}}
		got := p.tlsParams(netip.MustParseAddrPort("10.0.0.1:9092"))
		if got.InsecureSkipVerify {
			t.Errorf("the chain disabled verification for %q without being asked", host)
		}
	}
}

// And the relaxation cannot be reintroduced downstream either: a literal target
// whose peer presents a DNS-only certificate must fail identity verification,
// with the handshake recording that verification was performed.
func TestAnAddressTargetIsRejectedByADNSOnlyCertificate(t *testing.T) {
	peer := newTLSPeer(t, []string{"primary.internal"})
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host:     "127.0.0.1",
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	var handshake domain.Evidence
	for _, node := range graph.Nodes() {
		if node.Step() == vocabulary.StepTLSHandshake {
			handshake = node
		}
	}
	if handshake.IsZero() {
		t.Fatalf("no handshake was recorded: %v", stepsOf(graph))
	}
	if handshake.State() != domain.StateFail {
		t.Fatalf("handshake state = %s, want FAIL: a DNS SAN does not satisfy an address",
			handshake.State())
	}
	if handshake.FailureClass() != domain.FailureTLSHostnameMismatch {
		t.Fatalf("failure class = %s, want TLS_HOSTNAME_MISMATCH", handshake.FailureClass())
	}
	if verified, ok := handshake.Attribute(tls.AttrVerified); ok {
		if b, _ := verified.Bool(); b {
			t.Fatal("a failed verification recorded tls.verified = true")
		}
	}

	// And no path completed, so nothing was handed on as usable.
	if len(result.Continuations()) != 0 {
		t.Fatal("a failed handshake yielded a usable path")
	}
}

// The same address *with* a matching IP SAN verifies, so the test above is about
// identity rather than about literals failing in general.
func TestAnAddressTargetVerifiesAgainstAMatchingIPSAN(t *testing.T) {
	peer := newTLSPeerWithIPs(t, "127.0.0.1")
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, Params{
		Host:     "127.0.0.1",
		Port:     testPort,
		Resolver: &countingResolver{t: t},
		Dialer:   &loopbackDialer{target: peer.addr},
		TLS:      &TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	for _, node := range graph.Nodes() {
		if node.Step() != vocabulary.StepTLSHandshake {
			continue
		}
		if node.State() != domain.StatePass {
			t.Fatalf("handshake state = %s (%s), want PASS against a matching IP SAN",
				node.State(), node.FailureClass())
		}
		verified, ok := node.Attribute(tls.AttrVerified)
		if !ok {
			t.Fatal("the handshake recorded no tls.verified attribute")
		}
		if b, _ := verified.Bool(); !b {
			t.Fatal("a passing address handshake recorded tls.verified = false")
		}
	}
}
