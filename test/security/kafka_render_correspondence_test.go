package security_test

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/render"
	renderterminal "github.com/hakanaltindag/svcdoctor/internal/render/terminal"
	servicekafka "github.com/hakanaltindag/svcdoctor/internal/service/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/vocabulary"
)

// The Kafka renderer, driven by the production composition root.
//
// # Why here
//
// `internal/render/terminal` builds its fixtures by hand, and it must: depguard
// denies a renderer the application, in test files too, so its goldens cannot
// come from a run. That leaves one thing unproven — whether the graph those
// fixtures imitate is the graph `DiagnoseKafka` produces — and this file is
// where it is proven, because the composed-run peer fixture already lives here.
//
// # And why it matters more than it looks
//
// Two independent implementations of ADR 0051's `reached` predicate exist and
// cannot share code: `internal/app` uses one for run completeness, and the
// renderer uses one for the `topology` line. If they drift, the Result block
// says `3 of 3 reached` on a run it also calls INCOMPLETE. ADR 0052 assumed one
// implementation; the depguard boundary means there are two, so the agreement is
// a test rather than a construction.

// renderRun renders a composed run the way the command boundary would.
func renderRun(t *testing.T, result renderable) string {
	t.Helper()

	var out bytes.Buffer
	err := renderterminal.Write(&out, render.Input{
		Report: result.Report(), Incomplete: result.Incomplete(),
	})
	if err != nil {
		t.Fatalf("terminal.Write: %v", err)
	}
	return out.String()
}

// renderable is what a renderer needs from a run, named so this file does not
// depend on app.Result's other methods.
type renderable interface {
	Report() domain.Report
	Incomplete() bool
}

// TestTheRenderedHierarchyMatchesTheProducedGraph is the correspondence.
func TestTheRenderedHierarchyMatchesTheProducedGraph(t *testing.T) {
	ca := newAuthority(t)

	sibling := newPeer(t, ca, peerConfig{serverName: siblingCanaryHost})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, siblingCanaryHost, int32(sibling.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary, addrSibling},
			siblingCanaryHost:   {addrHostile},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrSibling: {to: bootstrap.addr},
			addrHostile: {to: sibling.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
	}
	result := s.run(t)
	graph := result.Report().Graph()

	// The fixture must have produced the shape this test is about, or it proves
	// nothing.
	requireStep(t, graph, servicekafka.StepMetadata, domain.StatePass)
	if got := countStep(graph, servicekafka.StepBrokerAdvertised); got != 1 {
		t.Fatalf("advertisements = %d, want 1", got)
	}
	if got := countStep(graph, vocabulary.StepTCPConnect); got != 3 {
		t.Fatalf("tcp.connect nodes = %d, want 3 (two bootstrap, one advertised)", got)
	}

	text := renderRun(t, result)

	// Two bootstrap paths at the outer level, one advertised path indented under
	// an advertisement. Three connections, three path headings, no duplication.
	bootstrapPaths, advertisedPaths := 0, 0
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Path "):
			bootstrapPaths++
		case strings.HasPrefix(line, "    Path "):
			advertisedPaths++
		}
	}
	if bootstrapPaths != 2 {
		t.Errorf("bootstrap paths = %d, want 2:\n%s", bootstrapPaths, text)
	}
	if advertisedPaths != 1 {
		t.Errorf("advertised paths = %d, want 1:\n%s", advertisedPaths, text)
	}

	// The advertised address appears exactly once, and as an advertised path.
	advertised := advertisedAddress(t, graph)
	if got := strings.Count(text, "Path "+advertised); got != 1 {
		t.Errorf("the advertised address appears %d times as a path, want 1:\n%s", got, text)
	}
	if !strings.Contains(text, "    Path "+advertised) {
		t.Errorf("the advertised address was promoted to a bootstrap path:\n%s", text)
	}

	// Exactly one path continued, and it is the one holding the credentialed
	// step — asserted from the graph rather than from the text.
	if got := strings.Count(text, "· continued"); got != 1 {
		t.Errorf("continued markers = %d, want 1:\n%s", got, text)
	}

	// The outcome and topology lines say what this run actually did.
	requireRow(t, text, "outcome", "Kafka metadata obtained")
	requireRow(t, text, "topology", "1 of 1 advertised broker endpoints reached")
	requireRow(t, text, "execution", "complete")
}

// TestTheTopologyLineAgreesWithRunCompleteness is the two-implementations check.
//
// The advertised peer is never dialable, so the sweep's connection ends UNKNOWN
// on svcdoctor's own step budget. ADR 0051 leaves the advertisement unresolved,
// which makes the run INCOMPLETE — and the topology line must say `not measured`
// rather than counting it as unreached.
func TestTheTopologyLineAgreesWithRunCompleteness(t *testing.T) {
	ca := newAuthority(t)

	// A peer that accepts the connection and then never speaks. The advertised
	// TLS handshake hangs until svcdoctor's own step budget expires, which is an
	// UNKNOWN nobody proved anything from — not a refusal.
	silent := newPeer(t, ca, peerConfig{serverName: siblingCanaryHost, silent: true})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, siblingCanaryHost, int32(silent.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			siblingCanaryHost:   {addrHostile},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrHostile: {to: silent.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
		timeout:    500 * time.Millisecond,
	}
	result := s.run(t)
	text := renderRun(t, result)

	if !result.Incomplete() {
		t.Fatalf("the fixture did not produce an incomplete run:\n%s", text)
	}
	requireRow(t, text, "execution",
		"INCOMPLETE svcdoctor did not finish the intended measurement")
	requireRow(t, text, "topology",
		"0 of 1 advertised broker endpoints reached, 1 not measured")

	// The distinction the run turns on: nothing here says the endpoint refused.
	if strings.Contains(text, "TCP_CONNECTION_REFUSED") {
		t.Errorf("an unmeasured endpoint was reported as refused:\n%s", text)
	}
}

// TestARenderedRunNeverAttributesAuthenticationToADiscoveredBroker is ADR 0050,
// read off the rendered document rather than off a byte counter.
func TestARenderedRunNeverAttributesAuthenticationToADiscoveredBroker(t *testing.T) {
	ca := newAuthority(t)

	hostile := newPeer(t, ca, peerConfig{serverName: hostileCanaryHost, hostile: true})
	bootstrap := newPeer(t, ca, peerConfig{
		serverName: bootstrapCanaryHost,
		advertised: []brokerEntry{advertise(2, hostileCanaryHost, int32(hostile.addr.Port()))},
	})

	s := &scenario{
		host: bootstrapCanaryHost, port: bootstrap.addr.Port(),
		resolver: tableResolver{
			bootstrapCanaryHost: {addrPrimary},
			hostileCanaryHost:   {addrHostile},
		},
		dialer: &routingDialer{routes: map[netip.Addr]route{
			addrPrimary: {to: bootstrap.addr},
			addrHostile: {to: hostile.addr},
		}},
		tls:        &transport.TLSOptions{RootCAs: ca.pool},
		credential: credentialFor(t, bootstrapCanaryHost, bootstrap.addr.Port()),
	}
	text := renderRun(t, s.run(t))

	inside := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case strings.HasPrefix(line, "  Advertised broker"):
			inside = true
		case line == "Findings":
			inside = false
		}
		if !inside {
			continue
		}
		for _, forbidden := range []string{
			"Authentication", "SASL", "Kafka API versions", "Kafka metadata",
		} {
			if strings.Contains(line, forbidden) {
				t.Errorf("a discovered broker's subtree mentions %q:\n%s", forbidden, line)
			}
		}
	}

	// And no secret reached the document, whatever the peer said.
	for _, canary := range []string{secretCanary, identityCanary} {
		if strings.Contains(text, canary) {
			t.Errorf("the rendered document carries %q", canary)
		}
	}
}

// --- helpers -------------------------------------------------------------------

func requireStep(t *testing.T, g domain.Graph, step domain.Step, state domain.State) {
	t.Helper()
	for _, node := range g.Nodes() {
		if node.Step() == step && node.State() == state {
			return
		}
	}
	t.Fatalf("no %s node in state %s; the fixture proves nothing", step, state)
}

func countStep(g domain.Graph, step domain.Step) int {
	n := 0
	for _, node := range g.Nodes() {
		if node.Step() == step {
			n++
		}
	}
	return n
}

// advertisedAddress returns the concrete address the advertised sweep measured.
func advertisedAddress(t *testing.T, g domain.Graph) string {
	t.Helper()
	for _, node := range g.Nodes() {
		if node.Step() != servicekafka.StepBrokerAdvertised {
			continue
		}
		for _, lookupID := range g.Children(node.ID()) {
			for _, connectID := range g.Children(lookupID) {
				connect, ok := g.Node(connectID)
				if ok && connect.Step() == vocabulary.StepTCPConnect {
					return connect.Subject().Ref()
				}
			}
		}
	}
	t.Fatal("the advertised sweep recorded no connection")
	return ""
}

// requireRow asserts one Result row, ignoring the column padding tabwriter chose.
func requireRow(t *testing.T, text, label, value string) {
	t.Helper()
	want := strings.Join(strings.Fields(label+" "+value), " ")
	for _, line := range strings.Split(text, "\n") {
		if strings.Join(strings.Fields(line), " ") == want {
			return
		}
	}
	t.Errorf("no Result row %q:\n%s", want, text)
}
