package kafka

import (
	"context"
	cryptotls "crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// The reachability fixtures answer a different question from the broker fixture
// above them. That one is a Kafka peer: it decodes requests and replies. This one
// deliberately is not, because the property under test is that svcdoctor sends a
// discovered endpoint no protocol bytes at all — so the peer counts what arrives
// and would fail loudly if anything did.
//
// Everything runs over loopback listeners the test creates and closes.

// --- the advertised endpoint ------------------------------------------------

// advertisedPeer stands in for a discovered broker: it accepts connections,
// optionally completes TLS, and reads whatever follows.
//
// It speaks no Kafka. A single application byte reaching it is a failure of the
// one-hop boundary, which is why the byte counter exists and why nothing here
// can answer an ApiVersions request even if one arrived.
type advertisedPeer struct {
	addr netip.AddrPort

	// pool is the only trust source that verifies this peer's certificate, and
	// is nil for a plaintext peer.
	pool *x509.CertPool

	mu       sync.Mutex
	accepted int
	appBytes int

	// serving tracks the read loops, so a test can wait until everything
	// svcdoctor ever wrote has been read before asserting that it wrote nothing.
	serving sync.WaitGroup
}

// newAdvertisedPeer starts a plaintext peer.
func newAdvertisedPeer(t *testing.T) *advertisedPeer {
	t.Helper()

	return startAdvertisedPeer(t, nil, nil)
}

// newAdvertisedTLSPeer starts a peer that speaks TLS first, with a certificate
// generated in memory for serverName.
//
// The returned peer's pool is the only trust source that verifies it, so a run
// that verifies is verifying something real rather than trusting the machine.
func newAdvertisedTLSPeer(t *testing.T, serverName string) *advertisedPeer {
	t.Helper()

	cert, pool := brokerCertificate(t, serverName)
	return startAdvertisedPeer(t, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS12,
	}, pool)
}

func startAdvertisedPeer(
	t *testing.T, serverTLS *cryptotls.Config, pool *x509.CertPool,
) *advertisedPeer {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the peer address: %v", err)
	}

	peer := &advertisedPeer{addr: addr, pool: pool}
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			// The read loop is registered before the connection is counted, so
			// that observing the count under the mutex proves every registration
			// has already happened. The other order lets awaitIdle start waiting
			// while an accepted connection is still being registered, which is
			// the one way a WaitGroup can be misused.
			peer.serving.Add(1)

			peer.mu.Lock()
			peer.accepted++
			peer.mu.Unlock()

			if serverTLS != nil {
				conn = cryptotls.Server(conn, serverTLS)
			}
			go func() {
				defer peer.serving.Done()
				defer func() { _ = conn.Close() }()
				peer.read(conn)
			}()
		}
	}()
	return peer
}

// read consumes everything the peer is sent, above TLS where there is TLS.
//
// Counting here rather than on svcdoctor's own socket is what makes a zero
// meaningful: closing a *tls.Conn writes a close_notify alert, so a raw byte
// counter on the client side would move even when the protocol layer sent
// nothing.
func (p *advertisedPeer) read(conn net.Conn) {
	buffer := make([]byte, 512)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			p.mu.Lock()
			p.appBytes += n
			p.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// awaitAccepted blocks until the peer has accepted want connections.
//
// It exists because this peer is never spoken to: svcdoctor connects and closes,
// so there is no reply a test could have waited for, and reading a counter
// straight after the run would race the accept loop. Waiting for the expected
// count first is what turns the assertions that follow into proofs rather than
// observations of an unfinished peer.
func (p *advertisedPeer) awaitAccepted(t *testing.T, want int) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		p.mu.Lock()
		got := p.accepted
		p.mu.Unlock()
		if got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the advertised peer accepted %d connections, want %d", got, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// awaitIdle blocks until every accepted connection's read loop has exited.
//
// A read loop exits when svcdoctor closes its end, so after this returns two
// things are simultaneously true: every byte that was ever written has been read
// and counted, and no connection to this peer is still open. Call awaitAccepted
// first, so that every loop this waits for has actually started.
func (p *advertisedPeer) awaitIdle() { p.serving.Wait() }

// appBytesRead reports how many bytes svcdoctor's protocol layer sent this peer.
// Read it after awaitIdle; the expected answer everywhere is zero.
func (p *advertisedPeer) appBytesRead() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.appBytes
}

func (p *advertisedPeer) acceptedCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

// --- transport seams --------------------------------------------------------

// hostResolver answers per hostname, so one run can measure several advertised
// names with different answers — including two names that resolve to one
// address, and a name that does not resolve at all.
type hostResolver struct {
	answers  map[string][]netip.Addr
	failures map[string]error

	mu      sync.Mutex
	queried []string
}

func newHostResolver() *hostResolver {
	return &hostResolver{
		answers:  map[string][]netip.Addr{},
		failures: map[string]error{},
	}
}

// resolving records that host answers with addresses.
func (r *hostResolver) resolving(t *testing.T, host string, addresses ...string) *hostResolver {
	t.Helper()

	r.answers[host] = parseAddrs(t, addresses)
	return r
}

// failing records that host does not resolve.
func (r *hostResolver) failing(host string, err error) *hostResolver {
	r.failures[host] = err
	return r
}

func (r *hostResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	r.queried = append(r.queried, host)
	r.mu.Unlock()

	if err, ok := r.failures[host]; ok {
		return nil, err
	}
	return r.answers[host], nil
}

// lookups returns every hostname this resolver was asked about, in order.
func (r *hostResolver) lookups() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queried...)
}

// advertisedDialer routes every address to one loopback peer, so a run that
// sweeps several "addresses" exercises real sockets without a network.
type advertisedDialer struct {
	target netip.AddrPort

	// refuse lists addresses that must fail, by address literal.
	refuse map[string]bool

	mu     sync.Mutex
	dialed []netip.AddrPort
	conns  []*countingConn
}

func newAdvertisedDialer(peer *advertisedPeer, refuse ...string) *advertisedDialer {
	refused := make(map[string]bool, len(refuse))
	for _, address := range refuse {
		refused[address] = true
	}
	return &advertisedDialer{target: peer.addr, refuse: refused}
}

func (d *advertisedDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	refused := d.refuse[addr.Addr().String()]
	d.mu.Unlock()

	if refused {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.target.String())
	if err != nil {
		return nil, err
	}

	counted := &countingConn{Conn: conn}
	d.mu.Lock()
	d.conns = append(d.conns, counted)
	d.mu.Unlock()
	return counted, nil
}

// attempts returns every address this dialer was asked to reach, in order.
func (d *advertisedDialer) attempts() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.AddrPort(nil), d.dialed...)
}

// established returns every socket this dialer produced, so a test can count
// closes rather than trust them.
func (d *advertisedDialer) established() []*countingConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*countingConn(nil), d.conns...)
}

// --- prepared topologies ----------------------------------------------------

// advertisedTarget is a completed run: the bootstrap chain measured and
// authenticated, one Metadata exchange performed, and the advertisements it
// carried ready to be measured.
type advertisedTarget struct {
	*topologyTarget

	brokers []DiscoveredBroker
}

// discoveredTopology runs the real chain to an authenticated session, discovers
// the advertised brokers, and hands back what Phase 3.4 consumes.
//
// Nothing is hand-made. A hand-built DiscoveredBroker would carry an evidence
// identifier nobody recorded, and the derivation edge — the thing this phase is
// for — would then be asserted against a node that does not exist.
func discoveredTopology(t *testing.T, advertised ...kmsg.MetadataResponseBroker) *advertisedTarget {
	t.Helper()

	target := authenticatedTarget(t, withAdvertisedBrokers(advertised...))
	result := discover(t, target, MetadataParams{})

	return &advertisedTarget{topologyTarget: target, brokers: result.Brokers()}
}

// measure runs Phase 3.4 over the discovered advertisements.
func measure(t *testing.T, target *advertisedTarget, plan TransportPlan) *MeasurementResult {
	t.Helper()

	return measureWith(t.Context(), t, target, plan)
}

// measureWith is measure with a caller-supplied context, for the budget tests.
func measureWith(
	ctx context.Context, t *testing.T, target *advertisedTarget, plan TransportPlan,
) *MeasurementResult {
	t.Helper()

	result, err := MeasureAdvertised(ctx, target.builder, target.brokers, plan)
	if err != nil {
		t.Fatalf("MeasureAdvertised: unexpected error: %v", err)
	}
	return result
}

// tcpPlan is the common no-TLS transport plan.
func tcpPlan(resolver *hostResolver, dialer *advertisedDialer) TransportPlan {
	return TransportPlan{Resolver: resolver, Dialer: dialer}
}

// tlsPlan asks for a verified handshake against the peer's own trust material.
func tlsPlan(
	resolver *hostResolver, dialer *advertisedDialer, peer *advertisedPeer,
) TransportPlan {
	return TransportPlan{
		Resolver: resolver,
		Dialer:   dialer,
		TLS:      &transport.TLSOptions{RootCAs: peer.pool},
	}
}

// --- graph helpers ----------------------------------------------------------

// sweepScopes returns the distinct scope labels present in the graph, read out
// of the DNS nodes' identifiers.
//
// It is the one place in these tests that looks at a scope at all, and it does
// so by matching identifiers that were minted from a known advertisement rather
// than by parsing one. Nothing in production reads a scope back.
func sweepScopes(t *testing.T, target *advertisedTarget) []string {
	t.Helper()

	scopes := make([]string, 0, len(target.brokers))
	for _, broker := range target.brokers {
		if _, usable := broker.Endpoint(); !usable {
			continue
		}
		scope, err := advertisedScope(broker.Evidence())
		if err != nil {
			t.Fatalf("advertisedScope: %v", err)
		}
		scopes = append(scopes, scope.String())
	}
	return scopes
}

// scopedLookupID is the identifier the sweep caused by broker must have minted
// for its DNS node.
func scopedLookupID(t *testing.T, broker DiscoveredBroker) string {
	t.Helper()

	scope, err := advertisedScope(broker.Evidence())
	if err != nil {
		t.Fatalf("advertisedScope: %v", err)
	}
	return "dns.lookup/" + scope.String() + "/" + broker.Host()
}

// scopedConnectID is the same for the TCP node of one resolved address.
func scopedConnectID(t *testing.T, broker DiscoveredBroker, address string) string {
	t.Helper()

	scope, err := advertisedScope(broker.Evidence())
	if err != nil {
		t.Fatalf("advertisedScope: %v", err)
	}
	endpoint, _ := broker.Endpoint()
	return "tcp.connect/" + scope.String() + "/" + endpoint + "/" + address
}

// scopedHandshakeID is the same for the TLS node of one resolved address.
func scopedHandshakeID(t *testing.T, broker DiscoveredBroker, address string) string {
	t.Helper()

	scope, err := advertisedScope(broker.Evidence())
	if err != nil {
		t.Fatalf("advertisedScope: %v", err)
	}
	endpoint, _ := broker.Endpoint()
	return "tls.handshake/" + scope.String() + "/" + endpoint + "/" + address
}

// brokerByNode returns the advertisement for one node identifier.
func brokerByNode(t *testing.T, target *advertisedTarget, nodeID int32, host string) DiscoveredBroker {
	t.Helper()

	for _, broker := range target.brokers {
		if broker.NodeID() == nodeID && broker.Host() == host {
			return broker
		}
	}
	t.Fatalf("no advertisement for node %d at %s", nodeID, host)
	return DiscoveredBroker{}
}

// nodesWithStep returns every node in the graph produced by one step.
func nodesWithStep(graph domain.Graph, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == step {
			out = append(out, evidence)
		}
	}
	return out
}

// advertisedNodesWithStep is nodesWithStep restricted to the nodes an advertised
// sweep produced.
//
// The bootstrap chain runs DNS, TCP and TLS too, so a graph-wide count would mix
// the two and pass for the wrong reason. Scoped identifiers are how the two are
// told apart, which is what the scope is for.
func advertisedNodesWithStep(graph domain.Graph, step domain.Step) []domain.Evidence {
	var out []domain.Evidence
	for _, evidence := range nodesWithStep(graph, step) {
		if strings.Contains(evidence.ID().String(), advertisedScopePrefix) {
			out = append(out, evidence)
		}
	}
	return out
}
