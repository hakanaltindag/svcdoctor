package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// The chain is driven through the probes' own seams, so most tests need no
// network at all. The TLS paths need a real handshake, which needs a real
// socket: those use a loopback listener the test creates and closes, exactly as
// the TLS probe's own tests do.

const (
	testHost = "primary.internal"
	testPort = 9092
)

// --- resolver -------------------------------------------------------------

type fakeResolver struct {
	addrs   []netip.Addr
	err     error
	gotHost string
	calls   int
}

func (r *fakeResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	r.calls++
	r.gotHost = host
	return r.addrs, r.err
}

func resolving(t *testing.T, values ...string) *fakeResolver {
	t.Helper()

	addrs := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		addrs = append(addrs, addr)
	}
	return &fakeResolver{addrs: addrs}
}

// --- dialer ---------------------------------------------------------------

// countingConn counts closes so ownership assertions are facts rather than
// hopes, and records writes so a transferred connection can be shown to work.
type countingConn struct {
	net.Conn
	mu     sync.Mutex
	closes int
}

func (c *countingConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()

	err := c.Conn.Close()
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *countingConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

// scriptedDialer answers each address according to the script, and hands out
// connections the test can inspect afterwards.
type scriptedDialer struct {
	// refuse lists addresses that must fail, by address literal.
	refuse map[string]bool
	// err, when set, fails every dial.
	err error

	mu       sync.Mutex
	dialed   []netip.AddrPort
	conns    map[string]*countingConn
	listener net.Listener
}

func newScriptedDialer(t *testing.T, refuse ...string) *scriptedDialer {
	t.Helper()

	refused := make(map[string]bool, len(refuse))
	for _, r := range refuse {
		refused[r] = true
	}

	// A listener nobody speaks on: it exists only so that every "successful"
	// dial produces a genuine socket with a real lifetime.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()

	return &scriptedDialer{
		refuse:   refused,
		conns:    make(map[string]*countingConn),
		listener: ln,
	}
}

func (d *scriptedDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	d.mu.Unlock()

	if d.err != nil {
		return nil, d.err
	}
	if d.refuse[addr.Addr().String()] {
		return nil, refusedError(addr)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.listener.Addr().String())
	if err != nil {
		return nil, err
	}

	counted := &countingConn{Conn: conn}
	d.mu.Lock()
	d.conns[addr.Addr().String()] = counted
	d.mu.Unlock()
	return counted, nil
}

func (d *scriptedDialer) attempts() []netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netip.AddrPort(nil), d.dialed...)
}

func (d *scriptedDialer) conn(t *testing.T, address string) *countingConn {
	t.Helper()

	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.conns[address]
	if !ok {
		t.Fatalf("no connection was established to %s", address)
	}
	return c
}

func refusedError(addr netip.AddrPort) error {
	return &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: net.TCPAddrFromAddrPort(addr),
		Err:  os.NewSyscallError("connect", syscall.ECONNREFUSED),
	}
}

// --- TLS peer -------------------------------------------------------------

// tlsPeer is a real TLS server on loopback, plus the trust material a client
// needs to verify it.
type tlsPeer struct {
	addr netip.AddrPort
	pool *x509.CertPool
}

func newTLSPeer(t *testing.T, dnsNames []string) *tlsPeer {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor chain test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	cert := cryptotls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()

				server := cryptotls.Server(conn, &cryptotls.Config{
					Certificates: []cryptotls.Certificate{cert},
					MinVersion:   cryptotls.VersionTLS12,
				})
				if server.HandshakeContext(context.Background()) != nil {
					return
				}
				_, _ = io.Copy(server, server)
			}()
		}
	}()

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the peer address: %v", err)
	}
	return &tlsPeer{addr: addr, pool: pool}
}

// loopbackDialer connects every address to one real peer, so a chain sweeping
// several "addresses" exercises real handshakes without a network.
type loopbackDialer struct {
	target netip.AddrPort

	mu     sync.Mutex
	dialed []netip.AddrPort
	conns  []*countingConn
	refuse map[string]bool
}

func (d *loopbackDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	refused := d.refuse[addr.Addr().String()]
	d.mu.Unlock()

	if refused {
		return nil, refusedError(addr)
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

func (d *loopbackDialer) established() []*countingConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*countingConn(nil), d.conns...)
}

// --- graph helpers --------------------------------------------------------

func freeze(t *testing.T, builder *domain.GraphBuilder) domain.Graph {
	t.Helper()

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return graph
}

func node(t *testing.T, graph domain.Graph, id string) domain.Evidence {
	t.Helper()

	evidence, ok := graph.Node(domain.EvidenceID(id))
	if !ok {
		t.Fatalf("node %q is missing; graph holds %v", id, nodeIDs(graph))
	}
	return evidence
}

func nodeIDs(graph domain.Graph) []string {
	ids := make([]string, 0, graph.Len())
	for _, e := range graph.Nodes() {
		ids = append(ids, e.ID().String())
	}
	return ids
}

func run(t *testing.T, params Params) (*Result, domain.Graph) {
	t.Helper()

	builder := domain.NewGraphBuilder()
	result, err := Run(context.Background(), builder, params)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, freeze(t, builder)
}

// tcpParams is the common no-TLS setup.
func tcpParams(resolver *fakeResolver, dialer *scriptedDialer) Params {
	return Params{Host: testHost, Port: testPort, Resolver: resolver, Dialer: dialer}
}
