package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

// A scripted PostgreSQL peer, not a PostgreSQL server.
//
// It replays bytes a test chose, optionally performing a real TLS handshake, and
// records enough to prove svcdoctor used one socket for the whole exchange.
// Loopback rather than net.Pipe, because a TLS handshake over an unbuffered
// synchronous pipe deadlocks — the reason internal/probe/tls's fixtures already
// record.

// script says how the peer should behave on a connection.
type script struct {
	// sslReply is written in answer to the SSLRequest. Empty means read the
	// request and answer nothing.
	sslReply []byte

	// upgradeTLS performs a real server-side handshake after answering 'S'.
	upgradeTLS bool

	// afterStartup is written once a StartupMessage has been read.
	afterStartup []byte

	// expectNoSSLRequest makes the peer go straight to reading a startup packet,
	// which is how the plaintext plan is exercised.
	expectNoSSLRequest bool

	// hangBeforeReply blocks instead of answering, to exercise cancellation.
	hangBeforeReply bool
}

type pgPeer struct {
	addr netip.AddrPort
	cert cryptotls.Certificate
	ca   *x509.CertPool

	mu        sync.Mutex
	accepted  int
	startups  [][]byte
	localAddr []string
}

// newPGPeer starts a listener that serves one script.
func newPGPeer(t *testing.T, s script) *pgPeer {
	t.Helper()

	cert, pool := selfSigned(t)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr := netip.MustParseAddrPort(ln.Addr().String())
	p := &pgPeer{addr: addr, cert: cert, ca: pool}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			p.mu.Lock()
			p.accepted++
			p.localAddr = append(p.localAddr, conn.RemoteAddr().String())
			p.mu.Unlock()
			go p.serve(conn, s)
		}
	}()
	return p
}

func (p *pgPeer) serve(conn net.Conn, s script) {
	defer func() {
		time.Sleep(300 * time.Millisecond)
		_ = conn.Close()
	}()

	active := conn

	if !s.expectNoSSLRequest {
		var req [8]byte
		if !readExactly(conn, req[:]) {
			return
		}
		if s.hangBeforeReply {
			time.Sleep(5 * time.Second)
			return
		}
		if len(s.sslReply) == 0 {
			return
		}
		if _, err := conn.Write(s.sslReply); err != nil {
			return
		}
		if s.upgradeTLS {
			server := cryptotls.Server(conn, &cryptotls.Config{
				Certificates: []cryptotls.Certificate{p.cert},
				MinVersion:   cryptotls.VersionTLS12,
			})
			if err := server.HandshakeContext(context.Background()); err != nil {
				return
			}
			active = server
		}
	}

	if s.afterStartup == nil {
		return
	}

	// Read the startup packet: a four-byte length that includes itself.
	var header [4]byte
	if !readExactly(active, header[:]) {
		return
	}
	length := binary.BigEndian.Uint32(header[:])
	if length < 4 || length > 1<<16 {
		return
	}
	body := make([]byte, length-4)
	if !readExactly(active, body) {
		return
	}
	p.mu.Lock()
	p.startups = append(p.startups, append(header[:], body...))
	p.mu.Unlock()

	_, _ = active.Write(s.afterStartup)
	time.Sleep(300 * time.Millisecond)
}

func readExactly(conn net.Conn, buf []byte) bool {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return false
		}
	}
	return true
}

// connections returns how many sockets the peer accepted. One, for a whole
// negotiation, is what proves nothing redialled.
func (p *pgPeer) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

// clientPorts returns the remote address of every accepted connection, so a test
// can prove the same socket carried every step.
func (p *pgPeer) clientPorts() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.localAddr))
	copy(out, p.localAddr)
	return out
}

// waitForConnection blocks until the peer has accepted a connection, so a test
// can cancel at a known point rather than after a guessed sleep.
func (p *pgPeer) waitForConnection(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if p.connections() > 0 {
			time.Sleep(50 * time.Millisecond)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peer never accepted a connection")
}

// startupPackets returns the raw StartupMessages the peer read.
func (p *pgPeer) startupPackets() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([][]byte, len(p.startups))
	copy(out, p.startups)
	return out
}

// waitForStartup blocks until the peer has read a startup packet.
func (p *pgPeer) waitForStartup(t *testing.T) []byte {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if packets := p.startupPackets(); len(packets) > 0 {
			return packets[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peer never received a startup packet")
	return nil
}

// selfSigned issues a throwaway certificate for "localhost", generated in memory
// so no key or certificate is ever written to the repository.
func selfSigned(t *testing.T) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)

	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}, pool
}

// canaryHost is the logical name every fixture uses. It is deliberately
// identity-shaped, so a redaction test has something real to remove.
const canaryHost = "db-canary.payments.internal"

// canaryAddr is the address the transport nodes record. It is a documentation
// range address, never the loopback the fixture actually dials, so a test can
// tell the recorded subject apart from the socket.
const canaryAddr = "10.88.0.17"

// pathTo produces a real transport.Continuation for the peer.
//
// It goes through transport.Run with seams pointing at the fixture, exactly as
// the Kafka fixtures do, so the continuation the adapter receives is a genuine
// one and the ownership handoff under test is the real one. The DNS and TCP
// nodes it records are the ones a production run would record.
func pathTo(t *testing.T, p *pgPeer) (*transport.Continuation, *domain.GraphBuilder) {
	t.Helper()

	builder := domain.NewGraphBuilder()
	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     canaryHost,
		Port:     5432,
		Resolver: fixedResolver{addr: netip.MustParseAddr(canaryAddr)},
		Dialer:   peerDialer{target: p.addr},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	paths := result.Continuations()
	if len(paths) != 1 {
		t.Fatalf("transport produced %d paths, want 1", len(paths))
	}
	return paths[0], builder
}

// fixedResolver answers every lookup with one address, so the recorded subject
// is stable and is not the loopback the fixture dials.
type fixedResolver struct{ addr netip.Addr }

func (r fixedResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

// peerDialer sends every connection to the scripted peer, whatever address the
// chain asks for.
type peerDialer struct{ target netip.AddrPort }

func (d peerDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// graph freezes the builder or fails the test.
func freeze(t *testing.T, builder *domain.GraphBuilder) domain.Graph {
	t.Helper()
	g, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return g
}

// nodeFor returns the node for a step, and fails if it is absent.
func nodeFor(t *testing.T, g domain.Graph, step domain.Step) domain.Evidence {
	t.Helper()
	for _, n := range g.Nodes() {
		if n.Step() == step {
			return n
		}
	}
	t.Fatalf("no %s node in the graph", step)
	return domain.Evidence{}
}

// hasNode reports whether a step is present.
func hasNode(g domain.Graph, step domain.Step) bool {
	for _, n := range g.Nodes() {
		if n.Step() == step {
			return true
		}
	}
	return false
}
