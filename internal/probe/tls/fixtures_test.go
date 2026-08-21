package tls

import (
	"context"
	"crypto"
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
	"sync"
	"testing"
	"time"
)

// Every fixture here is generated in memory and served by a listener the test
// creates on loopback. Nothing reaches the internet, no certificate or key is
// checked into the repository, and no external tool is invoked.
//
// # Why a loopback listener rather than net.Pipe
//
// net.Pipe is unbuffered and fully synchronous: both sides of a TLS handshake
// flush at the same moment, so each blocks writing while the other waits to
// write, and the handshake deadlocks. The standard library's own TLS tests use a
// real loopback connection for the same reason. A listener the test creates and
// closes is controlled, so this does not weaken the rule that no test may depend
// on an uncontrolled service — but it does mean these tests skip in an
// environment that forbids loopback sockets.

// testCA is a certificate authority that exists for the duration of one test.
type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// leafOptions describes the certificate a fixture server should present.
type leafOptions struct {
	dnsNames  []string
	ips       []net.IP
	notBefore time.Time
	notAfter  time.Time
}

func (ca *testCA) issue(t *testing.T, opts leafOptions) cryptotls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}

	notBefore, notAfter := opts.notBefore, opts.notAfter
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}

	commonName := "server.test"
	if len(opts.dnsNames) > 0 {
		commonName = opts.dnsNames[0]
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// peerBehaviour is what the far end of the fixture connection does.
type peerBehaviour int

const (
	// peerTLS runs a TLS server and echoes everything afterwards, so a test can
	// prove a transferred connection still carries bytes.
	peerTLS peerBehaviour = iota
	// peerPlaintext answers with bytes that are not a TLS record.
	peerPlaintext
	// peerSilent accepts the connection and never answers, so a handshake blocks
	// until the caller's context ends it.
	peerSilent
	// peerHangsUp accepts the connection and closes it immediately.
	peerHangsUp
)

// fixture is one controlled peer plus a connection to it.
type fixture struct {
	conn net.Conn
	addr netip.AddrPort
}

// dialFixture starts a controlled peer on loopback and returns a connection to
// it, standing in for the connection the TCP probe would have established.
func dialFixture(t *testing.T, behaviour peerBehaviour, serverCfg *cryptotls.Config) fixture {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// The peer connection is tracked so that cleanup can close it. Without that,
	// a test that legitimately keeps its end open — having taken ownership of it,
	// which is the whole point of this phase — would leave the echo goroutine
	// blocked on a read forever.
	var mu sync.Mutex
	var peer net.Conn

	served := make(chan struct{})
	go func() {
		defer close(served)

		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		mu.Lock()
		peer = conn
		mu.Unlock()
		defer func() { _ = conn.Close() }()

		switch behaviour {
		case peerPlaintext:
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		case peerSilent:
			// Hold the connection open without answering until the test ends.
			_, _ = io.Copy(io.Discard, conn)
		case peerHangsUp:
			// The deferred Close is the whole behaviour.
		case peerTLS:
			server := cryptotls.Server(conn, serverCfg)
			if handshakeErr := server.HandshakeContext(context.Background()); handshakeErr != nil {
				return
			}
			// Echo, so a transferred connection can be shown to still work.
			_, _ = io.Copy(server, server)
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		if peer != nil {
			_ = peer.Close()
		}
		mu.Unlock()
		<-served
	})

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dialing the fixture: %v", err)
	}

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the fixture address: %v", err)
	}
	return fixture{conn: conn, addr: addr}
}

// serverConfig builds the fixture server's configuration.
func serverConfig(cert cryptotls.Certificate, maxVersion uint16) *cryptotls.Config {
	return &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MaxVersion:   maxVersion,
		MinVersion:   cryptotls.VersionTLS12,
	}
}

// countingConn wraps a connection and counts its closes, which is what makes the
// ownership tests assertions rather than hopes.
type countingConn struct {
	net.Conn
	closes int
}

func (c *countingConn) Close() error {
	c.closes++
	err := c.Conn.Close()
	// A second close of an already-closed socket is not a leak; the count is
	// what the tests care about.
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// params returns the secure defaults for a fixture, trusting the fixture CA.
func (f fixture) params(ca *testCA, serverName string) Params {
	return Params{
		Endpoint:   "primary.internal:9092",
		Address:    f.addr,
		ServerName: serverName,
		RootCAs:    ca.pool,
	}
}
