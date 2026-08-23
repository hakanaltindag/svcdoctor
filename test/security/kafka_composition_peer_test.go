package security_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"
)

// The controlled network `app.DiagnoseKafka` is exercised over.
//
// # Why a fixture here rather than reuse
//
// `internal/adapter/kafka` has a richer fake broker, and it is unreachable from
// here: it lives in that package's own test files. Copying it would be worse
// than writing this, because these tests need something the adapter's fixture
// deliberately does not have — **a second, hostile peer holding a valid
// certificate for its own name**, which is the whole of ADR 0050 section 5's
// threat model and only becomes expressible once a composition root exists to
// hand a Metadata response to.
//
// Encoding goes through kmsg, as every Kafka fixture in this repository does, so
// these tests do not quietly become a second Kafka implementation. The precedent
// for kmsg in `test/security` is `kafka_auth_redaction_test.go`; the production
// rule that only a wire package may import it is unchanged.
//
// # What the counters mean, and why there are two kinds
//
// `appBytes` counts every byte a peer read **above its own TLS layer**. That is
// the unit a zero-transmission claim needs on an encrypted path: counting on
// svcdoctor's socket cannot express it, because closing a `*tls.Conn` writes a
// close_notify alert and moves a raw counter even when nothing was transmitted.
//
// `keysSeen` records the API key of every request the peer decoded, in order. It
// is the sharper assertion of the two wherever the question is *what* was sent
// rather than *whether* anything was: `[18 17]` says ApiVersions and
// SaslHandshake arrived and SaslAuthenticate did not, which is a stronger and
// more legible statement than a byte count nobody can read.
//
// Both are only trustworthy after the peer has finished consuming what
// svcdoctor sent, which is what awaitIdle is for.

// Kafka API keys, named so that an assertion reads as a protocol statement.
const (
	keyMetadata         int16 = 3
	keySASLHandshake    int16 = 17
	keyAPIVersions      int16 = 18
	keySASLAuthenticate int16 = 36
)

// SASL_AUTHENTICATION_FAILED, which is how a broker says the credential is wrong.
const errorCodeAuthFailed int16 = 58

// brokerEntry is one Metadata broker entry.
//
// Aliased so that the scenario file does not import the protocol library merely
// to name a slice type. The production rule that only a wire package may import
// kmsg is about production code; this keeps the test surface honest about where
// the dependency actually is.
type brokerEntry = kmsg.MetadataResponseBroker

// peerConfig is how a test says what its peer does.
type peerConfig struct {
	// serverName is the identity the peer's certificate carries. Empty means a
	// plaintext peer, which is how the channel-policy tests get an exact
	// zero-byte socket to assert on.
	serverName string

	// certificateFor overrides the name the certificate is issued for, so a test
	// can make a TLS handshake fail on identity rather than on trust.
	certificateFor string

	// mechanisms is what the peer says it offers at the handshake.
	mechanisms []string

	// rejectAuth makes the peer refuse the credential it is presented.
	rejectAuth bool

	// breakMetadata makes the peer hang up instead of describing the cluster.
	breakMetadata bool

	// advertised is the topology the peer describes.
	advertised []brokerEntry

	// silent makes the peer accept a connection and then never speak, which is
	// what a black-holed endpoint looks like to a bounded run.
	silent bool

	// hostile makes the peer read and count, and answer nothing at all. It is
	// the advertised endpoint an operator never named.
	hostile bool
}

// peer is a controlled Kafka endpoint on loopback.
type peer struct {
	addr netip.AddrPort
	cfg  peerConfig

	mu           sync.Mutex
	appBytes     int
	keysSeen     []int16
	saslPayloads [][]byte
	connections  int

	serving sync.WaitGroup
}

// authority issues the certificates a run trusts.
//
// One CA signs both the bootstrap peer and the hostile peer, deliberately. It is
// what makes the exfiltration test the real threat model rather than a weaker
// one: the attacker's certificate **verifies**, so nothing about the TLS result
// distinguishes it from the broker the operator asked for. TLS proves endpoint
// identity; it has no cluster-membership assertion to prove.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newAuthority(t *testing.T) *authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor composition test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the CA certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &authority{cert: cert, key: key, pool: pool}
}

// issue mints a leaf certificate for one DNS name. Nothing touches disk: a
// fixture key on disk is a key somebody eventually trusts.
func (a *authority) issue(t *testing.T, name string) cryptotls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("creating a leaf certificate for %s: %v", name, err)
	}
	return cryptotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newPeer starts a controlled endpoint and returns it.
func newPeer(t *testing.T, ca *authority, cfg peerConfig) *peer {
	t.Helper()

	if cfg.mechanisms == nil {
		cfg.mechanisms = []string{"PLAIN"}
	}

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
	p := &peer{addr: addr, cfg: cfg}

	var serverTLS *cryptotls.Config
	if cfg.serverName != "" {
		name := cfg.serverName
		if cfg.certificateFor != "" {
			name = cfg.certificateFor
		}
		serverTLS = &cryptotls.Config{
			Certificates: []cryptotls.Certificate{ca.issue(t, name)},
			MinVersion:   cryptotls.VersionTLS12,
		}
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			p.mu.Lock()
			p.connections++
			p.mu.Unlock()

			if serverTLS != nil {
				conn = cryptotls.Server(conn, serverTLS)
			}
			p.serving.Add(1)
			go func() {
				defer p.serving.Done()
				p.serve(conn)
			}()
		}
	}()
	return p
}

// serve answers requests until the peer stops asking.
func (p *peer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if p.cfg.silent {
		// Accept, and say nothing. A bounded run records a local timeout, which
		// is the UNKNOWN this fixture exists to produce.
		<-time.After(30 * time.Second)
		return
	}

	for {
		request, ok := p.readRequest(conn)
		if !ok {
			return
		}
		if p.cfg.hostile {
			// A hostile endpoint reads and counts. Answering would let a test
			// pass because the peer declined rather than because svcdoctor did.
			continue
		}
		payload, keep := p.respond(request)
		if !keep {
			return
		}
		if !writeFrame(conn, payload) {
			return
		}
	}
}

// respond builds the answer to one request.
func (p *peer) respond(request peerRequest) ([]byte, bool) {
	prefix := correlation(request.correlationID)

	switch request.key {
	case keyAPIVersions:
		response := kmsg.NewPtrApiVersionsResponse()
		response.SetVersion(0)
		for _, spec := range [][3]int16{{keyAPIVersions, 0, 3}, {keyMetadata, 0, 12}} {
			entry := kmsg.NewApiVersionsResponseApiKey()
			entry.ApiKey, entry.MinVersion, entry.MaxVersion = spec[0], spec[1], spec[2]
			response.ApiKeys = append(response.ApiKeys, entry)
		}
		return response.AppendTo(prefix), true

	case keySASLHandshake:
		response := kmsg.NewPtrSASLHandshakeResponse()
		response.SetVersion(1)
		response.SupportedMechanisms = p.cfg.mechanisms
		return response.AppendTo(prefix), true

	case keySASLAuthenticate:
		p.recordSASL(request.body)
		response := kmsg.NewPtrSASLAuthenticateResponse()
		response.SetVersion(1)
		response.SessionLifetimeMillis = 3_600_000
		if p.cfg.rejectAuth {
			response.ErrorCode = errorCodeAuthFailed
		}
		return response.AppendTo(prefix), true

	case keyMetadata:
		if p.cfg.breakMetadata {
			return nil, false // hang up mid-exchange
		}
		response := kmsg.NewPtrMetadataResponse()
		response.SetVersion(1)
		response.ControllerID = -1
		response.Brokers = p.cfg.advertised
		return response.AppendTo(prefix), true

	default:
		return nil, false
	}
}

// recordSASL keeps the authentication payload that arrived, so that a test can
// prove a credential really travelled to the bootstrap endpoint before proving
// it travelled nowhere else.
func (p *peer) recordSASL(body []byte) {
	decoded := kmsg.NewPtrSASLAuthenticateRequest()
	decoded.SetVersion(1)
	if err := decoded.ReadFrom(body); err != nil {
		return
	}
	p.mu.Lock()
	p.saslPayloads = append(p.saslPayloads, append([]byte(nil), decoded.SASLAuthBytes...))
	p.mu.Unlock()
}

// peerRequest is one decoded request header plus the body that followed it.
type peerRequest struct {
	key           int16
	correlationID uint32
	body          []byte
}

// readRequest consumes one framed request, counting every byte it reads.
//
// The byte count is taken before the frame is validated, so a write that never
// forms a legal Kafka request still moves it. That matters: a careless write of
// credential material is exactly that shape, and a counter that only saw
// well-formed requests would report zero for it.
func (p *peer) readRequest(conn net.Conn) (peerRequest, bool) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return peerRequest{}, false
	}
	p.countBytes(len(sizeBuf))

	size := int64(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 8 || size > 1<<20 {
		return peerRequest{}, false
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		p.countBytes(len(raw))
		return peerRequest{}, false
	}
	p.countBytes(len(raw))

	//nolint:gosec // G115: a Kafka api key is an int16 on the wire by definition.
	request := peerRequest{
		key:           int16(binary.BigEndian.Uint16(raw[0:2])),
		correlationID: binary.BigEndian.Uint32(raw[4:8]),
	}

	// apiKey, apiVersion, correlationID, then the nullable client id.
	rest := raw[8:]
	if len(rest) < 2 {
		return peerRequest{}, false
	}
	//nolint:gosec // G115: a nullable string length is an int16 on the wire.
	clientIDLen := int16(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if clientIDLen > 0 {
		if int(clientIDLen) > len(rest) {
			return peerRequest{}, false
		}
		rest = rest[clientIDLen:]
	}
	request.body = rest

	p.mu.Lock()
	p.keysSeen = append(p.keysSeen, request.key)
	p.mu.Unlock()

	return request, true
}

func (p *peer) countBytes(n int) {
	p.mu.Lock()
	p.appBytes += n
	p.mu.Unlock()
}

func writeFrame(conn net.Conn, payload []byte) bool {
	if len(payload) > math.MaxInt32 {
		return false
	}
	framed := make([]byte, 4, 4+len(payload))
	//nolint:gosec // G115: the guard above bounds the length; a frame prefix has no other form.
	binary.BigEndian.PutUint32(framed, uint32(len(payload)))
	_, err := conn.Write(append(framed, payload...))
	return err == nil
}

func correlation(id uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, id)
	return out
}

// --- observation ------------------------------------------------------------

// awaitIdle waits until every serving goroutine has finished reading.
//
// Without it the counters below are a poll rather than a proof: a test could
// read `appBytes` before the peer had consumed what svcdoctor sent and conclude
// that nothing was sent. The run closes every connection it opened, so the
// serving goroutines end on their own once DiagnoseKafka has returned.
func (p *peer) awaitIdle(t *testing.T) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		p.serving.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the peer never finished serving; a connection was not closed")
	}
}

func (p *peer) bytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.appBytes
}

func (p *peer) keys() []int16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int16(nil), p.keysSeen...)
}

func (p *peer) sasl() [][]byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([][]byte(nil), p.saslPayloads...)
}

func (p *peer) connectionCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connections
}

// --- the network seams ------------------------------------------------------

// tableResolver answers from a fixed table, so a hostname the cluster advertises
// resolves exactly as the test says and never as the machine says.
type tableResolver map[string][]netip.Addr

func (r tableResolver) LookupAddresses(_ context.Context, host string) ([]netip.Addr, error) {
	answers, ok := r[host]
	if !ok || len(answers) == 0 {
		return nil, nil
	}
	return answers, nil
}

// route is what one synthetic address does when it is dialled.
type route struct {
	// to is the real listener this address reaches. The zero value means the
	// address refuses.
	to netip.AddrPort
}

// routingDialer maps synthetic addresses onto real loopback listeners and
// records every connection it hands out.
//
// It exists because the composition dials `resolvedAddress:port`, and a test
// that needs two bootstrap addresses cannot rely on 127.0.0.2 being bound —
// it is on Linux and is not on macOS. Routing removes the platform from the
// test, and it buys the ownership ledger below for free.
type routingDialer struct {
	routes map[netip.Addr]route

	mu    sync.Mutex
	conns []*ledgerConn
}

func (d *routingDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	target, known := d.routes[addr.Addr()]
	if !known || !target.to.IsValid() {
		return nil, &net.OpError{
			Op: "dial", Net: "tcp",
			Err: errors.New("connection refused"),
		}
	}
	// The route names a real listener outright, port included, so a bootstrap
	// address and an advertised address can reach different peers even though
	// the composition derives their ports from different places.
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.to.String())
	if err != nil {
		return nil, err
	}
	tracked := &ledgerConn{Conn: conn}

	d.mu.Lock()
	d.conns = append(d.conns, tracked)
	d.mu.Unlock()

	return tracked, nil
}

// bytesWrittenByClient totals what svcdoctor wrote to every socket this dialer
// handed out.
//
// **It is only meaningful on a plaintext path**, which is why the two callers are
// both plaintext scenarios. On a TLS path closing a `*tls.Conn` emits a
// close_notify alert through this counter, so a run that transmitted nothing
// still moves it — the reason peer-side `appBytes`, measured above TLS, exists.
//
// On plaintext it buys something the peer counter cannot: the peer counts what
// **arrived and was read**, so a write that never forms a legal frame, or that
// the peer never gets to, is invisible there. Comparing the two proves svcdoctor
// wrote exactly what the peer consumed and not one byte more.
func (d *routingDialer) bytesWrittenByClient() int {
	total := 0
	for _, c := range d.ledger() {
		total += c.bytesWritten()
	}
	return total
}

// ledger returns the connections this dialer created.
func (d *routingDialer) ledger() []*ledgerConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]*ledgerConn(nil), d.conns...)
}

// requireBalanced asserts that every connection the run opened was closed, and
// that nothing was written to one after it was closed.
//
// It is the ownership assertion in its observable form. `defer` inspection
// proves that a close was *written*; this proves one *happened*, on every path
// out of the composition including the ones a test did not think of.
func (d *routingDialer) requireBalanced(t *testing.T) {
	t.Helper()

	for i, conn := range d.ledger() {
		if conn.closes() == 0 {
			t.Errorf("connection %d was opened and never closed", i)
		}
		if conn.writesAfterClose() != 0 {
			t.Errorf("connection %d was written to %d times after it was closed",
				i, conn.writesAfterClose())
		}
	}
}

// ledgerConn records what happened to one connection.
type ledgerConn struct {
	net.Conn

	mu               sync.Mutex
	closeCount       int
	written          int
	writtenAfterShut int
}

func (c *ledgerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	closed := c.closeCount > 0
	c.mu.Unlock()

	n, err := c.Conn.Write(p)

	c.mu.Lock()
	c.written += n
	if closed {
		c.writtenAfterShut += n
	}
	c.mu.Unlock()

	return n, err
}

func (c *ledgerConn) Close() error {
	c.mu.Lock()
	c.closeCount++
	c.mu.Unlock()

	err := c.Conn.Close()
	if err != nil && errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func (c *ledgerConn) closes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCount
}

func (c *ledgerConn) bytesWritten() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written
}

func (c *ledgerConn) writesAfterClose() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writtenAfterShut
}

// advertise builds one Metadata broker entry.
func advertise(nodeID int32, host string, port int32) brokerEntry {
	entry := kmsg.NewMetadataResponseBroker()
	entry.NodeID, entry.Host, entry.Port = nodeID, host, port
	return entry
}
