package kafka

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

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The peer here answers just enough Kafka to exercise ApiVersions, and it uses
// kmsg to encode rather than hand-written bytes, so the tests do not quietly
// become a second Kafka implementation. Everything runs over a loopback listener
// the test creates and closes: no broker, no container, no network.

// peerBehaviour is what the fake broker does with a request.
type peerBehaviour int

const (
	// peerAnswers replies with a well-formed ApiVersions response.
	peerAnswers peerBehaviour = iota
	// peerAnswersWithError replies with a well-formed response carrying a
	// broker-side error code.
	peerAnswersWithError
	// peerHangsUp closes the connection without answering.
	peerHangsUp
	// peerSpeaksHTTP answers with something that is not Kafka framing.
	peerSpeaksHTTP
	// peerSendsGarbage answers with plausible framing and an undecodable body.
	peerSendsGarbage
	// peerMisscorrelates answers a different request than the one sent.
	peerMisscorrelates
	// peerSaysNothing keeps the connection open and never answers.
	peerSaysNothing
)

// advertised is the API set the fake broker announces, deliberately out of
// order so the canonical ordering can be shown to be svcdoctor's doing.
func advertised() []kmsg.ApiVersionsResponseApiKey {
	keys := make([]kmsg.ApiVersionsResponseApiKey, 0, 3)
	for _, spec := range []struct{ key, min, max int16 }{
		{18, 0, 3}, // ApiVersions
		{3, 0, 12}, // Metadata
		{1, 0, 13}, // Fetch
	} {
		key := kmsg.NewApiVersionsResponseApiKey()
		key.ApiKey = spec.key
		key.MinVersion = spec.min
		key.MaxVersion = spec.max
		keys = append(keys, key)
	}
	return keys
}

// countingConn counts closes so ownership assertions are facts.
//
// It deliberately does not count bytes written. Counting them here cannot
// express "nothing was transmitted" on a TLS path: closing a *tls.Conn writes a
// close_notify alert through this socket, so a refusal that sent nothing still
// moves the counter. The zero-byte claims are measured on the peer instead,
// above its TLS layer — see broker.appBytes.
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

const (
	// defaultErrorCode is what peerAnswersWithError reports unless a test asks
	// for another. 35 is UNSUPPORTED_VERSION, the one code the protocol defines
	// for an ApiVersions response.
	defaultErrorCode int16 = 35

	// Request keys the fixture answers.
	apiKeyAPIVersions      int16 = 18
	apiKeySASLHandshake    int16 = 17
	apiKeySASLAuthenticate int16 = 36

	// saslHandshakeFixtureVersion is the response version the fixture encodes.
	// It matches what the adapter asks for, and a test pins that they agree.
	saslHandshakeFixtureVersion int16 = 1

	// saslAuthenticateFixtureVersion is the same for authentication.
	saslAuthenticateFixtureVersion int16 = 1

	// errorCodeSASLAuthenticationFailedFixture is what a broker answers when it
	// evaluated a credential and refused it.
	errorCodeSASLAuthenticationFailedFixture int16 = 58
)

// defaultMechanisms is what the fake broker offers, deliberately out of
// alphabetical order so canonical ordering can be shown to be svcdoctor's doing.
func defaultMechanisms() []string {
	return []string{"SCRAM-SHA-512", "PLAIN", "SCRAM-SHA-256"}
}

// broker is a fake Kafka peer on loopback.
type broker struct {
	addr      netip.AddrPort
	behaviour peerBehaviour
	errorCode int16

	sasl           peerBehaviour
	saslErrorCode  int16
	saslMechanisms []string

	auth                peerBehaviour
	authErrorCode       int16
	authErrorMessage    string
	authSessionLifetime int64

	// serverTLS is nil for a plaintext broker. When set, every accepted
	// connection is wrapped before any Kafka byte is read, so a path through
	// this broker is a real TLS path.
	serverTLS *cryptotls.Config

	mu                 sync.Mutex
	requests           int
	saslRequests       int
	saslMechanismsSeen []string
	saslPayloads       [][]byte
	clientIDs          []string

	authRequests     int
	authPayloads     [][]byte
	authVersionsSeen []int16

	// appBytes counts the request bytes this peer has consumed, above TLS.
	//
	// It is the unit the zero-byte claims need. Counting on svcdoctor's own
	// socket cannot express it on a TLS path: closing a *tls.Conn writes a
	// close_notify alert, so a refusal that transmitted nothing still moves a
	// raw byte counter by the size of that alert. Counted here, after the
	// server's TLS layer has decrypted, the number is exactly what svcdoctor's
	// protocol layer sent — and awaitIdle is what makes reading it a proof
	// rather than a poll.
	appBytes int

	// serving tracks the goroutines reading from accepted connections, so that
	// a test can wait for the peer to have consumed everything svcdoctor ever
	// sent before asserting that it sent nothing. See awaitIdle.
	serving sync.WaitGroup
}

// brokerOption configures a fixture broker before its listener starts, so that
// nothing the serving goroutine reads is ever written afterwards.
type brokerOption func(*broker)

// withErrorCode makes the ApiVersions answer carry code.
func withErrorCode(code int16) brokerOption {
	return func(b *broker) { b.errorCode = code }
}

// withSASL sets how the broker reacts to a SaslHandshake.
func withSASL(behaviour peerBehaviour) brokerOption {
	return func(b *broker) { b.sasl = behaviour }
}

// withSASLError makes the handshake answer carry code.
func withSASLError(code int16) brokerOption {
	return func(b *broker) {
		b.sasl = peerAnswersWithError
		b.saslErrorCode = code
	}
}

// withMechanisms replaces what the broker says it offers.
func withMechanisms(mechanisms ...string) brokerOption {
	return func(b *broker) { b.saslMechanisms = mechanisms }
}

// withAuth sets how the broker reacts to a SaslAuthenticate.
func withAuth(behaviour peerBehaviour) brokerOption {
	return func(b *broker) { b.auth = behaviour }
}

// withAuthError makes the authentication answer carry code, which is how a
// fixture says "these credentials are wrong".
func withAuthError(code int16) brokerOption {
	return func(b *broker) {
		b.auth = peerAnswersWithError
		b.authErrorCode = code
	}
}

// withAuthErrorMessage makes the broker attach prose to its rejection.
//
// It exists to be given a canary: a real broker writes this field itself, and
// what it writes routinely names principals, listeners and internal hosts.
func withAuthErrorMessage(message string) brokerOption {
	return func(b *broker) { b.authErrorMessage = message }
}

// withSessionLifetime sets what the broker says about how long the
// authentication stays valid.
func withSessionLifetime(millis int64) brokerOption {
	return func(b *broker) { b.authSessionLifetime = millis }
}

// newErrorBroker answers every ApiVersions request with a well-formed response
// carrying code, so a test can pin what one specific broker error code
// classifies as.
func newErrorBroker(t *testing.T, code int16) *broker {
	t.Helper()

	return newBroker(t, peerAnswersWithError, withErrorCode(code))
}

func newBroker(t *testing.T, behaviour peerBehaviour, options ...brokerOption) *broker {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("parsing the broker address: %v", err)
	}
	b := &broker{
		addr:           addr,
		behaviour:      behaviour,
		errorCode:      defaultErrorCode,
		sasl:           peerAnswers,
		saslErrorCode:  errorCodeUnsupportedSASLMechanism,
		saslMechanisms: defaultMechanisms(),
		auth:           peerAnswers,
		authErrorCode:  errorCodeSASLAuthenticationFailedFixture,
	}
	for _, option := range options {
		option(b)
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			if b.serverTLS != nil {
				conn = cryptotls.Server(conn, b.serverTLS)
			}
			b.serving.Add(1)
			go func() {
				defer b.serving.Done()
				b.serve(conn)
			}()
		}
	}()
	return b
}

// newTLSBroker is a fake Kafka peer that speaks TLS first.
//
// It exists so that a test can prove the channel fact travels from a real
// handshake all the way to a HandshakeSession. The certificate is generated in
// memory for serverName and the returned pool is the only trust source that
// verifies it, so a run that verifies is verifying something real.
func newTLSBroker(t *testing.T, serverName string, options ...brokerOption) (*broker, *x509.CertPool) {
	t.Helper()

	cert, pool := brokerCertificate(t, serverName)
	options = append(options, func(b *broker) {
		b.serverTLS = &cryptotls.Config{
			Certificates: []cryptotls.Certificate{cert},
			MinVersion:   cryptotls.VersionTLS12,
		}
	})
	return newBroker(t, peerAnswers, options...), pool
}

// brokerCertificate generates a throwaway CA and leaf for serverName. Nothing
// touches disk: a fixture key on disk is a key somebody eventually trusts.
func brokerCertificate(t *testing.T, serverName string) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor kafka test ca"},
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
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{serverName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return cryptotls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pool
}

// serve answers requests until the peer stops asking.
//
// It is a loop rather than a single exchange because one connection now carries
// several: ApiVersions and then SaslHandshake. A fixture that closed after the
// first would make every "the adapter did not redial" assertion pass for the
// wrong reason.
func (b *broker) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	for {
		request, err := b.readRequest(conn)
		if err != nil {
			return
		}
		if !b.answer(conn, request) {
			return
		}
	}
}

// answer replies to one request and reports whether the connection continues.
func (b *broker) answer(conn net.Conn, request brokerRequest) bool {
	switch request.key {
	case apiKeyAPIVersions:
		b.count(&b.requests)
		return b.react(conn, b.behaviour, request, b.apiVersionsResponse)
	case apiKeySASLHandshake:
		b.count(&b.saslRequests)
		b.recordMechanism(request)
		return b.react(conn, b.sasl, request, b.saslHandshakeResponse)
	case apiKeySASLAuthenticate:
		b.count(&b.authRequests)
		b.recordAuthPayload(request)
		return b.react(conn, b.auth, request, b.saslAuthenticateResponse)
	default:
		return false
	}
}

// react applies one behaviour to one request. encode builds the well-formed
// answer for whichever request kind is being served.
func (b *broker) react(
	conn net.Conn,
	behaviour peerBehaviour,
	request brokerRequest,
	encode func(correlationID uint32) []byte,
) bool {
	switch behaviour {
	case peerHangsUp:
		return false
	case peerSaysNothing:
		// Hold the connection open until the client gives up or goes away.
		_, _ = io.Copy(io.Discard, conn)
		return false
	case peerSpeaksHTTP:
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		return false
	case peerSendsGarbage:
		body := append(correlationBytes(request.correlationID), 0xff, 0xff, 0xff)
		_, _ = conn.Write(frame(body))
		return false
	case peerMisscorrelates:
		_, _ = conn.Write(frame(encode(request.correlationID + 1000)))
		return false
	case peerAnswers, peerAnswersWithError:
		_, _ = conn.Write(frame(encode(request.correlationID)))
		return true
	}
	return false
}

// brokerRequest is one decoded request header plus the body that followed it.
type brokerRequest struct {
	key           int16
	version       int16
	correlationID uint32
	clientID      string
	payload       []byte
}

// readRequest consumes one framed request and decodes its header.
//
// The header is parsed by hand because the fixture is the peer: it has to see
// exactly what svcdoctor put on the wire, including the client identifier, which
// is the only place a test can prove svcdoctor names itself honestly.
func (b *broker) readRequest(conn net.Conn) (brokerRequest, error) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return brokerRequest{}, err
	}
	size := int64(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 8 || size > 1<<20 {
		return brokerRequest{}, errors.New("implausible request size")
	}

	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return brokerRequest{}, err
	}
	b.countAppBytes(4 + len(body))

	// apiKey int16, apiVersion int16, correlationID int32, clientID nullable string
	request := brokerRequest{
		key:           readInt16(body[0:2]),
		version:       readInt16(body[2:4]),
		correlationID: binary.BigEndian.Uint32(body[4:8]),
	}

	rest := body[8:]
	if len(rest) < 2 {
		return brokerRequest{}, errors.New("request header is truncated")
	}
	clientIDLen := readInt16(rest[0:2])
	rest = rest[2:]
	if clientIDLen > 0 {
		if int(clientIDLen) > len(rest) {
			return brokerRequest{}, errors.New("client id runs past the request")
		}
		request.clientID = string(rest[:clientIDLen])
		rest = rest[clientIDLen:]
	}
	request.payload = rest
	return request, nil
}

// apiVersionsResponse encodes an ApiVersions response with the header the
// protocol uses.
func (b *broker) apiVersionsResponse(correlationID uint32) []byte {
	response := kmsg.NewPtrApiVersionsResponse()
	response.SetVersion(0)
	response.ApiKeys = advertised()
	if b.behaviour == peerAnswersWithError {
		response.ErrorCode = b.errorCode
		response.ApiKeys = nil
	}

	out := correlationBytes(correlationID)
	return response.AppendTo(out)
}

// saslHandshakeResponse encodes a SaslHandshake response.
func (b *broker) saslHandshakeResponse(correlationID uint32) []byte {
	response := kmsg.NewPtrSASLHandshakeResponse()
	response.SetVersion(saslHandshakeFixtureVersion)
	response.SupportedMechanisms = b.saslMechanisms
	if b.sasl == peerAnswersWithError {
		response.ErrorCode = b.saslErrorCode
	}

	out := correlationBytes(correlationID)
	return response.AppendTo(out)
}

// saslAuthenticateResponse encodes a SaslAuthenticate response.
//
// The error message is attached whenever a test set one, including on a
// successful answer, because "the broker sent prose and it went nowhere" is the
// property under test and it should hold on every path.
func (b *broker) saslAuthenticateResponse(correlationID uint32) []byte {
	response := kmsg.NewPtrSASLAuthenticateResponse()
	response.SetVersion(saslAuthenticateFixtureVersion)
	response.SessionLifetimeMillis = b.authSessionLifetime
	if b.auth == peerAnswersWithError {
		response.ErrorCode = b.authErrorCode
	}
	if b.authErrorMessage != "" {
		message := b.authErrorMessage
		response.ErrorMessage = &message
	}

	out := correlationBytes(correlationID)
	return response.AppendTo(out)
}

// recordAuthPayload keeps the exact SASL bytes svcdoctor sent, so a test can
// prove what did reach the peer before proving what did not reach anywhere else.
//
// A leak test whose canary never travelled proves nothing, so this is what makes
// the absence assertions elsewhere mean something.
func (b *broker) recordAuthPayload(request brokerRequest) {
	decoded := kmsg.NewPtrSASLAuthenticateRequest()
	decoded.SetVersion(request.version)
	if err := decoded.ReadFrom(request.payload); err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.authPayloads = append(b.authPayloads, append([]byte(nil), decoded.SASLAuthBytes...))
	b.authVersionsSeen = append(b.authVersionsSeen, request.version)
}

// recordMechanism decodes the mechanism the client asked about, so a test can
// assert svcdoctor sent the mechanism it was given and nothing else.
func (b *broker) recordMechanism(request brokerRequest) {
	decoded := kmsg.NewPtrSASLHandshakeRequest()
	decoded.SetVersion(request.version)
	if err := decoded.ReadFrom(request.payload); err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.saslMechanismsSeen = append(b.saslMechanismsSeen, decoded.Mechanism)
	b.saslPayloads = append(b.saslPayloads, append([]byte(nil), request.payload...))
	b.clientIDs = append(b.clientIDs, request.clientID)
}

func (b *broker) count(counter *int) {
	b.mu.Lock()
	*counter++
	b.mu.Unlock()
}

func (b *broker) requestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.requests
}

func (b *broker) saslRequestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.saslRequests
}

// mechanismsSeen returns the mechanism of every handshake the broker received.
func (b *broker) mechanismsSeen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.saslMechanismsSeen...)
}

// handshakeBytes returns the body of every handshake request as it arrived, so
// a test can search the exact bytes svcdoctor put on the wire.
func (b *broker) handshakeBytes() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.saslPayloads...)
}

func (b *broker) authRequestCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.authRequests
}

func (b *broker) countAppBytes(n int) {
	b.mu.Lock()
	b.appBytes += n
	b.mu.Unlock()
}

// appBytesRead reports how many request bytes this peer has consumed above TLS.
//
// Read it after awaitIdle to make a difference of zero a proof that svcdoctor's
// protocol layer wrote nothing.
func (b *broker) appBytesRead() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.appBytes
}

// awaitIdle blocks until every accepted connection's read loop has exited.
//
// It is what turns "the broker received no authentication" from a poll into a
// proof. Without it a test could observe zero simply because the peer's
// goroutine had not run yet, which is the failure mode that makes a leak test
// pass for the wrong reason. Once svcdoctor has closed a socket, the peer reads
// end-of-file and its loop exits — so after this returns, everything that was
// ever written has been read and counted.
//
// It is only safe to call once the test has stopped opening connections, which
// is always the case here: the exchange under test has already returned.
func (b *broker) awaitIdle() { b.serving.Wait() }

// authPayloadsSeen returns the SASL bytes of every authentication the broker
// received, decoded out of the request.
func (b *broker) authPayloadsSeen() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([][]byte(nil), b.authPayloads...)
}

// authVersions returns the request version of every authentication received.
func (b *broker) authVersions() []int16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]int16(nil), b.authVersionsSeen...)
}

func (b *broker) clientIDsSeen() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.clientIDs...)
}

// readInt16 decodes one signed big-endian int16.
//
// Every Kafka integer field is signed on the wire, including a nullable string's
// length, which is -1 when the string is absent. Reinterpreting the two bytes is
// the decode rather than a narrowing conversion.
//
//nolint:gosec // G115: see above; the wire field is int16 by protocol definition.
func readInt16(b []byte) int16 { return int16(binary.BigEndian.Uint16(b)) }

func correlationBytes(correlationID uint32) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, correlationID)
	return out
}

// frame prefixes a Kafka message with its length. The fixture never builds a
// body anywhere near the limit, and the guard says so rather than assuming it.
func frame(body []byte) []byte {
	if len(body) > math.MaxInt32 {
		panic("fixture response is implausibly large")
	}
	out := make([]byte, 4, 4+len(body))
	//nolint:gosec // G115: the guard above bounds the length; a frame prefix has no other form.
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	return append(out, body...)
}

// --- transport paths ------------------------------------------------------

// path builds a transport continuation the way the chain would, over a real
// connection to the fake broker.
//
// It goes through transport.Run with seams pointing at the broker, so the
// continuation this adapter receives is a genuine one rather than a hand-made
// value: the ownership handoff under test is the real one.
func path(t *testing.T, b *broker, addresses ...string) (*transport.Result, *domain.GraphBuilder) {
	t.Helper()

	if len(addresses) == 0 {
		addresses = []string{"10.0.0.1"}
	}
	builder := domain.NewGraphBuilder()
	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     "primary.internal",
		Port:     9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, addresses)},
		Dialer:   brokerDialer{target: b.addr, conns: &connRegistry{}},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, builder
}

type connRegistry struct {
	mu    sync.Mutex
	conns []*countingConn
}

func (r *connRegistry) add(c *countingConn) {
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
}

func (r *connRegistry) all() []*countingConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*countingConn(nil), r.conns...)
}

type fixedResolver struct {
	addresses []netip.Addr
}

func (r fixedResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return r.addresses, nil
}

type brokerDialer struct {
	target netip.AddrPort
	conns  *connRegistry
	refuse map[string]bool
}

func (d brokerDialer) DialTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if d.refuse[addr.Addr().String()] {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.target.String())
	if err != nil {
		return nil, err
	}
	counted := &countingConn{Conn: conn}
	if d.conns != nil {
		d.conns.add(counted)
	}
	return counted, nil
}

func parseAddrs(t *testing.T, values []string) []netip.Addr {
	t.Helper()

	addrs := make([]netip.Addr, 0, len(values))
	for _, v := range values {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			t.Fatalf("netip.ParseAddr(%q): %v", v, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// apiVersionsSessions runs transport and ApiVersions, which is the input every
// SASL test starts from: real sockets, measured by the real chain, carried
// through the real adapter.
func apiVersionsSessions(
	t *testing.T, b *broker, addresses ...string,
) (*Result, *domain.GraphBuilder, *connRegistry) {
	t.Helper()

	paths, builder, registry := dialedPaths(t, b, addresses...)

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result, builder, registry
}

// apiVersionsSessionsAt does the same for one named endpoint against one
// broker, so a test can build a graph holding two endpoints with different
// answers.
//
// tlsOptions is nil for a plaintext path. When it is set the chain performs a
// real handshake against the broker, which is what lets one graph hold paths
// whose channels genuinely differ.
func apiVersionsSessionsAt(
	t *testing.T,
	builder *domain.GraphBuilder,
	b *broker,
	host, address string,
	tlsOptions *transport.TLSOptions,
) *Result {
	t.Helper()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: host, Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, []string{address})},
		Dialer:   brokerDialer{target: b.addr, conns: &connRegistry{}},
		TLS:      tlsOptions,
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
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
		ids := make([]string, 0, graph.Len())
		for _, e := range graph.Nodes() {
			ids = append(ids, e.ID().String())
		}
		t.Fatalf("node %q is missing; graph holds %v", id, ids)
	}
	return evidence
}

func attribute(t *testing.T, e domain.Evidence, key domain.AttributeKey) domain.AttrValue {
	t.Helper()

	value, ok := e.Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing; present: %v", key, e.Attributes())
	}
	return value
}

// --- authentication targets -----------------------------------------------

// The endpoint every authentication test runs against. The logical label and the
// resolved address are deliberately different values, because the distinction
// between them is what most of these tests are about.
const (
	authHost     = "primary.internal"
	authAddress  = "10.0.0.1"
	authEndpoint = "primary.internal:9092"
	authNodeID   = "kafka.sasl_authenticate/primary.internal:9092/10.0.0.1"

	// authIdentity and authSecret are what a test presents. The secret is
	// high-entropy and unlike any other string in the repository, so finding it
	// anywhere is unambiguous and finding it nowhere is not luck.
	authIdentity = "svcdoctor-probe-user"
	//nolint:gosec // G101: a leak-test canary, not a credential. It exists so that
	// finding it anywhere outside the peer's received payload is unambiguous.
	authSecret = "Zq7XmK4pR9wL2vN8tJ6bH3sY5cD1gF0aQeUiOpAsDfGh"
)

// authTarget is one prepared path: a broker answering all three requests, the
// handshake sessions over real sockets, the graph they were recorded in, and the
// registry holding those sockets.
type authTarget struct {
	broker   *broker
	builder  *domain.GraphBuilder
	sessions []*HandshakeSession
	registry *connRegistry
}

// session returns the single handshake session, failing if the path did not
// produce exactly one.
func (a *authTarget) session(t *testing.T) *HandshakeSession {
	t.Helper()

	if len(a.sessions) != 1 {
		t.Fatalf("handshake sessions = %d, want 1: the fixture path did not complete",
			len(a.sessions))
	}
	return a.sessions[0]
}

// conn returns the single socket the transport chain established.
func (a *authTarget) conn(t *testing.T) *countingConn {
	t.Helper()

	established := a.registry.all()
	if len(established) != 1 {
		t.Fatalf("transport established %d connections, want 1", len(established))
	}
	return established[0]
}

// buildAuthTarget runs the whole real chain — DNS, TCP, optionally TLS,
// ApiVersions, SaslHandshake — so that authentication receives a session
// produced the way production would produce one.
//
// Nothing here is hand-made. A hand-built HandshakeSession would let a test
// assert against a channel and an endpoint nobody established, which is the one
// thing these tests must not do.
func buildAuthTarget(
	t *testing.T, b *broker, tlsOptions *transport.TLSOptions, addresses ...string,
) *authTarget {
	t.Helper()

	if len(addresses) == 0 {
		addresses = []string{authAddress}
	}
	registry := &connRegistry{}
	builder := domain.NewGraphBuilder()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: authHost, Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, addresses)},
		Dialer:   brokerDialer{target: b.addr, conns: registry},
		TLS:      tlsOptions,
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	protocol, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = protocol.Close() })

	handshake, err := SASLHandshake(
		context.Background(), builder, protocol.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })

	return &authTarget{
		broker:   b,
		builder:  builder,
		sessions: handshake.Sessions(),
		registry: registry,
	}
}

// verifiedTarget is the only kind of path the default policy permits: a real TLS
// handshake against a certificate the test generated, verified against the only
// pool that trusts it.
func verifiedTarget(t *testing.T, options ...brokerOption) *authTarget {
	t.Helper()

	b, pool := newTLSBroker(t, authHost, options...)
	return buildAuthTarget(t, b, &transport.TLSOptions{RootCAs: pool})
}

// verifiedTargetAt is verifiedTarget over several resolved addresses, which is
// how the "one credential, five addresses" case is exercised.
func verifiedTargetAt(t *testing.T, addresses []string, options ...brokerOption) *authTarget {
	t.Helper()

	b, pool := newTLSBroker(t, authHost, options...)
	return buildAuthTarget(t, b, &transport.TLSOptions{RootCAs: pool}, addresses...)
}

// unverifiedTarget completes a real TLS handshake and verifies nothing, which is
// the case that proves encryption alone does not permit a credential.
func unverifiedTarget(t *testing.T, options ...brokerOption) *authTarget {
	t.Helper()

	b, _ := newTLSBroker(t, authHost, options...)
	return buildAuthTarget(t, b, &transport.TLSOptions{InsecureSkipVerify: true})
}

// plaintextTarget performs no TLS at all.
func plaintextTarget(t *testing.T, options ...brokerOption) *authTarget {
	t.Helper()

	return buildAuthTarget(t, newBroker(t, peerAnswers, options...), nil)
}

// credentialFor binds the fixture secret to one endpoint.
func credentialFor(t *testing.T, host string, port uint16) security.Credential {
	t.Helper()

	return credentialWith(t, host, port, authIdentity, authSecret)
}

func credentialWith(t *testing.T, host string, port uint16, identity, secret string) security.Credential {
	t.Helper()

	endpoint, err := security.NewEndpoint(host, port)
	if err != nil {
		t.Fatalf("security.NewEndpoint(%q, %d): %v", host, port, err)
	}
	credential, err := security.NewCredential(endpoint, identity, security.NewSecret(secret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}
	return credential
}

// authenticate runs one authentication over one session with the default policy.
func authenticate(
	t *testing.T, target *authTarget, credential security.Credential, params AuthParams,
) *AuthResult {
	t.Helper()

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t), credential, params)
	if err != nil {
		t.Fatalf("Authenticate: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
}
