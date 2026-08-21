package security

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	cryptotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kmsg"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The end-to-end leak matrix for the first phase that transmits a credential.
//
// A whole run is performed against a controlled TLS peer — DNS, TCP, TLS,
// ApiVersions, SaslHandshake, SaslAuthenticate — assembled into a canonical
// report and redacted into a shareable one. Three canaries travel: the secret
// svcdoctor sends, the identity it authenticates as, and the prose the broker
// answers with. None may appear in either report.
//
// The host and address canaries are the ones that *must* appear in the local
// report and must not survive redaction, which is the existing contract.

const (
	authCanaryHost    = "auth-canary.kafka.internal"
	authCanaryAddr    = "10.61.62.63"
	authCanaryVantage = "auth-runner-canary.local"

	// authCanarySecret is what goes on the wire. It is high-entropy and unlike
	// any other string in the repository, so finding it is unambiguous.
	//nolint:gosec // G101: a leak-test canary, not a credential.
	authCanarySecret = "Xk9pQ2mV7nR4tY6uB1cZ8wE3sD5fG0hJ"

	// authCanaryIdentity is the principal svcdoctor authenticates as. It is
	// deployment identity, so it must not enter a report at all.
	authCanaryIdentity = "svc-canary-principal"

	// authCanaryBrokerMessage is what the peer says. A real broker writes this
	// field itself, and what it writes names principals and internal hosts.
	authCanaryBrokerMessage = "SASL authentication failed for svc-canary-principal at broker-9.canary.internal:9093"
)

// authPeer is a controlled Kafka peer that speaks TLS and answers the three
// requests one authenticated run makes.
type authPeer struct {
	addr netip.AddrPort
	pool *x509.CertPool

	// reject makes the peer refuse the credential, so the broker-message canary
	// travels on a path that produces a FAIL node.
	reject bool

	received chan []byte
}

func newAuthPeer(t *testing.T, reject bool) *authPeer {
	t.Helper()

	cert, pool := authCertificate(t, authCanaryHost)

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

	peer := &authPeer{
		addr:     addr,
		pool:     pool,
		reject:   reject,
		received: make(chan []byte, 4),
	}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			wrapped := cryptotls.Server(conn, &cryptotls.Config{
				Certificates: []cryptotls.Certificate{cert},
				MinVersion:   cryptotls.VersionTLS12,
			})
			go peer.serve(wrapped)
		}
	}()
	return peer
}

func (p *authPeer) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	for {
		request, ok := readAuthRequest(conn)
		if !ok {
			return
		}

		var payload []byte
		switch request.key {
		case 18: // ApiVersions
			response := kmsg.NewPtrApiVersionsResponse()
			response.SetVersion(0)
			apiKey := kmsg.NewApiVersionsResponseApiKey()
			apiKey.ApiKey, apiKey.MinVersion, apiKey.MaxVersion = 36, 0, 2
			response.ApiKeys = []kmsg.ApiVersionsResponseApiKey{apiKey}
			payload = response.AppendTo(correlationBytes(request.correlationID))
		case 17: // SaslHandshake
			response := kmsg.NewPtrSASLHandshakeResponse()
			response.SetVersion(1)
			response.SupportedMechanisms = []string{"PLAIN"}
			payload = response.AppendTo(correlationBytes(request.correlationID))
		case 36: // SaslAuthenticate
			p.recordAuth(request.body)
			response := kmsg.NewPtrSASLAuthenticateResponse()
			response.SetVersion(1)
			response.SessionLifetimeMillis = 3_600_000
			if p.reject {
				response.ErrorCode = 58
			}
			message := authCanaryBrokerMessage
			response.ErrorMessage = &message
			payload = response.AppendTo(correlationBytes(request.correlationID))
		default:
			return
		}

		if len(payload) > math.MaxInt32 {
			return
		}
		framed := make([]byte, 4, 4+len(payload))
		//nolint:gosec // G115: the guard above bounds the length; a frame prefix has no other form.
		binary.BigEndian.PutUint32(framed, uint32(len(payload)))
		if _, err := conn.Write(append(framed, payload...)); err != nil {
			return
		}
	}
}

// recordAuth keeps the SASL bytes that arrived, so a test can prove the canary
// really travelled before proving it appears nowhere else.
func (p *authPeer) recordAuth(body []byte) {
	decoded := kmsg.NewPtrSASLAuthenticateRequest()
	decoded.SetVersion(1)
	if err := decoded.ReadFrom(body); err != nil {
		return
	}
	select {
	case p.received <- append([]byte(nil), decoded.SASLAuthBytes...):
	default:
	}
}

// authRequest is one decoded request header plus the body that followed it.
type authRequest struct {
	key           int16
	correlationID uint32
	body          []byte
}

func readAuthRequest(conn net.Conn) (authRequest, bool) {
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		return authRequest{}, false
	}
	size := int64(binary.BigEndian.Uint32(sizeBuf[:]))
	if size < 8 || size > 1<<20 {
		return authRequest{}, false
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return authRequest{}, false
	}

	//nolint:gosec // G115: a Kafka api key is an int16 on the wire by definition.
	request := authRequest{
		key:           int16(binary.BigEndian.Uint16(raw[0:2])),
		correlationID: binary.BigEndian.Uint32(raw[4:8]),
	}

	// apiKey, apiVersion, correlationID, then the nullable client id.
	rest := raw[8:]
	if len(rest) < 2 {
		return authRequest{}, false
	}
	//nolint:gosec // G115: a nullable string length is an int16 on the wire.
	clientIDLen := int16(binary.BigEndian.Uint16(rest[0:2]))
	rest = rest[2:]
	if clientIDLen > 0 {
		if int(clientIDLen) > len(rest) {
			return authRequest{}, false
		}
		rest = rest[clientIDLen:]
	}
	request.body = rest
	return request, true
}

func authCertificate(t *testing.T, serverName string) (cryptotls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "svcdoctor auth canary ca"},
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

type authResolver struct{}

func (authResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(authCanaryAddr)}, nil
}

type authDialer struct{ target netip.AddrPort }

func (d authDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// authRun performs the whole run and returns the report plus the peer, so a test
// can check both what was produced and what actually travelled.
func authRun(t *testing.T, reject bool) (domain.Report, *authPeer) {
	t.Helper()

	peer := newAuthPeer(t, reject)
	builder := domain.NewGraphBuilder()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     authCanaryHost,
		Port:     9092,
		Resolver: authResolver{},
		Dialer:   authDialer{target: peer.addr},
		TLS:      &transport.TLSOptions{RootCAs: peer.pool},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	protocol, err := kafka.Run(context.Background(), builder, paths.Continuations(), kafka.Params{})
	if err != nil {
		t.Fatalf("kafka.Run: %v", err)
	}
	t.Cleanup(func() { _ = protocol.Close() })

	handshake, err := kafka.SASLHandshake(
		context.Background(), builder, protocol.Sessions(), kafka.SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("kafka.SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })

	sessions := handshake.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("handshake sessions = %d, want 1: the fixture path did not complete", len(sessions))
	}

	endpoint, err := security.NewEndpoint(authCanaryHost, 9092)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, authCanaryIdentity, security.NewSecret(authCanarySecret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}

	auth, err := kafka.Authenticate(
		context.Background(), builder, sessions[0], credential, kafka.AuthParams{})
	if err != nil {
		t.Fatalf("kafka.Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if auth.Authenticated() == reject {
		t.Fatalf("authenticated = %v with reject = %v: the fixture did not behave as configured",
			auth.Authenticated(), reject)
	}

	return assembleReport(t, builder), peer
}

func assembleReport(t *testing.T, builder *domain.GraphBuilder) domain.Report {
	t.Helper()

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	service, err := domain.NewServiceID("kafka")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata(
		"0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(authCanaryHost+":9092", authCanaryHost+":9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(authCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, false, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// credentialCanaries are the values that must appear in neither report.
func credentialCanaries() []string {
	return []string{
		authCanarySecret,
		authCanaryIdentity,
		authCanaryBrokerMessage,
		"broker-9.canary.internal",
	}
}

// TestTheAuthCanariesActuallyTravel is the precondition for everything below.
//
// A leak matrix whose canaries never left the process proves nothing. This
// asserts the secret and the identity really reached the controlled peer, and
// that the peer really answered with its prose.
func TestTheAuthCanariesActuallyTravel(t *testing.T) {
	_, peer := authRun(t, false)

	select {
	case payload := <-peer.received:
		if !strings.Contains(string(payload), authCanarySecret) {
			t.Fatalf("the peer received %q, which does not contain the secret", payload)
		}
		if !strings.Contains(string(payload), authCanaryIdentity) {
			t.Fatalf("the peer received %q, which does not contain the identity", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the peer never received an authentication, so the leak tests prove nothing")
	}
}

// TestLocalAuthReportContainsTheHostCanaries is the other precondition: the
// values redaction is supposed to remove must be present before it runs.
func TestLocalAuthReportContainsTheHostCanaries(t *testing.T) {
	report, _ := authRun(t, false)
	encoded := canonicalJSON(t, report)

	for _, canary := range []string{authCanaryHost, authCanaryAddr, authCanaryVantage} {
		if !strings.Contains(encoded, canary) {
			t.Errorf("the local report does not contain %q, so the leak test would prove nothing", canary)
		}
	}
}

// TestCanonicalAuthReportLeaksNoCredentialMaterial: the canonical report is the
// local, unredacted one, and even it must never have held a secret, an identity
// or the broker's prose. Redaction is not what keeps those out — nothing ever
// put them in.
func TestCanonicalAuthReportLeaksNoCredentialMaterial(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "accepted"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			report, _ := authRun(t, reject)
			encoded := canonicalJSON(t, report)

			for _, canary := range credentialCanaries() {
				if strings.Contains(encoded, canary) {
					t.Errorf("the canonical report leaks %q:\n%s", canary, encoded)
				}
			}
		})
	}
}

// TestShareableAuthReportLeaksNothing covers the redacted form, for both the
// accepted and the rejected path.
func TestShareableAuthReportLeaksNothing(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "accepted"
		if reject {
			name = "rejected"
		}
		t.Run(name, func(t *testing.T) {
			report, _ := authRun(t, reject)

			shareable, err := redaction.Redact(report)
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			encoded := canonicalJSON(t, shareable)

			forbidden := append(credentialCanaries(),
				authCanaryHost, authCanaryAddr, authCanaryVantage)
			for _, canary := range forbidden {
				if strings.Contains(encoded, canary) {
					t.Errorf("the shareable report leaks %q:\n%s", canary, encoded)
				}
			}
		})
	}
}

// TestAuthenticationFactsSurviveRedaction is the other half: a shared report
// must still say what happened at L5, because that is the reason to share it.
func TestAuthenticationFactsSurviveRedaction(t *testing.T) {
	report, _ := authRun(t, true)

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	var auth domain.Evidence
	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Step() == kafka.StepSASLAuthenticate {
			auth = evidence
			break
		}
	}
	if auth.IsZero() {
		t.Fatal("no authentication evidence survived redaction")
	}

	if auth.Layer() != domain.LayerAuth {
		t.Errorf("layer = %s, want L5", auth.Layer())
	}
	if auth.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", auth.State())
	}
	if auth.FailureClass() != domain.FailureAuthCredentialsRejected {
		t.Errorf("class = %s, want AUTH_CREDENTIALS_REJECTED", auth.FailureClass())
	}

	// The mechanism is a protocol fact, not identity: pseudonymizing PLAIN into
	// host-001 would destroy the only thing the node is for.
	mechanism, ok := auth.Attribute(kafka.AttrSASLMechanism)
	if !ok {
		t.Fatal("the mechanism did not survive redaction")
	}
	if value, _ := mechanism.Str(); value != "PLAIN" {
		t.Errorf("mechanism = %q, want PLAIN intact", value)
	}

	code, ok := auth.Attribute(kafka.AttrErrorCode)
	if !ok {
		t.Fatal("the broker error code did not survive redaction")
	}
	if value, _ := code.Int(); value != 58 {
		t.Errorf("error code = %d, want 58 intact", value)
	}

	lifetime, ok := auth.Attribute(kafka.AttrSASLSessionLifetimeMs)
	if !ok {
		t.Fatal("the session lifetime did not survive redaction")
	}
	if value, _ := lifetime.Int(); value != 3_600_000 {
		t.Errorf("session lifetime = %d, want 3600000 intact", value)
	}
}

// TestAuthNodeCarriesNoIdentityAfterRedaction: the node's own identifier and
// subject are built from the endpoint and the address, and both are identity
// that must be gone.
func TestAuthNodeCarriesNoIdentityAfterRedaction(t *testing.T) {
	report, _ := authRun(t, false)

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}

	for _, evidence := range shareable.Graph().Nodes() {
		if evidence.Step() != kafka.StepSASLAuthenticate {
			continue
		}
		for _, canary := range []string{authCanaryHost, authCanaryAddr} {
			if strings.Contains(evidence.ID().String(), canary) {
				t.Errorf("the authentication identifier still carries %q", canary)
			}
			if strings.Contains(evidence.Subject().Ref(), canary) {
				t.Errorf("the authentication subject still carries %q", canary)
			}
		}
	}
}

// TestAuthParentSurvivesIdentifierRemapping checks the L5 -> L5 edge still
// resolves after every identifier is rewritten, and still points at the
// handshake rather than at ApiVersions.
func TestAuthParentSurvivesIdentifierRemapping(t *testing.T) {
	report, _ := authRun(t, false)

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	graph := shareable.Graph()

	var authID domain.EvidenceID
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == kafka.StepSASLAuthenticate {
			authID = evidence.ID()
		}
	}
	if authID == "" {
		t.Fatal("no authentication node in the shareable report")
	}

	parents := graph.Parents(authID)
	if len(parents) != 1 {
		t.Fatalf("parents = %v, want exactly one", parents)
	}
	parent, ok := graph.Node(parents[0])
	if !ok {
		t.Fatalf("the authentication node points at %s, which is not in the graph", parents[0])
	}
	if parent.Step() != kafka.StepSASLHandshake {
		t.Errorf("parent step = %s, want the handshake", parent.Step())
	}

	// And the chain is intact all the way down: handshake -> api versions ->
	// tls -> tcp -> dns.
	wantChain := []domain.Step{
		kafka.StepSASLHandshake,
		kafka.StepAPIVersions,
	}
	current := authID
	for _, want := range wantChain {
		ps := graph.Parents(current)
		if len(ps) != 1 {
			t.Fatalf("%s has %d parents, want 1", current, len(ps))
		}
		n, present := graph.Node(ps[0])
		if !present {
			t.Fatalf("%s is not in the graph", ps[0])
		}
		if n.Step() != want {
			t.Fatalf("step = %s, want %s", n.Step(), want)
		}
		current = ps[0]
	}
}

// --- the refusal path -----------------------------------------------------

// refusedRun performs the same run over a channel the policy refuses, so the
// report holds a SKIPPED authentication node with a blocked-by reference.
func refusedRun(t *testing.T) (domain.Report, *authPeer) {
	t.Helper()

	peer := newAuthPeer(t, false)
	builder := domain.NewGraphBuilder()

	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     authCanaryHost,
		Port:     9092,
		Resolver: authResolver{},
		Dialer:   authDialer{target: peer.addr},
		// A completed handshake that verified nothing: encrypted to whoever
		// answered, which is exactly what the policy refuses.
		TLS: &transport.TLSOptions{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	protocol, err := kafka.Run(context.Background(), builder, paths.Continuations(), kafka.Params{})
	if err != nil {
		t.Fatalf("kafka.Run: %v", err)
	}
	t.Cleanup(func() { _ = protocol.Close() })

	handshake, err := kafka.SASLHandshake(
		context.Background(), builder, protocol.Sessions(), kafka.SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("kafka.SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshake.Close() })

	sessions := handshake.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("handshake sessions = %d, want 1", len(sessions))
	}

	endpoint, err := security.NewEndpoint(authCanaryHost, 9092)
	if err != nil {
		t.Fatalf("security.NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(
		endpoint, authCanaryIdentity, security.NewSecret(authCanarySecret))
	if err != nil {
		t.Fatalf("security.NewCredential: %v", err)
	}

	auth, err := kafka.Authenticate(
		context.Background(), builder, sessions[0], credential, kafka.AuthParams{})
	if err != nil {
		t.Fatalf("kafka.Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = auth.Close() })

	if auth.Authenticated() {
		t.Fatal("an unverified channel was permitted to carry a credential")
	}

	return assembleRefusedReport(t, builder), peer
}

// assembleRefusedReport differs from assembleReport in one field: this run
// disabled verification, and the report says so.
func assembleRefusedReport(t *testing.T, builder *domain.GraphBuilder) domain.Report {
	t.Helper()

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	service, err := domain.NewServiceID("kafka")
	if err != nil {
		t.Fatalf("NewServiceID: %v", err)
	}
	run, err := domain.NewRunMetadata(
		"0.0.0-dev", time.Unix(1700000000, 0).UTC(), time.Second, service)
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(authCanaryHost+":9092", authCanaryHost+":9092")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(authCanaryVantage)
	if err != nil {
		t.Fatalf("NewLocalVantage: %v", err)
	}
	reportSecurity, err := domain.NewReportSecurity(domain.OutputModeLocalFull, true, false)
	if err != nil {
		t.Fatalf("NewReportSecurity: %v", err)
	}

	report, err := domain.NewReport(domain.ReportInput{
		Run: run, Target: target, Vantage: vantage, Graph: graph, Security: reportSecurity,
	})
	if err != nil {
		t.Fatalf("NewReport: %v", err)
	}
	return report
}

// TestRefusedAuthenticationSendsNothingAndSaysSo is the whole phase in one
// end-to-end statement: the credential never left the process, and the report
// records why.
func TestRefusedAuthenticationSendsNothingAndSaysSo(t *testing.T) {
	report, peer := refusedRun(t)

	select {
	case payload := <-peer.received:
		t.Fatalf("the peer received an authentication payload %q; nothing should have been sent",
			payload)
	default:
	}

	encoded := canonicalJSON(t, report)
	for _, canary := range credentialCanaries() {
		if strings.Contains(encoded, canary) {
			t.Errorf("the report of a refused attempt leaks %q:\n%s", canary, encoded)
		}
	}

	var auth domain.Evidence
	for _, evidence := range report.Graph().Nodes() {
		if evidence.Step() == kafka.StepSASLAuthenticate {
			auth = evidence
		}
	}
	if auth.IsZero() {
		t.Fatal("the refusal produced no node, so a reader cannot tell it from a step nobody ran")
	}
	if auth.State() != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", auth.State())
	}
	if auth.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Errorf("class = %s, want EXEC_SKIPPED_BY_POLICY", auth.FailureClass())
	}
}

// TestRefusalBlockedBySurvivesIdentifierRemapping: the refusal points at the TLS
// node whose tls.verified is false, and that reference must still resolve after
// every identifier in the report has been rewritten.
func TestRefusalBlockedBySurvivesIdentifierRemapping(t *testing.T) {
	report, _ := refusedRun(t)

	shareable, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	graph := shareable.Graph()

	var authID domain.EvidenceID
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == kafka.StepSASLAuthenticate {
			authID = evidence.ID()
		}
	}
	if authID == "" {
		t.Fatal("no authentication node in the shareable report")
	}

	blockers := graph.BlockedBy(authID)
	if len(blockers) != 1 {
		t.Fatalf("blocked-by = %v, want exactly one", blockers)
	}
	blocker, ok := graph.Node(blockers[0])
	if !ok {
		t.Fatalf("the refusal points at %s, which is not in the shareable graph", blockers[0])
	}
	if blocker.Layer() != domain.LayerTLS {
		t.Errorf("blocker layer = %s, want L3", blocker.Layer())
	}

	verified, has := blocker.Attribute("tls.verified")
	if !has {
		t.Fatal("the blocker records no tls.verified, so it does not explain the refusal")
	}
	if value, _ := verified.Bool(); value {
		t.Error("the refusal points at a node that did verify the peer")
	}

	// The reference survived remapping, which means it names a rewritten
	// identifier rather than the original one.
	if strings.Contains(blockers[0].String(), authCanaryHost) {
		t.Error("the blocked-by reference still carries the hostname")
	}
}
