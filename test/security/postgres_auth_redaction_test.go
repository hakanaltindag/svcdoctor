package security

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	cryptotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
	"github.com/hakanaltindag/svcdoctor/internal/security/redaction"
)

// The PostgreSQL authentication redaction check, end to end.
//
// It drives the real adapter through a real SCRAM-SHA-256 exchange over a real
// TLS connection, assembles a real report, and then redacts it. Nothing here
// hand-authors a node, and nothing simulates the credential path: the peer
// really receives a client proof, which is what makes the absence assertions
// mean something.

const (
	pgAuthHost    = "db-auth-canary.payments.internal"
	pgAuthAddr    = "10.88.0.42"
	pgAuthRole    = "payments_writer_secretish"
	pgAuthDB      = "payments_prod_customer42"
	pgAuthVantage = "pg-auth-runner-canary.local"

	//nolint:gosec // G101: a leak-test canary, not a credential.
	pgAuthPassword = "Qw8-CANARY-scram-pw-3Ht9zXbM"

	pgAuthIterations = 4096
	pgAuthServerTail = "AUTHSERVERNONCEtail1234="

	// Identity planted in the two ParameterStatus values svcdoctor drops.
	pgCanarySearchPath = `"$user", schema_QK7z_payments`
)

func pgAuthSalt() []byte { return []byte("fedcba9876543210") }

// pgAuthPeer is a scripted PostgreSQL server that completes SCRAM honestly.
type pgAuthPeer struct {
	addr netip.AddrPort
	ca   *x509.CertPool

	mu              sync.Mutex
	accepted        int
	clientFirstBare string
	serverFirst     string
	clientFinal     string
}

func newPGAuthPeer(t *testing.T) *pgAuthPeer {
	t.Helper()

	cert, pool := authCertificate(t, "localhost")

	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener unavailable in this environment: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	p := &pgAuthPeer{addr: netip.MustParseAddrPort(ln.Addr().String()), ca: pool}

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			p.mu.Lock()
			p.accepted++
			p.mu.Unlock()
			go p.serve(conn, cert)
		}
	}()
	return p
}

func (p *pgAuthPeer) serve(conn net.Conn, cert cryptotls.Certificate) {
	defer func() {
		time.Sleep(200 * time.Millisecond)
		_ = conn.Close()
	}()

	// SSLRequest -> 'S' -> TLS on the same socket.
	var req [8]byte
	if _, err := readAll(conn, req[:]); err != nil {
		return
	}
	if _, err := conn.Write([]byte("S")); err != nil {
		return
	}
	server := cryptotls.Server(conn, &cryptotls.Config{
		Certificates: []cryptotls.Certificate{cert},
		MinVersion:   cryptotls.VersionTLS12,
	})
	if err := server.HandshakeContext(context.Background()); err != nil {
		return
	}

	// StartupMessage: a four-byte length that includes itself.
	var header [4]byte
	if _, err := readAll(server, header[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(header[:])
	if length < 4 || length > 1<<16 {
		return
	}
	if _, err := readAll(server, make([]byte, length-4)); err != nil {
		return
	}

	if _, err := server.Write(pgAuthFrame('R', pgAuthCode(10, []byte("SCRAM-SHA-256\x00\x00")))); err != nil {
		return
	}

	first, ok := pgAuthRead(server)
	if !ok {
		return
	}
	clientFirst, ok := pgAuthDecodeInitial(first)
	if !ok {
		return
	}
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce := pgAuthAttr(clientFirstBare, 'r')

	serverFirst := "r=" + clientNonce + pgAuthServerTail +
		",s=" + base64.StdEncoding.EncodeToString(pgAuthSalt()) +
		",i=" + strconv.Itoa(pgAuthIterations)
	if _, err := server.Write(pgAuthFrame('R', pgAuthCode(11, []byte(serverFirst)))); err != nil {
		return
	}

	final, ok := pgAuthRead(server)
	if !ok {
		return
	}
	clientFinal := string(final)

	p.mu.Lock()
	p.clientFirstBare, p.serverFirst, p.clientFinal = clientFirstBare, serverFirst, clientFinal
	p.mu.Unlock()

	signature := pgAuthServerSignature(clientFirstBare, serverFirst, clientFinal)

	var out bytes.Buffer
	out.Write(pgAuthFrame('R', pgAuthCode(12, []byte("v="+base64.StdEncoding.EncodeToString(signature)))))
	out.Write(pgAuthFrame('R', pgAuthCode(0, nil)))

	// The session-establishment burst: the four parameters svcdoctor keeps, the
	// two it must drop as identity, a BackendKeyData whose halves are
	// unmistakable, and ReadyForQuery.
	out.Write(pgAuthParam("in_hot_standby", "off"))
	out.Write(pgAuthParam("session_authorization", pgAuthRole))
	out.Write(pgAuthParam("search_path", pgCanarySearchPath))
	out.Write(pgAuthParam("server_version", "18.6 (Debian 18.6-1.pgdg13+2)"))
	out.Write(pgAuthParam("default_transaction_read_only", "off"))
	out.Write(pgAuthParam("is_superuser", "on"))
	out.Write(pgAuthFrame('K', pgBackendKey()))
	out.Write(pgAuthFrame('Z', []byte{'I'}))

	_, _ = server.Write(out.Bytes())

	time.Sleep(200 * time.Millisecond)
}

func pgAuthServerSignature(clientFirstBare, serverFirst, clientFinal string) []byte {
	salted, err := pbkdf2.Key(sha256.New, pgAuthPassword, pgAuthSalt(), pgAuthIterations, sha256.Size)
	if err != nil {
		return nil
	}
	withoutProof := clientFinal
	if i := strings.Index(clientFinal, ",p="); i >= 0 {
		withoutProof = clientFinal[:i]
	}
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof
	serverKey := pgAuthMAC(salted, []byte("Server Key"))
	return pgAuthMAC(serverKey, []byte(authMessage))
}

func pgAuthMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func pgAuthFrame(kind byte, body []byte) []byte {
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out := []byte{kind}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

func pgAuthCode(code uint32, payload []byte) []byte {
	body := binary.BigEndian.AppendUint32(nil, code)
	return append(body, payload...)
}

// pgAuthParam builds a ParameterStatus message.
func pgAuthParam(key, value string) []byte {
	body := make([]byte, 0, len(key)+len(value)+2)
	body = append(body, key...)
	body = append(body, 0)
	body = append(body, value...)
	body = append(body, 0)
	return pgAuthFrame('S', body)
}

// pgBackendKey is a BackendKeyData body whose two halves are unmistakable, so a
// leak assertion is about the report rather than about a value that might not
// have been there.
func pgBackendKey() []byte {
	return []byte{0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF}
}

// pgAuthRead reads one framed client message and returns its body.
func pgAuthRead(conn net.Conn) ([]byte, bool) {
	var header [5]byte
	if _, err := readAll(conn, header[:]); err != nil {
		return nil, false
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || length > 1<<20 {
		return nil, false
	}
	body := make([]byte, length-4)
	if _, err := readAll(conn, body); err != nil {
		return nil, false
	}
	return body, true
}

func pgAuthDecodeInitial(body []byte) (string, bool) {
	i := bytes.IndexByte(body, 0)
	if i < 0 || len(body) < i+5 {
		return "", false
	}
	return string(body[i+5:]), true
}

func pgAuthAttr(s string, key byte) string {
	for _, attr := range strings.Split(s, ",") {
		if len(attr) >= 2 && attr[0] == key && attr[1] == '=' {
			return attr[2:]
		}
	}
	return ""
}

func (p *pgAuthPeer) exchange() (string, string, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.clientFirstBare, p.serverFirst, p.clientFinal
}

func (p *pgAuthPeer) connections() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

type pgAuthResolver struct{ addr netip.Addr }

func (r pgAuthResolver) LookupAddresses(_ context.Context, _ string) ([]netip.Addr, error) {
	return []netip.Addr{r.addr}, nil
}

type pgAuthDialer struct{ target netip.AddrPort }

func (d pgAuthDialer) DialTCP(ctx context.Context, _ netip.AddrPort) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target.String())
}

// pgAuthRun drives DNS, TCP, SSLRequest, TLS, Startup and Authenticate, and
// assembles a report from what they recorded.
func pgAuthRun(t *testing.T) (domain.Report, *pgAuthPeer) {
	t.Helper()

	peer := newPGAuthPeer(t)
	builder := domain.NewGraphBuilder()

	result, err := transport.Run(context.Background(), builder, transport.Params{
		Host:     pgAuthHost,
		Port:     5432,
		Resolver: pgAuthResolver{addr: netip.MustParseAddr(pgAuthAddr)},
		Dialer:   pgAuthDialer{target: peer.addr},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	paths := result.Continuations()
	if len(paths) != 1 {
		t.Fatalf("got %d transport paths, want 1", len(paths))
	}

	session, err := postgres.Negotiate(context.Background(), builder, paths[0], postgres.Params{
		TLS:        postgres.TLSRequired,
		TLSOptions: postgres.TLSOptions{ServerName: "localhost", RootCAs: peer.ca},
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	startup, err := postgres.Startup(context.Background(), builder, session, postgres.StartupParams{
		User: pgAuthRole, Database: pgAuthDB,
	})
	if err != nil || startup == nil {
		t.Fatalf("Startup: %v", err)
	}
	t.Cleanup(func() { _ = startup.Close() })

	endpoint, err := security.NewEndpoint(pgAuthHost, 5432)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	credential, err := security.NewCredential(endpoint, pgAuthRole, security.NewSecret(pgAuthPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	authenticated, err := postgres.Authenticate(
		context.Background(), builder, startup, credential, postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if authenticated == nil {
		t.Fatal("authentication did not succeed against the scripted peer")
	}
	t.Cleanup(func() { _ = authenticated.Close() })

	established, err := postgres.EstablishSession(
		context.Background(), builder, authenticated, postgres.SessionParams{})
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	if established == nil {
		t.Fatal("session establishment did not reach ReadyForQuery")
	}

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	run, err := domain.NewRunMetadata("0.1.0", time.Now(), time.Second, "postgres")
	if err != nil {
		t.Fatalf("NewRunMetadata: %v", err)
	}
	target, err := domain.NewTarget(pgAuthHost + ":5432")
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	vantage, err := domain.NewLocalVantage(pgAuthVantage)
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
	return report, peer
}

// pgAuthCanaries recomputes every sensitive intermediate of the real exchange.
func pgAuthCanaries(t *testing.T, peer *pgAuthPeer) map[string]string {
	t.Helper()

	clientFirstBare, serverFirst, clientFinal := peer.exchange()
	if clientFirstBare == "" || clientFinal == "" {
		t.Fatal("the peer did not observe a complete SCRAM exchange")
	}
	withoutProof := clientFinal
	if i := strings.Index(clientFinal, ",p="); i >= 0 {
		withoutProof = clientFinal[:i]
	}
	authMessage := clientFirstBare + "," + serverFirst + "," + withoutProof

	salted, err := pbkdf2.Key(sha256.New, pgAuthPassword, pgAuthSalt(), pgAuthIterations, sha256.Size)
	if err != nil {
		t.Fatalf("pbkdf2: %v", err)
	}
	clientKey := pgAuthMAC(salted, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	serverKey := pgAuthMAC(salted, []byte("Server Key"))

	b64 := base64.StdEncoding.EncodeToString
	proof := pgAuthAttr(clientFinal, 'p')
	if proof == "" {
		t.Fatal("the peer received no client proof")
	}

	return map[string]string{
		"password":         pgAuthPassword,
		"client nonce":     pgAuthAttr(clientFirstBare, 'r'),
		"server nonce":     pgAuthAttr(serverFirst, 'r'),
		"salt":             b64(pgAuthSalt()),
		"salted password":  b64(salted),
		"client key":       b64(clientKey),
		"stored key":       b64(storedKey[:]),
		"client proof":     proof,
		"server key":       b64(serverKey),
		"server signature": b64(pgAuthMAC(serverKey, []byte(authMessage))),
		"auth message":     authMessage,
	}
}

// TestPostgresAuthLocalReportIsAlreadyFreeOfCredentialMaterial checks the
// LOCAL_FULL report, before redaction.
//
// Redaction removes identity; it has never been the thing that keeps a secret
// out. A credential-derived value must be absent from the unredacted report too,
// because nothing downstream would remove it.
func TestPostgresAuthLocalReportIsAlreadyFreeOfCredentialMaterial(t *testing.T) {
	report, peer := pgAuthRun(t)
	encoded := encodeReport(t, report)

	// Controls: the exchange really happened over one socket, and the report
	// really describes it.
	if got := peer.connections(); got != 1 {
		t.Errorf("peer accepted %d connections, want 1", got)
	}
	for _, present := range []string{
		"postgres.authentication", "postgres.session", "SCRAM-SHA-256", "PASS",
	} {
		if !strings.Contains(encoded, present) {
			t.Fatalf("the report does not contain %q; the assertions below are unreliable", present)
		}
	}

	for label, canary := range pgAuthCanaries(t, peer) {
		if canary == "" {
			t.Fatalf("canary %q was not computed", label)
		}
		if strings.Contains(encoded, canary) {
			t.Errorf("the LOCAL_FULL report contains the %s", label)
		}
	}
}

// TestPostgresAuthShareableReportRemovesIdentityAndKeepsTheDiagnosis is the
// redaction half.
func TestPostgresAuthShareableReportRemovesIdentityAndKeepsTheDiagnosis(t *testing.T) {
	report, peer := pgAuthRun(t)

	redacted, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	encoded := encodeReport(t, redacted)

	// Identity is gone, including the two ParameterStatus values the session
	// step drops at the wire boundary.
	for _, identity := range []string{
		pgAuthHost, pgAuthAddr, pgAuthRole, pgAuthDB, pgAuthVantage,
		pgCanarySearchPath, "schema_QK7z_payments", "$user",
	} {
		if strings.Contains(encoded, identity) {
			t.Errorf("the shareable report still contains %q", identity)
		}
	}

	// The diagnosis survives, session facts included.
	for _, keep := range []string{
		"postgres.authentication", "postgres.session", "SCRAM-SHA-256", "PASS", "L5",
		"postgres.in_hot_standby", "postgres.transaction_status", "idle",
		"postgres.server_version", "postgres.is_superuser",
	} {
		if !strings.Contains(encoded, keep) {
			t.Errorf("redaction removed %q, which carries no identity", keep)
		}
	}

	// The backend key never existed in the model to begin with.
	for _, canary := range []string{"3405691582", "3735928559", "cafebabe", "deadbeef"} {
		if strings.Contains(strings.ToLower(encoded), canary) {
			t.Errorf("a BackendKeyData value (%s) reached the shareable report", canary)
		}
	}

	// No credential material, still.
	for label, canary := range pgAuthCanaries(t, peer) {
		if strings.Contains(encoded, canary) {
			t.Errorf("the shareable report contains the %s", label)
		}
	}
}

// TestPostgresAuthRedactionIsIdempotent pins that redacting twice changes
// nothing, which is the property a caller relies on when a report is passed
// through more than one boundary.
func TestPostgresAuthRedactionIsIdempotent(t *testing.T) {
	report, _ := pgAuthRun(t)

	once, err := redaction.Redact(report)
	if err != nil {
		t.Fatalf("Redact: %v", err)
	}
	twice, err := redaction.Redact(once)
	if err != nil {
		t.Fatalf("Redact twice: %v", err)
	}

	if a, b := encodeReport(t, once), encodeReport(t, twice); a != b {
		t.Errorf("redaction is not idempotent:\n once: %s\ntwice: %s", a, b)
	}
}
