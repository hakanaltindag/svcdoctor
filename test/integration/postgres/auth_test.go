//go:build integration

// Package postgres validates the PostgreSQL adapter against a real server.
//
// It is behind a build tag and is not part of `make check`: it needs Docker and
// takes seconds rather than milliseconds, while the ordinary gate must stay fast
// and hermetic. See README.md.
//
// Everything here drives production code paths — the real resolver, the real
// dialer, the real TLS probe, the real protocol, the real graph. No evidence is
// hand-authored and no exchange is simulated.
package postgres

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/postgres"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/dns"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tcp"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

const (
	// A loopback literal rather than "localhost", and the difference is not
	// cosmetic. "localhost" resolves to both 127.0.0.1 and ::1, so the chain
	// produces **two** completed paths and every caller must then choose one —
	// which ADR 0024 §3 refuses to let any layer do implicitly.
	//
	// This suite has no basis for choosing, so it removes the choice instead of
	// making it: one address, one path, asserted rather than assumed. The
	// generated certificate carries IP:127.0.0.1 in its SANs, so verification is
	// unaffected. Production selection is deferred to ADR 0041.
	pgHost = "127.0.0.1"
	pgPort = 55432

	scramRole = "scramuser"
	// Printable ASCII including a space and a tilde, so the accepted range is
	// exercised at both ends against a real verifier.
	scramPassword = "sc RAM-pw~7Kv2"

	trustRole     = "trustuser"
	md5Role       = "md5user"
	cleartextRole = "clearuser"

	norightsRole     = "norights"
	norightsPassword = "pw-norights"
	closedDatabase   = "closeddb"

	database = "appdb"
)

func rootCAs(t *testing.T) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("env", "certs", "server.crt"))
	if err != nil {
		t.Skipf("validation certificate not generated: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the validation certificate did not parse")
	}
	return pool
}

// The production seams, so the suite exercises the real resolver and the real
// dialer rather than fixtures standing in for them.

// startup runs DNS, TCP, SSLRequest, TLS and Startup against the real server.
func startup(t *testing.T, plan postgres.TLSPlan, insecure bool, role string) (
	*postgres.StartupResult, *domain.GraphBuilder,
) {
	t.Helper()
	return startupFor(t, plan, insecure, role, database)
}

// startupFor is startup with an explicit database, for the cases where the
// database is what the test is about.
func startupFor(t *testing.T, plan postgres.TLSPlan, insecure bool, role, db string) (
	*postgres.StartupResult, *domain.GraphBuilder,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	builder := domain.NewGraphBuilder()
	result, err := transport.Run(ctx, builder, transport.Params{
		Host: pgHost, Port: pgPort,
		Resolver: dns.SystemResolver{}, Dialer: tcp.SystemDialer{},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	// A fixture precondition, never a selection policy. See
	// requireSingleContinuation.
	path := requireSingleContinuation(t, result)

	options := postgres.TLSOptions{ServerName: pgHost}
	if insecure {
		options.InsecureSkipVerify = true
	} else {
		options.RootCAs = rootCAs(t)
	}

	session, err := postgres.Negotiate(ctx, builder, path, postgres.Params{
		TLS: plan, TLSOptions: options,
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	startupResult, err := postgres.Startup(ctx, builder, session, postgres.StartupParams{
		User: role, Database: db,
	})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if startupResult == nil {
		t.Fatal("Startup produced no result against the real server")
	}
	t.Cleanup(func() { _ = startupResult.Close() })
	return startupResult, builder
}

func credential(t *testing.T, role, password string) security.Credential {
	t.Helper()
	endpoint, err := security.NewEndpoint(pgHost, pgPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	c, err := security.NewCredential(endpoint, role, security.NewSecret(password))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}
	return c
}

func authNode(t *testing.T, builder *domain.GraphBuilder) domain.Evidence {
	t.Helper()
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	for _, n := range graph.Nodes() {
		if n.Step() == postgres.StepAuthentication {
			return n
		}
	}
	t.Fatal("no postgres.authentication node in the graph")
	return domain.Evidence{}
}

func hasAuthNode(t *testing.T, builder *domain.GraphBuilder) bool {
	t.Helper()
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	for _, n := range graph.Nodes() {
		if n.Step() == postgres.StepAuthentication {
			return true
		}
	}
	return false
}

// 1. Verified TLS with the correct password: the whole point of the phase.
func TestRealServerSCRAMOverVerifiedTLS(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, false, scramRole)

	if result.Channel() != security.ChannelTLSVerified {
		t.Fatalf("channel = %s, want tls-verified", result.Channel())
	}
	if result.AuthMethod() != "sasl" {
		t.Fatalf("auth method = %q, want sasl", result.AuthMethod())
	}
	// 8. The mechanism offer, confirmed against a real server.
	mechanisms := result.SASLMechanisms()
	if !contains(mechanisms, "SCRAM-SHA-256") {
		t.Fatalf("mechanisms = %v, want one to be SCRAM-SHA-256", mechanisms)
	}
	t.Logf("advertised mechanisms over TLS: %v", mechanisms)

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, scramRole, scramPassword), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatal("authentication against a real server did not succeed")
	}
	t.Cleanup(func() { _ = session.Close() })

	node := authNode(t, builder)
	if node.State() != domain.StatePass {
		t.Fatalf("state = %s (%s), want PASS", node.State(), node.FailureClass())
	}
	if got, ok := node.Attributes()[postgres.AttrSCRAMIterations]; ok {
		t.Logf("server iteration count: %s", got)
	} else {
		t.Error("no scram iteration count was recorded")
	}

	// 10. The session step continues on the same socket and reaches
	// ReadyForQuery.
	established, err := postgres.EstablishSession(
		context.Background(), builder, session, postgres.SessionParams{})
	if err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	if established == nil {
		t.Fatal("session establishment did not reach ReadyForQuery against a real server")
	}

	sessionNode := nodeOf(t, builder, postgres.StepSession)
	if sessionNode.State() != domain.StatePass {
		t.Fatalf("session state = %s (%s), want PASS",
			sessionNode.State(), sessionNode.FailureClass())
	}
	for key, want := range map[domain.AttributeKey]string{
		postgres.AttrTransactionStatus:          "idle",
		postgres.AttrInHotStandby:               "off",
		postgres.AttrDefaultTransactionReadOnly: "off",
	} {
		if got := attr(sessionNode, key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	t.Logf("server_version=%q is_superuser=%q",
		attr(sessionNode, postgres.AttrServerVersion),
		attr(sessionNode, postgres.AttrIsSuperuser))

	// The four kept keys, the transaction status, and nothing else.
	if got := len(sessionNode.Attributes()); got != 5 {
		t.Errorf("session node has %d attributes, want 5: %+v",
			got, sessionNode.Attributes())
	}
	for _, forbidden := range []domain.AttributeKey{
		"postgres.session_authorization", "postgres.search_path",
		"postgres.backend_key", "postgres.application_name",
	} {
		if _, present := sessionNode.Attributes()[forbidden]; present {
			t.Errorf("%s reached the session node", forbidden)
		}
	}
}

// nodeOf returns the node for a step, failing if absent.
func nodeOf(t *testing.T, builder *domain.GraphBuilder, step domain.Step) domain.Evidence {
	t.Helper()
	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	for _, n := range graph.Nodes() {
		if n.Step() == step {
			return n
		}
	}
	t.Fatalf("no %s node in the graph", step)
	return domain.Evidence{}
}

func attr(node domain.Evidence, key domain.AttributeKey) string {
	if v, ok := node.Attributes()[key]; ok {
		return v.String()
	}
	return "<absent>"
}

// establish runs the whole chain and returns the session node.
func establish(t *testing.T, plan postgres.TLSPlan, role, password, database string) domain.Evidence {
	t.Helper()

	result, builder := startupFor(t, plan, false, role, database)
	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, role, password), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatalf("authentication for %s did not succeed", role)
	}
	t.Cleanup(func() { _ = session.Close() })

	if _, err := postgres.EstablishSession(
		context.Background(), builder, session, postgres.SessionParams{}); err != nil {
		t.Fatalf("EstablishSession: %v", err)
	}
	return nodeOf(t, builder, postgres.StepSession)
}

// TestRealServerSessionFailures covers the three SQLSTATEs that arrive after
// AuthenticationOk on a genuine backend.
func TestRealServerSessionFailures(t *testing.T) {
	t.Run("unknown database is RESOURCE_NOT_FOUND", func(t *testing.T) {
		node := establish(t, postgres.TLSRequired, scramRole, scramPassword, "nosuchdb_qk7z")
		if node.State() != domain.StateFail {
			t.Errorf("state = %s, want FAIL", node.State())
		}
		if node.FailureClass() != domain.FailureResourceNotFound {
			t.Errorf("class = %s, want RESOURCE_NOT_FOUND", node.FailureClass())
		}
		if got := attr(node, postgres.AttrSQLState); got != "3D000" {
			t.Errorf("sqlstate = %q, want 3D000", got)
		}
	})

	t.Run("CONNECT denied is AUTHZ_DENIED", func(t *testing.T) {
		node := establish(t, postgres.TLSRequired, norightsRole, norightsPassword, closedDatabase)
		if node.State() != domain.StateFail {
			t.Errorf("state = %s, want FAIL", node.State())
		}
		if node.FailureClass() != domain.FailureAuthzDenied {
			t.Errorf("class = %s, want AUTHZ_DENIED", node.FailureClass())
		}
		if got := attr(node, postgres.AttrSQLState); got != "42501" {
			t.Errorf("sqlstate = %q, want 42501", got)
		}
	})
}

// 2. Verified TLS, wrong password.
func TestRealServerWrongPassword(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, false, scramRole)

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, scramRole, "definitely-not-the-password"), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("a wrong password produced an authenticated session")
	}

	node := authNode(t, builder)
	if node.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", node.State())
	}
	if node.FailureClass() != domain.FailureAuthCredentialsRejected {
		t.Errorf("class = %s, want AUTH_CREDENTIALS_REJECTED", node.FailureClass())
	}
	if got, ok := node.Attributes()[postgres.AttrSQLState]; !ok || got.String() != "28P01" {
		t.Errorf("sqlstate = %v, want 28P01", got)
	}
}

// 3. Unknown role must be indistinguishable from a wrong password.
//
// PostgreSQL issues a mock salt for a role that does not exist, deliberately, so
// that a client cannot enumerate roles. The assertion is that svcdoctor reports
// the same thing for both — because claiming otherwise would be a claim it
// cannot support.
func TestRealServerUnknownRoleIsIndistinguishable(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, false, "ghost_role_that_does_not_exist")

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, "ghost_role_that_does_not_exist", scramPassword), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("an unknown role produced an authenticated session")
	}

	node := authNode(t, builder)
	if node.FailureClass() != domain.FailureAuthCredentialsRejected {
		t.Errorf("class = %s, want AUTH_CREDENTIALS_REJECTED", node.FailureClass())
	}
	if got, ok := node.Attributes()[postgres.AttrSQLState]; !ok || got.String() != "28P01" {
		t.Errorf("sqlstate = %v, want 28P01 — the same code a wrong password produces", got)
	}
}

// 4. The printable-ASCII boundary, against a real verifier.
func TestRealServerPasswordBoundaries(t *testing.T) {
	t.Run("a printable-ASCII password with a space and a tilde authenticates", func(t *testing.T) {
		result, builder := startup(t, postgres.TLSRequired, false, scramRole)
		session, err := postgres.Authenticate(context.Background(), builder, result,
			credential(t, scramRole, scramPassword), postgres.AuthParams{})
		if err != nil || session == nil {
			t.Fatalf("Authenticate: %v", err)
		}
		_ = session.Close()
	})

	t.Run("a non-ASCII password is a gap in svcdoctor, not a rejection", func(t *testing.T) {
		result, builder := startup(t, postgres.TLSRequired, false, scramRole)
		session, err := postgres.Authenticate(context.Background(), builder, result,
			credential(t, scramRole, "pa ss"), postgres.AuthParams{})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if session != nil {
			t.Fatal("a non-ASCII password produced a session")
		}

		node := authNode(t, builder)
		if node.State() != domain.StateUnknown {
			t.Errorf("state = %s, want UNKNOWN", node.State())
		}
		if node.FailureClass() != domain.FailureExecUnsupportedBySvcdoctor {
			t.Errorf("class = %s, want EXEC_UNSUPPORTED_BY_SVCDOCTOR", node.FailureClass())
		}
		if node.FailureClass() == domain.FailureAuthCredentialsRejected {
			t.Fatal("a svcdoctor limitation was reported as a credential rejection")
		}
	})
}

// 5. Plaintext under the default policy: refused, with the ssl_request node as
// the blocker.
func TestRealServerPlaintextIsRefusedByPolicy(t *testing.T) {
	result, builder := startup(t, postgres.TLSDisabled, false, scramRole)

	if result.Channel() != security.ChannelPlaintext {
		t.Fatalf("channel = %s, want plaintext", result.Channel())
	}

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, scramRole, scramPassword), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("a plaintext channel produced an authenticated session")
	}

	node := authNode(t, builder)
	if node.State() != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", node.State())
	}
	if node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Errorf("class = %s, want EXEC_SKIPPED_BY_POLICY", node.FailureClass())
	}

	graph, err := builder.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	blockers := graph.BlockedBy(node.ID())
	if len(blockers) == 0 {
		t.Fatal("the refusal names no blocker; the ssl_request node should be one")
	}
	t.Logf("refusal blocked by: %v", blockers)
}

// 6. Unverified TLS under the default policy: also refused.
func TestRealServerUnverifiedTLSIsRefusedByPolicy(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, true, scramRole)

	if result.Channel() != security.ChannelTLSUnverified {
		t.Fatalf("channel = %s, want tls-unverified", result.Channel())
	}

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, scramRole, scramPassword), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session != nil {
		t.Fatal("an unverified channel produced an authenticated session")
	}

	node := authNode(t, builder)
	if node.State() != domain.StateSkipped ||
		node.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Errorf("state/class = %s/%s, want SKIPPED/EXEC_SKIPPED_BY_POLICY",
			node.State(), node.FailureClass())
	}
}

// 7. A credential bound elsewhere is a local invocation error, not evidence.
func TestRealServerEndpointMismatch(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, false, scramRole)

	elsewhere, err := security.NewEndpoint("somewhere-else.internal", pgPort)
	if err != nil {
		t.Fatalf("NewEndpoint: %v", err)
	}
	bound, err := security.NewCredential(elsewhere, scramRole, security.NewSecret(scramPassword))
	if err != nil {
		t.Fatalf("NewCredential: %v", err)
	}

	session, err := postgres.Authenticate(
		context.Background(), builder, result, bound, postgres.AuthParams{})
	if !errors.Is(err, security.ErrEndpointMismatch) {
		t.Fatalf("err = %v, want ErrEndpointMismatch", err)
	}
	if session != nil {
		t.Fatal("a mismatched credential produced a session")
	}
	if hasAuthNode(t, builder) {
		t.Error("an endpoint mismatch recorded an authentication node")
	}
	if strings.Contains(err.Error(), scramPassword) {
		t.Error("the error carried the password")
	}
}

// Mechanisms svcdoctor observes and declines, against real pg_hba entries.
func TestRealServerDeclinedMechanisms(t *testing.T) {
	for _, tc := range []struct {
		name, role, method string
	}{
		{"md5", md5Role, "md5"},
		{"cleartext password", cleartextRole, "cleartext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, builder := startup(t, postgres.TLSRequired, false, tc.role)

			if result.AuthMethod() != tc.method {
				t.Fatalf("auth method = %q, want %q", result.AuthMethod(), tc.method)
			}

			session, err := postgres.Authenticate(context.Background(), builder, result,
				credential(t, tc.role, "irrelevant"), postgres.AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if session != nil {
				t.Fatal("a declined mechanism produced a session")
			}

			node := authNode(t, builder)
			if node.State() != domain.StateUnknown {
				t.Errorf("state = %s, want UNKNOWN", node.State())
			}
			if node.FailureClass() != domain.FailureAuthMechanismUnsupported {
				t.Errorf("class = %s, want AUTH_MECHANISM_UNSUPPORTED", node.FailureClass())
			}
		})
	}
}

// A server that demands nothing produces no authentication node and a usable
// connection, even over plaintext, because no credential is written.
func TestRealServerTrustAuthentication(t *testing.T) {
	result, builder := startup(t, postgres.TLSDisabled, false, trustRole)

	if result.AuthMethod() != "ok" {
		t.Fatalf("auth method = %q, want ok", result.AuthMethod())
	}

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, trustRole, "unused"), postgres.AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if session == nil {
		t.Fatal("a trust server produced no session")
	}
	t.Cleanup(func() { _ = session.Close() })

	if hasAuthNode(t, builder) {
		t.Error("a trust server produced an authentication node")
	}
}

// 9. One socket carries DNS-to-authentication, and nothing redials.
func TestRealServerUsesOneSocket(t *testing.T) {
	result, builder := startup(t, postgres.TLSRequired, false, scramRole)
	before := result.Address()

	session, err := postgres.Authenticate(context.Background(), builder, result,
		credential(t, scramRole, scramPassword), postgres.AuthParams{})
	if err != nil || session == nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if session.Address() != before {
		t.Errorf("address changed from %s to %s: something redialled", before, session.Address())
	}
	if result.Available() {
		t.Error("the startup result still offers a connection after Authenticate")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func readFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	header := make([]byte, 5)
	if _, err := readFull(conn, header); err != nil {
		t.Fatalf("reading frame header: %v", err)
	}
	length := int(header[1])<<24 | int(header[2])<<16 | int(header[3])<<8 | int(header[4])
	if length < 4 {
		t.Fatalf("frame announced an impossible length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := readFull(conn, body); err != nil {
		t.Fatalf("reading frame body: %v", err)
	}
	return header[0], body
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func printable(b []byte) string {
	out := make([]rune, 0, len(b))
	for _, c := range b {
		if c == 0 {
			out = append(out, '=')
			continue
		}
		out = append(out, rune(c))
	}
	return string(out)
}
