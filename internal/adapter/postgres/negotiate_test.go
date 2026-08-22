package postgres

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	probetls "github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// saslReply is an AuthenticationSASL advertising the mechanisms a real server
// offers over TLS.
func saslReply(mechanisms ...string) []byte {
	body := binary.BigEndian.AppendUint32(nil, 10)
	for _, m := range mechanisms {
		body = append(body, m...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := []byte{'R'}
	// Bounded before the conversion: a fixture body is never near the limit,
	// and an unchecked int->uint32 is the shape of a real framing bug.
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

// errorReply is an ErrorResponse carrying a SQLSTATE, a non-localized severity,
// and a message stuffed with everything that must not survive.
func errorReply(sqlState string, extra ...string) []byte {
	pairs := []string{"S", "FATAL", "V", "FATAL", "C", sqlState}
	pairs = append(pairs, extra...)

	var body []byte
	for i := 0; i+1 < len(pairs); i += 2 {
		body = append(body, pairs[i][0])
		body = append(body, pairs[i+1]...)
		body = append(body, 0)
	}
	body = append(body, 0)

	out := []byte{'E'}
	if len(body) > 1<<20 {
		panic("fixture body too large to frame")
	}
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)+4)) //nolint:gosec // bounded above.
	return append(out, body...)
}

func tlsOptions(p *pgPeer) TLSOptions {
	return TLSOptions{ServerName: "localhost", RootCAs: p.ca}
}

// --- the accepted path -------------------------------------------------------

// TestSSLAcceptedUpgradesTheSameSocket is the phase's central proof.
//
// One socket carries the SSLRequest, the TLS handshake and the StartupMessage.
// The graph records the causal chain, the channel comes from the probe that
// handshook, and the peer accepted exactly one connection.
func TestSSLAcceptedUpgradesTheSameSocket(t *testing.T) {
	peer := newPGPeer(t, script{
		sslReply:     []byte("S"),
		upgradeTLS:   true,
		afterStartup: saslReply("SCRAM-SHA-256-PLUS", "SCRAM-SHA-256"),
	})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if !session.Available() {
		t.Fatal("a successful upgrade produced no connection")
	}
	if got := session.Channel(); got != security.ChannelTLSVerified {
		t.Errorf("channel = %s, want tls-verified", got)
	}
	if !security.RequireVerifiedTLS.PermitsCredentials(session.Channel()) {
		t.Error("the default policy refused a verified channel")
	}

	result, err := Startup(context.Background(), builder, session, StartupParams{
		User: "payments_writer", Database: "payments_prod",
	})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if result == nil {
		t.Fatal("Startup produced no result on a server that asked for authentication")
	}
	t.Cleanup(func() { _ = result.Close() })

	// One socket for the whole exchange.
	if got := peer.connections(); got != 1 {
		t.Errorf("peer accepted %d connections, want 1: something redialled", got)
	}
	if ports := peer.clientPorts(); len(ports) != 1 {
		t.Errorf("client used %d sockets, want 1: %v", len(ports), ports)
	}

	// Exactly the graph ADR 0036 section 8.1 draws.
	g := freeze(t, builder)
	assertParent(t, g, StepSSLRequest, "tcp.connect")
	assertParent(t, g, probetls.StepHandshake, StepSSLRequest)
	assertParent(t, g, StepStartup, probetls.StepHandshake)

	ssl := nodeFor(t, g, StepSSLRequest)
	if ssl.State() != domain.StatePass {
		t.Errorf("ssl_request state = %s, want PASS", ssl.State())
	}
	if ssl.Layer() != domain.LayerTLS {
		t.Errorf("ssl_request layer = %s, want L3", ssl.Layer())
	}
	if offered, ok := ssl.Attribute(AttrSSLOffered); !ok || !boolOf(offered) {
		t.Error("ssl_request did not record that the server offered TLS")
	}

	startup := nodeFor(t, g, StepStartup)
	if startup.State() != domain.StatePass {
		t.Errorf("startup state = %s, want PASS", startup.State())
	}
	if startup.Layer() != domain.LayerProtocol {
		t.Errorf("startup layer = %s, want L4", startup.Layer())
	}
	if got := stringOf(t, startup, AttrAuthMethod); got != "sasl" {
		t.Errorf("auth_method = %q, want %q", got, "sasl")
	}

	// The mechanism list is channel-dependent: PLUS is offered only over TLS.
	if got := result.SASLMechanisms(); len(got) != 2 || got[0] != "SCRAM-SHA-256-PLUS" {
		t.Errorf("mechanisms = %v, want the advertised pair in order", got)
	}
	if result.Channel() != security.ChannelTLSVerified {
		t.Errorf("startup result channel = %s, want tls-verified", result.Channel())
	}
}

// TestChannelEvidenceNamesTheTLSNode proves the runtime fact and the node that
// established it describe the same connection.
func TestChannelEvidenceNamesTheTLSNode(t *testing.T) {
	peer := newPGPeer(t, script{sslReply: []byte("S"), upgradeTLS: true})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	id, ok := session.ChannelEvidence()
	if !ok {
		t.Fatal("a TLS session named no classifier")
	}
	g := freeze(t, builder)
	node, present := g.Node(id)
	if !present {
		t.Fatalf("channel evidence %s is not in the graph", id)
	}
	if node.Step() != probetls.StepHandshake {
		t.Errorf("channel evidence is %s, want the TLS node", node.Step())
	}
}

// TestUnverifiedTLSStaysUnverified proves the adapter propagates a weaker fact
// unchanged rather than strengthening it.
func TestUnverifiedTLSStaysUnverified(t *testing.T) {
	peer := newPGPeer(t, script{sslReply: []byte("S"), upgradeTLS: true})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS:        TLSRequired,
		TLSOptions: TLSOptions{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if got := session.Channel(); got != security.ChannelTLSUnverified {
		t.Errorf("channel = %s, want tls-unverified", got)
	}
	if security.RequireVerifiedTLS.PermitsCredentials(session.Channel()) {
		t.Error("the default policy permitted credentials on an unverified channel")
	}
}

// TestTLSHandshakeFailureStopsTheChain covers a certificate the run cannot
// accept: the generic probe owns the diagnosis and PostgreSQL adds nothing.
func TestTLSHandshakeFailureStopsTheChain(t *testing.T) {
	peer := newPGPeer(t, script{sslReply: []byte("S"), upgradeTLS: true})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired,
		// A name the fixture's certificate does not carry.
		TLSOptions: TLSOptions{ServerName: "wrong.example", RootCAs: peer.ca},
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if session.Available() {
		t.Error("a failed handshake left a usable connection")
	}
	if got := session.Channel(); got != security.ChannelUnknown {
		t.Errorf("channel = %s, want unknown", got)
	}

	g := freeze(t, builder)
	tlsNode := nodeFor(t, g, probetls.StepHandshake)
	if tlsNode.State() != domain.StateFail {
		t.Errorf("tls state = %s, want FAIL", tlsNode.State())
	}
	if tlsNode.FailureClass() != domain.FailureTLSHostnameMismatch {
		t.Errorf("tls failure = %s, want TLS_HOSTNAME_MISMATCH", tlsNode.FailureClass())
	}

	// Startup records why it never ran.
	if _, err := Startup(context.Background(), builder, session, StartupParams{User: "app"}); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	g = freeze(t, builder)
	startup := nodeFor(t, g, StepStartup)
	if startup.State() != domain.StateSkipped {
		t.Errorf("startup state = %s, want SKIPPED", startup.State())
	}
	if blocked := g.BlockedBy(startup.ID()); len(blocked) != 1 || blocked[0] != tlsNode.ID() {
		t.Errorf("startup blockedBy = %v, want the TLS node", blocked)
	}
}

// --- the declined path -------------------------------------------------------

// TestTLSRequiredButDeclinedFailsAtL3 is the contract ADR 0036 section 4 fixes.
//
// The observation is "the server said no"; the failure is the *step's*, because
// the step exists to obtain encryption the run required. There is no fallback.
func TestTLSRequiredButDeclinedFailsAtL3(t *testing.T) {
	peer := newPGPeer(t, script{sslReply: []byte("N")})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if session.Available() {
		t.Error("a declined negotiation left a usable connection")
	}

	g := freeze(t, builder)
	ssl := nodeFor(t, g, StepSSLRequest)
	if ssl.State() != domain.StateFail {
		t.Errorf("ssl_request state = %s, want FAIL", ssl.State())
	}
	if ssl.FailureClass() != domain.FailureProtocolUnsupportedCapability {
		t.Errorf("failure = %s, want PROTOCOL_UNSUPPORTED_CAPABILITY", ssl.FailureClass())
	}
	if offered, ok := ssl.Attribute(AttrSSLOffered); !ok || boolOf(offered) {
		t.Error("ssl_request did not record that the server declined")
	}

	// The handshake that would have run is recorded as skipped and blocked.
	tlsNode := nodeFor(t, g, probetls.StepHandshake)
	if tlsNode.State() != domain.StateSkipped {
		t.Errorf("tls state = %s, want SKIPPED", tlsNode.State())
	}
	if blocked := g.BlockedBy(tlsNode.ID()); len(blocked) != 1 || blocked[0] != ssl.ID() {
		t.Errorf("tls blockedBy = %v, want the ssl_request node", blocked)
	}

	// And no startup packet ever left.
	if _, err := Startup(context.Background(), builder, session, StartupParams{User: "app"}); err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if got := len(peer.startupPackets()); got != 0 {
		t.Errorf("%d startup packets were sent after a refused negotiation, want 0", got)
	}
}

// --- the plaintext path ------------------------------------------------------

// TestPlaintextPlanDoesNotAsk pins the correction this phase made to ADR 0036
// section 4.
//
// The ADR said the request would still be sent under a plaintext plan and the
// session would continue regardless. A real PostgreSQL 18.6 server proves it
// cannot: after 'S' the socket belongs to the server's TLS layer, and a plaintext
// StartupMessage is read as a TLS record and the connection closed. libpq does
// not ask under `disable` either.
//
// The fact the ADR wanted survives: the node is still recorded, as SKIPPED by
// policy, which states positively that no TLS was attempted here.
func TestPlaintextPlanDoesNotAsk(t *testing.T) {
	peer := newPGPeer(t, script{
		expectNoSSLRequest: true,
		afterStartup:       saslReply("SCRAM-SHA-256"),
	})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{TLS: TLSDisabled})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	if !session.Available() {
		t.Fatal("the plaintext plan produced no usable connection")
	}
	if got := session.Channel(); got != security.ChannelPlaintext {
		t.Errorf("channel = %s, want plaintext", got)
	}
	if security.RequireVerifiedTLS.PermitsCredentials(session.Channel()) {
		t.Error("the default policy permitted credentials over plaintext")
	}

	g := freeze(t, builder)
	ssl := nodeFor(t, g, StepSSLRequest)
	if ssl.State() != domain.StateSkipped {
		t.Errorf("ssl_request state = %s, want SKIPPED", ssl.State())
	}
	if ssl.FailureClass() != domain.FailureExecSkippedByPolicy {
		t.Errorf("failure = %s, want EXEC_SKIPPED_BY_POLICY", ssl.FailureClass())
	}
	if _, present := ssl.Attribute(AttrSSLOffered); present {
		t.Error("a node that never asked recorded whether the server offered TLS")
	}
	if got := stringOf(t, ssl, AttrTLSPlan); got != "disabled" {
		t.Errorf("tls plan = %q, want %q", got, "disabled")
	}

	// No TLS node at all: nothing attempted a handshake.
	if hasNode(g, probetls.StepHandshake) {
		t.Error("a plaintext run recorded a TLS handshake node")
	}

	// This is what Phase 4.2 left open: a plaintext channel that can name the
	// node proving it.
	id, ok := session.ChannelEvidence()
	if !ok {
		t.Fatal("a plaintext session named no classifier; ADR 0030's gap is still open")
	}
	if id != ssl.ID() {
		t.Errorf("channel evidence = %s, want the ssl_request node %s", id, ssl.ID())
	}

	// The session still works: startup goes over the same socket.
	result, err := Startup(context.Background(), builder, session, StartupParams{User: "app"})
	if err != nil {
		t.Fatalf("Startup: %v", err)
	}
	if result == nil {
		t.Fatal("startup produced no result over plaintext")
	}
	t.Cleanup(func() { _ = result.Close() })

	if got := peer.connections(); got != 1 {
		t.Errorf("peer accepted %d connections, want 1", got)
	}
	if result.Channel() != security.ChannelPlaintext {
		t.Errorf("result channel = %s, want plaintext", result.Channel())
	}
}

// --- responses that are not a negotiation ------------------------------------

// TestSSLResponseFailures covers everything the negotiation can meet that is not
// an accept or a decline.
func TestSSLResponseFailures(t *testing.T) {
	cases := []struct {
		name  string
		reply []byte
		want  domain.FailureClass
	}{
		{"error response", []byte("E"), domain.FailureProtocolUnexpectedResponse},
		{"http server", []byte("HTTP/1.1 200 OK\r\n"), domain.FailureProtocolUnexpectedResponse},
		{"stuffed socket", []byte("SINJECTED"), domain.FailureProtocolUnexpectedResponse},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := newPGPeer(t, script{sslReply: tc.reply})
			path, builder := pathTo(t, peer)

			session, err := Negotiate(context.Background(), builder, path, Params{
				TLS: TLSRequired, TLSOptions: tlsOptions(peer),
			})
			if err != nil {
				t.Fatalf("Negotiate: %v", err)
			}
			t.Cleanup(func() { _ = session.Close() })

			g := freeze(t, builder)
			ssl := nodeFor(t, g, StepSSLRequest)
			if ssl.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", ssl.State())
			}
			if ssl.FailureClass() != tc.want {
				t.Errorf("failure = %s, want %s", ssl.FailureClass(), tc.want)
			}
			if session.Available() {
				t.Error("a failed negotiation left a usable connection")
			}
		})
	}
}

// TestSSLErrorResponseTextNeverEscapes is the CVE-2024-10977 guard at the
// adapter boundary.
//
// The peer is unauthenticated when it answers an SSLRequest, so its message must
// not be shown or stored. svcdoctor does not even read it: the negotiation stops
// at the single byte.
func TestSSLErrorResponseTextNeverEscapes(t *testing.T) {
	const canary = "UNAUTHENTICATED-ERROR-CANARY"

	peer := newPGPeer(t, script{sslReply: append([]byte("E"), canary...)})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	g := freeze(t, builder)
	assertNoCanary(t, g, canary)
}

// TestPeerClosedDuringNegotiation distinguishes a peer that went away from one
// that answered wrongly.
func TestPeerClosedDuringNegotiation(t *testing.T) {
	peer := newPGPeer(t, script{})
	path, builder := pathTo(t, peer)

	session, err := Negotiate(context.Background(), builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	g := freeze(t, builder)
	ssl := nodeFor(t, g, StepSSLRequest)
	if ssl.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", ssl.State())
	}
	if ssl.FailureClass() != domain.FailureProtocolPeerClosed {
		t.Errorf("failure = %s, want PROTOCOL_PEER_CLOSED", ssl.FailureClass())
	}
}

// TestCancellationIsNotARemoteFailure keeps svcdoctor's own budget on
// svcdoctor's side of the line.
func TestCancellationIsNotARemoteFailure(t *testing.T) {
	peer := newPGPeer(t, script{hangBeforeReply: true})
	path, builder := pathTo(t, peer)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		peer.waitForConnection(t)
		cancel()
	}()

	session, err := Negotiate(ctx, builder, path, Params{
		TLS: TLSRequired, TLSOptions: tlsOptions(peer),
	})
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	g := freeze(t, builder)
	ssl := nodeFor(t, g, StepSSLRequest)
	if ssl.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a cancelled run is not a remote failure", ssl.State())
	}
	if ssl.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure = %s, want EXEC_CANCELLED", ssl.FailureClass())
	}
}

// --- helpers -----------------------------------------------------------------

func assertParent(t *testing.T, g domain.Graph, child, parent domain.Step) {
	t.Helper()

	childNode := nodeFor(t, g, child)
	parentNode := nodeFor(t, g, parent)
	for _, id := range g.Parents(childNode.ID()) {
		if id == parentNode.ID() {
			return
		}
	}
	t.Errorf("%s is not parented to %s; parents are %v", child, parent, g.Parents(childNode.ID()))
}

func assertNoCanary(t *testing.T, g domain.Graph, canaries ...string) {
	t.Helper()

	for _, node := range g.Nodes() {
		text := node.ID().String() + " " + node.Subject().Ref()
		for key, value := range node.Attributes() {
			text += " " + string(key) + " " + value.String()
		}
		for _, canary := range canaries {
			if strings.Contains(text, canary) {
				t.Errorf("canary %q reached evidence: %s", canary, text)
			}
		}
	}
}

func boolOf(v domain.AttrValue) bool {
	b, _ := v.Bool()
	return b
}

func stringOf(t *testing.T, e domain.Evidence, key domain.AttributeKey) string {
	t.Helper()
	v, ok := e.Attribute(key)
	if !ok {
		t.Fatalf("attribute %s is missing from %s", key, e.Step())
	}
	s, ok := v.Str()
	if !ok {
		t.Fatalf("attribute %s has kind %s, want string", key, v.Kind())
	}
	return s
}
