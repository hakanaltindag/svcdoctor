package kafka

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests fail if authentication ever dials, keeps a socket it has nothing
// to send on, closes one it handed over, leaks one it kept, or touches a session
// it was not given.

// The compile-time half of the singular contract. Assigning each function to a
// variable of its exact intended type means a signature change stops the build
// rather than quietly widening what authentication accepts.
var (
	_ func(
		context.Context, *domain.GraphBuilder, *HandshakeSession, security.Credential, AuthParams,
	) (*AuthResult, error) = Authenticate

	_ func(
		context.Context, *domain.GraphBuilder, []*Session, SASLParams,
	) (*HandshakeResult, error) = SASLHandshake
)

// TestAuthenticateTakesExactlyOneSession states the asymmetry that carries the
// security decision.
//
// A slice parameter would make "authenticate everything" the path of least
// resistance and sessions[0] — which is IPv4 by canonical address ordering — the
// second-easiest thing to write. Discovery costs the target nothing and takes a
// slice; authentication is logged, counted and lockout-relevant, and takes one.
// Selection belongs to the caller, and this is where that is provable rather
// than promised.
func TestAuthenticateTakesExactlyOneSession(t *testing.T) {
	sessionParam := reflect.TypeOf(Authenticate).In(2)

	if sessionParam.Kind() == reflect.Slice {
		t.Fatalf("Authenticate takes %s: a slice makes authenticating every path the default",
			sessionParam)
	}
	if want := reflect.TypeOf(&HandshakeSession{}); sessionParam != want {
		t.Errorf("Authenticate takes %s, want %s", sessionParam, want)
	}

	// The discovery step keeps its slice, deliberately. A future change that
	// made the two symmetric would have to delete this on purpose.
	discoveryParam := reflect.TypeOf(SASLHandshake).In(2)
	if discoveryParam.Kind() != reflect.Slice {
		t.Errorf("SASLHandshake takes %s, want a slice: discovery asks every path", discoveryParam)
	}
}

// --- lifecycle ------------------------------------------------------------

// TestSuccessKeepsTheMeasuredConnection: this is the first Kafka step whose
// success returns a connection more usable than the one it consumed, because
// after authentication the protocol defines every next message.
func TestSuccessKeepsTheMeasuredConnection(t *testing.T) {
	target := verifiedTarget(t)
	conn := target.conn(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	if !result.Authenticated() {
		t.Fatal("the fixture credential was not accepted")
	}
	if got := conn.closeCount(); got != 0 {
		t.Fatalf("the authenticated connection was closed %d times, want 0", got)
	}

	session, ok := result.Session()
	if !ok {
		t.Fatal("no session on an authenticated result")
	}
	if !session.Available() {
		t.Error("the authenticated session holds no connection")
	}
	if got, want := session.Endpoint(), authEndpoint; got != want {
		t.Errorf("endpoint = %q, want the logical label %q", got, want)
	}
	if got, want := session.Mechanism(), "PLAIN"; got != want {
		t.Errorf("mechanism = %q, want %q carried from the handshake", got, want)
	}
	if got := session.Channel(); got != security.ChannelTLSVerified {
		t.Errorf("channel = %s, want tls-verified carried from the transport path", got)
	}
	if got := session.Evidence(); got != domain.EvidenceID(authNodeID) {
		t.Errorf("evidence = %s, want the authentication node", got)
	}
}

// TestAuthenticatedResultTransfersOwnershipOnce holds the ADR 0021 rules for the
// third session type.
func TestAuthenticatedResultTransfersOwnershipOnce(t *testing.T) {
	target := verifiedTarget(t)
	conn := target.conn(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
	session, ok := result.Session()
	if !ok {
		t.Fatal("no session on an authenticated result")
	}

	taken, ok := session.TakeConn()
	if !ok {
		t.Fatal("the authenticated session has no connection to take")
	}
	if _, again := session.TakeConn(); again {
		t.Error("a second caller took the same connection")
	}

	// After a transfer the result must not close what somebody else owns.
	if err := result.Close(); err != nil {
		t.Errorf("Close after transfer: %v", err)
	}
	if got := conn.closeCount(); got != 0 {
		t.Errorf("the result closed a connection it had handed over (%d closes)", got)
	}

	if err := taken.Close(); err != nil {
		t.Errorf("closing the taken connection: %v", err)
	}
	// Close stays idempotent and safe to defer unconditionally.
	if err := result.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

// TestFailedAuthenticationClosesItsConnection is the lifecycle matrix.
//
// The criterion is the protocol's, not the recorded state's: does this socket
// have a defined next message? After a rejection Kafka fails the connection.
// After a broken exchange nobody knows the socket's protocol state. After an
// expired budget a request may be in flight and a response unread, so the next
// reader would decode the wrong bytes — which is why UNKNOWN closes too.
func TestFailedAuthenticationClosesItsConnection(t *testing.T) {
	tests := []struct {
		name    string
		options []brokerOption
		params  AuthParams
	}{
		{name: "credentials rejected", options: []brokerOption{withAuthError(58)}},
		{name: "peer hangs up", options: []brokerOption{withAuth(peerHangsUp)}},
		{name: "undecodable response", options: []brokerOption{withAuth(peerSendsGarbage)}},
		{name: "peer is not kafka", options: []brokerOption{withAuth(peerSpeaksHTTP)}},
		{name: "answers another request", options: []brokerOption{withAuth(peerMisscorrelates)}},
		{
			name:    "local budget expired",
			options: []brokerOption{withAuth(peerSaysNothing)},
			params:  AuthParams{ExchangeTimeout: 50 * time.Millisecond},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := verifiedTarget(t, test.options...)
			conn := target.conn(t)

			result := authenticate(t, target, credentialFor(t, authHost, 9092), test.params)

			if result.Authenticated() {
				t.Fatal("a failed authentication reports itself as authenticated")
			}
			if _, ok := result.Session(); ok {
				t.Error("a failed authentication returned a session")
			}
			if got := conn.closeCount(); got == 0 {
				t.Error("the connection was left open after a failed authentication")
			}

			// The evidence exists whatever happened to the socket.
			if result.Evidence() == "" {
				t.Error("no evidence was recorded for the attempt")
			}
			if _, ok := freeze(t, target.builder).Node(result.Evidence()); !ok {
				t.Error("the result names a node that is not in the graph")
			}
		})
	}
}

// TestConnectionLifetimeIsNotDrivenByAuthEvidenceState holds apart two outcomes
// that share a shape: a broker error code at L4 keeps its socket, and a broker
// error code at authentication loses it.
//
// Both are FAIL with a recorded kafka.error_code. The difference is not the
// state; it is whether the protocol defines anything that may follow on that
// connection.
func TestConnectionLifetimeIsNotDrivenByAuthEvidenceState(t *testing.T) {
	// L4: a broker that answers ApiVersions with an error code keeps its socket.
	protocolBroker := newErrorBroker(t, 35)
	paths, builder, registry := dialedPaths(t, protocolBroker)
	protocolResult := run(t, paths, builder, Params{})

	if len(protocolResult.Sessions()) != 1 {
		t.Fatalf("api versions sessions = %d, want 1", len(protocolResult.Sessions()))
	}
	if got := openCount(registry.all()); got != 1 {
		t.Errorf("the L4 error-code path closed its connection; open = %d, want 1", got)
	}
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")
	if evidence.State() != domain.StateFail {
		t.Fatalf("precondition: L4 state = %s, want FAIL", evidence.State())
	}

	// L5 authentication: the same shape, and the socket goes.
	authTargetWithError := verifiedTarget(t, withAuthError(58))
	authConn := authTargetWithError.conn(t)
	authenticate(t, authTargetWithError, credentialFor(t, authHost, 9092), AuthParams{})

	authEvidence := node(t, freeze(t, authTargetWithError.builder), authNodeID)
	if authEvidence.State() != domain.StateFail {
		t.Fatalf("precondition: auth state = %s, want FAIL", authEvidence.State())
	}
	if authConn.closeCount() == 0 {
		t.Error("a rejected authentication kept its connection")
	}
}

// TestAuthenticateNeverDials: the whole vertical slice speaks over the socket
// the transport evidence describes.
func TestAuthenticateNeverDials(t *testing.T) {
	target := verifiedTarget(t)

	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d connections were established, want 1", got)
	}
}

// --- multi-path isolation -------------------------------------------------

// TestAuthenticatingOneSessionLeavesTheOthersUntouched is the practical half of
// the singular contract: given several paths, exactly the one that was named is
// used, and nothing about the others changes.
func TestAuthenticatingOneSessionLeavesTheOthersUntouched(t *testing.T) {
	target := verifiedTargetAt(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})

	if len(target.sessions) != 3 {
		t.Fatalf("handshake sessions = %d, want 3", len(target.sessions))
	}

	chosen := target.sessions[1]
	result, err := Authenticate(
		t.Context(), target.builder, chosen, credentialFor(t, authHost, 9092), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if !result.Authenticated() {
		t.Fatal("the chosen session did not authenticate")
	}

	// Exactly one authentication reached the peer.
	if got := target.broker.authRequestCount(); got != 1 {
		t.Errorf("broker received %d authentications, want exactly 1", got)
	}

	// The other sessions still hold their connections, unconsumed.
	for i, session := range target.sessions {
		if i == 1 {
			continue
		}
		if !session.Available() {
			t.Errorf("session %d (%s) lost its connection to an authentication it was not part of",
				i, session.Address())
		}
	}

	// And exactly one authentication node exists, for the address that was used.
	graph := freeze(t, target.builder)
	nodes := 0
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == StepSASLAuthenticate {
			nodes++
			if got, want := evidence.Subject().Ref(), "10.0.0.2:9092"; got != want {
				t.Errorf("authentication node subject = %q, want %q", got, want)
			}
		}
	}
	if nodes != 1 {
		t.Errorf("%d authentication nodes were recorded, want 1", nodes)
	}
}

// TestAuthenticationHasNoAddressFamilyPreference: the caller picked the IPv6
// path, and nothing in this package quietly used the IPv4 one that sorts first.
//
// ADR 0024 removed that artifact from the transport chain; re-introducing it on
// the path that carries a password would be strictly worse.
func TestAuthenticationHasNoAddressFamilyPreference(t *testing.T) {
	target := verifiedTargetAt(t, []string{"10.0.0.1", "2001:db8::1"})

	if len(target.sessions) != 2 {
		t.Fatalf("handshake sessions = %d, want 2", len(target.sessions))
	}
	if got := target.sessions[0].Address().Addr().String(); got != "10.0.0.1" {
		t.Fatalf("precondition: sessions[0] = %s, want the IPv4 address canonical order puts first", got)
	}

	ipv6 := target.sessions[1]
	if !ipv6.Address().Addr().Is6() {
		t.Fatalf("precondition: sessions[1] = %s, want an IPv6 address", ipv6.Address())
	}

	result, err := Authenticate(
		t.Context(), target.builder, ipv6, credentialFor(t, authHost, 9092), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if !result.Authenticated() {
		t.Fatal("the IPv6 path did not authenticate")
	}
	if !target.sessions[0].Available() {
		t.Error("the IPv4 session was consumed although the caller chose the IPv6 one")
	}

	graph := freeze(t, target.builder)
	if _, ok := graph.Node(domain.EvidenceID(authNodeID)); ok {
		t.Error("an authentication node exists for 10.0.0.1, which nobody authenticated")
	}
	wanted := domain.EvidenceID("kafka.sasl_authenticate/primary.internal:9092/2001:db8::1")
	if _, ok := graph.Node(wanted); !ok {
		t.Errorf("no authentication node for the IPv6 address the caller chose")
	}
}
