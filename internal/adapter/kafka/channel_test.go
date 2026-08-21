package kafka

import (
	"context"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests follow the channel fact through the two Kafka steps. The adapter
// must carry it and must not be able to change it: it never performed a
// handshake, so it has nothing to base a stronger claim on.

// TestChannelReachesTheSession covers the first hop, transport to L4.
func TestChannelReachesTheSession(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	want := paths.Continuations()[0].Channel()
	if want != security.ChannelPlaintext {
		t.Fatalf("precondition: continuation channel = %s, want plaintext", want)
	}

	result := run(t, paths, builder, Params{})
	if got := result.Sessions()[0].Channel(); got != want {
		t.Errorf("session channel = %s, want %s", got, want)
	}
}

// TestChannelReachesTheHandshakeSession covers the second hop, L4 to L5. This is
// the accessor authentication will consult.
func TestChannelReachesTheHandshakeSession(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	want := sessions.Sessions()[0].Channel()

	result := runHandshake(t, sessions, builder, SASLParams{})
	handshakeSessions := result.Sessions()
	if len(handshakeSessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(handshakeSessions))
	}
	if got := handshakeSessions[0].Channel(); got != want {
		t.Errorf("handshake session channel = %s, want %s", got, want)
	}
}

// TestPlaintextIsRefusedByTheDefaultPolicy is the end-to-end statement this
// phase exists to make: the fixture's connections are plaintext, and the policy
// a future authentication step will consult refuses them.
//
// Nothing here authenticates. The point is that the refusal is derivable today,
// from a fact that travelled with the connection, without inspecting the socket
// or reading the graph.
func TestPlaintextIsRefusedByTheDefaultPolicy(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	result := runHandshake(t, sessions, builder, SASLParams{})

	var policy security.CredentialTransportPolicy
	for _, session := range result.Sessions() {
		if policy.PermitsCredentials(session.Channel()) {
			t.Errorf("%s: a plaintext session is permitted to carry credentials", session.Address())
		}
	}
}

// TestAdapterExposesNoChannelMutator checks the part of the guarantee the type
// system actually provides: no caller of this package can set or upgrade a
// channel, because the fields are unexported and no mutator exists.
//
// It deliberately does not claim more. Inside this package the fields are
// reachable — a package owns them — so what stops this code from forging a
// channel is the constructors copying it from the object being continued, a lint
// that forbids naming a security.Channel constant here, and the mutation-checked
// tests below. See ADR 0029, "What the guarantee actually is".
func TestAdapterExposesNoChannelMutator(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)
	result := runHandshake(t, sessions, builder, SASLParams{})

	var session any = result.Sessions()[0]
	if _, ok := session.(interface{ SetChannel(security.Channel) }); ok {
		t.Error("a handshake session lets a caller set its channel")
	}
	if _, ok := session.(interface {
		WithChannel(security.Channel) *HandshakeSession
	}); ok {
		t.Error("a handshake session lets a caller derive one with another channel")
	}
	if _, ok := session.(interface{ MarkVerified() }); ok {
		t.Error("a handshake session lets a caller mark itself verified")
	}

	var apiSession any = sessions.Sessions()[0]
	if _, ok := apiSession.(interface{ SetChannel(security.Channel) }); ok {
		t.Error("a session lets a caller set its channel")
	}
}

// TestVerifiedTLSReachesTheHandshakeSession is the precondition for any future
// credential: a real handshake, verified against a trust source the test
// controls, whose fact survives DNS, TCP, TLS, ApiVersions and SaslHandshake and
// arrives on the session authentication would consume.
func TestVerifiedTLSReachesTheHandshakeSession(t *testing.T) {
	broker, pool := newTLSBroker(t, "primary.internal")

	builder := domain.NewGraphBuilder()
	sessions := apiVersionsSessionsAt(t, builder, broker, "primary.internal", "10.0.0.1",
		&transport.TLSOptions{RootCAs: pool})

	if len(sessions.Sessions()) != 1 {
		t.Fatalf("sessions = %d, want 1: the TLS path did not complete", len(sessions.Sessions()))
	}
	if got := sessions.Sessions()[0].Channel(); got != security.ChannelTLSVerified {
		t.Fatalf("session channel = %s, want tls-verified", got)
	}

	result, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	handshakeSessions := result.Sessions()
	if len(handshakeSessions) != 1 {
		t.Fatalf("handshake sessions = %d, want 1", len(handshakeSessions))
	}

	channel := handshakeSessions[0].Channel()
	if channel != security.ChannelTLSVerified {
		t.Errorf("handshake session channel = %s, want tls-verified", channel)
	}

	var policy security.CredentialTransportPolicy
	if !policy.PermitsCredentials(channel) {
		t.Error("a verified TLS session is refused, so nothing could ever authenticate")
	}
}

// TestMixedChannelsDoNotContaminate is the case a single transport run cannot
// produce: two endpoints established under different transport security, whose
// sessions meet in one adapter call. Each fact must arrive on its own session.
func TestMixedChannelsDoNotContaminate(t *testing.T) {
	secure, pool := newTLSBroker(t, "primary.internal")
	plain := newBroker(t, peerAnswers)

	builder := domain.NewGraphBuilder()
	secureSessions := apiVersionsSessionsAt(t, builder, secure, "primary.internal", "10.0.0.1",
		&transport.TLSOptions{RootCAs: pool})
	plainSessions := apiVersionsSessionsAt(t, builder, plain, "secondary.internal", "10.0.0.2", nil)

	combined := append(secureSessions.Sessions(), plainSessions.Sessions()...)
	if len(combined) != 2 {
		t.Fatalf("sessions = %d, want 2", len(combined))
	}

	result, err := SASLHandshake(context.Background(), builder, combined, SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	byAddress := map[string]security.Channel{}
	for _, session := range result.Sessions() {
		byAddress[session.Address().Addr().String()] = session.Channel()
	}
	if len(byAddress) != 2 {
		t.Fatalf("handshake sessions = %d, want one per path", len(byAddress))
	}
	if got := byAddress["10.0.0.1"]; got != security.ChannelTLSVerified {
		t.Errorf("the verified path carries %s", got)
	}
	if got := byAddress["10.0.0.2"]; got != security.ChannelPlaintext {
		t.Errorf("the plaintext path carries %s", got)
	}

	// The decision a future authentication step makes must differ per session,
	// which is the whole reason the fact travels with the connection.
	var policy security.CredentialTransportPolicy
	if !policy.PermitsCredentials(byAddress["10.0.0.1"]) {
		t.Error("the verified path was refused")
	}
	if policy.PermitsCredentials(byAddress["10.0.0.2"]) {
		t.Error("the plaintext path was permitted; a fact reached the wrong session")
	}
}

// TestChannelSurvivesSessionOwnershipTransfer checks the fact stays readable
// after the connection has been taken, which is when a caller most needs it: it
// is holding a socket and deciding what may be written to it.
func TestChannelSurvivesSessionOwnershipTransfer(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)
	result := runHandshake(t, sessions, builder, SASLParams{})

	session := result.Sessions()[0]
	before := session.Channel()

	conn, ok := session.TakeConn()
	if !ok {
		t.Fatal("no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if after := session.Channel(); after != before {
		t.Errorf("channel changed across the transfer: %s then %s", before, after)
	}
}

// TestChannelIsNotRecordedAsEvidence pins the decision that the channel is a
// runtime ownership fact rather than a diagnostic observation.
//
// tls.verified already records what a handshake proved, on the node that
// observed it. A second copy on a Kafka node would be one fact with two
// representations that can disagree, and it would change the canonical report
// for a value no reader asked for.
func TestChannelIsNotRecordedAsEvidence(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)
	runHandshake(t, sessions, builder, SASLParams{})

	graph := freeze(t, builder)
	for _, evidence := range graph.Nodes() {
		for key := range evidence.Attributes() {
			switch key {
			case "kafka.channel", "kafka.tls_verified", "channel", "transport.channel":
				t.Errorf("%s records %s: the channel leaked into evidence", evidence.ID(), key)
			}
		}
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		for _, forbidden := range []string{"plaintext", "tls-unverified", "tls-verified"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Errorf("%s carries the channel rendering %q", evidence.ID(), forbidden)
			}
		}
	}
}

// TestConstructorsCopyTheChannelRatherThanAcceptIt pins the enforcement that
// replaced the overclaim: neither adapter constructor takes a channel, so no
// call site can supply the wrong one.
//
// It is a compile-time property expressed as a runtime check on the same
// objects: every session's channel equals the channel of the object it was
// built from, for every path, with nothing in between that could substitute a
// value.
func TestConstructorsCopyTheChannelRatherThanAcceptIt(t *testing.T) {
	secure, pool := newTLSBroker(t, "primary.internal")
	plain := newBroker(t, peerAnswers)

	builder := domain.NewGraphBuilder()

	securePaths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: "primary.internal", Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, []string{"10.0.0.1"})},
		Dialer:   brokerDialer{target: secure.addr, conns: &connRegistry{}},
		TLS:      &transport.TLSOptions{RootCAs: pool},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = securePaths.Close() })

	plainPaths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: "secondary.internal", Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, []string{"10.0.0.2"})},
		Dialer:   brokerDialer{target: plain.addr, conns: &connRegistry{}},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = plainPaths.Close() })

	paths := append(securePaths.Continuations(), plainPaths.Continuations()...)
	fromTransport := map[string]security.Channel{}
	for _, p := range paths {
		fromTransport[p.Address().Addr().String()] = p.Channel()
	}

	apiVersions, err := Run(context.Background(), builder, paths, Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = apiVersions.Close() })

	for _, session := range apiVersions.Sessions() {
		address := session.Address().Addr().String()
		if got, want := session.Channel(), fromTransport[address]; got != want {
			t.Errorf("%s: L4 session carries %s, transport said %s", address, got, want)
		}
	}

	handshakes, err := SASLHandshake(
		context.Background(), builder, apiVersions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = handshakes.Close() })

	for _, session := range handshakes.Sessions() {
		address := session.Address().Addr().String()
		if got, want := session.Channel(), fromTransport[address]; got != want {
			t.Errorf("%s: L5 session carries %s, transport said %s", address, got, want)
		}
	}
	if len(handshakes.Sessions()) != 2 {
		t.Fatalf("handshake sessions = %d, want 2", len(handshakes.Sessions()))
	}
}
