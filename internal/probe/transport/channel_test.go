package transport

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests pin the fact a future authentication step will rely on: what a
// retained connection proved about its peer. They use real handshakes against a
// loopback peer the test controls, because the fact is only worth anything if it
// comes from a handshake that actually happened.

// TestPlaintextPathCarriesPlaintextChannel covers the no-TLS branch. The value
// is a positive statement — the caller asked for no TLS — rather than something
// concluded from a missing TLS node.
func TestPlaintextPathCarriesPlaintextChannel(t *testing.T) {
	result, _ := run(t, tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1", len(continuations))
	}
	if got := continuations[0].Channel(); got != security.ChannelPlaintext {
		t.Errorf("channel = %s, want plaintext", got)
	}
	if continuations[0].Channel().IdentityVerified() {
		t.Error("a plaintext path claims a verified identity")
	}
}

// TestVerifiedTLSPathCarriesVerifiedChannel covers the only channel a credential
// may ever be written to under the current policy.
func TestVerifiedTLSPathCarriesVerifiedChannel(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1", len(continuations))
	}
	if got := continuations[0].Channel(); got != security.ChannelTLSVerified {
		t.Errorf("channel = %s, want tls-verified", got)
	}

	var policy security.CredentialTransportPolicy
	if !policy.PermitsCredentials(continuations[0].Channel()) {
		t.Error("a verified TLS path is refused by the default policy, so nothing could authenticate")
	}
}

// TestUnverifiedTLSIsNotVerifiedTLS is the mistake the whole phase exists to
// make impossible. The handshake completes, the channel is encrypted, and nobody
// checked who answered.
//
// The peer's certificate names another host, so this handshake would fail
// verification. It succeeds only because verification is off, which is exactly
// the situation that must not be mistaken for a verified channel.
func TestUnverifiedTLSIsNotVerifiedTLS(t *testing.T) {
	peer := newTLSPeer(t, []string{"other.internal"})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool, InsecureSkipVerify: true},
	})

	continuations := result.Continuations()
	if len(continuations) != 1 {
		t.Fatalf("continuations = %d, want 1: the handshake should complete unverified", len(continuations))
	}

	channel := continuations[0].Channel()
	if channel != security.ChannelTLSUnverified {
		t.Fatalf("channel = %s, want tls-unverified", channel)
	}
	if channel == security.ChannelTLSVerified {
		t.Fatal("an unverified handshake produced the verified channel")
	}
	if channel.IdentityVerified() {
		t.Error("an unverified handshake claims a verified identity")
	}

	var policy security.CredentialTransportPolicy
	if policy.PermitsCredentials(channel) {
		t.Error("the default policy permits credentials over an unverified channel")
	}
}

// TestChannelAgreesWithTheEvidence checks that the runtime fact and the recorded
// one cannot disagree about a single handshake, because both come from the same
// observation.
func TestChannelAgreesWithTheEvidence(t *testing.T) {
	cases := []struct {
		name        string
		insecure    bool
		wantChannel security.Channel
	}{
		{"verified", false, security.ChannelTLSVerified},
		{"verification disabled", true, security.ChannelTLSUnverified},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			peer := newTLSPeer(t, []string{testHost})
			dialer := &loopbackDialer{target: peer.addr}

			result, graph := run(t, Params{
				Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
				TLS: &TLSOptions{RootCAs: peer.pool, InsecureSkipVerify: tt.insecure},
			})

			continuations := result.Continuations()
			if len(continuations) != 1 {
				t.Fatalf("continuations = %d, want 1", len(continuations))
			}
			channel := continuations[0].Channel()
			if channel != tt.wantChannel {
				t.Fatalf("channel = %s, want %s", channel, tt.wantChannel)
			}

			evidence := node(t, graph, "tls.handshake/primary.internal:9092/10.0.0.1")
			recorded, ok := evidence.Attribute(tls.AttrVerified)
			if !ok {
				t.Fatal("the TLS node records no tls.verified attribute")
			}
			verified, _ := recorded.Bool()
			if verified != channel.IdentityVerified() {
				t.Errorf("evidence says verified=%v, the channel says %v: two representations of one handshake disagree",
					verified, channel.IdentityVerified())
			}
		})
	}
}

// TestFailedVerificationProducesNoChannelToUse covers the case a policy never
// has to judge: a rejected handshake yields no continuation at all, so there is
// no connection whose channel could be asked about.
func TestFailedVerificationProducesNoChannelToUse(t *testing.T) {
	peer := newTLSPeer(t, []string{"other.internal"})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort, Resolver: resolving(t, "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	if got := len(result.Continuations()); got != 0 {
		t.Fatalf("continuations = %d, want 0 after a rejected handshake", got)
	}
}

// TestChannelsDoNotContaminateEachOther covers several addresses in one run: each
// continuation carries the fact for its own connection, and taking or closing one
// does not disturb another.
//
// A single Run shares one TLS setting, so the cross-setting case is covered by
// the adapter's tests, where continuations from two runs meet.
func TestChannelsDoNotContaminateEachOther(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "10.0.0.1", "10.0.0.2", "2001:db8::1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	continuations := result.Continuations()
	if len(continuations) != 3 {
		t.Fatalf("continuations = %d, want 3", len(continuations))
	}
	for _, c := range continuations {
		if got := c.Channel(); got != security.ChannelTLSVerified {
			t.Errorf("%s channel = %s, want tls-verified", c.Address(), got)
		}
	}

	// Take one and close another. The remaining facts must be untouched: a
	// channel describes a connection, not the Result's bookkeeping.
	conn, ok := continuations[0].TakeConn()
	if !ok {
		t.Fatal("the first continuation had no connection")
	}
	defer func() { _ = conn.Close() }()
	if err := continuations[1].Close(); err != nil {
		t.Errorf("closing the second continuation: %v", err)
	}

	for _, c := range result.Continuations() {
		if got := c.Channel(); got != security.ChannelTLSVerified {
			t.Errorf("after transfer and close, %s channel = %s", c.Address(), got)
		}
	}
}

// TestChannelSurvivesOwnershipTransfer checks that the fact stays with the
// Continuation after its connection is taken. A caller holding the connection
// still needs to know what it proved.
func TestChannelSurvivesOwnershipTransfer(t *testing.T) {
	result, _ := run(t, tcpParams(resolving(t, "10.0.0.1"), newScriptedDialer(t)))

	continuation := result.Continuations()[0]
	before := continuation.Channel()

	conn, ok := continuation.TakeConn()
	if !ok {
		t.Fatal("no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if after := continuation.Channel(); after != before {
		t.Errorf("channel changed across the transfer: %s then %s", before, after)
	}
	if continuation.Available() {
		t.Error("the continuation still claims the connection")
	}
}

// TestChannelIntroducesNoSelection guards the rule that survives every phase:
// nothing here ranks paths, and a security fact must not become one by being a
// convenient sort key.
func TestChannelIntroducesNoSelection(t *testing.T) {
	peer := newTLSPeer(t, []string{testHost})
	dialer := &loopbackDialer{target: peer.addr}

	result, _ := run(t, Params{
		Host: testHost, Port: testPort,
		Resolver: resolving(t, "2001:db8::1", "10.0.0.1"), Dialer: dialer,
		TLS: &TLSOptions{RootCAs: peer.pool},
	})

	var r any = result
	if _, ok := r.(interface{ Verified() []*Continuation }); ok {
		t.Error("the Result filters continuations by channel")
	}
	if _, ok := r.(interface{ Best() *Continuation }); ok {
		t.Error("the Result ranks continuations")
	}

	// Canonical address order is evidence ordering, and adding a channel must
	// not have turned it into anything else.
	continuations := result.Continuations()
	if len(continuations) != 2 {
		t.Fatalf("continuations = %d, want 2", len(continuations))
	}
	if !continuations[0].Address().Addr().Is4() {
		t.Error("canonical ordering changed; that is evidence ordering, not a preference")
	}
}
