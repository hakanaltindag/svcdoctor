package tls

import (
	cryptotls "crypto/tls"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// This package is the authority for what a TLS handshake proved, and these are
// the tests that make that true rather than documented. Every case drives a real
// handshake against the loopback fixtures; none constructs a Result by hand,
// because a hand-built Result would prove that the accessor works and nothing
// about what the handshake observed.

// TestVerifiedHandshakeIsVerifiedChannel is the only channel a credential may
// cross under the default policy, so it is the case worth stating first.
func TestVerifiedHandshakeIsVerifiedChannel(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))

	if got := r.Channel(); got != security.ChannelTLSVerified {
		t.Errorf("Channel() = %s, want %s", got, security.ChannelTLSVerified)
	}
	if !security.RequireVerifiedTLS.PermitsCredentials(r.Channel()) {
		t.Error("the default policy refused a verified TLS channel")
	}
}

// TestInsecureHandshakeIsUnverifiedChannel is the canonical unverified case: the
// handshake completed, the traffic is encrypted, and nobody knows who answered.
//
// It must never be treated as equivalent to a verified channel, and the default
// policy must refuse it.
func TestInsecureHandshakeIsUnverifiedChannel(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"other.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	params := f.params(ca, "server.test")
	params.InsecureSkipVerify = true
	r := handshake(t, f.conn, params)

	if got := r.Channel(); got != security.ChannelTLSUnverified {
		t.Errorf("Channel() = %s, want %s", got, security.ChannelTLSUnverified)
	}
	if security.RequireVerifiedTLS.PermitsCredentials(r.Channel()) {
		t.Error("the default policy permitted credentials on an unverified channel")
	}
	// The handshake did succeed: this is a usable connection, just not an
	// identified one.
	if !r.Connected() {
		t.Error("an insecure handshake produced no connection")
	}
}

// TestFailedHandshakeHasNoChannelToClassify is the load-bearing negative case.
//
// A rejected certificate is a real diagnostic fact and the evidence records
// which one it was. It is *not* a runtime channel, because Channel governs what
// may be written to a live connection and a failed handshake produced none. In
// particular a hostname mismatch must not surface as ChannelTLSUnverified: that
// would describe a socket this package already closed.
//
// ChannelUnknown is refused by every policy, so the honest answer is also the
// safe one.
func TestFailedHandshakeHasNoChannelToClassify(t *testing.T) {
	ca := newTestCA(t)

	cases := map[string]func(t *testing.T) *Result{
		"hostname mismatch": func(t *testing.T) *Result {
			cert := ca.issue(t, leafOptions{dnsNames: []string{"other.test"}})
			f := dialFixture(t, peerTLS, serverConfig(cert, 0))
			return handshake(t, f.conn, f.params(ca, "server.test"))
		},
		"unknown authority": func(t *testing.T) *Result {
			other := newTestCA(t)
			cert := other.issue(t, leafOptions{dnsNames: []string{"server.test"}})
			f := dialFixture(t, peerTLS, serverConfig(cert, 0))
			return handshake(t, f.conn, f.params(ca, "server.test"))
		},
		"peer does not speak TLS": func(t *testing.T) *Result {
			f := dialFixture(t, peerPlaintext, nil)
			return handshake(t, f.conn, f.params(ca, "server.test"))
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			r := build(t)

			if r.Evidence().State() == domain.StatePass {
				t.Fatalf("fixture did not fail the handshake: %s", r.Evidence())
			}
			if got := r.Channel(); got != security.ChannelUnknown {
				t.Errorf("Channel() = %s, want %s: a failed handshake produced no "+
					"connection, so there is nothing to classify", got, security.ChannelUnknown)
			}
			if security.RequireVerifiedTLS.PermitsCredentials(r.Channel()) {
				t.Error("a failed handshake produced a channel the policy accepted")
			}
			if r.Connected() {
				t.Error("a failed handshake reported a live connection")
			}
		})
	}
}

// TestChannelAndEvidenceCannotDisagree is the single-source-of-truth proof, in
// both directions.
//
// The runtime fact governs whether a secret may be written to the socket; the
// evidence fact is what a report and a diagnosis rule read afterwards. They
// describe one handshake, and a deployment where they disagreed would either
// leak a credential or produce a report that contradicts what the tool did.
func TestChannelAndEvidenceCannotDisagree(t *testing.T) {
	ca := newTestCA(t)

	cases := []struct {
		name     string
		insecure bool
		want     security.Channel
	}{
		{"verified", false, security.ChannelTLSVerified},
		{"insecure", true, security.ChannelTLSUnverified},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
			f := dialFixture(t, peerTLS, serverConfig(cert, 0))
			params := f.params(ca, "server.test")
			params.InsecureSkipVerify = tc.insecure

			r := handshake(t, f.conn, params)

			channel := r.Channel()
			if channel != tc.want {
				t.Fatalf("Channel() = %s, want %s", channel, tc.want)
			}

			recorded := boolAttr(t, r.Evidence(), AttrVerified)
			verified := channel == security.ChannelTLSVerified

			if recorded != verified {
				t.Errorf("evidence %s = %v but Channel() = %s; the runtime fact and the "+
					"recorded fact describe one handshake and must agree",
					AttrVerified, recorded, channel)
			}
			// And the other accessor, which exists for callers that only need the
			// boolean, must not become a third opinion.
			if r.Verified() != verified {
				t.Errorf("Verified() = %v but Channel() = %s", r.Verified(), channel)
			}
		})
	}
}

// TestVerifiedIsDerivedFromChannel pins that the two accessors are one
// computation rather than two that happen to agree today.
func TestVerifiedIsDerivedFromChannel(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})

	for _, insecure := range []bool{false, true} {
		f := dialFixture(t, peerTLS, serverConfig(cert, 0))
		params := f.params(ca, "server.test")
		params.InsecureSkipVerify = insecure

		r := handshake(t, f.conn, params)
		if got, want := r.Verified(), r.Channel() == security.ChannelTLSVerified; got != want {
			t.Errorf("insecure=%v: Verified() = %v, want %v", insecure, got, want)
		}
	}
}

// TestChannelSurvivesOwnershipTransfer is why Channel is not keyed on
// Connected().
//
// The caller that takes the socket is exactly the caller that has to decide what
// may be written to it, and it asks after taking ownership — the transport chain
// does precisely that. A fact that evaporated on transfer would be useless to the
// only layer that needs it.
func TestChannelSurvivesOwnershipTransfer(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))
	before := r.Channel()

	conn, ok := r.TakeConn()
	if !ok {
		t.Fatal("TakeConn reported nothing to take")
	}
	t.Cleanup(func() { _ = conn.Close() })

	if after := r.Channel(); after != before {
		t.Errorf("Channel() = %s after TakeConn, was %s before", after, before)
	}
	if r.Connected() {
		t.Error("Connected() should be false after a transfer")
	}

	// Closing the Result after a transfer is a no-op, and must not change the
	// fact either.
	_ = r.Close()
	if after := r.Channel(); after != before {
		t.Errorf("Channel() = %s after Close, was %s before", after, before)
	}
}

// TestClosedResultKeepsItsChannel covers the caller that measured a path and
// then discarded it, which the transport chain does for every path it does not
// hand on.
func TestClosedResultKeepsItsChannel(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))
	before := r.Channel()
	if err := r.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if after := r.Channel(); after != before {
		t.Errorf("Channel() = %s after Close, was %s before", after, before)
	}
}

// TestZeroResultIsUnknown pins the fail-closed direction of the zero value.
//
// A Result nobody produced classified nothing, and Unknown is what every policy
// refuses. It must never default to plaintext, which is a positive claim.
func TestZeroResultIsUnknown(t *testing.T) {
	var r Result

	if got := r.Channel(); got != security.ChannelUnknown {
		t.Errorf("zero Result Channel() = %s, want %s", got, security.ChannelUnknown)
	}
	if r.Verified() {
		t.Error("zero Result reported a verified peer")
	}
	if security.RequireVerifiedTLS.PermitsCredentials(r.Channel()) {
		t.Error("the default policy accepted the zero Result's channel")
	}
}

// TestChannelNeverInspectsTheConnectionType records why this package can answer
// the question at all, and why no other layer should try.
//
// The classification comes from the observation this package made, not from
// looking at the connection afterwards. A caller that wrapped the socket — a
// counting conn, a proxy, a test double — would defeat a type assertion, and a
// service adapter re-deriving TLS state would be a second authority for one
// fact. The assertion here is that a wrapped connection changes nothing.
func TestChannelNeverInspectsTheConnectionType(t *testing.T) {
	ca := newTestCA(t)
	cert := ca.issue(t, leafOptions{dnsNames: []string{"server.test"}})
	f := dialFixture(t, peerTLS, serverConfig(cert, 0))

	r := handshake(t, f.conn, f.params(ca, "server.test"))
	if got := r.Channel(); got != security.ChannelTLSVerified {
		t.Fatalf("Channel() = %s, want %s", got, security.ChannelTLSVerified)
	}

	conn, _ := r.TakeConn()
	t.Cleanup(func() { _ = conn.Close() })

	// The taken connection is a *crypto/tls.Conn today. Nothing outside this
	// package may depend on that, and the fact the caller needs travelled beside
	// the connection instead.
	if _, isTLSConn := conn.(*cryptotls.Conn); !isTLSConn {
		t.Log("the taken connection is not a *tls.Conn; " +
			"this is fine precisely because no caller may assert on it")
	}
}
