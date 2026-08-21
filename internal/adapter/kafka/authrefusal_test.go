package kafka

import (
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/tls"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests are the point of the phase. svcdoctor sends a password only over a
// channel whose peer identity was verified, and a refusal is recorded as a fact
// rather than as silence or as a failure. See ADR 0028 section 3 and ADR 0030.

const tlsNodeID = "tls.handshake/primary.internal:9092/10.0.0.1"

// refusalCase is one channel the policy must refuse.
type refusalCase struct {
	name    string
	target  func(t *testing.T) *authTarget
	blocker string // the node the refusal must point at, empty when none exists
}

func refusalCases() []refusalCase {
	return []refusalCase{
		{
			// The password would be readable by anything on the path.
			name:   "plaintext",
			target: func(t *testing.T) *authTarget { return plaintextTarget(t) },
			// No node states that TLS is absent, so there is nothing to point at.
			blocker: "",
		},
		{
			// Encrypted to whoever answered. Encryption without identity is
			// exactly the case where a credential goes to an unknown peer.
			name:    "tls with verification disabled",
			target:  func(t *testing.T) *authTarget { return unverifiedTarget(t) },
			blocker: tlsNodeID,
		},
	}
}

// TestPolicyRefusesEveryChannelBelowVerifiedTLS is the whole matrix in one
// place: what is recorded, what is returned, and what reached the peer.
func TestPolicyRefusesEveryChannelBelowVerifiedTLS(t *testing.T) {
	for _, test := range refusalCases() {
		t.Run(test.name, func(t *testing.T) {
			target := test.target(t)
			before := target.broker.appBytesRead()

			result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

			// 1. Nothing was sent. Not "authentication failed" — nothing was
			//    written to the socket at all after the handshake.
			target.broker.awaitIdle()
			if got := target.broker.authRequestCount(); got != 0 {
				t.Errorf("broker received %d authentications, want 0", got)
			}
			if after := target.broker.appBytesRead(); after != before {
				t.Errorf("%d protocol bytes reached the peer, want 0", after-before)
			}

			// 2. The refusal is visible, not silent.
			evidence := node(t, freeze(t, target.builder), authNodeID)
			if evidence.State() != domain.StateSkipped {
				t.Errorf("state = %s, want SKIPPED: a policy applied, nothing failed",
					evidence.State())
			}
			if evidence.FailureClass() != domain.FailureExecSkippedByPolicy {
				t.Errorf("class = %s, want EXEC_SKIPPED_BY_POLICY", evidence.FailureClass())
			}
			if got, want := evidence.Layer(), domain.LayerAuth; got != want {
				t.Errorf("layer = %s, want %s", got, want)
			}
			if got, want := evidence.Subject().Ref(), authAddress+":9092"; got != want {
				t.Errorf("subject = %q, want the address, which is known %q", got, want)
			}

			// 3. No authenticated continuation is handed back.
			if result.Authenticated() {
				t.Error("a refused attempt reports itself as authenticated")
			}
			if _, ok := result.Session(); ok {
				t.Error("a refused attempt returned a session")
			}
			if got := result.Evidence(); got != evidence.ID() {
				t.Errorf("result names %s, want the refusal node %s", got, evidence.ID())
			}
		})
	}
}

// TestRefusalPointsAtTheFactThatCausedIt covers the blocked-by half.
//
// On an unverified TLS path the blocker is the node carrying tls.verified=false,
// which is the fact that made the channel insufficient. On a plaintext path
// there is deliberately no blocker, because no node anywhere states that TLS is
// absent and inventing one would be a synthetic fact.
func TestRefusalPointsAtTheFactThatCausedIt(t *testing.T) {
	for _, test := range refusalCases() {
		t.Run(test.name, func(t *testing.T) {
			target := test.target(t)
			authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

			graph := freeze(t, target.builder)
			blockers := graph.BlockedBy(domain.EvidenceID(authNodeID))

			if test.blocker == "" {
				if len(blockers) != 0 {
					t.Fatalf("blocked-by = %v, want none: nothing in this graph proves TLS is absent",
						blockers)
				}
				// The TCP node passed and says nothing about encryption, so it
				// must not have been pressed into service as a stand-in.
				for _, id := range blockers {
					if node(t, graph, id.String()).Layer() == domain.LayerTCP {
						t.Error("the refusal points at the TCP node, which proves nothing about TLS")
					}
				}
				return
			}

			if len(blockers) != 1 {
				t.Fatalf("blocked-by = %v, want exactly one", blockers)
			}
			if got := blockers[0].String(); got != test.blocker {
				t.Fatalf("blocker = %s, want the TLS node %s", got, test.blocker)
			}

			blocker := node(t, graph, test.blocker)
			if blocker.Step() != tls.StepHandshake {
				t.Errorf("blocker step = %s, want %s", blocker.Step(), tls.StepHandshake)
			}
			verified, ok := blocker.Attribute(tls.AttrVerified)
			if !ok {
				t.Fatal("the blocker records no tls.verified, so it does not prove the refusal")
			}
			if value, _ := verified.Bool(); value {
				t.Error("the refusal points at a node whose handshake did verify the peer")
			}
		})
	}
}

// TestRefusalRecordsOnlyWhatIsTrueWhenNothingWasSent: an attribute that implies
// a request was made and answered would be a fact about an exchange that did not
// happen.
func TestRefusalRecordsOnlyWhatIsTrueWhenNothingWasSent(t *testing.T) {
	target := plaintextTarget(t, withSessionLifetime(1000))
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := node(t, freeze(t, target.builder), authNodeID)

	if got, _ := attribute(t, evidence, AttrSASLMechanism).Str(); got != "PLAIN" {
		t.Errorf("mechanism = %q, want PLAIN: the reader needs to know what was skipped", got)
	}
	for _, key := range []domain.AttributeKey{
		AttrErrorCode, AttrRequestAPIVersion, AttrSASLSessionLifetimeMs,
	} {
		if _, ok := evidence.Attribute(key); ok {
			t.Errorf("a refusal records %s, which asserts a request was made and answered", key)
		}
	}
	if got := evidence.Duration(); got != 0 {
		t.Errorf("duration = %s, want 0: nothing ran", got)
	}
}

// TestRefusalClosesTheConnection pins the ownership decision.
//
// A consuming API was chosen over handing the session back, and the reason is
// the protocol rather than convenience: after a SaslHandshake the broker accepts
// only that mechanism's SaslAuthenticate, so a session whose authentication is
// refused has no other legal operation on that socket. There is no reusable
// connection being discarded. See ADR 0030.
func TestRefusalClosesTheConnection(t *testing.T) {
	target := plaintextTarget(t)
	conn := target.conn(t)
	session := target.session(t)

	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	if got := conn.closeCount(); got == 0 {
		t.Error("the connection was left open after a policy refusal")
	}
	if session.Available() {
		t.Error("the session still offers its connection after being consumed")
	}
	if _, ok := session.TakeConn(); ok {
		t.Error("a consumed session handed its connection to a second caller")
	}
}

// TestUnclassifiedChannelRefuses covers the zero value and the undefined value.
//
// Both directions of "I do not know" must deny: a connection nobody classified,
// and a channel integer no constant names. The session is built here by hand
// because the transport chain cannot produce either — which is the point, since
// this is the failure mode a future carrier could introduce.
func TestUnclassifiedChannelRefuses(t *testing.T) {
	tests := []struct {
		name    string
		channel security.Channel
	}{
		{name: "zero value", channel: security.ChannelUnknown},
		{name: "undefined value", channel: security.Channel(99)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := verifiedTarget(t)
			real := target.session(t)
			before := target.broker.appBytesRead()

			conn, ok := real.TakeConn()
			if !ok {
				t.Fatal("no connection to take")
			}

			// A live, verified socket carried by a session whose channel says
			// nothing. The policy must look at the claim, not the socket.
			unclassified := &HandshakeSession{
				ownedConn:  ownedConn{conn: conn},
				endpoint:   real.Endpoint(),
				address:    real.Address(),
				mechanism:  real.Mechanism(),
				evidenceID: real.Evidence(),
				channel:    test.channel,
			}

			result, err := Authenticate(t.Context(), target.builder, unclassified,
				credentialFor(t, authHost, 9092), AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			t.Cleanup(func() { _ = result.Close() })

			if result.Authenticated() {
				t.Fatal("an unclassified channel was permitted to carry a credential")
			}

			target.broker.awaitIdle()
			if got := target.broker.authRequestCount(); got != 0 {
				t.Errorf("broker received %d authentications, want 0", got)
			}
			if after := target.broker.appBytesRead(); after != before {
				t.Errorf("%d protocol bytes reached the peer, want 0", after-before)
			}

			evidence := node(t, freeze(t, target.builder), authNodeID)
			if evidence.State() != domain.StateSkipped {
				t.Errorf("state = %s, want SKIPPED", evidence.State())
			}
			if evidence.FailureClass() != domain.FailureExecSkippedByPolicy {
				t.Errorf("class = %s, want EXEC_SKIPPED_BY_POLICY", evidence.FailureClass())
			}
		})
	}
}

// TestUndefinedPolicyRefusesEverything is the other fail-closed direction: a
// policy value no constant names must permit nothing, including a verified
// channel.
func TestUndefinedPolicyRefusesEverything(t *testing.T) {
	target := verifiedTarget(t)
	before := target.broker.appBytesRead()

	result := authenticate(t, target, credentialFor(t, authHost, 9092),
		AuthParams{TransportPolicy: security.CredentialTransportPolicy(42)})

	if result.Authenticated() {
		t.Fatal("an undefined policy permitted a credential")
	}

	target.broker.awaitIdle()
	if after := target.broker.appBytesRead(); after != before {
		t.Errorf("%d protocol bytes reached the peer, want 0", after-before)
	}
}

// TestZeroValuePolicyRequiresVerifiedTLS states the property the API depends on:
// a caller that never sets the policy gets the safe one.
//
// Every other test in this file relies on it by passing AuthParams{}, so it is
// worth asserting directly rather than leaving it implied.
func TestZeroValuePolicyRequiresVerifiedTLS(t *testing.T) {
	var params AuthParams

	if params.TransportPolicy != security.RequireVerifiedTLS {
		t.Fatalf("zero policy = %s, want require-verified-tls", params.TransportPolicy)
	}
	for _, channel := range []security.Channel{
		security.ChannelUnknown, security.ChannelPlaintext, security.ChannelTLSUnverified,
	} {
		if params.TransportPolicy.PermitsCredentials(channel) {
			t.Errorf("the default policy permits %s", channel)
		}
	}
	if !params.TransportPolicy.PermitsCredentials(security.ChannelTLSVerified) {
		t.Error("the default policy refuses verified TLS, so nothing could ever authenticate")
	}
}
