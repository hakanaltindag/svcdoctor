package kafka

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/adapter/kafka/wire"
	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// The mechanisms a broker can agree to that svcdoctor cannot perform.
//
// The last entry is deliberately not a real mechanism: an unrecognized name must
// be unsupported by the same rule as a recognized-but-unimplemented one, not by
// a separate branch that could be forgotten.
var unsupportedMechanisms = []string{
	"SCRAM-SHA-256",
	"SCRAM-SHA-512",
	"OAUTHBEARER",
	"GSSAPI",
	"AWS_MSK_IAM",
	"PLAIN-NOT-REALLY",
}

// TestUnsupportedMechanismSendsNoCredentialBytes is the security property of
// this phase, and it is asserted against the bytes a real broker received.
//
// Before the guard, a session that negotiated SCRAM-SHA-256 was handed to
// wire.ExchangePLAIN, which framed the identity and the password as RFC 4616's
// three NUL-separated fields and wrote them to the socket. The peer had agreed
// to a different mechanism and would never have parsed them as PLAIN — the
// secret went on the wire regardless.
//
// The assertion is on the payload rather than on a call count because the
// payload is what leaks.
func TestUnsupportedMechanismSendsNoCredentialBytes(t *testing.T) {
	for _, mechanism := range unsupportedMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			withNegotiatedMechanism(t, mechanism)
			target := verifiedTarget(t)
			before := target.broker.appBytesRead()

			result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

			if payloads := target.broker.authPayloadsSeen(); len(payloads) != 0 {
				t.Fatalf("broker received %d SaslAuthenticate payloads, want 0: "+
					"credential material reached the wire for mechanism %q",
					len(payloads), mechanism)
			}

			// The strongest available statement, and stronger than the payload
			// check above: **no byte of any kind** reached the peer's protocol
			// layer after the handshake. A payload assertion alone would miss
			// bytes written outside Kafka framing, which the peer cannot decode
			// and would therefore never record as a payload — and raw bytes are
			// exactly what a careless write of a revealed secret would be.
			target.broker.awaitIdle()
			if after := target.broker.appBytesRead(); after != before {
				t.Errorf("%d protocol bytes reached the peer for mechanism %q, want 0",
					after-before, mechanism)
			}
			assertNoSecretAnywhere(t, target)

			evidence := evidenceOf(t, target, result)
			if got := evidence.State(); got != domain.StateUnknown {
				t.Errorf("state = %s, want UNKNOWN: svcdoctor's gap is not the peer's failure", got)
			}
			if got := evidence.FailureClass(); got != domain.FailureAuthMechanismUnsupported {
				t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED", got)
			}
		})
	}
}

// TestUnsupportedMechanismNeverCallsSecretFor proves the ordering requirement
// behaviourally, without weakening any type.
//
// security.Credential is a struct, so no double can be injected. The endpoint
// binding supplies the seam instead: a credential bound to a *different*
// endpoint makes SecretFor return ErrEndpointMismatch, which Authenticate turns
// into an error. So if the mechanism guard ran after SecretFor, this call would
// fail; because it runs before, the mismatched credential is never consulted and
// the run records evidence instead.
//
// That is a stronger statement than a call counter: it shows the credential was
// not merely unused but unreachable.
func TestUnsupportedMechanismNeverCallsSecretFor(t *testing.T) {
	withNegotiatedMechanism(t, "SCRAM-SHA-256")
	target := verifiedTarget(t)

	// Bound to an endpoint this session is not. SecretFor would reject it.
	mismatched := credentialFor(t, "somewhere-else.internal", 9092)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t), mismatched, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate returned %v; the mechanism guard must precede SecretFor, "+
			"so a mismatched credential must never be consulted", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	evidence := evidenceOf(t, target, result)
	if got := evidence.FailureClass(); got != domain.FailureAuthMechanismUnsupported {
		t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED", got)
	}
	assertNoSecretAnywhere(t, target)
}

// TestUnsupportedMechanismWinsOverAZeroCredential pins which outcome is reported
// when both conditions hold.
//
// A run with no credential at all is a caller error for this adapter today
// (ErrUnboundCredential), but reporting it here would say "you forgot a
// credential" about an exchange that could never have used one. The mechanism
// gap is the true and more actionable answer, so the guard precedes the
// credential check.
func TestUnsupportedMechanismWinsOverAZeroCredential(t *testing.T) {
	withNegotiatedMechanism(t, "SCRAM-SHA-512")
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate returned %v; the mechanism gap must be reported, "+
			"not a missing credential for an impossible exchange", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if got := evidenceOf(t, target, result).FailureClass(); got != domain.FailureAuthMechanismUnsupported {
		t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED", got)
	}
}

// TestUnsupportedMechanismWinsOverAnUnverifiedChannel pins the other collision.
//
// Both conditions refuse to send a credential, and they read differently: the
// policy refusal says *establish verified TLS and this will work*, which is
// false when svcdoctor cannot perform the mechanism at all. Reporting the
// channel would send an operator to fix TLS and change nothing.
//
// This mirrors internal/adapter/postgres, where admissibleMechanism is checked
// before the transport policy for the same reason (docs/ARCHITECTURE.md §5.7).
func TestUnsupportedMechanismWinsOverAnUnverifiedChannel(t *testing.T) {
	withNegotiatedMechanism(t, "SCRAM-SHA-256")
	target := unverifiedTarget(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := evidenceOf(t, target, result)
	if got := evidence.State(); got != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureAuthMechanismUnsupported {
		t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED; "+
			"an unsupported mechanism must not be reported as a channel-policy refusal", got)
	}
	assertNoSecretAnywhere(t, target)
}

// TestUnsupportedMechanismEvidenceShape pins every field of the node, because a
// node that exists but misdescribes itself is worse than none.
func TestUnsupportedMechanismEvidenceShape(t *testing.T) {
	withNegotiatedMechanism(t, "SCRAM-SHA-256")
	target := verifiedTarget(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
	evidence := evidenceOf(t, target, result)

	if got := evidence.Step(); got != StepSASLAuthenticate {
		t.Errorf("step = %s, want %s", got, StepSASLAuthenticate)
	}
	if got := evidence.Layer(); got != domain.LayerAuth {
		t.Errorf("layer = %s, want auth", got)
	}
	if got := evidence.Duration(); got != 0 {
		t.Errorf("duration = %s, want 0: nothing was attempted", got)
	}

	graph := freeze(t, target.builder)
	parents := graph.Parents(evidence.ID())
	if len(parents) != 1 {
		t.Fatalf("parents = %d, want 1", len(parents))
	}
	parent, ok := graph.Node(parents[0])
	if !ok {
		t.Fatal("parent is not in the graph")
	}
	if got := parent.Step(); got != StepSASLHandshake {
		t.Errorf("parent step = %s, want %s", got, StepSASLHandshake)
	}

	// No blocker: nothing in the graph obstructed this step. The limitation is
	// svcdoctor's, and the handshake above passed.
	if blockers := graph.BlockedBy(evidence.ID()); len(blockers) != 0 {
		t.Errorf("blocked-by edges = %d, want 0: no evidence blocked this step", len(blockers))
	}

	// The mechanism, and nothing that would assert a request was made.
	mechanism, ok := evidence.Attribute(AttrSASLMechanism)
	if !ok {
		t.Fatal("the mechanism attribute is missing; a reader cannot tell which one was declined")
	}
	if got := mechanism.String(); !strings.Contains(got, "SCRAM-SHA-256") {
		t.Errorf("mechanism attribute = %q, want SCRAM-SHA-256", got)
	}
	for _, forbidden := range []domain.AttributeKey{
		AttrSASLSessionLifetimeMs, AttrErrorCode, AttrRequestAPIVersion,
	} {
		if _, present := evidence.Attribute(forbidden); present {
			t.Errorf("attribute %s is present; it would assert a request was made and answered",
				forbidden)
		}
	}
}

// TestOnlyPLAINIsSupported pins the supported set to exactly one mechanism.
//
// It is the guard against the quiet failure: a later phase adding a mechanism
// name to supportedMechanism without adding the exchange that performs it would
// re-create the defect this phase closed. Widening the set must fail here first.
func TestOnlyPLAINIsSupported(t *testing.T) {
	if !supportedMechanism(wire.MechanismPLAIN) {
		t.Error("PLAIN must remain supported")
	}
	for _, mechanism := range unsupportedMechanisms {
		if supportedMechanism(mechanism) {
			t.Errorf("supportedMechanism(%q) = true; Phase 6.1a performs PLAIN and nothing else. "+
				"Adding a mechanism here without its wire exchange re-creates the defect this "+
				"test exists to prevent", mechanism)
		}
	}
	// Case and whitespace are not folded: an unrecognized spelling is
	// unsupported, never approximated to the framing of another mechanism.
	for _, near := range []string{"plain", "Plain", " PLAIN", "PLAIN ", ""} {
		if supportedMechanism(near) {
			t.Errorf("supportedMechanism(%q) = true; the comparison must be exact", near)
		}
	}
}

// TestPLAINRemainsUnchanged is the regression half: the guard must not alter the
// mechanism it permits.
func TestPLAINRemainsUnchanged(t *testing.T) {
	target := verifiedTarget(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := evidenceOf(t, target, result)
	if got := evidence.State(); got != domain.StatePass {
		t.Fatalf("state = %s, want PASS: PLAIN must still authenticate", got)
	}
	payloads := target.broker.authPayloadsSeen()
	if len(payloads) != 1 {
		t.Fatalf("broker received %d SaslAuthenticate payloads, want 1", len(payloads))
	}
	// RFC 4616: authzid NUL authcid NUL passwd, with an empty authzid.
	if fields := bytes.Split(payloads[0], []byte{0}); len(fields) != 3 {
		t.Errorf("PLAIN payload has %d NUL-separated fields, want 3", len(fields))
	}
}

// --- helpers -----------------------------------------------------------------

// evidenceOf returns the node the result recorded, failing if there is not
// exactly one authentication node.
func evidenceOf(t *testing.T, target *authTarget, result *AuthResult) domain.Evidence {
	t.Helper()

	id := result.Evidence()
	if id == "" {
		t.Fatal("the result recorded no evidence; an absent node is indistinguishable " +
			"from a step nobody requested")
	}
	found, ok := freeze(t, target.builder).Node(id)
	if !ok {
		t.Fatalf("evidence %s is not in the graph", id)
	}
	return found
}

// assertNoSecretAnywhere fails if the fixture secret or identity reached the
// wire or the graph.
func assertNoSecretAnywhere(t *testing.T, target *authTarget) {
	t.Helper()

	for _, payload := range target.broker.authPayloadsSeen() {
		if bytes.Contains(payload, []byte(authSecret)) {
			t.Error("the secret appears in a SaslAuthenticate payload")
		}
		if bytes.Contains(payload, []byte(authIdentity)) {
			t.Error("the identity appears in a SaslAuthenticate payload")
		}
	}
	for _, node := range freeze(t, target.builder).Nodes() {
		for key, value := range node.Attributes() {
			rendered := value.String()
			if strings.Contains(rendered, authSecret) {
				t.Errorf("the secret appears in attribute %s of %s", key, node.ID())
			}
		}
	}
}

// TestUnsupportedMechanismWritesNoBytesAtAll closes the gap broker.appBytes
// cannot reach.
//
// appBytes counts request bytes the peer *consumed*, so bytes written outside
// Kafka framing never reach it: the broker cannot decode them into a request, so
// it records nothing, and a payload assertion passes while the bytes are on the
// wire. A careless write of credential material has exactly that shape.
//
// This measures svcdoctor's own socket instead, which is exact on a plaintext
// path because nothing writes a TLS close_notify alert through it. The baseline
// is taken after the handshake, so only what Authenticate wrote is counted.
func TestUnsupportedMechanismWritesNoBytesAtAll(t *testing.T) {
	withNegotiatedMechanism(t, "SCRAM-SHA-256")
	target := plaintextTarget(t)

	conn := target.conn(t)
	before := conn.bytesWritten()
	if before == 0 {
		t.Fatal("the handshake wrote nothing; the baseline would prove nothing")
	}

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	if after := conn.bytesWritten(); after != before {
		t.Errorf("Authenticate wrote %d bytes for an unsupported mechanism, want 0",
			after-before)
	}
	if got := evidenceOf(t, target, result).FailureClass(); got != domain.FailureAuthMechanismUnsupported {
		t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED", got)
	}
}
