package kafka

import (
	"context"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// TestZeroCredentialRecordsMissingInput is the defect this phase closes.
//
// Before it, a broker that agreed to PLAIN while the run held no credential
// produced an ErrUnboundCredential invocation error and **no authentication
// node at all**. The graph was then indistinguishable from one where the step
// never came up, so a report could reach the authentication layer, learn that
// the operator had configured nothing, and say nothing about it.
//
// The outcome is a diagnostic fact about the run, so it is evidence.
func TestZeroCredentialRecordsMissingInput(t *testing.T) {
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate returned %v; a run with no credential configured is a "+
			"diagnostic outcome and must be recorded, not returned as a caller error", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	evidence := evidenceOf(t, target, result)
	if got := evidence.State(); got != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED: the exchange was intentionally not executed", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureExecRequiredInputMissing {
		t.Errorf("failure class = %s, want EXEC_REQUIRED_INPUT_MISSING", got)
	}
}

// TestMissingInputSendsNoBytes proves the security property against a real
// socket rather than against a call count.
//
// The authoritative assertion is the **client-side raw write counter**, taken
// as a delta across the call. A broker-side counter reports only the bytes the
// peer decoded into a request, so bytes written outside Kafka framing — which
// the peer can never decode, and which is exactly the shape of a careless write
// of credential material — would never reach it. Counting at the socket cannot
// miss them.
//
// The payload and broker-side checks stay beside it because they say something
// different and narrower: that no SaslAuthenticate was parsed at all.
// The target is deliberately plaintext. countingConn wraps the TCP socket, so
// on a TLS path the delta also captures the close_notify record that closing
// the connection legitimately writes — which would force this assertion to
// tolerate a nonzero byte count and blunt the very thing it exists to prove.
// Over plaintext the honest expectation is exactly zero.
//
// It costs nothing in coverage: the missing-input check precedes the channel
// policy, so a plaintext path reaches it identically. That it does is pinned
// separately by TestMissingInputWinsOverUnverifiedChannel.
func TestMissingInputSendsNoBytes(t *testing.T) {
	target := plaintextTarget(t)
	conn := target.conn(t)
	writtenBefore, readBefore := conn.bytesWritten(), target.broker.appBytesRead()

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if after := conn.bytesWritten(); after != writtenBefore {
		t.Errorf("%d bytes were written to the socket, want 0: nothing may leave this "+
			"path, framed or not", after-writtenBefore)
	}
	if payloads := target.broker.authPayloadsSeen(); len(payloads) != 0 {
		t.Errorf("broker received %d SaslAuthenticate payloads, want 0", len(payloads))
	}
	target.broker.awaitIdle()
	if after := target.broker.appBytesRead(); after != readBefore {
		t.Errorf("%d protocol bytes reached the peer, want 0", after-readBefore)
	}
	assertNoSecretAnywhere(t, target)
}

// TestMissingInputNeverReachesSecretFor proves the ordering behaviourally.
//
// security.Credential is a struct, so no double can be injected. The zero
// credential supplies the seam instead: Credential.SecretFor on a zero value
// returns ErrUnboundCredential, which Authenticate turns into an error. So if
// the missing-input check ran after SecretFor — or after the endpoint binding
// that precedes it — this call would fail. It returns evidence, so neither was
// reached.
//
// That is stronger than a call counter: the credential was not merely unused,
// it was unreachable. And because SecretFor is the only door to a Secret, and
// security.Reveal is only ever called with one, nothing on this path can reveal.
func TestMissingInputNeverReachesSecretFor(t *testing.T) {
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate returned %v; the missing-input check must precede both "+
			"the endpoint binding and SecretFor, so neither may be consulted", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	if got := evidenceOf(t, target, result).FailureClass(); got != domain.FailureExecRequiredInputMissing {
		t.Errorf("failure class = %s, want EXEC_REQUIRED_INPUT_MISSING", got)
	}
}

// TestMissingInputEvidenceShape pins every field of the node, because a node
// that exists but misdescribes itself is worse than none.
func TestMissingInputEvidenceShape(t *testing.T) {
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	evidence := evidenceOf(t, target, result)
	if got := evidence.Step(); got != StepSASLAuthenticate {
		t.Errorf("step = %s, want %s", got, StepSASLAuthenticate)
	}
	if got := evidence.Layer(); got != domain.LayerAuth {
		t.Errorf("layer = %s, want auth", got)
	}
	// Not "zero": a zero-length measurement is something a real exchange can
	// produce. Nothing ran here, so nothing was timed at all.
	if evidence.Elapsed().IsMeasured() {
		t.Error("nothing was attempted, yet the node carries a measurement")
	}
	if got := evidence.Subject().Ref(); got != "10.0.0.1:9092" {
		t.Errorf("subject = %q, want the concrete peer the session ran against", got)
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

	// No blocker: nothing in the graph obstructed this step. The missing input
	// is the run's own, and the handshake above passed.
	if blockers := graph.BlockedBy(evidence.ID()); len(blockers) != 0 {
		t.Errorf("blocked-by edges = %d, want 0: no evidence blocked this step", len(blockers))
	}

	mechanism, ok := evidence.Attribute(AttrSASLMechanism)
	if !ok {
		t.Fatal("the mechanism attribute is missing; a reader cannot tell which " +
			"authentication went unattempted")
	}
	if got := mechanism.String(); !strings.Contains(got, "PLAIN") {
		t.Errorf("mechanism attribute = %q, want PLAIN", got)
	}

	// Nothing that would assert a request was made and answered.
	for _, forbidden := range []domain.AttributeKey{
		AttrSASLSessionLifetimeMs, AttrErrorCode, AttrRequestAPIVersion,
	} {
		if _, present := evidence.Attribute(forbidden); present {
			t.Errorf("attribute %s is present; it would assert a request was made", forbidden)
		}
	}
}

// TestMissingInputRecordsNothingCredentialDerived guards the attribute set
// against a plausible future addition.
//
// "empty password", a length, or a configured-identity echo would each describe
// a secret that was never supplied, and a length is a genuine disclosure. The
// node names the mechanism and nothing else.
func TestMissingInputRecordsNothingCredentialDerived(t *testing.T) {
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	attributes := evidenceOf(t, target, result).Attributes()
	if len(attributes) != 1 {
		t.Errorf("attributes = %d, want exactly 1 (the mechanism): %v", len(attributes), attributes)
	}
	for key, value := range attributes {
		name, rendered := strings.ToLower(string(key)), strings.ToLower(value.String())
		for _, banned := range []string{"password", "secret", "credential", "identity", "user"} {
			if strings.Contains(name, banned) {
				t.Errorf("attribute %s names credential material", key)
			}
			if strings.Contains(rendered, banned) {
				t.Errorf("attribute %s renders %q, which describes credential material", key, rendered)
			}
		}
	}
}

// TestUnsupportedMechanismWinsOverMissingInput pins the precedence for every
// mechanism svcdoctor cannot perform, not just the one sampled elsewhere.
//
// Both conditions hold at once, and the mechanism gap is the true and more
// actionable answer: supplying a credential would change nothing, because
// svcdoctor still could not frame the exchange. Reporting a missing credential
// would send an operator to configure one for an exchange that can never run.
//
// The order is security-significant, which is why it is pinned across the whole
// set rather than sampled.
func TestUnsupportedMechanismWinsOverMissingInput(t *testing.T) {
	for _, mechanism := range unsupportedMechanisms {
		t.Run(mechanism, func(t *testing.T) {
			withNegotiatedMechanism(t, mechanism)
			target := verifiedTarget(t)

			result, err := Authenticate(
				context.Background(), target.builder, target.session(t),
				security.Credential{}, AuthParams{})
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			t.Cleanup(func() { _ = result.Close() })

			evidence := evidenceOf(t, target, result)
			if got := evidence.State(); got != domain.StateUnknown {
				t.Errorf("state = %s, want UNKNOWN", got)
			}
			if got := evidence.FailureClass(); got != domain.FailureAuthMechanismUnsupported {
				t.Errorf("failure class = %s, want AUTH_MECHANISM_UNSUPPORTED; a mechanism "+
					"svcdoctor cannot perform must not be reported as a missing credential",
					got)
			}
		})
	}
}

// TestMissingInputWinsOverUnverifiedChannel pins the other collision.
//
// A policy refusal means *a credential existed and svcdoctor declined to send
// it here*. It reads as "establish verified TLS and this will work", which is
// false when the run holds nothing: over a perfect channel it would still have
// nothing to present. With no credential, the policy has no question to answer.
//
// This mirrors internal/adapter/postgres, where the missing-input check
// likewise precedes the transport policy (ADR 0046).
func TestMissingInputWinsOverUnverifiedChannel(t *testing.T) {
	target := unverifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	evidence := evidenceOf(t, target, result)
	if got := evidence.State(); got != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureExecRequiredInputMissing {
		t.Errorf("failure class = %s, want EXEC_REQUIRED_INPUT_MISSING; with nothing to "+
			"present there is no credential for a policy to refuse", got)
	}
	assertNoSecretAnywhere(t, target)
}

// TestPolicyRefusalSurvivesAConfiguredCredential is the other half of the
// distinction above, and it must not regress.
//
// A credential that exists and is withheld from an unverified channel is a
// security decision svcdoctor made. Collapsing it into the missing-input class
// would erase that decision from the report.
func TestPolicyRefusalSurvivesAConfiguredCredential(t *testing.T) {
	target := unverifiedTarget(t)

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := evidenceOf(t, target, result)
	if got := evidence.State(); got != domain.StateSkipped {
		t.Errorf("state = %s, want SKIPPED", got)
	}
	if got := evidence.FailureClass(); got != domain.FailureExecSkippedByPolicy {
		t.Errorf("failure class = %s, want EXEC_SKIPPED_BY_POLICY; a credential that "+
			"existed and was withheld is not a credential that was never configured", got)
	}
	assertNoSecretAnywhere(t, target)
}

// TestFourAuthenticationOutcomesStayDistinct pins the whole vocabulary in one
// place, because the risk is not any single mapping but a future change that
// collapses two of them into an umbrella class.
//
// Each row is a different question an operator asks, and each leads somewhere
// different:
//
//	unsupported mechanism  -> svcdoctor cannot do this; the tool has the gap
//	missing input          -> configure a credential for this run
//	policy withheld        -> a credential exists; fix the channel and retry
//	credentials rejected   -> the broker evaluated it and said no
func TestFourAuthenticationOutcomesStayDistinct(t *testing.T) {
	tests := []struct {
		name    string
		run     func(t *testing.T) (*authTarget, *AuthResult)
		state   domain.State
		failure domain.FailureClass
	}{
		{
			name: "unsupported mechanism",
			run: func(t *testing.T) (*authTarget, *AuthResult) {
				withNegotiatedMechanism(t, "SCRAM-SHA-512")
				target := verifiedTarget(t)
				return target, authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
			},
			state:   domain.StateUnknown,
			failure: domain.FailureAuthMechanismUnsupported,
		},
		{
			name: "required input missing",
			run: func(t *testing.T) (*authTarget, *AuthResult) {
				target := verifiedTarget(t)
				return target, authenticate(t, target, security.Credential{}, AuthParams{})
			},
			state:   domain.StateSkipped,
			failure: domain.FailureExecRequiredInputMissing,
		},
		{
			name: "withheld by policy",
			run: func(t *testing.T) (*authTarget, *AuthResult) {
				target := unverifiedTarget(t)
				return target, authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
			},
			state:   domain.StateSkipped,
			failure: domain.FailureExecSkippedByPolicy,
		},
		{
			name: "credentials rejected",
			run: func(t *testing.T) (*authTarget, *AuthResult) {
				target := verifiedTarget(t, withAuthError(errorCodeSASLAuthenticationFailed))
				return target, authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
			},
			state:   domain.StateFail,
			failure: domain.FailureAuthCredentialsRejected,
		},
	}

	seen := make(map[domain.FailureClass]string, len(tests))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, result := test.run(t)

			evidence := evidenceOf(t, target, result)
			if got := evidence.State(); got != test.state {
				t.Errorf("state = %s, want %s", got, test.state)
			}
			if got := evidence.FailureClass(); got != test.failure {
				t.Errorf("failure class = %s, want %s", got, test.failure)
			}
		})
		if previous, clash := seen[test.failure]; clash {
			t.Errorf("%q and %q share failure class %s; the four outcomes must stay distinct",
				previous, test.name, test.failure)
		}
		seen[test.failure] = test.name
	}
}

// TestMissingInputIsDeterministic pins that repeated runs produce the same node.
//
// The evidence identifier is derived from the step, the logical endpoint and the
// resolved address, so two runs against the same fixture must agree on all of
// it. A node whose identity varied would break every downstream reference.
func TestMissingInputIsDeterministic(t *testing.T) {
	var first domain.Evidence
	for range 3 {
		target := verifiedTarget(t)
		result, err := Authenticate(
			context.Background(), target.builder, target.session(t),
			security.Credential{}, AuthParams{})
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		t.Cleanup(func() { _ = result.Close() })

		evidence := evidenceOf(t, target, result)
		if first.ID() == "" {
			first = evidence
			continue
		}
		if evidence.ID() != first.ID() {
			t.Errorf("evidence ID = %s, want %s", evidence.ID(), first.ID())
		}
		if evidence.State() != first.State() || evidence.FailureClass() != first.FailureClass() {
			t.Errorf("outcome drifted between identical runs")
		}
	}
}

// TestMissingInputConsumesTheSession keeps the ownership contract the other
// non-passing paths already hold.
//
// Authenticate is a consuming boundary: it takes the connection before it
// validates anything, so every outcome that does not authenticate must close
// it. A path that returned normally while leaking a socket would be a slow leak
// no test elsewhere would catch.
func TestMissingInputConsumesTheSession(t *testing.T) {
	target := verifiedTarget(t)

	result, err := Authenticate(
		context.Background(), target.builder, target.session(t),
		security.Credential{}, AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	_ = result.Close()

	conn := target.conn(t)
	if got := conn.closeCount(); got == 0 {
		t.Error("the connection was never closed; a non-authenticating outcome must not " +
			"leak the socket it consumed")
	}
	if got := conn.closeCount(); got > 1 {
		t.Errorf("close count = %d, want 1: the socket was closed more than once", got)
	}
}
