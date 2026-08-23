package kafka

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// --- evidence contract ----------------------------------------------------

func TestAuthenticateEvidenceContract(t *testing.T) {
	target := verifiedTarget(t)

	before := time.Now()
	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
	evidence := node(t, freeze(t, target.builder), authNodeID)

	if evidence.State() != domain.StatePass {
		t.Fatalf("state = %s (%s), want PASS", evidence.State(), evidence.FailureClass())
	}
	if got, want := evidence.Layer(), domain.LayerAuth; got != want {
		t.Errorf("layer = %s, want %s: authentication is L5 work", got, want)
	}
	if got, want := evidence.Step(), StepSASLAuthenticate; got != want {
		t.Errorf("step = %s, want %s", got, want)
	}
	if got, want := evidence.Subject().Kind(), domain.SubjectKindEndpoint; got != want {
		t.Errorf("subject kind = %s, want %s", got, want)
	}
	if got, want := evidence.Subject().Ref(), authAddress+":9092"; got != want {
		t.Errorf("subject = %q, want the concrete peer %q", got, want)
	}
	if got := evidence.FailureClass(); got != domain.FailureNone {
		t.Errorf("failure class = %s, want NONE on a passing node", got)
	}
	if evidence.StartedAt().Before(before.Add(-time.Second)) {
		t.Errorf("startedAt = %s, want a time from this run", evidence.StartedAt())
	}
	if d, measured := evidence.Elapsed().Duration(); !measured || d < 0 {
		t.Errorf("elapsed = (%s, %t), want a non-negative measurement", d, measured)
	}
	if got := result.Evidence(); got != evidence.ID() {
		t.Errorf("result names %s, want the node it recorded %s", got, evidence.ID())
	}
}

// TestAuthenticateParentsToTheHandshake pins the edge to the step whose live
// connection this authentication continues.
//
// The ApiVersions node is the grandparent, not the parent. Parenting there
// instead would say the authentication followed capability discovery, skipping
// the mechanism negotiation that is its actual prerequisite and the only reason
// the socket accepts this message at all.
func TestAuthenticateParentsToTheHandshake(t *testing.T) {
	target := verifiedTarget(t)
	session := target.session(t)
	handshakeID := session.Evidence()

	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})
	graph := freeze(t, target.builder)

	parents := graph.Parents(domain.EvidenceID(authNodeID))
	if len(parents) != 1 {
		t.Fatalf("parents = %v, want exactly one", parents)
	}
	if parents[0] != handshakeID {
		t.Errorf("parent = %s, want the handshake node %s", parents[0], handshakeID)
	}

	parent := node(t, graph, parents[0].String())
	if parent.Step() != StepSASLHandshake {
		t.Errorf("parent step = %s, want %s", parent.Step(), StepSASLHandshake)
	}
}

// --- the wire format ------------------------------------------------------

// TestAuthenticateSendsTheRFC4616Payload checks the exact bytes, because PLAIN
// is a formatted string and a wrong separator count is the kind of defect that
// only shows up against a real broker.
func TestAuthenticateSendsTheRFC4616Payload(t *testing.T) {
	target := verifiedTarget(t)

	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	payloads := target.broker.authPayloadsSeen()
	if len(payloads) != 1 {
		t.Fatalf("broker received %d authentications, want 1", len(payloads))
	}

	// authzid NUL authcid NUL passwd, with an empty authorization identity.
	want := append([]byte{0}, authIdentity...)
	want = append(want, 0)
	want = append(want, authSecret...)

	if !bytes.Equal(payloads[0], want) {
		t.Errorf("payload = %q, want %q", payloads[0], want)
	}

	fields := bytes.Split(payloads[0], []byte{0})
	if len(fields) != 3 {
		t.Fatalf("payload has %d NUL-separated fields, want 3", len(fields))
	}
	if len(fields[0]) != 0 {
		t.Errorf("authzid = %q, want empty: svcdoctor has no authorization identity to send", fields[0])
	}
	if string(fields[1]) != authIdentity {
		t.Errorf("authcid = %q, want %q", fields[1], authIdentity)
	}
	if string(fields[2]) != authSecret {
		t.Errorf("passwd = %q, want the secret", fields[2])
	}
}

// TestAuthenticateSendsVersionOne pins the version choice, which is a decision
// rather than a default: v1 carries the session lifetime, and v2 is flexible and
// would be refused by the shared framing guard.
func TestAuthenticateSendsVersionOne(t *testing.T) {
	target := verifiedTarget(t)
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	versions := target.broker.authVersions()
	if len(versions) != 1 {
		t.Fatalf("broker received %d authentications, want 1", len(versions))
	}
	if versions[0] != 1 {
		t.Errorf("request version = %d, want 1", versions[0])
	}

	evidence := node(t, freeze(t, target.builder), authNodeID)
	recorded, _ := attribute(t, evidence, AttrRequestAPIVersion).Int()
	if recorded != int64(versions[0]) {
		t.Errorf("recorded version = %d, but %d was sent", recorded, versions[0])
	}
}

// TestOneSocketCarriesAllThreeRequests is the invariant of the whole vertical
// slice, now five layers deep: DNS, TCP, TLS, ApiVersions, SaslHandshake and
// SaslAuthenticate all describe one socket.
func TestOneSocketCarriesAllThreeRequests(t *testing.T) {
	target := verifiedTarget(t)
	measured := target.conn(t).LocalAddr().String()

	result := authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	session, ok := result.Session()
	if !ok {
		t.Fatal("authentication did not produce a session")
	}
	conn, ok := session.TakeConn()
	if !ok {
		t.Fatal("the authenticated session has no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if got := conn.LocalAddr().String(); got != measured {
		t.Errorf("authentication ran on %s, want the measured socket %s", got, measured)
	}
	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d connections were established, want 1: the adapter must not redial", got)
	}
	if got := target.broker.requestCount(); got != 1 {
		t.Errorf("broker saw %d ApiVersions requests, want 1", got)
	}
	if got := target.broker.saslRequestCount(); got != 1 {
		t.Errorf("broker saw %d handshakes, want 1", got)
	}
	if got := target.broker.authRequestCount(); got != 1 {
		t.Errorf("broker saw %d authentications, want 1", got)
	}
}

// --- attributes -----------------------------------------------------------

func TestAuthenticateAttributes(t *testing.T) {
	target := verifiedTarget(t, withSessionLifetime(3_600_000))
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := node(t, freeze(t, target.builder), authNodeID)

	if got, _ := attribute(t, evidence, AttrSASLMechanism).Str(); got != "PLAIN" {
		t.Errorf("mechanism = %q, want PLAIN", got)
	}
	if got, _ := attribute(t, evidence, AttrErrorCode).Int(); got != 0 {
		t.Errorf("error code = %d, want 0 recorded as a statement", got)
	}
	if got, _ := attribute(t, evidence, AttrSASLSessionLifetimeMs).Int(); got != 3_600_000 {
		t.Errorf("session lifetime = %d, want 3600000", got)
	}
}

// TestAuthenticateRecordsNoIdentityOrSecretShapedAttribute is the conservative
// half of the attribute contract: what the node must never carry.
//
// The authenticating identity is deliberately absent too. It is real deployment
// identity with no declared redaction kind, so recording it would put an
// unpseudonymizable principal into a report meant to be shareable.
func TestAuthenticateRecordsNoIdentityOrSecretShapedAttribute(t *testing.T) {
	target := verifiedTarget(t, withSessionLifetime(1000))
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := node(t, freeze(t, target.builder), authNodeID)

	allowed := map[domain.AttributeKey]bool{
		AttrSASLMechanism:         true,
		AttrRequestAPIVersion:     true,
		AttrErrorCode:             true,
		AttrSASLSessionLifetimeMs: true,
	}
	for key := range evidence.Attributes() {
		if !allowed[key] {
			t.Errorf("unexpected attribute %s: this node's vocabulary is closed on purpose", key)
		}
	}

	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, forbidden := range []string{authSecret, authIdentity, "password", "authzid", "auth_bytes"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Errorf("the authentication node carries %q:\n%s", forbidden, encoded)
		}
	}
}

// --- classification -------------------------------------------------------

// TestAuthenticateClassification is the failure matrix. Each case names what the
// peer did and what svcdoctor is allowed to conclude from it.
func TestAuthenticateClassification(t *testing.T) {
	tests := []struct {
		name    string
		options []brokerOption
		state   domain.State
		class   domain.FailureClass
	}{
		{
			name:    "credentials rejected",
			options: []brokerOption{withAuthError(58)},
			state:   domain.StateFail,
			class:   domain.FailureAuthCredentialsRejected,
		},
		{
			name:    "mechanism not offered",
			options: []brokerOption{withAuthError(33)},
			state:   domain.StateFail,
			class:   domain.FailureAuthMechanismNotOffered,
		},
		{
			name:    "unsupported version",
			options: []brokerOption{withAuthError(35)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolUnsupportedVersion,
		},
		{
			// Two causes behind one code, so nothing generic is proved.
			name:    "illegal sasl state stays conservative",
			options: []brokerOption{withAuthError(34)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:    "peer hangs up",
			options: []brokerOption{withAuth(peerHangsUp)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolPeerClosed,
		},
		{
			name:    "peer is not kafka",
			options: []brokerOption{withAuth(peerSpeaksHTTP)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:    "undecodable response",
			options: []brokerOption{withAuth(peerSendsGarbage)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolMalformedResponse,
		},
		{
			name:    "response answers another request",
			options: []brokerOption{withAuth(peerMisscorrelates)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolMalformedResponse,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := verifiedTarget(t, test.options...)
			authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

			evidence := node(t, freeze(t, target.builder), authNodeID)
			if evidence.State() != test.state {
				t.Errorf("state = %s, want %s", evidence.State(), test.state)
			}
			if evidence.FailureClass() != test.class {
				t.Errorf("failure class = %s, want %s", evidence.FailureClass(), test.class)
			}
		})
	}
}

// TestRejectionIsAuthenticationNotAuthorization pins a distinction
// docs/ARCHITECTURE.md calls load-bearing: "your credentials are wrong" and
// "your credentials are fine but you lack permission" lead to different actions,
// and this exchange performs no operation that could be denied.
func TestRejectionIsAuthenticationNotAuthorization(t *testing.T) {
	target := verifiedTarget(t, withAuthError(58))
	authenticate(t, target, credentialFor(t, authHost, 9092), AuthParams{})

	evidence := node(t, freeze(t, target.builder), authNodeID)
	switch evidence.FailureClass() {
	case domain.FailureAuthzDenied, domain.FailureAuthzScopeInsufficient:
		t.Errorf("class = %s: a refused credential is not an authorization decision",
			evidence.FailureClass())
	}
	if got, _ := attribute(t, evidence, AttrErrorCode).Int(); got != 58 {
		t.Errorf("error code = %d, want the broker's own 58 recorded beside the class", got)
	}
}

// TestLocalTimeoutIsNotARemoteFailure: an expired local budget says nothing
// about the peer, so it can never be FAIL.
func TestLocalTimeoutIsNotARemoteFailure(t *testing.T) {
	target := verifiedTarget(t, withAuth(peerSaysNothing))

	authenticate(t, target, credentialFor(t, authHost, 9092),
		AuthParams{ExchangeTimeout: 50 * time.Millisecond})

	evidence := node(t, freeze(t, target.builder), authNodeID)
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a local deadline is not a remote failure",
			evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("class = %s, want EXEC_LOCAL_TIMEOUT", evidence.FailureClass())
	}
	if _, ok := evidence.Attribute(AttrErrorCode); ok {
		t.Error("an exchange that never completed recorded an error code")
	}
	if _, ok := evidence.Attribute(AttrSASLSessionLifetimeMs); ok {
		t.Error("an exchange that never completed recorded a session lifetime")
	}
}

func TestCancellationIsRecordedAsCancellation(t *testing.T) {
	target := verifiedTarget(t, withAuth(peerSaysNothing))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	result, err := Authenticate(
		ctx, target.builder, target.session(t), credentialFor(t, authHost, 9092), AuthParams{})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, target.builder), authNodeID)
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("class = %s, want EXEC_CANCELLED", evidence.FailureClass())
	}
}

// --- input contract -------------------------------------------------------

// TestAuthenticateRejectsUnusableInput checks that a defect in the caller comes
// back as an error rather than as a diagnostic claim about the target.
func TestAuthenticateRejectsUnusableInput(t *testing.T) {
	target := verifiedTarget(t)
	credential := credentialFor(t, authHost, 9092)

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "nil context",
			call: func() error {
				//nolint:staticcheck // SA1012: passing a nil context is the defect under test.
				_, err := Authenticate(nil, target.builder, target.session(t), credential, AuthParams{})
				return err
			},
		},
		{
			name: "nil builder",
			call: func() error {
				_, err := Authenticate(
					context.Background(), nil, target.session(t), credential, AuthParams{})
				return err
			},
		},
		{
			name: "nil session",
			call: func() error {
				_, err := Authenticate(
					context.Background(), target.builder, nil, credential, AuthParams{})
				return err
			},
		},
		// A zero credential was a row here until Phase 6.1c-P1. It is no longer
		// a caller defect: a run that reaches authentication with nothing
		// configured is a fact about that run, and the operator has to see it.
		// It is now evidence — SKIPPED + EXEC_REQUIRED_INPUT_MISSING — and
		// requiredinput_test.go owns it.
		{
			name: "negative timeout",
			call: func() error {
				_, err := Authenticate(context.Background(), target.builder, target.session(t),
					credential, AuthParams{ExchangeTimeout: -time.Second})
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want one wrapping ErrInvalidInput", err)
			}
			if got := target.broker.authRequestCount(); got != 0 {
				t.Errorf("broker received %d authentications, want 0", got)
			}
		})
	}
}

// TestAuthenticateRefusesASessionWithoutAConnection: an authentication with
// nothing to run over is a caller defect, not evidence.
func TestAuthenticateRefusesASessionWithoutAConnection(t *testing.T) {
	target := verifiedTarget(t)
	session := target.session(t)

	conn, ok := session.TakeConn()
	if !ok {
		t.Fatal("no connection to take")
	}
	defer func() { _ = conn.Close() }()

	_, err := Authenticate(
		context.Background(), target.builder, session, credentialFor(t, authHost, 9092), AuthParams{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want one wrapping ErrInvalidInput", err)
	}
	if got := target.broker.authRequestCount(); got != 0 {
		t.Errorf("broker received %d authentications, want 0", got)
	}
}
