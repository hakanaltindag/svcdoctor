package kafka

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

const handshakeNodeID = "kafka.sasl_handshake/primary.internal:9092/10.0.0.1"

func runHandshake(
	t *testing.T, sessions *Result, builder *domain.GraphBuilder, params SASLParams,
) *HandshakeResult {
	t.Helper()

	if params.Mechanism == "" {
		params.Mechanism = "PLAIN"
	}
	result, err := SASLHandshake(context.Background(), builder, sessions.Sessions(), params)
	if err != nil {
		t.Fatalf("SASLHandshake: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
}

// --- evidence contract ----------------------------------------------------

func TestHandshakeEvidenceContract(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	before := time.Now()
	result := runHandshake(t, sessions, builder, SASLParams{Mechanism: "SCRAM-SHA-512"})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	if evidence.State() != domain.StatePass {
		t.Fatalf("state = %s (%s), want PASS", evidence.State(), evidence.FailureClass())
	}
	if got, want := evidence.Layer(), domain.LayerAuth; got != want {
		t.Errorf("layer = %s, want %s: a handshake is authentication-layer work", got, want)
	}
	if got, want := evidence.Step(), StepSASLHandshake; got != want {
		t.Errorf("step = %s, want %s", got, want)
	}
	if got, want := evidence.Subject().Ref(), "10.0.0.1:9092"; got != want {
		t.Errorf("subject ref = %q, want the concrete peer %q", got, want)
	}
	if got := evidence.Subject().Kind(); got != domain.SubjectKindEndpoint {
		t.Errorf("subject kind = %s, want ENDPOINT", got)
	}
	if evidence.StartedAt().IsZero() {
		t.Error("startedAt is zero")
	}
	if evidence.StartedAt().Before(before.UTC().Add(-time.Second)) {
		t.Errorf("startedAt = %s, want at or after %s", evidence.StartedAt(), before)
	}
	if evidence.Duration() < 0 {
		t.Errorf("duration = %s, want non-negative", evidence.Duration())
	}
	if len(result.Sessions()) != 1 {
		t.Fatalf("sessions = %d, want 1", len(result.Sessions()))
	}
	if got := result.Sessions()[0].Mechanism(); got != "SCRAM-SHA-512" {
		t.Errorf("session mechanism = %q, want the one the broker accepted", got)
	}
}

func TestHandshakeAttributes(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{Mechanism: "PLAIN"})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	requested, ok := attribute(t, evidence, AttrSASLRequestedMechanism).Str()
	if !ok || requested != "PLAIN" {
		t.Errorf("%s = %q, want PLAIN", AttrSASLRequestedMechanism, requested)
	}

	offered, ok := attribute(t, evidence, AttrSASLOfferedMechanisms).StringList()
	if !ok {
		t.Fatalf("%s is not a string list", AttrSASLOfferedMechanisms)
	}
	// The broker sent SCRAM-SHA-512, PLAIN, SCRAM-SHA-256 in that order.
	want := []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"}
	if strings.Join(offered, ",") != strings.Join(want, ",") {
		t.Errorf("offered = %v, want %v sorted", offered, want)
	}

	code, ok := attribute(t, evidence, AttrErrorCode).Int()
	if !ok || code != 0 {
		t.Errorf("%s = %d, want 0", AttrErrorCode, code)
	}
	version, ok := attribute(t, evidence, AttrRequestAPIVersion).Int()
	if !ok || version != 1 {
		t.Errorf("%s = %d, want 1: the flow with framed authentication errors",
			AttrRequestAPIVersion, version)
	}
}

// TestOfferedMechanismsKeepDuplicates pins the half of the ordering rule that is
// easy to lose: a repeated entry is something the broker sent.
func TestOfferedMechanismsKeepDuplicates(t *testing.T) {
	broker := newBroker(t, peerAnswers, withMechanisms("PLAIN", "PLAIN", "OAUTHBEARER"))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	offered, _ := attribute(t, evidence, AttrSASLOfferedMechanisms).StringList()
	want := []string{"OAUTHBEARER", "PLAIN", "PLAIN"}
	if strings.Join(offered, ",") != strings.Join(want, ",") {
		t.Errorf("offered = %v, want %v", offered, want)
	}
}

func TestHandshakeParentsTheApiVersionsNode(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	want := sessions.Sessions()[0].Evidence()

	runHandshake(t, sessions, builder, SASLParams{})
	graph := freeze(t, builder)

	parents := graph.Parents(domain.EvidenceID(handshakeNodeID))
	if len(parents) != 1 || parents[0] != want {
		t.Fatalf("parents = %v, want [%s]", parents, want)
	}
	parent := node(t, graph, parents[0].String())
	if parent.Layer() != domain.LayerProtocol {
		t.Errorf("parent layer = %s, want L4", parent.Layer())
	}
	if parent.Step() != StepAPIVersions {
		t.Errorf("parent step = %s, want %s", parent.Step(), StepAPIVersions)
	}
}

// TestOneAddressReadsAsOneFamily checks the whole chain a reader follows: every
// layer for one address, connected, from the lookup down to the handshake.
func TestOneAddressReadsAsOneFamily(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{})
	graph := freeze(t, builder)

	chain := []struct {
		id    string
		layer domain.Layer
	}{
		{"dns.lookup/primary.internal", domain.LayerDNS},
		{"tcp.connect/primary.internal:9092/10.0.0.1", domain.LayerTCP},
		{"kafka.api_versions/primary.internal:9092/10.0.0.1", domain.LayerProtocol},
		{handshakeNodeID, domain.LayerAuth},
	}
	previous := chain[0]
	if got := node(t, graph, previous.id).Layer(); got != previous.layer {
		t.Errorf("%s layer = %s, want %s", previous.id, got, previous.layer)
	}
	for _, step := range chain[1:] {
		if got := node(t, graph, step.id).Layer(); got != step.layer {
			t.Errorf("%s layer = %s, want %s", step.id, got, step.layer)
		}
		parents := graph.Parents(domain.EvidenceID(step.id))
		if len(parents) != 1 || parents[0].String() != previous.id {
			t.Errorf("%s parents = %v, want [%s]", step.id, parents, previous.id)
		}
		previous = step
	}
}

func TestHandshakeEvidenceIDIsDeterministic(t *testing.T) {
	first := newBroker(t, peerAnswers)
	sessionsA, builderA, _ := apiVersionsSessions(t, first)
	runHandshake(t, sessionsA, builderA, SASLParams{})

	second := newBroker(t, peerAnswers)
	sessionsB, builderB, _ := apiVersionsSessions(t, second)
	runHandshake(t, sessionsB, builderB, SASLParams{})

	idA := node(t, freeze(t, builderA), handshakeNodeID).ID()
	idB := node(t, freeze(t, builderB), handshakeNodeID).ID()
	if idA != idB {
		t.Errorf("identifiers differ between equivalent runs: %q and %q", idA, idB)
	}
}

// --- classification -------------------------------------------------------

func TestHandshakeFailures(t *testing.T) {
	tests := []struct {
		name        string
		options     []brokerOption
		wantState   domain.State
		wantFailure domain.FailureClass
	}{
		{
			name:      "mechanism is not offered",
			options:   []brokerOption{withSASLError(33)},
			wantState: domain.StateFail, wantFailure: domain.FailureAuthMechanismNotOffered,
		},
		{
			name:      "handshake is not expected here",
			options:   []brokerOption{withSASLError(34)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:      "broker does not support the request version",
			options:   []brokerOption{withSASLError(35)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnsupportedVersion,
		},
		{
			name:      "an error code nobody anticipated",
			options:   []brokerOption{withSASLError(58)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:      "peer closes before answering",
			options:   []brokerOption{withSASL(peerHangsUp)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolPeerClosed,
		},
		{
			name:      "peer stops speaking kafka",
			options:   []brokerOption{withSASL(peerSpeaksHTTP)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:      "response cannot be decoded",
			options:   []brokerOption{withSASL(peerSendsGarbage)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolMalformedResponse,
		},
		{
			name:      "response answers a different request",
			options:   []brokerOption{withSASL(peerMisscorrelates)},
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolMalformedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker := newBroker(t, peerAnswers, tt.options...)
			sessions, builder, _ := apiVersionsSessions(t, broker)

			result := runHandshake(t, sessions, builder, SASLParams{})
			evidence := node(t, freeze(t, builder), handshakeNodeID)

			if evidence.State() != tt.wantState {
				t.Errorf("state = %s, want %s", evidence.State(), tt.wantState)
			}
			if evidence.FailureClass() != tt.wantFailure {
				t.Errorf("failure class = %s, want %s", evidence.FailureClass(), tt.wantFailure)
			}
			// No outcome but acceptance leaves a socket with a next message.
			if got := len(result.Sessions()); got != 0 {
				t.Errorf("sessions = %d, want 0 for a handshake that was not accepted", got)
			}
		})
	}
}

// TestRejectedMechanismRecordsWhatIsOffered is the point of the step: the answer
// that says "no" is the one that says what to ask for instead.
func TestRejectedMechanismRecordsWhatIsOffered(t *testing.T) {
	broker := newBroker(t, peerAnswers,
		withSASLError(33), withMechanisms("SCRAM-SHA-512", "OAUTHBEARER"))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{Mechanism: "PLAIN"})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	if evidence.FailureClass() != domain.FailureAuthMechanismNotOffered {
		t.Errorf("failure class = %s, want AUTH_MECHANISM_NOT_OFFERED", evidence.FailureClass())
	}
	requested, _ := attribute(t, evidence, AttrSASLRequestedMechanism).Str()
	if requested != "PLAIN" {
		t.Errorf("requested = %q, want PLAIN", requested)
	}
	offered, _ := attribute(t, evidence, AttrSASLOfferedMechanisms).StringList()
	if strings.Join(offered, ",") != "OAUTHBEARER,SCRAM-SHA-512" {
		t.Errorf("offered = %v, want the broker's list", offered)
	}
	code, _ := attribute(t, evidence, AttrErrorCode).Int()
	if code != 33 {
		t.Errorf("%s = %d, want 33", AttrErrorCode, code)
	}
}

// TestNotOfferedIsNotUnsupportedBySvcdoctor pins a distinction the architecture
// calls binding: a broker declining a mechanism is a fact about the broker, and
// svcdoctor being unable to perform one is a gap in this tool. They are
// different classes and must never be produced by the same observation.
func TestNotOfferedIsNotUnsupportedBySvcdoctor(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASLError(33))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	// GSSAPI is a mechanism svcdoctor cannot perform. Asking about it still
	// produces the peer-side fact, because asking is all that happened.
	runHandshake(t, sessions, builder, SASLParams{Mechanism: "GSSAPI"})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	switch evidence.FailureClass() {
	case domain.FailureAuthMechanismNotOffered:
	case domain.FailureAuthMechanismUnsupported, domain.FailureExecUnsupportedBySvcdoctor:
		t.Errorf("failure class = %s: the broker's answer was turned into a claim about svcdoctor",
			evidence.FailureClass())
	default:
		t.Errorf("failure class = %s, want AUTH_MECHANISM_NOT_OFFERED", evidence.FailureClass())
	}
}

// --- budget ---------------------------------------------------------------

func TestHandshakeCallerDeadlineIsNotAPeerFailure(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSaysNothing))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := SASLHandshake(ctx, builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, builder), handshakeNodeID)
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a local deadline proves nothing about the broker",
			evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", evidence.FailureClass())
	}
}

func TestHandshakeCancellationIsNotAPeerFailure(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSaysNothing))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	result, err := SASLHandshake(ctx, builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, builder), handshakeNodeID)
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", evidence.FailureClass())
	}
}

func TestHandshakeExchangeTimeoutBoundsOnePath(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSaysNothing))
	sessions, builder, _ := apiVersionsSessions(t, broker, "10.0.0.1", "10.0.0.2")

	runHandshake(t, sessions, builder, SASLParams{
		Mechanism: "PLAIN", ExchangeTimeout: 30 * time.Millisecond,
	})
	graph := freeze(t, builder)

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		evidence := node(t, graph, "kafka.sasl_handshake/primary.internal:9092/"+address)
		if evidence.FailureClass() != domain.FailureExecLocalTimeout {
			t.Errorf("%s failure = %s, want EXEC_LOCAL_TIMEOUT", address, evidence.FailureClass())
		}
	}
	if got := broker.saslRequestCount(); got != 2 {
		t.Errorf("broker saw %d handshakes, want both paths attempted", got)
	}
}

// --- multiple paths -------------------------------------------------------

func TestEveryPathIsAskedAboutTheMechanism(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker, "10.0.0.1", "10.0.0.2", "2001:db8::1")

	result := runHandshake(t, sessions, builder, SASLParams{})
	graph := freeze(t, builder)

	for _, address := range []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"} {
		evidence := node(t, graph, "kafka.sasl_handshake/primary.internal:9092/"+address)
		if evidence.State() != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", address, evidence.State())
		}
	}
	if got := broker.saslRequestCount(); got != 3 {
		t.Errorf("broker saw %d handshakes, want 3", got)
	}
	if got := len(result.Sessions()); got != 3 {
		t.Errorf("sessions = %d, want 3", got)
	}
}

// TestHandshakeChoosesNoPath is the rule that matters most here, because the
// step after this one is the step that would send credentials. A list in
// canonical address order must not become a decision about where a secret goes.
func TestHandshakeChoosesNoPath(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker, "2001:db8::1", "10.0.0.1")

	result := runHandshake(t, sessions, builder, SASLParams{})

	families := map[bool]bool{}
	for _, session := range result.Sessions() {
		if !session.Available() {
			t.Errorf("session %s is not available to take", session.Address())
		}
		families[session.Address().Addr().Is4()] = true
	}
	if !families[true] || !families[false] {
		t.Errorf("both families accepted but only one was offered: %v", families)
	}

	var handshakeResult any = result
	if _, ok := handshakeResult.(interface{ Best() *HandshakeSession }); ok {
		t.Error("the handshake result ranks its sessions")
	}
	if _, ok := handshakeResult.(interface{ Preferred() *HandshakeSession }); ok {
		t.Error("the handshake result names a preferred session")
	}
	if _, ok := handshakeResult.(interface{ Status() string }); ok {
		t.Error("the handshake result exposes an overall status")
	}
}

// TestOneRejectingBrokerDoesNotHideAnother is the inconsistency the per-path
// design exists to surface: one listener with a different SASL configuration.
func TestOneRejectingBrokerDoesNotHideAnother(t *testing.T) {
	accepting := newBroker(t, peerAnswers)
	rejecting := newBroker(t, peerAnswers, withSASLError(33), withMechanisms("SCRAM-SHA-512"))

	builder := domain.NewGraphBuilder()
	first := apiVersionsSessionsAt(t, builder, accepting, "primary.internal", "10.0.0.1", nil)
	second := apiVersionsSessionsAt(t, builder, rejecting, "secondary.internal", "10.0.0.2", nil)

	combined := append(first.Sessions(), second.Sessions()...)
	result, err := SASLHandshake(context.Background(), builder, combined, SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph := freeze(t, builder)
	good := node(t, graph, "kafka.sasl_handshake/primary.internal:9092/10.0.0.1")
	bad := node(t, graph, "kafka.sasl_handshake/secondary.internal:9092/10.0.0.2")

	if good.State() != domain.StatePass {
		t.Errorf("the accepting broker state = %s, want PASS", good.State())
	}
	if bad.State() != domain.StateFail {
		t.Errorf("the rejecting broker state = %s, want FAIL", bad.State())
	}
	if len(result.Sessions()) != 1 {
		t.Errorf("sessions = %d, want only the path that accepted", len(result.Sessions()))
	}
}

// --- input and error boundaries -------------------------------------------

func TestHandshakeRejectsUnusableInput(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	//nolint:staticcheck // passing a nil context is exactly what this guard is for.
	if _, err := SASLHandshake(nil, builder, nil, SASLParams{Mechanism: "PLAIN"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil context: error = %v, want ErrInvalidInput", err)
	}
	if _, err := SASLHandshake(
		context.Background(), nil, nil, SASLParams{Mechanism: "PLAIN"},
	); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil builder: error = %v, want ErrInvalidInput", err)
	}
	if _, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{},
	); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty mechanism: error = %v, want ErrInvalidInput", err)
	}
	if _, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(),
		SASLParams{Mechanism: "PLAIN", ExchangeTimeout: -time.Second},
	); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative timeout: error = %v, want ErrInvalidInput", err)
	}
}

// TestEmptyMechanismSendsNothing checks that the rejection above happens before
// any socket is touched, so an unusable parameter cannot spend a connection.
func TestEmptyMechanismSendsNothing(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	if _, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{},
	); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if got := broker.saslRequestCount(); got != 0 {
		t.Errorf("broker saw %d handshakes, want 0", got)
	}
	if !sessions.Sessions()[0].Available() {
		t.Error("a rejected call took the connection anyway")
	}
	if freeze(t, builder).Len() != 3 {
		t.Error("a rejected call recorded evidence")
	}
}

func TestNoSessionsIsNotAnError(t *testing.T) {
	builder := domain.NewGraphBuilder()

	result, err := SASLHandshake(context.Background(), builder, nil, SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("SASLHandshake with no sessions: %v", err)
	}
	defer func() { _ = result.Close() }()

	if len(result.Sessions()) != 0 {
		t.Error("sessions were produced without input")
	}
	if freeze(t, builder).Len() != 0 {
		t.Error("evidence was produced without input")
	}
}

func TestHandshakeOutcomesAreNotAdapterErrors(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSpeaksHTTP))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	result, err := SASLHandshake(
		context.Background(), builder, sessions.Sessions(), SASLParams{Mechanism: "PLAIN"})
	if err != nil {
		t.Fatalf("a broken handshake became an adapter error: %v", err)
	}
	defer func() { _ = result.Close() }()

	if node(t, freeze(t, builder), handshakeNodeID).State() != domain.StateFail {
		t.Error("the outcome was not recorded as evidence")
	}
}

// --- what goes on the wire ------------------------------------------------

// TestHandshakeSendsOnlyTheMechanism is the security premise of this phase: a
// handshake carries a mechanism name and nothing else, which is what makes it
// safe to run on every path without a credential decision.
func TestHandshakeSendsOnlyTheMechanism(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{Mechanism: "SCRAM-SHA-256"})

	if got := broker.mechanismsSeen(); len(got) != 1 || got[0] != "SCRAM-SHA-256" {
		t.Fatalf("mechanisms seen = %v, want [SCRAM-SHA-256]", got)
	}

	// The request body is a single Kafka string: two length bytes and the
	// mechanism. Anything else on the wire would show up as extra bytes here.
	payloads := broker.handshakeBytes()
	if len(payloads) != 1 {
		t.Fatalf("handshake payloads = %d, want 1", len(payloads))
	}
	want := len("SCRAM-SHA-256") + 2
	if len(payloads[0]) != want {
		t.Errorf("handshake body is %d bytes, want exactly %d: the mechanism and its length",
			len(payloads[0]), want)
	}

	if ids := broker.clientIDsSeen(); len(ids) != 1 || ids[0] != "svcdoctor" {
		t.Errorf("client ids = %v, want [svcdoctor]: a diagnostic tool identifies itself", ids)
	}
}

// TestHandshakeCarriesNoCredentialMaterial searches every byte svcdoctor put on
// the wire, and the evidence it produced, for a canary a caller might hold as a
// password. Phase 3.2 sends no credentials at all, and this is what will fail
// first if that ever stops being true by accident.
func TestHandshakeCarriesNoCredentialMaterial(t *testing.T) {
	const canary = "Zx9-CANARY-PASSWORD-7fA3q1"

	broker := newBroker(t, peerAnswers)
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{Mechanism: "PLAIN"})

	for _, payload := range broker.handshakeBytes() {
		if bytes.Contains(payload, []byte(canary)) {
			t.Error("a credential reached the wire during a handshake")
		}
	}

	evidence := node(t, freeze(t, builder), handshakeNodeID)
	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(encoded), canary) {
		t.Errorf("evidence carries credential material: %s", encoded)
	}

	// The formatted forms a test failure or a log line would use.
	for _, formatted := range []string{
		evidence.String(),
		fmt.Sprintf("%v", evidence),
		fmt.Sprintf("%+v", evidence),
		fmt.Sprintf("%#v", evidence.Attributes()),
	} {
		if strings.Contains(formatted, canary) {
			t.Error("a formatted evidence value carries credential material")
		}
	}
}

// TestNoRawProtocolValuesReachHandshakeEvidence guards ADR 0010 at the new step.
func TestNoRawProtocolValuesReachHandshakeEvidence(t *testing.T) {
	broker := newBroker(t, peerAnswers, withSASL(peerSpeaksHTTP))
	sessions, builder, _ := apiVersionsSessions(t, broker)

	runHandshake(t, sessions, builder, SASLParams{})
	evidence := node(t, freeze(t, builder), handshakeNodeID)

	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, forbidden := range []string{
		"kmsg", "SASLHandshakeResponse", "127.0.0.1:", "HTTP", "Bad Request",
		"announced response size", "kafka framing",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("evidence carries %q: %s", forbidden, encoded)
		}
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	allowed := map[string]bool{
		"id": true, "subject": true, "layer": true, "step": true, "state": true,
		"failureClass": true, "attributes": true, "startedAt": true, "duration": true,
	}
	for field := range fields {
		if !allowed[field] {
			t.Errorf("evidence carries an unexpected field %q", field)
		}
	}
}

// TestHandshakeClassesStayServiceNeutral pins that no Kafka name reaches the
// domain vocabulary.
func TestHandshakeClassesStayServiceNeutral(t *testing.T) {
	for _, code := range []int16{33, 34, 35} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			broker := newBroker(t, peerAnswers, withSASLError(code))
			sessions, builder, _ := apiVersionsSessions(t, broker)

			runHandshake(t, sessions, builder, SASLParams{})
			evidence := node(t, freeze(t, builder), handshakeNodeID)

			if class := evidence.FailureClass().String(); strings.Contains(strings.ToLower(class), "kafka") {
				t.Errorf("failure class %q carries a service name", class)
			}
			if got, ok := attribute(t, evidence, AttrErrorCode).Int(); !ok || got != int64(code) {
				t.Errorf("%s = %d, want the broker's own code %d", AttrErrorCode, got, code)
			}
		})
	}
}
