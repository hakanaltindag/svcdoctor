package kafka

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/probe/transport"
)

func run(t *testing.T, paths *transport.Result, builder *domain.GraphBuilder, params Params) *Result {
	t.Helper()

	result, err := Run(context.Background(), builder, paths.Continuations(), params)
	if err != nil {
		t.Fatalf("Run: unexpected error: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })
	return result
}

// --- protocol success -----------------------------------------------------

func TestApiVersionsEvidenceContract(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	before := time.Now()
	result := run(t, paths, builder, Params{})
	graph := freeze(t, builder)

	evidence := node(t, graph, "kafka.api_versions/primary.internal:9092/10.0.0.1")

	if evidence.State() != domain.StatePass {
		t.Fatalf("state = %s (%s), want PASS", evidence.State(), evidence.FailureClass())
	}
	if got, want := evidence.Layer(), domain.LayerProtocol; got != want {
		t.Errorf("layer = %s, want %s", got, want)
	}
	if got, want := evidence.Step(), StepAPIVersions; got != want {
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
	if d, measured := evidence.Elapsed().Duration(); !measured || d < 0 {
		t.Errorf("elapsed = (%s, %t), want a non-negative measurement", d, measured)
	}
	if len(result.Sessions()) != 1 {
		t.Errorf("sessions = %d, want 1", len(result.Sessions()))
	}
}

func TestAdvertisedRangesAreNormalized(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	ranges, ok := attribute(t, evidence, AttrAPIVersions).StringList()
	if !ok {
		t.Fatalf("%s is not a string list", AttrAPIVersions)
	}

	// The broker advertised 18, 3, 1 in that order; the report is sorted by key
	// numerically, so 2 would precede 10 rather than following it lexically.
	want := []string{"1:0-13", "3:0-12", "18:0-3"}
	if len(ranges) != len(want) {
		t.Fatalf("ranges = %v, want %v", ranges, want)
	}
	for i := range want {
		if ranges[i] != want[i] {
			t.Fatalf("ranges = %v, want %v", ranges, want)
		}
	}

	code, ok := attribute(t, evidence, AttrErrorCode).Int()
	if !ok || code != 0 {
		t.Errorf("%s = %d, want 0", AttrErrorCode, code)
	}
	requested, ok := attribute(t, evidence, AttrRequestAPIVersion).Int()
	if !ok || requested != 0 {
		t.Errorf("%s = %d, want 0", AttrRequestAPIVersion, requested)
	}
}

// TestNumericOrderingIsNotLexical pins the grammar's ordering rule with keys
// that would sort differently as strings.
func TestNumericOrderingIsNotLexical(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")
	ranges, _ := attribute(t, evidence, AttrAPIVersions).StringList()

	if ranges[0] != "1:0-13" || ranges[len(ranges)-1] != "18:0-3" {
		t.Errorf("ranges = %v, want key 1 first and key 18 last", ranges)
	}
}

func TestProtocolNodeParentsTheTransportNode(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	// The transport path had no TLS, so the parent must be the TCP node.
	continuation := paths.Continuations()[0]
	want := continuation.Evidence()

	run(t, paths, builder, Params{})
	graph := freeze(t, builder)

	protocolID := domain.EvidenceID("kafka.api_versions/primary.internal:9092/10.0.0.1")
	parents := graph.Parents(protocolID)
	if len(parents) != 1 || parents[0] != want {
		t.Fatalf("parents = %v, want [%s]", parents, want)
	}
	if _, ok := graph.Node(parents[0]); !ok {
		t.Error("the protocol node points at a parent that is not in the graph")
	}
	if got := node(t, graph, parents[0].String()).Layer(); got != domain.LayerTCP {
		t.Errorf("parent layer = %s, want L2 for a path without TLS", got)
	}
}

func TestEvidenceIDIsDeterministic(t *testing.T) {
	first := newBroker(t, peerAnswers)
	pathsA, builderA := path(t, first)
	run(t, pathsA, builderA, Params{})

	second := newBroker(t, peerAnswers)
	pathsB, builderB := path(t, second)
	run(t, pathsB, builderB, Params{})

	idA := node(t, freeze(t, builderA), "kafka.api_versions/primary.internal:9092/10.0.0.1").ID()
	idB := node(t, freeze(t, builderB), "kafka.api_versions/primary.internal:9092/10.0.0.1").ID()
	if idA != idB {
		t.Errorf("identifiers differ between equivalent runs: %q and %q", idA, idB)
	}
}

// --- failures -------------------------------------------------------------

func TestProtocolFailures(t *testing.T) {
	tests := []struct {
		name        string
		behaviour   peerBehaviour
		wantState   domain.State
		wantFailure domain.FailureClass
	}{
		{
			name: "peer closes before answering", behaviour: peerHangsUp,
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolPeerClosed,
		},
		{
			name: "peer does not speak kafka", behaviour: peerSpeaksHTTP,
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnexpectedResponse,
		},
		{
			name: "response cannot be decoded", behaviour: peerSendsGarbage,
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolMalformedResponse,
		},
		{
			name: "response answers a different request", behaviour: peerMisscorrelates,
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolMalformedResponse,
		},
		{
			name: "broker reports an error code", behaviour: peerAnswersWithError,
			wantState: domain.StateFail, wantFailure: domain.FailureProtocolUnsupportedVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			broker := newBroker(t, tt.behaviour)
			paths, builder := path(t, broker)

			result := run(t, paths, builder, Params{})
			evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

			if evidence.State() != tt.wantState {
				t.Errorf("state = %s, want %s", evidence.State(), tt.wantState)
			}
			if evidence.FailureClass() != tt.wantFailure {
				t.Errorf("failure class = %s, want %s", evidence.FailureClass(), tt.wantFailure)
			}
			// A broken exchange leaves no usable socket; a broker that
			// answered with an error code leaves one that is still fine.
			wantSessions := 0
			if tt.behaviour == peerAnswersWithError {
				wantSessions = 1
			}
			if got := len(result.Sessions()); got != wantSessions {
				t.Errorf("sessions = %d, want %d", got, wantSessions)
			}
		})
	}
}

// TestBrokerErrorCodeIsRecordedAsAFact checks that the specific code survives
// even though the generic class stays conservative.
func TestBrokerErrorCodeIsRecordedAsAFact(t *testing.T) {
	broker := newBroker(t, peerAnswersWithError)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	code, ok := attribute(t, evidence, AttrErrorCode).Int()
	if !ok || code != 35 {
		t.Errorf("%s = %d, want 35", AttrErrorCode, code)
	}
	if _, present := evidence.Attribute(AttrAPIVersions); present {
		t.Error("no ranges were advertised, so none should be recorded")
	}
	if evidence.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL: the broker did not answer what was asked", evidence.State())
	}
}

// TestUnsupportedVersionIsNormalized covers the one broker error code the
// protocol defines well enough to translate.
//
// UNSUPPORTED_VERSION on an ApiVersions response says the broker does not
// support the request version it was sent, which is exactly what the generic
// class says. Leaving it as PROTOCOL_UNEXPECTED_RESPONSE would put it in the
// same class as a peer that is not Kafka at all, and those two lead to opposite
// actions.
func TestUnsupportedVersionIsNormalized(t *testing.T) {
	broker := newErrorBroker(t, 35)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	if got := evidence.FailureClass(); got != domain.FailureProtocolUnsupportedVersion {
		t.Errorf("failure class = %s, want PROTOCOL_UNSUPPORTED_VERSION", got)
	}
	if evidence.State() != domain.StateFail {
		t.Errorf("state = %s, want FAIL", evidence.State())
	}

	// The generic class is a normalization, never a replacement: the Kafka code
	// and the version that produced it both stay on the node.
	code, ok := attribute(t, evidence, AttrErrorCode).Int()
	if !ok || code != 35 {
		t.Errorf("%s = %d, want the broker's own code 35", AttrErrorCode, code)
	}
	requested, ok := attribute(t, evidence, AttrRequestAPIVersion).Int()
	if !ok || requested != 0 {
		t.Errorf("%s = %d, want 0: a version error is uninterpretable without it",
			AttrRequestAPIVersion, requested)
	}
}

// TestOtherErrorCodesStayConservative is the other half of the rule. Every code
// but UNSUPPORTED_VERSION keeps the conservative class, because nothing else an
// ApiVersions response can carry proves a generic fact on its own — inferring an
// authentication state or a configuration from a number is diagnosis, and it
// would be diagnosis performed here on one code with no evidence.
func TestOtherErrorCodesStayConservative(t *testing.T) {
	// 34 ILLEGAL_SASL_STATE and 42 INVALID_REQUEST are the codes a Kafka-shaped
	// peer could plausibly produce; 58 is one no ApiVersions response defines.
	for _, code := range []int16{34, 42, 58} {
		t.Run(strconv.Itoa(int(code)), func(t *testing.T) {
			broker := newErrorBroker(t, code)
			paths, builder := path(t, broker)

			run(t, paths, builder, Params{})
			evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

			if got := evidence.FailureClass(); got != domain.FailureProtocolUnexpectedResponse {
				t.Errorf("failure class = %s, want PROTOCOL_UNEXPECTED_RESPONSE", got)
			}
			if evidence.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", evidence.State())
			}
			got, ok := attribute(t, evidence, AttrErrorCode).Int()
			if !ok || got != int64(code) {
				t.Errorf("%s = %d, want %d", AttrErrorCode, got, code)
			}
		})
	}
}

// TestNoKafkaSemanticsEnterTheDomain pins the boundary the normalization must
// not cross: the class vocabulary stays service neutral, and the Kafka name for
// a code is never recorded.
func TestNoKafkaSemanticsEnterTheDomain(t *testing.T) {
	broker := newErrorBroker(t, 35)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	if got := evidence.FailureClass().String(); got != "PROTOCOL_UNSUPPORTED_VERSION" {
		t.Errorf("failure class = %q, want the service-neutral name", got)
	}
	if got := evidence.FailureClass().String(); strings.Contains(strings.ToLower(got), "kafka") {
		t.Errorf("failure class %q carries a service name", got)
	}

	// The Kafka code travels as a number under a Kafka-namespaced key. Its
	// spelling is Kafka's own table, and a report that carried it would be
	// naming a service in a field the domain owns.
	if _, ok := attribute(t, evidence, AttrErrorCode).Int(); !ok {
		t.Errorf("%s is not an integer, so it is carrying a Kafka name", AttrErrorCode)
	}
	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(encoded), "ILLEGAL_SASL_STATE") {
		t.Errorf("evidence carries a Kafka error name: %s", encoded)
	}
}

// --- budget ---------------------------------------------------------------

func TestCallerDeadlineIsNotAPeerFailure(t *testing.T) {
	broker := newBroker(t, peerSaysNothing)
	paths, builder := path(t, broker)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result, err := Run(ctx, builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN: a local deadline proves nothing about the broker", evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecLocalTimeout {
		t.Errorf("failure class = %s, want EXEC_LOCAL_TIMEOUT", evidence.FailureClass())
	}
}

func TestCancellationIsNotAPeerFailure(t *testing.T) {
	broker := newBroker(t, peerSaysNothing)
	paths, builder := path(t, broker)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	result, err := Run(ctx, builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("failure class = %s, want EXEC_CANCELLED", evidence.FailureClass())
	}
}

// TestExchangeTimeoutBoundsOnePath shows why the per-exchange bound exists: one
// silent broker must not consume the budget every later path needs.
func TestExchangeTimeoutBoundsOnePath(t *testing.T) {
	broker := newBroker(t, peerSaysNothing)
	paths, builder := path(t, broker, "10.0.0.1", "10.0.0.2")

	run(t, paths, builder, Params{ExchangeTimeout: 30 * time.Millisecond})
	graph := freeze(t, builder)

	for _, address := range []string{"10.0.0.1", "10.0.0.2"} {
		evidence := node(t, graph, "kafka.api_versions/primary.internal:9092/"+address)
		if evidence.State() != domain.StateUnknown {
			t.Errorf("%s state = %s, want UNKNOWN", address, evidence.State())
		}
		if evidence.FailureClass() != domain.FailureExecLocalTimeout {
			t.Errorf("%s failure = %s, want EXEC_LOCAL_TIMEOUT", address, evidence.FailureClass())
		}
	}
	if got := broker.requestCount(); got != 2 {
		t.Errorf("broker saw %d requests, want both paths attempted", got)
	}
}

// --- multiple paths -------------------------------------------------------

// TestEveryPathIsAsked is the diagnostic premise: ApiVersions describes the
// broker at the other end of one connection, so every path must be asked.
func TestEveryPathIsAsked(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker, "10.0.0.1", "10.0.0.2", "2001:db8::1")

	result := run(t, paths, builder, Params{})
	graph := freeze(t, builder)

	for _, address := range []string{"10.0.0.1", "10.0.0.2", "2001:db8::1"} {
		evidence := node(t, graph, "kafka.api_versions/primary.internal:9092/"+address)
		if evidence.State() != domain.StatePass {
			t.Errorf("%s state = %s, want PASS", address, evidence.State())
		}
	}
	if got := broker.requestCount(); got != 3 {
		t.Errorf("broker saw %d requests, want 3", got)
	}
	if got := len(result.Sessions()); got != 3 {
		t.Errorf("sessions = %d, want 3", got)
	}
}

// TestNoPathIsChosen is the counterpart: the adapter offers what answered and
// ranks nothing, so no hidden family or ordering preference can exist.
func TestNoPathIsChosen(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker, "2001:db8::1", "10.0.0.1")

	result := run(t, paths, builder, Params{})

	families := map[bool]bool{}
	for _, session := range result.Sessions() {
		if !session.Available() {
			t.Errorf("session %s is not available to take", session.Address())
		}
		families[session.Address().Addr().Is4()] = true
	}
	if !families[true] || !families[false] {
		t.Errorf("both families answered but only one was offered: %v", families)
	}

	var adapterResult any = result
	if _, ok := adapterResult.(interface{ Best() *Session }); ok {
		t.Error("the adapter ranks its sessions")
	}
	if _, ok := adapterResult.(interface{ Status() string }); ok {
		t.Error("the adapter exposes an overall status")
	}
}

// TestOneBrokenPathDoesNotHideAnother is the inconsistency this design exists to
// surface: one address answering does not stop the others from being asked.
func TestOneBrokenPathDoesNotHideAnother(t *testing.T) {
	answering := newBroker(t, peerAnswers)
	silent := newBroker(t, peerSpeaksHTTP)

	// Two transport paths, each dialed to a different fake peer.
	builder := domain.NewGraphBuilder()
	registry := &connRegistry{}
	paths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: "primary.internal", Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, []string{"10.0.0.1"})},
		Dialer:   brokerDialer{target: answering.addr, conns: registry},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = paths.Close() })

	otherPaths, err := transport.Run(context.Background(), builder, transport.Params{
		Host: "secondary.internal", Port: 9092,
		Resolver: fixedResolver{addresses: parseAddrs(t, []string{"10.0.0.2"})},
		Dialer:   brokerDialer{target: silent.addr, conns: registry},
	})
	if err != nil {
		t.Fatalf("transport.Run: %v", err)
	}
	t.Cleanup(func() { _ = otherPaths.Close() })

	combined := append(paths.Continuations(), otherPaths.Continuations()...)
	result, err := Run(context.Background(), builder, combined, Params{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() { _ = result.Close() })

	graph := freeze(t, builder)
	good := node(t, graph, "kafka.api_versions/primary.internal:9092/10.0.0.1")
	bad := node(t, graph, "kafka.api_versions/secondary.internal:9092/10.0.0.2")

	if good.State() != domain.StatePass {
		t.Errorf("the answering broker state = %s, want PASS", good.State())
	}
	if bad.State() != domain.StateFail {
		t.Errorf("the non-Kafka peer state = %s, want FAIL", bad.State())
	}
	if len(result.Sessions()) != 1 {
		t.Errorf("sessions = %d, want only the path that answered", len(result.Sessions()))
	}
}

// --- input and error boundaries -------------------------------------------

func TestRunRejectsUnusableInput(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	if _, err := Run(context.Background(), nil, paths.Continuations(), Params{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil builder: error = %v, want ErrInvalidInput", err)
	}
	if _, err := Run(context.Background(), builder, paths.Continuations(), Params{
		ExchangeTimeout: -time.Second,
	}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("negative timeout: error = %v, want ErrInvalidInput", err)
	}
}

//nolint:staticcheck // passing a nil context is exactly what this guard is for.
func TestRunRejectsNilContext(t *testing.T) {
	result, err := Run(nil, domain.NewGraphBuilder(), nil, Params{})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("error = %v, want ErrInvalidInput", err)
	}
	if result != nil {
		t.Error("a result was produced without a context")
	}
}

func TestNoPathsIsNotAnError(t *testing.T) {
	builder := domain.NewGraphBuilder()

	result, err := Run(context.Background(), builder, nil, Params{})
	if err != nil {
		t.Fatalf("Run with no paths: %v", err)
	}
	defer func() { _ = result.Close() }()

	if len(result.Sessions()) != 0 {
		t.Error("sessions were produced without paths")
	}
	if freeze(t, builder).Len() != 0 {
		t.Error("evidence was produced without paths")
	}
}

// TestProtocolOutcomesAreNotAdapterErrors pins the boundary between a
// diagnostic fact and an operational error.
func TestProtocolOutcomesAreNotAdapterErrors(t *testing.T) {
	broker := newBroker(t, peerSpeaksHTTP)
	paths, builder := path(t, broker)

	result, err := Run(context.Background(), builder, paths.Continuations(), Params{})
	if err != nil {
		t.Fatalf("a non-Kafka peer became an adapter error: %v", err)
	}
	defer func() { _ = result.Close() }()

	if node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1").State() != domain.StateFail {
		t.Error("the outcome was not recorded as evidence")
	}
}

// --- no raw protocol values -----------------------------------------------

// TestNoRawProtocolValuesReachEvidence guards ADR 0010 at the adapter boundary.
func TestNoRawProtocolValuesReachEvidence(t *testing.T) {
	broker := newBroker(t, peerAnswers)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, forbidden := range []string{"kmsg", "ApiVersionsResponse", "127.0.0.1:", "0x"} {
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

// TestNoRuntimeErrorProseReachesEvidence checks the failure path for the same
// property: the peer's bytes and the socket's error text stay out.
func TestNoRuntimeErrorProseReachesEvidence(t *testing.T) {
	broker := newBroker(t, peerSpeaksHTTP)
	paths, builder := path(t, broker)

	run(t, paths, builder, Params{})
	evidence := node(t, freeze(t, builder), "kafka.api_versions/primary.internal:9092/10.0.0.1")

	encoded, err := evidence.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	for _, forbidden := range []string{"HTTP", "Bad Request", "announced response size", "kafka framing"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("evidence carries error prose %q: %s", forbidden, encoded)
		}
	}
}
