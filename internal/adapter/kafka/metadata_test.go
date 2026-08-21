package kafka

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

const metadataNodeID = "kafka.metadata/primary.internal:9092/10.0.0.1"

// brokerNodeID builds the identifier of one advertisement node.
//
// It is spelled out rather than derived from the production code, so that a
// change to the identifier scheme fails these tests instead of silently taking
// them along with it.
func brokerNodeID(nodeID int32, ref string) string {
	return "kafka.broker_advertised/primary.internal:9092/10.0.0.1/" +
		strconv.FormatInt(int64(nodeID), 10) + "/" + ref
}

// --- the exchange -----------------------------------------------------------

func TestMetadataEvidenceContract(t *testing.T) {
	target := authenticatedTarget(t, withControllerID(2))

	before := time.Now()
	result := discover(t, target, MetadataParams{})
	evidence := node(t, freeze(t, target.builder), metadataNodeID)

	if evidence.State() != domain.StatePass {
		t.Fatalf("state = %s (%s), want PASS", evidence.State(), evidence.FailureClass())
	}
	if got, want := evidence.Layer(), domain.LayerTopology; got != want {
		t.Errorf("layer = %s, want %s: metadata is topology discovery", got, want)
	}
	if got, want := evidence.Step(), StepMetadata; got != want {
		t.Errorf("step = %s, want %s", got, want)
	}
	if got, want := evidence.Subject().Ref(), authAddress+":9092"; got != want {
		t.Errorf("subject = %q, want the peer that answered %q", got, want)
	}
	if evidence.StartedAt().Before(before.Add(-time.Second)) {
		t.Errorf("startedAt = %s, want a time from this run", evidence.StartedAt())
	}
	if got := result.Evidence(); got != evidence.ID() {
		t.Errorf("result names %s, want %s", got, evidence.ID())
	}

	if got, _ := attribute(t, evidence, AttrMetadataControllerID).Int(); got != 2 {
		t.Errorf("controller id = %d, want 2", got)
	}
	if got, _ := attribute(t, evidence, AttrRequestAPIVersion).Int(); got != 1 {
		t.Errorf("request version = %d, want 1", got)
	}
	if got, _ := attribute(t, evidence, AttrMetadataBrokerCount).Int(); got != 3 {
		t.Errorf("broker count = %d, want 3", got)
	}
}

// TestMetadataRecordsNoClusterOrErrorFacts pins two absences that would each be
// a synthetic fact: a cluster identifier this version never receives, and a
// broker error code this version never carries.
func TestMetadataRecordsNoClusterOrErrorFacts(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})

	evidence := node(t, freeze(t, target.builder), metadataNodeID)

	allowed := map[domain.AttributeKey]bool{
		AttrRequestAPIVersion:            true,
		AttrMetadataControllerID:         true,
		AttrMetadataBrokerCount:          true,
		AttrMetadataAdvertisedEntryCount: true,
		AttrMetadataUnrepresentableCount: true,
	}
	for key := range evidence.Attributes() {
		if !allowed[key] {
			t.Errorf("unexpected attribute %s: this node's vocabulary is closed on purpose", key)
		}
	}
	if _, ok := evidence.Attribute(AttrErrorCode); ok {
		t.Error("a v1 Metadata response has no top-level error code; recording one invents a fact")
	}
	for _, key := range []domain.AttributeKey{
		"kafka.metadata.cluster_id", "kafka.cluster_id", "kafka.metadata.topic_count",
	} {
		if _, ok := evidence.Attribute(key); ok {
			t.Errorf("the exchange records %s", key)
		}
	}
}

// TestMetadataAsksForNoTopicsOnTheWire is the end-to-end half of the request
// decision, seen from the peer.
func TestMetadataAsksForNoTopicsOnTheWire(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})

	topics := target.broker.metadataTopics()
	if len(topics) != 1 {
		t.Fatalf("broker received %d metadata requests, want 1", len(topics))
	}
	if len(topics[0]) != 0 {
		t.Errorf("svcdoctor asked about %v, want no topics", topics[0])
	}

	// Empty is not null. Null at this version means "every topic".
	nulls := target.broker.metadataTopicsWereNull()
	if len(nulls) != 1 || nulls[0] {
		t.Error("the topic list was null, which asks the cluster to describe every topic")
	}

	versions := target.broker.metadataVersions()
	if len(versions) != 1 || versions[0] != 1 {
		t.Errorf("request versions = %v, want [1]", versions)
	}
}

// --- one socket -------------------------------------------------------------

// TestMetadataUsesTheExactAuthenticatedConnection is the invariant of the whole
// vertical slice, now six layers deep: DNS, TCP, TLS, ApiVersions,
// SaslHandshake, SaslAuthenticate and Metadata all describe one socket.
func TestMetadataUsesTheExactAuthenticatedConnection(t *testing.T) {
	target := authenticatedTarget(t)
	measured := target.conn(t).LocalAddr().String()

	result := discover(t, target, MetadataParams{})

	session, ok := result.Session()
	if !ok {
		t.Fatal("a completed exchange returned no session")
	}
	conn, ok := session.TakeConn()
	if !ok {
		t.Fatal("the continued session has no connection to take")
	}
	defer func() { _ = conn.Close() }()

	if got := conn.LocalAddr().String(); got != measured {
		t.Errorf("metadata ran on %s, want the measured socket %s", got, measured)
	}
	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d connections were established, want 1: the adapter must not redial", got)
	}
	if got := target.broker.metadataRequestCount(); got != 1 {
		t.Errorf("broker saw %d metadata requests, want 1", got)
	}
	if got := target.broker.requestCount(); got != 1 {
		t.Errorf("broker saw %d ApiVersions requests, want 1", got)
	}
	if got := target.broker.authRequestCount(); got != 1 {
		t.Errorf("broker saw %d authentications, want 1", got)
	}
}

// TestMetadataSuccessPreservesTheSession: Metadata reads a description and
// advances no protocol state, so the connection is exactly as usable afterwards.
func TestMetadataSuccessPreservesTheSession(t *testing.T) {
	target := authenticatedTarget(t)
	conn := target.conn(t)
	before := target.session

	result := discover(t, target, MetadataParams{})

	if got := conn.closeCount(); got != 0 {
		t.Fatalf("the connection was closed %d times after a successful exchange", got)
	}
	session, ok := result.Session()
	if !ok {
		t.Fatal("no session after a completed exchange")
	}
	if !session.Available() {
		t.Error("the continued session holds no connection")
	}
	if got, want := session.Endpoint(), before.Endpoint(); got != want {
		t.Errorf("endpoint = %q, want %q carried through", got, want)
	}
	if got, want := session.Mechanism(), before.Mechanism(); got != want {
		t.Errorf("mechanism = %q, want %q carried through", got, want)
	}
	if got, want := session.Channel(), before.Channel(); got != want {
		t.Errorf("channel = %s, want %s carried through", got, want)
	}
	if got, want := session.Evidence(), before.Evidence(); got != want {
		t.Errorf("evidence = %s, want the authentication node %s: "+
			"metadata added a fact about the cluster, not about the connection", got, want)
	}
}

// TestMetadataFailureClosesTheConnection is the lifecycle matrix.
func TestMetadataFailureClosesTheConnection(t *testing.T) {
	tests := []struct {
		name    string
		options []brokerOption
		params  MetadataParams
		state   domain.State
		class   domain.FailureClass
	}{
		{
			name:    "peer hangs up",
			options: []brokerOption{withMetadata(peerHangsUp)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolPeerClosed,
		},
		{
			name:    "peer is not kafka",
			options: []brokerOption{withMetadata(peerSpeaksHTTP)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolUnexpectedResponse,
		},
		{
			name:    "undecodable response",
			options: []brokerOption{withMetadata(peerSendsGarbage)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolMalformedResponse,
		},
		{
			name:    "answers another request",
			options: []brokerOption{withMetadata(peerMisscorrelates)},
			state:   domain.StateFail,
			class:   domain.FailureProtocolMalformedResponse,
		},
		{
			name:    "local budget expired",
			options: []brokerOption{withMetadata(peerSaysNothing)},
			params:  MetadataParams{ExchangeTimeout: 50 * time.Millisecond},
			state:   domain.StateUnknown,
			class:   domain.FailureExecLocalTimeout,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := authenticatedTarget(t, test.options...)
			conn := target.conn(t)

			result := discover(t, target, test.params)

			if _, ok := result.Session(); ok {
				t.Error("a failed exchange returned a session")
			}
			if got := conn.closeCount(); got == 0 {
				t.Error("the connection was left open after a failed exchange")
			}
			if len(result.Brokers()) != 0 {
				t.Errorf("a failed exchange discovered %d brokers", len(result.Brokers()))
			}

			evidence := node(t, freeze(t, target.builder), metadataNodeID)
			if evidence.State() != test.state {
				t.Errorf("state = %s, want %s", evidence.State(), test.state)
			}
			if evidence.FailureClass() != test.class {
				t.Errorf("class = %s, want %s", evidence.FailureClass(), test.class)
			}

			// A failed exchange records the request version and nothing it did
			// not learn.
			for _, key := range []domain.AttributeKey{
				AttrMetadataControllerID, AttrMetadataBrokerCount,
				AttrMetadataAdvertisedEntryCount,
			} {
				if _, ok := evidence.Attribute(key); ok {
					t.Errorf("a failed exchange recorded %s", key)
				}
			}
		})
	}
}

func TestMetadataCancellationIsRecordedAsCancellation(t *testing.T) {
	target := authenticatedTarget(t, withMetadata(peerSaysNothing))

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	result, err := Metadata(ctx, target.builder, target.session, MetadataParams{})
	if err != nil {
		t.Fatalf("Metadata: %v", err)
	}
	defer func() { _ = result.Close() }()

	evidence := node(t, freeze(t, target.builder), metadataNodeID)
	if evidence.State() != domain.StateUnknown {
		t.Errorf("state = %s, want UNKNOWN", evidence.State())
	}
	if evidence.FailureClass() != domain.FailureExecCancelled {
		t.Errorf("class = %s, want EXEC_CANCELLED", evidence.FailureClass())
	}
}

func TestMetadataRejectsUnusableInput(t *testing.T) {
	target := authenticatedTarget(t)

	tests := []struct {
		name string
		call func() error
	}{
		{"nil context", func() error {
			//nolint:staticcheck // SA1012: passing a nil context is the defect under test.
			_, err := Metadata(nil, target.builder, target.session, MetadataParams{})
			return err
		}},
		{"nil builder", func() error {
			_, err := Metadata(context.Background(), nil, target.session, MetadataParams{})
			return err
		}},
		{"nil session", func() error {
			_, err := Metadata(context.Background(), target.builder, nil, MetadataParams{})
			return err
		}},
		{"negative timeout", func() error {
			_, err := Metadata(context.Background(), target.builder, target.session,
				MetadataParams{ExchangeTimeout: -time.Second})
			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("error = %v, want one wrapping ErrInvalidInput", err)
			}
			if got := target.broker.metadataRequestCount(); got != 0 {
				t.Errorf("broker received %d metadata requests, want 0", got)
			}
		})
	}
}

// --- topology ---------------------------------------------------------------

// discoveredRefs returns the subject reference of every advertisement node, so a
// test can assert on the topology the graph actually holds.
func discoveredRefs(t *testing.T, graph domain.Graph) []string {
	t.Helper()

	var refs []string
	for _, evidence := range graph.Nodes() {
		if evidence.Step() == StepBrokerAdvertised {
			refs = append(refs, evidence.Subject().Ref())
		}
	}
	sort.Strings(refs)
	return refs
}

func TestOneBrokerIsDiscovered(t *testing.T) {
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(1, "broker-1.internal", 9093)))

	result := discover(t, target, MetadataParams{})

	brokers := result.Brokers()
	if len(brokers) != 1 {
		t.Fatalf("brokers = %d, want 1", len(brokers))
	}
	if got := brokers[0].NodeID(); got != 1 {
		t.Errorf("node id = %d, want 1", got)
	}
	endpoint, ok := brokers[0].Endpoint()
	if !ok {
		t.Fatal("a well-formed advertisement produced no usable endpoint")
	}
	if endpoint != "broker-1.internal:9093" {
		t.Errorf("endpoint = %q, want broker-1.internal:9093", endpoint)
	}

	evidence := node(t, freeze(t, target.builder),
		brokerNodeID(1, "broker-1.internal:9093"))
	if evidence.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS", evidence.State())
	}
	if got, want := evidence.Layer(), domain.LayerTopology; got != want {
		t.Errorf("layer = %s, want %s", got, want)
	}
	if got, _ := attribute(t, evidence, AttrBrokerNodeID).Int(); got != 1 {
		t.Errorf("node id attribute = %d, want 1", got)
	}
	host, ok := attribute(t, evidence, AttrBrokerAdvertisedHost).Host()
	if !ok {
		t.Fatal("the advertised host is not a declared identity value")
	}
	if host != "broker-1.internal" {
		t.Errorf("advertised host = %q, want broker-1.internal", host)
	}
	if got, _ := attribute(t, evidence, AttrBrokerAdvertisedPort).Int(); got != 9093 {
		t.Errorf("advertised port = %d, want 9093", got)
	}
}

func TestMultipleBrokersAreDiscovered(t *testing.T) {
	target := authenticatedTarget(t)
	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 3 {
		t.Fatalf("brokers = %d, want 3", got)
	}

	refs := discoveredRefs(t, freeze(t, target.builder))
	want := []string{
		"broker-1.internal:9093", "broker-2.internal:9093", "broker-3.internal:9093",
	}
	if len(refs) != len(want) {
		t.Fatalf("advertisement nodes = %v, want %v", refs, want)
	}
	for i := range want {
		if refs[i] != want[i] {
			t.Errorf("advertisement %d = %q, want %q", i, refs[i], want[i])
		}
	}
}

// TestIdenticalEntriesCollapseVisibly is the fact-dedup case: a byte-identical
// repetition is one fact, and the collapse is reported rather than silent.
func TestIdenticalEntriesCollapseVisibly(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(1, "broker-1.internal", 9093),
	))

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 1 {
		t.Fatalf("brokers = %d, want 1: identical entries are one fact", got)
	}

	evidence := node(t, freeze(t, target.builder), metadataNodeID)
	if got, _ := attribute(t, evidence, AttrMetadataBrokerCount).Int(); got != 1 {
		t.Errorf("broker count = %d, want 1", got)
	}
	if got, _ := attribute(t, evidence, AttrMetadataAdvertisedEntryCount).Int(); got != 2 {
		t.Errorf("advertised entry count = %d, want 2: the collapse must stay visible", got)
	}
}

// TestOneNodeIDAtTwoEndpointsStaysTwoFacts: a broker identity that appears at
// two addresses is a rolling reconfiguration or a listener mistake. Merging on
// node identifier would erase the second address.
func TestOneNodeIDAtTwoEndpointsStaysTwoFacts(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(1, "broker-1-alt.internal", 9094),
	))

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 2 {
		t.Fatalf("brokers = %d, want 2: one node id at two endpoints is two facts", got)
	}
	for _, broker := range result.Brokers() {
		if broker.NodeID() != 1 {
			t.Errorf("node id = %d, want 1 on both", broker.NodeID())
		}
	}

	graph := freeze(t, target.builder)
	refs := discoveredRefs(t, graph)
	if len(refs) != 2 || refs[0] == refs[1] {
		t.Fatalf("advertisement nodes = %v, want two distinct ones", refs)
	}
	// Both identifiers exist, which is what proves the scheme stayed injective.
	node(t, graph, brokerNodeID(1, "broker-1.internal:9093"))
	node(t, graph, brokerNodeID(1, "broker-1-alt.internal:9094"))
}

// TestTwoNodeIDsAtOneEndpointStayTwoFacts: two brokers claiming one address is a
// misconfiguration that routes clients to the wrong broker. Merging on
// host:port would erase one of the claimants.
func TestTwoNodeIDsAtOneEndpointStayTwoFacts(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-shared.internal", 9093),
		advertisedBroker(2, "broker-shared.internal", 9093),
	))

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 2 {
		t.Fatalf("brokers = %d, want 2: two node ids at one endpoint is two facts", got)
	}

	ids := map[int32]bool{}
	for _, broker := range result.Brokers() {
		ids[broker.NodeID()] = true
		endpoint, ok := broker.Endpoint()
		if !ok || endpoint != "broker-shared.internal:9093" {
			t.Errorf("endpoint = %q (%v), want the shared one", endpoint, ok)
		}
	}
	if !ids[1] || !ids[2] {
		t.Errorf("node ids = %v, want both 1 and 2", ids)
	}

	graph := freeze(t, target.builder)
	node(t, graph, brokerNodeID(1, "broker-shared.internal:9093"))
	node(t, graph, brokerNodeID(2, "broker-shared.internal:9093"))
}

// TestAdvertisedHostNormalization covers the rules that are contractually
// justified and no others.
func TestAdvertisedHostNormalization(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		port         int32
		wantEndpoint string
	}{
		{"lower case name", "broker.internal", 9093, "broker.internal:9093"},
		{"upper case name", "BROKER.INTERNAL", 9093, "broker.internal:9093"},
		{"trailing dot", "broker.internal.", 9093, "broker.internal:9093"},
		{"ipv4 literal", "10.9.8.7", 9093, "10.9.8.7:9093"},
		{"ipv6 literal", "2001:db8::1", 9093, "[2001:db8::1]:9093"},
		{"ipv6 long form", "2001:0db8:0000:0000:0000:0000:0000:0001", 9093, "[2001:db8::1]:9093"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := authenticatedTarget(t,
				withAdvertisedBrokers(advertisedBroker(1, test.host, test.port)))

			result := discover(t, target, MetadataParams{})
			brokers := result.Brokers()
			if len(brokers) != 1 {
				t.Fatalf("brokers = %d, want 1", len(brokers))
			}
			endpoint, ok := brokers[0].Endpoint()
			if !ok {
				t.Fatal("a well-formed advertisement produced no usable endpoint")
			}
			if endpoint != test.wantEndpoint {
				t.Errorf("endpoint = %q, want %q", endpoint, test.wantEndpoint)
			}
		})
	}
}

// TestNormalizationDoesNotResolve: a hostname stays a hostname. Turning it into
// an address here would make a DNS answer part of a topology fact, and measuring
// that answer is the whole point of the reachability phase that follows.
func TestNormalizationDoesNotResolve(t *testing.T) {
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(1, "localhost", 9093)))

	result := discover(t, target, MetadataParams{})
	brokers := result.Brokers()
	if len(brokers) != 1 {
		t.Fatalf("brokers = %d, want 1", len(brokers))
	}
	if got := brokers[0].Host(); got != "localhost" {
		t.Errorf("host = %q, want the advertised name unresolved", got)
	}
}

// TestUnusableAdvertisementsBecomeEvidence: a cluster advertising something no
// client can act on is precisely the misconfiguration somebody runs a diagnostic
// tool to find, so it is recorded rather than dropped.
func TestUnusableAdvertisementsBecomeEvidence(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		port    int32
		wantRef string
	}{
		{"empty host", "", 9093, ":9093"},
		{"port zero", "broker.internal", 0, "broker.internal:0"},
		{"negative port", "broker.internal", -1, "broker.internal:-1"},
		{"port beyond range", "broker.internal", 70000, "broker.internal:70000"},
		{"empty host and port", "", 0, ":0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := authenticatedTarget(t,
				withAdvertisedBrokers(advertisedBroker(7, test.host, test.port)))

			result := discover(t, target, MetadataParams{})

			brokers := result.Brokers()
			if len(brokers) != 1 {
				t.Fatalf("brokers = %d, want 1: an unusable entry is still a fact", len(brokers))
			}
			if endpoint, ok := brokers[0].Endpoint(); ok {
				t.Errorf("endpoint = %q, want none: nothing usable was advertised", endpoint)
			}
			if got := brokers[0].NodeID(); got != 7 {
				t.Errorf("node id = %d, want 7 preserved", got)
			}

			evidence := node(t, freeze(t, target.builder), brokerNodeID(7, test.wantRef))
			if evidence.State() != domain.StateFail {
				t.Errorf("state = %s, want FAIL", evidence.State())
			}
			if evidence.FailureClass() != domain.FailureProtocolUnexpectedResponse {
				t.Errorf("class = %s, want PROTOCOL_UNEXPECTED_RESPONSE", evidence.FailureClass())
			}
			if got, _ := attribute(t, evidence, AttrBrokerAdvertisedPort).Int(); got != int64(test.port) {
				t.Errorf("advertised port = %d, want %d exactly as it arrived", got, test.port)
			}
		})
	}
}

// TestUnrepresentableEntriesAreCounted closes the one hole through which an
// entry could vanish without trace.
func TestUnrepresentableEntriesAreCounted(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker\x00two.internal", 9093),
	))

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 1 {
		t.Fatalf("brokers = %d, want 1", got)
	}

	evidence := node(t, freeze(t, target.builder), metadataNodeID)
	if got, _ := attribute(t, evidence, AttrMetadataAdvertisedEntryCount).Int(); got != 2 {
		t.Errorf("advertised entry count = %d, want 2", got)
	}
	if got, _ := attribute(t, evidence, AttrMetadataUnrepresentableCount).Int(); got != 1 {
		t.Errorf("unrepresentable count = %d, want 1: nothing may vanish silently", got)
	}
}

// TestEmptyBrokerListIsAFact: a cluster that advertised nothing said something.
func TestEmptyBrokerListIsAFact(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers())

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 0 {
		t.Fatalf("brokers = %d, want 0", got)
	}
	evidence := node(t, freeze(t, target.builder), metadataNodeID)
	if evidence.State() != domain.StatePass {
		t.Errorf("state = %s, want PASS: the exchange completed", evidence.State())
	}
	if got, _ := attribute(t, evidence, AttrMetadataBrokerCount).Int(); got != 0 {
		t.Errorf("broker count = %d, want 0 recorded as a statement", got)
	}
}
