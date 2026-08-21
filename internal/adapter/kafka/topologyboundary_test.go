package kafka

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests guard the boundaries this phase exists to keep: derivation is
// recorded and provenance is not claimed, discovery stays discovery, and nothing
// a cluster advertised becomes somewhere svcdoctor connects or sends a
// credential.

// --- graph relationships ----------------------------------------------------

// TestMetadataParentsToTheAuthentication pins the edge to the step whose live
// connection this exchange continues.
func TestMetadataParentsToTheAuthentication(t *testing.T) {
	target := authenticatedTarget(t)
	authID := target.session.Evidence()

	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	parents := graph.Parents(domain.EvidenceID(metadataNodeID))
	if len(parents) != 1 {
		t.Fatalf("parents = %v, want exactly one", parents)
	}
	if parents[0] != authID {
		t.Errorf("parent = %s, want the authentication node %s", parents[0], authID)
	}
	if got := node(t, graph, parents[0].String()).Step(); got != StepSASLAuthenticate {
		t.Errorf("parent step = %s, want %s", got, StepSASLAuthenticate)
	}
}

// TestAdvertisementParentsToTheExchangeThatCarriedIt pins the derivation edge.
//
// It makes "which Metadata response produced this fact?" answerable by walking
// edges rather than by parsing an attribute. It does *not* make "how did this
// endpoint enter the run?" answerable — see
// TestBootstrapEndpointCanAlsoBeAdvertised for why those are different
// questions.
func TestAdvertisementParentsToTheExchangeThatCarriedIt(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	found := 0
	for _, evidence := range graph.Nodes() {
		if evidence.Step() != StepBrokerAdvertised {
			continue
		}
		found++

		parents := graph.Parents(evidence.ID())
		if len(parents) != 1 {
			t.Errorf("%s has parents %v, want exactly the exchange", evidence.ID(), parents)
			continue
		}
		if parents[0] != domain.EvidenceID(metadataNodeID) {
			t.Errorf("%s parents to %s, want the metadata exchange", evidence.ID(), parents[0])
		}
	}
	if found != 3 {
		t.Fatalf("advertisement nodes = %d, want 3", found)
	}
}

// TestDerivationChainIsWalkableToTheTransport: the chain from an advertisement
// back through the exchange, the authentication and the protocol steps to the
// transport that measured the connection is intact.
//
// This is derivation — what produced what — and it is what a later reachability
// probe follows. It is not a statement about how any endpoint entered the run.
func TestDerivationChainIsWalkableToTheTransport(t *testing.T) {
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(1, "broker-1.internal", 9093)))
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	current := domain.EvidenceID(brokerNodeID(1, "broker-1.internal:9093"))
	want := []domain.Step{
		StepMetadata, StepSASLAuthenticate, StepSASLHandshake, StepAPIVersions,
	}
	for _, step := range want {
		parents := graph.Parents(current)
		if len(parents) != 1 {
			t.Fatalf("%s has %d parents, want 1", current, len(parents))
		}
		evidence, ok := graph.Node(parents[0])
		if !ok {
			t.Fatalf("%s is not in the graph", parents[0])
		}
		if evidence.Step() != step {
			t.Fatalf("step = %s, want %s", evidence.Step(), step)
		}
		current = parents[0]
	}

	// And it keeps going down to the transport that measured the connection.
	if parents := graph.Parents(current); len(parents) != 1 {
		t.Errorf("the chain stops at %s; derivation must reach the transport", current)
	}
}

// TestGraphHasNoDanglingReferences: every edge resolves.
func TestGraphHasNoDanglingReferences(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	for _, evidence := range graph.Nodes() {
		for _, parent := range graph.Parents(evidence.ID()) {
			if _, ok := graph.Node(parent); !ok {
				t.Errorf("%s parents to %s, which is not in the graph", evidence.ID(), parent)
			}
		}
		for _, blocker := range graph.BlockedBy(evidence.ID()) {
			if _, ok := graph.Node(blocker); !ok {
				t.Errorf("%s is blocked by %s, which is not in the graph", evidence.ID(), blocker)
			}
		}
	}
}

// TestNoOriginIsRecorded pins the decision that no node claims a provenance.
//
// An Origin field would be a record of how a subject entered the run, and
// nothing in this phase has one to write: the decisive case is that a bootstrap
// endpoint and a discovered broker can be the same machine, so origin is not
// even a function of the subject. It is not inferred from the edges either —
// REPORT_SCHEMA.md forbids that explicitly. See ADR 0031 section 6.
func TestNoOriginIsRecorded(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	for _, evidence := range graph.Nodes() {
		for key := range evidence.Attributes() {
			switch key {
			case "origin", "kafka.origin", "kafka.broker.origin",
				"evidence.origin", "subject.origin", "kafka.broker.discovered":
				t.Errorf("%s records %s: this phase records derivation, not provenance",
					evidence.ID(), key)
			}
		}
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if strings.Contains(string(encoded), "\"origin\"") {
			t.Errorf("%s serializes an origin field", evidence.ID())
		}
	}

	// And the domain model still has no field for one.
	var value any = domain.Evidence{}
	if _, ok := value.(interface{ Origin() string }); ok {
		t.Error("domain.Evidence grew an Origin accessor")
	}
}

// TestGraphBuilderStaysDumb: this phase added topology, and the builder still
// stores structure without deciding it.
func TestGraphBuilderStaysDumb(t *testing.T) {
	var value any = domain.NewGraphBuilder()

	for _, probe := range []struct {
		name string
		is   bool
	}{
		{"Visited", func() bool { _, ok := value.(interface{ Visited(domain.EvidenceID) bool }); return ok }()},
		{"Depth", func() bool { _, ok := value.(interface{ Depth() int }); return ok }()},
		{"Dedup", func() bool { _, ok := value.(interface{ Dedup() }); return ok }()},
		{"Expand", func() bool { _, ok := value.(interface{ Expand() error }); return ok }()},
		{"Node lookup", func() bool {
			_, ok := value.(interface {
				Node(domain.EvidenceID) (domain.Evidence, bool)
			})
			return ok
		}()},
	} {
		if probe.is {
			t.Errorf("GraphBuilder grew %s: it stores structure and does not decide it (ADR 0013)",
				probe.name)
		}
	}
}

// --- execution boundary -----------------------------------------------------

// TestMetadataProbesNoDiscoveredBroker is the scope statement of the phase.
//
// Three brokers are advertised at addresses that do not exist. If anything tried
// to reach them, the connection count would rise and the run would take a
// dial timeout. Both stay flat.
func TestMetadataProbesNoDiscoveredBroker(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-1.invalid", 9093),
		advertisedBroker(2, "broker-2.invalid", 9093),
		advertisedBroker(3, "203.0.113.9", 9093),
	))

	result := discover(t, target, MetadataParams{})

	if got := len(result.Brokers()); got != 3 {
		t.Fatalf("brokers = %d, want 3 recorded", got)
	}
	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d connections exist, want 1: discovery must not dial what it discovers", got)
	}

	// No transport evidence exists for any discovered endpoint.
	graph := freeze(t, target.builder)
	for _, evidence := range graph.Nodes() {
		switch evidence.Layer() {
		case domain.LayerDNS, domain.LayerTCP, domain.LayerTLS:
			if strings.Contains(evidence.Subject().Ref(), "broker-") ||
				strings.Contains(evidence.Subject().Ref(), "203.0.113.9") {
				t.Errorf("%s: a discovered broker was probed", evidence.ID())
			}
		}
	}
}

// TestMetadataSendsNoCredentialAnywhere is the hard security boundary.
//
// A credential authorized for the bootstrap endpoint must never reach a broker
// merely because the cluster advertised it. This phase has no parameter a
// credential could be put into, which is what makes the guarantee structural.
func TestMetadataSendsNoCredentialAnywhere(t *testing.T) {
	signature := reflect.TypeOf(Metadata)
	credentialType := reflect.TypeOf(security.Credential{})
	policyType := reflect.TypeOf(security.ForwardingPolicy(0))

	for i := range signature.NumIn() {
		switch signature.In(i) {
		case credentialType:
			t.Error("Metadata takes a credential; discovery must not be able to present one")
		case policyType:
			t.Error("Metadata takes a forwarding policy; this phase does not forward")
		}
	}

	var params any = MetadataParams{}
	if _, ok := params.(interface{ Credential() security.Credential }); ok {
		t.Error("MetadataParams exposes a credential")
	}

	// And the result hands back no credential-bearing handle for a discovered
	// broker either.
	var broker any = DiscoveredBroker{}
	if _, ok := broker.(interface{ Credential() security.Credential }); ok {
		t.Error("a discovered broker carries a credential")
	}
	if _, ok := broker.(interface{ SecurityEndpoint() security.Endpoint }); ok {
		t.Error("a discovered broker hands out a security.Endpoint, " +
			"which would put credential forwarding one call away")
	}
}

// TestDiscoveredBrokerIsNotACredentialEndpoint: the normalization rules match
// security.Endpoint's, and the type deliberately does not.
//
// Reusing that type would mean a caller who merely wanted somewhere to connect
// could pass a discovered broker straight to SecretFor. Same rules, different
// type, no conversion offered.
func TestDiscoveredBrokerIsNotACredentialEndpoint(t *testing.T) {
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(1, "BROKER-1.Internal.", 9093)))

	result := discover(t, target, MetadataParams{})
	brokers := result.Brokers()
	if len(brokers) != 1 {
		t.Fatalf("brokers = %d, want 1", len(brokers))
	}

	endpoint, ok := brokers[0].Endpoint()
	if !ok {
		t.Fatal("no usable endpoint")
	}
	if endpoint != "broker-1.internal:9093" {
		t.Errorf("endpoint = %q, want the security.Endpoint normalization rules applied", endpoint)
	}

	// The rules agree; the types do not.
	if reflect.TypeOf(brokers[0].Host()).Kind() != reflect.String {
		t.Error("Host is not a plain string")
	}
	endpointMethod, exists := reflect.TypeOf(brokers[0]).MethodByName("Endpoint")
	if !exists {
		t.Fatal("DiscoveredBroker has no Endpoint method")
	}
	if endpointMethod.Type.Out(0) == reflect.TypeOf(security.Endpoint{}) {
		t.Error("Endpoint returns a security.Endpoint, which is the credential-binding type")
	}
}

// TestMetadataIsNotRecursive: one exchange, one hop, no re-entry. There is no
// traversal, which is why there is no depth limit to tune.
func TestMetadataIsNotRecursive(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})

	if got := target.broker.metadataRequestCount(); got != 1 {
		t.Errorf("broker saw %d metadata requests, want exactly 1", got)
	}

	var params any = MetadataParams{}
	for _, probe := range []struct {
		name string
		is   bool
	}{
		{"MaxDepth", func() bool { _, ok := params.(interface{ MaxDepth() int }); return ok }()},
		{"Recursive", func() bool { _, ok := params.(interface{ Recursive() bool }); return ok }()},
		{"Expand", func() bool { _, ok := params.(interface{ Expand() bool }); return ok }()},
	} {
		if probe.is {
			t.Errorf("MetadataParams exposes %s: there is no traversal to bound", probe.name)
		}
	}
}

// TestMetadataDoesNotRetry: one request per call, whatever the peer did.
func TestMetadataDoesNotRetry(t *testing.T) {
	target := authenticatedTarget(t, withMetadata(peerSendsGarbage))
	discover(t, target, MetadataParams{})

	if got := target.broker.metadataRequestCount(); got != 1 {
		t.Errorf("broker saw %d metadata requests after a bad response, want 1", got)
	}
	if got := len(target.registry.all()); got != 1 {
		t.Errorf("%d connections exist, want 1: a failure must not redial", got)
	}
}

// --- identity ---------------------------------------------------------------

// TestBrokerIdentityAndEndpointIdentityAreSeparate states the distinction the
// whole topology model rests on.
func TestBrokerIdentityAndEndpointIdentityAreSeparate(t *testing.T) {
	// The host deliberately contains none of the node identifier's digits, so
	// "the endpoint does not embed the identity" is a real check rather than a
	// coincidence of naming.
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(42, "broker-primary.internal", 9093)))

	result := discover(t, target, MetadataParams{})
	broker := result.Brokers()[0]

	// The logical identity is an integer and is never a connection target.
	if reflect.TypeOf(broker.NodeID()).Kind() != reflect.Int32 {
		t.Errorf("NodeID is %s, want a numeric identity", reflect.TypeOf(broker.NodeID()))
	}
	endpoint, ok := broker.Endpoint()
	if !ok {
		t.Fatal("no endpoint")
	}
	if strings.Contains(endpoint, "42") {
		t.Error("the endpoint embeds the node identifier; the two identities are not separate")
	}

	// The evidence records both, separately.
	evidence := node(t, freeze(t, target.builder), brokerNodeID(42, "broker-primary.internal:9093"))
	if _, ok := evidence.Attribute(AttrBrokerNodeID); !ok {
		t.Error("the node identifier is not recorded")
	}
	if _, ok := evidence.Attribute(AttrBrokerAdvertisedHost); !ok {
		t.Error("the advertised host is not recorded")
	}
}

// TestEvidenceIDsStayInjectiveAcrossConflicts is the identifier half of the
// conflict guarantee: every case that must stay two facts produces two
// identifiers.
func TestEvidenceIDsStayInjectiveAcrossConflicts(t *testing.T) {
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-a.internal", 9093),
		advertisedBroker(1, "broker-b.internal", 9093),
		advertisedBroker(2, "broker-a.internal", 9093),
		advertisedBroker(2, "broker-b.internal", 9093),
	))

	result := discover(t, target, MetadataParams{})
	if got := len(result.Brokers()); got != 4 {
		t.Fatalf("brokers = %d, want 4 distinct facts", got)
	}

	graph := freeze(t, target.builder)
	seen := map[domain.EvidenceID]struct{}{}
	for _, evidence := range graph.Nodes() {
		if evidence.Step() != StepBrokerAdvertised {
			continue
		}
		if _, duplicate := seen[evidence.ID()]; duplicate {
			t.Fatalf("identifier %s appears twice", evidence.ID())
		}
		seen[evidence.ID()] = struct{}{}
	}
	if len(seen) != 4 {
		t.Errorf("advertisement nodes = %d, want 4", len(seen))
	}

	for _, nodeID := range []int32{1, 2} {
		for _, host := range []string{"broker-a.internal", "broker-b.internal"} {
			node(t, graph, brokerNodeID(nodeID, host+":9093"))
		}
	}
}

// TestNodeIDIsNotConfusedWithEndpointInTheIdentifier: the components are
// escaped and ordered, so a node identifier cannot be read as part of a host.
func TestNodeIDIsNotConfusedWithEndpointInTheIdentifier(t *testing.T) {
	// A host that looks like a node identifier followed by an endpoint.
	target := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "2", 9093),
		advertisedBroker(12, "broker.internal", 9093),
	))

	result := discover(t, target, MetadataParams{})
	if got := len(result.Brokers()); got != 2 {
		t.Fatalf("brokers = %d, want 2", got)
	}

	graph := freeze(t, target.builder)
	node(t, graph, brokerNodeID(1, "2:9093"))
	node(t, graph, brokerNodeID(12, "broker.internal:9093"))
}

// --- determinism ------------------------------------------------------------

// TestBrokerOrderPermutationProducesIdenticalEvidence: the same facts in a
// different order must produce the same graph, because a report is byte-stable
// for the same content.
func TestBrokerOrderPermutationProducesIdenticalEvidence(t *testing.T) {
	first := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
		advertisedBroker(3, "broker-3.internal", 9093),
	))
	discover(t, first, MetadataParams{})

	second := authenticatedTarget(t, withAdvertisedBrokers(
		advertisedBroker(3, "broker-3.internal", 9093),
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	))
	discover(t, second, MetadataParams{})

	firstIDs := topologyIdentifiers(t, freeze(t, first.builder))
	secondIDs := topologyIdentifiers(t, freeze(t, second.builder))

	if len(firstIDs) != len(secondIDs) {
		t.Fatalf("identifier counts differ: %v vs %v", firstIDs, secondIDs)
	}
	for i := range firstIDs {
		if firstIDs[i] != secondIDs[i] {
			t.Errorf("identifier %d differs: %q vs %q", i, firstIDs[i], secondIDs[i])
		}
	}
}

// topologyIdentifiers returns every topology node identifier, in the graph's own
// canonical order.
func topologyIdentifiers(t *testing.T, graph domain.Graph) []string {
	t.Helper()

	var ids []string
	for _, evidence := range graph.Nodes() {
		if evidence.Layer() == domain.LayerTopology {
			ids = append(ids, evidence.ID().String())
		}
	}
	return ids
}

// TestRepeatedEncodingIsStable: encoding one node twice yields identical bytes.
func TestRepeatedEncodingIsStable(t *testing.T) {
	target := authenticatedTarget(t)
	discover(t, target, MetadataParams{})
	graph := freeze(t, target.builder)

	for _, evidence := range graph.Nodes() {
		if evidence.Layer() != domain.LayerTopology {
			continue
		}
		first, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		second, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		if string(first) != string(second) {
			t.Errorf("%s encodes differently on repeat:\n%s\n%s", evidence.ID(), first, second)
		}
	}
}

// TestControllerIDDefaultIsRecordedAsAStatement: -1 means the responding broker
// knows of no controller, which is a fact rather than a missing value.
func TestControllerIDDefaultIsRecordedAsAStatement(t *testing.T) {
	target := authenticatedTarget(t, withControllerID(-1))
	discover(t, target, MetadataParams{})

	evidence := node(t, freeze(t, target.builder), metadataNodeID)
	value, ok := evidence.Attribute(AttrMetadataControllerID)
	if !ok {
		t.Fatal("the controller identifier was not recorded")
	}
	if got, _ := value.Int(); got != -1 {
		t.Errorf("controller id = %d, want -1 recorded as the statement it is", got)
	}
}

// TestSecondMetadataOnOnePathIsRefusedNotMerged pins a limitation rather than a
// feature, so that it is known instead of discovered.
//
// An identifier is derived from the step and its scope, so two Metadata
// exchanges over one endpoint and address in one run mint the same identifier.
// The graph rejects the duplicate outright — it does not merge, and it does not
// overwrite — so the second call fails loudly and the first call's evidence is
// left intact.
//
// That is the retry case ADR 0019 left open, arriving here for the first time.
// It is not solved: retry is execution policy, no layer owns it, and inventing
// an attempt counter in this phase would settle that question as a side effect
// of a topology exchange. See ADR 0031.
func TestSecondMetadataOnOnePathIsRefusedNotMerged(t *testing.T) {
	target := authenticatedTarget(t)

	first := discover(t, target, MetadataParams{})
	session, ok := first.Session()
	if !ok {
		t.Fatal("the first exchange returned no session")
	}

	_, err := Metadata(t.Context(), target.builder, session, MetadataParams{})
	if err == nil {
		t.Fatal("a second exchange on one path was accepted; " +
			"its evidence would have collided with the first")
	}
	if !errors.Is(err, domain.ErrInvalidGraph) {
		t.Errorf("error = %v, want one wrapping ErrInvalidGraph", err)
	}

	// The first exchange's evidence is untouched, and the graph still freezes.
	graph := freeze(t, target.builder)
	evidence := node(t, graph, metadataNodeID)
	if evidence.State() != domain.StatePass {
		t.Errorf("the first exchange's node was disturbed: state = %s", evidence.State())
	}
	if got, _ := attribute(t, evidence, AttrMetadataBrokerCount).Int(); got != 3 {
		t.Errorf("broker count = %d, want the first exchange's 3", got)
	}
}

// TestBootstrapEndpointCanAlsoBeAdvertised is the case that decides what a
// parent edge is allowed to mean.
//
// The cluster advertises the very endpoint the operator supplied — routine for a
// single-broker cluster, and common wherever the bootstrap name is also a
// broker's advertised listener. The run then contains one normalized
// host:port occupying two roles at once.
//
// What the graph proves and what it does not:
//
//   - **It proves derivation.** The advertisement node was produced by that
//     Metadata exchange, and its parent edge records exactly that.
//   - **It does not prove how the endpoint entered the run.** The same
//     host:port is also the bootstrap target, reached by nodes that predate the
//     exchange and derive from a DNS lookup instead. Nothing in the graph ranks
//     those two roles, and nothing should: they are both true.
//
// So `Origin` cannot be read off graph shape, exactly as REPORT_SCHEMA.md warns.
// Derivation is structural; provenance is not, and stays deferred. See ADR 0031.
func TestBootstrapEndpointCanAlsoBeAdvertised(t *testing.T) {
	// authHost:9092 is the bootstrap target; the cluster advertises it back.
	target := authenticatedTarget(t,
		withAdvertisedBrokers(advertisedBroker(1, authHost, 9092)))

	result := discover(t, target, MetadataParams{})
	brokers := result.Brokers()
	if len(brokers) != 1 {
		t.Fatalf("brokers = %d, want 1", len(brokers))
	}

	advertisedEndpoint, ok := brokers[0].Endpoint()
	if !ok {
		t.Fatal("no usable endpoint")
	}
	if advertisedEndpoint != authEndpoint {
		t.Fatalf("advertised endpoint = %q, want the bootstrap endpoint %q: "+
			"the collision this test needs did not occur", advertisedEndpoint, authEndpoint)
	}

	graph := freeze(t, target.builder)

	// 1. Derivation is preserved: the advertisement came from the exchange.
	advertisementID := domain.EvidenceID(brokerNodeID(1, authEndpoint))
	node(t, graph, advertisementID.String())
	parents := graph.Parents(advertisementID)
	if len(parents) != 1 || parents[0] != domain.EvidenceID(metadataNodeID) {
		t.Fatalf("advertisement parents = %v, want the metadata exchange", parents)
	}

	// 2. The same endpoint is simultaneously the bootstrap target, reached by
	//    nodes that derive from the lookup rather than from the exchange.
	bootstrapNodes := 0
	for _, evidence := range graph.Nodes() {
		if evidence.Step() != StepAPIVersions && evidence.Step() != domain.Step("tcp.connect") {
			continue
		}
		bootstrapNodes++
		for _, parent := range graph.Parents(evidence.ID()) {
			if parent == domain.EvidenceID(metadataNodeID) {
				t.Errorf("%s derives from the metadata exchange; "+
					"the bootstrap path must predate discovery", evidence.ID())
			}
		}
	}
	if bootstrapNodes == 0 {
		t.Fatal("no bootstrap-path nodes found for the shared endpoint")
	}

	// 3. Nothing in the graph says which role the endpoint entered the run by,
	//    and nothing records an origin. That question has no answer here, which
	//    is why it stays deferred rather than being inferred.
	for _, evidence := range graph.Nodes() {
		for key := range evidence.Attributes() {
			switch key {
			case "origin", "kafka.origin", "kafka.broker.origin",
				"kafka.broker.discovered", "kafka.broker.is_bootstrap":
				t.Errorf("%s records %s: no node may claim how an endpoint entered the run",
					evidence.ID(), key)
			}
		}
	}
}
