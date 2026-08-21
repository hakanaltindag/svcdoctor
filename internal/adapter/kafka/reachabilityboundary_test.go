package kafka

import (
	"crypto/sha256"
	"encoding/hex"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
	"github.com/hakanaltindag/svcdoctor/internal/security"
)

// These tests guard the boundaries the phase exists to keep: it measures
// transport and stops, it carries no credential, it claims no provenance, and it
// reaches no conclusion about what it measured.

// --- no credential ----------------------------------------------------------

// TestReachabilityHasNoCredentialSurface is the hard security boundary.
//
// A credential authorized for the bootstrap endpoint must never reach a broker
// merely because the cluster advertised it. The guarantee is structural: there
// is no parameter, field or accessor in this phase that a credential, a secret,
// an identity, a mechanism or an authenticated session could occupy.
func TestReachabilityHasNoCredentialSurface(t *testing.T) {
	forbidden := map[reflect.Type]string{
		reflect.TypeOf(security.Credential{}):        "a credential",
		reflect.TypeOf(security.Secret{}):            "a secret",
		reflect.TypeOf(security.Endpoint{}):          "a credential-binding endpoint",
		reflect.TypeOf(security.ForwardingPolicy(0)): "a forwarding policy",
		reflect.TypeOf(&AuthenticatedSession{}):      "an authenticated session",
		reflect.TypeOf(&HandshakeSession{}):          "a post-handshake session",
		reflect.TypeOf(&Session{}):                   "a protocol session",
	}

	signature := reflect.TypeOf(MeasureAdvertised)
	for i := range signature.NumIn() {
		if what, banned := forbidden[signature.In(i)]; banned {
			t.Errorf("MeasureAdvertised takes %s in parameter %d", what, i)
		}
	}

	plan := reflect.TypeOf(TransportPlan{})
	for i := range plan.NumField() {
		field := plan.Field(i)
		if what, banned := forbidden[field.Type]; banned {
			t.Errorf("TransportPlan.%s is %s", field.Name, what)
		}
	}

	// And no accessor smuggles one back out.
	var value any = &MeasurementResult{}
	for _, probe := range []struct {
		name string
		is   bool
	}{
		{"Credential", func() bool {
			_, ok := value.(interface{ Credential() security.Credential })
			return ok
		}()},
		{"Session", func() bool {
			_, ok := value.(interface {
				Session() (*AuthenticatedSession, bool)
			})
			return ok
		}()},
	} {
		if probe.is {
			t.Errorf("MeasurementResult exposes %s", probe.name)
		}
	}
}

// TestTransportPlanNamesNoSASLOrIdentityField reads the plan's field names, so a
// future field called Identity or Mechanism fails here rather than in review.
func TestTransportPlanNamesNoSASLOrIdentityField(t *testing.T) {
	plan := reflect.TypeOf(TransportPlan{})
	for i := range plan.NumField() {
		name := strings.ToLower(plan.Field(i).Name)
		for _, banned := range []string{
			"credential", "secret", "password", "token", "identity",
			"principal", "sasl", "mechanism", "auth",
		} {
			if strings.Contains(name, banned) {
				t.Errorf("TransportPlan.%s names %q: this phase transmits no credential",
					plan.Field(i).Name, banned)
			}
		}
	}
}

// TestReachabilityImportsNoProtocolOrCredentialPackage.
//
// The one-hop boundary is easiest to keep when the tools to cross it are not in
// the file. Reachability drives generic transport and nothing else, so it
// imports neither the Kafka wire package nor the Kafka protocol library nor
// internal/security — and reading the imports is how that stays true.
func TestReachabilityImportsNoProtocolOrCredentialPackage(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "reachability.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing reachability.go: %v", err)
	}

	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		switch {
		case strings.HasSuffix(path, "/adapter/kafka/wire"):
			t.Errorf("reachability.go imports %s: no Kafka protocol client belongs in the "+
				"reachability path", path)
		case strings.Contains(path, "franz-go"):
			t.Errorf("reachability.go imports %s: this phase speaks no Kafka", path)
		case path == "github.com/hakanaltindag/svcdoctor/internal/security":
			t.Errorf("reachability.go imports %s: this phase handles no credential, and "+
				"importing the package to assert that would be the wrong kind of proof", path)
		}
	}
}

// --- no provenance, no interpretation of the scope --------------------------

// TestTheSweepScopeReachesTheIdentifierAndNothingElse.
//
// A scope says which execution a measurement belongs to. It must not become part
// of what was observed, because two measurements of one host would then start
// describing two hosts.
func TestTheSweepScopeReachesTheIdentifierAndNothingElse(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")

	measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))

	scopes := sweepScopes(t, target)
	if len(scopes) != 1 {
		t.Fatalf("scopes = %v, want 1", scopes)
	}
	scope := scopes[0]

	graph := freeze(t, target.builder)
	found := false
	for _, evidence := range graph.Nodes() {
		if strings.Contains(evidence.ID().String(), scope) {
			found = true
		}
		if strings.Contains(evidence.Subject().Ref(), scope) {
			t.Errorf("%s carries the scope in its subject", evidence.ID())
		}
		encoded, err := evidence.MarshalJSON()
		if err != nil {
			t.Fatalf("MarshalJSON: %v", err)
		}
		body := string(encoded)
		// The identifier legitimately carries it; nothing else in the node may.
		body = strings.ReplaceAll(body, evidence.ID().String(), "")
		if strings.Contains(body, scope) {
			t.Errorf("%s carries the scope outside its identifier: %s", evidence.ID(), encoded)
		}
	}
	if !found {
		t.Error("no identifier carries the scope, so this test proves nothing")
	}
}

// TestScopesAreUniquePerAdvertisementAndDeterministic.
//
// Uniqueness is inherited from the advertisement identifiers, which the graph
// already keeps distinct. Determinism is a property of the derivation: the same
// advertisement produces the same label on every call, with no clock, counter or
// random source involved.
func TestScopesAreUniquePerAdvertisementAndDeterministic(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker.internal", 9093),
		advertisedBroker(2, "broker.internal", 9093),
		advertisedBroker(1, "broker.internal", 9092),
		advertisedBroker(3, "broker-3.internal", 9093),
	)

	seen := map[string]struct{}{}
	for _, broker := range target.brokers {
		scope, err := advertisedScope(broker.Evidence())
		if err != nil {
			t.Fatalf("advertisedScope: %v", err)
		}
		if _, duplicate := seen[scope.String()]; duplicate {
			t.Fatalf("two advertisements share the scope %q", scope)
		}
		seen[scope.String()] = struct{}{}

		again, err := advertisedScope(broker.Evidence())
		if err != nil {
			t.Fatalf("advertisedScope: %v", err)
		}
		if again != scope {
			t.Errorf("the same advertisement produced %q then %q", scope, again)
		}
		if !strings.HasPrefix(scope.String(), advertisedScopePrefix) {
			t.Errorf("scope %q does not say what kind of execution it names", scope)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("distinct scopes = %d, want 4", len(seen))
	}
}

// TestTheSweepScopeCarriesTheWholeDigest pins uniqueness as a proven property
// rather than a probable one.
//
// A truncated digest would make two advertisements' scopes collide with some
// small probability, and the failure mode would not be uniformly loud: a
// collision between advertisements naming *different* hostnames produces no
// identifier collision at all, so nothing fails and two unrelated measurements
// quietly share a label. The full digest costs 48 characters and removes the
// question. See ADR 0033 section 5.
func TestTheSweepScopeCarriesTheWholeDigest(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	broker := brokerByNode(t, target, 1, "broker-1.internal")

	scope, err := advertisedScope(broker.Evidence())
	if err != nil {
		t.Fatalf("advertisedScope: %v", err)
	}

	digest := sha256.Sum256([]byte(broker.Evidence()))
	want := advertisedScopePrefix + hex.EncodeToString(digest[:])
	if scope.String() != want {
		t.Errorf("scope = %q, want the whole digest %q", scope, want)
	}
	if got := len(scope.String()) - len(advertisedScopePrefix); got != 2*sha256.Size {
		t.Errorf("digest is %d characters, want the full %d: a truncated digest makes "+
			"uniqueness probabilistic, and its collision failure mode is not uniformly loud",
			got, 2*sha256.Size)
	}
}

// TestTheScopeIsNotOrigin: a scope answers "which execution is this?" and must
// never be read as "how did this endpoint enter the run?".
//
// The decisive case is the same one that keeps `Origin` deferred: the bootstrap
// endpoint is measured twice here, once unscoped and once under an advertised
// scope, and both measurements describe an endpoint that is simultaneously
// supplied and advertised. A scope that meant provenance would have to claim one
// of those and be wrong.
func TestTheScopeIsNotOrigin(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, authHost, 9092))
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().resolving(t, authHost, authAddress)

	measure(t, target, tcpPlan(resolver, newAdvertisedDialer(peer)))
	graph := freeze(t, target.builder)

	for _, evidence := range graph.Nodes() {
		for key := range evidence.Attributes() {
			switch key {
			case "origin", "kafka.origin", "kafka.broker.origin", "evidence.origin",
				"subject.origin", "kafka.broker.discovered", "probe.sweep_scope",
				"transport.sweep", "kafka.broker.is_bootstrap":
				t.Errorf("%s records %s: this phase records derivation, not provenance",
					evidence.ID(), key)
			}
		}
	}

	// Nothing hands a scope back to be interpreted, and no type reports one.
	var plan any = TransportPlan{}
	if _, ok := plan.(interface{ Origin() string }); ok {
		t.Error("TransportPlan exposes an Origin")
	}
	var result any = &MeasurementResult{}
	for _, name := range []string{"Origin", "Scopes", "Scope"} {
		if _, ok := reflect.TypeOf(result).MethodByName(name); ok {
			t.Errorf("MeasurementResult exposes %s: a scope is not a value to read back", name)
		}
	}
}

// --- no traversal, no judgement ---------------------------------------------

// TestReachabilityIsNotRecursive: one hop, no re-entry, and therefore no depth
// limit to tune and no visited set to keep.
func TestReachabilityIsNotRecursive(t *testing.T) {
	var plan any = TransportPlan{}
	for _, probe := range []struct {
		name string
		is   bool
	}{
		{"MaxDepth", func() bool { _, ok := plan.(interface{ MaxDepth() int }); return ok }()},
		{"Recursive", func() bool { _, ok := plan.(interface{ Recursive() bool }); return ok }()},
		{"Expand", func() bool { _, ok := plan.(interface{ Expand() bool }); return ok }()},
		{"Visited", func() bool {
			_, ok := plan.(interface{ Visited(string) bool })
			return ok
		}()},
	} {
		if probe.is {
			t.Errorf("TransportPlan exposes %s: there is no traversal to bound", probe.name)
		}
	}

	planType := reflect.TypeOf(TransportPlan{})
	for i := range planType.NumField() {
		name := strings.ToLower(planType.Field(i).Name)
		for _, banned := range []string{"depth", "recurs", "visited", "dedup", "retry"} {
			if strings.Contains(name, banned) {
				t.Errorf("TransportPlan.%s names %q", planType.Field(i).Name, banned)
			}
		}
	}
}

// TestReachabilityReachesNoConclusion.
//
// The phase produces the exact evidence a future rule needs and deliberately
// does not use it. Whether one unreachable broker out of three is WARN, ERROR or
// CRITICAL depends on Kafka semantics and diagnosis policy, and both belong to a
// layer that consumes frozen evidence.
func TestReachabilityReachesNoConclusion(t *testing.T) {
	result := reflect.TypeOf(&MeasurementResult{})
	for i := range result.NumMethod() {
		name := strings.ToLower(result.Method(i).Name)
		for _, banned := range []string{
			"reachable", "healthy", "health", "severity", "finding",
			"confidence", "status", "ok", "success",
		} {
			if strings.Contains(name, banned) {
				t.Errorf("MeasurementResult.%s reports %q: this phase judges nothing",
					result.Method(i).Name, banned)
			}
		}
	}

	// The only things it reports are two counts.
	if got := result.NumMethod(); got != 2 {
		names := make([]string, 0, got)
		for i := range got {
			names = append(names, result.Method(i).Name)
		}
		t.Errorf("MeasurementResult has %d methods (%v), want the two counts", got, names)
	}
}

// TestNoKafkaSpecificFailureClassIsInvented: the transport vocabulary is the
// generic one, and a service-specific class would be a finding in disguise.
func TestNoKafkaSpecificFailureClassIsInvented(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedPeer(t)
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	dialer := newAdvertisedDialer(peer, "10.20.0.1")

	measure(t, target, tcpPlan(resolver, dialer))
	graph := freeze(t, target.builder)

	for _, evidence := range graph.Nodes() {
		if !strings.Contains(evidence.ID().String(), advertisedScopePrefix) {
			continue
		}
		if strings.Contains(evidence.FailureClass().String(), "KAFKA") {
			t.Errorf("%s carries %s: transport failures stay service-neutral",
				evidence.ID(), evidence.FailureClass())
		}
		if strings.HasPrefix(evidence.Step().String(), "kafka.") {
			t.Errorf("%s is a Kafka step: this phase records transport evidence", evidence.ID())
		}
	}
}

// --- graph shape ------------------------------------------------------------

// TestTheDerivationChainRunsAdvertisementToDNSToTCPToTLS.
//
// There is no synthetic Kafka reachability node between the advertisement and
// the lookup. One would observe nothing of its own — every fact in the chain is
// already a DNS, TCP or TLS fact — and a wrapper node states a step that never
// ran.
func TestTheDerivationChainRunsAdvertisementToDNSToTCPToTLS(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedTLSPeer(t, "broker-1.internal")
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")

	measure(t, target, tlsPlan(resolver, newAdvertisedDialer(peer), peer))

	broker := brokerByNode(t, target, 1, "broker-1.internal")
	graph := freeze(t, target.builder)

	handshake := node(t, graph, scopedHandshakeID(t, broker, "10.20.0.1"))
	connect := node(t, graph, scopedConnectID(t, broker, "10.20.0.1"))
	lookup := node(t, graph, scopedLookupID(t, broker))

	for _, step := range []struct {
		child, parent domain.Evidence
	}{
		{handshake, connect},
		{connect, lookup},
	} {
		parents := graph.Parents(step.child.ID())
		if len(parents) != 1 || parents[0] != step.parent.ID() {
			t.Errorf("%s parents = %v, want %s", step.child.ID(), parents, step.parent.ID())
		}
	}

	parents := graph.Parents(lookup.ID())
	if len(parents) != 1 || parents[0] != broker.Evidence() {
		t.Fatalf("lookup parents = %v, want the advertisement %s", parents, broker.Evidence())
	}

	// And the advertisement still derives from the exchange that carried it, so
	// the whole chain from a handshake back to the bootstrap transport is walkable.
	advertisementParents := graph.Parents(broker.Evidence())
	if len(advertisementParents) != 1 {
		t.Fatalf("advertisement parents = %v, want the metadata exchange", advertisementParents)
	}
	if got := node(t, graph, advertisementParents[0].String()).Step(); got != StepMetadata {
		t.Errorf("advertisement parent step = %s, want %s", got, StepMetadata)
	}

	// No node between the advertisement and the lookup, and no Kafka step at L1-L3.
	for _, evidence := range graph.Nodes() {
		if !strings.Contains(evidence.ID().String(), advertisedScopePrefix) {
			continue
		}
		switch evidence.Layer() {
		case domain.LayerDNS, domain.LayerTCP, domain.LayerTLS:
		default:
			t.Errorf("%s is at %s: a reachability sweep records transport layers only",
				evidence.ID(), evidence.Layer())
		}
	}
}

// TestTheGraphStaysValidWithScopedSweeps: no dangling reference, no cycle, and
// blocked-by still belongs to transport.
func TestTheGraphStaysValidWithScopedSweeps(t *testing.T) {
	target := discoveredTopology(t,
		advertisedBroker(1, "broker-1.internal", 9093),
		advertisedBroker(2, "broker-2.internal", 9093),
	)
	peer := newAdvertisedTLSPeer(t, "broker-1.internal")
	resolver := newHostResolver().
		resolving(t, "broker-1.internal", "10.20.0.1").
		resolving(t, "broker-2.internal", "10.20.0.2")
	// The second address is refused, so its TLS node is skipped and blocked by
	// the TCP node that produced no connection.
	dialer := newAdvertisedDialer(peer, "10.20.0.2")

	measure(t, target, tlsPlan(resolver, dialer, peer))
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
			if evidence.State() != domain.StateSkipped {
				t.Errorf("%s is %s and carries a blocker", evidence.ID(), evidence.State())
			}
		}
	}

	refused := brokerByNode(t, target, 2, "broker-2.internal")
	skipped := node(t, graph, scopedHandshakeID(t, refused, "10.20.0.2"))
	if skipped.State() != domain.StateSkipped {
		t.Fatalf("tls state = %s, want SKIPPED after a refused connection", skipped.State())
	}
	blockers := graph.BlockedBy(skipped.ID())
	if len(blockers) != 1 || blockers[0] != domain.EvidenceID(scopedConnectID(t, refused, "10.20.0.2")) {
		t.Errorf("blocked by %v, want the scoped TCP node", blockers)
	}
}

// --- latency ----------------------------------------------------------------

// TestPerLayerLatencyIsPreserved.
//
// The product value of this phase is being able to say "DNS answered in X, TCP
// connected in Y, TLS completed in Z" for a broker-advertised endpoint. That
// needs three durations on three nodes, and no aggregate that would invite a
// reader to use one number instead.
func TestPerLayerLatencyIsPreserved(t *testing.T) {
	target := discoveredTopology(t, advertisedBroker(1, "broker-1.internal", 9093))
	peer := newAdvertisedTLSPeer(t, "broker-1.internal")
	resolver := newHostResolver().resolving(t, "broker-1.internal", "10.20.0.1")

	measure(t, target, tlsPlan(resolver, newAdvertisedDialer(peer), peer))

	broker := brokerByNode(t, target, 1, "broker-1.internal")
	graph := freeze(t, target.builder)

	lookup := node(t, graph, scopedLookupID(t, broker))
	connect := node(t, graph, scopedConnectID(t, broker, "10.20.0.1"))
	handshake := node(t, graph, scopedHandshakeID(t, broker, "10.20.0.1"))

	if lookup.Duration() < 0 {
		t.Errorf("dns duration = %s", lookup.Duration())
	}
	if connect.Duration() <= 0 {
		t.Errorf("tcp duration = %s, want a measured connection time", connect.Duration())
	}
	if handshake.Duration() <= 0 {
		t.Errorf("tls duration = %s, want a measured handshake time", handshake.Duration())
	}

	// And nothing aggregates them.
	for _, evidence := range graph.Nodes() {
		for key := range evidence.Attributes() {
			if strings.Contains(string(key), "reachability") {
				t.Errorf("%s records %s: per-layer latency must not be summarized",
					evidence.ID(), key)
			}
		}
	}
}
