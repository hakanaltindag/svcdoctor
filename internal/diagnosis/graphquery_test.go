package diagnosis

import (
	"slices"
	"testing"

	"github.com/hakanaltindag/svcdoctor/internal/domain"
)

// Phase 10.1a: the shared graph queries.
//
// ADR 0079 section 2.6 is what most of this is for: sibling comparison must be
// generic, and the engine must be able to tell "one of three failed" from "all
// three did" and from "two were never tried" without knowing what any of them is.

// discoveryGraph is the flagship shape:
//
//	a discovery node with three discovered endpoints, one passing, one failing
//	and one never measured.
func discoveryGraph(t *testing.T) domain.Graph {
	t.Helper()

	s := newSpec(t)
	discovery := s.endpoint("q-discovery", "seed.example:9092",
		domain.LayerTopology, "topology.discover", domain.StatePass)

	good := s.endpoint("q-one", "one.example:9092", domain.LayerTCP, "tcp.connect", domain.StatePass)
	bad := s.endpoint("q-two", "two.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	unknown := s.unknown("q-three", "three.example:9092", domain.LayerTCP, "tcp.connect")

	s.parent(good, discovery)
	s.parent(bad, discovery)
	s.parent(unknown, discovery)
	return s.freeze()
}

// TestDIAG015SiblingCountingIsGeneric is ADR 0079 section 2.6.
func TestDIAG015SiblingCountingIsGeneric(t *testing.T) {
	g := discoveryGraph(t)

	counts := SiblingOutcome(g, "q-discovery")

	if got := counts.Total(); got != 3 {
		t.Fatalf("Total() = %d, want 3", got)
	}
	if got := refsOf(counts.Passed()); !slices.Equal(got, []string{"one.example:9092"}) {
		t.Errorf("Passed() = %v", got)
	}
	if got := refsOf(counts.Failed()); !slices.Equal(got, []string{"two.example:9092"}) {
		t.Errorf("Failed() = %v", got)
	}
	if got := refsOf(counts.NotMeasured()); !slices.Equal(got, []string{"three.example:9092"}) {
		t.Errorf("NotMeasured() = %v", got)
	}
}

// TestNotMeasuredIsNeverFoldedIntoFailed is the three-categories property, and it
// is the one ADR 0052 names: "not measured" is never collapsed into "not
// reached".
//
// A run whose budget expired before two of three endpoints were tried must not
// produce "all endpoints unreachable". That is the same defect in a different
// costume every time it appears, and keeping the third category is what makes it
// unavailable rather than merely discouraged.
func TestNotMeasuredIsNeverFoldedIntoFailed(t *testing.T) {
	s := newSpec(t)
	discovery := s.endpoint("r-discovery", "seed.example:9092",
		domain.LayerTopology, "topology.discover", domain.StatePass)
	bad := s.endpoint("r-one", "one.example:9092", domain.LayerTCP, "tcp.connect", domain.StateFail)
	first := s.unknown("r-two", "two.example:9092", domain.LayerTCP, "tcp.connect")
	second := s.unknown("r-three", "three.example:9092", domain.LayerTCP, "tcp.connect")
	s.parent(bad, discovery)
	s.parent(first, discovery)
	s.parent(second, discovery)
	g := s.freeze()

	counts := SiblingOutcome(g, "r-discovery")

	if len(counts.Failed()) != 1 {
		t.Errorf("Failed() = %v, want exactly the one that failed", refsOf(counts.Failed()))
	}
	if len(counts.NotMeasured()) != 2 {
		t.Errorf("NotMeasured() = %v, want the two that were never tried",
			refsOf(counts.NotMeasured()))
	}
}

// TestASubjectWithAMixedRecordIsClassifiedByItsWorstOutcome pins the reduction
// rule: a subject with one failure and one pass is not half-healthy.
func TestASubjectWithAMixedRecordIsClassifiedByItsWorstOutcome(t *testing.T) {
	s := newSpec(t)
	discovery := s.endpoint("s-discovery", "seed.example:9092",
		domain.LayerTopology, "topology.discover", domain.StatePass)
	pass := s.endpoint("s-a-tcp", "mixed.example:9092", domain.LayerTCP, "tcp.connect", domain.StatePass)
	fail := s.endpoint("s-a-tls", "mixed.example:9092", domain.LayerTLS, "tls.handshake", domain.StateFail)
	s.parent(pass, discovery)
	s.parent(fail, discovery)
	g := s.freeze()

	counts := SiblingOutcome(g, "s-discovery")
	if len(counts.Failed()) != 1 || len(counts.Passed()) != 0 {
		t.Errorf("a subject with one PASS and one FAIL was classified passed=%v failed=%v",
			refsOf(counts.Passed()), refsOf(counts.Failed()))
	}

	// And a subject with a pass and an unmeasured step is not fully passed
	// either: something about it is still unknown.
	s2 := newSpec(t)
	d2 := s2.endpoint("t-discovery", "seed.example:9092",
		domain.LayerTopology, "topology.discover", domain.StatePass)
	p2 := s2.endpoint("t-a-tcp", "part.example:9092", domain.LayerTCP, "tcp.connect", domain.StatePass)
	u2 := s2.unknown("t-a-tls", "part.example:9092", domain.LayerTLS, "tls.handshake")
	s2.parent(p2, d2)
	s2.parent(u2, d2)

	counts2 := SiblingOutcome(s2.freeze(), "t-discovery")
	if len(counts2.NotMeasured()) != 1 || len(counts2.Passed()) != 0 {
		t.Errorf("a partly measured subject was classified passed=%v notMeasured=%v",
			refsOf(counts2.Passed()), refsOf(counts2.NotMeasured()))
	}
}

func TestSiblingOutcomeOfALeafIsEmpty(t *testing.T) {
	g := discoveryGraph(t)

	counts := SiblingOutcome(g, "q-one")
	if counts.Total() != 0 {
		t.Errorf("Total() = %d for a leaf, want 0", counts.Total())
	}
	if SiblingOutcome(g, "no-such-node").Total() != 0 {
		t.Error("an unknown identifier produced siblings")
	}
	if (SiblingCounts{}).Total() != 0 {
		t.Error("the zero SiblingCounts is not empty")
	}
}

func TestSiblingCountsHandOutCopies(t *testing.T) {
	g := discoveryGraph(t)
	counts := SiblingOutcome(g, "q-discovery")

	counts.Passed()[0] = domain.Subject{}
	counts.Failed()[0] = domain.Subject{}
	counts.NotMeasured()[0] = domain.Subject{}

	if len(refsOf(counts.Passed())) != 1 || counts.Passed()[0].Ref() != "one.example:9092" {
		t.Error("editing a returned slice changed the counts")
	}
}

func TestNodesForSubjectIsInLayerOrder(t *testing.T) {
	g, subject := linearGraph(t)

	nodes := NodesForSubject(g, subject)
	var got []domain.EvidenceID
	for _, n := range nodes {
		got = append(got, n.ID())
	}
	if want := []domain.EvidenceID{"a-dns", "a-tcp", "a-tls"}; !slices.Equal(got, want) {
		t.Errorf("NodesForSubject = %v, want %v (layer order)", got, want)
	}

	if got := NodesForSubject(g, endpointSubject(t, "absent.example:5432")); got != nil {
		t.Errorf("an absent subject returned %v", got)
	}
	if got := NodesForSubject(g, domain.Subject{}); got != nil {
		t.Errorf("the zero subject returned %v", got)
	}
}

func TestSubjectsAreCanonicallyOrderedAndDeduplicated(t *testing.T) {
	g := discoveryGraph(t)

	want := []string{
		"one.example:9092", "seed.example:9092", "three.example:9092", "two.example:9092",
	}
	if got := refsOf(Subjects(g)); !slices.Equal(got, want) {
		t.Errorf("Subjects = %v, want %v", got, want)
	}

	// The linear graph has three nodes about one subject and yields one.
	linear, _ := linearGraph(t)
	if got := Subjects(linear); len(got) != 1 {
		t.Errorf("Subjects = %v, want one deduplicated subject", refsOf(got))
	}
	if got := Subjects(domain.Graph{}); got != nil {
		t.Errorf("the empty graph has subjects: %v", refsOf(got))
	}
}

// TestBlockedChainIsTransitiveAndBounded covers the traversal and its guard.
//
// The visited set is what makes the walk terminate. A domain.Graph is a DAG by
// construction, so a cycle cannot arrive from GraphBuilder — but a traversal
// whose termination depends on a caller's invariant is a hang waiting for a bug
// somewhere else.
func TestBlockedChainIsTransitiveAndBounded(t *testing.T) {
	s := newSpec(t)
	dns := s.endpoint("u-dns", "chain.example:5432", domain.LayerDNS, "dns.lookup", domain.StateFail)
	tcp := s.endpoint("u-tcp", "chain.example:5432", domain.LayerTCP, "tcp.connect", domain.StateSkipped)
	tls := s.endpoint("u-tls", "chain.example:5432", domain.LayerTLS, "tls.handshake", domain.StateSkipped)
	auth := s.endpoint("u-auth", "chain.example:5432", domain.LayerAuth, "auth.exchange", domain.StateSkipped)
	s.parent(tcp, dns)
	s.parent(tls, tcp)
	s.parent(auth, tls)
	s.blockedBy(tcp, dns)
	s.blockedBy(tls, tcp)
	s.blockedBy(auth, tls)
	g := s.freeze()

	want := []domain.EvidenceID{"u-auth", "u-tcp", "u-tls"}
	if got := BlockedChain(g, "u-dns"); !slices.Equal(got, want) {
		t.Errorf("BlockedChain = %v, want %v (transitive, sorted)", got, want)
	}
	if got := BlockedChain(g, "u-tls"); !slices.Equal(got, []domain.EvidenceID{"u-auth"}) {
		t.Errorf("BlockedChain from the middle = %v", got)
	}
	if got := BlockedChain(g, "u-auth"); got != nil {
		t.Errorf("BlockedChain of a leaf = %v, want nil", got)
	}
	if got := BlockedChain(g, "no-such-node"); got != nil {
		t.Errorf("BlockedChain of an absent node = %v, want nil", got)
	}
	// The starting node is never in its own chain, which is what keeps a
	// boundary's failing half out of its own blocked set.
	if slices.Contains(BlockedChain(g, "u-dns"), "u-dns") {
		t.Error("the starting node appears in its own blocked chain")
	}
}

// TestGraphQueriesAreRepeatable is the determinism half.
//
// Every one of these walks a Go map somewhere — the graph's own indexes, or the
// inverted blocked-by relation — and Go randomizes map iteration per range, so a
// single pass would pass by luck.
func TestGraphQueriesAreRepeatable(t *testing.T) {
	g := discoveryGraph(t)
	linear, subject := linearGraph(t)

	subjects := refsOf(Subjects(g))
	counts := refsOf(SiblingOutcome(g, "q-discovery").NotMeasured())
	chain := BlockedChain(linear, "a-tcp")
	var nodes []domain.EvidenceID
	for _, n := range NodesForSubject(linear, subject) {
		nodes = append(nodes, n.ID())
	}

	for i := range 64 {
		if got := refsOf(Subjects(g)); !slices.Equal(got, subjects) {
			t.Fatalf("iteration %d: Subjects = %v, want %v", i, got, subjects)
		}
		if got := refsOf(SiblingOutcome(g, "q-discovery").NotMeasured()); !slices.Equal(got, counts) {
			t.Fatalf("iteration %d: NotMeasured = %v, want %v", i, got, counts)
		}
		if got := BlockedChain(linear, "a-tcp"); !slices.Equal(got, chain) {
			t.Fatalf("iteration %d: BlockedChain = %v, want %v", i, got, chain)
		}
		var again []domain.EvidenceID
		for _, n := range NodesForSubject(linear, subject) {
			again = append(again, n.ID())
		}
		if !slices.Equal(again, nodes) {
			t.Fatalf("iteration %d: NodesForSubject = %v, want %v", i, again, nodes)
		}
	}
}

func refsOf(subjects []domain.Subject) []string {
	if len(subjects) == 0 {
		return nil
	}
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, s.Ref())
	}
	return out
}
