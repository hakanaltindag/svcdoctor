package domain

import (
	"testing"
)

// buildDiamond constructs the same semantic graph, adding nodes and edges in the
// order given, so that determinism can be checked across insertion orders.
//
//	  a
//	 / \
//	b   c
//	 \ /
//	  d   (skipped, blocked by b and c)
func buildDiamond(t *testing.T, nodeOrder, edgeOrder []int) Graph {
	t.Helper()

	nodes := []Evidence{
		passing(t, "a"),
		passing(t, "b"),
		passing(t, "c"),
		skipped(t, "d"),
	}
	edges := [][2]EvidenceID{{"b", "a"}, {"c", "a"}, {"d", "b"}, {"d", "c"}}

	b := NewGraphBuilder()
	for _, i := range nodeOrder {
		if err := b.AddEvidence(nodes[i]); err != nil {
			t.Fatalf("AddEvidence(%q): %v", nodes[i].ID(), err)
		}
	}
	for _, i := range edgeOrder {
		if err := b.AddParent(edges[i][0], edges[i][1]); err != nil {
			t.Fatalf("AddParent(%q, %q): %v", edges[i][0], edges[i][1], err)
		}
	}
	// Blockers recorded in a deliberately non-canonical order.
	for _, blocker := range []EvidenceID{"c", "b"} {
		if err := b.AddBlockedBy("d", blocker); err != nil {
			t.Fatalf("AddBlockedBy(d, %q): %v", blocker, err)
		}
	}

	return mustFreeze(t, b)
}

// TestOrderingIsCanonicalNotInsertionOrder is the determinism requirement.
// Insertion order becomes nondeterministic once orchestration probes endpoints
// concurrently, so it must not decide output order.
func TestOrderingIsCanonicalNotInsertionOrder(t *testing.T) {
	orders := []struct {
		name  string
		nodes []int
		edges []int
	}{
		{"declared order", []int{0, 1, 2, 3}, []int{0, 1, 2, 3}},
		{"reversed nodes", []int{3, 2, 1, 0}, []int{0, 1, 2, 3}},
		{"reversed edges", []int{0, 1, 2, 3}, []int{3, 2, 1, 0}},
		{"both reversed", []int{3, 2, 1, 0}, []int{3, 2, 1, 0}},
		{"shuffled", []int{2, 0, 3, 1}, []int{1, 3, 0, 2}},
	}

	want := struct {
		nodes     []EvidenceID
		parentsD  []EvidenceID
		childrenA []EvidenceID
		blockedD  []EvidenceID
	}{
		nodes:     []EvidenceID{"a", "b", "c", "d"},
		parentsD:  []EvidenceID{"b", "c"},
		childrenA: []EvidenceID{"b", "c"},
		blockedD:  []EvidenceID{"b", "c"},
	}

	for _, o := range orders {
		t.Run(o.name, func(t *testing.T) {
			g := buildDiamond(t, o.nodes, o.edges)

			if got := idsOf(g.Nodes()); !equalIDs(got, want.nodes) {
				t.Errorf("Nodes() = %v, want %v", got, want.nodes)
			}
			if got := g.Parents("d"); !equalIDs(got, want.parentsD) {
				t.Errorf("Parents(d) = %v, want %v", got, want.parentsD)
			}
			if got := g.Children("a"); !equalIDs(got, want.childrenA) {
				t.Errorf("Children(a) = %v, want %v", got, want.childrenA)
			}
			if got := g.BlockedBy("d"); !equalIDs(got, want.blockedD) {
				t.Errorf("BlockedBy(d) = %v, want %v", got, want.blockedD)
			}
		})
	}
}

// TestRepeatedReadsAreStable guards against Go's randomized map iteration
// leaking into output across calls on one graph.
func TestRepeatedReadsAreStable(t *testing.T) {
	g := buildDiamond(t, []int{0, 1, 2, 3}, []int{0, 1, 2, 3})

	firstNodes := idsOf(g.Nodes())
	firstParents := g.Parents("d")
	firstChildren := g.Children("a")
	firstBlocked := g.BlockedBy("d")

	for i := 0; i < 50; i++ {
		if got := idsOf(g.Nodes()); !equalIDs(got, firstNodes) {
			t.Fatalf("Nodes() varied between calls: %v vs %v", got, firstNodes)
		}
		if got := g.Parents("d"); !equalIDs(got, firstParents) {
			t.Fatalf("Parents() varied between calls: %v vs %v", got, firstParents)
		}
		if got := g.Children("a"); !equalIDs(got, firstChildren) {
			t.Fatalf("Children() varied between calls: %v vs %v", got, firstChildren)
		}
		if got := g.BlockedBy("d"); !equalIDs(got, firstBlocked) {
			t.Fatalf("BlockedBy() varied between calls: %v vs %v", got, firstBlocked)
		}
	}
}

// TestSeparatelyBuiltGraphsAgree checks that two builders producing the same
// semantic content yield identical ordering, which is what makes a report
// byte-stable for the same run content.
func TestSeparatelyBuiltGraphsAgree(t *testing.T) {
	a := buildDiamond(t, []int{0, 1, 2, 3}, []int{0, 1, 2, 3})
	b := buildDiamond(t, []int{3, 1, 0, 2}, []int{2, 0, 3, 1})

	if !equalIDs(idsOf(a.Nodes()), idsOf(b.Nodes())) {
		t.Error("node order differs between equivalent graphs")
	}
	for _, id := range idsOf(a.Nodes()) {
		if !equalIDs(a.Parents(id), b.Parents(id)) {
			t.Errorf("Parents(%q) differs between equivalent graphs", id)
		}
		if !equalIDs(a.Children(id), b.Children(id)) {
			t.Errorf("Children(%q) differs between equivalent graphs", id)
		}
		if !equalIDs(a.BlockedBy(id), b.BlockedBy(id)) {
			t.Errorf("BlockedBy(%q) differs between equivalent graphs", id)
		}
	}
}

// TestLexicalOrderingAcrossManyNodes exercises the ordering rule with enough
// nodes that map iteration order would show up if it were being used.
func TestLexicalOrderingAcrossManyNodes(t *testing.T) {
	ids := []string{
		"target/ep:broker-2.internal:9092/dns",
		"target",
		"target/ep:bootstrap.kafka:9092/tls",
		"target/ep:bootstrap.kafka:9092/dns",
		"target/ep:broker-10.internal:9092/dns",
		"target/ep:bootstrap.kafka:9092/tcp",
	}

	b := NewGraphBuilder()
	for _, id := range ids {
		addAll(t, b, passing(t, id))
	}
	g := mustFreeze(t, b)

	want := []EvidenceID{
		"target",
		"target/ep:bootstrap.kafka:9092/dns",
		"target/ep:bootstrap.kafka:9092/tcp",
		"target/ep:bootstrap.kafka:9092/tls",
		// Lexical, so "broker-10" sorts before "broker-2".
		"target/ep:broker-10.internal:9092/dns",
		"target/ep:broker-2.internal:9092/dns",
	}
	if got := idsOf(g.Nodes()); !equalIDs(got, want) {
		t.Errorf("Nodes() = %v,\nwant %v", got, want)
	}
}
