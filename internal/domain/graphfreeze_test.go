package domain

import (
	"testing"
)

// TestFreezeIsolatesTheGraph is the core immutability guarantee: once frozen,
// nothing the builder does afterwards can change the graph a caller already
// holds. Diagnosis purity depends on it.
func TestFreezeIsolatesTheGraph(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"), passing(t, "b"))
	if err := b.AddParent("b", "a"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}

	first := mustFreeze(t, b)

	// Keep building after the freeze.
	addAll(t, b, passing(t, "c"), skipped(t, "d"))
	if err := b.AddParent("c", "b"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy("d", "a"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}

	if first.Len() != 2 {
		t.Errorf("the frozen graph grew to %d nodes", first.Len())
	}
	if _, ok := first.Node("c"); ok {
		t.Error("a node added after Freeze appeared in the frozen graph")
	}
	if got := first.Children("b"); got != nil {
		t.Errorf("an edge added after Freeze appeared in the frozen graph: %v", got)
	}
	if got := first.BlockedBy("d"); got != nil {
		t.Errorf("a blocked-by reference added after Freeze appeared: %v", got)
	}

	// A second freeze does reflect the later work, and the first stays as it was.
	second := mustFreeze(t, b)
	if second.Len() != 4 {
		t.Errorf("the second graph has %d nodes, want 4", second.Len())
	}
	if got := second.Children("b"); !equalIDs(got, []EvidenceID{"c"}) {
		t.Errorf("Children(b) = %v, want [c] in the second graph", got)
	}
	if first.Len() != 2 {
		t.Errorf("the first graph changed when the second was frozen: %d nodes", first.Len())
	}
}

// TestReturnedSlicesAreCopies proves a reader cannot edit graph structure
// through anything an accessor hands back.
func TestReturnedSlicesAreCopies(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), passing(t, "p2"), skipped(t, "tcp"))
	if err := b.AddParent("tcp", "dns"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddParent("tcp", "p2"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy("tcp", "dns"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}

	g := mustFreeze(t, b)

	parents := g.Parents("tcp")
	parents[0] = "mutated"
	if got := g.Parents("tcp"); !equalIDs(got, []EvidenceID{"dns", "p2"}) {
		t.Errorf("Parents changed through a returned slice: %v", got)
	}

	children := g.Children("dns")
	children[0] = "mutated"
	if got := g.Children("dns"); !equalIDs(got, []EvidenceID{"tcp"}) {
		t.Errorf("Children changed through a returned slice: %v", got)
	}

	blockers := g.BlockedBy("tcp")
	blockers[0] = "mutated"
	if got := g.BlockedBy("tcp"); !equalIDs(got, []EvidenceID{"dns"}) {
		t.Errorf("BlockedBy changed through a returned slice: %v", got)
	}

	nodes := g.Nodes()
	nodes[0] = Evidence{}
	if got := idsOf(g.Nodes()); !equalIDs(got, []EvidenceID{"dns", "p2", "tcp"}) {
		t.Errorf("Nodes changed through a returned slice: %v", got)
	}
}

// TestEvidenceStaysImmutableInsideTheGraph checks that the graph relies on the
// value semantics Evidence already guarantees rather than adding a second
// copying layer: a node's attributes cannot be edited through the graph.
func TestEvidenceStaysImmutableInsideTheGraph(t *testing.T) {
	in := EvidenceInput{
		ID:         mustID(t, "a"),
		Subject:    mustEndpointSubject(t, "kafka.internal:9092"),
		Layer:      LayerDNS,
		Step:       mustStep(t, "dns.lookup"),
		State:      StatePass,
		Attributes: map[AttributeKey]AttrValue{"dns.rcode": StringAttr("NOERROR")},
		StartedAt:  testStart,
	}
	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence: %v", err)
	}

	b := NewGraphBuilder()
	addAll(t, b, e)
	g := mustFreeze(t, b)

	stored, ok := g.Node("a")
	if !ok {
		t.Fatal("node not found")
	}
	attrs := stored.Attributes()
	attrs["dns.rcode"] = StringAttr("SERVFAIL")
	attrs["injected"] = BoolAttr(true)

	again, _ := g.Node("a")
	v, ok := again.Attribute("dns.rcode")
	if !ok {
		t.Fatal("attribute disappeared")
	}
	if got, _ := v.Str(); got != "NOERROR" {
		t.Errorf("attribute changed through the graph: %q", got)
	}
	if _, ok := again.Attribute("injected"); ok {
		t.Error("an attribute was injected through the graph")
	}
}

// TestFreezeRejectsInconsistentBlockedBy is the final safety net. The
// incremental check already rejects this, so the test reaches past the public
// API to prove Freeze validates independently and a Graph cannot exist in an
// invalid state even if a future builder change lets something slip through.
func TestFreezeRejectsInconsistentBlockedBy(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), passing(t, "tcp"))

	// Bypass AddBlockedBy deliberately.
	addToSet(b.blockedBy, "tcp", "dns")

	if _, err := b.Freeze(); err == nil {
		t.Fatal("Freeze accepted a blocked-by reference on non-skipped evidence")
	}
}

// TestFreezeRejectsDanglingReference proves Freeze re-validates references even
// though AddParent already required both nodes to exist.
func TestFreezeRejectsDanglingReference(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "child"))

	addToSet(b.parents, "child", "ghost")

	if _, err := b.Freeze(); err == nil {
		t.Fatal("Freeze accepted an edge to an absent node")
	}
}

// TestFreezeRejectsCycle proves the full-graph cycle validation runs even when
// the incremental check is bypassed.
func TestFreezeRejectsCycle(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"), passing(t, "b"), passing(t, "c"))

	addToSet(b.parents, "b", "a")
	addToSet(b.parents, "c", "b")
	addToSet(b.parents, "a", "c")

	if _, err := b.Freeze(); err == nil {
		t.Fatal("Freeze accepted a cycle")
	}
}

// TestFreezeRejectsSelfEdge proves self references are caught by the final
// validation too.
func TestFreezeRejectsSelfEdge(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"))

	addToSet(b.parents, "a", "a")

	if _, err := b.Freeze(); err == nil {
		t.Fatal("Freeze accepted a self edge")
	}
}

// TestChildIndexCannotDisagreeWithParents pins the single-source-of-truth
// decision: children are derived during Freeze, so every parent edge has exactly
// one matching child entry.
func TestChildIndexCannotDisagreeWithParents(t *testing.T) {
	b := NewGraphBuilder()
	for _, id := range []string{"a", "b", "c", "d"} {
		addAll(t, b, passing(t, id))
	}
	edges := [][2]EvidenceID{{"b", "a"}, {"c", "a"}, {"d", "b"}, {"d", "c"}}
	for _, e := range edges {
		if err := b.AddParent(e[0], e[1]); err != nil {
			t.Fatalf("AddParent(%q, %q): %v", e[0], e[1], err)
		}
	}

	g := mustFreeze(t, b)

	// Every parent edge appears exactly once in the child index, and nothing else does.
	seen := 0
	for _, node := range g.Nodes() {
		for _, parent := range g.Parents(node.ID()) {
			children := g.Children(parent)
			found := 0
			for _, c := range children {
				if c == node.ID() {
					found++
				}
			}
			if found != 1 {
				t.Errorf("child index lists %q under %q %d times, want 1", node.ID(), parent, found)
			}
			seen++
		}
	}
	if seen != len(edges) {
		t.Errorf("walked %d edges, want %d", seen, len(edges))
	}
}
