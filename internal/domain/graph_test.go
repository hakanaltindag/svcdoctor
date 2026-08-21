package domain

import (
	"errors"
	"testing"
	"time"
)

// evidenceAt builds a valid node with the given id and state, so graph tests can
// concentrate on structure.
func evidenceAt(t *testing.T, id string, state State) Evidence {
	t.Helper()

	in := EvidenceInput{
		ID:        mustID(t, id),
		Subject:   mustEndpointSubject(t, "kafka.internal:9092"),
		Layer:     LayerDNS,
		Step:      mustStep(t, "dns.lookup"),
		State:     state,
		StartedAt: testStart,
		Duration:  time.Millisecond,
	}
	switch state {
	case StateFail:
		in.FailureClass = FailureDNSNXDomain
	case StateSkipped:
		in.FailureClass = FailureExecSkippedPrerequisiteFailed
	case StateUnknown, StatePass, StateDegraded:
		// No failure class required.
	}

	e, err := NewEvidence(in)
	if err != nil {
		t.Fatalf("NewEvidence(%q): %v", id, err)
	}
	return e
}

func passing(t *testing.T, id string) Evidence {
	t.Helper()
	return evidenceAt(t, id, StatePass)
}

func skipped(t *testing.T, id string) Evidence {
	t.Helper()
	return evidenceAt(t, id, StateSkipped)
}

// addAll adds every node and fails the test on error.
func addAll(t *testing.T, b *GraphBuilder, nodes ...Evidence) {
	t.Helper()
	for _, e := range nodes {
		if err := b.AddEvidence(e); err != nil {
			t.Fatalf("AddEvidence(%q): %v", e.ID(), err)
		}
	}
}

func mustFreeze(t *testing.T, b *GraphBuilder) Graph {
	t.Helper()
	g, err := b.Freeze()
	if err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	return g
}

func idsOf(nodes []Evidence) []EvidenceID {
	out := make([]EvidenceID, 0, len(nodes))
	for _, e := range nodes {
		out = append(out, e.ID())
	}
	return out
}

func equalIDs(a, b []EvidenceID) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEmptyGraph(t *testing.T) {
	g := mustFreeze(t, NewGraphBuilder())

	if g.Len() != 0 {
		t.Errorf("Len() = %d, want 0", g.Len())
	}
	if g.Nodes() != nil {
		t.Error("an empty graph should return no nodes")
	}
	if _, ok := g.Node("missing"); ok {
		t.Error("an empty graph should not resolve any node")
	}
}

// TestZeroGraphIsUsable confirms the zero value behaves as an empty graph rather
// than panicking, so a consumer holding an unset Graph is safe.
func TestZeroGraphIsUsable(t *testing.T) {
	var g Graph

	if g.Len() != 0 {
		t.Errorf("Len() = %d, want 0", g.Len())
	}
	if g.Nodes() != nil || g.Parents("x") != nil || g.Children("x") != nil || g.BlockedBy("x") != nil {
		t.Error("the zero Graph should return nothing")
	}
}

func TestAddAndLookupNodes(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"), passing(t, "b"), passing(t, "c"))

	g := mustFreeze(t, b)

	if g.Len() != 3 {
		t.Fatalf("Len() = %d, want 3", g.Len())
	}
	for _, id := range []EvidenceID{"a", "b", "c"} {
		e, ok := g.Node(id)
		if !ok {
			t.Fatalf("Node(%q) not found", id)
		}
		if e.ID() != id {
			t.Errorf("Node(%q).ID() = %q", id, e.ID())
		}
	}
	if _, ok := g.Node("missing"); ok {
		t.Error("Node should report an unknown id as absent")
	}
}

func TestDuplicateEvidenceIDRejected(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"))

	// Rejected even though the value is identical: a silent overwrite would
	// hide the orchestration bug that produced two nodes for one step.
	err := b.AddEvidence(passing(t, "a"))
	if !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("err = %v, want ErrInvalidGraph", err)
	}

	// A different value under the same id is equally rejected.
	err = b.AddEvidence(evidenceAt(t, "a", StateFail))
	if !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("err = %v, want ErrInvalidGraph", err)
	}

	g := mustFreeze(t, b)
	if g.Len() != 1 {
		t.Errorf("Len() = %d, want 1", g.Len())
	}
	e, _ := g.Node("a")
	if e.State() != StatePass {
		t.Errorf("the original node was overwritten: state = %s", e.State())
	}
}

func TestAddZeroEvidenceRejected(t *testing.T) {
	if err := NewGraphBuilder().AddEvidence(Evidence{}); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("err = %v, want ErrInvalidGraph", err)
	}
}

func TestParentRelationships(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "child"), passing(t, "p1"), passing(t, "p2"))

	if err := b.AddParent("child", "p1"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddParent("child", "p2"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}

	g := mustFreeze(t, b)

	if got := g.Parents("child"); !equalIDs(got, []EvidenceID{"p1", "p2"}) {
		t.Errorf("Parents(child) = %v, want [p1 p2]", got)
	}
	if got := g.Children("p1"); !equalIDs(got, []EvidenceID{"child"}) {
		t.Errorf("Children(p1) = %v, want [child]", got)
	}
	if got := g.Children("p2"); !equalIDs(got, []EvidenceID{"child"}) {
		t.Errorf("Children(p2) = %v, want [child]", got)
	}
	if got := g.Parents("p1"); got != nil {
		t.Errorf("Parents(p1) = %v, want nil", got)
	}
	if got := g.Children("child"); got != nil {
		t.Errorf("Children(child) = %v, want nil", got)
	}
}

func TestDuplicateParentEdgeIsIdempotent(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "child"), passing(t, "parent"))

	for i := 0; i < 3; i++ {
		if err := b.AddParent("child", "parent"); err != nil {
			t.Fatalf("AddParent call %d: %v", i, err)
		}
	}

	g := mustFreeze(t, b)
	if got := g.Parents("child"); !equalIDs(got, []EvidenceID{"parent"}) {
		t.Errorf("Parents(child) = %v, want exactly one edge", got)
	}
	if got := g.Children("parent"); !equalIDs(got, []EvidenceID{"child"}) {
		t.Errorf("Children(parent) = %v, want exactly one edge", got)
	}
}

func TestParentRelationshipRejections(t *testing.T) {
	tests := []struct {
		name          string
		child, parent EvidenceID
	}{
		{"missing child", "ghost", "parent"},
		{"missing parent", "child", "ghost"},
		{"both missing", "ghost1", "ghost2"},
		{"self edge", "child", "child"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewGraphBuilder()
			addAll(t, b, passing(t, "child"), passing(t, "parent"))

			err := b.AddParent(tt.child, tt.parent)
			if !errors.Is(err, ErrInvalidGraph) {
				t.Fatalf("err = %v, want ErrInvalidGraph", err)
			}

			g := mustFreeze(t, b)
			if got := g.Parents("child"); got != nil {
				t.Errorf("a rejected edge was recorded: %v", got)
			}
		})
	}
}

// TestNoForwardReferences pins the decision that both endpoints must exist
// before a relationship is recorded: a typo becomes an error at the call that
// made it, not an unexplained failure at Freeze.
func TestNoForwardReferences(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "child"))

	if err := b.AddParent("child", "parent"); !errors.Is(err, ErrInvalidGraph) {
		t.Fatalf("a forward reference should be rejected, got %v", err)
	}

	// Adding the parent afterwards does not retroactively create the edge.
	addAll(t, b, passing(t, "parent"))
	g := mustFreeze(t, b)
	if got := g.Parents("child"); got != nil {
		t.Errorf("Parents(child) = %v, want nil", got)
	}
}

func TestDiamondIsAccepted(t *testing.T) {
	//   a
	//  / \
	// b   c
	//  \ /
	//   d
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "a"), passing(t, "b"), passing(t, "c"), passing(t, "d"))

	for _, edge := range [][2]EvidenceID{{"b", "a"}, {"c", "a"}, {"d", "b"}, {"d", "c"}} {
		if err := b.AddParent(edge[0], edge[1]); err != nil {
			t.Fatalf("AddParent(%q, %q): %v", edge[0], edge[1], err)
		}
	}

	g := mustFreeze(t, b)

	if got := g.Parents("d"); !equalIDs(got, []EvidenceID{"b", "c"}) {
		t.Errorf("Parents(d) = %v, want [b c]", got)
	}
	if got := g.Children("a"); !equalIDs(got, []EvidenceID{"b", "c"}) {
		t.Errorf("Children(a) = %v, want [b c]", got)
	}
	if got := g.Parents("a"); got != nil {
		t.Errorf("Parents(a) = %v, want nil", got)
	}
}

func TestChainIsAccepted(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, passing(t, "dns"), passing(t, "tcp"), passing(t, "tls"), passing(t, "proto"))

	for _, edge := range [][2]EvidenceID{{"tcp", "dns"}, {"tls", "tcp"}, {"proto", "tls"}} {
		if err := b.AddParent(edge[0], edge[1]); err != nil {
			t.Fatalf("AddParent(%q, %q): %v", edge[0], edge[1], err)
		}
	}

	g := mustFreeze(t, b)
	if got := g.Parents("proto"); !equalIDs(got, []EvidenceID{"tls"}) {
		t.Errorf("Parents(proto) = %v", got)
	}
	if got := g.Children("dns"); !equalIDs(got, []EvidenceID{"tcp"}) {
		t.Errorf("Children(dns) = %v", got)
	}
}

func TestCyclesAreRejected(t *testing.T) {
	tests := []struct {
		name  string
		nodes []string
		// edges are child -> parent; the last one is expected to be rejected.
		edges [][2]EvidenceID
	}{
		{
			name:  "two node cycle",
			nodes: []string{"a", "b"},
			edges: [][2]EvidenceID{{"b", "a"}, {"a", "b"}},
		},
		{
			name:  "three node cycle",
			nodes: []string{"a", "b", "c"},
			edges: [][2]EvidenceID{{"b", "a"}, {"c", "b"}, {"a", "c"}},
		},
		{
			name:  "long cycle",
			nodes: []string{"a", "b", "c", "d", "e"},
			edges: [][2]EvidenceID{{"b", "a"}, {"c", "b"}, {"d", "c"}, {"e", "d"}, {"a", "e"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewGraphBuilder()
			for _, id := range tt.nodes {
				addAll(t, b, passing(t, id))
			}

			last := len(tt.edges) - 1
			for i, edge := range tt.edges[:last] {
				if err := b.AddParent(edge[0], edge[1]); err != nil {
					t.Fatalf("edge %d should have been accepted: %v", i, err)
				}
			}

			closing := tt.edges[last]
			err := b.AddParent(closing[0], closing[1])
			if !errors.Is(err, ErrInvalidGraph) {
				t.Fatalf("the closing edge should be rejected, got %v", err)
			}

			// The graph is still valid without the rejected edge.
			if _, err := b.Freeze(); err != nil {
				t.Errorf("Freeze after a rejected edge: %v", err)
			}
		})
	}
}

func TestBlockedBy(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), skipped(t, "tcp"))

	if err := b.AddParent("tcp", "dns"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}
	if err := b.AddBlockedBy("tcp", "dns"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}

	g := mustFreeze(t, b)

	if got := g.BlockedBy("tcp"); !equalIDs(got, []EvidenceID{"dns"}) {
		t.Errorf("BlockedBy(tcp) = %v, want [dns]", got)
	}
	if got := g.BlockedBy("dns"); got != nil {
		t.Errorf("BlockedBy(dns) = %v, want nil", got)
	}
	// A parent edge and a blocked-by reference coexist: the first records
	// sequence, the second records why the step did not run.
	if got := g.Parents("tcp"); !equalIDs(got, []EvidenceID{"dns"}) {
		t.Errorf("Parents(tcp) = %v, want [dns]", got)
	}
}

func TestMultipleBlockers(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), evidenceAt(t, "policy", StateFail), skipped(t, "tcp"))

	if err := b.AddBlockedBy("tcp", "policy"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}
	if err := b.AddBlockedBy("tcp", "dns"); err != nil {
		t.Fatalf("AddBlockedBy: %v", err)
	}

	g := mustFreeze(t, b)
	if got := g.BlockedBy("tcp"); !equalIDs(got, []EvidenceID{"dns", "policy"}) {
		t.Errorf("BlockedBy(tcp) = %v, want [dns policy] in canonical order", got)
	}
}

func TestDuplicateBlockerIsIdempotent(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), skipped(t, "tcp"))

	for i := 0; i < 3; i++ {
		if err := b.AddBlockedBy("tcp", "dns"); err != nil {
			t.Fatalf("AddBlockedBy call %d: %v", i, err)
		}
	}

	g := mustFreeze(t, b)
	if got := g.BlockedBy("tcp"); !equalIDs(got, []EvidenceID{"dns"}) {
		t.Errorf("BlockedBy(tcp) = %v, want exactly one reference", got)
	}
}

func TestBlockedByRejections(t *testing.T) {
	t.Run("missing blocker", func(t *testing.T) {
		b := NewGraphBuilder()
		addAll(t, b, skipped(t, "tcp"))

		if err := b.AddBlockedBy("tcp", "ghost"); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("err = %v, want ErrInvalidGraph", err)
		}
	})

	t.Run("missing skipped node", func(t *testing.T) {
		b := NewGraphBuilder()
		addAll(t, b, evidenceAt(t, "dns", StateFail))

		if err := b.AddBlockedBy("ghost", "dns"); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("err = %v, want ErrInvalidGraph", err)
		}
	})

	t.Run("self blocker", func(t *testing.T) {
		b := NewGraphBuilder()
		addAll(t, b, skipped(t, "tcp"))

		if err := b.AddBlockedBy("tcp", "tcp"); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("err = %v, want ErrInvalidGraph", err)
		}
	})

	t.Run("blocked-by cycle", func(t *testing.T) {
		b := NewGraphBuilder()
		addAll(t, b, skipped(t, "a"), skipped(t, "b"))

		if err := b.AddBlockedBy("a", "b"); err != nil {
			t.Fatalf("AddBlockedBy: %v", err)
		}
		if err := b.AddBlockedBy("b", "a"); !errors.Is(err, ErrInvalidGraph) {
			t.Fatalf("a mutual block should be rejected, got %v", err)
		}
	})
}

// TestBlockedByRequiresSkipped pins the rule that only a step which did not run
// can be explained by a blocker. Any other state produced a result, so claiming
// something prevented it is self-contradictory.
func TestBlockedByRequiresSkipped(t *testing.T) {
	for _, state := range []State{StatePass, StateFail, StateDegraded, StateUnknown} {
		t.Run(state.String(), func(t *testing.T) {
			b := NewGraphBuilder()
			addAll(t, b, evidenceAt(t, "dns", StateFail), evidenceAt(t, "tcp", state))

			err := b.AddBlockedBy("tcp", "dns")
			if !errors.Is(err, ErrInvalidGraph) {
				t.Fatalf("state %s should not accept a blocker, got %v", state, err)
			}
		})
	}
}

// TestGraphDoesNotInferBlocking is the boundary against an execution engine: a
// failed parent does not automatically produce a blocked-by reference.
func TestGraphDoesNotInferBlocking(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail), skipped(t, "tcp"))

	if err := b.AddParent("tcp", "dns"); err != nil {
		t.Fatalf("AddParent: %v", err)
	}

	g := mustFreeze(t, b)
	if got := g.BlockedBy("tcp"); got != nil {
		t.Errorf("the graph invented a blocked-by reference: %v", got)
	}
}

// TestGraphDoesNotInventNodes is the other half of that boundary: a failed step
// does not cause the graph to create a skipped successor.
func TestGraphDoesNotInventNodes(t *testing.T) {
	b := NewGraphBuilder()
	addAll(t, b, evidenceAt(t, "dns", StateFail))

	g := mustFreeze(t, b)
	if g.Len() != 1 {
		t.Errorf("Len() = %d, want exactly the node that was added", g.Len())
	}
}
