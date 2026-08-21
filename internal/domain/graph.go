package domain

import (
	"errors"
	"slices"
)

// ErrInvalidGraph reports that a described graph is not structurally valid.
//
// It is distinct from ErrInvalidValue: that one means a single value cannot be
// represented by the model, while this one means the values are individually
// fine but the structure they describe is not. Duplicate node identifiers,
// references to absent nodes, self edges, cycles, and blocked-by relationships
// on evidence that was not skipped all fail this way.
var ErrInvalidGraph = errors.New("invalid evidence graph")

// Graph is an immutable set of evidence nodes and the relationships between them.
//
// It is deliberately dumb. It knows identifiers, nodes, structural parent edges,
// recorded blocked-by references, and whether its own structure is valid. It
// knows nothing about what an endpoint is, whether two endpoints are the same
// execution target, how deep topology discovery should recurse, or which layer
// runs next. Those are execution concerns and belong to orchestration, probe and
// adapter code. See docs/ARCHITECTURE.md.
//
// A Graph is produced by GraphBuilder.Freeze and never changes afterwards. It
// has no mutation methods, and every accessor that returns a slice returns a
// copy, so a caller cannot reach the internal structure. Because it exposes no
// mutable state, a frozen Graph is safe for concurrent reads without any
// synchronization; none is added here.
//
// The zero Graph is a valid empty graph.
type Graph struct {
	// order is every node identifier in canonical order. It is the single
	// source of iteration order for the whole type.
	order []EvidenceID

	nodes map[EvidenceID]Evidence

	// parents maps a child to its parents; children is derived from it during
	// Freeze so that the two cannot disagree. Both are sorted.
	parents  map[EvidenceID][]EvidenceID
	children map[EvidenceID][]EvidenceID

	// blockedBy maps skipped evidence to the evidence that explains why it did
	// not run. Sorted.
	blockedBy map[EvidenceID][]EvidenceID
}

// Len returns the number of nodes.
func (g Graph) Len() int { return len(g.order) }

// Node returns the evidence with the given identifier and whether it exists.
func (g Graph) Node(id EvidenceID) (Evidence, bool) {
	e, ok := g.nodes[id]
	return e, ok
}

// Nodes returns every node in canonical order.
//
// The order is EvidenceID lexical order, never insertion order. Insertion order
// would be nondeterministic once orchestration probes endpoints concurrently,
// and the canonical report has to be byte-stable for the same content.
func (g Graph) Nodes() []Evidence {
	if len(g.order) == 0 {
		return nil
	}
	out := make([]Evidence, 0, len(g.order))
	for _, id := range g.order {
		out = append(out, g.nodes[id])
	}
	return out
}

// Parents returns the parents of id in canonical order.
//
// A node with no parents, or an identifier that is not in the graph, yields nil.
// Callers that need to tell those apart should use Node first.
func (g Graph) Parents(id EvidenceID) []EvidenceID {
	return copyIDs(g.parents[id])
}

// Children returns the children of id in canonical order.
//
// This index is derived from the parent edges during Freeze rather than stored
// alongside them, so the two views cannot disagree.
func (g Graph) Children(id EvidenceID) []EvidenceID {
	return copyIDs(g.children[id])
}

// BlockedBy returns the evidence that explains why id did not run, in canonical
// order.
//
// This is recorded by the caller, never inferred. The graph stores that a
// skipped step was blocked by a particular piece of evidence; deciding that a
// DNS failure should block a TCP attempt is an execution decision made
// elsewhere.
func (g Graph) BlockedBy(id EvidenceID) []EvidenceID {
	return copyIDs(g.blockedBy[id])
}

// copyIDs returns an owned copy so that a caller cannot edit graph structure
// through a returned slice.
func copyIDs(ids []EvidenceID) []EvidenceID {
	if len(ids) == 0 {
		return nil
	}
	return slices.Clone(ids)
}
