package domain

import (
	"fmt"
	"slices"
)

// GraphBuilder accumulates evidence and the relationships between it, and
// produces an immutable Graph.
//
// The mutable builder and the immutable Graph are separate types on purpose.
// Diagnosis must be a pure function over finished evidence, and a single type
// carrying both a frozen flag and mutation methods would leave that guarantee
// to discipline. Here it is enforced by the type: Graph simply has no way to
// change.
//
// The builder records structure. It does not decide it. It will not create a
// skipped node because a previous layer failed, will not judge whether two
// endpoints are the same execution target, and applies no depth, retry, or
// concurrency policy. Callers describe what happened; the builder checks that
// the description is a valid graph.
//
// A builder is not safe for concurrent use. Orchestration serializes graph
// mutations or synchronizes around the builder; no locking is added here for a
// requirement that does not exist yet.
//
// A builder may be frozen more than once. Each Freeze returns an independent
// Graph, and later mutation of the builder leaves earlier graphs untouched.
type GraphBuilder struct {
	nodes map[EvidenceID]Evidence

	// Sets rather than slices so that recording the same relationship twice is
	// naturally idempotent. Freeze converts them to sorted slices.
	parents   map[EvidenceID]map[EvidenceID]struct{}
	blockedBy map[EvidenceID]map[EvidenceID]struct{}
}

// NewGraphBuilder returns an empty builder.
func NewGraphBuilder() *GraphBuilder {
	return &GraphBuilder{
		nodes:     make(map[EvidenceID]Evidence),
		parents:   make(map[EvidenceID]map[EvidenceID]struct{}),
		blockedBy: make(map[EvidenceID]map[EvidenceID]struct{}),
	}
}

// AddEvidence records one piece of evidence.
//
// The evidence must already be valid: it comes from NewEvidence, which has
// checked it. The builder only enforces the graph-level invariant that an
// identifier appears once.
//
// A repeated identifier is rejected even when the evidence is identical. There
// is no merge and no last-write-wins, because a silent overwrite would hide the
// orchestration bug that produced two nodes for one step.
func (b *GraphBuilder) AddEvidence(e Evidence) error {
	if e.IsZero() {
		return fmt.Errorf("%w: cannot add the zero Evidence", ErrInvalidGraph)
	}
	if _, exists := b.nodes[e.ID()]; exists {
		return fmt.Errorf("%w: evidence %q is already in the graph", ErrInvalidGraph, e.ID())
	}
	b.nodes[e.ID()] = e
	return nil
}

// AddParent records that child derives from or follows parent.
//
// Argument order is child first, then parent: the call reads as "add this
// parent to this child". A node may have several parents, which is what makes
// the structure a DAG rather than a tree.
//
// Both nodes must already be present. Forward references are not accepted,
// because requiring the nodes first turns a typo into an immediate error rather
// than one that surfaces at Freeze with no context.
//
// Recording the same edge twice is idempotent. Orchestration may legitimately
// discover the same relationship more than once, and the structure it describes
// is unchanged.
//
// The edge is rejected if it would introduce a cycle. Checking here rather than
// only at Freeze reports the problem at the call that caused it; Freeze
// re-validates the whole graph regardless.
func (b *GraphBuilder) AddParent(child, parent EvidenceID) error {
	if err := b.requireNode("child", child); err != nil {
		return err
	}
	if err := b.requireNode("parent", parent); err != nil {
		return err
	}
	if child == parent {
		return fmt.Errorf("%w: evidence %q cannot be its own parent", ErrInvalidGraph, child)
	}
	// Adding child -> parent closes a cycle exactly when child is already
	// reachable from parent by following parent edges.
	if reachable(b.parents, parent, child) {
		return fmt.Errorf(
			"%w: making %q a parent of %q would create a cycle", ErrInvalidGraph, parent, child)
	}
	addToSet(b.parents, child, parent)
	return nil
}

// AddBlockedBy records that skipped did not run because of blocker.
//
// Argument order is the skipped evidence first, then what blocked it.
//
// This is stored separately from parent edges because it means something a
// parent edge does not. A parent can mean sequence or derivation; a blocked-by
// reference is the explanation a report needs to answer "why was TLS never
// checked?".
//
// Only evidence in the SKIPPED state may carry one. Any other state either ran
// or produced a result, so claiming something prevented it from running is
// self-contradictory.
//
// The relationship is recorded, never inferred. Deciding that a failed DNS
// lookup should stop a TCP attempt is an execution decision, and the graph does
// not make it.
func (b *GraphBuilder) AddBlockedBy(skipped, blocker EvidenceID) error {
	if err := b.requireNode("skipped evidence", skipped); err != nil {
		return err
	}
	if err := b.requireNode("blocker", blocker); err != nil {
		return err
	}
	if skipped == blocker {
		return fmt.Errorf("%w: evidence %q cannot block itself", ErrInvalidGraph, skipped)
	}
	if state := b.nodes[skipped].State(); state != StateSkipped {
		return fmt.Errorf(
			"%w: evidence %q is %s, only SKIPPED evidence can be blocked", ErrInvalidGraph, skipped, state)
	}
	if reachable(b.blockedBy, blocker, skipped) {
		return fmt.Errorf(
			"%w: making %q block %q would create a cycle", ErrInvalidGraph, blocker, skipped)
	}
	addToSet(b.blockedBy, skipped, blocker)
	return nil
}

// Freeze validates the accumulated structure and returns an immutable Graph.
//
// Everything the incremental checks enforce is verified again over the whole
// structure, so a Graph cannot exist in an invalid state even if a future
// builder change lets something slip through.
//
// The returned Graph owns its data. Continuing to use the builder afterwards is
// allowed and does not affect any Graph already returned.
func (b *GraphBuilder) Freeze() (Graph, error) {
	order := make([]EvidenceID, 0, len(b.nodes))
	for id := range b.nodes {
		order = append(order, id)
	}
	slices.Sort(order)

	nodes := make(map[EvidenceID]Evidence, len(b.nodes))
	for id, e := range b.nodes {
		nodes[id] = e
	}

	parents, err := b.freezeRelation(b.parents, "parent")
	if err != nil {
		return Graph{}, err
	}
	blockedBy, err := b.freezeRelation(b.blockedBy, "blocked-by")
	if err != nil {
		return Graph{}, err
	}

	for id := range b.blockedBy {
		if state := b.nodes[id].State(); state != StateSkipped {
			return Graph{}, fmt.Errorf(
				"%w: evidence %q is %s but has blocked-by references", ErrInvalidGraph, id, state)
		}
	}

	// Children are derived here rather than maintained alongside parents, so
	// the two views have a single source of truth and cannot drift apart.
	children := make(map[EvidenceID][]EvidenceID)
	for _, child := range order {
		for _, parent := range parents[child] {
			children[parent] = append(children[parent], child)
		}
	}
	for parent := range children {
		slices.Sort(children[parent])
	}

	return Graph{
		order:     order,
		nodes:     nodes,
		parents:   parents,
		children:  children,
		blockedBy: blockedBy,
	}, nil
}

// freezeRelation validates one relation and converts it to sorted slices.
func (b *GraphBuilder) freezeRelation(
	rel map[EvidenceID]map[EvidenceID]struct{}, label string,
) (map[EvidenceID][]EvidenceID, error) {
	out := make(map[EvidenceID][]EvidenceID, len(rel))

	for from, targets := range rel {
		if _, ok := b.nodes[from]; !ok {
			return nil, fmt.Errorf("%w: %s relation references absent evidence %q", ErrInvalidGraph, label, from)
		}
		ids := make([]EvidenceID, 0, len(targets))
		for to := range targets {
			if _, ok := b.nodes[to]; !ok {
				return nil, fmt.Errorf("%w: %s relation references absent evidence %q", ErrInvalidGraph, label, to)
			}
			if to == from {
				return nil, fmt.Errorf("%w: %s relation on %q references itself", ErrInvalidGraph, label, from)
			}
			ids = append(ids, to)
		}
		slices.Sort(ids)
		out[from] = ids
	}

	if cycle, found := findCycle(rel); found {
		return nil, fmt.Errorf("%w: %s relation contains a cycle through %q", ErrInvalidGraph, label, cycle)
	}
	return out, nil
}

// requireNode reports an explicit error when a relationship names a node that
// has not been added.
func (b *GraphBuilder) requireNode(label string, id EvidenceID) error {
	if _, ok := b.nodes[id]; !ok {
		return fmt.Errorf("%w: %s %q is not in the graph", ErrInvalidGraph, label, id)
	}
	return nil
}

// addToSet records to in the set for from, creating the set on first use.
func addToSet(rel map[EvidenceID]map[EvidenceID]struct{}, from, to EvidenceID) {
	set, ok := rel[from]
	if !ok {
		set = make(map[EvidenceID]struct{})
		rel[from] = set
	}
	set[to] = struct{}{}
}

// reachable reports whether target can be reached from start by following rel.
//
// Graphs here hold one run's evidence and stay small, so a plain depth-first
// walk is the right amount of machinery.
func reachable(rel map[EvidenceID]map[EvidenceID]struct{}, start, target EvidenceID) bool {
	if start == target {
		return true
	}
	seen := make(map[EvidenceID]struct{})
	stack := []EvidenceID{start}

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, done := seen[current]; done {
			continue
		}
		seen[current] = struct{}{}

		for next := range rel[current] {
			if next == target {
				return true
			}
			stack = append(stack, next)
		}
	}
	return false
}

// findCycle reports a node participating in a cycle, if there is one.
//
// It is a standard three-colour depth-first search: unvisited, on the current
// path, finished. A node reached while still on the current path closes a cycle.
func findCycle(rel map[EvidenceID]map[EvidenceID]struct{}) (EvidenceID, bool) {
	const (
		onPath   = 1
		finished = 2
	)
	mark := make(map[EvidenceID]int)

	var visit func(EvidenceID) (EvidenceID, bool)
	visit = func(id EvidenceID) (EvidenceID, bool) {
		switch mark[id] {
		case onPath:
			return id, true
		case finished:
			return "", false
		}
		mark[id] = onPath

		// Sorted so that the reported node is the same on every run for the
		// same structure, which keeps error messages reproducible.
		next := make([]EvidenceID, 0, len(rel[id]))
		for to := range rel[id] {
			next = append(next, to)
		}
		slices.Sort(next)

		for _, to := range next {
			if found, ok := visit(to); ok {
				return found, true
			}
		}
		mark[id] = finished
		return "", false
	}

	starts := make([]EvidenceID, 0, len(rel))
	for id := range rel {
		starts = append(starts, id)
	}
	slices.Sort(starts)

	for _, id := range starts {
		if found, ok := visit(id); ok {
			return found, true
		}
	}
	return "", false
}
