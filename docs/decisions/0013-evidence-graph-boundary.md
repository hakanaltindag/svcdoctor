# ADR 0013: Evidence graph boundary

## Status

Accepted.

## Decision

The evidence graph is a structural container. It stores which evidence exists and
how the pieces relate. It does not decide execution semantics.

### Evidence versus Graph

`Evidence` represents one canonical normalized fact. `Graph` owns the relationships
between facts.

Relationships are not stored on `Evidence`. A parent reference on a node would make
each fact carry a claim about the run's shape, which is not what the fact observed,
and would give the same relationship two homes. Relationships must not be moved onto
`Evidence` for convenience later.

### Construction boundary

```text
mutable GraphBuilder
        |
        | AddEvidence / AddParent / AddBlockedBy
        v
     Freeze()
        v
  immutable Graph
```

Diagnosis consumes the immutable `Graph`, never `GraphBuilder`.

The implementation uses two separate concrete types rather than one type with a
`frozen` flag and mutation methods still present. Diagnosis must be a pure function
over finished evidence, and a flag leaves that to discipline: the mutation methods
still exist and can still be reached. Two types make it a compile-time property.
`Graph` has no way to change.

A builder may be frozen more than once. Each `Freeze` returns an independent `Graph`,
and later mutation of the builder does not affect a graph already returned.

### Structural relationships

- Parent relationships are graph-owned.
- Multiple parents are allowed, so the structure is a DAG rather than a tree.
- Duplicate `EvidenceID` insertion is rejected, even when the evidence value is
  identical. There is no merge and no last-write-wins, because a silent overwrite
  would hide the orchestration bug that produced two nodes for one step.
- Duplicate structural edges are idempotent. Orchestration may discover the same
  relationship twice, and the structure it describes is unchanged.
- Cycles and self edges are rejected, both when an edge is added and again during
  `Freeze` over the whole structure.
- Relationships require both nodes to exist already. Forward references are not
  accepted, so a mistake surfaces at the call that made it.
- Canonical ordering is lexical `EvidenceID` order, independent of insertion order.
  Insertion order becomes nondeterministic once orchestration probes endpoints
  concurrently, and the canonical report must be byte-stable for the same content.

### BlockedBy

`BlockedBy` is stored separately from parent relationships because it means
something different.

- A parent is a structural or derivation relationship.
- A blocked-by reference is the explicit causal explanation for why a `SKIPPED`
  check did not execute. It is what lets a report answer "why was TLS never
  checked?".

Only evidence in the `SKIPPED` state may carry one. Any other state either ran or
produced a result, so claiming something prevented it from running is
self-contradictory.

The graph never infers a blocked-by relationship. Deciding that a failed DNS lookup
should stop a TCP attempt is an execution decision recorded by the
execution/orchestration layer; the graph stores and validates what it is told.

### Responsibility boundary

The graph is deliberately dumb. It must not own:

- endpoint semantic equality
- endpoint deduplication
- topology recursion
- topology visited sets
- topology depth limits
- retry behavior
- concurrency policy
- execution scheduling
- timeout policy
- authentication policy
- credential forwarding policy
- short-circuit decisions
- service-specific semantics

The graph may validate only its own structural integrity:

- duplicate `EvidenceID`
- missing references
- self-reference
- cycles
- invalid blocked-by structure

The distinction that matters most here is between cycle detection and a visited set.
Cycle detection inside the builder is graph integrity: a structure that loops back on
itself is not a DAG. "Do not probe this endpoint again" is execution policy, and it
depends on knowing what an endpoint is. They look similar and must not be conflated.

### Origin

`Origin`, distinguishing a user-supplied subject from a discovered one, remains
intentionally deferred.

- Topology and discovery execution do not exist yet, so nothing reads it.
- Adding it now risks creating a second source of truth about how a subject entered
  the run, alongside the graph structure itself, with no implementation to show which
  should be authoritative.
- Whether explicit provenance is necessary is a question only a real topology
  implementation can answer.

This is a deferral, not a rejection. Revisit it when topology orchestration exists,
at which point the requirement will be concrete enough to decide whether provenance
belongs on the node, in graph metadata, or nowhere.

## Context

Phase 1.3a produced a canonical `Evidence` node and deliberately left relationships
out of it. Phase 1.3b had to place those relationships somewhere, and the choice
determines whether diagnosis can be kept pure and whether the graph stays free of
execution concerns.

The risk this ADR guards against is drift. A graph that already holds nodes,
relationships, and a cycle check looks like a natural home for endpoint
deduplication, depth limits, and short-circuit rules. Each of those additions is
individually plausible and collectively turns a structural container into an
orchestration engine that diagnosis can no longer treat as inert data.

## Consequences

- Diagnosis can be a pure function over a frozen `Graph`, testable without a network.
- Reports are byte-stable for the same content regardless of probe concurrency.
- Adding topology later cannot require changing the graph, only what is recorded in it.
- `GraphBuilder` is not a topology engine and not an execution engine. A change that
  would make it one should be rejected with a reference to this ADR.
