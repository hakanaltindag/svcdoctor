# ADR 0016: The report owns canonical serialization; the graph has none

## Status

Accepted.

## Decision

`Report` defines the canonical JSON contract. `Graph` implements no `MarshalJSON`
and is not a public serialization contract.

Within the report's `evidence` section, nodes and relationships are separate:

```json
"evidence": {
  "nodes": [ { "id": "...", "layer": "L1", "state": "PASS", ... } ],
  "relationships": [
    { "id": "...", "parents": ["..."], "blockedBy": ["..."] }
  ]
}
```

Nodes are encoded by `Evidence.MarshalJSON`. Relationships are read from the
graph and listed separately, in the graph's canonical `EvidenceID` order, and
only for nodes that have any.

This is schema v1 behavior.

## Context

Two questions had to be settled together: who owns the external shape, and how
graph structure appears in it.

**Ownership.** Giving `Graph` a `MarshalJSON` would create a second serialization
contract with no consumer. A graph's in-memory API and the report schema are
separate concerns that would then have to be kept in step, and any future report
change would risk leaving the standalone encoding behind. The report is the only
thing anyone serializes, so the report defines the shape.

**Placement.** `docs/REPORT_SCHEMA.md` section 5 lists `parent / parents` among an
evidence node's conceptual fields, which suggests attaching relationships to each
node. That list describes the information a report must carry, and it predates
ADR 0013, which then established that relationships are graph-owned rather than
properties of a fact.

Attaching parents to each encoded node would contradict that separation in the
wire format, and it would also require restating every evidence field in the
report package to build the augmented object, leaving two definitions of how a
node is written that could drift apart.

Separate sections keep `Evidence.MarshalJSON` as the single definition of a node,
keep relationships in one place with one owner, and make the encoded form say what
the architecture says. The information content is identical either way: exact
identifiers plus deterministic ordering, which is what section 5 requires.

## Consequences

- `Evidence.MarshalJSON` is the only definition of how a node is encoded.
- Relationships appear once, not scattered across nodes.
- The encoding is deterministic without extra work: both lists follow the graph's
  canonical order and no map is iterated.
- A renderer reads nodes and relationships as two lists and joins them by
  identifier.
- If a consumer ever needs a standalone graph encoding, it can be added then, with
  this report shape as the reference rather than as a competitor.
