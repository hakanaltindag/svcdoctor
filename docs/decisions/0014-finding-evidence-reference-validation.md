# ADR 0014: Findings reference evidence by identifier; the report validates membership

## Status

Accepted.

## Decision

A `Finding` names the evidence that produced it by `EvidenceID` and nothing more.

`Finding` validates that each identifier is individually well formed. It does not
check that an identifier resolves to a node in an evidence graph, and it does not
take a `Graph` as a construction dependency.

The cross-object invariant

> every `Finding` evidence reference must resolve to an `Evidence` node in the
> report's `Graph`

is validated when a report is constructed, because a report is the first thing
that owns both sets.

`Finding` also never embeds `Evidence` values. A reference is an identifier, not a
copy of the fact.

## Context

A finding must be traceable: a reader has to be able to answer "why did svcdoctor
say this?" from the report alone, without rerunning a probe. That requirement is
satisfied by carrying exact identifiers, and it says nothing about who checks that
those identifiers resolve.

Two placements were possible for that check.

Validating inside `Finding` would mean `NewFinding` takes a `Graph`. Every finding
would then depend on a graph, a diagnosis rule could not build a finding before it
had one, and tests for finding values would have to construct graphs to exercise
unrelated validation. It would also invert the intended direction: the value model
would depend on the container that holds it.

Embedding `Evidence` values inside a finding would make the reference always
resolvable, but it duplicates every referenced fact into the findings section,
gives the same evidence two representations that can disagree, and grows the report
by a copy per reference. ADR 0013 already rejects the mirror of this for the same
reason: relationships are stored once, in one place, with one owner.

Validating at report construction keeps `Finding` a free-standing value, keeps the
check in the only place where both sides are present, and reports a dangling
reference as what it is: an inconsistency between two parts of one report.

## Consequences

- `Finding` is constructible and testable without any graph.
- Diagnosis can emit findings while holding only the identifiers it read.
- A dangling reference is caught once, at report construction, rather than
  partially and repeatedly at each finding.
- The report phase must implement that check. It is recorded as an open item in
  `docs/BACKLOG.md` so it is not forgotten.
- If a future requirement forces earlier validation, it belongs at whatever
  boundary owns both the findings and the graph, not inside the value type.
