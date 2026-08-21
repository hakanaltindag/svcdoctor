# ADR 0010: Canonical evidence excludes raw objects and uncontrolled payloads

## Decision

Canonical evidence carries normalized values only.

Excluded from canonical evidence:

- raw protocol-library objects, such as wire response structs
- raw runtime objects, such as `tls.ConnectionState` or transport error values
- uncontrolled `map[string]any` payloads

The chain is:

```text
raw protocol/network result -> Observation -> normalized Evidence -> Diagnosis -> Finding
```

Normalization happens at the probe or adapter boundary. Diagnosis never receives a raw object.

## Context

Canonical evidence must preserve four properties at once:

- a stable schema, because JSON is the canonical report representation
- deterministic serialization, because diagnosis and reporting must be reproducible
- redaction safety, because structural redaction runs before serialization
- boundary integrity, because diagnosis must not become coupled to protocol libraries

An uncontrolled payload type defeats all four simultaneously: the schema drifts, output
ordering becomes unstable, arbitrary values can smuggle credential material into a report,
and library types leak across an architectural boundary.

## Handling complex service data

When a service needs to express complex data, prefer:

- a normalized scalar or list representation, or
- separate evidence nodes

## No speculative machinery

This boundary is a data contract, not a framework. Constructs such as `EvidenceProvider`,
`ObservationFactory`, `EvidenceProcessor`, `ProbeResultFactory`, or
`GenericEvidenceNormalizer` must not be introduced without a demonstrated need.

## Consequences

- Diagnosis rules and their tests are independent of protocol library choices.
- Report schema stability can be asserted by test.
- Structural redaction is guaranteed by the shape of the model rather than by pattern matching.
