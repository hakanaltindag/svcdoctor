# ADR 0009: Explicit composition-root service registration

## Decision

Services are registered explicitly at a single composition root.

Accepted:

```text
registry.Register(kafka)
registry.Register(postgres)
registry.Register(redis)
```

Rejected:

- central service branching (`if kafka ... else if postgres ...`)
- magic `init()` auto-registration
- reflection-based plugin discovery
- a generic plugin framework

## Context

Central branching couples every future service to shared code. Implicit registration avoids
the branching but replaces it with hidden global state that is harder to test, harder to
reason about, and dependent on import side effects.

An explicit list at one wiring point is not sprawl. Adding a service changes that one point
and adds service-specific packages; it does not require edits across unrelated adapters,
probes, diagnosis rules, or renderers.

## Adapter contract sizing

The registration boundary may be defined early. The shared adapter contract must stay
minimal:

- keep the contract as small as the Kafka implementation actually requires
- let the real Kafka implementation reveal what belongs in it
- treat PostgreSQL as the second real implementation that validates any shared abstraction
- do not create speculative generic interfaces for a single implementation

Concrete structs first. Interfaces only at real boundaries.

## Consequences

- Adding a service changes one wiring point plus new service-specific packages.
- Registration is explicit, ordered, and testable without import side effects.
- The adapter contract grows from demonstrated need rather than anticipated need.
