# ADR 0008: Kafka wire-client strategy

## Decision

`franz-go` remains the primary Kafka ecosystem direction.

Diagnostic correctness requires a controlled connection lifecycle with no hidden failover or
retry semantics. Therefore svcdoctor targets franz-go's low-level protocol primitives (such
as its wire message package) rather than depending on high-level client behaviour.

No dependency is added and no implementation is started by this decision.

## Context

High-level Kafka clients are built to keep an application working: they retry, reconnect,
and transparently switch brokers. Those behaviours are correct for a producer or consumer
and wrong for a diagnostic tool.

svcdoctor's primary topology finding asserts that a specific advertised endpoint is
unreachable from the current vantage point. A client that silently fails over to a reachable
broker destroys exactly the evidence that finding depends on. Retry wrappers also obscure
the original transport or protocol error, and background reconnection makes per-step timing
non-deterministic.

## Requirements

- Diagnosis must not depend on high-level client behaviour.
- Retry, failover, and automatic broker switching must not cause evidence loss.
- Kafka diagnostic transport must be deterministic.
- Connection lifecycle must be controlled by svcdoctor, including the live connection handed
  over by the generic transport layer (see `docs/ARCHITECTURE.md` section 4).

## Consequences

- Kafka protocol library coupling is confined to the narrowest possible boundary inside
  `internal/adapter/kafka/`. Code outside that boundary does not import Kafka wire types.
- Normalized observations, not library response objects, cross the adapter boundary, so
  diagnosis rules and their tests remain independent of the library choice.
- Replacing or upgrading the wire library stays a contained change.
