# ADR 0011: CLI uses service-specific subcommands

## Status

**Accepted, and partially superseded by ADR 0041 — command-tree shape only.**

ADR 0041 moves the tree from service-first to action-first:

```text
svcdoctor diagnose postgres …      instead of      svcdoctor postgres …
```

**Everything else in this record stands, and ADR 0041 relies on it.** The service
remains a subcommand with its own flag set, its own help text and its own
validation — one level below the action rather than at the top — so the rationale
below is preserved rather than overturned. The CLI still holds no service switch,
subcommands still come from explicit registration (ADR 0009), and port-based
inference is still rejected outright.

The text below is left as written. It records what was decided and why, and the
"why" did not change.

## Decision

The primary CLI shape is a service-specific subcommand:

```text
svcdoctor kafka ...
svcdoctor postgres ...
```

Future services follow the same shape:

```text
svcdoctor redis ...
svcdoctor rabbitmq ...
```

Subcommands come from explicit service registration at the composition root (ADR 0009). The
CLI does not hold a service switch.

## Rejected

- `svcdoctor --service kafka ...` as the primary UX.
- Inferring the service type from port numbers.

## Rationale

Each service has genuinely different inputs. Kafka takes bootstrap endpoints and a security
protocol; PostgreSQL takes a DSN or multi-host target with an sslmode. A single flat flag set
covering every service would either become a union of unrelated flags or push service-specific
validation into shared code.

A subcommand gives each service its own flag set, its own help text, and its own validation,
without any of that leaking into the core.

Port-based inference is rejected outright. Ports are conventions, not facts. Guessing wrong
would make svcdoctor produce a confidently mislabelled diagnosis, which is the exact failure
mode the project's claim discipline exists to prevent.

## Consequences

- Adding a service adds a subcommand through the same registration point that adds its
  adapter and rules. No separate CLI edit, no central branching.
- Help output is generated from registered services rather than maintained by hand.
- A `--service` style flag may still exist later as a secondary convenience, but it is not the
  primary interface and must not become the path that shared code branches on.
