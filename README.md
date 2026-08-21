# svcdoctor

`svcdoctor` is a client-vantage connection and topology diagnostic CLI for distributed services.

## Project status

**Phase 1 — Core Foundations is complete. The tool is not usable yet**: it cannot connect to
anything, because no probe, adapter or CLI exists.

What is implemented, with zero runtime dependencies:

- `internal/security` — masked secret and endpoint-bound credential primitives
- `internal/security/redaction` — structural redaction into a shareable report
- `internal/domain` — domain primitives, evidence, the immutable evidence DAG, findings and
  the canonical report
- `internal/diagnosis` — the rule contract and a deterministic diagnosis engine

What is not implemented: DNS/TCP/TLS probes, connection ownership transfer, the short-circuit
execution engine, service adapters, Kafka, PostgreSQL, topology execution, renderers and the
CLI. Those directories contain no Go code.

> **Picking this up with no context?** Start with **[`docs/PHASE1_HANDOFF.md`](docs/PHASE1_HANDOFF.md)**.
> It reconstructs the mental model, the locked invariants, the rejected alternatives and the
> open decisions, and it states exactly where Phase 2 may begin. Then read
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), the relevant records in
> [`docs/decisions/`](docs/decisions/README.md), and [`docs/BACKLOG.md`](docs/BACKLOG.md).

The first implementation target will be Kafka. PostgreSQL follows after the Kafka vertical slice is complete and validated.

| | |
|---|---|
| Repository | `github.com/hakanaltindag/svcdoctor` |
| Go module path | `github.com/hakanaltindag/svcdoctor` |
| Go version | 1.26 |
| License | Apache-2.0 (ADR 0006) |

## Development

```sh
make check     # full local quality gate: fmt-check, test, vet, lint, build
make fmt       # format sources in place
make help      # list targets
```

`make check` mirrors CI. Gates that require Go packages report `SKIPPED` until the first
package exists; they activate automatically at that point. No placeholder Go code exists to
make them artificially green.

Linting uses [golangci-lint](https://golangci-lint.run) `v2.13.1` (v2 config format).

## Architectural invariant

> **Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence. Renderers explain results.**

This separation is non-negotiable.

> **Extensibility comes from stable boundaries, not from maximizing abstractions.**

Concrete structs first. Interfaces only at real boundaries.

- Probes must remain protocol-agnostic wherever possible.
- Generic transport owns DNS/TCP/TLS and hands a live connection to the adapter when a protocol handshake needs one.
- Adapters own protocol semantics and topology discovery.
- Diagnosis consumes normalized evidence and must not perform network or protocol I/O.
- Renderers only transform diagnosis results into output formats.
- Service growth must not introduce central `if kafka`, `if postgres`, `if redis` dispatch sprawl.
- New services are registered explicitly at a single composition root.

## Layer order

```text
L0  Input / config normalization
L1  DNS
L2  TCP
L3  TLS
L4  Protocol / capability discovery
L5  Authentication / authorization
L6  Topology discovery
```

Protocol/capability discovery precedes authentication because that is the real wire order
for both v0.1 services.

## CLI shape

```text
svcdoctor kafka ...
svcdoctor postgres ...
```

Service-specific subcommands, sourced from explicit service registration. Service type is
never inferred from port numbers. See ADR 0011.

Exit codes are documented in `docs/SCOPE.md`. Exit code `1` means svcdoctor worked and found
a target-side problem; it does not mean svcdoctor failed.

## v0.1 scope

The product scope is intentionally narrow:

- Kafka first.
- PostgreSQL second.
- L0-L6 diagnostics are the core product surface.
- L7-L8 signals are allowed only when required for correlation.
- Outputs: terminal, JSON, Markdown, HTML.
- JSON is the canonical report model; terminal, Markdown, and HTML are derived from it.
- Security and redaction are architecture requirements, not follow-up work.

Deferred until the Kafka + PostgreSQL vertical slice is validated:

- Redis / Valkey
- RabbitMQ
- MySQL / MariaDB
- Elasticsearch / OpenSearch

Out of scope for v0.1: host mode, eBPF, MCP server, PDF generation, tuning advisor,
long-term monitoring, LLM-based core diagnosis, and generic rule scripting DSLs.

## Repository layout

The `internal/`, `cmd/`, and `test/` directories below are scaffold only. They contain no Go code.

```text
svcdoctor/
├── .github/
│   └── workflows/
│       └── ci.yml
├── cmd/
│   └── svcdoctor/                 # CLI entrypoint boundary; intentionally empty
├── internal/
│   ├── app/                       # Application orchestration
│   ├── domain/                    # Shared normalized domain/evidence model
│   ├── probe/
│   │   ├── dns/                   # Generic DNS facts
│   │   ├── tcp/                   # Generic TCP facts
│   │   └── tls/                   # Generic TLS facts
│   ├── adapter/
│   │   ├── kafka/                 # Kafka protocol + topology semantics
│   │   └── postgres/              # Reserved for phase 3
│   ├── diagnosis/
│   │   ├── transport/             # Cross-service transport-layer correlation
│   │   ├── kafka/                 # Kafka-specific diagnosis rules
│   │   └── postgres/              # Reserved for phase 3
│   ├── render/                    # Terminal / JSON / Markdown / HTML renderers
│   ├── security/                  # Secret types + structural redaction
│   └── platform/
│       ├── kubernetes/            # Optional platform context; phase 4
│       └── local/                 # Local vantage metadata only; no host doctor
├── test/
│   ├── integration/
│   │   ├── kafka/
│   │   └── postgres/
│   └── security/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── REPORT_SCHEMA.md
│   ├── FINDINGS.md
│   ├── SCOPE.md
│   ├── SECURITY.md
│   ├── BACKLOG.md
│   └── decisions/
├── .golangci.yml
├── Makefile
├── go.mod
├── LICENSE
└── .gitignore
```

Unit and package-level fixtures will live in package-adjacent `testdata/` directories once
the corresponding packages exist. `test/` holds cross-package and environment-dependent tests.

## Implementation order

1. Freeze architecture contracts and evidence schema.
2. Define secret handling and redaction contracts.
3. Implement generic DNS/TCP/TLS probes.
4. Implement Kafka transport and protocol discovery.
5. Implement Kafka metadata/topology verification.
6. Implement deterministic Kafka diagnosis.
7. Implement canonical JSON and Markdown output.
8. Validate the Kafka vertical slice.
9. Only then start PostgreSQL.

No production implementation should be added before the relevant architecture boundary is documented and reviewed.
