# svcdoctor

`svcdoctor` is a client-vantage connection and topology diagnostic CLI for distributed services.

## Project status

This repository is currently **scaffold and design stage**. No Go implementation exists yet.

The first implementation target will be Kafka. PostgreSQL follows after the Kafka vertical slice is complete and validated.

| | |
|---|---|
| Repository | `github.com/hakanaltindag/svcdoctor` |
| Future Go module path | `github.com/hakanaltindag/svcdoctor` |
| License | Apache-2.0 (ADR 0006; `LICENSE` file added during bootstrap) |

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

Directories below are scaffold only. They contain no Go code.

```text
svcdoctor/
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
