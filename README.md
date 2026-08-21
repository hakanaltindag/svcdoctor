# svcdoctor

`svcdoctor` is a client-vantage connection and topology diagnostic CLI for distributed services.

## Project status

**Phases 1 and 2 are complete, and Phase 3 — the Kafka vertical slice — has begun. The tool is
not usable yet**: it can sweep one endpoint end to end, ask every reachable broker for its API
versions and which SASL mechanisms it offers, and produce an evidence graph. Nothing interprets
or presents that yet, because no diagnosis rule, renderer or CLI exists.

**No credential has ever been sent.** SASL mechanism discovery is credential-free by protocol
definition — the request carries a mechanism name and nothing else — and authentication is
deliberately deferred behind four recorded decisions (ADR 0026). `security.Reveal`, the one
function that turns a masked secret into plaintext, is confined by lint to adapter wire
packages and has zero call sites (ADR 0027).

What is implemented, with one runtime dependency (`github.com/twmb/franz-go/pkg/kmsg`,
BSD-3-Clause, no transitive dependencies):

- `internal/security` — masked secret and endpoint-bound credential primitives
- `internal/security/redaction` — structural redaction into a shareable report
- `internal/domain` — domain primitives, evidence, the immutable evidence DAG, findings and
  the canonical report
- `internal/diagnosis` — the rule contract and a deterministic diagnosis engine
- `internal/probe` — the evidence identifier encoding every probe shares
- `internal/probe/dns` — the DNS probe, the first real I/O producer (Phase 2.1)
- `internal/probe/tcp` — the TCP probe and connection ownership transfer (Phase 2.2)
- `internal/probe/tls` — the TLS probe, which consumes and produces that ownership (Phase 2.3)
- `internal/probe/transport` — the generic transport chain: DNS → TCP per address → TLS (Phase 2.4)
- `internal/adapter/kafka` — the Kafka adapter boundary, ApiVersions evidence (Phase 3.1) and
  SASL mechanism discovery (Phase 3.2a)

What is not implemented: Kafka authentication, Metadata and topology, PostgreSQL, concrete
diagnosis rules, renderers and the CLI. Those directories contain no Go code.

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

Only `internal/domain`, `internal/security`, `internal/security/redaction`,
`internal/diagnosis`, `internal/probe`, `internal/probe/dns`, `internal/probe/tcp`,
`internal/probe/tls`, `internal/probe/transport` and `test/security` contain Go code. Every
other `internal/`, `cmd/` and `test/` directory below is scaffold and is empty.

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
│   │   ├── dns/                   # Generic DNS facts; phase 2.1
│   │   ├── tcp/                   # Generic TCP facts + connection ownership; phase 2.2
│   │   ├── tls/                   # Generic TLS facts + handshake ownership; phase 2.3
│   │   └── transport/             # Generic transport chain; phase 2.4
│   ├── adapter/
│   │   ├── kafka/                 # Kafka protocol semantics; phase 3
│   │   │   └── wire/              # the only importer of the Kafka protocol library
│   │   └── postgres/              # Reserved for phase 4
│   ├── diagnosis/
│   │   ├── transport/             # Cross-service transport-layer correlation
│   │   ├── kafka/                 # Kafka-specific diagnosis rules; phase 3
│   │   └── postgres/              # Reserved for phase 4
│   ├── render/                    # Terminal / JSON / Markdown / HTML renderers
│   ├── security/                  # Secret types + structural redaction
│   └── platform/
│       ├── kubernetes/            # Optional platform context; phase 5
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

The authoritative phase numbering and checklist live in
[`docs/BACKLOG.md`](docs/BACKLOG.md): Phase 1 Core Foundations (complete), Phase 2 Generic
Transport Engine, Phase 3 Kafka, Phase 4 PostgreSQL, Phase 5 productization/platform/
renderers, Phase 6 validation. The sequence below is the same work read as a narrative.

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
