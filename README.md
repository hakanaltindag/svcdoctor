# svcdoctor

`svcdoctor` is a client-vantage connection and topology diagnostic CLI for distributed services.

## Project status

**Phases 1 and 2 are complete, and Phase 3 — the Kafka vertical slice — is in progress. The
tool is not usable yet**: it can sweep one endpoint end to end, ask every reachable broker for
its API versions and which SASL mechanisms it offers, authenticate to one chosen broker with
SASL/PLAIN, ask that broker to describe the cluster's brokers, measure every endpoint that
broker advertised, and produce an evidence graph. Nothing interprets or presents that yet,
because no diagnosis rule, renderer or CLI exists.

**svcdoctor now transmits credentials, under a contract written before the first byte.** A
password is sent only over a channel whose peer identity was verified — never plaintext, never
TLS with verification disabled — and a refusal is recorded as a `SKIPPED` node with
`EXEC_SKIPPED_BY_POLICY` rather than as silence. A credential is authorized by the logical
endpoint the operator named, never by an address it resolved to, so DNS cannot widen its
authority. Authentication takes exactly one session, never a list, so the adapter cannot choose
which broker receives a credential. `security.Reveal`, the one function that turns a masked
secret into plaintext, is confined by lint to adapter wire packages and has **exactly one call
site** (ADR 0027, ADR 0028, ADR 0030).

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
- `internal/adapter/kafka` — the Kafka adapter boundary, ApiVersions evidence (Phase 3.1),
  SASL mechanism discovery (Phase 3.2a), channel propagation (Phase 3.2b), SASL/PLAIN
  authentication (Phase 3.2c), Metadata topology discovery (Phase 3.3) and advertised
  endpoint reachability (Phase 3.4)
- `internal/adapter/kafka/wire` — the only importer of the Kafka protocol library, and the only
  package permitted to call `security.Reveal`

**Discovered endpoints are measured, never spoken to, and never given a credential.** Metadata
tells svcdoctor which brokers a cluster advertises, and each advertisement becomes its own
evidence node parented to the exchange that carried it. Reachability then measures those
endpoints with the generic transport chain — DNS, TCP and TLS — and stops: no Kafka request
reaches a discovered broker, no credential can, and there is no recursion to bound. The
transport plan is supplied by the caller rather than guessed from a port or copied from the
bootstrap connection, because a Metadata response says nothing about what a listener speaks
(ADR 0031, ADR 0033).

**Two advertisements naming one endpoint produce two measurements.** That redundancy is
deliberate: a deduplicated sweep would have two causes and one effect, and the graph could only
record it by picking one advertisement as *the* cause and silently leaving the other with no
measurement attached. Truthful attribution was chosen over saving a bounded number of
credential-free connections (ADR 0033).

**svcdoctor now produces its first finding.** Phase 3.5 decided what may be concluded from
advertised-endpoint reachability evidence and Phase 3.6 implemented it, inventing nothing: the
Kafka finding owns those transport failures outright so no generic finding duplicates them, an
unreachable advertised broker is `ERROR` because severity is the impact of a finding's claim
about its own subject, a partially reachable endpoint gets no finding because svcdoctor does
not observe which address a client would select, and an unfinished measurement never becomes a
remote failure — it becomes a `HYPOTHESIS` at `WARN`, or nothing at all. `Origin` was examined
a third time and stays deferred (ADR 0034).

- `internal/diagnosis/kafka` — the Kafka rules: `AdvertisedEndpointUnreachable` behind
  `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` (Phase 3.6), and `UnusableAdvertisement` behind
  `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` (Phase 3.7)
- `internal/service/kafka` — a leaf holding the three Kafka constants both the adapter and the
  rule name. It imports `internal/domain` and nothing else

**A second finding covers what the first deliberately cannot.** When Metadata reports a broker
with no host, or a port outside the range a port can occupy, no endpoint exists to measure and
"unreachable" would be false — nothing was reached because nothing was tried.
`KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` states that narrower claim, and it is the first finding
marked `vantageDependent: false`: the defect is in the values the cluster reported, so no other
network position sees anything different. It stops short of naming a cause, because Metadata
says what a broker reports and never how it arrived at it (ADR 0035).

**The rule anchors at the advertisement and walks down.** It enumerates the advertisement
nodes and follows derivation edges to the sweep each one caused; it never meets a transport
failure and asks what that failure is about. That direction is what lets it say "the cluster
answered, and then advertised an address this client cannot reach" without ever inferring how
an endpoint entered the run — which is why the same host being both bootstrap target and
advertised broker stays two honest measurements and one finding.

**The Kafka slice is validated against a real cluster.** `make integration-kafka` runs the
whole vertical — DNS, TCP, TLS, ApiVersions, SASL/PLAIN, Metadata, advertised-endpoint
reachability, diagnosis and redaction — against three real Apache Kafka 4.0 brokers in KRaft
mode, and differentially against `kcat`. Broker identifiers, advertised endpoints and topology
agree exactly; injected DNS, TCP and TLS failures produce exactly the findings the policy
authorizes and no others; a partially reachable endpoint produces none. See
[`docs/validation/KAFKA_PHASE3_VALIDATION.md`](docs/validation/KAFKA_PHASE3_VALIDATION.md).
It needs Docker and is deliberately not part of `make check`.

What is not implemented: SCRAM and every other SASL mechanism, protocol checks against
discovered brokers, topic and partition analysis, PostgreSQL, generic transport rules,
renderers and the CLI. Those directories contain no Go code. svcdoctor also cannot yet reach
Metadata on a cluster with no SASL, which is this repository's restriction rather than Kafka's
(ADR 0031).

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
