# v0.1 Scope

## Services

Only **Kafka + PostgreSQL** are in v0.1. Development is Kafka-first.

Order:

1. Generic architecture/core
2. Kafka vertical slice
3. PostgreSQL

## Layers

The authoritative layer order is:

- L0: input/config sanity and normalization
- L1: DNS
- L2: TCP
- L3: TLS
- L4: protocol / capability discovery
- L5: authentication / authorization
- L6: topology discovery and reachability

Protocol/capability discovery precedes authentication because that is the real wire order
for both v0.1 services. See ADR 0007.

L7-L8 signals are allowed only when required for correlation, read-only, privilege-aware, and tightly scoped.

## Kafka v0.1

Layer mapping:

```text
DNS -> TCP -> TLS -> ApiVersions -> SASL mechanism discovery / authentication
    -> Metadata -> topology verification
```

Target capabilities:

- bootstrap endpoint normalization
- DNS/TCP/TLS separation
- security-protocol mismatch evidence
- ApiVersions
- SASL mechanism discovery where possible
- PLAIN
- SCRAM-SHA-256/512
- supplied-token OAUTHBEARER
- mTLS
- Metadata topology discovery
- reachability verification of every advertised broker endpoint
- vantage-aware topology findings
- privilege-aware behavior
- minimal KRaft/cluster correlation signals after the core path is stable

Detect-and-explain only:

- GSSAPI/Kerberos
- AWS_MSK_IAM unless separately approved as an opt-in implementation

## PostgreSQL v0.1 — after Kafka

Layer mapping:

```text
DNS -> TCP -> TLS / SSLRequest -> Startup / protocol negotiation
    -> AuthenticationRequest / authentication -> multi-host / role discovery
```

Target capabilities:

- DNS/TCP
- PostgreSQL SSLRequest/TLS behavior
- certificate/sslmode diagnosis
- authentication-type evidence
- password/SCRAM(+PLUS)/certificate paths
- pg_hba-related bisection evidence
- multi-host DSN endpoint verification
- per-IP role discovery
- minimal replication/slot signals when permissions allow

Detect-and-explain only:

- GSS/Kerberos

Optional only after explicit decision:

- RDS IAM token support

## CLI shape

The primary interface is a service-specific subcommand:

```text
svcdoctor kafka ...
svcdoctor postgres ...
```

Subcommands come from explicit service registration at the composition root. Service type is
never inferred from port numbers. See ADR 0011.

## Outputs

v0.1 target outputs:

- Terminal
- JSON
- Markdown
- HTML

JSON is the canonical representation. Terminal, Markdown, and HTML are derived from the
canonical report model. HTML lands later in v0.1, once the core is stable.

The canonical report model is specified in `docs/REPORT_SCHEMA.md`.

## Exit code contract

| Code | Meaning |
|---|---|
| 0 | Diagnostic run completed and no `ERROR`/`CRITICAL` finding exists |
| 1 | Diagnostic run completed successfully, but `ERROR`/`CRITICAL` findings exist |
| 2 | User input / configuration / CLI usage error |
| 3 | svcdoctor internal execution error |
| 4 | Diagnostic run completed only partially because of cancellation or local execution budget exhaustion |

> **Exit code 1 means svcdoctor itself worked and found a target-side problem.**
> It must not be read as svcdoctor failing.

Codes 2 and 3 mean no usable diagnosis was produced. Codes 0, 1, and 4 mean a report exists.

When more than one code could apply, the precedence is:

```text
3 > 2 > 4 > 1 > 0
```

Code 4 outranks code 1 because incompleteness qualifies every conclusion in the report. A
partial run that found an `ERROR` still exits 4, and the findings remain in the report. This
precedence rule is a clarification of the contract, not a change to the meaning of code 4.

## Explicitly out of scope

Future services, deferred until Kafka + PostgreSQL are validated:

- Redis / Valkey
- RabbitMQ
- MySQL / MariaDB
- Elasticsearch / OpenSearch

Out of scope for v0.1 entirely:

- host mode / host agent
- eBPF
- Rust
- MCP server
- PDF generation
- tuning advisor
- long-term monitoring
- LLM-based core diagnosis
- generic rule scripting DSL

A third service is not added until Kafka + PostgreSQL have produced real validation signals.
