# Backlog

## Repository state

No Go implementation exists yet. The repository contains directory scaffold, architecture
documentation, and decision records only.

A checked box in the documentation section below means a decision was recorded, not that code
exists. Nothing may be assumed implemented unless a corresponding Go package actually exists.

## Open decisions

Deliberately left open until implementation reveals the real boundary:

- Attribute-key ownership between adapter and diagnosis for a given service.
- Contract-package placement for the Adapter contract, registry, probe chain contract,
  diagnosis `Rule` contract, and CLI orchestration.

See `docs/ARCHITECTURE.md` section 18.

## Phase 0 — Architecture and safety foundation

### Documentation and decisions (complete)

- [x] Initial repository directory scaffold
- [x] Architecture documentation and decision records
- [x] License selected: Apache-2.0 (ADR 0006)
- [x] Module path selected: `github.com/hakanaltindag/svcdoctor`
- [x] Canonical report model documented (`docs/REPORT_SCHEMA.md`)
- [x] Finding code convention and catalog documented (`docs/FINDINGS.md`)
- [x] Exit-code contract documented (`docs/SCOPE.md`)
- [x] CLI service-subcommand decision documented (ADR 0011)
- [x] Vantage semantics documented (ADR 0012)
- [x] Timeout/cancellation/concurrency semantics documented (`docs/ARCHITECTURE.md` section 13)

The items above are documentation decisions only. No code exists for any of them.

### Bootstrap and implementation (not started)

- [ ] `LICENSE` file (Apache-2.0)
- [ ] `go.mod` for `github.com/hakanaltindag/svcdoctor`
- [ ] Adapter registration boundary
- [ ] Domain primitives for observations/evidence/findings/reports
- [ ] Report schema v1 implementation
- [ ] Vantage model implementation
- [ ] Timeout/cancellation implementation
- [ ] Secret wrapper and redaction boundary
- [ ] Endpoint credential policy implementation
- [ ] Redaction leak fixtures
- [ ] Exit-code implementation

## Phase 1 — Generic L0-L3 engine

- [ ] Target normalization
- [ ] DNS probe with latency and multi-address observations
- [ ] TCP probe per resolved address
- [ ] TLS handshake probe
- [ ] certificate chain/SAN/expiry observations
- [ ] live connection ownership transfer to protocol adapters
- [ ] short-circuit behavior
- [ ] evidence DAG builder
- [ ] deterministic fixtures/tests

## Phase 2 — Kafka vertical slice

- [ ] Add Kafka wire dependency with license/security review
- [ ] ApiVersions (L4)
- [ ] SASL mechanism discovery (L5)
- [ ] PLAIN
- [ ] SCRAM-SHA-256
- [ ] SCRAM-SHA-512
- [ ] supplied-token OAUTHBEARER
- [ ] mTLS
- [ ] Metadata discovery (L6)
- [ ] normalize broker endpoints
- [ ] probe every advertised endpoint from the current vantage
- [ ] `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` rule
- [ ] protocol/security mismatch rules
- [ ] privilege-aware skipped states
- [ ] Kafka integration environment/fixtures
- [ ] JSON + Markdown report acceptance tests

## Phase 3 — PostgreSQL

Start only after Kafka acceptance criteria are complete.

- [ ] SSLRequest/TLS
- [ ] startup/protocol negotiation evidence
- [ ] auth-type evidence
- [ ] sslmode/certificate correlation
- [ ] pg_hba bisection evidence
- [ ] multi-host DSN verification
- [ ] per-IP role discovery
- [ ] minimal replication/slot signals

## Phase 4 — Platform/reporting/distribution

- [ ] Kubernetes context behind an explicit dependency/build strategy
- [ ] Strimzi context
- [ ] CNPG context
- [ ] self-contained HTML renderer
- [ ] GoReleaser
- [ ] signing/SBOM/provenance
- [ ] multi-OS/multi-arch release validation

## Phase 5 — Validation

- [ ] Run against at least 10 real connection/auth/TLS/topology incidents
- [ ] Measure first-broken-layer accuracy
- [ ] Measure false positives
- [ ] Validate shareable-report usefulness
- [ ] Decide whether to expand to a third service
