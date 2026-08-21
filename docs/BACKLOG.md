# Backlog

## Repository state

Repository and tooling bootstrap exists, and the following packages are implemented:

- `internal/security` — Phase 1.1 security primitives
- `internal/domain` — Phase 1.2 domain primitives

Not implemented: `internal/probe`, `internal/adapter`, `internal/diagnosis`,
`internal/render`, `internal/platform`, `internal/app`, and the CLI. Those directories
contain no Go code.

A checked box below means the item exists and validates. A checked box in the documentation
or bootstrap sections does **not** mean any architecture is implemented. Nothing may be
assumed implemented unless a corresponding Go package actually exists.

## Open decisions

Deliberately left open until implementation reveals the real boundary:

- Attribute-key ownership between adapter and diagnosis for a given service.
  Phase 1.3a added the generic `domain.AttributeKey` type. That does **not** settle
  where service-specific key constants live, and this package must not grow a
  registry of them.
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

### Repository bootstrap (complete)

- [x] Apache-2.0 `LICENSE`
- [x] Go module initialization (`github.com/hakanaltindag/svcdoctor`, Go 1.26)
- [x] Local quality-gate `Makefile` (`fmt`, `fmt-check`, `test`, `vet`, `lint`, `build`, `check`)
- [x] golangci-lint configuration (v2 format, pinned `v2.13.1`)
- [x] GitHub Actions CI workflow

Tooling only. No architecture is implemented by any of the above.

Deferred architecture lint rules, to activate as the packages gain Go code:

- [ ] depguard rule for the adapter contract / registry package (placement still open)
- [ ] depguard rule for CLI orchestration (placement still open)
- [ ] Kafka adapter must not implement generic DNS/TCP/TLS transport (needs an import-level
      expression once `internal/adapter/kafka/` exists; not expressible as a package deny today)
- [ ] `noctx` / `bodyclose` once network-facing code exists
- [ ] `gosec` once there is code with meaningful signal

### Phase 1.1 — Security primitives (complete)

Implemented in `internal/security/`, standard library only:

- [x] `Secret` value type with masked String/GoString/Format/JSON/text output
- [x] `Reveal` as the single audited plaintext escape hatch
- [x] `Credential` bound to an endpoint at construction, readable only via `SecretFor`
- [x] `Endpoint` normalization and comparison (ASCII DNS casing, IPv6, zones)
- [x] `ForwardingPolicy` with `deny` as the zero value
- [x] Canary-based leak tests across fmt, JSON, text, reflection and error paths

Scope note: this covers safe *value types* only. Secret source resolution and
structural report redaction are separate items below and are not started.

### Deferred security hardening

Tracked now, implemented when the required boundaries exist:

- [ ] Restrict and audit `security.Reveal` usage to explicitly approved low-level
      boundaries. Today it is greppable and documented, but nothing enforces where it
      may be called. Still deferred: no adapter wire package exists to confine it to,
      and inventing a path to point a lint rule at would be worse than waiting. As of
      Phase 1.6 there are zero call sites outside its own package and tests.
- [x] Preserve the full secret leak regression matrix whenever the representation or
      formatting of `Secret` changes. **Satisfied by executable tests, no extra CI
      mechanism needed.** Two matrices run under the ordinary `go test ./...` that
      `make check` already invokes: the Phase 1.1 secret matrix in
      `internal/security/leak_test.go`, which sweeps every fmt verb, JSON, text, error
      and reflection path, and the Phase 1.6 report matrix in
      `internal/security/redaction/redact_test.go`, which asserts hostname, IP, vantage
      and secret canaries are absent from every field, the canonical JSON and error
      strings. A change that reopens a leak fails the build rather than needing a
      separate guard.

### Phase 1.2 — Domain primitives (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `State` — PASS/FAIL/DEGRADED/UNKNOWN/SKIPPED with stable symbolic JSON
- [x] `Layer` — L0-L6 in the ADR 0007 order, ordered and comparable
- [x] `FailureClass` — service-neutral failure vocabulary, factual only
- [x] Normalized attribute value model — closed tagged union, no `map[string]any`
- [x] `Vantage` — first-class, storage only, no collection logic

Scope note: this is domain *vocabulary* only. Evidence, the evidence DAG, findings,
reports, and target normalization are separate items below and are not started.

### Phase 1.3a — Observation and Evidence node (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `EvidenceID` — caller-supplied, validated, comparable, usable as a map key
- [x] `Step` and `AttributeKey` — validated dotted names, no central registry
- [x] `Subject` / `SubjectKind` — generic target or endpoint reference
- [x] `Evidence` — immutable node with attributes, timing and state/failure invariants
- [x] Evidence-level canonical JSON

**`Observation` is intentionally not a domain type, and should not be added here later.**
An observation is producer-shaped by definition: a DNS answer and a protocol capability
exchange have no common structure. A generic version could only be a duplicate of
`Evidence`, which adds a stage without adding a boundary, or a container of arbitrary
values, which ADR 0010 forbids. The stage is real but belongs to the producer: it
materializes as concrete typed structs inside the probe and adapter packages, which
normalize into `Evidence` at their own boundary. See the package documentation in
`internal/domain/doc.go`.

Deliberately deferred to Phase 1.3b rather than guessed at now:

- `Origin` (direct vs discovered). Its meaning is "how did this subject enter the run",
  which is a property of the expansion process rather than of a lone node. It has no
  consumer yet, and adding it now would lock a representation before topology exists.
- Parent edges, `BlockedBy`, and every other relationship between nodes.

### Phase 1.3b — Evidence DAG, builder and freeze (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `GraphBuilder` — mutable accumulation with graph-integrity validation
- [x] `Graph` — immutable, produced only by `Freeze`
- [x] Structural parent edges, multiple parents, idempotent duplicates
- [x] `BlockedBy` references, restricted to `SKIPPED` evidence
- [x] DAG validation — self edges and cycles rejected incrementally and at `Freeze`
- [x] Deterministic ordering by `EvidenceID`, never insertion order
- [x] Derived child index, so parents and children cannot disagree

Boundary and rationale: **ADR 0013**, summarized in `docs/ARCHITECTURE.md` section 11.1.

**Responsibilities that are deliberately not the graph's**, recorded so a later
change does not move them into `GraphBuilder`:

- **Endpoint deduplication.** Deciding two endpoints are the same execution target
  needs to know what an endpoint is, and the answer varies by service and vantage.
  The builder deduplicates identifiers and edges, never subjects.
- **Topology recursion depth and visited-endpoint tracking.** Cycle detection in the
  builder is graph integrity; "do not probe this endpoint again" is execution policy.
- **Execution scheduling, retries, timeouts, concurrency, layer progression.**
- **Short-circuit decisions.** The builder records that a step was skipped and what
  blocked it; deciding that a failed DNS lookup stops a TCP attempt happens in
  orchestration.

**`Origin` remains intentionally deferred.** Topology and discovery execution do not
exist yet, so nothing reads it, and adding it now would introduce a second place
recording how a subject entered the run alongside the graph structure itself, with no
implementation to show which should be authoritative. Whether explicit provenance is
necessary is a question only a real topology implementation can answer.

This is a deferral, not a rejection. **Revisit it when topology orchestration exists.**
See ADR 0013.

**`Graph.MarshalJSON` is deliberately not implemented.** `docs/REPORT_SCHEMA.md` places
evidence inside the report rather than defining a standalone graph object, so the
embedding shape is the report phase's decision. Serializing now would lock a schema that
phase would likely have to change. Determinism is verified through the ordering of
`Nodes`, `Parents`, `Children` and `BlockedBy` instead.

Not started, and not this package's work: short-circuit execution, endpoint dedup,
topology traversal, depth policy, probe execution.

### Phase 1.4a — Finding model (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `FindingCode` — format validated, namespace set left open, no catalog in core
- [x] `FindingKind` — `CONFIRMED` / `HYPOTHESIS`
- [x] `Severity` — `INFO` / `WARN` / `ERROR` / `CRITICAL`, ordering documented as contract
- [x] `Confidence` — `HIGH` / `MEDIUM` / `LOW`, ordinal only, never numeric
- [x] `Recommendation` — inert single action
- [x] `Finding` — immutable value with evidence references, vantage flag and discriminator

**Findings reference evidence by identifier only.** `Finding` validates that each
identifier is well formed; it never takes a `Graph` and never embeds `Evidence`.
Membership validation belongs to the report, which is the first thing owning both
sets. See **ADR 0014**.

**Deliberately not implemented here:** diagnosis rules or engine, any concrete
finding rule, exit-code mapping (`Severity` is data; the contract lives in
`docs/SCOPE.md`), `RecommendationRisk` and a recommendation reference link (listed
in `docs/FINDINGS.md` as "recommended when relevant", but nothing consumes them and
no renderer exists), and `affectedResources`.

### Phase 1.4b — Canonical report model (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `SchemaVersion` constant (v1), never caller-supplied
- [x] `RunMetadata` — caller-supplied facts only, no clock or environment access
- [x] `ServiceID` — format validated, service set left open
- [x] `Target` — requested vs normalized, no per-service target type, no secret-bearing field
- [x] `ReportSecurity` + `OutputMode`
- [x] `Summary` — derived, with fixed aggregation rules (ADR 0015)
- [x] `Report` — immutable assembly with canonical JSON v1
- [x] **ADR 0014 acceptance criterion: every `Finding` evidence reference must resolve to a
      node in the report's `Graph`, or the whole construction fails**
- [x] Canonical finding ordering, independent of input order
- [x] Evidence encoded as separate `nodes` and `relationships` sections (ADR 0016)

**Deliberately not implemented, with reasons recorded in `docs/REPORT_SCHEMA.md`:**

- Execution mode — no defined vocabulary; `vantage` owns "where" and the summary owns
  incompleteness.
- Redacted-field counts and categories — no redactor exists, so any value would be
  fabricated.
- `SHAREABLE_REDACTED` output mode — rejected at construction until redaction exists, so a
  report cannot claim a transformation that never ran.
- Exit-code computation — the contract lives in `docs/SCOPE.md` and belongs to the CLI.

### Phase 1.5 — Diagnosis engine (complete)

Implemented in `internal/diagnosis/`, standard library plus `internal/domain` only,
zero interfaces:

- [x] `Rule` contract — `func(domain.Graph) []domain.Finding`, owned by
      `internal/diagnosis` (ADR 0017)
- [x] `Engine` — immutable rule set, deterministic evaluation, canonical ordering
- [x] `domain.SortFindings` exported so the engine and the report share one
      definition of canonical order
- [x] Purity enforced by depguard rather than convention

**No concrete rules were implemented, and the reason is a missing policy rather than
missing work.** `docs/FINDINGS.md` names `DNS_RESOLUTION_FAILED`,
`TCP_CONNECTION_REFUSED` and `TLS_CERTIFICATE_EXPIRED` only as examples of the naming
convention; it assigns them no severity, confidence or kind. Kind and confidence are
derivable from evidence state, severity is not. See ADR 0017.

Two questions must be answered before the first transport rule is written:

- [ ] **Severity policy for transport failures.** Severity is impact, and whether a
      failed lookup or refused connection prevents correct use depends on whether the
      endpoint was user-supplied or discovered. That distinction is `Origin`, deferred
      by ADR 0013 until topology orchestration exists.
- [ ] **Generic/service rule overlap.** `docs/FINDINGS.md` section 5 forbids
      manufacturing downstream failure findings, but nothing says how a generic
      transport rule and a service rule avoid both reporting one failed endpoint —
      `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` and a generic `TCP_CONNECTION_REFUSED`
      would otherwise describe the same fact twice.

Also deferred:

- [ ] **Finding identity**, needed only if a real rule set produces duplicates. The
      engine preserves them today rather than guessing which to discard (ADR 0017).

### Phase 1.6 — Structural redaction (complete)

Implemented in `internal/security/redaction/`, standard library plus `internal/domain`
only, zero interfaces:

- [x] `Redact` — `LOCAL_FULL` report to `SHAREABLE_REDACTED` report
- [x] Deterministic per-report pseudonyms, assigned from a sorted collection pass
- [x] Evidence identifier remapping, with every reference rewritten (ADR 0014 still passes)
- [x] Target, vantage, subject, attribute and prose redaction
- [x] `SHAREABLE_REDACTED` activated, with derived `RedactionCounts` metadata
- [x] Idempotent: an already-shareable report is returned unchanged
- [x] Fail-closed, with a residual scan over known values as a safety net
- [x] Purity enforced by depguard, including a ban on `regexp`

**Known limit, recorded in `docs/SECURITY.md` and ADR 0018:** an attribute value that
carries identity in a shape the transformation cannot recognize structurally, and that
appears nowhere else in the report, is preserved. Closing this needs per-key sensitivity
classification, which is tied to the open attribute-key ownership decision below.

### Phase 1 — Core Foundations: COMPLETE

Present: security primitives, domain primitives, evidence, immutable evidence DAG,
finding model, canonical report, diagnosis engine, structural redaction.

Deliberately absent, and belonging to Phase 2 or later: DNS/TCP/TLS probes, connection
ownership transfer, the short-circuit execution engine, service adapters, Kafka,
PostgreSQL, topology execution, the CLI, and terminal/Markdown/HTML renderers.

Zero runtime dependencies. Every layer above is a pure value model or a pure
transformation over one, which is what makes the whole of Phase 1 testable without a
network.

### Implementation (not started)

- [ ] Adapter registration boundary
- [ ] Concrete transport rules under `internal/diagnosis/transport/`
- [ ] Exit-code mapping at the CLI boundary
- [ ] Short-circuit execution and layer progression (orchestration, not the graph)
- [ ] Endpoint deduplication and topology depth policy (orchestration, not the graph)
- [ ] Target normalization
- [ ] Report schema v1 implementation
- [ ] Timeout/cancellation implementation
- [ ] Secret source resolution (stdin, file, env, external references)
- [ ] Structural report redaction and shareable-report pseudonymization
- [ ] Credential-forwarding wiring into topology discovery and the CLI
- [ ] Redaction leak fixtures for reports
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
