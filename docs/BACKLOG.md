# Backlog

## Repository state

Repository and tooling bootstrap exists. The following packages are implemented, with zero
runtime dependencies:

- `internal/domain` — domain primitives, evidence, the immutable evidence DAG, findings and
  the canonical report
- `internal/security` — masked secret and endpoint-bound credential primitives
- `internal/security/redaction` — structural redaction into a shareable report
- `internal/diagnosis` — the `Rule` contract and the deterministic `Engine`

No Go code exists in any of the following, and nothing in them may be assumed implemented:

- `internal/probe`
- `internal/adapter`
- `internal/render`
- `internal/platform`
- `internal/app`
- `cmd/svcdoctor`

So there are no probes, no DNS/TCP/TLS execution, no connection ownership transfer, no
short-circuit execution engine, no adapters, no Kafka, no PostgreSQL, no topology execution,
no renderers and no CLI. **The tool cannot connect to anything yet.**

`internal/diagnosis` ships the rule contract and the engine and **no concrete rules**. That
is a deliberate deferral with a recorded reason, not missing work; see Phase 1.5 and Phase 2
below.

A checked box means the item exists and validates. A checked box in the documentation or
bootstrap sections does **not** mean any architecture is implemented. Nothing may be assumed
implemented unless a corresponding Go package actually exists.

## Roadmap

This is the authoritative phase numbering for the whole repository. Any other numbering is
stale and should be corrected against this table.

| Phase | Title | Status |
|---|---|---|
| 0 | Architecture and safety foundation | Complete |
| 1 | Core Foundations | **Complete** |
| 2 | Generic Transport Engine | **Not started** |
| 3 | Kafka Vertical Slice | Not started |
| 4 | PostgreSQL Vertical Slice | Not started |
| 5 | Productization, Platform and Renderers | Not started |
| 6 | Real-world Validation and Hardening | Not started |

Phase 0 is documentation, decisions and tooling. Phase 1 is the pure value model and the
transformations over it. Phase 2 is the first code that touches a network.

The order is a dependency order, not merely a preference. PostgreSQL follows Kafka because
Kafka is the first real implementation that reveals which abstractions are genuine, and
PostgreSQL is the second one that validates them. See ADR 0005 and `docs/SCOPE.md`.

## Open decisions

Deliberately left open until implementation reveals the real boundary. Each names the
condition that should reopen it.

| Decision | Why deferred | Reopen when |
|---|---|---|
| **Transport severity policy** | Severity is impact, and whether a failed lookup or refused connection prevents correct use depends on whether the endpoint was user-supplied or discovered — that distinction is `Origin` | Phase 2 has produced real transport evidence (ADR 0017) |
| **`Origin` / provenance** | No consumer; topology discovery does not exist. Adding it now creates a second record of how a subject entered the run, with no implementation to say which is authoritative | Topology orchestration exists, in Phase 3 (ADR 0013) |
| **Generic vs service finding overlap** | Nothing says how a generic `TCP_CONNECTION_REFUSED` and a service `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` avoid describing one fact twice | The first service rules are written, in Phase 3 (ADR 0017) |
| **Finding identity / duplicate semantics** | Defining when two findings are one conclusion is guesswork today; the engine preserves duplicates rather than discarding a real finding | A real rule set produces duplicates in practice (ADR 0017) |
| **Service attribute-key ownership**, and per-key sensitivity classification | Where service-specific key constants live is unsettled, and `internal/domain` must not grow a registry of them. Redaction's known limit depends on the same answer | The Kafka adapter demonstrates the real boundary, in Phase 3 |
| **Contract-package placement** for the adapter contract, the registry, the probe chain contract and CLI orchestration | Concrete structs first; interfaces only at real boundaries. A placement chosen before a real consumer is a guess | Each is forced by the implementation that needs it |
| **`security.Reveal` restriction** | No adapter wire package exists to confine it to, and inventing a path to point a lint rule at would be worse than waiting | Kafka wire packages exist, in Phase 3 |
| **Execution mode** in run metadata | No vocabulary is defined, and both plausible meanings already have owners: `vantage` and the summary | A real execution mode exists that neither already expresses |
| **`affectedResources`, recommendation reference / risk** | Listed as "recommended when relevant"; nothing consumes them and no renderer exists | A renderer or a finding catalog needs them |

The first three converge on the same question and will likely be answered together. See
`docs/ARCHITECTURE.md` section 18 and `docs/PHASE1_HANDOFF.md` sections 13 and 15.

---

## Phase 0 — Architecture and safety foundation: COMPLETE

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
- [x] Six `depguard` rules encoding the dependency direction

Tooling only. No architecture is implemented by any of the above.

### Deferred architecture lint rules

Each activates when the code it governs exists. The phase named is when it becomes
expressible, not a promise that it lands automatically.

- [ ] `noctx` / `bodyclose` once network-facing code exists — **Phase 2**
- [ ] `gosec` once there is code with meaningful signal — **Phase 2**
- [ ] depguard rule for the adapter contract / registry package (placement still open) — **Phase 3**
- [ ] Kafka adapter must not implement generic DNS/TCP/TLS transport. Needs an import-level
      expression once `internal/adapter/kafka/` exists; not expressible as a package deny
      today — **Phase 3**
- [ ] depguard rule for CLI orchestration (placement still open) — **Phase 5**

### Deferred security hardening

- [ ] Restrict and audit `security.Reveal` usage to explicitly approved low-level boundaries.
      Today it is greppable and documented, but nothing enforces where it may be called.
      Still deferred: no adapter wire package exists to confine it to, and inventing a path
      to point a lint rule at would be worse than waiting. There are currently zero call
      sites outside its own package and tests — **Phase 3**
- [x] Preserve the full secret leak regression matrix whenever the representation or
      formatting of `Secret` changes. **Satisfied by executable tests, no extra CI mechanism
      needed.** Two matrices run under the ordinary `go test ./...` that `make check` already
      invokes: the Phase 1.1 secret matrix in `internal/security/leak_test.go`, which sweeps
      every fmt verb, JSON, text, error and reflection path, and the Phase 1.6 report matrix
      in `internal/security/redaction/redact_test.go`, which asserts hostname, IP, vantage
      and secret canaries are absent from every field, the canonical JSON and error strings.
      A change that reopens a leak fails the build rather than needing a separate guard.

---

## Phase 1 — Core Foundations: COMPLETE

### Phase 1.1 — Security primitives (complete)

Implemented in `internal/security/`, standard library only:

- [x] `Secret` value type with masked String/GoString/Format/JSON/text output
- [x] `Reveal` as the single audited plaintext escape hatch
- [x] `Credential` bound to an endpoint at construction, readable only via `SecretFor`
- [x] `Endpoint` normalization and comparison (ASCII DNS casing, IPv6, zones)
- [x] `ForwardingPolicy` with `deny` as the zero value
- [x] Canary-based leak tests across fmt, JSON, text, reflection and error paths

Scope note: this covers safe *value types* only. Secret source resolution is a separate item
and belongs to Phase 5, where real CLI and configuration input exists.

### Phase 1.2 — Domain primitives (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `State` — PASS/FAIL/DEGRADED/UNKNOWN/SKIPPED with stable symbolic JSON
- [x] `Layer` — L0-L6 in the ADR 0007 order, ordered and comparable
- [x] `FailureClass` — service-neutral failure vocabulary, factual only
- [x] Normalized attribute value model — closed tagged union, no `map[string]any`
- [x] `Vantage` — first-class, storage only, no collection logic

Scope note: this is domain *vocabulary* only.

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

**Responsibilities that are deliberately not the graph's**, recorded so a later change does
not move them into `GraphBuilder`:

- **Endpoint deduplication.** Deciding two endpoints are the same execution target needs to
  know what an endpoint is, and the answer varies by service and vantage. The builder
  deduplicates identifiers and edges, never subjects.
- **Topology recursion depth and visited-endpoint tracking.** Cycle detection in the builder
  is graph integrity; "do not probe this endpoint again" is execution policy.
- **Execution scheduling, retries, timeouts, concurrency, layer progression.**
- **Short-circuit decisions.** The builder records that a step was skipped and what blocked
  it; deciding that a failed DNS lookup stops a TCP attempt happens in orchestration.

**`Graph.MarshalJSON` is deliberately not implemented.** `docs/REPORT_SCHEMA.md` places
evidence inside the report rather than defining a standalone graph object, so the embedding
shape is the report phase's decision. Determinism is verified through the ordering of
`Nodes`, `Parents`, `Children` and `BlockedBy` instead.

### Phase 1.4a — Finding model (complete)

Implemented in `internal/domain/`, standard library only, zero interfaces:

- [x] `FindingCode` — format validated, namespace set left open, no catalog in core
- [x] `FindingKind` — `CONFIRMED` / `HYPOTHESIS`
- [x] `Severity` — `INFO` / `WARN` / `ERROR` / `CRITICAL`, ordering documented as contract
- [x] `Confidence` — `HIGH` / `MEDIUM` / `LOW`, ordinal only, never numeric
- [x] `Recommendation` — inert single action
- [x] `Finding` — immutable value with evidence references, vantage flag and discriminator

**Findings reference evidence by identifier only.** `Finding` validates that each identifier
is well formed; it never takes a `Graph` and never embeds `Evidence`. Membership validation
belongs to the report, which is the first thing owning both sets. See **ADR 0014**.

**Deliberately not implemented here:** diagnosis rules or engine, any concrete finding rule,
exit-code mapping (`Severity` is data; the contract lives in `docs/SCOPE.md`),
`RecommendationRisk` and a recommendation reference link, and `affectedResources`.

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

This is the report schema v1 implementation. It is delivered, and must not be relisted as
pending work in a later phase.

**Deliberately not implemented, with reasons recorded in `docs/REPORT_SCHEMA.md`:**

- Execution mode — no defined vocabulary; `vantage` owns "where" and the summary owns
  incompleteness.
- `Origin` on evidence — deferred by ADR 0013 until topology orchestration exists.
- Exit-code computation — the contract lives in `docs/SCOPE.md` and belongs to the
  application/CLI boundary in Phase 5.

### Phase 1.5 — Diagnosis engine (complete)

Implemented in `internal/diagnosis/`, standard library plus `internal/domain` only, zero
interfaces:

- [x] `Rule` contract — `func(domain.Graph) []domain.Finding`, owned by `internal/diagnosis`
      (ADR 0017)
- [x] `Engine` — immutable rule set, deterministic evaluation, canonical ordering
- [x] `domain.SortFindings` exported so the engine and the report share one definition of
      canonical order
- [x] Purity enforced by depguard rather than convention

**No concrete rules were implemented, and the reason is a missing policy rather than missing
work.** `docs/FINDINGS.md` names `DNS_RESOLUTION_FAILED`, `TCP_CONNECTION_REFUSED` and
`TLS_CERTIFICATE_EXPIRED` only as examples of the naming convention; it assigns them no
severity, confidence or kind. Kind and confidence are derivable from evidence state,
severity is not. See ADR 0017 and the open decisions table above.

### Phase 1.6 — Structural redaction (complete)

Implemented in `internal/security/redaction/`, standard library plus `internal/domain` only,
zero interfaces:

- [x] `Redact` — `LOCAL_FULL` report to `SHAREABLE_REDACTED` report
- [x] Deterministic per-report pseudonyms, assigned from a sorted collection pass
- [x] Evidence identifier remapping, with every reference rewritten (ADR 0014 still passes)
- [x] Target, vantage, subject, attribute and prose redaction
- [x] `SHAREABLE_REDACTED` activated, with derived `RedactionCounts` metadata
- [x] Idempotent: an already-shareable report is returned unchanged
- [x] Fail-closed, with a residual scan over known values as a safety net
- [x] Redaction leak fixtures for reports — the report leak matrix in `redact_test.go`
- [x] Purity enforced by depguard, including a ban on `regexp`

Structural report redaction and shareable-report pseudonymization are delivered here. They
must not be relisted as pending work in a later phase. What remains is *wiring* — choosing
the shareable form at an interface that does not exist yet — which belongs to Phase 5.

**Known limit, recorded in `docs/SECURITY.md` and ADR 0018:** an attribute value that carries
identity in a shape the transformation cannot recognize structurally, and that appears
nowhere else in the report, is preserved. Redaction recognizes a string attribute as
identifying when it parses as an IP address or as a `host[:port]` reference. Closing the gap
needs per-key sensitivity classification, which is tied to the open attribute-key ownership
decision.

> **Constraint on every later phase:** a probe or adapter that records an identifying value
> in some other string shape lands inside this known limit. Prefer attribute shapes redaction
> can recognize structurally.

### Phase 1 seal

Present: security primitives, domain primitives, evidence, immutable evidence DAG, finding
model, canonical report, diagnosis engine, structural redaction.

Deliberately absent, and belonging to Phase 2 or later: DNS/TCP/TLS probes, connection
ownership transfer, the short-circuit execution engine, service adapters, Kafka, PostgreSQL,
topology execution, the CLI, and terminal/Markdown/HTML renderers.

Zero runtime dependencies. Every layer above is a pure value model or a pure transformation
over one, which is what makes the whole of Phase 1 testable without a network.

Sealed. `docs/PHASE1_HANDOFF.md` is the entry point for anyone starting Phase 2 with no
prior context.

---

## Phase 2 — Generic Transport Engine: NOT STARTED

No Go code exists for any item below. Phase 2 is the first code in the repository to import
`net` and `crypto/tls`, and the first real exercise of the `probe-is-service-agnostic`
depguard rule.

Phase 2 delivers a **reusable generic transport engine**: the facts a client can gather about
reaching an endpoint, and a live connection the first adapter can take over in Phase 3. It
delivers no product.

### What Phase 2 may implement

- [ ] DNS probe with latency and multi-address observations
- [ ] TCP probe per resolved address
- [ ] TLS handshake probe with chain, SAN and expiry observations
- [ ] Producer-local observation types, concrete and probe-shaped, normalized into
      `domain.Evidence` at the probe boundary
- [ ] A deterministic evidence identifier scheme for transport nodes, stable within a run.
      The domain deliberately does not generate identifiers, so the producer must
- [ ] Generic transport chain, orchestrating DNS → TCP → TLS execution inside the probe
      boundary
- [ ] Transport-local timeout and budget handling, with an expired local deadline recorded as
      `UNKNOWN` and `FailureExecLocalTimeout`, never as a remote `FAIL`
- [ ] Short-circuit execution producing `SKIPPED` evidence and `BlockedBy` relationships
- [ ] **Connection ownership transfer** — a successfully established live connection handed to
      a protocol adapter, so an adapter never opens its own
- [ ] Hermetic test seams: `Resolver`, `Dialer`, `Handshaker`
- [ ] Deterministic transport fixtures and tests, depending on no uncontrolled public service
- [ ] Activate `noctx`, `bodyclose` and `gosec` now that network-facing code exists

**Watch this boundary.** Connection ownership transfer is the invariant most easily lost by
accident: if a probe is written as "connect, measure, close", the adapter is forced to open
its own connection, and the rule that generic transport owns DNS/TCP/TLS dies without a
single test failing. Design the probe API so a live connection can be handed over from the
start.

### What Phase 2 must not implement

- `internal/app` product orchestration
- `cmd/svcdoctor`
- The CLI, in any form
- Service selection
- The adapter contract, the adapter registry, or service registration
- Kafka protocol
- PostgreSQL protocol
- Topology discovery, endpoint deduplication, or topology depth policy
- Renderers
- Exit-code mapping or exit-code implementation
- Secret source resolution
- Concrete transport diagnosis rules, whose severity policy remains unresolved
- Any service-specific branching, and any speculative plugin framework

### Generic transport orchestration is not application orchestration

> **Generic transport orchestration belongs to Phase 2. Product and application
> orchestration does not.**

The two are easy to conflate, because both are "something that runs steps in order". They sit
on opposite sides of an architecture boundary:

| | Generic transport orchestration (Phase 2) | Application orchestration (Phase 5) |
|---|---|---|
| Lives in | `internal/probe` | `internal/app`, `cmd/svcdoctor` |
| Knows | how to run DNS → TCP → TLS for one endpoint, and when a failure blocks the next layer | which service was selected, which adapter to wire, which rules to evaluate, which renderer to use, which exit code to return |
| Produces | evidence and, on success, a live connection | a report, rendered output and a process exit code |
| Depends on | `internal/domain` and the standard library | everything |

A transport chain that sequences generic probes is inside the probe boundary and is Phase 2
work. Anything that chooses a *service*, assembles a *report*, or decides what the *process*
does is application orchestration and is not.

The same split governs timeouts. A per-probe or per-chain deadline is transport-local and is
Phase 2. The whole-run execution budget, cancellation propagation and the partial-run exit
code described in `docs/ARCHITECTURE.md` section 13 belong to the application boundary in
Phase 5.

### Design decisions Phase 2 must answer from real evidence

These are not implementation items. Phase 2 must **produce the evidence that lets them be
answered**, and must not resolve them from first principles.

- [ ] **Transport severity policy.** What severity does an evidenced transport failure carry,
      and does it depend on the endpoint's role? (ADR 0017)
- [ ] **`Origin` / provenance.** Does a node need to record how its subject entered the run,
      or is graph structure enough? Answering this reopens ADR 0013's deferral, which is
      expected and allowed — the ADR names this exact condition. It is unlikely to be settled
      before Phase 3, because topology is what makes the question concrete
- [ ] **Generic vs service finding overlap.** Which layer reports a failed endpoint when both
      a transport rule and a service rule could? (ADR 0017, `docs/FINDINGS.md` section 5)

Because the first is unresolved, concrete rules under `internal/diagnosis/transport/` are
**not** Phase 2 implementation work. They are listed in Phase 3, blocked on this answer.
Writing them earlier would put invented diagnostic policy into the layer whose entire purpose
is not to invent.

### Items that used to be listed here

Recorded so the move is traceable rather than looking like a loss:

| Item | Where it went |
|---|---|
| Report schema v1 implementation | Already delivered in Phase 1.4b |
| Structural report redaction and shareable-report pseudonymization | Already delivered in Phase 1.6 |
| Redaction leak fixtures for reports | Already delivered in Phase 1.6 |
| Short-circuit execution and layer progression | Kept in Phase 2 — it is transport orchestration |
| Concrete transport rules under `internal/diagnosis/transport/` | Phase 3, blocked on transport severity policy |
| Adapter registration boundary | Phase 3, forced by the first real adapter |
| Target normalization | Phase 3 — L0 normalization is service-shaped |
| Endpoint deduplication and topology depth policy | Phase 3, with topology |
| Credential-forwarding wiring into topology discovery | Phase 3, with topology |
| Secret source resolution | Phase 5, when real CLI and configuration input exists |
| Exit-code mapping and implementation | Phase 5, at the application/CLI boundary |
| Whole-run timeout and cancellation implementation | Phase 5; transport-local timeouts stay in Phase 2 |

---

## Phase 3 — Kafka Vertical Slice: NOT STARTED

The first real adapter. It is what forces the adapter contract, the registry, service
attribute-key ownership and the topology questions to become concrete, and it must be able to
consume Phase 2's transport engine without reimplementing any of it.

### Boundary and contract work

- [ ] Add the Kafka wire dependency with a license and security review. franz-go low-level
      protocol primitives, not high-level client behaviour, because hidden retry, failover
      and automatic broker switching destroy the evidence topology findings depend on
      (ADR 0008)
- [ ] Adapter contract and explicit composition-root registration boundary. Keep the shared
      contract as small as the Kafka implementation actually requires; PostgreSQL is the
      second implementation that validates it. Package placement is still open (ADR 0009)
- [ ] Target normalization for Kafka bootstrap endpoints (L0)
- [ ] Settle service attribute-key ownership, and per-key sensitivity classification for
      redaction's known limit
- [ ] Restrict and audit `security.Reveal` to approved wire boundaries, now that a wire
      package exists to confine it to
- [ ] depguard: adapter contract / registry package rule, and an import-level expression that
      a Kafka adapter must not implement generic DNS/TCP/TLS transport

### Protocol and authentication

- [ ] ApiVersions (L4)
- [ ] SASL mechanism discovery (L5)
- [ ] PLAIN
- [ ] SCRAM-SHA-256
- [ ] SCRAM-SHA-512
- [ ] supplied-token OAUTHBEARER
- [ ] mTLS
- [ ] Normalize protocol errors and response codes into evidence at the adapter boundary; no
      raw protocol object crosses it (ADR 0010)

GSSAPI/Kerberos and AWS_MSK_IAM stay detect-and-explain only unless the project explicitly
changes scope.

### Topology

- [ ] Metadata discovery (L6)
- [ ] Normalize broker endpoints
- [ ] Probe every advertised endpoint from the current vantage, credential-free by default
- [ ] Endpoint deduplication and topology depth policy — orchestration, never the graph
- [ ] Credential-forwarding wiring into topology discovery, with `deny` as the default policy
- [ ] Answer the `Origin` / provenance question, now that topology orchestration exists

### Diagnosis rules

- [ ] Answer the transport severity policy and generic/service overlap questions from the
      evidence Phase 2 and this phase produce
- [ ] Concrete generic transport rules under `internal/diagnosis/transport/`, unblocked by
      that answer
- [ ] `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` rule (`docs/FINDINGS.md` section 6)
- [ ] Protocol/security mismatch rules
- [ ] Privilege-aware skipped states

### Validation

- [ ] Kafka integration environment and fixtures
- [ ] Canonical JSON report acceptance tests for the Kafka slice. Terminal, Markdown and HTML
      renderers are Phase 5; JSON is already canonical and needs no renderer

---

## Phase 4 — PostgreSQL Vertical Slice: NOT STARTED

Start only after the Kafka acceptance criteria are complete. PostgreSQL is the second real
implementation, and its job is as much to validate the shared abstractions Kafka produced as
to add a service. An abstraction Kafka introduced that PostgreSQL cannot use is a signal to
narrow it, not to generalize it further.

- [ ] SSLRequest/TLS
- [ ] startup/protocol negotiation evidence
- [ ] auth-type evidence
- [ ] sslmode/certificate correlation
- [ ] pg_hba bisection evidence
- [ ] multi-host DSN verification, with credential material removed from the recorded target
- [ ] per-IP role discovery
- [ ] minimal replication/slot signals
- [ ] Confirm that adding this service required no edit to a generic package beyond the single
      registration point

---

## Phase 5 — Productization, Platform and Renderers: NOT STARTED

Everything that turns a diagnostic engine into a tool a person runs. This is where
application orchestration lives, and it is deliberately last among the implementation phases:
every boundary it wires together is validated by then.

### Application and CLI

- [ ] `internal/app` application orchestration
- [ ] `cmd/svcdoctor` with service subcommands, sourced from explicit registration; service
      type is never inferred from port numbers (ADR 0011)
- [ ] Service selection and composition-root wiring
- [ ] Whole-run execution budget, cancellation, and preservation of evidence collected before
      cancellation
- [ ] Exit-code mapping and implementation, per the contract in `docs/SCOPE.md`
- [ ] Secret source resolution: stdin, askpass, strict-permission file, environment, external
      references. Bare CLI secret flags are not considered safe
- [ ] `--insecure` as an explicit per-run opt-in: warned about on stderr, recorded in the
      report, never an automatic fallback
- [ ] Shareable-report selection wiring, calling the redaction that already exists

### Renderers

- [ ] Terminal renderer
- [ ] Markdown renderer
- [ ] Self-contained HTML renderer
- [ ] Renderer acceptance tests proving no renderer creates findings, computes severity or
      discovers secrets

### Platform

- [ ] Vantage collection at the platform/orchestration boundary
- [ ] Kubernetes context behind an explicit dependency/build strategy
- [ ] Strimzi context
- [ ] CNPG context

### Distribution

- [ ] GoReleaser
- [ ] signing/SBOM/provenance
- [ ] multi-OS/multi-arch release validation
- [ ] Release hardening for core-dump exposure; telemetry off by default

---

## Phase 6 — Real-world Validation and Hardening: NOT STARTED

- [ ] Run against at least 10 real connection/auth/TLS/topology incidents
- [ ] Measure first-broken-layer accuracy
- [ ] Measure false positives
- [ ] Validate shareable-report usefulness with a reader who did not run the tool
- [ ] Review whether the deferred decisions closed in Phases 2-4 held up in practice
- [ ] Decide whether to expand to a third service

A third service is not added until Kafka and PostgreSQL have produced real validation
signals. See `docs/SCOPE.md`.
