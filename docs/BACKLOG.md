# Backlog

## Repository state

Repository and tooling bootstrap exists. The following packages are implemented. The project
has exactly one runtime dependency, added in Phase 3.1: `github.com/twmb/franz-go/pkg/kmsg`
(BSD-3-Clause, no transitive dependencies).

- `internal/domain` — domain primitives, evidence, the immutable evidence DAG, findings and
  the canonical report
- `internal/security` — masked secret and endpoint-bound credential primitives, plus the
  channel-security fact and the fail-closed credential-transport policy (Phase 3.2b)
- `internal/security/redaction` — structural redaction into a shareable report
- `internal/diagnosis` — the `Rule` contract and the deterministic `Engine`
- `internal/probe` — the evidence identifier encoding every probe shares
- `internal/probe/dns` — the DNS probe, the first real I/O producer (Phase 2.1)
- `internal/probe/tcp` — the TCP probe and connection ownership (Phase 2.2)
- `internal/probe/tls` — the TLS probe, which consumes and produces that ownership (Phase 2.3)
- `internal/probe/transport` — the generic transport chain (Phase 2.4)
- `internal/adapter/kafka` — the Kafka adapter boundary, ApiVersions evidence (Phase 3.1),
  SASL mechanism discovery (Phase 3.2a), channel propagation (Phase 3.2b) and PLAIN
  authentication (Phase 3.2c)
- `internal/adapter/kafka/wire` — the only package that imports the Kafka protocol library, and
  the only package that may call `security.Reveal`

No Go code exists in any of the following, and nothing in them may be assumed implemented:

- `internal/adapter/postgres`
- `internal/render`
- `internal/platform`
- `internal/app`
- `cmd/svcdoctor`

So the generic transport engine is complete: it sweeps an endpoint end to end and produces a
deterministic evidence graph plus one live connection. What is still absent is everything that
would consume it — no adapters, no Kafka, no PostgreSQL, no topology execution, no diagnosis
rules, no renderers, no CLI. **The tool still cannot diagnose anything**: it can gather
transport evidence for one endpoint, and nothing interprets or presents it yet.

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
| 2 | Generic Transport Engine | **Complete** — 2.1 DNS, 2.2 TCP, 2.3 TLS, 2.4 chain |
| 3 | Kafka Vertical Slice | **In progress** — 3.1 adapter boundary and ApiVersions, 3.2a SASL mechanism discovery, 3.2b credential transport safety, 3.2c PLAIN authentication, 3.3 Metadata topology discovery, 3.3b transport sweep identity, 3.4 advertised endpoint reachability complete |
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
| **Transport severity policy** | Severity is impact, and whether a failed lookup or refused connection prevents correct use depends on whether the endpoint was user-supplied or discovered — that distinction is `Origin`. **Phase 3.4 now produces exactly the evidence such a rule needs and deliberately does not use it**: whether one unreachable broker out of three is WARN, ERROR or CRITICAL is Kafka semantics plus diagnosis policy (ADR 0033 §15) | Phase 2 has produced real transport evidence (ADR 0017) |
| **`Origin` / provenance** | **Examined in Phase 3.3 and left deferred.** Discovery now exists and needed only *derivation* — which parent edges already record — not provenance. The two are distinct: when a cluster advertises the bootstrap endpoint back, one `host:port` has both a discovery-derived node and a lookup-derived transport path, so origin is not a function of the subject and cannot be read off graph shape (`REPORT_SCHEMA.md`) | An execution or topology planner has a real consumer for provenance (ADR 0031 §6) |
| **Generic vs service finding overlap** | Nothing says how a generic `TCP_CONNECTION_REFUSED` and a service `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` avoid describing one fact twice | The first service rules are written, in Phase 3 (ADR 0017) |
| **Execution deduplication, and a many-causes→one-execution graph shape** | Phase 3.4 runs one transport sweep per advertisement, including when two advertisements name one endpoint. A deduplicated sweep would have two causes and one effect, and the derivation parent is singular — recording it would mean picking one cause by a tiebreak and leaving the other with no measurement a finding could reference (ADR 0033 §3) | The graph gains a truthful many-causes→one-execution representation; the dedup key stays the normalized endpoint, never the node identifier |
| **Finding identity / duplicate semantics** | Defining when two findings are one conclusion is guesswork today; the engine preserves duplicates rather than discarding a real finding | A real rule set produces duplicates in practice (ADR 0017) |
| **Service attribute-key ownership** | Where service-specific key constants live is unsettled, and `internal/domain` must not grow a registry of them | The Kafka adapter demonstrates the real boundary, in Phase 3 |
| **Contract-package placement** for the adapter contract, the registry, the probe chain contract and CLI orchestration | Concrete structs first; interfaces only at real boundaries. A placement chosen before a real consumer is a guess | Each is forced by the implementation that needs it |
| **SCRAM's implementation route** | franz-go's SCRAM lives in the main module, alongside `kgo` and three transitive dependencies, which would end this project's one-dependency property. The alternative is hand-rolled crypto. Neither belongs in a phase about SASL generally | SCRAM is its own subphase with its own dependency decision (ADR 0026 §7.4) |
| **A `SKIPPED` protocol node for a transport path that failed** | The adapter receives completed paths only, so it cannot know an address it was never handed exists. Nothing today knows a service step was *requested* for one: the transport chain must not know Kafka, and the layer that would is the orchestration boundary Phase 3.1 did not build. The subject rule does not forbid the node — `ip:port` is known — so this is an open question, not a settled shape (ADR 0025 §9) | Phase 3 orchestration sequences transport and an adapter for one endpoint, or a rule needs to tell "L4 was never reached here" from "no L4 node here" |
| **Execution mode** in run metadata | No vocabulary is defined, and both plausible meanings already have owners: `vantage` and the summary | A real execution mode exists that neither already expresses |
| **`affectedResources`, recommendation reference / risk** | Listed as "recommended when relevant"; nothing consumes them and no renderer exists | A renderer or a finding catalog needs them |

The first three converge on the same question and will likely be answered together. See
`docs/ARCHITECTURE.md` section 18 and `docs/PHASE1_HANDOFF.md` sections 13 and 15.

**Two credential questions left this table in Phase 3.2b's decision pass**, recorded so the
move is traceable rather than looking like a loss:

| Was open | Answer | Where |
|---|---|---|
| Which transport paths may receive credentials | Caller-selected, and **structurally singular**: the authentication API takes one session, never a list, so no ordering or index inside the adapter can become a selection | ADR 0028 §1 |
| Whether credentials may cross an unverified channel | Verified TLS only; anything weaker is an explicit, per-run, recorded opt-in. A refusal is recorded as `SKIPPED` + `EXEC_SKIPPED_BY_POLICY`, never silence | ADR 0028 §3 |

Both mechanisms now exist: Phase 3.2b built them (ADR 0029). Neither *authentication* is
implemented. **Secret source resolution was also re-classified**: ADR 0026 §7.2 called it
a blocker for authentication, and ADR 0028 §7 narrows that — a `security.Credential` is
constructible by any caller, so resolution is a Phase 5 usability item at the CLI boundary,
not a Phase 3 contract blocker.

**Per-key sensitivity classification is no longer part of the attribute-key question.** It was
listed here as redaction's prerequisite until Phase 2.3, when TLS forced the issue and ADR 0022
answered it differently: sensitivity moved onto the *value*, so redaction needs no key
vocabulary at all. Where keys live is still open; who is allowed to import them is still open.

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

- [x] `noctx` once network-facing code exists — activated in **Phase 2.2**
- [x] `gosec` once there is code with meaningful signal — activated in **Phase 2.3**, when
      crypto/tls arrived
- [x] `forbidigo` once a wire package existed to confine `security.Reveal` to — activated in
      **Phase 3.2a** (ADR 0027), with zero call sites, so the guard precedes the first
      credential rather than following it
- [ ] `bodyclose` — evaluated in 2.2, 2.3, 3.1 and 3.2 and still off: it checks HTTP response
      bodies and no code uses `net/http`. **Reopen when** something does
- [ ] depguard rule for the adapter contract / registry package (placement still open) — **Phase 3**
- [ ] Kafka adapter must not implement generic DNS/TCP/TLS transport. Needs an import-level
      expression once `internal/adapter/kafka/` exists; not expressible as a package deny
      today — **Phase 3**
- [ ] depguard rule for CLI orchestration (placement still open) — **Phase 5**

### Deferred security hardening

- [x] Restrict and audit `security.Reveal` usage to explicitly approved low-level boundaries.
      **Done in Phase 3.2** (ADR 0027), when the reopen condition below was met. `forbidigo`
      confines the call to `internal/adapter/<service>/wire/` and fails the build elsewhere;
      two `depguard` rules additionally deny `internal/security` to diagnosis, renderers and
      platform. depguard could not express the reveal rule on its own, because an adapter must
      import `internal/security` to hold a `Credential` and call `SecretFor`. There are still
      **zero call sites**: the guard was installed in the phase before the first credential
      byte, so no exception has to be argued against working code
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

## Phase 2 — Generic Transport Engine: IN PROGRESS

Phase 2 delivers a **reusable generic transport engine**: the facts a client can gather about
reaching an endpoint, and a live connection the first adapter can take over in Phase 3. It
delivers no product.

Phases 2.1 through 2.4 are complete. Everything else below is not started.

### Phase 2.1 — Generic probe contracts and DNS (complete)

Implemented in `internal/probe/dns/`, standard library plus `internal/domain` only, one
interface:

- [x] DNS probe with latency and multi-address observations
- [x] Producer-local observation type, unexported, holding the raw resolver error and address
      values so neither can leave the package
- [x] Normalization into `domain.Evidence` at the probe boundary
- [x] Deterministic evidence identifier scheme, `<step>/<subject reference>` (**ADR 0019**)
- [x] Conservative local-deadline and cancellation semantics: `UNKNOWN` with
      `EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED`, never a remote `FAIL` (**ADR 0020**)
- [x] `Resolver` hermetic test seam and a standard-library `SystemResolver`
- [x] Deterministic multi-address handling: sorted, deduplicated, IPv4-mapped forms unmapped,
      both families kept
- [x] Hermetic tests only — no test resolves a real name
- [x] Cross-package redaction contract test in `test/security/`
- [x] `probe-is-service-agnostic` depguard rule verified empirically against a deliberate
      violation

The evidence contract, the rejected alternatives and the reasoning are in **ADR 0020**,
summarized in `docs/ARCHITECTURE.md` section 3.1, with the package documentation in
`internal/probe/dns/doc.go` as the local record.

**Deliberately not done in 2.1:** no TCP, no TLS, no transport chain, no `GraphBuilder`
orchestration, no `BlockedBy`, no short-circuit logic, no findings, no service knowledge.

Questions 2.1 surfaced:

- [x] **`DNS_NO_ADDRESS` semantics — settled.** The class was documented as "the name exists
      but yielded no usable address" while the probe also used it for the undistinguished
      not-found case, where existence is unknown. The contract is now widened to **"the lookup
      yielded no usable address"**, which claims nothing about existence and is therefore true
      for a name with no address record, a name that does not exist, and a resolver that does
      not separate them. `DNS_NXDOMAIN` keeps its meaning as the stronger claim and stays
      **reserved** for a resolver that positively evidences non-existence; nothing produces it
      today, and `TestNXDomainStaysReserved` keeps it that way. A third class was rejected: it
      would split one diagnostic outcome for a distinction no available resolver reports. See
      ADR 0020.
- [x] **Evidence identifier scoping and encoding — settled in Phase 2.2.** The scheme is now
      `<step>[/<component>...]` with each component escaped (`%` → `%25`, `/` → `%2F`), built
      by `probe.EvidenceID` so both probes share one implementation. TCP forced it: one name
      resolves to several addresses, and two names can share an address, so an identifier
      needs both the endpoint and the address. The delimiter rule is now honoured rather than
      merely stated — the DNS probe no longer refuses a host containing `/`. See ADR 0019.
- [ ] **Where generic transport attribute keys live — revisited again in Phase 2.3; half of it
      dissolved, half still open.** TLS is the third producer and the first with a large
      factual vocabulary (nine keys), yet it still shares no key with DNS or TCP: each probe
      observes different things, so there is still nothing to hoist and `internal/probe` holds
      only the identifier encoding.
      **Dissolved:** redaction no longer needs to know any key. It used to be a candidate
      consumer of a shared key table, which would have become the central service-key registry
      the architecture rejects; ADR 0022 moved sensitivity onto the *value* instead, so the
      redactor needs no vocabulary at all.
      **Still open:** a future rule in `internal/diagnosis/transport/` cannot import
      `tls.AttrVerified` or `dns.AttrAnswers`, because depguard forbids diagnosis importing
      probes. **Reopen when** the first transport rule needs a key, or when two probes need the
      same one. This remains the generic half and does **not** settle the service-specific
      half.

### Phase 2.2 — Generic TCP probe and connection ownership (complete)

Implemented in `internal/probe/tcp/` and `internal/probe/`, standard library plus
`internal/domain` only, one new interface:

- [x] TCP probe attempting one concrete address per call, so multiple resolved addresses
      become multiple independently identifiable evidence nodes
- [x] **Connection ownership transfer** — `Result` owns a successful connection, `TakeConn`
      transfers it exactly once, `Close` releases it only while still owned (**ADR 0021**)
- [x] `Dialer` hermetic test seam taking a `netip.AddrPort`, so a probe cannot resolve a name,
      and a standard-library `SystemDialer`
- [x] Structured error classification through `errors.Is` on error numbers, never error text
- [x] Conservative timeout attribution: the network stack's `ETIMEDOUT` is a remote fact, any
      other timeout is svcdoctor's own budget and stays `UNKNOWN`
- [x] `domain.FailureTCPConnectionFailed`, the conservative floor for a dial failure that
      cannot be classified further
- [x] Shared identifier encoding in `internal/probe`, with escaping so no input is refused
      (**ADR 0019**, amended)
- [x] Cross-package redaction contract test covering a hostname reachable only through an
      evidence identifier
- [x] `noctx` activated; `probe-is-service-agnostic` and `noctx` both verified empirically
      against deliberate violations

**Deliberately not done in 2.2:** no TLS, no transport chain, no `GraphBuilder`
orchestration, no `BlockedBy`, no short-circuit logic, no address selection or racing, no
findings, no service knowledge, no `Origin`.

**Lint reassessment, decided from evidence rather than from the plan:**

- **`noctx` — enabled.** It flags network calls that take no context, which is the mechanism
  the execution-budget contract depends on: an uncancellable dial makes a local budget
  unenforceable. Run against the new code it immediately caught a real `net.Listen` in this
  repository's own test, which was fixed rather than suppressed.
- **`bodyclose` — still off.** It checks HTTP response bodies. Run against the current tree it
  reports nothing because no code uses `net/http`. **Reopen when** something does.
- **`gosec` — still off.** Run against the current tree its only finding is a G602 false
  positive in a sealed Phase 1 test helper. Enabling it now would mean either editing Phase 1
  code or adding a suppression, for no security signal on a probe with no crypto, no file
  access and no privilege handling. **Reopen in Phase 2.3**, where G402 and the `--insecure`
  path give it something real to check — and where the G602 false positive must be dealt with.
  *(That is what happened: gosec was activated in Phase 2.3 — see below.)*

### Phase 2.3 — Generic TLS probe (complete)

Implemented in `internal/probe/tls/`, standard library plus `internal/domain` and
`internal/probe` only, **no new interface**:

- [x] TLS handshake over a connection the caller already owns, never dialing and never
      resolving
- [x] **Ownership consumed and produced** — `Handshake` takes the connection
      unconditionally, closes it on failure, and returns the wrapped TLS connection under the
      ADR 0021 rules (**ADR 0023**)
- [x] Generic TLS parameters: server name, trust source, version bounds, per-attempt
      verification control
- [x] Certificate facts — validity window, DNS and IP SANs, chain length — recorded on
      verification failure as well as success, because the rejected chain is what makes a
      failure actionable
- [x] Negotiated version and cipher suite as stable names, with a numeric fallback for values
      nobody has anticipated
- [x] Typed-error classification, including `TLS_PEER_NOT_TLS` for a peer that answers with
      something that is not a TLS record
- [x] `domain.FailureTLSPeerNotTLS`, the one class the vocabulary was missing
- [x] Verification on by default; disabling it is per-attempt, explicit, never an automatic
      fallback, and recorded on the node as `tls.verified`
- [x] **Declared identity values** — `domain.HostAttr` / `HostListAttr` (**ADR 0022**), after
      the first `test/security` run leaked certificate names into a shareable report
- [x] Hermetic fixtures: an in-memory CA, generated certificates and a loopback peer the test
      controls; no fixture keys on disk
- [x] `gosec` activated; `probe-is-service-agnostic` and the new lint verified empirically

**Deliberately not done in 2.3:** no transport chain, no `GraphBuilder` orchestration, no
`BlockedBy`, no findings, no service knowledge, no mTLS, no ALPN, no trust-material loading
from disk, no CLI flag.

**No `Handshaker` seam was added, and the backlog item is closed rather than deferred.** Every
case — verified, unknown authority, hostname mismatch, expired, not-yet-valid, version
mismatch, plaintext peer, hang-up, deadline, cancellation — is reproducible against a real
`crypto/tls` server on a loopback listener the test creates. An interface with no test
consumer is the speculative abstraction the architecture forbids, so the reason DNS and TCP
have seams (they reach the network) simply does not apply here. See ADR 0023.

**Lint reassessment, decided from evidence:**

- **`gosec` — enabled.** It now has crypto to check. Verified by removing the suppression:
  it flags G402 on the single line that honours a caller's explicit request to skip
  verification. That line keeps a targeted `nolint` with its reason; the pre-existing G602
  false positive in a Phase 1 test helper was removed by rewriting the helper with
  `slices.Equal` rather than by suppressing it.
- **`noctx` — still enabled**, still clean.
- **`bodyclose` — still off.** Run against the current tree it reports nothing, because no
  code uses `net/http`. **Reopen when** something does.

Questions 2.3 surfaced:

- [x] **Redaction could not recognize a bare hostname in an attribute — settled.** The
      documented "known limit" of ADR 0018 stopped being theoretical the moment a probe
      recorded certificate names. Fixed structurally by declaring identity in the value's type
      (**ADR 0022**), not by a shape heuristic, which cannot separate `broker.internal` from
      `TLS1.3`. `docs/SECURITY.md` records what is left of the limit.
- [ ] **Two handshakes to one address under different server names** would collide on one
      identifier. No caller does it, so no component was added on speculation. Recorded with
      the other identifier-scoping cases in ADR 0019.

### Phase 2.4 — Generic transport chain (complete)

Implemented in `internal/probe/transport/`, standard library plus `internal/domain` and the
three probe packages, **no new interface**:

- [x] `Run` sweeps one endpoint: DNS, then TCP for **every** resolved address, then TLS where
      the caller asked for it (**ADR 0024**)
- [x] Sequential execution in the canonical address order the DNS probe produced
- [x] Every completed path returned as a `Continuation`, with the chain choosing none of them:
      selecting a working path is client policy that belongs to the layer which knows what
      protocol it will speak (**ADR 0024**)
- [x] `GraphBuilder` relationships built outside the probe packages: parent edges for
      derivation, `BlockedBy` for a TLS step that could not run
- [x] `SKIPPED` TLS evidence after a TCP failure, and **no synthetic nodes** when a lookup
      produced no address
- [x] Transport-local budget: the caller's context plus an optional per-step timeout; an
      exhausted budget records `SKIPPED` with `EXEC_CANCELLED` / `EXEC_LOCAL_TIMEOUT`, never a
      remote failure
- [x] TLS optionality expressed by the presence of `Params.TLS`, never inferred from a port
- [x] Chain `Result` owning every retained connection under the ADR 0021 rules, plus the
      address and evidence identifier a protocol layer needs to continue from each
- [x] Ownership regression tests over real sockets, including a proof that bytes flow over the
      transferred connection and that a failed run leaks nothing
- [x] `test/security/transport_chain_redaction_test.go` — the first redaction test over a graph
      with real parent and `BlockedBy` edges

**Deliberately not done in 2.4:** no adapters, no topology, no `Origin`, no diagnosis rules, no
findings, no severity, no renderer, no CLI, no `internal/app`, no retries, no Happy Eyeballs,
no concurrency.

**Lint reassessment:** `noctx` and `gosec` stay enabled and clean. `bodyclose` was run against
the new chain and reports nothing, because no code uses `net/http`; it stays off. Both the
`probe-is-service-agnostic` and `diagnosis-is-pure` depguard rules were verified empirically
against deliberate violations in the new package.

**Design corrected before commit.** The first implementation retained "the first successful
path in canonical address order". Canonical order puts every IPv4 address before every IPv6
one, so the observable behaviour was an IPv4 preference that nobody chose and no test guarded.
Evidence ordering and runtime connection selection were being coupled; they are now separate,
and `TestCanonicalOrderIsNotAFamilyPreference` keeps them that way. See ADR 0024.

**Contract tension found and resolved:** `docs/ARCHITECTURE.md` section 12 read as though a
failed lookup must still produce SKIPPED TCP and TLS nodes, while ADR 0020 requires a subject
to name what its layer touched — and after a failed lookup there is no address to name.
Section 12 now states the rule explicitly: a skipped node exists only when its subject is
known. See ADR 0024.

### What the rest of Phase 2 may implement

Nothing. The generic transport engine is complete; Phase 3 is the next work.

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

Phase 2.1 produced the first real transport evidence and deliberately answered none of these.
A DNS failure alone does not settle severity: whether a failed lookup prevents correct use
still depends on whether the name was user-supplied or discovered, which is `Origin`, and
topology is what makes that concrete.

Phase 2.2 added evidence that sharpens the first question without answering it. One endpoint
now produces several TCP nodes, so a rule will have to say what "the endpoint is unreachable"
means when one address of three refused — a question about aggregation that did not exist
before, and that still needs a severity policy it cannot invent for itself. The endpoint scope
component in an identifier is **not** `Origin`: it is caller-supplied bookkeeping in an opaque
string, not a claim recorded on a node. All three remain open.

Phase 3.4 sharpened them again, and added a **second level of aggregation** to the same
question. One advertisement now produces a whole scoped sweep, so a rule must say what an
advertised endpoint being "unreachable" means when one address of two refused *and* what a
cluster being reachable means when one advertised broker of five failed — and the two compose.
`docs/FINDINGS.md` section 6 is ambiguous at exactly that point: "one or more discovered broker
endpoints fail connectivity verification" does not say whether a broker fails when any address
failed or only when all of them did, and both rules' *trigger condition* depends on the answer.
Phase 3.4 also demonstrated concretely that the overlap question is not hypothetical: a generic
`TCP_CONNECTION_REFUSED` rule and `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` would cite the same
evidence identifier on the first real run. All of it remains open.

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

## Phase 3 — Kafka Vertical Slice: IN PROGRESS

### Phase 3.1 — Adapter boundary and ApiVersions (complete)

Implemented in `internal/adapter/kafka/` and `internal/adapter/kafka/wire/`, **no new
interface**, one runtime dependency:

- [x] First service adapter, consuming transport continuations without reopening a connection
- [x] ApiVersions over **every** transport path, one evidence node each, nothing aggregated and
      no path chosen (**ADR 0025**)
- [x] L4 evidence parented to the transport node whose connection carried the exchange
- [x] franz-go coupling confined to `wire`, using `kmsg` only — never `kgo`, whose retries and
      reconnects would break the measured-connection invariant (ADR 0008)
- [x] Three normalized attributes: advertised ranges as a sorted `"<key>:<min>-<max>"` list,
      the broker's error code, and the requested ApiVersions version
- [x] Conservative protocol classification using the existing service-neutral vocabulary; **no
      new FailureClass was needed**. One broker error code is normalized —
      `UNSUPPORTED_VERSION` to `PROTOCOL_UNSUPPORTED_VERSION`, because the response states that
      generic fact outright — and every other code stays `PROTOCOL_UNEXPECTED_RESPONSE` with
      the code itself as an attribute (ADR 0025 §6)
- [x] Sessions keep their connections open for Phase 3.2, under the ADR 0021 ownership rules
- [x] Hermetic fake broker over loopback; no container, no cluster, no network
- [x] Redaction contract test covering the new L2 → L4 parent edge
- [x] `adapter must not import diagnosis` added to depguard, now that an adapter package exists,
      and verified against a deliberate violation

**Deliberately not done in 3.1:** no SASL, no Metadata, no topology, no advertised-endpoint
verification, no diagnosis rules, no findings, no severity, no CLI, no renderer, no registry,
no `Origin`.

**Decisions taken, with their reopen conditions:**

- [x] **No generic adapter interface, no registry.** One implementation, no CLI, no second
      service: any method set would encode guesses about PostgreSQL. ADR 0009 governs how
      registration works when wiring exists, not that it must exist first. **Reopen when** the
      second adapter or the first composition root arrives.
- [ ] **No `SKIPPED` protocol node for a failed transport path.** The adapter is handed
      completed paths, so the absence is a consequence of the input contract rather than a
      decision that the node should not exist — the subject would be nameable. Recorded with
      its reopen condition in ADR 0025 §9 and in the open decisions table above, so the
      current API shape does not become policy by default.
- [ ] **Kafka attribute keys stay in the adapter.** A future rule in
      `internal/diagnosis/kafka` will need them and cannot import an adapter, so they will move
      to a leaf both can import — most likely `internal/service/kafka`. Not created now because
      it would have one consumer, and a shared vocabulary invented before its second consumer
      is a guess. Moving constants is mechanical. **Reopen when** the first Kafka diagnosis
      rule is written.

### Phase 3.2a — SASL mechanism discovery (complete)

Implemented in `internal/adapter/kafka/` and `internal/adapter/kafka/wire/`, **no new
interface**, **no new dependency**, **no credential sent**:

- [x] `SASLHandshake` over every ApiVersions session, one L5 node each, parented to the
      `kafka.api_versions` node of the same path (**ADR 0026**)
- [x] SaslHandshake **v1**, the flow whose failures are framed error codes rather than a
      closed socket, with no automatic downgrade to v0
- [x] Caller-supplied mechanism; probing with a deliberately invalid mechanism name was
      rejected, because it puts a value on the wire no client would send
- [x] Two normalized attributes — the requested mechanism and the offered list, sorted for
      byte-stability and **not** deduplicated — plus the existing `kafka.error_code` and
      `kafka.request_api_version` keys, reused with one meaning each
- [x] One new code normalized: `UNSUPPORTED_SASL_MECHANISM` to `AUTH_MECHANISM_NOT_OFFERED`,
      the **peer-side** class. `ILLEGAL_SASL_STATE` stays conservative: two causes, one code
- [x] Connection lifetime follows the protocol, not the evidence state — only an accepted
      handshake has a defined next message, and a test holds that apart from `FAIL`
- [x] `HandshakeSession` as a distinct type, so authentication cannot be handed a session
      whose mechanism was never agreed
- [x] `Session.Endpoint()` added: Phase 3.1 dropped the logical endpoint at L4, and credential
      authority is name-based (ADR 0026 §9)
- [x] Kafka framing consolidated in `wire`, one implementation for every request kind, with a
      guard that refuses flexible messages the header reader cannot parse
- [x] `security.Reveal` confined mechanically, before any credential exists (**ADR 0027**)
- [x] Hermetic fake broker answering both requests on one connection; no container, no cluster
- [x] Redaction contract test covering the L5 node and its mechanism facts

**Deliberately not done in 3.2a:** no authentication, no PLAIN, no SCRAM, no
SaslAuthenticate, no credential acquisition, no `security.Reveal` call site, no path
selection, no Metadata, no topology, no diagnosis rules, no findings, no severity, no CLI,
no renderer, no registry, no `Origin`, and no L5 skipped nodes.

**Lint reassessment, decided from evidence:** `forbidigo` enabled and verified both ways —
the same file is rejected in `internal/adapter/kafka` and accepted in
`internal/adapter/kafka/wire`. `gosec` stayed enabled and produced five real findings in the
new test code, all fixed rather than suppressed except one narrow, explained `nolint` on a
signed-int16 wire decode. `noctx` clean. `bodyclose` still off: no `net/http`.

### Phase 3.2b — Credential transport safety (complete)

**Sends no credential, and contains no authentication code.** It builds the two mechanisms
ADR 0028 required before any credential byte, and nothing else. See **ADR 0029**.

- [x] **`security.Channel`** — one ordered fact per connection: `unknown`, `plaintext`,
      `tls-unverified`, `tls-verified`. The zero value is `unknown` rather than `plaintext`,
      because a connection nobody classified and one known to be in the clear are different
      facts; both are refused, only one is a claim
- [x] **`security.CredentialTransportPolicy`** — fail-closed, modelled on `ForwardingPolicy`.
      One value, `RequireVerifiedTLS`, which is also the zero value. Every undefined channel
      *and* every undefined policy integer denies
- [x] **`tls.Result.Verified()`** — the fact exposed on the value that owns the connection,
      computed from the same observation that produces the `tls.verified` attribute, so the
      runtime and recorded facts cannot disagree about one handshake
- [x] Propagation `Continuation` → `Session` → `HandshakeSession`, each hop passing the
      channel in the same statement as the connection, through an unexported constructor
- [x] **`tcp.Result` gained nothing.** TCP cannot classify a connection whose TLS status is
      decided one layer later
- [x] Real-TLS Kafka fixture, so a verified channel is proven end to end through DNS, TCP,
      TLS, ApiVersions and SaslHandshake, and mixed channels are proven not to contaminate
- [x] Mutation-checked: forging a verified channel in the adapter, or calling every TLS path
      verified in the chain, both fail the suite

**Deliberately not done in 3.2b:** no authentication, no PLAIN, no `SaslAuthenticate`, no
`security.Reveal` call site, no evidence attribute, no report-schema change, no
`ReportSecurity` field, no unsafe override, no path selection, no CLI, no diagnosis.

**Decisions taken, with their reopen conditions:**

- [x] **The channel is not recorded as evidence.** `tls.verified` already states what a
      handshake proved on the node that observed it; a second copy would be one fact with two
      representations that can disagree. A runtime ownership fact and a diagnostic observation
      are not the same thing. **Reopen when** a diagnosis rule needs a channel fact that the
      TLS node cannot supply — which would mean the TLS node is incomplete, not that the
      channel belongs in evidence
- [ ] **No `ReportSecurity` field, and no unsafe override.** Both were anticipated by ADR 0028
      and both are deferred under one shared condition, because neither is useful alone: the
      three things a report could record are per-connection (already in the TLS evidence), a
      constant (one policy value, unchoosable), or absent (no override). **Reopen when** a CLI
      or application layer can carry an explicit per-run decision into the report

### Phase 3.2c — PLAIN authentication (complete)

**The first phase in this repository that transmits credential-derived bytes.** Contract
fixed by ADR 0028, mechanisms built by ADR 0029, implementation and its open questions
recorded in **ADR 0030**.

- [x] `Authenticate` taking **exactly one** `HandshakeSession` and one `security.Credential`.
      A `reflect`-based test and a compile-time signature assertion both fail if it ever
      takes a slice
- [x] `SecretFor` called with the **logical endpoint**, recovered from the session label by
      `net.SplitHostPort` and normalized by `security.NewEndpoint` — never the resolved address
- [x] PLAIN payload built inside `internal/adapter/kafka/wire`, in the repository's **one and
      only** `security.Reveal` call site (ADR 0027). The guard was re-verified against
      deliberate violations in an adapter and a probe package before the first byte was written
- [x] `SaslAuthenticate` v1, non-flexible, so the wire framing guard accepts it and a rejection
      arrives as an error code rather than a closed socket. v0 lacks the session lifetime; v2
      is flexible and would misparse
- [x] `security.CredentialTransportPolicy.PermitsCredentials(session.Channel())` consulted
      **before** the endpoint is even parsed, using the fact 3.2b propagated
- [x] Policy refusal recorded as `SKIPPED` + `EXEC_SKIPPED_BY_POLICY`, blocked by the TLS node
      when one exists and by **nothing** on a plaintext path, because no node states TLS is
      absent
- [x] Broker-supplied `ErrorMessage` kept out of evidence — structurally, by there being no
      field for it above the wire boundary. Canary-tested whole and in fragments
- [x] Credential-authority matrix: one credential authorizes all five resolved addresses of its
      endpoint; an address-bound credential is refused for the named endpoint; case and
      trailing-dot forms are accepted; a different name or port is refused
- [x] Zero-byte proofs measured on the **peer's protocol layer above TLS**, for policy refusal,
      endpoint mismatch, unclassified channel and undefined policy alike
- [x] `AuthenticatedSession` as a third session type, so a future Metadata step cannot be
      written against a connection that never presented a credential
- [x] `ChannelEvidence` propagated `Continuation` → `Session` → `HandshakeSession` →
      `AuthenticatedSession`, so a refusal names the fact that caused it rather than asserting it

**Deliberately not done in 3.2c:** no SCRAM, no OAUTHBEARER, no GSSAPI, no mTLS, no Metadata,
no topology, no `Origin`, no diagnosis rule, no finding, no severity, no CLI, no registry, no
generic adapter contract, no retry, no reconnect, no broker selection, no credential forwarding
to discovered brokers, no unsafe transport override, no new dependency, no report-schema change.

**Decisions taken, with their reopen conditions:**

- [x] **The authenticating identity is not recorded.** A username is deployment identity with
      no declared redaction kind, so a plain string holding one would survive into a shareable
      report unpseudonymized. **Reopen when** a diagnosis rule needs to tell two identities
      apart — which needs an identity-bearing attribute kind in ADR 0022's model first
- [x] **A policy refusal consumes the session and closes the socket.** The non-consuming
      alternative was analysed: after a SaslHandshake the broker accepts only that mechanism's
      SaslAuthenticate, so a refused session has no other legal operation on that socket and
      nothing reusable is discarded. **Reopen when** a non-credential operation becomes legal
      on a post-handshake socket
- [ ] **A plaintext policy refusal carries no `blockedBy`.** Nothing in the graph positively
      records "no TLS was attempted", and the TCP node proves nothing about encryption.
      **Reopen when** such a node exists

### Phase 3.3 — Metadata topology discovery (complete)

**The first phase that records endpoints the operator never named.** See **ADR 0031**.

- [x] `Metadata` over the exact authenticated connection — one socket carries DNS, TCP,
      TLS, ApiVersions, SaslHandshake, SaslAuthenticate and Metadata, proven by socket
      identity and a connection count that stays at 1
- [x] **Metadata v1 with an empty topic list**, which at that version means *no topics*.
      v0 cannot express it (empty means every topic); v2+ would receive a cluster
      identifier with no redaction classification; v9+ is flexible and the framing refuses it
- [x] One `kafka.metadata` exchange node (L6) plus one `kafka.broker_advertised` node
      per advertisement (L6), so a later reachability probe has a precise parent
- [x] Broker identity (node ID) and network endpoint identity kept separate, with the
      evidence identifier carrying both so neither conflict case can merge
- [x] Advertised host normalized by the `security.Endpoint` rules and deliberately **not**
      by that type; nothing resolved
- [x] Unusable advertisements — empty host, port 0, negative, out of range — recorded as
      FAIL nodes carrying what arrived, never turned into a usable endpoint
- [x] Identical entries collapse; the collapse is counted so it is visible. Contradictions
      never collapse
- [x] Advertised hosts recorded as declared identity values, pseudonymized in shareable
      reports while node identifiers, controller relationship, counts and edges survive
- [x] No probing, no recursion, no depth limit, no retry, no credential anywhere near a
      discovered endpoint — each asserted by reflection over the API surface

**Deliberately not done in 3.3:** no reachability probing of discovered brokers, no
credential forwarding, no recursion, no execution dedup, no `Origin` field, no diagnosis,
no severity, no findings, no topic/partition/ISR/consumer-group analysis, no retry, no
registry, no CLI, no new dependency, no report-schema change.

**Decisions taken, with their reopen conditions:**

- [x] **`Origin` examined and left deferred.** This phase needed *derivation* — "which
      response produced this fact?" — which the parent edge already records. It did not
      need *provenance* — "how did this endpoint enter the run?" — which a parent edge
      does not encode and `REPORT_SCHEMA.md` forbids inferring from graph shape. The two
      come apart whenever a cluster advertises the bootstrap endpoint back, so origin is
      not a function of the subject. **Reopen when** an execution or topology planner has a
      real consumer for provenance
- [x] **Fact dedup collapses only identical advertisements**, and reports the collapse.
      **Execution dedup does not exist yet** and will be keyed by normalized endpoint, never
      by node identifier
- [x] **Attribute keys stay in the adapter.** `internal/diagnosis/kafka` is still empty, so
      the "second real consumer" condition is unmet and `internal/service/kafka` is not
      created
- [ ] **Metadata is reachable only from an authenticated session.** Kafka serves it on
      PLAINTEXT and SSL listeners too; this is svcdoctor's scope, not the protocol's.
      **Reopen when** a non-SASL Kafka path exists
- [ ] **Two Metadata exchanges over one path collide**, and the second is rejected rather
      than merged. This is ADR 0019's retry case arriving for the first time. **Reopen when**
      a layer owns retry policy

### Phase 3.3b — Generic transport sweep identity (complete)

**A prerequisite, discovered by attempting Phase 3.4 and finding it structurally blocked.**
See **ADR 0032**.

Evidence identifiers are derived from what a node is about, and a DNS lookup is about a name
alone — so `dns.lookup/<host>` allowed at most one lookup per hostname per run. A topology
sweep of a host the bootstrap already resolved was therefore rejected by the graph. That is
routine, not exotic: a single-listener cluster advertises its bootstrap host back.

- [x] `probe.SweepScope` — an opaque, validated, caller-owned label naming one execution.
      Zero value is unscoped
- [x] `probe.ScopedEvidenceID` — the scope as an optional component after the step.
      **Unscoped output is byte-identical to every identifier minted since Phase 2**
- [x] Threaded through `dns.Lookup`, `tcp.Connect`, `tls.Params` and the chain's own
      skipped/unattempted nodes — one sweep, one scope, no probe inventing its own
- [x] Optional `transport.Params.Parent` recording that a sweep derives from the observation
      that caused it. Absent leaves the DNS node a root, as before
- [x] Scope reaches the identifier and **nothing else** — never a subject, never an attribute
- [x] Redaction needs no new rule: wholesale identifier remapping removes it, proven with a
      hostname-shaped canary scope
- [x] Injectivity argument stated honestly, including the arity caveat, and pinned by a test

**Deliberately not done in 3.3b:** no execution dedup, no many-causes→one-execution model,
no `Origin`, no retry policy, no recursion, no concurrency, no Kafka code, no reachability,
no findings, no schema change, no new dependency.

**Decisions taken, with their reopen conditions:**

- [x] **`GraphBuilder` allocates nothing.** A hidden counter would make identifiers depend on
      execution order and turn an inert container into an allocator (ADR 0013). Scope is
      caller-owned. **Reopen** never
- [x] **The derivation parent is singular.** The graph permits several, but a slice would
      pre-empt the many-causes→one-execution question. **Reopen when** a caller genuinely
      deduplicates execution
- [ ] **Scoped/unscoped identifiers are distinguished by arity, not by escaping.** Safe
      because every step mints a fixed number of components. **Reopen when** a producer varies
      its component count per call

### Phase 3.4 — Advertised endpoint reachability (complete)

The consumer Phase 3.3 was built to feed, and the first caller of 3.3b's sweep scope. See
**ADR 0033**.

- [x] `kafka.MeasureAdvertised` — one scoped generic DNS/TCP/TLS sweep per usable
      advertisement, credential-free, sequential, stopping at L3
- [x] **The transport plan is caller-supplied.** A Metadata response carries a host and a
      port and says nothing about whether the listener is plaintext or TLS, so nothing is
      inferred from the port, the bootstrap channel, the node identifier or convention. It
      reuses `transport.TLSOptions` rather than duplicating a TLS model in an adapter
- [x] Transport evidence parented to the advertisement node that named the endpoint —
      derivation, never provenance — with no synthetic wrapper node between them
- [x] Sweep scope = `advertised.` plus the **full** SHA-256 of the advertisement's evidence
      identifier, used as opaque input. Deterministic, order-independent, unique by
      inheritance from the graph's own identifier uniqueness. A 64-bit truncation was
      implemented first and rejected on review: it made uniqueness probabilistic in a scheme
      whose contract is *proven* injectivity (ADR 0019, ADR 0032 §3), and its collision
      failure mode was not uniformly loud — colliding scopes on different hostnames produce
      no identifier collision at all, so nothing fails and two unrelated measurements share
      a label. The full digest costs 48 characters and no compute (ADR 0033 §5.1)
- [x] Bootstrap endpoint advertised back is measured **again** under its own scope, reusing
      no bootstrap DNS, TCP or TLS evidence
- [x] Every connection released before the call returns, proven on both ends: the peer goes
      idle, and each of svcdoctor's own sockets is closed exactly once
- [x] Zero Kafka bytes to a discovered endpoint, measured on a peer that counts what arrives
      above TLS. `reachability.go` imports neither `wire` nor `kmsg` nor `internal/security`
- [x] Generic failure classes only, per-layer latency preserved, no aggregate verdict, no
      finding, no severity

**Deliberately not done in 3.4:** no execution dedup, no protocol request or authentication
against a discovered broker, no credential forwarding, no recursion or depth bound, no
`Origin`, no retry, no concurrency, no findings, no severity, no schema change, no new
dependency, no `GraphBuilder` change.

**Decisions taken, with their reopen conditions:**

- [x] **Execution dedup is deliberately NOT implemented, and this reverses the expectation
      this backlog previously recorded.** ADR 0031 §4 said that when dedup arrives it would be
      keyed by the normalized endpoint; this phase decides it does not arrive yet. A
      deduplicated sweep has two causes and one effect, and `transport.Params.Parent` is
      singular (ADR 0032 §6), so recording it would mean picking one advertisement as *the*
      cause by a tiebreak — leaving the loser with no measurement a finding could reference
      (ADR 0014). **Redundant but truthful execution was chosen over deduplicated execution
      because the graph has no canonical many-causes→one-execution representation.**
      **Reopen when** it has one; the key stays the normalized endpoint, never the node
      identifier
- [x] **The existing `StepTimeout` is the only budget.** It already bounds every DNS, TCP and
      TLS call, which is the one place a topology sweep can block. A per-advertisement or
      phase-global budget would bound the same work twice with numbers that can disagree.
      **Reopen when** a blocking case appears that `StepTimeout` does not cover
- [x] **A cancelled run leaves unreached advertisements with no evidence at all.** Nothing was
      measured about them, and a node claiming otherwise would report svcdoctor's budget as a
      remote failure. **Reopen** never
- [x] **Reachability lives in `internal/adapter/kafka`.** A `topology` subpackage would add a
      boundary with no new responsibility, and could not deliver the isolation it appears to:
      importing the package for `DiscoveredBroker` links `kmsg` transitively anyway. The
      file's own import list is the honest guarantee. **Reopen when** a consumer of the
      advertisement facts exists outside this package
- [ ] **One transport plan applies to every advertisement in a call.** A cluster mixing
      plaintext and TLS listeners needs two calls. **Reopen when** something can say which
      listener is which — nothing on the wire does

### Phase 3.2d — SCRAM (not started, blocked on a dependency decision)

- [ ] SCRAM-SHA-256 / SCRAM-SHA-512, with the dependency route decided first (ADR 0026 §7.4)

### Remaining Phase 3 work

The first real adapter. It is what forces the adapter contract, the registry, service
attribute-key ownership and the topology questions to become concrete, and it must be able to
consume Phase 2's transport engine without reimplementing any of it.

### Boundary and contract work

- [x] Add the Kafka wire dependency with a license and security review — `kmsg` v1.13.1,
      BSD-3-Clause, zero transitive dependencies (Phase 3.1, ADR 0025)
- [ ] Adapter contract and explicit composition-root registration boundary. Phase 3.1
      established that neither is needed yet; the reopen condition is the second adapter or the
      first composition root (ADR 0025)
- [ ] Target normalization for Kafka bootstrap endpoints (L0)
- [ ] Settle service attribute-key ownership, and per-key sensitivity classification for
      redaction's known limit
- [x] Restrict and audit `security.Reveal` to approved wire boundaries — Phase 3.2a, ADR 0027
- [ ] depguard: adapter contract / registry package rule, and an import-level expression that
      a Kafka adapter must not implement generic DNS/TCP/TLS transport

### Protocol and authentication

- [x] ApiVersions (L4) — Phase 3.1
- [x] SASL mechanism discovery (L5) — Phase 3.2a
- [x] PLAIN — Phase 3.2c, ADR 0030. The first credential svcdoctor transmits
- [ ] SCRAM-SHA-256 — Phase 3.2d, needs a dependency decision first
- [ ] SCRAM-SHA-512 — Phase 3.2d, needs a dependency decision first
- [ ] supplied-token OAUTHBEARER
- [ ] mTLS
- [ ] Normalize protocol errors and response codes into evidence at the adapter boundary; no
      raw protocol object crosses it (ADR 0010)

GSSAPI/Kerberos and AWS_MSK_IAM stay detect-and-explain only unless the project explicitly
changes scope.

### Topology

- [x] Metadata discovery (L6) — Phase 3.3, ADR 0031
- [x] Normalize broker endpoints — Phase 3.3, by the `security.Endpoint` rules and
      deliberately not by that type
- [x] Measure every advertised endpoint from the current vantage, credential-free — Phase 3.4,
      ADR 0033. Generic DNS/TCP/TLS only; no protocol request reaches a discovered broker
- [ ] Endpoint deduplication and topology depth policy — orchestration, never the graph.
      **Phase 3.4 deliberately did not take either**: it runs one sweep per advertisement
      because the graph cannot yet attribute one execution to several causes, and there is no
      traversal to bound. See ADR 0033 §3 and §9
- [ ] Credential-forwarding wiring into topology discovery, with `deny` as the default policy
- [ ] Answer the `Origin` / provenance question, now that topology orchestration exists

### Diagnosis rules

**The policy comes first, as its own subphase, and it decides which of the items below are
even written.** The evidence side is now complete enough to settle it — Phase 3.4 produced the
advertised-endpoint transport evidence the questions were waiting on — and writing any rule
before it would answer them by implementation instead of by decision, which is the failure mode
ADR 0017 exists to prevent.

- [ ] **Phase 3.5 — Kafka advertised endpoint diagnosis policy** (decision work; no rules).
      Settles, against the real Phase 3.4 graph: whether generic transport findings should
      exist at all; who owns an advertised-endpoint failure, generic or Kafka; what severity
      inputs replace `Origin`, which stays deferred; partial multi-address success; partial
      multi-broker success; and the exact evidence-reference discipline for a finding whose
      meaning is a *contrast* between the bootstrap half and the discovered half
      (`docs/FINDINGS.md` section 6). **It must not resolve `Origin` as a side effect**: if the
      policy cannot be stated without provenance, that is ADR 0013's reopen condition being met
      deliberately, not incidentally
- [ ] Concrete generic transport rules under `internal/diagnosis/transport/` — **only if the
      policy above says they should exist**
- [ ] `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` rule (`docs/FINDINGS.md` section 6), unblocked by
      that policy. A Kafka rule can already reach its evidence by *derivation* — walking
      `kafka.broker_advertised` to the transport nodes that derive from it — which needs no
      `Origin` (ADR 0031 §6, ADR 0033 §6). What it still lacks is severity and the aggregation
      rules above
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
