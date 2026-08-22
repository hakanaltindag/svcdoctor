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
| 3 | Kafka Vertical Slice | **Validated** — 3.1 adapter boundary and ApiVersions, 3.2a SASL mechanism discovery, 3.2b credential transport safety, 3.2c PLAIN authentication, 3.3 Metadata topology discovery, 3.3b transport sweep identity, 3.4 advertised endpoint reachability, 3.5 advertised endpoint diagnosis policy, 3.6 the advertised endpoint diagnosis rule, 3.6.5 diagnosis output review, 3.7 unusable advertisement diagnosis, 3.7.5 redaction residual-scan correctness complete; **integration validated against a real 3-broker KRaft cluster** |
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
| **Transport severity policy** | **Unblocked by ADR 0042, still unwritten.** ADR 0034 answered it for service-anchored rules; the generic half needed a rule to know whether an endpoint was asked for or discovered, which read as `Origin`. ADR 0042's requested-target anchor supplies that context without `Origin`: an anchored generic rule only ever runs on the sweep the operator caused. **What severity, kind, confidence and vantage such a finding carries is the remaining decision**, and it is Phase 4.9a's | Phase 4.9a resumes with the anchor implemented (ADR 0017 amendment, ADR 0034 §13, ADR 0042 §17) |
| **`Origin` / provenance** | **Examined again in Phase 4.9a-pre and left deferred — the consumer that looked like it needed provenance did not.** Discovery needed only *derivation*, which parent edges already record. Generic transport diagnosis looked like the first real `Origin` consumer, and ADR 0042 showed it is not: it asks which *execution* the operator caused, not how a *subject* entered the run. The advertised-back case that kills `Origin` — one `host:port` with both a discovery-derived node and a lookup-derived path — leaves the anchor untouched, because two sweeps stay two sweeps | An execution or topology planner has a real consumer for **subject** provenance (ADR 0031 §6, ADR 0042 §10) |
| **Generic vs service finding overlap** | **Structurally answered by ADR 0042.** ADR 0034 gave the Kafka finding outright ownership of advertised evidence and defined the duplicate/complementary/causal test; what stayed open was whether generic transport findings could exist at all, which needed run intent `diagnosis.Rule` cannot see. ADR 0042 puts that intent in the graph as an L0 anchor and draws the boundary at **direct** parentage of a sweep root — not descendant reachability, because the advertised sweep is a transitive descendant of the bootstrap target. Ownership is disjoint by construction, with no engine suppression. **Whether such findings exist is now a policy question, not a structural one** | Phase 4.9a resumes (ADR 0034 §16, ADR 0042 §7) |
| **Execution deduplication, and a many-causes→one-execution graph shape** | Phase 3.4 runs one transport sweep per advertisement, including when two advertisements name one endpoint. A deduplicated sweep would have two causes and one effect, and the derivation parent is singular — recording it would mean picking one cause by a tiebreak and leaving the other with no measurement a finding could reference (ADR 0033 §3) | The graph gains a truthful many-causes→one-execution representation; the dedup key stays the normalized endpoint, never the node identifier |
| **Finding identity / duplicate semantics** | Defining when two findings are one conclusion is guesswork today; the engine preserves duplicates rather than discarding a real finding | A real rule set produces duplicates in practice (ADR 0017) |
| **Service attribute-key ownership** | **Settled for the keys that have a second consumer, in Phase 3.6.** A key lives with the code that produces it until something outside that package genuinely reads it; then it moves to a leaf vocabulary package (`internal/service/<service>`) that imports `internal/domain` and nothing else. Three Kafka constants moved on exactly that trigger (ADR 0034 §19); the rest stayed. `internal/domain` still holds no service key | A key acquires a consumer outside the package that produces it |
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
      **Reopened and answered in principle by ADR 0042 §11:** a future rule in
      `internal/diagnosis/transport/` cannot import `tls.AttrVerified`, `dns.AttrAnswers` or
      the step names `dns.lookup`, `tcp.connect` and `tls.handshake`, because depguard forbids
      diagnosis importing probes — and `internal/domain` deliberately holds no step constants.
      The generic transport rule needs the three **step names** to bound its traversal, so the
      anchor phase must create a service-neutral vocabulary leaf on the same terms ADR 0040 §22
      used for `internal/service/postgres`: `internal/domain` only, no behaviour, not named for
      a service. **The package name is left to implementation.** This settles the generic half
      and does **not** settle the service-specific half.

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

## Phase 3 — Kafka Vertical Slice: VALIDATED

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
      **Reopen when** a blocking case appears that `StepTimeout` does not cover.
      *One did, and it was not a topology sweep:* `postgres.startup` had no field to receive
      this budget in and ran unbounded until Phase 4.11d (ADR 0047). The rule held; a step had
      quietly opted out of it
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

### Phase 3.5 — Kafka advertised endpoint diagnosis policy (complete)

**A decision phase. No rule, no finding, no engine change, no production diagnosis code.**
See **ADR 0034**.

It exists because writing the rule first would have answered four questions by
implementation instead of by decision — ownership, severity, two levels of aggregation, and
UNKNOWN handling — in the layer whose entire purpose is not to invent.

- [x] **Ownership: the Kafka finding owns advertised-endpoint transport failures outright.**
      No generic transport finding fires for the same evidence. Resolved by anchoring, not by
      engine suppression, and ADR 0034 §3 defines the general duplicate / complementary /
      causal-parent test the overlap question had been missing since ADR 0017
- [x] **The terminal transport layer is observable**, which was the phase's real blocker. The
      chain mints a TLS node — real or SKIPPED — under every TCP node **iff** the plan required
      TLS. Verified against the real graph and pinned by
      `internal/probe/transport/terminallayer_test.go`. The one gap, a sweep that resolved no
      address, sits exactly where the answer cannot change the verdict
- [x] **Exact trigger, kind, severity, confidence, subject, evidence set, vantage flag,
      discriminator and recommendation mapping** all fixed, so Phase 3.6 invents nothing
- [x] **Partial multi-address: no finding.** Any path reaching the terminal layer withholds the
      unreachability claim, and no partial-reachability finding is authorized — its
      actionability depends on which address a real client would select, which svcdoctor does
      not observe
- [x] **Partial multi-broker: one finding per unreachable advertisement, no aggregate.** An
      aggregate would state no independent fact, and the natural wording would be false: the
      broker that answered Metadata was demonstrably reachable
- [x] **UNKNOWN never becomes a remote failure.** Proven unreachable, not proven reachable and
      measurement incomplete stay three distinct outcomes
- [x] **`Origin` examined a third time and left deferred** — a rule anchored at the
      advertisement has its context by construction

**Deliberately not done in 3.5:** no rule function, no `internal/diagnosis/kafka` code, no
`internal/diagnosis/transport` code, no engine change, no finding constructed in production
code, no severity enum change, no schema change, no adapter or probe behaviour change, no
`internal/service/kafka` package, no dependency change.

**Decisions taken, with their reopen conditions:**

- [x] **Severity is the impact of a finding's claim about its own subject**, so an unreachable
      advertised broker is ERROR whether one or three are affected. Count-derived severity was
      rejected: it encodes a replication and leadership model svcdoctor never observed.
      **Reopen when** svcdoctor observes replication topology
- [x] **ADR 0017's severity blocker dissolves for service-anchored rules and stands for
      unanchored ones.** That asymmetry is why a Kafka rule is authorized and a generic
      transport rule is not. **Reopen when** a generic transport rule acquires an owner
- [x] **Attribute-key ownership reopen condition is now met.** `internal/service/kafka` is
      authorized as a leaf holding exactly `StepMetadata`, `StepBrokerAdvertised` and
      `AttrBrokerNodeID`; the move is Phase 3.6's and is purely mechanical. depguard is not
      weakened and no Kafka key enters `internal/domain`
- [x] **One unreachable advertised broker will make a run exit non-zero**, because ERROR
      derives `PROBLEMS_FOUND`. Accepted deliberately: exit 1 means svcdoctor worked and found
      a target-side problem, which is exactly this. **Reopen** never
- [ ] **Controller-aware severity: analysed and not used.** The controller is a point-in-time
      fact that moves on election, and a client does not need it to produce or consume.
      **Reopen when** svcdoctor diagnoses admin operations
- [ ] **A TLS-all-failed sweep is reported as unreachable**, with the failing layer and class
      in the summary. **Reopen when** a certificate-shaped Kafka finding refines it out
- [x] **An unusable advertisement produces no reachability finding.** A configuration finding
      for "the cluster advertises an endpoint no client can act on" is genuinely independent
      and deserves its own decision. **That decision was taken in Phase 3.7 (ADR 0035)**, which
      added `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`. The reachability rule is unchanged: the two
      are mutually exclusive by construction

### Phase 3.6 — Kafka advertised endpoint diagnosis rule (complete)

**The first diagnosis rule svcdoctor ships, and the first finding it can produce.** It
implements ADR 0034 and decides nothing: every field of the finding was fixed in Phase 3.5.

- [x] `internal/diagnosis/kafka` — `AdvertisedEndpointUnreachable`, one exported rule function
      plus the `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` code constant. `diagnosis.Rule` is
      unchanged: the graph is still the only argument, and the function already had the shape
- [x] `internal/service/kafka` — the leaf vocabulary package ADR 0034 §19 authorized, holding
      exactly `StepMetadata`, `StepBrokerAdvertised` and `AttrBrokerNodeID`. The adapter
      re-exports all three, so every wire value, evidence identifier and serialized report is
      byte-identical. It imports `internal/domain` and nothing else
- [x] depguard gained `service-vocabulary-is-a-leaf`, so the leaf property is enforced rather
      than remembered. No existing rule was weakened; `diagnosis-is-pure` still denies the
      adapter, and the move exists precisely because it does
- [x] Anchoring verified empirically: the rule enumerates advertisements and walks `Children`
      down. It reads no sweep scope, parses no evidence identifier, matches no subject, and
      names no `Origin` — pinned by an AST scan over the package's own sources
- [x] The terminal layer is read off the graph, never from a plan field, a port, or the
      bootstrap channel
- [x] Report integration: every authorized finding passes ADR 0014 reference validation, and
      the canonical JSON is stable across graph assembly order
- [x] Redaction: the finding carries identity only on its subject and its evidence references,
      where structural redaction already transforms it. Prose is byte-identical before and
      after, so no new heuristic was needed (`test/security/kafka_finding_redaction_test.go`)
- [x] Nine mutations of the implementation were run and every one was caught by a named test

**Deliberately not done in 3.6:** no generic transport rule, no engine change, no suppression,
no registry, no `Origin`, no aggregate finding, no partial-reachability finding, no schema
change, no domain change, no dependency change, no new `security.Reveal` call site.

**Implementation-level decisions, none of which change ADR 0034's policy:**

- [x] **The finding's `layer` is L6.** ADR 0034 fixes every other field and does not name this
      one. L6 is the layer the *claim* concerns — the advertisement it anchors at is an L6 node
      — and not the earliest failing layer, which travels in the summary per
      `docs/FINDINGS.md` §5 while the report derives `firstBrokenLayer` from the graph. Nothing
      reads a finding's layer yet. **Reopen when** a renderer gives it meaning
- [x] **The terminal-layer quantifier is universal.** "TLS when the sweep's TCP nodes have TLS
      children" is read as *every*, not *any*. The pinned biconditional makes the two agree on
      every graph the chain produces, so the choice is visible only where it is already
      violated — and there the universal reading withholds a claim instead of calling a passing
      TCP path insufficient. **Reopen** never, while the invariant holds
- [x] **A structurally unexpected sweep withholds every claim.** An advertisement with two
      Metadata parents, a transport node in the wrong place, or two handshakes under one
      connection produces no finding rather than a guess. ADR 0034 does not enumerate these
      because no producer creates them; the bias is `docs/FINDINGS.md` §4
- [x] **`domain.NewFinding` cannot fail here, and the omission branch is proven unreachable**
      rather than trusted. `Rule` has no error channel and silently returning fewer findings is
      the failure mode the claim discipline exists to prevent, so
      `TestEveryAuthorizedShapeBuildsAValidFinding` drives the whole authorized matrix

**One documentation imprecision found in ADR 0034 and left uncorrected** because the intent is
unambiguous: §11.5 states "no reference is ever a PASS node" immediately after a table whose
every row includes the `kafka.metadata` node, which §5 requires to be PASS. The invariant is
§11.3's, and §11.3 scopes it correctly to the *causal set*. The implementation follows §11's
numbered list: exchange + advertisement + causal set, and no PASS node among the causal set.

### Phase 3.6.5 — Diagnosis output review (complete)

**A product checkpoint, not a feature.** The first finding was inspected as a user-facing
artifact across seven real scenarios — confirmed DNS/TCP/TLS, partial success, incomplete
measurement, multi-broker, and bootstrap-equals-advertised — in both `LOCAL_FULL` and
`SHAREABLE_REDACTED` form, to decide whether the finding contract scales to many findings
before many findings exist.

**Verdict: the machine contract passes and needed no change.** A sketch renderer built from
structured fields and graph traversal alone reproduced every fact the prose carries, without
parsing a sentence. No policy, code, kind, severity, confidence, evidence-reference or
partial-success semantics changed.

- [x] **One real defect found and fixed (wording only).** The finding's `detail` named a
      terminal layer on a sweep whose lookup produced no address — a case ADR 0034 §4 calls
      **unknowable**, because such a sweep mints no TCP node and nothing records whether a
      handshake would have been required. It always said `L2`, which is wrong for every
      TLS-required cluster with broken DNS. The layer is now named only when a transport path
      was actually measured, and the impossibility is carried by a type (`reachability`) rather
      than by a comment
- [x] **A second wording defect fixed:** "no measured path reached L2" beside a summary naming
      L2 as the failing layer reads as a contradiction. A path *arrives at* a layer and then
      fails to *complete* it; the verb now says so, and the layer label (`L2 (tcp)`) is
      included for operators who do not think in layer numbers
- [x] **`finding.layer` semantics documented** — `docs/REPORT_SCHEMA.md` §7.5. It was listed in
      three documents and defined in none, while `layer: "L6"` sits beside
      `firstBrokenLayer: "L2"` in the same report. It is the layer of the **claim**; the
      section says which field a consumer should read for "where did it break?"
- [x] **The `evidenceRefs` renderer contract documented** — `docs/REPORT_SCHEMA.md` §7.4.
      References are minimal proof, not a display list; a renderer traverses the graph from
      them, and classifies cited nodes by their own `state` rather than assuming their roles
- [x] **The finding quality bar written** — `docs/FINDINGS.md` §3.1, eighteen items binding on
      every future rule. The load-bearing one is *a renderer must never parse `summary`*
- [x] **`docs/DIAGNOSIS_EXAMPLES.md` created**, because the product output was previously
      invisible without writing a harness. Illustrative, with the tests named as authoritative

**Reviewed and deliberately not changed:**

- [ ] **The `summary` string is overloaded** — it ends with `earliest evidenced failure L2
      TCP_CONNECTION_REFUSED, TCP_CONNECTION_TIMEOUT`, a comma-joined list of enum constants
      inside prose, and every part of it is already derivable structurally. It violates
      §3.1 item 14 in spirit while satisfying item 13 in fact. Left alone because changing it
      is a product decision that wants a renderer to judge against, and no renderer exists.
      **Reopen when** the first renderer lands, or when a second finding has to imitate the
      style — whichever comes first
- [ ] **A `PROBLEMS_FOUND` report says nothing about cluster availability**, and cannot: an
      unreachable advertised broker is per-subject impact. The wording risk is real but the
      fix belongs to a renderer, not to the finding
- [ ] **A shareable report's `evidenceRefs` become opaque** (`evidence-004`), so raw shareable
      JSON is materially harder to read than raw local JSON. Correct per ADR 0018 and worth
      knowing before someone reads one without a renderer

### Phase 3.7 — Kafka unusable advertisement diagnosis (complete)

**The second Kafka finding**, taking the case ADR 0034 §14 placed out of scope. Policy and rule
land in the same phase — see **ADR 0035** — because every structural question was already
settled and only three small ones were open.

- [x] `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` in `internal/diagnosis/kafka`, anchored at
      `kafka.broker_advertised`. `CONFIRMED` / `ERROR` / `HIGH`, subject reused unrepaired,
      two evidence references and no transport evidence, one recommendation, no discriminator
- [x] **`vantageDependent: false` — the first finding in the repository where it is.** The
      defect is in the values that arrived, not in the path to them, so no other network
      position sees anything different. Copying `true` from the reachability rule would have
      been an actively misleading field inviting a retry that cannot help
- [x] **The claim stops short of a cause.** Metadata says what a broker reports, never how it
      arrived at it — a proxy or a service mesh produces the same bytes — so
      `advertised.listeners` is never named, in the code, the summary, the detail or the
      recommendation
- [x] **The two Kafka findings are mutually exclusive by construction**, not by suppression:
      the reachability rule requires a PASS advertisement and this one requires FAIL. Pinned on
      the drift graph where the two enforcing mechanisms come apart
- [x] **No new field, enum, attribute or moved constant.** The subcase — missing host versus
      impossible port — is already distinguishable from `kafka.broker.advertised_host` and
      `kafka.broker.advertised_port` on the cited node, so prose does not duplicate it
- [x] Ten mutations run; **two escaped and exposed real test gaps**, both closed (below)

**Two test gaps a mutation run found, and what they were hiding:**

- [x] **The state check was untestable behind the class check.** Every withholding case was
      also rejected by the failure class, so deleting `State() != FAIL` changed no result. An
      `UNKNOWN` advertisement carrying the expected class now isolates it — "not determined"
      must never become "determined to be unusable"
- [x] **Exclusivity was guaranteed by the wrong mechanism.** In every real graph the
      reachability rule stays silent for two reasons at once — the advertisement is not PASS
      *and* there is no sweep — so the state check could be removed undetected. A drift graph
      with a sweep beneath an unusable advertisement separates them

**Deliberately not done:** no aggregate finding, no generic protocol finding, no Kafka failure
class, no structured reason field, no engine change, no schema change, no domain change, no
`Origin`, no dependency change, no new `security.Reveal` call site, and no change to the Phase
3.6 rule beyond extracting a shared node-identifier helper.

**Open, recorded rather than solved:**

- [x] **A pre-existing redaction defect, surfaced here and not caused here — fixed in Phase 3.7.5.** A broker
      advertising `host="" port=0` produces the subject `:0`. Redaction classifies it as a
      hostname, then `verifyNoResidual` scans the encoded report for the literal `:0` — which
      every report contains, in `"info":0` among the severity counts and in any timestamp with
      a zero in its seconds field. The scan matches its own punctuation and **redaction fails
      closed on a transformation that succeeded**, so no shareable report can be produced for
      such a run. It fails closed rather than leaking, which is the right direction, but it
      blocks a legitimate report. Pinned by a test named as a known defect. **Not fixed here:**
      widening the residual scan is a change to a security-critical component and deserves its
      own decision rather than a patch inside a diagnosis phase
- [ ] **An unrepresentable advertisement has no finding, and cannot have one yet.** An entry
      whose text cannot be a subject reference — a control character, invalid UTF-8, leading
      whitespace — produces **no evidence node** and survives only as
      `kafka.metadata.unrepresentable_entry_count` on the exchange. A finding with nothing to
      reference is not expressible under ADR 0014. **Reopen when** that case needs diagnosing
- [ ] **An `ENDPOINT` subject that is not a usable endpoint.** Reusing the producer's kind is
      right — the alternative invents a target — but the oddity is real. **Reopen when** a
      subject kind for a reported-but-unusable target is justified on its own evidence

### Phase 3.7.5 — Redaction residual-scan correctness (complete)

**A security correctness fix**, triggered by a producible Kafka state and fixed generically.
No ADR: the contract in ADR 0018 is unchanged — fail closed, structural, no inference — and
this phase corrects an implementation that did not match it. `docs/SECURITY.md` gained the
residual-scan section that states it explicitly.

**The reported symptom.** A broker advertising `host="" port=0` produces the advertisement
subject `:0`. Redaction transformed the report correctly and then refused it, because the
residual scan searched the raw encoding for `:0` and found it in `"info":0` among the severity
counts. No shareable report could be produced for such a run.

**Two defects, both generic, neither Kafka-specific:**

- [x] **Identity discovery treated a whole endpoint reference as a hostname when its port was
      not a usable port number.** `splitHostPort` reported "no port" for `:0`, `broker:0` and
      `[2001:db8::1]:0` alike, and every caller then read the entire display string as the
      identity. Split into a syntactic `endpointParts` and a `looksLikeEndpoint` predicate that
      keeps the *undeclared plain string* heuristic exactly as narrow as it was
- [x] **The residual scan searched serialized bytes rather than string positions.** It now
      decodes and checks string leaves and object keys, which is complete for every value the
      package protects — all of them are string-typed in the schema — and removes collisions
      with punctuation, numbers, timestamps and durations entirely

**Three further correctness bugs fell out of the first fix, all previously silent:**

- [x] **A pseudonym was invented where no host existed.** `:0` redacted to `host-001`, telling a
      reader the cluster named a host it never named. It now passes through as `:0`
- [x] **An IPv6 literal with an out-of-range port was pseudonymized and counted as a hostname.**
      `[2001:db8::1]:0` now becomes `ip-001:0`, and the IP and hostname counts are right
- [x] **One host could hold two pseudonyms.** `broker` on an attribute and `broker:0` in a
      subject were different map keys, so the same host redacted two ways and the hostname
      count was inflated. The port is now preserved and the host resolves to one pseudonym

**Fail-closed proven, not assumed.** Ten surfaces are planted with a raw value in turn —
hostname, IPv4 and IPv6 in a subject, declared host attribute, declared host list, hostname and
IP in prose, original evidence identifier, target, vantage — and each must be rejected. Seven
production mutations were run and every one was caught, including relabelling a `LOCAL_FULL`
report as shareable without transforming it.

**Open, recorded rather than solved:**

- [ ] **An identity whose text occurs inside other report text still trips the scan.** A host
      named `kafka` collides with the service identifier, `host` with an attribute key and with
      the pseudonym `host-001`, `0` with a timestamp. Such a run fails closed and cannot produce
      a shareable report. It is far narrower than what it replaced — that broke every endpoint
      with an out-of-range port — and no shape-based rule can settle it, because whether an
      occurrence of `host` is the hostname or part of `probe.host` is a question about
      provenance rather than text. **The fix is verification that checks identity-bearing
      surfaces structurally instead of searching the serialized document**, keeping the
      byte-level net only for surfaces the transformer does not know. Pinned by
      `TestKnownLimitationIdentityTextOccurringInOtherReportText`. **Reopen when** a shareable
      report is blocked in practice, or before the first release that publishes them
- [ ] **Disabling the residual scan breaks no test, by construction.** It is dead code on a
      correct transformation, so its behaviour is covered by calling it directly rather than
      through `Redact`. A wiring regression would not be caught; the trade is deliberate

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
- [x] Answer the `Origin` / provenance question — examined in Phase 3.3, 3.4 and 3.5 and
      **deferred every time**, most recently because a rule anchored at a service fact needs
      no provenance at all (ADR 0034 §21)

### Diagnosis rules

**The policy comes first, as its own subphase, and it decides which of the items below are
even written.** The evidence side is now complete enough to settle it — Phase 3.4 produced the
advertised-endpoint transport evidence the questions were waiting on — and writing any rule
before it would answer them by implementation instead of by decision, which is the failure mode
ADR 0017 exists to prevent.

- [x] **Phase 3.5 — Kafka advertised endpoint diagnosis policy (complete).** Decision work;
      no rule implemented. See **ADR 0034**. It settled ownership, the exact trigger, the
      terminal-layer question, both aggregation levels, UNKNOWN handling, kind, confidence,
      severity, subject, evidence discipline, vantage, discriminator and the recommendation
      mapping. `Origin` was examined a third time and **stays deferred**: a rule anchored at
      the advertisement has its context by construction and never asks how an endpoint entered
      the run
- [x] **Phase 3.6 — the `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` rule (complete).** Implemented
      under `internal/diagnosis/kafka/` with no policy invented. `internal/service/kafka` was
      created as the leaf vocabulary package and the three constants moved into it with
      byte-identical values; depguard was strengthened rather than weakened. The rule is
      anchored, pure, deterministic, and the only exported symbols are the rule function and
      its finding code
- [ ] Concrete generic transport rules under `internal/diagnosis/transport/` — **not
      authorized.** ADR 0034 gives advertised-endpoint evidence to the Kafka rule, and whether
      generic transport findings exist at all needs run intent `diagnosis.Rule` cannot see
- [ ] Protocol/security mismatch rules
- [ ] Privilege-aware skipped states

### Validation

- [x] **Kafka integration environment and fixtures** — `test/integration/kafka/`, a real
      three-broker Apache Kafka 4.0 KRaft cluster behind `make integration-kafka`. Excluded
      from `go test ./...` by the `integration` build tag; the ordinary gate needs no Docker
- [x] **Phase 3 integration validation: PASS.** See
      `docs/validation/KAFKA_PHASE3_VALIDATION.md`. Healthy baseline, advertised DNS/TCP/TLS
      failures, partial-address success, multi-broker partial failure, SASL/PLAIN success and
      rejection, connection ownership and redaction all validated against the real cluster and
      differentially against kcat
- [ ] Canonical JSON report acceptance tests for the Kafka slice. Terminal, Markdown and HTML
      renderers are Phase 5; JSON is already canonical and needs no renderer

**What the real cluster taught us, beyond confirming the contracts:**

- [x] **The Metadata `controllerId` field does not name the controller under KRaft.** Eight
      consecutive reads of an idle three-broker cluster returned `1, 1, 2, 1, 1, 3, 2, 3`
      while the quorum leader stayed node 1: KRaft controllers are not brokers, so a broker
      answers with an arbitrary live one. **This vindicates ADR 0034 §15** — a rule reading it
      would have produced different severities on identical runs. The attribute's doc comment
      claimed it named the controller and was corrected; no behaviour changed
- [x] **A real Kafka broker cannot emit an unusable advertisement.** `port=0` is replaced by
      the bound port and an empty host is replaced by the broker's hostname, so
      `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` (ADR 0035) has no `advertised.listeners` route. Its
      realistic sources are a proxy rewriting Metadata, a non-Kafka implementation, or a
      corrupted response. The finding stays: svcdoctor does not get to assume the response came
      from Apache Kafka. Recorded as a negative result
- [x] **No real run produced an unrepresentable Metadata entry**, so that gap stays open at its
      existing priority rather than rising
- [x] **The Phase 3.7.5 residual-scan limitation did not occur naturally.** Every hostname the
      environment produces redacts cleanly, so it remains a backlog item and not a release
      blocker
- [ ] **svcdoctor cannot reach Metadata on a cluster without SASL.** `kafka.Metadata` takes an
      `*AuthenticatedSession` whose only constructor is a successful authentication, so a
      PLAINTEXT or SSL-only listener — the common development shape — has no path to topology
      discovery. Already recorded in `internal/adapter/kafka/metadata.go` and ADR 0031 as this
      repository's restriction rather than Kafka's; integration made its practical cost
      concrete, because the validation cluster had to be SASL_SSL to exercise anything above
      L5. **Reopen when** application orchestration exists and has to configure a real run

---

## Phase 4 — PostgreSQL Vertical Slice

PostgreSQL is the second real implementation, and its job is as much to validate the shared
abstractions Kafka produced as to add a service. An abstraction Kafka introduced that
PostgreSQL cannot use is a signal to narrow it, not to generalize it further.

The decomposition below replaces the eight-item sketch this section carried before Phase
4.0. It is derived from measured protocol behaviour, not from the Kafka sequence: see
`docs/validation/POSTGRES_PHASE4_PROTOCOL_STUDY.md` for the evidence and ADR 0036 for the
decisions.

### Phase 4.0 — Discovery and protocol contract: COMPLETE

- [x] Repository reconstructed from source; every baseline gate green before and after
- [x] PostgreSQL protocol lifecycle verified against PostgreSQL 18.6 and 14.24, pgBouncer
      1.25.2 and a non-PostgreSQL peer, rather than from documentation alone
- [x] ADR 0036 — the session evidence model, TLS negotiation, success boundary, `ErrorResponse`
      handling, layers, subject, failure classes, library choice, exclusions
- [x] ADR 0037 — `AttrKindIdentity`, closing the redaction gap ADR 0030 predicted
- [x] Integration matrix and differential-oracle plan designed (ADR 0036 §12, and below)
- [x] No production Go code written; no dependency added

Three results changed the design and are worth carrying forward:

1. **`AuthenticationOk` is not success.** `3D000` (database does not exist) and `42501`
   (`CONNECT` revoked) both arrive after it and before `ReadyForQuery`.
2. **pgBouncer collapses the SQLSTATE vocabulary** to `08P01`, so no rule may assume its
   SQLSTATE fires, and no finding may say "I reached PostgreSQL".
3. **`ParameterStatus` already carries `in_hot_standby` and `default_transaction_read_only`**
   on every supported version, so the first slice executes no SQL and
   `pg_is_in_recovery()` is unnecessary rather than deferred.

### Phase 4.1 — Identity redaction: COMPLETE

Generic core work. It blocked everything below it: no PostgreSQL evidence node could exist
until a role name and a database name could be pseudonymized.

- [x] `domain.AttrKindIdentity`, `domain.IdentityAttr`, the `identity` wire tag, appended so
      no existing kind is renumbered
- [x] `domain.RedactionCounts.Identity`, and the comment denying its existence removed
- [x] `internal/security/redaction`: collect, pseudonymize, prose-replace, residual-verify
- [x] `docs/REPORT_SCHEMA.md` records the new kind and the new count; `schemaVersion` stays
      `1` because the change is additive under its own section 1
- [x] `test/security` canaries for a role, a database and a tenant, alongside a password
      canary proving the secret boundary is untouched
- [x] Architecture guard: an AST scan proving `internal/domain` and
      `internal/security/redaction` contain no service-specific policy, plus a behavioural
      test proving no key-name inference
- [x] ADR 0037 marked implemented, with the questions it did not reach settled by precedent

Decisions the implementation settled, recorded in ADR 0037's status block: separate pseudonym
namespaces, global-once-declared propagation, no pseudonym for an empty identity, and no
special case in the residual scan.

**Does not include** L0 target normalization, which is the other half of the identity
question and belongs to the phase that parses a connection string.

**Known limit, inherited not introduced.** An identity whose text is a substring of the
report's own vocabulary — a role named `PASS`, `error` or `host-001` — fails the residual
scan closed, so such a run cannot produce a shareable report. A *hostname* with the same text
behaves identically and did before this phase. Settling it needs verification that checks
identity-bearing surfaces structurally instead of searching decoded strings; see
`docs/SECURITY.md`.

### Phase 4.2 — Channel authority moves to the TLS probe: COMPLETE

Small, generic, and a prerequisite for sending any PostgreSQL credential.

- [x] `probe/tls.Result.Channel()`, derived from the handshake it performed;
      `Verified()` now derives from it, so the package has one place that turns an
      observation into a claim
- [x] `transport.channelOf` deleted; the chain copies `session.Channel()` and
      cannot reinterpret it
- [x] `forbidigo` split into two rules with distinguishable messages, and the
      exclusions matched on that text, so each package receives one authority
      without the other. The chain **lost** TLS-constant authority: this is a
      narrowing
- [x] `depguard` denies `crypto/tls` to adapter production code, which removes the
      capability to re-derive a channel by type assertion
- [x] Guard verified in both directions against nine deliberate violations
- [x] ADR 0029 amended, not superseded; ADR 0036's `SSLRequest` finding recorded
      as the trigger
- [x] Zero Kafka production changes; zero dependency, schema, domain and redaction
      changes

Narrowing the exclusions had a second effect worth recording: the transport chain
previously held a blanket `forbidigo` exemption, which also exempted it from the
`security.Reveal` ban. It no longer does.

**Deliberately not done.** `internal/adapter/postgres` was not granted plaintext
authority in advance, because the package does not exist. A protocol observing
`SSLRequest → 'N'` genuinely establishes known plaintext and will need the same
narrow grant the transport chain has; that is one exclusion rule added beside the
existing one. Recorded as a reopen condition on ADR 0029 rather than pre-opened.

### Phase 4.3 — Wire package, SSLRequest and startup: COMPLETE

The first PostgreSQL code. No credential is sent in this phase.

- [x] `internal/adapter/postgres/wire`: `SSLRequest`, `StartupMessage`, the 5-byte typed
      header, `ErrorResponse` and `Authentication` decoders. **Zero new dependencies**
- [x] `postgres.ssl_request` (L3), with the CVE-2021-23222 surplus-byte check and the
      CVE-2024-10977 rule that an `E` message is never read
- [x] TLS upgrade on the same socket through `probe/tls.Handshake`, parented to the
      `ssl_request` node
- [x] `postgres.startup` (L4): protocol version 3.0, the demanded authentication method,
      the SASL mechanism list, and SQLSTATE on a rejection
- [x] `AUTHZ_NOT_PERMITTED` added to `domain.FailureClass`
- [x] `internal/adapter/postgres` granted plaintext-only channel authority, closing the
      reopen condition ADR 0029's amendment recorded
- [x] Scripted peer at the protocol boundary, over a loopback listener, with a real
      server-side TLS handshake
- [x] Ownership tests proving no redial and exactly one owner at every instant
- [x] The Phase 4.1 producer obligation made real: role and database are recorded as
      `IdentityAttr`, and `test/security` proves a `StringAttr` would leak

**`RESOURCE_NOT_FOUND` was deliberately not added.** ADR 0036 section 16 authorizes it, but
`3D000` arrives after `AuthenticationOk`, which this phase's state machine cannot reach. A
class with no reachable producer would be untested speculation; it arrives with Phase 4.5.

**ADR 0036 section 4 was corrected by measurement.** The `disable` plan no longer sends an
`SSLRequest`: a server that answers `S` has already given the socket to its TLS layer, so a
plaintext `StartupMessage` afterwards is read as a TLS record and the connection dies —
observed against PostgreSQL 18.6. The node is still recorded, as `SKIPPED` by policy, which
preserves the plaintext blocker carrier the section wanted.

### Phase 4.4a — SCRAM decision and protocol verification: COMPLETE

No Go code. The `security.Reveal` count, the dependency graph and the report schema are
unchanged. ADR 0038 and `docs/validation/POSTGRES_PHASE4_SCRAM_STUDY.md` are the output.

- [x] SCRAM-SHA-256 exchange verified against PostgreSQL 18.6, 14.24 and pgBouncer 1.25.2
- [x] `AuthenticationSASLFinal` proven **insufficient** for success — measured through
      pgBouncer, which follows a verifying signature with `08P01` and no `AuthenticationOk`
- [x] `AuthenticationOk` proven insufficient on its own: nothing obliges a peer to prove
      itself first, and RFC 5802 §5 makes the client's verification a MUST
- [x] **PostgreSQL applies SASLprep to passwords** — a raw-password client gets `28P01` for a
      correct password, on both majors. Scope narrowed to printable ASCII rather than adding
      a second SASLprep implementation; ADR 0038 §11
- [x] Iteration count measured as unbounded server-side (`max_val 2147483647`, ≈ 8 min of
      CPU) and unbounded in libpq; ceiling fixed at 1 048 576
- [x] `crypto/pbkdf2` confirmed present in the pinned toolchain — **no new dependency**
- [x] `internal/adapter/postgres/wire` confirmed already able to call `security.Reveal`,
      verified in both directions — **no lint change needed**
- [x] Read-ahead boundary measured: a `bufio.Reader` steals 455 bytes of Phase 4.5's session;
      `wire.ReadMessage`'s exact-length reads steal none
- [x] MD5, cleartext and `SCRAM-SHA-256-PLUS` decided: observed and declined, each with its
      own reason and its own failure class

### Phase 4.4b — Authentication: COMPLETE

Implements ADR 0038. **The second phase in svcdoctor that transmits credential-derived
bytes**, and the second and last production `security.Reveal` call site.

- [x] SCRAM-SHA-256 (RFC 5802) in `internal/adapter/postgres/wire/scram.go`, from
      `crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`, `encoding/base64`.
      **No new dependency**
- [x] Verified against the RFC 7677 published test vector, not only against itself
- [x] The second production `security.Reveal` call site — two total, one per service
- [x] The gate, in the implemented order: mechanism → channel → policy → endpoint →
      `SecretFor` → wire → `Reveal` → printable-ASCII check (ADR 0038 amendment A)
- [x] PASS requires **both** a verified ServerSignature and `AuthenticationOk`
- [x] Stops at `AuthenticationOk`; `ParameterStatus`, `BackendKeyData` and `ReadyForQuery`
      stay unread, proven against a real server
- [x] Printable-ASCII password scope (`U+0020`–`U+007E`), refused outside it as `UNKNOWN` +
      `EXEC_UNSUPPORTED_BY_SVCDOCTOR` with zero bytes sent. No SASLprep, no Unicode dependency
- [x] Iteration ceiling 1 048 576, enforced before any PBKDF2 runs; low counts accepted
      and recorded
- [x] Server nonce must strictly extend the client nonce
- [x] Policy refusal is `SKIPPED` + `EXEC_SKIPPED_BY_POLICY`, blocked by the
      `postgres.ssl_request` node on a plaintext path and the `tls.handshake` node on an
      unverified one
- [x] `28P01` → `AUTH_CREDENTIALS_REJECTED`; `28000` → `AUTHZ_NOT_PERMITTED`; **`08P01`
      deliberately unmapped** — it is pgBouncer's default code and proves nothing about the
      cause, so it degrades to `PROTOCOL_UNEXPECTED_RESPONSE` (ADR 0038 amendment B, which
      also corrects ADR 0036 §10)
- [x] MD5, cleartext, GSS, SSPI, Kerberos, SCM and `-PLUS` observed and declined as
      `UNKNOWN` + `AUTH_MECHANISM_UNSUPPORTED`, zero bytes, no fallback
- [x] `AuthenticatedSession` type-state: a second authentication does not typecheck
- [x] Leak matrix over every SCRAM intermediate, every fmt verb, evidence, report and errors
- [x] 16 mutation guards, each verified to compile and to flip a test
- [x] `forbidigo` verified in ten directions; **two blanket grants narrowed** (ADR 0038
      amendment C)
- [x] `make integration-postgres`: ten scenarios against real PostgreSQL 18.6

**No `domain` change, no `FailureClass` added, no report schema change, no redaction change,
no Kafka change.** Two attribute keys under the existing `postgres.` namespace.

### Phase 4.5a — Session decision and protocol verification: COMPLETE

No Go code. `security.Reveal` count, dependency graph, `FailureClass` count and report
schema all unchanged. ADR 0039 and `docs/validation/POSTGRES_PHASE45_SESSION_STUDY.md` are
the output.

- [x] The `AuthenticationOk` → `ReadyForQuery` window measured frame by frame on 18.6, 14.24,
      a real streaming standby, and pgBouncer 1.25.2
- [x] `ReadyForQuery` confirmed as the session boundary; `3D000`, `42501` and `53300` all
      reproduced after `AuthenticationOk`, each as **frame 1 with zero `ParameterStatus`**
- [x] **ADR 0036 §5 corrected**: `57P03` arrives *pre-authentication* from
      `BackendInitialize`, so it is a `postgres.startup` fact
- [x] **pgBouncer served a complete passing session with its backend stopped** — which fixes
      what a passing session node may claim
- [x] `ParameterStatus` inventory: 15 keys on 18.6, 13 on 14.24. `server_version_num` is sent
      by neither; `search_path` is 18.6-only
- [x] Allowlist decided: four keys kept, `session_authorization` and `search_path` dropped as
      identity, nine dropped for want of a consumer
- [x] `in_hot_standby` verified `on` against a real standby — and
      `default_transaction_read_only` measured `off` there, so the two are independent
- [x] `BackendKeyData` decided: parsed for length, discarded whole
- [x] No SQL re-verified against the facts actually needed

### Phase 4.5b — Session and ReadyForQuery: COMPLETE

Implements ADR 0039 and completes the PostgreSQL vertical slice. **The terminal step:**
svcdoctor sends `Terminate` and closes, and no connection is returned.

- [x] `postgres.session` (L5), parented to whatever `AuthenticatedSession.Evidence()` names
- [x] PASS **only** on `ReadyForQuery`; authentication is never rewritten by a session failure
- [x] `RESOURCE_NOT_FOUND` added — the second class ADR 0036 §16 authorized, held back since
      Phase 4.3 for want of a reachable producer. `FailureClass` count 38 → 39
- [x] `3D000` → `RESOURCE_NOT_FOUND`; `42501` → `AUTHZ_DENIED`; everything else, `53300`
      included, → `PROTOCOL_UNEXPECTED_RESPONSE` with the SQLSTATE recorded
- [x] **Step-scoped classification**, with the cross-step matrix pinned: the same `3D000` or
      `42501` at `postgres.startup` or `postgres.authentication` stays weak
- [x] Refactor guard: a shared global SQLSTATE table breaks the suite
- [x] Four-key `ParameterStatus` allowlist enforced **structurally** —
      `wire.SessionParameters` has four fields and no map, so a dropped key has nowhere to go
- [x] Cardinality guard: a fifth key fails a test
- [x] `session_authorization` and `search_path` dropped at the wire boundary, with canaries
- [x] `BackendKeyData` validated for length and discarded whole; PID and secret both absent
      from LOCAL_FULL and SHAREABLE reports
- [x] `postgres.transaction_status` recorded; a non-`idle` value is a fact, not a failure
- [x] Partial observations retained per attribute on FAIL and UNKNOWN, per the TLS precedent
- [x] Repeated allowlisted keys take the last value (ADR 0039 amendment A)
- [x] `NoticeResponse` skipped structurally; its payload is never decoded
- [x] Unknown frame types refused — no generic skip-unknown logic
- [x] `Terminate` sent after `ReadyForQuery` only; a failure to write it does not unmake the
      session
- [x] Terminal ownership: no live connection returned, closed on every outcome, no redial
- [x] **No SQL**, enforced by an AST guard over the session sources
- [x] 14 mutation guards, each verified to compile and flip a test
- [x] `make integration-postgres`: 12 scenarios against real PostgreSQL 18.6, including
      `3D000` and `42501` after `AuthenticationOk`

**A latent `bindDeadline` race was fixed** in `internal/adapter/postgres/wire` (ADR 0039
amendment C). Phase 4.5b is the first path that writes to a connection after a bounded read,
which is why it surfaced now. `internal/adapter/kafka/wire` holds the same copy and was
deliberately **not** changed — no Kafka path triggers it, and the fix belongs to the phase
that owns that package.

**No report schema change, no `AttrKind`, no redaction change, no new dependency, no new
`security.Reveal` site.**

### Phase 4.6a — Diagnosis policy ADR: COMPLETE

The 0034 analogue, written against the producers and the Phase 4.4a/4.5a wire measurements.
**ADR 0040**, with `docs/validation/POSTGRES_PHASE46_DIAGNOSIS_STUDY.md` as its evidence.
No production Go code was written or changed.

- [x] Every field of every authorized finding fixed, as ADR 0034 §5 does — **twelve codes**,
      each with trigger, claim, must-not-claim list, severity, evidence set and
      recommendation boundary
- [x] Vantage dependence decided claim by claim, not copied — **six of twelve are
      vantage-dependent**, on two distinct grounds (ADR 0040 §6.1): proved, where `pg_hba`
      matches the source address to select both the refusal *and the demanded authentication
      method*; and unassertable, where a floor deliberately does not attribute a cause and so
      cannot exclude a source-keyed one. `false` is a positive claim of position-independence
- [x] Credential dependence carried in the discriminator, and the decision not to add a
      field re-examined — **no finding in ADR 0040 is a `HYPOTHESIS`**, so no discriminator
      arises: every claim is about an observed boundary, which is §1 working as intended.
      No new field
- [x] `POSTGRES_CREDENTIALS_REJECTED` proven not to claim a cause it cannot establish — it
      requires `sqlstate=28P01`, so it fires only where the peer itself asserted the refusal
- [x] Minimal causal evidence sets fixed per finding
- [x] `internal/service/postgres` specified: **eight** constants, each because a rule reads it,
      each moved rather than copied (ADR 0040 §22). Created in 4.6b

**The falsifying result of this pass.** `AUTH_CREDENTIALS_REJECTED` on the authentication node
has three producers and one of them points the other way: `ErrServerSignatureMismatch` is
**svcdoctor refusing the peer's server signature**, not the peer refusing svcdoctor's material.
The graph cannot separate it from `ErrSCRAMRejected`, because neither decodes an
`ErrorResponse` and so neither records a SQLSTATE. ADR 0040 §11 answers with a claim true in
both directions and records the producer-side repair as a reopen condition rather than
guessing.

**The `08P01` policy, stated once:** a pooler emits it for at least six unrelated conditions
at two different protocol steps. It is never a credential finding, never a database finding,
and never classified by protocol position. It lands on a step floor —
`POSTGRES_STARTUP_FAILED` or `POSTGRES_AUTHENTICATION_FAILED` — which names where the
connection died and points at the endpoint's own log, the one place the distinction survives.

**Corrected by an adversarial pre-implementation review, before any rule existed.** Nine
defects, all fixed in ADR 0040; the code *count* is unchanged at twelve and the code *set* is
not. The substantive corrections: the two mechanism findings were split on *whose gap it is*,
which moves with svcdoctor's own capability rather than with the target, and are now one code
with a varying severity; `POSTGRES_STARTUP_REJECTED` became `POSTGRES_STARTUP_FAILED` because
its trigger includes peer closes and malformed frames; the floors' "no attributable cause"
sentence became class-gated because it is false where a class already names a stronger fact;
six `vantageDependent` values flipped to `true`; and "one node, one finding" was rescoped from
a permanent invariant to the Phase 4.6 primary set.

### Phase 4.6a.5 — SCRAM producer evidence correction: COMPLETE

The only production Go change ADR 0040 has caused, and the reason no Phase 4.6 finding code
ships provisional.

- [x] `AUTH_PEER_VERIFICATION_FAILED` added to `internal/domain` — the 39th class, generic,
      naming no mechanism and no protocol. Count guard updated 39 → 40 entries deliberately
- [x] `ErrServerSignatureMismatch` → `AUTH_PEER_VERIFICATION_FAILED`; `ErrSCRAMRejected`
      stays `AUTH_CREDENTIALS_REJECTED`. The two directions no longer share a class
- [x] `e=invalid-username-encoding` → `ErrUnexpectedResponse`: an encoding fault, not a
      rejection. Unreachable in practice — svcdoctor sends an empty username
- [x] Every production producer of `AUTH_CREDENTIALS_REJECTED` audited, PostgreSQL and Kafka
      alike; all are direction A, so the class is trustworthy on its own
- [x] Producer direction contract test, asserting both directions positively and negatively
- [x] Attribute-set test: no signature, proof, nonce, salt or auth message can reach evidence
- [x] Six mutations applied for real, each compiled and confirmed caught, then restored
- [x] ADR 0038 amendment D records the unsound normalization without rewriting history

**Why it was worth the 39th class.** The old mapping was not merely imprecise. A SCRAM server
sends a server-final only after accepting the client proof, so `ErrServerSignatureMismatch` is
reachable only where the peer **accepted** svcdoctor's material and then failed to prove
itself — and `AUTH_CREDENTIALS_REJECTED` says the peer refused it. The class asserted the
opposite of what happened, and no diagnosis-layer predicate can repair a class that lies.

**No** `security.Reveal` change (still 2), no new attribute, no `AttrKind`, no redaction
change, no report-schema change, no dependency change, no Kafka production change.

### Phase 4.6b — Diagnosis rules: COMPLETE

Implements ADR 0040 exactly, inventing nothing. `internal/service/postgres` (eight constants,
moved with aliases left behind) and `internal/diagnosis/postgres` (four rules, twelve codes).

- [x] `internal/service/postgres`: eight constants moved from the adapter, no behaviour change
- [x] `internal/diagnosis/postgres`: four rules, one per anchor step, the twelve codes of
      ADR 0040 §6 — no thirteenth, asserted by a count guard
- [x] At most one **primary Phase 4.6 diagnosis** per node — mutual exclusivity structural,
      not asserted (ADR 0040 §3). Scoped to the primary set: the guards must **not** be
      written as "no node ever carries two findings"
- [x] Totality: every `postgres.*` FAIL node in a producible graph yields exactly one primary
      finding (ADR 0040 §4), subject to the §16 parent precondition
- [x] The acceptance matrix (ADR 0040 §24), every `—` row asserted as a decision, and every
      row additionally asserting `vantageDependent`, `kind`, `confidence` and the absence of a
      discriminator
- [x] Mutation guards, each applied for real, compiled, confirmed caught and restored
- [x] Guards G1–G9 (ADR 0040 §23). G6 lives in `test/security/` — depguard denies diagnosis
      the redaction import, and the boundary is not weakened for a test (ADR 0040 amendment B)
- [x] `POSTGRES_CREDENTIALS_REJECTED` keys on the **class alone** — no SQLSTATE clause
- [x] Floor detail is class-gated: the attribution sentence renders only for
      `PROTOCOL_UNEXPECTED_RESPONSE` (ADR 0040 §8.1)
- [x] `POSTGRES_PEER_VERIFICATION_FAILED` (ADR 0040 §11) — stable, and worded so it never
      reads as a rejected credential or as a named cause
- [x] Determinism: the same graph encoded twice, byte-identical — **and** each rule ordered
      in its own right, which is the only test that can see a map-ordered rule (amendment A)

**Not owned, and recorded rather than deferred silently:** generic DNS/TCP/TLS findings
(ADR 0017's open blocker), TLS verification quality, replica and read-only facts, capacity
claims, and peer-implementation identification. A PostgreSQL run that fails at DNS, TCP or TLS
produces zero findings, and ADR 0040 §2 says so in as many words — pinned by a test at both
the rule and the report level, so the day it changes somebody changes those tests on purpose.
See the release gate below.

**No** `security.Reveal` change (still 2), no new `FailureClass`, no `AttrKind`, no redaction
change, no report-schema change, no dependency change, no Kafka production change, no SQL, no
CLI or renderer code.

**The one limitation, stated rather than buried.** These rules run against hand-built graphs,
because **no composition root exists**: `internal/app` and `cmd/svcdoctor` are empty, so
nothing assembles a PostgreSQL graph end to end. That is deliberate — inventing an
orchestrator under cover of a diagnosis phase is exactly the scope creep this backlog exists
to prevent — and closing it is **Phase 4.8**, which drives production paths end to end and
compares a real graph against the ADR 0040 acceptance matrix. Any row a real graph does not
describe reopens ADR 0040.


### Product/CLI release gate — generic transport diagnosis ownership: OPEN (DNS/TCP decided)

**Not Phase 4.6b scope, and not a PostgreSQL question.** Recorded here because it is the one
place the PostgreSQL slice is architecturally correct and incomplete as a product.

> **Before the first usable CLI/product release, the repository must decide the owner of
> generic transport diagnosis for user-requested endpoints.**

Today a run whose endpoint fails at DNS, TCP or TLS produces complete evidence, a correct
`summary.firstBrokenLayer`, and **zero actionable findings** — for Kafka and PostgreSQL alike.
Those are the *common* failure modes: a name that does not resolve, a refused port, an
untrusted certificate. A first-time user meets a report that reads as broken.

It was a gate rather than a task because the blocker was a fact, not effort: a rule needed run
intent — *is this a service diagnosis or a bare endpoint check?* — which `diagnosis.Rule`
cannot see, receiving only a `Graph`. See **ADR 0017**, and ADR 0040 §26.1.

**Phase 4.9a attempted the decision and stopped on that fact**, finding a second one beside it:
the requested logical `host:port` is the subject of no node, so even granting ownership a
generic finding had nothing truthful to be *about*. **Phase 4.9a-pre answered both**
(**ADR 0042**) with an L0 requested-target anchor and direct-parent sweep ownership, without
`Origin`, without identifier parsing and without touching `diagnosis.Rule`.

**Phase 4.9a decided DNS and TCP and Phase 4.9b implemented them** (**ADR 0043**): three codes,
one aggregation unit, withheld on partial success and on incomplete measurement. **Two of the
gate's three named failures are closed** — a name that does not resolve and a refused port both
now produce an ERROR finding and `PROBLEMS_FOUND` where they produced silence and `OK`.

**The gate stays open on the third.** An untrusted certificate is still diagnosed by nobody,
and for two separate reasons:

- **Generic TLS has no producer.** No production run yields a `tls.handshake` node whose direct
  parent is a requested `tcp.connect`: PostgreSQL negotiates in band, and Kafka has no
  composition root. Policy for evidence that cannot occur would be wrong by the time it could.
- **PostgreSQL's in-band TLS is closed.** ADR 0044, implemented in Phase 4.9d. What was
  `findings: 0`, `status: OK`, `firstBrokenLayer: L3` now produces a per-endpoint PostgreSQL
  finding and `PROBLEMS_FOUND`.
- **What keeps the gate open is generic requested-target TLS**, which still has no production
  producer: PostgreSQL negotiates in band, and Kafka has no composition root. A producer
  arrives with Kafka bootstrap composition, and the policy needs its own record then.

- [x] Decide whether run intent can reach a rule at all, and how — ADR 0042
- [x] Implement the anchor, including the generic vocabulary leaf ADR 0042 §11 requires
- [x] Decide generic DNS and TCP findings, their codes and their semantics — ADR 0043
- [x] Decide the partial-success and incomplete-measurement rules — withhold on both,
      ADR 0043 §6
- [x] **Implement the three ADR 0043 rules** in `internal/diagnosis/transport/`, and narrow
      the module-wide code ban to an allow-list of exactly those three — still rejecting every
      `TLS_` code, so §14's deferral keeps a mechanical guard
- [x] **PostgreSQL in-band TLS diagnosis** — ADR 0044, implemented in Phase 4.9d
- [ ] **Generic TLS policy** — blocked on a producer; ADR 0043 §14
- [ ] Until then, keep each gap stated in the report rather than papered over by a service rule

### Phase 4.8a — Real end-to-end validation from a test composition boundary: COMPLETE

The vertical slice driven from a real socket to a redacted report, against real servers.
The first phase in which diagnosis meets a graph it did not receive hand-built.
`docs/validation/POSTGRES_PHASE48A_ENDTOEND_STUDY.md` records what ran.

- [x] `test/integration/postgres` composes the production stages: `transport.Run` →
      `Negotiate` → `Startup` → `Authenticate` → `EstablishSession` → diagnosis →
      `NewReport` → `Redact`. **Test orchestration only**
- [x] No hand-authored evidence on the end-to-end paths, enforced by an AST guard
- [x] `requireSingleContinuation` — a fixture precondition that fails on 0 or >1, never a
      selection. Guarded so no other call site indexes a path
- [x] 11 scenarios measured against real servers: healthy, wrong password, unknown role,
      `3D000`, `42501`, TLS declined, `pg_hba` reject, md5, cleartext, trust, plaintext policy
- [x] Redaction from a real run: role, database and address canaries removed; semantics and
      prose byte-identical; idempotent
- [x] 11 mutations applied, compiled, caught and restored
- [x] Guards: no production composition root, no production path selection, no address-family
      preference, no service registry, no SQL, diagnosis still pure

**Two findings worth carrying forward.** `localhost` resolves to two addresses, so the
suite's previous `Continuations()[0]` had been silently selecting IPv4 — the exact invisible
preference ADR 0024 §3 removed from the chain, sitting in the validation suite. It surfaced
on the first run against the new precondition. And the `bindDeadline` regression is **not**
covered: reverting the Phase 4.5b fix passes 40 end-to-end runs, because the race needs the
caller's context to end at a specific moment and a local server never gets there. No coverage
is claimed; Phase 4.5b's evidence remains authoritative.

**Not measured here, and not claimed:** pgBouncer (no pgBouncer in this environment — the
Phase 4.4a/4.5a studies remain the authority), and the `53300` session floor.

**Production composition remains deliberately absent.** `internal/app`, `cmd/svcdoctor` and
`internal/render` are empty and a test asserts it.

### Decision — ADR 0041: the application run boundary and path selection: COMPLETE

**ADR 0041 — "A run discovers broadly and authenticates narrowly."** Accepted as policy;
no production code. It closes the deferral ADR 0028 §1 left open and partially supersedes
ADR 0011's command tree.

- [x] Which continuation may be authenticated — every path is measured through
      **credential-free discovery** first, then exactly one *eligible* path is selected by a
      deterministic canonical-order tie-break among those already measured
- [x] Whether more than one may ever be authenticated — **no.** At most one
      credential-bearing attempt per logical endpoint per run, counted by authentication
      execution rather than by connection
- [x] Whole-run budget and cancellation — the root context deadline, no second framework;
      the run deadline always wins, and unattempted work is never a target failure
- [x] Run and output modes — the run produces `LOCAL_FULL`; redaction is a derivative at the
      output boundary
- [x] Service registration — principle pinned (explicit, no generic `Adapter` interface),
      mechanics left to implementation

**The decisive fact.** PostgreSQL's startup exchange presents no secret, and `pg_hba`
selects behaviour by source address — so a family-dependent `reject`, a different mechanism,
or a different backend is observable **without spending a credential attempt on each path**.
That is why the two symmetric alternatives were both rejected: refusing to authenticate when
several paths exist withholds the tool's main function on every dual-stack endpoint, and
authenticating every path multiplies the one thing that is logged, counted and
lockout-relevant.

**Deferred by ADR 0041, each with a reopen condition:** `inspect`'s output contract,
`--address` and any `--prefer-*` flag, retry/fallback, service-registration mechanics, and
concurrent path discovery.

### Phase 4.8b — Production composition root: COMPLETE

`internal/app` implements ADR 0041 and nothing else: `DiagnosePostgres`, a pure `selectPath`,
and a `Result` carrying the report plus whether the run got to finish.

- [x] The run — root context, one `GraphBuilder`, transport discovery, credential-free
      discovery on every permitted path, one selection, one credential attempt, closure of
      unselected continuations, freeze, diagnosis, `LOCAL_FULL` report
- [x] Structural guards: import allowlist, no socket, no SQL, no `EvidenceID` parsing, no
      evidence construction, no registry or generic adapter, no exit code, no redaction
- [x] **Real dual-stack, measured**: `localhost` → 2 transport paths, **2 startup
      observations, 1 authentication**, selected path = canonical minimum, read from the
      authentication node's own `Subject`
- [x] **Connection lifecycle proven** through the production `tcp.Dialer` seam:
      `opened=2 closed=2` — the unselected path is closed deliberately
- [x] Real failure runs through the production run: wrong password, unknown role, `3D000`,
      `42501`, `pg_hba` reject, md5, TLS declined, trust
- [x] 21 mutations applied, compiled, caught and restored
- [x] No generic `Adapter` interface; no CLI; no renderer; no registry

**One guard changed on purpose.** Phase 4.8a asserted `internal/app` was empty. ADR 0041
authorized filling it, so that guard now covers only what is still absent — the CLI and the
renderers — plus a new one keeping the composition root PostgreSQL-only.

**Corrected by an adversarial review before commit.** The first implementation selected purely
by canonical order over every startup-successful path, so a `trust` path that sorted first was
continued and a configured credential was **never exercised** — a run that reported `OK`
without answering the question it was asked. ADR 0041 gained §8.1: candidates are partitioned
by whether the endpoint demanded authentication, and the run prefers the class it can carry
furthest. Credential attempts remain ≤ 1; nothing else moved. The same review found
`Incomplete()` blind to a cancellation that landed inside a protocol stage, now reconciled from
the run context in one place.

**Three limitations recorded rather than worked around.** A run carrying no credential against
a server that demands one presents nothing and records no authentication node; there is no
finding saying "no credential was configured", because that is diagnosis work and no rule
exists. The class partition distinguishes *demanded* from *not demanded*, not *performable*
from *not performable*, so an `md5`/SCRAM split by family could select the `md5` path
(ADR 0041 §8.1). And an end-to-end run over a genuinely mixed-method endpoint is not
reproducible here: Docker translates both loopback families to one container-side address, so
`pg_hba` cannot distinguish them — measured, and pinned by a test that fails if the
environment ever gains the capability.

### Phase 4.9a — Generic transport diagnosis ownership: STOPPED

Set out to decide who owns DNS/TCP/TLS diagnosis for the endpoint an operator names. Stopped
without a policy, correctly, on two structural facts verified from the tree at `e20c904`:

- **Ownership.** No structure proved which transport sweep the operator caused. Rootness is
  forbidden provenance inference and is not type-enforced — `transport.Params.Parent` was
  optional — and `SweepScope` reaches the identifier and nothing else, so reading it means
  parsing an `EvidenceID`.
- **Subject.** The requested logical `host:port` is the subject of no node. `dns.lookup` carries
  the hostname alone; `tcp.connect` and `tls.handshake` carry the resolved `ip:port`. On the
  flagship NXDOMAIN case there is no TCP child to recover a port from at all.

Model D — generic for user-supplied targets, service for discovered ones — is the right
destination and was the one ADR 0034 §3 had already rejected by name as unimplementable. It
became implementable only after Phase 4.9a-pre. **No ADR was written and no file changed**; a
record saying "still blocked" would have been a record of a non-decision.

### Phase 4.9a-pre — Requested-target anchor: COMPLETE

**ADR 0042.** One L0 evidence node, minted by the composition root, whose subject is the
operator's logical endpoint and whose child is the sweep it caused. It closes both gaps above
with one node.

Its load-bearing finding is adversarial rather than architectural: the Kafka advertised sweep is
a **transitive descendant** of the bootstrap target, through
`tls.handshake → api_versions → authentication → metadata → broker_advertised`. So
"generic diagnosis owns everything below the anchor" would have walked straight into
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`'s evidence and reintroduced the duplication ADR 0034
resolved. Ownership is therefore **direct** parentage at the sweep root plus a step-typed walk
of bounded depth — which also leaves PostgreSQL's in-band `tls.handshake` with its adapter,
because that node parents to `postgres.ssl_request` rather than to `tcp.connect`.

Layer-bounding was tried and fails: `postgres.ssl_request` is L3.

- [x] The anchor node, minted by `recordRequestedTarget` in `internal/app/target.go`
- [x] `logicalTarget` — one typed value projecting to both the anchor subject and
      `Report.Target`, so IPv6 bracketing is decided once and cannot drift
- [x] The narrowed evidence-authority guard — `NewFinding`, `AddBlockedBy`, `AddParent` and
      every attribute constructor stay banned package-wide; `NewEvidence`/`AddEvidence`
      permitted in one named function, and the call count is asserted to be exactly one
- [x] `internal/vocabulary` (ADR 0042 §11) — the anchor step plus the three transport steps,
      with the probes aliasing rather than redeclaring, and a module-wide scan proving each
      string appears in exactly one production file
- [x] `transport.Params.Parent` carries the sweep's declared cause; `internal/app` adds no edge
- [x] The Kafka hazard measured, not argued — against a real advertised sweep, the naive
      descendant walk is shown to capture it and the authorized walk is shown not to
- [x] PostgreSQL in-band TLS proven outside the boundary, on a faked network and on a real
      TLS upgrade in the integration gate
- [x] A non-vacuous redaction canary: both projections pseudonymize identically, the raw
      hostname is proven present locally and absent from the shareable document
- [x] 21 mutations applied for real, each caught by a named guard and each restored

**One thing the record did not anticipate:** `internal/app` now imports `internal/probe` for
the identifier encoding ADR 0019 owns. The encoding only — no probe, no dial, no resolver.

**No schema change, no `Origin`, no `Rule` signature change, no new dependency.**
`security.Reveal` stays 2, `FailureClass` 39, `FindingCode` 14, `schemaVersion` 1.

### Phase 4.9a/4.9b — Generic requested-target DNS/TCP diagnosis: COMPLETE

**ADR 0043.** Three codes — `DNS_NAME_NOT_RESOLVED`, `DNS_RESOLUTION_FAILED`,
`TCP_CONNECTION_NOT_ESTABLISHED` — all `CONFIRMED` / `ERROR` / `HIGH` / `vantageDependent`,
all subjected to the ADR 0042 anchor rather than to a resolved address.

Three decisions worth remembering when the rules are written:

- **One TCP code, not two.** Refused and timed-out suggest different remediation, but the split
  is not stable across one endpoint: an IPv4 address with nothing listening and a filtered IPv6
  address produce both in one run, and any tiebreak makes the public contract depend on address
  family. The distribution stays in `FailureClass` on the cited evidence.
- **Names avoid two traps.** `TCP_ENDPOINT_UNREACHABLE` was rejected because a refused
  connection proves a host answered; `TCP_CONNECTION_FAILED` was rejected because it collides
  exactly with a `FailureClass` name, which would make a claim indistinguishable from an
  observation. `TARGET_*` was rejected because `docs/FINDINGS.md` §1 already fixes the
  convention — generic transport findings use the layer as the namespace.
- **`DNS_NXDOMAIN` has no producer** and no policy was written for it. The probe deliberately
  emits the weaker `DNS_NO_ADDRESS`, and the finding inherits that restraint: it never claims a
  name does not exist.

**Phase 4.9b implemented it.** `internal/diagnosis/transport` holds two rules and three codes,
wired into `internal/app.DiagnosePostgres` beside the four PostgreSQL rules. `FindingCode` 14 →
17; nothing else moved.

- [x] Two rules, `DNS` and `TCP`, importing `internal/domain` and `internal/vocabulary` only
- [x] The full ADR 0043 acceptance matrix, plus the shapes a rule must refuse to recognize —
      an anchor child that is not a lookup, two lookups under one anchor, an anchor-shaped node
      with the wrong layer or subject kind
- [x] A prose guard rejecting eleven cause-claiming phrases, with a control proving it can see
      them. It caught the record's own draft detail text, which named a firewall in order to
      deny it
- [x] Permutation tests over evidence-reference order, and a two-anchor ordering test that
      pins multi-target support as a composition change rather than a rule rewrite
- [x] Kafka forward compatibility: on a real graph, the bootstrap sweep would be owned and the
      advertised sweep would not, asserted without importing the rules
- [x] Redaction: the finding subject, the report target and the anchor subject pseudonymize to
      one value; the prose carries no identity
- [x] 18 of 19 mutations caught by named guards; the nineteenth is structurally impossible —
      `domain.NewFinding` sorts and deduplicates references, so map-order cannot reach output

**Two guards were narrowed rather than deleted.** `internal/vocabulary`'s blanket ban on
generic finding codes became an allow-list of exactly three, still rejecting every `TLS_` code;
`internal/diagnosis/transport`'s "this package is empty" guard became the architecture suite
that replaced it.

### Phase 4.9c/4.9d — PostgreSQL in-band TLS diagnosis: COMPLETE

**ADR 0044.** Five codes — `POSTGRES_TLS_UPGRADE_NOT_HONORED`,
`POSTGRES_TLS_IDENTITY_MISMATCH`, `POSTGRES_TLS_CHAIN_NOT_TRUSTED`,
`POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW`, `POSTGRES_TLS_HANDSHAKE_FAILED` — all
`CONFIRMED` / `ERROR` / `HIGH` / `vantageDependent: true`, subject the concrete `ip:port`,
evidence the negotiation node plus the handshake node.

Four things worth remembering when the rule is written:

- **It overturns an Accepted decision, deliberately.** ADR 0040 declined `POSTGRES_TLS_*`
  findings because one "would add nothing the node does not already state". That argument
  proves too much — it deletes `POSTGRES_TLS_DECLINED` and all three ADR 0043 codes — and the
  ground shifted when ADR 0043 gave L1 and L2 owners. The reversal is argued in ADR 0044 §2 and
  noted in ADR 0040.
- **It does not copy ADR 0043's partial-success withholding.** A PostgreSQL finding claims
  something about *this endpoint*; another endpoint working does not make it false. One failing
  handshake, one finding, even on a dual-stack target where the other family works.
- **The predicate requires the negotiation to have PASSED**, which is what separates this from
  `POSTGRES_TLS_DECLINED` and structurally excludes the SKIPPED handshake node the adapter mints
  when the negotiation failed.
- **Expired and not-yet-valid share one code.** They pose one question, and
  `tls.peer_not_before` / `tls.peer_not_after` answer which end.

**Phase 4.9d implemented it** as `internal/diagnosis/postgres.TLS`, the fifth rule in that
package. `FindingCode` 17 → 22; nothing else moved.

- [x] The rule, the closed class mapping, and the five-condition ownership predicate
- [x] The full ADR 0044 acceptance matrix, including the shapes that must withhold — no
      parent, two parents, a transport parent, a subject mismatch, a wrong layer, and a
      handshake under a failed negotiation
- [x] Guards: no identifier parsing, no `Origin`, no ancestor search, no `Children`, no
      coupling to startup/authentication/session, no certificate material or library error
      text, a closed mapping, a declaration scan over the package's codes, and a guard that no
      code mirrors a `FailureClass` name
- [x] Real integration for two of the five codes, by varying **client** configuration against
      the same real certificate: `POSTGRES_TLS_IDENTITY_MISMATCH` and
      `POSTGRES_TLS_CHAIN_NOT_TRUSTED`, both subjected to `127.0.0.1:55432`, both
      `PROBLEMS_FOUND`, `firstBrokenLayer` still L3
- [x] Redaction: the finding subject and its cited evidence pseudonymize to one value, two
      endpoints stay two endpoints, and every semantic field survives
- [x] 19 of 20 mutations caught; the twentieth is structurally impossible, because the
      predicate already requires the handshake's subject to equal the negotiation's, so
      substituting one for the other cannot change the output

**Three codes are honestly unit-only.** The environment cannot reissue the fixture's
certificate to make it expired or not-yet-valid, and no correct server agrees to encrypt and
then does not speak TLS. The acceptance matrix says which rows are which rather than implying
uniform coverage.

**One pre-existing sharp edge was found and pinned rather than fixed.** A PostgreSQL role
literally named `svcdoctor` collides with the word in finding prose, so the residual scan finds
its plaintext and refuses to emit a shareable report. That is fail-closed and correct
(ADR 0018); it predates this phase, and `TestAToolWordAsARoleNameFailsClosed` records it as
intended behaviour.

Generic TLS is **not** implemented — it still has no producer and needs its own record.

### PostgreSQL BASIC closure checklist — re-enumerated after Phase 4.9d

Everything recorded anywhere in the repository as a PostgreSQL BASIC gap, so that closure is a
check rather than a memory:

- [x] **ADR 0044 implementation** (Phase 4.9d) — the five in-band TLS codes
- [x] **No credential configured** — **ADR 0046, implemented in Phase 4.11b.** The blocker was
      never the claim but the predicate: a graph cancelled between Startup and the credentialed
      step was byte-identical to one where no credential existed. The fact moved to the producer
      — `postgres.authentication` SKIPPED with the new generic class
      `EXEC_REQUIRED_INPUT_MISSING` — so the two graphs now differ mechanically, and diagnosis
      infers nothing from absence
- [x] **`postgres.ssl_request` failures other than a decline** — **ADR 0045, implemented in
      Phase 4.11b.** One floor, `POSTGRES_SSL_NEGOTIATION_FAILED`, over
      `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_PEER_CLOSED` and `PROTOCOL_MALFORMED_RESPONSE`.
      The `E` answer still has no claim of its own and keeps its reopen condition
- [ ] **Confirm no `SummaryStatusOK`-with-failed-evidence case remains** for PostgreSQL, by
      enumerating every FAIL-producing step and checking each has an owner. L1, L2, L3-in-band,
      L4 and L5 all have owners as of Phase 4.9d; what remains unchecked is whether any *other*
      FAIL-producing step exists that nobody has enumerated
- [ ] **Integration coverage review** — which acceptance rows are unit-only by nature and which
      are unit-only because the environment cannot serve them (ADR 0044 marks the certificate
      validity rows and `UPGRADE_NOT_HONORED` as the latter)
- [ ] **Decide whether the `svcdoctor`-as-a-role-name redaction refusal needs anything.** It is
      correct and fail-closed today. The question for closure is only whether a user meeting it
      gets an error they can act on, which is a CLI/renderer concern rather than a diagnosis one

Deliberately **not** on this list, because they are not BASIC: replica/read-only/superuser and
version facts (ADR 0040 §20), capacity and availability (ADR 0039 §10), peer implementation
identification (ADR 0040 §18), and certificate expiry on a *passing* handshake, which is expiry
monitoring rather than diagnosis (ADR 0044).

### Phase 4.11a/4.11b — the final PostgreSQL BASIC terminal gaps: COMPLETE

**ADR 0045** and **ADR 0046**, decided and implemented. `FindingCode` 22 → **24**;
`FailureClass` 39 → **40**, the first addition since Phase 4.6a.5.

- [x] `POSTGRES_SSL_NEGOTIATION_FAILED` — the L3 floor. A wrong port stops reading as healthy
- [x] `EXEC_REQUIRED_INPUT_MISSING` — one generic class, service-neutral, distinct from the
      policy skip, the capability gap and the privilege gap
- [x] `POSTGRES_CREDENTIAL_NOT_CONFIGURED` — WARN, on an explicit node, never on absence
- [x] The producer records it, not the run and not diagnosis: `internal/app` keeps its single
      evidence authority (ADR 0042 §3)
- [x] Ordering: the capability gap outranks the missing input, and the missing input precedes
      the channel policy, the endpoint binding, `SecretFor` and `security.Reveal` — guarded by
      reading the source order, not only the paths a behaviour test exercises
- [x] Orchestration's budget check before the credentialed step is now load-bearing and is
      guarded structurally, because a cancellation timed into that window is not reproducible
- [x] Real integration for both: a SCRAM server with no credential, and a trust endpoint with
      none, which must stay silent
- [x] 23 mutations applied, all caught, all restored

**Two things worth remembering.** The missing-credential finding is the only PostgreSQL finding
produced by a graph in which *nothing failed*, which is why `SummaryStatus` stays `OK` and why
the exit-code question belongs to the renderer rather than to severity. And `Authenticate` lost
an invocation error: a zero credential used to be the caller's defect, which is precisely what
kept a real diagnostic outcome out of the report.

### Phase 4.11d — local execution budget correctness: COMPLETE

**ADR 0047**, decided and implemented. No `FindingCode`, no `FailureClass`, no schema field and
no dependency changed: `FindingCode` stays **24**, `FailureClass` **40**, `schemaVersion` **1**,
`security.Reveal` **two**.

Phase 4.11c's closure gate reproduced three defects, all in one seam — a per-step budget
expiring while the caller's context stays alive:

- [x] `postgres.startup` ran **unbounded**. `StartupParams` had no timeout field, so
      `PostgresParams.StepTimeout` was dropped at a call site that looked complete, and a peer
      that accepted TCP and never answered the StartupMessage held the run open indefinitely.
      It now takes `ExchangeTimeout`, like every sibling step
- [x] A local deadline at `postgres.ssl_request` was published as
      `FAIL` + `PROTOCOL_UNEXPECTED_RESPONSE` with an ERROR finding. The classifier lacked the
      `isTimeout(err)` guard `authenticate.go` and `establish.go` already had, in the same
      position. Both it and `classifyStartup` now have it; the other two were already correct
- [x] `Result.Incomplete()`, derived from `ctx.Err()` alone, called a run that never reached L3
      finished — leaving `docs/SCOPE.md`'s exit-4 contract ("cancellation **or local execution
      budget exhaustion**") false and ADR 0043 §6's premise broken
- [x] The decision, and the only genuinely new one: **a run is incomplete when svcdoctor's own
      execution limit prevented it from reaching the outcome it set out to measure.** Not "any
      local `UNKNOWN` anywhere" — ADR 0041 measures every address and continues one, so that
      rule would report an ordinary dual-stack run as truncated while it holds a passing session
- [x] Computed in `internal/app.incompleteRun` from `State`/`FailureClass` through domain
      accessors plus one typed control-flow value. No finding, severity, `SummaryStatus`, path
      count, `EvidenceID` parse, step name or `Origin`
- [x] Status and incompleteness stay orthogonal, and severity was not used as an exit-code lever
- [x] An interrupted step keeps its measured duration, which means how long svcdoctor waited —
      never that the endpoint was slow. No threshold and no latency finding
- [x] Real loopback-socket regression tests, because none of the three reproduced through
      `net.Pipe` or a stub dialer; 13 mutations applied, 12 caught, all restored

**Next: re-run the Phase 4.11c closure gate.** PostgreSQL BASIC was not marked complete by that
phase, and no closure documentation was written there. It was re-run — see below.

### Phase 4.11c-R2 — final PostgreSQL BASIC closure gate: PASSED

**POSTGRESQL BASIC COMPLETE — FEATURE FREEZE AUTHORIZED.**

The gate was read-only and re-derived every conclusion from committed source rather than from
the previous phase reports. Recorded here because the gate itself wrote nothing.

- [x] Five critical gates green: total FAIL ownership; no-credential cannot be silent; the
      SSLRequest floor cannot be silent; execution/timing/redaction correct; generic TLS
      **proven** unnecessary
- [x] Zero unowned reachable FAIL outcomes. Every service floor is total over FAIL, and the
      SSLRequest pair is total over its four reachable classes
- [x] All three Phase 4.11d fixes reproduced independently against real loopback peers, not
      by reading the tests that shipped with them
- [x] Generic TLS proven from source, not deferred by assertion: `transport.Params.TLS` is nil
      on the PostgreSQL path, its only production setter is Kafka's advertised sweep, and the
      in-band handshake is parented to `postgres.ssl_request`. `tlsClaims` is total over the
      TLS probe's six reachable FAIL classes
- [x] `Σ(stage durations)` measured **not** equal to `run.Duration()` — 473µs of orchestration
      gap on a 122ms run. Multi-path timings stay per subject with no averaging
- [x] Determinism verified under address-order permutation
- [x] Invariants unchanged: `FindingCode` 24, `FailureClass` 40, `Reveal` 2, dependencies 1,
      `schemaVersion` 1

**Feature freeze.** Bug fixes, security fixes, correctness fixes, CLI/renderer consumption,
tests and documentation need no reopen. A new PostgreSQL probe stage, BASIC finding,
target-health inference, timeout semantics, protocol fallback, retry, BASIC SQL query,
performance interpretation or latency threshold does — recorded here with its condition.
Generic TLS stays deferred; PostgreSQL DEEP stays separate.

### Phase 5.0/5.0a — CLI and output decisions: COMPLETE

**ADR 0048** (CLI and output boundary) and **ADR 0049** (credential input), both Accepted and
neither implemented. No production Go code, no dependency, no schema change.

- [x] Action-first tree confirmed; `inspect` and `diagnose kafka` deliberately not exposed
- [x] `cmd` / `internal/cli` / `internal/app` / `internal/render` ownership fixed; the renderer
      receives a report plus one boolean, never `app.Result`
- [x] JSON is the canonical `domain.Report`; `Result.Incomplete()` stays out of the schema per
      `docs/REPORT_SCHEMA.md` §8, and machines learn it from exit code 4
- [x] stdout carries the artifact on 0, 1 and 4; stderr only on 2 and 3
- [x] Exit precedence unchanged from `docs/SCOPE.md`: `3 > 2 > 4 > 1 > 0`
- [x] WARN+OK and incomplete rendering made normative; `status OK` never prints bare
- [x] Standard library only — no CLI framework, no colour library, no colour in v0.1
- [x] `--password-file` / `--password-stdin`, mutually exclusive, no precedence, no literal flag

### Phase 5.1 — CLI spine and canonical JSON: COMPLETE

`svcdoctor diagnose postgres` runs end to end. **ADR 0048 implemented through this phase**;
ADR 0049 remains Accepted and unimplemented.

- [x] `cmd/svcdoctor` — bootstrap only: root `signal.NotifyContext`, `cli.New(...).Run`, `os.Exit`
- [x] `internal/cli` — dispatch, flags, validation, params, exit codes, stream routing
- [x] `internal/render/json` — a thin canonical `domain.Report` serializer, one trailing newline
- [x] `internal/platform/local` — the local vantage fact, from `os.Hostname`
- [x] Standard library only. Dependencies stay at **one**
- [x] Exit contract implemented as one pure function, precedence `3 > 2 > 4 > 1 > 0`, with
      **4 outranking 1** pinned against a real incomplete-plus-ERROR run
- [x] stdout carries the artifact on 0, 1 and 4; stderr only on 2 and 3; help and `--version`
      on stdout
- [x] No credential source, by design: a real SCRAM endpoint produces
      `POSTGRES_CREDENTIAL_NOT_CONFIGURED`, WARN, status OK, no session, **exit 0**
- [x] `TestNoCLIOrRendererExists` retired and replaced by positive guards — the product
      boundary exists, the CLI never reaches diagnosis or a wire package, the renderer imports
      only `internal/domain`, and no credential surface exists yet
- [x] `render-is-presentation-only` depguard rule added, now that `internal/render` has files
- [x] Real binary integration: healthy trust session, no-credential SCRAM, target-side ERROR,
      local-timeout exit 4, invalid invocations, help/version, and SIGINT still producing a
      partial report at exit 4
- [x] 25 mutations applied; 22 caught, 3 not applicable. Two escapes were real test defects and
      were fixed rather than explained away

**Two mutation escapes worth remembering.** Routing `postgres` straight to the PostgreSQL
command still exited 2 — for a missing `--user`, not for the rejected route — so the dispatch
table now carries complete flags and asserts the application was never reached. And deriving
the exit code from `FindingCount()` escaped every unit test, because no unit fixture carried a
finding on an `OK` report; a scripted SCRAM-demanding peer now makes the WARN+OK shape
reachable without Docker, which is the invariant the whole phase exists to protect.

### Phase 5 — remaining CLI work: DECIDED, NOT IMPLEMENTED

- **5.2** credential input (ADR 0049) and `--shareable`
- **5.3** terminal renderer: stage tree, findings, session status, incompleteness, durations,
  multi-path, golden tests
- **5.4** release validation: real PostgreSQL through the actual binary — exit codes,
  stdout/stderr discipline, JSON automation, text output, redaction, signals, security

The action-first tree ADR 0041 fixed: `svcdoctor diagnose <service>`, with `inspect`
reserved and its output contract deferred.

Driving production paths end to end — real resolver, real dialer, real TLS, real protocol,
real graph, real diagnosis, real report, real redaction. No hand-authored evidence and no
hand-authored findings.

Scenarios, with the oracle each is compared against:

| Scenario | Oracle | What the oracle proves |
|---|---|---|
| healthy TLS + SCRAM → `ReadyForQuery` | `psql` | a session was established, which is the same claim |
| healthy plaintext + `trust` | `psql` | same |
| hostname does not resolve | resolver, `dig` | name resolution only |
| connection refused | `pg_isready` | a listener answered or did not — **not** that a session is possible |
| server without TLS, TLS required | `openssl s_client` | that the port does not start TLS directly; it does **not** speak `SSLRequest`, so it cannot test PostgreSQL's negotiation |
| untrusted CA, hostname mismatch, expired certificate | `openssl s_client` + `psql sslmode=verify-full` | certificate facts, and libpq's verdict on them |
| wrong password | `psql` | refusal, and nothing about which cause |
| unknown role | `psql` + server log | the log is the only place the two are distinguished, which is the point |
| `pg_hba` no entry, and explicit `reject` | `psql` + server log | `28000` and which rule matched |
| SCRAM and MD5 roles | `psql` | which method was demanded |
| unknown database, `CONNECT` revoked | `psql` | `3D000` and `42501` after `AuthenticationOk` |
| server terminates before `ReadyForQuery` | injected fault | `PROTOCOL_PEER_CLOSED`, not a remote failure claim |
| replica endpoint | `psql -c 'SELECT pg_is_in_recovery()'` | agrees with `in_hot_standby` obtained without a query |
| behind pgBouncer | `psql` | that svcdoctor degrades to a weaker true claim rather than a false precise one |
| redaction | the shareable report itself | no residual hostname, role, database, password canary, or source address |

`pg_isready` and `psql` prove different things and neither is universal. `pg_isready`
performs a startup and reads the response; it does not authenticate a session or reach a
database. `psql` is the strong oracle for session establishment. `openssl s_client` cannot
speak `SSLRequest` at all and is therefore an oracle for the certificate, never for
PostgreSQL's negotiation. The server log is the only oracle for a cause PostgreSQL
deliberately hides from the client.

- [ ] `make integration-postgres`, outside `make check` as the Kafka gate is
- [ ] `docs/validation/POSTGRES_PHASE4_VALIDATION.md` recording what it found
- [ ] Confirm that adding this service required no edit to a generic package beyond
      Phases 4.1 and 4.2, both of which are core changes PostgreSQL *forced* rather than
      service logic leaking into the core

### Deferred out of Phase 4, with the condition that reopens each

- [ ] **Plaintext credential authentication.** Blocked by the single-valued
      `CredentialTransportPolicy`. **Reopen when** a layer can carry an explicit, per-run,
      recorded transport decision (ADR 0029, Phase 5). This is the largest practical
      limitation of the first slice
- [ ] **The transport finding for a user-supplied target.** Still unowned; ADR 0034 §14 left
      it open and ADR 0036 §18 declines to close it. **Reopen when** orchestration knows
      what was requested
- [ ] **Multi-host DSN and per-address role discovery.** **Reopen when** L0 normalization
      exists
- [ ] **Two negotiation strategies in one run** (TLS and plaintext, both measured, no
      fallback). The primitive exists — `probe.SweepScope` — and nothing blocks it.
      **Reopen when** a real report needs both answers
- [ ] **Protocol 3.2.** Costs a negotiation round trip on older servers and buys nothing
      svcdoctor reads. **Reopen when** a 3.2 capability is worth having
- [ ] **Primary/replica, replication, slots, WAL, failover, Patroni, CloudNativePG.**
      `in_hot_standby` is already recorded as a fact. **Reopen when** an HA phase is scheduled
- [ ] **A `credentialDependent` field on `Finding`.** **Reopen when** a second service needs
      the distinction
- [ ] **Client certificate authentication.** Needs the trust-material loading ADR 0023 defers

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
