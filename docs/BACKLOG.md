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
  SASL mechanism discovery (Phase 3.2a), channel propagation (Phase 3.2b), PLAIN
  authentication (Phase 3.2c), the mechanism guard (6.1a) and SCRAM-SHA-256 (6.2)
- `internal/adapter/kafka/wire` — one of the two packages that may call `security.Reveal`, and
  the only one that imports the Kafka protocol library
- `internal/adapter/postgres` and `internal/adapter/postgres/wire` — the PostgreSQL vertical
  slice through `ReadyForQuery`, and the second and last `security.Reveal` call site
- `internal/sasl/scram` — the shared SCRAM-SHA-256 core, which never receives plaintext
  (ADR 0055, ADR 0056)
- `internal/diagnosis/transport`, `internal/diagnosis/postgres`, `internal/diagnosis/kafka` —
  the concrete rules, 40 finding codes between them
- `internal/render/terminal` and `internal/render/json` — the two v0.1 output forms, derived
  from one report
- `internal/app` — the PostgreSQL and Kafka composition roots
- `internal/platform/local`, `internal/service/*`, `internal/vocabulary` — vantage collection
  and the shared step vocabulary
- `internal/cli` and `cmd/svcdoctor` — `svcdoctor diagnose postgres` and
  `svcdoctor diagnose kafka`

**This section was stale until Phase 6.5's audit read it.** It claimed no Go code existed in
`internal/adapter/postgres`, `internal/render`, `internal/platform`, `internal/app` or
`cmd/svcdoctor`, and that "the tool still cannot diagnose anything" — all true when Phase 2
sealed and none of it true since Phase 4.5. `internal/platform/kubernetes` remains empty and
is Phase 5 work.

So both vertical slices are complete and exposed: PostgreSQL BASIC is feature-frozen and
released as v0.1.0, and Kafka BASIC closed in Phase 6.5.

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
| **SCRAM defensive resource bounds** | **Closed in Phase 7.0b.** ADR 0061 is Accepted and implemented: 8192/8192/1024/1368/1024/32, `MaxIterations` and `maxUsernameLen` unchanged. Redpanda v25.1.9's 130-byte salt (176 encoded) now passes against a real broker, and the committed fixture fails against the old bounds on that same broker. The bound refusal is no longer reported as a malformed peer response: it reaches `UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR` in both services, on a rule that already existed, so no finding code or failure class was added. Every bound is now pinned by value, which Phase 7.0 found nothing did | Closed. Reopens only on ADR 0061 §27's conditions — a real implementation measured above the new ceilings, a third service with different framing, SCRAM-SHA-512 or channel binding, or a materially different derivation cost |
| **SCRAM's implementation route** | **Closed in Phase 6.0.** ADR 0026 §7.4 framed it as franz-go's main module — `kgo` plus three transitive dependencies — or hand-rolled crypto. Phase 4.4b settled it in practice: `internal/adapter/postgres/wire/scram.go` implements SCRAM-SHA-256 on the standard library alone and is validated against a real server, so Kafka SCRAM needs **no new module**. What remains is extraction and framing | Closed. Extraction is Phase 6.2, under the constraints in `docs/ARCHITECTURE.md` §5.8, and requires its own security review |
| **Kafka integration fixture cannot bootstrap from a fresh checkout** | **Fixed in Phase 7.0b.** `test/integration/kafka/env/gen-certs.sh` now does `mkdir -p certs` before `cd`, as the PostgreSQL fixture always has. Reproduced first in a fresh worktree (exit 1 against PostgreSQL's exit 0), fixed, and re-verified from another fresh worktree including a second idempotent run | Closed |
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

### Phase 3.2d — SCRAM (not started; the dependency blocker is closed)

**ADR 0026 §7.4's blocker is stale, and the record of why is here rather than in that ADR.**
It framed the choice as franz-go's `pkg/sasl/scram` — which lives in the **main** franz-go
module and would add three transitive modules plus the `kgo` client ADR 0008 forbids — or
"hand-rolled cryptography". Phase 4.4b settled the second option in practice:
`internal/adapter/postgres/wire/scram.go` implements SCRAM-SHA-256 with the standard library
only (`crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`, `crypto/rand`), including strict
server-nonce extension checking, an iteration bound and server-signature verification, and it
is validated against a real PostgreSQL server.

So **completing Kafka SCRAM requires no new module**. What remains is extraction and framing,
scheduled as Phase 6.2 with its own security review (ADR 0054 §3 in spirit; constraints in
`docs/ARCHITECTURE.md` §5.8).

- [ ] Extract the RFC 5802 core into a shared package, under the §5.8 constraints
- [ ] Kafka SCRAM-SHA-256, reusing that core behind Kafka's SaslAuthenticate framing
- [ ] SCRAM-SHA-512 — **P2**, deferred; a hash swap over the same core, not a release blocker

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
- **What kept the gate open was generic requested-target TLS**, which had no production
  producer: PostgreSQL negotiates in band, and Kafka had no composition root. **The policy now
  exists — ADR 0053, Accepted in Phase 6.0c** — and is scheduled as Phase 6.1b so the owner
  lands before Kafka bootstrap composition makes the producer reachable
  (`docs/ARCHITECTURE.md` §12.1). The gate closes when 6.1b is implemented, not when the record
  was accepted.

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

### Phase 5.2 — credential sources and shareable output: COMPLETE

**ADR 0049 implemented**; ADR 0048's redaction step implemented. No `FindingCode`, no
`FailureClass`, no schema field, no dependency: counts stay 24 / 40 / **2 Reveal** / 1 / 1.

- [x] `--password-file` and `--password-stdin`, mutually exclusive, **no precedence** —
      supplying both is exit 2, and a failed source never falls back to the other
- [x] Exactly one trailing `\n` or `\r\n` removed; `TrimSpace` forbidden and guarded, so a
      password with leading or trailing spaces survives byte for byte
- [x] 4 KiB bound on **the input as read**, not the trimmed secret; oversize is exit 2, never a
      truncation, and the refusal names neither the material nor its size
- [x] The read itself is bounded, not just checked afterwards — an endless stream returns
      promptly instead of being consumed into memory
- [x] An empty source builds **no credential at all**, so an empty file, a newline-only file
      and no flag all reach `POSTGRES_CREDENTIAL_NOT_CONFIGURED`
- [x] `--shareable` derives `SHAREABLE_REDACTED` in the command, once, from the finished
      report; the renderer cannot import redaction and depguard now says so
- [x] The exit code is decided from the result **before** the projection is chosen, so
      redaction cannot turn a 1 into a 0
- [x] A refused redaction — the committed role-name fail-closed case — is an output failure:
      exit 3, nothing on stdout, no partially redacted artifact
- [x] Real integration: correct credential from both sources reaches a session; wrong
      credential is rejected at exit 1; `--tls-insecure` plus a credential still yields
      `POSTGRES_CREDENTIAL_WITHHELD` with nothing presented
- [x] 30 mutations applied, 26 caught, 4 not applicable. Five escapes were real test gaps and
      were closed

**What the mutation pass found, and it is worth remembering.** Replacing the bounded read with
a plain `ReadAll` left every behavioural test passing, because the size check afterwards still
refused the result — the property that changed was invisible to tests that only looked at
outcomes. Closing stdin was invisible too, because a `strings.Reader` is not an `io.Closer`. And
a projection that skipped redaction whenever a warning was present went unnoticed, because every
shareable test used a report carrying an ERROR or none at all — which would have leaked identity
on exactly the run an operator is most likely to share.

### Phase 5.3 — terminal renderer: COMPLETE

**ADR 0048 fully implemented.** `--output text|json`, default `text`. No `FindingCode`, no
`FailureClass`, no schema field, no dependency: counts stay 24 / 40 / 2 / 1 / 1, and no
production code outside `internal/render` and `internal/cli` changed.

- [x] `internal/render.Input` — the report projection plus one boolean, and nothing else
- [x] `internal/render/terminal` — header, per-path stage tree, findings, Result section
- [x] Three facts rendered separately and never collapsed: `status`, `session`, `execution`.
      `OK` never prints without "no target-side error was proven"
- [x] Session establishment read from a passing `postgres.session` node — never from the
      status, the absence of findings, or a passing startup or authentication
- [x] Incompleteness read from `render.Input`, never re-derived from the graph
- [x] Absence distinguished from SKIPPED, structurally: "not reached", "not attempted" and
      "not attempted on this path" — so a `trust` path and an unselected path read differently
      and neither is described as a missing credential
- [x] `continued` marked only from a real authentication or session node, never from other
      paths lacking children, sorting, address family or timing
- [x] Failure classes rendered verbatim; no prose is invented and no cause is named
- [x] Total from `RunMetadata.Duration()`; stage durations never summed; no threshold and no
      `slow`/`fast`/`degraded` vocabulary anywhere
- [x] No colour, no TTY detection, no width query — `os` is denied to the renderer, so output
      is byte-identical piped, redirected and interactive
- [x] Seven golden files rendered from **real** app runs against loopback sockets
- [x] Real binary integration: default text, no-credential, wrong credential, TLS failure,
      incomplete, shareable, and JSON unchanged
- [x] 28 mutations applied, 25 caught, 3 not applicable. Three escapes were real test gaps

**What the mutation pass found.** A hardcoded "IPv4 before IPv6" path order was invisible
because the obvious multi-path fixture uses two IPv4 addresses — the test now uses
`2001:db8::1` and `9.9.9.9`, where canonical order and family order genuinely disagree. And a
renderer that inspected `os.Stdout` to change its glyphs escaped every test, because tests
write to a buffer; `os` is now denied to `internal/render` outright.

### Phase 5 — remaining work: RELEASE VALIDATION

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

## Phase 6 — Kafka BASIC: DECIDED, NOT STARTED

Phase 6.0 fixed the prerequisites (ADRs 0050-0054, all Accepted, none implemented). The
sequence below is **normative**, and its ordering is a correctness property rather than a
convenience: *owner before producer, authority before credential use, security guard before
composition* (`docs/ARCHITECTURE.md` §12.1).

| Phase | Scope | Why here |
|---|---|---|
| **6.1a** | Kafka authentication mechanism guard | `Authenticate` reads `Mechanism()` nowhere and calls `ExchangePLAIN` unconditionally. The guard must precede `SecretFor`, `Reveal` and any credential-bearing wire output |
| **6.1b** | Generic requested-target TLS diagnosis (ADR 0053) | The owner must exist before 6.1c makes the producer reachable, or `tls.handshake` FAIL lands with `findings: []` and `status: OK` |
| **6.1c** | `DiagnoseKafka` application composition | Anchor, bootstrap sweep, ApiVersions, handshake, one authenticated path, Metadata, advertised sweep, ADR 0051's predicate. Existing rules wired; no new findings |
| **6.2** | Shared SCRAM core extraction + Kafka SCRAM-SHA-256 | **Complete.** ADR 0055 rejected Model A; ADR 0056 is the contract it was built to |
| ~~6.3~~ | ~~Kafka protocol diagnosis ownership~~ | **Delivered early as Phase 6.1c-P2.** ADR 0054 required the owners before composition made their producers reachable, so this moved ahead of 6.1c rather than staying here. The number is retired, not pending |
| **6.4** | Kafka renderer hierarchy + Kafka CLI | `collectPaths` promotes every `tcp.connect` to a top-level path, which conflates bootstrap and advertised sweeps; the tree needs a third level. Also owns the measured-zero versus unmeasured duration contract |
| **6.5** | Kafka BASIC closure | **Complete.** Includes the ADR 0054 §5 closure test, re-run mechanically against the producers |
| **6.6** | TLS trust and peer identity policy | **Complete.** ADR 0058. A decision phase: it had to precede IP literals, managed compatibility and release validation, because each would otherwise have made its own trust and identity assumption |
| **6.7** | IP literal target semantics | **Complete.** ADR 0059: Model A — a literal records no `dns.lookup` node at all. `net/netip` is the single classification and canonicalization; scoped IPv6 refused; TCP and generic TLS ownership landed with their producers; `schemaVersion` 1. ADR 0058's three gaps proved to be one coupled defect and moved to 6.8 |
| **6.8** | Release and compatibility validation | Formerly numbered 6.6. Real-cluster release validation, and the first managed/Redpanda evidence |

- [x] **6.1a** mechanism guard: UNKNOWN + `AUTH_MECHANISM_UNSUPPORTED`, zero `SecretFor`,
      zero `Reveal`, zero bytes written, proven by test — **COMPLETE**
- [x] **6.1b** generic requested-target TLS rule and its five codes (24 → 29) — **COMPLETE**
- [x] **6.1c** `DiagnoseKafka`, requested-target anchor, ADR 0051 completeness predicate,
      ADR 0050 structurally enforced, closure guard turned positive — **COMPLETE**
- [x] **6.2a** shared SCRAM core security review — **COMPLETE**, ADR 0055: Model A
      **rejected**, Model D adopted, seventeen implementation conditions recorded
- [x] **6.2a-R2** Model D API and security contract — **COMPLETE**, ADR 0056: exact API,
      callback contract, eight bounds, SASLprep refused, atomic gate transition
- [x] **6.2** extraction under ADR 0056 — `internal/sasl/scram`, SASLname escaping, Kafka
      SCRAM-SHA-256, the two new `Reveal` guards, the atomic guard swap — **COMPLETE**
- [x] **6.3** Kafka protocol diagnosis ownership — **delivered as 6.1c-P2**; the number is
      retired. Phase 6.2 added the two owners SCRAM made newly reachable, in the same
      change-set as their producer
- [x] **6.4** renderer path hierarchy, `outcome` / `topology` lines, `diagnose kafka` and the
      duration contract — **COMPLETE**. `domain.Elapsed` replaced the bare `time.Duration`,
      `internal/render/terminal` gained a third tree level and a per-service table, ADR 0057
      settled mechanism selection, and the inherited golden flake is fixed at the product
      layer rather than in the fixture. See "Phase 6.4" below
- [x] **6.5** Kafka BASIC closure gate, including the per-service ownership closure test —
      **COMPLETE**. Audit only: no product surface added. 44 mutations, zero survivors after
      three test files closed five real guard gaps — the renderer's three unasserted
      `not measured` branches, unread finding prose, and unguarded README capability claims.
      SCRAM production files byte-identical, `schemaVersion` 1, 40 finding codes. See
      "Phase 6.5" below
- [x] **6.6** TLS trust and peer identity policy — **COMPLETE**, ADR 0058. Decision only: no
      production Go, no `FindingCode`, no `FailureClass`, no `schemaVersion`, no flag, no
      dependency, and no SCRAM change. Sixteen mutations; the two clauses that turned out to be
      unguarded rather than unimplemented are now covered, and Go's IP-SAN and CN behaviour is
      pinned by test rather than remembered. Three product gaps recorded and deferred to 6.7.
      See "Phase 6.6" below
- [x] **6.7** IP literal target semantics — **COMPLETE**, ADR 0059. First-class IPv4 and IPv6
      literal targets for both services, requested and Kafka-advertised. A literal performs and
      records **no resolution**: no `dns.lookup` node, no DNS finding, no hostname prose. One
      address has one spelling. Scoped IPv6 is refused rather than silently mis-measured. 30
      mutations, one equivalent mutant, two real gaps found and closed — verification silently
      relaxed for a literal, and the Kafka completeness predicate partially reading a mixed
      shape. `schemaVersion` 1, 40 finding codes, 41 failure classes, 2 `Reveal` call sites,
      one credential-bearing Kafka auth attempt, SCRAM byte-identical. ADR 0058 §14's three
      gaps were measured, found to be one coupled defect, and deferred to 6.8. See
      "Phase 6.7" below
- [x] **6.8** Kafka release validation against the real cluster — **complete.** 6.8A closed the
      three ADR 0058 §14 TLS gaps (ADR 0060), 6.8B re-validated both services through a
      release-shaped binary against the real fixtures, 6.8C produced the first non-Apache Kafka
      evidence, 6.8D the compatibility matrix. Recommended next version **v0.2.0**; not tagged

### Phase 6.1a — Kafka authentication mechanism guard (complete)

`kafka.Authenticate` inspected `HandshakeSession.Mechanism()` nowhere and called
`wire.ExchangePLAIN` unconditionally. A session that negotiated SCRAM-SHA-256 therefore
received RFC 4616 PLAIN framing — `authzid NUL authcid NUL passwd` — carrying the real
identity and password, to a peer that had agreed to a different mechanism and would never
parse them as PLAIN. **The defect was reproduced against the fixture broker before the fix:
one SaslAuthenticate payload, three NUL-separated fields, containing the secret.**

- [x] `wire.MechanismPLAIN`, the one mechanism this adapter can perform
- [x] `supportedMechanism` — an exact-match whitelist of exactly that one, with no folding,
      no fallback and no retry
- [x] The guard runs **first**: before the credential check, before the channel policy,
      before the endpoint binding, before `SecretFor`, before `Reveal`, before any wire write
- [x] Unsupported → `UNKNOWN` + `AUTH_MECHANISM_UNSUPPORTED`, a truthful
      `kafka.sasl_authenticate` node parented to the handshake, mechanism attribute only,
      zero duration, **no blocker edge** — nothing in the graph obstructed it
- [x] Zero-access proofs: `SecretFor` unreachable (a credential bound elsewhere would error
      and does not), zero credential payloads, and **zero bytes written** on a plaintext path

**Ordering changed deliberately, and it is a behaviour change in one combination.** The
mechanism gap now outranks the channel-policy refusal. Previously an unsupported mechanism on
an unverified channel reported `SKIPPED` + `EXEC_SKIPPED_BY_POLICY`, which reads as *establish
verified TLS and this will work* — false when svcdoctor cannot perform the mechanism at all.
This matches `internal/adapter/postgres`, whose `admissibleMechanism` precedes its transport
policy for the same reason (`docs/ARCHITECTURE.md` §5.7).

**Two gaps recorded rather than closed here:**

- **Kafka has no missing-input producer.** A zero credential is still `ErrUnboundCredential`, a
  caller error, where PostgreSQL records `EXEC_REQUIRED_INPUT_MISSING` evidence (ADR 0046).
  Kafka has no "no credential configured" path at all. **Phase 6.1c/6.3.**
- **`AUTH_MECHANISM_UNSUPPORTED` has no diagnosis owner.** ADR 0054 permits this only while the
  outcome is not product-reachable, and it is not: `internal/adapter/kafka` still has zero
  production importers, no `DiagnoseKafka`, no CLI. **Ownership must land no later than Phase
  6.1c-P2 — which is where it landed — before Kafka becomes product-reachable, and the Phase
  6.5 closure gate must verify it
  mechanically.**

### Phase 6.1b — generic requested-target TLS diagnosis (complete)

Implements ADR 0053, and is **ADR 0054's ordering applied for the first time**: the owner
landed before Phase 6.1c introduces the producer. After 6.1b the owner exists and the
producer is still not product-reachable; after 6.1c they become reachable together.

- [x] `internal/diagnosis/transport.TLS`, beside `DNS` and `TCP`
- [x] Five codes, 24 → 29: `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS`, `TLS_IDENTITY_MISMATCH`,
      `TLS_CHAIN_NOT_TRUSTED`, `TLS_CERTIFICATE_NOT_VALID_NOW`, `TLS_HANDSHAKE_NOT_COMPLETED`
- [x] Closed mapping over the **six** classes `internal/probe/tls` produces; the three
      declared-but-unproduced classes gain nothing, and an unrecognized class produces nothing
- [x] Endpoint-scoped, **no partial-success withholding** — a passing sibling address does not
      suppress a failing endpoint's finding
- [x] UNKNOWN (`EXEC_LOCAL_TIMEOUT`, `EXEC_CANCELLED`) and SKIPPED produce no claim
- [x] Real-socket coverage in `test/security` for identity mismatch and unknown authority,
      plus the redaction projection

**Two implementation notes worth carrying forward.**

The rule **descends from the anchor** rather than walking up from the handshake, which is how
ADR 0053 §8 states the predicate. `internal/diagnosis/transport` bans `Graph.Parents` — asking
what a node hangs from is the provenance question `Origin` was deferred to avoid — so
`collectSweep` collects a handshake only as a **direct child** of a connection it already
reached from an anchor. The relation checked is identical.

`collectSweep` **ignores** a connect child it does not recognize rather than rejecting it.
Rejecting would make every PostgreSQL sweep ill-formed — its connect carries a
`postgres.ssl_request` child — and silence the DNS and TCP findings that already work. That
is also what keeps PostgreSQL's in-band handshake outside this rule: it is a grandchild of the
connection, never a direct child.

### Phase 6.1c — first attempt: STOPPED by the ADR 0054 gate (history)

Composition was attempted and **declined**. `internal/diagnosis/kafka` owns only the two
advertised-broker findings, and both anchor on `kafka.broker_advertised`. Nothing owns
`kafka.api_versions` FAIL, `kafka.sasl_handshake` FAIL, `kafka.sasl_authenticate`
FAIL/UNKNOWN/SKIPPED or `kafka.metadata` FAIL.

`deriveSummary` sets `SummaryStatus` from findings alone, and `incompleteRun` returns true only
for `StateUnknown` with `EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED`. A composition today would
therefore let a **rejected Kafka credential** arrive as `findings: []`, `status: OK`,
`incomplete: false`, exit 0 — and would silence the fail-closed credential-transport refusal
ADR 0029 exists to make loud.

Owner before producer is normative, so **Phase 6.3 moves ahead of 6.1c**. The reordering is a
correctness property, not a preference: "the Kafka CLI does not exist yet" is not a defence,
because ADR 0054 is about production application reachability rather than user routing.

### Phase 6.1c-P1 — Kafka required-authentication-input producer: COMPLETE

The Kafka analogue of ADR 0046, and the first of the two prerequisites 6.1c uncovered.

A broker that agreed to a mechanism svcdoctor can perform, on a run holding no credential,
returned `ErrInvalidInput`/`ErrUnboundCredential` and recorded **no authentication node at
all**. The graph was indistinguishable from one where the step never came up. It now records:

```text
kafka.sasl_authenticate   SKIPPED   EXEC_REQUIRED_INPUT_MISSING
```

with `SecretFor` = 0, `Reveal` = 0 and zero bytes written, proven at the socket rather than by
a call count. No new `FailureClass`, no `FindingCode`, no schema change, no dependency.

Four authentication outcomes are now distinct, and `TestFourAuthenticationOutcomesStayDistinct`
holds them apart so no future change can collapse two into an umbrella class:

| Condition | State | Class |
| --- | --- | --- |
| svcdoctor cannot perform the mechanism | `UNKNOWN` | `AUTH_MECHANISM_UNSUPPORTED` |
| the run configured no credential | `SKIPPED` | `EXEC_REQUIRED_INPUT_MISSING` |
| a credential existed and the policy withheld it | `SKIPPED` | `EXEC_SKIPPED_BY_POLICY` |
| the broker evaluated a credential and refused it | `FAIL` | `AUTH_CREDENTIALS_REJECTED` |

The order in `Authenticate` is the security contract and is pinned mechanically: mechanism
guard → required input → channel policy → endpoint binding → `SecretFor` → `Reveal`. The
mechanism guard wins over a missing credential, because supplying one would change nothing for
an exchange svcdoctor cannot frame. A missing credential wins over the channel policy, because
with nothing to present there is no credential for a policy to refuse.

**This outcome has no diagnosis owner yet, and that is safe only because Kafka is not
production-reachable.** `test/security/kafka_production_reachability_test.go` enforces exactly
that: zero production importers of `internal/adapter/kafka`, and no `DiagnoseKafka` entry
point. It is the ADR 0054 gate in executable form, and it must fail on the first composition
commit.

### Phase 6.1c-P2 — Kafka protocol diagnosis ownership: COMPLETE

Formerly Phase 6.3, moved ahead of composition because ADR 0054 made the original order unsafe.

`internal/diagnosis/kafka.Protocol` is one rule over four steps, keyed on a **closed**
`(step, state, failureClass)` table with no default branch. Ten codes; see `docs/FINDINGS.md`
for the full table and the reasoning behind each `vantageDependent` value.

Every outcome the four producers can emit now has an owner, and the mapping is checked against
a list derived by reading `internal/adapter/kafka` — so a producer that gains an outcome fails
the build until the table gains an owner. Two facts found by re-deriving rather than trusting
the earlier audit:

- `AUTH_MECHANISM_NOT_OFFERED` is reachable at `kafka.sasl_authenticate` as well as at
  `kafka.sasl_handshake`, because `authenticationFailure` falls through to `handshakeFailure`.
  Both map to the same code rather than the later one falling into the authentication floor.
- `PROTOCOL_UNSUPPORTED_VERSION` is **not** reachable at `kafka.metadata`: its `classify`
  consults no broker error code, because Metadata carries a top-level one only from v13 and
  svcdoctor sends v1. Writing that mapping would have authorized a claim for evidence that
  cannot occur.

The question P1 left open is settled: `KAFKA_CREDENTIAL_NOT_CONFIGURED` is
CONFIRMED/WARN/HIGH with **`vantageDependent: false`**. PostgreSQL's `true` rests on
`pg_hba.conf` selecting the method by source address, so its compound claim inherits the weaker
half. Neither Kafka half is source-keyed: a listener's SASL requirement is fixed per listener,
and that the run held nothing is svcdoctor's own configuration.

Three shared constants moved to `internal/service/kafka` on the trigger that package's doc
comment always named — a second reader outside the producing package. `StepAPIVersions`,
`StepSASLHandshake` and `StepSASLAuthenticate`, plus `AttrSASLMechanism`,
`AttrRequestAPIVersion` and `AttrErrorCode`. The strings are unchanged and the adapter
re-exports them, so no identifier and no serialized report moved.

`Result.Incomplete()` is unchanged, `SummaryStatus` is unchanged, and no schema field, no
`FailureClass`, no dependency and no `Origin` was added.

### Phase 6.1c — `DiagnoseKafka` application composition: COMPLETE

`internal/app.DiagnoseKafka` is the second composition root, and the commit that
introduced it is the commit that made every Kafka stage product-reachable. It was safe to
land because ADR 0054's ordering was honoured rather than waived: 6.1a, 6.1b, 6.1c-P1 and
6.1c-P2 all landed first, and the first attempt at this phase was **stopped** rather than
argued around.

- [x] `KafkaParams` / `DiagnoseKafka` / `Result`, beside the PostgreSQL pair. `Result` is
      reused unchanged — one report, one `Incomplete()` boolean, no exit code
- [x] The requested-target anchor through the existing service-neutral `logicalTarget`;
      `internal/app` still creates exactly one kind of evidence, at one site, in
      `target.go`
- [x] Bootstrap sweep with a **TLS plan** — the first production producer of a generic
      requested-target `tls.handshake` node, which is what ADR 0053 landed a phase early
      for
- [x] ApiVersions and SaslHandshake on **every** completed path; both are credential-free
- [x] **At most one** credential-bearing authentication, on the canonically smallest path
      whose broker accepted the mechanism. No retry, no mechanism fallback, no channel
      downgrade
- [x] Metadata on the authenticated session, then a credential-free DNS/TCP/TLS sweep of
      every advertisement, gated on the exchange having completed
- [x] ADR 0051's completeness predicate in `incompleteKafkaRun`, all ten acceptance rows
      pinned plus five shapes the record implies
- [x] Six diagnosis rules wired: generic DNS, TCP and TLS, Kafka protocol, advertised
      reachability and unusable advertisements
- [x] `test/security/kafka_production_reachability_test.go` **transformed**, not deleted —
      see below

**ADR 0050 is structurally enforced, four ways.** A credential bound to anything but the
logical target is refused at the door as `ErrInvalidInput`, before any socket opens. The
composition calls `NewCredential`, `NewSecret`, `Reveal` and `SecretFor` nowhere, asserted
statically. `kafka.TransportPlan` has no field that could hold credential material,
asserted by reflection. And a hostile broker that advertises an attacker endpoint holding
a **valid certificate signed by the CA the run trusts** receives zero application bytes
above its TLS layer, asserted at the socket.

**One composition decision is not in an ADR and is recorded here.** The advertised sweep
inherits the run's `RootCAs`, version bounds and `InsecureSkipVerify`, but **not**
`ServerName`. An explicit server name pins one endpoint's identity; applying it to every
advertised sweep would verify each broker's certificate against the bootstrap's name and
produce identity mismatches no real client would see. Clearing it restores verification
against the advertised hostname, which is what a client checks. This is ADR 0050's
reasoning one layer down — a value authorized for the endpoint the operator named does not
travel to an endpoint a peer named — and it is exercised by a test that would fail if the
name travelled.

**The ADR 0054 gate was transformed rather than retired.** The old file asserted that
`internal/adapter/kafka` had zero production importers and that no `DiagnoseKafka` existed.
It now asserts the positive closure: **exactly one** production importer and it is
`internal/app`, **exactly one** `DiagnoseKafka` and it is in `internal/app/kafka.go`, the
exact set of six rules the composition wires, no credential minting or secret resolution in
the composition root, one authentication call site outside any loop, no credential-bearing
field on the advertised transport plan, and that the protocol closure test still fails in
both directions. Two guard files vouch for each other, so deleting either fails the other.

**Known limitation, recorded rather than fixed.** `kafka.Metadata` consumes an
`AuthenticatedSession`, so a Kafka listener with **no SASL at all** cannot reach Metadata
through this composition: the handshake fails and the run stops with a truthful protocol
finding. That restriction is the adapter's, not Kafka's, and it is documented on
`kafka.Metadata` itself. Lifting it needs a session type the adapter deliberately does not
have, and it is not in Kafka BASIC's scope.

**Deliberately not done in 6.1c:** no CLI route, no renderer, no `outcome` or `topology`
line, no SCRAM, no new `FindingCode`, no new `FailureClass`, no schema field, no
dependency, and no change to `Reveal`'s two production call sites.

**REOPENED in the Phase 6.2 closure pass. Root cause proven in R1; the fix is deferred to
Phase 6.4, which owns renderer semantics.**

Phase 6.1c recorded this as a one-off `internal/cli` failure under load. It is not one-off.

**Measured.** ~6 failures in 25 runs of `TestGoldenTerminalOutput` on the Phase 6.2 tree, and
**3 failures in 20 runs in a clean worktree at `fdc2c3a`** — the commit before any Phase 6.2
change. Same subtests, same rate, none of this phase's code present. **It predates Phase 6.2
and this was measured rather than assumed.**

**It is per-process, not per-iteration.** `-count=50` in one process passes; 50 separate
invocations of the single subtest passed 50/50; the full package fails ~1 run in 4. Whatever
varies, varies across process warm-up, which is why it looked random.

**More than one golden case is affected.** Captured failures include
`TestGoldenTerminalOutput/local_budget_exhausted` and `.../no_credential`. Every observed
failure has the same shape, one token on the DNS row:

```text
want   ✓ PASS  DNS  <duration>
got    ✓ PASS  DNS
```

**Root cause, measured from source and from the running fixture.** The golden fixtures build
their reports with `runReal`, so `internal/probe/dns`'s `observe` measures a genuine
`time.Since` around a `stubResolver` that returns a preallocated slice. Sampled across
processes the DNS step measures **42–834 ns**, and every value is a multiple of ~41.67 ns —
the Apple Silicon monotonic tick. One tick below the floor is **zero**, and `0s` was directly
observed in failing runs. `internal/render/terminal/duration.go` renders `d <= 0` as the empty
string, deliberately, so that a SKIPPED node or the requested-target anchor does not print
`0s`. So a measured-but-sub-tick DNS step renders exactly like a step that was never timed.

An earlier draft of this note guessed the mechanism was a sub-microsecond value falling below
a formatting floor. That is wrong and the guess is recorded here because it was wrong: the
formatter renders `<1µs` for anything under a microsecond, and the golden normalizer already
matches that token. Only exact zero renders empty.

**Why R1 did not fix it.** The classification is *both* a fixture problem and a product
ambiguity:

- *Fixture* — a golden test that pins rendered layout has no reason to measure a real clock
  around a synthetic resolver.
- *Product* — `domain.Evidence` stores a bare `time.Duration` with **no "was this measured" bit**,
  and there is no injectable clock anywhere in `internal/probe`, `internal/app` or
  `internal/domain`. So *measured zero* and *never measured* are genuinely indistinguishable in
  the model, and the renderer cannot tell them apart even in principle. ADR 0052 already fixed
  the principle that `not measured` must never be collapsed into another outcome; this is that
  collapse one layer down.

The clean test-only fixes are all blocked. `app.Result` has unexported fields and no exported
constructor, so a golden test cannot consume a fixed report without a production affordance;
making the stub resolver consume measurable time is a sleep wearing a different hat; and
normalizing an absent duration to `<duration>` would erase the SKIPPED-versus-measured
distinction the golden exists to pin.

**CLOSED in Phase 6.4A, at the product layer.** `domain.Evidence` now carries a
`domain.Elapsed` — a duration and whether one was taken, with the zero value meaning
*unmeasured* — so a measured zero and an absent measurement are different values. The
terminal renderer renders them as `0s` and an empty cell. Nothing was added to the fixture, no
clock was injected, no sleep was introduced and no test-only special case exists: the golden
became deterministic because the ambiguity it exposed is gone.

**Measured before and after, in separate processes, because the flake was process-sensitive:**

| | before | after |
|---|---|---|
| `TestGoldenTerminalOutput`, targeted | **16 failures / 40 runs** | **0 / 120** |
| `internal/cli`, whole package | not measured at entry | **0 / 60** |

`schemaVersion` is unchanged and the canonical JSON is byte-identical: `duration` has been a
required string on every node since Phase 1 and an unmeasured step has always encoded as
`"0s"`, so the distinction stops at the domain. That is a **v1 limitation**, recorded rather
than hidden — a JSON consumer cannot tell a step that was never timed from one that measured
zero. Reopening it means a schema version, not a field.

### Phase 6.2 — AUTHORIZED by ADR 0056. Gate transition is atomic

**Phase 6.2a-R2 is complete and its outcome is ADR 0056, the Model D implementation
contract. Phase 6.2 implementation is authorized.**

What R2 settled beyond ADR 0055's outline:

- **The core is `internal/sasl/scram`**, a leaf importing nothing internal, and
  `internal/sasl` may contain nothing but `scram/` — a family directory is how a generic
  SASL framework would begin, and this phase is SCRAM-SHA-256 only.
- **The core generates the nonce.** ADR 0055 sketched `Begin(username, nonce)`; that puts
  entropy authority in two wire packages, where a short or `math/rand` nonce becomes a
  caller's mistake to make.
- **SASLprep is refused, and that is a correctness decision, not a shortcut.** PostgreSQL
  applies SASLprep on both sides; Apache Kafka does not (`KAFKA-6272`, open since 1.0.0,
  `ScramFormatter.normalize()` only UTF-8 encodes). **The two services require opposite
  behaviour for non-ASCII input**, so no shared implementation is correct for both. Over
  printable ASCII SASLprep is provably the identity, so restricting to U+0020–U+007E is the
  only choice correct against both — and it needs no Unicode dependency. SASLname escaping
  (`,`→`=2C`, `=`→`=3D`) *is* core-owned, because it is pure RFC grammar.
- **Eight core-owned bounds**, with the encoded-salt length checked *before* the base64
  decode — today's parser decodes the salt before applying the iteration ceiling.
- **A three-step state machine**, so a second `Continue` or a `Verify` before `Continue` is
  an error rather than a silent wrong answer.
- **Two new `Reveal` guards.** Kafka has no count guard today, and nothing asserts the
  repository-wide total of two.
- **The gate transition is atomic (ADR 0056 §13), superseding ADR 0055.** The negative guard
  is **not** deleted by the R2 commit. It is deleted in the same commit that introduces the
  package and its positive guards. There must never be a commit where neither holds.

Three residual risks are recorded rather than argued away: a password could be passed as the
`Username` (caught by review, vectors and integration, not by construction); the derivation
callback closes over wire scope the core cannot inspect, so the core performs no I/O *of its
own*; and the SaltedPassword is not harmless — Model D removes password-reuse transfer, not
the whole class.

### Phase 6.2 — shared SCRAM core and Kafka SCRAM-SHA-256: COMPLETE

`internal/sasl/scram` holds the RFC 5802 semantics for both services and **cannot observe a
password**: no function it exposes accepts one. Each wire package reveals its own secret,
performs PBKDF2 itself, and hands the core a callback the core invokes exactly once, after ten
validation steps. What crosses the boundary is a SaltedPassword — one principal, one target,
one salt — rather than the operator's reusable credential.

- [x] `internal/sasl/scram`: `Begin`/`Continue`/`Verify` over a pointer `State` with a
      three-step machine, six standard-library imports, no `fmt`, no `strings`
- [x] Depguard **allowlist** plus the package's own AST guards, both mutation-tested
- [x] The atomic gate swap: `TestNoSharedSCRAMPackageExists` deleted in the same change-set
      that introduced the package and its positive guards. The reciprocal guard in
      `kafka_composition_test.go` **caught the deletion** and had to be updated to name the
      successors — the mutual-reference mechanism working as designed
- [x] PostgreSQL migrated with no semantic change; three sentinels aliased, two deliberately
      translated instead so framing and SCRAM meanings stay distinct
- [x] Kafka SASL/SCRAM-SHA-256, with `wire.Authenticate` as the single reveal boundary
- [x] RFC 7677 vectors pinning every intermediate, plus the message-construction vectors the
      PostgreSQL test could never reach because it passed a literal client-first-bare in
- [x] Five fuzz targets, 20s each, green
- [x] 14 core mutations, 4 Kafka mutations, 2 PostgreSQL mutations — all caught
- [x] Real-cluster integration including an escaped principal, a wrong credential, non-ASCII
      refusals and redaction

**Four things this phase found that the reviews did not.**

1. **PLAIN and SCRAM each having an exported exchange took `Reveal` from two sites to three.**
   The obvious structure — one exported function per mechanism, each opening its own secret —
   is a perfectly ordinary Go design and it broke an invariant every ADR since 0027 states.
   Caught by the new repository-wide guard, which is exactly the gap Phase 6.2a identified and
   which nothing had enforced before.
2. **SCRAM made two outcomes newly reachable with no diagnosis owner**, which ADR 0054 forbids
   landing. `KAFKA_PEER_VERIFICATION_FAILED` was added — mirroring the PostgreSQL concept, not
   inventing one — and the capability refusals reuse the existing unsupported-by-svcdoctor code.
   Owners landed in the same change-set as the producer. **This is the first new `FindingCode`
   since Phase 6.1b: 40 → 41.**
3. **A nonce narrowing was made on a false premise, measured, and reverted.** The theory was
   that Kafka's client-first regex rejects base64's `+` and `/`. Kafka 4.0.0 accepts both and
   completes the exchange. Reverted rather than kept, because a change defended by a wrong
   reason teaches the next reader something untrue.
4. **Three fixture defects masqueraded as product defects, and each cost real time.** Every one
   of them presented as "SCRAM is broken" while SCRAM was correct.
   - The broker could not construct a SCRAM `SaslServer` at all, because `jaas.conf` declared
     only `PlainLoginModule`. Kafka answers that by **closing the connection**, which reaches a
     client as a bare EOF — indistinguishable from a network fault.
   - `integration-kafka` chains up/test/down, so a failing test aborts before teardown; the next
     `kafka-up` then regenerated certificates against still-running brokers, producing
     `TLS_UNKNOWN_AUTHORITY` while the mounted CA file looked perfectly correct. `kafka-up` now
     force-recreates.
   - **`compose-sasl.yaml` has no named volume for the KRaft data directory**, so
     `up -d --force-recreate` — which `restore()` and `reconfigure()` both use — discards the
     metadata log and every SCRAM credential with it. PLAIN never noticed because its
     credentials live in the `jaas.conf` bind mount. The SCRAM readiness helper re-provisions
     the principals rather than a volume being added, because every other test in the suite
     depends on `kafka-up` starting from an empty cluster.

**Deliberately not done in 6.2:** no SCRAM-SHA-512, no SCRAM-SHA-256-PLUS, no channel binding,
no OAUTHBEARER, no GSSAPI, no IAM, no fallback in either direction, no CLI, no renderer, no
schema field, no dependency, and no change to PostgreSQL semantics.

**A readiness condition worth remembering.** SCRAM verifiers live in the KRaft metadata log and
each broker's `ScramPublisher` warms its credential cache *asynchronously after startup*, so a
broker can be registered, bound and answering ApiVersions while SCRAM still fails — and the
failure is indistinguishable from a wrong password. `kafka-configs --describe` returns earlier
than that. The suite's readiness condition is therefore a real SCRAM authentication.

### Phase 6.2a — Model A rejected (history)

**Phase 6.2a is complete and its outcome is ADR 0055: Model A rejected, Model D adopted.**
The shared core must accept **no password in any type**; it receives a derivation callback
and the wire package keeps the plaintext and the `crypto/pbkdf2` call. What crosses the
package boundary is the SaltedPassword, which authenticates one principal to one target
rather than being the operator's reusable password.

Three things the review found that the plan did not have:

- **`saslname` escaping is new code, not extracted code.** PostgreSQL sends `n=` — an empty
  username, because the role travels in the `StartupMessage`. Kafka reads the username from
  `n=`, so RFC 5802 §5.1 escaping (`,` → `=2C`, `=` → `=3D`) is required. A repository-wide
  search found no escaping of any kind, and the existing RFC 7677 vector passes a literal
  `client-first-bare` into `derive`, so message construction with a username has never been
  tested.
- **The two wire packages bound peer payloads eight times apart** — PostgreSQL's
  `MaxMessageSize` is 1 MiB, Kafka's `maxResponseSize` is 8 MiB. The core cannot inherit a
  caller's bound and must bound message length, salt length, nonce length and attribute count
  itself.
- **Kafka has no `Reveal`-count guard.** `forbidigo` confines the call to wire packages and
  `TestPostgresCredentialSurfaceIsExactlyTwoCalls` pins PostgreSQL at one, but nothing pins
  Kafka's. Phase 6.2 adds the analogue and a repository-wide "exactly two" assertion.

**Implementation is authorized by Phase 6.2a-R2**, a short follow-up review confirming Model D
against a written API and ADR 0055's seventeen conditions. `TestNoSharedSCRAMPackageExists`
stays until then and is deleted in the commit that records *that* acceptance.

The Model A framing below is retained as history; ADR 0055 supersedes it.

### Phase 6.2 — the Model A gate as written before 6.2a (history)

**Phase 6.2 implementation must not begin as a normal implementation phase.** It begins with:

> **Phase 6.2a — shared SCRAM core security review**

which must be Accepted first. Extraction moves revealed plaintext across a package boundary
for the first time, and that is the one place in the Kafka plan where a security boundary is
*relaxed* rather than tightened.

**As of Phase 6.1c this gate is mechanically enforced, not merely written down.**
`test/security/kafka_production_reachability_test.go`'s `TestNoSharedSCRAMPackageExists`
fails the build if `internal/sasl`, `internal/scram` or `internal/crypto/scram` appears. It
is to be deleted **in the commit that records 6.2a's acceptance**, never in the commit that
wants the package. Phase 6.1c completing authorizes nothing here: composition exposed no
new SCRAM need, and an unsupported mechanism still travels through the 6.1a guard to the
6.1c-P2 owner as `UNKNOWN` + `AUTH_MECHANISM_UNSUPPORTED`.

The review must re-open Model A and settle: `string` vs `[]byte`; plaintext copies and escape
analysis where useful; Go's zeroization limits; accidental `fmt`/error formatting; panic paths;
the depguard rule for the shared package; RFC 5802 test vectors; nonce injection and test
seams; PostgreSQL regression risk; Kafka framing separation; the `Reveal` count; whether any
sensitive intermediate material is returned; whether SCRAM-SHA-512 belongs now or stays
deferred; and whether a smaller package boundary is safer.

Constraints already fixed (`docs/ARCHITECTURE.md` §5.8): the shared core must not import
`internal/security` or `net`, must not call `security.Reveal`, perform I/O, log plaintext, put
plaintext in errors or retain connection state; plaintext enters only as a short-lived
argument; `Reveal` stays in wire packages and its call-site count is unchanged by extraction.

### Phase 6.4 — Kafka renderer hierarchy, the duration contract and the Kafka CLI: COMPLETE

Three ordered parts, and the order was a correctness property: the duration contract had to
be decided before the fixture could be made deterministic, and the renderer had to present a
discovered broker as a discovered broker before a CLI could show one to anybody.

**6.4A — the duration contract.** `domain.Elapsed`, a duration plus whether one was taken,
zero value *unmeasured*. Every one of the 35 `EvidenceInput` construction sites was revisited
by the compiler rather than by search: the field changed type, so there was no way to skip
one. Ten production sites record a measurement, eight record its absence. `schemaVersion`
stays 1 and the canonical JSON is byte-identical.

**6.4B — the renderer.** A third tree level, a per-service table, ADR 0052's `outcome` and
`topology` lines, and sixteen goldens that need **no normalization at all** because nothing in
them is volatile.

**6.4C — the CLI.** `svcdoctor diagnose kafka`, ADR 0057, and a real-binary integration suite
against the three-broker cluster.

**Five things this phase found that the plan did not.**

1. **ADR 0052 was wrong twice, in its own Consequences section.** It claimed PostgreSQL output
   would be byte-identical — it changes on one line per report, because §2 renamed the label
   `session` to `outcome` and the Consequences sentence read that as being about bytes. And it
   said the topology count and ADR 0051's completeness rule would share one implementation;
   depguard denies a renderer the application, so they cannot. Both corrections are recorded in
   the ADR, and the second is now a test against real composed runs rather than an assumption.
2. **The advertised journey is a security boundary, not a presentation choice.** Reusing the
   bootstrap journey beneath an advertisement printed `Authentication  not attempted on this
   path` under every discovered broker — a row that says svcdoctor *could* have authenticated
   there and happened not to, when ADR 0050 says it must never. The fix is a second journey in
   the table, not a filter: a node the journey does not place is still rendered, so an
   authentication node that somehow appeared would be **visible rather than hidden**.
3. **Two mutations survived the first pass, and both were real gaps.** A renderer that decided
   the advertisement boundary by `strings.Contains(id, "advertised")` passed every test,
   because the production identifiers happen to contain that word. And a renderer that filtered
   auth rows out of advertised subtrees passed, because the test only asserted their absence.
   The first is now an AST guard, the second an assertion that a deliberately-planted node is
   shown.
4. **`IsMeasured` was reachable by no assertion at all.** Replacing its body with `e.d > 0`
   survived the whole suite: every test that called it did so on an unmeasured value, where
   both bodies agree. Found by mutation, closed by a direct unit test of the type.
5. **A fixture canary that is the tool's own name proves nothing.** The Kafka fixture principal
   is literally `svcdoctor`, which appears in every report's header, so a shareable-output sweep
   for it fails on the banner rather than on a leak. The PostgreSQL suite records the same
   hazard from the other side. The port is also **deliberately preserved** by redaction — it
   selects a service, it does not identify anyone — and asserting its absence was a test defect,
   not a leak.

**Deliberately not done in 6.4:** no Markdown or HTML renderer, no colour, no TTY detection, no
latency finding, no `inspect` namespace, no IP-literal work, no Redpanda, no managed-provider
compatibility, no server-final strictness change, no new finding code, no new failure class, no
schema field, no dependency, and no change to `Reveal`'s two production call sites or to any
SCRAM production file.

**One PostgreSQL change, it is presentation only, and it touches output that v0.1.0 already
shipped.** The terminal Result block's label is `outcome` rather than `session`. Measured byte
for byte against `HEAD`:

```diff
 Result
-  status     OK           no target-side error was proven
-  session    established
+  status     OK                   no target-side error was proven
+  outcome    session established
   execution  complete
   duration   12.0ms
```

**Two lines differ, not one**, and the second is worth stating precisely: `status` is unchanged
in content and shifts only because tabwriter sizes a column from its widest cell, and the value
column now holds `session established` rather than `established`. Everything else in the
document — the header, every stage row, every glyph, every absence phrase, every finding, the
`execution`, `first break` and `duration` rows — is byte-identical.

What did **not** change: the value wording (`session established` / `session NOT established`,
ADR 0052 §2 preserves it verbatim), the canonical JSON, `schemaVersion`, every finding code and
severity, `SummaryStatus`, and every exit code. No `outcome` field and no `sessionEstablished`
field was added to the report model; the line is a presentation restatement of one node's
state, which ADR 0048 §5 is why it is not serialized.

This is a **presentation compatibility change**, introduced so that two services can share one
Result block truthfully: Kafka has no session-establishment handshake, so a `session` label
carrying a metadata value would be a claim the protocol cannot support. ADR 0052 §2 decided the
label and §3's rejected-alternatives table refuses keeping `session`. A script parsing the
terminal text for `^  session` breaks; JSON is the canonical automation surface and is
unaffected.

**A v1 JSON limitation is now recorded rather than latent.** `duration` cannot distinguish a
step that was never timed from one that measured zero; both encode as `"0s"`. The terminal
renderer can, because the distinction lives in the domain. Changing the JSON means a schema
version.

### Phase 6.5 — Kafka BASIC product closure: COMPLETE

**KAFKA BASIC COMPLETE — FEATURE FREEZE AUTHORIZED.** An audit phase. It added no product
surface, no finding code, no failure class, no schema field, no dependency, no flag and no
production behaviour. Three test files and two documentation edits; `schemaVersion` stays 1,
the finding-code count stays 40, and all 23 SCRAM production files are byte-identical to their
pre-audit checksums.

#### What Kafka BASIC is

*What svcdoctor learns while attempting to behave as the Kafka client the operator asked it to
be, against one bootstrap endpoint, plus the transport reachability of the endpoints that
cluster advertised.*

| | |
|---|---|
| Target | one hostname that resolves, one port, whole-run and per-step budgets |
| Transport | DNS, TCP, and out-of-band TLS with a CA file, a server-name override or an explicit insecure opt-in |
| Protocol | ApiVersions, SaslHandshake, SaslAuthenticate, Metadata v1 with an empty topic list |
| Authentication | `PLAIN` and `SCRAM-SHA-256`, mechanism named explicitly by the operator, credential from a file or stdin, or no credential at all |
| Topology | DNS, TCP and TLS for every advertised broker endpoint — **credential-free, and nothing else** |
| Output | terminal and JSON from one report, shareable redaction, four independent Result axes, the exit-code contract |

#### What Kafka BASIC does not claim

Not cluster, broker, controller or quorum health. Not partition, ISR or replication state. Not
topic availability. Not producer, consumer or consumer-group health, and no lag. Not ACL
completeness. Not end-to-end produce or consume. No performance, latency or throughput
interpretation — stage duration is measurement only, and no latency finding exists or is
authorized.

`Kafka metadata obtained` means an authenticated, authorized Metadata v1 call succeeded
**against the one broker that answered**, and nothing more. `N of M advertised broker endpoints
reached` counts transport reachability from this vantage and ranks nothing.

#### What the audit found

The production code was correct on every invariant tested. **Every defect found was a missing
guard, not a missing behaviour**, which is the outcome a closure phase should have and is worth
recording as such.

1. **Three of the renderer's four `not measured` branches were unguarded.**
   `internal/render/terminal/topology.go`'s `classify` is a deliberate second implementation of
   ADR 0051's predicate — depguard denies a renderer the application, so they cannot share one —
   and only the *unmeasured connection* branch was asserted anywhere. An advertisement whose
   sweep never began, whose lookup was cut short, or whose resolved name nothing was attempted
   against could all have been counted as **unreached** with no test failing. All three are
   production-reachable: `MeasureAdvertised` breaks out of its loop the moment the context is
   done. The application-side twin was fully covered by `TestADR0051AcceptanceMatrix`
   throughout, so the two halves were guarded unequally rather than either being wrong.

2. **No test read the prose of any finding.** Rewriting `summaryCredentialsRejected` to *"The
   password configured for this Kafka endpoint is wrong"* passed the whole suite, goldens
   included — they simply re-rendered the new sentence. That is the exact overclaim the code's
   own documentation forbids, because Kafka returns one error code for a wrong secret, an
   unknown principal, a disabled account and a failing backend alike.
   `TestPeerVerificationIsNeverRenderedAsARejectedCredential` held the neighbouring direction
   at the output boundary and nothing held the source of the words.

3. **A prose guard that bans vocabulary is wrong, and failing on truthful text proved it.**
   The first version flagged `KAFKA_METADATA_NOT_COMPLETED`'s *"says nothing about topics,
   partitions, the controller, or whether the cluster is healthy"* — a sentence whose entire
   purpose is to refuse the claims it names. The rule had to become *per sentence, and a
   sentence that disclaims may name what it refuses*, with the disclaimer list itself pinned to
   phrases production prose actually uses.

4. **The README's capability claims were unguarded, and a line-level check was not enough.**
   A planted *"supported today, including Confluent Cloud, AWS MSK and Redpanda"* survived its
   first guard because the same README line ends *"No APM ... is required"*, and that
   neighbouring `No` read as a denial. Sentence granularity fixed it. The IP-literal boundary
   and the managed-compatibility backlog pointer are now both held by test, in the README and
   in both services' `--help`.

#### Mutation matrix

44 mutations applied to production source and restored exactly. **Zero survived**, after the
three test files above closed the five that did on the first pass. Every one of the thirty the
phase brief named was exercised, several split into finer variants where one mutation would
have proven less than it appeared to — the four `not measured` branches separately, the
renderer half and the application half separately, and a claim's summary, detail and
recommendation separately.

#### What this phase deliberately did not do

No IP-literal support, no managed or Redpanda compatibility, no `SCRAM-SHA-512`,
`OAUTHBEARER`, `GSSAPI`, `AWS_MSK_IAM` or mTLS, no generic SASL framework, no TLS trust
redesign, no certificate auto-discovery, no mechanism retry or fallback, no monitoring, no
performance diagnostics, and no change to the SCRAM implementation. The SCRAM server-final
strictness question was not touched; it remains the separate decision recorded below.

#### Still open after closure

These are recorded elsewhere in this document and are **not** closed by Phase 6.5:

- [x] IP literal target semantics — *closed afterwards by Phase 6.7 and ADR 0059.* The public
      contract is now that `--host` accepts a hostname or an IPv4/IPv6 address literal, and the
      guard that used to forbid that sentence inverted to require it:
      `TestTheDocsRecordIPLiteralSupport`, with `assertNoScopedIPv6Claim` taking over the
      forbidding side
- [x] TLS Trust & Identity Policy Review — system roots versus a supplied CA, trust
      replacement versus augmentation, internal and enterprise PKI, `ServerName` override, IP
      SAN verification, insecure mode, discovered-broker identity, mTLS. **No trust widening
      was decided or implied here.** *Closed afterwards by Phase 6.6 and ADR 0058, except
      mTLS, which that ADR deliberately leaves open*
- [ ] Managed-service protocol compatibility — Apache Kafka self-hosted is the only Kafka
      implementation svcdoctor has ever run against. Redpanda self-hosted, Redpanda Cloud,
      Confluent Cloud, AWS MSK SCRAM, AWS MSK IAM and Azure Event Hubs' Kafka API are all
      **unproven**, as are RDS, Aurora, Cloud SQL and Azure Database for PostgreSQL
- [ ] Redpanda compatibility specifically, as the most valuable single addition: it is the
      only item that tests the Kafka protocol against a non-Apache implementation
- [ ] SCRAM server-final strictness hardening — the four-row table below is pinned at
      first-wins behaviour and row three is the one worth revisiting

### Phase 6.7 — IP literal target semantics: COMPLETE

**Output: ADR 0059, production changes in seven packages, and six new test files.** Unlike
Phase 6.6 this was an implementation phase; the decision it rests on is the graph shape.

#### What was wrong, measured before the fix

`net.Resolver` returns a literal unchanged, so a literal target produced a **passing L1
measurement, with a duration, of an operation that never happened** — and a downstream rule
read it as the denominator of a claim about resolution:

```text
  ✓ PASS  DNS  78µs                     ← nothing was resolved
  ✗ ERROR  TCP_CONNECTION_NOT_ESTABLISHED  127.0.0.1:1
    Every address the hostname resolved to was tried...
                     ^^^^^^^^ there was no hostname
```

Two more were found in the same pass: `--host 2001:0db8:0:0:0:0:0:1` produced an anchor and a
connection subject naming two different spellings of one address, and `--host fe80::1%lo0`
named `[fe80::1%lo0]:1` while measuring `[fe80::1]:1`.

#### The decision

**Model A.** A literal records no `dns.lookup` node at all; the connections derive directly
from whatever caused the sweep. Models B (a `dns.lookup` in a new "not required" state), C (a
new `address.literal` step) and D (resolve anyway) were each rejected with reasons, in
ADR 0059 §4.

`net/netip` is the single classification *and* the single canonicalization, in
`internal/probe`, shared by L0 input normalization, the transport chain and the credential
key. Diagnosis cannot reach it — `depguard` denies the import — which is a forcing function:
a rule answers "did resolution happen here?" structurally or not at all.

#### Producer before owner

Two FAIL-producing stages became reachable in a new shape, and both were measured **unowned**
in the intermediate state — a literal TCP refusal produced `findings none` and `status OK`,
exactly the ADR 0054 failure. Both owners landed in the same change-set as the producer. The
generic TLS rule needed no change at all: its predicate is "a handshake directly under a
connection under this anchor", a sentence that never mentioned DNS.

#### What the mutation pass found

30 mutations, one equivalent mutant, **two real gaps**:

- **Verification silently relaxed for a literal survived the first pass.** Nothing stopped the
  chain from setting `InsecureSkipVerify` for an address target — the exact shortcut somebody
  reaches for when an IP fails to verify. Closed by a real handshake against a DNS-only
  certificate, plus its positive twin against a matching IP SAN.
- **The Kafka completeness predicate partially read a mixed shape.** A lookup with a stray
  sibling connection took the lookup branch and ignored the sibling. Found by a test written
  for this phase, against code written for this phase; now unresolved, because unrecognized
  must always err towards "the run is not finished".

The equivalent mutant is worth recording: removing the DNS rule's `hasLookup` guard changes
nothing, because a zero `Evidence` has `State` `UNKNOWN` and the rule requires `FAIL`. The
claim is unreachable for a literal by two independent mechanisms.

#### The Phase 6.5 guard, inverted

`TestTheREADMENeverClaimsIPLiteralSupport` and its `--help` sibling existed to stop the
capability being advertised while the semantics were undecided. They fired on the first
documentation edit of this phase, which is what they were for. They now require the sentence
they used to forbid, and `assertNoScopedIPv6Claim` took over the forbidding side — the guard
kept its shape and changed sides.

#### Unchanged

`schemaVersion` 1. 40 finding codes. 41 failure classes. 2 production `security.Reveal` call
sites. One credential-bearing Kafka authentication attempt per run. Zero `SecretFor`, zero
`Reveal` and zero SASL bytes to an advertised endpoint, literal or named. SCRAM untouched. No
new dependency, state, step or layer. The generic TCP finding gained a second *detail string*,
not a second code.

### Phase 6.6 — TLS trust and peer identity policy: COMPLETE

**A decision phase. Its output is ADR 0058 and three test files; it changed no production Go.**

It had to come before Phase 6.7, managed compatibility and release validation, because each of
those would otherwise have made its own trust-and-identity assumption and none of them would
have written it down.

#### What was decided

Almost every clause ratifies what the code already did — which is the outcome a review should
hope for and not the one it should assume. Each was checked against source, and the
externally-observable ones against the Go standard library rather than against its
documentation.

- **A supplied `--tls-ca-file` replaces the system trust store.** Model A. Augmentation was
  rejected because it cannot express *"only this issuer is acceptable here"* and because it
  silently passes a run configured with the **wrong** CA against any publicly-issued
  certificate — a diagnostic tool reporting success for a broken configuration.
- **Identity is `--host`, or `--tls-server-name` when given, and DNS resolution never changes
  it.** The identity analogue of ADR 0028's credential rule, for the same reason: resolution
  is attacker-influenceable.
- **The override drives verification *and* SNI**, because in Go they are one field. Splitting
  them is refused: it needs hand-written verification and no operator wants it.
- **IP SANs already verify with no flag**, and Go sends no SNI for an IP literal (RFC 6066
  forbids it). **CN is never an identity** and svcdoctor will add no exception to resurrect it.
- **Advertised Kafka brokers are verified against their own advertised names**, and the
  requested-target override does **not** propagate. One `--tls-server-name` cannot truthfully
  be the expected identity for both a bootstrap load balancer and three brokers with their own
  certificates — that is the *normal* managed topology — so it does not try. No new flag.
- **Discovery creates identity context; discovery never creates credential authority.** An
  advertised name necessarily becomes the expected peer identity for a connection to that
  endpoint, and that constrains what svcdoctor will accept *upward*. It authorizes nothing:
  zero credential bytes, zero SASL bytes, whatever certificate the endpoint presents.
- **`--tls-insecure` disables identity verification and nothing else.** It notably does not
  enable authentication — the credential-transport policy still refuses an unverified channel,
  so the flag makes authentication *not* happen.
- **Go's default TLS version bounds are kept**, measured at 1.2 minimum with 1.3 negotiated.
  Pinning stricter bounds would make the evidence describe svcdoctor rather than the target.
- **No new finding code.** The distinction that mattered — unknown CA versus name mismatch,
  which need different operator actions — is already `TLS_CHAIN_NOT_TRUSTED` and
  `TLS_IDENTITY_MISMATCH`.

#### What the phase found that the plan did not

1. **Two policy clauses were unguarded rather than unimplemented, and only mutation found
   them.** Making a supplied CA *append* to the system store passed the entire repository
   suite — the single most consequential clause of the trust policy, and every existing test
   covered what the loader refuses rather than what its pool contains. And a transport chain
   that ignored `--tls-server-name` outright also passed, while the PostgreSQL adapter's copy
   of the same rule *was* covered. The two halves of one policy were guarded unequally, and the
   uncovered half is the one every Kafka handshake goes through.

2. **A surviving mutation is a hypothesis, not a finding.** The mutation for *"keep trust,
   drop identity"* added a permissive `VerifyConnection` and survived — meaninglessly, because
   Go calls it **after** normal verification rather than instead of it. Measured, then
   rewritten as `InsecureSkipVerify` plus a chain-only `VerifyPeerCertificate`, which is the
   only reachable form and is exactly what the ADR forbids svcdoctor from writing. Reported as
   a guard gap it would have been wrong.

3. **The terminal never says peer verification was disabled.** `internal/render/terminal`
   contains no reference to `TLSVerificationDisabled` or `tls.verified`. A `--tls-insecure`
   run renders `✓ PASS  TLS  1.7ms` and `status OK`, with nothing anywhere in the document
   saying nobody checked who answered. Reproduced. The canonical JSON is correct, so it is a
   projection gap rather than a semantic one — which is why it is a recorded gap and not a
   STOP — but it is the same failure ADR 0048 §9 fixed for `OK`.

4. **PostgreSQL and Kafka disagree about inert TLS flags.** `--tls disable --tls-server-name x`
   is refused by Kafka and silently accepted by PostgreSQL, which then also reports
   `tlsVerificationDisabled: true` for a run that performed no handshake. Measured against the
   built binary. Both are PostgreSQL predating Kafka's reasoning; neither is a trust defect,
   and fixing the first turns a previously-accepted invocation into exit 2, which is a
   released-CLI change.

5. **TLS was never what blocked IP literals.** The layer already does the right thing for an
   address target. What Phase 6.7 must fix is DNS and graph shape.

#### Deliberately not done

No IP-literal execution, no managed or Redpanda validation, no mTLS, no trust-source flag, no
certificate auto-discovery, no revocation or pinning, no TLS version change, no renderer
change, and no SCRAM change — all 23 SCRAM production files byte-identical.

## Standing design items opened by Phase 6.2 — NOT STARTED

### SCRAM server-final strictness hardening

**Do not change this inside an extraction or refactor phase.** Phase 6.2 deliberately carried
PostgreSQL's released `verifyServerFinal` behaviour into `internal/sasl/scram` unaltered: the
**first** relevant attribute decides, and RFC 5802's trailing extensions after it are ignored.
That is what `v=<valid>,x=ignored` being accepted means, and it is pinned by test.

The shapes a stricter reader would refuse are currently resolved by first-wins and are pinned
at that behaviour rather than left undefined:

| Server-final | Today |
|---|---|
| `v=<valid>,v=<other>` | accepted — first wins |
| `e=invalid-proof,e=other` | rejected as a credential refusal — first wins |
| `v=<valid>,e=invalid-proof` | **accepted** — the verifier decides |
| `e=invalid-proof,v=<valid>` | rejected — the error decides |

Row three is the one worth revisiting: a peer sending both is malformed, and svcdoctor accepts
on the verifier. It is defensible — a matching verifier proves the peer holds `ServerKey` — and
no PostgreSQL or pgBouncer version observed sends either shape, so the change would be
invisible against real servers. That is exactly why it was **not** made during extraction: a
behaviour change invisible in integration is one nobody can validate, and ADR 0056 §8 forbids
altering PostgreSQL semantics during the move.

A separate decision must settle it, and must bring:

- [ ] RFC 5802 §5.1 strictness read against the `server-final-message` production
- [ ] what PostgreSQL, pgBouncer and Kafka actually send for each row above
- [ ] whether rejecting row three could refuse a real peer that today authenticates
- [ ] real integration evidence for both services before, not after, the change
- [ ] whether the two services may diverge here at all, given one shared core

### IP literal target semantics — CLOSED by ADR 0059 (Phase 6.7)

**PostgreSQL and Kafka support literal IPv4 and IPv6 targets as first-class input**, for the
requested target and for Kafka advertised broker endpoints.

Every item this section used to carry as open is decided and implemented:

- [x] how the requested-target anchor represents a literal — the canonical spelling, minted at
      L0 by `probe.ParseHost` before validation, so the anchor, the report envelope, the
      endpoint every node is scoped by and the credential key are one string
- [x] whether `dns.lookup` remains a graph stage for a literal — **it does not.** Model A:
      `target.requested -> tcp.connect`, no L1 node at all
- [x] how it records *resolution was not required* — by absence. No new state, no new step, no
      new attribute; `dns.lookup` names an operation and none of its states means "there was
      nothing to attempt"
- [x] **no DNS finding may be produced for a literal, in any state** — unreachable by two
      independent mechanisms, neither of which is a hostname heuristic, an EvidenceID parse or
      renderer hiding
- [x] IPv4 canonicalization — dotted decimal, IPv4-mapped IPv6 unmapped
- [x] IPv6 canonicalization — RFC 5952 via `netip.Addr.String`
- [x] zone identifiers — **refused**, explicitly and with the limitation named. Deferred, not
      rejected; see ADR 0059 §3
- [x] IPv6 bracket-and-port formatting everywhere a subject is rendered — `net.JoinHostPort`,
      pinned against `net.SplitHostPort` round-tripping
- [x] TLS verification against IP SANs — ADR 0058 §6, and now pinned end to end through the
      chain, including that verification is never relaxed for an address
- [x] interaction with `--tls-server-name` — connect by address, verify the name, send it in
      SNI; does not propagate to advertised brokers
- [x] a Kafka bootstrap target given as a literal
- [x] a Kafka **advertised** broker endpoint that is a literal — first-class, counted in the
      topology line, credential-free
- [x] redaction and pseudonymization of literals — already correct; now proved with canaries
      in both families, and four mutations against the path are caught
- [x] a deterministic graph shape — a literal and a name that resolves to it produce
      structurally different graphs *by design*, because one performed an L1 measurement and
      the other did not. What is deterministic is the spelling: one address, one identity
- [x] what run completeness means when there was nothing to resolve — ADR 0051's asymmetry,
      applied to the second shape

**The defect this closed, reproduced against the shipped binary before the fix**, is quoted in
ADR 0059's Context along with the two it found alongside it: a non-canonical IPv6 spelling
producing two endpoints in one report, and a zone identifier silently dropped so that
svcdoctor named one endpoint and measured another.

### The three ADR 0058 §14 gaps — CLOSED by ADR 0060 (Phase 6.8A)

**Settled.** Phase 6.7 measured the three and found them to be **one coupled defect with one
fix order**. Phase 6.8A reproduced all three against a release-shaped binary before changing
anything, then closed them in that order in one change-set.

- [x] **PostgreSQL accepted `--tls-ca-file`, `--tls-server-name` and `--tls-insecure` alongside
      `--tls disable`**, where Kafka refused all three. Now refused by both, from one shared
      `refuseInertTLSFlags`. This is a **released-CLI tightening**: three previously-accepted
      invocations now exit 2. The compatibility packet is ADR 0060 §5, and `--tls disable` on
      its own is unchanged.
- [x] **A plaintext PostgreSQL run reported `tlsVerificationDisabled: true`.** Now gated on the
      run's TLS *plan* in both composition roots, and guarded at `internal/app` rather than only
      at the CLI, because the CLI refusal makes the combination unreachable from the command
      line and a test there would pass for the wrong reason.
- [x] **The terminal never said verification was disabled.** It now says so twice: a header line
      for the run, read from `security.tlsVerificationDisabled`, and a note on each affected
      handshake row, read from that node's own `tls.verified`. Two readings on purpose, so a
      renderer inventing either from the other fails a test. **Not a finding** — the operator
      asked for it, and the status and exit code are unchanged.

The tripwires `TestPostgresStillAcceptsInertTLSFlags` and `TestKafkaStillRefusesInertTLSFlags`
existed so this could not drift without a decision. The decision was taken, so both were
removed and `internal/cli/tls_test.go` pins the contract they were guarding.

`SchemaVersion` stays **1**. The three verification states stay distinguishable across two
existing fields — `security.tlsVerificationDisabled` and the presence and `tls.verified` of a
handshake node — so no schema change was needed and none was made. No `FindingCode`,
`FailureClass`, flag or dependency was added.

**One guard gap was found and closed**, by the mutation that shortened `--tls-insecure`'s help
entry to `skip TLS verification`: true, insufficient, and invisible to every test. The
capability-claim audit in `internal/cli/docsclaims_test.go` now covers the entry's content for
both services, in the same spirit as the managed-provider guard beside it.

### TLS Trust & Identity Policy Review — CLOSED by ADR 0058 (Phase 6.6)

**Settled. The policy is ADR 0058; it is Accepted and it is a decision record, not an
implementation record.** Phase 6.6 changed no production Go.

- [x] system trust store versus an explicitly supplied CA — §2
- [x] internal AD / private PKI trust, including container and Kubernetes CA injection — §2;
      an injected CA is supplied through `--tls-ca-file` like any other
- [x] `--tls-ca-file`: **replacement**, not augmentation, and the reasoning is that
      augmentation cannot express "only this issuer is acceptable here" and silently passes a
      run configured with the wrong CA — §2
- [x] hostname verification and the `ServerName` override — §3, §4. The override drives
      verification **and** SNI, because in Go they are one field; it applies to the requested
      target only
- [x] **IP SAN verification** — §6. It already works, measured rather than assumed: an IP
      literal verifies against an IP SAN with no flag, and Go sends no SNI for one. **The TLS
      layer is therefore not what blocks IP literals**; the graph layer is
- [x] bootstrap versus advertised-endpoint `ServerName` — §7. Each advertised endpoint is
      verified against its own advertised name, and the requested-target override does not
      propagate. One flag could not truthfully serve both, and does not try
- [ ] client certificates / mTLS, and where that credential's authority lives — **still open,
      deliberately.** ADR 0058 §17 records that mTLS credential authority is *not* decided by
      the trust policy and must not be assumed to follow from it
- [x] managed-service CA bundles — §2 and §13; a provider bundle is an ordinary
      `--tls-ca-file`. Policy compatibility only; nothing is validated

This stayed separate from SCRAM secret authority (ADR 0055, ADR 0056), as required.

**Three product gaps were found and deferred to Phase 6.7** (ADR 0058 §14), none of them a
trust or identity defect:

- [ ] the terminal renderer never says peer verification was disabled — `✓ PASS TLS` with no
      annotation. The canonical JSON is correct, so this is a projection gap. Reproduced in
      ADR 0058 §14.1
- [ ] PostgreSQL accepts `--tls-ca-file`, `--tls-server-name` and `--tls-insecure` alongside
      `--tls disable`, where Kafka refuses all three. Fixing it turns a previously-accepted
      invocation into exit 2, which is a released-CLI change and needs its regression test
- [ ] a plaintext PostgreSQL run can report `tlsVerificationDisabled: true`, because the flag
      is not gated on a TLS plan existing. Kafka gates it correctly

**Two policy clauses turned out to be unguarded rather than unimplemented**, found by the
Phase 6.6 mutation matrix and closed by tests that changed no production behaviour: a supplied
CA appending to the system store passed the whole suite, and so did a transport chain that
ignored `--tls-server-name` outright. A third file pins Go's IP-SAN and CN behaviour, so
Phase 6.7 inherits a measured contract rather than a remembered one.

### Managed-service protocol compatibility — FIRST EVIDENCE TAKEN in Phase 6.8C/6.8D

The full matrix, with its evidence level per platform, is **`docs/COMPATIBILITY.md`**. It grades
by what was actually done rather than by what the vendor documents, and a guard in
`internal/cli/docsclaims_test.go` fails the build if a row claims a tested level for a platform
nobody ran against.

- [x] **Redpanda self-hosted** — Level 2, TESTED BASIC. `PLAIN` over TLS completes the whole
      journey against a real v25.1.9 instance. See below for the one thing that does not.
- [x] **Apache Kafka**, **PostgreSQL self-hosted** — Level 3, and already were
- [ ] Redpanda Cloud, Confluent Cloud, Azure Event Hubs' Kafka API — Level 1, documentation
      only. Each is protocol-plausible and **none has been run against**
- [ ] AWS RDS, Aurora, Cloud SQL, Azure Database for PostgreSQL — Level 1, documentation only.
      All four are ordinary PostgreSQL wire with a provider CA; Azure's roots are public and
      may need no `--tls-ca-file` at all
- [x] **AWS MSK SASL/SCRAM** — resolved and **negative**: MSK is `SCRAM-SHA-512` only, which
      svcdoctor does not implement. Not a validation gap, a mechanism gap
- [x] **AWS MSK IAM** — resolved and negative: needs `AWS_MSK_IAM` and AWS request signing

Redpanda was indeed the most valuable single addition, and for the reason predicted: it tested
the protocol against a non-Apache implementation and immediately found something the Apache
fixture never could.

#### Kafka SCRAM-SHA-256 fails against Redpanda — salt bound, deferred with a proven fix

**Redpanda issues a 130-byte SCRAM salt. `internal/sasl/scram` bounds a salt at 128 bytes.**
The server-first message is refused as malformed, `kafka.sasl_authenticate` fails with
`PROTOCOL_MALFORMED_RESPONSE`, and svcdoctor correctly declines to say the credential was
rejected. Measured five times; the size is fixed, not sampling noise.

Causality was **proven, not inferred**: raising the bound locally made the entire journey pass —
authentication, Metadata, advertised topology — and the change was then reverted and the SCRAM
freeze re-verified byte-for-byte.

**Not fixed in 6.8, deliberately.** Phase 6.8's stop conditions list *"SCRAM must change"* as a
STOP and the phase froze the shared core at entry. Both were right: `maxSaltLen` is a security
bound with a recorded rationale (ADR 0056 §7), and its stated justification — *"128 is eight
times the largest value in common use"* — is now known to be **factually wrong**, since RFC 5802
and RFC 7677 set no maximum and a mainstream implementation exceeds it.

**Reopen condition:** a phase that owns the shared SCRAM core, with its own security review. It
must decide what the bound protects against, what headroom covers implementations nobody has
measured, and whether the answer is a larger constant or a bound derived from the framing limit.
That is an ADR 0056 amendment.

- [ ] raise the SCRAM salt bound under security review, then re-measure Redpanda SCRAM-SHA-256
- [ ] a committed `test/integration/redpanda/` fixture — the remaining requirement for Level 3

AWS MSK IAM stays detect-and-explain only unless scope changes explicitly.

## Phase 7.1 — OCI container and Kubernetes runtime: COMPLETE

The image, the Kubernetes execution model and their guards are in the repository.
[ADR 0062](decisions/0062-oci-runtime-and-kubernetes-execution-model.md) is **Accepted;
runtime implemented, publication deferred to Phase 7.1-P**.

## Phase 7.1-R — OCI release contract review: COMPLETE

The four questions Phase 7.1 deferred are answered and normative in ADR 0062 §12–§20:
distroless pinned by tag+digest, `ghcr.io/hakanaltindag/svcdoctor` as the single canonical
registry, the Git semver tag as the sole version authority, required reproducibility scoped to
platform image manifests, CycloneDX SBOM, keyless cosign over the digest, and required build
provenance. `scripts/build-image.sh` is the official recipe and refuses a dirty tree or an
untagged HEAD.

Nothing is published. No `v0.3.0` tag exists.

## Phase 7.1-P — OCI publication pipeline: IMPLEMENTED, NEVER RUN

`.github/workflows/release-oci.yml` implements ADR 0062 §12–§21. It is triggered by a `v*`
tag push, derives every identity value from `scripts/build-image.sh --emit`, stages the image
under `sha-<commit>`, validates that digest, signs and verifies it, runs a native amd64 smoke,
and only then points `:vX.Y.Z` at the digest that passed. Job `needs` edges are the ordering
enforcement, and `internal/cli/releaseworkflow_test.go` fails the build if any of them is
removed.

**Nothing has been published.** The workflow has never executed, no image exists at GHCR, and
no `v0.3.0` tag exists.

### Before the first public release

- [ ] **Run the workflow for real.** Every mechanism was validated against a local registry
      and every step's logic was executed locally, but the pipeline has never run end to end.
      The first run is the test.
- [ ] **Native `linux/amd64` execution.** The workflow performs a pull-by-digest smoke on
      `ubuntu-latest`, which is native amd64; that closes Phase 7.1's emulation-only gap, but
      only when it actually runs. **This is the one outstanding evidence obligation.**
- [ ] **Confirm GHCR-specific behaviour**: `GITHUB_TOKEN` push permission, tag immutability,
      and package-to-repository association via `org.opencontainers.image.source`. The
      mechanisms were proven against a local registry; GHCR has not been asked.
- [ ] **Confirm cosign keyless signing and constrained verification.** Not exercised locally
      by design: signing with a throwaway key would have uploaded to the public Rekor
      transparency log, which is a publication.
- [ ] **Decide whether to enable the optional native arm64 smoke.** The job exists behind the
      repository variable `ENABLE_ARM64_SMOKE`; GitHub's arm64 runners are free for public
      repositories and not for private ones, and ADR 0062 requires no paid infrastructure.
- [ ] **Decide the GitHub Release relationship.** The workflow deliberately does not create a
      GitHub Release. If one is wanted, it should consume the digest this workflow already
      outputs rather than becoming a second release authority.

### Open evidence, not blockers

- [ ] **NetworkPolicy behaviour on a CNI that enforces it.** Still **unverified** — neither
      passed nor failed. Does not block publication: svcdoctor depends on no NetworkPolicy API.
- [ ] **Reproducibility across differing BuildKit versions, compression implementations and a
      registry round-trip.** Untested, and therefore not claimed.
- [ ] **Publishing development `:sha-<commit>` images.** The pipeline stages under one; whether
      such tags are ever kept deliberately is deferred.

Not wanted in this phase or the next: a Helm chart, an operator, a controller, a CRD, or any
Kubernetes API access from svcdoctor itself. svcdoctor is a bounded diagnostic worker that a
platform invokes; it does not become an agent.

## Phase 7.1-V — Remote OCI publication validation: IMPLEMENTED, NEVER RUN

Phase 7.1-P's checklist above is a list of things that cannot be proven without publishing.
This phase builds the machinery to close them **without releasing anything**: a
`workflow_dispatch` workflow that publishes exactly one reference,
`ghcr.io/hakanaltindag/svcdoctor:sha-<full commit>`, and no semver tag.

### The architectural decision: shared machinery, split authority

The obvious way to write a validation workflow is to copy the release workflow's build, scan,
SBOM, signing and smoke steps. That validates the copy. The two drift on the first edit that
touches only one of them, and the release path stays the one nobody ever exercised — which
would make this phase's evidence worthless for the purpose it exists to serve.

So the machinery was extracted into `.github/workflows/oci-stage-verify.yml`
(`on: workflow_call`), and **both** workflows call it:

```
release-oci.yml    tag trigger + strict semver + publish job  ─┐
                                                               ├─> oci-stage-verify.yml
validate-oci.yml   workflow_dispatch + dev version            ─┘
```

What the shared workflow may **not** do is decide identity. It is handed a version, a
revision, an epoch, a staging tag and the exact certificate identity it must produce; it
contains no `imagetools create`, no `git describe` and no reference to `GITHUB_REF_NAME`.
Public release identity stays with the caller, and only one caller is triggered by a tag.

### What changed in the accepted release pipeline

- **Staging tags now use the full 40-character commit SHA**, not `git rev-parse --short`. The
  staging tag is an immutable identity; an abbreviation can collide.
- **The staging tag is now enforced immutable.** Before pushing, the run asks GHCR whether
  `sha-<commit>` exists. If it does, its platform manifest digests are compared against a
  fresh reproducible build, and the run either reuses the identical index digest or **stops**.
  Comparison is at the platform level because ADR 0062 §16 establishes that the index digest
  is not reproducible while provenance is enabled. This is what makes a re-run safe.
- **The published platform manifests are checked against the reproducibility proof.** Before,
  "reproducible" and "published" were two claims in the same run with nothing joining them.
- **The CycloneDX SBOM is now attached to the digest** with `cosign attest --type cyclonedx`
  and proven bound with `cosign verify-attestation`. ADR 0062 §17 required an OCI referrer;
  the pipeline previously produced the SBOM only as an expiring CI artifact.
- **Provenance content is now checked, not just its attachment** — it must name this
  repository and the exact commit, and on a non-tag run it must contain no `refs/tags/vX.Y.Z`.
- **The certificate identity is computed by the caller** and passed in, so `cosign verify` is
  pinned to one identity rather than to a pattern. The certificate's real claims are printed
  before the gate runs, so the constraint can be corrected from evidence rather than widened
  until it passes.

None of this weakens release authority: `release-oci.yml` still triggers only on `v*`, still
validates `^v[0-9]+\.[0-9]+\.[0-9]+$`, still accepts no input, and still applies the semver
tag last, from a job the shared machinery cannot reach.

### Guards

`internal/cli/validateworkflow_test.go` and the reworked
`internal/cli/releaseworkflow_test.go` enforce all of the above. **All 42 mutations from the
phase's semver-safety, SHA-immutability, signing, attestation, remote-smoke, permission and
documentation matrices were applied to the real files and all 42 were caught.**

Nine escaped on the first pass, and every one escaped for the same reason: a whole-file
substring guard stayed green when a needle that appears in several steps was deleted from one
of them. The guards are now scoped to the step they are about, and count runtime references
rather than merely finding one.

### Result: PASSED, on real infrastructure

`validate-oci.yml` ran against GHCR on a GitHub-hosted runner. **Nothing was
released**: the only references it created are `sha-<commit>` and cosign's `.sig` and `.att`.

| | |
|---|---|
| Commit | `66e277f698c3bfd04df2ee3ce7a8688c70e57a4c` |
| Version | `0.0.0-dev+66e277f` |
| Staging tag | `sha-66e277f698c3bfd04df2ee3ce7a8688c70e57a4c` |
| Index digest | `sha256:eb2e9b6b31106121552b4ae3e7b80f78993853fa177b771db9c7faaba17e2a10` |
| `linux/amd64` | `sha256:7539216ccaa35da431a1df8d627514e25f36780e8acd9dd4c57bce9f5760ae34` |
| `linux/arm64` | `sha256:3dabdafb184236a8b6e52ae65b14f133cea6a9d74e62438d1e5198e76eac2bce` |

**Native `linux/amd64` — the one open evidence obligation from §21 — is closed.**
`Linux 6.17.0-1022-azure`, `uname -m` = `x86_64`, `RUNNER_ARCH` = `X64`, Docker
daemon `amd64`. No emulation. `--version` reported `0.0.0-dev+66e277f`; the image
ran read-only, `cap-drop=ALL`, `no-new-privileges`, as `65532:65532`; and the
pulled amd64 manifest equals the one the reproducibility job produced.

- **Reproducible.** Both platform digests IDENTICAL across two cold-cache builds,
  and the *published* manifests equal them.
- **GHCR.** `GITHUB_TOKEN` only. No PAT, no Docker Hub, no static registry secret.
  The package is **public** — anonymous pull-by-digest works with no credentials.
- **Index.** Exactly `linux/amd64` and `linux/arm64`, plus 2 `unknown/unknown`
  attestation manifests, each bound to its platform image by
  `vnd.docker.reference.digest`.
- **Vulnerabilities.** 0 CRITICAL, 0 HIGH — at the configured `HIGH,CRITICAL`
  threshold, with nothing suppressed (`.trivyignore` has no active entries).
  Lower severities were not enumerated, so this is not a "zero vulnerabilities"
  claim. Positive proof the scan analysed something: Trivy detected
  `debian 12.15` and scanned the `gobinary` target as well as OS packages.
- **SBOM.** CycloneDX, 10 components, attached with `cosign attest --type
  cyclonedx` and proven bound by `cosign verify-attestation`.
- **Provenance.** 60 806 bytes, names this repository and the exact commit, and
  contains **no** `refs/tags/vX.Y.Z` — checked, because a validation build that
  could describe itself as a release would look like evidence.
- **Keyless signing.** Certificate identity
  `https://github.com/hakanaltindag/svcdoctor/.github/workflows/oci-stage-verify.yml@refs/heads/feat/v0.3.0`,
  issuer `https://token.actions.githubusercontent.com`, trigger `workflow_dispatch`,
  10-minute Fulcio certificate. `cosign verify` passed against that exact identity
  plus the repository and commit — no regexp. Rekor log index `2579293960`.
- **Signature target.** `:sha256-eb2e9b6b….sig`, and the verified payload names
  `sha256:eb2e9b6b…` — the **index**, not a tag and not a platform manifest.
- **Native arm64** also passed, unconditionally in validation because this
  repository is public and the runners are free.

### Staging-tag immutability, measured both ways

Run 4 found `sha-66e277f...` **absent** (HTTP 404) and published it. Re-dispatching the
same workflow on the **same commit** found it present at
`sha256:eb2e9b6b...`, compared its platform manifests against a fresh cold-cache
rebuild, and reported:

```
staging tag sha-66e277f698c3bfd04df2ee3ce7a8688c70e57a4c already exists at sha256:eb2e9b6b...
published platform digests are identical to the rebuild — idempotent re-run
```

Nothing was pushed and **the index digest did not change**. That is the property that
makes recovery from a mid-run failure safe: a re-run either reuses the identical
artifact or stops, and it can never re-point an immutable identity at different bits.
Cosign referrers accumulate across re-runs — a second `.sig` layer under the same
`.sig` tag — which is expected and does not alter the image digest.

The mismatch branch is not exercised by any run, because producing it would require
the same source to build differently. It is covered by mutation instead: deleting the
comparison, ignoring a mismatch, or dropping the `sys.exit(1)` beneath it each fail
the build.

### What publishing found that review had not

Four defects, all in code written to build or observe the image, none in the
image. Each was invisible locally and would have fired on the release run.

1. **Neither source gate installed `golangci-lint`.** `make check` runs it and
   fails closed when it is missing; `ci.yml` installs it with an action that
   *runs* the linter rather than providing one for `make check` to call. Nothing
   local caught it because the binary is on a developer's PATH. **On
   `release-oci.yml` this would have failed the v0.3.0 tag push itself.**
2. **The certificate evidence dump read the wrong JSON key** — `cert` rather than
   `Cert`, whose value is an object carrying base64 DER, not PEM. Worse, being an
   ordinary step it took the job down and **skipped `cosign verify`**, the actual
   gate. It is now `continue-on-error`: a diagnostic that can abort a gate is a
   liability.
3. **The image content audit reported a package manager that is not there.**
   distroless `static-debian12` ships the directories `etc/dpkg` and
   `var/lib/dpkg` — package metadata, which is what lets a scanner enumerate base
   packages at all — and no dpkg binary. Executable-shaped findings now consider
   regular files only.
4. **The system-CA smoke was testing the runner's network, not the image.** It
   required *every* `tls.handshake` to PASS. `www.google.com` resolves to 8 A and
   8 AAAA records and GitHub-hosted runners have no IPv6 route, so the measured
   evidence is 8 × `tcp.connect` PASS → `tls.handshake` PASS
   (`trust_source=system`, `verified=true`) and 8 × `tcp.connect`
   FAIL/`TCP_NETWORK_UNREACHABLE` → `tls.handshake`
   SKIPPED/`EXEC_SKIPPED_PREREQUISITE_FAILED`.

   That last row is svcdoctor's own layered short-circuiting working correctly —
   a failed prerequisite yields SKIPPED, never a fabricated FAIL — and the check
   was wrong because it treated SKIPPED as failure. **It had reintroduced, in the
   workflow that validates svcdoctor, exactly the conflation svcdoctor exists to
   refuse: a local path failure is not proof about the target.** The gate now
   requires at least one verified handshake and keeps a negative control — no
   handshake may carry `TLS_UNKNOWN_AUTHORITY`, which is what a missing or
   incomplete CA bundle actually produces.

### Still open

- [ ] **Decide the SHA staging artifacts' retention.** Recommended: retain until
      v0.3.0 is released, so signatures and attestations stay inspectable and the
      release run can be compared against them. Deleting them orphans their
      referrers.
- [ ] **The image carries two SBOM formats.** `--sbom=true` makes BuildKit attach
      an **SPDX** attestation while the canonical CycloneDX SBOM is attached by
      cosign. Both are bound to the digest, by different mechanisms, and ADR 0062
      §17 says one format only. Not fixed here: `--sbom=false` changes the release
      build recipe, and changing it unreviewed during a validation phase is the
      failure mode this phase exists to avoid. Needs an ADR 0062 decision before
      v0.3.0.
- [ ] **`cosign triangulate` is deprecated** and is removed in cosign v4. The
      signature-target check uses it. The stronger half of that check — the
      verified payload naming the staged digest — does not.
- [ ] **`validate-oci.yml` is registered on `main`** because GitHub only lists a
      `workflow_dispatch` workflow from the default branch. The run executes the
      file from the dispatched ref. A run dispatched against `main` fails at
      identity derivation and can publish nothing, since the shared machinery is
      not on `main`.

## Phase 7.1-VR — OCI supply-chain closure: IMPLEMENTED, PENDING REMOTE RE-VALIDATION

Phase 7.1-V passed but left two release blockers. Both are closed here. Neither needed an
architectural change, and no product Go was touched.

### Blocker 1 — two SBOM formats

**Measured on the published index, not inferred from flags.** Each of the two BuildKit
attestation manifests carried two in-toto predicates:

| Predicate | Size | Producer |
|---|---|---|
| `https://spdx.dev/Document` | 636 461 B | BuildKit `--sbom=true` |
| `https://slsa.dev/provenance/v1` | 29 629 B | BuildKit `--provenance=mode=max` |

On top of those, cosign attached the CycloneDX SBOM to the index — three SBOM-bearing objects
in two formats at two levels.

`--sbom=false`; `--provenance=mode=max` unchanged. The canonical SBOM stays CycloneDX JSON,
generated explicitly and attached with `cosign attest --type cyclonedx` to the index digest.

The two flags **look like a matched pair and are not**: they shared an attestation manifest, so
disabling the first could plausibly have taken the second with it. Provenance answers a
different question and nothing else produces it. The pipeline now proves both facts in one
pass **against the registry** — it fetches every attestation manifest, reads its layers'
predicate types, and fails if any SPDX document is present *or* if no SLSA provenance is.
Checking the artifact rather than the build flags is the point: an upstream default change
would show up there and in no diff.

### Blocker 2 — `cosign triangulate`

Two findings, and the first was not in the brief.

**The pipeline was running cosign v2.5.2.** `sigstore/cosign-installer` was pinned by commit
SHA — which pins the *action*, not the binary it downloads — and v2.5.2 was that action's
default. A signing pipeline should not learn its own tool version from an upstream default.
`cosign-release` is now pinned explicitly at **v3.1.3** alongside the action SHA, and the
workflow prints `cosign version` so the log records what actually ran.

**cosign v4 is announced but unreleased.** The current line is v3.1.3; `cosign triangulate` is
*deprecated* in v3 and is removed when v4 ships. The `cosign-installer` **action** is at v4.1.2,
which is the action's version and not cosign's — its default `cosign-release` is v3.0.6. So
this pipeline does not run v4 and does not claim to; it claims not to depend on what v4
removes.

The removed check asked `cosign triangulate` where the signature lived and compared the answer
to a string built from the same digest — **a tautology** that could only fail if cosign changed
its formatting, over a storage-layout detail. What replaces it reads what the *verifier*
attested to: the signature payload's `docker-manifest-digest`, and the attestation's decoded
in-toto subject, predicate type (`https://cyclonedx.org/bom`) and `bomFormat`. It also confirms
the signed digest is the image *index* and not a platform manifest. Shapes were established by
running cosign v3.1.3 against the published Phase 7.1-V digest rather than guessed.

### What the cosign upgrade proved on contact

Under v2.5.2 a signed image gained `sha256-<digest>.sig` and `sha256-<digest>.att`. Under
v3.1.3 it gains **one** tag, `sha256-<digest>` with no suffix, holding an OCI index of two
`vnd.dev.sigstore.bundle.v0.3+json` artifacts. **The `.sig` tag the removed check asserted on
does not exist for v3-signed images**, while `cosign verify` and `cosign verify-attestation`
pass unchanged. Storage-layout assertions would have broken on a version bump; semantic
verification did not notice one.

The evidence parsers did break — the certificate dump read `Cert.Raw`, the Rekor step read
`cosign verify`'s `optional.Bundle`, and v3 moved both. They went silent, and because they
tolerate failure GitHub reported the steps as **successful**: `continue-on-error` sets a step's
conclusion to success while its outcome is failure. Both now handle both shapes and fail loudly
on an empty read, and neither can block a gate.

### Guards

`TestExactlyOneSBOMFormatIsPublished`, `TestNoDocumentClaimsTwoCanonicalSBOMFormats` and
`TestCosignIsPinnedAndForwardCompatible`. **All 38 Phase 7.1-VR mutations were caught, and the
42 Phase 7.1-V mutations still are.**

Six of the 38 escaped on the first pass, all the same failure as in Phase 7.1-V: a guard hunting
for a string that survives partial deletion. Replacing each condition with `if False:` left
every error message in place. The guards now assert on the **comparison expressions**
themselves.

### Result: PASSED, on real infrastructure

`validate-oci.yml` ran against GHCR on a GitHub-hosted runner and passed every gate.

| | |
|---|---|
| Commit | `cf3f12309010478f71378ea7db0087e3bdc9a8a7` |
| Staging tag | `sha-cf3f12309010478f71378ea7db0087e3bdc9a8a7` |
| Index digest | `sha256:b8ccb1ae36031b587bb9b248a167535622559ff925e61d18b29230521034cdc7` |
| `linux/amd64` | `sha256:7947aebfa160301d210de82d71e897a9de8979f7ec1b2a94f24011287471e96e` |
| `linux/arm64` | `sha256:1111cb04652f6bdae9957bf2f18d07c59bcc4765bb42f0ed06a1d472896f8a4c` |
| cosign | v3.1.3 |

**The one-SBOM proof, read back off the published image:** two attestation manifests, each
carrying exactly one predicate, `https://slsa.dev/provenance/v1`. No SPDX. Under the previous
configuration each carried two. The CycloneDX SBOM — 10 components, spec 1.7 — is attached by
cosign to the index digest and verifies against it.

- **The SBOM flag does not move the image.** Measured directly rather than inferred: the same
  source built with `--sbom=true` and `--sbom=false`, same VERSION, REVISION and epoch,
  produces **identical** platform digests, and those digests are the ones CI published. The
  attestation manifest *count* is unchanged too — SPDX was a layer *inside* the existing
  manifest, not a manifest of its own. Only the index digest moves, which §16 already permits.
- Reproducible: both platform digests IDENTICAL across two cold-cache builds.
- 0 CRITICAL, 0 HIGH, nothing suppressed; Trivy scanned `debian 12.15` and the `gobinary`.
- Provenance 60 458 bytes, names this repository and commit, contains no `refs/tags/vX.Y.Z`.
- Keyless sign, `cosign verify` and `cosign verify-attestation` all pass against the pinned
  identity. Rekor `2579323300` (signature) and `2579323317` (attestation).
- Native amd64: `x86_64`, `RUNNER_ARCH=X64`, Docker `amd64`. Native arm64 also passed.
- System CA: 8/16 handshakes verified — 8 IPv4 PASS, 8 IPv6
  `TCP_NETWORK_UNREACHABLE` → `SKIPPED`, correctly not read as a trust failure.
- Content audit: 1444 entries, 970 regular files, no shell, no package-manager executable.
- `:latest`, `:v0`, `:v0.3`, `:v0.3.0`, `:0.3.0` all absent. Git tags: `v0.1.0`, `v0.2.0`.

Four SHA staging artifacts are retained: `a4a835a`, `769371c` and `66e277f` record the
two-SBOM configuration, `9abdc6d` and `cf3f123` the corrected one.

### Still open
- [ ] **`validate-oci.yml` is registered on `main`** so GitHub lists the `workflow_dispatch`;
      the run executes the file from the dispatched ref. Operational debt, retained.
- [ ] **`release-oci.yml` has still never been triggered by a semver tag.** Its authority path
      is statically verified and the machinery it shares is remotely validated; the semver
      publication step itself runs first at v0.3.0.

## Phase 7 — Real-world Validation and Hardening: NOT STARTED

*Renumbered from Phase 6 in Phase 6.0c, when the Kafka BASIC sequence took the Phase 6
numbering the architecture review assigned it. The content is unchanged.*

- [ ] Run against at least 10 real connection/auth/TLS/topology incidents
- [ ] Measure first-broken-layer accuracy
- [ ] Measure false positives
- [ ] Validate shareable-report usefulness with a reader who did not run the tool
- [ ] Review whether the deferred decisions closed in Phases 2-4 held up in practice
- [ ] Decide whether to expand to a third service

A third service is not added until Kafka and PostgreSQL have produced real validation
signals. See `docs/SCOPE.md`.
