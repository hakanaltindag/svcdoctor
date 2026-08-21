# Backlog

## Repository state

Repository and tooling bootstrap exists. The following packages are implemented, with zero
runtime dependencies:

- `internal/domain` — domain primitives, evidence, the immutable evidence DAG, findings and
  the canonical report
- `internal/security` — masked secret and endpoint-bound credential primitives
- `internal/security/redaction` — structural redaction into a shareable report
- `internal/diagnosis` — the `Rule` contract and the deterministic `Engine`
- `internal/probe` — the evidence identifier encoding every probe shares
- `internal/probe/dns` — the DNS probe, the first real I/O producer (Phase 2.1)
- `internal/probe/tcp` — the TCP probe and connection ownership (Phase 2.2)
- `internal/probe/tls` — the TLS probe, which consumes and produces that ownership (Phase 2.3)
- `internal/probe/transport` — the generic transport chain (Phase 2.4)

No Go code exists in any of the following, and nothing in them may be assumed implemented:

- `internal/adapter`
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
| 2 | Generic Transport Engine | **In progress** — 2.1 DNS, 2.2 TCP, 2.3 TLS and 2.4 chain complete |
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
| **Service attribute-key ownership** | Where service-specific key constants live is unsettled, and `internal/domain` must not grow a registry of them | The Kafka adapter demonstrates the real boundary, in Phase 3 |
| **Contract-package placement** for the adapter contract, the registry, the probe chain contract and CLI orchestration | Concrete structs first; interfaces only at real boundaries. A placement chosen before a real consumer is a guess | Each is forced by the implementation that needs it |
| **`security.Reveal` restriction** | No adapter wire package exists to confine it to, and inventing a path to point a lint rule at would be worse than waiting | Kafka wire packages exist, in Phase 3 |
| **Execution mode** in run metadata | No vocabulary is defined, and both plausible meanings already have owners: `vantage` and the summary | A real execution mode exists that neither already expresses |
| **`affectedResources`, recommendation reference / risk** | Listed as "recommended when relevant"; nothing consumes them and no renderer exists | A renderer or a finding catalog needs them |

The first three converge on the same question and will likely be answered together. See
`docs/ARCHITECTURE.md` section 18 and `docs/PHASE1_HANDOFF.md` sections 13 and 15.

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
- [ ] `bodyclose` — evaluated in 2.2 and 2.3 and still off: it checks HTTP response bodies
      and no code uses `net/http`. **Reopen when** something does
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
