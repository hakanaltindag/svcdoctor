# Phase 1 Handoff

For an engineer or agent starting Phase 2 with no prior context. It gives the
mental model and points at the authoritative documents; it does not replace them.

Conversation history is not authoritative. This repository is.

---

## 1. Product mental model

svcdoctor is a **client-vantage connection and topology diagnostic CLI**. It answers
"why can't I reach this service from here?" with evidence a reader can check, rather
than with a guess.

The architecture rests on one separation:

> **Probes collect facts. Adapters understand protocols. Diagnosis correlates
> evidence. Renderers explain results.**

Kafka and PostgreSQL are **adapters** — the first two vertical slices — not the
product. The product is the evidence-and-diagnosis machinery they plug into. A third
service must be addable without editing anything generic. Everything in Phase 1 is
service-neutral, and no file in it mentions a service except to forbid one.

A second principle governs growth:

> **Extensibility comes from stable boundaries, not from maximizing abstractions.**
> Concrete structs first. Interfaces only at real boundaries.

Phase 1 added **zero interfaces** and **zero runtime dependencies**.

---

## 2. Phase 1 result

**Implemented and tested:**

| Package | What it holds |
|---|---|
| `internal/security` | Masked `Secret`, endpoint-bound `Credential`, `ForwardingPolicy` |
| `internal/security/redaction` | `LOCAL_FULL` → `SHAREABLE_REDACTED` transformation |
| `internal/domain` | Primitives, `Evidence`, evidence DAG, `Finding`, `Report`, derived `Summary` |
| `internal/diagnosis` | `Rule` contract and deterministic `Engine` |

**Not implemented.** These directories exist and contain no Go code:
`internal/probe`, `internal/adapter`, `internal/render`, `internal/platform`,
`internal/app`, `cmd/svcdoctor`.

So there are no probes, no DNS/TCP/TLS execution, no adapters, no Kafka, no
PostgreSQL, no topology execution, no renderers, no CLI. **The tool cannot connect
to anything yet.**

That is the point of the phase: every layer is a pure value model or a pure
transformation over one, so the whole of Phase 1 is testable without a network.

---

## 3. End-to-end data model

```text
normalized facts        <- Phase 2+ produces these; today they are hand-built in tests
      |
      v
  Evidence              one canonical, service-neutral fact
      |
      v
  Graph (frozen)        the relationships between facts
      |
      v
  Diagnosis             pure function over the frozen graph
      |
      v
  Findings              conclusions, each pointing at exact evidence
      |
      v
  Report                assembles and validates; derives the summary
      |
      v
  Redaction             optional: produces the shareable form
```

Everything from `Evidence` rightwards exists and is tested. The left end — probes and
adapters producing normalized facts — is Phase 2 and later. Until then, tests
hand-craft evidence, which is exactly why the rest could be built and verified first.

---

## 4. Package map

### `internal/domain`

**Owns:** the service-neutral vocabulary and every canonical value. `State`, `Layer`,
`FailureClass`, `AttrValue`, `Vantage`, `EvidenceID`, `Step`, `AttributeKey`,
`Subject`, `Evidence`, `Graph`, `GraphBuilder`, `Finding` and its enumerations,
`Recommendation`, `Target`, `RunMetadata`, `ReportSecurity`, `Summary`, `Report`.

**Must not own:** any service concept, any I/O, any interpretation of what a failure
means, any exit-code policy, any redaction.

**Depends on:** the standard library only. It is a leaf: it imports no other
`internal` package, including `internal/security`.

### `internal/security`

**Owns:** secret safety primitives. `Secret` (masked through every output path),
`Credential` (bound to the endpoint it was resolved for), `Endpoint`,
`ForwardingPolicy`, and `Reveal`, the single audited escape hatch to plaintext.

**Must not own:** the report model, any domain type.

**Depends on:** the standard library only. Also a leaf.

### `internal/security/redaction`

**Owns:** the transformation from a local report to a shareable one.

**Must not own:** diagnosis, rendering, any I/O, any mutation of its input.

**Depends on:** `internal/domain` and the standard library. It is a *subpackage* of
`internal/security` on purpose: that keeps `internal/security` a leaf, so `domain`
may import it later for masked value types without creating a cycle (ADR 0018).

### `internal/diagnosis`

**Owns:** the `Rule` contract and the `Engine` that evaluates rules.

**Must not own:** any I/O, any service dispatch, report assembly, summary derivation,
exit-code mapping. It ships **no concrete rules yet** — see §13.

**Depends on:** `internal/domain` and the standard library.

---

## 5. Dependency direction

```text
                internal/diagnosis ──┐
                                     ├──> internal/domain ──> (stdlib)
   internal/security/redaction ──────┘

                internal/security ──────────────────────> (stdlib)

   Phase 2 boundary, not yet present:
       internal/probe ──> internal/domain
       internal/adapter ──> internal/probe, internal/domain
```

`internal/domain` and `internal/security` are both leaves. Nothing imports
`internal/diagnosis` or `internal/security/redaction`.

Enforced by `depguard` in `.golangci.yml`, not by convention. See §16.

---

## 6. Evidence lifecycle

**Normalized fact.** A probe or adapter observes something and normalizes it at its
own boundary. There is deliberately **no generic `domain.Observation` type**: an
observation is producer-shaped, so a generic one could only duplicate `Evidence` or
be a bag of arbitrary values, and ADR 0010 forbids the latter. The stage is real and
belongs to the producer.

**`Evidence`.** One canonical fact: identifier, subject, layer, step, state, failure
class, attributes, start time, duration. Immutable, built once through `NewEvidence`.
It cannot hold severity, confidence, a recommendation, a raw protocol object, an
error value or a secret — not by convention, but because no field or constructor
argument could carry them.

Two state rules are enforced at construction: `PASS` must carry no failure class, and
`FAIL` must carry one. `DEGRADED`, `UNKNOWN` and `SKIPPED` accept either, because all
three have legitimate classified and unclassified cases.

**`EvidenceID`.** Caller-supplied and validated, never generated here: the domain has
no clock and no random source, so it cannot produce something stable across runs. It
is a string so it is comparable and usable as a map key.

**Attributes.** `map[AttributeKey]AttrValue`, where `AttrValue` is a **closed tagged
union** over string, int, bool, duration, time and string list. There is no
constructor taking `any`, so a protocol response cannot reach evidence. Copied on
both input and output.

**`GraphBuilder` → `Freeze` → `Graph`.** Two separate concrete types, not one type
with a `frozen` flag. Diagnosis must be a pure function over finished evidence, and a
flag leaves that to discipline while two types make it a compile-time property.

**Relationships are graph-owned**, not fields on `Evidence`. A fact does not carry a
claim about the shape of the run, and one relationship gets one home.

**`BlockedBy` is distinct from a parent.** A parent is structure or derivation; a
blocked-by reference is the explicit causal explanation for why a `SKIPPED` step did
not run — what lets a report answer "why was TLS never checked?". Only `SKIPPED`
evidence may carry one, and the graph never infers it.

**The graph is deliberately dumb.** It validates its own structure — duplicate
identifiers, missing references, self edges, cycles — and nothing else. It does not
own endpoint equality or deduplication, topology recursion, visited sets, depth
limits, retries, scheduling, or short-circuit decisions. Cycle detection is graph
integrity; "do not probe this endpoint again" is execution policy, and the two look
alike and must not be conflated. See ADR 0013.

**Ordering** is lexical by `EvidenceID`, never insertion order, because insertion
order becomes nondeterministic once Phase 2 probes endpoints concurrently.

---

## 7. Diagnosis lifecycle

```text
frozen domain.Graph -> rules -> []domain.Finding
```

A rule is a **function**, not an interface:

```go
type Rule func(g domain.Graph) []domain.Finding
```

The graph is the only argument. `RunMetadata` and `Vantage` describe the run rather
than the evidence; `ServiceID` would hand the engine a name to branch on;
`Report` would be circular; a context has nothing to cancel. A rule needing
configuration is a closure over it. See ADR 0017.

**No error result.** A rule reads a frozen in-memory graph and has nothing
operational to fail at. A rule that would build an invalid `Finding` has a bug, and
must not respond by silently returning fewer findings.

**The engine** holds rules, evaluates them, and returns findings in the canonical
order of `domain.SortFindings` — the same order the report uses, from one shared
implementation. Wiring order does not reach the output.

**It does not deduplicate.** Deciding which of two similar findings to discard needs
a definition of finding identity that no document provides, and dropping one could
remove a real finding.

**No concrete rules ship yet**, and the reason is a missing policy, not missing work.
See §13.

---

## 8. Report lifecycle

`NewReport` takes run metadata, target, vantage, a **frozen** graph, findings and
security metadata. It assembles and validates; it does not diagnose.

**Cross-object integrity (ADR 0014).** Every evidence identifier referenced by every
finding must resolve to a node in the graph. One dangling reference fails the whole
construction — the finding is not dropped, the reference is not removed, the graph is
not touched. This is the only place the check can live: a `Finding` validates its own
identifiers but never takes a `Graph`, so the report is the first thing holding both
sides.

**The summary is derived, never supplied** (ADR 0015). If a caller could pass one, a
report could claim two findings while its summary counted five. Status is
`PROBLEMS_FOUND` when any finding is `ERROR` or `CRITICAL`, otherwise `OK` — exactly
the exit-code 0/1 boundary. **`OK` is not a claim of health**: a run where most checks
were skipped produces no errors, which is why the skipped and unknown counts sit
beside it.

**JSON is canonical and the report owns it** (ADR 0016). `Graph` has no standalone
encoding. Evidence is encoded as separate `nodes` and `relationships` sections, so
`Evidence.MarshalJSON` stays the single definition of a node and the wire format says
what ADR 0013 says.

**Deterministic.** Same content, same bytes, regardless of graph insertion order,
finding input order or map iteration.

**Vantage is first class** (ADR 0012). A connectivity finding is valid only from the
recorded vantage point. "broker-2 is unreachable" is a claim about a network position,
not about a cluster.

---

## 9. Security lifecycle

**`Secret`** holds plaintext behind a pointer and masks every output path: `String`,
`GoString`, `Format`, `MarshalJSON`, `MarshalText`. The pointer is load-bearing, not
an allocation choice — `%p` on a non-pointer struct reaches fmt's reflection path,
which reads unexported fields, and a real leak was found and fixed that way.

**`Credential`** is bound to its endpoint at construction and has no plain secret
accessor. The only way to read it is `SecretFor(endpoint)`, which requires naming the
endpoint the secret is about to be used against.

**`ForwardingPolicy`** has `deny` as its zero value: a policy never set, never parsed
or never threaded through a call chain refuses forwarding.

**`Reveal`** is a package-level function, not a method, so it does not appear in
completion on a `Secret` and every call is greppable as `security.Reveal(`. There are
currently **zero call sites** outside its own package and tests.

**Structural redaction** (ADR 0018) rebuilds a local report into a shareable one
through the ordinary domain constructors, so the result satisfies every invariant
including ADR 0014 and a re-derived summary. Principles:

- *Preserve correlation, remove identity.* Each distinct value maps to one stable
  pseudonym everywhere. Ports survive — a port says which protocol was expected.
- *Deterministic assignment.* Values are collected, sorted, then numbered. Pseudonyms
  are per-report, so two shared reports cannot be correlated through them.
- **Evidence identifiers are rewritten**, because the identifier grammar admits
  hostnames and the project's own identifiers embed endpoints. Every reference is
  remapped: node identity, parents, blocked-by, finding references.
- *Fail closed.* No partial report, and errors never name the value they protected.
  A residual scan over known values runs after rebuilding, so a report field added
  later without a transformation fails loudly instead of shipping an identifier.
- `SHAREABLE_REDACTED` can only be produced by a real transformation: the ordinary
  constructor still refuses the mode.

**Leak matrices** run under ordinary `go test ./...`: the secret matrix sweeps every
fmt verb, JSON, text, error and reflection path; the report matrix asserts hostname,
IP, vantage and secret canaries are absent from every field, the canonical JSON and
error strings. Both assert the **exact original value is absent**, never that output
merely looks masked.

**Known limit.** An attribute value carrying identity in a shape redaction cannot
recognize structurally, and appearing nowhere else in the report, is preserved. See
§13.

---

## 10. Locked architectural invariants

Phase 2 must not violate these.

**MUST**

- Keep `internal/domain` service-neutral and free of I/O.
- Normalize at the probe or adapter boundary; only normalized values cross into
  `Evidence`.
- Let generic transport own DNS, TCP and TLS, and hand a **live connection** to the
  adapter when a protocol handshake needs one.
- Build evidence through `NewEvidence` and graphs through `GraphBuilder` + `Freeze`.
- Give diagnosis a frozen `Graph`.
- Reference evidence from findings by identifier only.
- Keep output ordering deterministic regardless of concurrency.
- Register services explicitly at one composition root.
- Treat a local timeout as `UNKNOWN`, not as remote failure.
- Treat missing privilege as `SKIPPED` with the privilege recorded, never as healthy.
- Treat an unsupported capability as `UNKNOWN` — a gap in svcdoctor is not a defect in
  the target.
- Add a redaction transformation for any new report field that can carry identity.

**MUST NOT**

- Branch on a service name anywhere generic (`if kafka`, `switch service`).
- Add a central enumeration of every service's finding codes, attribute keys or steps.
- Put `map[string]any` or a raw protocol/runtime object into canonical evidence.
- Put relationships on `Evidence`, or endpoint dedup / topology depth / visited sets /
  scheduling / short-circuit decisions into `GraphBuilder`.
- Let an adapter call `net.Dial` or perform its own TLS handshake.
- Let diagnosis perform I/O, receive a `GraphBuilder`, or build a report or summary.
- Let a `Finding` hold a `Graph` or embedded `Evidence`, or map to an exit code.
- Let a caller supply a `Summary` or claim `SHAREABLE_REDACTED` without transforming.
- Express confidence as a number or percentage.
- Introduce an interface without a real second implementation.
- Add a runtime dependency without an explicit decision.

---

## 11. Accepted decisions

| Area | Decision | ADR |
|---|---|---|
| Layer order | L0 config → L1 DNS → L2 TCP → L3 TLS → **L4 protocol → L5 auth** → L6 topology, matching real wire order | 0007 |
| Kafka client | franz-go **low-level primitives**; no hidden retry or failover, which would destroy topology evidence | 0008 |
| Service wiring | Explicit composition-root registration; no `init()` magic, no reflection | 0009 |
| Evidence content | Normalized values only; no raw objects, no `map[string]any` | 0010 |
| CLI shape | Service subcommands; never infer service from a port | 0011 |
| Vantage | First-class report section, not run metadata | 0012 |
| Graph boundary | Evidence is a fact, the graph owns relationships, the graph is dumb | 0013 |
| Finding refs | Identifiers only; the report validates membership | 0014 |
| Summary | Derived by the report, never supplied | 0015 |
| Serialization | The report owns canonical JSON; the graph has none | 0016 |
| Rule contract | A function taking only the graph; no error result | 0017 |
| Redaction | Structural, deterministic, fail-closed, identifier-remapping | 0018 |

Full reasoning and rejected alternatives live in the ADRs. See
`docs/decisions/README.md` for the index.

---

## 12. Rejected alternatives

Each was considered and rejected for a recorded reason. Reopening one means
addressing that reason.

| Rejected | Why | ADR |
|---|---|---|
| A generic `domain.Observation` | Would duplicate `Evidence` or be a bag of arbitrary values; the stage belongs to the producer | 0010, package doc |
| One `Graph` type with a `frozen` flag | Mutation methods stay reachable, so diagnosis purity depends on discipline | 0013 |
| Relationships stored on `Evidence` | A fact would carry a claim about the run's shape, and one relationship would have two homes | 0013 |
| Graph-owned endpoint dedup / depth / visited | Requires knowing what an endpoint is; that is execution policy, and it would turn a container into an engine | 0013 |
| A central `FindingCode` enum | Every new service would edit shared core code — the same coupling as central branching | FINDINGS.md §1 |
| `Finding` depending on `Graph` | The value model would depend on its container; findings could not be built or tested without a graph | 0014 |
| Embedding `Evidence` inside `Finding` | Duplicates each fact and gives it two representations that can disagree | 0014 |
| Caller-supplied `Summary` | A report could contradict itself silently | 0015 |
| `Graph.MarshalJSON` | A second serialization contract with no consumer, to keep in step with the report's | 0016 |
| Parents attached to each encoded node | Contradicts ADR 0013 in the wire format and restates the evidence schema in a second place | 0016 |
| Numeric confidence | Implies a calibration svcdoctor cannot justify and invites arithmetic | REPORT_SCHEMA §7.3 |
| A `Rule` interface | A method set for one method, inviting growth; a closure handles configuration | 0017 |
| Redaction by rewriting serialized JSON | Domain values must be transformed before serialization; `regexp` is banned in that package | 0018 |
| Hash-based or cross-report pseudonyms | An unsalted hash re-enables correlation across shared reports; a salted one destroys byte stability | 0018 |
| Blanket-replacing prose | A shareable report with no summaries is not worth sharing | 0018 |
| Rewriting the identity part of an identifier path | Requires parsing a format the domain leaves opaque; a wrong parser leaks a hostname | 0018 |

---

## 13. Deferred and open decisions

Authoritative alongside `docs/BACKLOG.md`. None of these was accidentally resolved.

| Decision | Why deferred | Reconsider when |
|---|---|---|
| **`Origin`** (user-supplied vs discovered subject) | No consumer; topology does not exist. Adding it now creates a second record of how a subject entered the run, with no implementation to say which is authoritative | Topology orchestration exists (ADR 0013) |
| **Transport severity policy** | Severity is impact, and whether a failed lookup prevents correct use depends on whether the endpoint was user-supplied or discovered — that is `Origin` | Phase 2 produces real transport evidence (ADR 0017) |
| **Generic/service finding overlap** | Nothing says how a generic `TCP_CONNECTION_REFUSED` and a service `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` avoid describing one fact twice | The first service rules are written (ADR 0017) |
| **Service attribute-key ownership** and per-key sensitivity classification | Where service key constants live is unsettled; redaction's known limit depends on the same answer | The Kafka adapter demonstrates the real boundary |
| **Finding identity / duplicate semantics** | Defining when two findings are one conclusion is guesswork today | A real rule set produces duplicates (ADR 0017) |
| **`security.Reveal` restriction** | No adapter wire package exists to confine it to; inventing a path to point a lint rule at would be worse than waiting | Kafka wire packages exist |
| **Execution mode** in run metadata | No vocabulary is defined, and both plausible meanings already have owners: `vantage` and the summary | A real execution mode exists that neither expresses |
| **Exit-code mapping** | The contract is in `docs/SCOPE.md`; computing it belongs to the CLI | The CLI is built |
| **`affectedResources`, recommendation reference / risk** | Listed as "recommended when relevant"; nothing consumes them and no renderer exists | A renderer or catalog needs them |

Three of these — `Origin`, transport severity, generic/service overlap — converge on
the same question and will likely be answered together.

---

## 14. Phase 2 entry contract

**Phase 2 — Generic Transport Engine.**

**May implement:** DNS, TCP and TLS probes under `internal/probe`; per-probe
observation types normalized into `Evidence` at their own boundary; a transport chain;
**connection ownership transfer**, so a successfully established live connection can
be handed to a protocol adapter; short-circuit execution that records `SKIPPED`
evidence and produces `BlockedBy` relationships; and hermetic test seams
(`Resolver`, `Dialer`, `Handshaker`) — the one place an interface is justified,
because testability is a real second consumer and no test may depend on an
uncontrolled public service.

**Must not implement:** Kafka or PostgreSQL protocol, topology discovery, any
service-specific branching, renderers, CLI productization unless separately
scheduled, or a speculative plugin framework.

**Watch this boundary.** Connection ownership transfer is the invariant most easily
lost by accident: if a probe is written as "connect, measure, close", the adapter is
forced to open its own connection, and the rule that generic transport owns
DNS/TCP/TLS dies without a single test failing. Design the probe API so a live
connection can be handed over from the start.

Phase 2 will be the first real exercise of the `probe-is-service-agnostic` depguard
rule and the first code in the repository to use `net` and `crypto/tls`.

---

## 15. Phase 2 first decisions

Do not resolve these from first principles — resolve them against the real evidence
Phase 2 produces:

1. **Transport severity policy.** What severity does an evidenced transport failure
   carry, and does it depend on the endpoint's role?
2. **`Origin` / provenance.** Does a node need to record how its subject entered the
   run, or is the graph structure enough?
3. **Generic vs service finding overlap.** Which layer reports a failed endpoint when
   both a transport rule and a service rule could?

Answering 1 probably requires answering 2. Answering 2 reopens ADR 0013's deferral,
which is expected and allowed — the ADR names this exact condition.

---

## 16. Quality gates

```sh
make check    # fmt-check, test, vet, lint, build — the local and CI gate
```

Individually: `gofmt -l .`, `go test ./...`, `go vet ./...`,
`golangci-lint run ./...`, `CGO_ENABLED=0 go build ./...`, plus
`git diff --check`.

Linting uses **golangci-lint v2.13.1** (v2 config format), pinned in the `Makefile`,
`.golangci.yml` and `.github/workflows/ci.yml`.

**Architecture is enforced by `depguard`, not by convention.** Six rules encode the
dependency direction, and they fail the build rather than a review:

| Rule | Forbids |
|---|---|
| `diagnosis-is-pure` | probe, adapter, render, platform, `net`, `net/http`, `crypto/tls`, `os`, `os/exec`, random |
| `redaction-is-a-transformation` | the above plus diagnosis and **`regexp`** |
| `probe-is-service-agnostic` | adapter, diagnosis |
| `adapter-does-not-render` | render |
| `render-explains-only` | probe, adapter, diagnosis |
| `platform-collects-context` | adapter, probe, diagnosis |

Do not weaken these to make code compile. If a rule genuinely blocks correct work,
explain the conflict before changing it.

---

## 17. Context reset protocol

A fresh agent or engineer should read, in order:

1. `README.md` — what the project is and its current state
2. **This document**
3. `docs/ARCHITECTURE.md` — the authoritative architecture contract
4. The ADRs the work touches (`docs/decisions/README.md` is the index)
5. `docs/BACKLOG.md` — what is done, what is deferred, what is open
6. The implementation and its tests

If `CLAUDE.md`, `AGENTS.md` and `.claude/skills/` are present in the working
directory, read them first: they carry the agent guardrails and point back here.
They are **deliberately gitignored** — a local-only choice recorded in `.gitignore` —
so a fresh clone will not contain them. Everything needed to work safely is in the
tracked documents above; the agent files add convenience, not authority.

**Conversation history is not authoritative.** If a chat summary and this repository
disagree, the repository is right. If two repository documents disagree, report the
contradiction rather than choosing one silently.
