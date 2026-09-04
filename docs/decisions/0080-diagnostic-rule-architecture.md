# ADR 0080 — Diagnostic rule architecture, ownership and registration

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Refines:** ADR 0017 (the rule contract), ADR 0009 (explicit composition-root registration).
It keeps both and extends the first.

---

## 1. Context

Phase 10 asks rules to do more than map evidence to a finding: locate boundaries, weigh
competing explanations, compare siblings, and say what to measure next. The question is whether
`type Rule func(domain.Graph) []domain.Finding` survives that, and whether the generic engine
can stay free of service names while service knowledge grows.

Six architectures were evaluated.

| | Architecture | Type safety | Determinism | Testability | Debuggability | Extensibility | Explainability | Security | Schema impact | Mutation-testable | Fuzzable | Verdict |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Hard-coded generic diagnosis with service branches | high | high | medium | high | **very poor** | high | high | none | yes | n/a | **rejected** — the `if service == "kafka"` tree ADR 0009 exists to prevent |
| B | Service-owned imperative rules, generic engine | high | high | high | high | high | high | high | none | yes | yes | **selected**, extended |
| C | Declarative rule data (YAML/JSON rules) | **none** | high | medium | poor | high | medium | **poor** | new format | weakly | yes | rejected |
| D | Typed rule objects with metadata | high | high | high | high | high | high | high | none | yes | yes | partially adopted |
| E | Graph-pattern matching | medium | medium | medium | **poor** | high | **poor** | high | none | weakly | yes | rejected as primary |
| F | Hybrid: generic engine + service rules + shared predicates | high | high | high | high | high | high | high | none | yes | yes | **selected** |

**C is the one worth arguing about**, because "rules as data" sounds like the extensible answer.
It fails on the axes this project weights most: a YAML predicate language has no compiler, so a
typo in an attribute key is a silent no-match rather than a build failure; it cannot be
mutation-tested meaningfully, because mutating data produces data; it needs an interpreter,
which is new attack surface reachable from a file; and it would grow into a general-purpose
expression language — the "generic business-rule DSL" this project explicitly does not want.
Every rule svcdoctor has written so far needed arithmetic, string parsing or graph walking that
a small DSL would have had to grow anyway.

**E fails on explainability.** A pattern that matched is not an explanation a human can read,
and "why did this not fire" is the most common diagnostic-rule question.

## 2. Decision

### 2.1 The rule contract keeps its shape and gains one input

ADR 0017's function type stands. Phase 10 changes exactly one thing: a rule may need facts
about the run that are not in the graph — most importantly whether execution completed, so that
"not measured" is distinguishable from "measured and absent".

```go
// Illustrative. Not implemented in Phase 10.0.
type Rule func(RuleContext) []domain.Finding

type RuleContext struct {
    Graph      domain.Graph   // frozen, copy-on-read
    Vantage    domain.Vantage // where this was measured from
    Incomplete bool           // svcdoctor's own budget cut the measurement short
}
```

Three things are deliberately **absent**, and their absence is the security model:

- **no `context.Context`** — nothing to cancel, and its presence would invite I/O;
- **no `ServiceID`** — the engine never hands a rule a service name to branch on; a service rule
  is a rule that is only wired in for that service (ADR 0009);
- **no credential, no config, no filesystem, no clock.**

`RuleContext` is a struct rather than more parameters so the next addition is source-compatible.
ADR 0017's reasoning for excluding run metadata is narrowed rather than reversed: `Incomplete`
is admitted because a rule that cannot tell "not measured" from "measured absent" *will*
eventually state the RAB18 error, and `Vantage` is admitted because ADR 0012 makes reachability
claims vantage claims and a rule should be able to say so from data rather than from a constant.

### 2.2 Rules stay pure, and purity is enforced by the build

A rule is **deterministic, side-effect free, network-free, secret-free and allocation-bounded**.
It reads a frozen graph and returns findings. This is not a guideline; `.golangci.yml`'s
`diagnosis-is-pure` rule already denies `internal/probe`, `internal/adapter`, `internal/render`,
`internal/platform`, `internal/security`, `net`, `net/http`, `crypto/tls` and `os` to everything
under `internal/diagnosis/`.

**Phase 10.1 extends that deny list** with `math/rand`, `crypto/rand`, `time.Now` (via a
`forbidigo` pattern rather than a package ban, since `time` is needed for durations), `os/exec`
and `io/ioutil`. A rule that reads the clock is a rule whose output depends on when it ran.

### 2.3 Service knowledge lives with the service; the engine holds concepts

The boundary is drawn by **vocabulary**, and it is testable.

The generic engine and generic rules may know: endpoint, subject, layer, step, state, failure
class, dependency, blocked-by, discovery relationship, sibling set, boundary, confidence,
evidence reference.

They may **not** know: `advertised.listeners`, `pg_is_in_recovery()`, SQLSTATE values, AMQP
vhosts, RESP verbs, SASL mechanism names, or any service's finding codes.

```text
internal/diagnosis/            engine + generic rules + shared predicates   (no service names)
internal/diagnosis/transport/  generic DNS/TCP/TLS correlation             (exists)
internal/diagnosis/kafka/      Kafka rules and Kafka finding codes         (exists)
internal/diagnosis/postgres/   …                                           (exists)
internal/service/<svc>/        the service's vocabulary constants          (exists, leaf)
```

The test that keeps it true already has a precedent in this repository: a guard parses the
generic packages with `go/ast` and fails if a service name, a service finding-code prefix or an
import of a service diagnosis package appears. That is the same mechanism
`TestSharedCoreImportsAreExactlyTheAllowlist` uses for the SASL core.

### 2.4 Registration stays explicit, at the composition root

No `init()`, no reflection, no plugin discovery, no registry file. `internal/app` wires the
rules for a service exactly as it wires the service:

```go
// Illustrative.
engine := diagnosis.NewEngine(
    diag.FailureBoundary,              // generic
    transport.DNSResolutionFailed,     // generic
    kafka.AdvertisedEndpointUnreachable,
    kafka.DiscoveredEndpointBoundary,
)
```

**Duplicate rule identity is prevented at construction**, not at review: `NewEngine` rejects two
rules with the same `RuleID` and returns an error rather than silently keeping one. A rule set
is small, fixed and known at build time, so this is a wiring assertion and cannot fail at
runtime for an operator.

### 2.5 Rules gain an identity; findings do not carry it yet

Each rule has a stable `RuleID` — `"<owner>/<name>"`, for example `kafka/advertised-endpoint`
— used for duplicate detection, deterministic tie-breaking (ADR 0081 §2.6), test naming and
debugging.

**`RuleID` is not serialized into the report in the first implementation.** `run.svcdoctorVersion`
already identifies the producer, and a report that named rules would make every rule name a
public interface. Revisit when a support workflow actually needs to ask "which rule said this"
about a report from a version nobody has.

**No per-rule versioning.** A rule that changes its conclusion changes the product, and the
product version is the identity of that change. Per-rule semantic versions would be a second
compatibility surface with no consumer.

### 2.6 Import direction, and why cycles are structurally impossible

```text
domain  ←  diagnosis  ←  diagnosis/<service>
   ↑           ↑
service/<svc> ─┘                app  →  everything
```

`internal/diagnosis` imports **nothing from its own subpackages** — that is already true and is
why `internal/diagnosis/kafka` can have the `Rule` shape without importing the engine. Service
rule packages import `domain` and their own `service/<svc>` vocabulary. Only `internal/app`
knows about all of them. A cycle would require the engine to import a service, which the generic
vocabulary guard forbids.

### 2.7 A new service's diagnostic workflow

1. Add `internal/service/<svc>/` constants (steps, attribute keys) — a leaf.
2. The adapter produces evidence using them.
3. Add `internal/diagnosis/<svc>/`, importing only `domain` and that vocabulary.
4. Declare the service's finding codes **beside the rules that produce them**, never in a
   central catalogue (`docs/FINDINGS.md` §1).
5. Wire the rules in `internal/app`.
6. Add fixtures to the golden incident corpus, including forbidden claims.

Step 0 for a contributor is that **no generic file is edited**. If a change requires one, the
generic vocabulary is missing a concept and that is an ADR.

## 3. Consequences

**The existing four rule packages need no restructuring** — they already have this shape.
Phase 10.1's work is the shared predicate/query layer and `RuleContext`, not a rewrite.

**`Rule`'s signature changes**, which touches every existing rule's declaration. It is a
one-line mechanical change per rule and it is deliberate: the alternative is a second rule type,
and two contracts is how rule sets fragment.

**Rules cannot be added at runtime.** That is intended and is the same trade ADR 0009 made for
services.

**A rule remains debuggable by reading it.** A contributor asking "why did this not fire" reads
Go with a debugger, not a rule interpreter's trace.

## 4. Alternatives considered

**Keep `Rule func(domain.Graph)` unchanged.** Rejected. A rule that cannot see `Incomplete`
must either assume the run finished — which produces the RAB18 error class — or every rule must
re-derive completeness from the graph, which is worse and would drift between rules.

**Declarative rules (C).** Rejected — §1. Reconsider only if third-party rule authorship without
recompilation becomes a product requirement; at that point the security review is the work, not
the parser.

**Graph-pattern matching (E).** Rejected as the primary model, kept as an implementation
technique: a rule may use shared graph queries internally.

**A plugin ABI.** Rejected. It would mean loading foreign code into a process that holds
credentials, which no diagnostic convenience justifies.

**`RuleContext` carrying the whole `Report`.** Rejected as circular (ADR 0017): a report
contains the findings a rule produces.

## 5. Security implications

This record's central security property is that **the rule API is too small to be dangerous**.
A rule receives a frozen graph, a vantage and a boolean. It cannot dial, read a file, read the
environment, obtain a credential, or observe wall-clock time. The depguard rule makes the first
five build failures and §2.2 adds the sixth.

The residual risks are peer-controlled strings (ADR 0081 §2.7) and a rule panicking mid-report
(ADR 0083 §2.3), both handled there.

## 6. Compatibility implications

Internal only. `Rule` is not exported outside `internal/`, so its signature change is invisible
to consumers. No schema change; no CLI change.

## 7. Validation requirements

- Static guard: generic diagnosis packages contain no service name, no service finding-code
  prefix and no import of a service diagnosis package — parsed with `go/ast`, not grepped.
- Static guard: the extended `diagnosis-is-pure` deny list, plus a `forbidigo` pattern for
  `time.Now` inside `internal/diagnosis/`.
- Unit: `NewEngine` rejects duplicate `RuleID`s.
- Property: shuffling the rule slice produces byte-identical findings (already partially held by
  the engine's canonical sort; extended to cover tie-breaking).
- Mutation: make rule order affect output; remove the duplicate-ID check; let a generic rule
  read a service constant.
