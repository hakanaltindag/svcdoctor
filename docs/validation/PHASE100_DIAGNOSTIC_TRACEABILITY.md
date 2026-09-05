# Phase 10.0 — Diagnostic intelligence traceability

Every load-bearing contract frozen by ADRs 0078–0083, with its owner, its future implementation
site, its future test, and whether it is security- or schema-relevant.

**Phase 10.0 implemented nothing; Phase 10.1A implemented part of this table.** The "package"
and "test" columns name where each contract lands, so that a later phase can be checked against
this table rather than against memory. The status column below says which are done.

## Phase 10.1A status

Implemented and enforced by a named test:

`DIAG-009` `DIAG-011` `DIAG-012` `DIAG-015` `DIAG-016` `DIAG-017` `DIAG-018` `DIAG-019`
`DIAG-020` `DIAG-021` `DIAG-022` `DIAG-023` `DIAG-024` `DIAG-025` `DIAG-026` `DIAG-027`
`DIAG-028` `DIAG-031` `DIAG-032` `DIAG-033` `DIAG-034` `DIAG-035` `DIAG-036` `DIAG-037`
`DIAG-039` `DIAG-041` `DIAG-042` `DIAG-047` `DIAG-048`

Implemented internally and **not emitted**, by the 10.1a/10.1b split in
`docs/design/DIAGNOSTIC_INTELLIGENCE.md` section P: `DIAG-013` (the boundary is computed and
tested against all six shapes; the finding code arrives in 10.1b, so the count is still 60).

Unchanged and still true without new work: `DIAG-001` `DIAG-002` `DIAG-003` `DIAG-010`
`DIAG-029` `DIAG-046`.

Belonging to a later phase: `DIAG-004` `DIAG-005` `DIAG-006` `DIAG-007` `DIAG-008` `DIAG-014`
`DIAG-030` `DIAG-038` `DIAG-040` `DIAG-043` `DIAG-044` `DIAG-045` — the renderer guards
(10.5), the golden incident corpus (10.6), and the claim-discipline properties that need a
service rule to hold them against (10.2 onward). `DIAG-005` and `DIAG-008` have generic
analogues that *are* held now — `P03`, `P04` and the boundary properties — and gain their
per-rule form when rules exist to test.

See `docs/validation/PHASE101A_DIAGNOSTIC_CORE_VALIDATION.md`, which also records three
deviations from the frozen records and why each was taken.

## Phase 10.1B status

Activation. Three concepts became live in production, and every remaining
Phase 10.1 row is now implemented and enforced:

`DIAG-013` the boundary is emitted as `DIAG_FAILURE_BOUNDARY`, `CONFIRMED`,
`INFO`, citing both halves — finding codes **60 → 61**, the one increase ADR
0078 §3 authorized · `DIAG-014` "ruled out" is rendered and no ruled-out finding
exists; a renderer guard proves it computes no boundary · `DIAG-025`, `DIAG-026`,
`DIAG-031` convergence merges, does not accumulate, and no canonical field is
chosen by rule order · `DIAG-005`, `DIAG-006`, `DIAG-007`, `DIAG-008` the
claim-discipline properties now have a production rule to hold them against ·
`DIAG-040` the false-positive policy as `FP01`-`FP05` · `DIAG-043`, `DIAG-044`,
`DIAG-045` the golden incident corpus, with `forbidden` first-class and a
synthetic-identity guard.

Still belonging to later phases: `DIAG-004` and `DIAG-030` (renderer presentation
of competing hypotheses, Phase 10.5), `DIAG-027`, `DIAG-033`, `DIAG-035`,
`DIAG-037`, `DIAG-038` — the recommendation and next-evidence rows, which stay
internal because Phase 10.1B emits no hypothesis and therefore no next-evidence.

**ADR 0081 §2.2a** was added as a clarification: semantic identity is a candidacy
test rather than a licence, and `Layer` and `Discriminator` are merge
preconditions. It changes no decision in §2.1 or §2.2. See
`docs/validation/PHASE101B_DIAGNOSTIC_ACTIVATION_VALIDATION.md` §3 for the
measured defect that prompted it and the full merge-compatibility matrix.

**Scope note.** Thirty-four requirements, not three hundred. A row earns its place by being a
contract someone could plausibly break; restating a type definition is not one.

| ID | Contract | ADR | Future package | Future test | Sec | Schema |
|---|---|---|---|---|---|---|
| DIAG-001 | Observation, evidence, finding, hypothesis and recommendation stay distinct concepts | 0078 §2.1 | `internal/domain` (unchanged) | corpus structure review | | |
| DIAG-002 | A hypothesis is a `Finding` with `kind: HYPOTHESIS`; no parallel type is created | 0078 §2.1 | `internal/domain` | `TestNoParallelHypothesisType` (static) | | ✅ none |
| DIAG-003 | Observation is never promoted into the domain | 0078 §2.1 | — | existing ADR 0010 guards | | |
| DIAG-004 | Fact and inference are distinguished by `kind`, owned by the domain, never by a renderer | 0078 §2.2 | `internal/render/*` | renderer guard: no `kind` derivation | | |
| DIAG-005 | A claim may not exceed what its cited evidence carries | 0078 §2.3 | `internal/diagnosis/**` | property: deleting a cited node changes the output | | |
| DIAG-006 | Mechanism may not be claimed without mechanism evidence | 0078 §2.3, 0083 §2.2 | `internal/diagnosis/**` | corpus `forbidden` claims | | |
| DIAG-007 | "Not measured", "not proven" and "proven false" stay three claims | 0078 §2.3 | `internal/diagnosis/**` | corpus: cancellation and budget scenarios | | |
| DIAG-008 | `UNKNOWN` never becomes `FAIL` through reasoning | 0078 §2.3 | `internal/diagnosis/**` | mutation: treat `UNKNOWN` as `FAIL` | | |
| DIAG-009 | Diagnosis performs no I/O; no hidden second collection pass | 0078 §2.6 | `.golangci.yml` | `diagnosis-is-pure` (exists) | ✅ | |
| DIAG-010 | An iterative measure-reason-measure mode is out of scope and needs its own ADR | 0078 §2.6 | — | — | | |
| DIAG-011 | The failure boundary is per subject, computed in the diagnosis layer | 0079 §2.1–2.2 | `internal/diagnosis` | unit: six boundary shapes | | |
| DIAG-012 | `SKIPPED`/`UNKNOWN` is neither half of a boundary | 0079 §2.2 | `internal/diagnosis` | property + mutation | | |
| DIAG-013 | The boundary is expressed as `DIAG_FAILURE_BOUNDARY`, `CONFIRMED`, `INFO`, citing both halves | 0079 §2.3 | `internal/diagnosis` | unit; finding-count guard 60 → 61 | | ✅ +1 code |
| DIAG-014 | "Ruled out" is rendered from the boundary and the graph; no ruled-out finding or field | 0079 §2.4 | `internal/render/*` | renderer guard | | ✅ none |
| DIAG-015 | Sibling comparison is generic; the engine never learns what a broker is | 0079 §2.6 | `internal/diagnosis` | `go/ast` vocabulary guard | | |
| DIAG-016 | Rules are service-owned imperative Go functions; no DSL, no plugin ABI, no pattern engine as the primary model | 0080 §1–2.1 | `internal/diagnosis/**` | architecture review; import guards | ✅ | |
| DIAG-017 | `RuleContext` carries graph, vantage and `Incomplete` — and nothing else | 0080 §2.1 | `internal/diagnosis` | static: `RuleContext` field set is exact | ✅ | |
| DIAG-018 | Rules are deterministic, side-effect free, network-free, secret-free, clock-free | 0080 §2.2 | `.golangci.yml` | extended `diagnosis-is-pure` + `forbidigo` on `time.Now` | ✅ | |
| DIAG-019 | Generic packages contain no service name, code prefix or service import | 0080 §2.3 | `internal/diagnosis` | `go/ast` guard | | |
| DIAG-020 | Registration is explicit at the composition root; no `init()`, reflection or discovery | 0080 §2.4 | `internal/app` | existing ADR 0009 guards | ✅ | |
| DIAG-021 | Duplicate `RuleID` is rejected at engine construction | 0080 §2.4 | `internal/diagnosis` | unit + mutation | | |
| DIAG-022 | `RuleID` exists internally, is not serialized, and rules are not individually versioned | 0080 §2.5 | `internal/diagnosis` | schema guard: no rule identity in JSON | | ✅ none |
| DIAG-023 | Adding a service edits no generic file | 0080 §2.7 | — | `go/ast` guard + review checklist | | |
| DIAG-024 | Semantic identity is `(Code, Subject)`; never prose similarity | 0081 §2.1 | `internal/diagnosis` | unit; mutation: dedupe by summary | | |
| DIAG-025 | Convergence merges by the frozen field table | 0081 §2.2 | `internal/diagnosis` | unit per field; property: commutative and associative | | |
| DIAG-026 | Confidence never accumulates on convergence | 0081 §2.2 | `internal/diagnosis` | mutation: accumulate | | |
| DIAG-027 | The confidence ladder: `HIGH` needs direct protocol authority or complete contrast | 0081 §2.3 | `internal/diagnosis/**` | unit per rule; corpus ceilings | | |
| DIAG-028 | Supporting, contradicting, missing and blocked evidence are four distinct relations | 0081 §2.4 | `internal/diagnosis` | property: absence never changes confidence | | |
| DIAG-029 | Contradiction is rule-internal; no `contradictedBy` field | 0081 §2.4 | `internal/domain` | schema guard | | ✅ none |
| DIAG-030 | Competing hypotheses coexist unranked; mutual exclusivity is not represented | 0081 §2.5 | `internal/diagnosis`, renderers | corpus KAFKA-A; renderer guard | | |
| DIAG-031 | Deterministic identities and ordering; merge ties break by `RuleID` | 0081 §2.6 | `internal/diagnosis` | property: shuffled rules → identical bytes | | |
| DIAG-032 | Peer-controlled text never becomes finding prose | 0081 §2.7 | `internal/diagnosis/**` | fuzz with hostile server strings | ✅ | |
| DIAG-033 | Two recommendation kinds in one type: `NEXT_EVIDENCE`, `REMEDIATION` | 0082 §2.1 | `internal/domain` | unit; schema additive | | ✅ +fields |
| DIAG-034 | Seven safety classes; `RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` unreachable by any rule | 0082 §2.2–2.3 | `internal/diagnosis/**` | `go/ast` guard; mutation: swap class | ✅ | |
| DIAG-035 | `REMEDIATION` requires `CONFIRMED` + `HIGH`; below that, `NEXT_EVIDENCE` | 0082 §2.3 | `internal/diagnosis` | unit + mutation | ✅ | |
| DIAG-036 | No recommendation is an executable command | 0082 §2.3 | `internal/domain` | validator unit; existing docs guard | ✅ | |
| DIAG-037 | Next-evidence declares collectability and safety; `SelfCollectable` may be false | 0082 §2.4 | `internal/domain` | unit; corpus PG-B | | ✅ +fields |
| DIAG-038 | A discriminator and a `NEXT_EVIDENCE` recommendation agree and co-occur | 0082 §2.5 | `internal/diagnosis` | property | | |
| DIAG-039 | Schema evolution is additive; `SchemaVersion` and `RunSchemaVersion` stay 1 | 0083 §2.1 | `internal/domain` | existing version guards, per phase | | ✅ |
| DIAG-040 | The false-positive policy: four rules, and refusal scenarios are acceptance criteria | 0083 §2.2 | `internal/diagnosis/**` | corpus `forbidden` claims | | |
| DIAG-041 | A rule panic discards that rule's output, marks the run incomplete, exits 4; no new exit code | 0083 §2.3 | `internal/diagnosis`, `internal/cli` | unit: panicking rule; exit-code guard | ✅ | |
| DIAG-042 | Invalid rule output is rejected, never repaired; canonical evidence is never mutated | 0083 §2.3 | `internal/diagnosis`, `internal/domain` | unit; existing ADR 0014 validation | ✅ | |
| DIAG-043 | The six-level validation pyramid is the release gate | 0083 §2.4 | `test/**`, `scripts/` | the gate itself | | |
| DIAG-044 | The golden corpus carries `forbidden` claims as first-class expectations | 0083 §2.5 | `test/corpus` | harness; mutation: delete a forbidden assertion | | |
| DIAG-045 | Corpus fixtures are synthetic or redacted; no captured real identity | 0083 §2.5 | `test/corpus` | leakage guard over fixtures | ✅ | |
| DIAG-046 | Declared intent stays out of configuration; observed ≠ violates-intent | 0083 §2.6 | `internal/fleet/config` | existing strict-schema guard | | ✅ none |
| DIAG-047 | No cross-target reasoning of any kind; no run-level finding code | 0083 §2.7 | `internal/fleet/run` | existing guard: no service name, no rule | | ✅ none |
| DIAG-048 | No LLM, remote AI, embedding or opaque classifier in the canonical path | design §O | — | dependency-count guard (2 modules) | ✅ | |

## Unresolved, and deliberately so

| Item | Why it is open | What would close it |
|---|---|---|
| Structured contradiction (`contradictedBy`) | no consumer; risks the negative-hypothesis explosion | a support workflow that needs to know why a hypothesis was *not* emitted |
| Rule identity in the report | `run.svcdoctorVersion` is sufficient today | debugging a report from a version nobody has |
| Declared intent (`expect:`) | would turn configuration into policy | a scenario where the observed/intended distinction is the whole diagnosis, with a closed vocabulary |
| Non-causal aggregate observations | one sentence from causal language | a design that can state "7 of 8 failed at DNS" with no shared-cause implication, tested |
| Iterative diagnostic mode | changes what a report means | an ADR defining a report that describes a search rather than a measurement |
| Hypothesis-to-hypothesis derivation | not needed by any exemplar; risks cycles and self-justification | a real scenario that cannot be expressed over evidence alone |

## Counts frozen by Phase 10.0

Unchanged, because 10.0 produced no Go code:

`SchemaVersion` **1** · `RunSchemaVersion` **1** · finding codes **60** · RabbitMQ codes **11** ·
failure classes **42** · `Reveal` **4** · `SecretFor` **4** · external modules **2**.

Authorized to change in 10.1, and nowhere else: finding codes **60 → 61**
(`DIAG_FAILURE_BOUNDARY`), and three additive fields inside `recommendations[]`.

**Re-proven unchanged at the end of Phase 10.1A.** Both authorized changes belong to 10.1b,
which is the half of the split that changes reports; 10.1a took neither.

**Phase 10.1B took the first and not the second.** Finding codes are **61**
(`DIAG_FAILURE_BOUNDARY`). The three additive `recommendations[]` fields were not
taken, because 10.1B emits no new recommendation and a field nothing populates is
a schema change with no consumer. Everything else is unchanged: `SchemaVersion`
**1** · `RunSchemaVersion` **1** · RabbitMQ codes **11** · failure classes **42** ·
`Reveal` **4** · `SecretFor` **4** · external modules **2**.
