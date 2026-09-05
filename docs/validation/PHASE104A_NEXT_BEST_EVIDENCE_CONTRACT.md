# Phase 10.4A — next-best evidence: architecture, contract and traceability

**Date:** 2026-09-05
**Baseline:** `1fbbd17b5ba570ab08562dfe906f082f2c174566`, `HEAD == origin/main`, tree clean,
`git describe` = `v0.4.0-7-g1fbbd17`.
**Record:** ADR 0086.
**Production code changed:** **none.** This is a contract phase.
**Freezes:** semantics — meaning, relations, safety, reporting, `Advice` → `Recommendation`
preservation, discriminator consistency, the no-ranking policy, the report-only iterative
boundary, service/core ownership, and the constraints binding any future set implementation.
**Does not freeze:** a hypothesis-set data structure, runtime set derivation, discriminator
identity representation, grouping execution order, or set renderer behaviour — all deferred to
Phase 10.4C, which opens only when a real competing pair exists (ADR 0086 §2.0).
**Release state:** uncommitted, unreleased. The most recent release tag is `v0.4.0`.

---

## 1. Baseline verified

| Fact | Value |
|---|---|
| HEAD | `1fbbd17` *feat(postgres): add diagnostic intelligence* |
| origin/main | `1fbbd17` — identical, 0 ahead / 0 behind |
| working tree at start | clean |
| `domain.SchemaVersion` | **1** |
| `domain.RunSchemaVersion` | **1** |
| finding codes | **65** (Kafka 15, PostgreSQL 21, RabbitMQ 11, Redis 9, `DIAG_` 1, transport 8 within services) |
| failure classes | **42** |
| production rules | **22** across six packages: generic 1, transport 3, Kafka 5, PostgreSQL 6, Redis 4, RabbitMQ 3 |
| exit codes | 5, precedence `3 > 2 > 4 > 1 > 0` |
| external modules | 2 |

Phase 10.3 PostgreSQL diagnostic intelligence is present and committed. Released `v0.4.0`
history was not modified or reinterpreted.

### 1.1 Architecture as found

- **Rule shape.** `type Rule func(ctx RuleContext) []domain.Finding`. Pure, no error result, no
  service name. `RuleContext` carries exactly three fields — `Graph`, `Vantage`, `Incomplete` —
  and a test fails if that field set changes.
- **Registration.** Explicit `RuleSet.Add(RuleID, Rule)` at a composition root; no `init()`
  magic, no reflection.
- **Advice.** `diagnosis.Advice` = `{kind, safety, action, rationale, selfCollectable}`, with
  `NewAdvice` (four structural refusals) and `AdmitAdvice` (the confidence gate).
- **Discriminator.** `Finding.Discriminator string`, `omitempty` in JSON, refused on a
  `CONFIRMED` finding by `domain.NewFinding`.
- **Basis.** `EvidenceBasis` with four disjoint relations and a five-check `Freeze(graph)`.
- **Confidence.** `AdmitConfidence(kind, authority, basis)`; `HIGH` on `AuthorityDirect` or on
  `AuthorityCompleteContrast`+`CONFIRMED`; contradiction caps at `LOW`; a missing observation
  makes complete contrast an *error*, not a downgrade.
- **Convergence.** Semantic identity `(Code, Subject)`; merge preconditions include `Layer`,
  `Summary`, `Detail` and `Discriminator`; `RuleID` reaches no merged field.
- **Failure boundary.** `DIAG_FAILURE_BOUNDARY`, one derived finding per subject.

---

## 2. Repository facts discovered

### 2.1 The reasoning vocabulary is largely unwired

Production producers, counted excluding tests and the defining file itself:

| Primitive | Producers | Note |
|---|---|---|
| `FindingKindHypothesis` | **2 codes** | both Kafka |
| `Finding.Discriminator` | **2 sites** | both Kafka |
| `NewBasis` / `.Support` | **1 site** | `kafka/topology.go` |
| `.Contradict` | **0** | |
| `.Block` | **0** | |
| `.Miss` | **0** | the input side of next-best evidence |
| `AdmitConfidence` | **1 site** | |
| `AuthorityDirect` as a value | **0** | named only in PostgreSQL comments |
| `AuthorityCompleteContrast` | **0** | |
| `NewAdvice` | 2 sites | via a duplicated `projectAdvice` |
| `SelfCollectable: true` | 2 sites | |
| `domain.Recommendation` extra fields | **0** | still `{action}` |

### 2.2 The three mismatches between the brief's terminology and the repository

1. **"Discriminator" is already a field, not a concept to introduce.** It has been in
   `domain.Finding` since before Phase 10 and is JSON-visible.
2. **"Next-best-evidence" already has an ADR.** ADR 0082 is titled for it. The brief's §5
   selection question is largely pre-answered, and the parts that are not are answered by
   refusal (ADR 0086 §2.4).
3. **"Information gain", "cost/priority" and "ranking" have no repository counterpart at all**,
   and three separate existing decisions refuse the shape they imply — confidence is never
   arithmetic (ADR 0081 §2.3), severity is never count-derived (ADR 0034 §13), and no scoring
   crosses a threshold anywhere in the tree.

### 2.3 The documentation defect found

ADR 0083 §2.1 says the report gains *"three fields inside `recommendations[]` (ADR 0082 §2.1)"*.
ADR 0082 §2.1's illustrative struct does show three, but §2.4 of the same record adds
`SelfCollectable`. **The correct number is four.** ADR 0086 §2.8 records the correction; ADR 0083
is not edited, because amending an Accepted record from a later phase is what the supersession
convention exists to avoid.

---

## 3. Primitives reusable as-is, and the ones that are insufficient

**Reusable, unchanged:** `Finding.Kind`, `Finding.Subject`, `Finding.Discriminator`,
`Finding.Confidence`, `Finding.EvidenceRefs`, `Finding.VantageDependent`; `EvidenceBasis` and its
four relations; `AdmitConfidence` and `Authority`; `Advice`, `AdviceKind`, `SafetyClass`,
`NewAdvice`, `AdmitAdvice`, `ValidateActionText`; `SemanticIdentity` and `Converge`;
`RuleContext.Incomplete`; `Result.Incomplete()`; the graph's `BlockedBy`; `domain.SortFindings`.

**Insufficient, and the whole of what is:**

| Gap | Consequence today |
|---|---|
| `domain.Recommendation` holds `action` alone | a consumer cannot distinguish `NEXT_EVIDENCE` from `REMEDIATION`, cannot see the safety class, cannot read the rationale, and cannot see `SelfCollectable`. The four facts that *are* next-best evidence are computed, validated, and then discarded at the report boundary |
| no `Discriminator` ↔ `NEXT_EVIDENCE` binding | ADR 0082 §2.5's guard was owed *"once Phase 10.1 lands"* and was never written. A hypothesis can carry an open question with no structured observation, or a structured observation contradicting its question |
| `BasisBuilder.Miss` has no producer | the relation that *defines* a discriminator is never recorded, so no test can check that a discriminator corresponds to a genuinely missing observation |
| `projectAdvice` duplicated in two service packages | acceptable today (ADR 0084 §9); it disappears once the fields exist |

**Not a gap: the absence of a hypothesis-set type.** §4.3 shows why.

---

## 4. Worked examples

### 4.1 Generic transport — TCP timeout

| | |
|---|---|
| **observed** | `tcp.connect` at `10.0.0.5:9092` is `FAIL` / `EXEC_LOCAL_TIMEOUT`; DNS `PASS`; TLS `SKIPPED`, `BlockedBy` the TCP node |
| **surviving explanations** | firewall `DROP`; host down; lossy path; listener bound elsewhere; the peer's own backlog |
| **why they cannot be distinguished** | a timeout is the absence of a reply. Nothing svcdoctor can observe *from this vantage* separates five silences |
| **distinguishing observation** | none svcdoctor can name. From another vantage the same probe would separate "reachable from there" from "reachable from nowhere", but that is a different run, not an observation |
| **can svcdoctor collect it** | no |
| **what is emitted** | one `CONFIRMED`, `vantageDependent` claim about what was observed, plus `DIAG_FAILURE_BOUNDARY` at TCP. **Zero hypotheses.** The TLS node is `SKIPPED`/blocked and is cited as neither support nor contradiction |
| **must NOT be claimed** | "the host is down", "the service is not running", "the port is not listening", "a firewall is blocking it", "routing is broken" — all four are forbidden by name in `test/diagnosis/falsepositive_test.go` |

**Result:** narrowing the claim removed the pair. This is the design working, not a gap.

### 4.2 Kafka — an advertised topology that may be unsuitable

| | |
|---|---|
| **observed** | Metadata `PASS`; advertised endpoints reached in three categories; at least one positively unreachable from this vantage |
| **surviving explanations** | the advertised addresses are wrong for this network; routing is absent; the listener is not exposed; a broker is down |
| **why they cannot be distinguished** | svcdoctor has no model of what addresses this network is expected to route, and did not measure routing or listener exposure |
| **distinguishing observation** | *"whether the advertised addresses are the ones a client on this network is expected to use to reach these brokers"* — the live `discriminatorUnsuitable` |
| **structured form** | `NEXT_EVIDENCE` / `COMPARE`, `SelfCollectable: false`, with a rationale |
| **what reaches the report today** | the discriminator, and the recommendation's **action text only**. Not its kind, not its safety class, not its rationale, not `SelfCollectable` |
| **what is emitted** | one `HYPOTHESIS`, `WARN`, `MEDIUM` (`HIGH` unreachable — `AuthorityNone`) |
| **must NOT be claimed** | that the cluster is unhealthy; that a broker is down; that `advertised.listeners` is misconfigured; that a loopback or RFC 1918 advertisement is wrong per se (ADR 0084 refuses address-shape heuristics) |

**This is a lone hypothesis, not a set**, and it is nonetheless exactly where next-best evidence
pays: the value is the four discarded fields on a single finding, not a partition. It is the
reason Phase 10.4B is worth doing with no set machinery at all.

### 4.3 PostgreSQL — `53300`, and the pair that was dissolved rather than reported

| | |
|---|---|
| **observed** | authentication `PASS`; session `FAIL` / `RESOURCE_LIMIT_REACHED`; SQLSTATE `53300` |
| **candidate pair** | *the limit is enforced at this endpoint* vs *a pooler in front enforced its own* |
| **why undistinguishable** | a pooler collapses every SQLSTATE to `08P01`, so the response cannot say where the limit lives; and PostgreSQL applies several admission limits and names none |
| **what ADR 0085 §3.2 did instead** | narrowed the claim to *this endpoint refused this session at a limit that applied to it*, `CONFIRMED`, `ERROR`, `HIGH` on direct authority, stating explicitly that which limit was reached is not in the response |
| **next evidence** | *"Identify the connection limits applicable to this attempted session and compare their current usage with their configured limits"*, `NEXT_EVIDENCE`/`COMPARE`, `SelfCollectable: false` — BASIC executes no SQL |
| **must NOT be claimed** | which limit; global `max_connections` exhaustion; no slot available; a leak; a pool sized wrongly; a spike; memory pressure; persistence; where the limit is enforced; any recommendation to raise a limit |

**PostgreSQL emits no hypothesis at all**, and Phase 10.3 kept it that way deliberately.

### 4.4 Convergence: explicit merge and non-merge cases

| # | Input | Outcome | Why |
|---|---|---|---|
| 1 | two `KAFKA_AUTH_MECHANISM_NOT_OFFERED` at one endpoint from two protocol steps, byte-identical summary/detail/recommendations | **merge** into one finding citing both nodes | every parsed field already agrees |
| 2 | two `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` at one endpoint naming brokers 2 and 7 | **no merge** | `Summary` differs; merging would publish one broker's sentence over both brokers' evidence (Phase 10.2A defect 1) |
| 3 | `CONFIRMED` and `HYPOTHESIS` at one endpoint for one code | **no merge** | prose differs; absorbing would promote the hypothesis and drop its discriminator (Phase 10.2A defect 3) |
| 4 | two hypotheses, one code, one subject, **different discriminators** | **no merge** | two questions are not one question. This is a *precondition that refuses*, which is safe under prose drift — the result is two findings each stating what its rule stated |
| 5 | two hypotheses, one code, one subject, one discriminator set and one empty | **merge**, carrying the one question anybody asked | silence is not a conflicting second question |
| 6 | two hypotheses, **different codes**, one subject, same open question | **no merge**; whether it is *a set* is Phase 10.4C's question | different codes ⇒ different semantic identity ⇒ never a convergence candidate. Under the §2.2a candidate this would be a two-member set, and the mechanisms would be disjoint — but that is the candidate's property to prove (NBE-037), not a fact of the tree today |
| 7 | case 6 under an incomplete run | **the same set, unchanged** | an incomplete run may not remove a member to make a set look decisive, and may not raise a confidence |
| 8 | case 6 with the rules renamed | **byte-identical output and the same set** | `RuleID` reaches neither mechanism |

**Case 6 has no producer today**, and no mechanism decides it. It is written as the shape the
first producer will present, and as the case Phase 10.4C must resolve.

---

## 5. Requirement register — NBE-001 … NBE-044

Every requirement carries a **tier**, and the tier is the correction this register received:

| Tier | Meaning |
|---|---|
| **F** | **Frozen in 10.4A.** A semantic contract, true today or binding on every future phase |
| **B** | **Phase 10.4B.** Structured next-evidence plumbing. No set machinery |
| **C** | **Phase 10.4C, deferred constraint.** Binds whoever implements set derivation, *if* a real competing pair ever makes one necessary. **Nothing here licenses 10.4B to build it** |

Owner: **CORE** = `internal/diagnosis`, **DOM** = `internal/domain`, **SVC** = a service rule
package, **RND** = a renderer, **SEC** = a `test/security` guard.

### 5.1 Hypothesis eligibility — semantics

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-001 | **F** | Only `HYPOTHESIS` findings may be indistinguishable-set members | 0086 §2.2 | 10.4C: a `CONFIRMED` finding is never a member | CORE |
| NBE-002 | **F** | A `CONFIRMED` finding may not carry a discriminator | 0086 §2.2 | already enforced by `domain.NewFinding`; regression | DOM |
| NBE-003 | **F** | Members must share a `Subject` | 0086 §2.2 | 10.4C | CORE |
| NBE-004 | **F** | Members need **not** share a `Layer` or a failure boundary | 0086 §2.2 | 10.4C | CORE |
| NBE-005 | **C** | Whether members must come from different codes is part of the §2.2a decision, not frozen | 0086 §2.2a, §2.9 | 10.4C | CORE |
| NBE-006 | **F** | Comparison across rules never reads `RuleID` | 0086 §2.2 | existing rename-invariance property; extended in 10.4C | CORE |
| NBE-007 | **F** | Confidence is never an eligibility filter | 0086 §2.2 | 10.4C | CORE |
| NBE-008 | **F** | A hypothesis may not reference another finding | 0086 §2.2, ADR 0014 | structural today; regression | DOM |

### 5.2 Identity mechanism — deferred

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-009 | **F** | Fuzzy or semantic discriminator matching is forbidden **permanently** | 0086 §2.2a | 10.4C mutation: similarity matching must be caught | CORE |
| NBE-009a | **C** | The identity mechanism is **not frozen**. 10.4C decides among exact equality (A), a typed key (B), or the missing-`Step` (C) | 0086 §2.2a | the 10.4C ADR itself | CORE |
| NBE-009b | **F** | No `DiscriminatorID` or equivalent field is added before a producer exists | 0086 §2.2a | `SEC`: field inventory of `domain.Finding` unchanged | SEC |
| NBE-009c | **F** | Whatever mechanism is chosen partitions by a decision procedure — never a similarity, distance or threshold | 0086 §2.2, §2.2a | 10.4C property | CORE |
| NBE-010 | **C** | A set is derived and never stored; no new report field or array | 0086 §2.3 | `SEC`: report field inventory unchanged (enforceable **now**) | SEC |
| NBE-011 | **C** | Set derivation is order-independent | 0086 §2.3 | 10.4C property | CORE |
| NBE-012 | **C** | Set derivation runs after convergence | 0086 §2.3 | 10.4C | CORE |
| NBE-013 | **C** | A lone hypothesis is not reported as a set | 0086 §2.2 | 10.4C golden incident | CORE |
| NBE-014 | **C** | Two open questions on one subject yield two sets, both reported | 0086 §2.4 | 10.4C | CORE |

### 5.3 Contradiction, missing, blocked, unknown, incomplete — all frozen

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-015 | **F** | Absence of evidence never becomes contradiction | 0086 §2.1 | `AdmitConfidence`; regression | CORE |
| NBE-016 | **F** | `UNKNOWN` is never evidence against a hypothesis | 0086 §2.1 | per-service boundary tests | SVC |
| NBE-017 | **F** | Blocked evidence is cited as neither support nor contradiction | 0086 §2.1 | `BasisBuilder.Freeze` checks 3–4; regression | CORE |
| NBE-018 | **F** | A blocked step named as the open question states that its blocker owns the failure | 0086 §2.2 | `docs/FINDINGS.md` §3.1 rule 11; per-rule unit | SVC |
| NBE-019 | **C** | An incomplete run never removes a set member | 0086 §2.2 | 10.4C monotonicity property | CORE |
| NBE-020 | **F** | An incomplete run never raises a finding's confidence | 0086 §2.2 | existing monotonicity properties | CORE |

### 5.4 Discriminator ownership and the binding invariant — the heart of 10.4B

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-021 | **B** | A `HYPOTHESIS` with a discriminator carries ≥1 `NEXT_EVIDENCE` recommendation | ADR 0082 §2.5, 0086 §2.10 | `SEC` guard over every production hypothesis | SEC |
| NBE-022 | **B** | A `NEXT_EVIDENCE` recommendation on a hypothesis must not contradict its discriminator | 0086 §2.10 | unit per producing rule | SVC |
| NBE-023 | **F** | The discriminator sentence is owned by the service rule, never the core | 0086 §2.10 | `SEC`: no discriminator literal in `internal/diagnosis/*.go` | SEC |
| NBE-024 | **F** | The core never branches on a service name | 0086 §2.10 | existing generic-core scan | SEC |

### 5.5 Selection and ranking — frozen as refusals

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-025 | **F** | No ranking function exists at any tier | 0086 §2.4 | `SEC`: no comparator over recommendations or hypotheses | SEC |
| NBE-026 | **F** | `SelfCollectable` is never a sort key | 0086 §2.4 | `SEC` + 10.4B mutation | SEC |
| NBE-027 | **F** | No cost model, no priority number, no threshold | 0086 §2.4–2.5 | `SEC` | SEC |
| NBE-028 | **C** | Set cardinality may be displayed and may order nothing | 0086 §2.5 | 10.4C mutation | CORE/RND |
| NBE-029 | **F** | No probability, entropy, Bayesian term or learned model anywhere | 0086 §2.5 | `SEC` vocabulary scan | SEC |

### 5.6 Safety and collection capability

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-030 | **B** | A `NEXT_EVIDENCE` recommendation is `OBSERVE`, `VERIFY` or `COMPARE` | 0086 §2.6 | `NewAdvice` today; **reachable through the report** after 10.4B | CORE |
| NBE-031 | **F** | `RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` stay unreachable | 0086 §2.6 | `Producible()`; regression | CORE |
| NBE-032 | **F** | `SelfCollectable: true` authorizes no collection | 0086 §2.6–2.7 | `SEC`: nothing consumes it as an instruction | SEC |
| NBE-033 | **F** | No typed credential-capability category exists | 0086 §2.6 | `SEC` enum inventory | SEC |
| NBE-034 | **F** | No recommendation is an executable command | 0086 §2.6 | `ValidateActionText`; regression | CORE |
| NBE-035 | **F** | Nothing here creates a new secret authority | 0086 §5 | `Reveal`/`SecretFor` call-site counts | SEC |

### 5.7 Convergence, schema, renderer

| ID | Tier | Requirement | Design | Planned test | Owner |
|---|---|---|---|---|---|
| NBE-036 | **F** | A merge never erases a discriminator, promotes a hypothesis, or picks prose by `RuleID` | 0086 §2.9 | existing convergence suite | CORE |
| NBE-037 | **C** | A future set mechanism must be **provably** disjoint from convergence, or provably order-independent with respect to it — demonstrated, not argued | 0086 §2.9 | 10.4C property over both mechanisms | CORE |
| NBE-038 | **F** | `SchemaVersion` and `RunSchemaVersion` stay 1 | 0086 §2.8, §6 below | existing frozen-count guards | SEC |
| NBE-039 | **B** | `recommendations[]` gains exactly four named fields; no existing field is repurposed and `action` stays required | 0086 §2.8 | golden JSON diff limited to the four | DOM |
| NBE-040 | **B** | `rationale` is redacted like every other prose field | 0086 §2.8, §5 | redaction test | DOM |
| NBE-041 | **C** | A renderer groups by the chosen mechanism only; it computes, chooses and infers nothing | 0086 §2.8, §2.10 | 10.4C renderer test | RND |
| NBE-042 | **F** | No finding code is added for a set | 0086 §2.11 | frozen count stays 65 | SEC |
| NBE-043 | **B** | `docs/REPORT_SCHEMA.md` and `docs/OUTPUT.md` gain the four fields — the debt ADR 0082 §6 incurred when Phase 10.1 landed without them | 0086 §2.8 | docs-claims drift guard | DOM |
| NBE-044 | **B** | **No generic hypothesis-set grouping abstraction exists after 10.4B** | 0086 §2.11 | `SEC`: the absence is asserted, because this is what gets added by accident | SEC |

**Count: 44** (42 original, two added by this correction: NBE-043 and NBE-044; NBE-009 split into
009 / 009a / 009b / 009c, and NBE-005 converted from a frozen rule into a deferred decision).

**Tier totals: F = 27, B = 8, C = 12.** Not one **B** requirement implies a set engine, and
NBE-044 fails the build if one appears.

## 6. The phase plan

| Phase | Name | Gate to enter |
|---|---|---|
| **10.4A** | Contract freeze | — (this phase) |
| **10.4B** | **Structured next-evidence plumbing** | none; it is unblocked |
| **10.4C** | **First real competing hypothesis pair** | **a service phase has produced one.** Not enterable before |

### 6.1 Phase 10.4B — structured next-evidence plumbing

**Goal: make the next-best evidence svcdoctor already computes readable by a machine. Build no
set machinery of any kind.**

| Package | Change |
|---|---|
| `internal/domain/recommendation.go` | four fields — `kind`, `safety`, `rationale`, `selfCollectable` — with a constructor that takes them, extended `MarshalJSON`, validation over the closed vocabularies. `action` stays required and keeps its meaning |
| a new `internal/domain` enum file | `RecommendationKind` and `SafetyClass` as **domain** enumerations; whether `internal/diagnosis`'s copies move down or map is a 10.4B decision recorded in its own §2 |
| `internal/diagnosis/advice.go` | one **safe conversion path**: `Advice.Recommendation() (domain.Recommendation, error)`. The existing guardrails are unchanged and stay upstream of it |
| `internal/diagnosis/kafka`, `internal/diagnosis/postgres` | delete **both** copies of `projectAdvice`; call the single conversion path. **No prose change, no code change, no severity change** |
| `internal/diagnosis` | the discriminator ↔ `NEXT_EVIDENCE` invariant (NBE-021), as a guard — **not** a grouping function |
| `internal/security/redaction/redact.go` | transform `rationale` |
| `internal/render/terminal` | display a recommendation's kind, safety and self-collectability |
| `internal/render/json` | nothing — canonical marshalling lives on the domain type |
| `docs/REPORT_SCHEMA.md`, `docs/OUTPUT.md` | the four fields (NBE-043) |

**Explicitly out of scope, and NBE-044 fails the build on the first:** `IndistinguishableSets()`
or any equivalent generic grouping abstraction; any set type, field or finding code; any identity
mechanism or `DiscriminatorID`; any ranking; any renderer set display; `RuleContext` changes;
iterative execution; **and any new hypothesis producer added merely to exercise the model.**

**Schema:** `SchemaVersion` 1, `RunSchemaVersion` 1 — authority in §6.3.
**Migration:** none. Golden reports move by exactly the four fields; that diff is the review.

**Tests:** the **B**-tier requirements — NBE-021, 022, 030, 039, 040, 043, 044 — plus the
mutation set in ADR 0086 §7.

### 6.2 Phase 10.4C — first real competing hypothesis pair

**Entry gate: a service phase has produced two mutually competing hypotheses about one subject
that one observation would separate.** Until that exists, this phase does not open, and no part
of it may be pulled forward.

It then, and only then:

1. decides ADR 0086 §2.2a — exact discriminator equality (A), a typed key (B), or the missing
   `domain.Step` (C) — **against the measured pair**, in its own ADR;
2. implements a derivation *if* the evidence shows one is required, under every **C**-tier
   requirement;
3. proves the convergence relationship rather than arguing it (NBE-037);
4. adds a golden incident for a real two-member set and one for a lone hypothesis.

**No service is nominated.** The repository contains no competing pair today, so nominating one
would be nominating a hypothesis about a hypothesis. **As a candidate only, and not a plan:**
Kafka SASL mechanism negotiation is where the survey found the most plausible future pair —
*"the broker offers no mechanism svcdoctor implements"* versus *"this listener is configured for
a different security protocol"*. That is a Kafka phase's finding to make or refuse, and it may
well be resolved the way `53300` was: by narrowing one claim until the pair dissolves.

### 6.3 Schema authority, verified rather than inferred

The review asked that this not be assumed. It is not. Four checks:

| Source | Text | Bearing |
|---|---|---|
| `docs/REPORT_SCHEMA.md` §1 | *"v0.1 development prefers additive changes. Removing a field, or changing the semantic meaning of an existing field, requires an explicit schema decision recorded as an ADR."* | Only removal and semantic change are gated. **Adding an optional field is not** |
| ADR 0083 §2.1 | *"What is genuinely new is three fields inside `recommendations[]` (ADR 0082 §2.1) … Both are additive."* Forcing conditions for v2: *"removing or repurposing an existing field, changing the meaning of `kind` or `confidence`, or making an existing optional field required."* | Authorizes **this exact addition** by name; **none** of the three forcing conditions is met |
| ADR 0082 §6 | *"Additive within an existing JSON object; `SchemaVersion` stays 1."* | Direct |
| repository scan | `additionalProperties` appears **nowhere** | svcdoctor publishes no closed schema an unknown field could violate |

**Conclusion: `SchemaVersion` 1 is authorized by the repository contract, explicitly, and the
authority is ADR 0083 §2.1 read together with `docs/REPORT_SCHEMA.md` §1.** The count correction
(three → **four**, ADR 0082 §2.4's `SelfCollectable`) does not disturb it: the forcing conditions
are about *kind* of change, not quantity.

## 7. Deferred, with the condition that would reopen each

| Item | Condition |
|---|---|
| Iterative measure-reason-measure diagnosis | its own ADR, defining a report that describes a search: a second schema version, a round budget, an explicit opt-in, and a security review of whether a later round may present a credential (ADR 0078 §2.6, ADR 0086 §2.7) |
| A stored hypothesis-set object | a consumer that provably cannot derive the set from the report |
| **A runtime set derivation of any kind** | **Phase 10.4C's entry gate: a service phase has produced a real competing pair.** Phase 10.4B is forbidden from building one, and NBE-044 fails the build if it appears |
| **The set identity mechanism** (ADR 0086 §2.2a) | the same gate. Byte-equal `Discriminator` is the **minimum safe candidate**, not a rule: `Discriminator` is human-facing prose, and freezing it as a runtime grouping key would let a wording-only edit change diagnostic behaviour — the coupling Phase 10.2A removed. Options are exact equality (A), a typed key (B), or the missing `domain.Step` (C) |
| A `DIAG_INDISTINGUISHABLE_EXPLANATIONS` finding code | a claim a set makes that its members do not. None identified |
| Ranking next-best evidence | a decision procedure justified by evidence rather than by convenience, plus an ADR reopening ADR 0086 §2.4 |
| A typed credential-capability category | a security review that answers how a privilege-escalation prompt in a shareable report is not one (ADR 0086 §2.6) |
| Unifying `projectAdvice` | disappears in 10.4B via the single `Advice` → `Recommendation` conversion path; no separate item |
| `docs/REPORT_SCHEMA.md` / `docs/OUTPUT.md` do not document the recommendation fields | ADR 0082 §6 owed this *"when Phase 10.1 lands"*. It landed; they did not. NBE-043, in 10.4B |
| `BasisBuilder.Miss`/`.Block`/`.Contradict` producers | a service rule that genuinely records one. `.Miss` is the one next-best evidence would most benefit from, and 10.4B does **not** force it — forcing a producer to justify a primitive is the inversion ADR 0054 forbids |
