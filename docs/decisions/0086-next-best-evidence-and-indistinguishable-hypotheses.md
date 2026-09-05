# ADR 0086 — Next-best evidence and indistinguishable hypotheses

**Status:** Accepted
**Date:** 2026-09-05
**Phase:** 10.4A
**Amended:** Phase 10.5A — **ADR 0087 §2.5 supersedes row 1 of §2.1's table**, and nothing else
in this record. The superseded cell is left standing below with a marker, so the reasoning that
was wrong stays legible; this is the same practice ADR 0081's header records.
**Amended:** Phase 11.0 — **ADR 0092 §8 corrects one clause of §1.2**: the two hypothesis-carrying
Kafka codes are at the **same** layer, `domain.LayerTopology`, not different ones. The paragraph's
conclusion is unaffected — differing subjects and differing open questions each independently
prevent a set, and §2.2 frees a set from needing one layer anyway — and nothing else in this
record is touched. The original sentence is left as written.
**Refines:** ADR 0078 §2.1 and §2.6, ADR 0081 §2.1 and §2.4, ADR 0082 §2.1, §2.4 and §2.5.
**Corrects:** ADR 0083 §2.1's field count (three → **four**).
**Upholds:** ADR 0054 (owner before producer), ADR 0083 §2.2 (the false-positive policy).

---

## 1. Context

The strategic direction is that svcdoctor should prefer

> *"I cannot distinguish these explanations with the evidence available; this observation would
> distinguish them"*

over guessing a most-likely root cause. That capability is **next-best evidence**, and this
record fixes how it is represented and selected.

### 1.1 It is not a new idea in this repository

ADR 0082 is already titled *"Recommendation safety and next-best-evidence"*, and it already
decided most of what a naive Phase 10.4 would re-decide: §2.1 puts `kind`, `safety` and
`rationale` on `domain.Recommendation`, §2.4 adds `SelfCollectable` and says what it does and
does not authorize, and §2.5 states that `Finding.Discriminator` and a `NEXT_EVIDENCE`
recommendation are *one idea in two places*. ADR 0081 §2.4 froze the four evidence relations and
§2.3 froze the confidence ladder. ADR 0078 §2.1 settled that a hypothesis is a `Finding`, not a
type.

So the question this phase actually had to answer is narrower than the brief assumed: **what,
if anything, is missing.**

### 1.2 What the measurement found, and it decided the record

Phase 10.4A counted production producers — not tests, not vocabulary, *producers* — for every
primitive the reasoning model froze:

| Primitive | Production producers | Where |
|---|---|---|
| `FindingKindHypothesis` | **2 codes** | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` (incomplete branch), `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` |
| `Finding.Discriminator` | **2 sites** | the same two |
| `diagnosis.NewBasis` | **1 site** | `internal/diagnosis/kafka/topology.go` |
| `BasisBuilder.Support` | 1 site | the same one |
| `BasisBuilder.Contradict` | **0** | — |
| `BasisBuilder.Block` | **0** | — |
| `BasisBuilder.Miss` | **0** | — |
| `AdmitConfidence` | **1 site** | the same one |
| `AuthorityDirect` passed as a value | **0** | named in PostgreSQL comments; the rule sets `ConfidenceHigh` directly |
| `AuthorityCompleteContrast` | **0** | — |
| `NewAdvice` | 2 sites | via a `projectAdvice` helper copied into two service packages |
| `SelfCollectable: true` | 2 sites | `postgres/admission.go`, `kafka/topology.go` |
| the four `Recommendation` fields ADR 0082 §2.1 decided | **0** | `domain.Recommendation` still holds `action` alone |

Three conclusions follow, and they are the whole record.

**First: `RelationMissing` — the relation whose own doc comment says *"it is the reason
`Finding.Discriminator` exists, and it is the input to a next-evidence recommendation"* — has no
producer at all.** The input side of next-best evidence is unwired.

**Second: the output side is truncated.** Both service packages construct a fully classified
`diagnosis.Advice`, run it through every guardrail, and then throw `kind`, `safety`, `rationale`
and `selfCollectable` away, because `domain.Recommendation` cannot carry them. The report says
*what to look at* and cannot say *that this is an observation rather than a change*, *that it is
read-only*, *why it discriminates*, or *whether svcdoctor could take it*. **Those four facts are
next-best evidence.** Without them a consumer cannot tell a `NEXT_EVIDENCE` from a
`REMEDIATION`, which is the distinction the whole safety model rests on.

**Third, and it is the finding that shapes everything below: there is no pair of competing
hypotheses anywhere in the tree, and there is no accident in that.** Two hypothesis-producing
codes exist. They have different subjects, different layers and different codes, and they are
not alternatives — *"this advertised endpoint may be unreachable"* and *"the advertised topology
may be unsuitable for this network"* can both be true at once. *(Phase 11.0 footnote:
**"different layers" is wrong** — both codes set `domain.LayerTopology`. The other two grounds
hold and each is independently sufficient; see ADR 0092 §8.)* Everywhere a competing pair would
naturally arise — a TCP timeout, a `53300`, an `08P01` from a pooler — ADR 0083 §2.2's
false-positive policy has already resolved it the other way: **one narrow `CONFIRMED` claim
instead of N hypotheses.** §4.3 works three of them through.

An engine that selects among surviving hypotheses would therefore be built over an empty input
set. ADR 0054 fixed the rule for exactly this shape — **owner before producer** — and
`CLAUDE.md` states it independently: *"Concrete structs first. Interfaces only at real
boundaries. Do not create speculative generic interfaces for a single implementation."*

---

## 2. Decision

### 2.0 What this record freezes, and what it deliberately leaves open

The first cut of this record froze more than the evidence supports. It defined a runtime
grouping identity for indistinguishable sets and planned the grouping function into the next
implementation phase — while §1.2 of the same record established that **no competing hypothesis
pair exists to group**. The two halves contradicted each other, and the correction is to freeze
the semantics and defer the mechanism.

| Frozen here (Phase 10.4A) | Deferred, with the constraints it must satisfy |
|---|---|
| what next-best evidence **means** (§2.4) | an actual hypothesis-set data structure (§2.3) |
| the seven epistemic positions and the six forbidden collapses (§2.1) | runtime set derivation, and when it runs (§2.3) |
| the **necessary conditions** for two hypotheses to be indistinguishable (§2.2) | the **identity mechanism** — how "the same open question" is decided (§2.2a) |
| safety semantics and collection capability (§2.6) | set renderer behaviour (§2.8) |
| reporting semantics: additive fields, no set code, renderers do not diagnose (§2.8, §2.11) | |
| **`Advice` → `Recommendation` information preservation** (§2.8) | |
| the discriminator ↔ `NEXT_EVIDENCE` consistency requirement (§2.10) | |
| the **no-ranking** policy (§2.4, §2.5) | |
| the report-only iterative boundary (§2.7) | |
| service/core ownership (§2.10) | |
| the constraints any future set implementation must satisfy (§2.2b, §2.9) | |

**The rule behind the split:** a semantic contract can be frozen from measurement of what
exists. A *mechanism* cannot be frozen from measurement of what does not. Everything in the
right-hand column needs a producer first, and §2.11 says why.

### 2.1 Seven epistemic positions, and the six collapses that are forbidden

The brief asked for at least seven distinctions. All seven are already expressible; this table
fixes where each one lives, so that no later phase invents a second home for one.

| # | Position | Representation today | Never becomes |
|---|---|---|---|
| 1 | evidence **supporting** a claim | **Superseded by ADR 0087 §2.5: two citation surfaces, `basis.Supporting()` ⊆ `EvidenceRefs` and never the reverse.** Originally: `EvidenceBasis.supporting` → `Finding.EvidenceRefs` | — |
| 2 | evidence **contradicting** it | `EvidenceBasis.contradicting`, rule-internal | a report field (ADR 0079 §2.4's negative explosion) |
| 3 | observation **simply absent** | `EvidenceBasis.missing` (a `domain.Step`) | contradiction |
| 4 | attempted, outcome **UNKNOWN** | a node with `StateUnknown` and an `EXEC_*` or capability class | contradiction, or FAIL |
| 5 | **blocked** by an upstream failure | the graph's `BlockedBy`, `StateSkipped` | support *or* contradiction |
| 6 | **not attempted**, budget-cut run | `RuleContext.Incomplete` / `Result.Incomplete()` | a stronger claim |
| 7 | the observation that **would discriminate** | `Finding.Discriminator` + a `NEXT_EVIDENCE` recommendation | a cause, or a remediation |

Positions 3, 4, 5 and 6 are four different kinds of not-knowing and they are **not
interchangeable**. Each collapse already has a name and a guard:

- **3 → 2** turns *"we could not look"* into *"we looked and it disagreed"*. Guarded by
  `AdmitConfidence`: a missing observation never raises and never lowers, and it makes
  `AuthorityCompleteContrast` a *false declaration* — an error, not a downgrade.
- **5 → 2 or 5 → 1** blames a downstream layer for an upstream failure. Guarded structurally by
  `BasisBuilder.Freeze` checks 3 and 4: a node the graph records as blocked may not be cited in
  either observed set, and a node cited as blocked must actually be blocked.
- **4 → 2** reads an unsupported capability or a local timeout as a denial. Guarded by the
  claim-discipline rules and by every service's boundary test.
- **6 → a stronger claim** is the failure this project names by name: *less evidence must never
  produce a stronger claim*. Guarded by `RuleContext.Incomplete`, by the completeness branches in
  `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and `POSTGRES_ADMISSION_SCOPE`, and by the
  monotonicity property tests.

**Nothing in this record adds a representation for 1–6.** They are complete. Only 7 is
incomplete, and only on the output side.

**Phase 10.5A footnote.** That paragraph stands: no representation was missing. What row 1 got
wrong was not *whether* position 1 had a representation but *how many* — it has two, admitting
different sets, and three production findings live in the difference. See ADR 0087 §2.5.

### 2.2 "Indistinguishable": the meaning is frozen, the identity mechanism is not

> **Two hypotheses are indistinguishable when they are competing explanations of one thing that
> the evidence in hand cannot separate, and one observation would separate them.**

Three **necessary conditions** are frozen. They are stated as conditions a future mechanism must
enforce, not as a grouping key a runtime may compute today.

- **`HYPOTHESIS` only.** A `CONFIRMED` finding may never participate. `domain.NewFinding`
  already refuses a discriminator on a `CONFIRMED` finding, so the exclusion is structural rather
  than policy. A proof has no open question left to settle.
- **One subject.** Two claims about different endpoints are not competing explanations of one
  thing; they are two things. `domain.Subject` is already the "what this is about" axis and is
  already half of semantic identity (ADR 0081 §2.1).
- **One open question.** The members must be settled by *the same* observation. What "the same"
  means mechanically is **§2.2a**, and it is deferred.

Two further properties are frozen as **not** required, because getting them wrong would exclude
the interesting cases:

- **Not one layer.** Two explanations at different layers are exactly the case worth reporting —
  *"the listener is not exposed"* (L2) versus *"the advertised address is wrong"* (L6). Layer is a
  merge precondition for *convergence* because a merged finding must claim one layer; a set claims
  nothing of its own, so it needs no layer.
- **Not one failure boundary.** `DIAG_FAILURE_BOUNDARY` is already one derived finding per subject
  (ADR 0079 §2.3). Requiring agreement would add a second, redundant key.

Answering the brief's remaining questions, all of which are about *semantics* and are therefore
frozen:

| Question | Answer |
|---|---|
| pairwise or over a set? | **Over a set.** A pair is the case where it has two members |
| across rules? | **Yes**, and without reading `RuleID` — ADR 0081 §2.6a already binds everything downstream |
| can `CONFIRMED` participate? | **No.** Structurally impossible |
| can `HIGH`-confidence hypotheses participate? | **Yes**, though nearly unreachable: a `HYPOTHESIS` reaches `HIGH` only on `AuthorityDirect`, and a peer that stated the condition in its own protocol has not left competing explanations. Confidence is never an eligibility filter — filtering by it would be confidence arithmetic |
| does one contradicting observation eliminate a hypothesis? | **Not at this layer.** Contradiction is handled *inside the rule* (ADR 0081 §2.4): a rule holding contradicting evidence emits nothing or emits a weaker claim. An eliminated hypothesis is simply absent, and no later mechanism may perform elimination or re-evaluation |
| evidence supports both? | Both remain. That is what "indistinguishable" means |
| evidence supports neither? | Neither was emitted; there is nothing to group |
| a required observation was blocked? | The rule may cite it in **neither** direction. It may name the *step* as missing, and a blocked step named as the open question must state that its blocker owns the failure (`docs/FINDINGS.md` §3.1 rule 11) |
| the run was incomplete? | Membership, confidence and the open question are **unchanged**. An incomplete run may never remove a member to make a set look decisive, and may never raise a confidence |
| can a hypothesis depend on another hypothesis? | **No.** A finding cites evidence identifiers, never another finding (ADR 0014). Chained hypotheses are how a reasoning system invents a causal graph nobody measured |

**No probabilistic semantics anywhere.** No percentages, no Bayes, no scoring, no confidence
arithmetic. Whatever mechanism §2.2a eventually selects, it partitions by a decision procedure —
never by a similarity, a distance or a threshold.

### 2.2a The identity mechanism is deferred, and byte equality is a candidate rather than a rule

The first cut of this record froze the runtime identity of a set as

> same `Subject`, different `Code`, **byte-identical `Discriminator`**.

**That is withdrawn as a frozen rule and retained as the minimum safe candidate.** The reasoning
that produced it is sound as far as it goes and is kept below; what it missed is a coupling this
repository has already been bitten by once.

**Why it is not frozen.** `Finding.Discriminator` is **human-facing prose**. Freezing byte
equality over it as a grouping identity would make *canonical diagnostic behaviour depend on
wording*: a typo fix, a clarity edit or a translation would silently split one open question into
two sets, or fuse two into one. That is the same class of defect Phase 10.2A removed when it
found prose deciding convergence outcomes through a `RuleID` tie-break, and ADR 0081 §2.2b's
answer there was to make prose a *precondition* — a guard that refuses — rather than a *key* that
selects. A precondition that refuses to merge is safe when the prose drifts: the result is two
findings that each state what their rule stated. A key that groups is not: the result is a
different partition, silently.

**Why it nonetheless remains the candidate to beat.** Byte equality is the only comparison this
project permits over prose. **Fuzzy and semantic discriminator matching are forbidden
permanently** — ADR 0081 §2.2b banned prose similarity by name after measuring three production
shapes where it published claims no rule made, and nothing about next-best evidence weakens that.
So the choice is not "byte equality versus something looser"; it is "byte equality versus
something *more* structured".

**What a later phase must decide**, once a real competing pair exists to decide it against:

| Option | Shape | Cost |
|---|---|---|
| **A** | exact `Discriminator` equality is sufficient | zero new structure; prose controls grouping, and a wording edit is a behaviour change that only a golden test would catch |
| **B** | a typed discriminator identity — a stable key beside the prose, owned by the service rule | prose becomes free to edit again; costs one field, its validation, its redaction treatment and a schema decision |
| **C** | a smaller repository-supported mechanism — for example deriving identity from the **missing `domain.Step`** the rule already records via `BasisBuilder.Miss`, which is svcdoctor's own vocabulary, is never peer-supplied, and is already the way `EvidenceBasis` names an unmade observation | zero new report structure; requires `.Miss` to have a producer, which today it does not |

**Option C is noted, not preferred.** It is the one an author reaching for B should look at first,
because ADR 0081 §2.4 already made `missing` a *step* rather than a string for exactly the reason
that argues for it here. But choosing between the three without a producer would be choosing in
the abstract, which is what this section refuses.

**`DiscriminatorID` is deliberately not introduced now.** Adding a field to solve a problem no
producer has yet posed is the speculative machinery `CLAUDE.md` forbids, and it would have to be
schema-decided, redaction-decided and renderer-decided before anything could use it.

### 2.3 A set, if one is ever derived, is derived and never stored

This is a **constraint on a future implementation**, not a description of one.

There is no `HypothesisSet` type, no `DiagnosticRelation` object and no new report array, and a
later phase may not add one without reopening this section. A stored set would be a second place
for the report's own content to be wrong, and it would have to be redacted, versioned, validated
for reference resolution and rendered — four costs ADR 0078 §2.1 already refused when it declined
a `Hypothesis` type for the same reason.

Whatever mechanism §2.2a selects, it must be:

- **derivable from the report alone**, so a consumer can reproduce it without rerunning anything;
- **order-independent**, over findings already in `domain.SortFindings` order;
- **invariant under rule renaming**, extending ADR 0081 §2.6a's property to the new mechanism;
- **monotone**: less evidence never produces a smaller set that looks more decisive, and never a
  stronger member;
- **run after convergence**, so it sees final findings — but see §2.9, which is why the ordering
  matters less than it appears.

**No such derivation exists today and none is authorized before Phase 10.4C.**

### 2.4 Next-best evidence is a property of a finding, and nothing ranks it

**Frozen definition:**

> **The next-best evidence for a hypothesis is the observation named by its `Discriminator`, and
> the structured form of that observation is the `NEXT_EVIDENCE` recommendation it carries.**

It is a property of **one finding**. It does not require a set, and it is fully deliverable — and
fully valuable — on a lone hypothesis, which is the only shape that exists in the tree today
(§4.2). Should a set ever be derived, its next-best evidence is by construction the open question
its members share; that is a consequence of §2.2, not an additional decision.

**There is therefore no ranking function, and this record declines to create one.** The brief
offered a six-element ordered tuple; every element of it is either already enforced upstream or
would be arithmetic:

| Proposed criterion | Disposition |
|---|---|
| can svcdoctor collect it itself | already `SelfCollectable`; **reported, never ranked on** — ranking self-collectable observations first would systematically bury the observation an operator actually needs behind one svcdoctor finds convenient |
| non-disruptive / read-only | already enforced at construction: `NewAdvice` refuses a `NEXT_EVIDENCE` that is not `OBSERVE`/`VERIFY`/`COMPARE`. Nothing to rank — the unsafe ones cannot exist |
| direct authority before inference | already the confidence ladder (`AdmitConfidence`), applied per finding |
| separates more surviving hypotheses | **refused as a ranking input** — see §2.5 |
| lower collection cost | **refused.** svcdoctor has no cost model, and inventing one would be a number crossing a threshold |
| stable deterministic tie-breaker | unnecessary; with no ranking there is no tie |

When one subject carries **two different open questions**, both are reported, in the order
`domain.SortFindings` already gives their findings — total and order-independent. Choosing
between two genuinely different questions is the operator's judgement, and a tool that ranked
them would be asserting a prioritization it cannot justify from evidence.

### 2.5 Information gain is structural, and it is never a ranking input

**Forbidden:** entropy, mutual information, any probability, any learned model, any score.

**Permitted, if and when a set is ever derived:** its **cardinality** — how many surviving
explanations one observation would settle — as a *descriptive* fact a renderer may state
(*"one observation would settle both of these"*).

**Refused:** using that cardinality to order anything. A count that decides an output is
arithmetic scoring wearing an ordinal costume, which is the exact phrase `internal/diagnosis/
converge.go` uses to refuse confidence promotion by count, and ADR 0034 §13 refuses severity by
count for the same reason. Cardinality may be *shown*. It may not *decide*.

### 2.6 Collection capability: two fields, and the two that stay prose

The brief listed six categories. Four are already representable and two must not become
structure:

| Category | Representation |
|---|---|
| A — svcdoctor can collect it in this run | **not representable, and correctly so.** Diagnosis is a pure function of frozen evidence (ADR 0078 §2.6). If svcdoctor could have collected it in this run, it already did |
| B — a differently configured or future run could | `SelfCollectable: true` — this is exactly what §2.4 of ADR 0082 says it means |
| C — the operator must collect it externally | `SelfCollectable: false` |
| D — collection needs credentials svcdoctor lacks | **`rationale` prose. Never an enum member** |
| E — collecting it would be disruptive or unsafe | **unreachable by construction.** `NewAdvice` refuses it |
| F — impossible from svcdoctor's vantage | **`rationale` prose**, beside `VantageDependent` on the finding |

**D is the security decision in this record.** A machine-readable *"svcdoctor could take this
observation if you gave it a credential it does not have"* is a privilege-escalation request
channel: it invites an operator to widen a grant, it invites a future phase to consume the field
and prompt for one, and it puts the shape of a missing privilege into a shareable document. The
existing rules stand unchanged and this record adds no exception to any of them — credentials
stay endpoint-bound (ADR 0028, ADR 0030), discovered endpoints inherit nothing (ADR 0050),
secrets never become report content, and there is no automatic escalation. A rationale sentence
that says *"this needs a privilege this run's credential may not hold"* is honest prose; a typed
`NEEDS_CREDENTIAL` category is a feature request aimed at the operator.

**`SelfCollectable: true` authorizes nothing.** It is a statement about capability, not a
grant, not a plan, and not a promise. §2.7 keeps it that way.

### 2.7 Iterative diagnosis: report only, and the deferral is explicit

**Decision: option A. Phase 10.4 reports next-best evidence and performs no additional
observation.**

ADR 0078 §2.6 already refused a hidden second collection pass and already said an
operator-visible iterative mode *"would require its own ADR, because it changes what a report
means: today a report describes one bounded measurement, and an iterative one would describe a
search."* Nothing measured in this phase disturbs that, and option B would break the property
that makes every existing guarantee cheap: diagnosis is pure, so it cannot leak, cannot dial,
cannot escalate and cannot be non-deterministic.

**What a later iterative phase would have to add, without invalidating anything here:**

1. a report type that describes a **search** — rounds, what each round observed, and why the
   next round was chosen — with its **own** schema version, exactly as ADR 0074 gave the
   aggregate `RunSchemaVersion` rather than sectioning the single-target report;
2. a **budget** for rounds, nested inside the existing execution budget, and a truthful
   `Incomplete()` when it is exhausted mid-search;
3. an explicit **operator opt-in flag**, never a default and never automatic;
4. a re-collection step that runs in the *collection* layer and hands diagnosis a new frozen
   graph — diagnosis itself still performs no I/O;
5. a decision about whether round *n+1* may present a credential, which is a security review of
   its own and is **presumed no**.

None of the five requires this record to change. `SelfCollectable` is forward-compatible with
all of them because it already means *"a differently configured run could"*.

### 2.8 Schema: `SchemaVersion` stays **1**, and four fields land inside an existing object

ADR 0083 §2.1 already authorized this addition and already stated the reasoning; ADR 0082 §3
already stated the compatibility consequence. This record changes neither, and **corrects one
number**: ADR 0083 §2.1 says *"three fields inside `recommendations[]`"*, counting ADR 0082
§2.1's illustrative struct and missing `SelfCollectable`, which §2.4 of the same record adds.
**The number is four**: `kind`, `safety`, `rationale`, `selfCollectable`.

```jsonc
"recommendations": [
  {
    "action": "Identify the connection limits applicable to this attempted session and …",
    "kind": "NEXT_EVIDENCE",          // new
    "safety": "COMPARE",              // new
    "rationale": "The endpoint stated that a connection limit applying to …",  // new
    "selfCollectable": false          // new
  }
]
```

**The authority for keeping `SchemaVersion` 1 is quoted rather than inferred**, because
"the fields are additive" is an argument and not a contract. Three independent sources in this
repository authorize it, and a fourth check found nothing that forbids it:

1. **`docs/REPORT_SCHEMA.md` §1**, the versioning policy itself: *"v0.1 development prefers
   additive changes. Removing a field, or changing the semantic meaning of an existing field,
   requires an explicit schema decision recorded as an ADR."* Only removal and semantic change are
   gated. Adding an optional field is not.
2. **ADR 0083 §2.1**, which authorizes *this specific addition* by name: *"What is genuinely new
   is three fields inside `recommendations[]` (ADR 0082 §2.1) and one new finding code
   (ADR 0079 §2.3). Both are additive."* It then names the only three conditions that would force
   `SchemaVersion` 2 — *"removing or repurposing an existing field, changing the meaning of `kind`
   or `confidence`, or making an existing optional field required"* — and **none is met**:
   nothing is removed, nothing is repurposed, `action` keeps its meaning, and it stays required
   exactly as it is today.
3. **ADR 0082 §6**: *"Additive within an existing JSON object; `SchemaVersion` stays 1."*
4. **No strict schema artifact exists.** `additionalProperties` appears nowhere in the
   repository, so svcdoctor publishes no closed schema that an unknown field would violate. The
   only compatibility surface is a consumer's own validator, which is outside this contract.

`RunSchemaVersion` stays 1 for the same reasons; the aggregate wraps reports verbatim and gains
nothing.

**One documentation debt is uncovered by the same check.** ADR 0082 §6 promised that
*"`docs/REPORT_SCHEMA.md` and `docs/OUTPUT.md` gain the new fields when Phase 10.1 lands"*. Phase
10.1 landed and they did not; `docs/REPORT_SCHEMA.md` still lists `recommendations` as a bare
field name. Updating both is part of Phase 10.4B, not a separate item.

**No existing string is overloaded.** `action` keeps meaning exactly what it means, `detail`
gains nothing, and `discriminator` keeps being one human sentence. The new facts arrive as new
named fields with closed vocabularies that a schema can validate — which is the opposite of
encoding semantics in prose a consumer would have to parse (`docs/FINDINGS.md` §3.1 rule 13).

**Redaction:** `kind`, `safety` and `selfCollectable` are closed enumerations and a boolean, so
they carry no identity and pass through unchanged. `rationale` is svcdoctor-authored prose and
is transformed exactly as `action`, `summary`, `detail` and `discriminator` already are — a new
prose field needs a matching transformation (ADR 0018), and it gets one.

**Renderers diagnose nothing.** Canonical JSON stays the source of truth. A renderer may group
by `(subject, discriminator)` and display the group, because grouping by equality of two fields
it was handed is presentation, not inference. It may not compute membership by similarity, may
not choose a "best" question, may not re-derive a discriminator from prose, and may not state
anything a finding does not state.

### 2.9 Convergence safety: what is true now, and what a future set mechanism must not break

**Frozen now, and already true.** Every prohibition the review asks for holds today, without any
set mechanism existing:

- **A merge never erases a discriminator.** An unset discriminator folds into the one non-empty
  value; two different non-empty values refuse to merge; a `CONFIRMED` merge clears it because
  `domain.NewFinding` refuses one there.
- **A merge never promotes a hypothesis.** Absorption of a `HYPOTHESIS` into a `CONFIRMED` claim
  was Phase 10.2A's third measured defect and is now refused outright by the `Summary`/`Detail`
  preconditions.
- **A merge never turns incomplete evidence into a stronger claim.** Confidence takes the maximum
  of independently admitted values, never a count.
- **A merge never picks prose by `RuleID`.** `RuleID` reaches no merged field, and
  `TestC06ARuleIDRenameCannotChangeAnything` permutes every rule identity and requires
  byte-identical output.
- **Two hypotheses whose distinguishing observations differ never merge.** Already a
  precondition.

**A constraint on whatever §2.2a selects.** The first cut of this record argued that convergence
and set formation are *disjoint by construction*, because a set required differing codes and
convergence keys on `(Code, Subject)`. **That argument is only as frozen as the differing-codes
clause was, and that clause is now a candidate rather than a rule** — so it is restated as a
requirement instead of relied on as a theorem:

> **A future set mechanism must be provably disjoint from convergence, or provably
> order-independent with respect to it.** Whichever it achieves, it must be demonstrated by a
> property test over both mechanisms, not argued.

The differing-codes formulation achieves disjointness cleanly and is the reason it is the
candidate to beat. A mechanism that admitted same-code members would have to answer what a set of
findings convergence declined to merge *means*, and answer it before it is built.

### 2.10 Ownership: the generic core learns no service name

| Layer | Owns |
|---|---|
| **adapter** | facts only. No hypothesis, no discriminator, no advice |
| **generic core** (`internal/diagnosis`) | the relation vocabulary; `AdmitConfidence`; `NewAdvice`/`AdmitAdvice` safety gates; the `Discriminator` ↔ `NEXT_EVIDENCE` binding invariant; set formation by `(Subject, Discriminator)`; determinism and ordering; convergence |
| **service rule** (`internal/diagnosis/<service>`) | what the hypothesis *means*; which observation would settle it; the discriminator sentence; the recommendation text and its `SelfCollectable` value; protocol-authoritative predicates |
| **renderer** | explanation only. Group and display; never compute, never choose, never infer |

The generic core still receives no `ServiceID` and still branches on no service name. Set
formation reads `Subject`, `Discriminator`, `Kind` and `Code` — four generic fields — and is
service-neutral by construction, exactly as convergence is.

`projectAdvice` is currently duplicated in `internal/diagnosis/kafka` and
`internal/diagnosis/postgres`, deliberately (ADR 0084 §9). Once the four `Recommendation` fields
exist the helper collapses to a single constructor call, and the duplication question answers
itself by disappearing rather than by being resolved.

### 2.11 What this record refuses to build, and why

**No hypothesis-set object.** §2.3.

**No ranking engine, no cost model, no information-gain score.** §2.4, §2.5.

**No `NEEDS_CREDENTIAL` capability category.** §2.6.

**No iterative execution.** §2.7.

**And no new finding code.** A set is a *view over* findings, not a claim of its own. A
`DIAG_INDISTINGUISHABLE_EXPLANATIONS` code would be a finding whose content is *"two other
findings exist"*, which fails `docs/FINDINGS.md` §3.1 rule 1 — one finding is one independent
claim, and removing the two members would remove this one's entire content.

**Above all: no set engine while no producer exists.** ADR 0054's rule is *owner before
producer*; this is its mirror — **producer before engine**.

Stated as a binding constraint on the phase plan, because the first cut of this record violated
it while stating it: **Phase 10.4B must not introduce `IndistinguishableSets()` or any equivalent
generic grouping abstraction.** A grouping function whose only exercise is a synthetic fixture is
a primitive manufacturing its own producer, which is the inversion this repository refuses in
three separate places — ADR 0054, `CLAUDE.md`'s *"concrete structs first; interfaces only at real
boundaries"*, and its *"do not introduce speculative machinery"*.

The first legitimate competing pair must arrive from a **service** phase that measures one. When
it does, §2.2's semantics are ready for it and §2.2a's three options are decided against a real
case rather than an imagined one. That phase is **10.4C**, and it is the *only* phase authorized
to freeze an identity mechanism or build a derivation.

---

## 3. Consequences

**Phase 10.4A changes no production code.** The model was already right; what is missing is
plumbing, and plumbing is 10.4B's work.

**The phase plan is three phases, not two.** **10.4A** freezes the contract; **10.4B** carries
`Advice`'s four fields into `domain.Recommendation` and enforces the discriminator ↔
`NEXT_EVIDENCE` relationship, and builds **no** set machinery; **10.4C** exists only when a
service phase has produced a genuine competing pair, and is the phase that decides §2.2a and
implements a derivation *if the evidence then shows one is required*.

**The report will gain four fields inside `recommendations[]`** and nothing else. Every existing
consumer keeps working. `SchemaVersion` stays 1.

**`svcdoctor` will be able to say, machine-readably, that a suggestion is an observation rather
than a change.** Today it cannot, and that is the single largest gap between what the reasoning
model decided and what an operator or a CI job can actually read.

**A discriminator becomes structurally bound to its recommendation.** ADR 0082 §2.5 asked for
that guard *"once Phase 10.1 lands"*; Phase 10.1 landed and the guard was not written. It is
NBE-021 and it is now owed.

**Next-best evidence is deliverable without a hypothesis-set engine**, which is the commercially
relevant result: the differentiator is *"here is the observation that would settle this, here is
why, and here is whether we could take it"* — four fields on an object that already exists, on a
**single** hypothesis, needing no set at all.

**Diagnostic grouping behaviour is not made a function of prose.** §2.2a's withdrawal is the
substance of this record's correction: freezing byte-identical human-facing text as a runtime
identity would have let a wording edit change what svcdoctor groups, which is the coupling
Phase 10.2A spent a phase removing.

**Two counts stay frozen and one is corrected.** Finding codes stay **65**; failure classes stay
**42**; ADR 0083 §2.1's "three fields" becomes **four**.

---

## 4. Alternatives considered

### 4.1 The four models the brief named

**Model A — keep the discriminator as prose and derive sets from compatible discriminator
text.** *Rejected in its fuzzy form, permanently.* "Compatible text" is similarity matching,
which ADR 0081 §2.2b banned by name after Phase 10.2A measured it publishing claims no rule made.
Its byte-equal form survives as **§2.2a option A — a candidate, not a decision**, and the reason
it is not more than a candidate is that `Discriminator` is human-facing prose and a grouping key
made of prose lets a wording edit change behaviour.

**Model B — a typed internal discriminator structure, preserving the public contract.**
*Substantially selected.* `diagnosis.Advice` **is** that structure and it already exists,
validated, guarded and tested. Model B's remaining content is that it must reach the report,
which is §2.8. Building a *second* typed structure beside `Advice` would be the duplication
ADR 0082 §2.1 refused when it declined a second recommendation type.

**Model C — an explicit generic relation object carrying hypothesis set, distinguishing
observation, collection capability, safety and cost.** *Rejected, and it is the alternative
that most needed rejecting.* Four objections, in order of weight: it has **zero producers**
(§1.2); it duplicates `Advice`'s three fields and `Finding`'s two; "cost/priority" requires a
cost model svcdoctor has no basis for; and a stored set is a second place for the report's own
content to be wrong, needing its own redaction, validation, ordering and renderer. It is the
speculative machinery `CLAUDE.md` names.

**Model D — the one selected.** *"Freeze the semantics, finish the wiring, and defer both the
identity mechanism and the derivation until a producer exists."* §2, and §2.0 is the frozen /
deferred split.

**Selecting Model B's typed key (a `DiscriminatorID`) now.** *Rejected for now, retained as
§2.2a option B.* It is the right answer if option A's prose coupling proves real, and it is the
wrong thing to add before a producer can show that it does: a new field is a schema decision, a
redaction decision and a renderer decision, and taking three decisions to pre-empt a problem
nobody has posed is how speculative structure enters a codebase.

### 4.2 Other alternatives

**A `DIAG_INDISTINGUISHABLE_EXPLANATIONS` finding code.** Rejected — §2.11.

**Ranking next-best evidence by self-collectability.** Rejected. It sounds operator-friendly and
is the opposite: it would systematically promote whatever svcdoctor finds easy over whatever the
operator needs. Report the flag; never sort by it.

**Eliminating a hypothesis from a set when contradicting evidence exists.** Rejected. That
re-runs the rule's own judgement outside the rule. Contradiction belongs inside the rule
(ADR 0081 §2.4); a contradicted hypothesis is one that was never emitted.

**`SchemaVersion` 2.** Rejected — ADR 0083 §2.1's forcing conditions are not met.

### 4.3 The three places a competing pair would live, and why none does

These are the brief's required worked examples, and their answer is the phase's main result.

**Generic transport — a TCP timeout.** The natural pair is *"a firewall is dropping packets"*
versus *"the host is down"* versus *"the path is lossy"*. svcdoctor emits **none** of them. A
timeout is a `CONFIRMED` claim about what was observed from this vantage, `vantageDependent`, and
`test/diagnosis/falsepositive_test.go` forbids "the host is down", "is not running", "not
listening" and "routing" by name. **The pair does not exist because the policy already refused
to create it** — and refusing three hypotheses in favour of one honest narrow claim is *better*
output than a set plus a discriminator, because there is no observation svcdoctor could name that
would separate them from where it stands.

**Kafka — an unreachable advertised endpoint.** This is the closest the tree comes, and it is
still one hypothesis, not two. `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` is `HYPOTHESIS`/`WARN`/
`MEDIUM` with a real discriminator — *"whether the advertised addresses are the ones a client on
this network is expected to use to reach these brokers"* — and a `COMPARE` recommendation with
`SelfCollectable: false`. The alternatives it does not exclude (routing, listener exposure, a
broker-side outage) are named in the rule's own comment as *not measured*, and none of them is
emitted as a sibling hypothesis. **One observation, one open question, one finding.** Under
§2.2 this is a **lone hypothesis, not a set** — and it is still exactly where next-best evidence
pays, because the value is the four fields the report currently discards, on one finding.

**PostgreSQL — `53300`.** The natural pair is *"the limit is enforced at this endpoint"* versus
*"a pooler in front of it enforced its own"*. ADR 0085 §3.2 resolved it the other way, and
correctly: the claim is scoped to *this endpoint's refusal of this session*, `CONFIRMED`, and it
states that where the limit is enforced is not in the response. **Narrowing the claim dissolved
the pair.** PostgreSQL produces no hypothesis at all (`docs/FINDINGS.md`), and Phase 10.3
deliberately kept it that way.

The lesson is worth stating because it will be argued again: **a competing pair is not a sign of
sophistication; it is usually a sign that the claim was drawn too wide.** Next-best evidence
earns its place on single hypotheses too — one hypothesis with a named discriminator and a
classified, self-collectability-annotated observation is already the product's differentiator.

---

## 5. Security implications

**Nothing in this record widens any surface.** Diagnosis stays a pure function of frozen
evidence, `RuleContext` gains no field, and no rule gains access to a credential, a socket, a
clock or a filesystem.

**The one active security decision is §2.6's refusal of a credential-capability category.** A
typed *"svcdoctor could observe this with a credential it lacks"* is a privilege-escalation
prompt embedded in a shareable document, and it is refused permanently. The prose form stays.

**`SelfCollectable: true` grants nothing.** §2.6 and §2.7 both say so, and the iterative
deferral means nothing consumes it as an instruction.

**The new `rationale` field is svcdoctor-authored prose and is redacted like every other prose
field** (ADR 0018). It is not peer-supplied and may never carry a peer-supplied string
(ADR 0081 §2.7).

**A set names no host.** It is keyed on `Subject`, which redaction already pseudonymizes, so a
shareable report's sets are structurally identical to a local report's with the identities
transformed — the correlation-preserving, identity-removing property ADR 0018 requires.

---

## 6. Compatibility implications

`SchemaVersion` **1**, `RunSchemaVersion` **1**, finding codes **65**, failure classes **42**,
exit codes **5**, external modules **2** — all unchanged by this record and by the phase it
plans.

The four `recommendations[]` fields are additive. A consumer reading `action` is unaffected. A
consumer that validates against a closed schema and rejects unknown fields would need to update,
which is why they land in one phase rather than trickling in.

No CLI flag, no exit-code mapping and no renderer contract changes in 10.4A. 10.4B adds
renderer *display* of the new fields, which is additive terminal output.

---

## 7. Validation requirements

The requirement register is `docs/validation/PHASE104A_NEXT_BEST_EVIDENCE_CONTRACT.md` §5,
NBE-001 through NBE-042, each mapped to a design section, a planned test and an owning layer.

For **10.4A** (this phase), the bar is that nothing moved: the frozen counts, `SchemaVersion`,
every finding code, and zero production diff.

For **10.4B** — *structured next-evidence plumbing, and no set machinery* — the bar is:

- unit tests for the four new `Recommendation` fields, including every rejection
  `NewAdvice`/`AdmitAdvice` already performs, now reachable through the report;
- **the discriminator ↔ `NEXT_EVIDENCE` invariant** (NBE-021), as a guard over every production
  hypothesis rather than a per-rule assertion;
- a redaction test proving `rationale` is transformed, and that no report leaks an identity
  through it;
- byte-stability of every existing golden report except for the four new fields — that diff is
  the thing to inspect;
- a `test/security` guard that **no generic grouping abstraction exists**: the absence of a set
  engine is a property worth failing the build over, because it is exactly the thing that will be
  added by accident;
- mutation closure on the plumbing: an `Advice` field dropped on the way to a `Recommendation`;
  a `REMEDIATION` admitted below `CONFIRMED`/`HIGH`; `SelfCollectable` inverted; a
  `NEXT_EVIDENCE` given a non-read-only safety class; a hypothesis carrying a discriminator with
  no `NEXT_EVIDENCE` recommendation.

For **10.4C** — *and only once a service phase has produced a real competing pair* — the bar is:

- the §2.2a decision recorded in its own ADR, against the measured pair rather than in the
  abstract;
- property tests that the chosen mechanism is order-independent, rule-rename invariant, monotone
  under evidence removal, and **provably disjoint from convergence or provably order-independent
  with respect to it** (§2.9);
- a golden-corpus incident with a real two-member set, and one with a lone hypothesis proving it
  is not reported as a set;
- mutation closure covering: similarity matching reintroduced; a `CONFIRMED` finding admitted;
  a set formed across differing subjects; ranking introduced; `SelfCollectable` used as a sort
  key; an incomplete run removing a member; a merge dropping a discriminator.
