# ADR 0087 — Evidence basis relations: the two citation surfaces, and deferred activation

- **Status:** Accepted
- **Date:** 2026-09-05
- **Phase:** 10.5A (architecture / archaeology; no production code)
- **Upholds:** ADR 0054 (owner before producer), ADR 0078 §2.3, ADR 0079 §2.4 (no negative
  explosion), ADR 0081 §2.3 and §2.4, ADR 0086 §2.11 (producer before engine) and rows 2–7 of
  ADR 0086 §2.1
- **Supersedes:** **ADR 0086 §2.1, row 1 only** — its "Representation today" cell,
  `EvidenceBasis.supporting` → `Finding.EvidenceRefs`. §2.5 states the replacement. The
  superseded cell is left standing in ADR 0086 with a forward marker, per the practice ADR 0081's
  header records, so the reasoning that was wrong stays legible. Nothing else in ADR 0086 is
  affected: rows 2 through 7, the six forbidden collapses and every §2.2–§2.11 decision stand
  unchanged.
- **Corrects:** nothing by arithmetic. The word is reserved in this repository for a countable
  fix (ADR 0086 "Corrects: ADR 0083 §2.1's field count"); a withdrawn normative cell is a
  supersession, and this record is one.

---

## 1. Context

### 1.1 The question

`diagnosis.EvidenceBasis` carries four relations — supporting, contradicting, missing, blocked.
Phase 10.4A counted their producers and found `.Support` at one site and `.Contradict`, `.Miss`
and `.Block` at none. It recorded the gap and deliberately did not close it (ADR 0086 §1.2,
`docs/validation/PHASE104A_NEXT_BEST_EVIDENCE_CONTRACT.md` §7).

Phase 10.5A asks the next question, which a producer count cannot answer: **do existing rules
already compute facts that belong in those relations and currently flatten them into supporting
evidence or into prose?** A latent abstraction with no legitimate producer and an abstraction
whose producers exist but are unwired are different situations with different remedies, and
nothing in the tree distinguished them.

### 1.2 The measured inventory, at `105e43b`

Counted by reading every production file in the six diagnosis packages. Not tests, not
vocabulary — **producers and readers**.

| Symbol | Production writers | Production readers |
|---|---|---|
| `diagnosis.NewBasis` | **1** — `internal/diagnosis/kafka/topology.go:700` | — |
| `BasisBuilder.Support` | **1 site**, three calls (`topology.go:700,702,704`) | — |
| `BasisBuilder.Contradict` | **0** | — |
| `BasisBuilder.Miss` | **0** | — |
| `BasisBuilder.Block` | **0** | — |
| `EvidenceBasis.Supporting()` | — | **1** — `topology.go:667`, into `EvidenceRefs` |
| `EvidenceBasis.Contradicting()` | — | **0** |
| `EvidenceBasis.Missing()` | — | **0** |
| `EvidenceBasis.Blocked()` | — | **0** |
| `AdmitConfidence` | **1** — `topology.go:647` | — |
| `AuthorityNone` passed as a value | **1** | — |
| `AuthorityDirect` passed as a value | **0** | — |
| `AuthorityCompleteContrast` passed as a value | **0** | — |
| `Boundary.Blocked()` | `boundary.go:191` (`BlockedChain`) | **0** |
| `Boundary.NotMeasured()` | `boundary.go` | **1** — `failureboundary.go:159`, to select one prose sentence |
| `GraphBuilder.AddBlockedBy` | **6** adapter/probe sites | `Graph.BlockedBy` read by 3 rules and by `domain.Report`'s graph projection |

The scan covers **22** exported rule functions and **65** finding codes: `internal/diagnosis`
1 rule / 1 code, `transport` 3 / 8, `kafka` 5 / 15, `postgres` 6 / 21, `redis` 4 / 9, `rabbitmq`
3 / 11. Twenty-one of the 22 set `Confidence` as a literal; one obtains it from the ladder.

### 1.3 The three things the inventory found that no prior record holds

**First, `EvidenceBasis.supporting` and `Finding.EvidenceRefs` are not the same set, and the
difference is not cosmetic.** `BasisBuilder.Freeze` check 3 refuses to let a node the graph
records as blocked into the supporting set. **Three production findings put exactly such a node
into `EvidenceRefs`, and all three are correct to**:

| Finding | The blocked node it cites | Why it is right |
|---|---|---|
| `KAFKA_CREDENTIAL_WITHHELD` | the `SKIPPED` / `EXEC_SKIPPED_BY_POLICY` authentication node, plus its blocker (`kafka/protocol.go:726`) | the claim's subject *is* the step that did not run |
| `POSTGRES_CREDENTIAL_WITHHELD` | the same shape (`postgres/authentication.go:339–345`) | the same reason |
| `POSTGRES_ADMISSION_SCOPE` | every `admissionUndetermined` startup node, including one `SKIPPED` and blocked by an earlier stage (`postgres/admission.go:396–403`) | one of the three counts the finding states is *"no admission decision was observed"* |

Each of the three producers is reachable in production: `internal/adapter/postgres/startup.go:384`,
`internal/adapter/postgres/authenticate.go:643` and `internal/adapter/kafka/saslauthenticate.go:606`
all call `AddBlockedBy` on the node the finding then cites.

Measured rather than argued: `NewBasis().Support(<blocked node>).Freeze(g)` returns
`ErrInvalidBasis` — *"evidence "a-tls" did not run because an upstream step failed, so it is
neither supporting nor contradicting"* — and `TestP06BlockedEvidenceIsNotSupportOrContradiction`
has pinned that since Phase 10.1A.

So the projection ADR 0086 §2.1 row 1 states — `EvidenceBasis.supporting` → `Finding.EvidenceRefs`
— **cannot** produce three findings the tree already publishes. §2.5 supersedes that cell. Any
activation phase must decide between narrowing check 3 and changing those three findings' output.
Neither is free, and neither had been noticed.

**Second, the one guard that makes `AuthorityCompleteContrast` honest is vacuous.**
`AdmitConfidence` refuses complete contrast when `basis.missing` is non-empty — *"I excluded
every alternative" and "I could not look" are different claims*. `Miss` has no producer, so a
rule may declare complete contrast while any number of discriminating observations were never
made, and the check will pass. It is not currently exploitable, because
`AuthorityCompleteContrast` also has no producer. The two zeroes are load-bearing together and
neither is safe alone.

**Third, the ladder has no admission ground for the most common claim in the tree.** ADR 0081
§2.3 admits `HIGH` on two grounds: the peer stated it, or every distinguishable alternative was
measured and excluded. `DIAG_FAILURE_BOUNDARY` is neither — no peer states a boundary, and no
alternative is excluded — and it publishes `HIGH` today, correctly, because *the claim is a
restatement of two measured states*. Routed through the ladder truthfully it is `AuthorityNone`
with two supporting nodes, which is `MEDIUM`; with one it is `LOW`. The same holds for the
incomplete branches of `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and `POSTGRES_ADMISSION_SCOPE`.

This is not an argument for adding a third `Authority`. It is the reason **adopting the ladder is
not output-neutral**, which matters because adopting the ladder is the only path by which any of
the three unused relations acquires a consumer.

---

## 2. Decision

### 2.0 What this record freezes, and what it defers

| Frozen here | Deferred, with its condition |
|---|---|
| the exact meaning of each of the four relations (§2.1–§2.4) | any production producer for `.Contradict`, `.Miss` or `.Block` (§2.11) |
| **Model A** for `BLOCKED`, and its subordination to `Graph.BlockedBy` (§2.4) | narrowing `Freeze` check 3 (§2.5) |
| that the two citation surfaces are distinct, **superseding ADR 0086 §2.1 row 1** (§2.5) | a third `Authority` ground (§2.6) |
| the confidence interaction, including the two vacuous guards (§2.6) | any relation reaching a report field (§2.7, §2.8) |
| that relations never reach convergence (§2.7) | relation-aware convergence (§2.7) |
| that no relation is serialized, and that `blockedBy` already is (§2.8) | |
| that `MISSING` and `NEXT_EVIDENCE` imply each other in **neither** direction (§2.9) | |
| the producer admission bar (§2.10) | |

**Admitted producers: none.** §2.11.

### 2.1 SUPPORT

**Frozen meaning: the observation was made, and the claim is more credible for it.**

It is **contributing** evidence — neither necessary nor sufficient, and stronger than merely
related. Three properties fix that reading and all three are already enforced:

- **Not sufficient.** `AdmitConfidence` grants `HIGH` on authority, never on a count. Two
  supporting observations are `MEDIUM` because *"several independent observations converge"* is
  what `MEDIUM` means; a third does not move it.
- **Not necessary.** Nothing requires a rule to cite every node consistent with its claim.
  `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` cites one reaching node per reached endpoint and says
  why more would be decoration.
- **More than related.** `docs/FINDINGS.md` §3.1 rule 1 and ADR 0078 §2.3 rule 1 state the test a
  rule author applies: **delete the node and a claim changes.** `reachabilityRefs` and
  `admissionScope.refs` both state it in as many words.

**Not checked, deliberately: that supporting evidence is conclusive.** An `UNKNOWN` node is
legitimate support for a claim *about not having measured something*, which is most of what
svcdoctor says when a capability is unsupported. Forbidding it would forbid the honest claim
along with the dishonest one; the dishonest one is the blocked case and it has its own check.

### 2.2 CONTRADICTION

**Frozen meaning: reading A of the four the brief offered — the evidence was observed and is
inconsistent with the claim.** Not B (weakens confidence), not C (supports an alternative), not D.

The three that are refused, and why each refusal is load-bearing:

- **B is refused** because a confidence downgrade is an *effect* a contradiction may have, not
  its definition. `AdmitConfidence` caps a contradicted claim at `LOW`; that is what
  contradiction *does*, and defining it as what it does makes any downgrade retro-fittable as a
  contradiction.
- **C is refused** because supporting an alternative is a relation between evidence and *another
  claim*, and the basis is a relation between evidence and *this* one. ADR 0081 §2.5 already
  settled that two hypotheses coexist unranked, and mutual exclusivity is not represented.
- **A contrast is not a contradiction.** `PASS` at one address and `FAIL` at another is two
  observations about two subjects. It contradicts a universal claim over the set — and every
  set-level rule in the tree is written not to make one. `POSTGRES_ADMISSION_SCOPE`'s
  `detailAdmissionContrast` states the disagreement and attributes no cause, which is the
  contrast being *supporting* evidence for a claim about the set rather than contradicting one.

**Representation stays rule-internal, per ADR 0081 §2.4, and this record upholds it.** A rule
holding contradicting evidence emits nothing or emits a weaker claim. There is no
`contradictedBy` field, and adding one would be ADR 0079 §2.4's negative explosion.

**One consequence the tree already demonstrates, and it is why `.Contradict` has no producer:**
where contradiction is decisive, it fires *before a basis exists*.
`AdvertisedTopologyUnsuitable` skips the subject entirely when `len(t.reached) > 0`, and its own
doc comment names that as the contradiction test. A rule that returns before constructing a
basis has nowhere to record `Contradict`, and giving it somewhere would mean emitting the finding
it just decided not to emit.

### 2.3 MISSING

**Frozen meaning: a specific observation that would discriminate between the explanations that
remain was never made, and there is no evidence node for it.**

It is one of the six listed possibilities and not a union of them. Precisely:

| Situation | Is it `MISSING`? | What it is instead |
|---|---|---|
| a discriminating observation was never made and has no node | **yes** | — |
| a node exists in `UNKNOWN` with an `EXEC_*` or capability class | **no** | ADR 0086 §2.1 position 4 |
| a step did not run because an upstream one failed | **no** | position 5 — `BLOCKED` |
| svcdoctor's own budget cut the run short | **no** | position 6 — `RuleContext.Incomplete` |
| an input was not configured | **no** | a `SKIPPED` node with `EXEC_REQUIRED_INPUT_MISSING`, which four services already turn into a finding |
| an observation does not exist as a concept | **no** | not representable; `domain.Step` is a closed vocabulary |

**The type enforces the boundary.** `Missing()` returns `[]domain.Step`, not `[]EvidenceID`,
because a missing observation has no identifier — nothing was recorded, so there is no node to
point at. That is also why an `UNKNOWN` node cannot be recorded as missing without lying about
its own type: it *has* an identifier.

**Absence is never contradiction**, and `AdmitConfidence` states it structurally: a missing
observation never raises confidence and never lowers it. Its one effect is to make
`AuthorityCompleteContrast` a **false declaration** — an error, not a downgrade.

**Budget exhaustion does not make an observation missing.** ADR 0086 §2.1 gives position 6 its
own representation, and `RuleContext.Incomplete` exists precisely so a rule can tell the two
apart. A rule that recorded a budget-cut step as `MISSING` would be claiming that observing it
would discriminate, which it has not established.

### 2.4 BLOCKED, and its relation to `Graph.BlockedBy` — **Model A**

**Frozen: Model A. `EvidenceBasis.blocked` is a finding-local *reference* to graph nodes whose
observations were prevented by a failed prerequisite. It is a projection of `Graph.BlockedBy` and
never a second meaning of "blocked".**

Models B and C are both rejected, and the reasons are structural rather than stylistic:

- **Model C — a distinct epistemic relation — is rejected** because `Freeze` check 4 already
  makes it impossible. A node cited as blocked must be recorded blocked *by the graph*; a rule
  cannot label one. There is no room for a second sense to live in, and inventing one would give
  the repository two vague "blocked" concepts, which §7 of the phase brief rightly refuses.
- **Model B — redundant, leave it unused — is rejected as a description**, while its *practical*
  consequence is adopted: the relation is exact, not redundant, but it has no reader, so nothing
  is activated. `Graph.BlockedBy` answers *"what stopped this node"* over the whole graph;
  `EvidenceBasis.blocked` would answer *"which of those this claim declined to read"*. They are
  different questions with one underlying fact. Calling it redundant would invite deleting a
  check that is doing work.

**The subordination rule, stated once so it cannot drift:**

> `basis.blocked` ⊆ { n : `len(g.BlockedBy(n)) > 0` }, enforced by `Freeze` check 4; and
> `basis.blocked` ∩ (`basis.supporting` ∪ `basis.contradicting`) = ∅, enforced by checks 2 and 3.
> Blocking is **recorded by whoever decided not to run the step** and is never inferred by a rule.
> `AddBlockedBy` additionally admits only `SKIPPED` nodes, so a node that ran can never be
> excused as blocked.

**`blocked` is not `failed`, and the tree already keeps them apart.** `internal/diagnosis/transport/tls.go`
returns early unless the node is `FAIL`, so a TLS step skipped because TCP failed produces **no
TLS finding at all** — which is the answer to the brief's §6.C: *no downstream claim is
fabricated in order to populate `BLOCKED`*, and none may be. `Boundary` computes the blocked
chain and `DIAG_FAILURE_BOUNDARY` deliberately cites none of it, saying so in `detail`.

### 2.5 The two citation surfaces are distinct — **ADR 0086 §2.1 row 1 is superseded**

**Supersession, stated once and unambiguously.** ADR 0086 §2.1 row 1's "Representation today"
cell reads *"`EvidenceBasis.supporting` → `Finding.EvidenceRefs`"*. **That cell is withdrawn.**
The arrow holds for the one rule that uses a basis and fails for three findings that do not
(§1.3), so it is not a projection with exceptions — it is not a law. **This section is
authoritative for position 1's representation from Phase 10.5A onward.** Rows 2 through 7 of
ADR 0086 §2.1, its six forbidden collapses and every other decision in that record are untouched
and remain authoritative.

The replacement, in three parts:

> **1. `Finding.EvidenceRefs` is the public citation surface of a finding.** It is what the
> report carries, what ADR 0014 validates for membership, and what a reader checks a claim
> against. It admits any node in the graph, **including a graph-blocked one, when the claim's
> subject is the step that did not run**.
>
> **2. `EvidenceBasis.supporting` is an internal epistemic subset**: observed evidence that
> *contributes support to the claim*. It is not serialized, and `BasisBuilder.Freeze` check 3
> excludes a graph-blocked node from it unconditionally, because a step that never ran supports
> nothing about the subject's condition.
>
> **3. Therefore the containment runs one way, and only one way.** Supporting evidence is always
> valid finding evidence — every member of `basis.Supporting()` is an admissible `EvidenceRef` —
> but **not every `Finding.EvidenceRef` is supporting evidence**. `EvidenceRefs =
> basis.Supporting()` is a sound projection for a rule whose claim is about the subject's
> condition, and it is **not** a general law about findings.

**`BasisBuilder.Freeze` is not weakened by this, and must not be.** Check 3 is correct for what
it governs. What changes is only the claim made *about* it: it constrains the epistemic subset,
never the public citation surface.

Both surfaces are right for their own claim shape, and the distinction is exactly the one
`docs/FINDINGS.md` §3.1 rule 11 draws: a blocked step is never cited **as a cause**; it may be
cited **as the subject**. `Freeze` check 3 states the first half correctly and, because it is
stated over the whole supporting set rather than over the causal part of it, also forbids the
second — which `basis.go`'s own doc comment endorses one paragraph earlier, in the sentence about
an `UNKNOWN` node supporting a claim about not having measured something.

**Nothing is changed in 10.5A.** Which half moves — the check narrows, or the three findings
change what they cite — is a decision for the phase that has a reason to make it, and §2.11 gives
the condition.

### 2.6 Confidence interaction

**Frozen, and all four are properties of `AdmitConfidence` as it stands:**

1. **Contradiction only ever lowers**, and it lowers to `LOW` outright. There is no arithmetic
   and none is authorized: `HIGH − contradiction = MEDIUM` and every equivalent is refused
   permanently.
2. **Missing neither raises nor lowers.** Its one effect is to turn a complete-contrast
   declaration into an error.
3. **Blocked bears on nothing**, because checks 3 and 4 prevent a blocked node from reaching a
   position where it could matter.
4. **"No contradicting evidence exists" is established today by the rule emitting nothing**, not
   by a check over a populated set. `len(basis.contradicting) > 0` is unreachable in production.

**Two guards are therefore vacuous, and this record says so rather than implying they are live:**

- the complete-contrast/missing check, because `Miss` has no producer — and it is safe only
  because `AuthorityCompleteContrast` has none either. **They must acquire producers in the same
  change-set or the check stops protecting anything.**
- the contradiction cap, because `.Contradict` has no producer.

**Activation would change existing confidence output**, and that is the finding, not a side note.
Any rule that adopts the ladder must declare an authority, and for a claim that restates
svcdoctor's own measurement neither admitted ground is truthful: `DIAG_FAILURE_BOUNDARY` would
fall from `HIGH` to `MEDIUM`. **No third `Authority` is added here.** Adding an admission ground
with no rule wired to it is the inversion ADR 0054 forbids; the condition that would justify one
is in §2.11.

### 2.7 Convergence

**Frozen: no basis relation reaches convergence, and none may without a schema decision first.**

`Converge` operates on `domain.Finding`, which carries `EvidenceRefs` and nothing else from a
basis. The basis is destroyed at the rule boundary. Every question the brief asks about
relation-aware convergence — union, dedup, ordering, whether `SUPPORT` from one finding may merge
with `CONTRADICTION` from another, whether `MISSING` disappears when a convergent rule supplies
the evidence, whether `BLOCKED` survives when another path measured the observation — is
therefore **unreachable today**, and answering any of them now would be freezing a mechanism from
measurement of what does not exist (ADR 0086 §2.0).

Two constraints bind whoever makes them reachable, and both follow from Phase 10.2A:

- **A relation must never become a merge input that a consumer parses without being a
  precondition.** ADR 0081 §2.2b's rule is that `Summary` and `Detail` are preconditions because a
  merged claim must not describe half its own evidence. A merged `MISSING` set is exactly that
  shape: two rules asking different open questions would produce a union that neither asked.
- **A relation must never reach semantic identity.** Identity is `(Code, Subject)` (ADR 0081
  §2.1) and adding a relation to it would make a report depend on which observations a run
  happened to omit.

### 2.8 Canonical report and schema

**Frozen: no basis relation is serialized in `SchemaVersion` 1, and activation of any relation is
output-semantic only until a schema decision says otherwise.**

- `domain.Finding`'s JSON carries `evidenceRefs` and `discriminator`. It carries no relation
  class, and `EvidenceBasis` is not a report type.
- **`blockedBy` *is* already serialized**, on the graph projection (`domain/report.go:258`), and
  `docs/REPORT_SCHEMA.md` §378–384 already documents the consumer path: *cited node → its
  `blockedBy` → why a downstream step never ran*. **Position 5 is therefore already legible to a
  consumer without any finding-level field**, which is the strongest argument that
  `EvidenceBasis.blocked` needs no report representation at all.
- **No renderer reads `BlockedBy`** and none exposes a relation class. No renderer design is
  added here; ADR 0086 §2.8's additive-field rules govern if one is ever needed.

**`SchemaVersion` stays 1. `RunSchemaVersion` stays 1. No field is added in 10.5A.**

### 2.9 `MISSING` and `NEXT_EVIDENCE`

**Frozen: neither implies the other, and neither implication may be frozen as an invariant.**

The repository falsifies one direction outright: **`NEXT_EVIDENCE` without `MISSING` is the only
shape that exists.** Four production `NEXT_EVIDENCE` recommendations are emitted — two by
`kafka/topology.go`, two by `postgres/admission.go` — and `Miss` has zero producers, so
*"every `NEXT_EVIDENCE` corresponds to a `MISSING` relation"* is already false in the tree.

The other direction is unmeasurable and stays unfrozen: with no `MISSING` producer, *"every
`MISSING` has a `NEXT_EVIDENCE`"* has no instance to be true or false about.

**What is frozen instead is the weaker, checkable statement:** a `MISSING` relation *may* be the
structured justification for a `NEXT_EVIDENCE` recommendation, and the two remain separately
constructed. A discriminator may name an unresolved observation with no `MISSING` relation behind
it — `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` does exactly that today — and that stays legitimate.

The live binding is the one ADR 0086 §2.10 already froze and 10.4B enforced: a `HYPOTHESIS`
carrying a `Discriminator` carries at least one `NEXT_EVIDENCE` recommendation
(`test/diagnosis/nextevidenceinvariant_test.go`, one recorded exception, pinned at size 1). That
invariant is between a *finding field* and a *recommendation*. It does not reach the basis and
must not be re-stated over it.

### 2.10 The producer admission bar

A production producer for `.Contradict`, `.Miss` or `.Block` is admitted only when **all thirteen**
hold. They are the brief's twelve, plus one this archaeology forces:

1. the rule already computes the fact today;
2. no new probe or protocol observation is needed;
3. the relation is strictly more precise than the current representation;
4. it is derived deterministically;
5. no prose interpretation;
6. no regex or server-message interpretation;
7. no probabilistic reasoning;
8. no confidence arithmetic;
9. no hypothesis invented to consume it;
10. it survives convergence without semantic ambiguity;
11. it is explainable from canonical evidence references;
12. it does not turn absence into contradiction;
13. it does not duplicate `Graph.BlockedBy` under a second model;
14. **it has a reader in the same change-set.** ADR 0054's *owner before producer*, applied to a
    primitive rather than a failure class: a relation written and read by nothing is a producer
    with no owner, and ADR 0086 §2.11's mirror — *producer before engine* — refuses the inverse
    for the same reason.

### 2.11 Admitted producers: **none**. Phase 10.5B is not opened

Every candidate was audited against §2.10 and every one fails. The register is in
`docs/validation/PHASE105A_EVIDENCE_RELATION_AUDIT.md` §4; the four that came closest:

| Candidate | Relation | Fails on |
|---|---|---|
| `AdvertisedTopologyUnsuitable`'s reached-endpoint gate | CONTRADICTION | **1** — the fact is computed *before* a basis exists, and recording it would mean emitting the finding the rule just declined to emit. ADR 0081 §2.4's chosen representation is that suppression |
| `AdvertisedEndpointUnreachable`'s `verdictIncomplete` unmeasured paths | MISSING | **3, 12** — the unmeasured paths are `UNKNOWN` nodes with local classes, which is position 4 and not position 3. They have identifiers; `Miss` takes a `Step` precisely because a missing observation has none |
| `POSTGRES_ADMISSION_SCOPE`'s `undetermined` set | MISSING | **3, 12** — the same, and worse: the finding's claim is *"no admission decision was observed at N"*, so those nodes are **supporting evidence for a count**, not an absence. Moving them would delete a citation the claim rests on |
| `Boundary.Blocked()` in `DIAG_FAILURE_BOUNDARY` | BLOCKED | **14, and 3** — it is the one place a rule computes graph blocking and discards it, but nothing would read it, the finding's output would not change, and §2.8 shows the fact already reaches a consumer through the serialized `blockedBy` edge |

**The outcome is DEFER.** Unused abstraction is preferable to false epistemic semantics, and the
four relations are not latent for want of attention: three of them are latent because the tree's
rules are written in the shapes ADR 0081 §2.4 chose for them — suppression, an `UNKNOWN` node, a
graph edge — and those shapes are the correct ones.

---

## 3. Consequences

- **No Go file changes in Phase 10.5A**, and no Phase 10.5B is proposed.
- **ADR 0086 §2.1 row 1 is superseded by §2.5 of this record**, and ADR 0086 carries a forward
  marker at the row and in its header, so authority is legible from either document without
  reconstructing history. The supersession is narrowing: it withdraws a law that was never true,
  and nothing depended on it. Rows 2–7 and every other ADR 0086 decision stand.
- **Two vacuous guards are now written down as vacuous.** `AuthorityCompleteContrast` and `Miss`
  must acquire producers together; a future phase that adds one without the other removes the only
  defence against a false complete-contrast declaration. `REL-014` states it as a requirement.
- **`docs/FINDINGS.md` §3.1 gains rule 20**, the rule-author-facing form of §2.5: a blocked node
  may be cited when the claim is about that node not having run, and never as evidence about the
  subject's condition. Three existing findings are its instances, so it documents the tree rather
  than constraining it further.
- The four relations remain frozen vocabulary with one producer between them. `EvidenceBasis` is
  correctly described as a **reasoning-time checking value**, not a producer surface, and
  `basis.go`'s doc comment already says so.

---

## 4. Alternatives considered

**Activate `.Block` in `DIAG_FAILURE_BOUNDARY` because the fact is already computed.** Rejected on
bar item 14. `Boundary.Blocked()` would be written into a basis nothing reads, on a finding whose
bytes would not change, duplicating a fact the report already serializes on the cited node's
`blockedBy` edge. It is a primitive manufacturing its own producer.

**Activate `.Miss` for the two "not measured" aggregate branches**, on the argument that a
next-best-evidence input is exactly what those branches lack. Rejected on bar items 3 and 12, and
it would be actively harmful: both rules currently cite the unmeasured nodes as *support for a
count they state*, and `Miss` cannot hold an identifier, so activation would delete evidence from
`EvidenceRefs` and replace it with a `Step` naming a stage that does have nodes. Less precision,
not more. This is the brief's §6.A answered from the rules' own prose: the findings are phrased
only over measured members, so "not measured" is inside the claim and not missing from it.

**Add a third `Authority` — "the claim restates a measurement svcdoctor took directly" — so the
ladder can be adopted.** Rejected for this phase and recorded as the sharpest deferred item. It is
a real gap (§1.3) and it is a *contract* change to ADR 0081 §2.3, which admits `HIGH` on exactly
two grounds. Freezing an admission ground in a phase forbidden to write production code would
leave a third zero-producer primitive beside the three this record just declined to activate.

**Add a `contradictedBy` report field so contradiction has somewhere to go.** Rejected, and
permanently: ADR 0079 §2.4's negative explosion, upheld by ADR 0081 §2.4, and re-affirmed here.
The revisit condition stays what ADR 0081 gave it — a support workflow needing to know *why a
hypothesis was not emitted* is a debugging surface, answered by rule tests and a verbose mode.

**Narrow `Freeze` check 3 now, so the three withheld/scope findings could adopt a basis.**
Rejected: it is a security-adjacent relaxation of the check that implements ADR 0081 §2.4's
sharpest case, and relaxing it with no rule waiting to use the relaxation is the same inversion.
The condition is in §2.11's register.

**Declare `EvidenceBasis` dead and delete the three unused relations.** Rejected. The vocabulary
is what makes the six forbidden collapses *statable*, and `Freeze`'s checks are what make a rule's
reasoning checkable. Deleting them would remove the guard that catches the first rule to get it
wrong, in exchange for four fewer methods.

---

## 5. Security implications

None introduced; the phase writes no Go.

Two properties are re-affirmed because an activation phase would be the place to lose them.
`RuleContext` still carries three fields and no credential, clock, socket or service name, so a
rule cannot leak a credential by construction (ADR 0080 §2.1). And `Missing()` names steps from
svcdoctor's own closed vocabulary rather than evidence identifiers, so a missing observation can
never be named with a string a peer chose (ADR 0081 §2.7) — which is a redaction property, not
only a taste one.

One thing this record makes harder to get wrong: §2.5 states in advance that citing a blocked
node is legitimate **only** when the claim's subject is the step that did not run. Without that
written down, the obvious reading of `Freeze` check 3 is that the three existing findings are
defects, and "fixing" them would delete the citation that lets an operator see *why* a credential
was withheld.

---

## 6. Compatibility implications

**None.** `SchemaVersion` 1, `RunSchemaVersion` 1, 65 finding codes, 42 failure classes, 4
`Reveal` and 4 `SecretFor` production call sites, 2 external modules, 5 exit codes — all
unchanged, and no report byte moves. `docs/COMPATIBILITY.md` is untouched: this record claims
nothing about any platform.

---

## 7. Validation requirements

`docs/validation/PHASE105A_EVIDENCE_RELATION_AUDIT.md` holds the register, `REL-001` … `REL-018`,
each classified `FROZEN`, `10.5B` or `DEFERRED`. Nothing in it requires a new test in 10.5A: every
`FROZEN` requirement is already enforced by a named existing test, which is what an archaeology
phase should be able to say.

The one requirement that would fail today if it were asserted as written is **`REL-009`** — that
`basis.Supporting()` can produce every production `EvidenceRefs` set, which is the superseded
row 1 restated as a test. It is classified `DEFERRED`
with §2.5's condition, rather than written as a test that the tree would fail.
