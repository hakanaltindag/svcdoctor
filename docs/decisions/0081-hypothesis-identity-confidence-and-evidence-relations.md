# ADR 0081 — Hypothesis identity, confidence semantics and evidence relations

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Amended:** Phase 10.1B (§2.2a, a clarification) and **Phase 10.2A (§2.2b and §2.6a, a
supersession of one row of §2.2's merge table)**. The amendments are dated in place and the
superseded text is left standing with a marker, so the reasoning that was wrong stays legible.
**Refines:** ADR 0014 (findings reference evidence by identifier), ADR 0017 (which deferred
finding identity), `docs/FINDINGS.md` §3.1.

---

## 1. Context

Once several rules reason over one graph, four questions arrive together and cannot be answered
separately:

1. When are two hypotheses **the same hypothesis**?
2. What makes confidence `HIGH` rather than `MEDIUM`, in a way that can be tested?
3. How is **contradicting** evidence different from **missing** evidence and from **blocked**
   evidence?
4. How do competing explanations coexist without svcdoctor picking a favourite?

ADR 0017 explicitly deferred finding identity: "deciding which of two findings to discard would
require defining when two findings are the same conclusion, which no document does." This is
that document.

## 2. Decision

### 2.1 Semantic identity is `(Code, Subject)`

Two findings are the same conclusion when they carry the same finding code about the same
subject. Not the same prose, not a fuzzy string match, not a hash of the summary.

This works because the existing model already made it work: a finding code is one independent
claim (`docs/FINDINGS.md` §3.1 rule 1), and a subject is the thing the claim is about. Two rules
that reach `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` about `broker-3:9093` from different evidence
have reached one conclusion by two routes.

A finding with no subject — a run-level claim — has identity `(Code, ∅)` and there can be at
most one.

### 2.2 Convergence merges; it does not accumulate copies

When two rules produce findings with the same identity, the engine merges them:

| Field | Merge rule |
|---|---|
| `EvidenceRefs` | union, deduplicated, sorted — the merged claim rests on both routes |
| `Confidence` | the **maximum**, but only if §2.3's ladder admits it; see below |
| `Kind` | `CONFIRMED` wins over `HYPOTHESIS`: a proof and a guess about the same thing means it was proven |
| `Severity` | the maximum |
| `Summary` / `Detail` | **superseded by §2.2b: MUST_EQUAL, a merge precondition.** Originally: the winner's, chosen by the deterministic tie-break in §2.6 |
| `Recommendations` | union by action text. **§2.2b replaces the ordering:** content order, not the tie-break winner's |
| `Discriminator` | the group's one non-empty value; empty once `Kind` is `CONFIRMED` |
| `VantageDependent` | logical OR — if either route is vantage-dependent, the claim is |

**Confidence does not add up.** Two `MEDIUM` routes to the same conclusion produce `MEDIUM`,
not `HIGH`. Independent convergence is what §2.3 already calls `MEDIUM`; promoting on count
would make confidence a vote, and a vote is arithmetic scoring wearing an ordinal costume. A
merged finding may reach `HIGH` only if one of the merged inputs independently qualified for
`HIGH`.

This overturns nothing in ADR 0017: that record declined to deduplicate *because no definition
existed*, and it named the missing definition as the blocker. §2.1 supplies it.

### 2.2a Clarification (Phase 10.1B): identity is candidacy, not a licence

**Status of this section:** a clarification recorded during implementation. It
changes no decision in §2.1 or §2.2 — semantic identity is still `(Code, Subject)`
and the merge table above is unchanged — and it answers a question the table did
not: *which fields must already agree before the table is applied.*

The table assigns `Summary` and `Detail` to the tie-break winner and says nothing
about `Layer`. Phase 10.1A filled that silence with "the winner's" and Phase
10.1B measured what that does.

`POSTGRES_CONNECTION_NOT_PERMITTED` is produced by two rules about one endpoint
at two layers, deliberately: `postgres/startup` anchors it at L4 and
`postgres/authentication` at L5, and `internal/diagnosis/postgres/shared.go`
records the reason — "the claim's layer is the anchor's own and the two anchors
sit at different ones". Merged under a tie-break, the published finding claimed
**L5 while citing the startup node**, because `postgres/a…` sorts before
`postgres/s…`. A refusal observed at the protocol stage would have been published
as an authentication-stage claim, decided by an alphabet.

**The rule.** Two findings that share a semantic identity may converge only when
every field a consumer *parses* already agrees. Where they differ, both are kept.

Concretely, the merge preconditions are:

| Field | Precondition |
|---|---|
| `Layer` | must be equal |
| `Discriminator` | at most one distinct non-empty value; an unset one joins a set one |

`Layer` qualifies because it is structured metadata a consumer reads and one of
the keys `domain.SortFindings` orders by. `Discriminator` qualifies because two
hypotheses naming different observations are asking different questions, and
reducing them to one silently discards a question.

`Summary` and `Detail` are **not** preconditions and keep the winner's value,
which §2.2 decided explicitly. That is safe precisely because everything a
consumer parses now has to match: once `Code`, `Subject` and `Layer` agree, the
two routes state one claim at one layer, and which wording survives changes
nothing machine-readable. Prose is explicitly not identity (§4) and is explicitly
free to be reworded (`docs/FINDINGS.md` §3.1 rule 13).

> **Superseded by §2.2b (Phase 10.2A).** The paragraph above is left as written
> because the reasoning is legible and the mistake in it is worth seeing. Its
> hidden premise is that a finding's prose says nothing its structured fields do
> not, and Phase 10.2's Kafka rules — which name a broker node identifier in
> prose under a subject that carries only the endpoint — falsify it. Prose is now
> a merge precondition.

**Why this is not an identity change.** Adding `Layer` to `(Code, Subject)` would
produce the same output and would rewrite §2.1. Expressing it as a merge
precondition leaves the identity definition alone and fills the gap §2.2 left,
which is the smaller of the two changes for the same behaviour.

**Why it is not the alternative that discards.** Refusing to *emit* on a
mismatch, or picking the shallowest layer, would each drop or invent something.
Keeping both findings loses no evidence and states no layer nobody measured; it
is weaker than merging, and weaker is the safe direction.

Measured at the time of writing: across all 61 finding codes, `Layer` varies for
exactly one, and `Severity`, `Kind`, `Confidence` and `Discriminator` are constant
at every construction site. `VantageDependent` varies for three codes and is
reconciled by logical OR, which is order-independent and is what OR is for. The
full matrix is in
`docs/validation/PHASE101B_DIAGNOSTIC_ACTIVATION_VALIDATION.md`.

### 2.2b Supersession (Phase 10.2A): prose is a merge precondition

**Status of this section:** it **supersedes** one row of §2.2's table. §2.2a was a
clarification — it filled a silence. This is not: §2.2 said *"`Summary` / `Detail` — the
winner's, chosen by the deterministic tie-break in §2.6"* explicitly, §2.2a re-affirmed it, and
Phase 10.1B's validation defended it at length. That decision is withdrawn.

| Field | §2.2 said | Now |
|---|---|---|
| `Summary` | the tie-break winner's | **MUST_EQUAL — a merge precondition** |
| `Detail` | the tie-break winner's | **MUST_EQUAL — a merge precondition** |
| `Recommendations` | union by action text, winner's order first | union by action text, **content order** |

Everything else in §2.2 stands unchanged.

#### Why the original argument fails

It was: once `Code`, `Subject` and `Layer` all match, the two routes state one claim at one
layer, so which wording survives changes nothing a consumer parses. Prose is not identity (§4)
and is free to be reworded (`docs/FINDINGS.md` §3.1 rule 13).

The hidden premise is that **a finding's prose says nothing its structured fields do not**.
Phase 10.2 built the first rules that break it, and Phase 10.2A measured three shapes that a
real Kafka cluster can produce:

1. **Two brokers advertised at one endpoint.** `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` carries
   the broker node identifier in its summary and only the endpoint in its subject — deliberately,
   because `docs/REPORT_SCHEMA.md` has no subject kind for a service-internal integer (ADR 0034
   §12). Two such findings shared an identity and a layer while describing different brokers.
   The merge published *"for broker node 2"* over evidence from nodes 2 and 7, and node 7's
   claim ceased to exist. **ADR 0034 §10 had already decided the opposite** — *"two
   advertisements naming one endpoint are two facts and produce two findings; nothing
   deduplicates by endpoint or by node identifier"* — so the tie-break silently overrode an
   Accepted decision.
2. **The same shape for `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`.**
3. **A CONFIRMED claim and a HYPOTHESIS at one endpoint.** The unset discriminator folded into
   the set one, `CONFIRMED` absorbed `HYPOTHESIS`, the discriminator was cleared, and the report
   stated that an endpoint whose paths were never finished measuring *could not be reached*.
   **Less evidence produced a stronger claim**, which is the failure this project names by name.

None of these is a defect in a rule. Each rule said something true; the engine chose between two
true sentences and published one of them over both sets of evidence.

#### The decision

**A group may be merged only when its members already agree about every field the merged
finding *takes* rather than *reconciles*.** Concretely, the merge preconditions are now:

| Field | Precondition |
|---|---|
| `Code`, `Subject` | equal — they are the identity |
| `Layer` | equal (§2.2a) |
| `Discriminator` | at most one distinct non-empty value (§2.2a) |
| `Summary` | **equal** |
| `Detail` | **equal** |

Where they differ, both findings are kept. `Severity`, `Confidence`, `Kind`,
`VantageDependent`, `EvidenceRefs` and `Recommendations` remain reconciled exactly as §2.2 says,
because every one of those operations is order-independent.

This is a **strict narrowing**. A group that used to merge either still merges byte for byte, or
becomes two findings that each state exactly what their rule stated. Convergence can now produce
*more* findings than before and never a *different* one, which is why no golden output moved.

#### Byte equality, and no fuzzy matching

Two rules that mean one claim write one sentence, and the ordinary way to do that is to share a
constant. Byte equality is the only comparison a rule author can predict and a test can state.

Similarity scoring is refused for the same reason §2.1 refuses prose as identity: it would make
a merge depend on a threshold, a typo would silently split or join conclusions, and no reviewer
could tell which. **If two rules cannot share a constant, they did not mean the same thing.**

#### What replaces the tie-break

Nothing. There is no winner. Every field a merged finding takes is a precondition, so the
representative could be any member without changing a byte — which is what makes §2.6a below a
structural property rather than a tested hope.

#### The consequence that is a feature, not a regression

A report may now carry two findings with one code, one subject and one layer, saying different
things. That looks like duplication and is not: it is two claims that were always there, one of
which used to be discarded. A renderer showing both is showing what was measured. The
alternative — one finding whose sentence describes half of its own evidence — is the shape this
supersession exists to make unreachable.

#### The one production convergence, unaffected

Kafka reaches `KAFKA_AUTH_MECHANISM_NOT_OFFERED` about one endpoint from the SASL handshake step
and the SASL authenticate step, with byte-identical summary, detail and recommendation. It is a
genuine two-routes-one-claim case, it still merges, and the merged finding cites both nodes.

#### A note on §2.1's run-level sentence

§2.1 ends *"a finding with no subject has identity `(Code, ∅)` and there can be at most one of
it"*. That is a statement about **identity**, and it stands. It is not a guarantee that two
run-level findings always merge into one — under these preconditions they merge when they say
the same thing and stay apart when they do not, exactly as for subject-bearing findings. No
run-level finding code exists (ADR 0073 §12 declined to create one), so nothing depends on the
stronger reading.

### 2.6a The rule-identity rename property (Phase 10.2A)

**Renaming a `RuleID`, while preserving the rule's semantics and the registration set, must not
change the canonical diagnostic meaning of a report.**

A rule identity is svcdoctor's internal name for a piece of code. It is not serialized (ADR 0080
§2.5), no consumer can see it, and renaming one is a refactor. A claim that moved when a rule was
renamed would mean the report encoded a fact about svcdoctor's source tree, which is not a fact
about the target.

It must never alter `Layer`, `Kind`, `Severity`, `Confidence`, `Discriminator`, recommendation
meaning **or order**, `Summary` or `Detail`.

Before Phase 10.2A this property did not hold, in two places. Prose came from the RuleID winner,
so a rename could change the published sentence. And the recommendation union was ordered
"winner first, then by RuleID", so a rename could reorder a user-visible array. Both are gone:
prose is a precondition, and the union is ordered by the findings' own content — evidence, then
the reconciled fields, then the advice.

§2.6's tie-break by `RuleID` therefore no longer has a subject. It is retained in this record as
history: the ordering it defined is the one this section removes.

**How it is held.** `TestC06ARuleIDRenameCannotChangeAnything` rewrites every identity in an
input through five namings — including ones that reverse the original alphabetical order, and one
that gives every rule the same name — and requires the encoded output to be byte-identical.
`TestC06TheRenamePropertyHoldsForRecommendationOrderToo` isolates the array-order half. Mutation
`C-M04` restores the RuleID sort and must be caught.

### 2.3 The confidence ladder

Confidence is **epistemic strength only** and stays ordinal — `LOW`, `MEDIUM`, `HIGH`, no
percentages, no scores, no arithmetic. The definitions are stated as *admission tests* a rule
must be able to pass, not as adjectives.

**`HIGH` — the peer told us, or the contrast is complete.** Admitted when either:

- **(a) direct authority**: the condition is stated by the peer in its own protocol, in a field
  whose meaning is defined by that protocol — a PostgreSQL SQLSTATE, an AMQP close code, a Redis
  error reply, a Kafka error code; **or**
- **(b) complete contrast**: every alternative explanation that svcdoctor can distinguish has
  been measured and excluded, and the exclusions are cited.

And in both cases: **no contradicting evidence exists** (§2.4), and the claim is about what was
observed rather than about a mechanism behind it (ADR 0078 §2.3 rule 2).

**`MEDIUM` — several independent observations converge, alternatives remain.** The evidence is
consistent with the claim and inconsistent with the obvious alternatives, but at least one
realistic alternative has not been excluded because svcdoctor could not measure it.

**`LOW` — compatible but weakly discriminating.** The evidence would look the same under a
realistic alternative. A `LOW` hypothesis must carry a discriminator, or it should not be
emitted at all (ADR 0083 §2.2).

**The ceiling rule, which is the one that prevents overconfidence:** a `HYPOTHESIS` may not be
`HIGH` unless test (a) applies. If alternatives remain *and* svcdoctor cannot discriminate them,
the claim is at most `MEDIUM`, and if nothing distinguishes it from the alternatives at all it
is `LOW` or absent.

**Confidence is explainable.** The rule that emits a finding states its basis in `detail` — which
protocol field, or which alternatives were excluded and by what evidence. A confidence with no
stated basis is a defect the finding-quality review catches.

### 2.4 Four relations to evidence, and they are not interchangeable

| Relation | Meaning | Representation |
|---|---|---|
| **supporting** | observed, and it makes the claim more credible | `EvidenceRefs` |
| **contradicting** | observed, and it is inconsistent with the claim | rule-internal; suppresses or downgrades |
| **missing** | not observed, and observing it would discriminate | `Discriminator`, and a `NEXT_EVIDENCE` recommendation |
| **blocked** | not observed *because* an upstream step failed | the graph's `BlockedBy`; never either of the above |

**The frozen rule: absence of evidence is not contradicting evidence.** A hypothesis is not
weakened because svcdoctor could not look; it is weakened only by something it *saw*. Blocked
evidence is the sharpest case — TLS was never attempted because TCP failed, so TLS is neither
broken nor healthy, and no rule may read that `SKIPPED` node as evidence in either direction.

**Contradiction is handled inside the rule, not as a report field.** A rule that finds
contradicting evidence emits nothing, or emits a weaker claim, and explains why in `detail`. No
`contradictedBy` field is added, because a report full of explicitly negated hypotheses is the
negative explosion ADR 0079 §2.4 rejects, and because the useful contradiction — "DNS resolved,
so this is not a DNS failure" — is already visible as a `PASS` node plus the boundary.

Revisit condition: if a support workflow needs to know *why a hypothesis was not emitted*, that
is a debugging surface, and the answer is rule tests and a verbose mode — not a report field.

### 2.5 Competing hypotheses coexist, unranked beyond confidence

Two hypotheses about the same subject with **different codes** are different claims and both are
emitted. `KAFKA-A` produces both "unreachable from this vantage point" and "the advertised
address may be unsuitable for this client network", because svcdoctor cannot distinguish them.

- They are **not** ranked against each other beyond their own confidence values. There is no
  score, no ordering hint and no "most likely" flag.
- Ties do not need breaking, because nothing is being chosen.
- **Mutual exclusivity is not represented.** Two hypotheses that cannot both be true are two
  hypotheses; declaring the exclusion would be a third claim requiring its own evidence, and the
  useful consequence — "here is what would tell them apart" — is the discriminator, which each
  already carries.
- The renderer explains the ambiguity by showing both with their discriminators. It does not
  pick one, does not sort by plausibility, and does not hide the second.

### 2.6 Determinism: identities and ordering

- **`FindingID`** is not introduced. Identity is `(Code, Subject)` and is computed, not stored;
  a stored identifier would be a schema addition with no consumer.
- **`RuleID`** is `"<owner>/<name>"` — stable, lower-case, hyphenated, never derived from a
  runtime value.
- **Ordering** is `domain.SortFindings`, unchanged: the canonical order a report already uses.
  Rules run in wiring order and that order does not reach the output.
- **Tie-break for merges** is by `RuleID`, ascending. It is arbitrary and it is stable, which is
  what determinism requires; the alternative — "whichever rule ran first" — makes wiring order
  observable.
- Nothing may be derived from map iteration, goroutine scheduling, a clock, a random source, or
  the order in which endpoints happened to be discovered where the semantics are equivalent.

### 2.7 Peer-controlled text never becomes prose

A server chooses its error strings. A rule may **read** a peer-supplied value to decide what to
claim, and may **not** copy it into `summary`, `detail` or a recommendation.

This is already the standing rule at the wire boundary — "the broker's SASL error message never
leaves the wire package" (ADR 0030) — and Phase 10 restates it because a reasoning layer is
exactly where "include the server's message, it is helpful" gets proposed. A peer-supplied value
reaches the report only as a **normalized evidence attribute**, where it is typed, bounded and
redactable, and never as free text in a claim.

## 3. Consequences

**ADR 0017's deferral is closed.** The engine gains a merge step, and two rules converging on
one conclusion produce one finding with the union of their evidence — which is a better report
than either alone.

**Confidence becomes reviewable.** "Why is this HIGH?" has an answer that cites a ladder rung
and a piece of evidence, and a reviewer can reject it.

**Some hypotheses will not be emitted at all.** A `LOW` claim with no discriminator is noise,
and ADR 0083 §2.2 forbids it.

**Reports will sometimes carry two explanations and no verdict.** That is the intended output
for a genuinely ambiguous incident, and it is more useful than a confident guess.

## 4. Alternatives considered

**String-similarity deduplication.** Rejected. Prose is free to change (`docs/FINDINGS.md` §3.1
rule 13); identity derived from it would be unstable across a wording edit.

**Numeric confidence, even internally.** Rejected. An internal float becomes a displayed float,
and a displayed 0.73 is fake precision over evidence that does not support two significant
figures. The project has held ordinal confidence since ADR 0014 and nothing here needs more.

**Confidence accumulation on convergence.** Rejected — §2.2. It is a vote count, and it would
let three weak rules manufacture a strong claim.

**A `contradictedBy` field.** Rejected — §2.4, with a revisit condition.

**Explicit mutual-exclusion links between hypotheses.** Rejected — §2.5. It is a third claim
needing its own evidence, and the discriminator already delivers the operational value.

**Ranking competing hypotheses.** Rejected. Ranking is choosing, and the premise of the scenario
is that svcdoctor cannot choose.

**Five models for prose ownership, weighed in Phase 10.2A** before §2.2b chose the second:

| | Model | Verdict |
|---|---|---|
| A | keep the `RuleID` winner | **rejected** — it is already publishing a claim no rule made, on three reachable Kafka shapes, and "it is deterministic" answers a different question from "it is true" |
| B | **prose MUST_EQUAL for merge eligibility** | **selected** — mechanical, byte-comparable, no schema change, and a strict narrowing: it can only ever produce more findings, never a different one |
| C | rules emit no prose; the engine generates it from a typed semantic result | rejected for now — it needs a typed payload per finding code, which is a large model addition with one motivating case, and it moves every sentence in the tree out of the package that owns the claim. It is the right answer *if* B ever forces a rule author to duplicate a constant across packages; nothing does today |
| D | one "primary" rule owns prose, others contribute evidence only | rejected — it re-creates the arbitrary choice as a wiring decision, and the composition root would then decide what a report says |
| E | a typed payload determines canonical prose | the same as C with the same blocker; recorded separately because it could arrive without C's renderer implications |
| F | similarity matching on prose | rejected outright — a threshold decides a merge, a typo splits or joins conclusions silently, and no reviewer can tell which. §2.1 already refuses prose as identity for this reason |

The condition that would reopen C or E: a service where two rules genuinely mean one claim and
cannot share a constant because they live in different packages. Kafka's one real convergence
shares a table entry, so it does not.

## 5. Security implications

§2.7 is the security-relevant clause: it keeps attacker-controlled text out of the prose surface
of a document that is designed to be shared. A malicious server that returns a crafted error
string reaches, at most, a typed evidence attribute that redaction processes.

Merging cannot leak: it unions evidence identifiers, all of which are already in the report's
graph and already validated by ADR 0014's membership check.

## 6. Compatibility implications

No schema change. Merging changes the *content* of the findings array — fewer, richer entries —
which is a diagnostic improvement rather than a format change, and `docs/CI.md`'s exit contract
is unaffected because severity is merged by maximum.

## 7. Validation requirements

- Unit: the merge table, field by field, including the confidence non-accumulation rule.
- Property: merging is commutative and associative — the same finding set in any order merges
  to the same result.
- Property: a `SKIPPED`/`UNKNOWN` node never appears in `EvidenceRefs` as support for a claim
  about the subject's health.
- Property: no finding's prose contains any string that appears only in a peer-supplied
  evidence attribute — a fuzz target with adversarial server strings.
- Unit: §2.2a's preconditions — same identity and same layer converges, same
  identity and different layer does not, and no canonical field is chosen by rule
  order (`internal/diagnosis/mergecompat_test.go`).
- Unit: §2.2b's preconditions and §2.6a's rename property — the C01-C10 closure
  suite in `internal/diagnosis/convergeclosure_test.go`, and the three Kafka
  shapes that forced them in `internal/diagnosis/kafka/convergence_test.go`.
- Property: renaming every rule identity, including to one shared name, produces
  byte-identical output.
- Static guard: every finding code reachable from more than one production rule
  is inventoried with the reason it is safe
  (`test/security/convergenceinventory_test.go`), with two non-vacuity proofs —
  the scan must find the one real pair, and must see through a package-level
  claim table.
- Mutation: `scripts/phase102a-mutations.sh` — restore the layer, summary,
  detail and recommendation-order tie-breaks; merge incompatible discriminators;
  merge distinct subjects; lose evidence.
- Mutation: accumulate confidence on convergence; treat missing evidence as contradiction;
  allow `HIGH` for a hypothesis without direct authority; break merge ties by wiring order;
  deduplicate by summary text.
