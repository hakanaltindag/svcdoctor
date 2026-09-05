# ADR 0081 — Hypothesis identity, confidence semantics and evidence relations

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
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
| `Summary` / `Detail` | the winner's, chosen by the deterministic tie-break in §2.6 |
| `Recommendations` | union by action text, order preserved from the tie-break winner |
| `Discriminator` | the winner's; empty once `Kind` is `CONFIRMED` |
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
- Mutation: accumulate confidence on convergence; treat missing evidence as contradiction;
  allow `HIGH` for a hypothesis without direct authority; break merge ties by wiring order;
  deduplicate by summary text.
