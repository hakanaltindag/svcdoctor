# ADR 0097 — Every production recommendation is classified, and none of them is a remediation

- **Status:** Accepted
- **Date:** 2026-09-09
- **Phase:** 13.1A (contract freeze; no production, test or CI change)
- **Extends:** ADR 0082, whose vocabulary, guardrails and refusals are unchanged. This record adds
  two rules ADR 0082 deliberately did not make, and reverses one sentence in the domain model.
- **Upholds:** ADR 0078 (*observation != cause*), ADR 0081 §2.2b (a merged field never holds a value
  nobody stated), ADR 0083 §2.1 (additive at schema version 1), ADR 0092 (planning deferred),
  ADR 0096 §2.2 (the three-question scope test) and §2.5 (a recommendation that does not say who can
  take it is incomplete).
- **Supersedes in part:** the doc comment on `domain.NewRecommendation`, which reads *"It is not
  deprecated and is not a legacy path."*

---

## 1. Context

ADR 0082 froze the recommendation model in Phase 10.0: two kinds, seven safety classes, a
self-collectability flag, a rationale, and three guardrails — the high-blast-radius classes refused
outright, next evidence forced to change nothing, and a remediation gated on CONFIRMED and HIGH.
Phase 10.4B moved the vocabulary into the report model so the refusals bind every construction path.

It also, deliberately, reclassified nothing. Two constructors were left standing, and the domain
model said so in as many words: a producer that has not decided what its advice costs *"should say
so by omission rather than guess, and this is how."* At the time that was right. Guessing a
classification for sixty sentences nobody had read would have asserted safety that nobody had
established.

Phase 13.1A read all of them. **73 production recommendations exist; 64 were unclassified.** The
corpus answered the taxonomy question in the negative — every one of the 73 is representable by the
existing model, and **not a single one needs a kind or a class that does not exist**. What it found
instead was a hole underneath the model rather than in it:

> `domain.NewRecommendation` reaches none of ADR 0082's checks. Not `Producible()`, not
> `ChangesNothing()`, not `ValidateActionText`, not the confidence gate.

And **eight recommendations went through that hole carrying instructions to change the target** —
five of them unambiguously: *"Grant this user permissions on the virtual host, for example with
`rabbitmqctl set_permissions`"*, *"Enable SASL PLAIN on this endpoint"*, *"Grant the diagnostic
identity permission to run PING"*, *"Enable TLS for this endpoint"*, *"configure a mechanism
svcdoctor performs"*.

None of them is unsafe to say. Every one sits on a CONFIRMED, HIGH finding and would have passed the
gate had it been asked. **The defect is that nothing asked**, and a model whose guardrails can be
skipped by choosing the other constructor is a model that holds only where someone remembered it.

## 2. Decision

### 2.1 A production diagnosis rule may not decline to classify its own advice

Every recommendation produced by `internal/diagnosis/**` is built through `diagnosis.Recommend`, so
that every recommendation reaching a report has passed ADR 0082's guardrails.

`domain.NewRecommendation` is **not removed** — `internal/security/redaction` needs it to rebuild a
value the type still admits, and deleting that branch would trade a live path for a failure. It is
**forbidden to production rules**, and the prohibition is a structural guard rather than a
convention, because the last five years of this repository's own evidence is that a convention
about which of two constructors to call is a convention that decays.

**This reverses the sentence quoted above.** Omission was the honest answer while nobody had read
the corpus. Someone has now read all of it, and *"nobody classified this"* has stopped being a
finding about the advice and started being a finding about the tree.

### 2.2 `REMEDIATION` remains unreachable, and the five candidates are rewritten rather than promoted

The audit found five recommendations that are remediations in substance. All five would pass
`AdmitAdvice`. **They are still refused**, and the reason is not the confidence gate:

> svcdoctor proved the broker refused this user's access to this virtual host.
> It did **not** prove the refusal was wrong.

Proving a *condition* does not authorize a *policy*. The evidence that makes the finding CONFIRMED
and HIGH is evidence about what happened; the recommendation to grant a permission, enable a
mechanism or turn on TLS is a claim about what the operator intended, and svcdoctor has no
observation of intent. This is ADR 0096 §2.2's third question — *does the claim stop where the
observation stops?* — applied to advice rather than to findings, and it is the same rule that keeps
ADR 0085 from turning `in_hot_standby` into a role finding.

One of the five is worth naming for its own sake: `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`
advises *"configure a mechanism svcdoctor performs"* — it asks the **target** to change so that the
**diagnostic tool** can authenticate. That inverts the product.

So the five are **rewritten as observations or verifications** and then classified. Every one of them
already carries a safe alternative in its own text, except the two whose mutating clause is the whole
sentence; those get a new sentence that verifies whether the observed state is intended.

**Consequence, stated as one:** `RecommendationKindRemediation` keeps zero producers.
`SafetyConfigChange` stays producible and unused. The reachable safety set is the three read-only
classes, and svcdoctor's advice becomes uniformly *"here is what to look at next"*.

Activating `REMEDIATION` later is a new record with its own security review. It is not blocked; it is
unfunded, and the condition is in §7.

### 2.3 One constant, one classification

A `recommend<Name>` constant is classified exactly once. No branch may classify the same constant two
ways.

This is not tidiness — it is what makes the migration provably convergence-neutral. `converge.go`
deduplicates the recommendation union on the **whole five-field value**, precisely so that two
identically-worded recommendations with different classifications coexist rather than one silently
winning (the ADR 0081 §2.2b rule). That safety property becomes a hazard during a migration: one
constant classified two ways would turn one merged recommendation into two. Under this rule every
merge group sees the value it sees today plus four fields identical across the group, and dedup
collapses exactly the same members.

### 2.4 What does not change

The vocabulary, both types, both constructors' signatures, every guardrail, the confidence gate,
`SelfCollectable`'s bool, the rationale requirement, `SchemaVersion` and `RunSchemaVersion`.

The four JSON fields already exist with `omitempty` and shipped in Phase 10.4B. Populating them is
field population, not schema evolution.

## 3. Consequences

- **Canonical JSON gains four populated fields** on 68 finding codes' recommendations. A consumer
  reading `action` alone is unaffected; a consumer diffing whole reports sees the addition.
- **Terminal output gains a classification tag** on 64 recommendations. That is the point rather than
  a side effect: *"you must collect"* and *"svcdoctor can collect"* is the hand-over made visible,
  which ADR 0096 §2.5 makes part of the product boundary.
- **Six recommendation strings change.** That is a behaviour change, it is enumerated in the Phase
  13.1A record, and it is reviewed as prose rather than as metadata.
- **The `SelfCollectable: true` inventory becomes complete**, and today it would be **2** — both
  *"re-run with a larger execution budget."* That is the measurement the planner question has been
  waiting for, and it is why the planner stays deferred.
- No finding code, rule, severity, confidence, evidence reference, failure class or exit code moves.

## 4. Rejected alternatives

**Classify the five as `REMEDIATION`.** They would pass every gate. Refused because the gate is about
evidence strength and the problem is evidence *scope*: a CONFIRMED refusal is not a confirmed opinion
about whether the refusal was correct. Accepting them would make svcdoctor's first remediation a
policy recommendation, which is the worst possible first one.

**Make `SECURITY_WEAKENING` producible so that "Enable SASL PLAIN" can be classified honestly.**
Refused, and it is the sharpest case in the set. The class exists so the prohibition is nameable; the
correct response to advice that would weaken security is to stop giving it, not to label it.

**Remove `domain.NewRecommendation`.** Refused: redaction rebuilds unclassified values through it,
and the type still admits them. Removing the constructor would not remove the state.

**Leave the unclassified path available "for producers that have not decided."** That is the status
quo, and the corpus is what it produced: eight target-mutating sentences with no safety class, in a
tree whose entire safety model is built on that class existing.

**Add an `OPERATOR_CHECK` kind for the 41 "Check…" recommendations.** Refused: they are observations
that reduce diagnostic uncertainty, which is what `NEXT_EVIDENCE` means. The distinction the proposal
was reaching for — who performs the observation — is `SelfCollectable`, on an orthogonal axis. A kind
that duplicates a field is decoration.

**Add a `DIAGNOSTIC_EXPERIMENT` kind.** Refused for want of a member: the corpus contains no
recommendation that changes something temporarily in order to discriminate.

**Add a stable `RecommendationCode`.** Deferred, not refused. After classification, `kind`, `safety`
and `selfCollectable` discriminate for every routing decision a consumer makes today, and dedup keys
on the whole value already. Reopen when a consumer names itself.

## 5. Security implications

This record **closes** a gap rather than opening one. Today a recommendation can instruct a
permission grant, a TLS change or an authentication-mechanism change with no safety class attached,
because the constructor that built it never asked. After 13.1C no production recommendation instructs
a change to the target at all, and the guard that keeps it so is structural.

No credential exposure changes. Classification adds no evidence, contacts nothing and reads nothing
new. The rationale field is redacted through the same transformation as the action, and it is frozen
as svcdoctor-owned bounded prose: no peer bytes, no runtime error text, no formatted attribute value.
`ValidateActionText` — which already refuses command-shaped advice across all 73 strings — is
unchanged and begins running on the 64 that previously bypassed it.

One residual is recorded rather than claimed away: `RABBITMQ_VHOST_ACCESS_REFUSED` names
`rabbitmqctl set_permissions`, and it passes `ValidateActionText` only because that command carries
no single-hyphen flag and no shell metacharacter. ADR 0082 rule 3 says *state what to look at, not
what to type*, and that sentence types. It is fixed by the rewrite rather than by widening the
validator.

## 6. Verification

`docs/validation/PHASE131A_RECOMMENDATION_CLASSIFICATION_CONTRACT_FREEZE.md` is the measurement:
the complete 73-row inventory, the per-service distribution, the eight-row high-risk table, and the
guard and mutation design.

Phases 13.1B and 13.1C implement it, and the guards R-G01 (every production recommendation is
classified), R-G02 (no legacy production caller), R-G04 (no mutating imperative in a read-only class)
and R-G06 (no `REMEDIATION` producer) are what make this record enforced rather than remembered. Each
requires a companion proving it can fail.

## 7. Reopen conditions

| Item | Condition |
|---|---|
| `REMEDIATION` gains a producer | A recommendation whose action is authorized by the same evidence that authorizes its finding — that is, where svcdoctor observed the intent as well as the state. Its own ADR and its own security review |
| `SECURITY_WEAKENING`, `RESTART`, `DISRUPTIVE` become producible | None. The corpus contains no candidate for two of the three, and the third is the one svcdoctor exists to refuse |
| `domain.NewRecommendation` is removed | The redaction path stops needing it |
| `RecommendationCode` identity | A named consumer — a planner, a report differ, or a runbook that must reference a recommendation across versions |
| Next-evidence observation identity | The planner is reopened first. Never before |
| Rationale becomes renderer-visible | An operator study showing the rationale is wanted at the terminal; it is canonical-only until then |
| One-constant-one-classification | None. It is what makes convergence neutrality provable |
