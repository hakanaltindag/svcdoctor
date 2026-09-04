# ADR 0078 — The diagnostic reasoning model and what svcdoctor may claim

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Refines:** ADR 0002 (architecture separation), ADR 0012 (vantage), ADR 0017 (the rule
contract). It overturns nothing in them.

---

## 1. Context

svcdoctor v0.4.0 answers *"which checks failed"*. Phase 10 exists to make it answer *"where the
failure begins, what that rules out, what remains plausible, how sure we are, and what to look
at next"* — without inventing causes.

The archaeology matters, because most of the model already exists and the temptation is to
rebuild it:

| Concept | Where it already lives |
|---|---|
| Observation | probe and adapter results, before normalization |
| Evidence | `domain.Evidence` — subject, layer, step, state, failure class, attributes |
| Evidence graph | `domain.Graph` — `Parents`, `Children`, `BlockedBy`, frozen and copy-on-read |
| Finding | `domain.Finding` |
| Hypothesis | `domain.FindingKind` = `HYPOTHESIS`, alongside `CONFIRMED` |
| Confidence | `domain.Confidence` — `LOW` / `MEDIUM` / `HIGH`, ordinal, no percentages |
| Next evidence | `Finding.Discriminator` — "the *observation* that would settle it, never a remediation" |
| Recommendation | `domain.Recommendation`, already an **object** in JSON so fields can be added |
| Traceability | `Finding.EvidenceRefs`, membership-validated by the report (ADR 0014) |
| Vantage dependence | `Finding.VantageDependent` |
| Claim discipline | `docs/FINDINGS.md` §3.1 (18 rules), §4, §5 |
| Purity | `.golangci.yml` `diagnosis-is-pure`: no probe, adapter, render, platform, security, `net`, `net/http`, `crypto/tls`, `os` |

What is genuinely missing is not a type system. It is **five inference behaviours**: locating
the failure boundary, forming competing hypotheses over one graph, reconciling them when
several rules converge, treating contradiction and absence differently, and saying what to
measure next in a form a reader can act on.

## 2. Decision

### 2.1 Five concepts, and they stay distinct

**Observation → Evidence → Finding → Hypothesis → Recommendation.** They are not collapsed
merely because fewer structs would be easier, and they are not multiplied either:

- **Observation** is what a probe or adapter saw. It is *not* a domain type and will not become
  one. It exists inside the collecting package and is normalized at that package's own boundary
  (ADR 0020). Promoting it would put raw protocol data in the canonical model, which ADR 0010
  forbids.
- **Evidence** is the normalized fact. `domain.Evidence`, unchanged.
- **Finding** is a user-relevant interpretation backed by evidence. `domain.Finding`, unchanged.
- **Hypothesis** is a *candidate explanation*. It is **a Finding whose `kind` is `HYPOTHESIS`**,
  not a new type. A hypothesis has exactly the fields a finding has, and it needs no others:
  it is backed by `EvidenceRefs`, weighted by `Confidence`, and its open question is named by
  `Discriminator`.
- **Recommendation** is an inert suggested next action. `domain.Recommendation`, extended
  additively by ADR 0082.

**Why a hypothesis is not a new type.** Every field a separate `Hypothesis` struct would need
already exists on `Finding`, the report already validates that its evidence references resolve,
redaction already covers it, and every renderer already displays it. A parallel type would
duplicate all four and create the question ADR 0014 settled once: which of the two does a
report carry? `docs/FINDINGS.md` already documents `HYPOTHESIS` as "alternatives remain, with a
discriminator that names the observation that would settle it". Phase 10 uses that, rather than
building beside it.

### 2.2 Fact and inference are distinguished by `kind`, and the distinction is owned by the domain

A reader must be able to tell a measurement from a piece of reasoning. Three levels, and each
is already representable:

| Statement | Representation |
|---|---|
| observed fact | an `Evidence` node with a `State` |
| derived fact — true by construction from evidence | `Finding` with `kind: CONFIRMED` |
| inference — one of several possible explanations | `Finding` with `kind: HYPOTHESIS` |

**A renderer never invents this distinction and never recomputes it.** It prints `kind`,
`confidence` and `evidenceRefs` as given. This is ADR 0077 §2.7 applied to reasoning.

### 2.3 The epistemic rule, stated so it can be tested

svcdoctor is an external observer and diagnoses from its own vantage point. Concretely, and
binding on every rule:

1. **A claim may not exceed what its cited evidence carries.** If removing an evidence
   reference would not weaken the claim, it was decoration; if no remaining reference supports
   the claim, the claim is unsupported and must not be emitted.
2. **Mechanism is not observed unless it was measured.** "TCP connect timed out" is evidence.
   "A firewall is blocking it" is not a hypothesis svcdoctor may state, because it has no
   firewall evidence and could not obtain any — it is not a *candidate explanation svcdoctor
   can discriminate*, and an undiscriminable explanation is speculation. "The endpoint is not
   reachable from this vantage point" is the supported claim.
3. **"Not measured", "not proven" and "proven false" are three claims.** Collapsing any two is
   the defect this project has already made twice and guards against by test.
4. **Absence of evidence is not contradiction.** See ADR 0081 §2.4.
5. **A downstream step blocked by an upstream failure is `UNKNOWN`, not healthy and not
   broken.** No rule may treat a `SKIPPED` or `UNKNOWN` node as evidence *for* or *against*
   anything except the fact that it was not measured.
6. **UNKNOWN never becomes FAIL through reasoning.** A rule may not upgrade a state; it reads
   states and produces findings.

### 2.4 Rule 2 in full, because it is the one that will be argued about

The tempting counter-example is `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, which already exists
and already says something about mechanism: the cluster advertised an address this client could
not reach. That is admissible precisely because both halves were *measured* — the advertisement
is in the metadata response, and the unreachability is a transport result on that exact address.
The claim is a contrast between two observations, not a mechanism inferred from one.

The test a rule must pass: **name the observations, and delete the claim's verbs.** If what is
left is not a statement about something svcdoctor measured, the claim is speculation.

### 2.5 What Phase 10 adds to the model

Nothing to `domain` in 10.0. The additions are behaviours, specified by the ADRs this record
heads:

| Addition | ADR |
|---|---|
| failure boundary as a derived diagnostic property | 0079 |
| rule architecture, ownership and registration | 0080 |
| hypothesis identity, confidence semantics, evidence relations | 0081 |
| recommendation safety and next-best-evidence | 0082 |
| report evolution, validation and the false-positive policy | 0083 |

### 2.6 Diagnosis remains a pure function of frozen evidence

Restated because Phase 10 is where it would be convenient to break it: **diagnosis performs no
I/O.** A rule that discovers it lacks a discriminating observation emits a
*next-evidence recommendation*; it does not probe. There is no hidden second collection pass, no
lazy evidence, and no mutation of the graph after freezing.

An explicit, operator-visible iterative mode — measure, reason, measure again — is a coherent
future product and is **out of scope**. It would require its own ADR, because it changes what a
report means: today a report describes one bounded measurement, and an iterative one would
describe a search.

## 3. Consequences

**The schema does not change.** `SchemaVersion` stays 1 through the whole of Phase 10.0, and
ADR 0083 shows how it stays 1 through the implementation phases too.

**Hypotheses are findings, so every existing guarantee applies to them for free**: evidence
membership validation, redaction, deterministic ordering, severity/confidence independence, the
renderer contract, and the 18 quality-bar rules.

**"Firewall", "connection leak", "misconfigured pool" and their relatives are not in
svcdoctor's vocabulary** unless a phase adds evidence that observes them. This will
occasionally make svcdoctor less satisfying than a tool that guesses. That is the trade this
project has already made everywhere else.

**One new generic finding code is authorized for Phase 10.1** — the failure boundary (ADR
0079). The frozen count moves 60 → 61 in the phase that implements it, not before.

## 4. Alternatives considered

**A separate `Hypothesis` type in `domain`.** Rejected. Every field it needs is on `Finding`;
it would duplicate evidence validation, redaction and rendering; and it would reintroduce the
two-parallel-types shape that `docs/REPORT_SCHEMA.md` explicitly forbids ("there are no separate
parallel `Hypothesis` and `Finding` report types"). Reconsider only if a hypothesis needs a
field that is meaningless on a confirmed finding — none has been found.

**Promote Observation into the domain.** Rejected: ADR 0010. Raw protocol objects and
uncontrolled payloads must not enter canonical evidence, and an `Observation` type is where
they would arrive.

**Let rules request more evidence.** Rejected for this phase — §2.6. It converts diagnosis into
a second probe system, breaks the "frozen graph" property every determinism guarantee rests on,
and makes a report's meaning depend on how many rounds ran.

**Numeric confidence.** Rejected; see ADR 0081 §2.3.

**Cross-target causal inference.** Rejected and already frozen: ADR 0073, `docs/SCOPE.md`. See
ADR 0083 §2.5 for the non-causal aggregate boundary.

## 5. Security implications

Diagnosis gains no new inputs, so it gains no new attack surface. The `diagnosis-is-pure`
depguard rule already denies `internal/security`, `net`, `net/http`, `crypto/tls` and `os` to
every package under `internal/diagnosis/`, which makes "a rule cannot read a secret, a file, an
environment variable or a socket" a build failure rather than a convention. ADR 0080 §2.6
extends that rule set rather than replacing it.

Server-controlled text is the one live risk and is handled by ADR 0081 §2.7: a rule may not
copy a peer-supplied string into a finding's prose.

## 6. Compatibility implications

None in 10.0: no production code changes. Through the implementation phases,
`domain.SchemaVersion` stays 1 and `domain.RunSchemaVersion` stays 1; the only report-visible
changes are additive (ADR 0083 §2.1) and the one new finding code above.

## 7. Validation requirements

- A guard proving `internal/diagnosis/**` imports nothing that could perform I/O or reach a
  secret — exists today as `diagnosis-is-pure`; extended per ADR 0080 §2.6.
- Property test: for every finding a rule produces, deleting any cited evidence node from the
  graph must change the rule's output. A citation that changes nothing is decoration and
  violates §2.3 rule 1.
- Property test: no rule output may contain a state that is not in the graph — that is, no rule
  may report `FAIL` for a subject whose only evidence is `UNKNOWN` or `SKIPPED`.
- Mutation: reversing rule 6 (treat `UNKNOWN` as `FAIL`) must be caught.
- The golden incident corpus of ADR 0083 §2.4, whose fixtures carry **forbidden claims** as
  first-class expectations.
