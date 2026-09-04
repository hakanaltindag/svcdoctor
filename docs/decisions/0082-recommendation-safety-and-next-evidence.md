# ADR 0082 — Recommendation safety and next-best-evidence

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Refines:** `docs/FINDINGS.md` §3.1 rule 17 ("recommendations follow the evidenced failure and
nothing else… never an executable command"), which it makes structural.

---

## 1. Context

`domain.Recommendation` today holds one field, `action string`, and its own doc comment
anticipates this record: it is "a struct rather than a bare string so that the encoded form is
an object from the outset, which lets fields such as a reference link or a remediation risk be
added later without changing the shape of every existing report."

Two problems arrive with Phase 10. First, a diagnostic tool that says *"restart the broker"* on
weak evidence is worse than one that says nothing — and the pressure to emit remediation grows
exactly as the reasoning gets better. Second, the most valuable output of an ambiguous
diagnosis is not advice at all; it is **the next observation that would resolve the ambiguity**,
and a reader needs to know whether they can take it, whether it needs privilege, and whether it
is safe.

## 2. Decision

### 2.1 Two kinds of recommendation, one type

`Recommendation` gains fields; no second type is created.

```go
// Illustrative. Not implemented in Phase 10.0.
type Recommendation struct {
    kind    RecommendationKind // NEXT_EVIDENCE | REMEDIATION
    safety  SafetyClass        // OBSERVE | VERIFY | COMPARE | CONFIG_CHANGE | RESTART | DISRUPTIVE | SECURITY_WEAKENING
    action  string             // one line, human-readable, never a command to execute
    rationale string           // why this discriminates, or why it follows from the evidence
}
```

- **`NEXT_EVIDENCE`** — an observation that would discriminate between remaining explanations.
  *"Compare the address the broker advertised with the addresses routable from this client
  network."*
- **`REMEDIATION`** — a change to make, and it requires much stronger evidence.
  *"Correct `advertised.listeners` to expose a client-reachable address."*

One type, because they share every field and a reader distinguishes them by `kind`. Two types
would duplicate validation, marshalling and redaction for no gain.

### 2.2 Safety classes, ordered by blast radius

| Class | Meaning | Example |
|---|---|---|
| `OBSERVE` | read something that already exists | read the broker's configured listeners |
| `VERIFY` | check a claim, changing nothing | confirm the certificate's SANs cover the name used |
| `COMPARE` | contrast two observations | compare the advertised address with a routable one |
| `CONFIG_CHANGE` | change configuration; takes effect on reload or reconnect | correct `advertised.listeners` |
| `RESTART` | requires restarting a component | restart the broker |
| `DISRUPTIVE` | interrupts service or risks data | fail over the primary, delete a queue |
| `SECURITY_WEAKENING` | reduces a security property | disable TLS verification |

The first three change nothing and are the classes a diagnostic tool should overwhelmingly
produce.

### 2.3 The guardrails, which are the point of this record

1. **Confidence gates safety.** A `REMEDIATION` may be attached only to a finding whose `kind`
   is `CONFIRMED` **and** whose `confidence` is `HIGH`. Anything less produces `NEXT_EVIDENCE`
   instead. A `LOW`-confidence hypothesis may carry only `OBSERVE`, `VERIFY` or `COMPARE`.
2. **`RESTART`, `DISRUPTIVE` and `SECURITY_WEAKENING` are not producible by any rule.** They
   exist in the vocabulary so that the report model can *classify* advice, and so a future phase
   that genuinely needs one must add it deliberately, against an ADR. svcdoctor does not tell
   anyone to restart anything, and it never recommends weakening a security control it exists to
   verify.
3. **No recommendation is an executable command.** No shell, no SQL, no `kubectl`, no API call.
   This is `docs/FINDINGS.md` §3.1 rule 17, now enforceable: a validator rejects an action
   containing a shell metacharacter or a leading command word.
4. **A recommendation cites nothing the finding does not.** It is attached to a finding and
   inherits that finding's evidence; it may not introduce a new claim.
5. **Prefer `NEXT_EVIDENCE` while the cause is ambiguous.** When two hypotheses remain, the
   correct output is the observation that separates them — not a remediation for whichever
   happens to be listed first.

### 2.4 Next-best-evidence carries its collectability

A `NEXT_EVIDENCE` recommendation answers four questions, and three of them are new:

| Question | Where it lives |
|---|---|
| what to observe | `action` |
| why it discriminates | `rationale` |
| can svcdoctor collect it itself | `SelfCollectable bool` |
| does collection need privilege svcdoctor may not have | implied by the class and stated in `rationale` |
| is collection safe | `safety`, always one of the first three classes |

`SelfCollectable` is deliberately honest and frequently `false`. *"Read `pg_stat_activity` to
distinguish capacity exhaustion from admission pressure"* is exactly the right next observation
and svcdoctor **cannot** take it: PostgreSQL BASIC runs no SQL, and the credential may lack the
privilege. Saying so is more useful than pretending, and it is the difference between a tool
that helps an operator investigate and one that implies it already did.

**`SelfCollectable: true` does not mean svcdoctor will collect it.** ADR 0078 §2.6 stands:
diagnosis performs no I/O, and there is no automatic collection. It means a *future* explicit
mode, or a differently configured run, could — for example "re-run with a larger execution
budget", which is what the existing Kafka discriminator already says.

### 2.5 The discriminator and the recommendation are one idea in two places

`Finding.Discriminator` already exists and already means "the observation that would settle
it". A `NEXT_EVIDENCE` recommendation is the structured form of the same thought.

The rule: **the discriminator is the one-line human statement; the recommendation carries the
structure.** A finding that has one should have the other, and they must not disagree. A guard
asserts that a `HYPOTHESIS` with a discriminator also carries at least one `NEXT_EVIDENCE`
recommendation once Phase 10.1 lands.

## 3. Consequences

**The report gains three fields inside an existing object.** `Recommendation` was designed for
this, so consumers that read `recommendations[].action` keep working unchanged.

**svcdoctor will refuse to give the advice users sometimes want.** "What should I do?" will
frequently be answered with "here is what to look at, and here is why it would tell you". That
is the honest answer when the cause is not proven, and the guardrail exists because the
dishonest answer is always available and always tempting.

**Three safety classes are unreachable by construction.** A future phase that wants one must
change this record, which is the intended friction.

## 4. Alternatives considered

**Separate `NextEvidence` and `Remediation` types.** Rejected — §2.1. Identical fields,
duplicated machinery, and a consumer that must handle two arrays.

**No safety classification; rely on rule authors' judgement.** Rejected. Judgement is what
review checks; a class is what a test checks, and "no rule may emit `DISRUPTIVE`" is a test.

**A free-text severity or risk note.** Rejected. Unparseable by a consumer and unenforceable by
a guard.

**Let svcdoctor collect the discriminating evidence automatically.** Rejected — ADR 0078 §2.6.
It makes diagnosis a probe system and a report's meaning depend on how many rounds ran.

**Executable remediation commands.** Rejected permanently. A command in a report is a command
someone pastes, and svcdoctor changes nothing by design (`README.md`, `docs/SCOPE.md`).

## 5. Security implications

`SECURITY_WEAKENING` exists in the vocabulary and is **unreachable**: svcdoctor must never
recommend disabling TLS verification, widening an ACL, or relaxing an authentication mechanism.
The class exists so that the prohibition is nameable and testable rather than merely absent.

Rule 3 — no executable commands — keeps the report free of anything a reader could paste
without reading, which matters most in the shareable projection, where the reader may not be the
operator who ran it.

Recommendations carry no identity of their own and inherit their finding's evidence, so they
open no path around redaction.

## 6. Compatibility implications

Additive within an existing JSON object; `SchemaVersion` stays 1. `docs/REPORT_SCHEMA.md` and
`docs/OUTPUT.md` gain the new fields when Phase 10.1 lands. No exit-code impact: recommendations
never affect an exit code.

## 7. Validation requirements

- Unit: the confidence gate — a `HYPOTHESIS`, or a `CONFIRMED` finding below `HIGH`, cannot
  carry a `REMEDIATION`.
- Static guard: no rule package constructs `RESTART`, `DISRUPTIVE` or `SECURITY_WEAKENING`,
  parsed with `go/ast`.
- Unit: the action validator rejects shell metacharacters and leading command words.
- Property: every `HYPOTHESIS` with a discriminator carries a `NEXT_EVIDENCE` recommendation,
  and vice versa.
- Mutation: swap a recommendation's safety class; drop the confidence gate; allow an executable
  command; emit `REMEDIATION` from a `LOW`-confidence hypothesis.
- Corpus: every fault-injection scenario in ADR 0083 §2.4 declares its **forbidden
  remediation**.
