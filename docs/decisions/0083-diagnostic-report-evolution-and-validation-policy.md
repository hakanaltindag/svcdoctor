# ADR 0083 — Diagnostic report evolution, false-positive policy and validation

**Status:** Accepted
**Date:** 2026-09-02
**Phase:** 10.0
**Refines:** ADR 0015 and 0016 (report ownership), ADR 0074 (the aggregate document), ADR 0077
(the public report and CI consumption contract).

---

## 1. Context

Three questions remain once the reasoning model is fixed: how the canonical report absorbs
Phase 10 without breaking consumers, what stops the reasoning from becoming confidently wrong,
and how any of it is proven.

The third is the one that decides whether Phase 10 is worth shipping. A diagnostic engine that
passes unit tests and invents causes in production is a net loss: it costs the trust that makes
the measured half of the tool useful.

## 2. Decision

### 2.1 Schema evolution: additive, and `SchemaVersion` stays 1

Five options were considered — additive fields at v1; `SchemaVersion` 2; a separately versioned
diagnosis section; internal-only first; a side-car document. **Additive at v1 is selected**, and
it is selected because the schema was already built for it:

| Phase 10 concept | Already in `SchemaVersion` 1 |
|---|---|
| hypothesis | `finding.kind = HYPOTHESIS` |
| confidence | `finding.confidence` |
| confidence rationale | `finding.detail` (prose), plus the evidence it cites |
| next evidence | `finding.discriminator` |
| traceability | `finding.evidenceRefs` |
| recommendations | `finding.recommendations[]`, **already an object** |
| failure boundary | a finding (ADR 0079) |

What is genuinely new is three fields inside `recommendations[]` (ADR 0082 §2.1) and one new
finding code (ADR 0079 §2.3). Both are additive: an unknown field is ignored by every consumer
that reads named fields, and an unknown finding code is a finding like any other.

**`SchemaVersion` 2 is rejected** because a version bump is a promise of breakage, and there is
none. `RunSchemaVersion` likewise stays 1. A separately versioned diagnosis section is rejected
as two version axes over one document — the mistake ADR 0074 avoided by giving the *aggregate*
its own version rather than sectioning the single-target report.

**The condition that would force `SchemaVersion` 2**, recorded so it is not argued case by case:
removing or repurposing an existing field, changing the meaning of `kind` or `confidence`, or
making an existing optional field required. None is contemplated.

### 2.2 The false-positive policy

**A HIGH-confidence hypothesis must be supported by evidence that materially discriminates it
from the realistic alternatives.** If the realistic alternatives are indistinguishable with the
evidence in hand, the confidence is not `HIGH` — and if nothing distinguishes the claim from
the alternatives at all, **no causal hypothesis is emitted**.

Four rules, each testable:

1. **No mechanism without observation.** A claim about *why* something failed requires evidence
   about the mechanism, not only about the effect (ADR 0078 §2.3 rule 2).
2. **No hypothesis without a discriminator.** If a rule cannot name the observation that would
   settle its guess, the guess is not actionable and is not emitted.
3. **No promotion by count.** Convergence is `MEDIUM` (ADR 0081 §2.2).
4. **When in doubt, report the boundary and stop.** The failure boundary plus the evidenced
   finding is always emittable and always true; a cause is not.

**Scenarios where svcdoctor must refuse to go further** — these are acceptance criteria, not
illustrations:

| Observation | Emit | Must not emit |
|---|---|---|
| TCP connect timed out | unreachable from this vantage point; boundary at TCP | "a firewall is blocking it", "the host is down", "the service is not listening" |
| PostgreSQL SQLSTATE `53300` | the server rejected the connection at its resource limit (`HIGH`, direct authority) | "a connection leak", "the pool is misconfigured", "increase `max_connections`" |
| One discovered broker unreachable, two reachable | that endpoint is unreachable from here; boundary is branch-specific | "the broker is down", "the cluster is degraded" |
| AMQP endpoint times out during negotiation | protocol identity unknown, blocked by timeout | "not an AMQP server", "the broker is broken" |
| Redis reports the implementation is Valkey | the observed implementation | any implication that this is a problem |
| PostgreSQL host reports standby | the observed role | "the wrong host is configured" — unless intent was declared (§2.6) |

### 2.3 When diagnosis itself fails

A rule that panics, returns a dangling evidence reference, produces a duplicate identity it
should have merged, or emits an impossible state is a **defect in svcdoctor**, and the response
is fail-closed and narrow:

- **A rule panic is recovered by the engine**, that rule's output is discarded entirely, and the
  run continues. A partial rule set is better than no report, and a report missing one rule's
  findings is closer to the truth than one containing half of them.
- **The failure is recorded**, and it is recorded as svcdoctor's own — never as a target-side
  finding. It sets the run's incompleteness, which already means "svcdoctor's own execution did
  not finish" and already maps to **exit 4**.
- **No new exit code.** The five are frozen (ADR 0077 §2.1). A diagnostic-engine defect is not a
  target problem (1), not a usage error (2), and does not prevent a report (3) — it makes the
  report incomplete, which is exactly 4.
- **Invalid rule output is rejected, not repaired.** A finding citing evidence not in the graph
  is dropped; the report's own membership validation (ADR 0014) is the backstop and stays.
- **Canonical evidence is never touched.** The graph is frozen and copy-on-read; a rule cannot
  corrupt it, which is a property of the type rather than a promise here.

### 2.4 The validation pyramid

Six levels. Each catches something the level below cannot.

**L1 — rule unit tests.** Synthetic graph in, expected findings out: codes, kinds, confidence,
evidence references, discriminators, recommendation classes. Plus the negative half — the
inputs for which the rule must emit *nothing*.

**L2 — property tests.** The invariants, over generated graphs:
same graph → same result; rule order → no effect; blocked evidence never becomes a confirmed
fact; missing evidence never raises confidence; contradiction never raises confidence;
`UNKNOWN` never becomes `FAIL`; every cited evidence reference resolves; deleting any cited
node changes the output; merging is commutative and associative; the renderer cannot change a
finding.

**L3 — mutation tests.** A `scripts/phase10*-mutations.sh` in the established shape, with the
interrupt-restore trap. Required plants, each of which must be caught:
remove contradictory-evidence handling; reverse the confidence ordering; ignore `BlockedBy`;
treat `UNKNOWN` as `FAIL`; drop a required evidence reference; swap a recommendation's safety
class; make rule order affect the result; accumulate confidence on convergence; let a generic
rule read a service constant; emit `REMEDIATION` from a `LOW` hypothesis.

**L4 — fuzzing.** Targets: graph traversal against cyclic and self-referential inputs; merge and
deduplication against adversarial identities; rule evaluation against graphs with missing
parents, empty subjects and maximal attribute values; **and prose safety — a fuzz corpus of
hostile server strings asserting none reaches a finding's prose** (ADR 0081 §2.7).

**L5 — integration with injected faults.** The matrix in the design document, run against the
real fixtures the repository already operates.

**L6 — adversarial incident scenarios.** Incidents with several plausible causes, where the
correct output is *uncertainty*. A scenario passes when svcdoctor emits the boundary, the
competing hypotheses and the discriminator — and fails if it picks one.

### 2.5 The golden incident corpus, and forbidden claims

Deterministic fixtures, each carrying:

```text
intent          the configuration and any declared expectation
evidence        the frozen graph, committed
expected        findings, kinds, confidence, discriminators, recommendation classes
forbidden       claims that must NOT appear
```

**`forbidden` is a first-class expectation, not a comment.** A fixture for a TCP timeout
forbids the substring "firewall"; a `53300` fixture forbids "leak" and "max_connections"; a
LavinMQ fixture forbids any claim that the implementation is itself a problem. This is the
mechanism that stops diagnostic language from drifting into overconfidence one helpful sentence
at a time, and it is the direct descendant of the RAB18 lesson: **less evidence must never
produce a stronger claim.**

### 2.6 Declared intent stays out, for now

Several useful diagnoses need to know what the operator expected — that an endpoint should be
primary, that TLS should be required, that a vhost should be reachable. Without that, svcdoctor
can only report the observed role, never "the wrong role".

**No configuration change in Phase 10.** The distinction is frozen instead: svcdoctor reports
**observed** properties, and may call one a *problem* only when the operator declared an
expectation. Until an `expect:` block exists, a standby is a standby and not a fault.

If a later phase adds one it must stay a small closed vocabulary — a handful of typed
expectations — and not become a policy language. That is its own ADR, against ADR 0071's
strict-schema contract.

### 2.7 Non-causal aggregate observations stay out too

"7 of 8 targets failed at DNS" is a true, useful, non-causal statement. It is also one sentence
away from "there is a shared network problem", which ADR 0073 forbids and which this project
will not ship.

**Phase 10 implements no cross-target reasoning of any kind.** If a later phase adds aggregate
*observations*, they must be counts over the aggregate document with no causal language, no
shared-cause hypothesis, and no finding — the run-level finding code that ADR 0073 §10 declined
to create stays declined.

## 3. Consequences

**Consumers of the v1 report keep working**, including through the whole of Phase 10.

**Phase 10 acquires an expensive test suite**, and that is the intended cost. The corpus and the
mutation suite are the deliverables that make the reasoning trustworthy; the rules are the easy
part.

**A diagnostic-engine bug degrades a report rather than corrupting one**, and it surfaces as
exit 4 — which already means "the report is truthful but partial".

**Some scenarios will produce less than users want**, permanently, by policy.

## 4. Alternatives considered

**`SchemaVersion` 2 for diagnosis.** Rejected — §2.1. Nothing breaks.

**A separately versioned `diagnosis` section.** Rejected. Two version axes over one document,
and consumers would have to negotiate both.

**Internal-only diagnosis first, public schema later.** Rejected as the *primary* plan: it
means building the reasoning with no consumer, and the first consumer always changes the model.
Retained in weakened form — Phase 10.1 lands the generic engine and the boundary before any
service intelligence, which exercises the model on one small surface first.

**Emit a finding when a rule panics.** Rejected. It is svcdoctor's defect and must not appear
in a document whose findings are claims about the target.

**A new exit code for diagnostic-engine failure.** Rejected — §2.3.

**Skip the golden corpus and rely on unit tests.** Rejected. Unit tests assert what a rule
says; the corpus asserts what the *product* must never say, and the second is the one that
decays without a test.

## 5. Security implications

The fuzz target in L4 is a security control, not a robustness exercise: it is the automated form
of ADR 0081 §2.7, and its corpus is hostile server-controlled strings.

The corpus fixtures are committed evidence graphs. They must be synthetic or already-redacted —
a fixture captured from a real environment would put a real hostname in the repository, which
`docs/SECURITY.md` and the redaction contract exist to prevent.

Fail-closed rule handling (§2.3) means a defective rule cannot produce a report that claims more
than the evidence: its output is discarded whole rather than partially trusted.

## 6. Compatibility implications

`SchemaVersion` 1 and `RunSchemaVersion` 1 throughout. Additive `recommendations[]` fields; one
new finding code; no CLI change; no exit-code change; no configuration change; no new module.

## 7. Validation requirements

- The pyramid in §2.4, in full, as the Phase 10.1+ release gate.
- A guard that the golden corpus's `forbidden` list is non-empty for every scenario that
  produces a hypothesis — a corpus whose forbidden claims are empty proves nothing.
- A guard that `SchemaVersion` and `RunSchemaVersion` are still 1 at the end of every Phase 10
  implementation phase.
- Mutation: delete a `forbidden` assertion and confirm the corpus harness fails.
