# ADR 0090 — Existing evidence consumption: unconsumed is not debt

- **Status:** Accepted
- **Date:** 2026-09-06
- **Phase:** 10.8A (repository archaeology / diagnostic design / contract freeze; no production code)
- **Upholds:** ADR 0008 (no hidden client behaviour), ADR 0014 (a finding cites evidence),
  ADR 0018 (transform domain values, never serialized text), ADR 0034 §15, ADR 0035 §1,
  ADR 0038 §16–§17, ADR 0039 §17 (no SQL), ADR 0040 §5, §18, §20, §22, ADR 0044 (expiry monitoring
  is not diagnosis), ADR 0053, ADR 0054 (owner before producer), ADR 0058, ADR 0063 §11 and
  ADR 0066 (Redis command allowlist and prefix-only classification), ADR 0067 §9,
  **ADR 0069 §6, §8, §9.4**, ADR 0078–0083, ADR 0084 §4, §7, ADR 0085 §4, ADR 0086, ADR 0087,
  ADR 0088, ADR 0089
- **Supersedes:** nothing. **Corrects:** ADR 0089 §1.2's inventory figures (§3).
- **Amended in Phase 10.8A.1 — ADR 0091 supersedes §5, §6 and §11 in part**, and nothing else in
  this record. Phase 10.8B's pre-implementation archaeology proved that `Finding.Detail` and
  `Finding.Recommendations` are **canonical domain fields serialized into canonical JSON**, not
  renderer-only presentation — so §6's *"additive in presentation and inert everywhere else"* is
  wrong, and §5.4's LavinMQ compatibility claim is factually wrong (LavinMQ template **L3** and
  integration scenario **LMQ-06** both produce `VHOST_CONNECTION_LIMIT`). The **audit, the winner,
  the C1-A classification and every count below stand unchanged.** Superseded text is left standing
  with markers so the reasoning that was wrong stays legible — the practice ADR 0069's and
  ADR 0081's headers record. See ADR 0091 §2 for the exact five statements.
- **Decision:** **ACTIVATE RABBITMQ PRESENTATION** — preserve, in operator-facing output, *which*
  capacity ceiling `rabbitmq.close_outcome` already records. Class 1: nothing is acquired, and
  **no diagnosis is created**. The existing diagnosis `RESOURCE_LIMIT_REACHED` is unchanged; the
  phase closes an information-loss gap between canonical evidence and finding prose. §5.

---

## 1. Context

Phase 10.7A measured that a large share of svcdoctor's recorded evidence is read by nothing, and
concluded that *the frontier is consumption, not acquisition*. Phase 10.7B then consumed one such
attribute. Both were right, and both left the same question open: **is the remainder an
opportunity, or is it simply what a careful evidence model looks like?**

ADR 0089 §1.2 named it a pool to draw candidates from. That framing invites a phase per attribute
until the pool is empty. This record answers the question by exhausting the pool in one pass
instead — every attribute with no rule and no renderer consumer put on trial individually — and
the answer changes the roadmap more than the winner does.

`docs/validation/PHASE108A_EXISTING_EVIDENCE_CONSUMPTION_AUDIT.md` holds the archaeology: the
methodology, the 38 case files, the opportunity table, the deep dives and the adversarial review.
This record holds the decision.

---

## 2. Methodology, frozen

### 2.1 What is a recorded evidence attribute

A `domain.AttributeKey` constant declared in non-test production code and written into
`domain.EvidenceInput.Attributes`, so that it crosses the adapter or probe boundary into the
canonical graph.

Excluded, because mixing categories inflates the number and destroys its meaning: adapter locals;
`wire` fields never retained; `FailureClass`, which is derived interpretation with its own count;
`Finding` and `Recommendation` fields; report and run metadata; configuration values and credential
references, which cannot enter evidence by construction; and renderer-only synthetic labels.

### 2.2 What is consumption

- **Diagnosis consumption** — a rule reads the attribute from a node.
- **Renderer consumption** — a renderer deliberately interprets or presents it as an
  operator-facing observation.

**Canonical JSON serialization is not consumption.** Every attribute in the graph is serialized by
definition, so counting it would make every attribute consumed and the measurement vacuous. This
is frozen, because it is the distinction the whole audit rests on.

Structural redaction is likewise not consumption: `internal/security/redaction` iterates attributes
but dispatches on `AttrKind` and never on a key, so it is total over the attribute space and would
survive renaming every key in the tree.

### 2.3 Unconsumed must be proven, not grepped

A single key grep is not evidence. Every candidate is traced wire → adapter → evidence → graph →
diagnosis → renderer, and checked for helper-mediated reads, map iteration, generic render paths,
literal-spelled keys, and — the pass that changed four verdicts — **failure-class derivation before
the attribute was recorded**. An attribute the adapter already used to compute the class diagnosis
keys on is `SEMANTICALLY_CONSUMED_EARLIER`, not dead.

---

## 3. The measurement, and the correction to ADR 0089

| | Recorded | Diagnosis | Renderer | Both | **Neither** |
|---|---|---|---|---|---|
| Kafka | 14 | 2 | 1 | 1 | **12** |
| PostgreSQL | 17 | 4 | 2 | 0 | **11** |
| Redis/Valkey | 7 | 2 | 5 | 1 | **1** |
| RabbitMQ/LavinMQ | 21 | 2 | 15 | 0 | **4** |
| **service subtotal** | **59** | 10 | 23 | 2 | **28** |
| DNS / TCP / TLS | 11 | 0 | 1 | 0 | **10** |
| **TOTAL** | **70** | **10** | **24** | **2** | **38** |

**ADR 0089 §1.2's figures are corrected.** Its recorded count of 59 reproduces exactly. Its
unconsumed count does not, and its two statements of it disagree with each other: the table says
**24** while the prose in the same paragraph names **27**. Re-measured, the service-scoped figure
is **28** — Phase 10.7B removed `postgres.default_transaction_read_only`, and two attributes were
never in 10.7A's list at all: **`postgres.role`** and **`postgres.server_version`**. Adding the ten
generic-probe attributes 10.7A did not scope gives **38**.

So "24 became 23" is not what happened, and this record does not pretend the historical number was
ever right.

---

## 4. Taxonomy

| Class | Meaning |
|---|---|
| **C1-A** presentation gap | the fact is in canonical evidence, no inference is needed, and an operator materially benefits from seeing it. Phase 10.7B was one. It must not silently become diagnosis |
| **C1-B** diagnosis gap | existing evidence supports a new claim under current contracts. A much higher bar: it must state the claim, kind, confidence, admission authority, evidence refs, possible contradiction, incomplete-set semantics, intermediary survival and convergence safety |
| **C1-C** next-evidence gap | the fact improves svcdoctor's ability to say what observation would distinguish unresolved possibilities. Requires a **real** competing hypothesis pair; none exists |
| **C1-D** intentional non-consumption | useful internally or historically, and should not become operator-facing semantics. Subclasses: `BOOKKEEPING`, `DUPLICATE`, `UNSAFE_TO_CONSUME`, `NO_OPERATOR_VALUE` |

Deferral reasons are distinct from rejection: `DEFER_REQUIRES_INTENT`,
`DEFER_REQUIRES_REAL_FIXTURE`, `DEFER_REQUIRES_ARCHITECTURE_DECISION`.

### 4.1 The gates, and the one that does most of the work

Nine gates decide a candidate: a real operator question; explicit authority classification;
the duplicate-value test; the information-value test; the false-positive ceiling; compatibility per
implementation pair; data minimization; output-noise cost; and the real-fixture gate.

Two are worth restating because they killed the most candidates.

**A negotiated integer is not a configuration opinion.** Without a protocol-defined threshold or a
declared application requirement, `channel_max`, `frame_max`, `heartbeat` and an API-version range
are numbers, not verdicts. ADR 0069 §8 already said this for three of them; this record generalizes
it.

**Peer self-description does not carry protocol authority.** `product`, `version`, `platform`,
`cluster_name` and a peer's own close-method attribution are what the peer says about itself.
`rabbitmq.peer_close_method` is the proof: RabbitMQ sends `0/0` for an authentication refusal and
LavinMQ sends `10/11` for the identical condition.

---

## 5. Decision: present what `rabbitmq.close_outcome` already records

**This is a presentation decision, and the distinction is load-bearing.** svcdoctor already
diagnoses this condition correctly: the endpoint named a capacity ceiling, the adapter classified
it as `RESOURCE_LIMIT_REACHED`, and `RABBITMQ_CONNECTION_NOT_PERMITTED` is published with the
right severity and the right confidence. **None of that changes, and none of it is weakened.**

What is wrong is downstream of the diagnosis:

```text
canonical evidence   knows which ceiling   (rabbitmq.close_outcome, closed set, 7 literals)
        │
        ▼
existing diagnosis   RESOURCE_LIMIT_REACHED  →  RABBITMQ_CONNECTION_NOT_PERMITTED
        │
        ▼
operator prose       collapses the specificity  ←  the defect
```

The gap is **information loss in presentation**, not a missing inference. Phase 10.8B recovers
already-known bounded specificity on the way out. It adds **no rule, no `FindingCode`, no claim,
no confidence admission, no observation, no request and no exit-code effect.**

### 5.1 What is wrong today

RabbitMQ enforces three separate connection ceilings. Phase 8.0C reproduced **all three live** on
4.2.0, and svcdoctor classifies each by reconstructing its own expected reply sentence and
comparing **byte for byte** with a digit hole — the strongest evidence standard in the tree, and one
that survives both adversarial cases Phase 8.0C constructed. The result lands in
`rabbitmq.close_outcome` as one of seven **svcdoctor-owned string literals**; the producer's
contract is that *"none is ever a slice of a peer's buffer."*

All three then collapse into `FailureResourceLimitReached`, which shares one finding code —
`RABBITMQ_CONNECTION_NOT_PERMITTED` — with `FailureAuthzNotPermitted`. Four distinct situations,
one output:

> **Summary** *This endpoint refused to open the connection*
> **Detail** *…refused the connection for a reason other than a missing virtual host or a
> permission decision. **Where** the endpoint named a capacity ceiling, that is recorded as what it
> said and nothing more.*
> **Recommendation** *Check the broker's own log for this connection attempt, and review any
> **node, virtual host or user** connection limits*

The conditional *"Where"* and the three-way enumeration are the finding admitting it does not know
which situation it is in — while the evidence node it cites holds the constant that says exactly
which. `internal/diagnosis/rabbitmq/connectionopen.go:172-174` states the loss in a comment:
*"a node-wide one is reached by every client at once — but a per-user ceiling is not, and svcdoctor
does not separate them here."*

### 5.2 This is not a new idea; it is an unimplemented one

**ADR 0069 §6 already decided it:**

> *"The three RabbitMQ ceilings share the class. The class explains the kind of break; the
> `FindingCode` **and the sentinel attribute** explain which ceiling. That is the division this
> repository already keeps."*

Neither half is true in the tree. The `FindingCode` does not distinguish the three, and the
sentinel attribute reaches no operator-facing surface. **ADR 0069 §9.4** compounds it, describing
the rejected fallback as one that *"preserves the operator-visible difference"* — the record assumed
throughout that the difference was preserved.

**ADR 0069 §8 permits the fix by exclusion.** Its table of what may not be said forbids opinions
about the negotiated integers, version policy, identity facts and `ANONYMOUS` posture — and forbids
`VHOST_DOWN` from *"produc[ing] a restating detail sentence"* explicitly because it lacks *"a live
measurement"*, under *"`namedConditions`' rule — membership requires having watched a real endpoint
produce it."* All three ceilings satisfy that membership rule. A live-measured sentinel producing a
restating detail sentence is precisely the case §8 carves out rather than forbids.

### 5.3 The claim, and the claims that stay forbidden

**Permitted:** *the endpoint named this ceiling, for this attempt, at that moment.*

**Forbidden, permanently:**

| Forbidden | Why |
|---|---|
| the limit is too low | svcdoctor has no expectation and no capacity model |
| demand is abnormal | it measured one connection |
| the application is leaking connections | a cause, not an observation |
| the condition still holds | the existing impermanence sentence is retained verbatim |
| **no named ceiling means no ceiling was reached** | truncation destroys the sentinel — Phase 8.0C produced a 255-byte reply with the limit clause entirely absent. **Presence is evidence; absence is not** |
| "RabbitMQ is at capacity" | the subject is the endpoint that refused this attempt |

### 5.4 Why this and not the alternatives

`kafka.sasl.offered_mechanisms` scores **higher on operator value** and loses on one gate: its
domain is arbitrary peer text copied verbatim off the wire with no allowlist, and svcdoctor has no
renderer sanitization boundary. `postgres.scram_iterations` has direct protocol authority and an
explicit invitation in ADR 0038 §16 — and it answers no incident question, while reopening ADR 0040
§22's attribute allowlist and the PostgreSQL BASIC freeze. `postgres.is_superuser` is safe and
would print `off` on nearly every run.

The winner is the only candidate that is simultaneously high-value, structurally bounded, free of
intent, safe across an implementation pair, deterministically fixturable, and already argued for in
an Accepted record.

> **Corrected by ADR 0091 §6 (Phase 10.8A.1).** *"Safe across an implementation pair"* is right,
> but this record reached it by the wrong route: the audit claimed LavinMQ *"was never measured
> producing any limit text"* and would therefore yield `UNSPECIFIED` with unchanged output.
> **LavinMQ produces `VHOST_CONNECTION_LIMIT`** — template `L3` in
> `internal/adapter/rabbitmq/wire/close.go:143-147`, measured live by **LMQ-06** against LavinMQ
> 2.3.0. That is a legitimate shared outcome rather than a false enrichment, and it forces the rule
> ADR 0091 §6 freezes: **the explanation is earned by the authoritative closed outcome, never by
> product identity.** ADR 0091 §6.2 also corrects §6's fixture requirement below — the vhost
> ceiling is **already** proven on real RabbitMQ (RAB-21, three versions) and real LavinMQ, so the
> open gap is `NODE_CONNECTION_LIMIT` and `USER_CONNECTION_LIMIT`, two outcomes rather than three.

---

## 6. What Phase 10.8B may do, and may not

**Phase 10.8B is presentation enrichment of an existing diagnosis.** It preserves specificity the
canonical evidence already carries. It does **not** create a diagnostic claim, and a 10.8B that
finds itself adding a rule, a code or a confidence has left this contract.

**IN SCOPE.** Relocate the seven `CloseOutcome` literals into `internal/service/rabbitmq` as a
closed constant set — the established pattern, and necessary because depguard denies
`internal/diagnosis` the adapter. One closed lookup in
`internal/diagnosis/rabbitmq/connectionopen.go` from the already-recorded outcome to a detail
clause and a scoped recommendation, applied through the mechanism `vhostNotFoundDetail` already
uses. Unit tests, mutations, and integration fixtures for all three ceilings plus a LavinMQ
contrast.

**The existing diagnosis is preserved exactly.** `connectionOpenFinding` keeps selecting the same
code from the same `FailureClass`; `RESOURCE_LIMIT_REACHED`'s semantics are untouched; and the
existing impermanence sentence is retained verbatim. An outcome absent from the lookup renders
today's text byte for byte, so the change is additive in presentation and inert everywhere else.

> **Superseded in part by ADR 0091 §3 and §4 (Phase 10.8A.1): the last clause is wrong.**
> `Finding.Detail` and `Finding.Recommendations` are canonical domain fields emitted by
> `Finding.MarshalJSON`, so writing to them is **not** inert — canonical JSON bytes change for
> every report carrying a mapped capacity outcome. The *schema* is unchanged and byte-identity
> still holds for unmapped outcomes, which is the half this sentence got right. ADR 0091 §9 is the
> replacement compatibility contract, and ADR 0091 §7 narrows *"and a scoped recommendation"*
> above: **recommendations stay byte-identical by default.**

**OUT OF SCOPE.** **Any new diagnostic rule, diagnostic inference or diagnostic claim** — the
phase asserts nothing the report does not already assert. Any new `FindingCode`. Any severity,
confidence or exit-code change. Any weakening or redefinition of `RESOURCE_LIMIT_REACHED`. Any new
failure class. Any schema, `RuleContext`, dependency or CLI change. Consuming
`rabbitmq.reply_code`, `peer_close_method` or `graceful_close`. Opening a channel, calling the
management API, or passive-declaring anything. Any Kafka, PostgreSQL or Redis change. Any renderer
sanitization work. Relation producers. A hypothesis-set engine. Any compatibility claim the new
fixture does not establish.

**Frozen counts, expected unchanged:** `SchemaVersion` 1, `RunSchemaVersion` 1, finding codes 65,
failure classes 42, `RuleContext` fields 3, modules 2, `Reveal` 4, `SecretFor` 4, exit codes 5.

**Fixture requirement (hard).** All three ceilings, provisioned with **limit 0** so the refusal is
deterministic with no held connections and no race — the trick Phase 10.3 used for PostgreSQL
`CONNECTION LIMIT 0`, and a value Phase 8.0C already exercised. Phase 9.1C's lesson binds: the
provisioning gate must verify the limits were set, because `rabbitmq-diagnostics ping` answers
before `rabbitmqctl` works.

---

## 7. Unconsumed is not debt

This is the record's most consequential clause, and it is deliberately general.

Of 38 attributes read by no rule and no renderer, **31 are rejected and most will never be worth
consuming.** They are duplicates of a subject reference, operator input echoed back to the
operator, svcdoctor's own build constants, measurements the repository itself proved unstable,
identity that must not enter a prose field, or facts whose value is a tripwire for a surprise that
has never occurred.

**An attribute earns a place in canonical evidence for auditability, protocol legibility, machine
consumption or future reasoning. That does not earn it a terminal line, a finding, a hypothesis, a
recommendation or a roadmap item.** A repository that treats every unread attribute as a gap will
fill its output with true, bounded, safe and useless statements — and svcdoctor is not a protocol
dump.

`docs/BACKLOG.md` is revised accordingly: the row that framed the unconsumed set as *"the pool the
next several candidates should be drawn from"* now records that the pool was exhausted in one pass,
with the classification of all 38.

---

## 8. The frontier, and what it now takes to move it

The Class-1 frontier is **not exhausted, but it is nearly so, and what remains is concentrated.**
Six deferred candidates, and **four of them are blocked by only two decisions**:

1. **Renderer sanitization of unbounded observation values.** Blocks
   `kafka.sasl.offered_mechanisms`, `postgres.sasl_mechanisms` and `postgres.server_version`. Redis
   and RabbitMQ already render verbatim peer versions while PostgreSQL is refused one, which is not
   a defensible steady state. It must be decided **once, for all four services** — never inside a
   service phase.
2. **A product-wide security-posture finding class.** Would give `postgres.scram_iterations` a
   home, together with TLS certificate posture and the weak-mechanism claim ADR 0040 §5 names in the
   same sentence. It must answer whether a posture weakness is a target-side problem worth exit
   code 1.

The other two are `postgres.is_superuser`, deferred on operator value, and Kafka's
`unrepresentable_entry_count`, deferred on the fixture gate (§9, C2).

**New observation acquisition is still not justified.** Every acquisition candidate weighed by
ADR 0089 remains more expensive than what is already paid for, and this audit has not emptied the
consumption side. Class 2 and Class 3 are named for a future audit and are not reopened here.

---

## 9. Conflicts recorded, not fixed

This phase is documentation-only, so a conflict between an Accepted record and the tree is recorded
rather than patched.

| | Conflict | Disposition |
|---|---|---|
| **C1** | ADR 0069 §6 and §9.4 describe a ceiling distinction the product does not make | **Resolved by 10.8B**, not by editing the ADR |
| **C2** | ADR 0084 §4's completeness predicate is computed over an exchange's children, so an unrepresentable advertisement — which produces no child — is invisible to it, and `detailTopologyComplete` can claim the counts *"account for the whole advertised set"* when they do not. ADR 0035 §1 anticipated the missing *finding*, not this later *overclaim* | **DEFER.** No supported fixture produces the condition, and `KAFKA_PHASE3_VALIDATION.md` records that no real run ever has. **Reopen when** a fixture produces one, or when a decision argues `complete` must read the count regardless |
| **C3** | `internal/service/redis/vocabulary.go:105-106` claims a renderer reads `redis.auth_required`; none ever has | documentation defect; no behaviour is wrong |
| **C4** | `internal/service/rabbitmq/vocabulary.go:152` says rules read `close_outcome`; they read the derived class | documentation imprecision; superseded in substance by 10.8B |
| **C5** | ADR 0089 §1.2's table contradicts its own prose and omits two attributes | corrected in §3; history not edited |

---

## 10. Gates

**Phase 10.4C — CLOSED.** No real competing hypothesis pair emerged from any of the 38. The winner
produces no `HYPOTHESIS`, and RabbitMQ emits none at all. No set engine, `DiscriminatorID` or
grouping identity was designed.

**Phase 10.5B — CLOSED.** No candidate needs `CONTRADICTION`, `MISSING` or `BLOCKED`. The winner's
basis is the single supporting node its finding already cites, so ADR 0087's OUTCOME C is
undisturbed and `AdmitConfidence`'s two vacuous guards stay vacuously paired.

**Declared intent — UNCHANGED.** ADR 0083 §2.6 still binds. Two candidates were intent-adjacent and
neither was admitted. The winner needs no expectation at all: the endpoint named the condition
itself, which is exactly why it clears the gate `channel_max`, `frame_max` and `heartbeat` fail.

**PostgreSQL BASIC freeze — NOT REOPENED.** **Kafka topic surface — UNTOUCHED** (`Topics = []`
stands). **Redis command allowlist — UNTOUCHED**; no new command, no new literal.

---

## 11. Rejected alternatives

| Alternative | Verdict |
|---|---|
| **Classifying this as a diagnosis activation** | **Rejected, and the wording matters.** The phase adds no rule, no inference, no claim, no confidence admission and no observation; the diagnosis `RESOURCE_LIMIT_REACHED` already exists and is already correct. Calling it *"activate diagnosis"* would imply a new inference and would invite a later reader to weaken or re-derive the class. It is **C1-A presentation**: already-known bounded specificity preserved on the way out. The file it is wired in is a location, not a layer promotion |
| Three new `FindingCode`s, one per ceiling | **Rejected.** The class already carries the kind of break and the subject is identical; three codes would multiply the surface for a distinction one sentence carries — and would turn a presentation fix into a diagnosis change. ADR 0069 §6's own division puts the ceiling in the sentinel, not in the code |
| Render `close_outcome` as a Result-block observation line | **Rejected.** The `observations` mechanism is keyed by step and prints regardless of outcome; a close outcome exists only on a failed open, and a raw enum detached from the finding explaining it is worse than the enumeration it replaces |
| Publish `rabbitmq.reply_code` alongside it | **Rejected.** One reply code covers six semantically different conditions — the sentinel apparatus exists to disambiguate exactly that. Publishing both hands the operator the answer and the trap side by side |
| Bound the mechanism lists with a registry allowlist so §8's first blocker clears now | **Rejected.** It invents sanitization machinery for one service while the cross-service decision is outstanding, which is the conditional sprawl the architecture rule forbids |
| Take the renderer-sanitization decision inside this phase | **Rejected.** It is a renderer-security decision affecting four services and deserves its own record and its own review, not a corner of a RabbitMQ audit |
| Declare the Class-1 frontier exhausted | **Rejected on the evidence.** One candidate passes every gate today and six more are deferred with named conditions. Frontier-exhausted would have been the honest answer if the winner had failed adversarial review; it did not |
| Select a second winner | **Rejected.** At most one, by construction — and §8's two decisions are not this phase's to take |
| Treat the unconsumed set as debt to be burned down | **Rejected. §7** |

---

## 12. Reopen conditions

1. **The renderer sanitization decision is taken.** Then `kafka.sasl.offered_mechanisms`,
   `postgres.sasl_mechanisms` and `postgres.server_version` are re-audited **together**.
2. **A product-wide security-posture finding class is decided.** Then `postgres.scram_iterations`
   is re-audited against it, with the Kafka asymmetry answered.
3. **Declared operational intent lands** (ADR 0083 §2.6, ADR 0085 §5). Then `postgres.is_superuser`
   and every intent-adjacent candidate here are re-audited.
4. **A supported fixture produces an unrepresentable Kafka advertisement**, or a decision argues
   `complete` must read the count regardless. Then C2 is closed (ADR 0035 §1's own reopen
   condition, extended by this record to the completeness claim ADR 0084 §4 built after it).
5. **A live `VHOST_DOWN` measurement** (ADR 0069 §9.2). Then `rabbitmq.reply_code` gains a reason to
   be read.
6. **A new attribute is recorded.** It enters this audit's classification with a stated class, per
   ADR 0054's *owner before producer* discipline applied to evidence rather than to findings.
7. **A rejected verdict here is challenged by a real operator question.** The 31 rejections are
   reasoned, not permanent — but a challenge must bring the question, not the observation that the
   field exists.
