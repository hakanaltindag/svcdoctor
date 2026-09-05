# ADR 0092 — Diagnostic planning admission: the frontier is served, not open

- **Status:** Accepted
- **Date:** 2026-09-06
- **Phase:** 11.0 (architecture / archaeology / epistemic-safety audit; no production code)
- **Upholds:** ADR 0012 (vantage), ADR 0028 and ADR 0030 (credentials are endpoint-bound),
  ADR 0034 §13 (severity is never count-derived), ADR 0039 §17 (no SQL), ADR 0040 §18, §20, §22,
  ADR 0041 (one authenticated path), ADR 0043 (generic transport claim scope), ADR 0050
  (discovery creates no secret authority), ADR 0054 (owner before producer), ADR 0058 (trust
  versus identity), ADR 0059 (an address is not a name), ADR 0063 §11 and ADR 0066 (Redis command
  allowlist, prefix-only classification), ADR 0067–0070 (RabbitMQ observation ceiling),
  ADR 0073 and ADR 0083 §2.7 (no cross-target reasoning), **ADR 0078 §2.6** (diagnosis is a pure
  function of frozen evidence; no hidden second collection pass), ADR 0079 §2.4, ADR 0081,
  **ADR 0082** (recommendation safety and next-best evidence), **ADR 0083 §2.2 and §2.6** (the
  false-positive policy; declared intent frozen out of Phase 10), **ADR 0086** (next-best evidence
  and indistinguishable hypotheses, including §2.7's report-only boundary and §2.11's refusals),
  **ADR 0087** (evidence-relation semantics, OUTCOME C), ADR 0088, ADR 0089, ADR 0090 §7,
  ADR 0091
- **Supersedes:** nothing. **Corrects:** ADR 0086 §1.2's claim that the two hypothesis-carrying
  Kafka codes sit at *"different layers"* — both are `domain.LayerTopology` (§8).
- **Decision:** **DEFER DIAGNOSTIC PLANNING.** Twenty-nine candidates weighed, **zero admitted**.
  No planner, no planning loop, no `--investigate`, no `DiscriminatorID`, no hypothesis-set
  engine, no observation scheduler, no planning budget, no new evidence relation. §2.11.

---

## 1. Context

### 1.1 The question

Does svcdoctor have at least one **real** diagnostic situation where the existing diagnosis
reaches an epistemic boundary and one additional **bounded** observation would materially
distinguish between **genuinely competing** explanations?

The strategic ambition behind it is the one ADR 0086 §1 records: svcdoctor should prefer *"I
cannot distinguish these explanations with the evidence available; this observation would
distinguish them"* over guessing a most-likely root cause.

### 1.2 What the audit found, and it decides the record

`docs/validation/PHASE110_DIAGNOSTIC_PLANNING_OPPORTUNITY_AUDIT.md` holds the archaeology: the
re-measured inventory, **67** frontier cases covering all 65 finding codes and every non-finding
state, and **29** candidate case files.

**Zero were admitted, and the reason is not that svcdoctor has no epistemic boundaries.** It has
many. It is that at every boundary where two genuinely competing explanations remain *and* a
discriminating observation exists, exactly one of three things is true:

1. **the observation is not svcdoctor's to take** — it is operator intent, privileged
   configuration, or a network position svcdoctor does not occupy;
2. **svcdoctor already names it** — a `Discriminator` plus a classified `NEXT_EVIDENCE`
   recommendation with an honest `SelfCollectable` value, which Phase 10.4B shipped and
   `internal/render/terminal` prints;
3. **taking it would attack the endpoint, guess, or exceed a bound.**

**A planner is justified only when svcdoctor can complete this sentence: *"I cannot distinguish A
from B with the current evidence; observation O would materially distinguish them, and I could
take O."* The tree contains the first two clauses in real, shipped findings. It contains no
instance of the third.**

### 1.3 Why the record freezes semantics rather than deferring silently

Three prior phases have now asked a version of this question — 10.4A, 10.5A and this one — and
each had to re-derive the vocabulary before it could answer. Worse, the arguments most likely to
reopen it wrongly are the ones a reasonable engineer reaches for first: *"a second vantage would
tell us whether it is a firewall"*, *"we could just ask another resolver"*, *"the operator could
declare what they expected, so let's collect it."* Each is answerable, and each answer is worth
writing down once.

So this record freezes the **admission criteria and the claim ceilings**, and the deferral falls
out of them. That is the same split ADR 0086 §2.0 chose: **a semantic contract can be frozen from
measurement of what exists; a mechanism cannot be frozen from measurement of what does not.**

---

## 2. Decision

### 2.1 What diagnostic planning is

> **Diagnostic planning is the selection, by deterministic reasoning over frozen evidence, of a
> bounded observation whose outcomes would materially distinguish between two or more genuinely
> competing explanations that svcdoctor's existing evidence cannot separate.**

A **planning opportunity** exists only when **all seven** hold:

1. svcdoctor has reached an **epistemic boundary** — its evidence supports no further true claim
   about the subject;
2. at least **two genuinely distinct explanations** remain compatible with that evidence;
3. the explanations **matter operationally** — they send the operator to different places;
4. a **concrete observation O** exists whose outcomes would materially distinguish them;
5. O has a **defined authority boundary** — what its result would and would not prove is known
   in advance;
6. O has **bounded cost and bounded side effects**;
7. O's result would **change what svcdoctor can responsibly say**.

**None of the following is diagnostic planning**, and each exclusion is load-bearing because each
killed at least one candidate in the audit:

- another recommendation;
- generic troubleshooting advice — *"check the firewall"*, *"check the logs"*, *"ask your DBA"*;
- arbitrary remediation, or a documentation link;
- **retrying the same probe**, including re-running it with a larger budget;
- collecting more data because it happens to be available;
- a hard-coded sequence of troubleshooting steps;
- an LLM-generated investigation plan.

An observation need not fully prove one root cause. It **must** materially reduce uncertainty.

### 2.2 The competing-explanation test

For a pair (A, B) to be a competing pair, **all five** must hold:

| | Test |
|---|---|
| **A** | both explanations are compatible with the **same existing evidence** |
| **B** | they are **operationally meaningfully different** — the operator's first move differs |
| **C** | they predict **different outcomes** for at least one concrete observation |
| **D** | the distinction is representable **without claiming hidden causality** |
| **E** | one is not merely a **broader wording** of the other |

**Four shapes are permanently invalid pairs**, named so they are not re-proposed:

- *network issue* versus *firewall issue* — one contains the other (fails E);
- *service unavailable* versus *connection failed* — the second restates the evidence (fails E);
- *configuration issue* versus *runtime issue* — vague categories, not testable explanations
  (fails C and D);
- *wrong credentials* versus *authentication failed* — the second is an observation and a
  classification, not a competing explanation (fails E).

**A competing pair is not a sign of sophistication. It is usually a sign that the claim was drawn
too wide.** ADR 0086 §4.3 established this and the Phase 11.0 audit confirmed it three more times
— PostgreSQL `53300`, the pooler question and the RabbitMQ capacity ceilings each dissolved when
the claim was narrowed to what the evidence supports.

### 2.3 Observation classes, frozen

Every candidate observation carries **exactly one**:

| Class | Meaning |
|---|---|
| `O0_ALREADY_COLLECTED` | svcdoctor already has it |
| `O1_PASSIVE_EXISTING_PROTOCOL` | obtainable within an already-established interaction, changing no remote state and sending no extra byte |
| `O2_PASSIVE_NEW_REQUEST` | an additional read-only request or network operation |
| `O3_ALTERNATE_VANTAGE` | the same or a similar measurement from a different network position |
| `O4_OPERATOR_DECLARED` | operator-supplied intent, expectation or context |
| `O5_PRIVILEGED` | needs a privilege this run does not hold |
| `O6_STATE_CHANGING` | mutates remote state, including a counter, an audit log or a lockout window |
| `O7_SECURITY_WEAKENING` | reduces a security property. **Unreachable by construction** and stays so |
| `O8_UNBOUNDED` | response, fan-out or cost cannot currently be bounded safely |
| `O9_NOT_COLLECTABLE` | svcdoctor cannot responsibly collect it |

**A failed authentication attempt is `O6`, not `O2`.** It writes a counter, a log line and
possibly a lockout, and treating it as passive is the mistake this classification exists to
prevent.

### 2.4 The vantage claim ceiling

This is the sharpest freeze in the record, because it governs the candidate most likely to be
proposed again.

> **A contrast between two network positions proves that behaviour differs by network position,
> and nothing else.**

It does **not** prove — and no finding, detail, discriminator, rationale or recommendation may
say — that a **firewall**, a **route**, a **security group**, a **NetworkPolicy**, a **proxy** or
a **server-side condition** produced the difference. svcdoctor observed none of them and can
distinguish none of them.

Three consequences bind permanently:

- **Measured contrast is an authority, and it is not causal authority.** The closed authority
  list is: protocol-authoritative · local-kernel-authoritative ·
  resolver-authoritative-for-this-query · operator-declared · remote-peer-reported ·
  measured-contrast · inferred-only. A record that lets the sixth become the first is wrong.
- **A same-endpoint multi-vantage measurement is never modelled as two targets.** Doing so would
  make it the cross-target causal diagnosis ADR 0073 forbids and ADR 0083 §2.7 re-states.
- **Two samples are not a population.** Failure from two positions does not establish that a
  condition is not vantage-specific.

`test/diagnosis/falsepositive_test.go` FP01A already enforces the first consequence for a TCP
timeout, by scanning **the whole document** — a mechanism svcdoctor never observes has no business
in an evidence attribute either. Nothing here weakens it.

### 2.5 Operator-declared intent is a premise, never next-best evidence

> **What the operator expected is an input to diagnosis, not an observation of the target.**

Five of the audit's twenty-nine candidates were blocked on intent, across three services. For all
of them:

- intent is class **`O4_OPERATOR_DECLARED`**;
- it may **never** be marked `SelfCollectable: true` — that would claim svcdoctor could discover
  what the operator meant;
- it may never be described as an observation svcdoctor could take, in a discriminator, a
  rationale or a recommendation;
- **its arrival would not make svcdoctor a planner.** It would give existing rules a second
  input.

**ADR 0083 §2.6 is not reopened.** Declared intent stays deferred on its own terms: a small
closed vocabulary of typed expectations, never a policy language, against ADR 0071's
strict-schema contract, in its own record, and **never as a side effect of a service phase**
because it applies to every service the instant it exists. Its principal risk is named here so
that record inherits it: **a declared expectation that drifts from reality produces confident
findings about a system that is fine — a configuration-driven false positive, a category this
tree currently has none of.**

### 2.6 Information gain is ordinal and never a ranking input

Four values: **`NONE` · `LOW` · `MATERIAL` · `DECISIVE`.** A candidate needs `MATERIAL` or
`DECISIVE` for at least one realistic outcome, with the reason written out.

**Forbidden:** percentages, entropy, mutual information, probability, any learned model, any
score, and any threshold. This restates ADR 0086 §2.5 for a new consumer and adds nothing to it:
cardinality and gain may be **shown**; they may never **decide**.

### 2.7 The minimum justified iteration model is A, and it is already built

| Model | Shape | Verdict |
|---|---|---|
| **A** | diagnose → emit structured `NEXT_EVIDENCE` → the operator or an external system collects | **Selected, and implemented since Phase 10.4B** |
| **B** | diagnose → choose one bounded self-collectable observation → collect once → re-evaluate | **Refused.** Its only plausible instance in the tree is re-measuring after a budget cut, which would make the operator's timeout advisory, make `Result.Incomplete()` and exit 4 mean something that moves, and be the hidden second collection pass ADR 0078 §2.6 forbids |
| **C** | the same, iterated | **Refused.** With no observation svcdoctor may take, it is a loop with an empty body |

**Model A is not a plan.** `domain.Recommendation` carries `action`, `kind`, `safety`,
`rationale` and `selfCollectable`; `Advice.Recommendation` is the single production projection;
`internal/render/terminal/findings.go` prints `[NEXT_EVIDENCE / COMPARE / you must collect]`; and
`TestNBE021EveryHypothesisDiscriminatorHasStructuredNextEvidence` guards the binding with a
**shrink-only** exemption list of exactly one entry.

**No `INVESTIGATE` mode is authorized and no `--investigate` flag is designed, named or
reserved.** The consent rule is frozen conditionally so a future phase does not re-derive it:
**an observation of class `O2` or above requires explicit operator consent**; `O0` and `O1`
require none, because nothing extra is sent. ADR 0078 §2.6 and ADR 0086 §2.7's five requirements
for any iterative phase are unchanged and unrelaxed.

### 2.8 Nothing here widens any existing boundary

**Credential authority is untouched.** Credentials stay bound to the logical endpoint (ADR 0028,
ADR 0030); discovered endpoints inherit nothing (ADR 0050); there is no mechanism for a
credential at a second vantage and none is proposed. A candidate whose credential story is
ambiguous is `SelfCollectable: false` or rejected — never resolved by relaxing the model.

**Safety classes are untouched.** `RESTART`, `DISRUPTIVE` and `SECURITY_WEAKENING` stay
unreachable by construction, refused by `NewAdvice` and re-refused at the report boundary. **No
observation may be proposed as `O7`**, and `--tls-insecure` is never a diagnostic step: it is an
operator's explicit per-run choice, recorded, and svcdoctor must never recommend disabling the
verification it exists to perform.

**Service observation ceilings are untouched.** No SQL (ADR 0039 §17). `Topics = []` stands
(ADR 0089 §3.1). The Redis three-command allowlist stands (ADR 0063 §11). No RabbitMQ channel, no
passive declare, no management API — and each of those three would need its own record, never
one (ADR 0089 §9).

**Budgets are unchanged and no fourth nesting level is created.** Recorded as pressure for
whoever proposes one: the three budgets are `context`-derived, and **target concurrency bounds
targets and not sockets** — ADR 0073 §10.1's global probe semaphore is still declined — so an
iterative mode multiplying observations per target would multiply sockets with no global bound.

### 2.9 Canonical diagnostic behaviour is deterministic, permanently

No LLM, no embedding similarity, no probabilistic model, no semantic or fuzzy matching, no
external AI service, and no opaque classifier may decide any canonical diagnostic output — a
finding, a code, a kind, a severity, a confidence, a discriminator, a recommendation, a merge, or
the selection of any observation.

An LLM may one day **explain** canonical output. It may never **decide** it. This restates
`docs/design/DIAGNOSTIC_INTELLIGENCE.md` §O and ADR 0081 §2.2b as a rule binding any future
planning work.

### 2.10 The cross-target boundary is unchanged

No cross-target causal diagnosis, no shared-cause hypothesis, no run-level finding code
(ADR 0073, ADR 0074, ADR 0083 §2.7). `domain.RunReport` wraps target reports **verbatim** and
never merges them, proven by test.

### 2.11 What must not be built, and the gates any winner must pass

**Refused while no candidate is admitted**, and a change-set that adds one has left this record:

- a `Planner` interface, type or package;
- a planning loop, or any iterative collection;
- a `--investigate` flag or any equivalent mode;
- a `DiscriminatorID` or any typed discriminator identity;
- a hypothesis-set engine, a set object, a set finding code, or any generic grouping abstraction
  — ADR 0086 §2.11's prohibition is inherited unchanged, and NBE-044 already fails the build;
- an observation scheduler;
- a planning budget or a fourth budget nesting level;
- a producer for `CONTRADICTION`, `MISSING` or `BLOCKED` — ADR 0087's OUTCOME C stands, and
  REL-014's rule that the two vacuous `AdmitConfidence` guards must be armed in one change-set is
  untouched;
- a typed credential-capability category — ADR 0086 §2.6 refuses it permanently.

**Twenty-five gates bind any future candidate proposed as a first implementation. All must pass:**

`G01` a real production diagnostic frontier · `G02` two real competing explanations · `G03` the
same evidence permits both · `G04` operationally distinct · `G05` a concrete discriminator
observation · `G06` `MATERIAL` or `DECISIVE` gain · `G07` bounded observation semantics · `G08`
authority precisely known · `G09` no causal overclaim · `G10` no security weakening · `G11`
credential authority preserved · `G12` bounded cost · `G13` bounded response and fan-out · `G14`
cancellation feasible · `G15` a deterministic fixture is feasible · `G16` supported-version
compatibility understood · `G17` canonical report semantics can represent the result · `G18`
convergence safety understood · `G19` no cross-target causal diagnosis · `G20` no LLM dependency ·
`G21` acceptable false-positive risk · `G22` existing evidence cannot already answer it · `G23`
operator value materially exceeds output noise · `G24` the minimal model A/B/C is identified ·
`G25` the BASIC-versus-consent requirement is understood.

**One gate failure means no winner.** The audit's §12 applies all twenty-five to the two
strongest candidates: the alternate-vantage measurement fails **eight**, and the PostgreSQL
admission contrast passes **all twenty-five** and is still not selected — because selecting it
would authorize building something that already exists.

---

## 3. Consequences

**Phase 11.0 changes no production code, no test, no fixture and no harness.** Every frozen count
is unchanged: `SchemaVersion` **1**, `RunSchemaVersion` **1**, finding codes **65**, production
rules **22**, failure classes **42**, `RuleContext` fields **3**, external modules **2**,
`Reveal` **4**, `SecretFor` **4**, exit codes **5**.

**Phase 10.4C remains CLOSED**, and the audit shows *why* rather than asserting it. Its condition
1 fails on its own: the tree's two hypothesis-carrying codes have different subjects and —
decisively — **different open questions** (*re-run with a larger budget* versus *compare against
the expected addresses*). Two different observations cannot be one open question.

**Phase 10.5B remains CLOSED.** `.Contradict`, `.Miss` and `.Block` still have zero production
producers; `.Support` still has one site.

**The value a planner would deliver is already delivered.** That is the record's most useful
consequence and the one a future reader should take first: five `NEXT_EVIDENCE` producers across
two services, each naming a discriminating observation, its safety class, why it discriminates,
and whether svcdoctor could ever take it. **Two `SelfCollectable: true` values exist, and both
mean "re-run with a larger budget" — which is not planning.** The honest answer to *"could
svcdoctor take this observation?"* is, everywhere else, **no**, and saying so is more useful than
implying it already looked.

**One documentation gap is recorded and not fixed.** `docs/FINDINGS.md` documents Kafka,
PostgreSQL, generic transport and RabbitMQ, and **the nine `REDIS_*` codes have no entry in it at
all**. No behaviour is wrong — the codes are specified in ADRs 0063–0066, implemented and tested
— but the finding catalog is incomplete, and writing a service section is a documentation phase's
work rather than an audit's.

**One measurement is worth keeping.** On **Go 1.26.6**, a *received* TLS alert surfaces as
`*tls.permanentError` and matches neither `tls.AlertError` nor `tls.RecordHeaderError` nor
`*tls.CertificateVerificationError`; the description survives only in the error text, which
`internal/probe/tls` refuses to match by policy. So `TLS_VERSION_MISMATCH`,
`TLS_CLIENT_CERTIFICATE_REQUIRED` and `TLS_CLIENT_CERTIFICATE_REJECTED` remain unproducible
**without text matching**, and the package's own comment — which said this of `protocol_version`
alone — is right and narrower than the truth.

---

## 4. Alternatives considered

**Admit the alternate-vantage measurement (C-01/C-12).** *Rejected as a winner; deferred on
architecture.* Its epistemics are the best in the audit and every non-epistemic gate fails at
once: svcdoctor has one `VantageSource` and `NewLocalVantage` is the only constructor by design,
a report carries one vantage, the aggregate forbids merging, no execution channel exists, and the
bounded claim it buys — *reachability differs by network position* — is one an operator with a
second vantage establishes in ten seconds with a shell. **Building it means becoming a
distributed execution system**, which is the largest security surface anyone could propose adding
here.

**Admit the alternate-resolver DNS observation (C-05).** *Rejected as a winner; deferred on
architecture.* Its information gain is the highest measured and two objections are decisive. A
public resolver would **disclose the operator's internal hostname to a third party**, which is a
data-exfiltration channel with a helpful name and is **refused permanently**. And
`dns.SystemResolver` is chosen precisely because it is *"the resolver a client on this vantage
would use"* — **a second resolver answers a question about a different client**, which is
backwards when split horizon is working as designed.

**Admit the PostgreSQL admission contrast (C-18).** *Rejected because it is built.* It passes all
twenty-five gates. It also already carries a `NEXT_EVIDENCE` / `COMPARE` recommendation with a
rationale and `SelfCollectable: false`, and its finding's own detail states both competing
explanations. Three cheaper self-collectable routes were sought and refuted rather than assumed:
a second session cannot exist (the refused address never reaches one, which is the finding's
premise); a credential-free identity contrast is asymmetric, so agreement would have to be read
as evidence of sameness; and the DNS answer set cannot tell one host's two address families from
two hosts.

**Admit a vantage-contrast recommendation on every transport failure (C-02).** *Rejected.* It
would restate prose the finding already carries, it would be identical on every transport
failure — and the only way to make it evidence-dependent is to key it on the failure class, which
reintroduces exactly the per-address-family arbitration ADR 0043 refused when it merged six
classes into one code.

**Admit re-measurement after a budget cut as Model B (C-08).** *Rejected*, on four independent
grounds in §2.7.

**Build a planner anyway, over a synthetic corpus.** *Rejected — it is the inversion this
repository refuses in three separate places.* ADR 0054's *owner before producer*, ADR 0086
§2.11's *producer before engine*, and `CLAUDE.md`'s *"concrete structs first; interfaces only at
real boundaries; do not introduce speculative machinery."*

**Freeze nothing and simply defer.** *Rejected.* Three phases have now re-derived this
vocabulary, and the arguments most likely to reopen the question wrongly are the ones a
reasonable engineer reaches for first. Writing the ceilings down once is cheaper than answering
them a fourth time.

**Declare the diagnostic frontier closed.** *Rejected on the evidence.* Nine candidates are
deferred with named conditions, and three of them are blocked only by a fixture nobody has built.

---

## 5. Security implications

**Nothing in this record widens any surface**, and the phase writes no Go.

Four active security decisions are recorded rather than implied:

- **The vantage ceiling (§2.4) is a security decision as well as an epistemic one.** A tool that
  turned a two-position contrast into *"a firewall is blocking you"* would send operators to
  change firewall rules on evidence that supports no such conclusion.
- **A public DNS resolver is refused permanently (§4).** svcdoctor is most often aimed at names
  that exist only inside a private zone.
- **Credential-rejection disambiguation is refused as an attack (audit C-14).** Probing to
  separate *unknown identity* from *wrong secret* is a user-enumeration oracle; if it worked, the
  endpoint would have a vulnerability. The absence of that discriminator is a **security property
  of the protocols**, not a gap in svcdoctor.
- **No remote-execution channel is authorized, designed or reserved.**

`O7_SECURITY_WEAKENING` has no producer, must never gain one, and `SECURITY_WEAKENING` advice
stays unreachable by construction.

---

## 6. Compatibility implications

**None.** `SchemaVersion` **1**, `RunSchemaVersion` **1**, finding codes **65**, failure classes
**42**, `RuleContext` fields **3**, exit codes **5**, external modules **2** — all unchanged. No
CLI flag, no report field, no renderer contract and no `docs/COMPATIBILITY.md` grading moves.

---

## 7. Reopen conditions

**The single condition that would reopen diagnostic planning**, stated as narrowly as it can be:

> A production diagnosis reaches a state where **two competing explanations** remain under §2.2,
> and there exists an observation that **(a)** svcdoctor could take **from its own vantage with
> its existing credential authority**, **(b)** is class `O0`, `O1` or `O2` with a bounded
> response, and **(c)** whose outcomes would **materially** change what svcdoctor may claim.

The nine deferred candidates carry their own narrower conditions:

| Candidate | Condition |
|---|---|
| **C-01 / C-12** alternate-vantage measurement | a vantage model, a remote-execution contract, a two-vantage report shape and a security review — four records, and a reason better than *"it would be nice to know"* |
| **C-05** alternate DNS resolver | a probe-capability record, an operator-supplied-resolver CLI decision, a privacy review, a report representation for *resolved differently elsewhere*, and a DNS client that does not move the module count |
| **C-06** re-verify a rejected chain against the other trust source | a security review of publishing an alternate-trust verdict, and a decision on whether a second verification pass belongs in a probe. **It is an evidence-consumption question under ADR 0090 §12.6, not a planning one** |
| **C-21** declared operational intent | ADR 0083 §2.6's own terms, unchanged, plus the configuration-driven-false-positive risk named in §2.5 |
| **C-16** Kafka unrepresentable advertisement | ADR 0090 §12.4, unchanged |
| **C-24** Redis client-limit exhaustion | RRI-017a, unchanged: a **closed, structurally authoritative** signal. Never text matching |
| **C-25** Redis / RabbitMQ multi-address aggregates | ADR 0088 and Phase 10.6A §5, unchanged: a multi-address run whose addresses **disagree** |
| **C-28** RabbitMQ `VHOST_DOWN` | ADR 0090 §12.5, unchanged: a live measurement |
| **C-10** TLS handshake floor | a Go release exposing a **received** alert as a typed error. **Re-measure before assuming; do not read the text** |

**One reopening that is explicitly not a planning reopening.** If declared intent lands, it gives
existing rules a second input. It does not create a planner, and a phase that treats it as one has
misread §2.5.

---

## 8. The correction

ADR 0086 §1.2 states that the two hypothesis-carrying Kafka codes *"have different subjects,
different layers and different codes, and they are not alternatives."*

**The layers are the same.** `internal/diagnosis/kafka/advertisedendpoint.go:224` and
`internal/diagnosis/kafka/topology.go:662` both set `domain.LayerTopology`.

The conclusion is unaffected: subject and open question each independently prevent a set, and
ADR 0086 §2.2 explicitly frees a set from needing one layer anyway. But the stated reason was one
third wrong, and it is corrected here rather than repeated. The original text stands, per this
repository's convention that reasoning which was wrong stays legible.
