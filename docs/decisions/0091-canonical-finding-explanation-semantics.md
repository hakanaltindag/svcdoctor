# ADR 0091 — Canonical finding explanation semantics: enrichment is a report change, not a rendering

- **Status:** Accepted
- **Date:** 2026-09-06
- **Phase:** 10.8A.1 (corrective contract freeze; documentation only, no production code)
- **Supersedes:** **ADR 0090 §5, §6 and §11 in part** — precisely the statements listed in §2.
  Everything else in ADR 0090 stands, including its audit, its winner and its frozen counts.
- **Upholds:** ADR 0014 (severity is data; a finding cites evidence), ADR 0016 (the report owns the
  canonical JSON shape), ADR 0034 §3 (duplicate versus complementary), **ADR 0067 §3.1** (a finding
  must say the vhost default was used), ADR 0069 §3, §6, §8, ADR 0081 §2.2b (Summary and Detail are
  merge preconditions), ADR 0083 (additive schema evolution; §2.6 declared intent frozen),
  ADR 0088 (authority boundary), ADR 0090 (the evidence-consumption audit and its winner)
- **Decision:** **CANONICAL EXPLANATION ENRICHMENT AUTHORIZED.** Phase 10.8B may make
  `Finding.Detail` more specific where the closed `rabbitmq.close_outcome` supports it, and
  canonical JSON bytes **will** change for those reports. No schema, code, rule, confidence or
  failure-class change. §4.

---

## 1. Context

Phase 10.8B stopped before writing any code. Its mandatory pre-implementation archaeology
disproved an assumption ADR 0090 had frozen, and the STOP was correct.

ADR 0090 §6 specified the implementation as *"one closed lookup in
`internal/diagnosis/rabbitmq/connectionopen.go` from the already-recorded outcome to a detail
clause and a scoped recommendation"*, and described the result as *"additive in presentation and
inert everywhere else."*

`Finding.Detail` and `Finding.Recommendations` are canonical domain fields. They are serialized by
`Finding.MarshalJSON` into the canonical JSON report. Writing to them is not inert.

So the triple ADR 0090 asserted — *presentation activation* **+** *enrich Detail and
Recommendation* **+** *canonical JSON unchanged* — is internally inconsistent, and no choice of
implementation location resolves it. This record fixes the contract rather than the code, and it
does so through supersession rather than by amending an Accepted decision.

`docs/validation/PHASE108A1_CANONICAL_FINDING_EXPLANATION_CORRECTION.md` holds the proofs.

---

## 2. Exactly what is superseded

Narrowly. Five statements, no more.

| # | ADR 0090 statement | Status |
|---|---|---|
| S1 | §6 — *"the change is additive in presentation and inert everywhere else"* | **Superseded.** It is additive in **canonical domain data**; the report changes (§3) |
| S2 | §5, §6 — "presentation" used in a sense that reads as renderer-only | **Superseded** by the term frozen in §5 |
| S3 | §6 — *"a detail clause **and a scoped recommendation**"*, authorized together | **Narrowed.** Recommendations stay byte-identical by default (§7) |
| S4 | §5.4, and the audit's §7.25/§9.1 — LavinMQ *"was never measured producing any limit text"*, therefore *"no sentence; output unchanged"* | **Superseded.** LavinMQ produces `VHOST_CONNECTION_LIMIT`, measured (§6) |
| S5 | §6 — the fixture requirement for *"all three ceilings"* as if none existed | **Corrected.** The vhost ceiling is already proven on both implementations; two remain (§6.2) |

**Not superseded, and explicitly reaffirmed:** ADR 0090's inventory (70 recorded, 38 unconsumed),
its taxonomy, its 31 rejections and 6 deferrals, its §7 *"unconsumed is not debt"* clause, its §8
frontier analysis, its §12 reopen conditions, and its selection of `rabbitmq.close_outcome` as the
single winner at class **C1-A**.

ADR 0090's text is left standing. A reader who follows the supersession finds the reasoning that
was wrong still legible, which is this repository's convention.

---

## 3. The architecture, frozen

```text
Evidence  →  Diagnosis  →  canonical Finding ──→ canonical JSON
                             Code · Summary · Detail        │
                             Recommendations · EvidenceRefs └─→ human renderers (verbatim)
```

- `internal/domain/finding.go:334-347` declares `Summary`, `Detail` and `Recommendations` as JSON
  fields; `MarshalJSON` emits all three.
- `internal/render/json` reimplements nothing — *"json.Marshal calls the report's own
  MarshalJSON."*
- `internal/render/terminal/findings.go:27-32` forbids the alternative in as many words:
  *"It repeats what the finding says and adds nothing… a renderer rewording them would be making a
  diagnostic claim in a presentation layer."*

**Therefore: finding explanation is canonical report semantics.** svcdoctor has **no
operator-facing presentation layer for finding prose**, and "renderer-only rewording of a finding"
is not expressible in this architecture. That is the fact ADR 0090 lacked.

---

## 4. Schema change is not value change

The distinction ADR 0090 needed.

| | Phase 10.8B |
|---|---|
| `SchemaVersion`, `RunSchemaVersion` | **unchanged** |
| JSON object structure, `Finding` field set | **unchanged** |
| `FindingCode` vocabulary | **unchanged** |
| `Finding.Detail` **value** | **may become more specific** where existing authoritative evidence supports it |
| canonical JSON **bytes** | **may change**, for evidence states receiving the bounded explanation |

ADR 0083 governs the *shape* of the report, and nothing here changes the shape. This is a
**canonical diagnostic explanation change**: the same fields carrying a more specific true
sentence.

**The phrase "canonical JSON unchanged" is retired** for this line of work. It conflated structure
with content and made the weaker half unverifiable.

---

## 5. Terminology: canonical explanation enrichment

ADR 0090's decision was already corrected once, from *activate diagnosis* to *activate
presentation*. That correction was directionally right — **no new diagnostic inference is
created** — and its substance survives. But "presentation" reads as renderer-only, and §3 proves
that reading false here.

> **The frozen term is CANONICAL EXPLANATION ENRICHMENT.**

- **explanation** — it changes what the report *says*, never what it *concludes*;
- **canonical** — that text is canonical domain data, so the report changes.

**The candidate is not reclassified.** It remains **C1-A**: it rests entirely on already-recorded
authoritative evidence and adds no rule, no code, no confidence admission and no inference. C1-B is
for a candidate supporting a *new claim*; this supports none.

### 5.1 The precedent, and its exact limits

svcdoctor **already** varies canonical `Finding.Detail` from an evidence attribute, and an Accepted
record required it. `vhostNotFoundDetail(node)`
(`internal/diagnosis/rabbitmq/connectionopen.go:194-203`) reads `AttrVHostDefaulted` and appends a
fixed clause, because **ADR 0067 §3.1** says *"when a vhost-scoped refusal occurs and `--vhost` was
not supplied, the finding must say that the default was used."*

The precedent proves five things and no more: Detail may vary with a bounded evidence attribute;
selection is by a **closed** value; the attribute is read from **the finding's own cited node**,
handed in directly; the variation is **fixed svcdoctor prose**; and an Accepted record authorizes
the sentence. It does **not** license reading any attribute, varying a recommendation, searching
the graph, or rendering an unbounded value.

Phase 10.8B is consistent with it on every point, and this record is its authorizing ADR.

---

## 6. LavinMQ correction, and the rule it forces

ADR 0090 asserted that LavinMQ was never measured producing a limit text and would therefore yield
`UNSPECIFIED` with byte-identical output. **The repository disagrees in two places.**

- **Template L3**, `internal/adapter/rabbitmq/wire/close.go:143-147`, maps LavinMQ's vhost
  connection-limit sentence to `CloseVHostConnectionLimit`.
- **LMQ-06**, `test/integration/lavinmq/scenarios_test.go:183-208`, measures it against real
  LavinMQ 2.3.0 and asserts both the outcome and `RESOURCE_LIMIT_REACHED`. Its comment records that
  this scenario is what upgraded L3 from source-derived to measured.

This is **not** a false enrichment to defend against. LavinMQ reaches the outcome through the same
construct-and-compare byte-equality discipline, and it means the same thing.

> **The explanation is driven by the authoritative `close_outcome`, never by product identity.**

No `if RabbitMQ` / `if LavinMQ`, in generic core or in a service rule. A compatible implementation
that legitimately produces the same closed outcome **earns the same bounded explanation** — and no
outcome is broadened merely because two implementations are compatible. The shared explanation is
earned by the **shared authoritative outcome** alone. If a template later proves to mean something
different on one implementation, the template is corrected, not the explanation.

### 6.1 The consequence for testing

The right LavinMQ tests are that it **does** receive the vhost-limit explanation, and receives
**no** node or user explanation because it produces neither outcome. A blanket "LavinMQ negative
contrast" would assert something now known to be false.

### 6.2 Real-fixture status, measured

ADR 0090 demanded three new fixtures. Its grep was too narrow — the tree spells it
`max-connections` and names the vhost `limited`.

| Outcome | Status |
|---|---|
| `VHOST_CONNECTION_LIMIT` — RabbitMQ | **PROVEN_REAL, committed.** RAB-21, `vhost_test.go:104-137`, provisioned on **all three** brokers (4.2.0, 3.13.7, 4.0.9) |
| `VHOST_CONNECTION_LIMIT` — LavinMQ | **PROVEN_REAL, committed.** LMQ-06 |
| `NODE_CONNECTION_LIMIT` | **PROVEN_ONLY_UNIT.** No `connection_max` in any fixture |
| `USER_CONNECTION_LIMIT` | **PROVEN_ONLY_UNIT.** No `set_user_limits` anywhere |

**The gap is two outcomes, not three.** The limit-0 strategy ADR 0090 *proposed* is already in
production use for the vhost case and already deterministic. Phase 10.8B must establish the
equivalent for the other two — and must **verify** the provisioning: `set_vhost_limits` currently
ends in `|| true` and is unverified, which is the Phase 9.1C defect in miniature.

---

## 7. Detail authority is not recommendation authority

`close_outcome` proves **which ceiling the peer named** when it refused this attempt. It does not
prove what the operator should change: a node ceiling may be correctly configured and legitimately
saturated, a user ceiling may be a deliberate quota or the caller's own leak, and the condition may
already have passed.

| Field | Authority |
|---|---|
| `Finding.Detail` | **MAY** become more specific, where directly supported by the closed outcome |
| `Finding.Recommendations` | **MUST remain byte-identical by default** |

A recommendation changes only if Phase 10.8B **separately proves** the specificity is justified
without operator intent, causal inference, global-state inference, configuration-quality opinion or
tuning advice. **The burden is on changing them; the preference is not to.** This narrows ADR 0090
§6, which authorized both in one breath and justified only one.

---

## 8. The claim ceiling

Frozen as semantics, not as prose. Phase 10.8B derives wording from current style.

**Allowed shape:** this attempted AMQP connection was refused, and the authoritative classified
outcome identified the **node** / **virtual-host** / **user** connection-limit **scope**.

**Forbidden permanently:** globally exhausted · all slots used · server or broker overloaded ·
RabbitMQ unhealthy · misconfigured · limit too low · increase the limit · connection leak · root
cause · capacity exhausted everywhere.

`RESOURCE_LIMIT_REACHED` is **not weakened and not redefined**, and the existing impermanence
sentence stays.

### 8.1 "Named" is not "reached", and PostgreSQL settled it first

The code says `REACHED`; the evidence proves the peer **named a scope** while refusing **this**
attempt. ADR 0088's authority boundary requires keeping those apart, and `53300` is the precedent:
`test/integration/postgres/intelligence_test.go:117` pins *"a connection limit that applied to this
attempted session"*. **`named` / `identified` / `reported` are safe; `exhausted` is not.**

And **absence is not evidence**: a truncated reply degrades to `UNSPECIFIED_TRUNCATED`, so a real
ceiling can go unnamed. Presence proves the scope; absence proves nothing.

---

## 9. The canonical JSON compatibility contract

| Case | Canonical `Finding` | Canonical JSON |
|---|---|---|
| mapped capacity outcome | `Detail` **expected to change** | **bytes expected to change** |
| unmapped / non-capacity outcome | **byte-identical** | **byte-identical** |
| schema, field set, both schema versions | **unchanged globally** | **unchanged globally** |
| code, severity, confidence, kind, layer, subject, `evidenceRefs`, `vantageDependent` | **unchanged globally** | **unchanged globally** |
| `Recommendations` | unchanged unless separately admitted under §7 | same |
| exit status | **unchanged globally** | — |

The byte-identity half must be **proven by test**, not asserted.

---

## 10. Convergence and evidence membership

**Convergence.** ADR 0081 §2.2b makes `Summary` and `Detail` merge preconditions, so varying Detail
touches convergence. Phase 10.8B must prove four cases: same subject with the same outcome; same
subject with **different** capacity outcomes, which must never collapse into prose naming one
ceiling while citing both; a mapped outcome beside a generic `RESOURCE_LIMIT_REACHED`, which must
not collapse into misleading specific prose; and different subjects, which stay distinct.
`internal/app/rabbitmq.go:281` continues at most one path, so the multi-node shapes are graphs no
producer makes today — that lowers the risk and does not discharge the proof.
**No convergence architecture change is authorized**, and the `RuleID`-winner prose §2.2b withdrew
stays withdrawn.

**Evidence membership.** The explanation may use only `close_outcome` from the finding's own cited
evidence. No graph-wide search, no first match, no cross-endpoint, no cross-target.
**Already true by construction:** `connectionopen.go:110-127` hands
`connectionOpenFinding(node)` exactly the node whose identifier becomes the finding's sole
`EvidenceRefs` entry — the same shape `vhostNotFoundDetail(node)` uses. No graph redesign is
needed or permitted. Phase 9's multi-target isolation is untouched: the enrichment stays inside a
per-target report and derives nothing at `RunReport` level.

---

## 11. Revised Phase 10.8B stop conditions

STOP if: arbitrary peer prose can reach canonical `Detail`; the closed vocabulary is not
structurally enforced; evidence membership cannot be established; safe enrichment requires a new
rule, code or confidence; `FailureClass` semantics must change; schema must change; unmapped
outcomes cannot remain byte-identical; recommendation specificity cannot be justified but is
changed anyway; convergence becomes semantically unsafe; a product-name branch is required; the
node or user fixture cannot be produced deterministically; or compatible-peer behaviour cannot be
proven.

> **Canonical JSON byte change for mapped outcomes is no longer a stop condition. It is expected.**

---

## 12. Rejected alternatives

| Alternative | Verdict |
|---|---|
| **Amend ADR 0090 in place** | **Rejected.** The convention is supersession, and the reasoning that was wrong should stay legible. §2 lists exactly five superseded statements so the amendment cannot creep |
| **Enrich in `writeFindings`, keeping JSON byte-identical** | **Rejected.** `findings.go:27-32` forbids generating prose there — *"a renderer rewording them would be making a diagnostic claim in a presentation layer."* It would also make the terminal say what the canonical report does not, and the canonical consumer is the one that matters |
| **Enrich via the Result-block `conditionalNote` mechanism** | **Rejected twice.** It reads `lastNodeAt(graph, step)` — a graph-wide lookup, which §10 forbids — and ADR 0090 §11 already rejected it on the merits: a raw outcome detached from the finding explaining it is worse than the enumeration it replaces |
| **Add a presentation-only field to `Finding`** | **Rejected.** That *is* a schema change, and it would create two sources for one sentence — the drift ADR 0016 exists to prevent |
| **Bump `SchemaVersion` because output changed** | **Rejected.** ADR 0083's additive-evolution policy is about shape. No consumer's parse breaks when a `detail` string becomes more specific; a version bump would signal a structural change that did not happen |
| **Withdraw the candidate** | **Rejected.** Nothing about its safety, authority or value changed. Only the description of its layer was wrong |
| **Reclassify the candidate as C1-B** | **Rejected.** It adds no rule and supports no new claim. A more specific true sentence about an existing claim is not a new claim (§5) |
| **Keep "canonical JSON unchanged" and scope 10.8B to something smaller** | **Rejected.** There is nothing smaller that closes the gap: the information loss is in the canonical explanation itself |

---

## 13. Reopen conditions

1. **A human renderer arrives that is authorized to interpret findings** — Markdown or HTML with
   its own record. Then the renderer-versus-domain question in §3 is worth re-asking; today only
   two renderers exist and one is the canonical serializer.
2. **A presentation-only finding field is decided on its own merits**, with an answer to the
   two-sources-for-one-sentence problem. Then §12's fourth row is reopened.
3. **`Finding.Detail` stops being canonical.** Then this record's premise is gone and it should be
   superseded in turn.
4. **A capacity outcome cannot be fixture-proven.** Then it receives no explanation, and §6.2's
   table is the record of which ones did.
5. **A compatible implementation reaches a capacity outcome through a template that turns out to
   mean something different.** Then the *template* is corrected against the measurement, per
   ADR 0069 §9.1 — never the explanation, and never by a product-name branch.
