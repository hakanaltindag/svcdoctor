# Phase 10.8A.1 — canonical finding explanation contract correction

- **Phase:** 10.8A.1 — corrective contract freeze. **Documentation only. No production Go, no
  test Go, no fixture, no harness, no config.**
- **Baseline:** `872575533e996ef116a1e4a24a91fec4afa0a0bd`, `HEAD == origin/main`, tree clean
- **Record:** ADR 0091, which narrowly supersedes parts of ADR 0090 and does not amend it
- **Cause:** Phase 10.8B stopped before implementation. Its §26/§27 archaeology disproved one
  assumption ADR 0090 froze.
- **Outcome:** **CANONICAL EXPLANATION ENRICHMENT AUTHORIZED.** The candidate, its class and every
  frozen count survive unchanged. What changes is the description of *where finding explanation
  lives* and therefore *what output is permitted to move*.

---

## 1. Baseline

| Fact | Value | How |
|---|---|---|
| `HEAD` == `origin/main` | `8725755` | `git rev-parse` |
| working tree at start | clean | `git status --short` empty |
| ADR 0090 | **committed** at `8725755` | `git ls-files` |
| `make check` before edits | **exit 0** | fmt-check · test · vet · `golangci-lint` *0 issues* · build |
| next available ADR | **0091** | highest present is `0090` |

Frozen counts, unchanged and unchangeable by this phase: `SchemaVersion` **1**,
`RunSchemaVersion` **1**, finding codes **65**, production rules **22** (RabbitMQ **3** rules /
**11** codes), `RuleContext` fields **3**, failure classes **42**, modules **2**, `Reveal` **4**,
`SecretFor` **4**, exit codes **5**.

---

## 2. What Phase 10.8B disproved

ADR 0090 §6 specified the Phase 10.8B implementation as:

> *"One closed lookup in `internal/diagnosis/rabbitmq/connectionopen.go` from the already-recorded
> outcome to a detail clause and a scoped recommendation"*

and characterized the result as:

> *"the change is **additive in presentation and inert everywhere else**."*

**The second statement is false.** `Finding.Detail` and `Finding.Recommendations` are canonical
domain fields, serialized into the canonical JSON report. Writing to them is not inert; it changes
the report.

So the triple

```text
ACTIVATE RABBITMQ PRESENTATION
  + enrich connectionOpenFinding Detail/Recommendation
  + canonical JSON bytes unchanged
```

is internally inconsistent, and Phase 10.8B was right to stop rather than pick two of the three.

---

## 3. The actual architecture, frozen

### 3.1 Canonical serialization proof

`internal/domain/finding.go:334-347` — the wire shape of a `Finding`:

```go
type findingJSON struct {
	Code             FindingCode      `json:"code"`
	Kind             FindingKind      `json:"kind"`
	Severity         Severity         `json:"severity"`
	Confidence       Confidence       `json:"confidence"`
	Layer            Layer            `json:"layer"`
	Subject          *Subject         `json:"subject,omitempty"`
	Summary          string           `json:"summary"`
	Detail           string           `json:"detail,omitempty"`
	EvidenceRefs     []EvidenceID     `json:"evidenceRefs"`
	Recommendations  []Recommendation `json:"recommendations,omitempty"`
	VantageDependent bool             `json:"vantageDependent"`
	Discriminator    string           `json:"discriminator,omitempty"`
}
```

`Finding.MarshalJSON` (`finding.go:356-378`) populates `Summary`, `Detail` and `Recommendations`
from the unexported fields and calls `json.Marshal`. **All three are canonical JSON.**

`internal/render/json/json.go:65-67` reimplements nothing: *"json.Marshal calls the report's own
MarshalJSON."* There is no second serializer and no presentation-only copy.

### 3.2 Renderer consumption proof

`internal/render/terminal/findings.go:47-59` reads `finding.Summary()`, `finding.Detail()` and
`finding.Recommendations()` and prints them verbatim. Its doc comment (lines 27-32) is an explicit
prohibition on the alternative:

> *"**It repeats what the finding says and adds nothing.** Code, severity, subject, summary, detail
> and recommendations, **as written**. No prose is generated here, no FailureClass is translated
> into a sentence, and no cause is named that the finding did not name. Those words were argued
> over in the ADRs that authorized each code, and **a renderer rewording them would be making a
> diagnostic claim in a presentation layer.**"*

Renderer surfaces present: `internal/render/json` and `internal/render/terminal`. No Markdown or
HTML renderer exists yet, so no second human surface can drift.

### 3.3 The frozen model

```text
Evidence
   ↓
Diagnosis
   ↓
canonical Finding ── Code · Summary · Detail · Recommendations · EvidenceRefs · …
   ↓                                    ↓
canonical JSON                    human renderers (verbatim)
```

**Therefore: finding explanation *is* canonical report semantics.** svcdoctor has no
operator-facing presentation layer for finding prose, and "renderer-only rewording of a finding" is
not expressible in this architecture. That is the fact ADR 0090 did not have.

---

## 4. Schema change versus value change

The distinction ADR 0090 needed and lacked.

| | Phase 10.8B |
|---|---|
| `SchemaVersion` | **unchanged** |
| `RunSchemaVersion` | **unchanged** |
| JSON object structure | **unchanged** |
| `Finding` field set | **unchanged** |
| `FindingCode` vocabulary | **unchanged** |
| `Finding.Detail` **value** | **may become more specific** where existing authoritative evidence supports it |
| canonical JSON **bytes** | **may change**, for evidence states that receive the bounded explanation |

This is **not schema evolution**. ADR 0083's additive-evolution policy governs the shape of the
report; nothing here changes the shape. It is a **canonical diagnostic explanation change**: the
same fields, carrying a more specific true sentence.

**The phrase "canonical JSON unchanged" is retired.** It conflated two things and made one of them
unverifiable.

---

## 5. Terminology

ADR 0090's decision was corrected once already, from `ACTIVATE RABBITMQ DIAGNOSIS` to
`ACTIVATE RABBITMQ PRESENTATION`. That correction was directionally right — **no new diagnostic
inference is created** — and is retained in substance.

But "presentation" reads as *renderer-only*, and §3 proves that reading is wrong here. The frozen
term is:

> **CANONICAL EXPLANATION ENRICHMENT**

It names both halves precisely:

- **explanation** — it changes what the report *says*, not what it *concludes*;
- **canonical** — that text is canonical domain data, so the report changes.

The candidate is **not** reclassified. It stays **C1-A**: it rests entirely on already-authoritative
recorded evidence, adds no rule, no code, no confidence admission and no inference. C1-B is
reserved for a candidate that supports a *new claim*, and this supports none.

---

## 6. The `vhostNotFoundDetail` precedent

**svcdoctor already varies canonical `Finding.Detail` from an evidence attribute, and an Accepted
record required it.**

`internal/diagnosis/rabbitmq/connectionopen.go:194-203`:

```go
func vhostNotFoundDetail(node domain.Evidence) string {
	if defaulted, ok := boolAttr(node, servicerabbitmq.AttrVHostDefaulted); ok && defaulted {
		return detailVHostNotFound + detailVHostDefaultedSuffix
	}
	return detailVHostNotFound
}
```

**ADR 0067 §3.1** mandates it:

> *"One mitigation is required and is part of this decision: **when a vhost-scoped refusal occurs
> and `--vhost` was not supplied, the finding must say that the default was used.** That converts
> the one bad case into a self-explaining one."*

### 6.1 Exactly what the precedent proves — and what it does not

**Proves:**

1. Canonical `Finding.Detail` **may** vary with a bounded evidence attribute.
2. The variation may be selected by a **closed** value (here a `bool`).
3. The attribute is read from **the finding's own cited node**, passed in directly.
4. The variation is **fixed svcdoctor prose**, appended or substituted — never interpolated peer
   content.
5. An Accepted ADR is what authorizes the specific sentence.

**Does not prove**, and must not be inferred:

- that any attribute may be read — only one supported by a record;
- that a *recommendation* may vary (this precedent varies Detail only);
- that a graph-wide lookup is acceptable — the node is handed in;
- that arbitrary-domain values may be rendered — the precedent's domain is two-valued.

Phase 10.8B is consistent with the precedent on every point, because `rabbitmq.close_outcome` is a
closed seven-value svcdoctor-owned set read from the same node, and ADR 0091 is the authorizing
record.

---

## 7. Correction — LavinMQ produces a capacity outcome

**Phase 10.8A stated the opposite, and it was wrong.** The 10.8A record says, at §7.25 and §9.1:

> *"LavinMQ produces different reply texts and was never measured producing any limit text at all,
> so it degrades to `UNSPECIFIED`… the new sentence does not appear, and the output is
> byte-identical to today's."*

The repository disagrees, in two places.

**Production template L3**, `internal/adapter/rabbitmq/wire/close.go:143-147`:

```go
// L3: LavinMQ, vhost capacity ceiling. Derived from LavinMQ's source rather
// than measured in Phase 8.0C, and the LavinMQ fixture exercises it: if the
// bytes differ, the scenario fails and this template is corrected against
// the measurement rather than the source.
case matchesDigitHole(text,
	"NOT_ALLOWED - access to vhost '"+vhost+"' refused: connection limit (",
	") is reached"):
	return CloseVHostConnectionLimit
```

**Real integration evidence**, `test/integration/lavinmq/scenarios_test.go:183-208` — **LMQ-06**,
against real LavinMQ 2.3.0. It establishes ground truth independently, then asserts
`AttrCloseOutcome == VHOST_CONNECTION_LIMIT` and `FailureClass == RESOURCE_LIMIT_REACHED`. Its own
comment records that this scenario is what upgraded L3 from source-derived to measured.

The vhost limit is provisioned through LavinMQ's management API
(`PUT /api/vhost-limits/limited/max-connections {"value":0}`, `Makefile:513-514`).

### 7.1 What this changes, and what it does not

It is **not** a false enrichment to protect against. LavinMQ reaches `VHOST_CONNECTION_LIMIT`
through the same construct-and-compare byte-equality discipline as RabbitMQ, and the outcome means
the same thing. A compatible implementation that legitimately produces the same closed outcome
**earns the same bounded explanation.**

The frozen rule is therefore:

> **The explanation is driven by the authoritative `close_outcome`, never by product identity.**

- No `if RabbitMQ` / `if LavinMQ` anywhere, in generic core or in the RabbitMQ rule.
- The shared explanation is earned by the **shared authoritative outcome**, not by compatibility in
  general. No other outcome is broadened because two implementations happen to be compatible.
- If a future implementation reaches an outcome by a template that turns out to mean something
  different, the fix is the template, not the explanation.

This makes §20 of the Phase 10.8B brief — "LavinMQ negative contrast" — the **wrong test to
require for the vhost ceiling**. The right LavinMQ tests are: it *does* receive the vhost-limit
explanation, and it receives **no** node or user explanation, because it produces neither outcome.

---

## 8. Correction — real-fixture status, measured

Phase 10.8A recorded the winner as `PROVEN_REAL (uncommitted)` and demanded three new fixtures. The
10.8A grep that produced that was too narrow: it searched `max_connections` / `CONNECTION_LIMIT`,
while the fixtures spell it `max-connections` and name the vhost `limited`. Measured now:

| Outcome | Status | Evidence |
|---|---|---|
| `VHOST_CONNECTION_LIMIT` — RabbitMQ | **PROVEN_REAL, committed** | `test/integration/rabbitmq/vhost_test.go:104-137` (**RAB-21**). Provisioned `set_vhost_limits -p limited '{"max-connections":0}'` on **all three** brokers — 4.2.0, 3.13.7, 4.0.9 (`Makefile:454`). Ground truth via `env/groundtruth.py`; asserts outcome, failure class, and that no peer text reached the report |
| `VHOST_CONNECTION_LIMIT` — LavinMQ | **PROVEN_REAL, committed** | `test/integration/lavinmq/scenarios_test.go:183-208` (**LMQ-06**), LavinMQ 2.3.0 |
| `NODE_CONNECTION_LIMIT` | **PROVEN_ONLY_UNIT** | `wire_test.go`, `fuzz_test.go`, terminal golden **G7**. **No** `connection_max` in `env/30-svcdoctor.conf` or `env/compose.yaml`; no integration scenario |
| `USER_CONNECTION_LIMIT` | **PROVEN_ONLY_UNIT** | `wire_test.go`, `fuzz_test.go`. **No** `set_user_limits` anywhere in the tree |

**The remaining Phase 10.8B fixture gap is two outcomes, not three**, and one of the two — the
vhost ceiling — is already covered on both implementations and across all three supported RabbitMQ
versions.

### 8.1 The limit-0 strategy is already proven, not proposed

ADR 0090 proposed limit 0 as a way to avoid capacity races. The repository **already uses it** and
it already works: `{"max-connections":0}` on the `limited` vhost, refusing every open
deterministically with no held connections and nothing to clean up. Phase 10.8B inherits a proven
mechanism for the vhost case and must establish the equivalent for `set_user_limits` and
`connection_max`.

### 8.2 The Phase 9.1C readiness lesson is real and already implemented

`Makefile:435-441` records it: *"`rabbitmq-diagnostics ping` answers before the broker will accept
`rabbitmqctl add_user`, so provisioning is retried until it takes and then **verified**. Phase 9.1C
found this the expensive way: every command here ended in `|| true`…"* The loop retries up to 45
times and **fails the gate** if the principal is absent.

**Note a live weakness Phase 10.8B must not inherit:** the `set_vhost_limits` call itself still
ends in `|| true` and is **not** verified, unlike `add_user`. It happens to work because it runs
after the verified user loop. Any new limit provisioning must be **verified**, not merely attempted.

---

## 9. Detail authority versus recommendation authority

These are separated deliberately, because the evidence supports them unequally.

**What `close_outcome` proves:** *which* connection-capacity ceiling the peer named when it refused
this attempt.

**What it does not prove:** what the operator should change. A node ceiling may be correctly
configured and legitimately saturated; a user ceiling may be the caller's own leak or a deliberate
quota; the condition may already have passed.

Frozen default:

| Field | Phase 10.8B authority |
|---|---|
| `Finding.Detail` | **MAY** become more specific, where directly supported by the closed `close_outcome` |
| `Finding.Recommendations` | **MUST remain byte-identical by default** |

A recommendation may change only if Phase 10.8B **separately proves** the specificity is justified
without operator intent, causal inference, global-state inference, configuration-quality opinion or
tuning advice. **The burden of proof is on changing them, and the preference is not to.**

This narrows ADR 0090 §6, which authorized *"a detail clause and a scoped recommendation"* in one
breath and gave the recommendation no separate justification.

---

## 10. The safe claim boundary

Frozen as a **semantic ceiling**, not as prose. Phase 10.8B derives exact wording from current
style and its own measurement.

**Allowed shape:** this attempted AMQP connection was refused, and the authoritative classified
outcome identified the **node** / **virtual-host** / **user** connection-limit **scope**.

**Forbidden, permanently:** globally exhausted · all slots used · server or broker overloaded ·
RabbitMQ unhealthy · misconfigured · limit too low · increase the limit · connection leak · root
cause · capacity exhausted everywhere.

`RESOURCE_LIMIT_REACHED` is **not weakened and not redefined**. The existing impermanence sentence
— *"a second run a moment later may succeed"* — is retained.

### 10.1 "Named" versus "reached", and the 53300 lesson

The code says `REACHED`; the evidence proves the peer **named a scope** while refusing **this**
attempt. Those are different strengths, and ADR 0088's authority boundary requires keeping them so.

PostgreSQL settled the identical question for `53300`: an authoritative rejection of *this*
attempted session is not proof of global capacity state, and
`test/integration/postgres/intelligence_test.go:117` pins the surviving wording — *"a connection
limit that applied to this attempted session"*. Phase 10.8B must reach an equivalently scoped
formulation. **`named` / `identified` / `reported` are safe; `exhausted` is not.**

One further asymmetry Phase 10.8B must respect: **absence is not evidence.** A truncated reply text
degrades to `UNSPECIFIED_TRUNCATED`, so a real ceiling can go unnamed. Presence of an outcome proves
the scope; absence proves nothing.

---

## 11. Canonical JSON compatibility contract

Replaces the blanket claim.

| Case | Canonical `Finding` | Canonical JSON |
|---|---|---|
| mapped capacity outcome | `Detail` **expected to change** | **bytes expected to change** |
| unmapped or non-capacity outcome | **byte-identical** | **byte-identical** |
| schema / field set / `SchemaVersion` / `RunSchemaVersion` | **unchanged globally** | **unchanged globally** |
| `FindingCode` / severity / confidence / `evidenceRefs` / subject / `vantageDependent` | **unchanged globally** | **unchanged globally** |
| `Recommendations` | **unchanged** unless separately admitted under §9 | same |
| exit status | **unchanged globally** | — |

Phase 10.8B must prove the byte-identity half by test, not by assertion: an unmapped outcome must
render today's finding exactly.

---

## 12. Convergence consequence

Phase 10.2A made `Summary` and `Detail` **merge preconditions** (ADR 0081 §2.2b). Varying `Detail`
by `close_outcome` therefore touches convergence, and Phase 10.8B must prove all four cases:

| Case | Required behaviour |
|---|---|
| same subject, same capacity outcome | merges, or stays two identical-prose findings — either is safe; the outcome must be stated |
| same subject, **different** capacity outcomes | **must not** collapse into prose naming one ceiling while citing both. Under §2.2b this becomes two findings, which is the safe direction |
| mapped capacity outcome + generic `RESOURCE_LIMIT_REACHED` | **must not** collapse into misleading specific prose |
| different subjects | remain distinct |

**Contributory structural fact, already true:** `internal/app/rabbitmq.go:281` —
`continueOneRabbitMQPath` "selects at most one path" — so a run holds at most one
`rabbitmq.connection_open` node and the multi-node cases are graphs no producer makes today. That
makes the risk low; it does **not** discharge the proof, because §2.2b is what keeps it safe if a
producer ever changes.

**No convergence architecture change is authorized**, in 10.8A.1 or in 10.8B. The `RuleID`-winner
prose that §2.2b withdrew stays withdrawn.

---

## 13. Evidence-membership consequence

Frozen: the explanation may use only `close_outcome` from evidence belonging to the finding being
built. **No graph-wide search. No first-match. No cross-endpoint. No cross-target.**

**Already satisfied by construction**, and Phase 10.8B need only not break it.
`internal/diagnosis/rabbitmq/connectionopen.go:110-127`:

```go
for _, node := range nodesAt(g, servicerabbitmq.StepConnectionOpen) {
	...
	in, ok := connectionOpenFinding(node)      // ← the same node
	...
	in.EvidenceRefs = []domain.EvidenceID{node.ID()}   // ← and its sole citation
```

`connectionOpenFinding` receives exactly the node whose identifier becomes the finding's only
evidence reference. This is the pattern `vhostNotFoundDetail(node)` already uses. **No graph
redesign is needed or permitted.**

Phase 9's multi-target isolation is unaffected: the enrichment lives inside a per-target canonical
report and derives nothing at `RunReport` level.

---

## 14. The revised Phase 10.8B contract

**Name:** RabbitMQ/LavinMQ capacity-scope **canonical explanation enrichment**.

**Purpose:** preserve the bounded specificity already present in the authoritative
`rabbitmq.close_outcome`, in the canonical finding that already exists.

**Layer:** existing canonical `Finding` construction — **not** renderer-only rewording, and **not**
new diagnosis.

| Expected to change | Expected unchanged |
|---|---|
| `Finding.Detail` for mapped capacity outcomes | schema, `SchemaVersion`, `RunSchemaVersion` |
| canonical JSON bytes for those reports | `FindingCode`, severity, confidence, kind, layer |
| human renderer output derived from those findings | `FailureClass` semantics, `EvidenceRefs`, subject |
| | exit status, acquisition, credentials, CLI, config, dependencies |
| | `Recommendations` — **unchanged by default** (§9) |

**Fixtures:** every capacity outcome that receives an explanation must be proven against a real
supported implementation. Per §8 the vhost ceiling already is, on RabbitMQ (three versions) and
LavinMQ; node and user remain. **An outcome that cannot be fixture-proven does not get an
explanation** — the claim is not weakened to fit the fixture.

**Compatibility:** outcome-driven, never product-name-driven (§7).
**Security:** fixed svcdoctor prose selected only by the closed svcdoctor-owned outcome; no
interpolation of any peer byte, username, vhost, hostname or version.
**Unknown / unmapped:** existing canonical finding byte-identical.

### 14.1 Revised stop conditions

Phase 10.8B must STOP if: arbitrary peer prose can reach canonical `Detail`; the closed vocabulary
is not structurally enforced; evidence membership cannot be established; safe enrichment requires a
new rule, code or confidence; `FailureClass` semantics must change; schema must change; unmapped
outcomes cannot remain byte-identical; recommendation specificity cannot be justified but the
implementation changes it anyway; convergence becomes semantically unsafe; a product-name branch is
required; the node or user fixture cannot be produced deterministically; or compatible-peer
behaviour cannot be proven.

> **Canonical JSON byte change for mapped outcomes is no longer a stop condition. It is expected.**

---

## 15. Security note — the tripwire that did not move

Nothing in this correction touches the safety argument, which Phase 10.8B verified independently
and which is stronger than 10.8A claimed.

`normalizeClose` (`wire/close.go:74-155`) returns only one of **seven** compile-time constants;
there is no construction of a `CloseOutcome` from peer bytes anywhere. Classification is
construct-and-compare byte equality, one bounded digit hole that **does not parse or return** the
integer, and exactly one prefix rule (T3) that only ever reaches a conclusion the bare template
already supports.

**This is already fuzz-proven.** `FuzzNormalizeClose` (`wire/fuzz_test.go:187-238`) fuzzes
`(code, text, vhost, username)` together — deliberately, because two of the three inputs are
svcdoctor's own — and asserts the result is one of the seven, that truncation short-circuits every
other rule, that a text above the protocol maximum is never classified, and that a non-530 code can
never reach a 530-only outcome. `FuzzParseClose` asserts the same at the frame boundary.

Phase 10.8B therefore inherits the §25 closed-value invariant rather than having to build it.

---

## 16. Requirement register — `CFE-001` … `CFE-014`

Tiers: **F** frozen · **N** binding on Phase 10.8B.

| ID | Tier | Requirement |
|---|---|---|
| CFE-001 | **F** | `Finding.Summary`, `Finding.Detail` and `Finding.Recommendations` are **canonical domain fields**, serialized by `Finding.MarshalJSON` and consumed verbatim by human renderers. Changing them changes canonical report semantics (§3) |
| CFE-002 | **F** | **Schema change and value change are distinct.** A more specific `Detail` is not schema evolution. `SchemaVersion` and the field set are unchanged; bytes may move (§4) |
| CFE-003 | **F** | The frozen term is **canonical explanation enrichment**. It creates no diagnosis and no new claim; it changes the explanation attached to an existing diagnosis. The candidate remains **C1-A** (§5) |
| CFE-004 | **F** | The phrase *"canonical JSON unchanged"* is retired for this line of work and replaced by the §11 table |
| CFE-005 | **F** | ADR 0067 §3.1 / `vhostNotFoundDetail` is the precedent, and it proves exactly the five points in §6.1 and no more |
| CFE-006 | **F** | Explanation is driven by the **authoritative closed outcome**, never by product identity. **No product-name branch.** A compatible implementation reaching the same outcome earns the same explanation; no outcome is broadened merely because implementations are compatible (§7) |
| CFE-007 | **F** | LavinMQ **does** produce `VHOST_CONNECTION_LIMIT`, measured by LMQ-06. ADR 0090's contrary statement is superseded (§7) |
| CFE-008 | **F** | `VHOST_CONNECTION_LIMIT` is already fixture-proven on real RabbitMQ (RAB-21, three versions) and real LavinMQ. The open gap is **`NODE_CONNECTION_LIMIT` and `USER_CONNECTION_LIMIT`** (§8) |
| CFE-009 | **N** | `Finding.Detail` **may** gain specificity supported by the closed outcome; `Finding.Recommendations` **must stay byte-identical by default**, and changing one requires its own proof under §9 |
| CFE-010 | **N** | The claim ceiling is §10: the peer **named a scope** while refusing **this attempt**. The forbidden list is permanent, `RESOURCE_LIMIT_REACHED` is not redefined, and **absence of an outcome proves nothing** |
| CFE-011 | **N** | Unmapped and non-capacity outcomes must render **byte-identical** canonical findings, proven by test (§11) |
| CFE-012 | **N** | All four convergence cases in §12 must be proven. No convergence architecture change; no return of `RuleID`-winner prose |
| CFE-013 | **N** | The outcome must come from the finding's **own cited evidence node** — already true by construction (§13). No graph-wide search, no first match, no cross-endpoint or cross-target read, no graph redesign |
| CFE-014 | **N** | Every outcome that receives an explanation must be proven against a **real supported implementation**, with **verified** provisioning rather than `\|\| true`. An unprovable outcome gets no explanation; the claim is never weakened to fit a fixture (§8, §8.2) |

---

## 17. Validation

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 8725755
git status --short                               # clean at start
make check                                       # exit 0 — before edits
make check                                       # exit 0 — after edits
git diff --check                                 # clean
git diff --name-only | grep -E '\.(go|mod|sum)$' # no output
```

**Not run, and no green claim is made:** every container integration suite — RabbitMQ, LavinMQ,
PostgreSQL, Kafka, Redpanda, Redis, Valkey, multi-target — every mutation harness, and every fuzz
target. **This phase is a documentation-only contract correction and changed no production, test,
fixture or harness behaviour**, so there is nothing for them to measure that the baseline run did
not already establish.

The integration facts cited in §7 and §8 are **read from committed test source and Makefile
targets**, not from a run performed here, and are labelled as such.

---

## 18. Outcome

**CANONICAL EXPLANATION ENRICHMENT AUTHORIZED.**

Phase 10.8A's audit stands: 70 recorded attributes, 38 unconsumed, one winner, six deferrals,
thirty-one rejections, and `rabbitmq.close_outcome` selected as C1-A. Nothing about the candidate,
its safety or its value changed.

What changed is the description of the layer it lives in. svcdoctor has no presentation layer for
finding prose — the prose *is* canonical — so the honest contract says the report changes for the
runs this is about, and stays byte-identical for every other. Phase 10.8B may reopen against that
contract.
