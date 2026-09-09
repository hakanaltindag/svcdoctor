# Phase 13.1A — Recommendation classification contract freeze

- **Phase:** 13.1A — recommendation semantics audit and contract freeze. **No production, test, CI,
  Makefile or dependency change.**
- **Baseline:** `d481779dd96a8995ebe03da2bc027e14c6537832`, `HEAD == origin/main`, clean tree,
  `make check` green before anything was written
- **Method:** **corpus first, taxonomy second.** All 73 production recommendations were inventoried
  and classified before the model was evaluated
- **Headline:** the existing model needs **no change**. Every one of the 73 is representable —
  **GROUP C (contract gap) is zero**. What the corpus exposes instead is **eight recommendations
  that instruct a change to the target while carrying no safety classification at all**, and five
  of those cross from *mechanism* into *policy*
- **Open blockers:** none

---

## 1. Baseline and re-measured state

```
HEAD        d481779dd96a8995ebe03da2bc027e14c6537832  docs(roadmap): audit diagnostic product direction
origin/main d481779dd96a8995ebe03da2bc027e14c6537832
tree        clean
make check  GREEN
```

Re-measured from source, not inherited from Phase 13.0:

| Fact | Value | How |
|---|---:|---|
| Total finding codes | **69** | `TestTheConvergenceInventoryIsComplete` inventory |
| Finding codes with ≥1 recommendation | **68** | REC inventory, §6 |
| Finding codes with zero recommendations | **1** | `DIAG_FAILURE_BOUNDARY` only |
| Codes carrying **classified** recommendations | **8** | §6.2 |
| Codes carrying **only unclassified** recommendations | **60** | §6.2 |
| Distinct recommendation constants (REC-*) | **73** | AST-equivalent extraction, cross-checked against `TestDIAG036…` which reports 73 |
| Structured (classified) constants | **9** | `diagnosis.Recommend` / `advise` |
| Legacy (unclassified) constants | **64** | `domain.NewRecommendation` |
| `Recommendations:` producer sites | **47** | §6.1 |
| Production rules | **24** | 1+3+5+6+4+3+2 |
| Failure classes | **42** | `internal/domain/failureclass.go` |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** | `internal/domain` |
| `RecommendationKind` members | **3** (`UNSPECIFIED`, `NEXT_EVIDENCE`, `REMEDIATION`) | `recommendationkind.go` |
| `SafetyClass` members | **8** (`UNSPECIFIED` + 7 frozen) | `recommendationkind.go` |
| `SelfCollectable` representation | `bool` on the value, `*bool` in JSON | `recommendation.go` |
| REMEDIATION producers | **0** | no production caller |
| NEXT_EVIDENCE producers | **9 constants / 8 codes** | §6.2 |
| Discriminator-bearing findings | **2**, both Kafka | unchanged |

### 1.1 One Phase 13.0 number is corrected

Phase 13.0 reported *"61 of 69 finding codes carry a recommendation with no kind…"*. The precise
split is **8 classified / 60 unclassified / 1 with no recommendation at all**, which sums to 69.
The 61 conflated *"not classified"* with *"carries an unclassified recommendation"*, and
`DIAG_FAILURE_BOUNDARY` belongs to neither group: it carries nothing to classify. The direction and
the argument of Phase 13.0 are unaffected; the number is corrected here and in `docs/BACKLOG.md`.

By constant rather than by code the figures are **73 total, 9 structured, 64 legacy**, and those
are the numbers 13.1B will work against, because a constant — not a code — is the unit of work.

## 2. The current recommendation model, verified from implementation

`domain.Recommendation` is an immutable five-field value with two constructors.

| Field | Type | Optional | Absence means | In canonical JSON | Affects bytes | Affects schema | Renderer | Convergence | Dedup key | Safety validation |
|---|---|---|---|---|---|---|---|---|---|---|
| `action` | `string` | no | invalid value | `action` | yes | no | printed after `→` | union member | **yes** | `ValidateActionText` on the classified path only |
| `kind` | `RecommendationKind` | yes | *nobody classified this* | `kind,omitempty` | when set | no | drives `[TAG]` | not reconciled | **yes** | `Valid()` + gate |
| `safety` | `SafetyClass` | yes | *nobody classified this* | `safety,omitempty` | when set | no | in `[TAG]` | not reconciled | **yes** | `Producible()`, `ChangesNothing()` |
| `rationale` | `string` | yes | unclassified, or not stated | `rationale,omitempty` | when set | no | **not rendered** | not reconciled | **yes** | non-blank required on classified path |
| `selfCollectable` | `bool` | yes | see below | `selfCollectable,omitempty` (`*bool`) | when set | no | in `[TAG]` for NEXT_EVIDENCE | not reconciled | **yes** | refused on REMEDIATION |

Five properties were verified rather than assumed:

1. **`Classified()` is `kind.Valid()`** — a single bit derived from `kind`. There is no separate
   flag, so "classified" and "has a kind" are the same statement.
2. **`selfCollectable` is already tri-state in the wire form.** The Go field is a `bool`, but
   `MarshalJSON` emits it as a pointer *only for `NEXT_EVIDENCE`*. A consumer therefore reads
   present-true, present-false and **absent**, and absent means *nobody said*. The bool does not
   collapse the three states; the encoding separates them.
3. **The deduplication key is the whole value, not the action.** `converge.go` keys `seen` on
   `domain.Recommendation` — five comparable fields — precisely so that two identically-worded
   recommendations with different classifications coexist rather than one silently winning. This is
   the Phase 10.2A lesson applied in advance, and it is what makes §11's migration-neutrality
   argument work.
4. **`rationale` is redacted.** `internal/security/redaction/redact.go` passes it through the same
   `t.text()` transformation as `action`, and rebuilds classified and unclassified recommendations
   down separate branches. Classification survives the shareable projection.
5. **`rationale` is not rendered anywhere.** The terminal `adviceTag` prints kind, safety and
   collectability; the rationale reaches canonical JSON and no human surface.

### 2.1 The two construction paths

```
domain.NewRecommendation(action)                 → action only, four fields zero
diagnosis.Recommend(AdviceInput{…}, kind, conf)  → NewAdvice → AdmitAdvice → Advice.Recommendation()
```

**`diagnosis.Recommend` swallows every error and returns `nil`.** A misclassification therefore does
not fail the build or the run — it silently deletes the recommendation from the report. That is the
single largest migration hazard in this phase and §12 answers it with a guard rather than with care.

## 3. ADR 0082, as actually implemented

| Question | Answer, from source |
|---|---|
| Kinds allowed | `NEXT_EVIDENCE`, `REMEDIATION` |
| Kinds **reachable** | `NEXT_EVIDENCE` only — **`REMEDIATION` has zero production producers** |
| Safety levels allowed | 7: `OBSERVE`, `VERIFY`, `COMPARE`, `CONFIG_CHANGE`, `RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` |
| Safety levels **producible** | 4 — `Producible()` returns false for `RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` **and** for `UNSPECIFIED` |
| Safety levels **reachable today** | 3 — `OBSERVE`, `VERIFY`, `COMPARE`. `CONFIG_CHANGE` is producible and unused |
| Invalid combinations | `NEXT_EVIDENCE` + a class that changes something; `REMEDIATION` + `SelfCollectable`; any non-producible class; blank rationale; an action that reads as a command |
| Where validation runs | **Two places.** `NewAdvice` (diagnosis) and `NewClassifiedRecommendation` (domain, the report boundary). Phase 10.4B moved the refusals down so they bind every construction path |
| Confidence gate | `AdmitAdvice`: `REMEDIATION` requires **CONFIRMED and HIGH**. It needs a finding, so it stays in `internal/diagnosis` |
| **Can legacy prose bypass all of it?** | **Yes, completely.** `NewRecommendation` reaches none of these checks — not `Producible()`, not `ChangesNothing()`, not `ValidateActionText`, not the confidence gate |

The last row is the architectural finding of this phase, and §7 measures what got through.

**Why the three are unreachable, from the record:** `RESTART` — "svcdoctor does not tell anyone to
restart anything"; `DISRUPTIVE` — interrupting service or risking data; `SECURITY_WEAKENING` — "the
sharpest of the three: svcdoctor must never recommend disabling the verification it exists to
perform." They exist in the vocabulary so the prohibition is *nameable and testable* rather than
merely absent.

**One partial mitigation exists and is worth recording**, because it changes what "bypass" means:
`TestDIAG036EveryProducedRecommendationIsAlreadySafe` runs `ValidateActionText` over every
`recommend*` constant in the tree and passes — **73 of 73**. So the *command-injection* half of
ADR 0082 rule 3 is already enforced across the whole corpus. What is unenforced is everything about
*what the action does*.

## 4. Corpus construction

The unit of analysis is the **distinct semantic recommendation**, which in this repository is
exactly the `recommend<Name>` constant: every rule builds recommendations from a package constant
rather than from a literal at the call site, and the existing `TestDIAG036…` guard relies on the
same property.

Three counts are different and must not be mixed:

| Count | Value | What it is |
|---|---:|---|
| **Producer sites** | **47** | `Recommendations:` assignments in finding literals. Fewer than the constants because table-driven rules (`transport/build.go`, `kafka/protocol.go`, `postgres/tls.go`) have **one** site serving many codes |
| **Distinct semantic recommendations (REC-*)** | **73** | one per constant; the migration unit |
| **Finding codes with ≥1 recommendation** | **68** | fewer than 73 because five codes carry two or three recommendations |

Codes carrying more than one recommendation: `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` (**three** —
DNS/TCP/TLS, selected by which layers failed, so this producer emits 1–3 depending on the branch),
`KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` (two), `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`
(two, selected by failure class), `POSTGRES_ADMISSION_SCOPE` (two, one conditional on completeness),
`KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` (one, conditional — **absent** when the set is complete).

Every constant maps to exactly one finding code and one construction path; the extraction reports
**zero unmapped constants and zero map entries without a constant**.

## 5. Semantic families found in the corpus

Derived from the text, not imposed. Sixteen descriptive labels collapsed to twelve families:

| Family | n | Meaning |
|---|---:|---|
| `CHECK_CONFIGURATION` | 20 | read a configuration svcdoctor cannot see |
| `OBSERVE_SERVER` | 16 | read the endpoint's own log or current state |
| `CHECK_CERTIFICATE` | 7 | compare certificate material against what was verified |
| `RE-RUN_SVCDOCTOR` | 6 | change how svcdoctor is invoked and run again |
| `CHECK_CREDENTIAL` | 5 | verify the credential this run used |
| `CHECK_AUTHORIZATION` | 5 | read an authorization rule |
| `CHECK_NETWORK_PATH` | 2 | read routing, firewall or security-group policy |
| `INCREASE_SVCDOCTOR_BUDGET` | 2 | re-run with a larger execution budget |
| `USE_VENDOR_TOOL` | 1 | verify with a client that implements what svcdoctor does not |
| `VERIFY_OPERATOR_INTENT` | 1 | compare what was observed against what was intended |
| `MODIFY_*` (config / authorization / security policy) | 5 | **change the target** |
| mixed `MODIFY_* | RE-RUN_*` | 3 | the prose offers both and does not disambiguate |

**No `RESTART_COMPONENT` and no `CONTACT_OWNER` appear anywhere.** The candidate labels the brief
offered for those two found nothing, which is a result rather than an omission.

**No diagnostic experiment exists** (§16 of the brief). The nearest shapes — *"re-run with a larger
execution budget"* (REC-024, REC-028) — change nothing on the target, alter no credential authority
and weaken nothing; they are ordinary next evidence that happens to be self-collectable. Nothing in
the corpus asks the operator to change something temporarily in order to discriminate.

## 6. Corpus measurements

### 6.1 Action mode, evidence intent, collectability, risk

| Dimension | Distribution |
|---|---|
| **Action mode** | OBSERVE **65** · MUTATE **5** · AMBIGUOUS **3** |
| **Evidence intent** | YES **65** · CONDITIONAL **6** · NO **2** |
| **Self-collectable** | TRUE **2** · FALSE **69** · NOT_APPLICABLE **2** |
| **Operational risk** | READ_ONLY **57** · LOCAL_ONLY **8** · AMBIGUOUS **3** · SECURITY_POSTURE_CHANGE **2** · ACCESS_MUTATING **2** · TARGET_MUTATING **1** |
| **Recommendation authority** | DIRECT **64** · OPERATOR_INTENT_REQUIRED **6** · BOUNDED_MECHANISM **3** |
| **Content quality** | SAFE_AS_WRITTEN **64** · ACTION_SCOPE_AMBIGUOUS **3** · POLICY_OVERCLAIM **3** · SECURITY_CONTEXT_MISSING **2** · TARGET_SCOPE_AMBIGUOUS **1** |
| **Proposed kind** | NEXT_EVIDENCE **68** · REMEDIATION **5** *(as written — see §8 for the decision)* |
| **Proposed safety** | OBSERVE **35** · VERIFY **19** · COMPARE **14** · CONFIG_CHANGE **5** *(as written)* |
| **Migration group** | **M 64** · **S 9** · **C 0** · **R 0** |

**`SelfCollectable: TRUE` is 2, and both are the same sentence in two services** — *"Re-run with a
larger execution budget"* (`KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`, `POSTGRES_ADMISSION_SCOPE`).
The two `NOT_APPLICABLE` are the two pure mutations, where the field is meaningless by construction.
**No discriminating observation in the entire corpus is one svcdoctor could take.** This is the
measurement §14 turns into the planner trigger, and it is now derived from all 73 rather than from
the 9 that happened to be classified.

**GROUP C is zero.** Every recommendation in the tree is representable by the existing
`RecommendationKind` × `SafetyClass` model. That is the corpus answering the taxonomy question, and
§7 records the decisions that follow.

### 6.2 Per service

| Service | Codes w/ rec | REC | legacy | structured | OBSERVE | MUTATE | AMBIG | self=TRUE | high-risk | policy-overclaim | security-sensitive | GROUP M | GROUP S |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| transport | 8 | 8 | 8 | 0 | 8 | 0 | 0 | 0 | 0 | 0 | 0 | 8 | 0 |
| kafka | 15 | 18 | 16 | 2 | 17 | 0 | 1 | 1 | 1 | 0 | 1 | 16 | 2 |
| postgres | 21 | 23 | 20 | 3 | 20 | 1 | 2 | 1 | 3 | 1 | 1 | 20 | 3 |
| redis | 9 | 9 | 9 | 0 | 7 | 2 | 0 | 0 | 2 | 1 | 1 | 7 | 2 |
| rabbitmq | 11 | 11 | 11 | 0 | 9 | 2 | 0 | 0 | 2 | 1 | 1 | 9 | 2 |
| kubernetes | 4 | 4 | 0 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| **total** | **68** | **73** | **64** | **9** | **65** | **5** | **3** | **2** | **8** | **3** | **4** | **64** | **9** |

`high-risk` is 8 while `GROUP S` is 9: **REC-021** needs prose review without carrying operational
risk (§9). `structured` counts constants already classified in production; `codes w/ rec` is per
service and sums to 68.

**Redis and RabbitMQ are disproportionately risky.** Between them they hold **4 of the 5** pure
mutations, **2 of the 3** policy overclaims and **2 of the 4** security-sensitive items, on
**20 of 73** recommendations. Neither service runs in any CI lane (Phase 13.0 §4), which is the
compounding factor and the reason §13 sequences them last.

**Transport and Kubernetes are clean**: 12 recommendations, all OBSERVE, all READ_ONLY, all DIRECT,
zero semantic review. Kubernetes is clean because it was written after the vocabulary existed;
transport is clean because its advice never leaves *"read the evidence and compare it with the
configuration"*.

## 7. The taxonomy decisions

Taken **after** the corpus, and each is a decision the corpus forced rather than a preference.

### 7.1 Kind — **KEEP UNCHANGED**

`UNSPECIFIED` · `NEXT_EVIDENCE` · `REMEDIATION`.

GROUP C = 0 is the whole argument: no recommendation in the tree needs a kind that does not exist.

The brief's two candidates are refused with the corpus as the reason:

- **`OPERATOR_CHECK`** — proposed for the 41 *"Check…"* / *"Review…"* items. Refused: every one of
  them is an observation whose purpose is to reduce diagnostic uncertainty, which is exactly what
  `NEXT_EVIDENCE` means. Splitting them would encode *who performs the observation*, and
  `SelfCollectable` already carries that on an orthogonal axis. A kind that duplicates a field is
  taxonomy decoration.
- **`DIAGNOSTIC_EXPERIMENT`** — refused for want of a member. The corpus contains no recommendation
  that changes something temporarily to discriminate (§5). Adding the kind now would be designing
  for a case that does not exist, and §19 of the brief requires two real producers.

`CONFIGURATION_CHANGE`, `ACCESS_CHANGE` and `SECURITY_CHANGE` are refused as kinds: they describe
**what the action costs**, which is `SafetyClass`'s axis. Promoting them to kinds would make the
model a Cartesian product of two things that are already orthogonal.

### 7.2 Safety — **KEEP UNCHANGED**

All seven, with `Producible()` unchanged: `OBSERVE`, `VERIFY`, `COMPARE`, `CONFIG_CHANGE` producible;
`RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` permanently unreachable.

**What Safety encodes is frozen explicitly, because the brief is right that the candidates differ:**
it is **blast radius** — how much of the world a reader changes by taking the advice — ordered from
"reads something that already exists" to "reduces a security property". It is **not** reversibility,
**not** likelihood of success, and **not** security impact as a separate axis; security impact is
the top of the same ordering rather than a second dimension.

No member is activated by this freeze. After 13.1B/13.1C the reachable set is **OBSERVE, VERIFY,
COMPARE** — the three read-only classes — and `CONFIG_CHANGE` stays producible-but-unused, because
§8 rewrites the five recommendations that would have used it.

### 7.3 SelfCollectable — **KEEP THE BOOL, RESTRICTED TO `NEXT_EVIDENCE`**

The audit asked whether the bool collapses meaningful states. **It does not**, because the encoding
separates them:

| Wire form | Meaning |
|---|---|
| `"selfCollectable": true` | svcdoctor could take this observation in a differently configured run |
| `"selfCollectable": false` | svcdoctor **cannot** take it under its current architecture, credentials and authority |
| field absent | nobody said — the recommendation is unclassified, or it is a remediation |

Frozen semantics, unchanged: `true` means *capable today under current authority*, never *could be
programmed to*. The constructor's refusal of `SelfCollectable` on a `REMEDIATION` stays. It
**authorizes nothing** — diagnosis performs no I/O, and no code path reads the field as an
instruction.

After migration the field is present on all 68 next-evidence-bearing codes, and **66 of the 69
recommendations that carry it will say `false`**. That is the honest answer and it is the useful
one: it tells a runbook that svcdoctor has handed over.

### 7.4 Rationale — **REQUIRED on every classified recommendation, canonical-only**

Already enforced: `NewAdvice` refuses a blank rationale. Frozen additions:

- It explains **why this observation discriminates**, or why the change follows from the evidence.
- It is **svcdoctor-owned bounded prose**. No peer bytes, no runtime error text, no server message
  may reach it — the same rule the report model applies everywhere (ADR 0010).
- It is **not machine-readable and must not become so**. Nothing may branch on its content.
- It stays **canonical-only**: no renderer prints it today and 13.1B adds none.

**The cost is named rather than hidden: 13.1B must write 64 rationales**, one per legacy constant.
That is the real work of the migration, and it is judgement rather than plumbing.

### 7.5 Recommendation identity — **NONE. Defer.**

Option A of §23. Evaluated against the three questions the brief asks:

- *Can tooling distinguish two recommendations without comparing prose?* After migration, yes —
  `kind` + `safety` + `selfCollectable` discriminate for every routing decision a runbook makes.
- *Can deduplication rely on content?* It already does, and on the **whole value** (§2, property 3).
  An identity field would be a second key for the same job.
- *Can planner logic reference recommendations?* The planner is deferred and §14 keeps it deferred.

No current consumer needs one. A `RecommendationCode` would add a registry, a compatibility surface
and a naming burden to serve a use case that does not exist. **Reopen when a consumer names itself.**

### 7.6 Next-evidence identity — **NONE. Defer, and refuse for a stronger reason.**

A structured *observation* identity — "retry with larger budget", "inspect listener configuration"
as machine values — is the data model a planner selects over. Adding it here would put a planner's
input into the domain while ADR 0092 keeps the planner deferred, and §24 of the brief forbids
exactly that. **Refused for this phase and every phase until the planner itself is reopened.**

## 8. The eight high-risk recommendations, and the policy decision

### 8.1 Finding authority is not recommendation authority

All five pure mutations sit on **CONFIRMED / HIGH** findings — verified individually — so
`AdmitAdvice` would admit them as `REMEDIATION`/`CONFIG_CHANGE` and none would silently vanish. The
gate would pass.

**And they should still not be remediations.** Each proves a *condition* and then recommends a
*policy*, and the evidence that authorizes the first does not authorize the second:

> svcdoctor proved the broker refused this user's access to this virtual host.
> It did **not** prove the refusal was wrong.

Granting the permission may be exactly the wrong action. The same reasoning applies to enabling a
SASL mechanism, enabling TLS on an endpoint, and reconfiguring an authentication method — and one
of them, REC-034, inverts the product: it asks the *target* to change so that *svcdoctor* can
authenticate.

This is ADR 0096 §2.2 Q3 applied to advice rather than to claims: the recommendation must stop where
the observation stops.

### 8.2 Decision — REMEDIATION stays unreachable; the five are rewritten

**Frozen:** `RecommendationKindRemediation` gains **no producer** in 13.1B or 13.1C. The five
mutation recommendations are **rewritten as observations or verifications** and then classified.

Every one of them already contains a safe alternative in its own text, except REC-052 and REC-067
where the mutating clause is the whole sentence. Those two need a new sentence, and it is available
without inventing anything: both findings already prove a *state*, and the honest advice is to
verify whether that state is intended.

**This is a recommendation behaviour change and is enumerated as one (§16), not hidden under
"metadata migration."** Six recommendation strings change; no finding code, severity, confidence,
evidence reference or exit code moves.

### 8.3 The complete high-risk table

Every recommendation classified MUTATE, AMBIGUOUS, ACCESS_MUTATING, SECURITY_POSTURE_CHANGE,
POLICY_OVERCLAIM or SECURITY_CONTEXT_MISSING. No sampling.

| REC | Service | FindingCode | Current action | Risk | Finding authority | Recommendation authority | Future handling |
|---|---|---|---|---|---|---|---|
| **REC-012** | kafka | `KAFKA_CREDENTIAL_WITHHELD` | *"Establish verified TLS to this endpoint, or review the trust context this run used, then re-run"* | AMBIGUOUS — *"establish verified TLS"* may mean configure the broker (mutation) or supply trust material to svcdoctor (local) | CONFIRMED/HIGH — the policy withheld the credential | BOUNDED_MECHANISM | **REWRITE_AND_CLASSIFY** — disambiguate to the local action, as RabbitMQ's REC-062 already does |
| **REC-021** | kafka | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | *"Check whether the advertised hostname resolves from this vantage point, and what the broker publishes in advertised.listeners"* | TARGET_SCOPE_AMBIGUOUS — its first clause asks the operator to redo a measurement svcdoctor already took and recorded | CONFIRMED or HYPOTHESIS | DIRECT | **REWRITE_AND_CLASSIFY** — keep the clause svcdoctor cannot answer, drop the one it already did |
| **REC-031** | postgres | `POSTGRES_CREDENTIAL_WITHHELD` | *"Establish a verified TLS channel to this endpoint before presenting a credential, or re-run with the transport policy this run is meant to use"* | AMBIGUOUS — same shape as REC-012 | CONFIRMED/HIGH | BOUNDED_MECHANISM | **REWRITE_AND_CLASSIFY** |
| **REC-034** | postgres | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | *"Diagnose this endpoint with a client that performs the authentication method it demands, **or configure a mechanism svcdoctor performs for the role this run used**"* | TARGET_MUTATING + POLICY_OVERCLAIM — asks the server to change its authentication configuration **to suit the diagnostic tool** | CONFIRMED/HIGH, severity WARN or INFO | OPERATOR_INTENT_REQUIRED | **REWRITE_AND_CLASSIFY** — drop the second clause; the first is already correct and sufficient |
| **REC-036** | postgres | `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | *"Re-run against a role whose password is printable ASCII, or diagnose this endpoint with a client that implements the full mechanism"* | AMBIGUOUS — read as selecting another role it is local; read as changing a password it is a mutation, and the two differ in **kind** | CONFIRMED/HIGH | BOUNDED_MECHANISM | **REWRITE_AND_CLASSIFY** — state role *selection* explicitly |
| **REC-052** | redis | `REDIS_CREDENTIAL_WITHHELD` | *"Enable TLS for this endpoint and supply the trust material that verifies it, then run again"* | SECURITY_POSTURE_CHANGE — *"Enable TLS for this endpoint"* is unambiguously a server configuration change | CONFIRMED/HIGH | OPERATOR_INTENT_REQUIRED | **REWRITE_AND_CLASSIFY** — the mutating clause is the whole sentence and needs replacing, not trimming |
| **REC-055** | redis | `REDIS_COMMAND_NOT_PERMITTED` | *"Grant the diagnostic identity permission to run PING, or diagnose with an identity that already has it"* | ACCESS_MUTATING + POLICY_OVERCLAIM — the ACL may be doing exactly what its author wrote | CONFIRMED/HIGH/WARN | OPERATOR_INTENT_REQUIRED | **REWRITE_AND_CLASSIFY** — the second clause survives; the first becomes a verification of intent |
| **REC-064** | rabbitmq | `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | *"Enable SASL PLAIN on this endpoint, or diagnose it with a client that implements the mechanisms it offers"* | SECURITY_POSTURE_CHANGE + SECURITY_CONTEXT_MISSING — PLAIN on a listener without TLS exposes the credential, and the sentence carries no TLS condition | CONFIRMED/HIGH/ERROR | OPERATOR_INTENT_REQUIRED | **REWRITE_AND_CLASSIFY** — drop the first clause; ADR 0068 already forbids svcdoctor sending PLAIN without verified TLS, so recommending the server enable it is advice svcdoctor's own policy would then refuse to use |
| **REC-067** | rabbitmq | `RABBITMQ_VHOST_ACCESS_REFUSED` | *"Grant this user permissions on the virtual host, for example with `rabbitmqctl set_permissions`"* | ACCESS_MUTATING + POLICY_OVERCLAIM, and it **names an administrative command** | CONFIRMED/HIGH/ERROR | OPERATOR_INTENT_REQUIRED | **REWRITE_AND_CLASSIFY** — the strongest case in the table |

**REC-067 additionally passes `ValidateActionText` only by accident**: `rabbitmqctl set_permissions`
carries no single-hyphen flag and no shell metacharacter, so the command-shaped-advice rule does not
fire on it. ADR 0082 rule 3 says *"state what to look at, not what to type"*, and this types.

**Nine recommendations reach GROUP S**: the eight above plus REC-021, which is listed in the table
because it needs prose review, and is not counted in the high-risk total of 8 because it carries no
operational risk.

## 9. Zero-recommendation findings, and the failure boundary

**Exactly one finding code carries no recommendation: `DIAG_FAILURE_BOUNDARY`.**

**Decision: KEEP NONE.** Not because absence is tidy, but because the corpus shows the useful action
is already present:

- The boundary finding is **derived**. It says *"the first stage measured for this subject failed"*
  and localizes where observation stopped. In every normal shape the failing stage's **own** finding
  is in the same report, on the same subject, carrying the actionable recommendation. Adding one here
  would duplicate REC-003 (or REC-001, REC-021, …) under a second code.
- It is **INFO**, and adding advice to an informational locator invites a reader to act on the
  locator rather than on the claim.
- Its subject is a stage, not a condition, so any generic sentence would be *"look at the stage that
  failed"* — which the finding already says.

**One shape contradicts this and is named rather than absorbed.** A Kubernetes `401` produces
**`DIAG_FAILURE_BOUNDARY` alone**: the `k8s.api_access` node is FAIL with
`AUTH_CREDENTIALS_REJECTED`, ADR 0094 §10.4 gives it no Kubernetes code, and the run exits 0. That
report contains one INFO finding and **no recommendation at all**.

That is a real gap, and **it is not this contract's to close**: the missing thing is a Kubernetes
credential-rejection finding, already tracked in `docs/BACKLOG.md` and requiring ADR 0094 §7. Adding
a generic boundary recommendation would paper over a missing service code with a sentence that is
wrong in the other 68 shapes.

**Frozen: zero-recommendation findings remain ALLOWED.** The success metric is *every recommendation
that exists has explicit semantics, and every absence is defensible* — never 69/69.

## 10. Convergence and deduplication

**The migration is convergence-neutral, and the reason is structural rather than incidental.**

`converge.go` keys the recommendation union on the **whole `domain.Recommendation` value**. Three
cases:

| Case | Today | After migration |
|---|---|---|
| Two merging findings carry the same action, both unclassified | identical values → dedup to one | identical values → dedup to one |
| Two merging findings carry the same action with **different** classification | cannot occur | **both are kept**, deliberately (the Phase 10.2A rule: a merged field never holds a value nobody stated) |
| Two merging findings carry different actions | both kept, ordered by content | unchanged |

The middle row is the only way classification could change a merged report, and it is reachable only
if **one constant receives two classifications**. So the migration rule that makes convergence
provably neutral is stated as a rule rather than left to care:

> **One constant, one classification.** A `recommend<Name>` constant is classified exactly once, at
> its definition or at a single shared construction site. No branch may classify the same constant
> two ways.

Under that rule every merge group sees the same value it sees today plus four fields that are
identical across the group, so dedup collapses the same members and the union order — which is
content-derived — is unchanged.

**Merge-key membership is unaffected.** `mergeable` keys on layer, summary, detail and discriminator.
Recommendations are not in the key today and gain no influence over it.

## 11. Schema, renderers and compatibility

### 11.1 Schema — **`SchemaVersion` KEEPS 1, `RunSchemaVersion` KEEPS 1**

The four fields already exist in `recommendationJSON` with `omitempty`, shipped in Phase 10.4B and
released. Populating them is **field population, not schema evolution** — the additive-at-v1 contract
of `docs/REPORT_SCHEMA.md` §1 and ADR 0083 §2.1. A consumer reading `action` alone is unaffected.

**Canonical JSON bytes for a real run DO change**: `kind`, `safety`, `rationale` and
`selfCollectable` appear on 68 codes' recommendations where today they are absent. That is the
intended outcome and the distinction §39 asks for: *same schema, different optional field
population*.

### 11.2 Committed goldens — **measured, and the answer is surprising**

**Every committed golden is synthetic.** The terminal goldens build findings by hand
(`domain.NewRecommendation("Check the thing the finding names")` in `kafkagolden_test.go`), and the
`test/golden` JSON fixtures carry hand-written recommendations such as *"Check that the service is
listening on this port"* that appear in no production rule.

**So no committed golden changes as a consequence of classifying production constants.** 13.1B may
still choose to extend the synthetic fixtures to cover the new shapes; that is an addition, not a
forced update.

### 11.3 Renderers — **renderer-visible, and that is the point**

`internal/render/terminal/findings.go` prints `[KIND / SAFETY / who collects]` for a classified
recommendation and nothing for an unclassified one. Classification therefore adds a tag to 64
recommendations in real terminal output.

Byte-identical human output was evaluated and **refused**: preserving it would mean suppressing the
tag, which would delete a shipped feature that already works for the 9 classified recommendations
and is exercised by `next-evidence-classified.txt`. Phase 13.0 §16 measured the operator value —
*"svcdoctor can collect" versus "you must collect"* — as the reason the classification is worth
doing at all.

**No renderer file is modified.** `adviceTag` already handles every value; the change is in what it
receives. Only Markdown and HTML would need new code, and neither exists.

### 11.4 Backward compatibility statement

| Class | Applies | Detail |
|---|---|---|
| NO PUBLIC CHANGE | schema, exit codes, finding codes, severities, confidences, evidence refs, ordering | none moves |
| **ADDITIVE CANONICAL METADATA** | **yes** | four optional fields become populated on 68 codes' recommendations |
| **HUMAN-OUTPUT CHANGE** | **yes** | terminal gains a classification tag on 64 recommendations |
| SCHEMA CHANGE | no | `SchemaVersion` and `RunSchemaVersion` stay 1 |
| **BEHAVIOR CHANGE** | **yes, bounded and enumerated** | six recommendation strings are rewritten (§8.2); nothing else |

A consumer parsing `action` is unaffected. A consumer diffing whole reports across the upgrade sees
new fields and new terminal tags, and that is documented in the release notes rather than avoided.

## 12. Enforcement — the safety gate closure

**The architectural question:** after migration, can any recommendation instruct a target mutation
while bypassing structured safety classification?

**The answer must be NO, and the current model cannot enforce it**, because `NewRecommendation` is a
valid exported constructor with no gate. Enforcement is therefore structural and external.

### 12.1 Legacy producer path — **KEEP the API, forbid production callers**

`domain.NewRecommendation` is **not removed**. `internal/security/redaction/redact.go` uses it to
rebuild an unclassified recommendation, and deleting the branch would make redaction fail closed on
a value the type still admits — trading a live path for a panic-adjacent one. It stays, and after
migration it has **zero production callers outside redaction**.

Its doc comment currently says *"It is not deprecated and is not a legacy path."* **This freeze
reverses that**, which is why §17 creates an ADR: a production rule may no longer decline to
classify its own advice.

### 12.2 The guard set, derived rather than accepted

The brief offered twelve candidates. Eight are admitted, four are refused with reasons.

| ID | Guard | Verdict |
|---|---|---|
| **R-G01** | every production recommendation in `internal/diagnosis/**` is built through `diagnosis.Recommend` | **ADMIT** — the primary gate |
| **R-G02** | `domain.NewRecommendation` has no caller in `internal/diagnosis/**`; the redaction call site is named explicitly | **ADMIT** — the anti-regression half |
| **R-G03** | every `NEXT_EVIDENCE` recommendation reaching a report has an explicit `selfCollectable` | **ADMIT** — free, since `MarshalJSON` already emits it for that kind |
| **R-G04** | no recommendation classified `OBSERVE`/`VERIFY`/`COMPARE` contains a mutating imperative | **ADMIT, as a closed word list** — `enable`, `grant`, `revoke`, `disable`, `increase`, `set`, `restart`, `delete`, `create`, `configure` as the **first word**. The Kubernetes fuzz precedent (Phase 12.1C pinned eighteen imperatives by name) is the pattern |
| **R-G05** | `RESTART`, `DISRUPTIVE`, `SECURITY_WEAKENING` remain unreachable | **ADMIT** — `Producible()` already refuses them; the guard states it as a property |
| **R-G06** | `REMEDIATION` has zero production producers | **ADMIT** — this freeze's §8.2 decision, made testable |
| **R-G07** | recommendation content non-empty | **REFUSE as new** — `validateIdentifier` and `ValidateActionText` already enforce it at both constructors |
| **R-G08** | no raw runtime error becomes recommendation content | **ADMIT, extended to rationale** — the corpus is 73 package constants and must stay so; a guard that every action and rationale is a constant, never a formatted value, is the durable form |
| **R-G09** | recommendation ordering deterministic | **REFUSE as new** — `converge.go`'s content-derived sort and `TestTheInventory…` already pin it |
| **R-G10** | convergence does not discard conflicting metadata | **ADMIT** — the whole-value dedup key makes it true today; a guard keeps it true |
| **R-G11** | no safety downgrade through deduplication | **REFUSE as separate** — subsumed by R-G10; two different classifications coexist rather than one winning |
| **R-G12** | zero-recommendation findings remain allowed | **ADMIT as a non-vacuity anchor** — `DIAG_FAILURE_BOUNDARY` is the one member and the guard fails if the list empties or grows silently |

Every admitted guard needs a companion proving it can fail, per repository convention.

**Static/AST guards are appropriate and already precedented**: `TestDIAG036…` parses the tree for
`recommend*` constants, and `test/security` holds several AST walkers. R-G01, R-G02 and R-G08 are
AST guards of exactly that kind.

## 13. Migration phasing — **OPTION 2: safe corpus, then high-risk corpus**

| Phase | Scope | Size |
|---|---|---:|
| **13.1B** | GROUP M — classify the **55** legacy constants whose prose is safe and correct as written, with rationales. No prose changes. Land R-G03, R-G05, R-G10, R-G12 | 55 |
| **13.1C** | GROUP S — rewrite and classify the **9**, each with its own review. Land R-G01, R-G02, R-G04, R-G06, R-G08 once the last legacy producer is gone | 9 |

64 GROUP M constants minus the **9 already classified** leaves **55** requiring work.

**Why not one phase.** The 9 include six prose rewrites that are recommendation *behaviour* changes
touching authorization and TLS advice. Mixing them with 55 mechanical classifications would put a
security review inside a 64-file diff, which is precisely the trade §33 warns against. Splitting
also lets R-G01 — *"no production recommendation is unclassified"* — land at the moment it becomes
true, rather than being written twice.

**Why not service-by-service.** The mechanical/semantic split is orthogonal to service and cuts the
security-relevant work into one reviewable phase; service-by-service would scatter the eight
high-risk items across five phases.

**Why not model-first.** There is no model change to do first.

## 14. Planner reassessment trigger

**The planner stays deferred**, and this phase sharpens the trigger with a measurement Phase 11.0
could not take: across **all 73** recommendations, `SelfCollectable: TRUE` is **2**, and both are
*"re-run with a larger execution budget."*

**Frozen minimum trigger — all three, simultaneously:**

1. Every production recommendation is classified (13.1C complete, R-G01 green), **and**
2. at least one `NEXT_EVIDENCE` recommendation is `SelfCollectable: true` **and is not a
   budget-or-re-run variant**, **and**
3. it sits on a finding carrying a `Discriminator` — that is, a finding that still has an open
   question for the observation to close.

Condition 2 is the one that fails today, and it fails at 0. Nothing weaker is a planner: selecting
between observations svcdoctor cannot take is advice, and advice is what the recommendation already
is.

## 15. Mutation properties for 13.1B/13.1C

Designed, not run. Properties rather than a count.

| # | Mutation | Protected invariant | Likely site | Detecting guard |
|---|---|---|---|---|
| P1 | remove `Kind` from one classified call | every production recommendation is classified | a rule's `AdviceInput` | R-G01 |
| P2 | change `NEXT_EVIDENCE` → `REMEDIATION` | REMEDIATION unreachable | any rule | R-G06 |
| P3 | downgrade `VERIFY` → `OBSERVE` on a mutating sentence | safety describes blast radius | a rewritten GROUP S item | R-G04 |
| P4 | flip `SelfCollectable` false → true | collectability is capability, not aspiration | any next evidence | a pinned inventory of the `true` set |
| P5 | replace `diagnosis.Recommend` with `domain.NewRecommendation` | no legacy production path | any rule | R-G01 + R-G02 |
| P6 | reintroduce a raw string literal at a call site | corpus stays constants | any rule | R-G08 |
| P7 | classify one constant two ways on two branches | convergence neutrality | a branching rule | R-G10 + the one-constant-one-classification guard |
| P8 | make `SafetySecurityWeakening` producible | the three stay unreachable | `Producible()` | R-G05 |
| P9 | blank a rationale | advice must say why | any rule | `NewAdvice` (already) + a corpus guard |
| P10 | build a rationale by `fmt.Sprintf` from a node attribute | no peer bytes in advice | any rule | R-G08 |
| P11 | drop `DIAG_FAILURE_BOUNDARY` from the zero-recommendation list while it still has none | absence stays defensible | the list | R-G12 |
| P12 | let dedup key on `action` alone | no merged field nobody stated | `converge.go` | R-G10 |

**No production mutation was run in this phase**, per §46.

## 16. What 13.1B and 13.1C may and may not change

**MAY:**

| Path | Why |
|---|---|
| `internal/diagnosis/*/` rule files | the 73 construction sites and their constants |
| `internal/diagnosis/kafka/nextevidencedebt_test.go` | **deletion**, and the repository asks for it: the test fails by design the moment `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` is classified |
| `test/diagnosis/nextevidenceinvariant_test.go` | remove the `hypothesesWithoutStructuredNextEvidence` entry; the list is shrink-only and pinned by size |
| new guard tests in `test/security/` and `internal/diagnosis/` | R-G01…R-G12 with non-vacuity proofs |
| `docs/validation/PHASE131B_*.md`, `PHASE131C_*.md` | the records |
| `docs/FINDINGS.md`, `docs/OUTPUT.md`, `docs/REPORT_SCHEMA.md` | only if a documented example shows a recommendation |
| synthetic goldens | **optional addition**, never a forced update (§11.2) |

**MUST NOT:** probes, adapters, transport, acquisition, protocol semantics, finding codes, rules,
severities, confidences, failure classes, the evidence graph, the Kubernetes client, fleet
configuration, CLI flags, dependencies, CI, `Makefile`, `SchemaVersion`, `RunSchemaVersion`,
renderer source.

**The domain model is untouched.** Kind, Safety, SelfCollectable and Rationale all keep their current
types and semantics; `NewRecommendation` keeps its signature.

### 16.1 The invariant that keeps this from becoming diagnosis expansion

Frozen: recommendation classification creates **no** evidence, **no** finding code, and changes
**no** confidence, severity, failure boundary, evidence reference, ordering or exit behaviour.

**The one exception is stated rather than hidden:** §8.2's six rewritten recommendation strings are a
recommendation behaviour change. They are enumerated in the high-risk table, they belong to 13.1C,
and they are reviewed as prose changes rather than as metadata.

## 17. Success metrics

Not *"69/69 findings have recommendations"*. Frozen instead:

1. **73 of 73** recommendation constants classified.
2. **0** unclassified recommendation producers in `internal/diagnosis/**`.
3. **100%** of `NEXT_EVIDENCE` recommendations carry an explicit `selfCollectable`.
4. **0** recommendations instructing a target mutation without a safety class.
5. **0** policy overclaims remaining without explicit handling — all 3 resolved in 13.1C.
6. `SchemaVersion` 1, `RunSchemaVersion` 1, finding codes **69**, rules **24**, failure classes
   **42**, severities/confidences/evidence refs/exit codes **unchanged**.
7. **0** renderer source files changed.
8. Recommendation behaviour changes **enumerated**, and equal to the six of §8.2.

## 18. Validation performed

| | Result |
|---|---|
| `make check` | **GREEN** (before and after) |
| `git diff --check` | **CLEAN** |
| `TestDIAG036EveryProducedRecommendationIsAlreadySafe` | **PASS** — 73 distinct strings, all already text-safe |
| `TestNBE021EveryHypothesisDiscriminatorHasStructuredNextEvidence` | **PASS** |
| `TestTheConvergenceInventoryIsComplete` | **PASS** — 24 rules, 69 codes |
| Documentation, ADR and report-schema guards | **PASS** |
| `go test ./test/security/...`, `./internal/diagnosis/...`, `./internal/domain/...` | **PASS** |

**Omitted, and why:** real clusters, mutation suites, fuzz and `-race`. No Go file, workflow, fixture
or Makefile target changed, so each would re-measure code that did not move. §15's mutation
properties are **designed** here and run in 13.1B/13.1C.

## 19. Frozen contract

**RECOMMENDATION KIND CONTRACT** — *unchanged*
`UNSPECIFIED` (absence of classification; forbidden in production after 13.1C) ·
`NEXT_EVIDENCE` (an observation that would discriminate between the explanations that remain) ·
`REMEDIATION` (a change to make; requires CONFIRMED + HIGH; **no producer, and none authorized**).

**RECOMMENDATION SAFETY CONTRACT** — *unchanged*. Safety encodes **blast radius**, not
reversibility and not a separate security axis.
Producible: `OBSERVE` (read what exists) · `VERIFY` (check a claim, change nothing) ·
`COMPARE` (contrast two observations) · `CONFIG_CHANGE` (change configuration; producible and
**unused**).
Unreachable, permanently until an ADR says otherwise: `RESTART` · `DISRUPTIVE` ·
`SECURITY_WEAKENING`.

**SELFCOLLECTABLE CONTRACT** — keep the bool, meaningful only on `NEXT_EVIDENCE`.
`true` = svcdoctor could take this observation under its **current** architecture, credentials and
authority. `false` = it cannot. Absent = nobody said. It authorizes nothing and instructs nothing.
Future capability is never `true`.

**RATIONALE CONTRACT** — required on every classified recommendation. svcdoctor-owned bounded prose,
never peer bytes and never a formatted runtime value. Explains why the observation discriminates.
**Canonical-only**; no renderer prints it and none may start without a separate decision. Never
machine-readable; nothing may branch on it.

**RECOMMENDATION IDENTITY** — **NONE.** Deferred; reopen when a consumer names itself.

**NEXT-EVIDENCE IDENTITY** — **NONE.** Refused for this phase and until the planner is reopened; it
is a planner input and would put one in the domain model.

**LEGACY PRODUCER POLICY** — `domain.NewRecommendation` is **kept** (redaction needs it) and becomes
**forbidden in `internal/diagnosis/**`**, enforced by R-G01 and R-G02. Its doc comment's claim that
it *"is not a legacy path"* is reversed by ADR 0097.

**TARGET-MUTATION POLICY** — a recommendation that instructs a change to the target must carry a
producible non-read-only safety class. Since `REMEDIATION` has no producer, the operative rule is:
**no production recommendation instructs a change to the target.** The eight that do today are
rewritten in 13.1C.

**REMEDIATION POLICY** — **remains unreachable.** Not because the five candidates fail the
confidence gate — all sit on CONFIRMED/HIGH and would pass — but because proving a condition does
not authorize a policy. Activating it needs its own ADR and its own security review.

**SECURITY-WEAKENING POLICY** — `SECURITY_WEAKENING` stays unproducible. Two current recommendations
carry security-posture change without the class (REC-052, REC-064); both are rewritten rather than
classified, because classifying them would require making the class producible.

**DISRUPTIVE-ACTION POLICY** — `RESTART` and `DISRUPTIVE` stay unproducible. **The corpus contains no
candidate for either**, which is the strongest evidence available that the prohibition costs nothing.

## 20. Stop conditions

Every §47 stop condition was evaluated; **none fires**.

| Condition | Status |
|---|---|
| Corpus cannot be enumerated | Does not fire — 73 enumerated, 0 unmapped |
| A producer cannot be mapped to a code or bounded source | Does not fire — all 73 map 1:1 |
| Kind / Safety / SelfCollectable semantics ambiguous | Does not fire — §7 |
| High-risk mutations cannot be represented or deferred | Does not fire — all 8 have named handling |
| Corpus requires a boundary change conflicting with ADR 0096 | Does not fire — §8 *applies* ADR 0096 rather than straining it |
| Migration needs new evidence or new authority | Does not fire — none |
| Classification would silently alter convergence | Does not fire — §10, and the rule that makes it provable |
| Unresolved schema decision | Does not fire — §11.1 |
| Mutating and next-evidence recommendations cannot be separated | Does not fire — 8 identified individually |
| Migration cannot prevent legacy prose returning | Does not fire — R-G01/R-G02 |

## Appendix A — the complete REC-* inventory

73 rows. `State` is the current construction path; `Grp` is the migration group; `Kind` and `Safety`
are the **proposed** classification (for GROUP S, the classification the rewritten prose should
carry).

| REC | Svc | File | Constant | FindingCode | State | Mode | Evid | Self | Risk | Auth | Grp | Kind | Safety | Action text |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| REC-001 | transport | `dns.go` | `recommendNameNotResolved` | `DNS_NAME_NOT_RESOLVED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check that the hostname is spelled as intended and that it has an address record visible to the resolver this host is configured to use |
| REC-002 | transport | `dns.go` | `recommendResolutionFailed` | `DNS_RESOLUTION_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check that the resolver this host is configured to use is reachable and answering from this network position |
| REC-003 | transport | `tcp.go` | `recommendConnectionNotEstablished` | `TCP_CONNECTION_NOT_ESTABLISHED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check that the endpoint accepts connections on this port from this network position, and read the per-address outcomes recorded on the referenced evidence |
| REC-004 | transport | `tls.go` | `recommendCertificateNotValidNow` | `TLS_CERTIFICATE_NOT_VALID_NOW` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the certificate's validity window on the referenced evidence with the clock of the host this run used |
| REC-005 | transport | `tls.go` | `recommendChainNotTrusted` | `TLS_CHAIN_NOT_TRUSTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Check the trust material this run was given — the system store or the supplied CA file — against the chain recorded on the referenced evidence |
| REC-006 | transport | `tls.go` | `recommendEndpointDoesNotSpeakTLS` | `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check what is listening on this endpoint and whether this run was meant to negotiate TLS with it |
| REC-007 | transport | `tls.go` | `recommendHandshakeNotCompleted` | `TLS_HANDSHAKE_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Read the handshake outcome recorded on the referenced evidence, and compare it with what this endpoint is configured to accept |
| REC-008 | transport | `tls.go` | `recommendIdentityMismatch` | `TLS_IDENTITY_MISMATCH` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the names on the presented certificate with the identity this run verified, which is recorded on the referenced evidence |
| REC-009 | kafka | `protocol.go` | `recommendAPIVersionsNotCompleted` | `KAFKA_API_VERSIONS_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check what is listening on this address and port, and whether anything on the path terminates or rewrites the connection |
| REC-010 | kafka | `protocol.go` | `recommendAuthenticationNotCompleted` | `KAFKA_AUTHENTICATION_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker log for this connection around the time recorded on the evidence node |
| REC-011 | kafka | `protocol.go` | `recommendCredentialNotConfigured` | `KAFKA_CREDENTIAL_NOT_CONFIGURED` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Supply a credential for this endpoint and the mechanism the listener offers, then re-run |
| REC-012 | kafka | `protocol.go` | `recommendCredentialWithheld` | `KAFKA_CREDENTIAL_WITHHELD` | legacy | AMBIGUOUS | CONDITIONAL | FALSE | AMBIGUOUS | BOUNDED_MECHANISM | **S** | NEXT_EVIDENCE | OBSERVE | Establish verified TLS to this endpoint, or review the trust context this run used, then re-run |
| REC-013 | kafka | `protocol.go` | `recommendCredentialsRejected` | `KAFKA_CREDENTIALS_REJECTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check the principal and secret this run was configured with, and the broker's authentication backend for this listener |
| REC-014 | kafka | `protocol.go` | `recommendHandshakeNotCompleted` | `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker log for this connection, and whether the listener expects SASL at all |
| REC-015 | kafka | `protocol.go` | `recommendMechanismNotOffered` | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Check sasl.enabled.mechanisms on the listener serving this address and port, and which mechanism this run was configured to use |
| REC-016 | kafka | `protocol.go` | `recommendMetadataNotCompleted` | `KAFKA_METADATA_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker log for this connection, and whether the authenticated principal may describe the cluster |
| REC-017 | kafka | `protocol.go` | `recommendPeerVerificationFailed` | `KAFKA_PEER_VERIFICATION_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify the credential configured for this endpoint, and establish what this broker is before presenting the credential again |
| REC-018 | kafka | `protocol.go` | `recommendUnsupportedBySvcdoctor` | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check whether the listener offers a mechanism svcdoctor supports, or verify this endpoint with a Kafka client that implements the negotiated one |
| REC-019 | kafka | `protocol.go` | `recommendUnsupportedExchange` | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the referenced evidence for which limit applied; if the endpoint is behaving correctly this is a gap in svcdoctor rather than something to change on the cluster |
| REC-020 | kafka | `protocol.go` | `recommendVersionRejected` | `KAFKA_API_VERSIONS_VERSION_REJECTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Check the broker version against the ApiVersions request version recorded on the evidence node |
| REC-021 | kafka | `recommendation.go` | `recommendDNS` | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **S** | NEXT_EVIDENCE | VERIFY | Check whether the advertised hostname resolves from this vantage point, and what the broker publishes in advertised.listeners |
| REC-022 | kafka | `recommendation.go` | `recommendTCP` | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check routing, firewall rules and security group policy between this vantage point and the advertised address and port |
| REC-023 | kafka | `recommendation.go` | `recommendTLS` | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check whether the broker certificate names the advertised host, and whether its issuer is trusted at this vantage point |
| REC-024 | kafka | `topology.go` | `recommendUnmeasured` | `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` | CLASSIFIED | OBSERVE | YES | TRUE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Re-run with a larger execution budget so the advertised endpoints that were not measured are attempted |
| REC-025 | kafka | `topology.go` | `recommendUnsuitable` | `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | OPERATOR_INTENT_REQUIRED | **M** | NEXT_EVIDENCE | COMPARE | Compare the addresses this cluster advertised with the addresses a client on this network is expected to use to reach its brokers |
| REC-026 | kafka | `unusableadvertisement.go` | `recommendUnusable` | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check how this broker's advertised host and port are configured, and whether anything rewrites Kafka Metadata responses between the broker and this client |
| REC-027 | postgres | `admission.go` | `recommendAdmissionContrast` | `POSTGRES_ADMISSION_SCOPE` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare this endpoint's host-based access rules for the addresses that refused the connection with the rules for the addresses that accepted it, for the role this run used |
| REC-028 | postgres | `admission.go` | `recommendAdmissionUnmeasured` | `POSTGRES_ADMISSION_SCOPE` | CLASSIFIED | OBSERVE | YES | TRUE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Re-run with a larger execution budget so the addresses that reached no admission decision are attempted |
| REC-029 | postgres | `authentication.go` | `recommendAuthenticationFailed` | `POSTGRES_AUTHENTICATION_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review this endpoint's authentication log for the role this run used |
| REC-030 | postgres | `authentication.go` | `recommendCredentialNotConfigured` | `POSTGRES_CREDENTIAL_NOT_CONFIGURED` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Supply a credential for this endpoint and the role this run used, or check whether this endpoint was expected to accept the connection without one |
| REC-031 | postgres | `authentication.go` | `recommendCredentialWithheld` | `POSTGRES_CREDENTIAL_WITHHELD` | legacy | AMBIGUOUS | CONDITIONAL | FALSE | AMBIGUOUS | BOUNDED_MECHANISM | **S** | NEXT_EVIDENCE | OBSERVE | Establish a verified TLS channel to this endpoint before presenting a credential, or re-run with the transport policy this run is meant to use |
| REC-032 | postgres | `authentication.go` | `recommendCredentialsRejected` | `POSTGRES_CREDENTIALS_REJECTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify the credential configured for this endpoint and the role it is meant to authenticate as; the endpoint's own log is the only place a wrong secret and an unknown role are distinguished |
| REC-033 | postgres | `authentication.go` | `recommendMechanismNotOffered` | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check which authentication mechanisms this endpoint offers for the role this run used and from the address this run connected from |
| REC-034 | postgres | `authentication.go` | `recommendMechanismUnsupported` | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | legacy | MUTATE | CONDITIONAL | FALSE | TARGET_MUTATING | OPERATOR_INTENT_REQUIRED | **S** | REMEDIATION | CONFIG_CHANGE | Diagnose this endpoint with a client that performs the authentication method it demands, or configure a mechanism svcdoctor performs for the role this run used |
| REC-035 | postgres | `authentication.go` | `recommendPeerVerificationFailed` | `POSTGRES_PEER_VERIFICATION_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify the credential configured for this endpoint, and establish what this endpoint is before presenting the credential again |
| REC-036 | postgres | `authentication.go` | `recommendUnsupportedBySvcdoctor` | `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | legacy | AMBIGUOUS | CONDITIONAL | FALSE | AMBIGUOUS | BOUNDED_MECHANISM | **S** | NEXT_EVIDENCE | OBSERVE | Re-run against a role whose password is printable ASCII, or diagnose this endpoint with a client that implements the full mechanism |
| REC-037 | postgres | `session.go` | `recommendConnectionLimitReached` | `POSTGRES_CONNECTION_LIMIT_REACHED` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Identify the connection limits applicable to this attempted session and compare their current usage with their configured limits |
| REC-038 | postgres | `session.go` | `recommendDatabaseConnectDenied` | `POSTGRES_DATABASE_CONNECT_DENIED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Review the CONNECT privilege on the requested database for the role this run used |
| REC-039 | postgres | `session.go` | `recommendDatabaseNotFound` | `POSTGRES_DATABASE_NOT_FOUND` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify that the database name this run requested exists and is available at this endpoint |
| REC-040 | postgres | `session.go` | `recommendSessionEstablishmentFailed` | `POSTGRES_SESSION_ESTABLISHMENT_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review this endpoint's log for the session it accepted and then closed |
| REC-041 | postgres | `shared.go` | `recommendNotPermitted` | `POSTGRES_CONNECTION_NOT_PERMITTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review this endpoint's host-based access rules for the role this run used and for the address this run connected from |
| REC-042 | postgres | `sslrequest.go` | `recommendSSLNegotiationFailed` | `POSTGRES_SSL_NEGOTIATION_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check that this endpoint is the PostgreSQL service this run was meant to reach, and read the referenced evidence for what the exchange observed |
| REC-043 | postgres | `sslrequest.go` | `recommendTLSDeclined` | `POSTGRES_TLS_DECLINED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check whether this PostgreSQL endpoint is configured to accept encrypted connections, and whether anything between this vantage point and it answers the SSLRequest on its behalf |
| REC-044 | postgres | `startup.go` | `recommendStartupFailed` | `POSTGRES_STARTUP_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review this endpoint's connection-level logs for the role and database this run requested |
| REC-045 | postgres | `tls.go` | `recommendTLSCertificateNotValidNow` | `POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the certificate validity window recorded on the referenced evidence with this host's clock |
| REC-046 | postgres | `tls.go` | `recommendTLSChainNotTrusted` | `POSTGRES_TLS_CHAIN_NOT_TRUSTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Check the trust material this run was given against the chain recorded on the referenced evidence |
| REC-047 | postgres | `tls.go` | `recommendTLSHandshakeFailed` | `POSTGRES_TLS_HANDSHAKE_FAILED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Read the referenced evidence for what the handshake recorded, and check whether the protocol versions this run offered are acceptable to this endpoint |
| REC-048 | postgres | `tls.go` | `recommendTLSIdentityMismatch` | `POSTGRES_TLS_IDENTITY_MISMATCH` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the certificate names recorded on the referenced evidence with the server identity this run was asked to verify |
| REC-049 | postgres | `tls.go` | `recommendTLSUpgradeNotHonored` | `POSTGRES_TLS_UPGRADE_NOT_HONORED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check what terminates connections at this endpoint after PostgreSQL SSL negotiation, and whether it is the component expected to serve TLS |
| REC-050 | redis | `authentication.go` | `recommendAuthenticationNotCompleted` | `REDIS_AUTHENTICATION_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review the endpoint's connection-level logs for this vantage's address around the time of this run |
| REC-051 | redis | `authentication.go` | `recommendCredentialNotConfigured` | `REDIS_CREDENTIAL_NOT_CONFIGURED` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Supply the credential your application uses for this endpoint and run again |
| REC-052 | redis | `authentication.go` | `recommendCredentialWithheld` | `REDIS_CREDENTIAL_WITHHELD` | legacy | MUTATE | NO | NOT_APPLICABLE | SECURITY_POSTURE_CHANGE | OPERATOR_INTENT_REQUIRED | **S** | REMEDIATION | CONFIG_CHANGE | Enable TLS for this endpoint and supply the trust material that verifies it, then run again |
| REC-053 | redis | `authentication.go` | `recommendCredentialsRejected` | `REDIS_CREDENTIALS_REJECTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check the username and secret this run used against the endpoint's ACL configuration, and check the endpoint's ACL log for the attempt |
| REC-054 | redis | `hello.go` | `recommendProtocolNotEstablished` | `REDIS_PROTOCOL_NOT_ESTABLISHED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check whether this port serves the Redis protocol, and review the endpoint's connection-level logs for this vantage's address |
| REC-055 | redis | `ping.go` | `recommendCommandNotPermitted` | `REDIS_COMMAND_NOT_PERMITTED` | legacy | MUTATE | CONDITIONAL | FALSE | ACCESS_MUTATING | OPERATOR_INTENT_REQUIRED | **S** | REMEDIATION | CONFIG_CHANGE | Grant the diagnostic identity permission to run PING, or diagnose with an identity that already has it |
| REC-056 | redis | `ping.go` | `recommendEndpointNotServing` | `REDIS_ENDPOINT_NOT_SERVING` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check this endpoint's own logs and current state for the condition it named, and run again once it is serving |
| REC-057 | redis | `ping.go` | `recommendPingNotCompleted` | `REDIS_PING_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Review this endpoint's connection-level logs for this vantage's address around the time of this run |
| REC-058 | redis | `sentinel.go` | `recommendSentinel` | `REDIS_ENDPOINT_IS_SENTINEL` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Point svcdoctor at the Redis or Valkey data endpoint this Sentinel monitors, or at the address your application connects to |
| REC-059 | rabbitmq | `authentication.go` | `recommendAuthNotCompleted` | `RABBITMQ_AUTHENTICATION_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker's log for this connection, and confirm no proxy between svcdoctor and the broker is terminating the connection |
| REC-060 | rabbitmq | `authentication.go` | `recommendAuthUnsupported` | `RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the endpoint's configured frame size limit against the AMQP 0-9-1 minimum of 4096 bytes |
| REC-061 | rabbitmq | `authentication.go` | `recommendCredentialNotConfigured` | `RABBITMQ_CREDENTIAL_NOT_CONFIGURED` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Supply --username together with --password-file or --password-stdin to diagnose authentication and virtual host access |
| REC-062 | rabbitmq | `authentication.go` | `recommendCredentialWithheld` | `RABBITMQ_CREDENTIAL_WITHHELD` | legacy | OBSERVE | YES | FALSE | LOCAL_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Use --tls require with a trusted certificate chain, or supply --tls-ca-file so the endpoint's identity can be verified |
| REC-063 | rabbitmq | `authentication.go` | `recommendCredentialsRejected` | `RABBITMQ_CREDENTIALS_REJECTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Check the broker's own log for the refusal reason, and confirm the username and password against the endpoint you are diagnosing |
| REC-064 | rabbitmq | `authentication.go` | `recommendMechanismNotOffered` | `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | legacy | MUTATE | CONDITIONAL | FALSE | SECURITY_POSTURE_CHANGE | OPERATOR_INTENT_REQUIRED | **S** | REMEDIATION | CONFIG_CHANGE | Enable SASL PLAIN on this endpoint, or diagnose it with a client that implements the mechanisms it offers |
| REC-065 | rabbitmq | `connectionopen.go` | `recommendConnectionNotEstablished` | `RABBITMQ_CONNECTION_NOT_ESTABLISHED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker's log for this connection, and confirm no proxy between svcdoctor and the broker is terminating it |
| REC-066 | rabbitmq | `connectionopen.go` | `recommendConnectionNotPermitted` | `RABBITMQ_CONNECTION_NOT_PERMITTED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | OBSERVE | Check the broker's own log for this connection attempt, and review any node, virtual host or user connection limits |
| REC-067 | rabbitmq | `connectionopen.go` | `recommendVHostAccessRefused` | `RABBITMQ_VHOST_ACCESS_REFUSED` | legacy | MUTATE | NO | NOT_APPLICABLE | ACCESS_MUTATING | OPERATOR_INTENT_REQUIRED | **S** | REMEDIATION | CONFIG_CHANGE | Grant this user permissions on the virtual host, for example with rabbitmqctl set_permissions |
| REC-068 | rabbitmq | `connectionopen.go` | `recommendVHostNotFound` | `RABBITMQ_VHOST_NOT_FOUND` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Confirm the virtual host name, including its exact case and any leading slash, against the broker's own list |
| REC-069 | rabbitmq | `protocol.go` | `recommendStartNotCompleted` | `RABBITMQ_CONNECTION_START_NOT_COMPLETED` | legacy | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Confirm the port carries AMQP 0-9-1 rather than the management HTTP API, a TLS listener addressed as plaintext, or another protocol |
| REC-070 | kubernetes | `acquisition.go` | `recommendAPIAccessDenied` | `KUBERNETES_API_ACCESS_DENIED` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify whether the identity this run used is authorized to perform this read in this namespace |
| REC-071 | kubernetes | `acquisition.go` | `recommendServiceNotFound` | `KUBERNETES_SERVICE_NOT_FOUND` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | VERIFY | Verify the namespace and Service name this run declared against the cluster it was pointed at |
| REC-072 | kubernetes | `backends.go` | `recommendNoReadyEndpoint` | `KUBERNETES_SERVICE_NO_READY_ENDPOINT` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare the readiness the backing Pods report with the endpoints published for this Service |
| REC-073 | kubernetes | `backends.go` | `recommendSelectsNoPods` | `KUBERNETES_SERVICE_SELECTS_NO_PODS` | CLASSIFIED | OBSERVE | YES | FALSE | READ_ONLY | DIRECT | **M** | NEXT_EVIDENCE | COMPARE | Compare this Service's selector with the labels on the Pods intended to back it |
