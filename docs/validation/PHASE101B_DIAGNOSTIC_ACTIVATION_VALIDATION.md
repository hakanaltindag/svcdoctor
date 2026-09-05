# Phase 10.1B — Diagnostic intelligence activation

**Status:** implemented. **Reports change, and this is the phase that is allowed
to change them.**

Phase 10.1A landed the reasoning machinery with byte-identical output. Phase
10.1B is the second half of the split `docs/design/DIAGNOSTIC_INTELLIGENCE.md`
section P recommends: it activates that machinery in production, so the diff here
is the behavioural change and nothing else.

Three things became live: **convergence**, the **failure boundary**, and the
**confidence ladder** for anything new. Nothing else did — no service
intelligence, no generic hypothesis, no new recommendation.

---

## 1. Baseline audit

Phase 10.1A's 96-file diff was classified before anything was built on it.

| Class | Files |
|---|---|
| TEST | 55 |
| PRODUCTION_FOUNDATION | 35 |
| DOCUMENTATION | 3 |
| MUTATION_HARNESS | 1 |
| CONFIG/GUARD | 1 |
| GENERATED/GOLDEN (one fuzz seed) | 1 |
| **UNEXPECTED** | **0** |

`internal/domain`, `render`, `probe`, `adapter`, `security`, `fleet`, `cli` and
`cmd/` were verified at **0 changed files each**. The 18 rule files' entire diff
is 18× `g := ctx.Graph`, 18× one import, 18× a blank line and 18 signature lines
— zero rule-body changes, checked by content rather than accepted on claim. The
four composition roots changed only rule-set construction, `Diagnose` →
`Evaluate`, and `incomplete || outcome.Failed()`.

The foundation was trustworthy. Phase 10.1A was then pushed to `origin/main`
under explicit authorization, as a fast-forward from `fb91c0b`.

## 2. The three Phase 10.1A deviations, resolved

| # | Deviation | Classification | Resolution |
|---|---|---|---|
| 1 | duplicate `RuleID` rejected at `RuleSet.Freeze`, not `NewEngine` | `BENIGN_IMPLEMENTATION_DETAIL` | ADR 0080 §2.4 requires rejection at construction returning an error. Both hold, strictly earlier, at the call that names the mistake. No change. |
| 2 | `time.Now` banned by an AST guard, not `forbidigo` | `BENIGN_IMPLEMENTATION_DETAIL` | The prohibition is implemented and more precisely scoped than the suggested mechanism. No change. |
| 3 | `Layer` taken from the tie-break winner | **`ADR_CLARIFICATION_REQUIRED`** | Fixed. See §3. |

## 3. The Layer defect, and the merge-compatibility contract

### 3.1 It was reachable, not theoretical

`POSTGRES_CONNECTION_NOT_PERMITTED` is produced by **two rules about one
endpoint at two layers**, deliberately: `postgres/startup` anchors it at L4 and
`postgres/authentication` at L5. `internal/diagnosis/postgres/shared.go` says so
in as many words — *"the claim's layer is the anchor's own and the two anchors
sit at different ones"*.

Under Phase 10.1A's rule, merging them produced:

```text
layer=L5  refs=[auth-node startup-node]
```

A refusal observed at the protocol stage, published as an authentication-stage
claim, because `postgres/a…` sorts before `postgres/s…`. Measured, not argued.

### 3.2 The resolution

Semantic identity stays `(Code, Subject)`. What changes is that **identity is a
candidacy test rather than a licence**: two findings may converge only when every
field a consumer parses already agrees. Recorded as ADR 0081 §2.2a — a
clarification filling §2.2's silence, not a rewrite of §2.1's identity.

### 3.3 The merge-compatibility matrix

Every canonical `Finding` field, with its frozen convergence rule.

| Field | Classification | Rule | Can rule order reach it? |
|---|---|---|---|
| `Code` | `MUST_EQUAL` | identity; the grouping key | no |
| `Subject` | `MUST_EQUAL` | identity; the grouping key | no |
| `Layer` | `MUST_EQUAL` | **precondition**: differing layers stay two findings | no |
| `Discriminator` | `MUST_EQUAL` | **precondition**: at most one distinct non-empty value; an unset one joins a set one; cleared when the merge is `CONFIRMED` | no |
| `EvidenceRefs` | `DETERMINISTIC_UNION` | union, deduplicated, sorted | no |
| `Confidence` | `ADMISSION_RECONCILIATION` | the maximum; never accumulation; `HIGH` only if an input independently qualified | no |
| `Severity` | `OTHER_WITH_EXPLICIT_RULE` | the maximum (ordinal, commutative) | no |
| `Kind` | `OTHER_WITH_EXPLICIT_RULE` | `CONFIRMED` absorbs `HYPOTHESIS` (a two-element lattice join) | no |
| `VantageDependent` | `BOOLEAN_JOIN` | logical OR | no |
| `Recommendations` | `SEMANTIC_DEDUP_UNION` | union by action text; winner's order first | ordering only, and by `RuleID` rather than registration order |
| `Summary` | `OTHER_WITH_EXPLICIT_RULE` | the winner's — ADR 0081 §2.2, explicitly | yes, and deliberately |
| `Detail` | `OTHER_WITH_EXPLICIT_RULE` | the winner's — ADR 0081 §2.2, explicitly | yes, and deliberately |

**No field a consumer parses is chosen by a tie-break.** `Summary` and `Detail`
are the two exceptions and they are safe *because* of the preconditions above:
once `Code`, `Subject` and `Layer` all match, the two routes state one claim at
one layer, and which wording survives changes nothing machine-readable. Prose is
explicitly not identity (ADR 0081 §4) and explicitly free to be reworded
(`docs/FINDINGS.md` §3.1 rule 13).

### 3.4 The latent-defect audit

The other fields were checked for the same defect by scanning every construction
site of every finding code.

| Field | Varies across sites? | Verdict |
|---|---|---|
| `Layer` | **yes**, for one code | the defect; now a precondition |
| `Severity` | no | reconciled by maximum; order-independent anyway |
| `Kind` | no | absorption; order-independent anyway |
| `Confidence` | no | the ladder; order-independent anyway |
| `Discriminator` | no | made a precondition regardless, so it stays that way |
| `VantageDependent` | **yes**, for three codes | correct: OR is exactly what a varying vantage flag needs |

Recommendation *metadata* — kind and safety class — is not in the matrix because
it is not on `domain.Recommendation` yet. ADR 0082 §2.1 puts it there additively;
Phase 10.1B emits no new recommendation, so the move stays a later phase's.

## 4. What was activated, and what was not

| Concept | Activated? |
|---|---|
| convergence by semantic identity | **yes** |
| the failure boundary as `DIAG_FAILURE_BOUNDARY` | **yes** |
| the confidence ladder for new results | **yes** |
| generic hypotheses | **no** |
| next-evidence and remediation | **no** |
| service intelligence | **no** — Phase 10.2 onward |

**No generic hypothesis was manufactured**, and the prompt's §12 blesses it: a
correct empty result is superior to an impressive false diagnosis. Generic
evidence — a state, a layer, a class — does not justify a causal claim without
service knowledge, and inventing one to demonstrate the engine is the failure
mode the whole phase is defending against.

Because no hypothesis is emitted, **no next-evidence recommendation has a
production instance**. The distinction is nonetheless fixed before it is needed
(§5), and the guardrails are tested.

### 4.1 Convergence activation changed no existing output

Wiring `Converge` into `Engine.Evaluate` moved no golden byte. No production rule
set currently produces two findings sharing `(Code, Subject, Layer)`, so
activation is a no-op on today's outputs — the safest possible activation, and
the reason the boundary's diff is the whole behavioural change.

## 5. `discriminator` versus `NEXT_EVIDENCE`

Fixed before either is used, because two concepts with unclear ownership is how
they drift.

| | `Finding.Discriminator` | `NEXT_EVIDENCE` recommendation |
|---|---|---|
| what it is | the **observation** that would settle the hypothesis | the **structured, safety-classified** form of that thought |
| shape | one line of human prose, one per finding | an object: action, rationale, safety class, self-collectability |
| example | *whether the address is routable from this network* | *compare the advertised address with one routable from this client network* — `COMPARE`, not self-collectable |
| who reads it | a person | a person, and a consumer that wants the class |

The rule: **the discriminator names the question; the recommendation carries the
structure of going and answering it.** They must not disagree, and ADR 0082 §2.5
requires a hypothesis carrying one to carry the other once both are live. Neither
is emitted in Phase 10.1B.

## 6. The failure boundary

**Representation.** ADR 0079 §2.1's four candidates were re-weighed against the
implementation before activation, and the ADR's choice held:

| Candidate | Verdict |
|---|---|
| a field on `domain.Report` | rejected — the report assembles and validates rather than concludes (ADR 0015) |
| a `Graph` query a renderer calls | rejected — whoever calls it decides what it means, and the obvious caller is a renderer |
| a new domain type | rejected — it would carry exactly what a finding carries |
| **a generic rule producing a finding** | **selected** — canonical JSON, cited evidence, validated membership, existing redaction, existing renderers, existing convergence |

No conceptual contradiction was found, so no ADR amendment was proposed.

**Claim semantics.** For one subject, the deepest stage that positively succeeded
and the shallowest that positively failed. It is `CONFIRMED` at `INFO`, filed at
the failing stage's layer, `vantageDependent` when that layer is DNS, TCP or TLS,
and it carries no discriminator and no recommendation. It never means "everything
after this point is broken" and never means "this layer caused it".

**Traceability.** It cites both halves; where there is no confirmed-good half it
cites one node and says so in the detail rather than promoting an earlier success
into a contrast that did not happen.

**Branches.** One per subject. The multipath golden shows it scoped to the single
failing address while the passing one gets none.

**Incomplete runs.** It emits the same finding either way, because the claim
contains no statement about completeness. Proven by comparing the two reports'
findings byte for byte.

**Terminal.**

```text
  · INFO  DIAG_FAILURE_BOUNDARY  10.0.0.2:<port>
    Observation of this subject last succeeded at the tcp stage and first failed at the protocol stage
    This states where observation stopped succeeding and nothing about why. …
    evidence: 2
```

**Shareable.** The subject is the pseudonym (`ip-001:<port>`), through the
existing redaction contract. No second redaction system was introduced.

## 7. What the validation found

**The existing wording guard caught the boundary's prose on the day it was
written.** The detail said a stage that did not run is "neither healthy nor
broken"; `internal/cli`'s guard bans "healthy" outright, negated or not, because
`SummaryStatus` already refuses that claim four levels down. Reworded to "neither
proven to work nor proven to fail".

**The refusal corpus was scanning the wrong surface.** The first version checked
forbidden phrases against the raw JSON and terminal output, and a fixture
forbidding "tcp" failed because the evidence records a `tcp.connect` step whose
state is `SKIPPED`. That record is the measurement, not a claim. The scan now
targets claim prose — summary, detail, discriminator, recommendations — from both
the local and shareable reports, with a separate whole-document scan reserved for
mechanisms that must appear nowhere at all, such as "firewall".

**Two mutation survivors, both real.** `B02` (SKIPPED as first failure) survived
because every scenario had its skipped stage *below* the failure, where the walk
stops first; `S11` now covers a stage declined above one. `B18` survived because
canonical ordering is applied twice — once in `Converge`, once in `Evaluate` — so
removing either alone was an equivalent mutant; the plant now removes both.

## 8. Validation

| Level | What ran | Result |
|---|---|---|
| L1 | merge-compatibility `MC01`-`MC10`, boundary, engine, ladder units | pass |
| L2 | monotonicity, contradiction and recommendation monotonicity, determinism across `GOMAXPROCS` | pass |
| L3 | `scripts/phase101b-mutations.sh` | **21 planted, 21 caught, 0 survivors** |
| L4 | `FuzzActivatedPipeline` and the four Phase 10.1A targets | pass |
| L5 | the eight service integration suites | see §10 |
| L6 | the golden incident corpus, with `forbidden` first-class | pass |
| — | `S01`-`S11` production-path scenarios | pass |
| — | `FP01`-`FP05` refusal corpus, with a non-vacuity proof | pass |
| — | historical mutation suites 9.1A/B/C, 9.2B, 9.3A, 10.1A | 0 survivors each |

## 9. Public compatibility

| | Before | After |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| finding codes | 60 | **61** |
| generic `DIAG_` codes | 0 | **1** |
| RabbitMQ codes | 11 | **11** |
| failure classes | 42 | **42** |
| `Reveal` call sites | 4 | **4** |
| `SecretFor` call sites | 4 | **4** |
| external modules | 2 | **2** |
| exit codes | 5 | **5** |

**No JSON field was added, removed, renamed or repurposed.** The one new code is
additive: a consumer that does not know `DIAG_FAILURE_BOUNDARY` sees one more
`INFO` finding, which `docs/CI.md`'s exit contract already tolerates. Four
terminal goldens gained six lines each; the healthy and no-credential goldens are
unchanged.

**Exit semantics are unchanged and proven so.** `deriveSummary` sets
`PROBLEMS_FOUND` only on `ERROR` or `CRITICAL`, so an `INFO` boundary cannot
promote a clean run. The case that would otherwise be invisible — a failing node
that no service rule owns — is asserted directly: status stays `OK` with one
`INFO` finding.

## 10. Integration

All eight suites were run against real servers.

| Suite | Result | vs. the Phase 10.1A baseline |
|---|---|---|
| PostgreSQL 18 | 117 pass, 1 fail | identical |
| Apache Kafka 4.0.0, three-broker KRaft | green | identical |
| Redis 8.2.1 | 23/23 | identical |
| Valkey | 10/10 | identical |
| RabbitMQ 3.13.7, 4.0.9, 4.2.0 | 58 pass, 3 fail in 2 tests | identical |
| LavinMQ 2.3.0 | 9/9 | identical |
| Redpanda v25.1.9 | 12/12 | identical |
| Multi-target | 7/7 | identical, and the boundary flows through the fleet path |

**Every failure is the same test failing for the same reason as at the Phase
10.1A baseline, with byte-identical messages, and none involves diagnosis:**

- `TestTheTLSKeyIsOwnedByTheDatabaseUser` — `server.key uid=0 gid=0`. A macOS
  virtiofs bind mount reports uid 0 and does not honour a `chown` issued from
  inside a container, which was verified directly. The guard runs before any
  product code and its file is untouched by this phase.
- `TestRAB16BrokerStopped` — `tcp = PASS, want FAIL against a stopped broker`.
  colima keeps a forwarded port listening after its container stops.
- `TestRAB24And25AddressLiterals/RAB-25_IPv6_literal` — `tcp = FAIL, want PASS`.
  colima does not forward IPv6 to containers.

All three fail at the transport or fixture level, before any rule runs. The
environment was not correctable from here — virtiofs ownership and IPv6
forwarding are properties of the VM — and the alternative, changing a fixture to
accommodate it, is exactly what must not be done to satisfy an environmental
problem.

**What the integration run establishes about this phase:** four PostgreSQL tests
and one CLI test asserted "exactly one finding" and now legitimately see the
boundary alongside the service claim. They were scoped to the service claim, the
same way the `internal/app` assertions were, rather than the boundary being
suppressed. No other integration assertion moved.

## 11. Schema pressure

None was acted on and two are recorded.

- **Structured contradiction.** Contradiction is rule-internal by ADR 0081 §2.4
  and reaches no report field. Phase 10.1B needed none: the ladder consumes it
  and the finding carries the result. The revisit condition is unchanged — a
  support workflow that needs to know *why* a hypothesis was not emitted.
- **Recommendation kind and safety class.** ADR 0082 §2.1 puts them on
  `domain.Recommendation` additively. Phase 10.1B emits no new recommendation, so
  moving them would add a field nothing populates.

Neither was forced into an existing string field. `SchemaVersion` stays 1, and
the honest conclusion is the narrow one: *Phase 10.1B required no schema change.*
