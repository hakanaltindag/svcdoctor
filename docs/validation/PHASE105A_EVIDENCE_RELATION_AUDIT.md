# Phase 10.5A — Evidence relations activation audit

- **Phase:** 10.5A — architecture / archaeology. **No production Go code.**
- **Baseline:** `105e43bf4588735217c884915feb3eadd01c2228`, working tree clean
- **Record:** ADR 0087
- **Outcome:** **DEFER.** No relation is activated; no Phase 10.5B is proposed.

---

## 1. Baseline, as measured

| Fact | Value | How |
|---|---|---|
| `HEAD` == `origin/main` | `105e43b` | `git rev-parse` |
| working tree | clean | `git status --short` empty |
| `domain.SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `domain.RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| finding codes | **65** | `TestTheConvergenceInventoryIsComplete`: *attributed 65 of 65* |
| `RuleContext` fields | **3** | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| failure classes | **42** | unchanged; no class touched |
| external modules | **2** | `TestTheDependencyCountIsExact` |
| `Reveal` / `SecretFor` production sites | **4 / 4** | `TestRevealHasOneProductionCallSitePerService` |
| production rules | **22** exported rule functions | convergence scan, per package |

Per-package rule/code split, from the scan: `internal/diagnosis` 1/1, `transport` 3/8, `kafka`
5/15, `postgres` 6/21, `redis` 4/9, `rabbitmq` 3/11.

---

## 2. Producer and reader inventory

Production only. Tests and vocabulary declarations excluded.

| Symbol | Writers | Readers |
|---|---|---|
| `diagnosis.NewBasis` | **1** — `internal/diagnosis/kafka/topology.go:700` | — |
| `BasisBuilder.Support` | **1 site** (`:700`, `:702`, `:704`) | — |
| `BasisBuilder.Contradict` | **0** | — |
| `BasisBuilder.Miss` | **0** | — |
| `BasisBuilder.Block` | **0** | — |
| `EvidenceBasis.Supporting()` | — | **1** — `topology.go:667` |
| `EvidenceBasis.Contradicting()` / `.Blocked()` / `.Missing()` | — | **0** |
| `AdmitConfidence` | **1** — `topology.go:647` | — |
| `AuthorityNone` / `AuthorityDirect` / `AuthorityCompleteContrast` as values | **1 / 0 / 0** | — |
| `Boundary.Blocked()` | `boundary.go:191` | **0** |
| `Boundary.NotMeasured()` | `boundary.go` | **1** — `failureboundary.go:159`, prose selection |
| `GraphBuilder.AddBlockedBy` | **6** — `probe/transport/run.go:368`, `adapter/postgres/{startup:384,negotiate:363,authenticate:643}`, `adapter/kafka/saslauthenticate.go:606`, `adapter/redis/ping.go:89` | `Graph.BlockedBy` read by 3 rules; serialized by `domain/report.go:321` |
| `Confidence` set as a literal | **21 of 22 rules**, all `ConfidenceHigh` except `kafka/advertisedendpoint.go:268` (`Low`) | — |

**Findings that cite a graph-blocked node in `EvidenceRefs`: three.**
`KAFKA_CREDENTIAL_WITHHELD` (`kafka/protocol.go:726`), `POSTGRES_CREDENTIAL_WITHHELD`
(`postgres/authentication.go:339`), `POSTGRES_ADMISSION_SCOPE` (`postgres/admission.go:396`).
All three are production-reachable; the blocking is recorded by the adapter sites listed above.

---

## 3. Frozen semantics, in one table

| Relation | Frozen meaning | Representation | Never |
|---|---|---|---|
| **SUPPORT** | observed, and the claim is more credible for it — **contributing**, not necessary and not sufficient | **two surfaces, not one** (ADR 0087 §2.5, superseding ADR 0086 §2.1 row 1): `Finding.EvidenceRefs` is the **public** citation surface; `EvidenceBasis.supporting` is an **internal epistemic subset**. `Supporting()` ⊆ `EvidenceRefs`, never the reverse | a count that reaches `HIGH`; the complete citation set of a finding |
| **CONTRADICTION** | observed, and inconsistent with **this** claim — reading A only | rule-internal: the rule emits nothing or emits weaker, and says why in `detail` | a report field; a confidence downgrade by definition; support for an alternative; a contrast between two subjects |
| **MISSING** | a discriminating observation that was never made and **has no node** | `EvidenceBasis.missing` (`[]domain.Step`); `Finding.Discriminator`; a `NEXT_EVIDENCE` recommendation | an `UNKNOWN` node; a blocked step; a budget-cut run; an unconfigured input; contradiction |
| **BLOCKED** | not observed **because** an upstream step failed — **Model A**, a projection of `Graph.BlockedBy` | the graph's `blockedBy` edge, serialized in `SchemaVersion` 1; `EvidenceBasis.blocked` as a rule-local citation | a second meaning of blocked; support; contradiction; a reason to fabricate a downstream finding |

**`Graph.BlockedBy` relationship:** `basis.blocked` ⊆ graph-blocked, enforced by `Freeze` check 4;
disjoint from supporting and contradicting, enforced by checks 2 and 3; `AddBlockedBy` admits only
`SKIPPED` nodes; blocking is recorded by whoever declined to run the step and never inferred.

---

## 4. Candidate register

Every rule that could plausibly hold a relation, audited against ADR 0087 §2.10. **"Why NOT" is
mandatory and is the column that decided each row.**

| # | Rule / finding | Current relation | Candidate | Exact evidence | Why candidate | Why NOT candidate | Verdict |
|---|---|---|---|---|---|---|---|
| 1 | `kafka/advertised-suitability` — `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` | suppression | CONTRADICTION | `len(t.reached) > 0` gate, `topology.go:266` | the rule's own doc names it *"the contradiction test"*; a reached advertised peer genuinely falsifies the claim | fails bar **1**: the fact is computed before any basis exists, and the rule returns. Recording it would require emitting the finding it declined to emit — ADR 0081 §2.4's chosen representation *is* the suppression | **Rejected** |
| 2 | `kafka/advertised-endpoint` — `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, `verdictUnreachable` | suppression | CONTRADICTION | `anyReachedTerminal` short-circuit | one completed path resolves the endpoint outright | same as row 1; PASS is existential and the rule never reaches a claim to contradict | **Rejected** |
| 3 | `kafka/advertised-endpoint` — `verdictIncomplete` | `Discriminator` + 3 recommendations | MISSING | unmeasured sibling paths, `advertisedendpoint.go:262–268` | it is the tree's clearest *"we could not finish looking"* hypothesis, and `Miss` is described as the input to next-best evidence | fails bar **3** and **12**: the unmeasured paths are `UNKNOWN` nodes with `EXEC_*` classes — ADR 0086 §2.1 **position 4**, not position 3. They have identifiers; `Miss` takes a `Step` *because* a missing observation has none | **Rejected** |
| 4 | `kafka/advertised-topology` — `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`, incomplete branch | `notMeasured` counted, cited, and stated in prose | MISSING | `t.notMeasured`, `topology.go:342` | unmeasured advertised endpoints are outside a complete claim | fails **3** and **12**. The rule's prose is deliberately narrowed — *"An endpoint that was not measured is not an endpoint that refused"* — so the unmeasured members are **inside** the claim as a stated count, not absent from it. Strengthening the hypothesis to justify MISSING is what the brief forbids | **Rejected** |
| 5 | `postgres/admission-scope` — `POSTGRES_ADMISSION_SCOPE`, `undetermined` | counted, cited as `EvidenceRefs`, stated in prose | MISSING | `scope.undetermined`, `admission.go:271` | an undetermined address is an unmade admission observation | fails **3** and **12**, and activation would **remove** evidence: the nodes are supporting evidence for the count *"no admission decision was observed at N"*. `Miss` cannot hold their identifiers | **Rejected** |
| 6 | `diag/failure-boundary` — `DIAG_FAILURE_BOUNDARY` | `Boundary.Blocked()` computed and discarded; one prose sentence from `NotMeasured()` | BLOCKED | `BlockedChain(g, firstFailure)`, `boundary.go:191` | the one production site where a rule computes graph blocking and throws it away | fails bar **14**, and **3**: nothing would read it, no output byte would change, and the fact already reaches a consumer through the serialized `blockedBy` edge on the cited node (`docs/REPORT_SCHEMA.md` §378–384) | **Rejected** |
| 7 | `transport/tls` — generic TLS | no finding at all when `SKIPPED` | BLOCKED | `tls.go:292`, `State() != StateFail` returns | the brief's §6.C shape: DNS FAIL → TCP not attempted → TLS not attempted | **the correct answer is that no TLS finding exists.** Creating one to carry a BLOCKED basis is a fabricated downstream claim, which the architectural invariant forbids outright | **Rejected — and it proves the shape belongs to no finding** |
| 8 | `postgres/authentication` — `POSTGRES_CREDENTIAL_WITHHELD` | blocked node **and its blocker** in `EvidenceRefs` | BLOCKED | `authentication.go:339–345` | it is literally about a step that did not run | not a relation candidate but the **counter-example**: expressing it through a basis would move the node from `Supporting()` into `blocked`, deleting it from `EvidenceRefs` and changing output. Fails **3** | **Rejected; drives ADR 0087 §2.5** |
| 9 | `kafka/protocol` — `KAFKA_CREDENTIAL_WITHHELD` | the same | BLOCKED | `protocol.go:726` | the same | the same | **Rejected; drives §2.5** |
| 10 | `redis/authentication`, `rabbitmq/authentication` — withheld / not-configured | `SKIPPED` node in `EvidenceRefs`, no blocker edge | BLOCKED | `redis/authentication.go:133`, `rabbitmq/authentication.go:172` | same claim shape as rows 8–9 | neither adapter records a `blockedBy` edge for the auth node, so there is no graph blocking to project. `Freeze` check 4 would refuse `Block` and check 3 would permit `Support`. Nothing to activate | **Rejected** |
| 11 | `redis/ping` — blocked ping node | none | BLOCKED | `adapter/redis/ping.go:89` records the edge | a genuine production `blockedBy` edge | `evaluatePing` produces no finding for a `SKIPPED` node: the blocker owns the failure. Fabricating one is row 7's error | **Rejected** |
| 12 | `postgres/ssl-request`, `postgres/tls` | none; both refuse to cite a blocked step as a cause | BLOCKED | `sslrequest.go:169`, `tls.go:271` | both already reason about blocking | both already implement `docs/FINDINGS.md` §3.1 rule 11 correctly, in the direction of *not* claiming. There is nothing flattened | **Rejected** |
| 13 | `transport/dns`, `transport/tcp` | `CONFIRMED` / `HIGH`, `EvidenceRefs` only | any | `transport/build.go:58` | three codes, one shared builder — a cheap place to adopt a basis | fails **3** and **14**: their claims restate a single `FAIL` node, so a basis would hold one supporting entry and three empty sets, and adopting `AdmitConfidence` truthfully would drop them from `HIGH` to `LOW` | **Rejected** |
| 14 | every remaining service rule (`postgres/{startup,session}`, `redis/{hello,sentinel,ping}`, `rabbitmq/{connection-start,connection-open}`, `kafka/{protocol,unusable-advertisement}`) | `CONFIRMED` / `HIGH`, `EvidenceRefs` only | any | per-file | completeness | each is a direct restatement of one node's state and failure class. No contradicting observation is held, no discriminating observation is named, no blocking is read. There is no relation to flatten | **Rejected** |

**Accepted producers: 0. Rejected: 14 rows covering all 22 rules.**

---

## 5. Requirement register — `REL-001` … `REL-018` (plus `REL-009a`)

Tiers: **F** frozen now and already enforced · **B** required of any activation phase (10.5B) ·
**D** deferred, with a condition.

### 5.1 Relation semantics

| ID | Tier | Requirement | Design | Enforced by |
|---|---|---|---|---|
| REL-001 | **F** | SUPPORT is contributing evidence: not necessary, not sufficient, stronger than related | 0087 §2.1 | `AdmitConfidence` (no count reaches `HIGH`); `docs/FINDINGS.md` §3.1 rule 1 |
| REL-002 | **F** | An `UNKNOWN` node is legitimate SUPPORT for a claim about not having measured something | 0087 §2.1 | `BasisBuilder.Freeze` deliberately omits a conclusiveness check; `POSTGRES_ADMISSION_SCOPE` unit tests |
| REL-003 | **F** | CONTRADICTION means *observed and inconsistent with this claim*, and nothing weaker | 0087 §2.2 | `AdmitConfidence` caps at `LOW`; `TestP05MissingIsNotContradiction` |
| REL-004 | **F** | A contrast between two subjects is never a CONTRADICTION | 0087 §2.2 | `POSTGRES_ADMISSION_SCOPE` prose tests; `test/diagnosis/corpus_test.go` |
| REL-005 | **F** | CONTRADICTION reaches no report field; no `contradictedBy` exists | 0081 §2.4, 0079 §2.4, 0087 §2.2 | `domain.Finding` has no such field; `internal/domain/finding_test.go` |
| REL-006 | **F** | MISSING is an observation with **no node**; an `UNKNOWN` node, a blocked step, a budget-cut run and an unconfigured input are each something else | 0086 §2.1, 0087 §2.3 | `Missing()` returns `[]domain.Step`; `TestP05MissingIsNotContradiction` |
| REL-007 | **F** | Absence never becomes contradiction, and never raises or lowers confidence | 0081 §2.4 | `AdmitConfidence`; `TestNBE015`-family |
| REL-008 | **F** | BLOCKED is **Model A** — a projection of `Graph.BlockedBy`, never a second meaning | 0087 §2.4 | `Freeze` checks 3 and 4; `TestARuleCannotLabelANodeBlocked` |

### 5.2 The two citation surfaces

| ID | Tier | Requirement | Design | Enforced by |
|---|---|---|---|---|
| REL-009 | **F** | The containment runs one way: every `basis.Supporting()` member is an admissible `EvidenceRef`, and **not** every `EvidenceRef` is supporting evidence. `EvidenceRefs = basis.Supporting()` is a sound projection for a claim about the subject's condition and **is not a general law** | 0087 §2.5 (supersedes 0086 §2.1 row 1) | documentation authority, closed in 10.5A: forward markers in ADR 0086's header and at the row itself; `docs/FINDINGS.md` §3.1 rule 20 |
| REL-009a | **D** | A rule of the blocked-subject shape cannot express itself through a basis, because `Freeze` check 3 excludes the node its claim is about | 0087 §2.5 | **would fail today if asserted as a test**; recorded rather than tested. Condition: the phase that narrows check 3 or changes those three findings. `Freeze` is **not** weakened in the meantime |
| REL-010 | **F** | A finding may cite a blocked node when the claim's **subject** is the step that did not run; never as evidence about the subject's condition | 0087 §2.5, `docs/FINDINGS.md` §3.1 rules 11 and 20 | the three producing rules' unit tests; `docs/FINDINGS.md` |
| REL-011 | **F** | No finding is fabricated downstream of a failure in order to carry a BLOCKED relation | 0087 §2.4 | `transport/tls.go:292`; `internal/diagnosis/transport/boundary_test.go` |
| REL-012 | **B** | An activation phase states, before writing a producer, which of the two surfaces it changes and what happens to the three findings in §2 | 0087 §2.5 | the 10.5B record |

### 5.3 Confidence

| ID | Tier | Requirement | Design | Enforced by |
|---|---|---|---|---|
| REL-013 | **F** | No confidence arithmetic. `HIGH − contradiction = MEDIUM` and every equivalent is refused permanently | 0081 §2.3 | `AdmitConfidence`; `internal/diagnosis/confidence_test.go` |
| REL-014 | **B** | `AuthorityCompleteContrast` and `BasisBuilder.Miss` acquire producers **in the same change-set**, because the missing-set check is the only defence against a false complete-contrast declaration and both are at zero today | 0087 §1.3, §2.6 | the 10.5B record; `confidence_test.go` covers the mechanism |
| REL-015 | **D** | The ladder admits no `HIGH` for a claim that restates a measurement svcdoctor took directly; `DIAG_FAILURE_BOUNDARY` would fall to `MEDIUM` under it | 0087 §1.3, §2.6 | recorded, not tested. Condition: a phase with a rule that needs the ground, which then reopens ADR 0081 §2.3 in its own record |

### 5.4 Convergence, schema and next-best evidence

| ID | Tier | Requirement | Design | Enforced by |
|---|---|---|---|---|
| REL-016 | **F** | No basis relation reaches convergence; `Converge` sees `domain.Finding` only | 0087 §2.7 | `internal/diagnosis/converge.go`; `TestC06ARuleIDRenameCannotChangeAnything` |
| REL-017 | **F** | No relation is serialized in `SchemaVersion` 1; `blockedBy` already is, on the graph projection | 0087 §2.8 | `TestALiteralReportKeepsSchemaVersionOne`; `docs/REPORT_SCHEMA.md` |
| REL-018 | **F** | MISSING and `NEXT_EVIDENCE` imply each other in **neither** direction; the live binding is `Discriminator` → `NEXT_EVIDENCE` | 0086 §2.10, 0087 §2.9 | `test/diagnosis/nextevidenceinvariant_test.go`; four `NEXT_EVIDENCE` producers against zero `Miss` producers |

### 5.5 Phase invariants

| ID | Tier | Requirement | Held |
|---|---|---|---|
| REL-A | **F** | absence ≠ contradiction | yes |
| REL-B | **F** | blocked ≠ failed | yes |
| REL-C | **F** | no fabricated downstream finding | yes |
| REL-D | **F** | no new producer without real rule evidence | yes — zero admitted |
| REL-E | **F** | no confidence arithmetic | yes |
| REL-F | **F** | no service-specific import in the generic engine | yes — `internal/diagnosis` imports no service package |
| REL-G | **F** | no schema change in 10.5A | yes — `SchemaVersion` 1, `RunSchemaVersion` 1 |
| REL-H | **F** | no new `FindingCode` in 10.5A | yes — 65 |
| REL-I | **F** | no `RuleContext` change in 10.5A | yes — 3 fields |

---

## 6. Deferred, with the condition that would reopen each

| Item | Condition |
|---|---|
| A production producer for `.Contradict` | a rule that holds observed inconsistent evidence **and still emits a claim**. Every contradiction in the tree today is decisive and fires as suppression before a basis exists, so the producer needs a claim that survives its own counter-evidence — which ADR 0083 §2.2's false-positive policy usually resolves into emitting nothing |
| A production producer for `.Miss` | a rule that names a discriminating observation for which **no evidence node exists**. Every "not measured" in the tree has a node. The likeliest source is a service phase that reasons about a stage svcdoctor never attempts — the same gate `docs/BACKLOG.md` records for a `SKIPPED` protocol node on a failed transport path |
| A production producer for `.Block` | a reader, in the same change-set (ADR 0087 §2.10 item 14). `DIAG_FAILURE_BOUNDARY` already computes the input |
| Narrowing `Freeze` check 3 | a rule that must express, through a basis, a claim whose subject is a blocked step. It is a relaxation of the check implementing ADR 0081 §2.4's sharpest case and needs the reasoning written down, not just the diff |
| A third `Authority` for direct measurement | a rule that needs `HIGH` from the ladder and cannot truthfully declare either existing ground. It reopens ADR 0081 §2.3 and belongs in that phase's record |
| Relation-aware convergence | a relation reaching a `Finding`, which needs §2.8's schema decision first. The two constraints in ADR 0087 §2.7 bind it |
| A relation exposed by a renderer | a report field to expose. There is none |

---

## 7. Validation run

Commands actually run at `105e43b`, working tree carrying documentation changes only:

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 105e43b
git status --short                               # clean at start
git diff --name-only | grep '\.go$'              # no output
gofmt -l .                                       # no output
go build ./...                                   # clean
go vet ./...                                     # clean
go test -count=1 ./...                           # all packages ok
go test ./test/security/... -run 'Closure|Convergence|RuleContext|Schema' -v
go test ./test/security/... -run 'Reveal|SecretFor|Dependenc|Module' -v
```

Guard output recorded: *attributed 65 of 65 declared finding codes*;
`TestDIAG017RuleContextCarriesExactlyThreeFields` PASS;
`TestALiteralReportKeepsSchemaVersionOne` PASS; `TestTheDependencyCountIsExact` PASS;
`TestRevealHasOneProductionCallSitePerService` PASS.

One throwaway probe was written, run and deleted, leaving no diff: it asserted
`NewBasis().Support(<graph-blocked node>).Freeze(g)` returns `ErrInvalidBasis` and that
`.Block(<same node>)` returns nil, which is the measurement behind ADR 0087 §1.3.

**Not run:** container integration suites, mutation harnesses, release or publication steps.
Phase 10.5A is documentation-only, so **no integration-green claim is made.**

---

## 8. Outcome

**OUTCOME C — DEFER.**

No existing rule justifies activating `CONTRADICTION`, `MISSING` or `BLOCKED`. The three
relations are not latent for want of attention: they are latent because the rules that would
produce them are written in the shapes ADR 0081 §2.4 chose — suppression, an `UNKNOWN` node, a
graph edge — and those shapes are correct.

**What would open a Phase 10.5B** is in §6, one condition per relation. The single most likely
opener is a service phase that reasons about a stage svcdoctor never attempts, which is the only
shape that produces an observation with no evidence node — the definition of `MISSING`.

The phase's product is three things the tree did not previously record: the **supersession** of
ADR 0086 §2.1 row 1 by ADR 0087 §2.5 — marked from both ends, so authority is legible from either
document — the fact that two guards in `AdmitConfidence` are currently vacuous and must be armed
together, and `docs/FINDINGS.md` §3.1 rule 20.
