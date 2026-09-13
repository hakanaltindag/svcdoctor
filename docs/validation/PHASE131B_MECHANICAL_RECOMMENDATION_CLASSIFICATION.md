# Phase 13.1B — Mechanical recommendation classification

- **Phase:** 13.1B — controlled implementation of the Phase 13.1A freeze. **Metadata, not meaning.**
- **Baseline:** `719c432c5a8b9af6f2d46087d2484640c507ab3c`, `HEAD == origin/main`, clean tree,
  `make check` green before anything was edited
- **Contract:** ADR **0097** and
  `docs/validation/PHASE131A_RECOMMENDATION_CLASSIFICATION_CONTRACT_FREEZE.md`. Appendix A of that
  record is the migration map and was followed row by row; nothing was reclassified independently
- **Result:** **55 migrated · 9 already classified · 9 deferred to 13.1C · 73 total.** Every one of
  the 73 action strings is **byte-identical** to the baseline, proven by SHA-256 rather than by review
- **Open blockers:** none

---

## 1. Baseline and pre-state

```
HEAD        719c432c5a8b9af6f2d46087d2484640c507ab3c  docs(diagnosis): freeze recommendation classification contract
origin/main 719c432c5a8b9af6f2d46087d2484640c507ab3c
tree        clean
make check  GREEN
```

Re-measured from source before editing, and matching the 13.1A freeze exactly:

| Fact | Pre | Post |
|---|---:|---:|
| Total finding codes | **69** | **69** |
| Production rules | **24** | **24** |
| Failure classes | **42** | **42** |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** | **1 / 1** |
| Distinct semantic recommendations (constants) | **73** | **73** |
| Structured (classified) | **9** | **64** |
| Legacy (unclassified) | **64** | **9** |
| `Recommendations:` producer sites | **47** | **47** |
| NEXT_EVIDENCE producers | 9 constants | **64 constants** |
| **REMEDIATION producers** | **0** | **0** |
| `RecommendationKind` members | 3 | 3 |
| `SafetyClass` members | 8 | 8 |
| `security.Reveal` / `SecretFor` | 5 / 5 | 5 / 5 |
| Legacy production construction sites | 7 helpers | **5 helpers**, serving exactly the 9 |

## 2. What was done, per package

Each rule package gained a classified construction helper modelled on the one
`internal/diagnosis/kubernetes/shared.go` has carried since Phase 12.1C, and kept its legacy
`recommend` helper for the recommendations Phase 13.1C owns.

| Package | Mechanism | Migrated | Deferred |
|---|---|---:|---:|
| `transport` | `buildInput` gains `safety`/`rationale`; `recommendations()` routes through `diagnosis.Recommend` | 8 | 0 |
| `kafka` | `claim` gains `safety`/`rationale` with `SafetyUnspecified` meaning "13.1C owns it"; `claim.recommendations()` dispatches; `recommendationFor(layer)` returns a classification per layer | 14 | 2 |
| `postgres` | `advise()` added beside `recommend()`; the TLS claim table gains two fields; `mechanismUnavailable` threads the classification from its caller | 17 | 3 |
| `redis` | `advise()` added beside `recommend()` | 7 | 2 |
| `rabbitmq` | `advise()` added beside `recommend()` | 9 | 2 |
| `kubernetes` | untouched — already classified | 0 | 0 |

### 2.1 The three shapes that needed more than a call-site edit

**Table-driven claims.** `kafka/protocol.go`, `postgres/tls.go` and `transport/tls.go` select a
recommendation from a table keyed by failure class. The classification is a table column, which is
what keeps *one constant, one classification* (ADR 0097 §2.3) true by construction: 22 of the Kafka
table's 23 entries were touched, and the 11 distinct constants each carry a single safety class
across every entry that names them.

**A mixed list.** `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` emits one recommendation per failing
transport layer — DNS, TCP, TLS — and only two of the three were migrated. The finding therefore
carries a **mixed** set of classified and unclassified advice while REC-021 stands. The report model
admits it: both are valid values and each says exactly what is known about it, and the deduplication
key is the whole value, so the two never collapse.

**A hypothesis at LOW confidence.** That same finding is CONFIRMED/HIGH when every path failed and
HYPOTHESIS/LOW when some were never measured. `AdmitAdvice` is handed the finding's own kind and
confidence, so `recommendations()` now takes them and the `Recommendations` assignment moved to
*after* the verdict switch. Passing a constant CONFIRMED/HIGH pair would have been a lie in the call
even though `AdmitAdvice` constrains neither for NEXT_EVIDENCE.

## 3. Action-text freeze — the proof

**Mechanism:** every `recommend<Name>` constant in the production diagnosis tree was extracted and
hashed **before the first edit**, and re-extracted and re-compared after every stage. The per-constant
digests are frozen in `test/security/recommendationclassification_test.go`, so the proof is a test
rather than a transcript.

```
constants checked   73
mismatches           0
corpus digest        12cce3646822d23071ffd595c1b825ab8ad4071daf555ff7912414abc36da20c   (before)
corpus digest        12cce3646822d23071ffd595c1b825ab8ad4071daf555ff7912414abc36da20c   (after)
```

**All 64 previously-legacy actions and the 9 already-classified ones are byte-identical**, which is
the whole of §5's and §51's claim. The guard is `TestMigratedRecommendationActionTextIsFrozen`.

## 4. Distributions

**Kind** — NEXT_EVIDENCE **64**, REMEDIATION **0**.

**Safety** — OBSERVE **32**, VERIFY **18**, COMPARE **14**, CONFIG_CHANGE **0**, RESTART **0**,
DISRUPTIVE **0**, SECURITY_WEAKENING **0**. Unclassified **9**.

Of the 55 migrated: OBSERVE **30**, VERIFY **16**, COMPARE **9** — exactly Appendix A.

**SelfCollectable**, over classified NEXT_EVIDENCE — `true` **2**, `false` **62**,
**absent 0**. The two `true` values are the pre-existing *"re-run with a larger execution budget"*
pair; **none of the 55 is self-collectable**, which is the measurement §14 of the freeze turned into
the planner trigger and which this phase leaves untouched at zero discriminating observations
svcdoctor can take.

### 4.1 Per service

| Service | Total | Structured before | Migrated in 13.1B | Deferred to 13.1C | Structured after |
|---|---:|---:|---:|---:|---:|
| Generic/Core (transport) | 8 | 0 | **8** | 0 | 8 |
| Kafka | 18 | 2 | **14** | 2 | 16 |
| PostgreSQL | 23 | 3 | **17** | 3 | 20 |
| Redis/Valkey | 9 | 0 | **7** | 2 | 7 |
| RabbitMQ/LavinMQ | 11 | 0 | **9** | 2 | 9 |
| Kubernetes | 4 | 4 | **0** | 0 | 4 |
| **Total** | **73** | **9** | **55** | **9** | **64** |

The generic `internal/diagnosis` root holds no recommendation: `DIAG_FAILURE_BOUNDARY` carries none,
and Phase 13.1A §9 decided KEEP NONE.

## 5. Rationales

55 written, one per migrated constant, in the style the nine existing ones established: one sentence
that says what this client established and names the half of the question it did not answer.

Frozen contract honoured — svcdoctor-owned bounded prose, deterministic, **no format verb, no IP
literal, no hostname, no port, no peer text, no runtime error, no credential**. Scanned for all five
patterns across all 64 rationale constants: **0 hits**.

**Two were shortened after a guard refused them, and neither was a licence to raise the bound.**
`TestUX1920TheOutputIsStableAndBounded` records the widest emitted line at **285** columns and exists
so that svcdoctor's unwrapped output *"does not get worse while the wrapping work is outstanding"*.
The first draft pushed it to **318**. The two over-budget rationales were rewritten to fit; the final
widest line is **281**.

**One was reworded for a claim-discipline guard**, which is the more interesting catch.
`rationaleTCP` read *"…and none of them is visible to a client that was refused"*, and the Kafka
golden corpus forbids the substring `"none of the"` in a scenario where two of three endpoints *were*
reached — because that phrasing reads as a cluster-wide claim. `"none of them"` contains it. Reworded
to *"a refused client observes no part of it"*. A second, `rabbitmq/rationaleCredentialsRejected`,
said *"a wrong password and an unknown user are one observation"*; `"wrong password"` is a forbidden
phrase in this repository even inside a disclaimer, because a substring guard cannot tell the
difference. Changed to *"a mistyped password"*.

## 6. Silent-drop defense

`diagnosis.Recommend` returns `nil` on any error — an invalid kind/safety pair, a blank rationale, an
action the text validator refuses, a confidence-gate refusal. A misclassification therefore does not
fail a build; **it deletes the recommendation from the report.**

Three independent guards close it:

| Guard | What it proves |
|---|---|
| `TestEveryMigratedRecommendationSurvivesAdmission` (test/security) | all **64** classified rows construct through the production function and come back as exactly one recommendation with the expected kind, safety, collectability and action. **64 admitted, 0 dropped.** |
| `TestEveryProducedRecommendationCarriesItsFrozenClassification` (×5, per rule package) | the **production rules** attach the frozen classification, driven over each package's own producer matrix — and a finding carrying *no* recommendation fails unless its code is named as one for which that is the designed answer |
| `TestEveryProducedRecommendationIsClassifiedExceptTheNine` (test/diagnosis) | every recommendation the golden corpora produce is classified, except the nine, by action text |

The per-package layer exists because of the mutation suite: **eight mutations of a call site survived
a table-only guard set** (§9.1). A table can be right about what the classification should be and
blind to whether production applies it.

## 7. Legacy producer boundary

**All production recommendation construction paths were discovered by AST**, not by grepping a
remembered directory: `TestLegacyRecommendationConstructionIsBoundedToTheNine` walks every production
file in every package under `internal/diagnosis` — derived from `allProductionPackages`, so a new rule
package cannot escape it — and looks for `domain.NewRecommendation` call expressions.

After migration there are **5** legacy sites in **4** packages, and the allowlist names the nine
recommendations they serve individually:

| Package | Legacy sites | Phase 13.1C recommendations served |
|---|---|---|
| `kafka` | `protocol.go` (claim dispatch), `recommendation.go` (layer map) | REC-012, REC-021 |
| `postgres` | `shared.go` (`recommend`, reached from three call sites) | REC-031, REC-034, REC-036 |
| `redis` | `shared.go` | REC-052, REC-055 |
| `rabbitmq` | `shared.go` | REC-064, REC-067 |
| `transport`, `kubernetes` | **none** — allowlist entry is empty, and a call from either fails | — |

**Shrink-only, three ways.** The package count is pinned at 4; the allowlist must name exactly 9
`REC-` identifiers; and those 9 must equal the set the frozen corpus marks deferred. A tenth
exemption (**M15**) and a *narrowed* reason that would let a tenth in unnamed (**M16**) are both
caught.

`domain.NewRecommendation` is **kept**, per ADR 0097 §2.1: `internal/security/redaction` rebuilds an
unclassified recommendation through it, and the type still admits them.

## 8. Convergence

**Neutral, and provably so rather than by assertion.** The recommendation union deduplicates on the
**whole five-field value**, so `TestClassifyingOneConstantOnceKeepsConvergenceNeutral` states the four
reachable cases:

| Case | Behaviour | Why it matters |
|---|---|---|
| same action, same metadata | one value, collapses | the only case production reaches, because one constant gets one classification |
| same action, different safety | distinguishable | ADR 0081 §2.2b — a merged field never holds a value nobody stated |
| same action, different rationale | distinguishable | the rationale is part of the value |
| classified vs unclassified, same action | distinguishable | the mixed Kafka list does not collapse |

`mergeable` keys on layer, summary, detail and discriminator; recommendations are not in the key and
gain no influence over it. **M11** — giving one shared constant two classifications — is caught.

## 9. Mutation closure — 17 planted / 17 caught / 0 survivors

All three files sets restored byte-for-byte, verified by SHA-256. No `git stash`, `reset` or
`checkout` was used anywhere.

M01 remove Kind · M02 NEXT_EVIDENCE→REMEDIATION · M03 Safety→SECURITY_WEAKENING ·
M03b Safety→CONFIG_CHANGE · M04 remove Rationale · M05 flip a frozen `true` to `false` ·
M06 flip a frozen `false` to `true` · M07 migrate a deferred recommendation · M08 revert one to
legacy · M09 create a legacy producer in a fully migrated package · M10 modify a migrated action
string · M11 two classifications for one constant · M12 drop a corpus row · M13 make a
recommendation silently drop · M14 add a REMEDIATION producer · M15 add a tenth exemption ·
M16 widen an allowlist reason.

### 9.1 The first run caught 9 of 17, and that is the useful part

**Every one of the eight survivors was a real gap in the guard set, and they were all the same gap:**
the guards proved the *table* and the *model* and nothing proved the *wiring*. M01, M03, M03b, M04,
M06, M07 and M08 all mutate a production call site, and a frozen table cannot notice that a rule
stopped passing it. The corpora could not either — they reach Kafka, PostgreSQL and generic transport
and **not Redis or RabbitMQ at all**.

The fix was the five per-package wiring guards of §6, driven over each package's own producer matrix.
Building them found three further things worth recording:

- **`transport`'s `everyFinding` covers three of eight recommendations.** It exists to prove three
  codes build, and the five TLS classes share one finding. The guard drives the six TLS failure
  classes explicitly rather than weakening its own reachability requirement.
- **`postgres`'s `shapes()` is keyed by finding code, so it silently keeps one of two shapes that
  share a code.** `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` has two actions selected by failure
  class; the map kept whichever was built last, and one action was therefore unreachable from that
  matrix. Both are driven now.
- **`KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` legitimately carries no recommendation** when the
  advertised set is complete. The guard takes a `mayCarryNone` set rather than treating every empty
  list as a silent drop, and that code is its only member.

### 9.2 Two harness defects, disclosed rather than absorbed

**The first harness run left two mutations in the working tree.** Its `FILES` backup list omitted
`internal/diagnosis/kafka/topology.go` and `internal/diagnosis/redis/hello.go`, so `restore()` never
touched them — and it still reported *"all files restored byte-for-byte"*, because it verified only
the files it knew about. M05's `SelfCollectable: true → false` and M10's removed comma survived into
the tree.

Both were found, and by different means: M05 by the new Kafka wiring guard, and M10 by the
action-text freeze during the race run. **Both were repaired by direct edit**, not by
`git checkout`, and the whole 73-constant corpus was re-verified against the pre-edit baseline
afterwards — `mismatches 0`, aggregate digest identical.

The harness now asserts every file it plants into is in its backup set, and that assertion is
computed from the plant bodies rather than maintained by hand. **This is the third time this
repository has lost a mutation run to a harness that reported success while measuring less than it
claimed** — after the Phase 9.x `grep -q`/`SIGPIPE` defect and the Phase 12.2B empty `-run`
selection. The lesson is the same each time and is worth stating plainly: *a mutation harness must
prove the set it measured, not the set it intended.*

**Two plant anchors went stale and were repaired rather than retired**, which is the precedent Phase
9.x set for stale `-run` selectors. `NBE-M17` in `scripts/phase104b-mutations.sh` anchored on the
comment `// recommend wraps one action`, which this phase reworded; it is re-anchored on the function
**declaration**, which cannot drift with prose. M12's anchor was a regex over the corpus table's
exact whitespace, which `gofmt` changed; it now filters lines and asserts it removed one.

## 10. Historical mutation suites

| Suite | Result |
|---|---|
| `phase104b` — Phase 10.4B structured recommendations | **17 / 17 / 0** (after the NBE-M17 re-anchor; 16/17 with the stale anchor, classified *unplantable* by the harness itself) |
| `phase102a` — convergence semantics | **8 / 8 / 0** |
| `phase102` — Kafka intelligence | **25 / 25 / 0** |
| `phase103` — PostgreSQL intelligence | **27 / 27 / 0** |
| `phase101b` — the engine, boundary and recommendation fields | **21 / 21 / 0** |

**No historical suite gained a survivor.** `TestNoServiceLocalAdviceProjectionHelperExists` — the
property NBE-M17 protects — was verified to still pass and still catch a reintroduced lossy helper
before the anchor was touched.

Not run, and why: `phase121b`, `phase121c`, `phase121c2`, `phase121d` (Kubernetes acquisition and
real-cluster validation — this phase changes no Kubernetes file), `phase91a`/`91b`/`91c` (fleet
configuration and execution), `phase92b`, `phase93a`, `phase101a`, `phase107b`, `phase108b`.

## 11. Renderer, canonical JSON, fleet and exit behaviour

**No renderer source file changed.** `internal/render/terminal/findings.go` already prints the
classification tag and the rationale; what changed is what it receives.

### 11.1 One factual error in the Phase 13.1A record, corrected here

13.1A §7.4 and §11.3 state that the rationale *"stays canonical-only: no renderer prints it today"*.
**That is wrong.** `internal/render/terminal/findings.go:57-59` prints the rationale, indented, for
every classified recommendation — and has since Phase 10.4B, which is why the nine already-classified
recommendations already showed theirs.

This is an error about **existing behaviour**, not a contract violation and not a reason to stop: no
renderer source changed, and the decision it was attached to — *no renderer change in 13.1B* — holds
exactly. The consequence is that the human-output change is **larger than 13.1A predicted**: the
terminal gains a tag *and* a rationale line on 55 recommendations, not a tag alone. It is reported
here rather than left for a reader to discover in a diff.

### 11.2 Fixtures — three classes, and only one of them moved

*Terminology tightened by Phase 13.1A.1: this section originally called two different fixture
classes "goldens". The measurements below did not change.*

| Class | Location | Construction | 13.1B effect |
|---|---|---|---|
| Aggregate contract fixtures | `test/golden/testdata/*.json` (6) | **synthetic** — `rungolden_test.go` hand-builds `domain.RunReport` values; its only recommendation is `NewRecommendation("Check that the service is listening on this port")`, a string in no production file | **unchanged** |
| Renderer-package goldens | `internal/render/terminal/testdata/*.txt` (19) | **synthetic report, real renderer** — findings hand-built in `*_test.go`, rendered by the real terminal renderer | **unchanged** |
| CLI output fixtures | `internal/cli/testdata/*.txt` (8) | **real run, real renderer** — reports from `internal/app` measuring real loopback sockets, rendered through the real command; only durations and ephemeral ports normalized | **5 of 8 changed** |

The first two classes are unchanged **because of how they are constructed, not by luck**: neither
contains a production recommendation constant, so classifying production constants cannot reach
them. No fixture was suppressed or exempted to keep them still.

Five CLI output fixtures changed, and the diff is **10 insertions / 5 deletions across 5 files** —
nothing but the tag appended to an unchanged action line, plus one rationale line:

```
-    → Check that the hostname is spelled as intended and that it has an address record visible to …
+    → Check that the hostname is spelled as intended and that it has an address record visible to …  [NEXT_EVIDENCE / VERIFY / you must collect]
+      svcdoctor asked this host's own resolver for the name the target declared and was answered …
```

Regenerated with `-update` and every hunk read. **`shareable.txt` is among them**, which confirms the
rationale survives the redaction projection — correctly, since `redact.go` passes it through the same
`t.text()` transformation as the action, and no rationale carries anything to pseudonymize.

13.1A §11.2 said no committed golden would move, on the ground that the `test/golden` JSON fixtures
are synthetic. That is true of **those** fixtures; `internal/cli/testdata` is produced by running the
real CLI, and those five are the ones that moved. The distinction was in the record; the conclusion
drawn from it was too broad. **Phase 13.1A.1 corrected 13.1A §11.2 in place** with the table above
and corrected its may-touch file list, which had named only *"synthetic goldens"* as an optional
addition and omitted `internal/cli/testdata` as a required regeneration.

The three unchanged CLI fixtures are `healthy.txt`, `incomplete.txt` and `testdata/help/`: their
runs produce no finding carrying one of the 55.

### 11.3 Canonical JSON, measured on a real run

```
svcdoctor diagnose postgres --host 127.0.0.1 --port 5433 --user app --output json
  schemaVersion                  1
  TCP_CONNECTION_NOT_ESTABLISHED
    action            (unchanged)
    kind              NEXT_EVIDENCE
    safety            VERIFY
    selfCollectable   false
    rationale         present
  exit code           1
```

### 11.4 Fleet RunReport

```
svcdoctor run --config … --output json
  aggregate schemaVersion       1
  nested report schemaVersion   1
  executionState                COMPLETED
  kind=NEXT_EVIDENCE safety=VERIFY selfCollectable=false rationale=present
  exit code                     1
```

**Both schema versions stay 1**, the metadata survives nesting verbatim, and the exit code is
unchanged. No fleet configuration, scheduling or aggregate field changed.

### 11.5 Finding semantics

No finding field moved. `make check` is the proof for most of it — the frozen counts, the golden
help surfaces, the claim guards and the corpora all pass — and the five per-package wiring guards
assert the recommendation metadata specifically while the corpora assert the surrounding finding.
Codes **69**, rules **24**, failure classes **42**, severities, confidences, evidence references,
discriminators, layers and exit codes: all unchanged.

## 12. Security regression

| Check | Result |
|---|---|
| Action redacted structurally | unchanged — `redact.go` rebuilds through the same path |
| Rationale redacted | **yes**, through the same `t.text()` transformation, on the classified branch |
| Raw runtime error in advice | none — all 64 rationales are package constants |
| Peer-controlled text in advice | none — scanned for format verbs, addresses, hostnames and ports: **0 hits** |
| Secret or credential in advice | none |
| Security-weakening advice newly admitted | **none** — `SECURITY_WEAKENING` stays unproducible |
| Target mutation structured as safe | **none** — all 55 are OBSERVE/VERIFY/COMPARE, and the 8 target-mutating sentences stay unclassified in 13.1C's hands |
| `test/security` suite | **PASS**, including `-race` |

## 13. Validation performed

| | Result |
|---|---|
| **`make check`, final clean tree, no plant** | **GREEN** |
| `git diff --check` | **CLEAN** |
| Phase 13.1B mutation suite | **17 / 17 / 0** |
| Historical suites (5) | **98 planted / 98 caught / 0 survivors** |
| `-race` on `internal/diagnosis/...`, `internal/domain/...`, `internal/render/...`, `internal/security/...`, `test/diagnosis`, `test/security` | **all ok** |
| Action-text freeze | **73 checked, 0 mismatches** |
| Admission | **64 admitted, 0 silently dropped** |

**Omitted, and why.** **Fuzz** — the domain model, both constructors and the serializer are
untouched, so every existing fuzz target covers code that did not move. **Docker and `kind`
integration suites** — no protocol, adapter, probe or acquisition file changed, and the recommendation
path is covered hermetically by the five per-package matrices, the two corpora and the golden CLI
runs; running a real PostgreSQL or a `kind` cluster would re-measure unchanged acquisition. The
`-race` sweep was scoped to the modified and directly affected packages rather than the whole tree,
and that scope is stated rather than implied.

## 14. Compatibility statement

| Class | Applies | Detail |
|---|---|---|
| **ADDITIVE CANONICAL METADATA** | **YES** | four already-`omitempty` fields become populated on 64 recommendations. A consumer reading `action` alone is unaffected |
| **HUMAN-OUTPUT — CLASSIFICATION TAG** | **YES** | the terminal appends `[KIND / SAFETY / who collects]` to 55 more action lines |
| **HUMAN-OUTPUT — RATIONALE LINE** | **YES** | the terminal prints one indented rationale line beneath each of those 55. **Pre-existing renderer behaviour becoming populated**, shipped in Phase 10.4B and documented in `docs/OUTPUT.md`; it is not listed under "metadata" because it is prose an operator reads |
| **ACTION TEXT CHANGE** | **NO** | byte-identical, 73 of 73, proven per constant by SHA-256 |
| **SCHEMA CHANGE** | **NO** | `SchemaVersion` 1, `RunSchemaVersion` 1 |
| **EXIT BEHAVIOR CHANGE** | **NO** | no severity, status or precedence moved |
| **DIAGNOSTIC CLAIM CHANGE** | **NO** | no finding code, rule, severity, confidence, evidence reference or failure boundary moved |
| **CLI CONTRACT CHANGE** | **NO** | no flag, command, argument or output form; the rendered *content* of `--output text` changes, and nothing about how it is invoked or parsed |
| **CONFIG CHANGE** | **NO** | no fleet configuration, no schema, no credential source |
| **ACQUISITION CHANGE** | **NO** | no probe, adapter, wire package or Kubernetes client file touched; nothing new is sent to any endpoint |
| **RENDERER SOURCE CHANGE** | **NO** | **0 files**. `internal/render/terminal/findings.go` already printed both |

**Released-behaviour scope.** None of the above reaches a published release: rationale rendering and
`adviceTag` landed in Phase 10.4B on 2026-09-05, and the newest tag `v0.4.0` is 2026-09-02.

## 15. Phase 13.1C handoff

The nine remain exactly as Phase 13.1A recorded them, verified unchanged byte for byte. Their table is
§17 below. 13.1C owns: the semantic review, the authorized rewrites, the security review, the final
zero-production-legacy invariant, the remaining R-G guards, and the deletion of the temporary
allowlist in `test/security/recommendationclassification_test.go` together with the per-package
`recommend` helpers it exempts.

No replacement prose is proposed here beyond what 13.1A already recorded.

## 16. Changed files

| File | Class |
|---|---|
| `internal/diagnosis/transport/{build,dns,tcp,tls}.go` | **PRODUCTION** |
| `internal/diagnosis/kafka/{protocol,recommendation,advertisedendpoint,unusableadvertisement}.go` | **PRODUCTION** |
| `internal/diagnosis/postgres/{shared,authentication,session,startup,sslrequest,tls}.go` | **PRODUCTION** |
| `internal/diagnosis/redis/{shared,authentication,hello,ping,sentinel}.go` | **PRODUCTION** |
| `internal/diagnosis/rabbitmq/{shared,authentication,connectionopen,protocol}.go` | **PRODUCTION** |
| `internal/diagnosis/*/classification_test.go` (5 new) | **TEST** |
| `test/security/recommendationclassification_test.go` (new) | **TEST** |
| `test/diagnosis/recommendationclassification_test.go` (new) | **TEST** |
| `test/diagnosis/nextevidenceinvariant_test.go` | **TEST** |
| `internal/diagnosis/kafka/nextevidencedebt_test.go` (**deleted**) | **TEST** |
| `internal/cli/testdata/*.txt` (5) | **GENERATED** |
| `scripts/phase104b-mutations.sh` | **MUTATION_HARNESS** |
| `docs/validation/PHASE131B_*.md`, `docs/BACKLOG.md` | **DOCUMENTATION** |

No ADR, CI, CONFIG, INTEGRATION or UNEXPECTED change. **No renderer source, no domain model, no
probe, no adapter, no wire package, no CLI, no fleet configuration, no dependency, no `Makefile`.**

### 16.1 The two retired debt tests

`internal/diagnosis/kafka/nextevidencedebt_test.go` is **deleted** and the
`hypothesesWithoutStructuredNextEvidence` entry removed, with its pinned size moved from 1 to 0 —
which is what both files' own comments instruct when the debt is paid.

**The debt is genuinely paid, not waived.** NBE-021 was *"a hypothesis that carries an open question
with no structured observation beside it"*, and `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` now offers
one in every reachable shape. The DNS sentence is still unclassified, but it **cannot be the only
recommendation on a hypothesis**: the incomplete branch requires an unmeasured causal owner at TCP or
TLS, which requires the lookup to have passed, so a DNS-only hypothesis is unreachable. What remains
of that debt is narrower than a finding code, and it is now guarded as such — by the legacy allowlist,
which names the constant rather than the code.


## 17. Migration ledger

### Migrated in Phase 13.1B — all 55

| REC | Service | FindingCode | Source | Action SHA-256 (frozen) | Kind | Safety | SelfCollectable | Rationale | Status |
|---|---|---|---|---|---|---|---|---|---|
| REC-001 | Generic/Core (transport) | `DNS_NAME_NOT_RESOLVED` | `internal/diagnosis/transport/dns.go` · `recommendNameNotResolved` | `de848a8e3f1070dc…` | NEXT_EVIDENCE | VERIFY | false | `rationaleNameNotResolved` | **MIGRATED** |
| REC-002 | Generic/Core (transport) | `DNS_RESOLUTION_FAILED` | `internal/diagnosis/transport/dns.go` · `recommendResolutionFailed` | `41600a5cc255eb5b…` | NEXT_EVIDENCE | VERIFY | false | `rationaleResolutionFailed` | **MIGRATED** |
| REC-003 | Generic/Core (transport) | `TCP_CONNECTION_NOT_ESTABLISHED` | `internal/diagnosis/transport/tcp.go` · `recommendConnectionNotEstablished` | `029814d6b8fd0eeb…` | NEXT_EVIDENCE | VERIFY | false | `rationaleConnectionNotEstablished` | **MIGRATED** |
| REC-004 | Generic/Core (transport) | `TLS_CERTIFICATE_NOT_VALID_NOW` | `internal/diagnosis/transport/tls.go` · `recommendCertificateNotValidNow` | `1d34c7a185fb5c3c…` | NEXT_EVIDENCE | COMPARE | false | `rationaleCertificateNotValidNow` | **MIGRATED** |
| REC-005 | Generic/Core (transport) | `TLS_CHAIN_NOT_TRUSTED` | `internal/diagnosis/transport/tls.go` · `recommendChainNotTrusted` | `2554aecc366cbaf6…` | NEXT_EVIDENCE | COMPARE | false | `rationaleChainNotTrusted` | **MIGRATED** |
| REC-006 | Generic/Core (transport) | `TLS_ENDPOINT_DOES_NOT_SPEAK_TLS` | `internal/diagnosis/transport/tls.go` · `recommendEndpointDoesNotSpeakTLS` | `8ee2b01f375edd6e…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleEndpointDoesNotSpeakTLS` | **MIGRATED** |
| REC-007 | Generic/Core (transport) | `TLS_HANDSHAKE_NOT_COMPLETED` | `internal/diagnosis/transport/tls.go` · `recommendHandshakeNotCompleted` | `0a8fd5a7dd71937e…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleHandshakeNotCompleted` | **MIGRATED** |
| REC-008 | Generic/Core (transport) | `TLS_IDENTITY_MISMATCH` | `internal/diagnosis/transport/tls.go` · `recommendIdentityMismatch` | `03ac4fccd0108f35…` | NEXT_EVIDENCE | COMPARE | false | `rationaleIdentityMismatch` | **MIGRATED** |
| REC-009 | Kafka | `KAFKA_API_VERSIONS_NOT_COMPLETED` | `internal/diagnosis/kafka/protocol.go` · `recommendAPIVersionsNotCompleted` | `88e652796d695eb1…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleAPIVersionsNotCompleted` | **MIGRATED** |
| REC-010 | Kafka | `KAFKA_AUTHENTICATION_NOT_COMPLETED` | `internal/diagnosis/kafka/protocol.go` · `recommendAuthenticationNotCompleted` | `a6ab3dfdbbb9bb42…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleAuthenticationNotCompleted` | **MIGRATED** |
| REC-011 | Kafka | `KAFKA_CREDENTIAL_NOT_CONFIGURED` | `internal/diagnosis/kafka/protocol.go` · `recommendCredentialNotConfigured` | `660b4f972971c051…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleCredentialNotConfigured` | **MIGRATED** |
| REC-013 | Kafka | `KAFKA_CREDENTIALS_REJECTED` | `internal/diagnosis/kafka/protocol.go` · `recommendCredentialsRejected` | `b874815f7c4f98a2…` | NEXT_EVIDENCE | VERIFY | false | `rationaleCredentialsRejected` | **MIGRATED** |
| REC-014 | Kafka | `KAFKA_SASL_HANDSHAKE_NOT_COMPLETED` | `internal/diagnosis/kafka/protocol.go` · `recommendHandshakeNotCompleted` | `b85308d3c0104692…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleHandshakeNotCompleted` | **MIGRATED** |
| REC-015 | Kafka | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` | `internal/diagnosis/kafka/protocol.go` · `recommendMechanismNotOffered` | `56a094e5712b9b6b…` | NEXT_EVIDENCE | COMPARE | false | `rationaleMechanismNotOffered` | **MIGRATED** |
| REC-016 | Kafka | `KAFKA_METADATA_NOT_COMPLETED` | `internal/diagnosis/kafka/protocol.go` · `recommendMetadataNotCompleted` | `fa5996ce13635c05…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleMetadataNotCompleted` | **MIGRATED** |
| REC-017 | Kafka | `KAFKA_PEER_VERIFICATION_FAILED` | `internal/diagnosis/kafka/protocol.go` · `recommendPeerVerificationFailed` | `1f7d3a5490f4dd19…` | NEXT_EVIDENCE | VERIFY | false | `rationalePeerVerificationFailed` | **MIGRATED** |
| REC-018 | Kafka | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `internal/diagnosis/kafka/protocol.go` · `recommendUnsupportedBySvcdoctor` | `32c6387d15ddd075…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleUnsupportedBySvcdoctor` | **MIGRATED** |
| REC-019 | Kafka | `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `internal/diagnosis/kafka/protocol.go` · `recommendUnsupportedExchange` | `b21670f42441f422…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleUnsupportedExchange` | **MIGRATED** |
| REC-020 | Kafka | `KAFKA_API_VERSIONS_VERSION_REJECTED` | `internal/diagnosis/kafka/protocol.go` · `recommendVersionRejected` | `94561a18a3034458…` | NEXT_EVIDENCE | COMPARE | false | `rationaleVersionRejected` | **MIGRATED** |
| REC-022 | Kafka | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | `internal/diagnosis/kafka/recommendation.go` · `recommendTCP` | `cb6dbe4c0746aebf…` | NEXT_EVIDENCE | VERIFY | false | `rationaleTCP` | **MIGRATED** |
| REC-023 | Kafka | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | `internal/diagnosis/kafka/recommendation.go` · `recommendTLS` | `0211041efe98637b…` | NEXT_EVIDENCE | VERIFY | false | `rationaleTLS` | **MIGRATED** |
| REC-026 | Kafka | `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` | `internal/diagnosis/kafka/unusableadvertisement.go` · `recommendUnusable` | `1f95a28c6502e0da…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleUnusable` | **MIGRATED** |
| REC-029 | PostgreSQL | `POSTGRES_AUTHENTICATION_FAILED` | `internal/diagnosis/postgres/authentication.go` · `recommendAuthenticationFailed` | `8e222e9e3aa017e6…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleAuthenticationFailed` | **MIGRATED** |
| REC-030 | PostgreSQL | `POSTGRES_CREDENTIAL_NOT_CONFIGURED` | `internal/diagnosis/postgres/authentication.go` · `recommendCredentialNotConfigured` | `5235f25384dea21b…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleCredentialNotConfigured` | **MIGRATED** |
| REC-032 | PostgreSQL | `POSTGRES_CREDENTIALS_REJECTED` | `internal/diagnosis/postgres/authentication.go` · `recommendCredentialsRejected` | `6e3355bde0bf167f…` | NEXT_EVIDENCE | VERIFY | false | `rationaleCredentialsRejected` | **MIGRATED** |
| REC-033 | PostgreSQL | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | `internal/diagnosis/postgres/authentication.go` · `recommendMechanismNotOffered` | `def6c5f182830439…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleMechanismNotOffered` | **MIGRATED** |
| REC-035 | PostgreSQL | `POSTGRES_PEER_VERIFICATION_FAILED` | `internal/diagnosis/postgres/authentication.go` · `recommendPeerVerificationFailed` | `e1c125436ba8e307…` | NEXT_EVIDENCE | VERIFY | false | `rationalePeerVerificationFailed` | **MIGRATED** |
| REC-038 | PostgreSQL | `POSTGRES_DATABASE_CONNECT_DENIED` | `internal/diagnosis/postgres/session.go` · `recommendDatabaseConnectDenied` | `c7cb4086ece157b4…` | NEXT_EVIDENCE | VERIFY | false | `rationaleDatabaseConnectDenied` | **MIGRATED** |
| REC-039 | PostgreSQL | `POSTGRES_DATABASE_NOT_FOUND` | `internal/diagnosis/postgres/session.go` · `recommendDatabaseNotFound` | `c6424ca86613013e…` | NEXT_EVIDENCE | VERIFY | false | `rationaleDatabaseNotFound` | **MIGRATED** |
| REC-040 | PostgreSQL | `POSTGRES_SESSION_ESTABLISHMENT_FAILED` | `internal/diagnosis/postgres/session.go` · `recommendSessionEstablishmentFailed` | `214d7c8f88ce6e8a…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleSessionEstablishmentFailed` | **MIGRATED** |
| REC-041 | PostgreSQL | `POSTGRES_CONNECTION_NOT_PERMITTED` | `internal/diagnosis/postgres/shared.go` · `recommendNotPermitted` | `d5167a709428e51d…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleNotPermitted` | **MIGRATED** |
| REC-042 | PostgreSQL | `POSTGRES_SSL_NEGOTIATION_FAILED` | `internal/diagnosis/postgres/sslrequest.go` · `recommendSSLNegotiationFailed` | `2eb5002f5c1701a6…` | NEXT_EVIDENCE | VERIFY | false | `rationaleSSLNegotiationFailed` | **MIGRATED** |
| REC-043 | PostgreSQL | `POSTGRES_TLS_DECLINED` | `internal/diagnosis/postgres/sslrequest.go` · `recommendTLSDeclined` | `a0bf304b184e1c3d…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleTLSDeclined` | **MIGRATED** |
| REC-044 | PostgreSQL | `POSTGRES_STARTUP_FAILED` | `internal/diagnosis/postgres/startup.go` · `recommendStartupFailed` | `87398f2d21b992e5…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleStartupFailed` | **MIGRATED** |
| REC-045 | PostgreSQL | `POSTGRES_TLS_CERTIFICATE_NOT_VALID_NOW` | `internal/diagnosis/postgres/tls.go` · `recommendTLSCertificateNotValidNow` | `4212ffa7e02fe4c0…` | NEXT_EVIDENCE | COMPARE | false | `rationaleTLSCertificateNotValidNow` | **MIGRATED** |
| REC-046 | PostgreSQL | `POSTGRES_TLS_CHAIN_NOT_TRUSTED` | `internal/diagnosis/postgres/tls.go` · `recommendTLSChainNotTrusted` | `dcb463d074c98599…` | NEXT_EVIDENCE | COMPARE | false | `rationaleTLSChainNotTrusted` | **MIGRATED** |
| REC-047 | PostgreSQL | `POSTGRES_TLS_HANDSHAKE_FAILED` | `internal/diagnosis/postgres/tls.go` · `recommendTLSHandshakeFailed` | `69d10fe000fff4bf…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleTLSHandshakeFailed` | **MIGRATED** |
| REC-048 | PostgreSQL | `POSTGRES_TLS_IDENTITY_MISMATCH` | `internal/diagnosis/postgres/tls.go` · `recommendTLSIdentityMismatch` | `1fbacb641dd84d20…` | NEXT_EVIDENCE | COMPARE | false | `rationaleTLSIdentityMismatch` | **MIGRATED** |
| REC-049 | PostgreSQL | `POSTGRES_TLS_UPGRADE_NOT_HONORED` | `internal/diagnosis/postgres/tls.go` · `recommendTLSUpgradeNotHonored` | `46a1b34057abcdab…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleTLSUpgradeNotHonored` | **MIGRATED** |
| REC-050 | Redis/Valkey | `REDIS_AUTHENTICATION_NOT_COMPLETED` | `internal/diagnosis/redis/authentication.go` · `recommendAuthenticationNotCompleted` | `bb806efb10e5f56e…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleAuthenticationNotCompleted` | **MIGRATED** |
| REC-051 | Redis/Valkey | `REDIS_CREDENTIAL_NOT_CONFIGURED` | `internal/diagnosis/redis/authentication.go` · `recommendCredentialNotConfigured` | `bf0fa792da942849…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleCredentialNotConfigured` | **MIGRATED** |
| REC-053 | Redis/Valkey | `REDIS_CREDENTIALS_REJECTED` | `internal/diagnosis/redis/authentication.go` · `recommendCredentialsRejected` | `aee13c1683067ebc…` | NEXT_EVIDENCE | VERIFY | false | `rationaleCredentialsRejected` | **MIGRATED** |
| REC-054 | Redis/Valkey | `REDIS_PROTOCOL_NOT_ESTABLISHED` | `internal/diagnosis/redis/hello.go` · `recommendProtocolNotEstablished` | `6e2b25c2dbf4b39f…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleProtocolNotEstablished` | **MIGRATED** |
| REC-056 | Redis/Valkey | `REDIS_ENDPOINT_NOT_SERVING` | `internal/diagnosis/redis/ping.go` · `recommendEndpointNotServing` | `f71047dd5d9d917c…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleEndpointNotServing` | **MIGRATED** |
| REC-057 | Redis/Valkey | `REDIS_PING_NOT_COMPLETED` | `internal/diagnosis/redis/ping.go` · `recommendPingNotCompleted` | `19baef77d1cd6867…` | NEXT_EVIDENCE | OBSERVE | false | `rationalePingNotCompleted` | **MIGRATED** |
| REC-058 | Redis/Valkey | `REDIS_ENDPOINT_IS_SENTINEL` | `internal/diagnosis/redis/sentinel.go` · `recommendSentinel` | `f0039cfe1cbcf8b0…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleSentinel` | **MIGRATED** |
| REC-059 | RabbitMQ/LavinMQ | `RABBITMQ_AUTHENTICATION_NOT_COMPLETED` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendAuthNotCompleted` | `07f6a88be512848b…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleAuthNotCompleted` | **MIGRATED** |
| REC-060 | RabbitMQ/LavinMQ | `RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendAuthUnsupported` | `2e99d6f64572e989…` | NEXT_EVIDENCE | COMPARE | false | `rationaleAuthUnsupported` | **MIGRATED** |
| REC-061 | RabbitMQ/LavinMQ | `RABBITMQ_CREDENTIAL_NOT_CONFIGURED` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendCredentialNotConfigured` | `8aec77f663771d79…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleCredentialNotConfigured` | **MIGRATED** |
| REC-062 | RabbitMQ/LavinMQ | `RABBITMQ_CREDENTIAL_WITHHELD` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendCredentialWithheld` | `7260febadc7c611a…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleCredentialWithheld` | **MIGRATED** |
| REC-063 | RabbitMQ/LavinMQ | `RABBITMQ_CREDENTIALS_REJECTED` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendCredentialsRejected` | `7235afe1d433bf1e…` | NEXT_EVIDENCE | VERIFY | false | `rationaleCredentialsRejected` | **MIGRATED** |
| REC-065 | RabbitMQ/LavinMQ | `RABBITMQ_CONNECTION_NOT_ESTABLISHED` | `internal/diagnosis/rabbitmq/connectionopen.go` · `recommendConnectionNotEstablished` | `58abca4d5dbf65ec…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleConnectionNotEstablished` | **MIGRATED** |
| REC-066 | RabbitMQ/LavinMQ | `RABBITMQ_CONNECTION_NOT_PERMITTED` | `internal/diagnosis/rabbitmq/connectionopen.go` · `recommendConnectionNotPermitted` | `a09e3d44a903e2e8…` | NEXT_EVIDENCE | OBSERVE | false | `rationaleConnectionNotPermitted` | **MIGRATED** |
| REC-068 | RabbitMQ/LavinMQ | `RABBITMQ_VHOST_NOT_FOUND` | `internal/diagnosis/rabbitmq/connectionopen.go` · `recommendVHostNotFound` | `1f34aa8292d30f1b…` | NEXT_EVIDENCE | VERIFY | false | `rationaleVHostNotFound` | **MIGRATED** |
| REC-069 | RabbitMQ/LavinMQ | `RABBITMQ_CONNECTION_START_NOT_COMPLETED` | `internal/diagnosis/rabbitmq/protocol.go` · `recommendStartNotCompleted` | `5eaceecb699dfb2f…` | NEXT_EVIDENCE | VERIFY | false | `rationaleStartNotCompleted` | **MIGRATED** |

### Deferred to Phase 13.1C — all 9, verified unchanged

| REC | Service | FindingCode | Source | Reason deferred | Verified Unchanged |
|---|---|---|---|---|---|
| REC-012 | Kafka | `KAFKA_CREDENTIAL_WITHHELD` | `internal/diagnosis/kafka/protocol.go` · `recommendCredentialWithheld` | "establish verified TLS" is ambiguous between a broker change and trust material supplied to svcdoctor | **YES** |
| REC-021 | Kafka | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | `internal/diagnosis/kafka/recommendation.go` · `recommendDNS` | its first clause asks the operator to redo a DNS measurement this run already took and recorded | **YES** |
| REC-031 | PostgreSQL | `POSTGRES_CREDENTIAL_WITHHELD` | `internal/diagnosis/postgres/authentication.go` · `recommendCredentialWithheld` | same ambiguity as REC-012, on the PostgreSQL credential-withheld path | **YES** |
| REC-034 | PostgreSQL | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | `internal/diagnosis/postgres/authentication.go` · `recommendMechanismUnsupported` | its second clause asks the endpoint to reconfigure authentication so the diagnostic tool can authenticate | **YES** |
| REC-036 | PostgreSQL | `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `internal/diagnosis/postgres/authentication.go` · `recommendUnsupportedBySvcdoctor` | read as role selection it is local; read as a password change it is a mutation, and the two differ in Kind | **YES** |
| REC-052 | Redis/Valkey | `REDIS_CREDENTIAL_WITHHELD` | `internal/diagnosis/redis/authentication.go` · `recommendCredentialWithheld` | "Enable TLS for this endpoint" is unambiguously a server configuration change | **YES** |
| REC-055 | Redis/Valkey | `REDIS_COMMAND_NOT_PERMITTED` | `internal/diagnosis/redis/ping.go` · `recommendCommandNotPermitted` | asks for an ACL grant the refusal does not establish is the correct policy | **YES** |
| REC-064 | RabbitMQ/LavinMQ | `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | `internal/diagnosis/rabbitmq/authentication.go` · `recommendMechanismNotOffered` | "Enable SASL PLAIN on this endpoint" carries no TLS condition | **YES** |
| REC-067 | RabbitMQ/LavinMQ | `RABBITMQ_VHOST_ACCESS_REFUSED` | `internal/diagnosis/rabbitmq/connectionopen.go` · `recommendVHostAccessRefused` | asks for a permission grant and names an administrative command | **YES** |

---

## 18. Phase 13.1A.1 reconciliation and revalidation — 2026-09-13

Phase 13.1A.1 is a contract-correction phase that produced **no production and no test change**. It
reconciled the frozen 13.1A contract with the renderer this repository already had, corrected the
historical record, and revalidated this implementation against the corrected contract. What follows
is what it measured, and it is an addition to this record rather than a rewrite of it.

### 18.1 The renderer contract, accepted

The central question was whether the pre-existing rationale rendering is the intended contract.
**It was accepted.** `docs/OUTPUT.md` already documents the rationale line to operators and
`internal/render/terminal/testdata/next-evidence-classified.txt` already pins it, so rejecting it
would have meant deleting a documented, golden-pinned feature — a renderer change needing its own
phase. ADR 0097 §8 is the amended record; 13.1A §2, §7.4, §11.2, §11.3, §11.4 and §19 are corrected
in place, each marked as a correction.

**Frozen field visibility, re-measured from source rather than from §11.1:**

| Field | Canonical JSON | Terminal | Condition | Machine-readable |
|---|---|---|---|---|
| `action` | always | after `→` | non-empty | the stable unit |
| `kind` | `omitempty` | in `[ … ]` | `Classified()` | yes |
| `safety` | `omitempty` | in `[ … ]` | `Classified()` | yes |
| `selfCollectable` | `omitempty` `*bool`, `NEXT_EVIDENCE` only | in `[ … ]` | `Classified()` and `NEXT_EVIDENCE` | yes, tri-state |
| `rationale` | `omitempty` | own line, six-column indent, unwrapped | **`Rationale() != ""`** | **no** |

§11.1 of this record says the renderer prints the rationale *"for every classified recommendation"*.
That is true in effect and not the renderer's own condition: `findings.go:57` tests
`Rationale() != ""`. The two coincide only because `domain.NewRecommendation` cannot set a rationale
and `NewClassifiedRecommendation` refuses a blank one. There is **no Markdown or HTML renderer** —
`internal/render` holds `terminal` and `json`, and `--output markdown|html` is an exit-2 usage error.

### 18.2 Rationale content review — 64 reviewed, 0 changed

Because the rationale is human-visible, all 64 were re-reviewed against the bounded-prose contract,
extracted by AST rather than by grep. **9 are byte-identical to the 719c432 baseline; 55 are new.**

| Property | Result |
|---|---|
| format verb (`%v`, `%s`, …) | **0** — every one is a package constant |
| IPv4 literal, hostname token, `:port` | **0** |
| quoted peer text or raw runtime error | **0** (the one quoted string, `kafka/topology.go`'s `rationaleUnmeasured`, quotes svcdoctor's own two prose alternatives and predates 13.1B) |
| credential-shaped token | **0** |
| longest of the 55 new | **277 characters** (`rabbitmq/rationaleConnectionNotPermitted`) |
| contradicts its own `Action` | **0** — each was read against the action, summary and detail it ships with |
| introduces a diagnostic claim the finding does not make | **0** |
| implies remediation or policy authorization | **0** |

**No rationale required a correction**, so this phase changed no production output. The two longest
constants in the tree — `postgres/rationaleConnectionLimitReached` (317) and
`rationaleAdmissionContrast` (315) — are **pre-existing**, from Phases 10.3 and 10.4B, and are not
13.1B's to answer for.

### 18.3 Revalidation results

| Check | Result |
|---|---|
| `make check` on the inherited tree, before any doc edit | **GREEN** |
| Output bound `knownWidest` | **285, unchanged** — not raised, not disabled; `releaseux_test.go` is not in the working-tree diff at all. Widest emitted line **281** |
| Shareable / redaction | **GREEN** — 38 redaction guards including `TestTheRationaleIsRedactedLikeEveryOtherProseField`, plus the CLI leak sweep. `shareable.txt` renders the rationale with hosts pseudonymized to `host-001` / `ip-001` and no identity token surviving |
| Action-text freeze | **73 checked, 0 mismatches** |
| Classification counts | **73 total · 64 structured · 9 legacy in 4 packages · REMEDIATION 0 · CONFIG_CHANGE 0** |
| Silent drops | **64 admitted, 0 dropped** |
| Convergence | whole-value dedup key unchanged; `TestClassifyingOneConstantOnceKeepsConvergenceNeutral`, `TestRecommendationsCollapseOnlyOnFullSemanticEquality`, `TestTheRecommendationUnionIsOrderInvariant`, `TestC06TheRenamePropertyHoldsForRecommendationOrderToo` all **PASS** |
| CLI fixture diffs, read hunk by hunk | **5 files, 10 insertions, 5 deletions.** Every `→` line's action prefix is byte-identical; the only suffixes added are the tag and one rationale line. **0 unexpected differences** |
| `scripts/phase104b-mutations.sh` | **anchor maintenance only** — see §18.5 |
| `phase104b` mutation suite, re-run | **17 / 17 / 0**, `NBE-M17` caught with the repaired anchor |

### 18.4 The mutation harness was never committed, and 13.1A.1 reconstructed it

§9 reports **17 / 17 / 0** and the harness that produced it is **not in the tree**. Every other
mutation suite in this repository is committed as `scripts/phase<NN>-mutations.sh`; there is no
`scripts/phase131b-mutations.sh`, so §9's closure was not reproducible from the repository.

Phase 13.1A.1 reconstructed all 17 plants from §9's descriptions as a **validation-only** harness
under `/tmp`, never committed, and re-ran them: **17 planted / 17 caught / 0 survivors**, no
unplantable anchor. Every catcher is named:

| Plant | Caught by |
|---|---|
| M01 remove `Kind` · M03 `SECURITY_WEAKENING` · M03b `CONFIG_CHANGE` · M04 remove `Rationale` · M05 frozen `true`→`false` · M06 frozen `false`→`true` · M08 revert to legacy · M11 one constant two classifications · M13 blank rationale | `TestEveryProducedRecommendationCarriesItsFrozenClassification` (per rule package) |
| M02 `NEXT_EVIDENCE`→`REMEDIATION` · M14 add a `REMEDIATION` producer | `TestNoProductionRecommendationIsARemediation` |
| M07 classify a deferred recommendation | `TestEveryProducedRecommendationIsClassifiedExceptTheNine` |
| M09 legacy producer in a migrated package · M15 a tenth exemption · M16 narrow an allowlist reason | `TestLegacyRecommendationConstructionIsBoundedToTheNine` |
| M10 modify a migrated action string | `TestMigratedRecommendationActionTextIsFrozen` |
| M12 drop a corpus row | `TestEveryRecommendationConstantIsAccountedFor` |

**Restoration was verified independently of the harness**, which is the point §9.2 makes and the
reason the reconstruction was done this way. A SHA-256 manifest of **all 974 files in the tree** —
not the harness's write-set, not its backup list — was taken before the first plant and recomputed
after the last: **identical, digest for digest**, and identical again after the `phase104b` re-run.
No `git stash`, `reset`, `checkout` or `restore` was used at any point.

### 18.5 `scripts/phase104b-mutations.sh`, reviewed

The one change is `NBE-M17`'s anchor. The old anchor was the comment `// recommend wraps one
action`, which 13.1B reworded to *"one **unclassified** action"*; it matches **0 times** in the
working tree, so the plant was genuinely unplantable. The new anchor is the function declaration
`func recommend(action string) []domain.Recommendation {`, which matches **exactly once**.

The planted body, the `assert "func projectAdvice" in s` check, the target file and the catching
test `TestNoServiceLocalAdviceProjectionHelperExists` are **all byte-identical**. Nothing was
weakened, no invariant removed, no skip broadened, no coverage decreased, and the suite still
catches 17 of 17. Classification: **MUTATION_HARNESS, anchor maintenance only.**
