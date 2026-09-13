# Phase 13.2 — Post-13.1 roadmap and validation investment checkpoint

- **Phase:** 13.2 — roadmap audit, validation-gap audit, product investment decision.
  **No production, test, script, workflow or dependency change.**
- **Baseline:** `a1881e13f73c9e04361ab8f096dac0bc3ba1a6f5`, `HEAD == origin/main`, clean tree,
  `make check` green before anything was written
- **Question:** what should svcdoctor build next, and why that before the alternatives?
- **Answer:** **hosted and release-gating integration coverage for the five uncovered suites** —
  Redis, Valkey, RabbitMQ, LavinMQ and multi-target. Not more diagnosis. The diagnostic-opportunity
  frontier has been swept four times by prior audits and is close to exhausted under the current
  authority boundary, while **five of nine `integration-*` targets appear in zero CI workflows**
- **Open blockers:** none

---

## 1. Baseline

```
HEAD        a1881e13f73c9e04361ab8f096dac0bc3ba1a6f5  feat(diagnosis): close recommendation classification semantics
origin/main a1881e13f73c9e04361ab8f096dac0bc3ba1a6f5
tree        clean
make check  GREEN
```

## 2. Methodology

Every number below is measured from source, workflows, the `Makefile` or a test that derives it.
Where a prior record already answered a question, the record is cited **and** the underlying source
re-checked, because a remembered phase summary is not evidence.

The hypothesis under test was stated in the phase brief: *svcdoctor may have accumulated enough
product breadth that the highest-value marginal investment is now trust depth rather than more
diagnosis.* It is **confirmed**, and §4.4 records the one way it was nearly falsified.

## 3. Current product inventory

| Fact | Value | Source |
|---|---|---|
| Finding codes | **69** | `TestTheConvergenceInventoryIsComplete` — 69 of 69 attributed |
| Diagnostic rules | **24** | same |
| Failure classes | **42** | `internal/domain/failureclass_test.go` `wantCount` |
| Service adapters | **5** — Kafka, PostgreSQL, Redis, RabbitMQ, Kubernetes | `internal/adapter/*/` |
| Semantic recommendations | **73** | AST over `recommend*` constants |
| Structured | **73** | `TestEveryRecommendationConstantIsAccountedFor` |
| Legacy | **0** | `TestNoProductionRuleBuildsAnUnclassifiedRecommendation` — 47 files, 7 packages |
| Hypothesis producers | **2 rules**, both Kafka | `kafka/advertisedendpoint.go`, `kafka/topology.go` |
| Discriminator producers | **1** — `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` | `kafka/topology.go:668` |
| `SelfCollectable: true` | **2**, both *"Re-run with a larger execution budget"* | `postgres/admission.go:432`, `kafka/topology.go:628` |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** | `internal/domain` |
| Leaf CLI services | **5** + `run --config` | `internal/cli` |
| Fleet services | **5** | `internal/fleet/services/` |

Rules and codes per package: generic **1/1**, transport **3/8**, Kafka **5/15**, PostgreSQL
**6/21**, Redis **4/9**, RabbitMQ **3/11**, Kubernetes **2/4**.

## 4. The measurement that decides the phase

### 4.1 Every `integration-*` target against every workflow

Nine integration targets exist in the `Makefile`. Six workflow files exist. This is every
occurrence of each target name in each workflow:

| `make integration-…` | `ci.yml` | `kubernetes.yml` | `validate-integration.yml` | `release-oci.yml` | Release-gated |
|---|---:|---:|---:|---:|---|
| `kafka` | 0 | 0 | ✓ | ✓ | **YES** |
| `redpanda` | 0 | 0 | ✓ | ✓ | **YES** |
| `postgres` | 0 | 0 | ✓ | ✓ | **YES** |
| `kubernetes` | 0 | ✓ | 0 | ✓ | **YES** |
| **`redis`** | **0** | **0** | **0** | **0** | **NO** |
| **`valkey`** | **0** | **0** | **0** | **0** | **NO** |
| **`rabbitmq`** | **0** | **0** | **0** | **0** | **NO** |
| **`lavinmq`** | **0** | **0** | **0** | **0** | **NO** |
| **`multitarget`** | **0** | **0** | **0** | **0** | **NO** |

**Five of nine targets appear zero times in all six workflow files.**

### 4.2 What the gates actually are

`ci.yml` — the only lane on `pull_request` and `push: main` — runs `make check`, which is
`fmt-check test vet lint build`. `make test` is `go test ./...` with **no** `-tags integration`, and
every integration suite is behind `//go:build integration`. Measured directly:

```
$ go test ./test/integration/... -count=1
go: warning: "./test/integration/..." matched no packages
```

**Main CI runs zero integration tests for any service, including the four that are release-gated.**

`release-oci.yml` gates publication through `needs:`:

```
stage-and-verify  needs: [identity, source, integration, kubernetes]
publish           needs: [identity, stage-and-verify, archives, kubernetes]
```

and its integration matrix is, verbatim (`release-oci.yml:201`):

```yaml
suite: [postgres, kafka, redpanda]
```

`validate-integration.yml` offers `[all, postgres, kafka, redpanda]` and runs only on
`workflow_dispatch` or a push to `validate-integration/**` — so it is neither a PR gate nor a main
gate for anything.

### 4.3 The compatibility claim this leaves unguarded

`docs/COMPATIBILITY.md` grades **Redis 8.2.1**, **Valkey 8.1.1**, **RabbitMQ** and **LavinMQ** at
**Level 3 — SUPPORTED BASIC**, whose stated bar is *"real evidence **plus** a repeatable committed
test **plus** documented known differences."*

The repeatable committed tests exist — `test/integration/redis` (20 test functions),
`valkey` (8), `rabbitmq` (38), `lavinmq` (10), `multitarget` (7). **Nothing runs them
automatically.** `internal/cli/docsclaims_test.go` enforces that a Level-3 row corresponds to a real
run that happened; it cannot enforce that the run still passes.

So a published release can carry a Level-3 compatibility claim for four platforms that no automation
re-verified for that commit. That is the concrete, user-visible risk.

### 4.4 How the hypothesis was nearly falsified, and why it survived

The strongest counter-argument is that trust work is invisible and diagnosis is the product. It was
tested against the record and it loses on two independent grounds.

**First, the diagnostic frontier has already been swept four times, by audits that admitted almost
nothing:**

| Audit | Scope | Outcome |
|---|---|---|
| **10.6A** (ADR 0088) | Redis + RabbitMQ diagnostic intelligence | **DEFER BOTH** — zero candidates admitted, no 10.6B proposed |
| **10.7A** (ADR 0089) | observation expansion, all services | **one** admitted (PostgreSQL read-only), built as 10.7B |
| **10.8A** (ADR 0090/0091) | existing evidence consumption | **one** admitted (RabbitMQ capacity scope), built as 10.8B |
| **11.0** (ADR 0092) | planner / next-best evidence | **DEFER** — 29 candidates, **zero** admitted |
| **13.0** (ADR 0096) | product and diagnostic roadmap | not an adapter, not Kubernetes, not a planner |

Four sweeps, two admissions, both of which were *activations of evidence already on the wire* rather
than new acquisition. That is what an exhausted frontier looks like under a fixed authority boundary.

**Second, Phase 13.0 already ranked this exact gap second, and Phase 13.1 completed the first.**
`PHASE130…md` §22 names exactly two new items:

| Item | 13.0 verdict |
|---|---|
| 61 of 69 recommendations unclassified | **NEW — DO NEXT (primary)** |
| **CI coverage gap for Redis/Valkey/RabbitMQ/LavinMQ/multi-target** | **NEW — DO NEXT (secondary)** |

13.0 §"SECONDARY — C3" says it plainly: *"That is 20 finding codes and the entire
`svcdoctor run --config` path protected only by a maintainer remembering the release checklist."*
Phase 13.1A/B/C closed the primary. **This phase is not choosing a new direction; it is reaching the
item the repository already put second**, and the independent workflow measurement in §4.1 confirms
nothing has changed since.

**The third ground is the one that surprised the audit.** Phase 10.7A deferred Redis transient-state
findings not on authority but on **fixture determinism** — *"`LOADING` is a restart race,
`MASTERDOWN` needs a replica plus a severed link."* So the blocker on the best product-depth
candidate is validation capability. Trust depth is not competing with product depth here; for Redis
it is **upstream of it**.

## 5. Diagnostic maturity, defined then assigned

The scale is defined before it is used, and it is deliberately not a finding count.

| Level | Meaning |
|---|---|
| **D0** | transport only — DNS/TCP/TLS, no protocol |
| **D1** | protocol connectivity — the service answers, no service-specific claim |
| **D2** | bounded protocol diagnosis — per-stage outcomes normalized into service codes |
| **D3** | authority-backed service diagnosis — claims grounded in fields the protocol defines, with declared non-claims |
| **D4** | multi-observation diagnostic intelligence — a claim no single observation supports: completeness, contrast, or a hypothesis with a discriminator |

| Service | Product depth | Evidence |
|---|---|---|
| **Kafka** | **D4** | 15 codes, 5 rules, the only hypothesis producers, the only discriminator, advertised-topology reachability and suitability aggregates |
| **PostgreSQL** | **D4** | 21 codes, 6 rules, `POSTGRES_ADMISSION_SCOPE` completeness-and-contrast aggregate, connection-limit direct authority |
| **Redis/Valkey** | **D3** | 9 codes, 4 rules; closed `ErrorPrefix` vocabulary, condition named in finding detail; **no aggregate, no hypothesis, no discriminator** |
| **RabbitMQ/LavinMQ** | **D3** | 11 codes, 3 rules; closed `CloseOutcome` vocabulary incl. three capacity scopes; no aggregate |
| **Kubernetes** | **D2/D3** | 4 codes, 2 rules; `AuthorityDirect` with `ConfidenceHigh`, but no aggregate and a deliberate exit-code gap (a `401` exits 0) |

## 6. Validation maturity — a separate axis, and the point of the phase

| Service | Validation/trust maturity | Why |
|---|---|---|
| **Kubernetes** | **STRONGEST** | PR + main + weekly schedule + release gate, two-version matrix, pinned node-image digests |
| **Kafka / Redpanda** | **STRONG** | release-gated, two products, but **no PR or main lane** |
| **PostgreSQL** | **STRONG** | release-gated, but **no PR or main lane** |
| **Redis/Valkey** | **WEAK** | committed suites, Level-3 claims, **no automated execution anywhere** |
| **RabbitMQ/LavinMQ** | **WEAK** | as above, 48 integration test functions run by nothing |
| **Fleet / multi-target** | **WEAKEST** | a real four-service suite exists and is gated by nothing; no hosted lane; leaf/fleet equivalence tests exist for **Kubernetes only** |

**A D4 service can have poor release-gate maturity and a D3 service can have none.** Kafka is D4 and
has no PR lane; Redis is D3 and has no lane at all.

## 7. Validation coverage matrix

`unit` = hermetic Go tests in `make check`. `hermetic diagnosis` = a cross-package corpus in
`test/diagnosis`. `mutation` = a committed `scripts/phase*-mutations.sh` plants in that area.
`local integration` = a `make integration-*` target. `hosted PR CI` = `ci.yml` or `kubernetes.yml`
on `pull_request`.

| Row | unit | hermetic diagnosis | mutation | local integration | real product | compat product | hosted PR CI | scheduled CI | release gate | leaf/fleet equiv | shareable/redaction | deterministic output |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **DNS** | STRONG | STRONG | STRONG | N/A | STRONG | N/A | STRONG | ABSENT | PARTIAL | N/A | STRONG | STRONG |
| **TCP** | STRONG | STRONG | STRONG | N/A | STRONG | N/A | STRONG | ABSENT | PARTIAL | N/A | STRONG | STRONG |
| **TLS** | STRONG | STRONG | STRONG | N/A | STRONG | N/A | STRONG | ABSENT | PARTIAL | N/A | STRONG | STRONG |
| **Kafka** | STRONG | STRONG | STRONG | STRONG | STRONG | STRONG | **ABSENT** | ABSENT | **STRONG** | ABSENT | STRONG | STRONG |
| **Redpanda** | N/A | ABSENT | ABSENT | STRONG | STRONG | STRONG | **ABSENT** | ABSENT | **STRONG** | ABSENT | PARTIAL | STRONG |
| **PostgreSQL** | STRONG | STRONG | STRONG | STRONG | STRONG | N/A | **ABSENT** | ABSENT | **STRONG** | ABSENT | STRONG | STRONG |
| **Redis** | STRONG | **ABSENT** | PARTIAL | STRONG | STRONG | STRONG | **ABSENT** | **ABSENT** | **ABSENT** | **ABSENT** | STRONG | STRONG |
| **Valkey** | N/A | ABSENT | ABSENT | STRONG | STRONG | STRONG | **ABSENT** | **ABSENT** | **ABSENT** | ABSENT | PARTIAL | STRONG |
| **RabbitMQ** | STRONG | **ABSENT** | PARTIAL | STRONG | STRONG | STRONG | **ABSENT** | **ABSENT** | **ABSENT** | **ABSENT** | STRONG | STRONG |
| **LavinMQ** | N/A | ABSENT | ABSENT | STRONG | STRONG | STRONG | **ABSENT** | **ABSENT** | **ABSENT** | ABSENT | PARTIAL | STRONG |
| **Kubernetes** | STRONG | ABSENT | STRONG | STRONG | STRONG | STRONG | **STRONG** | **STRONG** | **STRONG** | **STRONG** | STRONG | STRONG |
| **Fleet/multi-target** | STRONG | N/A | PARTIAL | STRONG | STRONG | N/A | **ABSENT** | **ABSENT** | **ABSENT** | **PARTIAL** | STRONG | STRONG |

Three facts the matrix makes visible that a per-service view hides:

- **`hosted PR CI` is ABSENT for every service except Kubernetes.** No integration suite runs on any
  pull request. Kubernetes is the sole exception and must not be read as evidence for the others.
- **`hermetic diagnosis` is ABSENT for Redis and RabbitMQ.** The `test/diagnosis` corpora are
  `corpus()`, `kafkaCorpus()` and `pgCorpus()` only — Phase 13.1B measured the same thing when eight
  call-site mutations survived a table-only guard set. So Redis and RabbitMQ are weak on the
  hermetic axis **and** the integration axis simultaneously.
- **`leaf/fleet equivalence` is ABSENT everywhere except Kubernetes** (`test/fleet/` holds
  `kubernetes_test.go` and `kubernetesleaf_test.go` and nothing else).

## 8. Release-gate audit

| Gate | Present | Blocks publication |
|---|---|---|
| Go unit / vet / lint / build | ✓ `ci.yml` | **no** — a separate workflow; `release-oci.yml` does not need it |
| Reproducibility, staging, cosign, SBOM, provenance | ✓ `oci-stage-verify.yml` | ✓ |
| Integration — postgres, kafka, redpanda | ✓ | ✓ via `stage-and-verify` |
| Kubernetes real cluster, 2 lanes | ✓ | ✓ via `stage-and-verify` **and** `publish` |
| **Integration — redis, valkey, rabbitmq, lavinmq** | **✗** | **no** |
| **Multi-target / fleet** | **✗** | **no** |
| Mutation suites | ✗ | no — developer-invoked only |

**Can a release succeed while these are broken?** Answered from `needs:` edges, not from intent:

| Broken thing | Release still publishes? |
|---|---|
| Redis BASIC | **YES** |
| Valkey compatibility | **YES** |
| RabbitMQ BASIC | **YES** |
| LavinMQ compatibility | **YES** |
| Multi-target execution | **YES** |
| Kafka compatibility | no |
| Redpanda compatibility | no |
| PostgreSQL | no |
| Kubernetes | no |

## 9. §29 — the special question, answered exactly

> *If a one-line production regression broke Redis BASIC today, could main CI still be green? Could a
> release still be published?*

**Main CI: green, if the regression is one only a real server reveals.** `ci.yml` runs `make check`,
which excludes every `//go:build integration` suite. A regression in `internal/diagnosis/redis` is
still caught by the hermetic unit and classification tests inside `make check`; a regression in
`internal/adapter/redis` or `internal/adapter/redis/wire` whose only symptom is a real RESP exchange
is **not**. That distinction is stated precisely rather than overclaimed.

**Release: published.** `redis` appears in no `needs:` edge.

| Service | Main CI green despite a real-server regression? | Release still publishes? |
|---|---|---|
| Redis | **YES** | **YES** |
| Valkey | **YES** | **YES** |
| RabbitMQ | **YES** | **YES** |
| LavinMQ | **YES** | **YES** |
| Kafka | **YES** | no — release gate catches it |
| Redpanda | **YES** | no |
| PostgreSQL | **YES** | no |

**Main CI is green for all seven.** The release gate is the only automated protection any service
has, and four services plus the fleet have none.

## 10. §30 — the fleet question, answered exactly

> *Can a change break mixed-service `svcdoctor run --config` while every service-specific leaf test
> stays green?*

**Yes.**

- `internal/fleet/run` is service-agnostic by construction — it *"contains no service name at all"* —
  so a leaf test cannot exercise scheduling, aggregation or the `RunReport` envelope.
- The hermetic guards that do cover it (`internal/fleet/run/{execute,isolation,stress}_test.go`,
  `test/fleet/`) are in `make check`, so unit-level regressions are caught.
- What is **not** caught is a real mixed-service composition failure. `test/integration/multitarget`
  exists and is exactly that test — `TestFourServicesThroughOneRun`,
  `TestARemoteRefusalDoesNotDisturbOtherTargets`, `TestDuplicateEndpointsAreTwoExecutions`,
  `TestAMissingCredentialIsNotAnAuthenticationFailure`, `TestShareableAggregateAcrossServices` — and
  it runs in **no** lane. `make integration-multitarget` needs postgres, kafka, redis and rabbitmq
  fixtures simultaneously.
- **Leaf/fleet equivalence tests exist for Kubernetes only.** Equivalence is not inferred from shared
  code anywhere else.

Severity: the fleet is a released CLI surface (`svcdoctor run --config`, Phase 9.1B) whose only
end-to-end validation is a local command a maintainer must remember.

## 11. §31 — the mutation question, answered exactly

**18 committed harnesses, 421 plants.** Every one uses `mktemp` backup plus a sha256 comparison
**scoped to its own declared `FILES` list**. No harness invokes `git` — the only mention is Phase
13.1C's comment saying it does not.

> *How many harnesses can claim reproducible plants, zero survivors, and independently verified
> restoration?*

**One: `scripts/phase131c-mutations.sh`.** It is the only harness that (a) verifies the whole working
tree with a `find` that knows nothing about `FILES`, and (b) refuses to plant into an undeclared
file. The other **17** verify only what they already know about — the exact blind spot that let Phase
13.1B leave two plants in the tree while reporting success.

There is also **one phase with mutation evidence and no committed harness: 13.1B**, already recorded
in `docs/BACKLOG.md`.

> *Is standardizing that immediately worth more than service release coverage?*

**No**, and the reason is about who is exposed. A mutation harness is a developer-time tool invoked
deliberately; its failure mode is a leftover plant in an uncommitted tree, which is loud, local, and
was caught every time it happened — four times, by something other than the harness. A missing
release gate's failure mode is a **published artifact** carrying a compatibility claim nobody
re-verified, and the exposed party is a user. Same class of defect, two very different blast radii.

## 12. Redis/Valkey diagnostic intelligence — reassessment

**Previous decision: DEFER (ADR 0088, reaffirmed 10.7A and 13.0). New decision: DEFER, unchanged,
with a sharper reason.**

The old summary — *"arbitrary Redis ERR prose is insufficient authority"* — is **true but not the
binding constraint**, and the audit corrects that emphasis. `internal/adapter/redis/wire/errors.go`
already normalizes a **closed set** of prefixes (`LOADING`, `MASTERDOWN`, `BUSY`, `OOM`, `READONLY`,
`MISCONF`, `NOPERM`, `WRONGPASS`, `NOAUTH`, `DENIED`, `MOVED`, `ASK`, …), matched on prefix rather
than text *precisely because* Redis and Valkey parameterize the message but not the prefix. Those
conditions are structurally authoritative.

Three measured reasons to keep deferring:

1. **The fact is already published.** `redis.error_prefix` is a canonical JSON attribute, and
   `detailWithNamedCondition` already renders *"The condition the endpoint named was LOADING."* into
   the finding. A per-condition code would restate an attribute the report already carries — the same
   argument ADR 0040 §20 used to refuse a PostgreSQL role finding in Phase 10.3.
2. **Fixture determinism**, which is the real blocker and the one Phase 10.7A named: `LOADING` is a
   restart race and `MASTERDOWN` needs a replica plus a severed link. **Redis also has no
   `test/diagnosis` corpus and no CI lane**, so there is nowhere to prove such a rule stays true.
3. **One service, against a gap affecting four plus the fleet.**

Generic `ERR` remains authority for nothing — Redis interpolates caller arguments into it. That rule
is preserved exactly.

**Evidence has not materially changed since 13.0**, and the reason to defer is now *upstream
dependency* rather than *doubt*: Candidate A builds the Redis and Valkey fixtures in CI that a future
Redis DI phase would need.

## 13. RabbitMQ/LavinMQ diagnostic intelligence — reassessment

**Previous decision: DEFER (ADR 0088). New decision: DEFER, unchanged.**

Phase 10.6A weighed the candidate set explicitly and rejected essentially all of it as **already
built**: vhost refused vs absent (two codes), mechanism not offered, the three credential codes,
capacity ceiling on open. What it deferred — a connection-start scope aggregate across addresses — is
*"structurally yes, never produced"*, i.e. blocked on a graph shape no producer makes, which is the
same structural refusal PostgreSQL multi-endpoint role reasoning carries.

Phase 10.8B then consumed the remaining real opportunity: `rabbitmq.close_outcome` distinguishes
`NODE_CONNECTION_LIMIT`, `VHOST_CONNECTION_LIMIT` and `USER_CONNECTION_LIMIT`, and that scope is
already preserved in operator-facing output.

Scope discipline holds: **no management API, no `rabbitmqctl`, no cluster membership, no queue or
exchange topology, no node metrics, no logs.** Nothing in this audit proposes moving that line.
RabbitMQ has 11 codes to Kafka's 15; that is not a reason to build, and it is explicitly not used as
one.

## 14. Kafka / PostgreSQL further depth — reassessment

**DEFER both.** Phase 10.7A rejected the strongest Kafka candidate (partition availability) as
**Class 3 acquisition** — a topic-scoped Metadata request with an unbounded response and a possible
new ACL requirement — and it remains rejected. Phase 11.0 swept 29 candidates across both services
and admitted zero. PostgreSQL's remaining depth is behind SQL, which PostgreSQL BASIC's freeze
refuses and this audit does not reopen.

Both are **D4** already, and both have **no PR or main CI lane** — their marginal need is trust, not
depth.

## 15. Kubernetes — reassessment

**Previous decision: BUILD NOTHING NOW (13.0). New decision: DEFER — unchanged.**

Scope stays Service, Pod, EndpointSlice with four codes. Events, logs, metrics, NetworkPolicy,
Gateway, Ingress, Deployments, StatefulSets, probes, mesh and eBPF are each either a different
product's job or require authority a client vantage does not have. Nothing in this audit is a strong
client-vantage argument for any of them, and ease of implementation is not admitted as one.

One genuine open item is **recorded, not promoted**: a `401`, an unreachable API server and a `5xx`
all exit 0, because ADR 0094 §10.4 gives a `401` no Kubernetes code. Closing it needs a fifth code
under ADR 0094 §7 — a claim change with its own phase. It is already in the backlog as C5.

Kubernetes is the **only** service with PR, main, scheduled and release-gate coverage. It is the
model for Candidate A, not a place to add features.

## 16. New service adapter — reassessment

**DEFER, none admitted.** Phase 13.0 found MySQL/MariaDB the best of the set and still deferred it,
on the ground that a sixth adapter *"would multiply the classification gap rather than close it."*
That specific argument expired when 13.1C closed the gap — so the audit re-derived it rather than
reusing it, and the conclusion is the same for a **different** reason: **a sixth adapter would be a
sixth ungated service.** Four of five current adapters' compatibility products already run in no PR
lane. Adding breadth on top of that widens the very asymmetry this phase exists to close.

HTTP stays rejected as duplication of `curl`.

## 17. Planner trigger — reassessment

Measured, not recalled.

| Trigger | Result | Evidence |
|---|---|---|
| 1 — every production recommendation classified, zero-legacy guard green | **PASS** | 73/73; 47 files, 7 packages, 0 unclassified constructors |
| 2 — ≥1 `SelfCollectable: true` `NEXT_EVIDENCE` that is **not** merely rerun/retry/larger budget | **FAIL** | exactly 2 exist and both read *"Re-run with a larger execution budget…"* |
| 3 — that recommendation sits on a finding carrying a `Discriminator` | **FAIL** | neither `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` nor `POSTGRES_ADMISSION_SCOPE` carries one; the only production discriminator is on `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE`, whose advice is **not** self-collectable |

**PLANNER: KEEP DEFERRED.** Trigger 1 flipping to PASS is exactly what Phase 13.1 was expected to do
and is not on its own a reason to reopen. Nothing was manufactured to satisfy 2 or 3.

## 18. Evidence relations — reassessment

**KEEP DEFERRED.** Production callers re-counted: `.Contradict(` **0**, `.Miss(` **0**, `.Block(`
**0**, `.Support(` **3**. Unchanged since Phase 10.5A / ADR 0087, and no diagnostic added since needs
a relation that `EvidenceRefs` plus finding structure cannot express. `EvidenceRefs` and semantic
relation edges are not conflated here: the former is a citation surface, the latter a typed basis,
and only the former has producers.

## 19. Candidate scorecard

1–5. For **maintenance burden** and **scope-creep risk**, **5 = bad** (high burden / high risk);
every other dimension **5 = good**. Arithmetic is shown but does not decide; §20 does.

| Candidate | user value | risk reduction | differentiation | evidence readiness | boundedness | validation feasibility | maint. burden (5=bad) | scope creep (5=bad) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **A** service integration CI | 4 | **5** | 3 | **5** | **5** | **5** | 3 | **1** |
| **B** new fleet validation capability | 3 | 4 | 3 | 3 | 3 | 3 | 3 | 3 |
| **C** mutation harness hardening | 2 | 3 | 2 | **5** | 4 | 4 | 2 | 2 |
| **D** Redis/Valkey DI | 3 | 2 | 3 | 2 | 3 | **1** | 3 | 4 |
| **E** RabbitMQ/LavinMQ DI | 2 | 2 | 3 | **1** | 3 | 2 | 3 | 4 |
| **F** Kafka/PostgreSQL depth | 2 | 2 | 4 | **1** | 2 | 2 | 3 | **5** |
| **G** Kubernetes expansion | 2 | 1 | **1** | 2 | 2 | 3 | 4 | **5** |
| **H** new adapter | 3 | 1 | 2 | 2 | **1** | 2 | **5** | **5** |
| **I** planner | 2 | 1 | 4 | **1** | **1** | 2 | 4 | **5** |
| **J** evidence relations | 1 | 1 | 2 | **1** | 3 | 3 | 2 | 3 |

A wins on the dimensions that matter most at this maturity — risk reduction, evidence readiness,
boundedness, validation feasibility — and is the only candidate with the lowest possible
scope-creep risk, because it adds no product surface at all.

## 20. BUILD / DEFER / REJECT

| Candidate | Verdict | Reason |
|---|---|---|
| **A — service integration CI coverage** | **BUILD** | Five of nine integration targets run in zero workflows; four Level-3 compatibility claims and the whole `run --config` path are unguarded at release |
| **B — new fleet validation capability** | **DEFER** | The mixed-service suite already exists and is ungated. Gate what exists before writing more; new tests that run nowhere add no confidence. Reopen once A has landed |
| **C — mutation harness hardening** | **DEFER** | Real debt — 17 of 18 harnesses verify only their own write-set — but it is developer-time infrastructure whose failure mode is a local leftover plant, not a published artifact |
| **D — Redis/Valkey DI** | **DEFER** | Unchanged. The condition is already machine-readable and already rendered; the binding constraint is fixture determinism, which A improves |
| **E — RabbitMQ/LavinMQ DI** | **DEFER** | Unchanged. 10.6A rejected the candidate set as already built; 10.8B consumed the remainder |
| **F — Kafka/PostgreSQL further depth** | **DEFER** | 10.7A and 11.0 swept both and admitted nothing reachable; the best Kafka candidate needs Class 3 acquisition |
| **G — Kubernetes expansion** | **DEFER** | Boundary unchanged; the one genuine gap (a `401` exits 0) is a claim change needing ADR 0094 §7 |
| **H — new service adapter** | **DEFER** | Would add a sixth ungated service while four of five are already ungated |
| **I — planner** | **DEFER** | Triggers 2 and 3 FAIL |
| **J — evidence relations** | **DEFER** | Still zero producers |

**One BUILD.** Nothing is rejected outright: every deferred candidate remains a legitimate idea with
a recorded reopen condition, and calling a live idea REJECT would misrepresent the record.

## 21. Primary next phase

### Phase 14.0 — hosted and release-gating integration coverage for the five uncovered suites

**Why now.** Phase 13.0 ranked it second and Phase 13.1 finished first. Independent workflow
measurement confirms the gap is unchanged: `redis`, `valkey`, `rabbitmq`, `lavinmq` and
`multitarget` appear zero times across all six workflow files, while `docs/COMPATIBILITY.md` makes
Level-3 claims for four of those platforms.

**Why before the alternatives.** Every product-depth candidate has been deferred by at least one
prior audit on its own merits, and the strongest of them (Redis transient state) is blocked on
fixture determinism that this phase improves. Mutation hardening is real debt with a smaller blast
radius. This is the only candidate where the failure it prevents is *user-visible and irreversible*:
a published release.

**Exact gap closed.** Redis, Valkey, RabbitMQ, LavinMQ and multi-target gain automated execution, and
release publication depends on them.

**Explicitly out of scope.** No new finding code, rule, severity, claim or recommendation. No adapter
or wire change. No new service. No Redis condition findings. No RabbitMQ management API. No
Kubernetes change. No mutation-harness migration. No new fleet *tests* — the existing suites are
gated, not extended. If a suite proves flaky, the honest outcome is a narrower lane or a scheduled
one, **never a weakened assertion**.

**Observable completion criterion.** All three must hold:

1. `redis`, `valkey`, `rabbitmq`, `lavinmq` and `multitarget` each appear in at least one workflow's
   execution path, measurable by the same grep this audit ran.
2. `release-oci.yml`'s `stage-and-verify` or `publish` job cannot start unless those suites passed —
   verifiable from the `needs:` graph, the way `TestOCIPublicationCannotStartBeforeLinuxIntegration`
   already verifies the existing edge.
3. A deliberately broken Redis or RabbitMQ BASIC path fails the lane, proven by planting the break
   and observing the failure — the non-vacuity proof this repository applies to every guard.

The phase should be **frozen as a contract first** (lane model, trigger placement, flake policy,
runtime budget), because §18's cost question — PR versus scheduled versus release-only — is a
judgement about CI economics that deserves deciding before YAML is written.

## 22. Secondary follow-up

**Candidate C — mutation harness hardening**, carrying Phase 13.1C's two properties to the other 17
harnesses: whole-tree restoration verification independent of the declared write-set, and refusal to
plant into an undeclared file.

**What would change this.** If Phase 14.0's lanes prove that the existing Redis/RabbitMQ integration
suites are *thin* rather than merely ungated — that is, if a planted break survives them — then
deepening those suites outranks mutation hygiene, and Candidate B or D moves up instead.

## 23. DO NOT BUILD NEXT

| Item | Why not |
|---|---|
| **Planner / next-best-evidence** | Triggers 2 and 3 FAIL. Trigger 1 flipping is what 13.1 was for and is not a reason on its own. Do not manufacture a qualifying recommendation |
| **Evidence relations** (`Contradict`, `Miss`, `Block`) | Still zero producers. `EvidenceRefs` already serves every current claim; do not confuse the two |
| **Kubernetes scope expansion** | Events, logs, metrics, NetworkPolicy, Gateway, Ingress, workloads, probes, mesh, eBPF — each needs authority a client vantage lacks or duplicates another tool. Ease of implementation is not an argument |
| **Redis condition findings** | The prefix is already canonical JSON and already rendered in the finding detail; `LOADING` and `MASTERDOWN` cannot be produced deterministically in a fixture. Generic `ERR` is authority for nothing |
| **RabbitMQ management API / `rabbitmqctl` / topology** | Outside AMQP 0-9-1 direct-endpoint authority. ADR 0096's scope test refuses it, and no evidence here reverses that |
| **A sixth service adapter** | Would add a sixth ungated service while four of five are ungated |
| **SQL-based PostgreSQL health inspection** | PostgreSQL BASIC is feature-frozen; reopening needs the recorded condition, which nothing has met |
| **Weakening any assertion to make a new CI lane pass** | A green lane that asserts less than the local suite is worse than no lane, because it converts an absence of evidence into an appearance of it |

## 24. Risks and uncertainties

**Risks in choosing A.**

- **Flake risk is real and unquantified.** Four fixtures must start simultaneously for the
  multi-target lane. This audit measured that the suites exist and pass locally; it did **not** run
  them on a GitHub-hosted runner, so hosted runtime and flake behaviour are genuinely unknown. That
  is the single largest uncertainty in the recommendation.
- **Runtime cost.** `integration-multitarget` brings up PostgreSQL, Kafka, Redis and RabbitMQ
  together. A release already runs three suites plus two Kubernetes lanes; adding five more could
  make the release gate materially slower. A layered model — PR-cheap, release-complete — is likely
  right, and the contract freeze should decide it rather than the implementation.
- **arm64 evidence is absent for every service lane.** GitHub-hosted Linux runners are amd64; the
  release publishes multi-arch images. This audit does not claim a fix and records it as a known
  limit of whatever A builds.

**Uncertainties recorded rather than resolved.**

- Whether the existing Redis/RabbitMQ suites are *strong enough* to be worth gating is not proven
  here. Criterion 3 in §21 exists precisely to find out.
- The Kubernetes `401`-exits-0 gap (C5) remains open and this phase does not schedule it.
- Phase 13.1B's missing harness stays missing; C would close it.

## 25. Source references

| Claim | Source |
|---|---|
| Release integration matrix is 3 suites | `.github/workflows/release-oci.yml:201` |
| Publication depends on it | `release-oci.yml:362`, `:394` (`needs:`) |
| Main/PR lane runs only `make check` | `.github/workflows/ci.yml`, job `check` |
| `make check` excludes integration | `Makefile` `test:` → `go test ./...`; `//go:build integration`; `go test ./test/integration/...` matches no packages |
| Nine integration targets | `Makefile:173,229,283,313,372,501,538,565,649` |
| Level-3 claims for Redis/Valkey/RabbitMQ/LavinMQ | `docs/COMPATIBILITY.md` |
| 13.0 ranked this gap second | `docs/validation/PHASE130_PRODUCT_DIAGNOSTIC_ROADMAP_AUDIT.md` §22, §"SECONDARY — C3", `:505`, `:684` |
| Redis/RabbitMQ DI deferred | `PHASE106A…md` (ADR 0088), `PHASE107A…md` §4.3 |
| Planner deferred | `PHASE110…md` (ADR 0092) |
| Evidence relations deferred | `PHASE105A…md` (ADR 0087) |
| Redis prefix vocabulary is closed | `internal/adapter/redis/wire/errors.go` |
| Redis condition already rendered | `internal/diagnosis/redis/ping.go` `detailWithNamedCondition` |
| RabbitMQ close-outcome vocabulary | `internal/service/rabbitmq/vocabulary.go:143-216` |
| Only 13.1C verifies the whole tree | `scripts/phase131c-mutations.sh` `tree_hash`; 17 others lack it |
| Fleet equivalence is Kubernetes-only | `test/fleet/` |
| Hermetic corpora are Kafka/PG/generic | `test/diagnosis` — `corpus()`, `kafkaCorpus()`, `pgCorpus()` |

## 26. Validation

| | Result |
|---|---|
| `make check` | **GREEN** before and after |
| `git diff --check` | **CLEAN** |
| Production / test / script / workflow / dependency changes | **0** |
| Mutation or integration suites executed | **none** — static inspection was sufficient, so no source was mutated and no restoration was required |
| ADRs created or modified | **0** — roadmap prioritization is not an architecture decision, and no source contradicts a durable ADR |

## 27. Open blockers

**None.**
