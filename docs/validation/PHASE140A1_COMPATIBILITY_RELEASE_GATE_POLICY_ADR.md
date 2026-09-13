# Phase 14.0A.1 — Compatibility release-gate policy ADR and contract reconciliation

- **Phase:** 14.0A.1 (ADR closure, release-policy freeze, contract reconciliation; **no**
  production, test, CI, script or fixture change)
- **Baseline:** `07b4f03999d099ce16ef8729f4d0566ee1d29295`, equal to `origin/main`. The working tree
  carried Phase 14.0A's two still-uncommitted documentation files and nothing else, verified before
  any edit; `make check` green
- **Why it exists:** Phase 14.0A concluded **ADR: REQUIRED** and **Phase 14.0B: AUTHORIZED BY
  CONTRACT** in the same decision block. Its governing contract did not permit that pair
- **Outcome:** **ADR 0098 Accepted.** The contradiction is corrected in place, the RabbitMQ
  tree-neutrality prerequisite is frozen, 14.0B's file scope gains one narrow fixture-hygiene
  surface, and **Phase 14.0B is authorized — by ADR 0098**
- **Blockers:** none open

---

## 1. Baseline

```
HEAD        07b4f03999d099ce16ef8729f4d0566ee1d29295  docs(roadmap): freeze post-13.1 investment direction
origin/main 07b4f03999d099ce16ef8729f4d0566ee1d29295
working tree  M docs/BACKLOG.md
              ? docs/validation/PHASE140A_INTEGRATION_CI_RELEASE_GATE_CONTRACT_FREEZE.md
make check  GREEN
```

The tree was **not** clean, and that is expected rather than tolerated: Phase 14.0A's output is
uncommitted, this phase's brief names that case explicitly in its baseline definition, and §17 of
the brief requires editing a file that exists only in that uncommitted state. What was verified
before editing is the thing that actually matters — **the dirty tree is exactly Phase 14.0A's two
documentation files and contains no non-documentation path.**

## 2. The contradiction, stated plainly

Phase 14.0A ended with:

```
ADR:            REQUIRED
PHASE 14.0B:    AUTHORIZED BY CONTRACT
```

Its governing contract said the opposite: *if the Level-3 release-gate policy requires an ADR and
that ADR is unresolved, Phase 14.0B is BLOCKED.*

**The reasoning behind the error was not arbitrary, which is why it is worth recording.** 14.0A
argued that the ADR was needed only for the *general* cross-service policy, that the five concrete
lanes depend on ADR 0062's job graph and ADR 0095's gate precedent instead, and therefore that
14.0B could proceed while the general policy was frozen separately. That engineering judgement is
defensible on its merits.

**It is still the wrong answer**, for a reason that has nothing to do with its merits: the stop
condition was about the ADR being unresolved, not about whether the next phase happened to consume
it. A phase does not get to grant itself an exception to its own gate because the gate looks
avoidable in hindsight — that is precisely the behaviour stop conditions exist to prevent, and
reading one narrowly until it stops applying is how a contract stops meaning anything.

**Corrected sequence, recorded rather than rewritten:**

| Point in time | ADR | Phase 14.0B |
|---|---|---|
| End of Phase 14.0A | **REQUIRED, unresolved** | **BLOCKED** |
| End of Phase 14.0A.1 | **ADR 0098, Accepted** | **AUTHORIZED** |

The 14.0A record is corrected **in place with the original text preserved and marked**, not
rewritten to look as though the ADR existed during 14.0A. Five sections carry the correction: the
header, §22, §33, §34's stop-condition table and §35's freeze table.

## 3. The policy — ADR 0098

**ADMITTED**, in all three parts the brief separates:

| Part | Decision |
|---|---|
| The Level-3 ⇒ release-gate rule | **ADMITTED** |
| The real-product requirement | **ADMITTED** |
| The release-gating requirement | **ADMITTED** |

> If svcdoctor publicly labels a product/version combination **Level 3 — SUPPORTED BASIC**, release
> publication must be gated by a repeatable **real-product** integration path that exercises the
> BASIC compatibility claim for that combination.

### 3.1 Why it is one clause, not a new regime

`docs/COMPATIBILITY.md` §6 already reads: *"To Level 3: Level 2, plus a committed repeatable
fixture with its own `make` target, plus the known differences written down here."*

**The bar already required a `make` target. Nothing said the target had to run.** That is the entire
gap Phase 13.2 measured, and the ADR closes it by appending four words to an existing rule rather
than by inventing a grading system. Framing it that way is not cosmetic: it means no row's meaning
changes, and no existing claim is re-derived.

### 3.2 How it is bounded

The brief listed six over-readings to refuse; the ADR refuses seven. It does **not** claim that every
compatibility test runs on every PR, that every supported version runs in every release, that the
newest upstream release is automatically supported, that a passing lane proves all product
functionality, that Level 3 is a production certification, that compatibility holds on an
architecture the lane did not run on, or that two Level-3 rows have equal test depth.

**Version semantics are inherited, not written.** `docs/COMPATIBILITY.md` already says per family
that *"svcdoctor does no version arithmetic, so it makes no prediction about any other release."*
ADR 0098 §2.4 takes that unchanged: `Redis 8.2.1 — Level 3` obliges a lane against **8.2.1** and
obliges nothing about any other 8.x. **No support is broadened by this phase.**

**"Real product"** means the actual supported server or the explicitly named compatibility
implementation, over its real wire protocol. Mocks, fake servers, hermetic fixtures, constructed
findings and unit tests remain valuable — they are most of this repository's evidence — and they do
not satisfy this rule alone. Phase 13.2 measured the class of defect that survives them: a
regression in `internal/adapter/redis/wire` whose only symptom is a real RESP exchange.

**"Gates release publication"** is defined as a property of the `needs:` graph — the publication DAG
cannot reach the publication operation when the required result fails, is cancelled, or does not
complete. Explicitly **not** "a workflow contains a job with that name".

### 3.3 What was deliberately kept out

| Kept out | Why |
|---|---|
| Trigger frequency — cron, PR, main, dispatch, timeouts, runner image | CI economics decided on measured runtime; it belongs to the 14.0A/14.0B contract, not to architecture. ADR 0098 §2.7 fixes **one** edge: the release edge |
| Multi-target | A **product surface**, not a claim about a third-party product. Its release invariant is owned by ADR 0062's job graph and recorded in 14.0A §23. ADR 0098 §2.8 records the exclusion from the other side, as a permanent refusal rather than a deferral. **No second ADR was created** |
| Any compatibility level change | None is authorized and none was made |

## 4. RabbitMQ tree-neutrality — FROZEN

Phase 14.0A measured that `make integration-rabbitmq` **rewrites a committed file**:

```
 M test/integration/rabbitmq/env/__pycache__/groundtruth.cpython-314.pyc
```

Same length, different bytes. It was restored byte-identically during that audit (SHA-256 verified).

**Frozen requirement:**

> **RabbitMQ hosted gating is not complete until `make integration-rabbitmq` is tree-neutral** —
> clean tree before the suite, clean tree after it, with **no Git restoration required**.

Phase 14.0B may not add RabbitMQ as a hosted or release gate while accepting a suite that mutates
tracked repository bytes as normal behaviour. A gate whose own execution dirties the repository
cannot support a cleanliness or reproducibility assertion, which is exactly what a release gate is
for.

**The remedy is not prescribed.** 14.0A inspected the symptom, not the cause. Stop tracking the
bytecode, prevent its generation, add ignore protection — candidates, not instructions. **The
invariant is frozen; the fix is 14.0B's to derive from source.**

## 5. Phase 14.0B file-scope reconciliation

14.0A's allowed surface gains exactly one thing, for exactly one purpose:

| Added | Purpose |
|---|---|
| `test/integration/rabbitmq/**` | **solely** making the suite tree-neutral |
| `.gitignore` or the nearest appropriate ignore file | same |

**This authorizes nothing else.** Not RabbitMQ protocol semantics, not weakening or removing an
integration assertion, not reducing test cases, not production code. **Any behavioural test
weakening is a blocker**, not a trade for a green lane — the same rule ADR 0098 §2.5 applies to
compatibility lanes generally.

## 6. Phase 14.0B tree-neutrality validation — frozen

Added to 14.0A §30's validation contract:

- Capture the repository file-hash state **before** the five-suite validation set and compare
  **after**.
- Require **no tracked file modified**, and no unexpected untracked generated fixture artifact.
- **`git stash`, `git checkout`, `git restore` and `git reset` may not satisfy it.** Restoring the
  tree to hide a mutating suite is the defect, not the fix.

## 7. How the policy lands on the current services

Compliance is about **existence and gating**, not about equal test depth — two Level-3 rows may be
backed by suites of very different size, and ADR 0098 §2.6 says so.

| Service | State after Phase 14.0B |
|---|---|
| **Kafka** | existing release gate sufficient — already in the release integration matrix |
| **Redpanda** | existing release gate sufficient |
| **PostgreSQL** | existing release gate sufficient |
| **Kubernetes** | existing release gate sufficient, under its own contract (ADR 0095) — two lanes, both `needs:`-blocking |
| **Redis** | **requires Phase 14.0B** |
| **Valkey** | **requires Phase 14.0B** |
| **RabbitMQ** | **requires Phase 14.0B + the tree-neutrality fix** |
| **LavinMQ** | **requires Phase 14.0B** |

**Four rows are non-compliant with ADR 0098 today**, and the ADR says so in its own §7 rather than
implying otherwise: a Level-3 row without a gating lane is permitted only as a recorded,
time-bounded exception with a named closing phase. That phase is 14.0B. **No row was downgraded**,
because the exception is recorded and bounded.

## 8. Phase 14.0B authorization test

| Condition | Result |
|---|---|
| ADR admitted | **PASS** — ADR 0098, Accepted |
| ADR indexed / documented | **PASS** — `docs/decisions/README.md` |
| 14.0A contradiction reconciled | **PASS** — five sections corrected in place, original text preserved |
| RabbitMQ tree-neutrality frozen | **PASS** — §4 |
| 14.0B allowed file scope reconciled | **PASS** — §5 |
| No production behaviour change required by contract | **PASS** — the only code the contract obliges is fixture hygiene |
| `make check` green | **PASS** |
| `git diff --check` clean | **PASS** |

**PHASE 14.0B: AUTHORIZED — by ADR 0098.**

## 9. Validation performed

| | Result |
|---|---|
| `make check` | **GREEN** before and after |
| `git diff --check` | **CLEAN** |
| Documentation, ADR-structure and claim guards | **PASS** |
| Production / test / workflow / script / fixture changes | **0** |
| Compatibility level changes | **0** |

**Omitted, and why:** integration suites, mutation suites, fuzz and `-race`. No Go file, workflow,
fixture, script or `Makefile` target changed, so each would re-measure code that did not move. The
runtime measurements this phase relies on were taken in Phase 14.0A and are not re-run, because
nothing they measured has changed.

**No commit, push, tag, merge, rebase, reset, cherry-pick, revert or stash was executed.** `HEAD`
and `origin/main` are unchanged at the baseline commit.

## 10. Open blockers

**None.**
