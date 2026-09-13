# ADR 0098 — A Level-3 compatibility claim requires a release-gating real-product lane

- **Status:** Accepted
- **Date:** 2026-09-13
- **Phase:** 14.0A.1 (policy freeze; no production code, no CI change, no dependency change)
- **Extends:** `docs/COMPATIBILITY.md` §6, whose Level-3 bar already requires *"a committed
  repeatable fixture with its own `make` target"*. This record adds one clause to that bar and
  changes nothing else about grading.
- **Generalizes:** ADR 0095 §2.3 (*a green lane protects a claim; it never creates one*) and §2.4's
  sentence that *"a version the pinned toolchain can no longer run is not repeatable and therefore
  no longer Level 3"* — both stated for Kubernetes, both true of every service.
- **Upholds:** ADR 0062 §12–§21c (the release pipeline and its ordering) and ADR 0076 §2.3's
  required-artifact model. It adds no job, no trigger and no artifact.
- **Amends:** nothing. No existing rule is reversed.

---

## 1. Context

Phase 13.2 measured the repository against its own published claims and found them decoupled.
`docs/COMPATIBILITY.md` grades **Redis 8.2.1, Valkey 8.1.1, RabbitMQ (3.13.7 / 4.0.9 / 4.2.0) and
LavinMQ 2.3.0** at **Level 3 — SUPPORTED BASIC**. Each has the committed fixture and `make` target
§6 requires — `make integration-redis`, `integration-valkey`, `integration-rabbitmq`,
`integration-lavinmq`, together 76 integration test functions.

**Nothing ran them.** All five uncovered integration targets appeared zero times across all six
workflow files, and `release-oci.yml`'s integration matrix was `[postgres, kafka, redpanda]`. A
release could therefore publish an artifact carrying four Level-3 claims that no automation had
re-verified for that commit. `internal/cli/docsclaims_test.go` enforces that a Level-3 row
corresponds to a real run that *happened*; nothing could enforce that the run still *passes*.

Phase 14.0A froze the concrete CI contract that closes it. That contract is service-specific and
lives in its validation record. **This record exists because the underlying rule is not.** It binds
every service adapter svcdoctor has and every one it gains, so it is a decision rather than a phase
detail — the test ADR 0096 §2.2 applies to scope proposals, applied here to release policy.

Phase 14.0A identified the rule as ADR-worthy, could not create the ADR inside its own file scope,
and — reading its governing contract correctly — left Phase 14.0B **blocked** on it. This is the
resolution.

## 2. Decision

### 2.1 The rule

> **If svcdoctor publicly labels a product/version combination Level 3 — SUPPORTED BASIC, release
> publication must be gated by a repeatable real-product integration path that exercises the BASIC
> compatibility claim for that combination.**

It is one added clause to the `docs/COMPATIBILITY.md` §6 bar, which becomes:

> **To Level 3**: Level 2, plus a committed repeatable fixture with its own `make` target, plus the
> known differences written down here, **plus that fixture gating release publication**.

The rule is prospective and applies to every service adapter — existing, and any future one.

### 2.2 "Real product" means the actual implementation

A **real-product integration** executes against the actual supported server, or against the
explicitly named compatibility implementation, over its real wire protocol.

**These do not satisfy this rule on their own**, however good they are: mocks, fake or scripted
servers, hermetic protocol fixtures, directly constructed findings, unit tests, and golden corpora.

That is not a judgement about their worth — they are the majority of this repository's evidence and
they catch most defects first. It is a statement about *what a compatibility claim is about*. A
claim that svcdoctor works with RabbitMQ 4.2.0 is a claim about RabbitMQ 4.2.0, and only RabbitMQ
4.2.0 can be the witness for it. Phase 13.2 measured the gap this closes precisely: a regression in
`internal/adapter/redis/wire` whose only symptom is a real RESP exchange passes every hermetic test
there is.

### 2.3 "Gates release publication" is a property of the dependency graph

**Gating means the release publication DAG cannot reach the publication operation when the required
compatibility result fails, is cancelled, or does not successfully complete.**

It explicitly does **not** mean that a workflow contains a job with a plausible name. A job that
runs beside publication and blocks nothing is decoration. The claim is checkable only against the
`needs:` edges, which is how `TestOCIPublicationCannotStartBeforeLinuxIntegration` already checks
the three suites that were gated before this record.

A gate that is satisfied through a matrix leg is a direct dependency of whatever `needs:` that
matrix job, and transitive through anything downstream of it. Both are admitted; what is not
admitted is an edge that does not exist.

### 2.4 Version semantics are unchanged, and deliberately narrow

`docs/COMPATIBILITY.md` already says it, per service family: **svcdoctor does no version
arithmetic, so it makes no prediction about any other release.** A row names an exact version;
"any other version" is Level 0.

This record inherits that unchanged. The lane must validate **the version or reference that actually
backs the row**. `Redis 8.2.1 — Level 3` obliges a lane against Redis 8.2.1, and obliges nothing
about any other 8.x. Advancing a pinned version is a pull request that moves the pin, re-runs the
lane and updates `docs/COMPATIBILITY.md` **in the same change** — ADR 0095 §2.4's mechanism, applied
generally.

**Nothing here broadens support.** A green lane still authorizes nothing (ADR 0095 §2.3): grading
requires a validation record, a `docs/COMPATIBILITY.md` update and a human, and this record adds a
fourth requirement to that list rather than removing any of the three.

### 2.5 Failure policy

When a Level-3 lane fails, the response is one of four, chosen explicitly and recorded:

1. **Fix svcdoctor** — the defect is ours.
2. **Fix the fixture or orchestration** — the test infrastructure is wrong, and it is repaired
   *without weakening an assertion*.
3. **Keep the previously validated version pinned** — the default, since pins are explicit.
4. **Downgrade or amend the compatibility claim** — the product is genuinely no longer supported at
   that version.

**Forbidden in all four cases:** `continue-on-error`, automatic retry to green, removing the release
dependency in order to publish, and silently reducing what the suite asserts.

**CI does not redefine compatibility.** A lane that is weakened until it passes converts an absence
of evidence into an appearance of it, which is worse than having no lane at all — the row still
claims Level 3 and now a green check appears to support it.

### 2.6 What this record does not claim

Stated explicitly, because each is a plausible over-reading:

- **Not** that every compatibility test runs on every pull request. Trigger frequency outside the
  release gate is a CI contract detail, not architecture — §2.7.
- **Not** that every supported version of a product runs in every release. Only the versions a row
  claims at Level 3.
- **Not** that the newest upstream release is automatically supported. Nothing discovers versions;
  a pin moves by a pull request.
- **Not** that a passing lane proves all product functionality. It proves the **BASIC journey**,
  which is what the row claims and no more.
- **Not** that Level 3 is a production certification.
- **Not** compatibility on any architecture the lane did not run on. A lane on hosted amd64 is
  evidence about amd64.
- **Not** equal test depth between services. Two rows at Level 3 may be backed by suites of very
  different size; the rule is about existence and gating, not about coverage parity.

### 2.7 Trigger frequency is not this record's business

Which events run a lane — pull request, main, schedule, dispatch — is a CI economics judgement made
on measured runtime, and it belongs to the phase contract that measures it. This record fixes one
edge only: **the release edge**. A service whose lane runs on every pull request and a service whose
lane runs only at release both satisfy this ADR.

### 2.8 Multi-target is not covered by this record

`svcdoctor run --config` is a **product surface**, not a compatibility claim about a third-party
product, and it is deliberately not forced into the Level-3 model. Its release invariant — that
publication is blocked unless a real mixed-service multi-target suite passes — is owned by ADR
0062's job graph and recorded in the Phase 14.0A contract. It needs no ADR of its own: it adds an
entry to a matrix publication already depends on and states nothing about grading.

## 3. Consequences

**Positive.**

- A public compatibility claim is tied to release evidence rather than to a maintainer's memory of a
  local run.
- A release cannot silently ship while a product path its own documentation calls SUPPORTED BASIC is
  known broken by its gate.
- A future adapter cannot reach Level 3 on local or manual evidence alone, which is the failure mode
  this repository has just measured on four platforms at once.
- The claim becomes falsifiable by machine: the `needs:` graph either reaches publication or it does
  not.

**Costs, named rather than minimised.**

- The release pipeline becomes broader and slower. Phase 14.0A measured the four new service lanes
  at 14 s, 17 s, 19 s and 117 s locally, which is small against the existing Kubernetes lanes — but
  it is not zero, and it grows with every future Level-3 row.
- **Fixture determinism becomes a release concern.** A flaky suite now blocks publication, and §2.5
  forbids the retry that would hide it. That pressure is intended, and it is the reason Phase 14.0A
  froze a tree-neutrality requirement for RabbitMQ before its lane may be called complete.
- Pinned product versions and image references need deliberate maintenance, because a pin nobody
  advances silently becomes a claim about an old release.
- Compatibility-claim updates and CI updates become operationally coupled: moving a pin is now a
  change to documentation and to a gate in one pull request.
- A product that becomes hard to run in CI now forces an explicit choice under §2.5 instead of
  quietly keeping its badge.

**Non-goals.** Every product version · every architecture · every feature beyond BASIC · every
trigger · automatic upstream compatibility discovery.

## 4. Rejected alternatives

**Leave the rule implicit in the Phase 14.0A contract.** It would bind four platforms today and be
forgotten by the sixth adapter — which is exactly how the current gap formed: `docs/COMPATIBILITY.md`
§6 already required a `make` target, and nothing said the target had to run.

**Require the lane on every pull request.** Conflates two different questions. Release gating is
about what may be published; trigger frequency is about developer feedback economics, and forcing
them together would make every new Level-3 row a pull-request tax and create pressure to avoid
grading honestly.

**Require it for Level 2 as well.** Level 2 is *"svcdoctor completed the BASIC journey against a
real instance"* — a recorded historical event, with no repeatability claim. Gating it would make
Level 2 and Level 3 the same grade, and Level 2's usefulness is precisely that it can be honest
about a one-off.

**Make a green lane promote a row automatically.** Refused, and it is the same refusal as ADR 0095
§2.3. Grading needs a record, a documentation update and a human; automation that promotes would let
a matrix edit manufacture a support claim.

**Allow hermetic suites to satisfy the rule.** They cannot witness the thing the claim is about.
Phase 13.2 measured the class of defect that survives them: a wire-level regression whose only
symptom is a real exchange.

## 5. Security implications

**None introduced, and one narrowed.** This record adds no credential, no network authority, no
secret and no permission. Phase 14.0A's contract freezes the lanes at `contents: read`, zero
repository secrets, and fixture credentials that are ephemeral, workflow-local and already committed
as non-sensitive values.

The narrowing: a Level-3 row now carries continuously re-verified evidence that the **credential
path** for that product still behaves as measured — the TLS-required credential policies for Redis
and RabbitMQ are exercised by the very suites this rule gates. A silent regression in a
credential-transport refusal is exactly the kind of defect that a hermetic test can miss and a real
server catches.

**No compatibility row changes on the strength of this record.** Nothing is promoted, nothing is
downgraded, and no product is upgraded.

## 6. Verification

`docs/validation/PHASE140A1_COMPATIBILITY_RELEASE_GATE_POLICY_ADR.md` is this record's phase report.
`docs/validation/PHASE140A_INTEGRATION_CI_RELEASE_GATE_CONTRACT_FREEZE.md` is the measured contract
it generalizes, including the runtime measurements, the release DAG and the five-lane trigger model.

The rule becomes enforced rather than remembered in **Phase 14.0B**, by extending
`TestOCIPublicationCannotStartBeforeLinuxIntegration` to the full suite set and adding the workflow
contract guards that fail if a suite leaves the release matrix, if `continue-on-error` appears, or if
the `needs:` edge is cut. Each needs a non-vacuity companion, as every guard in this repository
whose assertions are absences already does.

**This ADR is not self-enforcing and does not pretend to be.** Until 14.0B lands, the four rows it
names are non-compliant, and §7's first row says what that means.

## 7. Reopen conditions

| Item | Condition |
|---|---|
| A Level-3 row without a release-gating lane | **Permitted only as a recorded, time-bounded exception.** Redis, Valkey, RabbitMQ and LavinMQ are in exactly this state today, closing in Phase 14.0B. A row that stays non-compliant without a named closing phase must be downgraded instead |
| Level 2 gains a gating requirement | A measured case where a Level-2 row misled someone. None exists |
| Automatic promotion from a green lane | None. It is the refusal ADR 0095 §2.3 already made |
| Hermetic evidence satisfying the rule | A hermetic harness that provably exercises the real wire behaviour the claim is about — which would make it a real-product test under a different name |
| A product that cannot run in CI at all | Not a reopen: §2.5 already answers it. The claim is downgraded, or the row names the previously validated version and says the lane is historical |
| Trigger frequency | Never this record's business. §2.7 |
| Multi-target folded into this rule | None. §2.8 — it is a product surface, not a compatibility claim |
