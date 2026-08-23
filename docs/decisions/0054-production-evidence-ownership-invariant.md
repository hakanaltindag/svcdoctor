# ADR 0054: Evidence that can fail does not ship before something can explain it

## Status

**Accepted as policy. Enforcement is deferred and partial.**

**First applied in Phase 6.1b**, which implemented ADR 0053's generic
requested-target TLS owner *before* Phase 6.1c introduces the producer that makes
those outcomes reachable from a production run. Ordering, not cleanup: after
6.1b the owner exists and the producer is still not product-reachable; after
6.1c they become reachable together. That is §4 in practice.

**Enforced mechanically for Kafka as of Phase 6.1c-P2**, in two tests that
together are the closure test §5 asks for:

- `internal/diagnosis/kafka`'s `TestTheAuthorizedTableIsExactlyTheProducedOutcomes`
  holds a list of every outcome the four Kafka protocol producers can emit,
  derived by reading `internal/adapter/kafka`, and fails in **both** directions:
  a produced outcome with no owner, and an owner for an outcome no producer
  emits.
- `test/security/kafka_production_reachability_test.go`, which until Phase 6.1c
  asserted that `internal/adapter/kafka` had zero production importers and that
  no `DiagnoseKafka` existed — the negative that made it safe for Phase 6.1c-P1
  to land a producer whose owner arrived one phase later.

**Phase 6.1c satisfied that gate's condition and turned the file around rather
than deleting it**, which is what §5 asks for once a service becomes
production-reachable. It now asserts the positive closure: exactly one
production importer and it is `internal/app`, exactly one `DiagnoseKafka`, the
exact set of rules the composition wires, no credential minting or secret
resolution in the composition root, one authentication call site outside any
loop, no credential-bearing field on the advertised transport plan, and that the
outcome enumeration above still fails in both directions. The two files assert
each other's key contents, because a guard cannot protect itself and deletion is
the failure mode this record exists to prevent.

The record of that ordering is worth keeping, because it is §4 in practice and it
cost a phase. Phase 6.1c was **stopped** by this invariant: composition would have
made six classes of Kafka failure reachable with no owner, including a rejected
credential arriving as `findings: []`, `status: OK`, exit 0. The response was to
move the ownership phase ahead of composition rather than to waive the rule —
"the Kafka CLI does not exist yet" was rejected, because this invariant is about
production application reachability rather than user routing.

PostgreSQL has no equivalent mechanical closure test yet; there, enforcement is
still by review. So this record stays **not** marked implemented: the invariant
binds every service, and one service having a mechanism is not the same as the
policy having one everywhere.

It is service-neutral and applies to PostgreSQL, Kafka and every service after
them.

## Enforcement status after Phase 6.4C

**Kafka became product-visible in Phase 6.4C, and the gate was re-run before the
route was added rather than after.**

At the point `svcdoctor diagnose kafka` was wired:

- reachable unowned Kafka FAIL outcomes: **0**
- `TestTheAuthorizedTableIsExactlyTheProducedOutcomes` (`internal/diagnosis/kafka`): passing
- `TestExactlyOneProductionPackageReachesTheKafkaAdapter`: `internal/app` only
- `TestTheCompositionWiresEveryOwnerOfWhatItCanProduce`: passing
- `TestAtMostOneAuthenticationCallSiteExists`: passing
- `TestRevealHasExactlyTwoProductionCallSites`: passing

**The CLI does not import the adapter**, so exposing the command did not widen
the set of packages from which a Kafka outcome is reachable. It builds
`app.KafkaParams` and calls one function. The `cli-composes-and-does-not-conclude`
depguard rule still denies `internal/adapter/kafka` from `internal/cli`; its
*reason* changed in Phase 6.4C — from "no Kafka composition exists" to "a
mechanism name is a string on the wire, and reaching for the adapter's constant
would put the protocol in the CLI" — and the denial did not.

## Problem

PostgreSQL BASIC needed several closure phases, and the failures they closed were
one shape repeated: **a stage produced evidence that nobody could explain, and
the report presented the silence as health.**

Recorded instances, cited rather than paraphrased:

- **`docs/BACKLOG.md`**: *"What was `findings: 0`, `status: OK`,
  `firstBrokenLayer: L3` now produces a per-endpoint PostgreSQL finding and
  `PROBLEMS_FOUND`"* — ADR 0044, Phase 4.9d. A broken TLS layer read as a clean
  run for several phases.
- **ADR 0044 Consequences**: *"The last transport-layer silence in a PostgreSQL
  run closes. `status: OK` beside a broken L1, L2 or L3 becomes impossible."*
  That sentence exists because the opposite had been possible.
- **ADR 0043**, which closed the DNS and TCP deferral ADR 0017 had left open:
  requested-target transport failures had no owner until Phase 4.9b.
- **ADR 0046 / Phase 4.11b**, which added `FailureExecRequiredInputMissing`
  because *"a run that reaches a step without an input that step needs had no way
  to say so: the alternative was a graph indistinguishable from one cancelled at
  the same point."*
- **ADR 0047 / Phase 4.11c**, which added `Result.Incomplete()` because a local
  execution timeout was not visible as anything.

Each was found late, by a closure audit rather than by the phase that introduced
the producer. **The cost is asymmetric**: a missing finding does not fail a test,
does not fail a build, and does not look wrong — it looks like a healthy target.

ADR 0053 documents the same gap about to recur for Kafka: `collectSweep` accepts
a `tcp.connect` without inspecting its children, so a bootstrap `tls.handshake`
FAIL would be structurally invisible the moment `DiagnoseKafka` lands. That is
what makes this record necessary now rather than after the fact.

## Decision

### 1. The invariant

> **A production-reachable FAIL-producing evidence stage must not be introduced
> unless every reachable FAIL outcome has a diagnosis owner, or an Accepted ADR
> explicitly records evidence-only behaviour as intentional and explains why it
> is safe.**

"Production-reachable" means reachable from a composition root the product ships
— not from a test. A stage that exists but that no `Diagnose<Service>` can call is
not yet subject to the invariant; it becomes subject the moment composition
reaches it.

### 2. UNKNOWN and SKIPPED need a visibility policy, not necessarily a finding

A FAIL needs an owner. An UNKNOWN or SKIPPED outcome often should **not** produce
a finding — an unfinished measurement is not a target defect, and ADR 0047's
whole point is that a local timeout is not a remote failure. But it must not be
silent either.

> **UNKNOWN and SKIPPED outcomes must have an explicit visibility policy whenever
> their absence from the findings list could make a report appear complete or
> healthy when it is neither.**

The policy may be a finding, or run-level visibility such as
`Result.Incomplete()`, or a recorded decision that the evidence node alone
suffices. What it may not be is unexamined. ADR 0051's completeness predicate is
this rule applied to Kafka's advertised sweep.

### 3. The escape hatch is real, and it is the record

Evidence-only is a legitimate outcome. ADR 0033's advertised sweep produced
transport evidence for two phases with no rule, deliberately: the reachability
policy was not yet decided, and inventing one to satisfy a checklist would have
been worse than the silence.

What makes that acceptable is that it was **recorded, argued and given a reopen
condition**. The invariant demands a decision, not a finding.

### 4. Ordering follows from the invariant

If a phase would introduce a producer whose failures have no owner, the owner
lands **first**, in its own phase. That is why the Kafka roadmap sequences
generic requested-target TLS diagnosis (6.1b) before `DiagnoseKafka` composition
(6.1c), and the mechanism guard (6.1a) before both.

An owner can usually be built and tested before its production producer exists —
ADR 0053's rule is exercisable through a test composition against a loopback TLS
peer — so this ordering costs a phase boundary, not a capability.

### 5. Enforcement: a per-service closure test

Each service's BASIC closure must add a test that mechanically enumerates, per
evidence-producing step, every production-reachable `FAIL`, `UNKNOWN` and
`SKIPPED` outcome, and classifies each as exactly one of:

| Classification | Meaning |
|---|---|
| **finding-owned** | a diagnosis rule produces a finding for it |
| **run-visibility-owned** | surfaced through `Result.Incomplete()` or equivalent |
| **deliberately evidence-only** | an Accepted ADR records why, and the test cites it |
| **unreachable** | no production path produces it |
| **declared, producer-absent** | the class exists in the vocabulary and nothing emits it |

The test **fails** on a sixth category: **production-reachable, no owner, no
recorded exemption.** That is the dangerous state, and it is the only one the
test exists to catch.

Phase 5.6's Kafka audit performed exactly this enumeration by hand and found
thirteen unowned outcomes. Mechanizing it is the deliverable.

### 6. Why a lint cannot do this

Reachability of a `FailureClass` from a composition root is not decidable from
imports. A `depguard`-style rule could see that `internal/app` imports an adapter,
but not which classes that adapter can emit on a path the root actually walks. A
lint would be either trivially weak (import graph only) or noisy enough to be
suppressed, and a suppressed guard is worse than none.

The closure test is the right mechanism because it runs against the real
composition and the real vocabulary, and because it is allowed to require a human
to classify a new outcome deliberately — which is the point.

### 7. Where the invariant lives

`docs/ARCHITECTURE.md` carries the normative statement, because it binds every
service. This record carries the argument, the escape hatch and the enforcement
specification. `docs/BACKLOG.md` carries the closure-test work item per service.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| Leave it as review practice | It already failed that way repeatedly; the failure mode is invisible by construction | Never |
| A static lint | Reachability is not decidable from imports; a noisy guard gets suppressed | A sound reachability analysis becomes cheap |
| Require a finding for every FAIL, with no escape hatch | Would have forced a reachability policy in ADR 0033 before it was understood, producing a worse finding | Never |
| Require a finding for UNKNOWN and SKIPPED too | An unfinished measurement is not a target defect; ADR 0047 exists because the opposite was modelled once | Never |
| One repository-wide test instead of per-service | Vocabulary and composition are per service; a shared test would either be generic to the point of vacuity or need a service switch | A shared reachability model appears |
| Mark this record implemented on acceptance | No mechanical enforcement exists yet, and claiming otherwise is the overclaim the invariant forbids | The first closure test lands |

## Consequences

- Phase ordering becomes a security-and-honesty property rather than a
  convenience: owner before producer.
- Each service BASIC closure gains one test, and its scope is already known from
  the Phase 5.6 audit shape.
- Existing accepted records are unaffected. ADR 0033's evidence-only period is
  retroactively an instance of §3's escape hatch, not a violation — it was
  recorded and argued at the time.
- No production code, schema, dependency or `FailureClass` change.

## Reopen conditions

- The first closure test lands, at which point this record's status moves from
  *enforcement deferred* to enforced for that service.
- A sound static reachability analysis becomes available, reopening §6.
