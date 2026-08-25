# `test/harness` — the validation harness, v1

## Purpose

Turn the validation discipline already proven across PostgreSQL, Kafka and
Redis into one reusable scenario + assertion contract, so a fourth service is
cheaper to validate without weakening the evidence discipline.

A scenario arranges ground truth, runs svcdoctor, and hands the frozen outcome
to `harness.Assert` as a `Subject` plus an `Expectation`.

```text
establish ground truth      ← the service's own integration package
        ↓
invoke svcdoctor            ← the service's own integration package
        ↓
capture the canonical Result
        ↓
assert graph semantics      ┐
assert allowed claims       ├─ this package
assert forbidden claims     │
assert security invariants  ┘
```

## Non-goals

It is not a test platform, a provider framework, an infrastructure
orchestrator, or a scenario DSL. There is no YAML, no JSON scenario file, no
schema version, no registry and no templating. Scenario definitions are Go
structs at the call site.

It does not start services, configure users, break network paths, edit
`pg_hba.conf`, set Kafka advertised listeners or write Redis ACLs. Ground truth
stays with the fixture that owns it.

## The one load-bearing rule

**The harness knows no service.**

It holds no branch on PostgreSQL, Kafka or Redis, and imports no adapter, wire
or diagnosis package. It sees `domain.Step`, `domain.State`,
`domain.FailureClass` and `domain.FindingCode` values that a scenario passed in,
and never decides which of them a service ought to produce.

Anything service-shaped is derived by the scenario and handed over as data. The
clearest case is the credential count: which step carries a credential is Kafka
knowledge, so `test/integration/kafka` counts and the harness only bounds. No
production telemetry was added to make any of this convenient.

If a change here ever needs to know which service it is looking at, the
abstraction was wrong. Remove it rather than branch it.

## Why the contract stays at the call site

`harness.Assert(t, subject, harness.Expectation{...})`, never
`harness.AssertScenario(t, result, "pg-wrong-password")`.

A reviewer should read one service test and see what happened, what svcdoctor
may claim, and what it must not claim, without opening five helper files. A
registry keyed by scenario name moves all three somewhere else.

## Claim discipline is the point

Every migrated scenario states at least one **forbidden** claim, because that is
the assertion that actually protects the product. A finding code promises a
category; its prose is what an operator reads, and most ways svcdoctor could
overclaim are available to prose while every code stays correct — "the password
is wrong" under a code meaning only "the endpoint rejected what was presented".

## Secret discipline

The harness obeys the rules it checks. A failed leak assertion names the
document that carried the value and never reproduces the value, the surrounding
text or the report; a failed prose assertion names the finding and the phrase,
not the sentence around it.

## Scenarios migrated in v1

| ID | Scenario | Home |
|---|---|---|
| PG-H1 | wrong password | `test/integration/postgres/endtoend_test.go` |
| PG-H2 | `pg_hba` deny | `test/integration/postgres/endtoend_test.go` |
| PG-H3 | local timeout | `test/integration/postgres/app_test.go` |
| K-H1 | bootstrap ok, advertised unreachable | `test/integration/kafka/advertised_test.go` |
| R-H1 | `WRONGPASS` | `test/integration/redis/scenarios_test.go` |
| R-H2 | `NOPERM` | `test/integration/redis/scenarios_test.go` |

Redis Sentinel is deliberately **not** migrated in v1 and its existing coverage
is untouched. It is the first candidate if a v2 is ever justified.

## Testing the harness

`harness_test.go` proves each assertion **can fail**, and fails for the reason
it claims. A helper that silently passes is worse than no helper: every scenario
leaning on it becomes a green test asserting nothing.
