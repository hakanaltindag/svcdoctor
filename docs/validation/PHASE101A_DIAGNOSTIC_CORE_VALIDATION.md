# Phase 10.1A — Diagnostic intelligence core foundations

**Status:** implemented. **No report changed.**

Phase 10.1A is the first half of the split
`docs/design/DIAGNOSTIC_INTELLIGENCE.md` section P recommends: 10.1a lands
`RuleContext`, the purity extensions, panic recovery and the shared graph
queries with byte-identical reports, so that 10.1b's diff is the entire
behavioural change and is reviewable as such.

Everything it adds is either unwired or invisible. The acceptance criterion was
**same input → same existing public output**, and it holds against every one of
the 38 committed golden artifacts, unchanged.

---

## 1. What landed

| Area | File | Wired into production? |
|---|---|---|
| the rule contract's new input | `internal/diagnosis/rulecontext.go` | yes |
| rule identity | `internal/diagnosis/ruleid.go` | yes |
| registration: builder → frozen registry | `internal/diagnosis/registry.go` | yes |
| evaluation, panic recovery, outcome | `internal/diagnosis/engine.go`, `outcome.go` | yes |
| the four evidence relations | `internal/diagnosis/basis.go` | no |
| the confidence ladder | `internal/diagnosis/confidence.go` | no |
| semantic identity and convergence | `internal/diagnosis/converge.go` | no |
| shared graph queries and sibling counting | `internal/diagnosis/graphquery.go` | no |
| the failure boundary | `internal/diagnosis/boundary.go` | no |
| recommendation safety | `internal/diagnosis/advice.go` | no |
| rule-output validation | `internal/diagnosis/validate.go` | no |

Three things are wired and each is invisible in a passing run:

- **`RuleContext`** replaces `domain.Graph` on `diagnosis.Rule` (ADR 0080 §2.1).
  All eighteen existing rules take it and read `ctx.Graph`; none consults
  `Vantage` or `Incomplete`, so no finding moved.
- **The registry** replaces `NewEngine(rules...)`. The four composition roots
  register the same rules in the same order under stable identities.
- **Panic recovery** discards a panicking rule's output and marks the run
  incomplete. No production rule panics, so no run's incompleteness changed.

## 2. The two design challenges the phase was asked to settle

### 2.1 The failure boundary stays internal, and there is no circularity

ADR 0079 §2.3 expresses the boundary as `DIAG_FAILURE_BOUNDARY`, and ADR 0078 §3
authorizes the finding-code count to move 60 → 61 **"in the phase that implements
it, not before"**. That phase is 10.1b, by the design document's own split. No
ADR requires emission in 10.1a, so nothing was bent: the boundary is computed,
tested against all six shapes of ADR 0079 §2.5, and emitted nowhere. The count is
still **60**.

The conceptual worry — evidence → finding → boundary → finding — does not arise,
and it was checked rather than assumed. `Boundaries` reads `domain.Graph` and
nothing else; it does not accept, import or inspect a `Finding`. The chain is
one-directional, and `TestTheBoundaryIsDerivedFromEvidenceAndNothingElse` holds
it behaviourally: running a rule set that produces findings about the very nodes
a boundary cites moves no boundary.

### 2.2 `SchemaVersion` is unchanged, and that is a claim about this phase only

`SchemaVersion` **1**, `RunSchemaVersion` **1**, no field added, removed,
renamed or repurposed. The valid conclusion is the narrow one: *Phase 10.1A
requires no schema change*. Section 6 records the pressure that exists anyway.

## 3. Deviations from the frozen records, and why

Three, each small and each recorded rather than absorbed.

**ADR 0080 §2.4 puts duplicate-identity rejection on `NewEngine`, and it lives on
`RuleSet.Freeze`.** The record's requirement is that the rejection happens at
construction rather than at review, and returns an error rather than silently
keeping one rule. Both hold, strictly earlier: `Add` refuses the duplicate at the
call that makes it and `Freeze` rechecks, so a `Registry` that exists is already
valid and `NewEngine` cannot fail. The alternative — an error on `NewEngine` as
well — would be a second failure path that can never fire.

**ADR 0080 §2.2 specifies a `forbidigo` pattern for `time.Now`, and the ban is an
AST guard instead.** `forbidigo`'s forbid list is global in golangci-lint v2.
Scoping a call ban to one directory means granting an exclusion to every *other*
directory, which is an enumeration a new top-level package escapes silently. The
prohibition is implemented in
`test/security/diagnosticcore_test.go`, scoped exactly, using the same technique
the SASL core already uses. `crypto/rand` and `io/ioutil` — the rest of that
section's list — were added to `depguard` as specified.

**ADR 0081 §2.2's merge table does not mention `Layer`.** `Converge` takes the
tie-break winner's, because `Summary`, `Detail` and `Discriminator` already come
from the winner and a finding whose prose came from one rule and whose layer came
from another would describe a claim neither rule made.

## 4. What the validation found

Three things, none of them expected, all of them fixed in this phase.

**The action-safety validator was over-broad, and the guard that measured it
is the deliverable.** `TestDIAG036EveryProducedRecommendationIsAlreadySafe` runs
the new validator over all 64 recommendation strings the tree ships. The first
version rejected six of them — and every one was correct prose:

| Rejected | Why the validator was wrong |
|---|---|
| `Supply --username together with --password-file …` | a `--long-flag` here is svcdoctor naming its *own* option, not a command to run on the target |
| `Use --tls require with a trusted certificate chain …` | the same |
| `Grant the diagnostic identity permission to run PING …` | "Grant" is an English verb as well as a SQL keyword |
| `Grant this user permissions on the virtual host …` | the same |
| `Verify the credential …; the endpoint's own log …` | a semicolon joining two clauses is punctuation, not a shell separator |
| `Check the referenced evidence …; if the endpoint …` | the same |

Since 10.1A must not reword an existing recommendation, the validator was
narrowed rather than the strings: only single-hyphen flags count, `;` left the
metacharacter set, and a leading SQL keyword is refused when written in capitals
or followed by the structure that makes it a query. All 64 now pass with **zero
strings changed**, which is what makes adopting the guard in 10.1b a wiring
change rather than a content one.

**The generic core had learned two service names**, and the vocabulary guard
caught it in the same commit that introduced it: `commandWords` held
`rabbitmqctl` and `redis-cli`. They are gone. The residual gap is recorded in
`advice.go` and asserted by
`TestTheActionValidatorsResidualGapIsWhereItWasPutOnPurpose`: a bare
`<service-tool> <subcommand>` with no flag and no metacharacter is not caught
generically, because catching it needs the tool's name and only the service's own
rule package may know it.

**The hostile-text fuzzer refuted its own first assertion in seconds.**
Substring absence — "the peer's value does not appear in the prose" — failed on
the value `"a"`, which is a substring of almost any English sentence. Raising a
minimum length would have hidden the false positive. The property is now the
stronger one: changing the peer's value changes no byte of the prose, so there is
no channel at all. This is the technique Phase 9.1C used for secret leakage, for
the same reason. The refuting input is committed as a regression seed.

The mutation suite found two more, and they were coverage gaps rather than
defects. `TestDIAG011LinearBoundary` looked like it covered "SKIPPED is not a
failure" and did not — its skipped node sits *below* the failure, so the walk
stops first. And every boundary fixture had named its nodes so that identifier
order and layer order agreed, so removing the layer sort changed nothing. Both
now have fixtures that discriminate.

## 5. Validation

| Level | What ran | Result |
|---|---|---|
| L1 | unit tests for identity, registry, basis, ladder, merge, queries, boundary, advice, validation, rule failure | pass |
| L2 | the property suite `P01`–`P18` | pass |
| L3 | `scripts/phase101a-mutations.sh` | **27 planted, 27 caught, 0 survivors** |
| L4 | `FuzzRuleID`, `FuzzActionText`, `FuzzBoundaryTraversal`, `FuzzHostileServerText` | pass, ≥20s each |
| — | `go test ./...`, `go test -race ./...`, `make check` | pass |
| — | the security corpus | 220 tests, pass (213 before, +7 added here) |
| — | the historical mutation suites 9.1A, 9.1B, 9.1C, 9.2B, 9.3A | 20 · 31 · 45 · 21 · 10 caught, **0 survivors each** |
| L5 | the eight service integration suites | see below |

**One mutation was withdrawn as an equivalent mutant, and the reason is in the
script.** Replacing `slices.Clip(out)` with the builder's own slice in
`RuleSet.Freeze` is unobservable: a slice header is copied by value, so a later
`Add` cannot change a frozen registry's length, and every accessor clones or
reads. A test could only "catch" it by asserting an implementation detail. It was
replaced by an aliasing mutation at a place the aliasing is actually reachable.

### Integration regression

All eight suites were run against real servers, because the phase changed the
four composition roots and those are what the suites drive end to end.

| Suite | Result |
|---|---|
| PostgreSQL 18 | **117 pass, 1 fail** — the fixture's own key-ownership guard; see below |
| Apache Kafka 4.0.0, three-broker KRaft | **green**, full `integration-kafka` gate |
| Redis 8.2.1 | **23/23** |
| Valkey | **10/10** |
| RabbitMQ 3.13.7, 4.0.9, 4.2.0 | **58 pass, 3 fail** in 2 tests; see below |
| LavinMQ 2.3.0 | **9/9** |
| Redpanda v25.1.9 | **12/12** |
| Multi-target | **7/7** |

**Zero semantic output change was caused by the new foundations**, and the three
failures are the local environment rather than the product:

- `TestTheTLSKeyIsOwnedByTheDatabaseUser` fails because a macOS virtiofs bind
  mount reports uid 0 for the server key and does not honour a `chown` from
  inside a container. The guard's own message names this condition. It runs
  before any product code and its file is unchanged by this phase.
- `TestRAB16BrokerStopped` and `TestRAB24And25AddressLiterals/RAB-25_IPv6_literal`
  fail because colima keeps a forwarded port listening after its container stops,
  and does not forward IPv6 to containers. Both were **re-run at the Phase 10.0
  baseline commit `fb91c0b` and fail there with byte-identical messages**, which
  is what makes them pre-existing rather than a regression.

### Property coverage

`P01` input permutation · `P02` registration permutation · `P03` UNKNOWN never
FAIL · `P04` SKIPPED never FAIL · `P05` missing ≠ contradiction · `P06` blocked ≠
contradiction · `P07` contradiction never raises · `P08` absence never raises ·
`P09` no vote to HIGH · `P10` convergence commutative and associative · `P11`
subjects stay separate · `P12` all-PASS has no boundary · `P13` cancellation
fabricates none · `P14` dangling references rejected · `P15` duplicate identity
rejected · `P16` frozen registry immutable · `P17` repeated evaluation
deterministic across `GOMAXPROCS` · `P18` no public output changed.

## 6. Schema pressure, recorded and not acted on

Nothing here needed a schema change. Three concepts are represented internally
and have no v1 home, and each is a decision already taken rather than a gap:

- **Recommendation kind and safety class.** ADR 0082 §2.1 puts them on
  `domain.Recommendation`, additively. They live in `internal/diagnosis` for this
  phase because adding a field would change the JSON of every report that carries
  a recommendation. 10.1b moves them, as specified.
- **The evidence relations.** Only *supporting* reaches a report, as
  `EvidenceRefs`. Contradicting, missing and blocked stay rule-internal by ADR
  0081 §2.4, which also records the revisit condition for the first of them.
- **Rule identity.** Deliberately not serialized (ADR 0080 §2.5).

The boundary is the one concept whose absence from the report is temporary: it
becomes `DIAG_FAILURE_BOUNDARY` in 10.1b, additively, and the finding-code count
moves 60 → 61 there.

## 7. Frozen counts, re-proven

| | Phase 10.0 | Now |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| finding codes | 60 | **60** |
| RabbitMQ finding codes | 11 | **11** |
| failure classes | 42 | **42** |
| `security.Reveal` production call sites | 4 | **4** |
| `Credential.SecretFor` production call sites | 4 | **4** |
| external modules | 2 | **2** |
| exit codes | 5 | **5** |

## 8. Public compatibility

Zero bytes changed in any of the 38 committed golden artifacts — the 18 Kafka
terminal goldens, the 8 PostgreSQL CLI goldens including the shareable
projection, the 6 fleet `RunReport` goldens covering all four services in
canonical and shareable JSON, and the help goldens. Verified with
`git diff fb91c0b -- '*testdata*'`, which is empty.

`internal/domain`, `internal/render`, `internal/probe`, `internal/adapter`,
`internal/security`, `internal/fleet`, `internal/cli` and `cmd/` are byte-for-byte
unchanged from the Phase 10.0 baseline. The only production changes are under
`internal/diagnosis/**` and the four composition roots in `internal/app/`.

No CLI command, flag, help text or exit code changed. No finding code, failure
class, severity, confidence, discriminator or recommendation string changed.

## 9. What Phase 10.1B inherits

The engine still concatenates and sorts; `Converge` exists, is tested, and is
called by nothing. `TestP18DuplicateFindingsAreStillPreserved` fails the day
merging is wired in, which is the day a golden report is expected to move. That
is the intended signal, not a regression.
