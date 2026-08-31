# ADR 0074: The run report wraps target reports and never reinterprets them

## Status

**Accepted in Phase 9.0. Not implemented.**

It decides the shape of the aggregate document, its versioning, the closed vocabulary for
how orchestration disposed of each target, what the run summary may count, the CLI surface,
the exit-code mapping, and what redaction means across a whole run.

`domain.SchemaVersion` stays **1** and the canonical single-target report is **byte-identical
to what it is today**. No `FailureClass`, no `FindingCode`, no dependency.

Companion records: [0071](0071-multi-target-configuration-schema.md) is the schema,
[0072](0072-multi-target-credential-references.md) the credential contract,
[0073](0073-multi-target-execution-and-budgets.md) the execution model.

It applies ADR 0014's severity-is-data rule, ADR 0015's derived-summary rule, ADR 0016's
serialization-ownership rule, ADR 0018's redaction contract and ADR 0048's output boundary
to a document that holds many reports, and changes none of them.

## 1. Decision summary

1. **A separate document with its own `schemaVersion`, starting at 1.** The existing report
   is embedded verbatim and gains no field.
2. **Four execution states** — `COMPLETED`, `NOT_STARTED`, `CANCELLED`, `EXECUTION_FAILED`
   — orthogonal to the evidence states `PASS / FAIL / DEGRADED / UNKNOWN / SKIPPED`.
3. **The run summary is derived, never supplied**, exactly as `domain.Summary` is.
4. **Factual counts only.** No target is ever described as healthy.
5. **`svcdoctor run --config <file>`.** Four leaf commands are untouched.
6. **The exit vocabulary is unchanged**, and so is its precedence `3 > 2 > 4 > 1 > 0`.
7. **One pseudonym table for the whole run**, so a host appearing in two targets is one
   pseudonym rather than two.
8. **The renderer diagnoses nothing across targets.**

## 2. The shape

```
RunReport {
  schemaVersion  1              its own, not domain.SchemaVersion
  kind           "run"          present only on this document
  run {
    svcdoctorVersion
    startedAt
    duration
    concurrency
    outputMode                  LOCAL_FULL | SHAREABLE_REDACTED
    stoppedReason?              absent, or why scheduling stopped
  }
  targets  [ TargetResult ]     declared configuration order
  summary  RunSummary           derived
}

TargetResult {
  targetId
  service                       domain.ServiceID
  executionState                §4
  report?                       the existing canonical Report, verbatim
  incomplete?                   the target's own Result.Incomplete()
  executionError?               a closed class and a message, §4.2
}
```

### 2.1 It wraps; it does not merge

The embedded value is a `domain.Report` and nothing else — same fields, same order, same
`schemaVersion: 1`, same bytes it would have as a single-target artifact. A consumer that
parses svcdoctor reports today parses `targets[i].report` with no change.

Merging the targets into one report was rejected. One report has one `target`, one
`vantage`, one graph and one summary; a merged document would have to either invent
composite values for all four or make them optional, and evidence identifiers from different
runs would collide — two PostgreSQL targets both minting
`dns.lookup/db.internal`. Wrapping has none of those problems and the existing contract is
already exactly the right shape for one target.

### 2.2 `incomplete` travels beside the report, as it already does

`render.Input` carries `Incomplete` beside the report rather than inside it, because *"a
report cannot observe its own partiality"*. `TargetResult` does the same for the same
reason, and it is what makes the run-level incompleteness in §5 derivable from the target
list.

A consumer must not recompute it by scanning for `UNKNOWN` nodes. ADR 0047's predicate is
more than that — a passing session settles the question even when another path ended on a
local budget — and a recomputation would disagree with the exit code the same run produced.

## 3. Versioning

**Two documents, two version numbers, two lifecycles.**

| | Number | Describes |
|---|---|---|
| `domain.SchemaVersion` | 1 | one target's canonical report |
| `RunReport.schemaVersion` | 1 | the aggregate document |
| `version` in the config | 1 | what the operator writes (ADR 0071 §4) |

Coupling any two would mean a change to one forced a version bump in the others, telling
consumers their parsers were obsolete when nothing they read had changed.

**`domain.SchemaVersion` is not incremented by this record and must not be incremented by
Phase 9.1.** The single-target report gains no field, not even the `kind` discriminator: the
aggregate is self-describing because it carries `kind: "run"`, and adding a field to a
released contract to make a *different* document identifiable would be a schema change paid
for by every existing consumer.

### 3.1 Where it lives

`internal/domain`, beside `Report`.

`internal/domain` already models one run — `RunMetadata`, `Summary`, `SummaryStatus` — so
modelling a set of runs is the same kind of work. More decisively, ADR 0016 placed canonical
serialization on the report because *"giving Graph a public encoding would create a second
serialization to keep in step with this one for no consumer"*. Putting the aggregate's
encoding in `internal/fleet` would create exactly that second serialization, in a package
that also schedules goroutines.

So `internal/domain` owns the type, its derived summary and its JSON shape, and
`internal/fleet` assembles inputs and hands them over — the same relationship
`internal/app` already has with `domain.Report`.

## 4. Execution state

A closed vocabulary of four, describing **how orchestration disposed of a target** — not
what the target found.

| State | Meaning | `report` | `executionError` |
|---|---|---|---|
| `COMPLETED` | The runner called the composition root and it returned a report | **yes** | no |
| `NOT_STARTED` | The runner never called it | no | no |
| `CANCELLED` | It was called, and the **run** ended it — run deadline or signal | **yes** | no |
| `EXECUTION_FAILED` | It was called and returned an error, or could not be called | no | **yes** |

Those four presence rules are invariants a constructor enforces, not conventions.

### 4.1 It is orthogonal to evidence state, and that is the point

```
executionState = COMPLETED   and   the report contains FAIL
```

is the ordinary outcome of a successful diagnosis of a broken endpoint. svcdoctor did its
job; the target has a problem.

The two vocabularies must never be merged, and neither may borrow the other's words. A
target is never `FAILED` at run level and never `NOT_STARTED` at evidence level.

**Why a target-budget expiry is `COMPLETED`.** A target whose own `timeout` or `step_timeout`
expired ran to the end of *its own* budget and produced its own truthful report, with
`incomplete` true. That is the target's business, and the report already says so. `CANCELLED`
is reserved for the case where the **run** ended it, because that is the only distinction
orchestration can make that the report cannot make about itself.

### 4.2 `executionError` is a closed class

Two causes, both svcdoctor-local, because a configuration error never reaches execution at
all (ADR 0071, and §9 below):

- a credential reference that resolved at preflight and failed at execution — ADR 0072 §5.3;
- a composition root returning an error instead of a report, which means an invariant failed.

It carries a class and a message. It carries **no** secret, no credential reference name, no
file path and no environment variable name — ADR 0072 §10 puts those on stderr only.

### 4.3 Why `NOT_STARTED` is not three states

The phase brief suggests `NOT_STARTED / CANCELLED / RUN_BUDGET_EXHAUSTED`. Splitting the
first by reason was rejected: **the reason is a run-level fact, not a per-target one.** A run
stops scheduling once, for one reason, and recording that reason on each of 400 queued
targets is 400 copies of a single fact.

It is recorded once, in `run.stoppedReason`, and a reader who wants to know why
`orders-db` never ran reads it there. `NOT_STARTED` says the same thing about every target
that has it, which is what a closed vocabulary should do.

## 5. The run summary

Derived by the constructor from the target list. **Never supplied**, for ADR 0015's reason
verbatim: a supplied summary could claim two completed targets while the list held five, and
nothing would say which was right.

```
RunSummary {
  targets            declared
  completed
  notStarted
  cancelled
  executionFailed
  withProblems       COMPLETED or CANCELLED targets whose report status is PROBLEMS_FOUND
  incompleteReports  targets whose own Result.Incomplete() was true
  status             derived: OK | PROBLEMS_FOUND
  incomplete         derived: any NOT_STARTED, CANCELLED, EXECUTION_FAILED,
                              or any incomplete target report
}
```

### 5.1 Words that are forbidden

**No target is ever counted as healthy or unhealthy.** `domain.SummaryStatus` already says
why: *"`SummaryStatusOK` means exactly one thing: no finding reached ERROR or CRITICAL. It
does not mean the target is healthy."* A run summary that said "3 services healthy" would
make a claim the underlying report explicitly refuses to make, four levels down.

Also absent: "up", "down", "reachable", "available", "degraded", and any count of services
by a health taxonomy no document defines.

### 5.2 `status` and `incomplete` are derived, not stored opinions

Both are computed from the counts in the same object, in the constructor, so they cannot
disagree with them. This mirrors `deriveSummary` exactly.

`status` is `PROBLEMS_FOUND` when `withProblems > 0`, otherwise `OK`. It is a fold over the
per-target statuses the reports already derived — never a fresh severity scan, which would be
a second opinion that could contradict the reports it is describing.

### 5.3 `OK` and `incomplete` are independent, at run level too

The three load-bearing product invariants in `CLAUDE.md` survive unchanged and compose:

- a run of four targets, all `OK`, one of which never started, is `status: OK` and
  `incomplete: true`, and exits **4**;
- a run of four targets where one has `<SERVICE>_CREDENTIAL_NOT_CONFIGURED` is `status: OK`,
  `incomplete: false`, `withProblems: 0`, and exits **0** — because that finding is WARN and
  its report already says `OK`, not because anything here recognizes the code;
- `UNKNOWN` is still not `FAIL`, at either level.

## 6. Exit codes

**The vocabulary is unchanged and no code is added.** `docs/SCOPE.md`'s five codes, and its
precedence, applied to a set.

| Code | Multi-target meaning |
|---|---|
| **0** | The run completed and no target's report reached `PROBLEMS_FOUND` |
| **1** | The run completed and at least one target's report reached `PROBLEMS_FOUND` |
| **2** | A configuration or usage error. **No target was dialled** |
| **3** | svcdoctor itself failed and produced no usable aggregate report |
| **4** | An aggregate report exists and the run is incomplete |

Precedence stays **`3 > 2 > 4 > 1 > 0`**.

### 6.1 The worked example

> one target has a real authentication failure, one target times out locally, one succeeds

**Exit 4.** The local timeout makes the run incomplete, and 4 outranks 1 for exactly the
reason it already does at single-target scope: incompleteness qualifies every conclusion, so
reporting the authentication failure as though the picture were complete would overstate what
was measured. The authentication finding stays in the report, in full.

This is not a new rule. It is `cli.ExitCode`'s existing ordering, and Phase 9.1's matrix pins
it the way `TestExitCodeMatrix` already pins the single-target one.

### 6.2 What contributes to 4

Any of: a `NOT_STARTED` target, a `CANCELLED` target, an `EXECUTION_FAILED` target, or any
target whose own report was incomplete.

**`EXECUTION_FAILED` contributes to 4 rather than to 3.** A single target failing locally
does not make the aggregate unusable: the other targets were measured and their reports are
truthful. 3 is reserved for the case where **no** usable aggregate report exists, which is
what `docs/SCOPE.md` says it means.

### 6.3 Ownership

The runner returns a structured aggregate outcome. The CLI maps it to a status. **The
renderer never does**, which is ADR 0048 §3 unchanged: *"a renderer never chooses an exit
code and a command never formats a finding"*.

The mapping reads the run summary and nothing else — not a finding, not a severity, not a
finding code, not a graph, not which targets are which service. Severity reaches it only
through statuses the reports already derived.

## 7. Rendering

The multi-target renderer presents the run summary, then each target's report through the
existing renderers, then the targets that produced no report.

It **may**: show the run summary; render each embedded report; mark `NOT_STARTED`,
`CANCELLED` and `EXECUTION_FAILED` targets clearly and distinguishably; state the reason
scheduling stopped.

It **may not**: re-diagnose any evidence; create a finding; compute a severity; choose a
root cause; compare two targets; infer a relationship between services; or order targets by
anything but §6.1 of ADR 0073.

### 7.1 The forbidden claim

> "Kafka is failing because PostgreSQL is down."

svcdoctor measured two endpoints independently and has no evidence of any relationship
between them. Multi-target v1 is orchestration, not distributed causal inference, and a
renderer is the last place such an inference could be made legitimately — it holds no
evidence, only a presentation.

**No cross-target diagnosis exists in v1, at any layer.** Not in the renderer, not in the
runner, and not as a rule: `internal/diagnosis` runs per target, over that target's frozen
graph, exactly as it does today.

### 7.2 `not measured` is never collapsed into `not reached`

ADR 0052 froze this for Kafka and it generalizes. A `NOT_STARTED` target must not be rendered
in a way a reader can mistake for a target that was tried and did not answer. Three
dispositions, three presentations, and a test that fails if any two produce the same line.

## 8. Shareable output

`--shareable` on `run` derives a `SHAREABLE_REDACTED` aggregate through the existing
structural redaction, applied to every embedded report.

### 8.1 One pseudonym table for the whole run

Redaction's principle is *preserve correlation, remove identity*. Applied across the run,
that means a host appearing in two targets receives **one** pseudonym.

Redacting each target independently was rejected: it would give the same real host two
different pseudonyms in one document — and, worse, could give two different real hosts the
same pseudonym in different targets, which is a false correlation invented by the redactor.
For a document whose purpose is to be shared and reasoned about, inventing a correlation is
worse than preserving one.

The consequence is stated rather than hidden: a redacted aggregate does reveal that two
targets share infrastructure. That is the same class of structural information a single
redacted Kafka report already reveals about a bootstrap and its advertised brokers, and it
is what makes the document useful.

Phase 9.1 therefore adds a run-level entry point to `internal/security/redaction`. `Redact`
itself is unchanged.

### 8.2 Target IDs are pseudonymized

`orders-db-prod-eu-west-1` is operator-chosen text that can carry deployment structure,
tenancy and geography. Under `SHAREABLE_REDACTED` it is pseudonymized like any other
identity, consistently across the whole document so that a finding and its target still
correlate.

Under `LOCAL_FULL` it appears verbatim, as hostnames already do.

### 8.3 Never serialized, in either mode

- the config file path;
- credential reference names and paths;
- the raw configuration, in any form, including a normalized echo of it;
- any secret value;
- any credential surface at all — ADR 0072 §10.

**A report never embeds the configuration that produced it.** The temptation is real —
it would make a report self-contained — and it is refused: the config holds every credential
reference in the run, and a report is the artifact most likely to be pasted somewhere public.

## 9. Configuration errors never start a network

**Any configuration error anywhere means zero targets are dialled.** Parse, then validate the
whole file, then preflight every credential reference, and only then execute.

The alternative — validating lazily — means an operator discovers that target 18 is malformed
after 17 targets have been diagnosed, authenticated against and logged. Those 17 connections
were spent on a run that cannot complete, and against directory-backed deployments each
authentication is counted and is a step toward lockout (ADR 0028).

So a configuration error produces exit **2**, a message naming the file, the target and the
field, and **no aggregate report at all**. There is nothing to report: nothing ran.

Runtime credential resolution failure is different, is not a configuration error, and is
handled by `EXECUTION_FAILED` per §4.2.

## 10. The CLI

### 10.1 `svcdoctor run --config <file>`

Action-first, a sibling of `diagnose` and of the reserved `inspect`, consistent with
ADR 0041.

| Candidate | Verdict |
|---|---|
| `svcdoctor run --config f.yaml` | **Accepted** |
| `svcdoctor diagnose --config f.yaml` | Rejected. `diagnose` requires a service word; a flag in the service position makes `diagnose` two commands |
| `svcdoctor diagnose batch --config f.yaml` | Rejected. `batch` would sit exactly where `postgres` sits without being a service — the confusion ADR 0041 removed |
| `svcdoctor diagnose multi --config f.yaml` | Rejected, same reason |
| `svcdoctor fleet --config f.yaml` | Rejected. `fleet` is a noun in the action position |

**The four leaf commands are untouched.** Same flags, same defaults, same help, same exit
codes, same credential sources. A regression test asserts their surfaces byte-for-byte, and
`run` is additive.

`--config` is required. There is no default path search (ADR 0071 §8.3).

### 10.2 Flags on `run`, and what may not be one

| Flag | Precedence |
|---|---|
| `--config` | required; no config equivalent |
| `--timeout` | CLI > `run.timeout` > unset |
| `--concurrency` | CLI > `run.concurrency` > 4 |
| `--output` | CLI > built-in `text` |
| `--shareable` | CLI > built-in false |

Every one is **run-global**. Precedence is uniformly **CLI > config `run:` block > built-in
default**, which matches how a flag already overrides a default in every leaf command.

Forbidden, and not deferred:

- **any service-specific override** — no `--postgres-host`, no `--rabbitmq-vhost`, no
  `--kafka-broker`. A flag that edited one target would mean the file no longer describes
  the run, and with N targets it could not say which one it edited.
- **any per-target override**, including `--target-timeout`. Same reason.
- **`--password-file` and `--password-stdin`.** One ambient CLI secret available to N targets
  is precisely the cross-contamination ADR 0072 §7 exists to prevent. Credentials come from
  per-target references only.

### 10.3 `--config -` does not mean stdin

Config comes from a **regular file** only.

In fleet mode stdin cannot be both the configuration and a credential source, and there is
one stdin against N credentials. Making it the config would create an invocation in which
the file describing which secrets to use arrives on the same channel a secret would — and
deciding which by position is exactly the ambiguity ADR 0049 §2 refuses to resolve.

The file requirement also makes a run reproducible: the artifact that produced a report still
exists after the run.

### 10.4 Filtering is not in v1

`--target orders-db` and `--type postgres` are plausible and are **not** implemented. No
glob, no regex, no selector language, and no reserved flag name.

The identity contract does not foreclose them: target IDs are explicit, unique across the
file, case-fixed and drawn from a small grammar, so an exact-match selector remains available
whenever a concrete need appears.

## 11. Rejected alternatives

| Alternative | Reason | Reopen condition |
|---|---|---|
| Merging targets into one `domain.Report` | Composite target, composite vantage, colliding evidence identifiers | None |
| Incrementing `domain.SchemaVersion` | Charges every existing consumer for a document they do not read | A real change to the single-target report |
| A `kind` field on the single-target report | Same | Same |
| Run status as a stored field | A second opinion that could disagree with its own counts (ADR 0015) | None |
| Splitting `NOT_STARTED` by reason | 400 copies of one run-level fact | None |
| A run-level `FindingCode` | Makes a configuration error into a claim about a service | A concrete reporting constraint findings alone can satisfy |
| Counting healthy targets | A claim the underlying report explicitly refuses to make | None |
| Per-target independent redaction | Invents false correlations and destroys true ones | None |
| Embedding the config in the report | It holds every credential reference in the run | None |
| A new exit code for partial runs | 4 already means exactly that | None |
| `--output-file` with atomic rename | Not needed by Phase 9.1; stdout already works and inherits the existing output boundary | A measured need for large reports written under cancellation |

## 12. Reopen conditions

1. **A concrete cross-target question an operator can state and svcdoctor can measure**
   reopens §7.1 — and would need an evidence model for the relationship first, which does
   not exist.
2. **A change to the single-target report** reopens §3's independence, in the direction of
   confirming it.
3. **A consumer that cannot distinguish the two documents** reopens §3's decision to keep
   `kind` off the single-target report.
4. **A CI need the five exit codes cannot express** reopens §6 — and would be a stop
   condition for the whole phase, not a local fix, because it would mean the single-target
   contract was wrong too.
