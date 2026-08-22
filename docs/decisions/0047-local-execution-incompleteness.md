# ADR 0047: A run svcdoctor cut short says so, and a run that got its answer does not

## Status

**Accepted, and implemented in Phase 4.11d.**

`internal/app.Result.Incomplete()` reports local execution incompleteness rather
than only caller cancellation, `internal/adapter/postgres.StartupParams` carries
an `ExchangeTimeout`, and the SSL-negotiation and startup classifiers gained the
local-deadline guard their two siblings already had.

No `FindingCode`, no `FailureClass`, no schema field, no dependency and no
severity changed. `FindingCode` stays **24**, `FailureClass` **40**,
`schemaVersion` **1**, `security.Reveal` **two**, the dependency set one.

## 1. Context: three defects with one seam

Phase 4.11c reproduced three failures against a real loopback listener, all of
them turning on the same fact: **a per-step budget expiring leaves the caller's
context alive.**

`PostgresParams.StepTimeout` bounds each individual exchange; the caller's
context bounds the run. When the step budget is the one that expires, the socket
deadline `wire.bindDeadline` installed comes back as a `net.Error` timeout — not
as `context.DeadlineExceeded`, and `ctx.Err()` is still nil.

Measured, in that configuration:

```text
postgres.startup   never bounded at all      run did not return
postgres.ssl_request  FAIL PROTOCOL_UNEXPECTED_RESPONSE + ERROR finding
tcp.connect        UNKNOWN EXEC_LOCAL_TIMEOUT   status OK, Incomplete() false
```

The first is a liveness defect. The second publishes svcdoctor's own deadline as
the endpoint's protocol failure, which `docs/ARCHITECTURE.md` and ADR 0020 both
forbid in the same words: *a local timeout is not a remote failure.* The third
reports a run that never reached L3 as a finished, healthy one.

## 2. Two of the three were not decisions

Bounding the startup exchange and classifying a local deadline as
`EXEC_LOCAL_TIMEOUT` are corrections, not choices. Every sibling step in the
adapter already took `PostgresParams.StepTimeout`; `StartupParams` had no field
for it, so the value was dropped silently at a call site that looked complete.
`authenticate.go` and `establish.go` already carried the `isTimeout(err)` guard
in exactly the position the two broken classifiers lacked it.

ADR 0045's own disposition table already states the row the producer did not
implement — `budget expired | UNKNOWN | EXEC_LOCAL_TIMEOUT | nobody,
deliberately`. This record does not re-decide any of that.

## 3. The decision: when does a local timeout make the *run* incomplete?

That question was genuinely open, and it is the reason this record exists.

`Result.Incomplete()` was derived from `ctx.Err() != nil` alone. Widening it to
"any local timeout anywhere" is the obvious repair and it is wrong, because
ADR 0041 measures **every** resolved address deliberately and continues exactly
one. A path the run did not select ending without a conclusion is the designed
shape, not a truncated run — so under that rule an ordinary dual-stack run with
one slow address would report itself incomplete while sitting on a session that
reached `ReadyForQuery`.

**Decided:** a run is incomplete when svcdoctor's own execution limit prevented
it from reaching the outcome it set out to measure. Concretely:

```text
incomplete = the caller's context ended
           OR (no session was established
               AND some step that was entered ended UNKNOWN with
                   EXEC_LOCAL_TIMEOUT or EXEC_CANCELLED)
```

| Scenario | Incomplete |
|---|---|
| session reached `ReadyForQuery`, another path locally timed out | **false** |
| every path ended on the local budget | **true** |
| the selected path timed out locally at SSLRequest, startup, auth or session | **true** |
| DNS failure, TCP refusal, TLS failure, startup rejection | false |
| rejected credential, absent database, authorization denial | false |
| no credential configured, credential withheld by policy | false |
| cancellation, caller deadline | true |

### Why a passing session settles it, and nothing weaker

A run that reached `ReadyForQuery` answered the question it was asked. Local
uncertainty on a path it did not use does not unmake that answer. Anything
weaker is not a substitute: a session node that is itself UNKNOWN because the
read budget expired is precisely the case this must catch, so the test is a
**passing** session and not the presence of a session node.

### Why UNKNOWN and not SKIPPED

`UNKNOWN` means a step was entered and could not be determined. A SKIPPED node
carrying a local class means an address was never tried, and the transport chain
records that only after seeing the caller's context already done — so the first
clause covers it and counting it twice would say nothing new.

### What this supersedes

**ADR 0041 acceptance 36** — *"`Incomplete()` is true whenever the run context
ended before the work did"* — is narrowed by this record. It was the whole rule
and is now the first of two clauses. Everything else in 0041 stands: the second
clause is written so that ordinary path divergence and an authentication failure
remain complete runs, which is what acceptance 36 was protecting.

### Why this restores ADR 0043 rather than contradicting it

ADR 0043 §6 withholds `TCP_CONNECTION_NOT_ESTABLISHED` on a sweep that did not
prove every path fails, and rests that on `Result.Incomplete()`, exit code 4 and
`unknownEvidenceCount` already reporting the run was cut short. Two of those
three were false for a per-step budget. Its disposition table already assigns
`tcp.connect UNKNOWN EXEC_LOCAL_TIMEOUT` the disposition *"INCOMPLETE — forces
Case C"*. This makes that premise true rather than changing it.

## 4. Where it is computed, and what it may not read

In `internal/app.incompleteRun`, over the frozen graph, from `State()` and
`FailureClass()` through domain accessors — plus one typed control-flow value,
whether `EstablishSession` returned a session.

It reads no finding, no severity, no `SummaryStatus`, no path count, no
`EvidenceID` spelling, no step name, no subject and no parent edge. There is no
`Origin`, no provenance inference and no new abstraction: the evidence stays the
canonical record of what happened, and orchestration keeps the one bit that is
about the run rather than about any node.

## 5. Status and incompleteness stay orthogonal

`SummaryStatus` answers *was a target-side ERROR or CRITICAL condition
diagnosed*. `Incomplete()` answers *did svcdoctor finish measuring*. A run may be
`OK` and incomplete, `PROBLEMS_FOUND` and complete, or neither.

No `SummaryStatus` special case was added, and severity was not used as a lever
to force an exit code — the same separation ADR 0046 §on severity insists on.
The future CLI keeps `docs/SCOPE.md`'s contract unchanged: exit 4 for an
incomplete run, exit 1 for an ERROR finding, exit 0 for a WARN one.

## 6. Duration

An interrupted step keeps its measured duration, and that duration means **how
long svcdoctor waited before its own limit stopped the step** — never that the
endpoint was slow. No threshold, no latency finding and no "slow" or "degraded"
wording exists or is authorized here.

## 7. Rejected alternatives

| Alternative | Why rejected | Reopen when |
|---|---|---|
| Any local `UNKNOWN` anywhere implies incomplete | Reports an ordinary dual-stack run as truncated while it holds a passing session; contradicts ADR 0041's deliberate multi-path measurement | Path selection stops continuing exactly one path |
| Keep `ctx.Err()` only, and document the gap | Leaves `docs/SCOPE.md`'s exit-4 contract false and ADR 0043 §6's premise broken | — |
| A mutable "budget exhausted" flag threaded through every stage | Five signatures changed to carry what the evidence already states per node; two sources of one fact | — |
| Infer incompleteness from the absence of findings | Couples execution to diagnosis, and an absent finding has many causes | — |
| Raise the no-credential or timeout severity to force exit 4 | Severity is the impact of a claim about its subject, not an exit-code lever; ADR 0046 settled this | — |
| A new `FailureClass` for a step-scoped timeout | `EXEC_LOCAL_TIMEOUT` already means svcdoctor's own budget expired, whichever budget it was | A consumer needs to tell the two budgets apart |

## 8. What would falsify this

- A report where a run that reached `ReadyForQuery` should have been called
  incomplete.
- A run reported incomplete that an operator would call finished.
- A local deadline reaching a target-side `FailureClass` at any PostgreSQL step.
