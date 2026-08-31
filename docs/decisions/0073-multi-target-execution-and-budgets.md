# ADR 0073: Targets are independent, bounded, and ordered by the file

## Status

**Accepted in Phase 9.0. Not implemented.**

It decides how many targets run at once, how the three budget levels compose, what a
cancellation means, what happens to a target that never starts, and what bounds a run's
resource use.

`SchemaVersion` stays **1**. No `FailureClass`, no `FindingCode`, no dependency, and **no
run-level finding of any kind** — §12.

Companion records: [0071](0071-multi-target-configuration-schema.md) is the schema,
[0072](0072-multi-target-credential-references.md) decides credential resolution timing,
[0074](0074-multi-target-report-and-exit-semantics.md) decides what the run reports.

It applies ADR 0047's local-incompleteness contract to a set of runs and does not change
it.

## 1. Decision summary

1. **Targets are independent.** No dependency graph, no ordering constraints, no fail-fast.
2. **A bounded worker pool.** Default concurrency **4**, maximum **16**, both derived.
3. **Three budgets — run, target, step — and the earlier deadline always wins**, because a
   target's context is derived from the run's rather than being a peer of it.
4. **Report order is declared configuration order**, always, whatever order execution
   completed in.
5. **A target that never started is recorded as never started.** It acquires no fabricated
   evidence and no finding.
6. **The first interrupt stops scheduling, cancels what is in flight, and still produces an
   aggregate report.**
7. **512 targets and 1 MiB of configuration**, derived in §11 from measured report sizes.
8. **Target concurrency does not bound sockets**, and v1 does not add a global probe
   semaphore. This is a stated limitation, not an oversight — §10.

## 2. Independence

A target is a complete diagnosis of one endpoint. It shares no session, no connection, no
credential, no evidence builder, no graph, no report and no adapter state with any other
target.

**No dependency DAG in v1.** Ordering constraints between targets would mean svcdoctor had
a model of which service depends on which — and it does not, cannot measure one, and would
be inventing the cross-target causal inference ADR 0074 §7 forbids the renderer from
producing. "Diagnose the database before the queue" is a scheduling preference with no
diagnostic content: neither result changes based on the other.

**No fail-fast in v1.** One broken target must not prevent the diagnosis of unrelated ones,
which is the entire reason an operator put them in one file. A run where target 2 fails and
targets 3 through 40 are never attempted is strictly less useful than one that measures all
40, and it is *more* misleading, because the unmeasured targets look identical to targets
that were fine.

If fail-fast is ever wanted it will be for CI, and CI's actual need is an exit code, which
ADR 0074 §6 already supplies without stopping anything early. **Nothing is reserved for
it** — no flag name, no field, no state.

## 3. Concurrency

| | Value |
|---|---|
| Default | **4** |
| Minimum | 1 |
| Maximum | **16** |
| `concurrency: 0` | **configuration error** |
| Negative, or above 16 | **configuration error** naming the range |
| CLI override | `--concurrency`, which beats the config's `run.concurrency`, which beats 4 |

### 3.1 Why 4, and why not the CPU count

Concurrency here is a **safety control before it is a performance flag**. It decides how
much simultaneous diagnostic load a single operator command puts on shared production
infrastructure.

Deriving it from `runtime.NumCPU()` would make that load vary with the machine: 2 on a CI
runner, 12 on a workstation, 96 on a build host. The same file, run by two people against
the same cluster, would produce two different amounts of load — and the larger one is
produced by the machine that has the least reason to need it, since this work is
network-bound and not CPU-bound.

So the default is a fixed number, and machine-independence is the property being frozen. 4
is small enough that a fleet run against one cluster does not resemble an incident, and
large enough that the wall-clock improvement over sequential execution is real. An operator
who knows their infrastructure raises it.

### 3.2 Why the maximum is 16

The ceiling exists because §10 is true: target concurrency does not bound sockets, so the
ceiling is what makes a socket bound hold at all.

The derivation:

- A container's default file-descriptor soft limit is commonly **1024**. That is the number
  to design against, not the 1048576 a developer workstation happens to offer.
- Per-target peak descriptor use is bounded by the transport sweep, which dials every
  resolved address sequentially but **holds every completed connection open** until one is
  selected. Kafka is the worst shape, adding a credential-free sweep of every advertised
  broker. A conservative per-target peak is **32** sockets.
- Reserve ~64 descriptors for stdio, the resolver, the trust store and the runtime.
- `16 × 32 = 512`, half of 1024, against a per-target estimate that is already generous.

A 2× margin over a pessimistic estimate of the worst service is the right amount of
caution for a bound whose violation is a run that fails partway through for a reason that
has nothing to do with any target.

### 3.3 `concurrency: 0` is an error, not a meaning

Zero has two plausible readings — "unlimited" and "use the default" — and one of them is
dangerous. An operator who wrote `0` typed something; refusing it costs them one edit and
removes a reading under which a 512-target file opens every connection at once.

### 3.4 What concurrency must not change

Not evidence identifiers, not finding order within a report, not target order in the
aggregate, not credential authority, not any per-target timeout, and not the meaning of any
value in any report.

A run at concurrency 1 and the same run at concurrency 16 differ in wall-clock time and in
nothing else that is written down. §6 is how that is made true rather than hoped for.

## 4. The three budgets

```
run budget        run.timeout / --timeout       bounds the whole execution
  └─ target budget  targets[].timeout           bounds one app.DiagnoseX call
       └─ step budget  targets[].step_timeout   bounds one probe call or protocol exchange
```

### 4.1 Composition, and why it cannot be got wrong

A target's context is **derived from the run's context**:

```
runCtx    = WithTimeout(rootCtx, runTimeout)      // only when run.timeout is set
targetCtx = WithTimeout(runCtx, targetTimeout)
```

This is not a comparison, a `min()` or a precedence rule. It is the structure, and it makes
the required property automatic: **the earlier deadline always wins, and a target budget can
never extend the run's**. A target that starts 20 seconds before a run deadline gets 20
seconds, not its full 30.

"Target timeout overrides the global deadline" is one of the mutations Phase 9.1 must plant.
With this construction it cannot be written without deriving the target context from the
root instead — a one-line change that is visible in review and caught by a test that runs a
short run budget against a long target budget.

### 4.2 Defaults

| Budget | Default | Source |
|---|---|---|
| `run.timeout` | **unset** | §4.3 |
| `targets[].timeout` | **30 s** | The existing `--timeout` default on all four commands |
| `targets[].step_timeout` | **10 s** | The existing `--step-timeout` default on all four commands |

Both target-level defaults are inherited unchanged from the leaf commands, so a target
written with no budgets behaves exactly as the equivalent single-target invocation does
today. That is the property that makes a fleet file a faithful description of four
invocations rather than an approximation of them.

Service-owned validation still applies: a RabbitMQ target's `step_timeout` must exceed 3 s
(ADR 0070 §8, ADR 0071 §7.4). The 10 s default satisfies it.

### 4.3 `run.timeout` has no default, and the run is still bounded

An arbitrary run default would silently truncate large files: at concurrency 4 and a 30 s
target budget, 40 targets need 300 s in the worst case, so any fixed default would decide
in advance how big a file is allowed to be.

The run is bounded regardless, and the bound is **derived rather than declared**:

```
worst case  ≈  ceil(targets / concurrency) × target_timeout  +  cleanup
```

Every term is frozen: `targets` ≤ 512 (§11), `concurrency` ≥ 1, `target_timeout` is set per
target. There is no unbounded run, and no arbitrary number was invented to say so. This
satisfies the execution semantics in `CLAUDE.md` — *every run has a local execution budget*
— with a computed budget instead of a guessed one.

An operator who needs a tighter bound sets `run.timeout`, and CI usually should.

### 4.4 One validation rule on `run.timeout`

If set, it must be **at least the largest `targets[].timeout` in the file**. Otherwise no
target can complete, and every target in the run is guaranteed to be cut short by a
configuration that looks deliberate. It is a configuration error naming both values.

## 5. Run budget exhaustion, and the target that never started

When the run deadline passes with targets still queued:

- **Queued targets are `NOT_STARTED`.** They are not failures, not remote failures, not
  `SKIPPED` evidence, and not findings.
- **They acquire no evidence graph at all.** No `target.requested` node, no `dns.lookup`
  node, no fabricated anything. Nothing was measured, so nothing is recorded — which is
  ADR 0059's reasoning about IP-literal targets applied to a different absence: *absence is
  the truthful representation*, and a node whose every state describes how an operation went
  cannot describe an operation that never began.
- **In-flight targets are cancelled** and keep whatever their composition root returned.
- **The run is incomplete**, and ADR 0074 §6 maps that to exit 4.

**No `FailureClass` and no `FindingCode` is created for this.** A never-started target is an
orchestration disposition, and the aggregate report expresses it in the execution-state
field ADR 0074 §4 defines. Minting `EXEC_NOT_STARTED` would put an orchestration fact into a
vocabulary that describes measurements, and every existing consumer of that vocabulary would
have to learn that one member of it never involved a network.

The counts stay at 60 finding codes and 42 failure classes.

## 6. Determinism

Execution order is nondeterministic. Output is not.

| Aspect | Rule |
|---|---|
| Target order in the report | **declared configuration order**, always |
| Findings within a target | the existing canonical finding order, untouched |
| Evidence within a target | the existing canonical `EvidenceID` order, untouched |
| Run summary counts | derived from the ordered target list |
| JSON key order | fixed by struct field order, as the existing report already is |
| Map iteration | **none**, anywhere in the fleet layer |
| Worker completion order | **never observable** in any output |

### 6.1 Why declared order and not sorted by ID

Both are deterministic and both give stable golden tests, so the tiebreak is elsewhere.

**The operator's own arrangement is the only structure the file has.** A fleet file is
grouped deliberately — all of production, then all of staging; the data path, then the
queue — and re-sorting alphabetically destroys the one piece of information the operator
put there by hand. The report is read next to the file that produced it.

**There is a second, security-flavoured reason.** Under `--shareable`, target IDs are
pseudonymized (ADR 0074 §8). If targets were sorted by their real IDs and then
pseudonymized, the sequence `target-1, target-2, …` would encode the **lexical order of the
real names**, which is a small but genuine leak from a document whose whole purpose is not
to leak. Declared order encodes only the order the operator wrote, which the redacted report
is entitled to show.

The counter-argument — that sorted order is stable when the file is reordered, which helps
when diffing two runs — is real and lost. Reordering a fleet file is rare; reading a report
beside it is every time.

### 6.2 The structural consequence

Targets are held in a **slice**, from decode through execution to serialization. There is no
point at which they live in a map, so "map iteration changed the report order" is not a bug
that can be fixed but a program that cannot be written. Results are written back by index.

## 7. Cancellation

### 7.1 First interrupt

1. **Stop scheduling.** Queued targets become `NOT_STARTED`.
2. **Cancel in-flight target contexts.** Cancellation propagates through the context every
   probe and every protocol exchange already takes.
3. **Wait, bounded.** The bound is the **target budget**, which is already frozen — no new
   constant. A target that observes cancellation returns essentially immediately, and a
   target that somehow does not is bounded by its own budget regardless.
4. **Keep everything already collected.** A cancelled target's composition root still
   returns a report: the transport chain records what it measured, the graph is frozen,
   diagnosis runs, and `Result.Incomplete()` is true. That report is kept.
5. **Emit the aggregate report** and exit 4.

**A cancelled target is not a failing target.** The operator stopped svcdoctor; the endpoint
did nothing. This is ADR 0047's distinction — *"a local deadline expiring is not proof of
remote failure"* — at run scope, and getting it backwards would have svcdoctor report a
production database as broken because someone pressed Ctrl-C.

### 7.2 Second interrupt

Immediate termination, exit **3**, one line on stderr saying the run was forcibly aborted.
No aggregate report is guaranteed.

Exit 3 is right because svcdoctor produced no usable diagnosis, which is exactly what
`docs/SCOPE.md` says code 3 means. The alternative — leaving the process to the default
signal disposition and exiting 130 — was rejected because it steps outside the 0–4 exit
vocabulary the whole contract is stated in, and a CI script that switches on svcdoctor's
exit code would meet a value no document defines.

## 8. Cleanup

Frozen expectations for every started target:

- it receives cancellation through its own context;
- its sockets close, on every path out, through the `defer`s the composition roots already
  hold;
- its credential goes out of scope when its execution returns;
- its worker returns to the pool.

The runner waits for in-flight work with the bound in §7.1 step 3 and **never waits
indefinitely** on one target. No goroutine outlives the run, and no worker outlives the pool.

Cleanup is bounded by the target budget rather than by a new cleanup budget, because the
work it waits for is bounded by that budget already. Inventing a second number would create
a case where the two disagree.

## 9. Duplicate endpoints

Two targets may name the same endpoint. This is supported and is the ordinary case:

| Same endpoint, different… | Example |
|---|---|
| database | one PostgreSQL server, `orders` and `billing` |
| virtual host | one RabbitMQ broker, `/production` and `/staging` |
| credentials | one Redis instance, two ACL users |
| identity | one Kafka bootstrap, two principals |

Frozen:

- **No deduplication by endpoint.** Ever, and not as an optimization.
- **No result sharing.** Each target is diagnosed independently and gets its own report.
- **No shared connection.** Two targets against one endpoint open two connections, which is
  what two clients would do and therefore what svcdoctor must do to answer either question.
- **Target IDs distinguish them** — which is why ADR 0071 §5.3 refuses to make the endpoint
  identity.

The cost is one extra connection per duplicate. The alternative would be a report in which
two targets share evidence gathered under one of their credentials, which is a correctness
failure and, for the credential case, an authority failure.

## 10. Target concurrency does not bound sockets

This is stated because it is true and easy to assume otherwise.

A single target fans out internally:

- a name resolving to N addresses produces N TCP attempts, and every completed connection
  is **held open** until one path is selected;
- with TLS requested, each of those becomes a handshake too;
- Kafka additionally sweeps every advertised broker, each of which resolves to its own
  addresses.

So `concurrency: 16` does not mean 16 sockets. §3.2 derives the ceiling from a pessimistic
per-target peak precisely because of this.

### 10.1 v1 does not add a global probe semaphore

Two designs were weighed:

**A — bound target concurrency only.** What §3 decides. Simple, one control the operator
understands, no change to any existing package.

**B — additionally bound total in-flight probes** with a semaphore threaded through the
transport chain.

**A is chosen.** B would put a run-level resource control inside `internal/probe/transport`,
which is a Phase 2 package that knows nothing about runs and must not learn — and it would
change the behaviour of the four existing single-target commands, which have no such
problem, to solve a problem only fleet mode has. A ceiling derived against the worst
plausible fan-out (§3.2) achieves the same bound without any of that.

**Recorded as a known limitation:** the socket bound rests on an estimate of per-target
fan-out rather than on a measurement of it, and a service with a much larger fan-out than
Kafka's advertised sweep would invalidate the arithmetic rather than trip a guard. B is
reopened if a measured run exceeds the descriptor budget, or if a fifth service fans out
further. `docs/BACKLOG.md` carries it with that condition.

## 11. Resource bounds

### 11.1 Measured inputs

Phase 9.0 measured canonical JSON report sizes from a release-shaped binary — the full
table is in the study:

| Shape | Bytes |
|---|---|
| 1 address, no TLS | 2,375 |
| 2 addresses, no TLS | 3,023 |
| 2 addresses, TLS | 3,824 |

So an envelope plus one path is ≈ 2.4 KB, each additional address costs ≈ 0.65 KB, and each
additional TLS path ≈ 1.05 KB. All four services land in the same band for a comparable
shape.

### 11.2 The per-target ceiling: 64 KiB

The worst realistic single report is a Kafka run whose bootstrap resolves to several
addresses and whose advertised sweep adds a dozen brokers with their own addresses — on the
order of 50 transport paths:

```
2.4 KB  +  50 × 1.05 KB  ≈  55 KB
```

**64 KiB** is that, rounded up to the next power of two. It is roughly 6× the ordinary
single-endpoint report and covers the largest shape the current adapters can produce.

### 11.3 The target ceiling: 512

The aggregate report is built fully in memory (§11.5), so accumulated reports are what
bounds the target count — not descriptors, which §3.2 bounds through concurrency and which
are independent of how many targets exist.

Budgeting **32 MiB** for accumulated target reports:

```
32 MiB / 64 KiB = 512 targets
```

32 MiB is chosen against the smallest common CI container limits (256–512 MiB), leaving room
for the process itself and for the JSON encoder's working copy, which roughly doubles peak
use at serialization time — so a full 512-target run peaks near 96 MiB, not 32.

**512 also comfortably exceeds any hand-maintained file.** At ~20 lines per target, 512
targets is a 10,000-line configuration. The bound is a resource ceiling, not a product
limit, and no realistic operator workflow meets it.

### 11.4 The file ceiling: 1 MiB

512 targets × a generous 2 KiB per fully-specified, commented target block. It happens to
equal the existing `maxCAFileSize`, which is a consistency worth having rather than a
coincidence worth hiding.

### 11.5 The aggregate is built in memory, and no streaming is added

At the ceiling the whole aggregate is ~32 MiB, which is well inside any environment
svcdoctor runs in. Streaming JSON would buy nothing and cost the ability to derive the run
summary from the finished target list — a derivation ADR 0074 §5 requires and ADR 0015's
reasoning demands.

Documented honestly: **aggregate size scales linearly with target count**, and §11.3 is what
keeps that finite.

## 12. No run-level findings

**No `FindingCode` is created by this record or by Phase 9.1.** The count stays at 60.

A finding is a diagnostic conclusion about a target, drawn from evidence, carrying a
severity, a confidence and the evidence identifiers that produced it. A configuration error
has no evidence, no target-side subject and no vantage. An exhausted run budget is a fact
about svcdoctor's own execution.

Both are expressed in execution metadata — ADR 0074 §4 and §5 — which is exactly where the
existing contract already puts svcdoctor's own limits: `Result.Incomplete()` is not a
finding either, and `docs/REPORT_SCHEMA.md` §8 keeps exit codes 2, 3 and 4 out of the
summary for the same reason.

Inventing `RUN_CONFIGURATION_INVALID` would make a configuration error into a claim about a
service, which is the confusion the whole distinction between a configuration error and a
diagnostic failure exists to prevent.

## 13. Cross-target state

| Shared | Allowed | Note |
|---|---|---|
| The validated configuration | yes | immutable after validation |
| The worker pool | yes | carries no per-target data |
| The registry of service factories | yes | immutable, built once at the composition point |
| A resolver or dialer value | yes | the same stateless `dns.SystemResolver{}` / `tcp.SystemDialer{}` the leaf commands already share within a run |
| A connection or session | **no** | |
| A credential or secret | **no** | ADR 0072 §7 |
| An evidence builder or graph | **no** | |
| A report | **no** | |
| Adapter state of any kind | **no** | |

The runner holds one results slice, written by index, with each element written exactly once
by the worker that owns that target. There is no shared mutable structure a second worker
can observe.

## 14. Rejected alternatives

| Alternative | Reason | Reopen condition |
|---|---|---|
| Dependency DAG between targets | svcdoctor has no dependency model and cannot measure one; neither result changes based on the other | A measured case where one target's result must gate another's |
| Fail-fast | Prevents the diagnosis of unrelated targets, and the unmeasured ones look like healthy ones | A CI need that the exit code cannot serve |
| Concurrency from `runtime.NumCPU()` | Makes production load depend on the operator's laptop | None |
| `concurrency: 0` meaning unlimited | The dangerous reading of an ambiguous value | None |
| A default `run.timeout` | Silently decides how large a file may be | None |
| Sorting the report by target ID | Destroys the operator's grouping, and leaks lexical order through pseudonyms | If IDs stop being operator-chosen |
| A global probe semaphore | §10.1 | A measured descriptor overrun, or a service with a larger fan-out |
| A new failure class for never-started | Puts an orchestration fact into a measurement vocabulary | None |
| Streaming the aggregate report | Buys nothing at 32 MiB; prevents deriving the summary | A measured need for far more than 512 targets |
| Retrying a failed target | A retry destroys the evidence topology findings depend on, which is ADR 0008's reason for a controlled connection lifecycle | None |

## 15. Reopen conditions

1. A measured descriptor overrun, or a fifth service whose fan-out exceeds §3.2's estimate
   — reopens §10.1.
2. A measured need for more than 512 targets — reopens §11.3's memory budget first, and
   §11.5's in-memory decision second.
3. A CI requirement the exit-code contract genuinely cannot express — reopens §2's
   fail-fast decision, and nothing else.
4. Evidence that declared order is the wrong default for how reports are actually read —
   reopens §6.1, which is the one decision here made on a tiebreak rather than on a
   constraint.
