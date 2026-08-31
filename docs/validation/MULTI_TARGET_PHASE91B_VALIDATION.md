# Multi-target Phase 9.1B — execution, aggregate report and CLI

What Phase 9.1B built against the contract ADRs [0071](../decisions/0071-multi-target-configuration-schema.md)
to [0074](../decisions/0074-multi-target-report-and-exit-semantics.md) froze, what it
measured while building it, and what it deliberately did not build.

Phase 9.1A owns the configuration half: YAML, strict decoding, validated typed targets,
service-owned configs, credential references, preflight and the resolver boundary. This
phase adds the layer above it, and the invariant it obeys is the last clause of the
architectural rule:

> Probes collect facts. Adapters understand protocols. Diagnosis correlates evidence.
> Renderers explain results. **Multi-target orchestration schedules existing diagnoses.**

**There is no cross-target diagnosis, no dependency DAG, no discovery, no retry, no
remediation, no secret cache, no daemon mode and no target filtering.** Each is refused by
a guard rather than merely absent.

## 1. Start-state gate

Verified at `03e9337`, working tree clean, `make check` green.

| Invariant | At 9.1A | After 9.1B |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| Finding codes | 60 | **60** |
| RabbitMQ finding codes | 11 | **11** |
| Failure classes | 42 | **42** |
| `security.Reveal` sites | 4 | **4** |
| `Credential.SecretFor` sites | 4 | **4** |
| External modules | 2 | **2** |

The aggregate document has its **own** version constant, `domain.RunSchemaVersion = 1`.
Adding it changed `domain.SchemaVersion` not at all, and the single-target report gained no
field — not even a `kind` discriminator, because making a *different* document identifiable
is not a cost every existing consumer should pay (ADR 0074 §3).

## 2. Packages created and changed

| Package | Role |
|---|---|
| `internal/domain/runreport.go`, `executionstate.go` | `RunReport`, `TargetResult`, `RunSummary`, the four execution states, the two error classes, the stopped reasons, and the aggregate's JSON |
| `internal/fleet/run` | the scheduler: registry, budgets, cancellation, state classification, aggregation |
| `internal/fleet/services` | `Environment` — the three process values the four runners share |
| `internal/fleet/services/*` | each service's `Run`, bridging a validated target to its existing composition root |
| `internal/security/redaction/run.go` | `RedactRun` — one pseudonym table for the whole run |
| `internal/render/terminal/run.go`, `internal/render/json/run.go` | aggregate rendering |
| `internal/cli/run.go`, `exit.go` | `svcdoctor run --config`, and `RunExitCode` |
| `internal/security/trustsource` | **extracted**, so a fleet run and a leaf command load trust material through one implementation |

`internal/app` is unchanged. The four composition roots keep their signatures, their
validation and their credential-rebinding refusal; a service runner is a parameter mapping
and nothing more.

## 3. The service runner registry

```go
type Runner interface {
    Kind() string
    Run(ctx context.Context, target config.Target, credential security.Credential) (Outcome, error)
}
```

`Outcome` is `app.Result`'s two values restated, so the scheduler does not import
`internal/app` — which would pull every adapter, probe and diagnosis package into its build
graph and make the import guards unenforceable.

One type per service implements **both** `config.Factory` and `run.Runner`, so a service is
registered once. Registration is explicit, at the single composition point in
`internal/cli/run.go`. **The scheduler contains no service name at all**, proven by a guard
over its string literals, so a fifth service requires no edit to it, to the aggregate, to
the renderer or to the exit mapping.

## 4. Two executors, and why

`ExecuteSequential` is the reference: one target after another, no goroutine, no channel.
`Execute` is the production path and is bounded-concurrent. Both call one `execute`, which
differs only in worker count — so their agreement is a property of one implementation
rather than a coincidence between two.

`TestMTE20AndConcurrencyOneMatchesTheSequentialReference` compares their structured output
on a scenario mixing a success, a diagnostic failure, an incomplete report and a credential
resolution failure. `TestConcurrencyFourMatchesConcurrencyOne` does the same at 1 against 4
over six targets.

Both comparisons serialize and blank three fields: `startedAt` and `duration`, which are
measurements, and `concurrency`, which is the one field that is **supposed** to differ —
the aggregate records the pool size the run used. It describes how the run executed, not
what it found, and it is none of the things §23 names as a defect.

## 5. Budgets

```
run budget      run.timeout / --timeout      bounds the whole execution
  target budget targets[].timeout            derived from the run's context
    step budget targets[].step_timeout       passed through, unchanged
```

**A target's context is derived from the run's**, so "the earlier deadline always wins" is
structural rather than a comparison someone has to write correctly. `context.WithTimeout`
on a parent that is already closer never extends it, which is why mutation B14 — deriving
the target context from `context.Background()` — is caught rather than merely discouraged.

The scheduler implements **no step timing of its own**. It passes the frozen value to the
composition root, which already owns it, and a test asserts the runner receives it
unchanged.

Cleanup is bounded without a new timer: every started target runs under a context derived
from the run's and additionally capped by its own budget, so a worker cannot outlive the
smaller of the two. ADR 0073 §8 declines a separate cleanup budget for exactly that reason
— a second number would create a case where the two disagree. `wg.Wait()` is
unconditional, and there is no goroutine leak because there is nothing to leak.

## 6. Execution states

`COMPLETED`, `NOT_STARTED`, `CANCELLED`, `EXECUTION_FAILED`. Four, closed, and orthogonal to
`PASS/FAIL/DEGRADED/UNKNOWN/SKIPPED`.

The presence rules are constructor invariants, not conventions:

| State | `report` | `executionError` |
|---|---|---|
| `COMPLETED` | yes | no |
| `CANCELLED` | yes | no |
| `NOT_STARTED` | no | no |
| `EXECUTION_FAILED` | no | yes |

### 6.1 The classification decision, and its residual ambiguity

`CANCELLED` requires **both** that the run context is done and that the outcome is
incomplete. A target that finished fully in the instant before a cancellation landed is
`COMPLETED`, because it completed; testing the run context alone would relabel it on a race
that changed nothing about what was measured.

A target cut short by its **own** budget is `COMPLETED` with `Incomplete` true. It ran to
the end of its own budget and produced its own truthful report; that is the report's
business, and orchestration has nothing to add.

The residual ambiguity is stated rather than hidden: a target still running when the run
was cancelled *and* which would have been incomplete anyway is attributed to the run. Its
report carries what actually happened either way.

### 6.2 A never-started target carries nothing

No secret resolution, no DNS, no TCP, no TLS, no protocol, no report.
`TestMTE17NeverStartedTargetsInvokeNothing` proves it by counting: zero runner invocations
and zero resolver invocations for every `NOT_STARTED` target.

`StoppedReason` is recorded **once**, on the run. ADR 0074 §4.3: a run stops scheduling for
one reason, and copying it onto four hundred queued targets is four hundred copies of one
fact.

## 7. One defect found and fixed during implementation

**The resolver's error named the credential reference, and the scheduler put it in the
report.**

`internal/fleet/secret`'s `refErrorf` produced `credential env ORDERS_DB_PASSWORD: not
set` — correct for stderr, because ADR 0049 §3 requires a source svcdoctor cannot read to
be nameable to the person fixing it. The scheduler wrote `err.Error()` into the
`TargetResult`, which **is** serialized. ADR 0074 §4.2 forbids exactly that.

The fix is a typed error with two messages:

| Method | Names the reference | Destination |
|---|---|---|
| `Error()` | yes | stderr — ephemeral, local, read by the operator who owns the file |
| `SafeMessage()` | no | the canonical report — attached to tickets, pasted into chats |

The scheduler asks for the safe form through a one-method interface, so it needs no import
of the resolver's package, and it **fails closed**: an error offering no safe form gets a
fixed sentence rather than its own text. Defaulting to `err.Error()` would mean every
future error type leaks by omission — someone adds a source, forgets `SafeMessage`, and a
path appears in a document people paste into tickets.

## 8. Redaction across a run

One pseudonym table for the whole run (ADR 0074 §8.1). `Redact` was factored into
`redactWith(table, report)` so `RedactRun` can share assignments across every embedded
report, and the table gained `resetUsage` so each report's security metadata still
describes **its own** transformation rather than everything the run had replaced so far.

Target identifiers are pseudonymized in **declared order**, never sorted: numbering sorted
identifiers would make `target-001 … target-00n` encode the lexical ordering of the real
names, which is information this is removing.

They are deliberately **not** added to the prose replacement list. A target named `orders`
would otherwise rewrite the word "orders" wherever it appeared in a finding's detail —
mangling report text to hide a value that is not in report text.

## 9. CLI

```
svcdoctor run --config <file> [--timeout D] [--concurrency N] [--output text|json] [--shareable]
```

Every flag is run-global. There is no `--host`, `--port`, `--vhost`, `--broker`,
`--username`, `--type`, `--target` or `--filter`, and no `--password-file`,
`--password-stdin` or `--password-env`. `--config -` is refused with its reason.

Precedence is **CLI flag > the config's `run:` block > the built-in default**, decided once
in `applyRunOverrides` so the scheduler reads a single number. An override is validated
exactly as a configuration value is: there is no path by which `--concurrency 0` is
accepted because it arrived on the command line.

The four leaf commands are untouched, asserted flag by flag. Two Phase 9.1A guards were
**turned around rather than deleted**, the way the RabbitMQ contract-freeze guard was at
8.2: `TestTheRunCommandIsNotRoutedYet` became `TestTheRunCommandIsRouted`, and the root-help
guard moved `run` from its forbidden list to its required one.

## 10. Exit codes

The vocabulary is unchanged and no code was added. `docs/SCOPE.md`'s five, applied to a set,
with its own precedence `3 > 2 > 4 > 1 > 0`.

### 10.1 Reachability matrix

| Code | Meaning | Originating layer | Reachable after a valid config | Coexists with | Precedence reason |
|---|---|---|---|---|---|
| **0** | run completed, no target's report reached `PROBLEMS_FOUND` | run summary | yes | nothing | the base case |
| **1** | run completed, at least one did | run summary, folded from statuses the reports derived | yes | — | lowest positive signal |
| **2** | configuration or usage error; **no target dialled** | `config.ErrConfig`, `ErrUsage`, `app.ErrInvalidInput` | **no — it precedes execution** | never coexists with 0/1/4 | ADR 0071's all-or-nothing validation makes the combination unconstructable |
| **3** | svcdoctor failed and produced no usable aggregate | a non-config error, or a zero report with no error | rare | never with 0/1/4 | a tool failure is reported as a tool failure |
| **4** | an aggregate exists and the run is incomplete | any `NOT_STARTED`, `CANCELLED`, `EXECUTION_FAILED`, or any incomplete report | yes | **outranks 1** | incompleteness qualifies every conclusion |

**Unreachable combinations, pinned as unreachable.** 2 and 3 cannot coexist with a report,
because both mean no aggregate exists. A malformed configuration cannot coexist with a
successfully executed target: `LoadFile` returns a whole validated configuration or an
error, so `TestAConfigurationErrorDialsNothing` declares three valid targets and one
malformed and asserts **zero** executions. No synthetic runtime state was invented to
exercise a precedence pair that cannot occur.

### 10.2 The worked case

One target with a real authentication failure, one cut short locally, one success →
**exit 4**. `TestTheWorkedCaseKeepsItsFinding` additionally asserts that the finding stays
in the report and the status stays `PROBLEMS_FOUND`: incompleteness qualifies the
conclusion rather than erasing it.

**`EXECUTION_FAILED` contributes to 4, never to 3.** One target failing locally does not
make the aggregate unusable — the others were measured and their reports are truthful.

## 11. Rendering

The terminal renderer **composes**: every target that produced a report is shown by the
same `Write` a leaf command uses, indented under its heading. What the aggregate adds is
the frame — which target a section belongs to, what happened to targets that produced no
report, and the factual counts.

The three non-completed dispositions read differently on purpose (ADR 0074 §7.2, which
generalizes ADR 0052): *not measured* is never collapsed into *not reached*.

Neither renderer mentions any exit constant, proven by a guard over their source. Neither
imports `internal/diagnosis`, so cross-target inference is not something they could express.

The run summary is factual counts and nothing else.
`TestNeitherRunSummaryBranchDescribesTargetsAsHealthy` renders **all four** summary
branches and forbids `healthy`, `unhealthy`, `up`, `down`, `reachable`, `available` and
`root cause` as whole words in each.

## 12. Target concurrency is not a socket bound

Stated plainly because it is the honest limit of what ADR 0073 authorizes.

`concurrency: 16` means at most sixteen targets in flight. It does **not** mean sixteen
sockets: one target opens a connection per resolved address and holds every completed one
until a path is selected, and a Kafka target additionally sweeps its advertised brokers
credential-free.

ADR 0073 §10.1 declines a global probe semaphore in this phase, and this phase did not add
one. The 16 ceiling is derived against a *pessimistic estimate* of per-target fan-out
rather than a measurement of it. That remains the open item ADR 0073 §15.1 records, with
its reopen condition: a measured descriptor overrun, or a service that fans out further
than Kafka.

**No compatibility or safety claim is made beyond that.**

## 13. Test results

### 13.1 Execution matrix

| ID | Case | Result |
|---|---|---|
| MT-E01 | all four targets complete | pass |
| MT-E02 | one remote auth failure is a COMPLETED execution | pass |
| MT-E03 | one local timeout is COMPLETED + incomplete | pass |
| MT-E04 | credential resolution failure, no report, no fabricated evidence | pass |
| MT-E05 | run budget exhausted before all targets start | pass |
| MT-E06 | cancellation with completed, active and queued targets | pass |
| MT-E07 | deterministic output under a chosen completion order | pass |
| MT-E08 | duplicate endpoints as distinct executions | pass |
| MT-E09 | one reference, two independent resolutions, two endpoints | pass |
| MT-E10 | concurrency = 1 | pass |
| MT-E11 | maximum concurrency, observed ≤ pool size at 1, 2, 4 and 16 over 64 targets | pass |
| MT-E12 | invalid concurrency refused before anything runs | pass |
| MT-E13 | a diagnostic failure does not fail-fast | pass |
| MT-E14 | an execution failure does not fail-fast | pass |
| MT-E15 | the run deadline dominates a one-hour target deadline | pass |
| MT-E16 | a target deadline does not cancel a sibling | pass |
| MT-E17 | a never-started target invokes neither runner nor resolver | pass |
| MT-E18 | a cancelled active target keeps its partial report | pass |
| MT-E19 | preflight/Resolve TOCTOU is a local failure, never an auth finding | pass |
| MT-E20 | concurrency 1 ≡ the sequential reference | pass |

### 13.2 Determinism

| ID | Case | Result |
|---|---|---|
| MT-D01 | declared order preserved, and preserved under **mixed** execution states | pass |
| MT-D02 | worker completion order never reaches the report | pass |
| MT-D03 | findings unchanged — an embedded report is byte-identical to the same single-target run | pass |
| MT-D04 | target identifiers stable | pass |
| MT-D05 | the aggregate is structurally identical across 20 repeated concurrent runs | pass |

### 13.3 Security

| Requirement | Result |
|---|---|
| secret absent from terminal, JSON, shareable and stderr | pass, both credential sources, four invocations |
| secret absent from every execution-error path | pass |
| no cross-target secret reuse | pass — two targets, one reference, two endpoint-bound credentials, neither usable at the other's endpoint |
| no `Reveal` in the fleet layer | pass |
| no `SecretFor`, `os.Getenv`, `os.ReadFile` or `os.Open` in the scheduler | pass |
| no adapter, wire, diagnosis, probe or render import in the scheduler | pass |
| no raw configuration serialized | pass |
| no credential reference, env name or file path serialized | pass |
| one pseudonym table per run | pass — one host in two targets receives one pseudonym; a third host receives a different one |

## 14. Mutation closure — 31 planted, 31 caught, 0 survivors

`scripts/phase91b-mutations.sh`, restored byte-for-byte by sha256.

**The first run had seven survivors, and that is the more useful result.** Four were real
guard gaps and two were ineffective plants; all six were fixed and the closure re-run.

| Survivor | Diagnosis | Fix |
|---|---|---|
| B06 cache by reference | **Real gap.** `TestTheFleetLayerHasNoSecretCache` scanned the two packages that existed when it was written; the scheduler — the layer that actually holds several credentials at once — was outside it | the guard now scans `internal/fleet/run` |
| B21 / B23 `SafeMessage` leaks | **Real gap.** The scheduler's test proved which method it *calls*, using a fake. Nothing proved the real `ResolutionError`'s safe form is safe | a test on the real type, both sources, plus `%#v` |
| B08 sort by status | **Real gap.** The ordering test declared five targets that all COMPLETE, so a stable sort by state is a no-op on it | a determinism test mixing all four dispositions, which asserts the sorted order differs from the declared one |
| B29 "N targets healthy" | **Real gap.** The wording test rendered a run that reached `PROBLEMS_FOUND`, so the OK branch was never executed | render all four summary branches directly |
| B03 calls `Reveal` | Ineffective plant: `_ = security.Reveal` is a function *reference* and the guard looks for a call | plant a real call |
| B12 fake report | Ineffective plant: `CompletedTarget` refuses a zero report, so it fell through to `NotStartedTarget` | attribute **another target's** report, which is the fabricated-evidence failure the mutation is about |

The remaining mutation — a hanging target — also exposed a script defect: `go test`'s
10-minute default was being waited out. Every mutation test now runs under `-timeout 90s`.

## 15. Integration validation

Seven existing suites plus the new multi-target one, sequentially, each with teardown.

| Suite | Result | Duration | Skips | svcdoctor containers left |
|---|---|---|---|---|
| PostgreSQL | **PASS** | 28 s | 0 | 0 |
| Kafka | **PASS** | 269 s | 0 | 0 |
| Redpanda | **PASS** | 6 s | 0 | 0 |
| Redis | **PASS** | 7 s | 0 | 0 |
| Valkey | **PASS** | 3 s | 0 | 0 |
| RabbitMQ | **PASS** | 91 s | 0 | 0 |
| LavinMQ | **PASS** | 5 s | 0 | 0 |
| **Multi-target** | **PASS** | 49 s | 0 | 0 |

Zero unexpected skips. Eight stopped containers remain on the machine, all of them
unrelated to svcdoctor and months old; no `svcd-*` container survives any suite.

### 15.1 The multi-target suite found a real thing, and it was the test that was wrong

The first version pointed every credential-bearing target at a **plaintext** listener. Two
scenarios failed with `REDIS_CREDENTIAL_WITHHELD` and `POSTGRES_CREDENTIAL_WITHHELD`.

That is the product working exactly as ADR 0029 and ADR 0030 require: a password crosses
only a channel whose peer identity was verified, the refusal is a policy skip, and **zero
bytes derived from the credential reach the wire**. The fleet path inherits that from the
composition roots without restating it, which is the property worth having.

`--tls-insecure` would not have helped either: the policy reads *verification*, not
encryption, and an unverified channel is still not a verified one.

So every credential-bearing scenario now points at that fixture's TLS listener and supplies
its CA, and each asserts that no `*_CREDENTIAL_WITHHELD` finding appears — because a
withheld credential means the scenario proved nothing about authentication. With that fixed,
`TestARemoteRefusalDoesNotDisturbOtherTargets` observes a real
`REDIS_CREDENTIALS_REJECTED` while PostgreSQL and RabbitMQ complete `OK` beside it, and
`TestDuplicateEndpointsAreTwoExecutions` observes `POSTGRES_DATABASE_NOT_FOUND` on one of
two targets sharing an endpoint.

The multi-target suite composes the four existing fixtures rather than adding a fifth. It
proves **composition**: one file, four services, four composition roots, four canonical
reports in declared order, and a remote refusal in one target leaving the other three
alone. It proves **no protocol behaviour** — every protocol claim is owned by that
service's own suite, and re-asserting any of it here would create a second place for those
claims to drift.

LavinMQ, Redpanda and Valkey are absent from it for the same reason: compatibility is owned
by the service-level suites, and a compatibility claim does not become stronger by being
made twice. **No compatibility level changed in this phase.**

## 16. Quality gate

| Check | Result |
|---|---|
| `git diff --check` | clean |
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `golangci-lint run` | 0 issues |
| `go test ./...` | pass |
| `go test -race ./...` | pass |
| `CGO_ENABLED=0 go build ./...` | pass |
| `go mod tidy` | no-op |
| `make check` | pass |

## 17. What Phase 9.1C may implement

Nothing in this phase decided it. The open items it leaves are:

- **A global probe semaphore**, if a measured descriptor overrun or a wider-fanning service
  justifies one (ADR 0073 §10.1).
- **Second-signal hard-abort semantics.** ADR 0073 §7.2 froze exit 3 on a second interrupt;
  9.1B implements the first-signal contract only, and the CLI's signal integration is the
  thin layer `cmd/svcdoctor` already provides.
- **Filtering** — `--target`, `--type` — which ADR 0074 §10.4 leaves out of v1 and for which
  no flag name is reserved.
- **Output to a file**, which ADR 0074 §11 records as not needed by this phase.
