# Multi-target Phase 9.1C — adversarial closure

What Phase 9.1C measured, what it found, and what it changed. It is a validation and
hardening phase: no new product feature, no new service, no new configuration capability, no
new credential source, no new finding code, no new failure class, no new report semantics.

The companion document is
[`MULTI_TARGET_PHASE91_TRACEABILITY.md`](MULTI_TARGET_PHASE91_TRACEABILITY.md), which maps all
108 frozen requirements to executable proofs.

## 1. Start-state gate

Verified mechanically at `9f9ce8b`, working tree clean, before anything was edited.

| Invariant | Expected | Measured |
|---|---|---|
| `domain.SchemaVersion` | 1 | **1** |
| `domain.RunSchemaVersion` | 1 | **1** |
| Finding codes | 60 | **60** |
| RabbitMQ finding codes | 11 | **11** |
| Failure classes | 42 | **42** |
| `security.Reveal` production sites | 4 | **4** |
| `Credential.SecretFor` production sites | 4 | **4** |
| External modules | 2 | **2** |

`svcdoctor run --config` exists, all four leaf commands exist, no `--password-env` flag
exists, no fleet secret cache exists, no run-level finding code exists, no cross-target
diagnosis exists. `make check` passed.

Per-namespace codes, counted from the syntax tree: DNS 2, TCP 1, TLS 5, Kafka 13, PostgreSQL
19, Redis 9, RabbitMQ 11 — **60**.

## 2. The four defects

Phase 9.1C found four things. Three are product defects and one is a fixture defect; all four
were fixed narrowly, each with a regression, and each is recorded here with **why the previous
test surface could not see it**.

### 2.1 The second interrupt was swallowed entirely

ADR 0073 §7.2 froze a two-stage interrupt contract: the first signal cancels the run and it
finishes truthfully at exit 4; the second aborts immediately at exit **3**, because svcdoctor
produced no usable diagnosis and 130 is outside the vocabulary the whole exit contract is
stated in.

`cmd/svcdoctor` used `signal.NotifyContext`, which collapses every signal onto one
cancellation and keeps its handler installed for the process's life. The second interrupt
therefore cancelled an already-cancelled context and **did nothing at all** — Go's default
handler never ran either, so an operator who wanted out could not get out.

Phase 9.1B recorded this as an open item rather than a gap. The reconciliation disagrees: MT-E07
and MT-R04 are frozen requirements with no proof, and §37 requires missing = 0.

`internal/cli/interrupt.go` implements it. `cmd/svcdoctor` now delivers signals on a buffered
channel and hands the decision to `internal/cli`, which owns the exit code and the message
(ADR 0048 §3).

**Why nothing caught it:** no run test owned a signal. Signal handling lived entirely in
`cmd/svcdoctor`, which had one test file about version resolution.

**The non-obvious part**, recorded because the first implementation had it wrong: the watcher
cannot wait on the run's context in its second stage. It has just cancelled that context
itself, so the wait returns immediately and the second signal is never observed.
`TestTheWatcherDoesNotWaitOnTheCancelledContext` is the regression for exactly that.

**Measured side note.** POSIX coalesces a non-realtime signal that is already pending, so two
`SIGINT`s raised before the runtime dequeues the first arrive as one. That is an operating
system property, not svcdoctor's, and the interval between two deliberate Ctrl-C presses is
orders of magnitude larger than the window. `TestTheDeliveryChannelHoldsBothStages` records
the measurement rather than asserting the false version of it.

**This changes released behaviour for the four leaf commands as well**, and deliberately: a
second interrupt now exits 3 rather than being ignored. Applying it process-wide is simpler
and safer than a command-conditional, and `cmd/svcdoctor` is bootstrap that must not know
which command is running.

### 2.2 A missing environment variable exited 3 instead of 2

A credential reference that fails at **preflight** is a *configuration error*: ADR 0072 §5 and
the Phase 9.0 terminology both say so — "a defect in the file or in a credential reference at
preflight. Exit 2, zero targets dialled, no report" — and MT-C09 through MT-C12 sit in the
configuration family, whose exit is 2.

`RunExitCode` classified `secret.ErrResolution` as neither usage nor configuration, so it fell
to the default: **exit 3**, which means *svcdoctor itself failed*. It had not. The tool worked
perfectly; the operator had not exported a variable. A CI pipeline switching on the code would
have been told its tooling was broken.

Fixed in `internal/cli/exit.go`. The other `ErrResolution` path — a reference that resolves at
preflight and fails at execution — never reaches this function: it is captured inside a
`TargetResult` as `EXECUTION_FAILED` and the aggregate decides the code, so the branch cannot
swallow a genuine execution failure.

**Why nothing caught it:** the assertion read `if code != ExitInternal && code != ExitUsage`.
A test that accepts two codes cannot detect the wrong one. It is now exact.

### 2.3 The credential-file success path had no leakage test

`TestMTS04NoSecretValueReachesAnError` covered four refusals — empty env, missing env, missing
file, directory — and every one of them fails because the material is *absent*. There was no
value to leak in any case, so the absence assertion was satisfied by there being nothing to
find.

Mutation **C09**, which turns a successful environment resolution into an error naming the
value, survived the whole test. A success-path case with the canary present now exists.

### 2.4 The RabbitMQ fixture provisioned no users, silently

Every command in the Makefile's `rabbitmq-users` target ended in `|| true`.
`rabbitmq-diagnostics ping` answers before the broker will accept `rabbitmqctl add_user`, so
on a cold start the `app` principal was **not created** and nothing said so. Three multi-target
scenarios then failed with `RABBITMQ_CREDENTIALS_REJECTED` against a broker that simply had no
such user.

This is a fixture defect, not a product one — the product correctly reported that the
credential was refused. But a gate that can silently fail to provision is a gate that can
report a wrong answer, so provisioning is now retried until it takes and then **verified**,
and the target fails loudly if it cannot.

## 3. Hostile YAML corpus

`internal/fleet/config/hostile_test.go`: 38 adversarial documents plus three resource-shaped
cases, each asserted against four properties at once — no panic, either a classified
`config.Error` or a valid `Config`, no library-interpolated value in the message, and no
network.

Covered: duplicate root and nested keys, merge keys, aliases, anchors, recursive aliases,
custom and non-core tags, multi-document files, a trailing `---`, null/scalar/sequence
credentials, both sources and neither, unknown sources, unknown fields at every level, unknown
service types, unsupported and absent versions, every target-ID grammar violation, duplicate
IDs, zero targets, tab indentation, malformed UTF-8, an embedded NUL, 200-deep nesting, a
900 KiB scalar, a 20,000-key service node, and four strings that *look* like syntax and are
not.

**All 38 behaved.** The four accepted cases are accepted correctly: a comment containing
`<<:`, a quoted string containing `<<:`, a quoted `${VAR}` and a quoted `&anchor` are data, and
a parser that refused them would be paranoid rather than correct.

The 900 KiB case additionally asserts the message stays under 4 KiB — a parser that returns the
document to the operator is its own denial of service.

## 4. Fuzzing

Four targets, each run at a bounded 120 s budget after seeding.

| Target | Executions | New interesting | Crashers | Result |
|---|---|---|---|---|
| `FuzzLoad` | 1,298,639 | 495 | 0 | pass |
| `FuzzServiceNode` | 1,488,856 | 450 | 0 | pass |
| `FuzzCredentialReference` | 692,467 | 607 | 0 | pass |
| `FuzzSanitizedErrorPath` | 2,838,060 | 108 | 0 | pass |

**The first run produced four failures, and all four were defects in the fuzz properties
rather than in the product.** That is the useful result, and each narrowed the property to
something true:

| Input | Apparent failure | What it actually was |
|---|---|---|
| `id: 0` + backtick | "an unredacted backtick span survived" | svcdoctor quoting an operator-written *identifier* that contains a backtick, via `%q`. A name, not a value |
| `0` + backtick as a field name | same | the same, for an unknown-field message |
| `!000` | "the refusal echoes the reference" | the tag refusal names the tag, which an operator has to be told |
| `file` | same | the refusal's own prose contains the example `{file: PATH}` |

The corrected property matches the shape the library actually interpolates —
``cannot unmarshal !!str `value` into T`` — and excludes the redacted form, which is itself
backtick-quoted and was measured to occur (`port: "abc"`). Leakage is otherwise asserted with a
**planted canary** rather than by looking for the fuzz input, because a check that cannot
distinguish "the message quoted your value" from "the message contains that word" is measuring
vocabulary.

`TestTheInterpolationCheckIsNotVacuous` proves the corrected check still fires on genuinely
unsanitized library text. The four failing inputs are retained as seed corpus.

## 5. Secret leakage

`internal/cli/runcanary_test.go`: 25 adversarial values, each planted in **both** credential
sources, each run through four invocations (terminal, JSON, shareable terminal, shareable
JSON), each searched in three representations — raw, JSON-escaped and `strconv.Quote`d.

Searching only the raw bytes is the mistake this exists to avoid: a secret containing a newline
appears in JSON as `\n` and in no other form.

Values: ordinary ASCII, internal and surrounding spaces, both quote kinds, backslashes,
newline, CRLF, tabs, JSON-looking, YAML-looking, shell-looking, `%s`, `%+v`, `%q`, `%#v`,
Unicode, emoji, a 1,700-byte value, prefixes and suffixes shared with the username and the
hostname, a value equal to the environment variable name, and a path-shaped value.

**Zero leaks.** `TestTheCanaryCorpusWouldCatchALeak` proves the corpus is not vacuous by
running the same search against a surface that does contain each value.

### 5.1 The one case that cannot be fixed, and is not claimed to be

A secret set **equal to a value the report must carry** — the username, or the target
identifier — appears in the report because the *identity* appears in the report. No structural
redaction can resolve that: the two are the same characters, and the document's purpose
requires printing one of them.

`TestASecretEqualToAReportedValueIsIndistinguishable` pins the honest property instead. The
same run is performed with two different passwords and the two documents must be byte-identical
once timing is normalized — so the appearance is provably caused by the reported value and not
by the secret. Separating these two cases rather than deleting them is what keeps the corpus
from quietly implying a guarantee svcdoctor does not make.

## 6. Secret-reference leakage

The environment variable name, the credential file path, the configuration file path and three
Go type names (`SecretRef`, `config.Reference`, `SourceKind`) are absent from all four
canonical forms.

The other half of ADR 0072 §10's split is asserted too, so the test cannot be satisfied by
deleting the diagnostic: `TestSourceMetadataIsStillNameableOnStderr` requires stderr to name
the missing variable, because an operator who cannot see which variable is missing cannot fix
it.

## 7. Isolation

### 7.1 One reference, two targets

`internal/fleet/run/isolation_test.go` wires the **real** `*secret.Resolver` rather than a
fake, because a fake that hands out a distinct secret per target proves the property by
construction and would pass against a caching implementation.

At concurrency 1 and 4, across two service kinds, and for both sources: two resolutions, two
credentials, each opening **only** at its own endpoint and refused at every other. The file
case rewrites the file between the two resolutions and observes two different values, which is
proof that two reads happened rather than one value being handed out twice.

### 7.2 Same endpoint, different authority

Four targets on one `host:port` differing in username, credential reference and service
configuration: four results, four runner invocations, four distinct report documents, declared
order, and no credential for the target that declared none. At concurrency 1 and 4.

Proven again against real fixtures in `TestSameEndpointDifferentAuthorityThroughRealFixtures`:
two PostgreSQL targets on one endpoint, one reaching `OK` and the other
`POSTGRES_DATABASE_NOT_FOUND`, with the two report documents required to differ.

## 8. TOCTOU and file semantics

The gap between preflight and resolution is **deliberate**: ADR 0072 §5.2 chose it so that at
most `concurrency` secrets are alive at once, and §8 refuses the cache that would close it. So
the tests pin the consequences rather than trying to remove the window.

| Sequence | Result |
|---|---|
| env present at preflight, removed before Resolve | resolution fails, no cached value |
| env value changed between the two | Resolve returns the **current** value |
| file present at preflight, deleted before Resolve | resolution fails |
| file contents replaced between the two | Resolve returns the new contents |
| file becomes a directory | fails closed |
| permission removed | fails closed, no value in the message |
| one target's source vanishes | the other still resolves |

Symlink policy is exactly the frozen one: followed, destination must be regular. A dangling
symlink and a symlink to a directory are refused; a symlink to a regular file resolves. A FIFO
and a device are refused **on the type**, without opening them — which is what stops a hostile
path hanging a run forever.

File content semantics are the leaf commands' unchanged: one trailing line ending removed and
only one, spaces kept, a second line kept, an embedded NUL passed through. Nothing was
tightened; ADR 0049 owns that decision for all four leaf commands at once.

## 9. Concurrency, scale and determinism

| Property | Method | Result |
|---|---|---|
| Bounded concurrency | 64 targets at pool 1, 2, 4, 8, 16 | peak **equals** the configured width at every size |
| No lost or duplicated target | result-set identity at every size | pass |
| 511 and 512 targets | full run with fake runners | pass, declared order, summary reconciles exactly |
| 513 targets | configuration boundary | refused before any runner or resolver exists |
| Repeated-run determinism | 100 repetitions, mixed dispositions, pool 8 | byte-identical modulo start time and duration |
| Randomized completion order | 40 seeded PCG permutations, gated release | declared order every time, identical documents |
| Goroutine leak | 20 warm-up runs, then 200 | no growth |
| Goroutine leak after cancellation | 10 warm-up, then 100 | no growth |

The concurrency test uses a **barrier**: every target blocks until the configured number of
runners is inside `Run` together. The obvious version — race instant-returning fakes and
observe the peak — passes at pool 16 with a peak of 1 and asserts nothing.

512-target run: aggregate 320 KB, about 640 bytes per target, well inside the 64 KiB per-target
ceiling ADR 0073 §11.2 derives. Recorded as a measurement; it is not a capacity claim.

## 10. Cancellation and deadlines

One run holding all four lifecycle states at the instant of cancellation: already completed,
actively running, and four queued behind a full pool. Completed stays completed; the in-flight
target is `CANCELLED` and keeps its partial report; the queued four are `NOT_STARTED` with no
report, **no resolver call** and no runner call. Stopped reason `CANCELLED`, run incomplete,
status `OK` — the operator stopped svcdoctor and the endpoints did nothing.

Cancellation is also exercised immediately, once a target is running, and after most targets
have completed.

Deadline race stress runs four budget arrangements 25 times each: run budget equal to target
budget, each just under the other, and a cancellation racing the run budget. Exactly one result
per target, no panic, no missing result, and never a `PROBLEMS_FOUND` produced by a local
deadline.

`TestMTE16ATargetTimeoutDoesNotCancelASibling` was **rewritten**. The original gave one target
a short budget and left the siblings instant, so they had already finished when it expired and
mutation C28 — cancelling the run on a target-local timeout — survived. The siblings are now
held in flight until the slow target has demonstrably timed out.

## 11. Exit contract, end to end

`internal/cli/runblackbox_test.go` drives the real command surface rather than `RunExitCode`,
and asserts the integer, stream ownership and report presence together — a correct code with
the artifact on the wrong stream still breaks every pipeline.

| Code | Scenario | Owner |
|---|---|---|
| 0 | four healthy services | Docker integration suite |
| 1 | an unresolvable name | black-box |
| 2 | ten configuration and credential defects | black-box |
| 3 | the forced abort | `TestMTE07AFirstInterruptCancelsAndASecondAborts` |
| 4 | cancellation, and the 4-outranks-1 worked case | black-box |

Exit 0 is **not** fabricated in-process. Reaching it requires a service that answers correctly,
and stubbing the composition root to get there would make the test about the stub.

The worked case is the one ADR 0074 §6.1 specifies: a target-side `ERROR` beside an unmeasured
target exits 4, and the finding stays in the report in full.

Zero-execution is proven for three defect kinds refused by three different passes — the strict
decode, the per-target validation loop, and the credential reference's own decoder. Only the
second exercises the validation loop, and mutation C38 survived the unknown-field case alone.

## 12. Rendering

The domain refuses control characters in every identifier and in prose except `\n`, and
`config.checkHostSyntax` refuses a host holding one. So a control character cannot reach a
renderer, which is why the renderer does not sanitize; both boundaries are pinned, because
removing either alone would leave the property apparently intact.

Twelve legal-but-awkward hosts — Unicode, CJK, emoji, both quote kinds, brackets, braces,
backslash, `%s`-shaped, a printable ANSI-looking string, a backtick, and one at the length
boundary — render with no control character and a stable frame.

Aggregate JSON is valid and survives a decode/re-encode round trip for every one, in both
output modes, with no credential surface present.

## 13. Pseudonyms and shareable output

One pseudonym table per run: a host in two targets receives one pseudonym, a third host
receives its own. **Asserted differentially**, and that correction matters — the obvious count
is wrong because a report also names the *vantage*, which is a host and is pseudonymized like
any other. Pinning an absolute number would encode an assumption about the machine running the
test.

64 distinct hosts produce 64 distinct pseudonyms; a collision would merge two real hosts into
one apparent host, which is worse than revealing either because it invents a correlation a
reader cannot detect.

Within a run, assignment is deterministic. **Across runs it is not, deliberately** — a stable
cross-run pseudonym would let someone holding two shared reports from one environment correlate
them.

Shareable versus local: the exit code, every execution state, every status, every severity and
every finding code are identical. Only representation changes. No host-shaped token appears in
the shareable form that is absent from the local one, and the real hosts and target identifiers
are gone.

## 14. Aggregate serialization

Six golden fixtures in `test/golden/testdata/`, deterministic by construction with no
normalized placeholders: all-completed, a completed diagnostic failure, an execution failure,
cancelled-plus-not-started, a four-service run, and a shareable mixed run.

They live in `test/` rather than beside the renderer because the shareable fixture needs
`internal/security/redaction`, and a depguard rule forbids anything under `internal/render`
from importing it. The rule is right, so the fixtures moved rather than the guard.

`TestTheEmbeddedReportSchemaVersionIsStillOne` reads both versions out of the serialized
document — the aggregate's `schemaVersion: 1` with `kind: "run"`, and every embedded report's
`schemaVersion: 1` — because that is what a consumer reads.

## 15. Structural closure

New guards in `test/security/fleet_closure_test.go`:

- **Finding codes counted from the syntax tree** — 60, with the RabbitMQ namespace at 11. This
  did not exist: failure classes had a count test because they are a map, and finding codes are
  `const` declarations across five packages with no central registry, deliberately. "Finding
  codes stay at 60" was an ADR 0073 §12 decision that no test could contradict.
- **No fleet package declares a `domain.FindingCode`, converts to one, or calls
  `domain.NewFinding`.**
- **No aggregate surface uses causal vocabulary** in code — twelve phrases, comments excluded,
  because the code that forbids a phrase has to name it.
- **`Reveal` = 4 and `SecretFor` = 4**, counted from the tree, with every `Reveal` required to
  be inside a wire package.
- **Exactly one fleet call site builds a credential**, it is the resolver's, and the scheduler
  builds no `security.Endpoint` at all.
- **The resolver binds authority to the target's own `Host` and `Port`**, read from the AST, so
  an edit reaching for `target.ID` has to delete the test.
- **The scheduler checks the run context before spending anything**, and does not spend inside
  that branch.

That last one is **structural on purpose**, and the limit is stated rather than glossed. The
race window needs a worker parked on the dispatch channel at the instant the run context
expires; neither condition can be forced from outside, and mutations C21 and C22 survived every
behavioural test written for them. Asserting the code shape is a weaker claim than "the race
cannot happen", and it is written as one.

`internal/domain/runreport_test.go` is new for the same class of reason: the aggregate's
invariants were covered only *through* the scheduler, which cannot exercise the combinations
the constructors exist to refuse.

## 16. Mutation closure — 45 planted, 45 caught, 0 survivors

`scripts/phase91c-mutations.sh`, restored byte-for-byte by sha256.

**The first run had 12 survivors and that is the more useful result.** Three were real guard
gaps, four were ineffective plants, and five were escaping or anchor defects in the script.

| Survivor | Diagnosis | Fix |
|---|---|---|
| C28 target timeout cancels siblings | **Real gap.** The siblings had already finished when the slow target expired, so cancelling the run changed nothing observable | hold the siblings in flight until the timeout has landed |
| C09 resolver echoes the value | **Real gap.** Every case in the leakage test failed because the material was *absent*, so there was no value to leak | a success-path case with the canary present |
| C38 config error still executes earlier targets | **Real gap.** The scenario's defect was an unknown field, refused by the strict decode before the per-target loop the mutation edits was ever reached | three defect kinds, refused by three different passes |
| C21 / C22 never-started target spends anyway | **Unobservable behaviourally**, see §15 | a structural guard, with its weaker claim stated |
| C31 execution failure stops the run | Ineffective plant: only the runner-error branch was edited, and the scenario failed at *resolution* | plant both branches |
| C10 scheduler serializes the unsafe message | Ineffective target: the named test is in the resolver's package and never calls the scheduler's `safeMessage` | point at the scheduler's own test |
| CEX5 second interrupt swallowed | Ineffective plant: `_ = abortMessage` disables nothing | delete the second stage |
| C06, C40, CEX1, CEX3 | Unplantable: backticks inside an unquoted heredoc are command-substituted, and two asserts were wrong | `chr(96)`, and corrected asserts |

## 17. Quality gate

| Check | Result |
|---|---|
| `git diff --check` | clean |
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `golangci-lint run ./...` | 0 issues |
| `go test ./...` | pass |
| `go test -race ./...` | pass |
| `go test -race ./internal/fleet/run -count=20` | pass, 119 s |
| `CGO_ENABLED=0 go build ./...` | pass |
| `go mod tidy` | no-op |
| `make check` | pass |

No race suppression, no retry loop, no skipped test hiding one.

## 17.1 Integration regression

All eight suites sequentially, each with its own setup and teardown, from a clean state.

| Suite | Result | Duration | Skips | `svcd-*` containers left |
|---|---|---|---|---|
| PostgreSQL | **PASS** | 36 s | 0 | 0 |
| Kafka | **PASS** | 351 s | 0 | 0 |
| Redpanda | **PASS** | 6 s | 0 | 0 |
| Redis | **PASS** | 9 s | 0 | 0 |
| Valkey | **PASS** | 5 s | 0 | 0 |
| RabbitMQ | **PASS** | 124 s | 0 | 0 |
| LavinMQ | **PASS** | 7 s | 0 | 0 |
| **Multi-target** | **PASS** | 75 s | 0 | 0 |

Zero unexpected skips, zero fixture overlap, and no container survives any suite.

**The first sequential run failed**, and §2.4 is what it found: the RabbitMQ gate's
`TestRAB18ManagementPortTargetedAsAMQP` failed because `rabbitmq_management` read `[E ]` —
enabled but not running — so nothing bound 15672. `rabbitmq-plugins enable` had been issued
before the broker was up, which writes the enabled-plugins file without activating anything,
and the `|| true` hid it. The plugin enable now runs after the principals, is retried, and is
verified against a real listener check.

The multi-target suite gained two scenarios in this phase:
`TestTheChaosMixKeepsEveryTargetIndependent` (six targets, six different outcomes, one run) and
`TestSameEndpointDifferentAuthorityThroughRealFixtures`.

The chaos scenario needed a resolver failure that **survives preflight**, which one
deterministic construction provides: preflight refuses a credential file above `MaxInput + 1`
and the read refuses input above `MaxInput`, so a file of exactly 4097 bytes passes the first
and fails the second. Measured, with and without a trailing newline. Deleting a file mid-run
is a race, and a race is not a test.

## 18. Invariants, unchanged

| Invariant | Value |
|---|---|
| `domain.SchemaVersion` | **1** |
| `domain.RunSchemaVersion` | **1** |
| Finding codes | **60** |
| RabbitMQ finding codes | **11** |
| Failure classes | **42** |
| `security.Reveal` production sites | **4** |
| `Credential.SecretFor` production sites | **4** |
| External modules | **2** |

No finding code, failure class, execution state, stopped reason, credential source,
configuration field or report field was added. Production changes are four files:
`cmd/svcdoctor/main.go`, `internal/cli/exit.go`, the new `internal/cli/interrupt.go`, and one
stale comment reference in `internal/fleet/run/run.go`. Everything else is tests, fixtures, a
mutation script, the Makefile fixture fix and documentation.

## 19. What Phase 9.1C did not do

- **No global probe semaphore.** ADR 0073 §10.1 still declines one, and target concurrency
  still bounds targets rather than sockets. Unchanged from 9.1B, and no measurement here
  justifies revisiting it.
- **No filtering flags.** ADR 0074 §10.4 leaves them out of v1 and reserves no name.
- **No output to a file.**
- **No compatibility claim.** `docs/COMPATIBILITY.md` is unchanged, and multi-target execution
  appears in no compatibility row at any level.
