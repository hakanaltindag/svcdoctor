# Multi-target Phase 9.0 — contract study

What Phase 9.0 established, and which of it is measured rather than reasoned. ADRs
[0071](../decisions/0071-multi-target-configuration-schema.md) to
[0074](../decisions/0074-multi-target-report-and-exit-semantics.md) are the decisions; this
is the evidence behind them, the frozen vocabulary, and the Phase 9.1 matrices.

**No multi-target code exists.** No Go file was created or edited in this phase. Nothing
here is a capability claim: `docs/COMPATIBILITY.md` is unchanged, and multi-target execution
appears in no compatibility row at any level.

## 1. Start-state gate

Verified mechanically at `a79ef48`, before any document was written.

| Invariant | Expected | Measured | Method |
|---|---|---|---|
| `SchemaVersion` | 1 | **1** | `internal/domain/report.go:21` |
| Finding codes | 60 | **60** | `domain.FindingCode = "` declarations across `internal/diagnosis/*`, excluding tests |
| RabbitMQ finding codes | 11 | **11** | same, `internal/diagnosis/rabbitmq` |
| Failure classes | 42 | **42** | `internal/domain/failureclass_test.go:254` |
| `security.Reveal` production sites | 4 | **4** | kafka, postgres, redis, rabbitmq wire packages |
| `Credential.SecretFor` production sites | 4 | **4** | one per adapter |
| External modules | 1 | **1** | `go.mod`; `test/security/dependency_test.go` |

Per-service finding codes: kafka 13, postgres 19, redis 9, transport 8, rabbitmq 11 — 60.

**One delta was found, and it is documentation staleness rather than a repository
difference.** `docs/BACKLOG.md`'s roadmap row for Phase 8 and several paragraphs of
`CLAUDE.md` still said *"No RabbitMQ code exists"* and *"decided and not built"*, which
stopped being true when Phase 8.2 landed `internal/adapter/rabbitmq`,
`internal/diagnosis/rabbitmq`, `internal/app/rabbitmq.go` and `svcdoctor diagnose rabbitmq`.
`docs/COMPATIBILITY.md` was already correct, grading RabbitMQ 3.13.7 / 4.0.9 / 4.2.0 and
LavinMQ 2.3.0 at Level 3. Both stale documents were corrected in this phase. No invariant
count was affected.

Build, vet and the full test suite were green before and after.

## 2. Measurements

### 2.1 YAML strictness and hazards

Run against `gopkg.in/yaml.v3` v3.0.1 and `go.yaml.in/yaml/v3` v3.0.5, in scratch modules
outside the repository, both since deleted. `svcdoctor`'s own `go.mod` was never touched.

| # | Input | Result | Consequence |
|---|---|---|---|
| 1 | unknown field, `KnownFields(true)` | **rejected**, `line 2: field bogus not found` | Fail-closed unknown fields are free |
| 2 | unknown field, `KnownFields(false)` | accepted | Strictness must be switched on explicitly |
| 3 | duplicate top-level key | **rejected**, `mapping key "version" already defined at line 1` | Stronger than `encoding/json`, which last-wins |
| 4 | duplicate nested key | **rejected**, both lines named | Holds at depth |
| 5 | anchor + alias | **accepted silently**, expanded into two identical targets | Needs an explicit pre-pass |
| 6 | two documents | first `Decode` succeeds; a second `Decode` returns the second document | Refusing multi-document needs an explicit second `Decode` expecting `io.EOF` |
| 7 | `!!python/object` | rejected — but only because the *type* did not match | Tag refusal cannot rely on decoding failure |
| 8 | `id: no` into a `string` field | `"no"` | The Norway problem is absent when decoding into typed structs |
| 8b | the same into `any` | a map value, untyped | Decoding into `any` must never happen |
| 9 | `password: hunter2` into a struct field | **rejected**, ``cannot unmarshal !!str `hunter2` into Cred`` | **The plaintext refusal is a property of the type, not a check** |
| 10 | 9-way, 7-deep alias bomb into `map[string]any` | **rejected**, `document contains excessive aliasing`, 1–2 ms | Expansion is bounded by the library |
| 11 | merge key `<<: {id: a}` into a struct, `KnownFields(true)` | **accepted silently** | **Refusing aliases does not refuse merges**; `!!merge` needs its own refusal |
| 12 | JSON document through the YAML decoder | accepted | JSON needs no second parser |
| 13 | empty document | `io.EOF` | Distinguishable from a valid empty config |
| 14 | tab indentation | rejected, `line 2: found character that cannot start any token` | A classic authoring error, with a line number |
| 15 | CRLF line endings | accepted | |
| 16 | lax decode of `version` from an otherwise-unknown document | succeeds | A two-pass decode can name an unsupported version precisely |

Node-walk detection, measured on parsed `yaml.Node` trees: anchors, aliases, `!!merge`,
`!!binary`, `!!timestamp`, `!!float` and arbitrary `!tags` are each individually visible, so
an allow-list of `!!str !!int !!bool !!null !!map !!seq` is implementable in a single
recursive pass.

Rows **9** and **11** are the two that changed the design. Row 9 is why a credential
reference is an object rather than a prefixed string. Row 11 is the hazard a careful
implementer would reasonably assume was covered by refusing aliases, and is not.

### 2.2 Dependency profile

| Module | Latest | Own `go.mod` requirements |
|---|---|---|
| `gopkg.in/yaml.v3` | v3.0.1 (June 2022, frozen) | `gopkg.in/check.v1` |
| **`go.yaml.in/yaml/v3`** | **v3.0.5** | **none** |
| `github.com/goccy/go-yaml` | v1.19.2 | not evaluated further |

`go.yaml.in/yaml/v3` retracts `[v3.0.0, v3.0.1]` as belonging to the old import path, which
identifies it as the maintained continuation. All sixteen behaviours in §2.1 were confirmed
on v3.0.5 as well as on v3.0.1.

Adding it takes the module count from **1 to 2**.

### 2.3 Report sizes

Measured with a binary built from `a79ef48`, `--output json`, against closed local ports.

| Shape | Bytes |
|---|---|
| postgres, unresolvable name (2 nodes, 1 finding) | 2,160 |
| redis, 1 address, no TLS | 2,375 |
| redis, 2 addresses, no TLS | 3,023 |
| redis, 2 addresses, TLS | 3,824 |
| postgres, 2 addresses | 3,025 |
| kafka, 2 addresses | 3,017 |

Derived: envelope plus one path ≈ **2.4 KB**; each additional address ≈ **0.65 KB**; each
additional TLS path ≈ **1.05 KB**. All four services land in the same band for a comparable
shape, so no service needs its own model.

These three numbers are what ADR 0073 §11 turns into the 64 KiB per-target ceiling, the
512-target bound and the 1 MiB file bound.

### 2.4 Transport fan-out

`internal/probe/transport/run.go` sweeps addresses in a plain `for` loop — **sequential**,
no goroutines — but accumulates every completed connection into the `Result` and closes them
together. So a target's peak descriptor use is its **whole resolved address set**, not one at
a time, and Kafka adds the advertised-broker sweep on top.

This is the measurement behind ADR 0073 §10: target concurrency does not bound sockets.

## 3. Terminology, frozen

| Term | Definition |
|---|---|
| **Run** | One invocation of `svcdoctor run`. Produces exactly one aggregate report |
| **Target** | One declared diagnostic subject: an endpoint, a service kind, its configuration and its credential reference |
| **Target ID** | The operator-written `id`. 1–63 bytes, `[a-z0-9_-]`, alphanumeric at both ends, unique in the file. Explicit, never derived |
| **Target name** | **Does not exist in v1.** The ID is the only human-facing label |
| **Service kind** | The `type` discriminator selecting a registered service factory. Not part of identity |
| **Endpoint** | The `host:port` pair. The credential authority boundary. **Not identity** |
| **Credential reference** | `{env: NAME}` or `{file: PATH}`. Names where a secret lives; never holds one |
| **Credential resolver** | `internal/fleet/secret`. Reads env or a file, builds `security.Secret`, binds `security.Credential`. Knows no protocol |
| **Target execution** | One call to a registered service runner, which calls one `app.DiagnoseX` |
| **Target report** | The existing `domain.Report`, unchanged, for one target |
| **Aggregate report** | The `RunReport` wrapping every `TargetResult`. Its own `schemaVersion` |
| **Run status** | **Derived**, never stored as an independent opinion: `PROBLEMS_FOUND` when any target report is, otherwise `OK` |
| **Execution budget** | Any of the three bounds. Unqualified, the run's |
| **Run budget** | `run.timeout`. Unset by default; the run is bounded by derivation instead |
| **Target budget** | `targets[].timeout`, default 30 s. Derived from the run's context |
| **Step budget** | `targets[].step_timeout`, default 10 s. Unchanged from the leaf commands |
| **Concurrency limit** | Targets in flight at once. Default 4, maximum 16 |
| **Dependency / ordering** | **Absent in v1.** Targets are independent; declared order is presentation only |
| **Partial failure** | A run in which some targets completed and others did not. Always reported in full, never a reason to stop |
| **Configuration error** | A defect in the file or in a credential reference at preflight. Exit 2, **zero targets dialled**, no report |
| **Execution error** | A svcdoctor-local failure while running one target. `EXECUTION_FAILED`, contributes to exit 4 |
| **Diagnostic finding** | A `domain.Finding` about a target, produced by `internal/diagnosis`. **The fleet layer creates none** |

### 3.1 The five mandatory distinctions

| Not the same as | Because |
|---|---|
| Configuration error ≠ target diagnostic failure | One is a defect in what the operator wrote and reaches no network; the other is a measured fact about a service |
| Local execution failure ≠ remote service failure | ADR 0047, at run scope. A cancelled or never-started target says nothing about its endpoint |
| Target report ≠ aggregate report | Different documents, different schema versions, different owners |
| Credential resolution failure ≠ authentication rejection | One means svcdoctor could not obtain the material; the other means the endpoint refused it. Only the second is a finding |
| Run incompleteness ≠ target unhealthiness | Orthogonal, at run level exactly as `Result.Incomplete()` is orthogonal to `SummaryStatus` today |

## 4. Frozen decision table

| Topic | Frozen decision | Reason |
|---|---|---|
| **Config format** | YAML 1.2, one document, strict. JSON accepted as a YAML subset, not as a second format | Comments, and measured duplicate-key rejection where JSON silently last-wins |
| **Config parser** | `go.yaml.in/yaml/v3` v3.0.5, importable only by `internal/fleet/config`. Modules 1 → 2 in Phase 9.1 | Zero own dependencies; maintained continuation; every needed strictness measured |
| **Config version** | `version: 1`, its own number. Missing or unknown ⇒ configuration error. Read by a lax first pass | Independent lifecycle from `SchemaVersion`; a defaulted version silently changes meaning at v2 |
| **Unknown fields** | Rejected, at every level, including inside `config:` | Free with `KnownFields(true)`; a typo must not be silence |
| **Duplicate keys** | Rejected, at every depth | Free; the alternative silently discards a credential reference |
| **Anchors, aliases, merge keys** | Rejected by an explicit node pre-pass | Aliases expand silently; a merge key needs its own refusal (measured) |
| **YAML tags** | Allow-list `!!str !!int !!bool !!null !!map !!seq` | Fail closed; a deny-list grows with the library |
| **Documents per file** | Exactly one | A second document is a second run nobody asked for |
| **Config file** | Regular file after symlink resolution; ≤ 1 MiB; `--config` required, no default path | K8s projects config through symlinks; ambient config is refused |
| **Target ID** | Required, explicit. 1–63 bytes `[a-z0-9_-]`, alphanumeric at both ends, lowercase enforced not folded, unique. Duplicates are an error | Derived identity moves; folding creates two spellings of one thing |
| **Endpoint as identity** | No. Duplicate endpoints supported, never deduplicated, never shared | Same server, different database / vhost / credential / identity |
| **Service kind in identity** | No | `--target x` must never need a type to disambiguate |
| **Target ordering** | Declared configuration order, always | The operator's grouping is the file's only structure; sorted order would leak lexical order through pseudonyms |
| **Service config ownership** | `{id, type, host, port, timeout, step_timeout, tls, credentials, config}`; `config` is an unparsed node decoded by the registered service | Keeps the core free of a global struct and of `map[string]any` |
| **Generic vs service field rule** | Generic only when semantics are identical. Identical semantics with a different valid range ⇒ generic field, service-owned validation | `step_timeout` (RabbitMQ's 3 s floor) is the measured instance |
| **TLS ownership** | Block generic; wire meaning service-owned | `internal/cli/tls.go` already made this split, and ADR 0060 forced it |
| **Credential sources v1** | `env` and `file`. Exactly one per password. No stdin, no literal, no manager, no exec | What a container and a pod already provide, with no network and no dependency |
| **Plaintext secrets** | Configuration error, refused by the decoder's type. No accept-and-redact. File mode never consulted | A structural refusal cannot be forgotten; a mode check would imply `0600` makes it acceptable |
| **Credential resolution timing** | Preflight proves every reference resolvable and retains no value; resolution is per target, immediately before execution | A's determinism at B's residency: ≤ concurrency secrets alive |
| **Secret caching** | **None.** Same reference in two targets ⇒ two resolutions, two bindings | A reference is not an authority |
| **Credential authority** | The target's own `host:port`. Not the target ID, not the vhost, not a discovered broker | ADR 0028, 0050, 0068 unchanged |
| **`env` vs ADR 0049 §5** | Allowed in fleet config; still refused on every leaf command. `internal/cli` keeps zero env-read sites | A written, target-bound reference under review is a different object from an ambient flag |
| **Target concurrency** | Default 4, min 1, max 16. `0`, negative and > 16 are errors. CLI > config > default | Machine-independent load; 16 × 32 sockets = half a 1024 descriptor limit |
| **Global timeout** | `run.timeout`, **unset by default**. If set, ≥ the largest target timeout. Run bounded by derivation: `ceil(targets/concurrency) × target_timeout` | A default would silently decide how large a file may be |
| **Target timeout** | `targets[].timeout`, default 30 s, context derived from the run's | Inherited from the leaf commands; derivation makes "earlier deadline wins" structural |
| **Step timeout** | `targets[].step_timeout`, default 10 s, unchanged. RabbitMQ's > 3 s floor still applies | ADR 0070 §8 |
| **Cancellation** | First signal: stop scheduling, cancel in flight, wait bounded by the target budget, keep every report, exit 4. Second signal: abort, exit 3 | A cancelled target is not a failing target |
| **Fail-fast** | **None**, and nothing reserved for it | One broken target must not hide 39 others |
| **Config error execution policy** | Any configuration error ⇒ **zero targets dialled**, exit 2, no report | 17 spent authentications on a run that cannot complete |
| **Aggregate report** | Separate document, own `schemaVersion: 1`, `kind: "run"`, wrapping unmodified `domain.Report` values. Lives in `internal/domain` | Merging collides evidence IDs; a second serialization is what ADR 0016 refuses |
| **`domain.SchemaVersion`** | **Unchanged at 1.** The single-target report gains no field | Charging every consumer for a document they do not read |
| **Execution state vocabulary** | `COMPLETED`, `NOT_STARTED`, `CANCELLED`, `EXECUTION_FAILED`. Orthogonal to `PASS/FAIL/DEGRADED/UNKNOWN/SKIPPED` | Four dispositions by the runner; the reason scheduling stopped is recorded once, at run level |
| **Never-started targets** | No evidence graph at all, no finding, no failure class | Absence is the truthful representation (ADR 0059's reasoning) |
| **Run-level findings** | **None.** Finding codes stay at 60, failure classes at 42 | A configuration error is not a claim about a service |
| **Run summary** | Derived, never supplied. Factual counts only. Never "healthy" | ADR 0015; `SummaryStatus` already refuses the word |
| **Exit codes** | Unchanged: 0/1/2/3/4, precedence `3 > 2 > 4 > 1 > 0`. `EXECUTION_FAILED` ⇒ 4, not 3 | The single-target contract applied to a set |
| **Exit-code ownership** | Runner returns a structured outcome; CLI maps it; renderer never does | ADR 0048 §3 |
| **CLI command** | `svcdoctor run --config <file>`. Four leaf commands byte-for-byte unchanged | Action-first; a flag in the service position makes `diagnose` two commands |
| **CLI overrides** | `--config`, `--timeout`, `--concurrency`, `--output`, `--shareable`. No service or per-target override; no `--password-*` | A flag editing one target means the file no longer describes the run |
| **Config stdin** | `--config -` is **not** stdin. Regular file only | One stdin, N credentials; and a run must stay reproducible |
| **Arbitrary env interpolation** | **Absent, and refused rather than deferred.** Env is reachable only through `password.env` | `${VAR}` is a templating language, and templating languages grow conditionals |
| **Cross-target diagnosis** | **None**, at any layer | svcdoctor has no evidence of any relationship between two endpoints |
| **Shareable output** | Every embedded report redacted; **one pseudonym table for the whole run**; target IDs pseudonymized | Preserve correlation, remove identity — inventing a correlation is worse than preserving one |
| **Never serialized** | Config path, credential reference names and paths, raw config, any secret, any credential surface | A report is the artifact most likely to be pasted somewhere public |
| **Target maximum / bounds** | 512 targets; 64 KiB per target report; 1 MiB config; aggregate built in memory, no streaming | Derived from §2.3 measurements and a 32 MiB accumulated-report budget |
| **Filtering** | Not in v1. No flag name reserved | The identity contract keeps exact-match selection available later |
| **Labels / metadata** | Not in v1 | Cardinality, sensitivity and selector semantics for a use case nobody has stated |
| **Output to file** | Not in v1; stdout only, inheriting the existing output boundary | Phase 9.1 does not need it |

No row is TBD.

## 5. Package boundaries and import direction

```
internal/cli
  └─ run command: wires the registry, supplies resolver/dialer, maps the exit code
       ├─> internal/fleet                 the runner
       ├─> internal/fleet/services/*      one per service, registered explicitly
       └─> internal/app                   unchanged composition roots

internal/fleet            -> internal/domain, internal/fleet/config, internal/fleet/secret
internal/fleet/config     -> the YAML module ONLY
internal/fleet/secret     -> internal/security
internal/fleet/services/* -> internal/app, internal/probe/{dns,tcp}, internal/fleet/config
```

Frozen prohibitions, each with a structural guard in §7:

| Package | Must not import |
|---|---|
| `internal/fleet` (runner core) | `internal/adapter/**`, `internal/diagnosis/**`, `internal/probe/**`, `internal/render/**` |
| `internal/fleet/config` | `internal/security` — it structurally cannot build a secret |
| `internal/fleet/**` | anything permitting `security.Reveal`; `forbidigo` already fails the build |
| `internal/cli` | `os.Getenv`, `os.LookupEnv`, `os.Environ` — the existing guard, unrelaxed |
| anything but `internal/fleet/config` | the YAML module |

**`internal/app` is unchanged.** The four composition roots keep their signatures, their
validation and their credential rebinding refusal. The fleet layer calls them; it does not
reach past them into an adapter, a wire package, a probe or a rule.

## 6. Phase 9.1 test matrix — 108 cases

### 6.1 Configuration — 31

| ID | Case |
|---|---|
| MT-C01 | A valid file covering all four services |
| MT-C02 | Duplicate target ID, both occurrences named |
| MT-C03 | Unknown service type |
| MT-C04 | Unknown field at the top level |
| MT-C05 | Unknown field inside a service's `config:` |
| MT-C06 | `password: hunter2` rejected |
| MT-C07 | `password: {env: A, file: B}` rejected |
| MT-C08 | `password: {}` rejected |
| MT-C09 | Missing environment variable |
| MT-C10 | Empty environment variable |
| MT-C11 | Unreadable secret file |
| MT-C12 | Secret file is a directory |
| MT-C13 | Malformed YAML — tab indentation |
| MT-C14 | Duplicate YAML key |
| MT-C15 | `version` absent |
| MT-C16 | Unsupported `version` |
| MT-C17 | Anchor and alias refused |
| MT-C18 | Merge key `<<` refused |
| MT-C19 | Non-core YAML tag refused |
| MT-C20 | Multi-document file refused |
| MT-C21 | Config file is not a regular file |
| MT-C22 | Config file above 1 MiB |
| MT-C23 | More than 512 targets |
| MT-C24 | Target ID grammar: uppercase, leading `-`, 64 bytes, empty |
| MT-C25 | `host: ${DB_HOST}` is taken literally, never interpolated |
| MT-C26 | `run.timeout` below the largest target timeout |
| MT-C27 | RabbitMQ `step_timeout` ≤ 3 s refused |
| MT-C28 | TLS-only fields under `mode: disable` refused (ADR 0060) |
| MT-C29 | Missing required service field — Kafka `sasl_mechanism`, PostgreSQL username |
| MT-C30 | Zero targets |
| MT-C31 | `--config -` is not stdin |

### 6.2 Execution — 22

| ID | Case |
|---|---|
| MT-E01 | All four targets complete |
| MT-E02 | One remote authentication failure; unrelated targets still run |
| MT-E03 | One local step-budget expiry |
| MT-E04 | Credential resolution fails at execution time (post-preflight) |
| MT-E05 | Run budget exhausted before every target starts |
| MT-E06 | Cancellation with completed, in-flight and queued targets |
| MT-E07 | Second interrupt aborts |
| MT-E08 | Output unchanged when completion order is changed |
| MT-E09 | Duplicate endpoints as distinct logical targets |
| MT-E10 | One secret reference used independently by two targets |
| MT-E11 | `concurrency: 1` |
| MT-E12 | `concurrency: 16` |
| MT-E13 | `concurrency: 0` rejected |
| MT-E14 | `concurrency: 17` rejected |
| MT-E15 | `--concurrency` overrides the config |
| MT-E16 | `--timeout` overrides the config |
| MT-E17 | A target budget cannot exceed the remaining run budget |
| MT-E18 | A target with no credential yields `CREDENTIAL_NOT_CONFIGURED`, exit 0 |
| MT-E19 | A partial target report is preserved when its step budget expires |
| MT-E20 | No target is dialled when any configuration error exists |
| MT-E21 | No goroutine or worker leak after cancellation |
| MT-E22 | 512 targets complete |

### 6.3 Security — 20

| ID | Case |
|---|---|
| MT-S01 | No secret value in terminal output |
| MT-S02 | No secret value in JSON output |
| MT-S03 | No secret value in shareable output |
| MT-S04 | No secret value on any error path |
| MT-S05 | No cross-target secret reuse: two targets, one reference, distinct credentials |
| MT-S06 | No `security.Reveal` in any fleet package |
| MT-S07 | The runner core imports no adapter, wire, diagnosis, probe or render package |
| MT-S08 | A plaintext config secret is structurally rejected |
| MT-S09 | Arbitrary environment interpolation is rejected |
| MT-S10 | The raw configuration is never serialized |
| MT-S11 | Credential reference names and paths never reach a report |
| MT-S12 | The config file path never reaches a report |
| MT-S13 | `internal/fleet/config` does not import `internal/security` |
| MT-S14 | `internal/cli` still has zero environment-read call sites |
| MT-S15 | Target IDs are pseudonymized under `--shareable` |
| MT-S16 | One host in two targets receives one pseudonym |
| MT-S17 | A credential bound to the wrong endpoint is refused |
| MT-S18 | No `%v` / `%+v` / `%#v` of any credential-bearing structure |
| MT-S19 | `run` exposes no `--password-*` flag |
| MT-S20 | Preflight retains no secret value |

### 6.4 Determinism — 8

| ID | Case |
|---|---|
| MT-D01 | Declared configuration order preserved |
| MT-D02 | Worker completion order does not reach the output |
| MT-D03 | Findings within a target match the single-target run exactly |
| MT-D04 | Target IDs are stable |
| MT-D05 | The aggregate summary is stable |
| MT-D06 | No map iteration decides any order in the fleet layer |
| MT-D07 | JSON is byte-identical across runs, modulo time-varying fields |
| MT-D08 | Concurrency changes no report content |

### 6.5 Report and exit — 18

| ID | Case |
|---|---|
| MT-R01 | Exit 0 — complete, no problems |
| MT-R02 | Exit 1 — complete, one target `PROBLEMS_FOUND` |
| MT-R03 | Exit 2 — configuration error, zero targets dialled, no report |
| MT-R04 | Exit 3 — forced abort |
| MT-R05 | Exit 4 — any `NOT_STARTED` |
| MT-R06 | Exit 4 — any `CANCELLED` |
| MT-R07 | Exit 4 — any `EXECUTION_FAILED`, never 3 |
| MT-R08 | Exit 4 — any incomplete target report |
| MT-R09 | Exit 4 outranks 1 — the §6.1 worked example |
| MT-R10 | Execution-state presence invariants hold |
| MT-R11 | An embedded report is byte-identical to the single-target artifact |
| MT-R12 | Every embedded report still carries `schemaVersion: 1` |
| MT-R13 | The run summary is derived and cannot be supplied |
| MT-R14 | The summary never says "healthy" |
| MT-R15 | A `NOT_STARTED` target has no evidence graph |
| MT-R16 | The renderer makes no cross-target claim |
| MT-R17 | The three non-completed dispositions render distinguishably |
| MT-R18 | The renderer does not choose the exit code |

### 6.6 Regression — 9

| ID | Case |
|---|---|
| MT-G01 | `diagnose postgres` surface unchanged |
| MT-G02 | `diagnose kafka` surface unchanged |
| MT-G03 | `diagnose redis` surface unchanged |
| MT-G04 | `diagnose rabbitmq` surface unchanged |
| MT-G05 | Finding codes still 60 |
| MT-G06 | Failure classes still 42 |
| MT-G07 | `Reveal` still 4, `SecretFor` still 4 |
| MT-G08 | The module graph is exactly 2 |
| MT-G09 | Root usage gains `run` and changes nothing else |

## 7. Phase 9.1 mutation plan — 40 mutations

Each mutation must make at least one named test fail. A mutation that passes is a missing
guard, not a passing build.

| # | Mutation | Caught by |
|---|---|---|
| 1 | Remove duplicate-ID rejection | MT-C02 |
| 2 | Allow an unknown top-level field | MT-C04 |
| 3 | Allow an unknown field inside `config:` | MT-C05 |
| 4 | Allow a plaintext password | MT-C06, MT-S08 |
| 5 | Accept a prefixed scalar such as `env:NAME` | MT-C06 |
| 6 | Interpolate `${VAR}` in any string | MT-C25, MT-S09 |
| 7 | Share one resolved secret object across two targets | MT-S05 |
| 8 | Bypass `SecretFor` | MT-S17 |
| 9 | Call `security.Reveal` from orchestration | MT-S06 |
| 10 | Import `internal/adapter/rabbitmq/wire` from the runner | MT-S07 |
| 11 | Import the PostgreSQL adapter directly from the runner | MT-S07 |
| 12 | Import `internal/security` from `internal/fleet/config` | MT-S13 |
| 13 | Read an environment variable in `internal/cli` | MT-S14 |
| 14 | Report a global cancellation as a remote failure | MT-E06, MT-R06 |
| 15 | Give a never-started target fabricated DNS/TCP evidence | MT-R15 |
| 16 | Let worker completion order set report order | MT-D02 |
| 17 | Hold targets in a map | MT-D06, MT-D01 |
| 18 | Start earlier targets despite a later configuration error | MT-E20, MT-R03 |
| 19 | Stop unrelated targets when one fails | MT-E02 |
| 20 | Make the run summary say "healthy" | MT-R14 |
| 21 | Let the renderer choose the exit status | MT-R18 |
| 22 | Derive the target context from the root instead of the run context | MT-E17 |
| 23 | Accept `concurrency: 0` as unlimited | MT-E13 |
| 24 | Accept `concurrency: 17` | MT-E14 |
| 25 | Remove the 512-target bound | MT-C23 |
| 26 | Remove the 1 MiB config bound | MT-C22 |
| 27 | Serialize a credential reference into the report | MT-S11 |
| 28 | Serialize the config path into the report | MT-S12 |
| 29 | Serialize the raw config into the report | MT-S10 |
| 30 | Accept anchors and aliases | MT-C17 |
| 31 | Accept a merge key | MT-C18 |
| 32 | Accept a non-core tag | MT-C19 |
| 33 | Accept a multi-document file | MT-C20 |
| 34 | Default a missing `version` to 1 | MT-C15 |
| 35 | Let a duplicate YAML key last-win | MT-C14 |
| 36 | Use a separate pseudonym table per target | MT-S16 |
| 37 | Leave target IDs verbatim under `--shareable` | MT-S15 |
| 38 | Make exit 1 outrank exit 4 | MT-R09 |
| 39 | Map `EXECUTION_FAILED` to exit 3 | MT-R07 |
| 40 | Add `--password-file` to `run` | MT-S19 |

Mutations 4, 7, 9, 12, 22 and 34 are the six whose absence would be hardest to notice in
review, and each is guarded structurally rather than by a behavioural assertion.

## 8. Stop conditions — all five cleared

| # | Condition | Finding |
|---|---|---|
| 1 | The single-target architecture cannot support orchestration without weakening credential authority | **Cleared.** `security.Credential` is already endpoint-bound with no plain accessor, and every composition root already refuses a credential bound elsewhere. The fleet layer adds a caller, not an authority |
| 2 | Report semantics cannot represent truthful target-local and run-local incompleteness without a schema break | **Cleared.** `Result.Incomplete()` already travels beside the report because a report cannot observe its own partiality; `TargetResult` carries it the same way, and run-level incompleteness derives from the target list. `SchemaVersion` stays 1 |
| 3 | CLI exit semantics conflict with truthful multi-target CI behaviour | **Cleared.** The five codes and `3 > 2 > 4 > 1 > 0` apply to a set with no addition and no reinterpretation |
| 4 | Service configuration cannot be owned modularly without central branching | **Cleared.** Envelope plus an unparsed service node plus explicit registration at one composition point, exactly as `cli.New` already wires four function values |
| 5 | Credential-source semantics are contradictory across services | **Cleared, and it was checked rather than assumed.** All four commands expose exactly `--password-file` and `--password-stdin`, all four map their identity flag through one `credentialFor`, and Phase 8.2-R3 had already removed the one divergence that existed |

## 9. What Phase 9.1 may implement

The contract, and nothing else. An implementer should be able to write multi-target
execution without a new decision, and any decision they find themselves making is one this
phase missed and should be recorded rather than absorbed.

Specifically **not** authorized without reopening an ADR: a dependency DAG, fail-fast,
cross-target diagnosis, target auto-discovery, a secret-manager source, templating, a remote
config source, a run-level finding code, a `SchemaVersion` change, a global probe semaphore,
streaming output, filtering flags, labels, or any service-specific flag on `run`.
