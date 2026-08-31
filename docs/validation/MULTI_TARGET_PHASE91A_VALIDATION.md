# Multi-target Phase 9.1A — configuration and credential reference foundation

What Phase 9.1A built, what it measured while building it, and what it deliberately did
not build. ADRs [0071](../decisions/0071-multi-target-configuration-schema.md) to
[0074](../decisions/0074-multi-target-report-and-exit-semantics.md) are the frozen
contract; this records the implementation against it.

**There is no multi-target execution.** No runner, no worker pool, no concurrency, no
aggregate report, no `svcdoctor run`. A test asserts that the command is unrouted and that
the root help names it nowhere, because ADR 0048 refuses to expose a command as a stub.

## 1. Start-state gate

Verified at `0f93a6d`, working tree clean, before any production file was touched.

| Invariant | Expected | Measured | After 9.1A |
|---|---|---|---|
| `SchemaVersion` | 1 | 1 | **1** |
| Finding codes | 60 | 60 | **60** |
| RabbitMQ finding codes | 11 | 11 | **11** |
| Failure classes | 42 | 42 | **42** |
| `security.Reveal` sites | 4 | 4 | **4** |
| `Credential.SecretFor` sites | 4 | 4 | **4** |
| External modules | 1 | 1 | **2** |

The module count is the one authorized change, and it is the only one. No finding code, no
failure class, no schema version and no credential-boundary call site moved.

*(A note for whoever runs the gate next: counting finding codes with `grep -rh ... | grep -v
_test` is wrong and reports 61. `grep -h` emits no filename, so the second filter cannot
exclude test files, and one line from `internal/diagnosis/postgres/acceptance_test.go`
survives. Use `grep -rn` and filter on the path.)*

## 2. Packages created

| Package | Owns | May import |
|---|---|---|
| `internal/fleet/config` | bytes, YAML syntax, version, envelope, bounds, identity, registry dispatch, credential reference **shape** | the YAML module, stdlib |
| `internal/fleet/secret` | env and file mechanics, `security.Secret`, endpoint binding | `internal/security`, `internal/fleet/config`, stdlib |
| `internal/fleet/services/{postgres,kafka,redis,rabbitmq}` | one service's typed config and its validation | `internal/fleet/config`, `internal/app` |
| `internal/security/secretinput` | the one implementation of ADR 0049 §3's read semantics | stdlib |

`internal/security/secretinput` is an **extraction, not a new rule**. ADR 0072 §12 requires
a fleet `file:` reference to use exactly the semantics `--password-file` already has and
says *"nothing in this record creates a second interpretation of a secret file"*. A copy in
the resolver would have been two implementations of one contract, drifting silently — the
defect ADR 0060 found when the TLS-flag contract lived in two places. `internal/cli/secret.go`
now delegates to it and its existing tests pass unchanged.

## 3. Measurements taken during implementation

Four library behaviours were measured before the design was fixed. Three of them changed it.

| # | Measured | Consequence |
|---|---|---|
| 1 | A `*yaml.Node` struct field **cannot** be captured under `KnownFields(true)`: the decoder matches the subtree's keys against `yaml.Node`'s own fields and refuses every one | `ServiceNode` exists, with an `UnmarshalYAML` that captures instead |
| 2 | `yaml.Node.Decode` **ignores** the decoder's `KnownFields` setting — an unknown field inside a captured subtree decoded cleanly | `strictDecodeNode` re-encodes the fragment and decodes it through a strict decoder. Without this, unknown fields inside every service config and every credential reference would be silently accepted |
| 3 | A **null value skips `UnmarshalYAML` entirely**, in both pointer and value form. `password:` written and left empty is indistinguishable at the type level from omitting the key | `Credentials.UnmarshalYAML` inspects its own mapping pairs for that one shape |
| 4 | Decoding into `yaml.Node` performs **no duplicate-key detection**; decoding into a typed struct does | The strict decode is what refuses duplicates, and `parseDocument` carries a comment saying so, so nobody adds a second weaker check believing the first is missing |

Result 2 is the one that would have been easiest to get wrong: the natural implementation —
capture a node, call `node.Decode` on it later — compiles, passes an acceptance test, and
silently accepts `config: {database: d, bogus: 1}`.

### 3.1 The YAML library interpolates offending scalars into its own errors

```
cannot unmarshal !!str `hunter2` into config.Reference
```

The single most security-relevant refusal in the package — ADR 0072 §3's structural refusal
of `password: hunter2` — is also the one whose library error carries the password.
Propagating that text unchanged would put a plaintext credential on the operator's terminal
and into anything collecting their stderr.

Two independent defences, deliberately redundant:

- `Reference.UnmarshalYAML` inspects the node's **Kind before the decoder formats anything**
  and builds its own message naming the YAML kind, never the value.
- `sanitizeYAML` redacts every backtick-quoted span from **every** library error, at the one
  place each becomes a `config.Error`. It fires only on the `cannot unmarshal` family — the
  other two families use double quotes — and preserves the tag and target type, which are
  the parts that explain the defect.

The second exists because a defence covering only the anticipated shapes is the one that
fails on the shape nobody anticipated. `credentials: hunter2`, one level up from the
position the interceptor guards, is caught by the sanitizer alone.

## 4. What was implemented, against the contract

| Contract | Implementation |
|---|---|
| One strict YAML document | `parseDocument`; a second `Decode` must return `io.EOF`. A trailing `---` counts as a second document, measured; a trailing comment does not |
| 1 MiB config bound | `MaxBytes`, checked from `os.Stat` before reading and again on a bounded read one byte past the limit |
| Regular file after symlink resolution | `os.Stat` follows symlinks; directory, FIFO, device and socket are each named |
| `version: 1`, required | Lax probe before the strict decode, so `version: 2` says so rather than producing an unknown-field avalanche |
| Unknown fields refused | `KnownFields(true)` at the root **and** in every re-encoded fragment. Tested at seven levels |
| Duplicate keys refused | The decoder's, at every depth. Tested at five levels |
| Anchors, aliases, merge keys refused | `checkStructure` walks nodes and reads `Anchor`, `Kind` and `Tag` — never raw text, so `host: "&foo.example.com"` is data |
| Tag allow-list | `!!str !!int !!bool !!null !!map !!seq`, plus the empty document tag |
| Target `id` required, explicit | 1–63 bytes, `[a-z0-9_-]`, alphanumeric at both ends, lowercase **enforced not folded** |
| 512 targets | `MaxTargets`, tested at 0, 1, 512 and 513 |
| Declared order preserved | Targets are a slice from decode onward; nothing sorts and no map is iterated to produce them |
| Registry dispatch | `NewRegistry` refuses duplicate and nil registration and a zero default port; the core names no service |
| `env` / `file` only, exactly one | `Reference`, a closed union with two name fields and no value field |
| Plaintext refused structurally | By the decoder's type, for nine scalar shapes |
| Preflight without retention | `Resolver.Preflight`; env reads and drops, file stats only |
| No secret cache | `Resolver` is a zero-field struct; every `Resolve` reads the source |

### 4.1 Two deliberate, frozen differences from the leaf commands

Both are ADR 0072's, not this phase's, and both are recorded because they look like
inconsistencies until the reason is stated.

- **An empty credential file is a fleet preflight failure and a leaf-command "no
  credential".** ADR 0072 §5.1 froze the preflight as *"regular file, non-empty, within the
  size bound"*; ADR 0049 maps an empty `--password-file` to an unset credential. Both are
  right: an operator who wrote `password: {file: X}` asked for a credential, and reporting
  `CREDENTIAL_NOT_CONFIGURED` when the store returned nothing would describe the wrong
  problem. The *read* semantics are byte-identical — one shared implementation.
- **The fleet preflight requires a regular file; `--password-file` does not.** The leaf
  command has no preflight to hold such a check, and `secretinput.ReadFile` deliberately does
  not impose one: tightening released input handling is a decision for ADR 0049, for all four
  commands at once, and this phase does not make it.

### 4.2 One clarification of ADR 0072 §2, which changes no decision

`password:` written and left empty is refused, with the same reason `password: {}` is
refused — *a reference that names nothing*. The ADR's table lists `{}` and does not list an
explicit null, because at contract time the two looked like one case; measurement 3 above
showed the type system cannot see the second. The refusal is the `{}` rule reaching a
syntactically equivalent form. It narrows nothing and widens nothing, so no ADR text was
edited.

### 4.3 Host validation stops at syntax, on purpose

`checkHostSyntax` requires a non-empty host with no whitespace or control character, and
nothing more. Canonicalization — literal parsing, IPv6 zone refusal, the single spelling
every later layer must agree on — stays in `internal/app` through `internal/probe`, where it
already is for all four leaf commands.

This is neither stricter nor looser than a leaf command: `probe.ParseHost` returns any
non-empty non-literal string verbatim, so `host: db.example.com:5432` is accepted here and
fails at resolution exactly as `--host db.example.com:5432` does today. A second
normalization here is the drift ADR 0042 records, where one spelling of an IPv6 address
appeared in the anchor and another in the connection subject of a single report.

## 5. Service configuration

| Service | Own fields | Service-owned validation of generic fields |
|---|---|---|
| postgres | `database` | `credentials.username` **required** — the startup message has no anonymous form, so a role is needed whether or not a password is |
| kafka | `sasl_mechanism` (required) | identity and credential must be present together or absent together |
| redis | none | none |
| rabbitmq | `vhost` (default `/`) | `step_timeout` must **exceed 3 s** |

`step_timeout` is ADR 0071 §7.1's second clause, measured: identical semantics, one
service-owned range. It is pinned on both sides — RabbitMQ refuses 3 s and the other three
accept 1 s.

**Kafka takes one bootstrap endpoint and no broker list.** `app.KafkaParams` has one
`Host`/`Port`; a `brokers:` list would advertise a capability the composition root does not
have. A test refuses `brokers`, `bootstrap_servers` and `bootstrap`.

**Redis adds no field**, and `config: {db: 0}` is refused rather than ignored. `SELECT` is
not in ADR 0063's three-command allowlist, so a `db:` field would be configuration for
behaviour svcdoctor does not have — and an inert field reads as an honoured one.

## 6. Tests

**84 new test functions, 726 assertions including subtests.**

| Area | Functions | Covers |
|---|---|---|
| `internal/fleet/config/config_test.go` | 28 | MT-C01–C04, C08–C17, envelope, registry, bounds, errors |
| `internal/fleet/config/credential_test.go` | 13 | MT-C05, C18–C20, env grammar, interpolation absence |
| `internal/fleet/config/services_test.go` | 11 | four service configs, duplicate endpoints, no network I/O |
| `internal/fleet/secret/secret_test.go` | 16 | MT-C06, C07, MT-S01, S04, S05, S09; inherited file semantics |
| `test/security/fleet_boundary_test.go` | 12 | MT-S02, S03, S08, S10, plus their non-vacuity proofs |
| `internal/cli/fleetregression_test.go` | 4 | the four leaf surfaces, and `run` unrouted |

Phase 9.0 matrix coverage: **MT-C01 through MT-C20 complete**, and **MT-S01 through MT-S10
complete**. The execution, determinism and report matrices belong to Phase 9.1B and are
untouched.

### 6.1 Guards, and their non-vacuity proofs

Every structural guard is paired with a proof that its scan can see something. A guard whose
package list has silently gone empty passes forever, which is worse than no guard.

| Guard | Non-vacuity proof |
|---|---|
| the config package cannot construct a secret | the import scan finds the YAML module in that package |
| the fleet core reaches no protocol | the core's import list is non-empty |
| only the config package imports YAML | that package is proven to import it |
| the fleet layer never reveals a secret | the scan finds a real `security.Reveal` in `internal/adapter/redis/wire` |
| only the resolver reads the environment | the scan finds `os.LookupEnv` in the resolver, so the env source is proven implemented |
| the resolver holds no state | the `Resolver` type is proven to be found and parsed |
| the generic core names no service | the core's source is proven to be scanned |

## 7. Mutation closure — 20 planted, 20 caught, 0 survivors

`scripts/phase91a-mutations.sh` plants each mutation, runs the guard that should notice, and
requires it to **fail**. The tree is restored and verified byte-for-byte against sha256
checksums taken before anything was touched.

| # | Mutation | Caught by |
|---|---|---|
| A01 | unknown fields accepted | `TestMTC04...` |
| A02 | duplicate YAML keys accepted | `TestMTC09...` |
| A03 | YAML merge key accepted | `TestMTC11MergeKeyIsRejected` |
| A04 | plaintext scalar password accepted | `TestMTC05AndC18...` |
| A05 | env and file together accepted | `TestMTC19...` |
| A06 | empty credential reference accepted | `TestMTC20...` |
| A07 | duplicate target IDs accepted | `TestMTC02...` |
| A08 | target count limit removed | `TestMTC15AndC16...` |
| A09 | config byte limit removed | `TestMTC14...` |
| A10 | unsupported config version accepted | `TestMTC10ConfigVersion` |
| A11 | arbitrary `${VAR}` interpolation added | `TestOnlyTheResolverReadsTheEnvironment` |
| A12 | config package reads the environment | same |
| A13 | resolver reveals a secret | `TestTheFleetLayerNeverRevealsASecret` |
| A14 | resolved secrets cached globally | `TestTheFleetLayerHasNoSecretCache` |
| A15 | a resolved secret reused for one reference | `TestResolutionReadsTheSourceEveryTime` |
| A16 | the core imports an adapter wire package | `TestTheFleetCoreReachesNoProtocol` |
| A17 | a service-specific union in the generic core | `TestTheGenericCoreNamesNoService` |
| A18 | targets sorted instead of declared order | `TestMTC17...`, `TestDeclaredOrderSurvives...` |
| A19 | raw configuration retained in the model | `TestAValidatedConfigRetainsNoRawBytes` |
| A20 | a resolver error carries the secret value | `TestTheFleetLayerNeverRevealsASecret` |

### 7.1 A03 survived its first form, and the finding is kept

Removing the explicit `!!merge` branch from `checkStructure` changed **no outcome**: the tag
allow-list already refuses `!!merge`, because it is not in it. The branch is therefore
redundant for safety and earns its place only on message quality — an operator who wrote
`<<:` is told they wrote a merge key rather than that they used a tag whose name they never
typed.

Three things came out of that, and all three are kept:

1. the code comment was corrected, because it had implied the branch was the load-bearing
   refusal;
2. the mutation was corrected to remove **both** refusals, which is what "merge keys are
   accepted" actually means;
3. the redundancy is recorded here, so nobody deletes the allow-list entry believing the
   branch covers it.

Three mutations planted during development — A11, A17 and A19 — had **no guard** when first
written. Each guard was added in response, which is the mutation matrix doing the job it
exists for rather than confirming work already done.

## 8. Single-target regression

Unchanged, and checked rather than assumed:

- all four `diagnose` flag surfaces are pinned flag by flag;
- `--config`, `--targets`, `--concurrency`, `--target` and `--password-env` are each refused
  as unknown on all four;
- `internal/cli` still contains **zero** environment-read call sites, asserted from outside
  the package as well as by its own existing guard;
- `svcdoctor run` is unrouted and the root help lists no command that does not exist.

`internal/cli/secret.go` was refactored to delegate to `internal/security/secretinput`. Its
existing tests — trailing-line-ending semantics, the `TrimSpace` prohibition, the bound on
the input as read, the oversize message, path-naming in errors — pass unchanged, which is
what makes the extraction behaviour-preserving rather than merely intended to be.

## 9. Quality gate

| Check | Result |
|---|---|
| `git diff --check` | clean |
| `gofmt -l .` | clean |
| `go vet ./...` | clean |
| `golangci-lint run` | **0 issues** |
| `go test ./...` | pass |
| `go test -race ./...` | pass |
| `CGO_ENABLED=0 go build ./...` | pass |
| `go mod tidy` | **no-op** |
| `make check` | pass |

No Docker, no network test, no container, and no generated secret outside a `t.TempDir()`.
Two `//nolint` directives were added, each with its reason: a gosec G101 false positive on
the error-category name table, and a staticcheck S1025 on a `%s` format that is deliberately
exercising that verb.

The YAML module was fetched once during Phase 9.0's research in a scratch module outside the
repository, and once here into `go.mod`. `go.sum` holds two entries for it and none for
anything transitive, because it requires nothing.

## 10. What Phase 9.1B may implement

The runner, the worker pool, budgets and cancellation, the aggregate report, the execution
states, the exit-code mapping, `svcdoctor run --config`, and the run-level redaction entry
point.

Nothing in this phase decided any of those. What it fixed is the shape they consume: a
`config.Config` holding validated targets in declared order, each carrying a typed service
configuration and a credential *reference*, and a `secret.Resolver` that turns one reference
into one endpoint-bound credential and caches nothing.

Three tests are expected to be **inverted rather than deleted** in 9.1B, the way the RabbitMQ
contract-freeze guard was turned around at 8.2: `TestTheRunCommandIsNotRoutedYet`,
`TestTheRootUsageNamesNoUnimplementedCommand`, and the `fleetCorePackages` list once the
runner package exists.
