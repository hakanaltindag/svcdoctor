# Phase 10.7B — PostgreSQL session read-only observation completion

- **Phase:** 10.7B — implementation. Class 1 activation: **no observation is acquired.**
- **Baseline:** `92158d128b6e85faddf959f6c97e72f31f7342fc`
- **Record:** ADR 0089 §7 (this phase is its implementation; no new ADR is required)
- **Result:** `postgres.default_transaction_read_only` is presented as a terminal observation
  line beside the existing `recovery` line, and proven `on` against a real PostgreSQL 18 server.

---

## 1. What changed, and what did not

**Changed:** the terminal Result block for PostgreSQL gains one line —
`default transaction read-only` with the value `on` or `off` — and one conditional note that fires
only on `on`.

**The line prints the parameter's own value, and that is the phase's sharpest decision.** An
earlier draft rendered `off` as *"read write"*. It was withdrawn on review: the parameter says one
default is **not set**, and every positive phrasing of that — "read write", "writable", "writes
enabled" — is a claim about what the session can *do*, which svcdoctor did not measure. The label
carries the meaning; the value stays the endpoint's own token. `PSRO-M04b` plants the withdrawn
rendering and the tests kill it.

**Not changed:** canonical JSON, `SchemaVersion`, `RunSchemaVersion`, finding codes, failure
classes, rules, `RuleContext`, exit codes, the CLI, the security model, credential authority,
dependencies, configuration semantics, and every other renderer. **No SQL, no protocol request,
no second connection, no round trip.**

The value has been on the wire and in canonical evidence since Phase 4.5. Phase 10.7A measured
that nothing read it (ADR 0089 §1.2) and selected it as the smallest, safest activation available.

## 2. The observation contract

| | |
|---|---|
| **Operator question** | *"What did the PostgreSQL session svcdoctor established report for `default_transaction_read_only`?"* |
| **Subject** | **the session svcdoctor established** — never the server, backend, database, cluster, requested hostname, any other connection, or the application |
| **Source** | `ParameterStatus("default_transaction_read_only", …)`, retained by `wire.SessionParameters` |
| **Domain** | exactly `on` and `off`. Anything else, including a value merely beginning `on`, drops the line |
| **`on` renders** | `default transaction read-only   on`, plus a bounded note |
| **`off` renders** | `default transaction read-only   off`, and **no note**. Never a positive phrasing |
| **Absent renders** | nothing at all. It is never defaulted, never "unknown", never a finding |
| **Prerequisite** | a `postgres.session` node. A run that established none renders no line |

### 2.1 Claims it does not make

Not that the server, database or backend is read-only. Not that writes will fail, or work. Not
that the application can or cannot write. Not that the endpoint is a replica, a primary or in
recovery. Not that anything is misconfigured. Not a fault, at any severity.

The parameter that settles a given transaction is the session-local `transaction_read_only`,
which is not sent as a `ParameterStatus` and would need SQL (ADR 0039 §17, ADR 0040 §20).
Object, database and row-level privileges are untouched by it, a transaction may override the
default with `SET TRANSACTION READ WRITE`, and a pooler may serve the next one from a different
backend.

### 2.2 Independence from `in_hot_standby`

The two lines read two attributes and **neither derives from the other**. The repository measured
a real standby reporting `in_hot_standby=on` while `default_transaction_read_only=off`, so a
reader that collapsed them would publish a mode nobody reported. All four combinations are valid
and none is a contradiction — `in_hot_standby=off` beside a read-only default is the ordinary
shape of `ALTER ROLE … SET default_transaction_read_only = on`.

### 2.3 Pooler and proxy boundary

PgBouncer, Pgpool and other intermediaries forward or synthesize `ParameterStatus`, and under
transaction or statement pooling the next transaction may be served by a different backend. The
claim survives that thought experiment because it is scoped to the session: svcdoctor reports
what the endpoint said to **this** session and attributes it to no backend. This is ADR 0040
§18's *"endpoint, never server"* applied to one more value.

## 3. Requirement register — `PSRO-001` … `PSRO-020`

All **FROZEN** and all proven; there is no NEXT_IMPLEMENTATION tier, because the phase is
complete.

| ID | Requirement | Proven by |
|---|---|---|
| PSRO-001 | No new PostgreSQL network operation | no adapter, probe or wire file changed; `git diff` is the proof |
| PSRO-002 | No SQL | unchanged; ADR 0039 §17's AST guard still passes |
| PSRO-003 | Consumes only the already-normalized `postgres.default_transaction_read_only` | `TestPSROTheModeAttributeIsDeclaredByTheServiceView` |
| PSRO-004 | Subject is the svcdoctor-established session | prose review; `TestPSROOn…` forbidden set |
| PSRO-005 | `on` implies no server/database/application-wide read-only state | `TestPSROOnRendersABoundedSessionObservation`, PSRO-M03 |
| PSRO-006 | `off` implies no writability and is never rendered positively | `TestPSROOffIsNotReassurance`, PSRO-M04, **PSRO-M04b** |
| PSRO-007 | Absence does not default to `off` | `TestPSROAbsentParameterRendersNothing`, PSRO-M01/M02 |
| PSRO-008 | No `FindingCode` | 65, attributed 65 of 65 |
| PSRO-009 | No diagnostic rule consumes the attribute | `TestTheRulesReadOnlyTheAuthorizedAttributes` (four-key allowlist), `TestSessionFactsStayEvidenceAndNeverBecomeFindings` |
| PSRO-010 | No severity, recommendation or remediation | `TestPGP21`, integration assertion, PSRO-M09/M10 |
| PSRO-011 | Independent from `in_hot_standby` | `TestPSROTheTwoObservationsAreIndependent`, `TestPSROTheRecoveryValueNeverDrivesTheModeLine`, `TestPGP21`, corpus P08's strengthened guard, PSRO-M05/M06/M07 |
| PSRO-012 | No operator intent inferred | `TestNoPostgresFindingAssertsAnExpectation`; no note or line names an expectation |
| PSRO-013 | Canonical JSON unchanged | `internal/domain`, `internal/render/json` and every golden untouched; `test/golden` green |
| PSRO-014 | Schema versions unchanged | `SchemaVersion` 1, `RunSchemaVersion` 1 |
| PSRO-015 | Credential authority unchanged | `Reveal` 4, `SecretFor` 4; no credential code touched |
| PSRO-016 | Exit codes unchanged | 5; the observation reaches no severity and no summary status |
| PSRO-017 | A real PostgreSQL 18 fixture proves `on` | `svcd-pg-readonly`, started `-c default_transaction_read_only=on`; `TestRealServerReportsAReadOnlyDefaultAndSvcdoctorClaimsNothing` |
| PSRO-018 | Renderer tests prove `on`, `off`, absent, independence and unrecognized | six `TestPSRO*` tests, whose forbidden set includes `read write` / `read-write` |
| PSRO-019 | Focused mutation closure proves the semantic guards | `scripts/phase107b-mutations.sh` — **14 planted, 14 caught, 0 survivors** |
| PSRO-020 | `make check` green | exit 0 |

## 4. The real fixture, and what it forced

`svcd-pg-readonly` is a third PostgreSQL 18 container started with
`-c default_transaction_read_only=on`. **No statement sets the value**, so it arrives in the
`ParameterStatus` stream ahead of `ReadyForQuery` exactly as a real deployment's would.

The first attempt at the fixture failed, and the failure is worth recording because it constrains
any future one. `-c` applies from process start, **including to the temporary server the
entrypoint uses to initialize the cluster** — so `CREATE DATABASE "appdb"`, `ALTER USER … WITH
PASSWORD` and every `CREATE ROLE` in `init.sql` failed with *"cannot execute CREATE DATABASE in a
read-only transaction"*. The container therefore runs with `POSTGRES_HOST_AUTH_METHOD=trust`, the
default database and no init script, so the entrypoint issues **no SQL whatsoever**. The run
connects as the bootstrap superuser over plaintext with no credential, which also keeps the
credential-transport policy out of the measurement.

**Measured:** `default_transaction_read_only = on` and `in_hot_standby = off` on the same session
node — the primary-with-a-read-only-default pair — with zero findings, `SummaryStatus` `OK`, and
`default transaction read-only   on` in the Result block, beside the note that names **this session** rather than the endpoint.

## 5. Mutation closure

`scripts/phase107b-mutations.sh` — **14 planted, 14 caught, 0 survivors**, tree restored
byte-for-byte.

`PSRO-M01` absent → `off` · `M02` absent → `on` · `M03` session claim → server-wide claim ·
`M04` `off` → writability reassurance · **`M04b` `off` inverted into `read write`** · `M05`
recovery drives the read-only line · `M06` the read-only value drives the recovery line · `M07`
the two facts merged into one verdict · `M08` arbitrary peer value rendered verbatim · `M09` the
line graded as a fault · `M10` a read-only default called a misconfiguration · **`M13` the note
attributes the parameter to the endpoint rather than the session** · `M11` the observation
deleted · `M12` the render map admits a near-miss value.

**Two contract mutations are deliberately not planted**, because the architecture makes them
unplantable rather than merely wrong, and saying so is more useful than a green line: a rule
reading the attribute (`internal/diagnosis/postgres` cannot import the renderer, and
`TestTheRulesReadOnlyTheAuthorizedAttributes` scans its source against a four-key allowlist), and
a `FindingCode` for the observation (pinned by attribution at 65). Both are exercised by the
frozen-inventory run instead.

## 6. Validation run

```
make check                                          # exit 0 — MANDATORY
  fmt-check OK · go test ./... · go vet ./... · golangci-lint run ./... "0 issues." · build
git diff --check                                    # clean
bash scripts/phase107b-mutations.sh                 # 12/12, 0 survivors, tree restored
make postgres-up                                    # three servers ready
go test -tags integration ./test/integration/postgres/...   # 93 pass, 1 pre-existing failure
go test ./test/security/... -run 'Closure|Convergence|RuleContext|Schema|Reveal|SecretFor|Dependenc|Module'
```

**The one integration failure is environmental, and the attribution is established by
isolation rather than asserted.** `TestTheTLSKeyIsOwnedByTheDatabaseUser` requires
`env/certs/server.key` to be owned by uid 999; on this macOS host the bind mount reports uid 0.
Four independent checks:

1. this phase modified no certificate, no `gen-certs.sh` and no TLS file — `git status` shows none;
2. the ownership assertion itself is byte-identical to `HEAD` — `git diff HEAD -- fixture_test.go`
   is empty, and it was **not weakened**;
3. the `svcd-pg-readonly` container declares **no `volumes:` key at all**, so it cannot touch that
   key;
4. **reverting all three of this phase's production files to `HEAD` and removing the new
   integration test reproduces the identical failure**, with the same uid 0 message.

Every TLS-dependent behavioural scenario in the same run passed, including
`TestRealServerSCRAMOverVerifiedTLS`, `TestAppTLSDeclined`, `TestAppInBandTLSFailureIsDiagnosed`
and `TestCLIInsecureTLSWithholdsTheCredential`. **No integration-green claim is made.**

**Fuzzing: not applicable and not run.** The phase crosses no parser and no normalizer. The
`ParameterStatus` decoder is unchanged and keeps its existing coverage; the render map is a
two-case switch over an already-decoded value, and the hostile-value path is covered exactly by
`TestPGP13ServerControlledTextNeverReachesTrustedProse` and
`TestPSROAnUnrecognizedValueDropsTheLine`. Inventing a fuzz target here would be ceremony.

**Other integration suites not run:** Kafka, Redpanda, Redis, Valkey, RabbitMQ, LavinMQ,
multi-target. The blast radius was assessed: the change is data in the PostgreSQL entry of the
renderer's `services` table plus one vocabulary constant. `observationLines` and `activeNotes`
are untouched, so no other service's view can render differently — and the whole hermetic suite,
including every other service's renderer goldens, is green under `make check`.

## 7. Frozen counts — all unchanged

`SchemaVersion` **1** · `RunSchemaVersion` **1** · finding codes **65** (attributed 65 of 65) ·
production rules **22** · `RuleContext` fields **3** · failure classes **42** · external modules
**2** · `Reveal` **4** · `SecretFor` **4** · exit codes **5**.

**Gates:** Phase 10.4C remains **closed** — this observation produces no hypothesis and no
competing pair. Phase 10.5B remains **closed** — no `SUPPORT`, `CONTRADICTION`, `MISSING` or
`BLOCKED` producer exists.
