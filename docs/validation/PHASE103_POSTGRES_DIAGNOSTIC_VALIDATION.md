# Phase 10.3 — PostgreSQL diagnostic intelligence: validation

**Date:** 2026-09-05
**Baseline:** `e71208b569e02a24868526f268f217ec32c86280` (Phase 10.2A), `HEAD == origin/main`,
tree clean, `v0.4.0^{} == 118231120eb1ef88af7c262648d23926e0677266`.
**Record:** ADR 0085.
**Release state:** **uncommitted, unreleased candidate.** Nothing in this phase is committed,
tagged or published. The most recent release tag is `v0.4.0`; every "behaviour change" recorded
here is a change to *candidate* public behaviour, measured against what `v0.4.0` published. See
§13.

---

## 1. What this phase was asked to demonstrate

Phase 10.2 showed topology-aware reasoning. This one had to show something different:
**distinguishing an authoritative server observation from an inferred cause, and both from a
violated intent.** PostgreSQL is the right exemplar because of an asymmetry no other service in
the tree shows so plainly — the server often names *what* happened in a field its protocol
defines, and says nothing whatever about *why*.

> **PostgreSQL told us WHAT happened. svcdoctor does not therefore know WHY it happened.**

Two worked examples, both implemented:

| The server said | svcdoctor CONFIRMS | svcdoctor leaves UNKNOWN |
|---|---|---|
| SQLSTATE `53300` | this endpoint authoritatively rejected **this attempted session** with its `too_many_connections` condition — a connection limit that applied to the attempted session had been reached at that moment | **which** limit was reached; a leak, a limit set low, a pool sized wrongly, a burst; whether the condition outlasted the instant; whether the limit is enforced at the endpoint or behind it; whether any other session would have been refused |
| `in_hot_standby = on` | this endpoint reported the session as being in recovery | whether that role is a replica or a primary whose value a pooler cached, whether it is writable, and **whether it violates what the operator wanted** |

The second row is the one that produced the phase's most consequential decision, and it is a
refusal: **the observed role is not a finding at all.**

## 2. Evidence capability matrix

Read off `internal/adapter/postgres` and `internal/probe`, not off a document.

### 2.1 Authoritative — the peer stated it in its own protocol

| Observation | Source | Layer | Subject | Vantage-dependent | Consumed by a rule |
|---|---|---|---|---|---|
| SQLSTATE `28000` at `postgres.startup` | `ErrorResponse` field `C` → `AUTHZ_NOT_PERMITTED` | L4 | address | **yes** (matches on source address) | `POSTGRES_CONNECTION_NOT_PERMITTED`, `POSTGRES_ADMISSION_SCOPE` |
| SQLSTATE `28000` at `postgres.authentication` | same | L5 | address | yes | `POSTGRES_CONNECTION_NOT_PERMITTED` |
| SQLSTATE `28P01` | → `AUTH_CREDENTIALS_REJECTED` | L5 | address | no | `POSTGRES_CREDENTIALS_REJECTED` |
| SQLSTATE `3D000` | → `RESOURCE_NOT_FOUND` | L5 | address | no | `POSTGRES_DATABASE_NOT_FOUND` |
| SQLSTATE `42501` | → `AUTHZ_DENIED` | L5 | address | no | `POSTGRES_DATABASE_CONNECT_DENIED` |
| **SQLSTATE `53300` at `postgres.session`** | → `RESOURCE_LIMIT_REACHED` | L5 | address | no | **`POSTGRES_CONNECTION_LIMIT_REACHED` (new)** |
| `AuthenticationOk` / demanded method | `postgres.auth_method` | L4 | address | yes | `POSTGRES_*` auth rules |
| SASL mechanisms offered | `postgres.sasl_mechanisms` | L4 | address | yes | adapter only |
| `ReadyForQuery` reached | `postgres.session` PASS | L5 | address | no | nothing — a passing path produces zero findings |
| **`in_hot_standby`** | `ParameterStatus` allowlist | L5 | address | no | **no rule; renderer observation (new)** |
| `default_transaction_read_only` | `ParameterStatus` | L5 | address | no | no rule |
| `is_superuser` | `ParameterStatus` | L5 | address | no | no rule |
| `server_version` | `ParameterStatus` | L5 | address | no | no rule, **and no renderer line** — §7.2 |
| `transaction_status` | `ReadyForQuery` payload | L5 | address | no | no rule |
| `postgres.error_is_native` | `ErrorResponse` field `V` present | L4/L5 | address | no | detail prose only; never an input (ADR 0040 §18.1) |
| `postgres.ssl.offered` | the `S`/`N` answer | L3 | address | no | `POSTGRES_TLS_DECLINED` |

### 2.2 Derived — svcdoctor's own arithmetic over the above

| Observation | Derivation | Completeness required |
|---|---|---|
| the requested target | recorded before measurement, `target.requested`, TARGET subject | — |
| resolved addresses | `dns.lookup`; absent entirely for a literal target (ADR 0059) | — |
| per-address transport outcome | `tcp.connect`, `tls.handshake` | for a "no path works" claim |
| **admission scope across addresses** | counting `postgres.startup` verdicts under one anchor | **yes**, for "at all N" |
| failure boundary per subject | `DIAG_FAILURE_BOUNDARY` | no |
| run incompleteness | `RuleContext.Incomplete` | — |

### 2.3 NOT CURRENTLY KNOWABLE

Each of these was checked against the tree, and no rule may depend on any of them.

| Fact | Why not |
|---|---|
| `pg_is_in_recovery()` directly | BASIC executes no SQL; an AST guard enforces it |
| session-local `transaction_read_only` | not sent as `ParameterStatus`; needs SQL |
| `max_connections`, or any configured value | svcdoctor reads no server configuration |
| connections currently in use | needs `pg_stat_activity`, i.e. SQL and a privilege |
| whether a backend or a pooler answered | `error_is_native`'s absence is equally consistent with a pooler, a proxy and a pre-9.6 server (ADR 0040 §18) |
| whether two addresses are one server | nothing observed distinguishes them |
| the endpoint's replication topology | never measured |
| **declared operator intent of any kind** | no CLI flag, no target YAML field, no adapter parameter, no report field. `ROLE_INTENT_NOT_AVAILABLE`. |
| two roles in one run | structurally impossible — §5 |

## 3. Server authority → maximum claim strength

| Evidence authority | Example | Maximum claim | Why |
|---|---|---|---|
| **Direct peer statement** in a protocol-defined field | SQLSTATE `53300`, `28000`, `28P01` | `CONFIRMED` / `HIGH` about *what the peer reported* | `AuthorityDirect`: not an inference, a repetition |
| **Direct peer parameter** in an allowlisted field | `in_hot_standby` | an observation the renderer prints; **no finding** | it restates one attribute, and without intent there is nothing to act on |
| **Complete contrast** over a measured set | every address refused, nothing undetermined | `CONFIRMED` / `HIGH` about *the set*, `INFO` severity | every member measured and cited |
| **Partial contrast** | some addresses undetermined | the same claim with all three counts and no total | "not measured" is never "not reached" |
| **Transport observation** | TCP refused from this vantage | `CONFIRMED` about reachability *from here* | ADR 0012 |
| **Derived interpretation** | "this endpoint is unsuitable for writes" | **not admissible** | needs intent, which does not exist |
| **Mechanism behind an effect** | "a leak caused the exhaustion" | **not admissible at any confidence** | no mechanism was observed and none is discriminable |
| **Scope wider than the statement** | "the endpoint has no connection slot available" from `53300` | **not admissible**; the claim stays at the attempted session | `53300` is raised against whichever applicable limit was reached, and `CONNECTION LIMIT 0` on a role produces it on a server with connections to spare |

No statistical reasoning, no common-cause reasoning, no confidence voting. Convergence is
`MEDIUM` by definition and never accumulates (ADR 0081 §2.2).

## 4. Rule inventory

Two production rules added; one candidate deliberately implemented outside the finding layer.

| | `postgres/admission-scope` | the 53300 branch of `postgres/session` |
|---|---|---|
| **FindingCode** | `POSTGRES_ADMISSION_SCOPE` | `POSTGRES_CONNECTION_LIMIT_REACHED` |
| **Subject** | the requested target (TARGET kind) | the address (ENDPOINT kind) |
| **Kind / Severity / Confidence** | CONFIRMED / **INFO** / HIGH | CONFIRMED / ERROR / HIGH |
| **Layer** | L4 protocol | L5 auth |
| **Authority** | restates measured states; true by construction | `AuthorityDirect` |
| **Required evidence** | one target anchor, ≥2 classified `postgres.startup` nodes, ≥1 refused | a FAIL `postgres.session` node with `RESOURCE_LIMIT_REACHED` **and** a parent proving authentication completed |
| **Support** | the anchor and every classified startup node | the session node, the proof, the startup node |
| **Contradiction** | none recorded; the shape that would contradict it stops the rule | none |
| **Missing** | the undetermined addresses' decisions | connection utilisation and configured limit |
| **Blocked** | a skipped startup node is *undetermined* and cited only as "no decision observed" | — |
| **Discriminator** | none (CONFIRMED) | none (CONFIRMED) |
| **Recommendation** | `NEXT_EVIDENCE`/`COMPARE` on contrast; `NEXT_EVIDENCE`/`OBSERVE` when partial; none when complete and uniform | one `NEXT_EVIDENCE`/`COMPARE`, `SelfCollectable: false`, naming **no** applicable limit — *identify the connection limits applicable to this attempted session and compare their current usage with their configured limits* |
| **VantageDependent** | true | **false** — "not inferred from a source-address-dependent observation", never "endpoint-wide invariant" |
| **Forbidden** | misconfiguration, "add a rule", credential claims, reachability claims, server identity | leak, `max_connections`, pool, spike, memory, "increase", where the limit lives, **which limit was reached**, and every endpoint-wide wording of the shortage |

**Value beyond what existed**, which is the test each had to pass:

- The admission scope carries **completeness** and **contrast**, neither of which is in the
  conjunction of per-address findings and neither of which was expressible before
  `RuleContext.Incomplete`.
- The connection-limit claim turns a **prose sentence into a machine-readable code**. A CI job
  must not parse `detail` (`docs/FINDINGS.md` §3.1 rule 13), and before this it had nothing else
  to match on.

**Discarded because they already exist**: pg_hba admission rejection, server-rejection-after-
healthy-transport, policy-vs-credentials, credential withholding, TLS reinterpretation. Five of
seven candidate domains, which is the same ratio Phase 10.2 found for Kafka.

**Discarded as restating its own observation**: a per-address admission *hypothesis*. For Kafka
the suitability hypothesis said something the counts did not; here "admission differs between
these two addresses" *is* what the counts say.

## 5. Multi-host: unreachable, not forbidden

The single most important structural result of the phase.

`internal/app/postgres.go` measures every resolved address through DNS, TCP, `SSLRequest`, TLS and
`Startup` — all credential-free — and then **continues exactly one path** (ADR 0041 §§5-9). A run
therefore holds **at most one authentication node and at most one session node**, whatever the
target resolved to.

So the following are graphs **no producer makes**:

- endpoint A reports primary and endpoint B reports standby;
- two endpoints both report themselves out of recovery;
- one address answers `53300` while its sibling accepts.

Nothing suppresses those claims. There is no evidence from which to draw them, which is a much
stronger property than a forbidden-substring test, and it is guarded as one:
`TestPGStructuralSingleSessionPerRun` parses the composition root and requires `selectPath` and
`continuePath` to be called exactly once each. A change that continued two paths fails there
rather than in a report.

**Split brain, dual primary, fencing failure and Patroni failure are therefore unreachable**, and
the corpus additionally forbids the words so that a future evidence change cannot quietly make
them sayable.

What *is* reachable and is built: the **admission contrast at the startup stage**, because that
stage runs on every address by design.

## 6. Declared intent

`ROLE_INTENT_NOT_AVAILABLE`. Searched: `internal/cli`, `internal/fleet/config` (the target YAML
decoder), `internal/adapter/postgres`'s parameters, `internal/app`'s `PostgresParams`, and
`domain.Report`. **None carries an expected role, an expected TLS posture or an expected anything.**

ADR 0083 §2.6 froze that for the whole of Phase 10: *"No configuration change in Phase 10 …
Until an `expect:` block exists, a standby is a standby and not a fault."*

**Classification of the pressure: `CONFIG_CONTRACT_PRESSURE` + `ADR_DECISION_REQUIRED`.** Adding
intent means adding a target configuration field, which is ADR 0071's strict-schema contract, and
it needs its own record and its own review of what a closed expectation vocabulary may contain. It
is **deferred, not declined**, and nothing was smuggled in through rule configuration, a detail
string or a subject.

**The phase is therefore not `PHASE_10_3_DESIGN_BLOCKED`**: the decision that would have blocked
it was already made, in an Accepted record, before the phase began. Role observation is
implemented; role mismatch is deferred; ADR 0085 §5 records both.

## 7. What was deliberately not built

### 7.1 A role finding

ADR 0085 §4. ADR 0040 §20 named three reopen conditions — SQL authorized, intent expressible, or a
second non-SQL writability fact — and **none has fired**. Its second ground stands untouched: the
claim has no actionable half. And the plainer argument is that it would restate one attribute the
report already carries, where Kafka's aggregate carried something the evidence did not.

The mechanism that does carry it — `internal/render/terminal`'s `observations` — already existed
and its own doc comment already named "what replication role it holds" as the kind of fact it is
for. PostgreSQL's slice was simply empty.

### 7.2 A `server_version` observation line — and a pre-existing exposure, recorded

`wire.SessionParameters` allowlists four ParameterStatus **keys** and retains each one's value as
the server's own string, with **no length or character bound**. So `server_version` and
`in_hot_standby` are unbounded peer-controlled text.

`in_hot_standby` is safe because its render function is a closed two-value map: anything other
than `"on"` or `"off"` drops the line, so a peer cannot steer it.

`server_version` would have to be verbatim, and was therefore **not added**. Redis and RabbitMQ
already render a verbatim version, and `internal/render/terminal` performs no sanitisation of
observation values. **That is a pre-existing cross-service exposure, not one this phase
introduced, and not one this phase fixes**: correcting it means one decision about sanitising
observation values at the renderer boundary for every service at once. Recorded here and in
ADR 0085 §4.4 rather than silently inherited.

### 7.3 Everything in ADR 0085 §7

The refusal list is longer than the build list. It is not repeated here.

## 8. Convergence

Phase 10.2A's supersession is upheld and a result was measured against it.

**No two PostgreSQL findings can share `(Code, Subject, Layer)` while saying different things.**

- `POSTGRES_ADMISSION_SCOPE` is produced at most once per run, and its subject is the TARGET
  anchor's, which no per-address finding shares.
- Every other PostgreSQL code is one claim per node.
- The one code two rules reach — `POSTGRES_CONNECTION_NOT_PERMITTED` — is separated by **layer**:
  `postgres/startup` anchors it at L4 and `postgres/authentication` at L5, and both share one
  prose constant, so if they ever did meet at one layer they would merge byte for byte rather than
  one overwriting the other. `PG-P19` asserts both halves.

The consequence for the mutation suite is recorded rather than hidden: `PG-M19` and `PG-M20` — the
prose-precondition plants — are caught by the **generic** closure suite, because a
PostgreSQL-scoped guard for them would be vacuous. The invariant is not deleted; it is held where
it is reachable.

**The prose/subject audit.** Both new findings name data in prose that their subject does not
carry — integer counts, and the SQLSTATE. Under §2.2b that is safe by construction: differing
prose means the findings do not merge, which is the strict narrowing 10.2A chose. The SQLSTATE
appears in a `detail` and in **no** summary, discriminator or recommendation (`PG-P13b`), and the
counts appear only in a finding of which at most one exists per run.

`test/security/convergenceinventory_test.go` was re-run and needed no new entry: neither new code
is reachable from more than one rule.

## 9. Validation results

| Level | What | Result |
|---|---|---|
| L1 | rule unit tests, both rules, including every input that must emit nothing | green |
| L2 | properties PG-P01 … PG-P20, over the production rule set → report → redaction → both renderers | green |
| L3 | mutation `scripts/phase103-mutations.sh` | **27 planted, 27 caught, 0 survivors** |
| L4 | `FuzzPostgresRules` | seed corpus green; **537,083 execs / 314 new interesting / 0 failures** in a 45 s run |
| L5 | integration against real PostgreSQL 18 | **product tests green; one environment-fixture assertion fails on macOS/colima — §9.1 and §10** |
| L6 | golden incident corpus P01-P15, every fixture with a non-empty `forbidden` list | green |

### 9.1 Two result scopes, and they are not the same scope

The hermetic suite and the tagged integration package are reported separately on purpose. A single
"green" over both would be false on this workstation, and the thing that is not green is not the
product.

| Scope | Command | Result |
|---|---|---|
| **Whole repository, hermetic** | `go test ./...` | **PASS.** Every package, zero failures. This is the scope that covers the rules, the report, redaction, both renderers, the CLI, the golden corpus and the security suites. |
| **PostgreSQL integration package, tagged** | `go test -tags integration ./test/integration/postgres/...` (`make postgres-test`) | **FAILS on this workstation**, on exactly one test: `TestTheTLSKeyIsOwnedByTheDatabaseUser`. The package therefore exits non-zero and `make postgres-test` returns an error. |
| **Phase 10.3 product behaviour against the running server** | `go test -tags integration -run 'TestRealServer' ./test/integration/postgres/` | **PASS.** All `TestRealServer*` tests passed against a live PostgreSQL 18 container, including every Phase 10.3 test and the pre-existing ones. |

**The failure is environmental and is recorded rather than explained away.** Verbatim:

```
--- FAIL: TestTheTLSKeyIsOwnedByTheDatabaseUser (0.47s)
    fixture_test.go:122: server.key uid=0 gid=0 mode=600; postgres uid=999 gid=999
    fixture_test.go:136: server.key is owned by uid 0, not the database user (uid 999).
    fixture_test.go:143: server.key has group 0, not the postgres group (999)
FAIL	github.com/hakanaltindag/svcdoctor/test/integration/postgres	30.813s
```

It asserts a property of the **fixture's host filesystem** — that `env/certs/server.key` is owned
by the container's `postgres` uid — and on macOS under colima a bind mount reports uid 0 / gid 0
regardless of what the host file is chowned to. It exercises no svcdoctor code, reads no report and
makes no claim about a finding. It is the guard added after the v0.3.1 release failure, and it is
doing its job: it says this host cannot reproduce the CI ownership condition.

**Three things follow, and the third is the one not to blur.**

1. `go test ./...` passed. That statement is about the hermetic scope and is unqualified.
2. The tagged PostgreSQL integration **package** did not pass on this workstation, because of the
   macOS/colima bind-mount UID/GID behaviour in the environment fixture.
3. All Phase 10.3 PostgreSQL **product** integration tests against the running PostgreSQL instance
   passed. That is a narrower claim than "the integration suite is green", and it is deliberately
   the narrower one — **the environmental failure is not a product pass and is not reported as
   one.** Whether the environment assertion holds is unknown from this host and has to be
   established on a Linux runner before the L5 row can read green without a qualifier.

**Historical mutation suites, all re-run, all zero survivors:**

| Suite | Planted | Survivors |
|---|---|---|
| 9.1A | 20 | 0 |
| 9.1B | 31 | 0 |
| 9.1C | 45 | 0 |
| 9.2B | 21 | 0 |
| 9.3A | 10 | 0 |
| 10.1A | 27 | 0 |
| 10.1B | 21 | 0 |
| 10.2 | 25 | 0 |
| 10.2A | 8 | 0 |
| **10.3** | **24** | **0** |
| **total** | **232** | **0** |

### 9.1 Two mutations that were equivalent, and what that taught

`PG-M01` — *a session claim without its authentication proof* — survived twice before it was
planted correctly, and both failures are worth recording.

1. Pointed at `TestAcceptanceMatrix`, it survived: every row there has a proper parent, so
   removing the gate changed nothing any of them observed.
2. Planted as the removal of the `if !ok` gate, it survived again for a subtler reason:
   `authenticationProof` returns the zero `Evidence`, whose empty identifier `domain.NewFinding`
   rejects, so the finding still did not appear — **the same outcome by a different route**.

What is planted now is the check that decides *whether a parent proves anything*: a non-passing
authentication node becomes a proof. `TestEverySessionClaimRequiresItsAuthenticationProof` was
written for the shapes where the proof is **absent**, which is the only input the gate is about,
and it covers all four session codes rather than only the new one.

## 10. Integration against a real server

Eight new tests in `test/integration/postgres/intelligence_test.go`, all through
`app.DiagnosePostgres`: real resolver, real dialer, real in-band TLS, real SCRAM, the real
server's own answers, the production rule set, a real report, real redaction, both renderers.
**All eight passed against a live PostgreSQL 18 container.** §9.1 records the one test in the same
package that did not, and why it is an environment-fixture assertion rather than a product one —
that distinction belongs beside this table and not folded into it.

**`53300` is produced by configuration, not by a race — and the configuration is also the
semantic counterexample the claim is bounded by.** The fixture reaches `53300` through a limit
attached to a *role*, on a server with connections to spare, so any sentence asserting an
endpoint-wide shortage is falsified by the very run that produces the report being scanned.
`init.sql` gains
`CREATE ROLE limituser LOGIN PASSWORD '…' CONNECTION LIMIT 0`. PostgreSQL then refuses **every**
login for that role at `InitializeSessionUserId` — after authentication completes and before
`ReadyForQuery`, which is exactly the ADR 0036 §5 window — and reports `53300`. No connection is
held, nothing is exhausted, no client races another, and an interrupted run leaves the server
exactly as it found it. Lowering `max_connections` and opening sockets until it ran out would have
been timing-dependent and would have leaked connections on any path that missed its cleanup.

| Test | Qualified |
|---|---|
| `TestRealServerConnectionLimitIsDiagnosed` | real SCRAM PASS, real `53300`, `RESOURCE_LIMIT_REACHED`, CONFIRMED/HIGH/ERROR, not vantage-dependent, and the claim scoped to the attempted session with the limit left unidentified |
| `TestRealServerConnectionLimitInventsNoCause` | fourteen forbidden causes **and seven endpoint-wide scope wordings** absent from the local report, the shareable report and the terminal. The fixture is the counterexample that gives this teeth: `limituser` is refused by a limit on the role while the server has connections to spare |
| `TestRealServerAdmissionScopeOverTwoAddresses` | `localhost` reached **2** real addresses, both refused by real `pg_hba` with real `28000`, complete uniform sentence: *"…at all 2 addresses this target resolved to"* |
| `TestRealServerAdmissionScopeIsSilentOnOneAddress` | a literal target produces the per-address finding and no aggregate |
| `TestRealServerReportsItsRecoveryStateAndSvcdoctorClaimsNothing` | real `in_hot_standby`, **zero findings**, status OK, the result block reports it, and "primary"/"replica"/"standby"/"warning"/"failover" appear nowhere |
| `TestRealServerSessionParametersReachNoFinding` | four real ParameterStatus values present, no finding, and the raw `server_version` reaches no terminal line |
| `TestRealServerBoundaryAndServerSemanticsAreTwoFindings` | `DIAG_FAILURE_BOUNDARY` at auth **and** the server claim, two codes, no second PostgreSQL boundary |
| `TestRealServerJSONIsConsumableByCI` | the code survives the canonical JSON at `schemaVersion` 1 and the shareable projection; the role name does not |

**What could not be qualified against a real server, and why.** The admission-scope *contrast*
branch — one address refused while a sibling is admitted — needs `pg_hba` to answer differently
per address. Through Docker's published ports every loopback family arrives at the container from
the same bridge source address, so the server cannot distinguish them and the fixture cannot
produce the divergence. The contrast branch is covered by the unit and corpus fixtures and is
recorded here as fixture-only rather than claimed.

### 10.1 Other integration suites

| Suite | Result |
|---|---|
| Kafka (3-broker KRaft) | **green**, 248 s |
| Redis / Valkey | **green** |
| PostgreSQL | green except one pre-existing environmental failure — below |
| RabbitMQ / LavinMQ | two pre-existing environmental failures — below |

**Pre-existing failures, reproduced at the baseline under the same environment**, `git stash`ed to
`e71208b` and re-run:

- `TestTheTLSKeyIsOwnedByTheDatabaseUser` — `server.key uid=0 gid=0`, which is what a macOS bind
  mount reports for a key that was never chowned. The test is correct and is failing for a correct
  reason on this host; making it pass means moving the fixture off a bind mount, which is a change
  to the very CI condition it guards and is out of this phase's scope.
- `TestRAB16BrokerStopped` and `TestRAB24And25AddressLiterals/RAB-25_IPv6_literal` — identical
  failures at `e71208b`.

**None is a diagnosis regression, and none was normalised away.** No retry was added, no sleep was
inserted, and no blanket exception was written.

## 11. Performance

`internal/diagnosis/postgres/scaling_test.go`, Apple M4, whole production rule set, half the
addresses refused so both the classification pass and the construction path run.

| Addresses | ns/op | B/op | allocs/op | per address |
|---|---|---|---|---|
| 1 | 3,362 | 3,104 | 14 | 3.66 µs |
| 3 | 10,656 | 8,536 | 33 | 5.17 µs |
| 10 | 25,982 | 27,595 | 60 | 4.21 µs |
| 50 | 75,744 | 121,527 | 168 | 2.64 µs |
| 100 | 105,253 | 242,963 | 297 | 1.93 µs |
| 500 | 398,366 | 1,171,313 | 1,308 | 1.54 µs |

Per-address cost **falls** from 3.7 µs to 1.5 µs across a 500× range: linear with a shrinking
constant. **No rule compares an address with another address**, which is the thing that would make
it all-pairs. 500 addresses — an absurd figure for a real target — cost 400 µs of reasoning beside
network work measured in milliseconds to seconds.

`TestTheAdmissionScopeScalesLinearly` asserts the property with an 8× tolerance, wide enough that
only a genuine complexity change trips it and narrow enough to separate linear from quadratic.

## 12. Counts

| | Before | After |
|---|---|---|
| `domain.SchemaVersion` | 1 | **1** |
| `domain.RunSchemaVersion` | 1 | **1** |
| finding codes | 63 | **65** |
| — `POSTGRES_` | 19 | **21** |
| — `KAFKA_` | 15 | 15 |
| — `RABBITMQ_` | 11 | 11 |
| — `REDIS_` | 9 | 9 |
| — `DIAG_` | 1 | **1** |
| — generic transport (`DNS_`/`TCP_`/`TLS_`) | 8 | 8 |
| failure classes | 42 | **42** |
| `security.Reveal` production call sites | 4 | **4** |
| `SecretFor` production call sites | 4 | **4** |
| external modules | 2 | **2** |
| exit codes | 5 | **5** |
| PostgreSQL production rules | 5 | **6** |

Counted mechanically by `TestMTG05TheFindingCodeCountIsUnchanged`, which gained a per-namespace
assertion for PostgreSQL in this phase so the number cannot move silently either.

## 13. Candidate public output

**Release state first, because it qualifies everything in this section.** Phase 10.3 is an
**uncommitted, unreleased candidate**: not committed, not tagged, in no published release. The
most recent release tag is `v0.4.0` (present locally and on `origin`), and the branch this
candidate sits on is already several commits past it. So the three items below are changes to
**candidate public behaviour** — what an operator would see if this candidate were released —
measured against the behaviour `v0.4.0` published. None of them has shipped.

**Two candidate changes to previously published behaviour**, both deliberate:

1. A run whose session is refused with `53300` would report `POSTGRES_CONNECTION_LIMIT_REACHED`
   instead of `POSTGRES_SESSION_ESTABLISHMENT_FAILED`, and `vantageDependent` would move `true` →
   `false`. Severity, kind, confidence, status and exit code are unchanged. A consumer matching on
   the *code* would see a new one, which is why it is in a record rather than a changelog line.
2. A run that establishes a session and receives `in_hot_standby` would print one more line in the
   terminal Result block, and a note when the value is `on`. No finding, no JSON change, no status
   change, no exit-code change.

**One new finding this candidate can carry**: `POSTGRES_ADMISSION_SCOPE`, INFO, on a multi-address
target with at least one refusal. It moves no exit code.

Exit-code precedence `3 > 2 > 4 > 1 > 0` is unchanged and no code was added.

## 14. Security

- Diagnosis gains **no new input**. Phase 10.3 adds **no attribute read to any rule** —
  `TestTheAdmissionRuleReadsNoAttribute` and `TestTheRulesReadOnlyTheAuthorizedAttributes` both
  hold, and the latter's four-key surface is unchanged. That is what keeps the path closed by
  which a replica claim would arrive without a decision.
- `Reveal` **4**, `SecretFor` **4**. `diagnosis-is-pure` unchanged: no rule can reach a secret, a
  file, an environment variable, a clock or a socket.
- Peer-controlled text: `validSQLState` bounds a SQLSTATE to five alphanumeric ASCII characters and
  `validSeverity` to a closed set of eight words at the **wire** boundary, which is why the
  SQLSTATE's verbatim appearance in a `detail` is safe. ParameterStatus values are unbounded, and
  the recovery render function's closed two-value map is the control; §7.2 records why no second
  unbounded value was added.
- `PG-P13` drives seven hostile parameter values, including escape sequences, markdown, newlines,
  a secret-shaped string and a 4.8 KB repetition, through the whole pipeline: the claim is
  unchanged, no marker reaches any finding's summary, detail, discriminator or recommendation in
  either the local or the shareable report, and none reaches the terminal.
- The full security corpus (`./test/security`) is green.

## 15. Harness authenticity

Phase 10.2 found the Kafka integration harness wiring two of the Kafka rules while claiming to
differ from production "in nothing but the graph". The PostgreSQL harnesses were audited and
**one of them had the same defect on the day it was checked**: `test/diagnosis`'s `postgresRules()`
ran five of six rules.

The existing corpus guards are hand-maintained lists compared against literal lists beside them,
which catches a harness that *drops* a rule and misses the case that actually happened — a
composition root that *gains* one. `test/security/postgres_rule_wiring_test.go` is derived
instead: it parses `internal/app/postgres.go`'s own `NewRuleSet` chain and requires every
PostgreSQL harness to run exactly that set. It caught the drift immediately, which is the whole
argument for it, and carries its own non-vacuity proof.

## 16. Answers to the principal review

1. **Can PostgreSQL diagnosis perform network I/O?** No. `diagnosis-is-pure` denies `net`,
   `net/http`, `crypto/tls`, `os`, `os/exec` and both random sources; a package guard denies
   `context`, `time`, `database/sql` and `regexp` as well.
2. **Can PostgreSQL rules access credentials?** No. `internal/security` is denied to the whole
   diagnosis tree.
3. **Can transport failure produce a SQLSTATE diagnosis?** No — PG-P01. There is no session node,
   and the claim additionally requires a parent proving authentication completed.
4. **Can arbitrary SQLSTATE become 53300?** No — PG-P02, twenty-three codes swept. The rule reads
   the failure **class**, which only `53300` at `postgres.session` produces.
5. **Does 53300 prove resource-limit rejection?** Yes, at HIGH, on direct authority: the peer named
   the condition in a field its protocol defines. It proves it **of the attempted session**, and
   two follow-ups bound the scope:
   - *Does it prove the endpoint had no connection slot available?* **No** — PG-M25, PG-M26,
     `TestTheConnectionLimitClaimIsScopedToTheAttemptedSession`. The `CONNECTION LIMIT 0` fixture is
     a live counterexample: it yields `53300` on a server with connections to spare.
   - *Does it identify which limit was reached?* **No.** The `ErrorResponse` names none, and the
     claim says so in as many words. The recommendation names none either — PG-M27.
6. **Does 53300 prove connection leak?** No — PG-P04, PG-M03.
7. **Does 53300 prove `max_connections` is too low?** No.
8. **Can 53300 recommend increasing `max_connections`?** No — permanently. PG-M04.
9. **Can pg_hba rejection imply bad credentials?** No — PG-P05, both directions, plus the
   structural fact that the refused path has no authentication node at all.
10. **Can pg_hba rejection prove policy misconfiguration?** No — PG-M05. A policy that refuses may
    be exactly what it was written to do.
11. **Can pg_hba rejection recommend broadening access?** No — PG-M06.
12. **Can authentication rejection prove bad password?** No. `28P01` is issued identically for a
    wrong secret, an unknown role, a corrupted proof and a correct secret needing Unicode
    preparation.
13. **Can `pg_is_in_recovery()` prove observed role?** svcdoctor does not call it. `in_hot_standby`
    proves what the endpoint *reported* about this session, and not an endpoint identity.
14. **Is standby itself an incident?** No — PG-P06, PG-M08. Zero findings, status OK.
15. **Is primary itself correctness?** No — PG-P07. Zero findings either way.
16. **Can role mismatch exist without explicit intent?** No. No such claim exists at all — PG-P15.
17. **Can two observed primaries become split brain?** **Unreachable** — §5, PG-P08, PG-M10.
18. **Can role observations imply replication health?** No; nothing about replication is measured.
19. **Can incomplete hosts produce only/all claims?** No — PG-P11, PG-M11, PG-M12, PG-M13.
20. **Can UNKNOWN become standby?** No — PG-P09, PG-M18. An absent or unrecognised value drops the
    line.
21. **Can SKIPPED become standby?** No — PG-P10.
22. **Can withheld credentials become auth rejection?** No — PG-P12, PG-M14. The node is SKIPPED,
    not FAIL.
23. **Can server Message/Detail/Hint enter trusted prose?** No. `Message`, `Detail` and `Hint` are
    never decoded at all — `ErrorFields` has no field for them. PG-P13, PG-M15, PG-M16.
24. **Can rules parse server prose instead of structured authority?** No. No English server string
    is examined anywhere in the phase; `regexp` is a denied import.
25. **Can evidence removal strengthen a claim?** No — PG-P14, PG-M17.
26. **Can removing intent preserve an intent-mismatch diagnosis?** There is no intent and no
    mismatch diagnosis — PG-P15.
27. **Can RuleID naming change diagnostic meaning?** No — PG-P16/P17, four alternative namings
    including two whose alphabetical order reverses production's, byte-identical output.
28. **Can semantically incompatible prose converge?** No — merge preconditions; PG-M19, PG-M20.
29. **Can different endpoint subjects converge?** No — PG-P18, PG-M21.
30. **Does the generic core stay PostgreSQL-unaware?** Yes — PG-P20 parses the AST of every
    generic file, PG-M23.
31. **Does the renderer stay reasoning-free?** Yes. The change is one row in a configuration table:
    a step, an attribute key, a label, a closed two-value render function, and one conditional
    note. No rendering function learned the word "postgres".
32. **Does the canonical report remain the source of truth?** Yes. JSON is unchanged in shape and
    carries both new codes.
33. **Is `SchemaVersion` still honest?** Yes — 1. Nothing was removed, repurposed or made required,
    and nothing was buried in a `Detail` or a `Subject` string to avoid a bump.
34. **Does fleet remain free of cross-target causal inference?** Yes; no fleet file was touched and
    no run-level finding exists.
35. **Does the architecture still satisfy the four boundaries?** Yes. Probes collected the facts,
    the adapter normalized the protocol, diagnosis correlated frozen evidence, and the renderer
    explained the result — including the role, which is the one place this phase deliberately used
    the fourth boundary instead of the third.

## 17. What a future agent should not re-derive

**Multi-endpoint PostgreSQL role reasoning is not "not yet built" — it is not producible.** One
path continues; there is at most one session per run. Anyone reaching for a split-brain or
role-contrast rule must first change ADR 0041, and the structural guard will say so.

**The renderer's observation mechanism is the right home for an endpoint-reported fact.** It
existed since Phase 7, its doc comment already named "what replication role it holds", and
PostgreSQL's slice was empty for two phases. The next service that measures a self-reported
property should look there before reaching for a finding code.

**ParameterStatus values are unbounded and no renderer sanitises an observation value.** Redis and
RabbitMQ render verbatim versions today. That is a real, pre-existing, cross-service question and
it wants one decision, not four.
