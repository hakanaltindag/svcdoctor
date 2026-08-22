# PostgreSQL diagnosis study — Phase 4.6a decision pass

What the PostgreSQL evidence graph actually contains, and which claims it will
support. ADR 0040 is the decision this study produced; this file is the evidence
behind it.

**No production Go code was written or changed in Phase 4.6a.** The production
`security.Reveal` count is unchanged at **two**, the `FailureClass` count at
**38**, the report `schemaVersion` at **1**, and the dependency set at one
(`github.com/twmb/franz-go/pkg/kmsg v1.13.1`).

Everything below was read out of the PostgreSQL producers and the two prior wire
studies. Nothing is reasoned from PostgreSQL documentation.

## 1. Repository state this study was written against

| | |
|---|---|
| HEAD at start | `08ec046`, with Phase 4.5 present and **uncommitted** in the working tree |
| HEAD at finish | `c86fdc3` — Phase 4.5 was committed during this pass, in five commits ending *test(security): verify PostgreSQL evidence boundaries* |
| Working tree | clean apart from this pass's documentation |
| Baseline | `gofmt`, `go vet`, `golangci-lint` (0 issues), `go test`, `go test -count=1 -race`, `CGO_ENABLED=0 go build`, `git diff --check`, `go mod tidy`, `make check` — **all green**, before and after |

The commit did not change any file this study reads: `git diff HEAD -- internal/`
is empty, so every producer quoted below is byte-identical to what was analysed.
Phase 4.5 is therefore **committed**, not pending.

**The Kafka `bindDeadline` fix is deliberately absent, and still is.** Commit
`63d5d9b` fixed the released-watcher race in `internal/adapter/postgres/wire`
only. ADR 0039 amendment C records that `internal/adapter/kafka/wire/exchange.go`
holds an identical copy, that no Kafka path writes after a bounded read so
nothing triggers it there, and that a phase which does not own that package
should not edit it silently. Verified at `c86fdc3`: the Kafka copy has no
`stopped` channel and `release` still clears the deadline without waiting for its
watcher.

### 1.1 Packages that exist, and the two that do not

```text
internal/diagnosis/            engine.go, rule.go, doc.go            — the contract
internal/diagnosis/kafka/      2 rules, 2 finding codes              — the precedent
internal/diagnosis/postgres/   .gitkeep only                         — EMPTY
internal/diagnosis/transport/  .gitkeep only                         — EMPTY
internal/service/kafka/        doc.go, vocabulary.go                 — 3 constants
internal/service/postgres/     DOES NOT EXIST
internal/app/, internal/render/, cmd/svcdoctor/   .gitkeep only      — EMPTY
```

**There is no composition root.** No production code assembles a PostgreSQL
graph end to end; the adapter's four steps are driven by tests. Every graph shape
in section 3 is therefore derived from the producers' source, not dumped from a
run, and section 3.6 records exactly which shapes have no producer today.

## 2. The PostgreSQL evidence ladder, from the producers

Read from `internal/adapter/postgres/{negotiate,startup,authenticate,establish}.go`
and `internal/probe/{dns,tcp,tls}`.

| Step | Layer | PASS means | FAIL means | UNKNOWN means | SKIPPED means | Attributes a rule could read | Blocker edge |
|---|---|---|---|---|---|---|---|
| `dns.lookup` | L1 | the name resolved to at least one usable address | the resolver positively evidenced no usable address | the resolver did not answer in the budget | not attempted | — | — |
| `tcp.connect` | L2 | a connection was established to this address | the attempt was made and did not connect | budget expired | prerequisite failed | — | yes, on skip |
| `postgres.ssl_request` | L3 | the endpoint answered `S` and authorized the upgrade | the endpoint answered `N` (**`PROTOCOL_UNSUPPORTED_CAPABILITY`**), answered `E`, or the exchange broke | budget expired or run cancelled | **the run asked for no TLS** (`EXEC_SKIPPED_BY_POLICY`, `postgres.tls.plan`) | `postgres.ssl.offered` (only when an answer arrived), `postgres.tls.plan` (only on the skipped node) | — |
| `tls.handshake` | L3 | handshake completed and verification satisfied the plan | handshake or verification failed | budget expired | `SSLRequest` did not pass (`EXEC_SKIPPED_PREREQUISITE_FAILED`) | certificate facts | **yes** — blocked by `postgres.ssl_request` |
| `postgres.startup` | L4 | the endpoint accepted the `StartupMessage` and **named an authentication it wants**, `AuthenticationOk` included | the endpoint rejected startup (`0A000`→`PROTOCOL_UNSUPPORTED_VERSION`, `28000`→`AUTHZ_NOT_PERMITTED`, everything else→`PROTOCOL_UNEXPECTED_RESPONSE`) or the exchange broke | budget expired or run cancelled | the negotiation left nothing usable | `postgres.protocol_version`, `postgres.auth_method`, `postgres.sasl_mechanisms`, `postgres.sqlstate`, `postgres.error_severity`, `postgres.error_is_native`, **`postgres.role` / `postgres.database` (identity)** | **yes** — blocked by whatever killed the session |
| `postgres.authentication` | L5 | server signature verified **and** `AuthenticationOk` arrived | see §2.1 — five distinct producers | svcdoctor gap, budget, or cancellation | policy refused the channel (`EXEC_SKIPPED_BY_POLICY`) | `postgres.sasl_mechanism`, `postgres.scram_iterations`, `postgres.sqlstate`, `postgres.error_severity`, `postgres.error_is_native` | **yes** — on the policy refusal, pointing at the channel node |
| `postgres.session` | L5 | `ReadyForQuery` was read | `3D000`→`RESOURCE_NOT_FOUND`, `42501`→`AUTHZ_DENIED`, everything else→`PROTOCOL_UNEXPECTED_RESPONSE` | budget expired or run cancelled | **never** | `postgres.server_version`, `postgres.in_hot_standby`, `postgres.default_transaction_read_only`, `postgres.is_superuser`, `postgres.transaction_status`, `postgres.sqlstate`, `postgres.error_severity`, `postgres.error_is_native` | — |

### 2.1 `postgres.authentication` has five outcome families, and one of them points two ways

This is the load-bearing result of the study. From
`internal/adapter/postgres/authenticate.go` and
`internal/adapter/postgres/wire/scram.go`:

| State | FailureClass | Producer | Bytes sent? | `postgres.sqlstate` present? |
|---|---|---|---|---|
| PASS | `NONE` | signature verified **and** `AuthenticationOk` | yes | no |
| UNKNOWN | `AUTH_MECHANISM_UNSUPPORTED` | peer demanded non-SASL (md5/cleartext/gss/…), **or** SASL offering only `SCRAM-SHA-256-PLUS` | **no** | no |
| FAIL | `AUTH_MECHANISM_NOT_OFFERED` | peer offered SASL but neither `SCRAM-SHA-256` nor `-PLUS` | **no** | no |
| SKIPPED | `EXEC_SKIPPED_BY_POLICY` | the credential-transport policy refused this channel | **no** | no |
| UNKNOWN | `EXEC_UNSUPPORTED_BY_SVCDOCTOR` | `ErrPasswordUnsupported` (non-printable-ASCII password) or `ErrIterationsUnsupported` (count above `MaxSCRAMIterations`) | password: no; iterations: yes | no |
| FAIL | `AUTH_CREDENTIALS_REJECTED` | **three producers — see below** | yes | **sometimes** |
| FAIL | `AUTHZ_NOT_PERMITTED` | `28000` | yes | yes |
| FAIL | `PROTOCOL_*` | `28P01`-less `ErrorResponse` (incl. **`08P01`**), malformed frame, peer close | yes | usually |

**`AUTH_CREDENTIALS_REJECTED` has three producers, and they do not all mean the
same thing:**

```text
authenticate.go classify():
  wire.ErrServerSignatureMismatch  -> AUTH_CREDENTIALS_REJECTED
  wire.ErrSCRAMRejected            -> AUTH_CREDENTIALS_REJECTED
  authSQLStateFailure("28P01")     -> AUTH_CREDENTIALS_REJECTED
```

- `28P01` — the peer sent `ErrorResponse` in place of `AuthenticationSASLFinal`.
  **The peer refused svcdoctor's material.**
- `ErrSCRAMRejected` — `scram.go:536`, the server-final carried
  `e=invalid-proof`, `e=unknown-user` or `e=invalid-username-encoding`.
  **The peer refused svcdoctor's material**, in SCRAM's own vocabulary rather
  than a SQLSTATE.
- `ErrServerSignatureMismatch` — `scram.go:546`, the server's `v=` value did not
  equal the expected `ServerSignature`. **svcdoctor refused the peer.** The
  direction is reversed: the endpoint failed to prove it knows the credential.

`domain.FailureAuthCredentialsRejected` documents itself as *"the peer refused
the authentication material it was presented"*, which is **not true of the third
producer**. The adapter's own comment acknowledges this and justifies the reuse
on the grounds that SCRAM is mutual so "the refusal is mutual".

**Can a rule tell them apart from the graph?** Partly.

| Producer | `postgres.sqlstate` | Distinguishable |
|---|---|---|
| `28P01` | `"28P01"` | **yes** |
| `ErrSCRAMRejected` | absent — `wire.SCRAM.Fields` is zero, no `ErrorResponse` was decoded | no |
| `ErrServerSignatureMismatch` | absent — same reason | no |

So `sqlstate == "28P01"` separates the peer's own assertion from the other two,
and **nothing in the graph separates the last two from each other.** A finding
over the no-SQLSTATE case must therefore make a claim true whichever party
refused. ADR 0040 §7 does exactly that, and §26 records the reopen condition.

### 2.2 The graph shape when a `trust` server answers

`authenticate.go` returns early when `result.AuthMethod() == "ok"` and
**records no `postgres.authentication` node at all** — deliberately, per ADR 0038
§12: svcdoctor presented nothing, so a passing authentication node would be an
overclaim. The resulting `postgres.session` node's parent is the
`postgres.startup` node, which carries `postgres.auth_method="ok"`.

**Consequence for every rule anchored at `postgres.session`:** the parent may be
either a PASS `postgres.authentication` node or a PASS `postgres.startup` node
with `postgres.auth_method="ok"`. A rule that assumed the first would silently
stop firing on `trust` paths.

### 2.3 A failed authentication produces **no** `postgres.session` node

Verified by exhaustive grep: `StepSession` is referenced only in
`establish.go`, and `EstablishSession` is the only writer. `Authenticate`
returns `(nil, nil)` on every non-passing outcome and records no skipped session
node, so the graph simply has no L5 session node. There is nothing for a rule to
find and nothing to suppress.

The same holds one step earlier for `Negotiate`→`Startup`, **except** that
`Startup` *does* record a SKIPPED node with a `blockedBy` edge when the session
arrived dead. So:

```text
SSLRequest FAIL   -> postgres.startup SKIPPED (blockedBy ssl_request), no auth node, no session node
startup FAIL      -> no auth node, no session node
auth FAIL/SKIPPED -> no session node
```

## 3. Graph shapes, per scenario

Derived from the producers. `->` is a parent edge; `⊘` is a `blockedBy` edge.

### 3.1 Healthy, TLS required, SCRAM

```text
dns.lookup PASS -> tcp.connect PASS -> postgres.ssl_request PASS (ssl.offered=true)
  -> tls.handshake PASS -> postgres.startup PASS (auth_method=sasl, sasl_mechanisms=[…])
  -> postgres.authentication PASS -> postgres.session PASS (transaction_status=idle)
```

### 3.2 Endpoint declines `SSLRequest` under a required-TLS plan

```text
… tcp.connect PASS -> postgres.ssl_request FAIL PROTOCOL_UNSUPPORTED_CAPABILITY (ssl.offered=false)
                        -> tls.handshake SKIPPED EXEC_SKIPPED_PREREQUISITE_FAILED ⊘ ssl_request
                        -> postgres.startup SKIPPED EXEC_SKIPPED_PREREQUISITE_FAILED ⊘ ssl_request
```

Two SKIPPED nodes, one FAIL node. `docs/FINDINGS.md` §3.1 item 11 forbids citing
either skip as a cause.

### 3.3 Plaintext plan, SCRAM demanded, fail-closed policy

```text
… postgres.ssl_request SKIPPED EXEC_SKIPPED_BY_POLICY (tls.plan=disabled)
  -> postgres.startup PASS (auth_method=sasl)
  -> postgres.authentication SKIPPED EXEC_SKIPPED_BY_POLICY ⊘ postgres.ssl_request
```

The blocker points at the `postgres.ssl_request` node, which positively records
that no TLS was attempted and why. ADR 0030 recorded the absence of such a
carrier as a Kafka gap; PostgreSQL closes it because it negotiates in band.

### 3.4 Wrong credential, direct PostgreSQL

```text
… postgres.startup PASS -> postgres.authentication FAIL AUTH_CREDENTIALS_REJECTED
                                                  (sqlstate=28P01, error_is_native=true)
```

### 3.5 Wrong credential, behind pgBouncer

```text
… postgres.startup PASS -> postgres.authentication FAIL PROTOCOL_UNEXPECTED_RESPONSE
                                                  (sqlstate=08P01, error_is_native=false)
```

Measured in Phase 4.4a. `28P01` never fires behind this pooler.

### 3.6 Shapes with no producer today

Recorded so ADR 0040 does not authorize a rule for evidence nothing writes:

- **No `postgres.*` node is ever `DEGRADED`.** No producer emits it.
- **`postgres.session` is never `SKIPPED`.** §2.3.
- **A partial `ParameterStatus` block followed by an error was not observed** on
  a real backend (Phase 4.5a §11); it needs a timeout or a scripted peer.
- **`postgres.startup` with `PROTOCOL_UNSUPPORTED_VERSION`** is reachable in
  principle (`0A000`) and was not observed: svcdoctor requests 3.0 and every
  server in the support window accepts it.

## 4. The pgBouncer adversarial matrix

Rows are the Phase 4.4a and 4.5a measurements against pgBouncer 1.25.2,
`auth_type=scram-sha-256`. "Boundary" is the node that actually records the
outcome.

| Scenario | Boundary node | State / class | `sqlstate` | `error_is_native` |
|---|---|---|---|---|
| wrong password, direct | `postgres.authentication` | FAIL `AUTH_CREDENTIALS_REJECTED` | `28P01` | true |
| wrong password, pgBouncer | `postgres.authentication` | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `08P01` | **false** |
| unknown role, direct | `postgres.authentication` | FAIL `AUTH_CREDENTIALS_REJECTED` | `28P01` | true |
| unknown role, pgBouncer | **`postgres.startup`** | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `08P01` | **false** |
| missing database, direct | `postgres.session` | FAIL `RESOURCE_NOT_FOUND` | `3D000` | true |
| missing database, pgBouncer | **`postgres.startup`** | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `08P01` | **false** |
| `CONNECT` denied, direct | `postgres.session` | FAIL `AUTHZ_DENIED` | `42501` | true |
| `CONNECT` denied, pgBouncer | **`postgres.startup`** | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `08P01` | **false** |
| corrupted proof, direct | `postgres.authentication` | FAIL `AUTH_CREDENTIALS_REJECTED` | `28P01` | true |
| corrupted proof, pgBouncer | `postgres.authentication` | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `08P01` | **false** |
| `pg_hba` reject, direct | `postgres.startup` | FAIL `AUTHZ_NOT_PERMITTED` | `28000` | true |
| `hot_standby=off` replica | `postgres.startup` | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `57P03` | true |
| slots exhausted, direct | `postgres.session` | FAIL `PROTOCOL_UNEXPECTED_RESPONSE` | `53300` | true |
| backend stopped, pgBouncer cache | `postgres.session` | **PASS** | — | — |

Three things this table settles.

1. **`08P01` appears at two different steps for six different root causes.** It
   is pgBouncer's substitute for a NULL sqlstate — its own source comment says it
   "used to report SQLSTATE 08P01 (protocol_violation) for all cases". Neither
   the code nor its protocol position narrows the cause.
2. **The pooler *moves* failures earlier, it does not collapse them in place.**
   A missing database is a `postgres.session` fact directly and a
   `postgres.startup` fact behind a pooler. A rule keyed on `RESOURCE_NOT_FOUND`
   correctly produces nothing in the second case; a rule that tried to recover
   it from `08P01` at startup would be guessing between six causes.
3. **The last row forbids every success claim about a backend.** `ReadyForQuery`
   arrived with no PostgreSQL server running.

## 5. Adversarial wording review

The test applied to each candidate: *is there another real situation that
produces this same evidence, in which this sentence would be a lie?*

| Candidate sentence | Verdict | The situation that falsifies it |
|---|---|---|
| "The password is incorrect." | **REJECTED** | An unknown role, a corrupted proof and a correctly-typed password needing SASLprep produce byte-identical `28P01` responses. PostgreSQL issues a mock salt for a non-existent role *deliberately*, so a client cannot tell |
| "The credentials are invalid." | **REJECTED** | Same evidence, and "invalid" is a judgement about the material rather than a report of what happened |
| "Authentication failed." | **True but useless at `28P01`** | Accurate; it discards the one thing the peer did assert. Retained as the wording of the *floor* finding where nothing more is known |
| "The peer rejected the authentication material presented." | **ACCEPTED for `28P01` and `e=invalid-proof` only** | False for `ErrServerSignatureMismatch`, where svcdoctor refused the peer (§2.1) |
| "The configured credential was rejected by the PostgreSQL endpoint." | **ACCEPTED for `28P01`** | Same caveat. "endpoint" is required; "server" would claim a backend |
| "The requested database does not exist." | **REJECTED** | `3D000` is also raised when the catalog row exists and its files do not — corruption reported as absence |
| "The requested database is not available." | **ACCEPTED** | True of all three `3D000` conditions |
| "PostgreSQL is out of connections." | **REJECTED** | `53300` is unmapped; svcdoctor does not translate SQLSTATEs it did not authorize, and a pooler emits `08P01` for its own limit |
| "The server does not support TLS." | **REJECTED** | `N` is one endpoint's answer on one connection; `ssl=off` on a server, a pooler with no `server_tls_sslmode`, and a proxy stripping the upgrade are indistinguishable |
| "The PostgreSQL backend is healthy." | **REJECTED** | pgBouncer served a passing session with the backend stopped |
| "This endpoint is writable." | **REJECTED** | `default_transaction_read_only` was `off` on a real standby; the parameter that answers this is session-local and needs SQL |
| "This endpoint is a primary." / "…a replica." | **REJECTED for Phase 4.6** | `in_hot_standby=on` proves recovery, but a pooler forwards the cached value, and nothing distinguishes a replica from a primary that was in recovery when the pooler cached |
| "The role lacks permission." | **REJECTED** | `42501` at `CheckMyDatabase` is the `CONNECT` privilege and only that; no table, schema, function or write check can have run because svcdoctor issues no statement |

## 6. What this study did not establish

- **No new measurement was taken.** Every wire fact is cited from Phase 4.4a
  (`POSTGRES_PHASE4_SCRAM_STUDY.md`) or Phase 4.5a
  (`POSTGRES_PHASE45_SESSION_STUDY.md`), both of which measured PostgreSQL 18.6,
  14.24 and pgBouncer 1.25.2 directly. This pass added no server and no probe;
  it read the producers and the two studies.
- **No real end-to-end graph was dumped**, because no composition root exists to
  produce one (§1.1). ADR 0040 §22 makes hand-authored graph fixtures a Phase
  4.6b obligation and Phase 4.8 the first place a rule meets a real one.
- **HAProxy, Envoy, RDS, Aurora, Cloud SQL and Azure were not contacted.** The
  proxy-transparency policy in ADR 0040 §18 is written to be correct without
  them, which is the point: it names the observed boundary rather than the peer.
- **`0A000` at startup, `08004`, and `57P03` after `AuthenticationOk` remain
  unobserved** and are handled by the floor findings rather than by a mapping.
