# ADR 0039: A PostgreSQL session is established at ReadyForQuery, and that proves less than it looks like

## Status

**Accepted, and implemented in Phase 4.5b.** The production `security.Reveal` count is
**two**, the dependency graph is unchanged, and no report schema field, `AttrKind` or
redaction rule changed. One `FailureClass` was added — `RESOURCE_NOT_FOUND`, which ADR 0036
section 16 authorized and Phase 4.3 deferred for want of a reachable producer.

Validated against a real PostgreSQL 18.6 server under `make integration-postgres`, including
`3D000` and `42501` arriving after `AuthenticationOk`.

**Two things this record did not decide, settled during implementation** and recorded under
"Amendments from implementation" at the end: how a repeated `ParameterStatus` key is
resolved, and the exact shape of the step's return value.

It completes the vertical slice ADR 0036 designed: `SSLRequest` (4.3), `Startup`
(4.3), `Authenticate` (4.4b), and now the window between `AuthenticationOk` and
`ReadyForQuery`. It adds one `FailureClass` that ADR 0036 already authorized and
declines to add a second.

## Problem

Phase 4.4b stops at `AuthenticationOk` having read exactly that frame. ADR 0036
§5 fixed the *success* boundary at `ReadyForQuery` on the strength of two
measurements — `3D000` and `42501` arriving after `AuthenticationOk` — and left
everything else about the window unmodelled:

1. what frames may legally appear, and in what order;
2. which `ParameterStatus` values are safe and useful to retain, when the server
   sends fifteen and two of them are identity;
3. what `BackendKeyData`'s secret key is for, and whether svcdoctor keeps it;
4. how the SQLSTATEs in this window classify;
5. what a passing session node is actually entitled to claim.

Question 5 turned out to be the load-bearing one, and the answer is narrower than
`ReadyForQuery` suggests.

## Observed evidence

Read from the tree at `08ec046`, and measured against real servers, not assumed:

- `AuthenticatedSession` carries the logical endpoint, the concrete address, the
  channel, the channel evidence, its own evidence identifier and the live
  connection, plus `TakeConn`/`Close`/`Available`. It carries **no credential and
  no secret**, and there is no accessor through which either could be read.
- **Nothing after `AuthenticationOk` has been consumed.** `grep -rn bufio internal/`
  finds no production match; `wire.ReadMessage` reads a 5-byte header and exactly
  the announced body with `io.ReadFull`. Verified against a real server in Phase
  4.4b: the first unread frame is the first `ParameterStatus`.
- `wire.ErrorFields` holds `SQLState`, `Severity` and `Native`, and has no field
  any other `ErrorResponse` field could occupy.
- `wire.MsgAuthentication`, `MsgErrorResponse`, `MsgNoticeResponse` and
  `MsgNegotiateProtocolVersion` are the framing constants that exist today.
  `'S'`, `'K'` and `'Z'` are not yet named.
- `RESOURCE_NOT_FOUND` is **absent** from `domain.FailureClass` — 38 members, the
  count unchanged since Phase 4.3 deferred it for want of a reachable producer.
- `AUTHZ_DENIED`, `AUTHZ_NOT_PERMITTED`, `PROTOCOL_UNEXPECTED_RESPONSE`,
  `PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_PEER_CLOSED`, `EXEC_LOCAL_TIMEOUT` and
  `EXEC_CANCELLED` all exist. **There is no capacity or server-unavailable class.**
- `make check` green, one runtime dependency, zero transitive.

Measured on PostgreSQL **18.6** and **14.24**, a real streaming standby, and
pgBouncer **1.25.2**. Frame-by-frame transcripts are in
`docs/validation/POSTGRES_PHASE45_SESSION_STUDY.md`.

## Decision

### 1. `ReadyForQuery` is the boundary, and it is the *only* boundary

```text
session PASS  ⟺  ReadyForQuery received
```

Every counterexample ADR 0036 predicted was reproduced, and one it did not:

| After `AuthenticationOk` | Measured |
|---|---|
| unknown database | `ErrorResponse 3D000`, then EOF |
| `CONNECT` revoked | `ErrorResponse 42501`, then EOF |
| connection slots exhausted | `ErrorResponse 53300`, then EOF |
| healthy | 15 `ParameterStatus`, `BackendKeyData`, `ReadyForQuery 'I'` |

**`57P03` was measured *pre-authentication*.** A standby with `hot_standby=off`
answers `cannot_connect_now` from `BackendInitialize`, before any
`AuthenticationXXX` message. It is a `postgres.startup` fact, not a session one,
and this record does not map it at the session step. ADR 0036 §5 listed it among
the post-`AuthenticationOk` failures; that placement was reasoned rather than
measured, and it is corrected here.

**Authentication is never retroactively failed.** A session that fails at `3D000`
leaves the `postgres.authentication` node `PASS`, because the credential *was*
accepted — the server said so with `AuthenticationOk` after a signature svcdoctor
verified. The two nodes answer two different questions and a later answer does not
rewrite an earlier one.

### 2. The frame state machine, measured rather than remembered

```text
AuthenticationOk
   │
   ├─ E ErrorResponse            → FAIL. Measured as the *first* frame, always.
   │
   └─ S ParameterStatus × N      → N = 15 on 18.6, 13 on 14.24
        │
        └─ K BackendKeyData      → 8 bytes under protocol 3.0: pid, then secret
             │
             └─ Z ReadyForQuery  → transaction status byte. PASS.
```

Answering the ordering questions directly, from measurement:

| Question | Answer |
|---|---|
| Can `ErrorResponse` precede any `ParameterStatus`? | **Yes — and on a genuine backend it always did.** All three failure SQLSTATEs arrived as frame 1, with zero parameters before them |
| Can it follow some `ParameterStatus`? | Not observed on a real backend. The protocol permits it and a pooler or a timeout can produce it, so the reader must handle it |
| Can `BackendKeyData` precede an error? | Not observed. It is emitted immediately before `ReadyForQuery` |
| Is `ReadyForQuery` always last? | Yes. Nothing followed it, and after an `ErrorResponse` the peer closed |
| Can `NoticeResponse` appear? | Not reproduced on a stock server. The protocol permits one almost anywhere, so it is skipped structurally — as `Startup` and the SCRAM loop already do |
| Can `NotificationResponse` appear? | Not before `ReadyForQuery`: it requires `LISTEN`, and svcdoctor issues no commands |
| Can `ParameterStatus` repeat? | Not in this window. It repeats mid-session when a GUC changes, which is past the boundary |
| Are unknown frame types legal here? | No frame type other than `S`, `K`, `Z`, `E` and `N` was observed. An unknown type is `PROTOCOL_UNEXPECTED_RESPONSE` |

**The "partial parameters then failure" case does not occur naturally**, and that
is a measured fact rather than an assumption. It is still handled, because a
timeout mid-block and a hostile peer both produce it.

### 3. `ParameterStatus`: four keys kept, eleven dropped

The server sends fifteen. Copying them wholesale would leak by default, which is
the wrong failure direction, so the allowlist is built from consumers rather than
from availability.

**Kept:**

| Key | Why | 14.24 | 18.6 |
|---|---|---|---|
| `postgres.server_version` | version-dependent behaviour is a real diagnostic axis, and nothing else in a run reports it | ✓ | ✓ |
| `postgres.in_hot_standby` | primary versus replica. **Measured `on` against a real streaming standby and `off` against its primary** | ✓ | ✓ |
| `postgres.default_transaction_read_only` | a session-level writability default that is **independent** of recovery — see §4 | ✓ | ✓ |
| `postgres.is_superuser` | one bit about the privilege of the connection svcdoctor established | ✓ | ✓ |

**Dropped as identity:**

| Key | Why |
|---|---|
| `session_authorization` | **it is the role.** Identity, and the role is already on the startup node as an `IdentityAttr` |
| `search_path` | contains `"$user"` and deployment schema names. 18.6 only; 14.24 does not send it |

**Dropped for want of a consumer.** `integer_datetimes`,
`standard_conforming_strings`, `server_encoding`, `client_encoding`, `DateStyle`,
`IntervalStyle`, `TimeZone` are server configuration trivia that no candidate
finding in ADR 0036 §17 reads. `application_name` is svcdoctor's own value echoed
back. `scram_iterations` (16+) is **already recorded on the authentication node**
from the wire, and a second copy would be one fact with two representations.

**`server_version_num` is not sent by either version**, so the ADR 0036 §9
candidate list is corrected: only `server_version` is available, and it carries
the packaging string — `"18.6 (Debian 18.6-1.pgdg13+2)"` — not a bare number. A
consumer that needs an ordered comparison must parse it, and that is a Phase 4.6
problem, not a reason to retain more here.

Two members are the weakest-justified and are flagged for review rather than
smuggled through. `is_superuser` is a statement about the *principal* rather than
about the server, though it names nobody; `postgres.transaction_status` (§5) is
provably constant on every path measured. Both are directly observed,
identity-free single values, and both have the precedent
`kafka.sasl.session_lifetime_ms` set: recorded, never acted on.

### 4. `in_hot_standby` and `default_transaction_read_only` are not the same fact

Phase 4.0 claimed both are available without SQL. Verified — and the relationship
between them was not what the claim implied.

On a real streaming standby: `in_hot_standby = on`, and
**`default_transaction_read_only = off`**.

A session on a standby is read-only because of *recovery*, not because that GUC is
set. So a rule that read `default_transaction_read_only` alone would call a
replica writable. The two are independent facts and both are kept:
`in_hot_standby` answers "is this a replica", `default_transaction_read_only`
answers "is the GUC set". Neither alone answers "can I write here", and this
record authorizes no finding that claims to.

`transaction_read_only` is not sent at all; it is session-local and would need
SQL. It is therefore deferred as a *fact*, which is the rule §11 states: defer the
fact, never the no-SQL decision.

### 5. `ReadyForQuery`'s status byte is recorded; `postgres.ready` is not

`ReadyForQuery` carries one byte: `'I'` idle, `'T'` in a transaction block, `'E'`
in a failed transaction block.

**`'I'` on every path measured** — 18.6, 14.24, primary, standby, superuser,
non-superuser, and through pgBouncer. A fresh session cannot be inside a
transaction, because svcdoctor issues no command that could open one, so `'T'` and
`'E'` are unreachable here by construction rather than by luck.

Recorded as `postgres.transaction_status` anyway, because it is the entire payload
of the frame that *defines* success, and a value other than `'I'` would say
something no other observation could. A non-`'I'` value is **not** a failure: the
session reached the boundary, and what the byte says is a fact about it.

`postgres.ready` from ADR 0036 §9 is **not** added. It would be `true` exactly
when the node is `PASS`, which is one fact with two representations.

### 6. `BackendKeyData` is parsed and discarded whole

Eight bytes under protocol 3.0: a 32-bit process ID and a 32-bit secret key. (It
grows to 32 bytes under 3.2, which svcdoctor does not request.)

**The secret is never retained, anywhere.** It exists for `CancelRequest`, and
cancellation is not in scope: svcdoctor issues no query, so there is nothing to
cancel. Storing a secret "for future cancellation" would create a second secret
carrier in a repository that has spent four phases confining the first one.

**The process ID is not retained either.** No candidate finding reads it, and it
is a server-side identifier of the backend serving *this* connection — which
through a pooler is synthetic anyway: pgBouncer answered with pid `799998125` and
`1172961953` on two connections to the same server.

So the frame is read for its length and dropped. `wire` returns nothing from it,
which means there is no field a caller could leak.

### 7. SQLSTATE classification

**Every mapping below is scoped to this step, and to no other.** The table is not
a PostgreSQL SQLSTATE dictionary; it is what these codes prove *when they arrive
between `AuthenticationOk` and `ReadyForQuery`, with no statement issued*. §7.1
states that rule and §11.1 records the acceptance tests that hold it.

| SQLSTATE | PostgreSQL meaning | Observed | Class |
|---|---|---|---|
| `3D000` | `invalid_catalog_name` | post-auth, frame 1 | **`RESOURCE_NOT_FOUND`** (§8) |
| `42501` | `insufficient_privilege` | post-auth, frame 1 | **`AUTHZ_DENIED`** (§9) |
| `53300` | `too_many_connections` | post-auth, frame 1 | `PROTOCOL_UNEXPECTED_RESPONSE` + SQLSTATE (§10) |
| `57P03` | `cannot_connect_now` | **pre-auth** | not a session class; see §1 |
| `08004` | `sqlserver_rejected_establishment_of_sqlconnection` | not observed | `PROTOCOL_UNEXPECTED_RESPONSE` |
| `28000`, `28P01` | authentication | not observed post-auth | `PROTOCOL_UNEXPECTED_RESPONSE` |
| `08P01` | pgBouncer's default | **never reaches this step** (§11) | `PROTOCOL_UNEXPECTED_RESPONSE` |
| anything else | — | — | `PROTOCOL_UNEXPECTED_RESPONSE` |

`28P01` is deliberately **not** mapped to `AUTH_CREDENTIALS_REJECTED` here. That
class means *the peer refused the authentication material it was presented*, and
the session step presents none — the claim would be vacuous. This is the same
discipline ADR 0038 amendment B applied to `08P01`.

#### 7.1 SQLSTATE mappings are protocol-step scoped, and there is no global table

The repository already works this way and this record makes it a rule rather than
an accident. Each step owns its own classifier:

| Step | Classifier |
|---|---|
| `postgres.startup` | `sqlStateFailure` |
| `postgres.authentication` | `authSQLStateFailure` |
| `postgres.session` | added in 4.5b |

**A shared, service-wide `SQLSTATE → FailureClass` table must not be created, and
is not a refactor to accept later.** Its whole appeal — one place to look up a
code — is the defect: it would answer *what does this code mean* when the only
answerable question is *what does this code prove here*.

Concretely: `3D000` and `42501` arriving at `postgres.startup` or at
`postgres.authentication` **stay `PROTOCOL_UNEXPECTED_RESPONSE`**. Neither step
proves what §8 and §9 prove. Startup has not authenticated anybody, so nothing
was denied an operation; authentication presents no database name for a catalog
lookup to fail on. A code arriving where its meaning is not established is a code
svcdoctor cannot normalize, and the weak class says exactly that.

A step earns a stronger class only by proving the generic fact independently, in
its own window, from its own source path — which is the work §8 and §9 do and
which any future step would have to repeat.

This is the same discipline ADR 0038 amendment B applied to `08P01`: position and
plausibility are not proof, and a classifier that stops asking *which window* is
one refactor away from becoming a lookup table.

### 8. `RESOURCE_NOT_FOUND` is added, because the producer now exists

ADR 0036 §16 authorized it; Phase 4.3 deferred it because `3D000` arrives after
`AuthenticationOk`, which that phase's state machine could not reach. **This phase
is that producer**, and the class is added in 4.5b.

It is honest for `3D000`. The claim is *the named resource a step targets does not
exist*, and the server asserted exactly that with its own catalog-name code —
`ERRCODE_UNDEFINED_DATABASE` — about a database name svcdoctor itself supplied. It
is not authorization: the role never got far enough to be denied anything. It is
not a protocol failure.

It is service-neutral: Kafka's `UNKNOWN_TOPIC_OR_PARTITION` is the same shape, and
a future adapter targeting a named resource inherits it.

#### 8.1 Three distinct causes, one code, and the claim that survives all three

`src/backend/utils/init/postinit.c` emits `3D000` in this window from more than
one condition, and svcdoctor sees the same five characters for each:

| Cause | Where | What actually happened |
|---|---|---|
| requested database lookup failed | `InitPostgres`, `GetDatabaseTuple` on `in_dbname` | no such row for the name in the `StartupMessage` |
| concurrent disappearance or rename | `InitPostgres`; `CheckMyDatabase`'s *"has disappeared from pg_database"* | the row existed at lookup and did not survive the race |
| catalog/filesystem inconsistency | `InitPostgres`, missing database subdirectory | the catalog row exists and its files do not |

The third is the interesting one: it is **corruption, not absence**, and the
server still reports it as `database "%s" does not exist`.

**The mapping is authorized anyway**, because the generic claim is true of all
three: the peer asserts that the requested database resource cannot be found or
used as the named database. What svcdoctor must not do is say *which*.

**`postgres.session` and any finding built on it MUST NOT claim:**

- that the database was never created;
- that it was explicitly dropped;
- that the catalog is healthy;
- that the filesystem is healthy;
- any specific root cause at all.

The evidence and finding layers may state the generic resource-not-found fact and
stop. `postgres.sqlstate = 3D000` is on the node for a reader who wants to go
further; svcdoctor does not go there on their behalf.

### 9. `42501` reuses `AUTHZ_DENIED`, and the reuse is narrow

`AUTHZ_DENIED` means *the identity authenticated but was denied the operation*.
Both halves hold and were measured: `AuthenticationOk` arrived after a verified
signature, and the server then refused with `permission denied for database`.

It is deliberately **not** `AUTHZ_NOT_PERMITTED`, which ADR 0036 added for a
refusal made *before* any authentication material was evaluated. Here the identity
authenticated first, which is the whole distinction between the two classes.

#### 9.1 Only one 42501 site is reachable, and that is a property of what svcdoctor sends

`postinit.c` contains three `ERRCODE_INSUFFICIENT_PRIVILEGE` sites. Two are
structurally unreachable for svcdoctor, and the reason is its own
`StartupMessage` surface rather than a hope about server configuration:

| Site | Requires | Reachable |
|---|---|---|
| `CheckMyDatabase` — `CONNECT` privilege | nothing | **yes, the only one** |
| `InitPostgres` — *"must be superuser to connect in binary upgrade mode"* | the binary-upgrade startup option | no |
| `InitPostgres` — *"permission denied to start WAL sender"* | the `replication` startup parameter | no |

`wire.EncodeStartup` emits `user` and, when supplied, `database` — nothing else.
`TestStartupSendsNothingItWasNotAskedFor` already asserts the absence of
`replication` and `options` by name, so the two unreachable rows stay unreachable
by a test rather than by convention.

**One residual was measured rather than reasoned away.** `process_settings()`
applies `ALTER ROLE SET` GUCs inside this window, and a superuser-only setting
applied to a non-superuser could plausibly raise `ERRCODE_INSUFFICIENT_PRIVILEGE`
there — which would be a completely different fact wearing the same five
characters. Tested on 18.6: `ALTER ROLE plain SET log_statement = 'all'`, then a
connection as `plain`. The result was **`ReadyForQuery 'I'`** — no `42501`, no
`NoticeResponse`. PostgreSQL skips a setting it cannot apply and continues. The
residual is closed.

So, **within the `postgres.session` classifier only**:

> `42501` means the authenticated principal was denied `CONNECT` to the requested
> database.

**It MUST NOT imply:**

- table, schema or function privilege denial;
- missing role membership;
- write permission denial;
- that superuser is required.

svcdoctor issues no statement, so none of those checks can have run. That is a
binding constraint on Phase 4.6's wording, not only on this node's class.

### 10. Capacity and availability get no new class

`53300` is a real operational fact and a different remedy from anything else in
the table: it sends a reader to `max_connections` or to a pooler, not to a
credential store or a catalog.

**No class is added anyway**, and the reasoning is the one Phase 4.3 applied to
`RESOURCE_NOT_FOUND` in reverse:

- No ADR authorizes a capacity class. `RESOURCE_NOT_FOUND` is being added because
  ADR 0036 §16 authorized it and the producer arrived; a capacity class has
  neither.
- There is exactly one producer — PostgreSQL's `53300`. Kafka implements no
  analogue. A generic class with one service behind it is a vocabulary invented
  from a single SQLSTATE, which §13 of this phase's own brief forbids.
- **Nothing is lost.** `postgres.sqlstate = 53300` is on the node, and a Phase 4.6
  rule can key a finding on it without any new class at all — which is the
  0033 → 0034 pattern: evidence first, policy second.

So `53300` is `FAIL` + `PROTOCOL_UNEXPECTED_RESPONSE` with the code recorded. The
class is weak and true: the peer refused to establish the session and svcdoctor
declines to normalize why. **Reopen when a second service produces a capacity
refusal**, or when a Phase 4.6 rule demonstrates that the SQLSTATE attribute is
insufficient.

### 11. pgBouncer: the session step sees success or nothing

Re-measured, because this is where Phase 4.0 and Phase 4.4b both found the model
degrading.

| Scenario | Where the failure lands |
|---|---|
| healthy | full session: 15 `ParameterStatus`, `BackendKeyData`, `ReadyForQuery 'I'` |
| unknown database | `08P01` **pre-authentication** — `3D000` never reaches this step |
| `CONNECT` denied | `08P01` **pre-authentication** — `42501` never reaches this step |
| backend down, verifier cached | **a complete successful session** — see below |

**Neither `3D000` nor `42501` survives a pooler.** They do not arrive collapsed at
this step; they arrive at `postgres.startup` as `08P01`, before authentication.
So a Phase 4.6 rule keyed on either must not assume it fires, exactly as ADR 0036
§10 requires for `28P01`.

**And the sharpest result of this phase: with the backend stopped, pgBouncer
returned a complete, passing session.** Fifteen `ParameterStatus` values from its
cache, a synthetic `BackendKeyData`, and `ReadyForQuery 'I'` — with no PostgreSQL
server running behind it.

That is what fixes the wording in §12. No pooler-specific production code is
added; `postgres.error_is_native` remains the one structural, non-prose signal.

#### 11.1 Acceptance tests for the two mappings, required in 4.5b

These pin the **window**, not the value. A test that only asserts
`3D000 → RESOURCE_NOT_FOUND` would pass against a global lookup table, which is
the outcome §7.1 forbids.

| # | Step | SQLSTATE | Required class |
|---|---|---|---|
| 1 | `postgres.session` | `3D000` | `RESOURCE_NOT_FOUND` |
| 2 | `postgres.startup` | `3D000` | `PROTOCOL_UNEXPECTED_RESPONSE` |
| 3 | `postgres.authentication` | `3D000` | `PROTOCOL_UNEXPECTED_RESPONSE` |
| 4 | `postgres.session` | `42501` | `AUTHZ_DENIED` |
| 5 | `postgres.startup` | `42501` | `PROTOCOL_UNEXPECTED_RESPONSE` |
| 6 | `postgres.authentication` | `42501` | `PROTOCOL_UNEXPECTED_RESPONSE` |

Rows 2, 3, 5 and 6 are the ones that matter. They are the difference between "this
code means X" and "this code proves X *here*", and they must fail if a later
change makes classification uniform across steps.

Plus one structural guard:

> **Moving these mappings into a shared, service-wide SQLSTATE table must break
> the test suite.** The guard asserts that a distinct per-step classifier function
> exists for each step, in the same shape as
> `TestEnglishMessageGuardCoversTheClassifier`, and the mutation is verified to
> compile and to flip rows 2, 3, 5 and 6 before it is trusted.

### 12. What a passing session node claims — and the four things it does not

> **A PostgreSQL-protocol session reached `ReadyForQuery` at this endpoint, for
> the role and database this run named.**

That is the whole claim. It does **not** mean:

- that a PostgreSQL server exists behind the endpoint — measured: a pooler served
  a complete session with its backend stopped;
- that the session is writable, or that the endpoint is a primary —
  `in_hot_standby` is recorded as a separate fact and answers that separately;
- that any schema, table or row exists, or that the role may read one — svcdoctor
  executed no statement and has no basis for either;
- that the connection would still work a second later.

The endpoint wording is deliberate and matches ADR 0036 §10: svcdoctor never says
"I reached PostgreSQL".

### 13. Evidence contract

| | |
|---|---|
| Step | `postgres.session` |
| Layer | **L5** |
| Parent | whatever `AuthenticatedSession.Evidence()` names — the authentication node, or the startup node on a `trust` path where no authentication node exists |
| Subject | the concrete `ip:port`, matching every node on the path |
| Identifier | `probe.ScopedEvidenceID(scope, step, endpoint, addr)` — two components, as every other step here |

L5 is correct and L6 is wrong. `docs/ARCHITECTURE.md` puts topology discovery at
L6; this step discovers nothing and speaks for one connection. It shares L5 with
`postgres.authentication` for the reason `kafka.sasl_handshake` and
`kafka.sasl_authenticate` already do: a layer says where in the ladder a step
sits, not what taxonomy its failure belongs to.

**Attributes**

| Key | Kind | When |
|---|---|---|
| `postgres.server_version` | string | when the parameter was observed |
| `postgres.in_hot_standby` | bool | when observed |
| `postgres.default_transaction_read_only` | bool | when observed |
| `postgres.is_superuser` | bool | when observed |
| `postgres.transaction_status` | string | when `ReadyForQuery` was read |
| `postgres.sqlstate` | string | on an `ErrorResponse` |
| `postgres.error_severity` | string | on an `ErrorResponse` — `V` only |
| `postgres.error_is_native` | bool | on an `ErrorResponse` |

**Never recorded:** `BackendKeyData`'s secret key or its process ID;
`session_authorization`; `search_path`; any non-allowlisted `ParameterStatus`; any
`ErrorResponse` field other than `C` and `V`; any `NoticeResponse` content; the
role or database, which are already on the startup node as identity attributes.

**No new `AttrKind` is needed.** Every value is a string or a bool, and none is
identity — which is the direct consequence of dropping the two parameters that
were.

### 14. Partial observations are recorded, per attribute, on any state

If a timeout arrives after `server_version` and `in_hot_standby` but before
`ReadyForQuery`, the `UNKNOWN` node carries those two attributes.

This is not a new rule; it is `internal/probe/tls`'s rule, quoted:

> *"An attribute appears when the observation actually produced it. A failed
> handshake has no negotiated version, and a handshake that never reached the
> peer's certificates has no certificate facts, so those keys are absent rather
> than empty: an absent fact and a zero value are different things."*

The TLS probe records the certificate chain of a handshake that **failed**
verification, and its own comment calls that "usually the most useful thing in the
report when a handshake fails". The session step inherits the shape: presence is
decided per attribute by whether it was observed, never per node by whether the
step passed.

The state still tells the truth on its own — `UNKNOWN` means svcdoctor does not
know whether a session could be established — so a reader cannot mistake a
recorded `server_version` for a session that worked.

### 15. Ownership: the session step is terminal, and closes in every outcome

| Outcome | Evidence | Connection |
|---|---|---|
| `ReadyForQuery` | **PASS** | `Terminate`, then closed |
| any `ErrorResponse` | FAIL | closed |
| malformed or unexpected frame | FAIL | closed |
| peer closed | FAIL | closed |
| local deadline expired | UNKNOWN | closed |
| run cancelled | UNKNOWN | closed |

**No live connection is returned, and no new session type is created.** That is a
deliberate departure from the shape the three steps before it use, and the reason
is that the reasons for that shape are gone:

- Nothing in v0.1 consumes a post-`ReadyForQuery` connection. There is no SQL, and
  PostgreSQL topology discovery is out of scope (ADR 0036 §12).
- ADR 0036 §12 requires `Terminate` before closing a session that reached
  `ReadyForQuery`. That is the *owner's* courtesy, and if the connection escapes,
  nobody performs it.
- A live handle with no consumer is the speculative machinery ADR 0002 forbids,
  and a type named `Session` in a package that already has `Session` and
  `AuthenticatedSession` would be the third carrier of the same socket.

The step therefore consumes the `AuthenticatedSession` and returns `error` only:
every protocol outcome is evidence, and an error means the step could not run.
**Reopen the moment a step exists that runs after `ReadyForQuery`** — a query
executor, or PostgreSQL topology — at which point the connection has a consumer
and a returned type has a reason.

**No redial, no retry, no second attempt, no statement.**

### 16. No node is invented for a session nobody asked for

If authentication did not pass, there is no `AuthenticatedSession`, so the step
cannot be called and no `postgres.session` node exists. That is correct and needs
no special case: an absent node means nobody requested the step, which is what the
graph already communicates.

Called with unusable input — a nil builder, a consumed session — the step returns
a Go error and records nothing. That matches `Negotiate`, `Startup` and
`Authenticate`, and it keeps svcdoctor from reporting on its own caller.

There is one deliberate difference from `Startup`, which *does* record a `SKIPPED`
node when its session is dead. `Startup` can do that because a dead `Session`
carries a blocker identifying what stopped it. Nothing analogous reaches this
step, so nothing is fabricated.

### 17. No SQL, and the decision is re-verified rather than inherited

`SELECT 1`, `SHOW transaction_read_only` and `SELECT pg_is_in_recovery()` are all
unnecessary:

| Wanted | Available without SQL |
|---|---|
| the endpoint speaks PostgreSQL and a session works | `ReadyForQuery` itself |
| primary or replica | `in_hot_standby`, measured `on` on a real standby |
| read-only default | `default_transaction_read_only` |
| server version | `server_version` |
| role privilege | `is_superuser` |

The one fact that *would* need SQL — the session-local `transaction_read_only`,
which is what actually makes a standby session read-only — is **deferred as a
fact**. The no-SQL rule is not weakened to obtain it. If a Phase 4.6 rule proves
it needs that value, that is a new decision about executing a statement, with its
own record and its own threat model.

### 18. Security

- **No new `security.Reveal` site.** The count stays at two, one per service.
- **No `Credential` or `Secret` in the Phase 4.5 API.** The step takes an
  `AuthenticatedSession`, which carries neither, so there is no parameter through
  which one could arrive.
- **No new secret carrier.** `BackendKeyData`'s key is read as length and dropped.
- **No prose.** The `C`/`V` whitelist is unchanged and gains no field.
- **No identity.** The two identity-bearing parameters are dropped at the wire
  boundary, so nothing downstream has to remember to filter them.
- **No report schema change, no redaction change, no new `AttrKind`.**

The hostile-canary tests are repeated in 4.5b rather than assumed, because
post-authentication `ErrorResponse` messages carry the database name, the role and
svcdoctor's own NAT-translated source address — measured in Phase 4.0 §4.2 and
again here.

### 19. Phase 4.5 produces evidence and no findings

No finding code, no severity, no diagnosis rule. `POSTGRES_DATABASE_NOT_FOUND`,
`POSTGRES_CONNECT_DENIED`, a capacity finding, a replica finding and pooler
degradation are all Phase 4.6's, written against real graphs as ADR 0034 was.
This record authorizes the *facts* those rules will read and nothing else.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| `AuthenticationOk` as the session boundary | Measured false three ways: `3D000`, `42501` and `53300` all arrive after it | Never |
| Fail authentication retroactively when the session fails | Two nodes answer two questions; the credential really was accepted | Never |
| Record every `ParameterStatus` | Leaks by default. Two of the fifteen are identity | Never |
| Keep `session_authorization` | It is the role, already on the startup node as an identity attribute | Never |
| Keep `search_path` | Contains `"$user"` and deployment schema names; 18.6 only | Never |
| Keep the encoding and formatting parameters | No candidate finding reads them | A rule needs one |
| Re-record `scram_iterations` here | Already on the authentication node; one fact, two representations | Never |
| Store `BackendKeyData`'s secret for cancellation | Cancellation is out of scope, and it would be a second secret carrier | A step issues a statement that could need cancelling |
| Store `BackendKeyData`'s pid | No consumer, and a pooler's value is synthetic — measured | A rule correlates backends across connections |
| Add `postgres.ready` | True exactly when the node is PASS | Never |
| Add a capacity `FailureClass` for `53300` | One producer, no authorizing ADR, and the SQLSTATE attribute already carries it | A second service produces a capacity refusal |
| Map `53300` to `AUTHZ_DENIED` | Nothing was authorized or denied; the server is full | Never |
| Map `28P01` at this step to `AUTH_CREDENTIALS_REJECTED` | The session step presents no authentication material, so the claim is vacuous | Never |
| Map `57P03` at the session step | Measured *pre-auth*; it belongs to `postgres.startup` | A post-auth occurrence is observed |
| Assume `3D000` survives a pooler | Measured: pgBouncer answers `08P01` before authentication | Never |
| A shared PostgreSQL `SQLSTATE → FailureClass` table across steps | Answers "what does this code mean" when the only answerable question is "what does it prove here"; §7.1 | Never |
| Name a root cause for `3D000` | Three distinct causes share the code, one of them corruption rather than absence; §8.1 | A structural signal distinguishes them |
| Read `42501` as any privilege denial | Only the `CONNECT` check is reachable, because svcdoctor sends no `replication` or binary-upgrade option and issues no statement; §9.1 | svcdoctor executes SQL, which is its own decision |
| Return a live connection and a `ReadySession` type | Nothing consumes it, and `Terminate` would never be sent | A step runs after `ReadyForQuery` |
| Record a `SKIPPED` session node when authentication failed | No blocker reaches this step; the absent node is the honest record | A caller can name the subject and the blocker |
| Execute `SELECT 1` to prove the session works | `ReadyForQuery` proves it, and a statement changes the threat model | Never |
| Execute `pg_is_in_recovery()` | `in_hot_standby` is the same fact, measured, for free | Never |
| Drop partial attributes on a non-PASS node | Contradicts the TLS probe's rule, which reports the chain of a failed handshake | Never |
| Treat a non-`'I'` transaction status as failure | The session reached the boundary; the byte is a fact about it | Never |

## Consequences

- svcdoctor will complete the PostgreSQL vertical slice: DNS, TCP, `SSLRequest`,
  TLS, `Startup`, SCRAM authentication and session establishment, over one socket,
  with no SQL and no redial.
- **One `FailureClass` is added** — `RESOURCE_NOT_FOUND`, authorized by ADR 0036
  §16 and now with a reachable producer. The count goes 38 → 39.
- Five attribute keys are added under the existing `postgres.` namespace. **No
  `domain` type, no report schema field, no redaction rule and no `AttrKind`
  changes.**
- **No new dependency and no new `security.Reveal` site.** Still one runtime
  module, two reveal call sites.
- A passing session node claims that a PostgreSQL-protocol session reached
  `ReadyForQuery` at an endpoint — not that PostgreSQL is behind it, not that the
  session is writable, and not that any object exists.
- Phase 4.6 receives the facts it needs for database-not-found, connect-denied,
  replica and capacity findings, and the measured constraints on what each may
  claim behind a pooler.
- **Two wording constraints bind Phase 4.6 directly.** A database-not-found
  finding may not name a root cause (§8.1), and a connect-denied finding may not
  imply any privilege other than `CONNECT` (§9.1).
- Classification stays per step. There is no global SQLSTATE table, and creating
  one is a rejected alternative rather than an open refactor (§7.1).

## Amendments from implementation (Phase 4.5b)

### A. A repeated `ParameterStatus` key takes the last value

Section 2 recorded that `ParameterStatus` does not repeat in this window, which is what was
measured, and left the policy unstated because nothing needed one. An implementation needs
one anyway, for the peer that does it.

**Last wins.** A `ParameterStatus` reports what a run-time parameter *is*, and the protocol
emits another when it changes, so a later frame describes the session and an earlier one
describes a state it has left.

That is deliberately the opposite of `DecodeErrorFields`, which takes the first occurrence,
and the two are not in tension. There the duplicates are fields *inside one message*, where
a last-wins reader could be steered by anything able to append to a field list. Here they
are separate frames whose whole purpose is to supersede. Different situations, different
rules, both now written down and both pinned by a test.

### B. The step returns a result value, not only an error

Section 15 said the step "returns `error` only". It returns `(*SessionResult, error)`, with
`SessionResult` carrying an endpoint label and the session node's identifier — and **no
connection**.

Every load-bearing part of section 15 stands: no live socket escapes, no reusable session
type exists, `Terminate` is sent by the owner, and every outcome closes. What changed is the
success signal. Under an error-only signature a caller cannot tell a session that reached
`ReadyForQuery` from one that did not without walking the graph, which the three sibling
steps do not require of it. `nil` result on a recorded non-passing outcome is the idiom
`Negotiate`, `Startup` and `Authenticate` already use.

`TestSessionResultCarriesNoConnection` pins the type at two accessors and asserts by
reflection that neither a field nor a method can carry a `net.Conn`, so the narrow shape is
enforced rather than remembered.

### C. A latent deadline race was fixed in `postgres/wire`, and Kafka still has it

Not a decision change. `bindDeadline`'s watcher goroutine expires the socket when its
context ends, and `release` used to clear the deadline without waiting for that goroutine to
exit. A watcher scheduled *after* release could then find both channels ready, pick
`ctx.Done()`, and leave an expired deadline nothing would ever clear.

Phase 4.5b is the first path in the repository that **writes to a connection after a bounded
read on it** — the `Terminate` that closes an established session — so it is the first phase
where the bug could be observed at all. It failed with `i/o timeout` against a peer that was
plainly still listening. `release` now waits for the watcher before clearing, which makes
the invariant the function already documented actually true.

`internal/adapter/kafka/wire` holds an identical copy and was **not** changed: no Kafka path
writes after a bounded read, so nothing triggers it there, and a phase that does not own
that package should not edit it silently. Recorded here so the next person to touch it knows.

## Reopen conditions

- **A step that runs after `ReadyForQuery`** — §15's terminal shape becomes a
  returned live session with a consumer.
- **A second service that refuses on capacity** — §10's deferred class gains the
  generality a `FailureClass` requires.
- **A Phase 4.6 rule that needs session-local `transaction_read_only`** — the
  deferred fact is reconsidered on its own merits, as a decision about executing a
  statement.
- **A `57P03` observed after `AuthenticationOk`** — §1's placement is revisited.
- **A `NoticeResponse` observed before `ReadyForQuery`** — the structural skip
  stops being defensive and becomes testable against something real.
- **Protocol 3.2** — `BackendKeyData` grows to 32 bytes and the startup version
  becomes a choice with consequences.
- **A structural signal that separates the three `3D000` causes** — §8.1's
  must-not-claim list narrows, and only then.
- **svcdoctor executing a statement** — §9.1's reachability argument for `42501`
  is rebuilt from scratch, because table, schema and function privilege checks
  become reachable the moment a query runs.
- **Anything that writes to a Kafka connection after a bounded read** — amendment C's fix
  must be carried into `internal/adapter/kafka/wire` before that path exists.
- **A rule that needs an ordered server version** — `server_version` carries a
  packaging string, and parsing it is a Phase 4.6 problem with its own record.
