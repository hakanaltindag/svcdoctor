# ADR 0069: A RabbitMQ refusal is classified by construction, and vhost authorization is its own stage

## Status

**Accepted in Phase 8.1.** The RabbitMQ half is **not implemented**; the one
service-neutral half — the `RESOURCE_LIMIT_REACHED` failure class and the migration of
PostgreSQL SQLSTATE `53300` onto it — **is implemented in this phase**.

`SchemaVersion` stays **1**. This record authorizes **one** new `FailureClass` and the
RabbitMQ `FindingCode` set in §7; no dependency, and no new `Step` beyond ADR 0067's
three.

Companion records: [0067](0067-rabbitmq-basic-journey-and-terminal-boundary.md) is the
journey, [0068](0068-rabbitmq-authentication-and-credential-authority.md) is the
credential model, [0070](0070-rabbitmq-tune-contract-and-wire-bounds.md) owns the
negotiation outcomes this record's §5 table refers to.

It applies ADR 0066's rule — a peer-supplied string is a fact about what the peer said,
never about what is true — to a payload that is a formatted sentence rather than a
single token, and tightens it in the process.

## 1. Two stages, and the protocol separates them for us

| Stage | svcdoctor is awaiting | Refusal code | Peer `class_id`/`method_id` |
|---|---|---|---|
| `rabbitmq.authentication` | `Connection.Tune` | **403 `ACCESS_REFUSED`** | RabbitMQ `0/0`, LavinMQ `10/11` |
| `rabbitmq.connection_open` | `Connection.Open-Ok` | **530 `NOT_ALLOWED`**, or `541 INTERNAL_ERROR` | `10/40` on both |

Phase 8.0A had asked whether *credential rejected* and *vhost denied* could be separated
if both used `ACCESS_REFUSED`. **They never share a code.** RabbitMQ raises
`access_refused` for the first and `not_allowed` for the second, and Phase 8.0C measured
both on 3.13.7 and 4.2.0. LavinMQ agrees.

They are therefore separated **three times over**: by svcdoctor's own handshake position,
by the numeric code, and by the peer's class and method ids. That redundancy is what
makes the rest of this record safe — text is only ever asked to refine a conclusion that
already stands without it.

**Attribution authority is svcdoctor's own handshake state.** It is peer-independent and
unforgeable: a hostile peer can lie about `class_id` and `reply_code`, but it cannot
change which frame svcdoctor was waiting for. The peer's class and method ids are
recorded as corroborating observations and drive nothing.

## 2. Raw peer text never crosses the wire boundary

`reply_text` is peer-controlled twice over. RabbitMQ interpolates the vhost and username
into it. An authorization backend can **append arbitrary bytes** to a vhost refusal —
`check_access/5` concatenates `" by backend ~ts: ~ts"` for a `{false, Reason}` result and
formats an arbitrary Erlang term with `~tp` for an `{error, E}` result — so the text is
not a closed set and cannot be made one.

> **No byte of `reply_text` is stored, rendered, logged, returned in an error value, or
> placed in evidence. Only a normalized sentinel leaves the wire package.**

This is ADR 0066's rule. What follows is how it is applied to a payload that carries a
distinction the numeric code does not.

## 3. Construct-and-compare, not parsing

Phase 8.0A proposed anchored prefix matching. Phase 8.0B rejected it and Phase 8.0C
measured why. Two defects, both reproduced live:

1. **The proposed anchors did not exist.** RabbitMQ prepends the symbolic exception name:
   `amqp_exception_explanation/2` formats `"~ts - ~ts"` from the constant name and the
   explanation. Every real text begins `NOT_ALLOWED - `, `ACCESS_REFUSED - ` or
   `INTERNAL_ERROR - `. LavinMQ does the same, which Phase 8.0A had recorded as a LavinMQ
   *difference* and was in fact RabbitMQ's own shape.
2. **Prefix and infix matching misclassify.** A vhost legally named
   `a': connection limit (5) is reached`, refused for lack of permission, produced
   `NOT_ALLOWED - access to vhost 'a': connection limit (5) is reached' refused for user '<U>'`
   — and an infix matcher reported a capacity ceiling for an authorization denial.

### 3.1 The contract

Let `S` be the received `reply_text`, `V` the vhost svcdoctor sent and `U` the username
svcdoctor sent. svcdoctor **renders each candidate from its own inputs and compares for
byte equality.** It does not parse, tokenize, extract or scan for substrings.

| # | Guard | Candidate | Match | Sentinel |
|---|---|---|---|---|
| **T0** | any | — | `S` ends with `...` | **`UNSPECIFIED_TRUNCATED`** — evaluated **first**, short-circuits everything |
| T1 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - vhost {V} not found` | equality | `VHOST_NOT_FOUND` |
| T2 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - access to vhost '{V}' refused for user '{U}'` | equality | `VHOST_ACCESS_REFUSED` |
| T3 | 530, awaiting `Open-Ok` | T2 candidate `+ " by backend "` | `S` starts with it | `VHOST_ACCESS_REFUSED` |
| T4 | 530, awaiting `Open-Ok` | T2 candidate `+ ": connection limit ("` ⟨digits⟩ `") is reached"` | equality with the digit hole | `VHOST_CONNECTION_LIMIT` |
| T5 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - connection refused: node connection limit (` ⟨digits⟩ `) is reached` | equality with the digit hole | `NODE_CONNECTION_LIMIT` |
| T6 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - connection refused for user '{U}': user connection limit (` ⟨digits⟩ `) is reached` | equality with the digit hole | `USER_CONNECTION_LIMIT` |
| T7 | 541, awaiting `Open-Ok` | `INTERNAL_ERROR - access to vhost '{V}' refused for user '{U}': vhost '{V}' is down` | equality | `VHOST_DOWN` |
| L1 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - vhost not found` | equality | `VHOST_NOT_FOUND` |
| L2 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - '{U}' doesn't have access to '{V}'` | equality | `VHOST_ACCESS_REFUSED` |
| L3 | 530, awaiting `Open-Ok` | `NOT_ALLOWED - access to vhost '{V}' refused: connection limit (` ⟨digits⟩ `) is reached` | equality with the digit hole | `VHOST_CONNECTION_LIMIT` |
| T8 | anything else | — | — | `UNSPECIFIED` |

The digit hole is **1 to 20 ASCII digits between two fixed literals**, at a fixed
position. No scanning, no numeric conversion of unbounded input.

### 3.2 The properties that make it safe

1. **T0 first.** A truncated string cannot be classified, because truncation removes
   exactly the discriminating suffix. §4.
2. **Nothing is extracted.** `V` and `U` are already in the report from the operator's
   own input; the peer's echo of them is discarded unread. LavinMQ echoes the username in
   L2 and it never surfaces.
3. **A crafted name cannot confuse it.** The pathological vhost of §3 renders into the T2
   candidate and matches it exactly, so the classification is correct — measured.
4. **Only T3 is a prefix rule**, and its extension point is the one place the source
   proves a backend appends.
5. **Bounded work.** At most 255 bytes in, at most eleven candidates out, each rendered
   from data svcdoctor already holds. No allocation depends on peer length.
6. **A hostile peer gains nothing.** It can forge any sentinel — and it already controls
   the reply code, the class ids, the `server-properties` and whether `Open-Ok` arrives at
   all. Text adds no authority. What it must not add is an injection or allocation
   surface, and comparison has neither.
7. **Unmatched degrades.** `UNSPECIFIED` is a fixed sentinel, never a passthrough.

## 4. Truncation is the reason T0 exists, and it was measured

RabbitMQ bounds the explanation with `{chars_limit, 255}`, and the budget is distributed
by `io_lib_format:build_limited/5` so the explanation receives `252 − len(symbol)`
characters — 241 after `NOT_ALLOWED`. Truncation appends **three dots**.

Phase 8.0C reproduced it: a 119-byte vhost and an 80-byte username under a vhost
connection limit produced a `reply_text` of **exactly 255 bytes ending in `...`**, with
`: connection limit (0) is reached` **entirely absent**. A naive prefix matcher still
matched T2's prefix and would have reported an authorization denial for a capacity
ceiling.

So the T0 rule is not defensive tidiness; it is the difference between a wrong answer and
no answer. Both exact templates also fail to match a truncated string, which makes T0
belt-and-braces rather than load-bearing alone — but it is written first so that the
outcome is `UNSPECIFIED_TRUNCATED` rather than a bare `UNSPECIFIED`, and a reader can
tell that svcdoctor saw something it deliberately declined to read.

## 5. Outcome mapping

| Condition | Sentinel | State | FailureClass | Owner step |
|---|---|---|---|---|
| credential refused (403) | — | FAIL | `AUTH_CREDENTIALS_REJECTED` | `rabbitmq.authentication` |
| PLAIN not offered | — | UNKNOWN | `AUTH_MECHANISM_NOT_OFFERED` | `rabbitmq.authentication` |
| only unimplemented mechanisms offered | — | UNKNOWN | `AUTH_MECHANISM_UNSUPPORTED` | `rabbitmq.authentication` |
| credential not configured | — | SKIPPED | `EXEC_REQUIRED_INPUT_MISSING` | `rabbitmq.authentication` |
| credential withheld by policy | — | SKIPPED | `EXEC_SKIPPED_BY_POLICY` | `rabbitmq.authentication` |
| vhost not found | `VHOST_NOT_FOUND` | FAIL | **`RESOURCE_NOT_FOUND`** (§6.1) | `rabbitmq.connection_open` |
| vhost access refused | `VHOST_ACCESS_REFUSED` | FAIL | `AUTHZ_DENIED` | `rabbitmq.connection_open` |
| node / vhost / user connection limit | `NODE_` / `VHOST_` / `USER_CONNECTION_LIMIT` | FAIL | **`RESOURCE_LIMIT_REACHED`** (§6) | `rabbitmq.connection_open` |
| vhost down (541) | `VHOST_DOWN` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` (§6.2) | `rabbitmq.connection_open` |
| unmatched or truncated 530 | `UNSPECIFIED` / `UNSPECIFIED_TRUNCATED` | FAIL | `AUTHZ_NOT_PERMITTED` | `rabbitmq.connection_open` |
| peer closed during handshake | — | FAIL | `PROTOCOL_PEER_CLOSED` | the step awaiting a frame |
| malformed frame or bound violation | — | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | the step awaiting a frame |
| local timeout | — | UNKNOWN | `EXEC_LOCAL_TIMEOUT` | the step awaiting a frame; run **incomplete**, exit 4 |

A local timeout is UNKNOWN and incomplete, never a target-side FAIL. RabbitMQ makes that
distinction sharper than usual: several of its refusal paths hold the socket open for a
deliberate three seconds before closing, so a per-step timeout below that would report a
broker's deliberate delay as svcdoctor's own budget expiring. ADR 0070 §8 fixes the
floor.

## 6. `RESOURCE_LIMIT_REACHED` — one new class, and the bar it had to clear

`internal/adapter/postgres/establish.go` had already written down the condition under
which such a class should exist, while declining to create one:

> "A connection-limit refusal is a real operational fact and a different remedy from
> anything else here, and it still gets no class of its own: **one producer and no
> authorizing record is not enough** to grow a service-neutral vocabulary."

Both halves are now satisfied. RabbitMQ enforces three separate ceilings and Phase 8.0C
reproduced all three live on 4.2.0, which makes **four producers across two services**;
this record is the authorizing record. That sentence was a standing reopen condition, and
it fired.

The class is also more truthful than the one it replaces. Every existing candidate is
wrong about something:

- `AUTHZ_NOT_PERMITTED` says the peer refused "on the basis of who is connecting and from
  where, without evaluating any authentication material" — and here authentication
  succeeded first, and a node-wide ceiling is about neither.
- `AUTHZ_DENIED` says an identity was denied an operation — true of the wording, false of
  the cause, and it sends a reader to a permissions table for a capacity problem.
- `PROTOCOL_UNEXPECTED_RESPONSE` says the peer answered "not as the protocol expects" —
  and a `Connection.Close(530)` is a defined error path that is exactly what the protocol
  expects. The peer is working.

**The three RabbitMQ ceilings share the class.** The class explains the kind of break;
the `FindingCode` and the sentinel attribute explain which ceiling. That is the division
this repository already keeps.

### 6.1 PostgreSQL `53300` migrates onto it, and the pairing is not optional

`sessionSQLStateFailure` now returns `FailureResourceLimitReached` for `53300`. Nothing
else about `53300` moved: the finding is still `POSTGRES_SESSION_ESTABLISHMENT_FAILED`,
the severity is unchanged, the Phase 7.3A detail sentence is unchanged, and
`floorDetail`'s unattributable sentence was already suppressed for it by
`namedConditions` and stays suppressed.

**Two services classifying the identical condition differently would be worse than either
choice alone.** So the migration is part of this decision rather than a follow-up, and it
is permitted by the PostgreSQL feature freeze, which allows correctness fixes.

Only `sessionSQLStateFailure` changed. `sqlStateFailure` (startup) and
`authSQLStateFailure` (authentication) are untouched: PostgreSQL's connection-slot check
runs after authentication, that is where Phase 7.3A measured it, and svcdoctor keeps one
classifier per protocol step deliberately (ADR 0039 §7.1).

A refusal that merely *might* be a ceiling does not reach this class. It requires the
peer to have named the condition — which `53300` does and a generic code does not.

### 6.2 `RESOURCE_UNAVAILABLE` is rejected

A `541` vhost-down refusal is not a capacity ceiling, so it does not belong in the new
class. It also does not justify a second one: one producer, one service, and **not live
measured** — Phase 8.0C spent three bounded attempts and 27 probes on the
`restart_vhost` window without observing it.

It maps to `PROTOCOL_UNEXPECTED_RESPONSE` with the `VHOST_DOWN` sentinel recorded as an
attribute. Template T7 is **SOURCE-ONLY**, and §8 gates what may be said about it.

### 6.3 `VHOST_NOT_FOUND` needs a doc amendment, and this record makes it

`FailureResourceNotFound`'s documentation requires that "the peer asserted the absence
with a code whose own meaning is absence". `530 NOT_ALLOWED` is not such a code.

**This record narrowly amends that clause** to read: *asserted the absence with a code
whose own meaning is absence, or with a normalized peer statement of absence that
svcdoctor reconstructed from its own input and matched exactly.*

The amendment **raises** the evidentiary bar rather than lowering it. The numeric code is
emitted for six conditions here; the reconstructed string is emitted for exactly one, and
matching it requires svcdoctor to have predicted the peer's sentence byte for byte.
Construct-and-compare is stronger evidence than the code it supplements.

The finding must render it as peer attribution — *"the endpoint reported that this
virtual host was not found"* — never as *"this virtual host does not exist"*. That is the
`53300` treatment: the peer named it; svcdoctor is not inferring it.

## 7. Finding vocabulary

Eleven codes. Every one reuses an existing generic `FailureClass`; the RabbitMQ-specific
knowledge lives in the code and the detail.

| Code | Kind | Severity | Owner step |
|---|---|---|---|
| `RABBITMQ_CONNECTION_START_NOT_COMPLETED` | CONFIRMED | ERROR | `rabbitmq.connection_start` |
| `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIALS_REJECTED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_AUTHENTICATION_NOT_COMPLETED` | CONFIRMED | ERROR | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIAL_NOT_CONFIGURED` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_CREDENTIAL_WITHHELD` | CONFIRMED | WARN | `rabbitmq.authentication` |
| `RABBITMQ_VHOST_NOT_FOUND` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_VHOST_ACCESS_REFUSED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_CONNECTION_NOT_PERMITTED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |
| `RABBITMQ_CONNECTION_NOT_ESTABLISHED` | CONFIRMED | ERROR | `rabbitmq.connection_open` |

Generic transport findings — `DNS_*`, `TCP_CONNECTION_NOT_ESTABLISHED`, `TLS_*` — are
unchanged and are not duplicated here.

`RABBITMQ_CREDENTIAL_NOT_CONFIGURED` follows the `POSTGRES_CREDENTIAL_NOT_CONFIGURED`
precedent exactly: WARN, `SummaryStatus` OK, run complete, exit 0, and no session. A
renderer must show all three facts separately.

**No `HYPOTHESIS` finding is authorized.** ADR 0068 §4.1 records why the one candidate was
dropped.

### 7.1 There is no RabbitMQ peer-verification finding, and there cannot be

**Corrected in Phase 8.2-R1.** This table listed a twelfth code,
`RABBITMQ_PEER_VERIFICATION_FAILED`, owned by `tls.handshake`. It was struck,
because implementation proved it unproducible and because the row conflated two
layers.

`AUTH_PEER_VERIFICATION_FAILED` means the *peer* failed to prove its own
knowledge of the authentication material, in a mechanism where **both parties
authenticate**. Its only two producers in this repository are inside SCRAM paths
— `internal/adapter/postgres/authenticate.go` and
`internal/adapter/kafka/saslauthenticate.go` — and `internal/diagnosis/postgres`
records why: it is reachable only after the endpoint has *accepted* svcdoctor's
material, because a peer that rejects the proof never sends a signature at all.

**SASL PLAIN is not mutual.** It authenticates the client to the broker and the
broker returns no reciprocal proof, so there is nothing to verify and nothing
that can fail. ADR 0068 §2 freezes PLAIN as the only mechanism, so no RabbitMQ
BASIC execution can reach that class.

The owner step was wrong in the same row. TLS trust and identity failures are
owned by `internal/diagnosis/transport` and the five `TLS_*` codes ADR 0053
froze, at the `tls.handshake` node, for every service. Redis is the precedent and
it agrees: it authenticates with a non-mutual `AUTH`, has no
`REDIS_PEER_VERIFICATION_FAILED`, and its composition wires the generic TLS rule.
**RabbitMQ does the same and adds no service-specific TLS finding.**

A regression guard in `internal/diagnosis/rabbitmq` fails the build if a
RabbitMQ-specific peer-verification code is declared, or if any RabbitMQ producer
maps a PLAIN authentication outcome to `AUTH_PEER_VERIFICATION_FAILED`.

## 8. What may not be said

| Observation | What would have to exist first |
|---|---|
| RabbitMQ version X | a supported-version policy svcdoctor owns, plus a maintained EOL table with a refresh obligation |
| `heartbeat`, `frame_max`, `channel_max` | an operator-supplied expectation; svcdoctor has no basis for a "good" value |
| TLS enabled or disabled | already settled — ADR 0060 projects verification state and says explicitly that it is not a finding |
| `cluster_name`, node name, `product` | an expected-identity input; until then these are identity facts and `cluster_name` is redacted (ADR 0037) |
| `ANONYMOUS` offered | a posture contract; BASIC diagnoses reachability, not hardening |
| one endpoint reached | it is already the terminal PASS; promoting it would be ADR 0067 §5.1's overclaim |
| **`VHOST_DOWN`** | **a live measurement.** Until one exists, the sentinel may be recorded as an attribute and must not produce a restating detail sentence. This is `namedConditions`' rule — membership requires having watched a real endpoint produce it — applied before the table exists. |
| **backend-qualified denial (T3)** | it is SOURCE-ONLY. It may classify, because it only ever reaches a conclusion T2 already supports; it may not produce a distinct sentence. |

## 9. Reopen conditions

1. **A template stops matching.** The measured strings were byte-identical across
   RabbitMQ 3.13.7, 4.0.9, 4.2.0 and `main`, but they are not a published contract. A
   mismatch degrades to `UNSPECIFIED` by construction; re-freezing a template requires a
   new measurement, never a source reading.
2. **`541` is measured.** Then T7 may gain a detail sentence, and only then may a
   dedicated class be argued for.
3. **A third service produces a capacity ceiling.** Redis answers `-ERR max number of
   clients reached` and currently folds it into `REDIS_ENDPOINT_NOT_SERVING`; migrating it
   onto `RESOURCE_LIMIT_REACHED` is a separate, allowed correctness fix and is not done
   here.
4. **Text classification is rejected on review.** The fallback is `AUTHZ_NOT_PERMITTED`
   for every 530 with the distinction carried only by `FindingCode` — which preserves the
   operator-visible difference and costs only class precision. It is recorded so that
   reversing this decision does not require redesigning §7.
