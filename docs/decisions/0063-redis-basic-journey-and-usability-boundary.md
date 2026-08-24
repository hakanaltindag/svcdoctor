# ADR 0063: The Redis/Valkey BASIC journey, and what PING is allowed to prove

## Status

**Accepted in Phase 7.4. Not implemented.** No Go exists for it.

It decides the wire journey, the command allowlist, the protocol baseline and the usability
boundary for the first Redis/Valkey slice, before any adapter is written. Phase 7.5 implements
it and is expected to invent nothing.

`SchemaVersion` stays **1**. This record authorizes no `FindingCode`, no `FailureClass`, no
dependency, and no change to Kafka or PostgreSQL semantics. It adds three `Step` values, which
are additive exactly as `postgres.*` and `kafka.*` were.

Companion records: [0064](0064-credential-free-hello-before-redis-authentication.md) decides the
credential ordering this journey depends on,
[0065](0065-redis-cluster-observed-and-sentinel-detected.md) decides what happens when the
endpoint is a cluster node or a Sentinel, and
[0066](0066-redis-error-prefix-classification-and-observed-identity.md) decides how a reply that
is not `+PONG` is classified.

## 1. Context

Redis and Valkey have no session. PostgreSQL has `ReadyForQuery` and Kafka has an authenticated
connection that Metadata can be asked over; Redis has a socket on which commands either succeed
or do not. So the first question is not *how does svcdoctor connect* — the generic transport
chain already answers that — but **what is the smallest thing svcdoctor can execute that proves
something worth reporting, and exactly what does executing it prove.**

Everything else in this record follows from answering that precisely and refusing to answer it
generously.

Four facts were read out of `redis/redis@unstable` and `valkey-io/valkey@unstable` rather than
out of documentation, because the documentation does not state any of them:

| Fact | Source |
|---|---|
| `HELLO`, `AUTH` and `RESET` carry `CMD_NO_AUTH`, and `CMD_NO_AUTH` **skips the ACL command-permission check entirely** | `src/acl.c:1726`; `src/server.c:4586` |
| `PING` carries neither `CMD_NO_AUTH`, nor `CMD_LOADING`, nor `CMD_STALE` | `src/commands/ping.json`; gates at `src/server.c:4573`, `4575`, `4586`, `4604`, `4783` |
| `helloCommand` returns **before** `c->resp = ver` on the `NOAUTH` path | `src/networking.c:5089`-`5100` |
| A command with no key arguments is **never** cluster-redirected | `src/server.c:4609`-`4616` |

The first two decide which command is the usability proof. The third decides whether a second
`HELLO` is necessary. The fourth is 0065's, and is recorded there.

## 2. Decision

The BASIC journey is:

```text
requested target  (hostname | IPv4 literal | IPv6 literal)
  → DNS resolution                [omitted entirely for a literal — ADR 0059]
  → TCP connect
  → TLS handshake                 [when the plan requires it; ordinary out-of-band TLS]
  → HELLO                         [zero arguments]
  → Sentinel guard                [mode == "sentinel" ⇒ stop — ADR 0065]
  → AUTH [<username>] <password>  [at most once, policy-gated — ADR 0064]
  → HELLO                         [zero arguments; only when the first returned -NOAUTH
                                   and AUTH then succeeded]
  → PING
```

Maximum four commands, one connection, no re-dial, **RESP2 throughout**, and **no key is ever
named**.

The command allowlist is **`HELLO`, `AUTH`, `PING`** and nothing else. A command absent from that
list is forbidden, not merely unused.

## 3. `PING` is the usability proof, and the flag table is why

The candidates were `TCP + valid RESP`, `HELLO`, `AUTH`, `PING` and `ROLE`.

| Command | `no_auth` | `loading` | `stale` | ACL categories |
|---|---|---|---|---|
| `HELLO` | **yes** | yes | yes | `@fast @connection` |
| `AUTH` | **yes** | yes | yes | `@fast @connection` |
| `PING` | **no** | **no** | **no** | `@fast @connection` |
| `ROLE` | no | yes | yes | `@admin @fast @dangerous` |
| `INFO` | no | yes | yes | `@slow @dangerous` |

`PING` is the only keyless command gated simultaneously on **authentication**, **ACL
authorization**, **dataset-loading state** and **stale-replica state**. Every other candidate is
exempt from at least one, and `HELLO` is exempt from two of the four by protocol design.

The consequence that matters is not that `PING` is stricter. It is that **`HELLO` success carries
no authorization evidence at all** — `acl.c:1726` skips the command-permission check for
`CMD_NO_AUTH` commands, so a user whose ACL is `-@all` still gets `+OK` from `AUTH` and a full map
from `HELLO`. A journey that stopped at `HELLO` would report success for a principal that cannot
run a single command.

`TCP + valid RESP` was rejected because a protected-mode server, a TLS terminator, a proxy and a
Sentinel all produce valid RESP. Valid RESP proves that something speaking RESP is at this
address, and stops there.

## 4. What `+PONG` authorizes, exactly

> At `<timestamp>`, from `<vantage>`, a RESP client connected to `<endpoint>` at `<address>` over
> `<channel>`, authenticated as `<identity | no credential presented>`, issued `PING`, and the
> endpoint answered `PONG`.

Nothing more. The following are **forbidden** renderings, in any surface:

- "Redis is healthy", "Redis is up", "Redis is usable"
- "the backend is available"
- "the cluster is healthy"
- "replication is healthy"
- "your application will work"

The last is the one an operator will read in anyway, and it is the one the flag table forbids
most sharply: ACL authorization is per command and per key, and `PING` is one keyless command.

### It is endpoint-scoped, and the reason is measured elsewhere

Azure Managed Redis under its Enterprise clustering policy "routes all requests to a single Redis
node that acts as a proxy", and disabled commands there return `ERR unknown command`. Envoy
`redis_proxy`, twemproxy, Redis Enterprise generally and ElastiCache serverless have the same
shape. A proxy can answer `PING` while what is behind it cannot serve anything.

This is the pgBouncer lesson, and PostgreSQL BASIC already froze the answer: a passing session
node claims only that a session reached it *at this endpoint*, measured against a pooler serving
a complete passing session with its backend stopped. Redis inherits the wording, not a new
mechanism.

## 5. The step is named `redis.ping`

`redis.session` was rejected. PostgreSQL's `postgres.session` names a real protocol boundary;
Redis has none, and importing the word would let a renderer read a session concept into a
protocol that lacks one. Naming the step after the command makes the claim self-documenting and
makes "PING PONG called Redis healthy" a harder mutation to commit.

The cost is that a future `--probe-command` would make the name wrong. That is accepted: BASIC is
frozen without it, and its arrival is a recorded reopen condition below.

## 6. RESP2 only. RESP3 is not attempted

The parser must handle six RESP2 forms: `+`, `-`, `:`, `$` (including `$-1`), `*` (including
`*-1`). Nothing else.

RESP3 was seriously considered — modern clients default to it — and rejected for v1 on four
grounds:

1. **It buys no evidence.** `HELLO`'s reply carries the same fields in RESP2 as a flat array that
   it carries in RESP3 as a map. For a three-command journey there is nothing RESP3 tells us.
2. **It makes an entire hostile-frame class unreachable rather than merely handled.** RESP3 push
   frames (`>`) and attribute frames (`|`) may arrive at any time. On a connection that never
   sends `HELLO <protover>` and never subscribes, they cannot arrive at all. Refusing RESP3
   deletes the asynchronous-frame problem instead of defending against it.
3. **It removes the fallback ladder.** A `HELLO 3` journey needs a `-NOPROTO` branch and a
   `HELLO 2` retry, and a fallback ladder is precisely the mechanism by which an incompatibility
   gets hidden. With no ladder, "silent RESP3 fallback" is not a bug that can be written.
4. **It would be scope creep into client-compatibility diagnosis.** "Would a modern RESP3 client
   work here?" is a different product question from "how far did a client get from this vantage",
   and BASIC answers only the second.

On a RESP2 connection, a first byte of `%`, `~`, `>`, `|`, `#`, `,`, `(`, `=` or `_` is a
protocol violation: `PROTOCOL_MALFORMED_RESPONSE`, connection closed, nothing allocated.

## 7. `HELLO` carries zero arguments

No `protover`, no `AUTH`, no `SETNAME`. Three consequences, in descending order of importance:

- **The credential-echo defect becomes impossible rather than forbidden.** That argument belongs
  to [ADR 0064](0064-credential-free-hello-before-redis-authentication.md) and is not repeated
  here.
- **`-NOPROTO` becomes unreachable.** `networking.c:5036` only parses a protocol version when
  `argc >= 2`. There is no branch, no failure class and no test for a reply that cannot occur.
- **The invariant is byte-testable.** The frame is exactly `*1\r\n$5\r\nHELLO\r\n`, and a
  mutation that adds any argument fails on a literal comparison rather than on a reviewer's
  attention.

`SETNAME` was declined separately from `AUTH`, and for a different reason: it is not a security
defect, it is a *courtesy* — it puts `svcdoctor` in the operator's `CLIENT LIST`. It is worth
less than the zero-argument invariant is worth, and it is the only thing that would reopen the
argument surface. Deferred, not rejected.

## 8. The second `HELLO` is conditional, and its necessity is proven

It is issued **only** when the first `HELLO` returned `-NOAUTH` and `AUTH` then succeeded. In
every other case exactly one `HELLO` is sent.

The proof is `networking.c:5089`-`5100`:

```c
    /* At this point we need to be authenticated to continue. */
    if (!c->authenticated) {
        addReplyError(c,"-NOAUTH HELLO must be called with the client already "
                        "authenticated, ...");
        return;                       /* <- returns here */
    }
    ...
    if (ver) c->resp = ver;           /* <- protocol switch is below the return */
    addReplyMapLen(c,6 + !server.sentinel_mode);   /* <- so is the reply map */
```

So on a password-protected endpoint the first `HELLO` yields **no** identity, **no** `mode` and
**no** `role`, and no other allowlisted command yields them. Without the second `HELLO`, every
authenticated endpoint loses the Sentinel guard and the implementation identity. That is the
whole argument; it is not a convenience.

The second `HELLO` is a **second `redis.hello` node**, distinguished by `probe.SweepScope`
(ADR 0032, which exists for exactly "another one that measured the same endpoint and address in
the same run"). Evidence is immutable (ADR 0003), so the first node is never amended.

## 9. Per-reply outcomes

### First `HELLO`

| Reply | State | Meaning |
|---|---|---|
| map/array of fields | PASS | RESP is spoken; no authentication was required; identity, `mode`, `role` captured |
| `-NOAUTH` | UNKNOWN | RESP is spoken; **this endpoint requires authentication**. Identity unavailable until after `AUTH` |
| `-ERR unknown command` | UNKNOWN + `PROTOCOL_UNSUPPORTED_CAPABILITY` | Pre-6.0 server, or a proxy. `mode`, `role` and identity are **not measured**, and svcdoctor does not claim the endpoint is a Redis data server |
| `-DENIED` then close | FAIL + `PROTOCOL_PEER_CLOSED` | Protected mode, non-loopback, no password configured |
| `-NOPROTO` | unreachable | §7 |

### `PING`

| Reply | State | FailureClass | Summary | Incomplete | Exit |
|---|---|---|---|---|---|
| `+PONG` | PASS | none | OK | false | 0 |
| `-NOPERM` | **UNKNOWN** | `AUTHZ_DENIED` | OK, WARN finding | false | 0 |
| `-LOADING` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` + prefix attribute | OK, WARN | false | 0 |
| `-MASTERDOWN` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` + prefix attribute | OK, WARN | false | 0 |
| `-NOAUTH` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` + prefix attribute | OK | false | 0 |
| generic `-ERR` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` | OK | false | 0 |
| local timeout | UNKNOWN | `EXEC_LOCAL_TIMEOUT` | either | **true** | 4 |
| peer close | FAIL | `PROTOCOL_PEER_CLOSED` | PROBLEMS_FOUND | false | 1 |
| malformed frame | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | PROBLEMS_FOUND | false | 1 |

**`NOPERM` is UNKNOWN, not FAIL.** The service did not fail; svcdoctor's measurement was blocked.
That is the frozen rule that missing privilege is not healthy and not a FAIL, and it matches the
`POSTGRES_CREDENTIAL_NOT_CONFIGURED` precedent: WARN, status OK, complete run, exit 0.

**On `NOPERM`, svcdoctor does not try another command.** Not `ECHO`, not `ROLE`, not `INFO`. Each
attempt is another ACL-log entry and another guess, and it converts a clean authorization answer
into a shotgun. The restriction is reported.

`LOADING` and `MASTERDOWN` reaching the honest weak class rather than a class of their own
follows `internal/adapter/postgres/establish.go:420`-`441` exactly, where `53300` and `57P03` —
both real operational facts — land on `PROTOCOL_UNEXPECTED_RESPONSE` with the SQLSTATE recorded
beside them, on the stated ground that one producer and no authorizing record is not enough to
grow a service-neutral vocabulary.

## 10. `ROLE` and `INFO` are not in v1

`ROLE` is `@admin @fast @dangerous`, so a least-privilege application user is denied it; it is
documented **not supported** on Redis Software and Redis Cloud, and therefore on Azure Managed
Redis; it carries `loading` and `stale`, so it succeeds on a server that cannot serve data; and
its reply discloses every connected replica's IP and port, or the primary's. `HELLO` supplies
`role` with less privilege, no disclosure and no extra command.

`INFO` is `@slow @dangerous` and discloses `run_id`, `config_file`, `executable`, `os`,
`process_id` and peer addresses. There is a smaller command giving the identity BASIC needs, and
it is already in the journey. `INFO replication` is assurance and would create an expectation
svcdoctor will diagnose replication health.

## 11. Zero keyspace access

The frozen invariant is stronger than "no writes":

> **Redis BASIC names no key.** No write, no read, no `EXISTS`, no `TYPE`, no `SCAN`, no `KEYS`,
> no synthetic diagnostic key, no key-name disclosure.

It is achievable because the whole journey is keyless, and it is enforceable as a lint over a
three-command allowlist rather than as a semantic judgment per command.

| Command | Keyspace | Server state | Connection state | Logged on failure | Key names |
|---|---|---|---|---|---|
| `HELLO` (zero args) | none | none | none — the bare form never sets `c->resp` | no | no |
| `AUTH` | none | none | authentication state | **yes — ACL LOG** | no |
| `PING` | none | none | none | no | no |

Two side effects are unavoidable and are recorded rather than minimized: a failed `AUTH` writes
an ACL LOG entry and may increment provider-side metrics, and `AUTH` mutates the authentication
state of a connection svcdoctor opened and closes. `RESET` is excluded permanently — it would
make re-authentication expressible.

## 12. Graph shape

Three new steps, in `internal/service/redis/vocabulary.go`, following the existing convention.

| Step | Layer | Parent | Evidence owner | Failure owner |
|---|---|---|---|---|
| `redis.hello` | L4 | `tls.handshake` or `tcp.connect` (pre-auth); `redis.authentication` (post-auth) | `internal/adapter/redis` | `internal/diagnosis/redis` |
| `redis.authentication` | L5 | `redis.hello` (pre-auth) | `internal/adapter/redis` | `internal/diagnosis/redis` |
| `redis.ping` | L4/L5 boundary | the last successful protocol node on the connection | `internal/adapter/redis` | `internal/diagnosis/redis` |

**Protocol negotiation and authentication get separate nodes, non-negotiably.** They have
different owners and different failure classes, and — decisively — one is credential-free and the
other is not. Merging them would make "credential-free discovery preceded authentication"
unauditable in the graph, which is the entire security argument of ADR 0064.

Nine frozen shapes:

```text
1. hostname + plaintext + no auth
   target.requested → dns.lookup → tcp.connect → redis.hello(PASS) → redis.ping(PASS)
   No redis.authentication node: none was configured and none was requested.

2. hostname + TLS + auth
   … → tls.handshake(PASS) → redis.hello#1(UNKNOWN, NOAUTH)
     → redis.authentication(PASS) → redis.hello#2(PASS) → redis.ping(PASS)

3. IP literal + TLS + auth
   target.requested → tcp.connect → tls.handshake(PASS) → …as (2)
   NO dns.lookup node exists — structurally, not suppressed (ADR 0059).

4. auth rejected
   … → redis.authentication(FAIL, AUTH_CREDENTIALS_REJECTED)
     → redis.ping(SKIPPED, EXEC_SKIPPED_PREREQUISITE_FAILED)

5. ACL denied
   … → redis.authentication(PASS) → redis.hello#2(PASS)
     → redis.ping(UNKNOWN, AUTHZ_DENIED)

6. HELLO unsupported
   … → redis.hello#1(UNKNOWN, PROTOCOL_UNSUPPORTED_CAPABILITY)
     → redis.authentication(PASS) → redis.ping(PASS)
   No second HELLO. mode/role/identity are NOT MEASURED, and the report says so.

7. Sentinel detected
   … → redis.hello#1(PASS, redis.mode=sentinel)
     → redis.authentication(SKIPPED) → redis.ping(SKIPPED)

8. local timeout
   … → redis.ping(UNKNOWN, EXEC_LOCAL_TIMEOUT); Incomplete() = true; exit 4.

9. cluster-mode direct endpoint
   Structurally identical to (2), with redis.mode=cluster. No topology node.
```

`SchemaVersion` stays 1: no node shape, edge semantic, state or report field changes.

## 13. Summary and completeness

No new exit code and no Redis special case in `ExitCode`. The three product invariants frozen for
PostgreSQL bind unchanged:

- `SummaryStatus == OK` means no ERROR or CRITICAL target-side problem was **proven**. It does
  not mean `PING` was answered.
- A credential-withheld or credential-not-configured run is WARN + OK + complete + exit 0 with
  **no `redis.ping` PASS**, and a renderer must show all three facts separately.
- `Result.Incomplete()` is orthogonal to `SummaryStatus`. UNKNOWN is not FAIL.

## 14. Hostile-peer bounds: a strategy, not numbers

RESP is length-prefixed, and `proto-max-bulk-len` (`src/config.c:3470`, default 512 MB) bounds
what a server will *receive*. **There is no upstream bound on what a server may send a client**,
and no per-field number can be copied from anywhere.

ADR 0061 is the precedent and its lesson is explicit: the discredited rationale was "8× the
largest common value", falsified by a real Redpanda salt. So this record freezes a *shape*:

> **One bound: a total-bytes budget per command reply, enforced with strictly incremental
> allocation.** The parser never allocates on a *declared* length. It allocates as bytes arrive,
> decrementing a per-reply budget, and aborts the moment the budget is exhausted.

Depth, element count and per-field length are then bounded implicitly and exactly by the byte
budget, with no second number that can disagree with the first. This makes the safety property
independent of guessing well, so the budget can be generous and carry no interoperability risk.

**No numeric constant is authorized before a measurement exists.** Phase 7.5 sets exactly one
number, measured against the largest legitimate reply the three allowlisted commands can produce,
records the measurement, and pins it by value — as Phase 7.0b did for SCRAM.

## 15. Rejected alternatives

| Option | Rejected because |
|---|---|
| **Journey A** — TCP/TLS → AUTH → PING | No `mode`, so a Sentinel passes as a healthy Redis server. Also sends the credential before any capability discovery, inverting ADR 0007's layer order |
| **Journey B** — HELLO 3 → AUTH → PING | Broken on the auth-required path: `HELLO 3` returns `NOAUTH` and the protocol is **not** switched, so the run believes it negotiated RESP3 and did not |
| **Journey C** — HELLO 3 → AUTH → HELLO 3 → PING | Correct, but pays for RESP3 unconditionally and issues the second `HELLO` when it is not needed |
| **Journey D** — C + `HELLO 2` fallback + `SETNAME` | The largest surface of the four: a fallback ladder, an extra mutation class, an extra argument, and the full RESP3 type set |
| `ROLE` for role/mode evidence | `@admin @dangerous`, unsupported on Redis Enterprise, `loading`/`stale`-flagged, discloses peer addresses |
| `INFO server` for identity | `@dangerous`, and strictly larger than a command already in the journey |
| A synthetic diagnostic key to provoke a redirect | Breaks zero-keyspace-access for evidence obtainable keylessly later, and needs a key ACL a scoped user will not have |
| `redis.session` as the step name | Imports a concept the protocol does not have |
| Per-field RESP bounds chosen now | ADR 0061 §1's falsified premise, repeated |

## 16. Reopen conditions

- **svcdoctor makes a client-compatibility claim** — "would a modern RESP3 client work here?" —
  which would make RESP3 negotiation evidence rather than decoration. RESP3 arrives with the
  claim, not before it.
- **Validation shows `NOPERM` on `PING` is common**, which would justify `--probe-command` — and
  with it, a rename of `redis.ping`, argued in a new record.
- **Operators ask for `CLIENT LIST` attribution**, which would reopen `HELLO ... SETNAME` — and
  with it, the zero-argument invariant, which must then be re-expressed as "no credential in
  `HELLO`" and enforced by something weaker than a byte comparison.
- **A measured reply legitimately exceeds the byte budget Phase 7.5 sets**, which reopens §14 by
  ADR 0061 §27's conditions rather than by raising the number.
- **A Redis-compatible implementation is found whose `PING` is exempt from any of the four
  gates**, which would end `PING`'s claim to be the usability proof.
