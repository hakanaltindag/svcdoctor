# ADR 0036: A PostgreSQL session is one connection, and it is usable only at ReadyForQuery

## Status

Accepted (policy). Implemented by Phase 4.2 onwards; Phase 4.0 writes no Go code.

Depends on ADR 0037, which must land first: this record produces evidence carrying a role
name and a database name, and the report cannot pseudonymize either today.

## Problem

Phase 3 delivered a Kafka vertical slice and proved the architecture. PostgreSQL is the
second service, and the obvious failure mode is to model it on Kafka. PostgreSQL is not
shaped like Kafka in three ways that matter, and each of them would corrupt the evidence
model if it were assumed away:

1. **TLS is negotiated by the application protocol.** Kafka's TLS begins the moment TCP is
   established. PostgreSQL sends an 8-byte `SSLRequest`, reads one byte, and only then
   hands the same socket to TLS. The transport chain has no way to express that today.
2. **Authentication succeeding does not mean the endpoint is usable.** Kafka's
   `SaslAuthenticate` success is the end of the authentication question. PostgreSQL's
   `AuthenticationOk` is followed by a window in which the connection still fails, and two
   of the most useful diagnoses live in that window.
3. **The protocol requires disclosing a role name before it says anything.** Kafka's
   `ApiVersions` and `SaslHandshake` carry no identity. PostgreSQL's `StartupMessage`
   requires `user`, and there is no anonymous startup.

`docs/validation/POSTGRES_PHASE4_PROTOCOL_STUDY.md` establishes the protocol behaviour
this record decides against. Every empirical claim below is cited from it.

## Decision

### 1. The whole session is one TCP connection, and svcdoctor never redials

`SSLRequest → TLS → StartupMessage → authentication → ReadyForQuery` happens on exactly
one socket, the one the TCP probe measured and the DNS probe produced an address for.

This is stronger than the Kafka case and it is the protocol's rule, not a preference. The
server's `S` byte is a promise about *that* socket: it then waits for a TLS `ClientHello`
on it and will accept nothing else. There is no point in the sequence at which a fresh
connection could be substituted without discarding everything measured so far.

Ownership follows ADR 0021 unchanged, with one new transfer in the middle:

```text
transport.Run(TLS: nil)  →  Continuation owns the socket
  Continuation.TakeConn() →  the PostgreSQL adapter owns it
    SSLRequest, one byte  →  still the adapter's
      tls.Handshake(conn) →  the TLS probe owns it, in every outcome
        Result.TakeConn() →  the adapter owns the TLS connection
          Startup … ReadyForQuery
            Session.Close()
```

A failure at any step closes the socket there. `Terminate` (`X`) is sent before closing a
session that reached `ReadyForQuery`, because a server that is told the client is leaving
does not log a lost connection, and svcdoctor should not make noise in the log of the
system it is diagnosing.

**No implementation may exist in which the TCP probe measured socket A and the protocol
spoke over socket B.** The graph asserts causation along its parent edges, and a redial
would make every one of those edges a lie.

### 2. `SSLRequest` is always sent, and it is the identity-free capability probe

Whatever TLS plan the caller chose, the adapter sends `SSLRequest` first.

It costs 8 bytes, discloses nothing — no role, no database, no version — and answers three
questions at once (study §7):

- **is this peer speaking the PostgreSQL startup protocol?** Only `S`, `N` and `E` are
  valid answers. An `nginx` on the port answers `H`.
- **will this connection be encrypted?** `S` or `N`, positively, as a recorded fact.
- **is a man in the middle stuffing the socket?** Any byte readable after the single
  response byte is CVE-2021-23222, and the adapter reads exactly one byte and treats a
  surplus as a protocol violation.

Sending it unconditionally is what makes *"this connection was not encrypted"* a node in
the graph rather than an absence. That matters beyond PostgreSQL: **it supplies the
blocker carrier ADR 0030 recorded as missing** — a plaintext credential-transport refusal
can now point at a node that positively records why the channel was insufficient, instead
of having no blocker to name.

An `E` response is read, its SQLSTATE recorded, and the connection closed. Its message
text is discarded without being stored or rendered, because the server is unauthenticated
at that moment (CVE-2024-10977).

### 3. TLS is performed by the generic TLS probe, on the connection the adapter hands it

The adapter sequences; it does not handshake. `internal/probe/tls.Handshake` already takes
an established `net.Conn`, never dials, and owns the connection unconditionally — it is
tested today over connections its own tests create, entirely outside the transport chain.
That is exactly the seam PostgreSQL needs, and it needs no new abstraction.

The evidence node is `tls.handshake` at L3, unchanged, minting the same identifier the
transport chain would. **What differs is its parent**: for Kafka it is the TCP node, for
PostgreSQL it is the `postgres.ssl_request` node. That is honest — the handshake happened
because the server answered `S` — and it keeps the graph's parent edges meaning
derivation.

There is **no generic STARTTLS abstraction**. One protocol needs this, `TLSOptions`
presence in the transport chain remains the request for immediate TLS, and a service-
neutral hook shaped like PostgreSQL's negotiation would be a guess about a second caller
that does not exist. `docs/ARCHITECTURE.md`'s rule stands: concrete first.

#### 3.1 One consequence that must be paid before Phase 4.4

`security.Channel` constants are confined by `forbidigo` to `internal/probe/transport`,
because ADR 0029 gave the layer that established the connection sole authority to say what
it proved. The PostgreSQL adapter performs the handshake through the TLS probe and the
transport chain never sees it, so no layer can currently classify that channel.

The fix is a **narrowing, not a widening**: `probe/tls.Result` gains `Channel()`, derived
from the handshake it just performed and the connection it still owns, and
`transport.channelOf` is replaced by a call to it. Authority moves from "the chain that
orchestrated" to "the probe that handshook", which is the stricter of the two readings and
the one ADR 0029's own justification actually argues for. The adapter names no constant:
it propagates `Continuation.Channel()` on a plaintext path and `tls.Result.Channel()` on a
TLS one.

This is Phase 4.1 work and amends ADR 0029's exclusion list. It is recorded here rather
than deferred quietly, because Phase 4.4 cannot send a credential without it.

### 4. `sslmode` is not reproduced, and there is no fallback

svcdoctor takes an explicit TLS plan, exactly as the transport chain does. Two values:

| Plan | Behaviour |
|---|---|
| `require` | `SSLRequest`; `S` → handshake and continue; `N` → the run stops at L3 with a recorded failure |
| `disable` | `SSLRequest` is still sent and its answer recorded; the session then continues in plaintext regardless |

Certificate verification and trust source are the TLS probe's existing parameters, so
`verify-ca` and `verify-full` are already expressible and are not separate modes here.

**`prefer` is refused, and this is the decision most worth defending.** Under `prefer`, a
TLS failure is followed by a successful plaintext connection, and the run reports success.
The failures it would swallow are precisely the ones a diagnostic tool exists to find: an
expired certificate, an untrusted CA, a hostname mismatch, a TLS version floor. libpq
falls back because it wants a session; svcdoctor wants an explanation, and the two goals
point in opposite directions here. The repository already made this call one layer down —
`tls.Params.InsecureSkipVerify` "is never an automatic fallback after a verification
failure" — and falling back from TLS to plaintext is the same mistake with a larger blast
radius.

A run that genuinely wants both answers gets them honestly: two sweeps under two
`probe.SweepScope` labels (ADR 0032), two complete sets of evidence, no fallback semantics
and no hidden preference. The primitive exists; nothing here blocks it, and no phase
implements it yet.

### 5. Success is `ReadyForQuery`. `AuthenticationOk` is not enough, and this is measured

Model B, and the measurement is unambiguous (study §3, §4):

```text
AuthenticationOk  →  ErrorResponse 3D000  "database … does not exist"     →  EOF
AuthenticationOk  →  ErrorResponse 42501  "permission denied for database" →  EOF
```

Both are common, both are useful, and both would be reported as success by a model that
stopped at `AuthenticationOk`. Also in that window: `53300 too_many_connections` and
`57P03 cannot_connect_now` (a server still in recovery).

**What `ReadyForQuery` proves.** A backend process exists and is attached to the requested
database; the role authenticated and is permitted to connect; the server is past startup
and idle; the transaction status byte says which.

**What it does not prove.** That any table exists or that the role may read one; that the
server is a primary; that the session is writable; that replication is healthy; that a
connection pool has capacity for a second session; and — see §10 — that the responder is
genuinely PostgreSQL rather than something speaking enough of the protocol.

### 6. `ErrorResponse`: SQLSTATE and severity are kept, prose is destroyed

Fields are classified once, here, and the classification is fail-closed.

| Field | Classification | Kept |
|---|---|---|
| `C` SQLSTATE | stable, machine-readable, non-localizable, always present | **yes**, as `postgres.sqlstate` |
| `V` severity, non-localized | fixed vocabulary, no identity, absent from non-PostgreSQL backends | **yes**, value and presence |
| `S` severity | same content, localized | no — `V` is the same fact without a locale |
| `M` message | **carries the role, the database, and svcdoctor's own source address as the server sees it** | **never** |
| `D` detail, `H` hint | free prose, no guarantee about content | **never** |
| `P`, `p`, `q`, `W` | query text and positions; svcdoctor sends no query | never |
| `s`, `t`, `c`, `d`, `n` | schema, table, column, type, constraint names — internal identity | never |
| `F`, `L`, `R` | PostgreSQL source file, line and routine | never — version-unstable implementation detail |

`M` is the one that forces the rule. Study §4.2 records a real message containing
`192.168.65.1` — svcdoctor's NAT-translated source address as observed by the server, an
address that appears **nowhere else in the report**. `internal/security/redaction`
pseudonymizes values it collected from the report; a value that entered only through
server prose cannot be collected, so no amount of prose replacement makes `M` safe. It is
not stored, not logged, not rendered, and not carried in an error.

**Diagnosis is driven by SQLSTATE and by protocol position, never by English text.** That
is not a stylistic preference: the same English message is emitted for two different causes
(§7), and a different one is emitted for the same cause behind a pooler (§10).

### 7. What svcdoctor can and cannot distinguish

Established by measurement, not by reading the source.

| Distinction | Reliable? | Why |
|---|---|---|
| refused before any credential was evaluated (`28000`) vs. credential refused (`28P01`) | **yes** | different SQLSTATE, and `28000` arrives with no `AuthenticationXXX` ever sent |
| wrong password vs. role does not exist | **no** | identical SQLSTATE, identical message template, identical source location. PostgreSQL issues a fake SCRAM salt for a missing role on purpose |
| `pg_hba` has no matching entry vs. an explicit `reject` line matched | **no** | both are `28000`; only the English text differs |
| database does not exist (`3D000`) vs. `CONNECT` revoked (`42501`) | **yes** | different SQLSTATE, both post-`AuthenticationOk` |
| protocol version unsupported (`0A000`) | **yes** | distinct SQLSTATE, pre-authentication |
| server does not offer TLS | **yes** | the `N` byte, positively |
| the peer is genuinely PostgreSQL | **partially** | see §10 |

svcdoctor states the claim the evidence supports and no larger one. "The server refused
the credential presented for this role" is true; "the password is wrong" is not
established, and the finding's discriminator will say so.

### 8. Evidence graph

Five steps. Layers are monotonically non-decreasing along every parent edge, which is what
ADR 0007 requires of short-circuiting and first-broken-layer reporting.

| Step | Layer | Subject | Parent | Owns an exchange |
|---|---|---|---|---|
| `dns.lookup` | L1 | host | — | yes (generic) |
| `tcp.connect` | L2 | address | `dns.lookup` | yes (generic) |
| `postgres.ssl_request` | **L3** | address | `tcp.connect` | yes |
| `tls.handshake` | L3 | address | `postgres.ssl_request` | yes (generic) |
| `postgres.startup` | **L4** | address | `tls.handshake`, else `postgres.ssl_request` | yes |
| `postgres.authentication` | **L5** | address | `postgres.startup` | yes, when a credential is sent |
| `postgres.session` | **L5** | address | `postgres.authentication` | no — it reads to `ReadyForQuery` |

**Why `postgres.ssl_request` is L3 and not L4.** It is a PostgreSQL message, so L4 is
tempting. It is rejected because its consequence is a TLS decision and its failure is a
TLS-layer problem: a server answering `N` to a run that requires TLS sends the reader to
`ssl = on`, not to anything protocol-shaped. Placing it at L4 would also invert layer order
along a parent edge — an L3 `tls.handshake` deriving from an L4 node — and would make
`firstBrokenLayer` report L4 for what is a TLS availability failure. The repository's own
prior direction agrees: `.claude/skills/postgres-future-boundary/SKILL.md` already groups
"TLS / SSLRequest" together and "Startup / protocol negotiation" at L4.

**Why `postgres.startup` and `postgres.session` are separate from `postgres.authentication`.**
The `StartupMessage` is one atomic act that both negotiates a protocol version and declares
an identity; splitting it would fabricate two exchanges where the wire has one. Its node
therefore passes when the peer answered as a PostgreSQL backend at all, and fails only on
`0A000` or an undecodable reply. Everything the server decides afterwards is an L5
question, and `postgres.session` exists because the window between `AuthenticationOk` and
`ReadyForQuery` is where three distinct failures live and none of them is authentication.

**Why two steps share L5.** Because `kafka.sasl_handshake` and `kafka.sasl_authenticate`
already do. A layer says where in the ladder a step sits, not what taxonomy its failure
belongs to.

#### 8.1 The graphs

Healthy, TLS + SCRAM:

```text
dns.lookup            PASS
└── tcp.connect       PASS
    └── postgres.ssl_request  PASS   offered=true
        └── tls.handshake     PASS   verified=true
            └── postgres.startup      PASS  auth_method=sasl, mechanisms=[…PLUS, …]
                └── postgres.authentication PASS
                    └── postgres.session    PASS  ready=true, tx_status=I
```

Healthy plaintext, `trust` authentication — note that `postgres.authentication` is a real
PASS with no credential involved:

```text
        postgres.ssl_request  PASS   offered=false
        └── postgres.startup          PASS  auth_method=ok
            └── postgres.authentication PASS  (server demanded nothing)
                └── postgres.session    PASS
```

TLS required but unavailable:

```text
        postgres.ssl_request  FAIL   PROTOCOL_UNSUPPORTED_CAPABILITY   offered=false
        ├── tls.handshake             SKIPPED  EXEC_SKIPPED_PREREQUISITE_FAILED  blockedBy ssl_request
        ├── postgres.startup          SKIPPED  EXEC_SKIPPED_PREREQUISITE_FAILED  blockedBy ssl_request
        ├── postgres.authentication   SKIPPED  …                                  blockedBy ssl_request
        └── postgres.session          SKIPPED  …                                  blockedBy ssl_request
```

TLS hostname mismatch — the generic probe already owns this and PostgreSQL adds nothing:

```text
        postgres.ssl_request  PASS
        └── tls.handshake     FAIL  TLS_HOSTNAME_MISMATCH
            └── postgres.startup … SKIPPED, blockedBy tls.handshake
```

Startup rejected, unsupported protocol version:

```text
            postgres.startup          FAIL  PROTOCOL_UNSUPPORTED_VERSION  sqlstate=0A000
            └── postgres.authentication SKIPPED, blockedBy startup
                └── postgres.session    SKIPPED, blockedBy startup
```

`pg_hba` rejection — no `AuthenticationXXX` was ever sent, so the authentication node is
where it lands and no credential left the process:

```text
            postgres.startup          PASS
            └── postgres.authentication FAIL  AUTHZ_NOT_PERMITTED  sqlstate=28000
                └── postgres.session    SKIPPED, blockedBy authentication
```

Credential refused — indistinguishable from an unknown role, and the evidence says only
what happened:

```text
            └── postgres.authentication FAIL  AUTH_CREDENTIALS_REJECTED  sqlstate=28P01
                └── postgres.session    SKIPPED, blockedBy authentication
```

Unknown database, and `CONNECT` revoked — the two cases that make `postgres.session` exist:

```text
            └── postgres.authentication PASS
                └── postgres.session    FAIL  RESOURCE_NOT_FOUND  sqlstate=3D000
            └── postgres.authentication PASS
                └── postgres.session    FAIL  AUTHZ_DENIED        sqlstate=42501
```

Credential-transport policy refusal — the node the refusal points at is the one §2 exists
to produce:

```text
        postgres.ssl_request  PASS   offered=false
        └── postgres.startup          PASS  auth_method=sasl
            └── postgres.authentication SKIPPED  EXEC_SKIPPED_BY_POLICY  blockedBy ssl_request
                └── postgres.session    SKIPPED  EXEC_SKIPPED_PREREQUISITE_FAILED
```

Mechanism svcdoctor cannot perform — a gap in the tool, never a target failure, so
`UNKNOWN` rather than `FAIL`:

```text
            postgres.startup          PASS  auth_method=gss
            └── postgres.authentication UNKNOWN  EXEC_UNSUPPORTED_BY_SVCDOCTOR
                └── postgres.session    SKIPPED, blockedBy authentication
```

### 9. Attributes, and what may never become one

Recorded, with the identity classification ADR 0037 introduces:

| Attribute | Kind | Notes |
|---|---|---|
| `postgres.ssl.offered` | bool | the `S`/`N` answer, positively |
| `postgres.sqlstate` | string | five characters, no identity |
| `postgres.error_severity` | string | `V` only, fixed vocabulary |
| `postgres.error_is_native` | bool | whether `V` was present at all (§10) |
| `postgres.protocol_version` | string | what was requested and what was negotiated |
| `postgres.auth_method` | string | `ok`, `cleartext`, `md5`, `sasl`, `gss`, `sspi`, `kerberos` |
| `postgres.sasl_mechanisms` | stringList | as advertised; channel-dependent (study §5) |
| `postgres.role` | **identity** | ADR 0037 |
| `postgres.database` | **identity** | ADR 0037 |
| `postgres.server_version` | string | from `ParameterStatus` |
| `postgres.in_hot_standby` | bool | from `ParameterStatus` |
| `postgres.default_transaction_read_only` | bool | from `ParameterStatus` |
| `postgres.is_superuser` | bool | from `ParameterStatus` |
| `postgres.ready` / `postgres.transaction_status` | bool / string | the `Z` message |

**`ParameterStatus` is recorded from a fixed allowlist, never wholesale.** The server sends
whatever it likes, and two of the values it actually sends are identity: `session_authorization`
is the role and `search_path` contains `"$user"` and schema names. An adapter that copied
every parameter would leak by default, which is the wrong failure direction. Anything not
on the list is dropped.

Never an attribute, under any circumstances: the password, any SCRAM intermediate
(`SaltedPassword`, `ClientKey`, `StoredKey`, the client proof), the server's SCRAM salt or
nonce, the client private key, `BackendKeyData`'s secret, and any `ErrorResponse` field
other than `C` and `V`.

### 10. svcdoctor never claims to have reached PostgreSQL

Study §6 is the falsifying result of this phase. Through pgBouncer, every SQLSTATE
distinction in §7 collapses to `08P01 protocol_violation`: wrong password, unknown role and
unknown database become one code and three English sentences.

Two consequences, both binding:

- **A rule keyed on `28P01` must not assume it fires.** Behind a pooler it never will, and
  the evidence honestly records `AUTH_CREDENTIALS_REJECTED` with `sqlstate=08P01`, because
  the peer did refuse the material it was presented. The model degrades to a weaker true
  claim instead of producing a false one.
- **The wording of every finding says "this endpoint", never "PostgreSQL".** svcdoctor
  established a PostgreSQL session at an endpoint. Whether a real backend is behind it is a
  separate question, and `postgres.error_is_native` — the presence of the `V` field every
  genuine backend has sent since 9.6, and which pgBouncer omits — is the one structural,
  non-prose, non-identity signal available. It is recorded as a fact and is not yet read by
  any rule.

No pgBouncer-specific diagnosis is added. What is added is the discipline not to say more
than the wire proved.

### 11. Managed PostgreSQL is the *best* supported case, not the hardest

Reasoned, not measured (study §10).

| | Works with this design | Why |
|---|---|---|
| RDS PostgreSQL | yes | standard protocol; TLS always available; the CA bundle is a `RootCAs` pool the caller assembles, which `tls.Params` already takes and this repository never loads from disk |
| Aurora PostgreSQL | yes | same; the writer/reader cluster endpoints are DNS names whose targets change on failover, and sweeping every resolved address is already what the transport chain does. `in_hot_standby` says for free which one was reached |
| Cloud SQL | yes, directly | IAM database authentication supplies an OAuth token *as the password*, which `security.Secret` carries with no new mechanism. Through the Auth Proxy, §10 applies |
| Azure Database for PostgreSQL | yes | Flexible Server is standard and requires TLS |

All four force TLS, which means the fail-closed credential-transport policy of §12.2 is
*satisfied* there. The restricted case is self-hosted plaintext, which inverts the usual
expectation and is worth stating plainly.

### 12. What Phase 4 deliberately is not

**No SQL is executed.** `SELECT 1` adds nothing about connectivity that `ReadyForQuery`
does not already prove, and the semantic facts worth having — `server_version`,
`in_hot_standby`, `default_transaction_read_only`, `is_superuser` — arrive free in
`ParameterStatus` on every supported version (study §5). `pg_is_in_recovery()` is therefore
not deferred for lack of appetite; it is **unnecessary**, because the same fact is already
in hand. Executing statements is also the first step onto a road `docs/SCOPE.md` closes:
arbitrary SQL, schema checks, tuning advice.

**Primary/replica is recorded, not diagnosed.** `postgres.in_hot_standby` is a fact on the
session node. Concluding anything about topology, replication lag, failover or Patroni from
it is a later phase, and nothing here blocks one: the fact is present, the endpoint is
already the subject, and a topology sweep would use `probe.SweepScope` exactly as Kafka's
does.

Also excluded and recorded as future capability areas rather than gaps: pgBouncer-specific
diagnosis, HAProxy, CloudNativePG, Kubernetes discovery, cloud provider APIs, replication
slots, WAL inspection, connection-pool analysis, backup and migration checks, extensions.

#### 12.1 Compatibility floor

**PostgreSQL 14.** Protocol 3.0 is requested, which every server in the window accepts
without a negotiation round trip. `in_hot_standby` — the fact that makes §12's no-SQL
decision work — arrived in 14, and 14 is the oldest release in community support. No
version branching is implemented; `server_version` is recorded as a fact.

MD5 is observed and reported. Whether svcdoctor *performs* MD5 authentication is Phase 4.4's
decision: it is trivial to implement and still widely deployed, but it would be a credential
mechanism weaker than the channel it rides on.

#### 12.2 The credential restriction Phase 4 inherits, stated plainly

`security.CredentialTransportPolicy` has exactly one value, `RequireVerifiedTLS`. A
PostgreSQL password therefore crosses only a verified-TLS channel, and a plaintext
endpoint with password authentication produces `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` with
zero credential bytes sent.

This bites harder for PostgreSQL than it did for Kafka, because plaintext PostgreSQL is the
ordinary shape of a development or internal-network deployment. It is the correct
fail-closed default and it already has a named owner: ADR 0029 defers the explicit,
per-run, recorded unsafe-transport override to the layer that can carry one, which is
Phase 5. **Phase 4 does not build that override**, and this is the largest practical
limitation of the first slice.

What still works on a plaintext endpoint: DNS, TCP, `SSLRequest`, `Startup`, the observed
authentication method and mechanism list, and — for `trust` authentication — a complete
session through to `ReadyForQuery`, because no credential is written.

The role name and database name are **not** gated by that policy. They are user-supplied
targeting parameters of the same kind as the hostname, which svcdoctor already puts in a
DNS query and an SNI extension in the clear, and refusing to send them would make plaintext
PostgreSQL undiagnosable. The disclosure is not hidden: `postgres.ssl_request` records that
the channel was unencrypted, on the same path, as a node.

### 13. The client library: the wire protocol is implemented directly

No new dependency. `internal/adapter/postgres/wire` encodes and decodes the messages this
model needs, and computes SCRAM-SHA-256 with `crypto/hmac`, `crypto/sha256` and
`crypto/pbkdf2` from the standard library.

Evaluated against the requirement that svcdoctor be able to say *"this exact connection
reached step X and failed at step Y"*:

| | Direct | `pgx/v5/pgconn` | `pgx/v5/pgproto3` |
|---|---|---|---|
| Same-connection ownership | total | dialer is injectable, but TLS and fallback are not | total |
| No automatic retry or fallback | yes | **no** — `sslmode` fallback and multi-host failover are its core behaviour | yes |
| Exact protocol-step evidence | yes | transitions are internal | yes |
| Inspect raw `ErrorResponse` | yes | yes | yes |
| SCRAM | hand-written | provided | **not provided** — lives in `pgconn` |
| Dependency footprint | **zero** | whole `pgx/v5` module | whole `pgx/v5` module |

`pgproto3` is the honest analogue of `kmsg`, and ADR 0008 chose `kmsg` for exactly this
reason. It fails on two counts that `kmsg` passes. It is **not a separate module** —
verified: importing it alone pulls `github.com/jackc/pgx/v5` plus `pgpassfile`,
`pgservicefile`, `puddle/v2`, `golang.org/x/text` and `golang.org/x/sync`, against `kmsg`'s
zero transitive requirements. And it does not implement SCRAM, so the one genuinely
intricate piece would be hand-written either way.

The surface being hand-written is small and was fully exercised during this phase: an
8-byte `SSLRequest`, a `StartupMessage` of key/value pairs, a 5-byte typed header, and
decoders for `R`, `E`, `N`, `S`, `K`, `Z` and `v`. The extended query protocol is not
implemented because §12 executes no SQL.

`internal/adapter/postgres/wire` is the second package permitted to call `security.Reveal`,
under the existing `forbidigo` exclusion for `internal/adapter/*/wire/`. SCRAM changes the
shape of that call but not the boundary: the revealed password is consumed by PBKDF2 inside
the wire package, the plaintext never goes on the socket, and no derived value leaves the
package either.

### 14. Timeouts, cancellation, and disconnects

Following the TLS probe exactly, because the reasoning transfers unchanged.

| Observation | State | Class |
|---|---|---|
| the caller's deadline expired mid-step | UNKNOWN | `EXEC_LOCAL_TIMEOUT` |
| the caller cancelled | UNKNOWN | `EXEC_CANCELLED` |
| the peer closed the connection mid-exchange, with no `ErrorResponse` | FAIL | `PROTOCOL_PEER_CLOSED` |
| a reply that cannot be decoded as a protocol message | FAIL | `PROTOCOL_MALFORMED_RESPONSE` |
| a reply that decodes but is not what the protocol allows here | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| a byte other than `S`, `N`, `E` in answer to `SSLRequest` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| extra readable bytes after the `S` byte | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |

A local deadline is never a remote failure, and a step that did not run is `SKIPPED` with
`EXEC_SKIPPED_PREREQUISITE_FAILED`, `blockedBy` the node that did not deliver. **A finding
resting on an `UNKNOWN` node may be `HYPOTHESIS` and never `CONFIRMED`**, which is ADR 0034
§7 applied unchanged.

The `EOF` that follows an `ErrorResponse` is not a second failure. PostgreSQL always closes
after a fatal error; the `ErrorResponse` is the fact and the close is its consequence.

A connection reset mid-protocol is recorded as `PROTOCOL_PEER_CLOSED` rather than
`TCP_CONNECTION_RESET`, because the node that owns the exchange is a protocol node and the
weaker class is the honest one. The TCP classes stay with the TCP probe.

### 15. Subject, and why the database is not part of it

Every PostgreSQL node's subject is **the address the socket reached** — `SubjectKindEndpoint`,
identical to the `tcp.connect` and `tls.handshake` nodes on the same path.

The database does **not** change the subject. It is a parameter of the session, not a
network resource, and putting it in the subject would break the correlation the whole
report depends on: the L1–L3 nodes know nothing about a database, so the same socket would
carry two different subjects and no reader could line them up. It would also push an
identity-bearing, non-host value into the one field structural redaction pseudonymizes as
a host, which would render a database as `host-002`.

Role and database are attributes of the nodes that used them, declared identity-bearing
(§9, ADR 0037). One endpoint that accepts database A and rejects database B is one subject
with two runs, or one subject with different protocol evidence — never two resources.

### 16. FailureClass: reuse almost everything, add exactly two

Reused unchanged, and they cover most of the model: every DNS, TCP and TLS class,
`PROTOCOL_UNSUPPORTED_VERSION`, `PROTOCOL_UNSUPPORTED_CAPABILITY`,
`PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_PEER_CLOSED`,
`AUTH_MECHANISM_UNSUPPORTED`, `AUTH_CREDENTIALS_REJECTED`, `AUTHZ_DENIED`, and the whole
execution and policy group.

Two are added, each because the existing vocabulary collapses a distinction that leads to a
different action. Both are service-neutral; neither names PostgreSQL.

**`AUTHZ_NOT_PERMITTED`** — the peer refused the connection on the basis of who is
connecting and from where, without evaluating any credential.

`AUTH_CREDENTIALS_REJECTED` says the peer refused the material it was presented, and no
material was presented here — no `AuthenticationXXX` message was ever sent (study §4.1).
`AUTHZ_DENIED` says the identity authenticated and was denied an operation, and nothing
authenticated. The distinction is worth a class because *"your password is wrong"* and
*"you may not attempt this from here"* send the reader to completely different places:
one to a secret store, the other to `pg_hba.conf` or a security group. Kafka and Redis have
the same shape of refusal, so the class earns its generality.

**`RESOURCE_NOT_FOUND`** — the named resource a step targets does not exist.

`3D000` is not an authorization failure and not a protocol failure. `StateFail` requires a
class, the failure is positively evidenced, and no existing member is honest. Kafka's
`UNKNOWN_TOPIC_OR_PARTITION` is the same shape.

Everything else PostgreSQL-specific stays an **attribute**: SQLSTATE, severity, auth method,
mechanism list, protocol version. `FailureClass` does not grow a member per SQLSTATE, and
`docs/ARCHITECTURE.md` section 12's four load-bearing distinctions are untouched.

### 17. Findings: candidates only. This record authorizes none

Following the 0033 → 0034 precedent — evidence first, a policy ADR second, rules third —
Phase 4 produces evidence and defers every finding to a diagnosis-policy ADR written
against real graphs. What is settled now is the analysis each candidate must survive.

| Candidate | Anchored at | Kind | Vantage-dependent | Credential-dependent |
|---|---|---|---|---|
| `POSTGRES_TLS_NOT_OFFERED` | `postgres.ssl_request` FAIL | CONFIRMED | **no** — `ssl` is server-global | no |
| `POSTGRES_CONNECTION_NOT_PERMITTED` | `postgres.authentication` `28000` | CONFIRMED | **yes** — `pg_hba` matches the source address; the server's own message names it | partly (role and database also match) |
| `POSTGRES_CREDENTIALS_REJECTED` | `postgres.authentication` `28P01` | CONFIRMED | **no** — a credential is refused from everywhere | **yes** |
| `POSTGRES_DATABASE_NOT_FOUND` | `postgres.session` `3D000` | CONFIRMED | no | no |
| `POSTGRES_DATABASE_ACCESS_DENIED` | `postgres.session` `42501` | CONFIRMED | no | yes (the role) |
| `POSTGRES_AUTH_MECHANISM_UNSUPPORTED` | `postgres.authentication` UNKNOWN | CONFIRMED, INFO | no | no — a gap in svcdoctor |
| `POSTGRES_CREDENTIAL_TRANSPORT_REFUSED` | `postgres.authentication` SKIPPED | CONFIRMED, INFO | no | no — svcdoctor's own policy |
| `POSTGRES_PROTOCOL_VERSION_UNSUPPORTED` | `postgres.startup` `0A000` | CONFIRMED | no | no |

Two observations that the policy ADR must carry:

**Vantage dependence and credential dependence are different axes, and the report model has
one flag.** `28P01` is credential-dependent and vantage-independent; `28000` is both. A
finding states credential dependence in its **discriminator** rather than in a field. No
field is added: one service is not evidence for a schema change, and the reopen condition
is a second service needing the same distinction.

**`POSTGRES_CREDENTIALS_REJECTED` must not name a cause.** Its discriminator says, in
words, that the evidence does not separate a wrong password from a role that does not
exist, because study §3.1 proves it cannot.

### 18. Generic transport findings stay unowned, and PostgreSQL does not reopen the question

If DNS, TCP or TLS fails, PostgreSQL produces `SKIPPED` nodes and no finding, exactly as
Kafka does. ADR 0034's move — that ADR 0017's severity blocker dissolves for a rule
**anchored at a service fact** — does not transfer to the path the user typed, and ADR 0034
§14 explicitly left the bootstrap path's owner open. **This record leaves it open too.**

Concretely: `svcdoctor postgres` against a refused port produces a correct report with a
clear first broken layer and zero findings. That is honest and it is thin, and it is the
same thinness Kafka has. Closing it is a Phase 5 question about who owns the transport
claim for a user-supplied target, and it needs the orchestration layer that knows what was
requested.

### 19. Dependency direction

```text
internal/domain
   ↑              ↑
internal/service/postgres        internal/security
   ↑              ↑                     ↑
internal/diagnosis/postgres    internal/adapter/postgres
                                        ↑
                               internal/adapter/postgres/wire
```

`internal/adapter/postgres` also imports `internal/probe/transport` and
`internal/probe/tls`, which is what §3 requires and what `internal/adapter/kafka` already
does for the transport chain.

`internal/service/postgres` follows the ADR 0034 §19 precedent exactly: a leaf holding the
step names and the attribute keys a rule genuinely reads, and nothing else — no interface,
no registry, no protocol logic, no state. `depguard`'s existing
`service-vocabulary-is-a-leaf` rule already governs it with no edit. It is created by the
phase that writes the first rule, not before, because a vocabulary invented ahead of its
second consumer is a guess about what that consumer needs.

## Consequences

- The first PostgreSQL slice is a real diagnostic product, not a port checker: it separates
  "no TLS here", "refused before your credential was read", "credential refused", "that
  database does not exist" and "you may not connect to it", each anchored at the exact
  protocol position that proved it.
- **ADR 0037 becomes a prerequisite.** No PostgreSQL evidence node can be produced safely
  until the report can pseudonymize a role and a database name.
- ADR 0029's channel authority is narrowed from the transport chain to the TLS probe
  (§3.1), and the `forbidigo` exclusion list changes with it. No layer gains the ability to
  name a channel that did not perform the handshake.
- Two generic `FailureClass` members are added, and `docs/REPORT_SCHEMA.md` gains them.
- ADR 0030's missing blocker carrier is supplied: a plaintext credential refusal can point
  at `postgres.ssl_request`.
- svcdoctor gains a second `security.Reveal` call site, in a wire package, under the
  existing lint boundary.
- No new generic abstraction is created. No STARTTLS interface, no adapter interface, no
  registry, no `Origin`.
- The default credential-transport policy leaves plaintext password authentication
  undiagnosable beyond L4 until Phase 5 builds the recorded per-run override.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Success at `AuthenticationOk` | Measured false: `3D000` and `42501` both arrive after it | Never; the protocol says otherwise |
| Success requires `SELECT 1` | Adds nothing over `ReadyForQuery`, and the semantic facts it would chase already arrive in `ParameterStatus` | A check genuinely needs the query path, e.g. a permission probe |
| Reproduce libpq `sslmode=prefer` | Fallback hides expired certificates, untrusted CAs and hostname mismatches — the failures the tool exists to find | Never as a fallback; two scoped sweeps give both answers honestly |
| A generic STARTTLS abstraction in `internal/probe/transport` | One caller. A service-neutral hook shaped like PostgreSQL's negotiation is a guess | A second protocol negotiates TLS in-band |
| Let the adapter dial and handshake itself | Architecture violation; the protocol would speak over an unmeasured socket | Never |
| Use `pgx/pgconn` | Owns `sslmode` fallback and multi-host failover — automatic redial and automatic fallback, both rejected by ADR 0008 | Never for the diagnostic path |
| Use `pgx/v5/pgproto3` as the `kmsg` analogue | Not a separate module: pulls the whole `pgx/v5` module and five transitive requirements, and still does not provide SCRAM | The hand-written message surface outgrows a small package |
| `postgres.ssl_request` at L4 | Inverts layer order along a parent edge and reports L4 for a TLS availability failure | Never |
| Database in the evidence subject | Breaks correlation with the L1–L3 nodes on the same socket, and would be pseudonymized as a hostname | Never |
| Record every `ParameterStatus` | `session_authorization` is the role and `search_path` carries schema names; the default would leak | Never; extend the allowlist deliberately |
| Keep `ErrorResponse` `M`/`D`/`H` for prose | `M` carries the role, the database and svcdoctor's own NAT source address, which redaction structurally cannot catch | Never |
| Claim "wrong password" from `28P01` | Byte-identical to an unknown role, by PostgreSQL's design | Never |
| A `credentialDependent` field on `Finding` | One service is not evidence for a schema change; the discriminator carries it | A second service needs the same distinction |
| A `FailureClass` per SQLSTATE | The enum dump `docs/ARCHITECTURE.md` forbids; SQLSTATE is an attribute | Never |
| pgBouncer-specific diagnosis | Out of scope, and the useful part is a discipline rather than a feature | A pooler-aware phase with real demand |

## Reopen conditions

- **A second in-band TLS negotiation** — MySQL, or PostgreSQL's own `GSSENCRequest` —
  would make the generic STARTTLS abstraction rejected in §3 worth reconsidering, with two
  real implementations to extract it from.
- **A layer that can carry an explicit, recorded, per-run transport decision** reopens
  §12.2 and ADR 0029's deferred override together. That is the single change that would
  make plaintext PostgreSQL fully diagnosable.
- **A second service needing credential dependence as a field** reopens §17.
- **A real report in which `AUTHZ_NOT_PERMITTED` or `RESOURCE_NOT_FOUND` reads wrong**
  reopens §16. Both are new vocabulary and neither has met a user.
- **A protocol 3.2-only capability worth having** reopens the version choice in §12.1;
  today 3.0 costs nothing and 3.2 buys nothing svcdoctor uses.
- **Demand for topology or HA** reopens §12's replica decision. Nothing here blocks it:
  `in_hot_standby` is already recorded and `probe.SweepScope` already exists.
- **A pooler that omits `V` while a genuine backend also does**, or the reverse, would
  invalidate the one structural native-backend signal in §10.
