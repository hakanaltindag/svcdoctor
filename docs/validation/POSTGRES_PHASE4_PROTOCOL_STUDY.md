# PostgreSQL protocol study — Phase 4.0 discovery

What the PostgreSQL wire protocol actually does, established against real servers rather
than from the documentation alone. ADR 0036 and ADR 0037 are the decisions this study
produced; this file is the evidence behind them.

Nothing here is production code. The probe used to obtain these transcripts was a
throwaway experiment outside the repository and was deleted afterwards; every claim below
is reproducible from the recipes in section 9.

## 1. Environment

| | |
|---|---|
| Servers | PostgreSQL **18.6** and **14.24**, official `postgres:*-alpine` images |
| Proxy | **pgBouncer 1.25.2** (`edoburu/pgbouncer`), transaction pooling, `auth_type=scram-sha-256` |
| Non-PostgreSQL peer | `nginx:alpine` on port 80, as a negative control |
| TLS | throwaway self-signed certificate, `CN=pg-canary.svcdoctor.test`, `SAN=DNS:pg-canary.svcdoctor.test,DNS:localhost` |
| Runtime | Docker 28.3.2, linux/arm64 |
| Probe | ~250 lines of Go over `net.Conn`, stdlib only, including SCRAM-SHA-256 via `crypto/pbkdf2` |
| Documentation checked | `protocol-flow`, `protocol-message-formats`, `protocol-error-fields`, `errcodes-appendix` (current) |

`pg_hba.conf` used for the failure matrix:

```text
local   all all       trust
host    all blocked   all  reject
hostssl all tlsonly   all  scram-sha-256
host    all md5user   all  md5
host    all app       all  scram-sha-256
hostssl all app       all  scram-sha-256
host    all norights  all  scram-sha-256
hostssl all norights  all  scram-sha-256
```

## 2. The verified state machine

Every transition below was observed, not inferred. `→` is one server message.

```text
TCP established
   │
   ├─ SSLRequest  (Int32(8), Int32(80877103) — 8 bytes, carries no identity at all)
   │     │
   │     ├─ 'S'  server will do TLS ── TLS handshake on the SAME socket ──┐
   │     ├─ 'N'  server will not do TLS ───────────────────────────────────┤
   │     ├─ 'E'  ErrorResponse; connection must be closed, message must    │
   │     │       NOT be shown to the user (CVE-2024-10977)                 │
   │     └─ any other byte  →  the peer does not speak this protocol       │
   │                                                                       │
   │        (extra readable bytes after 'S' = buffer-stuffing, CVE-2021-23222)
   │                                                                       │
   └───────────────────────────────────────────────────────────────────────┘
   │
   ├─ StartupMessage  (protocol version + `user`, optional `database`, …)
   │        `user` is REQUIRED; there is no anonymous startup
   │     │
   │     ├─ ErrorResponse 0A000  unsupported protocol major version
   │     ├─ ErrorResponse 28000  pg_hba: no entry, or explicit reject
   │     ├─ NegotiateProtocolVersion  server offers an older minor version, then continues
   │     └─ AuthenticationXXX  the server names the method it demands
   │           │
   │           ├─ 0  AuthenticationOk         (no exchange needed — `trust`)
   │           ├─ 3  CleartextPassword
   │           ├─ 5  MD5Password + 4-byte salt
   │           ├─ 10 SASL + mechanism list    ← list is channel-dependent, see §5
   │           ├─ 7/9/8  GSS / SSPI / GSSContinue
   │           └─ 2  KerberosV5 (no longer supported)
   │                 │
   │                 ├─ ErrorResponse 28P01  credential refused
   │                 └─ AuthenticationOk
   │                       │
   │                       ├─ ErrorResponse 3D000  database does not exist
   │                       ├─ ErrorResponse 42501  no CONNECT privilege
   │                       ├─ ErrorResponse 53300 / 57P03  …
   │                       └─ ParameterStatus* , BackendKeyData? , ReadyForQuery
   │                                                                  ▲
   └──────────────────────────────────────────────── the session is usable here
```

**`AuthenticationOk` is not the success boundary.** Two distinct, common failures arrive
*after* it and before `ReadyForQuery`. This is the single most important result of the
study and it is what fixes the success boundary at `ReadyForQuery` (ADR 0036 §5).

## 3. Transcript: PostgreSQL 18.6, plaintext listener, SCRAM

```text
=== healthy: valid user + valid db (proto 3.0) ===
  SSLRequest -> 'N'  (extra buffered bytes: 0)
  <- R AuthenticationSASL mechanisms=[SCRAM-SHA-256]
  <- R AuthenticationSASLContinue (84 bytes)
  <- R AuthenticationSASLFinal (46 bytes)
  <- R AuthenticationOk
  <- S ParameterStatus [in_hot_standby off]
  <- S ParameterStatus [default_transaction_read_only off]
  <- S ParameterStatus [is_superuser on]
  <- S ParameterStatus [session_authorization app]
  <- S ParameterStatus [search_path "$user", public]
  <- S ParameterStatus [server_version 18.6]
  … (15 ParameterStatus messages in total)
  <- K BackendKeyData pid=73 keylen=4
  <- Z ReadyForQuery status='I'

=== wrong password ===
  <- R AuthenticationSASLContinue (84 bytes)
  <- E ErrorResponse S="FATAL" V="FATAL" C="28P01"
       M="password authentication failed for user \"app\""
       F="auth.c" L="317" R="auth_failed"
  <- CONNECTION END: EOF

=== unknown role ===
  <- R AuthenticationSASLContinue (84 bytes)
  <- E ErrorResponse S="FATAL" V="FATAL" C="28P01"
       M="password authentication failed for user \"ghost\""
       F="auth.c" L="317" R="auth_failed"
  <- CONNECTION END: EOF

=== unknown database (valid creds) ===
  <- R AuthenticationOk
  <- E ErrorResponse S="FATAL" V="FATAL" C="3D000"
       M="database \"nosuchdb\" does not exist"
       F="postinit.c" L="1014" R="InitPostgres"
  <- CONNECTION END: EOF

=== future protocol version 4.0 ===
  SSLRequest -> 'N'
  <- E ErrorResponse S="FATAL" V="FATAL" C="0A000"
       M="unsupported frontend protocol 4.0: server supports 3.0 to 3.2"
       F="backend_startup.c" L="731" R="ProcessStartupPacket"
  <- CONNECTION END: EOF
```

### 3.1 Wrong password and unknown role are byte-identical

Not merely similar: same SQLSTATE, same message template, same source file, same line,
same routine. The only difference is the username the client itself supplied. PostgreSQL
does this deliberately — it issues a fake SCRAM salt for a role that does not exist — so
that a client cannot enumerate roles.

**svcdoctor therefore cannot distinguish "wrong password" from "role does not exist", and
must never claim to.** The honest claim is the one the server made: the credential
presented for this role was refused.

## 4. Transcript: TLS listener and pg_hba matrix (PostgreSQL 18.6)

```text
=== TLS: SSLRequest -> S -> handshake -> app/appdb ===
  SSLRequest -> 'S'  (extra buffered bytes: 0)
  TLS handshake OK version=0x0304 certs=1
  <- R AuthenticationSASL mechanisms=[SCRAM-SHA-256-PLUS SCRAM-SHA-256]
  … → Z ReadyForQuery status='I'

=== plaintext: tlsonly/appdb  (hostssl-only role) ===
  <- E ErrorResponse S="FATAL" V="FATAL" C="28000"
       M="no pg_hba.conf entry for host \"192.168.65.1\", user \"tlsonly\",
          database \"appdb\", no encryption"
       F="auth.c" L="530" R="ClientAuthentication"

=== plaintext: blocked/appdb  (pg_hba reject) ===
  <- E ErrorResponse S="FATAL" V="FATAL" C="28000"
       M="pg_hba.conf rejects connection for host \"192.168.65.1\", user \"blocked\",
          database \"appdb\", no encryption"
       F="auth.c" L="462" R="ClientAuthentication"

=== plaintext: md5user/appdb ===
  <- R AuthenticationMD5Password salt=a82b966b

=== TLS: norights/closeddb (CONNECT revoked) ===
  <- R AuthenticationOk
  <- E ErrorResponse S="FATAL" V="FATAL" C="42501"
       M="permission denied for database \"closeddb\""
       D="User does not have CONNECT privilege."
       F="postinit.c" L="375" R="CheckMyDatabase"
```

### 4.1 `28000` and `28P01` are a real, reliable distinction

`28000` is returned before any authentication material is requested or evaluated —
no `AuthenticationXXX` message is ever sent. `28P01` is returned after the client's
credential was evaluated. Those are different facts with different remediations
(edit `pg_hba.conf` or the network path, versus fix the credential), and the SQLSTATE
carries the distinction without touching prose.

Separating *"no matching entry"* from *"an explicit `reject` line matched"* requires the
English message or the `F`/`L`/`R` source fields, and svcdoctor does neither.

### 4.2 The `M` field leaks three separate identity classes

`M="no pg_hba.conf entry for host \"192.168.65.1\", user \"tlsonly\", database \"appdb\", no encryption"`
contains, in one string:

1. the **username** the client supplied,
2. the **database name** the client supplied,
3. **svcdoctor's own source address as the server observed it** — here `192.168.65.1`,
   the Docker NAT address, which is not any address in the report.

The third is the important one. `internal/security/redaction` pseudonymizes values it
collected from elsewhere in the report; a NAT-translated source address appears nowhere
else, so no collect-and-replace mechanism can catch it. **Raw `M` cannot be made safe.**
See ADR 0036 §6.

## 5. Facts that are free, and facts that need a query

`AuthenticationSASL` advertises `SCRAM-SHA-256-PLUS` **only over TLS** and plain
`SCRAM-SHA-256` otherwise. The mechanism list is therefore evidence about the channel as
well as the server.

`ParameterStatus` arrives before `ReadyForQuery` and, on both 14.24 and 18.6, already
carries:

| Parameter | What it answers | Safe to record |
|---|---|---|
| `server_version` | which PostgreSQL this is | yes |
| `in_hot_standby` | primary or replica | yes |
| `default_transaction_read_only` | is the session read-only | yes |
| `is_superuser` | privilege of the supplied role | yes |
| `server_encoding`, `integer_datetimes`, `standard_conforming_strings`, `scram_iterations` | server configuration | yes |
| `session_authorization` | **the username** | no — identity |
| `search_path` | contains `"$user"` and schema names | no — identity |
| `application_name` | svcdoctor's own value, echoed | no value |

**`SELECT pg_is_in_recovery()` and `SHOW transaction_read_only` are unnecessary.**
`in_hot_standby` and `default_transaction_read_only` are the same facts, delivered without
executing a single statement, on every version in the support window. This is why ADR 0036
executes no SQL.

## 6. pgBouncer collapses the error vocabulary — the falsifying result

The same five scenarios, through pgBouncer 1.25.2 in front of the same PostgreSQL 18.6:

```text
=== pgbouncer: SSLRequest + app/appdb ===
  SSLRequest -> 'N'
  <- R AuthenticationSASL mechanisms=[SCRAM-SHA-256]
  … → Z ReadyForQuery status='I'   (BackendKeyData pid=1415742519 — synthetic)

=== pgbouncer: wrong password ===
  <- E ErrorResponse S="FATAL" C="08P01" M="SASL authentication failed"

=== pgbouncer: unknown role ===
  <- E ErrorResponse S="FATAL" C="08P01" M="SASL authentication failed"

=== pgbouncer: unknown database via pool ===
  <- E ErrorResponse S="FATAL" C="08P01" M="no such database: nosuchdb"

=== pgbouncer: future protocol 4.0 ===
  <- E ErrorResponse S="FATAL" C="08P01" M="bad packet header: '0000002100040000'"
```

Every distinction collapses into `08P01 protocol_violation`. A rule keyed on `28P01`
produces **nothing** behind a pooler; a rule keyed on the English message would be doing
exactly what this project forbids.

There is, however, a structural signal. **pgBouncer omits the `V` field** — the
non-localized severity that every genuine PostgreSQL backend has sent since 9.6 — and
omits `F`, `L` and `R` with it. `V` present is a one-bit, non-prose, non-identity
indicator that the responder is a genuine PostgreSQL backend rather than something
speaking enough of the protocol to establish a session.

This result is what stops svcdoctor from ever saying "I reached PostgreSQL". The truthful
claim is "I established a PostgreSQL session at this endpoint", plus the recorded
SQLSTATE, plus whether the error carried `V`.

## 7. Negative control: a peer that is not PostgreSQL

```text
=== non-PostgreSQL peer: SSLRequest to nginx ===
  SSLRequest -> 'H'  (extra buffered bytes: 308)
```

The first byte is `H` (the start of `HTTP/1.1 …`), and 308 further bytes were already
readable. Both halves of the CVE-2021-23222 check fire. An 8-byte `SSLRequest` therefore
answers three questions at once, **while disclosing no identity whatsoever**:

- does this peer speak the PostgreSQL startup protocol,
- will it encrypt this connection,
- is something stuffing the socket ahead of the TLS handshake.

That is what makes it the correct identity-free capability probe, and the reason ADR 0036
sends it unconditionally.

## 8. Version behaviour and the compatibility floor

| | 14.24 | 18.6 |
|---|---|---|
| `SSLRequest` → `N` on a plaintext listener | yes | yes |
| SCRAM-SHA-256 offered by default | yes | yes |
| `SCRAM-SHA-256-PLUS` offered over TLS | yes | yes |
| MD5 still accepted for an md5-hashed role | yes | yes |
| `in_hot_standby` in `ParameterStatus` | yes | yes |
| `default_transaction_read_only` in `ParameterStatus` | yes | yes |
| Protocol 3.0 accepted | yes | yes |
| Protocol 3.2 requested | `NegotiateProtocolVersion → 196608`, then continues | accepted; `BackendKeyData` grows 4 → 32 bytes |
| Protocol 4.0 requested | `0A000 "server supports 3.0 to 3.0"` | `0A000 "server supports 3.0 to 3.2"` |
| Wrong password / unknown role | identical `28P01` | identical `28P01` |
| Unknown database after `AuthenticationOk` | `3D000` | `3D000` |

`in_hot_standby` was added in PostgreSQL 14, which is what fixes the floor there. 14 is
also the oldest release still in community support during Phase 4.

**Requesting protocol 3.0 is the conservative choice** and is what ADR 0036 selects: every
server in the window accepts it with no negotiation round trip. Requesting 3.2 would make
an older server volunteer its highest supported minor version, which is real diagnostic
information; that is recorded as a later capability question, not a first-slice one.

## 9. Reproduction recipes

Plaintext server:

```sh
docker run -d --name pgx-plain \
  -e POSTGRES_USER=app -e POSTGRES_PASSWORD=s3cr3t-canary -e POSTGRES_DB=appdb \
  -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256" \
  -p 55432:5432 postgres:18-alpine
```

TLS server with the `pg_hba.conf` of section 1:

```sh
docker run -d --name pgx-tls … postgres:18-alpine \
  -c ssl=on -c ssl_cert_file=/etc/pg/server.crt -c ssl_key_file=/etc/pg/server.key \
  -c hba_file=/etc/pg/pg_hba.conf -c password_encryption=scram-sha-256
```

pgBouncer in front of it, `pool_mode=transaction`, `auth_type=scram-sha-256`.

The Phase 4.8 integration suite reproduces all of this under `make`, driving production
code paths rather than a throwaway probe. Its design is ADR 0036 §12.

## 10. What this study did not establish

Recorded so that a later phase does not assume it did.

- **GSSAPI and SSPI were not exercised.** Both are detect-and-explain only by scope.
- **`GSSENCRequest` was not exercised.** It is a second, parallel encryption negotiation
  with the same one-byte shape (`G` / `N` / `E`); svcdoctor does not send it.
- **Certificate authentication (`cert` in `pg_hba.conf`) was not exercised.** It needs
  client certificates, which the TLS probe does not yet load (ADR 0023).
- **No managed service was contacted.** RDS, Aurora, Cloud SQL and Azure compatibility in
  ADR 0036 §11 is reasoned from published behaviour, not measured.
- **Replication, failover and `Patroni` were not exercised**, deliberately — out of scope
  by ADR 0036 §13.
- **Connection-limit (`53300`) and `cannot_connect_now` (`57P03`) were not reproduced.**
  Both are documented post-`AuthenticationOk` failures and are named in the model on that
  basis; the integration matrix schedules them.
