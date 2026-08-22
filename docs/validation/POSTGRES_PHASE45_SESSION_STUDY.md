# PostgreSQL session establishment study — Phase 4.5a decision pass

What happens between `AuthenticationOk` and `ReadyForQuery`, measured frame by
frame against real servers. ADR 0039 is the decision this study produced; this
file is the evidence behind it.

Nothing here is production code. The probe was a throwaway experiment outside the
repository and was deleted afterwards. **No PostgreSQL session code was written in
Phase 4.5a**; the production `security.Reveal` count is unchanged at two and the
`FailureClass` count at 38.

## 1. Environment

| | |
|---|---|
| Servers | PostgreSQL **18.6** and **14.24**, official images |
| Standby | a real streaming replica of the 18.6 primary, built with `pg_basebackup -R -c fast` |
| Recovery server | a second replica with `hot_standby = off` |
| Proxy | **pgBouncer 1.25.2**, transaction pooling, `auth_type=scram-sha-256`, `auth_user` passthrough |
| Runtime | Docker 28.3.2, darwin/arm64 host |
| Probe | ~300 lines of Go over `net.Conn`, stdlib only, SCRAM-SHA-256 via `crypto/pbkdf2` |
| Protocol version | 3.0 (`196608`), which is what svcdoctor requests |

Roles: `app` (superuser), `plain` (ordinary), `norights` (no `CONNECT` on
`closeddb`), `rep` (replication). Databases: `appdb`, `closeddb` with `CONNECT`
revoked from `PUBLIC`. `max_connections = 10`,
`superuser_reserved_connections = 3`.

## 2. The healthy window, PostgreSQL 18.6

```text
  <- R AuthenticationSASLFinal (signature VERIFIED)
  <- R AuthenticationOk
  ---- post-AuthenticationOk frames, in order ----
  [ 1] S ParameterStatus  in_hot_standby                 = "off"
  [ 2] S ParameterStatus  integer_datetimes              = "on"
  [ 3] S ParameterStatus  TimeZone                       = "Etc/UTC"
  [ 4] S ParameterStatus  IntervalStyle                  = "postgres"
  [ 5] S ParameterStatus  search_path                    = "\"$user\", public"
  [ 6] S ParameterStatus  is_superuser                   = "on"
  [ 7] S ParameterStatus  application_name               = ""
  [ 8] S ParameterStatus  default_transaction_read_only  = "off"
  [ 9] S ParameterStatus  scram_iterations               = "4096"
  [10] S ParameterStatus  DateStyle                      = "ISO, MDY"
  [11] S ParameterStatus  standard_conforming_strings    = "on"
  [12] S ParameterStatus  session_authorization          = "app"
  [13] S ParameterStatus  client_encoding                = "UTF8"
  [14] S ParameterStatus  server_version                 = "18.6 (Debian 18.6-1.pgdg13+2)"
  [15] S ParameterStatus  server_encoding                = "UTF8"
  [16] K BackendKeyData    body=8 bytes  pid=115  secret=4 bytes
  [17] Z ReadyForQuery     transaction_status='I'
```

Fifteen parameters, then `BackendKeyData`, then `ReadyForQuery`. Nothing followed
`ReadyForQuery`.

## 3. Every post-authentication failure arrives as frame 1

```text
=== unknown database ===
  <- R AuthenticationOk
  [ 1] E ErrorResponse  S="FATAL" V="FATAL" C="3D000"
       M="database \"nosuchdb\" does not exist" F="postinit.c" L="1014" R="InitPostgres"
  ---- ParameterStatus seen before the error: 0 ----
  [--] after error: EOF

=== CONNECT revoked (norights -> closeddb) ===
  <- R AuthenticationOk
  [ 1] E ErrorResponse  S="FATAL" V="FATAL" C="42501"
       M="permission denied for database \"closeddb\""
       D="User does not have CONNECT privilege." F="postinit.c" L="375" R="CheckMyDatabase"
  ---- ParameterStatus seen before the error: 0 ----
  [--] after error: EOF

=== connection slots exhausted (10/10 held, non-superuser client) ===
  <- R AuthenticationOk
  [ 1] E ErrorResponse  S="FATAL" V="FATAL" C="53300"
       M="remaining connection slots are reserved for roles with the SUPERUSER attribute"
       F="postinit.c" L="942" R="InitPostgres"
  ---- ParameterStatus seen before the error: 0 ----
  [--] after error: EOF
```

**Zero `ParameterStatus` before the error, in all three cases.** On a genuine
backend the two are mutually exclusive: either the error arrives immediately, or
the whole parameter block does. The "partial parameters then failure" case is
therefore not natural — it requires a timeout mid-block or a scripted peer.

The peer closed immediately after each error; nothing was sent after it.

## 4. `57P03` is pre-authentication, not post

Reproduced with a replica configured `hot_standby = off`:

```text
=== standby with hot_standby=off ===
  <- E ErrorResponse (pre-auth)  S="FATAL" V="FATAL" C="57P03"
       M="the database system is not accepting connections"
       D="Hot standby mode is disabled."
       F="backend_startup.c" L="313" R="BackendInitialize"
```

No `AuthenticationSASL`, no `AuthenticationOk` — the refusal arrives from
`BackendInitialize`, before authentication is even requested. It is a
`postgres.startup` observation.

**This corrects ADR 0036 §5**, which listed `57P03` among the failures that arrive
"in that window" after `AuthenticationOk`. That placement was reasoned from the
documentation rather than measured.

## 5. `in_hot_standby` against a real standby, and the fact it does *not* imply

| | primary 18.6 | standby 18.6 |
|---|---|---|
| `in_hot_standby` | `off` | **`on`** |
| `default_transaction_read_only` | `off` | **`off`** |

Phase 4.0's claim that recovery state is available without SQL is **confirmed**.

The second row is the result worth having. A session on a standby is read-only
because of *recovery*, not because `default_transaction_read_only` is set — the
GUC is `off` on both. A rule that read only that parameter would call a replica
writable. The two are independent facts.

The session-local `transaction_read_only`, which is what actually reflects the
read-only state of a standby session, is **not** sent as a `ParameterStatus` at
all and would require SQL.

## 6. Version comparison: 14.24 sends thirteen, 18.6 sends fifteen

| Key | 14.24 | 18.6 |
|---|---|---|
| `application_name` | ✓ | ✓ |
| `client_encoding` | ✓ | ✓ |
| `DateStyle` | ✓ | ✓ |
| `default_transaction_read_only` | ✓ | ✓ |
| `in_hot_standby` | ✓ | ✓ |
| `integer_datetimes` | ✓ | ✓ |
| `IntervalStyle` | ✓ | ✓ |
| `is_superuser` | ✓ | ✓ |
| `server_encoding` | ✓ | ✓ |
| `server_version` | ✓ | ✓ |
| `session_authorization` | ✓ | ✓ |
| `standard_conforming_strings` | ✓ | ✓ |
| `TimeZone` | ✓ | ✓ |
| `search_path` | **✗** | ✓ |
| `scram_iterations` | **✗** | ✓ |
| **`server_version_num`** | **✗** | **✗** |

Two facts that change decisions:

- **`server_version_num` is sent by neither.** ADR 0036 §9 listed it as a
  candidate; it is not available. Only `server_version` is, and it carries the
  packaging string — `"18.6 (Debian 18.6-1.pgdg13+2)"`, `"14.24 (Debian
  14.24-1.pgdg13+2)"` — not a bare number.
- **`search_path` is 18.6-only**, so an allowlist that depended on it would behave
  differently across the support window. It is dropped as identity regardless.

`is_superuser` tracked the role correctly: `on` for `app`, `off` for `plain`.
`session_authorization` was the role name on every connection.

## 7. `ReadyForQuery`'s status byte

`'I'` on every path measured: 18.6, 14.24, primary, standby, superuser,
non-superuser, and through pgBouncer. No path produced `'T'` or `'E'`, which is
expected by construction — svcdoctor issues no command that could open a
transaction.

## 8. `BackendKeyData` under protocol 3.0

Eight bytes on both versions: a 32-bit process ID and a 32-bit secret key.

Observed process IDs: `115`, `141`, `163` on the direct 18.6 server — ordinary
backend PIDs. Through pgBouncer: `799998125` and `1172961953` on two connections
to the same server, which are synthetic values the pooler mints.

The secret is for `CancelRequest`. svcdoctor issues no statement, so there is
nothing to cancel.

## 9. pgBouncer: success, or a failure that never reaches this step

```text
=== healthy through pgBouncer ===
  [ 1..15] S ParameterStatus  (the same fifteen keys, forwarded)
  [16] K BackendKeyData    pid=799998125  (synthetic)
  [17] Z ReadyForQuery     transaction_status='I'

=== unknown database ===
  <- E ErrorResponse (pre-auth)  S="FATAL" C="08P01" M="no such database: nosuchdb"

=== CONNECT-denied role ===
  <- E ErrorResponse (pre-auth)  S="FATAL" C="08P01" M="SASL authentication failed"
```

**Neither `3D000` nor `42501` survives.** They do not arrive collapsed at the
session step — they arrive at `postgres.startup`, as `08P01`, before
authentication. A rule keyed on either must not assume it fires, exactly as ADR
0036 §10 requires for `28P01`.

`V` was absent from every pgBouncer error, matching Phase 4.0 and Phase 4.4b.

### 9.1 The sharpest result: a passing session with the backend stopped

```text
=== pgBouncer with the PostgreSQL backend stopped, verifier cached ===
  [ 1..15] S ParameterStatus  (fifteen, from the pooler's cache)
  [16] K BackendKeyData    pid=1172961953  (synthetic)
  [17] Z ReadyForQuery     transaction_status='I'
```

The backend container was stopped before this connection was made. pgBouncer
served a **complete, successful session** from its cached parameter block, with a
fabricated backend key, and reached `ReadyForQuery`.

So `ReadyForQuery` proves that *a PostgreSQL-protocol session was established at
this endpoint*. It does not prove that a PostgreSQL server exists behind it. This
is what fixes the success-claim wording in ADR 0039 §12, and it is measured rather
than argued.

## 10. Reproduction

```sh
docker run -d --name pg -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app-pw \
  -e POSTGRES_DB=appdb -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256" \
  -p 55450:5432 postgres:18 \
  -c password_encryption=scram-sha-256 -c max_connections=10 \
  -c wal_level=replica -c max_wal_senders=4
```

Roles and databases are created with `docker exec … psql` rather than a mounted
`initdb.d` script: on Docker Desktop for macOS a bind mount of a path under `/tmp`
silently becomes an **empty directory** inside the container, which cost an hour
and is worth writing down.

The standby needs a replication line appended to the primary's `pg_hba.conf` and a
reload, then:

```sh
pg_basebackup -h <primary> -U rep -D "$D" -Fp -Xs -R -c fast
```

`-c fast` is required. Without it `pg_basebackup` waits for the next checkpoint,
which on a default configuration is up to five minutes and looks exactly like a
hang.

Connection-slot exhaustion is easiest to reach by holding sessions **inside** the
container (`docker exec -d … psql -c "select pg_sleep(45)"`) and then connecting
as a non-superuser, so that `superuser_reserved_connections` does not mask the
limit.

## 11. What this study did not establish

- **`NoticeResponse` before `ReadyForQuery` was not reproduced.** No stock
  configuration produced one; PostgreSQL validated the invalid GUC values that
  would have triggered a warning. The protocol permits one almost anywhere, so it
  is skipped structurally and will be tested against a scripted peer in 4.5b.
- **`08004` was not observed.** It is documented for a rejected connection
  establishment; nothing in the matrix produced it.
- **`57P03` after `AuthenticationOk` was not observed.** It is reachable in
  principle from `InitPostgres` during a recovery race; only the pre-auth path was
  reproduced.
- **`'T'` and `'E'` transaction statuses were not observed**, and are unreachable
  without issuing a command.
- **A partial `ParameterStatus` block followed by an error was not observed** on a
  real backend. It requires a timeout or a scripted peer.
- **TLS was not re-exercised in this study.** The post-authentication window is
  channel-independent, and Phase 4.4b's integration suite already reads the first
  `ParameterStatus` off a verified-TLS connection against a real server.
- **No managed service was contacted.** RDS, Aurora, Cloud SQL and Azure remain
  reasoned from published behaviour.
- **Protocol 3.2 was not exercised.** svcdoctor requests 3.0; under 3.2
  `BackendKeyData` grows from 8 bytes to 32.
