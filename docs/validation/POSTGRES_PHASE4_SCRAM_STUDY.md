# PostgreSQL SCRAM-SHA-256 study — Phase 4.4a decision pass

What the PostgreSQL SASL/SCRAM exchange actually does, established against real servers
rather than from RFC memory. ADR 0038 is the decision this study produced; this file is the
evidence behind it.

Nothing here is production code. The probes used to obtain these transcripts were throwaway
experiments outside the repository and were deleted afterwards. **No PostgreSQL
authentication code was written in Phase 4.4a**, and the production `security.Reveal` count
was unchanged at one when sections 1–14 were written.

**Section 15 was added later**, during the Phase 4.4b pre-commit verification, and it
falsifies a mapping the earlier sections had accepted. It is appended rather than folded
into section 10, so that what was believed and what was measured stay distinguishable.

This study extends `POSTGRES_PHASE4_PROTOCOL_STUDY.md` rather than replacing it. Where the
two overlap they agree; where this one goes further it is because Phase 4.0 stopped at the
first `AuthenticationXXX` message and this phase had to cross it.

## 1. Environment

| | |
|---|---|
| Servers | PostgreSQL **18.6** and **14.24**, official `postgres:18` / `postgres:14` images |
| Proxy | **pgBouncer 1.25.2** (`edoburu/pgbouncer`), transaction pooling, `auth_type=scram-sha-256` |
| TLS | throwaway self-signed certificate, `CN=pg-canary.svcdoctor.test`, `SAN=DNS:…,DNS:localhost,IP:127.0.0.1` |
| Runtime | Docker 28.3.2, darwin/arm64 host |
| Probe | ~330 lines of Go over `net.Conn`, stdlib only, SCRAM-SHA-256 via `crypto/pbkdf2` |
| Toolchain | go1.26.6 |
| Sources read | `fe-auth-scram.c`, `auth-scram.c`, `scram-common.h` (REL_18_STABLE), RFC 5802, RFC 7677, RFC 4013 |

Roles created for the matrix, all in one `pg_hba.conf`:

```text
host    all blocked    all  reject
hostssl all tlsonly    all  scram-sha-256
host    all md5user    all  md5
host    all clearuser  all  password
host    all trustuser  all  trust
host    all nbspuser   all  scram-sha-256      -- password contains U+00A0
host    all softhyuser all  scram-sha-256      -- password contains U+00AD
host    all highiter   all  scram-sha-256      -- verifier built at scram_iterations=65536
host    all all        all  scram-sha-256
```

## 2. The verified SCRAM state machine

Every transition below was observed on the wire, not inferred.

```text
StartupMessage
   │
   └─ R AuthenticationSASL              code 10, NUL-terminated mechanism list, empty name terminator
        │
        ├─ p SASLInitialResponse        mechanism NUL, Int32 length, gs2-header + client-first-bare
        │
        └─ R AuthenticationSASLContinue code 11, server-first-message (r=, s=, i=)
             │
             ├─ p SASLResponse          client-final-message (c=, r=, p=)
             │
             ├─ E ErrorResponse 28P01   ← credential refused. NO SASLFinal. NO server signature.
             │
             └─ R AuthenticationSASLFinal  code 12, "v=<base64 ServerSignature>"
                  │
                  ├─ R AuthenticationOk    ← genuine PostgreSQL, always
                  │
                  └─ E ErrorResponse 08P01 ← observed through pgBouncer. SASLFinal, then NO Ok.
                                              (08P01 is that pooler's default code for
                                               everything — see section 15.)
```

Two results in that diagram are the load-bearing ones for ADR 0038:

- **A refused credential never produces a server-final message.** PostgreSQL answers
  `ErrorResponse 28P01` in place of `AuthenticationSASLFinal`, so a client that treats
  "no signature yet" as "keep going" has already lost.
- **`AuthenticationSASLFinal` is not followed by `AuthenticationOk` in every case.**
  Measured through pgBouncer: the signature verifies, and then an `ErrorResponse` arrives
  instead of `AuthenticationOk`. Success therefore requires *both*, and neither alone.

## 3. Transcript: PostgreSQL 18.6, plaintext, SCRAM-SHA-256 success

```text
  <- R AuthenticationSASL mechanisms=[SCRAM-SHA-256]
     raw body hex: 0000000a534352414d2d5348412d3235360000
                   ^^^^^^^^ code 10   ^^ … "SCRAM-SHA-256" ^^ 00 name terminator
                                                              ^^ 00 list terminator
  -> p SASLInitialResponse mech=SCRAM-SHA-256 payload="n,,n=,r=nP5LNX5JBuspgu0t1jZsB5NI"
  <- R AuthenticationSASLContinue (84 bytes)
       "r=nP5LNX5JBuspgu0t1jZsB5NIyAO98dIJh8X03o7XRRl2Y3mF,s=4BCmyjwnzSJewjl/3+gjeA==,i=4096"
     server-first: nonce_ext=24 chars  salt=16 bytes  iterations=4096
  -> p SASLResponse "c=biws,r=…Y3mF,p=<proof 44 b64 chars>"
  <- R AuthenticationSASLFinal (46 bytes) "v=aF5alUJ55pq1pA7e0cBZlQVNu2SkNM9M+ZysbVH4+lY="
     server signature VERIFIED (44 base64 chars)
  <- R AuthenticationOk (body 4 bytes, trailing 0)
  NEXT FRAME AFTER OK: type='S' len=19 ParameterStatus[in_hot_standby=off]
```

`AuthenticationOk`'s body is **exactly four bytes** — the code and nothing else. There is no
trailing payload to skip and no reason to read past it.

Identical shape observed on 14.24, on TLS, and through pgBouncer.

## 4. The `n=` username field is ignored by PostgreSQL

Three client-first messages were sent against the same role `app`, differing only in the
`n=` attribute:

| client-first-bare | Result |
|---|---|
| `n=,r=…` (empty, what libpq sends) | `AuthenticationOk` |
| `n=app,r=…` | `AuthenticationOk` |
| `n=definitely-not-the-role,r=…` | **`AuthenticationOk`** |

Confirmed in `src/backend/libpq/auth-scram.c`:

> `state->client_username = read_attr_value(&p, 'n');`
> *"Note: this is ignored. We use the username from the startup message instead, still it is
> kept around if provided as it proves to be useful for debugging purposes."*

**Consequence.** The role travels in the `StartupMessage`, which Phase 4.3 already sends.
Repeating it in the SCRAM message adds no authority, and sending it would create a second
place where a role name must be SCRAM-escaped (`,` → `=2C`, `=` → `=3D`) and a second place
where an escaping bug could exist. svcdoctor sends `n=`.

## 5. The gs2 header: `n,,` is legal even when `-PLUS` is offered

| gs2 header | Channel | Result |
|---|---|---|
| `n,,` | plaintext, list `[SCRAM-SHA-256]` | `AuthenticationOk` |
| `n,,` | **TLS, list `[SCRAM-SHA-256-PLUS, SCRAM-SHA-256]`** | **`AuthenticationOk`** |
| `y,,` | plaintext, list `[SCRAM-SHA-256]` | `AuthenticationOk` |
| `y,,` | TLS, list includes `-PLUS` | `E 28000 "SCRAM channel binding negotiation error"` |
| `n,a=app,` | any | `E 0A000 "client uses authorization identity, but it is not supported"` |
| mechanism `SCRAM-SHA-256-PLUS` with an `n,,` header | TLS | `E 08P01 "malformed SCRAM message"` |
| mechanism `SCRAM-SHA-1` | TLS | `E 08P01 "client selected an invalid SASL authentication mechanism"` |

Per RFC 5802 §5, `n` means *"client doesn't support channel binding"* and `y` means *"client
does support channel binding but thinks the server does not"*. `y` is the downgrade-detection
flag, and PostgreSQL enforces it: a client that claims `y` while the server offers `-PLUS`
is refused with `28000` and the detail *"The client supports SCRAM channel binding but thinks
the server does not. However, this server does support channel binding."*

**`n,,` is the truthful header for a client that does not implement channel binding**, and
PostgreSQL accepts it unconditionally. Choosing `SCRAM-SHA-256` while `SCRAM-SHA-256-PLUS`
is on offer is therefore legitimate negotiation, not a downgrade the server considers an
attack. It is what libpq itself sends when built without SSL support or run with
`channel_binding=disable`.

PostgreSQL also **rejects an authorization identity outright**, so the `authzid` question
ADR 0030 §2 settled for Kafka does not even arise here: the field must be empty.

## 6. SASLprep is required — the falsifying result of this phase

Two roles were created whose passwords differ from their SASLprep-normalized form:

| Role | Password bytes | SASLprep rule (RFC 4013 / RFC 3454) | Prepared bytes |
|---|---|---|---|
| `nbspuser` | `70 61 c2 a0 73 73` (`pa` U+00A0 `ss`) | C.1.2 non-ASCII space → U+0020 | `70 61 20 73 73` |
| `softhyuser` | `70 61 c2 ad 73 73` (`pa` U+00AD `ss`) | B.1 commonly mapped to nothing → deleted | `70 61 73 73` |

Result, reproduced on **both** 18.6 and 14.24:

```text
### PG18 nbspuser, password sent RAW ###
  <- E ErrorResponse S="FATAL" V="FATAL" C="28P01" M="password authentication failed for user \"nbspuser\""

### PG18 nbspuser, password SASLprepped ###
  <- R AuthenticationSASLFinal … server signature VERIFIED
  <- R AuthenticationOk

### PG14 nbspuser, password sent RAW ###
  <- E ErrorResponse S="FATAL" V="FATAL" C="28P01" M="password authentication failed for user \"nbspuser\""

### PG14 nbspuser, password SASLprepped ###
  <- R AuthenticationOk
```

`softhyuser` behaves identically.

**A SCRAM client that skips SASLprep produces `28P01` for a correct password.** For a
diagnostic tool that is the worst possible failure: it would tell an operator their
credential is wrong when it is right, and the report would carry
`AUTH_CREDENTIALS_REJECTED` as a confident, false claim.

### 6.1 Why the two sides agree, and when

Both ends apply the same function, and both fall back the same way.

Server, `src/backend/libpq/auth-scram.c`, when `CREATE ROLE … PASSWORD` builds the verifier:

> `rc = pg_saslprep(password, &prep_password);`
> `if (rc == SASLPREP_SUCCESS) password = (const char *) prep_password;`
> *"If the password isn't valid UTF-8 or contains prohibited characters, just proceed with
> the original password."*

Client, `src/interfaces/libpq/fe-auth-scram.c`, in `scram_init`:

> `rc = pg_saslprep(password, &prep_password);`
> `if (rc == SASLPREP_OOM) { … return NULL; }`
> `if (rc != SASLPREP_SUCCESS) prep_password = strdup(password);`

So:

| SASLprep on this password | Server stores | libpq computes | Agree |
|---|---|---|---|
| succeeds and changes the value | prepared | prepared | yes |
| succeeds and is the identity | raw | raw | yes |
| fails (invalid UTF-8, prohibited character, bidi violation) | raw | raw | yes |

A **raw-only** client agrees in rows two and three and is wrong in row one.

### 6.2 The ASCII subset where raw is provably correct

For a password whose bytes are all in `U+0020`–`U+007E`, SASLprep is the identity function.
Each stage, checked rather than assumed:

| SASLprep stage | Effect on printable ASCII |
|---|---|
| Mapping B.1 (map to nothing) | no member is ASCII |
| Mapping C.1.2 (non-ASCII space → space) | no member is ASCII, by definition |
| Normalization NFKC | no ASCII codepoint decomposes, and no ASCII pair composes |
| Prohibited C.2.1 (ASCII control) | `U+0000`–`U+001F` and `U+007F` only — outside the range |
| Prohibited C.2.2–C.9 | no member is ASCII |
| Bidi (RFC 3454 §6) | no ASCII codepoint is RandALCat |
| Unassigned A.1 | no ASCII codepoint is unassigned |

Verified empirically against `github.com/xdg-go/stringprep` v1.0.4, which implements the
SASLprep profile:

```text
printable ascii torture  in=20 21 22 … 7e -> out=20 21 22 … 7e   identity=true
nbsp U+00A0              in=70 61 c2 a0 73 73 -> out=70 61 20 73 73
soft hyphen U+00AD       in=70 61 c2 ad 73 73 -> out=70 61 73 73
zero width space U+200B  in=70 61 e2 80 8b 73 73 -> out=70 61 73 73
NFKC fullwidth U+FF21    in=ef bc a1 62 63 -> out=41 62 63
combining e + U+0301     in=65 cc 81 -> out=c3 a9
ascii control U+0001     -> ERROR: prohibited character
RandALCat bidi violation -> ERROR: BiDi string can't have runes from category L
```

The library's outputs for `nbspuser` and `softhyuser` are byte-identical to the hand-applied
mappings that authenticated successfully in §6, so it is proven correct against a real
server for both discriminating cases.

### 6.3 Dependency footprint, measured

```text
require (
	github.com/xdg-go/stringprep v1.0.4
	golang.org/x/text v0.41.0
)
```

Build closure beyond the standard library: `golang.org/x/text/transform`,
`golang.org/x/text/unicode/norm`, `github.com/xdg-go/stringprep` — three packages, two
modules. Source size 1.7 MB + 252 KB, dominated by `norm`'s Unicode tables. The wider
`go list -m all` graph (goldmark, `x/tools`, `x/net`, …) is `x/text`'s own test-only
dependencies and is not compiled.

For comparison, `golang.org/x/text/secure/precis` is **not** a substitute:
PRECIS `OpaqueString` (RFC 8265) normalizes with NFC rather than NFKC and does not delete
B.1 characters, so it fails the `softhyuser` case.

## 7. Iteration count: an unbounded, server-controlled work factor

`scram_iterations` on PostgreSQL 18.6:

```text
name             setting  min_val  max_val      boot_val  context
scram_iterations 4096     1        2147483647   4096      user
```

`context=user` means any role can raise it for its own session before creating a secret.
A verifier really was built at 65536 and served: `i=65536` observed on the wire.

An attempt to build one at `2147483647` did not complete within two minutes of server CPU
and had to be killed — which is the point.

**libpq imposes no upper bound.** `read_server_first_message` validates only:

> `state->iterations = strtol(iterations_str, &endptr, 10);`
> `if (*endptr != '\0' || state->iterations < 1)`

RFC 7677 §4 and RFC 5802 §5 give a `SHOULD` of at least 4096 and no maximum at all.

Cost of PBKDF2-HMAC-SHA256 measured with `crypto/pbkdf2` on the test machine:

| `i` | wall time |
|---|---|
| 4 096 | 0.89 ms |
| 65 536 | 19.4 ms |
| 1 048 576 | 246 ms |
| 4 194 304 | 1.30 s |
| 2 147 483 647 | ≈ 8 minutes (extrapolated, consistent across five rate samples) |

A peer that answers `i=2147483647` therefore buys itself eight minutes of a diagnostic
tool's CPU for four bytes of ASCII. This is the only place in the PostgreSQL exchange where
the peer chooses how much work svcdoctor does.

## 8. Nonce, salt and signature shapes

From `src/include/common/scram-common.h` and confirmed on the wire:

| | libpq / PostgreSQL | Observed |
|---|---|---|
| `SCRAM_RAW_NONCE_LEN` | 18 bytes, from `pg_strong_random`, base64-encoded | server nonce extension is 24 base64 chars = 18 raw bytes |
| `SCRAM_DEFAULT_SALT_LEN` | 16 bytes | `s=` decoded to 16 bytes in every transcript |
| `SCRAM_SHA_256_DEFAULT_ITERATIONS` | 4096 | `i=4096` unless configured otherwise |
| ServerSignature | HMAC-SHA-256, 32 bytes | `v=` is 44 base64 chars = 32 bytes |

Server-nonce rule, RFC 5802 §5: *"The client MUST verify that the initial part of the nonce
used in subsequent messages is the same as the nonce it initially specified."* Every observed
server nonce was `clientNonce || 24 more base64 characters`.

## 9. Server-signature verification is mandatory, and PostgreSQL never sends `e=`

RFC 5802 §5: *"The client then authenticates the server by computing the ServerSignature and
comparing it to the value sent by the server. If the two are different, the client MUST
consider the authentication exchange to be unsuccessful, and it might have to drop the
connection."*

libpq implements exactly that, and returns `SASL_COMPLETE` only on a match:

> `if (!verify_server_signature(state, &match, &errstr)) … return SASL_FAILED;`
> `if (!match) libpq_append_conn_error(conn, "incorrect server signature");`
> `return match ? SASL_COMPLETE : SASL_FAILED;`

`build_server_final_message` in `auth-scram.c` returns `psprintf("v=%s", …)` and nothing
else. PostgreSQL's own comment says why the `e=` path is unused:

> *"The SCRAM specification includes an error code, 'invalid-proof', for authentication
> failure, but it also allows erroring out in an application-specific way. We choose to do
> the latter, so that the error message for invalid password is the same for all
> authentication methods."*

`e=` was therefore **not observed from any peer in this study** — PostgreSQL 18.6, 14.24 and
pgBouncer 1.25.2 all report SCRAM failures as `ErrorResponse`. RFC 5802 defines
`server-error-value` as a closed token list *with* an extension production
(`server-error-value-ext`), so the token is not guaranteed to come from the closed set and
must never be treated as a reportable string.

**Nothing in the protocol stops a hostile peer from sending `AuthenticationOk` with no
server-final message at all.** A client that accepts it has authenticated the *client* to
the server and learned nothing about the server, which is precisely the property the
ServerSignature exists to provide.

## 10. Failure matrix, measured

### PostgreSQL 18.6 / 14.24

| Scenario | Wire outcome | SQLSTATE | `V` present |
|---|---|---|---|
| correct credential | SASLFinal → `AuthenticationOk` | — | — |
| wrong password | `ErrorResponse` in place of SASLFinal | `28P01` | yes |
| unknown role | `ErrorResponse` in place of SASLFinal | `28P01` | yes |
| corrupted client proof | `ErrorResponse` in place of SASLFinal | `28P01` | yes |
| non-SASLprepped Unicode password | `ErrorResponse` in place of SASLFinal | `28P01` | yes |
| `pg_hba` reject | `ErrorResponse` before any `AuthenticationXXX` | `28000` | yes |
| authzid in gs2 header | `ErrorResponse` | `0A000` | yes |
| `y,,` while `-PLUS` offered | `ErrorResponse` | `28000` | yes |
| unknown mechanism requested | `ErrorResponse` | `08P01` | yes |
| unknown database, valid credential | SASLFinal → `AuthenticationOk` → `ErrorResponse` | `3D000` | yes |
| no `CONNECT` privilege | SASLFinal → `AuthenticationOk` → `ErrorResponse` | `42501` | yes |
| `trust` role | `AuthenticationOk` immediately, no SASL at all | — | — |
| `md5` role | `AuthenticationMD5Password`, 4-byte salt | — | — |
| `password` role | `AuthenticationCleartextPassword`, **zero** trailing bytes | — | — |

**Wrong password, unknown role, corrupted proof and an un-normalized password are one
outcome.** Same SQLSTATE, same message template, same `F`/`L`/`R` source fields. The only
byte that differs is the username the client itself supplied. PostgreSQL issues a mock salt
for a non-existent role deliberately, so a client cannot enumerate roles.

### pgBouncer 1.25.2

| Scenario | Wire outcome | SQLSTATE | `V` present |
|---|---|---|---|
| correct credential | SASLFinal → `AuthenticationOk` | — | — |
| wrong password | `ErrorResponse` in place of SASLFinal, `M="SASL authentication failed"` | `08P01` | **no** |
| corrupted client proof | identical to wrong password | `08P01` | **no** |
| unknown role | `ErrorResponse` **before** `AuthenticationSASL`, `M="no such user"` | `08P01` | **no** |
| unknown database | **SASLFinal → `ErrorResponse`, no `AuthenticationOk`**, `M="no such database: …"` | `08P01` | **no** |

Three things follow.

1. **`28P01` never fires behind this pooler.** A rule keyed on it produces nothing, exactly
   as Phase 4.0 found for the startup vocabulary. The honest degradation is
   `AUTH_CREDENTIALS_REJECTED` with `sqlstate=08P01` recorded beside it, because the peer
   did refuse the material it was presented.
2. **The unknown-role case moves to a different protocol step.** pgBouncer refuses before it
   ever sends `AuthenticationSASL`, so Phase 4.3's `postgres.startup` node sees it, not the
   authentication node. `08P01` is unmapped there and classifies as
   `PROTOCOL_UNEXPECTED_RESPONSE` — a weak claim, and a true one.
3. **The unknown-database case is the sequence that forces the success boundary.** The
   ServerSignature verified, and `AuthenticationOk` never arrived. A client that treats a
   verified signature as success would report authentication PASS on a connection that was
   about to be closed.

`V` is absent from every pgBouncer error, matching Phase 4.0 §6. `postgres.error_is_native`
remains the one structural, non-prose, non-identity signal that the responder is a genuine
backend.

## 11. Read-ahead: measured, and the reason it matters

PostgreSQL sends `AuthenticationSASLFinal`, `AuthenticationOk`, every `ParameterStatus`,
`BackendKeyData` and `ReadyForQuery` in one burst. The same probe was run twice against the
same server, differing only in how it reads:

```text
### bufio.Reader ###
  --- Phase 4.4 would stop here. Buffered/stolen: 455 bytes ---
  NEXT FRAME AFTER OK: type='S' len=19 ParameterStatus[in_hot_standby=off]

### exact-length reads, as wire.ReadMessage does ###
  --- Phase 4.4 would stop here. Buffered/stolen: 0 bytes ---
  NEXT FRAME AFTER OK: type='S' len=19 ParameterStatus[in_hot_standby=off]
```

A buffered reader takes 455 bytes of Phase 4.5's session off the socket and into a buffer
Phase 4.5 has no handle on. `internal/adapter/postgres/wire.ReadMessage` reads a 5-byte
header with `io.ReadFull` and then exactly the announced body, straight from the `net.Conn`;
`grep -rn bufio internal/` finds no production match. **The property already holds and must
be preserved, not built.** It is the same concern that shaped the `SSLRequest` reader in
Phase 4.3, arriving one layer later.

## 12. Version behaviour

| | 14.24 | 18.6 |
|---|---|---|
| SCRAM-SHA-256 offered by default | yes | yes |
| `SCRAM-SHA-256-PLUS` offered over TLS only | yes | yes |
| `n,,` accepted while `-PLUS` is offered | yes | yes |
| `n=` username ignored | yes | yes |
| SASLprep required for U+00A0 / U+00AD passwords | yes | yes |
| Default iterations | 4096 | 4096 |
| `scram_iterations` GUC | **absent** (added in 16) | present, max 2147483647 |
| salt length | 16 bytes | 16 bytes |
| server nonce extension | 24 base64 chars | 24 base64 chars |
| SASLFinal before `AuthenticationOk` | yes | yes |
| wrong password / unknown role | identical `28P01` | identical `28P01` |
| `AuthenticationMD5Password` still issued for md5 roles | yes | yes |
| `AuthenticationCleartextPassword` for `password` hba | yes | yes |

Nothing in the SCRAM exchange differs across the support window. The only divergence is
whether the iteration count is server-tunable, and that only widens the range 18.6 can
present — which is why the bound has to be svcdoctor's, not the server's.

## 13. Reproduction recipes

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 3 \
  -keyout server.key -out server.crt \
  -subj "/CN=pg-canary.svcdoctor.test" \
  -addext "subjectAltName=DNS:pg-canary.svcdoctor.test,DNS:localhost,IP:127.0.0.1"

docker run -d --name pg-scram \
  -e POSTGRES_USER=app -e POSTGRES_PASSWORD=s3cr3t-canary -e POSTGRES_DB=appdb \
  -e POSTGRES_INITDB_ARGS="--auth-host=scram-sha-256" \
  -v "$PWD/certs:/etc/pg-certs:ro" -v "$PWD/pg_hba.conf:/etc/pg-hba.conf:ro" \
  -v "$PWD/init.sql:/docker-entrypoint-initdb.d/01-init.sql:ro" \
  -p 55432:5432 postgres:18 \
  -c ssl=on -c ssl_cert_file=/etc/pg-certs/server.crt -c ssl_key_file=/etc/pg-certs/server.key \
  -c hba_file=/etc/pg-hba.conf -c password_encryption=scram-sha-256
```

The Unicode roles are what make the SASLprep result reproducible; they must be created with
literal UTF-8 bytes, because `CREATE ROLE … PASSWORD` takes a string literal and not an
expression:

```sql
CREATE ROLE nbspuser   LOGIN PASSWORD 'pa<U+00A0>ss';
CREATE ROLE softhyuser LOGIN PASSWORD 'pa<U+00AD>ss';
```

pgBouncer in front of the same server, `pool_mode=transaction`, `auth_type=scram-sha-256`.

The Phase 4.8 integration suite reproduces this under `make`, driving production code paths
rather than a throwaway probe.

## 15. `08P01` re-measured: the code carries no cause

Added in the Phase 4.4b pre-commit verification, which asked whether
`AUTH_CREDENTIALS_REJECTED` is *provable* from `08P01` plus svcdoctor's own
protocol state. It is not, and this section is why.

Environment: pgBouncer 1.25.2 in `transaction` pooling with
`auth_type=scram-sha-256` and `auth_user=app` (auth-query passthrough) in front of
PostgreSQL 18.6. Each row records the state svcdoctor's classifier can actually
see at the moment the `ErrorResponse` arrives.

| # | Scenario | proofSent | SASLFinal | verified | AuthOk | SQLSTATE | `V` |
|---|---|---|---|---|---|---|---|
| 1 | correct user + correct password | yes | yes | yes | **yes** | — | — |
| 2 | correct user + wrong password, verifier **cached** | **yes** | no | **no** | no | `08P01` | absent |
| 3 | unknown user | no | no | no | no | `08P01` | absent |
| 4 | correct auth + unknown database | yes | yes | **yes** | no | `08P01` | absent |
| 5 | correct auth + existing but unpooled database | yes | yes | **yes** | no | `08P01` | absent |
| 6 | role exists with **no password set** (`rolpassword IS NULL`) | **yes** | no | **no** | no | `08P01` | absent |
| 7 | backend down, verifier **not** cached, correct password | no | no | no | no | `08P01` | absent |
| 8 | backend down, verifier cached, correct password | yes | yes | yes | no | `08P01` | absent |
| 9 | wrong password, verifier **not** cached | **no** | no | no | no | `08P01` | absent |
| 10 | **correct** password, pooler cannot serve the role | **no** | no | no | no | `08P01` | absent |

Three readings, in increasing order of decisiveness.

**Eight distinct causes, one code.** Rows 2–10 cover a wrong password, an unknown
user, an unknown database, an unpooled database, a role with no password, an
unreachable backend and a correct credential the pooler could not serve. Every one
of them is `08P01`, and every one omits `V`.

**The protocol position does not isolate the credential case.** The bucket
svcdoctor was using as its discriminator — `proofSent && !verified` — contains
row 2 (a genuinely wrong password) *and* row 6 (a role with no verifier to check
against, which is a server-side configuration fact). The bucket outside it
contains rows 4, 5 and 8, which are correct credentials, but also rows 3, 7, 9 and
10.

**The same cause moves between positions.** Rows 2 and 9 are the *same* wrong
password. It lands after the client proof when the pooler holds the role's
verifier and before any SASL message when it must fetch one. Row 10 is a
**correct** credential in the position row 9 occupies. The discriminator therefore
tracks pgBouncer's auth-query cache state, not the cause.

### The source says the same thing

`src/objects.c`, in the comment above `disconnect_client()`:

> *"PgBouncer used to report SQLSTATE 08P01 (protocol_violation) for all cases but
> it diverges from what Postgres reports in some cases."*

`disconnect_client()` passes a NULL sqlstate; `08P01` is what gets substituted.
Every client-facing failure in `src/client.c` reaches it — `SASL authentication
failed`, `password authentication failed`, `certificate authentication failed`,
`no such user`, `authentication database … is not configured`, `… is disabled`,
`old V2 protocol not supported`, `SSL required`, `unsupported startup parameter`,
`username too long`, `password too long`, and all three `max_client_conn` limits.

And in the SCRAM path specifically, two conditions send an error after the
client-final and before the server-final: a proof that did not verify, and *a
nonce that did not match*. The second is a protocol fault, not a credential
refusal, and it sits in exactly the position the discarded discriminator claimed
was proof of one.

The prose above is read only to establish the **scope** of the code. svcdoctor
classifies on the five-character SQLSTATE and its own protocol state, never on a
peer's message.

### Consequence

`08P01` is not mapped. It falls through to `PROTOCOL_UNEXPECTED_RESPONSE`, with
the code recorded as `postgres.sqlstate` and the missing `V` recorded as
`postgres.error_is_native=false`. See ADR 0038 amendment B, which also corrects
ADR 0036 section 10.

## 16. What this study did not establish

Recorded so that a later phase does not assume it did.

- **`SCRAM-SHA-256-PLUS` was not performed.** The mechanism list was observed over TLS on
  both versions; no channel-binding exchange was completed, and `tls-server-end-point` /
  `tls-exporter` derivation was not exercised.
- **No server was found that offers `-PLUS` without also offering `SCRAM-SHA-256`.**
  PostgreSQL advertises both over TLS and has no setting to advertise only the former, so
  the "PLUS-only peer" case is reasoned about rather than measured.
- **`e=` in a server-final message was not produced by any peer.** The classification
  proposed for it in ADR 0038 §15 is defensive and can only be tested against a scripted
  peer.
- **A hostile peer was not scripted.** `AuthenticationOk` without a server-final, a forged
  `v=`, a non-extending server nonce and `i=2147483647` are all analysed from the protocol
  and from `libpq`'s own validation, not observed. They are Phase 4.4b's scripted-peer test
  matrix.
- **MD5 and cleartext exchanges were not completed**, only their request messages observed.
  Completing either would mean writing the credential path ADR 0038 declines to build.
- **No managed service was contacted.** RDS, Aurora, Cloud SQL and Azure use SCRAM-SHA-256
  by published default; that remains reasoned, not measured.
- **`GSSENCRequest`, GSSAPI and SSPI were not exercised**, unchanged from Phase 4.0.
