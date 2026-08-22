# ADR 0038: PostgreSQL SCRAM-SHA-256, and the two facts that must both be true before authentication passes

## Status

**Accepted, and implemented in Phase 4.4b.** This is the second phase in svcdoctor that
transmits credential-derived bytes, and the production `security.Reveal` count is now
**two** — one per service. No new dependency; the dependency graph is unchanged.

Validated against a real PostgreSQL 18.6 server under `make integration-postgres`, and
against the RFC 7677 published test vector.

**Two sections were corrected by implementation**, and the corrections are set out under
"Amendments from implementation" at the end rather than edited silently into the text
above: the ordering in section 8, and the `08P01` mapping in section 21 — which is now
**no mapping at all**, on evidence from pgBouncer's own source. Amendment B also corrects
ADR 0036 section 10.

It applies ADR 0028's contract, ADR 0029's mechanisms and ADR 0030's ordering to a second
protocol. It invents no policy. What it adds is the protocol-specific half — the exchange,
the validation rules, and one scope restriction that measurement forced.

## Problem

Phase 4.3 stops at the first `AuthenticationXXX` message. It records what the server
demanded and answers nothing. The step after it is the second in this repository that can
leak a credential, and the first that runs a multi-round-trip mechanism.

ADR 0030 anticipated it in one line — *"A mechanism that needs more than one round trip —
SCRAM does. The single `ExchangePLAIN` call becomes a loop inside `wire` … Nothing above the
wire boundary changes."* That is true and it is not sufficient. SCRAM introduces four
questions PLAIN never raised:

1. the client must **verify the server**, and the exchange is worthless if it does not;
2. the server chooses a **work factor** and can choose an unbounded one;
3. the password must be **prepared** before it is hashed, and the preparation is not the
   identity function;
4. `AuthenticationOk` is a *separate message* from the server's proof, so the success
   condition is a conjunction rather than a single event.

Each is answered below against measurement. `docs/validation/POSTGRES_PHASE4_SCRAM_STUDY.md`
is the evidence.

## Observed evidence

Read from the tree at `f81d4da`, and from real servers, not assumed:

- **Exactly one production `security.Reveal` call site**, in
  `internal/adapter/kafka/wire/saslauthenticate.go`. `make check` green, `golangci-lint`
  reports 0 issues, one runtime dependency with zero transitive.
- **`internal/adapter/postgres/wire` may already call `security.Reveal`.** The `forbidigo`
  exclusion is written against `internal/adapter/[^/]+/wire/`, which matches this package
  today. Verified in both directions against a deliberate violation: the same function
  compiles clean inside `wire` and fails the build one directory up with the ADR 0027
  message. **No lint change is needed for Phase 4.4b.**
- `crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`, `crypto/rand` and `crypto/subtle` are all
  in the go1.26.6 toolchain, and none is denied to `internal/adapter/**` by `depguard`.
  Verified by compiling all five inside `postgres/wire` alongside a `Reveal` call.
- `StartupResult` carries `endpoint` (the logical `host:port` label), `address`, the startup
  `evidenceID`, `channel`, `channelEvidence`, `authMethod` and `mechanisms`, plus the
  `ownedConn` methods. It carries **no credential and no secret**, and it holds the same
  socket the TCP probe measured.
- **`channelEvidence` is set on every live `Session`, therefore on every `StartupResult`.**
  The TLS path names the `tls.handshake` node; the plaintext path names the
  `postgres.ssl_request` node, which positively records that no TLS was attempted. The two
  construction sites that leave it empty are dead sessions, which `Startup` refuses to
  continue from.
- `wire.AuthRequest` carries `Method`, `Code` and `Mechanisms` and **no challenge data**.
  That discards nothing SCRAM needs: `AuthenticationSASL` carries only the mechanism list,
  and the server-first message arrives later in `AuthenticationSASLContinue`, which Phase 4.4
  reads itself.
- `wire.ReadMessage` reads a 5-byte header and then exactly the announced body, with
  `io.ReadFull` straight from the `net.Conn`. `grep -rn bufio internal/` finds no production
  match.
- The failure vocabulary already holds `AUTH_MECHANISM_UNSUPPORTED`,
  `AUTH_MECHANISM_NOT_OFFERED`, `AUTH_CREDENTIALS_REJECTED`, `AUTHZ_NOT_PERMITTED`,
  `PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_PEER_CLOSED`,
  `EXEC_UNSUPPORTED_BY_SVCDOCTOR`, `EXEC_SKIPPED_BY_POLICY`, `EXEC_LOCAL_TIMEOUT` and
  `EXEC_CANCELLED`. **No new class is required.**

## Decision

### 1. Scope: SCRAM-SHA-256, one mechanism, one attempt, one connection

| Mechanism | Server can request it | Phase 4.4 performs it | Outcome when it arrives |
|---|---|---|---|
| **SCRAM-SHA-256** | yes, the modern default | **yes** | the exchange below |
| `SCRAM-SHA-256-PLUS` | yes, over TLS only | no | §5 |
| `AuthenticationMD5Password` | yes, for md5-hashed roles | no | §6 |
| `AuthenticationCleartextPassword` | yes, `password` in `pg_hba` | no | §7 |
| `AuthenticationGSS` / `GSSContinue` / `SSPI` | yes | no | `AUTH_MECHANISM_UNSUPPORTED` |
| `AuthenticationKerberosV5` | protocol code 2, unsupported by modern servers | no | `AUTH_MECHANISM_UNSUPPORTED` |
| `AuthenticationSCMCredential` | local sockets only; svcdoctor dials TCP | no | `AUTH_MECHANISM_UNSUPPORTED` |
| `AuthenticationOk` at startup | yes, `trust` | nothing to do | §12 |

One connection, one mechanism, one credential attempt. **No retry, no mechanism fallback, no
second credential, no reauthentication, no redial.** This is ADR 0028 §1 and ADR 0008
unchanged, and PostgreSQL gives no reason to weaken it: a failed SCRAM exchange is followed
by the server closing the connection, so there is nothing to retry on.

The signature is singular for the reason ADR 0028 §1 gives, and the shape is Kafka's with
this package's return idiom:

```go
// Shape only. Not implemented.
func Authenticate(
    ctx context.Context,
    builder *domain.GraphBuilder,
    result *StartupResult,          // exactly one, never a slice
    credential security.Credential,
    params AuthParams,
) (*AuthenticatedSession, error)
```

`(nil, nil)` on every recorded non-passing outcome, matching `Negotiate` and `Startup` in
this package rather than importing Kafka's `AuthResult` wrapper. Kafka needs the wrapper
because a refused caller must be able to name the node it caused; here nothing can follow a
refusal — Phase 4.5 requires an authenticated socket — so there is no consumer for the
identifier and a wrapper would be a type with one live field.

### 2. Two facts must both be true before authentication PASSes

This is the central decision of the record.

```text
authentication PASS  ⟺  ServerSignature verified  ∧  AuthenticationOk received
```

Neither half is sufficient, and both halves were measured.

**A verified signature is not success.** Through pgBouncer 1.25.2, an unknown database
produces `AuthenticationSASLFinal` with a signature that verifies correctly, followed by
`ErrorResponse 08P01` and **no `AuthenticationOk`**. A client that stopped at the signature
would report PASS on a connection about to be closed.

**`AuthenticationOk` is not success either.** Nothing in the protocol obliges a peer to send
a server-final message at all. A hostile or broken endpoint can answer the client-final with
`AuthenticationOk` directly, and a client that accepts it has proved *itself* to the peer and
learned nothing about the peer. RFC 5802 §5 is explicit: *"If the two are different, the
client MUST consider the authentication exchange to be unsuccessful."* libpq enforces it —
`scram_exchange` returns `SASL_COMPLETE` only when `verify_server_signature` matched.

So:

| Observed | State |
|---|---|
| SASLFinal verifies, then `AuthenticationOk` | **PASS** |
| SASLFinal verifies, then `ErrorResponse` | FAIL, classified by §15 |
| SASLFinal signature mismatches | FAIL — and a subsequent `AuthenticationOk` does not rescue it |
| `AuthenticationOk` with no SASLFinal | FAIL — `PROTOCOL_UNEXPECTED_RESPONSE` |
| SASLFinal carries `e=` | FAIL, classified by §15 |

The signature comparison uses `hmac.Equal`, which is `crypto/subtle`'s constant-time
comparison. It is cheap and it is the idiom; no timing claim is made beyond that.

### 3. `AuthenticationOk` is where Phase 4.4 stops, and it steals no bytes

`AuthenticationOk`'s body is exactly four bytes — the code, with no trailing payload.
Measured on 14.24, 18.6 and pgBouncer.

Phase 4.4 returns the moment it is read. It does **not** consume `ParameterStatus`,
`BackendKeyData` or `ReadyForQuery`; those are `postgres.session` at L5 and belong to Phase
4.5, which is where ADR 0036 §5 fixed the usability boundary.

That this is achievable was measured rather than assumed, because PostgreSQL sends the
server-final, the OK, every `ParameterStatus`, `BackendKeyData` and `ReadyForQuery` in one
burst. The same probe, differing only in how it reads:

```text
bufio.Reader        --- stop here. Buffered/stolen: 455 bytes ---
exact-length reads  --- stop here. Buffered/stolen:   0 bytes ---
```

`wire.ReadMessage` already reads exact lengths straight off the `net.Conn`. **Phase 4.4b
must preserve that property, not build it**: no `bufio.Reader`, no read-ahead, no
"convenience" drain. The first byte on the returned connection belongs to Phase 4.5. This is
the `SSLRequest` concern of Phase 4.3, one layer later, and a test asserts it the same way.

### 4. Mechanism selection: choose `SCRAM-SHA-256` by exact name, or do not authenticate

```text
mechanisms advertised by the server
  → contains "SCRAM-SHA-256"?  → send SASLInitialResponse naming it
  → does not?                  → AUTH_MECHANISM_NOT_OFFERED, zero bytes sent
```

Exact string match, no prefix matching, no case folding, no "closest available". The list is
in the server's preference order and svcdoctor ignores that order, because it implements
exactly one member: preference cannot influence a choice with one candidate, and reading it
would imply a negotiation that is not happening.

**Choosing `SCRAM-SHA-256` while `SCRAM-SHA-256-PLUS` is also offered is legitimate, and
this was verified rather than assumed.** PostgreSQL accepts a `n,,` gs2 header — *"client
doesn't support channel binding"*, RFC 5802 §5 — unconditionally, over TLS, with `-PLUS`
first in the list. It is what libpq sends when built without SSL or run with
`channel_binding=disable`.

What PostgreSQL *does* reject is a **`y,,`** header while it offers `-PLUS`: `28000 "SCRAM
channel binding negotiation error"`. `y` means *"I support channel binding but I think you
do not"*, which is a downgrade claim and false here. svcdoctor does not implement channel
binding, so `n` is the truthful flag and `y` must never be sent.

The gs2 header is the literal three bytes `n,,`. The authorization identity is **absent, not
empty-and-present** — the opposite of ADR 0030's SASL/PLAIN decision, and for a measured
reason: PostgreSQL refuses any `authzid` with `0A000 "client uses authorization identity, but
it is not supported"`. There is no field for a value `security.Credential` could not supply
anyway.

### 5. `SCRAM-SHA-256-PLUS` is not implemented, and the distinction is which side the gap is on

Not implemented in Phase 4.4. Channel binding would require deriving a `tls-server-end-point`
or `tls-exporter` value from the live TLS connection, which means an adapter interrogating a
`*tls.Conn` — the capability `depguard` removed from adapters in Phase 4.2, and the inference
ADR 0029 exists to prevent. Adding it is a change to `internal/probe/tls`'s contract with its
own record, not a line in a wire package.

Two cases, and they are different facts:

| Server offers | svcdoctor does | State | Class |
|---|---|---|---|
| `[SCRAM-SHA-256-PLUS, SCRAM-SHA-256]` | uses `SCRAM-SHA-256` with an `n,,` header | — | — |
| `[SCRAM-SHA-256-PLUS]` only | sends nothing | **UNKNOWN** | **`AUTH_MECHANISM_UNSUPPORTED`** |

The second row is `AUTH_MECHANISM_UNSUPPORTED`, **not** `AUTH_MECHANISM_NOT_OFFERED`. The
peer offered a mechanism; svcdoctor cannot perform it. The vocabulary already draws exactly
that line — *"`AUTH_MECHANISM_UNSUPPORTED` means svcdoctor cannot perform the mechanism"*
versus *"the peer does not offer the requested mechanism"* — and getting it backwards would
send a reader to the server's configuration for a gap in the tool.

No PostgreSQL configuration was found that advertises `-PLUS` without also advertising
`SCRAM-SHA-256`, so this row is defensive. It is written because a pooler or a
protocol-compatible service may differ, and because the alternative is a code path that
silently sends nothing.

**A channel-binding-capable peer is not a reason to fall back to anything.** There is no
downgrade here to protect against: svcdoctor sends a credential only over verified TLS
(§8), so the MITM that channel binding defends against has already been excluded by the
transport policy.

### 6. MD5 is observed and declined

`AuthenticationMD5Password` arrives with a four-byte salt, on both 14.24 and 18.6, for any
role whose password was stored with `password_encryption=md5`. Implementing it is easy —
`md5(md5(password || user) || salt)` — and that is not a reason.

Declined, and recorded as `AUTH_MECHANISM_UNSUPPORTED`, `StateFail`, zero bytes sent:

- It widens the credential-transmission surface by a second `security.Reveal` path, in the
  phase whose entire purpose is to keep that surface at one call per service.
- MD5 authentication is deprecated by the PostgreSQL project and is off by default on every
  release in the support window; a deployment still using it has a finding to receive, not a
  client to be accommodated by.
- The first slice needs one mechanism to be a complete vertical slice. A second adds no
  diagnostic capability that `postgres.auth_method=md5` does not already report from the
  startup node.

**What svcdoctor still reports for an md5 endpoint is not nothing.** DNS, TCP, `SSLRequest`,
TLS facts, the accepted protocol version, the role and database, and
`postgres.auth_method=md5` all come from Phase 4.3 and are unaffected. The gap is exactly
one node deep.

Reopen when a supported managed service is found that offers md5 and *not* SCRAM, which
would make PostgreSQL undiagnosable past L4 for a real deployment rather than an unusual one.

### 7. Cleartext password is not implemented, and it is the one with an extra reason

`AuthenticationCleartextPassword` arrives with zero trailing bytes; the client answers with
a `PasswordMessage` containing the password, NUL-terminated. It is one line of code.

Declined, `AUTH_MECHANISM_UNSUPPORTED`, zero bytes sent — and unlike MD5 this has a security
argument on top of the scope argument.

SCRAM never puts the password on the wire in any form: what crosses is a proof that depends
on a server-supplied salt and nonce, and it is not replayable against a different server or
a different exchange. A cleartext `PasswordMessage` hands the peer the password itself. On a
verified-TLS channel that is safe against the network and **not** against the peer, and
svcdoctor is a tool whose ordinary use is pointing it at an endpoint someone is not yet sure
about. The transport policy answers "may this cross the wire"; it does not answer "may this
peer keep it".

That is a different threat model from the one ADR 0028 §3 reasoned about, so it is not a
case the existing policy already covers, and Phase 4.4 does not extend the policy to cover
it. **No fallback to cleartext exists under any channel, including verified TLS.**

Reopen only alongside an explicit per-run opt-in of the `--insecure` shape — explicit,
warned about, recorded in `ReportSecurity` — which is ADR 0029's deferred override and has no
owner before Phase 5.

### 8. The ordering, unchanged from ADR 0030 §1

```text
result.AuthMethod() == "sasl"             did the peer ask for a mechanism family we do
  → "SCRAM-SHA-256" ∈ SASLMechanisms()      … and the exact mechanism we implement
  → result.Channel()                      what this connection proved
  → policy.PermitsCredentials(channel)    may a secret cross it at all
  → security.NewEndpoint(result)          the logical name, never the address
  → credential.SecretFor(endpoint)        is this credential authorized here
  → wire.AuthenticateSCRAM                the only layer that may reveal
  → security.Reveal                       first statement inside, then §11's check
```

*(The two mechanism steps moved ahead of the channel policy during implementation; see
amendment A.)*

Each step is a precondition for the next and each failure stops before the next exists in the
call stack. A channel the policy refuses never reaches the code that parses an endpoint; a
credential bound elsewhere never reaches the wire package.

**The two mechanism steps sit before `SecretFor`, and that placement is deliberate.** It is
the correction this record makes to the shape ADR 0030 §1 fixed for Kafka, where the
mechanism was already settled by a separate handshake step before `Authenticate` was called.
PostgreSQL has no such step: the demanded method arrives on the startup node, so admissibility
has to be decided here. Deciding it first means **`security.Reveal` is never reached for an
endpoint svcdoctor cannot authenticate to at all** — md5, cleartext, GSS, SSPI, Kerberos, SCM,
a `-PLUS`-only list, or a list without `SCRAM-SHA-256`. `SecretFor` is not called either, so
those rows do not even consult the credential.

**Zero credential-derived bytes** is the property, and it is stronger than "no password
bytes". None of the following is written on a refused path: the client nonce, the gs2 header,
the `SASLInitialResponse`, any HMAC output, any PBKDF2 output, the client proof, or the
mechanism name. The refusal is decided before the first SASL message, so the socket is left
exactly as `Startup` left it.

**The role identity is a deliberate exception, and it was already sent.** `StartupMessage`
carries `user` and `database` and the protocol has no anonymous startup, so Phase 4.3
disclosed both before the channel policy was ever consulted. That is not a leak this phase
introduces and not one it can prevent: ADR 0036 §12.2 decided that role and database are
targeting parameters of the same kind as a hostname — which svcdoctor already puts in a DNS
query and an SNI extension in the clear — and that refusing to send them would make
plaintext PostgreSQL undiagnosable. What protects them is `domain.IdentityAttr` and
redaction (ADR 0037), not the credential-transport policy. **A role name is identity; it is
not credential-derived material**, and this record does not blur the two.

Under the current policy, on each channel:

| Channel | Credential | Node |
|---|---|---|
| `tls-verified` | sent | the exchange |
| `tls-unverified` | **not sent** | `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` |
| `plaintext` | **not sent** | `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` |
| `unknown`, undefined | **not sent** | `SKIPPED` + `EXEC_SKIPPED_BY_POLICY` |

`CredentialTransportPolicy` has one member and its zero value is `RequireVerifiedTLS`, so a
policy nobody set refuses. ADR 0036 §12.2 already recorded that this bites harder for
PostgreSQL than for Kafka, because plaintext PostgreSQL is the ordinary shape of an internal
deployment. That remains the largest practical limitation of the slice and its owner is
Phase 5, not this record.

### 9. Credential authority is the logical endpoint, and PostgreSQL cannot widen it

`StartupResult.Endpoint()` is the label `transport.Params` built with `net.JoinHostPort`, so
`net.SplitHostPort` recovers the same parts and `security.NewEndpoint` normalizes case, the
trailing dot and IPv6 form. `StartupResult.Address()` — the concrete `ip:port` — is **never**
an input to `SecretFor`.

Nothing about PostgreSQL changes ADR 0028 §2, and the acceptance tests are the same ones:

| Case | Expected |
|---|---|
| exact `host:port` | allowed |
| `PG.Internal.` versus `pg.internal` | allowed — `security.Endpoint` normalization, not widening |
| different host | `ErrEndpointMismatch` |
| different port | `ErrEndpointMismatch` |
| credential bound to the resolved IP, session endpoint is the name | **`ErrEndpointMismatch`** |
| one name resolving to *N* addresses | authorized on all *N* — one endpoint, *N* paths |

The TLS `ServerName` does not control credential authority either. It is a handshake
parameter derived from the same endpoint, and if the two ever disagreed the credential would
follow the endpoint, because that is the name the operator asked about.

### 10. `security.Reveal` happens once, inside `internal/adapter/postgres/wire`

**Package:** `internal/adapter/postgres/wire`. **Nowhere higher, nowhere lower.**

Not `internal/security` — a generic package that derived SCRAM would need a mechanism
vocabulary it deliberately does not have, and `internal/security/doc.go` has said since
Phase 1 that this type models no mechanisms. Not `internal/adapter/postgres` — that is where
connections, evidence and the graph builder are in scope, which is exactly ADR 0027's
rejected alternative.

The adapter passes a `security.Secret` and never a string. The wire package imports
`internal/security` to accept it — verified to compile and to pass every lint.

**Expected production `security.Reveal` count:**

| | Count |
|---|---|
| before Phase 4.4b | 1 |
| after Phase 4.4b | **2** |

Two, not three: one per service, which is the number ADR 0027 said the rule was sized for.

**Enforcement grade, stated honestly.** `forbidigo`'s exclusion is *path-level* —
`internal/adapter/[^/]+/wire/` — so it grants the whole package, not one function. Any file
in `postgres/wire` could add a third call and CI would not object. That is the same grade
Kafka has had since Phase 3.2c and this record does not claim better. What contains it is
that the package is small, has no evidence model or report model in scope, owns no
connection, and is reviewed as a protocol boundary; and that `grep -rn 'security\.Reveal('`
over the tree is the audit, which is why the call form was chosen in Phase 1. If the count
of legitimate sites ever stops being one per service, ADR 0027's capability-token
alternative becomes justified.

### 11. Password preparation: SASLprep is required, and Phase 4.4 implements a provable subset

**This is the STOP-worthy question of the phase, and the measurement is unambiguous.**

PostgreSQL applies SASLprep (RFC 4013) to the password on **both** sides. Roles were created
whose passwords contain `U+00A0 NO-BREAK SPACE` (SASLprep maps it to `U+0020`) and
`U+00AD SOFT HYPHEN` (SASLprep deletes it). On 18.6 **and** 14.24:

```text
password sent RAW        -> E ErrorResponse C="28P01" "password authentication failed"
password sent SASLprepped -> R AuthenticationSASLFinal … AuthenticationOk
```

**A SCRAM client that skips SASLprep reports `AUTH_CREDENTIALS_REJECTED` for a correct
password.** For a diagnostic tool that is the worst available failure: a confident, false
claim that sends an operator to a secret store to fix something that is not broken.

The two ends agree because both fall back identically. Server, `auth-scram.c`:
*"If the password isn't valid UTF-8 or contains prohibited characters, just proceed with the
original password."* Client, `fe-auth-scram.c`:
`if (rc != SASLPREP_SUCCESS) prep_password = strdup(password);`

| SASLprep on this password | Server stored | libpq computes | Raw-only client |
|---|---|---|---|
| succeeds and **changes** the value | prepared | prepared | **wrong** |
| succeeds and is the identity | prepared (= raw) | prepared (= raw) | correct |
| fails (invalid UTF-8, prohibited, bidi) | raw | raw | correct |

#### 11.1 The decision

**Phase 4.4b handles passwords every code point of which is in `U+0020`–`U+007E`
inclusive, and refuses every other password before a single byte is sent.**

The range is closed at both ends: `U+001F` is refused, `U+0020` (space) is accepted,
`U+007E` (`~`) is accepted, `U+007F` is refused, and every code point above it — including
`U+00A0` and `U+00AD`, the two measured in §11 — is refused.

**The implementation may check bytes, and the two are exactly equivalent here.** Every code
point at or above `U+0080` encodes in UTF-8 as bytes in `0x80`–`0xBF` (continuations) or
`0xC2`–`0xF4` (leads), and none of those falls in `0x20`–`0x7E`. So "every byte is in
`0x20`–`0x7E`" and "every code point is in `U+0020`–`U+007E`" accept and reject exactly the
same inputs, with no decoding step. Invalid UTF-8 is refused by the same test, which is the
right answer: §11.1's guarantee is about a range where SASLprep is provably the identity, and
an undecodable byte sequence is not in it.

For that range SASLprep is provably the identity function — no B.1 or C.1.2 mapping member
is ASCII, NFKC is the identity on ASCII because no ASCII codepoint decomposes and no ASCII
pair composes, and the prohibited ASCII set (`U+0000`–`U+001F`, `U+007F`) lies outside the
range. Confirmed empirically against a reference SASLprep implementation on a
printable-ASCII torture string: `identity=true`.

A password outside that range produces:

```text
postgres.authentication   UNKNOWN   EXEC_UNSUPPORTED_BY_SVCDOCTOR
```

with zero SASL bytes sent and the connection closed.

**`UNKNOWN`, not `SKIPPED` and never `FAIL`**, and that is the repository's rule rather than
this record's preference. `internal/domain/state.go` gives *"svcdoctor does not support the
capability"* as its first example of `StateUnknown`; `docs/ARCHITECTURE.md` §"claim rules"
says *"An unsupported capability is not a FAIL. svcdoctor not supporting a mechanism is a gap
in svcdoctor, not a defect in the target. Use `UNKNOWN`"*; `CLAUDE.md` repeats it; and
`internal/domain/evidence_test.go` already pins `{StateUnknown, FailureExecUnsupportedBySvcdoctor}`
as a valid pairing. `SKIPPED` is for a step *intentionally not executed* — a failed
prerequisite, a policy, a privilege, a scope rule — and none of those applies. The claim being
made is precisely *"svcdoctor could not determine whether this credential authenticates"*,
which is what `UNKNOWN` means.

#### 11.1.1 Where the check sits, and the one ordering that cannot be achieved

The check is the **first statement after `security.Reveal`**, inside `wire`:

```text
wire.AuthenticateSCRAM
  → security.Reveal(secret)        ← the only call
  → printable-ASCII check          ← immediately, before anything else
  → refuse: return, having generated no nonce, computed no PBKDF2 or HMAC,
            built no gs2 header, and written no byte to the socket
```

So the refusal precedes nonce generation, all PBKDF2 and HMAC work, and every byte of
`SASLInitialResponse`. It does **not** precede `Reveal`, and this record states plainly that
it cannot.

`security.Secret`'s entire surface is `IsEmpty`, the masking output paths, and the
package-level `security.Reveal`. **There is no way to learn anything about a secret's content
without revealing it**, by construction — that is the design ADR 0027 confined with a lint.
Deciding "is this password printable ASCII" *is* an inspection of the plaintext, so no
ordering can put it earlier.

Adding a predicate to `security.Secret` — `IsPrintableASCII()` or similar — would move the
refusal before `Reveal` and is **rejected**. It would create a second, *unconfined* inspection
path on the one type whose whole design is that there is exactly one, lint-guarded way to read
it; any package importing `internal/security` could then probe a secret's shape a bit at a
time, with no `forbidigo` rule able to see it. The gain would be small, because under the
ordering above the revealed string is a local that is discarded before any derivation runs and
before any byte is written. The cost is a permanent widening of the type that holds every
credential in the tool.

What the ordering *does* buy, and this is the part that matters: because §8 puts the mechanism
gate before `SecretFor`, `Reveal` is reached **only** when the peer demanded SASL, advertised
`SCRAM-SHA-256`, the channel policy permitted a credential, and the credential was authorized
for this endpoint. Every other refusal in §20 happens with the secret still masked.

#### 11.2 Why not the library, which exists and works

`github.com/xdg-go/stringprep` v1.0.4 implements the SASLprep profile. It was measured:
its output for both discriminating passwords is byte-identical to the hand-applied mappings
that authenticated successfully against the real server, and its build closure is three
packages across two modules (`x/text/transform`, `x/text/unicode/norm`, `stringprep`).

It is rejected for Phase 4.4b, and the reason is not the dependency count.

**The two failure modes are not symmetric.** The ASCII restriction fails by *refusing*, in a
class that says "svcdoctor cannot do this" — visible, truthful, and never a claim about the
target. A second independent SASLprep implementation fails by *disagreeing with
`pg_saslprep` on some codepoint*, and that failure is silent and indistinguishable from a
wrong password: it reappears as the same false `28P01` this section exists to prevent, moved
somewhere harder to find. PostgreSQL generates its stringprep and normalization tables from a
pinned Unicode version at build time; `x/text/unicode/norm` ships its own. Nothing proves
they agree on every input, and proving it needs a differential fuzz harness against
`pg_saslprep` that this repository does not have.

The ASCII subset is provable, testable in a unit test, and correct by construction. Full
Unicode equivalence between two independent implementations is neither, today.

`golang.org/x/text/secure/precis` is **not** an alternative: PRECIS `OpaqueString` (RFC 8265)
normalizes with NFC rather than NFKC and does not delete B.1 characters, so it fails the
soft-hyphen case outright.

#### 11.3 Reopen

Two different things, and they must not be run together.

**What reopens the question:** a real deployment that svcdoctor cannot diagnose because of
this restriction. That raises the priority and nothing else.

**What gates shipping non-ASCII support:** adopting a PostgreSQL-compatible SASLprep
implementation **and** differentially validating it against `pg_saslprep` over a generated
corpus, with the comparison in the test suite. Both, in that order. A blocked deployment is
*not* a reason to relax the gate — it is the reason the gate exists, because the failure mode
of an unvalidated implementation is the same false `28P01` this section was written to
prevent, on inputs nobody thought to try.

Adopting `xdg-go/stringprep` is then a dependency addition with its own record and that
corpus — **and it changes no contract in this one**, because the restriction is expressed as a
failure class rather than as a shape. That is the property that makes it safe to start narrow.

### 12. `AuthenticationOk` at startup is not authentication, and this phase does not claim it

A `trust` role produces `AuthenticationOk` as the *first* reply to `StartupMessage`, with no
SASL exchange. Phase 4.3 already records that correctly as `postgres.auth_method=ok` on a
passing `postgres.startup` node.

If `Authenticate` is called on such a `StartupResult` there is nothing to do: no credential
can be presented because none was requested. It records **no `postgres.authentication`
node**, returns the connection as an `AuthenticatedSession`, and Phase 4.5 continues.

Writing a `PASS` node there would be svcdoctor claiming to have authenticated when it
presented nothing, which is the same overclaim `AUTHZ_NOT_PERMITTED` was added to avoid one
layer down. The absence of the node is the honest record, and the startup node already says
why.

### 13. Crypto route: standard library, no new dependency

Verified in the go1.26.6 toolchain, not assumed:

| Primitive | Package | Note |
|---|---|---|
| PBKDF2-HMAC-SHA256 | **`crypto/pbkdf2`** | `Key[Hash](h func() Hash, password string, salt []byte, iter, keyLen int) ([]byte, error)`. Present since Go 1.24 |
| HMAC-SHA-256 | `crypto/hmac` | also `hmac.Equal` for the signature comparison |
| SHA-256 | `crypto/sha256` | |
| Nonce entropy | `crypto/rand` | |
| Constant-time compare | `crypto/subtle` | reached through `hmac.Equal` |
| base64 | `encoding/base64` | standard alphabet, as the RFC requires |

ADR 0036 §13 predicted this and it holds. **A hand-written PBKDF2 was never on the table** —
it is a security-hostile way to save an import that already exists. The one thing that *did*
need a dependency decision is §11, and it is answered by narrowing scope rather than by
adding a module.

### 14. Nonce, and the shape of the messages

**Client nonce: 18 bytes from `crypto/rand`, base64-encoded to 24 characters.** Identical to
libpq's `SCRAM_RAW_NONCE_LEN = 18` with `pg_strong_random`. Eighteen is chosen because it is
divisible by three, so the encoding produces no `=` padding, and because matching libpq means
matching the shape every PostgreSQL-compatible server has been tested against.

`math/rand`, timestamps, counters, and UUIDs are forbidden. Determinism in production is a
defect here, not a feature.

**Test seam:** an unexported entropy parameter on the unexported derivation function, defaulting
to `crypto/rand`. Not an exported interface, not a package-level variable, not a generic
randomness abstraction — one unexported parameter, which is the smallest thing that makes the
message construction testable against a fixed vector.

Messages, with the values fixed by §4 and §11:

```text
client-first  = "n,,"  "n="  ","  "r=" <24 base64 chars>
                 ^gs2   ^empty, PostgreSQL ignores it (§4)
server-first  = "r=" <client nonce ‖ server extension> "," "s=" <base64 salt> "," "i=" <iterations>
client-final  = "c=biws"  ","  "r=" <server nonce>  ","  "p=" <base64 proof>
                       ^ base64("n,,"), computed, never a literal
server-final  = "v=" <base64 ServerSignature>     or     "e=" <token>
```

`c=biws` is `base64("n,,")` and is **computed from the gs2 header actually sent**, not
written as a constant. A literal would silently stop matching if the header ever changed,
and the server includes the header in the value it verifies.

SCRAM escaping (`,` → `=2C`, `=` → `=3D`) applies only to the username field, which is empty.
There is therefore no escaping code in Phase 4.4b, and no role name reaches the SCRAM layer.

### 15. Validation of everything the server says, and how each failure is classified

The server controls every byte of the server-first and server-final messages. Each rule below
is a refusal to continue, not a warning.

**server-first**

| Rule | Violation → |
|---|---|
| parses as comma-separated `k=v` attributes | `PROTOCOL_MALFORMED_RESPONSE` |
| `r`, `s`, `i` all present, none duplicated | `PROTOCOL_MALFORMED_RESPONSE` |
| `r` strictly extends the client nonce — prefix match **and** longer | `PROTOCOL_MALFORMED_RESPONSE` |
| `s` decodes as standard base64 | `PROTOCOL_MALFORMED_RESPONSE` |
| `i` is a decimal integer, no trailing bytes, `>= 1` | `PROTOCOL_MALFORMED_RESPONSE` |
| `i <= 1048576` | **`UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR`** — see §16 |

*"Strictly extends"* is both halves. RFC 5802 §5: *"The client MUST verify that the initial
part of the nonce used in subsequent messages is the same as the nonce it initially
specified."* A server nonce **equal** to the client nonce satisfies the prefix test and adds
no server entropy, which defeats the replay protection the nonce exists for, so it is refused
separately. Every observed server extended by exactly 24 base64 characters.

**server-final**

| Observed | State | Class |
|---|---|---|
| `v=` and the signature matches | continue to §2 | — |
| `v=` and the signature does **not** match | FAIL | `AUTH_CREDENTIALS_REJECTED` |
| `v=` that does not decode as base64 | FAIL | `PROTOCOL_MALFORMED_RESPONSE` |
| `e=invalid-proof` / `e=unknown-user` / `e=invalid-username-encoding` | FAIL | `AUTH_CREDENTIALS_REJECTED` |
| any other `e=` token, including unrecognized | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| neither `v=` nor `e=` | FAIL | `PROTOCOL_MALFORMED_RESPONSE` |

A signature mismatch is `AUTH_CREDENTIALS_REJECTED` because that class means *"the peer
refused the authentication material it was presented"* and a mutual mechanism makes the
refusal mutual: svcdoctor refused the peer's. It is not `PROTOCOL_MALFORMED_RESPONSE` — the
message was well-formed — and it is not a new class, because no reader would act differently
than on any other rejected authentication.

**`e=` was not produced by any peer in this study.** `build_server_final_message` in
`auth-scram.c` returns `psprintf("v=%s", …)` and nothing else, and PostgreSQL's own comment
says why: *"we choose to [error out in an application-specific way], so that the error
message for invalid password is the same for all authentication methods."* pgBouncer does the
same. The mapping is defensive and is testable only against a scripted peer.

**The `e=` token is never recorded.** RFC 5802 defines `server-error-value` as a token list
*with* a `server-error-value-ext` production, so it is not a closed set and a peer may put
arbitrary text there. It is read to select a class and then dropped, exactly as
`ErrorResponse`'s `M` field is.

**No English text is examined anywhere.** Classification reads a SQLSTATE, a SCRAM attribute
letter, or a token from a fixed comparison set. Nothing else.

### 16. Iteration count: the peer chooses svcdoctor's work, so svcdoctor chooses a ceiling

The server names the PBKDF2 iteration count and it is the only value in this exchange that
decides how much CPU svcdoctor spends. Measured on PostgreSQL 18.6:

```text
scram_iterations  setting 4096  min_val 1  max_val 2147483647  context user
```

`context=user` means any role can raise it for its own session before creating a secret. A
verifier really was built at 65536 and served. An attempt at `2147483647` did not finish
within two minutes of server CPU.

**libpq imposes no upper bound at all** — `read_server_first_message` checks only
`iterations < 1`. RFC 7677 §4 gives a `SHOULD` of at least 4096 and no maximum.

Cost with `crypto/pbkdf2`, measured:

| `i` | wall time |
|---|---|
| 4 096 (default) | 0.89 ms |
| 65 536 | 19.4 ms |
| **1 048 576 (the cap)** | **246 ms** |
| 2 147 483 647 | ≈ 8 minutes |

**Ceiling: `maxSCRAMIterations = 1 << 20` (1 048 576).** Two hundred and fifty-six times
PostgreSQL's default, sixteen times the highest value observed in a real configuration, and
a quarter of a second of work. A peer above it gets `EXEC_UNSUPPORTED_BY_SVCDOCTOR` and
`StateUnknown` — the peer demanded work svcdoctor declines, which is a gap in the tool and
not a defect in the target — and **no PBKDF2 is computed**, because the check precedes the
derivation. That is the whole point.

The class is the honest one. The peer made a legal protocol demand; svcdoctor declines to
satisfy it. That is *"svcdoctor cannot check this — a gap in the tool, not a defect in the
target"*, and calling it a protocol error would blame a server for using a value the RFC
permits. It is deliberately **not** `EXEC_LOCAL_TIMEOUT`, which would claim a budget expired
when nothing was attempted.

**A count below 4096 is accepted and recorded, not refused.** The RFC says `SHOULD`, the GUC
minimum is 1, and a server configured at `scram_iterations=1` is a real deployment with a
real weakness. Refusing it would make svcdoctor blind exactly where its finding would be
most valuable. The count is recorded as an attribute so a Phase 4.6 rule can state the
weakness; the client's job is to complete the exchange and report.

### 17. Evidence contract

One node, refining ADR 0036 §8:

| | |
|---|---|
| Step | `postgres.authentication` |
| Layer | L5 |
| Parent | `postgres.startup` |
| Subject | the concrete `ip:port`, matching every node on the path |
| Identifier | `probe.ScopedEvidenceID(scope, step, endpoint, addr)` — two components, as every other PostgreSQL step |

**Attributes**

| Key | Kind | When | Consumer |
|---|---|---|---|
| `postgres.sasl_mechanism` | string | whenever a mechanism was chosen or declined | which mechanism this node is about; the error must be read against it |
| `postgres.scram_iterations` | int | when a server-first message parsed | explains an excessive-iteration refusal; the only fact that can state a weak server configuration (§16) |
| `postgres.sqlstate` | string | on an `ErrorResponse` | already contract from Phase 4.3 |
| `postgres.error_severity` | string | on an `ErrorResponse` | the non-localized `V` field only |
| `postgres.error_is_native` | bool | on an `ErrorResponse` | whether `V` was present — the pooler signal (ADR 0036 §10) |

`postgres.sasl_mechanism` is a **separate key** from the startup node's
`postgres.sasl_mechanisms`, for the reason ADR 0030 gives for the identical Kafka pair: one
means *what was offered*, the other means *what is being used*. One key, one meaning.

`postgres.scram_iterations` is recorded with no rule reading it today, on the precedent of
Kafka's `kafka.sasl.session_lifetime_ms` — a target configuration fact nothing else in a run
reports. Unlike that one it has a named future consumer in §16 and in Phase 4.6.

**Never recorded, under any circumstances.** The password; the prepared password; the client
nonce; the server nonce; the salt; `SaltedPassword`; `ClientKey`; `StoredKey`;
`ClientSignature`; `ClientProof`; `ServerKey`; `ServerSignature`; the `AuthMessage`; the
`c=` channel-binding value; any `e=` token; any `ErrorResponse` field other than `C` and `V`;
and the role, which is already on the startup node as `IdentityAttr` and would be a second
representation of one fact.

The salt and the nonces are not passwords, and they are still absent: they are per-exchange
authentication material with **no diagnostic consumer**, and ADR 0036 §9 already names the
salt and nonce on its never-an-attribute list. An attribute nobody reads is a leak surface
with no benefit.

The leak matrix required by Phase 4.4b asserts exact canary absence for every value above —
in evidence, in the report, in every `fmt` verb, in every error, and in JSON — the way
`test/security/kafka_auth_redaction_test.go` does for PLAIN.

### 18. Secret lifetime, classified, with no claim of erasure

| Value | Class | May leave `wire` | May enter evidence / errors / logs |
|---|---|---|---|
| plaintext password (`Reveal` result) | **secret** | no | no |
| its ASCII-range check result | safe protocol fact | no (nothing needs it) | no |
| client nonce | credential-adjacent authentication material | no | no |
| server nonce | server-provided challenge | no | no |
| salt | server-provided challenge | no | no |
| iteration count | **safe protocol fact** | **yes** | **yes** — §17 |
| `SaltedPassword` | credential-derived | no | no |
| `ClientKey`, `StoredKey` | credential-derived | no | no |
| `AuthMessage` | contains nonces and salt | no | no |
| `ClientSignature`, `ClientProof` | credential-derived | no | no |
| `ServerKey`, `ServerSignature` | credential-derived | no | no |
| verification verdict (a bool) | safe protocol fact | **yes** | as `StatePass` / `StateFail` |
| SQLSTATE, `V` | safe protocol facts | **yes** | **yes** |
| `M`, `D`, `H`, `F`, `L`, `R` | peer prose, identity-bearing | **no** | no |

`wire.SCRAMResult` — or whatever it is called — carries the verdict, the iteration count and
the `ErrorFields` already whitelisted in Phase 4.3, and has **no field any other row could
occupy**. Structural absence is the mechanism, as ADR 0030 §5 established: a caller cannot
leak a value the package never returns.

**No zeroization is performed and none is claimed.** `internal/security/doc.go` has stated
since Phase 1 that Go cannot guarantee erasure. The string `Reveal` returns is immutable and
the collector may already have copied it; `crypto/pbkdf2.Key` takes a `string` and copies it
internally; the derived slices are copied into the encoded frames. Zeroing anything here
would leave live copies untouched while implying the value was gone. ADR 0027 rejected a
`[]byte`-returning `Reveal` with documented zeroization for exactly this reason, and this
record does not weaken it. Memory exposure is addressed by process hardening.

### 19. `ErrorResponse` safety is inherited unchanged

`wire.ErrorFields` holds a SQLSTATE and the non-localized severity. There is no field for
`M`, `D`, `H`, the schema, table, column or constraint name, or the server's source file,
line and routine. **Phase 4.4b adds no field**, and a source scan asserts it.

This matters more at authentication than at startup. Every `28P01` message observed in the
study reads *"password authentication failed for user \"…\""* — the role, verbatim — and the
`28000` messages carry the role, the database and svcdoctor's own NAT-translated source
address as the server saw it, which appears nowhere else in the report and which structural
redaction therefore cannot pseudonymize.

### 20. Failure classification, complete

Two rules govern the State column and neither is this record's invention.

**An unsupported capability is `UNKNOWN`, never `FAIL`.** `internal/domain/state.go` names
*"svcdoctor does not support the capability"* as its first `StateUnknown` example,
`docs/ARCHITECTURE.md` and `CLAUDE.md` both state the rule outright, and
`internal/domain/evidence_test.go` already pins `{StateUnknown, FailureExecUnsupportedBySvcdoctor}`
as valid. Every row below whose class is `AUTH_MECHANISM_UNSUPPORTED` or
`EXEC_UNSUPPORTED_BY_SVCDOCTOR` is therefore `UNKNOWN`. `SKIPPED` is reserved for a step
intentionally not executed — a policy, a failed prerequisite, a privilege, a scope rule — which
is why row 1 and only row 1 carries it.

**`NOT_OFFERED` is a fact about the peer; `UNSUPPORTED` is a gap in svcdoctor**, and
`TestNotOfferedIsNotUnsupportedBySvcdoctor` in `internal/adapter/kafka` already pins that one
observation may never produce both. The tie-break when `SCRAM-SHA-256` is absent from an
advertised list: if `SCRAM-SHA-256-PLUS` **is** present, the only thing blocking svcdoctor is
its own lack of channel binding, so the row is `UNSUPPORTED` and `UNKNOWN`; otherwise the peer
genuinely does not offer what svcdoctor speaks, so the row is `NOT_OFFERED` and `FAIL`.

| # | Observation | State | FailureClass | Bytes sent |
|---|---|---|---|---|
| 1 | policy refuses this channel | SKIPPED | `EXEC_SKIPPED_BY_POLICY` | **0** |
| 2 | credential bound to a different endpoint | *(no node)* | *(Go error)* | **0** |
| 3 | password with a code point outside `U+0020`–`U+007E` | **UNKNOWN** | `EXEC_UNSUPPORTED_BY_SVCDOCTOR` | **0** |
| 4 | `SCRAM-SHA-256` not in the advertised list | FAIL | `AUTH_MECHANISM_NOT_OFFERED` | **0** |
| 5 | only `SCRAM-SHA-256-PLUS` advertised | **UNKNOWN** | `AUTH_MECHANISM_UNSUPPORTED` | **0** |
| 6 | `md5`, `cleartext`, `gss`, `sspi`, `kerberos`, `scm` demanded | **UNKNOWN** | `AUTH_MECHANISM_UNSUPPORTED` | **0** |
| 7 | mechanism list malformed | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | **0** |
| 8 | server-first unparseable / missing / duplicated attribute | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | client-first only |
| 9 | server nonce does not strictly extend the client nonce | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | client-first only |
| 10 | salt is not valid base64 | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | client-first only |
| 11 | `i` non-numeric or `< 1` | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | client-first only |
| 12 | `i > 1048576` | **UNKNOWN** | `EXEC_UNSUPPORTED_BY_SVCDOCTOR` | client-first only |
| 13 | server-final unparseable, or neither `v=` nor `e=` | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | full exchange |
| 14 | ServerSignature mismatch | FAIL | `AUTH_CREDENTIALS_REJECTED` | full exchange |
| 15 | `e=invalid-proof` / `unknown-user` / `invalid-username-encoding` | FAIL | `AUTH_CREDENTIALS_REJECTED` | full exchange |
| 16 | any other `e=` token | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | full exchange |
| 17 | `AuthenticationOk` with no server-final | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | full exchange |
| 18 | `ErrorResponse 28P01` | FAIL | `AUTH_CREDENTIALS_REJECTED` | up to that point |
| 19 | `ErrorResponse 28000` | FAIL | `AUTHZ_NOT_PERMITTED` | up to that point |
| 20 | `ErrorResponse 08P01` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` — never a credential claim; see §21 and amendment B | up to that point |
| 21 | `ErrorResponse`, any other SQLSTATE | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | up to that point |
| 22 | peer closed mid-exchange | FAIL | `PROTOCOL_PEER_CLOSED` | up to that point |
| 23 | local deadline expired | UNKNOWN | `EXEC_LOCAL_TIMEOUT` | up to that point |
| 24 | run cancelled | UNKNOWN | `EXEC_CANCELLED` | up to that point |
| 25 | ServerSignature verified **and** `AuthenticationOk` | **PASS** | `NONE` | full exchange |

Rows 4 and 5 are the distinction §5 draws and must not be collapsed — and note they differ in
*state* as well as class, because one is a peer fact and the other is svcdoctor's gap. Rows 14
and 18 share a class truthfully: both are refusals, in opposite directions.

**No row in this table may produce `AUTH_CREDENTIALS_REJECTED` for a cause that is svcdoctor's
own.** Rows 3, 5, 6 and 12 are the ones where that mistake would be easy and would be a lie:
in each, the peer never evaluated any authentication material, and in rows 3, 5 and 6 it never
received a byte of one. The sentence those rows assert is *"svcdoctor cannot perform this
authentication"*, never *"PostgreSQL rejected the credential"*.

**`28000` maps to `AUTHZ_NOT_PERMITTED` here for the same reason it does at startup**, and
the reason is the one the class was added for: no authentication material had been evaluated.
Measured `28000` cases at this step are the gs2 channel-binding negotiation error and
`pg_hba` refusals that arrive before any `AuthenticationXXX`.

**What `28P01` means, and the four things it does not.** It means: *the peer refused the
authentication material it was presented.* That is the whole claim.

It does **not** mean the password was wrong, that the role exists, that the role does not
exist, that an account is enabled, or that the peer's authentication backend was healthy.
This is not caution — it was measured. Wrong password, unknown role, a corrupted client
proof and a correct-but-un-normalized password produce **byte-identical** responses: same
SQLSTATE, same message template, same `F`/`L`/`R` source fields. The only differing byte is
the username the client itself supplied. PostgreSQL issues a mock salt for a non-existent
role deliberately, so that a client cannot enumerate roles. Naming a cause is a hypothesis
over frozen evidence and belongs to Phase 4.6.

### 21. pgBouncer: three degradations, none of them handled by pooler-specific code

Re-verified because authentication is exactly where Phase 4.0 found the vocabulary collapse,
against pgBouncer 1.25.2 in front of the same 18.6:

| Scenario | Wire | SQLSTATE | `V` |
|---|---|---|---|
| correct credential | SASLFinal → `AuthenticationOk` | — | — |
| wrong password | `ErrorResponse` in place of SASLFinal | `08P01` | **absent** |
| corrupted proof | identical to wrong password | `08P01` | **absent** |
| unknown role | `ErrorResponse` **before** `AuthenticationSASL` | `08P01` | **absent** |
| unknown database | **SASLFinal → `ErrorResponse`, no `AuthenticationOk`** | `08P01` | **absent** |

1. **`28P01` never fires.** A `08P01` arriving at the authentication step, after a
   client-final was sent, is classified `AUTH_CREDENTIALS_REJECTED` with `sqlstate=08P01`
   recorded beside it — because the peer *did* refuse the material it was presented, which is
   the entire content of that class. `08P01` arriving **before** any credential was presented
   is `PROTOCOL_UNEXPECTED_RESPONSE`. **The discriminator is svcdoctor's own protocol state,
   never the message text.**
2. **Unknown role moves to a different node.** pgBouncer refuses before sending
   `AuthenticationSASL`, so Phase 4.3's `postgres.startup` node sees it, `08P01` is unmapped
   there, and it classifies as `PROTOCOL_UNEXPECTED_RESPONSE`. Weak, and true.
3. **Unknown database is the sequence that forced §2.** The signature verified and
   `AuthenticationOk` never came.

No pgBouncer-specific production code, no version sniffing, no message matching.
`postgres.error_is_native` — `V` present — remains the one structural, non-prose,
non-identity signal, recorded as a fact and read by no rule. **svcdoctor still never says "I
reached PostgreSQL."**

### 22. Connection ownership

| Outcome | Evidence | Connection | Why the socket goes |
|---|---|---|---|
| authenticated | PASS | **kept** → `AuthenticatedSession` | — |
| `trust`, nothing to authenticate | *(no node)* | **kept** → `AuthenticatedSession` | — |
| credentials rejected (`28P01`, `08P01`, `e=`) | FAIL | closed | **protocol** — PostgreSQL closes after a FATAL |
| ServerSignature mismatch | FAIL | closed | **svcdoctor** — the peer is unproven; nothing may continue on it |
| malformed server-first or server-final | FAIL | closed | **protocol** — the socket's state is unknown |
| excessive iteration count | **UNKNOWN** | closed | **svcdoctor** — mid-exchange, with no legal continuation that does not satisfy the demand |
| mechanism not offered | FAIL | closed | **svcdoctor** — see below |
| mechanism unsupported by svcdoctor | **UNKNOWN** | closed | **svcdoctor** — see below |
| password outside the supported range | **UNKNOWN** | closed | **svcdoctor** |
| policy refusal | SKIPPED | closed | **svcdoctor** |
| endpoint mismatch | *(no node)* | closed | **svcdoctor** |
| peer closed | FAIL | closed | protocol |
| timeout / cancellation | UNKNOWN | closed | **protocol state** — a message may be in flight and a reply unread |

**The rows do not all close for the same reason and this record does not pretend they do** —
the mistake ADR 0030 §10 corrected for Kafka and explicitly told this phase not to repeat.

The last five rows discard a socket PostgreSQL would happily continue on: the server is
waiting for a `SASLInitialResponse`, or has not yet been sent one, and a corrected credential
would be a legal next message. **svcdoctor closes them anyway, because `Authenticate` is a
consuming ownership boundary.** Returning a live pre-authentication socket would give
ownership two exits, make retry semantics depend on which error was returned, and — the
decisive one — make "try several credentials against one endpoint" the easy thing to write.
That is credential spraying with a tidy API, and the singular signature exists to keep it
visible. A caller that wants to retry re-runs the chain, which re-measures what it is about
to authenticate over.

The socket being technically reusable is acknowledged and deliberately not exploited.

**No redial, no retry, no second mechanism, no second credential, on any row.**

### 23. A policy refusal always names its blocker, which Kafka's could not

```text
postgres.authentication   SKIPPED   EXEC_SKIPPED_BY_POLICY
    BlockedBy → result.ChannelEvidence()
```

| Channel | Blocker node |
|---|---|
| `tls-unverified` | `tls.handshake`, whose `tls.verified` is `false` |
| `plaintext` | **`postgres.ssl_request`**, which positively records that no TLS was attempted and why |
| `unknown` | whatever `ChannelEvidence` names; there is always one |

ADR 0030 §9 had to record a gap: on a Kafka plaintext path *"no node anywhere in the graph
states that TLS is absent"*, so the refusal carried no `BlockedBy`. **PostgreSQL closed that
gap in Phase 4.3.** Because encryption is negotiated in band, the `postgres.ssl_request` node
exists on every path — `PASS` with `offered=false`, or `SKIPPED` under the `disable` plan —
and it is a truthful record that this connection was left in the clear. `channelEvidence` is
set at both live `Session` construction sites, so `Startup` cannot produce a `StartupResult`
without one.

`Authenticate` still handles the absent case rather than asserting, and records no blocker
if one is ever missing. A fabricated blocker would make the report read as though something
had been established.

### 24. Endpoint mismatch produces a Go error and no evidence

`credential.SecretFor(endpoint)` returning `ErrEndpointMismatch` is a **defect in whoever
wired the call**, not an observation of the target. It is returned as an error wrapping
`ErrInvalidInput`, no node is recorded, and zero bytes are sent.

An evidence node would be svcdoctor reporting on its own caller — the target was never asked
anything, so there is no observation of it to record. `security.Credential`'s own
documentation already says a mismatch *"is a programming error, not a diagnostic result. It
must not be normalized into evidence."* This is the Kafka precedent (ADR 0030 §10) applied
unchanged.

The connection is closed, and **that closure is an ownership decision, not a protocol
requirement** — see §22.

### 25. Integration plan for Phase 4.4b

Unit and scripted-peer tests, in `internal/adapter/postgres` and `internal/adapter/postgres/wire`:

| Scripted-peer scenario | Asserts |
|---|---|
| full SCRAM against a fixed vector | message construction, byte for byte |
| `AuthenticationOk` with **no** server-final | FAIL, not PASS — §2 |
| server-final with a **forged** `v=`, then `AuthenticationOk` | FAIL — the OK does not rescue it |
| server nonce equal to the client nonce | `PROTOCOL_MALFORMED_RESPONSE`, no proof computed |
| server nonce not prefixed by the client nonce | `PROTOCOL_MALFORMED_RESPONSE` |
| `i=2147483647` | `EXEC_UNSUPPORTED_BY_SVCDOCTOR`, **and the test completes in milliseconds** |
| `i=0`, `i=-1`, `i=4x` | `PROTOCOL_MALFORMED_RESPONSE` |
| non-base64 salt; duplicated `r`; missing `s` | `PROTOCOL_MALFORMED_RESPONSE` |
| each `e=` token | §15's mapping |
| `AuthenticationOk` **then** `ParameterStatus` | Phase 4.4 returns at OK; the test reads the exact `ParameterStatus` frame off the returned conn — **zero bytes lost** |
| policy refusal, every channel | peer's protocol layer received **zero** bytes after startup |
| endpoint mismatch | zero bytes, Go error, no node |
| password boundary vectors | `U+001F` refused, `U+0020` accepted, `U+007E` accepted, `U+007F` refused, `U+00A0` refused, `U+00AD` refused, ordinary ASCII accepted |
| invalid UTF-8 password | refused by the same test |
| every refusal row of §20 | asserts the **State** as well as the class — `UNKNOWN` for rows 3, 5, 6 and 12, and **never** `AUTH_CREDENTIALS_REJECTED` |
| `Reveal` reachability | rows 4, 5, 6 and the policy and endpoint rows reach neither `SecretFor` nor `security.Reveal` |
| non-ASCII password | zero bytes, `UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR`, no nonce generated, no PBKDF2 run |
| leak matrix | password, prepared password, nonces, salt, every SCRAM intermediate, `M`/`D`/`H`, `e=` token — absent from evidence, report, errors, every `fmt` verb, JSON |
| ownership | exactly one owner at every instant; no redial; every non-PASS closes |

Real servers, folded into the Phase 4.8 matrix:

| # | Scenario | Expected |
|---|---|---|
| 1 | verified TLS + correct password | PASS |
| 2 | verified TLS + wrong password | FAIL `AUTH_CREDENTIALS_REJECTED`, `28P01` |
| 3 | verified TLS + unknown role | **identical to 2** — the test asserts they are indistinguishable |
| 4 | plaintext + password | SKIPPED, `EXEC_SKIPPED_BY_POLICY`, blocked by `postgres.ssl_request` |
| 5 | unverified TLS + password | SKIPPED, blocked by `tls.handshake` |
| 6 | endpoint mismatch | Go error, no node |
| 7 | `md5` role | UNKNOWN `AUTH_MECHANISM_UNSUPPORTED`, zero bytes, no `Reveal` |
| 8 | `password` (cleartext) role | UNKNOWN `AUTH_MECHANISM_UNSUPPORTED`, zero bytes, no `Reveal` |
| 9 | `trust` role | no authentication node, session continues |
| 10 | `scram_iterations=65536` role | PASS, `postgres.scram_iterations=65536` |
| 11 | non-ASCII password role | UNKNOWN `EXEC_UNSUPPORTED_BY_SVCDOCTOR`, zero bytes |
| 12 | 14.24 and 18.6 | identical outcomes for 1–11 |
| 13 | pgBouncer, correct credential | PASS |
| 14 | pgBouncer, wrong password | FAIL `AUTH_CREDENTIALS_REJECTED`, `sqlstate=08P01`, `error_is_native=false` |
| 15 | pgBouncer, unknown role | classified at `postgres.startup`, not at authentication |
| 16 | pgBouncer, unknown database | **PASS at authentication**, and Phase 4.5 fails |

**Oracles.** `psql` proves a session was establishable, which is the same claim. Server logs
are read only to confirm what svcdoctor *cannot* know — case 3, where the log is the only
place wrong-password and unknown-role are distinguished. **A server log never improves a
svcdoctor classification**; it only validates the honesty of a claim svcdoctor declines to
make.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Accept `AuthenticationOk` as success without verifying the signature | A peer that never proves itself gets a PASS, and the mutual half of a mutual mechanism is discarded. RFC 5802 §5 says MUST | Never |
| Treat a verified signature as success without `AuthenticationOk` | Measured false: through pgBouncer the signature verifies and an `ErrorResponse` follows | Never |
| Send the raw password without SASLprep | Measured to produce a false `28P01` on 14.24 and 18.6 for a correct password | Never |
| Add `github.com/xdg-go/stringprep` in Phase 4.4b | Its failure mode is a silent disagreement with `pg_saslprep` that reappears as the same false `28P01`, somewhere harder to find. The ASCII subset is provable; two-implementation Unicode equivalence is not, without a differential harness | §11.3 |
| Use `golang.org/x/text/secure/precis` | PRECIS `OpaqueString` uses NFC and does not delete B.1; it fails the soft-hyphen case | Never |
| Hand-write SASLprep with local Unicode tables | NFKC needs full decomposition and composition tables; a hand-copied subset is the security-hostile option | Never |
| Hand-write PBKDF2 | `crypto/pbkdf2` is in the toolchain. Writing crypto to avoid an import that already exists | Never |
| Bound iterations at the server's own maximum | `2147483647`, ≈ 8 minutes of CPU for four bytes of ASCII. libpq's absence of a bound is not a licence | Never |
| Refuse `i < 4096` | RFC says SHOULD, the GUC minimum is 1, and refusing makes svcdoctor blind to the weak configuration it should be reporting | Never |
| Implement MD5 because it is easy | Widens credential transmission to a second `Reveal` path for a deprecated mechanism, in the phase whose purpose is keeping that surface at one per service | §6 |
| Implement cleartext because verified TLS makes it "safe" | Verified TLS protects against the network, not against the peer, and cleartext hands the peer the password itself. A different threat model from the one the policy covers | §7 |
| Fall back from SCRAM to MD5 after a rejection | Two authentication attempts on one connection, a second lockout-relevant act, and evidence that no longer says which mechanism the result describes | Never |
| Fall back from `-PLUS` to `SCRAM-SHA-256` as a *downgrade* | Not a fallback: `n,,` is a truthful statement by a client that does not implement channel binding, and PostgreSQL accepts it. A fallback would be retrying after a failure, which does not happen | Never |
| Send `y,,` when only `SCRAM-SHA-256` is offered | Measured to be accepted, and it is a false claim: svcdoctor does not support channel binding. `n` is truthful on every channel | Never |
| Send the role in the SCRAM `n=` field | PostgreSQL ignores it — measured with a deliberately wrong value, which still authenticated. It would add a second place a role must be SCRAM-escaped | Never |
| Send an `authzid` in the gs2 header | PostgreSQL refuses it: `0A000 "client uses authorization identity, but it is not supported"` | Never |
| Record the salt, nonces or iteration-derived values as evidence | Per-exchange authentication material with no consumer; a leak surface with no benefit. ADR 0036 §9 already names them | Never |
| Record the `e=` token | `server-error-value-ext` means it is not a closed set; a peer may put arbitrary text there | Never |
| Classify by the `M` field | It carries the role, the database, and svcdoctor's own NAT-translated address, and structural redaction cannot pseudonymize the last of those | Never |
| Add pgBouncer detection | `08P01` is classified by svcdoctor's own protocol state, never by the peer's identity or prose | Never |
| Read `ParameterStatus` "while we are here" | Steals Phase 4.5's bytes; measured at 455 for one connection | Never |
| Use a `bufio.Reader` for the exchange | Same defect, measured | Never |
| Record a `PASS` authentication node for a `trust` role | svcdoctor presented nothing; claiming authentication would be the overclaim `AUTHZ_NOT_PERMITTED` exists to avoid | Never |
| Return the live pre-authentication socket on a refusal | Makes credential spraying the easy thing to write, and gives ownership two exits | A non-credential operation becomes legal on a post-startup socket |
| Record an endpoint mismatch as evidence | svcdoctor reporting on its own caller for an operation that was never authorized | Never |
| Widen the `forbidigo` exclusion for `postgres/wire` | Not needed: `internal/adapter/[^/]+/wire/` already matches, verified in both directions | Never |
| Put SCRAM in `internal/security` | It would need a mechanism vocabulary that package deliberately does not have | Never |
| Zero the derived key material after use | `crypto/pbkdf2` copies the password string, the frames copy the derived bytes, and Go strings cannot be erased. It would imply a guarantee Phase 1 refuses | Never, absent a language-level guarantee |
| An `AuthResult` wrapper as Kafka has | Nothing can follow a refusal here — Phase 4.5 needs an authenticated socket — so the evidence identifier has no consumer | A caller appears that must name a refused node |
| A generic SASL framework across Kafka and PostgreSQL | Two mechanisms, two wire formats, two framings, and no third caller. `docs/ARCHITECTURE.md`: concrete first | A third service needs SCRAM and the duplication is proven |

## Consequences

- svcdoctor will authenticate to a PostgreSQL endpoint with SCRAM-SHA-256 over verified TLS,
  on one caller-chosen path, and report the outcome as normalized evidence.
- **Authentication PASSes only when svcdoctor proved the server *and* the server accepted
  svcdoctor.** A peer that skips its half of the proof fails, whatever it sends afterwards.
- A credential cannot cross plaintext or unverified TLS, and the refusal is a report line
  that — unlike Kafka's — always names the node that caused it.
- **Two** production `security.Reveal` call sites after Phase 4.4b, one per service, with no
  lint change.
- **No new dependency.** SCRAM is `crypto/pbkdf2`, `crypto/hmac`, `crypto/sha256`,
  `crypto/rand` and `encoding/base64`. Still one runtime module, zero transitive.
- **No new `FailureClass`, no `domain` change, no report schema change, no redaction change.**
  Two attribute keys are added under the existing `postgres.` namespace.
- A password containing any code point outside `U+0020`–`U+007E` is refused as `UNKNOWN` +
  `EXEC_UNSUPPORTED_BY_SVCDOCTOR` — a truthful "svcdoctor cannot do this", never a false
  "PostgreSQL rejected your credential". This is the narrowest scope that cannot lie, and
  §11.3 is how it widens.
- **Every outcome that is a gap in svcdoctor is `UNKNOWN`, and every outcome that is a fact
  about the peer is `PASS` or `FAIL`.** No refusal that svcdoctor originates can be read as a
  statement about the target.
- `security.Reveal` is reached only after the channel, the mechanism and the endpoint binding
  have all been cleared, so an md5, cleartext, GSS or `-PLUS`-only endpoint never causes a
  secret to be unmasked at all.
- A server-chosen work factor is bounded at 1 048 576 iterations, so a hostile peer cannot
  buy minutes of a diagnostic tool's CPU with four bytes.
- Phase 4.5 receives a live socket whose next unread byte is the first `ParameterStatus`.

## Amendments from implementation (Phase 4.4b)

Two sections were written against the protocol and turned out to be imprecise against the
code. Neither changes a security property; both are recorded here rather than edited into
the sections above, because a record that quietly rewrites itself teaches nothing.

### A. Section 8: the mechanism gate runs *before* the channel policy

Section 8 wrote the ordering as channel → policy → mechanism → endpoint → `SecretFor`. The
implementation runs mechanism → channel → policy → endpoint → `SecretFor`.

Both orders send zero bytes and reach no `Reveal` on every refusal path, so this is not a
security difference. It is a **truthfulness** difference, and it shows up when two
conditions fail at once. A peer demanding md5 over a plaintext channel would, under the
original order, be reported as a policy refusal — which implies that fixing TLS would make
it work. It would not: svcdoctor cannot perform md5 on any channel. The mechanism fact is
the one that survives every remedy, so it is the one reported.

Putting the mechanism gate first has a second consequence worth stating plainly:
`credential.SecretFor` is never called, and `security.Reveal` never reached, for an endpoint
svcdoctor cannot authenticate to at all — md5, cleartext, GSS, SSPI, Kerberos, SCM, a
`-PLUS`-only list, or a list without `SCRAM-SHA-256`.

### B. Section 21: `08P01` is not mapped at all

Section 21 said an `08P01` arriving "after a client-final was sent" is
`AUTH_CREDENTIALS_REJECTED`. An intermediate draft narrowed that to
`ProofSent && !Verified`. **Both are wrong, and the implemented behaviour maps
`08P01` to nothing at all.** It falls through to
`PROTOCOL_UNEXPECTED_RESPONSE` with the code recorded as an attribute.

The narrowing was caught by a pre-commit adversarial pass that asked what the
evidence actually *proves*, rather than what it usually accompanies. Three
results, in increasing order of decisiveness.

**1. `08P01` is pgBouncer's "no specific code" value.** From its own source, in
`src/objects.c`:

> *"PgBouncer used to report SQLSTATE 08P01 (protocol_violation) for all cases but
> it diverges from what Postgres reports in some cases."*

`disconnect_client()` passes a NULL sqlstate and pgBouncer substitutes `08P01`.
Every client-facing failure in `src/client.c` goes through it: SASL failure,
certificate failure, `no such user`, an unconfigured or disabled auth database,
`old V2 protocol not supported`, `SSL required`, `unsupported startup parameter`,
an over-long username or password, and all three `max_client_conn` limits.

**2. The protocol position does not isolate the credential case.** In pgBouncer's
SCRAM path two conditions send an error after the client-final and before the
server-final: a proof that did not verify, and *a nonce that did not match*. The
second is a protocol fault. Nothing on the wire distinguishes them.

**3. Measured against pgBouncer 1.25.2, the same cause moves between positions.**
A wrong password lands at `ProofSent=true, Verified=false` for a role whose
verifier the pooler holds, and *before any SASL message at all* for one it must
fetch — and a **correct** credential lands in that same earlier position when the
pooler cannot serve the role. So the discriminator tracks the pooler's cache
state, not the cause. The full matrix is in
`docs/validation/POSTGRES_PHASE4_SCRAM_STUDY.md` section 15.

`AUTH_CREDENTIALS_REJECTED` claims *the peer refused the authentication material
it was presented*. `08P01` proves only that the exchange ended with the peer's
generic error code. Deriving the first from the second is a hypothesis about a
cause, and ADR 0014 puts hypotheses in diagnosis, over frozen evidence — not in a
producer.

**Nothing a rule needs is lost.** `postgres.sqlstate` records `08P01` and
`postgres.error_is_native` records that `V` was absent, which is the structural
signal that the responder is not a genuine backend. A Phase 4.6 rule may combine
them into a hypothesis. This layer states the weaker true claim, which is the
conservative floor ADR 0036 section 10 asks for.

`wire.SCRAM.ProofSent` was removed with the inference it existed to support,
rather than left available for the next caller to reach for.

**This also corrects ADR 0036 section 10**, which wrote that a pooler's refusal
"honestly records `AUTH_CREDENTIALS_REJECTED` with `sqlstate=08P01`, because the
peer did refuse the material it was presented". The second clause does not follow
from `08P01`, for the reasons above. The rest of that section stands unchanged,
including the rule it exists to state — that no finding may assume `28P01` fires,
and that svcdoctor never claims to have reached PostgreSQL.

### C. Two blanket lint grants were narrowed

Not a decision change; recorded because the boundary this record relies on was looser than
the record described. Verifying `forbidigo` in **every** direction rather than only the two
that were expected found that the `internal/adapter/[^/]+/wire/` exclusion named no message
text, so it exempted wire packages from the channel-authority rules ADR 0029 reserves to
`internal/probe/tls`; and that Phase 4.3's plaintext grant to `internal/adapter/postgres/`
was a path prefix that also covered `wire/`. Neither was exploited. Both now match by
message text and by a path that stops at the directory, and ten directions are verified.

### D. Section 15's normalization of a server-signature mismatch was unsound (Phase 4.6a.5)

**A correction, not a rewrite.** Everything this record decided about the *wire*
stands: success is still the conjunction of a verified signature and
`AuthenticationOk`, the reveal boundary is unchanged, and no measurement is
revised. What was wrong is one line of **normalization** downstream of it.

`internal/adapter/postgres` mapped both SCRAM failure sentinels onto one class:

```text
wire.ErrSCRAMRejected            -> AUTH_CREDENTIALS_REJECTED
wire.ErrServerSignatureMismatch  -> AUTH_CREDENTIALS_REJECTED
```

justified in the code comment as *"it is a mutual mechanism, so the refusal is
mutual"*. That reasoning does not survive contact with the class contract.
`FailureAuthCredentialsRejected` states *"the peer refused the authentication
material it was presented"* — and on the second path the peer did no such thing.
A SCRAM server sends a server-final **only after accepting the client proof**; a
peer that rejects the proof answers with an error in its place and never sends a
signature at all. So `ErrServerSignatureMismatch` is reachable only where the
peer **accepted** the material and then failed to prove itself, and the class
asserted the opposite of what happened.

Two directions, and they are not the same observation:

```text
peer -> svcdoctor    the peer refused what it was presented       AUTH_CREDENTIALS_REJECTED
svcdoctor -> peer    the peer could not prove itself to svcdoctor AUTH_PEER_VERIFICATION_FAILED
```

Corrected in Phase 4.6a.5 by adding the second class to `internal/domain` —
generic, naming no mechanism — and splitting the branch. ADR 0040 §5.1 carries
the reasoning and states the reusable invariant. **This record's §15 mapping
table should be read with that split applied.**

A second, smaller correction rode along. §15 grouped three RFC 5802 server-error
tokens as rejections; `e=invalid-username-encoding` is an **encoding fault in the
username field**, not a decision about the material, and now yields
`ErrUnexpectedResponse`. It stays unreachable for the reason §15 already gave —
this client sends an empty username — so nothing observable changes.

Neither correction touches a byte on the wire, the `security.Reveal` boundary,
the evidence attribute set, redaction, or the report schema.

## Reopen conditions

- **A differential SASLprep harness against `pg_saslprep`, or a real deployment blocked by
  the ASCII restriction** — §11.3. The restriction is a failure class, so widening changes no
  contract here.
- **A managed service that offers md5 or cleartext and not SCRAM** — §6, §7. Both stay
  declined until a deployment is undiagnosable rather than unusual.
- **A peer that advertises only `SCRAM-SHA-256-PLUS`** — §5's second row becomes a measured
  case rather than a defensive one, and channel binding gains a reason. It needs a
  `internal/probe/tls` contract change first, with its own record.
- **A layer that can choose a transport policy** — the unsafe override, the second policy
  member and the `ReportSecurity` field arrive together, as ADR 0029 fixed. It is what would
  make plaintext PostgreSQL authenticable, and it is Phase 5's.
- **A peer observed sending `e=`** — §15's mapping stops being defensive and becomes testable
  against something real.
- **A third service needing SCRAM** — the duplication between `kafka/wire` and
  `postgres/wire` becomes evidence for a shared mechanism package rather than a guess about
  one.
- **A diagnosis rule that needs the authenticating identity** — the exclusion in §17 reopens,
  and ADR 0037's identity kind is now available where ADR 0030 had none.
