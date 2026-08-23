# ADR 0055: The shared SCRAM core never receives plaintext

## Status

**Accepted.** This record is the outcome of **Phase 6.2a**, the shared SCRAM core security
review that `docs/BACKLOG.md` and `TestNoSharedSCRAMPackageExists` require before any
extraction may begin.

The review's verdict is:

> **Model A is rejected.** Model D — a shared core that never accepts a password, receiving
> a derivation callback instead — is adopted in its place.

**Phase 6.2 implementation is therefore not authorized by this record.** It is authorized
by **Phase 6.2a-R2**, a short follow-up review that confirms Model D against a written API
and the conditions in §9. The gate test stays in place until that review is Accepted, and
it is to be deleted in the commit that records *that* acceptance.

Nothing here changes production code. `security.Reveal` retains exactly two production call
sites, both in wire packages, and this record narrows the future third — it does not create
one.

## Problem

Kafka SCRAM-SHA-256 needs RFC 5802 derivation that already exists, implemented on the
standard library alone, in `internal/adapter/postgres/wire/scram.go`. ADR 0026 §7.4's
dependency blocker is stale; no module is required. What remains is where the shared logic
lives.

`docs/ARCHITECTURE.md` §5.8 fixed a candidate in advance — **Model A**:

```text
PostgreSQL wire -> Reveal(secret) -> shared pure SCRAM core -> PostgreSQL framing
Kafka wire      -> Reveal(secret) -> shared pure SCRAM core -> Kafka framing
```

with the core forbidden to import `internal/security` or `net`, to call `Reveal`, to perform
I/O, to log, to put plaintext in errors, or to retain connection state. Plaintext enters as a
short-lived argument.

**This is the one place in the entire Kafka plan where a security boundary is relaxed rather
than tightened.** Today exactly two packages in this repository can observe a revealed
password: the two wire packages. Model A makes it three, and the third is shared, meaning
every future mechanism added to it inherits the widened boundary.

The question this review had to answer is not "is Model A survivable" — it is. The question
is whether the widening is *necessary*, and it is not.

## Observed evidence

All facts below were read from the tree at `e65a45b`, not from prior conversation.

**Reveal surface.** Two production call sites: `internal/adapter/postgres/wire/scram.go:179`
and `internal/adapter/kafka/wire/saslauthenticate.go:157`. `forbidigo` confines the call to
`internal/adapter/*/wire/` by an exclusion matched on the rule's message text, and
`TestPostgresCredentialSurfaceIsExactlyTwoCalls` pins PostgreSQL's count at exactly one in
exactly one file. **Kafka has no equivalent count guard** — see §9.7.

**Error safety, already sound.** `internal/adapter/postgres/wire` imports `fmt` in **no**
production file. Every error it produces is an `errors.New` sentinel with fixed text
(`conn.go:36-91`). There is nothing to fix before extraction; there is a property to preserve.

**Plaintext copies today.** `Reveal` returns the `string` held behind `secretValue.plaintext`.
Assigning it copies a string header, not bytes. `printableASCII` reads it without copying.
`crypto/pbkdf2.Key` takes a `string` and converts it for the HMAC key — that is the one
verbatim byte copy. **Two live copies of the plaintext bytes exist during a PostgreSQL
exchange, and the second is inside the standard library.**

**Model A adds zero plaintext copies.** Passing the same string across a package boundary
copies a header. This is the strongest argument in Model A's favour and it is a real one.

**Bound asymmetry, which the review found and which invalidates one of Model A's premises.**
`internal/adapter/postgres/wire.MaxMessageSize` is `1 << 20`. `internal/adapter/kafka/wire`'s
`maxResponseSize` is `8 << 20`. The two services bound peer-controlled payloads **eight times
apart**. "The wire already bounds it, so the core is safe" is therefore a service-specific
claim, not a property of the core.

**`parseServerFirst` decodes the salt before the iteration ceiling is applied**
(`scram.go`: nonce check, then `base64.StdEncoding.DecodeString(saltText)`, then
`parseIterations`). Bounded and not catastrophic, but the allocation precedes the refusal.

**Extraction is not only extraction.** `printableASCII`, `parseServerFirst`,
`scramAttributes`, `parseIterations`, `derive`, `mac`, `verifyServerFinal`, `cryptoNonce` and
the `serverFirst` struct are pure RFC 5802 and move cleanly. But the client-first-bare is
built as `"n=,r=" + clientNonce` — an **empty** username, correct for PostgreSQL because the
role travels in the `StartupMessage`. **Kafka has no startup message and the broker reads the
username from `n=`.** So Phase 6.2 must add:

- a username parameter that PostgreSQL passes empty;
- RFC 5802 §5.1 `saslname` escaping — `,` → `=2C`, `=` → `=3D`. **A repository-wide search
  found no escaping code of any kind.** It has never existed and has never been tested. An
  unescaped comma in a username does not merely produce a malformed message: it changes how
  the peer parses the attribute list *and* it changes the `AuthMessage` both sides sign;
- SASLprep treatment of the username, with the same honest refusal `printableASCII` gives a
  password;
- a Kafka `SaslAuthenticate` round trip that reads `SASLAuthBytes` — a field
  `wire.SASLAuthenticate` deliberately drops today — without exposing it to the adapter.

The existing RFC 7677 vector test passes `rfcClientFirstBare = "n=user,r=…"` as a literal into
`derive`. **The vector exercises the derivation; it has never exercised message construction
with a username.** That is exactly the code Kafka needs and exactly the code that does not
exist.

**Baseline.** `gofmt`, `go vet`, `golangci-lint` (0 issues), `go test`, `go test -race`,
`CGO_ENABLED=0 go build`, `git diff --check`, `go mod tidy`, `make check`,
`make integration-postgres` and `make integration-kafka` — all exit 0, the last two from clean
fixture lifecycles. The Phase 6.1c one-off `internal/cli` failure did **not** reproduce.

## Decision

### 1. Model A is rejected

Not because it is unsafe as specified. Because a strictly safer model achieves the same goal
at a cost this review measured and found small, and because Model A's safety is a **maintained**
property where the alternative's is a **structural** one.

Model A's guarantees all have the shape *"the core must not …"*: must not import
`internal/security`, must not log, must not `fmt`, must not retain, must not export, must not
implement `String`. Each is enforceable — by depguard, by lint, by a test — and each must keep
holding across every future edit, every future mechanism, and every future contributor.

This repository's stated doctrine is the opposite one. `scram.go` says it in the type comment:

> **Structural absence is the mechanism**: a caller cannot leak a value this package never
> returns.

ADR 0030 §5 says the same. The consistent application of that doctrine to a package that must
not leak a password is: **do not give it one.**

### 2. Model D: the core receives a derivation callback, never a password

```text
Kafka / PostgreSQL wire package
    Reveal(secret)                       plaintext exists here, and only here
    validate it locally
    scram.Continue(state, serverFirst, derive)
                                         core parses, validates, bounds,
                                         then calls derive(salt, iterations)
    derive closes over the plaintext and calls crypto/pbkdf2 in the wire package
    core receives a 32-byte SaltedPassword, builds the proof, verifies server-final
```

The shared core's API accepts **no `string` password and no password-shaped `[]byte`**. There
is no argument a caller could pass a plaintext to.

**This preserves the adjacency property ADR 0038 §16 calls "the whole point."** The callback is
invoked by the core *after* the iteration ceiling, the nonce-extension check, the salt decode
and the attribute validation have all passed. No PBKDF2 runs before the peer's demand has been
refused or accepted. A model that returned salt and iterations to the caller and let it derive
on its own would have lost that guarantee across a package boundary; this one does not.

**What crosses the boundary instead is the SaltedPassword.** That is credential-derived and
sensitive: it authenticates this principal to this server for this salt. It is not the
plaintext. It does not transfer to another service, another host, or the seventeen other places
an operator reused that password. **The blast radius of a future defect in the shared core drops
from "the operator's password" to "one account on one target."** That is the entire argument,
and it is worth ten lines.

### 3. What Model D costs, measured rather than asserted

Per wire package, an estimate from reading `scram.go`:

- one `crypto/pbkdf2.Key` call — one line, its parameters supplied by the core;
- `printableASCII`, roughly seven lines, which must live where the plaintext is;
- a closure literal at the call site — about three lines.

No cryptographic *construction* is duplicated. ClientKey, StoredKey, ClientSignature,
ClientProof, ServerKey, the expected ServerSignature, the AuthMessage assembly, the GS2 header,
the channel-binding value, both parsers, the nonce and every bound stay in one place, written
once, pinned by RFC vectors once. PBKDF2 is a single standard-library call whose arguments the
core hands it.

The one new misuse risk Model D introduces is a callback returning material derived with the
wrong hash. **The core rejects any returned length that is not 32 bytes**, which catches a
SHA-512 mistake (64 bytes) at the first call. A wrong-but-correctly-sized return produces a
failed authentication, not a security failure, and integration catches it.

### 4. The core owns the bounds, because the wire packages disagree

`MaxSCRAMIterations = 1 << 20` moves into the core and PostgreSQL's `wire.MaxSCRAMIterations`
becomes an alias, so no adapter-visible constant changes. The ceiling protects **svcdoctor's
CPU**, which is service-independent; the *failure class* it maps to stays with each adapter,
because `EXEC_UNSUPPORTED_BY_SVCDOCTOR` is a statement in a service's evidence model.

The core must additionally bound, independently of any caller:

| Bound | Why the core cannot inherit it |
|---|---|
| server-first message length | PostgreSQL bounds at 1 MiB, Kafka at 8 MiB — eight times apart |
| server-final message length | same |
| decoded salt length | decoded before the iteration ceiling; an 8 MiB salt allocates ~6 MiB first |
| server nonce length | peer-chosen, and the extension check does not bound it |
| attribute count | the parser allocates nothing per attribute, but the visitor call is unbounded |

A core that trusts its caller's framing bound is safe only for the callers that exist today.

### 5. Sentinel errors alias; PostgreSQL behaviour does not change

`internal/adapter/postgres/authenticate.go` classifies with `errors.Is` against
`wire.ErrPasswordUnsupported`, `wire.ErrIterationsUnsupported`,
`wire.ErrServerSignatureMismatch` and `wire.ErrSCRAMRejected`. The core defines its own
sentinels; each wire package declares `var ErrSCRAMRejected = scram.ErrRejected` and so on.
`errors.Is` keeps matching, every existing failure class keeps mapping, and no test changes.

**If extraction requires changing any PostgreSQL failure class, finding, evidence attribute or
error text, that is a separate decision and Phase 6.2 stops.**

### 6. `string`, not `[]byte`, at the one boundary that still carries plaintext

Inside a wire package, plaintext stays a `string`:

- `security.Reveal` returns `string`, and ADR 0027 rejected a `[]byte`-returning `Reveal`
  precisely because a `Zero` method would imply a guarantee Go does not make;
- `crypto/pbkdf2.Key` takes a `string`. Converting to `[]byte` and back would add a copy to
  buy nothing;
- Go strings are immutable, so a `[]byte` could be cleared — but clearing one copy while the
  original string, the collector's possible relocation of it and the standard library's
  internal HMAC key all persist is theatre. `internal/security/doc.go` has said since Phase 1
  that Go cannot guarantee erasure, and this record does not weaken it.

**No zeroization is performed and none is claimed.** Memory exposure is addressed by process
hardening.

### 7. Everything else the review settled

- **SHA-256 only in Phase 6.2.** The core is written for one mechanism. Hash-parametric
  abstraction is not built on speculation; SHA-512 is a reopen condition that must settle how
  the callback's hash is pinned.
- **No fallback, no downgrade, ever.** A failed SCRAM never retries as PLAIN. The core contains
  no mechanism selection, no retry and no fallback, and `supportedMechanism` stays an exact-match
  whitelist with no folding.
- **ADR 0050 is untouched.** The core does not know an endpoint, a host, a port, a broker node,
  a correlation ID or a connection. Endpoint authorization stays in the adapter, above the wire
  boundary. A Metadata-discovered broker gains nothing from this record.
- **Server signature verification stays mandatory.** No authentication PASSes without it, and
  the comparison stays `hmac.Equal`, which is constant-time.
- **Nonce extension stays strict**: prefix equality against svcdoctor's own generated value,
  plus a strict length increase. Never a search through peer-chosen text.
- **The nonce generator lives in the core**, with the unexported `nonceSource` function-type
  seam it has today. A test may inject a deterministic nonce; production has one source and it
  is `crypto/rand`. **No exported randomness abstraction.**
- **No new module dependency.** The count stays at one: `kmsg`.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| **Model A** — plaintext as a short-lived argument into the shared core | Adds a third package that can observe a password, to save an estimated ten lines per service. Its safety is maintained by lint and review rather than made impossible by the API. Zero extra copies is true and not sufficient | If Model D's callback proves unworkable against a real Kafka broker in a way this review did not foresee, Model A returns as the fallback — with §9's conditions **and** a depguard allowlist — not as the default |
| **Model B** — core returns salt and iterations, caller derives and calls back in | Loses the ADR 0038 §16 adjacency: nothing structurally prevents a caller from deriving before, or instead of, the core's validation. Model D is Model B with control inverted, which is what restores the property | Never; Model D dominates it |
| **Model C** — duplicate the derivation in both wire packages | Not rejected for looking ugly. Rejected because the duplicate would not be the tested code: the RFC 7677 vector would have to be maintained twice, the `saslname` escaping Kafka needs would be written fresh and unvectored, and the two copies would drift at exactly the points that fail silently — a proof that verifies against one server and not another. It has one real merit, that plaintext crosses nothing, and Model D captures that merit without the drift | If the shared core ever needs a second mechanism whose framing genuinely cannot share a state machine |
| Give `Reveal` a `[]byte` form for the core | ADR 0027 settled this; a `Zero` method implies a guarantee Go does not make | A language-level erasure guarantee |
| Let the core hold the mechanism-selection or fallback logic | It would put a downgrade decision in a package with no endpoint, no policy and no evidence model | Never |

## Consequences

- **Phase 6.2 is still blocked.** `TestNoSharedSCRAMPackageExists` stays. It is deleted in the
  commit that records Phase 6.2a-R2's acceptance of a written Model D API.
- `docs/ARCHITECTURE.md` §5.8's Model A constraints are superseded by this record and were
  corrected in the same commit, so the architecture document does not describe a rejected model
  as fixed.
- Phase 6.2 grew a prerequisite the plan did not have: `saslname` escaping and username
  handling are **new** RFC 5802 code, not extracted code, and need their own vectors.
- Kafka gains a `Reveal`-count guard it does not have today (§9.7), so "exactly two" becomes a
  property of the source on both sides rather than one.

## Phase 6.2 conditions

All of the following are required. Any one that cannot be enforced stops the phase.

1. The shared core exposes **no API accepting a password**, in any type.
2. It imports none of `internal/security`, `net`, `net/http`, `os`, `os/exec`, `log`, `log/slog`,
   `fmt`, `strings`, `crypto/pbkdf2`, or any `internal/adapter`, `internal/probe`,
   `internal/diagnosis`, `internal/render`, `internal/app` or `internal/service` package. Enforced
   by a depguard **allowlist**, landed with or before the package.
3. Permitted imports are exactly `crypto/hmac`, `crypto/rand`, `crypto/sha256`,
   `encoding/base64`, `errors` and `strconv`. `crypto/subtle` is not needed — `hmac.Equal` is
   already constant-time. `fmt` is denied outright rather than "allowed if proven safe": the
   PostgreSQL wire package proves fixed-text sentinels are sufficient.
4. No I/O, no connection state, no endpoint identity, no service framing.
5. Errors are `errors.New` sentinels with fixed text. No wrapping of peer-supplied bytes.
6. `security.Reveal` stays in wire packages; production call sites remain **exactly two**.
7. A repository-wide guard asserts that count, and a Kafka analogue of
   `TestPostgresCredentialSurfaceIsExactlyTwoCalls` pins Kafka's `Reveal` and `SecretFor` at one
   each.
8. State fields are unexported. No `String`, `GoString` or `Format` method on any state type.
   No exported field holds credential-derived material.
9. The state does not retain the derivation callback beyond the call that received it.
10. RFC 5802 and RFC 7677 vectors pin client-first-bare, server-first, client-final-without-proof,
    the AuthMessage, SaltedPassword, ClientKey, StoredKey, ClientSignature, ClientProof, ServerKey
    and the final verifier. Vectors additionally cover a username requiring `=2C` and `=3D`
    escaping — the case Kafka introduces and no existing test reaches.
11. Fuzz targets over the server-first parser, the server-final parser, the attribute walker, the
    iteration parser and base64 inputs. Properties: never panic; bounded allocation; no plaintext
    or peer bytes in any error; malformed input never authenticates; server-signature verification
    cannot be bypassed; duplicate mandatory attributes rejected consistently.
12. Adversarial parser cases decided and tested: missing / duplicate `r`, `s`, `i`; invalid base64
    salt; zero, negative, non-numeric, overflowing and over-ceiling iterations; empty values;
    malformed commas; unknown attributes ignored; mandatory `m=` refused; reordering accepted.
    Server-final: valid, wrong, malformed and non-base64 verifiers; `e=` alone; `v=` and `e=`
    together; neither.
13. The core's own size bounds per §4, independent of any caller's framing bound.
14. No test prints a password, a SaltedPassword or any derived key. No `%+v` over state. RFC
    public-vector credentials are labelled as such and kept distinct from fixture canaries.
15. The full PostgreSQL unit and integration suites pass unchanged, with identical failure
    classes, identical findings, no timing-semantic change, no redaction change and no new
    `Reveal` site.
16. Kafka SCRAM-SHA-256 is validated against the real three-broker fixture cluster, including a
    rejected credential and an unverified channel withholding the credential.
17. Advertised brokers still receive credential-free DNS, TCP and TLS and nothing else.

## Reopen conditions

- **SCRAM-SHA-512.** Needs a decision on how the callback's hash is pinned so a wire package
  cannot silently derive with the wrong one. The 32-byte length check is a SHA-256-only guard.
- **Channel binding (`-PLUS`).** Would change the GS2 header from `n,,` and give the core a
  reason to know something about the connection. It must not acquire that reason quietly.
- **A third service needing SCRAM.** Re-check §4's bound table; a third framing bound would be a
  third disagreement.
- **Model D failing against a real broker** in a way this review did not foresee — see the Model A
  row above.
- **TLS trust and identity policy** — system roots versus a custom CA, `--tls-ca-file` merge
  versus replace, bootstrap and advertised `ServerName` semantics, enterprise CA injection, future
  mTLS client-certificate authority. **Deliberately not decided here.** It is a separate
  security-sensitive design item and mixing it with secret authority would produce one record
  answering neither.
