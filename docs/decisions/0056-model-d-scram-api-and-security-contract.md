# ADR 0056: The Model D SCRAM API and security contract

## Status

**Accepted.** This record is the outcome of **Phase 6.2a-R2** and it is the implementation
contract for Phase 6.2.

ADR 0055 remains the record that rejected Model A and selected Model D for further review.
This record makes Model D precise enough to build: the exact API, the exact callback contract,
the exact bounds, the exact ownership rules and the exact guards.

**Phase 6.2 implementation is authorized**, subject to §14's prerequisites.

**Implemented in Phase 6.2.** `internal/sasl/scram` exists, PostgreSQL was migrated onto it
with no semantic change, and Kafka SASL/SCRAM-SHA-256 is validated against the real
three-broker KRaft cluster. `security.Reveal` still has exactly two production call sites.

Five things the implementation had to settle that this record did not, each recorded here
rather than left in a commit message:

1. **`GS2Header` is exported**, which §2 did not list. §2 asked `Begin` to return the
   client-first-*bare* while also claiming the core and its callers could not drift on the
   header — and those are only both true if there is one definition. A wire package holding
   its own `"n,,"` could drift from the header the core signs into the AuthMessage, and the
   symptom would be a signature mismatch rather than a visible disagreement.
2. **Two sentinels beyond §8's nine**: `ErrNoDerivation` for a nil callback, reported rather
   than panicking so the fuzz targets' never-panic property is total, and
   `ErrDerivationFailed`. The second is a security decision §8 left open: a callback's error
   is **discarded, never wrapped**, because the callback runs in a wire package with the
   plaintext in scope and any error it produces could carry credential material.
3. **The single Kafka reveal boundary.** The first implementation gave PLAIN and SCRAM an
   exported exchange each, and each revealed its own secret — an ordinary structure that
   quietly took the repository from two production reveal sites to **three**. `wire.Authenticate`
   now reveals once and dispatches on the plaintext, which also puts the framing choice in the
   package that owns framing.
4. **Two new reachable outcomes needed owners before the producer could land** (ADR 0054).
   SCRAM authenticates both parties, so `AUTH_PEER_VERIFICATION_FAILED` became reachable at
   `kafka.sasl_authenticate` and required a new code, `KAFKA_PEER_VERIFICATION_FAILED` —
   mirroring `POSTGRES_PEER_VERIFICATION_FAILED`, not inventing a concept. The
   printable-ASCII and local-derivation refusals made `UNKNOWN` +
   `EXEC_UNSUPPORTED_BY_SVCDOCTOR` reachable, and that reuses the existing
   `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` rather than dividing one operator-facing
   fact in two. **Both owners landed in the same change-set as the producer.**
5. **A nonce change was made, measured, and reverted.** The implementation narrowed the client
   nonce to an alphanumeric alphabet on the theory that Kafka's `ClientFirstMessage` regex
   constrains it to `[a-zA-Z0-9-]` and would reject base64's `+` and `/`. Tested against
   Kafka 4.0.0: **both characters are accepted and the exchange completes.** The change was
   reverted rather than kept as a harmless extra, because a narrower alphabet defended by a
   false reason is worse than no change — the next reader would have believed the reason.

**This record supersedes one sentence of ADR 0055.** That record said
`TestNoSharedSCRAMPackageExists` "is to be deleted in the commit that records *that*
acceptance" — this one. That is wrong, and §13 replaces it: deleting the negative guard now
would leave every commit between this record and Phase 6.2's first implementation commit
unguarded. The guard stays until it is replaced atomically.

No production Go changed in **Phase 6.2a-R2**, the review this record came from; the
implementation notes above describe Phase 6.2, which followed it. `security.Reveal` retains
exactly two production call sites in both phases, and both are in wire packages.

## Problem

ADR 0055 accepted Model D in outline: a shared SCRAM core that accepts no password and instead
receives a derivation callback, invoked only after the peer's server-first message has been
fully validated. It sketched three functions and one callback signature and explicitly declined
to treat that sketch as settled.

Three questions were left genuinely open, and each turned out to have a wrong answer that looks
reasonable:

1. **Does the core own the username, and therefore SASLprep?** RFC 5802 §5.1 says a client
   *SHOULD* SASLprep the username. Following that would be a defect — see §5.
2. **Who generates the nonce?** ADR 0055's sketch had `Begin(username, nonce)`, which pushes
   entropy authority to two callers.
3. **What may the state retain, and can misuse be made structural rather than documented?**

## Observed evidence

Verified at `40189ba`, from source and from primary specification text.

**Repository.** Working tree clean. `internal/sasl`, `internal/scram` and
`internal/crypto/scram` do not exist. `security.Reveal` has exactly two production call sites,
`postgres/wire/scram.go:179` and `kafka/wire/saslauthenticate.go:157`. One dependency
(`kmsg`). `SchemaVersion` 1. 40 production `FindingCode` values, 41 `FailureClass` members
including `FailureNone`. Kafka's `supportedMechanism` is an exact-match whitelist of
`wire.MechanismPLAIN`. `MaxSCRAMIterations = 1 << 20`. The BACKLOG note about the one-off
`internal/cli` failure is present and intact.

**PostgreSQL's failure classification matches four sentinels** with `errors.Is`, in
`internal/adapter/postgres/authenticate.go`: `wire.ErrPasswordUnsupported` (442),
`wire.ErrIterationsUnsupported` (444), `wire.ErrServerSignatureMismatch` (452),
`wire.ErrSCRAMRejected` (467). It does **not** match `ErrMalformedMessage` or
`ErrUnexpectedResponse` individually. That distinction decides §8.

**RFC 5802 §7**, quoted:

```
saslname        = 1*(value-safe-char / "=2C" / "=3D")
username        = "n=" saslname
value-safe-char = %x01-2B / %x2D-3C / %x3E-7F / UTF8-2 / UTF8-3 / UTF8-4
printable       = %x21-2B / %x2D-7E
```

**RFC 5802 §5.1**, quoted: *"Before sending the username to the server, the client SHOULD
prepare the username using the 'SASLprep' profile [RFC4013] … treating it as a query string …
If the preparation of the username fails or results in an empty string, the client SHOULD abort
the authentication exchange."* And: *"The characters ',' or '=' in usernames are sent as '=2C'
and '=3D' respectively. If the server receives a username that contains '=' not followed by
either '2C' or '3D', then the server MUST fail the authentication."*

Also §5.1 on the nonce: *"a sequence of random printable ASCII characters excluding ','"*. And
on `m`: *"its presence in a client or a server message MUST cause authentication failure when
the attribute is parsed by the other end."*

**Apache Kafka does not implement SASLprep.** `KAFKA-6272`, open since Kafka 1.0.0:
`ScramFormatter.normalize()` UTF-8 encodes and does nothing else, for both SASL/PLAIN and
SASL/SCRAM. This is a known, unfixed deviation from RFC 5802 and RFC 4616.

**PostgreSQL does implement SASLprep**, on both sides, and ADR 0038 §11 measured what happens
to a client that skips it: PostgreSQL 14.24 and 18.6 answer `28P01` for passwords containing
U+00A0 or U+00AD — *a correct password reported as rejected*.

**These two facts point in opposite directions**, and §5 is the consequence.

**Baseline.** `gofmt`, `go vet`, `golangci-lint` (0 issues), `go test`, `go test -race`,
`CGO_ENABLED=0 go build`, `git diff --check`, `go mod tidy` (no-op) and `make check` — all
exit 0.

## Decision

### 1. The package is `internal/sasl/scram`, and `internal/sasl` holds nothing else

Chosen on dependency direction and authority, not on naming.

`internal/security/scram` is refused: placing the core inside the package that owns secret
authority reads as though the core has some, when having none is the entire point, and every
depguard rule keyed on `internal/security/**` would need a carve-out. `internal/protocol/scram`
is refused: "protocol" is not a layer this architecture names.

`internal/sasl/scram` is a **leaf with no svcdoctor imports at all**. The dependency direction
is one-way and total: wire packages import the core; the core imports nothing internal, ever.

**`internal/sasl` must contain only `scram/`.** No `.go` file at the family level, no sibling
subpackage. ADR 0055 §7 and §19 of this review both forbid a generic SASL framework, and a
family directory is exactly how one would begin. A guard asserts the family's contents (§12).

### 2. The exact API

```go
package scram

// Mechanism name, iteration ceiling, and the derived-key length this core requires.
const (
	MechanismSHA256 = "SCRAM-SHA-256"
	MaxIterations   = 1 << 20
	DerivedKeyLen   = 32
)

// Username is the authentication identity, before SASLname escaping.
//
// A named type, so that passing a password here is an explicit, greppable
// conversion rather than an ordinary string argument. See §11 for what this
// does and does not prevent.
type Username string

// Derive computes the SCRAM SaltedPassword.
//
// The core calls it exactly once, only after every check in §4 has passed, and
// never retains it. salt is borrowed for the duration of the call. The returned
// slice must be exactly DerivedKeyLen bytes.
type Derive func(salt []byte, iterations int) ([]byte, error)

// State is one in-progress exchange. All fields are unexported. It has no
// String, GoString or Format method, and must be used through the pointer
// Begin returns.
type State struct{ /* §6 */ }

func Begin(user Username) (*State, string, error)
func (s *State) Continue(serverFirst string, derive Derive) (string, error)
func (s *State) Verify(serverFinal string) error
```

`Begin` returns the state and the **client-first-bare** (`n=<escaped>,r=<nonce>`). The GS2
header is not prepended: it is the caller's, because the caller frames it. The core exposes
`gs2Header` internally and uses it when it computes the channel-binding value, so the two
cannot drift — the property `TestChannelBindingValueIsComputedNotHardcoded` already pins.

Exported surface: three constants, three types, three functions, nine sentinels (§8). Nothing
else.

**No nonce parameter.** The core generates it — 18 bytes of `crypto/rand`, base64-encoded to
24 characters, matching libpq's `SCRAM_RAW_NONCE_LEN` and satisfying RFC 5802's `printable`
production. The unexported `nonceSource` function-type seam moves with it, and stays
unexported. A caller-supplied nonce would put entropy authority in two wire packages and make
a short, low-entropy or `math/rand` nonce a caller's mistake to make. One source, one length,
tested once.

PostgreSQL's `TestClientFirstMessageBytes` currently pins exact frame bytes via a deterministic
nonce. After extraction it pins the **framing** — `saslInitialResponse` applied to a fixed
payload string — which is precisely the responsibility that remains in that package. Exact
SCRAM payload bytes are pinned by the core's own vectors.

### 3. What the API structurally forbids

| Cannot be passed | Why |
|---|---|
| `security.Secret`, `security.Credential` | the core cannot import `internal/security`, so the types are unnameable in its signatures |
| `net.Conn` | the core cannot import `net` |
| a logger | no parameter, no `log`/`log/slog` import |
| an endpoint, host, port or broker node | no parameter carries one, and none is needed |
| PostgreSQL `Message` / kmsg types | the core cannot import either package |

All five are structural, not enforced. The one thing the API cannot structurally forbid is a
caller passing a **password as the `Username`** — see §11.

### 4. The derivation callback contract

**"Validation complete" means all of the following have passed, in this order, inside
`Continue`, before the callback expression is reached:**

1. the state is in the post-`Begin` step;
2. `len(serverFirst) <= MaxServerFirstLen` — checked **before any parsing**;
3. the attribute walk stays within `MaxAttributes`;
4. every attribute is at least two bytes with `=` as its second byte;
5. no `m` attribute is present (RFC 5802 §5.1: presence MUST fail authentication);
6. no duplicate `r`, `s` or `i`;
7. all three of `r`, `s`, `i` are present;
8. the server nonce is within `MaxNonceLen`, contains only RFC 5802 `printable`
   characters, and **strictly extends** the client nonce — prefix equality against this
   process's own generated value, plus a strict length increase;
9. the salt's *encoded* length is within `MaxSaltEncodedLen` **before** `base64.DecodeString`
   is called, and its decoded length is within `MaxSaltLen`;
10. the iteration count is all digits, parses, is `> 0`, and is `<= MaxIterations`.

Only then is `derive(salt, iterations)` evaluated. Immediately after, the returned slice's
length must equal `DerivedKeyLen` or the exchange fails with `ErrDerivedKeyLength`.

**Cardinality: exactly once on the successful `Continue` path, zero times on every other path.**
This is structural, not documentary: there is exactly one call expression on the callback
parameter in the entire package, it is not inside any loop, and the step machine (§6) makes a
second `Continue` an error before any parsing happens. A guard asserts both source properties
(§12).

**The callback must not be retained, must not be reachable from `Verify`, and must not run
asynchronously or after `Continue` returns.** `State` has no field of function type, `Verify`
takes no callback, and the package contains no `go` statement. All three are asserted.

**`salt` is borrowed.** It is valid only for the call. The core does not read it again after
the callback returns, so mutation is harmless; retention is forbidden by contract. No defensive
copy is made, because the salt is peer-supplied public data and a copy would buy nothing.

### 5. SASLname escaping is core-owned; SASLprep is refused, and that is a correctness decision

**The core owns SASLname escaping.** `,` → `=2C` and `=` → `=3D`, per RFC 5802 §5.1. This is
pure RFC grammar with no service content, it is the gap Phase 6.2a found — no escaping of any
kind exists in this repository — and duplicating it per service is exactly how the two copies
would drift.

**svcdoctor does not implement SASLprep, and restricts usernames and SCRAM passwords to
printable ASCII (U+0020–U+007E) instead.**

This is not a shortcut. Implementing SASLprep would be *wrong for Kafka*:

- PostgreSQL applies SASLprep on both sides. A client that skips it computes a different key
  for non-ASCII input, and the server answers `28P01` — a correct credential reported as
  rejected. Measured, ADR 0038 §11.
- Apache Kafka does **not** apply it (`KAFKA-6272`, open since 1.0.0). A client that *does*
  apply it computes a different key for non-ASCII input, and authentication fails.

**The two services require opposite behaviour for non-ASCII input.** There is no shared core
that is correct for both. Over printable ASCII, SASLprep is provably the identity — no
mapping-table member is ASCII, NFKC is the identity because no ASCII code point decomposes and
no ASCII pair composes, and the prohibited ASCII set is U+0000–U+001F with U+007F — so over
that range both services agree and svcdoctor is correct against both.

Restricting is therefore the *only* choice that is correct for both, and it happens to also
need no Unicode dependency. The dependency count stays at one. **A non-ASCII username or
password produces `UNKNOWN` plus a capability failure class — "svcdoctor cannot do this" — and
never a claim that the peer rejected the credential.** That is the policy PostgreSQL passwords
already ship with.

Two consequences worth stating plainly:

- **The empty username is a deliberate deviation, carried forward.** RFC 5802's `saslname` is
  `1*(...)`, so `n=` with nothing after it is not grammatical, and §5.1 says a client SHOULD
  abort on an empty prepared username. PostgreSQL requires exactly that, because the role
  travels in the `StartupMessage` and the server ignores the attribute — verified against a
  real server with a deliberately wrong value, which still authenticated. The core therefore
  **accepts an empty username**, and rejecting empty is the caller's job. Kafka must reject it
  before calling `Begin`, through the required-input path it already has.
- **Kafka SASL/PLAIN is not changed.** The printable-ASCII password restriction is
  SCRAM-specific, because SCRAM *derives* from the password and a mismatch becomes a silent
  authentication failure attributed to the peer. PLAIN transmits verbatim and has no
  client-side derivation to get wrong. Nobody should harmonize the two.

The password check stays in each **wire** package, where the plaintext is. The username check
and escaping live in the core, because a username is not a secret and the reason for the
restriction is RFC-level rather than service-level.

### 6. State: what it holds, and a three-step machine

`State` is used only through the pointer `Begin` returns. Every field is unexported.

| Step | Retained | Class |
|---|---|---|
| after `Begin` | `clientFirstBare`, `clientNonce`, `step` | credential-adjacent; never leaves the core |
| after `Continue` | `expectedServerSignature` (32 bytes), `step` | credential-derived; never leaves the core |
| after `Verify` | `step` only | — |

**The state is minimized at each step.** `Continue` computes both the client proof and the
expected server signature from the AuthMessage and then drops the AuthMessage, the
SaltedPassword, ClientKey, StoredKey, ServerKey, the client-first-bare and both nonces.
`Verify` needs only a 32-byte comparison, so nothing else survives it.

**The state never holds** a plaintext password, a `security.Secret`, a `security.Credential`,
the derivation callback, a `net.Conn`, an endpoint, a service identity or a logger. Several of
those are unnameable in the package; the rest are asserted.

The step field makes misuse an error rather than a silent wrong answer:

| Misuse | Result |
|---|---|
| `Continue` twice | `ErrWrongStep`, before any parsing and before any derivation |
| `Verify` before `Continue` | `ErrWrongStep` |
| `Verify` twice | `ErrWrongStep` |
| anything after a failure | `ErrWrongStep` — failure moves the state to a terminal step |

This is three lines of checking and one unexported field, and it removes two entries from
§12's mutation matrix. It is not a general state-machine abstraction and must not become one.

`State` is not safe to copy; the API returns only `*State`, so copying requires an explicit
dereference. No `noCopy` marker is added, because it would need `sync` in the allowlist to buy
a `go vet` diagnostic for a mistake the API shape already discourages.

### 7. Core-owned bounds

The two wire packages bound peer payloads **eight times apart** — PostgreSQL's
`MaxMessageSize` is 1 MiB, Kafka's `maxResponseSize` is 8 MiB — so the core cannot inherit a
caller's bound. All of these are **core policy**.

| Bound | Value | Prevents | Interop risk |
|---|---|---|---|
| `MaxServerFirstLen` | 4096 | parse and allocation abuse from a multi-megabyte message | none: a real server-first is ~90 bytes |
| `MaxServerFinalLen` | 4096 | same | none: a real server-final is ~46 bytes |
| `MaxSaltEncodedLen` | 172 | **the base64 allocation itself** | none: 16-byte salts are typical |
| `MaxSaltLen` | 128 | an absurd decoded salt | none: 8× the largest common value |
| `MaxNonceLen` | 256 | an unbounded server nonce entering the AuthMessage | none: real totals are 48–72 chars |
| `MaxAttributes` | 16 | an unbounded visitor loop | none: server-first carries 3, with room for extensions |
| `MaxUsernameLen` | 256 | an unbounded escaped username | none: PostgreSQL roles cap at 63 bytes |
| `MaxIterations` | `1 << 20` | PBKDF2 CPU exhaustion | none: 256× PostgreSQL's default |

**`MaxSaltEncodedLen` is checked before `base64.DecodeString` is called, and that ordering is
the point.** Today `parseServerFirst` decodes the salt before the iteration ceiling is applied,
so an 8 MiB salt from a Kafka-sized frame would allocate roughly 6 MiB before any refusal.
Bounding the encoded length first caps the decode at ~128 bytes.

### 8. Errors

Every core error is an `errors.New` sentinel with fixed text containing no peer payload, no
username, no nonce, no salt, no derived material and no plaintext. The core never wraps a
peer-supplied value. `fmt` is denied outright (§10), so this is structural rather than
disciplined — `internal/adapter/postgres/wire` already proves fixed-text sentinels are
sufficient by importing `fmt` in no production file.

```
ErrMalformedMessage  ErrUnexpectedResponse  ErrMessageTooLarge
ErrUsernameUnsupported  ErrIterationsUnsupported  ErrDerivedKeyLength
ErrRejected  ErrServerSignatureMismatch  ErrWrongStep
```

**Three PostgreSQL sentinels become aliases**, which preserves `errors.Is` identity and
therefore every existing failure class, with no test change:

```go
var (
	ErrIterationsUnsupported   = scram.ErrIterationsUnsupported
	ErrServerSignatureMismatch = scram.ErrServerSignatureMismatch
	ErrSCRAMRejected           = scram.ErrRejected
)
```

`ErrPasswordUnsupported` stays wholly wire-owned: the check that produces it inspects
plaintext, so it never moves.

**`ErrMalformedMessage` and `ErrUnexpectedResponse` are deliberately *not* aliased.** Those two
already exist in `internal/adapter/postgres/wire/conn.go` with framing meanings — *"postgres
message could not be decoded"*, *"peer response is not valid at this protocol step"* — and
aliasing would collapse two distinct meanings onto one identity. PostgreSQL's classification
does not match either individually, so the wire package **translates** the core's equivalents
into its own at the boundary. Translation preserves current behaviour exactly; aliasing would
have changed what those identities mean.

Kafka maps the shared sentinels into its own existing failure classes. `ErrUsernameUnsupported`
cannot fire for PostgreSQL, which passes an empty username.

**If extraction requires changing any PostgreSQL `FailureClass`, `FindingCode`, evidence
attribute, renderer output or public error text, Phase 6.2 stops** and that becomes a separate
decision.

### 9. Cryptography

Unchanged from the shipped implementation: PBKDF2-HMAC-SHA-256 with a 32-byte output,
HMAC-SHA-256 throughout, `ClientKey = HMAC(SaltedPassword, "Client Key")`,
`StoredKey = SHA256(ClientKey)`, `ClientSignature = HMAC(StoredKey, AuthMessage)`,
`ClientProof = ClientKey XOR ClientSignature`,
`ServerKey = HMAC(SaltedPassword, "Server Key")`,
`ExpectedServerSignature = HMAC(ServerKey, AuthMessage)`, GS2 header `n,,` (never `y,,`, which
is a downgrade claim), channel-binding value computed from the header actually sent, and
`hmac.Equal` for the verifier comparison — which is constant-time.

Server signature verification stays **mandatory**. No authentication PASSes without it.

**What the `DerivedKeyLen == 32` check proves, and what it does not.** It proves the callback
returned SHA-256-sized material, which catches the concrete mistake it exists for: a wire
package wiring SHA-512 into PBKDF2 and returning 64 bytes. It proves **nothing else**. It does
not prove PBKDF2 was used, that SHA-256 was the PRF, that the salt was used, that the iteration
count was honoured, or that the material is not arbitrary. What actually pins correctness is
the RFC 7677 vector executed end-to-end, password to proof, **inside each wire package** — see
§11's split.

### 10. Import allowlist

Exactly six, each required:

| Import | Required for |
|---|---|
| `crypto/hmac` | HMAC-SHA-256, and `hmac.Equal` for the constant-time verifier comparison |
| `crypto/rand` | the client nonce |
| `crypto/sha256` | `Sum256` for StoredKey, `New` for HMAC |
| `encoding/base64` | salt decode, proof and nonce encode |
| `errors` | the sentinels |
| `strconv` | `ParseUint` for the iteration count |

`crypto/subtle` is **not** required — `hmac.Equal` already wraps it. `strconv` is kept rather
than hand-rolling a seven-digit parser, because a stdlib parser with explicit overflow
behaviour is likelier to be correct than a bespoke one.

Denied: `crypto/pbkdf2` — which is the point of Model D — plus `fmt`, `strings`,
`internal/security`, `net`, `net/http`, `os`, `os/exec`, `log`, `log/slog`, `sync`, and every
package under `internal/adapter`, `internal/probe`, `internal/diagnosis`, `internal/render`,
`internal/app` and `internal/service`.

Enforced as a depguard **allowlist**, landed in the same commit as the package. If SASLprep
ever needs a Unicode dependency, that is a separate decision and does not widen this list.

### 11. What is not structural, stated plainly

Model D is stronger than Model A, and it is not airtight. Three residual risks, none of which
justify rejecting it:

**A password could be passed as the `Username`.** The `Username` named type makes it an
explicit, greppable conversion rather than an ordinary string argument, and the RFC vectors and
integration would fail immediately. But no API that accepts a username can structurally
distinguish one string from another. **This is caught by review, vectors and integration — not
by construction.**

**The callback closes over the wire package's scope, and the core cannot see what it captured.**
A closure could in principle capture the connection or the credential, which means the core's
"performs no I/O" property is precisely *"performs no I/O of its own"* — it can cause I/O by
invoking a caller-supplied function. This grants the wire package nothing it does not already
have: it already owns the socket and the only `Reveal`. But the weakening is real and is
recorded rather than argued away. A guard can assert the closure literal's captured identifiers
in each wire package; that guard is brittle, so **review is the primary control.**

**The SaltedPassword crosses the boundary and is not harmless.** It authenticates this
principal to this server for this salt and iteration count, and both StoredKey and ServerKey
derive from it. What Model D removes is *password reuse transfer*: a defect in the core leaks
one account on one target, not the credential the operator also used elsewhere. That is the
exact threat reduction, stated without inflation.

### 12. Guards

Mechanical wherever practical; AST or import-graph rather than grep.

| Guard | Asserts |
|---|---|
| depguard `sasl-core-is-a-leaf` | the §10 allowlist; no `internal/**` import at all |
| `TestSharedSCRAMFamilyHasOnlyScram` | `internal/sasl` contains only `scram/`; no family-level `.go` file |
| `TestSharedSCRAMCoreHasNoSecretSurface` | no `Reveal`/`SecretFor` selector; no `String`/`GoString`/`Format` method on `State`; no function-typed field on `State`; no `go` statement |
| `TestDerivationIsCalledOnceAfterValidation` | exactly one call expression on the `derive` parameter, not inside any loop |
| `TestDerivationUnreachableOnRejection` | a counting fake records **zero** invocations for each of: oversize message, bad grammar, `m=`, duplicate `r`/`s`/`i`, missing attribute, bad nonce charset, equal-length server nonce, oversize nonce, oversize salt, invalid base64 salt, iteration zero, malformed iteration, overflowing iteration, above-ceiling iteration |
| `TestKafkaCredentialSurfaceIsExactlyTwoCalls` | **new** — the Kafka analogue of the PostgreSQL guard: `Reveal` exactly once in `kafka/wire`, `SecretFor` exactly once in the adapter, neither anywhere else |
| `TestRepositoryRevealCountIsExactlyTwo` | **new** — AST walk over every non-test file outside `internal/security`: exactly two `security.Reveal` calls, at the two known paths. Fails on a third anywhere, and on a move above wire |
| existing composition suite | advertised brokers get no credential, one attempt per run, unverified channel withholds |

`TestKafkaCredentialSurfaceIsExactlyTwoCalls` and `TestRepositoryRevealCountIsExactlyTwo` close
a gap that exists **today**: `forbidigo` confines `Reveal` to wire packages and
`TestPostgresCredentialSurfaceIsExactlyTwoCalls` pins PostgreSQL at one, but nothing pins
Kafka's count and nothing asserts the repository-wide total.

### 13. The gate transition

**This is where a careless commit would open a hole, and ADR 0055 got it wrong.**

`TestNoSharedSCRAMPackageExists` fails the build if `internal/sasl`, `internal/scram` or
`internal/crypto/scram` exists. ADR 0055 said it should be deleted in the commit that records
this acceptance. That would leave every commit between this record and Phase 6.2's first
implementation commit with **no guard at all** — neither the negative one nor the positive ones,
which cannot exist until the package does.

The transition is therefore:

1. **This R2 commit.** ADR 0056 Accepted, Phase 6.2 authorized. The negative guard **stays**,
   unchanged. No Go changes.
2. **The first Phase 6.2 implementation commit, atomically.** It introduces
   `internal/sasl/scram`, deletes `TestNoSharedSCRAMPackageExists`, and adds the depguard
   allowlist and all of §12's positive guards **in the same commit**. Its message updates the
   deleted test's reasoning into the new guards' documentation.

There must never be a commit in which neither the negative guard nor the positive guards hold.
Splitting step 2 across two commits is the failure mode this section exists to prevent.

### 14. Phase 6.2 prerequisites

ADR 0055's seventeen conditions carry forward. This record adds:

1. The API in §2 exactly, including `Username`, no nonce parameter, and pointer-only `State`.
2. The §4 validation order, with the callback expression reachable only after step 10.
3. §5's printable-ASCII policy for usernames and SCRAM passwords, and SASLname escaping in the
   core. Kafka rejects an empty username before `Begin`. Kafka PLAIN is untouched.
4. §6's state minimization and step machine.
5. §7's eight bounds, with the encoded-salt check preceding the base64 decode.
6. §8's alias/translate split — three aliased, `ErrMalformedMessage` and `ErrUnexpectedResponse`
   translated, `ErrPasswordUnsupported` unmoved.
7. §10's allowlist as depguard, in the package's own commit.
8. §12's guards, with the two new `Reveal` guards.
9. §13's atomic transition.
10. **Vectors, split into two kinds.** *Derivation* vectors in the core: RFC 7677's
    `user`/`pencil` exchange pinning AuthMessage, SaltedPassword, ClientKey, StoredKey,
    ClientSignature, ClientProof, ServerKey, ServerSignature and the final verifier.
    *Message-construction* vectors, which the existing PostgreSQL test does **not** provide
    because it passes `client-first-bare` in as a literal: ordinary ASCII username, a username
    containing `,`, one containing `=`, one containing both, an empty username, a non-ASCII
    username refused, and the GS2 header. Plus the end-to-end password-to-proof vector in each
    wire package, which is what actually pins the callback's correctness.
11. **Fuzz targets**: the server-first parser, the server-final parser, the attribute walker,
    the iteration parser and the SASLname encoder. Properties: never panic; the derivation
    callback is never reached from malformed, duplicate, oversized, mandatory-extension,
    bad-nonce or bad-iteration input; parsing is deterministic; no peer payload appears in any
    error. Fuzz corpora contain no secrets and failure output contains no peer bytes.
12. **PostgreSQL regression**, semantically identical: success, wrong password, unsupported
    mechanism, malformed server-first, duplicate attributes, mandatory extension, nonce
    mismatch, non-strictly-extending nonce, malformed salt, iteration zero, iteration overflow,
    iteration ceiling, malformed server-final, server error token, signature mismatch,
    `AuthenticationOk` before verification, timeout and cancellation, evidence, `FailureClass`,
    findings and redaction. **The integration suite is not edited**, absent a real fixture bug.
    No cleanup while extracting.
13. **Kafka framing**: `SaslAuthenticate` carries the SCRAM payload in `SASLAuthBytes` across
    two round trips; the broker's `SASLAuthBytes` is read inside the wire package and never
    exposed above it; response bounds are enforced before bytes reach the core; `Reveal` and
    PBKDF2 both happen only in `kafka/wire`; no raw SCRAM payload enters evidence. Two
    `SaslAuthenticate` exchanges on one connection reuse `correlationSASLAuthenticate`; the
    lock-step reader makes that correct, and it is recorded here so it is a decision rather
    than an accident.
14. **Kafka authority is unchanged.** SCRAM runs only on the single selected requested-target
    continuation. It appears in no advertised loop, no metadata-discovered endpoint, no
    topology validation and no retry. At most **one** credential-bearing attempt per
    `DiagnoseKafka` run. No SCRAM→PLAIN fallback, no PLAIN→SCRAM fall-forward. Mechanism
    selection stays an exact-match whitelist with no folding. The core knows nothing about
    endpoints.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| `Begin(username, nonce)` as ADR 0055 sketched | puts entropy authority in two wire packages; a short, low-entropy or `math/rand` nonce becomes a caller's mistake to make | never |
| Implement SASLprep in the core | correct for PostgreSQL, **wrong for Kafka** (`KAFKA-6272`); the two services require opposite behaviour for non-ASCII, so no shared implementation is correct for both | Kafka fixes `KAFKA-6272`, *and* a per-service normalization policy is designed |
| Add a Unicode/stringprep dependency | would buy a normalization that is wrong for one of the two services, at the cost of the repository's one-dependency posture | as above |
| Alias `ErrMalformedMessage` / `ErrUnexpectedResponse` | collapses framing and SCRAM meanings onto one identity | never |
| `internal/security/scram` | places the core inside the package that owns secret authority, which is exactly the authority it must not appear to have | never |
| A generic SASL framework under `internal/sasl` | Phase 6.2 is SCRAM-SHA-256 only; a family directory is how one would start | a second mechanism is actually needed, with its own review |
| Defensive copy of the salt before the callback | the salt is peer-supplied public data the core does not reuse | never |
| `noCopy` marker on `State` | needs `sync` in the allowlist to diagnose a mistake the pointer-only API already discourages | never |

## Consequences

- Phase 6.2 is authorized and its contract is fixed. `TestNoSharedSCRAMPackageExists` stays
  until the atomic transition in §13.
- Kafka gains two `Reveal` guards it does not have today, so "exactly two" becomes a property
  of the source on both sides.
- Kafka SCRAM inherits a printable-ASCII credential restriction that Kafka PLAIN does not have,
  for a stated reason.
- ADR 0055's deletion instruction for the gate test is superseded by §13.

## Reopen conditions

- **SCRAM-SHA-512.** The `DerivedKeyLen == 32` check is SHA-256-specific. Needs a decision on
  how the callback's hash is pinned so a wire package cannot silently derive with the wrong one.
- **SCRAM-PLUS / channel binding.** Would change the GS2 header from `n,,` and give the core a
  reason to know about the connection. It must not acquire that reason quietly.
- **`KAFKA-6272` fixed upstream**, which would make the SASLprep divergence in §5 historical.
- **A third service needing SCRAM** — re-check §7's bounds against a third framing bound.
- **A second SASL mechanism** — re-check §1's family-contents guard before adding one.
- **TLS Trust & Identity Policy Review** — system trust store versus explicit CA, private PKI,
  `--tls-ca-file` replace versus augment, hostname verification, explicit `ServerName` override,
  client certificates and mTLS, managed-service CA bundles. **Deliberately not decided here**
  and not mixed with secret authority.
- **Managed-service protocol compatibility** — Redpanda self-hosted and Cloud, Confluent Cloud,
  AWS MSK SCRAM and MSK IAM, Azure Event Hubs' Kafka API; RDS, Aurora, Cloud SQL and Azure
  Database for PostgreSQL. A later compatibility phase about *protocol* behaviour, not
  cloud-provider SDK authority. Not Phase 6.2.
