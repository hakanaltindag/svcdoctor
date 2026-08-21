# ADR 0030: PLAIN authentication, and the ordering that governs every credential byte

## Status

Accepted, and implemented. **This is the first phase in svcdoctor that transmits
credential-derived bytes.**

It implements the contract ADR 0028 wrote, over the mechanisms ADR 0029 built,
inside the reveal boundary ADR 0027 installed. It adds no policy of its own; what
it adds is the code that obeys one, and the evidence that says when it did not.

## Problem

Everything about authentication had been decided and nothing had been written.
ADR 0028 fixed the signature, the credential authority, the transport policy and
the ownership rules; ADR 0029 built the channel fact and the fail-closed policy
that 0028 required first. What was missing was the step itself, and one thing
0028 could not have known: **whether a refusal could truthfully name what
blocked it.**

Verified from the tree at `0e26474`, not assumed:

- **Zero production `security.Reveal` call sites.** The `forbidigo` rule
  confining them to `internal/adapter/<service>/wire/` was re-verified in both
  directions against deliberate violations before any code was written.
- `security.Channel` reached `HandshakeSession.Channel()` unchanged, and
  `CredentialTransportPolicy.PermitsCredentials` refused everything below
  verified TLS, including both undefined-value directions.
- `HandshakeSession` exposed `Endpoint`, `Address`, `Mechanism`, `Evidence`,
  `Channel` and the ownership methods — **and nothing that named the node whose
  `tls.verified=false` makes a channel insufficient.** ADR 0028 section 3
  requires a refusal to point at that node. It could not.
- kmsg v1.13.1: `SASLAuthenticateRequest` is key 36, versions 0–2, carrying one
  field, `SASLAuthBytes`. v0 and v1 are non-flexible; v2 is flexible and the
  framing guard in `wire/exchange.go` refuses it. The v1 response adds
  `SessionLifetimeMillis`. Both response versions carry a broker-supplied
  `ErrorMessage`.
- One runtime dependency, zero transitive. `make check` green.

## Decision

### 1. One ordering governs everything, and it is the order of the code

```text
session.Channel()                        what this connection proved
  → policy.PermitsCredentials(channel)   may a secret cross it at all
  → security.NewEndpoint(session)        the logical name, never the address
  → credential.SecretFor(endpoint)       is this credential authorized here
  → wire.ExchangePLAIN                   the only layer that may reveal
  → security.Reveal                      inside plainAuthBytes, one call
```

Each step is a precondition for the next, and each failure stops before the one
after it exists in the call stack. A channel the policy refuses never reaches the
code that parses an endpoint; a credential bound elsewhere never reaches the wire
package. **Nothing is revealed in either path, because nothing reaches the only
function that can reveal.**

That is a structural property rather than a promise. It is asserted from the
outside, by measuring what the peer received: every refusal test proves the
peer's protocol layer consumed **zero bytes** after the handshake, not merely
that authentication reported failure.

### 2. Reveal happens once, in `plainAuthBytes`, and the payload is RFC 4616

```text
authzid NUL authcid NUL passwd
```

The authorization identity is **empty and present**: a leading NUL with nothing
before it. An empty authzid means "act as the authenticating identity", which is
what every ordinary Kafka client sends and what svcdoctor means. Omitting the
field would produce a two-field message no broker can parse.

`security.Credential` models an identity and a secret and has no authorization
identity, so there is nothing to put there. Overloading `Identity()` to mean both
was rejected — one field, two meanings — and inventing a second field for a value
no caller can supply would be speculative. **A deployment that needs a distinct
authzid is a change to the credential model with a record attached, not a
reinterpretation at the wire.**

The adapter above passes a `security.Secret` and never a string. There is exactly
**one** production `Reveal` call site in the repository, in
`internal/adapter/kafka/wire/saslauthenticate.go`.

### 3. SaslAuthenticate v1, chosen from both directions

Not "the newest", and not "the oldest that works":

| Version | Why not, or why |
|---|---|
| v0 | Answers with an error code, which is already enough to tell "rejected" from "broken". **No session lifetime.** |
| **v1** | Adds `SessionLifetimeMillis` — a fact about the target's configuration nothing else in a run reports — and stays non-flexible, so the shared framing accepts it. |
| v2 | Flexible. The response header carries tagged fields `readResponse` does not consume, so accepting one would misparse the body a byte at a time. Sending it would mean changing shared framing for one optional field nothing reads. |

The guard makes the wrong choice a returned error rather than a silent misparse,
and a test pins that v2 is still flexible so the reasoning cannot rot. No
automatic downgrade: a broker too old for v1 answers `UNSUPPORTED_VERSION`, which
is recorded next to the ApiVersions node that already says which versions it
supports.

### 4. `security.Reveal` is not accompanied by a claim of erasure

The plaintext exists as a local in `plainAuthBytes` and in the payload it
returns. It is not stored, not logged, not returned, and not put into any error.

**No zeroization is performed, and none is claimed.** By the time the bytes reach
the socket, kmsg has copied them into the frame it builds, so zeroing the slice
would leave that copy untouched while implying the value was gone. The string
`Reveal` returns cannot be erased at all: Go strings are immutable and the
collector may have moved it already.

`internal/security/doc.go` has stated since Phase 1 that Go cannot guarantee
erasure and that memory exposure is addressed by process hardening. ADR 0027
rejected a `[]byte`-returning `Reveal` with documented zeroization for the same
reason. **A `Zero` call here would be theatre that contradicts both**, and this
record does not weaken either.

### 5. The broker's ErrorMessage does not cross the wire boundary

`SASLAuthenticateResponse.ErrorMessage` is prose written by the deployment, not
by the protocol. What it contains in practice names principals, realms,
listeners and internal hostnames.

It is **dropped where it arrives**. `wire.SASLAuthenticate` has two fields,
`ErrorCode` and `SessionLifetimeMillis`, so there is no field an error message
could occupy and no filtering step anybody could forget. `SASLAuthBytes` — the
server's SASL continuation — stays inside for the same reason; PLAIN is a single
round trip and has nothing to continue.

Carrying it upward and sanitizing it later was rejected: evidence attributes have
no sanitization step, a report is meant to be shareable, and a structural
representation of broker prose is a design problem of its own. **The error code
is the normalized fact, and it is the one the protocol defines.**

A canary test gives the fake broker an error message naming a principal and an
internal host, proves the fixture really sends it, and then proves that neither
the whole message nor any fragment of it reaches evidence, a report, an error, a
`String()` or any `fmt` verb.

### 6. Evidence contract

```text
ID       kafka.sasl_authenticate/<endpoint>/<address>
Subject  ENDPOINT, the concrete ip:port the exchange ran against
Layer    L5 (auth)
Step     kafka.sasl_authenticate
Parent   the kafka.sasl_handshake node for the same path
```

**The parent is the handshake, not ApiVersions.** ApiVersions is the grandparent.
Parenting there would say the authentication followed capability discovery,
skipping the mechanism negotiation that is its actual prerequisite and the only
reason the socket accepts this message at all.

Attributes, recorded only when the exchange completed except where noted:

| Key | Why it is there |
|---|---|
| `kafka.sasl.mechanism` | always — the mechanism the broker agreed to, carried from the session so it cannot disagree with what was negotiated |
| `kafka.request_api_version` | the request version, without which an error code cannot be read |
| `kafka.error_code` | the broker's own code; zero is a statement, not an absence |
| `kafka.sasl.session_lifetime_ms` | how long the broker considers the authentication valid. Reported, never acted on — re-authenticating on it is client behaviour ADR 0008 keeps out |

`kafka.sasl.mechanism` is a **new key rather than a reuse** of
`kafka.sasl.requested_mechanism`. That one means what svcdoctor *asked about* at
the handshake; here the mechanism is settled. One key, one meaning.

### 7. What the node does not record, and why the identity is on that list

No password, no password length, no payload, no authzid, no raw response, no
broker prose. None of those has a field that could hold it: the wire boundary was
handed a `Secret` and returned two integers.

**The authenticating identity is also absent, and that is a decision.** A username
is real deployment identity. Redaction's declared identity kinds cover hosts and
addresses (ADR 0022), and a bare principal name is not structurally recognizable
— `svc-prod` and `PLAIN` are the same shape — so a plain string holding one would
survive into a shareable report unpseudonymized. Nothing today reads it.

**Reopen when** a diagnosis rule needs to tell two identities apart. It then needs
a declared identity-bearing attribute kind first, which is a change to ADR 0022's
model rather than a new attribute here.

### 8. Failure classification

One code is normalized beyond the handshake's mapping, under the same test the
two steps before it use: **the response must prove the generic fact by itself.**

| Observation | State | Class |
|---|---|---|
| Broker accepted the credential | PASS | — |
| `SASL_AUTHENTICATION_FAILED` (58) | FAIL | `AUTH_CREDENTIALS_REJECTED` |
| `UNSUPPORTED_SASL_MECHANISM` (33) | FAIL | `AUTH_MECHANISM_NOT_OFFERED` |
| `UNSUPPORTED_VERSION` (35) | FAIL | `PROTOCOL_UNSUPPORTED_VERSION` |
| `ILLEGAL_SASL_STATE` (34) | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Any other code | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Peer closed mid-exchange | FAIL | `PROTOCOL_PEER_CLOSED` |
| Not Kafka framing | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Undecodable, or answering another request | FAIL | `PROTOCOL_MALFORMED_RESPONSE` |
| Local budget expired | UNKNOWN | `EXEC_LOCAL_TIMEOUT` |
| Cancelled | UNKNOWN | `EXEC_CANCELLED` |
| Policy refused to send | SKIPPED | `EXEC_SKIPPED_BY_POLICY` |
| Credential bound elsewhere | *(no evidence)* | a Go error |

Code 58 exists because of KIP-152, which added it so a rejected credential
arrives as an error code instead of a closed socket — the same ambiguity ADR 0008
requires svcdoctor to avoid, resolved by the protocol itself.

**It is authentication, never authorization.** `AUTHZ_DENIED` means an identity
authenticated and was then refused an operation, and this exchange performs no
operation to be refused. Nothing the response carries distinguishes "wrong
password" from "unknown user", and neither does the class — which is correct,
because the response does not prove which.

No Kafka-specific class enters `internal/domain`, and no error text is parsed.

### 9. A policy refusal names the fact that caused it, or names nothing

This is what ADR 0028 section 3 required and could not yet express.

| Channel | Blocker |
|---|---|
| `tls-unverified` | the L3 TLS node for this path, whose `tls.verified` is `false` |
| `plaintext` | **none** |
| `unknown`, undefined | **none** |

A `plaintext` channel is recorded because the caller asked for no TLS. **No node
anywhere in the graph states that TLS is absent**, so a refusal there carries no
`BlockedBy`. Pointing at the TCP node instead was rejected: it passed, and it says
nothing about encryption, so it would make the report read as though something
had been established. The smallest honest representation of "nothing proves this"
is nothing.

To make the non-empty case truthful, the identifier had to travel. A new
optional fact was added, propagated exactly as ADR 0029 propagates the channel:

```text
transport.Continuation.ChannelEvidence()  set in the same statement as the channel
  → kafka.Session.ChannelEvidence()
    → kafka.HandshakeSession.ChannelEvidence()
      → kafka.AuthenticatedSession.ChannelEvidence()
```

It reports `(id, true)` when a TLS handshake classified the connection and
`("", false)` otherwise, so the plaintext gap is expressed in the type rather than
papered over. **Three alternatives were rejected**, each for a reason ADR 0029
already fixed: re-deriving the TLS identifier from the step and address
reconstructs an opaque identifier ADR 0019 says nothing decodes; querying the
graph makes an adapter depend on evidence structure, which ADR 0013 refuses;
inferring "the channel is TLS, therefore the deepest node is the TLS node" is the
guesswork-that-looks-like-knowledge ADR 0022 rules out, and would break silently
if the chain ever recorded another layer.

`transport.Result.add` became a parameter object in the same change, because it
would otherwise have taken two adjacent `EvidenceID`s that mean different things
and a transposition would compile.

### 10. Connection lifecycle, and why a refusal consumes the session

| Outcome | Evidence | Connection |
|---|---|---|
| Authenticated | PASS | **kept** — becomes an `AuthenticatedSession` |
| Credentials rejected | FAIL | closed |
| Exchange broke, peer closed, malformed | FAIL | closed |
| Budget expired or cancelled | UNKNOWN | closed |
| Policy refused to send | SKIPPED | closed |
| Credential bound elsewhere | none | closed |

The criterion is unchanged from ADR 0026 and it is the protocol's, not the
recorded state's: **does this socket have a defined next message?** A test holds
the two apart by showing the same broker-error-code shape keeping its socket at
L4 and losing it at L5.

The UNKNOWN row deserves its own sentence, because nothing is known to be wrong
with the peer. A request may be in flight and a response unread, so the next
reader on that socket would decode the wrong bytes. The connection is closed
because its *state* is unknown, not because the *result* is.

**The refusal row was the one genuine open question, and both options were
analysed.** A non-consuming API would hand the still-live session back, since a
refusal writes nothing and the socket is untouched. It is rejected: after a
SaslHandshake the broker accepts only that mechanism's SaslAuthenticate, so a
session whose authentication is refused has **no other legal operation on that
socket**. There is no reusable connection being discarded — there is a connection
whose only continuation svcdoctor has just declined to send. A consuming API also
gives ownership one path instead of two, at the one step that handles a
credential.

### 11. `AuthenticatedSession` is a third type, on the same grounds as the second

ADR 0026 made `HandshakeSession` distinct so that "authenticate before the
mechanism was agreed" is a compile error. The same argument applies once more, and
it is protocol state rather than elegance: a `HandshakeSession`'s socket accepts
exactly one message, and an authenticated socket accepts every request the broker
offers. Returning a `HandshakeSession` from a successful authentication would say
"authenticate on this again", which is false, and would let a future Metadata step
be written against a connection that never presented a credential.

It carries the connection, the logical endpoint, the address, the mechanism, the
channel, the channel evidence and its own evidence identifier. **No secret and no
identity**: the credential did its work at the wire boundary and has no reason to
outlive it. Tests assert there is no accessor through which either could be read
back.

`AuthResult` wraps it for two reasons that a bare `(*AuthenticatedSession, error)`
could not serve. It carries the evidence identifier, which is the **only** thing a
refused attempt produces — without it a refused caller receives nothing and cannot
name the node it just caused. And it keeps `defer result.Close()` the same
unconditional idiom it is for the two steps below, so ownership does not change
shape at the step that handles a credential.

## Corrections to earlier records

**ADR 0028 section 5 said a successful authentication is "the first Kafka step
whose success returns a connection that is *more* usable than the one it
consumed". That is right, and it did not say what type expresses it.** Section 11
above settles it.

**ADR 0028 anticipated no mechanism for its own section 3 blocker.** It wrote
"BlockedBy the TLS node whose `tls.verified` is false, when one exists" without
noticing that no carrier for that identifier existed. Section 9 above supplies
one and records the plaintext gap explicitly rather than leaving the requirement
half-satisfiable.

Nothing else in 0026, 0028 or 0029 is amended. Their reopen conditions stand.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| `Authenticate` takes a slice of sessions | Makes "authenticate everything" the default and `sessions[0]` — IPv4 by canonical ordering — the second-easiest thing to write | Never; a loop expresses a sweep explicitly |
| Pass the resolved `ip:port` to `SecretFor` | Lets a DNS answer widen credential authority, which `security.Endpoint` exists to prevent | Never |
| Check the policy after obtaining the secret | Reverses the ordering the whole phase rests on; a refusal would happen with plaintext already in hand | Never |
| Duplicate the policy or the binding check inside `wire` | Two layers that can disagree about whether a credential may be sent | Never |
| Record the broker's `ErrorMessage`, sanitized | Evidence has no sanitization step, and a structural representation of broker prose is its own design problem | A sanitized, structural representation is designed on purpose |
| Record the authenticating identity | Real deployment identity with no declared redaction kind; it would survive into a shareable report unpseudonymized | A rule needs to tell identities apart, and a declared kind exists |
| Zero the payload slice after the write | kmsg has already copied it into the frame, and the revealed string cannot be erased. It would imply a guarantee Phase 1 explicitly refuses | Never, absent a language-level guarantee |
| SaslAuthenticate v2 | Flexible; the framing reads a v0 response header, so it would misparse rather than fail | The framing gains flexible-header support for a reason of its own |
| SaslAuthenticate v0 | No session lifetime, for no compatibility gain the evidence cannot already explain | A broker matters that supports v0 only |
| Automatic downgrade after `UNSUPPORTED_VERSION` | Changes what the evidence means without saying so | Never |
| Point a plaintext refusal at the TCP node | The TCP node passed and proves nothing about encryption; it would read as though something had been established | A node exists that positively records "no TLS was attempted" |
| Derive the TLS node identifier from step and address | Reconstructs an identifier ADR 0019 says nothing decodes, and would break silently if the scheme changed | Never |
| Read the blocker out of the graph | Makes an adapter depend on evidence structure and turns the graph into a runtime store (ADR 0013) | Never |
| Return the still-live session on a policy refusal | The socket's only defined continuation is the message svcdoctor just declined to send | A non-credential operation becomes legal on a post-handshake socket |
| Reuse `kafka.sasl.requested_mechanism` on the auth node | One key would mean "what was asked about" on one node and "what is being used" on another | Never |
| Normalize a rejected credential to `AUTHZ_DENIED` | No operation was attempted, so nothing could be denied | Never |
| An unsafe transport override for this phase | Every clause of "explicit, per-run, recorded" needs an owner, and none exists | ADR 0029's shared reopen condition |

## Consequences

- svcdoctor can authenticate to a Kafka broker with SASL/PLAIN over verified TLS,
  on one caller-chosen path, and report the outcome as normalized evidence.
- **A credential cannot be sent over plaintext or unverified TLS**, and the
  refusal is a report line rather than a silent gap.
- There is exactly one production `security.Reveal` call site, and CI fails on a
  second one outside a wire package.
- The canonical report schema is unchanged. Two attribute keys are added under an
  existing service namespace; no `domain` type, no `FailureClass`, no
  `ReportSecurity` field and no redaction rule changed.
- No new dependency. Still one runtime module, zero transitive.
- PostgreSQL inherits the ordering, the policy, the endpoint authority and the
  reveal boundary unchanged; only the wire encoding is Kafka's.
- SCRAM (Phase 3.2d) now has a shape to fill in: the same ordering, the same
  evidence contract, a different payload — and its own dependency decision, still
  unmade.

## Reopen conditions

- **A mechanism that needs more than one round trip** — SCRAM does. The single
  `ExchangePLAIN` call becomes a loop inside `wire`, and `SASLAuthBytes` from the
  response starts being read there. Nothing above the wire boundary changes.
- **A distinct authorization identity** — `security.Credential` gains a field,
  with its own record. It is not synthesized at the wire.
- **An identity-bearing attribute kind for principals** — the identity exclusion
  in section 7 is reopened, not the redaction model bypassed.
- **A layer that can choose a transport policy** — the unsafe override, the second
  policy member and the `ReportSecurity` field arrive together, as ADR 0029 fixed.
- **A node that positively records "no TLS was attempted"** — the plaintext
  refusal in section 9 gains a truthful blocker.
