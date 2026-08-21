# ADR 0026: Kafka SASL enters as mechanism discovery, and authentication waits for an owner

## Status

Accepted.

## Decision

Phase 3.2 implements **SaslHandshake and nothing else**: svcdoctor asks each
broker whether it offers a named SASL mechanism, records what it answers, and
stops. No credential is acquired, revealed, or transmitted.

Authentication — PLAIN, SCRAM, and the SaslAuthenticate exchange that carries
them — is **deferred**, because four questions it depends on have no owner in
the repository yet. They are listed in section 7 with the condition that reopens
each.

### 1. Why the handshake is the whole phase

The split is not caution for its own sake. It follows from what the two requests
carry.

```text
SaslHandshake     mechanism name                      -> offered / not offered
SaslAuthenticate  identity and secret material        -> authenticated / rejected
```

A `SASLHandshakeRequest` has exactly one field, `Mechanism`, and the response has
two, an error code and the list of mechanisms the listener offers. Nothing in
that exchange is a credential. It is therefore as safe to run on every measured
path as ApiVersions was, and it answers the questions an operator actually asks
first:

- does this listener do SASL at all;
- which mechanisms does it offer;
- is the one I was told to use among them.

Authentication answers a different question and costs something different. A
failed authentication attempt is a security event on the broker: it is logged,
it is counted, and in deployments backed by a directory service it moves an
account towards lockout. Discovery has no such cost.

That asymmetry is the whole argument for the split. Discovery may be run
everywhere by default; authentication may not be run anywhere until somebody can
say where.

### 2. The protocol facts this rests on

Read from `github.com/twmb/franz-go/pkg/kmsg` v1.13.1, the pinned version, rather
than assumed:

| Fact | Source |
|---|---|
| `SASLHandshakeRequest` is key 17, versions 0-1, one field: `Mechanism` | generated.go |
| `SASLHandshakeResponse` carries `ErrorCode` and `SupportedMechanisms` | generated.go |
| The error code is `UNSUPPORTED_SASL_MECHANISM` or `ILLEGAL_SASL_STATE` | kmsg's own field documentation |
| Kafka fills `SupportedMechanisms` when it rejects the requested mechanism | kmsg's own field documentation |
| v0 continues with raw SASL tokens; v1 continues with `SaslAuthenticate` | kmsg's request documentation |
| `SASLAuthenticateRequest` is key 36, versions 0-2, and carries `SASLAuthBytes` | generated.go |
| Neither handshake message is flexible, so both use response header v0 | `IsFlexible()` on both types |

**There is no "list the mechanisms" request.** A client proposes one and learns
the rest from the answer. That shapes section 4.

### 3. svcdoctor sends SaslHandshake v1, and never downgrades

This is the opposite choice from ApiVersions, where ADR 0025 chose v0 for maximum
compatibility, and the reason the two differ is that a handshake version is not
an encoding — it selects the authentication flow that follows.

- v0 continues with raw SASL blobs outside Kafka's framing, so a rejection
  arrives as a closed socket.
- v1 continues with `SaslAuthenticate`, which carries an error code and an error
  message.

ADR 0008 requires a controlled connection lifecycle and attributable outcomes,
and only v1 provides them: "the credentials were rejected" and "the connection
broke" must never arrive as the same observation. A broker too old for v1 answers
with an error code, which is recorded as the fact it is — next to the ApiVersions
node that already says which SaslHandshake versions that broker supports, so the
report explains its own failure.

**No automatic downgrade.** Retrying at v0 after a v1 refusal would change what
the evidence means without saying so, in the same way ADR 0023 refuses to retry a
handshake with verification disabled.

### 4. The caller names the mechanism

`SASLParams.Mechanism` is required. Two alternatives were considered.

**Rejected: send a mechanism svcdoctor knows is invalid** — for example
`SVCDOCTOR-PROBE` — to harvest the offered list from the guaranteed rejection.
It works, and it is tempting because it never commits the connection to a
mechanism. It was rejected because it puts a value on the wire that no client
would ever send, in a request that lands in the broker's logs and metrics as a
failed handshake. A diagnostic tool that lies on the wire to make its own output
tidier has stopped being trustworthy, and the operator reading those logs is the
same person reading the report.

**Rejected: derive the mechanism from the ApiVersions evidence.** Nothing in an
ApiVersions response names a SASL mechanism, so there is nothing to derive.

A mechanism name is a protocol parameter, exactly like a TLS server name, and
`docs/ARCHITECTURE.md` section 3 already says a generic step may take parameters.
Naming one sends nothing secret.

### 5. Evidence contract

```text
ID       kafka.sasl_handshake/<endpoint>/<address>
Subject  ENDPOINT, the concrete ip:port the exchange ran against
Layer    L5 (auth)
Step     kafka.sasl_handshake
Parent   the kafka.api_versions node for the same path
```

L5 is right even though nothing authenticates: `docs/ARCHITECTURE.md` section 2
places "SASL mechanism discovery / authentication" together at that layer, and
the discovery step is what a report's first-broken-layer summary must point at
when a listener offers nothing the caller can use.

Attributes:

| Key | Why it is there |
|---|---|
| `kafka.sasl.requested_mechanism` | "Not offered" is uninterpretable without it |
| `kafka.sasl.offered_mechanisms` | What the broker said it offers, sorted |
| `kafka.error_code` | The broker's own code, reused from ADR 0025 — one key, one meaning: the code for this exchange |
| `kafka.request_api_version` | Reused likewise: the request version used for this exchange |

Mechanism names are **protocol facts, not identity**: they name algorithms from a
public registry, so they are `StringListAttr` and survive redaction intact. A
shared report that pseudonymized `PLAIN` into `host-001` would have destroyed the
only thing the node is for.

Sorted for byte-stability, because Kafka's enabled mechanisms are a set and the
order they arrive in expresses no preference. **Not deduplicated**: a repeated
entry is something the broker sent, and collapsing it would hide a
misconfiguration behind a tidier list.

### 6. Failure classification

| Observation | State | Class |
|---|---|---|
| Broker accepted the mechanism | PASS | — |
| `UNSUPPORTED_SASL_MECHANISM` (33) | FAIL | `AUTH_MECHANISM_NOT_OFFERED` |
| `ILLEGAL_SASL_STATE` (34) | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| `UNSUPPORTED_VERSION` (35) | FAIL | `PROTOCOL_UNSUPPORTED_VERSION` |
| Any other code | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Peer closed mid-exchange | FAIL | `PROTOCOL_PEER_CLOSED` |
| Not Kafka framing | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Undecodable, or answering another request | FAIL | `PROTOCOL_MALFORMED_RESPONSE` |
| Caller's budget expired or was cancelled | UNKNOWN | `EXEC_LOCAL_TIMEOUT` / `EXEC_CANCELLED` |

One code is added to the two-code mapping ADR 0025 established, under the same
test: **the response must prove the generic fact by itself**.
`UNSUPPORTED_SASL_MECHANISM` means the broker does not offer the mechanism that
was named, which is what `AUTH_MECHANISM_NOT_OFFERED` says, and the list of what
it does offer arrives in the same response.

**The peer-side class, deliberately.** `AUTH_MECHANISM_UNSUPPORTED` means
svcdoctor cannot perform a mechanism — a gap in this tool. Nothing here has tried
to perform anything, so using it would blame a broker for svcdoctor's limits.
That distinction is binding and it is tested: asking a broker about GSSAPI, which
svcdoctor cannot perform, still produces the peer-side fact, because asking is
all that happened.

**`ILLEGAL_SASL_STATE` stays unmapped.** It means a handshake was not expected at
this point in the connection, which one listener produces because it does not do
SASL at all and another because a handshake already happened. Two causes behind
one code prove no single generic fact.

### 7. What blocks authentication, and what would unblock it

Authentication is not merely unfinished. Each of these is a decision with no
layer entitled to make it today, and implementing authentication would mean
answering them by fiat inside an adapter.

> **Status after ADR 0028.** 7.1 and 7.3 are **answered** there — selection by a
> singular signature, transport safety by a fail-closed declared policy — and
> 7.2's argument was **narrowed**, because it proved weaker than stated. 7.4 is
> unchanged. The text below stands as written; ADR 0028 records what replaced it.

**7.1 Which path receives the credentials.** ApiVersions and the handshake run on
every measured path and choose none, because neither costs anything. Credentials
do. The options are: every successful path, one path, or a caller-selected
subset — and the third needs a caller. There is no CLI, no application
orchestration and no configuration input, so the only available answers are "all"
and "the first", and *the first* would silently mean IPv4, because canonical
address ordering puts IPv4 first. ADR 0024 removed exactly that artifact from the
transport chain; re-introducing it on the path that carries a password would be
strictly worse. **Reopen when** a layer exists that can express a selection and
record why it made it.

**7.2 Where the credential comes from.** `docs/BACKLOG.md` places secret source
resolution — stdin, askpass, strict-permission file, environment, external
reference — in Phase 5. Until then nothing but a test can construct a
`security.Credential`, so an authentication API would ship with no producer, which
is the speculative-API failure this architecture rejects elsewhere.
**Reopen when** secret source resolution exists.

**7.3 Whether credentials may cross an unverified channel.** `docs/SECURITY.md`
states that credentials are not automatically sent over an unverified TLS
channel, and the transport chain already records `tls.verified` per attempt. But
*enforcing* it is policy, and *explaining* it is diagnosis, and this adapter is
allowed to do neither (`docs/ARCHITECTURE.md` sections 5 and 6). An adapter that
silently refused would be inventing an undocumented policy; one that silently
sent would be violating a documented one. **Reopen when** either an orchestration
layer can carry the policy, or a diagnosis rule can state the finding — and note
that the mechanism/policy/diagnosis split has to be settled before the code, not
after.

**7.4 SCRAM's implementation route.** SCRAM-SHA-256/512 needs nonce generation,
PBKDF2, HMAC, a parsed server-first message, a client proof and server-signature
verification. franz-go implements it in `pkg/sasl/scram`, which lives in the
**main franz-go module** — the one that also contains `kgo`, and whose `go.mod`
requires `klauspost/compress`, `pierrec/lz4/v4` and `golang.org/x/crypto`.
Importing it would replace this project's "one dependency, zero transitive
dependencies" property with four modules and put the client ADR 0008 forbids into
the module graph. The alternative is hand-rolled cryptography. Neither is a
decision to take as a side effect of a phase about SASL. **Reopen when** SCRAM is
its own subphase with its own dependency decision.

PLAIN has none of 7.4's problem — it is a formatted string — which is why the
recommended order is PLAIN first, SCRAM second, once 7.1 to 7.3 are answered.

### 8. Connection ownership

The input is the `Session` list ApiVersions produced; the output is a
`HandshakeResult` of `HandshakeSession`s.

```text
transport.Continuation --ApiVersions--> Session --SaslHandshake--> HandshakeSession
```

| Outcome | Evidence | Connection |
|---|---|---|
| Mechanism accepted | PASS | **kept** — authentication must continue here |
| Mechanism rejected, or any error code | FAIL | closed |
| Exchange broke mid-flight | FAIL | closed |
| Caller's budget expired | UNKNOWN | closed |

**This is not "FAIL closes the connection", and the difference matters.** ADR 0025
keeps a connection whose broker answered ApiVersions with an error code, because
any request may still follow it. The criterion is *whether the protocol defines a
next message on this socket*, and after a handshake it does so only for the
accepted mechanism: the broker will accept that mechanism's continuation and
nothing else. A rejected handshake therefore leaves a connection with nothing that
may be sent on it, which is not a connection worth keeping. `TestConnectionLifetimeIsNotDrivenByEvidenceState`
holds the two apart by showing the same broker-error-code shape keeping its socket
at L4 and losing it at L5.

**`HandshakeSession` is a distinct type on purpose.** Authentication will consume
one, so "authenticate before the mechanism was agreed" becomes a compile error
rather than a protocol error discovered on the wire. It carries the mechanism the
broker accepted, so the step that authenticates cannot disagree with the step that
negotiated.

The ADR 0021 rules are unchanged and now live in one place, `ownedConn`, embedded
by both session types: one owner at a time, one transfer, `Close` safe to defer
and to repeat.

### 9. The endpoint a credential will have to name

Nothing here uses a credential, but the handshake had to answer half the question
anyway, and the answer is recorded now so that authentication does not have to
invent it.

`security.Endpoint.Equal` is **name-based by construction**, and its own
documentation says why: two endpoints are not equal merely because their
hostnames resolve to the same address, since resolution can change, can differ per
vantage, and can be attacker-influenced. So:

> **A credential is authorized by the logical endpoint the operator named, never
> by a resolved address.**

DNS therefore cannot widen credential authority: one lookup producing five
addresses produces five paths that are all still *the same* authorized endpoint,
and an address that appears in an answer is never itself an authority.

Phase 3.1 lost that value. `transport.Continuation` carries `Endpoint()`, but
`kafka.Session` did not, so the logical endpoint stopped at L4 and the handshake
would have had to be told again — the "two ways to name one thing" failure the
transport chain's own `endpoint()` comment warns about. `Session.Endpoint()` was
added, carrying the value through unchanged. It is used today to scope the L5
identifier, and it is what `SecretFor` must be given tomorrow.

What is **not** decided: how a `security.Credential` reaches the adapter, and
whether the comparison happens against a parsed `Endpoint` or a supplied one.
That is part of 7.2.

### 10. No SKIPPED nodes

The handshake records what it observed and nothing about paths it never received.
A session whose connection was already taken produces no node, for the reason ADR
0025 gives: there is nothing to say about an exchange there was never a means to
attempt.

A path whose ApiVersions exchange failed never becomes a `Session`, so this step
cannot know the address existed — the same information boundary ADR 0025 section 9
recorded at L4, in the same shape. It is deliberately **not** solved here.
Solving it for SASL alone would settle the general question by accident, in the
one place that happens to have a convenient input.

## Context

`docs/SCOPE.md` and `docs/BACKLOG.md` fix the Kafka order: ApiVersions, then SASL,
then Metadata. Phase 3.2 is the first phase where a credential could plausibly be
sent, which makes it the phase where the credential boundary is either built or
quietly skipped.

The risk is specific and it is not "SASL is hard". It is that authentication is
easy enough to write that it can land before anybody decides where the secret is
allowed to go — and that a report produced by an unauthorized credential use
looks exactly like one produced by an authorized one.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Implement handshake and PLAIN together | Bundles a credential-free capability with four unresolved policy questions, and makes the safe half wait for the unsafe one | 7.1 to 7.3 are answered |
| Implement SCRAM in this phase | Needs either the franz-go client module and three transitive dependencies, or hand-rolled crypto | SCRAM is its own subphase with its own dependency ADR |
| Probe with a deliberately invalid mechanism name | Puts a value on the wire no client would send, and a failed handshake in the operator's logs, to save a parameter | Never |
| Send SaslHandshake v0 for maximum compatibility | Selects the raw-blob flow, where a rejection is indistinguishable from a broken connection — the ambiguity ADR 0008 exists to avoid | A broker matters that supports v0 only, and the evidence for it exists |
| Downgrade automatically after `UNSUPPORTED_VERSION` | Changes what the evidence means without saying so | Never |
| Keep the connection after any completed handshake | The socket's only defined continuation is the mechanism that was refused | Never |
| Reuse `Session` for handshake output | Loses the compile-time ordering between negotiating a mechanism and using it, on the path that will carry credentials | Never |
| Map `ILLEGAL_SASL_STATE` to a capability class | Two causes behind one code; mapping it would infer which one | A response distinguishes them |
| Authenticate every successful path, by symmetry with ApiVersions | Symmetry is not a reason: ApiVersions costs nothing and an authentication attempt is a logged, counted, lockout-relevant event | 7.1 has an owner |
| A `SKIPPED` L5 node for a path whose ApiVersions failed | Would settle ADR 0025 section 9 by accident, in the one place with a convenient input | The same condition as ADR 0025 section 9 |

## Consequences

- svcdoctor can report which SASL mechanisms each broker behind a bootstrap name
  offers, and show one listener disagreeing with another — without holding a
  credential.
- The first credential byte cannot be sent by accident: there is no parameter to
  put one in, and `security.Reveal` is now mechanically confined (ADR 0027).
- Authentication has a written entry contract rather than an assumption: four
  questions, each with the condition that reopens it.
- The Kafka chain is four layers deep on one measured socket, and a test fails if
  that stops being true.
- `internal/adapter/kafka/wire` now owns Kafka framing once, for every request
  kind, which is where the SaslAuthenticate exchange will slot in.
