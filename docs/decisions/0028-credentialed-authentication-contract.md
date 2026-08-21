# ADR 0028: Credentialed authentication is singular, policy-gated and channel-aware

## Status

Accepted. It decides how authentication will be built; **no authentication code
exists**, and none may be written before the two mechanisms in section 6 do.

This record answers the questions ADR 0026 section 7 left open, and corrects one
of them.

## Problem

Phase 3.2a stopped at SaslHandshake because a handshake carries a mechanism name
and a credential exchange carries a password. The step after it is the first in
this repository that can leak, and the first whose failures cost the target
something.

Four questions had to be answered before any byte of it is written:

1. which session may receive a credential, and who decides;
2. which endpoint authorizes its use;
3. whether it may cross a plaintext or unverified channel;
4. what happens to the socket afterwards.

They are answered below, in a form that can be checked against the repository
rather than believed.

## Observed evidence

Read from the tree at `d5451a9`, not assumed:

- **`HandshakeSession` exposes `Endpoint`, `Address`, `Mechanism`, `Evidence`,
  and the ownership methods. Nothing about the channel.** `transport.Continuation`
  exposes no channel fact either. `tls.verified` exists only as an attribute on
  the L3 evidence node, which the adapter writes into a builder and never reads.
  **The adapter therefore cannot currently tell a plaintext socket from a verified
  TLS one.**
- `domain.FailureExecSkippedByPolicy` already exists, documented as "a policy
  prevented the step, for example the credential forwarding policy".
- `security.ForwardingPolicy` already exists as a fail-closed value type with no
  engine, built in Phase 1 *before* topology, expressly "so that the discovery
  code cannot be written without confronting the decision".
- `domain.ReportSecurity` already records `tlsVerificationDisabled` and
  `credentialForwardingEnabled` per run.
- `docs/SECURITY.md` item 6 and the `--insecure` contract: an unsafe transport
  mode is an explicit, per-run, recorded opt-in, and **never** an automatic
  fallback. Credentials "are not automatically sent over an unverified TLS
  channel."
- kmsg v1.13.1: `SASLAuthenticateResponse` carries `ErrorCode`, a broker-supplied
  `ErrorMessage`, `SASLAuthBytes` and `SessionLifetimeMillis` (v1+). v0 and v1 are
  non-flexible; v2 is flexible and the wire framing guard refuses it.

## Decision

### 1. Authentication is singular by construction

```go
// Shape only. Not implemented.
func Authenticate(
    ctx context.Context,
    builder *domain.GraphBuilder,
    session *HandshakeSession,      // exactly one, never a slice
    credential security.Credential,
    params AuthParams,
) (*AuthResult, error)
```

`Run` and `SASLHandshake` take a slice, ask every path and choose none, because
discovery costs the target nothing. **Authentication takes one session**, and the
asymmetry is the decision, expressed in the type rather than in a comment.

A slice parameter would have made "authenticate everything" the path of least
resistance — the caller already holds the list — and `sessions[0]` the second.
`sessions[0]` is IPv4 by canonical address ordering, which is exactly the hidden
preference ADR 0024 removed from the transport chain. With one session per call:

- no ordering exists inside the call, so no ordering can become a preference;
- no index exists, so no index can become a selection;
- authenticating every path remains possible, but only by writing a loop, which
  is a visible and reviewable act rather than a default.

**Selection is the caller's, and the adapter cannot make one.** That is provable
from the signature, not promised in prose. Today the only caller is a test; when
application orchestration exists it selects and records why. Until then the
absence of a selector is visible instead of being resolved by accident.

### 2. The credential is authorized by the logical endpoint

Confirmed from ADR 0026 section 9, with the mechanism now fixed:

```text
HandshakeSession.Endpoint()   "primary.internal:9092"     the name the operator gave
    -> net.SplitHostPort      ("primary.internal", 9092)
    -> security.NewEndpoint   normalized
    -> credential.SecretFor(endpoint)
```

`HandshakeSession.Address()` — the concrete `ip:port` — is **never** an input to
`SecretFor`. The proof that DNS cannot widen authority has three parts, each
checkable:

1. `security.Endpoint.Equal` compares normalized **names**, and its own
   documentation states why: resolution changes over time, differs per vantage
   and can be attacker-influenced, so "it must never widen the scope of a
   credential."
2. The label round-trips exactly. `transport.Params.endpoint()` builds it with
   `net.JoinHostPort`, so `net.SplitHostPort` recovers the same parts, and
   `NewEndpoint` then normalizes case, the trailing dot and IPv6 form. A credential
   bound to `KAFKA.Internal.` matches a run against `kafka.internal`, and that is
   normalization, not widening.
3. A resolved address never becomes an authority of its own. One lookup producing
   five addresses produces five sessions that are all still *the same* authorized
   endpoint. A credential bound to `10.0.0.1:9092` does **not** authorize
   `primary.internal:9092`, even when the name resolves to that address, and
   `SecretFor` returns `ErrEndpointMismatch` rather than a secret.

Two tests are required when the code lands, and they are the acceptance criteria
for this section: the five-address case must succeed on all five, and the
address-bound credential must be refused for the named endpoint.

A mismatch is a programming error, not a diagnostic result. It is returned as an
error and **must not be normalized into evidence** — `security.Credential` says so
already, and an evidence node saying "the wrong credential was offered" would be
svcdoctor reporting on its own caller.

### 3. PLAIN may be sent only over verified TLS

The three statements stay separate, as `docs/ARCHITECTURE.md` section 5.2
requires:

| | |
|---|---|
| **Capability** | The Kafka protocol permits SASL/PLAIN on a plaintext listener. It is a formatted string on a socket; nothing in the protocol prevents it. |
| **Policy** | svcdoctor sends a password only over a channel whose peer identity was verified. Anything weaker is an explicit, per-run, recorded opt-in — never an automatic fallback. |
| **Diagnosis** | "This cluster accepts PLAIN without verified TLS" is a finding a rule states. Not this layer's sentence to write. |

The policy is **derived, not invented**. `docs/SECURITY.md` item 6 and the
`--insecure` contract already fix the shape for every unsafe transport mode:
explicit, per-run, warned about, recorded in the report, never automatic.
`ForwardingPolicy` already implements exactly that shape for the sibling question
of credential forwarding. This decision applies the same rule to the same kind of
risk; it does not introduce a new policy vocabulary of its own devising.

So, answering the three cases directly:

- **plaintext TCP — no.** The password would be readable on the wire. Permitted
  only under an explicit opt-in that does not exist yet.
- **TLS with verification disabled — no.** An unverified handshake proves the
  channel is encrypted and proves nothing about who is on the other end, which is
  precisely the case where a credential is handed to an unknown peer.
  `docs/SECURITY.md` already states that `tls.verified` and "a handshake
  completed" never read the same.
- **verified TLS — yes**, and this is the only default-permitted case.

**A refusal is evidence, not silence.** This is what resolves the tension ADR
0026 section 7.3 recorded. The adapter neither silently refuses nor silently
sends: it records the L5 authentication node as

```text
State         SKIPPED
FailureClass  EXEC_SKIPPED_BY_POLICY
BlockedBy     the TLS node whose tls.verified is false, when one exists
Subject       the ip:port, which is known
```

and sends nothing. The class already exists for exactly this purpose. On a
plaintext path there is no TLS node to point at, so the node carries no
`BlockedBy` — which is allowed, and truthful, because nothing failed; a policy
applied. Whether that outcome is `WARN` or `CRITICAL` remains diagnosis's
decision, untouched here.

This is **obeying** a policy, not owning one. The distinction is the one Phase 1
drew for `ForwardingPolicy`: the value type and its fail-closed default live in
`internal/security`, the choice is made by whoever configures the run, and the
adapter only evaluates a declared policy against a declared fact.

### 4. `security.Reveal` stays confined, and PLAIN's payload is built where it is revealed

Verified in the tree, not assumed: `forbidigo` forbids `security.Reveal` outside
`internal/adapter/[^/]+/wire/`, and the rule was checked in both directions when
it landed. There are still **zero** call sites.

When PLAIN lands, the SASL payload — `authzid \0 authcid \0 passwd` — is built
**inside `internal/adapter/kafka/wire`**, from a `security.Secret` handed down,
and the plaintext exists only as the argument to the encoder. The adapter above it
passes a `Secret`, never a string.

Three properties are required of that code, and they are acceptance criteria:

- the revealed value is never stored in a struct field, an error, or anything the
  evidence or report model can reach;
- `SASLAuthenticateResponse.ErrorMessage` is broker-supplied prose and **must not**
  enter evidence, exactly as socket error text does not today;
- no zeroization is claimed. `internal/security/doc.go` states that Go cannot
  guarantee erasure, and this record does not weaken that.

### 5. Ownership after authentication

| Outcome | Evidence | Connection |
|---|---|---|
| Authenticated | PASS | **kept** — the session is now a normal authenticated connection, and Metadata continues on it |
| Broker rejected the credentials | FAIL | closed |
| Policy refused to send | SKIPPED | closed — nothing was sent and nothing may follow |
| Exchange broke mid-flight | FAIL | closed |
| Budget expired or cancelled | UNKNOWN | closed |

The criterion is the one ADR 0026 fixed and it is unchanged: **does the protocol
define a next message on this socket?** After a successful authentication it
defines all of them, which is why this is the first Kafka step whose success
returns a connection that is *more* usable than the one it consumed. After a
rejection Kafka fails the connection, so there is nothing to inherit.

`SessionLifetimeMillis` from the response is a fact about how long that session
stays valid. It is recorded as an attribute when the broker sends one; it is not
a timer this layer implements, because re-authentication is client behaviour that
ADR 0008 keeps out.

### 6. Two mechanisms must land before any credential byte

Neither exists, and neither is authentication:

**6.1 A channel fact, declared by transport.** The adapter cannot evaluate a
policy about a channel it cannot see. The fact must be **declared** by the layer
that established it, not inferred by the layer that uses it — the same rule ADR
0022 fixed for identity-bearing attributes, for the same reason: inference is
guesswork that looks like knowledge. Type-asserting `net.Conn` to `*tls.Conn` and
reading `VerifiedChains` was rejected: it puts TLS semantics in an adapter, which
`docs/ARCHITECTURE.md` section 4 forbids, and it re-derives a fact the transport
chain already had in its hand.

Shape: a small ordered value on `transport.Continuation`, carried through
`Session` and `HandshakeSession` unchanged, whose zero value is the least trusted
state so that an unset fact fails closed.

**6.2 A credential-transport policy, fail-closed.** A value type in
`internal/security`, modelled on `ForwardingPolicy`: no engine, no I/O, zero value
= require verified TLS, and a `String()` for the report's security section. The
adapter takes one and obeys it.

Both are small. They are deliberately **not** bundled with PLAIN, because a safety
mechanism that arrives in the same change as its first consumer is never reviewed
on its own — and `ForwardingPolicy` is the precedent for building the guard first:
Phase 1 built it before topology existed, precisely so the discovery code could
not be written without confronting the decision.

### 7. Correction to ADR 0026 section 7.2

That section argued authentication was blocked because secret source resolution is
Phase 5, so "an authentication API would ship with no producer".

**That argument was weaker than stated, and this record narrows it.** A
`security.Credential` is constructible by any caller, including a test, and the
entire Kafka adapter already ships with no production consumer — there is no CLI
for ApiVersions or the handshake either. Secret *resolution* (stdin, askpass,
strict-permission file, environment) is about acquisition ergonomics at the CLI
boundary, and it does not block the adapter's contract.

What actually blocks authentication is sections 1, 3 and 6 of this record: the
selection question, the channel policy, and the two missing mechanisms. Phase 5
remains the owner of secret resolution, and that is now recorded as a Phase 5
usability item rather than a Phase 3 blocker.

## Options compared

For selecting which session receives a credential:

| | 1. every successful path | 2. caller-selected, one per call | 3. orchestration selects | 4. no auth; Metadata first |
|---|---|---|---|---|
| Credential exposure | One credential to *N* brokers per run; a load balancer with five backends means five exposures | Exactly what the caller chose | Same as 2 | None |
| Lockout / rate limit | *N* failed attempts per run. A three-strike directory policy locks the account in one run | Caller-controlled, one by default | Same as 2 | None |
| Diagnostic completeness | Highest: finds one broker with a stale ACL or credential store | One path by default; full sweep still expressible as a loop | Same as 2 | No L5 result at all |
| IPv4/IPv6 neutrality | Neutral — all are used | Neutral **only** in the singular form; a slice invites `sessions[0]`, which is IPv4 | Same as 2 | Not applicable |
| Determinism | Deterministic | Deterministic | Deterministic | Deterministic |
| Ownership complexity | *N* authenticated sessions to own and close | One | One | None |
| Metadata / topology implications | Metadata needs one authenticated session, so *N* is more than the next phase can use | Fits: hands on the one session Metadata needs | Same as 2 | Metadata is unauthenticated only on non-SASL listeners |

Option 3 is not a distinct model: with no orchestration layer it *is* option 2
with a future caller, and the singular signature is what makes it safe to wait.

Option 4 is real and was seriously considered — Metadata needs no credential on a
`PLAINTEXT` or `SSL` listener, so it would deliver topology without touching this
question at all. It is rejected as a *reordering* rather than a solution: it does
not remove the need for the two mechanisms, it only postpones the phase that
needs them, and it would leave SASL listeners — the common production case —
undiagnosable past L5 discovery. It stays recorded as the fallback if the
mechanisms are deferred again.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| `Authenticate` takes `[]*HandshakeSession` | Makes "authenticate everything" the default by convenience and `sessions[0]` — that is, IPv4 — the second-easiest thing to write | Never; a loop expresses the sweep explicitly |
| Authenticate every path by symmetry with discovery | Symmetry is not a reason. Discovery costs the broker nothing; each authentication attempt is logged, counted and lockout-relevant | An operator explicitly asks for a per-broker auth sweep, which the singular API already supports |
| Let the adapter refuse unverified channels on its own judgement | That is an undocumented policy invented inside an adapter, which `docs/ARCHITECTURE.md` section 5 forbids | Never; it obeys a declared policy instead |
| Let the adapter send regardless and let diagnosis complain afterwards | The password is already on the wire by then. A finding cannot un-send it | Never |
| Infer the channel by type-asserting `*tls.Conn` and reading `VerifiedChains` | Puts TLS semantics inside an adapter and re-derives a fact transport already had. Declaration over inference, as ADR 0022 fixed for identity | Never |
| Pass the resolved `ip:port` to `SecretFor` | Would let a DNS answer widen credential authority, which `security.Endpoint` exists to prevent | Never |
| Record a policy refusal as `FAIL` | Nothing failed. A policy applied, and the target was never asked | Never |
| Silently skip a path the policy forbids | An absent node is indistinguishable from a step nobody requested. The refusal is a fact worth reporting | Never |
| Bundle the policy type, the channel fact and PLAIN in one phase | A safety mechanism that lands with its first consumer is never reviewed alone; `ForwardingPolicy` is the precedent for building the guard first | Never |
| Implement re-authentication on `SessionLifetimeMillis` | Client behaviour, and ADR 0008 keeps client behaviour out of the measured path | Never |

## Consequences

- The signature of authentication makes the exposure decision visible: one call,
  one credential, one broker.
- A refused authentication produces a report line — `SKIPPED`,
  `EXEC_SKIPPED_BY_POLICY` — rather than a silent gap, so a reader can tell "not
  attempted, by policy" from "not attempted, nobody asked".
- The default is the safe one and an unset policy is the safest one, because the
  zero values of both new types are.
- PostgreSQL inherits all of this: the channel fact is a transport fact and the
  policy is service-neutral.
- Phase 3.2b is a security phase that sends nothing, and Phase 3.2c is the first
  phase in this repository that transmits a credential.

## Reopen conditions

- **Selection** — if an orchestration layer or a CLI arrives that can express and
  record a multi-path authentication sweep, section 1's singular signature stays,
  and the sweep is written as a loop in that layer.
- **Policy** — if an explicit `--insecure`-style opt-in for credential transport
  is added, it must be per-run, warned about on stderr, and recorded in
  `ReportSecurity`, exactly as `tlsVerificationDisabled` is today.
- **Channel fact** — if a transport mode appears that is neither plaintext nor
  TLS, the ordered value in 6.1 gains a member rather than a boolean being
  reinterpreted.
