# ADR 0029: A connection carries what it proved, and a fail-closed policy reads it

## Status

Accepted, and implemented. Phase 3.2b builds the two mechanisms ADR 0028
section 6 required before any credential byte. **No credential is transmitted,
and no authentication code exists.**

## Problem

ADR 0028 decided that svcdoctor sends a password only over a channel whose peer
identity was verified. It could not be implemented, because the layer that would
have to obey that rule cannot see the channel.

Verified from the tree at `6698cb5`, not assumed:

- `transport.Continuation` exposed `Endpoint`, `Address`, `Evidence` and the
  ownership methods. Nothing about transport security.
- `kafka.Session` and `kafka.HandshakeSession` exposed the same, plus the
  mechanism. Nothing about transport security.
- `tls.verified` existed only as an attribute on the L3 evidence node, which the
  adapter writes into a builder and never reads back.
- `tls.Result` exposed `Evidence`, `Connected`, `TakeConn`, `Close` — and its own
  documentation said a caller "should have no reason to inspect the connection's
  state", which is true and was also why the fact had nowhere to travel.

So an adapter holding a live socket had no honest way to answer "was the peer at
the other end of this identified?". ADR 0028 was right, and this record is what
makes it enforceable.

## Decision

### 1. `security.Channel` — one ordered fact about one connection

```go
ChannelUnknown        // zero value: nothing classified this connection
ChannelPlaintext      // no TLS was performed
ChannelTLSUnverified  // handshake completed, identity not verified
ChannelTLSVerified    // handshake completed, identity verified
```

It answers one question — *was this peer identified?* — and refuses the others.
Negotiated version, cipher suite, certificate names and expiry are diagnostic
facts that already live in the TLS evidence, where a rule can reason about them.

**The zero value is `ChannelUnknown`, not `ChannelPlaintext`.** A connection
nobody classified and a connection known to be in the clear are different facts,
and recording the second when only the first is true would be a synthetic fact of
exactly the kind ADR 0024 refuses for evidence. Both are denied by policy; only
one of them is a claim.

### 2. `security.CredentialTransportPolicy` — fail-closed, one value

```go
RequireVerifiedTLS  // the zero value, and the only value
func (p CredentialTransportPolicy) PermitsCredentials(c Channel) bool
```

Modelled on `ForwardingPolicy`, which Phase 1 built before topology existed so
that "the discovery code cannot be written without confronting the decision".
This is the same pattern one layer over: a value type, no engine, no I/O, no
service name, and a zero value that requires the safest channel.

Both directions of "I do not know" deny: an unknown channel, an undefined channel
integer, and an undefined policy integer all return false.

### 3. The fact travels with the connection, never beside it

```text
tls.Result.Verified()                    the observation that established it
  → transport.Continuation.Channel()     first durable carrier
    → kafka.Session.Channel()
      → kafka.HandshakeSession.Channel() what authentication will consult
```

At every hop the fact is copied from the object being continued, inside an
unexported constructor, so the connection and the fact describing it are never
paired up by a caller. A `Continuation` or `Session` whose channel describes a
different socket cannot be built from outside its own package; what holds inside
those packages is set out under "What the guarantee actually is" below.

Each type gained exactly one accessor and one field. Nothing else changed, and
`tcp.Result` gained nothing at all: TCP produces a plaintext connection and does
not know whether the chain will wrap it, so the classification would have had to
be corrected one layer later, which is how a fact starts drifting from its
subject.

### 4. Source of truth

| Channel | Established by | Because |
|---|---|---|
| `ChannelPlaintext` | the transport chain's no-TLS branch | the caller asked for no TLS; the branch itself is the evidence |
| `ChannelTLSVerified` / `ChannelTLSUnverified` | `tls.Result.Verified()` | the handshake observation for *this* wrapped connection |

`tls.Result.Verified()` is computed from the same `observation.verified()` that
produces the evidence's `tls.verified` attribute, so the runtime fact and the
recorded fact cannot disagree about one handshake. A test asserts they agree in
both directions.

**Plaintext is never inferred from a missing TLS node.** It is recorded in the
branch that runs because `params.TLS == nil`. A handshake that failed produces no
continuation at all, so there is no connection whose channel could be wrong.

### 5. It does not enter evidence, and the report schema is unchanged

The channel is a **runtime ownership fact**, not a diagnostic observation, and the
two are not automatically the same thing.

`tls.verified` already records what a handshake proved, on the node that observed
it. A second copy on a Kafka node would be one fact with two representations that
can disagree — the failure ADR 0013 and ADR 0016 exist to prevent — and it would
change the canonical report for a value no reader asked for. A test asserts no
node carries it.

So: no `domain` change, no `REPORT_SCHEMA.md` change, no redaction change, no
determinism change. When a policy refusal eventually needs to appear in a report,
it appears as what it is — a `SKIPPED` node with `EXEC_SKIPPED_BY_POLICY`, decided
in ADR 0028 section 3 — rather than as a duplicated attribute.

### 6. No `ReportSecurity` field

ADR 0028 anticipated one. It is not added, because the three things that could be
recorded are all absent or constant today:

| Candidate | Status |
|---|---|
| what happened on a connection | per-connection, and already in the TLS evidence. Not report-global |
| what policy the run used | there is one policy value and no way to choose another. Recording a constant in every report is noise |
| whether an unsafe override was enabled | no override exists |

`ReportSecurity` is a Phase 1 canonical-contract type, and changing it to record a
constant would be schema churn. **Reopen when** a layer can choose a policy —
which is the same condition as the override below.

### 7. No unsafe override

`docs/SECURITY.md` permits an unsafe transport mode only as an explicit, per-run,
recorded opt-in. Every clause of that sentence needs an owner: "explicit" needs an
input surface, "per-run" needs run configuration, "recorded" needs the
`ReportSecurity` field above. None exists.

A weaker policy member added now would be a bypass with no owner, reachable by any
future caller without review, guarding nothing. So the policy set is one member
wide, and a test asserts that every other integer value denies everything.

**Reopen when** the CLI or application layer exists and can carry an
`--insecure`-style per-run decision into the report. Widening is then a visible
change to `internal/security/credentialtransport.go` with an ADR, not a value
somebody sets.

## Alternatives considered

| Option | Rejected because |
|---|---|
| **B. Capability booleans** — TLS used, verification requested, verification succeeded | More expressive and worse: three booleans admit eight states of which five are nonsense, including "no TLS but verification succeeded". A security decision is the wrong place to discover an impossible state |
| **C. Carry the TLS evidence identifier** | An identifier is a lookup key, so using it means querying the graph — option D with an extra step. ADR 0019 also makes identifiers opaque: nothing decodes them |
| **D. Query the graph** | Makes an adapter depend on evidence structure, and turns the graph into a runtime state store, which ADR 0013 explicitly refuses. The graph is for diagnosis, frozen, after the fact |
| **E. Type-assert `*tls.Conn`** | Puts TLS semantics in a package the architecture says must have none, and re-derives a fact transport already held. It is also **unreliable in this repository today**: the test fixtures wrap connections in `countingConn`, so the assertion fails on a connection that genuinely used TLS. A security check that silently depends on nobody wrapping a connection is not a check |
| **F. Re-derive from configuration** | Configuration is intent. `params.TLS != nil` says TLS was *requested*, not that a handshake verified anything |
| **G. A "credentials permitted" flag from transport** | Collapses mechanism and policy, and puts the policy in the layer least entitled to hold it. Transport would be deciding what may be sent over a connection it knows nothing about the purpose of |
| Add the fact to `tcp.Result` too | Mechanical propagation to every type. TCP cannot classify a connection whose TLS status is decided one layer later |
| Record the channel as an evidence attribute | Duplicates `tls.verified` into a second representation that can disagree, and changes the canonical report for a runtime value |
| A `ChannelPlaintext` zero value | An unclassified connection would claim a fact nobody established |

## What the guarantee actually is

A verification pass before commit asked whether code outside the transport
ownership path can manufacture a verified channel. It can, in one place, and the
answer is recorded here rather than smoothed over — an earlier draft of this
record claimed the adapter "cannot strengthen the claim", which is **too strong**.

Established by compiling the attempts, not by reading the design:

| Attempt, from where | Result |
|---|---|
| Name `security.ChannelTLSVerified`, any package | **compiles** — it is an exported constant |
| `&transport.Continuation{channel: ...}`, outside `transport` | compile error: cannot refer to unexported field |
| Positional literal, outside the package | compile error: implicit assignment to unexported field |
| `&transport.Continuation{}`, outside the package | compiles, and yields `ChannelUnknown`, which every policy refuses |
| Exported setter or mutator | none exists on any of the three carriers |
| `&HandshakeSession{channel: ChannelTLSVerified}` **inside `internal/adapter/kafka`** | **compiles** |

So the boundary is the *package*, not the *layer*:

> **Mechanically impossible** for every package except the one that defines the
> type. **Not mechanically impossible** inside `internal/adapter/kafka`, because
> that package defines `Session` and `HandshakeSession` and therefore owns their
> fields.

The correct contract language is:

> The authoritative channel fact is produced by the transport ownership path.
> Every other layer propagates it unchanged and must not manufacture a stronger
> value.

**Mechanical impossibility inside the defining package was considered and
rejected as unbuildable at proportionate cost.** Go offers no way to restrict a
value's construction to one call site without a capability or witness token, and
every cheaper variant fails: an exported `security.NewVerifiedChannel()` is
callable by the adapter too; an opaque struct moves the problem without solving
it; splitting the session types into their own package only relocates the
exported constructor the adapter would call.

It would also be defending the wrong door. **The adapter holds the raw
`net.Conn`.** A layer that can write arbitrary bytes to a socket cannot be
defended from itself by a value type, and the real barriers against credential
exposure are elsewhere: `security.Reveal` is confined to wire packages by lint
(ADR 0027), the policy is fail-closed, and credentials are endpoint-bound. The
channel fact exists to make the correct decision *derivable*, and to stop an
accidental wrong one — not to contain a hostile adapter.

What enforces it where the type system cannot:

1. **The constructors copy rather than accept.** `Result.add` takes the
   `*transport.Continuation` and `HandshakeResult.add` takes the `*Session`, and
   each reads the endpoint, address and channel from it. There is no channel
   parameter, so no call site can pass the wrong one; forging requires editing a
   security-carrying constructor.
2. **`forbidigo` forbids naming a `security.Channel` constant** outside
   `internal/probe/transport` and test files. Adapter production code cannot
   write `security.ChannelTLSVerified` at all. Verified in both directions
   against deliberate violations.
3. **Mutation-checked tests.** Forging verified at an adapter call site fails
   three tests; downgrading a verified channel fails two; marking an unverified
   or plaintext transport path verified fails two more.

Together these make the remaining gap a deliberate, visible edit to one of two
constructors in a package whose tests fail when it is made — which is the level
of protection the risk warrants, and no more.

## Consequences

- A future authentication step can decide whether to send a credential from one
  accessor on the value it already holds, without inspecting a socket, reading a
  graph, parsing evidence, or consulting configuration.
- No package outside the one defining a carrier can forge its channel, and the
  zero value it *can* construct refuses everything.
- The failure direction is fixed in one place. Every unknown — unset channel,
  undefined channel, undefined policy — denies.
- PostgreSQL inherits it unchanged: the fact is produced by transport and the
  policy names no service.
- `security` gained two value types and stays a stdlib-only leaf.
  `internal/probe/transport` now imports it, which is a leaf dependency in the
  allowed direction.

## Reopen conditions

- **A transport mode that is neither plaintext nor TLS** — `Channel` gains a
  member rather than a boolean being reinterpreted.
- **A layer that can choose a policy** — the override, the second policy member,
  and the `ReportSecurity` field arrive together, because each is useless without
  the others.
- **A verification outcome TLS cannot express today**, such as a channel verified
  by a mechanism other than the peer certificate chain — `IdentityVerified` is the
  single predicate that would need revisiting.
