# ADR 0067: The RabbitMQ BASIC journey, and what Connection.Open-Ok is allowed to prove

## Status

**Accepted in Phase 8.1. Not implemented.** No Go exists for it, and
`internal/adapter/rabbitmq` does not exist.

It decides the target model, the wire journey, the graph shape and the usability
boundary for the first RabbitMQ slice, before any adapter is written. A later phase
implements it and is expected to invent nothing.

`SchemaVersion` stays **1**. This record authorizes no `FindingCode`, no
`FailureClass`, no dependency, and no change to Kafka, PostgreSQL or Redis semantics.
It adds three `Step` values, which are additive exactly as `postgres.*`, `kafka.*` and
`redis.*` were.

Companion records: [0068](0068-rabbitmq-authentication-and-credential-authority.md)
decides the credential model this journey depends on,
[0069](0069-rabbitmq-vhost-authorization-and-close-normalization.md) decides how a
refusal is classified, and [0070](0070-rabbitmq-tune-contract-and-wire-bounds.md)
decides the negotiation values and the parser's resource bounds.

Evidence: `docs/validation/RABBITMQ_PHASE80_CONTRACT_STUDY.md` records the Phase 8.0A
research, the Phase 8.0B adversarial review and the Phase 8.0C wire measurements this
record freezes. Where a statement below says *measured*, that document names the
broker version it was measured against.

## 1. Context

The question is not *how does svcdoctor connect* — the generic transport chain already
answers that — but **what is the smallest thing svcdoctor can complete that proves
something worth reporting, and exactly what completing it proves.**

RabbitMQ answers that more cleanly than any service in the repository so far, and one
fact is the reason: **AMQP 0-9-1 separates authentication from resource authorization
into two distinct method exchanges on the same connection.** `Connection.Start-Ok`
carries the credential. `Connection.Open` names the virtual host. They are different
frames, they fail with different reply codes, and svcdoctor's own position in the
handshake tells them apart without reading a byte of peer text.

Nothing else in the protocol has to be reached for that separation to be visible. That
is the whole of the case for stopping where this record stops.

## 2. Decision

The BASIC journey is:

```text
requested target  (hostname | IPv4 literal | IPv6 literal)
  → DNS resolution                  [omitted entirely for a literal — ADR 0059]
  → TCP connect
  → TLS handshake                   [when the run's plan requires it; ordinary
                                     out-of-band TLS, no in-band negotiation]
  → AMQP protocol header            [exactly the 8 bytes AMQP\x00\x00\x09\x01]
  → Connection.Start                [received: the peer speaks AMQP 0-9-1]
  → Connection.Start-Ok             [PLAIN, at most once — ADR 0068]
  → Connection.Tune                 [received: authentication succeeded]
  → Connection.Tune-Ok              [channel_max 1, frame_max per ADR 0070, heartbeat 0]
  → Connection.Open(vhost)
  → Connection.Open-Ok              [TERMINAL]
  → Connection.Close / Close-Ok     [epilogue; cannot change the verdict]
```

One connection. No redial, no reconnect, no second attempt for any reason.

**The method allowlist is `connection.start-ok`, `connection.tune-ok`,
`connection.open`, `connection.close` and `connection.close-ok`, and nothing else.**
A method absent from that list is forbidden, not merely unused. An implementation is
expected to make the absence structural — a wire package with no encoder for any other
class cannot send one by accident, and that is a stronger guarantee than a review
comment.

`Connection.Secure-Ok` is deliberately excluded. It exists in the protocol, and
answering it would be a second credential-bearing frame; ADR 0068 §5 decides what
happens when a peer sends `Connection.Secure`.

## 3. The target model

| Input | Decision |
|---|---|
| `--host` | required; hostname, IPv4 literal or IPv6 literal. A literal resolves nothing and records no `dns.lookup` node at all (ADR 0059). A zone identifier is refused, deferred rather than rejected. |
| `--port` | default **5672**. The port is never semantic: a TLS plan comes from `--tls` and never from the port number. |
| `--vhost` | default **`/`**, which is RabbitMQ's own `default_vhost`. Always rendered. |
| credential | optional. Sourced exactly as ADR 0049 decided for PostgreSQL; never a literal on the command line. |
| TLS | `--tls`, `--tls-ca-file`, `--tls-server-name`, `--tls-insecure`, with ADR 0060's option-validity rule unchanged. |

Nothing else. In particular there is **no** `--mechanism` flag (there is exactly one
mechanism — ADR 0068), no heartbeat, frame-size or channel flag (ADR 0070 fixes all
three), and no flag naming a queue, an exchange or a management endpoint.

### 3.1 Why `/` is defaulted rather than required

Requiring `--vhost` would buy no truth. The vhost is rendered in the report either
way, so a defaulted `/` is never an *unstated* assumption — it is a stated one.

The argument for requiring it is that a multi-tenant deployment assigns a generated
vhost, so a defaulted `/` produces a refusal. That outcome is **correct, correctly
attributed and immediately actionable**, and ADR 0069 makes it name itself. One
mitigation is required and is part of this decision: **when a vhost-scoped refusal
occurs and `--vhost` was not supplied, the finding must say that the default was
used.** That converts the one bad case into a self-explaining one.

## 4. The graph is three service nodes

```text
target.requested
  └─ dns.lookup                     [absent for a literal]
      └─ tcp.connect
          └─ tls.handshake          [when planned]
              └─ rabbitmq.connection_start
                  └─ rabbitmq.authentication
                      └─ rabbitmq.connection_open
```

| Step | PASS means | Carries |
|---|---|---|
| `rabbitmq.connection_start` | a well-formed `Connection.Start` arrived | AMQP version, the peer's `product`, `version`, `cluster_name`, `platform`, the offered mechanism list, the locales |
| `rabbitmq.authentication` | `Connection.Tune` arrived | selected mechanism, authenticated identity (or "no credential presented"), **and the Tune values** — offered and selected `channel_max`, `frame_max`, `heartbeat` |
| `rabbitmq.connection_open` | `Connection.Open-Ok` arrived | the requested vhost, and on failure the normalized close outcome of ADR 0069 |

### 4.1 Tune is not a node, and the reason is measured

`Connection.Tune` is **authentication's success signal**. RabbitMQ never acknowledges
authentication; the `{ok, User}` branch of its reader is the only one that sends
`Tune`. So Tune's arrival *is* the proof, and its values belong on the node whose PASS
it establishes.

A separate `rabbitmq.tune` node was rejected because it could never observe its own
PASS: nothing is sent in reply to `Tune-Ok`, so the node's state would only be
decidable retroactively from `Open-Ok`. A node whose state cannot be determined when it
runs is a bad shape.

Phase 8.0C then removed the only complication this created. An invalid `Tune-Ok`
produces **no `Connection.Close` at all** — the socket is closed silently after about
three seconds, measured on RabbitMQ 4.2.0 for `channel_max = 0`, `frame_max = 0` and an
over-limit `channel_max`. Phase 8.0A had predicted a `Close(530)` attributed to
`connection.tune`, and that prediction is **falsified**. The consequence is a
simplification: there is no ambiguous position in the state machine, and no
disambiguation rule is needed. A negotiation refusal is observed as a peer close while
awaiting `Open-Ok`, and ADR 0070 §7 owns its outcome.

### 4.2 A vhost node was rejected

There is no vhost measurement separate from opening a connection in it. A
`rabbitmq.vhost` node would re-project `rabbitmq.connection_open`'s outcome, and
ADR 0013's rule is that relationships belong to the graph rather than to duplicated
evidence.

## 5. The terminal boundary is `Connection.Open-Ok`

Nothing weaker, and nothing stronger.

### 5.1 The claim, exactly

> At `<timestamp>`, from `<vantage>`, an AMQP 0-9-1 client connected to `<endpoint>` at
> `<address>` over `<channel>`, authenticated as `<identity | no credential presented>`,
> requested virtual host `<vhost>`, and the endpoint answered `Connection.Open-Ok`.

The following are **forbidden** renderings, in any surface:

- "RabbitMQ is healthy", "is up", "is usable"
- "the cluster is healthy", "all nodes are reachable"
- "queues are usable", "publishing works", "consuming works"
- "replication is healthy", "quorum queues are healthy"
- "your application will work"
- "the virtual host is healthy" — `Open-Ok` proves the vhost is reachable and
  permitted, not that anything inside it functions
- "you have configure, write or read permission" — §7 records that none was evaluated

### 5.2 It is endpoint-scoped, and for a *different* reason than PostgreSQL's

PostgreSQL BASIC is endpoint-scoped because a pooler serves a complete passing session
with its backend stopped — measured. **That argument does not transfer, and importing
it would put a false sentence in svcdoctor's own documentation.**

There is no pgBouncer for AMQP 0-9-1. HAProxy, an AWS NLB, a Kubernetes `Service` and
an Envoy TCP proxy are byte forwarders; none of them generates `Connection.Open-Ok`.
Reaching it therefore proves that a real AMQP 0-9-1 broker process, holding this vhost's
permission data, was alive at that instant. That is **stronger** evidence than a
PostgreSQL session through a pooler.

The wording stays endpoint-scoped anyway, for the reason that does apply: **an L4 load
balancer makes the node identity unknowable.** A three-node cluster behind one DNS name
answers from one node; svcdoctor cannot say which, cannot say the other two are healthy,
and a second run may land elsewhere. `cluster_name` does not disambiguate it — every
node in a cluster reports the same value.

## 6. What is excluded, and why each exclusion is structural

| Excluded | Why |
|---|---|
| `Channel.Open` | Tautological given `Open-Ok`. A channel needs no permission, touches no resource, and is refused only by a `channel_max` svcdoctor itself guarantees cannot be exceeded (ADR 0070). It would add a second error class — `channel.close` — for zero evidence. |
| queue and exchange operations, including passive declares | §7 |
| the management HTTP API | §8 |
| cluster discovery | AMQP 0-9-1 has no redirect method — it was removed after 0-8 — and RabbitMQ sends `Connection.Open-Ok` with an empty `known-hosts`. There is nothing to discover, so the invariant that discovery creates no credential authority is satisfied by the protocol rather than by policy. RabbitMQ BASIC needs **no analogue of ADR 0050**. |
| cluster diagnosis | Follows from the above and from §5.2. |
| AMQP 1.0, STOMP, MQTT, the Stream protocol | Different protocols on different ports. `AMQP\x00\x00\x09\x01` is the only header svcdoctor sends. |
| latency findings | Stage duration is measured, exactly as PostgreSQL BASIC froze it: measurement only, no threshold, no finding. |

## 7. Resource permissions are not measured, and the reason is not convenience

RabbitMQ's `configure`, `write` and `read` permissions are regex patterns evaluated on
resource names, at channel operations. None of them runs during `Connection.Open`.
Testing one would require naming a resource, and the least-bad candidate — a passive
declare against a built-in `amq.*` exchange — is the argument *against* the whole idea:
it would make svcdoctor's verdict depend on whether the operator's permission pattern
happens to match `amq.direct`. A correctly locked-down deployment would be reported as
broken.

That is ADR 0063 §9's rule — missing privilege is not a failure, it is a blocked
measurement — arriving one layer earlier. The cheapest way to honour it is not to ask.

**`Connection.Open-Ok` proves that the authenticated identity has some permission entry
for this virtual host and that the endpoint opened a connection in it. It proves
nothing about what that identity may do inside it.**

## 8. The management HTTP API is absent, not deferred to a flag

It is not enabled by default. It is a second protocol on a second port with its own TLS
configuration, its own authorization surface — the `management` tag, which AMQP access
does not require — and cluster-scoped data that would be attributed to one endpoint.

A user who can open an AMQP connection may receive 401 from `/api/overview`, and a user
who can read `/api/overview` may be unable to open a connection. Those are two answers
to two different questions, and conflating them would be svcdoctor's first genuinely
misleading verdict.

**No `--management-*` flag namespace is reserved.** An unused flag is an invitation.

## 9. The close epilogue

After `Open-Ok`, svcdoctor sends `Connection.Close(200)` with an empty reply text and
zero class and method ids, and reads `Close-Ok`. It carries no credential, no vhost and
no identity, so it can expose nothing.

It is not politeness. Measured: dropping the socket makes RabbitMQ log *"client
unexpectedly closed TCP connection"* at **warning** level, and svcdoctor must not
manufacture warnings in an operator's log. A clean close also releases the broker's
connection process immediately instead of after a timer.

**A failure while closing never retroactively erases a proven `Open-Ok`.** Evidence is
immutable (ADR 0003) and `Open-Ok` was recorded when it arrived. A missing `Close-Ok` is
an attribute on the `rabbitmq.connection_open` node: not a finding, no change to
`SummaryStatus`, and it does not make the run incomplete. The AMQP 0-9-1 specification
agrees — a peer that detects socket closure without `Close-Ok` *SHOULD log the error*,
not fail.

Symmetrically, when the **broker** sends `Connection.Close`, svcdoctor replies
`Close-Ok` before closing.

## 10. Alternatives rejected

| Journey | Rejected because |
|---|---|
| **B — add `Channel.Open`** | §6. Three more methods and a whole second error class for a tautology. |
| **C — add a passive queue or exchange declare** | §7. Converts an operator's least-privilege configuration into a svcdoctor failure, and reads customer topology. |
| **D — add the management HTTP API** | §8. |
| **Stop at `Connection.Tune`** | It proves authentication and nothing about authorization, which discards the distinction that makes RabbitMQ worth implementing. |

## 11. Reopen conditions

Each requires a deliberate reopen recorded in `docs/BACKLOG.md`, not a rule that
quietly starts asserting:

1. **A channel is needed.** Reopen only with a stated claim that `Channel.Open` proves,
   which §6 currently says is nothing.
2. **A resource permission must be measured.** Reopen with an answer to §7's objection —
   how a least-privilege deployment avoids being reported as broken.
3. **An expected-state contract exists.** Today `product`, `version`, `cluster_name`,
   `platform`, `heartbeat`, `frame_max` and `channel_max` are observations, and none is a
   problem without an expectation svcdoctor does not have.
4. **A second endpoint is diagnosed in one run.** That is cluster work and needs its own
   credential-authority analysis, even though §6 shows the protocol offers no discovery.
5. **`--probe-command` or any post-`Open-Ok` operation.** It would make
   `rabbitmq.connection_open` the wrong name for the terminal node.
