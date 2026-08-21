# ADR 0025: The Kafka adapter asks every transport path and keeps franz-go behind one package

## Status

Accepted.

## Decision

`internal/adapter/kafka` is the first service adapter. It performs Kafka protocol
exchanges over connections the transport chain established and measured, and
normalizes what it observes into `domain.Evidence`.

Phase 3.1 implements ApiVersions and nothing else.

### 1. ApiVersions runs on every transport path, and none is chosen

The transport chain returns every path that completed and picks none (ADR 0024).
This adapter does not pick one either, and the reason is stronger than symmetry.

**ApiVersions is a per-connection fact by protocol definition.** A Kafka client
sends it on every new connection because the answer describes the broker at the
other end of *that* connection. One bootstrap name routinely resolves to several
brokers, or to a load balancer with several backends, and those can genuinely
differ: a rolling upgrade, one node with a different listener configuration, one
backend that is not Kafka at all. Asking a single path would hide exactly the
inconsistency somebody runs a diagnostic tool to find.

The cost is small and the request is the right one to repeat: ApiVersions is
unauthenticated, side-effect free, and the first thing every Kafka client sends.

Each path gets its own exchange and its own evidence node. Nothing is aggregated:
two brokers advertising different ranges is two facts, and what that means about
the cluster is a rule's decision.

Because nothing is selected, no ordering can become a hidden preference. The
IPv4-before-IPv6 artifact that Phase 2.4 removed from the chain cannot reappear
here.

### 2. Connections survive their exchange, and only completed exchanges keep them

A path whose exchange completed keeps its connection open, owned by the returned
`Result`. Phase 3.2 (SASL) and 3.3 (Metadata) must continue on the same measured
socket; dialing again would attribute protocol facts to a connection nobody
measured.

The distinction that matters is between the exchange and the answer:

| Outcome | Evidence | Connection |
|---|---|---|
| Broker answered, no error code | PASS | kept |
| Broker answered with an error code | FAIL | **kept** — the exchange completed and the socket is fine |
| Exchange broke mid-flight | FAIL | closed — the socket's protocol state is unknown |
| Caller's budget expired | UNKNOWN | closed |

A broker that replies with an error code has spoken Kafka correctly. Only this
package can tell that apart from a socket left in an unknown state, which is why
the decision lives here rather than with the caller.

The ownership rules are the ones ADR 0021 fixed: one owner at a time, one
transfer, `Close` safe to defer.

### 3. franz-go enters through one package, and only kmsg

`internal/adapter/kafka/wire` is the only package that imports the protocol
library, and it imports only `github.com/twmb/franz-go/pkg/kmsg`.

kmsg encodes and decodes messages. `kgo`, the client, owns connections, refreshes
metadata, retries and switches brokers — the properties that make it a good
production client are exactly the ones ADR 0008 forbids here, because each of
them would attribute a measurement to a socket that was not the one measured.

kmsg's `RequestFormatter` writes the complete request, length prefix and header
included, so no protocol bytes are hand-written. The response's length prefix and
correlation identifier are read here because the caller owns the socket, and the
body goes back to kmsg.

Nothing above `wire` sees a kmsg type: the package returns plain `int16` values
and slices of them, and reports failures as three sentinel errors so the layer
above classifies structurally rather than by reading error text.

### 4. The first runtime dependency

`github.com/twmb/franz-go/pkg/kmsg v1.13.1`, BSD-3-Clause, compatible with this
project's Apache-2.0 licence. It is a separate Go module from franz-go itself and
has **zero transitive dependencies**, so `go.sum` holds two lines and the build
stays cgo-free.

The alternative was writing the Kafka wire format by hand. Rejected: the protocol
has ~70 message types with flexible-version encoding rules, and hand-rolling it
would put a second Kafka implementation inside a tool whose value depends on
being right about Kafka.

### 5. Evidence contract

```text
ID       kafka.api_versions/<endpoint>/<address>
Subject  ENDPOINT, the concrete ip:port the exchange ran against
Layer    L4 (protocol)
Step     kafka.api_versions
Parent   the transport node whose connection was used — TLS when TLS ran, else TCP
```

The subject is the concrete peer, not the bootstrap hostname, for the reason
ADR 0020 gives: a subject names what its layer touched, and the exchange happened
against an address. The logical endpoint scopes the identifier, so one endpoint's
L1 to L4 nodes read as one family, and the graph connects the layers.

Attributes, three of them:

| Key | Why it is there |
|---|---|
| `kafka.api_versions` | The advertised ranges, `"<key>:<min>-<max>"`, sorted by key numerically so key 2 precedes key 10 |
| `kafka.error_code` | The broker's own code; recorded whenever the exchange completed, because zero is a statement |
| `kafka.request_api_version` | What was asked for. Without it an error code cannot be interpreted |

One node with one list rather than a node per API key: a broker advertises about
seventy, and seventy nodes per path would bury the transport evidence in a report
whose point is the transport evidence. API *names* are deliberately absent — the
key number is what the broker sent, and a name is svcdoctor's local table, which
belongs to whatever renders the report.

### 6. Failure classification stays generic and conservative

The domain's protocol vocabulary was sufficient; no class was added.

| Observation | Class |
|---|---|
| Peer closed during the exchange | `PROTOCOL_PEER_CLOSED` |
| Framing that Kafka never produces | `PROTOCOL_UNEXPECTED_RESPONSE` |
| Plausible framing, undecodable body, or a response to another request | `PROTOCOL_MALFORMED_RESPONSE` |
| Broker answered with `UNSUPPORTED_VERSION` (35) | `PROTOCOL_UNSUPPORTED_VERSION`, with the code as an attribute |
| Broker answered with any other error code | `PROTOCOL_UNEXPECTED_RESPONSE`, with the code as an attribute |
| Caller's budget expired or was cancelled | `EXEC_LOCAL_TIMEOUT` / `EXEC_CANCELLED` |

Kafka error codes stay in attributes. Mapping arbitrary broker codes onto the
service-neutral vocabulary would invent precision the code does not carry, and it
would put Kafka semantics in `internal/domain`, which is service neutral by
design.

**One code is the exception, and the test for it is narrow: the response must
prove the generic fact by itself.** `UNSUPPORTED_VERSION` on an ApiVersions
response means the broker does not support the version of the request it was
sent — the same statement `PROTOCOL_UNSUPPORTED_VERSION` makes, with nothing
added. It is also the only error the protocol defines for this response: a
broker produces it and `NONE`, and `INVALID_REQUEST` only for the v3+ client
software fields svcdoctor's v0 request does not carry. Nothing is inferred,
because the version that was asked for is already on the node as
`kafka.request_api_version`, and the code itself is still recorded.

Without the mapping, "this port is not Kafka at all" and "this Kafka broker
declined the version" arrive as one class. That is the distinction
`TLS_PEER_NOT_TLS` exists for at L3, one layer down, and the two conclusions
lead to opposite actions in exactly the same way.

The state stays `FAIL`, not `UNKNOWN`. The claim-discipline rule that an
unsupported capability is `UNKNOWN` is about svcdoctor's own gaps — the class
for that is `EXEC_UNSUPPORTED_BY_SVCDOCTOR` — while this is the peer's own
statement about what it will accept, which is the same shape as
`AUTH_MECHANISM_NOT_OFFERED` rather than `AUTH_MECHANISM_UNSUPPORTED`. What that
failure means for the run is severity, and severity is a rule's decision.

Every other code, including `ILLEGAL_SASL_STATE` (34), stays conservative.
Reading an authentication state or a configuration out of a number is diagnosis,
and it would be diagnosis performed here, on one code, with none of the evidence
a rule would have.

### 7. No generic adapter interface, and no registry

Neither was created, and neither was needed.

An `Adapter` interface would have exactly one implementation and no consumer:
there is no CLI, no application orchestration and no second service. Its method
set could only encode guesses about what PostgreSQL will need. ADR 0009 governs
*how* registration works when wiring exists; it does not require a registry
before anything wires.

The reopen condition is concrete: the second service adapter, or the first
composition root that has to choose between them.

### 8. Kafka attribute keys stay with the adapter, for now

`kafka.api_versions` and its siblings are declared in `internal/adapter/kafka`.

The eventual problem is already visible: a rule in `internal/diagnosis/kafka` will
need these keys and cannot import an adapter — depguard forbids it, and Phase 3.1
made that rule stricter still. The landing place is named so nobody has to invent
one: a leaf package, most likely `internal/service/kafka`, holding the step and
key constants both sides import.

It is not created now because it would have one consumer, and a shared vocabulary
invented before its second consumer exists is a guess about what that consumer
needs. Moving constants is mechanical; designing the wrong package is not.

**Reopen when the first Kafka diagnosis rule is written.**

### 9. A failed transport path produces no SKIPPED protocol node, and that is deferred rather than decided

A path whose TCP or TLS step failed never reaches this adapter, so no
`kafka.api_versions` node is recorded for it. The report shows the failed L2 or
L3 node and stops there.

**That is not the subject rule doing the work.** `docs/ARCHITECTURE.md` section
12 permits a skipped node when the step was requested, its subject can be named
honestly, and an upstream prerequisite prevented execution. For a concrete
address all three look satisfiable: the subject would be the same `ip:port` the
skipped TLS node already uses, and the blocker would be the exact transport node
that failed. So the absence is not forced by ADR 0020, the way it is for a
lookup that produced no address at all.

What produces it is the input contract. `transport.Result` carries
`Continuation` values — paths that completed — and `kafka.Run` takes those. The
adapter cannot see a failed path, so it cannot know that an address it was never
told about exists. Under the current API the set of requested Kafka exchanges
*is* the set of paths handed over, which makes the absence honest; but it is
honest as a consequence of the plumbing, not because anything decided it.

The decision is deferred, because creating the node needs something that does
not exist yet:

- the transport chain cannot create it — a probe that knew the step
  `kafka.api_versions` would break `probe-is-service-agnostic`, which depguard
  enforces;
- the adapter cannot create it without an input wider than ADR 0024 defines, and
  even with one it would be asserting that Kafka was intended for an address
  nobody told it about;
- so it belongs to whatever holds both the full transport result and the
  knowledge that this is a Kafka run — the orchestration boundary section 7
  deliberately did not build.

It would also buy nothing today: no rule and no renderer consumes evidence yet,
so the only gain is a more complete-looking graph, and a node created for that
reason is a synthetic fact with better manners.

**Reopen when** either arrives, whichever is first:

1. a Phase 3 orchestration layer sequences transport and the adapter for one
   endpoint, and therefore knows what was requested rather than what succeeded;
   or
2. a diagnosis rule needs to distinguish "L4 was never reached for this address"
   from "this address has no L4 node", and cannot answer it from the failed
   transport node alone.

Until then the current shape is a consequence, not a policy, and this record is
what stops it from quietly becoming one.

## Context

`docs/SCOPE.md` fixes the Kafka order: DNS, TCP, TLS, ApiVersions, SASL,
Metadata, topology. Phase 3.1 is the first step past generic transport, so it is
where the adapter boundary either holds or quietly stops holding.

The risk it guards against is specific. An adapter that dialed its own connection
would make every transport fact in the report describe a socket the protocol
never used, and nothing would fail: the code compiles and the report looks right.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Ask one path and move on | Hides an inconsistent broker behind a working one, which is what a bootstrap name with several backends produces. That is a production client's goal | Never for ApiVersions; a later request whose answer is cluster-wide rather than per-connection may differ |
| Let the caller choose which path to ask | Pushes a Kafka decision into a layer that has no Kafka knowledge, and there is no such caller yet | A caller appears with a reason of its own |
| Use `kgo` | It owns connections, retries and refreshes metadata; it would break the connection lifecycle ADR 0008 requires | Never for the measured path |
| Hand-roll the wire format | A second Kafka implementation inside a tool that has to be right about Kafka | Never |
| Close the connection after collecting evidence | Would force SASL and Metadata to dial again, breaking the invariant the last three phases were built around | Never |
| Keep a connection after a broken exchange | Its protocol state is unknown; handing it on would push an undiagnosable failure into the next phase | Never |
| A node per advertised API key | Seventy nodes per path, burying the transport evidence | A rule needs per-key relationships the list cannot express |
| Kafka-specific `FailureClass` values in the domain | `internal/domain` is service neutral; the error code is an attribute | Never |
| Leave every broker error code at `PROTOCOL_UNEXPECTED_RESPONSE` | Puts a broker that declined a version in the same class as a peer that is not Kafka at all, discarding a generic fact the response states outright | Rejected in this record; the mapping is one code wide |
| Map further codes, for example `ILLEGAL_SASL_STATE` to an auth class | Reads a cause out of a number. Whether an authentication state explains a run is diagnosis, over evidence this adapter does not have | A response proves a generic fact by itself, as code 35 does |
| A SKIPPED `kafka.api_versions` node for a failed transport path | Nothing in this phase knows the step was requested for an address the adapter never saw; see section 9 | Phase 3 orchestration exists, or a rule needs the distinction |
| A generic `Adapter` interface now | One implementation, no consumer, and a method set that could only guess at PostgreSQL | The second adapter, or the first composition root |
| `internal/service/kafka` now | One consumer today; a shared vocabulary invented before its second consumer is a guess | The first Kafka diagnosis rule |

## Consequences

- A report can show that one broker behind a bootstrap name answers differently
  from another, which is the class of problem the Kafka slice exists to explain.
- The protocol layer speaks over the connection whose DNS, TCP and TLS facts are
  all in the report, and a test fails if that ever stops being true.
- Replacing franz-go means rewriting one package whose entire surface is three
  plain types and three sentinel errors.
- The project has one runtime dependency, with no transitive dependencies.
- Phase 3.2 receives live sessions with the identifier of each ApiVersions node,
  so SASL evidence can parent to the exchange that preceded it on the same socket.
