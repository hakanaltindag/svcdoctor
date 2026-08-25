# ADR 0070: The RabbitMQ Tune contract, and one frame ceiling instead of eight constants

## Status

**Accepted in Phase 8.1. Not implemented.**

It fixes the three values svcdoctor sends in `Connection.Tune-Ok`, the outcome of a
negotiation refusal, and every defensive bound the RabbitMQ wire package is permitted to
hold.

`SchemaVersion` stays **1**. No `FailureClass`, no `FindingCode`, no dependency.

Companion records: [0067](0067-rabbitmq-basic-journey-and-terminal-boundary.md) is the
journey, [0069](0069-rabbitmq-vhost-authorization-and-close-normalization.md) owns the
outcome vocabulary.

It is ADR 0061's lesson applied to a second parser. That record exists because a
defensive bound was justified as "8× the largest common value" and a real broker
falsified it. The response here is not eight better-chosen constants; it is **one
constant with a source, and everything else derived from bytes already read.**

## 1. Measured broker behaviour

Phase 8.0C, four brokers, all measurements against real instances:

| | RabbitMQ 3.13.7 | RabbitMQ 4.0.9 | RabbitMQ 4.2.0 | LavinMQ 2.3.0 |
|---|---|---|---|---|
| `Connection.Tune` offers | 2047 / 131072 / 60 | 2047 / 131072 / 60 | 2047 / 131072 / 60 | 2048 / 131072 / 300 |
| `Connection.Start` frame | 522 B | 530 B | 529 B | 328 B |
| `Start` with 5 custom properties | — | — | **712 B** | — |
| `frame_max = 4096` in `Tune-Ok` | accepted | accepted | **refused** | — |
| `frame_max = 8192` in `Tune-Ok` | accepted | accepted | accepted | accepted |
| `channel_max = 0` | — | — | **refused** | — |
| `channel_max = 1` | accepted | accepted | accepted | accepted |
| `heartbeat = 0` | accepted | accepted | accepted | accepted |

The `frame_max` result is a real version gate: RabbitMQ raised its internal
`?FRAME_MIN_SIZE` from 4096 to 8192 at v4.1.0, and 4096 now fails on current releases
while remaining legal per the AMQP 0-9-1 specification.

## 2. The values svcdoctor sends

| Field | Value | Derivation |
|---|---|---|
| `channel_max` | **1** | `1` is RabbitMQ's `?CHANNEL_MIN`, and `1 ≤` every non-zero server value measured. svcdoctor opens zero channels, so `1` is the smallest legal statement it can make. |
| `frame_max` | `server == 0 ? 8192 : min(8192, server)` | `8192` is `?FRAME_MIN_SIZE` on current RabbitMQ — a value the implementation fixes, not a multiple of anything observed. The clamp satisfies the 4096-floor of 3.13/4.0 and LavinMQ and the 8192-floor of 4.1+ simultaneously. |
| `heartbeat` | **0** | §4 |

**`0` is not "no limit" here, and that is the trap.** RabbitMQ's
`validate_negotiated_integer_value/3` refuses a client value of `0` for either field
whenever the server's own configured value is non-zero, which is the default. The AMQP
specification's "zero indicates no specified limit" is true of the specification and
false of this broker. Measured.

If the clamp would yield a value below **4096** — the specification's `frame-min-size`,
and the floor LavinMQ enforces — svcdoctor refuses locally rather than sending it. That
only arises against a broker configured below its own minimum, which no client can
satisfy.

## 3. An invalid `Tune-Ok` produces no `Connection.Close`

Phase 8.0A predicted `Close(530)` attributed to `connection.tune`, and **Phase 8.0C
falsified it.** Measured on RabbitMQ 4.2.0 for `channel_max = 0`, `frame_max = 0` and an
over-limit `channel_max`: the broker logs *"failed to negotiate connection parameters"*
and then **closes the socket silently, about three seconds later**, with no frame of any
kind.

The cause is in the reader's exception dispatch: `fail_negotiation` raises with the
method set, so the `#amqp_error{method = none}` catch does not match and the error
reaches the catch-all, which sleeps and throws rather than sending a close.

Two consequences, both of which simplify the contract:

1. **The outcome is a peer close while awaiting `Open-Ok`**, classified
   `PROTOCOL_PEER_CLOSED` and owned by `rabbitmq.connection_open`. It is not a distinct
   failure class and it authorizes no finding code beyond
   `RABBITMQ_CONNECTION_NOT_ESTABLISHED`.
2. **The disambiguation rule Phase 8.0B designed is deleted rather than implemented.**
   That rule existed because a `Close` arriving after both `Tune-Ok` and `Open` had been
   written could belong to either; with no `Close` on the tune path, the ambiguous
   position does not exist. svcdoctor's own handshake state is sufficient, as ADR 0069 §1
   requires.

Because svcdoctor derives its `Tune-Ok` values from the server's own proposal, a
negotiation refusal means the broker refused values it offered — a broker
misconfiguration. svcdoctor reports what it observed and names no cause.

## 4. `heartbeat = 0`, and no heartbeat loop

RabbitMQ takes the client's `Tune-Ok` heartbeat **verbatim**: the reader stores
`timeout_sec = ClientHeartbeat` and starts the heartbeater with the same value. The
"negotiation rule" in the documentation is a client-side convention, not something the
broker applies.

So advertising a non-zero heartbeat would be a promise svcdoctor does not keep, and a run
that stalled — a slow `Open` on a loaded broker, or a broker configured with a low
heartbeat — would be killed by a mechanism svcdoctor implemented no half of. Sending `0`
makes *"does BASIC need a heartbeat loop?"* **unreachable** rather than merely unlikely.
That is ADR 0063 §6.2's move applied to a different protocol.

The cost is stated rather than hidden: svcdoctor will not detect a broker that would kill
a real client for missed heartbeats. BASIC does not claim to.

One measured side effect is part of the contract: with `heartbeat = 0`, RabbitMQ holds
the socket for up to 30 seconds after `Close-Ok`. **svcdoctor closes its own socket
immediately** and does not wait.

The server's proposed heartbeat and svcdoctor's selected value are both recorded as
attributes on `rabbitmq.authentication`. Neither is a finding — ADR 0069 §8.

## 5. Resource bounds: one ceiling, and a structural depth of one

| # | Bound | Value | Executes | Justification |
|---|---|---|---|---|
| 1 | pre-Tune inbound frame payload | **8184** (8192 − 8) | on the frame header, before a payload byte is read | 8192 is the value RabbitMQ's own `initial_frame_max` defaults to. A peer exceeding it before Tune violates the AMQP `frame-min-size` contract and breaks RabbitMQ's own default clients. |
| 2 | post-Tune inbound frame payload | negotiated `frame_max` − 8 | same | accepting more than svcdoctor advertised would be a protocol lie |
| 3 | frame overhead | **8** bytes: type 1, channel 2, size 4, end 1 | — | the protocol's own layout |
| 4 | frame-end marker | **0xCE** | on every frame | `?FRAME_END = 206`; anything else is `PROTOCOL_MALFORMED_RESPONSE` |
| 5 | `reply_text` | **255** bytes | on the length byte | the `shortstr` maximum; longer is malformed |
| 6 | vhost input | **127** bytes | on operator input, before connecting | the `path` domain's own assert |
| 7 | field-table nesting | **1, structurally** | — | §5.1 |

**Nothing else is bounded, and that is deliberate.** The measured `Connection.Start`
frames were 328–712 bytes against a ceiling of 8192, and §6 forbids tightening the
ceiling toward them.

### 5.1 The parser never descends, so there is no depth bound to get wrong

RabbitMQ's own `parse_table/1` has **no depth counter at all**, so there is no
implementation-fixed number to borrow, and any number svcdoctor picked would be exactly
the "N× the observed value" reasoning ADR 0061 forbids.

> **svcdoctor extracts only the top-level `product`, `version`, `cluster_name` and
> `platform` from `server-properties`, and skips every other value by its declared
> encoded length without entering it.** A nested table or array is skipped, never
> recursed into.

Recursion depth is then **1 by construction**. The nesting attack surface is deleted
rather than defended. Phase 8.0C validated it against a broker configured with three
extra top-level entries, a two-deep nested table and an array: the four identity keys
stayed top-level and every unknown value was skippable by declared length.

`capabilities` is not read at all. svcdoctor needs to *send* a capability (ADR 0068 §3),
not read one.

Skipping still requires a complete type-to-length table for every AMQP 0-9-1 and QPid
extension field type. That is a size lookup with no allocation.

### 5.2 Two caps proposed in Phase 8.0A are deleted, not replaced

- **A 128-entry top-level table cap.** Deleted. The walk is already bounded by bound 1,
  and a minimal entry is 2 bytes, so entries cannot exceed 4092 and the walk terminates.
  No source constant justified 128.
- **A 64-token mechanism cap.** Deleted. svcdoctor needs one answer — *is the token
  `PLAIN` present in this space-delimited `longstr`?* — which is a single scan over bytes
  already in the frame, building no list. There is no count to cap.

Both are now bounded by the one constant that has a source. That is the shape ADR 0061
asked for: derive from an already-fixed byte budget, or delete the cap structurally.

## 6. The measured sizes must not become the bound

The largest `Connection.Start` measured was 712 bytes, 8.7% of the ceiling. It is
tempting to tighten 8192 toward it.

**That is forbidden**, and ADR 0061 is why. An operator may add arbitrary entries to
`server_properties` — Phase 8.0C did exactly that and the frame grew 183 bytes — a future
release may add fields, and a different implementation has a different shape. The bound
must come from a value an implementation fixes, not from a sample.

## 7. Refusing a bound

A bound violation is `PROTOCOL_MALFORMED_RESPONSE`, the connection is closed, and
**nothing is allocated beyond the header already read**. That is the Redis rule
unchanged.

## 8. Timeouts have a floor, because several RabbitMQ refusals are deliberately slow

RabbitMQ's `SILENT_CLOSE_DELAY` is three seconds, applied on its catch-all exception path
and on fatal frame errors, explicitly so that a client cannot retry failed logins
quickly. Phase 8.0C measured every authentication refusal and every tune refusal taking
almost exactly three seconds end to end.

> **The per-step timeout must exceed three seconds**, so that a broker's deliberate delay
> is never reported as svcdoctor's own budget expiring.

The existing 10-second `--step-timeout` default satisfies this. RabbitMQ's own
`handshake_timeout` is 10 seconds, which is the other side of the same window: the whole
handshake must complete inside it or the broker kills the connection.

## 9. Reopen conditions

1. **A measured `Connection.Start` approaches 8192.** Then the ceiling needs re-deriving
   from a new implementation-fixed value, not raising by a multiple.
2. **A peer requires a field svcdoctor can only reach by descending.** Today none does;
   §5.1 would have to be reopened with the specific field named.
3. **A broker refuses `frame_max = 8192` or `channel_max = 1`.** That would falsify §2
   and must be measured, not inferred.
4. **BASIC gains an operation after `Open-Ok`.** `channel_max = 1` and `heartbeat = 0`
   are both justified by there being nothing after the terminal boundary.
