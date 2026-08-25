# RabbitMQ Phase 8.0 — contract study and wire measurements

What Phases 8.0A, 8.0B and 8.0C established, and which of it is measured rather than
read. ADRs [0067](../decisions/0067-rabbitmq-basic-journey-and-terminal-boundary.md) to
[0070](../decisions/0070-rabbitmq-tune-contract-and-wire-bounds.md) are the decisions;
this is the evidence behind them.

**No RabbitMQ code exists.** Nothing here is a compatibility claim —
`docs/COMPATIBILITY.md` records RabbitMQ and LavinMQ at Level 0, and they stay there
until an implementation is run against them.

## 1. What each phase did

| Phase | Method | Output |
|---|---|---|
| **8.0A** | RabbitMQ server source, the RabbitMQ-vendored AMQP 0-9-1 spec, LavinMQ source, vendor documentation | the semantics survey and a first contract proposal |
| **8.0B** | adversarial re-derivation from the same primary sources, plus OTP's `io_lib_format` | six corrections to 8.0A, three of them load-bearing |
| **8.0C** | four brokers in Docker, a raw AMQP client with no channel/queue/exchange encoder | the measurements below |

Phase 8.0C modified no repository file, opened no channel, sent no queue or exchange
method, called no management API, sent exactly one credential-bearing frame per scenario
and used lab-only generated credentials. All containers, networks and volumes were
destroyed.

## 2. Brokers

| Broker | Image | Digest |
|---|---|---|
| RabbitMQ 3.13.7 | `rabbitmq:3.13.7` | `sha256:87178a0ee3e2f52980ba356d38646ed1056705ff2d5ff281f8965456eaa0c1e3` |
| RabbitMQ 4.0.9 | `rabbitmq:4.0.9` | `sha256:b3202c4c90cec335e1c2f61605a4df8fcd2fc476f23287bfd1ac580da79bd807` |
| RabbitMQ 4.2.0 | `rabbitmq:4.2.0` | `sha256:8b31dd492c1f97d48127326dd07519f8aa854b6e75cb7ebf76878daba1c57259` |
| LavinMQ 2.3.0 | `cloudamqp/lavinmq:2.3.0` | `sha256:3dd7f348e5ef59dc62d4a9b0216e7f980f98afa7aee718e1c7226e7997c14da3` |

## 3. `Connection.Start`

| Broker | Frame | Properties table | Mechanisms offered |
|---|---|---|---|
| 3.13.7 | 522 B | 477 B | `AMQPLAIN PLAIN` |
| 4.0.9 | 530 B | 475 B | `ANONYMOUS AMQPLAIN PLAIN` |
| 4.2.0 | 529 B | 474 B | `PLAIN AMQPLAIN ANONYMOUS` |
| 4.2.0 + 5 custom `server_properties` | **712 B** | 657 B | as 4.2.0 |
| LavinMQ 2.3.0 | 328 B | 283 B | `AMQPLAIN PLAIN` |

- `product`, `version`, `platform` and `cluster_name` are **top-level on every RabbitMQ
  broker**, including the one with custom properties. LavinMQ has no `cluster_name`,
  `copyright` or `information`.
- Maximum nesting is **1** by default (`capabilities` only), and **2** when an operator
  configures a nested table. Every unknown value was skippable by declared encoded length
  without descending — ADR 0070 §5.1.
- **Mechanism ordering is not stable across releases with identical configuration**, which
  is why ADR 0068 §2 selects by name and ignores order.
- Largest frame measured is **8.7% of the 8192 pre-Tune ceiling**. ADR 0070 §6 forbids
  tightening the ceiling toward it.

## 4. `Connection.Tune`

Offered by every RabbitMQ broker: `channel_max 2047`, `frame_max 131072`,
`heartbeat 60`. LavinMQ offers `2048 / 131072 / 300`.

| `Tune-Ok` sent | 3.13.7 | 4.0.9 | 4.2.0 |
|---|---|---|---|
| `channel_max = 1`, `frame_max = 8192`, `heartbeat = 0` | accepted | accepted | accepted |
| `frame_max = 4096` | accepted | accepted | **refused** |
| `channel_max = 0` | — | — | **refused** |
| `frame_max = 0` | — | — | **refused** |
| `channel_max = 2048` | — | — | **refused** |

**Every refusal was silent.** No `Connection.Close` frame of any kind; the socket closed
about three seconds after `Tune-Ok`, with the broker logging *"failed to negotiate
connection parameters"*. This **falsifies** Phase 8.0A's prediction of a `Close(530)`
attributed to `connection.tune` — see ADR 0070 §3.

## 5. Authentication

With `authentication_failure_close` advertised, on **both 3.13.7 and 4.2.0**, and
byte-identical between them:

```text
reply_code    403
class/method  0/0
reply_text    108 B
              ACCESS_REFUSED - Login was refused using authentication mechanism PLAIN.
              For details see the broker logfile.
```

A **wrong password and an unknown user produced byte-identical frames** — the
indistinguishability RabbitMQ's source describes, confirmed on the wire.

Without the capability: **no AMQP frame at all**, socket closed after about three
seconds, on both versions. ADR 0068 §3 makes the capability mandatory on this basis.

LavinMQ answers `403` with class/method `10/11` and a 17-byte `ACCESS_REFUSED - `.

**Credential leakage check.** Zero occurrences of the real lab password and zero
occurrences of a deliberately wrong password across all four brokers' logs. The
source-identified echo path requires a *malformed* PLAIN response, which a correct
encoder never produces — ADR 0068 §8.

## 6. `Connection.Open` refusals

Every RabbitMQ row below was byte-identical on 3.13.7 and 4.2.0, and every one carried
`reply_code 530` with `class_id/method_id 10/40` — so **the numeric code and the method
ids discriminate nothing** within this group.

| Condition | `reply_text` |
|---|---|
| vhost not found | `NOT_ALLOWED - vhost <V> not found` |
| vhost access refused | `NOT_ALLOWED - access to vhost '<V>' refused for user '<U>'` |
| vhost connection limit | `NOT_ALLOWED - access to vhost '<V>' refused for user '<U>': connection limit (N) is reached` |
| user connection limit | `NOT_ALLOWED - connection refused for user '<U>': user connection limit (N) is reached` |
| node connection limit | `NOT_ALLOWED - connection refused: node connection limit (N) is reached` |

LavinMQ:

| Condition | `reply_text` |
|---|---|
| vhost not found | `NOT_ALLOWED - vhost not found` — **no vhost name** |
| vhost access refused | `NOT_ALLOWED - '<U>' doesn't have access to '<V>'` |

Every text on both implementations begins with the symbolic exception name and `" - "`.
Phase 8.0A's proposed anchors omitted that prefix and would have matched nothing; Phase
8.0A had also recorded the prefix as a LavinMQ *difference* when it is RabbitMQ's own
shape.

All three connection limits were reproduced live on 4.2.0. They are the second producer
that ADR 0069 §6 required before adding `RESOURCE_LIMIT_REACHED`.

## 7. Truncation, and two adversarial cases

**Truncation.** A 119-byte vhost and an 80-byte username under a vhost connection limit
produced a `reply_text` of **exactly 255 bytes ending in `...`**. The untruncated string
would have been 284 bytes, and `: connection limit (0) is reached` was **entirely
absent**. A prefix matcher still matched the bare-denial template and would have reported
an authorization denial for a capacity ceiling.

**Crafted name.** A vhost legally named `a': connection limit (5) is reached`, refused for
lack of permission, produced:

```text
NOT_ALLOWED - access to vhost 'a': connection limit (5) is reached' refused for user '<U>'
```

An infix matcher reported a capacity ceiling for an authorization denial.

**Result.** Across the ten measured reply texts, including both adversarial cases:

| Matcher | Correct |
|---|---|
| naive prefix/infix (Phase 8.0A) | 8/10 — **wrong on both adversarial cases** |
| construct-and-compare with truncation-first (Phase 8.0B) | **10/10** |

ADR 0069 §3 and §4 freeze the second.

## 8. Not measured

| Fact | Status |
|---|---|
| `541 INTERNAL_ERROR` vhost-down | **SOURCE-PROVEN, NOT LIVE-MEASURED.** Three bounded attempts, 27 probes against the `restart_vhost` window, never observed. ADR 0069 §6.2 and §8 gate what may be said about it. |
| backend-qualified vhost denial (`" by backend …"`) | **SOURCE-ONLY.** No authorization backend plugin was installed. It may classify — it only reaches a conclusion the bare template already supports — and may not produce its own sentence. |
| client certificates, `EXTERNAL` | out of scope; ADR 0068 §10 |
| any managed provider | **none was contacted.** No cloud credential was used at any point. |

## 9. What this does not establish

Every measurement above was taken by a scratch AMQP client written for the phase, **not
by svcdoctor**. It establishes what the brokers do; it establishes nothing about what
svcdoctor does, because svcdoctor does not speak AMQP yet.

RabbitMQ and LavinMQ therefore stay at **Level 0 — NOT EVALUATED** in
`docs/COMPATIBILITY.md`. Reaching Level 2 requires an implementation completing the BASIC
journey against a real instance, and Level 3 requires that plus a committed repeatable
test.
