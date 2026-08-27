# RabbitMQ Phase 8.2-R3 — validation and implementation closure

Phase 8.0 measured four brokers with a scratch client and established what they do. Phase 8.1
froze the contract in ADRs 0067 to 0070. Phase 8.2 implemented it. **This phase is the first
in which svcdoctor itself spoke AMQP 0-9-1 to a real broker**, and it is what moves RabbitMQ
and LavinMQ off Level 0 in `docs/COMPATIBILITY.md`.

Nothing here was validated with cloud credentials, and none were used.

## 1. Brokers

| Broker | Image | Fixture |
|---|---|---|
| RabbitMQ 4.2.0 | `rabbitmq:4.2.0` | `test/integration/rabbitmq` |
| RabbitMQ 4.0.9 | `rabbitmq:4.0.9` | same |
| RabbitMQ 3.13.7 | `rabbitmq:3.13.7` | same |
| LavinMQ 2.3.0 | `cloudamqp/lavinmq:2.3.0` | `test/integration/lavinmq` |

The images are the ones Phase 8.0C measured. The scenario broker enables `rabbitmq_management`
at runtime rather than using the `-management` image variant, which keeps the digest identical
to the one the contract study used while still giving RAB-18 a real management listener.

**Ground truth is established before svcdoctor is asked**, in every scenario, through
`rabbitmqctl` or through `env/groundtruth.py` — a scratch AMQP client written for the phase
that shares no code with the implementation under test. A suite that only compared svcdoctor
against itself would pass just as happily against a broker that had changed underneath it.

## 2. Two fixture defects worth recording

**A root-owned readiness probe killed the broker it was checking.** `docker exec` defaults to
root, `/var/lib/rabbitmq` is mode 1777, and an Erlang command that runs before the server has
written its cookie creates `.erlang.cookie` owned by root with mode 0400. The server runs as
uid 999, cannot read it, and exits — so the probe caused the failure it was looking for, and
the symptom at the socket was indistinguishable from RAB-16. Measured: probing as root killed
the broker in 12 out of 12 attempts. Every exec in the Makefile now runs as `rabbitmq`.

**Every fixture in this repository lives in a directory named `env`**, so Compose derived the
same project name for all of them and `down --remove-orphans` in one deleted another's
containers. Observed live: bringing up LavinMQ destroyed the running RabbitMQ brokers. Kafka
and Redpanda already set an explicit `name:`; postgres, redis and valkey did not. All five now
do. This would otherwise have corrupted the sequential regression in §12.

## 3. What svcdoctor was asked, and what it answered

Twenty BASIC scenarios (RAB-00 … RAB-25) and nine LavinMQ scenarios (LMQ-00 … LMQ-08), each
driven through `app.DiagnoseRabbitMQ` — the same entry point the CLI calls.

The frozen wire facts were asserted **against each version** rather than against one and
assumed for the rest:

| Fact | Result |
|---|---|
| `channel_max 1`, `frame_max 8192`, `heartbeat 0` | accepted by all four brokers |
| `authentication_failure_close` | advertised, and asserted by consequence |
| graceful `Connection.Close` / `Close-Ok` | completed |
| `Channel.Open`, queue, exchange, publish, consume | **zero**, structurally and at runtime |
| management API calls | **zero** |
| credential-bearing frames per run | **at most one**, counted from the broker's own log |
| reconnects, auth retries | **zero** |

**`authentication_failure_close` is load-bearing and was measured to be.** Without it, all four
brokers send **no AMQP frame at all** on a failed login and close the socket after about three
seconds — reproduced with the ground-truth client by omitting the capability. A rejected
credential would otherwise be indistinguishable from a peer close.

**Mechanism order is not stable and does not matter.** The three RabbitMQ releases advertised
`AMQPLAIN PLAIN`, `ANONYMOUS AMQPLAIN PLAIN` and `ANONYMOUS PLAIN AMQPLAIN` respectively — a
different order again from the one Phase 8.0C recorded for 4.2.0. Selection is by name.

### RAB-05, and why the guest sentence is a hint

The fixture restores RabbitMQ's own default by overriding the image's
`conf.d/10-defaults.conf`, which ships `loopback_users.guest = false`. With the real restriction
in force, `guest` with its **correct** password is refused from the Docker bridge — and the
refusal is **byte-identical** to a wrong password. svcdoctor cannot know which applied, which is
exactly why ADR 0068 §4.1 gates the sentence on the username alone and never states a cause.

### LavinMQ, and the template that was source-only

LavinMQ answers authentication refusals with class/method `10/11` where RabbitMQ sends `0/0`,
and names no vhost in its vhost-not-found text where RabbitMQ interpolates one. Neither
difference changes attribution: svcdoctor's own handshake state decides which stage failed.

**LMQ-06 upgraded a template from SOURCE-ONLY to MEASURED.** Phase 8.0C could only derive
LavinMQ's connection-limit sentence from its source. The fixture sets a vhost
`max-connections` of 0 and measures it; the bytes matched the frozen template.

## 4. Raw peer text

No byte of a peer's `reply_text` reaches a report. Each refusal scenario asserts it twice: the
exact sentence the ground-truth client measured is absent, and so is every span that appears in
a broker's prose and in nothing svcdoctor can say on its own.

The check is deliberately narrow. `ACCESS_REFUSED` on its own would be a false positive, because
svcdoctor's **own** normalized outcome constant `VHOST_ACCESS_REFUSED` contains it — so the
marker carries the `" - "` that the symbolic-name prefix always has and the constant never does.

Two adversarial cases from Phase 8.0C are covered, and a third was added: a crafted **username**
carrying a capacity sentinel, which is the crafted-vhost hazard mirrored onto the operand
8.0C did not craft. Construct-and-compare classifies all of them correctly.

## 5. Fuzzing

Every target run individually and bounded. **Zero crashers, zero reproducers retained.**

| Target | Execs | Crashers |
|---|---|---|
| `FuzzReadFrame` | 15,047,676 | 0 |
| `FuzzParseClose` | 10,923,550 | 0 |
| `FuzzNormalizeClose` | 8,914,150 | 0 |
| `FuzzWalkTopLevelTable` | 8,309,671 | 0 |
| `FuzzParseStart` | 204,901 | 0 |

**The previously observed stall reproduced, and is not a product defect.** `FuzzParseStart`
reaches ~205k execs and then reports `0/sec` for the rest of the budget. Diagnosis: the worker
sits at 125% CPU with stable RSS, no individual execution exceeds a three-second watchdog, no
crasher is ever produced, and Go's own message when the worker is signalled reads *"hung or
terminated unexpectedly **while minimizing**"*. Shrinking the 4000-byte mechanisms seed removes
the stall entirely — 1,066,141 execs in 20s at a steady rate — which confirms the engine is
spending the budget minimizing a large interesting input rather than executing the target.

The seed is kept. `mechanisms` is a peer-controlled long string bounded only by the frame
ceiling and is exactly the field ADR 0067 §4.2 forbids copying, so a seed reaching toward the
ceiling is the one this target most needs. The characteristic is documented at the seed.

## 6. Mutation matrix

45 mutations executed — M1 to M44, plus M4b, *both authority checks removed simultaneously*.

| | |
|---|---|
| **Executable mutations** | 45 |
| **Caught** | 45 |
| **Survivors** | **0** |

Each was planted, shown to make the intended guard fail, and restored byte-for-byte with a
sha256 check. Compile-only failures were not counted as catches.

**Two genuine guard gaps were found and closed:**

- The adapter's `SecretFor` refusal could be **absorbed** — turned into an empty secret —
  without any test noticing, because the composition root refuses the same mismatch first and
  shadows it. ADR 0068 §6 says the refusal is returned, never absorbed, and that is now asserted
  structurally, because no behavioural test can see it.
- The closed mechanism set could be **widened by one token** with nothing to stop it.
  `TestTheRecognizedMechanismSetIsExactlyFrozen` now pins it by value.

A defect in the mutation driver itself is worth recording: every guard piped into `tail`, so the
captured exit status was `tail`'s zero rather than `go test`'s failure. Eight mutations were
briefly reported as survivors that had in fact been caught. `pipefail` fixed it.

## 7. Harness

Five scenarios migrated to Validation Harness v1 — RMQ-H1 wrong credential, H2 vhost not found,
H3 vhost access refused, H4 local timeout, H5 resource limit reached. **`test/harness` contains
no RabbitMQ branch**, and a guard asserts it.

Each pins the first broken layer, the state, the failure class, the finding codes, the
incompleteness, a credential-attempt upper bound and at least one forbidden claim.

`CredentialAttempts` is counted from the **broker's own log** — one line per credential-bearing
exchange — rather than from svcdoctor's authentication nodes, which would make the bound a
restatement of the thing under test. H4 uses a silent fake peer, which can prove zero frames
arrived where a blackhole address cannot.

Non-vacuity is proven by driving `harness.Assert` with a recording `T` and fifteen deliberately
wrong expectations, each of which is rejected, plus a control that is accepted.

## 8. What is still not claimed

- **`541 INTERNAL_ERROR` vhost-down** — still SOURCE-PROVEN and never live-measured. No
  normalized outcome is authorized for it.
- **Backend-qualified vhost denial** (`" by backend …"`) — still **SOURCE-ONLY**. No
  authorization-backend plugin was installed.
- **Clusters** — svcdoctor opens one connection to one endpoint and discovers nothing.
- **Client certificates, `EXTERNAL`, mTLS** — not implemented, not claimed.
- **Every managed provider** — Level 0. None was contacted.
