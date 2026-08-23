# Redpanda integration validation

Runs svcdoctor against a real **Redpanda v25.1.9** broker.

```sh
make integration-redpanda      # up, test, down
```

Needs Docker. Excluded from `go test ./...` by the `integration` build tag, and
deliberately **not** part of `make check`.

## Why this exists

ADR 0061 reopened svcdoctor's SCRAM defensive bounds because of this broker.
Redpanda emits a **130-byte SCRAM salt** — hardcoded as `SaltSize` in its own
source — which encodes to **176 base64 characters**. svcdoctor v0.2.0 bounded the
encoded form at 172, so it refused the message *before decoding it* and reported
`PROTOCOL_MALFORMED_RESPONSE`. The message was legal RFC 5802 throughout; the
refusal was svcdoctor's own policy, and the report blamed the broker for it.

Phase 6.8 measured that against a container someone ran by hand. A decision
resting on evidence nobody can regenerate is not evidence, so this suite
regenerates it.

## The version is pinned, and the claim is about the version

`env/compose.yaml` pins `redpandadata/redpanda:v25.1.9`. Redpanda's salt size is
a compile-time constant in its source, so a floating tag would silently change
the thing under test. **"Redpanda" is not what is validated here — v25.1.9 is**,
and `docs/COMPATIBILITY.md` says so.

Nothing here says anything about **Redpanda Cloud**. Self-hosted evidence does
not transfer.

## What it covers

| | |
|---|---|
| `SCRAM-SHA-256` | success, wrong credential, no credential configured |
| `PLAIN` | success, wrong credential |
| TLS | verified against the fixture CA, with real SANs |
| Journey | ApiVersions, SaslHandshake, SaslAuthenticate, Metadata, advertised sweep |
| Invariants | one credential-bearing attempt; no protocol or auth step beneath an advertisement; no credential in the report |
| Architecture | no production source names Redpanda |

That last one is the invariant a vendor fixture is most likely to break. Redpanda
works because it speaks the Kafka protocol, and it has to keep working for that
reason alone — `app.DiagnoseKafka` is the only composition this suite calls, with
no separate harness that could quietly diverge.

## Fixture credentials

Two principals, created by `make redpanda-users` through the admin API, reached
with `docker exec` because it is **not published to the host**:

| principal | password |
|---|---|
| `svcdoctor` | `svcdoctor-redpanda-canary` |
| `plainuser` | `plainuser-redpanda-canary` |

Both are fixture-only values on a loopback container that exists for the length
of one test run. They authenticate nothing anywhere else, and the suite asserts
neither reaches a report.

The first principal cannot be created over the Kafka API — SASL is already on and
there is no credential yet to authenticate the request with. The admin API is not
SASL-gated, which is Redpanda's documented bootstrap path.

## Ports

`19291` plaintext and `19292` TLS. The admin API stays container-local and is
unpublished — it is not SASL-gated and it can create principals, so nothing
outside the container should reach it. Both published ports are clear of the
Kafka fixture
(`19192`/`29192`/`39192`) and the PostgreSQL one (`55432`/`55433`) so the suites
cannot collide.

**Do not run this concurrently with `make integration-kafka`.** Phase 7.0
observed one unexplained Kafka failure while a Redpanda instance was competing
for the same cores; closure evidence for either is only meaningful if it ran
alone.

## Resource flags

`--smp 1 --memory 1G --reserve-memory 0M --overprovisioned --check=false`.
Redpanda sizes itself for a dedicated host and refuses to start under Docker's
default share. None of these affects the protocol behaviour under test.
