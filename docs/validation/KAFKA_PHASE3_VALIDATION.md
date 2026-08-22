# Phase 3 Kafka integration validation

svcdoctor run against a real three-broker Apache Kafka cluster, to check that the
implementation which passes hermetic tests also behaves correctly against a
broker that does not know it is being tested.

The suite is `test/integration/kafka/`; this file records what it found and what
that means. Reproduce with `make integration-kafka`.

## Environment

| | |
|---|---|
| Kafka | Apache Kafka **4.0.0**, official `apache/kafka` image, **KRaft** (no ZooKeeper) |
| Topology | 3 brokers, combined broker+controller roles, node IDs 1/2/3 |
| Client listener | `EXTERNAL` — SASL_SSL, SASL/PLAIN, `localhost:19192` / `:29192` / `:39192` |
| Inter-broker | `INTERNAL` — PLAINTEXT on the compose network |
| TLS | throwaway CA, broker certificate with `SAN=localhost,broker-1..3,127.0.0.1` |
| Runtime | Docker 28.3.3 via colima, linux/arm64 |
| Reference oracle | **kcat 1.7.1** (librdkafka 2.15.0), plus Kafka's own CLI tools |

**Why SASL_SSL and not PLAINTEXT.** `kafka.Metadata` takes an
`*AuthenticatedSession`, whose only constructor is a successful SASL
authentication, and the default credential-transport policy then requires
verified TLS. SASL_SSL is therefore the only listener shape that reaches topology
discovery at all. The restriction is svcdoctor's, not Kafka's — a real broker
serves Metadata happily on a PLAINTEXT listener — and it is already recorded in
`internal/adapter/kafka/metadata.go` and ADR 0031.

## Healthy baseline

29 evidence nodes, **zero findings**, `status: OK`, 325 ms.

Every layer reached: DNS → TCP → TLS → ApiVersions → SaslHandshake →
SaslAuthenticate → Metadata → three advertised sweeps. `localhost` is dual-stack
here, so every endpoint was measured over both `127.0.0.1` and `[::1]`.

### Four-way topology comparison

| | broker 1 | broker 2 | broker 3 |
|---|---|---|---|
| Configured `advertised.listeners` | `localhost:19192` | `localhost:29192` | `localhost:39192` |
| Kafka-reported (broker CLI) | registered | registered | registered |
| kcat `-L` | `broker 1 at localhost:19192` | `broker 2 at localhost:29192` | `broker 3 at localhost:39192` |
| svcdoctor `kafka.broker_advertised` | node 1, `localhost:19192` | node 2, `localhost:29192` | node 3, `localhost:39192` |

Node identifiers, endpoints and broker count agree exactly across all four.

## The controller field does not name the controller under KRaft

The one real disagreement of the whole exercise, and it is not svcdoctor's.

Sampled at one moment on an idle, stable cluster:

```text
KRaft quorum leader (kafka-metadata-quorum)   node 1   (stable)
kcat -L                                       broker 3 "(controller)"
svcdoctor kafka.metadata.controller_id        2
```

Eight consecutive Metadata reads returned `1, 1, 2, 1, 1, 3, 2, 3` while the
quorum leader stayed node 1 throughout.

**Kafka is behaving correctly.** KRaft controllers are not brokers, so
`MetadataResponse.controllerId` cannot name one; a broker answers with an
arbitrary live broker so that a legacy client routing admin requests "to the
controller" reaches something able to serve them. kcat renders the same field the
same way, so kcat and svcdoctor agree about the *field* and merely read different
responses.

**This vindicates a design decision.** ADR 0034 §15 refused to let controller
identity affect severity, reasoning that a controller moves on election. Reality
is stronger: under KRaft the field is arbitrary per response, so a rule reading it
would have produced a different severity on identical runs of a healthy cluster.

**Fixed here:** the doc comment on `AttrMetadataControllerID` claimed the value is
"the node the cluster named as its controller". It now says what the field is —
a record of one response — and why nothing may be concluded from it. No behaviour
changed; the attribute remains a faithful record, which is the evidence contract.

## Failure scenarios

All injected by broker configuration. svcdoctor was never modified to make a
scenario pass.

| Scenario | Injection | Kafka reality | kcat | svcdoctor evidence | Finding |
|---|---|---|---|---|---|
| Advertised DNS failure | `ADV_2=…invalid:9092` | cluster healthy, advertises an unresolvable name | lists the endpoint, later connection fails | `dns.lookup` FAIL `DNS_NO_ADDRESS`; **no TCP/TLS node minted** | 1 × `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE`, CONFIRMED/ERROR/HIGH, refs = metadata + advertisement + DNS |
| Advertised TCP refusal | `ADV_2=localhost:29999` | port closed | connection refused | both TCP paths FAIL `TCP_CONNECTION_REFUSED`; both TLS children SKIPPED `EXEC_SKIPPED_PREREQUISITE_FAILED`, each naming its blocker | 1 finding citing **the two TCP failures**, not the skips |
| Advertised TLS failure | broker-2 serves `SAN=not-the-broker.invalid` | TCP accepts, certificate wrong | handshake fails | TCP PASS, both TLS paths FAIL `TLS_HOSTNAME_MISMATCH` | 1 finding citing **the TLS failures**, no passing TCP node; summary names `L3 TLS_HOSTNAME_MISMATCH` |
| Partial address success | broker-2 published on IPv4 only | one family reachable | picks one address | `[::1]` TCP FAIL, `127.0.0.1` TCP+TLS PASS | **no finding** — failure stays visible in evidence |
| One bad broker of three | `ADV_2=localhost:29999` | two brokers fine | — | one failed sweep | exactly **1** broker-scoped finding, `PROBLEMS_FOUND` |
| All three bad | `ADV_1..3` unreachable | cluster still answering Metadata | — | three failed sweeps | **3** findings, one per advertisement, **no cluster aggregate**, no "down"/"unavailable" wording |
| Wrong credential | wrong password | broker rejects | auth fails | `kafka.sasl_authenticate` FAIL `AUTH_CREDENTIALS_REJECTED` | no finding (no rule owns auth yet); **no secret, identity or broker error text in either report form** |
| Unsupported mechanism | request `SCRAM-SHA-512` | broker offers PLAIN only | — | handshake FAIL `AUTH_MECHANISM_NOT_OFFERED`, offered list `[PLAIN]` recorded | — |

**The bootstrap stayed healthy in every advertised-failure scenario**, which is
the contrast the flagship finding rests on: the cluster answered, and *then*
advertised something this client cannot use.

## Connection ownership

Four protocol exchanges — ApiVersions, SaslHandshake, SaslAuthenticate, Metadata
— on a real broker, with a dialer that records every socket it opens:

```text
2 TCP connections for 2 measured addresses: [127.0.0.1:62259  [::1]:62260]
```

One connection per measured address, and no more. **No redial, no reconnection,
no hidden broker selection.** The adapter structurally cannot dial — it receives
live connections from the transport chain — and this measures it rather than
assuming it.

## Unusable advertisements: a real broker will not emit one

`KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` (ADR 0035) fires on an advertisement with no
host or a port outside 1–65535. Apache Kafka 4.0 normalizes both away:

| Configured | What Metadata reports |
|---|---|
| `EXTERNAL://localhost:0` | `localhost:9092` — the port the listener actually bound |
| `EXTERNAL://:9092` | the broker's own hostname substituted |

So the finding cannot be produced by a correctly functioning Kafka broker. It
remains correct and unit-tested, and its realistic sources are a proxy or service
mesh rewriting Metadata, a non-Kafka implementation of the protocol, or a
corrupted response — not `advertised.listeners`. Recorded as a negative result
rather than removed: the claim is about what a response carries, and svcdoctor
does not get to assume the response came from Apache Kafka.

The related gap — entries whose text cannot become a subject at all, surviving
only as `kafka.metadata.unrepresentable_entry_count` — **did not occur**: no real
run produced a non-zero count. Producing one would need a proxy, for the same
reason.

## Redaction

Every scenario produced both report forms.

```text
healthy run:  hostname=5  ip=2  evidenceId=29  prose=0
```

- Advertised hostnames, the bootstrap host, the vantage and all IP addresses are
  pseudonymized; every evidence identifier is remapped.
- All finding references resolve in the redacted graph; graph size is unchanged.
- Broker node identifiers survive, which is what keeps a shared report readable
  once hostnames are pseudonyms.
- Prose was rewritten **zero** times, because no finding prose carries identity.
- Redaction is idempotent on a real-cluster report.
- No credential material appears in either form, in any scenario.

**The Phase 3.7.5 residual-scan limitation did not occur naturally.** Every
hostname this environment produces redacts cleanly. The limitation — an identity
whose text also occurs in unrelated report text, such as a host literally named
`kafka` — remains open in the backlog and is not a Phase 3 blocker.

The direct residual safety-net tests in `internal/security/redaction/residual_test.go`
plant a raw value in each of ten surfaces and require rejection. They remain a
mandatory closure gate, because a correct transformation makes the net dead code:
removing it breaks no happy-path test.

## Runtime

| | |
|---|---|
| Healthy run (in-process) | ~0.33 s |
| DNS / TCP / TLS failure run | ~0.12–0.35 s |
| Scenario wall clock incl. broker recreate | 48–82 s each |
| Full suite | **~6 min** |
| Cluster start to three registered brokers | ~15 s |

The cost is broker recreation, not svcdoctor. Diagnosis itself is sub-second even
with three failed sweeps.

## CI recommendation

**Do not run the full suite on every PR.** Six minutes plus a Docker daemon is the
wrong trade for a repository whose ordinary gate is hermetic and fast.

- **Every PR** — `make check` only, unchanged. No Docker.
- **Nightly and pre-release** — `make integration-kafka` in full.
- **On PRs touching `internal/adapter/kafka`, `internal/probe`, or
  `internal/security/redaction`** — a smoke subset (`TestHealthyCluster`,
  `TestAdvertisedTCPRefused`, `TestOneConnectionCarriesEveryProtocolStep`),
  about 80 s, which covers composition, the flagship finding and the ownership
  invariant.

## Environment quirks, not product defects

- **Colima's userspace port forwarder drops connections under load.** kcat and
  svcdoctor both hit it; openssl confirmed the TLS listener was healthy
  throughout. Not a Kafka or svcdoctor fault.
- **Colima leaks host port bindings after `compose down`**, which is why the
  ports are `19192`/`29192`/`39192` rather than the obvious `19092` family.
