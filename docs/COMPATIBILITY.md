# Compatibility

**What svcdoctor has actually been run against, and what it has only been read about.**

This document exists because those two are routinely conflated, and the conflation is worse
than saying nothing. A managed service whose protocol looks compatible is not a service
svcdoctor has diagnosed. Every row below carries the evidence that produced it.

Produced by Phase 6.8D. Nothing here was validated with cloud credentials, and none were used.

## 1. Evidence levels

| Level | Meaning |
|---|---|
| **0 — NOT EVALUATED** | no meaningful evidence |
| **1 — PROTOCOL-PLAUSIBLE** | primary documentation says the wire protocol and auth mechanism are ones svcdoctor implements, **and svcdoctor has never run against it** |
| **2 — TESTED BASIC** | svcdoctor completed the BASIC journey against a real instance |
| **3 — SUPPORTED BASIC** | real evidence **plus** a repeatable committed test **plus** documented known differences |

Level 1 is not a weak form of support. **It is a hypothesis.** It says nothing structurally
prevents the thing from working; it does not say anyone has seen it work.

Evidence labels, used per row: `REAL SERVICE TEST`, `DOCUMENTATION ONLY`, `NOT TESTED`,
`UNSUPPORTED BY CURRENT AUTH`, `BLOCKED BY ENVIRONMENT`, `UNKNOWN`.

## 2. What svcdoctor supports, independent of any platform

The left half of every "auth overlap" judgement below. **This is the whole list.**

| | Supported |
|---|---|
| Kafka SASL mechanisms | `PLAIN`, `SCRAM-SHA-256` |
| PostgreSQL authentication | SCRAM-SHA-256; `trust`; and *observed and declined* — MD5, cleartext, SCRAM-SHA-256-PLUS |
| Redis/Valkey authentication | `AUTH` password-only and `AUTH <username> <password>`, over verified TLS only |
| Transport | plaintext, TLS with system roots, TLS with a replacement CA (`--tls-ca-file`), verification override (`--tls-server-name`), `--tls-insecure` |
| Credential input | `--password-file`, `--password-stdin`. **Never a literal on the command line.** |
| Targets | hostname, IPv4 literal, IPv6 literal. **Not** a zoned IPv6 literal. |

**Not implemented, at all:** `SCRAM-SHA-512`, `OAUTHBEARER`, `GSSAPI`/Kerberos, `AWS_MSK_IAM`,
mTLS client certificates, connection-string parsing, any cloud SDK, any credential refresh, any
authentication retry or mechanism fallback.

A platform supporting a mechanism svcdoctor does not implement makes that platform
**unsupported for that mechanism**, however standard the mechanism is.

## 3. Kafka

| Platform | Wire | TLS | Auth overlap | Real tested | Level | Known gaps |
|---|---|---|---|---|---|---|
| **Apache Kafka** 4.0.0 | Kafka | verified TLS, custom CA, IP SAN | **`PLAIN` ✓, `SCRAM-SHA-256` ✓** | **YES** — 3-broker KRaft fixture | **3 — SUPPORTED BASIC** | none |
| **Redpanda self-hosted** v25.1.9 | Kafka (clients 0.11+) | verified TLS, custom CA, IP SAN | **`PLAIN` ✓, `SCRAM-SHA-256` ✓** | **YES** — committed `test/integration/redpanda` fixture | **3 — SUPPORTED BASIC** | Tested at **v25.1.9 only**. Its 130-byte SCRAM salt needed svcdoctor's defensive bounds re-derived (ADR 0061) — see below |
| **Redpanda Cloud** | Kafka | TLS 1.2 mandatory | `SCRAM-SHA-256` ✓ per docs | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. Self-hosted evidence does **not** transfer, and the self-hosted row moving to Level 3 does not move this one |
| **Confluent Cloud** | Kafka | TLS 1.2 mandatory, public CA | **`PLAIN` ✓** — API key = username, API secret = password | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. The credential shape fits `--user` + `--password-file` with no parsing; verified against svcdoctor's input model only, not against the service |
| **AWS MSK — SASL/SCRAM** | Kafka | `SASL_SSL`, provider CA bundle | **✗ — `SCRAM-SHA-512` only** | **NO** | **0 — NOT EVALUATED** | `UNSUPPORTED BY CURRENT AUTH`. MSK documents `sasl.mechanism=SCRAM-SHA-512`; svcdoctor implements SHA-256 and does not fall back |
| **AWS MSK — IAM** | Kafka | `SASL_SSL` | **✗ — `AWS_MSK_IAM` not implemented** | **NO** | **0 — NOT EVALUATED** | `UNSUPPORTED BY CURRENT AUTH`. Would need AWS SigV4 request signing and a cloud credential chain |
| **Azure Event Hubs (Kafka API)** | Kafka 1.0+ | `SASL_SSL` mandatory | **`PLAIN` ✓ (SAS)** · `OAUTHBEARER` ✗ | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`, SAS path only. Single stable virtual IP rather than per-broker endpoints, so the advertised sweep will look unlike a real cluster's |

### Redpanda self-hosted, in detail

The complete BASIC journey succeeds over **both `PLAIN` and `SCRAM-SHA-256` on a TLS
listener** — DNS, TCP, TLS, ApiVersions, SaslHandshake, SaslAuthenticate, Metadata,
advertised-endpoint sweep, terminal, canonical JSON, shareable redaction. The evidence graph is
structurally identical to Apache Kafka's, and `app.DiagnoseKafka` is the only composition the
fixture calls — **no production source names Redpanda**, which the suite itself asserts.

**`SCRAM-SHA-256` did not work until Phase 7.0b, and the reason was svcdoctor's.** Redpanda
issues a **130-byte SCRAM salt** — hardcoded as `SaltSize` in its own source — encoding to
**176 base64 characters**, and `internal/sasl/scram` bounded the *encoded* form at 172, so the
server-first was refused before it was decoded and reported as a malformed broker response. It
was legal RFC 5802 throughout.

ADR 0061 re-derived every defensive bound from measured resource cost rather than from how
common a value looked, and corrected the classification so a refusal svcdoctor makes is no
longer reported as a defect in the peer. Full measurements:
[`docs/validation/SCRAM_PHASE70_BOUNDS_STUDY.md`](validation/SCRAM_PHASE70_BOUNDS_STUDY.md) and
[`docs/validation/KAFKA_PHASE68_REDPANDA_STUDY.md`](validation/KAFKA_PHASE68_REDPANDA_STUDY.md).

**What Level 3 does and does not say here.** `make integration-redpanda` runs the whole journey
against a pinned `redpandadata/redpanda:v25.1.9` and is reproducible from a clean checkout. It
is evidence about **that version**: Redpanda's salt size is a compile-time constant in its
source, so another version is another measurement. Nothing here is a claim about Redpanda
Cloud.

### Azure Event Hubs — the credential shape is *not* the blocker

Event Hubs' SAS path uses `sasl.mechanism=PLAIN` with the username set to the literal
`$ConnectionString` and the password set to the entire connection string. That reads like a
problem for a tool that refuses connection-string input, and it is not: svcdoctor never parses
the password, so the connection string travels verbatim in a `--password-file`. Both this and
the Confluent Cloud API-key shape were checked against svcdoctor's input model and accepted
with no CLI change.

What remains unvalidated is everything else — whether the endpoint behaves like a Kafka broker
through ApiVersions, SaslHandshake, SaslAuthenticate and Metadata, and what its single-virtual-IP
topology does to the advertised sweep. **No connection-string parsing was added and none is
needed.**

## 4. PostgreSQL

| Platform | Wire | TLS | Auth overlap | Real tested | Level | Known gaps |
|---|---|---|---|---|---|---|
| **PostgreSQL self-hosted** 18 | PostgreSQL | in-band `SSLRequest`, custom CA, IP SAN | **SCRAM-SHA-256 ✓, `trust` ✓** | **YES** — fixture, TLS and plaintext servers | **3 — SUPPORTED BASIC** | none |
| **AWS RDS PostgreSQL** | standard | `rds.force_ssl=1` optional; **provider CA bundle, not in system stores** | **SCRAM-SHA-256 ✓** — default from PG 14; supported from 13.1 | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. Needs `--tls-ca-file <rds bundle>`; system roots will not verify. **IAM DB auth is a different thing and is not supported** |
| **Aurora PostgreSQL** | standard | as RDS | **SCRAM-SHA-256 ✓** | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. Same CA-bundle requirement. Writer/reader endpoints are separate hostnames; svcdoctor diagnoses whichever it is given and infers no cluster role |
| **Google Cloud SQL PostgreSQL** | standard | per-instance server CA, downloaded | **SCRAM-SHA-256 ✓** | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`, **direct TCP only**. The Auth Proxy and Language Connectors are a different transport with their own identity model and are **not** what svcdoctor speaks |
| **Azure Database for PostgreSQL** (flexible server) | standard | **TLS mandatory**; roots are DigiCert Global Root G2 / Microsoft RSA Root CA 2017 — **public, normally already in system stores** | **SCRAM-SHA-256 ✓** · Microsoft Entra ✗ | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. Likely the only one that works with **system roots and no `--tls-ca-file`**. Azure rotates intermediate CAs without notice, so pinning one via `--tls-ca-file` would break — pass a **root**, or nothing |

### Provider-specific authentication is not supported, and is not the same thing

- **AWS IAM database authentication** is not "PostgreSQL password auth with a different
  password". It requires generating a signed, short-lived token through the AWS credential
  chain. `UNSUPPORTED BY CURRENT AUTH`.
- **Cloud SQL Auth Proxy / Language Connectors** are not the PostgreSQL wire protocol as
  svcdoctor speaks it. Diagnosing through one measures the proxy.
- **Microsoft Entra authentication** for Azure PostgreSQL is token-based and is therefore not
  something svcdoctor can perform — `UNSUPPORTED BY CURRENT AUTH`.

## 4b. Redis and Valkey

One command, `svcdoctor diagnose redis`, diagnoses both. Which implementation answered is read
from the endpoint's own `HELLO` reply and shown in the report; the verb is not a claim.

| Platform | Wire | TLS | Auth overlap | Real tested | Level | Known gaps |
|---|---|---|---|---|---|---|
| **Redis** 8.2.1 | RESP2 | verified TLS, custom CA, IP SAN, server-name override | **`AUTH` password ✓, `AUTH user password` ✓** | **YES** — committed `test/integration/redis` fixture, 21 scenarios | **3 — SUPPORTED BASIC** | Direct endpoint only. See the four limits below |
| **Valkey** 8.1.1 | RESP2 | verified TLS, custom CA | **`AUTH` password ✓, `AUTH user password` ✓** | **YES** — committed `test/integration/valkey` fixture, 8 scenarios | **3 — SUPPORTED BASIC** | Same four limits. Same production adapter, with no vendor branch anywhere |
| Any other Redis or Valkey version | RESP2 | — | — | **NO** | **0 — NOT EVALUATED** | Tested at the two exact versions above and nowhere else. svcdoctor does no version arithmetic, so it makes no prediction about any other release |
| **Redis Cluster** (as a cluster) | — | — | — | **NO** | **0 — NOT EVALUATED** | Topology is **not measured**. See below |
| **Redis Sentinel** | — | — | — | detection only | **0 — NOT EVALUATED** | Detection is validated; Sentinel is **not supported** and not diagnosed |
| **AWS ElastiCache / MemoryDB** | RESP2 | — | — | **NO** | **0 — NOT EVALUATED** | `NOT TESTED`. No cloud credential was used at any point |
| **GCP Memorystore** | RESP2 | — | — | **NO** | **0 — NOT EVALUATED** | `NOT TESTED` |
| **Azure Managed Redis / Azure Cache for Redis** | RESP2 | — | — | **NO** | **0 — NOT EVALUATED** | `NOT TESTED`. It runs Redis Enterprise, whose Enterprise clustering policy fronts the data path with a proxy |
| **Redis Enterprise / Redis Cloud** | RESP2 | — | — | **NO** | **0 — NOT EVALUATED** | `NOT TESTED` |

### What Level 3 means here, and the four things it does not cover

**A cluster-mode node is validated as an endpoint; the cluster is not.** `R-16` and `V-07` point
svcdoctor at a node running with `cluster-enabled yes` and the whole BASIC journey completes,
because every command svcdoctor sends is keyless and a keyless command is never redirected. The
report records `mode=cluster` and states that **cluster topology was not measured**: no node is
discovered, no slot coverage is checked, and no advertised address is probed.

**Sentinel is detected, not supported.** `R-17` points svcdoctor at a real Sentinel. It answers
`PING`, which is precisely why the guard exists — without it the run would report a healthy data
endpoint for a process holding no keys. svcdoctor stops before the credential boundary and says
the endpoint identified itself as a Sentinel. It asks the Sentinel nothing, and it makes no claim
about quorum, failover or health.

**No client certificate is presented.** Redis defaults `tls-auth-clients` to `yes`, and `R-20`
runs against a server with that default. svcdoctor has no client certificate, so the connection
cannot be used — and the report says the exchange did not complete rather than that the endpoint
is unhealthy or untrusted. Measured detail: under TLS 1.3 the handshake *passes* and the server
closes on the first read, which is not what ADR 0064 §8 predicted; the record notes the
correction.

**Zero keyspace access.** svcdoctor sends `HELLO`, `AUTH` and `PING` and nothing else. No key is
read, written or named, which every scenario re-checks against the endpoint's own
`INFO commandstats`.

### Evidence

`make integration-redis` and `make integration-valkey` run the whole journey against the pinned
images through `app.DiagnoseRedis` — the same entry point the CLI calls. Every scenario that
asserts something about a server establishes it independently with `redis-cli` or `valkey-cli`
first, so the suite cannot pass by agreeing with itself.

Three upstream behaviours the ADRs rest on were re-measured on the real servers rather than read:

- `AUTH default <anything>` returns `+OK` against a `nopass` user, so an accepted credential is
  never evidence that the credential is correct.
- The one-argument and two-argument `AUTH` forms behave differently on the same server, which is
  why svcdoctor sends the operator's form verbatim and never substitutes `default`.
- A wrong password, an unknown user and a disabled user produce **byte-identical** `WRONGPASS`
  replies, which is why no svcdoctor finding names a cause.

## 5. What none of this required

No provider-specific branch exists anywhere in production code — verified by search; the only
provider names in the tree are comments naming mechanisms that are *not* implemented. No
provider SDK, no new dependency, no new secret source, no connection-string parsing, no
credential refresh, no authentication retry, no alternate TLS authority. The dependency count
is unchanged at one external module.

**svcdoctor diagnoses protocol behaviour, not vendors.** A brand name has no place in the
evidence unless the peer supplied it and the product has a reason to expose it, and neither is
true today.

## 5b. Where svcdoctor runs, which is not the same question

Everything above grades the *peers* svcdoctor has been run against. This section grades the
*execution surface* it runs from, because Phase 7.1 added one: an OCI container image.

**The container changes vantage, not compatibility.** Every peer row above keeps its level
unchanged — a container is not a new implementation to be compatible with, and running the
same client from a different network position does not re-test the server. What was measured
is that containerization does not alter what svcdoctor concludes: schema version, evidence
states, findings and summary are identical between a native and a containerized run against
the same target. The only difference observed was *which* paths were measured, because a name
resolves differently from different positions — and reporting that difference is the product
working, not a discrepancy.

| Execution surface | Tested? | Level | Notes |
|---|---|---|---|
| **Native binary**, macOS/Linux | Yes, throughout | **3 — SUPPORTED** | How every integration suite runs |
| **OCI image**, `linux/arm64` | Yes — full PostgreSQL, Apache Kafka and Redpanda journeys, hardened runtime | **3 — SUPPORTED** | Built and run **natively** on arm64. `readOnlyRootFilesystem`, non-root 65532, all capabilities dropped |
| **OCI image**, `linux/amd64` | Built; run under **emulation** only | **2 — RUN, NOT NATIVELY** | The manifest is correct and the binary executes, but emulation is supporting evidence, not native production validation |
| **Kubernetes Job**, k3s v1.33.3 | Yes — Job completed, cluster DNS, secret mount, hardened `securityContext` | **2 — RUN** | No committed fixture, so not Level 3. NetworkPolicy enforcement was **not** verifiable: that cluster accepts NetworkPolicy objects without enforcing them |
| **Any published registry image** | **No** | **—** | **Nothing has been published.** No image exists at GHCR, Docker Hub or anywhere else |

The runtime contract is [ADR 0062](decisions/0062-oci-runtime-and-kubernetes-execution-model.md).

**What the container is for.** The reason this surface exists is the same reason vantage is a
first-class concept: a Kafka bootstrap endpoint can be reachable while the brokers it
advertises are not, and only a client standing inside the target network can observe that.
Measured from a container against the three-broker fixture — metadata obtained, `0 of 3
advertised broker endpoints reached`, and **zero** SASL bytes sent to any advertised endpoint.

## 6. How a row moves up

**To Level 2**: run svcdoctor against a real instance and record what happened, including what
did not work.

**To Level 3**: Level 2, plus a committed repeatable fixture with its own `make` target, plus
the known differences written down here.

Nothing moves up because its documentation looks right.
