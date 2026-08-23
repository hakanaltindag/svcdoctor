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
| **Redpanda self-hosted** v25.1.9 | Kafka (clients 0.11+) | verified TLS, custom CA, IP SAN | `PLAIN` ✓ · **`SCRAM-SHA-256` ✗** | **YES** — real instance | **2 — TESTED BASIC** | **SCRAM-SHA-256 fails**: Redpanda's 130-byte salt exceeds svcdoctor's 128-byte bound. Root cause measured, fix proven, deferred — see below |
| **Redpanda Cloud** | Kafka | TLS 1.2 mandatory | `SCRAM-SHA-256` ✓ per docs | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. Self-hosted evidence does **not** transfer; the SCRAM salt finding above may or may not apply |
| **Confluent Cloud** | Kafka | TLS 1.2 mandatory, public CA | **`PLAIN` ✓** — API key = username, API secret = password | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`. The credential shape fits `--user` + `--password-file` with no parsing; verified against svcdoctor's input model only, not against the service |
| **AWS MSK — SASL/SCRAM** | Kafka | `SASL_SSL`, provider CA bundle | **✗ — `SCRAM-SHA-512` only** | **NO** | **0 — NOT EVALUATED** | `UNSUPPORTED BY CURRENT AUTH`. MSK documents `sasl.mechanism=SCRAM-SHA-512`; svcdoctor implements SHA-256 and does not fall back |
| **AWS MSK — IAM** | Kafka | `SASL_SSL` | **✗ — `AWS_MSK_IAM` not implemented** | **NO** | **0 — NOT EVALUATED** | `UNSUPPORTED BY CURRENT AUTH`. Would need AWS SigV4 request signing and a cloud credential chain |
| **Azure Event Hubs (Kafka API)** | Kafka 1.0+ | `SASL_SSL` mandatory | **`PLAIN` ✓ (SAS)** · `OAUTHBEARER` ✗ | **NO** | **1 — PROTOCOL-PLAUSIBLE** | `DOCUMENTATION ONLY`, SAS path only. Single stable virtual IP rather than per-broker endpoints, so the advertised sweep will look unlike a real cluster's |

### Redpanda self-hosted, in detail

The complete BASIC journey succeeds over **`PLAIN` on a TLS listener** — DNS, TCP, TLS,
ApiVersions, SaslHandshake, SaslAuthenticate, Metadata, advertised-endpoint sweep, terminal,
canonical JSON, shareable redaction — for hostname, IPv4-literal and IPv6-literal targets. The
evidence graph is structurally identical to Apache Kafka's.

**`SCRAM-SHA-256` does not work**, and the reason is svcdoctor's, not Redpanda's: Redpanda
issues a **130-byte SCRAM salt** and `internal/sasl/scram` bounds a salt at **128 bytes**, so
the server-first message is refused as malformed. Raising the bound was proven to fix it
completely and was **deliberately not done** — the bound is a security parameter recorded in
ADR 0056 §7, and changing one to accommodate a vendor inside a compatibility phase is the
failure mode that phase exists to prevent. Full measurements:
[`docs/validation/KAFKA_PHASE68_REDPANDA_STUDY.md`](validation/KAFKA_PHASE68_REDPANDA_STUDY.md).

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

## 5. What none of this required

No provider-specific branch exists anywhere in production code — verified by search; the only
provider names in the tree are comments naming mechanisms that are *not* implemented. No
provider SDK, no new dependency, no new secret source, no connection-string parsing, no
credential refresh, no authentication retry, no alternate TLS authority. The dependency count
is unchanged at one external module.

**svcdoctor diagnoses protocol behaviour, not vendors.** A brand name has no place in the
evidence unless the peer supplied it and the product has a reason to expose it, and neither is
true today.

## 6. How a row moves up

**To Level 2**: run svcdoctor against a real instance and record what happened, including what
did not work.

**To Level 3**: Level 2, plus a committed repeatable fixture with its own `make` target, plus
the known differences written down here.

Nothing moves up because its documentation looks right.
