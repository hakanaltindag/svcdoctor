# Redpanda compatibility study — Phase 6.8C

**svcdoctor ran against a real Redpanda instance.** This records what was measured, not what
the documentation implies. Every row below was produced by the release-shaped binary against a
live broker; nothing here is inferred from protocol similarity.

| | |
|---|---|
| Redpanda | `redpandadata/redpanda:v25.1.9` (rpk `v25.1.9`, git `b3dac5a945`) |
| svcdoctor | `v0.2.0-rc.1`, `CGO_ENABLED=0 -trimpath`, darwin/arm64 |
| Runtime | Docker 28.3.2, darwin/arm64 host |
| Contrast | Apache Kafka 4.0.0, three brokers, the existing `test/integration/kafka` fixture |
| Date | 2026-08-23 |

## 1. Result, up front

**Redpanda self-hosted — LEVEL 2, TESTED BASIC, with one blocking mechanism limitation.**

- **`PLAIN` over TLS: the complete Kafka BASIC journey succeeds.** DNS, TCP, TLS, ApiVersions,
  SaslHandshake, SaslAuthenticate, Metadata, advertised-endpoint sweep, terminal, canonical
  JSON, shareable redaction — for hostname, IPv4-literal and IPv6-literal targets.
- **`SCRAM-SHA-256`: fails, for a measured reason that is svcdoctor's, not Redpanda's.**
  Redpanda issues a **130-byte SCRAM salt**; svcdoctor's shared SCRAM core bounds a salt at
  **128 bytes**. See §4.

It is **not Level 3 (SUPPORTED BASIC)**, for two reasons: half of svcdoctor's supported
mechanisms do not work, and no repeatable committed fixture exists yet. §7 states what Level 3
would require.

## 2. Primary-source position, before testing

From Redpanda's own documentation, recorded so that the measurements below can be compared
against what was claimed:

- **Kafka protocol**: "Kafka clients, version 0.11 or later, are compatible with Redpanda."
- **SASL mechanisms**: "Redpanda supports these SASL mechanisms: SASL/SCRAM, SASL/PLAIN,
  SASL/OAUTHBEARER (OpenID Connect), SASL/GSSAPI (Kerberos)." SCRAM is enabled by default;
  PLAIN and GSSAPI need explicit enablement; OIDC and Kerberos require an enterprise licence.
- **A documented limitation**: only one SASL/SCRAM mechanism per user — SCRAM-SHA-256 **or**
  SCRAM-SHA-512, not both.

Sources: [Configure Authentication](https://docs.redpanda.com/current/manage/security/authentication/),
[Kafka Compatibility](https://docs.redpanda.com/current/develop/kafka-clients/).

**None of that is evidence that svcdoctor works.** It says the protocol surface exists. §3 and
§4 are what happened when svcdoctor spoke to it.

## 3. What worked — `PLAIN` over TLS

The full journey, verbatim:

```text
svcdoctor · kafka · localhost:19292

  ✓ PASS  DNS  2.2ms

  Path 127.0.0.1:19292 · continued
    ✓ PASS  TCP                         195µs
    ✓ PASS  TLS                         7.4ms
    ✓ PASS  Kafka API versions          1.4ms
    ✓ PASS  SASL mechanism negotiation  444µs
    ✓ PASS  Authentication              2.2ms
    ✓ PASS  Kafka metadata              591µs

  Path [::1]:19292
    ✓ PASS  TCP                         198µs
    ✓ PASS  TLS                         2.6ms
    ✓ PASS  Kafka API versions          362µs
    ✓ PASS  SASL mechanism negotiation  313µs
    ·       Authentication                     not attempted on this path
    ·       Kafka metadata                     not attempted on this path

  Advertised broker 0 · localhost:19292
    ✓ PASS  Broker advertisement
    ✓ PASS  DNS                   257µs

    Path 127.0.0.1:19292
      ✓ PASS  TCP  102µs
      ✓ PASS  TLS  2.1ms

    Path [::1]:19292
      ✓ PASS  TCP  103µs
      ✓ PASS  TLS  1.9ms

Findings
  none

Result
  status     OK                                          no target-side error was proven
  outcome    Kafka metadata obtained
  topology   1 of 1 advertised broker endpoints reached
  execution  complete
  duration   23.0ms
```

**The graph shape is identical to Apache Kafka's**, level for level: one bootstrap DNS node, one
path per resolved address, discovery on every path, authentication on exactly one, an
advertisement level beneath Metadata, and a credential-free transport sweep beneath each
advertisement. No consumer of the graph needed to know which implementation produced it.

### Scenario coverage

| Scenario | Result |
|---|---|
| hostname target | OK, metadata obtained, 1 of 1 reached |
| IPv4 literal target | OK, metadata obtained, no `dns.lookup` node |
| IPv6 literal target | OK, metadata obtained, no `dns.lookup` node |
| custom CA (`--tls-ca-file`) | verified, `tls.verified: true` |
| system roots against the fixture CA | FAIL at L3, no fallback |
| `--tls-server-name` override on an IPv4 target | verified against the name |
| `--tls-insecure` | handshake completes, credential **withheld**, header and row both disclose |
| wrong credential | `PROBLEMS FOUND`, first break L5, exit 1 |
| no credential configured | `OK`, no metadata, exit 0 |
| plaintext listener with a credential | `KAFKA_CREDENTIAL_WITHHELD`, zero bytes sent |
| mechanism not offered (`GSSAPI`) | `KAFKA_AUTH_MECHANISM_NOT_OFFERED`, exit 1 |
| terminal / JSON / shareable | all three produced; shareable leaked no canary |

### Invariants, measured on the Redpanda run itself

| Invariant | Measured |
|---|---|
| credential-bearing authentication attempts | **1** |
| protocol or auth nodes beneath an advertisement | **none** |
| `schemaVersion` | **1** |
| shareable report canary leaks | **none** (`localhost`, `127.0.0.1`, `::1` and the password all absent) |
| provider-specific production branch added | **none** |
| dependencies added | **none** — still one external module |

## 4. What did not work — `SCRAM-SHA-256`, and exactly why

```text
  ✗ ERROR  KAFKA_AUTHENTICATION_NOT_COMPLETED  127.0.0.1:19292
    The Kafka authentication exchange did not complete at this endpoint
    Authentication was attempted and the exchange did not complete.
    svcdoctor could not attribute why. This does not state that a credential was evaluated or refused.
    The mechanism this step concerned was SCRAM-SHA-256.
```

`kafka.sasl_authenticate` is `FAIL` with `PROTOCOL_MALFORMED_RESPONSE`. **The Redpanda broker log
records nothing**, and `rpk` authenticates with the same credential and mechanism successfully —
so the failure is svcdoctor's side of the exchange.

### The measurement

A raw-protocol probe captured Redpanda's server-first message verbatim:

```text
SaslHandshake v1: errorCode=0 mechanisms=[SCRAM-SHA-256 SCRAM-SHA-512 PLAIN]
SaslAuthenticate v1: errorCode=0
  server-first (345 bytes): "r=fyko+d2lbbFgONRv9Qkxbry…c,s=wFZc91Kv…Og==,i=4096"
```

Against `internal/sasl/scram`'s bounds:

| Field | Redpanda | svcdoctor bound | |
|---|---|---|---|
| whole server-first | 345 | 4096 | OK |
| server nonce | 157 | 256 | OK |
| salt, base64 | **176** | **172** | **exceeds** |
| salt, decoded | **130** | **128** | **exceeds** |
| iterations | 4096 | 1048576 | OK |

Five consecutive exchanges produced a 130-byte salt every time, so it is Redpanda's fixed salt
size and not a sampling artefact.

The path is: `parse.go` returns `ErrMessageTooLarge` → `translateSCRAM` maps it to
`wire.ErrMalformedResponse` → the adapter classifies `PROTOCOL_MALFORMED_RESPONSE`.

### Causality was proven, not inferred

`maxSaltEncodedLen` and `maxSaltLen` were raised locally, the binary rebuilt, the run repeated,
and **the entire journey passed** — authentication, Metadata, advertised topology. The bound is
the sole cause. The change was then reverted and the SCRAM freeze re-verified byte-for-byte
against the checksum taken at the start of Phase 6.8.

### Why it was not fixed here

Phase 6.8's stop conditions list **"SCRAM must change"** as a STOP, and §2 froze the shared
SCRAM core for the duration. Both apply, and both are right:

- `maxSaltLen` is a **security bound**, not a constant. ADR 0056 §7 records why the core refuses
  to inherit its caller's framing limit, and the salt bound specifically exists because an
  earlier implementation decoded the salt before applying the iteration ceiling — a peer could
  force megabytes of allocation before any refusal.
- Its justification is now known to be **factually wrong**: the comment reads *"PostgreSQL uses
  sixteen bytes and RFC 7677 sets no maximum; 128 is eight times the largest value in common
  use."* Redpanda is a mainstream implementation in common use and it uses 130. RFC 5802 and
  RFC 7677 set no maximum, so no value is derivable from the specification.
- Changing a security bound inside a compatibility phase, to make one vendor work, is precisely
  the failure mode this phase was structured to prevent.

**Disposition: raise it in a phase that owns the shared SCRAM core, with its own security
review.** The review has to answer what the bound is protecting against, what headroom is
enough for implementations nobody has measured yet, and whether the right shape is a larger
constant or a bound derived from the framing limit. That is an ADR 0056 amendment, not a
one-line edit.

## 5. Semantic differences from Apache Kafka

| | Apache Kafka 4.0.0 | Redpanda v25.1.9 |
|---|---|---|
| SCRAM salt size | within svcdoctor's bound | **130 bytes** — exceeds it |
| `SaslHandshake` offered mechanisms | as configured | as configured, order differs |
| `sasl_mechanisms` configuration value | `SCRAM-SHA-256`, `PLAIN` | **`SCRAM`**, `PLAIN` — one value covers both digests |
| ApiVersions key coverage | full | 42 keys; no key svcdoctor uses is absent |
| Graph shape svcdoctor produces | — | **identical** |
| Finding vocabulary exercised | — | **identical**; no code was reached that Apache Kafka does not also reach |

The `sasl_mechanisms` difference is a **fixture** difference, not a client one: svcdoctor never
sends that value. It is recorded because it cost time — Redpanda rejects the literal
`SCRAM-SHA-256` as a configuration value with *"'SCRAM-SHA-256' is not a supported SASL
mechanism"*, which reads exactly like a compatibility failure and is not one. A first attempt at
this study concluded Redpanda did not offer SCRAM at all; svcdoctor's own
`kafka.sasl.offered_mechanisms` attribute is what disproved it.

## 6. What was deliberately not done

- **No `if redpanda` branch, anywhere.** Verified by grep over production sources: the only
  provider names in the tree are comments naming mechanisms that are *not* implemented.
- **No provider SDK, no new dependency.** Still one external module.
- **No change to svcdoctor to accommodate Redpanda.** The one change that would help is a STOP
  (§4).
- **No claim about Redpanda Cloud.** Nothing here was run against it, and self-hosted evidence
  does not transfer.

## 7. What Level 3 would require

1. The SCRAM salt bound raised under its own security review, and SCRAM-SHA-256 re-measured
   against a real Redpanda instance.
2. A committed, repeatable fixture — `test/integration/redpanda/` alongside the Kafka one, with
   its own `make` target — so the evidence is regenerated on demand rather than recorded once.
3. This document's known differences carried into `docs/COMPATIBILITY.md`.

Until then the honest claim is **"tested against Redpanda v25.1.9; `PLAIN` over TLS works,
`SCRAM-SHA-256` does not"**, and that is what the README and the release notes say.

## 8. Reproducing this

The instance was configured with a TLS listener on `19292` and a plaintext listener on `19291`,
`enable_sasl: true`, `sasl_mechanisms: [SCRAM, PLAIN]`, superuser `svcdoctor`, and the
throwaway PKI the Phase 6.8 TLS matrix used. No fixture was committed; §7 item 2 is what would
change that.
