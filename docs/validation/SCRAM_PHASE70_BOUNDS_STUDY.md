# SCRAM defensive bounds — Phase 7.0 measurement study

Every number in ADR 0061 comes from here. This records what was measured, how, and what could not
be established. Nothing was inferred from documentation where an experiment was possible.

| | |
|---|---|
| svcdoctor | `v0.2.0` (`4598144`), release-shaped `CGO_ENABLED=0 -trimpath`, darwin/arm64 |
| Redpanda | `redpandadata/redpanda:v25.1.9` |
| Apache Kafka | 4.0.0, three-broker KRaft, the committed `test/integration/kafka` fixture |
| PostgreSQL | 18, the committed `test/integration/postgres` fixture |
| Host | Apple Silicon, 10 cores, Go 1.26.6, Docker 28.3.2 |
| Date | 2026-08-24 |

**No production Go was changed.** The 35 SCRAM-adjacent files were checksummed at the start and
matched byte-for-byte at the end. Every experiment ran in a throwaway git worktree on branch
`phase70/experiment`, which was removed afterwards.

## 1. Redpanda server-first, measured

A raw protocol probe outside the repository performed `SaslHandshake` + `SaslAuthenticate` with a
24-character client nonce, and reported **lengths only** — no salt bytes, no nonce content, no
credential material.

```text
SaslHandshake v1: errorCode=0 mechanisms=[SCRAM-SHA-256 SCRAM-SHA-512 PLAIN]
SaslAuthenticate v1: errorCode=0

whole server-first    : 342 bytes
server nonce          : 154 chars   (24 client + 130 appended)
salt, base64-ENCODED  : 176 chars
salt, DECODED         : 130 bytes
iterations            : 4096
attribute count       : 3
```

**Twelve consecutive exchanges produced byte-identical lengths.** Not a sample — Redpanda's fixed
shape.

Arithmetic check: `2+154 + 3+176 + 3+4 = 342`. Internally consistent.

### Which check actually fires

| Field | Redpanda | Bound | Verdict |
|---|---|---|---|
| whole server-first | 342 | 4096 | OK |
| server nonce | 154 | 256 | OK |
| **salt, encoded** | **176** | **172** | **EXCEEDS — fires first, before `base64.DecodeString`** |
| salt, decoded | 130 | 128 | exceeds, but never reached |
| attribute count | 3 | 16 | OK |

Phase 6.8 recorded "a 130-byte salt against a 128-byte bound". That is the decoded pair and it is
correct. This study adds the operative detail: **the refusal is the *encoded* check**, and the
decoded bound is never evaluated. The implementation phase moves both, and the ordering between
them is the security property.

### One discrepancy, recorded rather than smoothed

Phase 6.8 measured nonce 157 / server-first 345; Phase 7.0 measured 154 / 342 — a uniform 3-byte
difference. **The salt figures match exactly** (176 / 130) and are independently confirmed by
Redpanda's source. The nonce difference is unexplained. It changes no conclusion, because the salt
is the field that fails.

## 2. Source confirmation

**Redpanda** — `src/v/security/scram_algorithm.h`:

```cpp
using scram_sha256 = scram_algorithm<hmac_sha256, hash_sha256, 130, 4096>;
bytes salt = random_generators::get_crypto_bytes(SaltSize);
```

`SaltSize` is **130 bytes**, hardcoded, not configurable. Confirms the wire measurement
independently. Redpanda's own parser (`scram_algorithm.cc`) validates only `_iterations > 0` and
bounds nothing else.

**Apache Kafka** — `ScramFormatter.secureRandomString()`:

```java
new BigInteger(130, random).toString(Character.MAX_RADIX)
```

A **130-bit** integer in base-36. Measured over 20 000 samples:

| decoded salt | share | encoded |
|---|---|---|
| 22 B | 0.005% | 32 |
| 23 B | 0.040% | 32 |
| 24 B | 1.55% | 32 |
| **25 B** | **57.7%** | 36 |
| **26 B** | **40.7%** | 36 |

**Kafka uses 130 bits; Redpanda uses 130 bytes.** The coincidence is worth recording because it
explains an otherwise arbitrary-looking constant.

**PostgreSQL** — `SCRAM_DEFAULT_SALT_LEN` 16, `SCRAM_RAW_NONCE_LEN` 18, default iterations 4096.
libpq's `read_server_first_message` bounds nothing but `iterations >= 1`.

## 3. Does salt size cost anything?

The question ADR 0056 §7 never asked. PBKDF2-HMAC-SHA256 mixes the salt into the first HMAC of the
first iteration only; every later iteration HMACs a fixed 32-byte block.

Iterations fixed at 4096, medians of five runs at 200 iterations each:

| salt | median | vs 16 B |
|---|---|---|
| 16 B | 363.7 µs | 1.000× |
| 25 B | 365.2 µs | 1.004× |
| 128 B | 365.4 µs | 1.005× |
| **130 B** | 367.2 µs | 1.010× |
| 256 B | 369.1 µs | 1.015× |
| 512 B | 366.6 µs | 1.008× |
| 1 024 B | 369.3 µs | 1.015× |
| 4 096 B | 370.6 µs | 1.019× |
| **65 536 B** | 392.3 µs | **1.079×** |

**A 64 KiB salt costs 7.9% more than a 16-byte one.** Salt size is effectively free.

A first run at `benchtime=20x` showed cost apparently *decreasing* with salt size — obviously an
artefact, and re-run with repetitions rather than reported.

## 4. Iteration cost — the bound that does the work

Salt fixed at 16 B, medians of five runs:

| iterations | median | ns/iteration |
|---|---|---|
| 4 096 | 0.68 ms | 166 |
| 10 000 | 0.87 ms | 87 |
| 100 000 | 9.05 ms | 91 |
| 250 000 | 24.4 ms | 98 |
| 500 000 | 47.6 ms | 95 |
| **1 048 576** | **101.5 ms** | 97 |

Linear at ~96 ns/iteration. `MaxIterations = 1<<20` costs **101.5 ms**. ADR 0056 estimated "about
a quarter of a second" on slower hardware — same order, bound sound on both.

## 5. Parser cost and allocation

Against the real `parseServerFirst`, 24-char client nonce:

| salt | ns/op | allocs/op | B/op |
|---|---|---|---|
| 16 B | 263 | 1 | 24 |
| 128 B | 431 | 1 | 144 |
| **130 B** | **242** | **0** | **0** |
| 512 B | 477 | **0** | **0** |
| 2 048 B | 1 402 | **0** | **0** |
| full 4096-byte message | 1 747 | **0** | **0** |

**Every refusal path allocates nothing** — the encoded-salt check precedes the decode, so an
oversized salt never reaches `base64.DecodeString`. The accepting path allocates exactly one slice,
the decoded salt. Worst-case parse of a full message is **1.7 µs** against **101 ms** of
derivation: parsing is four orders of magnitude below the cost that matters.

The attribute walk examines each byte exactly once — **O(n)** — with no repeated scanning and no
per-attribute allocation.

## 6. Interoperability comparison

| Implementation | Salt max | Nonce max | Iteration max | Attr max | Message max |
|---|---|---|---|---|---|
| RFC 5802 / 7677 | none | none | none | none | none |
| PostgreSQL libpq | none | none | none (≥1) | none | frame only |
| Apache Kafka (Java) | none | none | none | none | frame only |
| Redpanda (C++) | none | none | none (>0) | none | frame only |
| librdkafka | none | none | **1 000 000** | none | frame only |
| xdg-go/scram | none | none | none | none | none |
| **svcdoctor v0.2.0** | **128** | **256** | **1 048 576** | **16** | **4096** |

**svcdoctor is the only implementation surveyed that bounds the salt at all.** The one bound the
most widely deployed Kafka C client enforces is the iteration count, at essentially svcdoctor's
value.

## 7. Candidate policies against a real Redpanda instance

Each built in the worktree and run against the live v25.1.9 TLS listener with a real credential
(`rpk` authenticates with the same principal and mechanism, so the credential is not the variable).

| Policy | encoded / salt / nonce / message | Result |
|---|---|---|
| **Control — v0.2.0** | 172 / 128 / 256 / 4096 | ✗ `PROTOCOL_MALFORMED_RESPONSE` |
| **A — minimal patch** | 344 / 256 / 256 / 4096 | ✓ Authentication + Metadata PASS |
| **B — balanced** | 1368 / 1024 / 1024 / 8192 | ✓ Authentication + Metadata PASS |
| **C — outer-dominant** | 8192 / 6144 / 8192 / 8192 | ✓ Authentication + Metadata PASS |

Causality re-proven independently of Phase 6.8. All three candidates work; the choice between them
is a security judgement, not an interoperability one. ADR 0061 §21 records why A and C were
rejected.

## 8. Regression evidence for the recommended policy

Recommended policy: `8192 / 8192 / 1368 / 1024 / 1024 / 32`, `MaxIterations` unchanged.

| Suite | Result |
|---|---|
| Full unit suite | pass |
| `test/security` — authority, cardinality, redaction, dependency count | pass |
| PostgreSQL 18 integration | **ok, 24.9 s** |
| Apache Kafka 4.0.0 integration | **ok, 333.1 s** |
| Apache Kafka, **HEAD bounds control**, same worktree | **ok, 327.6 s** |

Invariants under the widened bounds: `SchemaVersion` 1, FindingCodes 40, FailureClasses 41,
`Reveal` production call sites 2, dependencies 1, Kafka credential-bearing auth attempts 1.

### One Kafka run failed and is recorded here rather than dropped

An earlier Kafka run under the recommended policy failed at 457.6 s, while a Redpanda container was
running concurrently. It was not reproduced: two subsequent clean runs — recommended policy 333.1 s
and HEAD control 327.6 s, times within 1.7% — both passed.

**The failing test was not identified**, because that run's output was truncated to its last four
lines before the failure detail. The most likely cause is resource contention with the concurrent
Redpanda instance (1 GB, one shard) against a three-broker cluster, consistent with the 124-second
slowdown, and the fixture's own Makefile comments record prior timing-sensitivity in this suite.
That is an explanation, not a proof, and it is the one loose end in this study.

## 9. Fuzz

Five targets, bounded runs, **no crashers**: `FuzzParseServerFirst` (3.97 M execs),
`FuzzAttributes` (5.92 M), `FuzzParseIterations` (4.26 M), `FuzzEncodeSASLname` (3.69 M),
`FuzzVerifyServerFinal` (1.44 M).

`FuzzVerifyServerFinal` reported "context deadline exceeded" at a 20-second budget. Re-run at 40
seconds it passes and writes no crasher — a shutdown artefact of the fuzzing harness, not a
finding.

**Seed gaps for the implementation phase:** no seed sits at limit−1 / limit / limit+1 for any field
bound, and duplicate `r=`/`s=`/`i=` attributes are unseeded. A 130-byte-salt Redpanda-shaped
server-first should become a permanent regression seed.

## 10. What the test suite does not pin

**The unit suite passed unchanged under all four experimental policies.** Every bound test is
written relative to its constant — `maxSaltLen+8`, `maxSaltEncodedLen+1`, `maxNonceLen`,
`maxServerFirstLen+1` — so it verifies the mechanism and the validation order but moves with any
edit to the value.

Only `MaxIterations` is value-pinned, at `scram_test.go:309`.

So today **a silent change to any field bound is invisible to the tests.** ADR 0061 §25 makes
value-pinning tests an implementation requirement.

## 11. Incidental finding

`test/integration/kafka/env/gen-certs.sh` does `cd "$(dirname "$0")/certs"` with no `mkdir -p`, and
`certs/` is untracked, so **`make integration-kafka` fails on any fresh clone or worktree**.
PostgreSQL's equivalent does `mkdir -p certs` first and works. Found while running the Kafka
regression in a worktree; not fixed, because Phase 7.0 forbade unrelated repairs. Recorded in
`docs/BACKLOG.md`.

## 12. Environment cleanup

The Redpanda container, its throwaway PKI, the experiment worktree and branch, the temporary
benchmark file and the raw probe were all removed. No fixture, secret or container survives this
study.
