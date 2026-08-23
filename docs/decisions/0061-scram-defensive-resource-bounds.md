# ADR 0061: SCRAM defensive resource bounds

## Status

**Accepted, and implemented in Phase 7.0b.** This record is the outcome of **Phase 7.0**, the
security review ADR 0056 §7 and `docs/validation/KAFKA_PHASE68_REDPANDA_STUDY.md` §4 both
deferred to. The human reviewers accepted **Policy B** — the balanced bounds in §15–§18 — and
Phase 7.0b implemented exactly those numbers. Nothing was substituted.

**It supersedes ADR 0056 §7 in part**, and only in part: the defensive numeric resource bounds
and the semantics of a bound refusal. Model D's plaintext boundary, the derivation-callback
contract, the import allowlist and the state-minimization rules are untouched.

Phase 7.0 itself changed no production Go — the `internal/sasl/scram` checksums taken at its
start matched byte-for-byte at its end, and every experiment ran in a throwaway worktree. §28
below records what Phase 7.0b then changed.

## 1. Context

`internal/sasl/scram` is the shared SCRAM-SHA-256 core. It is the only code in the repository
that parses a peer-chosen message and then hands the result to a key-derivation function, and it
serves both services. It therefore owns the question of how much work a hostile broker can make
svcdoctor do.

ADR 0056 §7 set eight bounds and recorded, for each, an interoperability risk. For seven of them
the recorded risk was "none". For the salt it was **"none: 8× the largest common value"**.

That premise is false, and a real implementation falsified it.

## 2. Triggering evidence

Phase 6.8 ran svcdoctor against a real Redpanda v25.1.9 instance. `PLAIN` over TLS completed the
whole BASIC journey. `SCRAM-SHA-256` did not. Phase 7.0 reproduced this independently, against a
freshly built instance, with the v0.2.0 release binary:

```text
✗ FAIL  Authentication   1.1ms   PROTOCOL_MALFORMED_RESPONSE
✗ ERROR KAFKA_AUTHENTICATION_NOT_COMPLETED
```

`rpk` authenticates against the same instance with the same principal, mechanism and password, so
the exchange is not Redpanda's to fix.

A raw protocol probe measured the server-first message. **Twelve consecutive exchanges produced
identical lengths**, so this is Redpanda's fixed shape and not a sample:

| Field | Redpanda v25.1.9 | svcdoctor v0.2.0 bound | |
|---|---|---|---|
| whole server-first | 342 B | 4096 | OK |
| server nonce | 154 chars (24 client + **130** appended) | 256 | OK |
| salt, base64-**encoded** | **176 chars** | **172** | **exceeds — this check fires first** |
| salt, **decoded** | **130 B** | **128** | exceeds |
| iterations | 4096 | 1048576 | OK |
| attribute count | 3 | 16 | OK |

**Terminology, corrected.** Both figures are real and they fail different checks. The refusal that
actually fires is `maxSaltEncodedLen` — 176 > 172 — *before* `base64.DecodeString` runs. The
decoded bound is never reached. Phase 6.8's "130-byte salt" is the decoded length and is correct;
this record adds which check the message actually dies on, because the implementation phase has to
move both constants and the ordering between them is the security property.

One reconciliation is recorded rather than smoothed over: Phase 6.8 measured the nonce at 157 and
the server-first at 345; Phase 7.0 measured 154 and 342, a uniform 3-byte difference. The salt
figures — the load-bearing ones — match exactly, and are independently confirmed by Redpanda's
source. The nonce difference is unexplained and does not affect any conclusion here.

## 3. Existing bounds, and where each check executes

Ordering matters as much as value, so this is the validation order rather than the constant block.

| # | Bound | Value | Executes | Bounds |
|---|---|---|---|---|
| 1 | `maxServerFirstLen` | 4096 | before parsing | total input, walker work |
| 2 | `maxAttributes` | 16 | during the walk | walker iterations |
| 3 | `maxNonceLen` | 256 | after the walk | AuthMessage HMAC input |
| 4 | `maxSaltEncodedLen` | 172 | **before base64 decode** | **the decode allocation** |
| 5 | `maxSaltLen` | 128 | after decode | decoded slice |
| 6 | `MaxIterations` | `1<<20` | **before the derive callback** | **PBKDF2 CPU** |
| 7 | `maxServerFinalLen` | 4096 | before parsing | total input |
| 8 | `maxUsernameLen` | 256 | in `Begin` | escaped username — **not peer-controlled** |

Outside the core: `postgres/wire.MaxMessageSize` = 1 MiB, `kafka/wire.maxResponseSize` = 8 MiB.
They differ by 8×, which is ADR 0056's stated reason the core refuses to inherit a caller's bound.
That reason is sound and this record does not disturb it.

## 4. Why the salt rationale is reopened

Git archaeology, not recollection. **Every field bound in §3 was invented in one commit**,
`703f4a4` "feat(scram): extract the shared SCRAM-SHA-256 core". Before it, the PostgreSQL
implementation had exactly one bound — `MaxSCRAMIterations` — and no salt, nonce, attribute or
message ceiling at all.

`703f4a4` landed **after** `v0.1.0`. So **the released v0.1.0 shipped PostgreSQL SCRAM with no
salt bound whatsoever**, validated against real PostgreSQL 18 and pgBouncer, protected only by the
1 MiB frame. The salt bound is not a long-standing invariant being questioned; it is a
fifteen-hour-old defensive addition whose only stated justification is a frequency claim.

The comment reads: *"PostgreSQL uses sixteen bytes and RFC 7677 sets no maximum; 128 is eight times
the largest value in common use."* Both halves are individually true. The inference is not:
"largest value **in common use**" was measured against PostgreSQL and Apache Kafka only, and a
third mainstream implementation uses 130.

**The methodology is the defect, not the number.** A bound selected from observed frequency will
fail against the first unobserved implementation, and will fail *narrowly* — here by two bytes —
which is the worst possible failure shape because it looks like a protocol error.

## 5. RFC constraints

RFC 5802 §7 (formal syntax) and RFC 7677.

```abnf
salt            = "s=" base64
s-nonce         = printable
iteration-count = "i=" posit-number     ; posit-number = %x31-39 *DIGIT
extensions      = attr-val *("," attr-val)
```

- **No maximum is defined for salt, nonce, iteration count, attribute count or message size** —
  in either RFC. `base64` and `printable` are unbounded productions; `posit-number` admits an
  arbitrarily long digit string.
- The salt is **opaque octets**. A large salt is semantically valid.
- The iteration count is **peer-chosen**, and RFC 7677 §4 gives only a lower guidance —
  *"should be such that a modern machine will take 0.1 seconds"* — and no ceiling.
- `extensions` is an unbounded list, so a legal server-first may carry many attributes.

Therefore **every bound in §3 is svcdoctor defensive policy**, not an RFC requirement, and none can
be derived from the specification. This is the honest separation ADR 0056 §7 asserted and this
record confirms.

## 6. Apache Kafka evidence

`ScramFormatter.secureRandomString()`:

```java
new BigInteger(130, random).toString(Character.MAX_RADIX)
```

A **130-bit** random integer rendered in base-36, then UTF-8 encoded. Measured over 20,000
samples: **22–26 bytes, mode 25 (57.7%) and 26 (40.7%)** — encoding to 32–36 base64 characters.
Comfortably inside every current bound, with ~5× headroom. Not configurable.

Kafka's own parser imposes **no** maximum on salt, nonce or message size.

A coincidence worth recording, because it explains an otherwise inexplicable constant: **Kafka
uses 130 bits; Redpanda uses 130 bytes.**

## 7. Redpanda evidence

`src/v/security/scram_algorithm.h`:

```cpp
using scram_sha256 = scram_algorithm<hmac_sha256, hash_sha256, 130, 4096>;
using scram_sha512 = scram_algorithm<hmac_sha512, hash_sha512, 130, 4096>;
bytes salt = random_generators::get_crypto_bytes(SaltSize);
```

**`SaltSize` is 130 bytes, hardcoded, for both digests.** Not configurable, not version-dependent
within v25.1.9, and the source independently confirms the wire measurement in §2.

Redpanda's own parser (`scram_algorithm.cc`) validates only `_iterations > 0` and imposes **no**
maximum on salt, nonce, iterations or message size.

## 8. PostgreSQL evidence

`SCRAM_DEFAULT_SALT_LEN` = **16**, `SCRAM_RAW_NONCE_LEN` = **18**,
`SCRAM_SHA_256_DEFAULT_ITERATIONS` = **4096**.

libpq's `read_server_first_message` enforces `iterations >= 1` and a nonce prefix match. It applies
**no maximum** to salt, nonce or iteration count, and allocates the decoded salt straight from the
encoded length.

## 9. Other implementations

| Implementation | Salt max | Nonce max | Iteration max | Attribute max | Message max |
|---|---|---|---|---|---|
| RFC 5802 / 7677 | none | none | none | none | none |
| PostgreSQL libpq | none | none | none (≥1) | none | frame only |
| Apache Kafka (Java) | none | none | none | none | frame only |
| Redpanda (C++) | none | none | none (>0) | none | frame only |
| librdkafka | none | none | **1 000 000** | none | frame only |
| xdg-go/scram | none | none | none | none | none |
| **svcdoctor v0.2.0** | **128** | **256** | **1 048 576** | **16** | **4096** |

Not a majority vote — a statement about what mature implementations judged worth defending.
**svcdoctor is the only one that bounds the salt at all.** And the one bound the most widely
deployed Kafka C client chose to enforce is the iteration count, at essentially svcdoctor's value.
That convergence is evidence that the iteration ceiling is the bound that matters.

## 10. Threat model

The peer controls the server nonce suffix, the salt, the iteration count, the attribute set and
order, both message sizes, malformed and duplicate attributes, and the error token.

**Memory.** Measured. On every refusal path the parser allocates **zero** bytes — the encoded-salt
check precedes the decode, so an oversized salt is refused before any allocation. On the accepting
path there is exactly **one** allocation, the decoded salt.

**CPU.** PBKDF2 dominates by four orders of magnitude. Parsing a full 4096-byte message costs
**1.7 µs**; one derivation at the current ceiling costs **101 ms**.

**Allocation amplification.** base64 decode expands 4 encoded characters to 3 bytes — a *reduction*.
The only amplification is the decode allocation itself, and it is already bounded twice.

**Parser complexity.** `attributes` scans for the next comma, visits, then advances past it, so
**each byte is examined exactly once: O(n)**, with no repeated scanning and no per-attribute
allocation. `maxAttributes` bounds the visitor count but not the byte count, which the message
bound already fixes.

**State retention.** After `Begin`: client-first-bare, client nonce. After `Continue`: a 32-byte
expected signature and nothing else — the salt, AuthMessage, SaltedPassword and both nonces are
dropped. After `Verify`: nothing. No peer-controlled value survives `Continue`.

**Error and log leakage.** Structural: `fmt` is not in the package's import allowlist, so every
error is a fixed-text sentinel and no peer byte can reach an error, a finding, the terminal or the
JSON.

## 11. Resource budget

Per authentication attempt, with the bounds recommended in §15–§18:

- **Input processed** ≤ 8 KiB (server-first) + 8 KiB (server-final) = **16 KiB**
- **Peak core allocation** ≤ 16 KiB of message plus **≤ 1 KiB** decoded salt plus 32 bytes
- **CPU** ≤ 1 048 576 PBKDF2 iterations ≈ **101 ms measured**, plus ~7 µs of parsing

**Kafka performs at most one credential-bearing authentication attempt per run** (ADR 0028,
enforced by `TestAtMostOneAuthenticationCallSiteExists`, which also rejects the call appearing
inside a loop). PostgreSQL likewise authenticates on exactly one selected path. So those figures
are not per-message — **they are the whole run's exposure**.

The claim this record supports: *even a wholly hostile broker cannot make svcdoctor process more
than 16 KiB of SCRAM message data or perform more than 2²⁰ PBKDF2 iterations per run.*

## 12. Salt-specific analysis

The question ADR 0056 never asked: **does salt size cost anything?**

PBKDF2-HMAC-SHA256 mixes the salt into the first HMAC of the first iteration only; the remaining
iterations HMAC a fixed 32-byte block. Salt size is therefore O(1) in the iteration count.
Measured, iterations fixed at 4096, medians of five runs:

| salt | median | vs 16 B |
|---|---|---|
| 16 B | 363.7 µs | 1.000× |
| 130 B | 367.2 µs | 1.010× |
| 1 024 B | 369.3 µs | 1.015× |
| 4 096 B | 370.6 µs | 1.019× |
| **65 536 B** | 392.3 µs | **1.079×** |

**A 64 KiB salt costs 7.9% more CPU than a 16-byte one.** Salt size is, for practical purposes,
free. It does not amplify CPU, it does not amplify memory beyond its own length, and its
allocation is already bounded by the message ceiling.

The bound that was breaking interoperability was protecting nothing measurable.

## 13. Iteration analysis

The bound that does the work. Measured, salt fixed at 16 B:

| iterations | median | ns/iteration |
|---|---|---|
| 4 096 | 0.68 ms | 166 |
| 100 000 | 9.05 ms | 91 |
| 500 000 | 47.6 ms | 95 |
| **1 048 576** | **101.5 ms** | 97 |

Linear, as expected. `1<<20` yields ~101 ms on this machine — ADR 0056 estimated "about a quarter
of a second" on slower hardware; same order, and the bound is sound on both.

Defaults: PostgreSQL 4096, Apache Kafka 4096, Redpanda 4096. librdkafka caps at 1 000 000.

**Recommendation: unchanged.** It is the only bound protecting a resource that matters, it is
already value-pinned by test, and it agrees with the one comparable implementation that bounds
anything.

## 14. Nonce, message and attribute analysis

**Nonce.** The server nonce enters the AuthMessage, which is HMAC'd over its full length — but
HMAC is linear and the message bound already caps it. The current 256 gives only **1.7× headroom
over Redpanda's measured 154**, which is the same uncomfortable margin the salt had before it
failed. Client nonce generation (18 raw bytes → 24 base64 chars, `crypto/rand`, core-owned, no
caller parameter) is **not** reopened; ADR 0056 §9 and `nonce.go` settle it and nothing measured
here disturbs it.

**Message.** This is the bound that actually constrains memory and parse work, and the one that
justifies the core not inheriting its caller's framing. Raising it from 4096 to 8192 costs ~3.5 µs
of worst-case parsing and buys 24× headroom over Redpanda's 342-byte message.

**Attributes.** RFC 5802's `extensions` production is unbounded, so a cap of 16 can reject a legal
message. It bounds visitor iterations but not bytes — the message bound already fixes those — so
its residual value is as a cheap parser-complexity guard, not as a resource bound. Raising it to
32 keeps the termination guarantee and removes the interoperability edge.

## 15. Message-size policy

```
maxServerFirstLen  4096 -> 8192
maxServerFinalLen  4096 -> 8192
```

## 16. Salt policy

```
maxSaltLen         128  -> 1024      (7.9x Redpanda's 130, 64x PostgreSQL's 16)
maxSaltEncodedLen  172  -> 1368      (= base64.EncodedLen(1024))
```

**The encoded-before-decode ordering is retained unchanged and is not negotiable.** It is the
property that keeps every refusal allocation-free, and §10 measured that it works.

`maxSaltLen` stays an **absolute constant, not derived from the message bound**. That is
deliberate — see §20.

## 17. Nonce and attribute policy

```
maxNonceLen        256  -> 1024      (6.6x Redpanda's measured 154)
maxAttributes      16   -> 32
```

## 18. Iteration and username policy

```
MaxIterations      1<<20   unchanged
maxUsernameLen     256     unchanged     (svcdoctor's own input, not peer-controlled)
```

## 19. Failure semantics — a defect this review found

Trace of a bound refusal today:

```
scram.ErrMessageTooLarge          "peer field exceeds the size svcdoctor reads"
  -> translateSCRAM               collapsed with ErrMalformedMessage
  -> wire.ErrMalformedResponse    "kafka response could not be decoded"
  -> FailureProtocolMalformedResponse
  -> KAFKA_AUTHENTICATION_NOT_COMPLETED, ERROR, exit 1
```

Redpanda's server-first is **valid RFC 5802**. svcdoctor reported that the peer's response could
not be decoded. **That is a false statement about the peer**, and `ErrMessageTooLarge`'s own
doc comment already says so: *"It is a statement about svcdoctor, not about the peer: the value may
be legal SCRAM."* The sentinel is truthful; the mapping discards its meaning.

Both adapters do this, symmetrically. PostgreSQL maps it to `ErrFrameTooLarge` — a distinct,
truthfully-named sentinel — but `negotiate.go` then classifies that as
`PROTOCOL_MALFORMED_RESPONSE` too, so the evidence carries the same overclaim.

**The correct vocabulary already exists and is already used for the structurally identical case.**
`ErrIterationsUnsupported` — also svcdoctor's own ceiling on a legal peer value — maps to
`UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR` in both adapters, under comments explaining that a gap
in svcdoctor must never be reported as a defect in the target. `ErrMessageTooLarge` is simply
absent from that branch.

**No `FindingCode` or `FailureClass` is added by this record**, and none is needed: both services
already own `EXEC_UNSUPPORTED_BY_SVCDOCTOR` and its finding. This is a mapping correction, and it
is an **implementation prerequisite** (§22) rather than an optional follow-up, because raising the
bounds narrows but does not close the window in which svcdoctor refuses a legal message.

## 20. Selected model

**Outer-bound dominant, with absolute field ceilings retained for defence in depth.**

- The **message bound** is the primary defence. It bounds input, parse work and every derived
  allocation, and it is why the core does not inherit its caller's framing limit.
- The **iteration bound** is the only CPU defence and is unchanged.
- **Field ceilings are retained** — not removed — but set from resource cost rather than observed
  frequency, at roughly 8× the largest value any real implementation is known to produce.

Field ceilings are kept as **absolute constants rather than fractions of the message bound**, and
that is the one place the counter-argument in §21 wins outright: if a future service needs a larger
message bound, a derived salt ceiling would silently widen with it, whereas an absolute one holds.
This model is therefore strictly tighter than removing the field bounds would be.

## 21. Rejected alternatives

**Policy A — minimal patch: `maxSaltLen` 128 → 256, nothing else.** Verified to make Redpanda pass.
Rejected: 256 is 1.97× Redpanda's 130, which repeats the exact methodological error being
corrected — a frequency-derived bound with no resource justification and almost no headroom. It
also leaves `maxNonceLen` at 1.7× a measured real value.

**Policy C — remove the salt and nonce ceilings, rely solely on the message bound.** Verified to
make Redpanda pass, and closest to what every other implementation does. Rejected for the
strongest argument against this record's own direction: the core is a reusable primitive whose
safety must not depend on a number a future caller might raise. With no absolute ceiling, raising
`maxServerFirstLen` for a third service would silently widen the decode allocation. Keeping an
absolute constant costs nothing and removes that coupling.

**Deriving the field bounds from `maxServerFirstLen`.** Rejected for the same reason.

**Raising `MaxIterations`.** Not requested by any evidence. 101 ms is a sane per-run cap and every
observed implementation defaults to 4096.

**Changing client nonce generation.** Out of scope; settled by ADR 0056 §9.

## 22. Implementation requirements

1. Move the six constants in §15–§17. `MaxIterations` and `maxUsernameLen` unchanged.
2. Preserve the validation order in §3 exactly, especially encoded-salt-before-decode and
   iteration-ceiling-before-`derive`.
3. **Correct the failure semantics in §19**: `ErrMessageTooLarge` must reach
   `UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR` in both adapters, not
   `PROTOCOL_MALFORMED_RESPONSE`. No new code or class.
4. Update ADR 0056 §7's table and the false rationale comment on `maxSaltLen`, citing this record.
5. No change to `SchemaVersion`, `FindingCode` set, `FailureClass` set, `Reveal` count,
   authentication cardinality, credential authority or the dependency count.

## 23. Fuzz requirements

Existing targets pass with no crashers (five targets, bounded runs). Seeds must be added at
**limit−1 / limit / limit+1** for every threshold moved, plus:

- a **130-byte-salt, 176-char-encoded** Redpanda-shaped server-first, as a permanent regression seed
- duplicate `r=`/`s=`/`i=` attributes, which are currently unseeded
- a nonce at exactly `maxNonceLen`, and one attribute set at exactly `maxAttributes`

## 24. Integration requirements

- Apache Kafka 4.0.0 fixture: SCRAM-SHA-256 success, wrong credential, escaped principal,
  malformed-response and iteration-limit cases — all must be unchanged.
- PostgreSQL 18 fixture: SCRAM success, wrong credential, iteration limit, server-signature
  verification, malformed parser semantics — all must be unchanged.
- Redpanda: a committed `test/integration/redpanda/` fixture with its own `make` target, per
  `KAFKA_PHASE68_REDPANDA_STUDY.md` §7, before any README or compatibility claim changes.

## 25. Mutation requirements

Phase 7.0 found that **the current test suite pins none of the field-bound values.** Every bound
test is written relative to its constant (`maxSaltLen+8`, `maxSaltEncodedLen+1`, `maxNonceLen`),
so it verifies the mechanism and the ordering but moves with any edit. The whole unit suite passed
unchanged under all four experimental policies. Only `MaxIterations` is value-pinned, at
`scram_test.go:309`.

The implementation must therefore add value-pinning tests, and mechanical catchers for at least:

| # | Mutation | Catcher |
|---|---|---|
| 1 | any bound silently changed | value-pinning test per constant |
| 2 | message bound removed | parse test at limit+1 |
| 3 | salt bound removed | parse test at limit+1 |
| 4 | iteration bound removed | existing, value-pinned |
| 5 | encoded salt decoded before the encoded check | allocation assertion on the refusal path |
| 6 | nonce / attribute bound removed | parse tests at limit+1 |
| 7 | `derive` invoked before validation | existing fuzz invariant |
| 8 | `derive` invoked twice | existing step machine |
| 9 | oversized message reaches PBKDF2 | existing fuzz invariant |
| 10 | overflowed iteration reaches PBKDF2 | existing |
| 11 | huge salt or nonce appears in an error | import allowlist denies `fmt` |
| 12 | bound refusal classified as peer credential rejection | §19 classification test, both services |
| 13 | Redpanda-shaped salt rejected | permanent fuzz seed + fixture |
| 14 | Apache Kafka / PostgreSQL regression | existing integration gates |
| 15 | server-signature verification bypassed | existing |
| 16 | `hmac.Equal` replaced by `==`/`bytes.Equal` | existing guard |
| 17 | advertised broker gains SCRAM | existing `TestTheAdvertisedSweepHasNowhereToPutASecret` |
| 18 | auth cardinality > 1 | existing `TestAtMostOneAuthenticationCallSiteExists` |

## 26. Consequences

- Redpanda SCRAM-SHA-256 is expected to authenticate. **Verified in a worktree against a real
  v25.1.9 instance**, alongside full Apache Kafka and PostgreSQL integration suites.
- The worst-case resource figures in §11 are stated, measured and testable, which the current
  bounds' rationale never was.
- One class of untruthful diagnosis is removed (§19).
- svcdoctor still refuses legal SCRAM above the new ceilings — the window is narrower, not closed.
  It will now say so truthfully.

## 27. Reopen conditions

- **Any real implementation observed producing a salt above 1024 B, a nonce above 1024 chars, or a
  server-first above 8192 B.** Record the measurement; do not widen reflexively.
- **A third service with a different framing bound** — re-derive §11's budget.
- **SCRAM-SHA-512 or channel binding** — both change the derivation contract; ADR 0056's reopen
  conditions still govern.
- **A materially faster or slower derivation primitive**, which would move §13's 101 ms and with it
  the justification for `MaxIterations`.

**The methodology, not just the numbers, is what this record fixes.** A future bound must be
justified by a measured resource cost and a stated headroom multiple over the largest value any
real implementation is known to produce. *"N times the largest value in common use"* is what
failed here, and it must not be the reason given again.

---

## 28. Implementation record — Phase 7.0b

### The numbers that shipped

Exactly §15–§18's, with no substitution:

| Bound | Was | Is |
|---|---|---|
| `maxServerFirstLen` | 4096 | **8192** |
| `maxServerFinalLen` | 4096 | **8192** |
| `maxSaltLen` | 128 | **1024** |
| `maxSaltEncodedLen` | 172 | **1368** |
| `maxNonceLen` | 256 | **1024** |
| `maxAttributes` | 16 | **32** |
| `MaxIterations` | `1<<20` | **unchanged** |
| `maxUsernameLen` | 256 | **unchanged** |

`maxSaltEncodedLen` is now **derived**, written as the constant expression
`(maxSaltLen + 2) / 3 * 4` — a const block cannot call `base64.StdEncoding.EncodedLen` — and
`TestEncodedSaltBoundTracksTheDecodedBound` pins the two to agree so the pair cannot drift into
a gap the decode could fall through.

### The validation order did not move

Unchanged, and now asserted behaviourally rather than only by reading:

- `TestAnOversizedEncodedSaltIsRefusedBeforeItIsDecoded` asserts **zero allocations** on the
  refusal path. That is the only observable that distinguishes the two orders — the error is
  identical either way.
- `TestAnOversizedIterationCountNeverReachesDerivation` and every case in
  `TestEveryThresholdAcceptsItsLimitAndRefusesOneMore` assert the derivation callback ran
  **exactly** 0 or 1 times, so a refused message that still derived would fail.

### Failure semantics, corrected

Both services gained a wire sentinel, `ErrSCRAMParametersUnsupported`, distinct from their
framing errors. `scram.ErrMessageTooLarge` now translates to it, and both adapters classify it
`UNKNOWN` + `EXEC_UNSUPPORTED_BY_SVCDOCTOR` — the branch each already used for
`ErrIterationsUnsupported`.

It lands on a diagnosis rule that **already existed**, so **no `FindingCode` and no
`FailureClass` was added**: Kafka reports `KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` and
PostgreSQL `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`, both `INFO`, both leaving
`SummaryStatus` `OK` and the exit code `0`. That is the correct reading: svcdoctor declining to
read a legal value proves nothing wrong with the target.

One further correction the core needed. Exceeding `maxAttributes` returned `ErrMalformedMessage`
— the peer-defect sentinel — although RFC 5802's `extensions` production is unbounded and such a
message is legal. It now returns `ErrMessageTooLarge`. The grammar violation beside it (an
attribute that is not `k=v`) still returns `ErrMalformedMessage`, and
`TestTheCoreSeparatesPolicyRefusalsFromGrammarViolations` keeps the two apart.

### The prose, which was the part that could not be reused

`KAFKA_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` covers two causes under one code, because to an
operator they are one fact. Its existing wording — *"svcdoctor cannot perform the SASL mechanism
this Kafka endpoint negotiated"* — is **false** for a bound refusal: svcdoctor implements
SCRAM-SHA-256, ran the handshake, began the exchange, and then declined a parameter inside it.
Telling that operator their broker negotiated an unsupported mechanism would send them to fix a
mechanism that was never the problem.

The rule therefore keeps the code and gets its own strings
(`summaryUnsupportedExchange` and friends), which say whose limit applied and that the credential
was neither accepted nor rejected. `TestTheExchangeCapabilityProseDoesNotClaimAMechanismGap`
guards the wording, splicing Go string concatenation first so re-wrapping a line cannot break it.

**This wording was already too narrow before Phase 7.0b** — the same rule already carried the
iteration-ceiling and printable-ASCII causes, for which the mechanism sentence was equally
untrue. The bound refusal made an existing defect visible rather than creating one.

PostgreSQL's wording was already mechanism-agnostic and only needed its enumeration widened to
name bounded message sizes.

### Evidence

| | |
|---|---|
| Redpanda v25.1.9, real broker, SCRAM-SHA-256 | **passes** — full journey through Metadata and the advertised sweep |
| The same suite at the pre-ADR-0061 bounds | **fails**, `KAFKA_AUTHENTICATION_NOT_COMPLETED` |
| Redpanda PLAIN | passes, before and after |
| Apache Kafka 4.0.0, two sequential runs | pass |
| PostgreSQL 18 | passes |
| Mutation matrix | 21 mutations, **zero surviving** |

The negative control is the load-bearing one: the committed fixture was run against the *old*
bounds in a worktree, on the same live broker, and SCRAM failed while PLAIN passed. The suite
detects the defect it was written for.

Two mutations were initially recorded as surviving. Both were **scoping errors in the mutation
run, not gaps**: a second `Continue` call was checked against `./test/security/` when the guard
that catches it lives in `internal/adapter/kafka/wire`, and a planted Redpanda branch was checked
against a scope that does not build the integration tag where its guard lives. Re-run against the
correct scope, both fail.

### The permanent fixture

`test/integration/redpanda/`, pinned to `redpandadata/redpanda:v25.1.9`, with
`make integration-redpanda`. It calls `app.DiagnoseKafka` and nothing else — a separate harness
could diverge from the product and would then prove something about the harness.

It also asserts the invariants a vendor fixture is most likely to erode: exactly one
credential-bearing attempt, no protocol or authentication step anywhere beneath an advertised
endpoint, no credential in the report, and **no production source naming Redpanda**.

It must not run concurrently with the Kafka gate. Phase 7.0 saw one unexplained Kafka failure
under exactly that contention.

### Not changed

`SchemaVersion` 1 · FindingCodes 40 · FailureClasses 41 · `Reveal` production call sites 2 ·
`SecretFor` production call sites 2 · dependencies 1 · Kafka credential-bearing attempts 1 ·
advertised `SecretFor`/`Reveal`/SASL bytes 0.

### One fixture prerequisite, landed separately

`test/integration/kafka/env/gen-certs.sh` did `cd "$(dirname "$0")/certs"` with no `mkdir -p`,
and `certs/` is untracked — so `make integration-kafka` failed on **any** fresh clone or
worktree, and only worked where an earlier run had created the directory. Reproduced in a fresh
worktree (exit 1, against exit 0 for the PostgreSQL fixture, which has always done this), fixed,
and re-verified from another fresh worktree. It touches no product semantics.
