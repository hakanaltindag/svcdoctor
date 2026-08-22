# ADR 0045: The negotiation gets a floor, so a wrong port stops reading as healthy

## Status

Accepted as **policy**. No rule is implemented here.

It decides one thing: who owns a `postgres.ssl_request` node that failed for any
reason other than the endpoint declining to encrypt. It adds one finding code, no
`FailureClass`, no schema field, no dependency and no engine behaviour.

**It is deliberately half of what Phase 4.11a set out to decide.** The other
PostgreSQL BASIC blocker — a run that reaches Startup and stops because no
credential was configured — is *not* settled here. It hit two of the phase's own
second-opinion triggers and is returned as a packet rather than decided. See §9.

It closes the gap ADR 0040 recorded under "What this does not own" and extends
that record's floor pattern to a fourth step. ADR 0041, ADR 0043 and ADR 0044 are
unchanged.

## Problem

Point svcdoctor at a port serving HTTP — the most ordinary way an operator gets a
PostgreSQL endpoint wrong — and this is the whole report:

```text
target.requested       L0  PASS
  └── dns.lookup       L1  PASS
       └── tcp.connect L2  PASS
            └── postgres.ssl_request  L3  FAIL   PROTOCOL_UNEXPECTED_RESPONSE
                 └── tls.handshake    L3  SKIPPED

findings: []        status: OK        firstBrokenLayer: L3
```

Measured, not supposed. `status: OK` beside a broken layer, for the single most
common wrong-target mistake there is.

ADR 0040 declined findings here in as many words:

> *`postgres.ssl_request` failures other than a decline — an `E` answer, a
> malformed reply, a peer close. No finding, recorded as a gap: an `E` answer is a
> peer refusing to negotiate and is worth a claim, but it is rare enough that no
> measurement exists and this record does not authorize findings for shapes it has
> not seen.*

That restraint was right, and it is now half-obsolete: the shapes have been seen.
What has **not** been seen is an `E` answer specifically, which is why §5 declines
to give that one its own claim.

## Decision

### 1. Every reachable outcome of the negotiation, and who owns it

Read from `classifySSLResponse` and `wireFailureClass` in
`internal/adapter/postgres/negotiate.go`, not from the class list.

| Outcome | State | Class | Owner |
|---|---|---|---|
| server answers `S` | PASS | — | no finding; ADR 0044 owns what follows |
| server answers `N` | FAIL | `PROTOCOL_UNSUPPORTED_CAPABILITY` | `POSTGRES_TLS_DECLINED` (ADR 0040) |
| server answers `E` | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | **this record** |
| any other byte | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | **this record** |
| readable bytes before the answer | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | **this record** |
| unclassifiable I/O failure | FAIL | `PROTOCOL_UNEXPECTED_RESPONSE` | **this record** |
| peer closed mid-exchange | FAIL | `PROTOCOL_PEER_CLOSED` | **this record** |
| frame too large / malformed | FAIL | `PROTOCOL_MALFORMED_RESPONSE` | **this record** |
| cancelled | UNKNOWN | `EXEC_CANCELLED` | **nobody, deliberately** |
| budget expired | UNKNOWN | `EXEC_LOCAL_TIMEOUT` | **nobody, deliberately** |
| TLS not requested by the plan | SKIPPED | `EXEC_SKIPPED_BY_POLICY` | nobody; nothing failed |

### 2. `POSTGRES_SSL_NEGOTIATION_FAILED`

| | |
|---|---|
| **Trigger** | `postgres.ssl_request` is FAIL **and** its class is one of `PROTOCOL_UNEXPECTED_RESPONSE`, `PROTOCOL_PEER_CLOSED`, `PROTOCOL_MALFORMED_RESPONSE` |
| **Claim** | *svcdoctor asked this endpoint to negotiate an encrypted PostgreSQL connection, and the exchange did not complete.* |
| **Kind** | `CONFIRMED` |
| **Severity** | `ERROR` |
| **Confidence** | `HIGH` |
| **`vantageDependent`** | **`true`** |
| **Layer** | `L3` |
| **Subject** | the negotiation node's own subject — the concrete `ip:port` |
| **Evidence** | the `postgres.ssl_request` node, alone |
| **Recommendation** | *Check that this endpoint is the PostgreSQL service this run intended to reach, and read the referenced evidence for what the exchange observed* |

**Must not claim**, and each of these is a real temptation:

- that the endpoint is not PostgreSQL — a PostgreSQL server behind a broken proxy
  produces the same bytes;
- that the port is wrong — likely, unobserved, and the recommendation asks rather
  than asserts;
- that TLS is disabled, or that the endpoint refused TLS specifically — that is
  `POSTGRES_TLS_DECLINED`, and this class is not it;
- that a proxy, firewall or middlebox exists;
- anything about certificates or authentication, neither of which was reached;
- that svcdoctor knows *why* the exchange failed. It does not, which is what makes
  this a floor.

#### Why ERROR

Severity is the impact of the claim about its own subject (ADR 0034 §13). The run
required an encrypted channel, this endpoint did not deliver the negotiation that
precedes one, and nothing further could be attempted on this connection. That is
what prevents correct use, and it matches `POSTGRES_TLS_DECLINED` — the adjacent
claim at the same node.

#### Why `true`, when the neighbouring code is `false`

This is the sharpest contrast in the record, and it is derived rather than copied.

`POSTGRES_TLS_DECLINED` is `false` because the `SSLRequest` answer is a
server-wide setting: the same peer answers every source identically. This floor
has no such backing. Under ADR 0040 §6.1's Ground 2 — *the cause is unattributed
by construction, so a source-keyed cause cannot be excluded* — a claim that
attributes nothing cannot rule out that something on this path produced it. The
three existing PostgreSQL floors are `true` for exactly this reason, and this is
the fourth.

Two adjacent codes on one node with opposite vantage values is correct, not an
inconsistency: one names what the server decided, the other declines to name
anything.

### 3. One floor, and the `E` answer stays open

| Model | Verdict |
|---|---|
| **A. One floor over the three classes** | **Chosen** |
| B. Split the `E` answer from malformed and peer-close | **Rejected for now**, and the reason is evidence rather than taste — see below |
| C. Split "not PostgreSQL" from "PostgreSQL refused" | **Rejected.** svcdoctor cannot tell them apart. A PostgreSQL server behind a rewriting proxy and an HTTP server produce the same malformed answer, and peer-close proves neither |
| D. Leave it evidence-only | **Rejected.** That is the measured `status: OK` above |

**On B, honestly.** An `E` answer *is* different: the peer spoke PostgreSQL and
refused to negotiate, which is a server-side decision an operator acts on
differently from a wrong port. It deserves a claim eventually.

It does not get one here for the same reason ADR 0040 declined it: **no
measurement of one exists.** This phase measured an unexpected *byte* — an HTTP
response — not an `ErrorResponse`. Authorizing a claim for a shape nobody has
produced is what the floor pattern exists to avoid, and the class
`PROTOCOL_UNEXPECTED_RESPONSE` on the cited node already distinguishes it for a
machine reading evidence.

**Reopen when** an `E` answer is measured against a real endpoint. The likely
producer is a server configured to reject the negotiation, or the CVE-2024-10977
shape the adapter already comments on.

### 4. Disjointness, proved rather than asserted

**From `POSTGRES_TLS_DECLINED`, by class alone.** `classifySSLResponse` returns
`PROTOCOL_UNSUPPORTED_CAPABILITY` only for `SSLDeclined`, and only on the `err ==
nil` branch — which is the same branch that records `postgres.ssl.offered`. So
that class always arrives with the attribute, always satisfies the declined
rule's predicate, and never appears in this floor's set. The two predicates are
disjoint on `FailureClass` with no attribute check and no ordering.

**From ADR 0044's in-band TLS finding, by state.** That rule requires the
negotiation to have **passed**; this one requires it to have failed. One node
cannot be both. The SKIPPED `tls.handshake` beneath a failed negotiation is
excluded there twice over — it is not FAIL, and its parent is not PASS.

**From ADR 0043's generic transport findings**, which never anchor at a
`postgres.*` step.

No suppression, no precedence, no first-match-wins.

### 5. What the floor does not cite

**The `tls.handshake` child is not referenced**, even though it exists and is
SKIPPED. `docs/FINDINGS.md` §11: a blocked step is never cited as a cause; its
blocker owns the failure. The negotiation node carries the state, the class and
the plan attribute, which is the whole proof.

Nothing above is cited either. The connection and the anchor prove that the
endpoint was reached, which this claim does not dispute.

### 6. Cancellation and the budget produce nothing

Both arrive as `UNKNOWN` with an `EXEC_*` class, and the rule fires only on FAIL.
"I could not measure it" and "it is broken" stay different claims because the
states differ, not because a rule remembers to check.

### 7. Report effect

| Run | Today | After implementation |
|---|---|---|
| HTTP server on the port | FAIL evidence, `firstBrokenLayer: L3`, **findings []**, **status OK** | one `POSTGRES_SSL_NEGOTIATION_FAILED` ERROR, `firstBrokenLayer: L3`, **PROBLEMS_FOUND** |
| peer closes mid-negotiation | same silence | same, one finding |
| server answers `N` | `POSTGRES_TLS_DECLINED` | unchanged |
| server answers `S`, TLS fails | ADR 0044 finding | unchanged |

`Summary` code does not change. `firstBrokenLayer` was already L3 and stays L3.

### 8. Acceptance matrix

| # | Scenario | Finding | Severity | Status | fBL |
|---|---|---|---|---|---|
| 1 | `N` answer | `POSTGRES_TLS_DECLINED` only | ERROR | PROBLEMS_FOUND | L3 |
| 2 | `E` answer | `POSTGRES_SSL_NEGOTIATION_FAILED` | ERROR | PROBLEMS_FOUND | L3 |
| 3 | unexpected byte (HTTP peer) | same | ERROR | PROBLEMS_FOUND | L3 |
| 4 | surplus bytes before the answer | same | ERROR | PROBLEMS_FOUND | L3 |
| 5 | malformed frame / frame too large | same | ERROR | PROBLEMS_FOUND | L3 |
| 6 | peer closed mid-exchange | same | ERROR | PROBLEMS_FOUND | L3 |
| 7 | unclassifiable I/O failure | same | ERROR | PROBLEMS_FOUND | L3 |
| 8 | cancelled during negotiation | **none** | — | OK | unset¹ |
| 9 | budget expired during negotiation | **none** | — | OK | unset¹ |
| 10 | TLS not requested by the plan (SKIPPED) | **none** | — | per later | per later |
| 11 | `S` answer, TLS handshake fails | ADR 0044 finding only | ERROR | PROBLEMS_FOUND | L3 |
| 12 | `S` answer, healthy | none from this record | — | per later | per later |
| 13 | TCP fails before the negotiation | ADR 0043 finding only | ERROR | PROBLEMS_FOUND | L2 |
| 14 | two paths, both negotiations fail | **one finding per endpoint** | ERROR | PROBLEMS_FOUND | L3 |
| 15 | one negotiation fails, another succeeds | **one finding**, on the failing endpoint | ERROR | PROBLEMS_FOUND | L3 |
| 16 | redacted report | subject pseudonymized, ref resolves | — | — | — |
| 17 | permuted insertion order | byte-identical findings | — | — | — |

¹ assuming nothing else failed.

**Rows 14 and 15 are endpoint-scoped**, following ADR 0044 §8 and ADR 0040's
per-node model, not ADR 0043's target-level withholding. The claim is about the
endpoint that failed to negotiate, and another endpoint working does not make it
false.

**Row 3 is reproducible in real integration**; rows 2, 4, 5, 6 and 7 are
unit-only, because the fixture serves a correct PostgreSQL listener and making it
emit an `E` answer or a malformed frame would mean asserting against a server
svcdoctor will never meet.

### 9. Mutation matrix

| | Mutation | Caught by |
|---|---|---|
| A | the floor swallows `PROTOCOL_UNSUPPORTED_CAPABILITY` | row 1 |
| B | UNKNOWN included | rows 8, 9 |
| C | SKIPPED included | row 10 |
| D | fires when the negotiation passed | rows 11, 12 |
| E | duplicates ADR 0044's TLS finding | row 11 |
| F | cites the SKIPPED handshake child | a reference-set assertion on rows 2–7 |
| G | peer-close or malformed silently dropped | rows 5, 6 |
| H | claims the endpoint is not PostgreSQL, or names a port, proxy or firewall | the prose guard already in this package |
| I | raw wire error text reaches the finding | the same prose guard; the adapter already discards it |
| J | subject becomes the logical target | rows 2–7 assert the node's own subject |
| K | `vantageDependent: false` | a per-code table test |
| L | a second SSL code appears | the declaration scan and the module-wide allow-list |
| M | generic transport claims the node | ADR 0043's rules never anchor at `postgres.*` |
| N | `schemaVersion`, `FailureClass` or `Reveal` change | the existing count guards |

### 10. Security and redaction

No new redaction rule. The subject is a `SubjectKindEndpoint` `ip:port`, already
rewritten through the pseudonym table; the negotiation node's only attribute is
`postgres.tls.plan`, a plan name carrying no identity. No credential is involved
at any point, and `security.Reveal` is untouched.

The prose must carry no hostname, address or wire error text. The adapter already
discards the error's text — *"the wire package has no idea a plan exists"* and the
classifier reads typed sentinels only — and this record does not reintroduce it.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Leave it evidence-only | The measured `status: OK` on a wrong port | Never |
| A code for the `E` answer now | No measurement of one exists; the class already distinguishes it | An `E` answer is measured |
| A "this endpoint is not PostgreSQL" claim | Unprovable from these bytes; a proxy in front of a real server looks identical | Never |
| Splitting malformed from peer-close | The same question — *is this the service I meant?* — and the same first move | An operator study shows they diverge |
| Citing the SKIPPED handshake | A blocked step is never a cause | Never |
| `vantageDependent: false` by analogy with `TLS_DECLINED` | That code names a server-wide decision; a floor names nothing | Never |
| Widening `POSTGRES_TLS_DECLINED`'s predicate | It would claim the endpoint declined when it never answered | Never |

## Consequences

- The most common wrong-target mistake stops producing a healthy-looking report.
- PostgreSQL gains one code: 22 → 23 across the repository.
- The negotiation joins startup, authentication and session in having a floor, so
  every `postgres.*` step is now total over failure.
- ADR 0040's recorded gap is closed for two of its three shapes, and the third —
  the `E` answer's own claim — is narrowed to a single reopen condition rather
  than left open-ended.
- `FailureClass`, `schemaVersion`, `Reveal`, the dependency set and
  `diagnosis.Rule` are unchanged.

## Reopen conditions

- **A measured `E` answer** — its own claim, §3.
- **A producer emitting a fourth FAIL class at this step** — the mapping is closed
  and would withhold, which is safe but should then be reviewed.
- **The no-credential decision** — §9 of Phase 4.11a's packet; it may or may not
  land in this package.
