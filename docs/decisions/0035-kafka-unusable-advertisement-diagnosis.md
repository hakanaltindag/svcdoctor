# ADR 0035: An unusable broker advertisement is its own claim, and it is not vantage-dependent

## Status

Accepted, and implemented in the same phase.

Unlike ADR 0034 this record decides a small, self-contained question, so the policy and the
rule land together. Everything structural it needs already exists: the anchoring mechanism
(ADR 0034 §2), the ownership test (§3), the per-subject severity reading (§13), the leaf
vocabulary package (§19) and the finding quality bar (`docs/FINDINGS.md` §3.1).

## Problem

ADR 0034 §14 placed one case explicitly out of scope:

> **An unusable advertisement** (empty host, port 0) — Phase 3.3 already records it as a FAIL
> node and Phase 3.4 runs no sweep. A finding for "the cluster advertises an endpoint no client
> can act on" is genuinely independent and genuinely useful, and is **not authorized here**: it
> is a configuration finding, not a reachability one, and it deserves its own decision.

This is that decision. Three things make it worth a record rather than an obvious extension of
the reachability rule:

- **Vantage dependence differs, and copying it would mislead.** ADR 0034 §17 makes every
  reachability finding vantage-dependent unconditionally. That reasoning does not transfer, and
  asserting it here would tell a reader that trying from elsewhere might help when it cannot.
- **The claim is easy to overstate.** "Kafka advertises an endpoint no client can act on" is
  one sentence away from "`advertised.listeners` is misconfigured", which svcdoctor has not
  observed and cannot observe.
- **The subject is not a well-formed endpoint**, which is a shape no finding has had before.

## Decision

### 1. What the producer actually records

Verified from `normalizeAdvertisement` at `35cc195`, not from comments. An entry is usable
exactly when:

```go
entry.host != "" && broker.Port > 0 && broker.Port <= 65535
```

and the node's state follows directly: `PASS` when usable, `FAIL` with
`PROTOCOL_UNEXPECTED_RESPONSE` when not. So the unusable set is total and small — **no host, a
port outside 1–65535, or both** — and the node carries `kafka.broker.node_id`,
`kafka.broker.advertised_host` (empty when none was advertised) and
`kafka.broker.advertised_port` (the raw `int32`, exactly as it arrived).

`advertisedRef` renders what was advertised rather than what would work, so the subject reads
`:9093` for a missing host and `broker.internal:-1` for an impossible port.

**There is a fourth category, and this record does not cover it.** An entry whose text cannot
be a subject reference at all — a control character, invalid UTF-8, leading whitespace —
produces **no node**, and survives only as a count in
`kafka.metadata.unrepresentable_entry_count` on the exchange. A rule anchored at
`kafka.broker_advertised` cannot see it. That is a real gap, it is recorded here so it is not
mistaken for coverage, and closing it needs its own decision because a finding with no
evidence node to reference is not expressible under ADR 0014. **Reopen when** an entry that
produced no node needs to be diagnosable.

### 2. The claim, and why the code is worded as it is

> **The cluster answered Metadata, and the host and port it reported for this broker do not
> name somewhere a client could connect.**

| Candidate | Verdict |
|---|---|
| "Kafka advertised an invalid endpoint" | **Rejected.** Invalidity is a judgement against a specification, and svcdoctor checked none. It checked whether the pair can become a network target |
| "`advertised.listeners` is misconfigured" | **Rejected, and it is the trap.** Metadata says what a broker reports, never how it arrived at it. A proxy, a service mesh or an operator rewrite produces the same bytes. This is the guessed root cause `docs/FINDINGS.md` §3.1 forbids |
| "Kafka Metadata contained an unusable broker advertisement" | Close, but subject-less — it reads as a claim about the response rather than about one broker |
| **"Kafka advertised broker node N without a usable network endpoint"** | **Chosen.** Names the broker, names the defect, asserts nothing about cause |

**Code: `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE`.** "Unusable" is the producer's own vocabulary —
the adapter decides usability and this code names that determination rather than introducing a
second standard. It shares a prefix with `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` deliberately:
the two are adjacent claims about the same kind of subject, met in the same place, and the
namespace should read as a family. No alias is created.

### 3. Independence, under ADR 0034 §3's own test

Two findings are duplicates when the same evidence entails both and one adds nothing.

```text
UNUSABLE      no endpoint could be formed, so nothing was measured
UNREACHABLE   an endpoint was formed, transport ran, and no path reached it
```

They rest on **disjoint evidence** — this finding cites no transport node, and there is none to
cite — and neither entails the other. They are **independent**, not parent and child.

They are also **mutually exclusive by construction**, which is stronger than being merely
distinct: an advertisement is `PASS` exactly when usable and `FAIL` exactly when not, the
reachability rule requires `PASS`, and this one requires `FAIL`. One advertisement can never
produce both.

That exclusivity is load-bearing, so it is pinned by a test on the graph where the two
mechanisms come apart — an unusable advertisement with a transport sweep beneath it, which no
producer creates. Without the state check such a graph would carry both "there was nothing to
reach" and "no path reached it" in one report. A mutation run found that the ordinary
composition tests did not detect this, because in every real graph the reachability rule stays
silent for two reasons at once.

### 4. Severity is ERROR, on the per-subject reading and not by inheritance

`SeverityError` is "something that prevents correct use", and severity is the impact of the
finding's own claim about its own subject (ADR 0034 §13).

A broker whose advertised endpoint cannot be connected to prevents correct use of that broker
**for every client that reads this Metadata response**. There is no vantage from which it
works, so this is if anything a stronger case for ERROR than unreachability, which at least
admits a network position where the endpoint is fine.

| Rejected | Why |
|---|---|
| WARN | WARN is "a real problem that is not currently breaking use". This is breaking use of that broker, everywhere |
| CRITICAL | Breadth would be a cluster-level claim, and the cluster demonstrably answered (ADR 0034 §10) |
| Severity from broker counts | Encodes an availability model svcdoctor never observed — unchanged from ADR 0034 §13 |
| Severity from controller identity | The controller moves on election and a client does not need it to produce or consume — unchanged from ADR 0034 §15 |

**One unusable advertisement therefore makes a run exit non-zero**, exactly as one unreachable
one does (ADR 0034 §20). Accepted on the same terms: exit 1 means svcdoctor worked and found a
target-side problem, and a broker nobody can connect to is precisely that.

### 5. It is not vantage-dependent, and that is the sharpest contrast with ADR 0034

> **`vantageDependent: false`.**

The defect is in the values that arrived. Usability is decided by `host != "" && 0 < port <=
65535` — arithmetic on wire values, with no resolver, no local trust store and no local
capability anywhere in it. Any client reading the same Metadata response receives the same
unusable pair from any network position.

ADR 0012 requires the flag where the claim depends on network position. Here it does not, and
`false` is a statement rather than an absence: the model always encodes it, so a reader is told
positively that moving will not help. Setting `true` by symmetry with the reachability finding
would have been the most expensive kind of wrong — an actively misleading field that invites a
pointless retry from another host.

### 6. Subject is the advertisement's own subject, unrepaired

The finding reuses the advertisement node's subject exactly: `SubjectKindEndpoint`, ref `:9093`
or `broker.internal:-1`.

It is an endpoint subject that is not a usable endpoint, which reads oddly and is nonetheless
right. The producer chose that kind (ADR 0031) and diagnosis does not get a second opinion:
the alternative is constructing a "fixed" endpoint the evidence never had, which would invent
the target the cluster failed to name.

**Reopen when** a subject kind for a reported-but-unusable target is justified on its own
evidence. It is not justified by this finding alone.

### 7. Evidence references: the exchange and the advertisement, and nothing else

Two references, which is the minimal sufficient proof:

1. `kafka.metadata` — establishes that a broker reported this, and that the exchange succeeded.
   It is also the rule's own precondition, and a finding that requires something it does not
   cite leaves a reader unable to check it.
2. `kafka.broker_advertised` — the determination itself, plus the raw host and port.

**No transport evidence is cited, because none exists.** Phase 3.4 runs no sweep for an
advertisement it cannot turn into a target, and a rule that invented a reference would fail
report assembly under ADR 0014.

### 8. The failure class stays generic, and the finding carries the semantics

The node's class is `PROTOCOL_UNEXPECTED_RESPONSE`, which is service-neutral and correct: a
peer answered, but not as the protocol expects. **No Kafka-specific failure class is added.**
`FailureClass` describes what was observed and belongs to evidence; `FindingCode` describes what
it means and belongs to interpretation. Collapsing them would put Kafka vocabulary into a core
enumeration every future service would edit — the coupling ADR 0009 exists to prevent.

### 9. Prose says one thing, and the structure says the rest

The summary is stable across every unusable subcase, because they are one claim. It carries the
node identifier and nothing else specific.

**The subcase is not in the prose, and does not need to be.** A machine reads
`kafka.broker.advertised_host` and `kafka.broker.advertised_port` off the cited node and
distinguishes "no host" from "impossible port" exactly. A human reads the subject and sees it at
a glance: `:9093` visibly has no host. Putting it in a sentence as well would duplicate
structure in prose and make the summary vary across subcases that share a claim — both against
`docs/FINDINGS.md` §3.1.

**No new Finding field, no new domain enum and no new attribute is introduced**, and no Kafka
constant needed moving: the rule reads `StepMetadata`, `StepBrokerAdvertised` and
`AttrBrokerNodeID`, all already in `internal/service/kafka` from ADR 0034 §19.

**One recommendation**, naming what to inspect without asserting a cause: how the broker's
advertised host and port are configured, and whether anything rewrites Metadata responses in
between. Both are real inspection targets; neither is claimed to be the source.

**No discriminator.** The claim is CONFIRMED with `HIGH` confidence — the cited node *is* the
determination, which is direct and strongly matching evidence — and there is nothing left to
settle. The model rejects the combination anyway.

### 10. Layer, and the case that makes `REPORT_SCHEMA` §7.5 legible

`layer: L6`, the layer of the claim, which is topology.

Here it **coincides** with `summary.firstBrokenLayer`, because the advertisement node is the
only `FAIL` in such a run and it is an L6 node. In the reachability finding the two differ, by
one to three layers. Both are correct, and having a worked example of each is what makes the
distinction teachable rather than a rule people memorize.

## Consequences

- svcdoctor produces two Kafka findings. They partition the advertisements structurally, so no
  engine change, no suppression and no ownership arbitration is needed — and none is authorized.
- The first finding in the repository with `vantageDependent: false`, which exercises a branch
  of ADR 0012 nothing had reached.
- No schema change, no domain change, no dependency change, no new `security.Reveal` call site,
  and no change to the Phase 3.6 rule beyond extracting a shared node-identifier helper.

## A pre-existing redaction defect, found here and deliberately not fixed here

Implementing this finding exercised redaction on subjects that are not well-formed endpoints,
and surfaced a defect that **predates this phase and is not caused by it** — the subject is on
the evidence node whether or not any rule reads it.

A broker advertising `host="" port=0` produces the subject `:0`. Redaction classifies that as a
hostname, because `splitHostPort` rejects `"0"` as a port and the whole ref becomes the host.
`verifyNoResidual` then scans the encoded report for the literal text `:0` — which every report
contains, in `"info":0` among the severity counts and in any timestamp with a zero in its
seconds field. The scan matches its own punctuation and **redaction fails closed on a
transformation that succeeded**.

The consequence is that no shareable report can be produced for a run in which a broker
advertises `:0`, which is a producible case the adapter's own tests already cover. It fails
closed rather than leaking, which is the right direction, but it is a false positive that blocks
a legitimate report.

It is recorded rather than worked around: widening the residual scan is a change to a
security-critical component with its own failure modes, and it deserves a decision rather than a
patch smuggled into a diagnosis phase. It is pinned by a test named as a known defect, which
fails when the behaviour changes.

**Fixed in Phase 3.7.5**, generically and without a Kafka special case. Identity discovery no
longer treats an endpoint reference with an out-of-range port as one opaque hostname, and the
residual scan checks string positions rather than serialized bytes. `:0` now redacts to `:0`,
inventing no host. See `docs/SECURITY.md`, "The residual scan, and what it is allowed to call
an identity".

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Fold this into `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | Different evidence, different vantage semantics, and "unreachable" is false — nothing was reached because nothing was tried | Never |
| A generic `PROTOCOL_UNEXPECTED_RESPONSE` finding over the same node | Restates the evidence node and adds no independent claim; the Kafka finding entails it and adds the broker identity | Never for one evidence node |
| `vantageDependent: true`, by symmetry with ADR 0034 | Actively misleading: it invites a retry from another host that cannot possibly help | Never |
| Naming `advertised.listeners` in the finding | A cause svcdoctor did not observe; a proxy or mesh produces the same bytes | svcdoctor observes broker configuration |
| A Kafka-specific `FailureClass` | Puts service vocabulary in a core enumeration every service would edit | Never |
| A structured "reason" field on the finding | The host and port attributes already distinguish every subcase exactly | Evidence stops distinguishing them |
| Naming the subcase in the summary | Duplicates structure in prose and makes one claim's sentence vary | Never |
| Repairing the subject into a well-formed endpoint | Invents the target the cluster failed to name | Never |
| An aggregate `KAFKA_TOPOLOGY_INVALID` | States no fact the per-broker findings do not | It carries something the conjunction does not |
| Deduplicating by node identifier or endpoint | Distinct advertisement facts are distinct findings, unchanged from ADR 0034 §12 | Never |

## Reopen conditions

- **An unrepresentable entry needs diagnosing** — §1's fourth category, which has no evidence
  node and therefore no finding under ADR 0014.
- **The redaction residual scan is fixed** — the known defect above.
- **A subject kind for a reported-but-unusable target** is justified on its own evidence (§6).
- **svcdoctor observes broker configuration** — the finding could then name a cause (§2).
