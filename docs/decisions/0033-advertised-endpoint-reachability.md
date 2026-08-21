# ADR 0033: An advertised endpoint is measured once per advertisement, and only at L1-L3

## Status

Accepted, and implemented. It is the consumer ADR 0031 was built to feed and the
first caller of the primitive ADR 0032 added.

**No credential leaves the bootstrap endpoint, no Kafka protocol byte reaches a
discovered broker, no traversal is introduced, and no finding or severity is
produced.** This record measures transport and stops.

## Problem

Phase 3.3 records what a cluster says about itself: one
`kafka.broker_advertised` node per advertisement, each parented to the exchange
that carried it. An advertisement is configuration, and configuration is usually
what a diagnostic tool was called in to examine — but until something measures
those endpoints, a report can say only that the cluster *claims* a broker exists
somewhere.

Measuring them is where four separate questions become expressible at once:
credential forwarding, execution deduplication, a recursion bound, and what an
unreachable advertised broker *means*. ADR 0031 deliberately refused to answer any
of them behind a protocol exchange. This record answers exactly one — execution
deduplication — and refuses the other three again, on the record.

Verified from the tree at `0cc1290`, not assumed:

- `probe.SweepScope`, `probe.ScopedEvidenceID`, `transport.Params.Scope` and
  `transport.Params.Parent` exist; unscoped identifiers are byte-identical to
  Phase 2's.
- No reachability implementation, no `Origin`, no recursion, no visited set, no
  Kafka diagnosis rule, no credential forwarding.
- `GraphBuilder` exposes `AddEvidence`, `AddParent`, `AddBlockedBy` and `Freeze`,
  and no read path.
- One runtime dependency, zero transitive. `make check` green.

## Decision

### 1. The phase is L1-L3 and stops there

```text
kafka.broker_advertised          the fact (L6, Phase 3.3)
  └── dns.lookup      [scoped]   L1
        └── tcp.connect [scoped] L2, one per resolved address
              └── tls.handshake  L3, when the plan asked for it
```

`kafka.MeasureAdvertised` takes a graph builder, the advertisements and a
transport plan, runs one generic transport sweep per usable advertisement, and
closes everything it opened.

**Why it stops at L3.** The layers above it are the ones that need decisions this
phase does not have. L4 needs a reason to believe an advertised listener speaks
Kafka at all — the protocol never said so. L5 needs credential authority for an
endpoint no credential was authorized for. L6 needs a traversal bound. Transport
reachability needs none of those and is already the fact most reports are missing:
"the cluster advertises broker 3 at an address this vantage cannot reach" is a
complete, actionable observation made entirely of DNS, TCP and TLS.

### 2. The transport plan is caller-supplied, because nothing on the wire implies it

A Metadata response carries a node identifier, a host and a port. It does **not**
carry `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT` or `SASL_SSL`. Every available
shortcut is a guess:

| Rejected source | Why it is wrong |
|---|---|
| **The port** | 9093 is a convention. ADR 0011 refuses to infer a service from a port and ADR 0024 refuses to infer TLS from one; a third repetition would not become true |
| **The bootstrap channel or TLS configuration** | It describes *one listener on one broker*. A cluster routinely runs several listeners, and copying the bootstrap's settings would silently turn "this run was encrypted" into "this cluster is encrypted" |
| **The node identifier or hostname** | Neither is a statement about a listener |
| **Kafka convention** | A convention is what a diagnostic tool is called in to find deviations from |

So `TransportPlan` is a parameter: `Resolver`, `Dialer`, `*transport.TLSOptions`
and `StepTimeout`.

**The TLS type is the transport chain's own**, deliberately not a Kafka-shaped
copy. A second TLS model inside an adapter drifts from the one that performs the
handshake, and an adapter that models TLS has begun reimplementing transport —
the boundary `docs/ARCHITECTURE.md` §4 exists to keep.

**Execution intent and observed channel stay separate types.** `TransportPlan`
says what will be attempted; `security.Channel` says what a connection turned out
to prove, and only the chain that performed the handshake may state one (ADR
0029). A plan cannot carry a channel and a channel cannot configure a plan.

### 3. One advertisement, one sweep — redundant on purpose

```text
node 1 -> broker.internal:9093      two advertisement facts
node 2 -> broker.internal:9093      two scoped sweeps
```

**Execution deduplication is deliberately not implemented.** ADR 0031 §4 said that
when it arrives it would be keyed by the normalized endpoint; ADR 0032 listed it
as open. This record decides that it does not arrive yet, and the reason is
representational rather than a preference for simplicity:

> **The graph has no truthful many-causes→one-execution representation, so
> deduplicated execution could only be recorded by dropping a cause.**

A deduplicated sweep would have two advertisements as its cause and one DNS node
as its effect. `transport.Params.Parent` is singular (ADR 0032 §6, kept singular
precisely so this decision was not pre-empted), so recording it would mean
choosing one advertisement to be *the* parent — by node identifier, by insertion
order, or by canonical identifier order. Every one of those is a semantic
ownership decision made by a tiebreak, and the losing advertisement would silently
have no measurement attributed to it. A rule that later concludes "the broker
advertised as node 2 is unreachable" must reference the exact evidence that
produced it (ADR 0014); with a dropped cause, it could not.

The cost of the choice is bounded and small: a handful of extra connections to
endpoints the cluster itself named, sequentially, with no credential. The cost of
the alternative is a graph that misattributes causes, which is permanent and
invisible.

**Recorded plainly: redundant but truthful execution was chosen over deduplicated
execution because the graph currently has no canonical many-causes→one-execution
representation.**

| Case | Sweeps | Why not merged |
|---|---|---|
| Two node identifiers, one endpoint | **2** | Both advertisements are causes; a tiebreak would drop one |
| One node identifier, two endpoints | **2** | A node identifier is not an execution target |
| One hostname, two ports | **2** | Two listeners, two facts. This is why ADR 0032 exists |
| Two hostnames, one resolved address | **2** | The DNS fact, the TLS identity, the routing intent and the advertised endpoint all differ |
| Bootstrap endpoint advertised back | **2 measurements of one host** | Measurement identity is not subject identity |
| Byte-identical repetition in one response | **1** | Phase 3.3 already collapsed it into one fact |

### 4. The fact-normalization boundary belongs to Phase 3.3

> **Phase 3.3 decides what a fact is. Phase 3.4 executes once per resulting fact.**

Byte-identical advertisements were collapsed by the Metadata step, which counts
the collapse so it stays visible; contradictions were preserved. This phase adds
**no second dedup layer** and rewrites nothing. Whatever `MetadataResult.Brokers`
returns is what gets measured, one sweep each.

### 5. The sweep scope is a prefix plus the whole SHA-256 of the advertisement identifier

```text
advertised.7abb44c52e8e3d95f6290679656123f8833667cd836fbfd6727786fef99be914
dns.lookup/advertised.7abb44c5…be914/broker-1.internal
```

The label is `"advertised."` followed by the SHA-256 of the advertisement's
evidence identifier, in hexadecimal. **The digest is not truncated**; §5.1 is why.

**Uniqueness is inherited, not asserted.** The advertisement identifier is already
unique per advertisement fact in the run, for a reason this phase does not
re-derive: `GraphBuilder` rejects a repeated identifier outright, so two
advertisements that reached the graph necessarily have different ones (ADR 0031
§3). The identifier is used as **opaque input** — nothing decodes it, splits it,
or reads a component out of it, and ADR 0019 still has no decoder.

| Option | Verdict |
|---|---|
| **Prefix + full SHA-256 of the advertisement identifier** | **Chosen.** Deterministic, order-independent, unique by inheritance, fixed-width, and safe through `NewSweepScope` without escaping |
| Prefix + a 64-bit truncation of that digest | Shorter by 48 characters, and the only option here that makes uniqueness *probabilistic*. Rejected: see §5.1 |
| The full advertisement identifier as the label | Rejected by ADR 0032 §2 as unreadable, and measurement confirms it with a second reason that record did not have: it is **unbounded**. It grows with the bootstrap endpoint and the advertised hostname — 87 characters for a short example, 143 for ordinary production names — where the digest stays at 75 forever, and it puts identity-bearing text into an identifier twice over |
| `<node-id>.<advertised-endpoint>` | Readable, but not unique: two Metadata exchanges in one run would mint one label for one advertised broker. Making it unique means adding the exchange's endpoint and address, at which point it is the full identifier again |
| An index, a counter or a timestamp | Order- or time-dependent, which §9 of ADR 0032 forbids |
| A random or pointer-derived value | Non-deterministic; a report would differ between identical runs |

Checked, rather than assumed: **escaping** — hexadecimal after a constant prefix
needs none; **determinism** — same advertisement, same label, on every run;
**length** — sixteen characters plus a prefix; **redaction** — see §10;
**accidental semantic parsing** — impossible by construction, and that is a
property rather than a compromise. *Which* advertisement caused a sweep is
answered precisely by the parent edge, which is the record entitled to answer it.

#### 5.1 Why the digest is not truncated

A 64-bit truncation was implemented first and then rejected on review. The
numbers were never the argument on either side:

| | 64-bit truncation | Full SHA-256 |
|---|---|---|
| Scope label | 27 characters | 75 characters |
| A TCP identifier | 72 characters | 120 characters |
| Compute cost | identical — the full digest is computed either way; truncation is a slice | identical |
| Uniqueness | **probabilistic**: birthday bound ≈ n²/2⁶⁵, about 3×10⁻¹⁴ at a thousand advertisements | the collision resistance the rest of computing assumes |

**The decisive argument is architectural, not numerical.** This repository states
identifier injectivity as a *proven* property and argues it: ADR 0019 derives it
from escaping rather than asserting it, and ADR 0032 §3 restates it "honestly",
caveat included, rather than generously. A truncation would have introduced the
first probabilistic element into that contract — and it would have done so in the
one phase whose entire thesis is that truthful attribution beats convenience (§3).

**The second argument corrects a claim an earlier draft of this record made.** A
truncated collision is *not* uniformly loud:

- Colliding scopes **and** one hostname → one identifier → the graph rejects the
  second, loudly. That is a false failure of a healthy run, not a safe outcome.
- Colliding scopes with **different** hostnames → no identifier collision at all
  → nothing fails, and two unrelated measurements quietly share a label.

A scheme with a silent failure mode has to justify it. There was nothing to
justify it with: the cost of removing the question is 48 characters of identifier
text and no compute, no dependency and no semantic change.

**So: why accept a collision probability here at all, when nothing requires it?**
It should not be accepted, and it no longer is. Negligible risk is still risk
taken for a reason, and the reason on offer — shorter opaque text — is not one.
Both options are opaque blobs a reader does not decode; *which* advertisement
caused a sweep is answered by the parent edge either way. The readability that
ADR 0032 §2 was protecting when it rejected the full identifier is not what
truncation was buying.

**Stated honestly, without overclaiming:** SHA-256 does not make a collision
impossible — no digest can, by pigeonhole. It moves the question from a
probability this record would have to compute and defend at realistic scale to an
assumption already relied on everywhere, with no adversary in the picture, since
the inputs are svcdoctor's own derived identifiers. `TestTheSweepScopeCarriesTheWholeDigest`
pins the width so the truncation cannot quietly return.

### 6. Derivation: the advertisement parents the sweep's DNS node

```text
kafka.broker_advertised  ──parent──  dns.lookup [scoped]
```

There is **no synthetic Kafka reachability node** between them. A wrapper would
have to state a step, and no step ran that a DNS, TCP or TLS node does not already
record; its state would have to be derived from the nodes beneath it, which is
diagnosis. It is not created, and a test pins that a scoped sweep produces L1-L3
nodes only.

**The edge is derivation and not provenance**, exactly as ADR 0031 §6 and ADR 0032
§6 require. It says *this measurement exists because that fact did*. It does not
say the endpoint entered the run by discovery — see §8.

### 7. Bootstrap == advertised is measured again, and reuses nothing

A single-listener cluster advertising its bootstrap host back is routine. The run
then holds:

```text
dns.lookup/primary.internal                              bootstrap, a root
dns.lookup/advertised.<digest>/primary.internal          topology, parented to the advertisement
```

Both are kept. **No bootstrap DNS, TCP or TLS evidence is reused**, and the
measurement is not skipped because the subject matches — measurement identity is
not subject identity, and the two measurements have different causes and different
moments. The subjects are identical, which is correct: a scope changes the
identifier and never what was observed.

### 8. `Origin` remains deferred, and a scope must never become one

A scope answers *which execution is this?*. It does not answer *how did this
endpoint enter the run?*.

- No `Origin()` on the scope, the plan or the result.
- Nothing parses a scope, and nothing infers "discovered" from one.
- A scope never reaches a `Subject` or an attribute (asserted).

The decisive case is unchanged and is now exercised end to end: the bootstrap
endpoint is measured twice in one run, once unscoped and once under an advertised
scope, so the same `host:port` is simultaneously supplied and advertised. A scope
that meant provenance would have to claim one of those and be wrong. ADR 0013's
and ADR 0031 §6's deferral stands, with the same reopen condition: an execution or
topology planner with a real consumer for provenance.

### 9. One hop, no credential, no protocol

**One hop.** Metadata advertisement → transport measurement → stop. Nothing
re-enters, so there is no recursion, no depth limit to tune, no visited set and no
work queue. The bound arrives with the traversal, as ADR 0031 §5 said.

**No credential.** The guarantee is structural: `MeasureAdvertised` takes a
builder, advertisements and a transport plan, and none of them can hold a
credential, a secret, an identity, a mechanism or an authenticated session.
`reachability.go` does not import `internal/security` — importing it to assert
non-use would be the wrong kind of proof — and the production `security.Reveal`
call-site count is unchanged at one. "Same cluster" is still not credential
authority (ADR 0028).

**No Kafka protocol.** `reachability.go` imports neither the `wire` package nor
`kmsg`, and both absences are asserted by reading its imports. The fixture peer
is not a Kafka broker: it accepts, optionally completes TLS, and counts every
byte that arrives above TLS. **The expected count is zero, and it is measured
rather than promised** — no ApiVersions, no SaslHandshake, no SaslAuthenticate, no
Metadata.

### 10. Connections are released, and none escapes

This phase is measurement-only: there is no protocol consumer behind the transport
it establishes. Every connection a sweep produced is closed before the next
advertisement is measured, in every outcome.

The caller receives no `transport.Continuation` and no socket, and
`MeasurementResult` has no `Close` because it owns nothing. A discovered-broker
connection pool would be a resource with no reader, closed by a layer that never
opened it.

Proven on both ends: the peer's read loop only ends when svcdoctor closes, so
waiting for the peer to go idle proves nothing is still open, and each of
svcdoctor's own sockets is asserted to have been closed **exactly once** — an
idempotent `Close` called twice looks identical from the far end.

### 11. Address-family neutrality, and sequential execution

The chain attempts **every** resolved address and this phase adds no preference:
no first-answer shortcut, no family ranking, no "chosen" path. A dual-stack
advertisement produces one TCP node per family and leaves zero live sockets.

Execution is **sequential**, in the order the broker sent its advertisements.
Concurrency would buy wall-clock on a bounded number of endpoints and cost
ownership clarity, budget predictability and deterministic operational behaviour.
Canonical ordering belongs to `Graph` and the report, never to execution timing —
a test runs a reversed advertisement order and gets an identical set of
identifiers.

### 12. Budget: the existing step timeout, and no new one

| Option | Verdict |
|---|---|
| **The chain's existing `StepTimeout`, threaded through** | **Chosen.** It already bounds every DNS, TCP and TLS call, which is the only place a topology sweep can block |
| Caller context only | Leaves one black-holed address able to consume the whole run — the exact case `StepTimeout` was added for in Phase 2.4 |
| A per-advertisement budget | Bounds the same work a second time with a number that can disagree with the first, and has no case `StepTimeout` does not already cover |
| A phase-global topology budget | The caller's context already is one |

**When the caller's context expires, the loop stops and the advertisements it
never reached receive no evidence at all.** Nothing was measured about them, and a
node claiming otherwise would be the local-timeout-as-remote-failure mistake the
claim discipline exists to prevent. Sweeps already performed keep their evidence;
inside a sweep, the chain's own contract for an address it did not attempt is
unchanged.

### 13. Unusable advertisements are skipped without fabricated evidence

Phase 3.3 records an advertisement that names no usable endpoint as a `FAIL` node
carrying what did arrive. This phase skips it: there is nothing to resolve and
nothing to dial, and a `SKIPPED` DNS or TCP node would need a subject — an
endpoint — that was never advertised. The problem is already recorded, once, on
the node that observed it.

### 14. Latency stays per layer

DNS, TCP and TLS keep their own durations on their own nodes, so a report can say
*DNS answered in X, TCP connected in Y, TLS completed in Z* for a broker-advertised
endpoint. **No aggregate "reachability latency" is produced**: it would be a
second representation of the same measurement, free to drift, and it would invite
a reader to use one number where three are the finding.

### 15. Failure classes stay generic, severity stays open

The evidence uses the existing DNS, TCP, TLS and `EXEC_` classes. **No
`KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` and no Kafka-specific transport class is
introduced**, and none may be: a service-specific failure class here would be a
finding in disguise.

This phase finally produces the exact data a transport severity rule needs, and
deliberately does not use it. Whether *one unreachable broker out of three* is
`WARN`, `ERROR` or `CRITICAL` depends on Kafka replication semantics and on
diagnosis policy, and both belong to a layer that consumes frozen evidence. **The
transport-severity decision (ADR 0017) and the generic-versus-service finding
overlap remain open, and the existence of this evidence does not settle either.**

### 16. Package ownership: the Kafka adapter

`internal/adapter/kafka/reachability.go`, in the existing package.

| Option | Verdict |
|---|---|
| **`internal/adapter/kafka`** | **Chosen.** It consumes this package's own `DiscoveredBroker`, invokes generic transport, diagnoses nothing, and needs nothing the package does not already have |
| A `topology` subpackage | A new package boundary with no new responsibility on either side. It could not even deliver the "no Kafka client in the path" property it appears to buy: importing `kafka` for `DiscoveredBroker` links `kmsg` transitively anyway. The file's own import list is the honest guarantee, and it is asserted |
| `internal/probe` or `internal/probe/transport` | Would put Kafka awareness into a generic probe. Forbidden by depguard and by the primary architecture rule |
| `internal/app` | This is service-local one-hop orchestration, not product orchestration. Opening the application boundary for it would confuse the two `docs/ARCHITECTURE.md` §3.2 separates |
| `internal/service/kafka` | Still has no second consumer; the reopen condition is the first Kafka diagnosis rule |

### 17. The result is two counts

`MeasurementResult` reports `Considered()` and `Measured()`, and nothing else.

Everything the phase learned is in the graph, in the form the report serializes. A
result that also carried DNS states, TCP outcomes, TLS verdicts or endpoint health
would be a second copy free to drift from the first and tempting to consume
instead of it (ADR 0013, ADR 0016). **There is no `Reachable bool`, no aggregate
health, no severity and no finding**, and a test pins that the type has exactly
two methods.

Why the counts exist at all: `Measured()` is not derivable without repeating this
function's usability rule, and `Considered()` distinguishes "examined and
unusable" from "never reached because the budget ended". Which of those it was is
a question about the caller's own context, which the caller already holds and this
type does not restate.

## Consequences

- svcdoctor can measure the endpoints a Kafka cluster advertises, credential-free,
  with each measurement derived from the exact advertisement that caused it.
- One run can hold two truthful measurements of one hostname, including the
  bootstrap host, and a shareable report keeps both.
- Contradictory topology reaches the report *with measurements attached to every
  claimant*, which is the case the whole design protects.
- The canonical report schema is unchanged: no new step, no new attribute, no new
  layer, no new failure class, no `domain` type touched. The evidence is generic
  transport evidence.
- `GraphBuilder` is untouched. No dedup, no visited set, no depth, no counter.
- No new dependency; still one runtime module, zero transitive.
- PostgreSQL inherits the shape unchanged: *advertised endpoint → scoped generic
  sweep → derivation edge* names no service.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Deduplicate execution by normalized endpoint | Requires choosing one advertisement as *the* cause; the loser silently loses its measurement, and a finding could not reference the evidence that produced it | The graph gains a truthful many-causes→one-execution representation — most plausibly a multi-parent sweep, which ADR 0032 kept out of `Parent` on purpose |
| Deduplicate by node identifier | A node identifier is not an execution target, and one identifier at two endpoints is a fact to keep | Never |
| Deduplicate by resolved address | Erases four differences to save one dial: the DNS fact, the TLS identity, the routing intent and the advertised endpoint | Never |
| Skip an advertised endpoint that equals the bootstrap target | Subject equality is not measurement identity; the two measurements have different causes and moments | Never |
| Infer TLS from the port, the bootstrap channel, or convention | Turns a convention into a claim, and a per-listener fact into a per-cluster one | Never |
| A Kafka-specific TLS options type | A second TLS model that drifts from the one performing the handshake, inside a layer that must not model transport | Never |
| A synthetic `kafka.reachability` wrapper node | It observes nothing of its own; its state could only be derived from its children, which is diagnosis | It observes an independent fact |
| Fabricate SKIPPED transport nodes for unusable advertisements | Needs a subject that was never advertised, and duplicates a problem Phase 3.3 already recorded | An existing contract requires such a node |
| Fabricate evidence for advertisements a cancelled run never reached | Claims a measurement that never happened; a local timeout is not a remote failure | Never |
| Return a live continuation, or pool discovered-broker connections | A resource with no reader, closed by a layer that never opened it | A phase exists that speaks to a discovered endpoint — which needs credential forwarding decided first |
| Speak ApiVersions to a discovered broker to confirm it is Kafka | Crosses the one-hop boundary; L4 on a discovered endpoint is its own phase with its own decisions | That phase is written, on its own merits |
| Concurrent sweeps | Buys wall-clock on a bounded endpoint count and costs ownership clarity, budget predictability and deterministic behaviour | A measured performance need |
| A per-advertisement or phase-global timeout | Bounds the same work twice with numbers that can disagree | A blocking case appears that `StepTimeout` does not cover |
| Emit `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` here | A finding, produced by a layer that must not diagnose, and it would pre-empt the generic-versus-service overlap question | The first Kafka transport rule, in diagnosis |
| Record an `Origin` now that endpoints are measured | Unchanged from ADR 0031 §6: origin is not a function of the subject, and this phase proves it by measuring one endpoint in both roles | An execution or topology planner has a real consumer |
| A `topology` subpackage | A boundary with no new responsibility, and it cannot deliver the isolation it appears to | A second consumer of the advertisement facts exists outside this package |

## Known limitations, recorded rather than solved

- **A cluster with many brokers costs one sweep per advertisement**, including
  repeated endpoints. Bounded, sequential, credential-free, and the deliberate
  trade in §3.
- **An advertised listener's security protocol is still unknown.** The plan says
  what svcdoctor attempted, not what the listener offers. A TLS failure against a
  plaintext listener is a true measurement of what was attempted, and reading it
  as "the broker is broken" is a diagnosis error this evidence cannot prevent on
  its own.
- **One transport plan applies to every advertisement in a call.** A cluster
  mixing plaintext and TLS listeners needs two calls, which the API permits and
  does not model. A per-advertisement plan would need a source of truth for which
  listener is which, and nothing on the wire supplies one.

## Reopen conditions

- **A truthful many-causes→one-execution representation** — then execution
  deduplication becomes decidable on its merits, keyed by the normalized endpoint
  as ADR 0031 §4 said, and `Parent` may need to accept several.
- **A phase that speaks a protocol to a discovered endpoint** — it owns credential
  forwarding, the L4 evidence question and the traversal bound together.
- **An execution or topology planner with a real consumer for provenance** —
  `Origin`, unchanged.
- **The first Kafka transport diagnosis rule** — transport severity, the
  generic-versus-service finding overlap, and the attribute-key move to a leaf
  both layers can import.
- **A measured performance need** — concurrency, with the ownership and ordering
  arguments in §11 re-derived rather than assumed.
