# ADR 0031: Metadata discovers a topology, records it, and probes none of it

## Status

Accepted, and implemented. **This is the first phase where svcdoctor learns
about endpoints the operator never named.**

It reopens the condition ADR 0013 set for `Origin` and answers the one ADR 0019
set for topology identifier uniqueness. `Origin` is examined and **left
deferred**: this phase records structural *derivation*, which is a different and
weaker thing than provenance, and needs no field. Identifier uniqueness is
resolved as *two observations, never one merged claim*.

## Problem

Every phase so far described one measured connection. This one asks a broker
what *other* endpoints exist, and the answer arrives as configuration the
operator may never have seen.

That transition can go wrong in a specific way: topology discovery, endpoint
reachability, credential forwarding, execution deduplication, recursion bounds
and severity all become expressible at the same moment, and each is individually
tempting to finish while the code is open. Bundled, they would settle four
architectural questions as a side effect of a protocol exchange.

Verified from the tree at `9e8a1d3`, not assumed:

- No Metadata implementation, no topology traversal, no `Origin` field, no
  Kafka diagnosis rule, no credential forwarding.
- `internal/diagnosis/kafka` contains a `.gitkeep` and nothing else, so the
  attribute-key ownership reopen condition — *a real second consumer* — is still
  unmet.
- `GraphBuilder` exposes `AddEvidence`, `AddParent`, `AddBlockedBy` and `Freeze`
  and **no read path**, so nothing can ask it what it already holds.
- kmsg v1.13.1 Metadata is key 3, versions 0–13; v9+ is flexible and the framing
  guard refuses it.
- One runtime dependency, zero transitive. `make check` green.

## Decision

### 1. The request asks for brokers and no topics, at v1

The topics field selects between two very different questions, and the versions
read an empty list differently:

```text
v0    empty topics array  ->  every topic
v1+   empty topics array  ->  no topics;  null -> every topic
```

So **v0 cannot express a broker-only request at all**, and the choice of v1 is
not a compatibility preference — it is the difference between a few dozen bytes
and a cluster's entire partition map.

| Option | Rejected because |
|---|---|
| **A/D. Cluster metadata without topics** | **Chosen.** At v1 these are the same thing: the response carries brokers and a controller identifier and nothing else |
| B. All topics | Orders of magnitude larger, needs describe authority on every topic — so a run could fail on authorization while saying nothing about connectivity — changes between runs, and yields no broker fact the empty request does not |
| C. Selected topics | Needs a topic parameter no layer can supply, and topic diagnosis is explicitly out of scope |

Not newer than v1, and the reason is security rather than framing. v2 adds
`ClusterID`, which is deployment identity with no settled redaction
classification. At v1 it is **not on the wire**, so it is structurally absent
rather than received and filtered — a property no future edit to the normalizer
can weaken, and a test pins that v1 neither encodes nor decodes one. v9 would
also be flexible, which the shared framing refuses.

`Rack` is on the wire at v1 and stays inside the wire package. It is
identity-ambiguous free text — "us-east-1a" carries little, "dc-frankfurt-rack-7"
carries a lot — with no consumer in this phase. **Reopen when** a rule needs
rack-aware topology, at which point it needs an identity classification first.

### 2. One exchange node, and one node per advertised broker

```text
kafka.sasl_authenticate        the connection this continues
  └── kafka.metadata           the exchange: one request, one outcome        (L6)
        ├── kafka.broker_advertised   one advertisement                      (L6)
        ├── kafka.broker_advertised
        └── kafka.broker_advertised
```

Both steps are L6. `docs/ARCHITECTURE.md` places topology discovery there, and
the Metadata exchange *is* topology discovery — the same reasoning that puts
credential-free SASL mechanism discovery at L5 (ADR 0026 §5).

| Option | Rejected because |
|---|---|
| **B. Exchange node + node per broker** | **Chosen** |
| A. One node, brokers in a string-list attribute | The decisive failure. A later reachability probe of broker X would have nothing precise to parent to, and a finding must reference the exact evidence that produced it (ADR 0014). "Which entry caused this?" would be answerable only by parsing an attribute — which ADR 0019 forbids for identifiers and ADR 0018 forbids for redaction |
| C. Broker nodes only | The exchange is a fact with its own state, timing and failure class. A Metadata request that timed out has no brokers to hang a node on, so the outcome would be unrecordable |

**What PASS means on an advertisement node** is narrow and stated on the node's
own documentation: the advertisement was observed and names somewhere a client
could connect. It is not a reachability claim. Nothing has been probed — the
same shape as a DNS lookup passing because an answer arrived, not because the
answer is good.

### 3. Broker identity and endpoint identity are different things

```text
NodeID     the broker identity this Metadata response reported. An integer the
           service chose; nothing a client connects to.
Endpoint   a network target. It is configuration, which is usually what a
           diagnostic tool was called in to examine.
```

**Neither is assumed unique or stable.** A single Metadata response cannot prove
that a node identifier is unique across the cluster or survives a restart, and
this step deliberately records responses where it is neither — see the conflict
table below. Calling it "the cluster's logical identity" would promise more than
the protocol proves, and would contradict the design that preserves those
conflicts.

Neither alone is the execution target, and neither alone is the identity.
`DiscoveredBroker` exposes them as separate methods so that using the wrong one
is a visible mistake rather than a field access.

**The identifier carries both, plus the exchange that carried them:**

```text
kafka.broker_advertised/<endpoint>/<address>/<node-id>/<advertised-endpoint>
```

That keeps it injective across exactly the cases this phase exists to surface:

| Case | Result | Why it must not merge |
|---|---|---|
| One node ID, two endpoints | two nodes (component 4 differs) | a rolling reconfiguration or a listener mistake |
| Two node IDs, one endpoint | two nodes (component 3 differs) | clients will be routed to the wrong broker |
| Same broker, two Metadata responses | two nodes (components 1–2 differ) | two observations that may disagree |
| Byte-identical repetition | one node, and the collapse is counted | see §4 |

### 4. Fact deduplication collapses only identical facts, and says so

Two different concerns, deliberately not one key:

**Fact dedup** — a byte-identical repetition of one advertisement within one
response is one fact. The exchange node records both
`kafka.metadata.broker_count` and `kafka.metadata.advertised_entry_count`, so a
response listing a broker twice is visibly different from one listing it once.
**The one collapse this phase performs is reported rather than silent.**

**Contradictions never collapse.** Merging on node identifier would erase a
second advertised address; merging on host:port would erase a second claimant.
Both are preserved as separate nodes. A diagnostic tool that tidied a
contradiction away would be hiding the finding somebody ran it to get.

**Execution dedup does not exist in this phase**, because nothing is executed
against a discovered endpoint. When it arrives it is keyed by the **normalized
endpoint** — the network target — and never by node identifier, because the
question it answers is "have I already dialled this?".

An entry whose text cannot be a subject reference at all is counted in
`kafka.metadata.unrepresentable_entry_count`. It is the one hole through which an
entry could otherwise vanish without trace.

### 5. Discovery records; it probes nothing

| Option | Rejected because |
|---|---|
| **1. Record only** | **Chosen.** The advertisement is already the useful fact |
| 2. Probe each discovered endpoint immediately | Forces credential forwarding, execution dedup, a recursion bound and a severity view about unreachable brokers into the phase that was supposed to produce their input |
| 3. Record, then a separate expansion component | The right eventual shape, and option 1 is its first half. The component is Phase 3.4's, with this phase's output as its input |

**Recursion is therefore impossible**, because nothing re-enters. **There is no
depth limit**, and that is deliberate: an arbitrary numeric bound with no
traversal to bound would be a knob nobody can justify. The bound arrives with
the traversal.

### 6. Metadata derivation is structural; provenance is not, and stays deferred

ADR 0013 deferred `Origin` until real topology orchestration existed. It now
does, so the decision is reopened — and answered against the implementation
rather than in the abstract.

**Two statements have to be kept apart, and only the first is claimed here:**

| | |
|---|---|
| **A. Derivation** | A `kafka.broker_advertised` node was produced by a specific `kafka.metadata` node, and its parent edge records that. **True, and structural.** |
| **B. Provenance** | The *endpoint* that node describes entered the run by discovery, so `Origin` is readable off graph shape. **Not claimed. Intentionally unresolved.** |

`docs/REPORT_SCHEMA.md` states the rule this record obeys: *"Do not infer that
parent relationships already encode discovery provenance. A parent edge is a
structural or derivation relationship and says nothing about how a subject
entered the run; reading provenance out of graph shape would be a guess with the
same authority problem in a less visible form."*

The difference is not academic, and the implementation demonstrates it. When a
cluster advertises the bootstrap endpoint back — routine for a single-broker
cluster — one normalized `host:port` occupies two roles in one run. The
advertisement node derives from the exchange; the transport and protocol nodes
for the same endpoint derive from the DNS lookup and predate the exchange
entirely. **Both are true, the graph ranks neither, and no node claims how the
endpoint entered the run.** `TestBootstrapEndpointCanAlsoBeAdvertised` pins it.

So A gives this phase everything it needs — a later reachability probe can name
the exact advertisement it followed — while B stays exactly as open as ADR 0013
left it.

| Question | Answer |
|---|---|
| Is the parent edge sufficient? | **Sufficient for derivation, and that is all this phase needs.** A broker node's parent is the exact exchange that carried it, whose own chain reaches the authentication, the handshake, ApiVersions, TLS, TCP and the lookup. A test walks it. It is *not* sufficient for provenance, per the table above |
| Can a broker also be a bootstrap endpoint? | **Yes** — a single-broker cluster routinely advertises the host the operator typed. So "origin" is **not a function of the subject**, and a field on the node could not represent it. This is the decisive argument |
| Can one broker be discovered twice? | Yes, and each observation keeps its own parent. A field would say "discovered" on both while losing *which response* |
| Would a field be a second truth source? | **Yes, provably.** Nothing would keep `Origin == discovered` consistent with "this node's parent chain reaches a Metadata node". Either could be set independently — exactly ADR 0013's stated fear |
| What is it a property of? | Not evidence and not the subject, for the reason above. The closest fit is the **execution plan** — "should I probe this, and with what credentials?" is a question about a planned action, and that is run-local orchestration state which does not exist |
| Does credential forwarding need it? | **No.** The layer that will ask is the expansion component, iterating over endpoints it just discovered. It knows by construction; it does not read a field back off frozen evidence |

**Decision: `Origin` remains deferred, unchanged in substance from ADR 0013.**
This phase adds a structural *derivation* record and no provenance record, and a
test asserts no node claims an origin. Nothing here makes `Origin` unnecessary in
general; it makes it unnecessary *for this phase*, which needed derivation and
got it.

**Reopen when an execution or topology planner has a real consumer for
provenance.** ADR 0013's condition was "topology orchestration exists"; discovery
now exists but *orchestration* — the layer that decides which endpoints to
execute against, and with what credentials — does not. That layer is the first
plausible consumer, because "was this endpoint supplied or discovered?" is a
question about a planned action rather than about a recorded fact. A diagnosis
rule weighting a finding by endpoint provenance is the second.

Two cautions for whoever reopens it. Walking parents answers *derivation*, not
provenance, so it is not a substitute. And the shared-endpoint case above shows
provenance is not a function of the subject, so wherever it lands it cannot
simply be a field keyed by endpoint.

### 7. Endpoint normalization borrows the rules and refuses the type

Advertised hosts are normalized by the same rules `security.Endpoint` uses —
ASCII-only lowercasing because DNS case insensitivity is an ASCII rule (RFC
4343), one trailing dot removed, IP literals canonicalized through `net/netip` —
and **not** by that type.

That refusal is itself a security property. `security.Endpoint` exists to
authorize a credential, and its `Equal` is a credential-authority decision. If a
`DiscoveredBroker` handed one out, forwarding a credential to a broker the
cluster merely advertised would be one function call away from a caller who
wanted somewhere to connect. Same rules, different type, **no conversion
offered**, and a test asserts none appears.

**Nothing is resolved.** A hostname stays a hostname: turning it into an address
here would fold a DNS answer into a topology fact, and measuring that answer is
the entire point of the phase that follows.

A port is validated to 1–65535. An advertisement that fails validation is
recorded as a `FAIL` node carrying what did arrive — including the impossible
port, unmodified — because a broker advertising `:0` is precisely the
misconfiguration somebody runs a diagnostic tool to find. **No usable endpoint is
invented from invalid metadata.**

### 8. Credential forwarding is not crossed, and cannot be

This phase sends no credential anywhere. The guarantee is structural rather than
promised: `Metadata` has no parameter a credential could occupy, `MetadataParams`
has no credential field, and `DiscoveredBroker` exposes neither a credential nor
a `security.Endpoint`. Tests assert all four by reflection.

**"Same cluster" is not credential authority.** A credential authorized for
`bootstrap.internal:9093` remains authorized for that endpoint and no other, and
`ForwardingPolicy`'s zero value still denies.

### 9. Attribute keys stay in the adapter

The reopen condition was *a real second consumer*. `internal/diagnosis/kafka`
contains a `.gitkeep`. The condition is **still unmet**, and metadata existing is
not the same as a consumer existing — §13 of the phase brief says so explicitly
and this record agrees.

`internal/service/kafka` is **not created.** When the first Kafka rule is
written it will need `kafka.broker.node_id` and the advertised host and port, and
the move is mechanical then. Creating the package now would ship a vocabulary
designed for a consumer nobody has read.

### 10. The connection survives a completed exchange

| Outcome | Evidence | Connection |
|---|---|---|
| Exchange completed | PASS | **kept** — still authenticated |
| Peer closed, not Kafka, malformed, miscorrelated | FAIL | closed |
| Budget expired or cancelled | UNKNOWN | closed |

Metadata reads a description and **advances no protocol state**, so the
connection is exactly as usable afterwards as before. This is the first Kafka
step whose success hands back the *same kind* of session it consumed rather than
a stronger one — it asked a question rather than completing a handshake — which
is why it introduces no new session type.

There is no broker error code to consult: a top-level error code arrives only at
v13, and svcdoctor sends v1, so a completed exchange is data rather than a
verdict. Recording a zero error code would claim the broker stated something it
was never asked to state.

## Consequences

- svcdoctor can describe a Kafka cluster's brokers, with each advertisement its
  own addressable evidence node parented to the exchange that carried it.
- A later phase can probe a discovered broker and parent its transport evidence
  to a precise node, which is the thing option A above would have made
  impossible.
- Contradictory metadata reaches the report intact.
- The canonical report schema is unchanged: two steps, seven attribute keys, one
  existing subject kind, one existing layer. No `domain` type changed.
- No new dependency. Still one runtime module, zero transitive.
- PostgreSQL inherits nothing service-specific: the topology *shape* — an
  exchange node parenting per-endpoint discovery nodes — is reusable, and
  everything Kafka-specific stays in the adapter.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Request all topics | Large, authorization-sensitive, non-deterministic, and yields no broker fact the empty request does not | Topic diagnosis is a phase, with its own request |
| Metadata v0 | Cannot express a broker-only request; an empty array means every topic | Never |
| Metadata v2+ | Would receive a cluster identifier with no redaction classification, for no fact this phase needs | Cluster identity is classified and a consumer needs it |
| Record `Rack` | Identity-ambiguous free text with no consumer | A rule needs rack-aware topology |
| Brokers as a string list on one node | Later reachability evidence would have no precise parent | Never |
| Add an `Origin` field now | No consumer. Not a function of the subject either — a broker can also be the bootstrap host — so the shape it would take is undecided | An execution or topology planner has a real consumer for provenance |
| Dedup by node ID | Erases a second advertised address | Never |
| Dedup by host:port | Erases a second claimant of one address | Never |
| Merge one broker seen by two responses | Two observations that may disagree become one claim, and `GraphBuilder` has no read path to detect the repeat without becoming smarter (ADR 0013) | An orchestration layer holds cross-exchange state and can record the merge as its own fact |
| Probe discovered brokers in this phase | Drags credential forwarding, execution dedup, recursion and severity in behind a protocol exchange | Phase 3.4, as its own component |
| A depth limit with no traversal | A knob nobody can justify, tuned against nothing | Recursive expansion exists |
| Reuse `security.Endpoint` for discovered brokers | Puts credential forwarding one call away from a caller who wanted a connection target | Never |
| Create `internal/service/kafka` now | Still one consumer; the vocabulary would be designed for a reader nobody has | The first Kafka diagnosis rule |
| A common `ProtocolSession` so Metadata works without SASL | Erases the compile-time ordering that makes "authenticate before the mechanism was agreed" impossible | A non-SASL Kafka path is actually built |

## Known limitations, recorded rather than solved

- **Metadata is reachable only from an authenticated session.** Kafka serves it
  perfectly well on a PLAINTEXT or SSL listener with no SASL; svcdoctor has no
  session type that survives the adapter chain unauthenticated. **This is
  scope, not Kafka protocol truth**, and it is stated on `Metadata`'s own
  documentation so nobody infers the protocol from the API.
- **Two Metadata exchanges over one endpoint and address in one run collide.**
  The identifier is derived from the step and its scope, so the second is
  rejected by the graph rather than merged or overwritten, and the first
  exchange's evidence is left intact. This is the retry case ADR 0019 left open,
  arriving for the first time; it is pinned by a test and deliberately not
  solved, because retry is execution policy and no layer owns it.

## Reopen conditions

- **A traversal** — a depth bound and an execution-deduplication key arrive
  together with it, keyed by normalized endpoint.
- **An execution or topology planner with a real consumer for provenance** —
  §6's `Origin` condition. Derivation edges do not satisfy it.
- **The first Kafka diagnosis rule** — the attribute keys move to a leaf both the
  adapter and diagnosis can import.
- **Cluster identity classified** — the version choice in §1 can then be
  revisited on its merits rather than avoided.
- **A non-SASL Kafka path** — the session-type question in the limitations above.
