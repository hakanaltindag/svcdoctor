# ADR 0052: Kafka has no session, so the report says what it obtained instead

## Status

**Accepted. Not implemented — this is renderer vocabulary, and the Kafka renderer
is Phase 6.4.**

Phase 6.1c produced the facts the lines restate, and deliberately no more. A
composed run's graph carries the `kafka.metadata` node whose state is the
`outcome` line, and the `kafka.broker_advertised` nodes and their transport
sweeps that the `topology` count reads. The count's predicate and ADR 0051's
completeness rule share one implementation — `transportPath.reachedTransport` in
`internal/app/kafkacompleteness.go` — so when the renderer arrives, the two
cannot disagree about what "reached" means.

**No Report field was added, and none is needed.** §5's rejected alternative
holds: the outcome is a presentation restatement of a node's state, and
serializing it would put a derived claim in the canonical model. `schemaVersion`
stays 1.

It fixes the user-facing outcome vocabulary for Kafka and the one renderer
extension that vocabulary requires.

**Revised before acceptance.** The first draft proposed `cluster metadata
obtained` and a bare `N of M reachable` topology line. A review narrowed both:
the Metadata request obtains no topic or partition state, and an unmeasured
advertisement must never be presented as an unreached one. §2 and §4 carry the
corrected wording.

## Problem

The terminal renderer prints a fixed Result block:

```text
Result
  status     OK           no target-side error was proven
  session    established
  execution  complete
  duration   13.5ms
```

`session` is derived in `internal/render/terminal/tree.go:237` from
`servicepostgres.StepSession` being PASS, and nothing else. It is the one
PostgreSQL-specific line in an otherwise service-neutral block.

Kafka needs a line there, and **"session established" would be a lie**. Kafka has
no session-establishment handshake: there is no `ReadyForQuery`, no server
message meaning *"the connection is now ready for ordinary work."* A Kafka client
opens a TCP connection, optionally authenticates, and issues requests. Calling
that a session would import a PostgreSQL concept the protocol does not have.

## External facts

- **API version negotiation is connection-scoped**: *"Supported API versions
  obtained from a broker are only valid for the connection on which that
  information is obtained."*
  ([Kafka protocol](https://kafka.apache.org/42/design/protocol/))
- **ApiVersions is answered before authentication**: *"On receiving
  ApiVersionsRequest, a broker returns its full list of supported ApiKeys and
  versions regardless of current authentication state (e.g., before SASL
  authentication on a SASL listener…)"* (ibid.)
- **Bootstrap endpoints are a discovery seed, not the cluster**: *"this list need
  not contain the full set of servers"*
  ([Producer Configs](https://kafka.apache.org/41/configuration/producer-configs/)).

Two consequences follow directly. ApiVersions PASS proves *"something here speaks
the Kafka protocol"* and **nothing about authentication**, because the broker
answers it unauthenticated. And nothing measured against the bootstrap endpoint
can speak for the cluster, because the bootstrap endpoint is not the cluster.

## Decision

### 1. The core journey terminates at `kafka.metadata` PASS

Among the candidate facts, Metadata is the only one that is an **ordinary Kafka
API exchange performed after authentication and authorization**:

| Fact | Proves | Insufficient because |
|---|---|---|
| `kafka.api_versions` PASS | a Kafka protocol speaker answered | answered pre-auth by design |
| `kafka.sasl_handshake` PASS | the mechanism is offered | nothing was authenticated |
| `kafka.sasl_authenticate` PASS | the credential was accepted | authorization untested |
| **`kafka.metadata` PASS** | **an authenticated, authorized API call succeeded** | — |

That is the closest true analogue of `ReadyForQuery`: the first exchange whose
success requires every layer beneath it to have worked. It is what ADR 0051 §1
uses as the core-journey boundary.

### 2. The user-facing terms

`session` is generalized to **`outcome`**, whose text is per service:

```text
PostgreSQL   outcome    session established      /  session NOT established
Kafka        outcome    Kafka metadata obtained  /  Kafka metadata NOT obtained
```

Each is a restatement of one node's state and claims nothing more. PostgreSQL's
existing wording is preserved verbatim, so no PostgreSQL output changes.

**Why `Kafka metadata`, not `cluster metadata`.** The request is Metadata **v1
with `Topics = []`**, which at v1 and above means *request metadata for no
topics*. The run therefore obtains no topic metadata, no partition leader, no
replica set, no ISR and no partition health. "Cluster metadata" invites a reader
to assume cluster state that is structurally absent from the response; "Kafka
metadata" names the exchange that happened and claims only that it completed.

**When Metadata did not pass**, the line reads `Kafka metadata NOT obtained` and
stops. It does not infer a cause from the absence — the stage tree above it
already shows where the journey stopped.

### 3. Rejected wording, and why each overclaims

| Phrase | Rejected because |
|---|---|
| `session established` (Kafka) | Kafka has no session establishment. Importing the word invents a protocol concept |
| `cluster reachable` | Proven of **one** broker. The other brokers are exactly what the advertised sweep is still deciding |
| `cluster usable` | Stronger still, and false whenever every advertised broker is unreachable — which Metadata PASS does not exclude |
| `connection established` | True and useless: it says TCP worked, at the bottom of a seven-stage journey |
| `authenticated` | Skips authorization, and is absent entirely on a `trust`-style listener where nothing authenticated |
| `journey completed` | Vague, and false when the advertised sweep found nothing usable |

### 4. Topology is a separate line, not folded into the outcome

Metadata PASS and topology health are different claims, and merging them is how
`cluster usable` becomes a lie. When advertisements exist, the Result block gains
one more line:

```text
Result
  status     PROBLEMS FOUND
  outcome    Kafka metadata obtained
  topology   2 of 3 advertised broker endpoints reached
  execution  complete
```

`topology` is a **count, not a judgement**. It ranks nothing, calls nothing
degraded and applies no threshold; the findings carry the claims. It is omitted
when the run recorded no advertisements.

**"reached" is past-tense and observational**, and it is defined exactly:

> At least one required transport path for that advertised endpoint completed
> successfully from this vantage, during this run.

Under a plaintext plan that means the `tcp.connect` node passed. Under a
TLS-bearing plan it means the `tcp.connect` node passed **and** its
`tls.handshake` child passed — the same `pathReachedTransport` predicate ADR 0051
§4 uses, so the count and the completeness rule cannot disagree.

`usable`, `healthy`, `transport usable` and `cluster reachable` are all rejected.
Per ADR 0050 an advertised endpoint is never authenticated, so nothing in a Kafka
BASIC run supports a fitness claim about a discovered broker.

**Unmeasured is never collapsed into unreached.** When ADR 0051 leaves an
advertisement unresolved, the line says so:

```text
topology   2 of 3 advertised broker endpoints reached, 1 not measured
```

Without that clause, `2 of 3 reached` asserts a failure that was never observed —
the same false certainty this record exists to prevent.

This line is desirable but not required for a first Kafka CLI: the same facts are
already legible in the stage tree. It may be deferred to a later phase without
making the Result block untruthful.

### 5. The renderer extension is a table, not a branch

`internal/render/terminal` already resolves per-service steps through two tables
(`journey`, `labels`) and falls back to the canonical step name for anything it
does not know. The comment on `labels` states the intent: *"It is also how a
second service arrives without a service switch: Kafka's steps become rows in
this table, not a branch in the renderer."*

The outcome line follows exactly that mechanism: a table from `domain.ServiceID`
to a terminal step and its two phrasings. Kafka additionally contributes its
journey steps — `kafka.api_versions`, `kafka.sasl_handshake`,
`kafka.sasl_authenticate`, `kafka.metadata` — as `journey` and `labels` rows.

**One genuine renderer change is required beyond tables**, and it is recorded
here rather than discovered in Phase 6.4: `collectPaths` currently promotes
**every** `tcp.connect` node in the graph to a top-level path. In a Kafka graph
the advertised sweeps also contain `tcp.connect` nodes, so bootstrap paths and
discovered-broker paths would render as undifferentiated siblings, while
`descendants()` would simultaneously pull the advertised subtree into the
bootstrap path's `extra` list. The tree needs a third level — target → path →
stage, plus advertisement → path → stage — and that is a design task for the
Kafka renderer phase, not a table edit.

### 6. `SummaryStatus` is unchanged

It is derived from findings, and findings are unchanged by this record. The
difficult cases resolve correctly once Phase 6.3 gives the currently-unowned
outcomes their findings; nothing here needs a new status value.

## Acceptance matrix

| Scenario | `outcome` | `topology` | `execution` | Status |
|---|---|---|---|---|
| ApiVersions PASS only, auth not attempted | Kafka metadata NOT obtained | omitted | complete | OK + finding |
| Auth PASS, Metadata FAIL | Kafka metadata NOT obtained | omitted | complete | PROBLEMS FOUND |
| Metadata PASS, all endpoints reached | Kafka metadata obtained | 3 of 3 … reached | complete | OK |
| Metadata PASS, one endpoint not reached | Kafka metadata obtained | 2 of 3 … reached | complete | PROBLEMS FOUND |
| Metadata PASS, no endpoint reached | Kafka metadata obtained | 0 of 3 … reached | complete | PROBLEMS FOUND |
| Metadata PASS, zero advertisements | Kafka metadata obtained | omitted | complete | OK |
| No credential, endpoint requires auth | Kafka metadata NOT obtained | omitted | complete | **OK** + WARN, exit 0 |
| Mechanism not supported by svcdoctor | Kafka metadata NOT obtained | omitted | complete | OK + INFO |
| Metadata PASS, one sweep unresolved | Kafka metadata obtained | 2 of 3 … reached, 1 not measured | **INCOMPLETE** | OK / PROBLEMS |

The two credential rows are the Kafka twins of PostgreSQL's
`POSTGRES_CREDENTIAL_NOT_CONFIGURED` and
`POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` invariants: status OK, exit 0,
and an outcome line that plainly says the metadata was not obtained.

### 6. Four orthogonal axes

`status`, `outcome`, `topology` and `execution` are independent, and a reader is
expected to use all four. None may be derived from another:

```text
status      OK                                              no ERROR/CRITICAL was proven
outcome     Kafka metadata obtained                         the core journey's terminal fact
topology    3 of 3 advertised broker endpoints reached      what discovery measured
execution   complete                                        svcdoctor finished
```

```text
status      PROBLEMS FOUND
outcome     Kafka metadata obtained
topology    2 of 3 advertised broker endpoints reached
execution   complete
```

```text
status      OK
outcome     Kafka metadata obtained
topology    2 of 3 advertised broker endpoints reached, 1 not measured
execution   INCOMPLETE
```

The second is coherent: the core journey succeeded and a discovered endpoint was
unreachable, which is a target-side problem. The third is coherent too: nothing
was proven wrong, and svcdoctor did not finish.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| Reuse `session established` for Kafka | Invents a protocol concept Kafka does not have | Never |
| `cluster metadata obtained` | Implies topic and partition state the `Topics = []` request never requests | The request scope changes |
| `topology  N of M … reachable` | Present-tense capability claim from a past-tense observation | Never |
| `topology  N of M … usable` | Advertised endpoints are never authenticated (ADR 0050) | A discovered-broker authority model exists |
| Collapsing `not measured` into `not reached` | Asserts a failure that was never observed | Never |
| Keep `session` as the label, vary only the value | The label is the claim; a `session` label with a metadata value is worse than either | Never |
| A service-specific Result renderer per service | The tables already generalize; a second renderer duplicates the neutral 80% | A service needs a Result section the neutral block cannot express |
| Four service lines (protocol / auth / metadata / topology) | The stage tree already shows all four with states and durations. The Result block summarizes; it does not restate the tree | Operator feedback shows the tree is not read |
| Report-schema field for the outcome | It is a presentation restatement of a node's state. Serializing it would put a derived claim in the canonical model, which ADR 0048 §5 refuses | Never |

## Consequences

- No Report schema change, no `SummaryStatus` change, no new finding code.
- PostgreSQL output is byte-identical: its wording and terminal step are unchanged.
- The renderer gains one table and one real structural task (§5).
- `docs/REPORT_SCHEMA.md` is untouched; this is renderer vocabulary.

## Reopen conditions

- Kafka BASIC gains a stage after Metadata that is a better journey terminus.
- The `topology` line's counting rule needs to distinguish *measured* from
  *reachable* once ADR 0051's unresolved case is rendered.
