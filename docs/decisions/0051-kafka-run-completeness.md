# ADR 0051: A Kafka run is complete when every advertisement it promised to measure reached a verdict

## Status

**Accepted, and implemented in Phase 6.1c** as `incompleteKafkaRun` in
`internal/app/kafkacompleteness.go`, beside the PostgreSQL predicate.

Graph accessors only, as §4 requires: `Nodes`, `Children`, `Node`, `Step`,
`State` and `FailureClass`. No identifier parsing, no `Origin`, no sweep scope,
no subject matching and no schema change — `Result` still carries one boolean.

All ten acceptance rows are pinned as tests, plus five shapes this record implies
without tabulating: a passing handshake resolving a TLS-plan advertisement, a
failed lookup as a complete negative, a locally timed-out lookup, a resolved
lookup with nothing attempted beneath it, and an unusable advertisement needing
no sweep.

**One implementation detail is worth recording**, because it is a distinction §4's
pseudocode does not have to make and an implementation does. *Absent* and
*unrecognized* are different: zero `tls.handshake` children means the plan was
plaintext and a passing connection is transport success, while two of them is a
shape the chain cannot produce. Reading the second as "no TLS plan" would turn an
incomprehensible graph into a reachability claim. Every unrecognized shape reads
as **unresolved**, which is the direction this predicate is required to err in.

It fixes what `Result.Incomplete()` means for a Kafka run, which ADR 0047 defined
only for PostgreSQL's shape.

**Revised before acceptance.** The first draft resolved an advertisement when
*any* address reached a terminal state. A security review rejected that: it
weakened a universally quantified claim into an existential one. §2 records the
corrected rule and why the original was wrong.

## Problem

ADR 0047's predicate, implemented in `internal/app/postgres.go:270`:

```go
func incompleteRun(ctx context.Context, graph domain.Graph, established bool) bool {
	if ctx.Err() != nil { return true }
	if established { return false }                 // postgres.session PASS
	for _, node := range graph.Nodes() {
		if node.State() != domain.StateUnknown { continue }
		switch node.FailureClass() {
		case domain.FailureExecLocalTimeout, domain.FailureExecCancelled:
			return true
		}
	}
	return false
}
```

The middle clause says: *once the run achieved its terminal purpose, an
unfinished alternate path does not make the run incomplete.* For PostgreSQL that
is right — a session was established, and the second address nobody finished
measuring was never the point.

**Kafka has no single fact that plays that role.** Its BASIC scope is two things:

1. a client journey to the bootstrap endpoint, ending at `kafka.metadata`;
2. a topology assessment of every endpoint the cluster advertised.

So the hard case is real:

```text
bootstrap + auth + kafka.metadata          PASS
broker-1 advertised sweep                  PASS
broker-2 advertised sweep                  UNKNOWN / EXEC_LOCAL_TIMEOUT
broker-3 advertised sweep                  PASS
```

If `kafka.metadata` PASS short-circuits the way `established` does, this exits 0
and the report silently omits that a third of the requested topology was never
measured. If any UNKNOWN anywhere makes the run incomplete, one slow alternate
address turns a fully measured cluster into exit 4.

## Decision

### 1. Metadata PASS does not short-circuit completeness

Kafka has **no** analogue of the `established` clause. `kafka.metadata` PASS ends
the *core journey* (ADR 0052) but does not end the *run*, because advertised
reachability is part of what the command promised to measure — it is where both
Kafka findings live.

This is the one place Kafka deliberately diverges from ADR 0047's shape, and the
reason is a scope difference rather than a protocol difference.

### 2. PASS is existential; FAIL is universal

**This asymmetry is the whole rule, and getting it backwards is the mistake the
first draft made.**

The claim an advertised sweep supports is *"this endpoint was not reachable from
this vantage."* That is a **universally quantified negative**: it is only true
when every selectable path was tried and none succeeded.

- **One PASS resolves the advertisement outright.** Reachability is existential;
  a single working path proves it, and no further measurement can overturn it.
- **A FAIL resolves the advertisement only when nothing was left unmeasured.**
  One address refused plus one address never measured does **not** prove the
  endpoint unreachable — a client selecting the unmeasured address might have
  connected.

This is not a new principle. It is already ADR 0043's rule for TCP: *"Every
address the hostname resolved to was tried and none accepted a connection."* The
rejected first draft, by treating any terminal state as resolution, would have let
`FAIL + unmeasured` masquerade as a complete negative — a false certainty of
exactly the kind PostgreSQL closure kept producing.

### 3. The resolution unit is the advertisement, not the address

An advertisement is **resolved** when the run learned whether that endpoint was
reachable. It is **unresolved** when svcdoctor's own budget stopped the
measurement before that could be known. Per-address UNKNOWN below an advertisement
already resolved by a PASS does not count.

### 4. The predicate

```text
incompleteKafkaRun(ctx, graph):
    if ctx.Err() != nil:
        return true                                    # cancelled, or whole-run budget

    metadata := the kafka.metadata node, if any
    if metadata is absent or metadata.State != PASS:
        # The core journey did not finish. Fall back to ADR 0047's scan: an
        # UNKNOWN carrying a local class means svcdoctor stopped, not the target.
        return anyUnknownExec(graph)

    # Metadata was obtained, so the promised topology work is enumerable.
    for each node A where A.Step == kafka.broker_advertised:
        if A.State != PASS:
            continue                                   # unusable advertisement: a verdict
        if not advertisementResolved(graph, A):
            return true
    return false


advertisementResolved(g, A):
    lookup := the single dns.lookup child of A
    if lookup is absent:            return false       # budget stopped before the sweep ran
    if unknownLocal(lookup):        return false
    if lookup.State == FAIL:        return true        # nothing to connect to: complete negative

    paths := the tcp.connect children of lookup
    if paths is empty:              return false       # resolved, yet nothing was attempted

    # Existential: one usable path resolves the advertisement outright.
    for each C in paths:
        if pathReachedTransport(g, C):
            return true

    # No usable path. The negative is provable only if nothing was left unmeasured.
    for each C in paths:
        if unknownLocal(C):
            return false
        h := the tls.handshake child of C, if any
        if h exists and unknownLocal(h):
            return false

    return true                                        # every path terminated in FAIL


pathReachedTransport(g, C):
    if C.State != PASS:
        return false
    h := the tls.handshake child of C, if any
    return h is absent or h.State == PASS


unknownLocal(n):
    n.State == UNKNOWN and
    n.FailureClass in {EXEC_LOCAL_TIMEOUT, EXEC_CANCELLED}


anyUnknownExec(g):
    any node with State == UNKNOWN and
        FailureClass in {EXEC_LOCAL_TIMEOUT, EXEC_CANCELLED}
```

Graph accessors only — `Nodes`, `Children`, `Step`, `State`, `FailureClass`. No
identifier parsing, no `Origin`, no `SweepScope`, no subject matching, no hidden
service flag, no schema field.

**TLS is part of transport success when the plan asked for it.** The advertised
`TransportPlan` mints a `tls.handshake` node under every TCP node if and only if
TLS was required (ADR 0034 §4), so `pathReachedTransport` reads the plan off the
graph rather than being told. **A TCP PASS followed by a TLS FAIL is not transport
success**, and a TCP PASS followed by a TLS UNKNOWN-local leaves the path
unresolved.

### 5. Root, advertisement, address

| Unit | Question | Effect on `Result.Incomplete` |
|---|---|---|
| **Root context** | did the run survive its own budget? | `ctx.Err() != nil` ⇒ true, unconditionally |
| **Logical advertisement** | did the run learn whether this endpoint was reachable? | the resolution unit; one unresolved ⇒ true |
| **Address path** | did this address answer? | never decides alone — contributes existentially (PASS) or blocks a negative (UNKNOWN-local) |

### 6. Finding confidence and `Result.Incomplete` are orthogonal

Confidence qualifies **a claim**. `Incomplete` qualifies **the run**. Both may
appear, and one does not imply the other in general:

- A **CONFIRMED** finding may coexist with `Incomplete = true`. An endpoint-scoped
  TLS identity mismatch on `addr-1` is a complete claim about `addr-1`; a local
  timeout on `addr-2` is a statement about the run. Neither weakens the other.
- An advertised-reachability **HYPOTHESIS** caused by an unfinished sweep should
  normally coincide with `Incomplete = true`, because under §4 the unfinished
  sweep is exactly what leaves the advertisement unresolved.

**Future test expectation**, recorded so it is not rediscovered: an advertised
reachability finding downgraded to `HYPOTHESIS` because of local execution
uncertainty implies `Result.Incomplete == true`. That test would have caught the
first draft's error.

### 7. Exit code 4 means the run did not finish, not that nothing is trustworthy

Restated because it decides how the topology case reads: exit 4 says *svcdoctor's
own execution was cut short, so every conclusion is qualified by what was not
measured.* Findings that were produced remain in the report and remain true.

## Acceptance matrix

| # | Evidence | Resolution | Incomplete | Findings | Status |
|---|---|---|---|---|---|
| **A** | IPv4 PASS, IPv6 UNKNOWN-local | **resolved** | **false** | none for this broker | OK |
| **B** | IPv4 FAIL, IPv6 UNKNOWN-local | **unresolved** | **true** | reachability withheld or HYPOTHESIS | OK / PROBLEMS |
| **C** | IPv4 TLS FAIL, IPv6 UNKNOWN-local | **unresolved** | **true** | endpoint TLS finding **may still fire** | PROBLEMS FOUND |
| **D** | IPv4 FAIL, IPv6 FAIL | **resolved** (complete negative) | **false** | `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` | PROBLEMS FOUND |
| **E** | b1 PASS, b2 all UNKNOWN-local, b3 PASS | b2 **unresolved** | **true** | b2 hedged | OK / PROBLEMS |
| **F** | every advertisement has ≥1 PASS path, some siblings UNKNOWN-local | all **resolved** | **false** | none | OK |
| **G** | Metadata PASS, sweep never begins (root cancellation) | — | **true** | none | OK |
| **H** | Metadata FAIL, target-side protocol error | — | **false** | Metadata finding (Phase 6.3) | PROBLEMS FOUND |
| **I** | one address: TCP PASS, TLS UNKNOWN-local | **unresolved** | **true** | none | OK |
| **J** | one address: TCP PASS, TLS FAIL, no sibling UNKNOWN | **resolved** (complete negative) | **false** | reachability finding | PROBLEMS FOUND |

Rows **B** and **C** are the ones the revision changed; the first draft reported
both as complete.

## Rejected alternatives

| Alternative | Why rejected | Reopen condition |
|---|---|---|
| **Any terminal address resolves the advertisement** (first draft) | Turns a universally quantified negative into an existential one. `FAIL + unmeasured` would read as a proven unreachable endpoint | Never |
| **Any local UNKNOWN ⇒ incomplete** | Would make one slow alternate address incomplete a run that fully measured every broker. Contradicts ADR 0047's own treatment of alternate addresses | Never |
| **Metadata PASS ⇒ complete** | Silently drops the topology half of BASIC, where both Kafka findings live | Advertised reachability leaves BASIC |
| **Hierarchical `coreComplete` / `topologyComplete`** | Requires expanding `Result` or the schema for a distinction §3's resolution unit already supplies | A second consumer needs the two axes separately and the evidence cannot supply it |
| Counting resolution in a diagnosis rule | `Result.Incomplete` is an execution fact about the run, not a claim about the target | Never |

## Consequences

- `Result` keeps one boolean. No schema change, no `SummaryStatus` change.
- `internal/app` gains a Kafka predicate beside the PostgreSQL one; service
  knowledge belongs at the composition root.
- The advertised rule's `verdictIncomplete` is **complementary**: it qualifies the
  claim, this predicate qualifies the run, and §6 records the consistency test
  that ties them together.
- Exit-code semantics and precedence `3 > 2 > 4 > 1 > 0` are reused unchanged.

## Reopen conditions

- Advertised reachability leaves Kafka BASIC.
- A Kafka stage is added whose non-completion is expressible neither as an
  unresolved advertisement nor as an UNKNOWN exec node.
