# ADR 0032: A sweep names an execution, so one run can measure a host twice

## Status

Accepted, and implemented. It removes the blocker that stopped Phase 3.4 before
any of it was written, and it resolves the "Topology" case ADR 0019 left open.

**No service reachability, no topology traversal, no credential forwarding and
no findings are implemented here.** This record adds one primitive.

## Problem

Phase 3.4 has to measure endpoints a Kafka cluster advertised. It could not
start, and the reason was not Kafka-shaped at all.

Evidence identifiers are derived from what a node is about (ADR 0019), and a DNS
lookup is about a name and nothing else — so its identifier is
`dns.lookup/<host>`, with no other component. A run may therefore contain **at
most one lookup per hostname**, and `GraphBuilder` rejects the second outright.

Reproduced from the tree at `1f3b13d`, not argued:

```text
Run(bootstrap  primary.internal:9092) -> dns.lookup/primary.internal
Run(topology   primary.internal:9093) -> recording dns evidence:
        invalid evidence graph: evidence "dns.lookup/primary.internal"
        is already in the graph
```

The collision matrix that matters:

| Case | Collided |
|---|---|
| Bootstrap host advertised back, same port | **yes** |
| Bootstrap host advertised back, different port | **yes** |
| Two advertisements sharing a hostname | **yes** |
| Genuinely different hostnames | no |

TCP and TLS identifiers carry the endpoint, so they already distinguish two
ports. **Only DNS collided**, and it collided on exactly the cases Phase 3.4
exists to handle: a single-listener cluster advertising its bootstrap host back
is routine, and two advertisements naming one host is the contradiction ADR 0031
deliberately preserves.

**This was predicted.** ADR 0019, under "Uniqueness, and what it still does not
solve", listed *Topology* as an open case and said of the failure:

> `GraphBuilder` failing loudly on a duplicate is the correct interim behaviour:
> it surfaces the question at the moment something first needs it.

That moment arrived. This record answers the question rather than working around
it in an adapter.

## Decision

### 1. Four things that are not the same

The blocker looks like an identifier problem and is really a modelling one, so
the distinctions are stated before the fix.

| | |
|---|---|
| **Subject identity** | *what was observed.* For a lookup, the hostname. Unchanged by this record |
| **Measurement identity** | *which observation this is.* Two lookups of one name at two moments are two measurements |
| **Execution scope** | *which run-local execution produced it.* The new concept |
| **Origin / provenance** | *how a subject entered the run.* Still deferred (ADR 0013, ADR 0031) |

Only measurement identity was under-specified. The subject was always right; the
graph was always right to reject a repeated identifier. What was missing was a
way to say "this is a different execution".

### 2. `probe.SweepScope` — an opaque, validated, caller-owned label

```go
scope, err := probe.NewSweepScope("topology")   // validated
var unscoped probe.SweepScope                   // zero value: unscoped
```

A small validated type, in `internal/probe` beside the identifier encoding it
belongs to — ADR 0019 put the encoding there precisely because it is "a rule
that would be wrong if two probes implemented it differently".

| Option | Rejected because |
|---|---|
| **B. Validated type** | **Chosen.** Validates where the label is chosen, not several layers later inside `NewEvidence`; carries its own doc; and being a distinct type makes transposition with the adjacent `endpoint string` a compile error rather than a silent mis-scope |
| A. Plain string | A control character or stray whitespace would surface as a confusing `NewEvidence` failure at a distance, and it transposes with neighbouring string parameters |
| C. Integer sequence | Meaningless in a report a human reads and diffs |
| D. Parent `EvidenceID` only | Does not work: a parent edge does not enter the identifier, so the identifiers still collide |
| E. Caller-supplied full `EvidenceID` as scope | Produces unreadable identifiers, against ADR 0019's readability property |
| F. Hidden counter in `GraphBuilder` | Turns the builder into an allocator with run state, which ADR 0013 exists to prevent, and makes identifiers depend on execution order |

**The separator and the escape character are deliberately accepted in a label.**
ADR 0019: "a delimiter choice must never decide what input a layer accepts." A
scope containing `/` or `%` is escaped like any other component.

**An empty label is rejected**, so `NewSweepScope("")` is an error rather than a
silent "unscoped". A caller that wants no scope uses the zero value, which reads
as the deliberate choice it is; one that computed an empty string has a bug worth
surfacing.

### 3. The scope sits after the step, and an unscoped call is byte-identical

```text
unscoped   dns.lookup/primary.internal
scoped     dns.lookup/topology/primary.internal
```

The step stays first, so an identifier still says what its node is at a glance
and still sorts by step. The scope precedes the components because ADR 0019's
ordering rule already dictates it: components run widest to narrowest, and a
sweep is wider than any endpoint inside it.

**A zero scope contributes no component at all — not an empty one.** Every
identifier this repository has minted since Phase 2 is unchanged, byte for byte,
and that is asserted directly rather than assumed.

#### Injectivity, stated honestly

Two scoped identifiers collide only when their scope and every component match —
which is when they describe the same measurement of the same subject by the same
sweep. Escaping is what makes that hold.

**Scoped and unscoped identifiers are told apart by arity, not by escaping, and
they are not universally distinct:**

```text
EvidenceID("dns.lookup", "a", "b")               -> dns.lookup/a/b
ScopedEvidenceID(scope "a", "dns.lookup", "b")   -> dns.lookup/a/b
```

What keeps the scheme injective here is that **a step mints a fixed number of
components** — `dns.lookup` always one, `tcp.connect` and `tls.handshake` always
two. A scoped identifier for a step therefore always carries exactly one more
component than its unscoped form.

That is a real constraint on future producers, and it is recorded rather than
left to be discovered. `TestStepArityIsFixed` asserts the counter-example above
still holds, so the caveat cannot quietly stop being true.

### 4. One sweep, one scope, every layer

```text
transport.Params.Scope
  -> dns.Lookup(ctx, resolver, host, scope)
  -> tcp.Connect(ctx, dialer, endpoint, addr, scope)
  -> tls.Params.Scope
  -> skipped TLS and unattempted TCP nodes
```

The chain threads one value into every probe it drives, including the nodes it
mints itself for steps that did not run. **No probe invents a scope**, and none
reads one: it is escaped, joined, and that is all.

### 5. The scope reaches the identifier and nothing else

A scope is orchestration context. What was observed is unchanged by who asked, so
it must not touch the observation.

- **Never the subject.** If it did, two measurements of one host would begin
  describing two hosts, which is the pollution this design exists to avoid.
- **Never an attribute.** There is no key for it and no value carrying it.

Both are asserted, including against a canary-shaped label.

### 6. An optional derivation parent

`transport.Params.Parent` optionally records that a sweep exists *because* an
earlier observation did. Absent, the DNS node is a graph root exactly as before.

| Question | Answer |
|---|---|
| One parent or a slice? | **One.** The graph supports several, but the only real consumer needs one. A slice would be answering the many-causes→one-execution question, which this record deliberately leaves open |
| Empty preserves the graph? | Yes, and it is asserted |
| Validated before execution? | **No.** `GraphBuilder` deliberately offers no read path (ADR 0013), and giving it one to save a lookup would trade a correct boundary for a cheap pre-flight |
| Absent parent — error or evidence? | **An invocation error.** A parent that is not in the graph is a caller defect. Nothing is fabricated to hang the edge on, and a test asserts the absent node is not created |

**The edge is derivation, not provenance.** It says this measurement exists
because that node did. It does not say the subject was discovered, supplied, or
trusted. `docs/REPORT_SCHEMA.md` forbids reading provenance out of graph shape
and this field does not change that.

### 7. `GraphBuilder` is untouched

No sweep registry, no visited set, no dedup, no depth, no counter, no identifier
allocator. It still stores evidence and relationships, validates the DAG, and
freezes. Scope is execution context, and execution context belongs to whoever
executes.

### 8. Redaction needs no new rule, and that is proven rather than assumed

A scope is caller-chosen text that could name infrastructure. It becomes part of
an identifier, and identifiers are remapped **wholesale** in a shareable report
(ADR 0018) — so it goes with them.

That is only sufficient because of §5: since a scope reaches no subject and no
attribute, there is nowhere else for it to survive. A canary scope shaped like a
hostname is proven present in the local report and absent from the shareable one,
and separately proven absent from every subject and attribute.

**No new redaction kind and no new heuristic.**

### 9. Determinism

The same label produces the same identifier on every call. No clock, no random
source, no pointer, no process-global counter, no allocation order.

**This record does not decide how a caller derives a label.** Generic transport
must not invent `topology-1` or `broker-2`; those are service-shaped names and
belong to whoever orchestrates. This provides the primitive and nothing else.

## What this does not solve

Explicitly still open, and none of them is touched:

- **Execution dedup** — whether many advertisements naming one endpoint cause one
  measurement or several.
- **Many causes → one execution** — if a future caller does dedup, how the graph
  represents several causes truthfully. `Parent` is single on purpose so this
  record does not pre-empt it.
- **`Origin`** — deferred (ADR 0013, ADR 0031 §6).
- **Retries** — ADR 0019's other open uniqueness case. A scope could express one,
  but retry policy has no owner and this record does not give it one.
- Topology recursion, concurrency, credential forwarding, Kafka reachability,
  severity and findings.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| Scope the DNS identifier by endpoint instead of host | Less truthful, not more: a lookup for a name is the same lookup whichever port will be dialled | Never |
| Put the scope in the subject | Pollutes an observed fact with orchestration context; two measurements of one host would describe two hosts | Never |
| A hidden counter or UUID in `GraphBuilder` | Non-deterministic or order-dependent identifiers, and an allocator inside a type ADR 0013 keeps inert | Never |
| Let each probe default its own scope | Two probes in one sweep could disagree about which sweep they belong to | Never |
| Reuse the bootstrap DNS evidence for a topology sweep | Subject equality is not measurement identity: different moment, different cause | Never |
| Dedup sweeps by hostname so the second never happens | Silently drops a real measurement when one host has two advertised ports | Never |
| Emit an empty scope component when unscoped | Rewrites every identifier in the repository for no gain | Never |
| A slice of parents now | Answers the many-causes question before a consumer exists | A caller genuinely dedups execution |

## Consequences

- One run can hold two truthful measurements of one hostname, distinguished by
  execution rather than by pretending the subjects differ.
- Every existing identifier, graph, report and redaction result is unchanged;
  unscoped is the default and reproduces Phase 2 byte for byte.
- Phase 3.4 can measure an advertised endpoint whose hostname was already swept
  — including the bootstrap host — without reusing or dropping evidence.
- `dns.Lookup` and `tcp.Connect` gained a parameter, and `tls.Params` a field.
  All three are internal packages with one production caller each.
- PostgreSQL and every future service inherit the primitive unchanged: nothing
  about it names a service.

## Reopen conditions

- **A caller that deduplicates execution** — the many-causes→one-execution
  question, and with it whether `Parent` should accept several.
- **Retry policy acquiring an owner** — ADR 0019's remaining open uniqueness
  case; a scope may or may not be the right vehicle.
- **A producer with variable component arity** — the injectivity argument in §3
  must be re-derived before it ships.

## Amendment (Phase 4.9a-pre): a sweep root declares its cause

Section 6 made `Parent` optional, and that was correct when written: every sweep
was a root and there was nothing to declare.

ADR 0042 §9 removes the option at one position only. A production transport sweep's
root node must be parented — to the run's requested-target anchor when the operator
asked for it, to the service evidence that caused it otherwise. A sweep root with
no parent is a producer defect.

**What a parent edge *means* is unchanged.** It still records derivation and still
does not say a subject was discovered, user-supplied or trusted; ADR 0042 §10
explains why declaring a sweep's cause is not the provenance inference
`REPORT_SCHEMA.md` forbids. Sections 1, 5, 8 and 9 are untouched: a scope is still
not `Origin`, still reaches the identifier and nothing else, and is still
deterministic.
