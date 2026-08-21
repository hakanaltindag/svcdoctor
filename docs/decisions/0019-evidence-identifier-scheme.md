# ADR 0019: Evidence identifiers are derived from the step and a scope path

## Status

Accepted. Amended in Phase 2.2, which was the reopen condition this record set
for its own encoding and scoping questions.

## Decision

The producer of a piece of evidence mints its identifier, and the identifier is
**derived from what the node is about**:

```text
<step>[/<component>...]
```

Components run from the widest scope to the narrowest, so identifiers for one
endpoint sort together:

```text
dns.lookup/primary.internal
tcp.connect/primary.internal:9092/10.0.0.1
tcp.connect/primary.internal:9092/2001:db8::1
```

The scheme has three properties, and each one is load-bearing:

- **Derived, not generated.** The same step and components produce the same
  identifier on every run. Nothing about it depends on a clock, a counter, a
  random source or the order in which probes executed.
- **Readable.** A local report can be read, diffed and grepped without a lookup
  table, and an identifier says what its node is.
- **Producer-owned.** `internal/domain` deliberately generates no identifiers; it
  has no clock and no random source and could not produce anything stable. The
  code that knows the shape of the run is the only code that can.

The encoding lives in `internal/probe`, which exists for exactly this: a rule that
would be wrong if two probes implemented it differently.

### Escaping, and why input is never restricted

Each component is escaped before joining: `%` becomes `%25` and `/` becomes
`%2F`. Escaping `%` first is the whole correctness argument — without it the
components `a/b` and `a%2Fb` would produce one identifier, and two facts would
silently become one node.

> **A delimiter choice must never decide what input a layer accepts.** A probe
> must not reject input a layer would otherwise accept merely because a character
> is awkward in an identifier. The encoding absorbs it instead. An identifier is
> bookkeeping, and bookkeeping does not get to narrow what svcdoctor is willing to
> diagnose.

Phase 2.1 violated that rule: the DNS probe refused a hostname containing `/`.
Phase 2.2 removed the restriction and escapes instead, which also made the DNS
probe consistent with its own documented stance of enforcing no hostname grammar.

### Nothing decodes an identifier

There is deliberately no decoder. `domain` treats an identifier as opaque, and
structural redaction replaces identifiers wholesale rather than parsing them
(ADR 0018). Escaping exists to guarantee uniqueness, not to serve a reader that
does not exist. A decoder would be a parser whose correctness nobody depends on
until the day it is wrong.

## Context

ADR 0013 and `internal/domain/evidenceid.go` left the scheme open on purpose: the
grammar is permissive about structure and strict about determinism, because the
first real producer had not been written. Phase 2.1 is that producer, so the
scheme has to exist.

Identifiers are not an internal detail. They appear in the canonical JSON, they
are what findings reference (ADR 0014), and structural redaction rewrites them
(ADR 0018). Choosing badly is expensive to undo.

## What Phase 2.2 settled, and why it took a second probe

Phase 2.1 left encoding and scoping open because a single probe could not reveal
what they had to solve. TCP revealed both immediately:

**Scoping.** One name resolves to several addresses, and each connection attempt
is its own fact. `<step>/<subject>` cannot express that — the subject of a TCP
attempt is the concrete address, and two *different* names resolving to one shared
address would then collide on a single identifier. The graph would reject the
second node, and it would be right to: the identifiers really were the same. So an
identifier needs the endpoint the attempt belongs to as well as the address it
dialed, and a single-component scheme could not carry both.

**Encoding.** Once components are joined, the join has to be unambiguous without
restricting what a component may contain. Escaping answers both.

### The scope component is not `Origin`

The endpoint in a TCP identifier is a **caller-supplied scope label**, not
recorded provenance. It says which attempt this is, so that two attempts stay two
nodes; it does not say how the endpoint entered the run, and nothing reads it back.

`Origin` remains deferred (ADR 0013). It is a claim on the node about the shape of
the run, which is a different thing from a bookkeeping component in an opaque
string, and topology is still what will make it concrete. Phase 2.2 deliberately
did not resolve it.

## Uniqueness, and what it still does not solve

One identifier means one node per `(step, components)` per run, and `GraphBuilder`
rejects a duplicate outright rather than merging.

Three cases remain open, and each belongs to the phase that produces it:

- **Retries.** Two attempts on the same endpoint and address in one run would
  collide. Retry policy is execution policy and does not exist yet.
- **Topology.** One endpoint discovered twice by different paths may be two facts.
  That is the `Origin` question, deferred by ADR 0013 until topology orchestration
  exists.
- **Server names.** Phase 2.3 added a layer whose attempt depends on a third
  input: two TLS handshakes to one address under different server names are two
  facts, and today they would collide. No caller does it — the chain performs one
  handshake per endpoint — so the component is not added on speculation.

None is invented now, because a scope shape designed for a caller that does not
exist would be a guess. `GraphBuilder` failing loudly on a duplicate is the correct
interim behaviour: it surfaces the question at the moment something first needs it.

## Redaction

The identifier grammar admits hostnames, and this scheme puts one in every
identifier. That is not a leak, because ADR 0018 rewrites every identifier to
`evidence-NNN` and remaps every reference to it. The readable form is a local
convenience; a shareable report keeps only the correlation.

The interaction is worth stating explicitly because it runs the other way to
intuition: a *less* readable identifier would not make a shareable report safer,
and would make a local one harder to work with.

## Rejected alternatives

| Rejected | Why | Reconsider when |
|---|---|---|
| UUIDs | Nondeterministic. Two runs of the same checks would produce different reports, so nothing could be diffed, and the domain has no random source by design | Never for this purpose; a genuinely opaque identity requirement would be a different problem |
| A hash of the step and subject | Costs readability and buys nothing. It hides an identifier that redaction already removes, and a local report is where the readable form earns its keep | A subject can be too long or too structured to embed directly |
| A sequence counter | Depends on execution order, which becomes nondeterministic as soon as endpoints are probed concurrently. The canonical report must be byte-stable for the same facts | Never; ordering must not reach identity |
| Subject alone, without the step | Collides immediately: DNS, TCP and TLS all describe the same endpoint | — |
| Caller-supplied identifiers | Every caller would invent its own grammar, and no two probes would agree. The producer knows the step and the components; that is the whole input | A caller has scope information the probe cannot know — the deferred topology case above |
| Rejecting input that is awkward to encode | Phase 2.1 did this and it was wrong: bookkeeping narrowed what svcdoctor would look at. Escaping costs a dozen lines and removes the constraint entirely | Never |
| A decoder for identifiers | Nothing reads them back. Redaction replaces them wholesale and the domain treats them as opaque, so a parser would exist only to rot | A consumer genuinely needs to recover components — and even then, carrying the parts separately would beat parsing a string |
| Percent-encoding every reserved URL character | Only two characters need escaping to keep the join injective. Encoding more would make identifiers harder to read for no additional guarantee | — |

## Consequences

- Two runs against an unchanged environment produce byte-identical identifiers,
  so reports diff cleanly.
- A probe needs no identifier service, no counter and no injected generator.
- The same `(step, components)` cannot be recorded twice in one graph, which
  surfaces the retry and topology scoping questions as loud failures rather than
  silent overwrites.
- Every later probe uses `probe.EvidenceID`, so identifiers stay predictable
  across layers without a registry and without a second copy of the encoding.
- A probe may accept any input its layer accepts. The identifier absorbs it.
