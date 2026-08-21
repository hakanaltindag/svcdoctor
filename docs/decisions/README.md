# Architecture Decision Records

Every ADR here is **in force**. None has been superseded or withdrawn.

Records 0001 to 0005 and 0007 to 0010 were written before this project adopted a
`## Status` heading, which ADR 0006 introduced because the license decision needed to
move from open to accepted. Their status is recorded in the table below rather than
by editing the records, so the decisions read as they were made.

Later records refine earlier ones. A refinement narrows or implements a decision; it
does not overturn it, and both remain authoritative.

| # | Title | Status | Relationship |
|---|---|---|---|
| 0001 | Modular monolith | Accepted | |
| 0002 | Architecture separation | Accepted | Refined by 0009 for the registration boundary |
| 0003 | Evidence is a DAG | Accepted | Refined by 0013, which fixes what the graph does and does not own |
| 0004 | JSON is canonical | Accepted | Refined by 0016, which places ownership of the encoding |
| 0005 | Kafka first | Accepted | |
| 0006 | Project license is Apache-2.0 | Accepted | Supersedes its own earlier open state |
| 0007 | Layer order places protocol before authentication | Accepted | Corrects the ordering used before it |
| 0008 | Kafka wire-client strategy | Accepted | Direction only; no Kafka code exists yet |
| 0009 | Explicit composition-root service registration | Accepted | No registry exists yet; the decision binds from Phase 3, when the first adapter lands |
| 0010 | Canonical evidence excludes raw objects and uncontrolled payloads | Accepted | |
| 0011 | CLI uses service-specific subcommands | Accepted | No CLI exists yet |
| 0012 | Vantage is a first-class concept | Accepted | |
| 0013 | Evidence graph boundary | Accepted | Refines 0003. Defers `Origin` |
| 0014 | Findings reference evidence by identifier | Accepted | |
| 0015 | The report derives its summary | Accepted | |
| 0016 | The report owns canonical serialization | Accepted | Refines 0004 |
| 0017 | The diagnosis rule contract | Accepted | Defers transport severity policy and finding identity |
| 0018 | Structural redaction produces the shareable report | Accepted | |
| 0019 | Evidence identifiers are derived from the step and a scope path | Accepted | Implements the scheme 0013 left to producers. Amended in Phase 2.2, which settled encoding and scoping |
| 0020 | Generic transport probes normalize at their own boundary | Accepted | Implements 0002 and 0010 for the first real producer. Widened the `DNS_NO_ADDRESS` contract. Confirmed unchanged by the second producer |
| 0021 | A successful connection is owned, transferred and closed explicitly | Accepted | Turns the ownership requirement in 0002 and ARCHITECTURE §4 into an API contract |
| 0022 | A producer declares which attribute values carry identity | Accepted | Closes the known limit 0018 recorded, and supersedes its per-key framing |
| 0023 | The TLS probe consumes a connection, verifies an identity, and hands it on | Accepted | Applies 0020 and 0021 at L3; defers mTLS, ALPN and trust-material loading |
| 0024 | The transport chain inspects every address and chooses no continuation | Accepted | First orchestration layer; applies 0013, 0019, 0020 and 0021 together |
| 0025 | The Kafka adapter asks every transport path and keeps franz-go behind one package | Accepted | First service adapter; implements 0008. Adds the first runtime dependency |
| 0026 | Kafka SASL enters as mechanism discovery, and authentication waits for an owner | Accepted | Extends 0025 to L5. Defers authentication with four named blockers |
| 0027 | `security.Reveal` is confined to adapter wire packages, mechanically | Accepted | Closes the Phase 1 deferral its own backlog entry named. Adds no call sites |

## Decisions that govern work not yet written

Some accepted records decide how something will be built rather than describe
something that exists. That is intentional, and they are binding when that work
starts: **0008** (Kafka wire client), **0009** (service registration), **0011**
(CLI shape).

## Deferrals recorded inside ADRs

A deferral is a decision too, and each names the condition that should reopen it:

- **0013** defers `Origin` until topology orchestration exists.
- **0017** defers transport severity policy, generic/service finding overlap, and
  finding identity until real rules and real evidence exist.
- **0018** recorded an attribute-sensitivity limit that **0022 has since closed**
  for declared values. What remains is narrower: identity a producer recorded as
  a plain string, in a shape that is neither an address nor a host:port
  reference, and that appears nowhere else in the report.
- **0019** settled encoding and endpoint scoping in Phase 2.2 and still defers
  identifier scoping for **retries**, for **one endpoint discovered twice**, and
  for **two handshakes to one address under different server names**. The second
  is the `Origin` question in another form and belongs to topology.
- **0023** defers mTLS, ALPN and trust-material loading, each with the condition
  that would bring it back.
- **0024** defers retry policy, connection-selection policy and concurrent
  sweeping. Selection is not merely deferred but placed: it belongs to the layer
  that knows which protocol it is about to speak, because no transport-level
  reason distinguishes one working path from another.
- **0025** defers the generic adapter contract and the registry until a second
  adapter or a composition root exists, defers moving the Kafka attribute keys
  to a shared leaf until the first Kafka diagnosis rule needs them, and defers
  whether a transport path that failed should carry a `SKIPPED` protocol node
  until an orchestration layer knows what was requested, or a rule needs the
  distinction.
- **0026** defers Kafka authentication itself behind four named conditions:
  a layer that can select which paths receive credentials, secret source
  resolution, an owner for the credentials-over-unverified-transport policy, and
  a dependency decision for SCRAM. It also carries the L5 half of 0025's
  skipped-node question, unsolved on purpose.
- **0027** names the one condition that would widen the reveal boundary: a
  legitimate caller that cannot live in a wire package.

`docs/BACKLOG.md` tracks these alongside every other open decision.

## Convention

- One decision per record, numbered sequentially, never renumbered.
- Record what was decided, the context that forced it, and the consequences.
- Record rejected alternatives with the reason and the condition that would justify
  reconsidering them.
- A decision that turns out wrong gets a new record that supersedes the old one. Do
  not edit history until a decision appears never to have been made.
- Do not create a record for a trivial implementation choice.
