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
| 0028 | Credentialed authentication is singular, policy-gated and channel-aware | Accepted | Answers 0026 §7.1 and §7.3, narrows §7.2. Decides work not yet written |
| 0029 | A connection carries what it proved, and a fail-closed policy reads it | Accepted | Implements 0028 §6. Sends no credential; changes no report schema |
| 0030 | PLAIN authentication, and the ordering that governs every credential byte | Accepted | Implements 0028 over 0029's mechanisms, inside 0027's boundary. **The first phase that transmits a credential.** Supplies the blocker carrier 0028 §3 assumed |
| 0031 | Metadata discovers a topology, records it, and probes none of it | Accepted | First topology discovery. Answers the `Origin` reopen condition of 0013 and the topology-uniqueness case of 0019 |
| 0032 | A sweep names an execution, so one run can measure a host twice | Accepted | Resolves the *Topology* uniqueness case 0019 left open. Adds a generic primitive; unblocks Phase 3.4 |
| 0033 | An advertised endpoint is measured once per advertisement, and only at L1-L3 | Accepted | The consumer 0031 was built to feed and the first caller of 0032. Answers the execution-dedup question by deliberately not deduplicating |
| 0034 | A Kafka rule owns advertised-endpoint reachability, anchored at the advertisement | Accepted (policy), implemented in Phase 3.6 | Revisits the two questions 0017 deferred and answers them for service-anchored rules. Authorizes one finding code and fixes every field of it; `internal/diagnosis/kafka` implements it and invents nothing |
| 0035 | An unusable broker advertisement is its own claim, and it is not vantage-dependent | Accepted | Takes the case 0034 §14 placed out of scope. First finding with `vantageDependent: false`; the redaction defect it surfaced was fixed generically in Phase 3.7.5 |

## Decisions that govern work not yet written

Some accepted records decide how something will be built rather than describe
something that exists. That is intentional, and they are binding when that work
starts: **0008** (Kafka wire client), **0009** (service registration), **0011**
(CLI shape).

**0028 has left this list.** It decided credentialed authentication before any
existed; 0029 built the mechanisms it required and 0030 implemented it, so it now
describes code. Its selection rule, endpoint authority and ownership table remain
binding on every mechanism added after PLAIN.

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
- **0026** deferred Kafka authentication behind four conditions. **0028 answered
  two and narrowed a third**: selection is fixed by a singular signature, the
  transport-safety question by a fail-closed declared policy, and the
  secret-source argument turned out to be a Phase 5 usability item rather than a
  Phase 3 blocker. What remains from 0026 is the SCRAM dependency route, and the
  L5 half of 0025's skipped-node question, unsolved on purpose.
- **0027** names the one condition that would widen the reveal boundary: a
  legitimate caller that cannot live in a wire package.
- **0028** defers nothing of its own, but it is binding on work not yet written:
  authentication may not be implemented until the channel fact and the
  credential-transport policy of its section 6 exist. **0029 built both.**
- **0029** defers the unsafe transport override and the `ReportSecurity` field
  that would record it, under one shared condition: a layer that can carry an
  explicit per-run decision. Neither is useful without the other, so they arrive
  together or not at all.
- **0032** closes the *Topology* case ADR 0019 listed as unsolved, in the layer
  that owns identifiers rather than in an adapter. It leaves 0019's other two
  open cases untouched — retries still have no owner, and no caller performs two
  TLS handshakes to one address under different server names — and it
  deliberately does not answer the many-causes→one-execution question, keeping
  its derivation parent singular so that a future phase decides that on its
  merits.
- **0031** answers 0019's topology-uniqueness case — one broker seen by two
  responses is two observations, never one merged claim — and **leaves `Origin`
  deferred** after examining it against a real implementation. The distinction it
  draws is the one `REPORT_SCHEMA.md` insists on: a parent edge records
  *derivation* and not *provenance*, and discovery needed only the former. It
  records two limitations rather than solving them: Metadata is reachable only
  from an authenticated session, which is svcdoctor's scope and not Kafka's
  protocol, and a second exchange over one path collides, which is 0019's retry
  case arriving.
- **0033** answers one open question and re-defers three. It decides that
  execution deduplication does **not** arrive with reachability, because the graph
  has no truthful many-causes→one-execution representation and a deduplicated
  sweep could only be recorded by dropping a cause; that is its own reopen
  condition. It leaves credential forwarding, `Origin` and transport severity
  exactly as deferred as they were, and states explicitly that producing the
  evidence a severity rule needs does not settle what the rule should say.
- **0030** defers nothing that blocks work, and names five conditions that would
  extend it: a multi-round-trip mechanism, a distinct authorization identity, an
  identity-bearing attribute kind for principals, a layer that can choose a
  transport policy, and a node that positively records "no TLS was attempted".
  The last is the one that would give a plaintext policy refusal a truthful
  blocker; today it correctly has none.

- **0035** takes the one case 0034 explicitly deferred and is deliberately small: the
  structural work — anchoring, the ownership test, per-subject severity, the leaf
  vocabulary package — all existed already, so policy and rule land together. Its
  substance is three things 0034's reasoning does *not* transfer to. **Vantage
  dependence is false**, because the defect is in the values that arrived rather
  than in the path to them, and copying `true` would have invited a retry that
  cannot help. **The claim stops short of a cause**: Metadata says what a broker
  reports, never how it arrived at it, so `advertised.listeners` is never named.
  And the two Kafka findings are shown to be **mutually exclusive by
  construction** rather than merely different, on the graph where the two
  mechanisms that enforce it come apart. It also records a redaction defect it
  surfaced and did not cause, and declines to fix it in a diagnosis phase.

- **0034** is a policy record: it decides what may be concluded from 0033's
  evidence and implements nothing itself; Phase 3.6 implements it exactly. It closes the generic-versus-service overlap
  **for advertised endpoints** by giving the Kafka rule exclusive ownership, and
  it settles severity by reading it as per-subject impact under an anchor. Its
  central move is that **ADR 0017's severity blocker dissolves for a rule
  anchored at a service fact and still stands for an unanchored generic one** —
  which is why it authorizes a Kafka rule and declines to authorize a generic
  transport rule. It leaves partial multi-address reachability, cluster-level
  aggregates, controller-aware severity and the bootstrap path's owner open, each
  with the missing fact named. `Origin` is examined for the third time and stays
  deferred, unchanged.

`docs/BACKLOG.md` tracks these alongside every other open decision.

## Convention

- One decision per record, numbered sequentially, never renumbered.
- Record what was decided, the context that forced it, and the consequences.
- Record rejected alternatives with the reason and the condition that would justify
  reconsidering them.
- A decision that turns out wrong gets a new record that supersedes the old one. Do
  not edit history until a decision appears never to have been made.
- Do not create a record for a trivial implementation choice.
