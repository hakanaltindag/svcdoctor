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
- **0018** records the attribute-sensitivity limit, which is tied to the open
  question of where service attribute keys live.

`docs/BACKLOG.md` tracks these alongside every other open decision.

## Convention

- One decision per record, numbered sequentially, never renumbered.
- Record what was decided, the context that forced it, and the consequences.
- Record rejected alternatives with the reason and the condition that would justify
  reconsidering them.
- A decision that turns out wrong gets a new record that supersedes the old one. Do
  not edit history until a decision appears never to have been made.
- Do not create a record for a trivial implementation choice.
