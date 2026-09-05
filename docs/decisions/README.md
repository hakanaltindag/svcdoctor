# Architecture Decision Records

Every ADR here is **in force**, and none has been withdrawn.

Three have been **superseded in part**, each by a later record that argues the reversal rather
than editing history: 0011 on command-tree shape (by 0041), one bullet of 0040 (by 0044), and
0056 §7's numeric SCRAM bounds and refusal semantics (by 0061). In every case the rest of the
superseded record still binds, and the original text is left as written.

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
| 0017 | The diagnosis rule contract | Accepted | Deferred transport severity policy and finding identity. 0042 supplied the missing context and 0043 **closed the deferral for DNS and TCP**, implemented in Phase 4.9b. It stands for generic TLS, which has no producer |
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
| 0029 | A connection carries what it proved, and a fail-closed policy reads it | Accepted, **amended in Phase 4.2** | Implements 0028 §6. Sends no credential; changes no report schema |
| 0030 | PLAIN authentication, and the ordering that governs every credential byte | Accepted | Implements 0028 over 0029's mechanisms, inside 0027's boundary. **The first phase that transmits a credential.** Supplies the blocker carrier 0028 §3 assumed |
| 0031 | Metadata discovers a topology, records it, and probes none of it | Accepted | First topology discovery. Answers the `Origin` reopen condition of 0013 and the topology-uniqueness case of 0019 |
| 0032 | A sweep names an execution, so one run can measure a host twice | Accepted | Resolves the *Topology* uniqueness case 0019 left open. Adds a generic primitive; unblocks Phase 3.4. Amended by 0042 §9: a sweep root's `Parent` stops being optional |
| 0033 | An advertised endpoint is measured once per advertisement, and only at L1-L3 | Accepted | The consumer 0031 was built to feed and the first caller of 0032. Answers the execution-dedup question by deliberately not deduplicating |
| 0034 | A Kafka rule owns advertised-endpoint reachability, anchored at the advertisement | Accepted (policy), implemented in Phase 3.6 | Revisits the two questions 0017 deferred and answers them for service-anchored rules. Authorizes one finding code and fixes every field of it; `internal/diagnosis/kafka` implements it and invents nothing |
| 0035 | An unusable broker advertisement is its own claim, and it is not vantage-dependent | Accepted | Takes the case 0034 §14 placed out of scope. First finding with `vantageDependent: false`; the redaction defect it surfaced was fixed generically in Phase 3.7.5 |
| 0036 | A PostgreSQL session is one connection, and it is usable only at ReadyForQuery | Accepted (policy), implemented from Phase 4.3, **§4 amended by measurement** | First PostgreSQL record. Applies 0020, 0021 and 0024 to a protocol that negotiates TLS in-band; narrows 0029's channel authority; supplies the blocker carrier 0030 named; depends on 0037 |
| 0037 | A principal or named resource is identity, and redaction must pseudonymize it | Accepted, **implemented in Phase 4.1** | Refines 0022 with a second identity category. Meets a reopen condition 0030 recorded. First report schema field added since v1 |
| 0038 | PostgreSQL SCRAM-SHA-256, and the two facts that must both be true before authentication passes | **Accepted, implemented in Phase 4.4b**, §8 and §21 amended by implementation | Applies 0028's contract, 0029's mechanisms and 0030's ordering to a second protocol and adds no policy. Fixes the success boundary at *signature verified* **and** *AuthenticationOk*, both measured. Narrows scope to printable-ASCII passwords rather than adding a SASLprep dependency |
| 0039 | A PostgreSQL session is established at ReadyForQuery, and that proves less than it looks like | **Accepted, implemented in Phase 4.5b**, §2 and §15 amended by implementation | Completes the slice 0036 designed. Confirms the ReadyForQuery boundary and **corrects 0036 §5** — `57P03` is pre-auth. Adds `RESOURCE_NOT_FOUND`, which 0036 §16 authorized and 4.3 deferred; declines a capacity class |
| 0040 | A PostgreSQL rule anchors only at a `postgres.*` step | Accepted (policy), implemented in Phase 4.6b, **one bullet superseded by 0044** | The 0034 analogue for PostgreSQL. Authorizes the service vocabulary leaf 0042 §11 reuses generically. Its refusal of `POSTGRES_TLS_*` findings is reversed by 0044; the twelve findings it fixed are untouched |
| 0041 | A run discovers broadly and authenticates narrowly | **Accepted, implemented in Phase 4.8b** | First record about the application. Closes the selection deferral 0028 left open; partially supersedes 0011 on command-tree shape. Narrowed by 0042 §3, which opens one hole in its evidence-authority ban |
| 0042 | A run records the target it was asked about, and a sweep declares its cause | **Accepted, implemented in Phase 4.9a-pre** | Closes the ownership and subject gaps Phase 4.9a stopped on. Narrows 0041, half-closes 0017's deferral, amends 0032 at the sweep root, and leaves 0034's advertised ownership structurally unreachable. Authorizes no finding |
| 0043 | svcdoctor says what it could not reach, and no more than that | **Accepted, implemented in Phase 4.9b** | Closes 0017's generic transport deferral **for DNS and TCP only**. Consumes 0042 as its ownership prerequisite; leaves 0034, 0040 and 0041 unchanged. Defers generic TLS for want of a producer, and records PostgreSQL's in-band TLS gap without fixing it |
| 0044 | A handshake belongs to whoever asked for it | **Accepted, implemented in Phase 4.9d** | Gives PostgreSQL the in-band `tls.handshake` node, read from the parent edge the negotiation already recorded. **Supersedes one bullet of 0040** — the refusal of `POSTGRES_TLS_*` findings — and argues the reversal. 0041, 0042 and 0043 unchanged; generic TLS still deferred |
| 0045 | The negotiation gets a floor, so a wrong port stops reading as healthy | **Accepted, implemented in Phase 4.11b** | Closes two of the three shapes 0040 recorded as an SSLRequest gap, and gives that step the floor the other three PostgreSQL steps already had. Disjoint from `POSTGRES_TLS_DECLINED` by class and from 0044 by state. The no-credential blocker is **not** decided here |
| 0046 | A run that could not start says so, and the graph proves which run it was | **Accepted, implemented in Phase 4.11b** | Closes the no-credential gap 0041 recorded. Adds one generic `FailureClass`, because absence could not be distinguished from a run cancelled at the same point. Distinct from 0030's policy skip; 0040's twelve findings and 0044 unchanged |

## Decisions that govern work not yet written

Some accepted records decide how something will be built rather than describe
something that exists. That is intentional, and they are binding when that work
starts: **0008** (Kafka wire client), **0009** (service registration), **0011**
(CLI shape).

**0063 to 0066 have left this list.** Phase 7.4 froze the Redis/Valkey BASIC
contract before any Redis code exists, so all four decide work not yet written and all four bind
from Phase 7.5: **0063** (the BASIC journey, the three-command allowlist, RESP2-only, and what
`PING` is allowed to prove), **0064** (zero-argument `HELLO`, one credential-bearing command per
run, and the unchanged plaintext policy), **0065** (cluster observed and not traversed, Sentinel
detected and not diagnosed), **0066** (prefix-only error classification, observed implementation
identity, one adapter and one CLI command). Between them they add three `Step` values and nothing
else: no finding code, no failure class, no `SchemaVersion` change and no dependency.

**0067 to 0070 have also left this list.** Phase 8.1 froze the RabbitMQ BASIC contract before any
RabbitMQ code existed, and Phase 8.2 implemented it: **0067** (AMQP 0-9-1 only, one direct endpoint, the five-method allowlist,
three service nodes, `Connection.Open-Ok` as the terminal boundary and the graceful close
epilogue), **0068** (PLAIN only, the mandatory `authentication_failure_close` capability, one
credential-bearing frame, endpoint-scoped authority and the unchanged verified-TLS-only policy),
**0069** (authentication and vhost authorization as separate stages, and construct-and-compare
normalization of a `Connection.Close` with truncation short-circuiting first), **0070** (the Tune
values, the silent-close correction, and one frame ceiling in place of eight constants). They add
three `Step` values and eleven RabbitMQ finding codes when implemented, and **one** generic
`FailureClass` — `RESOURCE_LIMIT_REACHED` — which 0069 §6 authorizes and Phase 8.1 implemented
immediately, because PostgreSQL SQLSTATE `53300` migrated onto it in the same change-set. No
`SchemaVersion` change and no dependency. The contract is measured rather than reasoned:
`docs/validation/RABBITMQ_PHASE80_CONTRACT_STUDY.md` records what was run and against which
brokers, and 0067 §4.1 and 0070 §3 record a Phase 8.0A prediction the measurements falsified.

**0078 to 0083 are the current occupants of this list.** Phase 10.0 froze the diagnostic
intelligence architecture before any of it is written, and all six bind from Phase 10.1:
**0078** (five concepts kept distinct, a hypothesis represented as a `Finding` with
`kind: HYPOTHESIS` rather than a new type, the epistemic rules a claim must pass, and diagnosis
staying a pure function of frozen evidence), **0079** (the failure boundary as a derived
diagnostic property computed in the diagnosis layer, per subject, expressed as one generic
finding, with "ruled out" left to presentation), **0080** (service-owned imperative rules over a
generic engine, a `RuleContext` of graph, vantage and one boolean, purity enforced by the build,
and explicit composition-root registration), **0081** (semantic identity as `(Code, Subject)`,
convergence merging without confidence accumulation, the confidence ladder, four distinct
evidence relations, and peer-controlled text kept out of prose), **0082** (two recommendation
kinds in one type, seven safety classes of which three are unreachable, and the confidence gate
on remediation), **0083** (additive schema evolution at version 1, the false-positive policy,
fail-closed handling of a defective rule, and the six-level validation pyramid with a golden
corpus whose *forbidden* claims are first-class expectations).

They add **nothing** to the frozen counts in 10.0: `SchemaVersion` stays 1, `RunSchemaVersion`
stays 1, finding codes stay 60, failure classes stay 42, `Reveal` and `SecretFor` stay at 4 each,
and the module count stays 2. They authorize exactly two report-visible changes in Phase 10.1 and
nowhere else — one generic finding code, `DIAG_FAILURE_BOUNDARY` (60 → 61), and three additive
fields inside the existing `recommendations[]` object, which `domain.Recommendation` was made an
object in order to accommodate. No new command, no new credential source, no configuration
change and no dependency: the design explicitly refuses an LLM, a remote API, embeddings and any
opaque classifier. The architecture is written out in `docs/design/DIAGNOSTIC_INTELLIGENCE.md`
and every load-bearing contract is traced in
`docs/validation/PHASE100_DIAGNOSTIC_TRACEABILITY.md`.

**0084 is the first service record built on them, and it is Kafka's.** Phase 10.2 turned the
reasoning model into two topology-scoped Kafka claims and, in the process, discovered that most
of what a reader would expect it to build already existed: thirteen Kafka codes cover every
*per-endpoint* claim the evidence supports, so no per-endpoint rule was added and five of the
phase's nine candidate categories were discarded as already built. What was missing was one
level up — **completeness** and **contrast**, neither recoverable from a conjunction of
per-endpoint findings, and neither expressible before `RuleContext` and the confidence ladder
existed. 0084 therefore reopens **0034 §10** on the condition that record named for itself, and
upholds everything else it refused: `KAFKA_CLUSTER_UNHEALTHY`, `KAFKA_BROKER_DOWN`,
`KAFKA_NETWORK_BROKEN`, controller and KRaft inference, partition and replication claims, a
per-endpoint suitability hypothesis — contradicted by its own premise whenever a peer is
reachable — and address-shape heuristics, because a broker on the same host as the client is a
correct deployment. Finding codes move 61 → **63**, both `KAFKA_`; the observation is `INFO`
because severity is never a count-derived cluster verdict, and the hypothesis cannot reach
`HIGH` because it declares `AuthorityNone` and the ladder admits `HIGH` on nothing else.

**0085 is the second service record, and it is PostgreSQL's — but its most interesting decision
is the one it declines to make.** Phase 10.3 asked svcdoctor to distinguish authoritative server
observations from inferred causes and from violated intent, and PostgreSQL is the exemplar
because the server frequently states *what* happened in a field its own protocol defines while
saying nothing about *why*. As with 0084, most of the candidates were already built: of the
seven domains the phase weighed, five existed — `POSTGRES_CONNECTION_NOT_PERMITTED` already owns
`pg_hba` admission, `DIAG_FAILURE_BOUNDARY` already owns transport-succeeded-then-server-refused,
and the credential-rejection, credential-withheld and TLS claims were all in place. Two were
built: **`POSTGRES_ADMISSION_SCOPE`**, the completeness-and-contrast aggregate over the addresses
one target resolved to, `INFO` for the same reason 0084's is; and
**`POSTGRES_CONNECTION_LIMIT_REACHED`**, which reopens **0040 §17** on the condition that section
stated for itself — it declined the finding "for the same reason" 0039 §10 declined a capacity
class, and Phase 8.1 satisfied that condition and added `RESOURCE_LIMIT_REACHED`. Codes move
63 → **65**, both `POSTGRES_`.

The third addition is **not a finding, deliberately**. `in_hot_standby` tracked
`pg_is_in_recovery()` exactly against a real Patroni cluster, which makes it authoritative about
*what the endpoint said* and about nothing else — a pooler forwards a cached value, and without
declared intent a standby is not a fault (0083 §2.6). 0040 §20 named three reopen conditions and
**none has fired**, so it becomes a terminal observation line in the mechanism
`internal/render/terminal` already built for exactly this and whose doc comment already named
"what replication role it holds". The finding layer refuses and the presentation layer shows the
fact. Role *mismatch* is deferred with `ROLE_INTENT_NOT_AVAILABLE` and nothing is smuggled
through a rule, a detail or a subject. And multi-endpoint role contrast is **unreachable rather
than forbidden**: a PostgreSQL run continues exactly one path (0041), so split brain, dual
primary and one-address-refused-while-its-sibling-accepts are graphs no producer makes — which is
guarded structurally, by reading the composition root, rather than by forbidding a word.

**0086 is the next-best-evidence record, and most of what it does is refuse to build things.**
Phase 10.4A set out to design an engine that selects the observation which would best separate
surviving hypotheses, and the first thing it did was count producers. Two finding codes in the
whole tree are ever a `HYPOTHESIS`, both Kafka; `BasisBuilder.Miss` — the relation whose own doc
comment calls it *"the input to a next-evidence recommendation"* — has **no producer at all**;
and **no pair of competing hypotheses exists anywhere**, because everywhere one would arise
(a TCP timeout, `53300`, a pooler's `08P01`) 0083 §2.2's false-positive policy has already
resolved it into one narrow `CONFIRMED` claim instead. So a set-selection engine would have been
built over an empty input, which is the shape 0054 refuses under *owner before producer*.

What it found instead is a real gap on the **output** side: both service packages construct a
fully classified, fully guarded `diagnosis.Advice` and then discard its `kind`, `safety`,
`rationale` and `selfCollectable`, because `domain.Recommendation` still holds `action` alone.
**Those four facts are next-best evidence**, and without them a report cannot say that a
suggestion is an observation rather than a change. 0082 §2.1 decided that addition in Phase 10.0
and nothing implemented it; 0086 makes it the substance of 10.4B, corrects 0083 §2.1's field
count from three to **four**, and owes the guard 0082 §2.5 asked for *"once Phase 10.1 lands"*.

**The record's own first cut had to be corrected, and the correction is the interesting part.**
It froze a runtime identity for an indistinguishable set — same subject, different code,
byte-identical discriminator — and planned the grouping function into the next phase, while the
same record established there is nothing to group. Both halves are withdrawn. §2.0 now splits the
record explicitly: **semantics are frozen, mechanism is deferred.** Frozen are what
next-best evidence means, the seven epistemic positions and six forbidden collapses, the
necessary conditions for indistinguishability, safety and reporting semantics, `Advice` →
`Recommendation` preservation, the discriminator ↔ `NEXT_EVIDENCE` requirement, the no-ranking
policy, the report-only iterative boundary, and the constraints binding any future set
implementation. Deferred are the set data structure, the derivation, the identity mechanism, the
grouping order and the renderer behaviour.

**Byte equality survives as the minimum safe candidate, not as a rule**, and the reason is
§2.2a: `Discriminator` is human-facing prose, so freezing it as a grouping *key* would let a
wording-only edit change diagnostic behaviour — the coupling Phase 10.2A spent a phase removing
when it found prose deciding convergence through a `RuleID` tie-break. ADR 0081 §2.2b's answer
there was to make prose a **precondition that refuses** rather than a **key that selects**, and
the same distinction applies here. Fuzzy matching stays forbidden permanently; the later choice
is between exact equality, a typed key, and deriving identity from the missing `domain.Step` a
rule already records — decided against a real pair, not in the abstract, and `DiscriminatorID`
is deliberately not added now.

There is no ranking at any tier; information gain is permitted only as a cardinality that may be
shown and may never order anything; and a typed "svcdoctor could observe this with a credential
it lacks" category is refused permanently as a privilege-escalation prompt inside a shareable
document. Iterative diagnosis stays deferred to its own ADR, with the five things it would have
to add written down. `SchemaVersion` stays **1** — authority quoted from `docs/REPORT_SCHEMA.md`
§1 and 0083 §2.1 rather than inferred from additivity — and no finding code is added, because a
set is a view over findings and not a claim of its own. The plan is three phases: **10.4A**
freezes, **10.4B** plumbs and is forbidden to build a set engine, **10.4C** opens only when a
service phase produces a genuine competing pair.

**0081 was amended a second time, and the second amendment is a supersession.** Phase 10.1B's
§2.2a filled a silence — the table said nothing about `Layer`, and measurement showed a
tie-break publishing an L5 claim over an L4 node. Phase 10.2A's **§2.2b** is different in kind:
§2.2 had said *explicitly* that `Summary` and `Detail` come from the tie-break winner, and that
row is now withdrawn. What forced it was three reachable Kafka shapes in which the engine chose
between two true sentences and published one of them over both routes' evidence — including one
that promoted a hypothesis about an unmeasured broker into a confirmed claim. The premise the
original row rested on was that a finding's prose says nothing its structured fields do not, and
Phase 10.2's rules — which name a broker node identifier in prose under a subject carrying only
the endpoint — falsify it. Prose is now a merge **precondition**, compared byte for byte and
never fuzzily; **§2.6a** adds the rename property that follows, and the superseded paragraphs are
left standing with markers so the reasoning that was wrong stays legible.

**0071 to 0074 have left this list.** Phase 9.0 froze the multi-target
configuration and execution contract before any multi-target code exists, and all four bind from
Phase 9.1, which implemented all four: **0071** (one strict YAML document, its own `version: 1`, a required and explicit target
`id`, an envelope with a service-owned `config` node, and the parsing bounds), **0072** (`env` and
`file` credential references, a plaintext secret refused by the decoder's type, preflight without
retention followed by per-target resolution, and no secret cache), **0073** (independent targets, a
bounded worker pool at 4 with a ceiling of 16, three nested budgets, declared configuration order,
and no run-level finding), **0074** (a separate aggregate document with its own schema version, four
execution states orthogonal to the evidence states, the unchanged exit-code contract, and
`svcdoctor run --config`).

Between them they add **nothing** to the frozen counts: `SchemaVersion` stays 1, finding codes stay
60, failure classes stay 42, and the `Reveal` and `SecretFor` call sites stay at 4 each. They
authorize **one new dependency** in Phase 9.1 — `go.yaml.in/yaml/v3`, which has none of its own —
taking the module count from 1 to 2, which is the decision `test/security/dependency_test.go` exists
to force someone to record. The contract is measured rather than reasoned:
`docs/validation/MULTI_TARGET_PHASE90_CONTRACT_STUDY.md` records the YAML strictness experiments, the
report-size measurements every resource bound is derived from, and the two hazards those experiments
found that the design would otherwise have missed — a merge key is not refused by refusing aliases,
and a plaintext password is refused by the type system rather than by a check.

**0075 to 0077 have left this list.** Phase 9.2B implemented them, so they now describe code and shipped documents rather than a plan. What they decided is unchanged and is summarized below; where implementation corrected a detail, the correction is recorded inside the ADR rather than smoothed away.

**They were the newest occupants of it.** Phase 9.2A audited svcdoctor as an
external Senior SRE meets it — README, `--help`, real invocations, real output, real errors — and
froze the release and user-experience contract before Phase 9.2B changes anything: **0075** (the
command surface frozen as it stands, one canonical mental model for `diagnose` versus `run`, seven
elements in every help surface, six public documents each with one owner, one canonical example
configuration plus two focused ones, and three mechanisms that prevent documentation drift),
**0076** (version identification unchanged because `run.svcdoctorVersion` already exists in both
schemas, five binary artifact platforms with checksums, the macOS pure-Go resolver limitation
documented rather than engineered away, a required root `SECURITY.md`, the two supply-chain gaps
closed, and `v0.4.0` as the next release), **0077** (the five exit codes frozen with `docs/CI.md` as
their authority, three documented CI policies built only from existing codes, the artifact rule that
survives `| tee` and `|| true`, the single-target completeness asymmetry documented rather than
fixed, configuration errors returned to exit 2 where ADR 0074 §9 already put them, a shareable
aggregate that fails closed, and the exact wording the shareable guarantee may and may not use).

They added **nothing** to the frozen counts: `SchemaVersion` stayed 1, `RunSchemaVersion` stayed 1,
finding codes stayed 60, failure classes stayed 42, `Reveal` and `SecretFor` stayed at 4 each, and
the module count stayed 2. They authorized **no** new dependency, **no** new command, **no** new
flag and **no** schema field, and Phase 9.2B added none of those.

Two of their decisions were weakened by measurement rather than by choice, and both are recorded
in `docs/validation/PHASE92B_UX_TRACEABILITY.md` rather than quietly restated: 0076 §2.6's
SHA-pinning requirement is met for two of three actions, because no verified digest for the third
existed anywhere this phase could check — and writing an unverified one is the defect a pin exists
to prevent. And 0075's terminal work stops at the blockers: the 100-column bound the audit froze
as UX-19 is **not met**, is held instead as a regression bound at the measured 277 columns, and
the wrapping that would meet it is deferred as UX-S09. Three of the four release blockers they respond to are defects against
contracts this project already holds — the ADR 0018 redaction policy, ADR 0074 §9's
validate-before-dial requirement, and the honest-documentation rule — so closing them restores those
contracts rather than reopening Phase 9. What was measured, and the commands that measured it, is in
`docs/validation/PHASE92A_RELEASE_UX_AUDIT.md`.

**0039 has left this list.** Phase 4.5b implemented it, so it now describes code. Two of its
sections were settled by that implementation and the settlements are recorded inside it.

**0038 has left this list.** It decided PostgreSQL authentication before any existed;
Phase 4.4b implemented it, so it now describes code. Two of its sections were corrected by
that implementation and the corrections are recorded inside it rather than smoothed away.

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

- **0036** defers every PostgreSQL *finding* to a later diagnosis-policy record, on the
  0033 → 0034 pattern: it produces evidence and authorizes no claim. It re-examines the
  bootstrap-path transport finding 0034 §14 left open and **declines to close it**, so
  PostgreSQL does not reopen the generic-transport severity question either. It defers the
  unsafe transport override to the same owner 0029 named, and records that this leaves
  plaintext password authentication undiagnosable beyond L4 — the largest practical
  limitation of the first slice. It declines to create a generic STARTTLS abstraction for
  one caller, naming a second in-band negotiation as the condition that would justify one.
  Its central empirical result is that **`AuthenticationOk` is not success**: two common
  failures arrive after it and before `ReadyForQuery`, measured rather than reasoned.

- **0037** closes the gap 0022 could not reach. 0022 taught redaction to carry identity
  that names a *network peer*; a role name and a database name are identity of a different
  category, and the model had no honest way to hold either — `HostAttr` would have been
  false and would have rendered a database as `host-002`. It adds exactly one kind rather
  than two, because the attribute key already distinguishes a role from a database and
  survives redaction. It leaves two things unsolved and says so: identity embedded in a
  connection string, which belongs to L0 normalization, and identity arriving only inside a
  peer's own prose, which 0036 §6 answers by refusing to store server prose at all.

- **0038** is the second record in this repository written *before* the code it governs,
  for the reason 0028 was: the phase it describes transmits a credential. It decides nothing
  new about policy — the ordering, the endpoint authority, the reveal boundary and the
  ownership rules are 0027, 0028, 0029 and 0030 unchanged — and everything it *does* decide
  is protocol. Two of its results were falsifying. `AuthenticationSASLFinal` verifying is not
  success, measured through a pooler that follows it with an error and no `AuthenticationOk`;
  and PostgreSQL applies SASLprep to passwords, measured on 14.24 and 18.6, so a client that
  skips it reports a *correct* password as rejected. The second forced the only scope
  narrowing in the record: printable-ASCII passwords are handled and everything else is
  refused as a gap in svcdoctor, because that failure mode is visible and a disagreeing
  second SASLprep implementation's is not.

- **0039** finishes the PostgreSQL slice and spends most of its length narrowing a claim
  rather than making one. `ReadyForQuery` is confirmed as the boundary, with the three
  post-authentication failures 0036 predicted all reproduced — and one of its predictions
  corrected: `57P03` arrives *before* authentication, from `BackendInitialize`, so it is a
  startup fact and not a session one. The decisive measurement is elsewhere. With its
  PostgreSQL backend **stopped**, pgBouncer served a complete passing session from cache —
  fifteen parameters, a fabricated backend key, `ReadyForQuery`. So the boundary proves that
  a PostgreSQL-protocol session was established at an endpoint, and nothing about what is
  behind it. Eleven of the fifteen `ParameterStatus` values are dropped, two of them because
  they are identity; `BackendKeyData` is read for its length and discarded whole, secret and
  process ID alike.

- **0040** is the 0034 analogue for PostgreSQL, and it spends its length deciding what
  svcdoctor may *not* say. Its primary invariant is that diagnosis names a root cause only
  when the evidence contract uniquely supports it, and otherwise names the observed failure
  boundary — the triple *(step, state, failure class)* a producer committed to. The fact
  that forces it is a pooler: pgBouncer emits `08P01` for at least six unrelated conditions
  and moves three of them to an earlier protocol step, so a missing database is a
  `postgres.session` fact directly and a `postgres.startup` fact behind a proxy. Twelve
  finding codes are authorized, each with a must-not-claim list; none is a `HYPOTHESIS`,
  because every claim is about something observed. Its own falsifying result is that
  `AUTH_CREDENTIALS_REJECTED` points two ways — one producer is svcdoctor refusing the
  *peer's* server signature — and the graph cannot separate the directions, so the finding
  over that case is worded to be true whichever party refused. Six candidate findings are
  refused by name, and a PostgreSQL run that fails at DNS, TCP or TLS produces no finding at
  all, which the record states rather than hides. It was then **revised by an adversarial
  review before a single rule existed**, which is the cheapest such revision will ever be: the
  two mechanism codes had been split on whose gap it is, a boundary that moves with
  svcdoctor's own capability rather than with the target; the L4 floor's code claimed the peer
  *rejected* something its own trigger disproves; and six `vantageDependent` values asserted a
  position-independence that `pg_hba` source matching disproves. The code count survived; the
  code set did not. It is now **implemented**: `internal/diagnosis/postgres` holds four rules,
  one per anchor step, and `internal/service/postgres` the eight constants they share with the
  adapter. Implementation amended it twice, both worth reading — the engine's finding sort is
  total, so it hides a map-ordered rule entirely and rule-level ordering needed its own test;
  and the redaction guard had to move to `test/security`, because depguard denies diagnosis
  the `internal/security` import and a boundary is not weakened to make a test convenient. A
  follow-on pass, **0040 §5.1**, then removed the one code that pass had
  marked provisional — by correcting the producer under it rather than shipping around it. The
  adapter had normalized *the peer refused what I presented* and *the peer could not prove
  itself to me* onto one class, and the second is only reachable once the peer has **accepted**
  the material, so the class stated the opposite of what happened. One generic
  `FailureClass` — `AUTH_PEER_VERIFICATION_FAILED`, the 39th — and a two-branch split fixed it,
  and the resulting invariant is reusable by any mutual mechanism. ADR 0038 carries the
  correction as amendment D.

- **0041** is the first record about the *application*, and it exists because Phase 4.8a
  measured `localhost` resolving to two usable paths — with the integration harness silently
  taking the first, which is the invisible IPv4 preference 0024 had removed from the chain,
  found alive in the suite meant to validate it. It closes the selection deferral 0028 left
  open, and its principle is one sentence: **discover broadly, authenticate narrowly.** Every
  path is measured through credential-free discovery, because PostgreSQL's startup exchange
  presents no secret and `pg_hba` selects behaviour by source address — so a family-dependent
  `reject` or a different mechanism is observable without spending a credential attempt on
  each path. Then exactly one eligible path receives the one attempt a run is allowed, chosen
  by a deterministic tie-break that is a tie-break and not a preference: it decides where the
  credential goes among paths already measured, never which path is measured at all. Two
  symmetric alternatives are rejected — authenticate none when ambiguous, which withholds the
  tool's main function on every dual-stack endpoint, and authenticate all, which multiplies
  the one thing that is logged, counted and lockout-relevant. It also fixes the CLI tree as
  action-first, partially superseding 0011's shape while preserving its reasoning, and it is
  careful to claim nothing about the paths it did not authenticate.

- **0042** is the record Phase 4.9a stopped to ask for. That phase set out to decide who owns
  DNS/TCP/TLS diagnosis for the endpoint an operator named, and found two gaps rather than a
  policy question: the graph could not prove which transport sweep the operator caused, and it
  carried the requested `host:port` in no subject at all — only inside identifiers, which
  nothing may parse. Both have one cause, and it is that nothing recorded *why the run
  happened*. The answer is one node at L0, minted by the composition root, whose subject is the
  logical endpoint and whose child is the sweep it caused. The accusation it had to survive is
  that this is `Origin` wearing a node, and the defence is mechanical rather than rhetorical:
  `Origin` asks how a *subject* entered a run and dies on a cluster advertising its bootstrap
  endpoint back, while the anchor asks which *execution* the operator caused and is untouched by
  that same case — the two sweeps stay distinct, as 0032 built them to. Its load-bearing
  discovery is that the Kafka advertised sweep is a **transitive descendant** of the bootstrap
  target, so "generic diagnosis owns everything below the anchor" would have walked straight
  into 0034's evidence; ownership is therefore direct parentage at the sweep root and a
  step-typed walk of bounded depth, which also leaves PostgreSQL's in-band handshake with its
  adapter. Phase 4.9a-pre implemented it: `internal/vocabulary` gives the four step names one
  spelling, `internal/app` mints the anchor in one authorized function, and the Kafka hazard is
  now measured rather than argued — against a real advertised sweep, the naive descendant walk
  is shown to capture it and the authorized walk is shown not to. It authorizes no finding, and
  says so.

- **0043** is the first record that lets svcdoctor say something about a target it never
  reached. It exists because the flagship failures produced nothing: a run that could not
  resolve a name, or could not open a socket, reported `status: OK` beside a broken layer —
  measured, not supposed. 0042 made the fix possible by giving the operator's sweep a
  structural owner; this record decides what may be said about it. Three codes, and the shape
  of the argument is the same each time: the claim is what was observed *from this vantage*,
  never what it implies. `DNS_NAME_NOT_RESOLVED` refuses to say a name does not exist, because
  the probe above it already refused to; `TCP_CONNECTION_NOT_ESTABLISHED` refuses the word
  *unreachable*, because a refused connection proves a host answered. Its hardest call was
  whether to split TCP by errno, and the answer is no — not because the distinction is
  uninteresting but because it is not stable across one endpoint, which routinely refuses on
  one family and times out on the other; the reason distribution lives in the evidence, where
  it does not become an unstable public contract. It withholds on partial success and on
  incomplete measurement, and it authorizes nothing for TLS: no production run produces a
  generic requested-target handshake, and policy for evidence that cannot occur is policy that
  will be wrong by the time it can. Phase 4.9b implemented it: two rules, three codes, and a
  prose guard that rejected the record's own first draft of the TCP detail for naming a
  firewall in order to deny it.

- **0044** closes the last transport silence in a PostgreSQL run, and it is the first record in
  this repository to overturn a predecessor's reasoning rather than narrow it. 0040 had declined
  `POSTGRES_TLS_*` findings on the grounds that one *"would add nothing the node does not already
  state, which is the duplicate test"* — and that reasoning proves too much: applied consistently
  it deletes `POSTGRES_TLS_DECLINED` and all three of 0043's codes, because every finding restates
  evidence. The duplicate test in 0034 is a test between *findings*. What a finding adds is not
  information but standing: `SummaryStatus` derives from findings and never from evidence, so a
  node cannot make a report say `PROBLEMS_FOUND`, and the measured result of the absence was
  `status: OK` on a run that failed at L3. The deferral was also written when *no* transport layer
  had an owner, so the silence was uniform; 0043 gave L1 and L2 owners and turned it into an
  inconsistency. Its ownership rule generalizes past PostgreSQL in one sentence — generic evidence
  belongs to the layer that caused the probe to run, read from the parent edge, never from the step
  name — and its most-argued detail is the one that looks like an oversight: it does **not** copy
  0043's partial-success withholding, because a PostgreSQL finding claims something about *this
  endpoint*, and another endpoint working does not make that claim false. Phase 4.9d
  implemented it, and found two things worth keeping: three of the five codes are honestly
  unit-only, because no correct server can be asked to agree to encrypt and then not speak
  TLS; and a PostgreSQL role literally named `svcdoctor` makes redaction refuse the whole
  report, because finding prose says that word and the residual scan cannot know the
  collision is coincidental. The refusal is correct and is now pinned as intended.

- **0045** exists because pointing svcdoctor at a port serving HTTP — the most ordinary way to
  get an endpoint wrong — produced `findings: []`, `status: OK` and a broken L3. It gives
  `postgres.ssl_request` the floor that startup, authentication and session already had, so every
  `postgres.*` step is now total over failure. Two details are worth keeping. Its
  `vantageDependent` is `true` while `POSTGRES_TLS_DECLINED` on the same node is `false`, and that
  is derived rather than inconsistent: one names a server-wide decision, the other attributes
  nothing and therefore cannot exclude a source-keyed cause. And it declines to give the `E`
  answer its own claim, for the same reason 0040 declined the whole thing — the shape has still
  not been measured, and this phase measured an unexpected *byte*, not an `ErrorResponse`. It is
  half a phase: the no-credential blocker hit two second-opinion triggers and was returned as a
  packet instead of decided.

- **0046** is the last PostgreSQL BASIC blocker, and the one whose *evidence* had to move before
  any claim was possible. Forgetting a password produced a report where every step passed,
  `status: OK`, and no broken layer at all — worse than the transport silences 0043 and 0044
  closed, because there was not even a FAIL node to hint at it. The obvious rule could not be
  written: ADR 0041 records nothing when the budget ends before the credentialed step, so a
  cancelled run left a byte-identical graph, and a rule reading absence would have claimed "no
  credential was configured" about a run that had one. So the fact moved to the producer, which
  needed one generic `FailureClass` — `EXEC_REQUIRED_INPUT_MISSING`, service-neutral, and none of
  the three execution classes it sits beside. Two details repay attention: the check is second,
  after the capability gap, so an endpoint demanding `md5` is not answered with "configure a
  password"; and the finding is WARN, because the endpoint did nothing wrong and severity is not a
  lever for forcing an exit code. Whether a run that never reached a session should *look* clean
  in a terminal is a renderer question, and 0046 says so rather than solving it with severity.

- **[0047](0047-local-execution-incompleteness.md) — A run svcdoctor cut short says so, and a run
  that got its answer does not.** Three defects shared one seam: a per-step budget expiring leaves
  the caller's context alive. `postgres.startup` had no field to receive a budget in and so ran
  unbounded; the SSL-negotiation classifier lacked the local-deadline guard its siblings had, and
  published svcdoctor's own timeout as the endpoint's protocol failure; and `Incomplete()`, derived
  from `ctx.Err()` alone, called a run that never reached L3 finished. Two of those are corrections.
  The decision is the third: *when does a local timeout make the whole run incomplete?* Not "any
  local UNKNOWN anywhere" — ADR 0041 measures every address and continues one, so that rule would
  report an ordinary dual-stack run as truncated while it holds a passing session. A run is
  incomplete when svcdoctor's own limit stopped it reaching what it set out to measure, and a
  session that reached `ReadyForQuery` settles the question. It narrows 0041's acceptance 36 and
  makes 0043 §6's premise true. Status and incompleteness stay orthogonal, and severity was not
  used as a lever.

- **[0048](0048-cli-and-output-boundary.md) — The report is the product, and the process status
  is the only thing said about the run.** The first user-facing boundary, and the risk it exists
  to manage is that PostgreSQL BASIC's committed semantics are easy to render as a lie: status
  `OK` is *no target-side error was proven*, not *the session worked*; a WARN can sit on a run
  that established nothing; incompleteness is orthogonal to status. So the terminal renders
  status, session and execution as three separate facts, and `status OK` never prints bare.
  JSON is the canonical `domain.Report` and nothing wrapped, which forces the one genuinely open
  question — `Result.Incomplete()` is not in the schema, so machines learn it from exit code 4,
  with a reopen condition for a detached-JSON consumer. stdout carries the artifact on 0, 1 and
  4; stderr carries only usage and internal failures. Exit precedence stays `docs/SCOPE.md`'s
  `3 > 2 > 4 > 1 > 0`. No CLI framework and no colour: one leaf command does not justify a second
  dependency, and meaning that survives `NO_COLOR` did not need colour to begin with.

- **[0049](0049-cli-credential-input.md) — A secret arrives by file or by pipe, and never by
  argument.** Split from 0048 because the failure mode is different: a bad output decision
  misleads, a bad secret decision leaks. `--password-file` and `--password-stdin`, mutually
  exclusive with **no precedence** — ambiguity is exit 2, because a precedence rule is one more
  thing to misremember during an incident. A literal flag is refused outright (shell history,
  process table); environment variables and a prompt are deferred with conditions. Two details
  earn their place: exactly one trailing newline is trimmed and never `TrimSpace`, because a
  space is legal password material and eating it would surface as a rejected credential; and
  supplying no credential stays valid input, because `POSTGRES_CREDENTIAL_NOT_CONFIGURED` is a
  truthful diagnosis rather than a usage error — which is what makes a prompt unnecessary.

- **[0050](0050-kafka-discovered-broker-credential-authority.md) — A credential is authorized for
  the endpoint the operator named, and a cluster cannot widen that.** The security prerequisite
  for `DiagnoseKafka`, and the first record whose subject is an *authority* rather than a claim.
  Kafka's Metadata response names brokers, and the tempting reading — the cluster told us these
  are its brokers, so the credential belongs there — converts a compromised broker into credential
  exfiltration through one protocol field. Verified TLS does not help: it proves *you are talking
  to attacker.example*, not *attacker.example belongs to the cluster you asked about*, and Kafka
  has no cluster-identity assertion to verify. So the invariant is **discovery may create evidence;
  discovery must not create secret authority**, advertised measurement stays transport-only as
  ADR 0033 already had it, and the rule binds the composition root because `security.NewCredential`
  is unrestricted by design and the root is the only layer that could rebind. `security.Credential`
  is reused unchanged; no delegation type, no cluster identity, no `Origin`.

- **[0051](0051-kafka-run-completeness.md) — A Kafka run is complete when every advertisement it
  promised to measure reached a verdict.** ADR 0047's `established` short-circuit has no Kafka
  analogue, because BASIC promises two things — a bootstrap journey *and* a topology assessment —
  so `kafka.metadata` PASS ends the journey but not the run. The decision is an asymmetry that the
  first draft got wrong and a security review corrected: **PASS is existential, FAIL is universal.**
  One working address resolves an advertisement outright; a refused address plus an unmeasured
  sibling does *not* prove the endpoint unreachable, because a client selecting the unmeasured path
  might have connected. That is ADR 0043's TCP rule applied one level down. `Result` keeps one
  boolean, and finding confidence stays orthogonal to it: a CONFIRMED endpoint claim can coexist
  with an incomplete run.

- **[0052](0052-kafka-product-outcome-semantics.md) — Kafka has no session, so the report says what
  it obtained instead.** Kafka has no `ReadyForQuery` and no session establishment, so the
  renderer's one PostgreSQL-specific line becomes a per-service `outcome`, and Kafka's terminal
  fact is `kafka.metadata` PASS — the first exchange requiring authentication *and* authorization
  to have worked. The wording is deliberately narrower than it could be: **`Kafka metadata
  obtained`**, not `cluster metadata obtained`, because the request is v1 with `Topics = []` and
  obtains no topic, partition, replica or ISR state at all. Topology is a separate line counting
  **endpoints reached**, past tense and observational, with `not measured` never collapsed into
  `not reached` — and never `usable`, because ADR 0050 means a discovered broker is never
  authenticated. Four axes stay independent: status, outcome, topology, execution. No schema change.

- **[0053](0053-requested-target-generic-tls-diagnosis.md) — A certificate is presented by an
  endpoint, so a generic TLS finding names one.** Satisfies 0043 §14's reopen condition exactly:
  Kafka bootstrap composition is the first production producer of a `tls.handshake` whose parent is
  a requested `tcp.connect`, and `collectSweep` never inspects a connect's children, so the node
  would be *invisible* rather than rejected. The scope decision resolves a real tension rather than
  copying a precedent: DNS and TCP claims are about a logical address set and withhold on partial
  success, but a certificate is presented by one endpoint, so a sibling succeeding cannot falsify
  what this one presented. Endpoint-scoped, no withholding — which keeps it coherent with 0044
  instead of making scope depend on whether a service negotiates in band. Five codes, two of them
  renamed during review because `TLS_PEER_NOT_TLS` mirrored its `FailureClass` exactly and generic
  codes carry no prefix, so evidence and finding namespaces would have collided on one string.

- **[0054](0054-production-evidence-ownership-invariant.md) — Evidence that can fail does not ship
  before something can explain it.** The generalization of what PostgreSQL closure kept finding:
  a stage produced evidence nobody could explain, and the report presented the silence as health.
  0043, 0044, 0046 and 0047 each closed one instance, always late and always by audit rather than
  by the phase that introduced the producer — because a missing finding fails no test and looks
  exactly like a healthy target. So: a production-reachable FAIL-producing stage does not land
  unless its outcomes have an owner or an Accepted ADR says evidence-only is intentional and why.
  UNKNOWN and SKIPPED need a visibility policy rather than necessarily a finding. The escape hatch
  is real — 0033's advertised sweep used it correctly for two phases. Accepted as policy with
  **enforcement deferred**: the per-service closure test it specifies does not exist yet, and a
  static lint cannot do the job because reachability is not decidable from imports.

- **[0055](0055-shared-scram-core-never-receives-plaintext.md) — The shared SCRAM core never
  receives plaintext.** The Phase 6.2a security review, and it **rejected** the model
  `docs/ARCHITECTURE.md` §5.8 had fixed in advance. Model A — plaintext as a short-lived
  argument into a shared core — is survivable, adds zero copies, and was still refused: it
  raises the number of packages that can observe a password from two to three, and every
  guarantee it offers has the shape *"the core must not …"*, maintained by lint and review
  forever. The adopted Model D gives the core a derivation callback instead, so it has no API
  that could accept a password; the wire package keeps the plaintext and the `crypto/pbkdf2`
  call, and only the SaltedPassword crosses — one principal on one target, not the operator's
  reusable password. The core invokes the callback *after* validating the peer's iteration
  count, which preserves ADR 0038 §16's adjacency across the new boundary. Cost measured
  rather than asserted: about ten trivial lines per service, no duplicated cryptographic
  construction. The review also found three things the plan lacked — `saslname` escaping is
  new unvectored code because Kafka reads the username from `n=` where PostgreSQL sends it
  empty, the two wire packages bound peer payloads eight times apart so the core must bound
  itself, and Kafka has no `Reveal`-count guard. Implementation waits on Phase 6.2a-R2.

- **[0056](0056-model-d-scram-api-and-security-contract.md) — The Model D SCRAM API and
  security contract.** The Phase 6.2a-R2 review, and the record that authorizes Phase 6.2. It
  fixes the exact API — `Begin`/`Continue`/`Verify` over a pointer `State` with a three-step
  machine, a named `Username` type, and no nonce parameter, because a caller-supplied nonce
  puts entropy authority in two wire packages. The derivation callback runs **exactly once**,
  after ten validation steps, and zero times on every rejection path; that is structural, since
  one call expression exists in the package and it is in no loop. Eight core-owned bounds,
  because the two wire packages bound peer payloads eight times apart — including an
  encoded-salt check placed *before* the base64 decode, which today's parser does after. Its
  hardest decision is to **refuse SASLprep**: PostgreSQL applies it, Apache Kafka does not
  (`KAFKA-6272`), so the two services need opposite behaviour for non-ASCII and no shared
  implementation is correct for both — restricting to printable ASCII, where SASLprep is
  provably the identity, is the only correct choice and needs no Unicode dependency. SASLname
  escaping is core-owned. Three residual risks are recorded rather than argued away: a password
  could be passed as the `Username`, the callback closes over scope the core cannot inspect, and
  the SaltedPassword is not harmless. It also **supersedes one sentence of 0055**: the negative
  gate guard is not deleted on acceptance but swapped atomically for the positive guards in the
  commit that introduces the package.

- **[0057](0057-kafka-cli-mechanism-selection.md) — The operator names one Kafka SASL
  mechanism, and svcdoctor never picks one.** `--sasl-mechanism` is required and has no
  default, because a default is a silent decision about the framing that carries the
  operator's password. One mechanism per run, presented at most once: no auto-probe from the
  broker's list, no fallback in either direction, no inference from the credential's shape or
  the port. Names are taken verbatim in RFC 4422's uppercase grammar and are **never folded**,
  because a looser matching rule at the CLI beside the exact-match guard that gates the
  credential is how that guard fails quietly. The command deliberately accepts mechanisms
  svcdoctor cannot perform — naming one sends no secret, and the truthful `UNKNOWN` + INFO at
  exit 0 is the only way to ask what a broker offers. `--user` is required with a credential
  source and refused without one, because Kafka's identity travels only inside SASL.

- **[0058](0058-tls-trust-and-peer-identity-authority.md) — Trust answers "whose certificate
  is this"; identity answers "is it the peer I meant".** Both must hold, and a trusted chain
  with the wrong identity is never a verified peer. A supplied `--tls-ca-file` **replaces** the
  system trust store, because augmentation cannot express "only this issuer is acceptable here"
  and still passes a run configured with the wrong CA. Identity is `--host` unless
  `--tls-server-name` overrides it, and **DNS resolution never changes it** — the identity
  analogue of 0028's credential rule. The override drives verification *and* SNI, because in Go
  they are one field, and it applies to the requested target only: Kafka brokers learned from
  Metadata are verified against **their own advertised names**, since one name cannot truthfully
  be the expected identity for both a bootstrap load balancer and three brokers with their own
  certificates. So **discovery creates identity context and never credential authority** — an
  advertised endpoint may present a perfectly valid certificate and still receives zero
  credential bytes. IP SANs already verify with no flag and Go sends no SNI for an IP literal;
  `CN` is never an identity and no exception will be added for one. `--tls-insecure` disables
  identity verification and nothing else — notably not the credential policy, so it makes
  authentication *not* happen. Go's version defaults are kept deliberately, so the evidence
  describes the target rather than svcdoctor. A decision record: no production Go changed, and
  three product gaps are recorded in §14 rather than repaired here.

- **[0059](0059-ip-literal-targets-and-resolution-free-transport.md) — An address is not a
  name, so a run that was given one resolves nothing and says so.** A literal target performs
  no resolution and records **no `dns.lookup` node at all**, which is what makes a DNS finding
  unreachable for one structurally rather than suppressed. The graph gains a second shape,
  `target.requested -> tcp.connect`, and four consumers learned it — requested-target and
  advertised sweep collection, Kafka completeness and the terminal renderer — each by branching
  on a step or layer the producer wrote, none by parsing a host string. `net/netip` is the
  single classification and the single canonicalization: one address has one spelling,
  IPv4-mapped is unmapped, and a **zone identifier is refused** rather than silently dropped as
  it was before. TCP and generic TLS ownership landed with the producer (ADR 0054); layer stays
  L2 and L3 because layer is data, not tree depth; identity is ADR 0058 unchanged, and the
  bare literal — never the bracketed endpoint — is what a raw address verifies. Advertised
  literals are first-class transport endpoints and still receive zero credential bytes.
  `SchemaVersion` stays 1; no code, class, state or dependency was added. ADR 0058 §14's three
  gaps proved to be one coupled defect and are deferred together in §14.

- **[0060](0060-tls-option-validity-and-verification-state-projection.md) — A TLS-only flag on a
  run with no handshake is a usage error, and a security fact the operator chose is stated
  rather than buried.** Closes ADR 0058 §14's three gaps as the one coupled defect Phase 6.7
  measured them to be, in its fix order. PostgreSQL now **refuses** `--tls-ca-file`,
  `--tls-server-name` and `--tls-insecure` under `--tls disable`, as Kafka always did — a
  released-CLI tightening, with the compatibility packet in §5 and the reasoning that
  `--tls disable --tls-insecure` reads as *a small deliberate compromise* while being a total
  one. `tlsVerificationDisabled` is gated on the run's TLS **plan** in both composition roots,
  so a plaintext run no longer reports a TLS fact; the three states stay distinguishable
  across two existing fields, so `SchemaVersion` stays 1. The terminal states disabled
  verification in the header from the run and on each handshake row from that node's own
  `tls.verified` — read from two places on purpose, so a renderer inventing either from the
  other fails a test. It is **not a finding**: the operator asked for it, the status and exit
  code are unchanged. `tls.verified` moved to `internal/vocabulary` on the trigger that package
  already named, because a renderer cannot import a probe. No code, class, flag or dependency
  was added.
- **[0061](0061-scram-defensive-resource-bounds.md) — A defensive bound must be justified by a
  measured resource cost, not by how common a value looks.** **Accepted, implemented in Phase
  7.0b**, and it supersedes ADR 0056 §7 in part — the numeric bounds and the refusal semantics,
  nothing else.
  Redpanda v25.1.9 issues a **130-byte** SCRAM salt — confirmed from its source, where
  `SaltSize` is hardcoded — and svcdoctor refuses it, at the **encoded** check (176 > 172)
  before the decoded one. ADR 0056 §7 justified `maxSaltLen` as *"8× the largest value in
  common use"*, and a third mainstream implementation falsifies that premise. Archaeology
  found every field bound was invented in the extraction commit, **after v0.1.0 shipped
  PostgreSQL SCRAM with no salt bound at all**. Measurement found the bound protects nothing:
  a **64 KiB salt costs 7.9% more PBKDF2 CPU than a 16-byte one**, refusals allocate zero, and
  parsing a full message costs 1.7 µs against 101 ms of derivation. So the message bound and
  the iteration ceiling are the bounds that do the work; field ceilings are retained as
  absolute constants — not derived from the message bound, which is the one point the
  counter-argument wins — but re-derived at ~8× the largest value any real implementation
  produces. Also records a **truthfulness defect**: a bound refusal is reported as
  `PROTOCOL_MALFORMED_RESPONSE`, claiming the peer's legal message was malformed, when the
  `EXEC_UNSUPPORTED_BY_SVCDOCTOR` vocabulary both adapters already use for
  `ErrIterationsUnsupported` is the truthful one. Phase 7.0b shipped 8192/8192/1024/1368/1024/32
  with `MaxIterations` unchanged, corrected that classification in both services, and committed
  `test/integration/redpanda/` pinned to v25.1.9 — whose SCRAM now passes, and whose suite fails
  against the old bounds on the same live broker. No finding code, failure class,
  `SchemaVersion`, `Reveal` count, auth cardinality or dependency changed.

`docs/BACKLOG.md` tracks these alongside every other open decision.

## Convention

- One decision per record, numbered sequentially, never renumbered.
- Record what was decided, the context that forced it, and the consequences.
- Record rejected alternatives with the reason and the condition that would justify
  reconsidering them.
- A decision that turns out wrong gets a new record that supersedes the old one. Do
  not edit history until a decision appears never to have been made.
- Do not create a record for a trivial implementation choice.
