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
| 0017 | The diagnosis rule contract | Accepted | Defers transport severity policy and finding identity. 0042 supplied the requested-versus-discovered context an anchored generic rule needs; **0043 closes the deferral for DNS and TCP**. It stands for generic TLS, which has no producer |
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
| 0040 | A PostgreSQL rule anchors only at a `postgres.*` step | Accepted (policy), implemented in Phase 4.6b | The 0034 analogue for PostgreSQL. Authorizes the service vocabulary leaf 0042 §11 reuses generically |
| 0041 | A run discovers broadly and authenticates narrowly | **Accepted, implemented in Phase 4.8b** | First record about the application. Closes the selection deferral 0028 left open; partially supersedes 0011 on command-tree shape. Narrowed by 0042 §3, which opens one hole in its evidence-authority ban |
| 0042 | A run records the target it was asked about, and a sweep declares its cause | **Accepted, implemented in Phase 4.9a-pre** | Closes the ownership and subject gaps Phase 4.9a stopped on. Narrows 0041, half-closes 0017's deferral, amends 0032 at the sweep root, and leaves 0034's advertised ownership structurally unreachable. Authorizes no finding |
| 0043 | svcdoctor says what it could not reach, and no more than that | Accepted (policy) | Closes 0017's generic transport deferral **for DNS and TCP only**. Consumes 0042 as its ownership prerequisite; leaves 0034, 0040 and 0041 unchanged. Defers generic TLS for want of a producer, and records PostgreSQL's in-band TLS gap without fixing it |

## Decisions that govern work not yet written

Some accepted records decide how something will be built rather than describe
something that exists. That is intentional, and they are binding when that work
starts: **0008** (Kafka wire client), **0009** (service registration), **0011**
(CLI shape).

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
  will be wrong by the time it can.

`docs/BACKLOG.md` tracks these alongside every other open decision.

## Convention

- One decision per record, numbered sequentially, never renumbered.
- Record what was decided, the context that forced it, and the consequences.
- Record rejected alternatives with the reason and the condition that would justify
  reconsidering them.
- A decision that turns out wrong gets a new record that supersedes the old one. Do
  not edit history until a decision appears never to have been made.
- Do not create a record for a trivial implementation choice.
