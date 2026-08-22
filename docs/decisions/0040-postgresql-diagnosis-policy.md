# ADR 0040: PostgreSQL diagnosis names the observed failure boundary, never the hidden cause

## Status

**Accepted as policy. Implementation pending (Phase 4.6b).**

The `security.Reveal` count stays **two**, the report `schemaVersion` **1**, the
dependency set one, and no `AttrKind` and no redaction rule changes. **One
`FailureClass` was added — `AUTH_PEER_VERIFICATION_FAILED`, 38 → 39** — by the
Phase 4.6a.5 producer correction §5.1 records; that is the only production Go
change this record has caused, and no diagnosis rule exists yet.

This is the ADR 0034 analogue for PostgreSQL: it decides what svcdoctor may
conclude from the evidence Phases 4.1–4.5 produce, so that Phase 4.6b can
implement rules without inventing anything. It authorizes **twelve finding
codes**, two new packages, and one constant move, and it refuses candidate
findings by name.

**Revised by an adversarial pre-implementation review, before any rule existed.**
The review found nine defects and all are corrected here. The substantive ones:
the two mechanism findings were split on *whose gap it is*, which is a moving
property of svcdoctor rather than of the target (§12.1); the L4 floor's code and
summary said *rejected*, which its own trigger disproves (§8); the floors'
attribution sentence was unconditional and therefore false on three classes
(§8.1); six `vantageDependent` values asserted position-independence that
`pg_hba` source matching disproves (§6.1); and "one node, one finding" was
written as a permanent invariant when it is a phase scope (§3). The code **count**
did not change; the code **set** did. Superseded wording is retained only under
"Rejected alternatives", labelled as history.

**Then revised once more by Phase 4.6a.5**, which corrected the producer defect
§11 had been written to work around rather than shipping a provisional code for
it. `POSTGRES_SCRAM_EXCHANGE_FAILED` is **gone**, replaced by the stable
`POSTGRES_PEER_VERIFICATION_FAILED`; the credential predicate lost its SQLSTATE
clause because the class itself became trustworthy; and §5.1 records the generic
authentication invariant the correction established. Still twelve codes.

Evidence: `docs/validation/POSTGRES_PHASE46_DIAGNOSIS_STUDY.md`, which reads the
PostgreSQL producers at `c86fdc3` and cites the wire measurements from Phases
4.4a and 4.5a.

## Problem

Phase 4.5 finished the PostgreSQL vertical slice and produced no findings, by
design (ADR 0039 §19). Writing the rules next is the same trap ADR 0034 named:
several questions become answerable at once, each is individually tempting, and
answering them by implementation puts invented policy into the layer whose
purpose is not to invent.

The PostgreSQL versions of those questions are harder than Kafka's, for one
measured reason:

> **A connection pooler emits one SQLSTATE for at least six unrelated root
> causes, and moves some of them to an earlier protocol step.**

`08P01` is pgBouncer's substitute for a NULL sqlstate. It arrives at
`postgres.authentication` for a wrong password and for a corrupted proof, and at
`postgres.startup` for an unknown role, an unknown database and a `CONNECT`
denial. Every distinction the direct-PostgreSQL vocabulary carries is gone, and
the protocol position does not restore it. Any rule that infers a cause from it
will be confidently wrong on a large fraction of real deployments, because
pooled PostgreSQL is the common case rather than the exotic one.

Four further questions, each of which would be decided by accident otherwise:

- **Ownership.** A PostgreSQL run fails at DNS, TCP or TLS more often than at the
  protocol. Whether a `POSTGRES_*` finding may fire on those nodes decides
  whether ADR 0017's still-open blocker gets quietly bypassed.
- **`AUTH_CREDENTIALS_REJECTED` points two ways.** Study §2.1: three producers
  feed it, and one of them is svcdoctor refusing the *peer's* server signature.
  A finding worded as "the peer refused what we sent" is false in that case.
- **Success proves almost nothing.** pgBouncer served a complete passing session
  with its backend stopped.
- **The replica facts are a trap.** `default_transaction_read_only` was `off` on
  a real standby.

## Decision

### 1. The no-root-cause-hallucination rule

This is the record's primary invariant and every other section is an application
of it.

> **Diagnosis may name a root cause only when the evidence contract uniquely
> supports that cause. Otherwise it names the observed failure boundary.**

The *observed failure boundary* is the triple *(which protocol step, in which
state, with which normalized failure class)* — all three of which a producer
committed to and a reader can check against the cited node. It is never a
SQLSTATE translated into English, never a position in the protocol reasoned back
to an intent, and never a peer implementation named from a missing field.

This restates `docs/FINDINGS.md` §4 in the form PostgreSQL needs, and it is
compatible with ADR 0034 rather than an extension of it: the Kafka rule names a
cause (*the cluster advertised an endpoint this vantage cannot reach*) precisely
because its evidence contract uniquely supports it.

### 2. A PostgreSQL rule anchors only at a `postgres.*` step

The four steps a PostgreSQL rule may anchor at, and no others:

```text
postgres.ssl_request      L3
postgres.startup          L4
postgres.authentication   L5
postgres.session          L5
```

**No `POSTGRES_*` finding fires on `dns.lookup`, `tcp.connect` or
`tls.handshake`.** Those are generic transport nodes, and a PostgreSQL rule
reading one would be answering the question ADR 0017 deferred — is this a
service diagnosis or a bare endpoint check? — from graph shape, which is the
provenance inference ADR 0034 §4 forbids.

`postgres.ssl_request` is at L3 and is still PostgreSQL's: it is not a transport
observation but the answer to an **in-band, PostgreSQL-specific negotiation**
that no generic probe performs or could perform. The distinction is what was
spoken, not what layer it happened at.

**The consequence is stated rather than hidden: a PostgreSQL run that fails at
DNS, TCP or TLS produces zero findings in Phase 4.6.** The evidence is in the
report and the summary derives `firstBrokenLayer` from the graph. That gap is
ADR 0017's, it is unchanged, and PostgreSQL may not paper over it — the same
position Kafka is in for a failed bootstrap path today.

### 3. At most one **primary Phase 4.6 diagnosis** per node

> **Each non-passing `postgres.*` node yields at most one finding from the
> primary diagnosis set this record authorizes, and a failed one yields exactly
> one.**

**The scope of that sentence is deliberate and load-bearing.** It constrains the
twelve codes in §6 and nothing else. It is **not** a permanent repository
invariant, and it must never be implemented or tested as one.

An earlier draft stated it as "one PostgreSQL node, one finding", full stop.
That is wrong, because genuinely independent claims can rest on the same node.
On a node carrying `AUTH_MECHANISM_NOT_OFFERED`, *"this endpoint offers only
md5, a weak password mechanism"* is a **security-posture** claim that would
remain true and useful if the diagnosis finding were removed — which is
precisely ADR 0034 §3's *complementary* case, not its *duplicate* case:

> **Two findings are duplicates when the same evidence entails both and one
> makes no claim the other does not already make. They are complementary when
> each states something the other does not, and each would remain true and
> useful if the other were removed.**

Future independent findings — security posture, weak-mechanism policy,
certificate posture, compliance signals — are therefore **not** foreclosed by
this record, on these nodes or any others. Freezing the engine against them to
buy a tidy invariant for one phase would be a bad trade, and `diagnosis.Engine`
must remain free of suppression logic either way (ADR 0017).

Within the primary set the property still holds and is still worth having. The
rules are structured as **four functions, one per anchor step**, each selecting a
single code from predicates that are disjoint on *(state, failure class,
attributes)*. This is a deliberate departure from the Kafka shape of one exported
rule per code, and it buys structurally the mutual exclusivity ADR 0035 had to
*prove* for its pair — twelve codes would otherwise need pairwise disjointness
arguments.

Within a step the predicates are **disjoint, not ordered**. A test asserts that
no two of them match one node, which is stronger than a precedence list and fails
loudly if a later edit makes two overlap. §23 G4 and G5 are scoped to the primary
set for the same reason this section is.

### 4. The weakest-true-claim ladder

Each anchor step has a **floor**: a finding whose claim is the observed boundary
and nothing more, which fires whenever the node is FAIL and no escalation
predicate matches. The floor makes the rule set total over failure, so a failed
PostgreSQL node can never produce silence.

```text
  specific peer assertion        the peer named the condition in its own vocabulary
          ↓                      (28P01, 3D000, 42501, 28000, e=invalid-proof)
  step-specific failure          a class the producer committed to
          ↓                      (AUTH_MECHANISM_NOT_OFFERED, AUTH_CREDENTIALS_REJECTED)
  protocol-boundary failure      the step did not complete, and no stronger claim
          ↓                      is justified (the floor: 08P01, 53300, 57P03,
                                 0A000, malformed, peer close)
  generic reachability failure   not owned here (§2) — no PostgreSQL finding
```

Applied to the cases that forced the ladder:

| Observation | Strongest justified claim |
|---|---|
| `28P01` at `postgres.authentication` | the endpoint refused the authentication material svcdoctor presented |
| `AUTH_PEER_VERIFICATION_FAILED` at `postgres.authentication` | this endpoint failed proof verification — **not** that it rejected the credential, and **not** a cause (§11) |
| `08P01` at `postgres.authentication` | the authentication exchange did not complete successfully, and svcdoctor could not attribute a cause — **not** credentials rejected |
| `3D000` at `postgres.session` | the requested database was not available to this session |
| `08P01` at `postgres.startup` (pooled missing database) | the startup exchange did not complete and no authentication was requested — **not** database not found |
| `0A000` / `57P03` / a peer close at `postgres.startup` | the startup exchange did not complete — and the floor's detail **omits** the attribution sentence, because each of these already names a stronger fact (§8.1) |
| `53300` at `postgres.session` | the session did not reach `ReadyForQuery` — **not** out of connections |

**A rule must prove the specific evidence before producing the specific
finding.** Every escalation predicate in §6–§17 names the exact attribute or
class that authorizes it, and the floor is defined as the complement.

**The one precondition on totality.** All three `postgres.session` findings
require the parent test in §16 — a PASS `postgres.authentication` node, or a PASS
`postgres.startup` node with `postgres.auth_method="ok"`. A FAIL session node
that fails that test produces **no finding**, deliberately: it is a graph shape
no producer emits (study §2.2, §2.3), and a rule that guessed at one would be
inventing the very half of its claim it cannot cite. This is
`internal/diagnosis/kafka`'s treatment of a malformed anchor — *unreachable on a
graph the chain produces; withheld rather than guessed* — applied unchanged. §4's
totality therefore reads: **every FAIL `postgres.*` node in a graph the producers
can emit yields exactly one finding.**

### 5. `FailureClass` is an input, `FindingCode` is an output, and there is no table

`FailureClass` is the service-neutral transport/protocol observation vocabulary;
`FindingCode` is the user-facing diagnosis vocabulary. They do not map one to one
and must not.

> **A finding is `predicate(step, state, failure class, attributes, graph
> context)` — evaluated inside a service-specific rule.**

There is **no global `switch failureClass`** anywhere, and none may be added.
`RESOURCE_NOT_FOUND` means "the named resource an operation targeted is not
available, according to the peer" in the service-neutral vocabulary; only inside
a rule that has already established *this node is `postgres.session`* does it
also mean "the requested database". A future Redis or Kafka producer will reuse
the class for something else, and that must cost nothing here.

Two classes are read at **two different steps** — `AUTHZ_NOT_PERMITTED` at
`postgres.startup` and `postgres.authentication` — and that is not a shared
table: each step's classifier independently concluded it, for the same
documented reason, and the rule reads the class rather than the SQLSTATE. The
per-step SQLSTATE classifiers that ADR 0039 §7.1 forbids merging stay in the
adapter, untouched.

#### 5.1 Authentication has a direction, and the two directions never share a class

Established by the Phase 4.6a.5 producer correction. It is **generic**, not a
PostgreSQL rule, and it is the reusable half of this record:

> **In a mechanism where both parties authenticate, "the peer refused what I
> presented" and "the peer could not prove itself to me" are different
> observations that lead to opposite actions. They must never be normalized into
> one `FailureClass`.**

The correction that forced it: `internal/adapter/postgres` had mapped
`ErrServerSignatureMismatch` — svcdoctor refusing the *peer's* server signature —
onto `AUTH_CREDENTIALS_REJECTED`, whose contract is *"the peer refused the
authentication material it was presented"*. That was not merely imprecise. A
SCRAM server emits a server-final **only after accepting the client proof**, so
that path is reachable only on a connection where the peer had **accepted** the
material: the class stated the opposite of what happened.

`AUTH_PEER_VERIFICATION_FAILED` was added to `internal/domain` for the second
direction — service-neutral, naming no mechanism and no protocol, and claiming
only that *the value the peer presented failed svcdoctor's verification*. It
names no cause: a peer that does not hold the credential, an intermediary
answering in its place, and a defective implementation are indistinguishable.

Two consequences reach this record directly:

- **`AUTH_CREDENTIALS_REJECTED` is now direction-A-only and therefore
  trustworthy on its own.** Every production producer was audited — PostgreSQL's
  `28P01` and its SCRAM refusal tokens, and Kafka's `SASL_AUTHENTICATION_FAILED`
  — and all are the peer refusing what svcdoctor presented. §10's predicate drops
  its SQLSTATE clause as a result.
- **`POSTGRES_SCRAM_EXCHANGE_FAILED` no longer has anything to describe** and is
  removed. §11 is now `POSTGRES_PEER_VERIFICATION_FAILED`, stable rather than
  provisional.

A third, smaller correction rode along: the SCRAM server-final token
`e=invalid-username-encoding` was mapped to a rejection and is an **encoding
fault**, not a decision about the material. It now yields
`PROTOCOL_UNEXPECTED_RESPONSE`. It is unreachable in practice — svcdoctor sends
an empty username — but it had to move before the class could be trusted without
the SQLSTATE clause.

### 6. The authorized findings

Twelve codes, and exactly twelve. Every one is `CONFIRMED` with `HIGH`
confidence; §6.2 says why, and why that is not a claim about root cause.

`CRITICAL` is never used: it means "an error with severe or broad impact", and
breadth would be a claim about a deployment when svcdoctor measured one endpoint.

| # | Code | Anchor | Layer | Severity | Vantage |
|---|---|---|---|---|---|
| 1 | `POSTGRES_TLS_DECLINED` | `ssl_request` | L3 | ERROR | false |
| 2 | `POSTGRES_STARTUP_FAILED` | `startup` | L4 | ERROR | **true** |
| 3 | `POSTGRES_CONNECTION_NOT_PERMITTED` | `startup` or `authentication` | L4 / L5 | ERROR | **true** |
| 4 | `POSTGRES_CREDENTIALS_REJECTED` | `authentication` | L5 | ERROR | false |
| 5 | `POSTGRES_PEER_VERIFICATION_FAILED` | `authentication` | L5 | ERROR | **true** |
| 6 | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | `authentication` | L5 | **WARN on FAIL, INFO on UNKNOWN** | **true** |
| 7 | `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | `authentication` | L5 | INFO | **true** |
| 8 | `POSTGRES_CREDENTIAL_WITHHELD` | `authentication` | L5 | WARN | false |
| 9 | `POSTGRES_AUTHENTICATION_FAILED` | `authentication` | L5 | ERROR | **true** |
| 10 | `POSTGRES_DATABASE_NOT_FOUND` | `session` | L5 | ERROR | false |
| 11 | `POSTGRES_DATABASE_CONNECT_DENIED` | `session` | L5 | ERROR | false |
| 12 | `POSTGRES_SESSION_ESTABLISHMENT_FAILED` | `session` | L5 | ERROR | **true** |

`Layer` is the layer of the **claim**, which here is always the anchor node's own
layer, because every claim is about what happened at that step. It is not
`summary.firstBrokenLayer`, which the report derives from the graph
(`docs/REPORT_SCHEMA.md` §7.5).

**Severity may vary within one code, and does, once.** `Severity` is a property
of a finding rather than of a code, and ADR 0034's reachability rule already
varies it (ERROR/WARN) within one code. Code 6 is the case here: the claim is
identical in both states, and the operational impact is not — a peer that offers
nothing svcdoctor performs is a fact about the target, while a mechanism
svcdoctor has not implemented is a gap in the tool. §12 carries the reasoning.

#### 6.1 Vantage dependence, and the test that decides it

`vantageDependent` has no dedicated section in `docs/REPORT_SCHEMA.md`. The
governing definitions are `internal/domain/finding.go` — *"marks a finding whose
validity depends on where the evidence was collected from"* — `docs/FINDINGS.md`
§3.1 item 8, and ADR 0012.

> **The test: for the same concrete peer, reached from a different network
> position, could the claim itself legitimately change?**

**"Another vantage might resolve a different peer" is explicitly not the test.**
Every `postgres.*` node's subject is the concrete `ip:port`
(`mustSubject(t.address)`), so a different peer is a **different subject** and
therefore a different claim, not a counterexample to this one. Using resolution
as the test would make every finding in the repository vantage-dependent and
drain the flag of meaning.

**`false` is a positive assertion of position-independence, not an absence.**
`finding.go`: *"vantageDependent is always present, because false is a meaningful
statement rather than an absent one."* A finding may therefore only be marked
`false` when position-independence is itself defensible.

**Two distinct grounds produce `true`, and they differ in strength:**

1. **Proven vantage dependence.** The mechanism by which the answer varies with
   source is known and documented. `pg_hba.conf` is `TYPE DATABASE USER ADDRESS
   METHOD`, and both the refusal decision *and the demanded authentication
   method* are selected by matching the connecting source — visible in this
   repository's own `test/integration/postgres/env/pg_hba.conf`, where `local`
   maps to `trust` and `host` to `scram-sha-256`. Codes 3, 6 and 7.
2. **Inability to honestly assert position-independence.** A floor finding
   deliberately does not attribute a cause, so a source-keyed cause cannot be
   excluded — pgBouncer supports `auth_type=hba` with its own source-matched
   rules, and `08P01` covers exactly those. Asserting `false` there would be an
   overclaim under §1. Codes 2, 9 and 12.

The costs are asymmetric and point the same way. A wrong `true` invites a retry
from elsewhere that cannot help (ADR 0035). A wrong `false` redirects an
investigation, which ADR 0012 calls *"worse than no report"*. Where the two
grounds above do not apply, `false` is asserted deliberately; where they do,
`true` is asserted rather than defaulted.

Per-finding reasons:

| Code | Vantage | Exact reason |
|---|---|---|
| `POSTGRES_TLS_DECLINED` | false | The `SSLRequest` answer is a postmaster-global GUC (`ssl`) on a backend and an instance-global setting (`client_tls_sslmode`) on pgBouncer. The same peer answers every source identically |
| `POSTGRES_STARTUP_FAILED` | **true** | Ground 2. The cause is unattributed by construction, so a source-keyed refusal cannot be excluded |
| `POSTGRES_CONNECTION_NOT_PERMITTED` | **true** | Ground 1, and the strongest instance of it. `pg_hba` matches the source address to decide the refusal |
| `POSTGRES_CREDENTIALS_REJECTED` | false | A completed evaluation: the peer was shown material and refused it. That record does not become false when a different observer is shown different treatment |
| `POSTGRES_PEER_VERIFICATION_FAILED` | **true** | Ground 1. The observation is path-dependent: an intermediary present on one path can produce it while another path to the same concrete peer does not |
| `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | **true** | Ground 1. The advertised mechanism set is a `pg_hba` METHOD decision keyed on source |
| `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR` | **true** | Ground 1. The claim names *the authentication this endpoint required*, and what it required is source-selected |
| `POSTGRES_CREDENTIAL_WITHHELD` | false | About svcdoctor's own policy and the channel this run established, neither of which is a property of network position |
| `POSTGRES_AUTHENTICATION_FAILED` | **true** | Ground 2 |
| `POSTGRES_DATABASE_NOT_FOUND` | false | `3D000` is a catalog lookup; a catalog does not vary by the source of the connection |
| `POSTGRES_DATABASE_CONNECT_DENIED` | false | `CONNECT` is a catalog ACL held per role per database, not per source address |
| `POSTGRES_SESSION_ESTABLISHMENT_FAILED` | **true** | Ground 2 |

**Seven of the twelve are `true`, five `false`**, so the flag still
discriminates. The `false` set is exactly the findings where the peer reached a
**catalog or credential** decision, which is the class of fact that does not move
with the observer. `POSTGRES_PEER_VERIFICATION_FAILED` is the one that most
repays the flag: a proof that fails verification is precisely the case where what
sits on the path matters, and the flag says so without naming a cause.

#### 6.2 Every finding is `CONFIRMED` / `HIGH`, and no finding is a `HYPOTHESIS`

`internal/domain/findingkind.go` on `FindingKindConfirmed`:

> *"the stated condition is directly supported by sufficient evidence. It does
> not mean an absolute root cause has been proven. A confirmed finding may
> establish a symptom or a condition without explaining the whole incident."*

Every finding here — floors included — states a condition that is directly
supported: *this step did not complete*, evidenced by a node whose state and
failure class a producer committed to. **A floor is therefore `CONFIRMED`, and
`HYPOTHESIS` would be wrong**, not merely conservative: `HYPOTHESIS` means
realistic alternative explanations remain *for the claim*, and there is no
alternative explanation for "the exchange did not complete". It would also invite
a discriminator, asserting an open question the finding does not have.

`internal/domain/confidence.go` on `ConfidenceHigh`: *"direct, strongly matching
evidence"* — for **the finding's own claim**, not for a root cause. ADR 0034
already grants `HIGH` to a confirmed reachability finding whose cause is unknown.
`MEDIUM` — *"multiple consistent indirect signals"* — fits nothing here, because
no finding in this record rests on an indirect signal.

**Not knowing the root cause is never grounds for `HYPOTHESIS` or for lowering
confidence.** It is grounds for making the claim narrower, which §1 and §4
already do. `docs/FINDINGS.md` §3.1 item 6 states the same rule from the other
side: if belief weakens, change the claim and let the impact follow.

No finding carries a `Discriminator`, and `domain.NewFinding` would reject one on
a `CONFIRMED` finding anyway.

### 7. `POSTGRES_TLS_DECLINED`

| | |
|---|---|
| **Trigger** | `postgres.ssl_request` is FAIL with `PROTOCOL_UNSUPPORTED_CAPABILITY` **and** `postgres.ssl.offered` is present and `false` |
| **Claim** | *The run required an encrypted channel, and this endpoint declined to encrypt this connection.* |
| **Summary** | `The PostgreSQL endpoint declined the requested TLS upgrade` |
| **Detail** | states both halves: svcdoctor sent `SSLRequest` because the run required TLS, and the endpoint answered that it would not encrypt this connection; nothing was sent afterwards and no credential was presented |
| **Must not claim** | that the endpoint does not support TLS in general; that a PostgreSQL installation has TLS disabled; that TLS cannot be enabled; anything about certificates; anything about what is behind the endpoint |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `false` |
| **Evidence** | the `postgres.ssl_request` node, alone |
| **Recommendation** | `Check whether this PostgreSQL endpoint is configured to accept encrypted connections, and whether anything between this vantage point and it answers the SSLRequest on its behalf` |

"Declined" attributes agency and is justified here, unlike in the floors: the
predicate requires `postgres.ssl.offered=false`, which the producer records
**only when a real answer arrived** (`negotiate.go`: `if err == nil`). Requiring
the attribute is how the rule distinguishes "the endpoint said no" from
"svcdoctor never found out".

The other `postgres.ssl_request` failures — an `E`-shaped answer, a malformed
reply, a peer close — produce **no finding** in Phase 4.6 and are recorded as a
gap in §26. The `SKIPPED` node a `disabled` plan produces is likewise not a
finding: nothing failed, and `postgres.tls.plan` states why.

### 8. `POSTGRES_STARTUP_FAILED` — the L4 floor

| | |
|---|---|
| **Trigger** | `postgres.startup` is FAIL and the class is **not** `AUTHZ_NOT_PERMITTED` |
| **Claim** | *The startup exchange did not complete at this endpoint, and no authentication was requested.* |
| **Summary** | `The PostgreSQL startup exchange did not complete at this endpoint, and no authentication was requested` |
| **Detail** | see §8.1 — class-gated, and never unconditional |
| **Must not claim** | that the endpoint *rejected* anything; which cause; that a database is missing; that a role is unknown; that a credential is wrong or right; that a pooler, proxy or any named product answered; that a PostgreSQL backend exists behind the endpoint |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `true` — ground 2 (§6.1) |
| **Evidence** | the `postgres.startup` node, alone |
| **Recommendation** | `Review this endpoint's connection-level logs for the role and database this run requested` |

**The code says FAILED and not REJECTED, and the summary says "did not
complete".** The floor's trigger includes `PROTOCOL_MALFORMED_RESPONSE` and
`PROTOCOL_PEER_CLOSED`: a peer that emitted an undecodable frame or vanished
mid-exchange **rejected nothing**, and a code or sentence claiming it did would
attribute agency the evidence does not carry. `docs/FINDINGS.md` §3.1 item 2
forbids exactly that, in prose as much as in fields.

"and no authentication was requested" *is* provable and is not agency: this step
ends at the peer's first decisive reply, and a failing one means no
`AuthenticationXXX` frame was ever received.

**This is the finding the pooler cases land on**, and it is the most important
one in the record. Study §4: an unknown role, an unknown database and a `CONNECT`
denial all arrive here as `08P01` before authentication. The finding says where
the connection died and points at the one place the distinction still exists —
the endpoint's own log. That is less than a user wants and is all the wire
proved.

`57P03` (`hot_standby=off`) and `0A000` (protocol version) land here too, and
neither gets a mapping: `0A000` was never observed, and a rule for a message this
code path has not received would be untested speculation.

#### 8.1 The detail is class-gated, and the attribution sentence is not unconditional

| Condition | Detail may say |
|---|---|
| `postgres.sqlstate` is present | the five characters, **verbatim and untranslated**, as structured protocol evidence |
| `postgres.error_is_native` is `false` | that the response did not carry the non-localized severity field a PostgreSQL backend has sent since 9.6 — see §18 for what that may and may not mean |
| class is `PROTOCOL_UNEXPECTED_RESPONSE` | **`svcdoctor could not attribute this outcome to a specific cause.`** |

**The attribution sentence is forbidden for `PROTOCOL_UNSUPPORTED_VERSION`,
`PROTOCOL_MALFORMED_RESPONSE`, `PROTOCOL_PEER_CLOSED`, and any other class that
already names a stronger fact** — because on those the sentence is itself false.
`PROTOCOL_UNSUPPORTED_VERSION` in particular is a specific, attributable class:
the peer said it does not support the version it was sent. `PROTOCOL_PEER_CLOSED`
names what happened. Saying "cause unknown" over either would be a weaker claim
than the evidence supports, which is a different error from overclaiming and
still an error.

Naming a SQLSTATE verbatim is permitted; translating it is not. The five
characters are machine-readable, carry no identity, and are already a structured
attribute a consumer should read instead (`docs/FINDINGS.md` §3.1 item 13);
repeating them helps a human without inventing a meaning.

### 9. `POSTGRES_CONNECTION_NOT_PERMITTED`

| | |
|---|---|
| **Trigger** | `postgres.startup` **or** `postgres.authentication` is FAIL with `AUTHZ_NOT_PERMITTED` |
| **Claim** | *The endpoint refused this connection attempt on the basis of who is connecting and from where, without evaluating any authentication material.* |
| **Summary** | `The PostgreSQL endpoint refused this connection before evaluating any credential` |
| **Detail** | the refusal arrived before any credential was presented, so it is a decision about the connecting role and the source address rather than about the credential; and it is relative to this vantage point |
| **Must not claim** | that the role is **globally** denied; that credentials are invalid; that the same attempt would fail from another source address; that authentication happened; that the role exists or does not; that a specific access rule matched |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `true` — **ground 1, and the strongest case of it in the record** |
| **Evidence** | the anchor node, plus the `postgres.startup` node when the anchor is the authentication node (which carries the role as identity) |
| **Recommendation** | `Review this endpoint's host-based access rules for the role this run used and for the address this run connected from` |

**The claim is about this connection attempt, never about the identity in
general.** `28000` arrives before any `AuthenticationXXX`, so nothing
authenticated and no material was evaluated; the summary's "this connection" and
"before evaluating any credential" are both load-bearing and neither may be
generalized.

**It is the only finding whose vantage dependence is directly proved rather than
merely not-excludable.** The mechanism is known and documented — `pg_hba.conf`
matches the source address to select the decision — so a reader is being told
something specific rather than being warned of an unquantified possibility. The
floors at codes 2, 9 and 12 are `true` for the weaker ground 2, and the record
keeps the two apart deliberately.

The class exists precisely to keep this apart from a rejected credential
(`domain/failureclass.go`): *"your credential is wrong" sends a reader to a
secret store; "you may not attempt this from here" sends them to a host-based
access rule or a network policy.* The finding is the user-facing half of that
distinction, and losing it would send a reader to the wrong place.

### 10. `POSTGRES_CREDENTIALS_REJECTED`

| | |
|---|---|
| **Trigger** | step is `postgres.authentication`; state is FAIL; class is `AUTH_CREDENTIALS_REJECTED`. **The class alone is sufficient** — see §10.1 |
| **Claim** | *The endpoint refused the authentication material svcdoctor presented.* |
| **Summary** | `The PostgreSQL endpoint rejected the authentication material svcdoctor presented` |
| **Detail** | the endpoint answered the proof with its own invalid-password code; that response is byte-identical for a wrong secret, an unknown role, a corrupted proof and a correct secret that needed Unicode preparation, and the endpoint issues it that way deliberately so a client cannot enumerate roles |
| **Must not claim** | that the password is wrong; that the credential is invalid; that the role exists; that the role does not exist; that an account is enabled, disabled or locked; that the endpoint's authentication backend was healthy; that the credential would be refused from another source |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `false` |
| **Evidence** | the `postgres.authentication` node, plus the `postgres.startup` node — which carries the role as an identity attribute |
| **Recommendation** | `Verify the credential configured for this endpoint and the role it is meant to authenticate as; the endpoint's own log is the only place a wrong secret and an unknown role are distinguished` |

The summary wording is taken verbatim from
`domain.FailureAuthCredentialsRejected`'s own definition — *"the peer refused the
authentication material it was presented"* — rather than paraphrased as "rejected
the credential", which leans toward *the credential is wrong* and is the exact
inference the must-not-claim list forbids.

#### 10.1 The class alone is sufficient, because the producer was corrected

An earlier draft required `postgres.sqlstate == "28P01"` as a fourth conjunct,
because `AUTH_CREDENTIALS_REJECTED` then had a producer pointing the other way.
**Phase 4.6a.5 removed that producer instead** (§5.1), which is the better repair:
a predicate clause would have worked around a class that was lying, and the class
is what other services read.

Every production producer of the class was audited and all are direction A —
*the peer refused the authentication material svcdoctor presented*:

| Producer | Meaning |
|---|---|
| `postgres` · `28P01` | PostgreSQL's own `invalid_password`, asserted by the peer |
| `postgres` · server-final `e=invalid-proof` | the peer declined the proof, in SCRAM's vocabulary |
| `postgres` · server-final `e=unknown-user` | the peer declined it, there being no principal to verify against |
| `kafka` · `SASL_AUTHENTICATION_FAILED` | the broker refused what it was presented |

So the finding now fires for `28P01` **and** for the two SCRAM refusal tokens,
which is correct: all three are the peer refusing, and none is stronger than the
claim. The SQLSTATE remains on the node as evidence when the peer sent one; it is
no longer part of the predicate.

**The guard moved rather than disappeared.** What is now pinned is the
*direction contract* — a dedicated producer test asserting that
`ErrServerSignatureMismatch` yields `AUTH_PEER_VERIFICATION_FAILED` and never
`AUTH_CREDENTIALS_REJECTED`, and that `ErrSCRAMRejected` yields the converse.
That guard sits in the adapter, where the mapping lives, and it catches the
collapse a diagnosis-level SQLSTATE clause could only paper over. See §25 O.

### 11. `POSTGRES_PEER_VERIFICATION_FAILED`

| | |
|---|---|
| **Trigger** | `postgres.authentication` is FAIL with `AUTH_PEER_VERIFICATION_FAILED` |
| **Claim** | *This endpoint could not prove its knowledge of the authentication material.* |
| **Summary** | `The PostgreSQL endpoint failed authentication proof verification` |
| **Detail** | states that the mechanism authenticates both parties; that the endpoint accepted the material svcdoctor presented and then presented a value of its own that did not verify against the configured credential; and that the observation does not say why |
| **Must not claim** | that the credential was rejected; that the credential is wrong or right; that the endpoint is malicious; that anything sits on the network path; that the endpoint is not PostgreSQL; that the root cause is known |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `true` — ground 1 (§6.1) |
| **Evidence** | the `postgres.authentication` node, plus the `postgres.startup` node |
| **Recommendation** | `Verify the credential configured for this endpoint, and establish what this endpoint is before presenting the credential again` |

#### 11.1 The wording, and the four sentences it refuses

The summary is the narrowest operator-readable sentence available. Everything
shorter is wrong in a specific way:

| Rejected wording | Why |
|---|---|
| *"the credential was rejected"* | inverted — the endpoint **accepted** the material; a server-final is only sent after the proof verifies |
| *"the endpoint is not who it claims to be"* | a conclusion about identity from one failed check |
| *"a man-in-the-middle was detected"* / *"possible interception"* | names a cause the evidence cannot distinguish from a peer that simply does not hold the credential, or from a defective implementation |
| *"the password is wrong"* | the credential is not what failed verification here; the **peer's** value is |

"failed authentication proof verification" says who failed (the endpoint), what
failed (its proof), and nothing else. Severity is `ERROR` and not `CRITICAL`:
`CRITICAL` means severe **or broad** impact, and this record refuses breadth
claims — svcdoctor measured one endpoint (§6).

#### 11.2 Why it is vantage-dependent, and why that is ground 1

An element on the path can answer in the endpoint's place; an element on a
different path cannot. So the answer can differ between two positions reaching
the **same concrete peer**, which is the §6.1 test met by a documented mechanism
rather than by an unexcludable possibility.

The flag says *this was observed from here* and leaves the cause open, which is
the honest scope and also the useful one: it points at re-observing from another
position, which is the observation that would actually narrow it.

#### 11.3 What this replaces

Until Phase 4.6a.5 this slot held `POSTGRES_SCRAM_EXCHANGE_FAILED`, a
**provisional** code whose claim — *the SCRAM exchange did not complete, and the
evidence does not say which party refused* — existed only because the producer
collapsed the two directions into `AUTH_CREDENTIALS_REJECTED`.

**That producer defect was corrected instead of being carried** (§5.1), so the
evidence now separates the directions structurally and the weakened claim is no
longer necessary. The provisional code is removed rather than renamed: it never
reached a consumer, and its meaning is not the meaning of the code replacing it.

The mechanism name is deliberately absent from the code. `SCRAM` in a public
identifier would tie it to one mechanism, and the claim is a property of mutual
authentication generally — the same reason `internal/domain` names no mechanism.

### 12. `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`

| | |
|---|---|
| **Trigger** | `postgres.authentication` is FAIL with `AUTH_MECHANISM_NOT_OFFERED`, **or** UNKNOWN with `AUTH_MECHANISM_UNSUPPORTED` |
| **Claim** | *The PostgreSQL endpoint and svcdoctor have no authentication mechanism in common for this connection.* |
| **Summary** | `The PostgreSQL endpoint and svcdoctor have no authentication mechanism in common for this connection` |
| **Detail** | names what the endpoint demanded or advertised, read from `postgres.auth_method` and `postgres.sasl_mechanisms` on the startup node, and states that **no credential was presented**, so nothing is known about it |
| **Must not claim** | that the credential is wrong or right; that the endpoint is misconfigured; that another client would also fail; that the endpoint's configuration is at fault, or that svcdoctor's is |
| **Kind / confidence** | `CONFIRMED` / `HIGH` |
| **Severity** | **`WARN` when the node is FAIL; `INFO` when the node is UNKNOWN** |
| **Vantage** | `true` — ground 1 (§6.1) |
| **Evidence** | the `postgres.authentication` node and the `postgres.startup` node |
| **Recommendation** | FAIL: `Check which SASL mechanisms this endpoint advertises for the role this run used and from the address this run connected from`. UNKNOWN: `Diagnose this endpoint with a client that performs the authentication method it demands, or configure a mechanism svcdoctor performs for the role this run used` |

#### 12.1 Why one code, and why the severity varies

An earlier draft of this record split these into two codes by *whose gap it is* —
`AUTHENTICATION_MECHANISM_NOT_OFFERED` for the peer and
`AUTHENTICATION_UNSUPPORTED` for svcdoctor. **That axis is a moving property of
svcdoctor, not of the target**, and putting it in the public contract is the
"implementation detail disguised as a code" failure:

```text
SCRAM-SHA-1-only peer   NOT_OFFERED today; PASS if svcdoctor ever adds SHA-1
-PLUS-only peer         UNSUPPORTED today; PASS if svcdoctor adds channel binding
```

A consumer branching on the pair would see findings **migrate between codes on a
svcdoctor upgrade with no change to the target**, which makes the branch unstable
and therefore wrong to write. `docs/FINDINGS.md` §2 requires a code's semantics
to stay stable once exposed; a boundary that moves with svcdoctor's own
capability cannot satisfy that.

The claim is stable in both directions: *there is no mechanism in common*. The
**whose-gap distinction survives structurally and losslessly** on the cited
node's `State` and `FailureClass` — `FAIL`/`AUTH_MECHANISM_NOT_OFFERED` versus
`UNKNOWN`/`AUTH_MECHANISM_UNSUPPORTED` — which is where a consumer should read
it, per `docs/FINDINGS.md` §3.1 item 13. Nothing is lost that a machine needs.

**Severity varies because the impact does, even though the claim does not.** A
peer that positively offers nothing svcdoctor performs is a fact about the target
worth acting on: `WARN` — not `ERROR`, because nothing here proves the operator's
own client cannot authenticate. A mechanism svcdoctor has not implemented is a
gap in the tool: `INFO`, because `docs/ARCHITECTURE.md` and `domain/state.go`
both require that an unsupported capability is never reported as a failure of the
inspected thing, and grading a tool gap higher would spend the target's severity
budget on svcdoctor's own coverage. The evidence `State` carries the same
distinction structurally, so severity and state agree by construction rather than
by coincidence.

The `-PLUS`-only tie-break the adapter makes is preserved intact: it produces
`UNKNOWN`/`AUTH_MECHANISM_UNSUPPORTED` and therefore `INFO`, so a channel-binding
gap in svcdoctor is still not reported as the server's problem.

### 13. `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`

| | |
|---|---|
| **Trigger** | `postgres.authentication` is UNKNOWN with `EXEC_UNSUPPORTED_BY_SVCDOCTOR` |
| **Claim** | *svcdoctor could not complete the authentication this endpoint required, because the required operation is outside its supported capability. The credential was neither accepted nor rejected.* |
| **Summary** | `svcdoctor could not complete the authentication this PostgreSQL endpoint required` |
| **Detail** | states that svcdoctor performs SCRAM-SHA-256 over printable-ASCII passwords and a bounded PBKDF2 iteration count and declines the rest, and ends with the sentence that matters: **the credential was neither accepted nor rejected** |
| **Must not claim** | that the endpoint failed; that the credential is wrong or right; that the endpoint is misconfigured; that the mechanism was unavailable |
| **Kind / severity / confidence** | `CONFIRMED` / `INFO` / `HIGH` |
| **Vantage** | `true` — ground 1 (§6.1): the claim names *the authentication this endpoint required*, and what it required is `pg_hba`-selected by source |
| **Evidence** | the `postgres.authentication` node, plus the `postgres.startup` node |
| **Recommendation** | `Re-run against a role whose password is printable ASCII, or diagnose this endpoint with a client that implements the full mechanism` |

**This is deliberately not merged with §12, and the distinction is the claim
rather than the blame.** In §12 there is no mechanism in common. Here **the
mechanism was available and was performed** — svcdoctor understood it, began it,
and declined to complete it for an explicit limitation of its own. Today those
limitations are the printable-ASCII password restriction (ADR 0038) and the
`wire.MaxSCRAMIterations` ceiling; any future limitation of the same shape —
mechanism understood and begun, completion declined for a stated implementation
reason — belongs here rather than in §12.

`INFO` for the reason §12's UNKNOWN half is `INFO`: this is a gap in svcdoctor,
not a defect in the target. Dropping the finding entirely was considered and
rejected — a user with a non-ASCII password would get a bare `UNKNOWN` node and
no explanation, collapsing *not measured* into *not proven*, which
`docs/FINDINGS.md` §3.1 item 3 forbids.

### 14. `POSTGRES_CREDENTIAL_WITHHELD`

| | |
|---|---|
| **Trigger** | `postgres.authentication` is SKIPPED with `EXEC_SKIPPED_BY_POLICY` |
| **Claim** | *svcdoctor did not present the credential, because this connection did not satisfy the credential-transport policy. Zero credential-derived bytes were sent.* |
| **Summary** | `svcdoctor withheld the credential because this connection did not meet the credential-transport policy` |
| **Detail** | names what the connection proved by pointing at the blocker — the `postgres.ssl_request` node on a plaintext path, the `tls.handshake` node on an unverified-TLS one — and states that the run's policy requires a verified TLS channel before a password crosses it |
| **Must not claim** | that authentication would have succeeded; that authentication would have failed; that the endpoint refused anything; anything at all about the credential |
| **Kind / severity / confidence** | `CONFIRMED` / `WARN` / `HIGH` |
| **Vantage** | `false` |
| **Evidence** | the `postgres.authentication` node **and its `blockedBy` node** |
| **Recommendation** | `Establish a verified TLS channel to this endpoint before presenting a credential, or re-run with the transport policy this run is meant to use` |

`WARN`: a real problem — the channel available to this run cannot carry a
credential — that is not currently breaking anything, because svcdoctor's own
refusal prevented it.

This is the only finding that reads a `blockedBy` edge, and it is the case the
edge exists for: the claim is *why nothing was attempted*, and the answer lives
on a different node. `docs/FINDINGS.md` §3.1 item 11 forbids citing a blocked
step as a **cause**; here the blocked step is the *subject* and its blocker is the
cause, which is the same rule read correctly.

It is mutually exclusive with `POSTGRES_TLS_DECLINED` by construction: a declined
`SSLRequest` under a required-TLS plan kills the session at L3, so `Startup`
records a SKIPPED node and `Authenticate` is never called — there is no
authentication node to anchor at. Asserted by a composition test, not assumed.

### 15. `POSTGRES_AUTHENTICATION_FAILED` — the L5 authentication floor

| | |
|---|---|
| **Trigger** | `postgres.authentication` is FAIL and no escalation in §9–§12 matched |
| **Claim** | *The PostgreSQL authentication exchange did not complete successfully.* |
| **Summary** | `The PostgreSQL authentication exchange did not complete successfully` |
| **Detail** | class-gated on exactly the terms of §8.1: the verbatim untranslated SQLSTATE when present, the `error_is_native` observation when `false`, and the attribution sentence **only** when the class is `PROTOCOL_UNEXPECTED_RESPONSE` |
| **Must not claim** | that the credential was rejected; that the credential is correct; that the endpoint rejected anything; that the role exists or does not; that a database is missing; that a pooler, proxy or named product answered |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `true` — ground 2 (§6.1) |
| **Evidence** | the `postgres.authentication` node, plus the `postgres.startup` node |
| **Recommendation** | `Review this endpoint's authentication log for the role this run used` |

**This is where `08P01` lands**, and turning it into a credential finding is the
single mutation this record most needs to fail (§25 A). ADR 0038's amendment B
established why at the producer, and the same argument holds one layer up:
`08P01` proves the exchange ended with the peer's generic error code, and
inferring a refused credential from it is a hypothesis about a cause.

"did not complete successfully" is the whole claim. It carries no agency: the
trigger includes malformed frames and peer closes, where nothing was rejected by
anyone.

### 16. `POSTGRES_DATABASE_NOT_FOUND`

| | |
|---|---|
| **Trigger** | `postgres.session` is FAIL with `RESOURCE_NOT_FOUND`, **and** the session node's parent is a PASS `postgres.authentication` node or a PASS `postgres.startup` node with `postgres.auth_method="ok"` |
| **Claim** | *This endpoint completed authentication and then reported that the database this run requested is not available.* |
| **Summary** | `PostgreSQL reported that the requested database is not available` |
| **Detail** | the endpoint accepted the connection's authentication and then refused it with the code whose own meaning is an absent database; **several distinct conditions produce that code** — no catalog row, a row that disappeared during the lookup, and a catalog row whose files are missing — so the absence is reported and its cause is not |
| **Must not claim** | that the database never existed; that it was deliberately dropped; that it was renamed; that it should be created; that the endpoint's catalog is healthy; that its storage is healthy; that the root cause is known; that a real PostgreSQL backend answered |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `false` |
| **Evidence** | the `postgres.session` node, the `postgres.startup` node (which carries the requested database as an identity attribute), and the parent that establishes the authentication half |
| **Recommendation** | `Verify that the database name this run requested exists and is available at this endpoint` |

#### 16.1 The code and the prose deliberately differ in word strength

**This is intentional and must not be "fixed" in either direction.**

- The **FindingCode** names PostgreSQL's own assertion. `3D000` is
  `ERRCODE_UNDEFINED_DATABASE`; the peer's own errcode name is absence, and the
  service-neutral class is literally `RESOURCE_NOT_FOUND`. `NOT_FOUND` mirrors
  both.
- The **prose** must stay valid across all three conditions the code covers:
  normal absence, concurrent disappearance, and catalog/filesystem
  inconsistency. "is not available" is true of all three; "does not exist" is not.

Renaming the code to `UNAVAILABLE` was considered and rejected: it would make the
code **weaker than the peer's own assertion**, which is a different inaccuracy
rather than a smaller one, and it would desynchronise the code from the
`FailureClass` for no gain. A code and the text beside it are different contracts
(`docs/FINDINGS.md` §2), and this is the case that shows why.

The recommendation deliberately stops short of `CREATE DATABASE`: the corruption
variant makes creating it the wrong action, and svcdoctor cannot tell the cases
apart. "Verify … exists and is available" is true advice under all three.

The parent requirement is the contrast half of the claim, in the same sense
ADR 0034 §11 requires both halves: without it the finding asserts "completed
authentication" without citing anything, and on a `trust` path a rule that
demanded an authentication node would silently stop firing (study §2.2).

**A rule keyed on this must not assume it fires.** Behind a pooler the same
condition arrives at `postgres.startup` as `08P01` and is reported by §8. That is
the model degrading to a weaker true claim, which is the intended behaviour.

### 17. `POSTGRES_DATABASE_CONNECT_DENIED` and `POSTGRES_SESSION_ESTABLISHMENT_FAILED`

Both anchor at `postgres.session` and both carry the same parent requirement as
§16.

**`POSTGRES_DATABASE_CONNECT_DENIED`** — trigger: FAIL with `AUTHZ_DENIED`.

| | |
|---|---|
| **Claim** | *This endpoint completed authentication and then denied this session `CONNECT` access to the requested database.* |
| **Summary** | `The PostgreSQL endpoint denied this session CONNECT access to the requested database` |
| **Must not claim** | a table, schema or function privilege denial; a denied write; missing role membership; that superuser is required; anything about the credential; that authentication failed |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `false` — `CONNECT` is a catalog ACL per role per database, not per source address |
| **Evidence** | the session node, the startup node, and the parent |
| **Recommendation** | `Review the CONNECT privilege on the requested database for the role this run used` |

The claim is exactly as narrow as the evidence: ADR 0039 §9 established that of
`postinit.c`'s three `ERRCODE_INSUFFICIENT_PRIVILEGE` sites, only
`CheckMyDatabase`'s `CONNECT` check is reachable, because the other two need a
startup option svcdoctor does not send. No other privilege check can have run —
svcdoctor issues no statement. The summary says "this session" rather than "the
authenticated role" because on a `trust` path no credential was presented and
"authenticated" would be the wrong word.

**`POSTGRES_SESSION_ESTABLISHMENT_FAILED`** — the L5 session floor. Trigger: FAIL
and no escalation matched.

| | |
|---|---|
| **Claim** | *This endpoint completed authentication and then did not bring the session to `ReadyForQuery`.* |
| **Summary** | `The PostgreSQL session did not reach ReadyForQuery after authentication completed` |
| **Detail** | class-gated on exactly the terms of §8.1 |
| **Must not claim** | that the endpoint is out of connections; that it is shutting down; that it is in recovery; any translation of the SQLSTATE; that a real PostgreSQL backend answered |
| **Kind / severity / confidence** | `CONFIRMED` / `ERROR` / `HIGH` |
| **Vantage** | `true` — ground 2 (§6.1) |
| **Evidence** | the session node, the startup node, and the parent |
| **Recommendation** | `Review this endpoint's log for the session it accepted and then closed` |

**`53300` gets no translation.** ADR 0039 §10 declined to add a capacity class
for it — one producer and no authorizing record is not enough to grow a
service-neutral vocabulary — and this record declines the matching finding for
the same reason. "PostgreSQL is out of connections" is what the message says and
not what the evidence contract proves; a pooler reports its own `max_client_conn`
limit as `08P01`, and svcdoctor cannot distinguish exhaustion at the endpoint
from exhaustion behind it.

### 18. Proxy transparency: "endpoint", never "server", and never a product name

svcdoctor does not know whether it is talking to PostgreSQL, pgBouncer, HAProxy,
Envoy or a cloud proxy, and no observation available to it settles the question.

> **Every PostgreSQL finding says "the PostgreSQL endpoint". "PostgreSQL server"
> is forbidden, and naming a proxy product is forbidden.**

"Server" claims a backend. `postgres.error_is_native` is the one structural,
non-prose signal, and it is weak in exactly one direction: its **presence** is
consistent with a genuine backend since 9.6, and its **absence** is consistent
with a pooler, a proxy, or a pre-9.6 server. A finding may state that absence as
the observation it is (§8, §15, §17) and may not conclude a peer implementation
from it.

The measured reason this is not pedantry: **pgBouncer served a complete passing
session with its PostgreSQL backend stopped.** Any sentence of the form "the
PostgreSQL backend is healthy / is reachable / is up" would have been false on
that run, and it is a stock configuration rather than an adversarial one.

#### 18.1 `postgres.error_is_native` is an observation and never an input

Normative, because this attribute is the most tempting thing in the graph.

> **Where `postgres.error_is_native` appears in a finding's detail, it is an
> observed property of the response and nothing else.**

It **does not**:

- change which `FindingCode` is produced;
- change `kind` — no finding becomes a `HYPOTHESIS` because of it, and none
  becomes `CONFIRMED` because of it;
- change `confidence` — it is an *indirect* signal, and confidence is `HIGH` on
  the strength of the direct evidence for the claim, which this is not part of
  (§6.2);
- change `severity`;
- justify a stronger cause, at any layer of the record;
- identify pgBouncer, HAProxy, Envoy, a cloud proxy or any other product;
- identify PostgreSQL directly, or establish that a genuine backend answered.

The only permitted rendering is the fact itself: *the response did not carry the
non-localized severity field a PostgreSQL backend has sent since 9.6*. Its
absence is equally consistent with a pooler, a proxy and a pre-9.6 server, so
concluding anything from it would be inventing a peer identity — the exact
failure §1 exists to prevent. A guard (§23 G8) asserts that no rule branches on
it.

### 19. A passing PostgreSQL path produces **zero** findings

`postgres.session` PASS produces no finding of any kind, and specifically no
statement that a backend is healthy, reachable, writable, primary or replica.

This matches the only precedent the repository has — `internal/diagnosis/kafka`
produces nothing for a healthy cluster — and the report is not thereby silent:
`domain.Report` derives its summary from the graph, `firstBrokenLayer` included,
and every PASS node is in it. Findings are for what a reader must act on.

`ReadyForQuery` from a pooler with a dead backend produces the same zero
findings, which is correct: svcdoctor established a PostgreSQL-protocol session
at that endpoint, and that is all that happened.

### 20. Replica and read-only facts are out of scope for Phase 4.6

`postgres.in_hot_standby`, `postgres.default_transaction_read_only`,
`postgres.is_superuser`, `postgres.transaction_status` and
`postgres.server_version` are recorded, are in the report, and **no rule reads
them**.

The reason is the Phase 4.5a measurement: on a real streaming standby,
`in_hot_standby` was `on` while `default_transaction_read_only` was `off`. A
session on a standby is read-only because of *recovery*, not because that GUC is
set, so a rule reading the GUC alone would call a replica writable. The parameter
that actually answers "can I write here" is the session-local
`transaction_read_only`, which is not sent as a `ParameterStatus` and would
require SQL — which ADR 0039 §17 forbids and an AST guard enforces.

A narrower `POSTGRES_ENDPOINT_IN_RECOVERY` from `in_hot_standby="on"` alone was
considered and **rejected for this phase** on two grounds. It would be the
repository's first success-path finding, which is a policy question about what
findings are *for* and not PostgreSQL's to settle alone; and it has no actionable
half, because without run intent there is no notion of "the operator wanted a
primary" — the same missing fact that keeps `internal/diagnosis/transport` empty.

**Reopen when** either svcdoctor executes SQL under a record that authorizes it,
or run intent becomes expressible, or a second non-SQL fact arrives that
distinguishes a writable session.

### 21. Determinism

Same graph in, same bytes out, always. Four mechanisms, none of them new:

1. Each rule iterates `Graph.Nodes()`, which returns canonical order, so a rule's
   own output is ordered before anything sorts it.
2. `diagnosis.Engine.Diagnose` applies `domain.SortFindings`, which is the same
   total order `domain.NewReport` applies: severity descending, layer ascending,
   code ascending, subject ascending, summary ascending, joined evidence
   references ascending. Rule wiring order cannot reach the output.
3. `domain.NewFinding` deduplicates and sorts `EvidenceRefs`, so a finding is
   byte-stable however the rule collected them.
4. **No rule may iterate a Go map to build prose or references.** Anything
   collected from a map or a traversal is sorted first (`docs/FINDINGS.md` §3.1
   item 18).

No new ordering policy is introduced, and none is needed: existing precedent
already makes the order total.

### 22. Package boundary, and what Phase 4.6b may create

Repository precedent, unchanged:

```text
internal/service/postgres/     NEW — a leaf vocabulary: constants, no behaviour
internal/diagnosis/postgres/   NEW — four rules, twelve codes
```

Not `internal/service/postgres/diagnose.go`: diagnosis rules live in
`internal/diagnosis/<service>/` (`docs/ARCHITECTURE.md` §6), and
`internal/service/<service>/` is the leaf both layers may import — the exact
arrangement ADR 0034 §19 authorized for Kafka, for the exact same reason, which
is that depguard denies diagnosis the adapter import.

Data flow, and the boundary it preserves:

```text
adapter:    bytes -> observations -> evidence        (protocol lives here)
diagnosis:  frozen Graph -> predicates -> Finding[]  (no protocol, no I/O)
```

**`internal/service/postgres` holds exactly eight constants**, each authorized
because a rule genuinely reads it, and each **moved** from
`internal/adapter/postgres` rather than copied — a second copy would be one fact
with two representations:

```text
StepSSLRequest       "postgres.ssl_request"      §7
StepStartup          "postgres.startup"          §8, §9, and every parent citation
StepAuthentication   "postgres.authentication"   §9–§15
StepSession          "postgres.session"          §16, §17

AttrSSLOffered       "postgres.ssl.offered"      §7 predicate
AttrAuthMethod       "postgres.auth_method"      §13 detail, §16/§17 trust-path parent test
AttrSQLState         "postgres.sqlstate"         §10/§11 predicate, §8/§15/§17 detail
AttrErrorIsNative    "postgres.error_is_native"  §8/§15 detail
```

Nothing else moves. `postgres.tls.plan`, `postgres.sasl_mechanism`,
`postgres.scram_iterations`, `postgres.protocol_version`, `postgres.role`,
`postgres.database`, `postgres.error_severity` and every session parameter stay
in the adapter, because no authorized rule reads them. The step names are already
part of the report contract and their string values do not change.

Moving these constants is the **only** change Phase 4.6b makes to
`internal/adapter/postgres`, and it changes no behaviour.

### 23. Guards: diagnosis cannot reach a secret, a wire type, or a peer's prose

Most of this is already true and enforced; the new work is stating it where the
next reader will look and closing the two gaps.

**Already enforced by depguard** for `**/internal/diagnosis/**`:
`internal/security` (so `security.Reveal` is unreachable — the credential, the
secret, the nonce, the salt and the proof with it), `internal/adapter` (so
`internal/adapter/postgres/wire` is unreachable), `internal/probe`,
`internal/render`, `internal/platform`, `net`, `net/http`, `crypto/tls`, `os`,
`os/exec`, `math/rand`, `math/rand/v2`.

**Already enforced by forbidigo**, repository-wide: `security.Reveal`,
`security.ChannelTLS*`, `security.ChannelPlaintext`.

**Already true structurally**: an `ErrorResponse` `M`, `D`, `H`, `F`, `L` or `R`
field cannot reach a rule, because it never crosses the wire boundary — only `C`
and `V` are decoded into evidence at all. A rule cannot decode a SQLSTATE frame,
because it receives no bytes.

**`**/internal/service/**` is already covered** by the existing
`service-vocabulary-is-a-leaf` depguard rule, so `internal/service/postgres`
inherits it on creation with no configuration change.

**Phase 4.6b must add**, as package-local tests in `internal/diagnosis/postgres`,
mirroring `internal/diagnosis/kafka/boundary_test.go`:

| # | Guard | Fails when |
|---|---|---|
| G1 | AST: the package's production imports are exactly `internal/domain`, `internal/service/postgres`, and standard-library packages from a fixed allowlist | any other import appears |
| G2 | AST: the set of `domain.AttributeKey` values referenced is exactly the four in §22 | a rule starts reading a fifth attribute without a record |
| G3 | AST: no string literal beginning `postgres.` appears — every step and key comes from the vocabulary package | a rule re-spells a contract string |
| G4 | Within **the twelve primary codes of §6**, every code is produced by exactly one predicate and no two predicates match one node (§3) | two primary findings could fire on one node |
| G5 | Every `postgres.*` FAIL node in the producible-shape fixture matrix yields exactly one **primary** finding (§4 totality) | a failed node produces silence |
| G5b | A `postgres.session` FAIL node whose parent fails the §16 test produces **no** finding, and the fixture is labelled as a shape no producer emits | a rule invents the authentication half of its claim |
| G8 | No rule branches on `postgres.error_is_native`: it is read only to select a detail sentence, and the produced code, kind, severity and confidence are identical for both values on an otherwise identical node (§18.1) | an indirect signal starts steering a claim |
| G9 | The producer direction contract holds: `AUTH_CREDENTIALS_REJECTED` has only direction-A producers, and `AUTH_PEER_VERIFICATION_FAILED` only direction-B ones (§5.1, §10.1). Enforced in `internal/adapter/postgres`, where the mapping lives | the two directions are normalized back together |
| G6 | Every finding's summary, detail and recommendations are unchanged when every host, address, role and database in the fixture is replaced | prose carries identity structure already carries |
| G7 | No SQLSTATE appears in prose translated — the only permitted rendering is the five characters verbatim | a rule turns `53300` into English |

G6 is the redaction bar `docs/BACKLOG.md` Phase 4.6b already asks for, stated
here as a guard rather than a wish: prose that must be rewritten to be shareable
will leak the day someone edits it.

**G4 and G5 are scoped to the twelve primary codes, deliberately.** They must not
be written as "no node ever carries two findings": §3 explains why a future
complementary finding on the same node is legitimate, and a guard phrased over
*all* findings would fail the day one is added and would then have to be weakened
under pressure — the worst possible moment to be re-deciding a policy.

### 24. Acceptance matrix

The canonical table Phase 4.6b tests are written against. "—" means **no
finding**, and every "—" is a decision rather than an omission.

| # | Evidence | Expected finding |
|---|---|---|
| 1 | `ssl_request` FAIL `PROTOCOL_UNSUPPORTED_CAPABILITY`, `ssl.offered=false` | `POSTGRES_TLS_DECLINED` |
| 2 | `ssl_request` FAIL `PROTOCOL_UNEXPECTED_RESPONSE` (`E` answer) | — (§7, gap) |
| 3 | `ssl_request` SKIPPED `EXEC_SKIPPED_BY_POLICY` (`disabled` plan) | — |
| 4 | `tls.handshake` FAIL, any class (unknown CA, hostname mismatch, expired) | — (§2; not PostgreSQL's, and no generic rule is authorized) |
| 5 | `tls.handshake` SKIPPED, blocked by `ssl_request` | — (a blocked step is never a cause) |
| 6 | `dns.lookup` or `tcp.connect` FAIL | — (§2) |
| 7 | `startup` FAIL `AUTHZ_NOT_PERMITTED` (`28000`) | `POSTGRES_CONNECTION_NOT_PERMITTED` |
| 8 | `startup` FAIL `PROTOCOL_UNEXPECTED_RESPONSE`, `sqlstate=08P01`, `error_is_native=false` | `POSTGRES_STARTUP_FAILED`, detail **with** the attribution sentence and **with** the native-field observation |
| 9 | `startup` FAIL `PROTOCOL_UNEXPECTED_RESPONSE`, `sqlstate=57P03` | `POSTGRES_STARTUP_FAILED`, detail **with** the attribution sentence and the verbatim SQLSTATE — svcdoctor does not translate `57P03` |
| 9b | `startup` FAIL `PROTOCOL_PEER_CLOSED` | `POSTGRES_STARTUP_FAILED`, detail **without** the attribution sentence (§8.1) |
| 9c | `startup` FAIL `PROTOCOL_MALFORMED_RESPONSE` | `POSTGRES_STARTUP_FAILED`, detail **without** the attribution sentence (§8.1) |
| 10 | `startup` FAIL `PROTOCOL_UNSUPPORTED_VERSION` (`0A000`) | `POSTGRES_STARTUP_FAILED`, detail **without** the attribution sentence — the class already names a stronger fact, so "cause unknown" would be false (§8.1) |
| 11 | `startup` FAIL, `sqlstate=3D000` | `POSTGRES_STARTUP_FAILED` — **never** database-not-found |
| 12 | `startup` FAIL, `sqlstate=42501` | `POSTGRES_STARTUP_FAILED` — **never** connect-denied |
| 13 | `startup` SKIPPED `EXEC_SKIPPED_PREREQUISITE_FAILED` | — |
| 14 | `auth` FAIL `AUTH_CREDENTIALS_REJECTED`, `sqlstate=28P01` | `POSTGRES_CREDENTIALS_REJECTED` |
| 15 | `auth` FAIL `AUTH_CREDENTIALS_REJECTED`, **no** `sqlstate` (server-final `e=invalid-proof`) | `POSTGRES_CREDENTIALS_REJECTED` — the class is direction-A-only, so no SQLSTATE is required (§10.1) |
| 15b | `auth` FAIL `AUTH_CREDENTIALS_REJECTED`, **no** `sqlstate` (server-final `e=unknown-user`) | `POSTGRES_CREDENTIALS_REJECTED` — same direction, same claim |
| 15c | `auth` FAIL `AUTH_PEER_VERIFICATION_FAILED` (server signature mismatch) | `POSTGRES_PEER_VERIFICATION_FAILED` — **never** credentials-rejected (§5.1) |
| 15d | `auth` FAIL `PROTOCOL_UNEXPECTED_RESPONSE` from server-final `e=invalid-username-encoding` | `POSTGRES_AUTHENTICATION_FAILED` — an encoding fault is not a rejection (§5.1) |
| 16 | `auth` FAIL `PROTOCOL_UNEXPECTED_RESPONSE`, `sqlstate=08P01` | `POSTGRES_AUTHENTICATION_FAILED` — **never** credentials-rejected |
| 17 | `auth` FAIL, `sqlstate=3D000` | `POSTGRES_AUTHENTICATION_FAILED` |
| 18 | `auth` FAIL, `sqlstate=42501` | `POSTGRES_AUTHENTICATION_FAILED` |
| 19 | `auth` FAIL `AUTHZ_NOT_PERMITTED` (`28000`) | `POSTGRES_CONNECTION_NOT_PERMITTED` |
| 20 | `auth` FAIL `AUTH_MECHANISM_NOT_OFFERED` | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`, severity **WARN** |
| 21 | `auth` UNKNOWN `AUTH_MECHANISM_UNSUPPORTED` (md5, cleartext, gss, `-PLUS`-only) | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`, severity **INFO** |
| 21b | Rows 20 and 21 compared | **same code, different severity** — the claim is identical, the impact is not (§12.1) |
| 22 | `auth` UNKNOWN `EXEC_UNSUPPORTED_BY_SVCDOCTOR` (non-ASCII password, iteration ceiling) | `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`, severity INFO — **never** mechanism-unavailable (§13) |
| 23 | `auth` SKIPPED `EXEC_SKIPPED_BY_POLICY` | `POSTGRES_CREDENTIAL_WITHHELD` |
| 24 | `auth` UNKNOWN `EXEC_LOCAL_TIMEOUT` or `EXEC_CANCELLED` | — (§25 note) |
| 25 | `session` FAIL `RESOURCE_NOT_FOUND` (`3D000`), parent PASS auth | `POSTGRES_DATABASE_NOT_FOUND` |
| 26 | `session` FAIL `RESOURCE_NOT_FOUND`, parent PASS startup `auth_method=ok` (trust) | `POSTGRES_DATABASE_NOT_FOUND` |
| 27 | `session` FAIL `AUTHZ_DENIED` (`42501`) | `POSTGRES_DATABASE_CONNECT_DENIED` |
| 28 | `session` FAIL `PROTOCOL_UNEXPECTED_RESPONSE`, `sqlstate=53300` | `POSTGRES_SESSION_ESTABLISHMENT_FAILED` — **never** an out-of-connections claim |
| 29 | `session` FAIL `PROTOCOL_PEER_CLOSED` | `POSTGRES_SESSION_ESTABLISHMENT_FAILED` |
| 30 | `session` PASS | — (§19) |
| 31 | `session` PASS from a pooler with the backend stopped | — (§19) — **no backend-health claim of any kind** |
| 32 | `session` UNKNOWN `EXEC_LOCAL_TIMEOUT` | — |
| 32b | `session` FAIL with a parent that is not a PASS authentication node and not a PASS startup node with `auth_method=ok` | — (§4 precondition; a shape no producer emits) |
| 33 | pgBouncer, missing database: `startup` FAIL `08P01` pre-auth | `POSTGRES_STARTUP_FAILED` only (rows 8 and 11 restated end to end) |
| 34 | Healthy end-to-end graph, TLS + SCRAM + `ReadyForQuery` | — (zero findings) |
| 35 | Any two rows differing **only** in `error_is_native` | identical code, kind, severity and confidence; only the detail differs (§18.1, guard G8) |

Every row additionally asserts the finding's `vantageDependent` value against the
table in §6.1. Six of the twelve are `true`, and a row that produced the right
code with the wrong flag is a failing row.

**Rows 24 and 32 are policy, not an oversight.** A local timeout or a cancelled
run is svcdoctor's own budget expiring; nothing was learned about the target, and
a finding would dress that as the endpoint's fault. The summary already reports
unknown counts. This is `internal/diagnosis/kafka`'s rule for the same situation,
applied unchanged.

### 25. Mutation matrix for Phase 4.6b

Each mutation must be **really applied, must compile, must be caught by the named
test, and must be restored**. A mutation that does not compile is not a passing
guard.

| # | Mutation | Must be caught by |
|---|---|---|
| A | `08P01` at `postgres.authentication` produces `POSTGRES_CREDENTIALS_REJECTED` | acceptance row 16 |
| B | The `3D000` predicate is moved to a step-independent check | acceptance rows 11, 17 |
| C | The `42501` predicate is moved to a step-independent check | acceptance rows 12, 18 |
| D | `startup` `08P01` is classified as a missing database when the run named one | acceptance rows 11, 33 |
| E | A PASS `postgres.session` produces any finding | acceptance rows 30, 31, 34 |
| F | `default_transaction_read_only="off"` produces a writable-endpoint finding | §20 scope test: the rule package references no session-parameter attribute (guard G2) |
| G | The `POSTGRES_DATABASE_NOT_FOUND` recommendation is changed to name `CREATE DATABASE` | recommendation-wording contract test |
| H | The `POSTGRES_CREDENTIALS_REJECTED` prose is changed to say the password is wrong | summary/detail wording contract test |
| I | `internal/diagnosis/postgres` imports `internal/adapter/postgres/wire` | depguard, and guard G1 |
| J | A rule calls `security.Reveal` | forbidigo, depguard, and guard G1 |
| K | A second finding is produced for the same node — a `POSTGRES_TLS_FAILED` beside a generic TLS failure, or two predicates matching | guards G4 and G5 |
| L | Finding assembly iterates a `map` instead of `Graph.Nodes()` | determinism test: the same graph encoded twice, byte-identical, over repeated runs |
| M | A finding's detail interpolates an `ErrorResponse` message field | structurally impossible — the guard is that no such field exists on `domain.Evidence`; the test asserts the authorized attribute set (G2) and that no PostgreSQL prose constant exists (G3) |
| N | `08P01` is classified by protocol position into a hidden root cause — "we sent a proof and got an error, so the credential was refused" | acceptance rows 8, 16, 33, and a dedicated weakest-true-claim test asserting that the two `08P01` rows produce different codes and neither names a cause |
| **O** | **The two authentication directions are collapsed back into one `FailureClass`** — `ErrServerSignatureMismatch` mapped to `AUTH_CREDENTIALS_REJECTED` | **The producer direction contract**, `TestCredentialRejectionIsDirectionalAndSoIsItsClass` in `internal/adapter/postgres`, which asserts both directions positively and both negatively. Already applied, compiled and confirmed caught in Phase 4.6a.5 |
| O2 | `e=invalid-username-encoding` is folded back into the rejection branch | the same test's `PROTOCOL_UNEXPECTED_RESPONSE` row. **Note:** the naive edit does not compile — Go rejects the duplicate case — so the mutation must also delete the dedicated branch, which was verified |
| O3 | `28P01` is mapped away from `AUTH_CREDENTIALS_REJECTED` | `TestOnlyThePeersOwnCodeProducesACredentialClaim` |
| O4 | `AUTH_PEER_VERIFICATION_FAILED` is collapsed into `PROTOCOL_UNEXPECTED_RESPONSE` | the direction contract, and acceptance row 15c |
| O5 | A signature-shaped value is added to the authentication node's attributes | `TestPeerVerificationFailureRecordsNoSCRAMValue`, which pins the attribute set exactly |
| P | The floor attribution sentence is made unconditional, so it also renders for `PROTOCOL_UNSUPPORTED_VERSION`, `PROTOCOL_MALFORMED_RESPONSE` and `PROTOCOL_PEER_CLOSED` | acceptance rows 9b, 9c and 10 |
| Q | `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` is given one fixed severity | acceptance rows 20, 21 and 21b |
| R | `EXEC_UNSUPPORTED_BY_SVCDOCTOR` is folded into `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE` | acceptance row 22 |
| S | A rule branches on `postgres.error_is_native` to select a code, kind, severity or confidence | guard G8 and acceptance row 35 |
| T | Any `vantageDependent` value is flipped | the per-row vantage assertion in §24, against the §6.1 table |
| U | `POSTGRES_STARTUP_FAILED`'s summary is reworded to say the endpoint *rejected* the exchange | the wording contract test — the trigger includes `PROTOCOL_PEER_CLOSED` and `PROTOCOL_MALFORMED_RESPONSE`, where nothing rejected anything (§8) |

Mutation M deserves its note: the prose field cannot be reached, so the guard
proves the *absence of a path* rather than catching a value. That is the stronger
property and it is why ADR 0036 refused to store server prose at all.

**Mutations O through O5 were applied for real in Phase 4.6a.5**, not merely
planned: each was written into the tree, compiled, confirmed to fail the named
test, and restored. O2 is the instructive one — the obvious edit does not
compile, and a mutation that does not compile proves nothing, so it had to be
written properly before it counted.

They live at the **producer**, not at the predicate. An earlier draft guarded
this at the diagnosis layer with a mandatory SQLSTATE clause; correcting the
class made that clause unnecessary and moved the guard to where the mapping
actually is. Twenty-five mutations in total, each verified to compile before it
is trusted.

### 26. What this policy does not own

Boundaries, so the finding set does not become a bucket:

- **Generic DNS, TCP and TLS diagnosis.** §2. Still blocked on run intent
  (ADR 0017), unchanged by this record. **This is now tracked as a
  product/CLI release gate rather than only as an architectural consequence** —
  see §26.1.
- **TLS verification quality** — an untrusted CA, a hostname mismatch, an expired
  certificate on a PostgreSQL endpoint. ADR 0034 §14 assigned this to a future
  TLS-consistency policy and it stays there. A `POSTGRES_TLS_*` finding over the
  `tls.handshake` node would add nothing the node does not already state, which
  is the duplicate test.
- **`postgres.ssl_request` failures other than a decline** — an `E` answer, a
  malformed reply, a peer close. No finding, recorded as a gap: an `E` answer is
  a peer refusing to negotiate and is worth a claim, but it is rare enough that
  no measurement exists and this record does not authorize findings for shapes it
  has not seen.
- **Replica, read-only, superuser and version facts.** §20.
- **Capacity and availability.** §17. ADR 0039 §10 declined the class; this
  record declines the matching finding.
- **Peer implementation identification.** §18. `postgres.error_is_native` is
  stated and never concluded from.
- ~~**Distinguishing which party refused a SCRAM proof.**~~ **Now owned and
  resolved** — Phase 4.6a.5 made the distinction structural at the producer
  (§5.1), which is why §11 is a stable code rather than a provisional one.
- **Why the peer failed proof verification.** A peer that does not hold the
  credential, an intermediary answering in its place, and a defective
  implementation are indistinguishable from the wire. The finding names the
  observation and stops (§11.1).
- **Cross-endpoint correlation**, and any claim about a deployment rather than an
  endpoint. svcdoctor measured one endpoint.

#### 26.1 The generic transport gap is a product release gate, not Phase 4.6b scope

The architecture decision stands and is not to be worked around: PostgreSQL
diagnosis does not own `dns.lookup`, `tcp.connect` or `tls.handshake` (§2).
**Phase 4.6b must not "fix" this**, and a `POSTGRES_*` finding on any of those
nodes is an architecture violation rather than an improvement.

The honest consequence is stated plainly:

> **A PostgreSQL run that fails at DNS, TCP or TLS currently produces complete
> evidence, a correct `summary.firstBrokenLayer`, and zero actionable findings.**

That is correct architecture and incomplete product UX, and the two must not be
confused for each other. It is also the *common* failure mode — a name that does
not resolve, a refused port, an untrusted certificate — so a first-time user
meeting it sees a report that reads as broken. Kafka is in the identical position
for a failed bootstrap path, so this is consistency rather than a new hole.

> **Release gate: before the first usable CLI/product release, the repository
> must decide the owner of generic transport diagnosis for user-requested
> endpoints.**

It is a gate rather than a task because the blocker is a fact, not effort: it
needs run intent — *is this a PostgreSQL diagnosis or a bare endpoint check?* —
which `diagnosis.Rule` cannot see, receiving only a `Graph` (ADR 0017). Tracked
in `docs/BACKLOG.md` outside Phase 4.6b scope.

## Rejected alternatives

| Alternative | Verdict |
|---|---|
| **A global `switch failureClass` producing findings** | **Rejected.** It is the central enumeration `docs/FINDINGS.md` §1 and ADR 0009 both refuse, in a new shape: `RESOURCE_NOT_FOUND` will mean something else for the next service, and a shared table would make that an edit here. §5 |
| **A `POSTGRES_TLS_*` finding for certificate failures** | **Rejected as a duplicate** by ADR 0034 §3's test: the finding would add nothing the `tls.handshake` node already states. The cost is honest — no finding fires — and it is ADR 0017's gap, not a new one. §26 |
| **Deriving a cause from `08P01` by protocol position** | **Rejected, and it is the trap.** pgBouncer emits it for at least six unrelated conditions at two different steps, and its own source says it is the substitute for a NULL sqlstate. This was rejected once already at the producer (ADR 0038 amendment B); rejecting it again one layer up is the whole point of §1 |
| **Two codes split by whose gap it is — `AUTHENTICATION_MECHANISM_NOT_OFFERED` for the peer, `AUTHENTICATION_UNSUPPORTED` for svcdoctor** | **Rejected, and this record previously got it wrong.** That boundary is a moving property of svcdoctor: a `SCRAM-SHA-1`-only peer changes codes if svcdoctor adds SHA-1, and a `-PLUS`-only peer changes codes if svcdoctor adds channel binding. A consumer's branch would be invalidated by a svcdoctor upgrade with no target change, which `docs/FINDINGS.md` §2 forbids. Merged into `POSTGRES_AUTHENTICATION_MECHANISM_UNAVAILABLE`, with the distinction carried losslessly by the node's `State` and `FailureClass` and by severity. §12.1 |
| **Merging `EXEC_UNSUPPORTED_BY_SVCDOCTOR` into the mechanism code, because both are svcdoctor gaps** | **Rejected.** Whose gap it is is not the axis; the claim is. In §12 there is no mechanism in common; in §13 the mechanism was available and performed, and svcdoctor declined to complete it. Two claims, two codes. §13 |
| **`POSTGRES_STARTUP_REJECTED` as the L4 floor's code** | **Rejected on review.** The floor's trigger includes `PROTOCOL_PEER_CLOSED` and `PROTOCOL_MALFORMED_RESPONSE`, where nothing rejected anything, so the name attributes agency the evidence does not carry. Renamed `POSTGRES_STARTUP_FAILED`. §8 |
| **An unconditional "svcdoctor could not attribute a cause" sentence on every floor** | **Rejected on review.** It is false for `PROTOCOL_UNSUPPORTED_VERSION`, `PROTOCOL_MALFORMED_RESPONSE` and `PROTOCOL_PEER_CLOSED`, each of which already names a stronger fact. Understating the evidence is a different error from overstating it and is still an error. Class-gated instead. §8.1 |
| **`vantageDependent: false` on the floors** | **Rejected on review.** `false` is a positive assertion of position-independence (`finding.go`), and a floor that deliberately does not attribute a cause cannot exclude a source-keyed one — pgBouncer's `auth_type=hba` among them. §6.1 ground 2 |
| **`vantageDependent: false` on the mechanism findings** | **Rejected on review.** `pg_hba.conf` selects the authentication METHOD by matching the connecting source, so what the endpoint demands is a function of where svcdoctor connected from. §6.1 ground 1 |
| **Renaming `POSTGRES_DATABASE_NOT_FOUND` to `…_UNAVAILABLE`** | **Rejected.** It would make the code weaker than the peer's own `ERRCODE_UNDEFINED_DATABASE` assertion and desynchronise it from `RESOURCE_NOT_FOUND`, for no gain. The conservatism belongs in the prose, which is a different contract. §16.1 |
| **"One PostgreSQL node, one finding" as a permanent invariant** | **Rejected on review.** A security-posture claim on the same node would be *complementary* under ADR 0034 §3, not a duplicate. Rescoped to the primary Phase 4.6 diagnosis set so the engine is not frozen against future independent findings. §3 |
| **One `POSTGRES_CREDENTIALS_REJECTED` covering the no-SQLSTATE case, under the old producer** | **Rejected then, and moot now.** It was false whenever the producer was `ErrServerSignatureMismatch`. Phase 4.6a.5 removed that producer from the class instead, so the class-only predicate became correct — §5.1, §10.1 |
| **Shipping `POSTGRES_SCRAM_EXCHANGE_FAILED` as a provisional public code** | **Rejected on review.** It existed only to work around a producer that collapsed two directions, and a public code is the wrong place to carry a producer defect. Correcting the producer cost one generic `FailureClass` and a two-branch split, and retired the code entirely. §11.3 |
| **Distinguishing the directions with an attribute instead of a class** | **Rejected.** An attribute cannot repair a class that states the opposite of what happened, and other services read the class. §5.1 |
| **`PROTOCOL_UNEXPECTED_RESPONSE` for the server-signature mismatch** | **Rejected.** The only existing class that is not false, and it re-collapses the case with pgBouncer's `08P01` and with malformed frames — losing exactly the distinction the correction exists to make, and filing a mutual-authentication failure as a generic protocol hiccup. §5.1 |
| **A PostgreSQL- or SCRAM-specific class name** | **Rejected.** The concept is a property of mutual authentication, not of one protocol. `internal/domain` names no mechanism, so Kafka SCRAM reaches the same class unchanged. §5.1 |
| **A `POSTGRES_ENDPOINT_IN_RECOVERY` INFO finding** | **Rejected for this phase.** Provable, and it would be the repository's first success-path finding, which is a policy question wider than PostgreSQL — and it has no actionable half without run intent. §20 |
| **A capacity finding for `53300`** | **Rejected.** The message says "out of connections"; the evidence contract does not, and a pooler reports its own limit as `08P01`. §17 |
| **Engine-level duplicate suppression** | **Rejected**, as ADR 0034 §3 rejected it: suppression keyed on undocumented identity. `diagnosis.Engine` does not deduplicate and must not start. Ownership is resolved by anchoring. §3 |
| **One exported rule per finding code, as Kafka has** | **Rejected here**, on twelve codes across four anchors: mutual exclusivity would become twelve pairwise proofs instead of a structural property. §3 |
| **Findings for `EXEC_LOCAL_TIMEOUT` and `EXEC_CANCELLED`** | **Rejected.** Nothing was learned about the target; a finding would dress svcdoctor's own budget as the endpoint's fault. §24 |

## Consequences

- Phase 4.6b implements twelve codes in four rules, and invents nothing: every
  trigger, claim, prohibition, severity, vantage flag, evidence set and
  recommendation boundary is fixed above.
- `internal/service/postgres` and `internal/diagnosis/postgres` are created;
  eight constants move out of `internal/adapter/postgres` and no behaviour
  changes with them.
- A PostgreSQL run that fails at DNS, TCP or TLS still produces no findings. The
  gap is visible and attributed to ADR 0017 rather than absorbed.
- Behind a connection pooler, most PostgreSQL runs will produce
  `POSTGRES_STARTUP_FAILED` or `POSTGRES_AUTHENTICATION_FAILED` rather than a
  specific finding. That is the model degrading to a weaker true claim, and it
  is the intended behaviour rather than a shortfall to be engineered away.
- Seven of the code set are `vantageDependent: true`, four on a proven mechanism
  and three because position-independence cannot honestly be asserted. A reader who
  expected the Kafka ratio should read §6.1 before assuming a copy error.
- **No code in the set is provisional.** The one that would have been was
  retired by correcting its producer instead (§5.1, §11.3).
- One `FailureClass` was added, 38 → 39. It is generic, names no mechanism, and
  is available to Kafka SCRAM unchanged when Phase 3.2d unblocks.
- No report schema change, no `AttrKind`, no redaction change, no new dependency,
  no new `security.Reveal` site, no new `FailureClass`.

## Reopen conditions

- ~~**A wire-boundary fact separating the two `AUTH_CREDENTIALS_REJECTED`
  directions.**~~ **Resolved in Phase 4.6a.5** by adding
  `AUTH_PEER_VERIFICATION_FAILED` and splitting the producer (§5.1). No error
  string is parsed, then or now.
- **A second mechanism reaches `AUTH_PEER_VERIFICATION_FAILED`** — Kafka SCRAM
  when Phase 3.2d unblocks, say. Then confirm the class stayed generic and that
  no mechanism name crept into `internal/domain`.
- **Run intent becomes expressible** — then generic transport diagnosis unblocks
  (ADR 0017), §2's gap closes from the other side, and §20's recovery finding
  gains its actionable half.
- **svcdoctor executes SQL under a record that authorizes it** — then the
  read-only and writability questions become answerable rather than guessable.
- **A measured `E`-shaped `SSLRequest` answer** — then §26's gap gets a finding.
- **A second peer-implementation signal beyond `postgres.error_is_native`** —
  then §18 can be revisited; one weak signal is not enough to name a peer.
- **A managed PostgreSQL service is measured** (RDS, Aurora, Cloud SQL, Azure) —
  and disagrees with the pooler model this record is built on.
- **Phase 4.8 produces a real end-to-end graph** that any acceptance row in §24
  does not describe.
- **The first complementary finding on a `postgres.*` node is proposed** — a
  security-posture or certificate-posture claim, say. Then §3's scoping and
  guards G4/G5 are exercised for the first time, and the record should confirm
  they held rather than assume it.
