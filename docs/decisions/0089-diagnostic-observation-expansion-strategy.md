# ADR 0089 — Diagnostic observation expansion: the frontier is presentation, not acquisition

- **Status:** Accepted
- **Date:** 2026-09-05
- **Phase:** 10.7A (architecture / archaeology; no production code)
- **Upholds:** ADR 0039 §17 (no SQL), **ADR 0040 §20 (replica and read-only facts reach no rule)**,
  ADR 0054 (owner before producer), ADR 0063 §11 and ADR 0066 (Redis command allowlist and
  prefix-only classification), ADR 0067/0069 §8 (RabbitMQ observation ceiling), ADR 0083 §2.6
  (declared intent frozen out of Phase 10), ADR 0085 §4 (an endpoint-reported fact is a renderer
  observation, not a claim), ADR 0086 §2.11, ADR 0087, ADR 0088
- **Supersedes:** nothing
- **Decision:** **ACTIVATE EXISTING OBSERVATION.** No probe, command, query, request or authority
  is added. §7.

---

## 1. Context

### 1.1 The question this phase was given

svcdoctor must stop optimizing for adapters, commands and finding codes, and start optimizing for
*the highest-value operator question answerable by the smallest, safest, most authoritative
additional observation*. Phase 10.7A asked which of the four service families — Kafka,
PostgreSQL, Redis/Valkey, RabbitMQ/LavinMQ — should be the first to acquire one, and whether any
should.

### 1.2 The measurement that decided it

Before generating a single candidate, the phase inventoried **every evidence attribute the four
adapters record** and asked, mechanically, which are read by a rule or a renderer:

| Service | Attributes recorded | Read by a rule | Read by a renderer | **Consumed by nothing** |
|---|---|---|---|---|
| Kafka | 14 | 2 | 1 | **10** |
| PostgreSQL | 17 | 5 | 3 | **9** |
| Redis/Valkey | 7 | 2 | 5 | **1** |
| RabbitMQ/LavinMQ | 21 | 2 | 15 | **4** |

**Twenty-four facts are already on the wire, already normalized, already in the report, and
consumed by nothing.** Before this phase, the plausible reading of "svcdoctor's diagnostic
frontier" was *acquisition*. It is not. The frontier is **consumption**, and the audit found no
candidate anywhere whose acquisition cost was justified while twenty-four already-paid-for facts
sit unread.

That reframing is the record's main contribution, and it decides §7.

### 1.3 The three acquisition classes, and why they must not be mixed

- **Class 1 — already measured, not diagnosed.** The fact is in evidence today. No new byte.
- **Class 2 — reachable by the current flow, never observed.** The code can classify it; no
  fixture has produced it. No new byte, but a real measurement is owed.
- **Class 3 — genuinely new observation.** A new request, command, query, connection or authority.

ADR 0054's *owner before producer* and ADR 0086 §2.11's *producer before engine* both point the
same way here: **exhaust Class 1, then Class 2, before Class 3.**

---

## 2. Operator questions and current answerability

The audit began from operator questions rather than protocol features. Answerability was decided
against repository code, never against protocol knowledge.

### 2.1 Kafka

| Operator question | Today |
|---|---|
| Bootstrap works — why can the application still not use the cluster? | **ANSWERED** — `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` (HYPOTHESIS/MEDIUM) plus per-endpoint `KAFKA_ADVERTISED_ENDPOINT_UNREACHABLE` |
| Are some advertised brokers unreachable from this vantage? | **ANSWERED** — `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`, three categories, never two |
| Is the failure isolated or widespread? | **ANSWERED** — the same aggregate carries completeness and contrast |
| Did I reach the expected auth boundary? | **ANSWERED** — `KAFKA_AUTH_MECHANISM_NOT_OFFERED` and the credential codes |
| Partition availability / leader / ISR? | **NOT ANSWERABLE — and not a Class 1 gap.** §3.1 |
| Controller / KRaft health? | **OUT_OF_SCOPE_BY_DESIGN** — ADR 0084 §7; the adapter measured `controller_id` returning 1,1,2,1,1,3,2,3 on a stable cluster |

### 2.2 PostgreSQL

| Operator question | Today |
|---|---|
| Did I reach a server in recovery? | **ANSWERED** — `in_hot_standby`, rendered as the `recovery` observation line (ADR 0085 §4) |
| Was admission refused before any credential? | **ANSWERED** — `POSTGRES_CONNECTION_NOT_PERMITTED`, plus `POSTGRES_ADMISSION_SCOPE` across addresses |
| Which connection limit applied? | **ANSWERED** — `POSTGRES_CONNECTION_LIMIT_REACHED`, direct authority |
| Am I talking to a pooler rather than PostgreSQL? | **OUT_OF_SCOPE_BY_DESIGN** — ADR 0040 §18: "endpoint", never "server", and never a product name |
| **The connection succeeds — will my writes work?** | **PARTIALLY_ANSWERED, and the partial answer misleads.** §3.2 |

### 2.3 Redis/Valkey

Every question in the inventory is `ANSWERED` or blocked, as Phase 10.6A established one commit
ago and re-verified here: primary/replica and standalone/cluster/sentinel are closed-set
observation lines; Sentinel is a finding; auth absent/required/rejected/ACL-denied are four
codes. Replication lag, cluster health and key ownership are `NOT_ANSWERABLE` and every route to
them is a build-forbidden command literal.

The one live item is Class 2: `LOADING`, `MASTERDOWN` and `BUSY` are reachable on `PING`,
classified from a closed prefix set, and **never observed by a fixture**. §5.

### 2.4 RabbitMQ/LavinMQ

Every question in the inventory is `ANSWERED` (SASL, vhost absent vs refused, capacity, terminal
non-settlement) or `OUT_OF_SCOPE_BY_DESIGN` under ADR 0069 §8's *what may not be said* table,
each item needing an operator-supplied expectation. Its four unconsumed attributes are the close
details the rule already keys on through the failure class the adapter derived from them; none is
a gap.

---

## 3. The two candidates that survived, and the one that did not

### 3.1 Kafka partition availability is **not** on the wire, and proving it mattered

The most attractive hypothesis entering the phase was that Kafka's `Metadata` response already
carries partition leaders and ISR, making an availability claim Class 1.

**It does not.** `internal/adapter/kafka/wire/metadata.go:116` sets
`request.Topics = []kmsg.MetadataRequestTopic{}` — empty, **not nil** — and the doc comment
states the consequence exactly: *"A nil slice would encode as null and mean 'every topic', so the
distinction is load-bearing and is pinned by a test: the difference between describing a cluster
and downloading its entire partition map is one field being empty rather than absent."*

So no partition, leader or ISR byte ever arrives. Obtaining one is **Class 3**, and it is the
worst-shaped Class 3 available: the minimum request that yields partition state for an unknown
application is *every topic*, which is a data-minimization violation (§18 of the brief), an
unbounded response, a fan-out multiplier across targets, and a source of topic names — tenant
identifiers — entering a shareable report. **Rejected, and the reason is recorded so the
hypothesis is not re-formed.**

Kafka's ten unconsumed attributes are protocol bookkeeping (`api_versions`, `request_api_version`,
counts) or already decided against (`controller_id`, measured unstable). Kafka has **no Class 1
candidate**.

### 3.2 PostgreSQL writability: the fact is present, the presentation is incomplete, and the
incompleteness points the wrong way

`internal/adapter/postgres/wire/session.go` retains exactly four `ParameterStatus` values;
`establish.go:504–507` puts all four into evidence on every successful session. Of the four:

| Attribute | Rule | Renderer |
|---|---|---|
| `postgres.in_hot_standby` | none, and none may (ADR 0040 §20) | **yes** — the `recovery` line, Phase 10.3 |
| `postgres.default_transaction_read_only` | none | **none** |
| `postgres.is_superuser` | none | none |
| `postgres.server_version` | none | none — deliberately, pending the observation-sanitization decision |

**The two writability facts are not the same fact, and the repository measured that.**
`establish.go:44` records it: *"Measured on a real standby: `in_hot_standby` was 'on' while this
was 'off'. A session on a standby is read-only because of recovery, not because this parameter is
set, so a rule reading only this one would call a replica writable. Both are recorded and neither
alone answers 'can I write here'."*

The consequence is the finding. Today the terminal prints **one** of the two, and prints it as
`recovery: not in recovery`. A session on a primary whose role or database carries
`ALTER ROLE … SET default_transaction_read_only = on` — a per-role setting invisible in
`postgresql.conf` and a classic cause of *"the app connects but writes fail"* — renders exactly
that line and nothing else. **The operator is shown the half of the answer that says "fine".**

This is Class 1: the value is already in the report's evidence, already normalized, already
redaction-safe. What is missing is that the presentation layer shows one of two facts a reader
needs together.

---

## 4. The conflict with ADR 0040 §20, stated rather than reinterpreted

ADR 0040 §20 is Accepted and directly on point. It names all five session facts, states that
**no rule reads them**, gives the standby measurement, records that the parameter which actually
settles writability is the session-local `transaction_read_only` — *not* sent as
`ParameterStatus` and obtainable only by SQL, which ADR 0039 §17 forbids and an AST guard
enforces — and rejects a narrower `POSTGRES_ENDPOINT_IN_RECOVERY` finding on two grounds: it
would be the repository's first success-path finding, and it has no actionable half without run
intent.

It gives three reopen conditions: SQL authorized by a record, run intent expressible, or **"a
second non-SQL fact arrives that distinguishes a writable session."**

**None has fired.** `default_transaction_read_only` is not a *new* fact — §20's own first
sentence names it. So:

> **A writability *finding* remains out of scope, and this record does not reopen ADR 0040 §20.**

What this record authorizes is at a different layer, and the layer distinction is one ADR 0085 §4
already drew and implemented for the sibling attribute: **the finding layer refuses and the
presentation layer shows the fact.** ADR 0040 §20 governs *rules*; the two guards that enforce it
— `TestTheRulesReadOnlyTheAuthorizedAttributes` (a four-key allowlist) and
`TestSessionFactsStayEvidenceAndNeverBecomeFindings` — are both scoped to rules and both stay
untouched and unweakened.

---

## 5. Redis Class 2, and why it loses on fixture determinism rather than on merit

`LOADING`, `MASTERDOWN` and `BUSY` remain the strongest Class 2 item in the tree: closed-set
prefixes, direct peer authority, byte-identical across Redis and Valkey, reachable on `PING`, and
today collapsed into one appended sentence in `REDIS_ENDPOINT_NOT_SERVING`'s `detail`. ADR 0088
deferred them on ADR 0069 §8's bar — *membership requires having watched a real endpoint produce
it*.

It loses to §3.2 on three grounds, and none of them is that it is unimportant:

- **Fixture determinism.** `BUSY` is producible (a blocking script), `MASTERDOWN` needs a replica
  plus a severed link, and `LOADING` needs a dataset large enough that a restart is observable —
  a race by construction. The PostgreSQL state is produced by one `-c` flag on a compose service,
  which is exactly how the existing fixture already configures its servers.
- **Finding inflation.** Making the three machine-readable plausibly costs a code split or a new
  failure class; the PostgreSQL activation costs **zero** new codes.
- **Frequency.** *"Why can't my application write?"* is asked more often than *"why did Redis
  answer BUSY?"*, and the PostgreSQL case has a silent variant — a per-role or per-database GUC —
  that an operator cannot see from the server's configuration file.

**Deferred, unchanged, on the condition ADR 0088 §2.5 already set.**

---

## 6. Analysis of the selected candidate

**Acquisition class:** Class 1. **Zero** new requests, commands, queries, connections, round
trips or bytes. The values arrive unsolicited in the `ParameterStatus` frames that already
precede `ReadyForQuery` on every successful session.

**Authority:** protocol-direct for what it is. A `ParameterStatus` frame is a protocol message
whose meaning the protocol defines, and both keys are `GUC_REPORT` parameters describing **this
session's own** current values — an application-visible fact (§21 of the brief), not a
configuration dump. It is *not* authority about the backend's identity; §6.4.

**Privilege delta: none.** Both arrive before any query is possible and require no grant, no
role membership, no `pg_monitor`, no system-view access.

**Credential authority: `SAME_AUTHORITY`.** No second credential, no elevated grant, no control
plane. The endpoint-bound credential model is untouched.

**Side-effect class: `PASSIVE`.** No session state changes, no transaction opens, no counter, no
log line, no lock, no cache effect. svcdoctor sends nothing extra.

**Round trips / fan-out: zero delta**, at any target count. A 512-target run costs exactly what
it costs today.

**Data sensitivity: minimal, and bounded by construction.** Both values are the two-token domain
`on`/`off`. The render function is a closed map — anything else yields the empty string and drops
the line — which is the discipline the `recovery` line already uses and the reason a hostile
endpoint cannot put bytes of its own choosing on a terminal through this path.

**Failure isolation:** trivially preserved, because there is nothing to fail. An absent parameter
already carries `Present: false` and simply produces no line. `in_hot_standby` is **PostgreSQL 14
and later**; on an older server it is absent and the line is omitted rather than defaulted.

**Compatibility:** `PROTOCOL_STANDARD` for `default_transaction_read_only`;
**`VERSION_GATED`** for `in_hot_standby` (PG14+), which the existing `Present` flag already
handles and the existing integration test already asserts.

### 6.4 Proxy and intermediary semantics — the sharpest constraint

`internal/service/postgres/vocabulary.go` already records it for `in_hot_standby`: *"A pooler
forwards a cached value, so nothing here distinguishes a replica from a primary that was in
recovery when the pooler cached."* The same applies to `default_transaction_read_only`, and more
so under transaction or statement pooling, where the next transaction may be served by a
different backend entirely.

**Therefore the frozen claim boundary is the session, never the server:**

> The endpoint reported these values **for the session svcdoctor established**. They are not a
> statement about a backend, a cluster role, or what any later connection will be given.

This is ADR 0040 §18's "endpoint, never server" rule applied to two more values, and it is what
keeps the activation truthful behind PgBouncer, Pgpool and every other intermediary.

### 6.5 Operator intent — fact, not fault

A read-only session may be exactly what the operator built. `default_transaction_read_only = on`
is a deliberate safety setting on reporting roles and read replicas. So the presentation states
**facts** and the finding layer stays silent, which is precisely ADR 0085 §4's arrangement. The
moment a claim would need *"this should have been writable"*, it is `INTENT_DEPENDENT` and
blocked by ADR 0083 §2.6.

**The two facts differ in strength and the prose must not merge them.** Recovery is not
overridable by the session; `default_transaction_read_only` is — a client may issue
`SET TRANSACTION READ WRITE`. Rendering them as one "read-only" verdict would flatten a real
distinction, and is forbidden.

---

## 7. Decision

**ACTIVATE EXISTING OBSERVATION.** Phase 10.7B completes PostgreSQL's session-state observation
line set by presenting `postgres.default_transaction_read_only` beside the existing `recovery`
line, in the mechanism ADR 0085 §4 already authorized and Phase 10.3 already built.

It is **not** an observation expansion, and naming it one would be false: no new protocol
interaction, no new authority, no new byte.

**No new `FindingCode`, and none is required.** Both facts are evidence today and stay evidence.
The report's JSON is unchanged; only the human-facing result block gains a line and the
conditional note beside it becomes truthful. `SchemaVersion` stays 1.

### 7.1 What is frozen for Phase 10.7B

| | |
|---|---|
| **Operator question** | *"The connection succeeded — will this application's writes work from here?"* |
| **Evidence gap** | Two facts answer it together and neither alone; the terminal presents one |
| **Observation** | none acquired; `postgres.default_transaction_read_only` is presented |
| **Acquisition class** | Class 1 |
| **Prerequisite step** | `postgres.session` PASS. No line on a run that never established a session |
| **Subject** | the session, never a backend or a role (§6.4) |
| **Authority** | protocol-direct about what the endpoint reported for **this session** |
| **Confidence ceiling** | not applicable — no finding is produced |
| **Credential authority** | `SAME_AUTHORITY` |
| **Privilege** | none |
| **Side-effect ceiling** | `PASSIVE` |
| **Budget** | zero delta, at any target count |
| **Compatibility** | `default_transaction_read_only` standard; `in_hot_standby` PG14+, absent ⇒ line omitted |
| **Redaction** | closed two-value render; a value outside the domain drops the line |
| **BASIC fallback** | **frozen: an absent or unrecognized parameter MUST NOT invalidate any BASIC evidence, finding, summary status or exit code.** It produces silence |
| **Forbidden stronger claims** | "this endpoint is a replica" · "the backend is read-only" · "your writes will fail" · "this is misconfigured" · merging recovery and the GUC into one verdict · any severity, any exit-code effect |
| **New `FindingCode`** | **no** |
| **New ADR for implementation** | **no** — this record is the authorization |

---

## 8. Consequences

- **No Phase 10.4C entry-gate candidate emerged.** The audit found no pair of mutually competing
  hypotheses; PostgreSQL produces zero `HYPOTHESIS` findings, and the selected candidate produces
  no finding at all. The gate stays closed.
- **No Phase 10.5B reopen candidate emerged.** Nothing here needs `CONTRADICTION`, `MISSING` or
  `BLOCKED`. ADR 0087's OUTCOME C stands.
- **ADR 0040 §20 is upheld, not reopened**, and its three reopen conditions are unchanged.
- `SchemaVersion` 1, `RunSchemaVersion` 1, **65** finding codes, 42 failure classes, 3
  `RuleContext` fields, 4 `Reveal`, 4 `SecretFor`, 2 modules, 5 exit codes — all unchanged.
- **The twenty-four unconsumed attributes are now inventoried** (§1.2). That inventory, not a
  protocol wish-list, is where the next several candidates should be drawn from.

---

## 9. Alternatives considered

**Kafka partition availability from `Metadata`.** Rejected: not on the wire (§3.1), and the
minimum request that would put it there is *every topic*.

**Kafka `DescribeCluster` or an Admin request.** Rejected: Class 3, plausibly a distinct ACL, and
it answers a question `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` already answers from the client
vantage — server-centric where svcdoctor is client-centric.

**PostgreSQL `SHOW transaction_read_only` or `SELECT pg_is_in_recovery()`.** Rejected. It is
Class 2/3 SQL that ADR 0039 §17 forbids and an AST guard enforces; `SHOW` and `SELECT` differ in
pooler compatibility and in whether a transaction is implied; and against a `ReadyForQuery`-bounded
session it would duplicate a fact already present. ADR 0040 §20's first reopen condition — SQL
authorized by a record — is the only route, and this phase does not take it.

**PostgreSQL `is_superuser` as an observation.** Rejected on data minimization and §17 of the
brief: no operator question in the inventory needs it, and publishing the privilege level of the
diagnostic role into a shareable report is a security surface with no diagnostic consumer.

**PostgreSQL `server_version` as a second observation line.** Rejected: it is unbounded
peer-controlled text, and the cross-service observation-sanitization decision Phase 10.3 opened
is still outstanding. Adding it would widen exactly the surface that decision exists to settle.

**Redis `ROLE`, `INFO replication`, `CLUSTER INFO`.** Rejected: build-forbidden literals, and
`HELLO` already yields mode and role from closed sets. Nothing was proven to be added.

**Redis transient-state activation (`LOADING`/`MASTERDOWN`/`BUSY`).** Deferred, on merit, losing
only on fixture determinism, finding-inflation cost and question frequency. §5.

**RabbitMQ channel operations, passive declaration, or the management API.** Rejected as three
distinct and increasingly severe surfaces that must never be grouped: a channel is
`SESSION_LOCAL_MUTATION` against a broker that currently negotiates `channel_max 1`; a passive
declare touches broker-visible state and needs `configure` permission; the management API is a
`CONTROL_PLANE_AUTHORITY` on a second protocol, a second port and a second credential that must
never silently reuse the AMQP one.

**Defer everything.** Rejected. Deferring is right when a candidate needs a measurement or an
authority the project does not have; here the fact is already measured, already in the report,
costs nothing, and its absence from the result block actively points an operator the wrong way.

---

## 10. Adversarial review of the selected candidate

Recorded because §33 of the brief requires the winner to be argued against.

**"This is observability theater."** It would be if it printed a fact nobody acts on. The
opposite holds: the *current* single line is the one that risks misleading, because
`recovery: not in recovery` beside silence reads as *writable*.

**"The report already contains both attributes."** True — a machine consumer reading the JSON can
already compute this, which is why no schema change and no finding code is proposed. What it
cannot do today is learn from the product that the two must be read together; nothing in the tree
says so outside an adapter comment.

**"A pooler could make it false."** The strongest objection, and it bounds the claim rather than
killing it: §6.4 fixes the subject as the session, never the server, and the value remains true of
what the endpoint said to this session.

**"An old PostgreSQL has no `in_hot_standby`."** Correct, and handled: `Present: false` already
drops the line. What must not happen is defaulting an absent value to `off`, which is why the
BASIC-fallback rule is frozen as silence.

**"Would an operator act differently?"** Yes. A reported read-only transaction default sends them
to a role or database `SET`; `in recovery` sends them to failover state. Those are different
investigations. **The exact rendering is not decided here** — this record fixes the claim boundary
and leaves the wording to the phase that writes it.

**"Is it too small to be a phase?"** It is small, and that is the point the brief makes in §28.
The project's value is truthfulness, not feature count, and the smallest step that removes a
misleading silence beats a larger step that adds a query.

**Surviving weakness, stated rather than hidden:** the `on` value has **never been produced by a
fixture**. Both PostgreSQL fixtures are default primaries. This is the same bar ADR 0088 applied
to Redis, and the candidate wins only because the state is deterministically producible with one
`-c default_transaction_read_only=on` flag — the mechanism the compose file already uses. **Phase
10.7B may not land without that fixture.**

---

## 11. Security implications

None introduced; the phase writes no Go, and the selected candidate acquires nothing.

The activation's own security properties: no credential involvement; no privilege escalation;
values bounded to a two-token domain and rendered through a closed map, so no peer-chosen byte
reaches a terminal; no raw response retained — `SessionParameters` is a four-field struct with no
map and no catch-all, which is what makes a fifth parameter structurally unleakable. Neither
value is identity: they name no role, database, host or path. `AttrKindIdentity` classification is
unchanged, and redaction is unaffected.

---

## 12. Compatibility implications

**None from this record.** Phase 10.7B adds no compatibility claim: the observation is presented
where present and omitted where absent, so no supported platform's grading moves.
`docs/COMPATIBILITY.md` is untouched by 10.7A and must stay untouched by 10.7B unless the fixture
work establishes a new tested claim.

---

## 13. Reopen conditions

| Item | Condition |
|---|---|
| A PostgreSQL **writability finding** | ADR 0040 §20's own three, unchanged: SQL authorized by a record, run intent expressible, or a second non-SQL fact that distinguishes a writable session. This record supplies none of them |
| Redis transient-state activation | ADR 0088 §2.5: a fixture that measures `LOADING`, `MASTERDOWN` or `BUSY` |
| Kafka partition availability | a record that authorizes a topic-scoped `Metadata` request, and answers the data-minimization, fan-out and topic-name-redaction questions §3.1 raises |
| Any PostgreSQL SQL | ADR 0039 §17's reopen path, with its own record and its own security review |
| RabbitMQ channel, passive declare, or management API | three separate records; never one |
| `server_version` as an observation line | the cross-service observation-value sanitization decision Phase 10.3 opened |
| The other 23 unconsumed attributes | each needs an operator question first, per §1.2's inventory |
