# ADR 0088 — Redis/Valkey and RabbitMQ/LavinMQ diagnostic intelligence: neither is selected

- **Status:** Accepted
- **Date:** 2026-09-05
- **Phase:** 10.6A (architecture / archaeology; no production code)
- **Upholds:** ADR 0054 (owner before producer), ADR 0063 §10 and §11, ADR 0065 §2 and §7,
  ADR 0066 (prefix-only classification), ADR 0069 §8, ADR 0083 §2.6 (declared intent frozen out
  of Phase 10), ADR 0086 §2.11 (producer before engine), ADR 0087 (relations stay deferred)
- **Supersedes:** **the second sentence of ADR 0069 §9 condition 3 only** — its claim that
  migrating Redis client-limit exhaustion onto `RESOURCE_LIMIT_REACHED` is *"a separate, allowed
  correctness fix"*. §6.1 states the replacement rule. The superseded text is left standing in
  ADR 0069 with a forward marker, per the practice ADR 0081's header records. Nothing else in
  ADR 0069 is affected: §9 conditions 1, 2 and 4, the §8 table and every §1–§7 decision stand,
  and the reopen condition itself is **re-gated, not withdrawn**.
- **Records without resolving:** the build-guard claim in
  `internal/service/rabbitmq/vocabulary.go`. §6.2. It is a test-only defect and this phase
  changes no test.

---

## 1. Context

### 1.1 The question, and why it is not the obvious one

Phase 10.2 gave Kafka service-owned diagnostic intelligence and Phase 10.3 gave PostgreSQL its
own. Redis/Valkey and RabbitMQ/LavinMQ have visibly less service-level *reasoning*, and
`docs/design/DIAGNOSTIC_INTELLIGENCE.md` §P still carries a **10.4** slot reading *"Redis/Valkey
+ RabbitMQ/LavinMQ: authn vs authz, vhost, protocol identity under timeout"*.

The naive reading is that two services are behind. Phase 10.6A asked the repository instead:
**does either family already expose enough authoritative wire evidence to support meaningful
diagnostic intelligence without adding a network probe?**

### 1.2 What the audit found, and it decides the record

**The 10.4 slot's own content is already implemented**, by Phases 7.5–7.7 and 8.2 rather than by
a Phase 10 phase:

| Design-doc 10.4 item | Where it already is |
|---|---|
| authn vs authz (Redis) | `REDIS_CREDENTIALS_REJECTED` vs `REDIS_COMMAND_NOT_PERMITTED` — `NOPERM` is `UNKNOWN`/`AUTHZ_DENIED`, never `FAIL` |
| authn vs authz (RabbitMQ) | `RABBITMQ_CREDENTIALS_REJECTED` vs `RABBITMQ_VHOST_ACCESS_REFUSED` |
| vhost | `RABBITMQ_VHOST_NOT_FOUND`, `RABBITMQ_VHOST_ACCESS_REFUSED`, `RABBITMQ_CONNECTION_NOT_PERMITTED`, `RABBITMQ_CONNECTION_NOT_ESTABLISHED` |
| protocol identity under timeout | `redis.hello` identity attributes plus `Result.Incomplete()`; `REDIS_PROTOCOL_NOT_ESTABLISHED` owns the non-answer |

Twenty of the tree's 65 finding codes are already Redis's (9) or RabbitMQ's (11), against Kafka's
15 and PostgreSQL's 21. **The gap is not a coverage gap.** What Kafka and PostgreSQL have that
these two lack is *aggregate* reasoning — completeness and contrast across several measured
subjects — and §3 shows why neither family can produce one today.

**Every candidate this phase weighed was already built, already forbidden by an Accepted record,
or has never been observed by any fixture.** Zero are admitted.

---

## 2. Decision

**Neither Redis/Valkey nor RabbitMQ/LavinMQ is selected. There is no Phase 10.6B.**

The design document's 10.4 slot is **closed by delivery, not by deferral**, and this record says
so, so that a future phase does not read it as an open opportunity.

### 2.1 The fact inventories are frozen as measured

**Redis/Valkey — BASIC sends exactly three commands**, proven from
`internal/adapter/redis/wire/conn.go`: `HELLO` (zero-argument constant), `AUTH` (one- or
two-argument, the operator's own form), `PING` (zero-argument constant). Nothing else exists,
and `TestNoRedisProductionFileNamesAForbiddenCommand` fails the build if `INFO`, `ROLE`,
`CLUSTER`, `COMMAND`, `SELECT` or fourteen others appear as a string literal in a Redis
production file.

| Observation | Kind | Source | Authority | Bounded? |
|---|---|---|---|---|
| `redis.mode` ∈ {standalone, cluster, sentinel} | direct | HELLO reply | peer self-description | closed set |
| `redis.role` ∈ {master, replica} | direct | HELLO reply | peer self-description | closed set; absent in sentinel mode, and the absence is meaningful |
| `redis.server`, `redis.server_version` | direct | HELLO reply | peer self-description, **configurable** (`extended-redis-compat`) | open strings, ≤128, charset-checked, recorded absent on failure |
| `redis.proto` | direct | HELLO reply | protocol | integer; always 2 |
| `redis.error_prefix` | direct | first token of an error reply | **svcdoctor's own constant**, never peer bytes | closed set of 23 + `UNRECOGNIZED` |
| `redis.auth_required` | derived | `Prefix == NOAUTH` on the credential-free HELLO | protocol | boolean |
| credential accepted / rejected | direct | `AUTH` → `+OK` / `WRONGPASS` | protocol | — |
| command authorized | direct | `PING` → `NOPERM` | protocol | — |

**Not knowable today:** replication lag or link state; keyspace size or memory; persistence
state; cluster topology, slot coverage or node inventory; which primary a replica follows;
whether a Sentinel's quorum is met; connected-client counts; configuration values; whether the
application's own commands would be permitted. Every one needs `INFO`, `ROLE`, `CLUSTER *` or
`CONFIG GET`, all of which are build-forbidden.

**RabbitMQ/LavinMQ — BASIC performs one direct AMQP 0-9-1 connection and nothing else.**
No management API, no passive declaration, no topology enumeration; a permanent test pins
management calls at zero and `channel_max` is negotiated to **1** with no channel ever opened.

| Observation | Kind | Source | Authority | Bounded? |
|---|---|---|---|---|
| `rabbitmq.amqp_version` | direct | `Connection.Start` | protocol | version tuple |
| `rabbitmq.mechanisms_offered` | direct | `Connection.Start` | protocol | **normalized set of recognized** mechanisms |
| `rabbitmq.anonymous_offered` | direct | `Connection.Start` | protocol | boolean |
| `rabbitmq.product`, `.version`, `.platform`, `.cluster_name` | direct | server properties | peer self-description | arbitrary strings; `cluster_name` is `AttrKindIdentity` |
| six `channel_max`/`frame_max`/`heartbeat` offered+selected | direct | `Connection.Tune`/`Tune-Ok` | protocol | integers |
| `rabbitmq.close_outcome`, `.reply_code`, `.peer_close_method`, `.graceful_close` | direct | `Connection.Close` | **svcdoctor's own handshake state** — which frame it was waiting for, which a hostile peer cannot change | closed outcome vocabulary, construct-and-compare |
| `rabbitmq.vhost`, `.vhost_defaulted` | operator input | the run's own flags | — | — |

**Not knowable today:** queue, exchange or binding existence; message counts, depths or rates;
consumer counts; cluster membership, partitions or quorum; node health, alarms or flow control;
policy or limit configuration; what the identity may do *inside* a vhost — RabbitMQ evaluates
configure/write/read at channel operations and svcdoctor opens no channel.

### 2.2 The aggregate shape is structurally unavailable, and that is the real finding

`KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and `POSTGRES_ADMISSION_SCOPE` are both
**completeness-and-contrast** aggregates over several measured subjects. Both Redis and RabbitMQ
composition roots *do* run the credential-free protocol stage on every resolved address and then
select exactly one path — so a graph with several `redis.hello` or several
`rabbitmq.connection_start` nodes is producible, and an aggregate is expressible in principle.

**No fixture has ever produced one.** Every Redis, Valkey, RabbitMQ and LavinMQ integration
scenario targets a single IP literal (`127.0.0.1`), which under ADR 0059 resolves nothing and
yields exactly one path. The aggregate would therefore be built over a shape this repository has
never measured, which is ADR 0054's *owner before producer* and ADR 0086 §2.11's *producer before
engine* pointing at the same thing.

### 2.3 The epistemic ceiling is the same one for both, and it is not a service problem

Every remaining candidate in both families fails on **declared operational intent**, which
ADR 0083 §2.6 froze out of the whole of Phase 10 and which ADR 0085 §5 confirmed nothing carries:

- `role=replica` needs an expected role. `mode=cluster` needs an expected topology.
  `server=valkey` needs an expected implementation. A version needs a supported-version policy.
- RabbitMQ's `heartbeat`/`frame_max`/`channel_max` need an operator-supplied expectation;
  ADR 0069 §8 states svcdoctor "has no basis for a 'good' value".
- `cluster_name`, node name and `product` need an expected-identity input.
- `ANONYMOUS` offered needs a posture contract; BASIC diagnoses reachability, not hardening.

This is the identical blocker Phase 10.3 hit for PostgreSQL and answered the same way: **the
finding layer refuses and the presentation layer shows the fact.** Redis reached that answer two
phases *earlier* — `redis.mode` and `redis.role` have been terminal observation lines with
conditional cluster and sentinel notes since Phase 7, which is the mechanism Phase 10.3 later
reused for `in_hot_standby`. There is nothing to port.

The one Redis observation that legitimately became a finding is `REDIS_ENDPOINT_IS_SENTINEL`, and
its exemption is precise and non-generalizable: **the operator typed `diagnose redis`, which
names a data endpoint, so the expectation was stated by the invocation itself.** No other Redis or
RabbitMQ observation has an expectation supplied that way.

### 2.4 The no-new-probe boundary, restated as a phase boundary

**Zero-cost candidates admitted: none.** Everything else weighed is a probe expansion and is
listed separately, permanently:

| Would need | For | Status |
|---|---|---|
| `INFO` | replication link, persistence, memory, clients | build-forbidden literal (ADR 0063 §10) |
| `ROLE` | authoritative replication role and offset | build-forbidden literal |
| `CLUSTER INFO` / `CLUSTER NODES` | slot coverage, node inventory | build-forbidden literal; ADR 0065 §2 |
| `CONFIG GET` | any configuration expectation | build-forbidden literal |
| management API (HTTP) | RabbitMQ queues, alarms, cluster state | pinned at zero calls by test |
| passive `queue.declare` / `exchange.declare` | resource existence | needs a channel; `channel_max` is 1 |

**A probe expansion may not be proposed in the same phase as zero-cost intelligence.** Each needs
its own architecture decision covering the command allowlist, the keyspace and code-execution
prohibitions, the ACL-log cost of extra attempts, and — for the management API — a second
protocol, a second port and a second credential authority.

### 2.5 What is deferred, and the exact observation each needs

| Deferred candidate | Reopens when |
|---|---|
| **`LOADING` / `MASTERDOWN` / `BUSY` become machine-readable** instead of one appended sentence in `REDIS_ENDPOINT_NOT_SERVING`'s `detail` | **a fixture measures one.** ADR 0069 §8's `VHOST_DOWN` rule is the bar and it applies here unchanged: *membership requires having watched a real endpoint produce it.* All three are source-derived from ADR 0066's reachability table and **no svcdoctor fixture has ever observed any of them.** The precedent for the lift itself is sound — Phase 10.3 did exactly this for `53300` — but a producer comes first |
| **A credential-free scope aggregate** over several resolved addresses, for either family | a fixture produces a multi-address run in which the addresses disagree — one requiring authentication and another not, one a Sentinel and another a data endpoint, one offering `PLAIN` and another not. §2.2 |
| Anything requiring an expected role, topology, version, identity or posture | the declared-intent phase ADR 0083 §2.6 and ADR 0085 §5 defer to. It applies to every service the instant it exists, so never as a side effect of a service phase |

### 2.6 Compatibility conclusions

Both families pass, and neither adds a constraint the audit had to work around.

**Redis and Valkey are safe to reason about identically.** ADR 0066 measured that the error
**prefixes** are byte-identical across both while the message *text* differs — Valkey
parameterizes the shared strings by server name — which is precisely why prefix-only
classification is the compatible choice and text classification is not. `mode` and `role` are the
same closed set, including `master` rather than `primary`. `TestNoProductionCodeBranchesOnImplementationName`
and `TestNoProductionCodeDoesVersionArithmetic` keep it that way.

**RabbitMQ and LavinMQ likewise.** The close templates were measured byte-identical across
RabbitMQ 3.13.7, 4.0.9, 4.2.0 and `main`, a mismatch degrades to `UNSPECIFIED` by construction,
and attribution authority is svcdoctor's own handshake state rather than anything the peer says.
LavinMQ's *values* differ where they may — `channel_max` 2048 against RabbitMQ's 2047,
`heartbeat` 300 against 60 — which is exactly why ADR 0069 §8 forbids a threshold on any of them.

Both are Level 3 in `docs/COMPATIBILITY.md` with committed fixtures. **No admitted candidate
means no new compatibility claim**, which is the safest possible outcome for a graded document.

---

## 3. Consequences

- **No Phase 10.6B.** The next diagnostic-intelligence phase must come from somewhere else.
- `SchemaVersion` 1, `RunSchemaVersion` 1, **65** finding codes, 42 failure classes, 3
  `RuleContext` fields, 4 `Reveal`, 4 `SecretFor`, 2 modules, 5 exit codes — all unchanged, and
  **no Go file changed**.
- **Phase 10.4C's entry gate stays closed.** Redis and RabbitMQ emit **zero** `HYPOTHESIS`
  findings and hold **zero** discriminators between them; every one of their 20 codes is
  `CONFIRMED`. No competing pair emerged, and none was manufactured.
- **Phase 10.5B is not reopened.** No candidate needed `CONTRADICTION`, `MISSING` or `BLOCKED`;
  ADR 0087's OUTCOME C stands untouched.
- `docs/design/DIAGNOSTIC_INTELLIGENCE.md` §P's 10.4 row should be read as **delivered**, not
  pending. This record is the authority for that reading.

---

## 4. Alternatives considered

**Select RabbitMQ for its vhost intelligence.** Rejected: it exists. `RABBITMQ_VHOST_NOT_FOUND`
and `RABBITMQ_VHOST_ACCESS_REFUSED` already make exactly the claim the phase brief named as
potentially strong — *authentication succeeded, and the requested virtual host was authoritatively
refused* — split into the two causes the protocol distinguishes, with `RABBITMQ_CONNECTION_NOT_PERMITTED`
for a refusal that is neither and `RABBITMQ_CONNECTION_NOT_ESTABLISHED` for an exchange that never
settled. Adding a fifth would be finding inflation.

**Add a RabbitMQ protocol-stage boundary finding.** Rejected under the value bar: `DIAG_FAILURE_BOUNDARY`
plus eleven service codes already say where the journey stopped and what the peer said about it.
A RabbitMQ-branded restatement adds no service-specific knowledge.

**Select Redis for the `LOADING`/`MASTERDOWN`/`BUSY` lift.** Deferred rather than rejected — it is
the strongest real candidate found, it needs no new probe, and its authority is direct. It fails
only on the producer bar, and §2.5 records the condition.

**Select Redis for role or mode intelligence.** Rejected, and it would fail the build:
`TestReplicaRoleProducesNoFinding` and `TestClusterModeProducesNoFinding` are permanent tests
asserting that these produce *nothing*, and `TestNoRedisFindingAssertsAnExpectation` scans every
finding's prose for expectation phrases.

**Read Redis error message text to recover the distinctions the prefix loses.** Rejected
permanently. ADR 0066 measured that Redis interpolates the caller's own arguments and the
username into error text, and that Valkey parameterizes the same strings by server name — so text
classification is both a redaction hazard and a compatibility break.

**Build the multi-address aggregate now, since both roots already measure every address.**
Rejected on §2.2: structurally expressible, never measured. Building it would be an engine over
an empty input.

**Record no ADR, since nothing was admitted.** Rejected. The audit freezes a service-selection
decision that binds later phases, closes the design document's 10.4 slot, states the
probe-expansion boundary, and corrects two records the tree disagrees with. A future agent asking
*"why is there no Redis intelligence phase?"* needs this to exist.

---

## 5. Security implications

None introduced; the phase writes no Go.

Four properties were re-verified because a diagnostic-intelligence phase is exactly where they get
lost, and all four hold:

- **No peer text crosses a wire boundary in either service.** Redis returns a constant from a
  closed set and discards the remainder of the error line; RabbitMQ compares against candidates it
  rendered itself and never returns the peer's `reply_text`.
- **The command allowlists are mechanically closed.** Redis's is three commands with a
  build-failing literal scan; RabbitMQ opens no channel and calls no management API.
- **Identity values stay redactable.** `rabbitmq.vhost` and `rabbitmq.cluster_name` are
  `AttrKindIdentity`; Redis's `server`/`version` are bounded and charset-checked, and a value
  failing either check is recorded **absent** rather than truncated.
- **Credential authority is unchanged**: one `Reveal` per service in its wire package, endpoint-bound,
  no discovered-endpoint inheritance, no adapter reading an environment variable or a file.

One thing this record makes harder to get wrong: `rabbitmq.anonymous_offered` looks like a
ready-made security finding. It is not one, permanently — ADR 0069 §8 classes it as posture rather
than reachability, and promoting it would put "this broker will accept an anonymous login" into a
shareable document as an assertion svcdoctor never tested by attempting one.

---

## 6. Two records the tree disagrees with

Both were found while proving the inventories in §2. The first is a **normative conflict** and is
superseded here; the second is a **test-only defect** and is recorded only.

### 6.1 ADR 0069 §9 condition 3 — superseded in part

The clause reads, verbatim:

> **A third service produces a capacity ceiling.** Redis answers `-ERR max number of clients
> reached` and currently folds it into `REDIS_ENDPOINT_NOT_SERVING`; migrating it onto
> `RESOURCE_LIMIT_REACHED` is a separate, allowed correctness fix and is not done here.

It is **normative, not speculation**: it sits in a numbered *Reopen conditions* list — the section
whose function is to state what a later phase may do — and it uses permission language,
*"allowed … correctness fix"*. Condition 2 beside it is explicitly gated (*"`541` is measured.
Then T7 may…"*); condition 3 carries no gate at all, which reads as standing authorization for a
mechanical follow-up.

**Two things are wrong with it, and they are independent.**

**The mechanism does not exist.** ADR 0066 measured that this reply carries a **bare `ERR`
prefix**, records that v1 therefore classifies it generically, and accepts the loss in as many
words: *"inventing a distinction the prefix does not carry is the error this record exists to
prevent."* Its §3 additionally refuses a message-fragment allowlist, on the ground that the one
fact such a list would recover is already recovered by the credential-free first `HELLO`. So the
migration cannot be performed without reading peer text that ADR 0066 forbids.

**The stated current behaviour is imprecise.** A connect-time reply arrives as the answer to
`HELLO`, and an `ERR` at that step is `Hello.Unsupported()` → `UNKNOWN` /
`PROTOCOL_UNSUPPORTED_CAPABILITY`. `diagnosis/redis.Hello` fires only on `FAIL`, so it produces
**no finding at all**. `REDIS_ENDPOINT_NOT_SERVING` is anchored at the `redis.ping` node and
requires an error there. Where the reply lands therefore depends on which step receives it, and
"currently folds it into `REDIS_ENDPOINT_NOT_SERVING`" is not what the code does at the step this
reply reaches.

**ADR 0066 does not already supersede the clause**, which is why this record must. ADR 0066
predates ADR 0069, never names `RESOURCE_LIMIT_REACHED` — the class did not exist until ADR 0069
created it — and carries no forward marker. The prohibition and the permission were written in
different records about different subjects and have never been read against each other until now.

#### The authoritative rule

> **Redis `RESOURCE_LIMIT_REACHED` may only be emitted when the wire evidence structurally and
> authoritatively identifies a resource limit.**
>
> **A generic `ERR` reply plus arbitrary server prose is insufficient.** The prefix is the only
> thing that crosses the wire boundary, and `ERR` is the generic prefix: it carries no capacity
> meaning, and the sentence that does is peer-controlled text ADR 0066 forbids reading.
>
> **Client-limit exhaustion therefore remains unclassified**, and is reported as whatever the
> generic `ERR` at its step already supports. svcdoctor states what the endpoint's prefix carried
> and infers no cause from it.

**This is a re-gating, not a permanent refusal.** ADR 0069 §9 condition 3 survives with a
condition it did not previously have: the question reopens the moment a **closed, structurally
authoritative signal** exists — a future Redis or Valkey release giving client-limit exhaustion
its own error prefix, which ADR 0066 already anticipates as *"additive and testable"*; or a
protocol or probe expansion, decided in its own record, that supplies the fact structurally. What
is refused is performing the migration on today's evidence, not the migration itself.

Nothing about `RESOURCE_LIMIT_REACHED` changes. It keeps its two producers — RabbitMQ's capacity
refusal and PostgreSQL `53300` — its definition, and its place in the 42-class vocabulary.

### 6.2 `internal/service/rabbitmq/vocabulary.go` claims a guard that does not exist

The comment above the six negotiation attributes reads, verbatim:

> All six are observations. There is no threshold svcdoctor could apply to any of them that would
> not be a policy invention, so no rule reads them and a guard fails the build if one does
> (ADR 0069 §8).

**The first half is true and was verified**: every rule in `internal/diagnosis/rabbitmq` was read,
and none reads `channel_max_offered`, `channel_max_selected`, `frame_max_offered`,
`frame_max_selected`, `heartbeat_offered` or `heartbeat_selected`. **The second half is false.**
No test in the tree scans that package for such a read; the only non-production references are
integration assertions and a renderer golden fixture. The same overstatement applies to
`rabbitmq.anonymous_offered`, whose comment says *"observation only, permanently"* with no
mechanical backing.

**The invariant is real and currently maintained by review, not by the build.** The comment
overstates enforcement, and a future author reading it would reasonably believe a violation cannot
land silently. It can.

**Not fixed here, and not chosen here.** This phase changes no Go and no test, and the closure has
two legitimate shapes that are a maintenance decision rather than an archaeology one:

- **(A) add the missing guard** — an AST scan over `internal/diagnosis/rabbitmq` for those seven
  attribute identifiers, in the shape `test/security` already uses for the SASL core and the
  diagnostic core; or
- **(B) correct the comment** to say the property is maintained by review, if mechanical
  enforcement is not in fact intended.

Whichever is chosen, it is one small change in its own commit. Recorded as `RRI-016` and in
`docs/BACKLOG.md`.

## 7. Compatibility implications

**None.** No finding code, failure class, attribute, schema field, command, or compatibility claim
is added, changed or removed. `docs/COMPATIBILITY.md` is untouched.

---

## 8. Validation requirements

`docs/validation/PHASE106A_DIAGNOSTIC_OPPORTUNITY_AUDIT.md` holds the register, `RRI-001` …
`RRI-018`, each classified `FROZEN`, `NEXT_IMPLEMENTATION` or `DEFERRED`. With no candidate
admitted, **no requirement is `NEXT_IMPLEMENTATION`** — which is the shape an audit that admitted
nothing should have, and saying so is the point.
