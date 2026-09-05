# Phase 10.8A — existing evidence consumption audit

- **Phase:** 10.8A — repository archaeology / diagnostic design / contract freeze.
  **No production Go, no test Go, no fixture, no harness, no config.**
- **Baseline:** `004313980291eca2b3bc50a5d6ab795afdcfd5da`, `HEAD == origin/main`, working tree clean
- **Record:** ADR 0090
- **Corrected 2026-09-06 by Phase 10.8A.1 / ADR 0091**, on three points of fact found by Phase
  10.8B's pre-implementation archaeology: `Finding.Detail` is **canonical JSON**, so the enrichment
  changes the report and the frozen term is now **canonical explanation enrichment**; **LavinMQ does
  produce `VHOST_CONNECTION_LIMIT`**; and that outcome **already has real fixtures** on both
  implementations. The audit, its counts, the winner and its **C1-A** class are unchanged. Markers
  are inline below; see `PHASE108A1_CANONICAL_FINDING_EXPLANATION_CORRECTION.md`.
- **Outcome:** **ACTIVATE RABBITMQ PRESENTATION** — preserve, in operator-facing output, *which*
  capacity ceiling `rabbitmq.close_outcome` already records. Class 1: nothing is acquired, no
  diagnostic rule is added, no `FindingCode` is added, no inference is made, no confidence is
  admitted, and no severity or exit code moves. The diagnosis — `RESOURCE_LIMIT_REACHED` — is
  unchanged; only the specificity it already rests on stops being discarded on the way out.

---

## 1. Baseline, as measured

| Fact | Value | How |
|---|---|---|
| `HEAD` == `origin/main` | `0043139` | `git rev-parse` |
| working tree at start | clean | `git status --short` empty |
| `make check` before the audit | **exit 0** | fmt-check OK · test · vet · `golangci-lint` *0 issues* · build |
| `SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| declared finding codes | **65** | convergence scan |
| attributed finding codes | **65** | convergence scan: *attributed 65 of 65* |
| production diagnosis rules | **22** | convergence scan |
| rules / codes per package | 1/1 generic · 3/8 transport · 5/15 Kafka · 6/21 PostgreSQL · 4/9 Redis · 3/11 RabbitMQ | convergence scan |
| `RuleContext` fields | **3** | `internal/diagnosis/rulecontext.go:53` — `Graph`, `Vantage`, `Incomplete` |
| failure classes | **42** | `internal/domain/failureclass_test.go:254` |
| external modules | **2** | `go.mod` — `kmsg` v1.13.1, `go.yaml.in/yaml/v3` v3.0.5 |
| `Reveal` production call sites | **4** | redis/wire/auth.go:74 · rabbitmq/wire/connection.go:196 · postgres/wire/scram.go:153 · kafka/wire/authenticate.go:54 |
| `SecretFor` production call sites | **4** | redis · rabbitmq · postgres · kafka `authenticate.go` |
| canonical exit codes | **5** | `internal/cli/exit.go` — 0/1/2/3/4 |

Every frozen count is unchanged by this phase, because this phase changes no Go.

---

## 2. Methodology

### 2.1 What counts as a recorded evidence attribute — ECA-001

A **recorded evidence attribute** is a `domain.AttributeKey` constant declared in non-test
production code that is written into `domain.EvidenceInput.Attributes` and therefore crosses the
adapter/probe boundary into the canonical evidence graph and the canonical JSON report.

Deliberately **excluded**, because mixing them would inflate the number and change what it means:

| Excluded | Why |
|---|---|
| adapter locals and `wire` struct fields never retained | they never reach canonical evidence |
| `domain.FailureClass` | derived interpretation, not a recorded attribute; it has its own count (42) |
| `Finding` fields, `Recommendation` fields | products of diagnosis, not evidence |
| report/run metadata (`tlsVerificationDisabled`, `outputMode`, `svcdoctorVersion`) | report-level, not node-level; already operator-facing |
| config values, credential references | never enter evidence by construction (ADR 0072) |
| renderer-only synthetic labels (`recovery`, `implementation`) | presentation of an attribute, not an attribute |
| `domain.Step`, `domain.Subject`, `domain.State` | node structure, not attributes |

### 2.2 What counts as consumption — ECA-002

Two consumer classes are counted, and one explicitly is not.

- **Diagnosis consumption** — a non-test file under `internal/diagnosis/**` reads the attribute
  from a node.
- **Renderer consumption** — a non-test file under `internal/render/**` deliberately interprets
  or presents the attribute as an operator-facing observation.
- **Canonical JSON serialization is NOT consumption.** Every attribute in the graph is serialized
  by definition, so counting it would make the measurement vacuous — every attribute would be
  "consumed" and the audit would have nothing to audit. This distinction is frozen as ECA-002.

Also **not** counted as consumption:

- **`internal/security/redaction`.** It iterates `e.Attributes()` at `redact.go:112` and `:279`,
  but it dispatches on `AttrKind` and never on a key. It is a structural transform that is total
  over the attribute space; it would keep working if every key were renamed. Verified: no key
  constant is referenced anywhere in that package.
- **Test files and integration fixtures.** A test asserting an attribute exists proves the
  producer works, not that an operator ever sees it.
- **`internal/app`.** The composition roots read adapter *return values*, not evidence attributes;
  the scan found no attribute key referenced there outside tests.

### 2.3 How the inventory was built — ECA-003

A static reference scan (executed from `/tmp`, writing nothing into the repository) that:

1. parses every non-test `*.go` file for `Attr… domain.AttributeKey = "…"` declarations,
   recording *(package path, identifier) → key* and the declaration site;
2. resolves each file's intra-module imports and their aliases;
3. records every `alias.Ident` and bare `Ident` reference that resolves to a declared key,
   excluding the declaration itself;
4. buckets each referencing file by package into producer / diagnosis / render / app / security /
   vocab / cli / test.

Alias resolution matters and is not optional: `AttrServerVersion` is declared in both
`internal/service/postgres` and `internal/service/redis`, and `AttrVersion`, `AttrRole` and
`AttrProto` collide similarly. A bare identifier grep would have merged them.

The scan is then **falsified rather than trusted** — §4.

---

## 3. The inventory

### 3.1 Recorded attributes

| Scope | Service | Recorded | Diagnosis reads | Renderer reads | **Consumed by neither** |
|---|---|---|---|---|---|
| service | Kafka | 14 | 2 | 1 | **12** |
| service | PostgreSQL | 17 | 4 | 2 | **11** |
| service | Redis/Valkey | 7 | 2 | 5 | **1** |
| service | RabbitMQ/LavinMQ | 21 | 2 | 15 | **4** |
| | **service subtotal** | **59** | **10** | **23** | **28** |
| generic | DNS | 1 | 0 | 0 | **1** |
| generic | TCP | 0 | — | — | — |
| generic | TLS | 10 | 0 | 1 | **9** |
| | **generic subtotal** | **11** | **0** | **1** | **10** |
| | **TOTAL** | **70** | **10** | **24** | **38** |

Consumed by **both** a rule and a renderer: **2** — `kafka.broker.node_id` and `redis.mode`.

**TCP records no attributes at all.** Its whole result is `State` + `FailureClass` + `Elapsed`,
which is why generic TCP diagnosis is failure-class-driven and needs nothing else.

### 3.2 Scope note

Phase 10.7A counted **service adapters only**. That scope reproduces exactly: **59 recorded**.
This audit widens it to include the generic probes, because `dns.answers` and the nine unread
`tls.*` keys are canonical evidence attributes by §2.1's definition and excluding them would let
ten attributes escape the audit on a technicality. Both numbers are reported so neither record
has to be read against the other.

---

## 4. Reconciliation with Phase 10.7A — ECA-004

**Phase 10.7A's own record is internally inconsistent, and this audit corrects it rather than
inheriting it.** Its §2 table says **24** unconsumed; the prose immediately below it *names*
27 — Kafka 12, PostgreSQL 10, Redis 1, RabbitMQ 4. The two halves of one paragraph disagree.

The named list is the accurate half. Re-measured from the current tree:

| | Kafka | PostgreSQL | Redis | RabbitMQ | service total |
|---|---|---|---|---|---|
| 10.7A table | 10 | 9 | 1 | 4 | **24** |
| 10.7A named prose | 12 | 10 | 1 | 4 | **27** |
| **measured at `0043139`** | **12** | **11** | **1** | **4** | **28** |

Three independent corrections, none of which cancel to the historical figure:

1. **`postgres.default_transaction_read_only` is now consumed** by
   `internal/render/terminal/service.go` (Phase 10.7B). PostgreSQL **−1**.
2. **`postgres.role` was missed by 10.7A.** Declared at `internal/adapter/postgres/startup.go:69`,
   written on the startup node, read by no rule and no renderer. PostgreSQL **+1**.
3. **`postgres.server_version` was missed by 10.7A.** Declared at
   `internal/service/postgres/vocabulary.go:78`, written on every passing session, read by no rule
   and no renderer — only by tests. PostgreSQL **+1**.

Net PostgreSQL 10 → 11, service total 27 → 28. Adding the ten generic-probe attributes 10.7A never
scoped gives the full figure of **38**.

**So the honest statement is not "24 became 23".** 10.7A's headline number was never right, one
attribute left the set, two were found that had never been in it, and ten more were out of scope.

---

## 5. The indirect-consumption audit — ECA-005

An attribute is not "dead" because no rule reads its key. Several were already used by the
adapter to derive the `FailureClass` diagnosis actually keys on. Every such chain, traced:

| Attribute | Chain | Terminal consumer |
|---|---|---|
| `kafka.error_code` | `wire.ApiVersions.ErrorCode` → `protocolFailure()` (`apiversions.go:333`) → `PROTOCOL_UNSUPPORTED_VERSION` / `PROTOCOL_UNEXPECTED_RESPONSE` | `internal/diagnosis/kafka/protocol.go` claim table |
| `postgres.error_severity` | `ErrorResponse` field `V` → **presence** sets `out.Native` (`wire/errorresponse.go:109`) → `postgres.error_is_native` | `internal/diagnosis/postgres/shared.go` |
| `redis.auth_required` | `HELLO` refusal/answer → `hello.AuthRequired()` → composition-root path selection (`internal/app/redis.go:310`, `:331`) and `ping.go:109` | path selection, not a rule |
| `rabbitmq.close_outcome` | `Connection.Close` reply text → byte-equality sentinel → `wire.CloseOutcome` → `classify()` (`open.go:153`) → `RESOURCE_NOT_FOUND` / `AUTHZ_DENIED` / `RESOURCE_LIMIT_REACHED` / `AUTHZ_NOT_PERMITTED` | `internal/diagnosis/rabbitmq/connectionopen.go:133` |
| `rabbitmq.reply_code` | same frame; `530` gates the sentinel switch | same |
| `rabbitmq.peer_close_method` | recorded only; **never** reaches `classify()` | none — corroboration only |

**This changes four verdicts and preserves one candidate.** `kafka.error_code`,
`postgres.error_severity` and `redis.auth_required` are `SEMANTICALLY_CONSUMED_EARLIER` and are
retained for auditability — they are not gaps. `rabbitmq.close_outcome` is the interesting case:
it is semantically consumed earlier **into a class that is coarser than the attribute**, and §7.25
is where that matters.

### 5.1 Duplicate observations discovered

| Attribute | Already carried by |
|---|---|
| `kafka.broker.advertised_host` / `_port` | the advertisement node's **`Subject.Ref()`** — the producer's own doc says a second copy "would create two sources for one fact" (`metadata.go:52-56`) |
| `kafka.metadata.broker_count` | `len(advertisements)` **is** `advertisedTopology.total()` (`topology.go:355`), the `N` printed in every topology summary and in the terminal's `topology` line |
| `kafka.sasl.requested_mechanism` | the operator's own `--sasl-mechanism` input |
| `postgres.role` / `postgres.database` / `postgres.tls.plan` | the operator's own CLI input |
| `postgres.sasl_mechanism` | `postgres.auth_method` on the startup node — the producer says so at `authenticate.go:33-36` |
| `dns.answers` | the resolved addresses are the `Subject` of every downstream node and are what the terminal tree prints |
| `tls.server_name` / `tls.trust_source` | the operator's own `--tls-server-name` / `--tls-ca-file` input |

### 5.2 Unsafe-to-consume observations discovered

| Attribute | Why |
|---|---|
| `kafka.metadata.controller_id` | **measured non-deterministic.** `metadata.go:65-68` records eight consecutive reads of a stable three-broker KRaft cluster returning **1, 1, 2, 1, 1, 3, 2, 3** while the quorum leader never moved |
| `rabbitmq.peer_close_method` | **measured to disagree between implementations.** RabbitMQ sends `0/0` for an authentication refusal, LavinMQ sends `10/11` for the same condition (ADR 0069 §1) |
| `tls.peer_dns_names` / `tls.peer_ip_addresses` | identity-bearing peer names; `TLS_IDENTITY_MISMATCH` deliberately **points at** them rather than inlining them (`tls.go:73-78`) |
| `kafka.sasl.offered_mechanisms`, `postgres.sasl_mechanisms` | **arbitrary peer text.** `decodeMechanisms` (`postgres/wire/authrequest.go:145`) and `saslhandshake.go:78-80` copy names verbatim with no allowlist, no length bound and no character restriction |

### 5.3 No-operator-value observations discovered

`kafka.api_versions` (≈70 entries, useless without declared client requirements),
`kafka.sasl.session_lifetime_ms` (re-authentication is client behaviour ADR 0008 keeps out),
`rabbitmq.reply_code` (the finding code already carries the distinction it supports),
`tls.cipher_suite`, `tls.version`, `tls.peer_not_before`, `tls.peer_not_after`.

### 5.4 Two documentation defects found, and neither is fixed here

Both are comment-versus-code conflicts. **No production behaviour is wrong**, so under this
phase's contract they are recorded, not patched.

1. **`internal/service/redis/vocabulary.go:105-106` claims a renderer reads
   `redis.auth_required`.** *"The composition root reads the adapter's own answer rather than this
   key; the renderer reads this one."* No renderer has ever read it: `grep -rn "AuthRequired\|
   auth_required" internal/render/` is empty, and the Redis `observations` table holds
   `server`, `server_version`, `proto`, `mode`, `role` and nothing else. Wrong since `aba0d45`,
   the Phase 7.5 implementation commit. It is also why 10.7A's *"read by the composition root for
   path selection, so not dead"* is imprecise — the composition root reads
   `session.AuthRequired()`, a Go method, not the attribute.
2. **`internal/service/rabbitmq/vocabulary.go:152` says rules read `rabbitmq.close_outcome`.**
   *"Rules read it to state what the endpoint named."* No rule reads it;
   `connectionopen.go:133` switches on `node.FailureClass()`. The comment describes the design
   ADR 0069 §6 intended and the tree does not implement — which is §7.25.

---

## 6. Case-file conventions

Every one of the **38** attributes with no rule and no renderer consumer gets a case file. There
is no sampling and no "the rest are bookkeeping" paragraph.

**Authority** is one of `DIRECT_PROTOCOL`, `DERIVED_FROM_DIRECT_PROTOCOL`, `LOCAL_MEASUREMENT`,
`PEER_SELF_DESCRIPTION`, `OPERATOR_INPUT`, `INTERNAL_BOOKKEEPING`.

**Real producibility** is one of `PROVEN_REAL`, `PROVEN_ONLY_UNIT`, `REACHABLE_NOT_PROVEN`,
`NOT_REACHABLE_IN_BASIC`, `UNKNOWN`.

The six qualitative gates — operator value, authority, false-positive risk, compatibility risk,
output-noise cost, fixture confidence — are `HIGH`/`MEDIUM`/`LOW` **analytical labels**. They are
not `domain.Confidence` and must never be read as it (ECA-018).

---

## 7. Case files

### Kafka — 12

#### 7.1 `kafka.api_versions`

- **Identity.** Kafka · `internal/adapter/kafka/apiversions.go:47` · step `kafka.api_versions` ·
  origin: the `ApiVersions` response's advertised key ranges.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL` — svcdoctor formats the peer's integers as
  `"<key>:<min>-<max>"`, sorted. The numbers are the peer's; the grammar is svcdoctor's.
- **Domain.** Bounded string list, ≈70 entries against Apache Kafka 4.0. Numeric triples only.
  Absent when the broker advertised none.
- **Subject.** This `ApiVersions` exchange, on this connection, with this listener.
- **Temporal scope.** This response. A broker upgrade changes it.
- **Intermediary boundary.** A Kafka-compatible implementation advertises its own set;
  Redpanda's differs from Apache Kafka's legitimately. Strongest safe subject: *the listener
  reached at this address*.
- **Current consumer proof.** Referenced only by `apiversions.go` and two tests.
- **Operator question.** *"Does this broker support the API versions my client library needs?"*
- **Current svcdoctor answer.** `PARTIALLY` — `PROTOCOL_UNSUPPORTED_VERSION` answers it for the
  one request svcdoctor made.
- **Incremental value.** None that svcdoctor can realize: the operator's *client's* requirements
  are declared nowhere, so a 70-line dump asks the operator to do the comparison.
- **Failure of interpretation.** "My client needs v9 and the list stops at v7, so that is my bug"
  — when the client negotiates down perfectly well.
- **Compatibility.** Kafka/Redpanda differ by design; no diagnosis is safe across them.
- **Real producibility.** `PROVEN_REAL` (every Kafka run).
- **Security.** Version fingerprinting of the target.
- **Existing decision pressure.** ADR 0089 DOE-002's minimum-observation principle; ADR 0083 §2.6
  (intent frozen).
- **Gates.** value LOW · authority HIGH · FP risk MEDIUM · compat risk HIGH · noise **HIGH** ·
  fixture HIGH.
- **Classification.** `C1D_NO_OPERATOR_VALUE`. **Verdict: REJECT.**
- **Reason.** This is the protocol dump §16 exists to refuse. Seventy bounded, accurate,
  unactionable lines do not reduce uncertainty about anything, and the only reading that would
  make them actionable requires client requirements svcdoctor cannot know.

#### 7.2 `kafka.broker.advertised_host`

- **Identity.** Kafka · `metadata.go:127` · step `kafka.broker_advertised` · the `Metadata`
  response's broker host.
- **Authority.** `DIRECT_PROTOCOL`. Recorded as `AttrKindHost`, so redaction can find it.
- **Domain.** Arbitrary peer-supplied hostname or address; empty when none was advertised.
- **Subject.** One advertised broker entry.
- **Temporal scope.** This response.
- **Intermediary boundary.** A proxy, a service mesh or an operator rewrite produces identical
  bytes (ADR 0035 §2).
- **Current consumer proof.** `metadata.go` and four tests.
- **Operator question.** *"What address did the cluster advertise for this broker?"*
- **Current svcdoctor answer.** `YES` — it is the advertisement node's `Subject.Ref()`, which the
  terminal tree prints and every topology finding names.
- **Incremental value.** None. The producer's own doc comment says a second copy "would create two
  sources for one fact" (`metadata.go:52-56`).
- **Failure of interpretation.** n/a.
- **Compatibility.** n/a.
- **Real producibility.** `PROVEN_REAL`.
- **Security.** Internal hostnames; already redacted via `AttrKindHost`.
- **Existing decision pressure.** ADR 0034 §19, ADR 0035 §1.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**
- **Reason.** Rendering it would print each broker's address twice on one line of the tree.

#### 7.3 `kafka.broker.advertised_port`

Identical to §7.2 in every field, for the port half. `DIRECT_PROTOCOL`, raw `int32` recorded
uncorrected because an impossible advertised port is a fact about the cluster; already in the
subject ref, which renders `broker.internal:-1` for exactly that case (ADR 0035 §1);
`KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` already owns the claim.
**Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.4 `kafka.error_code`

- **Identity.** Kafka · `internal/service/kafka/vocabulary.go:79` · written by `apiversions.go` ·
  the broker's own error code.
- **Authority.** `DIRECT_PROTOCOL` — a permanent numeric registry.
- **Domain.** `int16`; `0` recorded because zero is a statement.
- **Subject.** This exchange's answer.
- **Temporal scope.** This response.
- **Intermediary boundary.** Low; the number is structured.
- **Current consumer proof.** No rule, no renderer — **but see §5**: `protocolFailure()` maps it
  before the attribute is written.
- **Operator question.** *"What did the broker actually answer?"*
- **Current svcdoctor answer.** `YES` via `FailureClass`, plus `KAFKA_PROTOCOL_*` findings.
- **Incremental value.** A number for the two codes svcdoctor normalizes; for the rest, a number
  the operator must look up, which is the "guessed root cause" trap in reverse.
- **Failure of interpretation.** Treating an unmapped code as more meaningful than the class.
- **Compatibility.** Redpanda uses the same registry.
- **Real producibility.** `PROVEN_REAL`.
- **Security.** None.
- **Existing decision pressure.** ADR 0025 (no Kafka class in `internal/domain`).
- **Gates.** value LOW · authority HIGH · FP MEDIUM · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_DUPLICATE` (semantically consumed earlier). **Verdict: REJECT.**

#### 7.5 `kafka.metadata.advertised_entry_count`

- **Identity.** Kafka · `metadata.go:93` · `len(response.Brokers)` before identical repetitions
  were collapsed.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL`. **Domain.** Non-negative int.
- **Subject.** This `Metadata` response's broker array.
- **Temporal scope.** This response.
- **Intermediary boundary.** None meaningful.
- **Current consumer proof.** `metadata.go` and two tests.
- **Operator question.** *"Did the cluster advertise the same broker twice?"*
- **Current svcdoctor answer.** `NO`.
- **Incremental value.** It exists so the one collapse svcdoctor performs is visible to a reader
  auditing the report — a genuine purpose, and an auditability purpose rather than a diagnostic
  one. A duplicate advertisement changes no action.
- **Failure of interpretation.** "The counts differ, so svcdoctor lost an entry."
- **Real producibility.** `REACHABLE_NOT_PROVEN` (a differing value has never been observed).
- **Gates.** value LOW · authority HIGH · FP MEDIUM · compat LOW · noise LOW · fixture LOW.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**
- **Reason.** Its job is to make a transformation auditable in the JSON. That job is done by being
  recorded. Unused is not debt.

#### 7.6 `kafka.metadata.broker_count`

- **Identity.** Kafka · `metadata.go:84` · `len(advertisements)` after collapse.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL`. **Domain.** Non-negative int.
- **Current consumer proof.** No rule, no renderer.
- **Operator question.** *"How many brokers did this cluster advertise?"*
- **Current svcdoctor answer.** `YES`, twice. It is exactly `advertisedTopology.total()`
  (`topology.go:355`) — the `N` in *"K of the N broker endpoints this cluster advertised…"* — and
  exactly the terminal's `topology  3 of 3 advertised broker endpoints reached`.
- **Incremental value.** Zero, provably: same integer, two existing renderings.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.7 `kafka.metadata.controller_id`

- **Identity.** Kafka · `metadata.go:81` · the response's `ControllerID`.
- **Authority.** `DIRECT_PROTOCOL` **about the field**, and about nothing else.
- **Domain.** `int32`; `-1` means the responding broker knows of no controller.
- **Subject.** *What this one response said*, and explicitly not which node controls the cluster.
- **Temporal scope.** **This instant, and not even reliably that.**
- **Intermediary boundary.** Under KRaft, controllers are not brokers, so the field cannot name
  one; a broker answers with an arbitrary live broker.
- **Current consumer proof.** No rule, no renderer.
- **Operator question.** *"Which node is the controller?"*
- **Current svcdoctor answer.** `NO`, deliberately.
- **Incremental value.** **Negative.** `metadata.go:65-68` records eight consecutive `Metadata`
  reads of a stable three-broker Apache Kafka 4.0 KRaft cluster returning **1, 1, 2, 1, 1, 3, 2,
  3** while the quorum's actual leader stayed node 1 throughout — reproduced from repository
  source, as §19 required. A rule reading this field "would have produced a different severity on
  identical runs."
- **Failure of interpretation.** "The controller moved three times in eight seconds."
- **Compatibility.** Redpanda's semantics are its own; nothing here is portable.
- **Real producibility.** `PROVEN_REAL` — and the measurement is what disqualifies it.
- **Existing decision pressure.** ADR 0034 §15 refuses it on the weaker grounds that a controller
  moves on election; the measurement is stronger. ADR 0084 §7.
- **Gates.** value LOW · authority **LOW** · FP **HIGH** · compat HIGH · noise LOW · fixture HIGH.
- **Classification.** `C1D_UNSAFE_TO_CONSUME`. **Verdict: REJECT.**
- **Reason.** The one attribute in this audit whose *own producer* carries the experiment proving
  it means nothing. Presentation is as unsafe as diagnosis: an operator reading a controller id
  will believe it names the controller.

#### 7.8 `kafka.metadata.unrepresentable_entry_count`

- **Identity.** Kafka · `metadata.go:101` · entries whose text cannot be a `Subject` reference.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL`. **Domain.** Positive int; **recorded only when
  non-zero**, so absence means zero.
- **Subject.** This `Metadata` response's un-nodeable entries.
- **Temporal scope.** This response.
- **Intermediary boundary.** A rewriting proxy is a plausible source of such text.
- **Current consumer proof.** No rule, no renderer.
- **Operator question.** *"Did svcdoctor's topology counts cover everything the cluster
  advertised?"*
- **Current svcdoctor answer.** `NO` — **and this is the one place where the answer is currently
  wrong rather than merely absent.**
- **Incremental value.** Real, and it is a soundness matter. `advertisementsOf`
  (`metadata.go:344-353`) drops such an entry with no node. `advertisedTopology.complete` is
  `len(notMeasured) == 0 && !ctx.Incomplete` (`topology.go:347`), computed purely over the
  exchange's **children**, so an entry that produced no child is structurally invisible to it. A
  response with one unrepresentable entry therefore yields
  `detailTopologyComplete` — *"Each endpoint that response advertised was measured for
  reachability, so the counts above account for the whole advertised set"* — over a set that
  silently lost a member.
- **Failure of interpretation.** The overclaim above is svcdoctor's, not the operator's.
- **Compatibility.** Would apply identically to Redpanda.
- **Real producibility.** `NOT_REACHABLE_IN_BASIC` against a supported fixture.
  `validateIdentifier` (`evidenceid.go:52`) rejects only empty, invalid UTF-8, leading/trailing
  whitespace, and control characters. A real broker's `advertised.listeners` cannot normally carry
  any of these — an empty host yields the ref `:9092`, which is *representable* and becomes a
  `KAFKA_ADVERTISED_ENDPOINT_UNUSABLE` node. `docs/validation/KAFKA_PHASE3_VALIDATION.md:133`
  records that **no real run has ever produced one.**
- **Security.** A count, no identity.
- **Existing decision pressure.** **ADR 0035 §1** names this as the explicitly uncovered fourth
  category with the reopen condition *"when an entry that produced no node needs to be
  diagnosable"*; `docs/BACKLOG.md:1490` carries it; `docs/FINDINGS.md:459` states it. **ADR 0084
  §4** defines completeness over children and does not mention the interaction.
- **Gates.** value MEDIUM · authority HIGH · FP LOW · compat LOW · noise LOW · fixture **LOW**.
- **Classification.** `DEFER_REQUIRES_REAL_FIXTURE`. **Verdict: DEFER.**
- **Reason.** The soundness gap is real and newly articulated — ADR 0035 §1 anticipated the
  missing *finding*, not the later completeness *overclaim* ADR 0084 built on top of it. But the
  correct fix is a `complete` predicate that also reads this attribute, and no supported fixture
  can produce the condition, so a change would be unfalsifiable against reality. Recorded as an
  ADR-conflict observation (§12) and deferred on the fixture gate, not on merit.

#### 7.9 `kafka.request_api_version`

- **Identity.** Kafka · `internal/service/kafka/vocabulary.go:72` · written by `apiversions.go:351`
  and `metadata.go` as `wire.RequestAPIVersion()` — **svcdoctor's own compiled-in constant.**
- **Authority.** `INTERNAL_BOOKKEEPING`. **Domain.** A fixed int per build.
- **Subject.** svcdoctor's request.
- **Temporal scope.** Constant for a given binary.
- **Current consumer proof.** No rule, no renderer.
- **Operator question.** *"Which protocol version did svcdoctor ask for?"*
- **Current svcdoctor answer.** `NO`, and the question is svcdoctor's own.
- **Incremental value.** It is the other half of an error code for a machine reading JSON, which
  is why it is recorded. For a terminal reader it is a build constant.
- **Real producibility.** `PROVEN_REAL`. **Gates.** value LOW · authority HIGH · FP LOW · compat
  LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**

#### 7.10 `kafka.sasl.offered_mechanisms`

- **Identity.** Kafka · `saslhandshake.go:41` · step `kafka.sasl_handshake` · the
  `SaslHandshake` response's mechanism array, sorted, **not** deduplicated.
- **Authority.** `DIRECT_PROTOCOL` — but the *values* are peer-chosen strings.
- **Domain.** **Arbitrary peer text.** `saslhandshake.go:78-80` appends `SupportedMechanisms`
  verbatim: no allowlist, no length bound, no character restriction.
- **Subject.** The SASL configuration of the listener reached at this address and port.
- **Temporal scope.** This response; a listener reconfiguration changes it.
- **Intermediary boundary.** A proxy terminating SASL advertises its own set.
- **Current consumer proof.** `saslhandshake.go` and two tests.
- **Operator question.** *"The broker refused my mechanism — which ones does it accept?"* This is a
  genuine incident question and it clears §8's bar.
- **Current svcdoctor answer.** **`NO`, and the gap is visible in the prose.**
  `KAFKA_AUTH_MECHANISM_NOT_OFFERED` says *"the named mechanism is not one it offers"* and
  recommends *"Check `sasl.enabled.mechanisms` on the listener serving this address and port"* —
  sending the operator to a config file for an answer already on the node the finding cites.
- **Incremental value.** High in principle: it converts a "go look it up" recommendation into an
  answer.
- **Failure of interpretation.** "It offers SCRAM-SHA-512, so my credential will work" — offering
  a mechanism is not accepting a credential.
- **Compatibility.** Redpanda and Apache Kafka both answer here; the *list* differs legitimately,
  which is fine for presentation and fatal for diagnosis.
- **Real producibility.** `PROVEN_REAL` — the Kafka and Redpanda integration suites reach it.
- **Security.** **This is the blocker.** Rendering the list verbatim puts peer-chosen bytes on an
  operator's terminal. It is exactly the hazard that kept `postgres.server_version` off the Result
  block in Phase 10.3: *"no renderer sanitises an observation value"*, and that is *"a pre-existing
  cross-service question wanting one decision, not four."*
- **Existing decision pressure.** ADR 0089 DOE-006 (no arbitrary peer prose in a claim); the
  outstanding renderer-sanitization decision named by `internal/render/terminal/service.go:188-200`.
- **Gates.** value **HIGH** · authority HIGH · FP MEDIUM · compat MEDIUM · noise LOW ·
  fixture HIGH.
- **Classification.** `DEFER_REQUIRES_ARCHITECTURE_DECISION`. **Verdict: DEFER.**
- **Reason.** The best-scoring candidate in the audit on operator value, and it loses on exactly
  one gate: its domain is unbounded peer text and svcdoctor has no sanitization boundary. Bounding
  it with a registry allowlist here would invent machinery for one service while the cross-service
  decision is outstanding, which is the conditional sprawl the architecture rule forbids. It is
  the strongest reason for that decision to be taken, and it should be taken for all four services
  at once. §9.2.

#### 7.11 `kafka.sasl.requested_mechanism`

- **Identity.** Kafka · `saslhandshake.go:33` · `SASLParams.Mechanism`.
- **Authority.** `OPERATOR_INPUT`. **Domain.** Whatever the operator passed.
- **Subject.** svcdoctor's request. **Temporal scope.** The run.
- **Current consumer proof.** No rule, no renderer.
- **Operator question.** *"Which mechanism did svcdoctor try?"*
- **Current svcdoctor answer.** `YES` — the operator supplied it, and
  `recommendMechanismNotOffered` already says *"and which mechanism this run was configured to
  use"*.
- **Incremental value.** None. It is recorded because *"'not offered' is only interpretable next to
  what was requested"* for a machine reading JSON.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.12 `kafka.sasl.session_lifetime_ms`

- **Identity.** Kafka · `saslauthenticate.go:45` · the `SaslAuthenticate` response's
  `SessionLifetimeMs`.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** `int64` ms; `0` means no expiry and is recorded.
- **Subject.** The authenticated session svcdoctor just established.
- **Temporal scope.** This session.
- **Intermediary boundary.** Low.
- **Current consumer proof.** `saslauthenticate.go` and five tests.
- **Operator question.** *"How long before my client must re-authenticate?"*
- **Current svcdoctor answer.** `NO`.
- **Incremental value.** Low and mis-aimed. svcdoctor closes the session immediately; re-auth is
  long-lived-client behaviour, which ADR 0008 keeps out of the measured path precisely because
  hidden client behaviour destroys evidence topology. Reporting a lifetime svcdoctor never
  approaches invites the reader to believe svcdoctor measured something about it.
- **Failure of interpretation.** "svcdoctor verified my client can hold a connection this long."
- **Compatibility.** Redpanda may send `0`; nothing turns on it.
- **Real producibility.** `PROVEN_REAL`.
- **Existing decision pressure.** ADR 0038 §17 names it the precedent for "a target configuration
  fact nothing else in a run reports", recorded and unread — deliberately.
- **Gates.** value LOW · authority HIGH · FP MEDIUM · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_NO_OPERATOR_VALUE`. **Verdict: REJECT.**

---

### PostgreSQL — 11

#### 7.13 `postgres.database`

- **Identity.** PostgreSQL · `startup.go:70` · the `StartupMessage` `database` parameter.
- **Authority.** `OPERATOR_INPUT`. Recorded via `domain.IdentityAttr`, so a shareable report
  replaces it with `identity-NNN` (ADR 0037).
- **Domain.** Operator-supplied string. **Subject.** svcdoctor's own startup packet.
- **Current consumer proof.** `startup.go` and two tests.
- **Operator question.** *"Which database did svcdoctor try?"*
- **Current svcdoctor answer.** `YES` — the operator typed it, and it is on the command line.
- **Incremental value.** None. `POSTGRES_DATABASE_NOT_FOUND` already owns the case where it
  matters.
- **Security.** A dataset name; widening its presentation increases practical disclosure even
  though the JSON carries it, which §15 requires recording.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.14 `postgres.error_severity`

- **Identity.** PostgreSQL · `startup.go:48`, also written by `authenticate.go:599` and
  `establish.go:524` · the `ErrorResponse` non-localized `V` field.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** **Bounded** — `errorresponse.go:110-113` stores
  the value only when `validSeverity(value)`.
- **Subject.** The rejection frame. **Temporal scope.** That frame.
- **Intermediary boundary.** pgBouncer omits `V` entirely — which is the whole point of the
  sibling attribute.
- **Current consumer proof.** Three producer files and three tests. **But see §5**: the *presence*
  of `V` is what sets `postgres.error_is_native`, which `internal/diagnosis/postgres/shared.go`
  does read.
- **Operator question.** *"How serious was the server's rejection?"*
- **Current svcdoctor answer.** `YES` — every `ErrorResponse` svcdoctor observes terminated the
  exchange, which `State` = FAIL and the `FailureClass` already say, and the SQLSTATE says more
  precisely.
- **Incremental value.** Effectively zero: the value is `FATAL` on every path svcdoctor can reach.
- **Failure of interpretation.** Reading `ERROR` rather than `FATAL` as "less bad" when the
  connection ended either way.
- **Gates.** value LOW · authority HIGH · FP LOW · compat MEDIUM · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE` (semantically consumed earlier, via presence).
  **Verdict: REJECT.**

#### 7.15 `postgres.is_superuser`

- **Identity.** PostgreSQL · `establish.go:56` · the `is_superuser` `ParameterStatus`, one of four
  allowlisted keys.
- **Authority.** `DIRECT_PROTOCOL` — the server's own GUC report about the session it just opened.
- **Domain.** `"on"` / `"off"` in practice; the retained value is the server's own string with no
  length or character bound, so a renderer would need the same closed-map discipline Phase 10.7B
  used.
- **Subject.** **The session svcdoctor established**, never the server and never the role in
  general.
- **Temporal scope.** Session lifetime.
- **Intermediary boundary.** **Material.** A pooler forwards a cached value from *its* backend
  session; ADR 0040 §18's *"endpoint, never server"* applies exactly as it does to the two
  rendered session facts.
- **Current consumer proof.** `establish.go` and two tests.
- **Operator question.** *"Did I connect with the privileges I expected?"*
- **Current svcdoctor answer.** `NO`.
- **Incremental value.** Genuine but narrow. It is one bit about the connection's privilege that
  nothing else reports.
- **Failure of interpretation.** *"`is_superuser: off` means I lack permission for X."* Almost
  every permission an application needs is a role grant, not superuser, so `off` is the correct
  and unremarkable state for essentially every well-configured application role.
- **Compatibility.** Standard across supported PostgreSQL versions; pooler-dependent.
- **Real producibility.** `PROVEN_REAL` — `test/integration/postgres/auth_test.go` already
  asserts it.
- **Security.** A privilege bit about the operator's own credential; no identity.
- **Existing decision pressure.** `docs/BACKLOG.md:2424` lists *"replica/read-only/superuser and
  version facts (ADR 0040 §20)"* as deliberately not BASIC. Phase 10.7B established that the
  *presentation* layer may show such a fact where the *finding* layer refuses, so §20 does not
  close this by itself.
- **Gates.** value **LOW–MEDIUM** · authority HIGH · FP MEDIUM · compat MEDIUM · noise **MEDIUM** ·
  fixture HIGH.
- **Classification.** `C1A_PRESENTATION_CANDIDATE`. **Verdict: DEFER.**
- **Reason.** It passes every safety gate and fails the value gates. It would print on **every**
  successful PostgreSQL session, and on almost all of them it would print `off`, which is correct
  and expected. Contrast the line Phase 10.7B did add: `default_transaction_read_only` earned its
  place because the *absence* of the line was actively misleading — `recovery: not in recovery`
  read as reassurance while a hidden GUC made the session read-only. No analogous misreading
  exists here: nothing in the current output implies superuser status. **Reopen when** an operator
  question turns on connection privilege — the most likely source being declared intent (an
  expected privilege level), which ADR 0083 §2.6 has frozen out of Phase 10.

#### 7.16 `postgres.protocol_version`

- **Identity.** PostgreSQL · `startup.go:26`, written at `startup.go:329` as the **string literal
  `"3.0"`**.
- **Authority.** `INTERNAL_BOOKKEEPING`. **Domain.** A single constant value. There is no code
  path that produces anything else.
- **Subject.** svcdoctor's request. **Temporal scope.** Constant for all builds.
- **Current consumer proof.** `startup.go` only — the one attribute in this audit referenced by no
  test either.
- **Operator question.** None that is not answered by "svcdoctor speaks the PostgreSQL v3
  protocol".
- **Current svcdoctor answer.** `YES` trivially.
- **Incremental value.** Zero, provably: a constant carries no information.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**

#### 7.17 `postgres.role`

- **Identity.** PostgreSQL · `startup.go:69` · the `StartupMessage` `user` parameter, recorded via
  `domain.IdentityAttr`.
- **Authority.** `OPERATOR_INPUT`. **Domain.** Operator-supplied principal name.
- **Subject.** svcdoctor's own startup packet.
- **Current consumer proof.** `startup.go` and two tests. **Missed entirely by Phase 10.7A.**
- **Operator question.** *"Which role did svcdoctor authenticate as?"*
- **Current svcdoctor answer.** `YES` — the operator supplied it.
- **Incremental value.** None, and negative on disclosure: it is a principal name in the inspected
  environment. ADR 0038 §17 lists the role among values *"never recorded"* on the authentication
  node specifically because it is already here and a second copy would be one fact twice.
- **Security.** Tenant/principal identity. Redacted to `identity-NNN` in shareable output; a
  terminal line would widen practical disclosure (§15).
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.18 `postgres.sasl_mechanism`

- **Identity.** PostgreSQL · `authenticate.go:37` · the single mechanism svcdoctor chose or
  declined.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL` — svcdoctor's selection from the server's offer.
- **Domain.** In practice `SCRAM-SHA-256`; absent when no mechanism was ever chosen.
- **Subject.** This authentication node.
- **Current consumer proof.** `authenticate.go` and one test.
- **Operator question.** *"Which authentication mechanism was used?"*
- **Current svcdoctor answer.** `YES` — `postgres.auth_method` on the startup node is read by
  `internal/diagnosis/postgres/session.go`, and the producer's own comment
  (`authenticate.go:33-36`) says a second copy would be *"one fact with two representations"*.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.19 `postgres.sasl_mechanisms`

- **Identity.** PostgreSQL · `startup.go:38` · the `AuthenticationSASL` mechanism list, in the
  server's stated preference order.
- **Authority.** `DIRECT_PROTOCOL`, with peer-chosen values.
- **Domain.** **Arbitrary peer text.** `decodeMechanisms` (`wire/authrequest.go:145-160`) copies
  NUL-delimited names verbatim: no allowlist, no length bound, no character restriction.
- **Subject.** What this server offered *for this role, from this source address* — `pg_hba`
  selects the method by source address, so it is partly a fact about who asked.
- **Temporal scope.** This startup exchange.
- **Intermediary boundary.** pgBouncer offers its own mechanisms from its own userlist.
- **Current consumer proof.** `startup.go` only.
- **Operator question.** *"The server wanted SASL — which mechanisms, and why did svcdoctor
  decline?"* Real, because svcdoctor declines `SCRAM-SHA-256-PLUS`.
- **Current svcdoctor answer.** `PARTIALLY` — `POSTGRES_AUTHENTICATION_UNSUPPORTED_BY_SVCDOCTOR`
  states that svcdoctor performs SCRAM-SHA-256 and declines the rest, without naming what was
  offered. The producer notes the list *"describes the channel as well as the server"*, since a
  real server offers `SCRAM-SHA-256-PLUS` only over TLS.
- **Incremental value.** Moderate.
- **Compatibility.** Poolers legitimately differ.
- **Real producibility.** `PROVEN_REAL`.
- **Security.** Same unbounded-peer-text hazard as §7.10.
- **Gates.** value MEDIUM · authority HIGH · FP MEDIUM · compat MEDIUM · noise LOW · fixture HIGH.
- **Classification.** `DEFER_REQUIRES_ARCHITECTURE_DECISION`. **Verdict: DEFER.**
- **Reason.** Blocked on the same outstanding renderer-sanitization decision as §7.10, and it is
  the second of the four services that decision must serve.

#### 7.20 `postgres.scram_iterations`

- **Identity.** PostgreSQL · `authenticate.go:46` · written at `:593` · the PBKDF2 iteration count
  from the SCRAM server-first message.
- **Authority.** `DIRECT_PROTOCOL` — the server named it, and `parseIterations`
  (`internal/sasl/scram/parse.go:295`) accepts only ASCII digits, so the value is a validated
  integer and never peer prose.
- **Domain.** Bounded int, `1 … MaxIterations` = `1<<20`. Above the ceiling the exchange is refused
  before any derivation.
- **Subject.** The credential verifier of the endpoint that authenticated this session.
- **Temporal scope.** **Stable server property**, per stored verifier — one of the few attributes
  in this audit that is.
- **Intermediary boundary.** **Material.** pgBouncer with `auth_type=scram` presents *its own*
  userlist verifier, so the count belongs to the pooler, not the backend. Strongest safe subject:
  *the endpoint that authenticated this session.*
- **Current consumer proof.** `authenticate.go` and two tests.
- **Operator question.** *"Is this endpoint's password hashing configured to a safe strength?"*
- **Current svcdoctor answer.** `NO`. Nothing else in a run reports it.
- **Incremental value.** Real and unique. A server at `scram_iterations = 1` is a genuine
  deployment weakness invisible to every other svcdoctor output.
- **Failure of interpretation.** *"A high count means the server is secure"* — it says nothing
  about password quality, `pg_hba`, or TLS. And a count below 4096 is a `SHOULD` violation, not a
  vulnerability.
- **Compatibility.** `scram_iterations` is a PostgreSQL 16+ GUC; the count is present in every
  SCRAM server-first regardless. Kafka SCRAM has an equivalent number that svcdoctor **does not
  record at all**, so a finding here would be PostgreSQL-only — an asymmetry, not a blocker.
- **Real producibility.** `PROVEN_REAL` for the mechanism (`auth_test.go` asserts the attribute);
  a *low* value is `REACHABLE_NOT_PROVEN` but trivially fixturable — `SET scram_iterations = 1`
  then `ALTER ROLE … PASSWORD`, deterministic, no race.
- **Security.** No identity; a target-configuration fact.
- **Existing decision pressure.** **Strongly in favour, and unfired.** ADR 0038 §16 says *"a
  server configured at `scram_iterations=1` is a real deployment with a real weakness… recorded as
  an attribute so a Phase 4.6 rule can state the weakness"*; §17's table names it *"the only fact
  that can state a weak server configuration"*; `parse.go:293` says *"The count is returned so a
  caller can record it and a rule can say so later."* **Phase 4.6 came and went and built no such
  rule**, and PostgreSQL BASIC is now feature-frozen. **ADR 0040 §5 does not foreclose it**:
  *"Future independent findings — security posture, weak-mechanism policy, certificate posture,
  compliance signals — are therefore **not** foreclosed by this record."*
- **Gates.** value MEDIUM · authority **HIGH** · FP LOW · compat MEDIUM · noise LOW ·
  fixture **HIGH**.
- **Classification.** `C1B_DIAGNOSIS_CANDIDATE`. **Verdict: DEFER.**
- **Reason.** The strongest C1-B in the audit, and it is deferred on scope rather than on safety.
  Three costs, and the third is decisive. (1) It reopens **ADR 0040 §22's authorized attribute
  surface** — `TestTheRulesReadOnlyTheAuthorizedAttributes` allows four keys, the constant lives in
  `internal/adapter/postgres` where depguard makes it unreachable from diagnosis, and consuming it
  means moving it to `internal/service/postgres` *and* widening the allowlist. (2) It reopens the
  PostgreSQL **BASIC feature freeze**, which requires a recorded decision for "a new BASIC
  finding". (3) **It answers no incident question.** §8's bar asks whether the question occurs
  during an incident and changes the next diagnostic action; a weak iteration count changes
  neither — connectivity is unaffected and the remedy is a scheduled password rotation. It is a
  security-posture audit finding in a connectivity tool, and svcdoctor's severity and exit-code
  contract would have to answer whether a posture weakness is a "target-side problem" worth exit
  code 1. **Reopen when** a security-posture finding class is decided for the product as a whole —
  which would also give a home to TLS certificate posture and the weak-mechanism claim ADR 0040 §5
  names in the same sentence. Not as a side effect of a diagnosis phase. §9.3.

#### 7.21 `postgres.server_version`

- **Identity.** PostgreSQL · `internal/service/postgres/vocabulary.go:78` · written by
  `establish.go` from `ParameterStatus`.
- **Authority.** `PEER_SELF_DESCRIPTION`. **Domain.** **Unbounded** — retained as the server's own
  string with no length or character bound.
- **Subject.** The endpoint that served this session; a pooler reports its backend's or its own.
- **Current consumer proof.** No rule, no renderer. Tests only. **Missed by Phase 10.7A.**
- **Operator question.** *"What version am I actually talking to?"*
- **Current svcdoctor answer.** `NO` at the presentation layer; the JSON carries it.
- **Incremental value.** Moderate; Redis and RabbitMQ both render a version line, so PostgreSQL is
  the odd one out.
- **Failure of interpretation.** A pooler's version read as the backend's.
- **Security.** Version fingerprinting; unbounded peer bytes on a terminal.
- **Existing decision pressure.** **Explicitly declined by Phase 10.3, with a stated reopen
  condition**, at `internal/render/terminal/service.go:188-200`: *"`server_version` is deliberately
  not among them… a verbatim version line would put peer-chosen bytes on an operator's terminal…
  Redis and RabbitMQ already render a verbatim version, and that is a pre-existing cross-service
  question… it needs one decision about sanitizing observation values at the renderer boundary, for
  every service at once."*
- **Gates.** value MEDIUM · authority **LOW** (self-description) · FP MEDIUM · compat MEDIUM ·
  noise LOW · fixture HIGH.
- **Classification.** `DEFER_REQUIRES_ARCHITECTURE_DECISION`. **Verdict: DEFER.**
- **Reason.** Already deferred by an Accepted position with a named condition, and this audit finds
  no new fact that fires it. It is the third of three candidates blocked on one decision, which is
  itself the audit's most useful architectural signal (§9.2).

#### 7.22 `postgres.tls.plan`

- **Identity.** PostgreSQL · `negotiate.go:45` · written at `:134` as `params.TLS.String()`.
- **Authority.** `OPERATOR_INPUT`. **Domain.** Closed two-value: `"required"` / `"disabled"`.
  Recorded **only** on a node that did not negotiate.
- **Subject.** This run's TLS plan for this path.
- **Current consumer proof.** `negotiate.go` and one test.
- **Operator question.** *"Why was no TLS negotiated here?"*
- **Current svcdoctor answer.** `YES`, twice over. The operator passed `--tls disable`; ADR 0060
  gates `security.tlsVerificationDisabled` on the run's TLS plan and the terminal states it in the
  header; and the tree renders `not attempted` / `not attempted on this path` for the node itself
  (`tree.go:460-463`).
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.23 `postgres.transaction_status`

- **Identity.** PostgreSQL · `establish.go:64` · the `ReadyForQuery` status byte, normalized.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** Normalized; `"idle"` on every path ever measured.
- **Subject.** The frame that defines session success.
- **Current consumer proof.** `establish.go` and two tests.
- **Operator question.** *"Did the session reach a usable idle state?"*
- **Current svcdoctor answer.** `YES` — `ReadyForQuery` **is** the session-success boundary
  (ADR 0039), so a PASS session node already asserts it.
- **Incremental value.** Zero on every reachable path. The producer's own note explains why it is
  nonetheless recorded: *"svcdoctor issues no command that could open a transaction… a value other
  than 'idle' would say something no other observation could."* That is a tripwire for a future
  surprise, which is a legitimate reason to record and not a reason to render.
- **Real producibility.** A non-`idle` value is `NOT_REACHABLE_IN_BASIC` — svcdoctor executes no
  SQL.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture LOW.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**

---

### Redis / Valkey — 1

#### 7.24 `redis.auth_required`

- **Identity.** Redis · `internal/service/redis/vocabulary.go:107` · written by `hello.go:444` ·
  whether `HELLO` was refused with `NOAUTH` or answered outright.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL` — svcdoctor's boolean over a closed error prefix.
- **Domain.** `bool`. Recorded **only** when `HELLO` completed or was refused with `NOAUTH`, so it
  never claims either when `HELLO` itself did not complete.
- **Subject.** This endpoint's `HELLO` response. **Temporal scope.** This exchange.
- **Intermediary boundary.** A proxy answering `HELLO` itself would answer for itself.
- **Current consumer proof.** `hello.go` and one test. **But see §5**: the same underlying fact,
  read through `session.AuthRequired()`, drives composition-root path selection at
  `internal/app/redis.go:310` and `:331` and the `PING` classification at `ping.go:109`.
- **Operator question.** *"Does this endpoint require a password?"*
- **Current svcdoctor answer.** `YES`. The journey shows whether authentication was attempted, and
  the credential-withheld and credential-not-configured codes state the interesting cases
  explicitly.
- **Incremental value.** None: the boolean drives behaviour whose *outcome* is already rendered.
- **Failure of interpretation.** `auth_required: false` read as "this endpoint is open to the
  world" — it describes `HELLO`, not `bind`/`protected-mode`.
- **Compatibility.** Redis and Valkey identical.
- **Real producibility.** `PROVEN_REAL` — both suites exercise both values.
- **Existing decision pressure.** ADR 0066 (prefix-only classification); the build-forbidden
  command surface (`INFO`, `ROLE`, `CLUSTER`, `COMMAND`, `CONFIG GET`, `SELECT`) is untouched by
  this verdict, as it must be.
- **Gates.** value LOW · authority HIGH · FP MEDIUM · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE` (semantically consumed earlier). **Verdict: REJECT.**
- **Reason.** Redis has exactly one unconsumed attribute and it gets a full case file rather than
  a dismissal — but the honest answer is that it is not a gap. It is the input to a decision whose
  output is already visible. **Its doc comment is wrong** (§5.4) and that is worth fixing; the
  attribute is not worth surfacing. This audit manufactures no Redis candidate for symmetry.

---

### RabbitMQ / LavinMQ — 4

#### 7.25 `rabbitmq.close_outcome` — **THE WINNER**

- **Identity.** RabbitMQ · `internal/service/rabbitmq/vocabulary.go:155` · written by
  `open.go:222` · step `rabbitmq.connection_open` · the normalized classification of a
  `Connection.Close`.
- **Authority.** `DERIVED_FROM_DIRECT_PROTOCOL`, and the derivation is the strongest in the tree:
  svcdoctor **reconstructs** the expected sentence from its own vhost and username and compares
  for **byte equality** with a digit hole (ADR 0069 §3). Not a prefix match, not an infix match —
  both of which Phase 8.0C proved exploitable with a legally-named vhost.
- **Domain.** A **closed set of seven svcdoctor-owned string literals**:
  `UNSPECIFIED`, `UNSPECIFIED_TRUNCATED`, `VHOST_NOT_FOUND`, `VHOST_ACCESS_REFUSED`,
  `NODE_CONNECTION_LIMIT`, `VHOST_CONNECTION_LIMIT`, `USER_CONNECTION_LIMIT`. The producer's
  contract is explicit: *"Every value here is a literal declared in this file; **none is ever a
  slice of a peer's buffer**"* (`wire/close.go:5-10`). Recorded only when a refusal arrived.
- **Subject.** The refusal this endpoint issued for **this** connection attempt, by **this** user,
  naming **this** vhost.
- **Temporal scope.** **This instant.** A ceiling reached now may not hold in a second — which the
  existing detail already says and which the new sentence must not weaken.
- **Intermediary boundary.** LavinMQ produces different reply texts and was never measured
  producing any limit text at all, so it degrades to `UNSPECIFIED`. A proxy in front of RabbitMQ
  would have to reproduce the sentence byte for byte to be classified. Strongest safe subject:
  *the endpoint that refused this attempt named this ceiling.*
- **Current consumer proof.** `open.go` produces it; three tests reference it; **no rule and no
  renderer**. `internal/diagnosis/rabbitmq/connectionopen.go:133` switches on
  `node.FailureClass()`.
- **Operator question.** *"The broker refused my connection because a limit was reached — was it
  the node's limit, this virtual host's, or my user's?"*
- **Current svcdoctor answer.** **`NO`, and the output is visibly hedged because of it.** All
  three ceilings collapse into `FailureResourceLimitReached`, which shares one finding code —
  `RABBITMQ_CONNECTION_NOT_PERMITTED` — with `FailureAuthzNotPermitted`. The published text is:
  - Summary: *"This endpoint refused to open the connection"*
  - Detail: *"…refused the connection for a reason other than a missing virtual host or a
    permission decision. **Where** the endpoint named a capacity ceiling, that is recorded as what
    it said and nothing more."*
  - Recommendation: *"…review any **node, virtual host or user** connection limits"*

  The conditional *"Where"* and the three-way enumeration are the finding admitting it does not
  know which of four situations it is in — while the node it cites holds a byte-equality-verified
  constant that says exactly which. `TestGoldenRabbitMQResourceLimit` constructs
  `NODE_CONNECTION_LIMIT` and asserts output that never mentions it.
- **Incremental value.** The three ceilings have **three different owners and three different next
  actions**: a node ceiling affects every client on the broker and is a broker-wide capacity
  problem; a vhost ceiling affects one tenant; a user ceiling affects one application, most often
  its own connection leak. Today the operator is told to check all three. Additionally, the
  `FailureClass` already distinguishes *a ceiling was named* from *an unclassified refusal*, so the
  hedged `"Where…"` sentence is resolvable in the same change.
- **Failure of interpretation — the forbidden claims.** These must be stated and must remain
  forbidden: the limit is **not** *too low*; demand is **not** abnormal; there is **no** connection
  leak; the condition may **not** still hold; and — critically — **the absence of a named ceiling
  does not mean no ceiling was reached**, because a truncated or unmatched reply text degrades to
  `UNSPECIFIED`. Presence is evidence; absence is not.
- **Compatibility.** RabbitMQ 3.13.7 / 4.0.9 / 4.2.0 / `main`: byte-identical templates measured.
  **LavinMQ 2.3.0: no connection-limit text was ever measured**, only vhost-not-found and
  vhost-access-refused — so LavinMQ yields `UNSPECIFIED` and simply gets no extra sentence. The
  degradation is silent and safe, which is the property that makes this presentable across an
  implementation pair rather than only diagnosable on one.

  > **CORRECTED 2026-09-06 (Phase 10.8A.1, ADR 0091 §6). This paragraph, the "Intermediary
  > boundary" row above and the "Real producibility" row below are wrong.** LavinMQ **does**
  > produce `VHOST_CONNECTION_LIMIT`: template **L3** at
  > `internal/adapter/rabbitmq/wire/close.go:143-147`, measured live by **LMQ-06**
  > (`test/integration/lavinmq/scenarios_test.go:183-208`) against LavinMQ 2.3.0. The Phase 8.0C
  > study table this relied on listed only the two conditions 8.0C *measured*; L3 was
  > source-derived then, and the LavinMQ fixture has since measured it.
  >
  > The conclusion survives in a stronger form: it is presentable across the implementation pair
  > **because both reach the same closed outcome through the same byte-equality discipline**, not
  > because one stays silent. That forces ADR 0091 §6's rule — **the explanation is earned by the
  > authoritative outcome, never by product identity**, and no product-name branch exists.
  >
  > **Fixture status, re-measured.** `VHOST_CONNECTION_LIMIT` is **PROVEN_REAL and committed** on
  > real RabbitMQ (**RAB-21**, `test/integration/rabbitmq/vhost_test.go:104-137`, provisioned on
  > all three versions) and on real LavinMQ (**LMQ-06**). Only `NODE_CONNECTION_LIMIT` and
  > `USER_CONNECTION_LIMIT` remain unproven. This audit's grep searched `max_connections` and
  > `CONNECTION_LIMIT`; the fixtures spell it `max-connections` and name the vhost `limited`.
- **Real producibility.** `PROVEN_REAL` for the values —
  `docs/validation/RABBITMQ_PHASE80_CONTRACT_STUDY.md:125`: *"All three connection limits were
  reproduced live on 4.2.0."* — but `PROVEN_ONLY_UNIT` in the committed suite: no integration
  fixture produces any of them, and the only in-tree occurrence is the synthetic golden at
  `rabbitmqgolden_test.go:444`. A committed fixture is therefore a hard gate on 10.8B, and it is
  cheap: all three limits accept **0**, which the study already exercised
  (*"`: connection limit (0) is reached`"*), so `rabbitmqctl set_vhost_limits`,
  `set_user_limits` and a `connection_max` setting each refuse deterministically with no held
  connections and no race — the same trick Phase 10.3 used for PostgreSQL `CONNECTION LIMIT 0`.
- **Security.** **Clean.** The value is one of seven svcdoctor-owned literals. No hostname, no
  tenant name, no username, no version, no peer bytes. `rabbitmq.vhost` is separately
  `IdentityAttr` and stays redacted; the new sentence must not interpolate it.
- **Existing decision pressure — in favour, and it is a conflict.**
  - **ADR 0069 §6 states the design that the tree does not implement**: *"The three RabbitMQ
    ceilings share the class. The class explains the kind of break; the `FindingCode` **and the
    sentinel attribute** explain which ceiling. That is the division this repository already
    keeps."* The `FindingCode` does not distinguish them and the sentinel attribute reaches no
    operator-facing surface.
  - **ADR 0069 §9.4** describes the rejected fallback as *"every 530 with the distinction carried
    only by `FindingCode` — which **preserves the operator-visible difference**"*. The record
    assumed the difference was preserved.
  - **ADR 0069 §8 permits it by exclusion.** The table of what may not be said forbids
    `heartbeat`/`frame_max`/`channel_max` opinions, version policy, identity facts and `ANONYMOUS`
    posture — and forbids `VHOST_DOWN` from *"produc[ing] a restating detail sentence"* explicitly
    because it lacks *"a live measurement"*, under *"`namedConditions`' rule — membership requires
    having watched a real endpoint produce it."* All three ceilings satisfy that membership rule.
    A live-measured sentinel producing a restating detail sentence is the case §8 carves out.
  - The mechanism already exists: `vhostNotFoundDetail(node)` (`connectionopen.go:196`) reads
    `AttrVHostDefaulted` to refine a Detail. This is the same shape.
- **Gates.** value **HIGH** · authority **HIGH** · FP **LOW** · compat **LOW** · noise **LOW**
  (one clause on an already-failing path, never on a healthy run) · fixture **HIGH**.
- **Classification.** `C1A_PRESENTATION_CANDIDATE`. It presents a recorded fact and infers
  nothing. The *file* it is wired in lives under `internal/diagnosis` only because the Detail of
  an existing finding is the only honest home for the sentence; that is a location, not a layer
  promotion. **No rule is added, no claim is created, and the existing `RESOURCE_LIMIT_REACHED`
  semantics are untouched.** **Verdict: ADMIT.**

#### 7.26 `rabbitmq.graceful_close`

- **Identity.** RabbitMQ · `vocabulary.go:179` · written by `open.go` · whether the polite
  `Connection.Close`/`Close-Ok` epilogue completed after a successful open.
- **Authority.** `LOCAL_MEASUREMENT`. **Domain.** `bool`; recorded only when an epilogue was
  attempted.
- **Subject.** svcdoctor's own teardown of a session that had **already succeeded**.
- **Temporal scope.** After the terminal fact was recorded.
- **Current consumer proof.** `open.go` and four tests.
- **Operator question.** *"Did my connection shut down cleanly?"*
- **Current svcdoctor answer.** `NO` — and it should stay that way.
- **Incremental value.** None for the operator. The producer states the invariant: *"It can never
  change a verdict. Evidence is immutable and `Open-Ok` was recorded when it arrived, so a failure
  here is an attribute rather than a finding — and the AMQP specification agrees that a peer
  detecting socket closure without `Close-Ok` should log the error rather than fail (ADR 0067
  §9)."*
- **Failure of interpretation.** `graceful_close: false` read as a failed connection when the
  connection succeeded. This is the strongest reason **not** to render it.
- **Real producibility.** `PROVEN_REAL` for `true`; `false` is `REACHABLE_NOT_PROVEN`.
- **Gates.** value LOW · authority HIGH · FP **HIGH** · compat LOW · noise LOW · fixture LOW.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**

#### 7.27 `rabbitmq.peer_close_method`

- **Identity.** RabbitMQ · `vocabulary.go:170` · the class/method id the peer attributed its own
  `Connection.Close` to, as `"class/method"`.
- **Authority.** `PEER_SELF_DESCRIPTION`, and the producer says so: *"**Corroboration only.**
  Attribution authority is svcdoctor's own handshake state, which a peer cannot forge."*
- **Domain.** Two integers as a string.
- **Subject.** What the peer said about its own frame.
- **Current consumer proof.** `open.go` only. It never reaches `classify()` — the one RabbitMQ
  close attribute with no indirect consumption at all.
- **Operator question.** *"At which protocol step did the broker decide to refuse?"*
- **Current svcdoctor answer.** `YES` — svcdoctor's own handshake position is the authority, and
  the three-stage journey plus `DIAG_FAILURE_BOUNDARY` already publish it.
- **Incremental value.** Negative. **Phase 8.0C measured RabbitMQ sending `0/0` for an
  authentication refusal and LavinMQ sending `10/11` for the identical condition** (ADR 0069 §1).
  An operator comparing two implementations would see a difference that means nothing.
- **Failure of interpretation.** Treating `0/0` as "the broker did not know why".
- **Compatibility.** **Measured to differ.** This is precisely §14's *"do not create a compatibility
  claim from one implementation"*.
- **Real producibility.** `PROVEN_REAL`, on both implementations, disagreeing.
- **Gates.** value LOW · authority **LOW** · FP HIGH · compat **HIGH** · noise LOW · fixture HIGH.
- **Classification.** `C1D_UNSAFE_TO_CONSUME`. **Verdict: REJECT.**

#### 7.28 `rabbitmq.reply_code`

- **Identity.** RabbitMQ · `vocabulary.go:161` · the numeric AMQP reply code.
- **Authority.** `DIRECT_PROTOCOL` — *"The peer's own structured field rather than prose, so it is
  safe to carry verbatim — the same reasoning under which PostgreSQL renders a SQLSTATE."*
- **Domain.** Bounded `int16`; in practice `530`, `403`, `541`.
- **Subject.** This refusal frame.
- **Current consumer proof.** `open.go` and two tests. **But see §5**: `530` gates the sentinel
  switch in `classify()`.
- **Operator question.** *"What refusal code did the broker send?"*
- **Current svcdoctor answer.** `PARTIALLY`. The finding code carries the distinction the reply
  code supports — and the reply code alone is famously insufficient here: ADR 0069's whole sentinel
  apparatus exists because *"the reply code alone covers six semantically different conditions"*.
- **Incremental value.** Small and mostly negative: a bare `530` invites the operator to look it up
  and conclude something the sentinel already refused to conclude. The one case with residual value
  — distinguishing `541` vhost-down from `530` — is blocked because `541` was **never live
  measured** (ADR 0069 §6.2, §9.2 makes it a reopen condition).
- **Failure of interpretation.** Reading `530 NOT_ALLOWED` as an authorization problem when it
  covers six conditions including three capacity ceilings.
- **Compatibility.** Both implementations send codes; the meanings overlap imperfectly.
- **Real producibility.** `PROVEN_REAL` for `530`/`403`; `541` `REACHABLE_NOT_PROVEN`.
- **Gates.** value LOW · authority HIGH · FP **HIGH** · compat MEDIUM · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**
- **Reason.** Deliberately **not** bundled with §7.25 even though they sit on the same node.
  `close_outcome` is a byte-equality-verified constant; `reply_code` is the ambiguous number that
  constant exists to disambiguate. Publishing both would hand the operator the answer and the trap
  side by side.

---

### Generic transport — 10

#### 7.29 `dns.answers`

- **Identity.** DNS · `internal/probe/dns/lookup.go:43` · the resolved addresses.
- **Authority.** `LOCAL_MEASUREMENT` of a `DIRECT_PROTOCOL` answer. **Domain.** `AttrKindHostList`.
- **Subject.** This lookup, from this vantage, through this resolver.
- **Current consumer proof.** `lookup.go`, `transport/run.go` (the producer chain) and two tests.
  No rule — generic DNS diagnosis switches on `FailureClass` (`dns.go:139`).
- **Operator question.** *"What did this name resolve to?"*
- **Current svcdoctor answer.** `YES`. Every resolved address becomes the `Subject` of a
  `tcp.connect` node and of everything above it, and the terminal tree prints one branch per
  address. Under ADR 0059 an address literal produces no lookup node at all, so the two shapes stay
  distinguishable without this attribute.
- **Incremental value.** None; it would print the same addresses a second time.
- **Security.** Internal addresses, already `AttrKindHost`-redacted.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.30 `tls.cipher_suite`

- **Identity.** TLS · `internal/probe/tls/handshake.go:61`.
- **Authority.** `DIRECT_PROTOCOL` (negotiated). **Domain.** Bounded — Go's own suite registry.
- **Subject.** This handshake. **Temporal scope.** This connection.
- **Current consumer proof.** `handshake.go` and one test.
- **Operator question.** *"Is this connection using a strong cipher?"*
- **Current svcdoctor answer.** `NO`.
- **Incremental value.** A posture question, not a diagnosis question. Go's client offers only
  suites it considers acceptable, so the answer is "yes" by construction on every run that reaches
  here.
- **Failure of interpretation.** Reading a suite name as an endorsement of the endpoint's overall
  TLS configuration.
- **Existing decision pressure.** `docs/SCOPE.md` — no tuning advisor, no posture platform.
- **Gates.** value LOW · authority HIGH · FP MEDIUM · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_NO_OPERATOR_VALUE`. **Verdict: REJECT.**

#### 7.31 `tls.peer_certificate_count`

- **Identity.** TLS · `handshake.go:65`. **Authority.** `LOCAL_MEASUREMENT`. **Domain.** Small int.
- **Subject.** The chain this endpoint presented on this attempt.
- **Current consumer proof.** `handshake.go` and one test.
- **Operator question.** *"Did the endpoint send an incomplete chain?"*
- **Current svcdoctor answer.** `YES`, in the only form that is safe:
  `TLS_CHAIN_NOT_TRUSTED` fires when the chain does not verify, and its detail already explains
  that the claim is about a pairing and either half can be the reason. A count of 1 is perfectly
  valid when the root is in the trust store.
- **Incremental value.** None. A bare count cannot distinguish "incomplete chain" from "correctly
  minimal chain", so it invites exactly the inference it cannot support.
- **Gates.** value LOW · authority HIGH · FP **HIGH** · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_BOOKKEEPING`. **Verdict: REJECT.**

#### 7.32 `tls.peer_dns_names`

- **Identity.** TLS · `handshake.go:75` · the certificate's DNS SANs.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** Peer-chosen names; `AttrKindHostList`.
- **Subject.** The certificate presented on this attempt — which can depend on SNI and on the path.
- **Current consumer proof.** `handshake.go` and three tests.
- **Operator question.** *"My hostname did not match — what names does the certificate carry?"*
  A real and frequent incident question.
- **Current svcdoctor answer.** `PARTIALLY, by deliberate design.` `TLS_IDENTITY_MISMATCH`'s detail
  says *"The identity verified and the names presented are **both recorded on the referenced
  handshake evidence**"* and its recommendation says *"Compare the names on the presented
  certificate with the identity this run verified, **which is recorded on the referenced
  evidence**"*. The finding was written knowing the values are there and chose to **point** rather
  than **inline**.
- **Incremental value.** Convenience only; the operator already has a pointer to the exact node.
- **Security.** **The reason for the design.** SANs are internal hostnames. They are
  `AttrKindHostList` so redaction replaces them; interpolating them into a finding's `Summary` or
  `Detail` would put them in a **prose** field, where structural redaction cannot reach them
  without the regex matching ADR 0018 forbids relying on.
- **Existing decision pressure.** ADR 0018 (transform domain values, never serialized text);
  ADR 0058.
- **Gates.** value MEDIUM · authority HIGH · FP LOW · compat LOW · noise MEDIUM ·
  fixture HIGH.
- **Classification.** `C1D_UNSAFE_TO_CONSUME`. **Verdict: REJECT.**
- **Reason.** The one rejected attribute with genuine operator pull. It is refused because the
  gain is a pointer-following step and the cost is identity in a prose field, which is the exact
  boundary the redaction architecture is built on.

#### 7.33 `tls.peer_ip_addresses`

Identical to §7.32 for IP SANs. `AttrKindHostList`; already the subject of ADR 0058 §6's
measured IP-SAN verification behaviour; `TLS_IDENTITY_MISMATCH` covers a failed IP-SAN match.
**Classification.** `C1D_UNSAFE_TO_CONSUME`. **Verdict: REJECT.**

#### 7.34 `tls.peer_not_after`

- **Identity.** TLS · `handshake.go:70` · the leaf certificate's `notAfter`.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** A timestamp. **Bounded and safe to render.**
- **Subject.** The certificate presented on this attempt.
- **Temporal scope.** A stable property of that certificate.
- **Current consumer proof.** `handshake.go` and two tests. An **already expired** certificate is
  handled upstream: the handshake fails, `FailureTLSCertificateExpired` is set, and
  `TLS_CERTIFICATE_NOT_VALID_NOW` fires from the class (`tls.go:165`) — so the expired case is
  `SEMANTICALLY_CONSUMED_EARLIER`.
- **Operator question.** *"Is this certificate about to expire?"* — for a handshake that **passed**.
- **Current svcdoctor answer.** `NO`, deliberately.
- **Incremental value.** Real, and out of scope. It would require a threshold, which is a policy
  svcdoctor does not own, and a refresh cadence it cannot have from a one-shot run.
- **Failure of interpretation.** "svcdoctor is monitoring my certificates."
- **Existing decision pressure.** **Refused by an Accepted position.** `docs/BACKLOG.md:2425-2427`
  lists, among things *"deliberately not on this list, because they are not BASIC"*:
  *"certificate expiry on a **passing** handshake, which is **expiry monitoring rather than
  diagnosis** (ADR 0044)."* `docs/SCOPE.md` excludes a monitoring platform from v0.1.
  ADR 0053 §147 records that `tls.peer_not_after` exists so *a machine* can preserve the
  expired/not-yet-valid distinction.
- **Gates.** value MEDIUM · authority HIGH · FP MEDIUM · compat LOW · noise MEDIUM ·
  fixture HIGH.
- **Classification.** `C1D_NO_OPERATOR_VALUE` (out of product scope). **Verdict: REJECT.**

#### 7.35 `tls.peer_not_before`

The `notBefore` half of §7.34. The not-yet-valid case is likewise consumed earlier via
`FailureTLSCertificateNotYetValid` → `TLS_CERTIFICATE_NOT_VALID_NOW`; a passing handshake's
`notBefore` is in the past by definition and answers nothing.
**Classification.** `C1D_NO_OPERATOR_VALUE`. **Verdict: REJECT.**

#### 7.36 `tls.server_name`

- **Identity.** TLS · `handshake.go:40` · the identity this run asked to verify (SNI / verification
  target).
- **Authority.** `OPERATOR_INPUT`, possibly defaulted from the requested target.
- **Domain.** A hostname; `AttrKindHost`.
- **Current consumer proof.** `handshake.go` and four tests.
- **Operator question.** *"Which name did svcdoctor verify against?"*
- **Current svcdoctor answer.** `YES` — it is the operator's `--tls-server-name` or the requested
  target, and `TLS_IDENTITY_MISMATCH`'s prose names it as *"the identity this run verified"* and
  points at the node.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**

#### 7.37 `tls.trust_source`

- **Identity.** TLS · `handshake.go:55` · which trust material this run used.
- **Authority.** `OPERATOR_INPUT` (via `internal/security/trustsource`). **Domain.** A closed,
  bounded enum — one of the few here that would be safe to render verbatim.
- **Subject.** This run's trust context, not the peer.
- **Current consumer proof.** `handshake.go` and one test.
- **Operator question.** *"Was my `--tls-ca-file` actually used?"*
- **Current svcdoctor answer.** `PARTIALLY`. `TLS_CHAIN_NOT_TRUSTED`'s detail says *"**The trust
  context is this run's**: whether it was the system trust store or a file supplied…"* — it
  enumerates the possibilities rather than naming the one that applied. That is the same shape as
  §7.25's defect, and it is the closest thing to a second winner in this section.
- **Incremental value.** Materially lower than §7.25's, for one reason: the operator **chose** the
  trust source on the command line one moment earlier, so naming it back confirms an input rather
  than revealing a peer fact. §7.25 reveals something only the broker knew.
- **Failure of interpretation.** "svcdoctor used the system store, therefore my CA file was
  ignored" — when it may simply not have been passed.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise LOW · fixture HIGH.
- **Classification.** `C1D_DUPLICATE`. **Verdict: REJECT.**
- **Reason.** Rejected on the duplicate-value test in §9's terms: the operator loses nothing they
  cannot obtain from their own invocation. Recorded here rather than dropped, because it is the
  runner-up and a future generic-TLS phase may reasonably revisit it alongside mTLS.

#### 7.38 `tls.version`

- **Identity.** TLS · `handshake.go:58` · the negotiated protocol version.
- **Authority.** `DIRECT_PROTOCOL`. **Domain.** Bounded, `TLS 1.2` / `TLS 1.3` in practice.
- **Current consumer proof.** `handshake.go` and two tests.
- **Operator question.** *"Which TLS version did we negotiate?"*
- **Current svcdoctor answer.** `NO`; the tree shows the handshake succeeded and whether
  verification was disabled.
- **Incremental value.** Posture, not diagnosis. Go's client will not negotiate a version svcdoctor
  considers unacceptable, so the value is a narrow, uninformative range on every passing run; a
  version *problem* already lands as `TLS_HANDSHAKE_NOT_COMPLETED`.
- **Gates.** value LOW · authority HIGH · FP LOW · compat LOW · noise MEDIUM · fixture HIGH.
- **Classification.** `C1D_NO_OPERATOR_VALUE`. **Verdict: REJECT.**

---

## 8. The opportunity table — all 38 rows

| # | Service | Attribute | Authority | Operator question | Already answered? | Class | Real fixture | Verdict | Reason |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Kafka | `api_versions` | DERIVED | which API versions does this broker support? | PARTIALLY | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | 70-entry dump; needs undeclared client requirements |
| 2 | Kafka | `broker.advertised_host` | DIRECT | what address was advertised? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | already the advertisement's subject ref |
| 3 | Kafka | `broker.advertised_port` | DIRECT | what port was advertised? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | same subject ref; `_UNUSABLE` owns the claim |
| 4 | Kafka | `error_code` | DIRECT | what did the broker answer? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | consumed earlier into `FailureClass` |
| 5 | Kafka | `metadata.advertised_entry_count` | DERIVED | was a broker advertised twice? | NO | C1D_BOOKKEEPING | REACHABLE_NOT_PROVEN | REJECT | auditability of one collapse; no action changes |
| 6 | Kafka | `metadata.broker_count` | DERIVED | how many brokers advertised? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | identical to the topology finding's `N` |
| 7 | Kafka | `metadata.controller_id` | DIRECT | which node is controller? | NO | C1D_UNSAFE_TO_CONSUME | PROVEN_REAL | REJECT | measured 1,1,2,1,1,3,2,3 on a stable cluster |
| 8 | Kafka | `metadata.unrepresentable_entry_count` | DERIVED | did the topology counts cover everything? | NO | DEFER_REQUIRES_REAL_FIXTURE | NOT_REACHABLE_IN_BASIC | **DEFER** | real completeness gap; no supported fixture produces it |
| 9 | Kafka | `request_api_version` | INTERNAL | what version did svcdoctor ask? | NO | C1D_BOOKKEEPING | PROVEN_REAL | REJECT | svcdoctor's own build constant |
| 10 | Kafka | `sasl.offered_mechanisms` | DIRECT | which mechanisms does it accept? | NO | DEFER_REQUIRES_ARCHITECTURE_DECISION | PROVEN_REAL | **DEFER** | high value; unbounded peer text, no sanitization boundary |
| 11 | Kafka | `sasl.requested_mechanism` | OPERATOR | which did svcdoctor try? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | the operator's own flag |
| 12 | Kafka | `sasl.session_lifetime_ms` | DIRECT | when must I re-authenticate? | NO | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | client behaviour ADR 0008 keeps out |
| 13 | PostgreSQL | `database` | OPERATOR | which database? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | operator input; identity-classed |
| 14 | PostgreSQL | `error_severity` | DIRECT | how serious was the rejection? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | presence already drives `error_is_native` |
| 15 | PostgreSQL | `is_superuser` | DIRECT | did I connect with expected privilege? | NO | C1A_PRESENTATION_CANDIDATE | PROVEN_REAL | **DEFER** | safe but prints `off` on nearly every run; no misleading silence |
| 16 | PostgreSQL | `protocol_version` | INTERNAL | which protocol version? | YES | C1D_BOOKKEEPING | PROVEN_REAL | REJECT | hardcoded `"3.0"` |
| 17 | PostgreSQL | `role` | OPERATOR | which role? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | operator input; principal identity |
| 18 | PostgreSQL | `sasl_mechanism` | DERIVED | which mechanism was used? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | `auth_method` already carries it |
| 19 | PostgreSQL | `sasl_mechanisms` | DIRECT | what did the server offer? | PARTIALLY | DEFER_REQUIRES_ARCHITECTURE_DECISION | PROVEN_REAL | **DEFER** | unbounded peer text; same decision as row 10 |
| 20 | PostgreSQL | `scram_iterations` | DIRECT | is password hashing strong enough? | NO | C1B_DIAGNOSIS_CANDIDATE | REACHABLE_NOT_PROVEN | **DEFER** | needs a product-wide security-posture finding class |
| 21 | PostgreSQL | `server_version` | PEER_SELF_DESC | what version is this? | NO | DEFER_REQUIRES_ARCHITECTURE_DECISION | PROVEN_REAL | **DEFER** | explicitly deferred by Phase 10.3 on the same decision |
| 22 | PostgreSQL | `tls.plan` | OPERATOR | why no TLS here? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | operator input; header and tree both state it |
| 23 | PostgreSQL | `transaction_status` | DIRECT | did the session reach idle? | YES | C1D_BOOKKEEPING | NOT_REACHABLE_IN_BASIC (non-idle) | REJECT | `ReadyForQuery` is the success boundary |
| 24 | Redis | `auth_required` | DERIVED | does this endpoint need a password? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | drives path selection; outcome already rendered |
| 25 | **RabbitMQ** | **`close_outcome`** | **DERIVED** | **which ceiling refused me — node, vhost or user?** | **NO** | **C1A_PRESENTATION_CANDIDATE** | **PROVEN_REAL (uncommitted)** | **ADMIT** | **closed svcdoctor-owned enum; three different next actions; ADR 0069 §6 already says it should explain this** |
| 26 | RabbitMQ | `graceful_close` | LOCAL | did shutdown complete cleanly? | NO | C1D_BOOKKEEPING | REACHABLE_NOT_PROVEN | REJECT | can never change a verdict (ADR 0067 §9) |
| 27 | RabbitMQ | `peer_close_method` | PEER_SELF_DESC | at which step did it refuse? | YES | C1D_UNSAFE_TO_CONSUME | PROVEN_REAL | REJECT | RabbitMQ `0/0` vs LavinMQ `10/11` for one condition |
| 28 | RabbitMQ | `reply_code` | DIRECT | what code was sent? | PARTIALLY | C1D_DUPLICATE | PROVEN_REAL | REJECT | one code covers six conditions; the sentinel exists to disambiguate it |
| 29 | DNS | `answers` | LOCAL | what did the name resolve to? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | every address is a downstream subject and a tree branch |
| 30 | TLS | `cipher_suite` | DIRECT | is the cipher strong? | NO | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | posture, not diagnosis; Go offers only acceptable suites |
| 31 | TLS | `peer_certificate_count` | LOCAL | is the chain incomplete? | YES | C1D_BOOKKEEPING | PROVEN_REAL | REJECT | a count cannot distinguish incomplete from minimal |
| 32 | TLS | `peer_dns_names` | DIRECT | what names does the cert carry? | PARTIALLY | C1D_UNSAFE_TO_CONSUME | PROVEN_REAL | REJECT | identity into a prose field; the finding points at it by design |
| 33 | TLS | `peer_ip_addresses` | DIRECT | what IPs does the cert carry? | PARTIALLY | C1D_UNSAFE_TO_CONSUME | PROVEN_REAL | REJECT | same |
| 34 | TLS | `peer_not_after` | DIRECT | is the cert about to expire? | NO | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | expiry monitoring, not diagnosis (ADR 0044) |
| 35 | TLS | `peer_not_before` | DIRECT | is the cert not yet valid? | YES | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | consumed earlier; past by definition on a pass |
| 36 | TLS | `server_name` | OPERATOR | which name was verified? | YES | C1D_DUPLICATE | PROVEN_REAL | REJECT | operator input; the mismatch finding names it |
| 37 | TLS | `trust_source` | OPERATOR | was my CA file used? | PARTIALLY | C1D_DUPLICATE | PROVEN_REAL | REJECT | operator's own choice; runner-up, recorded not dropped |
| 38 | TLS | `version` | DIRECT | which TLS version? | NO | C1D_NO_OPERATOR_VALUE | PROVEN_REAL | REJECT | posture; a version problem lands as a handshake failure |

**38 rows, matching the corrected unconsumed count exactly.**

### 8.1 Shortlist — ADMIT and DEFER only

| # | Service | Attribute | Class | Verdict | Blocking gate |
|---|---|---|---|---|---|
| 25 | RabbitMQ | `close_outcome` | C1A | **ADMIT** | none |
| 10 | Kafka | `sasl.offered_mechanisms` | DEFER_ARCH | DEFER | renderer sanitization of unbounded observation values |
| 19 | PostgreSQL | `sasl_mechanisms` | DEFER_ARCH | DEFER | same |
| 21 | PostgreSQL | `server_version` | DEFER_ARCH | DEFER | same |
| 20 | PostgreSQL | `scram_iterations` | C1B | DEFER | a product-wide security-posture finding class |
| 15 | PostgreSQL | `is_superuser` | C1A | DEFER | operator value / output noise |
| 8 | Kafka | `unrepresentable_entry_count` | DEFER_FIXTURE | DEFER | no supported fixture can produce it |

---

## 9. Serious-candidate deep dive

### 9.1 `rabbitmq.close_outcome` — the winner

**BEFORE.** A run refused by a RabbitMQ node connection limit publishes
`RABBITMQ_CONNECTION_NOT_PERMITTED`, ERROR, CONFIRMED, HIGH, whose Summary is *"This endpoint
refused to open the connection"*, whose Detail hedges with *"**Where** the endpoint named a
capacity ceiling…"*, and whose single recommendation is *"…review any **node, virtual host or
user** connection limits."* The same three sentences appear for a vhost ceiling, a user ceiling,
and an unclassified 530 that is not a ceiling at all — four distinct situations, one output.

**FACT.** `rabbitmq.close_outcome` on the cited node, holding one of `NODE_CONNECTION_LIMIT`,
`VHOST_CONNECTION_LIMIT`, `USER_CONNECTION_LIMIT`, `VHOST_NOT_FOUND`, `VHOST_ACCESS_REFUSED`,
`UNSPECIFIED`, `UNSPECIFIED_TRUNCATED` — established by reconstructing svcdoctor's own expected
sentence and comparing byte for byte.

**AFTER.** The same code, the same severity, the same confidence, the same evidence refs — with a
Detail that names the ceiling the endpoint named and a recommendation scoped to it. Roughly:

> *The endpoint named a **node-wide** connection limit. It proves the endpoint refused at that
> moment; it proves nothing about why, for how long, or what to change, and a second run a moment
> later may succeed.*

**WHAT REMAINS UNKNOWN, and must stay so.** Whether the limit is appropriate. What the limit's
value is. Whether other clients are affected. Whether the condition persists. Whether the
application is leaking connections. Whether a *different* ceiling was also reached. And — the
subtle one — whether a ceiling was reached at all when the outcome is `UNSPECIFIED`, because
truncation destroys the sentinel: Phase 8.0C produced a 255-byte reply text with
`: connection limit (0) is reached` **entirely absent**.

**OPERATOR ACTION CHANGE.** Node ceiling → look at broker-wide `connection_max` and total
connections; affects every tenant. VHost ceiling → look at that vhost's limits; affects one
tenant. User ceiling → look at that user's limits, and this is the one that most often means the
operator's own application is leaking. Today all three produce the same instruction to check all
three.

**FALSE-POSITIVE ATTACK.** *A vhost is legally named `a': connection limit (5) is reached` and is
refused for lack of permission.* Phase 8.0C constructed exactly this and measured the reply text.
An infix matcher reports a capacity ceiling for an authorization denial. **svcdoctor's
construct-and-compare survives it**: the reconstructed sentinel for an access refusal is built
from the same vhost string and matches, so the outcome is `VHOST_ACCESS_REFUSED`. The attack is
already defeated in the producer, and consuming the outcome inherits that defence rather than
re-implementing it. The second attack — *a peer sends a ceiling sentence when no ceiling was
reached* — succeeds, and is bounded by the claim: svcdoctor says *the endpoint named this*, never
*this is true*.

**PROXY / COMPATIBILITY ATTACK.** *LavinMQ is the endpoint.* Phase 8.0C measured only
`vhost not found` and `vhost access refused` texts for LavinMQ; no limit text exists in the
record. LavinMQ therefore yields `UNSPECIFIED`, the new sentence does not appear, and the output
is byte-identical to today's. **The degradation is silent and correct**, which is why this is
presentable across an implementation pair — and why no compatibility claim is created from one
implementation.

> **CORRECTED 2026-09-06 (Phase 10.8A.1, ADR 0091 §6).** Wrong for the vhost ceiling: LavinMQ
> reaches `VHOST_CONNECTION_LIMIT` through template **L3**, measured by **LMQ-06**, and therefore
> **does** receive that explanation. The silent-degradation argument still holds for the node and
> user ceilings, which LavinMQ does not produce. The correct LavinMQ tests are that it *does* get
> the vhost explanation and gets **neither** of the other two — not a blanket negative contrast. *A proxy in front of RabbitMQ.* It would have to emit the sentence byte for byte,
including svcdoctor's own vhost and username, to be classified; if it does, the claim
*"the endpoint refused and named this ceiling"* is still exactly true of the endpoint svcdoctor
talked to.

**FIXTURE PLAN.** Three deterministic cases against a real RabbitMQ, using **limit 0** so nothing
races and nothing must be held open — the trick Phase 10.3 used for PostgreSQL `CONNECTION LIMIT
0`, and a value Phase 8.0C already exercised:

| Case | Provisioning | Expected |
|---|---|---|
| user ceiling | `rabbitmqctl set_user_limits app '{"max-connections":0}'` | `USER_CONNECTION_LIMIT` |
| vhost ceiling | `rabbitmqctl set_vhost_limits -p <v> '{"max-connections":0}'` | `VHOST_CONNECTION_LIMIT` |
| node ceiling | `connection_max = 0` in the node's config | `NODE_CONNECTION_LIMIT` |
| LavinMQ contrast | LavinMQ 2.3.0, any limit condition it supports | no new sentence; output unchanged |

No SQL, no management API, no channel, no passive declare, no admin credential beyond what the
existing fixture's provisioning step already uses, and nothing to clean up. The Phase 9.1C lesson
applies and must be honoured: **`rabbitmq-diagnostics ping` answers before `rabbitmqctl` works**,
so the gate must verify the limits were actually set rather than trusting `|| true`.

**MINIMUM IMPLEMENTATION (10.8B) — presentation enrichment of an existing diagnosis.** Move the
seven `CloseOutcome` literals into `internal/service/rabbitmq` as a closed constant set — the
established pattern, on the trigger that package already names, and required because depguard
denies `internal/diagnosis` the adapter. Then one closed lookup in
`internal/diagnosis/rabbitmq/connectionopen.go` from the already-recorded outcome to a detail
clause and a recommendation, applied through the mechanism `vhostNotFoundDetail` already uses.
Anything not in the lookup yields today's text exactly.

**It creates nothing.** No diagnostic rule is added; the existing `connectionOpenFinding` keeps
selecting the same code from the same `FailureClass`. No `FindingCode`, no severity, no
confidence, no exit-code movement, no failure class, no schema change, no new evidence, no
network request, no renderer file. The claim `RESOURCE_LIMIT_REACHED` already publishes is
unchanged and unweakened — the phase only stops the prose from discarding a bounded distinction
the evidence already carries.

> **CORRECTED 2026-09-06 (Phase 10.8A.1, ADR 0091 §3, §4, §7).** Every clause above is true except
> the implication. `Finding.Detail` and `Finding.Recommendations` are **canonical domain fields
> emitted by `Finding.MarshalJSON`**, so this is not renderer-adjacent work: **canonical JSON bytes
> change** for reports carrying a mapped capacity outcome. The *schema*, the field set and both
> schema versions are unchanged, and unmapped outcomes stay byte-identical — ADR 0091 §9 is the
> replacement contract. Two further narrowings: **recommendations stay byte-identical by default**
> (ADR 0091 §7), and the frozen term is **canonical explanation enrichment** rather than
> "presentation" (ADR 0091 §5). The candidate stays **C1-A**.

### 9.2 The three attributes blocked on one decision

`kafka.sasl.offered_mechanisms`, `postgres.sasl_mechanisms` and `postgres.server_version` all fail
on the same gate: **their domain is unbounded peer text and svcdoctor has no sanitization boundary
at the renderer.** Redis and RabbitMQ already render a verbatim `server_version` and a verbatim
`product`/`platform`, so the exposure exists today in two services and is refused in two others —
which is not a defensible steady state.

**BEFORE.** `KAFKA_AUTH_MECHANISM_NOT_OFFERED` tells the operator to go read
`sasl.enabled.mechanisms`; PostgreSQL's unsupported-mechanism finding names what svcdoctor speaks
but not what was offered; PostgreSQL alone among four services shows no version line.
**AFTER**, if the decision were taken: three answers svcdoctor already holds.
**WHAT REMAINS UNKNOWN:** whether a credential will be accepted by any offered mechanism.
**FIXTURE PLAN:** trivial — every existing suite already reaches all three.
**MINIMUM IMPLEMENTATION:** none here. This audit's contribution is to state that the decision now
blocks **three** candidates across **two** services rather than one, and that it should be taken
once for all four services, per the architecture rule against conditional sprawl. It is **not**
proposed as 10.8B, because a sanitization boundary is a renderer-security decision that deserves
its own record and its own review, and bundling it under a RabbitMQ detail sentence would be
exactly the side-effect widening this repository refuses.

### 9.3 `postgres.scram_iterations`

**BEFORE.** A server configured `scram_iterations = 1` authenticates svcdoctor successfully and
produces a completely clean report. The weakness is invisible.
**FACT.** The count, protocol-direct, digit-validated, bounded, on the authentication node.
**AFTER.** A finding could state that the endpoint's SCRAM verifier is configured below RFC 7677
§4's recommended 4096.
**WHAT REMAINS UNKNOWN.** Password quality, `pg_hba` posture, TLS posture, whether the verifier
belongs to a pooler, whether the operator can change it.
**OPERATOR ACTION CHANGE.** Schedule a password rotation after raising the GUC. **Not an incident
action.**
**FALSE-POSITIVE ATTACK.** pgBouncer with `auth_type=scram` presents its own userlist verifier;
a finding naming "the server" would blame the wrong component. Scoping the subject to *the
endpoint that authenticated this session* defeats it, as ADR 0040 §18 already requires.
**COMPATIBILITY.** Kafka SCRAM has the same number and svcdoctor does not record it, so the
product would warn about one service and stay silent about the other for the same weakness.
**FIXTURE PLAN.** `SET scram_iterations = 1; ALTER ROLE app PASSWORD '…';` — deterministic.
**MINIMUM IMPLEMENTATION.** Move the constant to `internal/service/postgres`, widen ADR 0040 §22's
four-key allowlist to five, add one code. That is three reopens for a claim that changes no
incident action — which is why it is DEFER and not ADMIT, and why the reopen condition is a
product-wide posture decision rather than a PostgreSQL phase.

---

## 10. Adversarial self-review of the winner

Every question §37 asks, against `rabbitmq.close_outcome`.

1. **Selected because the field exists?** No. Selected because the finding's own prose enumerates
   three possibilities the cited node already resolves, and because ADR 0069 §6 says the attribute
   is supposed to be doing this.
2. **Does an existing finding say it?** No. `RABBITMQ_CONNECTION_NOT_PERMITTED` covers four
   situations with one sentence, verified in code and in `TestGoldenRabbitMQResourceLimit`.
3. **Would an experienced operator change their next action?** Yes, and demonstrably: a node
   ceiling is a broker capacity problem, a user ceiling is usually the caller's own leak. The
   current recommendation asks them to check all three.
4. **Confusing self-description with protocol authority?** No. It is not what the peer *called
   itself*; it is a reconstruct-and-compare match against svcdoctor's own expected sentence, and
   the alternative interpretations were adversarially tested in Phase 8.0C.
5. **Turning a negotiated number into a configuration opinion?** No — and this is the
   discriminator against `channel_max`/`frame_max`/`heartbeat`, which ADR 0069 §8 forbids for
   exactly that reason. Those are negotiated integers with no protocol-defined "good" value. This
   is a categorical statement the endpoint itself made about why it refused.
6. **Assuming operator intent?** No. No expectation is required. The endpoint named the condition.
7. **Assuming server identity through a proxy?** No. The subject is *the endpoint that refused this
   attempt*, and the claim is *it named this*.
8. **Assuming stability from one response?** No, and the existing sentence about impermanence is
   retained verbatim: *"a second run a moment later may succeed."*
9. **Using presentation to sneak in diagnosis?** This is the sharpest question, because the file
   it is wired in sits under `internal/diagnosis`. The answer is that it emits **no new claim and
   performs no inference**: the existing `RESOURCE_LIMIT_REACHED` class already asserts that a
   ceiling was named, and the presented sentence only preserves *which* — a specificity the
   canonical evidence already holds and the prose currently discards. No new rule, no new code, no
   severity change, no exit-code movement, no confidence admission. §11's authority test is
   therefore satisfied by the very evidence that already justified the class, because nothing new
   is being asserted from it.
10. **Could a compatible implementation produce a different but valid value?** Yes — LavinMQ
    produces no limit sentinel at all. That is handled by producing no sentence, which is why the
    compatibility risk is LOW rather than merely acceptable.
11. **Is the fixture easy only because the claim was weakened?** No. The claim is the strongest one
    the evidence supports and the fixture proves the exact branch. If anything the fixture proves
    more than the claim needs, since limit 0 is a stronger condition than a limit merely reached.
12. **Would it make svcdoctor look sophisticated without reducing uncertainty?** No. It removes a
    three-way disjunction from a recommendation.

**The strongest candidate survives.** No fallback to candidate #2 was needed, and none was
performed automatically: §9.2 and §9.3 were each evaluated on their own gates and each failed one
independently of the winner's outcome.

---

## 11. Service-level adversarial conclusions

### 11.1 Kafka

Kafka has the most unconsumed attributes — **12 of 14** — and **quantity was not allowed to become
signal.** Ten are rejected: two are the advertisement's own subject in a second spelling; two are
counts the topology finding and the terminal already print; one is svcdoctor's own build constant;
one is the operator's own flag; one is consumed earlier into a failure class; one is a 70-line
protocol dump; one is client behaviour ADR 0008 excludes; and one — `controller_id` — carries the
experiment that disqualifies it in its own doc comment. **The 1, 1, 2, 1, 1, 3, 2, 3 measurement
was reproduced from repository source** at `internal/adapter/kafka/metadata.go:65-68`, against a
stable three-broker Apache Kafka 4.0 KRaft cluster whose quorum leader never moved. It does not
merely weaken operator value; it eliminates it in both directions, because a *presented*
controller id will be read as naming the controller just as surely as a diagnosed one.

No topic was requested, no `DescribeCluster` was proposed, and no ISR/leader/partition acquisition
was weighed — all are Class 2/3 and out of this phase's scope.

Two Kafka attributes survive as DEFERs, and they are the interesting result. `offered_mechanisms`
is the highest-*value* candidate in the entire audit and loses on a single safety gate.
`unrepresentable_entry_count` exposes a genuine soundness gap in a Phase 10.2 completeness claim
(§7.8, §12) that no supported fixture can exercise.

### 11.2 PostgreSQL

Recalculated: **11 of 17**, not the 9 the 10.7A table recorded nor the 10 its prose named —
`default_transaction_read_only` left the set in 10.7B, and `role` and `server_version` were never
in it. Seven are rejected as operator input, svcdoctor constants, earlier-consumed presence
signals or duplicates of `auth_method`. Four are deferred.

No SQL was proposed. Role mismatch was not reopened. Nothing infers writable, primary or replica:
the two session facts stay two facts, and the audit adds no third. The strongest PostgreSQL
candidate, `scram_iterations`, is the one place where the repository *asked for* a rule — ADR 0038
§16 and `parse.go:293` both say a rule should say this later — and it is still deferred, because
the claim is security posture rather than connectivity and its natural home is a decision that
would also cover certificate posture and weak-mechanism policy, which ADR 0040 §5 names in the
same sentence.

### 11.3 Redis / Valkey

**One** unconsumed attribute, and it received a complete case file rather than a dismissal —
§7.24. The verdict is REJECT: `redis.auth_required` is the input to a decision whose output is
already rendered, and the composition root reads the adapter's Go method rather than the
attribute. **No Redis candidate was manufactured for symmetry.** The build-forbidden command
surface — `INFO`, `ROLE`, `CLUSTER`, `COMMAND`, `CONFIG GET`, `SELECT` — is untouched, no new
command is proposed, and the `LOADING`/`MASTERDOWN`/`BUSY` activation stays deferred on ADR 0088
§2.5's own fixture condition, which nothing in this audit fires.

The one Redis deliverable is a documentation correction (§5.4), not a feature.

### 11.4 RabbitMQ / LavinMQ

**Four** unconsumed attributes, confirming the historical count exactly — and 10.7A's summary of
them, *"all four are what the adapter derived the failure class from, which the rule then keys on;
not gaps"*, is **right about three and wrong about the fourth**. `peer_close_method` never reaches
`classify()` at all. And `close_outcome` is derived into a class that is **strictly coarser than
the attribute**: three distinct ceilings, plus a fourth unrelated condition, arrive at one
`FindingCode`. That is not "not a gap"; that is a gap hidden by a true sentence.

`channel_max`, `frame_max` and `heartbeat` were **not** turned into configuration findings — they
are already rendered as offered/selected pairs, they have no protocol-defined good value, and
ADR 0069 §8 forbids an opinion about them for want of an operator-supplied expectation. No channel
was opened, no management API was proposed, and nothing was passive-declared.

---

## 12. ADR conflicts and imprecisions recorded, not fixed

Per §2 of the phase contract, conflicts are recorded and production behaviour is left alone.

| # | Conflict | Where | Disposition |
|---|---|---|---|
| C1 | **ADR 0069 §6 describes a division the tree does not implement.** *"The `FindingCode` and the sentinel attribute explain which ceiling"* — the code does not distinguish the three ceilings and the attribute reaches no operator-facing surface. §9.4 further assumes *"the operator-visible difference"* is preserved. | ADR 0069 §6, §9.4 vs `internal/diagnosis/rabbitmq/connectionopen.go:162-177` | **This is the winner.** Resolved by 10.8B, not by editing the ADR |
| C2 | **ADR 0084 §4's completeness predicate cannot see an unrepresentable advertisement.** `complete` is computed over the exchange's children; an entry that produced no child is invisible, so `detailTopologyComplete` can claim the counts *"account for the whole advertised set"* when they do not. ADR 0035 §1 anticipated the missing *finding*, not this later *overclaim*. | ADR 0084 §4 vs `internal/diagnosis/kafka/topology.go:347` and `internal/adapter/kafka/metadata.go:350` | **DEFER** — no supported fixture produces the condition; recorded in ADR 0090 §6 as a reopen condition |
| C3 | **`internal/service/redis/vocabulary.go:105-106` claims a renderer reads `redis.auth_required`.** No renderer ever has, since `aba0d45`. | comment vs `internal/render/terminal/service.go` | Documentation defect; no behaviour is wrong |
| C4 | **`internal/service/rabbitmq/vocabulary.go:152` says rules read `close_outcome`.** They read the derived `FailureClass`. | comment vs `connectionopen.go:133` | Documentation imprecision; superseded in substance by 10.8B |
| C5 | **Phase 10.7A's inventory table contradicts its own prose** (24 vs 27) and omits `postgres.role` and `postgres.server_version`. | `PHASE107A…md` §2 | Corrected here in §4 and in the BACKLOG row; the historical record is not edited |

None of C1–C5 required production semantics to resolve, so none is a STOP condition.

---

## 13. Gates

**Phase 10.4C — CLOSED.** No competing hypothesis pair emerged. The winner produces no
`HYPOTHESIS`; RabbitMQ emits zero hypotheses in total; and the §23 test fails at (A) for every
candidate — none has two real hypotheses that cannot both be true. `IndistinguishableSets()`,
`DiscriminatorID` and grouping identity were not designed, sketched or referenced.

**Phase 10.5B — CLOSED.** No candidate needs `CONTRADICTION`, `MISSING` or `BLOCKED`. The winner's
basis is a single supporting node — the same node the finding already cites — so `.Support` alone
suffices and ADR 0087's OUTCOME C is undisturbed. No relation producer is proposed. `AdmitConfidence`'s
two vacuous guards stay vacuous and stay paired.

**Declared intent — UNCHANGED and not smuggled.** ADR 0083 §2.6 still binds. Two candidates were
classified as intent-adjacent and neither was admitted: `is_superuser` (§7.15) defers partly
because its useful form needs an expected privilege, and `api_versions` (§7.1) is unusable without
declared client requirements. The winner needs **no** expectation: the endpoint named the
condition itself, which is precisely why it clears the gate that `channel_max`, `frame_max` and
`heartbeat` fail.

**PostgreSQL BASIC feature freeze — NOT REOPENED.** The winner is RabbitMQ. The one PostgreSQL
candidate that would have reopened it (`scram_iterations`, a new BASIC finding) is deferred.

**Kafka topic surface — UNTOUCHED.** `Topics = []` stands; nothing here proposes a topic-scoped
`Metadata`.

**Redis command allowlist — UNTOUCHED.** No new command, no new literal.

---

## 14. Requirement register — `ECA-001` … `ECA-024`

Tiers: **F** frozen · **N** binding on Phase 10.8B · **D** deferred.

### 14.1 Methodology and inventory — FROZEN

| ID | Tier | Requirement |
|---|---|---|
| ECA-001 | **F** | A **recorded evidence attribute** is a `domain.AttributeKey` constant written into `EvidenceInput.Attributes` by non-test production code. Adapter locals, wire fields, failure classes, finding fields, report metadata, config values and renderer labels are excluded (§2.1) |
| ECA-002 | **F** | **Canonical JSON serialization is not consumption.** Consumption means a rule reads it or a renderer deliberately presents it as an operator-facing observation. Kind-driven redaction is not consumption (§2.2) |
| ECA-003 | **F** | The inventory is built by alias-resolving static reference scan and then falsified by tracing literals, map iteration, generic render paths and failure-class derivation (§2.3, §4, §5) |
| ECA-004 | **F** | Every attribute with no rule and no renderer consumer receives an **individual case file**. No sampling, no representative subset, no residual prose category (§6, §7) |
| ECA-005 | **F** | The **indirect-consumption pass is mandatory**: before an attribute is called unconsumed, the audit must ask whether the adapter already derived the `FailureClass` diagnosis keys on (§5) |

### 14.2 Admission gates — FROZEN

| ID | Tier | Requirement |
|---|---|---|
| ECA-006 | **F** | Every admitted or deferred candidate maps to **one concrete operator question** that occurs during an incident and changes the next diagnostic action. Protocol trivia is rejected |
| ECA-007 | **F** | **Authority is classified explicitly.** Peer self-description never carries the authority of a structured protocol field, and is never promoted into diagnosis without its own justification |
| ECA-008 | **F** | **A negotiated integer is not a configuration opinion** without a protocol-defined threshold or a declared application requirement |
| ECA-009 | **F** | **Duplicate-value test.** If deleting the candidate loses the operator nothing they cannot obtain from existing svcdoctor output, it is a duplicate and is rejected |
| ECA-010 | **F** | **Information-value test.** `BEFORE ≈ AFTER` with different wording is diagnostic theatre and is rejected |
| ECA-011 | **F** | **Data minimization.** Canonical presence never authorizes richer presentation. Where presentation widens practical disclosure the audit records it |
| ECA-012 | **F** | **Presentation is not free.** A true, bounded, safe fact that does not help during diagnosis is rejected. svcdoctor is not a protocol dump |
| ECA-013 | **F** | **Diagnosis is not presentation.** A C1-B candidate must prove a finding adds what a bounded observation cannot. A candidate needing an expectation svcdoctor does not hold is `DEFER_REQUIRES_INTENT` |
| ECA-014 | **F** | **Every candidate states its strongest forbidden claim**, and a candidate whose safe form cannot avoid inviting a false inference is rejected or deferred |
| ECA-015 | **F** | **Compatibility is a first-class gate**, evaluated per implementation pair. Presentation may be safe where diagnosis is not; the two are separated |
| ECA-016 | **F** | **Real-fixture gate.** Unit-manufacturable is not producible. A semantically important branch that no supported fixture can produce is normally deferred, and the claim is never weakened to make a fixture easier |
| ECA-017 | **F** | **At most one winner.** "Nothing is worth implementing" is a valid and successful outcome |
| ECA-018 | **F** | Qualitative gates are `HIGH`/`MEDIUM`/`LOW` analytical labels. **No numeric scoring**, and they are never `domain.Confidence` |
| ECA-019 | **F** | **Unconsumed is not debt.** An attribute recorded for auditability, protocol legibility or future reasoning has earned canonical evidence and has earned nothing else |

### 14.3 Binding on Phase 10.8B — NEXT_IMPLEMENTATION

| ID | Tier | Requirement |
|---|---|---|
| ECA-020 | **N** | 10.8B consumes `rabbitmq.close_outcome` **and acquires nothing**: no probe, command, frame, channel, management API, round trip, connection or credential authority |
| ECA-021 | **N** | The consumed value comes from a **closed constant set** relocated into `internal/service/rabbitmq`. An outcome not in the map produces **today's text byte for byte**. No peer byte reaches a claim |
| ECA-022 | **N** | **No new `FindingCode`, no severity change, no confidence change, no exit-code movement, no failure class, no schema change, no `RuleContext` change, no dependency, no CLI change.** Counts stay 65 / 42 / 3 / 2 / 4 / 4 / 1 / 1 / 5 |
| ECA-023 | **N** | The claim is **the endpoint named this ceiling**, scoped to this attempt and this instant. The forbidden set of §9.1 — limit too low, abnormal demand, connection leak, condition persists, absence proves no ceiling — must be unreachable, and the existing impermanence sentence is retained |
| ECA-024 | **N** | **A real fixture must produce all three ceilings** on a supported RabbitMQ, and a LavinMQ case must prove the output is unchanged where no sentinel matches. 10.8B may not close without both, and the provisioning gate must verify the limits were set rather than trusting `\|\| true` (Phase 9.1C) |

### 14.4 Deferred

| Item | Condition |
|---|---|
| Renderer sanitization of unbounded observation values | one decision for **all four services**, with its own record; unblocks `kafka.sasl.offered_mechanisms`, `postgres.sasl_mechanisms` and `postgres.server_version` together |
| A product-wide **security-posture finding class** | would give `postgres.scram_iterations`, TLS certificate posture and ADR 0040 §5's weak-mechanism claim one home; needs its own review and its own severity/exit-code answer |
| `postgres.is_superuser` as an observation line | an operator question that turns on connection privilege — most plausibly declared intent |
| Kafka topology completeness vs unrepresentable entries (**C2**) | a supported fixture that produces an unrepresentable advertisement, or an argued decision that `complete` must read the count regardless |
| `rabbitmq.reply_code` `541` distinction | ADR 0069 §9.2 — a live `VHOST_DOWN` measurement |
| Redis `LOADING`/`MASTERDOWN`/`BUSY` | ADR 0088 §2.5 — a fixture that produces one |
| Kafka partition/leader/ISR | ADR 0089 §3.1 — a record authorizing topic-scoped `Metadata` |
| Documentation defects **C3** and **C4** | a maintenance change; not bundled into 10.8B |

---

## 15. Was the "unused attributes" backlog wording misleading?

**Yes, in three ways, and the row is revised.**

1. Its **number was wrong** — the table said 24 while the same paragraph named 27, and the true
   service-scoped figure at this baseline is 28 (§4).
2. It framed the set as a **pool to draw from**: *"This is the pool the next several candidates
   should be drawn from."* This audit tried every one of them and found **one**. Six more are
   deferred and **31 are rejected**, most on grounds that will never change — a duplicate of a
   subject reference does not stop being a duplicate.
3. Most importantly, its title — *"Twenty-four recorded evidence attributes are consumed by
   nothing"* — reads as debt. The distinction this phase freezes as ECA-019 is that
   **recorded-but-unconsumed is not actionable diagnostic debt.** An attribute recorded so that a
   collapse is auditable, so that a future surprise has a tripwire, or so that a machine reading
   JSON can interpret an error code, has earned its place in canonical evidence and has earned
   nothing further. It should not appear on a roadmap.

The corrected classification of all 38:

```
38 recorded-but-unconsumed
 ├──  1  presentation opportunity  (ADMIT)              rabbitmq.close_outcome
 ├──  1  presentation opportunity  (DEFER)              postgres.is_superuser
 ├──  1  diagnosis opportunity     (DEFER)              postgres.scram_iterations
 ├──  0  next-evidence opportunities
 ├──  3  blocked on one architecture decision (DEFER)   two mechanism lists + server_version
 ├──  1  blocked on a real fixture (DEFER)              kafka unrepresentable_entry_count
 └── 31  intentional non-consumption (REJECT)
          ├──  6  bookkeeping
          ├── 14  duplicate
          ├──  4  unsafe to consume
          └──  7  no operator value
```

---

## 16. Outcome

**ACTIVATE RABBITMQ PRESENTATION.**

The Class-1 frontier is **not** exhausted, but it is **nearly** exhausted, and the shape of what
remains is the audit's real finding. Of 38 attributes recorded and read by nothing, **31 will never
be worth consuming** — they are duplicates of subject references, operator input echoed back,
svcdoctor's own constants, measurements proven unstable, or identity that must not enter prose.
Six are blocked, and **four of those six are blocked on just two decisions** neither of which is a
service phase's to take.

Exactly one attribute is both valuable and safe today, and the argument for it was already written
down: ADR 0069 §6 says the sentinel attribute explains which ceiling, ADR 0069 §9.4 assumes the
operator-visible difference is preserved, and the product does neither. An operator refused by a
RabbitMQ capacity ceiling is currently told to check the node's limits, the virtual host's limits
and the user's limits — while the evidence node cited three lines above holds a
byte-equality-verified constant naming exactly which one of the three it was.

**This is an information-loss defect, not a missing diagnosis.** The diagnosis is already correct
and already made: `RESOURCE_LIMIT_REACHED` is the right class, `RABBITMQ_CONNECTION_NOT_PERMITTED`
is the right code, and neither changes. What is lost is *specificity the canonical evidence
already holds*, discarded between the graph and the operator. Phase 10.8B recovers it in
presentation. It makes no new inference, admits no confidence, and asserts nothing the report did
not already assert.

---

## 17. Validation run

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 0043139
git status --short                               # clean at start
make check                                       # exit 0 — MANDATORY, before edits
  fmt-check: OK · go test ./... · go vet ./... · golangci-lint "0 issues." · build
go test ./test/security/ -run TestTheConvergenceInventoryIsComplete -v
  # 22 rules; attributed 65 of 65 declared finding codes
make check                                       # exit 0 — MANDATORY, after edits
git diff --check                                 # clean
git diff --name-only | grep -E '\.(go|mod|sum)$' # no output
```

The attribute inventory was re-run after the documentation edits and the counts in §3 were
re-derived unchanged: **70 recorded**, **10 diagnosis-consumed**, **24 renderer-consumed**,
**2 both**, **38 neither**.

**Not run, and no green claim is made for any of them:** every container integration suite —
PostgreSQL, Kafka, Redpanda, Redis, Valkey, RabbitMQ, LavinMQ, multi-target — every mutation
harness (`scripts/phase*-mutations.sh`), and every fuzz target. **This phase changed no
production, test, protocol or fixture behaviour**, so there is nothing for them to measure that
the baseline run did not already establish.
