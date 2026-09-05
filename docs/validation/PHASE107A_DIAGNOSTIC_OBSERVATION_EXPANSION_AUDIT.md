# Phase 10.7A — diagnostic observation expansion audit

- **Phase:** 10.7A — architecture / archaeology. **No production Go, no test Go, no config.**
- **Baseline:** `92158d128b6e85faddf959f6c97e72f31f7342fc`, working tree clean
- **Record:** ADR 0089
- **Outcome:** **ACTIVATE EXISTING OBSERVATION** — PostgreSQL session read-only observation
  completion. Class 1. No probe, command, query, request or authority added.

---

## 1. Baseline, as measured

| Fact | Value | How |
|---|---|---|
| `HEAD` == `origin/main` | `92158d1` | `git rev-parse` |
| working tree at start | clean | `git status --short` empty |
| `make check` | **exit 0** | fmt-check OK · test · vet · lint *0 issues* · build |
| `SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| finding codes | **65** | convergence scan: *attributed 65 of 65* |
| production rules | **22** | convergence scan |
| `RuleContext` fields | **3** | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| failure classes | **42** | unchanged; none touched |
| external modules | **2** | `TestTheDependencyCountIsExact`, `TestTheModuleGraphIsExactlyWhatWasDecided` |
| `Reveal` / `SecretFor` | **4 / 4** | `TestRevealHasOneProductionCallSitePerService` |
| exit codes | **5** | `docs/SCOPE.md`, unchanged |

**CI contract.** `.github/workflows/ci.yml` job *Quality gates* runs `make fmt-check`, `make test`,
`make vet`, `make build` and `golangci/golangci-lint-action@v9` pinned to **v2.13.1**;
`.golangci.yml` enables `staticcheck` with default checks. `go vet` alone is **not** the gate.
`make check` is the authoritative local mirror and was run before and after.

**Service state.** Kafka intelligence: 2 topology codes (ADR 0084). PostgreSQL intelligence: 2
codes (ADR 0085). Redis/Valkey BASIC: 9 codes, 4 rules. RabbitMQ/LavinMQ BASIC: 11 codes, 3 rules.
Next-best evidence: `Advice` → `Recommendation` plumbed (10.4B); no set engine (10.4C gated).
Evidence relations: `.Support` only, 1 site (ADR 0087, OUTCOME C). Probe boundary: DNS/TCP/TLS
generic; three Redis commands; one AMQP connection with `channel_max 1`; Kafka `Metadata` with an
**empty** topic list; PostgreSQL **no SQL**. Credential authority: one `Reveal` per service in its
wire package, endpoint-bound, no discovered-endpoint inheritance.

---

## 2. The consumption inventory — the phase's central measurement

Every evidence attribute the four adapters record, against whether any production rule or renderer
reads it.

| Service | Recorded | Rule reads | Renderer reads | **Consumed by nothing** |
|---|---|---|---|---|
| Kafka | 14 | 2 | 1 | **10** |
| PostgreSQL | 17 | 5 | 3 | **9** |
| Redis/Valkey | 7 | 2 | 5 | **1** |
| RabbitMQ/LavinMQ | 21 | 2 | 15 | **4** |
| **Total** | **59** | | | **24** |

**Unconsumed, by service.** Kafka: `api_versions`, `broker_advertised_host`,
`broker_advertised_port`, `error_code`, `metadata.advertised_entry_count`,
`metadata.broker_count`, `metadata.controller_id`, `metadata.unrepresentable_count`,
`request_api_version`, `sasl.offered_mechanisms`, `sasl.requested_mechanism`,
`sasl.session_lifetime_ms`. PostgreSQL: `database`, **`default_transaction_read_only`**,
`error_severity`, `is_superuser`, `protocol_version`, `sasl_mechanism`, `sasl_mechanisms`,
`scram_iterations`, `tls_plan`, `transaction_status`. Redis: `auth_required` (read by the
composition root for path selection, so not dead). RabbitMQ: `close_outcome`, `graceful_close`,
`peer_close_method`, `reply_code` — all four are what the adapter derived the failure class from,
which the rule then keys on; not gaps.

**The frontier is consumption, not acquisition.** No Class 3 candidate's acquisition cost is
justifiable while 24 already-paid-for facts sit unread.

---

## 3. Answerability matrix

`A` answered · `P` partially answered · `N` not answerable · `O` out of scope by design.

| Service | Operator question | | Basis |
|---|---|---|---|
| Kafka | bootstrap works, cluster unusable | **A** | `KAFKA_ADVERTISED_TOPOLOGY_UNSUITABLE` + per-endpoint codes |
| Kafka | which advertised brokers are unreachable | **A** | `KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY`, 3 categories |
| Kafka | isolated or widespread | **A** | same aggregate: completeness + contrast |
| Kafka | expected auth boundary reached | **A** | `KAFKA_AUTH_MECHANISM_NOT_OFFERED` + credential codes |
| Kafka | partition / leader / ISR availability | **N** | not on the wire — `Topics = []` (§4.1) |
| Kafka | controller / KRaft health | **O** | ADR 0084 §7; `controller_id` measured unstable |
| PostgreSQL | reached a server in recovery | **A** | `in_hot_standby` → `recovery` observation line |
| PostgreSQL | admission refused pre-credential | **A** | `POSTGRES_CONNECTION_NOT_PERMITTED`, `POSTGRES_ADMISSION_SCOPE` |
| PostgreSQL | which connection limit applied | **A** | `POSTGRES_CONNECTION_LIMIT_REACHED` |
| PostgreSQL | pooler vs PostgreSQL | **O** | ADR 0040 §18 — "endpoint", never "server" |
| PostgreSQL | **will my writes work** | **P** | one of the two facts is presented; §4.2 |
| Redis | primary or replica; standalone/cluster/sentinel | **A** | closed-set observation lines since Phase 7 |
| Redis | endpoint able to serve | **P** | `REDIS_ENDPOINT_NOT_SERVING` restates the prefix in prose only |
| Redis | replication connected / lagging; cluster health; key ownership | **N/O** | needs `INFO`/`ROLE`/`CLUSTER` — build-forbidden literals |
| RabbitMQ | vhost accepted, absent, or refused | **A** | `RABBITMQ_VHOST_NOT_FOUND` / `_ACCESS_REFUSED` |
| RabbitMQ | failure before or after vhost admission | **A** | three stages + `DIAG_FAILURE_BOUNDARY` |
| RabbitMQ | channel usable; queue present; alarms; cluster health | **O** | ADR 0067 §11, ADR 0069 §8 — needs a channel, an API, or an expectation |

---

## 4. Serious candidates

### 4.1 Kafka partition availability — **REJECTED, and the proof matters**

`internal/adapter/kafka/wire/metadata.go:116` sets `request.Topics = []kmsg.MetadataRequestTopic{}`
— **empty, not nil**. Empty means *no topics*; nil would mean *every topic*. The distinction is
pinned by a test and stated in the doc comment. **No partition, leader or ISR byte arrives.**
Obtaining one is Class 3, and the minimum useful request for an unknown application is *every
topic*: unbounded response, fan-out multiplier, and topic names — tenant identifiers — entering a
shareable report.

### 4.2 PostgreSQL session writability — **SELECTED**

Both writability facts are in evidence on every successful session (`establish.go:504–507`).
`in_hot_standby` is rendered; `default_transaction_read_only` is rendered by nothing.

The repository measured that they are independent (`establish.go:44`): *on a real standby,
`in_hot_standby` was "on" while `default_transaction_read_only` was "off"*. Neither alone answers
*"can I write here"*.

**BEFORE:** a session on a primary whose role or database carries
`ALTER ROLE … SET default_transaction_read_only = on` renders exactly
`recovery: not in recovery` and nothing else. The operator is shown the half of the answer that
says "fine", for a setting invisible in `postgresql.conf`.
**AFTER:** both facts are present, and the reader can see that this session's transactions default
to read-only while the endpoint is not in recovery — two different investigations.

### 4.3 Redis transient-state activation — **DEFERRED, on merit**

Unchanged from ADR 0088 §2.5. Loses on fixture determinism (`LOADING` is a restart race,
`MASTERDOWN` needs a replica plus a severed link), finding-inflation cost, and question frequency.

---

## 5. Scorecard

| Field | Kafka partition | **PostgreSQL writability** | Redis transient state |
|---|---|---|---|
| Operator question | is a partition unavailable? | **will my writes work?** | why did the endpoint refuse? |
| Current answer | nothing | one of two facts shown | one prose sentence |
| Missing fact | leader/ISR | **presentation of a recorded fact** | machine-readable condition |
| Observation | topic-scoped Metadata | **none acquired** | none acquired |
| Acquisition class | **Class 3** | **Class 1** | **Class 2** |
| Already on wire? | **no** | **yes** | yes (unobserved) |
| New request / connection? | yes / no | **no / no** | no / no |
| Authority | protocol-direct | **protocol-direct, session-scoped** | protocol-direct |
| Credential delta | possibly new ACL | **none** | none |
| Privilege delta | Describe on topics | **none** | none |
| Side-effect class | `READ_ONLY_WITH_OBSERVABLE_FOOTPRINT` | **`PASSIVE`** | `PASSIVE` |
| Round trips | +1, larger response | **0** | 0 |
| Fan-out | per-target, unbounded response | **none** | none |
| Compatibility | Kafka/Redpanda drift risk | **standard; PG14+ for one key** | Redis/Valkey identical |
| Proxy ambiguity | bounded | **high — bounded by scoping to the session** | low |
| Data sensitivity | **topic names** | **two tokens** | closed prefix |
| Intent dependency | no | **no, as a fact** | no |
| Confidence ceiling | n/a | **n/a — no finding** | HIGH |
| Failure isolation | must be designed | **trivial — absence is silence** | trivial |
| NBE value | none | none | small |
| New `FindingCode`? | likely | **no** | likely |
| ADR required | yes, its own | **no — ADR 0089 authorizes it** | yes |
| **Verdict** | **REJECT** | **ADMIT** | **DEFER** |

**#1 beats #2** because #2 is not on the wire and its minimum acquisition is a whole partition
map. **#1 beats #3** on fixture determinism, zero finding inflation, and question frequency; the
difference is material, so this is not a defer.

---

## 6. Requirement register — `DOE-001` … `DOE-020`

Tiers: **F** frozen · **N** binding on Phase 10.7B · **D** deferred.

### 6.1 Selection principles — FROZEN

| ID | Tier | Requirement |
|---|---|---|
| DOE-001 | **F** | Candidate selection starts from an operator question, never from an available protocol feature |
| DOE-002 | **F** | The **minimum observation principle**: the smallest fact that materially reduces uncertainty, never a broad inspection surface. No `INFO` dump, no `pg_settings` dump, no metadata dump, no management snapshot |
| DOE-003 | **F** | **Class 1 before Class 2 before Class 3.** A Class 3 candidate must beat the best Class 1 and Class 2 alternative on the record |
| DOE-004 | **F** | Observation expansion does not imply finding expansion. A candidate must state whether a new `FindingCode` is genuinely required |
| DOE-005 | **F** | Data minimization: a field is acquired or presented only when a named consumer needs it |
| DOE-006 | **F** | No arbitrary peer prose enters canonical evidence or a claim; closed enums, booleans and bounded numerics are preferred |
| DOE-007 | **F** | No application-state mutation. `SESSION_LOCAL_MUTATION` and above require their own record |
| DOE-008 | **F** | Credential authority is classified explicitly — `SAME_AUTHORITY` / `ELEVATED_SAME_PROTOCOL` / `SECOND_CREDENTIAL` / `CONTROL_PLANE` — and anything beyond the first is a security decision, not a probe decision |
| DOE-009 | **F** | Multi-target worst case is reasoned about, never per-endpoint only |
| DOE-010 | **F** | No hidden operator intent. A candidate useful only with declared intent is `INTENT_DEPENDENT` and blocked by ADR 0083 §2.6 |
| DOE-011 | **F** | **BASIC fallback**: failure, absence or non-recognition of an enrichment MUST NOT invalidate BASIC evidence, findings, summary status or exit code |
| DOE-012 | **F** | `make check` is mandatory for any phase in this line; `go test`/`go vet`/`go build` are not substitutes |
| DOE-013 | **F** | No runtime implementation in 10.7A |

### 6.2 Binding on Phase 10.7B — NEXT_IMPLEMENTATION

Exact enough that 10.7B cannot silently widen.

| ID | Tier | Requirement |
|---|---|---|
| DOE-014 | **N** | 10.7B presents `postgres.default_transaction_read_only` as a terminal observation line beside the existing `recovery` line. **It acquires nothing**: no SQL, no command, no request, no round trip, no connection |
| DOE-015 | **N** | The render function is a **closed two-value map**; any other value yields the empty string and drops the line. An absent parameter drops the line and is never defaulted to `off` |
| DOE-016 | **N** | The line's subject is **the session svcdoctor established**, never a backend, a role, or a cluster identity (ADR 0040 §18, ADR 0089 §6.4) |
| DOE-017 | **N** | Recovery and the GUC are presented as **two facts of different strength** and are never merged into one read-only verdict: recovery is not session-overridable, the GUC is |
| DOE-018 | **N** | **No rule reads either attribute.** `TestTheRulesReadOnlyTheAuthorizedAttributes` (four-key allowlist) and `TestSessionFactsStayEvidenceAndNeverBecomeFindings` stay unweakened. ADR 0040 §20 is upheld, not reopened |
| DOE-019 | **N** | **No new `FindingCode`, no schema change, no `RuleContext` change, no failure class, no dependency, no CLI change.** Counts stay 65 / 42 / 3 / 2 / 4 / 4 / 1 / 1 / 5 |
| DOE-020 | **N** | A **real fixture** produces `default_transaction_read_only = on` — one `-c` flag on a compose service, the mechanism the file already uses — and an integration test asserts the rendered line. 10.7B may not close without it |

### 6.3 Deferred

| Item | Condition |
|---|---|
| A PostgreSQL **writability finding** | ADR 0040 §20's own three, unchanged and unfired |
| Redis `LOADING`/`MASTERDOWN`/`BUSY` activation | ADR 0088 §2.5 — a fixture that measures one |
| Kafka partition availability | a record authorizing a topic-scoped `Metadata` request, answering data-minimization, fan-out and topic-name redaction |
| Any PostgreSQL SQL | ADR 0039 §17's reopen path, with its own security review |
| RabbitMQ channel / passive declare / management API | three separate records, never one |
| `server_version` as an observation line | the cross-service observation-value sanitization decision |
| The other 23 unconsumed attributes | an operator question first (§2) |

---

## 7. Gates

**Phase 10.4C — closed.** No mutually competing hypothesis pair emerged; PostgreSQL produces zero
`HYPOTHESIS` findings and the selected candidate produces no finding at all.

**Phase 10.5B — closed.** Nothing here needs `CONTRADICTION`, `MISSING` or `BLOCKED`.

**Declared intent** — unchanged; ADR 0083 §2.6 still binds, and the selected candidate is a fact
rather than a fault precisely so it does not need intent.

---

## 8. Proposed Phase 10.7B

**Name: Phase 10.7B — PostgreSQL session read-only observation completion.**

**IN SCOPE:** one observation line and its conditional note in `internal/render/terminal`;
`internal/service/postgres` may gain the attribute alias if the vocabulary package's own
doc-comment trigger applies; a compose service with `-c default_transaction_read_only=on`; unit
tests for the render map; one integration assertion.

**OUT OF SCOPE:** any rule reading either attribute · any `FindingCode` · any SQL · any Redis,
Kafka or RabbitMQ change · `server_version` · `is_superuser` · schema, `RuleContext`, failure
classes, dependencies, CLI, credential authority · relation activation · a hypothesis-set engine ·
any compatibility claim not established by the new fixture.

**ENTRY:** this record Accepted; `make check` green at the starting commit.
**EXIT:** DOE-014 … DOE-020 all satisfied; `make check` green; the PostgreSQL integration suite
green against the new fixture; frozen counts unchanged.

**SECURITY:** no credential involvement; no privilege change; closed-domain rendering only; no raw
parameter value reaches a terminal.
**COMPATIBILITY:** `default_transaction_read_only` is standard; `in_hot_standby` is PG14+ and its
absence must omit the line. No `docs/COMPATIBILITY.md` grading may move unless the fixture
establishes a tested claim.

**REQUIRED REAL FIXTURES:** a real PostgreSQL 18 server started with
`-c default_transaction_read_only=on`. A real streaming standby is **desirable and not required** —
`in_hot_standby` behaviour is already asserted against a real primary and was measured against a
real Patroni cluster; reproducing a standby deterministically in the compose fixture is
acknowledged as harder, and the semantic claim is **not** weakened to avoid it: the line simply
states what the endpoint reported.

**REQUIRED MUTATIONS** (sketch only; no harness change in 10.7A): default an absent parameter to
`off`; render a value outside the closed domain verbatim; merge the two facts into one read-only
verdict; let a rule read either attribute; attach a severity or exit-code effect; let an absent
parameter suppress an unrelated finding; describe the value as a property of the backend rather
than the session.

**REQUIRED FUZZING:** none beyond the existing `ParameterStatus` decoder coverage.
**REQUIRED `make check`:** mandatory, before and after.

---

## 9. Validation run

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 92158d1
git status --short                               # clean at start
git diff --name-only | grep '\.go$'              # no output
make check                                       # exit 0 — MANDATORY
  fmt-check: OK · go test ./... · go vet ./... · golangci-lint run ./... "0 issues." · build
git diff --check                                 # clean
go test ./test/security/... -run 'Closure|Convergence|RuleContext|Schema|Reveal|SecretFor|Dependenc|Module' -v
```

Re-proved: *attributed 65 of 65 declared finding codes*; 22 rules; `RuleContext` three fields;
`SchemaVersion` 1; module graph exact; dependency count exact; one `Reveal` per service.
Additionally proved by direct source reading: **no new service command, query or request exists**
(Kafka `Topics = []`; three Redis frames; no SQL; `channel_max 1`), **no new credential authority**,
**no evidence-relation producer** (`.Contradict`/`.Miss`/`.Block` still zero), **no hypothesis-set
engine**.

**Not run:** every container integration suite — PostgreSQL, Kafka, Redpanda, Redis, Valkey,
RabbitMQ, LavinMQ, multi-target — and every mutation harness. This is a documentation-only audit,
so **no integration-green claim is made.**

---

## 10. Outcome

**ACTIVATE EXISTING OBSERVATION.**

svcdoctor's diagnostic frontier is not acquisition. Twenty-four facts already crossing the wire
are consumed by nothing, and the highest-value one among them — whether this session's
transactions default to read-only — is currently absent from the result block beside a line that,
alone, reads as reassurance.
