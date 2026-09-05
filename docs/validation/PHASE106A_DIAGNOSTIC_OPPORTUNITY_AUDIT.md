# Phase 10.6A — Redis/Valkey and RabbitMQ/LavinMQ diagnostic-intelligence opportunity audit

- **Phase:** 10.6A — architecture / archaeology. **No production Go code, no test change.**
- **Baseline:** `dabe12e1f7b1ca0705f89fd5d70904e44c3cf1c3`, working tree clean
- **Record:** ADR 0088
- **Outcome:** **DEFER BOTH.** No candidate admitted; no Phase 10.6B proposed.

---

## 1. Baseline, as measured

| Fact | Value | How |
|---|---|---|
| `HEAD` == `origin/main` | `dabe12e` | `git rev-parse` |
| working tree at start | clean | `git status --short` empty |
| `domain.SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `domain.RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| finding codes | **65** | convergence scan: *attributed 65 of 65* |
| `RuleContext` fields | **3** | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| failure classes | **42** | unchanged; none touched |
| external modules | **2** | `TestTheDependencyCountIsExact` |
| `Reveal` / `SecretFor` production sites | **4 / 4** | `TestRevealHasOneProductionCallSitePerService` |
| exit codes | **5** | `docs/SCOPE.md`, unchanged |
| production rules | **22** | convergence scan |
| `make check` | **exit 0** | fmt-check OK · test · vet · lint *0 issues* · build |

Per-package rules/codes: `diagnosis` 1/1, `transport` 3/8, `kafka` 5/15, `postgres` 6/21,
**`redis` 4/9**, **`rabbitmq` 3/11**.

**CI contract.** `.github/workflows/ci.yml` job *Quality gates* runs `make fmt-check`, `make test`,
`make vet`, `make build` and `golangci/golangci-lint-action@v9` pinned to **v2.13.1**.
`.golangci.yml` enables `staticcheck` with default checks (including `QF*`/`ST*`), so `go vet`
alone does **not** represent the gate. `make check` is the authoritative local mirror and was run.

---

## 2. Redis/Valkey — exact current fact inventory

**The journey is three commands and no more**, proven from `internal/adapter/redis/wire/conn.go`:

```
helloFrame = "*1\r\n$5\r\nHELLO\r\n"     zero-argument constant
pingFrame  = "*1\r\n$4\r\nPING\r\n"      zero-argument constant
AUTH                                     one- or two-argument, the operator's own form
```

`INFO`, `ROLE`, `CLUSTER *`, `COMMAND`, `CONFIG GET`, `SELECT`, `RESET` and eleven others are
**build-forbidden string literals** in any Redis production file
(`TestNoRedisProductionFileNamesAForbiddenCommand`). None is executed; none can be added silently.

### 2.1 Directly observed

| Attribute | Wire source | Authority | Scope | Peer prose? | Bounded? | HIGH-capable? |
|---|---|---|---|---|---|---|
| `redis.mode` | HELLO reply | peer self-description | endpoint | no | **closed set** {standalone, cluster, sentinel} | yes, for what the endpoint *said* |
| `redis.role` | HELLO reply | peer self-description | endpoint | no | **closed set** {master, replica}; absent under sentinel, meaningfully | yes, same ceiling |
| `redis.server` / `redis.server_version` | HELLO reply | peer self-description, **configurable** (`extended-redis-compat`) | endpoint | **yes — open string** | ≤128, charset-checked; failure ⇒ recorded **absent**, never truncated | no |
| `redis.proto` | HELLO reply | protocol | session | no | integer; always 2 | yes |
| `redis.error_prefix` | first token of an error | **svcdoctor's own constant**, never peer bytes | per exchange | no | closed set of 23 + `UNRECOGNIZED` | yes |
| credential accepted / rejected | `AUTH` → `+OK` / `WRONGPASS` | protocol | session | no | — | yes |
| command authorized | `PING` → `NOPERM` | protocol | session, one command | no | — | yes |

### 2.2 Derived

| Fact | From | Note |
|---|---|---|
| `redis.auth_required` | `Prefix == NOAUTH` on the **credential-free** HELLO | recovers the one fact prefix-only classification would lose |
| HELLO unsupported | `Prefix == ERR` **at the HELLO step** | decided on prefix + step, never on text |
| protected mode | `Prefix == DENIED` | lands on `PROTOCOL_PEER_CLOSED`; the finding names no cause |
| endpoint is a Sentinel | `mode == "sentinel"` | the **one** observation that legitimately becomes a finding — the operator typed `diagnose redis`, so the expectation came from the invocation |

### 2.3 Not knowable today

Replication lag, link state or offset · persistence state · memory or keyspace size · connected
clients · cluster topology, slot coverage, node inventory · which primary a replica follows ·
Sentinel quorum · any configuration value · whether the application's own commands would be
permitted (svcdoctor issued one keyless command and learned about that one) · client-limit
exhaustion **as such** — it arrives as a bare `ERR` and is indistinguishable without reading text.

**Reachable-but-never-observed:** `LOADING`, `MASTERDOWN`, `BUSY`. ADR 0066 §reachability proves
all three can arrive on `PING`; **no fixture in the tree has ever produced one.**

**Recognized but unreachable:** `MOVED`, `ASK`, `CLUSTERDOWN`, `TRYAGAIN`, `CROSSSLOT` (need a key
argument), `READONLY` (needs a write), `OOM`/`MISCONF` (need a `denyoom` or write command),
`NOPROTO` (a zero-argument HELLO requests no version). svcdoctor never writes and names no key.

---

## 3. RabbitMQ/LavinMQ — exact current fact inventory

**One direct AMQP 0-9-1 connection.** No management API (pinned at zero calls by test), no
passive declaration, no topology enumeration. `channel_max` is negotiated to **1** and no channel
is ever opened, so no resource is ever named.

### 3.1 Directly observed

| Attribute | Wire source | Authority | Peer prose? | Bounded? |
|---|---|---|---|---|
| `rabbitmq.amqp_version` | `Connection.Start` | protocol | no | version tuple |
| `rabbitmq.mechanisms_offered` | `Connection.Start` | protocol | no | **normalized set of recognized** mechanisms |
| `rabbitmq.anonymous_offered` | `Connection.Start` | protocol | no | boolean |
| `rabbitmq.product` / `.version` / `.platform` | server properties | peer self-description | **yes — arbitrary** | no |
| `rabbitmq.cluster_name` | server properties | peer self-description | **yes** | no; `AttrKindIdentity`, redacted |
| `rabbitmq.mechanism_selected`, `.identity` | svcdoctor's own choice / input | — | no | `PLAIN`; identity is `AttrKindIdentity` |
| six `channel_max`/`frame_max`/`heartbeat` offered + selected | `Tune`/`Tune-Ok` | protocol | no | integers |
| `rabbitmq.close_outcome`, `.reply_code`, `.peer_close_method`, `.graceful_close` | `Connection.Close` | **svcdoctor's own handshake state** — which frame it was waiting for; a hostile peer can lie about `reply_code` but cannot change that | **no** — construct-and-compare against candidates svcdoctor rendered itself | closed outcome vocabulary |
| `rabbitmq.vhost`, `.vhost_defaulted` | the run's own flags | operator input | no | `AttrKindIdentity` |

### 3.2 Not knowable today

Queue, exchange or binding existence · message counts, depths, rates · consumer counts · cluster
membership, partitions, quorum · node health, alarms, flow control · policies or limits as
configuration · what the identity may do **inside** a vhost — RabbitMQ evaluates configure/write/read
at channel operations, and svcdoctor opens no channel and names no resource · whether the `guest`
loopback restriction applied, because that is evaluated against the broker's view of the client's
source address, which svcdoctor cannot observe.

---

## 4. Candidate matrix

Ranking is for **phase selection only** and never becomes runtime diagnosis ranking. Qualitative
throughout; no numeric model.

| Service | Candidate | Already measured? | Authority | Operator value | False-positive risk | New probe? | Verdict |
|---|---|---|---|---|---|---|---|
| RabbitMQ | vhost refused vs vhost absent, after successful auth | yes | direct, protocol | high | low | no | **REJECT — already built.** `RABBITMQ_VHOST_NOT_FOUND` + `RABBITMQ_VHOST_ACCESS_REFUSED`, exactly this claim, exactly this boundary |
| RabbitMQ | SASL mechanism not offered | yes | direct | medium | low | no | **REJECT — already built.** `RABBITMQ_AUTH_MECHANISM_NOT_OFFERED` |
| RabbitMQ | credentials withheld / not configured / rejected | yes | direct | medium | low | no | **REJECT — already built.** Three codes |
| RabbitMQ | protocol-stage failure boundary as a service finding | yes | direct | **none added** | — | no | **REJECT — value bar.** `DIAG_FAILURE_BOUNDARY` + 11 service codes already localize it; a branded restatement adds no service knowledge |
| RabbitMQ | capacity ceiling on open | yes | direct | medium | low | no | **REJECT — already built.** `RABBITMQ_CONNECTION_NOT_PERMITTED`; `RESOURCE_LIMIT_REACHED` landed in Phase 8.2 |
| RabbitMQ | `heartbeat` / `frame_max` / `channel_max` assessment | yes | direct | low | **high** | no | **REJECT — ADR 0069 §8.** Needs an operator-supplied expectation; LavinMQ legitimately offers different values (2048/300 vs 2047/60), so any threshold is a policy invention |
| RabbitMQ | `ANONYMOUS` offered as a hardening finding | yes | direct | medium | **high** | no | **REJECT — ADR 0069 §8, permanently.** Posture, not reachability; asserting it in a shareable report without attempting it is a claim svcdoctor never tested |
| RabbitMQ | version / product / `cluster_name` claims | yes | peer self-description | low | **high** | no | **REJECT — ADR 0069 §8.** Needs a supported-version policy with an EOL refresh obligation, or an expected-identity input |
| RabbitMQ | connection-start scope aggregate across addresses | **structurally yes, never produced** | direct | medium | medium | no | **DEFER.** §5 |
| Redis | server mode / replication role as a finding | yes | peer self-description | medium | **high** | no | **REJECT.** Needs an expected role/topology (ADR 0063 §10, ADR 0065 §2); `TestReplicaRoleProducesNoFinding` and `TestClusterModeProducesNoFinding` fail the build. Already a **terminal observation line** since Phase 7 |
| Redis | endpoint is a Sentinel | yes | direct | high | low | no | **REJECT — already built.** `REDIS_ENDPOINT_IS_SENTINEL` |
| Redis | auth absent / required / rejected / ACL-denied | yes | direct | high | low | no | **REJECT — already built.** Four codes plus `redis.auth_required` |
| Redis | `LOADING` / `MASTERDOWN` / `BUSY` made machine-readable | **attribute yes, condition never observed** | direct | **medium-high** — three different remedies, today one prose sentence | low *if* the claim stays "the endpoint named X and refused" | no | **DEFER.** Strongest real candidate; fails only the producer bar. §5 |
| Redis | client-limit exhaustion → `RESOURCE_LIMIT_REACHED` | **no** | — | medium | **high** | no, but needs **text** | **REJECT.** Bare `ERR` prefix; ADR 0066 forbids text classification. See ADR 0088 §6 |
| Redis | `MOVED` / `ASK` / `READONLY` / `CLUSTERDOWN` classification | **unreachable** | — | — | — | would need a key or a write | **REJECT.** Not producible by any BASIC command |
| Redis | cluster topology | **no** | — | high | **very high** | `CLUSTER *` | **REJECT — probe expansion.** Never inferred from hostname, port or error prose |
| Redis | replication health | **no** | — | high | **very high** | `INFO` / `ROLE` | **REJECT — probe expansion** |
| Redis | hello scope aggregate across addresses | **structurally yes, never produced** | direct | medium | medium | no | **DEFER.** §5 |

**ADMIT: 0 · REJECT: 15 · DEFER: 3.**

---

## 5. Deferred candidates and the exact observation each needs

| Candidate | Required observation |
|---|---|
| `LOADING` / `MASTERDOWN` / `BUSY` machine-readable | **a fixture that measures one.** ADR 0069 §8's `VHOST_DOWN` rule applies unchanged: *membership requires having watched a real endpoint produce it.* All three are source-derived from ADR 0066's table and none has ever been observed. The lift itself has a sound precedent — Phase 10.3 did it for `53300` — but the producer comes first |
| Redis hello scope aggregate | a multi-address run whose addresses **disagree**: one requiring authentication and another not, or one a Sentinel and another a data endpoint. Every Redis and Valkey fixture targets `127.0.0.1`, which under ADR 0059 resolves nothing and yields one path |
| RabbitMQ connection-start scope aggregate | the same shape: a multi-address run whose addresses offer different mechanism sets. Same fixture limitation |

All three are **zero-cost in principle and unmeasured in fact**, which is ADR 0054's *owner
before producer* and ADR 0086 §2.11's *producer before engine* pointing at the same thing.

---

## 6. Requirement register — `RRI-001` … `RRI-018` (plus `RRI-017a`)

Tiers: **F** frozen now and already enforced · **N** next implementation phase · **D** deferred.

### 6.1 The audit's conclusions

| ID | Tier | Requirement | Design | Enforced by |
|---|---|---|---|---|
| RRI-001 | **F** | Redis BASIC sends exactly `HELLO`, `AUTH`, `PING` and nothing else | ADR 0063 §11 | `TestOnlyAuthorizedRedisCommandsCanBeEncoded`, `TestNoRedisProductionFileNamesAForbiddenCommand` |
| RRI-002 | **F** | No Redis command carries a key argument | ADR 0063 §11 | `TestNoRedisCommandCarriesAKeyArgument` |
| RRI-003 | **F** | RabbitMQ BASIC opens one AMQP connection, no channel and no management call | ADR 0067, 0070 | `test/integration/rabbitmq` management-call pin; `channel_max` 1 |
| RRI-004 | **F** | No Redis finding asserts an expectation about role, mode, implementation or version | ADR 0063 §10, ADR 0065 §2 | `TestReplicaRoleProducesNoFinding`, `TestClusterModeProducesNoFinding`, `TestNoRedisFindingAssertsAnExpectation` |
| RRI-005 | **F** | `NOPERM` is `UNKNOWN`/`AUTHZ_DENIED`, never a target `FAIL` | ADR 0065 | `TestNoPermIsNotAServiceFailure` |
| RRI-006 | **F** | `WRONGPASS` never becomes "wrong password" | ADR 0064 §6 | `TestWrongPassNeverBecomesWrongPassword` |
| RRI-007 | **F** | Only the normalized prefix — never peer text — reaches finding prose | ADR 0066 | `TestOnlyTheNormalizedPrefixReachesFindingProse`, `TestRawPeerTextCannotCrossTheWireBoundary` |
| RRI-008 | **F** | RabbitMQ refusal attribution is svcdoctor's own handshake state, not peer `reply_code` | ADR 0069 §1 | `internal/adapter/rabbitmq/wire`; per-outcome units |
| RRI-009 | **F** | No RabbitMQ finding names a cause RabbitMQ does not name | ADR 0069 §8 | `TestNoFindingNamesACauseRabbitMQDoesNotName` |
| RRI-010 | **F** | Redis and Valkey are reasoned about identically; no vendor branch, no version arithmetic | ADR 0066 | `TestNoProductionCodeBranchesOnImplementationName`, `TestNoProductionCodeDoesVersionArithmetic` |
| RRI-011 | **F** | The design document's **10.4** slot is delivered, not pending | ADR 0088 §1.2 | this record; the 20 existing Redis + RabbitMQ codes |

### 6.2 Phase invariants — all held

| ID | Tier | Requirement | Held |
|---|---|---|---|
| RRI-012 | **F** | No Go production change in 10.6A | yes — no Go file of any kind changed |
| RRI-013 | **F** | No new `FindingCode`; no schema change; no `RuleContext` change | yes — 65 / 1 / 1 / 3 |
| RRI-014 | **F** | No new network request; no Redis `INFO`/`ROLE`/`CLUSTER`; no RabbitMQ management call | yes — and RRI-001/003 fail the build otherwise |
| RRI-015 | **F** | No hypothesis-set engine, no `DiscriminatorID`, no discriminator-prose grouping; no evidence-relation producer; no credential-authority expansion; no unsupported compatibility claim | yes — ADR 0086 §2.11 and ADR 0087 untouched; `docs/COMPATIBILITY.md` unchanged |

### 6.3 Deferred

| ID | Tier | Requirement | Condition |
|---|---|---|---|
| RRI-016 | **D** | `internal/service/rabbitmq/vocabulary.go` says of the six negotiation attributes *"no rule reads them and **a guard fails the build if one does**"*. The first half is **true and verified**; the second is **false** — no test scans `internal/diagnosis/rabbitmq` for those reads, and the same overstatement covers `anonymous_offered`'s *"observation only, permanently"*. The invariant is maintained by **review**, not by the build | **A maintenance task, and 10.6A neither chooses nor implements it.** Two legitimate closures: **(A)** add the AST scan, in the shape `test/security` already uses for the SASL core and the diagnostic core; or **(B)** correct the comment to say the property is maintained by review, if mechanical enforcement is not intended. One small change, its own commit (ADR 0088 §6.2) |
| RRI-017 | **F** | **Redis `RESOURCE_LIMIT_REACHED` may only be emitted when the wire evidence structurally and authoritatively identifies a resource limit. A generic `ERR` reply plus arbitrary server prose is insufficient, so client-limit exhaustion remains unclassified.** | ADR 0088 §6.1, **superseding the second sentence of ADR 0069 §9 condition 3**, which read as standing permission for a migration whose mechanism ADR 0066 forbids. ADR 0069 carries a forward marker at the clause and in its header |
| RRI-017a | **D** | Client-limit exhaustion becomes classifiable | **a closed, structurally authoritative signal** — a future Redis or Valkey release giving it its own error prefix (ADR 0066 already calls an additional prefix *"additive and testable"*), or a protocol/probe expansion decided in its own record. **Never by text matching**, and the question is re-gated rather than closed |
| RRI-018 | **D** | The three §5 candidates | their observations, one per row |

**No requirement is tier N.** An audit that admitted nothing should have no next-implementation
row, and saying so is the point.

---

## 7. Gates

**Phase 10.4C — closed, and nothing moved it.** Redis and RabbitMQ produce **zero** `HYPOTHESIS`
findings and hold **zero** `Discriminator` values between them; all 20 of their codes are
`CONFIRMED`. No mutually competing hypothesis pair emerged, and none was manufactured.

**Phase 10.5B — not reopened.** No candidate required `CONTRADICTION`, `MISSING` or `BLOCKED`.
ADR 0087's OUTCOME C stands untouched, and no relation producer exists.

**Declared operational intent** — unchanged and still the binding ceiling for both families, as
ADR 0083 §2.6 froze and ADR 0085 §5 confirmed.

---

## 8. Validation run

```
git rev-parse HEAD; git rev-parse origin/main    # identical, dabe12e
git status --short                               # clean at start
git diff --name-only | grep '\.go$'              # no output
make check                                       # exit 0 — MANDATORY GATE
  fmt-check: OK · go test ./... · go vet ./... · golangci-lint run ./... "0 issues." · build
go test ./test/security/... -run 'Closure|Convergence|RuleContext|Schema|Reveal|SecretFor|Dependenc|Module|Failure' -v
```

Guard output recorded: *attributed 65 of 65 declared finding codes*; `RuleContext` three fields;
`SchemaVersion` 1; dependency count exact; `Reveal` one production call site per service.

**Not run:** every container integration suite — Redis, Valkey, RabbitMQ, LavinMQ, Kafka,
Redpanda, PostgreSQL, multi-target — and every mutation harness. Phase 10.6A is documentation-only,
so **no integration-green claim is made.**

---

## 9. Outcome

**DEFER BOTH.**

Neither family exposes a zero-cost observation that supports a diagnostic-intelligence finding it
does not already have. The reason differs by service and both are worth stating plainly:

**RabbitMQ has no gap.** Every candidate the phase brief named — SASL mechanism, credential
withheld, authentication rejected, and the vhost claim it singled out as *potentially strong* —
is already a finding, and the vhost case is already split into the two causes the protocol
distinguishes. What remains measured is frozen "may not be said" by ADR 0069 §8, each item needing
an operator-supplied expectation.

**Redis has one real candidate and no producer for it.** Lifting `LOADING`, `MASTERDOWN` and
`BUSY` out of `REDIS_ENDPOINT_NOT_SERVING`'s prose is sound, needs no probe, and has a direct
precedent — but no svcdoctor fixture has ever seen any of the three. Its role and mode facts are
already terminal observation lines, and a finding over either is a build failure by design.

The next diagnostic-intelligence phase must come from elsewhere. What would open one here is in
§5 and §6.3: **a measurement, not an argument.**
