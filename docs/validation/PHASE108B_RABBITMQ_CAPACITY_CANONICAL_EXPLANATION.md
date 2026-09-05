# Phase 10.8B — RabbitMQ/LavinMQ capacity-scope canonical explanation enrichment

- **Phase:** 10.8B — implementation. Production, test, integration fixture, mutation harness, docs.
- **Baseline:** `5bd658910ea2e1a5f3e561082847f60312e2c417`, `HEAD == origin/main`, tree clean
- **Records:** ADR 0090 (selection), **ADR 0091** (the authorizing contract). **No new ADR.**
- **Outcome:** `RABBITMQ_CONNECTION_NOT_PERMITTED` names which capacity ceiling the endpoint
  named. One sentence, three fixed values, selected by a closed lookup. No new diagnosis.

---

## 1. Baseline and frozen inventory

| Fact | Value |
|---|---|
| `HEAD` == `origin/main` | `5bd6589` |
| working tree at start | clean |
| `make check` before edits | **exit 0** |
| ADR 0090 / ADR 0091 committed | yes, at `8725755` and `5bd6589` |

Measured before and after; **every one unchanged**:

| | Before | After |
|---|---|---|
| `SchemaVersion` / `RunSchemaVersion` | 1 / 1 | 1 / 1 |
| finding codes (declared / attributed) | 65 / 65 | 65 / 65 |
| production rules | 22 | 22 |
| RabbitMQ rules / codes | 3 / 11 | 3 / 11 |
| `RuleContext` fields | 3 | 3 |
| failure classes | 42 | 42 |
| external modules | 2 | 2 |
| `Reveal` / `SecretFor` call sites | 4 / 4 | 4 / 4 |
| exit codes | 5 | 5 |

---

## 2. The complete `CloseOutcome` vocabulary and its provenance

Re-established from source at this baseline. **Seven values, all compile-time literals.**

| Value | Wire condition | Mechanism | FailureClass | FindingCode | Real fixture |
|---|---|---|---|---|---|
| `UNSPECIFIED` | any unmatched refusal; non-530; text > 255 B | default | `AUTHZ_NOT_PERMITTED` | `..._CONNECTION_NOT_PERMITTED` | PROVEN_REAL |
| `UNSPECIFIED_TRUNCATED` | text ends `...` (T0, short-circuits first) | exact suffix on **svcdoctor's own** marker | `AUTHZ_NOT_PERMITTED` | same | PROVEN_REAL |
| `VHOST_NOT_FOUND` | T1 RabbitMQ / L1 LavinMQ | byte equality, reconstructed | `RESOURCE_NOT_FOUND` | `RABBITMQ_VHOST_NOT_FOUND` | PROVEN_REAL, both |
| `VHOST_ACCESS_REFUSED` | T2 / T3 / L2 | byte equality; **T3 the only prefix rule** | `AUTHZ_DENIED` | `RABBITMQ_VHOST_ACCESS_REFUSED` | PROVEN_REAL, both |
| **`NODE_CONNECTION_LIMIT`** | **T5** | `matchesDigitHole` | `RESOURCE_LIMIT_REACHED` | `..._CONNECTION_NOT_PERMITTED` | **PROVEN_REAL (new, RAB-26)** |
| **`VHOST_CONNECTION_LIMIT`** | **T4 / L3** | `matchesDigitHole` | `RESOURCE_LIMIT_REACHED` | same | **PROVEN_REAL, both (RAB-21, LMQ-06)** |
| **`USER_CONNECTION_LIMIT`** | **T6** | `matchesDigitHole` | `RESOURCE_LIMIT_REACHED` | same | **PROVEN_REAL (new, RAB-27)** |

**Classification mechanism.** Construct-and-compare: svcdoctor renders each candidate sentence
from **its own** vhost and username and compares for byte equality. One bounded digit hole (1–20
ASCII digits at a fixed position) which **does not parse or return** the integer. Exactly one
prefix rule, T3, which only ever reaches a conclusion T2 already supports. No substring scan, no
regex, no case folding, no tokenizing.

**Can a peer byte become a `CloseOutcome`?** No, structurally. All thirteen `return` statements in
`normalizeClose` return a named constant; there is no `CloseOutcome(text)` construction anywhere
in production. Already fuzz-proven by `FuzzNormalizeClose` and `FuzzParseClose`, which assert over
arbitrary `(code, text, vhost, username)` that the result is one of the seven, that truncation
short-circuits, that an over-long text is never classified, and that a non-530 code never reaches
a 530-only outcome.

---

## 3. What was built

### 3.1 Vocabulary ownership — relocated, not duplicated

`internal/diagnosis` cannot import `internal/adapter` (depguard, `.golangci.yml`), so a rule
cannot name the adapter's constant. Respelling the literals in the rule package would create a
second authoritative spelling of a contract string.

So the **type and its seven constants moved to `internal/service/rabbitmq`**, beside
`AttrCloseOutcome`, which is the key they are the values of. `internal/service/**` is a leaf
depguard already forbids from importing the adapter, so the direction is legal and no cycle is
possible. `internal/adapter/rabbitmq/wire` now declares a **type alias and seven const aliases**:

```go
type CloseOutcome = servicerabbitmq.CloseOutcome
const CloseNodeConnectionLimit = servicerabbitmq.CloseNodeConnectionLimit   // and six more
```

- **One authoritative spelling.** `grep 'CloseOutcome = "'` over production returns **seven lines,
  all in `internal/service/rabbitmq/vocabulary.go`**; the wire package declares zero literals.
- **Values byte-identical.** The seven strings are unchanged, so canonical evidence is unchanged.
- **Zero call-site churn.** `wire.CloseVHostNotFound` and `wire.CloseOutcome` still resolve; the
  26 references in `wire_test.go`, 10 in `fuzz_test.go`, 6 in `open.go` and 12 across the two
  integration suites compile untouched.
- `normalizeClose`, `matchesDigitHole` and the reply-code constants **stayed in wire**. That is
  protocol logic, and a service vocabulary holds constants.

This is the move `AttrBrokerNodeID` made in Phase 6.1c and `AttrDefaultTransactionReadOnly` in
Phase 10.7B, on the same trigger.

### 3.2 The closed mapping

`internal/diagnosis/rabbitmq/connectionopen.go` gains a three-entry map and one selector:

```go
var capacityScopeDetail = map[servicerabbitmq.CloseOutcome]string{
	servicerabbitmq.CloseNodeConnectionLimit:  detailCapacityNode,
	servicerabbitmq.CloseVHostConnectionLimit: detailCapacityVHost,
	servicerabbitmq.CloseUserConnectionLimit:  detailCapacityUser,
}
```

`connectionNotPermittedDetail(node)` returns the generic text unless **both** gates pass: the
failure class is `RESOURCE_LIMIT_REACHED`, **and** the attribute's value is byte-equal to one of
the three keys. The class gate is deliberately redundant — `classify()` already pairs them — and
is there because the cost of the pairing breaking is a specific sentence over a refusal that was
never a ceiling.

It is a **map lookup, never a text match**: no prefix, no suffix, no trimming, no case folding.
The defence does not depend on the producer's closure holding.

### 3.3 The exact frozen strings

Shared first and last paragraphs, taken verbatim from the generic constant. **One sentence
differs, by three words.**

```text
svcdoctor authenticated successfully and the endpoint refused the connection for a reason
other than a missing virtual host or a permission decision.
The endpoint named a connection limit scoped to the node.
That is recorded as what it said and nothing more. It proves the endpoint refused at that
moment; it proves nothing about why, for how long, or what to change, and a second run a
moment later may succeed.
```

…and identically with `scoped to the virtual host.` and `scoped to the user.`

The generic text's fourth sentence — *"Where svcdoctor could not classify the refusal, it declines
to guess"* — is **dropped** in the three variants, because on these outcomes svcdoctor did
classify it and the sentence would describe a path the finding did not take.

**Adversarial review of each string:** no *exhausted*, no *globally*, no *overloaded*, no
*unhealthy*, no *misconfigured*, no *too low*, no *increase*, no *root cause*, no *leak*, no *all
slots*, no *cluster*, no *permanently*. No product name, no version, no numeric limit, no
endpoint, no username, no virtual host, no raw enum identifier. **No interpolation of any kind** —
each is a constant.

---

## 4. Proofs

### 4.1 Recommendations are byte-identical — RCCE-004

Asserted **absolutely**, against `recommendConnectionNotPermitted` itself, for all three outcomes.
Also compared as encoded JSON so a field added to `Recommendation` later is compared too.

**Mutation testing found the first version of this test to be inadequate**, and that is worth
recording. It originally compared a capacity finding against a *generic* finding built the same
way — but both come from the same `switch` arm, so `RCCE-M16`…`M19` (recommendation, code,
severity, confidence changed for the whole arm) moved both sides equally and **survived**. The
assertions are now literals. Four survivors became four catches.

### 4.2 Arbitrary peer prose cannot reach `Detail` — RCCE-005

Three independent layers:

1. **Producer.** `normalizeClose` emits one of seven constants; fuzz-proven, pre-existing.
2. **Consumer.** A map lookup on exact keys. `TestHostileOutcomeValuesCannotProduceCapacityProse`
   plants 18 values directly into evidence — trailing space, leading space, lower case, mixed
   case, plural, prefixed, NUL-suffixed, newline-suffixed, the peer's own reply sentence, CR/LF,
   two ANSI escape forms, a 100 000-byte string, credential-shaped text, SQL-shaped text, and the
   empty string. Every one yields the generic explanation, and none appears in it.
3. **Property.** `FuzzOnlyClosedOutcomesEnrich` states the rule for *any* string: enrichment
   happens **iff** the value is byte-equal to one of the three, and an enriched detail is one of
   exactly three constants. **10 317 989 executions in 45 s, zero failures.**

### 4.3 Evidence membership — RCCE-016

Structural and unchanged: `ConnectionOpen` iterates connection-open nodes and calls
`connectionOpenFinding(node)` with the same node whose identifier becomes
`in.EvidenceRefs = []domain.EvidenceID{node.ID()}`. `connectionNotPermittedDetail` takes a
`domain.Evidence`, not a graph — it **cannot** see another node.

`TestAnotherNodesOutcomeCannotEnrichThisFinding` proves the consequence: a graph holding a
scope-less refusal at one endpoint and a user ceiling at another produces two findings, and the
first acquires no scope.

### 4.4 Convergence — RCCE-014, all four cases

Driven through the **real engine** (`diagnosis.NewRuleSet().Add(...).Freeze()` +
`Engine.Evaluate`), in an external test package, because the property belongs to the engine's
treatment of the rule's output.

| Case | Result |
|---|---|
| A — same subject, same outcome | every surviving finding names the node scope and only it |
| B — same subject, **different** outcomes | **two findings, one per scope, each citing one node.** ADR 0081 §2.2b's precondition does this automatically *because Detail now differs* — a property this phase created |
| C — mapped beside generic `RESOURCE_LIMIT_REACHED` (the truncation shape) | two findings; the specific one absorbs no scope-less evidence |
| D — different subjects | distinct, each carrying its own endpoint's scope |

**No convergence code changed.** `mergeKey` already includes `summary` and `detail`
(`converge.go:312-325`), so differing prose cannot merge — the safe direction, inherited.

### 4.5 Canonical JSON — RCCE-013, both halves

`TestCanonicalJSONChangesOnlyInDetail` marshals the finding and compares field by field against a
generic baseline:

| Claim | How |
|---|---|
| A. `SchemaVersion` unchanged | 1, measured before and after |
| B. `RunSchemaVersion` unchanged | 1, measured before and after |
| C. JSON field **structure** unchanged | field count equal, every key present |
| D. mapped: only `detail` differs | every other key byte-compared as encoded JSON; `detail` asserted to differ |
| E. unmapped: byte-identical | `TestNonCapacityOutcomesKeepTheGenericExplanation` — 11 cases asserting `Detail() == detailConnectionNotPermitted` exactly |
| F–I. code / severity / confidence / evidenceRefs | absolute literals (§4.1) |
| J. recommendations | encoded-JSON equality against the constant |
| K. exit status | untouched: severity unchanged, so `ExitCode` input unchanged |
| L. aggregate `RunReport` | untouched: no aggregate code changed, and `test/golden` passes |

**This phase does not claim "canonical JSON unchanged."** For a mapped capacity outcome the bytes
change, in `detail`, by design (ADR 0091 §4).

### 4.6 Product independence — RCCE-006

The mapping is keyed by `CloseOutcome`. `TestTheMappingIsKeyedByOutcomeAlone` asserts the map has
exactly three entries, that they are the three capacity constants, and that the four non-capacity
outcomes are absent.

**The structural proof is stronger than a behavioural one:** nothing in
`internal/diagnosis/rabbitmq` can see which implementation answered — there is no product
attribute on the connection-open node and depguard forbids the import that could supply one. The
pre-existing `TestNoVendorBranchExistsInTheJourney` and
`TestVendorDifferencesLiveOnlyInTheCloseNormalizer` in the LavinMQ suite both pass.

---

## 5. Real fixtures

### 5.1 What existed, and what was added

RabbitMQ **4.2.0**, with 3.13.7 and 4.0.9 also provisioned. LavinMQ **2.3.0**.

| Outcome | Before | Now |
|---|---|---|
| `VHOST_CONNECTION_LIMIT` RabbitMQ | RAB-21, real, all three versions | **extended** to assert the explanation |
| `VHOST_CONNECTION_LIMIT` LavinMQ | LMQ-06, real | **extended** to assert the same explanation |
| `NODE_CONNECTION_LIMIT` | unit only | **RAB-26, new, real** |
| `USER_CONNECTION_LIMIT` | unit only | **RAB-27, new, real** |

### 5.2 Determinism — limit zero, and a dedicated node

Both new ceilings are configured to **0**, so the refusal is a property of the configuration
rather than a race. Nothing is held open, nothing is timed, nothing must be cleaned up. This is
the mechanism the vhost fixture already used and the one Phase 10.3 used for PostgreSQL
`CONNECTION LIMIT 0`.

**`USER_CONNECTION_LIMIT`** — `rabbitmqctl set_user_limits ulimit '{"max-connections":0}'` on a
dedicated principal, because a per-user ceiling on `app` would refuse every other scenario.
Provisioning is **verified**: the Makefile greps `list_user_limits --user ulimit` for
`"max-connections":0` and **fails the gate** otherwise. (Measured during this phase:
`list_user_limits` without `--user` returns `{}` even when the limit is set, so the flag is
required — a check written the obvious way would have passed vacuously.)

**`NODE_CONNECTION_LIMIT`** — its own broker, `svcd-rabbit-nodelimit`, with `connection_max = 0`
in `conf.d/40-nodelimit.conf`. A node-wide setting cannot be applied to a node any other scenario
uses, which is the reason `rabbit-stop` is already a separate container. Declarative and true from
boot, so there is no ordering dependency between provisioning and the scenario. `rabbitmqctl` and
`rabbitmq-diagnostics` reach the node over Erlang distribution rather than AMQP, so readiness and
provisioning work on a broker that accepts no AMQP connection.

**A runtime alternative was tested and rejected.** `rabbitmqctl eval 'application:set_env(rabbit,
connection_max, 0).'` works and produces the exact T5 sentence — measured — but it mutates a
shared broker and creates an ordering dependency. The experiment was reverted with
`application:unset_env` and verified back to `undefined`.

**The node broker needed TLS, and the first run proved why.** With a plaintext-only listener the
scenario measured `RABBITMQ_CREDENTIAL_WITHHELD` — correctly: svcdoctor will not put a credential
on an unverified channel (ADR 0068), so the journey never reaches `Connection.Open` where the
ceiling is enforced. The fixture now serves TLS with the same certificate as the scenario broker.

### 5.3 Readiness

The Phase 9.1C lesson is honoured: bounded retry, no blind sleep, and **verification** rather than
`|| true`. The new broker is added to the readiness loop and to the failure log dump.

**Pre-existing debt recorded, not fixed:** `set_vhost_limits` and `set_permissions` still end in
`|| true` and are unverified. They happen to work because they run after the verified user loop.
New provisioning does not rely on that; the existing lines are out of this phase's scope.

### 5.4 Results

| Suite | Result |
|---|---|
| **RAB-21** vhost ceiling, real RabbitMQ | **PASS** |
| **RAB-26** node ceiling, real RabbitMQ | **PASS** |
| **RAB-27** user ceiling, real RabbitMQ | **PASS** |
| **LMQ-06** vhost ceiling, real LavinMQ — same explanation | **PASS** |
| **LMQ-09** unmapped LavinMQ refusal gains no scope | **PASS** |
| LavinMQ suite total | **10 / 10 PASS** |
| RabbitMQ suite total | **36 PASS, 2 FAIL** |

**The two RabbitMQ failures are pre-existing and environmental, proven rather than asserted.** A
`git worktree` at the baseline commit `5bd6589`, run against the same containers, produced
**identical failures with identical messages**:

- `TestRAB16BrokerStopped` — `svcd-rabbit-stop` is restarted by the container runtime, so TCP
  succeeds where the scenario expects a stopped broker.
- `TestRAB24And25AddressLiterals/RAB-25` — this Docker environment does not publish on `[::1]`;
  `[::1]:56679` is refused while `127.0.0.1:56672` connects.

Neither touches a capacity outcome, a finding explanation, or any file this phase changed. The
worktree was removed and the main tree verified unaffected.

---

## 6. Mutation closure

`scripts/phase108b-mutations.sh`, following the repository harness convention: plant in production
code only, run the guard, require it to **fail**, restore, and verify the tree byte-for-byte by
sha256. The zero-match guard uses a here-string, per the Phase 10.2 SIGPIPE finding.

**22 planted, 22 caught, 0 survivors. Tree restored byte-for-byte.**

| | |
|---|---|
| M01–M03 | each scope explained as one of the other two |
| M04–M06 | unknown value / non-capacity outcome / absent attribute receives capacity prose |
| M07–M09 | the lookup matches on a prefix, folds case, or trims |
| M10 | the raw `close_outcome` is interpolated |
| M11–M13 | exhaustion / misconfiguration / connection-leak claims |
| M14–M15 | the no-cause and impermanence sentences are dropped |
| M16–M19 | recommendation / code / severity / confidence change |
| M20 | the failure-class gate is removed |
| M21 | the mapping admits a fourth, non-capacity outcome |
| M22 | a capacity outcome suppresses the finding |

**Three contract mutations are deliberately not planted, and the harness says why** rather than
claiming a green line: a product-name branch is unplantable (nothing in the package can see the
product, and two LavinMQ guards already scan for it); a graph-wide lookup would require a
different function signature, so it is a rewrite rather than a mutation; and schema or
finding-code counts are pinned by attribution in `test/security` and exercised by the frozen
inventory.

---

## 7. Security and redaction

The three explanations are **constants**. They interpolate no username, password, virtual host,
endpoint, hostname, reply text, product or version. No new redaction rule is needed and none was
added — `test/security` and `internal/security/redaction` pass unchanged.

RAB-27 additionally asserts that the principal name does not appear in the explanation, and all
three capacity scenarios keep the pre-existing `assertNoRawPeerText` check and the assertion that
the peer's configured limit value `(0)` never reaches the report.

---

## 8. Multi-target isolation and complexity

The enrichment lives inside one per-target canonical report. No aggregate inference, no
`RunReport`-level claim, no cross-target correlation. `test/golden` (which covers the aggregate)
passes unchanged.

`connectionNotPermittedDetail` is one attribute read and one map lookup on the node already in
hand — constant time, no graph traversal, no allocation of consequence, no cache, no I/O.

---

## 9. Requirement register — `RCCE-001` … `RCCE-023`

| ID | Requirement | Where proven |
|---|---|---|
| RCCE-001 | No new diagnosis: no `FindingCode`, rule, kind, confidence path, `EvidenceBasis`, relation, discriminator, recommendation kind or failure class | frozen inventory; convergence scan 65/65, 22 rules |
| RCCE-002 | Only canonical `Finding.Detail` changes | `TestOnlyDetailChangesForCapacityOutcomes` |
| RCCE-003 | `FailureClass` semantics unchanged; the adapter's classification is consumed, not redefined | no change to `open.go`'s `classify()` |
| RCCE-004 | Recommendations byte-identical | `TestOnlyDetailChangesForCapacityOutcomes`, M16 |
| RCCE-005 | No arbitrary peer prose can reach `Detail` | `TestHostileOutcomeValuesCannotProduceCapacityProse`, `FuzzOnlyClosedOutcomesEnrich`, M07–M10 |
| RCCE-006 | Mapping keyed by outcome, never product | `TestTheMappingIsKeyedByOutcomeAlone`; LavinMQ vendor guards |
| RCCE-007 | Node scope named correctly | `TestCapacityOutcomesNameTheirScope`, RAB-26, M01 |
| RCCE-008 | VHost scope named correctly | same, RAB-21, LMQ-06, M02 |
| RCCE-009 | User scope named correctly | same, RAB-27, M03 |
| RCCE-010 | Unknown / empty / absent value falls back | `TestNonCapacityOutcomesKeepTheGenericExplanation`, M04, M06 |
| RCCE-011 | Non-capacity known outcome falls back | same, M05, M21 |
| RCCE-012 | Deterministic repeated construction | `TestCapacityExplanationIsDeterministic` |
| RCCE-013 | Canonical JSON: structure unchanged, mapped `detail` changes, unmapped byte-identical | `TestCanonicalJSONChangesOnlyInDetail` |
| RCCE-014 | Convergence safe in all four cases | `capacityconvergence_test.go` |
| RCCE-015 | No convergence architecture change | `converge.go` untouched |
| RCCE-016 | Evidence membership: the cited node only | `TestAnotherNodesOutcomeCannotEnrichThisFinding` |
| RCCE-017 | One authoritative closed vocabulary, values byte-identical | seven literals in one file; wire declares zero |
| RCCE-018 | Real RabbitMQ proof for all three ceilings | RAB-21, RAB-26, RAB-27 |
| RCCE-019 | Real LavinMQ positive proof, and no false enrichment | LMQ-06, LMQ-09 |
| RCCE-020 | Fixtures deterministic, verified, no race, no blind sleep | limit 0; verified `list_user_limits --user` |
| RCCE-021 | Closed-value property over arbitrary strings | `FuzzOnlyClosedOutcomesEnrich`, 10 317 989 execs |
| RCCE-022 | Claim ceiling: no overclaim, no raw identifier, no-cause sentence retained | `TestCapacityExplanationsRefuseTheOverclaims`, M11–M15 |
| RCCE-023 | No schema, CLI, config, dependency, credential-authority or network change | `go.mod` unchanged; no CLI or config file touched |

---

## 10. Validation run

```
git rev-parse HEAD; git rev-parse origin/main       # identical, 5bd6589
git status --short                                  # clean at start
make check                                          # exit 0, before edits
gofmt -l <changed>                                  # empty
go test ./internal/diagnosis/rabbitmq/              # ok
go test ./test/security/... ./internal/security/... # ok
go test ./internal/render/... ./internal/domain/... # ok
go test ./test/golden/... ./test/diagnosis/...      # ok
go test ./...                                       # ok
go vet ./...                                        # clean
golangci-lint run ./...                             # 0 issues
make check                                          # exit 0, after edits
git diff --check                                    # clean

go test -tags integration ./test/integration/rabbitmq/   # 36 pass, 2 pre-existing fail
go test -tags integration ./test/integration/lavinmq/    # 10/10 pass
go test -fuzz FuzzOnlyClosedOutcomesEnrich -fuzztime=45s # 10,317,989 execs, 0 failures
bash scripts/phase108b-mutations.sh                      # 22/22 caught, 0 survivors
```

**Not run:** the PostgreSQL, Kafka, Redpanda, Redis, Valkey and multi-target integration suites,
and the other ten mutation harnesses. This phase changes no PostgreSQL, Kafka or Redis code path;
`go test ./...` covers their unit and security suites. **No integration-green claim is made for
them.**

**Known limitations.**

1. Two RabbitMQ integration scenarios fail in this environment, **proven pre-existing** at the
   baseline commit against the same containers (§5.4). They are unrelated to this phase.
2. `set_vhost_limits` and `set_permissions` remain unverified `|| true` provisioning — pre-existing
   debt, recorded and deliberately not refactored here.
3. `NODE_CONNECTION_LIMIT` and `USER_CONNECTION_LIMIT` are proven on **RabbitMQ 4.2.0 only**. The
   vhost ceiling is proven on 3.13.7, 4.0.9 and 4.2.0 because the fixture provisions it on all
   three; the two new ceilings are not, and no cross-version claim is made for them.
4. LavinMQ produces no node or user ceiling template, so those two scopes are unproven there and
   nothing claims otherwise.
5. Truncation means **absence of a scope proves nothing**. A real ceiling whose reply text was
   truncated keeps the general wording. This is stated in `docs/OUTPUT.md` rather than engineered
   around.
