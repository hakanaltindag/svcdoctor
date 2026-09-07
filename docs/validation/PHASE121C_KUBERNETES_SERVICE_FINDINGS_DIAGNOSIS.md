# Phase 12.1C — Kubernetes Service findings and diagnosis

- **Phase:** 12.1C (implementation; four finding codes, two rules, no CLI command, no renderer
  change, no dependency change)
- **Baseline:** `3444c3e94330bd0d8fc3385b5c669a4c5bc476d7`, equal to `origin/main`, clean tree
- **Contract:** ADR 0094 (Accepted, Phase 12.1A), refined by
  `docs/validation/PHASE121A_KUBERNETES_ADAPTER_CONTRACT_FREEZE.md` §10.3 and §10.8
- **Outcome:** **69 finding codes, 24 production rules, zero survivors, zero schema change**

---

## 1. Baseline and start state

`make check` was **GREEN** at `3444c3e` before anything was edited: `go test ./...`,
`go vet ./...`, `golangci-lint run ./...` (0 issues) and `CGO_ENABLED=0 go build ./...`, exit 0.

Phase 12.1A (`ce5542c`), Phase 12.1B (`3444c3e`) and ADR 0094
(`docs/decisions/0094-kubernetes-service-diagnostic-contract.md`) are all committed. `HEAD ==
origin/main`.

### 1.1 Pre-state, measured rather than trusted

| | Measured | ADR 0094 §2.10 expected |
|---|---|---|
| `SchemaVersion` | 1 | 1 |
| `RunSchemaVersion` | 1 | 1 |
| Finding codes | **65** — `DIAG` 1, `DNS` 2, `KAFKA` 15, `POSTGRES` 21, `RABBITMQ` 11, `REDIS` 9, `TCP` 1, `TLS` 5 | 65 |
| Production rules | **22** (distinct `RuleSet.Add` identities across `internal/app`) | 22 |
| Failure classes | 42 | 42 |
| `RuleContext` fields | 3 | 3 |
| `security.Reveal` production call sites | 5 | 5 |
| `SecretFor` production call sites | 5 | 5 |
| External modules | 40 | 40 |
| Exit codes | 5 | 5 |
| Kubernetes attributes | 17 | 17 |
| Kubernetes evidence nodes | 5 | 5 |

---

## 2. What was built

**`internal/diagnosis/kubernetes`** — three production files, 2 rules, 4 codes:

| Rule ID | Entry point | Codes | Category (ADR 0094 §2.8) |
|---|---|---|---|
| `kubernetes/acquisition` | `Acquisition` | F1, F2 | what svcdoctor could **obtain** |
| `kubernetes/backends` | `Backends` | F3, F4 | what Kubernetes **records** |

**`internal/app/kubernetes.go`** — the composition root now wires three rules and threads the
findings into the report. It wires `diag/failure-boundary`, `kubernetes/acquisition` and
`kubernetes/backends`, and **no transport rule**: a Kubernetes run measures no DNS, TCP or TLS
stage of its own, so a transport rule would be silent by construction rather than by
measurement.

### 2.1 The rule decomposition, and why two rather than four

ADR 0094 §2.10 froze `22 → 24` and §2.12 named them *"one acquisition rule and one publication
rule"*. The split is §2.8's taxonomy, and it is what keeps each rule's preconditions in one
place: the semantic rule's Service gate — read, supported type, non-empty selector — is one gate
that both of its codes need, and duplicating it across two rules is how the two would drift.

---

## 3. The four findings, as implemented

Every value below was source-proven against ADR 0094 §2.7 and `PHASE121A…§10.3` before it was
written, and every one is pinned by `TestEveryProducedFindingMatchesItsFrozenContract`.

| | Code | Kind | Severity | Confidence | Basis | Layer | `vantageDependent` | Discriminator |
|---|---|---|---|---|---|---|---|---|
| **F1** | `KUBERNETES_SERVICE_NOT_FOUND` | CONFIRMED | ERROR | HIGH | `AuthorityDirect` | **L6** | false | none |
| **F2** | `KUBERNETES_API_ACCESS_DENIED` | CONFIRMED | **WARN** | HIGH | `AuthorityDirect` | **L6** | false | none |
| **F3** | `KUBERNETES_SERVICE_SELECTS_NO_PODS` | CONFIRMED | ERROR | HIGH | `AuthorityDirect` | **L6** | false | none |
| **F4** | `KUBERNETES_SERVICE_NO_READY_ENDPOINT` | CONFIRMED | ERROR | HIGH | `AuthorityDirect` | **L6** | false | none |

**Confidence is a literal, not a ladder call.** `PHASE121A…§10.6` recorded that routing through
`AdmitConfidence` is not output-neutral for a claim restating a direct measurement, required the
same choice for all four, and offered both. `domain.ConfidenceHigh` is set as a literal, exactly
as 21 of the other 22 rules do — which also avoids arming either of ADR 0087's two vacuous
`AdmitConfidence` guards, since `AuthorityCompleteContrast` still has no producer and must be
armed together with `Miss` in one change-set.

**Every `Layer` is read from the node the claim cites**, never written as a constant. Phase 10.1B
measured the other shape in PostgreSQL — a finding published at L5 while citing an L4 node,
decided by an alphabet — and mutation KC-M36 plants it here.

**`vantageDependent` is false for all four.** What an API server answers does not change with
where it was asked from. Whether the published endpoints can be *reached* from here would be
vantage-dependent — and that is the claim F4 refuses to make.

### 3.1 Admission predicates

**F1** — `step == k8s.service` **and** `state == FAIL` **and** `class == RESOURCE_NOT_FOUND`.
The class is what the adapter assigns to `apierrors.IsNotFound` and to nothing else, so the
authority is the API's own `metav1.StatusReason` with **no string anywhere in the path**. The
step scope is load-bearing rather than tidy: a `LIST` can also be answered `404` — a namespace
that does not exist is the ordinary way — and without it the rule would announce that the
*Service* was not found because a *Pod list* was.

**F2** — `step ∈ {k8s.service, k8s.pod_set, k8s.endpoint_publication}` **and**
`state == UNKNOWN` **and** `class == AUTHZ_NOT_PERMITTED`, iterated over all three so two
refusals produce two findings. The operation is named from a closed three-entry map; a step with
no entry withholds the claim entirely rather than falling back to the step string.

**F3** — the Service gate (PASS · type ∈ {ClusterIP, NodePort, LoadBalancer} · selector present
and non-empty) **and** `k8s.pod_set` PASS **and** `k8s.pod_set_complete == true` **and**
`k8s.pod_observed_count == 0`.

**F4** — the Service gate **and** F3 not admitted **and** `k8s.endpoint_publication` PASS
**and** `k8s.slice_set_complete == true` **and** `k8s.ready_endpoint_count == 0`.

Every attribute read requires the attribute to be **present**. An absent boolean is never read
as false and an absent count is never read as zero.

### 3.2 Negative predicates, stated positively

| Never admits F1 | Never admits F2 | Never admits F3 | Never admits F4 |
|---|---|---|---|
| a `404` on any other node | a `401` in any state | an incomplete Pod set, any stop reason | an incomplete slice set, any stop reason |
| any other failure class on `k8s.service` | any class other than `AUTHZ_NOT_PERMITTED` | a selector-less Service | a selector-less Service |
| a Go error whose text contains "not found" — no error text is in the graph | a node in a state other than `UNKNOWN` | `ExternalName` or an unrecognized type | `ExternalName` or an unrecognized type |
| a cancelled, timed-out or skipped read | a `410`, a `5xx`, a timeout, a reset | a denied, failed, cancelled or skipped Pod read | a denied, failed, cancelled or skipped slice read |
| a `403` | a local configuration refusal | an observed count other than exactly zero | a ready count other than exactly zero |
| a `5xx`, a `410` or a timeout | a node with no bounded operation name | a Service node that did not pass | a Service node that did not pass |
| — | — | a completeness flag absent, or carried as a non-boolean | an endpoint budget that truncated the set |

### 3.3 Evidence membership

Frozen by `PHASE121A…§10.3`, pinned by `TestEveryFindingCitesExactlyTheFrozenEvidence` and by
`TestNoFindingCitesANodeThatIsNotAboutIt`.

| | Cites | Never cites |
|---|---|---|
| F1 | `k8s.service` **only** | the Pod set, the publication |
| F2 | the denied read's node **only** | any other node |
| F3 | `k8s.service` + `k8s.pod_set` | the publication |
| F4 | `k8s.service` + `k8s.endpoint_publication` | the Pod set |

Both references on F3 and F4 are load-bearing, which is the test ADR 0078 §2.3 rule 1 states:
delete either from the graph and the claim stops standing up. The over-citation direction is
checked too — a finding that cited the whole journey would look better supported than it is.

### 3.4 Recommendations

One each, all `NEXT_EVIDENCE` with `SelfCollectable: false`; `VERIFY` for F1 and F2, `COMPARE`
for F3 and F4. The **text is pinned byte for byte** by
`TestEveryRecommendationTextIsTheFrozenOne`, and
`TestNoRecommendationTellsAnOperatorToChangeAnything` refuses eighteen imperatives by name.

No `REMEDIATION` is reachable at any confidence; `RESTART`, `DISRUPTIVE` and
`SECURITY_WEAKENING` are not producible at all, which `diagnosis.NewAdvice` enforces on the
construction path and `TestNoKubernetesRecommendationIsEverARemediation` asserts from outside it.

### 3.5 F4's two Detail variants

A closed two-value map, mutually exclusive by construction, so ADR 0094 §10.9 shape C — *"cannot
co-occur"* — is a property of the code rather than a hope:

- **A**: *no EndpointSlice associated with this Service was published* (`slices == 0`)
- **B**: *EndpointSlices were published and no endpoint among them reports itself ready*

Variant B gains **one conditional sentence** when the set is non-empty and every endpoint reports
itself terminating: *"Every endpoint in that set reports itself terminating. Such an endpoint is
not necessarily out of service: where all of a Service's endpoints are terminating, a proxy may
still route to them."* That is ADR 0094 §2.6's requirement — silence there would let *"no ready
endpoint"* be read as *"no traffic"* — and it is a sentence rather than a count, because
rendering *how many* would put a cluster's cardinality into prose.

`TestTheTwoPublicationDetailVariantsAreExactAndExclusive` pins all of it, including that the note
is withheld for a partly-terminating set, for a set with no endpoints, and for variant A.

---

## 4. One contract question, reconciled rather than guessed

`PHASE121A…§10.3` lists F4's precondition as *"at least one Pod was selected **(so F3 and F4 are
disjoint)**"*. Read literally, that would also withhold F4 whenever the Pod branch was **denied
or incomplete** — because "at least one Pod was selected" is then not established.

`PHASE121A…§10.8` says the opposite in a table it states normatively:

| Condition | Behaviour |
|---|---|
| Pod set incomplete | **no F3.** *The slice branch is unaffected* |
| EndpointSlice set incomplete | **no F4.** *The Pod branch is unaffected* |

under the block-quoted rule *"one branch failing never erases the other branch's independent
evidence"*. The two rows are symmetric, and the second unambiguously means F3 may still fire.

**Resolution: implement the parenthetical, which is the condition's own stated purpose. F4 is
withheld exactly when F3 was admitted.** That is byte-for-byte the literal reading wherever the
Pod set is complete — the only case in which "at least one Pod was selected" can be established
at all — and it keeps the branches independent everywhere else.

The alternative was measured before being rejected: under the literal reading, a Service whose
Pod enumeration reached the 4,000-object budget could **never** produce F4, even with a complete
authoritative slice set showing nothing ready. A large Service is exactly where the publication
answer matters most, and withholding a proven claim because an unrelated read was denied is the
erasure §10.8 forbids.

This is recorded as a **contract interpretation**, not a silent rewrite: ADR 0094 is unchanged,
`internal/diagnosis/kubernetes/backends.go` carries the reasoning in `noReadyEndpoint`'s doc
comment, and `docs/BACKLOG.md` records it. **No ADR was edited.**

---

## 5. Short-circuit and coexistence matrices

`TestTheShortCircuitMatrixProducesExactlyTheseFindings` asserts the **exact** finding multiset
for **50 named scenarios**. There is no "at least" anywhere in it: an added claim and a lost one
both fail.

### 5.1 Selected rows

| Scenario | Findings |
|---|---|
| everything read and backed | — |
| service not found | F1 |
| service read denied | F2 |
| pod read denied, publication healthy | F2 |
| slice read denied, pods healthy | F2 |
| **both list reads denied** | **F2, F2** |
| **pod read denied, no ready endpoint** | **F2, F4** |
| **slice read denied, selector matched nothing** | **F2, F3** |
| 401 unauthorized | — |
| api server unreachable | — |
| service read answered 5xx / timed out | — |
| pod list answered 404 / slice list answered 404 | — |
| selector matched no pod | F3 |
| no endpoint slice published | F4 |
| slices published, none ready / all terminating / some terminating | F4 |
| one ready endpoint among many terminating | — |
| **no pod and no slice** | **F3** (F4 withheld — they are disjoint) |
| pod set incomplete, at zero or at a ceiling | — |
| slice set incomplete, at zero or with none ready | — |
| both sets incomplete at zero | — |
| selector-less service (skipped, or reads that ran empty) | — |
| external name service (skipped, or reads that ran empty) | — |
| unrecognized service type | — |
| headless service selecting nothing | F3 |
| node port service with nothing ready | F4 |
| load balancer service selecting nothing | F3 |
| pod count with no completeness flag | — |
| pod completeness flag with no count | — |
| ready count with no slice count | — |
| service node with no shape attributes | — |
| no service node at all / only the target anchor | — |
| negative pod count / negative ready count | — |
| completeness carried as a string | — |
| failed service node carrying a full shape | F1 |
| denied service node carrying a full shape | F2 |
| unfinished pod node claiming completeness | — |
| unfinished slice node claiming completeness | — |
| refusal class carried as a failure | — |
| refusal on a node with no bounded operation | — |

### 5.2 Coexistence, per the brief's A–G

| | Shape | Result |
|---|---|---|
| A | F3 only | *selector matched no pod* |
| B | F4 only | *no endpoint slice published* |
| C | F3 + F4 | **unreachable** — ADR 0094 §10.3 makes them disjoint |
| D | F2 on the Pod read + a valid slice branch | **F2 + F4**, branch independence intact |
| E | A valid Pod branch + F2 on the slice read | **F2 + F3**, likewise |
| F | F1 on the Service read | **F1 only** among Kubernetes findings |
| G | F2 on the Service read | **F2 only** among Kubernetes findings |

**No causal claim links any pair.** No graph edge, no prose and no recommendation says one
finding explains another; `docs/FINDINGS.md` §9.2 states the disjointness as a *presentation*
decision — one impact is never described twice at one severity — and never as causation.

#### 5.2.1 Row C, re-derived from the frozen sources rather than from this implementation

The user review asked whether F3 and F4 are contractually disjoint or may coexist when both
branches independently satisfy their admission predicates. Re-read against the committed frozen
text alone, **every source says disjoint and none says otherwise**:

| Source | Section | Requirement | Case: pod set complete at 0, slice set complete at 0 ready |
|---|---|---|---|
| `PHASE121A…` | §10.3, F4 admission | F4 requires *"at least one Pod was selected (so F3 and F4 are disjoint)"* | F4's predicate is **not satisfied**; F3 alone |
| `PHASE120…` | §17.1 | K10's preconditions include *"at least one Pod is selected (so K8 and K10 never both fire for one condition)"* | F3 alone |
| ADR 0094 | §2.7 | The finding table; states no coexistence and no joint shape | silent — no admission for it to license |
| ADR 0094 | §2.9 · `PHASE121A…` §10.8 | *"one branch failing never erases the other branch's independent evidence"* | **not engaged** — neither branch failed, so the rule has no case here |
| `PHASE121A…` | §10.9 | Convergence over six shapes; F3 + F4 is not among them | no pair exists to converge |

**Verdict: the sources are explicitly and consistently DISJOINT, and the implementation already
matches — no production change was required.** `TestTestKP09TheTwoSemanticClaimsAreDisjoint`
drives all 36 combinations of the two branches and asserts no input produces both, and
`admission_test.go`'s *"no pod and no slice"* scenario pins the exact case above to `{F3}`.

**The §10.3-versus-§10.8 tension recorded in §12 is a different question and does not touch
this one.** It concerns a Pod branch that was **denied or incomplete** — where §10.3 read
literally would erase a proven publication claim and §10.8 forbids exactly that erasure — and
resolving it in §10.8's favour *widens* F4 into cases where F3 was never admissible. It can
never produce coexistence, because F3 is not admitted in any of them.

---

## 6. Convergence

Driven through the real `Converge` in `test/diagnosis/kubernetescorpus_test.go`.

| | Shape | Result |
|---|---|---|
| A | one claim reached twice, byte-identically | **merges**, evidence is the union |
| B | F2 for two different denied operations | **two findings** — the Detail differs, and ADR 0081 §2.2b makes Detail a merge precondition |
| C | F4's two Detail variants | **cannot co-occur** — mutually exclusive by construction |
| D | different Service subjects | no merge; identity is `(Code, Subject)` |
| E | incomplete versus complete evidence | incomplete emits nothing, so no pair exists |
| F | evidence-insertion permutation | byte-identical canonical JSON |

Shape B is the one that needed checking. Both findings share a code, a subject, a **layer**, a
severity, a confidence and an empty discriminator — so `SemanticIdentity` is equal and
convergence really is asked the question. The only thing keeping them apart is the Detail, and
`TestTwoDeniedReadsSurviveConvergenceAsTwoFindings` asserts the identity equality *first*, so the
test cannot pass by the two never having been candidates.

`test/security/convergenceinventory_test.go` now attributes all **69** codes to the **24**
production rules and reports **no new cross-rule convergence candidate**: each of the four
Kubernetes codes is reachable from exactly one rule. `knownConvergentCodes` is unchanged.

`TestRenamingTheKubernetesRulesChangesNoByte` instantiates ADR 0081 §2.6a for a fifth service:
`RuleID` reaches no merged field, so renaming both rules leaves the canonical JSON identical.

**No merge-semantics change was made and none was needed.**

---

## 7. The failure boundary

The **existing generic** algorithm, unchanged. No Kubernetes-specific boundary exists and no
`Layer` value was added.

| Scenario | Boundary | Last good | First failure |
|---|---|---|---|
| a healthy run | **none** | — | — |
| a rejected identity (`401`) | yes | **L0** (`k8s.target`) | **L5** (`k8s.api_access`) |
| an absent Service (`404`) | yes | **L5** (`k8s.api_access`) | **L6** (`k8s.service`) |
| a denied read (`403`) | **none** | — | — (UNKNOWN is neither half) |

ADR 0094 §10.7's claim that *"both absences are deliberate and neither breaks the boundary"* —
L1–L4 being unused — is now measured rather than argued: `lastGood` requires only *a* PASS at a
strictly lower layer, and the L0 anchor supplies one.

`TestAKubernetesFindingAndTheBoundaryCoexistWithoutOverridingEachOther` drives the one case where
both exist. They carry different codes, so convergence never considers them; the boundary stays
INFO because it describes *where*, and the Kubernetes claim stays ERROR because that is the
impact of what it states.

---

## 8. Exit behaviour — the phase's public change

Measured end to end through `cli.App.Run` against a hermetic HTTPS API server
(`test/fleet/kubernetes_test.go`). **The exit codes are recorded, not chosen**: `RunExitCode`
reads the aggregate summary and nothing else, and there is no `if kubernetes` in the mapping.

| Scenario | Findings | Exit |
|---|---|---|
| ready endpoint, matching Pods | — | **0** |
| absent Service | F1 (ERROR) | **1** |
| refused Pod read | F2 (WARN) | **4** |
| selector matched nothing | F3 (ERROR) | **1** |
| nothing published | F4 (ERROR) | **1** |
| published, nothing ready | F4 (ERROR) | **1** |
| `401 Unauthorized` | — (boundary only, INFO) | **0** |

Two rows were **predicted wrongly and corrected to what was measured**, and both are worth
stating.

**A refused read exits 4, not 0.** A `403` on a list was *attempted* and did not complete, so
`client.Result.Incomplete()` is true and exit 4 outranks everything below it. The WARN finding
never decides that invocation's status — incompleteness qualifies every conclusion, which is
exactly what `docs/SCOPE.md`'s precedence `3 > 2 > 4 > 1 > 0` says it should do. This is 12.1B
behaviour, unchanged.

**A `401` exits 0, and that is a recorded limitation.** ADR 0094 §10.4 refuses a `401` a
Kubernetes code deliberately; `DIAG_FAILURE_BOUNDARY` localizes it and is INFO. So no ERROR
finding exists, `SummaryStatus` is OK, the run is complete (a `401` is an answer), and the
generic mapping returns 0. Every other service has a credential-rejection finding at ERROR;
Kubernetes has none, because the four-code budget is frozen. **The behaviour is unchanged by
12.1C** — before it, the same invocation exited 0 with no finding at all — and closing it needs a
fifth code, which is a decision with its own record. It is pinned by test and recorded in
`docs/BACKLOG.md` rather than smuggled in here.

---

## 9. The 17-attribute consumption audit

| Attribute | F1 | F2 | F3 | F4 | Otherwise |
|---|---|---|---|---|---|
| `k8s.auth_mode` | | | | | **audit only** — report-visible authority |
| `k8s.context` | | | | | **audit only** |
| `k8s.namespace` | | | | | **identity** — on the subject and the node; never in prose |
| `k8s.service_name` | | | | | **identity** — likewise |
| `k8s.service_type` | | | ✔ gate | ✔ gate | |
| `k8s.service_headless` | | | | | **rendering only, permanently** — `clusterIP: None` is never a fault |
| `k8s.selector_present` | | | ✔ gate | ✔ gate | |
| `k8s.selector_key_count` | | | | | **audit only** — the count, never the keys |
| `k8s.pod_set_complete` | | | ✔ | | |
| `k8s.pod_observed_count` | | | ✔ | | |
| `k8s.slice_set_complete` | | | | ✔ | |
| `k8s.slice_count` | | | | ✔ variant | |
| `k8s.endpoint_count` | | | | ✔ note | |
| `k8s.ready_endpoint_count` | | | | ✔ | |
| `k8s.terminating_endpoint_count` | | | | ✔ note | |
| `k8s.slice_excluded_by_owner_uid_count` | | | | | **audit only** — makes the race guard auditable |
| `k8s.slice_externally_managed` | | | | | **audit only** — does not gate admission |

**Seven attributes are consumed by a rule; ten are audit or rendering only, and that is
acceptable.** Phase 10.8's lesson holds: *data availability does not justify diagnosis*. No rule
was manufactured to consume an attribute, and `k8s.service_headless` is marked rendering-only
*permanently* by ADR 0094 §11.1 — a headless Service is a deliberate configuration.

F1 and F2 consume **no attribute at all**: their whole predicate is a step, a state and a failure
class, and the operation name comes from a closed map keyed on the step.

---

## 10. Architecture, security and dependency impact

| Question | Answer | How it is held |
|---|---|---|
| Did diagnosis perform an API call? | **No** | `TestTheKubernetesFleetTargetStillDialsOnlyTheAPIServer` counts **exactly 3** at the server, for a run that produces a finding |
| Did diagnosis access a secret? | **No** | `TestTheKubernetesDiagnosisReachesNoCredential` scans the source for `Reveal`, `SecretFor`, `security.`, `Credential`, `Secret` |
| Did diagnosis import `k8s.io`? | **No** | `TestTheKubernetesRulesImportNothingBelowDiagnosis` — an **allowlist** of 4 imports; `depguard` states it at lint time |
| Did the generic core gain a Kubernetes branch? | **No** | `TestNoKubernetesSpecialCaseExistsInAnyGenericPackage`, unchanged and still green |
| Did the scheduler or renderer branch? | **No** | zero files changed in `internal/fleet/run` and `internal/render` |
| Did the schema change? | **No** | `SchemaVersion` 1, `RunSchemaVersion` 1, no new field |
| Did config change? | **No** | zero files changed in `internal/fleet/config` and `internal/fleet/services/kubernetes` |
| Did the dependency graph change? | **No** | `go.mod` and `go.sum` untouched; `TestTheDependencyCountIsExact` green |
| Did a fifth finding appear? | **No** | `TestTheKubernetesFindingCodesAreExactlyTheFourFrozenOnes`, both directions |
| Did a relation producer arm? | **No** | `TestNoKubernetesRuleActivatesAnEvidenceRelation` |
| Did a planner appear? | **No** | no discriminator, no `SelfCollectable: true`, no observation scheduler |
| Did F3/F4 become causal? | **No** | no edge, no prose, no recommendation links them |
| Did incomplete evidence become zero? | **No** | K-P01, K-P02, and every stop reason through the real producer |
| Did raw Kubernetes prose enter canonical output? | **No** | `TestNoKubernetesSourceReadsAStatusMessage` unchanged; the graph carries no message |
| Did cross-target diagnosis appear? | **No** | `TestAMixedFleetKeepsItsTargetsApart` over a real two-service run |

**`k8s.io` allowlist: unchanged at ten paths. `.golangci.yml`: unchanged. `Reveal`: 5.
`SecretFor`: 5. Modules: 40. `go.sum`: unchanged.**

### 10.1 The 12.1B security regression suite

Re-run and green: the sole-importer property, the ten-path allowlist, the layer boundary, the
vocabulary leaf, the generic-core literal and import scans, the `Status.Message` AST guard, the
`exec` sentinel, credential authority, and the adapter's own no-finding boundary
(`TestTheKubernetesAdapterNeverProducesAFinding`, which scans only the adapter and vocabulary
packages and is **kept**, not relaxed).

Two 12.1B guards had their premise deliberately removed and were **turned around rather than
deleted**, the Phase 8.2 pattern:

- `TestNoKubernetesFindingCodeExistsYet` → **`TestTheKubernetesFindingCodesAreExactlyTheFourFrozenOnes`**:
  these four, in these two files, and no fifth. It matches on the *shape* of a screaming-snake
  token rather than on the prefix alone, because two in-cluster error messages open with
  `KUBERNETES_SERVICE_HOST`.
- `TestAKubernetesRunProducesNoFindingAtAll` → **`TestAKubernetesRunReportsWhatTheAPIAnswered`**:
  the same five-node graph now yields exactly two findings and moves the summary off OK.

---

## 11. Validation performed

### 11.1 Unit and property tests

`internal/diagnosis/kubernetes`, **38 test functions plus one fuzz target**, over **50 named scenarios**:

- the exact-multiset short-circuit matrix, and the no-fifth-code guard
- the frozen field contract, the evidence membership, the wrong-branch refusal, the subject and
  kind, and that every admitted shape builds a valid finding
- the claim ceilings — per-code forbidden phrases plus a universal list — with a **non-vacuity
  test** that plants each phrase and requires the same comparison to find it
- the positive half: the sentences each finding must contain
- hostile identity values and hostile counts never reaching prose; changing the counts never
  changing a byte of it
- the bounded operation identity, the two-refusal distinguishability, the two F4 detail variants
- determinism under five evidence-insertion permutations and eight repeated evaluations
- **K-P01 … K-P15**, the diagnosis half of ADR 0094 §13.5 (the acquisition half — `exec` never
  executing, credential authority, cancellation stopping pagination, budgets marking a set
  incomplete — is 12.1B's and stays there)

`test/diagnosis` — **15 test functions** — drives the **real `adapter/kubernetes.Record`** over
synthetic acquisition results: 18 producer-agreement rows, all 12 members of `client.Failure`,
all 6 stop reasons on both branches, plus convergence, the boundary, canonical-JSON determinism
and shape, the shareable projection, the terminal output, and a **five-scenario false-positive
corpus** (K-FP01 … K-FP05) checked against the local report, the shareable report and the
terminal.

It also holds the phase's **one duplicated-string guard**.
`client.Operation` and the rule package each declare `SERVICE_GET`, `POD_LIST` and
`ENDPOINTSLICE_LIST` — the first for its own audit purposes, the second as report prose — and
they cannot share a constant, because diagnosis may not import an adapter.
`TestTheDeniedOperationNamesMatchTheAcquisitionVocabulary` is the only thing in the tree that
can see both, and it drives a real refusal at each operation. It exists because
`acquisition.go`'s doc comment names it, and a comment claiming a guard that does not exist is
the drift `docs/BACKLOG.md` already records as RRI-016.

`test/fleet` — **3 test functions**, a new hermetic cross-package suite — drives the **real
CLI** against a hermetic HTTPS API server: the exit matrix, a
mixed Kubernetes + Redis fleet with cross-target isolation, and the request count.

### 11.2 Fuzz

`FuzzTheKubernetesRulesOverTheNormalizedAttributeSpace` — 9 seeds, **180 s**, **19,097,795
executions**, ~80,000/sec, 0 crashes, corpus 16 (no new interesting input after the first 9 s).

**The fuzzer found a defect in the test and the fix is stronger than the check it replaced.**
The first version asserted that the fuzzed Service type did not appear in the prose; the fuzzer
refuted it in 9 seconds with `"clu"`, a substring of *"the cluster"* in a frozen detail. The
rules were right and the check was wrong: a substring scan over English cannot tell an
interpolation from a coincidence, and lengthening the minimum only moves it. It is now
**membership in a closed set** computed from the deterministic matrix — exact, collision-free,
and directly the property being claimed. The offending input is kept as a seed.

### 11.3 Mutation

`scripts/phase121c-mutations.sh` — **42 planted, 42 caught, 0 survivors**, tree restored
byte-for-byte. Every plant is in production code; the zero-match guard uses a here-string.

**The first run caught 37 of 42, and not one of the five survivors was an equivalent mutation.**

| Survivor | What it revealed | Closure |
|---|---|---|
| KC-M03 | the Service gate's **state** check was equivalent to nothing — no scenario had a failed Service node carrying a shape | 2 scenarios added |
| KC-M07 | the F2 predicate's **state** half was equivalent to nothing. `AUTHZ_NOT_PERMITTED` is a **shared** class that PostgreSQL records as `FAIL` for `POSTGRES_CONNECTION_NOT_PERMITTED`, where it means something else | 1 scenario added |
| KC-M09 | genuinely unreachable alone; the plant was **reworked** to widen the scan *and* add the fallback, which is the shape an author reaching for "just print something" writes | 1 scenario added, plant rewritten |
| KC-M18 | the F3 Pod-node **state** check was equivalent to nothing | 2 scenarios added |
| KC-M24 | **the sharpest.** *"Change this Service's selector to match the intended workload"* is a well-formed `NEXT_EVIDENCE`/`COMPARE` with `SelfCollectable: false` — and a remediation in the only sense that matters to the reader | recommendation text pinned byte for byte; 18 imperatives refused by name |

All ten historical suites were re-run at the end of the phase; see §13.

### 11.4 Race, lint, build

`go test -race` over `internal/diagnosis/...`, `internal/adapter/kubernetes/...`,
`internal/app/...`, `internal/fleet/...`, `internal/cli`, `test/diagnosis`, `test/fleet`:
**exit 0, zero `DATA RACE` reports**. Diagnosis is pure, so this is boring by design.

`golangci-lint run ./...` — **0 issues**. `git diff --check` — clean.

### 11.5 A pre-existing harness defect, found and fixed

Re-running all ten historical mutation suites surfaced **one survivor that predates this phase**:
`A11 (unplantable)` in `scripts/phase91a-mutations.sh`.

Its anchor was `if err := checkHostSyntax(block.Host); err != nil {`. **Phase 12.1B** turned that
line into `} else if err := …` when `internal/fleet/config/load.go` gained the derive-or-check
branch a Kubernetes target needs — a Kubernetes target writes no host. The `.replace` silently
became a no-op, the plant's own `assert` then failed, and the harness reported *unplantable*: a
survivor for the best possible reason and the worst possible one.

Confirmed pre-existing by reading the file at both commits:

```
git show ce5542c:internal/fleet/config/load.go  ->  	if err := checkHostSyntax(block.Host)
git show 3444c3e:internal/fleet/config/load.go  ->  	} else if err := checkHostSyntax(block.Host)
```

`3444c3e` is this phase's baseline, so the drift arrived one commit before it. The anchor is
re-pointed at `deriver, derives := factory.(EndpointDeriver)` — inside the same function, not
part of the branch that moved, and the line a host-reading mutation would have to sit beside
anyway. **The mutation itself is unchanged**, and the property it guards
(`TestOnlyTheResolverReadsTheEnvironment`) is unchanged.

This is the same class of defect Phase 10.2 found across all eight scripts then: a harness that
reports something other than what it measures. It is fixed here rather than recorded, because a
plant that cannot land is a guard that is not guarding.

### 11.6 Existing-service regression

`go test ./...` green throughout. No golden file was regenerated, no Kafka, PostgreSQL, Redis or
RabbitMQ rule, code or wiring changed, and the four existing composition roots are untouched.
`test/golden`, `test/harness`, `test/release` and `internal/render` are unchanged.

---

## 12. Known limitations

1. **A `401`, an unreachable API server and a `5xx` all exit 0** where every other service would
   report a credential rejection or a transport failure at ERROR. This is a
   **CONTRACT-CONFORMANT KNOWN LIMITATION and not an ADR deviation**: ADR 0094 §10.4 refuses a
   `401` a Kubernetes finding code deliberately, `DIAG_FAILURE_BOUNDARY` localizes it, and that
   boundary is INFO. The implementation does exactly what the frozen contract says. It is pinned
   by test and recorded in `docs/BACKLOG.md`. **Phase 12.1D should weigh it against a real
   cluster**, where ADR 0094 §7's fifth-code condition can be tested rather than argued.
2. **`svcdoctor diagnose kubernetes` is not added yet.** ADR 0094 §2.10 and §2.12,
   `PHASE121A…§12.1` and `§14` (KAC-040) all assign **the CLI case** to Phase 12.1C by name. The
   phase brief instructed *"No new CLI command. No new flags."* twice, and this tree follows the
   brief; on a source reconciliation the frozen contract wins, so the phase is **not
   contract-complete**. Every finding is fully reachable and tested through
   `svcdoctor run --config`, so nothing about F1–F4 depends on it. **Phase 12.1C.1 has since
   frozen the command's public surface** —
   `docs/validation/PHASE121C1_KUBERNETES_LEAF_CLI_CONTRACT_FREEZE.md`, ten flags, zero new
   decisions — and implementation is authorized. See §12.1.

### 12.1 What the leaf command needed decided — closed by Phase 12.1C.1

*(The three open decisions below were answered from source in
`docs/validation/PHASE121C1_KUBERNETES_LEAF_CLI_CONTRACT_FREEZE.md`: stdin is **REQUIRED** as
`--token-stdin`; **no** budget flag and **no** `--step-timeout`, because both would be inert; and
the command may exist while no Kubernetes distribution is graded. The analysis is kept as written
so the resolution is legible rather than invisible.)*

`internal/cli/kubernetes.go` would be a sibling of `rabbitmq.go` and would reuse
`app.InspectKubernetesTarget` and `app.DiagnoseKubernetes` unchanged: no second diagnosis engine,
no duplicated acquisition, no Kubernetes renderer logic and no new config or schema semantics.
Four of its flags follow the repository's existing mechanical convention — a fleet `yaml:` key in
snake_case becomes the same flag in kebab-case, as `sasl_mechanism` → `--sasl-mechanism` already
does — giving `--kubeconfig`, `--context`, `--in-cluster`, `--namespace`, `--service-name` from
`internal/fleet/services/kubernetes`'s five frozen fields, plus the shared `--timeout`,
`--output` and `--shareable`.

**Three things are genuinely open and are contract decisions, not naming preferences**, because
`TestTheLeafCommandFlagSurfacesAreUnchanged` and `rabbitmqFlags` treat a leaf flag set as frozen
released surface, and ADR 0060 established that changing one later is a released-behaviour change:

1. **Whether a stdin credential source exists.** The other four commands each expose
   `--password-file` **and** `--password-stdin`. `PHASE121A…§6.1` names `--token-file` alone.
   Adding `--token-stdin` invents a flag no source names; omitting it makes the fifth command
   asymmetric with the other four.
2. **Whether any budget flag exists.** The other four expose `--step-timeout`. ADR 0094 §2.5
   freezes the Kubernetes object budgets as constants, and the `diagnose rabbitmq` precedent
   refuses *"a knob for a frozen value"* — so the answer is probably none, but no source says so.
3. **The documentation surface.** `internal/cli/docsclaims_test.go` checks README and release
   claims against `docs/COMPATIBILITY.md`, which grades **no** Kubernetes distribution and is
   12.1D's to change. What a fifth documented command may claim before that grading exists is a
   release-surface question.

Adding the command is a small change once those three are answered. It was refused in 12.1C
because "implement exactly the frozen command" was not possible against sources that freeze one
flag of eight. **Phase 12.1C.1 answered all three and authorized implementation.**
3. **No real-cluster validation.** Everything here is hermetic. **Real-cluster diagnosis
   validation is deferred to Phase 12.1D**, and `docs/COMPATIBILITY.md` is unchanged and grades
   no Kubernetes distribution.
4. **The terminal renders a Kubernetes report through the zero `serviceView`** — no journey line,
   no outcome line. The findings block is service-neutral and correct; whether the journey reads
   well to an operator is a 12.1D question against real output.
5. **A count of `-1` is not producible and is not refused.** The rules require *exactly* zero, so
   a negative count withholds every claim, which is the safe direction. No validation rejects it,
   because no producer can emit it.

---

## 13. Counts after the phase

| | Before | After |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| Finding codes | 65 | **69** (`KUBERNETES` 0 → **4**; `DIAG` stays **1**) |
| Production rules | 22 | **24** |
| Failure classes | 42 | **42** |
| `RuleContext` fields | 3 | **3** |
| `Reveal` / `SecretFor` | 5 / 5 | **5 / 5** |
| External modules | 40 | **40** |
| Exit codes | 5 | **5** |
| `k8s.io` import paths | 10 | **10** |
| Kubernetes attributes | 17 | **17** |
| Kubernetes evidence nodes | 5 | **5** |
| Renderer files changed | — | **0** |
| Closed vocabularies gaining a member | — | **0** |

---

## 14. Next phase

**Phase 12.1D — Kubernetes deterministic real-cluster, mutation/fuzz and release-quality
validation closure.** `kind` fixtures, the four finding scenarios plus the three Service-shape
scenarios, the two-version matrix, and `docs/COMPATIBILITY.md` grading. F4's fixture is a
Deployment with at least one replica whose readiness probe always fails, so the controller
publishes slices with `ready: false`; F2 is proven three times, once per denied operation, each
asserting the corresponding universal finding is **absent**. No `sleep`.

12.1D should also weigh limitation 1 — the `401` exit code — against a real cluster, where the
shape is trivially reproducible, and decide whether ADR 0094 §7's fifth-code condition is met.
