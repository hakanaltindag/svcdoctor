# Phase 12.0 — Kubernetes diagnostic adapter: architecture, scope and epistemic-safety audit

- **Phase:** 12.0 — principal-level architecture, scope, authority and epistemic-safety audit.
  **No production Go code, no test, no config, no fixture, no dependency.**
- **Baseline:** `738ef3c43b7473bd952e9e852a2cc75d11891ee0`, `HEAD == origin/main`, tree clean
- **Record:** ADR 0093
- **Outcome:** **SELECT ARCH A** — Kubernetes is a normal service adapter, diagnosing Kubernetes
  objects themselves. **MVP-D**: one `namespace + Service` target, three object kinds, **four**
  finding codes, and Pod state as **observation only**. The next phase is a **contract freeze**,
  not implementation: two architecture blockers are unresolved and both are measured rather than
  suspected.

---

## 1. Baseline, as measured

Nothing below is inherited from a document. Every figure was re-measured at `738ef3c`.

| Fact | Value | How |
|---|---|---|
| `HEAD` / `origin/main` | `738ef3c` / `738ef3c` — **identical** | `git rev-parse` |
| working tree at start | **clean** | `git status --short` empty |
| Phase 11.0 committed | yes — `738ef3c` *"docs(diagnosis): defer diagnostic planning"* | `git log` |
| ADR 0092 committed | yes, in that commit | `git show --stat HEAD` |
| `make check` **before** editing | **exit 0** (fmt-check · test · vet · `golangci-lint` *0 issues* · build) | run |

### 1.1 Frozen counts and vocabularies

| Measurement | Value | How |
|---|---|---|
| `domain.SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `domain.RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| declared / attributed `FindingCode`s | **65 / 65** | `TestTheConvergenceInventoryIsComplete` |
| production diagnostic rules | **22** | same scan |
| `FailureClass` values | **42** | `internal/domain/failureclass.go` |
| `RuleContext` fields | **3** | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| external modules | **2** | `TestTheDependencyCountIsExact`; `go list -m all` |
| `go.sum` | **4 lines** | measured |
| `Reveal` / `SecretFor` production sites | **4 / 4** (one per service) | `TestRevealHasOneProductionCallSitePerService` |
| exit codes | **5** (`0`–`4`) | `docs/SCOPE.md` |
| service adapters | **4** — Kafka, PostgreSQL, Redis/Valkey, RabbitMQ/LavinMQ | `internal/adapter/*` |
| generic transport packages | **4** — `probe/dns`, `probe/tcp`, `probe/tls`, `probe/transport` | tree |
| **production binary** | **10,310,258 bytes**, **219 packages** | `CGO_ENABLED=0 go build ./cmd/svcdoctor` |
| **`os/exec` / `net/http` in the production binary** | **neither is linked** | `go list -deps ./cmd/svcdoctor` |

Rules and codes per package, from the scan's own output:

```
internal/diagnosis                1 rules,  1 codes
internal/diagnosis/transport      3 rules,  8 codes
internal/diagnosis/kafka          5 rules, 15 codes
internal/diagnosis/postgres       6 rules, 21 codes
internal/diagnosis/redis          4 rules,  9 codes
internal/diagnosis/rabbitmq       3 rules, 11 codes
attributed 65 of 65 declared finding codes
```

**Closed vocabularies.** `State`: `UNKNOWN` `PASS` `FAIL` `DEGRADED` `SKIPPED` (5).
`FindingKind`: `CONFIRMED` `HYPOTHESIS` (2). `Confidence`: `HIGH` `MEDIUM` `LOW` (3).
`RecommendationKind`: `NEXT_EVIDENCE` `REMEDIATION` (2 producible). `SafetyClass`: 7 defined,
**4 producible** — `OBSERVE` `VERIFY` `COMPARE` `CONFIG_CHANGE`; `RESTART`, `DISRUPTIVE` and
`SECURITY_WEAKENING` are unreachable by construction. `Layer`: `L0` input · `L1` dns · `L2` tcp ·
`L3` tls · `L4` protocol · `L5` auth · `L6` topology (7). `SubjectKind`: **`TARGET` and
`ENDPOINT` — two, and no more**. `AttrKind`: 9, including `AttrKindIdentity`, documented as
*"one value that names a principal, a tenant, or **a named resource**, and that is not a network
peer."*

### 1.2 The seams a Kubernetes adapter would have to fit

Measured, because the audit's whole question is whether Kubernetes fits them.

| Seam | What it is today | Kubernetes fit |
|---|---|---|
| **adapter registry** | `internal/cli/root.go:158` is an explicit five-case switch at one composition point; `internal/fleet/config.Registry` takes factories as arguments, refuses duplicates, has no `init()` and no reflection | **Fits.** One CLI case, one factory |
| **service config ownership** | `config.Factory` requires `Kind()`, **`DefaultPort() uint16`**, `Decode(node, Common)`; `NewRegistry` **rejects a zero default port**; `Common` carries `Host`, `Port`, `TLS`, `Credentials`, and `load.go:232` makes a host **required** | **Does not fit.** A Kubernetes target has no operator-declared host and no port. §11.4 |
| **report ownership** | `domain.Report` owns the canonical JSON; its summary is derived, never supplied; `internal/render/json` reimplements nothing | Fits |
| **graph ownership** | `GraphBuilder` → immutable `Graph`; **multi-parent DAG** (`AddParent` doc: *"A node may have several parents, which is what makes the structure a DAG rather than a tree"*), cycle-checked at insert and again at `Freeze` | **Fits, and this is the strongest single fit.** §16 |
| **subject identity** | `Subject{kind, ref}`; two kinds; `ref` validated only as non-empty, valid UTF-8, trimmed, control-character-free — **no length bound** | Fits with a stated convention. §14 |
| **endpoint identity** | `security.Endpoint{host, port}` — non-empty host, **non-zero port** | **Fits, and decides the credential model.** §9.3 |
| **evidence attributes** | `AttributeKey` is a validated dotted name; no central registry, by design; `AttrValue` is 9 closed kinds | Fits |
| **run incompleteness** | `Result.Incomplete()`, orthogonal to status, exit 4; `RuleContext.Incomplete` | **Fits, and it is what pagination needs.** §12 |
| **blocked nodes** | `Graph.BlockedBy`, `StateSkipped`; serialized as `blockedBy` | Fits |
| **canonical JSON** | `domain` owns it (ADR 0016); renderers derive | Fits |
| **renderer ownership** | `terminal.serviceView` is **a table, not a branch** — but it models a **linear per-path journey** (`journey []domain.Step`, `narrowingSteps`, one `advertisementStep`, `advertisedJourney`) plus `observations` and `notes` | **Partial fit.** §17.3 |
| **failure boundary** | `diagnosis.boundaryFor` groups by `Subject` and orders by **`Layer`**; last-good requires a node at a **strictly lower layer** | **Fits only if Kubernetes evidence uses distinct layers.** §15 |

---

## 2. Records read, and what was verified on the web

**Repository (SOURCE-PROVEN).** ADRs 0008–0017 (evidence, graph, report, rule contract), 0021
(connection ownership), 0028 / 0030 (endpoint-bound credentials), 0034, 0039 §17, 0040 §18/§20,
0041, 0043, 0044, 0048, 0050, 0052 §5, 0054, 0058, 0059, **0062** (OCI runtime and the Kubernetes
execution model), 0063 §11, 0066, 0067, 0069 §8, 0070, **0071**, **0072** (multi-target credential
references — §13 is decisive), 0073, 0074, 0075–0077, 0078–0083, 0084, 0085, 0086, 0087, 0088,
0089, 0090, 0091, **0092**. Documents: `docs/FINDINGS.md`, `docs/OUTPUT.md`, `docs/BACKLOG.md`,
`docs/SCOPE.md`, `docs/ARCHITECTURE.md` boundaries as quoted in `CLAUDE.md`, `README.md`,
`docs/QUICKSTART.md`, and the Phase 10.0 → 11.0 validation records.

**Kubernetes (WEB-VERIFIED).** Official `kubernetes.io` only; no blogs, no third-party sources.
Each claim below is used somewhere in this audit and each changed a conclusion.

| # | Claim | Source |
|---|---|---|
| W1 | `EndpointConditions.ready`: *"A nil value should be interpreted as **"true"**."* and *"an endpoint should be marked ready if it is serving and not terminating, though this can be overridden … such as when the associated Service has set the `publishNotReadyAddresses` flag."* | EndpointSlice v1 API reference |
| W2 | `EndpointConditions.serving`: *"the EndpointSlice controller will mark the endpoint as serving if the pod's Ready condition is True. A nil value should be interpreted as **"true"**."* | same |
| W3 | `EndpointConditions.terminating`: *"A nil value should be interpreted as **"false"**."* | same |
| W4 | `endpoint.addresses`: *"must contain at least one address but no more than **100**. EndpointSlices generated by the EndpointSlice controller will always have exactly 1 address."* | same |
| W5 | Slices are linked to a Service by the **`kubernetes.io/service-name` label** and by an owner reference | EndpointSlice concepts |
| W6 | *"The control plane automatically creates EndpointSlices for any Kubernetes Service **that has a selector specified**."* | same |
| W7 | **`endpointslice.kubernetes.io/managed-by`** identifies the managing entity; the controller sets `endpointslice-controller.k8s.io` | same |
| W8 | Default **100 endpoints per slice**, configurable up to **1000**; **multiple slices per Service are normal**; dual-stack yields **at least two** slices, one per IP family | same |
| W9 | *"Due to the nature of EndpointSlice changes, endpoints may be represented in **more than one EndpointSlice at the same time**."* | same |
| W10 | A Service **without a selector** gets **no automatic EndpointSlices**; endpoints are managed manually. A **headless** Service **with** a selector **does** get EndpointSlices | Service concepts |
| W11 | **ExternalName** *"does not use selectors or Endpoints/EndpointSlices"* | same |
| W12 | Pod phases are exactly `Pending` `Running` `Succeeded` `Failed` `Unknown`; **`CrashLoopBackOff` and `Terminating` are kubectl display values, not phases** | Pod lifecycle |
| W13 | Pod conditions: `PodScheduled`, `PodReadyToStartContainers`, `Initialized`, `ContainersReady`, `Ready`; **readiness gates make `Ready` depend on all gates, not only container readiness** | same |
| W14 | **`ContainerStateWaiting.reason` / `.message` and `ContainerStateTerminated.reason` / `.message` are free-form strings, not closed enumerations.** `OOMKilled`, `CrashLoopBackOff`, `ImagePullBackOff`, `Completed`, `Error` are conventions, not API contract | Pod v1 API reference |
| W15 | `PodStatus.phase` **is** a closed enumeration; `PodStatus.reason` / `.message` are free-form | same |
| W16 | A **sidecar** is an init container with `restartPolicy: Always`; default since **v1.29**, locked stable since **v1.33** | Sidecar containers |
| W17 | `DeploymentStatus.readyReplicas` = *"non-terminating pods … with a Ready Condition"*; `availableReplicas` = *"ready for at least `minReadySeconds`"*; `replicas` = *"non-terminating pods targeted … (labels match the selector)"*; `observedGeneration` = *"the generation observed by the deployment controller"* | Deployment v1 API reference |

**Two measurements, run outside the repository** (nothing in the tree was created or modified;
both temporary modules were deleted):

| # | Measurement | Result |
|---|---|---|
| M1 | `k8s.io/client-go` v0.37.0 + `apimachinery`, using `clientcmd` to load a kubeconfig and `Clientset` to `Get` a Service and `List` EndpointSlices | **47 module requirements** (2 direct, 45 indirect); **36,833,026-byte** binary; **`os/exec` is linked** and `k8s.io/client-go/plugin/pkg/client/auth/exec` is in the dependency graph |
| M2 | The same without `clientcmd` — `rest.Config` built explicitly from a server URL, a CA bundle and a bearer token | **46 module requirements**; **36,525,474-byte** binary; **`os/exec` is still linked**, and the exec auth plugin package is still present, reached from `rest`'s transport |

**M2 is the audit's sharpest result and it is stated plainly: avoiding `clientcmd` does not avoid
linking the exec credential machinery.** It is reachable from `rest` itself.

---

## 3. What a Kubernetes adapter is, frozen

> **A Kubernetes adapter exists to answer a small, fixed set of bounded operator questions from
> authoritative Kubernetes API objects, and to correlate those objects in ways a single `kubectl`
> command does not.**

It is **not**, and no phase may quietly make it: a `kubectl` wrapper · cluster inventory · a
health dashboard · node monitoring · an Event dump · a log collector · a metrics collector · a
policy engine · a topology explorer · a service-dependency mapper · a cluster doctor · a
configuration linter · a best-practice scanner · an agent, an operator, a controller or a CRD.

The last clause is not new. `docs/BACKLOG.md:3927` already says of the OCI phase: *"Not wanted in
this phase or the next: a Helm chart, an operator, a controller, a CRD, or any Kubernetes API
access from svcdoctor itself. svcdoctor is a bounded diagnostic worker that a platform invokes;
**it does not become an agent**."*

**Two Kubernetes shapes exist in this repository and they must never be conflated.**
`internal/platform/kubernetes/` — a directory holding only a `.gitkeep` — is reserved for
*environment context collection*, and `CLAUDE.md`'s platform boundary says that layer *"does not
produce diagnosis, contain adapter logic, or contain protocol semantics."* ADR 0012 reserves
*"Kubernetes pod / namespace / cluster"* as a future **vantage**. **This audit is about neither.**
A Kubernetes diagnostic adapter diagnoses Kubernetes objects; a Kubernetes platform probe
describes where svcdoctor is running. §10.2 keeps them apart.

---

## 4. The authority model

Every Kubernetes fact svcdoctor could record is **relayed by the API server**. What differs is
who *wrote* the field, and that decides the claim ceiling.

| Authority | What it means | Ceiling |
|---|---|---|
| `API_SERVER_REPORTED` | object state the API server itself owns: existence, `metadata`, `spec`, labels, `status.code`/`reason` on a `Status` response | **Strongest available.** `HIGH` on direct authority |
| `CONTROLLER_REPORTED` | a controller's `status` — `DeploymentStatus`, EndpointSlice contents | `HIGH` for *"the controller published X"*; never for *"X is true of the world"* — it is an eventually-consistent snapshot |
| `SCHEDULER_REPORTED` | `PodScheduled` condition, `spec.nodeName` | `HIGH` for the condition; the `reason`/`message` behind it is free text |
| `KUBELET_REPORTED` | `containerStatuses`, container `state`, `lastState`, `restartCount`, `ready`, `started` | **Relayed, not defined.** `reason` is free-form (W14) and produced by kubelet + the container runtime |
| `APPLICATION_REPORTED` | readiness/liveness results, surfaced only as `ready`/conditions | `HIGH` for the boolean; **never** identifies *which* probe failed |
| `CSI_REPORTED` | PVC/PV phase and binding | `HIGH` for the phase; nothing about the storage backend |
| `CNI_INFERRED` | **nothing.** No Kubernetes API object proves packet-path behaviour | **No claim, ever** |
| `OPERATOR_DECLARED` | expected replicas, selector, namespace, target identity — from `spec` or from the invocation | A premise, never an observation (ADR 0092 §2.5) |
| `DERIVED_CONTRAST` | svcdoctor comparing two authoritative objects | Only what the comparison states; **never a cause** |

**The rule that follows, and it is the whole authority model in one line:** *API object state
never becomes a hidden runtime cause.* `status` says **what the cluster recorded**. It does not
say why the system reached it, and for `KUBELET_REPORTED` fields it does not even say it in a
vocabulary the API defines.

---

## 5. Object-source inventory

Nineteen object kinds, each judged on whether it answers a bounded diagnostic question — never on
how commonly it appears in a troubleshooting guide.

| Object | Verdict | Why |
|---|---|---|
| **Service** | **REQUIRED_FIRST_SCOPE** | The target. Its `spec.selector`, `spec.ports`, `spec.type` and `spec.clusterIP` are `API_SERVER_REPORTED` and fully bounded |
| **EndpointSlice** | **REQUIRED_FIRST_SCOPE** | The only authoritative statement of what Kubernetes **publishes** as a backend. Verified semantics (W1–W9). This is where the value is |
| **Pod** | **REQUIRED_FIRST_SCOPE, observation-only** | Needed to answer *"does the selector match anything"*; its `Ready` condition and `phase` are closed vocabularies (W12, W13). **No Pod finding in first scope** — §8 |
| **Namespace** | REJECT_FIRST_SCOPE | A `NotFound` on the Service already distinguishes a wrong namespace, from one fewer API call |
| **Deployment / StatefulSet / DaemonSet** | **USEFUL_LATER** | `readyReplicas` versus `spec.replicas` is real (W17) but is one snapshot and largely a `kubectl get deploy` restatement. §8, K7 |
| **ReplicaSet** | USEFUL_LATER | Only needed to attribute Pods to a rollout generation. Not needed for a Service target |
| **ContainerStatus / InitContainerStatus** | **REJECT_FIRST_SCOPE as a finding source** | Every high-value fact keys on a **free-form** `reason` (W14). §7 |
| **PVC / PV** | **DEFER_SECOND_SCOPE** | `phase != Bound` is bounded and authoritative, but it belongs to a Pod-shaped target and adds a fourth object kind and a storage domain |
| **Node** | **REJECT_FIRST_SCOPE** | Cluster-wide fan-out, infrastructure-sensitive, and it answers no first-scope question. If ever needed, **only the single node a selected Pod is bound to**, by name, never a list |
| **Event** | **REJECT** | §9.1 |
| **NetworkPolicy** | **REJECT** | §9.4 |
| **Ingress / Gateway API** | REJECT_FIRST_SCOPE | Controller-specific, external routing, TLS, DNS and policy in one — a separate domain, not a scope extension |
| **ConfigMap** | **NEVER_COLLECT_BY_DEFAULT** | Contents are application configuration. Reading them makes svcdoctor a config-dump product |
| **Secret** | **NEVER_COLLECT_BY_DEFAULT, permanently** | §13.2 |
| **Job / CronJob** | REJECT_FIRST_SCOPE | Not a target kind. Their Pods may still be selected by a Service, which is why `Succeeded` must be handled safely — §8, K-J |
| **Endpoints (v1, legacy)** | **REJECT** | EndpointSlice supersedes it; reading both would create two truths for one fact |
| **HorizontalPodAutoscaler** | REJECT | Inventory |
| **PodDisruptionBudget** | REJECT | Policy, not state |
| **ServiceAccount** | REJECT | Identity inventory with no diagnostic question |

---

## 6. The finding that shapes everything: Kubernetes `reason` is free text

W14 is not a detail. It decides the MVP.

`ContainerStateWaiting.reason` and `ContainerStateTerminated.reason` are **free-form strings**.
`OOMKilled`, `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull`,
`CreateContainerConfigError`, `RunContainerError`, `Completed` and `Error` are **kubelet and
container-runtime conventions**, not API contract. `CrashLoopBackOff` is not even a Pod phase
(W12) — it is a `Waiting` reason that `kubectl` renders in the `STATUS` column.

Compare what this repository accepts elsewhere, because the comparison is exact:

| Service | Discriminating token | Who defines it |
|---|---|---|
| PostgreSQL | `SQLSTATE` (`53300`, `28000`, `3D000`) | **the protocol**, five characters, closed |
| Redis | error **prefix** (`NOAUTH`, `WRONGPASS`, `NOPERM`) | **the protocol**; ADR 0066 permits the prefix and **forbids the message** |
| RabbitMQ | `close_outcome`, one of seven **svcdoctor-owned literals** decided by construct-and-compare **byte equality** against sentences svcdoctor renders itself | **svcdoctor**, never a slice of the peer's buffer |
| Kubernetes | `status.containerStatuses[].state.waiting.reason` | **kubelet**, free-form by the API's own reference |

Kubernetes container `reason` is the **weakest** of the four. It is a token rather than a
sentence, which puts it above prose — but unlike a RESP prefix, no protocol document closes the
set.

**It is not unusable, and the repository already has the rule that makes it usable.** ADR 0069 §8's
`namedConditions` rule — *membership requires having watched a real endpoint produce it* — plus
exact-match against an svcdoctor-owned allowlist, with the claim scoped to *"Kubernetes reported
the reason as X"*, is admissible. But it lowers the value considerably, because that sentence is
what `kubectl get pods` already prints in one column.

**One Kubernetes reason vocabulary is genuinely closed and it is worth naming:
`metav1.StatusReason`** on an API `Status` response — `NotFound`, `Forbidden`, `Unauthorized`,
`Conflict`, `Timeout` — is an API-contract enumeration. That asymmetry is why §8's K1 and K2 are
admitted while K4, K5 and K6 are not.

**Frozen prohibition.** No substring match, no regexp, no fuzzy match, no raw interpolation, over:
`status.message` · `condition.message` · `Event.message` · `terminationMessage` ·
`ContainerState*.message` · image-pull error text · scheduler text · `Status.message` ·
`Status.details.causes[].message`. Reading a `reason` at all requires an exact-match allowlist
whose every member has been observed on a real cluster, and it is not authorized in first scope.

---

## 7. Pod, container and workload frontier — the detail behind the verdicts

### 7.1 Pod phase (W12)

| Phase | Authoritative fact | Safe claim | Unsafe claim |
|---|---|---|---|
| `Pending` | accepted, not all containers set up and ready — **includes both scheduling wait and image download** | *"Kubernetes reports this Pod as Pending"* | scheduler failure · resource shortage · PVC problem · image problem — the phase distinguishes **none** of them |
| `Running` | bound to a node, all containers created, at least one running or starting | *"…as Running"* | that the application works. `Running` and `Ready=false` coexist routinely |
| `Succeeded` | all containers terminated successfully, no restart | *"…as Succeeded"* | **that anything failed.** A Job Pod ends here by design |
| `Failed` | all terminated, at least one in failure, no automatic restart | *"…as Failed"* | why |
| `Unknown` | state could not be obtained, typically a node-communication error | *"…as Unknown"* | that the Pod or the node is down |

**`POD_PENDING` as a finding is rejected.** It restates one enum value that `kubectl get pods`
prints, and distinguishing its causes needs `PodScheduled`'s free-text `reason` or Events.

### 7.2 Pod conditions (W13)

`PodScheduled`, `PodReadyToStartContainers`, `Initialized`, `ContainersReady`, `Ready` — each is
`True`/`False`/`Unknown` with a `reason` and a `message`. The booleans are safe; the strings are
not.

**The `Ready` trap, and it is a real one.** Readiness gates make `Ready` depend on all gates, not
only on containers. So **`ContainersReady=True` with `Ready=False` is legitimate**, and inferring
a container problem from `Ready=False` would be wrong. First scope reads `Ready` and
`ContainersReady` **as distinct facts** and infers neither from the other.

### 7.3 Container state, and K4/K5/K6

- **OOMKilled (K4).** The bounded fact is *"Kubernetes reported the **previous** container
  termination reason as OOMKilled"* — `lastState.terminated.reason`, plus `exitCode` and
  `restartCount`. Forbidden: *the memory limit is too low* · *the node ran out of memory* · *a
  memory leak* · *the kernel killed it because of a cgroup limit*. All four are causes the API
  does not report. And the honest fact is **historical**: the current container may be healthy.
  It fails first scope on W14, not on value.
- **CrashLoopBackOff (K5).** It is a `Waiting` **reason**, not a state and not a phase (W12) — a
  representation of the kubelet's exponential restart backoff. Whether it can appear after a
  single failure is a kubelet-timing question this audit did **not** verify, so the strongest safe
  claim is *"Kubernetes currently reports the container as waiting, with reason
  `CrashLoopBackOff`, and a restart count of N"* — never *"the application is crashing
  repeatedly"*, which asserts a rate.
- **Image pull (K6).** `ErrImagePull` and `ImagePullBackOff` do **not** distinguish image-not-found
  from registry authentication from DNS from rate limiting from TLS from a typo. Every one of
  those distinctions lives in the free-text `message`. The only safe claim — *"Kubernetes reports
  an image-pull failure"* — is one column of `kubectl get pods`.
- **restartCount (K-RC).** An integer with no time base. `restartCount > 0` does not prove
  instability, and it resets on Pod replacement. **Observation only, never a rate**, and never
  the words *storm*, *loop*, *flapping*, *repeatedly* or *unstable* (ADR 0092's time-series limit
  applied here).
- **exit code / signal (K-EC).** Safe facts, application-specific meaning. Observation only; no
  exit-code-specific diagnosis.

### 7.4 Init containers and sidecars

A Pod can be blocked before any application container starts, so ignoring init containers would
produce misleading Pod-level diagnoses — which is an argument **for** a Pod scope, not for a
finding on a free-text reason.

**Sidecars complicate it structurally** (W16): a sidecar is an init container with
`restartPolicy: Always`, default since v1.29 and locked stable since v1.33. So
`initContainerStatuses` holds both one-shot init containers and long-running sidecars, and
**"an init container is still running" is normal**, not a fault. Any future init-container scope
must read `spec.initContainers[].restartPolicy` before interpreting `initContainerStatuses`, and a
version below 1.29 has no such field. **Deferred, with that requirement written down.**

### 7.5 Workload replica contrast (K7)

W17 settles which field to use. `spec.replicas` is desired; **`status.readyReplicas`** counts
non-terminating Pods with a `Ready` condition; `availableReplicas` additionally requires
`minReadySeconds`, which makes a deficit against it a **configured delay** rather than a problem.
So a ready-replica deficit reads `spec.replicas` vs `status.readyReplicas` and never
`availableReplicas`.

`observedGeneration` versus `metadata.generation` is the staleness guard, and any future replica
finding **must** require them equal — otherwise it compares a new spec against an old status.

**Deferred anyway.** *"Desired 3, ready 1"* is the first line of `kubectl get deploy`. And the
word the operator wants — *stuck* — is unavailable: one snapshot cannot distinguish a rollout in
progress from a rollout that has stopped. `Progressing`/`ProgressDeadlineExceeded` could, but it
arrives as a condition `reason` beside a free-text `message`, and admitting it needs its own
measurement.

---

## 8. The candidate finding matrix

Thirteen candidates from the brief, plus five the audit added. **`RAW_STATUS_RESTATEMENT`** is the
verdict for a candidate whose whole content is one field `kubectl` already prints.

| # | Candidate | Direct evidence | Safe claim | Unsafe claim | Value vs kubectl | Verdict |
|---|---|---|---|---|---|---|
| **K1** | target not found | `Status.code 404` + `reason: NotFound` — an **API-contract enum** | *"No Service named X exists in namespace Y at this observation"* | that the workload is broken | **High.** A wrong namespace is the commonest incident-tooling mistake, and it is otherwise an empty `kubectl get` | **ADMIT_FIRST_SCOPE** |
| **K2** | API authorization denied | `Status.code 403` + `reason: Forbidden` | *"This credential was not permitted to read X; that measurement was not made"* | that the object does not exist, or that the target failed | **High.** It is the difference between *nothing there* and *you could not look*, and it must never read as the former | **ADMIT_FIRST_SCOPE** |
| **K8** | Service selector matches zero Pods | `spec.selector` + a **complete** label-scoped Pod list | *"This Service's selector currently matches no Pod in its namespace"* | that the workload is down; that the selector is wrong | **High.** The operator must otherwise hand-translate the selector into a `-l` query | **ADMIT_FIRST_SCOPE** |
| **K10** | Service publishes zero ready endpoints | a **complete** EndpointSlice set for the Service, with W1–W3 nil semantics | *"Kubernetes currently publishes no ready endpoint for this Service"* | that clients cannot reach it; that Pods are unhealthy; that the endpoint controller is broken | **Highest in the audit.** §17.1 | **ADMIT_FIRST_SCOPE** |
| **K9** | Service has zero EndpointSlices | complete list by `kubernetes.io/service-name` | — | — | **Subsumed by K10.** Zero slices and zero ready endpoints are one condition for a selector-backed Service, and two codes would publish two findings for one fact | **REJECT_LOW_VALUE** |
| **K11** | selected Pod absent from any EndpointSlice | Pod `Ready=True` + `targetRef` membership across a complete slice set | *"A Pod the selector matches and Kubernetes reports Ready is not present in any published EndpointSlice"* | that the endpoint controller is broken | Real, and genuinely invisible to `kubectl` | **DEFER_SECOND_SCOPE.** §17.2 |
| **K12** | named `targetPort` unresolved | `spec.ports[].targetPort` (string) + `spec.containers[].ports[].name` | *"No selected Pod declares a container port named X"* | **that the application is not listening** | Moderate | **REJECT_FALSE_POSITIVE.** §17.4 |
| **K7** | workload ready-replica deficit | `spec.replicas` vs `status.readyReplicas`, gated on `observedGeneration` | *"Fewer Pods currently report Ready than the workload declares"* | *stuck* · *unhealthy* · *rollout failed* | Low — it is `kubectl get deploy`'s first line | **DEFER_SECOND_SCOPE** |
| **K2b** | Pod not scheduled | `PodScheduled=False` | *"Kubernetes reports this Pod as not scheduled to a node"* | insufficient CPU · taint · affinity · topology — all live in a free-text `message` | Low | **REJECT_RAW_STATUS_RESTATEMENT** |
| **K3** | init container blocking startup | `initContainerStatuses` | — | — | Needs `restartPolicy` per init container to avoid calling a running sidecar a fault (W16), and its specific value lives in a free-text `reason` | **DEFER_ARCHITECTURE** |
| **K4** | previous termination OOMKilled | `lastState.terminated.reason` | *"Kubernetes reported the previous container termination reason as OOMKilled"* | memory limit too low · node OOM · a leak · the kernel · *that anything is wrong now* | Moderate, and historical | **DEFER_SECOND_SCOPE** — free-form `reason` (W14) needs an allowlist with live-measured membership |
| **K5** | CrashLoopBackOff | `state.waiting.reason` + `restartCount` | *"currently waiting, reason CrashLoopBackOff, restart count N"* | *crashing repeatedly* · any rate | Low — `kubectl get pods` prints it | **REJECT_RAW_STATUS_RESTATEMENT** |
| **K6** | image pull failure/backoff | `state.waiting.reason` | *"Kubernetes reports an image-pull failure"* | which of the six causes | Low, and the specificity is all in free text | **REJECT_RAW_STATUS_RESTATEMENT** |
| **K13** | referenced PVC not Bound | `spec.volumes` + `PersistentVolumeClaim.status.phase` | *"A claim this Pod references is not currently Bound"* | any CSI, storage-network or cloud-volume cause | Moderate | **DEFER_SECOND_SCOPE** — a fourth object kind and a Pod-shaped target |
| **K-PR** | Pod not ready | `Ready` condition | *"Kubernetes reports this Pod as not Ready"* | which probe · which container (readiness gates, §7.2) | Low as a finding; **useful as an observation** | **REJECT_RAW_STATUS_RESTATEMENT**, admitted as an observation |
| **K-J** | Pod `Succeeded` selected by a Service | `phase` | nothing | **"the container is not running"** — a completed Job Pod is not a fault | — | **Not a finding, and a required suppression**: `Succeeded` and `Failed` Pods are excluded from K8's *"matches no Pod"* denominator only if the audit's successor proves the semantics; first scope counts them and says so |
| **K-TERM** | terminating Pod | `metadata.deletionTimestamp` | *"this Pod is terminating"* | a new failure | — | **Observation only**, and an exclusion K10 and K8 must both respect |
| **K-NP** | NetworkPolicy blocks traffic | — | — | everything | — | **REJECT_UNSAFE.** §9.4 |

**Admitted: 4. Deferred: 5. Rejected: 9.**

---

## 9. The scope traps, decided

### 9.1 Events — **OUT**

Advantages are real: Events carry the specificity every rejected candidate above is missing.
Every one of the costs is disqualifying for a first scope, and together they are conclusive.
Unbounded cardinality; a **retention window that varies by cluster** so absence proves nothing;
aggregation that collapses distinct occurrences; **free-text `message` as the entire payload**;
controller- and runtime-version-dependent `reason` strings; identifiers and occasionally secrets
in messages; ambiguous ordering; and a listing surface that turns a bounded read into a
monitoring query. **An Event is not authority: it is one component's account of something,
retained for a while.** `EXPLICIT_OPT_IN_LATER` at best, and only with its own record.

### 9.2 Logs — **OUT, and frozen**

Unbounded; application-specific; routinely carry secrets, tokens and personal data; require
semantic interpretation that is not protocol-authoritative; and need `pods/log`, a distinct RBAC
verb operators deliberately restrict. Reading logs turns svcdoctor into a log-analysis tool. This
is a decision, not a deferral.

### 9.3 Metrics — **OUT**

metrics-server, Prometheus, kubelet metrics and cAdvisor are each a second system with its own
availability, auth and semantics. And **a measured historical fact does not need current
metrics**: *"the previous termination reason was OOMKilled"* is complete without a memory graph.

### 9.4 NetworkPolicy — **OUT, and the strongest refusal in the audit**

svcdoctor **cannot** determine *"NetworkPolicy blocks this traffic"* from API objects. The
evaluation is the union of every policy selecting the Pod, in both directions, across namespace
selectors, pod selectors, `ipBlock`, named ports and CIDR exceptions; default-deny only applies
once a Pod is selected at all; **enforcement is the CNI's**, and Cilium, Calico and others add
their own CRDs with their own semantics; `hostNetwork` changes the subject; Service routing
happens in kube-proxy or eBPF; a mesh may intercept before any of it applies.

Even the weakest statement — *"policies selecting this Pod exist"* — is **not** *"traffic is
blocked"*, and publishing it next to a connectivity problem invites exactly that reading.
**No policy solver, in this phase or any first scope.** `test/diagnosis/falsepositive_test.go`
FP01A already bans `network policy` and `networkpolicy` from **every part of the document**, and
ADR 0092 §2.4 froze the vantage ceiling that makes the ban principled rather than a word filter.

### 9.5 CNI internals and eBPF — **OUT**

Cilium agents, Hubble, eBPF, Calico internals, conntrack, iptables, nftables, CNI plugin state.
The first adapter must work against a **vanilla API boundary**. These may one day be optional
evidence providers; none may ever be required.

### 9.6 Service mesh — **OUT**

Istio, Linkerd, Envoy sidecars, Ambient, Gateway API. **A sidecar's presence is not a mesh
diagnosis**, and an annotation is not evidence of behaviour.

### 9.7 Ingress and Gateway API — **OUT of first scope**

Controller-specific behaviour, external routing, TLS termination, DNS and policy in one object
graph. A separate domain, not an extension of backend publication.

### 9.8 Active probing of Pods and Services — **OUT, and it is a security boundary**

svcdoctor must not connect to a Pod IP, a ClusterIP, a Service DNS name or an endpoint address in
first scope. Three independent reasons, and the first is decisive:

1. **The Kubernetes API credential authorizes the API server and nothing else.** §11.2.
2. The vantage may not reach ClusterIP space at all; a run outside the cluster would report
   *unreachable* for something working perfectly.
3. ADR 0050's rule already governs it: **discovery may create evidence; discovery must not create
   secret authority.**

---

## 10. Architecture

### 10.1 The three options

| | **ARCH A — a normal service adapter** | **ARCH B — a generic infrastructure domain** | **ARCH C — a discovery wrapper** |
|---|---|---|---|
| shape | target → `adapter/kubernetes` → evidence graph → `diagnosis/kubernetes` → report | a platform/infrastructure probe layer that later feeds several service adapters | Kubernetes finds endpoints; existing adapters diagnose them |
| invariant fit | **exact.** Probes collect, the adapter understands the API, diagnosis correlates, renderers explain | strained: it would produce *context*, and `CLAUDE.md` says the platform layer *"does not produce diagnosis"* | inverted: Kubernetes becomes a **transport for other adapters**, not a thing diagnosed |
| credential authority | one API-server-bound credential, cleanly | same | **immediately hazardous**: it manufactures endpoints that some other credential must reach, which is ADR 0050's exact prohibition |
| graph model | one DAG per target, owned by the adapter | unclear ownership | two graphs, or one graph with two authorities |
| multi-target semantics | one target, one report — unchanged | unchanged | **one target expanding into N service diagnoses**, which is fleet behaviour inside a target |
| future composition | ARCH C becomes reachable later, explicitly and with consent | possible | it *is* the composition, taken first |
| implementation size | one adapter, one diagnosis package, one CLI case | a new layer | the largest, and it needs a credential-binding language first |
| cross-target causality risk | none | none | **high** |
| report ownership | `domain.Report`, unchanged | unclear | ambiguous: whose report is it? |

**ARCH A is selected.** It is the only option that leaves every existing invariant exactly where
it is, and it is the only one whose first version can be small.

**ARCH B is not rejected — it is a different thing that also exists.** `internal/platform/kubernetes`
stays reserved for environment context feeding `domain.Vantage` (ADR 0012). It produces no
diagnosis and is not this adapter.

**ARCH C is deferred, not refused.** It is the genuinely valuable end state — *Kubernetes finds
the Kafka brokers, the Kafka adapter diagnoses them* — and it is unreachable until an operator can
**declare** a binding between a discovered Service and a credential source, because
ADR 0028/0030/0050 forbid inheritance. Architecture pressure, recorded in §19.

### 10.2 Package ownership, following the existing pattern exactly

| Package | Owns |
|---|---|
| `internal/service/kubernetes` | the normalized vocabulary — steps, attribute keys, closed value sets. A **leaf**, importable by diagnosis and by the renderer, exactly as the four existing service vocabularies are |
| `internal/adapter/kubernetes` | Kubernetes object semantics; turns API objects into `domain.Evidence`; builds the graph |
| `internal/adapter/kubernetes/client` | the **only** package that imports the Kubernetes client library, mirroring the four `wire` packages |
| `internal/diagnosis/kubernetes` | the rules |
| `internal/app` | one composition entry point, one `RuleSet` |
| `internal/cli` | one `case "kubernetes":` |

**No client library type may cross the adapter boundary.** ADR 0010 already forbids it, and the
existing `wire` boundary is the precedent: raw protocol objects stop there.

### 10.3 API transport — **MODEL A**, and duplicate truth is the reason

- **MODEL B** (generic probes dial the API server, then the client connects) produces DNS/TCP/TLS
  evidence about a connection **the Kubernetes client will not use**, because it dials its own.
- **MODEL C** records both and publishes two accounts of one connection.
- **MODEL A** — the client library owns transport, and svcdoctor records **one** `kubernetes.api`
  evidence node with a normalized failure class.

**MODEL A is selected, and the reason is ADR 0058.** Trust answers *whose certificate is this*,
and only the component that performed a handshake may say what it proved — the same rule
`forbidigo` enforces on `security.ChannelTLS*`. If the client library performs the handshake,
svcdoctor must not publish a `tls.handshake` node implying its own probe did. **Missing transport
detail is better than duplicated transport truth.**

The cost is stated rather than hidden: a first-scope Kubernetes run yields **no per-address
DNS/TCP/TLS evidence for the API server**, so a control-plane connectivity problem surfaces as one
classified API-access failure rather than as a transport journey. That is a real reduction in
resolution and it is the price of not lying about who measured what.

### 10.4 Client library — **client-go, and the cost is measured, not estimated**

Raw REST is refused for the reason §54 anticipates: it re-creates kubeconfig parsing, TLS
configuration, auth providers, pagination and API decoding — badly, and in the package that talks
to a control plane. "Lightweight" is not a security argument.

The cost, from M1/M2:

| | today | with client-go |
|---|---|---|
| module requirements | **2** | **46–47** |
| `go.sum` | 4 lines | hundreds |
| binary | **10.3 MB** | sample **36.5–36.8 MB** |
| `os/exec` linked | **no** | **yes** |
| `net/http` linked | **no** | yes |

**This is the largest single change to the project's supply-chain posture ever proposed**, and
`TestTheDependencyCountIsExact` exists precisely to force someone to record it. It is not a
blocker — the number is a consequence of correctness, not of carelessness — but it is a decision
for 12.1A with a stated alternative: **restrict the import surface to typed `CoreV1` and
`DiscoveryV1` clients plus `rest`**, and pin the Kubernetes minor explicitly.

---

## 11. Access, credentials and RBAC

### 11.1 The exec-auth blocker — measured, and it is the phase's hardest finding

`ADR 0072 §13` lists an `exec:` / command provider among sources that are not in v1:

> *"Arbitrary code execution driven by a config file. It is the single largest surface any of
> these would add"* — reopen condition: **"None. This is a decision, not a deferral."**

A kubeconfig with an `exec:` credential plugin is **precisely that shape**: a config file that
causes svcdoctor to run a local program. And EKS, GKE and AKS all use exec plugins in their
generated kubeconfigs by default.

Two guards already encode the rule as tests: `test/security/fleet_boundary_test.go` bans `os/exec`
with *"there is no exec credential provider (ADR 0072 §13)"*, and
`test/security/diagnosticcore_test.go` with *"diagnosis must not run commands"*. `internal/cli`
denies `os/exec` through depguard with *"the command runs no subprocesses"*. **No production file
imports it.**

**M2 is what makes this a blocker rather than a choice.** Avoiding `clientcmd` does **not** avoid
linking the exec machinery: `k8s.io/client-go/plugin/pkg/client/auth/exec` and `os/exec` are
reachable from `rest` itself. So *"refuse exec by not linking it"* is **not available**. The
guarantee can only be behavioural — never populate `ExecProvider`, and refuse a kubeconfig
carrying an `exec:` stanza at parse time — enforced by a guard test that svcdoctor never
constructs one, in the shape `forbidigo` already uses for `security.Reveal`.

Four options for 12.1A, with this audit's reading:

| | Option | Assessment |
|---|---|---|
| **A** | support exec as client-go does | **Contradicts ADR 0072 §13 directly.** Requires reopening a decision whose reopen condition is *"None"* |
| **B** | refuse `exec:` stanzas | Safe, predictable, and **loses the default kubeconfig of every managed cloud cluster** |
| **C** | explicit flag or consent | Preserves cloud usability at the cost of a flag whose meaning is *"run a program named by a file"* |
| **D** | external credential materialization — the operator supplies a token by `env` or `file`, and a CA bundle | **Compatible with ADR 0072 §13 unchanged**, because `env` and `file` are exactly the two sources §2 already supports. It is also the **in-cluster** shape |

**This audit recommends B+D for the first scope and marks A/C an explicit architecture blocker for
Phase 12.1A.** It does not decide it, because §117 says not to accept process execution silently
and because reopening ADR 0072 §13 needs its own security review.

### 11.2 Credential authority — the existing model already answers it

The Kubernetes API server has a host and a port, so a Kubernetes credential binds to a
`security.Endpoint` exactly as the four existing services' credentials do. That makes the rule
**structural rather than a policy somebody must remember**:

> **A Kubernetes API credential is bound to the API server endpoint. No Pod IP, ClusterIP,
> Service DNS name or endpoint address is that endpoint, so ADR 0028's binding check refuses it
> there without any new rule.**

**Kubernetes credentials never flow to discovered endpoints. This is not negotiable and needs no
new mechanism.**

### 11.3 In-cluster authentication, kubeconfig and proxies

**In-cluster** — the projected ServiceAccount token, the CA bundle and
`KUBERNETES_SERVICE_HOST`/`PORT` — is the cleanest path and needs no exec. **It must be selected
explicitly, never fallen back to**: silently using an ambient identity because a token file
happens to be mounted is precisely the hidden authority escalation the credential model exists to
prevent.

**This reverses a published, validated contract, and the reversal must be explicit.** ADR 0062 §9
states: *"**No Kubernetes API access.** svcdoctor never calls the API, so it needs no
ServiceAccount permissions, no Role and no RoleBinding, and the examples set
`automountServiceAccountToken: false`. Verified: the running pod had **no service-account token
volume at all**. A platform that creates these Jobs needs API permissions; svcdoctor does not
inherit them."* A Kubernetes adapter makes that false for one command. **ADR 0093 supersedes
ADR 0062 §9's no-API-access clause in part**, and `examples/kubernetes/` would gain a second,
clearly separate manifest with a `Role` and a `RoleBinding` — never a change to the existing one.

**Kubeconfig.** First scope should support an **explicit path only**, not `KUBECONFIG` merge-list
resolution: an incident tool that silently merges several files and picks a current context from
one of them is unpredictable at the worst moment. `token`, `tokenFile`, `client-key`,
`client-key-data`, `certificate-authority-data`, `auth-provider`, `proxy-url` and impersonation
each need an individual decision in 12.1A.

**Impersonation** (`as`, `as-groups`, `as-uid`) — **refuse in first scope.** It requests that the
API server act as a different principal, and a diagnostic tool that silently impersonates is
indefensible.

**Proxies.** `HTTP_PROXY`/`HTTPS_PROXY` and kubeconfig `proxy-url` change network authority and
vantage. svcdoctor has no proxy model today — no production file imports `net/http`. **If a proxy
is in effect it must be reported, never silently inherited.** Recorded as compatibility pressure.

### 11.4 The fleet-configuration mismatch

`config.Factory` requires `DefaultPort() uint16`, `NewRegistry` rejects a zero default port, and
`load.go:232` makes `host` required. **A Kubernetes target has neither in the operator's sense.**

**First scope is therefore a leaf CLI command only** — `svcdoctor diagnose kubernetes` — and is
**not registered with the fleet**. That is a real asymmetry and it is recorded rather than
papered over: closing it means either giving `Factory` a way to say *"this service is not
endpoint-shaped"* or deriving `Host`/`Port` from the resolved API server, and both are 12.1A
questions. Precedent supports the sequencing: Redis and RabbitMQ each shipped as leaf commands
before `run --config` existed.

### 11.5 Minimum RBAC for MVP-D

| API group | Resource | Verbs | Scope |
|---|---|---|---|
| `""` (core) | `services` | `get` | **namespaced** |
| `""` (core) | `pods` | `list` | **namespaced** |
| `discovery.k8s.io` | `endpointslices` | `list` | **namespaced** |

Three resources, two verbs, **one namespace**. No `watch`, `create`, `patch`, `update`, `delete`,
`exec`, `attach`, `portforward` or `pods/log`. **No cluster-scoped permission, and no
cluster-admin assumption.**

`list` is required rather than `get` for Pods and EndpointSlices, because the question is *which
objects match this selector* and a label-scoped list **is still `list`** from RBAC's point of
view. That is stated because it is the one place an operator may expect a narrower grant than the
one they must give.

---

## 12. Bounds, pagination, completeness and consistency

### 12.1 Fan-out ceilings, defensible rather than round

| Bound | Proposed ceiling | Derivation |
|---|---|---|
| namespaces per target | **1** | the target names one |
| Services per target | **1** | the target names one |
| Pods enumerated | **500** | above a namespace's realistic selector match for one Service, and a bounded page count at 100 per page |
| EndpointSlices enumerated | **64** | at the default 100 endpoints per slice (W8) that covers 6,400 endpoints; dual-stack doubles slices (W8), so the ceiling must not be small |
| endpoints enumerated | **5,000** | each slice holds ≤100 by default and ≤1000 configured (W4, W8) |
| total objects | **600** | Service + Pods + slices, one budget a reader can check |
| API calls | **3–8** | §12.5 |

These are proposals for 12.1A to confirm against a real cluster, not frozen numbers.

### 12.2 Pagination

A single `List` **does not** return all objects. First scope must send `limit`, follow `continue`
until exhausted **or** the object budget is reached, and **never** silently stop.

### 12.3 Completeness — the strongest freeze in this audit

> **Reaching an object budget or a pagination limit MUST NOT become "no Pods found" or "no ready
> endpoints". It becomes an incomplete enumeration**, `Result.Incomplete()`, exit code 4, and the
> universal claim is withheld.

This is the Kafka Phase 10.2 rule applied unchanged: *three categories, never two.* An object that
was not enumerated is not an object that is absent. Both admitted set-claims — K8's *"matches no
Pod"* and K10's *"no ready endpoint"* — are **universal quantifications** and each **requires a
proven-complete enumeration** as a precondition, exactly as
`KAFKA_ADVERTISED_TOPOLOGY_REACHABILITY` and `POSTGRES_ADMISSION_SCOPE` do.

### 12.4 Snapshot semantics and eventual consistency

**Kubernetes reads across several objects are not a transactional snapshot.** Reading a Service,
then Pods, then EndpointSlices samples three moments, and between them a rollout can replace a
Pod, a readiness transition can land, or the EndpointSlice controller can lag.

**Frozen claim language:** every set claim is scoped *"at the time of these API observations"*.
`resourceVersion` is **not** used for consistency in first scope: it would imply a guarantee
Kubernetes does not offer across resource kinds, and a stale-read retry loop is a mechanism a
first scope does not need.

Classification of the contrasts:

| Contrast | Class |
|---|---|
| Service has a selector and no Pod matches it | **CONFIRMED FACT** — one object's selector against a complete list |
| Zero ready endpoints published | **CONFIRMED FACT** — the slices say so directly; it is not a contrast at all |
| Pod `Ready=True` but absent from every slice | **TRANSIENT CONTRAST** — controller lag is normal. §17.2 |
| Deployment desired > ready | **TRANSIENT CONTRAST** during a rollout |
| Terminating Pod still referenced by an endpoint | **NOT A FINDING** — it is the documented graceful-termination path (W3) |

**Controller lag is never called misconfiguration.**

### 12.5 API call budget

`get service` (1) · `list pods` by selector (1, + up to ~5 pages at the ceiling) · `list
endpointslices` by `kubernetes.io/service-name` (1, + pages). **Three calls in the common case,
under ten at the ceiling.** Incident-friendly, and not API-server-abusive even across a fleet.

---

## 13. Identity, privacy and prohibited data

### 13.1 Subject and cluster identity

**Subject.** `SubjectKind` has two values and **no third is proposed**. A Kubernetes object is not
a network endpoint, so it takes `SubjectKindTarget` with a **deterministic, namespace- and
kind-qualified reference**, in a stable convention rather than a frozen URI grammar:

```
<kind>/<namespace>/<name>          e.g.  service/payments/api
```

Requirements: deterministic; stable within a report; namespace-aware; kind-aware; no ambiguous
bare names; bounded (Kubernetes names are ≤253 bytes and `Subject.ref` has no length bound of its
own, so **the adapter must impose one**); and redaction-aware.

**UID does not participate in the subject.** Names can be reused, which is the argument for UID,
but a UID is a high-entropy identifier with no operator meaning that would appear in every
shareable report. `metadata.uid` belongs in **internal correlation** — proving that two reads saw
the same object — and `metadata.generation`/`observedGeneration` in **staleness checks**;
`resourceVersion` reaches evidence in neither role.

**Cluster identity.** The report needs one, and none of the candidates is both authoritative and
safe. A kubeconfig **context name** is operator-local and not cluster identity. The **API server
URL** may disclose internal topology. The `kube-system` namespace UID is a common convention but
requires an extra read and an extra RBAC grant. **First scope: the operator's declared target
identifier is canonical, and the context name is displayed as what it is — a local label.**
**No API call is made merely to derive a prettier identifier.**

### 13.2 Data that is never collected

**Secrets — never read, and not even by metadata.** No `get`, no `list`, no watch. Not in first
scope, not later without its own record. **ConfigMap contents likewise.** svcdoctor is not a
config-dump product.

**Annotations — not collected.** Unbounded, vendor-specific and routinely used to carry
configuration and identity. A future feature needing one admits that one annotation explicitly.
**No annotation dump.**

**Labels — matched, never dumped.** Labels are used only for exact Kubernetes selector semantics.
The canonical evidence records `matched: true/false` and the **count**, not the label set.

**Container `image` and `imageID`, `containerID`, Pod IP, ClusterIP — not in canonical evidence in
first scope.** Image names carry private registry paths; container and image IDs are noise; Pod IPs
are ephemeral **and correlation is available authoritatively through `targetRef`**, which is
better evidence and less sensitive.

### 13.3 Redaction

**Every Kubernetes name that reaches evidence is `AttrKindIdentity`** — the kind's own doc comment
already covers *"a named resource"* — so structural redaction, which dispatches on `AttrKind` and
never on a key, transforms it without any new mechanism. Namespaces, Service names, Pod names and
node names are all identity. Endpoint addresses are `AttrKindHost`. **Nothing relies on
terminal-only masking**, and the shareable projection must keep the correlation while removing the
identity, exactly as ADR 0018 requires.

### 13.4 Dual-stack

W8: a dual-stack Service has **at least two** EndpointSlices, one per family, and W9 says an
endpoint may appear in more than one slice simultaneously. **Counting must deduplicate by
`targetRef` (preferred) or by `(addressType, address)`**, or a dual-stack Service will report
double the backends it has. This is a required property test, not an implementation detail.

---

## 14. Service-type behaviour, decided

| Type | First-scope behaviour |
|---|---|
| **ClusterIP with a selector** | **Supported.** The primary case |
| **Headless (`clusterIP: None`) with a selector** | **Supported.** W10: EndpointSlices are still created. Absence of a ClusterIP is **not** a failure and must never be reported as one |
| **Selector-less (any type)** | **Observation only.** W10: no automatic slices; endpoints are managed manually or by a third party. `KUBERNETES_SERVICE_SELECTS_NO_PODS` **must be structurally unreachable** here — a permanent property test |
| **ExternalName** | **Unsupported, reported as such.** W11: no selectors, no endpoints. Missing EndpointSlices are correct, not a fault |
| **NodePort / LoadBalancer** | Backend semantics apply unchanged; **no node-level reachability and no `status.loadBalancer` diagnosis.** Cloud load-balancer state is a different domain |
| **`sessionAffinity`, `internalTrafficPolicy`, `externalTrafficPolicy`, topology hints** | **Not modelled**, and §17.1's wording is what makes that safe |

---

## 15. Fit with the existing report, graph, boundary and renderer

**Schema: no change. `SchemaVersion` stays 1.** Every first-scope fact fits `Evidence`
(ID, Subject, Layer, Step, State, FailureClass, Attributes, StartedAt, Elapsed), `Graph`,
`Finding` and `Report` as they are. The requirement is **aggressive normalization**: closed value
sets and counts, never a JSON blob and never a Kubernetes struct.

**Layer mapping, and it is what keeps the failure boundary meaningful.** `boundaryFor` groups by
`Subject` and requires the last-good node to sit at a **strictly lower `Layer`**, so Kubernetes
evidence must occupy distinct layers or the boundary is vacuous:

| Layer | Kubernetes step |
|---|---|
| `L0` input | `target.requested` — the declared namespace + Service |
| `L5` auth | `kubernetes.api_access` — authentication and authorization against the API server |
| `L4` protocol | `kubernetes.service` — the Service object was retrieved |
| `L6` topology | `kubernetes.selected_pods`, `kubernetes.endpoint_publication` — **backend discovery, which is exactly what L6 is for** |

`L5` before `L4` is deliberate and matches the graph rather than the enum's numbering: an API
credential is evaluated before any object is served. The boundary reads layers per subject, so the
ordering that matters is the one the nodes declare.

**Graph.** A DAG with multi-parent edges and cycle detection is already what
`GraphBuilder` provides. The MVP-D shape is small:

```
target.requested (L0)
  └── kubernetes.api_access (L5)
        └── kubernetes.service (L4)
              ├── kubernetes.selected_pods (L6) ──┐
              └── kubernetes.endpoint_publication (L6) ──┴── (both cite the same Pod nodes)
```

Per-Pod nodes have **two parents** — the selection node and, where `targetRef` matches, the
publication node. That is a genuine DAG and the existing builder accepts it. **No graph change is
required.**

**Renderer — the one real gap.** `terminal.serviceView` models a **linear per-path journey** plus
**one** repeated child level (`advertisementStep` + `advertisedJourney`). Kubernetes has no
journey and **two** child kinds — selected Pods and published endpoints. Either the Kubernetes
`serviceView` uses the single child level for one of them and the `observations` mechanism for the
other, or `serviceView` gains a second child level. **The first is preferred and costs nothing**;
the second is a renderer change and must not happen by accident. Recorded as architecture pressure.

**Determinism.** Kubernetes list order is not a semantic contract. **Canonical output must sort**
by `(kind, namespace, name)` for objects, by container name within a Pod, and by
`(addressType, address)` for endpoints — never by API return order. This is mandatory future
behaviour and a required property test: a permuted list must produce byte-identical canonical JSON.

**Rule architecture.** The existing generic engine plus service-owned imperative rules is
sufficient. **No declarative Kubernetes rule DSL, no graph-pattern engine.** MVP-D needs
**two rules** — one for API access and target existence, one for backend publication — not one per
status reason.

---

## 16. Operator questions — the whole of first scope

Four, and every admitted finding maps to exactly one.

| # | Question | Finding |
|---|---|---|
| **Q1** | *"Does the Service I named exist in the namespace I named?"* | K1 |
| **Q2** | *"Was I permitted to read what I needed, or is this an answer I did not get?"* | K2 |
| **Q3** | *"Does this Service's selector currently match any Pod?"* | K8 |
| **Q4** | *"What backend endpoints does Kubernetes currently publish as ready for this Service?"* | K10 |

**Q4 is deliberately not** *"Can clients reach this Service?"* — that needs network-path evidence
svcdoctor does not have from the API. The distinction is the entire first Service scope.

---

## 17. The four admitted findings, and the two that were not

### 17.1 K10 — the finding the whole MVP exists for

**Claim:** *"Kubernetes currently publishes no ready endpoint for this Service."*

**Why it beats `kubectl`, concretely.** To answer Q4 by hand an operator must: know that
EndpointSlices are found by the `kubernetes.io/service-name` label rather than by name (W5);
enumerate **all** slices, because multiple per Service are normal and dual-stack guarantees at
least two (W8); know that **`ready: nil` means true, not false** (W1) — the single most likely
hand-analysis error; know that `serving` and `terminating` are separate conditions with their own
nil defaults (W2, W3); **deduplicate** endpoints that legitimately appear in more than one slice
(W9); and confirm the enumeration was complete. `kubectl get endpointslices` prints none of that
reasoning. **This is exactly the completeness-and-contrast work svcdoctor already does for Kafka
topology.**

**Preconditions:** the Service has a selector; at least one Pod is selected (so K8 and K10 never
both fire for one condition); the slice enumeration is **proven complete**.

**Severity ERROR, CONFIRMED, HIGH on direct authority** — the slices state it; nothing is
inferred. It is `vantageDependent: false`, because it is a control-plane fact rather than a
reachability measurement.

**Wording is frozen at "publishes", never "reachable".** Topology-aware routing, traffic policies
and mesh interception all mean a published ready endpoint is not necessarily usable from every
client, and an unpublished one is not necessarily unreachable. **Forbidden:** *the Service is
down* · *clients cannot reach it* · *the Pods are unhealthy* · *the endpoint controller is broken*
· any word implying persistence.

**Ready, not serving, is the counted condition**, and the reason is stated so it can be argued
with: `ready` is what kube-proxy programs, so it answers Q4. `serving` and `terminating` are
recorded as observations, which is what makes a graceful-termination window legible rather than
alarming.

### 17.2 K11 — deferred, and the reasoning is the audit's cleanest epistemic result

*"A Pod the selector matches and Kubernetes reports `Ready` is present in no published
EndpointSlice."* Four explanations:

| | Explanation | Distinguishable from API evidence? |
|---|---|---|
| A | EndpointSlice controller lag | **no** — only time separates it from D |
| B | the slices are third-party-managed | **yes** — `endpointslice.kubernetes.io/managed-by` (W7) |
| C | the Pod is terminating | **yes** — `metadata.deletionTimestamp` |
| D | a genuine controller problem | **no** |

B and C are excludable from evidence svcdoctor already holds. **A and D are separable only by
observing the same contrast later**, and Phase 11.0 / ADR 0092 froze that *re-running the same
measurement is not next-best evidence* and that a single run may not claim persistence. So K11
would be a hypothesis whose only discriminator is a second run — the exact shape ADR 0092
rejected. **Deferred; the membership contrast is recorded as evidence and rendered as an
observation, and the finding layer stays silent.** That is ADR 0085 §4's arrangement applied
again.

### 17.3 K12 — rejected on a false-positive that would be common

*"No selected Pod declares a container port named X."* `containerPort` declaration is **optional
and purely informational**; an application listening on a port it never declared works perfectly.
So the finding would fire on a correct deployment, and its tempting reading — *the application is
not listening* — is an inference about process state svcdoctor cannot make.

The **narrow** true statement — *"no selected Pod declares a container port with this name"* — is
worth keeping as an **observation** in a later scope, because a named `targetPort` that resolves
nowhere does prevent endpoint publication. It is rejected as a **finding** in first scope.

### 17.4 K1 and K2 — why an API result deserves a finding at all

Because the alternative is worse. `kubectl get svc api -n paymnets` prints *"not found"* and an
operator reads it as *the Service is gone*, when the namespace is misspelled. And a `403` on
EndpointSlices is **not** *"no endpoints"* — it is *"you could not look"*, and collapsing the two
is the failure §52 names.

**K2's shape follows `REDIS_COMMAND_NOT_PERMITTED` exactly**: state `UNKNOWN`, severity `WARN`,
and its detail says *the service did not fail; svcdoctor's measurement was blocked*. Both key on
`metav1.StatusReason`, the one Kubernetes reason vocabulary that **is** an API-contract enum (§6).

---

## 18. MVP-D, precisely

| | |
|---|---|
| **Target form** | `namespace` + `Service` name + an explicit cluster access selection. One target, one namespace, one Service |
| **Target kinds admitted** | **Service only.** No workload target, no Pod target, no Namespace target, no cluster-scoped target, no label-selector target, no `--all-namespaces` |
| **API objects** | `Service` (get) · `Pod` (label-scoped list by the Service's selector) · `EndpointSlice` (label-scoped list by `kubernetes.io/service-name`) |
| **Findings** | **4** — `KUBERNETES_TARGET_NOT_FOUND`, `KUBERNETES_API_ACCESS_DENIED`, `KUBERNETES_SERVICE_SELECTS_NO_PODS`, `KUBERNETES_SERVICE_NO_READY_ENDPOINTS`. *Names are candidates; 12.1A freezes them* |
| **Rules** | **2** |
| **Observations (no finding)** | selected-Pod count · per-Pod `phase` and `Ready` · terminating count · published endpoint counts by `ready` / `serving` / `terminating` · slice count · `managed-by` when it is not the built-in controller · enumeration completeness |
| **Free text read** | **none** |
| **Events / logs / metrics / NetworkPolicy / CNI / mesh / Ingress** | **none** |
| **Active probing of Pods or Services** | **none** |
| **Schema change** | **none.** `SchemaVersion` 1, `RunSchemaVersion` 1 |
| **Graph change** | **none** |
| **`RuleContext` change** | **none** |
| **New `FailureClass`** | **expected none** — `RESOURCE_NOT_FOUND` and the authorization classes already exist; 12.1A confirms against the 42 |
| **Exit codes** | unchanged |
| **RBAC** | 3 resources, 2 verbs, 1 namespace |
| **API calls** | 3 typical, <10 at the ceiling |

**Why not MVP-A (Pod/container only):** it fails §88. Its high-value facts all key on a
**free-form** `reason` (W14), and what survives is one column of `kubectl get pods`.

**Why not MVP-C (both):** it triples the surface — free-text reasons, restart-count temporality,
readiness gates, sidecars, init containers, Job semantics — for findings that are mostly
restatements. Pod **state** is still fetched and rendered; only Pod **findings** are excluded.

---

## 19. Validation strategy

### 19.1 Fixtures

| Admitted finding | Fixture | Class |
|---|---|---|
| K1 target not found | `kind` cluster; request a Service that was never created | **DETERMINISTIC_REAL** |
| K2 authorization denied | a ServiceAccount with a Role granting `services` but not `endpointslices` | **DETERMINISTIC_REAL** |
| K8 selector matches zero Pods | a Service whose selector names a label no Pod carries | **DETERMINISTIC_REAL** |
| K10 zero ready endpoints | a Deployment whose readiness probe **always fails** — Pods run, none becomes `Ready`, the controller publishes zero ready endpoints | **DETERMINISTIC_REAL** |
| headless with selector | `clusterIP: None` plus the same Deployment; asserts K10 still applies and no ClusterIP finding appears | **DETERMINISTIC_REAL** |
| selector-less Service | a Service with no selector; asserts K8 is **structurally unreachable** | **DETERMINISTIC_REAL** |
| ExternalName | asserts absent slices produce no finding | **DETERMINISTIC_REAL** |
| dual-stack de-duplication | two slices for one Service | **DETERMINISTIC_FAKE_ONLY** on a single-stack CI cluster |
| pagination truncation | many Pods, a small budget; asserts **incomplete**, never *"zero"* | **DETERMINISTIC_FAKE_ONLY** |
| *(deferred)* OOMKilled | a container with a low memory limit that allocates | **FLAKY** — timing- and node-dependent |
| *(deferred)* image pull backoff | a nonexistent image tag | DETERMINISTIC_REAL, but the finding is not admitted |

**Every admitted finding has a `DETERMINISTIC_REAL` fixture.** That is the §84 bar and MVP-D
clears it.

**`kind` is the recommended environment.** `envtest` runs an API server and controller-manager but
**no kubelet**, so Pods never actually run and container status is synthetic — it cannot prove
readiness or endpoint publication and **must not be described as real-cluster proof**. The
EndpointSlice controller is part of kube-controller-manager, so `envtest` can drive slice
publication, but the Pod readiness that feeds it cannot be genuine.

**Split the layers, as the existing services do.** Object normalization and every rule are
hermetic: fixtures in, evidence and findings out, no cluster. A real cluster validates
**acquisition** — auth, pagination, RBAC, list semantics — and nothing else.

### 19.2 Version and distribution matrix

| Target | Why |
|---|---|
| latest stable Kubernetes | the reference |
| one older supported minor | proves the audit's fields are not version-new |
| `kind` on both | CI-feasible on amd64 and arm64 |

`discovery.k8s.io/v1` EndpointSlice has been stable since v1.21, so a **minimum of v1.21** is
defensible for MVP-D — and the sidecar semantics that would gate a *Pod* scope (v1.29 default,
v1.33 locked, W16) do not bind it, which is a further argument for the chosen MVP.

**OpenShift, RKE2, k3s, EKS, GKE, AKS: first scope uses only stable upstream APIs, so no vendor
branch is permitted and none is needed.** The design must assume no container runtime, no
privileged access, no node filesystem and no upstream-only controller behaviour — MVP-D assumes
none of them. **Cloud-managed clusters are gated by §11.1's exec question, not by the API surface.**

### 19.3 Mutation and property targets

**Mutations a future harness must catch:** `ready: nil` treated as false · `terminating: nil`
treated as true · a truncated enumeration published as *"zero"* · a universal claim emitted
without proven completeness · endpoints counted without de-duplication across slices · K8 fired on
a selector-less Service · `serving` counted where `ready` was meant · `403` rendered as *"no
endpoints"* · a `NotFound` on one object attributed to another · resource ordering leaking API
list order into canonical JSON · UID confused with name · a terminating endpoint counted as ready
· a raw `message` reaching output · `availableReplicas` substituted for `readyReplicas` ·
a remediation admitted below CONFIRMED/HIGH.

**Property invariants:** an unknown `reason` string never produces a stronger finding · permuting
every list changes no canonical byte · duplicate endpoints across slices do not inflate any count
· an incomplete set never yields a universal claim · hostile object names and labels cannot inject
ANSI, CR or LF into terminal output · nil conditions are read exactly as W1–W3 specify · a
malformed named `targetPort` produces no finding · huge restart counts produce no rate language.

---

## 20. Security threat model

| Threat | Structural exclusion |
|---|---|
| hostile object names, labels, annotations | names are `AttrKindIdentity` and redacted; labels are matched, never dumped; annotations are never read; the terminal renders through the closed-map discipline PostgreSQL's `recovery` line established |
| hostile `status` / `condition` / Event messages | **never read.** §6 |
| ANSI / CR / LF injection into a terminal | no peer-chosen string reaches prose; `validateIdentifier` already refuses control characters in a `Subject.ref` |
| huge lists, huge slices, huge container counts | object budgets, pagination bounds, incomplete-not-zero |
| **exec credential plugins** | **not structurally excludable — measured (M2).** Behavioural refusal plus a guard test. §11.1 |
| kubeconfig file permissions, symlinks, path disclosure | explicit path only; errors must not echo file contents; the shipped image has no shell (ADR 0062) |
| API server redirects and proxies | reported, never silently inherited |
| impersonation | refused in first scope |
| Secret and token leakage | Secrets never read; the credential is a `security.Secret`; **no fifth `Reveal` call site is required**, because a bearer token is presented by the client library rather than assembled by svcdoctor — 12.1A must confirm this and, if it is wrong, the site belongs in `adapter/kubernetes/client` and nowhere else |
| panic and error text leakage | API errors normalized to structured `code` + `reason`; **`Status.message` never retained** |
| **`net/http` and `os/exec` entering the binary** | happens, and is recorded rather than denied: today **neither is linked**, and four separate guards say so |

---

## 21. Architecture blockers for Phase 12.1A

Two, both measured rather than suspected. Neither is a hard stop; both must be decided before any
Go is written.

**B1 — exec credential plugins.** ADR 0072 §13 refuses config-driven process execution with reopen
condition *"None."*; M2 proves `os/exec` and the exec auth plugin are linked by client-go
regardless of `clientcmd`; EKS/GKE/AKS kubeconfigs use exec by default. 12.1A must choose B+D (no
exec; in-cluster and explicit token/CA) or reopen ADR 0072 §13 **with its own security review**.

**B2 — the client-library dependency.** 2 modules → 46–47; a 10.3 MB binary → ~36 MB; two package
families the repository bans by test. 12.1A must decide the import surface and the Kubernetes
minor, and record the number rather than discover it.

Three further items are **contract questions**, not blockers: the target syntax and namespace
policy (§18, §22); the fleet `Factory.DefaultPort` mismatch (§11.4); and whether the renderer gains
a second child level (§15).

---

## 22. Namespace and target policy

**Namespace is mandatory and explicit.** Not the kubeconfig context's namespace, and not
`"default"`. For an incident tool, a target that silently changes meaning when someone runs
`kubectl config set-context --current --namespace=...` is a trap, and the failure mode — reading
the wrong namespace and reporting *"not found"* — looks exactly like a real finding.

**Cluster access is selected explicitly.** No implicit fallback chain from in-cluster to
`KUBECONFIG` to `~/.kube/config`.

**Cluster-scoped and whole-cluster targets are prohibited in first scope:** no `--all-namespaces`,
no cluster scan, no "every unhealthy Pod", no Namespace target, no Node target.

---

## 23. Traceability — `KDA-001` … `KDA-030`

Tiers: **F** frozen by ADR 0093 · **B** blocker for 12.1A · **D** deferred with a condition.

| ID | Tier | Requirement | Where |
|---|---|---|---|
| KDA-001 | **F** | **ARCH A** — Kubernetes is a normal service adapter diagnosing Kubernetes objects | §10.1 |
| KDA-002 | **F** | The nine-class authority model; API state never becomes hidden runtime cause | §4 |
| KDA-003 | **F** | One target = one namespace + one Service; no cluster-scoped or whole-cluster target | §18, §22 |
| KDA-004 | **F** | Minimum RBAC: 3 resources, 2 verbs, 1 namespace; no cluster-admin | §11.5 |
| KDA-005 | **B** | Kubeconfig policy: explicit path only; impersonation refused; proxies reported | §11.3 |
| KDA-006 | **B** | **Exec credential plugins** — B+D recommended, or reopen ADR 0072 §13 with a security review | §11.1 |
| KDA-007 | **F** | Object inventory: 3 kinds in first scope; Secrets and ConfigMaps never read | §5, §13.2 |
| KDA-008 | **F** | Object budgets, bounded and defensible | §12.1 |
| KDA-009 | **F** | Pagination: `limit` + `continue`, never a silent stop | §12.2 |
| KDA-010 | **F** | **A budget or page limit becomes INCOMPLETE, never "zero"**; universal claims require proven completeness | §12.3 |
| KDA-011 | **F** | Reads are not a snapshot; every set claim is scoped *"at the time of these API observations"*; controller lag is never misconfiguration | §12.4 |
| KDA-012 | **F** | Subject identity: `<kind>/<namespace>/<name>`, bounded, deterministic; **UID is internal correlation only** | §13.1 |
| KDA-013 | **F** | EndpointSlice semantics **as verified**: `ready` nil ⇒ true, `serving` nil ⇒ true, `terminating` nil ⇒ false; de-duplicate across slices | W1–W3, W9, §13.4 |
| KDA-014 | **F** | Service selector semantics: selector-backed only; **K8 structurally unreachable for a selector-less Service**; ExternalName unsupported and not a fault | §14 |
| KDA-015 | **F** | Pod/container state is **observation only** in first scope | §18 |
| KDA-016 | **D** | Init containers and sidecars need `spec.initContainers[].restartPolicy` before interpretation | §7.4 |
| KDA-017 | **D** | OOMKilled boundary: *"Kubernetes reported the previous termination reason as OOMKilled"*, never a cause | §7.3 |
| KDA-018 | **D** | CrashLoopBackOff boundary: a `Waiting` reason, never a rate | §7.3 |
| KDA-019 | **F** | **Free-text prohibition**: no substring, regexp, fuzzy match or raw interpolation over any Kubernetes message field | §6 |
| KDA-020 | **F** | **Events OUT** | §9.1 |
| KDA-021 | **F** | **Logs OUT** | §9.2 |
| KDA-022 | **F** | **Metrics OUT** | §9.3 |
| KDA-023 | **F** | **NetworkPolicy solver OUT; CNI/eBPF OUT; service mesh OUT; Ingress/Gateway OUT** | §9.4–9.7 |
| KDA-024 | **F** | **No active probing of Pods, ClusterIPs, Service DNS or endpoint addresses** | §9.8 |
| KDA-025 | **F** | **Kubernetes credentials never flow to discovered endpoints** — structural, via `security.Endpoint` binding | §11.2 |
| KDA-026 | **F** | Canonical report fit: **no schema, graph or `RuleContext` change**; layer mapping keeps the failure boundary meaningful | §15 |
| KDA-027 | **F** | **Deterministic ordering**: canonical JSON must not depend on API list order | §15 |
| KDA-028 | **F** | Privacy: names are `AttrKindIdentity`; no annotations, no label dump, no image/containerID/Pod IP/ClusterIP in canonical evidence | §13 |
| KDA-029 | **F** | Fixture strategy: every admitted finding has a `DETERMINISTIC_REAL` fixture; **`envtest` is not real-cluster proof** | §19.1 |
| KDA-030 | **F** | **MVP-D**: 4 findings, 2 rules, 4 operator questions; next phase is **Phase 12.1A — Kubernetes adapter contract freeze** | §16, §18, §24 |

---

## 24. Next phase

> ### Phase 12.1A — Kubernetes Adapter Contract Freeze
> **Documentation only. No Go, no dependency, no fixture.**

It must decide, and only these:

1. **B1 — exec credential plugins.** B+D, or reopen ADR 0072 §13 with a security review.
2. **B2 — the client library**, its import surface, its Kubernetes minor, and the recorded module
   and binary-size cost.
3. **The target syntax** — the leaf-command flags and the deferred fleet shape (§11.4).
4. **The four finding codes**, their exact names, kinds, severities, confidence admission,
   evidence references and forbidden claims.
5. **The normalized vocabulary** — steps, attribute keys, closed value sets.
6. **The object budgets**, confirmed against a real cluster.
7. **Whether any new `FailureClass` is required** — expected none.
8. **The renderer shape** (§15) and whether `serviceView` gains a second child level.
9. **Whether ADR 0062 §9's no-API-access clause is superseded in part**, and what
   `examples/kubernetes/` gains.

Only then **Phase 12.1B — Kubernetes API client and evidence normalization**, and **Phase 12.1C —
Service backend publication diagnosis**. Storage (K13), Pod/container findings (K3–K6) and the
publication-membership contrast (K11) are **12.2 and later**, each with its own entry gate.

---

## 25. Adversarial review

The twenty-five questions of §167, answered against the selected MVP.

1. **A kubectl wrapper?** No — MVP-D's value is enumeration completeness and the nil-condition
   semantics `kubectl` does not reason about.
2. **A finding that merely repeats status?** Four candidates were rejected for exactly that
   (K5, K6, K2b, K-PR).
3. **Free text parsed?** No. MVP-D reads **zero** free-text fields.
4. **Hidden cause inferred?** No. K10 says *publishes*, not *is broken*.
5. **Ready endpoint confused with reachable endpoint?** No — §17.1 freezes the wording, and
   topology hints and traffic policies are why.
6. **Service selector confused with workload ownership?** No — no workload is read, and §5 refuses
   name heuristics.
7. **Selector-less Services ignored?** No — K8 is **structurally unreachable** for them, as a
   permanent test.
8. **EndpointSlice eventual consistency ignored?** No — it is why K11 is deferred.
9. **Universal claims from incomplete lists?** Forbidden by KDA-010, mirroring Kafka 10.2.
10. **One API read assumed to be a snapshot?** No — §12.4 freezes the claim language.
11. **restartCount turned into a rate?** No — observation only, and the rate words are banned.
12. **Rollout deficit called "stuck"?** K7 is deferred, and the word is refused with it.
13. **OOMKilled called a memory leak?** K4 is deferred, and four causal readings are named as
    forbidden.
14. **NetworkPolicy blocking inferred?** No — §9.4, and FP01A already bans the words everywhere.
15. **cluster-admin required?** No — 3 resources, 2 verbs, 1 namespace.
16. **Secrets read?** No, and never.
17. **Kubeconfig plugins executed silently?** **This is the blocker, named as one** — and M2 proves
    the linkage is unavoidable, so the guarantee must be behavioural and guarded.
18. **Kubernetes credentials inherited by discovered endpoints?** No — structurally prevented by
    `security.Endpoint` binding.
19. **Pod names and IPs leaking into shareable output?** Names are `AttrKindIdentity` and
    pseudonymized; Pod IPs are not in canonical evidence at all.
20. **The whole ecosystem designed instead of an MVP?** 19 object kinds were weighed and **3**
    admitted.
21. **Does MVP-D materially outperform `kubectl`?** Yes, and §17.1 states exactly how — six
    reasoning steps `kubectl` does not perform.
22. **Can every admitted finding be proven on a deterministic real cluster?** Yes — §19.1.
23. **Does every universal claim require completeness?** Yes — KDA-010.
24. **Is canonical output deterministic under list reordering?** Required by KDA-027 and by a
    property test.
25. **Would a principal engineer trust every claim?** The claims are *this object does not exist*,
    *you were not permitted to read this*, *this selector matches nothing*, and *no ready endpoint
    is published*. Each is a fact the API server states, under a proven-complete enumeration.

**One narrowing was applied during this review** and it is recorded rather than smoothed away:
K11 began the audit as an admitted finding and was **demoted to an observation** once its
explanation set was written out and A and D proved separable only by time.

---

## 26. Validation

```
git rev-parse HEAD; git rev-parse origin/main    # identical, 738ef3c
git status --short                                # clean at start
make check                                        # exit 0 — MANDATORY GATE, before editing
go test ./test/security/... -run 'Convergence|RuleContext|Dependenc|FindingCode|Reveal' -v
  → 22 rules; attributed 65 of 65 finding codes; RuleContext 3 fields; dependency count exact
CGO_ENABLED=0 go build -o /tmp/... ./cmd/svcdoctor   # 10,310,258 bytes, 219 packages
go list -deps ./cmd/svcdoctor | grep -xE 'os/exec|net/http'   # no match
make check                                        # exit 0 — after editing
git diff --check                                  # clean
```

**Evidence labelling.**

- **SOURCE-PROVEN** — every statement about svcdoctor's packages, guards, ADRs and composition
  roots, read from the tree at `738ef3c`.
- **TEST-PROVEN** — the §1.1 inventory, by the named guards, executed.
- **WEB-VERIFIED** — W1–W17, from `kubernetes.io` only: the EndpointSlice v1 API reference,
  the EndpointSlice concepts page, the Service concepts page, the Pod lifecycle page, the Pod v1
  API reference, the sidecar-containers page and the Deployment v1 API reference. **No blog, no
  third-party source, no vendor documentation.**
- **MEASURED** — M1 and M2, run in temporary modules under `/tmp`, **outside the repository**.
  No repository file was created, modified or deleted by them, and both directories were removed.

**Not run, and no claim is made about them:** every container integration suite and all eleven
mutation harnesses. Phase 12.0 changes no Go code, so no integration-green and no mutation-closure
claim is made. **No Kubernetes cluster was contacted; M1 and M2 are build-graph measurements, not
API calls.**

**Explicitly not verified, and flagged for 12.1A rather than assumed:** whether
`CrashLoopBackOff` can appear after a single container failure (a kubelet-timing question);
whether the API server returns `404` rather than `403` for an object the caller may not read,
under every authorizer configuration; and whether a bearer token can be presented without a fifth
`security.Reveal` call site.
