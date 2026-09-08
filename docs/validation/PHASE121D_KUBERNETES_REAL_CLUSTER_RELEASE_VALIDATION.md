# Phase 12.1D — Kubernetes real-cluster and release-quality validation closure

- **Phase:** 12.1D (validation and compatibility closure; **one production change**, and it is a
  refusal)
- **Baseline:** `9967f1d600ce1681549387ff36b980ec1b9e30ff`, equal to `origin/main`, clean tree,
  `make check` green before anything was edited
- **Question:** does the frozen svcdoctor Kubernetes model survive contact with a real API server,
  a real authorizer, a real EndpointSlice controller and real list pagination?
- **Answer:** **yes**, on both lanes, with **one** contract gap found and closed and **four**
  behaviours measured that no earlier phase had recorded
- **Outcome:** Kubernetes graded **Level 3 — SUPPORTED BASIC** at **v1.34.0** and **v1.31.12**,
  and at no other version and no distribution

---

## 1. Baseline

```
HEAD        9967f1d600ce1681549387ff36b980ec1b9e30ff  feat(kubernetes): add diagnose kubernetes CLI
origin/main 9967f1d600ce1681549387ff36b980ec1b9e30ff
tree        clean
make check  GREEN
```

## 2. Tool versions

| | |
|---|---|
| Go | `go1.26.6 darwin/arm64` |
| kind | `v0.30.0` (`go1.26.6 darwin/arm64`) — installed for this phase; the host had none |
| kubectl | `v1.36.2` — **fixtures only**, never a runtime dependency (§17) |
| Docker | `28.3.3` |
| Colima | `0.8.4`, macOS Virtualization.Framework, virtiofs |
| Runtime | Ubuntu 24.04.2 LTS · aarch64 · 4 CPU · 6,197,383,168 B |
| Host | `Darwin arm64` |

`kubectl` is two minors ahead of the older lane's server and prints a skew warning. It affects
fixture construction only; svcdoctor never sees it.

## 3. Node images, pinned by digest

Taken from the kind v0.30.0 release's own notes. No tag is floating and `latest` appears nowhere.

| Lane | Image |
|---|---|
| **CURRENT** | `kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a` |
| **OLDER** | `kindest/node:v1.31.12@sha256:0f5cc49c5e73c0c2bb6e2df56e7df189240d83cf94edfa30946482eb08ec57d2` |

### 3.1 v1.21 is the architectural minimum and was not run, and that is stated rather than worked around

ADR 0094 §2.11 derives a floor of **v1.21** from the API — EndpointSlice `v1` is stable there and
`conditions.ready` is available. **That is a statement about the API svcdoctor uses. It is not a
compatibility claim.**

kind v0.30.0 publishes node images for **v1.31.12, v1.32.8, v1.33.4 and v1.34.0** and cannot run a
v1.21 node. Downgrading kind or client-go to force one would be manufacturing evidence, so the
OLDER lane is the **oldest minor this toolchain can reproducibly run**, and
`docs/COMPATIBILITY.md` says exactly that.

One consequence is recorded rather than glossed: `serving` and `terminating` became stable in
**v1.26**, so **neither lane exercises a server old enough to omit them**. Their nil semantics are
proven against authored API objects instead — see §9.

## 4. Binary

```
CGO_ENABLED=0 go build -o bin/svcdoctor-integration ./cmd/svcdoctor
CGO_ENABLED=0 GOOS=linux go build -o bin/svcdoctor-integration-linux ./cmd/svcdoctor

host  sha256 6cc49ec942f26586965acfdd6a24f3ed3b779e801ec0e9e3f67df4a8b1138a86
linux sha256 eeed4bd48122688a4248a53f2afe4e24d6e914dca64bf3b54203fce6d91de680
```

One binary per lane, built once, invoked by every scenario — so a difference between two scenarios
cannot be a difference between two builds. **Both lanes ran the identical binary**, which is why
the two lanes' results are comparable at all.

The second binary exists because the in-cluster lane runs svcdoctor inside a Linux container. It
is cross-compiled from the same tree and **named explicitly** in a separate environment variable;
pretending one file served both would be the quiet inaccuracy this phase exists to remove.

## 5. Lanes and how to run them

```sh
make integration-kubernetes                        # CURRENT, v1.34.0
KUBERNETES_LANE=older make integration-kubernetes  # OLDER,  v1.31.12
```

`kubernetes-up` refuses to proceed without `kind`, `kubectl` and a reachable container runtime,
and says how to install the first. **An absent capability fails; it never skips into green.**

## 6. Fixture architecture

`test/integration/kubernetes`, `//go:build integration`, outside `make check` for the reason every
other integration lane is: it needs a runtime, and the ordinary gate stays hermetic.

- **Declarative manifests**, applied through `kubectl` and built by small Go helpers.
- **One namespace per test**, named deterministically from the test so a failure leaves an
  inspectable namespace whose name says which test made it. Deleted asynchronously; a rerun
  deletes a leftover first, so the suite survives reruns.
- **Failure diagnostics are namespace-scoped and three-kind-bounded** — Service, Pod,
  EndpointSlice. No Secret, no ServiceAccount token, no kubeconfig material, nothing cluster-wide.
- **`registry.k8s.io/pause`** is every workload: svcdoctor connects to no Pod, so a fixture has to
  produce an API object in a state, and the cheapest container that reaches Ready is the honest
  choice.

### 6.1 Wait strategy — no `sleep` anywhere

Every wait names a condition, a deadline and what it last observed. Phase 9.1C's fixture lesson,
and this phase paid for it once:

> **The first K4 fixture waited for "zero ready endpoints" and the wait was satisfied instantly**,
> by a slice the controller had created and not yet populated while the Pod was still
> `ContainerCreating`. Zero ready was true for the wrong reason, and svcdoctor correctly reported
> the *no endpoint published* variant of F4 rather than the *published and none ready* variant the
> scenario exists to exercise.

The condition was too weak, not the timing. A scenario about unready endpoints now waits until
endpoints exist **and** none of them is ready.

## 7. K1–K7 — the Service shapes

| | Scenario | Result | What it pins |
|---|---|---|---|
| **K1** | healthy ClusterIP | **PASS** | no finding, exit 0, three complete reads, 1 matched Pod, 1 ready endpoint |
| **K2** | Service not found | **PASS** | `KUBERNETES_SERVICE_NOT_FOUND` from a real structured `NotFound`; both downstream reads `SKIPPED`; the API's own prose never quoted; exit 1 |
| **K3** | selector matches zero Pods | **PASS** | `KUBERNETES_SERVICE_SELECTS_NO_PODS` **alone**, with F4's own precondition independently satisfied — so disjointness is what withheld it |
| **K4** | Pod selected, no ready endpoint | **PASS** | `KUBERNETES_SERVICE_NO_READY_ENDPOINT` **alone**; no forbidden word in the prose; `publishes` present |
| **K5** | selector-less | **PASS** | no semantic finding; both reads `SKIPPED`; a Pod that a match-all reading would have selected is present and ignored |
| **K6** | `ExternalName` | **PASS** | no semantic finding; type recorded |
| **K7** | headless, selector-backed | **PASS** | diagnosed **normally** — recorded headless *and* selector-present, both reads `PASS`. Not mistaken for selector-less |

Both lanes. Identical results.

## 8. R1–R3 — real RBAC, and one measured distinction

Every identity is a real ServiceAccount holding a real namespaced `Role`. No `--as`, no simulated
403.

| | Denied | Findings | Still `PASS` | Withheld | Exit |
|---|---|---|---|---|---|
| **R1** | `services:get` | `API_ACCESS_DENIED` | — (both short-circuited) | `SERVICE_NOT_FOUND` | **0** |
| **R2** | `pods:list` | `NO_READY_ENDPOINT` + `API_ACCESS_DENIED` | `k8s.service`, `k8s.endpoint_publication` | `SELECTS_NO_PODS` | **4** |
| **R3** | `endpointslices:list` | `SELECTS_NO_PODS` + `API_ACCESS_DENIED` | `k8s.service`, `k8s.pod_set` | `NO_READY_ENDPOINT` | **4** |

Every denied node is `UNKNOWN` + `AUTHZ_NOT_PERMITTED`. No `Status.Message`, no
`system:serviceaccount:` prose, no `RBAC`/`Role`/`cluster-admin` in any detail.

**R2 and R3 confirm Phase 12.1C's reconciliation against a real authorizer.** Each produces
**two** findings, because *one branch failing never erases the other branch's independent
evidence*. Had the §10.3 literal reading been implemented instead, each would have produced one —
so this is the strongest available confirmation that the reconciliation was right.

### 8.1 A denied Service read exits 0; a denied list exits 4 — measured, and new

No earlier phase recorded this. Both are the generic mapping applied to two different completeness
states:

- A denied **Service** read short-circuits. The two downstream reads never run, so they are
  `SKIPPED` with `EXEC_SKIPPED_PREREQUISITE_FAILED`, **nothing was left half-measured**, the run is
  complete, F2 is WARN, and `docs/SCOPE.md`'s precedence returns **0**.
- A denied **list** was attempted and did not finish. The result is incomplete and **4** outranks
  everything below it.

Nothing Kubernetes-specific decides either. The initial expectation in this suite was 4 for all
three rows, copied from the 12.1C fleet test where the *Pod list* was denied; the cluster corrected
it.

### 8.2 The frozen RBAC minimum is sufficient, and is not more than is needed

An identity holding **exactly** `services:get`, `pods:list`, `endpointslices:list` completes a
whole diagnosis with all three nodes `PASS`. ADR 0094 §2.5's minimum is neither too small nor
padded.

## 9. E1–E5 — EndpointSlice condition semantics

**Authored objects**, because no controller writes an absent condition — and the API server was
measured to store `conditions: {}` **verbatim**, which is what makes the nil semantics testable at
all.

| | Endpoint | ready count | terminating count |
|---|---|---|---|
| **E1** | `ready: true` | 1 | 0 |
| **E2** | `ready: false` | 0 | 0 |
| **E3** | **`ready` absent** | **1** | 0 |
| **E4** | `ready:false, serving:true, terminating:true` | 0 | **1** |
| **E5** | `ready:false, serving:true` | **0** | 0 |

E3 is the single most likely hand-analysis error and the reason this scope beats reading
`kubectl get endpointslices` by eye. E5 is the one that would change if effective-ready were read
as `ready && serving && !terminating` instead of **`ready` alone**.

**All-terminating**: with every endpoint terminating, F4's detail says so and says a proxy **may
still route** to such an endpoint. `no ready endpoint` never becomes `no traffic`.

## 10. A1–A5 — association and the generation guard

| | Slice | Admitted | Excluded count |
|---|---|---|---|
| **A1** | matching Service owner UID | **yes** | 0 |
| **A2** | a **different live Service's** UID | **no** | **1** |
| **A3** | no owner reference | **yes** (by label alone) | 0 |
| **A4** | third-party `managed-by` | **yes** | 0 |
| **A5** | non-Service owner (`ConfigMap`) | **yes** | 0 |

### 10.1 The garbage collector deletes a dangling owner reference — measured, and new

A2 and A5 first used **fabricated** UIDs and both timed out waiting for a slice the cluster had
already removed. Kubernetes' garbage collector resolves an owner reference by **kind and name
within the namespace** and deletes the dependent when the UID it finds does not match — in well
under a second.

Two consequences, both recorded rather than worked around:

1. The fixtures now represent a mismatch with a **live second Service** and a **real ConfigMap**.
   The property under test is unchanged and is the one the contract states — *this slice is owned
   by a Service that is not the one I read* — and the fixture is durable rather than racing a
   controller.
2. **The delete-and-recreate window is narrower than assumed.** After a genuine delete and
   recreate the stale slice is usually *gone* rather than merely excluded — measured:
   `slice_count=1 excluded_by_owner_uid=0`. That is good news and it is **not the guard**, because
   it is asynchronous and svcdoctor cannot depend on it having run. The end state is asserted for
   the real flow; the exclusion mechanism itself is proven by A2.

**Delete-and-recreate: PASS.** Generation B sees 0 ready endpoints, generation A's published
endpoint satisfies nothing, no fourth API request is made, and neither UID reaches the report.

**Third-party managed: PASS.** Admitted, `k8s.slice_externally_managed` recorded, and the managing
controller's name never reaches any prose.

**Multi-slice: PASS.** 4 slices, 6 endpoints, 3 ready, aggregated across all of them, and stable
over five re-reads — the API's list order is not contractual and the answer does not depend on it.

**Dual-stack: NOT EXERCISED — ENVIRONMENT CAPABILITY ABSENT.** Both lanes' API Service reports
`ipFamilies=IPv4`. An authored IPv6 slice shows address family creates no semantic branch; that is
a **parser** result and is kept apart from a dual-stack claim, which is not made.

## 11. Pagination and the request budget, counted at the wire

A TLS reverse proxy in the test process counts each request and forwards it, with the lane's real
client certificate, to the **real API server**. Every response svcdoctor sees is the cluster's;
nothing under test is simulated.

| | Measured |
|---|---|
| Nominal run | **exactly 3** requests: `GET …/services/<name>`, `GET …/pods?labelSelector=…&limit=500`, `GET …/endpointslices?labelSelector=kubernetes.io/service-name=…&limit=500` |
| Selector-less Service | **exactly 1** |
| Pagination fixture | **600** Pod objects → **2** Pod list requests → **4** total |
| Refused kubeconfig (`exec`) | **0** |

No namespace read, no Service UID lookup, no per-Pod `GET`, no discovery call, no server-version
call. Both lists are **server-side filtered**; a client-side filter would read every Pod in the
namespace and is refuted by the observed query.

Pagination detail: the first page carries **no** `continue`, the second carries the server's
token, the **label selector and the limit are identical across pages**, there is no silent
restart, the set is complete only after the final page, and `pod_observed_count = 600`. F3 does
not fire.

The 600 Pods are deliberately **unschedulable and `Pending`**: an API `LIST` pages over API
objects, so the fixture costs the kubelet nothing while exercising exactly the thing under test.
Scheduling 600 running Pods would prove the same property and risk turning validation into a local
denial of service, which §23 forbids. **No budget ceiling was driven** — 4,000 Pods, 256 slices and
10,000 endpoints are hermetically tested constants and stay that way.

## 12. Authentication

| Mode | Result | How it was reached |
|---|---|---|
| **client certificate** | **PASS** | kind's own generated kubeconfig — `auth_mode = CLIENT_CERT`. No `--client-cert` flag exists and none was needed |
| **bearer token, file** | **PASS** | `--token-file` with a real TokenRequest token — `auth_mode = TOKEN` |
| **bearer token, stdin** | **PASS** | `--token-stdin`; the token is never an argument, so never in any `argv` |
| **in-cluster ServiceAccount** | **PASS** | **from a Job inside the cluster** |
| kubeconfig `tokenFile` | covered hermetically | not separately re-run here; the token path it feeds is the same one `--token-file` exercises |

No token, and no twelve-byte prefix of one, appears in any stream. No `PRIVATE KEY`,
`BEGIN CERTIFICATE`, `client-key` or `client-certificate` appears in any output of the
certificate run.

### 12.1 In-cluster closes 12.1C.2's recorded gap

Phase 12.1C.2 proved every one of `--in-cluster`'s *refusals* and could prove no execution,
because the mode needs a projected ServiceAccount. It is now executed: a `scratch` image built
from the Linux binary, loaded into the kind node with `kind load` — **nothing pushed, nothing
published** — and run as a `Job` with `backoffLimit: 0` under a ServiceAccount holding exactly the
frozen three permissions.

`auth_mode = IN_CLUSTER`, all five nodes `PASS`, no finding, **no context published** (a context
names a kubeconfig entry and has none in-cluster), and the counts are **identical** to the
equivalent external kubeconfig run. In-cluster is a way of obtaining a credential, not a different
product.

## 13. Security regressions, re-proven against a real cluster

**Exec auth: REFUSED BEFORE EXECUTION.** A kubeconfig for the real API server whose user carries an
`exec` plugin that would `touch` a sentinel: exit **2**, sentinel **absent**, API server counted
**0** requests, and neither `/bin/sh` nor the sentinel path in any output. The harness never needs
exec enabled anywhere.

**Credential authority: API SERVER ONLY.** Over a whole real run every observed request addressed
the target's own namespace, and none reached `/proxy`, `/exec`, `/portforward` or `/log`. The
strongest form of this invariant is structural: svcdoctor issues three reads and connects to
nothing it learns from them, so there is no path a credential could travel.

**Data minimization: PASS**, audited over **generated output** in three modes — text, JSON and
shareable. A fixture plants a marker in a Pod name, a label value and two annotations, and the
report is searched for that marker plus the real Pod IP, the ClusterIP, the Pod UID, the Service
UID and the kubeconfig path. **None appears.** Each value is asserted non-empty first, so its
absence proves something.

**No kubectl at runtime: NONE required.** A diagnosis completes with an empty `PATH`, no `HOME`
and no `KUBECONFIG`. The harness uses `kubectl`; the product does not.

## 14. Determinism and entry-point equivalence

**Determinism: PASS.** Eight repeated runs against a stable four-slice fixture produce
byte-identical canonical JSON with only `startedAt` and `duration` blanked — the repository's
existing policy, and nothing else normalized away. Evidence ordering, finding ordering, attributes,
recommendations and subject IDs are all compared.

**Leaf/fleet equivalence: PASS**, on a real cluster, across **healthy · selects no pods · no ready
endpoint · service not found**. `svcdoctor diagnose kubernetes` and `svcdoctor run --config`
produce the **same canonical report**, compared whole. One fixture path, not two.

## 15. The `401` decision

**Measured against a real API server**: a bearer token the cluster does not accept produces
`k8s.api_access` **FAIL** with `AUTH_CREDENTIALS_REJECTED`, the three reads `SKIPPED`, a
`DIAG_FAILURE_BOUNDARY` localizing where observation stopped, `SummaryStatus` **OK**, and exit
**0**. No Kubernetes finding code, exactly as ADR 0094 §10.4 specifies.

**Decision: it remains a CONTRACT-CONFORMANT KNOWN LIMITATION and is not a release blocker for the
compatibility claim this phase makes.** Three reasons:

1. The behaviour is what the frozen contract says, measured rather than assumed.
2. The run is **not silent**: the boundary finding says where observation stopped, and the evidence
   node carries the credential rejection with its failure class. An operator reading the report
   learns what happened; what they do not get is a non-zero exit.
3. Changing it needs a **fifth finding code**, which ADR 0094 §7 makes a decision with its own
   record, and §4 of this phase puts out of scope.

**It is recorded as a limitation in `docs/COMPATIBILITY.md`, in the README and in
`docs/BACKLOG.md`, and it is pinned by a real-cluster test** so that a future change to it is a
failing test rather than a discovery. A phase that wants to close it should weigh it as its own
decision; nothing here forecloses that.

## 16. The inert `step_timeout` — closed

**The gap, proven from source before it was closed**: `internal/fleet/services/kubernetes` refused
an inert `tls:` block and an inert `credentials.username`, and accepted a written `step_timeout`
that nothing reads. `app.KubernetesParams` has no step-timeout field, the runner passes none, and a
grep of `.StepTimeout` shows the other four services threading it into a probe chain while
Kubernetes appears nowhere. Phase 12.1C.1 refused `--step-timeout` on the leaf command for exactly
that reason; the two entry points disagreed about the same non-existent capability.

**The correction, and why it is the smallest one.** `Common.StepTimeout` is *resolved* and never
zero, so a service cannot tell an operator's `10s` from silence. One additive field —
`Common.StepTimeoutDeclared` — carries the written-ness, exactly as `Port *int` in the schema
already carries it for a different field and for the same reason. The Kubernetes decoder then
refuses it through `config.InvalidField`, which is the mechanism it already uses twice.

**Generic fleet semantics are unchanged.** Four services ignore the new field;
`TestTheOtherServicesStillAcceptAStepTimeout` drives all four through the real loader and asserts
they still accept the key.

**No ADR is needed and no released behaviour changes.** A Kubernetes target exists in **no
published release**, so there is no configuration in the world that this refuses and previously
accepted.

## 17. Boundaries, re-proved after the change

| | |
|---|---|
| Kubernetes finding codes | **4** |
| Total finding codes | **69** |
| Production rules | **24** |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1** |
| Failure classes | **42** |
| Kubernetes public flags | **10** |
| New `k8s.io` import paths | **0** |
| New `Reveal` / `SecretFor` sites | **0 / 0** |
| Relation producers added | **0** |
| Planner | **none** |
| Renderer files changed | **0** |
| External modules | **40** |

## 18. Testing

**Real-cluster suite**: 30 tests, 50 including subtests. **CURRENT 70.8 s**, **OLDER 71.6 s**,
same binary, identical results. Cluster creation 38 s / 32 s. Whole gate ≈ 2 minutes per lane.

**Mutation**: `scripts/phase121d-mutations.sh`, **7 planted / 7 caught / 0 survivors**, tree
restored byte-for-byte. The suite is small **because the phase changed almost no production
behaviour** — manufacturing production mutations for a validation phase would measure nothing —
and it mutates the one change that was made, in both directions: removed, inverted, hard-wired
true, hard-wired false, wrong error class, applied to every service, and naming no field.

**Historical regression**: Phase 9.1A 20/0 · 9.1B 31/0 · 9.1C 45/0 · 12.1B 41/0 · 12.1C 42/0 ·
12.1C.2 28/0. The Phase 9 fleet suites were re-run because `internal/fleet/config` changed.

**Race**: `go test -race ./internal/fleet/config ./internal/fleet/services/kubernetes` — **green**.
Targeted rather than repository-wide: the production change is one struct field and one pure
validation function on a path that starts no goroutine, and Phase 12.1C.2's full `-race` sweep over
the same package set was green with nothing concurrency-sensitive moving since.

### 18.1 One methodological error, and it is reported rather than absorbed

A `make check`-adjacent run of `./internal/cli` failed once with
`` `run --password-file` was not refused as unknown ``, and the cause was **this session, not the
code**: a historical mutation harness was running in the background with a plant in
`internal/cli/root.go` at that moment. The repository's own rule — *do not run `make check` while a
mutation is planted* — applies in the other direction too, and it was broken here.

The test passes deterministically in isolation over six consecutive runs and in every subsequent
full run, and the final gate below was taken with every harness idle and the tree verified restored
byte-for-byte. Recorded because a reader finding that failure in a transcript deserves to know it
was a harness collision and not a flaky guard.

**Fuzz**: not extended. 12.1D introduces no parser and no new boundary; the existing Kubernetes
parser and CLI targets are unchanged and green.

**`make check`**: green. **`git diff --check`**: clean.

## 19. CI strategy

**Recommended, not added.** No CI workflow changed in this phase: the repository's existing
integration lanes are all local `make` targets with no GitHub Actions lane, and adding the first
one for Kubernetes would be a workflow decision this phase did not measure the cost of on hosted
runners.

The measured local cost is the input to that decision: **≈2 minutes per lane**, ~1.2 GB of image
per node version, 4 CPU and 6 GiB sufficient. That is cheap enough for a PR lane on one version
and a scheduled lane for the matrix, which is the shape the repository's conventions would suggest.
Whoever adds it should pin the action versions and the node digests as `Makefile` already does, and
keep the generated kubeconfig out of any log.

## 20. Known limitations

1. **A `401`, an unreachable API server and a `5xx` all exit 0.** §15. Contract-conformant, pinned
   by a real-cluster test, and a fifth code is a decision with its own record.
2. **Dual-stack was not exercised** — environment capability absent. §10.
3. **No budget ceiling was driven on a real cluster.** 4,000 Pods / 256 slices / 10,000 endpoints
   stay hermetically tested constants, deliberately.
4. **No real-cluster timeout test.** Deterministic delay injection would need a proxy that stalls,
   an admission webhook or an API-server change; the existing hermetic timeout proof is the
   stronger deterministic test and the architecture was not widened to beat it.
5. **Two minors, not a range.** v1.32 and v1.33 have kind images and were not run. svcdoctor does
   no version arithmetic and the compatibility table makes no prediction about them.
6. **No distribution is graded.** EKS, GKE and AKS are additionally gated by ADR 0094 §2.2's
   `exec` refusal, which their default kubeconfigs trip.
7. **The kubeconfig `tokenFile` mode was not separately re-run on a real cluster.** It feeds the
   same token path `--token-file` exercises, and that path is validated here.

## 21. Deferred work

A fifth finding code for `401`, if a phase decides to want one. A CI lane. Dual-stack, on a lane
that has it. Any distribution grading, each of which needs its own evidence.
