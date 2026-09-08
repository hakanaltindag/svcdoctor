# Phase 12.2A — Kubernetes CI and release-gate contract freeze

- **Phase:** 12.2A (docs-only contract freeze; **no** production, test, CI or configuration change)
- **Baseline:** `cea71a9fbf53cff5849c1c77d5d471267278bd3f`, equal to `origin/main`, clean tree,
  `make check` green before anything was edited
- **Question:** what is the smallest sustainable CI and release gate that keeps Phase 12.1D's
  real-cluster proof from decaying, without making ordinary development expensive or fragile?
- **Answer:** **MODEL B** — one pinned CURRENT lane on every pull request, both graded lanes weekly,
  on demand and as a structural release gate inside `release-oci.yml`; **one** test tier, which is
  the whole suite
- **Outcome:** ADR **0095** Accepted. Phase 12.2B is authorized, with a fixed file surface and a
  closure policy that does not let a workflow call itself a gate before it has run
- **Blockers:** none open

---

## 1. Baseline

```
HEAD        cea71a9fbf53cff5849c1c77d5d471267278bd3f  test(kubernetes): validate real-cluster compatibility
origin/main cea71a9fbf53cff5849c1c77d5d471267278bd3f
tree        clean
make check  GREEN
```

Everything below was measured against that tree. Nothing was designed from memory, and where this
document and the phase brief disagree, §5.1 records it.

## 2. Current CI inventory — measured, not inferred

Five workflows exist. **None of them runs a Kubernetes cluster, and no Make target for one is
called anywhere in `.github/`.**

| File | Name | Triggers | Jobs | Runner | Go | Permissions | Concurrency | Timeout | Artifacts | Publishes |
|---|---|---|---|---|---|---|---|---|---|---|
| `ci.yml` | `CI` | `push` to `main`, `pull_request` | `check` | `ubuntu-latest` | `setup-go`, `'1.26'` | `contents: read` | `ci-${ref}`, cancel **true** | **none** | none | no |
| `validate-integration.yml` | `Validate integration (Linux, no publication)` | `workflow_dispatch`, `push` to `validate-integration/**` | `guard`, `suites`, `integration` (matrix), `summary` | `ubuntu-latest` | `'1.26'` | `contents: read` | `validate-integration-${ref}`, cancel **true** | **none** | none | no |
| `release-oci.yml` | `Release OCI` | `push` tag `v*` | `identity`, `source`, `integration` (matrix), `archives`, `stage-and-verify`, `publish`, `release`, `summary` | `ubuntu-latest` | `'1.26'` | `contents: read` default; per-job `packages: write`, `id-token: write`, `contents: write` (release job only) | `oci-release-${ref}`, cancel **false** | **none** | archives, SBOM | **yes** |
| `oci-stage-verify.yml` | shared machinery | `workflow_call` | staging, scan, sign, verify, smoke | `ubuntu-latest`, one `ubuntu-24.04-arm` | — | scoped per job | inherited | **none** | staging | stages |
| `validate-oci.yml` | OCI rehearsal | `workflow_dispatch` | rehearsal via the shared workflow | `ubuntu-latest` | `'1.26'` | scoped per job | own group | **none** | — | dev tag only |

Answers to the questions §6 of the brief asks, each measured:

| Question | Answer |
|---|---|
| PR validation workflow? | **Yes** — `ci.yml`, hermetic quality gate only |
| Release workflow? | **Yes** — `release-oci.yml`, tag-driven on `v*` |
| Scheduled workflow? | **No.** `schedule:` appears in no workflow |
| Integration tests in Actions? | **Yes** — `postgres`, `kafka`, `redpanda` only, in `release-oci.yml` and `validate-integration.yml`. Redis, Valkey, RabbitMQ, LavinMQ, multi-target and Kubernetes run **nowhere** in CI |
| Mutation suites in Actions? | **No.** All eight `scripts/phase*-mutations.sh` are local-only |
| Is `make check` run in Actions? | **Yes**, in `release-oci.yml`'s `source` job. `ci.yml` runs its constituents individually plus `golangci-lint-action` |
| Is release gated on CI? | **Yes, structurally.** `stage-and-verify` and `publish` both `needs: integration`, pinned by `TestOCIPublicationCannotStartBeforeLinuxIntegration` |
| Are tags protected by a validation workflow? | The tag *is* the trigger; the gates run inside the same workflow and precede publication |
| Are workflow permissions minimal? | **Yes**, and enforced: default `contents: read` everywhere, escalation per job, `contents: write` held by exactly one job |
| Is dependency caching used? | Only `actions/setup-go`'s default module cache. No explicit `actions/cache` |
| Are action references pinned? | **All but one**, by full commit SHA |
| Are job timeouts set? | **No.** `timeout-minutes` appears **zero** times across all five files |

### 2.1 Supply-chain posture of the existing workflows

| Reference | Class |
|---|---|
| `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1` | FULL_COMMIT_SHA |
| `actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | FULL_COMMIT_SHA |
| `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` | FULL_COMMIT_SHA |
| `actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093` | FULL_COMMIT_SHA |
| `docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` | FULL_COMMIT_SHA |
| `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9` | FULL_COMMIT_SHA |
| `sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6` | FULL_COMMIT_SHA |
| `aquasecurity/trivy-action@d2a0b60797ff03db6132bd4e2b293f9b37081297` | FULL_COMMIT_SHA |
| `./.github/workflows/oci-stage-verify.yml` | LOCAL_ACTION |
| `golangci/golangci-lint-action@v9` | **VERSION_TAG**, justified in place, tracked as UX-S16-b |

**The policy is already written and already enforced.** ADR 0076 §2.6 requires a commit SHA;
`TestUX22TheSupplyChainPinningIsRecorded` globs every `.github/workflows/*.yml`, and an unpinned
action fails unless the comment block above it contains the words `NOT SHA-pinned`. That guard covers
any new workflow automatically, with no edit.

**Nothing is installed by `curl | sh` anywhere.** `golangci-lint` is installed in `release-oci.yml`
with `go install …@v2.13.1`, and the comment says why: it goes through the Go module proxy so it is
checksum-verified "rather than fetched by a piped shell script into a job that later holds
`packages: write`". That precedent decides §8 of this document.

No `dependabot.yml` and no Renovate configuration exist. None is introduced.

## 3. Phase 12.1D measured inputs, re-verified from the repository

All of the following were read back from the repository, not from the phase brief.

| Input | Value | Source |
|---|---|---|
| CURRENT lane | `kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a` | `Makefile:596` and 12.1D §3 |
| OLDER lane | `kindest/node:v1.31.12@sha256:0f5cc49c5e73c0c2bb6e2df56e7df189240d83cf94edfa30946482eb08ec57d2` | `Makefile:597` and 12.1D §3 |
| `kind` | v0.30.0 | 12.1D §2; `Makefile:611` install hint |
| Real-cluster tests | **30** functions, ≈50 with subtests | counted in `test/integration/kubernetes/*.go` |
| Suite runtime | CURRENT **70.8 s**, OLDER **71.6 s** | 12.1D §18 |
| Cluster creation | 38 s / 32 s | 12.1D §18 |
| Whole gate | **≈2 minutes per lane** | 12.1D §18 |
| Environment | 4 CPU, 6,197,383,168 B (≈5.77 GiB), Ubuntu 24.04 **aarch64**, Colima 0.8.4, Docker 28.3.3 | 12.1D §2 |
| Nominal request count | **3**; selector-less **1**; 600-Pod pagination **4 total / 2 Pod LIST**; refused `exec` **0** | 12.1D §11, §13 |
| Cluster shape | **one control-plane node**, `maxPods: 800` | `test/integration/kubernetes/env/cluster.yaml` |
| Dual-stack | **NOT validated** — environment capability absent | 12.1D §10, §20.2 |
| Compatibility | v1.34.0 and v1.31.12, **Level 3 — SUPPORTED BASIC**, and nothing else | `docs/COMPATIBILITY.md` §4d |
| v1.21 | architectural minimum only, **not** a compatibility claim; `kind` v0.30.0 cannot run it | ADR 0094 §2.11, 12.1D §3.1 |

The scenario inventory the brief lists is present in full: K1–K7, R1–R3, E1–E5, A1–A5, the
owner-generation guard, third-party-managed slice, multi-slice, 600-Pod real pagination, in-cluster
authentication, external kubeconfig, `--token-file`, `--token-stdin`, client certificate,
leaf/fleet equivalence, determinism over eight runs, data minimization, credential authority, no
`kubectl` at runtime, exec-auth refusal, and the real `401` measurement.

### 3.1 Two discrepancies against the phase brief, and the repository wins both

1. **Architecture.** 12.1D ran on **`aarch64`** under Colima on macOS. Every GitHub-hosted
   `ubuntu-*` runner is **`amd64`**. The first CI run of this suite will therefore be its **first
   `amd64` execution**, and this repository has already lost a release (`v0.3.1`) to exactly one
   such platform difference. This is the single most important thing 12.2B's first hosted run
   proves, and it is why §16 refuses to call the gate operational before that run.
2. **Memory.** The brief says "~6 GiB RAM"; the record says 6,197,383,168 B, which is ≈5.77 GiB.
   The distinction matters only because the CI contract states an assumed floor, and the floor is
   taken from the measured value rather than from the rounded one.

A third item is an inference rather than a discrepancy, and is flagged as one: the two node-image
digests were pulled successfully on `arm64`, which is only possible if each digest names a
**multi-architecture index** rather than an `amd64`-only manifest. That is strong evidence the same
digests pull on an `amd64` runner, and it is not proof. It is the second thing the first hosted run
confirms.

## 4. Trust boundary

| Trigger | Decision | Reason |
|---|---|---|
| `pull_request` | **ADMIT** | Runs the pull request's own code with a read-only token and no secrets |
| `push` (branch `main`) | **ADMIT** | Post-merge confirmation on the integration branch |
| `pull_request_target` | **REFUSE** | Would execute untrusted pull-request code with the base repository's token and secret access. This lane runs arbitrary repository code inside a container runtime, which is the worst possible place for that trigger |
| `schedule` | **ADMIT** | The compatibility lane |
| `workflow_dispatch` | **ADMIT**, with **no free-form input** | Debugging and dependency-bump verification. Lane choice comes from the frozen matrix; no image reference may be supplied |
| `push` tag `v*` | **ADMIT**, inside `release-oci.yml` | The release gate |

**Permissions: `contents: read` at workflow level, no job escalation.** No `packages: write`, no
`id-token: write`, no `contents: write`, no `actions: write`. Measured requirement: checkout, Go
setup, Docker, and a `kind` cluster on the runner — none of which needs any write scope.

**Repository secrets: NONE, and none is needed.** The cluster, its CA, its client certificate and
key, and every ServiceAccount token the fixtures mint are created on the runner and destroyed with
the cluster. **If a future revision of this lane requires a repository secret, the design is
rejected** — that is the §49 stop condition, and it does not fire here.

**Fork pull requests run the lane normally.** They receive a read-only `GITHUB_TOKEN` and no secret,
which is exactly the posture this lane wants, so forks need no special case. (GitHub's
first-time-contributor approval setting may hold the run for a maintainer's click; that is a
repository setting, not a workflow property, and it is listed under §17.)

## 5. Secret and log hygiene

The contract is an **allowlist**, and the good news is that the harness already implements it.

**Admitted output**

- lane name and the node image reference
- `kind` version, `kubectl` client version, API server `gitVersion` (already printed by
  `kubernetes-up`)
- runner uid/gid/architecture and `docker version` — the precedent set by
  `validate-integration.yml`'s "Record the runner's file identity" step, which existed because a
  release was lost to exactly that unknown
- both binary SHA-256 digests (already printed by `kubernetes-test`)
- `go test` output, including the harness's failure dump: `kubectl get {service,pod,endpointslice}
  -o wide`, **scoped to the failing test's own namespace**
- exit codes, finding codes and evidence states as the tests assert them; test timings

**Refused, absolutely**

- kubeconfig content, ServiceAccount tokens, `Secret` objects, private keys
- `kubectl cluster-info dump`, any cluster-wide `get -A`, any environment dump
- `set -x` or equivalent tracing anywhere near credential handling
- workflow-level collection of container logs

**Already true at the baseline, and verified here:**

- `harness.dumpDiagnostics` prints three kinds, namespace-scoped, on failure only, with the reason
  in its doc comment.
- `test/integration/kubernetes/env/kubeconfig.generated` is `.gitignore`d (line 69) and `chmod 600`
  by `kubernetes-up`; `git check-ignore` confirms both it and `bin/`.
- No workflow uses `set -x`. The token paths under test use `--token-stdin` and `--token-file`, so
  no token is ever an `argv`.

**No artifact is uploaded.** Option A of §26 of the brief. The log already carries everything the
allowlist admits, and an upload step is a second exfiltration surface in the one lane that handles
kubeconfigs, tokens and client keys. If artifacts are ever wanted, the allowlist above is the
starting point and the reopen condition is in ADR 0095 §7.

## 6. CI model comparison

Estimates are derived from the measured local run plus the setup steps a hosted runner adds. Billing
is expressed in **runner-minutes**, rounded up per job as GitHub does; no monetary value is invented.

Per-job cost, cold:

| Step | Estimate |
|---|---|
| checkout | ~5 s |
| `setup-go` with module cache | 10–25 s |
| `go install sigs.k8s.io/kind@v0.30.0` | 45–75 s cold, ~10 s warm |
| `kubectl` install (pinned download + checksum) | ~5 s |
| node image pull (~1.2 GB) + `kind create` | 90–150 s |
| build host + Linux binaries | 60–120 s cold, 15–30 s warm |
| suite | **71 s** (measured) |
| teardown | ~10 s |
| **total** | **≈5–7 minutes** |

| Model | Jobs/PR | Jobs/scheduled | Runner-min/PR | Feedback latency | Compatibility coverage | Flake exposure | Verdict |
|---|---|---|---|---|---|---|---|
| **A** — both lanes every PR | 2 | — | ≈14 | immediate | both, continuously | 2× | **Rejected**: doubles cost for signal 12.1D measured as identical |
| **B** — CURRENT on PR, both on schedule/release | **1** | **2** | **≈7** | immediate for regressions | both, weekly and at every release | 1× | **SELECTED** |
| **C** — PR smoke subset, everything scheduled | 1 (shorter) | 2 | ≈6 | immediate but partial | both | 1× | **Rejected**: saves <1 min of a 6-min job and removes the security gates from PR |
| **D** — no PR gate, scheduled only | 0 | 2 | 0 | up to 7 days, or the release tag | both | 1× | **Rejected**: late signal attached to the wrong commit |

**Selected model versus the strongest rejected alternative (A):** B costs ≈7 runner-minutes per pull
request against A's ≈14, and adds ≈14 weekly plus ≈14 per release. For a repository with, say, 20
pull requests a month, B is ≈140 + ≈60 = ≈200 runner-minutes and A is ≈280 + ≈60 = ≈340 — a saving
of ≈40% for, by measurement, no loss of regression signal.

### 6.1 The expected candidate is proven, not assumed

The brief's candidate — one CURRENT lane on pull requests, CURRENT + OLDER on schedule and release —
is **confirmed**, and the evidence that confirms it is specific:

> **12.1D §18: "same binary, identical results"** on both lanes.

The older lane therefore carries **compatibility** information (does svcdoctor still meet an older
API server the same way?) and not **regression** information (did this commit break Kubernetes
diagnosis?). Regression signal must arrive on the commit; compatibility signal must arrive before a
claim is published. Those are two different triggers, and this is what makes the second lane worth
its cost weekly and at a release, and not worth it on every pull request.

**The one residual risk is named rather than engineered around.** A `client-go` bump is a pull
request whose older-lane effect the CURRENT lane cannot see. It is caught by the next scheduled run
or by the release gate, whichever comes first, and it **cannot reach a published release**, because
the release gate runs both lanes. A reviewer who wants the answer immediately dispatches the full
matrix manually — which is precisely why `workflow_dispatch` is admitted, and it is a cheaper escape
hatch than conditional matrix logic that would have to be maintained forever.

## 7. Test tiering — refused, on measurement

**Option A of §12: run the exact full suite in every lane.**

The suite is **71 s of a ≈5–7 minute job**. Cluster creation, node-image pull, tool installation and
the Go build are paid in full by every tier, so a core/extended split saves under a fifth of the job.
Against that saving sits a permanent risk: the tests most likely to be quietly moved out of the
pull-request tier are the slow structural ones, and in this suite those are

- `TestAnExecCredentialPluginIsStillRefusedAgainstARealCluster`
- `TestTheKubernetesCredentialReachesOnlyTheAPIServer`
- `TestNoRealClusterReportCarriesMaterialTheContractExcludes`
- `TestRepeatedRunsOfAStableFixtureAreByteIdentical`

That is the brief's own rule — *"do not move security gates out of PR merely because they are
inconvenient"* — arriving as a consequence rather than as a warning.

**A second, decisive consequence:** with one tier, Phase 12.2B needs **no change to
`test/integration/kubernetes/**` and no change to the `Makefile`.** Tier selection was the only thing
that would have required either. The implementation reduces to workflow files, one helper script, one
guard-test file and documentation.

### 7.1 §13's classification, resolved in full

Because there is exactly one tier, every invariant is **BOTH** — it runs on pull requests, on the
scheduled matrix and at the release gate. The table is filled in anyway, because the brief requires
each row to be resolved and because the "would this have been PR-only?" column is what a future tier
proposal has to argue against.

| | Invariant | Tier | Would survive a hypothetical PR-only tier? |
|---|---|---|---|
| P1 | external kubeconfig execution | BOTH | yes — every scenario depends on it |
| P2 | healthy Service | BOTH | yes — the base case |
| P3 | F1 Service not found | BOTH | yes — cheap, high-value |
| P4 | F2 real RBAC | BOTH | yes — three real identities, and the exit-code distinction of 12.1D §8.1 |
| P5 | F3 selects zero Pods | BOTH | yes |
| P6 | F4 no ready endpoint | BOTH | yes |
| P7 | F3/F4 disjointness | BOTH | yes — the reconciliation 12.1C had to make |
| P8 | selector-less / ExternalName | BOTH | yes — also pins the 1-request budget |
| P9 | headless semantics | BOTH | yes |
| P10 | EndpointSlice ready/nil semantics | BOTH | yes — E3 is the likeliest hand-analysis error |
| P11 | Service generation guard | BOTH | yes |
| P12 | exec-auth refusal | BOTH | **yes, mandatory** — a security gate, never tier-demoted |
| P13 | credential non-observability | BOTH | **yes, mandatory** — the data-minimization scan |
| P14 | exact API request budget | BOTH | yes — the cheapest proof that no hidden call appeared |
| P15 | leaf/fleet equivalence | BOTH | yes — two entry points, one report |
| P16 | in-cluster authentication | BOTH | borderline: it builds an image and loads it, the most expensive single scenario |
| P17 | token-file / token-stdin | BOTH | yes |
| P18 | client certificate auth | BOTH | yes — it is how every other scenario authenticates |

### 7.2 §14's extended membership, resolved

Because the tier is the whole suite, the extended gate's membership is *the same suite on a second
Kubernetes version*, and that is the only difference between the two lanes.

| Item | In extended | Note |
|---|---|---|
| older Kubernetes lane | **YES** | this is what "extended" means here |
| full EndpointSlice E1–E5 | YES | in both lanes |
| association A1–A5 | YES | in both lanes |
| delete/recreate generation guard | YES | in both lanes |
| third-party managed slice | YES | in both lanes |
| multi-slice | YES | in both lanes |
| 600-Pod pagination | YES | in both lanes |
| in-cluster execution | YES | in both lanes |
| all auth modes | YES | in both lanes |
| determinism repetitions | YES | eight runs, in both lanes |
| leaf/fleet equivalence | YES | in both lanes |
| data-minimization scan | YES | in both lanes |
| credential-authority trap | YES | in both lanes |
| no-`kubectl`-runtime-dependency | YES | in both lanes |
| real `401` | YES | in both lanes |
| exact request counts | YES | in both lanes |
| dual-stack | **NO** | not producible: both lanes' API Service reports `ipFamilies=IPv4` (12.1D §10). Not a gap this contract can close |

## 8. Tool installation and pinning

| Input | Mechanism | Class |
|---|---|---|
| `kind` **v0.30.0** | `go install sigs.k8s.io/kind@v0.30.0` | semantic version; integrity from the module proxy and `sum.golang.org` |
| `kubectl` | pinned version, verified against a SHA-256 **recorded in the repository** | semantic version **and** immutable digest |
| CURRENT node image | `kindest/node:v1.34.0@sha256:7416a61b…` | semantic **and** immutable |
| OLDER node image | `kindest/node:v1.31.12@sha256:0f5cc49c…` | semantic **and** immutable |
| Go | `go-version-file: go.mod` | single source of truth |
| Actions | the SHAs already in this repository | immutable |
| Runner | `ubuntu-24.04` | **generation pin only** |

**Strategy chosen for `kind`: A (`go install` at a pinned version).**

| Strategy | Supply chain | Reproducible | Cacheable | Complexity | Verdict |
|---|---|---|---|---|---|
| **A** `go install …@v0.30.0` | module proxy + `sum.golang.org` | yes | yes, by `setup-go`'s cache | one line | **SELECTED** |
| B downloaded binary + checksum | needs a digest this phase cannot verify | yes | manual | script + digest | rejected for `kind`; used for `kubectl` only because A does not exist there |
| C third-party `setup-kind` action | new action to pin and trust | yes | its own | new dependency | rejected |
| D repository-owned bootstrap | as A or B underneath | yes | yes | most | rejected as a wrapper around A |

A is also the mechanism this repository already chose for `golangci-lint` in `release-oci.yml`, for
the stated reason that it is checksum-verified rather than piped from a shell script — and the
`Makefile`'s own error message already tells a developer to install `kind` this exact way. No new
convention is created.

**`kubectl` is fixture-only and still gets pinned.** It never touches the product — 12.1D §13 proves
a diagnosis completes with an empty `PATH`, no `HOME` and no `KUBECONFIG` — and its failure mode is a
red lane rather than a false green, because the harness `t.Fatal`s on a failed `kubectl`. Even so,
**the ambient `kubectl` a runner image happens to ship is refused**: it is an unpinned input to a
release gate, and every other input here is pinned.

**This phase does not write the `kubectl` checksum**, and that is a decision rather than an omission.
Phase 9.2B faced the same question for `golangci-lint-action@v9` and recorded the answer in the
workflow itself: *"a plausible wrong one is precisely the supply-chain defect the pin exists to
prevent."* So 12.2A freezes the **policy** — pinned version, checksum recorded in the repository,
lane fails on mismatch, never the ambient copy — and 12.2B obtains and verifies the digest from the
upstream publisher. That is measurement deferred to the phase that can take it, not an unresolved
contract row.

**Refused outright:** `curl | sh`, `latest` binaries, floating `kind` versions, floating node images,
any dynamic discovery of a Kubernetes version.

## 9. Runner, resources, Go and Docker

**Runner: `ubuntu-24.04`.** An explicit generation pin, diverging from the twenty existing
`ubuntu-latest` uses, and the divergence is justified: this is the repository's most
environment-sensitive lane — kernel, cgroups, Docker version and container runtime all matter to
`kind` — and `ubuntu-latest` silently rolls to the next LTS. Migrating the other workflows is out of
scope and is not implied.

**`ubuntu-24.04` is a generation pin and not a supply-chain pin.** GitHub rebuilds runner images
continuously; the label fixes the OS generation only. No document may describe it as immutable.
**Response to deprecation:** when GitHub announces the label's retirement, the bump is an explicit
pull request that re-runs **both** lanes before merge, exactly like a `kind` bump.

**Resource contract.** 12.1D passed with **4 CPU and ≈5.77 GiB**, one control-plane node,
`maxPods: 800`. GitHub's published specification for standard hosted runners on public repositories
is 4 vCPU / 16 GB RAM / 14 GB SSD, which meets or exceeds every measured requirement; that is a
documented property to be **confirmed by the first real run**, not a measurement this phase took.

**One control-plane node, unchanged.** svcdoctor reads three API objects and connects to no Pod. A
worker node would add startup time and prove nothing, and `cluster.yaml` already says so. Multi-node
`kind` is refused because no frozen semantic requires it.

**Docker** is present on hosted Linux runners and its absence is a **failure**, never a skip.

**Go: `go-version-file: go.mod`.** `go.mod` declares `go 1.26.0`; the five existing workflows
hard-code `'1.26'` in six places. §20 of the brief forbids a second source of truth, so the new
workflow reads `go.mod` and nothing else. The trade-off is recorded: `go 1.26.0` resolves to that
exact patch rather than the newest `1.26.x`, so a toolchain patch bump becomes a `go.mod` edit — an
explicit pull request, which is consistent with every other pin in this contract. The existing
workflows are not changed; that is tracked in `docs/BACKLOG.md`, not done here.

## 10. Selected architecture

**Two files, one gate, no new mechanism.**

```
.github/workflows/kubernetes.yml        pull_request · push(main) · schedule(weekly) · workflow_dispatch
    └── matrix: lane ∈ {current}                on pull_request and push
        matrix: lane ∈ {current, older}         on schedule and workflow_dispatch

.github/workflows/release-oci.yml       (existing, one job added)
    └── job `kubernetes`, matrix lane ∈ {current, older}
        stage-and-verify  needs: [… , kubernetes]
        publish           needs: [… , kubernetes]
```

**Why the release gate is a job and not a workflow.** GitHub cannot make one workflow depend on
another's recent result, and "a green run last Tuesday" is a statement about a different commit.
`release-oci.yml` already enforces its integration gate through `job.needs`, and
`TestOCIPublicationCannotStartBeforeLinuxIntegration` already fails the build if that dependency is
removed. Putting the Kubernetes gate anywhere else would make it a gate in prose only.

This is architecture **E** of §15 (separate workflows sharing Make targets) with the release gate
placed inside the release workflow, which is where it can be enforced. **A** alone would leave no
scheduled decay detection; **B** (release relies on a recent scheduled run) is unenforceable; **C**
without the job would be the same unenforceable thing; **D** (one reusable `workflow_call` lane) was
considered and rejected as premature — the lane body is four steps, the repository's `oci-stage-verify.yml`
extraction was driven by a large signing-and-verification pipeline, and the closer precedent is
`validate-integration.yml` and `release-oci.yml`, which duplicate a four-step integration job on
purpose because the `make` target is the shared machinery.

### 10.1 Schedule cadence: weekly

Every input to this lane is pinned — node images by digest, `kind` by version, Go by `go.mod`,
actions by SHA. The only inputs that move on their own are the runner image and the Docker version
that ships with it. Those change on the order of weeks.

| Cadence | Verdict |
|---|---|
| daily | Rejected — ~5× the cost to detect a class of change that does not arrive daily. Scheduling for activity's sake |
| **weekly** | **SELECTED** — a runner-image change is attributable within days, and the cost is ≈14 runner-minutes a week |
| twice weekly | Rejected — no failure mode is described by "within 3 days but not within 7" |
| monthly | Rejected — a month of merges between the failure and its signal makes attribution expensive |

Fixed at **`cron: '17 4 * * 1'`** — Mondays, and deliberately not on the hour, because scheduled runs
that cluster on `:00` are the ones GitHub delays most.

### 10.2 Matrix design

One dimension: **`lane`**. Its two values carry the Kubernetes version and the node image with them,
via the `Makefile`'s existing `KIND_NODE_current` / `KIND_NODE_older` constants, so the workflow
names a lane and never an image.

Maximum width: **1 job on a pull request, 2 on a scheduled or dispatched run, 2 in the release
workflow.** Authentication mode, scenario and Service shape are **not** matrix dimensions — they
execute inside one lane, as they do locally. `fail-fast: false`, so a failing lane never hides the
other's result.

### 10.3 Naming — frozen, because required checks may depend on it

| Surface | Name |
|---|---|
| Workflow | `Kubernetes` |
| Job (standalone workflow) | `${{ matrix.lane }}` → check names `Kubernetes / current`, `Kubernetes / older` |
| Job (release workflow) | `Kubernetes (${{ matrix.lane }})`, matching the existing `Integration (postgres)` style |

**No Kubernetes version appears in any check name.** A check called
`Kubernetes / Compatibility (v1.34.0)` would have to be re-configured in branch protection every time
the lane advanced, which is churn a version bump should not cause. The lane name is stable; the
version it points at is data.

### 10.4 Concurrency

| Trigger | Group | `cancel-in-progress` |
|---|---|---|
| `pull_request` | `kubernetes-${{ github.event_name }}-${{ github.ref }}` | **true** — a superseded commit should not keep a cluster alive |
| `push`, `schedule`, `workflow_dispatch` | same expression, which separates them by event | **false** |
| release job | inherits `oci-release-${{ github.ref }}`, `cancel-in-progress: false` | **false** — a release gate is never cancelled |

The event name is in the group deliberately: without it, a scheduled run on `main` and a push to
`main` share a group, and one would cancel the other.

### 10.5 Timeout

**`timeout-minutes: 40`** on the lane job. Not a number chosen from the local runtime.

`kubernetes-test` runs `go test … -timeout 30m`. A job timeout below that would kill the job
*before* the Go test timeout fires, destroying the goroutine dump that is the most useful artefact a
hang produces. So the job timeout must exceed 30 m plus setup, and 40 minutes leaves margin for a
cold image pull. GitHub's default is 360 minutes; this is a large improvement on it, and every
existing workflow in this repository sets none at all.

### 10.6 Cache

**`actions/setup-go`'s default module and build cache, keyed on `go.sum`. Nothing else.**

It is free, already the repository's only caching, and it matters more here than anywhere: 40 modules
including `k8s.io/client-go`, and `go install sigs.k8s.io/kind` benefits from the same cache.

**Refused:** node-image caching (moving ≈1.2 GB through the Actions cache to avoid pulling ≈1.2 GB,
against a 10 GB budget, with no established saving), `kind` binary caching (subsumed by the Go build
cache), and — categorically — any caching of a kubeconfig, a token or cluster state.

## 11. Local/CI parity, teardown, flakes and skips

**The `Makefile` is the harness and the workflow calls it.** `make integration-kubernetes` stays the
canonical developer entry point and is what CI runs; `KUBERNETES_LANE=older` selects the second lane,
exactly as a developer selects it.

| Owner | Responsibility |
|---|---|
| **YAML** | runner, checkout, Go setup, tool installation, lane selection, teardown invocation, timeout, permissions, concurrency |
| **Harness (`Makefile` + `test/integration/kubernetes`)** | `kind` lifecycle, `cluster.yaml`, both binaries, fixtures, namespaces, waits, assertions, failure diagnostics, teardown |

**No Kubernetes fixture logic goes into YAML.** Not a manifest, not a `kubectl` invocation, not a
wait loop.

**Teardown: always attempted.** `make` stops at a failing target, so `integration-kubernetes` does
not reach `kubernetes-down` when the suite fails. The workflow therefore adds one step,
`if: always()`, that calls **`make kubernetes-down`** — the harness's own target, containing no
cleanup logic of its own. `kubernetes-down` is already idempotent (`-` prefixes, `--ignore-not-found`),
so the extra call on a successful run is free.

**Flakes: no automatic retry**, of a job, a step or a test. The suite already polls named conditions
under bounded deadlines and contains no `sleep` — 12.1D §6.1 records the one time a wait condition
was too weak and how it was strengthened rather than retried. A repeatable infrastructure failure is
classified, evidenced and fixed in the harness. A retry loop over an RBAC, EndpointSlice, readiness
or pagination race is how that class of bug becomes permanently invisible.

**Skips: refused.** Docker unreachable, `kind` absent, cluster creation failed or node image
unavailable are all **failures**. The harness already enforces it in both places — `kubernetes-up`
refuses and says how to install what is missing, and `newHarness`/`requireBinaries` call `t.Fatalf`
with *"a skipped mandatory gate is not a pass"* written into the message.

## 12. Path filtering — NO

**Refused**, on two grounds and the second is decisive.

*Correctness:* Kubernetes diagnosis sits on the generic core — `internal/domain`, `internal/security`,
`internal/render`, `internal/cli`, `internal/fleet`. A path allowlist would have to name nearly the
whole tree to be safe, and the moment it is incomplete it fails silently, which is the worst failure
mode a gate has.

*Operational:* the honest narrow filter is `paths-ignore` on documentation, and it is technically
sound because this lane runs no documentation guard. It is refused because a required check that does
not run leaves a pull request **pending** rather than green, and the usual workaround is a second
always-succeeding job whose entire purpose is to satisfy branch protection. That is a lie in the job
graph, traded for ≈7 runner-minutes.

**The accepted cost is stated rather than hidden:** a documentation-only pull request — like this
one — spends ≈7 runner-minutes creating a Kubernetes cluster it does not need. The reopen condition
is in ADR 0095 §7.

## 13. Compatibility promotion — CI protects claims, it does not create them

**A green lane authorizes nothing.** Adding a Kubernetes version to the matrix is **not** grading it,
and the separation is enforced by machinery that already exists:
`TestOnlyRealTestedPlatformsClaimLevelTwoOrThree` requires a hand-maintained entry naming the
validation record, and `TestEveryRealTestedPlatformSaysSo` catches the opposite error.

Grading requires all three: an explicit validation record, a `docs/COMPATIBILITY.md` update, and
human-reviewed evidence.

**No `latest`. No dynamic version discovery. No manual input that can name an image.** A dispatched
run picks a lane from the frozen matrix, so it cannot manufacture evidence for an ungraded version.

### 13.1 Version-upgrade policy

**CURRENT** — the newest minor the pinned `kind` release publishes a node image for. Advanced by an
explicit pull request that: pins the new image **by digest** from that `kind` release's own notes,
runs **both** lanes green, and updates `docs/COMPATIBILITY.md` and a validation record in the **same**
change if the claim moves.

**OLDER** — the oldest minor that same `kind` release publishes a node image for. It is a **fixed
validated version, not a moving compatibility floor.** A floor that advanced on its own would change
what a graded row means without anyone deciding to.

**Terminology, frozen:**

- **continuously gated** — in the current matrix; a regression fails a run.
- **validated historically** — measured once, recorded in its validation document, no longer gated.

A row must say which it is. And because Level 3 requires *a committed repeatable fixture*, a version
the pinned toolchain can no longer run is no longer repeatable: at the moment it leaves the matrix
for that reason, its row moves to **Level 2 with a dated note naming its validation record**, in the
same pull request that removes it. Leaving CI for any other reason is not contemplated.

**`kind` upgrades are explicit pull requests.** A `kind` bump re-derives **both** node-image digests,
because the digests belong to the `kind` release rather than to the Kubernetes version, and it
re-runs **both** lanes before merge. Floating or automated `kind` upgrades are refused. No Dependabot
or Renovate configuration exists in the repository and none is introduced; if one is added later, its
first rule must be that `kind` and the node images are excluded from automatic bumps.

## 14. Release-artifact relationship

**Option A: the gate tests a binary built in the validation job**, from the tagged tree, by the
harness's own `CGO_ENABLED=0 go build ./cmd/svcdoctor`.

Option B — validating the exact published release artifact — creates an ordering problem: `archives`
runs before `publish` but the Kubernetes gate must run before `stage-and-verify`, and the OCI image
does not exist until after staging. Making the gate consume either would invert the ordering that
protects publication, or require harness changes this contract forbids.

The difference between the two builds is recorded rather than waved away:
`scripts/build-release.sh` adds `-trimpath -ldflags "-s -w -X main.version=$VERSION"`. That changes
the version string and strips symbols. **No diagnosis, finding, evidence node or exit code reads
either.** Nothing is published for the sake of this lane, and no image is pushed.

## 15. Required checks and branch protection

**UNKNOWN, and deliberately not measured.** Branch-protection and required-check settings live in the
repository configuration, not in the tree, and this phase is local. Nothing in `.github/` records
them.

**Claude does not change repository settings, and 12.2B does not either.** Three states are distinct
and the validation record must never collapse them:

1. **workflow implemented** — the file exists in the tree;
2. **workflow green** — an actual GitHub-hosted run has succeeded;
3. **workflow configured as a required check** — a repository setting a human applied.

12.2B can reach 1 and, after the user pushes, 2. **State 3 is a manual user action**, and it is:

> Settings → Branches → branch protection rule for `main` → *Require status checks to pass* → add
> **`Kubernetes / current`**.
>
> Read-only confirmation, if wanted:
> `gh api repos/hakanaltindag/svcdoctor/branches/main/protection --jq '.required_status_checks.contexts'`

The release gate needs **no** setting: `job.needs` enforces it inside the workflow.

## 16. Actual-GitHub-execution closure — option B

**A workflow that has never run is not a gate.** Local validation can prove YAML parses and that the
guards pass; it cannot prove `kind` creates a cluster on a hosted `amd64` runner, that the pinned
digests resolve there, or that the suite passes on an architecture it has never run on.

Frozen closure sequence:

```
12.2B implementation complete, gates green locally
        ↓
PRE-COMMIT STATUS: READY FOR USER REVIEW
        ↓
user commits and pushes                       (user-owned; Claude does not)
        ↓
actual GitHub-hosted run of `Kubernetes / current`
        ↓
user confirms green
        ↓
POST-COMMIT CI CLOSURE — Phase 12.2B COMPLETE
        ↓
(optional, user-owned) required-check configuration
```

**The gate is not operational before its first real hosted run**, and no document may describe it as
one. This also resolves the bootstrap problem of §43 of the brief: the workflow cannot prove itself
before it exists, so the proof is a post-commit step with a named owner rather than a claim made in
advance.

## 17. What the first hosted run must confirm

Because the lane has never executed on GitHub infrastructure, these are open questions to be answered
by measurement, not blockers to the contract:

1. **`amd64` execution of the whole suite.** 12.1D ran on `arm64`. This is the `v0.3.1` lesson
   applied in advance.
2. **The two node-image digests resolve on `amd64`.** Inferred to be multi-architecture indexes from
   their successful `arm64` pull; not proven.
3. **Runner resources suffice** — in particular 600 Pending Pods with `maxPods: 800` on a single
   control-plane node, and disk headroom for the node image plus two builds.
4. **The in-cluster lane's `docker build` + `kind load`** works under the runner's Docker.
5. **The end-to-end job duration**, against the ≈5–7 minute estimate and the 40-minute timeout.
6. **Fork pull-request behaviour**, including GitHub's first-time-contributor approval gate.

## 18. Phase 12.2B — allowed implementation surface

**MAY change:**

| Path | Why |
|---|---|
| `.github/workflows/kubernetes.yml` | new; the PR, scheduled and dispatch lanes |
| `.github/workflows/release-oci.yml` | **one** job added, plus `kubernetes` in two `needs:` lists. The only enforceable place for a release gate |
| `scripts/install-kube-tools.sh` | new; pinned `kind` and pinned checksum-verified `kubectl`, usable locally and in CI |
| `internal/cli/kubernetesworkflow_test.go` | new; guards for the decisions above that no existing test covers |
| `docs/validation/PHASE122B_*.md` | the implementation record |
| `docs/BACKLOG.md`, `docs/COMPATIBILITY.md`, `docs/RELEASE_CHECKLIST.md`, `CONTRIBUTING.md`, `docs/decisions/README.md` | CI-operation documentation only |

**MUST NOT change:** Kubernetes production code, acquisition, diagnosis, rules, finding codes, the
evidence schema, canonical JSON, renderers, secret handling, credential authority, the public CLI,
the Kubernetes flag surface, fleet configuration, `client-go` dependencies, the Kubernetes
compatibility grade, `test/integration/kubernetes/**`, `Makefile`, or `cluster.yaml`.

**The `Makefile` and the integration suite are explicitly out of scope**, and §7 is why: refusing a
tier split removed the only reason either would have needed a change.

### 18.1 Two mechanical constraints the existing guards impose

Both were found by reading the guards, and either would fail the build if missed:

1. **`TestOCIPublicationCannotStartBeforeLinuxIntegration` locates the integration matrix with
   `strings.Cut(wf, "suite:")` — the first occurrence.** The new job must therefore use **`lane:`**
   as its matrix key and be placed **after** the `integration` job in the file.
2. **`TestUX22TheSupplyChainPinningIsRecorded` globs every workflow** and fails on an unpinned action
   without a `NOT SHA-pinned` justification. The new workflow uses only `actions/checkout` and
   `actions/setup-go`, at the SHAs this repository already carries — so **no new digest has to be
   invented**, which is the exact trap UX-S16-b recorded.

### 18.2 Suggested guards for 12.2B

No existing test covers any of these: the release job exists and `stage-and-verify`/`publish` need
it; the workflow never uses `pull_request_target`; it references no `secrets.` context; its default
permission block is `contents: read` and no job escalates; every version is pinned and no `latest`
appears; the pull-request matrix has exactly one lane and the scheduled matrix has two; the schedule
is a literal cron; the job declares a `timeout-minutes`; a teardown step runs `if: always()`; the
`kind` version in the install script equals the version named in the `Makefile`'s install hint; and —
per repository convention — a companion test proving each guard can still fail.

## 19. Phase 12.2B validation plan

**LOCAL** — `make check` (which covers every frozen count, since no production code moves);
`git diff --check`; both lanes end to end, `make integration-kubernetes` and
`KUBERNETES_LANE=older make integration-kubernetes`; the new guard tests plus their non-vacuity
proofs; YAML parse of every workflow; `shellcheck` on the new script if available, and its absence
said out loud rather than skipped silently; the documentation guards
(`go test ./internal/cli -run 'TestUX|TestTheREADME|TestNoDocument'`).

**CI** — a pull-request-equivalent `Kubernetes / current` run; the scheduled matrix semantics proven
by a `workflow_dispatch` run of both lanes. The release job's `needs:` wiring is proven statically by
guard, exactly as the existing integration gate is, because a release cannot be rehearsed.

**SECURITY** — `contents: read` and no escalation; no `pull_request_target`; no `secrets.` reference;
every action SHA-pinned; no artifact upload; the exec-auth refusal, credential-authority trap and
data-minimization scan all green **in the pull-request lane**.

**REGRESSION** — all by `make check`, and all unchanged because no production file is touched:
Kubernetes flags **10**, Kubernetes finding codes **4**, total finding codes **69**, rules **24**,
`SchemaVersion` **1**, `RunSchemaVersion` **1**, failure classes **42**, `Reveal` **5**, `SecretFor`
**5**, external modules **40**, `k8s.io` import paths **10**, exit codes **5**.

**MUTATION** — **not required for YAML**, and the reason is recorded rather than assumed: production
code does not move, so a production mutation rerun would measure nothing. The new **guard tests** do
need non-vacuity proofs, which is the repository's existing convention and is stronger than a
mutation count here. If 12.2B ends up touching any production file, that conclusion is void and the
relevant historical suites must be re-run.

## 20. Validation performed by this phase

```
make check          GREEN
git diff --check    CLEAN
```

Plus the documentation and workflow guards run directly:
`go test ./internal/cli -run 'TestUX22|TestUX21|TestTheReleaseWorkflow|TestOCIPublication|TestTheREADME|TestNoDocument|TestOnlyRealTestedPlatforms|TestEveryRealTestedPlatform'` and
`go test ./test/security/...`.

**Deliberately not run, and why:** the real-cluster suite, the mutation suites, the fuzz targets and
`-race`. This phase changes no Go file, no workflow, no fixture and no `Makefile` target — every one
of those measures the behaviour of code that did not move, so each would consume minutes to
re-confirm a result the baseline already carries. Running the Kubernetes suite in particular would
prove something about a developer machine, which is the *opposite* of the question this contract
exists to answer.

## 21. Rejected alternatives

Recorded in ADR 0095 §4 with their reopen conditions: both lanes on every pull request; a
pull-request smoke subset; no pull-request gate at all; path filtering; a separate
release-validation workflow that `release-oci.yml` "depends on"; a reusable `workflow_call` lane; a
third-party `setup-kind` action; node-image caching; publishing an image for the in-cluster lane.

Two more, specific to this document:

**Adding `kubernetes` to the existing `integration` matrix.** It would need `if: matrix.suite ==
'kubernetes'` on the tool-install step — a service-name conditional in the one place this repository
most consistently refuses one — and the release matrix is over *suites* while the Kubernetes gate is
over *lanes*. Different dimension, different job.

**Using the runner's preinstalled `kubectl`.** Zero setup and a bounded failure mode, and still
refused: it is an unpinned input to a release gate in a repository where everything else is pinned.

## 22. Open blockers

**None.** Each §49 stop condition was evaluated and none fires:

| Stop condition | Status |
|---|---|
| Existing CI cannot support a safe Kubernetes PR gate | Does not fire — `ci.yml` already shows the shape; the lane needs nothing `ci.yml` lacks |
| Repository secrets would be required | Does not fire — none needed; the cluster is created and destroyed on the runner |
| `pull_request_target` appears necessary | Does not fire — refused, and nothing requires it |
| No sustainable test tier | Does not fire — one tier, chosen on measurement |
| Release gate cannot connect to the release architecture | Does not fire — `job.needs` inside `release-oci.yml`, the mechanism already in use |
| Immutable Kubernetes/`kind` pinning cannot be defined | Does not fire — digests exist and are in the `Makefile` today |
| 12.2B would need Kubernetes production changes | Does not fire — surface is workflows, one script, one guard file and documentation |
| Compatibility policy ambiguous | Does not fire — §13 |
| Actual-GitHub-run closure unresolved | Does not fire — §16, option B |
| Workflow permissions unresolved | Does not fire — §4 |
| Security/logging contract unresolved | Does not fire — §5 |
| CURRENT/OLDER semantics ambiguous | Does not fire — §13.1 |
| Required-check ownership ambiguous | Does not fire — §15, three distinct states, state 3 user-owned |

## 23. Documentation debt found while measuring — not fixed here

Recorded because it was measured, and left alone because this phase is a CI contract freeze:

1. **`CONTRIBUTING.md` lists eight integration suites and omits `integration-kubernetes`**, and says
   `make check` *"mirrors CI exactly"*, which will stop being true when the Kubernetes lane exists.
   12.2B's documentation surface covers it.
2. **`CONTRIBUTING.md` says svcdoctor "has two" dependencies.** It has **40** since Phase 12.1B.
3. **`docs/RELEASE_CHECKLIST.md`'s frozen-count table is stale** — 60 finding codes (now 69),
   2 external modules (now 40), no `RunSchemaVersion` for Kubernetes — and its release-gate list does
   not mention a Kubernetes lane.
4. **The release `integration` matrix runs three of eight suites.** Redis, Valkey, RabbitMQ, LavinMQ
   and multi-target run only locally, while the checklist requires all eight by hand. Pre-existing,
   unrelated to Kubernetes, and larger than this phase.
5. **`govulncheck` is still absent from `ci.yml`**, against ADR 0076 §2.6 — already tracked as
   UX-S17.

## 24. Final freeze table

Every row is ADMIT, REFUSE or DEFER. No row is unresolved.

| # | Item | Decision | Value / rationale |
|---|---|---|---|
| 1 | CI architecture | **ADMIT** | MODEL B; standalone workflow + one job in `release-oci.yml` |
| 2 | PR trigger | **ADMIT** | `pull_request` (all branches) and `push` to `main` |
| 3 | PR Kubernetes lane | **ADMIT** | CURRENT only — `v1.34.0` |
| 4 | PR test tier | **ADMIT** | the **whole** suite; tiering refused on measurement |
| 5 | Extended trigger | **ADMIT** | `schedule` (weekly) and `workflow_dispatch` |
| 6 | Extended lanes | **ADMIT** | CURRENT + OLDER |
| 7 | Extended test tier | **ADMIT** | same whole suite, second Kubernetes version |
| 8 | Schedule cadence | **ADMIT** | weekly, `cron: '17 4 * * 1'` |
| 9 | `workflow_dispatch` | **ADMIT** | no free-form input; lanes from the frozen matrix |
| 10 | Release trigger | **ADMIT** | job `kubernetes` in `release-oci.yml`; `stage-and-verify` and `publish` `needs:` it |
| 11 | Runner | **ADMIT** | `ubuntu-24.04`; generation pin, not immutable |
| 12 | Go setup | **ADMIT** | `go-version-file: go.mod` |
| 13 | `kind` installation | **ADMIT** | `go install sigs.k8s.io/kind@v0.30.0` |
| 14 | `kind` version | **ADMIT** | v0.30.0 |
| 15 | `kubectl` | **ADMIT** | pinned version + repository-recorded checksum; digest obtained by 12.2B |
| 16 | CURRENT node image | **ADMIT** | `kindest/node:v1.34.0@sha256:7416a61b42b1662ca6ca89f02028ac133a309a2a30ba309614e8ec94d976dc5a` |
| 17 | OLDER node image | **ADMIT** | `kindest/node:v1.31.12@sha256:0f5cc49c5e73c0c2bb6e2df56e7df189240d83cf94edfa30946482eb08ec57d2` |
| 18 | Docker | **ADMIT** | runner-provided; unreachable ⇒ FAIL, never SKIP |
| 19 | Cluster shape | **ADMIT** | one control-plane node, `maxPods: 800`, unchanged |
| 20 | Cache | **ADMIT** | `setup-go` default only |
| 21 | Node-image / `kind`-binary cache | **REFUSE** | complexity without an established saving |
| 22 | Permissions | **ADMIT** | `contents: read`, no job escalation |
| 23 | `pull_request_target` | **REFUSE** | untrusted code with base-repository authority |
| 24 | Repository secrets | **REFUSE** | none needed; needing one voids the design |
| 25 | Fork PRs | **ADMIT** | run normally, read-only token, no secrets |
| 26 | Concurrency | **ADMIT** | `kubernetes-${event}-${ref}`; cancel on `pull_request` only |
| 27 | Timeout | **ADMIT** | 40 minutes, exceeding the harness's own 30-minute test timeout |
| 28 | Artifacts | **REFUSE** | none uploaded; allowlist recorded for a future reopen |
| 29 | Failure diagnostics | **ADMIT** | harness-owned allowlist, §5 |
| 30 | Path filtering | **REFUSE** | correctness, and required-check pending semantics |
| 31 | Cleanup | **ADMIT** | `if: always()` step calling `make kubernetes-down` |
| 32 | Automatic retry | **REFUSE** | masks RBAC, EndpointSlice, readiness and pagination races |
| 33 | Silent skip | **REFUSE** | already enforced by harness and `Makefile` |
| 34 | Compatibility auto-promotion | **REFUSE** | grading needs a record, a doc update and a human |
| 35 | CURRENT upgrade | **ADMIT** | manual PR, digest-pinned, both lanes green, docs in the same change |
| 36 | OLDER semantics | **ADMIT** | fixed validated version; **not** a moving floor |
| 37 | `kind` upgrade | **ADMIT** | explicit PR, re-derives both digests, both lanes before merge |
| 38 | Local/CI parity | **ADMIT** | workflow orchestrates; `make` + harness own the mechanics |
| 39 | Release artifact relationship | **ADMIT** | binary built in the job; archive/image validation DEFERRED with the ordering reason |
| 40 | Actual GitHub run for 12.2B closure | **ADMIT** | required; option B |
| 41 | Required-check configuration | **DEFER** | user-owned repository setting; state UNKNOWN locally |
| 42 | Dependabot / Renovate | **REFUSE** | none exists; none introduced |
| 43 | 12.2B production changes | **REFUSE** | — |
| 44 | 12.2B Kubernetes semantic changes | **REFUSE** | — |
| 45 | 12.2B public CLI changes | **REFUSE** | — |
| 46 | 12.2B compatibility grade changes | **REFUSE** | — |
| 47 | 12.2B `Makefile` / integration-suite changes | **REFUSE** | no tier split, so no reason exists |
| 48 | ADR | **ADMIT** | ADR 0095, Accepted |
