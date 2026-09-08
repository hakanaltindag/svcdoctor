# ADR 0095 — Kubernetes CI lanes and the release gate

- **Status:** Accepted
- **Date:** 2026-09-08
- **Phase:** 12.2A (contract freeze; no production code, no CI change, no dependency change)
- **Implements:** ADR 0094 §2.11's sentence *"CI runs two `kind` versions, the current stable minor
  and one older supported minor"*, by fixing which trigger runs which lane.
- **Upholds:** ADR 0062 §12–§21c (the release pipeline and its ordering), ADR 0076 §2.6 (every
  third-party action pinned by commit SHA), ADR 0094 §2.2 (exec auth refused) and §2.11 (no vendor
  branch, no distribution graded without a fixture), and `docs/COMPATIBILITY.md` §6's promotion
  rules.
- **Amends:** ADR 0062's job graph, by adding one gate that publication depends on. It changes no
  rule ADR 0062 states.

---

## 1. Context

Phase 12.1D took the frozen Kubernetes model to a real API server on two pinned `kind` node images
and it held: 30 real-cluster tests, both lanes green, ≈71 s of test time and ≈2 minutes per lane
including cluster creation. That proof exists **once**, on one developer's machine, on `arm64`,
and nothing re-takes it.

12.1D §19 declined to add CI in the same phase and said why: *"adding the first one for Kubernetes
would be a workflow decision this phase did not measure the cost of on hosted runners."* It left the
measured local cost as the input.

The repository already has the shape of an answer for every other suite, and it is worth naming
because it is what this record extends rather than invents:

- **`ci.yml`** runs the hermetic quality gate on every push to `main` and every pull request.
- **`validate-integration.yml`** runs the container-backed suites on a Linux runner on demand,
  publishing nothing.
- **`release-oci.yml`** runs on a `v*` tag, and its `integration` job is a **structural** release
  gate: `stage-and-verify` and `publish` both sit behind `needs: integration`, so GitHub will not
  schedule publication until the suites have passed. `TestOCIPublicationCannotStartBeforeLinuxIntegration`
  fails the build if that dependency is ever removed.

So the question this record answers is not whether to test Kubernetes in CI. It is **which lane runs
on which trigger, and what a green lane is and is not allowed to mean.**

One measured fact frames the whole decision. **Both 12.1D lanes ran the identical binary and
produced identical results.** The older lane's marginal value is therefore *compatibility* signal —
a change in how svcdoctor meets an older API server — and not *regression* signal, which the current
lane already carries in full. Compatibility signal decays slowly, because every input is pinned;
regression signal arrives with every commit.

## 2. Decision

### 2.1 Three triggers, two lanes, one tier

| Trigger | Lanes | Why |
|---|---|---|
| `pull_request` and `push` to `main` | **CURRENT only** | Regression signal, on the commit that could cause one |
| `schedule` (weekly) and `workflow_dispatch` | **CURRENT and OLDER** | Compatibility signal, at the cadence its inputs actually decay |
| `push` of a `v*` tag, inside `release-oci.yml` | **CURRENT and OLDER** | A release makes a compatibility claim, so a release re-proves both graded versions |

**There is exactly one test tier and it is the whole suite.** Splitting core from extended is
refused on measurement, not on taste: the suite is 71 s of a ≈5–7 minute job whose cost is dominated
by cluster creation, node-image pull and the Go build — all of which every tier pays in full. A tier
split would save under a fifth of the job for a permanent, silent risk that a security or claim
guard drifts into the tier nobody runs on a pull request.

The consequence is deliberate: `TestAnExecCredentialPluginIsStillRefusedAgainstARealCluster`,
`TestTheKubernetesCredentialReachesOnlyTheAPIServer` and
`TestNoRealClusterReportCarriesMaterialTheContractExcludes` run on **every pull request**, because
they are the tests whose absence would be least visible.

### 2.2 The release gate is a job inside the release workflow

A release gate has to be something GitHub can enforce. Cross-workflow "this run was green
recently" cannot be enforced and would be a claim about a different commit, so the Kubernetes gate
is a **job in `release-oci.yml`**, and `stage-and-verify` and `publish` depend on it exactly as they
depend on `integration`.

That is the only edit this contract authorizes to an existing workflow, and it is the one that
turns a lane into a gate. The scheduled workflow is not a release gate and never becomes one.

### 2.3 A green lane protects a claim; it never creates one

**Adding a Kubernetes version to the CI matrix is not grading it.** `docs/COMPATIBILITY.md` §6 is
unchanged: a row moves to Level 2 by a recorded run against a real instance, and to Level 3 by that
plus a committed repeatable fixture. Both require a human writing the row and a validation record
justifying it.

Two refusals follow, and both are absolute:

- **No dynamic version discovery.** No `latest`, no "newest kind release", no API query that could
  put an ungraded Kubernetes minor into the matrix without a commit.
- **No manual input that can invent a version.** `workflow_dispatch` selects from the frozen matrix
  and accepts no image reference, so a dispatched run cannot manufacture evidence for a version
  nobody decided to support.

### 2.4 CURRENT and OLDER are fixed versions, advanced only by a pull request

- **CURRENT** is the newest minor the pinned `kind` release publishes a node image for; today
  `v1.34.0`.
- **OLDER** is the oldest minor that same `kind` release publishes a node image for; today
  `v1.31.12`. **It is a fixed validated version, not a moving compatibility floor.** A floor that
  moved on its own would silently change what a graded row means.

Both are pinned by **image digest**, taken from that `kind` release's own notes. Advancing either is
a pull request that re-runs both lanes and updates `docs/COMPATIBILITY.md` in the same change, and a
`kind` upgrade re-derives **both** digests because they belong to the `kind` release rather than to
the Kubernetes version.

**Two states, named, because they are not the same:** a version is **continuously gated** while it is
in the matrix, and **validated historically** once it leaves. Leaving the matrix is not a
re-grading, but the row must say which state it is in, and a version the pinned toolchain can no
longer run is not repeatable and therefore no longer Level 3.

### 2.5 The trust boundary

- **`pull_request_target` is refused.** This lane executes the pull request's own code inside a
  container runtime; running it with the base repository's token and secrets is the exact shape of
  the vulnerability that trigger is known for.
- **No repository secret is used, and none is needed.** The cluster is created on the runner, its
  credentials are generated there, and it is destroyed there. If a future change to this lane
  requires a secret, that is a signal the lane has stopped being self-contained, and it is a new
  decision.
- **`permissions: contents: read`**, at the workflow level, with no job escalating. Nothing here
  writes to the repository, publishes a package, or holds an OIDC identity.
- **A fork pull request runs the lane normally**, with a read-only token and no secrets, which is
  what makes forks safe here rather than a special case.

### 2.6 Nothing floats, and no digest is invented

| Input | Pin | Kind of pin |
|---|---|---|
| Kubernetes node images | `kindest/node:vX.Y.Z@sha256:…` | Semantic version **and** immutable digest |
| `kind` | `go install sigs.k8s.io/kind@v0.30.0` | Semantic version, integrity by the Go module proxy and `sum.golang.org` |
| `kubectl` | pinned version, verified against a checksum recorded in the repository | Semantic version **and** immutable digest |
| Go toolchain | `go-version-file: go.mod` | One source of truth, advanced by editing `go.mod` |
| Third-party actions | the commit SHAs this repository already carries | Immutable (ADR 0076 §2.6) |
| Runner | `ubuntu-24.04` | **Generation pin only.** Not immutable, and no document may call it that |

`kind` is installed through the Go module proxy rather than by a downloaded binary or a third-party
action, because `release-oci.yml` already chose that mechanism for `golangci-lint` for the same
reason: it is checksum-verified by the toolchain rather than by a piped shell script.

**This record does not write a `kubectl` checksum it cannot verify.** Phase 9.2B's UX-S16-b decided
that question already — *"a plausible wrong one is precisely the supply-chain defect the pin exists
to prevent"* — so the **policy** is frozen here and the literal digest is obtained and verified by
the phase that can reach the upstream publisher. The ambient `kubectl` a runner image happens to
provide is not admissible under any circumstances.

### 2.7 Failure diagnostics are an allowlist the harness already owns

The integration harness prints, on failure only, `kubectl get` output for **three kinds** — Service,
Pod, EndpointSlice — **scoped to the failing test's own namespace**. That is the contract, it is
already implemented, and the workflow adds nothing to it.

**Admitted:** lane name and node image reference; `kind`, `kubectl` and API server versions; runner
identity, architecture and Docker version; both binary SHA-256 digests; the Go test output including
the namespace-scoped dump; exit codes; finding codes and evidence states as the tests assert them.

**Refused:** kubeconfig content, ServiceAccount tokens, `Secret` objects, private keys, any
cluster-wide dump, `kubectl cluster-info dump`, environment dumps, and shell tracing anywhere near
credential handling.

**No artifact is uploaded.** A lane that handles kubeconfigs, tokens and client keys does not get an
upload step in exchange for information the log already carries.

### 2.8 A missing prerequisite fails; it never skips

Docker unreachable, `kind` not installed, cluster creation failed, node image unavailable — every one
of these is a **failure**. The harness already enforces this: `kubernetes-up` refuses to proceed
without `kind`, `kubectl` and a container runtime, and the suite calls `t.Fatalf` rather than
`t.Skip` when its environment is absent, with the reason written into the message — *"a skipped
mandatory gate is not a pass"*.

**There is no automatic retry**, of a job, a step or a test. A real-cluster test may poll a named
condition under a bounded deadline, which it already does and which is not a retry. A repeatable
infrastructure failure is classified and fixed in the harness, because a workflow retry loop is how
an RBAC, EndpointSlice, readiness or pagination race becomes permanently invisible.

### 2.9 The workflow orchestrates; the repository harness runs the test

`make integration-kubernetes` stays the canonical entry point for a developer and for CI, and the
workflow calls it. YAML owns the runner, checkout, Go setup, tool installation and lane selection.
The harness owns the cluster lifecycle, the binaries, the fixtures, the tests and the teardown.

The one thing the workflow adds is an unconditional teardown step that calls `make kubernetes-down`,
because `make` stops at a failing target and would otherwise leave the cluster behind. It calls the
harness's own target and contains no cleanup logic of its own.

**The lane tests a binary built in the job, from the tagged tree, by the same `CGO_ENABLED=0 go
build ./cmd/svcdoctor` recipe.** It deliberately does not test the release archive: the archives are
produced later in the same run, and making the gate depend on them would either invert the ordering
that protects publication or duplicate the harness's build. The two builds differ only in
`-trimpath` and the injected version string, neither of which any diagnosis reads.

## 3. Consequences

- A Kubernetes regression is caught on the pull request that causes it, on the current graded
  version, and cannot reach a published release without both graded versions passing.
- A pull request that touches only documentation still pays for a cluster. That is accepted; §4
  records why the alternative is worse.
- The first hosted run is the first `amd64` execution of this suite. 12.1D ran on `arm64`, and the
  repository has already lost one release to a difference between a developer platform and a runner.
  **A workflow that has never executed is not a gate**, so this contract is operational only after
  a real green run, not when the file is committed.
- `docs/COMPATIBILITY.md` gains no row and no grade from this record.
- No production code, no finding code, no rule, no flag, no configuration key, no Kubernetes API
  request and no dependency is added or changed. `SchemaVersion` stays **1**.

## 4. Rejected alternatives

**Both lanes on every pull request.** Doubles the per-pull-request cost for the signal 12.1D measured
as identical: same binary, same results, both lanes. The older lane's real value is compatibility
decay, which does not arrive commit by commit. *Reconsider if the two lanes ever diverge on the same
commit — that is the measurement that would refute the premise.*

**A pull-request smoke subset with everything else scheduled.** Refused on measurement: the suite is
71 s of a ≈5–7 minute job, so the saving is under a fifth of the cost and the loss is that the exec
refusal, the credential-authority trap and the data-minimization scan stop running on pull requests.
*Reconsider if the suite's own runtime ever dominates the job.*

**No pull-request gate at all, scheduled only.** The first signal of a regression would arrive up to
a week late, attached to a merge commit rather than to the change that caused it, or at a release
tag — which is where this repository has already learned what late signal costs.

**Path filtering, so documentation-only pull requests skip the lane.** The honest filter is a
`paths-ignore` on documentation, and it is technically sound because the lane runs no documentation
guard. It is refused for an operational reason: a required check that does not run leaves a pull
request pending rather than green, and the standard workaround is a second always-succeeding job
whose only purpose is to lie to branch protection. Correctness over ≈7 runner-minutes.
*Reconsider if required checks are configured and documentation-only volume makes the cost material,
and then with the status-shim pattern written down rather than discovered.*

**A separate release-validation workflow that `release-oci.yml` "depends on".** GitHub cannot
enforce it. It would be a gate in prose and not in the job graph.

**A third-party `setup-kind` action.** Adds a supply-chain dependency whose digest this repository
would have to verify, to replace one line that the Go toolchain already verifies.

**Caching the node image.** A ≈1.2 GB image moved through the Actions cache to avoid pulling a
≈1.2 GB image. Complexity for a saving that is not established, against a 10 GB cache budget.

**Publishing an image for the in-cluster lane.** The harness builds it locally and `kind load`s it.
Nothing is pushed, and nothing needs to be.

## 5. Security implications

The lane holds no repository secret, holds only `contents: read`, and never runs under
`pull_request_target`. Every credential it touches — the `kind` kubeconfig, its client key, the
ServiceAccount tokens the fixtures mint — is created on the runner, used there and destroyed with the
cluster; the generated kubeconfig is already `.gitignore`d and `chmod 600`, so it cannot become a
tracked artefact. No artifact is uploaded, so there is no path by which any of it leaves the job.

ADR 0094 §2.2's exec refusal, ADR 0028's endpoint-bound credential authority and the report's data
minimization are all proven on **every pull request** rather than weekly, which is a strengthening
and is the direct consequence of refusing a tier split.

## 6. Verification

`docs/validation/PHASE122A_KUBERNETES_CI_RELEASE_GATE_CONTRACT_FREEZE.md` records the measurement
this record is derived from. Phase 12.2B implements it, and its own closure requires **an actual
green run on GitHub-hosted infrastructure** — local YAML validation proves syntax and cannot prove
execution.

The existing guards already bind the implementation: `TestUX22TheSupplyChainPinningIsRecorded` reads
every workflow and fails on an unjustified unpinned action, and
`TestOCIPublicationCannotStartBeforeLinuxIntegration` fails if publication stops depending on its
gates. 12.2B adds the guards that pin the decisions above which no existing test covers.

## 7. Reopen conditions

| Item | Condition |
|---|---|
| Both lanes on every pull request | The two lanes produce different results on the same commit |
| A test tier split | The suite's own runtime dominates the job, rather than setup and image pull |
| Path filtering | Required checks are configured **and** documentation-only pull-request volume makes ≈7 runner-minutes material; requires the pending-check behaviour to be solved explicitly |
| A third Kubernetes lane | A version whose behaviour is measured to differ, with the record that measured it |
| An artifact upload | A named failure this lane's log demonstrably could not explain, and an allowlist that admits nothing credential-bearing |
| A repository secret in this lane | None. A lane that needs one has stopped being self-contained and is a different decision |
| `pull_request_target` | None |
| Automatic retry | None |
