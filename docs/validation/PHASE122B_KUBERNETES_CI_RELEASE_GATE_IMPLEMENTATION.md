# Phase 12.2B — Kubernetes CI and release-gate implementation

- **Phase:** 12.2B (implementation of a frozen contract; **zero production changes**)
- **Baseline:** `e97496781f896520938aedd7478e02acab907479`, equal to `origin/main`, clean tree,
  `make check` green before anything was edited
- **Contract:** ADR **0095** and
  `docs/validation/PHASE122A_KUBERNETES_CI_RELEASE_GATE_CONTRACT_FREEZE.md`. Nothing was
  redesigned; where this document records a choice, it records which frozen clause forced it
- **Stage 1 — local implementation:** **COMPLETE**
- **Stage 2 — hosted CI closure:** **PENDING.** The workflow has never executed on
  GitHub-hosted infrastructure, and ADR 0095 §3 says a workflow that has never executed is not
  a gate

> **This record distinguishes two kinds of evidence and never mixes them.** §1–§14 are local
> evidence, taken on this machine. §15 is hosted evidence and every line of it is `PENDING`.

---

## 1. Baseline and pre-state

```
HEAD        e97496781f896520938aedd7478e02acab907479  docs(kubernetes): freeze CI and release-gate contract
origin/main e97496781f896520938aedd7478e02acab907479
tree        clean
make check  GREEN
```

Measured from source rather than taken from the phase brief:

| | Pre | Post |
|---|---|---|
| Total finding codes | **69** | **69** |
| Kubernetes finding codes | **4** | **4** |
| Production rules | **24** | **24** |
| `domain.SchemaVersion` | **1** | **1** |
| `domain.RunSchemaVersion` | **1** | **1** |
| Failure classes | **42** | **42** |
| Kubernetes public flags | **10** | **10** |
| `security.Reveal` production call sites | **5** | **5** |
| `SecretFor` production call sites | **5** | **5** |
| `k8s.io` direct import paths (production) | **10** | **10** |
| External modules | **40** | **40** |
| Workflow files | **5** | **6** |

The rule and code totals were read out of `TestTheConvergenceInventoryIsComplete`'s own inventory —
1 + 3 + 5 + 6 + 4 + 3 + 2 = **24** rules and 1 + 8 + 15 + 21 + 9 + 11 + 4 = **69** codes — rather
than counted by hand. Every other number is pinned by a test that `make check` runs, so the green
gate in §12 is the assertion that none moved.

## 2. Architecture, as implemented

```
.github/workflows/kubernetes.yml          pull_request · push(main) · schedule · workflow_dispatch
    job `lane`, name ${{ matrix.lane }}   →  checks `Kubernetes / current`, `Kubernetes / older`

.github/workflows/release-oci.yml         (existing; one job and two needs entries added)
    job `kubernetes`, matrix lane [current, older]
        stage-and-verify  needs: [identity, source, integration, kubernetes]
        publish           needs: [identity, stage-and-verify, archives, kubernetes]
```

MODEL B, unchanged from the freeze. The release gate is a **job**, not a workflow, because GitHub
cannot make one workflow depend on another's recent green run and "green last Tuesday" is a
statement about a different commit.

## 3. Event matrix

One job, one matrix dimension, resolved from the event:

```yaml
lane: ${{ (github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && fromJSON('["current","older"]') || fromJSON('["current"]') }}
```

| Event | Lanes | Proven by |
|---|---|---|
| `pull_request` | `current` | `TestTheKubernetesMatrixIsEventDependentExactlyAsFrozen/pull_request` |
| `push` to `main` | `current` | `…/push` |
| `schedule` | `current`, `older` | `…/schedule` |
| `workflow_dispatch` | `current`, `older` | `…/workflow_dispatch` |
| `push` tag `v*` | `current`, `older` | `TestKubernetesPublicationCannotStartBeforeBothLanes` |

**The test evaluates the expression rather than matching its text.** `resolveLanes` implements
exactly the frozen `COND && fromJSON(A) || fromJSON(B)` shape and fails on anything else, so a
rewritten expression is a failing test rather than a silently unevaluated one. Its two non-vacuity
subtests feed it a *widened* and a *narrowed* condition and require it to notice.

What it assumes is GitHub's documented operator semantics — `&&` yields its right operand when the
left is truthy, `||` yields its left when truthy, a non-empty array is truthy. **That the runtime
agrees is hosted evidence (§15, H10), not something this machine can prove.**

**One implementation detail, and it was a real hazard.** The expression was first written as a
folded block scalar (`>-`) across three lines for readability. Parsed with the repository's own
YAML decoder, the value came back carrying **literal newlines**, because YAML folding preserves the
line breaks of more-indented continuation lines. It would probably have worked; it is not worth
relying on. The expression is one line, and `laneMatrixExpression` fails if it is ever folded again.

## 4. Runner, budget, toolchain

| | Value | Why |
|---|---|---|
| Runner | `ubuntu-24.04` | Generation pin. This is the most environment-sensitive lane in the repository, and `ubuntu-latest` rolls to the next LTS on its own. **Not supply-chain immutable**, and no document here says it is |
| Timeout | **40 minutes** | Above the harness's own `go test -timeout 30m`, so a hang still produces its goroutine dump, with margin for a cold image pull. A guard re-reads the Makefile's 30m and fails if it moves |
| Go | `go-version-file: go.mod` | One source of truth. `go.mod` declares `go 1.26.0`; the other five workflows still hard-code `'1.26'` and were not touched |
| Cache | `actions/setup-go` default (module + build, keyed on `go.sum`) | Nothing else. No node-image cache, no `kind` binary cache, no cluster state |
| Actions | `actions/checkout@3d3c42e5…`, `actions/setup-go@b7ad1dad…` | The two SHAs this repository already carries. **No new digest had to be invented**, which is the trap UX-S16-b recorded |

## 5. Tool installation — `scripts/install-kube-tools.sh`

| Tool | Pin | Integrity |
|---|---|---|
| `kind` | `v0.30.0` | `go install sigs.k8s.io/kind@v0.30.0` — module proxy and `sum.golang.org`. The mechanism `release-oci.yml` already uses for `golangci-lint`, and the one the Makefile's own "kind is not installed" message recommends |
| `kubectl` | `v1.34.0` | SHA-256 `cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c`, compared before the binary is placed anywhere |

### 5.1 How the kubectl digest was established

Phase 12.2A deliberately refused to write a digest it could not check. This phase obtained the
artifact and verified it, rather than copying a number out of a document:

```
curl https://dl.k8s.io/release/v1.34.0/bin/linux/amd64/kubectl
  local sha256  cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c
  published     cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c   (…/kubectl.sha256)   MATCH
  local sha512  f08a01748dbbd413a65cfec5ac020c594b9882fb24699915a76251ae5301609f2ccee7228695d6dc52719711ff04d1623933b2d86960678c1d71306fc3629ebf
  published     f08a01748dbbd413a65cfec5ac020c594b9882fb24699915a76251ae5301609f2ccee7228695d6dc52719711ff04d1623933b2d86960678c1d71306fc3629ebf  (…/kubectl.sha512)  MATCH
  file(1)       ELF 64-bit LSB executable, x86-64, statically linked, stripped
  embedded      v1.34.0
```

Two independent digest algorithms over the artifact actually downloaded, plus confirmation that the
bytes are a Linux `x86_64` executable carrying the pinned version string. The download was deleted
afterwards; nothing was added to the repository except the constant.

**v1.34.0 was chosen to match the CURRENT lane.** Against the OLDER lane that is three minors of
skew, which is more than the officially supported ±1 — and Phase 12.1D ran `kubectl v1.36.2`
against `v1.31.12`, five minors, with nothing but a warning. `kubectl` builds fixtures and svcdoctor
never sees it (12.1D §13 proves a diagnosis completes with an empty `PATH`), so its failure mode is
a red lane rather than a false green.

### 5.2 Two narrowings, stated rather than glossed

**linux/amd64 only.** A checksum is per-platform, so a second platform means a second verified
digest. The script **fails closed** on anything else and points the reader at the Makefile's own
install hint. Phase 12.2A's prose called the script "usable locally and in CI"; on a non-Linux
developer machine it is not, and that is a narrowing of the record's wording, not of ADR 0095, which
says nothing about local usability. Refusing is the honest behaviour: the alternative is installing
an unverified binary, which is the defect the digest exists to prevent. **Measured on this machine
(`Darwin arm64`): exit 1, nothing installed.**

**The ambient `kubectl` is never consulted.** No `command -v kubectl` short-circuit exists, and a
guard fails if one appears. A runner image's `kubectl` moves when the image is rebuilt, which makes
it an unpinned input to a release gate.

**`go install pkg@version` cannot touch `go.mod`.** Verified: `git diff go.mod go.sum` is empty
after running the script's `go install` path. The module count stays where
`dependency_test.go` pins it.

## 6. Authority, trust boundary and hygiene

| | |
|---|---|
| Workflow permissions | `contents: read`, no job escalation |
| `pull_request_target` | **absent** |
| Repository secrets | **none referenced**, none needed |
| Fork pull requests | run normally — read-only token, no secrets, no privileged path |
| Artifacts | **none uploaded**; the workflow references no `upload-artifact` |
| Path filtering | **none** |
| Automatic retry | **none** |
| `continue-on-error` | **absent** |
| Shell tracing | **absent** from the workflow and the script |

**Failure diagnostics are the harness's, unchanged.** On failure it prints `kubectl get
service/pod/endpointslice -o wide` scoped to the failing test's own namespace. The workflow adds
only the bounded identity block ADR 0095 §2.7 admits: lane, runner uid/gid/os/arch, Docker version,
`go version`, `kind version`, `kubectl version --client`. The two binary SHA-256 digests are printed
by the Makefile, as they already were.

**Cleanup is unconditional.** `make` stops at a failing target, so `integration-kubernetes` does not
reach its own `kubernetes-down` when the suite fails. Both jobs add one `if: always()` step calling
**`make kubernetes-down`** — the harness's own target, with no cleanup logic in YAML. That target is
idempotent (`-` prefixes, `--ignore-not-found`), so the extra call after success costs nothing, and
it cannot mask the failure above it: the steps report separately and the job's conclusion is already
failure.

**A missing prerequisite fails; it never skips.** Already true and unchanged: `kubernetes-up`
refuses without `kind`, `kubectl` and a reachable runtime, and the suite calls `t.Fatalf` — *"a
skipped mandatory gate is not a pass"*.

## 7. Local/CI parity

`make integration-kubernetes` is what CI runs and what a developer runs. `KUBERNETES_LANE` selects
the lane in both. The workflow owns the runner, checkout, Go setup, tool installation, lane
selection and teardown invocation; the harness owns everything else. A guard fails on `kubectl
apply`, `kind create cluster`, ServiceAccount or EndpointSlice logic appearing in either job.

**The Makefile and `test/integration/kubernetes/**` are unchanged** — verified by `git diff --stat`.
That follows from Phase 12.2A refusing a tier split: tier selection was the only thing that would
have required editing either.

## 8. Release graph

```
identity ─┬─ source ──┬─ archives ────────────────┐
          │           │                            │
          ├─ integration ──┐                       │
          │                │                       │
          └─ kubernetes ───┤                       │
                           ↓                       ↓
                    stage-and-verify ─────────→ publish ──→ release ──→ summary
```

- `stage-and-verify` — `needs: [identity, source, integration, kubernetes]`
- `publish` — `needs: [identity, stage-and-verify, archives, kubernetes]`

**Both edges are direct.** `publish` already reached `integration` only transitively; the freeze
named both jobs, so `kubernetes` is written into both `needs:` lists. That is strictly stronger than
the shape it mirrors, and it means re-ordering the graph cannot quietly drop one. **No existing
dependency was removed**, and a guard asserts `integration` is still reachable from both.

**Two mechanical constraints Phase 12.2A measured were respected literally:**

1. The matrix key is **`lane`**, not `suite`. `TestOCIPublicationCannotStartBeforeLinuxIntegration`
   finds the integration matrix with `strings.Cut(wf, "suite:")` — the document's *first*
   occurrence.
2. The `kubernetes` job is placed **after** `integration` and before `archives`, for the same
   reason.

Both are now guarded, so the coupling is a failing test rather than folklore.

**No existing guard was weakened, and none needed changing.** All twenty-one release, validation and
supply-chain guards pass unmodified — including `TestUX22TheSupplyChainPinningIsRecorded`, which
globs every workflow and therefore covered the new file the moment it existed.

## 9. Structural tests — `internal/cli/kubernetesworkflow_test.go`

Ten test functions, all thirty frozen KWF identifiers covered:

| Test | KWF |
|---|---|
| `TestTheKubernetesWorkflowTriggersOnExactlyTheFrozenEvents` | 01–06, 26 |
| `TestTheKubernetesWorkflowHoldsNoAuthorityItDoesNotNeed` | 07, 19–22, 30 |
| `TestTheKubernetesLaneRunsOnTheFrozenRunnerAndBudget` | 08–10, 23 |
| `TestTheKubernetesMatrixIsEventDependentExactlyAsFrozen` | 12, 15, 16 |
| `TestTheKubernetesLanesArePinnedByDigest` | 11, 13, 14, 29 |
| `TestTheKubeToolInstallerFailsClosed` | 21, 29 |
| `TestTheKubernetesWorkflowDelegatesToTheHarness` | 17, 18, 27, 28 |
| `TestTheKubernetesConcurrencyCancelsOnlyPullRequests` | 24, 25 |
| `TestKubernetesPublicationCannotStartBeforeBothLanes` | release graph |
| `TestTheKubernetesWorkflowGuardsCanFail` | non-vacuity |

**KWF-23 is split deliberately.** Everything that *determines* the check identity is asserted here —
the workflow is named `Kubernetes`, the job is named `${{ matrix.lane }}`, and no version appears in
the job name. That GitHub renders those as `Kubernetes / current` is a statement about GitHub's
runtime and is **hosted evidence (H2)**. The record does not tell the user to configure branch
protection against a name nobody has seen.

## 10. Mutation closure — 26 planted, 26 caught, 0 survivors

Bounded structural mutations of the CI contract, planted one at a time from a harness in `/tmp`
that never entered the repository, with all three files verified restored **byte-for-byte** by
SHA-256 afterwards.

M01 current digest changed · M02 older digest removed · M03 `pull_request_target` introduced ·
M04 `kubernetes` dropped from `publish` needs · M05 permissions widened · M06 timeout removed ·
M07 test command replaced · M08 cleanup made conditional · M09 kind version floated ·
M10 kubectl checksum blanked · M11 checksum comparison neutered · M12 PR widened to both lanes ·
M13 schedule narrowed to one · M14 cancellation made unconditional · M15 runner floated to
`ubuntu-latest` · M16 Go version hardcoded · M17 artifact upload added · M18 path filter added ·
M19 dispatch input added · M20 release matrix key renamed to `suite` · M21 third-party
`setup-kind` action introduced · M22 curl-pipe-shell install · M23 shell tracing enabled ·
M24 retry loop added · M25 gate softened with `continue-on-error` · M26 existing integration gate
removed from `stage-and-verify`.

### 10.1 The first run caught 23 of 26, and none of the three was an equivalent mutation

This is the part worth keeping. **Two were real defects in the new guards and one was a defect in
the mutation harness — and the harness defect was hiding the other two.**

**The harness selected no tests for one guard.** The `-run` regex included `TestTheKubeTools`, and
the function is `TestTheKubeToolInstallerFailsClosed` — *"TestTheKubeTools"* with a trailing `s` is
not a substring of *"TestTheKubeToolInstaller…"*. Go's `-run` matched nothing, exited 0, and every
mutation of that file was reported as a survivor. **This is the same class of defect the repository
recorded in 2026-09-05**, where a `grep -q` under `pipefail` made a large selection look like no
selection at all. The harness now proves its selection is non-empty before planting anything, and
that pre-check reports **22 test entries**.

That mis-selection also means the earlier "all new guards pass" observation covered **nine of ten**
tests. Run by its real name, the tenth **failed on the clean tree**, for two independent reasons:

1. **The tracing guard read its own documentation.** `install-kube-tools.sh` explains at length why
   it does not trace, and that sentence contains the literal `set -x`. `strings.Contains(script,
   "set -x")` was therefore true on a script with no tracing in it — and would have been true
   forever, including after tracing was added. Fixed by stripping line-leading shell comments and
   matching `^\s*set\s+-\S*x` as a directive. This is exactly what
   `TestTheReleaseWorkflowUsesMinimalPermissions` records having found *"by mutation, not by
   review"*, arriving a second time in a new file.
2. **The ordering check compared an index that was always `-1`.** It searched for
   `KUBECTL_SHA256"; then`, but the script says `!= "$KUBECTL_SHA256" ]; then` — the substring never
   existed. Fixed by anchoring on the three operands (`--output "$tmp/kubectl"`, `!=
   "$KUBECTL_SHA256"`, `mv "$tmp/kubectl"`) and requiring `download < verify < install`, with an
   explicit branch that fails when any of the three is absent rather than folding that into the
   comparison.

**M22 is a genuine gap and the most useful of the three.** The guard looked for the literal
`curl | sh`. The mutation wrote `curl -sSL https://example.invalid/i | sh`, which is what anyone
would actually write, and it passed. The idiom everybody quotes is the one form that never appears.
Replaced with `\|\s*(sh|bash|zsh|dash)\b` — a pipeline into a shell, with the word boundary keeping
`| shasum` out — and applied to both the workflow and the script.

After the three fixes: **26 / 26 / 0**, and the re-run after the `golangci-lint` fix in §12 was also
26 / 26 / 0.

## 11. Local real-cluster validation — both lanes

Run on this machine, with the implementation in place, to prove the change did not break local
orchestration.

| | Host | Runtime | `kind` | `kubectl` | Server | Suite | Whole gate |
|---|---|---|---|---|---|---|---|
| **CURRENT** | `Darwin arm64`, macOS 26.6.2 | Docker 28.3.3 `linux/arm64` (Colima) | v0.30.0 | v1.36.2 | **v1.34.0** | **74.148 s** | **123 s** |
| **OLDER** | same | same | v0.30.0 | v1.36.2 | **v1.31.12** | **71.531 s** | **107 s** |

Both **exit 0**. Both clusters deleted by the gate; `kind get clusters` reports **none** afterwards,
and `test/integration/kubernetes/env/` holds only the tracked `cluster.yaml` — the generated
kubeconfig is gone and is `.gitignore`d in any case.

Within noise of Phase 12.1D's 70.8 s / 71.6 s, on the same host class.

**This is not a substitute for the hosted run and is not offered as one.** It is `arm64` under
Colima; §15 is the amd64 question.

## 12. Static validation and regression

| | Result |
|---|---|
| `make check` | **GREEN** |
| `git diff --check` | **CLEAN** |
| YAML parse, all six workflows, using the repository's own decoder | **PARSE OK** ×6 |
| `actionlint` on `kubernetes.yml` | **0 findings** |
| `actionlint` on `release-oci.yml` | 3 locations, **all pre-existing** — identical to the set at `HEAD`, shifted by the inserted job. **0 new** |
| `shellcheck` on `install-kube-tools.sh` | **0 findings** |
| `sh -n` on the installer | **OK** |
| Existing release / validation / supply-chain guards (21 tests) | **all PASS**, unmodified |
| New Kubernetes guards (10 tests) | **all PASS** |

**`actionlint` and `shellcheck` were already installed on this machine and neither was added to the
repository.** They are read-only supplementary evidence; the Go structural guards are authoritative,
and `make check` does not depend on either.

**One `make check` failure was found and fixed during implementation:** `staticcheck QF1001` on
`case !(download < verify && verify < install)`. Rewritten as `case download >= verify || verify >=
install`. Nothing else changed.

## 13. Omitted validations, and why

- **Race detector** — not run. No production Go file changed; the only Go change is a test that
  reads three files and starts no goroutine.
- **Fuzz** — not run. No parser, boundary or production behaviour changed.
- **Service mutation suites** (Kafka, PostgreSQL, Redis, RabbitMQ, fleet, 12.1B/12.1C/12.1D) — not
  re-run. They mutate production code that this phase did not touch, and `make check` already
  asserts every frozen count.
- **A real release** — not manufactured. No tag was created, nothing was published, and the release
  graph is proven structurally, which is how every other release property in this repository is
  proven between releases.
- **A hosted `workflow_dispatch`** — not triggered. Claude does not dispatch workflows, and ADR 0095
  requires only the CURRENT lane's hosted run for closure (§15.1).

## 14. Scope assertions

**Production files changed: 0.** No file under `internal/service`, `internal/adapter`,
`internal/app`, `internal/diagnosis`, `internal/domain`, `internal/security`, `internal/render`,
`internal/fleet` or `cmd/` was modified. `internal/cli` gained one **test** file and no production
file.

**`Makefile`: unchanged.** **`test/integration/kubernetes/**`: unchanged.** **`cluster.yaml`:
unchanged.** **`go.mod` / `go.sum`: unchanged.** **Compatibility grades: unchanged** — no row moved,
no version was added, and no `amd64`, GitHub Actions, v1.21 or distribution claim was made anywhere.

**Documentation debt was not opportunistically cleaned.** Phase 12.2A recorded five pre-existing
items — `CONTRIBUTING.md`'s missing `integration-kubernetes`, its *"mirrors CI exactly"* sentence and
its stale dependency count, `RELEASE_CHECKLIST.md`'s stale frozen-count table, the three-of-eight
release integration matrix, and the absent `govulncheck`. **None was touched.** ADR 0095 requires
none of them, and 12.2A's note that 12.2B's surface *covers* them was permission rather than
instruction.

The one documentation change is the one this phase makes necessary: `docs/RELEASE_CHECKLIST.md`'s
AUTOMATE gate list did not name the new release gate, so a release operator would not have watched
it. One bullet was added and nothing else in that file was edited.

## 15. HOSTED CI EVIDENCE — **PENDING**

**Nothing below has happened.** The workflow exists only in an uncommitted working tree.

| | Assertion | Status |
|---|---|---|
| **H1** | workflow started | **PENDING** |
| **H2** | check identity is exactly `Kubernetes / current` | **PENDING** |
| **H3** | runner is `ubuntu-24.04` | **PENDING** |
| **H4** | runner architecture is `x86_64` | **PENDING** |
| **H5** | Go came from `go.mod` | **PENDING** |
| **H6** | `kind v0.30.0` installed | **PENDING** |
| **H7** | kubectl checksum verification succeeded | **PENDING** |
| **H8** | CURRENT node image pulled by immutable reference | **PENDING** |
| **H9** | kind cluster created | **PENDING** |
| **H10** | whole suite ran (30 tests) and the PR matrix resolved to `current` alone | **PENDING** |
| **H11** | suite green | **PENDING** |
| **H12** | cleanup attempted | **PENDING** |
| **H13** | no secret or log-hygiene violation observed | **PENDING** |
| **H14** | no permission escalation required | **PENDING** |
| **H15** | no artifact containing cluster credentials uploaded | **PENDING** |

### 15.1 Which hosted lanes closure requires

**CURRENT only.** ADR 0095 §3 and Phase 12.2A §16 both name the hosted `Kubernetes / current` run
as the closure step; neither requires a hosted OLDER run before the phase closes. The OLDER lane is
proven structurally here (§3) and locally (§11), and it executes on the first weekly schedule, the
first dispatch or the first release, whichever comes first. **The user may dispatch it manually if
they want it sooner. Claude does not dispatch it.**

### 15.2 The three things the first hosted run is really testing

1. **`amd64`.** Phase 12.1D ran on `aarch64` under Colima. This will be this suite's **first
   `amd64` execution**, and the repository has already lost a release (`v0.3.1`) to one such
   developer-platform-versus-runner difference. A failure here is not automatically a YAML defect.
2. **That the two node-image digests resolve on `amd64`.** They pulled on `arm64`, which is only
   possible if each digest names a multi-architecture index — strong evidence, not proof.
3. **That `name: ${{ matrix.lane }}` renders the check as `Kubernetes / current`** (H2).

**If the hosted run fails, classify before changing anything**: `WORKFLOW_DEFECT`,
`HARNESS_DEFECT`, `ARCHITECTURE_DEPENDENCY`, `RUNNER_ENVIRONMENT`, `SUPPLY_CHAIN`,
`KUBERNETES_IMAGE_ARCHITECTURE`, `REAL_PRODUCT_REGRESSION` or `TRANSIENT_INFRASTRUCTURE`. No blind
retry, no weakening of the gate, and no version unpinned to get green.

### 15.3 Required-check configuration — **UNKNOWN**

Branch protection is a repository setting, not a tree artefact, and this phase is local. Three
states stay distinct and must never be collapsed:

1. **workflow implemented** — true after the user commits;
2. **workflow hosted-green** — true after H1–H15;
3. **workflow configured as a required check** — a setting a human applies.

State 3 is the user's, and it should not be configured against a guessed name. After the first
hosted run confirms H2:

> Settings → Branches → protection rule for `main` → *Require status checks to pass* → add
> **`Kubernetes / current`**.

Read-only confirmation: `gh api repos/hakanaltindag/svcdoctor/branches/main/protection --jq
'.required_status_checks.contexts'`.

The **release** gate needs no setting at all: `job.needs` enforces it inside the workflow.

## 16. Open blockers

**None.** No frozen contract was contradicted, no production change was required, and no ADR needed
editing.

## 17. Changed-file classification

| File | Class | State |
|---|---|---|
| `.github/workflows/kubernetes.yml` | **CI** | new |
| `.github/workflows/release-oci.yml` | **CI** | modified — one job, two `needs:` entries |
| `scripts/install-kube-tools.sh` | **SCRIPT** | new, executable |
| `internal/cli/kubernetesworkflow_test.go` | **TEST** | new |
| `docs/RELEASE_CHECKLIST.md` | **DOCUMENTATION** | modified — one bullet |
| `docs/validation/PHASE122B_…md` | **DOCUMENTATION** | new (this file) |
| `docs/BACKLOG.md` | **DOCUMENTATION** | modified — phase entry |

No PRODUCTION, INTEGRATION, CONFIG, GENERATED, ADR or UNEXPECTED file changed.
