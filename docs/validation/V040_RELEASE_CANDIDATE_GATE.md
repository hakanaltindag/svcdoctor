# v0.4.0 Release Candidate Gate

**Question:** can commit `7e7df84` be published as svcdoctor v0.4.0?

**Answer: NOT_RELEASE_READY.** Two blockers are open. Neither is a product defect; both are
release-mechanism gaps that no amount of testing the source can close.

> **Superseded by §16 — Phase 9.3A blocker closure, 2026-09-01.** Both blockers are now closed:
> private vulnerability reporting reads `{"enabled":true}`, and the release archives have an
> executable mechanism. Everything above and below this line is the gate as it was measured at
> `7e7df84` and is deliberately left unedited — a gate that rewrote its own findings after they
> were fixed would be a gate nobody could audit. Read §16 for the current state.

| | |
|---|---|
| Candidate HEAD | `7e7df84b699357333ae9d8efde8505438ddc6679` |
| Previous tag | `v0.3.3` (`bca8995`), annotated |
| Previous **published release** | `v0.3.3` — and `v0.1.0`. `v0.2.0`, `v0.3.0`, `v0.3.1`, `v0.3.2` are tags with no Release |
| Commits since `v0.3.3` | 49 |
| Candidate version | **v0.4.0** — candidate only. No tag exists locally or on `origin` |
| Open blockers | **2** — RB-02, RB-05. One more, RB-09, was found and closed during the gate |

---

## 1. Blocker ledger

### RB-01 — historical mutation survivors · **CLOSED**

| | |
|---|---|
| **Evidence** | Phase 9.2B reported 20 survivors across `phase91a` (8) and `phase91b` (12) |
| **Severity** | Was RELEASE_BLOCKER |
| **Owner** | Test harness |
| **Action** | Investigated individually; see §2 |
| **Verification** | All four suites now **117 planted, 117 caught, 0 survivors** |
| **Status** | **CLOSED** |

### RB-02 — GitHub private vulnerability reporting is disabled · **OPEN**

| | |
|---|---|
| **Evidence** | `gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting` → `{"enabled":false}`, re-verified during this gate |
| **Severity** | **RELEASE_BLOCKER** |
| **Owner** | Repository administrator — **not the tree** |
| **Action** | Enable it, then re-verify. See §5 |
| **Verification** | The same API call must return `{"enabled":true}` |
| **Status** | **OPEN** |

### RB-03 — vulnerability scan · **CLOSED**

| | |
|---|---|
| **Evidence** | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` → **"No vulnerabilities found."** |
| **Severity** | Was RELEASE_BLOCKER |
| **Owner** | Release gate |
| **Action** | Run the official scanner. `go run` was used rather than `go install`: nothing was persisted, and `go.mod`/`go.sum` were verified unchanged afterwards |
| **Verification** | Real result recorded above, not a green mark on an unrun tool |
| **Status** | **CLOSED** — with the standing caveat that it is a manual gate, since no workflow runs it (UX-S17) |

### RB-04 — clean-room install · **CLOSED**

| | |
|---|---|
| **Evidence** | `GOBIN=<temp> CGO_ENABLED=0 go install ./cmd/svcdoctor`, then run from an **empty** directory: `--version`, `--help`, `diagnose --help`, `run --help` all correct |
| **Severity** | Was RELEASE_BLOCKER |
| **Owner** | Release gate |
| **Action** | See §4 for the limitation and the post-tag procedure |
| **Verification** | No source tree reachable at runtime; cwd verified empty |
| **Status** | **CLOSED** |

### RB-05 — no release automation produces archives or checksums · **OPEN**

| | |
|---|---|
| **Evidence** | ADR 0076 §2.3 lists five archives and `SHA256SUMS` as **required**. `.github/workflows/release-oci.yml` contains no `GOOS`/`GOARCH` matrix, no `tar`/`zip` step and no checksum step; its `gh release create` attaches exactly one asset, `sbom.cdx.json` |
| **Severity** | **RELEASE_BLOCKER** |
| **Owner** | Release engineering |
| **Action** | Three ways to close it, in preference order: **(a)** add the archive-and-checksum job to the release workflow; **(b)** perform it as a documented **manual post-tag step** — the recipe is proven and is in §7, so this needs only a checklist line, not new code; **(c)** amend ADR 0076 §2.3 to make archives optional for v0.4.0. **(a)** and **(c)** are out of this gate's scope, which forbids new release automation and contract changes |
| **Verification** | The five archives and `SHA256SUMS` are attached to the `v0.4.0` Release and `shasum -a 256 -c` verifies them, or ADR 0076 §2.3 no longer requires them |
| **Status** | **OPEN** |

### RB-06 — tag, version and image consistency · **CLOSED**

| | |
|---|---|
| **Evidence** | See §6, §7, §8 |
| **Severity** | Was RELEASE_BLOCKER |
| **Owner** | Release gate |
| **Action** | Version injection, tag style and image tag policy all verified against the real recipe |
| **Verification** | `-ldflags "-X main.version=v0.4.0"` → binary reports `v0.4.0`; every prior tag is annotated; the workflow publishes no moving tag |
| **Status** | **CLOSED** |

### RB-07 — release notes · **CLOSED**

| | |
|---|---|
| **Evidence** | `docs/releases/v0.4.0.md`, written from `git log v0.3.3..HEAD` |
| **Severity** | Was RELEASE_BLOCKER |
| **Owner** | Release gate |
| **Action** | Written; every version claim traced to `docs/COMPATIBILITY.md` |
| **Verification** | §9; doc-claim guards green |
| **Status** | **CLOSED** |

### RB-09 — a RabbitMQ integration guard passed only when svcdoctor learned less · **CLOSED**

| | |
|---|---|
| **Evidence** | `integration-rabbitmq` failed on `TestRAB18ManagementPortTargetedAsAMQP`: `svcdoctor inferred a service from a port number: "management"` / `"http"` |
| **Severity** | RELEASE_BLOCKER while open — a release gate cannot pass with a failing integration suite |
| **Owner** | Integration test, **not the product** |
| **Action** | See below |
| **Verification** | Suite green, run twice, deterministic; production code untouched |
| **Status** | **CLOSED** |

**The product is not at fault, and that was established before anything was changed.** Production
code was byte-identical to `HEAD` throughout — `git status` on `internal/` and `cmd/` was empty.

The banned words come from the frozen recommendation in
`internal/diagnosis/rabbitmq/protocol.go`:

> "Confirm the port carries AMQP 0-9-1 rather than the **management HTTP** API, a TLS listener
> addressed as plaintext, or another protocol"

ADR 0067 §3's rule is **behavioural** — *"the port is never semantic: a TLS plan comes from
`--tls` and never from the port number."* That recommendation decides nothing from the port; it
lists candidates for the operator to rule out. The finding's own detail says so explicitly:
*"This is not a claim about which product is listening or which version it runs."*

**Why it passed before.** `ConnectionStart` fires only on `StateFail`, and skips a
local-timeout `UNKNOWN`. When the HTTP listener answered slower than the 5s step budget, the node
was `UNKNOWN`, **no finding existed**, and the substring ban had nothing to match. The suite
passed in Phase 9.2B for that reason. This gate hit the fast path, the finding fired, and the
contradiction surfaced.

**A guard that passes only when the product learns less is not a guard.** That is the defect.

**The fix does not weaken it.** The substring ban still applies to every surface that states a
fact — summary, detail and recorded attributes. On the recommendation surface it is replaced by
an **exact-match pin** of the frozen string, which is *stronger* there: any drift toward a real
claim now fails and has to be read by a human, where a substring ban would have permitted any
new wording that avoided four words.

Only `test/integration/rabbitmq/transport_test.go` changed. No production file, no schema, no
finding code, no invariant.

### RB-08 — artifact provenance is source qualification only · **OPEN by construction**

| | |
|---|---|
| **Evidence** | This gate modified five files, so `make image-dev` produced `svcdoctor:sha-7e7df84-dirty` reporting version `0.0.0-dev+7e7df84.dirty` |
| **Severity** | Procedural, not a defect — the recipe **correctly refused** to claim a clean commit |
| **Owner** | Release gate |
| **Action** | Commit this gate's changes, then re-run artifact qualification against the committed tree before tagging |
| **Verification** | `git status --porcelain` empty, then the §7 matrix re-run |
| **Status** | **OPEN until this gate's own output is committed** — see §12 |

---

## 2. RB-01 — the 20 survivors, individually

**Every one is `SCRIPT_DEFECT`. None was a product defect, and none was retired.**

### The single root cause

Phase 9.1C renumbered **28 test functions** back to the frozen MT identifiers. The `phase91a`
and `phase91b` harnesses still named the pre-renumbering tests. `go test -run <regex>` with a
regex that matches nothing **exits 0**, and the harness reads exit 0 as "the mutation survived".

So twenty mutations reported a finding about the product when the finding was about the harness.

### Proof that no product behaviour was vulnerable

Each mutation was planted and the **whole package suite** run against it, rather than the narrow
regex. **All twenty were caught.** The guarding test existed and passed the entire time; only the
selector was stale.

| Mutation | Intended contract | Classification | Guarding test (measured) |
|---|---|---|---|
| `A02` | duplicate YAML keys rejected | SCRIPT_DEFECT | `TestMTC14DuplicateYAMLKeyIsRejectedAtEveryLevel` |
| `A03` | merge key rejected | SCRIPT_DEFECT | `TestMTC18MergeKeyIsRejected` |
| `A04` | plaintext scalar password refused | SCRIPT_DEFECT | `TestMTC06AndS08APlaintextPasswordIsRefusedStructurally` |
| `A05` | `env` and `file` together refused | SCRIPT_DEFECT | `TestMTC07BothSourcesAreRefused` |
| `A06` | empty credential reference refused | SCRIPT_DEFECT | `TestMTC08NeitherSourceIsRefused` |
| `A08` | target-count bound enforced | SCRIPT_DEFECT | `TestMTC23AndC30TargetCountBounds` |
| `A09` | config byte bound enforced | SCRIPT_DEFECT | `TestMTC22ConfigByteBound` |
| `A10` | unsupported config version refused | SCRIPT_DEFECT | `TestMTC15AndC16ConfigVersion` |
| `B05` | one credential is not shared across targets | SCRIPT_DEFECT | `TestMTE10SameReferenceResolvesIndependently` |
| `B07` | completion order never becomes report order | SCRIPT_DEFECT | `TestMTE08AndD02CompletionOrderNeverReachesTheReport` |
| `B09` | a diagnostic failure does not stop the run | SCRIPT_DEFECT | `TestMTE02NoFailFastOnDiagnosticOrExecutionFailure` |
| `B10` | an execution failure does not stop the run | SCRIPT_DEFECT | `TestMTE02NoFailFastOnDiagnosticOrExecutionFailure` |
| `B14` | run deadline dominates target deadline | SCRIPT_DEFECT | `TestMTE17RunDeadlineDominatesTargetDeadline` |
| `B15` | a target timeout does not cancel siblings | SCRIPT_DEFECT | `TestMTE16ATargetTimeoutDoesNotCancelASibling` |
| `B16` | the concurrency ceiling holds | SCRIPT_DEFECT | `TestMTE11AndE13AndE14Concurrency` |
| `B17` | concurrency zero is refused | SCRIPT_DEFECT | `TestMTE11AndE13AndE14Concurrency` |
| `B18` | worker count never exceeds concurrency | SCRIPT_DEFECT | `TestMTE12MaxConcurrencyIsObserved` |
| `B26` | a resolution failure does not stop other targets | SCRIPT_DEFECT | `TestMTE02NoFailFastOnDiagnosticOrExecutionFailure` |
| `B27` | duplicate endpoints are distinct executions | SCRIPT_DEFECT | `TestMTE09DuplicateEndpointsAreDistinctExecutions` |
| `B28` | the same reference does not reuse one credential | SCRIPT_DEFECT | `TestMTE10SameReferenceResolvesIndependently` |

One renaming was actively misleading rather than merely stale: **`A09`'s old selector `TestMTC14`
now names `A02`'s guarding test.** So `A09` was running the duplicate-key test against a
byte-bound mutation — selecting nine tests, none of which could ever fail for that reason.

### The fix, and why nothing was retired

**No mutation met the ADR-required retirement bar** (§4 of the gate: the contract no longer
exists, the path is unreachable, a stronger invariant supersedes it, or the mutation cannot
change behaviour). Every one still describes a live frozen requirement whose guard still exists.
So all twenty were **repaired**, by pointing each at the test that actually guards it.

### The structural fix that prevents recurrence

All four harnesses now **fail loudly when a `-run` regex selects no test**:

```
  A02  NO MATCHING TEST — the -run regex selects nothing: <regex>
```

counted as a harness failure rather than a product finding, because the two need opposite fixes
and were indistinguishable without it.

Two defects were found while building that guard and are recorded because they are the same class
of error:

1. The check was first placed **after** planting. A mutation that deliberately breaks the build
   also produces no `=== RUN`, so it could not tell "regex matches nothing" from "the mutation
   worked". It now runs on the pristine tree, before planting.
2. `go test … | grep -q` makes `grep` exit at the first match, `go test` take `SIGPIPE`, and the
   pipeline report failure under `set -o pipefail` — so **every** regex, including ones matching
   nine tests, looked like it matched none. The output is now captured before being searched.

The guard immediately earned itself: it found a **twenty-first** stale selector, `B07`'s
`TestMTE07AndD02…` (the test is `TestMTE08AndD02…`), which the old harness had been silently
reporting as caught.

### Final mutation state

| Suite | Planted | Caught | Survivors | Retired |
|---|---|---|---|---|
| Phase 9.1A | 20 | **20** | **0** | 0 |
| Phase 9.1B | 31 | **31** | **0** | 0 |
| Phase 9.1C | 45 | **45** | **0** | 0 |
| Phase 9.2B | 21 | **21** | **0** | 0 |
| **Total** | **117** | **117** | **0** | **0** |

**Unexplained survivors: 0.** The original denominators are unchanged — nothing was retired, so
nothing was removed from the count.

---

## 3. Quality and invariants

`make check` green: `gofmt`, `go vet`, `golangci-lint` **0 issues** (including `gosec` and
`forbidigo`), `CGO_ENABLED=0 go build ./...`. `go test ./...` and `go test -race ./...` clean.
`git diff --check` clean. `go mod tidy` is a **no-op**.

| Invariant | Expected | Measured |
|---|---|---|
| `domain.SchemaVersion` | 1 | **1** |
| `domain.RunSchemaVersion` | 1 | **1** |
| Finding codes | 60 | **60** — `DNS:2 KAFKA:13 POSTGRES:19 RABBITMQ:11 REDIS:9 TCP:1 TLS:5` |
| RabbitMQ finding codes | 11 | **11** |
| Failure classes | 42 | **42** |
| `security.Reveal` sites | 4 | **4** |
| `SecretFor` sites | 4 | **4** |
| External modules | 2 | **2** |

No new service, no new CLI command, no new credential source, no report-schema change, no
config-schema change.

**Dependencies.** Go 1.26.6. `go list -m all` is exactly the module plus
`github.com/twmb/franz-go/pkg/kmsg v1.13.1` and `go.yaml.in/yaml/v3 v3.0.5`. `go mod graph` shows
neither has a dependency of its own. `go mod verify`: **all modules verified**. `go.sum` is 4
lines. Licences: BSD-3-Clause and MIT/Apache-2.0 — both compatible with the project's Apache-2.0.

---

## 4. Clean-room install and binary

`GOBIN` isolated, `CGO_ENABLED=0 go install ./cmd/svcdoctor`, run from an empty directory:
`--version`, `--help`, `diagnose --help`, `run --help` all correct with **no source tree
reachable**.

**Limitation, stated:** `go install <module>@v0.4.0` cannot be tested before the tag exists. What
is proven is the local module install path and the binary's independence from the source tree.
The post-tag procedure is in §12.

Clean-room behaviour from the extracted **release archive**, in a directory containing only the
artifact:

| | |
|---|---|
| config error (unknown field) | exit **2**, stdout 0 bytes, error names file and line |
| missing config file | exit **2** |
| valid run against an unresolvable host | exit **1** |
| JSON output | one document, `schemaVersion 1`, `svcdoctorVersion v0.4.0` |
| shareable output | `targetId: target-001`, `outputMode: SHAREABLE_REDACTED` |

No error path depended on a repository-relative file.

---

## 5. RB-02 — the exact manual action

```console
$ gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting
{"enabled":false}
```

`SECURITY.md` names this as the project's **only** reporting channel, so while it is off the
policy links to a form that does not exist — worse than no policy, because it looks like a
channel.

**This gate did not change it.** Enabling it is a write to remote repository state, which the
gate is instructed not to perform and which was not authorized.

**Required action, by the repository administrator, one of:**

```sh
gh api -X PUT repos/hakanaltindag/svcdoctor/private-vulnerability-reporting
```

or through the web UI, under the repository's **Settings → Code security**, the
**Private vulnerability reporting** control. *(The API path above is verified — its `GET` was
used for the measurement. The UI wording is GitHub's and may differ from this text; the API is
the authority.)*

**Then re-verify** — release condition is a documented channel **and** `{"enabled":true}`:

```sh
gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting   # want {"enabled":true}
```

`SECURITY.md` itself is truthful as written: it names the mechanism, invents no email address, no
SLA and no support lifetime, and its content is asserted by
`TestUX2123TheRepositoryHygieneFilesExist`.

---

## 6. Version and producer metadata

Release-recipe injection, exactly as `Dockerfile` line 56 does it:

```console
$ go build -ldflags "-s -w -X main.version=v0.4.0" … && ./svcdoctor --version
v0.4.0
```

A build from a **dirty** tree reports `dev`, and the image recipe reports
`0.0.0-dev+7e7df84.dirty` — both correctly refuse to claim a release. **No artifact built from a
dirty tree is a release candidate** (§12).

Producer version, from the release artifact, in every projection:

| Document | `schemaVersion` | `run.svcdoctorVersion` |
|---|---|---|
| single-target | 1 | `v0.4.0` |
| single-target `--shareable` | 1 | `v0.4.0` |
| aggregate | 1 | `v0.4.0` (embedded report: `v0.4.0`) |
| aggregate `--shareable` | 1 | `v0.4.0` (embedded report: `v0.4.0`) |

**Redaction does not remove the producer version**, which is what keeps a shared report
attributable to a build. No schema change.

---

## 7. Artifacts

Five platforms, `CGO_ENABLED=0`, `-trimpath`, release ldflags. All built.

| Platform | Binary | Archive |
|---|---|---|
| linux/amd64 | 7 340 194 B | `svcdoctor_0.4.0_linux_amd64.tar.gz` |
| linux/arm64 | 6 619 298 B | `svcdoctor_0.4.0_linux_arm64.tar.gz` |
| darwin/amd64 | 7 509 440 B | `svcdoctor_0.4.0_darwin_amd64.tar.gz` |
| darwin/arm64 | 6 816 498 B | `svcdoctor_0.4.0_darwin_arm64.tar.gz` |
| windows/amd64 | 7 545 344 B | `svcdoctor_0.4.0_windows_amd64.zip` |

**Contents:** `svcdoctor` (`.exe` on Windows), `LICENSE`, `README.md`. Verified absent from every
archive: `.DS_Store`, `.git`, `testdata`, `CLAUDE.md`, `AGENTS.md`, `.pem`, `.key`, anything
matching `secret`.

**Checksums:** `SHA256SUMS`, one line per artifact, five lines, **no path separators**, and
`shasum -a 256 -c` verifies all five.

**Native execution:** the `darwin/arm64` archive extracted to a fresh directory runs
`./svcdoctor --version` → `v0.4.0` and `--help` correctly. Foreign-architecture binaries were
built and inspected, not executed.

**All candidate artifacts were generated under `/tmp` and deleted.** None entered Git; the tree
contains no archive, checksum or binary.

*One cleanup overreach is recorded rather than left unsaid: removing the candidate image used a
pattern broad enough to also delete a pre-existing local `svcdoctor:v0.3.0` image. That is local
Docker cache, not repository state, and it is rebuildable from the `v0.3.0` tag with
`make image`. Nothing published was touched.*

---

## 8. Tag, image and workflows

**Tag style: annotated.** `v0.1.0`, `v0.2.0`, `v0.3.0`, `v0.3.2` and `v0.3.3` are all annotated
with subject `svcdoctor vX.Y.Z`. v0.4.0 must follow.

**Image tags.** `release-oci.yml` triggers on `push: tags: v*`, and publishes `:vX.Y.Z` only —
**no `latest`, no `v0`, no `v0.4`**. That matches ADR 0062 and the README. The image derives from
the tagged commit, so archives and image share one source.

**Local image build** (`make image-dev`, never pushes):

| | |
|---|---|
| base | `gcr.io/distroless/static-debian12:nonroot`, **pinned by digest** |
| builder | `golang:1.26.6-bookworm`, pinned by digest |
| user | `65532:65532`, non-root |
| entrypoint | `/svcdoctor`, no shell wrapper |
| shell | **absent** — `/bin/sh` does not exist |
| size | 3 423 250 B |
| read-only rootfs, `--cap-drop=ALL`, `no-new-privileges` | **runs correctly** |

**Workflows.** Every third-party action is SHA-pinned except `golangci/golangci-lint-action@v9`
in `ci.yml`, which carries a written exception (UX-S16-b) and is asserted by
`TestUX22TheSupplyChainPinningIsRecorded`. Global `permissions: contents: read`, escalated
per-job only where needed.

**Release secrets: `secrets.GITHUB_TOKEN` only.** No registry token and no signing key — cosign
is keyless through OIDC (`id-token: write`). No external release infrastructure is required.

---

## 9. Documentation and compatibility

**Release notes:** `docs/releases/v0.4.0.md`, matching the `v0.3.3.md` convention. **No
`CHANGELOG.md` was introduced** — release notes are this project's model and ADR 0076 requires no
changelog.

Every version claim traces to `docs/COMPATIBILITY.md`. No managed or cloud platform is upgraded;
24 unclaimed markers (`NOT TESTED` / `DOCUMENTATION ONLY` / `NOT EVALUATED`) remain. No
"production ready", no "enterprise", no guarantee wording.

**Links:** 72 local Markdown links across the public documents, plus 6 in the release notes —
**0 broken**.

**README five-minute replay:** all 14 questions answered from the shipped documents, none
requiring an ADR or the source.

**Known limitations retained** in the release notes: concurrency bounds targets not sockets, no
global probe semaphore, no cross-target causal diagnosis, no topology discovery, managed/cloud
unclaimed, terminal wrapping deferred, single-target JSON carries no completeness flag.

**Deferred UX items unchanged:** `UX-09` and `UX-19` remain `DEFERRED_BY_CONTRACT` — 22 PROVEN,
2 DEFERRED_BY_CONTRACT, 0 MISSING. Neither is a v0.4.0 blocker.

---

## 10. Security corpus, exit codes and interrupts

`test/security` green; the shareable-leakage corpus passes **42 subtests** across canonical
`RunReport`, JSON and terminal, covering secret values, `env` reference names, secret file paths,
CA file paths, IPv4, IPv6, zoned IPv6, hostnames, identities, mixed fleets and execution-only
targets. **Zero shareable residual escapes.**

Exit codes, through the extracted release artifact:

| Code | Scenario | Result |
|---|---|---|
| 0 | no error-level problem proven | ✓ |
| 1 | target-side problem | ✓ |
| 2 | config error — **stdout 0 bytes, no fabricated RunReport** | ✓ |
| 4 | local budget expired — **report preserved, 846 B** | ✓ |

Exit 3 is exercised by the in-tree matrix rather than fabricated here.

**Interrupts.** First `SIGINT`: graceful, exit **4**, truthful report, `stopped cancelled; this
says nothing about any target`, stderr empty — verified black-box. Second `SIGINT`: **could not
be forced from outside.** The shutdown window is too small to hit with `kill` from a shell, which
is the limitation Phase 9.1C already recorded. It is proven instead by
`TestMTE07AFirstInterruptCancelsAndASecondAborts`, which passes. Recorded as a weaker claim
rather than asserted as a black-box result.

---

## 11. Reproducibility

Two `linux/amd64` builds from identical source, `-trimpath`, identical ldflags:

```
build A: 64bcad9272e66cc32d02f7fbd97208192507eb74872aece9f634d7dac5c3ea72
build B: 64bcad9272e66cc32d02f7fbd97208192507eb74872aece9f634d7dac5c3ea72
```

**The binary is byte-identical — reproducible under tested conditions.**

**The `tar.gz` is not.** `tar` and `gzip` embed modification times and the archiving step pins
none. ADR 0076 does not require reproducible archives — its reproducibility clause is scoped to
the *platform image manifest* — so this is **not a blocker**. It is recorded so no one later
claims archive reproducibility that was never built.

---

## 12. Pre-tag, tag-time and post-tag

**PRE-TAG** — all complete except RB-02 and RB-05: tests, race, lint, static analysis, 117/117/0
mutations, `govulncheck`, eight integration suites, docs, release notes, build qualification.

**TAG-TIME** — annotated tag `v0.4.0` on the release commit, subject `svcdoctor v0.4.0`. **Not
created by this gate.**

**POST-TAG** — archive build from the tag, checksums, image publish, GitHub Release, publication
verification, and `go install …@v0.4.0` as the real clean-room proof.

**Source qualification versus final tagged-build qualification.** Everything in §7 was measured
against a tree carrying this gate's own five changed files, so the image recipe correctly
produced `sha-7e7df84-dirty`. **Artifact qualification must be re-run against the committed
release-candidate tree before tagging.** This document qualifies the *source*; it does not
establish provenance for any artifact.

---

## 12b. Files changed by this gate

Seven, none of them production code.

| File | Bucket |
|---|---|
| `scripts/phase91a-mutations.sh` | RB-01 — 8 selectors repaired, zero-match guard |
| `scripts/phase91b-mutations.sh` | RB-01 — 13 selectors repaired, zero-match guard |
| `scripts/phase91c-mutations.sh` | RB-01 — zero-match guard |
| `scripts/phase92b-mutations.sh` | RB-01 — zero-match guard |
| `test/integration/rabbitmq/transport_test.go` | RB-09 — assertion narrowed to claim surfaces, recommendation pinned |
| `docs/BACKLOG.md` | RB-01 resolution, RB-02/RB-05 blockers, RB-09 |
| `docs/RELEASE_CHECKLIST.md` | RB-01 resolved, RB-05 added |
| `docs/releases/v0.4.0.md` | new — release notes |
| `docs/validation/V040_RELEASE_CANDIDATE_GATE.md` | new — this document |

**`internal/` and `cmd/` are untouched.** Verified with `git status` and `git diff HEAD` on both,
before and after the gate.

## 13. RC traceability

| RC-ID | Requirement | Evidence | Status |
|---|---|---|---|
| RC-01 | clean tree | `git status --porcelain` empty at gate start; 5 files changed by the gate itself, all documentation or test harness | PASS |
| RC-02 | baseline quality | `make check`, `go test`, `-race`, `git diff --check`, `go mod tidy` no-op | PASS |
| RC-03 | mutation debt | §2 — 117 planted, 117 caught, **0 unexplained survivors**, 0 retired | PASS |
| RC-04 | private vulnerability reporting | `{"enabled":false}` — §5 | **FAIL — RB-02** |
| RC-05 | govulncheck | "No vulnerabilities found" | PASS |
| RC-06 | clean install | isolated `GOBIN`, empty cwd — §4 | PASS |
| RC-07 | five-platform builds | §7, all five | PASS |
| RC-08 | archive contents | binary + LICENSE + README; no noise, no secrets | PASS |
| RC-09 | checksums | `SHA256SUMS`, 5 lines, no paths, `-c` verifies | PASS |
| RC-10 | native artifact execution | darwin/arm64 extracted and run | PASS |
| RC-11 | version metadata | `v0.4.0` injected; dirty → `dev` | PASS |
| RC-12 | producer metadata | all four projections, schema 1 | PASS |
| RC-13 | tag strategy | annotated, matches all prior tags | PASS |
| RC-14 | image strategy | `:vX.Y.Z` only, no moving tag, same commit | PASS |
| RC-15 | image local build | distroless, non-root, no shell, read-only rootfs | PASS |
| RC-16 | release notes | `docs/releases/v0.4.0.md` | PASS |
| RC-17 | compatibility | frozen; nothing upgraded; managed unclaimed | PASS |
| RC-18 | public docs | 78 local links, 0 broken; 14/14 replay | PASS |
| RC-19 | security corpus | 42 subtests, 3 surfaces, 0 escapes | PASS |
| RC-20 | full integration | eight suites — §14 | PASS |
| RC-21 | exit codes | 0/1/2/4 black-box, 3 in-tree | PASS |
| RC-22 | interrupt contract | first black-box; second in-tree, limitation stated | PASS |
| RC-23 | reproducibility | binary identical; archive not, and not required | PASS |
| RC-24 | release checklist | §15 | **MANUAL_REQUIRED — RB-02, RB-05** |
| RC-25 | invariant freeze | §3, all eight unchanged | PASS |
| RC-26 | release artifact automation | no workflow builds archives or checksums | **FAIL — RB-05** |

---

## 14. Integration suites

Run sequentially, one at a time.

| Suite | Versions | Result |
|---|---|---|
| PostgreSQL | 18 | PASS |
| Kafka | Apache Kafka 4.0.0, 3-broker KRaft | PASS |
| Redpanda | v25.1.9 | PASS |
| Redis | 8.2.1 | PASS |
| Valkey | 8.1.1 | PASS |
| RabbitMQ | 3.13.7, 4.0.9, 4.2.0 | PASS — after RB-09; see §1 |
| LavinMQ | 2.3.0 | PASS |
| Multi-target | all four services | PASS |

Zero unexpected skips, zero fixture overlap, zero leftover containers. **No compatibility level
was raised.**

RabbitMQ failed on the first pass and is recorded as **RB-09**: a timing-dependent test
assertion, not a product defect. Re-run twice after the test fix, deterministic both times.

---

## 15. Release checklist status

Every blocking item PASS except:

- **Private vulnerability reporting enabled** — MANUAL_REQUIRED (RB-02).
- **Release artifacts and checksums** — FAIL (RB-05): required by ADR 0076 §2.3, produced by no
  automation.
- **Pre-existing mutation harness debt reconciled** — now PASS; the checklist line should be
  updated to record the resolution.

`MANUAL_REQUIRED` is not counted as PASS.

---

## Verdict

**NOT_RELEASE_READY.**

Both open blockers are release-mechanism gaps rather than product defects, and neither can be
closed by changing the source under this gate's scope:

1. **RB-02** needs a repository setting turned on by an administrator.
2. **RB-05** needs release automation this gate is forbidden to write, a documented manual
   post-tag step, or an amendment to ADR 0076 §2.3. The **build recipe itself is proven** — all
   five archives were produced and their checksums verified here — so the gap is delivery, not
   feasibility.

The product itself qualified: 117/117/0 mutations, all gates green, eight integration suites
passing, artifacts building and verifying on five platforms, and no invariant moved.


---

## 16. Phase 9.3A — blocker closure · 2026-09-01

Added after the gate above, which is left exactly as it was measured. This section records what
changed and what did not.

### 16.1 Ledger

| ID | Gate result | Now | Evidence |
|---|---|---|---|
| RB-01 | CLOSED at the gate | **CLOSED** | 117/117/0 across the four historical harnesses, re-run at 9.3A and unchanged — after §16.7a, which is why the first re-run disagreed |
| RB-02 | **OPEN** | **CLOSED** | `gh api …/private-vulnerability-reporting` → `{"enabled":true}`, re-measured read-only at 9.3A |
| RB-05 | **OPEN** | **CLOSED** | `scripts/build-release.sh`, called by the `archives` job; proven by `test/release` and 10/10 mutations |
| RB-09 | CLOSED at the gate | **CLOSED** | RabbitMQ guard repaired at the gate and committed in `3c99cc1`; not reopened |
| RB-08 | OPEN by construction | **unchanged** | Artifact provenance is still source qualification only. See §16.6 |

### 16.2 RB-02 — measured, not assumed

```console
$ gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting
{"enabled":true}
```

Read-only. The setting was turned on outside this phase by the repository administrator, which
is the action §5 asked for; nothing here wrote to remote repository state and no vulnerability
report was submitted.

`SECURITY.md` was **not edited**, because it was already correct: it names GitHub private
vulnerability reporting, links the advisory form, states the supported-version window, and puts
credential leakage and redaction failure in scope. The document described a mechanism that did
not exist; the mechanism now exists. Editing truthful prose to celebrate that would only add a
sentence that could go stale.

### 16.3 RB-05 — one recipe, two callers

`scripts/build-release.sh <version> [output-dir]` is the mechanism. It refuses a malformed
version, refuses a dirty tree, refuses a version that is not a tag on `HEAD` (waivable **only**
by `--untagged`, for qualifying a candidate before the tag exists — which waives nothing else),
builds the five ADR 0076 §2.3 platforms with `CGO_ENABLED=0 -trimpath` and the existing
`-X main.version=` injection, names archive members explicitly rather than archiving a
directory, writes `SHA256SUMS` from inside the output directory, and verifies it. It stages
platform binaries outside the repository and cleans them on success, failure and interrupt. It
publishes nothing.

The `archives` job in `release-oci.yml` **calls that script**, with the version `identity`
derived from Git. This is the whole of RB-05's fix: closing it with a `GOOS`/`GOARCH` matrix
written into YAML would have produced the artifacts and a second recipe that no local gate ever
runs — the drift RB-05 exists to prevent, one layer up. A guard fails the build if the workflow
stops calling the script or starts cross-compiling on its own.

**Ordering changed deliberately.** `publish` now needs `archives`. The first irreversible act of
a release is pointing the GHCR semver tag at a digest; an archive recipe that failed after that
point would reproduce the v0.3.2 shape — a correct published image and an incomplete release,
repairable only by burning the next version.

### 16.4 The artifacts, rebuilt through the new mechanism

Qualified with the builder, not by hand. Method, because it matters: the phase's own tree is
dirty by construction, so the content was copied to a temporary directory outside the
repository, committed there, tagged `v0.4.0`, and built in **release** mode — the dirty-tree and
tag refusals were satisfied rather than relaxed. The fixture's commit SHA is not this
repository's, so this proves the recipe and not the provenance of any particular release.

| Artifact | Contents |
|---|---|
| `svcdoctor_0.4.0_linux_amd64.tar.gz` | `svcdoctor`, `LICENSE`, `README.md` |
| `svcdoctor_0.4.0_linux_arm64.tar.gz` | `svcdoctor`, `LICENSE`, `README.md` |
| `svcdoctor_0.4.0_darwin_amd64.tar.gz` | `svcdoctor`, `LICENSE`, `README.md` |
| `svcdoctor_0.4.0_darwin_arm64.tar.gz` | `svcdoctor`, `LICENSE`, `README.md` |
| `svcdoctor_0.4.0_windows_amd64.zip` | `svcdoctor.exe`, `LICENSE`, `README.md` |
| `SHA256SUMS` | five lines, no path separators, no self-entry, verifies |

**Naming.** `svcdoctor_<version-without-v>_<os>_<arch>` follows the only binary release this
project has published — v0.1.0's assets were exactly that shape — and matches §7 of this gate.

**Contents differ from v0.1.0 on purpose.** v0.1.0's archives held a single file, the binary
named `svcdoctor_0.1.0_darwin_arm64`, with no `LICENSE` and no `README.md`. These hold a binary
named `svcdoctor` plus both files: Apache-2.0 §4(a) requires giving recipients a copy of the
licence with a redistributed work, and an archive that extracts to a file the operator must
rename first is a worse install journey for no gain. §7 of this gate recorded the same contents.

**Native execution:** `svcdoctor_0.4.0_darwin_arm64.tar.gz` extracted to a fresh directory,
`./svcdoctor --version` → `v0.4.0`, `--help` correct, `file` reports `Mach-O 64-bit executable
arm64`.

**Foreign artifacts** were built and inspected, not executed — an archive naming a platform has
to contain a binary *for* that platform, and nothing but `file` can say so:

| Archive | `file` |
|---|---|
| `linux_amd64` | ELF 64-bit LSB executable, x86-64, statically linked |
| `linux_arm64` | ELF 64-bit LSB executable, ARM aarch64, statically linked |
| `darwin_amd64` | Mach-O 64-bit executable x86_64 |
| `windows_amd64` | PE32+ executable (console) x86-64, for MS Windows |

**Verified with tools other than the ones that wrote the artifacts:** members listed with
Python's `tarfile`/`zipfile`, checksums re-verified with `shasum -a 256 -c` where the builder had
used `sha256sum`. That is not pedantry — §16.5 is a defect that only a second reader could see.

**All output was deleted.** No archive, checksum or binary is in the repository, and `dist/` is
ignored.

### 16.5 A real defect the executable test found

The first archives this builder produced contained `._svcdoctor`, `._LICENSE` and `._README.md`
— AppleDouble members holding macOS extended attributes. **`tar -tzf` on macOS did not show
them**, because bsdtar folds them back on read; Go's `archive/tar` reader did, which is what the
Linux machine unpacking the release would have seen. A hand-verified archive would have shipped
three junk files beside the binary.

Fixed by exporting `COPYFILE_DISABLE=1`, which bsdtar honours and GNU tar ignores. Recorded
because the lesson generalises: the tool that wrote an archive is the wrong tool to verify it
with, and `test/release` reads both archive formats with the standard library for that reason.

### 16.6 What is still not claimed

**Reproducible archives.** §11 measured the binary as byte-identical across builds and the
`tar.gz` as not reproducible — `tar` and `gzip` embed modification times. That is unchanged:
the builder pins no timestamp, ADR 0076 requires no such thing, and its reproducibility clause
is scoped to the platform image manifest. **No archive reproducibility is claimed.**

**A rehearsed release.** Nothing was tagged, pushed or published. The workflow's behaviour on a
real tag is proven statically — it calls the shared builder, gates `publish` on it, uploads the
five archives, `SHA256SUMS` and the unchanged `sbom.cdx.json`, and reads the asset list back
from the API — and the script itself is proven by execution. Neither is a live GitHub Release,
and RB-08 stays open by construction: artifact provenance remains source qualification only.

**Container path unchanged.** No image, SBOM, provenance, signature, tag policy or permission
was touched. The `archives` job holds `contents: read` and nothing else; `contents: write`
remains held by exactly one job, `release`.

### 16.7 Mutation closure

| Suite | Result |
|---|---|
| `scripts/phase91a-mutations.sh` | 20 planted, 20 caught, 0 survivors |
| `scripts/phase91b-mutations.sh` | 31 planted, 31 caught, 0 survivors |
| `scripts/phase91c-mutations.sh` | 45 planted, 45 caught, 0 survivors |
| `scripts/phase92b-mutations.sh` | 21 planted, 21 caught, 0 survivors |
| `scripts/phase93a-mutations.sh` | **10 planted, 10 caught, 0 survivors** |

127/127/0, all five measured on a clean tree in one sequential pass. Every harness keeps its
zero-match guard, and 9.3A's has one from the start.

Two of the ten 9.3A mutations were survivors before the guards were tightened, and both are
recorded because they were guard defects rather than mechanism defects. R07 — dropping
`sbom.cdx.json` from the upload — survived a guard that searched the whole Release job, where
the SBOM is legitimately named four times in steps that do not upload it; the guard now reads
the `gh release create` invocation alone. R06 exposed the same class of problem in the harness
itself: a mutation that cannot be planted looks exactly like a guard that cannot fail.

### 16.7a An interrupted harness poisoned the run that followed it

An earlier 9.3A pass reported `phase91c` as **44 caught, 1 survivor** — C28, *a target timeout
cancels its siblings*. It was neither a product defect nor a guard defect, and the diagnosis is
worth keeping because the failure was silent and self-consistent.

A prior run of that suite had been killed by a command timeout part-way through, leaving **C27's
mutation planted** in `internal/fleet/run/execute.go`: a target context rooted at
`context.Background()` rather than at the run context. The next run took that tree as its
pristine baseline, and with target contexts already detached from the run context, C28's
mutation — cancelling the run when a target's own deadline expires — could not reach the
siblings. So the guard passed, correctly, about a tree nobody meant to measure.

Nothing in the harness could see it. The `BEFORE`/`AFTER` checksums prove a run put back what it
found; they say nothing about whether what it found was the committed tree. The run duly
reported "tree restored byte-for-byte", and it was telling the truth.

**Diagnosis:** `git diff` on the file, which showed a mutation no one had planted deliberately.
Reproduced 5/5 on the polluted tree and caught on the restored one, so the survivor was an
artefact and not an intermittent guard.

**Fix, in all five harnesses:** `restore` now runs from an `EXIT`/`INT`/`TERM`/`HUP` trap,
guarded on the backup still existing so the ordinary path is not a double restore. A killed run
puts the tree back instead of leaving a mutation in it. **Proven, not assumed:** `phase91c` was
started and killed with `SIGTERM` at C11, exited 143, printed the restoration line, and left
`internal/` and `cmd/` clean.

A start-gate refusing a dirty tree was considered and rejected: these harnesses are run during
development, on trees with legitimate uncommitted work — including this phase's own. It would
have produced a false refusal every time and been deleted.

### 16.8 Verdict

**RELEASE_READY**, on the two blockers this phase owns. RB-02 and RB-05 are closed, every
invariant is unchanged, and `internal/` and `cmd/` carry zero production changes.

The release itself is still a human decision and still needs the ceremony in
`docs/RELEASE_CHECKLIST.md`: merge, negative check, annotated tag, and a watched workflow run.
Nothing here has been committed, tagged, pushed or published.
