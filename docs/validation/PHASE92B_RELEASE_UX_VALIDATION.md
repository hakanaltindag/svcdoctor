# Phase 9.2B — Release Blocker Remediation and Public UX Implementation

**Implementation phase.** It closed the four release blockers Phase 9.2A found, implemented the
public documentation and example contract frozen in ADR 0075–0077, and added the executable
proof that keeps those surfaces from drifting.

No new service, finding code, failure class, credential source or schema field. `SchemaVersion`
and `RunSchemaVersion` are unchanged. Nothing was committed, staged, pushed, tagged or released.

---

## 1. Start-state gate

| Gate item | Required | Measured | Verdict |
|---|---|---|---|
| Phase 9.2A committed | yes | `27d35b1 docs(release): freeze Phase 9.2 UX contract` | PASS |
| Working tree clean | yes | `git status --porcelain` empty | PASS |
| `make check` | green | exit 0 | PASS |
| `domain.SchemaVersion` | 1 | 1 | PASS |
| `domain.RunSchemaVersion` | 1 | 1 | PASS |
| Finding codes | 60 | 60 — `DNS:2 KAFKA:13 POSTGRES:19 RABBITMQ:11 REDIS:9 TCP:1 TLS:5` | PASS |
| RabbitMQ finding codes | 11 | 11 | PASS |
| Failure classes | 42 | 42 | PASS |
| `security.Reveal` production sites | 4 | 4 | PASS |
| `SecretFor` production sites | 4 | 4 | PASS |
| External modules | 2 | `kmsg` v1.13.1, `go.yaml.in/yaml/v3` v3.0.5 | PASS |

**Git facts, read from the repository rather than from `CLAUDE.md`.** Six tags exist —
`v0.1.0` through `v0.3.3`. `docs/releases/v0.3.3.md` records `v0.3.3` as the first release to
complete the whole publication path: signed multi-arch image, CycloneDX SBOM, provenance, GitHub
Release. That published release carries **PostgreSQL and Kafka**; Redis, RabbitMQ and
`svcdoctor run --config` are in the tree and in no published release. The version mechanism is
`cmd/svcdoctor/version.go`, whose `resolvedVersion()` feeds both `--version` and every report's
`run.svcdoctorVersion`.

That gap is the whole explanation for UX-B02: the README was written against a mixture of the
released product and the current tree.

---

## 2. The four blockers, reproduced before they were fixed

Every one was reproduced against `27d35b1` with a binary built from that commit. No fix was
written from the audit's description alone.

### UX-B01 — a shareable aggregate discloses addresses and paths

```console
$ svcdoctor run --config zone.yaml --shareable --output json
{ "targetId": "target-001", "service": "postgres",
  "executionState": "EXECUTION_FAILED",
  "executionError": { "class": "INTERNAL",
    "message": "invalid run input: unsupported host: fe80::1%en0 carries an IPv6 zone identifier…" } }

$ svcdoctor run --config badca.yaml --shareable --output json
  "executionError": { "class": "INTERNAL",
    "message": "loading the trust source: stat /etc/svcdoctor/pki/corp-root-ca.pem: no such file or directory" }
```

The target ID **was** pseudonymized. The address and the private-CA path were not. Reproduced on
the terminal surface too, and in a mixed run where one target had a report and one did not.

**Responsible layer:** `internal/security/redaction`. Two structural causes, both confirmed by
reading the code rather than inferred:

- `collectRun` began `if !result.HasReport() { continue }`, so a target that failed to execute
  contributed no identifiers and could not be looked for.
- `RedactRun` called no residual verification at all. `verifyNoResidual` lives inside
  `redactWith` and therefore only ever saw an embedded report — never the aggregate's own
  strings.

**Expected contract:** a shareable aggregate applies the same fail-closed residual contract as
shareable single-target output (ADR 0018; README's "redaction fails closed … exits 3").

### UX-B03 — a configuration error reaching execution

```console
$ svcdoctor diagnose postgres --host 'fe80::1%en0' --user app --tls disable
exit=2  svcdoctor: invalid invocation: --host fe80::1%en0 carries an IPv6 zone identifier…

$ svcdoctor run --config zone.yaml
exit=4  executionState EXECUTION_FAILED  class INTERNAL
```

Same for a missing `tls.ca_file`: exit 2 on the leaf, exit 4 and `INTERNAL` through the fleet.

**Responsible layer:** the composition path. `internal/fleet/services/postgres/postgres.go:123`
loaded the trust source inside `Run`; host parsing happened inside the composition root. Both
landed at `internal/fleet/run/execute.go:204`, which classifies as `ExecutionErrorInternal`.

**Expected contract:** `internal/domain/executionstate.go` states it in its own words —
*"configuration errors never reach execution at all — ADR 0074 §9 requires a whole configuration
to validate before any target is dialled."* The code contradicted its own documented invariant.

### UX-B02 — the README's stale and contradictory claims

Six measured, by line:

| Line | Said | Truth |
|---|---|---|
| 8 | "PostgreSQL BASIC and Kafka BASIC are supported today" | four services |
| 13–19 | journey diagram for two services | four have journeys |
| 337 | "There are exactly two credential sources" | three |
| 728 | "svcdoctor's production code reads no environment variable at all" | `internal/fleet/secret` reads one |
| 785 | "Two leaf commands" | five commands |
| 770 | "That workflow has never run, so nothing exists at GHCR yet" | contradicted at lines 660 and 672, and by `docs/releases/v0.3.3.md` |

**Responsible layer:** the guards. `internal/cli/docsclaims_test.go` forbids *over*claiming and
has no rule that can fire on a stale under-claim or an internal contradiction, which is why all
six survived `make check`.

### UX-B04 — no vulnerability reporting channel

No `SECURITY.md` at the root or under `.github/`. `docs/SECURITY.md` is the architecture record.
A case-insensitive search of `README.md`, `docs/` and `.github/` for a reporting address,
"responsible disclosure", "private vulnerability" or "security advisory" returned nothing.

---

## 3. The fixes

### UX-B03 — a service-neutral local preflight

**New: `internal/fleet/services/preflight.go`.** `PreflightAll` walks targets in declared order
and validates each target's local transport inputs before the scheduler starts.

It is **service-neutral**: there is no service switch and no per-service rule, because `host` and
the `tls` block are fields of the generic envelope (ADR 0071 §7.3). One pass covers four
services and every service added later.

It **duplicates nothing**. Both checks call the same function the runner calls later —
`probe.ParseHost` is the single host classification (ADR 0059) and `trustsource.Load` the single
trust loader. Preflight runs them earlier, where the answer is still a statement about the
configuration.

**Why it lives in `internal/fleet/services` and not in `internal/fleet/config`:** the
configuration package may import neither `internal/probe` nor `internal/security/*`, and both
restrictions are enforced by `test/security/fleet_boundary_test.go`. The second is what makes
"the parser cannot construct a secret" a property of the build. `services` is already the bridge
that legitimately holds probe types on the fleet layer's behalf.

**Wiring:** `internal/cli/run.go` calls it immediately before the credential preflight that
already ran at the same point, and `internal/cli/exit.go` classifies `services.ErrPreflight`
alongside `config.ErrConfig` and `secret.ErrResolution` — exit **2**.

**Two phrasings were extracted rather than copied**, which is what kept §10's no-duplication rule:

- `trustsource.Reason(err)` — the three trust-material refusals, now owned by the package that
  owns the rules. `internal/cli/tls.go` uses it; the leaf strings are **byte-identical**.
- `probe.Reason(err)` — the host refusal without the sentinel's prefix. `internal/cli` had this
  as a `strings.TrimPrefix` against a literal copy of the sentinel text, which goes stale
  silently. Now there is one owner and two callers.

**Result, measured:**

```console
$ svcdoctor run --config zone.yaml
exit=2  svcdoctor: target "prod-orders-db": host: fe80::1%en0 carries an IPv6 zone identifier…

$ svcdoctor run --config badca.yaml
exit=2  svcdoctor: target "prod-orders-db": tls.ca_file: cannot be read: no such file
```

Zero bytes on stdout. No report. The leaf output is unchanged.

### The pre-execution boundary, stated exactly

Validated **before** any target runs, with no network:

| Check | Where | Performs |
|---|---|---|
| Document shape, unknown fields, duplicate ids, versions | `config.Load` | reads one file |
| Durations, ports, concurrency, TLS mode, service config | `config.Load` | nothing |
| **Host syntax, including the zone refusal** | `services.PreflightAll` | string parsing |
| **Trust material: readable, bounded, holds a certificate** | `services.PreflightAll` | reads one operator-named file |
| Credential reference resolvable, value not retained | `secret.PreflightAll` | reads env or one file |

**Not performed at any point before execution:** no DNS resolution, no dial, no TLS handshake,
no authentication, no protocol exchange.

Proved rather than asserted: `TestUX08APreflightDefectExitsTwoAndDialsNothing` puts a **reachable
listener** in the same configuration as the broken target and requires the accept count to be
**zero**. `TestUX08TheZeroNetworkGuardCanFail` drives a valid configuration through the same
instrument and requires the count to rise, so a zero reading means something.

### Configuration error versus post-preflight failure

The Phase 9.1 distinction is preserved and now has a test.

| | Classification | Exit | Report |
|---|---|---|---|
| **Known at preflight** — the file was already absent, the host already unusable | configuration error | **2** | none; nothing dialled |
| **After preflight** — the material was proved loadable and then went away mid-run | local **execution** failure | **4** | aggregate produced; that target `EXECUTION_FAILED`; other targets keep their reports |

`TestUX08PreflightIsDistinctFromAPostPreflightFailure` forces the window rather than racing it:
the first target aims at `192.0.2.1`, a documentation-range address routed nowhere, so the
connect blocks for its whole step budget while the CA file is removed. Concurrency 1 means the
second target provably has not started.

*(The first version of that test used a `.invalid` hostname and failed: DNS refuses it in
milliseconds, which closes the window before it opens. The fixture is the fix.)*

**No new `ExecutionErrorClass` was added.** The two members are correct again precisely because
configuration errors no longer reach execution.

### UX-B01 — aggregate fail-closed redaction

Three changes in `internal/security/redaction/run.go`, all inside the existing architecture. **No
second redaction system was created.**

**1. Collection visits every result.** `collectRun` returns a `runValues` struct and no longer
skips report-less targets: each contributes its operator-chosen identifier.

A report-less target contributes its **identifier and nothing else**. Its execution message is
deliberately *not* mined for hosts or paths — inferring identities by reading prose is a regular
expression wearing a different hat, it fails open on the first message nobody anticipated, and
ADR 0018 forbids it.

**2. The shareable execution message is class-derived and locator-free.** Three options existed
and two are worse:

- *Search the message for host- and path-shaped substrings.* Rejected: `verifyNoResidual`'s own
  comment says why it checks exact known values rather than patterns — "so it cannot be satisfied
  by output that merely looks clean."
- *Add a structured locator field and drop it when sharing.* Rejected: a report-schema change,
  and `RunSchemaVersion` is frozen at 1.
- **Chosen:** replace the message with one svcdoctor authored, selected by the failure's class —
  already a separate, closed, machine-readable field. The locator is gone because it was never
  assembled, not because it was filtered.

What is given up is stated rather than glossed: a shareable report no longer says *which*
variable was missing or *which* file could not be read. Those are the local locators. The
LOCAL_FULL report the operator still holds says exactly which — and
`TestUX12TheLocalReportKeepsWhatTheOperatorNeeds` requires it to, so the corpus cannot be
satisfied by deleting the message.

**3. `verifyNoRunResidual` — the aggregate's net.** Hosts, addresses, identities and evidence
identifiers by **containment**, exactly as the per-report check does, which is what catches a
host collected from target A surviving inside target B's message. Target identifiers by **exact
equality**, because containment would be wrong and not merely imprecise: a target named `db` is a
substring of half the words in a finding's detail, and short identifiers are ordinary. And a
**collection-completeness check** — collection must have seen as many results as the document
holds, because "we looked at all of them" is the premise every other assertion rests on.

Failure is `ErrRedaction`, which `projectRun` turns into **exit 3** with no document written.

**Result, measured** on a genuine TOCTOU execution failure (CA file removed mid-run):

```console
$ svcdoctor run --config toctou.yaml --shareable --output json     # exit 4
  "executionError": { "class": "INTERNAL",
    "message": "the reason is local detail and is withheld from a shareable report" }
clean: corp-root-ca | db.corp.internal | /tmp/… | 10.255.255.1 | slow-first | prod-orders-db

$ svcdoctor run --config toctou.yaml --output json                 # LOCAL_FULL, exit 4
  "executionError": { "class": "INTERNAL",
    "message": "loading the trust source: stat /tmp/b92/toc/corp-root-ca.pem: no such file or directory" }
```

### UX-B02 — the README, reconciled against the repository

Rewritten as a landing page (ADR 0075 §2.4). Every stale claim corrected, and the whole document
audited rather than the six known lines patched:

- the headline states **four services**, and the journey diagram shows all four;
- the credential section documents **all three sources**, and replaces the false security claim
  with the true narrower one: *the four `diagnose` commands read no environment variable at all*;
- GHCR publication is stated once, consistently, matching `docs/releases/v0.3.3.md`;
- `## Current scope` names five commands;
- the roadmap says plainly that Redis, RabbitMQ and `run --config` are **implemented and not yet
  in a published release**, which is the fact a reader most needs and the one the old document
  could not express;
- a new platform note records the macOS pure-Go resolver limitation (ADR 0076 §2.4).

Detail moved to the owning documents, which are new: `docs/QUICKSTART.md`,
`docs/CONFIGURATION.md`, `docs/OUTPUT.md`, `docs/CI.md`.

### UX-B04 — a private reporting channel

**New: `SECURITY.md`** at the repository root, pointing at GitHub's private vulnerability
reporting for this repository. **No email address was invented**, and the guard fails if one
appears. It states what is in scope (credential exposure, redaction failure, credential transport
policy, TLS trust and identity, supply chain), what is a documented behaviour rather than a
vulnerability, what to include, and — honestly — what a single maintainer can commit to: a human
reply, a fix in a new release, credit. No response-time guarantee, because none could be kept.

**New: `CONTRIBUTING.md`**, required by ADR 0076 §2.5.

---

## 4. What was built

### Documentation architecture (ADR 0075 §2.4)

| Document | Status | Owns |
|---|---|---|
| `README.md` | rewritten | positioning, install, one example of each shape |
| `docs/QUICKSTART.md` | **new** | the five-minute first journey |
| `docs/CONFIGURATION.md` | **new** | every `run --config` field, credential references |
| `docs/OUTPUT.md` | **new** | terminal anatomy, JSON contract, shareable semantics |
| `docs/CI.md` | **new** | exit codes (authoritative), three policies, artifacts, four providers |
| `docs/COMPATIBILITY.md` | unchanged | what has actually been tested |
| `SECURITY.md` | **new** | vulnerability reporting |
| `CONTRIBUTING.md` | **new** | contribution guidance |

### Canonical examples (ADR 0075 §2.5)

`examples/minimal.yaml`, `examples/services.yaml` (one target per registered service),
`examples/production.yaml` (private CA, `env` and `file` references, explicit budgets). All three
parse through the real loader in tests; none contains a plaintext credential, a secret value or
an invented field; none demonstrates `insecure` as a production path.

### Help surfaces

`diagnose redis` gained the exit-code block and the exit-0 caveat every sibling carried;
`diagnose rabbitmq` gained the caveat; **`run` gained both** — the command written for CI was one
of the two with no exit-code documentation at all.

Seven golden snapshots in `internal/cli/testdata/help/`, plus
`TestUX02EveryHelpSurfaceCarriesItsContract`, which asserts the seven required elements per
surface. A golden pins what the text *is*; it cannot see that the text is incomplete, which is
exactly how `diagnose redis` kept no exit-code block through three phases.

### Drift guards

`internal/cli/docstructure_test.go` — the direction `docsclaims_test.go` was missing. Every YAML
fence in every public document and every shipped example decodes through the **real loader** (a
second parser would defeat the point); every relative link resolves (48 checked); the documented
services match the CLI registry; every credential source is documented; the shareable wording
stays honest; documented exit codes match the implemented ones; no documented shell example
discards the exit code (51 invocations checked).

---

## 5. Mutation closure — and the two defects it found in the fix

`scripts/phase92b-mutations.sh`: **21 planted, 21 caught, 0 survivors**, tree restored
byte-for-byte.

**Six of the first twenty survived the first run, and the two that mattered were defects in the fix rather than in
the mutations.** That is the most useful thing this phase measured, so it is recorded rather
than smoothed away.

- **U01 survived** — moving the identifier collection behind the `HasReport` check changed
  nothing observable. The reason was that `verifyNoRunResidual` checked target identifiers
  against the **alias map**, which is built independently of collection. So the "collection must
  visit every result" property was **not load-bearing**: the field was collected and never used.
  Fixed by making collection completeness a checked premise — `len(values.targetIDs)` must equal
  `len(out.Targets())` — and by checking identifiers against the collected originals.
- **U02 survived** — deleting the `verifyNoRunResidual` call broke no black-box test, because
  with the message replacement in place nothing leaks anyway. That is the permanent shape of a
  safety net, not a gap in the corpus: while the mechanism above it is correct the net is
  unreachable from outside. Closed two ways — five in-package tests that hand it a residual
  directly, and one structural guard that reads `RedactRun` and requires the call.
- **U05, U06** were weak mutations: a no-op rename, and a message change my own assertion
  accepted. Replaced with the real bypasses — the command skipping `RedactRun`, and the terminal
  renderer being handed the unprojected report. Both are now caught by the pre-existing
  `TestMTS15ShareableNeverExposesWhatLocalAlreadyHid`. The weak assertion behind U06 — a
  `Contains(msg, "withheld")` that the single word satisfies — was replaced with an exact,
  per-class wording check, and **U06b** was added to plant that exact defect.
- **U08, U13** were unplantable: a bad anchor assertion and a heredoc escaping problem.

**One earlier mutation stopped being plantable and was repaired rather than left.** Phase 9.1C's
`CEX3` anchored on the exact text of `RunExitCode`'s configuration-error branch, and Phase 9.2B
added `services.ErrPreflight` to it. The anchor moved, so the mutation could no longer plant —
which reads as `(unplantable)` and is a guard that has silently stopped guarding. Re-expressed
with the same intent, as a `&& false` that keeps the file compiling; **9.1C is back to 45 caught,
0 survivors.**

`phase91a` and `phase91b` carry **20 survivors between them**, all **pre-existing** and all
verified identical at `27d35b1`. They are recorded as release debt in §6c.

One further defect surfaced from `golangci-lint` rather than from mutation: the in-package
structural guard imported `os`, which `internal/security/redaction` may not do — *"redaction must
not read files, the environment, or process state."* The guard moved to `test/security/`, which
already reads source. **The boundary was not weakened to make a test convenient.**

---

## 6. Supply chain and platforms

**Five-platform cross-compilation, `CGO_ENABLED=0`, all succeeded**, binaries removed afterwards:

```
OK   linux/amd64     10504678 bytes      OK   darwin/arm64     9962306 bytes
OK   linux/arm64      9620079 bytes      OK   windows/amd64   10654208 bytes
OK   darwin/amd64    10791776 bytes
```

No CGO anywhere. `go.sum` unchanged. **External module count still 2.**

**Action pinning.** Two of three third-party actions in `ci.yml` are now SHA-pinned, using
digests this repository already carried in its release workflows. `golangci-lint-action` was
**left on its tag**, deliberately: no verified digest exists in this repository and none could be
obtained and checked here. An unverified digest would be worse than the tag — a wrong one fails
every pull request, and a plausible wrong one is the defect a pin exists to prevent. The guard
therefore asserts something true: **every unpinned action carries a written reason beside it.**

**`govulncheck` is not installed** on the machine this phase ran on, and the scope forbids
silently downloading tooling. Recorded in `docs/RELEASE_CHECKLIST.md` as a release-gate line and
in `docs/BACKLOG.md` as UX-S17. `gosec` runs as part of `golangci-lint` and is green.

---

## 6b. UX acceptance accounting

| | |
|---|---|
| Frozen acceptance tests | **24** |
| **PROVEN** | **22** |
| **DEFERRED_BY_CONTRACT** | **2** — UX-09, UX-19 |
| **MISSING** | **0** |

`PROVEN` and `DEFERRED_BY_CONTRACT` are the only terminal statuses; every one of the 24 carries
exactly one, so nothing is unaccounted. The per-row matrix is
`PHASE92B_UX_TRACEABILITY.md`.

**Phase 9.2B's first report said "24 total, 24 proven, 0 missing". That was wrong twice.**
UX-19 was counted as proven while its own row read "BOUNDED, NOT MET", and UX-09 was counted as
proven while its Evidence and Test columns were both empty. Both are the terminal-rendering
requirements, and both are unimplemented for the same reason: **renderer work was explicitly
excluded from Phase 9.2B's scope.**

Neither is `MISSING`. A missing requirement is one nobody accounted for; these were excluded by
contract, are recorded with Requirement, Evidence, Current bound, Reason deferred and Future
candidate phase, and are carried into the backlog as the terminal UX polish group.

**An executable regression bound is not a proof of responsive rendering.** UX-19 has one — the
widest emitted line, measured at **277 columns**, guarded against exceeding 285 — and it proves
only that the current behaviour cannot get worse. UX-09 has no bound at all, because its defects
are layout and content choices rather than a measurable scalar.

## 6c. Pre-existing mutation harness debt

The four suites are distinct and are **not** collapsed into one number:

| Suite | Planted | Caught | Survivors |
|---|---|---|---|
| **Phase 9.2B** | 21 | 21 | **0** |
| **Phase 9.1C** (after repairing `CEX3`) | 45 | 45 | **0** |
| Phase 9.1A | 20 | 12 | **8 — pre-existing** |
| Phase 9.1B | 31 | 19 | **12 — pre-existing** |

Phase 9.2B and Phase 9.1C are clean. **The two historical suites are not, and this document does
not claim they are.**

**Phase 9.1A — 8:** `A02` `A03` `A04` `A05` `A06` `A08` `A09` `A10`.
**Phase 9.1B — 12:** `B05` `B07` `B09` `B10` `B14` `B15` `B16` `B17` `B18` `B26` `B27` `B28`.

Named in full in `docs/BACKLOG.md`.

**Verified byte-identical at the Phase 9.2A baseline (`27d35b1`)**, by running both scripts in a
scratch worktree checked out at that commit and comparing the sorted survivor sets. The
comparison is exact and empty in both directions: **Phase 9.2B introduced none of them.**

### The count was wrong in the first report, and the reason is worth recording

Phase 9.2B's first report named two survivors, `A10` and `B27`. There were twenty. The run had
been summarised with `tail -1`, which prints the **last** survivor line and silently hides every
one above it — so the reading was of one line of a twenty-line answer.

Nothing about the tree changed between the two readings. This was a measurement-reading defect
in the report, of exactly the kind Phase 9.2A was convened to find in the documentation: a
number that looked checked and was not.

### Deliberately not fixed here

A survivor means one of two opposite things: the guard is weak and the defect is real, or the
mutation no longer describes a behaviour the product has. Several of these look like the second
— `A04` plants a plaintext scalar password against a decoder whose *type* now refuses one, and
`A03`, `A05` and `A06` are the same family — but "looks like" is not a finding, and telling them
apart means reading each mutation against the code it targets.

Twenty such judgements are a phase of work, not a footnote in a closure pass, and making them
here would mean making them by whoever happened to notice.

**Must be reconciled before the v0.4.0 Release Candidate Gate can PASS**, each resolved in
writing one of two ways: the guard is strengthened, or the mutation is retired with the reason
it no longer describes a reachable defect.

## 6d. The one thing UX-B04 cannot close from the tree

`SECURITY.md` names GitHub's private vulnerability reporting as the project's **only** channel,
which is what ADR 0076 §2.5 froze and what avoids publishing an email address nobody can rotate.

The closure pass verified the setting rather than assuming it, and the answer was **no**:

```console
$ gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting
{"enabled":false}
```

**This is externally verified repository state, not an inference.** With the setting off, the
advisory form the policy links to does not exist, so a researcher following `SECURITY.md` today
would find a dead link — which is worse than no policy, because it looks like a channel.

The distinction matters and is recorded as such:

| | |
|---|---|
| **Documentation path — configured** | `SECURITY.md` names the mechanism, states scope, asks reporters not to disclose publicly, and invents no email, no SLA and no support lifetime. Asserted by `TestUX2123TheRepositoryHygieneFilesExist` |
| **Enabled setting — externally verified as NOT enabled** | `private-vulnerability-reporting` is `{"enabled": false}` |

**No change to the tree can fix this.** It is a repository setting, it must be turned on by hand,
and doing so was outside this pass's authority. It is recorded as a release-gate line in
`docs/RELEASE_CHECKLIST.md` and must be true before the first release that ships `SECURITY.md`.

UX-B04's deliverable — the policy — is complete. The **channel it names is not yet live**, and
this document does not let "CLOSED" imply otherwise.

## 7. Blocker status

| | |
|---|---|
| **UX-B01** | **CLOSED** |
| **UX-B02** | **CLOSED** |
| **UX-B03** | **CLOSED** |
| **UX-B04** | **CLOSED** — the policy is written and guarded. **The GitHub setting it depends on is verified OFF** and is a release-gate precondition; see §6d |

---

## 8. Invariants

| | Before | After |
|---|---|---|
| `domain.SchemaVersion` | 1 | **1** |
| `domain.RunSchemaVersion` | 1 | **1** |
| Finding codes | 60 | **60** |
| RabbitMQ finding codes | 11 | **11** |
| Failure classes | 42 | **42** |
| `security.Reveal` production sites | 4 | **4** |
| `SecretFor` production sites | 4 | **4** |
| External modules | 2 | **2** |
| `ExecutionErrorClass` members | 2 | **2** |
| Execution states | 4 | **4** |
| Commands | 5 | **5** |
| CLI flags | unchanged | **unchanged** |

No new service. No config schema change. No report schema change. No new credential source.
