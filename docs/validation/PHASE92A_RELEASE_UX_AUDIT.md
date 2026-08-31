# Phase 9.2A — Release Readiness and User-Experience Audit

**Contract/research phase. No production code was changed. No CLI behaviour, report schema or
configuration schema was modified.**

This document is the frozen release/UX contract for Phase 9.2B. It evaluates svcdoctor as an
external Senior SRE would meet it: through the README, `--help`, real invocations, real output
and real errors — not through the source, the ADRs or the backlog.

Everything below was measured. Every command in section 3 was run against this tree at commit
`c43ec19`, and the outputs are quoted rather than described.

---

## 1. Start-state gate

| Gate item | Required | Measured | Verdict |
|---|---|---|---|
| Phase 9.1C committed | yes | `c43ec19 docs(fleet): freeze multi-target configuration and execution` | PASS |
| Working tree clean | yes | `git status --porcelain` empty | PASS |
| `make check` | green | exit 0 — fmt-check, test, vet, `golangci-lint` 0 issues, `CGO_ENABLED=0 go build` | PASS |
| `domain.SchemaVersion` | 1 | `internal/domain/report.go:21` = 1 | PASS |
| `domain.RunSchemaVersion` | 1 | `internal/domain/runreport.go:26` = 1 | PASS |
| Finding codes | 60 | `TestMTG05TheFindingCodeCountIsUnchanged` passes; by namespace `DNS:2 KAFKA:13 POSTGRES:19 RABBITMQ:11 REDIS:9 TCP:1 TLS:5` = 60 | PASS |
| RabbitMQ finding codes | 11 | same test | PASS |
| Failure classes | 42 | `internal/domain/failureclass_test.go` `wantCount = 42` passes | PASS |
| `security.Reveal` production sites | 4 | redis, rabbitmq, postgres, kafka wire packages | PASS |
| `SecretFor` production sites | 4 | rabbitmq, redis, postgres, kafka adapters | PASS |
| External modules | 2 | `kmsg` v1.13.1, `go.yaml.in/yaml/v3` v3.0.5 | PASS |
| Phase 9.1 marked FROZEN | yes | `docs/BACKLOG.md:72` — "Complete and FROZEN" | PASS |
| Traceability | 108/108, 0 missing | `MULTI_TARGET_PHASE91_TRACEABILITY.md` — 108 frozen, 108 proven | PASS |
| Mutation closure | 0 survivors | `MULTI_TARGET_PHASE91C_VALIDATION.md` §16 — 45 planted, 45 caught, 0 survivors | PASS |
| Four services via `run --config` | yes | measured, section 3.6 | PASS |
| Leaf commands available | yes | `diagnose postgres\|kafka\|redis\|rabbitmq` all present | PASS |

**One start-state correction, recorded rather than acted on.** `CLAUDE.md` states the
recommended next version is v0.2.0 and that nothing has been tagged. The repository disagrees
and the repository is authoritative: `v0.1.0`, `v0.2.0`, `v0.3.0`, `v0.3.1`, `v0.3.2` and
`v0.3.3` are tagged, and `docs/releases/v0.3.3.md` records `v0.3.3` as the first release to
complete the whole publication path — signed multi-arch image, SBOM, provenance and a GitHub
Release. This is not a gate failure; it is the fact that makes section 4 necessary, because
**the released product is PostgreSQL + Kafka and the tree is PostgreSQL + Kafka + Redis +
RabbitMQ + `run`**, and the README is written against both at once.

Gate verdict: **PASS. Proceed.**

---

## 2. Persona and method

Primary persona: Senior SRE / Platform Engineer. Understands DNS, TCP, TLS, authentication,
YAML, environment variables and CI. Has not read the ADRs, does not know the package layout,
and should not need either.

Secondary persona: an engineer who receives a svcdoctor report from someone else.

Method was black-box first. The README, `--help` on every surface, and 60+ real invocations
were evaluated before any implementation file was opened. Implementation was consulted only
afterwards, to establish cause and to decide whether a fix is legal under the Phase 9 freeze.

---

## 3. The measured journey

### 3.1 Discover and understand — the README first-five-minutes test

| # | Question | Answered by README? | Note |
|---|---|---|---|
| 1 | What problem does it solve? | **YES** | First paragraph is exact and well-judged |
| 2 | What does it NOT solve? | **YES** | "Not in v0.1", "Claim discipline" |
| 3 | Which services are supported? | **NO — wrongly** | Line 8: *"PostgreSQL BASIC and Kafka BASIC are supported today."* Four are built. See UX-B02 |
| 4 | How do I install it? | **YES** | `go install`, `go build`, GHCR image |
| 5 | How do I diagnose one service? | **PARTIAL** | Quick start is PostgreSQL only; no Redis or RabbitMQ example anywhere |
| 6 | How do I diagnose several? | **YES** | "Running many targets" with a working YAML example |
| 7 | How do credentials work? | **CONTRADICTORY** | "There are exactly two credential sources"; the config `env:`/`file:` reference is documented 200 lines later. See UX-B02 |
| 8 | Is my password safe? | **PARTIAL and self-contradicting** | "There is **no** environment-variable secret source — svcdoctor's production code reads no environment variable at all" is **false** since Phase 9.1A |
| 9 | How do I enable TLS? | **YES** | Best section in the document |
| 10 | How do I produce JSON? | **YES** | `--output json`, with the stdout/stderr contract |
| 11 | How do I create a shareable report? | **YES**, with one overclaim | See UX-B01 |
| 12 | What do exit codes mean? | **YES** | Table, precedence, and the three traps named |
| 13 | How do I use it in CI? | **NO** | No CI section exists at all |
| 14 | What compatibility is tested? | **YES** | `docs/COMPATIBILITY.md` is the strongest document in the repository |

### 3.2 Install

Measured: `go install ./cmd/svcdoctor` and `go build` both work; module path
`github.com/hakanaltindag/svcdoctor` is correct and installable without cloning
(`go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v0.3.3`); `CGO_ENABLED=0` is the
build environment in the `Makefile`; `svcdoctor --version` exists and prints `dev` for a
working-tree build, which is honest; `run.svcdoctorVersion` is already in both report schemas.

Cross-compilation, measured, all `CGO_ENABLED=0`, all succeeded:

```
OK   linux/amd64    10481058 bytes
OK   linux/arm64     9612995 bytes
OK   darwin/amd64   10768144 bytes
OK   darwin/arm64    9942610 bytes
OK   windows/amd64  10630144 bytes
OK   freebsd/amd64  10434716 bytes
```

No CGO anywhere. Static binaries. The gap is not portability — it is that **no binary artifact
is produced for any release**, and the README says so: prebuilt archives exist only for
`v0.1.0` and are not part of the current delivery model.

`svcdoctor version` (subcommand form) is not a command and exits 2 with root help.

### 3.3 CLI information architecture

Full inventory, measured:

```
svcdoctor                       exit 2, root help on stderr
svcdoctor --help                exit 0, root help
svcdoctor --version             exit 0, "dev"
svcdoctor version               exit 2, unknown command
svcdoctor diagnose              exit 2, "diagnose needs a service" + service list
svcdoctor diagnose --help       exit 0, service list
svcdoctor diagnose postgres --help    exit 0
svcdoctor diagnose kafka --help       exit 0
svcdoctor diagnose redis --help       exit 0
svcdoctor diagnose rabbitmq --help    exit 0
svcdoctor run                   exit 2, "--config is required"
svcdoctor run --help            exit 0
svcdoctor nonsense              exit 2, unknown command + root help
svcdoctor diagnose mysql        exit 2, unknown service + service list
```

Discoverability is good: every dead end prints the list of live ones. Naming is consistent and
action-first. Nothing is exposed as a stub.

**Help-surface consistency matrix** (measured, not inferred):

| Element | postgres | kafka | redis | rabbitmq | run |
|---|---|---|---|---|---|
| Opening form | sentence | sentence | sentence | `svcdoctor diagnose rabbitmq - …` | sentence |
| Credential section title | `Credential:` | `Credential:` | `Credential:` | `Authentication:` | prose |
| Principal flag | `--user` | `--user` | `--username` | `--username` | `credentials.username` |
| `--password-file` type word | `path` | `path` | `path` | `string` | n/a |
| Exit-code block | **yes** | **yes** | **NO** | yes, different wording | **NO** |
| "exit 0 is not success" caveat | yes | yes | **NO** | **NO** | **NO** |
| Worked example | **NO** | **NO** | **NO** | **NO** | **NO** |

Three of these are load-bearing rather than cosmetic: the missing exit-code block on
`diagnose redis`, the missing exit-code block on `run` — the one command whose whole purpose is
CI — and the `--user`/`--username` split for a single concept.

### 3.4 Terminal output

Twelve scenarios were run. Representative results:

**T1 — full success over verified TLS** (`diagnose postgres`, exit 0). Reads perfectly: DNS,
per-path stage table, `Findings none`, a four-line `Result` block. Ten-second test passed.

**T2 — DNS failure** (exit 1). Correct, and the finding explicitly refuses to overclaim
("This does not establish that the hostname is unknown"). Ten-second test passed.

**T3 — TCP refusal against an address literal** (exit 1). Correct, and the absence of a DNS row
is exactly ADR 0059. Two cosmetic defects: a doubled blank line where the DNS row would be, and
`first break  L2  tcp` exposes the internal layer vocabulary.

**T4 — TLS chain not trusted** (exit 1). Correct, but the *same* four-paragraph finding is
printed once per resolved address. A hostname with five addresses prints it five times.

**T5 — credential withheld on a plaintext channel**, measured against a real PostgreSQL 18:

```
Result
  status     OK                       no target-side error was proven
  outcome    session NOT established
  execution  complete
```

Exit **0**. This is the contract working exactly as designed, and it is also the single most
dangerous line in the product for a reader who skims. The `outcome` line saves it.

**T10 — mixed four-service fleet run** (exit 1). All four services diagnosed; RabbitMQ reported
`implementation RabbitMQ / version 4.0.9 / platform Erlang/OTP 27.3.4.16 / mechanisms offered
AMQPLAIN ANONYMOUS PLAIN`. Excellent. Three defects visible in one screen — see UX-S05, UX-S06,
UX-S07.

**T11 — local execution failure** (bad `tls.ca_file` path, exit 4) and **T12 — SIGINT
cancellation** (exit 4, `stopped  cancelled; this says nothing about any target`). Cancellation
is exemplary. T11 is UX-B01/UX-B03.

**Width.** The renderer performs no wrapping and consults neither `COLUMNS` nor the TTY. The
longest measured line was **246 columns** (a finding `detail` paragraph). At 80 columns the
terminal hard-wraps it to column 0, destroying the four-space finding indent and the visual
separation between `detail`, the vantage caveat and the `→` recommendation. Content is never
lost; hierarchy is.

**Color.** There is none — no escape sequences anywhere in `internal/render`. Output is
byte-identical redirected and on a TTY, which is why the golden tests are stable.

### 3.5 Configuration UX and the error corpus

Twenty-one configuration errors were run black-box. Every one exited **2**, wrote **nothing to
stdout**, and wrote one actionable line to stderr. A representative selection, verbatim:

```
missing file       svcdoctor: /…/nonexistent.yaml: cannot be read: no such file
unreadable         svcdoctor: /…/noperm.yaml: cannot be read: permission denied
directory          svcdoctor: /…/err: is a directory, not a configuration file
malformed YAML     svcdoctor: malformed.yaml: line 2: did not find expected '-' indicator
unknown field      svcdoctor: unknown.yaml: line 6: field hostname is not a field this schema defines
duplicate id       svcdoctor: dupid.yaml: targets[1] (target "a"): target identifier "a" is already
                   used by targets[0]; identifiers must be unique, and a repeat is refused rather
                   than resolved by position
unknown service    svcdoctor: badsvc.yaml: targets[0] (target "a"): service type "mysql" is not
                   supported; this build supports: kafka, postgres, rabbitmq, redis
bad version        svcdoctor: badver.yaml: configuration version 2 is not supported; this build
                   supports version 1
plaintext password svcdoctor: plaintext.yaml: line 2: must be a mapping naming exactly one source,
                   such as {env: NAME} or {file: PATH}, and a plain value was written instead.
                   A password is never written into the configuration itself
missing env var    svcdoctor: target "a": credential resolution failed: credential env
                   SVCD_AUDIT_NO_SUCH_VAR: the environment variable is not set
missing secret file svcdoctor: target "a": credential resolution failed: credential file
                   /…/does-not-exist.pw: no such file
bad concurrency    svcdoctor: badconc.yaml: run.concurrency: run.concurrency 99 is above the maximum
                   of 16; the ceiling is what bounds total sockets, because one target may itself
                   open one connection per resolved address
zero concurrency   svcdoctor: negconc.yaml: run.concurrency: run.concurrency 0 is not a value; it is
                   refused rather than read as "unlimited" or as "use the default"
bad duration       svcdoctor: badtimeout.yaml: line 3: "banana" is not a duration; write it with a
                   unit, such as "30s" or "2m"
target > run       svcdoctor: targetgtrun.yaml: run.timeout: run.timeout 5s is below the 1m0s timeout
                   of target "a", so that target could never complete
bad tls mode       svcdoctor: badtls.yaml: targets[0] (target "a"): tls.mode "verify-full" must be
                   "require" or "disable"
no targets         svcdoctor: notargets.yaml: targets: no targets are declared
missing id         svcdoctor: noid.yaml: targets[0]: a target identifier is required; it is written
                   rather than derived, because an identifier taken from list position moves when a
                   target is inserted above it
```

Every one answers WHAT, WHERE, WHY and HOW. Several answer a fifth question — *why the design
refuses to guess* — which is unusual and correct. **This is the best part of the product's UX
and it should be the model for everything else.**

Two exceptions, both real:

- `tls.ca_file` naming a path that does not exist is **not** caught here. See UX-B01/UX-B03.
- `host` carrying an IPv6 zone identifier is **not** caught here. See UX-B01/UX-B03.

The leaf commands' own corpus (19 invocations) is equally strong, with one leak: Go's `flag`
package wording escapes for type-parse failures and unknown flags —
`invalid value "xx" for flag -timeout: parse error` and
`flag provided but not defined: -bogus`, both with a **single dash** for flags the user typed
with two. Compare the fleet's `"banana" is not a duration; write it with a unit`.

### 3.6 JSON and machine consumption

Single-target document (`--output json`), top level:
`schemaVersion, run, target, vantage, evidence, findings, summary, security`.
`run.svcdoctorVersion` is present. Exit codes 0/1/4 write exactly one JSON document to stdout
and nothing to stderr; 2 and 3 write nothing to stdout. Measured and confirmed.

Aggregate document (`run --output json`), top level:
`schemaVersion, kind:"run", run, targets[], summary`, with per-target
`targetId, service, executionState, report, incomplete` and, on failure, `executionError{class,
message}`.

Machine-consumer questions, all answerable without parsing human text:

| Question | Field |
|---|---|
| Which targets have a diagnostic problem? | `targets[].report.summary.status` |
| Which targets could not be executed? | `targets[].executionState != "COMPLETED"` |
| Finding codes | `targets[].report.findings[].code` |
| Service kind | `targets[].service`, or `run.service` single-target |
| Tool failure vs service failure | `executionState` + `executionError.class` vs `summary.status` |
| Incomplete run | `summary.incomplete`, `targets[].incomplete` |
| Producer version | `run.svcdoctorVersion` |
| Document kind | `kind:"run"` present on the aggregate, absent on the single-target report |

**One asymmetry, and it matters.** The aggregate carries `incomplete`; the single-target report
does not, by explicit decision recorded in the README. A consumer holding only a
`diagnose … --output json` artifact — the normal CI shape — **cannot distinguish an incomplete
run from a complete one**, and must rely on the process exit code, which artifacts do not
carry. See UX-S01.

### 3.7 Shareable reports

Same run, local and shareable, measured:

```
LOCAL_FULL       target.requested = localhost:55433   vantage.host = Mac.home
                 evidence ids: dns.lookup/localhost, …
SHAREABLE_       target.requested = host-002:55433    vantage.host = host-001
REDACTED         evidence ids: evidence-001 … evidence-012
                 security.redactions = {hostname:2, ipAddress:2, evidenceId:12, prose:0, identity:2}
```

The terminal form announces itself: `Shareable report · identities redacted`. Ports, durations,
timestamps, service names, finding codes and severities are preserved by design. The redaction
counters are an excellent trust signal.

**It is not sound for a run aggregate whose target failed to execute.** See UX-B01.

### 3.8 CI and artifacts

Measured shell behaviour:

| Pattern | Exit code preserved? |
|---|---|
| `svcdoctor run --config c.yaml --output json > report.json` | **yes** (1) |
| `svcdoctor … \| tee report.json` under POSIX `sh` | **NO** (0) |
| `svcdoctor … \|\| true` | **NO** (0) |
| `set +e; svcdoctor … > f; rc=$?; set -e; exit $rc` | **yes** (1) |

stderr is empty for exit 0, 1 and 4, so `2>` capture is safe and never mixes into the artifact.

---

## 4. Findings

Severity uses the strict Phase 9.2A definition. `RELEASE_BLOCKER` means an external user could
be insecure, misread a critical result, automate against undocumented semantics, be unable to
install or run, receive a misleading compatibility claim, be unable to identify their version,
or hit a materially broken normal workflow.

### RELEASE_BLOCKERS

---

#### UX-B01 — a shareable run report can disclose an address or a filesystem path that redaction structurally cannot remove

| | |
|---|---|
| **Surface** | `svcdoctor run --config <f> --shareable`, both `text` and `json` |
| **Contract impact** | None. This *restores* ADR 0074 §4.2 and the ADR 0018 redaction policy; it does not reopen them |

**Evidence.** Measured, verbatim, from `--shareable --output json`:

```json
{ "targetId": "target-001", "service": "postgres",
  "executionState": "EXECUTION_FAILED",
  "executionError": { "class": "INTERNAL",
    "message": "invalid run input: unsupported host: fe80::1%en0 carries an IPv6 zone identifier, …" } }
```

and, from a config naming a CA file that does not exist:

```json
  "executionError": { "class": "INTERNAL",
    "message": "loading the trust source: stat /tmp/svcdaudit/err/no-such-ca.pem: no such file or directory" }
```

The target ID **was** pseudonymized to `target-001`. The host and the filesystem path were not.

**Cause.** `internal/security/redaction/run.go` passes `executionError.message` through
`t.text()`, but `collectRun` builds the pseudonym table only from targets that **have a
report** (`if !result.HasReport() { continue }`). A target that failed to execute contributes
none of its own identifiers, so its own host is not in the table and is not replaced. A
filesystem path is not a category the table covers at all. And `RedactRun` never calls
`verifyNoResidual` — that safety net runs inside `redactWith`, per embedded report only.

**User impact.** The README states: *"Redaction **fails closed**. If the residual identity
check cannot confirm that a covered value was replaced, svcdoctor emits no report at all and
exits 3 rather than writing a partially redacted artifact to stdout."* For this path that is
**not true**. An operator produces a shareable aggregate believing addresses are removed, and
sends an internal address — or the on-disk location of the organisation's private CA — to a
vendor or a public issue tracker. This is the definition of "use the tool insecurely because of
UX/docs".

**Proposed correction (9.2B).**
1. Extend `collectRun` to gather identifiers from a target's **declared configuration** (its
   host, and its target ID) regardless of whether it produced a report, so a failed target's
   own host enters the table.
2. Add a run-level `verifyNoResidual` over the finished `RunReport`, so the aggregate fails
   closed exactly as a single report does.
3. Never place a filesystem path in `executionError.message` — see UX-B03, which removes the
   two reachable producers at source.

**9.2B acceptance test.** `UX-12`: for every reachable `EXECUTION_FAILED` cause, the shareable
aggregate contains no byte of the target's declared host, no byte of any path named in the
configuration, and a planted residual makes the redaction fail closed rather than emit.

---

#### UX-B02 — the README's headline capability statement is false for the code it ships with, and it contradicts itself on credentials and on publication

| | |
|---|---|
| **Surface** | `README.md` |
| **Contract impact** | None. Documentation only |

**Evidence.** Four measured contradictions in one document:

| Line | Says | Truth |
|---|---|---|
| 8 | "**PostgreSQL BASIC and Kafka BASIC are supported today.**" | Four services are built and exposed |
| 13–19 | Journey diagram lists `postgres` and `kafka` only | Redis and RabbitMQ have journeys too |
| 337 | "There are exactly two credential sources" | Three: `--password-file`, `--password-stdin`, and the config `password: {env\|file}` |
| 728 | "**There is no environment-variable secret source** — svcdoctor's production code reads no environment variable at all, so `SVCDOCTOR_PASSWORD` and friends are ignored because nothing can read them" | `internal/fleet/secret` reads environment variables. The stated *reason* is now false |
| 784 | "Two leaf commands, `diagnose postgres` and `diagnose kafka`" | Five commands |
| 776 | "**That workflow has never run**, so nothing exists at GHCR yet" | Contradicted at line 660 ("Published container images are on GHCR"), line 672 (`docker run … :v0.3.3`) and by `docs/releases/v0.3.3.md` |

**Cause.** The README was partially updated across Phases 7, 8 and 9 — the flag inventory,
`Running many targets` and `Compatibility` are current — while the opening claim, the journey
diagram, `Credentials`, `Trust and secrets in the image` and `Current scope` were not.
`internal/cli/docsclaims_test.go` guards against **over**claiming and has no rule that can fire
on a stale **under**claim or on an internal contradiction, which is why every one of these
survived a full `make check`.

**User impact.** The second sentence a new user reads is wrong; they conclude Redis and
RabbitMQ are unsupported and go elsewhere. Worse, a user who reads line 728 concludes that
environment-variable credentials are structurally impossible in svcdoctor and treats it as a
security property — it is not one, and has not been since Phase 9.1A.

**Proposed correction (9.2B).** Rewrite the six stale passages against the current tree; scope
the "no environment-variable source" statement to what remains true (**the four leaf commands
read no environment variable; the fleet resolver reads one, by name, from a reference the
configuration declares**); resolve the GHCR contradiction to the measured fact.

**9.2B acceptance test.** `UX-15` extended: a guard asserting that every service registered in
the CLI's service list appears in the README's supported-services statement, and that every
credential source the product implements appears in the README's credential section. This is
the missing half of `docsclaims_test.go` — it currently forbids claiming what does not exist,
and must also forbid omitting what does.

---

#### UX-B03 — a configuration error reaches execution, is classed `INTERNAL`, and exits 4 instead of 2

| | |
|---|---|
| **Surface** | `svcdoctor run --config` |
| **Contract impact** | None. `internal/domain/executionstate.go` already documents the invariant this violates; the fix restores it |

**Evidence.** The same operator mistake, on the two entry points:

```
leaf   svcdoctor diagnose postgres --host 'fe80::1%en0' --user app --tls disable
       exit=2  svcdoctor: invalid invocation: --host fe80::1%en0 carries an IPv6 zone identifier…

fleet  host: fe80::1%en0  in a config
       exit=4  executionState EXECUTION_FAILED  class INTERNAL
```

```
leaf   --tls-ca-file /nope.pem
       exit=2  svcdoctor: invalid invocation: --tls-ca-file /nope.pem cannot be read: no such file

fleet  tls: { mode: require, ca_file: /nope.pem }
       exit=4  executionState EXECUTION_FAILED  class INTERNAL
       message "loading the trust source: stat /…/no-such-ca.pem: no such file or directory"
```

**Cause.** `internal/domain/executionstate.go:95` states the invariant in its own words: *"Two
members, because configuration errors never reach execution at all — ADR 0074 §9 requires a
whole configuration to validate before any target is dialled, so the only failures reachable
here are svcdoctor-local ones during a run."* Two configuration errors reach execution anyway.
`internal/fleet/services/postgres/postgres.go:123` loads the trust source inside `Run`, and
host parsing happens inside the composition root rather than in config validation. Both land
at `internal/fleet/run/execute.go:204`, which uses `ExecutionErrorInternal` and raw
`err.Error()` — unlike line 194's credential path, which uses `safeMessage`.

**User impact.** Three separate ways to be wrong. A YAML typo is reported as *"one of
svcdoctor's own invariants failed"*, so an operator files a bug against svcdoctor. The exit
code is **4** — "incomplete run, retry may help" — so a CI policy that retries on 4 loops
forever on a typo that will never succeed. And the README documents the leaf behaviour ("An
unusable CA file … is an invocation error (exit 2)") as if it were universal.

**Proposed correction (9.2B).** Validate the trust source and parse the host during
configuration validation, alongside every other field, so both exit **2** with the file and
line named — the shape section 3.5 already achieves for eighteen other errors. Then
`ExecutionErrorClass`'s two members are true again, and UX-B01's two reachable producers
disappear.

**9.2B acceptance test.** `UX-08` extended: for every configuration value the leaf CLI
validates at invocation, the equivalent configuration field is rejected at exit 2 by
`run --config` before any socket is opened; and no `EXECUTION_FAILED` result is reachable from
a value the configuration declares.

---

#### UX-B04 — there is no way to report a vulnerability

| | |
|---|---|
| **Surface** | Repository root, `.github/`, `docs/` |
| **Contract impact** | None |

**Evidence.** Measured: no `SECURITY.md` at the root or under `.github/`. `docs/SECURITY.md`
exists but is the **architecture** document — its headings are `Mandatory requirements`,
`Credential binding and topology discovery`, `TLS verification`, `Protocol wire boundaries`,
`Discovered endpoints`, `Report output mode`, `Redaction boundary`, `Testing`. A
case-insensitive search across `README.md`, `docs/` and `.github/` for `security@`, "report a
vulnerability", "responsible disclosure", "private vulnerability" and "security advisory"
returns **nothing**.

**User impact.** svcdoctor transmits credentials, holds a redaction guarantee, and publishes a
signed container image. A researcher who finds a leak — UX-B01 is exactly such a finding — has
no private channel and either files it publicly or says nothing. For a security-adjacent tool
this is the one piece of repository hygiene that cannot ship missing.

**Proposed correction (9.2B).** A root `SECURITY.md` with a private reporting channel (GitHub
private vulnerability reporting is sufficient and requires no infrastructure), the supported
version window, and an explicit statement that credential leakage and redaction failures are
in scope. `docs/SECURITY.md` stays where it is and is renamed in prose to what it is.

**9.2B acceptance test.** `UX-21`: a root `SECURITY.md` exists, names a private reporting
channel, and states a supported-version policy.

---

### SHOULD_FIX

| ID | Surface | Finding | Evidence | User impact | Proposed correction | 9.2B test |
|---|---|---|---|---|---|---|
| **UX-S01** | single-target JSON | The report carries no completeness field; only the exit code distinguishes 4 from 0/1 | §3.6 | A stored artifact cannot be judged complete; CI that keeps only the JSON silently treats a timed-out run as a clean one | **Do not change `SchemaVersion`.** Document that the exit code is the authority for a single-target artifact, and that a consumer needing completeness in-band should use `run --config` with one target, whose aggregate carries `incomplete`. Record the asymmetry as a known limit | UX-11 |
| **UX-S02** | `run --help` | No exit-code block on the one command built for CI | §3.3 | The CI user must leave `--help` for the README | Add the same exit-code block the leaf commands carry, plus the run-specific note that 4 covers not-started, cancelled, execution-failed and incomplete | UX-03 |
| **UX-S03** | `diagnose redis --help` | The only leaf with no exit-code block and no "exit 0 is not success" caveat | §3.3 | Inconsistent contract discoverability across siblings | Add both | UX-02 |
| **UX-S04** | all help + README | `--user` (postgres, kafka) vs `--username` (redis, rabbitmq) for one concept; config uses `credentials.username` uniformly | §3.3 | Every invocation of the second service in a session is a guess | **Do not rename a released flag.** Document the split explicitly in one table, in `docs/CONFIGURATION.md` and in `README.md`. Revisit an alias only in a phase that may change the CLI | UX-02 |
| **UX-S05** | terminal, run summary | The `Run` block's labels are not column-aligned, unlike every `Result` block; and it says `PROBLEMS_FOUND` where `Result` says `PROBLEMS FOUND` | §3.4 T10 | The most-read block in a fleet run is the least polished, and one run prints two spellings of one state | Align the `Run` block; use one spelling | UX-09 |
| **UX-S06** | terminal, run | The run summary is only at the **bottom**, after every target's full report | §3.4 T10 | "Which target failed?" needs scrolling past thousands of lines for a 20-target run | Emit a one-line-per-target index **before** the detail: `id · service · state · status` | UX-09 |
| **UX-S07** | RabbitMQ findings | A finding `detail` contains literal Markdown — `**Zero credential bytes were sent.**` — rendered verbatim to the terminal | §3.4 T10 | Visible defect in the product's most safety-relevant sentence | Remove the emphasis markers from the finding text; the renderer is right not to interpret them | UX-09 |
| **UX-S08** | RabbitMQ findings | Recommendations name leaf CLI flags — "Use `--tls require` … or supply `--tls-ca-file`" — and are printed unchanged inside a `run --config` report, where neither flag exists | §3.4 T10 | The recommendation instructs an action the running command rejects | Make the recommendation name the capability, not the flag ("establish a verified TLS channel, supplying a trust source if the chain is private"), as the PostgreSQL and Redis equivalents already do | UX-09 |
| **UX-S09** | terminal, all | No wrapping and no width awareness; longest measured line **246 columns** | §3.4 | At 80 columns the finding hierarchy collapses | Wrap `detail`, the vantage caveat and `→` recommendation text to `min(COLUMNS, 100)` with the indent preserved; leave the stage tables alone. Must stay deterministic when not a TTY — fix the width to 100 when `COLUMNS` is unset | UX-19, UX-20 |
| **UX-S10** | terminal, findings | An identical multi-paragraph finding is printed once per resolved address | §3.4 T4 | Two addresses double the output; five quintuple it | Print the finding once and list the subjects it applies to | UX-09 |
| **UX-S11** | terminal, findings | Recommendations say "read the per-address outcomes recorded on the referenced evidence" and "compare the certificate names recorded on the referenced evidence", but the text renderer prints only `evidence: 1` and never the attributes | §3.4 T3, T4 | The user is told to read something the output does not contain, and is not told `--output json` would contain it | Either surface the referenced attributes on the finding, or have the text renderer say where they are. **No new diagnosis** — the renderer must invent nothing | UX-09 |
| **UX-S12** | leaf CLI errors | Go `flag` package wording escapes: `invalid value "xx" for flag -timeout: parse error`, `flag provided but not defined: -bogus` — single-dash, for flags typed with two | §3.5 | Below the standard every other error in the product meets | Map both to the fleet's phrasing (`"xx" is not a duration; write it with a unit, such as "30s"`) and echo the flag as the user wrote it | UX-17 |
| **UX-S13** | fleet errors | `executionError.message` carries raw wrapped Go errors including `stat` and a filesystem path, while the credential path is sanitized by `safeMessage` | §3.5, `execute.go:194` vs `:204` | Inconsistent sanitization on the one field that reaches a shareable report | Route both through `safeMessage`-equivalent handling | UX-17 |
| **UX-S14** | `docs/COMPATIBILITY.md` §2 | The table headed "**This is the whole list**" omits RabbitMQ authentication, and "Credential input" omits the fleet `env:`/`file:` references | §3.1, measured | A completeness claim that is not complete | Add the RabbitMQ SASL `PLAIN` row and the two configuration credential sources | UX-15 |
| **UX-S15** | `docs/RELEASE_CHECKLIST.md` | "Security invariants unchanged: SchemaVersion 1, `Reveal` 2, `SecretFor` 2" — both counts are 4; `RunSchemaVersion`, 60 finding codes and 42 failure classes are absent; the Redis, Valkey, RabbitMQ and LavinMQ integration suites are absent from the sequential list | measured | The release gate under-checks the current product | Update the counts and the suite list; add `govulncheck`, docs-example validation and the UX acceptance suite | UX-13 |
| **UX-S16** | `.github/workflows/ci.yml` | The only workflow whose actions are pinned by **tag** (`actions/checkout@v7`, `actions/setup-go@v7`, `golangci/golangci-lint-action@v9`); every other workflow pins by SHA | measured | An inconsistent supply-chain posture in the repository that publishes a signed, attested image | Pin by SHA with a version comment, as the other four already do | UX-22 |
| **UX-S17** | CI | No `govulncheck`. Trivy scans the published *image*; nothing scans the module graph on a pull request | measured | A dependency advisory is not surfaced until release | Add a `govulncheck ./...` step to `ci.yml`. Adds no module dependency — it is a tool, not an import | UX-22 |
| **UX-S18** | repository root | No `CONTRIBUTING.md` | measured | An external contributor cannot learn the ADR-first workflow, the language policy, or that `make check` mirrors CI | Add a short one. Not `CODE_OF_CONDUCT.md`, not issue templates — those are NICE_TO_HAVE | UX-23 |
| **UX-S19** | release artifacts | No prebuilt binaries since `v0.1.0`; the only artifact is a `linux/amd64+arm64` container image | §3.2 | A macOS or Windows engineer, and anyone without Docker or a Go toolchain, cannot install | Publish `tar.gz`/`zip` archives with `SHA256SUMS` for the five platforms in §5.11 | UX-16 |
| **UX-S20** | release artifacts | A `CGO_ENABLED=0` macOS binary uses Go's pure-Go resolver, which does not consult `/etc/resolver/*` (split-horizon DNS, ordinary on corporate VPNs) or mDNS. `internal/probe/dns/resolver.go:53` uses `net.DefaultResolver` | measured | A **DNS diagnostic tool** could report `DNS_NAME_NOT_RESOLVED` for a name the operator's own machine resolves — the one failure mode that most damages trust in the product | Do not add CGO. **Document it** as a platform note on the macOS artifacts, name `GODEBUG=netdns=cgo` as the workaround, and state that the container image is unaffected | UX-24 |
| **UX-S21** | docs | No CI section anywhere, and no exit-code policy guidance | §3.1 Q13 | Every user invents their own policy, and `\| tee` or `\|\| true` silently discards the result | `docs/CI.md`, per §5.7 and §5.8 | UX-14 |
| **UX-S22** | examples | `examples/` contains Kubernetes manifests only. No `examples/services.yaml`; the README's YAML block is the only configuration example and no test parses it | §3.5, measured | The config format is learned by reading prose | Ship the canonical example of §5.5 and validate it, per §5.13 | UX-04, UX-05, UX-18 |

### NICE_TO_HAVE

| ID | Finding |
|---|---|
| UX-N01 | `svcdoctor version` is not a command; only `--version` works. Users type both |
| UX-N02 | `--version` prints only the version. Adding `commit`, OS/arch and Go version would help a bug report |
| UX-N03 | `svcdoctor · run · 1 targets` — pluralization |
| UX-N04 | A doubled blank line where the DNS row would be for an address-literal target |
| UX-N05 | `first break  L2  tcp` exposes the internal layer vocabulary. `tcp` alone is enough for the reader who needs it |
| UX-N06 | RabbitMQ renders a `DNS  not attempted` placeholder row for a literal target; the other three services omit it entirely, per ADR 0059 |
| UX-N07 | `execution  incomplete  1 never started, 1 cancelled, 1 cut short` reads as three targets when there are two |
| UX-N08 | The four leaf helps use three different opening forms and two credential section titles |
| UX-N09 | No `CODE_OF_CONDUCT.md`, no issue/PR templates, no `dependabot.yml` |
| UX-N10 | No shell completion |
| UX-N11 | The malformed-YAML error still carries `go-yaml`'s own phrasing (`did not find expected '-' indicator`), though it is prefixed with file and line |

### OUT_OF_SCOPE

Terminal color; a TUI; Markdown/HTML renderers; a `--ci` mode; a `--check`/dry-run flag for
`run`; renaming any released flag; Homebrew; apt/RPM; MySQL, Elasticsearch or any new service;
any change to `SchemaVersion` or `RunSchemaVersion`; any new finding code, failure class or
credential source.

**Count: 4 RELEASE_BLOCKER, 22 SHOULD_FIX, 11 NICE_TO_HAVE.**

---

## 5. Required decisions

None is deferred.

### 5.1 Canonical install method

**The container image is canonical for running it; `go install` is canonical for building it;
signed binary archives become canonical for humans at the next release.**

```sh
docker run --rm ghcr.io/hakanaltindag/svcdoctor:vX.Y.Z diagnose postgres --host db --user app
go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@vX.Y.Z
```

Rejected: making `go install` the only method — it requires a Go toolchain and gives no
signature. Rejected: Homebrew — a tap is a second release surface with its own trust story, for
a product with no user base yet.

### 5.2 Canonical single-target entry point

`svcdoctor diagnose <service> [flags]`. Unchanged, four services. `inspect` stays reserved.

### 5.3 Canonical multi-target entry point

`svcdoctor run --config <file>`. Unchanged. Run-global flags only.

### 5.4 CLI mental model — one sentence, to appear in the README and in root help

> **`diagnose` is one endpoint you name on the command line. `run` is many endpoints a file
> names for you. They perform exactly the same measurement — `run` schedules the diagnoses that
> `diagnose` performs, one per target — and the only reason both exist is that a password
> belongs to one endpoint, so N endpoints need N credential references and a file is where
> those live.**

This answers the "why do both exist" question directly, and it is true: `internal/fleet/run`
imports no adapter and performs no diagnosis.

### 5.5 Canonical example-config strategy

**One canonical file plus two focused ones**, all under `examples/`, all valid against the real
parser:

- `examples/services.yaml` — **canonical**. Four targets, one per service, TLS on, credentials
  by reference, commented where a comment earns its place. This is what the README links to and
  what `docs/QUICKSTART.md` uses.
- `examples/minimal.yaml` — the smallest thing that runs. Version, one target, three fields.
- `examples/production.yaml` — verified TLS with a private CA, `env:` for CI and `file:` for
  Kubernetes-mounted secrets, explicit budgets and concurrency.

Requirements, all met by construction: no plaintext credential, no invented syntax, no secret
value, parses under the real decoder, representative rather than exhaustive.

Rejected: one exhaustive file — a reader cannot tell required from optional. Rejected: one file
per service — four near-identical files teach nothing about the envelope.

### 5.6 Documentation architecture

Six documents, no more:

| File | Owns | Authoritative for |
|---|---|---|
| `README.md` | what it is, what it is not, install, one example of each shape, links | positioning |
| `docs/QUICKSTART.md` | the five-minute first success (§5.14) | onboarding |
| `docs/CONFIGURATION.md` | the full `run` schema, every field, every credential reference | the config schema |
| `docs/OUTPUT.md` | terminal anatomy, JSON contract, shareable semantics, `jq` recipes | the output contract |
| `docs/CI.md` | exit codes, the three policies, four platform examples, artifacts | CI |
| `docs/COMPATIBILITY.md` | unchanged; already authoritative | what was tested |

`SECURITY.md` at the root is a reporting policy (UX-B04), not a seventh user document.
`docs/REPORT_SCHEMA.md`, `docs/SECURITY.md`, `docs/ARCHITECTURE.md`, `docs/decisions/` and
`docs/validation/` remain **engineering evidence** and are linked, never required reading.

Rejected: putting configuration and CI into the README — it is already 956 lines and its stale
passages are in the parts a reader reaches last.

### 5.7 Exit-code documentation policy

The codes are frozen and unchanged. They are documented in exactly three places, with one
authority:

- **`docs/CI.md` is authoritative** and carries the full table, the precedence `3 > 2 > 4 > 1 > 0`,
  and the three traps.
- Every leaf help and `run --help` carries the same five-line block (UX-S02, UX-S03).
- The README carries the table and links to `docs/CI.md`.

The traps are stated wherever the table appears:

1. **Exit 0 is not "the service works."** It means no ERROR or CRITICAL target-side problem was
   *proven*. A run that withheld its credential over a plaintext channel exits 0 with no
   session. Read `outcome`.
2. **Exit 1 is not a svcdoctor failure.** svcdoctor worked and found a target-side problem.
3. **Exit 4 outranks exit 1**, and means svcdoctor's own execution did not finish — cancelled,
   never started, could not be executed, or out of budget. It qualifies every conclusion in the
   report. It is not evidence about the target.

### 5.8 CI contract and exit policy

Three documented policies built from the existing codes. No new flag, no `--ci` mode.

| Policy | Fails the pipeline on | For |
|---|---|---|
| **STRICT** | anything but 0 | a release gate, a promotion gate |
| **DIAGNOSTIC** | 1, 2, 3 — **not 4** | a scheduled connectivity check where a local timeout is noise, provided 4 is surfaced some other way |
| **OBSERVATIONAL** | 2 and 3 only | a report you always want to keep; diagnostic results are read from the artifact |

2 and 3 fail under **every** policy: 2 means the invocation was wrong, 3 means svcdoctor
failed. Neither is ever a statement about a target and neither is ever tolerable.

The artifact rule, in every example:

```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e
# upload report.json here, before deciding
exit $rc
```

**`| tee` and `|| true` are named as defects** in `docs/CI.md`, with the measured evidence from
§3.8. Examples are given for generic shell, GitHub Actions, GitLab CI and Azure DevOps, all
using environment-secret injection or a mounted file, and none using a platform-specific
integration.

### 5.9 CI artifact recommendation

`--output json` redirected to a file, uploaded unconditionally before the exit code is
re-raised. `--shareable --output json` as a **second** artifact when the report leaves the
organisation — and only once UX-B01 is fixed. Terminal output is for humans and is never the
artifact.

### 5.10 Shareable-report wording — exact, and the wording that is forbidden

**Permitted:**

> `--shareable` produces the `SHAREABLE_REDACTED` projection of the same report. Hostnames,
> IP addresses, logical identities (role, database, virtual host, username) and evidence
> identifiers are replaced with stable pseudonyms, applied consistently so that the
> relationships between target, evidence and findings stay readable. The number of
> substitutions of each kind is reported in `security.redactions`. **Ports, durations,
> timestamps, service names, finding codes, severities and every diagnostic conclusion are
> preserved unchanged.** The exit code is identical: redaction changes what a shared copy
> reveals, never what was concluded.
>
> Review a shared report against your own disclosure requirements before sending it.

**Forbidden, and each for a measured reason:**

- "anonymized" — it is pseudonymization, and a consistent pseudonym is a correlation handle.
- "compliant" with any named regime.
- "safe to publish" without qualification — a preserved port, duration and timestamp set is
  information.
- any unqualified "fails closed" claim while UX-B01 stands. Once UX-B01 is fixed the claim is
  restored, scoped: *the residual check covers the identity categories the redaction table
  holds, and a value it does not classify is not covered.*

### 5.11 Release artifacts and platforms

**Minimum for the next release:**

| Artifact | Class |
|---|---|
| `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64` archives | RELEASE_BLOCKER for a binary release; all five build clean today (§3.2) |
| `SHA256SUMS` alongside them | RELEASE_BLOCKER |
| Container image, multi-arch, signed | **already exists** |
| CycloneDX SBOM, provenance, keyless cosign signature | **already exists** for the image |
| GitHub Release with notes | **already exists** |
| SBOM and signature over the **binary archives** | SHOULD_FIX — the image already has all three; extending the same three to archives is mechanical |
| Homebrew tap, apt/RPM, Windows package | OUT_OF_SCOPE |

`freebsd/amd64` builds clean and is **not** published: nothing has been run against it.

### 5.12 Version strategy

`svcdoctor --version` is canonical and already correct — a release tag for a released build,
`dev` for anything that corresponds to no released commit, with an `-ldflags` override for
release builders. `resolveVersion` correctly refuses to report a pseudo-version or a `+dirty`
version as a release; this was measured and is right.

`svcdoctor version` as a subcommand alias: **NICE_TO_HAVE**, not required.

Enriching `--version` with commit, OS/arch and Go version: **NICE_TO_HAVE**.

### 5.13 Example-validation mechanism

**The minimum mechanism for 9.2B, and no more:**

1. **Configuration examples** — one test extracts every ` ```yaml ` fence from `README.md`,
   `docs/*.md` and every file in `examples/`, and decodes each through the real
   `internal/fleet/config` loader. A fence that must fail (the plaintext-password
   counter-example) is marked and asserted to fail with the expected error. This needs **no new
   CLI surface**: the test is in-tree and the loader is importable.
2. **Help snapshots** — golden files for all seven help surfaces, so a change to help text is a
   reviewed diff rather than a silent drift. `internal/cli/testdata/` already holds golden
   terminal output; this extends the pattern.
3. **Shell examples** — **not** executed. A `docker run` or a `gh` invocation in a test is a
   network dependency in `make check`. Instead, one guard asserts that no documented shell
   example contains `| tee`, `|| true`, or a `--password` flag that does not exist.

Rejected: a full literate-documentation harness. Rejected: executing README shell blocks — it
would make `make check` non-hermetic, which is the property that makes it useful.

### 5.14 Quickstart design — the five-minute journey

`docs/QUICKSTART.md`, in this order, no Docker required except in the optional last step:

1. **Install** — one `go install` line and one `docker run` line.
2. **Diagnose one endpoint** — `svcdoctor diagnose postgres --host … --user …`, credential-free.
   This succeeds against any reachable PostgreSQL and teaches that a credential is optional.
3. **Read the result** — the `Result` block explained in five lines, including why exit 0 does
   not mean "the service works."
4. **Add a credential safely** — `--password-file`, and why there is no `--password`.
5. **Diagnose several** — copy `examples/minimal.yaml`, run `svcdoctor run --config`.
6. **Reference a secret** — switch to `password: {env: DB_PASSWORD}` and export it.
7. **JSON** — `--output json > report.json` plus one `jq` line that lists failing targets.
8. **Share it** — `--shareable`, with the §5.10 wording.

### 5.15 Demo environment

**NICE_TO_HAVE, and declined for 9.2B.** The four integration fixtures under
`test/integration/` are a working demo environment for anyone who wants one, and they are
already documented per service. A separate `examples/demo/docker-compose.yml` would be a fifth
copy of provisioning that Phase 9.1C already found silently broken once. `docs/QUICKSTART.md`
points at the integration fixtures for readers who need a target to aim at, and labels their
credentials as test-only.

### 5.16 Terminal color

**Not needed. Do not add it in 9.2B.**

Measured: there is no color, no TTY detection and no `COLUMNS` handling anywhere in
`internal/render`. Output is byte-identical on a TTY and redirected, which is exactly why the
golden tests are stable and why CI logs are clean. The glyph vocabulary (`✓ ✗ ? · ⚠ ── →`)
already carries state without color, and state is duplicated in words (`PASS`, `FAIL`,
`UNKNOWN`, `SKIPPED`), so nothing depends on a visual channel.

Adding color means TTY detection, `NO_COLOR`, `CLICOLOR_FORCE`, a dumb-terminal path and a
determinism guard on every golden test — real cost, for a product whose readability problem is
**width** (UX-S09), not hue. Wrapping is where the effort belongs.

### 5.17 Producer version in `RunReport`

**No change. It is already there.**

Measured: `run.svcdoctorVersion` is present in both the single-target report and the aggregate,
and `internal/fleet/services/services.go` documents it as "svcdoctor's own version, recorded in
each target's run metadata." `resolvedVersion()` is the single authority feeding both
`--version` and the report, deliberately, so a shared report can never name a different build
than the operator saw.

No schema change is required and none is authorized. `SchemaVersion` stays 1.

---

## 6. Product positioning — does the current wording overclaim?

Audited against the §5 non-list. **It does not overclaim.** The README is explicit that
svcdoctor is client-vantage, on-demand, and requires no agent; that it is not monitoring, not
APM, not topology discovery (Kafka's advertised sweep is credential-free transport probing and
is described as such), not a daemon, not remediation and not a secret manager. `Claim
discipline` is the strongest section in the document.

`internal/cli/docsclaims_test.go` enforces the compatibility half mechanically:
`TestTheREADMENeverClaimsManagedCompatibility`, `TestOnlyRealTestedPlatformsClaimLevelTwoOrThree`,
`TestNoDocumentClaimsAnUnimplementedMechanism`, `TestNoDocumentClaimsHealthTheProductCannotObserve`,
`TestTheREADMEsRedpandaClaimStaysNarrow` — each with a paired can-fail proof.

The failure mode here is the opposite one, and it is unguarded: **under**claiming and internal
contradiction (UX-B02).

---

## 7. Failure terminology

The user-facing vocabulary is already well chosen. `Findings`, `Result`, `status`, `outcome`,
`execution`, `evidence`, and the `→` recommendation marker are all plain. `CONFIRMED` /
`HYPOTHESIS` and `HIGH` / `MEDIUM` / `LOW` are visible in JSON, correctly separated, and
explained in `docs/FINDINGS.md`.

Three terms are architecturally correct and poor UX, all minor:

| Term | Where | Why it reads badly | Recommendation |
|---|---|---|---|
| `first break  L2  tcp` | terminal `Result` | `L2` is the internal layer order; the reader has never seen it | Keep the field, drop the `L`-code from the terminal. `L2` stays in JSON |
| `evidence: 1` | terminal findings | A bare ordinal with nothing to look it up in | UX-S11 |
| `EXEC_SKIPPED_BY_POLICY` | terminal stage rows | A failure-class enum in a human view | Acceptable — it is precise, greppable, and the finding beneath it explains it in prose. Leave it |

`execution failure` vs `diagnostic failure` is the distinction that matters most, and the
product already separates them structurally: `executionState` and `executionError` on one side,
`summary.status` and `findings` on the other. `docs/OUTPUT.md` must state it in one paragraph.

---

## 8. Internal error leakage

| Leak | Where | Class |
|---|---|---|
| `stat /path: no such file or directory` in `executionError.message` | fleet, bad `ca_file` | **Security-relevant** — reaches a shareable report (UX-B01/UX-S13) |
| `fe80::1%en0` in `executionError.message` | fleet, zoned host | **Security-relevant** — an address in a shareable report (UX-B01) |
| `invalid value "xx" for flag -timeout: parse error` | leaf, type parse | Cosmetic (UX-S12) |
| `flag provided but not defined: -bogus` | leaf, unknown flag | Cosmetic (UX-S12) |
| `did not find expected '-' indicator` | fleet, malformed YAML | Cosmetic (UX-N11) — file and line are prefixed, so it is usable |
| `postgres runner received %T, …` | fleet, unreachable | Cosmetic — a Go type name in a user-facing string; structurally unreachable but present |

No stack traces. No `%!` verbs. No package names. No `context` implementation detail. No panic
reached any surface across 80+ invocations.

---

## 9. Help / README / docs consistency matrix

| Concept | README | root help | leaf help | `run --help` | COMPATIBILITY | **Authority** |
|---|---|---|---|---|---|---|
| Supported services | **STALE** (2 of 4) | correct | correct | n/a | correct | **the CLI service list** |
| Credential sources | **CONTRADICTORY** | — | correct per service | correct | **incomplete** | **`docs/CONFIGURATION.md`** (new) |
| TLS options | correct | — | correct | via config | correct | **leaf `--help`** |
| Output formats | correct | — | correct | correct | — | **`docs/OUTPUT.md`** (new) |
| Shareable | correct + one overclaim | — | correct | correct | — | **`docs/OUTPUT.md`** (new) |
| Timeouts | correct | — | correct | correct | — | **`docs/CONFIGURATION.md`** (new) |
| Concurrency | correct | — | n/a | correct | — | **`docs/CONFIGURATION.md`** (new) |
| Exit codes | correct | **absent** | 2 of 4 complete | **absent** | — | **`docs/CI.md`** (new) |
| Compatibility | correct | — | — | — | correct | **`docs/COMPATIBILITY.md`** |
| Publication status | **CONTRADICTORY** | — | — | — | — | **`docs/releases/`** |

---

## 10. Phase 9.2B implementation scope — frozen

**In scope, and nothing else.**

**A. Correctness (the four blockers)**
1. UX-B01 — run-aggregate redaction: collect declared identifiers from targets without reports,
   add a run-level residual check, remove filesystem paths from `executionError.message`.
2. UX-B03 — validate `tls.ca_file` and `host` during configuration validation; both exit 2.
3. UX-B02 — correct the six stale README passages, plus a guard that fires on an omitted
   service or credential source.
4. UX-B04 — root `SECURITY.md` with a private reporting channel.

**B. Help surfaces** — UX-S02, UX-S03, UX-S04, UX-S12; golden snapshots for all seven surfaces.

**C. Terminal renderer** — UX-S05, UX-S06, UX-S07, UX-S08, UX-S09, UX-S10, UX-S11 and the
NICE_TO_HAVE cosmetics UX-N03 through UX-N07 where they are one-line changes. **The renderer
creates no finding, computes no severity and interprets no protocol. Every change is layout,
wrapping, ordering, deduplication or wording of text a rule already produced.**

**D. Documentation** — `docs/QUICKSTART.md`, `docs/CONFIGURATION.md`, `docs/OUTPUT.md`,
`docs/CI.md`; README restructured per §5.6; UX-S14, UX-S15, UX-S21.

**E. Examples** — `examples/services.yaml`, `examples/minimal.yaml`,
`examples/production.yaml`, per §5.5.

**F. Supply chain and release** — UX-S16, UX-S17, UX-S18, UX-S19, UX-S20; the release workflow
gains the five binary archives and `SHA256SUMS`.

**G. Tests** — the 24 UX acceptance tests in §11, plus the example-validation mechanism of
§5.13.

**Explicit non-goals for 9.2B.** No new adapter. No topology inference. No monitoring, daemon,
web UI or TUI. No remediation. No secret-manager or cloud-provider integration. No plugin
system. No config templating. No target discovery. No global socket semaphore. No terminal
color. No `--ci` flag. No renamed flag. No change to `SchemaVersion`, `RunSchemaVersion`, the
60 finding codes, the 42 failure classes, the credential sources or the exit codes. No new
dependency.

---

## 11. UX acceptance matrix — frozen for 9.2B

| ID | Test | Asserts |
|---|---|---|
| UX-01 | root help discoverability | Root help lists every registered command; the service list matches the CLI registry exactly |
| UX-02 | single-target help | All four leaf helps carry: purpose, usage, required flags, credential safety, TLS, output, and the identical five-line exit-code block |
| UX-03 | fleet help | `run --help` carries the exit-code block and the run-specific meaning of 4 |
| UX-04 | minimal example parses | `examples/minimal.yaml` decodes through the real loader |
| UX-05 | four-service example parses | `examples/services.yaml` decodes and covers all four registered services |
| UX-06 | plaintext secret fails safely | A plaintext `password:` exits 2, names the file and line, and no socket is opened |
| UX-07 | missing env actionable | The error names the variable, says it is unset, and never prints a value |
| UX-08 | malformed and invalid config actionable | Every corpus case in §3.5 exits 2 with file, location, cause and remedy — **including `ca_file` and a zoned host** |
| UX-09 | terminal mixed run readable | Aligned run summary; one spelling of each state; per-target index before detail; no Markdown markers; no leaf flag named in a fleet recommendation; a finding printed once |
| UX-10 | execution vs diagnostic failure distinct | `EXECUTION_FAILED` never carries a report; a COMPLETED target with a rejected credential is not an execution failure |
| UX-11 | JSON machine consumption | Every §3.6 question answerable without parsing prose; the single-target completeness limit is documented and pinned |
| UX-12 | shareable redaction | No declared host, address, identity, evidence ID **or configured filesystem path** survives into a shareable aggregate, for every reachable `EXECUTION_FAILED` cause; a planted residual fails closed |
| UX-13 | exit-code docs match the executable | Every code documented in `docs/CI.md`, the README and every help surface is produced by a real invocation, and no code is documented that cannot occur |
| UX-14 | CI example preserves the exit code | No documented example uses `\| tee` or `\|\| true`; every one re-raises the captured code after the artifact step |
| UX-15 | compatibility claims backed by evidence | The existing `docsclaims` guards, **plus**: every registered service appears in the README's supported-services statement, and every implemented credential source appears in its credential section |
| UX-16 | version discoverable | `--version` prints the injected or module version; a dev build prints `dev`; the report's `run.svcdoctorVersion` equals what `--version` printed |
| UX-17 | no internal Go names | No user-facing error contains a Go type name, a package path, `%!`, a single-dash rendering of a double-dash flag, or a raw `os` syscall name |
| UX-18 | docs command examples executable | Every ` ```yaml ` fence in README, `docs/` and `examples/` decodes through the real loader, or is marked as a counter-example and fails as documented |
| UX-19 | 80-column output acceptable | No emitted line exceeds 100 columns; the finding indent survives wrapping at 80 |
| UX-20 | redirected / non-TTY output stable | Output is byte-identical to a pipe and to a TTY; no escape sequence is ever emitted; `COLUMNS` unset gives the fixed default |
| UX-21 | security reporting exists | A root `SECURITY.md` names a private channel and a supported-version policy |
| UX-22 | supply chain | Every third-party action in every workflow is SHA-pinned; `govulncheck` runs on pull requests |
| UX-23 | contribution guidance exists | `CONTRIBUTING.md` names the quality gate, the ADR requirement and the English-only policy |
| UX-24 | platform notes are honest | The macOS resolver limitation is documented wherever a macOS artifact is offered |

**24 acceptance tests.**

---

## 12. Release maturity recommendation

**`v0.4.0` after Phase 9.2B, and not before. Not `v1.0.0`, and not a pre-release label.**

Reasons, in order:

1. **Four release blockers are open**, one of which (UX-B01) is a disclosure defect in the
   feature whose entire purpose is safe disclosure. Nothing ships over that.
2. `v0.x` is the honest signal. The CLI has been stable across four tags, the report schema has
   been `SchemaVersion 1` since Phase 4 and has never broken, and the exit codes are frozen —
   but Redis, RabbitMQ and `run --config` have never been in a published release, and the
   `--user`/`--username` split (UX-S04) is a wart a `1.0` would freeze permanently.
3. `alpha`/`beta` would be **less** accurate, not more. Four services are validated at Level 3
   against seven real implementations with committed fixtures, mutation closure is at zero
   survivors, and 108 of 108 multi-target requirements are traced to named tests. That is not
   alpha work.
4. A minor bump rather than a patch: `v0.4.0` is the release that introduces Redis, RabbitMQ and
   multi-target execution to the public.

`v1.0.0` becomes discussable when the blockers are closed, the four leaf flag sets are
reconciled or deliberately frozen as-is, and at least one managed platform has real evidence.

---

## 13. Verdicts

| Area | Verdict |
|---|---|
| **User journey** | **Strong, with four blocking defects.** Discover→understand is damaged by a stale README; install→configure→run→read is genuinely excellent; share and automate have one real defect each |
| **Config UX** | **Excellent.** The best-executed surface in the product. Errors name the file, the location, the cause, the remedy, and often the reason the design refuses to guess |
| **Terminal UX** | **Good, unpolished.** Content and claim discipline are right; alignment, wrapping, deduplication and summary placement are not |
| **JSON / machine consumption** | **Good.** Every important decision is a typed field. One documented asymmetry (UX-S01) |
| **Shareable UX** | **Sound for single targets, defective for run aggregates** (UX-B01) |
| **OSS hygiene** | **Incomplete.** Apache-2.0 present; vulnerability reporting and contribution guidance absent |
| **Supply chain** | **Strong for the image, incomplete for the module.** SHA-pinned release workflows, SBOM, provenance, keyless signature, reproducible platform images; one tag-pinned workflow and no `govulncheck` |
| **Compatibility documentation** | **Exemplary and mechanically guarded.** No change needed beyond UX-S14's completeness gap |

---

## 14. Stop conditions

All five were evaluated. **None is met.**

1. *The CLI cannot be documented safely without changing a frozen contract* — **no.** Every
   correction in §10 is documentation, help text, renderer layout or a bug fix. The one place
   the frozen contract binds (UX-S01) is resolved by documenting the limit, not by changing it.
2. *Report semantics are insufficient for machine consumption without a schema break* — **no.**
   Every §3.6 question is answerable from typed fields today.
3. *Credential UX requires exposing secret material to be usable* — **no.** File, stdin and
   reference-by-name cover CI and Kubernetes without a value ever entering a config, an
   argument or a report.
4. *Version identification requires changing canonical report semantics* — **no.**
   `run.svcdoctorVersion` already exists in both schemas.
5. *Compatibility documentation contradicts the evidence* — **no.** It matches, is guarded by
   tests, and its one gap (UX-S14) is an omission inside a completeness claim, correctable in
   place.

UX-B01, UX-B02 and UX-B03 are **defects against contracts the project already holds** — the
ADR 0018 redaction policy, the ADR 0074 §9 validate-before-dial requirement, and the honest-
documentation rule. Fixing them restores those contracts rather than reopening them, and each
is permitted by the freeze rule as a security, correctness or documentation fix.

---

## 15. Ledger

| | |
|---|---|
| ADRs created | 0075, 0076, 0077 — all **Accepted**, none implemented |
| Files changed | 4 added — this document and the three ADRs — and 1 modified: `docs/decisions/README.md`, the ADR index, which gains the paragraph that lists them. **No source file, no test, no example and no user-facing document was modified** |
| `SchemaVersion` | 1 — unchanged |
| `RunSchemaVersion` | 1 — unchanged |
| Finding codes | 60 — unchanged |
| Failure classes | 42 — unchanged |
| `Reveal` production sites | 4 — unchanged |
| `SecretFor` production sites | 4 — unchanged |
| External modules | 2 — unchanged |
| Commits | 0 |
| Staged | 0 |
| Pushed | no |
| Tagged | no |

`make check` was green at the start of this phase and nothing it inspects was touched.
