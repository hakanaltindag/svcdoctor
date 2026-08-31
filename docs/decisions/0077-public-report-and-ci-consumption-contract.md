# ADR 0077 — Public report and CI consumption contract

**Status:** Accepted
**Date:** 2026-09-01
**Phase:** 9.2A
**Extends:** ADR 0018 (structural redaction), ADR 0074 (multi-target report and exit
semantics). Neither is reopened.

---

## 1. Context

svcdoctor's machine interface is two things: a process exit code and a JSON document. Phase
9.2A audited both from the outside — writing `jq` against real output, running the four
documented exit codes, and producing a shareable report from a run that failed to execute.

**The exit codes work and are undocumented where they matter.** `0`, `1`, `2`, `3`, `4` with
precedence `3 > 2 > 4 > 1 > 0` behave exactly as specified. The README explains them well. But
there is no CI documentation anywhere, `run --help` — the command written for CI — carries no
exit-code block, and `diagnose redis --help` is the one leaf that carries neither the block nor
the "exit 0 is not success" caveat. Measured, a run against a plaintext PostgreSQL with a
credential configured exits **0** with `session NOT established`, and two unreachable hosts
exit **4** with `status OK`. Both are correct and both are traps for a policy that reads only
the code.

**The JSON is good and has one asymmetry.** Every question a CI consumer asks is answerable
from a typed field: `summary.status` for a diagnostic problem, `targets[].executionState` for
an execution failure, `findings[].code` for the finding, `run.service` or `targets[].service`
for the service kind, `run.svcdoctorVersion` for the producer. Nothing important requires
parsing human prose. The aggregate carries `summary.incomplete` and `targets[].incomplete`; the
single-target report carries no completeness field at all, by explicit decision recorded in the
README. A consumer holding only a `diagnose … --output json` artifact — the normal CI shape —
cannot distinguish an incomplete run from a complete one, because the exit code that carries
that fact is not in the file.

**The shareable projection is sound for a single target and defective for an aggregate.**
Measured on a single target: `target.requested` becomes `host-002:55433`, `vantage.host`
becomes `host-001`, every evidence identifier becomes `evidence-0NN`, and
`security.redactions` reports the counts. Measured on a run whose target failed to execute:
the target ID is pseudonymized to `target-001` and `executionError.message` carries
`fe80::1%en0` — a raw address — or `stat /path/to/private-ca.pem: no such file or directory` —
a raw filesystem path. `internal/security/redaction/run.go` passes the message through prose
replacement, but `collectRun` builds the pseudonym table only from targets that **have a
report**, so a failed target contributes none of its own identifiers; and `RedactRun` never
calls `verifyNoResidual`, which runs per embedded report. The README's claim that redaction
"fails closed" is therefore not true of this path.

**Two configuration errors reach execution.** A `tls.ca_file` naming a missing file and a
`host` carrying an IPv6 zone identifier are both rejected at exit 2 by the leaf commands and
both become `EXECUTION_FAILED` with `class: INTERNAL` and exit 4 under `run --config`.
`internal/domain/executionstate.go` states the invariant they violate in its own words:
*"configuration errors never reach execution at all — ADR 0074 §9 requires a whole
configuration to validate before any target is dialled."*

---

## 2. Decision

### 2.1 The exit codes are frozen and `docs/CI.md` owns them

| Code | Meaning |
|---|---|
| `0` | a report was produced and no ERROR or CRITICAL target-side problem was proven |
| `1` | a report was produced and an ERROR or CRITICAL target-side problem was proven |
| `2` | svcdoctor was invoked with something it cannot act on; no report |
| `3` | svcdoctor itself failed and produced no usable report |
| `4` | a report was produced but svcdoctor's own execution did not finish |

Precedence `3 > 2 > 4 > 1 > 0`. No code is added, removed or reinterpreted.

They are documented in exactly three places with one authority: **`docs/CI.md` is
authoritative** and carries the table, the precedence and the three traps; every help surface
carries the same five-line block; the README carries the table and links to `docs/CI.md`.

The three traps are stated wherever the table appears:

1. **Exit 0 is not "the service works."** It means no ERROR or CRITICAL target-side problem was
   *proven*. A run that withheld its credential over a plaintext channel exits 0 with no
   session. Read `outcome`.
2. **Exit 1 is not a svcdoctor failure.** svcdoctor worked and found a target-side problem.
3. **Exit 4 outranks exit 1** and means svcdoctor's own execution did not finish. It qualifies
   every conclusion in the report and is not evidence about the target.

### 2.2 Three CI exit policies, documented, built only from existing codes

| Policy | Fails the pipeline on | For |
|---|---|---|
| **STRICT** | anything but `0` | a release gate, a promotion gate |
| **DIAGNOSTIC** | `1`, `2`, `3` — not `4` | a scheduled connectivity check where a local timeout is noise, provided `4` is surfaced some other way |
| **OBSERVATIONAL** | `2` and `3` only | a report you always want to keep; diagnostic results are read from the artifact |

`2` and `3` fail under **every** policy. `2` means the invocation was wrong; `3` means
svcdoctor failed. Neither is ever a statement about a target and neither is ever tolerable.

These are documentation patterns. **No `--ci` flag, no `--fail-on` flag and no new mode is
added**, because a policy is the pipeline's decision and the exit codes already express every
one of them.

### 2.3 The artifact rule is written once and used in every example

```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e
# upload report.json here, before deciding
exit $rc
```

Measured facts this rests on: a plain redirect preserves the exit code; stderr is empty for
exit `0`, `1` and `4`, so `2>` capture never contaminates the artifact; stdout is empty for `2`
and `3`.

**`| tee` and `|| true` are named as defects in `docs/CI.md`**, with the measured evidence:
under POSIX `sh`, `svcdoctor … | tee report.json` exits `0` for a run that exited `1`.

Examples are given for generic shell, GitHub Actions, GitLab CI and Azure DevOps. Every one
uses environment-secret injection or a mounted file, and none requires a platform-specific
integration.

`--output json` redirected to a file is the artifact. `--shareable --output json` is a
**second** artifact when the report leaves the organisation. Terminal output is for humans and
is never the artifact.

### 2.4 The single-target completeness asymmetry is documented, not fixed

`domain.SchemaVersion` stays **1** and the single-target report gains no field.

`docs/OUTPUT.md` states the limit plainly: for a single-target report the **exit code is the
authority on completeness**, and a consumer that needs completeness in-band should use
`svcdoctor run --config` — whose aggregate carries `summary.incomplete` and
`targets[].incomplete` — even for one target.

This is a real limit and it is written as one rather than argued away.

### 2.5 A configuration error never reaches execution

`tls.ca_file` and `host` are validated during configuration validation, alongside every other
field, and both exit **2** naming the file and the location — the shape eighteen other
configuration errors already achieve.

This restores what `internal/domain/executionstate.go` already documents and what ADR 0074 §9
already requires. `ExecutionErrorClass` keeps its two members and both become true again:
`CREDENTIAL_RESOLUTION` and `INTERNAL` are the only failures reachable during a run, and
`INTERNAL` once more means what it says.

### 2.6 The shareable aggregate fails closed, and its guarantee is stated exactly

Three changes, together:

1. `collectRun` gathers identifiers from a target's **declared configuration** — its host and
   its target ID — whether or not that target produced a report, so a failed target's own host
   enters the pseudonym table.
2. `RedactRun` performs a run-level `verifyNoResidual` over the finished aggregate, so it fails
   closed exactly as a single report does.
3. `executionError.message` never carries a filesystem path. §2.5 removes both reachable
   producers at source, and the remaining runner-error path is sanitized the way
   `execute.go:194`'s credential path already is.

The guarantee is then stated in these words and no stronger:

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

**Forbidden wording, each for a stated reason:** "anonymized" — it is pseudonymization, and a
consistent pseudonym is a correlation handle. "Compliant" with any named regime. "Safe to
publish" unqualified — a preserved port, duration and timestamp set is information. And any
unqualified "fails closed" claim until the three changes above land; once they do, the claim is
restored **scoped**: the residual check covers the identity categories the redaction table
holds, and a value it does not classify is not covered.

### 2.7 The renderer invents nothing

Every terminal change authorized by Phase 9.2B is layout, wrapping, ordering, deduplication or
the wording of text a rule already produced. No renderer creates a finding, computes a
severity, derives a state or interprets a protocol. A finding printed once for four addresses
is one finding rendered once, not a merged conclusion.

Two consequences follow directly. A finding's `detail` must not contain Markdown emphasis — the
terminal prints `**Zero credential bytes were sent.**` verbatim today, and the renderer is right
not to interpret it, so the finding text is what changes. And a recommendation must not name a
leaf CLI flag, because the same finding is rendered inside a `run --config` report where that
flag does not exist; it names the capability instead.

---

## 3. Consequences

**A CI author can copy a working pipeline instead of inventing one.** The three policies cover
the real cases and each is expressible with the exit codes that already exist, so nothing about
the CLI has to change to support them.

**A shareable aggregate becomes as safe as a shareable report.** Today it is not, and the gap is
invisible from outside: the target ID is pseudonymized, which makes the artifact *look*
redacted while an address or a private-CA path sits beside it.

**A YAML typo stops being reported as an internal svcdoctor failure.** Exit `2` instead of `4`,
`class: INTERNAL` no longer misapplied, and a CI policy that retries on `4` stops looping on a
mistake that will never succeed.

**The single-target JSON stays as it is, with a documented limit.** A consumer that needs
completeness in the file has a supported route — `run --config` with one target — and does not
need a schema change to get it.

**`SchemaVersion` stays 1 and `RunSchemaVersion` stays 1.** No field is added to either
document. The 60 finding codes, the 42 failure classes and the four execution states are
unchanged.

**Findings whose text names a CLI flag must be rewritten.** That is a small, real content change
in the diagnosis packages, and it is the correct place for it: a finding that assumes its
reader typed a flag is a finding making an assumption about its renderer.

---

## 4. Rejected alternatives

**Add an `incomplete` field to `domain.Report`.** Rejected. It is additive and it would still be
a change to a schema frozen since Phase 4, whose *absence* is a documented decision the README
explains: the CLI does not inject process- and presentation-level facts into the canonical
report. Reopening that for a case with a supported workaround is not proportionate. Recorded
here so a future phase can weigh it deliberately rather than rediscover it.

**Add a `--fail-on <codes>` or `--ci` flag.** Rejected. The exit codes already express all three
policies, and a flag would put pipeline policy inside the tool — where it cannot be reviewed by
the people who own the pipeline, and where it becomes a second place the semantics are defined.

**Emit exit-code guidance on stderr when the code is non-zero.** Rejected. stderr is empty for
`0`, `1` and `4`, and that is a contract machine consumers rely on. Advice on stderr would
break every pipeline that captures it.

**Redact `executionError.message` by dropping it entirely from shareable output.** Rejected. The
message is the only account of why a target was not measured, and a shareable report that says
"a target failed for an undisclosed reason" is not usefully shareable. Pseudonymizing it
correctly is the right answer, and §2.5 shrinks what it has to carry.

**Scan `executionError.message` for path-shaped and address-shaped substrings.** Rejected on the
same grounds `verifyNoResidual` already records: this package checks exact known values rather
than patterns, precisely so that it cannot be satisfied by output that merely looks clean. A
regular expression over prose is the mechanism ADR 0018 forbids.

**Leave the `ca_file` and zoned-host cases as execution failures and document them.** Rejected.
They contradict an invariant the code states about itself, they misclassify a user error as an
internal one, and they are the only two producers of the disclosure defect in §2.6. Documenting
a defect that has a correct fix is not a decision, it is a deferral.

**Make the renderer merge per-address findings into a synthesized cross-path conclusion.**
Rejected as an architecture violation. Deduplicating identical rendered text is presentation;
concluding that four addresses share a cause is diagnosis, and diagnosis runs on the frozen
evidence graph, not in a renderer.

---

## 5. Verification

| Claim | Verified by |
|---|---|
| The five exit codes and their precedence are unchanged | UX-13; existing exit-code tests |
| Every documented code is produced by a real invocation, and no undocumented code is claimed | UX-13 |
| `run --help` and every leaf help carry the exit-code block | UX-02, UX-03 |
| No documented CI example uses `\| tee` or `\|\| true`; every one re-raises the captured code | UX-14 |
| stdout carries exactly one JSON document for `0`, `1`, `4`; stderr is empty | UX-11 |
| stdout is empty for `2` and `3` | UX-11 |
| Every machine question is answerable without parsing prose | UX-11 |
| The single-target completeness limit is documented and pinned | UX-11 |
| Execution failure and diagnostic failure are structurally distinct | UX-10 |
| No configuration value the leaf CLI validates reaches execution under `run --config` | UX-08 |
| No `EXECUTION_FAILED` result is reachable from a value the configuration declares | UX-08 |
| No declared host, address, identity, evidence ID or configured path survives into a shareable aggregate, for every reachable failure cause | UX-12 |
| A planted residual makes the shareable aggregate fail closed | UX-12 |
| No finding text contains Markdown emphasis or names a leaf CLI flag | UX-09 |
| `SchemaVersion` 1, `RunSchemaVersion` 1, 60 finding codes, 42 failure classes | existing domain and closure tests |
