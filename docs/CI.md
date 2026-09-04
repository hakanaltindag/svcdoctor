# svcdoctor in CI

**This document is authoritative for exit codes.** Where the README, `--help` or any other
document disagrees with it, this one is right and the other is a defect.

## Exit codes

| Code | Meaning | Typical example | What a pipeline should do |
|---|---|---|---|
| `0` | A report was produced, execution completed, and **no ERROR or CRITICAL target-side problem was proven** | The journey reached its terminal exchange. Or it did not, and nothing proved a target-side fault — a credential withheld over a plaintext channel exits 0 | Pass. **Read the report before calling it healthy** |
| `1` | A report was produced, execution completed, and an ERROR or CRITICAL target-side problem was proven | DNS did not resolve, TCP was refused, the TLS chain did not verify, the credential was rejected | Fail, in most policies. svcdoctor worked; the target has a problem |
| `2` | svcdoctor was invoked with something it cannot act on. **No report** | A malformed configuration, an unknown field, a duplicate target id, a plaintext password, an unset credential variable, an unreadable `ca_file`, a mistyped flag | Fail always. Nothing was measured and retrying changes nothing |
| `3` | svcdoctor itself failed and produced no usable report | An internal invariant failed, or redaction could not certify a shareable report and refused to emit one | Fail always. This is a bug — please report it |
| `4` | A report was produced, but svcdoctor's **own execution** did not finish | The run was cancelled, a local budget expired, or a target could not be executed locally | Fail in most policies. The report is truthful but partial |

Precedence, when more than one applies: **`3` > `2` > `4` > `1` > `0`**.

### Three things exit codes do not mean

**Exit 0 is not "the service works."** It means no error-level target-side problem was *proven*.
A run against a plaintext endpoint with a credential configured exits 0 having sent nothing and
established no session, because svcdoctor's credential policy withheld the password and that is
not the target's fault. The report says so on its `outcome` line. Read it.

**Exit 1 is not a svcdoctor failure.** svcdoctor worked perfectly and found a problem with the
target. Treating it as a tool error is the most common mistake in a first pipeline.

**Exit 4 outranks exit 1.** A run that was cut short *and* proved an ERROR exits 4, and the
finding stays in the report in full. Incompleteness qualifies every conclusion in a document, so
reporting the ERROR as though the picture were complete would overstate what was measured.

### Where each code writes

| Code | stdout | stderr |
|---|---|---|
| `0`, `1`, `4` | exactly one report | empty |
| `2`, `3` | empty | one error line |

That is a contract. `2>` capture never contaminates a JSON artifact, and a non-empty stdout
always parses.

## Three exit policies

Pick one deliberately. These are documentation patterns built from the codes above — there is no
`--ci` flag and no `--fail-on` flag, because a policy belongs to the pipeline that owns the
consequences, not to the tool.

### STRICT — only 0 passes

A release gate or a promotion gate. Nothing ships unless the dependency was measured completely
and cleanly.

```sh
svcdoctor run --config services.yaml --output json > report.json
# any non-zero status fails the step
```

### DIAGNOSTIC — 1, 2 and 3 fail; 4 does not

A scheduled connectivity check where a local timeout is noise you have decided to tolerate. Use
it only if you surface code 4 some other way — an incomplete run is a run that measured less
than you asked for, and silently passing it is how a broken check looks healthy for a month.

```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e
case "$rc" in
  0) ;;                                   # nothing proven
  4) echo "::warning::run incomplete" ;;  # tolerated, but said out loud
  *) exit "$rc" ;;
esac
```

### OBSERVATIONAL — only 2 and 3 fail

A report you always want to keep, where the diagnostic result is read from the artifact rather
than from the process status.

```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e
[ "$rc" -ge 2 ] && [ "$rc" -le 3 ] && exit "$rc"
exit 0
```

**`2` and `3` fail under every policy.** `2` means the invocation was wrong; `3` means svcdoctor
failed. Neither is ever a statement about a target, and neither is ever tolerable.

## Keeping the report and the exit code

Redirect. Do not pipe.

```sh
set +e
svcdoctor run --config services.yaml --output json > report.json
rc=$?
set -e

# upload report.json here, before deciding anything

exit "$rc"
```

### Two patterns that silently discard the result

**`|| true` throws the answer away.** Do not copy this:

```text
svcdoctor run --config services.yaml > report.json || true   # always 0
```

That is the whole failure: the step passes for a run that proved an ERROR, and nothing in the
log says so.

**A pipeline reports the *last* command's status, not svcdoctor's.** Nor this:

```text
svcdoctor run --config services.yaml --output json | tee report.json   # exits with tee's status
```

Measured: a run that exits `1` becomes `0` through `tee` under POSIX `sh`. Bash can recover it
with `${PIPESTATUS[0]}`, but that is **Bash-specific** and does not work under `sh`, `dash` or
`ash` — which is what many container images provide:

```bash
#!/usr/bin/env bash
svcdoctor run --config services.yaml --output json | tee report.json
rc="${PIPESTATUS[0]}"
```

A plain redirect works everywhere and needs no explanation. Prefer it.

## Providers

Every example below injects a secret the platform's own way and mounts nothing svcdoctor-specific.
**None of these has been executed against the hosted service it targets**; they are the documented
shape, not a validation record.

### GitHub Actions

```yaml
- name: Diagnose service connectivity
  id: svcdoctor
  env:
    ORDERS_DB_PASSWORD: ${{ secrets.ORDERS_DB_PASSWORD }}
    KAFKA_PASSWORD: ${{ secrets.KAFKA_PASSWORD }}
  run: |
    set +e
    svcdoctor run --config services.yaml --output json > report.json
    echo "rc=$?" >> "$GITHUB_OUTPUT"
    set -e

- name: Keep the report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: svcdoctor-report
    path: report.json

- name: Apply the exit policy
  run: exit ${{ steps.svcdoctor.outputs.rc }}
```

`if: always()` on the upload step is the point: the artifact is most useful exactly when the run
failed.

### GitLab CI

```yaml
connectivity:
  image: ghcr.io/hakanaltindag/svcdoctor:v0.4.0
  variables:
    ORDERS_DB_PASSWORD: $ORDERS_DB_PASSWORD    # masked project variable
  script:
    - set +e
    - svcdoctor run --config services.yaml --output json > report.json
    - echo $? > report.rc
    - set -e
    - exit "$(cat report.rc)"
  artifacts:
    when: always
    paths: [report.json]
```

### Azure DevOps

```yaml
- script: |
    set +e
    svcdoctor run --config services.yaml --output json > $(Build.ArtifactStagingDirectory)/report.json
    echo "##vso[task.setvariable variable=svcdoctorRc]$?"
    set -e
  displayName: Diagnose service connectivity
  env:
    ORDERS_DB_PASSWORD: $(ordersDbPassword)   # secret variable

- publish: $(Build.ArtifactStagingDirectory)/report.json
  artifact: svcdoctor-report
  condition: always()

- script: exit $(svcdoctorRc)
  displayName: Apply the exit policy
```

### Kubernetes

svcdoctor runs, reports and exits, so it belongs in a `Job` rather than a `Deployment`. It needs
no Kubernetes API access, no capabilities and no `hostNetwork`. Mount secrets as files and use
`password: {file: /run/secrets/…}`. Worked manifests are in [`../examples/kubernetes/`](../examples/kubernetes/).

## Reading the artifact

Everything a pipeline needs is a typed field. Nothing requires parsing prose.

```sh
# Which targets have a diagnostic problem?
jq -r '.targets[] | select(.report.summary.status == "PROBLEMS_FOUND") | .targetId' report.json

# Which targets could not be executed at all?
jq -r '.targets[] | select(.executionState != "COMPLETED") | "\(.targetId) \(.executionState)"' report.json

# Every finding code, with its target and severity.
jq -r '.targets[] | .targetId as $t | .report.findings[]? | "\($t) \(.severity) \(.code)"' report.json

# Was the run complete?
jq '.summary.incomplete' report.json

# Which svcdoctor produced this?
jq -r '.run.svcdoctorVersion' report.json
```

The distinction that matters most: **`executionState` is about svcdoctor, and
`report.summary.status` is about the target.** A rejected password is a `COMPLETED` execution
whose report carries the failure. `docs/OUTPUT.md` explains why they are separate axes.

## Sharing a report outside your organisation

```sh
svcdoctor run --config services.yaml --output json --shareable > report.shareable.json
```

Produce it as a *second* artifact, never as a replacement for the first: the local report is what
you debug from. What the shareable projection replaces, and what it deliberately keeps, is in
[`OUTPUT.md`](OUTPUT.md#shareable-reports).
