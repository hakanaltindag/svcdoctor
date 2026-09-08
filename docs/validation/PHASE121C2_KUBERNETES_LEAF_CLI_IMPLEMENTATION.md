# Phase 12.1C.2 — the Kubernetes leaf CLI, implemented

- **Phase:** 12.1C.2 (implementation; **one new production file**, no dependency, no schema, no
  finding, no rule, no renderer change)
- **Baseline:** `065d13aa11b5f6184e870fc7bc6449f1bea9bef5`, equal to `origin/main`, clean tree,
  `make check` green before anything was edited
- **Implements:** `docs/validation/PHASE121C1_KUBERNETES_LEAF_CLI_CONTRACT_FREEZE.md`, exactly —
  ten flags, no eleventh
- **Closes:** Phase 12.1C's one open blocker. ADR 0094 §2.10 and §2.12 and `PHASE121A…§12.1`/`§14`
  (KAC-040) assign the CLI case to 12.1C, and it now exists
- **Outcome:** **69 finding codes, 24 production rules, 10 public Kubernetes flags, 28/28
  mutations caught, 0 survivors, 1,755,446 fuzz executions, 0 crashes**

---

## 1. Pre-state, measured rather than trusted

| | Before | After |
|---|---|---|
| `SchemaVersion` | 1 | **1** |
| `RunSchemaVersion` | 1 | **1** |
| Finding codes | 69 | **69** |
| Kubernetes finding codes | 4 | **4** |
| Production rules | 24 | **24** |
| Failure classes | 42 | **42** |
| `RuleContext` fields | 3 | **3** |
| Authorized `Reveal` sites | 5 | **5** |
| `SecretFor` production sites | 5 | **5** |
| External modules | 40 | **40** |
| `k8s.io` import paths | 10 | **10** |
| Exit codes | 5 | **5** |
| Public `diagnose` leaves | 4 | **5** |
| Kubernetes CLI cases | 0 | **1** |
| Kubernetes public flags | 0 | **10** |
| Renderer files changed | — | **0** |
| Relation producers | 0 | **0** |
| Planner | none | **none** |

The counts are the guards' own: `TestTheConvergenceInventoryIsComplete` attributes 69 of 69 codes
to 24 rules, `TestRevealHasOneProductionCallSitePerService` derives its total from a five-entry
map of authorized files, and `TestTheKubernetesClientImportsAreExactlyTheAllowlist` reads the ten
paths from the package's own sources.

---

## 2. What was built

**One production file.** `internal/cli/kubernetes.go` — `kubernetesCommand`, `parseKubernetes`
and `diagnoseKubernetesCommand`, a sibling of `rabbitmq.go` with the same six-part shape.

**Three production files touched.** `internal/cli/root.go` gains one `case` in the existing switch
and a fifth test seam; `internal/cli/usage.go` gains `usageKubernetes` and one line in the service
list; `internal/cli/secret.go` gains the flag-name pair (§5).

**Four production files touched for the parameterization alone** — `postgres.go`, `kafka.go`,
`redis.go`, `rabbitmq.go` — each by one line, naming the password pair they already used.

```
internal/cli/root.go            case "kubernetes": a.diagnoseKubernetesCommand(ctx, args[1:])
        ↓
internal/cli/kubernetes.go      parseKubernetes → app.KubernetesTarget
                                              → app.InspectKubernetesTarget → (host, port)
                                              → a.readSecret → credentialFor(host, port, "", …)
        ↓                       context.WithTimeout(ctx, command.timeout)
internal/app/kubernetes.go      DiagnoseKubernetes                       ← UNCHANGED
        ↓
internal/adapter/kubernetes     Inspect → Connect → Acquire, five nodes  ← UNCHANGED
        ↓
internal/diagnosis/kubernetes   two rules, four codes, + FailureBoundary ← UNCHANGED
        ↓
domain.Report → project → render → ExitCode                              ← UNCHANGED
```

**There is exactly one Kubernetes diagnosis implementation.** The leaf reaches no `k8s.io`
package, issues no API request of its own, creates no `Finding` and no `Evidence`, and leaves
`Budgets` zero — which is the frozen defaults, the same value the fleet runner passes.

---

## 3. The public surface, as implemented

```
svcdoctor diagnose kubernetes --kubeconfig <path> --context <name> \
                              --namespace <ns> --service-name <name> [flags]

svcdoctor diagnose kubernetes --in-cluster \
                              --namespace <ns> --service-name <name> [flags]
```

**Ten flags:** `--kubeconfig` `--context` `--in-cluster` `--namespace` `--service-name`
`--token-file` `--token-stdin` `--timeout` `--output` `--shareable`.

Defaults: `--timeout 30s`, `--output text`, `--shareable false`. Every other flag defaults empty
or false, and none is defaulted to a value that would change which cluster is read.

`TestTheKubernetesFlagSurfaceIsExact` asserts set equality in both directions **and** the count,
from a list written out rather than read from the production declaration — a guard that derived
its expectation from the code it guards would pass for any set at all.

---

## 4. Authentication, as reached from the command

| Mode | Reached by | Flag added |
|---|---|---|
| **A** explicit bearer token | `--token-file` or `--token-stdin` | the two |
| **B** kubeconfig `tokenFile`, read by svcdoctor | `--kubeconfig` + `--context` | **none** |
| **C** client certificate and key | `--kubeconfig` + `--context` | **none** |
| **D** in-cluster ServiceAccount | `--in-cluster` | that one |

A, B, C and the kubeconfig's own inline token are each driven end to end against a hermetic API
server in `test/fleet/kubernetesleaf_test.go`. **Modes B and C take the byte-identical
invocation**; only the kubeconfig differs, which is the point of refusing a `--client-cert` pair.

D is proven by its refusals — it needs a projected ServiceAccount, and 12.1D owns the real-cluster
half.

### 4.1 The credential

Bound to the API server the kubeconfig's own `server:` resolved to, with an **empty identity**,
because a Kubernetes credential carries no username. `TestADeclaredTokenBindsToTheDerivedAPIServer`
asserts the host, the port and the empty identity; ADR 0028's binding check refuses the credential
anywhere else, unchanged.

**`Reveal` and `SecretFor` stay at 5 / 5.** The command holds a `security.Secret` on its way to
`internal/app` and never opens it; `TestTheCommandBoundaryOpensNoSecret` says so from inside the
package and `forbidigo` fails the build on the call.

### 4.2 An empty declared token source is exit 2

The one place this command differs from its four siblings, and the difference is structural. For
the other four an empty source means *no credential* and the run reaches a truthful
`*_CREDENTIAL_NOT_CONFIGURED` finding at exit 0. Here it cannot: `Inspect` was already told a
credential is supplied and chose the bearer-token mode on that basis, and Kubernetes has **no**
credential-not-configured finding and cannot gain one (ADR 0094 §2.7). `internal/fleet/secret`
already refuses the same shape for the same mode.

Four inputs are covered: an empty file, a file holding one newline, empty stdin, and a newline on
stdin.

---

## 5. The generic secret helper stayed generic

`credentialSources` gained two fields — `fileFlag` and `stdinFlag` — and `readSecretFile` takes
the flag name. **There is no default and no service branch**: five call sites name their own pair,
and `TestTheSecretHelperKnowsNoServiceName` scans the file's executable text for a service name.

Every existing message is byte-identical, asserted from two directions:

- `TestTheFourExistingCommandsStillNameThePasswordFlags` drives all four real parsers and pins
  *"--password-file and --password-stdin are mutually exclusive"*.
- The four existing help goldens and `root.txt` are **unchanged**; the only golden diff in the
  phase is one added line in `diagnose.txt` and the new `kubernetes.txt`.

`internal/cli/secret_test.go`'s literals were updated to name the password pair. No assertion in
that file changed — they are ADR 0049's own tests, and they now exercise the shape the four
commands really construct.

---

## 6. Validation ownership: nothing is duplicated

The command validates the **invocation** — flag syntax, the output format, the timeout, source
exclusivity, the empty-source rule — and nothing about Kubernetes. Target shape, kubeconfig
parsing, context existence and every refused construct are one question with one owner:
`app.InspectKubernetesTarget`, which performs no network operation.

`TestTheKubernetesTargetRulesAreTheAdapters` drives eight defects and asserts the **adapter's own
wording** reaches stderr. If the CLI had restated any rule, the wording would be this package's,
and the fleet decoder — which asks the same function the same question — could answer differently
for the same file. Mutation **KL-M22** plants exactly that and is caught.

---

## 7. The release gate: exec auth never executes

`TestAnExecCredentialPluginNeverExecutesThroughTheLeaf` builds a kubeconfig whose exec plugin
would `touch` a sentinel, and drives it through `svcdoctor diagnose kubernetes`. Four assertions
together:

| | Measured |
|---|---|
| exit code | **2**, a configuration error |
| the sentinel file | **does not exist** |
| API requests, counted at the server | **0** |
| the plugin's command, args and env in stdout/stderr | **absent** |

This does not replace the Phase 12.1B client-level sentinel test, which is unchanged and still
passes. It adds the entry-point proof: the surface an operator actually types.

---

## 8. The no-request failure matrix

Twenty-one invalid invocations, each against a **request-counting** hermetic API server. Every one
exits 2, writes nothing to stdout, and leaves the counter at **zero**.

neither authority · both authorities · a kubeconfig with no context · a context in-cluster · a
context the file does not name · no namespace · no service name · both token sources · a token
file in-cluster · a token on stdin in-cluster · an empty token file · an empty token on stdin · a
token beside a kubeconfig identity · an auth-provider · impersonation · basic authentication · a
proxy URL · `insecure-skip-tls-verify` · an unreadable token file · an unknown output format · a
non-positive timeout.

`internal/cli`'s `TestKP03AnInvalidInvocationNeverStartsARun` states the same property one layer
up, where the run seam fails the test if a run so much as begins. The two together are the claim:
nothing is dialled, and nothing is even asked to dial.

---

## 9. Entry-point equivalence

**The strongest stable boundary the architecture offers, and it is the repository's own.** ADR
0074 §2.1 makes the aggregate *wrap* rather than merge, and
`TestTheEmbeddedReportIsByteIdenticalToASingleTargetRun` already asserts byte identity for Redis.
So `TestTheLeafAndTheFleetProduceTheSameReport` compares the **whole canonical report** — the
evidence graph, every finding, every severity, confidence, basis and recommendation, and the
summary — with only `startedAt` and `duration` blanked, because a duration is a measurement rather
than content.

Five scenarios: healthy · Service not found · API access denied · selector selects zero Pods · no
ready endpoint. All five are byte-identical between the two entry points.

The comparison is **guarded against vacuity**: the leaf document must contain `"schemaVersion"`,
`k8s.api_access`, `k8s.service` and `service/payments` before the equality is asserted, so two
empty strings cannot pass.

---

## 10. Secret non-observability, and one honest limit

`TestTheBearerTokenValueIsUnobservable` runs two different tokens against an identical hermetic
server with an otherwise identical invocation, in three modes — `--output json`, `--output text`
and `--output json --shareable` — and requires **byte-identical** output. Neither token, and no
twelve-byte fragment of either, appears in stdout or stderr. No length, hash or prefix is logged.

This is Phase 9.1C's honest property rather than a stronger one: a secret *equal to* a value the
report must carry would be indistinguishable, so what is pinned is that **changing the credential
changes no byte of the answer**.

---

## 11. Hostile remote prose

`TestHostileAPIProseNeverReachesTheReport` returns a reason svcdoctor does act on beside a
`Status.Message`, a `details.name`, a `details.group` and a `causes[].message` carrying markup, an
injected finding code, a shell fragment and an ANSI escape — on a 404, a 403 and a 500, in all
three output modes. None of it appears anywhere. ADR 0094 §2.8 holds: API errors are normalized
from the HTTP status and `metav1.StatusReason` only.

The exec test asserts the same for kubeconfig content: a refused construct is named by kind, never
by content.

---

## 12. Exit behaviour, delegated rather than decided

| Scenario | Exit | Why |
|---|---|---|
| healthy Service | **0** | no ERROR finding |
| invalid invocation or configuration | **2** | `ErrUsage` |
| `KUBERNETES_SERVICE_NOT_FOUND` | **1** | ERROR |
| `KUBERNETES_API_ACCESS_DENIED` | **4** | the refused read leaves the run incomplete, and 4 outranks a WARN |
| `KUBERNETES_SERVICE_SELECTS_NO_PODS` | **1** | ERROR |
| `KUBERNETES_SERVICE_NO_READY_ENDPOINT` | **1** | ERROR |
| `401 Unauthorized` | **0** | CONTRACT-CONFORMANT KNOWN LIMITATION, §14 |

Nothing in `internal/cli/kubernetes.go` reads a finding, a severity or a code. Mutation
**KL-M26** replaces `ExitCode(result, runErr)` with a constant and is caught, which is what proves
delegation rather than coincidence.

---

## 13. Structural boundaries, re-proved

| | |
|---|---|
| `k8s.io` imports in `internal/cli` | **0** — `TestTheCommandBoundaryImportsNoKubernetesLibrary`, and `depguard` for every package under `internal/` |
| `net/http` or `os/exec` in `internal/cli` | **0** — `depguard`, unchanged |
| `security.Reveal` in `internal/cli` | **0** — `TestTheCommandBoundaryOpensNoSecret` and `forbidigo` |
| a Kubernetes branch in a generic package | **none** |
| a Kubernetes renderer branch | **none**, zero renderer files changed |

**One structural guard was widened, and the reason is worth recording.**
`TestTheCommandBoundaryReachesNoWirePackage` matched packages *named* `wire`. Kubernetes'
authorized `Reveal` is not in one — client-go owns the transport, so the last layer svcdoctor
controls is the package that assembles the connection — so the guard would have said nothing about
the one package a Kubernetes leaf was most likely to reach for. **That is the Phase 7.6A defect's
exact shape.** The guard now *computes* the property: any `internal/adapter/...` package whose
production sources call `security.Reveal` is out of reach, whatever it is called.
`TestTheSecretOpeningPackageGuardIsLive` proves the predicate sees the Kubernetes client and does
not see its sibling. A `depguard` entry was added in the same change for the lint-time message.

The leaf needs no such import: `app.KubernetesTarget` is a type alias, which 12.1B introduced
saying *"the leaf command a later phase adds then needs no import of the adapter at all"*.

---

## 14. What did not change, deliberately

**The four finding contracts.** `KUBERNETES_SERVICE_NOT_FOUND`, `KUBERNETES_API_ACCESS_DENIED`,
`KUBERNETES_SERVICE_SELECTS_NO_PODS`, `KUBERNETES_SERVICE_NO_READY_ENDPOINT` — 4 codes, 2 rules,
no fifth, no new failure class, no relation producer, no planner, no convergence change, no
failure-boundary change, no recommendation change, and no `Summary`/`Detail` edit for
presentation.

**F3/F4 stay DISJOINT.** F4 is withheld exactly when F3 was admitted, and the two never coexist.
No causal claim links them, in either direction. The CLI has no authority over diagnosis
semantics and exercised none.

**A `401` is a CONTRACT-CONFORMANT KNOWN LIMITATION**, not an ADR deviation: ADR 0094 §10.4
refuses it a Kubernetes code deliberately, `DIAG_FAILURE_BOUNDARY` localizes it, that boundary is
INFO, and such a run exits 0. Unchanged by this phase and pinned at the new entry point.

**No compatibility claim.** `docs/COMPATIBILITY.md` is unchanged and grades **no** Kubernetes
distribution or version. The README says so in the Kubernetes section and again under *Not
implemented*, and no docs-claim guard was weakened. Real-cluster grading is Phase 12.1D's.

---

## 15. Testing

### 15.1 Unit and integration

`internal/cli/kubernetes_test.go` — the ten-flag surface in both directions with a separate count,
the refused surface over 60 names, routing including three misspellings and three wrong shapes,
the three defaults, budget unreachability, eight delegated target rules asserted by the adapter's
own wording, source exclusivity, the in-cluster credential refusals, the four empty-source inputs,
credential binding, kubeconfig ambiguity, the two structural boundaries, and the secret-helper
regression in both directions.

`internal/cli/kubernetesproperties_test.go` — KP01 order independence, KP02 the closed surface
over 800+ generated names with a non-vacuity floor, KP03 eleven invalid invocations that must
start no run, KP04 hostile operator-supplied names.

`test/fleet/kubernetesleaf_test.go` — five authentication paths, the exec release gate, the
21-row zero-request matrix, all four findings plus healthy and 401, five-scenario entry-point
equivalence, token non-observability in three modes, hostile prose on three statuses in three
modes, and the output-flag assertions.

### 15.2 Fuzz

`FuzzTheKubernetesTargetNamesAreNeverEchoed`, 180 s, **1,755,446 executions, 0 crashes**, 45 new
interesting inputs.

**The fuzzer found a defect in its own target, in under a second, and the fix is stronger.** The
first version asserted that every input is refused; seed `"payments-api"` is a perfectly good name,
so the run started and the seam fired. The property is really a **dichotomy** — refused ⇒ exit 2
with nothing on stdout and a diagnostic that is valid UTF-8 with no control character; accepted ⇒
the name reaches the target **byte for byte**, because `checkName` refuses a name it cannot use
rather than repairing one. The old form could not have caught a mangled-but-accepted name at all.

### 15.3 Mutation

**28 planted / 28 caught / 0 survivors**, tree restored byte-for-byte
(`scripts/phase121c2-mutations.sh`).

**The first run caught 24 of 28, and not one of the four survivors was an equivalent mutation.**
Each was a real gap, and two of them share a shape worth remembering.

- **KL-M02, a `k8s` alias.** The routing test drove `diagnose k8s` and expected exit 2 — which it
  gets *either way*, because the alias would route to a command whose target flags are missing.
  The test passed for the wrong reason. It now asserts the **reason**: an unrouted service is
  reported as `unknown service`.
- **KL-M24, the file message hard-coding `--password-file`.** No test covered the token-file
  *error* messages, so the Kubernetes command could have told an operator to fix a flag it does not
  define. `TestTheKubernetesTokenFileMessagesNameTheKubernetesFlag` now covers a directory and a
  missing file, and asserts the path is named and `--password-file` is not.
- **KL-M27 and KL-M28, `--shareable` and `--output` ignored.** Both survived because
  `TestTheBearerTokenValueIsUnobservable` **compares two runs against each other**, and a bug
  affecting both runs identically is invisible to a comparison. The fix is a test of the absolute
  facts: JSON is JSON, text is not JSON, and shareable is redacted while local is not.

**And chasing KL-M27 found a defect in a test helper that had made two comparisons vacuous.**
`blankVarying` split on whitespace and replaced any field containing a digit that ended in `s` or
contained `T`. **A JSON report is one line**, so the whole document was one field and matched —
every JSON comparison in the file was comparing `"<varies>"` with `"<varies>"`. It now parses JSON
and normalizes structurally, and falls back to a narrow regexp for terminal output. The token
property passes on real documents, which it had never actually done before.

### 15.4 Historical suites

| Suite | Result |
|---|---|
| Phase 9.1A | 20 caught / 0 survivors |
| Phase 9.1B | 31 caught / 0 survivors |
| Phase 9.1C | 45 caught / 0 survivors |
| Phase 9.2B | **21 caught / 0 survivors**, after one anchor repair |
| Phase 9.3A | 10 caught / 0 survivors |
| Phase 12.1B | 41 caught / 0 survivors |
| Phase 12.1C | 42 caught / 0 survivors |

**One historical anchor was repaired and it is reported rather than absorbed.** Phase 9.2B's
`U11` plants a stale service count over the README's headline sentence, and that sentence
legitimately changed from *"Four services are supported"* to *"Five"*. The mutation became
unplantable. **The guarded property is unchanged** — a stale headline count survives `make check`
unless a guard reads it — so the anchor was re-pointed and the planted text is still the exact
stale claim Phase 9.2A found in the wild. The mutation is caught.

Not re-run: the Kafka, PostgreSQL, Redis and RabbitMQ diagnosis suites (10.1A–10.8B). None of the
production code they guard was touched — no adapter, no rule, no domain type — and the one shared
file this phase edited, `internal/cli/secret.go`, is covered by Phase 9.2B and by the
four-command regression test above.

### 15.5 Race

`go test -race` over `internal/cli`, `internal/app`, `internal/adapter/kubernetes/...`,
`internal/diagnosis/kubernetes`, `internal/fleet/...`, `test/fleet`, `test/diagnosis` and
`test/security`: **zero data races**.

`internal/fleet/run` hit `go test`'s shared 10-minute default in the aggregate invocation and
emitted a goroutine dump. It is a **timeout, not a race** — the output contains no `DATA RACE`
anywhere — and the package passes under `-race` in 8.0 s on its own.

### 15.6 `make check`

Green on the clean intended tree, with no mutation planted, no sentinel left, no fuzz artifact and
no temporary kubeconfig: `go test ./...`, `go vet ./...`, `golangci-lint run ./...` at **0 issues**,
`CGO_ENABLED=0 go build ./...`. `git diff --check` clean.

---

## 16. Known limitations

1. **A `401`, an unreachable API server and a `5xx` all exit 0.** CONTRACT-CONFORMANT KNOWN
   LIMITATION, unchanged, pinned at both entry points. Closing it needs a fifth code under
   ADR 0094 §7. Phase 12.1D should weigh it against a real cluster.
2. **In-cluster mode is proven by its refusals, not by a run.** It needs a projected
   ServiceAccount, which is Phase 12.1D's. Every conflict — with `--kubeconfig`, `--context`,
   `--token-file`, `--token-stdin` — is covered, and the mode's own execution is not.
3. **No real-cluster validation and no compatibility grading.** Everything here is hermetic.
4. **The mode C test proves svcdoctor's half only.** The hermetic server requests no client
   certificate, so what is exercised is that mode C is selected, that the private key travels as a
   masked secret and that the run completes — not that a server accepted it.
5. **The fleet `kubernetes` target still accepts an inert `step_timeout:`.** A pre-existing Phase
   12.1B configuration-surface gap of the ADR 0060 shape, recorded in `PHASE121C1…§9.2` and owned
   by 12.1D. The leaf does not reproduce it: `--step-timeout` does not exist.

---

## 17. Next phase

**Phase 12.1D — deterministic real-cluster and release-quality Kubernetes validation closure.**
`kind` fixtures, the four finding scenarios plus the three Service-shape scenarios, the two-version
matrix, `docs/COMPATIBILITY.md` grading, in-cluster execution, and a decision on the `401` exit
code against a real cluster.
