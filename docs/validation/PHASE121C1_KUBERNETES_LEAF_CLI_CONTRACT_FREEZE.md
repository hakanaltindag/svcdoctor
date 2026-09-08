# Phase 12.1C.1 — Kubernetes leaf CLI contract freeze

- **Phase:** 12.1C.1 (contract freeze; **no production Go, no test, no dependency, no schema**)
- **Baseline:** `HEAD` = `origin/main` = `3444c3e`, with the uncommitted Phase 12.1C diagnosis
  implementation preserved and unmodified
- **Closes:** the single open blocker Phase 12.1C left — ADR 0094 §2.10 and §2.12 and
  `PHASE121A…§12.1`/`§14` (KAC-040) require `svcdoctor diagnose kubernetes`, and its public flag
  surface was not fully frozen
- **Decision:** **ten flags**, no eleventh. Nine are DERIVED or SHARED from contracts that already
  exist; one — `--token-file` — is EXPLICITLY_FROZEN by name. **Zero NEW_DECISION flags.**
  No acquisition budget is exposed. No `--step-timeout`. No TLS flag. No `--user`. No `--host`.
- **Implementation authorized:** yes, under §16's plan and §17's test obligations
- **Implemented:** Phase 12.1C.2, exactly as frozen — ten flags, no eleventh, zero deviations. See `docs/validation/PHASE121C2_KUBERNETES_LEAF_CLI_IMPLEMENTATION.md`

---

## 1. Why this record exists

Phase 12.1C implemented the two Kubernetes rules and the four findings, and did not implement the
leaf command the frozen contract assigns to that phase. The 12.1C closure pass re-read the frozen
sources and found the requirement real (ADR 0094 §2.12 lists *"the composition root, **the CLI
case** and the golden reports"*), and found the command unimplementable *exactly* because those
sources name **one** of its flags and leave the rest open.

This record answers that and only that. It adds no Kubernetes capability, no configuration field,
no authentication mode, no acquisition behaviour and no finding. Everything below either maps onto
something Phase 12.1B already froze, is inherited unchanged from the existing `diagnose <service>`
contract, or is named outright by an existing Kubernetes source.

**The question asked throughout was not *"what would be convenient"* but *"what is the smallest
public surface that expresses the already-frozen Kubernetes target contract"*.**

---

## 2. Source inventory

### 2.1 Kubernetes contracts

| Source | What was taken from it |
|---|---|
| **ADR 0094 §2.3** | four auth modes; kubeconfig explicit-path-only; context mandatory with kubeconfig and forbidden in-cluster; namespace mandatory and explicit; in-cluster explicit and never a fallback; proxy and impersonation refused |
| **ADR 0094 §2.4** | one target = one API authority + one namespace + one Service name; the forbidden target shapes |
| **ADR 0094 §2.5** | the five acquisition budgets, frozen as numbers |
| **ADR 0094 §2.10** | *"**No new top-level command.** `svcdoctor diagnose kubernetes …` is one `case` in the existing switch"*; **one Service is one target and one report through both entry points** |
| **ADR 0094 §2.12** · **`PHASE121A…§14`** (KAC-040) | the CLI case belongs to 12.1C |
| **`PHASE121A…§6.1`** | the auth-mode matrix, and the **only** flag any Kubernetes source names: mode A is *"explicit bearer token (via `env:` / `file:` credential reference, **or `--token-file`**)"* |
| **`PHASE121A…§6.3`–§6.8** | no `KUBECONFIG`, no `~/.kube/config`, no merge list, no `current-context`, no namespace default; in-cluster mutually exclusive; file authority; credential authority is the API server alone |
| **`PHASE121A…§12.1`** | *"`svcdoctor kubernetes …` is **refused**, per ADR 0041"*; `DefaultPort() 443`; **no `host` field** |
| **`PHASE120…§936`, §1076** | Service-only targets; no `--all-namespaces`, no selector, no workload target |
| **`PHASE121B…`** | the implemented shape this must map onto |

### 2.2 Generic CLI contracts

| Source | What was taken from it |
|---|---|
| **ADR 0041** | action-first `svcdoctor diagnose <service>`; each service owns its flag set, help and validation; service type never inferred |
| **ADR 0048** | the output/process boundary; `--output`, `--shareable`, the exit-code block in help |
| **ADR 0049** | *"A secret arrives by file **or by pipe**, and never by argument."* Two sources, mutually exclusive, **no precedence**, no prompt, no fallback, no literal, no environment variable. §3's read rules and the 4 KiB bound |
| **ADR 0060** | an inert-but-accepted flag is refused, not ignored — the rule this freeze applies to `--step-timeout` and to every TLS flag |
| **ADR 0062 §8** | *"Secrets: files and stdin, never the environment … The existing model is unchanged: `--password-file`, `--password-stdin`, mutually exclusive, no precedence, no prompt, no fallback"* — stated generically, in the containerized-Kubernetes record |
| **ADR 0072 §4, §12** | `env` is a **fleet** source *because* ADR 0049 §5 refused it *"for a leaf command"* (§4), and a change to leaf secret-file semantics *"is a change to ADR 0049 and must be argued there, for all four leaf commands as well"* (§12) — so ADR 0049 binds the leaf group, not PostgreSQL alone |
| **ADR 0073** | the three nested budgets; per-target timeout via the context |

### 2.3 Code read

`internal/cli/root.go` · `internal/cli/rabbitmq.go` · `redis.go` · `postgres.go` · `kafka.go` ·
`usage.go` · `secret.go` · `tls.go` · `exit.go` · `internal/cli/fleetregression_test.go` ·
`helpgolden_test.go` · `docsclaims_test.go` · `docstructure_test.go` ·
`internal/fleet/services/kubernetes/kubernetes.go` · `internal/fleet/config/{schema,load,registry}.go` ·
`internal/fleet/run/execute.go` · `internal/fleet/secret/secret.go` ·
`internal/adapter/kubernetes/client/{target,authority,kubeconfig,budgets}.go` ·
`internal/app/kubernetes.go` · `internal/security/credential.go`

---

## 3. The existing leaf CLI architecture, and what a fifth command inherits

Every leaf command has the same six-part shape, and none of it is service-specific:

```
parse<Service>(args)  →  flag.FlagSet, ContinueOnError, output discarded, Usage suppressed
                         validation → usagef(...) → exit 2
                         a.readSecret(credentialSources)
                         credentialFor(host, port, role, secret)
diagnose<Service>Command(ctx, args)
                         context.WithTimeout(ctx, command.timeout)
                         app.Diagnose<Service>(runCtx, params)
                         ExitCode(result, runErr)
                         project(result.Report(), command.shareable)
                         a.render(command.output, render.Input{...})
```

A fifth command reuses all of it. **Nothing in the list above is duplicated, forked or
parameterized by service** except the flag set, the help text and the params struct — which is
exactly the split ADR 0041 froze.

Three package-level surfaces move when a fifth command lands, and each is a **test** surface
rather than a product one: `helpSurfaces` (seven → eight), `leafFlagSurface` (four entries →
five), and `docstructure_test.go`'s *"Four services are registered and five commands are
exposed"* sentence. They are enumerated in §16.

---

## 4. The frozen Kubernetes configuration model this must map onto

Phase 12.1B froze `internal/fleet/services/kubernetes.Config` at **five fields, with the comment
that there is deliberately no sixth**, and `client.Target` mirrors it exactly:

```
kubeconfig      string   Config.Kubeconfig      client.Target.Kubeconfig
context         string   Config.Context         client.Target.Context
in_cluster      bool     Config.InCluster       client.Target.InCluster
namespace       string   Config.Namespace       client.Target.Namespace
service_name    string   Config.ServiceName     client.Target.ServiceName
```

Plus one credential, carried outside the target: a **bearer token**, resolved under the existing
secret discipline and bound to the derived API endpoint. `internal/adapter/kubernetes/client/
kubeconfig.go`'s `case credentialSupplied:` already documents both callers —

> *"The bearer token the target's own credential reference names. The value is resolved by the
> fleet resolver **or by the leaf command**, under the existing secret discipline, and arrives here
> already bound to this endpoint."*

— so the leaf command was anticipated by the implementation and needs no new plumbing.

**The CLI creates no second configuration model.** It fills `client.Target` and one
`security.Credential`, and that is the whole of its input surface.

Two things the fleet Kubernetes target **refuses**, which the leaf therefore must not offer:

- **the entire `tls:` block** — `checkInertTLS` refuses `tls.mode: disable`, `tls.ca_file`,
  `tls.server_name` and `tls.insecure`, because the API server's trust material comes from the
  kubeconfig's `certificate-authority` or the projected ServiceAccount CA, and svcdoctor will not
  present a credential over a channel it cannot verify;
- **`credentials.username`** — `checkInertIdentity` refuses it, because *"a bearer token and a
  client certificate each **are** the identity, and the API server decides who they name."*

---

## 5. The public flag surface, frozen

```
svcdoctor diagnose kubernetes --kubeconfig <path> --context <name> \
                              --namespace <ns> --service-name <name> [flags]

svcdoctor diagnose kubernetes --in-cluster \
                              --namespace <ns> --service-name <name> [flags]
```

**Ten flags. There is no eleventh.**

| # | Flag | Type | Required | Default | Class | Source citation |
|---|---|---|---|---|---|---|
| 1 | `--kubeconfig` | string | XOR with `--in-cluster` | `""` | **DERIVED** | `Config.Kubeconfig`; ADR 0094 §2.3, `PHASE121A…§6.3` |
| 2 | `--context` | string | **required** with `--kubeconfig`, **forbidden** with `--in-cluster` | `""` | **DERIVED** | `Config.Context`; ADR 0094 §2.3 |
| 3 | `--in-cluster` | bool | XOR with `--kubeconfig` | `false` | **DERIVED** | `Config.InCluster`; ADR 0094 §2.3, `PHASE121A…§6.4` |
| 4 | `--namespace` | string | **always** | `""` | **DERIVED** | `Config.Namespace`; ADR 0094 §2.3 |
| 5 | `--service-name` | string | **always** | `""` | **DERIVED** | `Config.ServiceName`; ADR 0094 §2.4 |
| 6 | `--token-file` | string | optional | `""` | **EXPLICITLY_FROZEN** | `PHASE121A…§6.1` mode A, by name |
| 7 | `--token-stdin` | bool | optional | `false` | **DERIVED** | ADR 0049 §2/§4's pair, applied to the noun `PHASE121A…§6.1` froze. §7 |
| 8 | `--timeout` | duration | optional | `30s` | **SHARED** | ADR 0073; `config.DefaultTargetTimeout`; every leaf command |
| 9 | `--output` | string | optional | `"text"` | **SHARED** | ADR 0048 |
| 10 | `--shareable` | bool | optional | `false` | **SHARED** | ADR 0018, ADR 0048 |

Per-flag detail:

| Flag | Validation | Conflicts | Maps to | Secret | Persisted | In report |
|---|---|---|---|---|---|---|
| `--kubeconfig` | path existence, parse, and every refused construct: **`client.Inspect`** | `--in-cluster` | `client.Target.Kubeconfig` | no | no | **no** — `PHASE121A…§6.7`: first scope records no filesystem path in evidence |
| `--context` | presence and existence in the file: `Target.Validate` then `client.Inspect` | `--in-cluster` | `client.Target.Context` | no | no | **yes** — `Authority.Context`; ADR 0094 §2.9 makes the context name a report-visible authority fact |
| `--in-cluster` | `Target.Validate` | `--kubeconfig`, `--context`, `--token-file`, `--token-stdin` | `client.Target.InCluster` | no | no | yes, as the auth-mode category `IN_CLUSTER` |
| `--namespace` | `Target.Validate` → `checkName` (non-empty, ≤ bound, valid UTF-8, no control/space, no `/` or `%`) | none | `client.Target.Namespace` | no | no | yes, `AttrKindIdentity`, pseudonymized when shareable |
| `--service-name` | as `--namespace` | none | `client.Target.ServiceName` | no | no | yes, `AttrKindIdentity`, pseudonymized when shareable |
| `--token-file` | `secretinput.ReadFile` — whole file, one trailing line ending trimmed, 4 KiB bound, directory named as one; **empty is a usage error**, §7.3 | `--token-stdin`, `--in-cluster`, and any credential in the selected kubeconfig user | `security.Credential` bound to the derived API endpoint, identity `""` | **yes** | never | **never** |
| `--token-stdin` | `secretinput.Read` — same bound, same trim, no prompt, no echo; **empty is a usage error** | as `--token-file` | as `--token-file` | **yes** | never | **never** |
| `--timeout` | `> 0` | none | `context.WithTimeout` around `app.DiagnoseKubernetes` | no | no | as run duration |
| `--output` | `"text"` or `"json"` | none | `a.render` | no | no | n/a |
| `--shareable` | none | none | `project(report, true)` | no | no | `SHAREABLE_REDACTED` mode |

**Auth-mode reachability of each flag:**

| Flag | Mode A token | Mode B kubeconfig `tokenFile` | Mode C client cert+key | Mode D in-cluster |
|---|---|---|---|---|
| `--kubeconfig` | **required** | **required** | **required** | forbidden |
| `--context` | **required** | **required** | **required** | forbidden |
| `--in-cluster` | forbidden | forbidden | forbidden | **required** |
| `--namespace` | required | required | required | required |
| `--service-name` | required | required | required | required |
| `--token-file` / `--token-stdin` | **one of the two** | forbidden (ambiguity) | forbidden (ambiguity) | forbidden |
| `--timeout` `--output` `--shareable` | allowed | allowed | allowed | allowed |

---

## 6. Authentication — which modes need a flag, and which do not

The frozen modes are `PHASE121A…§6.1`'s A, B, C and D. **Supporting a mode internally is not the
same as needing a dedicated CLI flag for it**, and three of the four are carried by material the
target already names.

| Mode | Reached from the leaf CLI by | New flag? |
|---|---|---|
| **A** explicit bearer token | `--token-file` or `--token-stdin` → `security.Secret` → `credentialFor(apiHost, apiPort, "", secret)` → `KubernetesParams.Credential` | **`--token-file` (frozen by name) + `--token-stdin`** |
| **B** kubeconfig `tokenFile` | `--kubeconfig` + `--context`. svcdoctor reads the file named *inside the kubeconfig*; `rest.Config.BearerTokenFile` is never set | **none** |
| **C** client certificate + key | `--kubeconfig` + `--context`. `client-certificate[-data]` and `client-key[-data]` live in the kubeconfig user | **none** |
| **D** in-cluster ServiceAccount | `--in-cluster`. The projected token and CA are at the standard paths | **`--in-cluster`** |

**Modes B and C need no flag, and adding one would be a contract violation rather than a
convenience.** `Config` has **five fields and deliberately no sixth**; there is no certificate
field, no key field and no kubeconfig-token-path field to map a flag onto. A `--client-cert` /
`--client-key` pair would be a **second Kubernetes configuration model** — precisely what §3 of
this pass forbids — and would let a leaf invocation express an identity a `run --config` target
cannot, breaking ADR 0094 §2.10's *"one Service is one target and one report through both entry
points"*.

**`--token` (a literal value) is refused permanently.** ADR 0049 §5: a secret in `argv` lands in
shell history and the process table. A bearer token is exactly the material that rule exists for.

---

## 7. The stdin token decision

**REQUIRED.** Symmetry with the other four commands is *not* the reason; three sources are.

1. **ADR 0049 decides the pair, and states it about a secret rather than about a password.** Its
   title is *"A secret arrives by file **or by pipe**, and never by argument"* and §2's decision is
   the two sources together, mutually exclusive, with no precedence. A bearer token is a
   `security.Secret` read through `internal/security/secretinput` under the same 4 KiB bound and
   the same one-trailing-newline rule; nothing distinguishes it from the material §2 governs.
2. **ADR 0072 §4 and §12 establish that ADR 0049 binds the leaf group.** §4: `env` is a fleet
   source *"because ADR 0049 §5 rejected environment variables as a credential source **for a leaf
   command**"*. §12: a change to leaf secret-file semantics *"is a change to ADR 0049 and must be
   argued there, **for all four leaf commands as well**"*. §5's refusals cannot be leaf-generic
   while §2's admissions are PostgreSQL-only.
3. **ADR 0062 §8 restates the pair as the model, in the containerized-Kubernetes record.** *"The
   existing model is unchanged: `--password-file`, `--password-stdin`, mutually exclusive, no
   precedence, no prompt, no fallback."*

**The consequence of refusing it is the actual argument.** ADR 0049 §5 already refuses a literal,
an environment variable, a prompt, a DSN and every secret manager. If stdin were also refused,
`--token-file` would be the **sole** channel, and an operator holding a token in a CI variable
would have to write it to disk — a capability removal, relative to every other service, that no
source decided.

### 7.1 The names are `--token-*`, not `--password-*`

`PHASE121A…§6.1` names `--token-file`. A Kubernetes credential is a bearer token: `checkInertIdentity`
already refuses a username on the grounds that *"a bearer token and a client certificate each **are**
the identity"*, and basic authentication is mode **H — REFUSE**. Calling the flag `--password-file`
would name the one authentication mode svcdoctor refuses.

`--token-stdin` is therefore **DERIVED**, not a new decision: the *pair* is ADR 0049's frozen
contract and the *noun* is `PHASE121A…§6.1`'s.

### 7.2 Exclusivity

`--token-file` and `--token-stdin` are **mutually exclusive with no precedence**, exit 2. ADR 0049
§2 verbatim: *"Refusing ambiguity is stronger than resolving it."*

### 7.3 An empty token source is a usage error — and this is where Kubernetes differs

> **Frozen: `--token-file` or `--token-stdin` that resolves to empty is exit 2, not a
> credential-free run.**

This differs from the other four leaf commands, where an empty source yields no credential and the
run proceeds to a truthful `*_CREDENTIAL_NOT_CONFIGURED` finding at exit 0. Two reasons, both
structural:

1. **`credentialSupplied` is decided before the value is read.** `client.Inspect(target,
   credentialSupplied)` selects `AuthModeToken` and refuses any competing kubeconfig credential on
   the strength of the *declaration*. A declared-but-empty token would leave `Inspect` having
   chosen a mode for which no credential exists — the ambiguity `resolveKubeconfigMode` refuses,
   arrived at from the other side.
2. **Kubernetes has no credential-not-configured finding**, and cannot gain one: the four-code
   budget is frozen (ADR 0094 §2.7). Silently degrading to a credential-free run is therefore not
   reportable, so it must not happen.

**Source:** `internal/fleet/secret/secret.go:214` already applies exactly this rule to the same
auth mode — a declared reference that *"resolved to an empty credential"* is refused — so the leaf
adopts the fleet's rule for this service rather than the leaf default. Classified **DERIVED**.

---

## 8. In-cluster, frozen

`--in-cluster` selects mode D and nothing else. **There is no implicit detection and no fallback**:
`KUBERNETES_SERVICE_HOST` is not read at decode, a mounted ServiceAccount token never causes
svcdoctor to acquire an identity nobody asked for, and a kubeconfig failure never degrades into it.

| With `--in-cluster` | Verdict | Where refused | Source |
|---|---|---|---|
| `--kubeconfig` | **forbidden** | `Target.Validate` | *"a run authenticates as the pod's ServiceAccount or as a kubeconfig identity, never as whichever of the two happens to resolve first"* |
| `--context` | **forbidden** | `Target.Validate` | *"a context names a kubeconfig entry and has no meaning in-cluster"* |
| `--token-file` / `--token-stdin` | **forbidden** | `client.Inspect` | *"in-cluster mode authenticates as the pod's ServiceAccount, so a target credential would be a second identity nobody asked for"* |
| certificate inputs | **do not exist** | — | §6 |
| `--namespace` | **required** | `Target.Validate` → `checkName` | never defaulted, never taken from a context |
| `--service-name` | **required** | `Target.Validate` → `checkName` | mandatory and explicit |

Neither `--kubeconfig` nor `--in-cluster` given is **exit 2**: *"a kubeconfig path or in-cluster
mode is required; svcdoctor consults no KUBECONFIG variable and no default kubeconfig location."*

---

## 9. Execution budget, output, and what is deliberately absent

### 9.1 `--timeout` — SHARED, admitted

It bounds the whole run through `context.WithTimeout`, which is exactly how the fleet bounds a
Kubernetes target: `internal/fleet/run/execute.go:198` applies `target.Timeout` to the context and
`app.KubernetesParams` carries no timeout field at all. Service-independent, and it needs no
Kubernetes interpretation. Default `30s`, matching `config.DefaultTargetTimeout`.

### 9.2 `--step-timeout` — REFUSED, and not for symmetry reasons

**There is no Kubernetes step-timeout concept to expose.** `app.KubernetesParams` has no such
field; `internal/fleet/services/kubernetes.Run` passes none; and a grep of `.StepTimeout` shows the
other four services threading it into `probe/transport` and their adapters while Kubernetes appears
nowhere. Acquisition sequences three requests under one context deadline.

A `--step-timeout` on this command would therefore be **accepted and inert**, which ADR 0060 makes
a refusal rather than a documented no-op: *"a flag that is accepted and ignored is
indistinguishable, at the call site, from a flag that is accepted and honoured."* It is not
defined, so `flag` refuses it as unknown — exit 2, no custom handling.

> **Noted, and owned elsewhere.** The *fleet* surface has the inverse gap today: a `kubernetes`
> target may set `step_timeout:` and it is resolved, stored on `config.Target` and never read.
> `internal/fleet/services/kubernetes.Decode` refuses an inert `tls:` block and an inert
> `credentials.username` but does not refuse this. That is a **pre-existing Phase 12.1B defect in
> the fleet configuration surface**, not a leaf-CLI decision, and it is recorded for Phase 12.1D.
> The leaf command must not reproduce it.

### 9.3 Acquisition budget flags — NONE

`client.Budgets`'s five values — `PageSize 500`, `MaxPages 8`, `MaxPods 4000`, `MaxSlices 256`,
`MaxEndpoints 10000` — and `MaxRequests 17` are frozen by ADR 0094 §2.5 and pinned individually by
`TestDefaultBudgetsAreTheFrozenNumbers`. **No entry point sets them**: the fleet passes the zero
`Budgets` and receives `DefaultBudgets`.

Three reasons they stay constants, in increasing order of importance:

1. Exposing them would make the two entry points disagree, against ADR 0094 §2.10.
2. It would create the second configuration model §4 forbids.
3. **A budget is a completeness input, and completeness is a finding precondition.** Lowering
   `--max-pods` below a Service's Pod count makes the set INCOMPLETE, and both F3 and F4 require a
   complete enumeration — so a budget flag would let an invocation *silently suppress a finding*.
   Internal safety limits are not knobs.

### 9.4 `--output` and `--shareable` — SHARED, admitted unchanged

`--output` takes `"text"` or `"json"` and nothing else; `--shareable` produces the
`SHAREABLE_REDACTED` report through the existing `project`. Both are service-independent: they act
on `domain.Report`, and ADR 0094 §12.3 already established that **no renderer change is needed**,
because a Kubernetes report is a single-path journey the terminal renderer expresses today.

**No Kubernetes-specific output mode exists.** `--pods`, `--endpoints`, `--wide`, `--raw`,
`--yaml-objects`, `--events` and `--logs` are refused permanently: there is no per-Pod and no
per-endpoint evidence node to render (ADR 0094 §2.9), so each would be a flag with nothing behind
it — and `--yaml-objects` and `--logs` would additionally publish material ADR 0094 §11.2 refuses
to collect at all.

---

## 10. Refused surface

**Refusal here mostly means "does not exist".** An undefined flag is reported by `flag` as
*"flag provided but not defined"* and mapped to exit 2 by the existing parse path. No custom
runtime handling is written for any row below unless the column says so.

| Flag | Verdict | Why | Handling |
|---|---|---|---|
| `--host` | **does not exist** | a Kubernetes target names a Service, not an endpoint; the API server host is **derived** (ADR 0094 §2.10, `PHASE121A…§12.1`) | undefined |
| `--port` | **does not exist** | as `--host`; `DefaultPort() 443` is the scheme's default and is never dialled as an override | undefined |
| `--server`, `--api-server` | **does not exist** | *"server / cluster override: **none.** The context selects the cluster"* (`PHASE121A…§6.3`) | undefined |
| `--user`, `--username` | **does not exist** | a bearer token and a client certificate each *are* the identity; the fleet already refuses `credentials.username` | undefined |
| `--password`, `--password-file`, `--password-stdin` | **does not exist** | basic auth is mode **H — REFUSE**; the credential is a token, and §7.1 names the flags accordingly | undefined |
| `--token` (literal) | **refused permanently** | ADR 0049 §5: shell history and the process table | undefined |
| `--tls`, `--tls-ca-file`, `--tls-server-name` | **does not exist** | trust material comes from the kubeconfig `certificate-authority` or the projected CA; a second answer to one question | undefined |
| `--insecure`, `--tls-insecure`, `--insecure-skip-tls-verify` | **refused permanently** | svcdoctor presents a credential to the API server and will not do so over a channel it cannot verify. Refused in **every** mode — no `--insecure` opt-in exists for Kubernetes | undefined at the CLI; **also refused inside the kubeconfig** by `client.Inspect`, before any network operation |
| `--impersonate`, `--as`, `--as-group` | **refused permanently** | ADR 0094 §2.3: unauditable, and the minimum Role deliberately requests no `impersonate` grant | undefined at the CLI; kubeconfig `as`/`as-groups`/`as-uid` refused by `client.Inspect` |
| `--proxy-url` | **refused permanently** | a proxy changes vantage, and ADR 0092 §2.4 scopes a claim to the position it was measured from | undefined at the CLI; kubeconfig `proxy-url` refused by `client.Inspect`; ambient `HTTP_PROXY` neutralized by an explicit direct dial |
| `--exec`, `--auth-provider`, `--allow-exec-auth` | **refused permanently** | ADR 0094 §2.2 — *"No `--allow-exec-auth` flag is created, named or reserved"* | undefined; kubeconfig constructs refused before any request, with the sentinel test as a release gate |
| `--all-namespaces`, `--namespace-pattern`, `--service-pattern`, `--selector` | **does not exist** | ADR 0094 §2.4 forbids a scan, a wildcard, a regexp, a selector target and multiple Services | undefined |
| `--pod`, `--deployment` | **does not exist** | no workload and no Pod target; no per-Pod evidence node | undefined |
| `--events`, `--logs`, `--metrics`, `--network-policy`, `--probe-endpoints` | **does not exist** | outside MVP-D entirely; `--probe-endpoints` would additionally break the credential-authority rule — svcdoctor connects to no Pod, no ClusterIP and no endpoint address | undefined |
| `--config`, `--target`, `--concurrency` | **does not exist** | `TestNoLeafCommandGainedAConfigurationFlag` — one invocation never names both one target and a file of many | undefined; the existing test extends to cover it |
| `--step-timeout` | **does not exist** | §9.2 | undefined |
| budget flags (`--page-size`, `--max-pods`, …) | **does not exist** | §9.3 | undefined |
| another service's own flags — `--database`, `--sasl-mechanism`, `--vhost` | **does not exist** | ADR 0041: each service owns its flag set, and service type is never inferred | undefined |

---

## 11. Valid invocations

No secret value appears in any form below.

**A — mode A, explicit bearer token from a file**

```sh
svcdoctor diagnose kubernetes \
  --kubeconfig /etc/svcdoctor/kubeconfig.yaml \
  --context prod-eu \
  --namespace payments \
  --service-name checkout \
  --token-file /run/secrets/k8s-token
```

**A′ — mode A, bearer token from a pipe**

```sh
printf '%s' "$K8S_TOKEN" | svcdoctor diagnose kubernetes \
  --kubeconfig /etc/svcdoctor/kubeconfig.yaml \
  --context prod-eu \
  --namespace payments \
  --service-name checkout \
  --token-stdin
```

**B — mode B, a `tokenFile` the kubeconfig names (svcdoctor reads it, not client-go)**

```sh
svcdoctor diagnose kubernetes \
  --kubeconfig /etc/svcdoctor/kubeconfig.yaml \
  --context prod-eu \
  --namespace payments \
  --service-name checkout
```

**C — mode C, client certificate and key inside the kubeconfig** — byte-identical invocation to B.
Which mode was selected is read from the kubeconfig user and reported as the auth-mode category;
it is not a command-line choice, and there is deliberately no flag that could disagree with the
file.

**D — mode D, in-cluster ServiceAccount, JSON to a CI job**

```sh
svcdoctor diagnose kubernetes \
  --in-cluster \
  --namespace payments \
  --service-name checkout \
  --output json --timeout 20s
```

---

## 12. Invalid invocations, and where each is decided

**No check is duplicated.** The CLI validates only what is decidable from the flags alone; every
target-shape question is answered once, by `client.Target.Validate` reached through
`app.InspectKubernetesTarget`; every file question is answered once, by `client.Inspect`.

| Invocation | Exit | Decided at | Message source |
|---|---|---|---|
| unknown flag | 2 | **CLI parse** (`flag`) | *"flag provided but not defined"* |
| `--output yaml` | 2 | **CLI parse** | `checkOutput` |
| `--timeout 0` / negative | 2 | **CLI parse** | `usagef` |
| `--token-file` **and** `--token-stdin` | 2 | **CLI parse** | `credentialSources.validate`, ADR 0049 §2 |
| `--token-file` naming a directory, an unreadable file, or one above 4 KiB | 2 | **CLI parse** | `secretinput` + `readSecretFile` wording |
| `--token-file` / `--token-stdin` resolving to **empty** | 2 | **CLI parse** | §7.3 |
| positional argument | 2 | **CLI parse** | `fs.NArg() > 0` |
| `--kubeconfig` **and** `--in-cluster` | 2 | **`Target.Validate`** | *"…never as whichever of the two happens to resolve first"* |
| `--context` **and** `--in-cluster` | 2 | **`Target.Validate`** | *"a context names a kubeconfig entry and has no meaning in-cluster"* |
| neither `--kubeconfig` nor `--in-cluster` (implicit-kubeconfig attempt) | 2 | **`Target.Validate`** | *"svcdoctor consults no KUBECONFIG variable and no default kubeconfig location"* |
| `--kubeconfig` without `--context` (`current-context` reliance) | 2 | **`Target.Validate`** | *"the file's current-context is never used"* |
| no `--namespace` | 2 | **`Target.Validate` → `checkName`** | *"a namespace is required and is never defaulted"* |
| no `--service-name` | 2 | **`Target.Validate` → `checkName`** | *"a service name is required and is never defaulted"* |
| namespace or service name with a control character, a space, `/` or `%`, or above the byte bound | 2 | **`Target.Validate` → `checkName`** | refused rather than escaped |
| `--in-cluster` with `--token-file` or `--token-stdin` | 2 | **`client.Inspect`** | *"…a target credential would be a second identity nobody asked for"* |
| kubeconfig missing, unparseable, or naming no such context | 2 | **`client.Inspect`** | existing wording |
| a token supplied **and** the selected kubeconfig user carries a token, `tokenFile` or client cert | 2 | **`resolveKubeconfigMode`** | *"…svcdoctor refuses the ambiguity rather than choosing one"* |
| kubeconfig with `exec` | 2 | **`client.Inspect`**, before any network operation | sentinel test is a release gate |
| kubeconfig with `auth-provider` | 2 | **`client.Inspect`** | plus: no auth-provider package is linked at all |
| kubeconfig with `insecure-skip-tls-verify` | 2 | **`client.Inspect`** | refused in every mode |
| kubeconfig with `proxy-url` | 2 | **`client.Inspect`** | vantage |
| kubeconfig with impersonation | 2 | **`client.Inspect`** | unauditable |
| kubeconfig with basic auth | 2 | **`client.Inspect`** | mode H |

Every row above exits **2 with nothing dialled and no report** — which is the whole reason
`Inspect` performs no I/O beyond reading the declared file (ADR 0094 §2.12; the 12.1B narrowing
that made a kubeconfig refusal a configuration error rather than one target's execution failure).

---

## 13. Secret safety

The freeze **weakens nothing** in Phase 12.1B's credential authority.

- **No secret in `argv`.** There is no `--token` value flag; ADR 0049 §5, permanent.
- **No environment secret.** No flag reads one, and production code contains zero `os.Getenv` call
  sites outside the fleet resolver (ADR 0062 §8).
- **No prompt, no echo.** `--token-stdin` reads once to EOF; ADR 0049 §4.
- **The path may be named in an error; the contents and their length never are** (ADR 0049 §3).
- **The CLI calls no `security.Reveal`** — `forbidigo` fails the build if it does, and the single
  Kubernetes `Reveal` site stays in `internal/adapter/kubernetes/client`. **`Reveal` and
  `SecretFor` stay at 5 / 5.**
- **The credential binds to the derived API server endpoint and to nothing else** (ADR 0028 via
  `security.Endpoint`). `credentialFor(apiHost, apiPort, "", secret)` uses the pair
  `InspectKubernetesTarget` returned, exactly as the fleet does; **nothing rebinds it**, and the
  composition root checks the binding rather than trusting it.
- **The identity is `""`.** A Kubernetes credential carries no username.
- **No secret in** stdout, stderr, canonical JSON, Markdown, terminal, an error, a panic, an
  `Evidence` node, an `EvidenceID`, a `Finding` or a recommendation. `security.Secret` masks
  `String`, `GoString`, `Format`, `MarshalJSON` and `MarshalText`, so the common accidents are safe
  by construction.
- **Help text and every documented example use a file or a pipe**, never a literal.

---

## 14. CLI → app mapping, frozen

```
internal/cli/root.go            case "kubernetes": a.diagnoseKubernetesCommand(ctx, args[1:])
        │
internal/cli/kubernetes.go      parseKubernetes(args)
        │                         → client.Target{Kubeconfig, Context, InCluster, Namespace, ServiceName}
        │                         → app.InspectKubernetesTarget(target, credentialSupplied) → (host, port)
        │                         → a.readSecret(tokenSources)      [existing internal/cli/secret.go]
        │                         → credentialFor(host, port, "", secret)
        │
        │                       context.WithTimeout(ctx, command.timeout)
        ▼
internal/app/kubernetes.go      app.DiagnoseKubernetes(runCtx, KubernetesParams{
                                    Target, Credential, Vantage, Version})   ← UNCHANGED
        ▼
internal/adapter/kubernetes/client  Inspect → Connect → Acquire               ← UNCHANGED
        ▼
internal/adapter/kubernetes         five evidence nodes                       ← UNCHANGED
        ▼
internal/diagnosis/kubernetes       two rules, four codes, + FailureBoundary  ← UNCHANGED
        ▼
domain.Report → project(·, shareable) → render → ExitCode                     ← UNCHANGED
```

**`Budgets` is left zero**, which yields `DefaultBudgets` — the fleet's behaviour exactly, so the
two entry points are byte-comparable.

Explicitly not permitted by this freeze: a second Kubernetes execution path, a second configuration
model, any diagnosis in `internal/cli`, any Kubernetes branch in a generic package, any
Kubernetes import of `k8s.io` outside `internal/adapter/kubernetes/client`, and any renderer
change.

---

## 15. Compatibility wording

**A command existing is not a compatibility grade.** Phase 12.1D owns grading, and this freeze and
its implementing commit change `docs/COMPATIBILITY.md` by **zero lines**.

Wording that may be used:

> `svcdoctor diagnose kubernetes` reads one Service's backend publication through the Kubernetes
> API. **No Kubernetes distribution or version is graded in `docs/COMPATIBILITY.md`**; real-cluster
> validation is Phase 12.1D's.

Wording that may **not** be used, in the README, the release notes or `docs/COMPATIBILITY.md`:

- *"supports Kubernetes 1.2x"* · *"works with kind"* · *"EKS/GKE/AKS supported"* · *"certified
  for …"* · any Level 1/2/3 row for any distribution
- anything implying the command reports Service, workload or cluster **health** — it reports what
  the API publishes

Two guards constrain this and **neither is weakened**: `TestOnlyRealTestedPlatformsClaimLevelTwoOrThree`
would fail on any Kubernetes Level 2/3 row, and `TestNoDocumentClaimsHealthTheProductCannotObserve`
on a health claim. `TestNoDocumentClaimsAnUnimplementedMechanism`'s list contains no Kubernetes
mechanism, so the exec/auth-provider refusals may be described freely. **The guards scan
`README.md`, `docs/COMPATIBILITY.md` and the release notes — not help text** — so the help may
describe the refusals plainly, and the README must stay in the wording above.

**Narrow consequence for the next phase:** EKS, GKE and AKS remain gated by ADR 0094 §2.2's exec
refusal regardless of grading, and `docs/COMPATIBILITY.md` must say so when it first gains a
Kubernetes section in 12.1D.

---

## 16. Implementation plan

Ten steps, one commit, no phase of its own.

1. **`internal/cli/kubernetes.go`** — `kubernetesCommand`, `parseKubernetes`,
   `diagnoseKubernetesCommand`. A sibling of `rabbitmq.go`, ~200 lines, no new helper package.
2. **`internal/cli/secret.go`** — thread the flag-name pair through `credentialSources` and
   `readSecretFile` so a message can say `--token-file`. **Every existing message must stay
   byte-identical**; this is a parameterization, not a rewrite.
3. **`internal/cli/root.go`** — one `case "kubernetes":` in the existing switch.
4. **`internal/cli/usage.go`** — `usageKubernetes`, plus one line in `usageDiagnose` and, if it
   lists services, `usageRoot`.
5. **Help goldens** — new `testdata/help/kubernetes.txt`; regenerate `diagnose.txt` and `root.txt`
   with `-update` and **read the diff**.
6. **`helpgolden_test.go`** — `helpSurfaces` seven → eight; the *"Seven, and the list is asserted
   complete"* comment becomes eight.
7. **`fleetregression_test.go`** — a fifth `leafFlagSurface` entry; *"The four leaf command
   surfaces are frozen"* becomes five.
8. **`docstructure_test.go`** — *"Four services are registered and five commands are exposed"*
   becomes five services and six commands.
9. **`docs/`** — README (§15's wording), `docs/QUICKSTART.md` if it enumerates commands,
   `docs/CONFIGURATION.md`'s *"The four leaf `diagnose` commands take `--password-file` and
   `--password-stdin`"* sentence, which is now four-of-five and must say so.
10. **`docs/BACKLOG.md` and `PHASE121C…`** — mark the blocker closed; 12.1C becomes fully complete.

Not in scope of the implementing commit: `docs/COMPATIBILITY.md`, any ADR, any adapter, any rule,
any renderer, `go.mod`, `go.sum`.

---

## 17. Required tests

| # | Test | Asserts |
|---|---|---|
| T1 | `kubernetesFlags` frozen-surface test | the command defines **exactly** these ten flags — the `rabbitmqFlags` shape, both directions |
| T2 | `leafFlagSurface["kubernetes"]` | each of the ten is defined |
| T3 | refused-surface test | every §10 row is refused as an unknown flag, exit 2 — at minimum `--host`, `--port`, `--user`, `--username`, `--password-file`, `--password-stdin`, `--token`, `--tls`, `--tls-ca-file`, `--tls-server-name`, `--tls-insecure`, `--insecure`, `--insecure-skip-tls-verify`, `--impersonate`, `--proxy-url`, `--exec`, `--auth-provider`, `--allow-exec-auth`, `--server`, `--api-server`, `--all-namespaces`, `--namespace-pattern`, `--service-pattern`, `--selector`, `--pod`, `--deployment`, `--events`, `--logs`, `--metrics`, `--network-policy`, `--probe-endpoints`, `--step-timeout`, `--page-size`, `--max-pods`, `--config`, `--target`, `--concurrency`, `--database`, `--sasl-mechanism`, `--vhost` |
| T4 | help golden | `testdata/help/kubernetes.txt`, plus regenerated `diagnose.txt` and `root.txt` |
| T5 | help content | the help names no flag the command lacks, claims no health, and states the exit-code block every sibling carries |
| T6 | credential exclusivity | `--token-file` + `--token-stdin` → exit 2, no report |
| T7 | empty credential | an empty `--token-file`, a file holding one newline, and empty stdin each → **exit 2** (§7.3), and **not** a credential-free run |
| T8 | credential reading | a token file with and without a trailing newline produce the same secret; leading/trailing spaces survive; over-bound input is exit 2 and not a truncated token |
| T9 | credential binding | the credential built by the leaf is bound to the **derived API server** endpoint, and `SecretFor` refuses a Pod IP, a ClusterIP and another service's endpoint — the 12.1B test, driven from the CLI |
| T10 | secret leakage | the token appears in no stream, no report, no error, in both output modes and both security modes; **changing the token changes no byte of output** (Phase 9.1C's honest property) |
| T11 | target validation is not duplicated | each §12 `Target.Validate` row exits 2 with the adapter's own message — proving the CLI did not restate the rule |
| T12 | in-cluster conflicts | `--in-cluster` with each of `--kubeconfig`, `--context`, `--token-file`, `--token-stdin` → exit 2 |
| T13 | refusal happens before any network operation | the exec-sentinel kubeconfig driven **through the CLI**: exit 2, sentinel absent, request-counting server at **zero** |
| T14 | entry-point equivalence | one Service diagnosed through `diagnose kubernetes` and through `run --config` produces a **byte-identical** embedded report — ADR 0094 §2.10 made checkable |
| T15 | all four findings reachable from the CLI | F1–F4 each produced through the leaf command against the hermetic API server, with the frozen exit code |
| T16 | exit-code mapping is the generic one | including that a `401` exits 0 and a refused read exits 4 — the 12.1C behaviour, unchanged by the new entry point |
| T17 | budgets are not reachable | `DefaultBudgets` is what a CLI run uses; no flag alters a budget |
| T18 | `svcdoctor kubernetes …` is refused | ADR 0041, per `PHASE121A…§12.1` |
| T19 | docs claims | the docs-claims and docs-structure suites pass with the new command documented, and `docs/COMPATIBILITY.md` is unchanged |
| T20 | existing surfaces unmoved | the four existing leaf flag surfaces, their help goldens and every existing credential message are byte-identical |

Mutation: the implementing commit extends `scripts/phase121c-mutations.sh` or adds a sibling with
plants for the §12 refusals — at minimum an accepted `--in-cluster --kubeconfig`, an empty token
accepted as credential-free, a credential bound to something other than the API server, and a
budget flag silently honoured. **Zero survivors.**

---

## 18. Impact

| Axis | Impact |
|---|---|
| Public flag count | **10** |
| `FindingCode` | **69 — unchanged.** No fifth Kubernetes code |
| Production rules | **24 — unchanged** |
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1 — unchanged** |
| `FailureClass` | **42 — unchanged** |
| Closed vocabularies | **none gains a member** |
| `Reveal` / `SecretFor` | **5 / 5 — unchanged** |
| External modules | **40 — unchanged** |
| `k8s.io` import paths | **10 — unchanged**; `internal/cli` imports none |
| Acquisition | **unchanged** — same three requests, same budgets, same 17 worst case |
| Diagnosis | **unchanged** — same two rules, same four codes |
| Renderer | **unchanged** — zero files |
| Exit codes | **5 — unchanged**, generic mapping |
| Configuration model | **unchanged** — five fields, no sixth |
| `docs/COMPATIBILITY.md` | **unchanged** — no Kubernetes distribution graded |

---

## 19. Unresolved public-surface decisions

**Zero.** Every flag in §5 carries a classification and a source; every refusal in §10 carries a
reason; every conflict in §12 carries the place it is decided.

One item is **recorded and owned elsewhere**, and it is not a leaf-CLI decision: the fleet
`kubernetes` target accepts an inert `step_timeout:` (§9.2). It is a pre-existing Phase 12.1B
configuration-surface gap of the ADR 0060 shape, it does not affect the command frozen here, and it
belongs to Phase 12.1D.

---

## 20. What would falsify this freeze

- An operator needing an authentication mode reachable through `run --config` but not through the
  command, or the reverse.
- A `--token-stdin` that turns out to be unusable because the token is longer than 4 KiB — the
  bound is ADR 0049 §3's and a projected ServiceAccount token is far below it, but a very large
  federated token would falsify the assumption rather than the design.
- A real cluster in Phase 12.1D producing a case where the derived API endpoint is not the one
  dialled, which would break the credential binding the whole model rests on.
