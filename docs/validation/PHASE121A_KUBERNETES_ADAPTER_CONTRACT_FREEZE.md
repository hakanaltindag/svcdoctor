# Phase 12.1A — Kubernetes adapter contract freeze

- **Phase:** 12.1A — contract freeze. **No production Go, no test, no config, no fixture, no
  dependency, no `go.mod`/`go.sum` change.**
- **Baseline:** `e92bd2fcd22c8e724171a9b101d41e1598e49350`, `HEAD == origin/main`, tree clean
- **Record:** ADR 0094
- **Outcome:** **CONTRACT FROZEN.** Nine contracts closed, **zero open blockers**. Phase 12.1B is
  an implementation exercise.

---

## 1. Baseline, re-measured

This is the **pre-client-go baseline** and it is the number every later phase is judged against.

| Fact | Value | How |
|---|---|---|
| `HEAD` / `origin/main` | `e92bd2f` / `e92bd2f` — identical | `git rev-parse` |
| working tree at start | clean | `git status --short` empty |
| Phase 12.0 / ADR 0093 committed | yes, both at `e92bd2f` | `git show --stat HEAD` |
| `make check` before editing | **exit 0** | run |
| `domain.SchemaVersion` | **1** | `internal/domain/report.go:21` |
| `domain.RunSchemaVersion` | **1** | `internal/domain/runreport.go:26` |
| declared / attributed `FindingCode`s | **65 / 65** | `TestTheConvergenceInventoryIsComplete` |
| production rules | **22** | same scan |
| `FailureClass` values | **42** | `internal/domain/failureclass.go` |
| `RuleContext` fields | **3** | `TestDIAG017RuleContextCarriesExactlyThreeFields` |
| external modules declared in `go.mod` | **2** | `TestTheDependencyCountIsExact`; `go list -m all` = 3 including the main module |
| `go.sum` | **4 lines** | measured |
| production binary | **10,310,258 bytes**, **219 packages** | `CGO_ENABLED=0 go build ./cmd/svcdoctor` |
| **`os/exec` linked today** | **NO** | `go list -deps ./cmd/svcdoctor` |
| **`net/http` linked today** | **NO** | same |
| service adapters | **4** | `internal/adapter/*` |
| `Reveal` / `SecretFor` production sites | **4 / 4**, one per service | `TestRevealHasOneProductionCallSitePerService` |
| exit codes | **5** (`0`–`4`) | `docs/SCOPE.md` |

**One property of the dependency guard is load-bearing and must be read before C1.**
`test/security/dependency_test.go` is a whitelist over `go.mod`'s direct requirements, and its
own comment states the principle: *"A transitive dependency appearing under one of them would be
a separate finding and is prevented in the only durable way, **by choosing dependencies that have
none**."* Both current modules have zero transitive dependencies. The guard also states **why**
the count matters: *"svcdoctor transmits credentials, so every module in the build graph runs in
the same process as a plaintext password."*

---

## 2. Measurements taken this phase

All in temporary modules under `/tmp`, **outside the repository**. Nothing in the tree was
created, modified or deleted; all scratch directories were removed and the tree was re-checked
clean.

| # | Measurement | Result |
|---|---|---|
| **M1** | baseline, above | 2 modules · 10,310,258 B · 219 packages · no `os/exec`, no `net/http` |
| **M2** | `client-go` v0.37.0, **full** surface (`kubernetes` Clientset + `clientcmd`) | **47** `go.mod` requirements · **36,833,026 B** · `os/exec` **linked** |
| **M2b** | `client-go` v0.37.0, **narrow** surface (typed `corev1` + `discoveryv1` + `rest`, **no** Clientset, **no** `clientcmd` import) | **46** requirements · **36,277,298 B** · `os/exec` **still linked** · `tools/clientcmd` **still in the graph** |
| **M3** | **when does client-go execute an `exec` credential plugin?** A kubeconfig whose plugin writes a sentinel file, probed at four points | `clientcmd.Load` → **not executed** · `.ClientConfig()` → **not executed** · `kubernetes.NewForConfig()` → **not executed** · **first API request → EXECUTED** |
| **M4** | a kubeconfig with `auth-provider: gcp` carrying `cmd-path` pointing at the same sentinel script | **never executed.** `NewForConfig` **fails closed**: `no Auth Provider found for name "gcp"` — the provider is unregistered unless a `plugin/pkg/client/auth/*` package is imported |
| **M5** | which dangerous kubeconfig fields are visible at pure-parse time | `clientcmd.Load` exposes `AuthInfo.Exec` (with `Command`/`Args`), `AuthInfo.AuthProvider` (with its config map, including `cmd-path`), `Impersonate`, `ImpersonateGroups`, `ImpersonateUID`, `TokenFile`, `ClientKey`, and `Cluster.ProxyURL` — **all of them, before anything runs** |
| **M6** | do impersonation and `proxy-url` propagate silently? | **Yes, with no error.** `rest.Config.Impersonate.UserName="victim"`, `Groups=[g1 g2]`, `Proxy != nil` |

**M3 is the phase's decisive measurement.** It converts C2 from *"we will not call the code
path"* into a structural contract with a proven boundary: the plugin is invoked lazily by the
transport, so **a refusal issued before the first request cannot be bypassed**.

**M2b is an honest correction to a Phase 12.0 suggestion.** Narrowing the import surface buys one
module and 0.55 MB. It is a **reachability and hygiene** decision, not a dependency-cost decision,
and no document may claim otherwise.

---

## 3. Kubernetes semantics verified this phase

Official `kubernetes.io` only. Paraphrased with the load-bearing clause quoted.

| # | Claim | Source |
|---|---|---|
| **V1** | `EndpointConditions.ready` — *"A nil value should be interpreted as **"true"**."* | EndpointSlice v1 API reference |
| **V2** | `EndpointConditions.serving` — *"A nil value should be interpreted as **"true"**."* | same |
| **V3** | `EndpointConditions.terminating` — *"A nil value should be interpreted as **"false"**."* | same |
| **V4** | **`ready` is *"essentially a shortcut for checking `serving` and not `terminating`"*, and is always `true` for a Service with `spec.publishNotReadyAddresses: true`** | EndpointSlice concepts |
| **V5** | **Service proxies normally ignore `terminating` endpoints "but they may route traffic to endpoints that are both `serving` and `terminating` if all available endpoints are `terminating`"** | same |
| **V6** | `serving` and `terminating` are **Stable since v1.26**; the **EndpointSlice API is Stable since v1.21** | same |
| **V7** | Slices are associated to a Service by the **`kubernetes.io/service-name` label** *and* by an **owner reference** on each slice | same |
| **V8** | `endpointslice.kubernetes.io/managed-by` identifies the managing entity; the built-in controller sets `endpointslice-controller.k8s.io` | same |
| **V9** | The control plane creates EndpointSlices **only for a Service that has a selector**; multiple slices per Service are normal; dual-stack yields **at least two**; *"endpoints may be represented in more than one EndpointSlice at the same time"* | same |
| **V10** | **API ceiling: "Each slice may include a maximum of 1000 endpoints"** and *"a maximum of 100 ports"*. The **controller default** is 100 endpoints per slice, configurable to 1000 | API reference + concepts |
| **V11** | **`Service.spec.selector`: "If empty or not set, the endpoints for this service will be determined by explicit EndpointSlices or Endpoints objects."** An **empty map is not "match all"** — it is selector-less | Service v1 API reference |
| **V12** | `type` enum: `ClusterIP`, `NodePort`, `LoadBalancer`, `ExternalName`. `ExternalName` requires `clusterIP` blank and *"No proxying will be involved"* | same |
| **V13** | `targetPort` *"is ignored for services with clusterIP=None"* | same |
| **V14** | `addressType` values are `IPv4`, `IPv6`, **`FQDN` (Deprecated)** — *"The 'FQDN' type is deprecated, and no semantics are defined for it"*; the controller only generates IPv4/IPv6 | EndpointSlice v1 API reference |
| **V15** | kubeconfig `users[].user.exec` — *"kubectl/client-go executes the named command"*, with `command`, `args`, `env`, `interactiveMode`, `provideClusterInfo` | Authentication concepts |
| **V16** | Impersonation kubeconfig fields are `act-as`/`as`, `as-groups`, `as-uid`, `as-user-extra`; they become `Impersonate-*` HTTP headers and need the RBAC verb **`impersonate`** | same |
| **V17** | *"A Role always sets permissions within a particular namespace… ClusterRole, by contrast, is a non-namespaced resource."* Permissions are *"purely additive (there are no 'deny' rules)"* | RBAC concepts |

**V10 corrects Phase 12.0.** The audit derived its EndpointSlice budget from *"no more than 100"*,
which is the ceiling on **`addresses` within one endpoint**, not on **endpoints within one slice**.
The API ceiling is **1000 endpoints per slice**, and §9 re-derives the budgets from it.

**V4 and V5 sharpen F4 materially and are new.** *"No ready endpoint"* is **not** *"no traffic will
be routed"*: when every endpoint is terminating, proxies may still route to `serving &&
terminating`. That is a second, independent reason the frozen wording is *publishes no **ready**
endpoint* and never anything about traffic.

**Not verified, and recorded as such.** The `kubernetes.io` API-concepts page truncated before
*"Retrieving large results sets in chunks"* on three separate fetches, so **cross-page `continue`
consistency is NOT WEB-VERIFIED in this phase.** §11 therefore designs conservatively — svcdoctor
relies on **completeness**, never on cross-page atomicity — which is the safe direction whatever
the guarantee turns out to be, and 12.1B carries a named obligation to re-verify before relying on
anything stronger.

---

## 4. C1 — the client-go dependency contract

### 4.1 Decision

> ### CLIENT_GO_AUTHORIZED

`k8s.io/client-go` and its required companions, at a **pinned minor**, are authorized for
`internal/adapter/kubernetes/client` and for no other package.

### 4.2 Why, and why not raw REST

Raw REST was weighed on its merits rather than dismissed. svcdoctor already has a YAML decoder,
`crypto/tls`, `encoding/json` and a secret model, and the first scope needs **three** read
operations over **fifteen** fields — so decoding is genuinely small. The reason it loses is not
size:

- **The exec and auth-provider refusals require parsing the same structures client-go parses.**
  A hand-rolled parser that missed a field shape would refuse nothing, silently. M5 shows
  `clientcmd.Load` exposing every dangerous field as a typed value; reimplementing that is
  reimplementing the attack surface.
- **kubeconfig merge, context resolution, TLS assembly, in-cluster discovery and pagination are
  each small and each has a wrong answer that fails open.**
- **`*bool` nil semantics (V1–V3) are the whole of C7.** Getting them from a generated type is
  free; getting them from hand-written decoding is a place for a mistake with no test that would
  obviously catch it.

### 4.3 The cost, stated rather than minimized

| | today | with client-go |
|---|---|---|
| `go.mod` requirements | **2** | **46–47** |
| transitive dependencies of those | **zero** | ~45 |
| binary | **10,310,258 B** | ~**36.3–36.8 MB** (≈3.5×) |
| `os/exec` linked | **no** | **yes** |
| `net/http` linked | **no** | **yes** |

**This is accepted as an intentional trade-off**, and the trade is stated in the repository's own
terms: reimplementing Kubernetes authentication, kubeconfig semantics, TLS assembly and API
decoding would create a larger **correctness and security** burden than the modules do — in a
package whose entire job is to talk to a control plane.

**It contradicts a recorded principle and the contradiction is named rather than absorbed.**
`test/security/dependency_test.go` states that transitive dependencies are *"prevented in the only
durable way, by choosing dependencies that have none."* client-go has 45. **Phase 12.1B must amend
that comment's reasoning, not merely its number**, and say in the same change that the principle
now reads *"prefer dependencies with none; where that is impossible, the exception is recorded in
an ADR."* Editing the count while leaving the reasoning would make the guard lie.

### 4.4 The import allowlist, frozen

**Permitted, and nothing else:**

| Package | For |
|---|---|
| `k8s.io/client-go/rest` | `rest.Config`, transport |
| `k8s.io/client-go/tools/clientcmd` | kubeconfig **parse and inspection** (C2 depends on it) |
| `k8s.io/client-go/tools/clientcmd/api` | the typed kubeconfig structures inspected at refusal time |
| `k8s.io/client-go/kubernetes/typed/core/v1` | `Services().Get`, `Pods().List` |
| `k8s.io/client-go/kubernetes/typed/discovery/v1` | `EndpointSlices().List` |
| `k8s.io/api/core/v1`, `k8s.io/api/discovery/v1` | the three object types |
| `k8s.io/apimachinery/pkg/apis/meta/v1` | `GetOptions`, `ListOptions`, `ObjectMeta` |
| `k8s.io/apimachinery/pkg/api/errors` | **structured** status inspection (`IsNotFound`, `IsForbidden`, `IsUnauthorized`, `StatusReason`) |
| `k8s.io/apimachinery/pkg/labels` | serializing a Service selector into a label selector string |

**Refused, and each refusal is a build-enforceable rule:**

`k8s.io/client-go/kubernetes` (the full `Clientset` / `kubernetes.Interface`) · `dynamic` ·
`discovery` (the API-discovery client) · `informers` · `listers` · `tools/cache` ·
`util/workqueue` · `tools/watch` · `tools/leaderelection` · `tools/portforward` ·
`tools/remotecommand` · `transport/spdy` · `plugin/pkg/client/auth/**` (**every** auth plugin
registration package — M4 shows this refusal is what makes `auth-provider` fail closed) ·
`sigs.k8s.io/controller-runtime` · any `k8s.io/kubectl` package · any code generator.

**The full `Clientset` is refused** because it is a capability surface: it makes every group and
verb one method call away, and the guardrails above become review discipline instead of a
compile error. Two typed group clients express exactly what MVP-D does.

**No `watch`, no informer, no cache, no reconciliation, no background goroutine.** svcdoctor runs,
reports and exits (ADR 0062 §9).

### 4.5 Linked package ≠ executable behaviour

> **`os/exec` in the binary is not the same fact as svcdoctor executing a credential plugin, and
> compliance is defined behaviourally.**

M2b proves the absence-based definition is unavailable: `os/exec` is reachable from `rest` itself.
So the contract names the **runtime path that must be unreachable** (§5.2), and Phase 12.1B proves
it with a sentinel test rather than with a linker check.

---

## 5. C2 — exec auth, and every other execution surface

### 5.1 Decision

> ### EXEC AUTH — REFUSED. CONFIG-DRIVEN LOCAL PROCESS EXECUTION — STRUCTURALLY REFUSED.

ADR 0072 §13 refuses an `exec:` / command provider — *"Arbitrary code execution driven by a config
file. It is the single largest surface any of these would add"* — with reopen condition **"None.
This is a decision, not a deferral."** A kubeconfig `exec:` stanza is that shape exactly (V15).
**ADR 0072 §13 is upheld, not reopened**, and no `--allow-exec-auth` flag is created, named or
reserved.

The practical cost is stated: **EKS, GKE and AKS generate exec-based kubeconfigs by default**, so
those clusters are reachable in first scope only through in-cluster identity or an
externally-materialized token (§6.1). That is a real usability limit and it is the price of not
running programs a file names.

### 5.2 The refusal happens before execution, and M3 proves where

```
read the kubeconfig file
        ↓
clientcmd.Load(bytes)              ← M3: nothing executes
        ↓
inspect the resolved AuthInfo and Cluster   ← M5: every dangerous field is visible here
        ↓
REFUSE the target if any prohibited construct is present
        ↓  (only if clean)
build rest.Config · build typed clients · issue requests
```

**Frozen requirement for 12.1B:** the refusal is issued **before the first API request**, which M3
shows is the earliest point at which client-go invokes a plugin. It is not enough to avoid
populating `ExecProvider`; the target is refused and no client is used.

**Frozen negative test:** a kubeconfig whose `exec.command` writes a sentinel file. svcdoctor must
refuse the target, and **the sentinel file must not exist** afterwards. This is the test M3 was
designed against and it is a release gate for 12.1B.

**Frozen output rule:** no `command`, no `args`, no `env` name or value, and no executable path
from a refused construct may reach canonical or shareable output, an error, a panic message or a
log line. The refusal names **the construct**, not its contents.

### 5.3 Every execution and authority surface, decided

| Construct | Executes a program? | First-scope behaviour |
|---|---|---|
| `users[].user.exec` | **yes** (V15, M3) | **REFUSE the target** |
| `users[].user.auth-provider` (any name, incl. `gcp` `cmd-path`) | historically yes | **REFUSE the target.** M4: it is *also* inert because no `plugin/pkg/client/auth/**` package is imported, so it fails closed even if the refusal were missed — belt **and** braces |
| `users[].user.as` / `as-groups` / `as-uid` / `as-user-extra` | no | **REFUSE the target** (§6.5) |
| `clusters[].cluster.proxy-url` | no | **REFUSE the target** (§6.6) |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` environment | no | **Neutralized**: `rest.Config.Proxy` is set explicitly to a direct-dial function so ambient environment proxying cannot apply (§6.6) |
| `users[].user.tokenFile` | no | **ALLOW**, read by svcdoctor (§6.1) |
| `users[].user.client-key` / `client-key-data` | no | **ALLOW** (§6.1) |
| `users[].user.username` / `password` | no | **REFUSE** — basic auth is not a first-scope mode |
| `clusters[].cluster.certificate-authority` / `-data` | no | **ALLOW** — public material |
| `clusters[].cluster.insecure-skip-tls-verify` | no | **REFUSE the target.** svcdoctor must not recommend or silently accept disabling the verification it exists to perform (ADR 0092 §2.8) |

**A refused construct is a configuration error, not a finding.** It is refused before any network
operation, and it maps to **exit 2** through the existing usage-error path — the same treatment
ADR 0060 gave `--tls-ca-file` under `--tls disable`.

---

## 6. C3 — authentication, credentials and files

### 6.1 The authentication mode matrix, frozen

| | Mode | Verdict | Why |
|---|---|---|---|
| **A** | explicit bearer token (via `env:` / `file:` credential reference, or `--token-file`) | **ALLOW** | The two sources ADR 0072 §2 already supports |
| **B** | kubeconfig `tokenFile` | **ALLOW**, and **svcdoctor reads it**, not client-go | Keeps the value inside `internal/security/secretinput` and the existing secret discipline. `rest.Config.BearerTokenFile` is **not** used, because it would let the library read a secret svcdoctor never masked |
| **C** | client certificate + key (`client-certificate[-data]`, `client-key[-data]`) | **ALLOW** | **Forced by the fixture strategy: `kind` and `kubeadm` kubeconfigs authenticate with client certificates.** Refusing it would make C9 unachievable |
| **D** | in-cluster ServiceAccount | **ALLOW**, explicit selection only | §6.4 |
| **E** | exec credential plugin | **REFUSE** | §5 |
| **F** | auth-provider | **REFUSE** | §5 |
| **G** | anonymous | **REFUSE** | A diagnostic that silently runs unauthenticated is a report whose authority nobody can reconstruct |
| **H** | username/password (basic) | **REFUSE** | Deprecated in Kubernetes; no first-scope need |
| **I** | cloud-specific auth plugins | **REFUSE** | A subset of E and F |

**Exactly four modes: A, B, C, D.**

**Mode C reopens ADR 0072 §14 condition 1**, which names *"a client certificate"* as a shape that
reopens §2's credential model — and it is the concrete need that condition anticipates. **The
reopening is recorded here rather than taken silently**, and it is narrow: the **private key** is
secret material and travels as a `security.Secret`; the certificate and the CA bundle are public
and do not.

### 6.2 The single `Reveal` site, and the count moves 4 → 5

Modes A, B and C all end with plaintext bytes handed to `crypto/tls` or to an `Authorization`
header. That is a `security.Reveal`.

> **Frozen: exactly one production `security.Reveal` call site for Kubernetes, in
> `internal/adapter/kubernetes/client`, reached by one function that handles whichever secret the
> selected mode carries.**

The one-per-service invariant holds; `Reveal` and `SecretFor` go **4 → 5**, and
`TestRevealHasOneProductionCallSitePerService` gains a fifth service rather than an exception.
`forbidigo` already fails the build on a `Reveal` outside a wire-shaped package, so
`internal/adapter/kubernetes/client` must be added to that rule's exclusion in the same change —
which is the mechanism that makes the site deliberate.

**Frozen prohibition:** no resolved secret may enter an `Evidence` attribute, a `Finding`, the
report, a renderer, an error, a panic message or any debug output. `AttrValue` has no field that
could carry one, which makes most of this structural.

### 6.3 kubeconfig selection, context and namespace

| | Frozen policy |
|---|---|
| **kubeconfig source** | **explicit path only.** The path is a required field of the target when kubeconfig mode is used |
| `KUBECONFIG` environment variable | **not consulted** |
| `~/.kube/config` fallback | **none** |
| merged kubeconfig lists | **not supported.** One file. A merge list makes one config file mean different things on different machines |
| **context** | **mandatory** when kubeconfig mode is used, and **forbidden** in in-cluster mode. `current-context` is **never** used implicitly |
| server / cluster override | **none.** The context selects the cluster |
| **namespace** | **mandatory and explicit.** Never from the context, never `"default"` |
| Service name | **mandatory and explicit** |

**Why context is mandatory rather than defaulted-and-reported.** Phase 12.0 left it open. A
defaulted context makes a `run --config` file mean different things depending on a machine-local
`current-context`, and its failure mode — reading the wrong cluster and reporting *"not found"* —
is indistinguishable from a real finding. One extra field removes an entire class of incident.
`kubectl config current-context` tells an operator what to write.

### 6.4 In-cluster mode

Selected by an explicit `inCluster: true`. **It is mutually exclusive with kubeconfig mode**, and
supplying both is a configuration error. **It is never a fallback after kubeconfig failure**, and
there is no implicit detection: a mounted ServiceAccount token must never cause svcdoctor to
acquire an ambient identity nobody asked for.

### 6.5 Impersonation — REFUSED

`as`, `act-as`, `as-groups`, `as-uid`, `as-user-extra` (V16). M6 shows they propagate into
`rest.Config.Impersonate` **with no error**, so silence would be indistinguishable from absence.
A diagnostic tool that silently acts as another principal is unauditable, and impersonation
requires an `impersonate` RBAC grant the minimum Role deliberately does not request.

### 6.6 Proxies — REFUSED and NEUTRALIZED

M6 shows `proxy-url` producing a non-nil `rest.Config.Proxy` silently. A proxy changes network
vantage, and ADR 0092 §2.4 froze that a claim is scoped to the position it was measured from.

- kubeconfig `proxy-url` → **refuse the target**.
- environment `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` → **neutralized**: `rest.Config.Proxy` is set
  explicitly to a direct-dial function, so ambient environment proxying cannot silently apply.
  Leaving it to library defaults would make the vantage depend on a variable the report never saw.

Because both are refused, **no proxy fact needs to reach canonical evidence**, and no proxy URL —
which can carry credentials in its userinfo — can leak.

### 6.7 File authority

Authorized reads, and only these, each named directly or by reference in the declared target:
the **kubeconfig path**; a **token file** referenced by the target or by that kubeconfig's
`tokenFile`; a **client certificate and key** file; a **CA bundle** file; and, in in-cluster mode,
the standard projected ServiceAccount token and CA paths.

- **No path discovered from remote API data is ever opened.** A path arriving in an API object is
  data, not an instruction.
- **Symlinks are followed** — the repository does not sandbox `--password-file` either — but the
  **resolved** path is what any diagnostic message names, so a symlink cannot make a report claim
  a file it did not read.
- **Paths are `AttrKindIdentity`** where they reach evidence at all, so structural redaction
  pseudonymizes them in a shareable report. **First scope records no filesystem path in canonical
  evidence**, because no admitted finding needs one (§13).

### 6.8 Credential authority — permanent

> **A Kubernetes credential authorizes exactly one thing: the Kubernetes API server selected by
> this target.**

It does **not** authorize a Pod IP, a Service ClusterIP, an EndpointSlice address, a Node IP, a
discovered hostname, an Ingress, a Gateway, or any Kafka, PostgreSQL, Redis or RabbitMQ endpoint.
**No discovered endpoint inherits Kubernetes credentials.**

This is **structural, not a rule to remember**: the credential binds to the API server's
`security.Endpoint` (host and port from the resolved server URL), and ADR 0028's binding check
refuses it anywhere else. Phase 12.1B must prove it with a test that constructs a Kubernetes
credential and asserts `SecretFor` refuses a Pod IP and a ClusterIP.

---

## 7. C4 — the target contract

### 7.1 Shape

One target is exactly **one Kubernetes API authority + one explicit namespace + one explicit
Service name**. Conceptually, in the repository's existing fleet idiom:

```
targets:
  - id: payments-api                 # generic TargetID, unchanged
    type: kubernetes
    config:
      kubeconfig: /etc/svcdoctor/kubeconfig     # XOR inCluster
      context: prod-eu                          # mandatory with kubeconfig
      namespace: payments                       # mandatory
      serviceName: payments-api                 # mandatory
```

**Forbidden, and each is a build-enforceable absence:** a selector target · a Pod target · a
Deployment or any workload target · a namespace scan · a cluster scan · a regexp · a wildcard ·
multiple Services · `allNamespaces`.

### 7.2 Identity, kept apart

| Concept | Owner |
|---|---|
| **svcdoctor target ID** | the run-level declared identity, unchanged (`TargetID`) |
| kubeconfig **context** | an operator-local input choice, report-visible as such |
| **API server identity** | the resolved server host:port, used for credential binding; **not** published as a canonical identifier |
| **namespace** | part of the Service subject |
| **Service object identity** | `service/<namespace>/<name>` — the evidence subject |

**No target is created per Pod or per EndpointSlice.** One declared Service is one target and one
report.

**Subject kind:** `SubjectKindTarget`, whose definition is *"the inspected target as a whole"* —
which the Service is. **No new `SubjectKind` is added**, and §14 shows no closed vocabulary moves.

### 7.3 The Service UID race, solved without a fourth API call

A Service may be deleted and recreated between the `Get` and the EndpointSlice `List`. Association
by the `kubernetes.io/service-name` label is **name**-based and would silently cross generations.

**Frozen solution:** V7 states that each slice carries **an owner reference to its Service** as
well as the label, and an owner reference carries the **UID**.

- A slice with an owner reference to a Service whose UID **differs** from the Service this run read
  is **excluded**, and the exclusion is counted.
- A slice with **no** Service owner reference is **included** by label association, and the fact
  that it was associated **by label alone** is recorded as a bounded attribute.

**No re-`GET` of the Service is added.** The owner reference gives the same guarantee for free,
and ADR 0092's discipline about not adding network operations without a reason applies.

**The Pod side has no equivalent guard**, and that is stated rather than hidden: the selector is
read once and the list is issued against it, so a selector changed mid-run yields a list against a
selector that is one moment stale. The claim's *"at the time of these API observations"* scoping
covers it, and no admitted finding misattributes as a result — the selector and the Pod list are
about the same Service name in the same namespace.

### 7.4 Service types, frozen

| Type / shape | First scope |
|---|---|
| **selector-backed `ClusterIP`** | **Fully supported** |
| **selector-backed headless (`clusterIP: None`)** | **Fully supported.** V9: slices are still created. The absence of a ClusterIP is **never** a finding |
| **selector-backed `NodePort`** | **Fully supported** for backend publication. **No** node-level reachability claim |
| **selector-backed `LoadBalancer`** | **Fully supported** for backend publication. **No** `status.loadBalancer` claim, no cloud LB diagnosis |
| **selector-less (any type)** | **Supported as observation only.** V11: an **empty map is selector-less**, identically to an absent one. **F3 is structurally unreachable**, and F4 is **withheld** — endpoints are managed by something svcdoctor did not observe |
| **`ExternalName`** | **Unsupported, and reported as such.** V12: no selector, no endpoints, no proxying. Absent slices are correct. **Neither F3 nor F4 may fire** |

**Service type is never equated with external reachability.** A `LoadBalancer` with ready
endpoints may be externally unreachable; a `ClusterIP` with none may be exactly what was intended.

---

## 8. C5 — the RBAC contract

### 8.1 The minimum Role

```
apiGroups: [""]                     resources: ["services"]        verbs: ["get"]
apiGroups: [""]                     resources: ["pods"]            verbs: ["list"]
apiGroups: ["discovery.k8s.io"]     resources: ["endpointslices"]  verbs: ["list"]
```

**Namespace-scoped `Role` + `RoleBinding`. No `ClusterRole`, no cluster-scoped grant, no
cluster-admin** (V17).

**No `get` on Pods or EndpointSlices is required**, because svcdoctor never addresses an individual
Pod or slice by name — it asks the API server two questions, each answered by a filtered list.

**Explicitly not requested:** `watch` · `create` · `patch` · `update` · `delete` · `deletecollection`
· `impersonate` · `escalate` · `bind` · `pods/log` · `pods/exec` · `pods/attach` ·
`pods/portforward` · `secrets` · `configmaps` · `events` · `nodes` · `namespaces` ·
`endpoints` (the legacy v1 resource) · anything in `apps`, `networking.k8s.io`, `batch` or
`gateway.networking.k8s.io`.

### 8.2 A label selector is not a narrower permission

> **Frozen documentation rule: RBAC authorizes `list` on a resource within a namespace. A label
> selector narrows the *request*; it does not narrow the *grant*.**

svcdoctor holds `pods:list` and `endpointslices:list` **for the whole namespace**. No document,
help text, README line or release note may claim *"svcdoctor can only list the matching Pods"* or
anything equivalent. `internal/cli/docsclaims_test.go` already fails the build on documentation
that overclaims, and this rule joins it.

### 8.3 Denial is never emptiness

> **A denied `list` is never zero objects.**

```
403 Forbidden on a read
        ↓
that read's evidence node FAILs with an authorization failure class
        ↓
the set it would have produced is UNAVAILABLE, not empty
        ↓
every universal claim over that set is WITHHELD
```

`FailureAuthzNotPermitted` already exists among the 42 classes and is the mapping. Downstream
nodes that cannot run are `StateSkipped` with `AddBlockedBy` pointing at the denied read, which is
the existing blocking mechanism and needs nothing new.

**Taxonomy, frozen (§10.5):** F1 and F2 are **acquisition** findings — statements about what
svcdoctor could obtain. F3 and F4 are **semantic** findings — statements about what Kubernetes
records. The two categories must never be collapsed, and the admission rule for future Kubernetes
API errors is in §10.5.

---

## 9. C6 — operations, budgets, pagination and completeness

### 9.1 The nominal API sequence, frozen

```
1.  GET   /api/v1/namespaces/<ns>/services/<name>
2.  LIST  /api/v1/namespaces/<ns>/pods                    ?labelSelector=<service selector>&limit=<L>
3.  LIST  /apis/discovery.k8s.io/v1/namespaces/<ns>/endpointslices
                                                          ?labelSelector=kubernetes.io/service-name=<name>&limit=<L>
```

**Three operations and no other Kubernetes request.** No API discovery, no version negotiation, no
`SelfSubjectAccessReview`, no `watch`, no re-`GET`.

**Order is: 1, then 2 and 3.** Step 1 must complete first because it yields the selector step 2
needs and the UID step 3 validates against. Steps 2 and 3 are **issued sequentially, not
concurrently** — two goroutines would make the interleaving of two non-atomic reads
non-deterministic for no measurable gain on three requests, and determinism is worth more here
than a few milliseconds.

**Server-side filtering is mandatory, not optional.** The API server evaluates both label
selectors. svcdoctor does **not** list all Pods and match locally: server-side selection is
exact Kubernetes semantics rather than a reimplementation of them, it bounds cardinality at the
source, and it makes F3 mean *"a complete server-filtered list was empty"* — a stronger and
simpler claim. It does **not** narrow RBAC (§8.2).

**Selector serialization** uses `k8s.io/apimachinery/pkg/labels` over the Service's
`map[string]string`. No hand-written string building, no regexp, no fuzzy matching, no name
heuristics.

### 9.2 Object budgets, derived

Re-derived from **V10**: the API ceiling is **1000 endpoints per slice**, not 100.

| Bound | Ceiling | Derivation |
|---|---|---|
| namespaces per target | **1** | the target names one |
| Services per target | **1** | the target names one |
| **list page size (`limit`)** | **500** | one round trip covers the overwhelming majority of namespaces while keeping a single response small enough to hold and normalize |
| **max pages per list** | **8** | with `limit` 500 this bounds each list at 4,000 objects and each list at 8 round trips |
| **max Pods enumerated** | **4,000** | 8 × 500. Far above any single Service's realistic backend count; a namespace larger than this is one where a universal claim should be withheld anyway |
| **max EndpointSlices enumerated** | **256** | at the API ceiling of 1000 endpoints per slice this admits 256,000 endpoints; at the controller default of 100 it admits 25,600. Dual-stack doubles slice count (V9), so the ceiling must not be small |
| **max endpoints normalized** | **10,000** | the point at which enumeration stops being an incident measurement. Reached only by a Service far outside MVP-D's intent |
| **total API round trips** | **≤ 17** | 1 + 8 + 8 |

**Every ceiling being reached produces the same outcome: the set is INCOMPLETE.** None produces a
truncated set presented as a total.

**Numbers are proposals frozen for 12.1B to confirm against a real cluster**, and confirming means
measuring, not re-arguing.

### 9.3 Response size is bounded by object count, not by bytes

`limit` bounds the **number of objects** in a page. It does **not** bound the response's **byte
size**: a single Pod carrying large annotations or a long status can be hundreds of kilobytes, and
`limit` 500 of them is not a byte bound.

**client-go's typed clients do not expose a per-response body ceiling**, so a byte ceiling is not
available without replacing the transport.

> **Frozen as a known limitation rather than a blocker.** First scope bounds objects and round
> trips, not bytes. The exposure is bounded in practice by the page size and by the fact that
> svcdoctor retains **fifteen fields** and discards every decoded object immediately (§13).
> Phase 12.1B records it in `docs/SECURITY.md` as a known limit; a byte ceiling is a later decision
> with its own record.

### 9.4 Pagination

- Every list sends an explicit `limit`.
- A returned `continue` token is followed.
- Pages accumulate **only** until the object budget or the page ceiling is reached.
- **If a `continue` token remains when a ceiling is reached, the set is INCOMPLETE.**
- A `410 Gone` / expired-continue mid-enumeration makes the set **INCOMPLETE**. It is never
  restarted silently, because a restart would sample a different moment and present the result as
  one enumeration.
- **Cancellation or deadline expiry mid-pagination makes the set INCOMPLETE**, and the partial
  pages are discarded from any universal claim.

**Cross-page consistency is not assumed** (§3, not verified). svcdoctor relies on **completeness**
— every page followed, no `continue` remaining, within budget — and never on cross-page atomicity.
This is the conservative direction and it is correct whatever the guarantee turns out to be.

### 9.5 Completeness, and the empty-versus-unavailable distinction

**No new completeness subsystem.** The existing primitives are sufficient and are used as they
are: a per-set boolean attribute on the set's own evidence node, `Result.Incomplete()` for the
run, `StateSkipped` + `Graph.BlockedBy` for what could not run.

A **Pod set** is complete iff the request succeeded **and** every page was followed **and** no
`continue` remained **and** no budget was reached **and** the context was not cancelled.
An **EndpointSlice set** is complete iff the same holds **and** every admitted slice was
normalized within the endpoint budget.

> **Frozen, and foundational to both semantic findings:**
> **an empty *complete* set ≠ an unavailable or incomplete set.**
> Only the first supports a universal claim. The second supports none.

**No `zero`, `all`, `none` or `only` claim may be emitted from an incomplete enumeration.** This is
Kafka Phase 10.2's rule, unchanged, in a third domain.

### 9.6 Duplicates

V9: an endpoint may legitimately appear in more than one slice, and dual-stack guarantees separate
slices per family.

- **For F4, only existence matters.** *"Does any effective-ready endpoint exist?"* is
  duplicate-immune by construction, which is the main reason the finding is phrased as an
  existence claim rather than a count.
- **Where a count is rendered**, deduplication identity is `targetRef` (namespace, name, uid) when
  present, and `(addressType, address, port)` otherwise. A count that double-counts a dual-stack
  backend would be a number nobody can reconcile with `kubectl`.

### 9.7 Time budget and retries

Every API call takes the target's context; there is no independent deadline, no background
goroutine, no informer and no watch. Pagination stops on cancellation. **No svcdoctor-level retry
of any kind** — a `429` or a `5xx` ends the read and the set becomes incomplete. Retrying would
turn one bounded diagnosis into a small monitoring loop, which is what `backoffLimit: 0` in
ADR 0062 §9 already refuses at the Job level.

---

## 10. C7 and C8 — semantics and the four findings

### 10.1 EndpointSlice condition semantics, frozen

| Field | Present | **Absent (nil)** |
|---|---|---|
| `conditions.ready` | as given | **`true`** (V1) |
| `conditions.serving` | as given | **`true`** (V2) |
| `conditions.terminating` | as given | **`false`** (V3) |

**Effective-ready algorithm, frozen and deliberately tiny:**

```
for each associated EndpointSlice:
    for each endpoint:
        effectiveReady := (conditions.ready == nil) ? true : *conditions.ready
        if effectiveReady { → at least one ready endpoint exists }
```

It does **not** consult `serving`, `terminating`, `targetRef`, the address, the port, the address
type, or any Pod. **`ready` alone decides `ready`**, because V4 states that `ready` already *is*
the shortcut for *"serving and not terminating"*, and adding a second condition to the test would
be svcdoctor re-deriving a value Kubernetes already publishes — and would silently change meaning
for a Service with `publishNotReadyAddresses: true`.

**Why `ready` and not `serving`.** The question F4 answers is *what does Kubernetes publish as
ready*, which is what a Service proxy programs. `serving` answers a different question.
**A `serving=true, ready=false, terminating=true` endpoint is not dead**, and V5 says proxies may
still route to it when every endpoint is terminating — so calling it dead would be false in the
exact case it matters.

**Terminating endpoints** are neither counted as ready nor treated as absent. Where the set
contains only terminating endpoints, that fact is recorded as a bounded count, so *"no ready
endpoint"* is not read as *"nothing is serving"* — which V5 makes explicitly possible.

**Address types**: `IPv4` and `IPv6` create **no** semantic branch, because first scope never
connects. **`FQDN` is deprecated with no defined semantics** (V14) and is counted like any other
endpoint for the existence test and given no interpretation of its own.

### 10.2 Service association, frozen

**Authoritative and exhaustive:** the **`kubernetes.io/service-name` label**, applied server-side
as the list selector (V7), with the **owner-reference UID check** of §7.3 applied to the result.

**Forbidden:** name prefixes · name similarity · IP matching · fuzzy label search · any heuristic.

**`endpointslice.kubernetes.io/managed-by` does not gate admission.** A third-party-managed slice
that carries the authoritative Service association is a published backend, and excluding it would
make svcdoctor's answer disagree with kube-proxy's. The managing entity is recorded as a bounded
observation **when it is not the built-in controller**, because that is a fact a reader needs in
order to interpret the answer — not a reason to distrust it.

**`targetRef` is not required to count a ready endpoint.** A Service may legitimately publish
endpoints not backed by Pods. `targetRef` is used only as a deduplication key (§9.6).

### 10.3 The four findings

Names are frozen. Layers are §10.7. **The count is exactly four; a fifth is refused in this
phase.**

---

#### F1 — `KUBERNETES_SERVICE_NOT_FOUND`

| | |
|---|---|
| **Authority** | `API_SERVER_REPORTED`. `metav1.StatusReason` `NotFound` on the Service `GET` — an API-contract enumeration, inspected through `apierrors.IsNotFound`, never through `Status.Message` |
| **Claim** | *"The Kubernetes API reported that no Service of this name exists in this namespace, at the time of this observation."* |
| **Kind / severity / confidence** | **CONFIRMED / ERROR / HIGH** |
| **Layer** | **L6** |
| **Subject** | `service/<ns>/<name>` |
| **Evidence** | the `k8s.service` node **only** |
| **Forbidden** | *the Service was deleted* · *it never existed* · *the namespace is wrong* · *the context is wrong* · *the deployment failed* · any claim about what the operator meant |
| **Short-circuit** | the Pod and EndpointSlice reads **do not run**; their nodes are `SKIPPED` with `AddBlockedBy` → the Service node |
| **Recommendation** | `NEXT_EVIDENCE` / `VERIFY`, `SelfCollectable: false` — *verify the namespace and Service name this run declared against the cluster it was pointed at* |

**Why ERROR:** the declared target does not exist, so nothing further about it is measurable.
`POSTGRES_DATABASE_NOT_FOUND` is the precedent and it is ERROR.

**Why the claim stops at "the API reported":** a `NotFound` can also be returned in some
authorization configurations, so *"it does not exist"* is a stronger statement than the response
supports.

---

#### F2 — `KUBERNETES_API_ACCESS_DENIED`

| | |
|---|---|
| **Authority** | `API_SERVER_REPORTED`. `StatusReason` `Forbidden` (HTTP 403), via `apierrors.IsForbidden` |
| **Claim** | *"The Kubernetes API denied this run's identity the read it required; that measurement was not made."* |
| **Kind / severity / confidence** | **CONFIRMED / WARN / HIGH**, and the evidence node's state is **`UNKNOWN`** |
| **Layer** | the layer of the denied read (**L6**) |
| **Subject** | `service/<ns>/<name>` |
| **Evidence** | the denied read's node only |
| **Operation** | a **bounded svcdoctor-owned enum** on the node: `SERVICE_GET`, `POD_LIST`, `ENDPOINTSLICE_LIST`. The Detail names it from a **closed map** — the `rabbitmq.close_outcome` precedent exactly |
| **Forbidden** | *RBAC is misconfigured* · *the ServiceAccount lacks the right Role* · *cluster policy is wrong* · *request cluster-admin* · **and never that the objects are absent** |
| **Downstream** | the set that read would have produced is unavailable; **F3 or F4 is impossible and is withheld** |
| **Recommendation** | `NEXT_EVIDENCE` / `VERIFY`, `SelfCollectable: false` — *verify whether the identity this run used is authorized to perform this read in this namespace* |

**Why WARN and `UNKNOWN`, not ERROR:** the target did not fail; svcdoctor's measurement was
blocked. `REDIS_COMMAND_NOT_PERMITTED` is the precedent, and its detail already says *"This is not
a failure of the endpoint."*

**Why one code for three operations:** the claim is identical in kind and the discriminator is a
closed enum on the evidence, which is where ADR 0069 §6's division puts it. Two denied reads
produce **two findings** rather than one merged one, because the Detail differs and ADR 0081 §2.2b
makes Detail a merge **precondition** — which is the correct outcome, not a defect.

---

#### F3 — `KUBERNETES_SERVICE_SELECTS_NO_PODS`

| | |
|---|---|
| **Authority** | `API_SERVER_REPORTED` selector evaluation over a **complete** server-filtered list |
| **Admission — all required** | the Service exists · it **has a non-empty selector** (V11: an empty map is selector-less) · its type is **not** `ExternalName` · the Pod list **succeeded** · the Pod list is **complete** · the selector was serialized by `labels` and evaluated **server-side** · **zero** Pods returned |
| **Claim** | *"At the time of these API observations, this Service's selector matched no Pod in its namespace."* |
| **Kind / severity / confidence** | **CONFIRMED / ERROR / HIGH** |
| **Layer** | **L6** |
| **Evidence** | the `k8s.service` node (the selector anchor) and the `k8s.pod_set` node (the complete set) |
| **Forbidden** | *the selector is wrong* · *the Deployment is missing* · *the Pods crashed* · *traffic has no backend* · *the Service is unavailable* · *the application is down* |
| **Recommendation** | `NEXT_EVIDENCE` / `COMPARE`, `SelfCollectable: false` — *compare this Service's selector with the labels on the Pods intended to back it* |

**Why ERROR rather than WARN or INFO**, answered against the question rather than by intuition:
**temporal risk is low** — label matching is evaluated by the API server at read time and is not
an eventually-consistent controller output, unlike a replica count or an endpoint publication; and
**the impact is identical to F4's** — a Service with no backend candidates has no possible ready
backend. Two findings describing the same impact at two severities would make severity describe
the *route to the conclusion* rather than the conclusion.

**The known true-but-intentional shape is recorded rather than argued away:** a workload
deliberately scaled to zero produces this finding, truthfully. svcdoctor reports the observed
state and never the violated intent (ADR 0083 §2.6), and the Detail says the selector matched
nothing without saying that it should have.

**F3 is structurally unreachable for a selector-less or `ExternalName` Service**, and that is a
permanent property test, not a runtime check somebody could remove.

---

#### F4 — `KUBERNETES_SERVICE_NO_READY_ENDPOINT`

| | |
|---|---|
| **Authority** | `CONTROLLER_REPORTED`, over a **complete** authoritative slice set |
| **Admission — all required** | the Service exists · it **has a non-empty selector** · type is **not** `ExternalName` · the EndpointSlice list **succeeded** · the set is **complete** · every admitted slice was normalized within the endpoint budget · **at least one Pod was selected** (so F3 and F4 are disjoint) · **no endpoint is effective-ready** by §10.1 |
| **Claim** | *"At the time of these API observations, Kubernetes published no ready endpoint for this Service."* |
| **Kind / severity / confidence** | **CONFIRMED / ERROR / HIGH** |
| **Layer** | **L6** |
| **Evidence** | the `k8s.service` node and the `k8s.endpoint_publication` node |
| **Forbidden** | *the Service is unreachable* · *clients cannot connect* · *the application is unavailable* · *the Pods are unhealthy* · *the EndpointSlice controller is broken* · *the selector is wrong* · *the network is broken* · **and any word implying persistence** |
| **Recommendation** | `NEXT_EVIDENCE` / `COMPARE`, `SelfCollectable: false` — *compare the readiness the backing Pods report with the endpoints published for this Service* |

**Two Detail variants from a closed two-value map**, because *no slice was published* and *slices
exist and none of their endpoints is ready* are **distinct observations supporting one bounded
conclusion**:

- **no associated EndpointSlice was published**, and
- **associated EndpointSlices were published and no endpoint among them is ready.**

They are **mutually exclusive by construction**, so they can never both occur and there is no
convergence hazard — and no fifth code is needed.

**Where the set contains only terminating endpoints, the Detail says so**, because V5 makes
*"no ready endpoint"* compatible with traffic still being routed, and silence there would mislead.

**Why the wording is `publishes`, never `reachable`:** topology-aware routing, traffic policies,
mesh interception and V5's all-terminating case all break the equation between publication and
reachability, in both directions. This is ADR 0093 §2.5, and it is the sentence the whole Service
scope rests on.

### 10.4 What is not a finding

**401 Unauthorized produces no Kubernetes finding.** It is authentication, not authorization, and
the four-code budget holds: the `k8s.api_access` node **FAILs** with
`FailureAuthCredentialsRejected`, the three downstream nodes are `SKIPPED` and blocked by it, and
`DIAG_FAILURE_BOUNDARY` localizes it generically. An operator sees *last succeeded at L0, first
failed at L5*, which is the true statement.

**Every other API error** — a `5xx`, a timeout, a connection failure, a `410 Gone` mid-pagination —
maps to an existing `FailureClass` on the node that suffered it (`EXEC_LOCAL_TIMEOUT`,
`EXEC_CANCELLED`, or a transport class), sets the affected set incomplete, and produces **no
Kubernetes finding**.

### 10.5 The admission rule for future Kubernetes API errors

> **A Kubernetes API failure earns a `FindingCode` only when the operator's first move differs
> from that of every other API failure, and the discriminating value comes from an API-contract
> enumeration rather than from a message.**

`NotFound` and `Forbidden` clear it: *"you named something that is not there"* and *"you were not
allowed to look"* send an operator to two different places, and both are `metav1.StatusReason`
values. A `503`, a timeout and a reset send an operator to the same place — the control plane's
own health — and are acquisition failures on the node, not claims.

### 10.6 Confidence

`AdmitConfidence` is applied unchanged and **no new `Authority` value is added**.

| | Authority | Admitted |
|---|---|---|
| F1 | `AuthorityDirect` — the peer stated the condition in a field its own protocol defines | **HIGH** |
| F2 | `AuthorityDirect` — the same | **HIGH** |
| F3 | `AuthorityDirect` — the API server evaluated the selector and returned the result; the completeness precondition is what makes the universal quantifier admissible | **HIGH** |
| F4 | `AuthorityDirect` — the slices state it | **HIGH** |

**F3 and F4 are `AuthorityDirect`, not `AuthorityCompleteContrast`.** They are not contrasts: each
restates what one authoritative source published, under a proven-complete enumeration. Reaching
for complete-contrast would arm one of the two vacuous `AdmitConfidence` guards ADR 0087 requires
to be armed **together with `Miss`**, in one change-set — which first scope does not do.

**Note carried to 12.1B**, from ADR 0087: 21 of 22 existing rules set `ConfidenceHigh` as a
literal, and routing through `AdmitConfidence` is not output-neutral for a claim that restates a
direct measurement. The four Kubernetes rules must therefore either pass `AuthorityDirect`
explicitly or set the literal as the existing rules do — and whichever is chosen must be the same
for all four.

### 10.7 Kind, layer and the failure boundary

**All four are `CONFIRMED`. None carries a `Discriminator`.** Each is a bounded fact about what an
authoritative source stated, not a causal explanation. **No hypothesis is created merely because
Kubernetes is eventually consistent** — eventual consistency bounds the *claim's scope*
(*"at the time of these API observations"*), not its *kind*.

**The evidence graph and its layers:**

```
k8s.target              L0   the declared namespace + Service
      └── k8s.api_access          L5   the API server accepted this run's identity
              ├── k8s.service              L6   the Service object read
              ├── k8s.pod_set              L6   the complete-or-not selector-filtered Pod set
              └── k8s.endpoint_publication L6   the complete-or-not associated slice set
```

**Five nodes maximum, one subject.** L1–L3 are unused because transport belongs to the client
library (ADR 0093 §2.10); L4 is unused because the Kubernetes API has no separate
capability-discovery step in first scope. **Both absences are deliberate and neither breaks the
boundary**, because `lastGood` requires only *a* PASS at a strictly lower layer.

**One consequence was examined rather than assumed.** `sortByLayer` breaks a same-layer tie by
**step name**, so among three L6 nodes the alphabetically-first failing node is cited as
`firstEvidencedFailure`. Short-circuiting makes this almost always vacuous — a failed
`k8s.service` leaves the other two `SKIPPED`, and `SKIPPED` is never a failure — and in the one
reachable case where two reads are both denied, either is an equally true first failure at the
same layer and the same instant. **The boundary stays truthful and deterministic**, and no `Layer`
value is added.

### 10.8 Short-circuiting, precisely

| Condition | Behaviour |
|---|---|
| `k8s.api_access` fails (401, transport, timeout) | the three L6 reads do not run; `SKIPPED` + `AddBlockedBy` → `k8s.api_access` |
| `k8s.service` → `NotFound` | **F1**; Pod and slice reads do not run; `SKIPPED` + blocked |
| `k8s.service` → `Forbidden` | **F2**(`SERVICE_GET`); Pod and slice reads do not run; `SKIPPED` + blocked |
| Service is selector-less or `ExternalName` | Pod and slice reads **do not run**; both nodes `SKIPPED`; **no F3, no F4**; the Service's shape is a bounded observation |
| Pod list `Forbidden` | **F2**(`POD_LIST`); **F3 impossible and withheld**. **The EndpointSlice read still runs** |
| EndpointSlice list `Forbidden` | **F2**(`ENDPOINTSLICE_LIST`); **F4 impossible and withheld**. **The Pod read still runs** |
| Pod set incomplete | **no F3.** The slice branch is unaffected |
| EndpointSlice set incomplete | **no F4.** The Pod branch is unaffected |
| context cancelled | every unfinished set is incomplete; no universal claim; `Result.Incomplete()` |

> **One branch failing never erases the other branch's independent evidence.** The Pod set and the
> slice set are siblings under the Service node, not a chain, which is what makes the graph a DAG
> rather than a list.

### 10.9 Convergence

Driven over the six shapes §55 requires, against existing semantics:

| | Shape | Result |
|---|---|---|
| A | same code, same subject, same Detail | merges byte-identically |
| B | F2 for two different denied operations | **two findings** — Detail differs, and ADR 0081 §2.2b makes Detail a merge precondition. Correct: two reads were denied and two things are said |
| C | F4 *no slice* versus *slices with none ready* | **cannot co-occur** — mutually exclusive by construction |
| D | different Service subjects | no merge; identity is `(Code, Subject)` |
| E | incomplete versus complete evidence | incomplete emits nothing, so no pair exists |
| F | page and list-order permutation | must produce byte-identical canonical JSON — a property test |

**Existing convergence represents all four findings safely. No merge-semantics change is required
and none is authorized.**

---

## 11. Evidence, data minimization and privacy

### 11.1 The normalized attribute set — fifteen fields, and every one is required

| Node | Attribute | Type | Required by |
|---|---|---|---|
| `k8s.api_access` | `k8s.auth_mode` | closed enum: `TOKEN`, `TOKEN_FILE`, `CLIENT_CERT`, `IN_CLUSTER` | auditability of authority |
| | `k8s.context` | identity | report-visible input choice (kubeconfig mode) |
| `k8s.service` | `k8s.namespace` | identity | subject reconstruction |
| | `k8s.service_name` | identity | subject reconstruction |
| | `k8s.service_type` | closed enum: `ClusterIP`, `NodePort`, `LoadBalancer`, `ExternalName` | F3/F4 admission |
| | `k8s.service_headless` | bool | rendering; never a finding |
| | `k8s.selector_present` | bool | **F3 admission** (V11) |
| | `k8s.selector_key_count` | int | auditability without label values |
| `k8s.pod_set` | `k8s.pod_set_complete` | bool | **F3 admission** |
| | `k8s.pod_observed_count` | int | F3; rendering |
| `k8s.endpoint_publication` | `k8s.slice_set_complete` | bool | **F4 admission** |
| | `k8s.slice_count` | int | F4 Detail variant; rendering |
| | `k8s.endpoint_count` | int | rendering (deduplicated, §9.6) |
| | `k8s.ready_endpoint_count` | int | **F4** |
| | `k8s.terminating_endpoint_count` | int | the V5 disclosure |
| | `k8s.slice_excluded_by_owner_uid_count` | int | the §7.3 race guard, made auditable |
| | `k8s.slice_externally_managed` | bool | V8, recorded only when true |

**Sixteen keys, closed types, no maps, no raw Kubernetes structs, no free text.** A count is
authoritative **only** when its set's `*_complete` attribute is true; otherwise it is
*observed so far* and the renderer must say so.

### 11.2 What is deliberately not collected

**No per-Pod evidence node exists.** MVP-D retains **no Pod name, UID, label, phase, readiness,
condition, container status, restart count, image, node name or IP**, because **no admitted
finding consumes a single Pod field** — F3 needs only *"is the complete filtered list empty"*.

**This narrows Phase 12.0**, which said Pod state would be retained as observation only. The
narrowing is deliberate and is the data-minimization rule applied honestly: retaining identity for
a rendering nobody's diagnosis depends on is exactly the debt ADR 0090 §7 refuses. It also removes
the renderer problem — with no per-Pod and no per-endpoint node, the graph is a simple tree and
`terminal.serviceView` needs **no change at all** (§12.3).

**Also never collected:** annotations · label keys or values · Secret and ConfigMap contents ·
container images · `containerID` / `imageID` · Pod IPs · Service `clusterIP` · endpoint addresses ·
node names · `resourceVersion` · `Status.Message` · any condition or status `message` · the API
server URL · filesystem paths.

**`metadata.uid` is internal correlation only** — the Service UID is used for the owner-reference
check and **never enters evidence**; only the *count* of slices excluded by it does.

### 11.3 Redaction

Every Kubernetes name that reaches evidence — the namespace, the Service name, the context — is
**`AttrKindIdentity`**, whose definition already covers *"a named resource"*. Structural redaction
dispatches on `AttrKind` and never on a key, so it transforms them with **no new mechanism**, and
nothing relies on terminal-only masking. Counts, booleans and closed enums carry no identity and
pass through.

**Report-visible authority facts, and only these:** the auth **mode category**, kubeconfig-versus-
in-cluster, and the selected **context name** (identity, pseudonymized when shared).
**Never:** a token, a private key, a certificate, exec arguments or environment, a credential file
path, a kubeconfig path, or a proxy URL.

### 11.4 Deterministic ordering

**API list order must not reach canonical output.** Before any evidence is constructed:

- **EndpointSlices** sort by `(namespace, name)`;
- **endpoints within a slice** sort by `(addressType, first address, port)`;
- **Pods** are never enumerated individually, so no Pod ordering exists;
- **`EvidenceRefs`** are already deduplicated and sorted by `domain.NewFinding`.

**A permuted list must produce byte-identical canonical JSON**, and that is a property test rather
than a convention.

---

## 12. Integration with the existing product

### 12.1 CLI and fleet

**No new top-level command.** `svcdoctor diagnose kubernetes …` is one `case` in
`internal/cli/root.go`'s existing switch, and `svcdoctor run --config` hosts it through the
existing `config.Factory` registry. **`svcdoctor kubernetes …` is refused**, per ADR 0041.

**One declared Service is one target and one report**, through both entry points. No
Kubernetes-specific scheduler, no per-Pod target, and **no `if kubernetes` branch anywhere in the
generic core** — the registry exists precisely so a fifth service needs no edit to the runner, the
decoder, the aggregate report, the renderer or the exit-code mapping (ADR 0071 §6.3).

**The `Factory.DefaultPort()` mismatch is closed here, not deferred.** `NewRegistry` rejects a
zero default port and `load.go` requires a host, and a Kubernetes target has neither.

> **Frozen: the Kubernetes factory declares `DefaultPort() 443` and the target requires no `host`
> field**, because the API server's host **is** derived — from the kubeconfig context's `server`
> URL, or from `KUBERNETES_SERVICE_HOST` in-cluster — and `443` is the port that URL defaults to.
> The generic `Common.Host` requirement is satisfied by the resolved API server host, which is
> **derived during decode from material the target already names**, not invented.

That keeps the generic contract intact with no widening, and it means the Kubernetes target is a
fleet citizen from day one rather than a leaf-only asymmetry.

### 12.2 Generic-core isolation

> **No Kubernetes library may be imported by `internal/domain`, `internal/diagnosis` (the generic
> engine), `internal/fleet`, `internal/render`, `internal/probe`, `internal/security` or
> `internal/cli`.**

The dependency stays behind `internal/adapter/kubernetes/client`, which is the sole importer —
the same boundary the four `wire` packages hold for their protocol libraries. `internal/service/
kubernetes` is a **vocabulary leaf** importing only `internal/domain`, so diagnosis and the
renderer can name Kubernetes steps and attributes without touching client-go. `depguard` gains the
rules; a test asserts the sole-importer property, as
`TestOnlyTheConfigPackageImportsTheYAMLLibrary` already does for YAML.

### 12.3 Renderer and schema

**No renderer change.** With no per-Pod and no per-endpoint node, the Kubernetes report is a
single-path journey — `k8s.target` → `k8s.api_access` → three sibling reads — which
`terminal.serviceView` expresses today with a `journey`, an `outcomeStep`, `observations` and
`notes`, and **no `advertisementStep`**. Phase 12.0's "second child level" problem was created by
retaining Pod objects and disappears with them.

**No schema change, and no closed vocabulary moves.**

| | |
|---|---|
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1, unchanged** |
| `State`, `FindingKind`, `Confidence`, `Layer`, `SubjectKind`, `AttrKind`, `RecommendationKind`, `SafetyClass`, `Authority` | **unchanged — not one new member** |
| `FailureClass` | **42, unchanged.** `RESOURCE_NOT_FOUND`, `AUTHZ_NOT_PERMITTED`, `AUTH_CREDENTIALS_REJECTED`, `EXEC_LOCAL_TIMEOUT`, `EXEC_CANCELLED`, `EXEC_SKIPPED_PREREQUISITE_FAILED` all exist and cover first scope |
| `FindingCode` | **65 → 69** — four service-namespaced codes, which ADR 0009 admits without any core change |
| `RuleContext` | **3 fields, unchanged** |
| production rules | **22 → 24** — one acquisition rule, one publication rule |
| `Reveal` / `SecretFor` | **4 → 5**, one per service (§6.2) |
| external modules | **2 → 2 + client-go's set**, recorded in `allowedModules` with its reason and licence |

`Step` and `AttributeKey` are **validated open strings by design** — the core deliberately holds
no central registry of either — so new Kubernetes steps and attributes are not vocabulary
expansion in any closed enum.

---

## 13. C9 — validation

### 13.1 Layers, and none substitutes for another

**UNIT (hermetic, no cluster):** object normalization · `metav1.StatusReason` mapping · subject
identity · **EndpointSlice nil semantics (V1–V3)** · effective-ready · completeness · ordering ·
deduplication · hostile object names and strings · selector serialization · the empty-map-is-
selector-less rule (V11).

**HERMETIC API (an in-process HTTP test server speaking the Kubernetes wire shape):** pagination
and `continue` · budget exhaustion · a `410 Gone` mid-enumeration · 401 / 403 / 404 · objects that
change between reads · owner-UID mismatch · malformed and hostile object content · cancellation
mid-pagination. **A fake clientset is not sufficient** — it bypasses the transport, the pagination
and the status codes, which is most of what needs proving.

**REAL `kind`:** actual Service, Pod and EndpointSlice API behaviour · real controller publication
· real RBAC · the four findings.

**MUTATION** (§13.4) and **PROPERTY/FUZZ** (§13.5).

### 13.2 The four real scenarios

| | Scenario | Construction | Class |
|---|---|---|---|
| **F1** | Service absent | declare a Service name never created; assert `NotFound` and that **no Pod or slice request was issued** | **DETERMINISTIC_REAL** |
| **F2** | authorization denied, **three ways** | a dedicated ServiceAccount + Role granting a strict subset. **(a)** no `services:get`; **(b)** `services:get` but no `pods:list`; **(c)** `services:get` + `pods:list` but no `endpointslices:list`. Each asserts the F2 operation enum **and** that the corresponding universal finding is **absent** | **DETERMINISTIC_REAL** |
| **F3** | selector matches zero Pods | a Service whose selector names a label no Pod in the namespace carries | **DETERMINISTIC_REAL** |
| **F4** | no ready endpoint | a Deployment with **≥1 replica** and a readiness probe that **always fails** (`exec: false`, or an HTTP probe against a closed port). Pods run and are never `Ready`, so the controller publishes slices whose endpoints are `ready: false` | **DETERMINISTIC_REAL** |

**F4's fixture is chosen so it does not depend on F3.** A selector matching zero Pods may produce
either no slice or an empty slice depending on version and controller behaviour, and building F4
on that would test the fixture rather than the contract. **A Service that selects a real Pod that never becomes ready exercises the `ready: false` path
directly**, which is the semantics F4 is about.
A second F4 case — **no slice published at all** — is built hermetically, where the absence is
constructed rather than raced for.

**Also required, and each is a real scenario rather than a unit test:** a **selector-less** Service
asserting F3 is unreachable and F4 withheld; an **`ExternalName`** Service asserting neither fires
and missing slices are not a fault; a **headless** Service asserting F4 still applies and no
ClusterIP claim appears.

**No `sleep`.** Readiness is awaited by polling the ground truth — the Deployment's
`readyReplicas`, or the published slice's own conditions — under a bounded deadline, and the
assertion is made against the state the poll confirmed. This is the discipline Phase 9.1C's
RabbitMQ fixture defect taught: **verify the provisioning, do not assume it.**

### 13.3 Versions and distributions

**Minimum supported Kubernetes: v1.21**, and the derivation is the frozen field set rather than a
round number. The EndpointSlice API is Stable since **v1.21** (V6), and `conditions.ready` is
available from it. `serving` and `terminating` are Stable only since **v1.26** (V6) — **and first
scope's effective-ready test reads `ready` alone (§10.1), so the v1.21 floor holds.** The
`terminating` count is a rendering-only observation and is simply absent on older servers, which
`Present: false` already handles.

**CI matrix: two `kind` versions — the current stable minor and one older supported minor.** Not
more; the API surface is three stable resources and a wider matrix would buy nothing.

**Distributions:** first scope uses stable upstream APIs only, so **no vendor branch is permitted
and none is needed** for OpenShift, RKE2, k3s, EKS, GKE or AKS. Compatibility for those is
**source-level reasoning, not a CI claim**, and `docs/COMPATIBILITY.md` may not grade any of them
until a fixture establishes it. **EKS, GKE and AKS are additionally gated by §5.1's exec refusal**,
and that limitation belongs in the compatibility document from the first release.

### 13.4 Mutation contract

Every plant below must be caught; **zero survivors** is the release gate for the implementing
phase.

`ready: nil` read as false · `terminating: nil` read as true · `serving` substituted for `ready` ·
an incomplete set emitting a zero claim · a denied read becoming an empty set · `NotFound` not
short-circuiting · F3 firing on a selector-less Service · F3 or F4 firing on `ExternalName` ·
an empty selector map treated as match-all · `Status.Message` interpolated · a label value
interpolated · duplicate endpoints inflating a count · API list order reaching canonical JSON ·
the owner-UID check removed · a recommendation upgraded to `REMEDIATION` · F4 wording changed to
*reachable* or *unavailable* · F3 wording changed to *the selector is wrong* · a Kubernetes
credential accepted for a Pod IP · an `exec` kubeconfig not refused · a `proxy-url` kubeconfig not
refused · impersonation not refused · `insecure-skip-tls-verify` not refused ·
`SchemaVersion` changed · the page ceiling removed · pagination not stopping on cancellation ·
a `410 Gone` treated as end-of-list.

### 13.5 Property and fuzz contract

**P1** arbitrary free text never strengthens a diagnosis · **P2** a `Status.Message` never enters
canonical output · **P3** label keys and values never enter output · **P4** list permutation leaves
canonical JSON byte-identical · **P5** duplicate slice data never strengthens semantics ·
**P6** an incomplete enumeration never produces a universal claim · **P7** nil conditions follow
V1–V3 exactly · **P8** an unknown Service type produces no unsupported-shaped diagnosis ·
**P9** a selector-less Service never produces F3 · **P10** hostile object names cannot inject ANSI,
CR or LF into terminal output · **P11** no secret ever serializes · **P12** an `exec` config never
executes (the sentinel test) · **P13** credential authority remains API-server-only ·
**P14** cancellation stops pagination · **P15** budget exhaustion marks the set incomplete.

---

## 14. Implementation split

One giant Kubernetes commit is refused. Three phases, each independently auditable:

| Phase | Scope | Gate |
|---|---|---|
| **12.1B — client, authentication and acquisition** | the dependency and its allowlist · `internal/service/kubernetes` vocabulary · `internal/adapter/kubernetes/client` (kubeconfig parse, **the refusals**, `rest.Config`, the one `Reveal`) · the three bounded reads · pagination and budgets · normalization into evidence · the target config and its factory | **the sentinel exec test** · credential-authority test · hermetic API suite · unit suite · `depguard` sole-importer test · the amended dependency guard. **No finding, no rule, no CLI command** |
| **12.1C — diagnosis and presentation** | `internal/diagnosis/kubernetes` · the two rules · F1–F4 · the composition root · the CLI case · terminal and JSON output · golden reports | convergence matrix · false-positive corpus · mutation closure |
| **12.1D — real-cluster closure** | `kind` fixtures, the four scenarios plus the three Service-shape scenarios, the two-version matrix, `docs/COMPATIBILITY.md` grading | all four findings proven on a real cluster; zero mutation survivors |

**12.1B lands with byte-identical reports for every existing service**, which makes 12.1C's diff
the entire behavioural change — the same split ADR 0078's design used for 10.1a/10.1b.

---

## 15. Traceability — `KAC-001` … `KAC-040`

| ID | Contract | Frozen as |
|---|---|---|
| KAC-001 | client-go decision | **AUTHORIZED**, pinned minor (§4.1) |
| KAC-002 | dependency/import boundary | 9-package allowlist; full `Clientset`, dynamic, discovery, informers, cache, watch, auth plugins, controller-runtime and kubectl **refused** (§4.4) |
| KAC-003 | exec refusal | **REFUSED**, before the first request, proven by M3; sentinel negative test (§5) |
| KAC-004 | authentication modes | exactly four: token, token file, client cert+key, in-cluster (§6.1) |
| KAC-005 | kubeconfig selection | **explicit path only**; no `KUBECONFIG`, no `~/.kube/config`, no merge (§6.3) |
| KAC-006 | context | **mandatory** with kubeconfig; **forbidden** in-cluster; `current-context` never implicit (§6.3) |
| KAC-007 | namespace | **mandatory and explicit** (§6.3) |
| KAC-008 | in-cluster | explicit, mutually exclusive with kubeconfig, **never a fallback** (§6.4) |
| KAC-009 | secret handling | **one** `Reveal` site; 4 → 5; no secret in evidence, report, error or log (§6.2) |
| KAC-010 | credential authority | **API server only**, structural via `security.Endpoint` binding (§6.8) |
| KAC-011 | proxy | `proxy-url` **refused**; environment proxying **neutralized** (§6.6) |
| KAC-012 | impersonation | **REFUSED** (§6.5) |
| KAC-013 | target shape | one API authority + one namespace + one Service; no scan, selector, wildcard or workload target (§7.1) |
| KAC-014 | Service support | selector-backed ClusterIP/headless/NodePort/LoadBalancer supported; selector-less observation-only; `ExternalName` unsupported (§7.4) |
| KAC-015 | RBAC | 3 resources, 2 verbs, namespaced Role; a label selector is **not** a narrower grant (§8) |
| KAC-016 | API sequence | exactly three operations, server-side filtered, sequential (§9.1) |
| KAC-017 | object budgets | limit 500 · 8 pages · 4,000 Pods · 256 slices · 10,000 endpoints · ≤17 round trips (§9.2) |
| KAC-018 | pagination | explicit `limit`, follow `continue`, stop at budget, `410` ⇒ incomplete, no silent restart (§9.4) |
| KAC-019 | completeness | per-set; **empty complete ≠ unavailable**; no universal claim from an incomplete set (§9.5) |
| KAC-020 | EndpointSlice nil semantics | `ready` nil ⇒ **true** · `serving` nil ⇒ **true** · `terminating` nil ⇒ **false** (§10.1) |
| KAC-021 | Service association | `kubernetes.io/service-name` label **plus** owner-reference UID check; no heuristic (§10.2, §7.3) |
| KAC-022 | F1 | `KUBERNETES_SERVICE_NOT_FOUND` — CONFIRMED / ERROR / HIGH (§10.3) |
| KAC-023 | F2 | `KUBERNETES_API_ACCESS_DENIED` — CONFIRMED / WARN / HIGH, state UNKNOWN (§10.3) |
| KAC-024 | F3 | `KUBERNETES_SERVICE_SELECTS_NO_PODS` — CONFIRMED / ERROR / HIGH (§10.3) |
| KAC-025 | F4 | `KUBERNETES_SERVICE_NO_READY_ENDPOINT` — CONFIRMED / ERROR / HIGH (§10.3) |
| KAC-026 | confidence | `AuthorityDirect` for all four; **no new `Authority`** (§10.6) |
| KAC-027 | recommendations | `NEXT_EVIDENCE` only; `VERIFY` / `COMPARE`; `SelfCollectable: false`; no remediation (§10.3) |
| KAC-028 | evidence membership | structurally associated nodes only; no graph search; no cross-target evidence (§10.3) |
| KAC-029 | convergence | six shapes verified against existing semantics; **no merge change** (§10.9) |
| KAC-030 | short-circuiting | table in §10.8; one branch never erases the other |
| KAC-031 | API error normalization | structured only — HTTP status and `metav1.StatusReason`; **never** `Status.Message` (§10.4, §10.5) |
| KAC-032 | data minimization | 16 attribute keys; **no per-Pod node**; no labels, annotations, images, IPs, UIDs or paths (§11.1, §11.2) |
| KAC-033 | privacy | Kubernetes names are `AttrKindIdentity`; existing structural redaction, unchanged (§11.3) |
| KAC-034 | deterministic ordering | sorted before evidence; permutation ⇒ byte-identical JSON (§11.4) |
| KAC-035 | real-cluster fixture | `kind`; four findings plus three Service-shape scenarios; no `sleep` (§13.2) |
| KAC-036 | version policy | minimum **v1.21**, derived from `ready` and EndpointSlice v1; two-version CI (§13.3) |
| KAC-037 | mutation | 24 named plants, zero survivors (§13.4) |
| KAC-038 | fuzz/property | P1–P15 (§13.5) |
| KAC-039 | generic-core isolation | one sole-importer package; `depguard` + a test (§12.2) |
| KAC-040 | implementation split | 12.1B / 12.1C / 12.1D (§14) |

---

## 16. Adversarial review

The twenty-five attacks of §102, answered against the frozen contract.

1. **Malicious kubeconfig executes a process?** No — refused at parse time; M3 proves the boundary; sentinel test is a gate.
2. **Kubernetes auth reaches a discovered endpoint?** No — structural, via `security.Endpoint` binding.
3. **Implicit context selects the wrong cluster?** No — context is mandatory.
4. **Implicit namespace selects the wrong Service?** No — namespace is mandatory.
5. **Proxying silently changes vantage?** No — `proxy-url` refused, environment proxying neutralized.
6. **Impersonation silently changes authority?** No — refused; M6 shows why silence was not an option.
7. **403 becomes "zero Pods"?** No — §8.3, and F2's fixture asserts the universal finding is absent.
8. **Incomplete pagination becomes "zero endpoints"?** No — KAC-019; a mutation plant covers it.
9. **`ready: nil` misread?** No — V1 verified twice, frozen, unit-tested and mutation-planted.
10. **Terminating endpoint called dead?** No — V5 is disclosed in the Detail, and `ready` alone decides.
11. **Selector-less Service gets F3?** No — structurally unreachable; V11 makes the empty map selector-less.
12. **`ExternalName` gets F4?** No — both reads are skipped.
13. **Service delete/recreate mixes generations?** No — owner-reference UID check, no extra API call.
14. **API list order changes JSON?** No — sorted before evidence; property P4.
15. **Duplicate slices inflate semantics?** No — F4 is an existence claim; counts deduplicate.
16. **`Status.Message` enters canonical output?** No — structured inspection only; P2.
17. **Labels leak?** No — only `selector_present` and a key count.
18. **Endpoint addresses leak?** No — never collected.
19. **Pod names leak?** No — **no per-Pod evidence node exists at all.**
20. **F3 says the selector is wrong?** No — forbidden and mutation-planted.
21. **F4 says the Service is unreachable?** No — forbidden, and V5 is the second reason why.
22. **F2 recommends granting broad permissions?** No — `VERIFY` only; *"grant cluster-admin"* is forbidden.
23. **A Kubernetes dependency leaks into the generic core?** No — one sole importer, `depguard` plus a test.
24. **A single Service target becomes a cluster scan?** No — three namespaced reads, bounded, no cluster-scoped grant.
25. **Can 12.1B start coding without an architecture decision?** **§17 answers all fifty-one questions.**

**Two things were narrowed during this review and both are recorded rather than smoothed away:**
Pod state went from *observation-only* to **not retained** (§11.2), and mode **C — client
certificates — was added** after the fixture strategy proved `kind` needs it (§6.1), which reopens
ADR 0072 §14 condition 1 explicitly.

---

## 17. Contract completeness — every question has exactly one answer

| Question | Answer |
|---|---|
| Which dependency? | `k8s.io/client-go` + companions, pinned minor |
| Which imports? | the 9-package allowlist; §4.4's refusals are build-enforced |
| Can exec run? | **No** — refused before the first request |
| Which auth modes? | token · token file · client cert+key · in-cluster |
| Which kubeconfig behavior? | explicit path only; no env, no fallback, no merge |
| Which context behavior? | mandatory with kubeconfig; forbidden in-cluster |
| Which namespace behavior? | mandatory and explicit |
| Which proxy behavior? | `proxy-url` refused; environment proxying neutralized |
| Which impersonation behavior? | refused |
| Which target fields? | `kubeconfig` XOR `inCluster` · `context` · `namespace` · `serviceName` |
| Which Service types? | selector-backed ClusterIP/headless/NodePort/LB supported; selector-less observation-only; ExternalName unsupported |
| Which API operations? | `services:get`, `pods:list`, `endpointslices:list` — three, server-side filtered |
| Which RBAC? | those three, namespaced Role, no cluster grant |
| Which list limit? | 500 |
| Which page limit? | 8 |
| Which object limits? | 4,000 Pods · 256 slices · 10,000 endpoints |
| What marks incomplete? | budget, page ceiling, remaining `continue`, `410`, cancellation, failed request |
| `ready=nil`? | **true** |
| `serving=nil`? | **true** |
| `terminating=nil`? | **false** |
| Which slices belong to the Service? | `kubernetes.io/service-name` label + owner-UID check |
| Which four findings? | F1–F4, §10.3 |
| Exact claim ceiling for each? | §10.3, per finding |
| Finding kind? | all four CONFIRMED, none carries a discriminator |
| Severity? | ERROR / WARN / ERROR / ERROR |
| Confidence? | HIGH, `AuthorityDirect`, all four |
| Evidence membership? | §10.3, per finding; structurally associated nodes only |
| Recommendation? | `NEXT_EVIDENCE`; VERIFY/VERIFY/COMPARE/COMPARE; `SelfCollectable: false` |
| Short-circuit behavior? | §10.8's table |
| How are API errors normalized? | HTTP status + `metav1.StatusReason`, structured only |
| 401? | FAIL on `k8s.api_access`, existing auth class, **no Kubernetes finding** |
| 403? | **F2**, with a bounded operation enum |
| 404? | **F1**, and short-circuit |
| Selector-less Service? | observation only; F3 unreachable, F4 withheld |
| ExternalName? | unsupported; both reads skipped; neither finding |
| Incomplete Pod list? | no F3; the slice branch proceeds |
| Incomplete slice list? | no F4; the Pod branch proceeds |
| Cancellation? | sets incomplete, no universal claim, `Result.Incomplete()`, exit 4 |
| Deterministic ordering? | §11.4 |
| What Kubernetes data is retained? | the 16 attributes of §11.1 |
| What is omitted? | §11.2 |
| What is pseudonymized? | namespace, Service name, context — `AttrKindIdentity` |
| How are real fixtures built? | `kind`; §13.2 |
| Which Kubernetes versions? | minimum **v1.21**; CI on current stable + one older minor |
| Which mutation properties? | §13.4, 24 plants |
| Which fuzz properties? | P1–P15 |
| `SchemaVersion` change? | **No** |
| `RunSchemaVersion` change? | **No** |
| Generic scheduler change? | **No** |
| Generic diagnosis core change? | **No** |

**Zero unanswered items.**

---

## 18. Validation

```
git rev-parse HEAD; git rev-parse origin/main    # identical, e92bd2f
git status --short                                # clean at start
make check                                        # exit 0 — before editing
go test ./test/security/... -run 'Convergence|RuleContext|Dependenc|FindingCode|Reveal|SecretFor' -v
CGO_ENABLED=0 go build -o /tmp/... ./cmd/svcdoctor          # 10,310,258 bytes, 219 packages
go list -deps ./cmd/svcdoctor | grep -xE 'os/exec|net/http' # no match
make check                                        # exit 0 — after editing
git diff --check                                  # clean
```

**Evidence labelling.** **SOURCE-PROVEN** — every statement about svcdoctor's packages, guards,
ADRs and composition roots, read at `e92bd2f`. **TEST-PROVEN** — §1's inventory, by the named
guards, executed. **WEB-VERIFIED** — V1–V17, from `kubernetes.io` only: the EndpointSlice v1 and
Service v1 API references, the EndpointSlice and Service concepts pages, the Authentication
concepts page and the RBAC concepts page. No blog, no vendor documentation, no third-party source.
**MEASURED** — M1–M6, in temporary modules under `/tmp`, **outside the repository**; nothing in the
tree was created, modified or deleted, all scratch directories were removed, and `git status`
was re-checked clean afterwards.

**Not run, and no claim is made about them:** every container integration suite and all eleven
mutation harnesses. Phase 12.1A changes no Go code, so no integration-green and no
mutation-closure claim is made. **No Kubernetes cluster was contacted**; M2–M6 are build-graph and
in-process measurements, and M3/M4/M6 issued their requests at `127.0.0.1:59999`, where nothing
listens.

**Explicitly not verified, with its conservative default and its 12.1B obligation:** cross-page
`continue` consistency (§3). svcdoctor relies on **completeness**, never on cross-page atomicity;
12.1B re-verifies before relying on anything stronger.
