# ADR 0094 — Kubernetes Service diagnostic contract

- **Status:** Accepted
- **Date:** 2026-09-06
- **Phase:** 12.1A (contract freeze; no production code, no dependency change)
- **Implements:** ADR 0093's ARCH A and MVP-D, and closes both of its architecture blockers.
- **Upholds:** ADR 0007 (protocol before authentication), ADR 0009 (explicit composition-root
  registration), ADR 0010 (no raw objects in canonical evidence), ADR 0014, ADR 0016, ADR 0018
  (structural redaction), **ADR 0028 and ADR 0030 (credentials are endpoint-bound)**, ADR 0034 §8
  and §13, ADR 0041 (the command shape), **ADR 0050 (discovery creates no secret authority)**,
  ADR 0052 §5, ADR 0054, ADR 0058, **ADR 0060 (an inert-but-refused invocation is exit 2)**,
  ADR 0062 §9 as amended by ADR 0093 §9, ADR 0069 §6 (the class explains the break, the sentinel
  explains which), **ADR 0071 §6.3 (a fifth service edits no generic code)**, **ADR 0072 §13 (no
  config-driven process execution)**, ADR 0073, ADR 0078–0083, ADR 0087, ADR 0091, **ADR 0092**
  (the vantage ceiling, intent as a premise, the time-series limit, the refusal list)
- **Reopens, narrowly and explicitly:** **ADR 0072 §14 condition 1** — a credential that is a
  client certificate. §4.3.
- **Decision:** **CLIENT_GO_AUTHORIZED** behind a nine-package allowlist; **exec auth REFUSED**
  with a measured refusal point; four authentication modes; explicit kubeconfig, context and
  namespace; a three-resource namespaced RBAC minimum; bounded pagination whose exhaustion is
  **incomplete and never zero**; frozen EndpointSlice nil semantics; and **exactly four**
  finding codes. `SchemaVersion` **1**. §2.

---

## 1. Context

ADR 0093 selected ARCH A and MVP-D and handed Phase 12.1A two blockers it had measured rather
than guessed: **B1**, that a kubeconfig `exec:` stanza is the config-driven process execution
ADR 0072 §13 refuses permanently, and that `os/exec` is linked by `client-go` regardless of
import surface; and **B2**, that the dependency goes from 2 modules to 46–47 and the binary from
10.3 MB to about 36 MB.

`docs/validation/PHASE121A_KUBERNETES_ADAPTER_CONTRACT_FREEZE.md` holds the archaeology, the six
measurements, the seventeen web-verified Kubernetes semantics and the fifty-one-question
completeness table. This record holds the decision.

**Both blockers are closed.** Neither was closed by argument.

---

## 2. Decision

### 2.1 C1 — `client-go` is authorized, behind an allowlist

> **CLIENT_GO_AUTHORIZED**, at a pinned Kubernetes minor, importable by
> `internal/adapter/kubernetes/client` and by no other package.

**Permitted, and nothing else:** `client-go/rest` · `client-go/tools/clientcmd` and
`.../clientcmd/api` (the parse and inspection C2 depends on) · `client-go/kubernetes/typed/core/v1`
· `client-go/kubernetes/typed/discovery/v1` · `k8s.io/api/core/v1` and `k8s.io/api/discovery/v1` ·
`apimachinery/pkg/apis/meta/v1` · `apimachinery/pkg/api/errors` · `apimachinery/pkg/labels`.

**Refused, and each refusal is build-enforced:** the full `kubernetes` `Clientset` /
`kubernetes.Interface` · `dynamic` · the API-`discovery` client · `informers` · `listers` ·
`tools/cache` · `util/workqueue` · `tools/watch` · `tools/leaderelection` · `tools/portforward` ·
`tools/remotecommand` · `transport/spdy` · **every** `plugin/pkg/client/auth/**` package ·
`controller-runtime` · any `k8s.io/kubectl` package · any code generator.

**No watch, no informer, no cache, no reconciliation, no background goroutine.** svcdoctor runs,
reports and exits (ADR 0062 §9).

**The full `Clientset` is refused because it is a capability surface**, not because it is large:
it puts every group and verb one method call away, and the guardrails above become review
discipline instead of a compile error. Two typed group clients express exactly what MVP-D does.

**Raw REST was weighed and rejected on correctness, not on size.** The exec and auth-provider
refusals require parsing the very structures `clientcmd` parses; a hand-rolled parser that missed
a field shape would refuse nothing, silently. Nil-`*bool` EndpointSlice semantics (§2.6) are the
whole of the semantic contract, and getting them from a generated type is free.

**The cost is accepted as an intentional trade-off and is stated rather than minimized:** 2 → 46–47
modules, a 10,310,258-byte binary → about 36 MB, and both `os/exec` and `net/http` linked where
neither is today. Reimplementing Kubernetes authentication, kubeconfig semantics, TLS assembly and
API decoding would be a larger correctness and security burden than the modules are, **in the one
package whose job is to talk to a control plane.**

**One measured correction to ADR 0093's suggestion:** narrowing the import surface saves **one
module and 0.55 MB**. It is a reachability and hygiene decision, and **no document may present it
as a dependency-cost reduction.**

**One recorded principle is contradicted and the contradiction is named.**
`test/security/dependency_test.go` states that transitive dependencies are *"prevented in the only
durable way, by choosing dependencies that have none."* client-go has 45. **The implementing phase
must amend that reasoning, not merely the count**, and say in the same change that the principle
now reads *prefer dependencies with none; where that is impossible the exception is recorded in an
ADR.* Editing the number and leaving the sentence would make the guard lie.

### 2.2 C2 — exec auth is refused, and the refusal point is measured

> **EXEC AUTH REFUSED. CONFIG-DRIVEN LOCAL PROCESS EXECUTION STRUCTURALLY REFUSED.**
> **ADR 0072 §13 is upheld, not reopened.**

No `--allow-exec-auth` flag is created, named or reserved.

**`os/exec` being linked is not the same fact as svcdoctor executing a plugin, and compliance is
defined behaviourally**, because Phase 12.1A measured that the absence-based definition is
unavailable: `os/exec` is reachable from `rest` itself, with or without `clientcmd`.

**The refusal point was measured, not assumed.** A kubeconfig whose plugin writes a sentinel file
executed **nothing** at `clientcmd.Load`, **nothing** at `ClientConfig()`, **nothing** at
`NewForConfig()`, and **executed on the first API request** — the plugin is invoked lazily by the
transport. Therefore:

```
read the kubeconfig file → clientcmd.Load → inspect the resolved AuthInfo and Cluster
        → REFUSE the target if any prohibited construct is present
        → (only if clean) build rest.Config · build typed clients · issue requests
```

**A refusal issued before the first request cannot be bypassed**, and every dangerous field —
`Exec`, `AuthProvider` and its config map, `Impersonate`/`Groups`/`UID`, `TokenFile`, `ClientKey`,
`Cluster.ProxyURL` — is visible as a typed value at that point.

**Frozen negative test:** a kubeconfig whose `exec.command` writes a sentinel file. svcdoctor
refuses the target and **the sentinel must not exist**. This is a release gate.

**Frozen output rule:** no command, argument, environment name or value, or executable path from a
refused construct reaches canonical or shareable output, an error, a panic or a log line. The
refusal names **the construct**, never its contents.

**Refused constructs, each refused before any network operation and each an exit-2 configuration
error** (ADR 0060's treatment of an inert-but-refused invocation): `exec` · `auth-provider` of any
name · impersonation (`as`, `as-groups`, `as-uid`, `as-user-extra`) · `proxy-url` ·
`insecure-skip-tls-verify` · `username`/`password`.

**`auth-provider` fails closed twice.** It is refused at parse time, **and** it is inert because no
`plugin/pkg/client/auth/**` package is imported — measured: `NewForConfig` returns
*"no Auth Provider found"*. Belt and braces, deliberately.

### 2.3 C3 — authentication, credentials and files

**Exactly four modes:** an explicit **bearer token** (through an `env:`/`file:` credential
reference), a kubeconfig **`tokenFile`** — **read by svcdoctor**, never by the library, so the
value stays inside the existing secret discipline — a **client certificate and key**, and
**in-cluster ServiceAccount**. Everything else is refused: exec, auth-provider, anonymous, basic
auth, and every cloud plugin.

**Kubeconfig: explicit path only.** `KUBECONFIG` is not consulted, `~/.kube/config` is not a
fallback, and merge lists are not supported — one file, because a merge list makes one
configuration mean different things on different machines.

**Context is mandatory** with kubeconfig and **forbidden** in-cluster. `current-context` is never
used implicitly: a defaulted context makes a `run --config` file machine-dependent, and its failure
mode — reading the wrong cluster and reporting *not found* — is indistinguishable from a real
finding.

**Namespace is mandatory and explicit.** Never from the context, never `"default"`.

**In-cluster is selected explicitly, is mutually exclusive with kubeconfig, and is never a
fallback.** A mounted ServiceAccount token must never cause svcdoctor to acquire an identity
nobody asked for.

**One `Reveal` call site, and the count moves 4 → 5.** All three credential-bearing modes end with
plaintext bytes reaching `crypto/tls` or an `Authorization` header. **Exactly one production
`security.Reveal` call site for Kubernetes**, in `internal/adapter/kubernetes/client`, reached by
one function that handles whichever secret the selected mode carries. The one-per-service
invariant holds; `forbidigo`'s exclusion list gains that package in the same change, which is what
makes the site deliberate.

**File authority is closed:** the kubeconfig path, a token file, a client certificate and key, a
CA bundle, and in-cluster the standard projected paths — each named directly or by reference in
the declared target. **No path discovered from remote API data is ever opened.** Symlinks are
followed, as they are for `--password-file`, and any message names the **resolved** path so a
symlink cannot make a report claim a file it did not read. **First scope records no filesystem
path in canonical evidence.**

**Credential authority, permanently:**

> **A Kubernetes credential authorizes exactly one thing: the Kubernetes API server selected by
> this target.** It does not authorize a Pod IP, a ClusterIP, an EndpointSlice address, a Node IP,
> a discovered hostname, an Ingress, a Gateway, or any Kafka, PostgreSQL, Redis or RabbitMQ
> endpoint. **No discovered endpoint inherits it.**

This is structural rather than a rule to remember: the credential binds to the API server's
`security.Endpoint`, and ADR 0028's binding check refuses it anywhere else.

**Proxies are refused and neutralized.** `proxy-url` refuses the target; ambient
`HTTP_PROXY`/`HTTPS_PROXY` is neutralized by setting `rest.Config.Proxy` to a direct dial, because
leaving it to library defaults would make the run's vantage depend on a variable the report never
saw (ADR 0092 §2.4). Because both are refused, no proxy URL — which can carry credentials in its
userinfo — can leak.

### 2.4 C4 — the target

One target is **one Kubernetes API authority + one explicit namespace + one explicit Service
name**: `kubeconfig` XOR `inCluster`, `context`, `namespace`, `serviceName`, beside the generic
`id` and budgets.

**Forbidden:** a selector target · a Pod or workload target · a namespace or cluster scan · a
regexp · a wildcard · multiple Services · `allNamespaces`.

**Identity stays separated.** The svcdoctor target ID remains the run-level identity; the context
is an operator-local input choice, report-visible as such; the API server host:port is used for
credential binding and is **not** published as a canonical identifier; the evidence subject is
`service/<namespace>/<name>` at `SubjectKindTarget` — *"the inspected target as a whole"*, which
the Service is. **No new `SubjectKind`.** **No target is created per Pod or per EndpointSlice.**

**The delete-and-recreate race is closed without a fourth API call.** Each EndpointSlice carries an
**owner reference** to its Service as well as the `kubernetes.io/service-name` label, and an owner
reference carries the UID. A slice whose Service owner UID differs from the Service this run read
is **excluded and counted**; a slice with no Service owner reference is included by label and the
fact that it was associated **by label alone** is recorded. **No re-`GET` is added.**

**Service types:** selector-backed **ClusterIP, headless, NodePort and LoadBalancer** are fully
supported for backend publication — with **no** node-level and **no** `status.loadBalancer` claim.
**Selector-less** Services are observation-only: an **empty selector map is selector-less**, not
match-all, so `KUBERNETES_SERVICE_SELECTS_NO_PODS` is **structurally unreachable** and
`KUBERNETES_SERVICE_NO_READY_ENDPOINT` is withheld. **ExternalName is unsupported and reported as
such**; absent slices there are correct, not a fault. **Service type is never equated with
external reachability.**

### 2.5 C5 and C6 — RBAC, operations, budgets and completeness

**Minimum RBAC — a namespaced `Role`, three resources, two verbs:** `services: [get]`,
`pods: [list]`, `endpointslices: [list]` (`discovery.k8s.io`). **No `ClusterRole`, no
cluster-scoped grant, no cluster-admin**, and no `watch`, `create`, `patch`, `update`, `delete`,
`impersonate`, `escalate`, `bind`, `pods/log`, `pods/exec`, `secrets`, `configmaps`, `events`,
`nodes` or `namespaces`.

> **A label selector narrows the request; it does not narrow the grant.** svcdoctor holds
> `pods:list` and `endpointslices:list` for the whole namespace, and **no document may claim
> otherwise.**

**Exactly three API operations**, server-side filtered, issued sequentially: `GET` the Service;
`LIST` Pods by the Service's serialized selector; `LIST` EndpointSlices by
`kubernetes.io/service-name`. **No discovery, no version negotiation, no
`SelfSubjectAccessReview`, no watch, no re-`GET`, and no svcdoctor-level retry of any kind** — a
`429` or `5xx` ends the read and the set becomes incomplete, because retrying turns one bounded
diagnosis into a small monitoring loop.

**Server-side filtering is mandatory**: it is exact Kubernetes selector semantics rather than a
reimplementation of them, it bounds cardinality at the source, and it makes the selector finding
mean *"a complete server-filtered list was empty."*

**Budgets:** page `limit` **500** · **8** pages per list · **4,000** Pods · **256** EndpointSlices
· **10,000** endpoints · **≤17** round trips. Derived from the API's own ceiling of **1000
endpoints per slice** and from dual-stack doubling the slice count.

**Pagination:** explicit `limit`; follow `continue`; stop at the budget; **a remaining `continue`,
a `410 Gone`, a failed request or a cancellation makes the set INCOMPLETE**, and an expired token
is never silently restarted, because a restart samples a different moment and would present the
result as one enumeration.

**Cross-page consistency is not assumed.** svcdoctor relies on **completeness** — every page
followed, none remaining, within budget — never on cross-page atomicity.

> **Reaching a budget or a page ceiling MUST NOT become "no Pods" or "no ready endpoints". It
> becomes an incomplete enumeration**, `Result.Incomplete()` and exit code 4.
> **An empty *complete* set is not an unavailable set**, and only the first supports a universal
> claim. No `zero`, `all`, `none` or `only` claim may be emitted from an incomplete enumeration.

This is Kafka Phase 10.2's rule, unchanged, in a third domain. **No new completeness subsystem** —
a per-set boolean, `Result.Incomplete()`, and `StateSkipped` + `Graph.BlockedBy` are sufficient.

**A denied read is never emptiness.** A `403` fails that read's node with
`FailureAuthzNotPermitted`; the set it would have produced is **unavailable**, not empty, and every
universal claim over it is withheld.

**Response byte size is a recorded known limitation**, not a blocker: `limit` bounds objects, not
bytes, and client-go's typed clients expose no per-response body ceiling. The exposure is bounded
in practice by the page size and by svcdoctor retaining sixteen fields and discarding every
decoded object immediately.

### 2.6 C7 — EndpointSlice semantics, frozen

| Field | Absent (nil) |
|---|---|
| `conditions.ready` | **`true`** |
| `conditions.serving` | **`true`** |
| `conditions.terminating` | **`false`** |

**Effective-ready is decided by `ready` alone:**

```
effectiveReady := (conditions.ready == nil) ? true : *conditions.ready
```

It consults no `serving`, no `terminating`, no `targetRef`, no address, no port, no address type
and no Pod. **`ready` already *is* the shortcut for "serving and not terminating"**, and adding a
second condition would re-derive a value Kubernetes publishes — and would silently change meaning
for a Service with `publishNotReadyAddresses: true`.

**A `serving=true, ready=false, terminating=true` endpoint is not dead**, and Service proxies may
still route to such endpoints when every available endpoint is terminating. Where the set contains
only terminating endpoints, the finding's detail says so, because silence there would mislead.

**Association is authoritative and exhaustive**: the `kubernetes.io/service-name` label applied
server-side, plus the owner-UID check of §2.4. **No name prefix, no similarity, no IP matching, no
fuzzy label search, no heuristic.**

**`endpointslice.kubernetes.io/managed-by` does not gate admission.** A third-party-managed slice
carrying the authoritative association is a published backend, and excluding it would make
svcdoctor disagree with kube-proxy. The managing entity is recorded as a bounded observation when
it is not the built-in controller.

**`targetRef` is not required to count a ready endpoint** — a Service may legitimately publish
endpoints not backed by Pods — and is used only as a deduplication key. **`IPv4` and `IPv6` create
no semantic branch**, because first scope never connects; **`FQDN` is deprecated with no defined
semantics** and receives no interpretation of its own.

**Duplicates never inflate semantics.** An endpoint may legitimately appear in more than one slice
and dual-stack guarantees separate slices, so the ready test is an **existence** claim, and any
rendered count deduplicates by `targetRef` where present and `(addressType, address, port)`
otherwise.

### 2.7 C8 — exactly four findings

| | Code | Kind / severity / confidence | Claim |
|---|---|---|---|
| **F1** | `KUBERNETES_SERVICE_NOT_FOUND` | CONFIRMED / **ERROR** / HIGH | *"The Kubernetes API reported that no Service of this name exists in this namespace, at the time of this observation."* |
| **F2** | `KUBERNETES_API_ACCESS_DENIED` | CONFIRMED / **WARN** / HIGH, node state **UNKNOWN** | *"The Kubernetes API denied this run's identity the read it required; that measurement was not made."* |
| **F3** | `KUBERNETES_SERVICE_SELECTS_NO_PODS` | CONFIRMED / **ERROR** / HIGH | *"At the time of these API observations, this Service's selector matched no Pod in its namespace."* |
| **F4** | `KUBERNETES_SERVICE_NO_READY_ENDPOINT` | CONFIRMED / **ERROR** / HIGH | *"At the time of these API observations, Kubernetes published no ready endpoint for this Service."* |

**All four are CONFIRMED and none carries a `Discriminator`.** Each restates what an authoritative
source stated. **No hypothesis is created merely because Kubernetes is eventually consistent** —
eventual consistency bounds a claim's *scope*, not its *kind*.

**All four are `AuthorityDirect` at HIGH, and no new `Authority` value is added.** F3 and F4 are
**not** `AuthorityCompleteContrast`: they are not contrasts but restatements of one source under a
proven-complete enumeration, and reaching for complete-contrast would arm one of the two vacuous
`AdmitConfidence` guards that ADR 0087 requires to be armed together with `Miss`, in one
change-set.

**Severity is deterministic from evidence.** F2 is WARN with an `UNKNOWN` node because the target
did not fail and svcdoctor's measurement was blocked — the `REDIS_COMMAND_NOT_PERMITTED` shape
exactly. F3 is ERROR rather than WARN because its temporal risk is **low** — label matching is
evaluated by the API server at read time, not published by an eventually-consistent controller —
and because its impact is identical to F4's; two findings describing one impact at two severities
would make severity describe the route to the conclusion rather than the conclusion. **The
known true-but-intentional shape — a workload deliberately scaled to zero — is recorded rather
than argued away**: svcdoctor reports observed state and never violated intent (ADR 0083 §2.6).

**F2 carries the denied operation as a bounded svcdoctor-owned enum** — `SERVICE_GET`, `POD_LIST`,
`ENDPOINTSLICE_LIST` — and names it from a **closed map**, which is ADR 0069 §6's division applied
again: the class explains the kind of break, the sentinel explains which. Two denied reads produce
**two findings**, because the Detail differs and ADR 0081 §2.2b makes Detail a merge precondition.

**F4 carries two Detail variants from a closed two-value map** — *no associated slice was
published* and *slices were published and no endpoint among them is ready* — which are distinct
observations supporting one bounded conclusion and are **mutually exclusive by construction**, so
no fifth code is needed and no convergence hazard exists.

**Recommendations are `NEXT_EVIDENCE` only**, `VERIFY` for F1 and F2 and `COMPARE` for F3 and F4,
all `SelfCollectable: false`. **Forbidden permanently:** change the selector · restart Pods ·
delete or recreate the Service · increase replicas · edit RBAC · grant cluster-admin · modify a
NetworkPolicy. No `RESTART`, `DISRUPTIVE` or `SECURITY_WEAKENING` class is reachable
(ADR 0092 §2.8).

**Claim ceilings, forbidden permanently.** F1: *the Service was deleted* · *it never existed* ·
*the namespace is wrong*. F2: *RBAC is misconfigured* · *the ServiceAccount lacks the right Role* ·
**and never that the objects are absent**. F3: *the selector is wrong* · *the Deployment is
missing* · *the Pods crashed* · *traffic has no backend*. F4: *the Service is unreachable* ·
*clients cannot connect* · *the application is unavailable* · *the Pods are unhealthy* · *the
endpoint controller is broken* · **and any word implying persistence.**

**The wording is `publishes`, never `reachable`** (ADR 0093 §2.5), and the all-terminating routing
behaviour is a second, independent reason.

### 2.8 The access-versus-semantic taxonomy, and the admission rule

**F1 and F2 are acquisition findings** — statements about what svcdoctor could obtain. **F3 and F4
are semantic findings** — statements about what Kubernetes records. The two categories are never
collapsed.

> **A Kubernetes API failure earns a `FindingCode` only when the operator's first move differs
> from that of every other API failure, and the discriminating value comes from an API-contract
> enumeration rather than from a message.**

`NotFound` and `Forbidden` clear it and are `metav1.StatusReason` values. **A `401` does not**: it
is authentication, and it fails the `k8s.api_access` node with an existing auth failure class, no
Kubernetes finding, and `DIAG_FAILURE_BOUNDARY` localizing it. Every other API error — a `5xx`, a
timeout, a reset, a `410` — is an acquisition failure on its node with an existing `FailureClass`,
and produces no finding.

**API errors are normalized from structured information only** — HTTP status and
`metav1.StatusReason`, through `apierrors`. **`Status.Message`, `Status.details.causes[].message`
and every condition or status `message` are never read**, never matched, never parsed and never
interpolated.

### 2.9 Evidence, layers, short-circuiting and data minimization

**Five nodes, one subject, and no `Layer` value is added:**

```
k8s.target  L0  →  k8s.api_access  L5  →  { k8s.service, k8s.pod_set, k8s.endpoint_publication }  L6
```

L1–L3 are unused because transport belongs to the client library (ADR 0093 §2.10); L4 is unused
because the Kubernetes API has no separate capability-discovery step. Both absences are deliberate
and neither breaks the failure boundary, which needs only *a* PASS at a strictly lower layer.

**Short-circuiting is exact, and one branch failing never erases the other's evidence.** A
`NotFound` or `Forbidden` on the Service stops the two reads and blocks their nodes. A denied Pod
list withholds F3 **and the EndpointSlice read still runs**; a denied slice list withholds F4 **and
the Pod read still runs**. A selector-less or `ExternalName` Service runs neither read and produces
neither semantic finding. The Pod set and the slice set are **siblings under the Service node, not
a chain**, which is what makes the graph a DAG rather than a list.

**Sixteen normalized attributes, all closed types, no maps, no raw Kubernetes structs, no free
text.** A count is authoritative **only** when its set's completeness flag is true; otherwise it is
*observed so far*.

**No per-Pod evidence node exists.** MVP-D retains **no Pod name, UID, label, phase, readiness,
condition, container status, restart count, image, node name or IP**, because **no admitted finding
consumes a single Pod field**. This **narrows ADR 0093**, which said Pod state would be retained as
observation only, and the narrowing is the data-minimization rule applied honestly: retaining
identity for a rendering no diagnosis depends on is the debt ADR 0090 §7 refuses. It also removes
the renderer problem ADR 0093 recorded — with no per-Pod and no per-endpoint node, the report is a
single-path journey and **`terminal.serviceView` needs no change at all**.

**Also never collected:** annotations · label keys or values · Secret and ConfigMap contents ·
images · `containerID`/`imageID` · Pod IPs · `clusterIP` · endpoint addresses · node names ·
`resourceVersion` · the API server URL · filesystem paths. **`metadata.uid` is internal correlation
only** and never enters evidence; only the count of slices excluded by it does.

**Privacy needs no new mechanism.** Namespace, Service name and context are `AttrKindIdentity` —
whose definition already covers *"a named resource"* — so structural redaction transforms them by
dispatching on the kind, and nothing relies on terminal-only masking. Report-visible authority
facts are the auth **mode category**, kubeconfig-versus-in-cluster, and the **context name**;
never a token, key, certificate, exec argument, credential path or proxy URL.

**Deterministic ordering is mandatory:** slices by `(namespace, name)`, endpoints by
`(addressType, address, port)`, before any evidence is constructed. **A permuted API list must
produce byte-identical canonical JSON.**

### 2.10 Integration, and the counts that move

**No new top-level command.** `svcdoctor diagnose kubernetes …` is one `case` in the existing
switch, and `svcdoctor run --config` hosts it through the existing registry. **One declared
Service is one target and one report** through both entry points, with **no Kubernetes-specific
scheduler and no `if kubernetes` branch in any generic package** (ADR 0071 §6.3).

**ADR 0093's `Factory.DefaultPort` mismatch is closed here rather than deferred.** The Kubernetes
factory declares `DefaultPort() 443` and the target requires no `host` field, because the API
server's host **is derived** during decode — from the context's `server` URL, or from
`KUBERNETES_SERVICE_HOST` in-cluster — and `443` is that URL's default port. The generic contract
is satisfied without widening, and the Kubernetes target is a fleet citizen from day one.

**Generic-core isolation:** no Kubernetes library may be imported by `internal/domain`,
`internal/diagnosis`, `internal/fleet`, `internal/render`, `internal/probe`, `internal/security` or
`internal/cli`. `internal/adapter/kubernetes/client` is the sole importer — the boundary the four
`wire` packages already hold — and `internal/service/kubernetes` is a vocabulary leaf importing
only `internal/domain`. `depguard` gains the rules and a test asserts the sole-importer property,
as `TestOnlyTheConfigPackageImportsTheYAMLLibrary` already does for YAML.

**Counts:**

| | |
|---|---|
| `SchemaVersion` / `RunSchemaVersion` | **1 / 1 — unchanged** |
| `State`, `FindingKind`, `Confidence`, `Layer`, `SubjectKind`, `AttrKind`, `RecommendationKind`, `SafetyClass`, `Authority` | **unchanged — not one new member** |
| `FailureClass` | **42 — unchanged** |
| `FindingCode` | **65 → 69** — four service-namespaced codes, which ADR 0009 admits with no core change |
| production rules | **22 → 24** |
| `RuleContext` fields | **3 — unchanged** |
| `Reveal` / `SecretFor` | **4 → 5**, one per service |
| external modules | **2 → 2 + client-go's set**, recorded in `allowedModules` with reason and licence |

`Step` and `AttributeKey` are validated open strings by design, so new Kubernetes steps and
attributes expand no closed enum.

### 2.11 C9 — validation

**Layered, and no layer substitutes for another.** Unit tests are hermetic and cover nil semantics,
effective-ready, completeness, ordering, deduplication, selector serialization and hostile strings.
**A hermetic HTTP test server** covers pagination, `continue`, `410`, budget exhaustion,
401/403/404, owner-UID mismatch, objects changing between reads and cancellation — **a fake
clientset is not sufficient**, because it bypasses the transport, the pagination and the status
codes, which is most of what needs proving. **Real `kind`** covers actual API and controller
behaviour, real RBAC and the four findings.

**F4's fixture is a Deployment with at least one replica whose readiness probe always fails**, so
the controller publishes slices with `ready: false`. It is deliberately not built on a
zero-matching-Pod Service, which would test the fixture rather than the contract. **A
selector-less, an `ExternalName` and a headless Service are each their own real scenario**, and
**F2 is proven three times**, once per denied operation, each asserting the corresponding universal
finding is **absent**.

**No `sleep`.** Readiness is awaited by polling ground truth under a bounded deadline, and the
assertion is made against the state the poll confirmed — Phase 9.1C's fixture lesson applied.

**Minimum supported Kubernetes: v1.21**, derived rather than chosen: the EndpointSlice API is
stable from v1.21 and `conditions.ready` is available from it. `serving` and `terminating` are
stable only from **v1.26**, and the effective-ready test reads `ready` alone, so the floor holds;
the terminating count is a rendering-only observation and is simply absent on older servers.
**CI runs two `kind` versions**, the current stable minor and one older supported minor.

**No vendor branch is permitted and none is needed.** OpenShift, RKE2, k3s, EKS, GKE and AKS are
source-level compatibility reasoning, not a CI claim, and `docs/COMPATIBILITY.md` may grade none of
them until a fixture establishes it. **EKS, GKE and AKS are additionally gated by §2.2's exec
refusal**, and that limitation belongs in the compatibility document from the first release.

**Mutation:** 24 named plants, **zero survivors**, including `ready: nil` read as false, an
incomplete set emitting a zero claim, a denied read becoming an empty set, F3 on a selector-less
Service, a credential accepted for a Pod IP, and an `exec` kubeconfig not refused.
**Property and fuzz:** P1–P15, including that an `exec` config never executes, that credential
authority remains API-server-only, and that list permutation leaves canonical JSON unchanged.

### 2.12 Implementation split

**12.1B — client, authentication and acquisition:** the dependency and its allowlist, the
vocabulary leaf, the client package with the refusals and the single `Reveal`, the three bounded
reads, pagination, budgets, normalization and the target factory. **No finding, no rule, no CLI
command**, and **byte-identical reports for every existing service** — which makes 12.1C's diff the
entire behavioural change, the split ADR 0078's design used for 10.1a/10.1b.

**12.1C — diagnosis and presentation:** the two rules, F1–F4, the composition root, the CLI case
and the golden reports.

**12.1D — real-cluster closure:** `kind` fixtures, the seven scenarios, the two-version matrix and
the compatibility grading.

**One giant Kubernetes commit is refused.**

---

## 3. Consequences

**Phase 12.1A changes no production code, no test, no config, no fixture and no dependency.** Every
frozen count is unchanged at this commit: `SchemaVersion` 1, `RunSchemaVersion` 1, finding codes
65, rules 22, failure classes 42, `RuleContext` fields 3, modules 2, `Reveal` 4, `SecretFor` 4,
exit codes 5.

**Both of ADR 0093's blockers are closed, and neither by argument.** B1 is closed by the measured
refusal point; B2 is closed by an authorization whose cost is recorded and whose import surface is
enumerated.

**Two things were narrowed relative to ADR 0093, and both are recorded rather than smoothed away.**
Pod state went from *observation-only* to **not retained**, which also removed the renderer
question ADR 0093 left open. And **client certificates were added** as an authentication mode after
the fixture strategy proved that `kind` and `kubeadm` kubeconfigs need them — which **reopens
ADR 0072 §14 condition 1**, narrowly: the private key is secret material carried by
`security.Secret`; the certificate and CA bundle are public and are not.

**A published usability limit follows from §2.2 and must be documented from the first release:**
EKS, GKE and AKS kubeconfigs use exec plugins by default, so those clusters are reachable in first
scope only through in-cluster identity or an externally materialized token.

**One recorded principle must be amended by the implementing phase**, not merely renumbered:
`test/security/dependency_test.go`'s *"prevented in the only durable way, by choosing dependencies
that have none."*

**Phase 12.1B is an implementation exercise.** All fifty-one questions of the completeness table
have exactly one answer, and there are **zero open blockers**.

---

## 4. Alternatives considered

**Raw REST instead of client-go.** *Rejected on correctness.* The exec and auth-provider refusals
require parsing the same structures, and a hand-rolled parser that missed a field shape would
refuse nothing, silently. Reopened only if the authentication-mode set stays this small **and** the
binary size proves unacceptable in the OCI image — a measurement, not an argument.

**The full `Clientset` for convenience.** *Rejected.* It is a capability surface that turns every
guardrail in §2.1 into review discipline.

**Allowing exec auth behind a flag.** *Rejected.* ADR 0072 §13's reopen condition is *"None. This
is a decision, not a deferral."* A flag would reopen it by convenience rather than by review, and
no flag is created, named or reserved.

**Defaulting the context to `current-context` and reporting it.** *Rejected.* Reporting the choice
does not stop a `run --config` file from meaning different things on different machines, and the
failure mode is indistinguishable from a real finding.

**Retaining Pod phase and readiness as observations.** *Rejected on data minimization.* No admitted
finding consumes a Pod field; retaining identity for a rendering nobody's diagnosis depends on is
what ADR 0090 §7 refuses.

**Counting `serving` rather than `ready` for F4.** *Rejected.* `ready` already means *serving and
not terminating*, and substituting `serving` would silently change meaning for a Service with
`publishNotReadyAddresses: true`.

**Excluding third-party-managed EndpointSlices.** *Rejected.* A slice carrying the authoritative
Service association is a published backend, and excluding it would make svcdoctor's answer
disagree with kube-proxy's.

**A fifth code for "the Service has no EndpointSlice at all".** *Rejected.* It is one of two
mutually exclusive Detail variants of one bounded conclusion, and ADR 0093 froze the budget at
four.

**A dedicated code for `401 Unauthorized`.** *Rejected.* It is an acquisition failure with an
existing failure class, and `DIAG_FAILURE_BOUNDARY` already localizes it.

**A re-`GET` of the Service to guard the delete-and-recreate race.** *Rejected.* The owner-reference
UID gives the same guarantee for free, and ADR 0092's discipline about not adding network
operations without a reason applies.

**A per-response byte ceiling.** *Deferred and recorded as a known limitation.* client-go's typed
clients expose none, and obtaining one means replacing the transport.

---

## 5. Security implications

**The largest single security decision in this record is §2.2**, and it is a refusal: configuration
supplied by an operator, or by anyone who can write the file the operator points at, must not cause
svcdoctor to execute a local program. The refusal is issued **before the first API request**, which
measurement established is the earliest point at which the library would invoke a plugin, and it is
proven by a sentinel-file negative test rather than by a linker check.

**The second is §2.3's credential authority**, which is structural rather than a policy: a
Kubernetes credential binds to the API server's endpoint, so ADR 0028's existing check refuses it
for a Pod IP, a ClusterIP or any discovered address without any new mechanism.

**The dependency is a security decision and is recorded as one.** The repository's guard states
that *"svcdoctor transmits credentials, so every module in the build graph runs in the same process
as a plaintext password"*, and this record adds about 45 modules to that process. It is accepted
because the alternative — hand-written Kubernetes authentication and TLS assembly — is a worse
security bet, and it is accepted **explicitly**, with the count, the binary size and the newly
linked `os/exec` and `net/http` all written down.

**Impersonation, proxying and `insecure-skip-tls-verify` are refused** because each silently
changes authority, vantage or the verification svcdoctor exists to perform, and measurement showed
that impersonation and `proxy-url` propagate with **no error** — so silence would have been
indistinguishable from absence.

**No secret may reach evidence, a report, a renderer, an error, a panic or a log**, and one
`Reveal` site makes that auditable. **`Status.Message` and every condition message are never read**,
which keeps hostile status strings, ANSI and CRLF out structurally rather than by escaping.

---

## 6. Compatibility implications

**None from this record**, which changes no code. For the implementing phases: `SchemaVersion` and
`RunSchemaVersion` stay **1**; no closed vocabulary gains a member; finding codes go **65 → 69**
and rules **22 → 24**, both additive and service-namespaced; `Reveal` and `SecretFor` go **4 → 5**,
preserving the one-per-service invariant; and the module set gains client-go's, recorded in
`allowedModules`.

**Minimum supported Kubernetes is v1.21**, derived from the frozen field set. **No vendor-specific
API is used and no vendor branch is permitted.** `docs/COMPATIBILITY.md` may grade no distribution
until a fixture establishes it, and the exec limitation affecting EKS, GKE and AKS is documented
from the first release rather than discovered by a user.

---

## 7. Reopen conditions

| Item | Condition |
|---|---|
| Exec credential plugins | **ADR 0072 §13's own reopen condition, which is "None."** Changing it is a new record with its own security review, never a convenience |
| Raw REST instead of client-go | The authentication-mode set stays this small **and** the binary size proves unacceptable in the OCI image — measured, not argued |
| A fifth first-scope finding | A bounded operator question no admitted finding answers, whose discriminating value comes from an API-contract enumeration (§2.8's admission rule) |
| Pod or container findings | ADR 0093's condition, unchanged: an svcdoctor-owned exact-match `reason` allowlist whose every member has been observed on a real cluster |
| A per-response byte ceiling | A transport svcdoctor controls, or a measured case where the object bound proved insufficient |
| `serving`-based publication semantics | A record arguing why re-deriving what `ready` already means is safe, including for `publishNotReadyAddresses` |
| Concurrent Pod and EndpointSlice reads | A measured latency case that outweighs deterministic interleaving on three requests |
| A workload, Pod or Namespace target | Its own record; ADR 0093's MVP-D boundary is unchanged here |
| Cross-page `continue` consistency being relied upon | Verification from official documentation, which this phase could not obtain |
