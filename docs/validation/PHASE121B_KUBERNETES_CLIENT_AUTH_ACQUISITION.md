# Phase 12.1B — Kubernetes client, authentication and acquisition

**Status:** implemented, uncommitted. Nothing was staged, committed, pushed or tagged.

**Scope:** the first Kubernetes production implementation. The dependency and its allowlist, the
vocabulary leaf, the client package with the refusals and the single `Reveal`, the three bounded
reads, pagination, budgets, normalization, the evidence shape, the composition root and the fleet
target factory.

**Out of scope, deliberately:** the four Kubernetes findings, the two rules, the CLI command, and
real-cluster validation. Those are Phases 12.1C and 12.1D, and ADR 0094 §2.12 split them so that
12.1C's diff is the entire behavioural change.

---

## 1. Baseline

| | |
|---|---|
| Baseline commit | `ce5542c4245932170ecc9d6bf4046e4540f7ec49` |
| `origin/main` | `ce5542c4245932170ecc9d6bf4046e4540f7ec49` — identical |
| Starting tree | clean |
| Pre-change `make check` | **green** (exit 0) |
| Phase 12.1A | committed at `ce5542c`, ADR 0094 committed |

Contracts read in full before any edit: ADR 0094, `PHASE121A_KUBERNETES_ADAPTER_CONTRACT_FREEZE.md`,
ADR 0093, `PHASE120_KUBERNETES_ADAPTER_ARCHITECTURE_SCOPE_AUDIT.md`, and the repository contracts
governing configuration, the service registry, secrets, credential and endpoint authority,
multi-target execution, graph and evidence ownership, the canonical report, redaction and error
normalization.

---

## 2. The dependency, measured rather than estimated

**Pinned: `k8s.io/client-go`, `k8s.io/api`, `k8s.io/apimachinery`, all at `v0.36.4`** (Kubernetes
1.36). Apache-2.0.

The minor was chosen by measurement, not convention. With the same ten-path import surface:

| client-go | modules in `go.mod` | probe binary |
|---|---|---|
| v0.34.0 | 41 | 49,582,162 B |
| **v0.36.4** | **39** | **31,152,450 B** |
| v0.37.0 | 47 | 32,386,450 B |

v0.36.4 wins on both counts against the newest stable.

### 2.1 Deltas

| | Before | After |
|---|---|---|
| `go.mod` requirements | **2** | **40** |
| direct decisions | 2 | **3** (client-go, api, apimachinery) |
| transitive, recorded by name | 0 | **35** |
| `go.sum` lines | 4 | **117** |
| `cmd/svcdoctor` binary (`CGO_ENABLED=0`) | **10,310,258 B** | **38,494,066 B** (×3.73) |
| linked packages | **219** | **518** |
| `os/exec` linked | **no** | **yes** |
| `net/http` linked | **no** | **yes** |
| `crypto/tls` linked | yes | yes (unchanged) |
| `go` directive | `1.26` | **`1.26.0`** |

The `go` directive moved because all three Kubernetes modules declare `go 1.26.0`, and a main
module's directive may not be below its dependencies'. It is the same language version.

**No document presents the narrow import surface as a dependency-cost reduction.** Narrowing saved
one module and 0.55 MB against the wider surface; it is a reachability and hygiene decision, and
ADR 0094 §2.1 forbids describing it as anything else.

### 2.2 What is linked and what is imported — three different facts

| Package | module present | linked | imported by svcdoctor |
|---|---|---|---|
| `client-go/rest`, `tools/clientcmd`, `clientcmd/api`, typed `core/v1`, typed `discovery/v1` | yes | yes | **yes** — the allowlist |
| `k8s.io/api/core/v1`, `discovery/v1`, `apimachinery` meta/v1, api/errors, labels | yes | yes | **yes** — the allowlist |
| *(ten import paths in total; see §12.2)* | | | |
| `client-go/discovery` | yes | **yes** | **no** |
| `client-go/plugin/pkg/client/auth/exec` | yes | **yes** | **no** |
| `client-go/plugin/pkg/client/auth/{gcp,azure,oidc,openstack}` | yes | **no** | no |
| `client-go/kubernetes` (full Clientset), `dynamic`, `informers`, `listers`, `tools/cache`, `tools/watch` | yes | **no** | no |
| `controller-runtime`, `k8s.io/kubectl` | **no** | no | no |

Two of these matter and both are recorded rather than glossed:

- **`client-go/discovery` is linked**, transitively, through the typed clients' scheme. It is not
  imported and no discovery request is made — which is asserted **behaviourally** against a
  request-counting server, because a linker check cannot say it.
- **`plugin/pkg/client/auth/exec` is linked**, from `rest` itself, which is exactly what Phase 12.1A
  measured. `os/exec` being linked is not the same fact as svcdoctor executing a plugin, and
  compliance is defined behaviourally by the sentinel test in §5.

**No auth *provider* package is linked at all**, so ADR 0094 §2.2's "auth-provider fails closed
twice" holds: refused at parse, and inert because no provider is registered.

---

## 3. Production architecture

```text
internal/service/kubernetes/            vocabulary leaf: 5 steps, 17 attribute keys,
                                        4 auth modes, 5 service types. Imports internal/domain only.

internal/adapter/kubernetes/client/     the SOLE importer of every k8s.io library.
    target.go        the declared target and its validation
    kubeconfig.go    read, parse, refuse; file authority; token trimming
    authority.go     endpoint resolution, in-cluster, rest.Config, THE ONE Reveal
    acquire.go       the three reads, normalization, association, endpoint semantics
    paginate.go      the bounded pagination primitive
    budgets.go       the frozen ceilings
    result.go        svcdoctor-owned result model and closed vocabularies
    apierror.go      structured API error normalization

internal/adapter/kubernetes/            acquisition result -> evidence. Imports no k8s.io package.

internal/app/kubernetes.go              DiagnoseKubernetes, KubernetesTarget, InspectKubernetesTarget

internal/fleet/services/kubernetes/     the config.Factory, config.EndpointDeriver and run.Runner
```

Generic edits, and there are exactly three:

| File | Change |
|---|---|
| `internal/fleet/config/registry.go` | the `EndpointDeriver` optional interface; the `Factory` doc comment amended |
| `internal/fleet/config/load.go` | consult it; refuse a written host/port for such a target; validate the derived endpoint |
| `internal/cli/run.go` | one entry in each of the two registries |

**No generic package names Kubernetes.** `TestNoKubernetesSpecialCaseExistsInAnyGenericPackage`
and the pre-existing `TestTheGenericCoreNamesNoService` both hold.

---

## 4. The target, and the one contract mechanism that had to be invented

### 4.1 The shape

```yaml
- id: payments-api
  type: kubernetes
  config:
    kubeconfig: /etc/svcdoctor/kubeconfig    # XOR in_cluster
    context: prod-eu                          # mandatory with kubeconfig
    namespace: payments                       # mandatory
    service_name: payments-api                # mandatory
```

No selector, no Pod, no workload, no wildcard, no regexp, no Service list, no all-namespaces mode
— each a field that does not exist.

### 4.2 `EndpointDeriver`, and why the generic core moved at all

ADR 0094 §12.1 froze the outcome — `DefaultPort() 443`, **no `host` field**, "the generic
`Common.Host` requirement is satisfied by the resolved API server host, derived during decode" —
without naming a mechanism. `load.go` refuses an empty host before `Decode` runs, so the outcome
was not reachable without a seam.

The seam is a **service-neutral optional interface** on `config.Factory`. A factory that implements
it declares that its targets name no endpoint; the loader then refuses a written `host` or `port`
(ADR 0060: an inert input is refused, not accepted), and after `Decode` asks the factory for the
endpoint and validates it through **the same `checkHostSyntax` a written host goes through**.

**The host requirement is satisfied, not relaxed**, and nothing downstream — preflight, credential
binding, the scheduler, the runner — can tell a derived endpoint from a written one.

### 4.3 Two recorded narrowings against ADR 0094 §12.1

**(a) In-cluster mode derives `kubernetes.default.svc:443` and not `KUBERNETES_SERVICE_HOST`.**

ADR 0094 §12.1 names the environment variable as the in-cluster derivation. Doing that at decode is
impossible without breaking a stronger invariant: `test/security/fleet_boundary_test.go`'s
`TestOnlyTheResolverReadsTheEnvironment` confines every environment read in the configuration path
to `internal/fleet/secret`, and ADR 0071 §8.3 refuses ambient configuration outright. A
configuration must also be checkable on a laptop, where the variable does not exist.

So the **logical** endpoint is the API Service's own fully qualified name, which is true in every
cluster and is not an invention; the **connection** is made to `KUBERNETES_SERVICE_HOST`, read
inside the adapter at execution, which is where file and environment authority already live. That
is ADR 0028's logical-endpoint rule applied unchanged: one lookup producing an address does not
produce a second authority. The name is also what TLS verifies, which is stronger than trusting
whichever SAN happens to cover the cluster IP.

A target credential is **refused** in in-cluster mode, so no credential is ever bound to that
endpoint by the fleet resolver.

**(b) `Decode` reads the kubeconfig, and the `Factory` doc comment was amended rather than bent.**

It said *"none of them performs I/O"*. A Kubernetes target's authority **is** a file, and three
things are only knowable from it: whether the target is usable, which API server it resolves to,
and whether it carries a refused construct. Deferring that to execution would make an `exec`
kubeconfig one target's execution failure at **exit 4** rather than a configuration error at
**exit 2** with nothing dialled — the exact defect Phase 9.1C found in the credential path.

`internal/fleet/config` still opens exactly one file, the configuration document. The *service
factory* reads what its own target names, which `internal/fleet/services` already does at preflight
through `trustsource.Load`.

**(c) The attribute count in the frozen record was internally inconsistent, and the enumeration
wins.** Resolved in the review pass; see §12.1.

**(d) "Associated by label alone" is not recorded.** §7.3 says a slice with no Service owner
reference is included and *"the fact that it was associated by label alone is recorded as a bounded
attribute"* — but §11.1's table has no key for it. Such slices **are** included, as required; the
disclosure is not recorded, because adding an eighteenth key would be inventing one. Deferred to
12.1C with its own decision.

---

## 5. Security: the refusals, and where they happen

```text
read the kubeconfig -> clientcmd.Load -> inspect the selected cluster and user
    -> REFUSE if any prohibited construct is present
    -> (only then) build rest.Config -> build typed clients -> issue requests
```

`clientcmd` is used **only to parse**. The `rest.Config` is assembled by hand from validated
fields, so `ExecProvider` and `AuthProvider` are **never populated on any path** — a refusal that
failed to fire could not produce a configuration capable of executing anything.

| Construct | Refused | Guard | Requests reaching the server |
|---|---|---|---|
| `exec` | yes | sentinel file **and** zero-request count | **0** |
| `auth-provider` | yes | named construct | **0** |
| `as` / `as-groups` / `as-uid` / `as-user-extra` | yes | named construct | **0** |
| `proxy-url` | yes | named construct, value never repeated | **0** |
| `insecure-skip-tls-verify` | yes | named construct | **0** |
| `username`/`password` | yes | named construct | **0** |
| no credential at all | yes | anonymous refusal | **0** |
| two credentials | yes | ambiguity refusal | **0** |
| a credential bound elsewhere | yes | svcdoctor's own message | **0** |
| `http://` API server | yes | scheme refusal | **0** |

### 5.1 The exec sentinel test — **PASS**

`TestAnExecKubeconfigNeverExecutesAnything`. The kubeconfig declares an exec plugin whose command is
**the test binary itself**, re-invoked with `-test.run=TestExecCredentialPluginHelper` and an
environment variable naming a sentinel path. The helper writes the file if it is ever run.

Cross-platform by construction: a `/bin/sh` command would prove nothing on Windows, and mocking the
call away would test the mock.

Three assertions together, none sufficient alone: every entry point (`Inspect`, `Connect`,
`Acquire`) refuses; **the sentinel does not exist**; and the API server counted **zero** requests —
which is what makes "before the first request" a measurement rather than a claim about ordering.

### 5.2 The refusal never repeats what it refused

`TestTheRefusalNeverRepeatsTheConstructsContents` plants a distinctive command, argument,
environment name and value, and requires none of them in the message. `proxy-url` gets its own test
because a proxy URL can carry credentials in its userinfo.

### 5.3 Environment proxy — neutralized

`rest.Config.Proxy` is set to a function that selects no proxy, so client-go never falls back to
`net/http`'s environment support.

**Proven twice, and the second test exists because the first is not sufficient.** The behavioural
test sets hostile `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` and requires the acquisition to still reach
the server in exactly three requests. That test **cannot fail**: Go never proxies a loopback
address whatever the environment says, and the hermetic fixture is on 127.0.0.1. The mutation
harness found it — the plant survived — so
`TestTheRESTConfigAlwaysSetsAnExplicitDirectProxy` asserts the structural fact: `Proxy` is non-nil
and returns no URL for a **routable** host with `HTTPS_PROXY` set.

**Recorded limitation:** the behavioural half is loopback-bound and a real routable-address proof
belongs to Phase 12.1D.

### 5.4 Credential authority — **API SERVER ONLY**

`TestACredentialIsBoundToTheAPIServerAndNothingElse` builds the credential the client would use and
asks it for its secret at a Pod IP (`10.244.1.7:8080`), a cluster IP (`10.96.0.10:443`), an IPv6
endpoint (`[fd00::1]:6443`) and another service's endpoint (`orders-db.internal:5432`). All four are
refused with `security.ErrEndpointMismatch`.

It is structural: `security.Credential` has no accessor returning the secret without naming an
endpoint, and only one endpoint matches. **No new mechanism was added.**

`SecretFor` and `Reveal` are each called exactly once, in `applyCredential`.

### 5.5 Authentication modes — all four implemented and exercised

| Mode | Source | Test |
|---|---|---|
| `TOKEN` | target credential reference, or an inline kubeconfig `token:` | whole acquisition against the hermetic server |
| `TOKEN_FILE` | kubeconfig `tokenFile`, **read by svcdoctor** | whole acquisition |
| `CLIENT_CERT` | `client-certificate[-data]` + `client-key[-data]` | whole acquisition |
| `IN_CLUSTER` | projected token + CA, **read by svcdoctor** | whole acquisition through an injected source |

`rest.Config.BearerTokenFile` is **never set**, in either file-backed mode. That declines
client-go's token-refreshing transport deliberately: a refresh is a reread on a schedule svcdoctor
does not control, inside a process that runs once and exits.

**An inline kubeconfig `token:` is accepted and classified `TOKEN`.** ADR 0094 §2.3 names four
modes and lists what is refused; an inline token is in neither list. It is a bearer token in a file
svcdoctor already reads, under the same secret discipline as `tokenFile`, and refusing it would be
a usability cliff with no security argument. Recorded as an implementation reading of a gap.

**Exactly one credential** may be declared between the target and the selected kubeconfig user.
Two is refused rather than ranked — a configuration that authenticates as whichever credential a
tool prefers is one nobody can audit.

### 5.6 Only the selected context is reachable

A kubeconfig legitimately holds several contexts, and refusing a whole document because an unrelated
context uses `exec` would make svcdoctor unusable on the machines it is most needed on. The
refusals are scoped to the selected context, and what makes that safe is that the connection is
assembled by hand from that context's fields: no unselected cluster, user or context is reachable.
`TestOnlyTheSelectedContextIsEverReached` proves both halves against one file whose
`current-context` is the exec-based one.

### 5.7 File authority

Authorized: the kubeconfig, a token file, a client certificate and key, a CA bundle, and in-cluster
the two standard projected paths. **No path from remote API data is ever opened.** Every read is
size-bounded (kubeconfig 4 MiB, PEM/token 1 MiB), refuses a directory, refuses an empty file, and
re-checks the size after reading so a file that grew is refused rather than truncated. Messages name
the **resolved** path. **No filesystem path reaches canonical evidence** — asserted by serializing
the graph and searching it.

---

## 6. Acquisition

### 6.1 The request sequence, and its exact shape

```text
GET  /api/v1/namespaces/<ns>/services/<name>
LIST /api/v1/namespaces/<ns>/pods
       ?labelSelector=<the Service's own selector>&limit=500
LIST /apis/discovery.k8s.io/v1/namespaces/<ns>/endpointslices
       ?labelSelector=kubernetes.io/service-name=<name>&limit=500
```

Asserted against a recording server: method, path, both label selectors, both limits, the absence
of `watch` and `resourceVersion`, and that a continue token is propagated **byte for byte** with
every other parameter identical.

Selector serialization is `k8s.io/apimachinery/pkg/labels`, never hand-built.

### 6.2 Request counts, measured

| Scenario | requests |
|---|---|
| client construction alone | **0** — no discovery, no version negotiation |
| nominal run | **3** |
| selector-less Service | **1** |
| `ExternalName` Service | **1** |
| unrecognized `spec.type` | **1** |
| any refused kubeconfig construct | **0** |
| cancelled before the first read | **0** |
| worst case against an endless server | **17** — exactly `1 + 8 + 8` |

### 6.3 Branch independence

A denied Pod list leaves the EndpointSlice evidence intact, and vice versa. Both directions are
tested: the surviving branch is `Complete()` with its counts, and the denied one is neither complete
nor empty.

### 6.4 Service semantics

| Type / shape | Reads issued | Notes |
|---|---|---|
| selector-backed `ClusterIP` | 3 | |
| headless (`clusterIP: None`) | 3 | never a failure |
| selector-backed `NodePort` | 3 | no node-level claim |
| selector-backed `LoadBalancer` | 3 | no `status.loadBalancer` claim |
| selector-less (nil **or** empty map) | 1 | both lists `SKIPPED`, run **not** incomplete |
| `ExternalName` | 1 | unsupported, not a failure |
| unrecognized type | 1 | never unlocks behaviour |
| `spec.type: ""` | 3 | the API's own declared default is `ClusterIP` |

**An empty selector map is selector-less, never match-all.** That case cannot be delivered by any
HTTP fixture — `json:"selector,omitempty"` omits it and it decodes as nil — so it is pinned by a
direct test of the normalizer. The mutation harness found this: a `!= nil` plant survived every
end-to-end test.

### 6.5 EndpointSlice association

Label **plus** owner-UID, and the owner's **name is never consulted**:

| Slice | Outcome |
|---|---|
| Service owner UID matches | admitted |
| Service owner, different UID | **excluded and counted** |
| no owner reference | admitted by label |
| non-Service owner | ignored, admitted by label |
| Service owner in another API version | ignored, admitted by label |
| several owners | the Service one decides |

No re-`GET` is added. Excluding a slice does not make the enumeration incomplete: it was enumerated
and found not to belong.

`endpointslice.kubernetes.io/managed-by` does **not** gate admission. A third-party manager is
disclosed as a boolean; its name never reaches a normalized value.

### 6.6 Endpoint semantics

```text
ready       nil => true
serving     nil => true
terminating nil => false
effectiveReady := ready alone
```

All nine combinations are asserted directly and exhaustively by fuzz. The
`serving=true, ready=false, terminating=true` shape is not ready and is **not dead**: it is counted
as not ready, its termination is counted separately, and nothing else is said about it.

Deduplication is by `targetRef` where present and by `(addressType, addresses, ports)` otherwise. A
dual-stack backend published in two slices counts once.

### 6.7 Pagination and completeness

Every stop reason is exercised end to end:

| Shape | `Complete()` | Stop |
|---|---|---|
| one page, nothing left | true | `COMPLETE` |
| three pages followed | true | `COMPLETE` |
| exactly the page ceiling, nothing left | **true** | `COMPLETE` |
| page ceiling with a token outstanding | false | `INCOMPLETE_PAGE_LIMIT` |
| object budget with a token outstanding | false | `INCOMPLETE_OBJECT_LIMIT` |
| endpoint budget reached | false | `INCOMPLETE_ENDPOINT_LIMIT` |
| slice budget reached | false | `INCOMPLETE_OBJECT_LIMIT` |
| `410` on page 3 | false | `INCOMPLETE_RESOURCE_EXPIRED` |
| `5xx` on page 2 | false | `INCOMPLETE_REQUEST_FAILED` |
| `403` on page 2 | false | `INCOMPLETE_REQUEST_FAILED` |
| cancelled mid-enumeration | false | `INCOMPLETE_CANCELLED` |
| skipped | **false** | — |

**A `410` is never restarted.** A third page is scripted and never consumed; consuming it would
prove a restart.

**Incomplete never becomes zero.** A denied first page reports zero observed **and**
`Complete() == false`, and the completeness flag is what stops the count becoming a universal claim.
`StopReason`'s own names carry `INCOMPLETE_`, asserted, so the vocabulary cannot be misread.

### 6.8 Cancellation

Cancelled before the first read: **0 requests**, `APIAccess` skipped, run incomplete. Cancelled
mid-pagination: the set is incomplete and no further round trip is issued — proven by counting
`fetch` calls in a direct test of `paginate`, because a request issued on a dead context fails at
the transport and reaches the same *outcome* by a different route. The mutation harness found that
gap.

### 6.9 Retries — none, and client-go's own behaviour

svcdoctor implements **no retry**. A `429` produces exactly one request, asserted.

The REST stack's own behaviour was inspected rather than assumed: `rest.Config.Timeout` is left at
zero and every call carries the run's context, so there is no independent deadline. No client-side
rate limiter is configured. Nothing observed in the hermetic suite issued more requests than
svcdoctor asked for — the worst case is exactly 17, measured, which would not hold if the transport
were retrying.

**Known limitation:** this is a behavioural observation over the hermetic suite, not a source proof
that no client-go path can ever retry. A real-cluster measurement belongs to Phase 12.1D.

### 6.10 Cross-page `continue` — **verified this phase**

Phase 12.1A could not obtain this and designed conservatively around not knowing. It is now
verified from official sources, and the answer is **stronger** than the assumption:

- `kubernetes.io` API concepts: *"the `resourceVersion` of the collection remains constant across
  each request, indicating the server is showing you a consistent snapshot of the pods."*
- `metav1.ListOptions.Continue`: *"clients may only use the continue value from a previous query
  result with identical query parameters (except for the value of continue)"*, and an invalid token
  *"whether due to expiration (generally five to fifteen minutes) or a configuration change on the
  server"* is answered with *"a 410 ResourceExpired error"*.
- `metav1.ListMeta.Continue`: *"Continuing a consistent list may not be possible if the server
  configuration has changed or more than a few minutes have passed."*

**No behaviour changed.** svcdoctor already sent identical parameters across pages (now asserted),
already refused to restart on a `410`, and already relied on completeness rather than atomicity.
What changed is the reasoning: a `410` now means precisely *this snapshot cannot be continued*,
which is why restarting would present two snapshots under one completeness flag.

**The guarantee is scoped to one list operation.** It says nothing across the three, which are three
separate moments — which is why no claim spans them.

Sources: `https://kubernetes.io/docs/reference/using-api/api-concepts/` (fetched via the
`kubernetes/website` source, because the rendered page truncates before the section — the same
truncation Phase 12.1A hit) and
`k8s.io/apimachinery/pkg/apis/meta/v1/types.go`.

### 6.11 Response byte size — unchanged known limitation

`limit` bounds objects, not bytes, and client-go's typed clients expose no per-response ceiling.
Bounded: objects per page (500), pages per list (8), Pods (4,000), slices (256), endpoints (10,000),
round trips (17). Recorded in `docs/SECURITY.md`. A byte ceiling needs a transport svcdoctor
controls.

---

## 7. The normalized model

`Result` is svcdoctor's own type throughout: scalars, closed enums and structs of those. **No
Kubernetes API struct is reachable from it.** Each decoded object is read for the fields below and
discarded.

Closed vocabularies, each pinned by name and count:

| Vocabulary | Members |
|---|---|
| `Operation` | `SERVICE_GET`, `POD_LIST`, `ENDPOINTSLICE_LIST` (+ `NONE`) |
| `Failure` | 12, from HTTP status, `metav1.StatusReason`, typed context errors and typed `crypto/x509` errors |
| `StopReason` | 7, six of which carry `INCOMPLETE_` |
| `SkipReason` | 6 |

### 7.1 Structured API errors only

Classified from the HTTP status code and `metav1.StatusReason` through `apierrors`, and from typed
`context` and `crypto/x509` errors. **`Status.Message`, `Status.details.causes[].message` and every
condition message are never read** — enforced by an AST guard over the three Kubernetes packages,
because a behavioural test cannot state a property about the source and a plant that branched on the
message survived every behavioural test.

| Input | Failure | Node state | Failure class |
|---|---|---|---|
| 401 | `UNAUTHORIZED` | **FAIL** | `AUTH_CREDENTIALS_REJECTED` |
| 403 | `FORBIDDEN` | **UNKNOWN** | `AUTHZ_NOT_PERMITTED` |
| 404 | `NOT_FOUND` | **FAIL** | `RESOURCE_NOT_FOUND` |
| 410 | `RESOURCE_EXPIRED` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` |
| other API status | `API_ERROR` | UNKNOWN | `PROTOCOL_UNEXPECTED_RESPONSE` |
| no response | `TRANSPORT` | FAIL | `TCP_CONNECTION_FAILED` |
| x509 unknown authority / hostname / expired | three values | FAIL | matching TLS classes |
| deadline / cancellation | `TIMEOUT` / `CANCELLED` | UNKNOWN | `EXEC_LOCAL_TIMEOUT` / `EXEC_CANCELLED` |
| budget or page ceiling | — | UNKNOWN | `EXEC_DEPTH_LIMIT` |

**A 403 is UNKNOWN, not FAIL.** The target did not fail; svcdoctor's measurement was blocked, and
every universal claim over the set it would have produced is withheld. Collapsing that into FAIL is
the single worst mistake this contract exists to prevent, and it is a planted mutation.

An unrecognized reason or an arbitrary error string can never become `NOT_FOUND` or `FORBIDDEN` —
the two states 12.1C's findings are built on. Asserted directly and by fuzz.

**One judgement recorded:** classifying a TLS verification failure from typed `crypto/x509` errors
is more than ADR 0094 required (*"an acquisition failure with an existing FailureClass"*). A CA that
does not belong to the cluster a kubeconfig names is the most common Kubernetes target failure, and
reporting it as an unclassified transport failure would send an operator to the network when the
answer is in the file they are holding. No `crypto/tls` import is used; client-go builds the TLS
configuration from `CertData`/`KeyData`.

### 7.2 Evidence

```text
k8s.target  L0  ->  k8s.api_access  L5  ->  k8s.service  L6
                                                ->  k8s.pod_set              L6
                                                ->  k8s.endpoint_publication L6
```

**Five nodes, always**, whatever happened — a graph whose shape changed with the outcome would make
"the read did not happen" indistinguishable from "the read was never part of this run". One subject,
`service/<namespace>/<name>`, at `SubjectKindTarget`. **No `SubjectKind` was added.**

Pod set and endpoint publication are **siblings under the Service node**, which is what makes the
graph a DAG and what lets one branch fail without erasing the other.

**No per-Pod and no per-endpoint node.** A 4,000-backend Service produces the same five nodes as an
empty one, asserted.

Seventeen attributes, exactly the enumerated set **and exactly the frozen table's node column**,
asserted per node with counts. `k8s.target` carries **none** — the subject already states what was
asked for, which is ADR 0042 §6's rule for the transport anchor applied here. Namespace, Service
name and context are `AttrKindIdentity`; the auth mode is a plain string because it is a category
svcdoctor declared, not a name from the environment.

On `k8s.service` the namespace and the Service name are recorded **unconditionally**, because they
are inputs the target declared rather than observations — and the run whose Service read was denied
is the one whose reader most needs them. The four Service *observations* are recorded only when the
read succeeded.

A skipped enumeration records **no count at all** — not zero with a flag, no observation — and is
`Unmeasured` rather than instantaneous. A skipped stage carries a `blockedBy` edge to what stopped
it.

### 7.3 Determinism

Slices sort by `(namespace, name)`; endpoints within a slice sort by their address/targetRef key.
Both are asserted by permutation **under the endpoint ceiling**, which is the only shape where the
ordering is observable — the mutation harness found that a slice-level permutation leaves the
endpoint sort untested.

The same acquisition result produces byte-identical canonical JSON across repeated runs.

---

## 8. Integration

### 8.1 No finding, and it is guarded

`DiagnoseKubernetes` wires **no rule at all**. A Kubernetes run produces a complete evidence graph
and **zero findings**, asserted. `test/security/kubernetes_boundary_test.go` fails the build if the
Kubernetes packages mention `NewFinding`, `FindingCode`, a severity, a confidence or a
recommendation, and if any of the four `KUBERNETES_*` codes appears anywhere in production source.

### 8.2 Fleet

Registered as one entry in each of the two registries in `internal/cli/run.go`. Verified end to end:
a configuration with a Kubernetes target parses, preflights, resolves credentials, schedules,
diagnoses, renders in text and JSON, and redacts to a shareable report.

Mixed-fleet ordering is unchanged and deterministic across repeated loads. The four existing
services decode with unchanged defaults through the five-factory registry.

### 8.3 CLI

**No new command.** `svcdoctor --help` and `svcdoctor diagnose --help` are byte-unchanged: the
service list under `diagnose` still names four. `run --config`'s unsupported-service message now
lists `kubernetes`, which is the registry doing its job.

### 8.4 Renderer

**Zero renderer files changed.** An unknown `ServiceID` gets the zero `serviceView`, and every
consumer of it is total on that. A Kubernetes report renders its header, its (empty) findings block
and its Result block, including the failure-boundary line.

---

## 9. Frozen counts

| | Before | After |
|---|---|---|
| `domain.SchemaVersion` | 1 | **1** |
| `domain.RunSchemaVersion` | 1 | **1** |
| finding codes | 65 | **65** |
| production rules | 22 | **22** |
| failure classes | 42 | **42** |
| `State`, `FindingKind`, `Confidence`, `Layer`, `SubjectKind`, `AttrKind`, `RecommendationKind`, `SafetyClass`, `Authority` | — | **not one new member** |
| `RuleContext` fields | 3 | **3** |
| exit codes | 5 | **5** |
| `security.Reveal` production call sites | 4 | **5** — one per service |
| `Credential.SecretFor` production call sites | 4 | **5** |
| external modules | 2 | **40** |
| renderer files changed | — | **0** |

---

## 10. Validation

### 10.1 Unit, property and hermetic tests

New test files: `target_test.go`, `security_test.go`, `acquire_test.go`, `pagination_test.go`,
`publication_test.go`, `incluster_test.go`, `vocabulary_test.go`, `fuzz_test.go`,
`fixtures_test.go` (client); `evidence_test.go` (adapter); `kubernetes_test.go` (app);
`kubernetes_test.go` (fleet service); `kubernetes_boundary_test.go` (security).

The hermetic API server is a real TLS `httptest` server with scripted pages, scripted statuses,
request recording and a response hook. **A fake clientset was not used**, per ADR 0094 §2.11: it
bypasses the transport, the pagination and the status codes, which is most of what needed proving.

### 10.2 Frozen properties P1–P15

| | Property | Where |
|---|---|---|
| P1 | arbitrary free text never strengthens a normalized state | `TestAnArbitraryErrorNeverBecomesAStrongerState`, `FuzzStatusNormalization` |
| P2 | `Status.Message` never enters canonical output | `TestNoKubernetesSourceReadsAStatusMessage` (structural), `TestAHostileStatusMessageNeverReachesTheResult` |
| P3 | arbitrary labels never enter output | `TestTheAttributeSetIsExactlyWhatWasFrozen`, `FuzzHostileSliceMetadata` |
| P4 | list permutation leaves output unchanged | two permutation tests, slice-level and endpoint-level |
| P5 | duplicates do not inflate semantics | `TestDuplicateEndpointsNeverInflateACount` |
| P6 | incomplete never becomes universal or zero | `TestAnIncompleteEnumerationIsNeverZero`, `TestOnlyACompleteEnumerationAdmitsAUniversalClaim` |
| P7 | nil conditions follow the contract | `TestTheNilConditionSemanticsAreExactlyTheFrozenOnes`, `FuzzEndpointConditionNormalization` |
| P9 | selector-less never becomes selector-zero | `TestASelectorLessServiceIssuesNeitherListAndIsNeverMatchAll`, `TestNormalizeServiceReadsAnEmptyMapAsSelectorLess` |
| P10 | hostile names inject no ANSI/CRLF | `TestTheTargetShapeIsExactlyWhatWasFrozen`, `FuzzKubernetesNameValidation` |
| P11 | secrets never serialize | `TestTheReportTargetIsTheServiceAndNotTheAPIServer`, `FuzzKubeconfigSecurityValidation` |
| P12 | exec config never executes | `TestAnExecKubeconfigNeverExecutesAnything` (sentinel) |
| P13 | credential authority is API-server-only | `TestACredentialIsBoundToTheAPIServerAndNothingElse` |
| P14 | cancellation stops pagination | `TestPaginationIssuesNoRequestOnADeadContext`, `TestPaginationStopsBetweenPagesWhenTheBudgetEnds` |
| P15 | budget exhaustion marks incomplete | `TestEveryWayAnEnumerationCanStop` and the two budget tests |

P8 is not a Phase 12.1B property (it belongs to the findings).

### 10.3 Fuzzing

Five targets, **45 seconds each**, all passing:

| Target | execs | new interesting |
|---|---|---|
| `FuzzKubeconfigSecurityValidation` | 97,939 | 165 |
| `FuzzKubernetesNameValidation` | 55,731 | 42 |
| `FuzzStatusNormalization` | 805,459 | 7 |
| `FuzzEndpointConditionNormalization` | 716,165 | 8 |
| `FuzzHostileSliceMetadata` | 681,849 | 1 |

No panic, no leak, no execution, no crasher. The corpus lives in the build cache; **no
`testdata/fuzz` file was added**.

### 10.4 Mutation closure

`scripts/phase121b-mutations.sh`, **41 plants**, every one in production code, with a zero-match
guard and byte-for-byte tree restoration.

**The first run caught 34 of 41.** Every one of the seven survivors was a real gap in the guards,
and each is recorded because the fix is the interesting part:

| | Survivor | Why it survived | Fix |
|---|---|---|---|
| K-M06 | ambient proxy inherited | Go never proxies loopback, so the hermetic fixture cannot see it | added the structural `rest.Config.Proxy` assertion |
| K-M11 | credential silently rebound | `SecretFor` refuses it too and its message shares the matched words | assert svcdoctor's own sentence, which only the early check produces |
| K-M12 | empty selector as match-all | `json:"selector,omitempty"` means an empty map cannot cross the wire | added a direct normalizer test |
| K-M22 | 410 restarts | a shell/Python escaping bug — **unplantable**, correctly reported | fixed the escaping |
| K-M23 | cancellation ignored | a request on a dead context fails at the transport, same outcome | count `fetch` calls in a direct `paginate` test |
| K-M30 | `Status.Message` read | the added branch was unreachable for the tested inputs, and an enum has no room to carry a string | replaced with an AST guard over the source |
| K-M37 | list order reaches output | the permutation was over slices, leaving the endpoint sort untested | added an endpoint-level permutation under the ceiling |

An earlier K-M02 was also **withdrawn as malformed**: it suppressed `loadKubeconfig`'s error and
reached `kubeconfigView.endpoint` with a zero view, measuring a nil dereference rather than the
property. It exposed a latent nil path, which is now **guarded in production**, and was replaced by
a plant on `Connect`'s re-validation.

**Final: 41 planted / 41 caught / 0 survivors.** Tree restored byte-for-byte. Re-run after the review pass changed production code; see §12.2a for the one plant that had to be re-anchored.

### 10.5 Commands run

```text
git rev-parse HEAD / origin/main / git status --short
make check                                   (baseline, green)
go build ./...
go vet ./...
golangci-lint run ./...
go test ./...
go test ./internal/adapter/kubernetes/... -count=1
go test ./internal/app/ ./test/security/ -count=1        (x5)
go test ./internal/fleet/... -count=1
go test -race ./internal/adapter/kubernetes/... ./internal/app/ ./internal/fleet/...
go test ./internal/adapter/kubernetes/client -fuzz=<each of five> -fuzztime=45s
./scripts/phase121b-mutations.sh
make check                                   (final, green)
git diff --check
CGO_ENABLED=0 go build -o … ./cmd/svcdoctor  (before and after, for the size delta)
go list -deps ./cmd/svcdoctor                (before and after, for the package delta)
svcdoctor --help / diagnose --help / run --help
svcdoctor run --config …                     (text, json, --shareable)
```

Deliberate falsification runs: each new architectural guard was verified against a planted
violation and then restored — the k8s import boundary, the nine-package allowlist, the finding-code
absence, and the endpoint-order property.

### 10.6 Integrations not run, and why

`integration-kafka`, `integration-postgres`, `integration-redis`, `integration-valkey`,
`integration-rabbitmq`, `integration-lavinmq`, `integration-redpanda` and
`integration-multitarget` were **not run**. Each needs Docker and minutes; none is part of
`make check`; and this phase changed **no** production code any of them exercises — the three
generic edits are additive and are covered by the hermetic fleet suites that `make check` runs.

**No `kind` cluster was run.** ADR 0094 §2.12 assigns real-cluster closure to Phase 12.1D, and
nothing here claims a validated distribution: `docs/COMPATIBILITY.md` is **unchanged** and grades no
Kubernetes distribution.

---

## 11. Known limitations

1. **A Kubernetes target exits 0 whatever it observed.** No rule is wired, so an unreachable API
   server, a missing Service and a denied read all produce `SummaryStatus OK` and exit 0. That is
   the phase split working as ADR 0094 §2.12 designed it, and it is the single most important thing
   12.1C changes. The README says "no diagnosis yet" for exactly this reason.
2. **The environment-proxy behavioural test is loopback-bound** and cannot fail; the structural test
   carries the property. A routable-address proof belongs to 12.1D.
3. **client-go's retry behaviour is established behaviourally**, over the hermetic suite, not by
   source proof.
4. **Response byte size is not bounded** (ADR 0094 §9.3), unchanged.
5. **"Associated by label alone" is not recorded**, because the frozen attribute table has no key
   for it (§4.3d).
6. **A shareable Kubernetes subject is pseudonymized into the *host* namespace** — `host-002` for
   `service/payments/payments-api` — because `redactSubject` treats every subject reference as an
   endpoint. Identity is removed and correlation survives, so this is cosmetic; giving Kubernetes
   subjects the identity namespace would be the new redaction mechanism ADR 0094 §11.3 says is not
   needed.
7. **`internal/platform/kubernetes` is still empty.** This phase adds no platform context.
8. **One intermittent, unreproducible failure was observed** in
   `test/security/TestARejectedCredentialIsAProblemAndNotSilence`, once, while running
   `./internal/app/ ./test/security/` together. It did not reproduce in 10 subsequent runs of the
   same combination, the test is unmodified by this phase, and it drives an in-process TLS Kafka
   peer under a step timeout — a load-sensitive fixture. Recorded as an observed flake with no
   evidence of a product regression rather than left unmentioned.

---

## 12. Review-pass reconciliation

A narrow reconciliation pass before commit, run against the frozen sources rather than against the
implementation. It changed **one** production behaviour and corrected several counts.

### 12.1 The attribute contract — 17, and one node moved

**Verdict: A, plus a second inconsistency.** `PHASE121A…§11.1`'s table is the only enumeration
anywhere and it lists **seventeen** rows, each naming its consumer. No source enumerates fifteen or
sixteen items; the three bare counts — the table's heading (*"fifteen"*), its closing sentence
(*"Sixteen keys"*) and ADR 0094 §2.9 (*"Sixteen normalized attributes"*) — are clerical.
**Phase 12.1B introduced no unauthorized attribute:** all seventeen keys come from the table
verbatim.

| # | Attribute | Frozen node (§11.1) | Implemented on | Symbol | Consumer per the table | Required by | Surface | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | `k8s.auth_mode` | `k8s.api_access` | `k8s.api_access` | `AttrAuthMode` | auditability of authority | acquisition contract | public | ✅ |
| 2 | `k8s.context` | `k8s.api_access` | `k8s.api_access` | `AttrContext` | report-visible input choice | acquisition contract | public | ✅ |
| 3 | `k8s.namespace` | `k8s.service` | **moved to `k8s.service`** | `AttrNamespace` | subject reconstruction | acquisition contract | public | ✅ **fixed** |
| 4 | `k8s.service_name` | `k8s.service` | **moved to `k8s.service`** | `AttrServiceName` | subject reconstruction | acquisition contract | public | ✅ **fixed** |
| 5 | `k8s.service_type` | `k8s.service` | `k8s.service` | `AttrServiceType` | F3/F4 admission | F3, F4 | public | ✅ |
| 6 | `k8s.service_headless` | `k8s.service` | `k8s.service` | `AttrServiceHeadless` | rendering; never a finding | acquisition contract | public | ✅ |
| 7 | `k8s.selector_present` | `k8s.service` | `k8s.service` | `AttrSelectorPresent` | F3 admission | F3 | public | ✅ |
| 8 | `k8s.selector_key_count` | `k8s.service` | `k8s.service` | `AttrSelectorKeyCount` | auditability without label values | acquisition contract | public | ✅ |
| 9 | `k8s.pod_set_complete` | `k8s.pod_set` | `k8s.pod_set` | `AttrPodSetComplete` | F3 admission | F3 | public | ✅ |
| 10 | `k8s.pod_observed_count` | `k8s.pod_set` | `k8s.pod_set` | `AttrPodObservedCount` | F3; rendering | F3 | public | ✅ |
| 11 | `k8s.slice_set_complete` | `k8s.endpoint_publication` | same | `AttrSliceSetComplete` | F4 admission | F4 | public | ✅ |
| 12 | `k8s.slice_count` | `k8s.endpoint_publication` | same | `AttrSliceCount` | F4 Detail variant; rendering | F4 | public | ✅ |
| 13 | `k8s.endpoint_count` | `k8s.endpoint_publication` | same | `AttrEndpointCount` | rendering (deduplicated) | acquisition contract | public | ✅ |
| 14 | `k8s.ready_endpoint_count` | `k8s.endpoint_publication` | same | `AttrReadyEndpointCount` | F4 | F4 | public | ✅ |
| 15 | `k8s.terminating_endpoint_count` | `k8s.endpoint_publication` | same | `AttrTerminatingEndpointCount` | the V5 disclosure | acquisition contract | public | ✅ |
| 16 | `k8s.slice_excluded_by_owner_uid_count` | `k8s.endpoint_publication` | same | `AttrSliceExcludedByOwnerUIDCount` | the §7.3 race guard, made auditable | acquisition contract | public | ✅ |
| 17 | `k8s.slice_externally_managed` | `k8s.endpoint_publication` | same | `AttrSliceExternallyManaged` | V8, recorded only when true | acquisition contract | public | ✅ |

Internal-only values, deliberately absent from every node: the Service UID (owner-reference guard),
the selector map (server-side query), and every deduplication key.

**The drift, and it was real.** Rows 3 and 4 were implemented on `k8s.target`, which the frozen
table does not list at all. They are now on `k8s.service`, where the table puts them — which also
restores the anchor discipline ADR 0042 §6 fixed for `target.requested`: an anchor carries no
attributes because the subject already states them. **The keys, their kinds and their values are
unchanged; only the node they hang on is.** `k8s.target` now carries none.

**Corrections made, and only counts:** ADR 0094 §2.9 and §9.3, and `PHASE121A…` §4.2, §9.3 and
§11.1's heading and closing sentence. Each preserves the original number in a parenthetical so the
correction is legible rather than invisible. **No frozen decision, set or rule was rewritten.**

### 12.2 The import allowlist — ten paths, nine rows

**Verdict: C.** `PHASE121A…§4.4`'s table has **nine rows** and names **ten import paths**: one row
admits `k8s.io/api/core/v1` and `k8s.io/api/discovery/v1` together, being the two object groups this
adapter reads. ADR 0094 §2.1's prose names the same ten across eight `·`-separated groups.
**"Nine-package allowlist" was a row count.**

Directly imported by production source — exactly ten, exactly the frozen set:

```text
k8s.io/api/core/v1                              k8s.io/client-go/kubernetes/typed/core/v1
k8s.io/api/discovery/v1                         k8s.io/client-go/kubernetes/typed/discovery/v1
k8s.io/apimachinery/pkg/api/errors              k8s.io/client-go/rest
k8s.io/apimachinery/pkg/apis/meta/v1            k8s.io/client-go/tools/clientcmd
k8s.io/apimachinery/pkg/labels                  k8s.io/client-go/tools/clientcmd/api
```

Linked but **not** imported: `k8s.io/client-go/discovery`,
`k8s.io/client-go/plugin/pkg/client/auth/exec`, and the rest of client-go's reachable set. Not
linked at all: the full `Clientset`, `dynamic`, `informers`, `listers`, `tools/cache`,
`tools/watch`. Not in the module graph: `controller-runtime`, `k8s.io/kubectl`.

Enforcement, unchanged and both verified against planted violations: `depguard`
`kubernetes-library-has-one-importer` (deny `k8s.io` outside the client package, expressed as a
negated glob so a package that does not exist yet is protected) and
`kubernetes-client-surface-is-narrow` (`list-mode: strict`, production files only); plus the AST
guards `TestOnlyTheKubernetesClientImportsClientGo` and
`TestTheKubernetesClientImportsAreExactlyTheAllowlist`.

**Nothing was added to the allowlist.** Only the word "nine" was corrected to "ten paths on nine
rows", in this repository's own text and as a parenthetical in the two frozen records.

### 12.2a The mutation harness caught the drift fix, from the mutation side

Re-running the harness after moving the two identity attributes reported **K-M40 as unplantable**,
not as a survivor: its anchor text was in `recordTarget` and the attributes had moved to
`recordService`. That is the harness's zero-match guard working on the *mutation* side as well as
on the `-run` side — a plant whose anchor has gone reports a failure rather than a silent pass, and
without it the run would have shown 40/40 while one property went untested.

The plant is re-anchored to the node the frozen table names. It is the second time in this phase
that a plant reported a defect in the guard rather than in the product, and both are recorded for
the same reason: a mutation suite whose plants rot is a suite that reports zero survivors forever.

### 12.3 The `go` directive — unavoidable

`go 1.26` → `go 1.26.0` is module-graph normalization, not a policy change. All three Kubernetes
modules declare `go 1.26.0`, and a main module's directive may not be below its dependencies'.
Reproduced in isolation: a throwaway module requiring only `k8s.io/apimachinery v0.36.4` is
rewritten by `go mod tidy` from `go 1.26` to `go 1.26.0`. Restoring `go 1.26` in this repository
makes every `go build` and `go vet` fail with *"updates to go.mod needed"*. **Same language
version; nothing to restore.**

### 12.4 EndpointSlice owner-UID — matches the frozen rule exactly

> A slice with an owner reference to a Service whose UID **differs** is **excluded**, and the
> exclusion is counted. A slice with **no** Service owner reference is **included** by label
> association. (ADR 0094 §2.4; `PHASE121A…§7.3`)

| Case | Implementation | Frozen rule |
|---|---|---|
| `kubernetes.io/service-name` label | applied **server-side** as the list selector; nothing is matched locally | ✅ |
| Service ownerRef, UID matches | admitted | ✅ |
| Service ownerRef, UID differs | **excluded and counted** into `k8s.slice_excluded_by_owner_uid_count` | ✅ |
| **no Service ownerRef** | **included** — `associated()` returns `true` | ✅ |
| non-Service ownerRef, or a Service ownerRef in another `apiVersion` | ignored; falls through to inclusion by label | ✅ |
| several ownerRefs | the first Service `v1` one decides; the owner's **name is never consulted** | ✅ |
| third-party `managed-by` | **admitted**; recorded as a boolean disclosure, never an admission gate | ✅ |

**The implementation does not exclude a correctly labelled slice that has no Service
ownerReference.** Association and ownership are separate concepts and are treated as such: the
label is the association, and the owner UID is only a generation guard that can *exclude* a slice
which claims a different Service generation. No new rule was invented in this pass.

## 12. The phase boundary

**Done:** the dependency, the boundary, the refusals, the four auth modes, the three bounded reads,
pagination, budgets, completeness, normalization, evidence, the composition root, the fleet target,
and every guard above.

**Not done, and owned elsewhere:** the four finding codes and two rules (12.1C), the CLI case and
golden reports (12.1C), and `kind` fixtures with the seven scenarios and the two-version matrix
(12.1D).

**Zero open blockers. No ADR change was required and none was made; ADR 0094 is unmodified.**
