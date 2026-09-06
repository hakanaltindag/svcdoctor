# ADR 0093 — Kubernetes diagnostic adapter: one Service, published backends, and no agent

- **Status:** Accepted
- **Date:** 2026-09-06
- **Phase:** 12.0 (architecture / scope / epistemic-safety audit; no production code, no dependency)
- **Upholds:** ADR 0009 (explicit composition-root registration), ADR 0010 (no raw objects in
  canonical evidence), ADR 0012 (vantage), ADR 0014 (a finding cites evidence; severity is data),
  ADR 0016 (the report owns canonical JSON), ADR 0018 (structural redaction), ADR 0021 (connection
  ownership), **ADR 0028 and ADR 0030 (credentials are endpoint-bound)**, ADR 0034 §13 (severity is
  never count-derived), ADR 0043 (generic transport claim scope), **ADR 0050 (discovery creates no
  secret authority)**, ADR 0052 §5 (a renderer table, never a branch), ADR 0054 (owner before
  producer), **ADR 0058 (only the component that performed a handshake may say what it proved)**,
  ADR 0066 (peer text is not a classifier), ADR 0069 §8 (`namedConditions`: membership requires a
  live measurement), **ADR 0072 §13 (no config-driven process execution)**, ADR 0073 and ADR 0083
  §2.7 (no cross-target reasoning), ADR 0078–0083, ADR 0085 §4 (the finding layer refuses and the
  presentation layer shows the fact), ADR 0090 §7 (unconsumed is not debt), **ADR 0092** (the
  planning-admission contract, the vantage ceiling, intent as a premise, the time-series limit)
- **Supersedes:** **ADR 0062 §9's "No Kubernetes API access" clause, in part and conditionally** — see §9.
- **Amended in Phase 12.1A — ADR 0094 closes both of this record's architecture blockers and
  narrows two of its statements**, and nothing else here changes. **B1** is closed by measurement:
  client-go executes an exec credential plugin only at the **first API request**, so a refusal
  issued after `clientcmd.Load` and before any request is structural. **B2** is closed by
  authorization with a nine-package import allowlist and a recorded cost. The two narrowings:
  **Pod state is not retained at all** rather than retained as observation — no admitted finding
  consumes a Pod field, which also dissolves §4's renderer question — and **client certificates
  are an admitted authentication mode**, forced by `kind`'s own kubeconfig. Both are strictly
  narrower or strictly required; the MVP-D boundary is unchanged.
- **Decision:** **ARCH A** — Kubernetes is a normal service adapter that diagnoses Kubernetes
  objects. **MVP-D**: one `namespace + Service` target, three object kinds, **four** finding codes,
  Pod state as **observation only**, and **no** Events, logs, metrics, NetworkPolicy solver, CNI
  internals, service mesh, Ingress or active probing. The next phase is a **contract freeze**. §2.

---

## 1. Context

`docs/validation/PHASE120_KUBERNETES_ADAPTER_ARCHITECTURE_SCOPE_AUDIT.md` holds the archaeology:
the re-measured inventory, the authority model, a nineteen-kind object inventory, eighteen finding
candidates, seventeen web-verified Kubernetes semantics and two dependency measurements. This
record holds the decision.

The question was whether Kubernetes can be added **without svcdoctor becoming `kubectl describe`
with nicer formatting**, a cluster inventory, a monitoring system, a log or metrics collector, an
eBPF agent, a mesh analyzer or a general troubleshooting engine.

**It can, and only for a narrow slice.** The audit's decisive measurement is that
`ContainerStateWaiting.reason` and `ContainerStateTerminated.reason` are **free-form strings by
Kubernetes's own API reference** — `OOMKilled`, `CrashLoopBackOff`, `ImagePullBackOff` are kubelet
and container-runtime conventions, not API contract, and `CrashLoopBackOff` is not even a Pod
phase. Every attractive Pod-level finding keys on one of them, and what remains after refusing
free text is a column of `kubectl get pods`.

What survives is the other half: **what Kubernetes publishes as a backend for a Service**. That
question needs no free text at all, and answering it correctly requires six reasoning steps a
`kubectl` command does not perform — which is the definition of a place svcdoctor belongs.

---

## 2. Decision

### 2.1 ARCH A — a normal service adapter

```text
declared target  →  internal/adapter/kubernetes  →  evidence DAG  →  internal/diagnosis/kubernetes  →  domain.Report
```

Kubernetes joins as a fifth service, wired at the same single composition point as the other four:
one `case "kubernetes":` in `internal/cli/root.go`, one vocabulary leaf in
`internal/service/kubernetes`, one adapter, one client sub-package that is the sole importer of
the Kubernetes client library, one diagnosis package, one `RuleSet`.

**ARCH B — a generic infrastructure domain — is not rejected; it is a different thing that also
exists.** `internal/platform/kubernetes` stays reserved for environment context feeding
`domain.Vantage` (ADR 0012). `CLAUDE.md`'s platform boundary already says that layer *"does not
produce diagnosis"*. **The two must never be conflated**: an adapter diagnoses Kubernetes objects;
a platform probe describes where svcdoctor is running.

**ARCH C — Kubernetes discovers endpoints and existing adapters diagnose them — is deferred, not
refused.** It is the genuinely valuable end state and it is unreachable until an operator can
**declare** a binding between a discovered Service and a credential source, because ADR 0028,
ADR 0030 and ADR 0050 forbid inheritance. Taking it first would put credential authority in the
hands of peer-supplied data, which is the one thing the security model exists to prevent.

### 2.2 MVP-D, and what it is not

| | |
|---|---|
| **Target** | one `namespace` + one `Service` name, plus an explicit cluster access selection |
| **Target kinds** | **Service only.** No workload, Pod, Namespace, Node or cluster-scoped target; no label-selector target; no `--all-namespaces` |
| **API objects** | `Service` (get) · `Pod` (label-scoped list) · `EndpointSlice` (label-scoped list) |
| **Findings** | **4** (§2.4) |
| **Rules** | **2** |
| **Free-text fields read** | **none** |
| **Schema / graph / `RuleContext` change** | **none.** `SchemaVersion` 1, `RunSchemaVersion` 1 |
| **RBAC** | 3 resources, 2 verbs (`get`, `list`), **1 namespace**, no cluster-scoped grant |
| **API calls** | 3 typical, fewer than 10 at the object ceiling |

**Pod and container state is fetched, normalized and rendered as observation, and produces no
finding.** That is ADR 0085 §4's arrangement: the finding layer refuses and the presentation layer
shows the fact.

### 2.3 The authority model, frozen

Every Kubernetes fact is **relayed by the API server**; what differs is who wrote the field.
`API_SERVER_REPORTED` · `CONTROLLER_REPORTED` · `SCHEDULER_REPORTED` · `KUBELET_REPORTED` ·
`APPLICATION_REPORTED` · `CSI_REPORTED` · `CNI_INFERRED` · `OPERATOR_DECLARED` ·
`DERIVED_CONTRAST`. Every proposed diagnosis must name which one supports it.

> **API object state never becomes a hidden runtime cause.** `status` records what the cluster
> observed. It does not say why the system reached it, and for `KUBELET_REPORTED` fields it does
> not even say it in a vocabulary the API defines.

**`CNI_INFERRED` has no admissible claim at all.** No Kubernetes API object proves packet-path
behaviour.

### 2.4 The four admitted findings, and their ceilings

Names are candidates; Phase 12.1A freezes them. The **claims** are frozen here.

| Claim | Authority | Kind / severity | Forbidden |
|---|---|---|---|
| *"No Service of this name exists in this namespace at this observation."* | `Status` `NotFound` — an **API-contract enum** | CONFIRMED / ERROR / HIGH | that the workload is broken |
| *"This credential was not permitted to read X; that measurement was not made."* | `Status` `Forbidden` | CONFIRMED / **WARN**, state `UNKNOWN` | **that the object is absent.** *"You could not look"* is never *"nothing is there"* |
| *"This Service's selector currently matches no Pod in its namespace."* | selector + a **complete** Pod enumeration | CONFIRMED / ERROR / HIGH | that the workload is down; that the selector is wrong |
| *"Kubernetes currently publishes no ready endpoint for this Service."* | a **complete** EndpointSlice set | CONFIRMED / ERROR / HIGH | *reachable* · *clients cannot connect* · *the Pods are unhealthy* · *the endpoint controller is broken* · any word implying persistence |

The second follows `REDIS_COMMAND_NOT_PERMITTED` exactly — the service did not fail; svcdoctor's
measurement was blocked.

**Both set claims are universal quantifications and each requires a proven-complete enumeration.**
The fourth additionally requires at least one selected Pod, so it and the third never both fire
for one condition.

### 2.5 Publication, never reachability

> **The frozen question is: "What backend endpoints does Kubernetes currently publish as ready for
> this Service?" — never "Can clients reach this Service?"**

Topology-aware routing, `internalTrafficPolicy`, `externalTrafficPolicy` and mesh interception all
mean a published ready endpoint is not necessarily usable from every client, and an unpublished
one is not necessarily unreachable. Reachability needs network-path evidence the API does not
carry. **This single distinction defines the whole first Service scope**, and it is the same
discipline ADR 0092 §2.4 froze for vantage.

### 2.6 Free text is prohibited

**No substring match, no regexp, no fuzzy match, no raw interpolation**, over `status.message` ·
`condition.message` · `Event.message` · `terminationMessage` · `ContainerState*.message` ·
image-pull error text · scheduler text · `Status.message` · `Status.details.causes[].message`.

Reading a `reason` **at all** requires exact match against an svcdoctor-owned allowlist whose every
member has been observed on a real cluster — ADR 0069 §8's `namedConditions` rule — and it is **not
authorized in first scope**. The one exception is `metav1.StatusReason`, which **is** an
API-contract enumeration; that asymmetry is why two of the four findings exist and why the
container-state candidates do not.

### 2.7 Completeness, pagination and eventual consistency

> **Reaching an object budget or a pagination limit MUST NOT become "no Pods found" or "no ready
> endpoints". It becomes an incomplete enumeration**, `Result.Incomplete()` and exit code 4.

Three categories, never two — Kafka Phase 10.2's rule, unchanged. An object that was not
enumerated is not an object that is absent.

**Kubernetes reads across several objects are not a transactional snapshot.** Every set claim is
scoped *"at the time of these API observations"*. **Controller lag is never called
misconfiguration**, and a single run may never claim that a contrast persists — ADR 0092's
time-series limit applied to a new domain.

**Deterministic ordering is mandatory.** API list order is not a semantic contract; canonical JSON
must sort by `(kind, namespace, name)` and by `(addressType, address)`, and a permuted list must
produce byte-identical output.

### 2.8 Credential authority — already answered by the existing model

The Kubernetes API server has a host and a port, so a Kubernetes credential binds to a
`security.Endpoint` exactly as the other four services' credentials do. Therefore:

> **A Kubernetes API credential is bound to the API server endpoint. No Pod IP, ClusterIP, Service
> DNS name or endpoint address is that endpoint, so ADR 0028's binding check refuses it there
> without any new rule.**

**Kubernetes credentials never flow to discovered endpoints.** This is structural, not a policy
somebody must remember.

**No active probing of Pods, ClusterIPs, Service DNS names or endpoint addresses** in first scope —
for that reason, because the vantage may not reach ClusterIP space at all, and because ADR 0050
already says discovery must not create secret authority.

### 2.9 What is excluded, and it is longer than what is included

| | Status |
|---|---|
| **Events** | **OUT.** Unbounded cardinality, cluster-dependent retention so absence proves nothing, aggregation that collapses occurrences, a free-text payload, version-dependent reasons, identifier leakage. An Event is one component's account, retained for a while — not authority |
| **Logs** | **OUT, and it is a decision rather than a deferral.** Unbounded, secret- and PII-bearing, application-specific, and `pods/log` is a distinct grant operators restrict on purpose |
| **Metrics** | **OUT.** A second system with its own auth and availability; a measured historical fact needs no current metric |
| **NetworkPolicy solver** | **OUT.** Enforcement is the CNI's; evaluation spans policy union, namespace and pod selectors, `ipBlock`, named ports, `hostNetwork`, kube-proxy and vendor CRDs. Even *"policies selecting this Pod exist"* is not *"traffic is blocked"* |
| **CNI internals, eBPF** | **OUT.** The first adapter works against a vanilla API boundary. These may one day be optional evidence providers; they may never be required |
| **Service mesh** | **OUT.** A sidecar's presence is not a mesh diagnosis |
| **Ingress, Gateway API** | **OUT of first scope.** A separate domain |
| **Node objects** | **OUT.** No cluster-wide node list, ever. If a bound node is ever needed, it is fetched by name |
| **Secrets** | **Never read, not even by metadata** |
| **ConfigMap contents, annotations, label dumps** | **Never collected.** Labels are matched; evidence records `matched` and a count |
| **Container image, `imageID`, `containerID`, Pod IP, ClusterIP** | Not in canonical evidence in first scope. `targetRef` is better correlation and less sensitive |

### 2.10 API transport — the client library owns it

The Kubernetes client owns DNS, TCP and TLS to the API server, and svcdoctor records **one**
API-access evidence node with a normalized failure class. **It does not manufacture
`dns.lookup`, `tcp.connect` or `tls.handshake` nodes for a connection its own probes did not
make** — ADR 0058 reserves a claim about a handshake to whoever performed it, and `forbidigo`
already enforces the same rule for `security.ChannelTLS*`.

The cost is stated rather than hidden: a control-plane connectivity problem surfaces as one
classified API-access failure rather than as a transport journey. **Missing transport detail is
better than duplicated transport truth.**

### 2.11 Identity and privacy

**Subject:** `<kind>/<namespace>/<name>` — deterministic, kind- and namespace-qualified, bounded
by the adapter (`Subject.ref` has no length bound of its own). **No third `SubjectKind` is
proposed.** **`metadata.uid` does not participate in the subject**; it is internal correlation
only, and `resourceVersion` reaches evidence in no role.

**Cluster identity:** the operator's declared target identifier is canonical. A kubeconfig context
name is an operator-local label and is displayed as one. **No API call is made merely to derive a
prettier identifier.**

**Every Kubernetes name that reaches evidence is `AttrKindIdentity`** — whose own definition
already covers *"a named resource"* — so structural redaction transforms it with no new mechanism,
and nothing relies on terminal-only masking.

### 2.12 Namespace and target policy

**Namespace is mandatory and explicit** — not the kubeconfig context's namespace and not
`"default"`. A target whose meaning changes when someone runs `kubectl config set-context` is a
trap, and its failure mode looks exactly like a real finding.

**Cluster access is selected explicitly.** No implicit fallback chain from in-cluster to
`KUBECONFIG` to `~/.kube/config`. No hidden context switching; the context in use is
report-visible. **Impersonation is refused in first scope.** A proxy in effect is reported, never
silently inherited.

### 2.13 What must not be built

No Helm chart, operator, controller or CRD. No watch, no cache, no informer, no reconciliation
loop — svcdoctor runs, reports and exits (ADR 0062 §9). No declarative Kubernetes rule DSL and no
graph-pattern engine: the existing generic engine plus service-owned imperative rules is
sufficient, and MVP-D needs **two** rules rather than one per status reason. No cluster scan. No
`kubectl` invocation, ever — the CLI already denies `os/exec`.

---

## 3. Two architecture blockers, measured rather than suspected

Neither stops this record. Both must be decided before any Go is written.

### 3.1 B1 — exec credential plugins

**ADR 0072 §13 refuses an `exec:` / command provider** — *"Arbitrary code execution driven by a
config file. It is the single largest surface any of these would add"* — with reopen condition
**"None. This is a decision, not a deferral."** A kubeconfig `exec:` stanza is exactly that shape,
and EKS, GKE and AKS generate one by default.

**The audit measured that the linkage is unavoidable.** Building a program that uses
`k8s.io/client-go`'s typed clients **without `clientcmd`** still links `os/exec` and
`k8s.io/client-go/plugin/pkg/client/auth/exec`, reached from `rest` itself. So *"refuse exec by not
linking it"* is **not available**, and no production file imports `os/exec` today — a property four
separate guards assert.

The guarantee can therefore only be **behavioural**: never populate an exec provider, refuse a
kubeconfig carrying an `exec:` stanza at parse time, and guard it by test in the shape `forbidigo`
already uses for `security.Reveal`.

**Phase 12.1A must choose** between (B) refusing exec and (D) external credential materialization —
a token by `env` or `file`, plus a CA bundle, which is **compatible with ADR 0072 §13 unchanged**
because those are the two sources §2 already supports — or **reopening ADR 0072 §13 with its own
security review**. This record recommends **B+D** and decides neither.

### 3.2 B2 — the client-library dependency

| | today | with client-go v0.37.0 |
|---|---|---|
| module requirements | **2** | **46–47** |
| binary | **10,310,258 bytes** | ~**36.5 MB** |
| `os/exec` linked | **no** | **yes** |
| `net/http` linked | **no** | **yes** |

Raw REST is refused: it re-creates kubeconfig parsing, TLS configuration, auth providers,
pagination and API decoding, in the package that talks to a control plane. **"Lightweight" is not a
security argument.**

This is the largest single change to the project's supply-chain posture ever proposed, and
`TestTheDependencyCountIsExact` exists to force someone to record it. **Phase 12.1A decides the
import surface and the pinned Kubernetes minor, and records the number.**

---

## 4. Consequences

**Phase 12.0 changes no production code, no test, no config, no fixture and no dependency.** Every
frozen count is unchanged: `SchemaVersion` **1**, `RunSchemaVersion` **1**, finding codes **65**,
rules **22**, failure classes **42**, `RuleContext` fields **3**, modules **2**, `Reveal` **4**,
`SecretFor` **4**, exit codes **5**.

**The first scope is a leaf CLI command and is not registered with the fleet.** `config.Factory`
requires `DefaultPort() uint16`, `NewRegistry` rejects a zero default port, and a host is
required — and **a Kubernetes target has neither in the operator's sense**. That asymmetry is real
and is recorded rather than papered over; Redis and RabbitMQ both shipped as leaf commands before
`run --config` existed.

*(Phase 12.1A marker: **resolved and no longer open.** ADR 0094 §2.9 retains no per-Pod and no
per-endpoint evidence node, so the report is a single-path journey and `serviceView` needs **no
change at all**.)*

**The renderer needs one decision.** `terminal.serviceView` models a linear per-path journey plus
**one** repeated child level, and Kubernetes has no journey and **two** child kinds. Using the
single child level for one and the `observations` mechanism for the other costs nothing; adding a
second child level is a renderer change that must not happen by accident.

**The failure boundary keeps working, and the layer mapping is why.** `boundaryFor` groups by
subject and requires the last-good node at a strictly lower `Layer`, so Kubernetes evidence
occupies `L0` input, `L5` API access, `L4` object retrieval and `L6` backend discovery — **L6 is
topology discovery, which is exactly what backend publication is.**

**Every admitted finding has a deterministic real-cluster fixture** on `kind`, including a
zero-ready-endpoint case produced by a readiness probe that always fails. **`envtest` runs no
kubelet and must never be described as real-cluster proof.**

---

## 5. Alternatives considered

**MVP-A — Pod and container diagnosis only.** *Rejected.* Every high-value fact keys on a
**free-form** `reason`, and what survives the free-text prohibition is one column of
`kubectl get pods`. It fails the value test that a first adapter must materially outperform
`kubectl get` and `kubectl describe`.

**MVP-C — Pod/container plus Service/EndpointSlice.** *Rejected.* It triples the surface —
free-text reasons, restart-count temporality, readiness gates, sidecars, init containers, Job
completion semantics — for findings that are mostly restatements. Pod **state** is still fetched
and rendered; only Pod **findings** are excluded.

**A Deployment or workload target.** *Deferred.* A ready-replica deficit is the first line of
`kubectl get deploy`, the word an operator wants — *stuck* — needs time evidence one run does not
have, and `availableReplicas` measures a configured delay rather than a problem.

**`KUBERNETES_SERVICE_HAS_NO_ENDPOINTSLICES` as a fifth code.** *Rejected.* For a selector-backed
Service, zero slices and zero ready endpoints are one condition, and two codes would publish two
findings for one fact.

**A finding for a Ready Pod missing from every EndpointSlice.** *Deferred, and the reasoning is the
audit's cleanest result.* Two of its four explanations — third-party slice management and a
terminating Pod — are excludable from evidence svcdoctor already holds. The remaining two,
controller lag and a genuine controller problem, are separable **only by observing the same
contrast later**, which ADR 0092 froze as *not* next-best evidence. It becomes an observation.

**Reading Events to recover the specificity the rejected candidates lack.** *Rejected.* It is the
single largest scope trap in the domain and it would make Kubernetes the first service whose
canonical authority is free text.

**Building on `internal/platform/kubernetes` instead of an adapter.** *Rejected as a category
error.* That layer collects environment context and produces no diagnosis. Both may exist; neither
is the other.

**Do not build a Kubernetes adapter at all.** *Rejected on the evidence.* Four bounded operator
questions survive every gate, all four have deterministic real fixtures, and answering the fourth
correctly requires reasoning `kubectl` does not do.

---

## 6. Security implications

**Nothing in this record widens any surface**, and the phase writes no Go and adds no dependency.

Active decisions, each recorded so a later phase inherits it:

- **Kubernetes credentials are endpoint-bound to the API server and reach nothing else** (§2.8),
  and it is structural rather than a rule to remember.
- **No active probing of Pods, Services or endpoint addresses** in first scope.
- **Secrets are never read, and neither are ConfigMap contents or annotations.**
- **No free text from any Kubernetes object may reach a claim** (§2.6), which is what keeps hostile
  status strings, ANSI and CRLF out of a report structurally rather than by escaping.
- **Impersonation is refused; a proxy is reported, never silently inherited; there is no implicit
  fallback to an ambient in-cluster identity.**
- **Exec credential plugins are an open blocker, not an accepted default** (§3.1).

`O7_SECURITY_WEAKENING` remains unreachable (ADR 0092 §2.8), and no Kubernetes recommendation may
propose a `RESTART`, `DISRUPTIVE` or `SECURITY_WEAKENING` action. First-scope recommendations are
`NEXT_EVIDENCE` with `OBSERVE`, `VERIFY` or `COMPARE`; *"change the selector"*, *"increase
replicas"*, *"restart the Pod"*, *"increase the memory limit"* and *"modify the NetworkPolicy"* are
refused.

---

## 7. Compatibility implications

**None from this record.** `SchemaVersion` **1**, `RunSchemaVersion` **1**, finding codes **65**,
failure classes **42**, exit codes **5**, modules **2** — all unchanged, and no
`docs/COMPATIBILITY.md` grading moves.

**For the implementation phases:** `discovery.k8s.io/v1` EndpointSlice has been stable since
Kubernetes **v1.21**, which is a defensible minimum for MVP-D — and the sidecar semantics that
would gate a *Pod* scope (default v1.29, locked v1.33) do not bind it, which is a further argument
for the chosen MVP. First scope uses **stable upstream APIs only**, so no vendor branch is
permitted and none is needed for OpenShift, RKE2, k3s, EKS, GKE or AKS; managed clusters are gated
by §3.1's exec question rather than by the API surface. No claim about any distribution may be made
until a fixture establishes it.

---

## 8. Reopen conditions

| Item | Condition |
|---|---|
| Pod and container findings (OOMKilled, CrashLoopBackOff, image pull) | An svcdoctor-owned exact-match `reason` allowlist whose **every member has been observed on a real cluster** (ADR 0069 §8), with the claim scoped to *"Kubernetes reported the reason as X"* |
| Init container and sidecar semantics | A design that reads `spec.initContainers[].restartPolicy` before interpreting `initContainerStatuses`, and states its behaviour below Kubernetes v1.29 |
| Workload replica deficit | A record that gates the claim on `observedGeneration == metadata.generation`, uses `readyReplicas` and never `availableReplicas`, and refuses the word *stuck* |
| Ready Pod absent from every EndpointSlice | A discriminator that is not a second observation of the same contrast |
| PVC binding | Its own record; it adds a fourth object kind and a Pod-shaped target |
| Events | Its own record answering retention, cardinality, aggregation and the free-text payload. **Never as a side effect of a service phase** |
| Logs, metrics, NetworkPolicy solving, CNI internals, eBPF, service mesh | **Decisions, not deferrals.** Each would need its own record and its own security review, and none is invited |
| Node objects | One bounded question that requires the single node a selected Pod is bound to, fetched by name. **Never a cluster-wide list** |
| ARCH C — Kubernetes discovering endpoints for other adapters | An operator-declared binding between a discovered Service and a credential source, with its own record. **Credential inheritance stays refused** |
| Fleet registration of a Kubernetes target | A `config.Factory` shape that admits a service which is not endpoint-shaped, or a defensible derivation of `Host`/`Port` from the resolved API server |
| Exec credential plugins | **ADR 0072 §13's own reopen condition, which is "None."** Changing it is a new record with a security review, not a convenience |

---

## 9. What this record supersedes

**ADR 0062 §9's "No Kubernetes API access" clause, in part and conditionally.**

That section states: *"**No Kubernetes API access.** svcdoctor never calls the API, so it needs no
ServiceAccount permissions, no Role and no RoleBinding, and the examples set
`automountServiceAccountToken: false`. Verified: the running pod had **no service-account token
volume at all**. A platform that creates these Jobs needs API permissions; svcdoctor does not
inherit them."*

**Everything else in ADR 0062 stands**, including the distroless non-root image, the read-only root
filesystem, the dropped capabilities, the Job execution model, `backoffLimit: 0`, the deadline
ordering and the output contract. The superseded text is left standing, per this repository's
convention that reasoning which was wrong — or has been overtaken — stays legible.

The supersession is **conditional and narrow**, and the conditions are the point:

1. It takes effect only for the **`diagnose kubernetes` command**. Every other command still calls
   no API and still needs no ServiceAccount.
2. The **existing** `examples/kubernetes/` manifests are **unchanged**, `automountServiceAccountToken: false`
   included. A Kubernetes-diagnosis example is a **second, clearly separate** manifest carrying its
   own `Role` and `RoleBinding` with the three-resource, two-verb, one-namespace grant of §2.2.
3. *"svcdoctor does not inherit a platform's API permissions"* **remains true and is strengthened**:
   the adapter's identity is explicitly selected, never fallen back to, and its permissions are the
   minimum written above.

The clause's last sentence — *"it does not become an agent"* — is not superseded and is reaffirmed
by §2.13.
