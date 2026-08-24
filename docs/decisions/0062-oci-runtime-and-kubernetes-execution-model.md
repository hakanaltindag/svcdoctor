# ADR 0062: OCI runtime and Kubernetes execution model

## Status

**Accepted; runtime and publication pipeline implemented, never executed.**

Read that wording literally. **Accepted** applies to every decision below.
**Runtime implemented** means the image, its security properties and the
Kubernetes execution model exist and are validated. **Publication pipeline
implemented** means `.github/workflows/release-oci.yml` now mechanically
enforces §12–§20. **Never executed** means the workflow has never run: no image
has been pushed to GHCR, nothing has been signed or attested, and no `v0.3.0`
tag exists. Phase 7.1-P validated the pipeline's mechanisms against a local
registry and its logic locally; it deliberately published nothing.

Two obligations remain open and are recorded in §21: the workflow's first real
run, and native `linux/amd64` execution, which needs a GitHub-hosted amd64
runner and therefore cannot be demonstrated from an arm64 workstation.

Phase 7.1 built and measured the runtime. Phase 7.1-R reviewed it, resolved the
four questions Phase 7.1 left open, and added the release contract in §12–§19.
Two of those answers changed as a result of measurement rather than preference,
and both are recorded in §16.

**Nothing has been committed, pushed, published or signed.**

## Reading this record

The sections below mix three kinds of statement, and conflating them is how a
release contract becomes fiction. They are marked:

| Marker | Meaning |
|---|---|
| **[FACT]** | Something measured. It was true of a specific artifact at a specific time. |
| **[INVARIANT]** | A security or correctness property the product must not lose. |
| **[POLICY]** | A rule official releases MUST follow. Normative. |
| **[GUIDANCE]** | A recommendation. Not binding. |

*"`SOURCE_DATE_EPOCH` produced reproducible images"* is **[FACT]**.
*"official release builds MUST set it"* is **[POLICY]**. This record never lets
one stand in for the other.

## 1. Context

Until now svcdoctor has been a binary someone runs from wherever they happen to
be standing. That is exactly the problem it is for: every connectivity finding
it makes is qualified by vantage, and the vantage that matters is almost never a
laptop.

The strongest case is Kafka. A bootstrap endpoint can answer perfectly while the
brokers it advertises are unreachable — an advertised-listener misconfiguration
that is invisible from outside the cluster and immediate from inside it. Phase
7.1 measured exactly that from a container, and the report said so:

```
outcome    Kafka metadata obtained
topology   0 of 3 advertised broker endpoints reached
```

So the container is not packaging. It is a **network position**, and it decides
what svcdoctor can truthfully observe.

That makes the image a product surface, and it raises questions that packaging
alone would not: whose certificates does it trust, as whom does it run, what can
it write, how does it receive a password, and what does it get to talk to.

## 2. Decision

Ship one OCI image, built from `gcr.io/distroless/static-debian12:nonroot`,
running as **65532:65532** with a **read-only root filesystem**, **no
capabilities**, **no shell**, **no Kubernetes API access** and a **direct binary
ENTRYPOINT**. Recommend running it as a **Job**, not a Deployment.

Everything below is a consequence of that sentence, and each part was measured.

## 3. The runtime requirements came first, and they are unusually small

The base image was chosen after inventorying what the binary actually needs, not
before. Searched in production source (excluding tests) and confirmed against a
real `CGO_ENABLED=0` binary:

| Requirement | Needed? | Evidence | Container consequence |
|---|---|---|---|
| libc / dynamic libraries | **No** | `file` reports `statically linked`, both arches | No libc in the final image |
| Shell, `/bin/sh` | **No** | No `os/exec`, no `exec.Command` anywhere in production | No shell; no wrapper script |
| External binaries (`curl`, `openssl`, dig) | **No** | Zero `os/exec` call sites | Nothing to install |
| CA certificates | **YES** | `RootCAs == nil` ⇒ Go reads the system store | **Decides the base image** — see §4 |
| `/etc/resolv.conf`, `/etc/hosts` | Yes, at runtime | Pure-Go resolver | Injected by the container runtime |
| `/etc/nsswitch.conf` | Consulted | Pure-Go resolver | Present in the chosen base |
| `/etc/passwd`, `/etc/group` | **No** | No `os/user`, no `UserHomeDir` | Present anyway; nothing depends on it |
| Writable `/tmp` | **No** | Zero `os.Create`/`WriteFile`/`MkdirAll`/`CreateTemp` in production | `readOnlyRootFilesystem: true` works |
| Writable `$HOME`, `HOME` set | **No** | No `UserHomeDir` | `WORKDIR /` |
| Any filesystem write | **No** | As above | Read-only root filesystem |
| File reads | **Two only** | `--password-file`, `--tls-ca-file` | Both operator-named, both mountable read-only |
| Environment variables | **None** | **Zero `os.Getenv` in production** | No env configuration; no env secret source (§8) |
| Timezone database | **No** | No `time.LoadLocation` | Present in base; unused (§10) |
| Signal handling | Yes | `signal.NotifyContext(SIGINT, SIGTERM)` in `cmd` | Binary must be PID 1 (§7) |
| Child processes | **None** | Zero `os/exec` | No reaping; **no init shim** |

The last three rows are why this ADR is short on machinery: there is nothing to
supervise, nothing to write and nothing to configure through the environment.

## 4. Base image: distroless static, and specifically not scratch

The priority order was: truthful system trust, then minimal privilege, then
attack surface, then predictability, then size.

**The deciding question is trust.** When no `--tls-ca-file` is given, svcdoctor
passes `RootCAs: nil` and Go falls back to the system trust store. A `scratch`
image has no trust store, so `nil` would silently stop meaning *use the system
roots* and start meaning *trust nothing*. That is a change to TLS semantics
disguised as a packaging choice, and the CA-less negative control recorded in
§22 proves it is real rather than theoretical: the same invocation that verifies
a public certificate in the shipped image fails with `TLS_UNKNOWN_AUTHORITY` and
`TLS_CHAIN_NOT_TRUSTED` in a CA-less scratch build.

| Model | Verdict | Why |
|---|---|---|
| **A — `scratch`** | Rejected | No trust store. Would work only by copying a CA bundle out of the *builder* image, which couples trust-store freshness to the Go toolchain image — a coupling nobody would predict from reading the Dockerfile. Also no `/etc/passwd` or `nsswitch.conf`. Saves the 6.18 MB base, most of it tzdata we never read. |
| **B — distroless static, nonroot** | **Selected** | Carries the trust store, an established numeric nonroot identity, and **zero executables**. |
| **C — Alpine** | Rejected | Ships busybox **and** `apk` — a shell and a package manager in the final image, both explicitly unwanted. musl's resolver also differs from glibc's, and DNS behaviour is something svcdoctor *reports on*; changing it as a side effect of packaging is the wrong direction. |
| **D — Debian slim** | Rejected | Full shell, `apt`, ~30 MB and a standing CVE queue for packages nothing executes. |
| **E — Wolfi / Chainguard static** | Rejected *for now* | Technically the closest competitor. Rejected on supply-chain durability: free-tier tags are mutable and older digests are not retained, so a pinned digest can stop resolving — which defeats the reason for pinning. Worth revisiting if a retained-digest channel is available. |

**"Zero executables" was verified, not assumed.** A full inventory of the base
shows the only files carrying an execute bit are data files with spurious modes
(`ca-certificates.crt`, `/etc/hosts`, `/etc/resolv.conf`, `os-release`) and
zoneinfo symlinks. There is no shell and no package manager to find.

Pinned to the multi-platform index digest
`sha256:afa5c872…`, so both architectures resolve from one reviewed manifest
list. The builder is pinned the same way.

## 5. System trust, and the negative control that makes the claim mean something

Five behaviours, each measured through the shipped image:

| # | Case | Result |
|---|---|---|
| A | Publicly-trusted peer, no `--tls-ca-file` | **PASS** — `tls.trust_source=system`, `tls.verified=true` |
| B | Private-CA peer, no `--tls-ca-file` | **FAIL** — `TLS_UNKNOWN_AUTHORITY` |
| C | Private-CA peer, with `--tls-ca-file` | **PASS** — `tls.trust_source=custom` |
| D | **Public** peer, with a private `--tls-ca-file` | **FAIL** — proves the custom CA **replaces** the system roots |
| E | Malformed / missing / directory CA | **Exit 2 before any connection** |

Case D is the one that matters most and is easiest to get wrong: a custom CA
must not be *appended* to the system roots, or `--tls-ca-file` would stop being
able to express *only this issuer is acceptable here*. `internal/cli/tls.go`
builds a fresh `x509.NewCertPool()` and never calls `SystemCertPool`, so the
replacement is structural; D confirms the image does not undo it.

Case A alone would be worthless without the CA-less negative control recorded in
§22, because a test that cannot fail proves nothing. The CA-less build fails it.
The trust store is doing real work.

`SSL_CERT_FILE` is set by the base image to the same bundle Go would find
anyway. It is left as inherited and noted here because it is, technically, an
environment variable that influences trust — a property of the Go standard
library, not a svcdoctor configuration surface.

## 6. Non-root identity

`USER 65532:65532` — **numeric, deliberately**. Kubernetes verifies
`runAsNonRoot: true` against the image's configured user before starting the
container and does not resolve `/etc/passwd` to do it, so a *name* would make
the pod fail to start. Measured both directions with no `runAsUser` in the pod
spec:

- shipped image → pod **Succeeded**, ran, reported its version;
- a variant rebuilt with `USER 0:0` → **`CreateContainerConfigError:
  container has runAsNonRoot and image will run as root`**.

The manifests *also* set `runAsUser: 65532` explicitly. That is defence in
depth: it forces non-root even if the image were rebuilt wrongly, and it was
observed doing exactly that during the mutation test.

## 7. Filesystem, entrypoint and signals

**`readOnlyRootFilesystem: true` works**, in Docker and in Kubernetes, for
complete PostgreSQL and Kafka journeys. svcdoctor writes nothing, so no
writable path was added — not `/tmp`, not `$HOME`. `WORKDIR /` rather than the
base image's `/home/nonroot`, so the run does not depend on a directory whose
ownership a `securityContext` could change.

**`ENTRYPOINT ["/svcdoctor"]`, no CMD, no shell, no wrapper.** `docker run IMAGE
diagnose postgres --host db` reads naturally; bare `docker run IMAGE` prints
usage and exits 2. A wrapper script would need a shell in the final image, would
interpose itself between the runtime and the process that handles SIGTERM, and
would add quoting and injection surface around operator arguments.

**svcdoctor is PID 1 and handles SIGTERM itself.** Measured: the container's
only process is `svcdoctor` running as 65532; `docker stop` returned in **1.92
s**, far inside the 30 s grace period, so no SIGKILL fallback occurred; the exit
code was **4**; and the process still emitted a complete report marked
`INCOMPLETE`. Cancellation preserving evidence is an existing invariant (ADR
0047); this confirms containerization does not break it.

No `tini`. There are no child processes to reap.

**No `HEALTHCHECK` and no `EXPOSE`.** svcdoctor terminates and listens on
nothing; either directive would misrepresent its process model. For the same
reason the Job examples carry no liveness or readiness probe.

## 8. Secrets: files and stdin, never the environment

The existing model is unchanged: `--password-file`, `--password-stdin`,
mutually exclusive, no precedence, no prompt, no fallback. **No
environment-variable secret source is introduced**, and this is stronger than a
convention — production code contains **zero `os.Getenv` call sites**, so
`SVCDOCTOR_PASSWORD`, `POSTGRES_PASSWORD`, `PGPASSWORD` and `KAFKA_PASSWORD`
are ignored because there is no code that could read them. Environment
variables leak into pod specs, `kubectl describe`, support bundles and CI logs
far more readily than a mounted file.

Measured in-container with real Linux ownership: a `0400` secret owned by the
runtime user is read normally; a `0400` secret owned by root produces
**exit 2, `permission denied`** — no fallback to another source, no attempt to
change the mode, and the secret never appears in output. In Kubernetes,
`defaultMode: 0400` with `fsGroup: 65532` makes the mount readable.

`--tls-ca-file` mounts the same way, read-only, with the §5 failure modes.

## 9. Kubernetes execution model

**A Job, or an ephemeral Pod.** svcdoctor runs, reports and exits; it is not a
daemon. A Deployment would restart a process whose job is to terminate, and a
DaemonSet would multiply a measurement without making it more true.

Recommended shape, all of it verified on a live cluster:

```yaml
restartPolicy: Never
backoffLimit: 0
automountServiceAccountToken: false
securityContext:            # pod
  runAsNonRoot: true
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  seccompProfile: {type: RuntimeDefault}
securityContext:            # container
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: {drop: ["ALL"]}
```

`backoffLimit: 0` because svcdoctor is deterministic: a re-run produces the same
answer while obscuring that it already answered.

**No capabilities are required.** svcdoctor opens ordinary client TCP sockets
and resolves names; it does not craft packets. `NET_RAW`, `NET_ADMIN` and
`SYS_ADMIN` are not needed and must not be granted. No `hostNetwork`, no
`hostPID`, no `hostIPC`, never privileged.

**No Kubernetes API access.** svcdoctor never calls the API, so it needs no
ServiceAccount permissions, no Role and no RoleBinding, and the examples set
`automountServiceAccountToken: false`. Verified: the running pod had **no
service-account token volume at all**. A platform that *creates* these Jobs
needs API permissions; svcdoctor does not inherit them.

**Deadline ordering.** `activeDeadlineSeconds` must exceed svcdoctor's
`--timeout`, so svcdoctor reaches its own execution budget first and exits with
a report. If Kubernetes kills the Pod first, there is no report — only a
terminated container. The examples pair `--timeout 30s` with
`activeDeadlineSeconds: 60`.

**[GUIDANCE] Image references.** The examples in `examples/kubernetes/` use an
exact semver tag because it is readable and because no digest exists to quote —
writing a fabricated one would be worse than useless. Production deployments
SHOULD pin the digest once a release is published:

```yaml
image: ghcr.io/hakanaltindag/svcdoctor@sha256:<digest of vX.Y.Z>
```

Semver is immutable by policy (§13); a digest is immutable by construction, and
does not depend on that policy being honoured. `latest` is never acceptable
here.

**Output.** `--output json` on stdout, captured from pod logs. No writable
volume is needed to retrieve a report. Logs carry real hostnames and addresses;
`--shareable` pseudonymizes them but also removes identity a machine consumer
may need to correlate, so it is right for sharing with a person and not
automatically right for every pipeline.

**Exit codes keep their contract.** `0` does not mean healthy — a run with no
credential configured exits 0 with a WARN finding and no session. A release gate
should read the canonical JSON as well as the process exit.

## 10. Consequences

**Accepted costs.**

- Unused payload ships with the base: tzdata is its single largest component
  (`docker history` reports the tzdata layer at 4.24 MB), plus Debian licence
  and doc text, none of which svcdoctor reads. Removing them means `scratch`,
  and §4 explains why that is the wrong trade. Measured sizes: base image
  **6.18 MB**, binary in the image **5.57 MB** (`-s -w -trimpath`), final image
  **14.1 MB** as `docker images` reports it, of which the required CA bundle is
  **224 KB / 150 certificates**.
- The image's trust store is fixed at build time. Refreshing CA roots means
  rebuilding against a newer base digest — a deliberate, reviewable act rather
  than a silent drift.
- The final image has no shell, so debugging inside it is not possible.
  `kubectl debug` with a separate ephemeral container is the intended path.

**[FACT] Reproducibility is real but conditional.** The **binary is
bit-identical** across different build paths with a cold cache — `-trimpath`,
`CGO_ENABLED=0` and a digest-pinned toolchain do their job. The **image digest**
is not reproducible by default: BuildKit stamps build time into the config and
layer metadata. With `SOURCE_DATE_EPOCH` *and* `rewrite-timestamp=true` the
platform image digest **is** bit-identical across paths and a cold cache.

Phase 7.1 recorded this as a measured property and deferred the policy. Phase
7.1-R took the decision: §15 makes it **required for official releases**, and
§16 records why the claim is scoped to platform image manifests rather than the
index.

**[INVARIANT] Labels are not provenance.** The `org.opencontainers.image.*`
labels are build metadata inside the image config. Build provenance is an
external attestation and a different artifact. The two are not interchangeable
and this ADR never calls the labels provenance. See §17.

## 11. Rejected alternatives

- **A wrapper shell entrypoint** — needs a shell, breaks signal directness, adds
  quoting and injection surface. Rejected.
- **`tini` or another init** — no child processes exist. Rejected as unnecessary
  machinery (`Extensibility comes from stable boundaries, not from maximizing
  abstractions`).
- **Environment-variable secrets** — §8. Rejected.
- **Appending `--tls-ca-file` to the system roots** — would destroy the
  *only this issuer* meaning. Rejected; §5 case D guards it.
- **A Helm chart, an operator or a controller** — turns a bounded diagnostic
  worker into an agent. Explicitly out of scope; §23.
- **`latest` as a deployment reference** — mutable. Immutable semver and digest
  only; §13.
- **Docker Hub as a second canonical registry** — a second credential and a
  second place for identity to diverge; §14.
- **A long-lived cosign signing key** — silent on compromise, manual to rotate;
  §17.
- **Requiring the multi-arch *index* digest to reproduce** — measurably
  incompatible with required provenance; §16.
- **Blocking every scanner HIGH unconditionally** — converts one measurement
  into a permanent promise and pushes false positives into suppression files;
  §19.
- **Publishing before review** — nothing is pushed, tagged or signed here.

## 12. Release contract: base image and version authority

**[POLICY] The base image is `gcr.io/distroless/static-debian12:nonroot`,
pinned as tag *and* digest.** The tag carries human-readable lineage; the digest
is the immutable build input. Neither alone is sufficient — a tag is mutable, a
bare digest is unreadable in review.

**[POLICY] The Git semver tag is the single public version authority.** For an
official release these four MUST agree, and all four are projections of the
first:

```
git tag vX.Y.Z
  └─ binary version          (-ldflags -X main.version)
  └─ org.opencontainers.image.version
  └─ OCI tag :vX.Y.Z
```

`org.opencontainers.image.revision` MUST be the exact commit the tag names.

There is no second authority. No runtime environment variable, no version file,
no hand-typed release input. **[FACT]** the existing `main.version` model
already supports this: the binary version and the version label derive from one
build argument, so they cannot disagree with each other.

**[FACT]** What that model does *not* do, measured in Phase 7.1-R: the build
argument is free-form, and a build with `VERSION=v9.9.9-not-a-real-tag` and
`REVISION=deadbeef` produced an image whose binary and label both stated a
version no tag names and a revision no commit has. Internal consistency was
never the gap; the tie to Git was.

**[POLICY] The tie is made by the official build recipe, not by hand.**
`scripts/build-image.sh` derives all three values — version, revision, epoch —
from Git and accepts no version argument. It refuses a dirty tree and refuses an
untagged HEAD. **[FACT]** both refusals were exercised and exit 1.

## 13. Release contract: tags

**[POLICY] An OCI semver tag MUST NOT exist before the corresponding Git tag.**
Otherwise the same semver names two possible source identities, and the question
*"what is in v0.3.0?"* stops having one answer. Enforced by the recipe, which
requires `git describe --exact-match` to yield a `vX.Y.Z` tag.

**[POLICY] A published semver tag is immutable.** Once `:v0.3.0` is published it
is never rebuilt, re-pointed or overwritten. A defect ships as `v0.3.1`. This is
the rule Git tags already follow, applied to the registry.

**[POLICY] Official tags**: `:vX.Y.Z` and `:sha-<commit>`. Both immutable.

**[GUIDANCE] Moving tags** — `:vX.Y`, `:vX`, `:latest` — are permitted but
optional, and if published MUST be documented as unsuitable for pinning. A
deployment that references one has no reproducible identity. `latest` never
appears in a production example in this repository.

**[POLICY] Development images use `:sha-<commit>` and a non-semver version
string** (`0.0.0-dev+<commit>`). A development build MUST NOT occupy a semver
tag it might later be confused with — including a future release's tag used for
pre-release testing. Real pre-release semver (`v0.3.0-rc.1`) is a release, not a
development build, and goes through the official path.

## 14. Release contract: registry

**[POLICY] The canonical registry is `ghcr.io/hakanaltindag/svcdoctor`.** One
registry, chosen because it shares the release identity that §12 makes
authoritative: the image lives under the same account as the source and the Git
tag that names it. It needs no long-lived credential — `GITHUB_TOKEN` with
`packages: write` suffices — and it is where GitHub's OIDC identity, which §17
and §18 depend on, is natively available.

Docker Hub was considered and **rejected for v0.3.0**: it would add a second
distribution surface, a second credential to hold, and a second place for the
two to disagree, in exchange for discoverability the project does not yet need.
Mirroring is not forbidden later; it is not part of this contract.

## 15. Release contract: reproducibility

**[POLICY] Official release images MUST be reproducible. Development builds MUST
NOT be held to it.** Reproducibility costs deliberate build parameters, and
imposing them on `make image-dev` would buy nothing.

**[POLICY] The reproducibility claim is exactly this, and no broader.** Given

- the same Git commit,
- the same pinned builder and base digests,
- the same supported platform,
- the same official recipe (`scripts/build-image.sh`),

then **the platform image manifest digest MUST be identical**.

**The claim is scoped to platform image manifests. It is not a claim about the
index digest, and not a claim about attestation bytes.** §16 explains why that
scoping is forced rather than convenient.

**[POLICY] Deterministic timestamps come from the release commit.**
`SOURCE_DATE_EPOCH` is the committer timestamp of the commit being released —
`git show -s --format=%ct <commit>`. Not wall-clock, not CI start time, not the
tagger's clock. Source identity is the only input that is the same on every
machine and in every year. An annotated tag's own timestamp is deliberately not
used: the tag names the commit, and the commit is what was built.

**[POLICY] BuildKit timestamp rewriting is required**: the OCI/Docker exporter
option `rewrite-timestamp=true`.

**[FACT] Both are required; neither alone is sufficient.** Measured in Phase
7.1-R against this repository with buildx v0.25.0 / BuildKit v0.32.2, each
configuration built twice with a cold cache:

| Configuration | Platform digest reproduces? |
|---|---|
| `rewrite-timestamp=true` alone | **No** |
| `SOURCE_DATE_EPOCH` alone | **No** |
| **Both** | **Yes** |

This was worth measuring rather than assuming: the intuition that
`rewrite-timestamp` subsumes the epoch is wrong, and a contract that required
only one would have been unsatisfiable.

**[FACT]** The reproducible arm64 digest
`sha256:e3d581dac804f3633400ecd5fe4257fac18a161c7dc90d15bc03149d100b73ec` was
obtained in Phase 7.1 and reproduced in Phase 7.1-R, in a different session, and
from a second checkout at a different absolute path with a cold cache — as did
both platform digests built through the recipe itself.

**[FACT] What has *not* been measured**, and therefore what this contract does
not promise: reproducibility across differing BuildKit versions, differing
compression implementations, or a registry round-trip. Those are plausible and
untested. The claim is scoped to the recipe as written.

## 16. Release contract: attestations are not the image

This section exists because a naive reading of §15 produces a contract that
cannot be satisfied.

**[FACT]** Phase 7.1-R built the multi-arch image twice with provenance
(`mode=max`) and SBOM attestations enabled, cold cache:

| Artifact | Reproduces? |
|---|---|
| `linux/amd64` image manifest | **Identical** |
| `linux/arm64` image manifest | **Identical** |
| Attestation manifests | **Differ** |
| **Index (manifest list)** | **Differs** — it references the attestations |

The image itself is untouched by attestation: the arm64 digest with attestations
enabled equals the digest without them.

**[POLICY] Therefore: image reproducibility and attestation reproducibility are
separate contracts, and only the first is required.** Attestations authenticate
*how* an artifact was built; they legitimately contain build-time-specific data
and are not required to be byte-reproducible. Since §17 requires provenance, a
published index will reference attestations and **will not** have a reproducible
digest. Demanding index reproducibility would mean forbidding provenance.

That is the trade, stated plainly: we chose verifiable provenance over a
reproducible index digest, and kept reproducibility where it does the work — the
image bytes an operator actually runs.

**[GUIDANCE]** A verifier reproduces a release by rebuilding with the recipe and
comparing **platform image manifest digests**, not the index.

## 17. Release contract: SBOM, signature, provenance — three distinct artifacts

These are routinely conflated. They answer different questions and none
substitutes for another:

| Artifact | Question it answers | Question it does *not* |
|---|---|---|
| **SBOM** | What components are inside? | Who built it, is it authentic |
| **Signature** | Is this artifact from us, unmodified? | What is inside, how it was built |
| **Build provenance** | How, by whom, from which source was it built? | What is inside, is the source safe |
| **OCI labels** | What does the image *say* about itself? | Anything verifiable |

**[POLICY] OCI labels are self-declared metadata and are never provenance.**
They are a projection of release identity (§12), not an authority for it and not
evidence of it. Nothing may cite a label as provenance.

**[POLICY] An SBOM is required for every official release.** Canonical format:
**CycloneDX JSON**, one format only — a second format is duplicate surface that
can disagree with the first. It MUST cover the base image packages, the
svcdoctor binary and its Go modules. **[FACT]** Phase 7.1 generated one
(CycloneDX 1.6, 10 components: 5 base OS packages, svcdoctor, `franz-go/kmsg`,
Go stdlib).

**[POLICY] First-release delivery model: attach the SBOM to the GitHub Release
*and* publish it as an OCI referrer/attestation.** The Release copy is
retrievable by anyone reading the release notes; the OCI attestation travels
with the image. **[GUIDANCE]** If only one can be delivered initially, the OCI
attestation is the one that matters, because it stays attached to the digest.

**[POLICY] Image signing is required.** The signing target is the **digest**,
never a tag — a tag can be re-pointed, and a signature over a mutable reference
proves nothing about what is served later.

**[POLICY] Keyless signing via GitHub Actions OIDC (cosign). No long-lived
signing key.** A long-lived private key is a repository secret whose compromise
is silent and whose rotation is manual. Short-lived OIDC ties the signature to a
workflow identity instead. If keyless signing is unavailable in the accepted
pipeline, that is a **STOP** for publication, not a licence to introduce a key.

**[POLICY] Build provenance is required**, produced as a BuildKit provenance
attestation and/or a GitHub artifact attestation, bound to the final digest.
**[GUIDANCE]** This record does not claim a SLSA level. A level is a
specification with requirements this project has not audited itself against, and
naming one without that audit would be exactly the unearned claim
`docs/COMPATIBILITY.md` exists to prevent.

**[POLICY] Identity constraint.** Every signature and provenance statement MUST
bind to: repository `github.com/hakanaltindag/svcdoctor`, ref
`refs/tags/vX.Y.Z`, and the exact commit. A build from an arbitrary branch MUST
NOT be able to produce an official semver artifact. Phase 7.1-P enforces this
through the workflow trigger and OIDC claims.

## 18. Release contract: what reproducibility does and does not buy

**[GUIDANCE]** Stated because overclaiming here is a supply-chain anti-pattern.

Reproducibility **can** detect: undeclared build-input drift, path- and
time-dependent nondeterminism, an artifact that does not match its source, and
the inability to reconstruct a past release.

It **does not** prove: that the source is safe, that dependencies are safe, that
the builder was uncompromised, or that the CI identity is trustworthy. A
reproducible build of compromised source reproduces the compromise perfectly.

Reproducibility is a *consistency* property. Signing and provenance are the
*authenticity* properties. Neither substitutes for the other, and svcdoctor
must never market one as the other.

## 19. Release contract: publication, failure and vulnerability policy

**[POLICY] Publication order.** Signing requires a pushed digest, so signing
cannot precede push; the semver tag is the last thing created, so a partially
published release never wears one:

1. source gates and integration suites pass
2. Git semver tag exists and names the release commit
3. workflow verifies tag → commit, and refuses any other ref
4. reproducible multi-arch build via the official recipe
5. verify binary version == tag
6. vulnerability scan
7. generate SBOM and provenance
8. push **platform images by digest only**
9. push the multi-arch index
10. sign the index digest; attach SBOM and provenance to it
11. verify signature and attestations against the digest
12. pull by digest and smoke-run `--version`
13. **only now** apply the `:vX.Y.Z` tag
14. record the digest in the GitHub Release

**[POLICY] Partial publication must fail loudly and must not produce a usable
semver tag.** Digests pushed before a failure are unreferenced and harmless;
they are garbage, not a release. Because step 13 is last, an aborted run leaves
no `:vX.Y.Z` pointing at incomplete bits. GHCR offers no cross-artifact
atomicity, so ordering is the mechanism. Recovery is to fix and re-run at the
same commit — which is safe precisely because the build is reproducible — or, if
a semver tag was already published, to release `X.Y.Z+1` rather than repoint it
(§13).

**[POLICY] Vulnerability scanning is required for every official release.**
**[POLICY] The gate blocks on HIGH or CRITICAL findings that are exploitable in
the shipped runtime.** A finding may be released past only with a written,
release-note-visible justification naming the CVE and why it is not reachable —
for example a CVE in a package the image contains but never executes, in an
image with no shell and no package manager.

Blocking on every HIGH unconditionally was rejected: it converts one
measurement — **[FACT]** Phase 7.1 measured 0 CRITICAL and 0 HIGH across 5 base
OS packages and 3 Go components — into a permanent promise about unrelated
future CVEs, and it makes the honest response to a false positive an untracked
scanner-suppression file. Scan-only was also rejected: a gate nobody can fail is
not a gate. No general waiver system is being built; the exception is a sentence
in the release notes.

**[POLICY] The base image is re-evaluated for every release.** A digest pin
freezes the CA trust store and OS packages, which is what makes builds
reproducible — and it means a stale pin silently ships a stale trust store. See
§20.

## 20. The CA trust store is a security-sensitive build input

**[INVARIANT]** svcdoctor passes `RootCAs: nil` when no `--tls-ca-file` is
given, so the image's trust store *is* the product's default trust behaviour.

**[FACT]** That store comes from the pinned base digest — not from Go, and not
from the host. Changing the base digest can therefore change which certificate
authorities svcdoctor trusts **even when no svcdoctor code changed**.

This is expected and is the cost of a reproducible build. It is also why the pin
must not be described as "secure": it is *fixed*, which is a different property.

**[POLICY] Base digest refresh triggers**, any one of which reopens the pin:

- a CVE affecting the base image;
- a CA trust store update (a root added, removed or distrusted);
- a distroless or Debian base refresh;
- **every release**, as a mandatory re-evaluation;
- otherwise, a scheduled periodic review.

**[GUIDANCE]** Automated dependency updates (Dependabot/Renovate) may propose
the bump; a human accepts it, because it changes trust.

## 21. Publication pipeline

**[POLICY] `.github/workflows/release-oci.yml` is the only way an official image
is produced.** It is triggered by a `v*` tag push, validates the tag as
`^v[0-9]+\.[0-9]+\.[0-9]+$`, and derives every identity value by running
`scripts/build-image.sh --emit` — the same script a developer runs locally, so
there is one derivation rather than one for humans and a second for CI.

**[POLICY] Job ordering is the enforcement mechanism, not script ordering.**
`publish` declares `needs` on identity, staging, verification and the native
amd64 smoke, which themselves depend on the source, integration and
reproducibility gates. GitHub will not schedule `publish` until all of them
succeed, so the ordering cannot be broken by editing a step.

**[FACT] Tag-last is achievable, and this was measured rather than assumed.**
Against a local registry, `docker buildx imagetools create --tag <semver>
<repo>@<digest>` re-pointed the tag at the **existing** index digest without
rewriting it — the semver tag and the staged digest were byte-identical. That is
what makes the following sequence real:

1. build and push to `:sha-<commit>`, capture the index digest;
2. validate the digest — index platforms, OCI labels, vulnerability scan,
   attestation binding, SBOM contents;
3. sign the digest keylessly and **verify** the signature;
4. pull by digest and run a native amd64 smoke;
5. **only then** point `:vX.Y.Z` at that exact digest, and confirm it resolves
   to it.

**[POLICY] The staging tag is `sha-<commit>` and is immutable.** It names its
source and can never be mistaken for a release. An aborted run leaves
unreferenced blobs and possibly a SHA tag — never a semver tag naming a partial
release, because step 5 is last.

**[POLICY] Every third-party action is pinned to a 40-character commit SHA.**
This workflow holds `packages: write` and an OIDC signing identity; an action
referenced by mutable tag would be a release-signing compromise waiting to
happen. All seven pins were verified to resolve against the GitHub API.

**[POLICY] Credentials.** GHCR authentication uses `GITHUB_TOKEN`. There is no
PAT, no Docker Hub credential, no cosign private key and no `COSIGN_PASSWORD`.
No secret of any kind is passed into the build: `--build-arg` carries `VERSION`
and `REVISION` and nothing else, and there is no `--secret` mount.

**[POLICY] `cosign verify` is a release gate, not a formality.** It is
constrained by `--certificate-identity` to this repository's workflow at
`refs/tags/vX.Y.Z` and by `--certificate-oidc-issuer` to GitHub's issuer. An
unconstrained verify — or `--certificate-identity-regexp` with a permissive
pattern — accepts any valid Sigstore signature from any identity on earth, and
is close to no check at all.

### What Phase 7.1-P proved, and what it did not

**[FACT] Validated locally, against a real registry and a real multi-arch image
with attestations:**

- the tag-last mechanism preserves the digest;
- a `HEAD` request distinguishes an existing tag (200) from an absent one (404),
  which is what makes the immutability refusal implementable;
- the index carries exactly `linux/amd64` and `linux/arm64` plus two
  `unknown/unknown` **attestation** manifests, and the workflow's check
  distinguishes them — reporting an attestation as a third architecture would be
  a plausible and wrong claim;
- each attestation is bound to its platform image by
  `vnd.docker.reference.digest`;
- the CycloneDX SBOM names `svcdoctor`, `ca-certificates` and
  `franz-go/kmsg`;
- the workflow's reproducibility step reproduces both platform digests exactly.

**[FACT] Not proved, because it cannot be without publishing:**

- **The workflow has never run.** Every claim above is about its mechanisms and
  its logic, tested in isolation.
- **Native `linux/amd64` execution.** Phase 7.1 ran amd64 only under emulation.
  The workflow performs a native amd64 pull-by-digest smoke on `ubuntu-latest`,
  which is native amd64 — but that requires a real run. This remains **the one
  open evidence obligation before first publication**, exactly as §22 records.
- **cosign keyless signing and verification.** Keyless signing requires an OIDC
  identity that exists only in CI. It was deliberately *not* exercised locally:
  signing with a throwaway key would have uploaded a signature to the public
  Rekor transparency log, which is a publication, and this phase published
  nothing.
- **GHCR-specific behaviour** — authentication, tag immutability, package
  association. The mechanisms were proven against a local registry; GHCR is
  expected to behave the same way and has not been asked to.

## 22. Validation

Measured through the built image unless stated. Source baseline (`gofmt`,
`vet`, `golangci-lint`, `go test`, `-race`, `go mod tidy`, `make check`) and all
three integration suites — PostgreSQL, Apache Kafka 4.0.0, Redpanda v25.1.9 —
were green **before** any container work, so no image result masks a source
regression.

- Full PostgreSQL BASIC journey to session, hardened, via hostname and via IPv4
  literal.
- Kafka `PLAIN` and `SCRAM-SHA-256` to `Kafka metadata obtained`; Redpanda
  v25.1.9 `PLAIN` and `SCRAM-SHA-256` likewise.
- **Container and native diagnosis semantics are identical.** Schema version,
  states, findings, summary and counts all match. The only difference is the
  number of measured paths, because `localhost` resolves to two addresses on the
  host and the in-cluster service name to one — which is vantage, and vantage
  is the point.
- **Literal targets create no DNS evidence in a container or in a Pod**
  (ADR 0059 holds): `target.requested → tcp.connect`, no `dns.lookup` node.
- **Credential authority is unchanged.** From the container run against a
  three-broker cluster: exactly **one** credential-bearing authentication node,
  on the bootstrap endpoint only. The advertised-broker subtrees contain
  `kafka.broker_advertised`, `dns.lookup`, `tcp.connect` and `tls.handshake` and
  **no SASL step of any kind** — advertised `SecretFor`, `Reveal` and SASL bytes
  all **0** (ADR 0050). Production `security.Reveal` call sites remain **2**.
- Image contains **exactly one** file beyond the base: `/svcdoctor`. No `.git`,
  no fixture keys, no test data, no canary.
- `docker history` carries only `VERSION` and `REVISION` build args and the OCI
  labels — no secret, no token, no host path.
- Trivy: **0 CRITICAL, 0 HIGH**, over 5 real OS packages and 3 Go components —
  a scanned result, not an empty one.
- Multi-arch manifest contains exactly `linux/amd64` and `linux/arm64`. arm64
  was validated **natively**; amd64 ran under emulation, which is supporting
  evidence and not native production validation.
- `--version`, the report's run metadata and
  `org.opencontainers.image.version` all read `v0.3.0` from the single
  `-ldflags` authority.

### Added in Phase 7.1-R

Release-contract measurements, all against this repository with buildx v0.25.0 /
BuildKit v0.32.2, each configuration built twice with a cold cache:

- **Both determinism parameters are necessary.** `rewrite-timestamp=true` alone:
  not reproducible. `SOURCE_DATE_EPOCH` alone: not reproducible. Both: platform
  digests identical. The contract in §15 requires both because measurement said
  so, not because it seemed thorough.
- **Attestations do not perturb the image.** With provenance `mode=max` and SBOM
  enabled, both platform image digests were identical across builds while the
  attestation manifests — and hence the index — differed. §16 is scoped to
  platform manifests as a direct consequence.
- **The recipe reproduces across paths.** `scripts/build-image.sh` run from two
  different absolute checkouts with cold caches produced identical `linux/amd64`
  and `linux/arm64` digests.
- **The arm64 digest reproduced across sessions**, matching the value Phase 7.1
  measured earlier from an independent build.
- **The version-authority gap is real.** A build with
  `VERSION=v9.9.9-not-a-real-tag` and `REVISION=deadbeef` produced an image whose
  binary and label both asserted a version no tag names — which is what §12's
  derive-from-Git recipe closes.
- **Both recipe refusals fire.** A dirty tree and an untagged HEAD each exit 1
  before any build starts.

**Not verified: NetworkPolicy enforcement (§17 of the phase brief).** The
available k3s cluster accepts NetworkPolicy objects but does not enforce them —
a deny-all-egress policy still permitted the connection — so no egress-denied
result is claimed. The product behaviour that test was aimed at was
nevertheless measured directly: the advertised-broker sweep produced
`TCP_CONNECTION_REFUSED` from container vantage with findings explicitly
qualified as *"could not be reached from this vantage point … not the health of
the cluster"*.

## 23. Relationship to existing decisions

Consumes and contradicts nothing. ADR 0050 (discovery creates no credential
authority), 0052 (Kafka has no session; the terminal line is *Kafka metadata
obtained*), 0058 (trust versus identity), 0059 (an address is not a name),
0060 (TLS option validity) and 0061 (SCRAM bounds) were all exercised through
the image and all held. `SchemaVersion` remains **1**; no finding code, failure
class, state, step or dependency was added by either Phase 7.1 or Phase 7.1-R.

**[INVARIANT] The release contract changes no product behaviour.** §12–§20
govern how an artifact is built, named, signed and described. They do not touch
diagnosis, evidence, credential authority or the report. Phase 7.1-R added no
production Go code.
