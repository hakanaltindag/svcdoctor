# ADR 0076 — Release artifact, version and repository-hygiene contract

**Status:** Accepted
**Date:** 2026-09-01
**Phase:** 9.2A
**Extends:** ADR 0062 (OCI runtime and Kubernetes execution model), whose registry, tag,
reproducibility and supply-chain rules are unchanged and remain in force.

---

## 1. Context

svcdoctor has six Git tags and one completed publication. `docs/releases/v0.3.3.md` records the
history plainly: `v0.2.0` was never published, `v0.3.0` was tagged on a tree with no
`Dockerfile`, `v0.3.1` was stopped by its own integration gate, `v0.3.2` published an image and
no GitHub Release, and **`v0.3.3` is the first release to complete the whole path** — signed
multi-arch image, CycloneDX SBOM, build provenance, GitHub Release.

That published release contains PostgreSQL and Kafka. The current tree also contains Redis,
RabbitMQ and `svcdoctor run --config`, none of which has ever been in a release.

The Phase 9.2A audit measured the release surface as an external user meets it and found four
things.

**The binary story ended at `v0.1.0`.** The README says so: prebuilt archives were attached to
that release and "are not part of the current delivery model, which is the container image plus
`go install`". Measured, all five candidate platforms cross-compile clean today with
`CGO_ENABLED=0` and no CGO anywhere — `linux/amd64`, `linux/arm64`, `darwin/amd64`,
`darwin/arm64`, `windows/amd64`, and `freebsd/amd64` besides. The artifacts are one workflow
step away and do not exist.

**There is no way to report a vulnerability.** No `SECURITY.md` at the root or under `.github/`.
`docs/SECURITY.md` exists and is the architecture document — its headings are credential
binding, TLS verification, protocol wire boundaries, redaction boundary. A case-insensitive
search of `README.md`, `docs/` and `.github/` for a reporting address, "responsible
disclosure", "private vulnerability" or "security advisory" returns nothing. svcdoctor
transmits credentials and publishes a redaction guarantee; the audit itself found a disclosure
defect in that guarantee.

**Version identification is already solved and should not be touched.** `resolvedVersion()`
combines an `-ldflags` injection with Go's stamped module version and correctly refuses to
report a pseudo-version or a `+dirty` version as a release. One authority feeds both
`--version` and `run.svcdoctorVersion` in every report, deliberately, so a shared report can
never name a different build than the operator saw.

**Supply-chain posture is strong and inconsistent in one place.** Four of five workflows pin
every third-party action by commit SHA. `ci.yml` — the one that runs on every pull request —
pins by tag. And nothing scans the module graph: Trivy scans the published image, which is a
distroless static binary, and `govulncheck` is absent.

---

## 2. Decision

### 2.1 Version identification is unchanged

`svcdoctor --version` is canonical. `resolvedVersion()` is the single authority and keeps
feeding both `--version` and the report's `run.svcdoctorVersion`. No schema change:
**`SchemaVersion` stays 1 and `RunSchemaVersion` stays 1.** The producer version is already in
both documents and nothing needs to be added to carry it.

`svcdoctor version` as a subcommand alias, and enriching `--version` with commit, OS/arch and
Go version, are NICE_TO_HAVE and are not required for release.

### 2.2 Canonical install methods

- **Running it:** the container image, `ghcr.io/hakanaltindag/svcdoctor:vX.Y.Z`, pinned by
  digest for anything that matters.
- **Building it:** `go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@vX.Y.Z`.
- **Installing it as a human:** signed archives from the GitHub Release, once §2.3 exists.

### 2.3 The minimum artifact set for the next release

| Artifact | Class |
|---|---|
| `tar.gz` for `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`; `zip` for `windows/amd64` | required |
| `SHA256SUMS` covering all five | required |
| Multi-arch container image, signed | exists |
| CycloneDX SBOM, build provenance, keyless cosign signature over the image digest | exists |
| GitHub Release with notes | exists |
| SBOM and signature over the **binary archives** | SHOULD_FIX — the three mechanisms already exist for the image |
| Homebrew tap, apt, RPM, Windows package, `freebsd` archive | out of scope |

`freebsd/amd64` builds clean and is deliberately not published: nothing has been run against it,
and ADR 0062's rule that a claim needs evidence applies to platforms as much as to services.

Every ADR 0062 rule survives intact: one canonical registry, the Git semver tag as the only
version authority, a tag never moved and never rebuilt, reproducible platform image manifests,
and production pinning by digest.

### 2.4 macOS artifacts carry a documented resolver limitation

`internal/probe/dns/resolver.go` uses `net.DefaultResolver`. A `CGO_ENABLED=0` macOS binary
therefore uses Go's pure-Go resolver, which does not consult `/etc/resolver/*` — split-horizon
DNS, ordinary on a corporate VPN — or mDNS. A **DNS diagnostic tool** can then report
`DNS_NAME_NOT_RESOLVED` for a name the operator's own machine resolves.

CGO is **not** enabled to fix this. The limitation is documented wherever a macOS artifact is
offered, `GODEBUG=netdns=cgo` is named as the workaround, and the statement that the Linux
container image is unaffected is made explicitly.

### 2.5 A root `SECURITY.md` is required before any further public release

It names a private reporting channel — GitHub private vulnerability reporting is sufficient and
needs no infrastructure — states the supported-version window, and says explicitly that
**credential leakage and redaction failures are in scope**. `docs/SECURITY.md` stays where it
is and is described in prose as what it is: the security architecture record.

`CONTRIBUTING.md` is required too, and is short: the quality gate (`make check` mirrors CI),
the ADR-first rule for anything that changes a contract, the English-only language policy, and
the test-placement convention. `CODE_OF_CONDUCT.md`, issue templates, PR templates and
`dependabot.yml` are NICE_TO_HAVE.

### 2.6 Supply-chain gaps close before the release

- Every third-party action in **every** workflow is pinned by commit SHA with a version
  comment. `ci.yml` is the only one that is not, and it becomes one.
- `govulncheck ./...` runs on pull requests. It is a tool, not an import: the module count
  stays **2**.
- `docs/RELEASE_CHECKLIST.md` is corrected. It currently reads "`Reveal` 2, `SecretFor` 2" —
  both are **4** — omits `RunSchemaVersion`, the 60 finding codes and the 42 failure classes,
  and omits the Redis, Valkey, RabbitMQ and LavinMQ integration suites from its sequential run
  list. It also gains `govulncheck`, the documentation-example validation of ADR 0075 §2.6, and
  the UX acceptance suite.

### 2.7 The next release is `v0.4.0`

Not `v1.0.0`. Not a pre-release label. Not a patch.

- Four release blockers are open, one of them a disclosure defect in the feature whose purpose
  is safe disclosure. Nothing ships over that.
- `v0.x` is the honest signal. The CLI has been stable across four tags, `SchemaVersion` has
  been 1 since Phase 4 and has never broken, and the exit codes are frozen — but Redis, RabbitMQ
  and `run --config` have never been published, and the `--user`/`--username` split is a wart a
  `1.0` would freeze permanently.
- `alpha` or `beta` would be **less** accurate. Four services are validated at Level 3 against
  seven real implementations with committed fixtures, mutation closure is at zero survivors, and
  108 of 108 multi-target requirements are traced to named tests.
- A minor bump rather than a patch, because `v0.4.0` is what introduces Redis, RabbitMQ and
  multi-target execution to the public.

`v1.0.0` becomes discussable when the blockers are closed, the four leaf flag sets are
reconciled or deliberately frozen as they stand, and at least one managed platform has real
evidence.

---

## 3. Consequences

**A macOS or Windows engineer can install svcdoctor.** Today they need Docker or a Go
toolchain. That is the single largest install-journey gap and five archives close it.

**The release workflow grows a build-and-attach job.** It builds five targets, generates
`SHA256SUMS`, and attaches both to the Release the tag already creates. It publishes nothing new
to the registry and touches no ADR 0062 rule.

**The macOS artifact ships with a stated limitation rather than a silent one.** A user who hits
split-horizon DNS reads why, instead of concluding the tool is wrong about their network. This
is the same discipline the product applies to its own findings, applied to its own packaging.

**A researcher has somewhere to send a finding.** For a tool that transmits credentials this is
not optional, and the audit demonstrated the need by producing exactly such a finding.

**`govulncheck` may fail a pull request on a dependency advisory.** With two dependencies, both
with no transitive dependencies of their own, that will be rare and it will be real.

**`v0.4.0` means the public sees Redis, RabbitMQ and `run` for the first time in one release.**
The release notes carry the whole delta from `v0.3.3`.

---

## 4. Rejected alternatives

**Publish binaries for every platform Go supports.** Rejected. An artifact is a claim that the
platform is intended to work. Five are what the compatibility document can stand behind;
`freebsd` builds and is unpublished for exactly that reason.

**Enable CGO for macOS to get the system resolver.** Rejected. It gives up static linking and
simple cross-compilation, requires a macOS builder per architecture, and produces a binary with
a libc dependency — for a resolver difference that affects a minority of macOS users and is
correctable at runtime with `GODEBUG=netdns=cgo`. Documenting a real limitation is better than
hiding it behind a build complication.

**Ship a Homebrew tap.** Rejected for this release. A tap is a second release surface with its
own trust story and its own update path, for a product with no user base yet. Signed archives
plus a signed image are enough.

**Add commit and build date to `--version` now.** Rejected as unnecessary. The version resolves
to a tag, the tag resolves to a commit, and the report already carries the version. This is a
convenience, and convenience does not gate a release.

**Put a producer-version field into `domain.Report`.** Rejected, because it already exists.
`run.svcdoctorVersion` is present in both the single-target report and the aggregate. Adding a
second field would create two answers to one question, which is precisely what
`resolvedVersion()` was written to prevent.

**Release `v1.0.0` because Phase 9 completed.** Rejected explicitly. Phase completion is an
internal milestone. The public contract is the CLI, the report schema and the exit codes, and
three of those five commands have never been released.

**Call the next release `v0.3.4`.** Rejected. A patch number for a release that introduces two
services and a new top-level command misdescribes it to everyone reading a changelog.

**Use a pre-release label (`v0.4.0-beta.1`).** Rejected. It would understate evidence that is
genuinely stronger than beta and would give users a reason to wait for a release that is not
coming — the blockers gate `v0.4.0` itself, not a promotion out of beta.

---

## 5. Verification

| Claim | Verified by |
|---|---|
| `--version` reports the injected or module version; a dev build reports `dev` | UX-16; `cmd/svcdoctor/version_test.go` (existing) |
| `run.svcdoctorVersion` equals what `--version` printed | UX-16 |
| `SchemaVersion` 1 and `RunSchemaVersion` 1 unchanged | existing domain tests; `test/golden` |
| All five platforms build with `CGO_ENABLED=0` | UX-24, extended to a cross-compile matrix |
| The release attaches five archives and `SHA256SUMS` | `internal/cli/releaseworkflow_test.go`, extended |
| Every ADR 0062 rule still holds | `internal/cli/releasecontract_test.go` (existing) |
| The macOS resolver limitation is documented where a macOS artifact is offered | UX-24 |
| A root `SECURITY.md` names a private channel and a supported-version policy | UX-21 |
| `CONTRIBUTING.md` names the gate, the ADR rule and the language policy | UX-23 |
| Every third-party action in every workflow is SHA-pinned | UX-22 |
| `govulncheck` runs on pull requests | UX-22 |
| The release checklist's invariant counts match the tree | UX-13 |
| The module count is still 2 | `test/security/dependency_test.go` (existing) |
