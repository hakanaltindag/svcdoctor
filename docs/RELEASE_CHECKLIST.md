# Release checklist

The permanent release ceremony. It exists so a release follows a list instead of rediscovering
the process, and because the two failures this project has actually had were both silent.

The normative rules are in ADR 0062 §12–§21c. This is the operational form of them.

## The one rule everything else serves

> **A semver tag is never moved.** Not locally, not on origin, not in the registry.

A broken release is **succeeded**, never repaired. If `v0.3.1` is wrong, the fix is `v0.3.2`.

This is not fastidiousness. Once a tag is pushed, `proxy.golang.org` may serve it and
`sum.golang.org` records the module checksum in an **append-only transparency log**. Deleting
the tag does not remove that record; it leaves a published checksum for a tag that no longer
resolves to it, and `go install …@<version>` then fails verification for anyone who already
fetched it. The tag is immutable whether or not we agree to treat it that way.

## PREPARE

- [ ] Release branch is pushed and its head is the intended release content.
- [ ] `git fetch origin`; know the ancestry between `main` and the release branch.
- [ ] Working tree clean. No untracked fixture output. `git status --porcelain` is empty.
- [ ] Source gates on the **release branch head**:
      `git diff --check`, `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...`,
      `go test ./...`, `go test -count=1 -race ./...`, `CGO_ENABLED=0 go build ./...`,
      `go mod tidy` (no change), `make check`.
- [ ] Integration suites, **sequentially** — they contend for ports and containers:
      `make integration-postgres`, `make integration-kafka`, `make integration-redpanda`.
- [ ] **The same suites on a native Linux amd64 runner**, via
      `gh workflow run validate-integration.yml --ref <branch>` (or a
      `validate-integration/**` branch push), and all three green.

      A local run does not answer this. The developer platform differs from the runner in ways
      the fixtures are sensitive to — most concretely, macOS bind mounts report a host file as
      root-owned and grant the read regardless, so a container's file-ownership check passes on
      a value the host never had. Docker Desktop, Colima and arm64 emulation reproduce that
      masking rather than the condition. **`v0.3.1` was lost exactly here:** the suites were
      green locally, had never been run on Linux for that tree, and failed on the release
      runner after the tag was already immutable.
- [ ] Security invariants unchanged: SchemaVersion 1, `Reveal` 2, `SecretFor` 2,
      Kafka `wire.Authenticate` 1, advertised `SecretFor`/`Reveal`/SASL bytes 0.
- [ ] Blocker inventory: every open item classified *release blocker* / *documented
      limitation* / *operational debt* / *future feature*. A blocker is not relabelled to ship.
- [ ] Release notes written, with the baseline set to **the last actual GitHub Release** — not
      the last Git tag. Those differ.
- [ ] Every public claim is covered by a guard test, or is not made.

## AUTHORIZE

- [ ] Report ends with `READY TO TAG <version>: YES/NO`.
- [ ] **A human authorizes explicitly.** Do not tag on inference.

## MERGE — before tagging, always

- [ ] Merge the release branch into `main` **first**, and tag the merge result.
- [ ] **Verify the commit about to be tagged actually contains the release machinery:**

      ```sh
      git ls-tree -r <commit> --name-only -- \
        Dockerfile scripts/build-image.sh \
        .github/workflows/release-oci.yml .github/workflows/oci-stage-verify.yml
      ```

      All four must be present. **This check exists because its absence is silent:** a tag on a
      tree without `release-oci.yml` triggers no workflow, produces no error, and publishes
      nothing. `v0.3.0` was lost exactly this way.
- [ ] `origin/main == local main`, tree clean, gates re-run after the merge.
- [ ] **Native Linux integration proof on the merge commit itself**, not on the branch head it
      came from. The merge result is the tree that gets tagged, and a clean merge can still
      combine two individually-green trees into a failing one. Confirm the green
      `validate-integration` run's commit SHA equals the commit about to be tagged.

## PRE-TAG NEGATIVE CHECK

Immediately before creating the tag, confirm the version is absent everywhere:

- [ ] Git, local and remote: `git tag -l`, `git ls-remote --tags origin`.
- [ ] GHCR: `:<version>`, `:latest`, `:v0`, `:v<major>.<minor>` all return 404.
- [ ] GitHub Releases: `gh release view <version>` reports not found.

## TAG

- [ ] `git tag -a v<X.Y.Z> -m "svcdoctor v<X.Y.Z>"` — annotated, on the merge commit.
- [ ] Verify the tag object: name, annotated, and target commit as expected.
- [ ] `git push origin v<X.Y.Z>` — that tag and nothing else.

**From this moment the tag is immutable**, whatever happens next.

## AUTOMATE — `release-oci.yml` runs on the tag

Watch the whole run, not just the build. Required gates:

- [ ] source gates (including the `golangci-lint` install — `make check` fails closed without it)
- [ ] integration suites
- [ ] reproducibility: both platform digests identical across two cold-cache builds
- [ ] staging under `sha-<full release commit>`, refusing to re-point an existing tag
- [ ] vulnerability scan, blocking, no blanket suppressions
- [ ] CycloneDX SBOM generated and attached; **no SPDX**
- [ ] BuildKit provenance attached, naming this repo, the commit and `refs/tags/v<X.Y.Z>`
- [ ] keyless cosign sign over the **digest**
- [ ] `cosign verify` and `cosign verify-attestation`, narrowly constrained
- [ ] native amd64 pull-by-digest smoke, hardened
- [ ] image content audit and system CA smoke

## PUBLISH — semver tag last

- [ ] The semver tag is applied **only after** every gate above, to the already-validated digest.
- [ ] Prove digest equality: the validated staging index digest **==** the digest `:v<X.Y.Z>`
      resolves to. Nothing is rebuilt at publication.

## VERIFY — independently, not just "the workflow was green"

- [ ] `cosign verify` and `cosign verify-attestation` against `IMAGE@<release digest>` from a
      workstation.
- [ ] Anonymous pull by digest, with no credentials.
- [ ] `go install github.com/hakanaltindag/svcdoctor/cmd/svcdoctor@v<X.Y.Z>`; `--version` matches.
- [ ] Moving tags absent: `latest`, `v0`, `v<major>.<minor>`.

## CLOSE

- [ ] GitHub Release created from the reviewed notes, referencing the tag. The Release is a
      human surface; it never defines the version.
- [ ] README and Kubernetes examples reference the real published version and a real digest.
- [ ] Release evidence recorded: run ID, digests, Rekor indices, certificate identity.
- [ ] Staging-artifact retention decided.

## What is never done

- move or force-push a semver tag; delete one to "fix" a release
- re-point a published OCI semver tag
- hand-publish a missing artifact to complete a failed release
- bypass a failed scan, signature, attestation or smoke gate
- create `latest`, `v0` or `v<major>.<minor>`
- publish from a dirty tree, or from an unmerged feature branch
- introduce a GHCR PAT, a Docker Hub credential or a long-lived cosign key
- add a manual version input to the release workflow
