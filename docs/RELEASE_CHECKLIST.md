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
      `make integration-postgres`, `make integration-kafka`, `make integration-redpanda`,
      `make integration-redis`, `make integration-valkey`, `make integration-rabbitmq`,
      `make integration-lavinmq`, `make integration-multitarget`.

      Eight, not three. Phase 9.2B corrected this list: Redis, Valkey, RabbitMQ, LavinMQ and
      the multi-target suite all shipped after it was written, and a release gate that runs
      three of eight suites is a gate with five blind spots.
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
- [ ] Frozen counts unchanged. Every one is pinned by a test, so this is a check that the
      tests still say what the contract says:

      | | |
      |---|---|
      | `domain.SchemaVersion` | 1 |
      | `domain.RunSchemaVersion` | 1 |
      | Finding codes | 60 (RabbitMQ 11) |
      | Failure classes | 42 |
      | `security.Reveal` production call sites | 4 — one per service, each in its wire package |
      | `SecretFor` production call sites | 4 |
      | External modules | 2 |

      Phase 9.2B corrected `Reveal` and `SecretFor` here: both read 2, and both have been 4
      since RabbitMQ shipped. A checklist item with a stale number is a check that passes
      while measuring nothing.

- [ ] Kafka `wire.Authenticate` 1; advertised `SecretFor`/`Reveal`/SASL bytes 0.
- [ ] Secret-leakage suites green: `go test ./test/security/...`, including the aggregate
      shareable corpus (`TestUX12…`) and the credential-boundary guards.
- [ ] Documentation and example guards green: every YAML example parses through the real
      loader, all seven help goldens match, the documented exit codes match the implemented
      ones, and no documented shell example discards the exit code
      (`go test ./internal/cli -run TestUX`).
- [ ] Mutation closure re-run for anything this release touched:
      `scripts/phase91a-mutations.sh`, `phase91b`, `phase91c`, `phase92b`, `phase93a`.
      **0 survivors.** Read each script's full output, never `tail -1`.
- [ ] Vulnerability scan: `govulncheck ./...`. If the tool is unavailable, say so in the
      release notes rather than skipping the line silently.
- [ ] **Release artifacts build from the candidate tree**, using the same recipe the release
      workflow runs — five platforms, `CGO_ENABLED=0`, `SHA256SUMS` written and verified:

      ```sh
      ./scripts/build-release.sh --untagged v<X.Y.Z> /tmp/svcdoctor-release-qualification
      ```

      `--untagged` waives exactly one rule, that the version is already a tag on HEAD, because
      qualification necessarily precedes the tag. It waives nothing else: a dirty tree is still
      refused, and the artifacts are what an official build of the same tree produces. Delete
      the output afterwards; no archive, checksum or binary belongs in the repository.

      The builder refuses a dirty tree, so a candidate with uncommitted work has to be
      committed first or qualified from a temporary clean checkout of the intended content.
      Do not relax the refusal to make this step convenient.
- [ ] **Private vulnerability reporting is enabled on the repository.** `SECURITY.md` names it
      as the project's only reporting channel, and the advisory form does not exist while the
      setting is off — a researcher following the policy would find a dead link.

      ```sh
      gh api repos/hakanaltindag/svcdoctor/private-vulnerability-reporting   # want {"enabled":true}
      ```

      **Measured `{"enabled": true}` at Phase 9.3A (2026-09-01), closing RB-02.** It read
      `{"enabled": false}` at the Phase 9.2B closure pass and at the v0.4.0 candidate gate. It
      is a repository setting rather than a tree change, so no commit can fix it and no commit
      can break it — re-measure it here every release rather than inheriting this line.
- [x] **Pre-existing mutation harness debt reconciled.** The v0.4.0 gate found all 20 survivors
      to be stale `-run` selectors left by Phase 9.1C's renumbering, not product gaps: every
      mutation was caught by its package's full suite. All were repaired, none retired, and all
      four harnesses now fail loudly on a regex that selects no test.
      **117 planted, 117 caught, 0 survivors.**
- [x] **Release archives and checksums have an executable mechanism.** ADR 0076 §2.3 requires
      five platform archives plus `SHA256SUMS`. `scripts/build-release.sh` produces them, the
      `archives` job in `release-oci.yml` calls **that script** rather than a copy of it, and
      the `release` job attaches its output beside `sbom.cdx.json`. Closed at Phase 9.3A as
      RB-05; the per-release check is the qualification step above and the asset check under
      CLOSE.
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
- [ ] the `archives` job: five archives and `SHA256SUMS`, built by `scripts/build-release.sh`
      from the tagged commit and verified in the job that produced them. It gates `publish`,
      so an archive failure stops the release **before** the semver tag reaches GHCR
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

- [ ] If this is a **re-run** of an already-published version: the workflow completed and
      `publish` reported that the semver tag already held the validated digest and wrote
      nothing. A re-run that *published* a tag which the pre-tag negative check said was absent
      means something changed underneath; stop and read the digests.
- [ ] **The `release` job created the GitHub Release.** It runs inside `release-oci.yml`, after
      `publish`, and re-checks that the semver tag still resolves to the validated digest before
      it announces anything. Creating the Release by hand skips that check and is not the
      documented path.
- [ ] Release is `Latest`, confirmed through the API rather than the web UI:
      `gh api /repos/<owner>/<repo>/releases/latest --jq .tag_name`.
- [ ] Release is not a draft and not a prerelease; title is `svcdoctor v<X.Y.Z>`.
- [ ] The body records the index digest, and `sbom.cdx.json` is attached.
- [ ] **All six binary assets are attached and verify.** The `release` job reads the asset list
      back from the API and fails without them, so this is a confirmation rather than a
      discovery — but download them and check independently, because a checksum file nobody
      ever verifies is decoration:

      ```sh
      gh release download v<X.Y.Z> -p 'svcdoctor_*' -p SHA256SUMS
      sha256sum -c SHA256SUMS      # or: shasum -a 256 -c SHA256SUMS
      ```
- [ ] **Public documentation names this release**, not the previous one. The install pins in
      `README.md` and `docs/QUICKSTART.md`, the image pin in `docs/CI.md`, the Kubernetes
      examples, the sample `svcdoctorVersion` in `docs/OUTPUT.md` and the supported-version
      example in `SECURITY.md` all name a concrete version, and every one of them is stale the
      moment a release publishes. Closed for v0.4.0 in the Phase 9.4 documentation commit;
      re-do it for each release.
- [ ] Re-running the `release` job is safe and was left safe: it verifies an existing Release
      rather than recreating it. If it ever reports a mismatch, that is §D1 of the playbook and
      needs a human, not a re-run.
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
