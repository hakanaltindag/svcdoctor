# Release failure playbook

What to do when a release goes wrong. The point of writing it down is that every entry below is
a decision made *before* the pressure of a half-finished release, when "just move the tag" looks
reasonable.

The governing rule, from ADR 0062 §13 and §21c:

> **A semver tag is never moved. A broken release is succeeded, not repaired.**

## A — failure *before* the Git tag exists

Nothing is published and nothing is immutable. Fix it normally: commit, re-run gates, re-run the
pre-tag checklist. No ceremony applies yet.

This is the only cheap failure, which is why the checklist front-loads so much into it.

## B — tag pushed, release workflow fails before the OCI semver tag

The Git tag is immutable from the moment origin has it. `release-oci.yml` is built so this state
is safe: the semver OCI tag is applied last, so an aborted run leaves unreferenced blobs and
possibly a `sha-<commit>` staging tag — **never** a `:vX.Y.Z` naming a partially validated
image.

Do:

1. Read the failing gate. Do not re-run hoping.
2. Decide whether the fault is in the *source* or in the *pipeline*.
   - Pipeline-only (a runner, a flake, a rate limit): re-running the same tag is safe. **Every
     tag-writing step is idempotent by the same rule** — compare, then reuse or stop. Staging
     compares `sha-<commit>`'s platform digests against a fresh reproducible build; `publish`
     compares `:vX.Y.Z` against the digest this run validated. Each reuses an identical digest
     without writing, and each **hard-stops** on a different one rather than re-pointing. So a
     re-run either reproduces the release exactly or refuses; it cannot quietly replace it.
   - Source fix required: the next version is **vX.Y.(Z+1)**. The failed tag stays where it is.

Never: delete the tag, move it, amend the release commit, or hand-publish the missing artifacts.

### B1 — the failing gate is an integration fixture

A fixture fault reads like a pipeline fault, and that resemblance is the trap. Both look like
"CI broke"; only one is safe to re-run. The discriminator is not how the failure *feels* but
whether the tagged tree would produce it again:

- **Pipeline fault** — the same commit passed this gate before, on this runner class, and the
  failure names something outside the repository: a pull rate limit, a runner disappearing, a
  registry 5xx. Re-running the tag is safe.
- **Fixture fault** — the gate has never passed on this runner class, or it fails identically on
  every re-run. The fixture is part of the source. Re-running cannot fix it, and each attempt
  spends the tag's credibility while proving nothing.

The cheap test: run the suite again on the same runner class *without* a tag, using
`validate-integration.yml`. If it fails again, the fault is in the tree and the version is spent.

A fixture fault is a **source fault** for the purposes of the table below, even though no
production Go changed. The next version is **vX.Y.(Z+1)**.

#### Recorded instance — v0.3.1

`v0.3.1` failed at `Integration (postgres)` (run `32689503708`). `Publish semver tag` and `OCI`
were **skipped** by `job.needs`, so:

| | |
|---|---|
| Git tag `v0.3.1` | exists, immutable, untouched |
| `ghcr.io/…:v0.3.1` | **never created** — only `sha-*` staging tags exist |
| GitHub Release v0.3.1 | **never created** |
| Production Go implicated | none |
| Fault | fixture: the PostgreSQL TLS private key was bind-mounted with the runner's ownership, and PostgreSQL refuses to start on a key it does not own |
| Succeeded by | v0.3.2 |

Two lessons were paid for here and are now mechanical rather than remembered. The fixture
normalizes key ownership inside the pinned image and a guard asserts it on the real files
(`test/integration/postgres/fixture_test.go`). And the suites can be run on a native Linux
runner *before* a tag exists (`validate-integration.yml`) — the gap that let this reach a tag
was not a missing gate but a gate that could only be reached too late.


## C — tag pushed but the workflow never ran

The symptom is silence: no run, no error, no artifact.

Almost always the tagged commit does not contain `release-oci.yml`. Verify:

```sh
git ls-tree -r <tag>^{} --name-only -- \
  Dockerfile scripts/build-image.sh \
  .github/workflows/release-oci.yml .github/workflows/oci-stage-verify.yml
```

If any is missing, that tag can never produce a release. **Retire the version and release the
next patch** from a correctly merged `main`. This is what happened to `v0.3.0`.

Do not delete the tag. `proxy.golang.org` may already serve it and `sum.golang.org` will have
recorded the module checksum permanently; removing the tag leaves a published checksum pointing
at nothing and breaks `go install …@<version>` verification for anyone who fetched it.

## D — OCI image published, GitHub Release missing or its creation failed

The container release is complete and correct; only the human surface is absent.

**Do not rebuild the image.** The Release is documentation of a release, not the release
itself, and the artifact it documents is already immutable.

This is categorically different from A, B and B1, and the difference is worth stating plainly
because the instinct after any red workflow is the same. There the *artifact* was in doubt, so
a source fix meant a new version. Here the artifact passed every gate, is signed, is attested
and resolves by digest. Nothing about it changes by re-running the Release step.

So:

- **Re-run the whole workflow for the same tag.** Every stage is idempotent, which is what makes
  this the ordinary recovery rather than a special procedure. Staging reuses the existing
  `sha-<commit>`; `publish` finds `:vX.Y.Z` already at the validated digest and writes nothing;
  `release` creates the GitHub Release only if none exists, and otherwise verifies the existing
  one against this run. A second run produces no second artifact and deletes nothing.

  This is a change made *because of* v0.3.2. `publish` used to fail on any existing semver tag,
  which was right while a release could only be published once and wrong the moment one had to
  be resumed — it refused the resume on a tag the pipeline itself had just written correctly,
  and pushed the recovery off the automated path onto a hand-made Release that carries none of
  the checks. Presence is not evidence of an overwrite; a differing digest is, and that is now
  what is tested.
- **Never burn a patch version on a GitHub UI failure.** `v0.3.3` for a failed `gh release
  create` would publish an identical image under a second version number and leave two tags
  claiming to be the same release.
- **Never create the Release by hand while the automated path is broken.** A hand-made Release
  is not verified against the digest, and it is the automated path that carries the check.

The one thing that must hold before re-running: the semver tag still resolves to the validated
digest. The job re-checks this itself, immediately before publishing, and refuses if it does
not — see §D1.

## D1 — GitHub Release exists but names the wrong artifact

The dangerous case, and the only one here that is not self-healing.

If a Release for the version exists but disagrees with the run — a different tag, a draft, an
unexpected prerelease, notes that do not record the published digest — **stop**. Do not delete
it, do not edit it, do not re-point anything.

A published Release is a public object. It may already have been linked to, cited or fetched by
automation, and once immutable it cannot be rewritten at all. More importantly, a disagreement
means two processes believed different things about one version, and overwriting one of them
destroys the evidence of which. The workflow refuses this deliberately rather than reconciling
it: **human review**, then a decision recorded here.

## E — GitHub Release exists but its notes or docs are wrong

Artifact identity is untouched by prose. Correct the notes, the README and the examples
directly. Editing a GitHub Release body does not change what shipped, and no new version is
needed for a documentation fix.

The exception: if the notes *claim capability the artifact does not have*, that is a
correctness problem in the release, not a typo. Fix the claim immediately, then decide whether
the capability gap itself warrants a patch release.

## F — signature or attestation is wrong

Stop. Do not re-sign, do not re-attest, do not delete referrers.

An artifact whose signature or SBOM cannot be trusted is not repaired by attaching a better
one — the old material stays in the transparency log, and a verifier now sees two claims. Decide
a patch release, and record what was wrong with the old one so the next verification is
comparable.

## G — a published image turns out to be vulnerable or defective

The image is immutable and stays. Publish **vX.Y.(Z+1)**, and say plainly in its notes what was
wrong with its predecessor. Do not re-point the old tag, and do not delete the old image while
anything may still reference it by digest.

## Quick reference

| Situation | Tag action | Image action | Next version |
|---|---|---|---|
| Fails before tag | none yet | none | same |
| Workflow fails, pipeline fault | keep | none | same, re-run |
| Workflow fails, source fault | keep | none | **patch** |
| Workflow fails, integration fixture fault | keep | none | **patch** |
| Workflow never ran (missing machinery) | keep, retire version | none | **patch** |
| Image published, Release missing or its creation failed | keep | none | **same** — re-run the release job |
| Release exists naming the wrong artifact | keep | none | stop; human review |
| Docs or notes wrong | keep | none | same |
| Signature/attestation wrong | keep | none | **patch** |
| Image defective | keep | none | **patch** |

Every row says *keep the tag*. That is the whole playbook.
