package cli

import (
	"regexp"
	"strings"
	"testing"
)

// The publication-workflow audit.
//
// # Why a Go test reads a YAML file
//
// Because the alternative is that nothing reads it. `.github/workflows/
// release-oci.yml` enforces ADR 0062 sections 12-20, and it runs exactly once
// per release — on a tag push, in an environment nobody can rehearse. Every
// mistake in it is therefore discovered at the worst possible moment, on the
// artifact that was supposed to be trustworthy.
//
// These guards are deliberately textual rather than a YAML parse. svcdoctor has
// **one** external dependency and a test that pins that count; adding a YAML
// library so a test can read a CI file would trade a real architectural
// property for a marginally tidier assertion. Where structure genuinely matters
// — the job dependency graph — the text is precise enough to check, because
// `needs:` lines are the structure.
//
// # What these cannot check
//
// That cosign actually signed, that Trivy actually blocked, that GHCR actually
// refused an overwrite. Those need a registry and a real run. The workflow is
// written so those are hard failures at release time; these guards only ensure
// the steps that produce them cannot quietly disappear from the file.

const (
	releaseWorkflow = ".github/workflows/release-oci.yml"

	// The build, scan, SBOM, provenance, signing, verification and runtime-smoke
	// machinery, extracted in Phase 7.1-V so `validate-oci.yml` could rehearse
	// the *release* path rather than a copy of it. See sharedMachineryTest.go's
	// drift guards in validateworkflow_test.go.
	sharedWorkflow = ".github/workflows/oci-stage-verify.yml"
)

// releasePipeline is everything a release tag actually executes: the caller that
// owns identity and semver authority, plus the shared machinery it invokes.
//
// Guards about *what a release does* must read this, not the caller alone.
// After the extraction, a guard scoped to `release-oci.yml` would pass happily
// while cosign, Trivy and the SBOM had been deleted from the file that performs
// them — the exact blindness the extraction could have introduced.
func releasePipeline(t *testing.T) string {
	t.Helper()
	return withoutComments(readRepoFile(t, releaseWorkflow)) + "\n" +
		withoutComments(readRepoFile(t, sharedWorkflow))
}

// TestTheReleaseWorkflowTriggersOnlyOnTags pins ADR 0062 sections 12 and 13.
//
// A branch trigger is the single most dangerous edit possible here: it would let
// any push to a branch run a workflow holding `packages: write` and an OIDC
// signing identity, and the semver tag would no longer be the version authority.
func TestTheReleaseWorkflowTriggersOnlyOnTags(t *testing.T) {
	wf := withoutComments(readRepoFile(t, releaseWorkflow))

	trigger, _, _ := strings.Cut(wf, "permissions:")
	if !strings.Contains(trigger, "tags:") {
		t.Fatal("the release workflow does not trigger on tags")
	}
	for _, forbidden := range []string{"branches:", "workflow_dispatch:", "pull_request:", "schedule:"} {
		if strings.Contains(trigger, forbidden) {
			t.Errorf("the release workflow can be triggered by %q.\n\n"+
				"Only a semver tag may produce an official image: this workflow holds "+
				"packages: write and an OIDC signing identity.", forbidden)
		}
	}

	// The `v*` filter is loose on purpose; the strict rule is a step.
	if !strings.Contains(wf, `'^v[0-9]+\.[0-9]+\.[0-9]+$'`) {
		t.Error("the release workflow does not strictly validate the tag as vX.Y.Z. " +
			"The `v*` trigger filter alone would accept v0.3, v01.2.3 and v0.3.0-dev.")
	}
}

// TestTheReleaseWorkflowNeverAcceptsAVersionInput pins ADR 0062 section 12.
//
// One version authority means the workflow may not offer a second. An `inputs:`
// block with a version, or a hand-written literal, would let a release name
// itself something the Git tag does not.
func TestTheReleaseWorkflowNeverAcceptsAVersionInput(t *testing.T) {
	wf := withoutComments(readRepoFile(t, releaseWorkflow))

	for _, forbidden := range []string{"inputs:", "github.event.inputs"} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("the release workflow accepts %q, creating a second version authority", forbidden)
		}
	}
	if !strings.Contains(wf, "./scripts/build-image.sh --emit") {
		t.Error("the release workflow does not derive its identity from " +
			"scripts/build-image.sh --emit.\n\n" +
			"Re-deriving the version from github.ref would be a second derivation " +
			"that can drift from the one developers run locally.")
	}
	// And it must confirm the derived version is the tag that triggered it.
	if !strings.Contains(wf, "!= \"${GITHUB_REF_NAME}\"") {
		t.Error("the release workflow does not verify the derived version equals the triggering tag")
	}
}

// TestTheReleaseWorkflowUsesMinimalPermissions pins ADR 0062 section 14 and the
// GitHub Actions permission model.
func TestTheReleaseWorkflowUsesMinimalPermissions(t *testing.T) {
	// Directives only. This workflow explains itself at length, and its prose
	// legitimately names the permissions it holds — a guard that read the
	// comments would report a permission that had been removed from every job
	// but was still described in a sentence. Found by mutation, not by review.
	wf := releasePipeline(t)

	for _, required := range []string{"packages: write", "id-token: write"} {
		if !strings.Contains(wf, required) {
			t.Errorf("the release workflow no longer requests %q; "+
				"it cannot push to GHCR or sign keylessly without it", required)
		}
	}
	// `contents: write` used to be forbidden outright, and that was right while
	// the pipeline only published an image. Creating a GitHub Release is a write
	// to the repository, so the rule becomes a scoping rule rather than a ban:
	// exactly one job may hold it, and it is the job that creates the Release.
	//
	// A ban would have been the easier guard to keep and the wrong one — it
	// would have been deleted the first time someone needed a Release, taking
	// the workflow-wide protection with it.
	assertContentsWriteIsScopedToTheReleaseJob(t)

	// Every file in the pipeline must default to read-only and escalate per job.
	for _, name := range []string{releaseWorkflow, sharedWorkflow, validateWorkflow} {
		doc := withoutComments(readRepoFile(t, name))
		if !strings.HasPrefix(strings.TrimSpace(afterLine(doc, "permissions:")), "contents: read") {
			t.Errorf("%s: the default permission block is not contents: read", name)
		}
		// The shared machinery and the validation pipeline still write nothing to
		// the repository. Only release-oci.yml has a Release job.
		if name != releaseWorkflow && strings.Contains(doc, "contents: write") {
			t.Errorf("%s requests contents: write; publishing an image needs no repository write access", name)
		}
		for _, never := range []string{"actions: write", "administration:", "packages: admin"} {
			if strings.Contains(doc, never) {
				t.Errorf("%s requests %q, which nothing in this pipeline needs", name, never)
			}
		}
	}
}

// assertContentsWriteIsScopedToTheReleaseJob holds the boundary that replaced an
// outright ban on `contents: write`.
//
// Three separate things have to be true, and the middle one is the one a
// careless edit breaks: the workflow default stays read-only, the escalation
// appears under exactly one job, and that job is `release`. A workflow-level
// grant would hand repository write to the build and publish jobs too, which is
// precisely the blast radius the per-job model exists to avoid.
func assertContentsWriteIsScopedToTheReleaseJob(t *testing.T) {
	t.Helper()

	doc := withoutComments(readRepoFile(t, releaseWorkflow))

	// The workflow-level block, which is everything before the first job.
	header, _, _ := strings.Cut(doc, "\njobs:")
	if strings.Contains(header, "contents: write") {
		t.Error("release-oci.yml grants contents: write at the workflow level.\n\n" +
			"That gives every job in the pipeline write access to the repository, " +
			"including the ones that build and push the image. The Release job is " +
			"the only one that writes anything here, and it is the only one that " +
			"may hold it.")
	}

	owners := jobsHolding(doc, "contents: write")
	switch {
	case len(owners) == 0:
		t.Error("no job requests contents: write, so the GitHub Release cannot be created")
	case len(owners) > 1:
		t.Errorf("contents: write is held by %v; only the Release job may hold it", owners)
	case owners[0] != "release":
		t.Errorf("contents: write is held by job %q, not by the Release job", owners[0])
	}
}

// jobsHolding reports which top-level jobs contain the given directive. Walked
// positionally, because every job's permission block looks identical and
// searching the document for the directive always finds the first one.
func jobsHolding(wf, directive string) []string {
	_, jobsBlock, _ := strings.Cut(wf, "\njobs:\n")
	var out []string
	current := ""
	for _, line := range strings.Split(jobsBlock, "\n") {
		if trimmed := strings.TrimLeft(line, " "); trimmed != "" &&
			len(line)-len(trimmed) == 2 && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
		}
		if strings.Contains(line, directive) && current != "" {
			out = append(out, current)
		}
	}
	return out
}

// TestTheReleaseWorkflowUsesNoLongLivedCredential pins ADR 0062 section 17.
//
// The whole point of keyless signing and GITHUB_TOKEN is that nothing
// long-lived exists to be stolen. Each name below is a specific way that
// property gets given away for convenience.
func TestTheReleaseWorkflowUsesNoLongLivedCredential(t *testing.T) {
	wf := releasePipeline(t) + "\n" + withoutComments(readRepoFile(t, validateWorkflow))

	forbidden := []struct{ needle, why string }{
		{"COSIGN_PRIVATE_KEY", "keyless signing needs no private key"},
		{"COSIGN_PASSWORD", "there is no key to unlock"},
		{"cosign sign --key", "signing must be keyless via OIDC"},
		{"GHCR_PAT", "GITHUB_TOKEN is sufficient for GHCR"},
		{"CR_PAT", "GITHUB_TOKEN is sufficient for GHCR"},
		{"DOCKERHUB_TOKEN", "GHCR is the single canonical registry"},
		{"DOCKERHUB_USERNAME", "GHCR is the single canonical registry"},
		{"registry: docker.io", "GHCR is the single canonical registry"},
	}
	for _, f := range forbidden {
		if strings.Contains(wf, f.needle) {
			t.Errorf("the release workflow references %q: %s", f.needle, f.why)
		}
	}
	if !strings.Contains(wf, "password: ${{ secrets.GITHUB_TOKEN }}") {
		t.Error("the release workflow does not authenticate to GHCR with GITHUB_TOKEN")
	}
}

// TestTheReleaseWorkflowSignsAndVerifiesTheDigest pins ADR 0062 section 17.
//
// Two separate failures are guarded here, and the second is the subtle one.
// Signing a *tag* proves nothing, because a tag can be re-pointed afterwards.
// And an unconstrained `cosign verify` accepts any valid Sigstore signature from
// anyone on earth — it looks like verification and is close to none.
func TestTheReleaseWorkflowSignsAndVerifiesTheDigest(t *testing.T) {
	wf := releasePipeline(t)

	if !strings.Contains(wf, `cosign sign --yes "${IMAGE}@${{ needs.stage.outputs.digest }}"`) {
		t.Error("the release workflow does not sign the staged digest. " +
			"Signing a tag would authenticate a pointer, not an artifact.")
	}
	// Signing a tag reference is the specific mistake.
	if regexp.MustCompile(`cosign sign[^\n]*\$\{IMAGE\}:`).MatchString(wf) {
		t.Error("the release workflow signs a tag reference rather than a digest")
	}
	if !strings.Contains(wf, "cosign verify") {
		t.Error("the release workflow does not verify the signature it created. " +
			"Signing succeeding is not evidence that the signature is usable.")
	}
	// The exact flag, with its trailing space. `--certificate-identity-regexp`
	// contains `--certificate-identity` as a substring, so a substring test
	// accepts `--certificate-identity-regexp .*` — a "constraint" that matches
	// every identity on earth. Found by mutation, not by review.
	for _, constraint := range []string{"--certificate-identity ", "--certificate-oidc-issuer "} {
		if !strings.Contains(wf, constraint) {
			t.Errorf("cosign verify is not constrained by %s.\n\n"+
				"An unconstrained verify accepts any valid Sigstore signature "+
				"from any identity.", strings.TrimSpace(constraint))
		}
	}
	if strings.Contains(wf, "--certificate-identity-regexp") {
		t.Error("cosign verify uses --certificate-identity-regexp. ADR 0062 §17 " +
			"binds the signature to one workflow at one tag; a pattern invites " +
			"a permissive one.")
	}
	// The identity is computed by the caller and passed in, so the shared
	// machinery cannot decide whose signature it will accept. For a release that
	// value embeds ${GITHUB_REF}, and the trigger guard above proves ${GITHUB_REF}
	// can only ever be a semver tag — together those pin the release signature to
	// refs/tags/vX.Y.Z without the shared file naming a tag at all.
	caller := withoutComments(readRepoFile(t, releaseWorkflow))
	if !strings.Contains(caller, "certificate_identity=https://github.com/${GITHUB_REPOSITORY}/.github/workflows/oci-stage-verify.yml@${GITHUB_REF}") {
		t.Error("the release workflow does not compute the exact certificate identity it requires")
	}
	if !strings.Contains(wf, `--certificate-identity "${{ inputs.certificate_identity }}"`) {
		t.Error("cosign verify is not constrained to the identity the caller demanded")
	}
	if !strings.Contains(wf, "--certificate-github-workflow-sha") {
		t.Error("cosign verify does not bind the signature to the commit being released")
	}
	if !strings.Contains(wf, "https://token.actions.githubusercontent.com") {
		t.Error("the verified identity is not constrained to the GitHub OIDC issuer")
	}
}

// TestTheReleaseWorkflowKeepsEverySupplyChainGate pins ADR 0062 sections 17 and 19.
func TestTheReleaseWorkflowKeepsEverySupplyChainGate(t *testing.T) {
	wf := releasePipeline(t)

	gates := []struct{ needle, what string }{
		{"trivy-action", "vulnerability scan"},
		{"exit-code: '1'", "vulnerability scan blocking on findings"},
		{"severity: HIGH,CRITICAL", "vulnerability severity threshold"},
		{"--provenance=mode=max", "build provenance"},
		{"--sbom=false", "the BuildKit SBOM staying disabled"},
		{"format: cyclonedx", "CycloneDX SBOM export"},
		{"cosign attest --yes --type cyclonedx", "attaching the canonical SBOM"},
		{"vnd.docker.reference.digest", "attestation-to-digest binding check"},
		{"docker pull --platform linux/amd64", "native amd64 pull by digest"},
		{"rewrite-timestamp=true", "deterministic timestamps"},
		{"SOURCE_DATE_EPOCH", "deterministic timestamps"},
	}
	for _, g := range gates {
		if !strings.Contains(wf, g.needle) {
			t.Errorf("the release workflow no longer performs the %s (looked for %q)", g.what, g.needle)
		}
	}

	// Blanket suppression is the way a scan gate stops being one.
	if strings.Contains(wf, "ignore-unfixed: true") {
		t.Error("the vulnerability scan ignores unfixed findings wholesale (ADR 0062 §19)")
	}
	if strings.Contains(wf, "exit-code: '0'") {
		t.Error("the vulnerability scan cannot fail the release")
	}
}

// TestTheSemverTagIsAppliedLast pins ADR 0062 section 19, and it is the most
// important guard in this file.
//
// The publication order is not enforced by a script that could be reordered: it
// is enforced by `needs:`, because GitHub will not schedule `publish` until
// every dependency has succeeded. This checks that the dependency graph still
// says so, and that the semver tag is written nowhere else.
func TestTheSemverTagIsAppliedLast(t *testing.T) {
	caller := withoutComments(readRepoFile(t, releaseWorkflow))
	shared := withoutComments(readRepoFile(t, sharedWorkflow))
	wf := releasePipeline(t)

	// A reusable-workflow call succeeds only when every job inside it succeeds,
	// so `publish -> stage-and-verify` is a stronger edge than the four separate
	// edges it replaced: it cannot be satisfied by a subset.
	needs := jobNeeds(caller)
	for _, r := range []string{"identity", "stage-and-verify", "source", "integration"} {
		if !reaches(needs, "publish", r) {
			t.Errorf("job 'publish' does not depend on '%s'.\n\n"+
				"Without that edge GitHub may schedule the semver tag before %s has "+
				"passed, and a partially validated release would wear a version number.",
				r, r)
		}
	}
	// And that edge only means anything if the shared workflow still contains the
	// gates. A call to a machinery file that no longer verifies anything is a
	// dependency on nothing.
	sharedGraph := jobNeeds(shared)
	for _, job := range []string{"reproducibility", "stage", "verify", "smoke-amd64"} {
		if _, ok := sharedGraph[job]; !ok {
			t.Errorf("the shared machinery no longer defines job %q, so depending on it proves nothing", job)
		}
	}
	// A gate that cannot fail the call is not a gate. `continue-on-error` is
	// permitted on exactly one kind of step — one that records evidence and
	// decides nothing — and never on a job, which would let the whole call
	// succeed with its gates broken.
	//
	// The allowlist exists because the first real run proved the opposite
	// mistake is also real: a diagnostic step that *could* fail aborted the job
	// before `cosign verify` ran. Evidence steps must not be gates in either
	// direction.
	evidenceOnly := map[string]bool{
		"Record the certificate claims this run actually produced": true,
		"Record the Rekor transparency entry":                      true,
	}
	// Walked positionally, tracking the step in scope. Resolving each hit by
	// searching the document for its own text does not work: every
	// `continue-on-error: true` line is identical, so the search always finds
	// the first one and reports the allowlisted step no matter which step was
	// mutated. Found by mutation.
	step := ""
	for _, line := range strings.Split(shared, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "- name: ") {
			step = strings.TrimSpace(strings.TrimPrefix(trimmed, "- name: "))
		}
		if !strings.Contains(line, "continue-on-error") {
			continue
		}
		if indent := len(line) - len(strings.TrimLeft(line, " ")); indent <= 4 {
			t.Errorf("a job in the shared machinery is continue-on-error; its failure "+
				"would not block publication:\n  %s", strings.TrimSpace(line))
			continue
		}
		if !evidenceOnly[step] {
			t.Errorf("step %q is continue-on-error but is not an evidence-only step.\n\n"+
				"A gate that cannot fail the run is not a gate.", step)
		}
	}
	if strings.Contains(caller, "uses: ./.github/workflows/oci-stage-verify.yml") &&
		strings.Contains(caller, "if: always()\n    uses:") {
		t.Error("the release workflow calls the shared machinery unconditionally on failure")
	}

	// The semver tag must be created exactly once, in the caller, by an actual
	// command rather than a comment describing one.
	invocations := regexp.MustCompile(`(?m)^\s*docker buildx imagetools create`).FindAllString(wf, -1)
	if len(invocations) != 1 {
		t.Errorf("expected exactly one `docker buildx imagetools create` invocation "+
			"(the semver tag); found %d", len(invocations))
	}
	// And it must live in the caller. The shared machinery is invoked by a
	// dispatch-triggered validation workflow too; a semver tag written there
	// would be reachable from a branch.
	if strings.Contains(shared, "imagetools create") {
		t.Error("the shared machinery creates a registry tag. Public identity is the " +
			"caller's authority: validate-oci.yml runs this same file from a branch.")
	}

	// The staged push must use the SHA tag, never the semver tag.
	if strings.Contains(wf, "push=true") && !strings.Contains(wf, "sha_tag }},push=true") {
		t.Error("the staging push does not use the sha-<commit> tag. " +
			"Pushing the semver tag during staging would publish it before validation.")
	}
	if !strings.Contains(caller, "already exists. Semver tags are immutable") {
		t.Error("the workflow no longer refuses to overwrite an existing semver tag")
	}

	// The authoritative check is in `publish`, immediately before the write, and
	// it is a three-way decision rather than a refusal. `identity` cannot make
	// it: that job runs before the build and does not yet know what digest this
	// commit produces, so "the tag exists" is the only question available to it —
	// which cannot distinguish a legitimate re-run from an overwrite.
	//
	// Deleting this leaves `identity`'s observation in place and passes every
	// other guard here, while `imagetools create --tag` overwrites rather than
	// refuses. Found by mutation.
	assertSemverPublicationIsIdempotent(t)
}

// assertSemverPublicationIsIdempotent pins ADR 0062 §13 and §21 as they apply to
// the semver tag: compare, then reuse or stop, and never re-point.
//
// The three branches are the contract, and each is a different failure if it
// goes missing:
//
//   - **absent -> publish.** Losing this makes a first release impossible.
//   - **present at the validated digest -> reuse.** Losing this makes a resumed
//     release impossible, which is what forced v0.3.2's GitHub Release off the
//     automated path in the first place.
//   - **present at any other digest -> STOP.** Losing this permits the one thing
//     the whole release contract exists to prevent: a published semver tag
//     re-pointed at different bits, invalidating every signature already made
//     against it.
func assertSemverPublicationIsIdempotent(t *testing.T) {
	t.Helper()

	doc := withoutComments(readRepoFile(t, releaseWorkflow))
	_, job, found := strings.Cut(doc, "\n  publish:")
	if !found {
		t.Fatal("release-oci.yml has no publish job")
	}
	if end := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:`).FindStringIndex(job); end != nil {
		job = job[:end[0]]
	}

	// It must resolve the tag and compare against the validated digest.
	if !strings.Contains(job, "manifests/${GITHUB_REF_NAME}") {
		t.Error("the publish job does not resolve the semver tag before writing it")
	}
	if !strings.Contains(job, "needs.stage-and-verify.outputs.digest") {
		t.Error("the publish job does not read the validated digest, so it cannot " +
			"be comparing anything against it")
	}

	// The three branches are read out of the preflight script's actual control
	// flow, not by searching the job for strings.
	//
	// Searching was tried and does not work here. Replacing the reuse message
	// with `exit 1` left `exists=true` in the file as dead code and the guard
	// green; deleting the mismatch branch's `exit 1` left a later step's `exit 1`
	// for a substring search to find. Presence of a line says nothing about
	// whether it can be reached — the same lesson the digest re-check already
	// taught. Found by mutation, three times.
	script := shellStep(t, job, "The semver tag is absent, or already holds the validated digest")

	absent := shellBlock(t, script, `if [ "$code" != "200" ]; then`)
	if !strings.Contains(absent, `echo "exists=false"`) || !strings.Contains(absent, "exit 0") {
		t.Errorf("the absent-tag branch does not record a publish decision and return.\n\n"+
			"Without it a first release cannot be published at all.\n\nbranch:\n%s", absent)
	}

	mismatch := shellBlock(t, script, `if [ "$existing" != "$WANT" ]; then`)
	if !strings.Contains(mismatch, "exit 1") {
		t.Errorf("the differing-digest branch does not fail the job, so execution "+
			"falls through to the write.\n\n"+
			"This is the branch the entire release contract exists for: re-pointing "+
			"a published semver tag invalidates every signature already made "+
			"against it.\n\nbranch:\n%s", mismatch)
	}
	if !strings.Contains(mismatch, "already exists. Semver tags are immutable") {
		t.Error("the differing-digest branch no longer says why it refuses")
	}

	// What follows both branches is the reuse path, and it has to be reachable:
	// an `exit 1` between the mismatch `fi` and the reuse decision would turn
	// every resumed release into a failure while leaving both branches intact.
	_, reuse, _ := strings.Cut(script, mismatch)
	if strings.Contains(reuse, "exit 1") {
		t.Errorf("the reuse path exits non-zero.\n\n"+
			"A tag that already holds the validated digest is a successful "+
			"idempotent re-run, not a failure — that is the whole point of "+
			"comparing digests rather than checking existence.\n\npath:\n%s", reuse)
	}
	if !strings.Contains(reuse, `echo "exists=true"`) {
		t.Error("the reuse path does not record that the tag is already correct")
	}

	// Branch 2: a matching digest reuses, and reuse means writing nothing. The
	// `if:` on the create step is what makes that true — a create that ran
	// anyway would re-point the tag to the same digest, which is harmless today
	// and is exactly the habit that stops being harmless.
	create := regexp.MustCompile(`(?s)- name: Point the semver tag at the validated digest\n(.*?)run:`).
		FindStringSubmatch(job)
	if create == nil {
		t.Fatal("the publish job no longer creates the semver tag")
	}
	if !strings.Contains(create[1], "if: steps.preflight.outputs.exists != 'true'") {
		t.Error("the semver tag is created unconditionally.\n\n" +
			"On an idempotent re-run the tag already holds the validated digest and " +
			"nothing should be written at all.")
	}

	// Branch 1: absence is an explicit publish decision, not a fall-through.
	if !strings.Contains(job, `echo "exists=false" >> "$GITHUB_OUTPUT"`) {
		t.Error("the publish job does not record that an absent tag will be published")
	}
	if !strings.Contains(job, `echo "exists=true" >> "$GITHUB_OUTPUT"`) {
		t.Error("the publish job does not record that an existing validated tag is reused")
	}

	// And the confirmation must run on both paths. Gating it on the write would
	// leave the reuse path asserting nothing about what the tag resolves to,
	// which is the path taken by every resumed release.
	confirm := regexp.MustCompile(`(?s)- name: Confirm the tag resolves to the verified digest\n(.*?)run:`).
		FindStringSubmatch(job)
	if confirm == nil {
		t.Fatal("the publish job no longer confirms what the tag resolves to")
	}
	if strings.Contains(confirm[1], "if:") {
		t.Error("the tag confirmation is conditional. It is the assertion both the " +
			"write path and the reuse path have to satisfy.")
	}
}

// shellStep returns the `run:` script of a named step, dedented enough to read.
func shellStep(t *testing.T, job, name string) string {
	t.Helper()
	_, after, found := strings.Cut(job, "- name: "+name)
	if !found {
		t.Fatalf("no step named %q", name)
	}
	if end := regexp.MustCompile(`(?m)^      - `).FindStringIndex(after); end != nil {
		after = after[:end[0]]
	}
	return after
}

// shellBlock returns one `if ...; then ... fi` block, opener included, matched by
// counting nesting rather than by finding the next `fi`. A nested conditional
// would otherwise end the block early and hide whatever followed it.
func shellBlock(t *testing.T, script, opener string) string {
	t.Helper()
	lines := strings.Split(script, "\n")
	start := -1
	for i, l := range lines {
		if strings.TrimSpace(l) == opener {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("the preflight script has no %q branch", opener)
	}
	depth := 0
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "if ") {
			depth++
		}
		if trimmed == "fi" {
			depth--
			if depth == 0 {
				return strings.Join(lines[start:i+1], "\n")
			}
		}
	}
	t.Fatalf("the %q branch is never closed", opener)
	return ""
}

// TestTheIdentityJobObservesTheSemverTagRatherThanGatingOnIt records why the
// pre-flight check stopped being a gate.
//
// It runs before the build, so the only question it can ask is whether the tag
// exists — and that question cannot distinguish a resumed release from an
// overwrite. Answering it with a failure made every resume impossible. The
// authority is in `publish`, which runs after the build and can compare digests;
// this guard exists so that nobody restores the fast-fail and re-breaks resume
// while believing they are tightening something.
func TestTheIdentityJobObservesTheSemverTagRatherThanGatingOnIt(t *testing.T) {
	doc := withoutComments(readRepoFile(t, releaseWorkflow))
	_, job, _ := strings.Cut(doc, "\n  identity:")
	if end := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:`).FindStringIndex(job); end != nil {
		job = job[:end[0]]
	}

	probe := strings.Index(job, "manifests/${GITHUB_REF_NAME}")
	if probe < 0 {
		return // it no longer looks at all, which is permitted: publish decides.
	}
	// If it does look, it must not refuse on presence alone.
	after := job[probe:]
	if regexp.MustCompile(`(?m)^\s*\[ "\$code" = "200" \].*exit 1`).MatchString(after) ||
		strings.Contains(after, `refusing to overwrite`) {
		t.Error("the identity job fails when the semver tag already exists.\n\n" +
			"It runs before the build and cannot know which digest this commit " +
			"produces, so presence alone is not evidence of an overwrite. Refusing " +
			"here makes a resumed release impossible — which is how v0.3.2's " +
			"GitHub Release came to need a manual path. `publish` compares digests " +
			"and is the authority.")
	}
}

// TestTheStagingTagIsAFullCommitAndImmutable pins ADR 0062 section 21.
//
// `sha-<commit>` is an identity claim — this source produced these bits — and
// Phase 7.1-V made it enforceable rather than conventional. Two separate
// properties:
//
//   - **Full SHA.** An abbreviated SHA is a registry identity that can collide,
//     and a collision means two sources claiming one immutable tag. The
//     abbreviation was what the pipeline used before this phase.
//   - **No silent overwrite.** If the tag exists, the run compares its platform
//     manifests against a fresh reproducible build and either reuses the
//     identical digest or stops. Overwriting would falsify the claim for every
//     signature already made against it.
func TestTheStagingTagIsAFullCommitAndImmutable(t *testing.T) {
	for _, name := range []string{releaseWorkflow, validateWorkflow} {
		wf := withoutComments(readRepoFile(t, name))
		if strings.Contains(wf, "sha_tag=sha-$(git rev-parse --short") {
			t.Errorf("%s builds the staging tag from an abbreviated SHA. "+
				"An abbreviation can collide, and this tag is an immutable identity.", name)
		}
		if !regexp.MustCompile(`sha_tag=sha-(\$\(git rev-parse HEAD\)|\$\{revision\})`).MatchString(wf) {
			t.Errorf("%s does not derive the staging tag from the full commit SHA", name)
		}
	}

	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	// The push must be conditional on the pre-flight check. Without the
	// condition the check is advice and the tag is mutable again.
	if !strings.Contains(shared, "if: steps.preflight.outputs.exists != 'true'") {
		t.Error("the staged push is not gated on the staging-tag pre-flight check, " +
			"so an existing tag would be silently overwritten")
	}

	// Scoped to the pre-flight step, and it must *exit*. A mismatch that only
	// prints is a tag that gets overwritten with a warning: mutation testing
	// showed a whole-file check for the error message stayed green after the
	// `sys.exit(1)` beneath it was deleted.
	pre := stepBlock(t, shared, "Staging tag is absent, or already holds exactly these bits")
	if !strings.Contains(pre, "refusing to re-point it") {
		t.Error("a staging-tag digest mismatch is not reported")
	}
	if !strings.Contains(pre, "sys.exit(1)") {
		t.Error("a staging-tag digest mismatch does not stop the run. Printing a warning " +
			"and continuing would re-point an immutable identity at different bits.")
	}
	// Comparison must be at the platform level. ADR 0062 §16: the index digest is
	// not reproducible while provenance is enabled, so comparing indexes would
	// report every honest re-run as tampering. Scoped, because these names also
	// appear in the verification job.
	if !strings.Contains(pre, "got != want") {
		t.Error("the staging-tag pre-flight does not compare the published platform digests " +
			"against the rebuilt ones")
	}
	// The digests must be *declared* to the step, not merely named inside its
	// script. A heredoc referencing an environment variable nothing exports is a
	// runtime failure, and a guard that reads the script body alone cannot see it.
	env, _, _ := strings.Cut(pre, "run: |")
	for _, want := range []string{
		"WANT_AMD64: ${{ needs.reproducibility.outputs.amd64_digest }}",
		"WANT_ARM64: ${{ needs.reproducibility.outputs.arm64_digest }}",
	} {
		if !strings.Contains(env, want) {
			t.Errorf("the staging-tag pre-flight is not given the reproduced platform "+
				"digests (looked for %q)", want)
		}
	}

	// And the reproducibility proof itself must fail the run, not merely report.
	repro := stepBlock(t, shared, "Build twice and compare platform digests")
	if !strings.Contains(repro, "::error::platform image digests are not reproducible") ||
		!strings.Contains(repro, "sys.exit(1)") {
		t.Error("a non-reproducible build does not fail the run. Every immutability " +
			"decision downstream compares against the digests this step produces.")
	}
}

// TestTheReleaseWorkflowBuildsExactlyTheOfficialArchitectures pins ADR 0062 §9.
func TestTheReleaseWorkflowBuildsExactlyTheOfficialArchitectures(t *testing.T) {
	wf := releasePipeline(t)

	if !strings.Contains(wf, "--platform linux/amd64,linux/arm64") {
		t.Error("the release workflow does not build both official architectures")
	}
	if !strings.Contains(wf, `sorted(plats) != ['linux/amd64', 'linux/arm64']`) {
		t.Error("the release workflow does not assert the published index exposes " +
			"exactly linux/amd64 and linux/arm64")
	}
	// Attestation manifests appear as unknown/unknown and must not be counted.
	if !strings.Contains(wf, "architecture') == 'unknown'") {
		t.Error("the index check does not distinguish attestation manifests from " +
			"runtime architectures; it would report a third architecture that does not exist")
	}
}

// TestTheReleaseWorkflowPinsEveryAction pins the supply chain of the pipeline
// itself. A tag is mutable; this workflow holds packages: write and an OIDC
// identity, so a compromised action tag would be a release-signing compromise.
func TestTheReleaseWorkflowPinsEveryAction(t *testing.T) {
	wf := readRepoFile(t, releaseWorkflow) + "\n" +
		readRepoFile(t, sharedWorkflow) + "\n" +
		readRepoFile(t, validateWorkflow)

	uses := regexp.MustCompile(`uses:\s*(\S+)`)
	sha := regexp.MustCompile(`^[^@]+@[a-f0-9]{40}$`)
	found := 0
	for _, m := range uses.FindAllStringSubmatch(wf, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "./") {
			continue
		}
		found++
		if !sha.MatchString(ref) {
			t.Errorf("action %q is not pinned to a 40-character commit SHA", ref)
		}
	}
	if found == 0 {
		t.Fatal("the release workflow uses no actions; the file is probably not what this test thinks")
	}
}

// TestTheReleaseWorkflowCarriesNoBuildSecrets pins ADR 0062 section 17.
//
// Registry authentication happens at the client layer. Nothing secret should
// reach the build, because anything that reaches the build can reach a layer.
func TestTheReleaseWorkflowCarriesNoBuildSecrets(t *testing.T) {
	wf := releasePipeline(t)

	for _, forbidden := range []string{"--secret", "mount=type=secret", "--build-arg TOKEN", "--build-arg SECRET"} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("the release workflow passes %q into the build", forbidden)
		}
	}
	// Only the two identity build args are expected.
	args := regexp.MustCompile(`--build-arg "?([A-Z_]+)=`).FindAllStringSubmatch(wf, -1)
	for _, a := range args {
		switch a[1] {
		case "VERSION", "REVISION":
		default:
			t.Errorf("unexpected build argument %q; the build takes identity values only", a[1])
		}
	}
}

// TestTheReleaseWorkflowDoesNotRaceOrPublishLatest pins ADR 0062 section 13.
func TestTheReleaseWorkflowDoesNotRaceOrPublishLatest(t *testing.T) {
	wf := releasePipeline(t) + "\n" + withoutComments(readRepoFile(t, validateWorkflow))
	caller := withoutComments(readRepoFile(t, releaseWorkflow))

	if !strings.Contains(caller, "cancel-in-progress: false") {
		t.Error("the release workflow may be cancelled mid-publication. " +
			"Interrupting a run that is pushing artifacts is not an improvement " +
			"on two runs racing.")
	}
	if !strings.Contains(caller, "concurrency:") {
		t.Error("the release workflow has no concurrency group; two runs could race on one tag")
	}
	if regexp.MustCompile(`--tag\s+"?\$\{IMAGE\}:latest`).MatchString(wf) ||
		strings.Contains(wf, ":latest\"") {
		t.Error("the release workflow publishes a `latest` tag. ADR 0062 §13 permits " +
			"moving tags but they are never the deployment reference, and this " +
			"workflow does not publish one.")
	}
}

// withoutComments strips whole-line and trailing YAML comments.
//
// Every guard that asks "does this workflow still do X" must read directives
// rather than prose, or a thorough comment becomes a way to hide a deleted
// step.
func withoutComments(doc string) string {
	var out []string
	for _, line := range strings.Split(doc, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// afterLine returns the remainder of the document following the first
// occurrence of marker, used for checking what a block begins with.
func afterLine(doc, marker string) string {
	_, rest, found := strings.Cut(doc, marker)
	if !found {
		return ""
	}
	return rest
}

// jobNeeds extracts the job dependency graph from the workflow text.
//
// A job is a two-space-indented `name:` key under `jobs:`; its `needs:` is a
// four-space-indented list. That is enough structure to reconstruct the graph
// without a YAML parser, and the graph is the thing publication ordering
// depends on.
func jobNeeds(wf string) map[string][]string {
	_, jobsBlock, _ := strings.Cut(wf, "\njobs:\n")
	graph := map[string][]string{}
	current := ""
	for _, line := range strings.Split(jobsBlock, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 2 && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
			graph[current] = nil
			continue
		}
		if current != "" && strings.HasPrefix(trimmed, "needs:") {
			list := strings.TrimSpace(strings.TrimPrefix(trimmed, "needs:"))
			list = strings.Trim(list, "[]")
			for _, dep := range strings.Split(list, ",") {
				if dep = strings.TrimSpace(dep); dep != "" {
					graph[current] = append(graph[current], dep)
				}
			}
		}
	}
	return graph
}

// reaches reports whether from transitively depends on target.
func reaches(graph map[string][]string, from, target string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(j string) bool {
		for _, dep := range graph[j] {
			if dep == target {
				return true
			}
			if !seen[dep] {
				seen[dep] = true
				if walk(dep) {
					return true
				}
			}
		}
		return false
	}
	return walk(from)
}

// TestTheReleaseWorkflowGuardsCanFail proves every guard above is load-bearing.
func TestTheReleaseWorkflowGuardsCanFail(t *testing.T) {
	t.Run("job graph is parsed correctly", func(t *testing.T) {
		graph := jobNeeds(readRepoFile(t, releaseWorkflow))
		if len(graph) < 5 {
			t.Fatalf("parsed only %d jobs from the release workflow: %v", len(graph), graph)
		}
		if !reaches(graph, "publish", "source") {
			t.Error("the parser cannot see that publish depends transitively on source")
		}
		if reaches(graph, "source", "publish") {
			t.Error("the parser reports a cycle that does not exist")
		}

		shared := jobNeeds(readRepoFile(t, sharedWorkflow))
		if len(shared) < 5 {
			t.Fatalf("parsed only %d jobs from the shared machinery: %v", len(shared), shared)
		}
		if !reaches(shared, "verify", "reproducibility") {
			t.Error("the parser cannot see that verify depends transitively on reproducibility")
		}
	})

	t.Run("a missing dependency edge is detected", func(t *testing.T) {
		broken := map[string][]string{"publish": {"stage"}, "stage": {}}
		if reaches(broken, "publish", "verify") {
			t.Error("a publish job that skips verification would pass")
		}
	})

	t.Run("an unpinned action is detected", func(t *testing.T) {
		sha := regexp.MustCompile(`^[^@]+@[a-f0-9]{40}$`)
		if sha.MatchString("actions/checkout@v7") {
			t.Error("a tag-pinned action would pass the SHA-pin check")
		}
		if !sha.MatchString("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1") {
			t.Error("a SHA-pinned action is rejected")
		}
	})

	t.Run("signing a tag is detected", func(t *testing.T) {
		bad := `cosign sign --yes "${IMAGE}:${GITHUB_REF_NAME}"`
		if !regexp.MustCompile(`cosign sign[^\n]*\$\{IMAGE\}:`).MatchString(bad) {
			t.Error("signing a tag reference would pass")
		}
		good := `cosign sign --yes "${IMAGE}@${{ needs.stage.outputs.digest }}"`
		if regexp.MustCompile(`cosign sign[^\n]*\$\{IMAGE\}:`).MatchString(good) {
			t.Error("signing a digest is wrongly flagged")
		}
	})

	t.Run("a branch trigger is detected", func(t *testing.T) {
		planted := "on:\n  push:\n    branches: [main]\npermissions:"
		trigger, _, _ := strings.Cut(planted, "permissions:")
		if !strings.Contains(trigger, "branches:") {
			t.Error("a branch trigger would not be caught")
		}
	})
}

// TestNoDocumentRecommendsAMutableTagForDeployment pins ADR 0062 section 13.
//
// `latest` is permitted to exist and is never a deployment reference: it has no
// reproducible identity, and an operator who pins it cannot say afterwards what
// they ran. The guard is about *recommendation*, not mention — the documents
// have to be able to explain why not to use it.
//
// Phase 7.1-P found this uncovered by mutation: the container guards check the
// Kubernetes manifests for `:latest` but nothing checked the prose that tells
// people what to deploy.
func TestNoDocumentRecommendsAMutableTagForDeployment(t *testing.T) {
	for _, name := range []string{
		"README.md",
		"examples/kubernetes/README.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
		// The release notes, which `release-oci.yml` publishes as the GitHub
		// Release body. Its Install section is the most-copied shell in the
		// project, so a `:latest` there is pasted into more deployments than one
		// in any of the documents above.
		releaseNotes,
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		for _, sentence := range claimSentences(strings.ReplaceAll(doc, "\n", " ")) {
			lower := strings.ToLower(sentence)
			if !strings.Contains(lower, ":latest") && !strings.Contains(lower, "latest tag") {
				continue
			}
			// A sentence that denies, warns or forbids is the documentation
			// doing its job.
			if denies(sentence) || strings.Contains(lower, "never") ||
				strings.Contains(lower, "not ") || strings.Contains(lower, "unsuitable") ||
				strings.Contains(lower, "mutable") || strings.Contains(lower, "optional") {
				continue
			}
			for _, verb := range []string{"use ", "using ", "deploy", "production", "recommend", "pull "} {
				if strings.Contains(lower, verb) {
					t.Errorf("%s appears to recommend a mutable `latest` tag:\n  %s\n\n"+
						"ADR 0062 §13: moving tags have no reproducible identity and are "+
						"never the deployment reference.", name, strings.TrimSpace(sentence))
					break
				}
			}
		}
	}
}

// TestNoDocumentClaimsKubernetesAuthorityIsRequired pins ADR 0062 section 9.
//
// "svcdoctor needs a ServiceAccount token" is a claim that would change what
// operators grant it, and it is false: the examples set
// `automountServiceAccountToken: false` and the product never calls the
// Kubernetes API. The asymmetry is the reason for the guard — an operator who
// believes this grants API access a diagnostic worker has no use for, and
// nothing in a passing test suite would have contradicted the sentence.
//
// Found uncovered by mutation in Phase 7.1-P.
func TestNoDocumentClaimsKubernetesAuthorityIsRequired(t *testing.T) {
	subjects := []string{"service account", "serviceaccount", "kubernetes api", "rbac", "cluster-admin", "clusterrole"}
	requirements := []string{"require", "must have", "needs ", "need ", "necessary", "mandatory"}

	for _, name := range []string{
		"README.md",
		"examples/kubernetes/README.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
		"docs/ARCHITECTURE.md",
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		for _, sentence := range claimSentences(strings.ReplaceAll(doc, "\n", " ")) {
			lower := strings.ToLower(sentence)
			named := false
			for _, s := range subjects {
				if strings.Contains(lower, s) {
					named = true
					break
				}
			}
			if !named || denies(sentence) {
				continue
			}
			for _, r := range requirements {
				if strings.Contains(lower, r) {
					t.Errorf("%s states that svcdoctor requires Kubernetes authority:\n  %s\n\n"+
						"svcdoctor never calls the Kubernetes API. The Job examples set "+
						"automountServiceAccountToken: false and need no Role or RoleBinding "+
						"(ADR 0062 §9).", name, strings.TrimSpace(sentence))
					break
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// GitHub Release publication (Phase 7.2-R2)
// ---------------------------------------------------------------------------

// releaseJob returns the `release` job block of release-oci.yml, comments
// stripped. Cut at the next two-space-indented job key, because every nested key
// also starts with two spaces once you are inside the block.
func releaseJob(t *testing.T) string {
	t.Helper()
	doc := withoutComments(readRepoFile(t, releaseWorkflow))
	_, job, found := strings.Cut(doc, "\n  release:")
	if !found {
		t.Fatal("release-oci.yml defines no `release` job, so no GitHub Release is ever created")
	}
	if end := regexp.MustCompile(`(?m)^  [a-z][a-z0-9-]*:`).FindStringIndex(job); end != nil {
		job = job[:end[0]]
	}
	return job
}

// TestTheGitHubReleaseIsCreatedLastAndBuildsNothing pins the ordering half of
// the release state machine.
//
// A GitHub Release is a claim that an artifact is available. Made before the
// semver tag is published it is a link to a tag that does not resolve; made in
// parallel with publication it is a race. So it depends on `publish`, which
// itself depends on every gate, and `needs` is the enforcement — there is no
// ordering inside a script to get wrong.
//
// It also builds nothing. A Release job that could produce an artifact would be
// a second release pipeline, and the two would differ on the first edit that
// touched only one.
func TestTheGitHubReleaseIsCreatedLastAndBuildsNothing(t *testing.T) {
	doc := withoutComments(readRepoFile(t, releaseWorkflow))
	needs := jobNeeds(doc)

	for _, dep := range []string{"publish", "stage-and-verify", "identity", "source", "integration"} {
		if !reaches(needs, "release", dep) {
			t.Errorf("the GitHub Release job does not depend on %q.\n\n"+
				"Publishing a Release announces an artifact. Announcing one before %s "+
				"has succeeded advertises something that may not exist.", dep, dep)
		}
	}

	// Transitive reachability is the ordering property, but it is not the whole
	// contract: `needs.<job>.outputs` resolves to an empty string unless <job> is
	// named in this job's own `needs`. Dropping `stage-and-verify` from the list
	// still satisfies the walk above, because `publish` depends on it — and the
	// digest silently becomes "". Found by mutation.
	declared := map[string]bool{}
	for _, d := range needs["release"] {
		declared[d] = true
	}
	for _, m := range regexp.MustCompile(`needs\.([a-z][a-z0-9-]*)\.outputs`).
		FindAllStringSubmatch(releaseJob(t), -1) {
		if !declared[m[1]] {
			t.Errorf("the Release job reads needs.%s.outputs but does not list %q in "+
				"its own `needs`.\n\n"+
				"That expression resolves to an empty string, so the value would be "+
				"silently blank rather than wrong-and-loud.", m[1], m[1])
		}
	}

	job := releaseJob(t)
	// Nothing that produces or moves an artifact belongs here.
	for _, forbidden := range []struct{ needle, why string }{
		{"docker build", "the Release job would be a second build"},
		{"buildx build", "the Release job would be a second build"},
		{"imagetools create", "the Release job would re-point a registry tag; `publish` owns that"},
		{"docker push", "the Release job publishes no image"},
		{"cosign sign", "signing happens against the digest, in the shared machinery"},
		{"git tag", "the Git tag already exists and is immutable"},
	} {
		if strings.Contains(job, forbidden.needle) {
			t.Errorf("the GitHub Release job runs %q: %s", forbidden.needle, forbidden.why)
		}
	}
}

// TestTheGitHubReleaseRechecksTheDigestItAnnounces pins the check that makes the
// announcement honest.
//
// `publish` confirms the tag resolves to the validated digest at the moment it
// writes it. This job runs later, and `imagetools create --tag` re-points rather
// than refuses, so the window between them is real. Asking the registry again,
// immediately before publishing the Release, is what turns "it was correct when
// we wrote it" into "it is correct as we announce it".
func TestTheGitHubReleaseRechecksTheDigestItAnnounces(t *testing.T) {
	job := releaseJob(t)

	if !strings.Contains(job, "needs.stage-and-verify.outputs.digest") {
		t.Error("the Release job never reads the validated digest, so it cannot be " +
			"comparing anything against it")
	}
	if !strings.Contains(job, "manifests/${GITHUB_REF_NAME}") {
		t.Error("the Release job does not re-resolve the semver tag against the registry.\n\n" +
			"Without that, a tag re-pointed between `publish` and this job would be " +
			"announced as the validated release.")
	}
	// The comparison must actually compare. Checking only that an error message
	// survives somewhere in the job is not enough: neutering the condition to
	// `if false` left the message in place and the guard green. Found by
	// mutation.
	if !regexp.MustCompile(`if \[ "\$got" != "\$WANT" \]; then`).MatchString(job) {
		t.Error("the digest re-check no longer compares the resolved digest against " +
			"the validated one.\n\n" +
			"An unreachable failure branch is not a check — the error text can " +
			"survive a mutation that makes it impossible to reach.")
	}
	if !strings.Contains(job, "Refusing to announce it") {
		t.Error("the digest re-check cannot fail the job")
	}
	// And the digest that is announced must be the one that was re-resolved,
	// not the one the earlier job reported. Writing DIGEST from the registry
	// response is what makes those the same value.
	if !strings.Contains(job, `DIGEST=$got`) {
		t.Error("the announced digest is not the one read back from the registry")
	}
}

// TestTheGitHubReleaseTakesItsIdentityFromGit pins ADR 0062 §12 through this new
// surface: the Git tag is the version authority, and nothing here may introduce
// a second one.
func TestTheGitHubReleaseTakesItsIdentityFromGit(t *testing.T) {
	doc := withoutComments(readRepoFile(t, releaseWorkflow))
	job := releaseJob(t)

	if !strings.Contains(job, "needs.identity.outputs.version") {
		t.Error("the Release job does not take its version from the `identity` job")
	}
	// A literal version anywhere in the job is a second authority that goes
	// stale on the next release and names the wrong artifact.
	if m := regexp.MustCompile(`v\d+\.\d+\.\d+`).FindString(job); m != "" {
		t.Errorf("the Release job hard-codes the version %q; it must come from `identity`", m)
	}
	// The notes file is derived, for the same reason.
	if !strings.Contains(job, `docs/releases/${VERSION}.md`) {
		t.Error("the Release job does not derive its notes file from the release version")
	}
	// The tag must already exist and must be verified to. `--verify-tag` is what
	// stops `gh` from creating one.
	if !strings.Contains(job, "--verify-tag") {
		t.Error("the Release job does not pass --verify-tag.\n\n" +
			"Without it `gh release create` will happily create a tag that does not " +
			"exist, which would make this job a version authority.")
	}
	// And no manual input anywhere in the workflow.
	if strings.Contains(doc, "workflow_dispatch") || strings.Contains(doc, "inputs:") {
		t.Error("release-oci.yml accepts an input. The tag is the only release authority.")
	}
}

// TestTheGitHubReleaseIsIdempotentAndNonDestructive pins the re-run contract.
//
// A release workflow gets re-run — after an operational failure, or by hand. The
// second run must not produce a second Release object, and must not repair a
// disagreement by overwriting it: a published Release is a public object that
// may already have been linked to, and once immutable it cannot be rewritten at
// all. Verify, or stop for a human. Never delete and recreate.
func TestTheGitHubReleaseIsIdempotentAndNonDestructive(t *testing.T) {
	job := releaseJob(t)

	// It must look before it creates.
	view := strings.Index(job, "gh release view")
	create := strings.Index(job, "gh release create")
	if view < 0 || create < 0 {
		t.Fatal("the Release job does not both check for and create a Release")
	}
	if view > create {
		t.Error("the Release job creates before checking whether a Release exists, " +
			"so a re-run would attempt a duplicate")
	}

	for _, forbidden := range []struct{ needle, why string }{
		{"gh release delete", "a published Release is never deleted; that is the whole rule"},
		{"gh release edit", "a re-run must verify an existing Release, not rewrite it"},
		{"--clobber", "overwriting assets silently repairs a disagreement that needs a human"},
	} {
		if strings.Contains(job, forbidden.needle) {
			t.Errorf("the Release job uses %q: %s", forbidden.needle, forbidden.why)
		}
	}

	// A mismatch must stop the run rather than be reconciled.
	if !strings.Contains(job, "Not overwriting it") {
		t.Error("the Release job does not refuse a mismatching existing Release")
	}
	// The properties it compares. Dropping any one turns the idempotency path
	// into an existence check, which would let a draft or an accidental
	// prerelease pass as a completed release.
	//
	// Read from the `--json` field list rather than from the job text: the field
	// names also appear in the Python that inspects them, so removing them from
	// the query left the guard green while the values became unavailable. Found
	// by mutation.
	// The idempotency query specifically — the one whose output is compared —
	// identified by where it writes rather than by being the first or the
	// fattest match. The job runs three `gh release view` calls: a cheap
	// existence probe, this comparison, and a final read-back. Searching for
	// "some query that asks for everything" found the read-back and stayed green
	// while the comparison had been narrowed to a single field. Found by
	// mutation, twice — the first fix moved the bug rather than removing it.
	want := []string{"tagName", "name", "isDraft", "isPrerelease", "body"}
	q := regexp.MustCompile(`gh release view "\$VERSION" --json ([a-zA-Z,]+) > /tmp/existing\.json`).
		FindStringSubmatch(job)
	if q == nil {
		t.Fatal("the idempotency check does not read the existing Release into a file " +
			"for comparison, so there is nothing to verify it against")
	}
	for _, prop := range want {
		if !strings.Contains(q[1], prop) {
			t.Errorf("the idempotency comparison does not request %q (requested: %s).\n\n"+
				"Without it the check degrades toward an existence test, and a draft "+
				"or an accidental prerelease would pass as a completed release.",
				prop, q[1])
		}
	}
}

// TestTheGitHubReleaseJobHoldsNothingItDoesNotNeed pins the negative half of the
// permission model. The positive half — that `contents: write` exists and is
// scoped to this job — lives in TestTheReleaseWorkflowUsesMinimalPermissions.
//
// Both escalations below are the plausible kind. `id-token: write` looks
// harmless and would let this job mint an OIDC identity and sign things, which
// would put a second signer in a pipeline whose whole signing story is that
// there is one. `packages: write` looks convenient and would let the job that
// writes public release text also re-point registry tags.
func TestTheGitHubReleaseJobHoldsNothingItDoesNotNeed(t *testing.T) {
	job := releaseJob(t)
	perms, _, _ := strings.Cut(job, "\n    steps:")

	for _, never := range []struct{ directive, why string }{
		{"id-token: write", "this job signs nothing; signing happens against the digest in the shared machinery"},
		{"packages: write", "this job publishes no image; `publish` owns the only registry write"},
		{"actions: write", "nothing here rewrites workflow state"},
	} {
		if strings.Contains(perms, never.directive) {
			t.Errorf("the GitHub Release job requests %q: %s", never.directive, never.why)
		}
	}

	// The token must be the ambient one. A PAT is a long-lived credential whose
	// compromise is silent and whose scope is whatever the person who made it
	// happened to tick.
	for _, m := range regexp.MustCompile(`secrets\.([A-Z_][A-Z0-9_]*)`).FindAllStringSubmatch(job, -1) {
		if m[1] != "GITHUB_TOKEN" {
			t.Errorf("the GitHub Release job uses secrets.%s.\n\n"+
				"GITHUB_TOKEN is scoped to this run and expires with it; a repository "+
				"secret is long-lived and outlives every reason it was created.", m[1])
		}
	}
}

// TestTheGitHubReleaseMarksStableVersionsLatest pins the Latest policy.
//
// `identity` accepts only vX.Y.Z today, so the prerelease branch is unreachable
// — and it is written anyway. The rule belongs with the decision, not with the
// tag-shape gate that currently happens to make it moot: widening that gate
// later must not silently promote an `-rc.1` to the release users land on.
func TestTheGitHubReleaseMarksStableVersionsLatest(t *testing.T) {
	job := releaseJob(t)

	if !strings.Contains(job, "--latest") {
		t.Error("the Release job never marks a stable release Latest, so the Releases " +
			"page would keep pointing at an older version")
	}
	if !strings.Contains(job, "--prerelease") {
		t.Error("the Release job has no prerelease path. A vX.Y.Z-rc.N must never " +
			"become the Latest release.")
	}
	if !strings.Contains(job, "v*.*.*-*") {
		t.Error("the Release job does not distinguish a prerelease version from a stable one")
	}
	// And it must confirm the outcome rather than assume the flag worked.
	if !strings.Contains(job, "releases/latest") {
		t.Error("the Release job does not read Latest back from the API after publishing")
	}
}

// TestTheGitHubReleaseCarriesTheSignedSBOM pins ADR 0062 §17's delivery model:
// the SBOM goes on the Release *and* on the digest.
//
// The attached file must be the one that was attested. A second export would be
// a second document with no signature over it, and the Release would be offering
// the unsigned one.
func TestTheGitHubReleaseCarriesTheSignedSBOM(t *testing.T) {
	job := releaseJob(t)
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	if !strings.Contains(job, "sbom.cdx.json") {
		t.Error("the GitHub Release does not carry the CycloneDX SBOM (ADR 0062 §17)")
	}
	if !strings.Contains(job, "download-artifact") {
		t.Error("the Release job does not download the SBOM produced by the shared machinery")
	}
	// Re-exporting it here would produce an unattested copy.
	for _, forbidden := range []string{"trivy-action", "cosign attest", "cosign verify"} {
		if strings.Contains(job, forbidden) {
			t.Errorf("the Release job runs %q; the SBOM it publishes must be the "+
				"artifact the shared machinery already exported and signed, not a "+
				"second one", forbidden)
		}
	}
	// And the producing side must still upload it.
	if !strings.Contains(shared, "upload-artifact") || !strings.Contains(shared, "sbom.cdx.json") {
		t.Error("the shared machinery no longer publishes the SBOM artifact the " +
			"Release job consumes")
	}
}
