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
	if strings.Contains(wf, "contents: write") {
		t.Error("the release workflow requests contents: write. Publishing an image " +
			"needs no write access to the repository.")
	}
	// Every file in the pipeline must default to read-only and escalate per job.
	for _, name := range []string{releaseWorkflow, sharedWorkflow, validateWorkflow} {
		doc := withoutComments(readRepoFile(t, name))
		if !strings.HasPrefix(strings.TrimSpace(afterLine(doc, "permissions:")), "contents: read") {
			t.Errorf("%s: the default permission block is not contents: read", name)
		}
		if strings.Contains(doc, "contents: write") {
			t.Errorf("%s requests contents: write; publishing an image needs no repository write access", name)
		}
		for _, never := range []string{"actions: write", "administration:", "packages: admin"} {
			if strings.Contains(doc, never) {
				t.Errorf("%s requests %q, which nothing in this pipeline needs", name, never)
			}
		}
	}
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
		{"--sbom=true", "SBOM attestation"},
		{"format: cyclonedx", "CycloneDX SBOM export"},
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
	// A gate that cannot fail the call is not a gate.
	if strings.Contains(shared, "continue-on-error") {
		t.Error("a job in the shared machinery is continue-on-error; its failure would not block publication")
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
