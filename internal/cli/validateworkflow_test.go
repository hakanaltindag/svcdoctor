package cli

import (
	"regexp"
	"strings"
	"testing"
)

// The remote-validation audit.
//
// # What Phase 7.1-V added, and the risk it created
//
// ADR 0062 §21 left four claims unproven because proving them requires a real
// registry and a real OIDC identity: GHCR authentication and tag behaviour,
// native `linux/amd64` execution, keyless cosign signing, and pull-by-digest
// after a real push. `validate-oci.yml` closes them by publishing a
// `sha-<commit>` staging image and nothing else.
//
// That created two dangers, and this file exists for both.
//
// **A bypass.** A workflow that can push, sign and tag, triggered by
// `workflow_dispatch` rather than by a semver tag, is one careless edit away
// from being a second release authority. The guards below make "it cannot
// publish a semver tag" a property of the file rather than a description of it.
//
// **Drift.** The obvious way to write a validation workflow is to copy the
// release workflow's build, scan, SBOM, signing and smoke steps. That validates
// the copy: the two diverge on the first edit that touches only one, and the
// release path becomes the one nobody ever exercised. So the machinery lives in
// `oci-stage-verify.yml` and both workflows call it — and the drift guards here
// are what keep that true, because a future edit could inline a step back into
// either caller and nothing else would notice.

const validateWorkflow = ".github/workflows/validate-oci.yml"

// stepBlock returns the body of the named workflow step.
//
// Whole-file substring guards are not enough here, and mutation testing is what
// showed it: `--read-only`, `65532:65532` and `--certificate-oidc-issuer` each
// appear in several steps, so deleting one occurrence left the guard green
// while the check it protected was gone. A guard has to read the step it is
// about.
func stepBlock(t *testing.T, doc, name string) string {
	t.Helper()
	_, rest, found := strings.Cut(doc, "- name: "+name)
	if !found {
		t.Fatalf("workflow step %q does not exist", name)
	}
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- name:") || strings.HasPrefix(trimmed, "- uses:") {
			break
		}
		// A two-space-indented key is the next job.
		if line != "" && !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":") {
			break
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// ---------------------------------------------------------------------------
// Semver safety
// ---------------------------------------------------------------------------

// TestTheValidationWorkflowCannotPublishASemverTag is the load-bearing guard in
// this file.
//
// The check is deliberately about *absence of capability*, not about a
// condition that suppresses it. `if: github.ref_type != 'tag'` guarding a
// publish step would be one typo from a release; a file containing no tagging
// command at all has no such failure mode.
func TestTheValidationWorkflowCannotPublishASemverTag(t *testing.T) {
	wf := withoutComments(readRepoFile(t, validateWorkflow))

	// The only registry write in the whole pipeline is the staged push, and it
	// is in the shared machinery, addressed by `inputs.sha_tag`.
	for _, forbidden := range []struct{ needle, why string }{
		{"imagetools create", "creating a registry tag is the semver publication mechanism"},
		{"docker tag", "re-tagging an image is publication by another name"},
		{"docker push", "the shared machinery performs the one authorised push"},
		{"GITHUB_REF_NAME", "naming an artifact after the ref is how a branch becomes a version"},
	} {
		if strings.Contains(wf, forbidden.needle) {
			t.Errorf("the validation workflow contains %q: %s", forbidden.needle, forbidden.why)
		}
	}

	// No floating or semver tag may be nameable in the acting part of the
	// workflow. The negative-proof job at the end must name all four, because
	// asserting a tag is absent means asking the registry for it by name.
	acting, negative, found := strings.Cut(wf, "  no-semver:")
	if !found {
		t.Fatal("the validation workflow has no semver negative-proof job")
	}
	for _, tag := range []string{"latest", "v0", "v0.3", "v0.3.0"} {
		if strings.Contains(acting, ":"+tag) {
			t.Errorf("the validation workflow names the tag %q outside its negative "+
				"proof. It publishes sha-<commit> and nothing else.", tag)
		}
		if !strings.Contains(negative, tag) {
			t.Errorf("the negative proof does not assert that %q is absent from GHCR", tag)
		}
	}
	if !strings.Contains(negative, "must never create one") {
		t.Error("the negative proof does not fail when a semver tag exists")
	}

	// It must refuse a tag ref outright rather than merely not act on one.
	if !strings.Contains(wf, `if [ "${GITHUB_REF_TYPE}" = "tag" ]`) {
		t.Error("the validation workflow does not refuse to run on a tag ref. " +
			"A tag is release authority and belongs to release-oci.yml.")
	}
	// And it must refuse a release-shaped version even if the script produced one.
	if !strings.Contains(wf, `'^v?[0-9]+\.[0-9]+\.[0-9]+$'`) {
		t.Error("the validation workflow does not refuse a release-shaped derived version")
	}
	if !strings.Contains(wf, "0.0.0-dev+*") {
		t.Error("the validation workflow does not require a development version string")
	}
}

// TestTheValidationWorkflowAcceptsNoInput pins the same rule ADR 0062 §12 puts
// on the release workflow, for the same reason.
//
// A `version` input would make this a second version authority. A `registry` or
// `image` input would let it publish somewhere unaudited. The workflow takes no
// inputs at all, which is the only shape with no argument about which inputs
// are safe.
func TestTheValidationWorkflowAcceptsNoInput(t *testing.T) {
	wf := withoutComments(readRepoFile(t, validateWorkflow))

	trigger, _, found := strings.Cut(wf, "\npermissions:")
	if !found {
		t.Fatal("cannot locate the validation workflow's trigger block")
	}
	if !strings.Contains(trigger, "workflow_dispatch:") {
		t.Error("the validation workflow is not manually triggered")
	}
	for _, forbidden := range []string{"push:", "pull_request:", "schedule:", "tags:", "branches:"} {
		if strings.Contains(trigger, forbidden) {
			t.Errorf("the validation workflow can be triggered by %q. It pushes to GHCR "+
				"and holds an OIDC signing identity; it runs when a human asks.", forbidden)
		}
	}
	for _, forbidden := range []string{"inputs:", "github.event.inputs"} {
		if strings.Contains(wf, forbidden) {
			t.Errorf("the validation workflow accepts %q. It takes no inputs: "+
				"identity is derived from the checked-out commit and from nothing else.", forbidden)
		}
	}
}

// TestTheReleaseWorkflowKeepsTagAuthority re-audits ADR 0062 §12 and §13 after
// the extraction, from the validation side.
//
// The specific failure this prevents: implementing SHA validation by teaching
// `release-oci.yml` to accept a branch or a manual version, which is the
// cheapest possible design and destroys the release contract.
func TestTheReleaseWorkflowKeepsTagAuthority(t *testing.T) {
	wf := withoutComments(readRepoFile(t, releaseWorkflow))

	trigger, _, _ := strings.Cut(wf, "\npermissions:")
	if !strings.Contains(trigger, "tags:") {
		t.Fatal("the release workflow no longer triggers on tags")
	}
	for _, forbidden := range []string{"workflow_dispatch", "branches:", "pull_request:", "schedule:", "repository_dispatch"} {
		if strings.Contains(trigger, forbidden) {
			t.Errorf("the release workflow gained a %q trigger while SHA validation was added. "+
				"Validation must not be implemented by weakening release authority.", forbidden)
		}
	}
	// The validation workflow must not be able to *invoke* the release workflow.
	// Naming it in an error message is fine and useful; calling it, or triggering
	// it, is the bypass. The two share machinery, never each other.
	val := withoutComments(readRepoFile(t, validateWorkflow))
	for name, doc := range map[string]string{validateWorkflow: val, releaseWorkflow: wf} {
		other := releaseWorkflow
		if name == releaseWorkflow {
			other = validateWorkflow
		}
		base := other[strings.LastIndex(other, "/")+1:]
		for _, verb := range []string{"uses: ./.github/workflows/" + base, "workflow: " + base, "-w " + base} {
			if strings.Contains(doc, verb) {
				t.Errorf("%s invokes %s (%q). Neither may be a path into the other.", name, other, verb)
			}
		}
	}
	// Nor may either dispatch a workflow through the API.
	for _, doc := range []string{val, wf} {
		if strings.Contains(doc, "workflow_dispatch --ref") || strings.Contains(doc, "gh workflow run") {
			t.Error("a pipeline workflow triggers another workflow, creating an indirect publication path")
		}
	}
}

// ---------------------------------------------------------------------------
// Shared machinery, and the drift it exists to prevent
// ---------------------------------------------------------------------------

// TestBothPipelinesRunTheSameMachinery pins the Phase 7.1-V architecture.
//
// This is what makes the remote validation *evidence about the release path*
// rather than about a lookalike. If either caller stopped calling the shared
// file, or inlined a gate back into itself, the validation would still pass and
// would no longer mean anything.
func TestBothPipelinesRunTheSameMachinery(t *testing.T) {
	const call = "uses: ./.github/workflows/oci-stage-verify.yml"

	release := withoutComments(readRepoFile(t, releaseWorkflow))
	validate := withoutComments(readRepoFile(t, validateWorkflow))
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	for name, doc := range map[string]string{releaseWorkflow: release, validateWorkflow: validate} {
		if !strings.Contains(doc, call) {
			t.Fatalf("%s does not call the shared OCI machinery. Two copies of the "+
				"build/scan/sign path drift apart, and the release path becomes the "+
				"one nobody rehearses.", name)
		}
	}

	// The machinery may live in exactly one place. If a gate reappears in a
	// caller, that caller has started to diverge.
	inlined := []struct{ needle, what string }{
		{"cosign sign", "signing"},
		{"cosign verify", "signature verification"},
		{"trivy-action", "the vulnerability scan"},
		{"format: cyclonedx", "SBOM generation"},
		{"--provenance=mode=max", "provenance"},
		{"docker pull --platform", "the pull-by-digest smoke"},
		{"vnd.docker.reference.digest", "attestation binding"},
		{"--no-cache", "the reproducibility build"},
	}
	for name, doc := range map[string]string{releaseWorkflow: release, validateWorkflow: validate} {
		for _, in := range inlined {
			if strings.Contains(doc, in.needle) {
				t.Errorf("%s performs %s itself (found %q). That step belongs to "+
					"%s so both pipelines run the same one.", name, in.what, in.needle, sharedWorkflow)
			}
		}
	}
	// And the shared file must still perform every one of them, or "neither
	// caller does it" would be trivially satisfiable by deleting the step.
	for _, in := range inlined {
		if !strings.Contains(shared, in.needle) {
			t.Errorf("the shared machinery no longer performs %s (looked for %q)", in.what, in.needle)
		}
	}

	// Both callers must hand over the same set of identity values, or one of
	// them is building something the other's proof does not cover.
	for name, doc := range map[string]string{releaseWorkflow: release, validateWorkflow: validate} {
		for _, in := range []string{"version:", "revision:", "source_date_epoch:", "sha_tag:", "certificate_identity:"} {
			if !strings.Contains(doc, "      "+in+" ${{ needs.identity.outputs.") {
				t.Errorf("%s does not pass %s to the shared machinery from its identity job", name, in)
			}
		}
	}
}

// TestTheSharedMachineryDecidesNoPublicIdentity pins the boundary that makes
// sharing safe at all.
//
// The shared workflow builds, verifies and signs whatever it is handed. If it
// could *derive* a version — from `github.ref`, from `git describe`, from an
// environment variable — then the authority split would be decorative, and a
// dispatch-triggered run could produce a release-shaped artifact.
func TestTheSharedMachineryDecidesNoPublicIdentity(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	for _, forbidden := range []struct{ needle, why string }{
		{"git describe", "deriving a version here would be a second version authority"},
		{"GITHUB_REF_NAME", "naming an artifact after the caller's ref bypasses the caller's identity job"},
		{"build-image.sh --emit", "identity derivation belongs to the caller"},
		{"imagetools create", "creating a registry tag is publication"},
		{"workflow_dispatch", "the shared machinery is called, never triggered"},
	} {
		if strings.Contains(shared, forbidden.needle) {
			t.Errorf("the shared machinery contains %q: %s", forbidden.needle, forbidden.why)
		}
	}

	trigger, _, _ := strings.Cut(shared, "\npermissions:")
	if !strings.Contains(trigger, "workflow_call:") {
		t.Fatal("the shared machinery is not a reusable workflow")
	}
	for _, required := range []string{"version:", "revision:", "source_date_epoch:", "sha_tag:", "certificate_identity:"} {
		if !strings.Contains(trigger, required) {
			t.Errorf("the shared machinery does not take %s as an input; it would have to derive one", required)
		}
	}

	// Exactly one registry reference is written, and it is the staging tag.
	pushes := regexp.MustCompile(`name=\$\{IMAGE\}:([^,"]+)`).FindAllStringSubmatch(shared, -1)
	if len(pushes) != 1 {
		t.Fatalf("expected exactly one pushed reference in the shared machinery, found %d: %v", len(pushes), pushes)
	}
	if !strings.Contains(pushes[0][1], "inputs.sha_tag") {
		t.Errorf("the shared machinery pushes %q rather than the caller's staging tag", pushes[0][1])
	}
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

// TestSigningIsKeylessOverTheDigestAndNarrowlyVerified pins ADR 0062 §17.
//
// Four separate ways this stops being a real gate, all of which have looked
// reasonable to someone at some point:
//
//   - a static key, because keyless "was flaky";
//   - signing the tag, because it reads better;
//   - `--certificate-identity-regexp '.*'`, because verification failed;
//   - dropping `id-token: write`, because a permission audit said to.
func TestSigningIsKeylessOverTheDigestAndNarrowlyVerified(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	if !strings.Contains(shared, `cosign sign --yes "${IMAGE}@${{ needs.stage.outputs.digest }}"`) {
		t.Error("the shared machinery does not sign the staged index digest")
	}
	if regexp.MustCompile(`cosign (sign|attest)[^\n]*\$\{IMAGE\}:`).MatchString(shared) {
		t.Error("cosign addresses a tag reference rather than a digest. " +
			"A tag can be re-pointed; a signature over one proves nothing about what is served later.")
	}
	for _, forbidden := range []string{"--key ", "COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD", "cosign generate-key-pair"} {
		if strings.Contains(shared, forbidden) {
			t.Errorf("the shared machinery uses %q; ADR 0062 §17 forbids a long-lived signing key", forbidden)
		}
	}
	if strings.Contains(shared, "--certificate-identity-regexp") {
		t.Error("cosign verify uses --certificate-identity-regexp, which invites a permissive pattern")
	}

	// Scoped per step. `cosign verify-attestation` carries the same flags, so a
	// whole-file check stayed green when `cosign verify` itself was deleted —
	// found by mutation, not by review.
	for _, step := range []struct{ name, cmd string }{
		{"Verify the signature against this exact identity", "cosign verify \\"},
		{"Verify the SBOM attestation is bound to this digest", "cosign verify-attestation"},
	} {
		block := stepBlock(t, shared, step.name)
		if !strings.Contains(block, step.cmd) {
			t.Errorf("step %q no longer runs %q", step.name, strings.TrimSpace(step.cmd))
		}
		for _, required := range []string{
			`--certificate-identity "${{ inputs.certificate_identity }}"`,
			`--certificate-oidc-issuer "https://token.actions.githubusercontent.com"`,
			"--certificate-github-workflow-repository",
			"--certificate-github-workflow-sha",
		} {
			if !strings.Contains(block, required) {
				t.Errorf("step %q is not constrained by %s", step.name, required)
			}
		}
		if !strings.Contains(block, "${IMAGE}@${{ needs.stage.outputs.digest }}") {
			t.Errorf("step %q does not verify the staged digest", step.name)
		}
	}

	// The verify job, and only the verify job, gets an OIDC identity.
	if n := strings.Count(shared, "id-token: write"); n != 1 {
		t.Errorf("id-token: write appears %d times in the shared machinery; exactly one job "+
			"(the signing job) must hold a signing identity, and without it keyless "+
			"signing is impossible", n)
	}
	// And it must be the job that signs. `id-token: write` on the staging job
	// would hand a signing identity to the job that pushes.
	_, signingJob, _ := strings.Cut(shared, "  verify:")
	if !strings.Contains(signingJob, "id-token: write") {
		t.Error("the signing job does not hold id-token: write")
	}

	// The signature must be proven to cover the index rather than a platform
	// manifest, and the proof must read what the *verifier* attested to rather
	// than infer it from where cosign happens to store things.
	// The *comparisons*, not strings that happen to sit near them. Mutation
	// replaced each condition with `if False:` and left every error message in
	// place, so needle-hunting for the messages proved nothing.
	binding := stepBlock(t, withoutComments(shared), "Signature and SBOM name the index digest, not a platform")
	for _, g := range []struct{ needle, what string }{
		{"subjects != {want}", "the signature subject comparison"},
		{"docker-manifest-digest", "reading the signed subject digest"},
		{"preds != {'https://cyclonedx.org/bom'}", "the attestation predicate-type comparison"},
		{"subs != {bare}", "the attestation subject-digest comparison"},
		{"application/vnd.oci.image.index.v1+json", "the index media-type comparison"},
		{"if want == d:", "the signed-digest-is-not-a-platform comparison"},
		{"sys.exit(1 if bad else 0)", "failing the run on any of them"},
	} {
		if !strings.Contains(binding, g.needle) {
			t.Errorf("the signature/SBOM binding proof no longer performs %s (looked for %q)",
				g.what, g.needle)
		}
	}
}

// ---------------------------------------------------------------------------
// Attestations
// ---------------------------------------------------------------------------

// TestAttestationsAreProducedAndProvenBound pins ADR 0062 §16 and §17.
//
// The distinction this guards is the one the whole section exists for:
// *producing* an SBOM or a provenance statement is not the claim. Being
// attached to the digest an operator pulls is. A CI artifact expires and is
// invisible to anyone holding the image.
func TestAttestationsAreProducedAndProvenBound(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	for _, g := range []struct{ needle, what string }{
		{"format: cyclonedx", "the CycloneDX SBOM export"},
		{"cosign attest --yes --type cyclonedx", "publishing the SBOM as an OCI referrer"},
		{"cosign verify-attestation --type cyclonedx", "proving the SBOM is bound to the digest"},
		{"--provenance=mode=max", "build provenance"},
		{"vnd.docker.reference.digest", "the attestation-to-digest binding check"},
		{"Provenance names this repository, commit and workflow", "checking what provenance claims"},
		{"trivy-action", "the vulnerability scan"},
		{"exit-code: '1'", "a vulnerability scan that can fail the run"},
		{"severity: HIGH,CRITICAL", "the vulnerability severity threshold"},
	} {
		if !strings.Contains(shared, g.needle) {
			t.Errorf("the shared machinery no longer performs %s (looked for %q)", g.what, g.needle)
		}
	}

	// ADR 0062 §17 declines to name a SLSA level, because a level is a
	// specification this project has not audited itself against.
	for _, name := range []string{releaseWorkflow, validateWorkflow, sharedWorkflow} {
		doc := readRepoFile(t, name)
		if regexp.MustCompile(`(?i)slsa\s*(level\s*)?[0-9]`).MatchString(doc) {
			t.Errorf("%s claims a SLSA level. ADR 0062 §17 declines to, because the "+
				"project has not audited itself against the specification.", name)
		}
	}

	// A SHA validation build must not be able to describe itself as a release.
	if !strings.Contains(shared, "Provenance does not claim a semver release ref") {
		t.Error("nothing checks that a non-tag run's provenance is free of a semver tag ref")
	}
	if !strings.Contains(shared, `if: github.ref_type != 'tag'`) {
		t.Error("the provenance semver check is not scoped to non-tag runs")
	}

	// Blanket suppression is how a scan gate stops being one.
	if strings.Contains(shared, "ignore-unfixed: true") || strings.Contains(shared, "exit-code: '0'") {
		t.Error("the vulnerability scan cannot fail the run (ADR 0062 §19)")
	}
}

// ---------------------------------------------------------------------------
// Remote runtime smoke
// ---------------------------------------------------------------------------

// TestTheRemoteSmokeProvesNativeExecutionByDigest pins the evidence obligation
// ADR 0062 §21 left open.
//
// Phase 7.1 ran amd64 only under emulation, and an emulated run is not evidence
// that the binary works on the architecture operators use. Two things make the
// smoke worth anything: the runner is genuinely x86_64, and the image is
// addressed by digest. Pulling by tag would test whatever the tag points at now.
func TestTheRemoteSmokeProvesNativeExecutionByDigest(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	native := stepBlock(t, shared, "Runner is genuinely native amd64")
	for _, g := range []struct{ needle, what string }{
		{`[ "$(uname -m)" = "x86_64" ]`, "the kernel architecture assertion"},
		{`[ "${RUNNER_ARCH}" = "X64" ]`, "the runner architecture assertion"},
		{"docker version --format '{{.Server.Arch}}'", "the Docker daemon architecture assertion"},
	} {
		if !strings.Contains(native, g.needle) {
			t.Errorf("the amd64 smoke no longer proves %s (looked for %q).\n\n"+
				"Without it the smoke could be running under emulation, which is exactly "+
				"the evidence gap ADR 0062 §21 left open.", g.what, g.needle)
		}
	}

	for _, g := range []struct{ needle, what string }{
		{"docker pull --platform linux/amd64", "the amd64 pull"},
		{"Remote image content audit", "the published-image content audit"},
		{"System CA trust survives publication", "the system trust store smoke"},
		{`'tls.trust_source'`, "the trust-source assertion"},
	} {
		if !strings.Contains(shared, g.needle) {
			t.Errorf("the shared machinery no longer performs %s (looked for %q)", g.what, g.needle)
		}
	}

	// Every runtime reference must be a digest. Counted rather than merely
	// present: the shared workflow resolves `ref` in four separate steps, so a
	// single one switched to a tag left a whole-file guard green while that step
	// tested a pointer. Found by mutation.
	byDigest := strings.Count(shared, `ref="${IMAGE}@${{ needs.stage.outputs.digest }}"`)
	byTag := strings.Count(shared, `ref="${IMAGE}:`)
	if byTag != 0 {
		t.Errorf("%d runtime step(s) resolve the image by tag. A tag can be re-pointed; "+
			"the smoke must test the digest that was verified.", byTag)
	}
	if byDigest < 4 {
		t.Errorf("only %d runtime steps resolve the image by staged digest; expected every one "+
			"of the pull, audit, CA-trust and arm64 steps to", byDigest)
	}
	if regexp.MustCompile(`docker (pull|run|create)[^\n]*\$\{IMAGE\}:`).MatchString(shared) {
		t.Error("the runtime smoke addresses the image by tag. It must pull by digest, " +
			"so what is tested is exactly what was verified.")
	}

	// The hardening flags must be in the steps that actually run the image.
	// `--read-only` and `65532:65532` each appear several times, so deleting one
	// occurrence used to leave this guard green.
	for _, step := range []string{
		"Pull by digest and verify the runtime contract",
		"System CA trust survives publication",
	} {
		block := stepBlock(t, shared, step)
		for _, flag := range []string{"--read-only", "--cap-drop=ALL", "no-new-privileges", "--user=65532:65532"} {
			if !strings.Contains(block, flag) {
				t.Errorf("step %q no longer runs the image with %s", step, flag)
			}
		}
	}
	// And the image's own configured identity must still be asserted.
	contract := stepBlock(t, shared, "Pull by digest and verify the runtime contract")
	// The command, not merely its error message. Deleting the test and leaving
	// the `|| { echo ... }` continuation behind kept the message in the file.
	if !strings.Contains(contract, `--format '{{.Config.User}}')" = "65532:65532"`) {
		t.Error("nothing asserts the published image config runs as a numeric non-root user")
	}
	if !strings.Contains(contract, `[ "$arch" = "amd64" ]`) {
		t.Error("nothing asserts the pulled manifest is actually amd64")
	}

	// The pulled platform manifest must be the reproduced one, or "reproducible"
	// and "published" are two unrelated claims in the same run.
	if !strings.Contains(shared, "the pulled image is the reproduced platform manifest") {
		t.Error("nothing ties the pulled amd64 manifest back to the reproducibility proof")
	}

	// ADR 0062 §20: the CA store is a security-sensitive build input, so the
	// smoke must keep both halves of the claim — a positive result and the
	// negative control that gives it meaning.
	ca := stepBlock(t, shared, "System CA trust survives publication")
	// The point of the smoke is that no CA file is supplied: the image's own
	// store has to do the work, or the test proves nothing about the image.
	if strings.Contains(ca, "--tls-ca-file") || strings.Contains(ca, "--tls-insecure") {
		t.Error("the system CA smoke supplies its own trust material or disables " +
			"verification, so it no longer tests the image's trust store")
	}
	if !strings.Contains(ca, "TLS_UNKNOWN_AUTHORITY") {
		t.Error("the system CA smoke no longer carries its negative control.\n\n" +
			"A missing CA bundle does not make handshakes disappear — it makes them " +
			"fail to verify, and TLS_UNKNOWN_AUTHORITY is the class that says so.")
	}

	// Scoped to the expression that selects a passing path, not to the whole
	// step: both attribute names also appear in the evidence-printing loop
	// above, so a whole-step check stayed green when the condition itself was
	// deleted. Found by mutation.
	_, good, found := strings.Cut(ca, "good = [n for n in tls")
	if !found {
		t.Fatal("the system CA smoke no longer selects verified handshakes")
	}
	// Cut at the statement after the comprehension, not at the first "]" —
	// n['state'] closes a bracket on the comprehension's own first line.
	good, _, _ = strings.Cut(good, "if not good")
	for _, g := range []struct{ needle, what string }{
		{"'PASS'", "the passing-state condition"},
		{"'tls.trust_source'", "the system trust-source condition"},
		{"'system'", "the expected trust source"},
		{"'tls.verified'", "the verification condition"},
		{"is True", "the requirement that verification actually succeeded"},
	} {
		if !strings.Contains(good, g.needle) {
			t.Errorf("the system CA smoke no longer requires %s (looked for %q)", g.what, g.needle)
		}
	}
	// It must not have been weakened into "a handshake happened".
	if !strings.Contains(ca, "no path verified against the image system trust store") {
		t.Error("the system CA smoke does not require a verified handshake")
	}
}

// TestTheRemoteAuditLooksForSecretsAndSource pins ADR 0062 §22.
//
// The audit runs against the *pulled* image rather than the built one, because
// the claim that matters is about what GHCR serves.
func TestTheRemoteAuditLooksForSecretsAndSource(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	// The executable-shaped checks must iterate *regular files*. Phase 7.1-V
	// measured why: distroless ships `etc/dpkg` and `var/lib/dpkg` as
	// directories holding package metadata — which is what lets a scanner
	// enumerate base packages — and no dpkg binary. Iterating names reported a
	// package manager that is not in the image.
	audit := stepBlock(t, shared, "Remote image content audit")
	if !strings.Contains(audit, "hits = [m.name for m in files if re.search(pat, m.name.rstrip('/'))]") {
		t.Error("the executable-shaped content checks no longer iterate regular files only.\n\n" +
			"Matching names alone reports package *metadata directories* as a package manager.")
	}
	if !strings.Contains(audit, "files = [m for m in members if m.isfile()]") {
		t.Error("the content audit no longer distinguishes regular files from directories")
	}

	for _, g := range []struct{ needle, what string }{
		{"a package manager", "the package-manager check"},
		{"'a shell'", "the shell check"},
		{"repository metadata", "the .git check"},
		{"Go source", "the source-leak check"},
		{"test fixtures", "the fixture check"},
		{"BEGIN RSA PRIVATE KEY", "the private-key canary"},
		{"svcdoctor-test-password", "the fixture-credential canary"},
		{"credential-shaped environment", "the password-environment check"},
		{"the CA bundle is missing", "the CA bundle presence check"},
	} {
		if !strings.Contains(shared, g.needle) {
			t.Errorf("the remote image audit no longer performs %s (looked for %q)", g.what, g.needle)
		}
	}

	// The published SBOM is a document anyone can fetch; it must not carry
	// credential material either.
	if !strings.Contains(shared, "SBOM contains material matching") {
		t.Error("nothing scans the published SBOM for credential material")
	}
}

// ---------------------------------------------------------------------------
// Credentials and permissions
// ---------------------------------------------------------------------------

// TestNoPipelineFileIntroducesALongLivedCredential pins ADR 0062 §21.
//
// Every name below is a specific way the "nothing long-lived exists to be
// stolen" property gets traded for convenience during a debugging session.
func TestNoPipelineFileIntroducesALongLivedCredential(t *testing.T) {
	for _, name := range []string{releaseWorkflow, validateWorkflow, sharedWorkflow} {
		wf := withoutComments(readRepoFile(t, name))

		for _, f := range []struct{ needle, why string }{
			{"GHCR_PAT", "GITHUB_TOKEN is sufficient for GHCR"},
			{"CR_PAT", "GITHUB_TOKEN is sufficient for GHCR"},
			{"REGISTRY_PASSWORD", "a static registry password is a long-lived credential"},
			{"REGISTRY_USERNAME", "a static registry identity implies a static password"},
			{"DOCKERHUB_TOKEN", "GHCR is the single canonical registry"},
			{"registry: docker.io", "GHCR is the single canonical registry"},
			{"index.docker.io", "GHCR is the single canonical registry"},
		} {
			if strings.Contains(wf, f.needle) {
				t.Errorf("%s references %q: %s", name, f.needle, f.why)
			}
		}

		// Every registry login in the pipeline must use the ephemeral token.
		logins := strings.Count(wf, "docker/login-action@")
		tokens := strings.Count(wf, "password: ${{ secrets.GITHUB_TOKEN }}")
		if logins != tokens {
			t.Errorf("%s has %d registry logins but %d GITHUB_TOKEN passwords; "+
				"one of them authenticates with something else", name, logins, tokens)
		}
		for _, login := range regexp.MustCompile(`registry: (\S+)`).FindAllStringSubmatch(wf, -1) {
			if login[1] != "ghcr.io" {
				t.Errorf("%s logs in to registry %q; GHCR is the only canonical registry", name, login[1])
			}
		}
	}
}

// TestPipelinePermissionsAreScopedToTheJobThatNeedsThem pins the GitHub Actions
// permission model.
//
// `packages: write` at workflow scope would grant push rights to the source
// gate and the summary; `id-token: write` everywhere would give a signing
// identity to jobs that have no business holding one. The escalation belongs at
// the job that uses it, where it is visible in review.
func TestPipelinePermissionsAreScopedToTheJobThatNeedsThem(t *testing.T) {
	for _, name := range []string{releaseWorkflow, validateWorkflow, sharedWorkflow} {
		wf := withoutComments(readRepoFile(t, name))

		header, _, found := strings.Cut(wf, "\njobs:")
		if !found {
			t.Fatalf("%s has no jobs block", name)
		}
		for _, escalation := range []string{"packages: write", "id-token: write", "attestations: write", "contents: write"} {
			if strings.Contains(header, escalation) {
				t.Errorf("%s grants %q at workflow scope. Every job would hold it, "+
					"including the ones that only run tests.", name, escalation)
			}
		}
		if !strings.Contains(header, "permissions:\n  contents: read") {
			t.Errorf("%s does not default to contents: read", name)
		}
	}

	// The caller of a reusable workflow must not hand down more than the
	// machinery needs.
	for _, name := range []string{releaseWorkflow, validateWorkflow} {
		wf := withoutComments(readRepoFile(t, name))
		_, call, found := strings.Cut(wf, "uses: ./.github/workflows/oci-stage-verify.yml")
		if !found {
			t.Fatalf("%s does not call the shared machinery", name)
		}
		block, _, _ := strings.Cut(call, "\n    with:")
		for _, over := range []string{"contents: write", "actions: write", "administration"} {
			if strings.Contains(block, over) {
				t.Errorf("%s hands %q down to the shared machinery", name, over)
			}
		}
	}
}

// TestTheSourceGateCanActuallyRunTheLinter pins a defect the first real run of
// validate-oci.yml found in the release workflow.
//
// `make check` runs golangci-lint and refuses to pretend it passed when the
// binary is absent — which is right, and means a job calling `make check` has to
// install one. Neither the release nor the validation source gate did. Both
// would have failed at the linter step, and for `release-oci.yml` that would
// have happened on the v0.3.0 tag push, on the run that was supposed to produce
// the first public artifact.
//
// The version must match the Makefile's, or the gate runs a linter whose
// findings the repository has never agreed to.
func TestTheSourceGateCanActuallyRunTheLinter(t *testing.T) {
	makefile := readRepoFile(t, "Makefile")
	m := regexp.MustCompile(`GOLANGCI_LINT_VERSION\s+\?=\s+(v\S+)`).FindStringSubmatch(makefile)
	if m == nil {
		t.Fatal("the Makefile no longer pins a golangci-lint version")
	}
	want := m[1]

	for _, name := range []string{releaseWorkflow, validateWorkflow} {
		wf := withoutComments(readRepoFile(t, name))
		if !strings.Contains(wf, "run: make check") {
			t.Errorf("%s no longer runs the source quality gate", name)
			continue
		}
		install := "go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + want
		if !strings.Contains(wf, install) {
			t.Errorf("%s runs `make check` without installing golangci-lint %s.\n\n"+
				"`make check` fails closed when the binary is missing, so the gate "+
				"would fail on the release tag rather than at review time.", name, want)
		}
		if !strings.Contains(wf, `echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"`) {
			t.Errorf("%s installs golangci-lint but does not put it on PATH", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Documentation claims
// ---------------------------------------------------------------------------

// TestNoDocumentClaimsASemverImageExists pins the release-claim discipline that
// `docs/COMPATIBILITY.md` and `docs/FINDINGS.md` already impose on the product.
//
// Phase 7.1-V publishes a `sha-<commit>` image and no semver tag. Until a
// release tag is pushed, `ghcr.io/hakanaltindag/svcdoctor:v0.3.0` does not
// exist, and a document that tells an operator to pull it is telling them to
// run a command that fails. Saying "SHA-only validation passed" is true and is
// allowed; saying the image is available is not.
func TestNoDocumentClaimsASemverImageExists(t *testing.T) {
	pull := regexp.MustCompile(`(?i)docker\s+(pull|run)[^\n` + "`" + `]*svcdoctor:v[0-9]`)
	tagged := regexp.MustCompile(`(?i)ghcr\.io/[a-z0-9._/-]*svcdoctor:v[0-9]`)

	for _, name := range []string{
		"README.md",
		"docs/BACKLOG.md",
		"docs/COMPATIBILITY.md",
		"docs/ARCHITECTURE.md",
		"examples/kubernetes/README.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		for _, line := range strings.Split(doc, "\n") {
			if !pull.MatchString(line) && !tagged.MatchString(line) {
				continue
			}
			// A line that says the image does *not* exist yet is the document
			// doing its job.
			lower := strings.ToLower(line)
			if strings.Contains(lower, "does not exist") || strings.Contains(lower, "not published") ||
				strings.Contains(lower, "will be") || strings.Contains(lower, "once ") ||
				strings.Contains(lower, "after ") || strings.Contains(lower, "no ") ||
				strings.Contains(lower, "never") {
				continue
			}
			t.Errorf("%s presents a semver GHCR image as available:\n  %s\n\n"+
				"No semver image has been published. Phase 7.1-V validated "+
				"sha-<commit> staging only.", name, strings.TrimSpace(line))
		}
	}
}

// ---------------------------------------------------------------------------
// One canonical SBOM format
// ---------------------------------------------------------------------------

// TestExactlyOneSBOMFormatIsPublished pins ADR 0062 §17 and closes the defect
// Phase 7.1-V measured but deliberately did not fix.
//
// The published image used to carry two inventories of itself: an SPDX document
// that BuildKit attached because `--sbom=true` was set, and the canonical
// CycloneDX JSON that the pipeline generates and cosign attests. Both were bound
// to the digest, by different mechanisms, at different levels — SPDX per
// platform, CycloneDX on the index.
//
// That is not a redundancy, it is an ambiguity. Two independently produced
// inventories of the same image can disagree about component names, versions and
// base-package modelling, and an operator asking "what is in this image" would
// have had two answers and no rule for choosing. ADR 0062 §17 chose one.
//
// The trap this guards against is that `--sbom` and `--provenance` look like a
// matched pair and are not. Turning both off would silently drop provenance,
// which nothing else produces.
func TestExactlyOneSBOMFormatIsPublished(t *testing.T) {
	shared := withoutComments(readRepoFile(t, sharedWorkflow))

	// The staged build is the only one that publishes. The reproducibility build
	// disables both attestations on purpose — it compares platform digests, and
	// attestations are not reproducible (ADR 0062 §16) — so this is scoped.
	push := stepBlock(t, shared, "Build and push by SHA tag")
	if !strings.Contains(push, "--sbom=false") {
		t.Error("the published build does not disable the BuildKit SBOM.\n\n" +
			"BuildKit emits SPDX. ADR 0062 §17 names one canonical format, CycloneDX JSON, " +
			"and a second inventory of the same image can disagree with the first.")
	}
	if strings.Contains(push, "--sbom=true") {
		t.Error("the published build re-enables the BuildKit SBOM")
	}
	// The half of the pair that must survive.
	if !strings.Contains(push, "--provenance=mode=max") {
		t.Error("the published build no longer produces provenance.\n\n" +
			"`--sbom` and `--provenance` look like a matched pair and are not: " +
			"provenance answers how the image was built and nothing else produces it.")
	}

	// Nothing in the publication path may *produce* SPDX. The proof step below
	// is excluded by construction, because detecting SPDX means naming it — a
	// blanket ban would forbid the check that enforces the ban.
	for _, name := range []string{releaseWorkflow, validateWorkflow, sharedWorkflow} {
		doc := withoutComments(readRepoFile(t, name))
		if i := strings.Index(doc, "- name: Exactly one SBOM format"); i >= 0 {
			rest := doc[i:]
			end := strings.Index(rest, "\n      - name: ")
			if end < 0 {
				end = len(rest)
			}
			doc = doc[:i] + rest[end:]
		}
		for _, needle := range []string{"spdx", "SPDX", "--sbom=true", "sbom-format", "type=spdx"} {
			if strings.Contains(doc, needle) {
				t.Errorf("%s names %q in an executable path; the canonical SBOM is CycloneDX JSON",
					name, needle)
			}
		}
	}

	// The canonical producer, its attachment and its verification must all exist.
	for _, g := range []struct{ needle, what string }{
		{"format: cyclonedx", "CycloneDX generation"},
		{"output: sbom.cdx.json", "writing the CycloneDX document"},
		{"cosign attest --yes --type cyclonedx", "attaching it as an OCI referrer"},
		{"cosign verify-attestation --type cyclonedx", "verifying it is bound to the digest"},
	} {
		if !strings.Contains(shared, g.needle) {
			t.Errorf("the canonical SBOM path no longer performs %s (looked for %q)", g.what, g.needle)
		}
	}

	// And the closure test itself: the published artifact is inspected, not the
	// build flags. A default change upstream would show up here and in no diff.
	proof := stepBlock(t, shared, "Exactly one SBOM format, and provenance survived")
	for _, g := range []struct{ needle, what string }{
		{"in-toto.io/predicate-type", "reading the attached predicate types"},
		{"'spdx' in p.lower()", "the SPDX detection"},
		{"if not any('slsa.dev/provenance' in p for p in preds):", "the provenance survival check"},
		{"sys.exit(1 if bad else 0)", "failing the run on either"},
	} {
		if !strings.Contains(proof, g.needle) {
			t.Errorf("the one-SBOM proof no longer performs %s (looked for %q)", g.what, g.needle)
		}
	}
}

// TestNoDocumentClaimsTwoCanonicalSBOMFormats keeps the documents honest about
// what a release actually carries.
//
// "We publish SPDX and CycloneDX" would be a supportability claim: it tells an
// operator both are maintained and reconciled, and neither is true.
func TestNoDocumentClaimsTwoCanonicalSBOMFormats(t *testing.T) {
	for _, name := range []string{
		"README.md",
		"docs/COMPATIBILITY.md",
		"docs/ARCHITECTURE.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		for _, sentence := range claimSentences(strings.ReplaceAll(doc, "\n", " ")) {
			lower := strings.ToLower(sentence)
			if !strings.Contains(lower, "spdx") {
				continue
			}
			// The risk is a *supportability* claim — a document telling an
			// operator that a release delivers SPDX, or that two formats are
			// canonical. Recording that BuildKit once attached one, in the past
			// tense, is the record doing its job, so the trigger is a
			// present-tense delivery verb rather than the word "SPDX".
			delivers := false
			for _, verb := range []string{
				"publishes", "publish ", "includes", "provides", "ships",
				"attaches", "carries", "supports", "supported", "canonical",
				"is attached", "are attached", "available", "both formats",
			} {
				if strings.Contains(lower, verb) {
					delivers = true
					break
				}
			}
			if !delivers {
				continue
			}
			// A sentence explaining that SPDX is *not* produced is fine.
			if denies(sentence) || strings.Contains(lower, "not ") || strings.Contains(lower, " no ") ||
				strings.Contains(lower, "never") || strings.Contains(lower, "disabled") ||
				strings.Contains(lower, "instead of") || strings.Contains(lower, "rather than") ||
				strings.Contains(lower, "would") || strings.Contains(lower, "used to") {
				continue
			}
			t.Errorf("%s presents SPDX as something svcdoctor publishes:\n  %s\n\n"+
				"ADR 0062 §17: the canonical SBOM format is CycloneDX JSON, one format only.",
				name, strings.TrimSpace(sentence))
		}
	}
}

// ---------------------------------------------------------------------------
// cosign forward compatibility
// ---------------------------------------------------------------------------

// TestCosignIsPinnedAndForwardCompatible pins two things Phase 7.1-VR found.
//
// **The version was not pinned.** `sigstore/cosign-installer` was pinned by
// commit SHA, which pins the *action* and not the *binary* it downloads. The
// pipeline was running cosign v2.5.2 — that action's default — while the
// repository's documentation discussed v3 behaviour. A signing pipeline should
// not learn its own tool version from an upstream default.
//
// **`cosign triangulate` is deprecated and is removed in v4.** It was used to
// ask where a signature was stored, and the answer was compared against a string
// this repository built from the same digest — a tautology over cosign's backing
// tag layout. Verification already proves the stronger fact semantically.
func TestCosignIsPinnedAndForwardCompatible(t *testing.T) {
	shared := readRepoFile(t, sharedWorkflow)

	m := regexp.MustCompile(`cosign-release:\s*'(v[0-9]+\.[0-9]+\.[0-9]+)'`).FindStringSubmatch(shared)
	if m == nil {
		t.Fatal("the cosign binary version is not pinned.\n\n" +
			"Pinning the installer action by SHA pins the action, not the binary: " +
			"the action picks a default cosign release and changes it on its own schedule.")
	}
	if !strings.HasPrefix(m[1], "v3.") {
		t.Errorf("cosign is pinned to %s. v3 is the current line; a downgrade to v2 or an "+
			"unreviewed jump needs a deliberate decision, not a silent edit.", m[1])
	}

	// Removed in v4. Permitted in prose that explains why it is gone; never in a
	// step that runs.
	for _, name := range []string{releaseWorkflow, validateWorkflow, sharedWorkflow} {
		doc := withoutComments(readRepoFile(t, name))
		if strings.Contains(doc, "triangulate") {
			t.Errorf("%s invokes `cosign triangulate`, which is deprecated in cosign v3 and "+
				"removed in v4. Verification proves the same fact semantically.", name)
		}
	}

	// Every cosign subcommand must address the digest. The reference sits on a
	// line continuation, so a single-line regex over the command never sees it —
	// found by mutation, which moved the target to a tag and went unnoticed.
	for _, step := range []string{
		"Sign the digest (keyless, GitHub OIDC)",
		"Attach the CycloneDX SBOM as a signed attestation",
		"Verify the signature against this exact identity",
		"Verify the SBOM attestation is bound to this digest",
	} {
		block := stepBlock(t, withoutComments(shared), step)
		if !strings.Contains(block, "${IMAGE}@${{ needs.stage.outputs.digest }}") {
			t.Errorf("step %q does not address the staged digest", step)
		}
		if strings.Contains(block, "${IMAGE}:") {
			t.Errorf("step %q addresses a tag. A tag can be re-pointed; signing or "+
				"attesting one proves nothing about what is served later.", step)
		}
	}

	// Correctness must rest on the verifier, not on cosign's storage layout.
	// Seeing a `.sig` tag says something exists; verification says a signed
	// object is valid for this digest and this identity.
	for _, required := range []string{
		"cosign verify \\",
		"cosign verify-attestation --type cyclonedx",
		"docker-manifest-digest",
		"https://cyclonedx.org/bom",
	} {
		if !strings.Contains(shared, required) {
			t.Errorf("the shared machinery no longer proves signature or attestation "+
				"binding semantically (looked for %q)", required)
		}
	}
	// A backing-tag existence check must not be the gate.
	if regexp.MustCompile(`(?m)^\s*\[ .*\.sig.* \]`).MatchString(shared) {
		t.Error("a cosign backing-tag name is used as a correctness gate; " +
			"use cosign verify, which proves validity rather than existence")
	}
}
