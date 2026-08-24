package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The release-contract audit: the parts of ADR 0062 sections 12-20 that can be
// checked without a registry, a network or a published artifact.
//
// # What this file can and cannot enforce, stated honestly
//
// The release contract has two halves. One half lives in files this repository
// owns — the build recipe, the Dockerfile, the documents — and is checkable
// here, now, in `make check`. The other half only becomes real when something
// is pushed: that a signature covers a digest rather than a tag, that provenance
// names `refs/tags/vX.Y.Z`, that a semver tag was applied last. Those need the
// publication workflow, and Phase 7.1-P owns them.
//
// Pretending otherwise would be the exact failure this repository keeps
// guarding against: a test suite that looks like it covers a contract and
// covers the half that was easy. So each guard below says which half it is in,
// and `TestUnenforceableContractItemsAreRecordedAsSuch` fails if the backlog
// stops carrying the other half.
//
// The recipe is the reason so much *is* checkable. Deriving the version from
// Git rather than accepting it as an argument turns "the image version must
// match the Git tag" from a policy nobody can test into a property of a script
// that can be read and executed.

// releaseRecipe is the one file that defines an official build.
const releaseRecipe = "scripts/build-image.sh"

// TestTheReleaseRecipeDerivesVersionFromGit pins ADR 0062 section 12.
//
// Phase 7.1-R measured the gap this closes: a hand-passed build argument
// produced an image whose binary and label both asserted `v9.9.9-not-a-real-tag`
// at revision `deadbeef`. Binary and label agreed with each other — they share
// one ARG — and both were fiction. Internal consistency was never the problem.
func TestTheReleaseRecipeDerivesVersionFromGit(t *testing.T) {
	recipe := readRepoFile(t, releaseRecipe)

	for _, derivation := range []struct{ what, from string }{
		{"the revision", "git rev-parse HEAD"},
		{"the version", "git describe --tags --exact-match"},
		{"SOURCE_DATE_EPOCH", "git show -s --format=%ct"},
	} {
		if !strings.Contains(recipe, derivation.from) {
			t.Errorf("%s does not derive %s from Git (expected %q).\n\n"+
				"A value that can be typed can be typed wrongly, and an official "+
				"image would then claim a version no tag names.",
				releaseRecipe, derivation.what, derivation.from)
		}
	}

	// And it must not offer a way to supply one instead.
	for _, escape := range []string{"--version)", "VERSION=$1", "${VERSION:-"} {
		if strings.Contains(recipe, escape) {
			t.Errorf("%s accepts a caller-supplied version (%q), which would create "+
				"a second version authority", releaseRecipe, escape)
		}
	}
}

// TestTheReleaseRecipeRefusesUntaggedAndDirtyBuilds pins ADR 0062 sections 12
// and 13: an OCI semver tag may not precede its Git tag.
//
// Both refusals were exercised in Phase 7.1-R and exit 1. This guard is that
// they stay in the file, because deleting either one is a one-line edit that
// leaves the script working perfectly for every case anyone tests by hand.
func TestTheReleaseRecipeRefusesUntaggedAndDirtyBuilds(t *testing.T) {
	recipe := readRepoFile(t, releaseRecipe)

	if !strings.Contains(recipe, "git status --porcelain") {
		t.Error(releaseRecipe + " does not check for a dirty tree; an official image " +
			"could be built from a state no commit contains")
	}
	if !strings.Contains(recipe, "--exact-match") {
		t.Error(releaseRecipe + " does not require an exact tag match; a commit that " +
			"merely descends from a tag would inherit that tag's version")
	}
	// The semver shape check, so `git describe` returning something tag-shaped
	// but not a release is refused.
	if !strings.Contains(recipe, "v[0-9]*.[0-9]*.[0-9]*") {
		t.Error(releaseRecipe + " does not validate the tag as vX.Y.Z")
	}
}

// TestTheReleaseRecipeSetsBothDeterminismParameters pins ADR 0062 section 15.
//
// Both, because Phase 7.1-R measured that neither alone is sufficient:
// rewrite-timestamp alone did not reproduce, and SOURCE_DATE_EPOCH alone did not
// reproduce. The plausible-sounding belief that one subsumes the other is
// exactly the belief that would delete one of these lines.
func TestTheReleaseRecipeSetsBothDeterminismParameters(t *testing.T) {
	recipe := readRepoFile(t, releaseRecipe)

	if !strings.Contains(recipe, "SOURCE_DATE_EPOCH") {
		t.Error(releaseRecipe + " does not set SOURCE_DATE_EPOCH; measured: not reproducible")
	}
	if !strings.Contains(recipe, "rewrite-timestamp=true") {
		t.Error(releaseRecipe + " does not set rewrite-timestamp=true; measured: not reproducible")
	}

	// A development build must not be held to the reproducibility contract, and
	// must not masquerade as a release.
	if !strings.Contains(recipe, "sha-$(git rev-parse --short HEAD)") {
		t.Error(releaseRecipe + " does not tag development images as sha-<commit> " +
			"(ADR 0062 section 13)")
	}
}

// TestTheReleaseRecipeNeverPublishes pins the boundary this phase deliberately
// did not cross.
//
// The recipe builds. Pushing, signing and tagging a registry reference belong
// to a pipeline that can enforce the identity constraints in ADR 0062 section
// 17 — a local script cannot, and a local script that pushed would be the
// easiest possible way to publish something unsigned by accident.
func TestTheReleaseRecipeNeverPublishes(t *testing.T) {
	recipe := readRepoFile(t, releaseRecipe)

	for _, publish := range []string{"--push", "docker push", "cosign sign", "type=registry"} {
		if strings.Contains(recipe, publish) {
			t.Errorf("%s can publish (%q). The build recipe must not push, sign or "+
				"tag a registry reference; that is Phase 7.1-P.", releaseRecipe, publish)
		}
	}
}

// TestNoDocumentConflatesTheSupplyChainArtifacts pins ADR 0062 section 17.
//
// SBOM, signature, provenance and OCI labels answer four different questions.
// The conflation that actually gets written is "the labels provide provenance",
// because labels do record a source URL and a revision — they just record what
// the builder chose to write, which is the opposite of evidence.
func TestNoDocumentConflatesTheSupplyChainArtifacts(t *testing.T) {
	conflations := []struct{ phrase, why string }{
		{"labels provide provenance", "labels are self-declared metadata"},
		{"labels are provenance", "labels are self-declared metadata"},
		{"label provides provenance", "labels are self-declared metadata"},
		{"sbom signs", "an SBOM is an inventory, not a signature"},
		{"sbom proves authenticity", "an SBOM is an inventory, not a signature"},
		{"provenance lists the components", "provenance records how it was built, not what is inside"},
		{"signature proves reproducib", "a signature proves origin, not determinism"},
	}
	for _, name := range []string{
		"README.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
		"examples/kubernetes/README.md",
		"docs/BACKLOG.md",
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		lower := strings.ToLower(doc)
		for _, c := range conflations {
			if strings.Contains(lower, c.phrase) {
				t.Errorf("%s says %q: %s (ADR 0062 section 17)", name, c.phrase, c.why)
			}
		}
	}
}

// TestNoDocumentClaimsAnUnearnedSupplyChainLevel pins ADR 0062 section 17.
//
// "SLSA Level 3" is a specification with requirements, not an adjective. The
// same rule docs/COMPATIBILITY.md applies to database compatibility applies
// here: a level is claimed after it is audited, not because the pipeline looks
// like it would qualify.
func TestNoDocumentClaimsAnUnearnedSupplyChainLevel(t *testing.T) {
	claims := []string{"slsa compliant", "slsa level", "slsa l3", "slsa-l3", "fully reproducible", "supply-chain proof"}
	for _, name := range []string{
		"README.md",
		"docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md",
		"docs/BACKLOG.md",
		"docs/COMPATIBILITY.md",
	} {
		doc, ok := readRepoFileOptional(t, name)
		if !ok {
			continue
		}
		// Sentence by sentence, and denials are exempt — reusing the same
		// helpers docsclaims_test.go uses for the managed-provider rule. ADR
		// 0062 has to be able to say "this record does not claim a SLSA level",
		// and a guard that forbade the disclaimer along with the claim would be
		// deleted rather than obeyed.
		for _, line := range strings.Split(doc, "\n") {
			for _, sentence := range claimSentences(line) {
				lower := strings.ToLower(sentence)
				for _, claim := range claims {
					if strings.Contains(lower, claim) && !denies(sentence) {
						t.Errorf("%s claims %q without an audit establishing it:\n  %s",
							name, claim, strings.TrimSpace(sentence))
					}
				}
			}
		}
	}
}

// TestTheReproducibilityClaimStaysScoped pins ADR 0062 sections 15 and 16.
//
// This is the claim most likely to drift, because the scoped version is a
// mouthful and the unscoped version is a slogan. Phase 7.1-R measured that with
// provenance and SBOM attestations enabled the platform image digests reproduce
// exactly while the attestation manifests — and therefore the index — do not.
// Since provenance is required, an unscoped claim is not merely imprecise: it is
// false about every image this project will ever publish.
func TestTheReproducibilityClaimStaysScoped(t *testing.T) {
	adr := readRepoFile(t, "docs/decisions/0062-oci-runtime-and-kubernetes-execution-model.md")

	if !strings.Contains(adr, "platform image manifest digest MUST be identical") {
		t.Error("ADR 0062 no longer states the reproducibility claim in terms of the " +
			"platform image manifest digest")
	}
	if !strings.Contains(adr, "not a claim about the\nindex digest") &&
		!strings.Contains(adr, "not a claim about the index digest") {
		t.Error("ADR 0062 no longer excludes the index digest from the reproducibility " +
			"claim. With required provenance the index cannot reproduce, so an " +
			"unscoped claim would be false for every published image.")
	}
	// And the measurement that forces the scoping must stay recorded.
	if !strings.Contains(adr, "Attestation manifests") {
		t.Error("ADR 0062 no longer records that attestation manifests do not reproduce")
	}
}

// TestUnenforceableContractItemsAreRecordedAsSuch is the honesty guard.
//
// Everything above checks the half of the contract that lives in files. The
// other half — signature target, provenance source ref, tag-applied-last —
// cannot be checked without publishing. That is fine, but only while it is
// written down somewhere a reader will find it. If the backlog stops carrying
// these, the contract silently becomes "whatever the tests happen to check".
func TestUnenforceableContractItemsAreRecordedAsSuch(t *testing.T) {
	backlog := readRepoFile(t, "docs/BACKLOG.md")

	if !strings.Contains(backlog, "Phase 7.1-P") {
		t.Fatal("docs/BACKLOG.md no longer records Phase 7.1-P, which owns every part " +
			"of the release contract that needs a registry to enforce")
	}
	for _, item := range []struct{ needle, what string }{
		{"never over a tag", "signing target"},
		{"amd64", "native amd64 validation before first publication"},
		{"NetworkPolicy", "unverified NetworkPolicy evidence"},
		{"tag last", "semver tag applied last, so a partial release wears no tag"},
	} {
		if !strings.Contains(backlog, item.needle) {
			t.Errorf("docs/BACKLOG.md no longer records the %s obligation (looked for %q).\n\n"+
				"It cannot be enforced by a test until publication exists, so the "+
				"written record is the only thing carrying it.", item.what, item.needle)
		}
	}
}

// TestTheReleaseContractGuardsCanFail proves the guards above are load-bearing.
//
// Same discipline as docsclaims_test.go and containerclaims_test.go: each case
// is a real mutation from the Phase 7.1-R matrix applied to synthetic input.
func TestTheReleaseContractGuardsCanFail(t *testing.T) {
	t.Run("hand-supplied version is detected", func(t *testing.T) {
		bad := `VERSION=${VERSION:-dev}`
		if !strings.Contains(bad, "${VERSION:-") {
			t.Error("a caller-supplied version would not be caught")
		}
		good := `VERSION=$(git describe --tags --exact-match HEAD)`
		if strings.Contains(good, "${VERSION:-") {
			t.Error("a Git-derived version is wrongly flagged")
		}
	})

	t.Run("missing determinism parameter is detected", func(t *testing.T) {
		onlyRewrite := "--output type=oci,dest=x,rewrite-timestamp=true"
		if strings.Contains(onlyRewrite, "SOURCE_DATE_EPOCH") {
			t.Error("a recipe missing SOURCE_DATE_EPOCH would pass")
		}
		onlyEpoch := "SOURCE_DATE_EPOCH=123 docker buildx build --output type=oci,dest=x"
		if strings.Contains(onlyEpoch, "rewrite-timestamp=true") {
			t.Error("a recipe missing rewrite-timestamp would pass")
		}
	})

	t.Run("publishing recipe is detected", func(t *testing.T) {
		for _, bad := range []string{"docker buildx build --push .", "cosign sign $IMG", "--output type=registry"} {
			hit := false
			for _, p := range []string{"--push", "docker push", "cosign sign", "type=registry"} {
				if strings.Contains(bad, p) {
					hit = true
				}
			}
			if !hit {
				t.Errorf("a publishing recipe would pass: %s", bad)
			}
		}
	})

	t.Run("label-as-provenance is detected", func(t *testing.T) {
		planted := "the oci labels provide provenance for each image"
		if !strings.Contains(planted, "labels provide provenance") {
			t.Error("a label-as-provenance claim would not be caught")
		}
	})

	t.Run("unearned SLSA level is detected", func(t *testing.T) {
		planted := strings.ToLower("Our pipeline is SLSA Level 3 compliant")
		hit := false
		for _, c := range []string{"slsa compliant", "slsa level"} {
			if strings.Contains(planted, c) {
				hit = true
			}
		}
		if !hit {
			t.Error("an unearned SLSA claim would not be caught")
		}
	})

	t.Run("unscoped reproducibility claim is detected", func(t *testing.T) {
		planted := "every svcdoctor release image is fully reproducible"
		if !strings.Contains(strings.ToLower(planted), "fully reproducible") {
			t.Error("an unscoped reproducibility slogan would not be caught")
		}
	})
}

// TestTheReleaseRecipeIsExecutable is a small correctness check: a recipe that
// is not executable is a recipe nobody runs the same way twice.
func TestTheReleaseRecipeIsExecutable(t *testing.T) {
	info, err := os.Stat(filepath.Join("..", "..", releaseRecipe))
	if err != nil {
		t.Fatalf("stat %s: %v", releaseRecipe, err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("%s is not executable (mode %v)", releaseRecipe, info.Mode().Perm())
	}
}
