#!/usr/bin/env bash
# Phase 9.3A mutation closure — the release-artifact mechanism.
#
# Each mutation is planted, the guard that should notice it is run and must FAIL,
# and the tree is restored and verified byte-for-byte against sha256 checksums
# taken before anything was touched.
#
# A mutation whose guard passes is a survivor and fails this script. A tree that
# does not restore exactly also fails it.
#
# # What this covers that the earlier scripts do not
#
# 9.1A/9.1B/9.1C mutated the multi-target chain; 9.2B mutated the release
# blockers and the documentation guards. This mutates the thing RB-05 said did
# not exist: the mechanism that produces the five platform archives and
# SHA256SUMS ADR 0076 section 2.3 requires.
#
#   R01-R04, R09-R10  scripts/build-release.sh — the recipe
#   R05-R07           .github/workflows/release-oci.yml — the caller
#   R08               a release version that stops coming from the tag
#
# Half of these are caught by an executed build in ./test/release and half by a
# static read in ./internal/cli, deliberately. A release runs once, on a tag, in
# an environment nobody rehearses: the structural guards say the workflow still
# calls the shared recipe, and the executed ones say the recipe still produces
# what the workflow claims to attach. Neither alone is enough — RB-05 existed
# because a required artifact set had a document and no mechanism.
#
# The executed mutations take a few minutes. Five cross-compilations per run is
# what proving an artifact rather than describing one costs.
set -uo pipefail

cd "$(dirname "$0")/.."

BACKUP="$(mktemp -d)"
FILES=(
  scripts/build-release.sh
  .github/workflows/release-oci.yml
)

for f in "${FILES[@]}"; do
  mkdir -p "$BACKUP/$(dirname "$f")"
  cp "$f" "$BACKUP/$f"
done

BEFORE="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
restore() { for f in "${FILES[@]}"; do cp "$BACKUP/$f" "$f"; done; }

# An interrupted harness must not leave a mutation planted.
#
# Phase 9.3A measured why this is not hypothetical. A run of this suite was
# killed by a ten-minute command timeout part-way through, leaving one planted
# mutation in the working tree. The next run took *that* tree as its pristine
# baseline, restored to it byte-for-byte at the end, truthfully reported "tree
# restored" — and reported a survivor that was an artefact of the leftover
# rather than a gap in any guard.
#
# The BEFORE/AFTER checksums cannot catch this: they prove the run put back what
# it found, not that what it found was the committed tree. A trap can, because
# the failure is a script that stops between planting and restoring.
#
# Guarded on the backup still existing, so the ordinary exit path — which
# restores and removes the backup itself — is not a double restore from a
# directory that is gone.
on_interrupt() {
  if [ -d "$BACKUP" ]; then
    restore
    rm -rf "$BACKUP"
    echo
    echo "interrupted: the tree was restored from the backup before exiting."
  fi
}
trap on_interrupt EXIT
trap 'on_interrupt; exit 130' INT
trap 'on_interrupt; exit 143' TERM HUP

PASS=0
FAIL=0
SURVIVORS=()

# mutate <id> <description> <file> <python-replacement> <test-package> <test-regex>
mutate() {
  local id="$1" desc="$2" file="$3" script="$4" pkg="$5" regex="$6"

  # A -run regex that selects **no test** makes `go test` exit 0, which this
  # harness would read as a survivor. Twenty mutations sat "surviving" across
  # phase91a and phase91b for exactly that reason until the v0.4.0 release gate
  # measured them. An empty selection is a harness failure, not a finding about
  # the product, and the two need opposite fixes.
  #
  # Checked on the **pristine** tree, before planting: after planting, a mutation
  # that breaks the build produces no `=== RUN` either, and a check placed later
  # could not tell the two apart.
  local selected
  selected="$(go test "$pkg" -run "$regex" -count=1 -timeout 600s -v 2>/dev/null || true)"
  if ! printf '%s' "$selected" | grep -q '^=== RUN'; then
    echo "  $id  NO MATCHING TEST — the -run regex selects nothing: $regex"
    FAIL=$((FAIL + 1)); SURVIVORS+=("$id (no matching test: $regex)"); return
  fi

  if ! python3 - "$file" <<PY
import sys
path = sys.argv[1]
s = open(path).read()
$script
open(path, 'w').write(s)
PY
  then
    echo "  $id  COULD NOT PLANT — the anchor text is gone: $desc"
    FAIL=$((FAIL + 1)); SURVIVORS+=("$id (unplantable)"); restore; return
  fi

  if go test "$pkg" -run "$regex" -count=1 -timeout 600s >/dev/null 2>&1; then
    echo "  $id  SURVIVOR — $desc"
    SURVIVORS+=("$id $desc"); FAIL=$((FAIL + 1))
  else
    echo "  $id  caught    — $desc"
    PASS=$((PASS + 1))
  fi
  restore
}

echo "Phase 9.3A mutation closure — the release-artifact mechanism (RB-05)"
echo
echo "--- the recipe: scripts/build-release.sh ---"

mutate R01 "the builder produces one platform instead of five" \
  scripts/build-release.sh \
  's = s.replace("""PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64\"""",
"""PLATFORMS="linux/amd64\"""", 1)
assert "PLATFORMS=\"linux/amd64\"\n" in s' \
  ./test/release 'TestReleaseBuilder'

mutate R02 "SHA256SUMS is never written" \
  scripts/build-release.sh \
  's = s.replace("""( cd "$OUTDIR_ABS" && sha256_sum "$@" > SHA256SUMS )
( cd "$OUTDIR_ABS" && sha256_check SHA256SUMS )""", """: no checksums""", 1)
assert "> SHA256SUMS" not in s' \
  ./test/release 'TestReleaseBuilder'

mutate R03 "one archive is left out of SHA256SUMS" \
  scripts/build-release.sh \
  's = s.replace("""( cd "$OUTDIR_ABS" && sha256_sum "$@" > SHA256SUMS )""",
"""shift
( cd "$OUTDIR_ABS" && sha256_sum "$@" > SHA256SUMS )""", 1)
assert "shift\n( cd \"$OUTDIR_ABS\" && sha256_sum" in s' \
  ./test/release 'TestReleaseBuilder'

mutate R04 "an absolute build path enters SHA256SUMS" \
  scripts/build-release.sh \
  's = s.replace("""( cd "$OUTDIR_ABS" && sha256_sum "$@" > SHA256SUMS )""",
"""( cd "$OUTDIR_ABS" && sha256_sum $(for a in "$@"; do printf "%s " "$OUTDIR_ABS/$a"; done) > SHA256SUMS )""", 1)
assert "printf \"%s \" \"$OUTDIR_ABS/$a\"" in s' \
  ./test/release 'TestReleaseBuilder'

mutate R09 "the dirty-tree refusal is removed" \
  scripts/build-release.sh \
  's = s.replace("""if [ -n "$DIRTY" ]; then""", """if [ -n "${DIRTY:+never}" ] && false; then""", 1)
assert "&& false; then" in s' \
  ./test/release 'TestReleaseBuilder'

mutate R10 "a source file enters every archive" \
  scripts/build-release.sh \
  's = s.replace("""ARCHIVE_EXTRAS="LICENSE README.md\"""", """ARCHIVE_EXTRAS="LICENSE README.md go.mod\"""", 1)
assert "LICENSE README.md go.mod" in s' \
  ./test/release 'TestReleaseBuilder'

mutate R08 "the builder defaults to a hardcoded release version" \
  scripts/build-release.sh \
  's = s.replace("""[ -n "$VERSION" ] || { printf \x27a version is required\\n\\n\x27 >&2; usage >&2; exit 2; }""",
"""VERSION=${VERSION:-v0.4.0}""", 1)
assert "VERSION=${VERSION:-v0.4.0}" in s' \
  ./internal/cli 'TestTheReleaseArchiveVersionComesFromTheTag'

echo
echo "--- the caller: .github/workflows/release-oci.yml ---"

mutate R05 "the workflow builds its own archives instead of calling the recipe" \
  .github/workflows/release-oci.yml \
  's = s.replace("""          ./scripts/build-release.sh "$VERSION" dist/release""",
"""          mkdir -p dist/release
          GOOS=linux GOARCH=amd64 go build ./cmd/svcdoctor""", 1)
assert "GOOS=linux GOARCH=amd64 go build" in s' \
  ./internal/cli 'TestTheReleaseArchivesAreBuiltByTheSharedRecipe'

# The needles below are assembled from chr() rather than written as escapes: the
# text being matched is a shell line continuation inside YAML, and it reaches
# Python through a shell heredoc. One backslash too many is a mutation that
# cannot be planted, which reads exactly like a guard that cannot fail.
mutate R06 "the Release stops attaching SHA256SUMS" \
  .github/workflows/release-oci.yml \
  'BS, NL = chr(92), chr(10)
s = s.replace(" " * 14 + "release-assets/SHA256SUMS " + BS + NL, "", 1)
assert "release-assets/SHA256SUMS" not in s.split("a Release already exists")[0]' \
  ./internal/cli 'TestTheGitHubReleaseAttachesEveryRequiredArtifact'

mutate R07 "the Release stops attaching the signed SBOM" \
  .github/workflows/release-oci.yml \
  'BS, NL = chr(92), chr(10)
s = s.replace(" " * 14 + "sbom.cdx.json " + BS + NL, "", 1)
assert "sbom.cdx.json" not in s.split("a Release already exists")[0].split("gh release create")[1]' \
  ./internal/cli 'TestTheGitHubReleaseAttachesEveryRequiredArtifact'

echo
echo "--- restoration ---"

AFTER="$(find "${FILES[@]}" -type f -exec shasum -a 256 {} \; | sort)"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "  TREE NOT RESTORED — checksums differ:"
  diff <(echo "$BEFORE") <(echo "$AFTER")
  FAIL=$((FAIL + 1))
else
  echo "  tree restored byte-for-byte (sha256)"
fi

rm -rf "$BACKUP"

echo
echo "caught: $PASS   survivors: ${#SURVIVORS[@]}"
if [ ${#SURVIVORS[@]} -gt 0 ]; then
  printf '  %s\n' "${SURVIVORS[@]}"
  exit 1
fi
[ "$FAIL" -eq 0 ] || exit 1
echo "0 survivors"
