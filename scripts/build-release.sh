#!/usr/bin/env bash
#
# The official svcdoctor release-archive recipe.
#
# This script *is* the recipe ADR 0076 section 2.3 refers to. "The release
# attaches five archives and SHA256SUMS" is a claim about what this file does,
# so archives built any other way are not archives this project stands behind.
#
# It builds and it checksums. It never tags, pushes, signs or publishes
# anything — publication is `.github/workflows/release-oci.yml`, which invokes
# *this* script rather than reimplementing it. One recipe, two callers: a local
# release qualification and the release workflow. That is the whole point.
# RB-05 exists because there was no executable recipe at all; a second copy of
# one in YAML would be the same defect wearing a different hat.
#
# Usage:
#   scripts/build-release.sh v0.4.0                 official; HEAD must carry that tag
#   scripts/build-release.sh v0.4.0 /tmp/out        official, explicit output directory
#   scripts/build-release.sh --untagged v0.4.0 out  qualification build; see below
#
# Environment:
#   GO        the Go toolchain to build with (default: go)
#
# --untagged relaxes exactly one rule: that the version being built is a tag on
# HEAD. It relaxes nothing else — the tree must still be clean, the version must
# still be a well-formed vX.Y.Z, and the artifacts are byte-for-byte what an
# official build of the same tree would produce. It exists so a release
# candidate can be qualified *before* the tag is cut, which is the only order in
# which qualification can influence the decision to cut it.

set -euo pipefail

# The five platforms ADR 0076 section 2.3 makes required, and only those.
# `freebsd/amd64` builds clean and is deliberately unpublished: an artifact is a
# claim that a platform is intended to work, and nothing has been run against it.
PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

# Held separately from PLATFORMS on purpose. Deriving the expected count from the
# list would make a truncated list self-consistent, and "build one platform
# instead of five" is precisely the edit this has to fail on.
EXPECTED_ARTIFACTS=5

# Everything an archive may contain, and nothing else. The tar and zip commands
# below name their members explicitly rather than archiving a directory, so this
# list is the mechanism and not merely a description of one.
ARCHIVE_EXTRAS="LICENSE README.md"

GO=${GO:-go}

# macOS `tar` is bsdtar, and bsdtar stores extended attributes as AppleDouble
# `._name` members. Those are invisible to `tar -tzf` on macOS — bsdtar folds
# them back on read — and perfectly visible to GNU tar on the Linux machine that
# unpacks the release, where they extract as three junk files beside the binary.
#
# Measured, not anticipated: the first archive this script produced contained
# `._svcdoctor`, `._LICENSE` and `._README.md`, and the macOS listing said it
# did not. COPYFILE_DISABLE is bsdtar's documented off switch and GNU tar
# ignores it, so one export covers both.
export COPYFILE_DISABLE=1

die() { printf 'refusing: %s\n' "$1" >&2; exit 1; }

usage() { sed -n '3,29p' "$0"; }

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

VERSION=""
OUTDIR=""
REQUIRE_TAG=yes

while [ $# -gt 0 ]; do
  case "$1" in
    --untagged) REQUIRE_TAG=no ;;
    -h|--help)  usage; exit 0 ;;
    -*)         printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
    *)
      if   [ -z "$VERSION" ]; then VERSION="$1"
      elif [ -z "$OUTDIR"  ]; then OUTDIR="$1"
      else printf 'unexpected argument: %s\n' "$1" >&2; exit 2
      fi
      ;;
  esac
  shift
done

# There is no default version and there never will be one. A release version is
# a decision, and a script that guessed it from the working tree would be a
# second version authority competing with the Git tag (ADR 0062 section 12).
[ -n "$VERSION" ] || { printf 'a version is required\n\n' >&2; usage >&2; exit 2; }

# The same shape `release-oci.yml` enforces on the triggering tag, deliberately
# character for character: a tag the workflow accepts must never be one this
# script rejects, or a release would fail after the image had been published.
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' \
  || die "'$VERSION' is not a vX.Y.Z release version"

OUTDIR=${OUTDIR:-dist/release}

# Absolute before anything changes directory, and by string rather than by
# realpath(1), which is not portable to a stock macOS.
case "$OUTDIR" in
  /*) OUTDIR_ABS="$OUTDIR" ;;
  *)  OUTDIR_ABS="$PWD/$OUTDIR" ;;
esac
OUTDIR_ABS="${OUTDIR_ABS%/}"

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
#
# Detected deliberately and refused loudly. This script runs on a developer's
# macOS and on an ubuntu-latest runner, and those two disagree about sha256:
# GNU coreutils provides `sha256sum`, macOS provides `shasum`. Guessing wrong
# produces no checksum file, and falling back to a weaker digest would produce a
# worthless one — so neither is done.

if command -v sha256sum >/dev/null 2>&1; then
  SHA_TOOL=sha256sum
elif command -v shasum >/dev/null 2>&1; then
  SHA_TOOL=shasum
else
  die "neither sha256sum nor shasum is available; SHA256SUMS cannot be produced"
fi

sha256_sum()   { if [ "$SHA_TOOL" = sha256sum ]; then sha256sum   "$@"; else shasum -a 256 "$@"; fi; }
sha256_check() { if [ "$SHA_TOOL" = sha256sum ]; then sha256sum -c "$@"; else shasum -a 256 -c "$@"; fi; }

command -v git >/dev/null 2>&1 || die "git is not available; release identity cannot be established"
command -v tar >/dev/null 2>&1 || die "tar is not available; the Unix archives cannot be produced"
command -v zip >/dev/null 2>&1 || die "zip is not available; the windows/amd64 archive cannot be produced"
command -v "$GO" >/dev/null 2>&1 || die "'$GO' is not available"

# ---------------------------------------------------------------------------
# Source identity
# ---------------------------------------------------------------------------

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not inside a Git repository"
cd "$ROOT"

# The output directory is an *output*, not source. Excluding it from the
# dirtiness check is what lets `scripts/build-release.sh v0.4.0 out` work when
# `out/` is not in .gitignore — without it, the second run of a release build
# would refuse because the first run's artifacts were sitting there.
#
# The default, `dist/release`, is inside an already-ignored `dist/`, so it never
# reaches this check at all: `git status --porcelain` does not report ignored
# files. Both paths are covered, and neither weakens the check for anything that
# is genuinely source.
#
# `--untracked-files=all` is load-bearing rather than thorough-looking. With the
# default, Git collapses an untracked directory to a single `?? out/` entry, and
# an exclusion naming `out/v0.4.0` then hides nothing — measured, not assumed.
# Listing files individually makes the exclusion exact, and it also makes the
# check itself stricter for everything that is not the output directory.
STATUS_ARGS=(status --porcelain --untracked-files=all)
case "$OUTDIR_ABS" in
  "$ROOT"/*) STATUS_ARGS+=(-- . ":(exclude)${OUTDIR_ABS#"$ROOT"/}") ;;
esac

DIRTY="$(git "${STATUS_ARGS[@]}")"
if [ -n "$DIRTY" ]; then
  printf 'refusing: the working tree is dirty.\n' >&2
  printf 'A release artifact must correspond to a commit, and this tree does not.\n' >&2
  printf '%s\n' "$DIRTY" >&2
  exit 1
fi

REVISION="$(git rev-parse HEAD)"

if [ "$REQUIRE_TAG" = yes ]; then
  # `git tag --points-at` rather than `git describe --exact-match`: describe
  # picks one tag when a commit carries several, so it can answer "yes, tagged"
  # about a tag that is not the one being built.
  if ! git tag --points-at HEAD | grep -qx -- "$VERSION"; then
    printf 'refusing: HEAD does not carry the tag %s.\n' "$VERSION" >&2
    printf 'An official archive may not precede its Git tag (ADR 0062 section 13).\n' >&2
    printf 'Tag the release commit first, or use --untagged to qualify a candidate.\n' >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# Output and staging
# ---------------------------------------------------------------------------

mkdir -p "$OUTDIR_ABS"
if [ -n "$(ls -A "$OUTDIR_ABS")" ]; then
  die "$OUTDIR_ABS is not empty. A release directory holds one release's artifacts and nothing else."
fi

# Platform binaries are staged outside the repository and never inside it, so an
# interrupted build cannot leave a foreign-architecture binary in a source tree
# that a later commit might pick up.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/svcdoctor-release.XXXXXX")"
cleanup() { rm -rf "$STAGE"; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

VERSION_NUMBER="${VERSION#v}"

if [ "$REQUIRE_TAG" = yes ]; then
  TAG_CHECK="required, and HEAD carries $VERSION"
else
  TAG_CHECK="waived (--untagged): this is a candidate qualification, not a release"
fi

printf 'version:   %s\n'   "$VERSION"
printf 'revision:  %s\n'   "$REVISION"
printf 'tag check: %s\n'   "$TAG_CHECK"
printf 'output:    %s\n\n' "$OUTDIR_ABS"

ARTIFACTS=""

for platform in $PLATFORMS; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  name="svcdoctor_${VERSION_NUMBER}_${goos}_${goarch}"

  binary=svcdoctor
  if [ "$goos" = windows ]; then binary=svcdoctor.exe; fi

  mkdir -p "$STAGE/$name"

  # The version injection is the one `Dockerfile` uses and the one `README.md`
  # documents. `resolvedVersion()` is the single authority inside the binary, and
  # this is the only thing that feeds it — so `--version` and every report's
  # `run.svcdoctorVersion` name the release this archive is.
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    "$GO" build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
      -o "$STAGE/$name/$binary" ./cmd/svcdoctor

  # shellcheck disable=SC2086 # ARCHIVE_EXTRAS is a deliberate word list.
  cp $ARCHIVE_EXTRAS "$STAGE/$name/"

  if [ "$goos" = windows ]; then
    archive="$name.zip"
    # Members named explicitly, and -X so no extra local attributes are stored.
    # `zip -r .` would archive whatever happened to be in the directory.
    ( cd "$STAGE/$name" && zip -q -X "$OUTDIR_ABS/$archive" $binary $ARCHIVE_EXTRAS )
  else
    archive="$name.tar.gz"
    # shellcheck disable=SC2086 # ARCHIVE_EXTRAS is a deliberate word list.
    tar -czf "$OUTDIR_ABS/$archive" -C "$STAGE/$name" $binary $ARCHIVE_EXTRAS

    # Read back what was actually written. Naming the members is the guarantee;
    # this is a cheap confirmation of it — and only that, because bsdtar hides
    # the AppleDouble members COPYFILE_DISABLE exists to prevent, so on macOS
    # this listing cannot see the one failure mode that made it necessary.
    # `test/release` reads the archives with Go's own tar and zip readers for
    # exactly that reason: the tool that wrote an archive is the wrong tool to
    # verify it with.
    listed="$(tar -tzf "$OUTDIR_ABS/$archive" | sort | tr '\n' ' ')"
    expected="$(printf '%s\n' $binary $ARCHIVE_EXTRAS | sort | tr '\n' ' ')"
    [ "$listed" = "$expected" ] || die "$archive contains [$listed], expected [$expected]"
  fi

  ARTIFACTS="$ARTIFACTS $archive"
  printf '  %s\n' "$archive"
done

# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------

# shellcheck disable=SC2086 # ARTIFACTS is a deliberate word list.
set -- $ARTIFACTS
[ "$#" -eq "$EXPECTED_ARTIFACTS" ] \
  || die "produced $# archives, expected $EXPECTED_ARTIFACTS (ADR 0076 section 2.3)"

# Run from inside the output directory and name the artifacts by basename, so
# the checksum file records file names rather than the path they happened to be
# built at. A SHA256SUMS carrying `/Users/somebody/...` verifies on exactly one
# machine, which is the one machine that does not need it.
#
# SHA256SUMS does not checksum itself. Neither did v0.1.0's, and a self-entry
# cannot be correct anyway: the digest would have to exist before the line
# containing it was written.
( cd "$OUTDIR_ABS" && sha256_sum "$@" > SHA256SUMS )
( cd "$OUTDIR_ABS" && sha256_check SHA256SUMS )

printf '\n%s\n\n' "$(cd "$OUTDIR_ABS" && cat SHA256SUMS)"
printf 'Checksums verified with %s.\n' "$SHA_TOOL"
printf 'Wrote %s archives and SHA256SUMS to %s.\n' "$EXPECTED_ARTIFACTS" "$OUTDIR_ABS"
printf 'Nothing was tagged, pushed, signed or published.\n'
