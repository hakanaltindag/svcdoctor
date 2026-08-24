#!/usr/bin/env sh
#
# The official svcdoctor OCI build recipe.
#
# This script *is* the recipe ADR 0062 section 15 refers to. "Reproducible under
# the official build recipe" is a claim about what this file does, so a release
# built any other way is not a release this project makes a reproducibility
# claim about.
#
# It builds. It never pushes, signs or tags a registry reference — publication
# is Phase 7.1-P and belongs in CI, where the identity constraints in ADR 0062
# section 16 can actually be enforced.
#
# Usage:
#   scripts/build-image.sh                 official build; HEAD must be a semver tag
#   scripts/build-image.sh --dev           development build; not reproducible, not official
#   scripts/build-image.sh --platform linux/arm64
#
# Environment:
#   OUT       output destination (default: an OCI layout tarball under ./dist)
#   IMAGE     image name for --dev --load (default: svcdoctor)
#   BUILDER   buildx builder name (default: the current one)

set -eu

MODE=official
PLATFORMS=linux/amd64,linux/arm64
IMAGE=${IMAGE:-svcdoctor}

while [ $# -gt 0 ]; do
  case $1 in
    --dev)      MODE=dev ;;
    --platform) PLATFORMS=$2; shift ;;
    -h|--help)  sed -n '2,25p' "$0"; exit 0 ;;
    *)          printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Version authority
# ---------------------------------------------------------------------------
#
# ADR 0062 section 12: the Git semver tag is the single public version
# authority, and the binary version, the OCI version label and the eventual OCI
# semver tag are all projections of it. That is only true if nothing here is
# hand-typed, so every value below is *derived* and there is no VERSION
# argument to pass.
#
# The refusals are the point. A release built from a tree that no commit
# contains, or from a commit no tag names, cannot honour the claim that a semver
# image traces to a semver tag — so it is refused rather than labelled
# optimistically.

REVISION=$(git rev-parse HEAD)

if [ "$MODE" = official ]; then
  if [ -n "$(git status --porcelain)" ]; then
    echo "refusing: the working tree is dirty." >&2
    echo "An official image must correspond to a commit, and this tree does not." >&2
    exit 1
  fi

  # --exact-match, so a commit that merely descends from a tag is refused
  # rather than silently inheriting that tag's version.
  VERSION=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
  if [ -z "$VERSION" ]; then
    echo "refusing: HEAD is not tagged." >&2
    echo "An official OCI semver image may not precede its Git tag (ADR 0062 section 13)." >&2
    echo "Tag the release commit first, or use --dev." >&2
    exit 1
  fi
  case $VERSION in
    v[0-9]*.[0-9]*.[0-9]*) ;;
    *) echo "refusing: '$VERSION' is not a vX.Y.Z tag." >&2; exit 1 ;;
  esac
else
  # A development build says so in its own version string. It deliberately does
  # not resemble a release, and the commit it came from is in the name so an
  # image found later can be traced back.
  DIRTY=$([ -n "$(git status --porcelain)" ] && echo .dirty || true)
  VERSION="0.0.0-dev+$(git rev-parse --short HEAD)${DIRTY}"
fi

# The registry tag for a development image, kept separate from the version
# string above. OCI tags may not contain '+', which semver build metadata uses,
# and ADR 0062 section 14 reserves the semver tag namespace for real releases —
# so a development image is addressed by its commit and never by a version
# number it could be mistaken for.
DEV_TAG="sha-$(git rev-parse --short HEAD)$([ -n "$(git status --porcelain)" ] && echo -dirty || true)"

# ---------------------------------------------------------------------------
# Deterministic timestamps
# ---------------------------------------------------------------------------
#
# Measured in Phase 7.1-R, on this repository, with buildx v0.25 / BuildKit
# v0.32:
#
#   rewrite-timestamp alone            NOT reproducible
#   SOURCE_DATE_EPOCH alone            NOT reproducible
#   both together                      platform image digests identical
#
# So both are required, and neither is a preference. The epoch is the *release
# commit's* committer timestamp — source identity, not wall-clock, not CI start
# time, not the tagger's clock — so the same commit yields the same epoch on
# every machine and in every year.
SOURCE_DATE_EPOCH=$(git show -s --format=%ct "$REVISION")
export SOURCE_DATE_EPOCH

mkdir -p dist
OUT=${OUT:-dist/svcdoctor-oci.tar}

set -- \
  --platform "$PLATFORMS" \
  --build-arg "VERSION=$VERSION" \
  --build-arg "REVISION=$REVISION" \
  --provenance=false \
  --sbom=false

# Attestations are deliberately off here and belong to the publishing pipeline.
# Phase 7.1-R measured why: with provenance and SBOM enabled the *platform image*
# digests still reproduce exactly, but the attestation manifests — and therefore
# the index that references them — do not. Generating them locally would make
# this script's output look non-reproducible for a reason that has nothing to do
# with the image (ADR 0062 section 16).

if [ "$MODE" = dev ] && [ "$PLATFORMS" = "${PLATFORMS%,*}" ]; then
  # Single-platform dev build: load it so it is immediately runnable.
  set -- "$@" --load -t "$IMAGE:$DEV_TAG"
else
  set -- "$@" --output "type=oci,dest=$OUT,rewrite-timestamp=true"
fi

[ -n "${BUILDER:-}" ] && set -- --builder "$BUILDER" "$@"

echo "mode:              $MODE"
echo "version:           $VERSION"
echo "revision:          $REVISION"
echo "SOURCE_DATE_EPOCH: $SOURCE_DATE_EPOCH"
echo "platforms:         $PLATFORMS"
[ "$MODE" = dev ] && echo "dev tag:           $IMAGE:$DEV_TAG"
echo

docker buildx build "$@" .

if [ "$MODE" = official ]; then
  echo
  echo "Built to $OUT. Nothing was pushed, signed or tagged in a registry."
fi
