#!/usr/bin/env sh
#
# Install the two tools the Kubernetes validation gate needs, at pinned versions,
# with nothing floating and nothing unverified.
#
# ADR 0095 section 2.6 is the contract this implements:
#
#   kind    — a semantic version, installed through the Go module proxy, whose
#             integrity comes from the proxy and sum.golang.org rather than from
#             a checksum copied into this file. That is the same mechanism
#             release-oci.yml already uses for golangci-lint, and the same one
#             the Makefile's own "kind is not installed" message recommends.
#
#   kubectl — a semantic version AND an immutable digest. There is no Go module
#             to install it from, so the binary is downloaded and its SHA-256 is
#             compared against the constant below BEFORE it is placed anywhere.
#             A mismatch is fatal and installs nothing.
#
# The digest was obtained and verified in Phase 12.2B rather than copied from a
# document: the artifact was downloaded, its SHA-256 and SHA-512 were computed
# locally, and both were compared against the publisher's own .sha256 and .sha512
# files. Phase 12.2A deliberately refused to write a digest it could not check,
# for the reason ci.yml already records about golangci-lint-action.
#
# # Why the ambient kubectl is refused
#
# A GitHub-hosted runner image may ship a kubectl. Its version moves when the
# image is rebuilt, which makes it an unpinned input to a release gate in a
# repository where every other input is pinned. It is not used.
#
# # Scope
#
# linux/amd64 only, which is the platform every lane runs on. A checksum is
# per-platform, so supporting a second one means recording and verifying a second
# digest; this script fails closed rather than installing an unverified binary,
# and it is deliberately not a package manager. A developer on another platform
# installs kind the way the Makefile already tells them to and uses their own
# kubectl.
#
# # No tracing
#
# There is no `set -x` here and none may be added. This script handles no secret,
# but the gate it bootstraps handles kubeconfigs, ServiceAccount tokens and client
# keys, and tracing is a habit rather than a per-script decision.

set -eu

KIND_VERSION='v0.30.0'
KUBECTL_VERSION='v1.34.0'

# sha256 of https://dl.k8s.io/release/v1.34.0/bin/linux/amd64/kubectl
KUBECTL_SHA256='cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c'

die() {
	printf '%s\n' "$*" >&2
	exit 1
}

# --- platform ---------------------------------------------------------------

os="$(uname -s)"
arch="$(uname -m)"
[ "$os" = 'Linux' ] || die "install-kube-tools.sh supports Linux only (this is $os).
The digest below is per-platform, and installing an unverified binary instead is
the defect the digest exists to prevent. Install kind with
'go install sigs.k8s.io/kind@$KIND_VERSION' and use your own kubectl."
[ "$arch" = 'x86_64' ] || die "install-kube-tools.sh supports x86_64 only (this is $arch)."

command -v go >/dev/null 2>&1 || die 'go is not on PATH; set up Go before calling this script.'

bindir="$(go env GOPATH)/bin"
mkdir -p "$bindir"

# --- kind -------------------------------------------------------------------
#
# `go install pkg@version` ignores the current module, so this cannot alter
# go.mod or go.sum. The module count stays where dependency_test.go pins it.

printf 'installing kind %s\n' "$KIND_VERSION"
go install "sigs.k8s.io/kind@$KIND_VERSION"

# --- kubectl ----------------------------------------------------------------

printf 'installing kubectl %s\n' "$KUBECTL_VERSION"
tmp="$(mktemp -d)"
# shellcheck disable=SC2064 # $tmp is expanded now on purpose.
trap "rm -rf '$tmp'" EXIT INT TERM

url="https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl"
curl --fail --silent --show-error --location --max-time 300 --output "$tmp/kubectl" "$url" \
	|| die "downloading kubectl from $url failed"

actual="$(sha256sum "$tmp/kubectl" | cut -d' ' -f1)"
if [ "$actual" != "$KUBECTL_SHA256" ]; then
	die "kubectl checksum mismatch — refusing to install.
  want $KUBECTL_SHA256
  got  $actual
This is either a corrupted download or a changed artifact. Do not 'fix' it by
updating the constant: verify the new digest against the publisher first."
fi
printf 'kubectl sha256 verified: %s\n' "$actual"

chmod 0755 "$tmp/kubectl"
mv "$tmp/kubectl" "$bindir/kubectl"

# --- reachability -----------------------------------------------------------
#
# Under Actions the directory has to be on PATH for every later step, and
# GITHUB_PATH is the only mechanism that survives the step boundary. Outside
# Actions the script says where the binaries went rather than editing a profile.

if [ -n "${GITHUB_PATH:-}" ]; then
	printf '%s\n' "$bindir" >>"$GITHUB_PATH"
else
	printf 'installed into %s — add it to PATH if it is not already there\n' "$bindir"
fi

PATH="$bindir:$PATH"
export PATH

# --- fail closed on a wrong version -----------------------------------------
#
# Verifying the digest proves the bytes; running the binary proves the pin
# actually took effect and that no earlier copy shadows it.

kind_got="$(kind version 2>/dev/null | awk '{print $2}')"
[ "$kind_got" = "$KIND_VERSION" ] \
	|| die "kind reports '$kind_got', want $KIND_VERSION (is another kind earlier on PATH?)"

kubectl_got="$(kubectl version --client 2>/dev/null | awk '/Client Version/ {print $NF}')"
[ "$kubectl_got" = "$KUBECTL_VERSION" ] \
	|| die "kubectl reports '$kubectl_got', want $KUBECTL_VERSION"

printf 'kind %s and kubectl %s are installed in %s\n' "$kind_got" "$kubectl_got" "$bindir"
