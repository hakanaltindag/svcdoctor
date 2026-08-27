#!/usr/bin/env bash
# Generates a throwaway server certificate for the PostgreSQL validation server.
#
# The SANs carry a name and both loopback addresses on purpose. Phase 6.7 made
# address literals first-class targets, and verifying one against a real IP SAN
# is not something a fixture can fake: `IP:127.0.0.1` and `IP:::1` are what let
# the suite measure that a bare address verifies, in both families, against a
# real server.
#
# Nothing here is ever committed: the directory is gitignored and the key is
# regenerated on every run. A repository that ships a private key teaches the
# wrong habit even when the key is worthless.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs

# stale reports whether a certificate is missing, unreadable, or expires within
# the next hour.
#
# **Absence is not the only reason to regenerate**, and assuming it was is a real
# defect this fixture shipped with: these certificates last two days, the script
# only rebuilt them when the file was gone, and so the suite began failing with
# TLS_CERTIFICATE_EXPIRED exactly two days after anyone first ran it — on a
# machine where everything looked present and correct. Checking expiry is what
# makes the fixture reproducible on the third day.
stale() {
  [ -f "$1" ] || return 0
  # Only a certificate has an expiry. Running the x509 check on a private key
  # fails for the wrong reason and would report every key as stale, which
  # regenerates material that was perfectly good.
  case "$1" in
    *.crt|*.pem) ;;
    *) return 1 ;;
  esac
  openssl x509 -checkend 3600 -noout -in "$1" >/dev/null 2>&1 || return 0
  return 1
}

if stale certs/server.crt || stale certs/server.key; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/CN=pg.svcdoctor.test" \
    -addext "subjectAltName=DNS:pg.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null
fi

# ---------------------------------------------------------------------------
# Ownership, and why this is not a `chmod`
# ---------------------------------------------------------------------------
#
# PostgreSQL will not start if it dislikes its TLS private key, and there are
# three separate ways to be disliked. Two are PostgreSQL's own checks; the third
# is the operating system, which is easy to forget because PostgreSQL reports it
# with a different message. Measured against `postgres:18` on a Linux-native
# filesystem, where `postgres` is uid 999:
#
#   owner              mode   result
#   1001:1001 (host)   0600   FATAL: must be owned by the database user or root
#   999:999            0600   starts
#   999:999            0400   starts
#   999:999            0640   FATAL: has group or world access
#   999:999            0644   FATAL: has group or world access
#   0:0    (root)      0600   FATAL: could not load ...: Permission denied
#   0:0    (root)      0640   FATAL: could not load ...: Permission denied
#   0:999              0640   starts
#   0:999              0600   FATAL: could not load ...: Permission denied
#
# So: the owner must be the database user or root; a key owned by the database
# user may carry no group or world bits at all; and the server process — which
# runs as `postgres`, not as root — has to be able to actually open the file.
# Root ownership passes both of PostgreSQL's checks and then fails at `open()`
# unless the group is `postgres` and group-read is set. Only one configuration
# is both minimal and correct, and it is the one below: owned by the database
# user, mode 0600.
#
# `chmod 600` alone answers the mode question and says nothing about ownership.
# That is exactly what this script used to do, and the comment above the chmod
# even described the ownership requirement it did not implement.
#
# ---------------------------------------------------------------------------
# Why every developer machine hid it
# ---------------------------------------------------------------------------
#
# Not because macOS is lax in general, but because of the specific values its
# bind mounts report. Measured on Docker Desktop, with a host key owned by the
# developer (501) and never chowned — the exact pre-fix state:
#
#   host view:       uid=501 gid=0  mode=600
#   container view:  uid=0   gid=0  mode=600      <- reported as root
#   result:          starts
#
# The mount layer reports the file as root-owned and grants the read anyway, so
# PostgreSQL's ownership check is satisfied by a value the host never had and
# its `open()` succeeds regardless. Both checks pass vacuously. On Linux the
# host uid passes through unchanged — the CI runner's 1001 — and the first check
# refuses it. The fixture therefore passed everywhere it was run and failed on
# every Linux runner, which is how it reached a release tag.
#
# That asymmetry is also why the guard in ../fixture_test.go refuses a
# root-owned key rather than accepting it as PostgreSQL nominally would: `0:0`
# is precisely the spelling macOS invents for the broken state, so a guard that
# allows it cannot catch this defect on the machine where it needs catching.
#
# ---------------------------------------------------------------------------
#
# The identity is read from the image rather than hard-coded, so a future
# postgres image that renumbers its user does not silently reintroduce this.
# `postgres:18` is a floating tag and may be rebuilt at any time. The work
# happens in that same image — already required by the fixture, so this adds no
# dependency and needs no host `sudo`.
#
# This runs unconditionally, including when the certificates already existed:
# a `certs/` directory left from an earlier run carries the old ownership, and
# skipping normalization would leave exactly the broken state we are fixing.
PG_IMAGE="$(awk '/^[[:space:]]*image:[[:space:]]*/ {print $2; exit}' compose.yaml)"
if [ -z "${PG_IMAGE}" ]; then
  echo "gen-certs: could not read the postgres image from compose.yaml" >&2
  exit 1
fi

docker run --rm --user 0:0 -v "$PWD/certs:/certs" "${PG_IMAGE}" sh -c '
  set -eu
  chown "$(id -u postgres):$(id -g postgres)" /certs/server.key /certs/server.crt
  chmod 600 /certs/server.key
  chmod 644 /certs/server.crt
'
