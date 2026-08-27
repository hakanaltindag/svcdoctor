#!/usr/bin/env bash
# Generates a throwaway server certificate for the Redis validation servers.
#
# Two certificates, because two scenarios need to disagree with each other:
#
#   server.crt  CN=redis.svcdoctor.test, SANs for the name and both loopback
#               addresses. R-08 verifies against it and R-10 fails to.
#   rogue.crt   a second self-signed certificate nothing trusts, which is what
#               makes R-09's unknown-authority failure a real chain failure
#               rather than a configuration typo.
#
# Nothing here is ever committed: the directory is gitignored and the material is
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
    -subj "/CN=redis.svcdoctor.test" \
    -addext "subjectAltName=DNS:redis.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null
fi

if stale certs/rogue.crt; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout certs/rogue.key -out certs/rogue.crt \
    -subj "/CN=rogue.svcdoctor.test" \
    -addext "subjectAltName=DNS:rogue.svcdoctor.test" 2>/dev/null
fi

# Redis reads its key as the container user. Unlike PostgreSQL it does not
# refuse a group-readable key, so this is a plain permission fix rather than the
# ownership dance the PostgreSQL fixture documents.
chmod 0644 certs/server.crt certs/server.key certs/rogue.crt certs/rogue.key
