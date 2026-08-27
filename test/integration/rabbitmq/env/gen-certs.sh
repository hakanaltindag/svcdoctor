#!/usr/bin/env bash
# Generates throwaway TLS material for the RabbitMQ validation brokers.
#
# Two certificates, because two scenarios have to disagree with each other:
#
#   server.crt  CN=rabbit.svcdoctor.test, SANs for the name and both loopback
#               addresses. RAB-01 and RAB-02 verify against it; RAB-09 fails to,
#               by asking for a --tls-server-name the SAN set does not contain.
#   rogue.crt   a second self-signed certificate nothing trusts. RAB-08 offers it
#               as the trust source, which makes the unknown-authority failure a
#               real chain failure rather than a missing file.
#
# Nothing here is ever committed: the directory is gitignored and the material is
# regenerated whenever it is absent. A repository that ships a private key
# teaches the wrong habit even when the key is worthless.
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
    -subj "/CN=rabbit.svcdoctor.test" \
    -addext "subjectAltName=DNS:rabbit.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null
fi

if stale certs/rogue.crt; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout certs/rogue.key -out certs/rogue.crt \
    -subj "/CN=rogue.svcdoctor.test" \
    -addext "subjectAltName=DNS:rogue.svcdoctor.test" 2>/dev/null
fi

# RabbitMQ reads its key as the `rabbitmq` user inside the container. The key is
# worthless and regenerated, so a world-readable mode is the simplest thing that
# works across every image in the matrix.
chmod 0644 certs/server.crt certs/server.key certs/rogue.crt certs/rogue.key
