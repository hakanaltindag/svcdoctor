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
if [ -f certs/server.crt ] && [ -f certs/server.key ]; then exit 0; fi
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=pg.svcdoctor.test" \
  -addext "subjectAltName=DNS:pg.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null
# PostgreSQL refuses a group- or world-readable key, and the container runs as
# the postgres user, so the file must be owned by uid 999 inside it.
chmod 600 certs/server.key
