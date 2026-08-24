#!/usr/bin/env bash
# Generates a throwaway server certificate for the Valkey validation servers.
#
# Two certificates, because two scenarios need to disagree with each other:
#
#   server.crt  CN=valkey.svcdoctor.test, SANs for the name and both loopback
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

if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout certs/server.key -out certs/server.crt \
    -subj "/CN=valkey.svcdoctor.test" \
    -addext "subjectAltName=DNS:valkey.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1" 2>/dev/null
fi

if [ ! -f certs/rogue.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout certs/rogue.key -out certs/rogue.crt \
    -subj "/CN=rogue.svcdoctor.test" \
    -addext "subjectAltName=DNS:rogue.svcdoctor.test" 2>/dev/null
fi

# Valkey reads its key as the container user. Unlike PostgreSQL it does not
# refuse a group-readable key, so this is a plain permission fix rather than the
# ownership dance the PostgreSQL fixture documents.
chmod 0644 certs/server.crt certs/server.key certs/rogue.crt certs/rogue.key
