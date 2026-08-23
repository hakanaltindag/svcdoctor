#!/usr/bin/env bash
# Generates a throwaway CA and broker certificate for the Redpanda validation
# instance. Everything here is test-only and regenerated on demand; nothing is
# committed.
#
# The SANs carry the name and both loopback addresses, so the suite can verify a
# hostname target and an address literal against real SANs rather than against a
# certificate that happens to match.
set -euo pipefail
# `mkdir -p` before `cd`: certs/ is generated and therefore untracked, so on a
# fresh clone it does not exist. The Kafka fixture failed exactly this way until
# Phase 7.0b.
cd "$(dirname "$0")"
mkdir -p certs
cd certs
rm -f ./*.pem ./*.srl ./*.cnf

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -subj "/CN=svcdoctor-redpanda-validation-ca" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr \
  -subj "/CN=redpanda.svcdoctor.test" 2>/dev/null

printf 'subjectAltName=DNS:redpanda.svcdoctor.test,DNS:localhost,IP:127.0.0.1,IP:::1\n' > san.cnf
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial \
  -out server-cert.pem -days 3650 -sha256 -extfile san.cnf 2>/dev/null

# Redpanda runs as a non-root user in the image and reads these read-only.
chmod 644 ./*.pem
rm -f server.csr

printf 'redpanda validation certificates generated\n'
