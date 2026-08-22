#!/usr/bin/env bash
# Generates a throwaway CA and broker certificates for Phase 3 validation.
# Everything here is test-only and regenerated on demand; nothing is committed.
set -euo pipefail
cd "$(dirname "$0")/certs"
rm -f ./*.pem ./*.p12 ./*.srl ./*.cnf

PASS=svcdoctor-test

# --- CA -------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout ca-key.pem -out ca-cert.pem \
  -subj "/CN=svcdoctor-validation-ca" 2>/dev/null

# --- issue(name, san) -----------------------------------------------------
issue() {
  local name="$1" san="$2"
  cat > "$name.cnf" <<CNF
[req]
distinguished_name=dn
[dn]
[ext]
subjectAltName=$san
extendedKeyUsage=serverAuth
CNF
  openssl req -newkey rsa:2048 -nodes -keyout "$name-key.pem" \
    -out "$name.csr" -subj "/CN=$name" 2>/dev/null
  openssl x509 -req -in "$name.csr" -CA ca-cert.pem -CAkey ca-key.pem \
    -CAcreateserial -out "$name-cert.pem" -days 3650 -sha256 \
    -extfile "$name.cnf" -extensions ext 2>/dev/null
  openssl pkcs12 -export -in "$name-cert.pem" -inkey "$name-key.pem" \
    -certfile ca-cert.pem -out "$name.p12" -name "$name" -passout "pass:$PASS" 2>/dev/null
  rm -f "$name.csr" "$name.cnf"
}

# The broker certificate a healthy run verifies against.
issue broker "DNS:localhost,DNS:broker-1,DNS:broker-2,DNS:broker-3,IP:127.0.0.1"

# A certificate for the SAN-mismatch scenario: valid chain, wrong name.
issue wrongname "DNS:not-the-broker.invalid"

# A second CA the client will not trust, for the untrusted-issuer scenario.
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout rogue-ca-key.pem -out rogue-ca-cert.pem \
  -subj "/CN=svcdoctor-rogue-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout rogue-key.pem -out rogue.csr \
  -subj "/CN=rogue" 2>/dev/null
cat > rogue.cnf <<CNF
[ext]
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
CNF
openssl x509 -req -in rogue.csr -CA rogue-ca-cert.pem -CAkey rogue-ca-key.pem \
  -CAcreateserial -out rogue-cert.pem -days 3650 -sha256 \
  -extfile rogue.cnf -extensions ext 2>/dev/null
openssl pkcs12 -export -in rogue-cert.pem -inkey rogue-key.pem \
  -certfile rogue-ca-cert.pem -out rogue.p12 -name rogue -passout "pass:$PASS" 2>/dev/null
rm -f rogue.csr rogue.cnf

# Truststore holding only the real CA, for the brokers themselves.
openssl pkcs12 -export -nokeys -in ca-cert.pem -out truststore.p12 \
  -name ca -passout "pass:$PASS" 2>/dev/null

chmod 644 ./*.p12 ./*.pem
echo "generated: $(ls *.p12 | tr '\n' ' ')"
