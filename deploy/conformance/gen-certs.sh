#!/usr/bin/env bash
# Generate the self-signed TLS material the conformance harness needs:
#   certs/as.crt, certs/as.key  — the AS server cert (SAN: as, localhost)
#   certs/truststore.p12        — PKCS12 truststore holding the CA, mounted
#                                 into the suite server so it trusts the AS.
# FAPI mandates TLS; this lets the suite call https://as:8443 in-network.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CERTS="$HERE/certs"
STOREPASS="${TRUSTSTORE_PASS:-changeit}"
rm -rf "$CERTS"
mkdir -p "$CERTS"
cd "$CERTS"

# CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 3650 \
  -subj "/CN=fapi2-conformance-ca"

# AS server cert signed by the CA, valid for the in-network name `as`.
openssl req -newkey rsa:2048 -nodes -keyout as.key -out as.csr -subj "/CN=as"
openssl x509 -req -in as.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out as.crt -days 3650 \
  -extfile <(printf "subjectAltName=DNS:as,DNS:localhost,IP:127.0.0.1")

# CA-only PKCS12 truststore for the suite JVM (it only calls the AS in this
# closed setup, so trusting just our CA is sufficient).
keytool -importcert -noprompt -alias fapi2-conformance-ca -file ca.crt \
  -keystore truststore.p12 -storetype PKCS12 -storepass "$STOREPASS"

# The suite/AS containers run as unprivileged users (test-only material).
chmod 644 as.key as.crt truststore.p12
echo "[gen-certs] wrote as.crt / as.key / truststore.p12 to $CERTS"
