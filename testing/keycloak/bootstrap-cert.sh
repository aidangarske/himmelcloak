#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=$(cd "$(dirname "$0")" && pwd)/.generated
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"
if [[ -f "$CERT_DIR/ca.pem" && -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]] &&
   openssl x509 -in "$CERT_DIR/ca.pem" -noout -checkend 3600 >/dev/null 2>&1 &&
   openssl x509 -in "$CERT_DIR/server.crt" -noout -checkend 3600 >/dev/null 2>&1 &&
   [[ "$(openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -nameopt RFC2253)" == 'subject=CN=keycloak.test' ]]; then
    exit 0
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=Himmelcloak test CA' \
    -keyout "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=keycloak.test' \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" >/dev/null 2>&1
cat > "$CERT_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:keycloak.test,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.pem" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -days 2 -out "$CERT_DIR/server.crt" -extfile "$CERT_DIR/server.ext" >/dev/null 2>&1
# The non-root Keycloak container must read this disposable mounted key.
# The generated directory is private to the host user.
chmod 644 "$CERT_DIR/server.key"
chmod 600 "$CERT_DIR/ca.key"
