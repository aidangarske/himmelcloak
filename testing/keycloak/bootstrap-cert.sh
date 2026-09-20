#!/usr/bin/env bash
set -euo pipefail

CERT_DIR=$(cd "$(dirname "$0")" && pwd)/.generated
mkdir -p "$CERT_DIR"
chmod 700 "$CERT_DIR"
if [[ -f "$CERT_DIR/ca.pem" && -f "$CERT_DIR/server.crt" && -f "$CERT_DIR/server.key" ]] &&
   openssl x509 -in "$CERT_DIR/ca.pem" -noout -checkend 3600 >/dev/null 2>&1 &&
   openssl x509 -in "$CERT_DIR/server.crt" -noout -checkend 3600 >/dev/null 2>&1 &&
   [[ "$(openssl x509 -in "$CERT_DIR/server.crt" -noout -subject -nameopt RFC2253)" == 'subject=CN=keycloak.test' ]] &&
   openssl verify -CAfile "$CERT_DIR/ca.pem" "$CERT_DIR/server.crt" >/dev/null 2>&1 &&
   cmp -s <(openssl x509 -in "$CERT_DIR/server.crt" -pubkey -noout) \
          <(openssl pkey -in "$CERT_DIR/server.key" -pubout 2>/dev/null); then
    exit 0
fi

work_dir=$(mktemp -d "$CERT_DIR/.new.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=Himmelcloak test CA' \
    -keyout "$work_dir/ca.key" -out "$work_dir/ca.pem" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=keycloak.test' \
    -keyout "$work_dir/server.key" -out "$work_dir/server.csr" >/dev/null 2>&1
cat > "$work_dir/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
subjectAltName=DNS:keycloak.test,DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in "$work_dir/server.csr" \
    -CA "$work_dir/ca.pem" -CAkey "$work_dir/ca.key" -CAcreateserial \
    -days 2 -out "$work_dir/server.crt" -extfile "$work_dir/server.ext" >/dev/null 2>&1
# The non-root Keycloak container must read this disposable mounted key.
# The generated directory is private to the host user.
chmod 644 "$work_dir/server.key"
chmod 600 "$work_dir/ca.key"
mv "$work_dir"/{ca.key,ca.pem,server.key,server.crt,server.csr,server.ext} "$CERT_DIR/"
