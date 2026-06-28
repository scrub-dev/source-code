#!/usr/bin/env bash
# Generate a SCRUB interception CA and install its certificate into the OS trust
# store, so clients accept the per-host certificates SCRUB mints.
#
# Usage: scripts/setup-ca.sh [dir]      (default dir: ./ca)
#
# Produces <dir>/ca.pem (cert) and <dir>/ca.key (private key — KEEP SECRET).
# Re-running reuses an existing CA and just (re)installs trust.
set -euo pipefail

DIR="${1:-ca}"
CERT="$DIR/ca.pem"
KEY="$DIR/ca.key"

mkdir -p "$DIR"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
  echo ">> reusing existing CA: $CERT"
else
  echo ">> generating CA at $CERT"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY" -out "$CERT" -days 3650 -nodes -subj "/CN=SCRUB CA"
  chmod 600 "$KEY"
fi

echo ">> installing CA into the OS trust store (may prompt for sudo)"
case "$(uname -s)" in
  Darwin)
    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "$CERT"
    ;;
  Linux)
    if command -v update-ca-certificates >/dev/null 2>&1; then
      sudo cp "$CERT" /usr/local/share/ca-certificates/scrub-ca.crt
      sudo update-ca-certificates
    elif command -v update-ca-trust >/dev/null 2>&1; then
      sudo cp "$CERT" /etc/pki/ca-trust/source/anchors/scrub-ca.pem
      sudo update-ca-trust
    else
      echo "!! unknown Linux trust store — install $CERT manually"
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "!! Windows: run in an elevated prompt:  certutil -addstore -f ROOT \"$CERT\""
    ;;
  *)
    echo "!! unknown OS — install $CERT into your trust store manually"
    ;;
esac

cat <<EOF

CA ready.
  cert: $CERT   -> intercept.ca_cert_path
  key:  $KEY    -> intercept.ca_key_path   (keep this secret!)

Note: Firefox, Java, and some apps use their own trust store — import $CERT there too.
Next:
  scrub --config examples/proxy.yaml
  export HTTPS_PROXY=http://127.0.0.1:8443 HTTP_PROXY=http://127.0.0.1:8443
EOF
