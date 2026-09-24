#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Generate a machine-specific config into a gitignored file rather than
# overwriting the committed softhsm2.conf template. This keeps the working tree
# clean and prevents accidentally committing an absolute, machine-specific
# tokendir. The justfile and the integration test read this same file.
CONF="$SCRIPT_DIR/softhsm2.local.conf"
export SOFTHSM2_CONF="$CONF"
TOKEN_DIR="$SCRIPT_DIR/tokens"

# Resolve the SoftHSM2 PKCS#11 module path once. Distros disagree on the
# location (Debian/Ubuntu multiarch vs the generic /usr/lib path), so probe
# the same candidates the integration test (hsm_sign_verify.rs) uses. This
# keeps setup.sh working anywhere SoftHSM2 is installed, not just on one box.
MODULE=""
for candidate in \
    /usr/lib/softhsm/libsofthsm2.so \
    /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
    /usr/lib64/softhsm/libsofthsm2.so \
    /usr/local/lib/softhsm/libsofthsm2.so; do
    if [ -f "$candidate" ]; then
        MODULE="$candidate"
        break
    fi
done
if [ -z "$MODULE" ]; then
    echo "ERROR: SoftHSM2 PKCS#11 module (libsofthsm2.so) not found in any known location." >&2
    echo "       Install SoftHSM2 (e.g. 'apt install softhsm2') and re-run." >&2
    exit 1
fi
echo "Using SoftHSM2 module: $MODULE"

# Generate the SoftHSM2 config so tokendir always points at this checkout's
# token directory. SoftHSM2 does not expand environment variables in its config
# file and needs an absolute path, so we write the resolved path into the
# gitignored softhsm2.local.conf. This keeps the config in sync with the
# TOKEN_DIR that setup.sh creates/cleans below.
cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
EOF

# Clean up any previous tokens
rm -rf "$TOKEN_DIR"
mkdir -p "$TOKEN_DIR"

# Initialize token
softhsm2-util --init-token --slot 0 --label "ribergshamra-test" --pin 1234 --so-pin 5678

# Generate an RSA 2048 key pair
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "ribergshamra-test" \
    --keypairgen --key-type rsa:2048 --id 01 --label "test-rsa-key"

# Generate an EC P-256 key pair
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "ribergshamra-test" \
    --keypairgen --key-type EC:prime256v1 --id 02 --label "test-ec-key"

# Generate an EC P-384 key pair
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "ribergshamra-test" \
    --keypairgen --key-type EC:secp384r1 --id 03 --label "test-ec384-key"

# Generate Ed25519 key pair (if SoftHSM2 supports it)
if pkcs11-tool --module "$MODULE" --list-mechanisms 2>/dev/null | grep -q "EC-EDWARDS-KEY-PAIR-GEN"; then
    if pkcs11-tool --module "$MODULE" \
        --login --pin 1234 --token-label "ribergshamra-test" \
        --keypairgen --key-type EC:edwards25519 --id 04 --label "test-ed25519-key" 2>/dev/null; then
        echo "  Ed25519 key generated successfully"
    else
        echo "  WARNING: Ed25519 key generation failed (SoftHSM2 may not fully support it)"
    fi
else
    echo "  WARNING: SoftHSM2 does not support EdDSA key generation, skipping Ed25519"
fi

# Generate HMAC key (256-bit = 32 bytes generic secret)
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "ribergshamra-test" \
    --keygen --key-type GENERIC:32 --id 05 --label "test-hmac-key" \
    --usage-sign

# Generate AES-256 key
pkcs11-tool --module "$MODULE" \
    --login --pin 1234 --token-label "ribergshamra-test" \
    --keygen --key-type AES:32 --id 06 --label "test-aes-key"

echo ""
echo "SoftHSM2 test token initialized successfully"
echo "  Token: ribergshamra-test"
echo "  PIN: 1234"
echo "  RSA 2048 key:     test-rsa-key    (id 01)"
echo "  EC P-256 key:     test-ec-key     (id 02)"
echo "  EC P-384 key:     test-ec384-key  (id 03)"
echo "  Ed25519 key:      test-ed25519-key (id 04) -- if supported"
echo "  HMAC-256 key:     test-hmac-key   (id 05)"
echo "  AES-256 key:      test-aes-key    (id 06)"
