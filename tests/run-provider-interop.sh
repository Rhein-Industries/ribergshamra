#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "$#" -ne 0 ]]; then
    echo "usage: run-provider-interop.sh" >&2
    exit 2
fi

dsig_expected='--- TOTAL OK: 446; OK (percent): 99; TOTAL FAILED: 0; TOTAL SKIPPED: 3'
enc_expected='--- TOTAL OK: 701; OK (percent): 100; TOTAL FAILED: 0; TOTAL SKIPPED: 0'

# Historical XMLSEC RSA-decryption compatibility needs the explicitly opted-in
# RustCrypto path. Default-policy refusal is covered by the library regressions.
# This gate is interoperability evidence, not timing-safety approval.
cargo build --locked --release --features legacy-rsa-decryption
export RIBERGSHAMRA="$root/target/release/ribergshamra"

run_suite() {
    local suite="$1"
    local expected="$2"
    local output
    output="$(mktemp)"

    set +e
    # The upstream harness advertises future-CRL acceptance for its OpenSSL
    # profile. Our authenticated-current-CRL policy intentionally rejects it.
    # Source the unchanged harness after disabling that one advertised option;
    # the negative/currentness regression is tested in the library separately.
    bash -c 'source <(sed "s/xmlsec_feature_crl_check_skip_time=\"yes\"/xmlsec_feature_crl_check_skip_time=\"no\"/" "$1") "${@:2}"' \
        _ "$root/test-data/testrun.sh" "$root/test-data/$suite" openssl "$root/test-data" \
        "$root/tests/xmlsec1-shim.py" pem 2>&1 | tee "$output"
    local status="${PIPESTATUS[0]}"
    set -e

    local actual
    actual="$(grep -- '--- TOTAL OK:' "$output" | tail -n 1 || true)"
    if [[ "$actual" != "$expected" ]]; then
        echo "Unexpected legacy-opt-in RustCrypto $suite totals" >&2
        echo "expected: $expected" >&2
        echo "actual:   ${actual:-<missing>}" >&2
        echo "harness status: $status" >&2
        exit 1
    fi
    if [[ "$status" -ne 0 ]]; then
        echo "Legacy-opt-in RustCrypto $suite unexpectedly returned $status" >&2
        exit 1
    fi
}

run_suite testDSig.sh "$dsig_expected"
run_suite testEnc.sh "$enc_expected"
