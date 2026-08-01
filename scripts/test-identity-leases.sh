#!/bin/sh

set -eu

BIN="${1:-./hans}"
case "$BIN" in
    /*) : ;;
    *) BIN="$(pwd)/$BIN" ;;
esac

TMPDIR_HANS="$(mktemp -d 2>/dev/null || echo /tmp/hans_identity_test_$$)"
cleanup() {
    rm -rf "$TMPDIR_HANS"
}
trap cleanup EXIT INT TERM

ID1="$(HANS_STATE_DIR="$TMPDIR_HANS" "$BIN" --show-device-id)"
ID2="$(HANS_STATE_DIR="$TMPDIR_HANS" "$BIN" --show-device-id)"

if [ "$ID1" != "$ID2" ]; then
    echo "FAIL: generated device id was not persistent"
    exit 1
fi

if ! echo "$ID1" | grep -Eq '^[0-9a-f]{32}$'; then
    echo "FAIL: generated device id is not 32 lowercase hex characters"
    exit 1
fi

NORMALIZED="$("$BIN" --show-device-id --device-id ABCDEF0123456789ABCDEF0123456789)"
if [ "$NORMALIZED" != "abcdef0123456789abcdef0123456789" ]; then
    echo "FAIL: explicit device id was not normalized"
    exit 1
fi

if "$BIN" --show-device-id --device-id invalid >/dev/null 2>&1; then
    echo "FAIL: invalid explicit device id was accepted"
    exit 1
fi

KEY1="$(HANS_STATE_DIR="$TMPDIR_HANS" "$BIN" --show-identity)"
KEY2="$(HANS_STATE_DIR="$TMPDIR_HANS" "$BIN" --show-identity)"
if [ "$KEY1" != "$KEY2" ] ||
   ! echo "$KEY1" | grep -Eq '^[0-9a-f]{32}$'; then
    echo "FAIL: secure identity fingerprint was not stable lowercase hex"
    exit 1
fi
if [ "$(wc -c <"$TMPDIR_HANS/identity.key" | tr -d ' ')" != "32" ]; then
    echo "FAIL: secure identity key has the wrong size"
    exit 1
fi
if command -v stat >/dev/null 2>&1; then
    key_mode="$(stat -c '%a' "$TMPDIR_HANS/identity.key" 2>/dev/null ||
                stat -f '%Lp' "$TMPDIR_HANS/identity.key" 2>/dev/null || true)"
    if [ -n "$key_mode" ] && [ "$key_mode" != "600" ]; then
        echo "FAIL: secure identity key mode is $key_mode, expected 600"
        exit 1
    fi
fi

if "$BIN" -c 127.0.0.1 -p test -f --require-v4 \
   --server-fingerprint invalid >/dev/null 2>&1; then
    echo "FAIL: invalid pinned server fingerprint was accepted"
    exit 1
fi

LEASE_FILE="$TMPDIR_HANS/leases"
echo "$ID1 167772260 1785484800 1 3405803796" >"$LEASE_FILE"
PEERS="$("$BIN" --list-peers --lease-file "$LEASE_FILE")"
PEERS_JSON="$("$BIN" --list-peers --json --lease-file "$LEASE_FILE")"

if ! echo "$PEERS" | grep -q "$ID1"; then
    echo "FAIL: peer list omitted device id"
    exit 1
fi
if ! echo "$PEERS" | grep -q "10.0.0.100"; then
    echo "FAIL: peer list did not format tunnel ip"
    exit 1
fi
if ! echo "$PEERS" | grep -q "online"; then
    echo "FAIL: peer list omitted active state"
    exit 1
fi
if ! echo "$PEERS_JSON" | grep -q "\"device_id\":\"$ID1\"" ||
   ! echo "$PEERS_JSON" | grep -q '"online":true'; then
    echo "FAIL: JSON peer list omitted expected fields"
    exit 1
fi

echo "OK: persistent identities, private key permissions, and peer-list checks passed"
