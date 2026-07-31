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

LEASE_FILE="$TMPDIR_HANS/leases"
echo "$ID1 167772260 1785484800 1 3405803796" >"$LEASE_FILE"
PEERS="$("$BIN" --list-peers --lease-file "$LEASE_FILE")"

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

echo "OK: persistent device id and peer-list checks passed"
