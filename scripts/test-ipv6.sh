#!/bin/sh

set -eu

BIN="${1:-./hans}"
BINABS="$(readlink -f "$BIN")"
suffix="$(printf '%s' "$$" | tail -c 6)"
server_ns="hans-v6-server-$suffix"
client_ns="hans-v6-client-$suffix"
work="/tmp/hans-v6-$suffix"

cleanup() {
    kill "${client_pid:-}" "${noise_pid:-}" "${server_pid:-}" 2>/dev/null || true
    ip netns delete "$client_ns" 2>/dev/null || true
    ip netns delete "$server_ns" 2>/dev/null || true
}
diagnostics() {
    status=$?
    if [ "$status" -ne 0 ]; then
        cat "$work/server.log" "$work/client.log" >&2 2>/dev/null || true
    fi
    cleanup
    exit "$status"
}
trap diagnostics EXIT INT TERM

mkdir -p "$work/server-state" "$work/client-state"
ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "v6a$suffix" type veth peer name "v6b$suffix"
ip link add "v4a$suffix" type veth peer name "v4b$suffix"
ip link set "v6a$suffix" netns "$server_ns"
ip link set "v6b$suffix" netns "$client_ns"
ip link set "v4a$suffix" netns "$server_ns"
ip link set "v4b$suffix" netns "$client_ns"
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" -6 addr add fd44:4841:4e53::1/64 dev "v6a$suffix"
# Connect to a secondary address.  Linux raw ICMPv6 replies may use the first
# address as their source, so the authenticated client must safely adopt it.
ip -n "$server_ns" -6 addr add fd44:4841:4e53::9/64 dev "v6a$suffix" \
    preferred_lft 0
ip -n "$client_ns" -6 addr add fd44:4841:4e53::2/64 dev "v6b$suffix"
ip -n "$server_ns" -4 addr add 192.0.2.1/24 dev "v4a$suffix"
ip -n "$client_ns" -4 addr add 192.0.2.2/24 dev "v4b$suffix"
ip -n "$server_ns" link set "v6a$suffix" up
ip -n "$client_ns" link set "v6b$suffix" up
ip -n "$server_ns" link set "v4a$suffix" up
ip -n "$client_ns" link set "v4b$suffix" up

HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" "$BINABS" \
    -s 10.91.0.0 -p hans-ipv6-ci --require-v5 -f -v >"$work/server.log" 2>&1 &
server_pid=$!
sleep 1
# Keep the server's IPv4 raw socket continuously busy while the IPv6 client
# connects.  A separate veth keeps the flood from congesting the IPv6 link:
# the assertion is about event-loop fairness between raw sockets, not about
# delivering data through an intentionally saturated shared interface.
ip netns exec "$client_ns" ping -4 -i 0.01 -q 192.0.2.1 \
    >"$work/noise.log" 2>&1 &
noise_pid=$!
HANS_STATE_DIR="$work/client-state" ip netns exec "$client_ns" "$BINABS" \
    -c fd44:4841:4e53::9 -p hans-ipv6-ci --require-v5 -f -v \
    >"$work/client.log" 2>&1 &
client_pid=$!

attempt=40
while [ "$attempt" -gt 0 ]; do
    ip -n "$client_ns" -4 addr show | grep -q '10.91.0.100/24' && break
    kill -0 "$server_pid"
    kill -0 "$client_pid"
    sleep 0.25
    attempt=$((attempt - 1))
done
ip -n "$client_ns" -4 addr show | grep -q '10.91.0.100/24'
# Address assignment precedes the adaptive direct-reply probe.  Do not make
# the data-plane assertion while that probe can still switch modes: a
# namespace/veth path may accept the probe burst and then reject sustained
# direct replies, in which case Hans deliberately falls back after its first
# transport heartbeat.  Waiting here tests the settled direct or credit mode
# instead of treating the designed transition as IPv6 packet loss.
attempt=40
while [ "$attempt" -gt 0 ]; do
    grep -q -e 'direct reply mode enabled' \
        -e 'keeping adaptive poll credits' "$work/client.log" && break
    kill -0 "$server_pid"
    kill -0 "$client_pid"
    sleep 0.25
    attempt=$((attempt - 1))
done
# A successful direct probe can still settle back to credit mode after its
# first heartbeat.  A failed probe is already in its final credit mode and
# should be exercised immediately, before the initial credits grow stale.
if grep -q 'direct reply mode enabled' "$work/client.log"; then
    sleep 6
fi
ip netns exec "$client_ns" ping -c 5 -W 2 10.91.0.1
grep -q 'secure protocol v5 connection established to fd44:4841:4e53::2' \
    "$work/server.log"
grep -q 'authenticated server handshake moved from fd44:4841:4e53::9 to fd44:4841:4e53::1' \
    "$work/client.log"
HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" "$BINABS" \
    --list-peers --json | grep -q '"real_ip":"fd44:4841:4e53::2"'

echo "OK: ICMPv6 outer transport with encrypted IPv4 tunnel passed"
