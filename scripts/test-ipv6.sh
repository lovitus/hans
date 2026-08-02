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
ip link set "v6a$suffix" netns "$server_ns"
ip link set "v6b$suffix" netns "$client_ns"
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" -6 addr add 2001:db8:44::1/64 dev "v6a$suffix"
# Connect to a secondary address.  Linux raw ICMPv6 replies may use the first
# address as their source, so the authenticated client must safely adopt it.
ip -n "$server_ns" -6 addr add 2001:db8:44::9/64 dev "v6a$suffix" \
    preferred_lft 0
ip -n "$client_ns" -6 addr add 2001:db8:44::2/64 dev "v6b$suffix"
ip -n "$server_ns" -4 addr add 192.0.2.1/24 dev "v6a$suffix"
ip -n "$client_ns" -4 addr add 192.0.2.2/24 dev "v6b$suffix"
ip -n "$server_ns" link set "v6a$suffix" up
ip -n "$client_ns" link set "v6b$suffix" up

HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" "$BINABS" \
    -s 10.91.0.0 -p hans-ipv6-ci --require-v5 -f -v >"$work/server.log" 2>&1 &
server_pid=$!
sleep 1
# Keep the server's IPv4 raw socket continuously busy while the IPv6 client
# connects.  This catches event loops that service only the first ready ICMP
# family and starve ICMPv6 on noisy public hosts.
ip netns exec "$client_ns" ping -4 -f -q 192.0.2.1 >"$work/noise.log" 2>&1 &
noise_pid=$!
HANS_STATE_DIR="$work/client-state" ip netns exec "$client_ns" "$BINABS" \
    -c 2001:db8:44::9 -p hans-ipv6-ci --require-v5 -f -v \
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
ip netns exec "$client_ns" ping -c 5 -W 2 10.91.0.1
grep -q 'secure protocol v5 connection established to 2001:db8:44::2' \
    "$work/server.log"
grep -q 'authenticated server handshake moved from 2001:db8:44::9 to 2001:db8:44::1' \
    "$work/client.log"
HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" "$BINABS" \
    --list-peers --json | grep -q '"real_ip":"2001:db8:44::2"'

echo "OK: ICMPv6 outer transport with encrypted IPv4 tunnel passed"
