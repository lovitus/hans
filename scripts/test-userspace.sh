#!/bin/sh
# Privileged Linux end-to-end test for an unprivileged userspace client.

set -eu

BIN="${1:-./hans}"
BINABS=$(readlink -f "$BIN")
suffix=$(printf '%s' "$$" | tail -c 6)
server_ns="hans-us-server-$suffix"
client_ns="hans-us-client-$suffix"
server_if="husa$suffix"
client_if="husb$suffix"
work="/tmp/hans-userspace-$suffix"
server_log="$work/server.log"
client_log="$work/client.log"

cleanup() {
    kill "${client_pid:-}" "${server_pid:-}" "${server_http_pid:-}" \
         "${client2_pid:-}" "${client_http_pid:-}" "${allports_http_pid:-}" \
         "${large_sink_pid:-}" "${udp_pid:-}" 2>/dev/null || true
    ip netns delete "$client_ns" 2>/dev/null || true
    ip netns delete "$server_ns" 2>/dev/null || true
}

diagnostics() {
    status=$?
    if [ "$status" -ne 0 ]; then
        echo "userspace server log:" >&2
        cat "$server_log" >&2 2>/dev/null || true
        echo "userspace client log:" >&2
        cat "$client_log" >&2 2>/dev/null || true
        echo "second same-NAT userspace client log:" >&2
        cat "$work/client2.log" >&2 2>/dev/null || true
    fi
    cleanup
    exit "$status"
}
trap diagnostics EXIT INT TERM

mkdir -p "$work/client-state" "$work/client2-state" "$work/server-state"
chmod 777 "$work/client-state"
chmod 777 "$work/client2-state"
printf '%s\n' 'userspace-secret' >"$work/socks-password"
chmod 600 "$work/socks-password"
chown 65534:65534 "$work/socks-password"

ip netns add "$server_ns"
ip netns add "$client_ns"
ip link add "$server_if" type veth peer name "$client_if"
ip link set "$server_if" netns "$server_ns"
ip link set "$client_if" netns "$client_ns"
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$server_ns" addr add 192.0.2.1/24 dev "$server_if"
ip -n "$client_ns" addr add 192.0.2.2/24 dev "$client_if"
ip -n "$server_ns" link set "$server_if" up
ip -n "$client_ns" link set "$client_if" up
ip netns exec "$client_ns" sysctl -q -w net.ipv4.ping_group_range="0 2147483647"

HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" "$BINABS" \
    -s 10.77.88.0 -p hans-userspace-ci -f -v >"$server_log" 2>&1 &
server_pid=$!

# The stripped product is intentionally tested without net-tools.  Older Hans
# releases used /sbin/ifconfig and log a non-fatal error when it is absent, so
# the namespace fixture supplies the server address with the iproute2 tool it
# already needs to construct the isolated network.
server_ready=0
attempt=40
while [ "$attempt" -gt 0 ]; do
    if ip -n "$server_ns" link show hans1 >/dev/null 2>&1; then
        ip -n "$server_ns" addr replace 10.77.88.1/24 dev hans1
        ip -n "$server_ns" link set hans1 up
        server_ready=1
        break
    fi
    kill -0 "$server_pid"
    sleep 0.25
    attempt=$((attempt - 1))
done
[ "$server_ready" -eq 1 ]

ip netns exec "$server_ns" python3 -m http.server 18080 \
    --bind 10.77.88.1 --directory "$(dirname "$BINABS")" >"$work/server-http.log" 2>&1 &
server_http_pid=$!
ip netns exec "$client_ns" python3 -m http.server 18081 \
    --bind 127.0.0.1 --directory "$(dirname "$BINABS")" >"$work/client-http.log" 2>&1 &
client_http_pid=$!
ip netns exec "$client_ns" python3 -m http.server 18086 \
    --bind 127.0.0.1 --directory "$(dirname "$BINABS")" >"$work/allports-http.log" 2>&1 &
allports_http_pid=$!
ip netns exec "$client_ns" python3 -c \
    'import socket
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",18087));s.listen(1)
c,_=s.accept();total=0
while True:
 d=c.recv(65536)
 if not d: break
 total+=len(d)
c.sendall(str(total).encode("ascii"));c.close();s.close()' \
    >"$work/large-sink.log" 2>&1 &
large_sink_pid=$!
ip netns exec "$server_ns" python3 -c \
    'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("10.77.88.1",18083));exec("while True:\n d,a=s.recvfrom(65535)\n s.sendto(d,a)")' \
    >"$work/server-udp.log" 2>&1 &
udp_pid=$!

ip netns exec "$client_ns" setpriv --reuid 65534 --regid 65534 --clear-groups \
    env HANS_STATE_DIR="$work/client-state" "$BINABS" \
    -c 192.0.2.1 -p hans-userspace-ci -f -v \
    --feature userspace --socks5 127.0.0.1:18080 \
    --socks5-user hans --socks5-password-file "$work/socks-password" \
    --shareports 18081,18082=127.0.0.1:18081 --allports \
    >"$client_log" 2>&1 &
client_pid=$!

connected=0
attempt=40
while [ "$attempt" -gt 0 ]; do
    if grep -q "userspace network ready at 10.77.88.100" "$client_log"; then
        connected=1
        break
    fi
    kill -0 "$server_pid"
    kill -0 "$client_pid"
    sleep 0.25
    attempt=$((attempt - 1))
done
[ "$connected" -eq 1 ]
grep -q "using unprivileged ICMP ping socket" "$client_log"
grep -q "sharing otherwise-unmapped VPN TCP ports" "$client_log"

# A second unprivileged userspace process has the same underlay source IP.
# Protocol v4 must demultiplex it by receiver index and assign an independent
# authenticated sticky identity instead of replacing the first client.
ip netns exec "$client_ns" setpriv --reuid 65534 --regid 65534 --clear-groups \
    env HANS_STATE_DIR="$work/client2-state" "$BINABS" \
    -c 192.0.2.1 -p hans-userspace-ci -f -v \
    --feature userspace --socks5 127.0.0.1:18084 \
    --shareports 18085=127.0.0.1:18081 \
    >"$work/client2.log" 2>&1 &
client2_pid=$!
attempt=40
while [ "$attempt" -gt 0 ]; do
    grep -q "userspace network ready at 10.77.88.101" "$work/client2.log" && break
    kill -0 "$client2_pid"
    sleep 0.25
    attempt=$((attempt - 1))
done
grep -q "userspace network ready at 10.77.88.101" "$work/client2.log"

# Userspace mode must not create any kernel tunnel interface in the client.
[ "$(ip -n "$client_ns" -o link show | wc -l)" -eq 2 ]

ip netns exec "$client_ns" curl --fail --silent --show-error --max-time 20 \
    --socks5-hostname 127.0.0.1:18080 \
    --proxy-user hans:userspace-secret \
    http://10.77.88.1:18080/$(basename "$BINABS") -o "$work/socks-download"
cmp "$BINABS" "$work/socks-download"
ip netns exec "$client_ns" curl --fail --silent --show-error --max-time 20 \
    --socks5-hostname 127.0.0.1:18084 \
    http://10.77.88.1:18080/$(basename "$BINABS") -o "$work/socks-download-2"
cmp "$BINABS" "$work/socks-download-2"

# Peer-to-peer packets are switched inside the server, so a restrictive host
# FORWARD policy must not prevent one VPN client from reaching another.
ip netns exec "$server_ns" iptables -P FORWARD DROP
ip netns exec "$client_ns" curl --fail --silent --show-error --max-time 20 \
    --socks5-hostname 127.0.0.1:18080 \
    --proxy-user hans:userspace-secret \
    http://10.77.88.101:18085/$(basename "$BINABS") -o "$work/peer-share-download"
cmp "$BINABS" "$work/peer-share-download"

peer_table="$(HANS_STATE_DIR="$work/server-state" ip netns exec "$server_ns" \
    "$BINABS" --list-peers --json)"
[ "$(printf '%s' "$peer_table" | grep -o '192.0.2.2' | wc -l)" -eq 2 ]

ip netns exec "$server_ns" curl --fail --silent --show-error --max-time 20 \
    http://10.77.88.100:18081/$(basename "$BINABS") -o "$work/share-download"
cmp "$BINABS" "$work/share-download"
ip netns exec "$server_ns" curl --fail --silent --show-error --max-time 20 \
    http://10.77.88.100:18082/$(basename "$BINABS") -o "$work/share-explicit-download"
cmp "$BINABS" "$work/share-explicit-download"

# An otherwise-unmapped destination is bridged on demand to loopback at the
# same port. The explicit 18082 mapping above must still take precedence over
# this fallback (there is intentionally no loopback service on port 18082).
ip netns exec "$server_ns" curl --fail --silent --show-error --max-time 20 \
    http://10.77.88.100:18086/$(basename "$BINABS") -o "$work/allports-download"
cmp "$BINABS" "$work/allports-download"

# A fallback connection whose same-numbered loopback service is closed must
# fail cleanly without damaging the wildcard listener or the client process.
if ip netns exec "$server_ns" curl --fail --silent --show-error --max-time 5 \
    http://10.77.88.100:18088/ >"$work/allports-closed.out" 2>&1; then
    echo "closed allports target unexpectedly accepted a connection" >&2
    exit 1
fi
kill -0 "$client_pid"

# Drive more than 65535 bytes from VPN to the local socket in a single flow.
# This catches truncated tcp_recved() window credits, which otherwise stall a
# fast connection after its advertised receive window is exhausted.
large_received=$(ip netns exec "$server_ns" python3 -c \
    'import socket
s=socket.create_connection(("10.77.88.100",18087),20);s.settimeout(20)
block=b"x"*65536
for _ in range(256): s.sendall(block)
s.shutdown(socket.SHUT_WR);print(s.recv(64).decode("ascii"));s.close()')
[ "$large_received" = 16777216 ]

ip netns exec "$client_ns" python3 "$(dirname "$BINABS")/test-socks5-udp.py" \
    127.0.0.1 18080 10.77.88.1 18083 hans userspace-secret

# Exercise multiple simultaneous TCP PCBs and bridge buffers.
for n in 1 2 3 4; do
    ip netns exec "$client_ns" curl --fail --silent --show-error --max-time 20 \
        --socks5 127.0.0.1:18080 \
        --proxy-user hans:userspace-secret \
        http://10.77.88.1:18080/$(basename "$BINABS") -o "$work/concurrent-$n" &
    eval "curl_pid_$n=$!"
done
for n in 1 2 3 4; do
    eval "curl_pid=\$curl_pid_$n"
    wait "$curl_pid"
    cmp "$BINABS" "$work/concurrent-$n"
done

kill -0 "$server_pid"
kill -0 "$client_pid"

# Teardown is part of the product contract. Waiting here is important: merely
# sending SIGTERM lets a userspace-client destructor crash go unnoticed.
kill "$client_pid"
if ! wait "$client_pid"; then
    echo "userspace client did not exit cleanly" >&2
    exit 1
fi
client_pid=
echo "OK: unprivileged SOCKS5 TCP/UDP, explicit sharing, and allports tests passed"
