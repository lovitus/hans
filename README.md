Hans - IP over ICMP
===================

Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could
call it a ping tunnel. This can be useful when you find yourself in a
situation where your Internet access is firewalled, but pings are allowed.

Original project: http://code.gerade.org/hans/

This fork additionally ships a GitHub Actions pipeline
(`.github/workflows/build-and-release.yml`) that cross-builds `hans` for
almost every OS/kernel/CPU architecture combination the code supports, runs a
smoke test on each build, and automatically publishes the resulting binaries
as a [GitHub Release](../../releases).

## How it works

- The **server** owns an IP network (e.g. `10.0.0.0/24`) that only exists
  inside the tunnel. It takes `network + 1` for itself and hands out
  `network + 100`, `network + 101`, ... to connecting clients.
- The **client** authenticates with a SHA1 challenge/response derived from a
  shared passphrase, then gets assigned a tunnel IP and a virtual `tun`
  interface that carries its IPv4 traffic wrapped inside ICMP echo
  request/reply packets to/from the server.
- **Server mode is Linux-only** (it relies on Linux-specific networking
  behavior). **Client mode** works on Linux, FreeBSD, OpenBSD, NetBSD, macOS
  and Windows (via Cygwin).
- The passphrase is only used to **authenticate** the handshake (SHA1
  challenge/response) — the tunneled IP payload itself is **not encrypted**.
  If you need confidentiality, run something like SSH/TLS/WireGuard on top of
  the tunnel.

## Downloads

Prebuilt binaries for Linux (amd64/arm64/armv7/i386/ppc64le/riscv64/s390x/
mips64le), macOS (amd64/arm64), Windows (amd64, via Cygwin), FreeBSD, OpenBSD
and NetBSD (amd64/aarch64/riscv64/powerpc64, several releases each) are
published automatically on the [Releases page](../../releases). Windows users
need `cygwin1.dll`, which is shipped alongside `hans.exe` in the same asset.

## Building from source

Requires `gcc`/`g++` (or `clang`'s `cc`/`c++`) and `make`:

```sh
make
```

This produces a `hans` binary (or `hans.exe` on Windows/Cygwin) in the
repository root. Run `make clean` to remove build artifacts.

---

# Quick Start

You need root privileges (or `CAP_NET_RAW`/`CAP_NET_ADMIN` on Linux) on both
ends, because Hans opens a raw ICMP socket and creates a `tun` device.

### 1. Start the server (Linux)

Pick a private /24 network that isn't used anywhere else and a passphrase:

```sh
sudo ./hans -s 10.0.0.0 -p my-secret-passphrase -f -v
```

- `-s 10.0.0.0` — run as server, using `10.0.0.0/24` as the tunnel network
  (the server itself becomes `10.0.0.1`).
- `-p my-secret-passphrase` — shared passphrase, must match the client.
- `-f` — stay in the foreground (omit this to daemonize).
- `-v` — verbose logging (omit for quiet/production use).

### 2. Connect from the client

```sh
sudo ./hans -c server.example.com -p my-secret-passphrase -f -v
```

- `-c server.example.com` — the server's real (non-tunnel) address or
  hostname; you must be able to ping it.
- `-p my-secret-passphrase` — must match the server.

On success you'll see `connection established` on both sides, and a new
`tunX`/`utunX` interface will appear carrying the `10.0.0.0/24` tunnel
network (client gets `10.0.0.100`, `10.0.0.101`, ... automatically).

### 3. Verify the tunnel

```sh
ip addr show          # look for the new tun interface (Linux)
ping 10.0.0.1          # ping the server over the tunnel
```

---

# Advanced Usage

## Route all client Internet traffic through the tunnel

On the **server**, enable IP forwarding and NAT the tunnel network out to the
Internet:

```sh
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

On the **client**, once the tunnel is up, replace the default route (keeping
a host route to the real server IP via your original gateway so the ICMP
tunnel itself doesn't loop):

```sh
sudo ip route add <server-real-ip> via <your-current-gateway>
sudo ip route add 0.0.0.0/1 dev tun0
sudo ip route add 128.0.0.0/1 dev tun0
```

## Run unprivileged after startup

Hans needs root to open the raw socket and create the `tun` device, but it
can drop privileges immediately afterwards with `-u`:

```sh
sudo ./hans -s 10.0.0.0 -p secret -u nobody
```

(Not supported on Windows — dropping privileges will refuse to start.)

## Request a specific client IP

If you want a client to always get the same tunnel address (e.g. to
whitelist it server-side), request it explicitly:

```sh
./hans -c server -p secret -a 10.0.0.150
```

## Make the server also answer normal pings

By default the server swallows all ICMP echo requests for tunnel use. If you
still want it to reply to ordinary `ping` from the outside world:

```sh
sudo ./hans -s 10.0.0.0 -p secret -r
```

## Tuning for restrictive/broken networks

| Flag | Purpose |
| --- | --- |
| `-m mtu` | Reference MTU of the path between client and server (default `1500`). Must match on both sides. Lower it if you see fragmentation/connectivity issues on constrained links. |
| `-w polls` | Number of echo requests the client pre-sends for the server to piggy-back replies on (default `10`, `0` disables polling). Increase on high-latency links; set to `0` if the network allows unlimited unsolicited echo replies. |
| `-i` | Change the ICMP echo **id** on every request (client only). Helps with routers/firewalls that get confused by a static id. |
| `-q` | Change the ICMP echo **sequence number** on every request (client only). Same rationale as `-i`. |
| `-d device` | Force a specific `tun` device name/number instead of auto-selecting one. |

## Running as a systemd service (Linux)

```ini
# /etc/systemd/system/hans-server.service
[Unit]
Description=Hans ICMP tunnel server
After=network.target

[Service]
ExecStart=/usr/local/bin/hans -s 10.0.0.0 -p secret -f -u nobody
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now hans-server
```

## Full CLI reference

```
RUN AS CLIENT
  hans -c server [-fv] [-p passphrase] [-u user] [-d tun_device]
       [-m reference_mtu] [-w polls]

RUN AS SERVER (linux only)
  hans -s network [-fvr] [-p passphrase] [-u user] [-d tun_device]
       [-m reference_mtu] [-a ip]

ARGUMENTS
  -c server     Run as client. Connect to given server address.
  -s network    Run as server. Use given network address on virtual interfaces.
  -p passphrase Set passphrase.
  -u username   Change user under which the program runs.
  -a ip         Request assignment of given tunnel ip address from the server.
  -r            Respond to ordinary pings in server mode.
  -d device     Use given tun device.
  -m mtu        Set maximum echo packet size (default 1500, must match on both ends).
  -w polls      Number of pre-sent echo requests for polling (default 10, 0 disables).
  -i            Change echo id on every echo request (client only).
  -q            Change echo sequence number on every echo request (client only).
  -f            Run in foreground.
  -v            Print debug information.
```

## CI/CD

See `.github/workflows/build-and-release.yml` for the full build matrix,
smoke tests (version/help checks are mandatory; a real client/server
loopback connection is attempted wherever the sandbox has root + a TUN
device, and gracefully exempted otherwise), and the automatic release step.
