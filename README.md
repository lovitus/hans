Hans - IP over ICMP
===================

Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could
call it a ping tunnel. This can be useful when you find yourself in a
situation where your Internet access is firewalled, but pings are allowed.

Original project: http://code.gerade.org/hans/

## Features in this fork

This fork keeps the original lightweight ICMP tunnel design and adds
deployment, compatibility, and peer-management features:

| Feature | What this fork adds |
| --- | --- |
| Persistent peer identity | Each client generates a random 128-bit device ID that is independent of its IP address, network adapter, and disk serial number. The ID can also be backed up, moved, or configured explicitly. |
| Sticky tunnel addresses | The server remembers device-to-IP leases across reconnects and server restarts, so clients normally keep the same tunnel address without configuring `-a`. |
| Lease retention | Offline leases are retained while unused addresses remain. When the pool is full, only the least-recently-seen offline lease is reclaimed; active peers are never evicted. |
| Peer inspection | `hans --list-peers` shows device ID, tunnel IP, real IP, online/offline state, and last-seen time. `hans --show-device-id` displays the local persistent identity. |
| Backward-compatible protocol | New servers still accept legacy clients. New clients try the device-identity protocol first and automatically fall back when connecting to an older server. |
| Broad release matrix | GitHub Actions builds Linux, macOS, Windows/Cygwin (amd64 and legacy i386), FreeBSD, OpenBSD, and NetBSD binaries for the CPU architectures supported by the codebase. |
| Static releases | Linux and BSD release binaries are fully static. Windows compiler/C++ runtimes are embedded in the executable; macOS uses only operating-system libraries. Release binaries are stripped before their isolated package tests to avoid shipping debug symbols. |
| Old-Linux support | Statically linked musl binaries avoid glibc version dependencies and run on systems such as CentOS 7, older distributions, embedded Linux, and Alpine. |
| Adapter fallback | Windows prefers an installed TAP-Windows adapter and automatically falls back to bundled Wintun. Linux prefers TUN and falls back to a veth pair plus `AF_PACKET` when TUN is unavailable. Auto-created interfaces use `hans1`, then `hans2`, and so on. |
| Safe orphan cleanup | Auto-created Linux veth pairs carry a random ownership marker. On startup Hans removes a pair only when both endpoints and markers match exactly and no live process still owns it; ambiguous interfaces are always retained. |
| Runtime packaging | Windows compiler and C++ runtimes are linked into `hans.exe`; the package includes the unavoidable `cygwin1.dll` and the signed official `wintun.dll`, allowing use without a separate Cygwin installation. |
| Automated validation | Every build checks version/help output and persistent identity/lease commands, then repeats those checks from an isolated product directory without the compiler or development environment. Environments with root and TUN support additionally attempt a real client/server tunnel connection. |
| Continuous releases | Successful builds are collected and published automatically on the [Releases page](../../releases). |

## How it works

- The **server** owns an IP network (e.g. `10.0.0.0/24`) that only exists
  inside the tunnel. It takes `network + 1` for itself and hands out
  `network + 100`, `network + 101`, ... to connecting clients.
- The **client** authenticates with a SHA1 challenge/response derived from a
  shared passphrase, then gets assigned a tunnel IP and a virtual `tun`
  interface that carries its IPv4 traffic wrapped inside ICMP echo
  request/reply packets to/from the server.
- New clients also send a persistent random device ID. The server uses it for
  sticky leases, so a peer normally receives the same tunnel IP after changing
  networks or reconnecting.
- **Server mode is Linux-only** (it relies on Linux-specific networking
  behavior). **Client mode** works on Linux, FreeBSD, OpenBSD, NetBSD, macOS
  and Windows (via Cygwin).
- The passphrase is only used to **authenticate** the handshake (SHA1
  challenge/response) — the tunneled IP payload itself is **not encrypted**.
  If you need confidentiality, run something like SSH/TLS/WireGuard on top of
  the tunnel.

## Downloads

Prebuilt binaries for Linux (amd64/arm64/armv7/i386/ppc64le/riscv64/s390x/
mips64le), macOS (amd64/arm64), Windows (amd64/i386, via Cygwin), FreeBSD, OpenBSD
and NetBSD (amd64/aarch64/riscv64/powerpc64, several releases each) are
published automatically on the [Releases page](../../releases). Windows users
should download `hans-windows-amd64-cygwin.zip` on normal 64-bit systems, or
the legacy `hans-windows-i386-cygwin.zip` when 32-bit support is required.
Extract all four files—`hans.exe`, `cygwin1.dll`, `wintun.dll`, and
`WINTUN-LICENSE.txt`—into the same directory; the DLLs must keep their exact
filenames. Cygwin ended x86 maintenance at version 3.3.6, so amd64 is
recommended whenever the operating system supports it.

Run the Windows client from an elevated PowerShell or Command Prompt. Hans
first uses an installed **TAP-Windows** adapter. If none can be opened, it
loads the bundled, signed official Wintun runtime and creates `hans1` (or
`hans2`, `hans3`, ... when earlier names are occupied). `-d "adapter name"`
still requests an exact TAP/Wintun name.

Server hostnames are supported when DNS provides an IPv4 **A** record. The
outer Hans transport currently uses IPv4 ICMP and does not yet implement
ICMPv6, so an AAAA-only hostname or an IPv6 literal cannot be used as the
server address. Add an A record or use an IPv4-capable hostname/address.

**Linux: which binary should I use?**

- `hans-linux-<arch>-ubuntuXX.XX` — fully static glibc build produced and
  tested on the named Ubuntu toolchain. It does not require a target-system
  copy of glibc or libstdc++.
- `hans-linux-<arch>-musl` — **statically linked against musl libc**, with
  no libc version dependency at all. Use this one if you're targeting an
  old kernel/distro, a musl-based system (Alpine, postmarketOS, ...), an
  embedded/router Linux, or you're simply unsure which glibc the target has.
  This is the recommended choice for maximum compatibility.

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
`hans1` (or the platform's native `utunX`) interface will appear carrying the
`10.0.0.0/24` tunnel network (client gets `10.0.0.100`, `10.0.0.101`, ...
automatically).

### 3. Verify the tunnel

```sh
ip addr show          # look for the new tun interface (Linux)
ping 10.0.0.1          # ping the server over the tunnel
```

On Linux, Hans normally creates a kernel TUN interface. If `/dev/net/tun` is
missing or unusable, it automatically creates a veth pair and uses an
`AF_PACKET` socket as its layer-3 backend. This fallback still needs
`CAP_NET_ADMIN` and `CAP_NET_RAW`, kernel veth support, and the `ip` command
from iproute2; it cannot bypass missing privileges. The public interface is
named `hans1`, then `hans2`, and so on. The private peer is removed with it
when Hans exits.

If Hans is killed with `SIGKILL`, normal teardown cannot run. New auto-created
veth pairs therefore carry the same random 128-bit ownership marker on both
ends while the owning process holds a Linux abstract socket for that marker.
At the next startup Hans reclaims a pair only if the names are the expected
`hansN`/`hanspN` pair, both aliases contain the same valid marker, their kernel
interface indexes point back to each other, their device types and `NOARP`
flags match, and no process owns the marker socket. A custom `-d` interface,
an interface created by an older Hans build, or any ambiguous/mismatched pair
is deliberately left untouched for manual inspection.

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
sudo ip route add 0.0.0.0/1 dev hans1
sudo ip route add 128.0.0.0/1 dev hans1
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

## Persistent peer identity and sticky leases

On first start, a client generates a random 128-bit device ID and stores it in
`/var/lib/hans/device-id` (or `$HOME/.hans/device-id` when not running as
root). The ID is not derived from an IP address, network adapter, disk serial
number, or other hardware, so those values can change without changing the
peer identity.

The server records leases in `/var/lib/hans/leases`. A reconnecting device
gets its previous tunnel IP whenever possible. Offline leases are retained
while unused addresses remain; only when the pool is full does the server
reclaim the least-recently-seen offline lease. If every address is actively
in use, the connection is rejected as `server full`.

Inspect the local device ID or the server's lease table with:

```sh
sudo ./hans --show-device-id
sudo ./hans --list-peers
```

Example peer output:

```text
DEVICE ID                         TUNNEL IP        REAL IP          STATE     LAST SEEN
4a7f28b1309d4e62b1cc7508ad6f91c2  10.0.0.100      203.0.113.20     online    2026-07-31 16:30:00
```

Use custom state paths when packaging Hans or running more than one instance:

```sh
./hans -c server -p secret --device-id-file /etc/hans/site-a.id
./hans -s 10.0.0.0 -p secret --lease-file /var/lib/hans/site-a.leases
./hans --list-peers --lease-file /var/lib/hans/site-a.leases
```

You can also supply a fixed 32-character hexadecimal ID with `--device-id`.
The device ID is not a secret, but it should be unique. If a system disk is
replaced without copying the ID file, copy the old ID from backup or configure
the same value explicitly; no software-only identity can survive loss of all
locally persisted state.

Servers accept legacy clients without a device ID (those clients continue to
receive non-sticky leases). New clients automatically fall back to the legacy
connection request when talking to an older server.

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
| `-d device` | Force a specific virtual interface name instead of auto-selecting `hans1`, `hans2`, and so on. |

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
       [-m reference_mtu] [-w polls] [--device-id id]
       [--device-id-file path]

RUN AS SERVER (linux only)
  hans -s network [-fvr] [-p passphrase] [-u user] [-d tun_device]
       [-m reference_mtu] [--lease-file path]

LIST SERVER PEERS
  hans --list-peers [--lease-file path]

SHOW CLIENT DEVICE ID
  hans --show-device-id [--device-id-file path]

ARGUMENTS
  -c server     Run as client. Connect to given server address.
  -s network    Run as server. Use given network address on virtual interfaces.
  -p passphrase Set passphrase.
  -u username   Change user under which the program runs.
  -a ip         Request assignment of given tunnel ip address from the server.
  -I id         Use an explicit persistent 32-hex-character device id.
  -k path       Load/create the client device id in this file.
  -j path       Store/read sticky server leases in this file.
  -l            List peers from the server lease file and exit.
  -o            Print the persistent client device id and exit.
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
