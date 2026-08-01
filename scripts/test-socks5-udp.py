#!/usr/bin/env python3
import socket
import struct
import sys


def recv_exact(sock, length):
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("SOCKS5 control connection closed")
        data += chunk
    return data


def main():
    if len(sys.argv) not in (5, 7):
        raise SystemExit("usage: test-socks5-udp.py proxy-ip proxy-port target-ip target-port [user password]")
    proxy_ip, proxy_port, target_ip, target_port = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    )
    control = socket.create_connection((proxy_ip, proxy_port), 5)
    if len(sys.argv) == 7:
        user, password = sys.argv[5].encode(), sys.argv[6].encode()
        control.sendall(b"\x05\x01\x02")
        if recv_exact(control, 2) != b"\x05\x02":
            raise RuntimeError("SOCKS5 username/password negotiation failed")
        control.sendall(b"\x01" + bytes([len(user)]) + user +
                        bytes([len(password)]) + password)
        if recv_exact(control, 2) != b"\x01\x00":
            raise RuntimeError("SOCKS5 username/password authentication failed")
    else:
        control.sendall(b"\x05\x01\x00")
        if recv_exact(control, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-authentication negotiation failed")
    control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
    reply = recv_exact(control, 10)
    if reply[:4] != b"\x05\x00\x00\x01":
        raise RuntimeError("SOCKS5 UDP ASSOCIATE failed: %r" % (reply,))
    relay = (socket.inet_ntoa(reply[4:8]), struct.unpack("!H", reply[8:10])[0])

    payload = b"hans-socks5-udp-test-" + bytes(range(128))
    header = b"\x00\x00\x00\x01" + socket.inet_aton(target_ip) + struct.pack("!H", target_port)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    udp.sendto(header + payload, relay)
    response, _ = udp.recvfrom(65535)
    if response[:10] != header or response[10:] != payload:
        raise RuntimeError("SOCKS5 UDP response did not match request")
    print("SOCKS5 UDP ASSOCIATE passed (%d payload bytes)" % len(payload))


if __name__ == "__main__":
    main()
