from __future__ import annotations

import argparse
import contextlib
import ipaddress
import select
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path


AF_HEADER_LENGTH = 4
CLIENT_IP = ipaddress.IPv4Address("10.250.0.2").packed
SERVER_IP = ipaddress.IPv4Address("127.0.0.1").packed
CLIENT_PORT = 40_123
CLIENT_INITIAL_SEQUENCE = 0x10203040
SOCKS_USERNAME = b"bridge-user"
SOCKS_PASSWORD = b"bridge-password"
EXPECTED_BODY = b"managed-bridge-ok"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def tcp_packet(
    *,
    source_ip: bytes,
    destination_ip: bytes,
    source_port: int,
    destination_port: int,
    sequence: int,
    acknowledgement: int,
    flags: int,
    payload: bytes = b"",
    identification: int = 1,
) -> bytes:
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        5 << 4,
        flags,
        65_535,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        source_ip,
        destination_ip,
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload),
    )
    tcp_sum = checksum(pseudo_header + tcp_header + payload)
    tcp_header = tcp_header[:16] + struct.pack("!H", tcp_sum) + tcp_header[18:]

    total_length = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        identification,
        0x4000,
        64,
        socket.IPPROTO_TCP,
        0,
        source_ip,
        destination_ip,
    )
    ip_sum = checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack("!H", ip_sum) + ip_header[12:]
    return ip_header + tcp_header + payload


def encode_tun(packet: bytes) -> bytes:
    return socket.AF_INET.to_bytes(AF_HEADER_LENGTH, "big") + packet


def decode_tun(frame: bytes) -> dict[str, int | bytes]:
    if len(frame) < AF_HEADER_LENGTH + 40:
        raise RuntimeError("TUN bridge returned a truncated frame")
    family = int.from_bytes(frame[:AF_HEADER_LENGTH], "big")
    if family != socket.AF_INET:
        raise RuntimeError("TUN bridge returned an unexpected address family")
    packet = frame[AF_HEADER_LENGTH:]
    header_length = (packet[0] & 0x0F) * 4
    if packet[0] >> 4 != 4 or header_length < 20:
        raise RuntimeError("TUN bridge returned an invalid IPv4 header")
    total_length = int.from_bytes(packet[2:4], "big")
    packet = packet[:total_length]
    tcp = packet[header_length:]
    if len(tcp) < 20:
        raise RuntimeError("TUN bridge returned a truncated TCP segment")
    tcp_header_length = (tcp[12] >> 4) * 4
    return {
        "source_port": int.from_bytes(tcp[0:2], "big"),
        "destination_port": int.from_bytes(tcp[2:4], "big"),
        "sequence": int.from_bytes(tcp[4:8], "big"),
        "acknowledgement": int.from_bytes(tcp[8:12], "big"),
        "flags": tcp[13],
        "payload": tcp[tcp_header_length:],
    }


def receive_exact(stream: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError("SOCKS peer closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class LocalHTTPServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            connection, _ = self.listener.accept()
            with connection:
                connection.settimeout(5)
                request = b""
                while b"\r\n\r\n" not in request:
                    request += connection.recv(4_096)
                response = (
                    b"HTTP/1.0 200 OK\r\n"
                    b"Content-Type: text/plain\r\n"
                    + f"Content-Length: {len(EXPECTED_BODY)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + EXPECTED_BODY
                )
                connection.sendall(response)
        except BaseException as error:  # noqa: BLE001
            self.error = error
        finally:
            self.listener.close()


class AuthenticatedSocksServer:
    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            client, _ = self.listener.accept()
            with client:
                client.settimeout(5)
                version, method_count = receive_exact(client, 2)
                methods = receive_exact(client, method_count)
                if version != 5 or 2 not in methods:
                    raise RuntimeError("SOCKS client did not offer password authentication")
                client.sendall(b"\x05\x02")

                auth_version, username_length = receive_exact(client, 2)
                username = receive_exact(client, username_length)
                password_length = receive_exact(client, 1)[0]
                password = receive_exact(client, password_length)
                if (
                    auth_version != 1
                    or username != SOCKS_USERNAME
                    or password != SOCKS_PASSWORD
                ):
                    raise RuntimeError("SOCKS client sent unexpected credentials")
                client.sendall(b"\x01\x00")

                request_version, command, reserved, address_type = receive_exact(client, 4)
                if request_version != 5 or command != 1 or reserved != 0:
                    raise RuntimeError("SOCKS client sent an invalid CONNECT request")
                if address_type == 1:
                    host = socket.inet_ntop(socket.AF_INET, receive_exact(client, 4))
                elif address_type == 3:
                    length = receive_exact(client, 1)[0]
                    host = receive_exact(client, length).decode("ascii")
                elif address_type == 4:
                    host = socket.inet_ntop(socket.AF_INET6, receive_exact(client, 16))
                else:
                    raise RuntimeError("SOCKS client used an unknown address type")
                port = int.from_bytes(receive_exact(client, 2), "big")

                with socket.create_connection((host, port), timeout=5) as upstream:
                    client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    self._relay(client, upstream)
        except BaseException as error:  # noqa: BLE001
            self.error = error
        finally:
            self.listener.close()

    @staticmethod
    def _relay(left: socket.socket, right: socket.socket) -> None:
        sockets = [left, right]
        while sockets:
            readable, _, _ = select.select(sockets, [], [], 5)
            if not readable:
                raise RuntimeError("SOCKS relay timed out")
            for source in readable:
                data = source.recv(65_536)
                if not data:
                    return
                destination = right if source is left else left
                destination.sendall(data)


def run_probe(executable: Path) -> None:
    http = LocalHTTPServer()
    socks = AuthenticatedSocksServer()
    http.start()
    socks.start()

    application_side, proxy_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    application_side.settimeout(5)
    proxy_url = (
        f"socks5://{SOCKS_USERNAME.decode()}:{SOCKS_PASSWORD.decode()}"
        f"@127.0.0.1:{socks.port}"
    )
    process = subprocess.Popen(
        [
            str(executable),
            "--tun-fd",
            str(proxy_side.fileno()),
            "--close-fd-on-drop",
            "false",
            "--proxy",
            proxy_url,
            "--dns",
            "direct",
            "--tcp-mss",
            "1320",
            "--max-sessions",
            "16",
            "--verbosity",
            "off",
        ],
        pass_fds=(proxy_side.fileno(),),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    proxy_side.close()

    primary_error: BaseException | None = None
    try:
        syn = tcp_packet(
            source_ip=CLIENT_IP,
            destination_ip=SERVER_IP,
            source_port=CLIENT_PORT,
            destination_port=http.port,
            sequence=CLIENT_INITIAL_SEQUENCE,
            acknowledgement=0,
            flags=0x02,
        )
        application_side.send(encode_tun(syn))
        syn_ack = decode_tun(application_side.recv(65_536))
        if syn_ack["flags"] & 0x12 != 0x12:
            raise RuntimeError("TUN bridge did not return TCP SYN-ACK")
        if syn_ack["acknowledgement"] != CLIENT_INITIAL_SEQUENCE + 1:
            raise RuntimeError("TUN bridge acknowledged the wrong TCP sequence")

        server_sequence = int(syn_ack["sequence"])
        client_sequence = CLIENT_INITIAL_SEQUENCE + 1
        server_acknowledgement = server_sequence + 1
        acknowledgement = tcp_packet(
            source_ip=CLIENT_IP,
            destination_ip=SERVER_IP,
            source_port=CLIENT_PORT,
            destination_port=http.port,
            sequence=client_sequence,
            acknowledgement=server_acknowledgement,
            flags=0x10,
            identification=2,
        )
        application_side.send(encode_tun(acknowledgement))

        request = b"GET / HTTP/1.0\r\nHost: local.test\r\n\r\n"
        data_packet = tcp_packet(
            source_ip=CLIENT_IP,
            destination_ip=SERVER_IP,
            source_port=CLIENT_PORT,
            destination_port=http.port,
            sequence=client_sequence,
            acknowledgement=server_acknowledgement,
            flags=0x18,
            payload=request,
            identification=3,
        )
        application_side.send(encode_tun(data_packet))
        client_sequence += len(request)

        response = bytearray()
        expected_sequence = server_acknowledgement
        deadline = time.monotonic() + 8
        identification = 4
        while EXPECTED_BODY not in response and time.monotonic() < deadline:
            segment = decode_tun(application_side.recv(65_536))
            payload = bytes(segment["payload"])
            sequence = int(segment["sequence"])
            if payload and sequence == expected_sequence:
                response.extend(payload)
                expected_sequence += len(payload)
            if segment["flags"] & 0x01 and sequence + len(payload) == expected_sequence:
                expected_sequence += 1
            if payload or segment["flags"] & 0x01:
                ack = tcp_packet(
                    source_ip=CLIENT_IP,
                    destination_ip=SERVER_IP,
                    source_port=CLIENT_PORT,
                    destination_port=http.port,
                    sequence=client_sequence,
                    acknowledgement=expected_sequence,
                    flags=0x10,
                    identification=identification,
                )
                identification += 1
                application_side.send(encode_tun(ack))

        if EXPECTED_BODY not in response:
            raise RuntimeError("HTTP response did not cross the managed TUN bridge")
        if socks.error is not None:
            raise RuntimeError(f"SOCKS test server failed: {socks.error}")
        if http.error is not None:
            raise RuntimeError(f"HTTP test server failed: {http.error}")
    except BaseException as error:  # noqa: BLE001
        primary_error = error
        raise
    finally:
        application_side.close()
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=3)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)
        if process.returncode not in (0, -15) and primary_error is None:
            stderr = (process.stderr.read() if process.stderr else "").strip()
            raise RuntimeError(f"managed bridge probe exited unexpectedly: {stderr[-500:]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exercise tun2proxy through a Darwin TUN fd")
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()
    if not args.probe.is_file():
        raise SystemExit("managed bridge probe executable is unavailable")
    run_probe(args.probe.resolve())
    print("managed_tun2proxy_roundtrip=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
