#!/usr/bin/env python3
"""Exercise Xray's Darwin TUN fd with the framing used by XrayBridge.

The test is intentionally self-contained and uses only loopback traffic. It
creates the same AF_UNIX/SOCK_DGRAM pair as the iOS Packet Tunnel extension,
passes one end to Xray, injects an IPv4/UDP packet into the other end, and
requires the echoed reply to come back as one complete Darwin TUN datagram.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path


CLIENT_ADDRESS = "198.18.0.1"
CLIENT_PORT = 53191
REQUEST = b"client-darwin-tun-request"
RESPONSE = b"client-darwin-tun-response"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def discover_host_address() -> str:
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # UDP connect selects an interface without sending a packet.
        probe.connect(("192.0.2.1", 9))
        address = probe.getsockname()[0]
    finally:
        probe.close()
    if address.startswith("127.") or address == "0.0.0.0":
        raise RuntimeError("could not discover a non-loopback test address")
    return address


def ipv4_udp_packet(destination_port: int, server_address: str) -> bytes:
    source = socket.inet_aton(CLIENT_ADDRESS)
    destination = socket.inet_aton(server_address)
    udp = struct.pack(
        "!HHHH",
        CLIENT_PORT,
        destination_port,
        8 + len(REQUEST),
        0,  # A zero UDP checksum is valid for IPv4.
    ) + REQUEST
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        0xCECC,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source,
        destination,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + udp


def parse_reply(frame: bytes, server_port: int, server_address: str) -> None:
    if len(frame) < 4 + 20 + 8:
        raise RuntimeError("returned TUN datagram is truncated")
    family = struct.unpack("!I", frame[:4])[0]
    if family != socket.AF_INET:
        raise RuntimeError("returned TUN datagram has the wrong address family")

    packet = frame[4:]
    if packet[0] >> 4 != 4:
        raise RuntimeError("returned packet is not IPv4")
    header_length = (packet[0] & 0x0F) * 4
    total_length = struct.unpack("!H", packet[2:4])[0]
    if total_length != len(packet) or header_length < 20:
        raise RuntimeError("returned IPv4 packet length is inconsistent")
    if packet[9] != socket.IPPROTO_UDP:
        raise RuntimeError("returned packet is not UDP")
    if socket.inet_ntoa(packet[12:16]) != server_address:
        raise RuntimeError("returned packet has the wrong source address")
    if socket.inet_ntoa(packet[16:20]) != CLIENT_ADDRESS:
        raise RuntimeError("returned packet has the wrong destination address")

    source_port, destination_port, udp_length, _ = struct.unpack(
        "!HHHH", packet[header_length : header_length + 8]
    )
    payload = packet[header_length + 8 : header_length + udp_length]
    if source_port != server_port or destination_port != CLIENT_PORT:
        raise RuntimeError("returned UDP ports do not match the injected flow")
    if payload != RESPONSE:
        raise RuntimeError("returned UDP payload does not match the echo response")


class EchoServer:
    def __init__(self, server_address: str) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((server_address, 0))
        self.socket.settimeout(8)
        self.port = self.socket.getsockname()[1]
        self.error: BaseException | None = None
        self.received = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        try:
            payload, peer = self.socket.recvfrom(4096)
            if payload != REQUEST:
                raise RuntimeError("loopback server received an unexpected payload")
            self.received.set()
            self.socket.sendto(RESPONSE, peer)
        except BaseException as error:  # surfaced on the main test thread
            self.error = error

    def close(self) -> None:
        self.socket.close()
        self.thread.join(timeout=1)


def wait_for_process_start(process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.communicate(timeout=1)[1].decode("utf-8", "replace")
            raise RuntimeError(f"Xray stopped before the TUN test: {output[-1000:]}")
        time.sleep(0.1)


def read_exactly(stream: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = stream.recv(count - len(chunks))
        if not chunk:
            raise RuntimeError("Darwin TUN stream ended in the middle of a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def receive_stream_frame(stream: socket.socket) -> bytes:
    header = read_exactly(stream, 4)
    family = struct.unpack("!I", header)[0]
    if family == socket.AF_INET:
        prefix = read_exactly(stream, 20)
        packet_length = struct.unpack("!H", prefix[2:4])[0]
        if packet_length < 20:
            raise RuntimeError("Xray returned an invalid IPv4 packet length")
        return header + prefix + read_exactly(stream, packet_length - 20)
    if family == socket.AF_INET6:
        prefix = read_exactly(stream, 40)
        payload_length = struct.unpack("!H", prefix[4:6])[0]
        return header + prefix + read_exactly(stream, payload_length)
    raise RuntimeError("Xray returned an unknown Darwin address family")


def run_test(xray: Path, transport: str) -> None:
    server_address = discover_host_address()
    echo = EchoServer(server_address)
    echo.start()
    socket_type = {
        "dgram": socket.SOCK_DGRAM,
        "seqpacket": socket.SOCK_SEQPACKET,
        "stream": socket.SOCK_STREAM,
    }[transport]
    xray_socket, swift_socket = socket.socketpair(socket.AF_UNIX, socket_type)
    swift_socket.settimeout(8)

    config = {
        "log": {"loglevel": "debug"},
        "inbounds": [
            {
                "protocol": "tun",
                "settings": {"name": "utun", "MTU": 1360},
                "tag": "in_proxy",
            }
        ],
        "outbounds": [{"protocol": "freedom", "tag": "proxy"}],
    }

    process: subprocess.Popen[bytes] | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", encoding="utf-8", delete=False
        ) as config_file:
            json.dump(config, config_file, separators=(",", ":"))
            config_path = config_file.name

        environment = os.environ.copy()
        environment["XRAY_TUN_FD"] = str(xray_socket.fileno())
        with tempfile.TemporaryFile() as process_log:
            process = subprocess.Popen(
                [str(xray), "run", "-c", config_path],
                env=environment,
                pass_fds=(xray_socket.fileno(),),
                stdout=process_log,
                stderr=process_log,
            )
            wait_for_process_start(process)

            frame = struct.pack("!I", socket.AF_INET) + ipv4_udp_packet(
                echo.port, server_address
            )
            try:
                if transport == "stream":
                    swift_socket.sendall(frame)
                    reply = receive_stream_frame(swift_socket)
                else:
                    if swift_socket.send(frame) != len(frame):
                        raise RuntimeError("the injected Darwin TUN frame was not sent atomically")
                    reply = swift_socket.recv(65539)
            except TimeoutError as error:
                process_log.seek(0)
                diagnostic = process_log.read().decode("utf-8", "replace")[-2000:]
                raise RuntimeError(
                    "timed out waiting for Xray's TUN reply; "
                    f"loopback_received={echo.received.is_set()} "
                    f"loopback_error={echo.error!r} xray_log={diagnostic!r}"
                ) from error
        parse_reply(reply, echo.port, server_address)
        if not echo.received.is_set():
            raise RuntimeError("the loopback server did not receive the proxied UDP packet")
        if echo.error is not None:
            raise echo.error
        print(
            "darwin_tun_bridge=ok "
            f"transport=SOCK_{transport.upper()} family=IPv4 protocol=UDP"
        )
    finally:
        xray_socket.close()
        swift_socket.close()
        echo.close()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if "config_path" in locals():
            os.unlink(config_path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument(
        "--transport",
        choices=("dgram", "seqpacket", "stream"),
        default="seqpacket",
    )
    arguments = parser.parse_args()
    if not arguments.xray.is_file():
        parser.error("--xray must point to an executable")
    run_test(arguments.xray.resolve(), arguments.transport)


if __name__ == "__main__":
    main()
