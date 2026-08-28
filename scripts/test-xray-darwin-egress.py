#!/usr/bin/env python3
"""Exercise Xray outbound socket binding on a Darwin interface.

The Packet Tunnel provider injects ``streamSettings.sockopt.interface`` into
every outbound. This probe first asks Xray to validate that exact shape,
including the DNS outbound, then sends an HTTP request through Xray's local
SOCKS inbound while the Freedom outbound is bound to ``lo0``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


EXPECTED_BODY = b"xray-darwin-interface-binding-ok"


def receive_exact(connection: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("SOCKS peer closed before completing its reply")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def reserve_loopback_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


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
                    + f"Content-Length: {len(EXPECTED_BODY)}\r\n".encode()
                    + b"Connection: close\r\n\r\n"
                    + EXPECTED_BODY
                )
                connection.sendall(response)
        except BaseException as error:  # surfaced by the main thread
            self.error = error
        finally:
            self.listener.close()


def wait_for_socks(port: int, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Xray exited before its SOCKS inbound became ready")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Xray SOCKS inbound did not become ready")


def socks_http_request(socks_port: int, destination_port: int) -> bytes:
    with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(b"\x05\x01\x00")
        if receive_exact(connection, 2) != b"\x05\x00":
            raise RuntimeError("Xray SOCKS inbound rejected no-auth negotiation")

        connection.sendall(
            b"\x05\x01\x00\x01\x7f\x00\x00\x01"
            + destination_port.to_bytes(2, "big")
        )
        header = receive_exact(connection, 4)
        if header[:2] != b"\x05\x00":
            raise RuntimeError("Xray could not open the interface-bound outbound")
        address_type = header[3]
        if address_type == 1:
            receive_exact(connection, 4)
        elif address_type == 3:
            receive_exact(connection, receive_exact(connection, 1)[0])
        elif address_type == 4:
            receive_exact(connection, 16)
        else:
            raise RuntimeError("Xray returned an invalid SOCKS address type")
        receive_exact(connection, 2)

        connection.sendall(b"GET / HTTP/1.0\r\nHost: local.test\r\n\r\n")
        response = bytearray()
        while True:
            chunk = connection.recv(4_096)
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)


def run_probe(xray: Path) -> None:
    http = LocalHTTPServer()
    http.start()
    socks_port = reserve_loopback_port()
    config = {
        "log": {"loglevel": "warning"},
        "dns": {"queryStrategy": "UseIPv4", "servers": ["1.1.1.1"]},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "tag": "in_proxy",
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct",
                "streamSettings": {"sockopt": {"interface": "lo0"}},
            },
            {
                "protocol": "dns",
                "tag": "dns-out",
                "streamSettings": {"sockopt": {"interface": "lo0"}},
            },
        ],
    }

    process: subprocess.Popen[bytes] | None = None
    primary_error: BaseException | None = None
    with tempfile.TemporaryDirectory() as directory:
        config_path = Path(directory) / "config.json"
        config_path.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
        validation = subprocess.run(
            [str(xray), "run", "-test", "-c", str(config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        if validation.returncode != 0:
            output = validation.stdout.decode("utf-8", "replace")[-1_000:]
            raise RuntimeError(f"Xray rejected interface-bound config: {output}")

        with tempfile.TemporaryFile() as process_log:
            process = subprocess.Popen(
                [str(xray), "run", "-c", str(config_path)],
                stdout=process_log,
                stderr=process_log,
            )
            try:
                wait_for_socks(socks_port, process)
                response = socks_http_request(socks_port, http.port)
                if EXPECTED_BODY not in response:
                    raise RuntimeError("HTTP response did not cross the bound Xray outbound")
                http.thread.join(timeout=1)
                if http.error is not None:
                    raise RuntimeError(f"loopback HTTP server failed: {http.error}")
            except BaseException as error:  # include safe local-only diagnostics
                primary_error = error
                process_log.seek(0)
                output = process_log.read().decode("utf-8", "replace")[-1_000:]
                raise RuntimeError(f"{error}; xray_log={output!r}") from error
            finally:
                if process.poll() is None:
                    process.terminate()
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        process.wait(timeout=3)
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)
                if process.returncode not in (0, -15) and primary_error is None:
                    process_log.seek(0)
                    output = process_log.read().decode("utf-8", "replace")[-1_000:]
                    raise RuntimeError(f"Xray stopped unexpectedly: {output}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Exercise Xray Darwin interface binding")
    parser.add_argument("--xray", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.xray.is_file():
        parser.error("--xray must point to an executable")
    run_probe(arguments.xray.resolve())
    print("xray_darwin_interface_binding=ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
